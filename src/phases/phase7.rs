// src/phases/phase7.rs

//! # Faza 7: Deep Forensics (Inteligentna Analiza Entropii Shannona)
//!
//! Wykrywanie anomalii matematycznych. Klasyfikuje szum informacyjny, zaszyfrowanie
//! (Ransomware), wydmuszki oraz błędy kompresji. Posiada hierarchiczny generator
//! raportu śledczego. Komunikuje się z interfejsem Ratatui poprzez PhaseEvent
//! i generuje pliki Dual-Logging.
//!
//! UWAGA ARCHITEKTONICZNA (UI): Pasek postępu pokazuje wyłącznie % i bieżący
//! plik. Liczniki live trafiają do panelu bocznego jako JEDEN, samodzielny blok
//! PER ŹRÓDŁO — patrz [`build_source_block`]. Cztery kategorie anomalii
//! (szum, szyfrowanie, zepsuta kompresja, wydmuszka), każda rozbita na
//! wspólne/unikalne, PLUS (Wariant A, na żądanie) lekki podgląd "które
//! rozszerzenia najczęściej wpadają w tę kategorię" — tylko licznik per
//! rozszerzenie (`Mutex<HashMap<String, usize>>`), BEZ przechowywania
//! konkretnych ścieżek w pamięci przez czas trwania fazy (to already robi
//! `raport_operacyjny_faza7.txt`, zapisywany strumieniowo na bieżąco w
//! [`process_side_stream`] — panel TUI i plik logu to dwie niezależne warstwy,
//! Wariant A niczego z pliku logu nie zabiera). Pełna wersja z przykładowymi
//! ścieżkami per rozszerzenie ([`SourceAnomalies`]/[`AnomalyCategory`]) jest
//! budowana WYŁĄCZNIE po zakończeniu skanowania, z całej tabeli SQL naraz —
//! nie jest dostępna w trakcie live-skanowania, stąd nie może zasilać panelu
//! bocznego bezpośrednio.
//!
//! UWAGA ARCHITEKTONICZNA (WĄTKOWANIE): każda strona dostaje własną, dedykowaną
//! pulę Rayon (`half_threads`, identycznie jak Fazy 2-6). Ta faza jest CPU-bound
//! (256 zliczeń na bajt + logarytmy dla całej zawartości pliku), więc głodzenie
//! jednej strony przy współdzielonej globalnej puli byłoby tu potencjalnie
//! dotkliwsze niż w Fazie 5 (lekki `lstat()`) — sam mechanizm błędu identyczny,
//! patrz dokumentacja modułu w `phase5.rs`.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent; // <--- NAPRAWIONY IMPORT
use crate::utils::{format_bytes, format_display_path, CANCEL_SIGNAL};
use ratatui::style::Color;
use rayon::prelude::*;
use rusqlite::{params, Connection, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;
use tracing::{info, instrument, warn};

const CHUNK_SIZE: usize = 100;

// ============================================================================
// STRUKTURY DANYCH
// ============================================================================

/// Pojedyncze zadanie: plik oczekujący na obliczenie entropii Shannona po JEDNEJ stronie.
#[derive(Debug, Clone)]
pub(crate) struct Task {
    /// Klucz główny rekordu w tabeli `files`.
    id: i32,
    /// Ścieżka względna liczona od katalogu bazowego danej strony.
    rel_path: String,
    /// `true` gdy plik jest obecny na OBU stronach — decyduje o klasyfikacji
    /// wykrytej anomalii do liczników `_common` czy `_unique`.
    is_common: bool, 
}

/// Wynik obliczenia entropii jednego pliku, przekazywany przez MPSC do wątku zapisu SQLite.
#[derive(Debug, Clone)]
pub(crate) struct SideEntropyResult {
    id: i32,
    /// Entropia Shannona w bitach/bajt (zakres 0.0-8.0). `None` przy błędzie
    /// I/O lub anulowaniu przez użytkownika.
    entropy: Option<f64>,
    io_error: Option<bool>,
}

/// Wiadomość do wątku zapisu SQLite, oznaczona stroną pochodzenia.
pub(crate) enum ScanMsg {
    UfsChunk(Vec<SideEntropyResult>),
    ScriptChunk(Vec<SideEntropyResult>),
}

/// Liczniki live dla JEDNEJ strony. Cztery kategorie anomalii entropii, każda
/// rozbita na `_common`/`_unique` (patrz [`Task::is_common`]), plus (Wariant A)
/// lekkie mapy "rozszerzenie -> liczba wystąpień" per kategoria - BEZ podziału
/// common/unique wewnątrz mapy (to dodatkowy wymiar "które formaty", niezależny
/// od "czy plik był wspólny" - liczniki `_common`/`_unique` już dają tę drugą
/// odpowiedź jako sumy). Nigdy nie łączone z licznikami drugiej strony.
pub(crate) struct LiveStats {
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    errors: AtomicUsize,
    ext_weights: Mutex<HashMap<String, u64>>,
    
    /// Biały szum/śmieci (entropia > 7.995) w plikach WSPÓLNYCH.
    noise_common: AtomicUsize,   
    noise_unique: AtomicUsize,
    /// Podejrzanie wysoka entropia (>7.5) dla formatu NIE-skompresowanego —
    /// sugeruje szyfrowanie lub nadpisanie losowymi danymi.
    crypto_common: AtomicUsize,  
    crypto_unique: AtomicUsize,
    /// Podejrzanie niska entropia (<6.0) dla formatu Z ZAŁOŻENIA skompresowanego
    /// (zip/jpg/mp4/...) — sugeruje uszkodzoną/przerwaną kompresję.
    broken_common: AtomicUsize, 
    broken_unique: AtomicUsize,
    /// Bardzo niska entropia (0.0-1.0) — wydmuszka/pusty blok (mało unikalnych bajtów).
    low_common: AtomicUsize,     
    low_unique: AtomicUsize,

    /// Wariant A: licznik wystąpień per rozszerzenie dla kategorii "szum".
    noise_ext: Mutex<HashMap<String, usize>>,
    /// Wariant A: licznik wystąpień per rozszerzenie dla kategorii "szyfrowanie".
    crypto_ext: Mutex<HashMap<String, usize>>,
    /// Wariant A: licznik wystąpień per rozszerzenie dla kategorii "zepsuta kompresja".
    broken_ext: Mutex<HashMap<String, usize>>,
    /// Wariant A: licznik wystąpień per rozszerzenie dla kategorii "wydmuszka".
    low_ext: Mutex<HashMap<String, usize>>,

    /// EKSPERYMENTALNE (Wariant A śledzenia wątków, patrz moduł
    /// `thread_activity`): śledzi zajętość logicznych slotów Rayon TEJ
    /// strony podczas liczenia entropii Shannon. Nie mylić z "Wariantem A"
    /// nazewnictwa `*_ext` map wyżej — to niepowiązana, wcześniejsza
    /// konwencja nazewnicza w tym pliku.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            processed_files: AtomicUsize::new(0),
            processed_bytes: AtomicU64::new(0),
            errors: AtomicUsize::new(0),
            ext_weights: Mutex::new(HashMap::new()),
            noise_common: AtomicUsize::new(0),
            noise_unique: AtomicUsize::new(0),
            crypto_common: AtomicUsize::new(0),
            crypto_unique: AtomicUsize::new(0),
            broken_common: AtomicUsize::new(0),
            broken_unique: AtomicUsize::new(0),
            low_common: AtomicUsize::new(0),
            low_unique: AtomicUsize::new(0),
            noise_ext: Mutex::new(HashMap::new()),
            crypto_ext: Mutex::new(HashMap::new()),
            broken_ext: Mutex::new(HashMap::new()),
            low_ext: Mutex::new(HashMap::new()),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }
}

/// Wylicza liczbę slotów trackera zajętości (Wariant A) odpowiednią dla
/// trybu I/O — patrz identyczna logika w `phase3::compute_activity_slots`.
fn compute_activity_slots(io_mode: &str, actual_threads: usize, half_threads: usize) -> usize {
    if io_mode == "CONCURRENT" { half_threads } else { actual_threads }
}

// Struktury dla Raportu Hierarchicznego
/// Mapa rozszerzenie -> lista pełnych ścieżek plików w tej kategorii anomalii.
/// UWAGA: w przeciwieństwie do liczników live w [`LiveStats`], ta struktura
/// przechowuje KONKRETNE ścieżki (nieograniczoną listę) i jest budowana
/// WYŁĄCZNIE po zakończeniu skanowania (patrz [`run`]) z zapytania SQL do
/// całej tabeli — nie istnieje w trakcie live-skanowania.
type ExtMap = HashMap<String, Vec<String>>;

/// Anomalie jednej kategorii, rozbite na stronę pochodzenia (UFS/Skrypt).
/// Używane wyłącznie do budowy Dziennika Końcowego — patrz [`ExtMap`].
struct SourceAnomalies {
    ufs: ExtMap,
    script: ExtMap,
}

impl SourceAnomalies {
    fn new() -> Self {
        Self { ufs: HashMap::new(), script: HashMap::new() }
    }
}

/// Pełny opis jednej kategorii anomalii entropii do Dziennika Końcowego:
/// nazwa i ikona do nagłówka sekcji raportu, oraz dwa zestawy [`SourceAnomalies`]
/// (pliki wspólne / unikalne). Wypełniane jednorazowo w [`run`] po zakończeniu
/// skanowania, iterując po całej tabeli SQL — nie w trakcie działania
/// [`process_side_stream`].
struct AnomalyCategory {
    name: &'static str,
    icon: &'static str, // <--- PRZYWRÓCONA IKONA DO RAPORTU
    common: SourceAnomalies,
    unique: SourceAnomalies,
}

impl AnomalyCategory {
    fn new(name: &'static str, icon: &'static str) -> Self {
        Self {
            name,
            icon,
            common: SourceAnomalies::new(),
            unique: SourceAnomalies::new(),
        }
    }
}

// ============================================================================
// LOGIKA BIZNESOWA I INTEGRACJA Z RATATUI
// ============================================================================

/// Oblicza entropię Shannona (bity/bajt) całej zawartości pliku:
/// `H = -Σ p(b) log2(p(b))` po wszystkich 256 możliwych wartości bajtu `b`,
/// gdzie `p(b)` to częstość występowania tej wartości w pliku. Zakres wyniku:
/// `0.0` (plik złożony z jednej powtarzającej się wartości bajtu — zero
/// niepewności informacyjnej) do `8.0` (wszystkie 256 wartości występują z
/// jednakową częstością — maksymalna losowość, typowa dla danych
/// skompresowanych lub zaszyfrowanych).
///
/// Zwraca `Ok(0.0)` dla pliku pustego (brak danych = brak entropii, nie błąd).
/// Kategorie anomalii entropii — wydzielone z [`klasyfikuj_entropie`], żeby
/// progi klasyfikacji dało się przetestować niezależnie od reszty
/// `process_side_stream` (liczniki `stats`, log operacyjny, I/O).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KategoriaEntropii {
    Szum,
    Zaszyfrowany,
    ZepsutaKompresja,
    Wydmuszka,
}

/// Klasyfikuje wynik entropii pliku. Dokumentacja modułu deklaruje zakres
/// "wydmuszki" jako domknięty przedział `0.0–1.0`, ale kod do niedawna
/// implementował otwarty `(0.0, 1.0)` — plik z entropią DOKŁADNIE `0.0`
/// (jeden powtarzający się bajt na całej długości, najbardziej klasyczny
/// pusty blok) nie pasował do ŻADNEJ kategorii i przechodził całkowicie
/// niesklasyfikowany. Naprawione: `ent >= 0.0`.
fn klasyfikuj_entropie(ent: f64, is_compressed: bool) -> Option<KategoriaEntropii> {
    if ent > 7.995 {
        Some(KategoriaEntropii::Szum)
    } else if ent > 7.5 && !is_compressed {
        Some(KategoriaEntropii::Zaszyfrowany)
    } else if ent < 6.0 && is_compressed {
        Some(KategoriaEntropii::ZepsutaKompresja)
    } else if ent >= 0.0 && ent < 1.0 {
        Some(KategoriaEntropii::Wydmuszka)
    } else {
        None
    }
}

/// Sprawdza `CANCEL_SIGNAL` między odczytami bufora (128 KB) i zwraca
/// `Err(ErrorKind::Interrupted)` przy anulowaniu — wywołujący
/// ([`process_side_stream`]) już poprawnie odróżnia to od prawdziwego błędu I/O.
fn calculate_entropy(path: &Path) -> std::result::Result<f64, std::io::Error> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();

    if file_len == 0 { return Ok(0.0); }

    let mut byte_counts = [0u64; 256];
    let mut buffer = [0u8; 131_072]; 
    let mut total_bytes = 0u64;

    loop {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { 
            return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Przerwano przez użytkownika")); 
        }
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        for &byte in &buffer[..n] { byte_counts[byte as usize] += 1; }
        total_bytes += n as u64;
    }

    if total_bytes == 0 { return Ok(0.0); }

    let mut entropy = 0.0;
    for &count in &byte_counts {
        if count > 0 {
            let p = count as f64 / total_bytes as f64;
            entropy -= p * p.log2();
        }
    }
    Ok(entropy)
}

/// Buduje pełny, samodzielny blok live DLA JEDNEGO ŹRÓDŁA (UFS albo Skrypt) —
/// prędkość MB/s, top 3 rozszerzenia wagowo, cztery kategorie anomalii entropii
/// (każda rozbita na wspólne/unikalne), oraz — Wariant A — dla każdej kategorii
/// najczęściej dotknięte rozszerzenie (samą nazwę i liczbę, bez konkretnych
/// ścieżek; pełna lista ze ścieżkami trafia do `raport_operacyjny_faza7.txt`
/// na bieżąco, niezależnie od tego panelu). Bez sumowania z drugą stroną.
fn build_source_block(label: &str, stats: &LiveStats, start_time: Instant) -> String {
    let bytes = stats.processed_bytes.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
    let speed_mb = (bytes as f64 / 1_048_576.0) / elapsed;

    let top_ext = {
        let map = stats.ext_weights.lock().unwrap();
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.into_iter().take(3).map(|(ext, w)| {
            let e = if ext == "brak" { "brak".to_string() } else { format!(".{}", ext) };
            format!("{} ({})", e, format_bytes(*w))
        }).collect::<Vec<_>>().join(", ")
    };
    let display_ext = if top_ext.is_empty() { "Analiza danych...".to_string() } else { top_ext };

    // Wariant A: najczęściej dotknięte rozszerzenie per kategoria (nazwa + liczba)
    let top_one = |map: &Mutex<HashMap<String, usize>>| -> String {
        let m = map.lock().unwrap();
        m.iter().max_by_key(|&(_, &count)| count).map(|(ext, count)| {
            let e = if ext == "brak" { "brak".to_string() } else { format!(".{}", ext) };
            format!("{} ({})", e, count)
        }).unwrap_or_else(|| "-".to_string())
    };

    let activity_markup = crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot());

    format!(
        "[{}]\nPrędkość: {:.2} MB/s\nTop format: {}\nSzum/Śmieci (H>7.99): {} wspólne / {} unikalne | top: {}\nSzyfrowanie (H>7.5): {} wspólne / {} unikalne | top: {}\nZepsuta kompresja (H<6.0): {} wspólne / {} unikalne | top: {}\nWydmuszki (H<1.0): {} wspólne / {} unikalne | top: {}\nWątki entropii (Wariant A): {}\nBłędy I/O: {}",
        label, speed_mb, display_ext,
        stats.noise_common.load(Ordering::Relaxed), stats.noise_unique.load(Ordering::Relaxed), top_one(&stats.noise_ext),
        stats.crypto_common.load(Ordering::Relaxed), stats.crypto_unique.load(Ordering::Relaxed), top_one(&stats.crypto_ext),
        stats.broken_common.load(Ordering::Relaxed), stats.broken_unique.load(Ordering::Relaxed), top_one(&stats.broken_ext),
        stats.low_common.load(Ordering::Relaxed), stats.low_unique.load(Ordering::Relaxed), top_one(&stats.low_ext),
        activity_markup,
        stats.errors.load(Ordering::Relaxed),
    )
}

/// Skanuje wszystkie zadania (`tasks`) dla JEDNEJ strony: dla każdego pliku
/// liczy entropię Shannona przez [`calculate_entropy`], klasyfikuje wynik do
/// jednej z czterech kategorii anomalii (patrz progi w [`LiveStats`]),
/// aktualizuje liczniki `_common`/`_unique` ORAZ (Wariant A) mapę
/// rozszerzenie->liczba dla trafionej kategorii, strumieniuje wyniki do wątku
/// zapisu SQLite. Rozgłasza postęp i statystyki do UI co ~200 plików LUB
/// co 250ms (hybrydowy próg — sam licznik czasu, deklarowany raz na paczkę
/// `CHUNK_SIZE`, mógłby nigdy nie zadziałać przy szybkim odczycie w obrębie
/// jednej paczki, stąd licznik globalny jako główny wyzwalacz).
pub struct StreamCtx<'a> {
    pub base_path: &'a Path,
    pub tasks: &'a [Task],
    pub side_label: &'a str,
    pub stats: &'a LiveStats,
    pub tx_db: mpsc::SyncSender<ScanMsg>,
    pub is_ufs: bool,
    pub tx_ui: &'a mpsc::Sender<PhaseEvent>,
    pub bar_idx: usize,
    pub start_time: Instant,
    // <--- DODANO BRAKUJĄCY ARGUMENT
    pub opr_log: Arc<Mutex<File>>,
}

#[instrument(skip(ctx), fields(base_path = %ctx.base_path.display()))]

fn process_side_stream<'a>(ctx: StreamCtx<'a>) {
    let StreamCtx { base_path, tasks, side_label, stats, tx_db, is_ufs, tx_ui, bar_idx, start_time, // <--- DODANO BRAKUJĄCY ARGUMENT
    opr_log } = ctx;

    tasks.par_chunks(CHUNK_SIZE).for_each_with(tx_db, |tx_db, chunk| {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

        let mut results = Vec::with_capacity(chunk.len());
        let mut local_ext_weights: HashMap<String, u64> = HashMap::new();
        // Wariant A: lokalne bufory liczników per rozszerzenie dla każdej
        // kategorii, scalane do globalnych map na tych samych zasadach co
        // local_ext_weights (minimalizacja rywalizacji o Mutex).
        let mut local_noise_ext: HashMap<String, usize> = HashMap::new();
        let mut local_crypto_ext: HashMap<String, usize> = HashMap::new();
        let mut local_broken_ext: HashMap<String, usize> = HashMap::new();
        let mut local_low_ext: HashMap<String, usize> = HashMap::new();
        let mut last_ui_update = Instant::now();

        for task in chunk {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

            let full_path: PathBuf = base_path.join(&task.rel_path);
            let ext = Path::new(&task.rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
            let file_size = std::fs::metadata(&full_path).map(|m| m.len()).unwrap_or(0);
            
            *local_ext_weights.entry(ext.clone()).or_insert(0) += file_size;

            let (entropy_opt, io_err) = match stats.thread_activity.track_current(|| calculate_entropy(&full_path)) {
                Ok(ent) => {
                    let mut anomalies = Vec::new();
                    let is_compressed = matches!(ext.as_str(), "zip" | "rar" | "7z" | "jpg" | "jpeg" | "png" | "mp4" | "mkv" | "pdf" | "apk" | "gz" | "docx" | "xlsx");

                    match klasyfikuj_entropie(ent, is_compressed) {
                        Some(KategoriaEntropii::Szum) => {
                            anomalies.push(format!("Biały Szum / Śmieci (H={:.3})", ent));
                            if task.is_common { stats.noise_common.fetch_add(1, Ordering::Relaxed); }
                            else { stats.noise_unique.fetch_add(1, Ordering::Relaxed); }
                            *local_noise_ext.entry(ext.clone()).or_insert(0) += 1;
                        }
                        Some(KategoriaEntropii::Zaszyfrowany) => {
                            anomalies.push(format!("Zaszyfrowany / Nadpisany (H={:.3})", ent));
                            if task.is_common { stats.crypto_common.fetch_add(1, Ordering::Relaxed); }
                            else { stats.crypto_unique.fetch_add(1, Ordering::Relaxed); }
                            *local_crypto_ext.entry(ext.clone()).or_insert(0) += 1;
                        }
                        Some(KategoriaEntropii::ZepsutaKompresja) => {
                            anomalies.push(format!("Zepsuta Kompresja (H={:.3})", ent));
                            if task.is_common { stats.broken_common.fetch_add(1, Ordering::Relaxed); }
                            else { stats.broken_unique.fetch_add(1, Ordering::Relaxed); }
                            *local_broken_ext.entry(ext.clone()).or_insert(0) += 1;
                        }
                        Some(KategoriaEntropii::Wydmuszka) => {
                            anomalies.push(format!("Wydmuszka / Pusty blok (H={:.3})", ent));
                            if task.is_common { stats.low_common.fetch_add(1, Ordering::Relaxed); }
                            else { stats.low_unique.fetch_add(1, Ordering::Relaxed); }
                            *local_low_ext.entry(ext.clone()).or_insert(0) += 1;
                        }
                        None => {}
                    }

                    if !anomalies.is_empty()
                        && let Ok(mut f) = opr_log.lock() {
                            let kategoria = if task.is_common { "Wspólne" } else { "Unikalne" };
                            let anomalies_str = anomalies.join(", ");
                            let _ = writeln!(f, "[{:<15}] [{:<8}] [{}] Format: .{:<5} | Ścieżka: \"{}\"", side_label, kategoria, anomalies_str, ext, full_path.display());
                        }
                    
                    (Some(ent), Some(false))
                },
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        // Anulowanie skanu przez operatora (CANCEL_SIGNAL sprawdzany
                        // co 128 KB w calculate_entropy), NIE błąd I/O - plik nigdy
                        // nie został faktycznie zbadany. `io_error=Some(true)` tutaj
                        // trwale i fałszywie oznaczałoby go jako uszkodzony (warunek
                        // ponownego zakolejkowania sprawdza `err_ufs/script != Some(true)`),
                        // blokując weryfikację na zawsze zamiast wznowić przy kolejnym
                        // uruchomieniu.
                        (None, None)
                    } else {
                        warn!(path = %task.rel_path, side = side_label, error = %e, "Błąd I/O podczas czytania pliku");
                        stats.errors.fetch_add(1, Ordering::Relaxed);
                        if let Ok(mut f) = opr_log.lock() {
                            let kategoria = if task.is_common { "Wspólne" } else { "Unikalne" };
                            let _ = writeln!(f, "[{:<15}] [{:<8}] [Błąd I/O: {}] Format: .{:<5} | Ścieżka: \"{}\"", side_label, kategoria, e, ext, full_path.display());
                        }
                        (None, Some(true))
                    }
                }
            };

            stats.processed_files.fetch_add(1, Ordering::Relaxed);
            stats.processed_bytes.fetch_add(file_size, Ordering::Relaxed);
            
            let current = stats.processed_files.load(Ordering::Relaxed);
            let now = Instant::now();

            // Hybrydowy próg (wzorzec z Fazy 5/6): licznik globalny jako główny
            // wyzwalacz (nie resetuje się na granicy paczki CHUNK_SIZE=100),
            // plus siatka bezpieczeństwa czasowa na wolne dyski/duże pliki
            // (ta faza czyta CAŁĄ zawartość i liczy entropię - CPU-bound,
            // pojedynczy plik może trwać realnie dłużej niż w innych fazach).
            let should_update = current.is_multiple_of(200)
                || now.duration_since(last_ui_update).as_millis() > 250;

            if should_update {
                last_ui_update = now; 

                if !local_ext_weights.is_empty() {
                    let mut global_map = stats.ext_weights.lock().unwrap();
                    for (k, v) in local_ext_weights.drain() { *global_map.entry(k).or_insert(0) += v; }
                }
                if !local_noise_ext.is_empty() {
                    let mut global_map = stats.noise_ext.lock().unwrap();
                    for (k, v) in local_noise_ext.drain() { *global_map.entry(k).or_insert(0) += v; }
                }
                if !local_crypto_ext.is_empty() {
                    let mut global_map = stats.crypto_ext.lock().unwrap();
                    for (k, v) in local_crypto_ext.drain() { *global_map.entry(k).or_insert(0) += v; }
                }
                if !local_broken_ext.is_empty() {
                    let mut global_map = stats.broken_ext.lock().unwrap();
                    for (k, v) in local_broken_ext.drain() { *global_map.entry(k).or_insert(0) += v; }
                }
                if !local_low_ext.is_empty() {
                    let mut global_map = stats.low_ext.lock().unwrap();
                    for (k, v) in local_low_ext.drain() { *global_map.entry(k).or_insert(0) += v; }
                }

                // PASEK: wyłącznie postęp + bieżący plik (bez liczników)
                let _ = tx_ui.send(PhaseEvent::UpdateBar {
                    idx: bar_idx,
                    current: current as u64,
                    message: format_display_path(&task.rel_path),
                });
                let _ = tx_ui.send(PhaseEvent::UpdateBottomPath {
                    idx: bar_idx,
                    path: full_path.to_string_lossy().to_string(),
                });

                // PANEL BOCZNY: pełny, samodzielny blok TEGO źródła
                let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                    idx: bar_idx,
                    text: build_source_block(side_label, stats, start_time),
                });
            }

            results.push(SideEntropyResult { id: task.id, entropy: entropy_opt, io_error: io_err });
        }

        if !local_ext_weights.is_empty() {
            let mut global_map = stats.ext_weights.lock().unwrap();
            for (k, v) in local_ext_weights.drain() { *global_map.entry(k).or_insert(0) += v; }
        }
        if !local_noise_ext.is_empty() {
            let mut global_map = stats.noise_ext.lock().unwrap();
            for (k, v) in local_noise_ext.drain() { *global_map.entry(k).or_insert(0) += v; }
        }
        if !local_crypto_ext.is_empty() {
            let mut global_map = stats.crypto_ext.lock().unwrap();
            for (k, v) in local_crypto_ext.drain() { *global_map.entry(k).or_insert(0) += v; }
        }
        if !local_broken_ext.is_empty() {
            let mut global_map = stats.broken_ext.lock().unwrap();
            for (k, v) in local_broken_ext.drain() { *global_map.entry(k).or_insert(0) += v; }
        }
        if !local_low_ext.is_empty() {
            let mut global_map = stats.low_ext.lock().unwrap();
            for (k, v) in local_low_ext.drain() { *global_map.entry(k).or_insert(0) += v; }
        }

        if !results.is_empty() {
            if is_ufs { let _ = tx_db.send(ScanMsg::UfsChunk(results)); } 
            else { let _ = tx_db.send(ScanMsg::ScriptChunk(results)); }
        }
    });

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: stats.processed_files.load(Ordering::Relaxed) as u64,
        message: "Analiza entropii (Odczyt ciał plików) zakończona.".to_string(),
    });
}

// ============================================================================
// GŁÓWNA FUNKCJA KORDYNUJĄCA (Entrypoint Fazy 7)
// ============================================================================

/// Punkt wejścia Fazy 7, wołany przez `menu::actions::run_phase_with_ui`.
///
/// Przebieg: (1) wczytuje z SQLite zadania — wszystkie pliki obecne po danej
/// stronie, którym brakuje jeszcze entropii (`entropy_ufs`/`_script` IS NULL)
/// i bez zapisanego błędu I/O; oznacza `is_common` na podstawie obecności po
/// obu stronach; (2) uruchamia [`process_side_stream`] dla UFS i Skryptu —
/// równolegle na dwóch dedykowanych pulach Rayon (`half_threads`, patrz
/// dokumentacja modułu) lub sekwencyjnie; (3) koreluje wyniki w SQLite;
/// (4) buduje Dziennik Końcowy — TU, dopiero po zakończeniu skanowania,
/// wypełniane są [`AnomalyCategory`]/[`SourceAnomalies`] pełnym zapytaniem
/// SQL do całej tabeli, z przykładowymi ścieżkami per rozszerzenie i stronę.
#[instrument(skip(conn, config, tx_ui), fields(ufs_path = %config.ufs_path, script_path = %config.script_path))]
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    // 1. INICJALIZACJA DUAL-LOGGING (Pobieranie ścieżek z Ustawień)
    let raport_cfg = config.raporty_faz.get("Faza 7").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza7.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza7.txt".to_string(),
    });
    
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);
    
    let opr_log = Arc::new(Mutex::new(File::create(&opr_path).unwrap()));
    {
        let mut f = opr_log.lock().unwrap();
        let _ = writeln!(f, "=== RAPORT OPERACYJNY - FAZA 7 (ANALIZA ENTROPII SHANNONA) ===");
        let _ = writeln!(f, "Zestawienie plików obarczonych wadami matematycznymi (Szum, Nadpisanie, Błędy Kompresji).\n");
    }

    let actual_threads = if config.max_threads > 0 { config.max_threads } else { rayon::current_num_threads() };
    let io_text = if config.io_mode == "CONCURRENT" { "RÓWNOLEGŁE (SSD/NVMe)" } else { "SEKWENCYJNIE (HDD)" };
    
    let _ = tx_ui.send(PhaseEvent::Log(format!("Uruchomiono Fazę 7. Metodyka szyny dyskowej: {}", io_text)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora (Rayon): {}", actual_threads)));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    // --- ETAP 1: POBIERANIE ZADAŃ Z BAZY ---
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, entropy_ufs, entropy_script, io_error_ufs, io_error_script 
         FROM files WHERE phase7_done = 0 OR phase7_done IS NULL"
    )?;
    
    let mut ufs_tasks = Vec::new();
    let mut script_tasks = Vec::new();
    let mut skipped_ufs = 0;
    let mut skipped_script = 0;

    let rows = stmt.query_map([], |row| {
        let id: i32 = row.get(0)?;
        let rel: String = row.get(1)?;
        let in_ufs: bool = row.get(2)?;
        let in_script: bool = row.get(3)?;
        let e_ufs: Option<f64> = row.get(4)?;
        let e_scr: Option<f64> = row.get(5)?;
        let err_ufs: Option<bool> = row.get(6)?;
        let err_scr: Option<bool> = row.get(7)?;
        Ok((id, rel, in_ufs, in_script, e_ufs, e_scr, err_ufs, err_scr))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_ufs, in_script, e_ufs, e_scr, err_ufs, err_scr) = r;
        let is_common = in_ufs && in_script;
        
        if in_ufs {
            if e_ufs.is_none() && err_ufs != Some(true) { ufs_tasks.push(Task { id, rel_path: rel.clone(), is_common }); } 
            else { skipped_ufs += 1; }
        }
        if in_script {
            if e_scr.is_none() && err_scr != Some(true) { script_tasks.push(Task { id, rel_path: rel, is_common }); } 
            else { skipped_script += 1; }
        }
    }
    drop(stmt);

    if skipped_ufs > 0 || skipped_script > 0 {
        let _ = tx_ui.send(PhaseEvent::Log(format!("Pominięto pliki z wyliczoną już entropią. UFS Explorer: {}, Skrypt Autorski: {}", skipped_ufs, skipped_script)));
    }

    let total_db_rows = ufs_tasks.len() + script_tasks.len();
    if total_db_rows == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak plików wymagających analizy entropii. Baza aktualna.".to_string()));
        return Ok(());
    }

    // Inicjalizacja pasków postępu Ratatui
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "UFS Explorer (Entropia)".to_string(), total: ufs_tasks.len() as u64, color: Color::Cyan });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 1, label: "Skrypt Autorski (Entropia)".to_string(), total: script_tasks.len() as u64, color: Color::Magenta });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 2, label: "Zapis SQLite".to_string(), total: total_db_rows as u64, color: Color::Green });

    let half_threads = std::cmp::max(1, actual_threads / 2);
    let activity_slots = compute_activity_slots(&config.io_mode, actual_threads, half_threads);

    let ufs_stats = LiveStats::new(activity_slots);
    let script_stats = LiveStats::new(activity_slots);
    let ufs_path = PathBuf::from(&config.ufs_path);
    let script_path = PathBuf::from(&config.script_path);

    // --- ETAP 3: PRZETWARZANIE STRUMIENIOWE (MPSC) ---
    std::thread::scope(|s| {
        let (tx_db, rx_db) = mpsc::sync_channel(200);
        let conn_ref = &mut *conn;
        let tx_ui_ref = &tx_ui;

        let _db_thread = s.spawn(move || {
            let mut last_db_update = Instant::now();
            let mut db_inserted = 0;

            for msg in rx_db {
                let chunk_len = match &msg {
                    ScanMsg::UfsChunk(c) => c.len(),
                    ScanMsg::ScriptChunk(c) => c.len(),
                };

                if chunk_len > 0 {
                    let tx_trans = conn_ref.transaction().unwrap();
                    {
                        // OPTYMALIZACJA: prepare_cached
                        let mut stmt = match &msg {
                            ScanMsg::UfsChunk(_) => tx_trans.prepare_cached(
                                "UPDATE files SET entropy_ufs = COALESCE(?1, entropy_ufs), io_error_ufs = COALESCE(?2, io_error_ufs) WHERE id = ?3"
                            ).unwrap(),
                            ScanMsg::ScriptChunk(_) => tx_trans.prepare_cached(
                                "UPDATE files SET entropy_script = COALESCE(?1, entropy_script), io_error_script = COALESCE(?2, io_error_script) WHERE id = ?3"
                            ).unwrap(),
                        };
                        
                        let chunk = match &msg {
                            ScanMsg::UfsChunk(c) => c,
                            ScanMsg::ScriptChunk(c) => c,
                        };

                        for res in chunk {
                            if res.entropy.is_some() || res.io_error == Some(true) {
                                stmt.execute(params![res.entropy, res.io_error, res.id]).unwrap();
                            }
                        }
                    }
                    tx_trans.commit().unwrap();
                }

                db_inserted += chunk_len;

                let now = Instant::now();
                if now.duration_since(last_db_update).as_millis() > 60 {
                    last_db_update = now;
                    let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Zapisywanie entropii do bazy...".to_string() });
                }
            }
            let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Entropie w 100% zsynchronizowane z SQLite.".to_string() });
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone(); let tx2 = tx_db.clone();
            let rep_u = opr_log.clone(); let rep_s = opr_log.clone();

            let stat_u = &ufs_stats;
            let stat_s = &script_stats;

            // NAPRAWA (ten sam bug jak w Fazie 5/6, patrz dokumentacja modułu):
            // dedykowana pula per strona, minimum 1 wątek. Szczególnie istotne
            // tutaj, bo liczenie entropii jest CPU-bound (256 zliczeń + logarytm
            // na bajt) - głodzenie jednej strony przy współdzielonej globalnej
            // puli byłoby bardziej dotkliwe niż przy lekkim lstat() z Fazy 5.
            // Wyliczone wcześniej, tu tylko używane.

            s.spawn(move || {
                if !ufs_tasks.is_empty() { 
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &ufs_path, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, start_time, // <--- DODANO BRAKUJĄCY ARGUMENT
    opr_log: rep_u, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &ufs_path, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, start_time, // <--- DODANO BRAKUJĄCY ARGUMENT
    opr_log: rep_u, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Analiza matematyczna (UFS Explorer) zakończona.".to_string()));
                }
            });

            s.spawn(move || {
                if !script_tasks.is_empty() { 
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &script_path, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, start_time, // <--- DODANO BRAKUJĄCY ARGUMENT
    opr_log: rep_s, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &script_path, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, start_time, // <--- DODANO BRAKUJĄCY ARGUMENT
    opr_log: rep_s, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Analiza matematyczna (Skrypt Autorski) zakończona.".to_string()));
                }
            });
            drop(tx_db);
        } 
        else {
            let rep_u = opr_log.clone(); let rep_s = opr_log.clone();
            
            if !ufs_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &ufs_path, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: &ufs_stats, tx_db: tx_db.clone(), is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, start_time, // <--- DODANO BRAKUJĄCY ARGUMENT
    opr_log: rep_u, }); 
                let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Analiza matematyczna (UFS Explorer) zakończona.".to_string()));
            }

            if !script_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &script_path, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: &script_stats, tx_db: tx_db.clone(), is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, start_time, // <--- DODANO BRAKUJĄCY ARGUMENT
    opr_log: rep_s, }); 
                let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Analiza matematyczna (Skrypt Autorski) zakończona.".to_string()));
            }
            drop(tx_db);
        }
    });

    // --- ETAP 4: SYNCHRONIZACJA Z BAZĄ DANYCH ---
    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log("🛑 Skanowanie przerwane przez użytkownika.".to_string()));
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::Log("Trwa generowanie hierarchicznego raportu w bazie SQLite...".to_string()));
    
    conn.execute(
        "UPDATE files SET phase7_done = CASE 
            WHEN (found_in_ufs = 0 OR entropy_ufs IS NOT NULL OR io_error_ufs = 1) 
             AND (found_in_script = 0 OR entropy_script IS NOT NULL OR io_error_script = 1) THEN 1 
            ELSE 0 
        END WHERE phase7_done = 0 OR phase7_done IS NULL", []
    )?;

    // --- ETAP 5: HIERARCHICZNY RAPORT KRYMINALISTYCZNY ---
    let mut stmt = conn.prepare(
        "SELECT relative_path, found_in_ufs, found_in_script, entropy_ufs, entropy_script 
         FROM files WHERE phase7_done = 1"
    )?;

    let mut cat_noise = AnomalyCategory::new("Biały Szum / Śmieci (H>7.99)", "💥");
    let mut cat_crypto = AnomalyCategory::new("Podejrzanie wysoka entropia (H>7.5)", "🔒");
    let mut cat_broken = AnomalyCategory::new("Zepsuta Kompresja (H<6.0 dla archiwów)", "📉");
    let mut cat_low = AnomalyCategory::new("Wydmuszki / Puste bloki (H<1.0)", "🧊");

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?, row.get::<_, bool>(1)?, row.get::<_, bool>(2)?,
            row.get::<_, Option<f64>>(3)?, row.get::<_, Option<f64>>(4)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (rel_path, in_ufs, in_scr, e_ufs, e_scr) = r;
        let is_common = in_ufs && in_scr;
        let ext = Path::new(&rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
        let is_compressed = matches!(ext.as_str(), "zip" | "rar" | "7z" | "jpg" | "jpeg" | "png" | "mp4" | "mkv" | "pdf" | "apk" | "gz" | "docx" | "xlsx");

        let add_to_cat = |cat: &mut AnomalyCategory, is_ufs_source: bool| {
            let target = if is_common { &mut cat.common } else { &mut cat.unique };
            let map = if is_ufs_source { &mut target.ufs } else { &mut target.script };
            map.entry(ext.clone()).or_default().push(rel_path.clone());
        };

        if in_ufs
            && let Some(e) = e_ufs { 
                if e > 7.995 { add_to_cat(&mut cat_noise, true); } 
                else if e > 7.5 && !is_compressed { add_to_cat(&mut cat_crypto, true); } 
                else if e < 6.0 && is_compressed { add_to_cat(&mut cat_broken, true); } 
                else if e > 0.0 && e < 1.0 { add_to_cat(&mut cat_low, true); }
            }

        if in_scr
            && let Some(e) = e_scr { 
                if e > 7.995 { add_to_cat(&mut cat_noise, false); } 
                else if e > 7.5 && !is_compressed { add_to_cat(&mut cat_crypto, false); } 
                else if e < 6.0 && is_compressed { add_to_cat(&mut cat_broken, false); } 
                else if e > 0.0 && e < 1.0 { add_to_cat(&mut cat_low, false); }
            }
    }
    drop(stmt);

    let elapsed = start_time.elapsed();
    let total_bytes = ufs_stats.processed_bytes.load(Ordering::SeqCst) + script_stats.processed_bytes.load(Ordering::SeqCst);
    let avg_speed_mb = (total_bytes as f64 / 1_048_576.0) / elapsed.as_secs_f64().max(1.0);
    let total_io_errors = ufs_stats.errors.load(Ordering::SeqCst) + script_stats.errors.load(Ordering::SeqCst);

    // -- GENEROWANIE DZIENNIKA KOŃCOWEGO --
    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(&mut log_out, "==========================================================================");
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 7 (MATEMATYCZNA ANALIZA ENTROPII SHANNONA)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "Sumaryczny transfer I/O: {} (Średnia prędkość: {:.2} MB/s)", format_bytes(total_bytes), avg_speed_mb);
    let _ = writeln!(&mut log_out, "==========================================================================\n");

    // PRZYWRÓCONE: Wzbogacony generator raportu z użyciem IKON
    let write_section_txt = |out: &mut String, title: &str, is_common: bool| {
        let _ = writeln!(out, "[ {} ]", title);
        let categories = [&cat_noise, &cat_crypto, &cat_broken, &cat_low];
        
        let mut has_any = false;
        for cat in &categories {
            let src_anom = if is_common { &cat.common } else { &cat.unique };
            let ufs_total: usize = src_anom.ufs.values().map(|v| v.len()).sum();
            let scr_total: usize = src_anom.script.values().map(|v| v.len()).sum();
            
            if ufs_total > 0 || scr_total > 0 {
                has_any = true;
                let _ = writeln!(out, "   {} Typ anomalii: {} (UFS: {}, Skrypt: {})", cat.icon, cat.name, ufs_total, scr_total);
                let _ = writeln!(out, "      [ ZNACZENIE ]: Wartość entropii wskazuje na matematyczny chaos lub brak spójności danych.");
                
                // Macierz rozszerzeń w raporcie TXT
                let mut print_exts = |map: &ExtMap, label: &str| {
                    if !map.is_empty() {
                        let _ = writeln!(out, "      {} - Rozkład formatów:", label);
                        let mut sorted: Vec<_> = map.iter().collect();
                        sorted.sort_by_key(|a| std::cmp::Reverse(a.1.len()));
                        for (ext, paths) in sorted.into_iter().take(3) {
                            let _ = writeln!(out, "         .{:<5} : {} plików (Przykł: {})", ext, paths.len(), paths[0]);
                        }
                    }
                };
                print_exts(&src_anom.ufs, "UFS Explorer");
                print_exts(&src_anom.script, "Skrypt Autorski");
                let _ = writeln!(out);
            }
        }
        
        if !has_any {
            let _ = writeln!(out, "   ✔ Brak anomalii w tej puli.\n");
        }
    };

    write_section_txt(&mut log_out, "CZĘŚĆ WSPÓLNA (Odnalezione przez oba programy)", true);
    write_section_txt(&mut log_out, "OSOBNE ŚCIEŻKI (Unikalne dla jednego źródła)", false);

    // PRZYWRÓCONE: Zestawienie wagowe formatów dla raportu
    let _ = writeln!(&mut log_out, "[ PODSUMOWANIE WAGOWE FORMATÓW ]");
    let print_all_exts = |out_str: &mut String, map: &HashMap<String, u64>, label: &str| {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        let _ = writeln!(out_str, "   {}", label);
        if sorted.is_empty() { let _ = writeln!(out_str, "      Brak plików."); }
        for (ext, weight) in sorted.into_iter().take(5) { 
            let e = if ext == "brak" { "brak".to_string() } else { format!(".{}", ext) };
            let _ = writeln!(out_str, "      - {:<8} : {}", e, format_bytes(*weight));
        }
    };
    print_all_exts(&mut log_out, &ufs_stats.ext_weights.lock().unwrap(), "UFS Explorer");
    print_all_exts(&mut log_out, &script_stats.ext_weights.lock().unwrap(), "Skrypt Autorski");
    let _ = writeln!(&mut log_out);

    if total_io_errors > 0 {
        let _ = writeln!(&mut log_out, "[ 🚨 BŁĘDY FIZYCZNE I/O ]");
        let _ = writeln!(&mut log_out, "   -> Błędy odczytu (I/O): {}", total_io_errors);
    }

    if let Ok(mut f) = fs::File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano fizyczny Dziennik Końcowy w: {}", dz_path.display())));
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano Raport Operacyjny (Live) w: {}", opr_path.display())));
    }

    // Wysyłamy również do Ratatui Log Panel
    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    // Zrzut telemetrii do głównego pliku logów w tle
    info!(
        total_io_errors,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 7 zakończona"
    );

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    // ------------------------------------------------------------------
    // compute_activity_slots (identyczna logika z Fazy 3/4/5/6)
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_activity_slots_concurrent_uses_half_threads() {
        assert_eq!(compute_activity_slots("CONCURRENT", 4, 2), 2);
    }

    #[test]
    fn test_compute_activity_slots_sequential_uses_full_actual_threads() {
        assert_eq!(compute_activity_slots("SEQUENTIAL", 4, 2), 4);
    }

    /// Tolerancja porównań zmiennoprzecinkowych dla entropii Shannona.
    const EPS: f64 = 1e-9;

    fn make_temp_file(content: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f
    }

    // ------------------------------------------------------------------
    // calculate_entropy
    // ------------------------------------------------------------------

    #[test]
    fn test_entropy_all_zeros_is_zero() {
        // Jedna powtarzająca się wartość bajtu => zero niepewności informacyjnej
        let f = make_temp_file(&vec![0x00u8; 1000]);
        let h = calculate_entropy(f.path()).unwrap();
        assert!((h - 0.0).abs() < EPS);
    }

    #[test]
    fn test_entropy_single_repeated_nonzero_byte_is_zero() {
        let f = make_temp_file(&vec![0x41u8; 500]); // same 'A'
        let h = calculate_entropy(f.path()).unwrap();
        assert!((h - 0.0).abs() < EPS);
    }

    #[test]
    fn test_entropy_two_symbols_50_50_is_one_bit() {
        // Dokładnie dwie wartości bajtu w równych proporcjach:
        // H = -[0.5*log2(0.5) + 0.5*log2(0.5)] = 1.0 bit/bajt
        let content: Vec<u8> = (0..1000).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect();
        let f = make_temp_file(&content);
        let h = calculate_entropy(f.path()).unwrap();
        assert!((h - 1.0).abs() < EPS, "Oczekiwano H=1.0, otrzymano {}", h);
    }

    #[test]
    fn test_entropy_all_256_values_equal_is_maximal() {
        // Wszystkie 256 wartości bajtu w równej liczbie => maksymalna entropia = 8.0
        let mut content = Vec::with_capacity(256 * 10);
        for _ in 0..10 {
            for b in 0..=255u8 { content.push(b); }
        }
        let f = make_temp_file(&content);
        let h = calculate_entropy(f.path()).unwrap();
        assert!((h - 8.0).abs() < EPS, "Oczekiwano H=8.0 (maksimum), otrzymano {}", h);
    }

    #[test]
    fn test_entropy_empty_file_is_zero_not_error() {
        let f = make_temp_file(b"");
        let h = calculate_entropy(f.path()).unwrap();
        assert_eq!(h, 0.0);
    }

    // ------------------------------------------------------------------
    // REGRESJA (Gemini review): H=0.0 musi trafić do kategorii "Wydmuszka",
    // nie zniknąć bez klasyfikacji (były otwarty przedział `ent > 0.0`).
    // ------------------------------------------------------------------

    #[test]
    fn test_klasyfikuj_entropie_zero_jest_wydmuszka_nie_brakiem_kategorii() {
        assert_eq!(klasyfikuj_entropie(0.0, false), Some(KategoriaEntropii::Wydmuszka));
    }

    #[test]
    fn test_klasyfikuj_entropie_zero_dla_pliku_skompresowanego_jest_zepsuta_kompresja() {
        // `is_compressed=true` i `ent<6.0` wygrywa PRZED gałęzią wydmuszki
        // (kolejność if/else) - zamierzone, zip wypełniony zerami to realnie
        // zepsuta kompresja, nie zwykła wydmuszka.
        assert_eq!(klasyfikuj_entropie(0.0, true), Some(KategoriaEntropii::ZepsutaKompresja));
    }

    #[test]
    fn test_klasyfikuj_entropie_granice_pozostalych_kategorii_niezmienione() {
        assert_eq!(klasyfikuj_entropie(8.0, false), Some(KategoriaEntropii::Szum));
        assert_eq!(klasyfikuj_entropie(7.8, false), Some(KategoriaEntropii::Zaszyfrowany));
        assert_eq!(klasyfikuj_entropie(0.5, false), Some(KategoriaEntropii::Wydmuszka));
        assert_eq!(klasyfikuj_entropie(4.0, false), None, "entropia środkowego zakresu bez kompresji nie jest anomalią");
    }

    // ------------------------------------------------------------------
    // REGRESJA (Gemini review): anulowanie skanu (CANCEL_SIGNAL) w trakcie
    // liczenia entropii nie może być mylone z prawdziwym błędem I/O -
    // inaczej plik dostaje trwałe `io_error=true` mimo że nigdy nie został
    // faktycznie zbadany, i nie wraca do kolejki przy wznowieniu.
    // ------------------------------------------------------------------

    #[test]
    fn test_calculate_entropy_zwraca_interrupted_gdy_cancel_signal_ustawiony() {
        // Plik dostatecznie duży, żeby CANCEL_SIGNAL zdążył zostać sprawdzony
        // w pętli odczytu (co 128 KB) przed wyczerpaniem pliku.
        let content = vec![0u8; 500_000];
        let f = make_temp_file(&content);

        CANCEL_SIGNAL.store(true, Ordering::Relaxed);
        let wynik = calculate_entropy(f.path());
        CANCEL_SIGNAL.store(false, Ordering::Relaxed); // sprzątanie - stan globalny

        match wynik {
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::Interrupted),
            Ok(_) => panic!("oczekiwano Err(Interrupted) przy ustawionym CANCEL_SIGNAL"),
        }
    }

    #[test]
    fn test_entropy_nonexistent_path_is_io_error() {
        let result = calculate_entropy(Path::new("/nieistniejaca/sciezka/do/pliku.dat"));
        assert!(result.is_err());
        assert_ne!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
    }

    // ------------------------------------------------------------------
    // build_source_block
    // ------------------------------------------------------------------

    #[test]
    fn test_build_source_block_reports_all_four_categories() {
        let stats = LiveStats::new(4);
        stats.noise_common.store(1, Ordering::Relaxed);
        stats.noise_unique.store(2, Ordering::Relaxed);
        stats.crypto_common.store(3, Ordering::Relaxed);
        stats.crypto_unique.store(4, Ordering::Relaxed);
        stats.broken_common.store(5, Ordering::Relaxed);
        stats.broken_unique.store(6, Ordering::Relaxed);
        stats.low_common.store(7, Ordering::Relaxed);
        stats.low_unique.store(8, Ordering::Relaxed);
        stats.errors.store(9, Ordering::Relaxed);

        let start_time = Instant::now() - Duration::from_secs(1);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        assert!(block.starts_with("[UFS Explorer]"));
        assert!(block.contains("Szum/Śmieci (H>7.99): 1 wspólne / 2 unikalne"));
        assert!(block.contains("Szyfrowanie (H>7.5): 3 wspólne / 4 unikalne"));
        assert!(block.contains("Zepsuta kompresja (H<6.0): 5 wspólne / 6 unikalne"));
        assert!(block.contains("Wydmuszki (H<1.0): 7 wspólne / 8 unikalne"));
        assert!(block.contains("Błędy I/O: 9"));
    }

    #[test]
    fn test_build_source_block_shows_thread_activity_markup() {
        let stats = LiveStats::new(4);
        stats.thread_activity.mark_busy(0);
        stats.thread_activity.mark_busy(3);

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        let line = block.lines().find(|l| l.starts_with("Wątki entropii")).expect("powinna istnieć linia Wariantu A");
        assert_eq!(line, "Wątki entropii (Wariant A): {G:1} {R:2} {R:3} {G:4}");
    }

    #[test]
    fn test_build_source_block_top_one_placeholder_when_empty() {
        let stats = LiveStats::new(4);
        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("Skrypt Autorski", &stats, start_time);

        // Każda kategoria bez danych powinna pokazać placeholder "-" jako "top"
        assert!(block.contains("top: -"));
    }

    #[test]
    fn test_build_source_block_top_one_picks_highest_count_extension() {
        let stats = LiveStats::new(4);
        stats.crypto_ext.lock().unwrap().insert("zip".to_string(), 2);
        stats.crypto_ext.lock().unwrap().insert("jpg".to_string(), 9); // powinien wygrać

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        let crypto_line = block.lines().find(|l| l.starts_with("Szyfrowanie")).unwrap();
        assert!(crypto_line.contains(".jpg (9)"), "Linia: {}", crypto_line);
    }

    #[test]
    fn test_build_source_block_does_not_leak_other_side_data() {
        let stats = LiveStats::new(4);
        stats.noise_unique.store(77, Ordering::Relaxed);
        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("Skrypt Autorski", &stats, start_time);
        assert!(block.contains("Szum/Śmieci (H>7.99): 0 wspólne / 77 unikalne"));
    }
}
