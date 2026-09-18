// src/phases/phase6.rs

//! # Faza 6: Zaawansowana Analiza Zawartości (Rozkład zer, Markery EOF, Analiza TRIM)
//!
//! Skanuje wnętrza plików w poszukiwaniu "wydmuszek HDD" (zera), "wydmuszek SSD" (0xFF po TRIM)
//! oraz weryfikuje znaczniki End-Of-File dla JPG, PDF, PNG oraz archiwów (ZIP/DOCX/XLSX).
//! Dla PDF sprawdzenie wykracza poza sam tekst `%%EOF` — potwierdza też, że
//! `startxref` wskazuje na wiarygodną tablicę xref (patrz [`pdf_xref_wyglada_na_spojny`]).
//! Działa w pełni asynchronicznie, komunikując się z Ratatui przez PhaseEvent.
//! Obsługuje system Dual-Logging dla anomalii strumieniowych.
//!
//! UWAGA ARCHITEKTONICZNA (UI): Pasek postępu pokazuje wyłącznie % i bieżący
//! plik. Liczniki live trafiają do panelu bocznego jako JEDEN, samodzielny blok
//! PER ŹRÓDŁO (`[UFS Explorer]` / `[Skrypt Autorski]`) — patrz [`build_source_block`].
//! Zapytanie SQL w [`run`] przetwarza WSZYSTKIE pliki niezależnie (jak Faza 2/5),
//! ale WEWNĄTRZ jednego źródła każda z 3 kategorii anomalii (zera, FF, EOF) jest
//! dodatkowo rozbita na "wspólne" (`is_common = found_in_ufs && found_in_script`)
//! i "unikalne" — bo plik obecny tylko po jednej stronie ma inne implikacje
//! kryminalistyczne niż uszkodzony plik, który miał szansę na porównanie z drugą
//! kopią. To dodatkowy wymiar podziału, ORTOGONALNY do podziału UFS/Skrypt, nie
//! drugi wariant architektury.
//!
//! UWAGA ARCHITEKTONICZNA (WĄTKOWANIE): każda strona dostaje WŁASNĄ, dedykowaną
//! pulę Rayon (`half_threads`, identycznie jak Fazy 2/3/4/5). Wcześniejsza wersja
//! tego pliku (jak pierwotna Faza 5) współdzieliła jedną globalną pulę między
//! UFS i Skrypt — przy niskim `max_threads` (np. 1) prowadziło to do głodzenia
//! jednej strony: pojedynczy worker Rayona zagłębiał się rekurencyjnie w JEDNO
//! zlecone zadanie przez swoją lokalną kolejkę LIFO, nie dotykając globalnej
//! kolejki drugiej strony, dopóki własna się nie wyczerpała. Błąd potwierdzony
//! empirycznie w Fazie 5 (UFS stał na 0% podczas gdy Skrypt szedł do 100%) i
//! naprawiony tym samym mechanizmem co Fazy 2-5.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent; // <--- NAPRAWIONY IMPORT
use crate::utils::{format_bytes, format_display_path, CANCEL_SIGNAL};
use ratatui::style::Color;
use rayon::prelude::*;
use rusqlite::{params, Connection, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;
use tracing::{debug, info, instrument, warn};

const CHUNK_SIZE: usize = 100;

// ============================================================================
// STRUKTURY DANYCH
// ============================================================================

/// Pojedyncze zadanie: plik oczekujący na analizę zawartości po JEDNEJ stronie.
#[derive(Debug, Clone)]
pub(crate) struct Task {
    /// Klucz główny rekordu w tabeli `files`.
    id: i32,
    /// Ścieżka względna liczona od katalogu bazowego danej strony.
    rel_path: String,
    /// `true` gdy plik jest obecny na OBU stronach (`found_in_ufs && found_in_script`).
    /// Decyduje, czy wykryta anomalia trafia do liczników `_common` czy `_unique`
    /// w [`LiveStats`] — patrz dokumentacja modułu.
    is_common: bool,
}

/// Wynik analizy zawartości jednego pliku.
#[derive(Debug, Clone, PartialEq)]
struct AdvancedAnalysis {
    /// Procent bajtów równych `0x00` w całym pliku (wydmuszka HDD po nieudanym odzysku).
    zeros_pct: f64,
    /// Procent bajtów równych `0xFF` w całym pliku (wydmuszka SSD po operacji TRIM).
    ffs_pct: f64,
    /// `Some(true)` = poprawny znacznik końca pliku dla rozpoznanego formatu,
    /// `Some(false)` = ucięty/brakujący znacznik, `None` = format bez zdefiniowanej reguły EOF.
    eof_ok: Option<bool>,
}

/// Wynik przetworzenia jednego zadania, przekazywany przez MPSC do wątku zapisu SQLite.
#[derive(Debug, Clone)]
pub(crate) struct SideAnalysisResult {
    id: i32,
    analysis: Option<AdvancedAnalysis>,
    io_error: Option<bool>,
}

/// Wiadomość do wątku zapisu SQLite, oznaczona stroną pochodzenia.
pub(crate) enum ScanMsg {
    UfsChunk(Vec<SideAnalysisResult>),
    ScriptChunk(Vec<SideAnalysisResult>),
}

/// Liczniki live dla JEDNEJ strony. Trzy kategorie anomalii (zera, FF, EOF) są
/// każda rozbita na `_common`/`_unique` — patrz [`Task::is_common`] i uzasadnienie
/// w dokumentacji modułu. Nigdy nie łączone z licznikami drugiej strony.
pub(crate) struct LiveStats {
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    errors: AtomicUsize,
    ext_weights: Mutex<HashMap<String, u64>>,
    
    /// Ucięte znaczniki EOF w plikach WSPÓLNYCH (obecnych po obu stronach).
    eof_common: AtomicUsize,
    /// Ucięte znaczniki EOF w plikach UNIKALNYCH (obecnych tylko po tej stronie).
    eof_unique: AtomicUsize,
    /// Wydmuszki HDD (>99% zer) w plikach WSPÓLNYCH.
    zero_common: AtomicUsize,
    /// Wydmuszki HDD (>99% zer) w plikach UNIKALNYCH.
    zero_unique: AtomicUsize,
    /// Wydmuszki SSD po TRIM (>99% bajtów 0xFF) w plikach WSPÓLNYCH.
    ffs_common: AtomicUsize,
    /// Wydmuszki SSD po TRIM (>99% bajtów 0xFF) w plikach UNIKALNYCH.
    ffs_unique: AtomicUsize,

    /// EKSPERYMENTALNE (Wariant A): śledzi zajętość logicznych slotów Rayon
    /// TEJ strony podczas czytania i analizy zawartości pliku — patrz moduł
    /// `thread_activity`.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            processed_files: AtomicUsize::new(0),
            processed_bytes: AtomicU64::new(0),
            errors: AtomicUsize::new(0),
            ext_weights: Mutex::new(HashMap::new()),
            eof_common: AtomicUsize::new(0),
            eof_unique: AtomicUsize::new(0),
            zero_common: AtomicUsize::new(0),
            zero_unique: AtomicUsize::new(0),
            ffs_common: AtomicUsize::new(0),
            ffs_unique: AtomicUsize::new(0),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }
}

/// Wylicza liczbę slotów trackera zajętości (Wariant A) odpowiednią dla
/// trybu I/O — patrz identyczna logika w `phase3::compute_activity_slots`.
fn compute_activity_slots(io_mode: &str, actual_threads: usize, half_threads: usize) -> usize {
    if io_mode == "CONCURRENT" { half_threads } else { actual_threads }
}

/// Buduje pełny, samodzielny blok live DLA JEDNEGO ŹRÓDŁA (UFS albo Skrypt) —
/// prędkość MB/s, top 3 rozszerzenia wagowo, oraz trzy kategorie anomalii
/// zawartości, każda rozbita na pliki wspólne/unikalne (patrz [`Task::is_common`]),
/// plus błędy I/O. Bez sumowania z drugą stroną.
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

    let activity_markup = crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot());

    format!(
        "[{}]\nPrędkość: {:.2} MB/s\nTop format: {}\nWydmuszki HDD (zera): {} wspólne / {} unikalne\nWydmuszki SSD (TRIM/0xFF): {} wspólne / {} unikalne\nUcięte EOF: {} wspólne / {} unikalne\nWątki analizy (Wariant A): {}\nBłędy I/O: {}",
        label, speed_mb, display_ext,
        stats.zero_common.load(Ordering::Relaxed), stats.zero_unique.load(Ordering::Relaxed),
        stats.ffs_common.load(Ordering::Relaxed), stats.ffs_unique.load(Ordering::Relaxed),
        stats.eof_common.load(Ordering::Relaxed), stats.eof_unique.load(Ordering::Relaxed),
        activity_markup,
        stats.errors.load(Ordering::Relaxed),
    )
}

// ============================================================================
// LOGIKA BIZNESOWA I RENDEROWANIE (TUI)
// ============================================================================

/// Analizuje CAŁĄ zawartość pliku (nie tylko nagłówek — w przeciwieństwie do
/// Fazy 3/4): liczy procent bajtów `0x00` i `0xFF` w całym strumieniu, oraz
/// weryfikuje znacznik końca pliku (EOF/EOCD) dla rozpoznanych formatów:
/// - JPG/JPEG: ostatnie 2 bajty muszą być `FF D9`,
/// - PDF: ostatni 1 KB musi zawierać tekst `%%EOF` ORAZ `startxref` musi
///   wskazywać na offset w pliku, pod którym faktycznie leży wiarygodna
///   tablica xref (patrz [`pdf_xref_wyglada_na_spojny`]) — samo `%%EOF` bez
///   struktury za nim (np. plik ucięty przed xref, z ocalałym/doklejonym
///   `%%EOF` w ogonie) już NIE wystarcza,
/// - PNG: ostatnie 12 bajtów musi być kanonicznym chunkiem `IEND`,
/// - archiwa ZIP-podobne (docx/xlsx/pptx/odt/ods/odp/epub/apk/jar/zip):
///   ostatnie do 65557 bajtów (maks. rozmiar End-Of-Central-Directory + komentarz)
///   musi zawierać sygnaturę EOCD `50 4B 05 06`.
///
/// Dla formatów bez zdefiniowanej reguły `eof_ok` pozostaje `None` (nie dotyczy,
/// nie błąd). Plik o rozmiarze 0 zwraca `eof_ok: Some(false)` — pusty plik nigdy
/// nie ma poprawnego znacznika końca, niezależnie od rozszerzenia.
fn analyze_file(path: &Path, rel_path: &str) -> std::result::Result<AdvancedAnalysis, std::io::Error> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();

    if file_len == 0 {
        return Ok(AdvancedAnalysis { zeros_pct: 0.0, ffs_pct: 0.0, eof_ok: Some(false) });
    }

    let mut zeros_count: u64 = 0;
    let mut ffs_count: u64 = 0;
    let mut buffer = [0u8; 131_072]; 

    loop {
        // REGRESJA (Gemini review — druga weryfikacja): wcześniej `break` przy
        // anulowaniu w trakcie odczytu zwracał `Ok(AdvancedAnalysis{...})`
        // policzone z NIEPEŁNEGO bufora podzielonego przez PEŁNY `file_len` —
        // sztucznie zaniżony `zeros_pct`/`ffs_pct` bez żadnej flagi
        // niekompletności. Taki błędny wynik trafiał do bazy przez COALESCE
        // tak samo jak pełna analiza (kolumna przestaje być NULL), więc plik
        // nigdy nie był ponownie analizowany przy wznowieniu. Teraz zwracamy
        // `Err(Interrupted)` — wywołujący (`process_side_stream`) rozróżnia to
        // od prawdziwego błędu I/O i NIE zapisuje żadnego wyniku do bazy.
        if CANCEL_SIGNAL.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Przerwano przez użytkownika"));
        }
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        let chunk = &buffer[..n];
        zeros_count += chunk.iter().filter(|&&b| b == 0x00).count() as u64;
        ffs_count += chunk.iter().filter(|&&b| b == 0xFF).count() as u64;
    }

    let zeros_pct = (zeros_count as f64 / file_len as f64) * 100.0;
    let ffs_pct = (ffs_count as f64 / file_len as f64) * 100.0;

    let mut eof_ok = None;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();

    if matches!(ext.as_str(), "jpg" | "jpeg") {
        if file_len >= 2 {
            let mut tail = [0u8; 2];
            if file.seek(SeekFrom::End(-2)).is_ok() && file.read_exact(&mut tail).is_ok() {
                eof_ok = Some(tail == [0xFF, 0xD9]); 
            } else { eof_ok = Some(false); }
        } else { eof_ok = Some(false); }
    } else if ext == "pdf" {
        let read_len = std::cmp::min(file_len, 1024) as i64;
        let mut tail = vec![0u8; read_len as usize];
        if file.seek(SeekFrom::End(-read_len)).is_ok() && file.read_exact(&mut tail).is_ok() {
            let tail_str = String::from_utf8_lossy(&tail);
            eof_ok = Some(tail_str.contains("%%EOF") && pdf_xref_wyglada_na_spojny(&mut file, file_len, &tail_str));
        } else { eof_ok = Some(false); }
    } else if ext == "png" {
        if file_len >= 12 {
            let mut tail = [0u8; 12];
            if file.seek(SeekFrom::End(-12)).is_ok() && file.read_exact(&mut tail).is_ok() {
                eof_ok = Some(tail == [0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
            } else { eof_ok = Some(false); }
        } else { eof_ok = Some(false); }
    } else if matches!(ext.as_str(), "zip" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub" | "apk" | "jar") {
        let read_len = std::cmp::min(file_len, 65557) as i64;
        let mut tail = vec![0u8; read_len as usize];
        if file.seek(SeekFrom::End(-read_len)).is_ok() && file.read_exact(&mut tail).is_ok() {
            eof_ok = Some(tail.windows(4).any(|w| w == b"\x50\x4B\x05\x06"));
        } else { eof_ok = Some(false); }
    } else {
        debug!(path = rel_path, ext = %ext, "brak zdefiniowanej reguły EOF");
    }

    Ok(AdvancedAnalysis { zeros_pct, ffs_pct, eof_ok })
}

/// Sprawdza, czy `startxref` z ogona pliku PDF wskazuje na wiarygodną
/// tablicę xref — klasyczną (`xref` + wpisy przesunięć) albo strumień xref
/// PDF 1.5+ (nagłówek obiektu `N G obj` ze słownikiem zawierającym
/// `/XRef`). NIE dekompresuje strumieni (dane strumienia bywają
/// `FlateDecode`, ale sam słownik obiektu nigdy nie jest skompresowany, więc
/// `/XRef` jest zawsze czytelne wprost) i NIE waliduje KAŻDEGO wpisu tablicy
/// — to ograniczony, ale realny sygnał: potwierdza, że offset ze
/// `startxref` w ogóle mieści się w pliku i trafia w strukturę o kształcie
/// prawdziwego xref, a nie w przypadkowe bajty albo pustkę po ucięciu.
///
/// Znacznie silniejszy test niż samo "gdzieś w ostatnim KB jest tekst
/// %%EOF" — wykrywa typowe uszkodzenie odzysku: plik ucięty PRZED tablicą
/// xref, gdzie sam tekst `%%EOF` przetrwał (np. doklejony z innego miejsca
/// albo pozostałość po nadpisanym trailerze).
fn pdf_xref_wyglada_na_spojny(file: &mut File, file_len: u64, tail_str: &str) -> bool {
    let Some(poz) = tail_str.rfind("startxref") else { return false; };
    let po = &tail_str[poz + "startxref".len()..];
    let cyfry: String = po.chars().skip_while(|c| c.is_whitespace()).take_while(|c| c.is_ascii_digit()).collect();
    let Ok(offset) = cyfry.parse::<u64>() else { return false; };
    if offset >= file_len {
        return false;
    }

    let okno_len = std::cmp::min(file_len - offset, 256) as usize;
    let mut okno = vec![0u8; okno_len];
    if file.seek(SeekFrom::Start(offset)).is_err() || file.read_exact(&mut okno).is_err() {
        return false;
    }

    if okno.starts_with(b"xref") {
        return true;
    }

    let tekst = String::from_utf8_lossy(&okno);
    let slowa: Vec<&str> = tekst.split_whitespace().take(3).collect();
    let wyglada_na_naglowek_obiektu = slowa.len() == 3
        && !slowa[0].is_empty() && slowa[0].chars().all(|c| c.is_ascii_digit())
        && !slowa[1].is_empty() && slowa[1].chars().all(|c| c.is_ascii_digit())
        && slowa[2] == "obj";

    wyglada_na_naglowek_obiektu && tekst.contains("/XRef")
}

/// Skanuje wszystkie zadania (`tasks`) dla JEDNEJ strony: dla każdego pliku
/// czyta CAŁĄ zawartość przez [`analyze_file`] (procent zer/FF + weryfikacja
/// EOF), klasyfikuje wykryte anomalie do liczników `_common`/`_unique` w
/// zależności od [`Task::is_common`], aktualizuje [`LiveStats`] i strumieniuje
/// wyniki do wątku zapisu SQLite. Rozgłasza postęp i statystyki do UI co ~60ms.
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
    pub opr_log: Arc<Mutex<File>>,
}

#[instrument(skip(ctx), fields(base_path = %ctx.base_path.display()))]

fn process_side_stream<'a>(ctx: StreamCtx<'a>) {
    let StreamCtx { base_path, tasks, side_label, stats, tx_db, is_ufs, tx_ui, bar_idx, start_time, opr_log } = ctx;

    tasks.par_chunks(CHUNK_SIZE).for_each_with(tx_db, |tx_db, chunk| {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

        let mut results = Vec::with_capacity(chunk.len());
        let mut local_ext_weights: HashMap<String, u64> = HashMap::new();
        let mut last_ui_update = Instant::now();

        for task in chunk {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

            let full_path: PathBuf = base_path.join(&task.rel_path);
            let ext = Path::new(&task.rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
            let file_size = std::fs::metadata(&full_path).map(|m| m.len()).unwrap_or(0);
            
            *local_ext_weights.entry(ext.clone()).or_insert(0) += file_size;

            let (analysis_opt, io_err) = match stats.thread_activity.track_current(|| analyze_file(&full_path, &task.rel_path)) {
                Ok(a) => {
                    let mut anomalies = Vec::new();
                    
                    if a.zeros_pct > 99.0 {
                        anomalies.push("Wydmuszka HDD (100% Zer)");
                        if task.is_common { stats.zero_common.fetch_add(1, Ordering::Relaxed); } 
                        else { stats.zero_unique.fetch_add(1, Ordering::Relaxed); }
                    }
                    if a.ffs_pct > 99.0 {
                        anomalies.push("Wydmuszka SSD TRIM (Bloki 0xFF)");
                        if task.is_common { stats.ffs_common.fetch_add(1, Ordering::Relaxed); } 
                        else { stats.ffs_unique.fetch_add(1, Ordering::Relaxed); }
                    }
                    if a.eof_ok == Some(false) {
                        anomalies.push("Ucięty Ogon (Brak znacznika EOF/EOCD)");
                        if task.is_common { stats.eof_common.fetch_add(1, Ordering::Relaxed); } 
                        else { stats.eof_unique.fetch_add(1, Ordering::Relaxed); }
                    }

                    if !anomalies.is_empty()
                        && let Ok(mut f) = opr_log.lock() {
                            let kategoria = if task.is_common { "Pula Wspólna" } else { "Pula Unikalna" };
                            let anomalies_str = anomalies.join(", ");
                            let _ = writeln!(f, "[{:<15}] [{:<13}] [{}] Format: .{:<5} | Ścieżka: \"{}\"", side_label, kategoria, anomalies_str, ext, full_path.display());
                        }
                    
                    (Some(a), Some(false))
                },
                // REGRESJA (Gemini review — druga weryfikacja): anulowanie
                // (`ErrorKind::Interrupted`, zwracane teraz przez `analyze_file`
                // przy CANCEL_SIGNAL) trafiało tu wcześniej do tej samej gałęzi
                // co prawdziwy błąd I/O — plik dostawał `io_error_*=1` na
                // stałe, czyli CASE WHEN w `run()` liczył go jako "rozliczony" i
                // nigdy nie wracał do kolejki przy wznowieniu, mimo że w
                // rzeczywistości nie został w ogóle przeanalizowany. Teraz
                // anulowanie nie zapisuje NIC (`None, None`) — COALESCE w
                // zapytaniu UPDATE zostawia `zeros_pct_*`/`io_error_*` bez
                // zmian (nadal NULL przy pierwszym przebiegu), więc plik
                // zostaje wybrany ponownie przy kolejnym uruchomieniu Fazy 6.
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (None, None),
                Err(e) => {
                    warn!(path = %task.rel_path, side = side_label, error = %e, "Błąd I/O podczas czytania zawartości pliku");
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut f) = opr_log.lock() {
                        let kategoria = if task.is_common { "Pula Wspólna" } else { "Pula Unikalna" };
                        let _ = writeln!(f, "[{:<15}] [{:<13}] [Błąd I/O: {}] Format: .{:<5} | Ścieżka: \"{}\"", side_label, kategoria, e, ext, full_path.display());
                    }
                    (None, Some(true))
                }
            };

            let current = stats.processed_files.fetch_add(1, Ordering::Relaxed) + 1;
            stats.processed_bytes.fetch_add(file_size, Ordering::Relaxed);
            
            let now = Instant::now();
            // Hybrydowy próg (identyczny wzorzec jak Faza 5): licznik globalny
            // jako główny wyzwalacz (nie resetuje się na granicy paczki
            // CHUNK_SIZE=100, w przeciwieństwie do last_ui_update deklarowanego
            // raz na paczkę - stąd wcześniejsze "skoki" paska zamiast płynnego
            // przyrostu), plus siatka bezpieczeństwa czasowa na wolne/zawodzące
            // dyski (ta faza czyta CAŁĄ zawartość pliku, nie tylko lstat, więc
            // pojedynczy plik może realnie trwać dłużej niż w Fazie 5).
            let should_update = current.is_multiple_of(200)
                || now.duration_since(last_ui_update).as_millis() > 250;

            if should_update {
                last_ui_update = now; 

                if !local_ext_weights.is_empty() {
                    let mut global_map = stats.ext_weights.lock().unwrap();
                    for (k, v) in local_ext_weights.drain() { *global_map.entry(k).or_insert(0) += v; }
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

            results.push(SideAnalysisResult {
                id: task.id,
                analysis: analysis_opt,
                io_error: io_err,
            });
        }

        if !local_ext_weights.is_empty() {
            let mut global_map = stats.ext_weights.lock().unwrap();
            for (k, v) in local_ext_weights.drain() { *global_map.entry(k).or_insert(0) += v; }
        }

        if !results.is_empty() {
            if is_ufs { let _ = tx_db.send(ScanMsg::UfsChunk(results)); } 
            else { let _ = tx_db.send(ScanMsg::ScriptChunk(results)); }
        }
    });

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: stats.processed_files.load(Ordering::Relaxed) as u64,
        message: "Skanowanie wnętrza plików zakończone.".to_string(),
    });
}

// ============================================================================
// GŁÓWNA FUNKCJA KORDYNUJĄCA (Entrypoint Fazy 6)
// ============================================================================

/// Punkt wejścia Fazy 6, wołany przez `menu::actions::run_phase_with_ui`.
///
/// Przebieg: (1) wczytuje z SQLite zadania — wszystkie pliki obecne po danej
/// stronie, którym brakuje jeszcze analizy zawartości (`eof_ok_ufs`/`_script`
/// IS NULL) i bez zapisanego błędu I/O; oznacza każde zadanie jako `is_common`
/// na podstawie obecności po OBU stronach; (2) uruchamia [`process_side_stream`]
/// dla UFS i Skryptu — równolegle na dwóch dedykowanych pulach Rayon
/// (`half_threads`, patrz dokumentacja modułu) lub sekwencyjnie; (3) koreluje
/// wyniki w SQLite; (4) generuje Dziennik Końcowy (rozkład wydmuszek i uciętych
/// EOF, osobno dla plików wspólnych i unikalnych) do pliku i do UI.
#[instrument(skip(conn, config, tx_ui), fields(ufs_path = %config.ufs_path, script_path = %config.script_path))]
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    crate::utils::CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    // 1. INICJALIZACJA DUAL-LOGGING
    let raport_cfg = config.raporty_faz.get("Faza 6").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza6.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza6.txt".to_string(),
    });
    
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);
    
    // REGRESJA (todo.faza02.md, ta sama klasa błędu we wszystkich fazach):
    // `.unwrap()` panikował, gdyby katalog logów stał się niezapisywalny
    // między `create_dir_all` a tym miejscem — cały bieg fazy ginął z
    // powodu samego logowania, zanim jakikolwiek plik został przetworzony.
    let opr_log_file = match File::create(&opr_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!("BŁĄD I/O: Nie można utworzyć pliku logu operacyjnego: {}. Sprawdź uprawnienia.", e)));
            return Ok(());
        }
    };
    let opr_log = Arc::new(Mutex::new(opr_log_file));
    {
        let mut f = opr_log.lock().unwrap();
        let _ = writeln!(f, "=== RAPORT OPERACYJNY - FAZA 6 (ANALIZA ZAWARTOŚCI I EOF) ===");
        let _ = writeln!(f, "Zestawienie plików uszkodzonych strukturalnie, zgrupowane na Pule Wspólne i Unikalne.");
        let _ = writeln!(f, "Uwzględnia: Puste pliki (Zera/HDD), Wydmuszki po TRIM (FF/SSD) oraz brak znaczników końca pliku.\n");
    }

    let actual_threads = if config.max_threads > 0 { config.max_threads } else { rayon::current_num_threads() };
    let io_text = if config.io_mode == "CONCURRENT" { "RÓWNOLEGŁE (SSD/NVMe)" } else { "SEKWENCYJNIE (HDD)" };
    
    let _ = tx_ui.send(PhaseEvent::Log(format!("Uruchomiono Fazę 6. Metodyka szyny dyskowej: {}", io_text)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora (Rayon): {}", actual_threads)));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    // --- ETAP 1: POBIERANIE ZADAŃ Z BAZY ---
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, zeros_pct_ufs, zeros_pct_script, io_error_ufs, io_error_script 
         FROM files WHERE phase6_done = 0 OR phase6_done IS NULL"
    )?;
    
    let mut ufs_tasks = Vec::new();
    let mut script_tasks = Vec::new();
    let mut skipped_ufs = 0;
    let mut skipped_script = 0;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i32>(0)?, row.get::<_, String>(1)?, 
            row.get::<_, bool>(2)?, row.get::<_, bool>(3)?,
            row.get::<_, Option<f64>>(4)?, row.get::<_, Option<f64>>(5)?,
            row.get::<_, Option<bool>>(6)?, row.get::<_, Option<bool>>(7)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_ufs, in_script, z_ufs, z_scr, err_ufs, err_scr) = r;
        let is_common = in_ufs && in_script;
        
        if in_ufs {
            if z_ufs.is_none() && err_ufs != Some(true) { 
                ufs_tasks.push(Task { id, rel_path: rel.clone(), is_common }); 
            } else {
                skipped_ufs += 1;
            }
        }
        
        if in_script {
            if z_scr.is_none() && err_scr != Some(true) { 
                script_tasks.push(Task { id, rel_path: rel, is_common }); 
            } else {
                skipped_script += 1;
            }
        }
    }
    drop(stmt);

    if skipped_ufs > 0 || skipped_script > 0 {
        let _ = tx_ui.send(PhaseEvent::Log(format!("Pominięto już zbadane pliki. UFS: {}, Skrypt: {}", skipped_ufs, skipped_script)));
    }

    let total_db_rows = ufs_tasks.len() + script_tasks.len();
    if total_db_rows == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak plików wymagających inspekcji strukturalnej. Baza aktualna.".to_string()));
        return Ok(());
    }

    // Inicjalizacja pasków postępu Ratatui
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "UFS Explorer (Skan Wnętrza)".to_string(), total: ufs_tasks.len() as u64, color: Color::Cyan });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 1, label: "Skrypt Autorski (Skan Wnętrza)".to_string(), total: script_tasks.len() as u64, color: Color::Magenta });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 2, label: "Zapis SQLite".to_string(), total: total_db_rows as u64, color: Color::Green });

    let half_threads = std::cmp::max(1, actual_threads / 2);
    let activity_slots = compute_activity_slots(&config.io_mode, actual_threads, half_threads);

    let ufs_stats = LiveStats::new(activity_slots);
    let script_stats = LiveStats::new(activity_slots);

    // --- ETAP 3: PRZETWARZANIE STRUMIENIOWE (MPSC) ---
    // REGRESJA (measure twice — druga weryfikacja Gemini): każdy błąd SQLite
    // w wątku bazy był wcześniej `.unwrap()`, czyli paniką w wątku pisarza
    // wewnątrz `thread::scope`. Ten sam wzorzec co `phase17_repair::run`/
    // `phase1::run`/`phase3::run` — `db_thread` zwraca `Result<()>`, panika
    // jest przechwytywana przez `.join()` i zamieniana na błąd domenowy.
    let wynik_zapisu: Result<()> = std::thread::scope(|s| {
        let (tx_db, rx_db) = mpsc::sync_channel(200);
        let conn_ref = &mut *conn;
        let tx_ui_ref = &tx_ui;

        let db_thread = s.spawn(move || -> Result<()> {
            let mut last_db_update = Instant::now();
            let mut db_inserted = 0;

            for msg in rx_db {
                let chunk_len = match &msg {
                    ScanMsg::UfsChunk(c) => c.len(),
                    ScanMsg::ScriptChunk(c) => c.len(),
                };

                if chunk_len > 0 {
                    let tx_trans = conn_ref.transaction()?;
                    {
                        // OPTYMALIZACJA: prepare_cached
                        let mut stmt = match &msg {
                            ScanMsg::UfsChunk(_) => tx_trans.prepare_cached(
                                "UPDATE files SET zeros_pct_ufs = COALESCE(?1, zeros_pct_ufs), eof_ok_ufs = COALESCE(?2, eof_ok_ufs), io_error_ufs = COALESCE(?3, io_error_ufs) WHERE id = ?4"
                            )?,
                            ScanMsg::ScriptChunk(_) => tx_trans.prepare_cached(
                                "UPDATE files SET zeros_pct_script = COALESCE(?1, zeros_pct_script), eof_ok_script = COALESCE(?2, eof_ok_script), io_error_script = COALESCE(?3, io_error_script) WHERE id = ?4"
                            )?,
                        };
                        
                        let chunk = match &msg {
                            ScanMsg::UfsChunk(c) => c,
                            ScanMsg::ScriptChunk(c) => c,
                        };

                        for res in chunk {
                            if res.analysis.is_some() || res.io_error == Some(true) {
                                // NAPRAWA (patrz dokumentacja modułu, sekcja "zeros_pct vs
                                // ffs_pct"): kolumna `zeros_pct_ufs`/`zeros_pct_script`
                                // przechowuje WYŁĄCZNIE `a.zeros_pct` (prawdziwe zera 0x00).
                                // Wcześniej był tu `.max(a.ffs_pct)`, co spłaszczało DWA
                                // różne sygnały (wydmuszka HDD = zera, wydmuszka SSD/TRIM =
                                // 0xFF) do jednej liczby - Fazy 8/9/diag.rs czytające tę
                                // kolumnę nie miały jak odróżnić TRIM od realnych zer, więc
                                // opisywały plik TRIM jako "wypełniony zerami", co jest
                                // fałszywe kryminalistycznie. `a.ffs_pct` NIE trafia do tej
                                // kolumny - schemat bazy nie dostaje nowej kolumny (zbyt
                                // inwazyjne), za to fakt TRIM pozostaje w opisowym logu per
                                // plik (patrz `anomalies.push("Wydmuszka SSD TRIM...")` w
                                // `process_side_stream`, niezależne od tego zapisu do bazy) i
                                // w zbiorczych licznikach `ffs_common`/`ffs_unique` tej sesji
                                // w Dzienniku Końcowym (ETAP 5, sekcja WYDMUSZKI SSD) - więc
                                // informacja nie znika całkowicie, nawet jeśli sama kolumna
                                // liczbowa zostaje ograniczona do zer.
                                let zeros_only_pct = res.analysis.as_ref().map(|a| a.zeros_pct);
                                stmt.execute(params![
                                    zeros_only_pct,
                                    res.analysis.as_ref().and_then(|a| a.eof_ok),
                                    res.io_error,
                                    res.id
                                ])?;
                            }
                        }
                    }
                    tx_trans.commit()?;
                }

                db_inserted += chunk_len;

                let now = Instant::now();
                if now.duration_since(last_db_update).as_millis() > 60 {
                    last_db_update = now;
                    let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Zapisywanie wskaźników do bazy...".to_string() });
                }
            }
            let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Baza danych zaktualizowana.".to_string() });
            Ok(())
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone(); let tx2 = tx_db.clone();
            let log_u = opr_log.clone(); let log_s = opr_log.clone();

            // Referencje (nie własność) - ufs_stats/script_stats są odczytywane
            // ponownie PO zakończeniu tego bloku (raport końcowy), więc domknięcia
            // `move` mogą przejąć wyłącznie te referencje, nie same struktury.
            let stat_u = &ufs_stats;
            let stat_s = &script_stats;

            // NAPRAWA (ten sam bug jak w Fazie 5, patrz dokumentacja modułu):
            // dedykowana pula per strona, minimum 1 wątek, żeby uniknąć
            // głodzenia jednej strony przez współdzieloną globalną pulę
            // przy niskim actual_threads. Wyliczone wcześniej, tu tylko używane.

            s.spawn(move || {
                if !ufs_tasks.is_empty() {
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: Path::new(&config.ufs_path), tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, start_time, opr_log: log_u, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: Path::new(&config.ufs_path), tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, start_time, opr_log: log_u, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Analiza ciał plików (UFS) zakończona.".to_string()));
                }
            });

            s.spawn(move || {
                if !script_tasks.is_empty() {
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: Path::new(&config.script_path), tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, start_time, opr_log: log_s, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: Path::new(&config.script_path), tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, start_time, opr_log: log_s, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Analiza ciał plików (Skrypt) zakończona.".to_string()));
                }
            });
            drop(tx_db); 
        } else {
            let log_u = opr_log.clone(); let log_s = opr_log.clone();
            if !ufs_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: Path::new(&config.ufs_path), tasks: &ufs_tasks, side_label: "UFS Explorer", stats: &ufs_stats, tx_db: tx_db.clone(), is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, start_time, opr_log: log_u, });
                let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Analiza ciał plików (UFS) zakończona.".to_string()));
            }
            if !script_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: Path::new(&config.script_path), tasks: &script_tasks, side_label: "Skrypt Autorski", stats: &script_stats, tx_db: tx_db.clone(), is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, start_time, opr_log: log_s, });
                let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Analiza ciał plików (Skrypt) zakończona.".to_string()));
            }
            drop(tx_db);
        }

        match db_thread.join() {
            Ok(wynik) => wynik,
            // `join` zwraca `Err` WYŁĄCZNIE gdy wątek spanikował. Sama panika
            // jest już odnotowana przez globalny hook w `logging.rs`, więc tu
            // zamieniamy ją na błąd domenowy, żeby nie rozprzestrzeniała się
            // dalej i żeby wywołujący nie uznał przebiegu za udany.
            Err(_) => {
                let _ = tx_ui.send(PhaseEvent::Log(
                    "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 6 mógł nie zostać w pełni zapisany.".to_string()
                ));
                Err(rusqlite::Error::UnwindingPanic)
            }
        }
    });
    wynik_zapisu?;

    // --- ETAP 4: SYNCHRONIZACJA Z BAZĄ DANYCH ---
    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log("🛑 Skanowanie przerwane przez użytkownika.".to_string()));
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::Log("Trwa wiązanie macierzy w bazie SQLite...".to_string()));
    
    conn.execute(
        "UPDATE files SET phase6_done = CASE 
            WHEN (found_in_ufs = 0 OR zeros_pct_ufs IS NOT NULL OR io_error_ufs = 1) 
             AND (found_in_script = 0 OR zeros_pct_script IS NOT NULL OR io_error_script = 1) THEN 1 
            ELSE 0 
        END WHERE phase6_done = 0 OR phase6_done IS NULL", []
    )?;

    // --- ETAP 5: GENEROWANIE DZIENNIKA KOŃCOWEGO ---
    let mut stmt = conn.prepare(
        "SELECT relative_path, found_in_ufs, found_in_script, zeros_pct_ufs, zeros_pct_script, eof_ok_ufs, eof_ok_script 
         FROM files WHERE phase6_done = 1"
    )?;

    let mut ufs_z_com = 0; let mut ufs_z_uni = 0;
    let mut scr_z_com = 0; let mut scr_z_uni = 0;
    
    let mut ufs_e_com = 0; let mut ufs_e_uni = 0;
    let mut scr_e_com = 0; let mut scr_e_uni = 0;

    let mut spoofing_matrix_ufs: HashMap<String, Vec<String>> = HashMap::new();
    let mut spoofing_matrix_script: HashMap<String, Vec<String>> = HashMap::new();

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?, row.get::<_, bool>(1)?, row.get::<_, bool>(2)?,
            row.get::<_, Option<f64>>(3)?, row.get::<_, Option<f64>>(4)?,
            row.get::<_, Option<bool>>(5)?, row.get::<_, Option<bool>>(6)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (rel_path, in_ufs, in_scr, z_ufs, z_scr, e_ufs, e_scr) = r;
        let is_common = in_ufs && in_scr;
        let ext = Path::new(&rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();

        if in_ufs {
            if let Some(z) = z_ufs && z > 99.0 { if is_common { ufs_z_com += 1; } else { ufs_z_uni += 1; } }
            if e_ufs == Some(false) { 
                if is_common { ufs_e_com += 1; } else { ufs_e_uni += 1; } 
                spoofing_matrix_ufs.entry(ext.clone()).or_default().push(rel_path.clone());
            }
        }

        if in_scr {
            if let Some(z) = z_scr && z > 99.0 { if is_common { scr_z_com += 1; } else { scr_z_uni += 1; } }
            if e_scr == Some(false) { 
                if is_common { scr_e_com += 1; } else { scr_e_uni += 1; } 
                spoofing_matrix_script.entry(ext.clone()).or_default().push(rel_path);
            }
        }
    }
    drop(stmt);

    let elapsed = start_time.elapsed();
    let total_bytes = ufs_stats.processed_bytes.load(Ordering::SeqCst) + script_stats.processed_bytes.load(Ordering::SeqCst);
    let avg_speed_mb = (total_bytes as f64 / 1_048_576.0) / elapsed.as_secs_f64().max(1.0);
    let total_io_errors = ufs_stats.errors.load(Ordering::SeqCst) + script_stats.errors.load(Ordering::SeqCst);

    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(&mut log_out, "==========================================================================");
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 6 (ANALIZA ZAWARTOŚCI I ZNACZNIKÓW EOF)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "Sumaryczny transfer I/O: {} (Średnia prędkość: {:.2} MB/s)", format_bytes(total_bytes), avg_speed_mb);
    let _ = writeln!(&mut log_out, "==========================================================================\n");

    if ufs_z_com > 0 || ufs_z_uni > 0 || scr_z_com > 0 || scr_z_uni > 0 {
        let _ = writeln!(&mut log_out, "[ 1 ] ANALIZA WYDMUSZEK (Puste pliki HDD i SSD):");
        let _ = writeln!(&mut log_out, "   -> UFS Explorer:    {} (Pula Wspólna), {} (Pula Unikalna)", ufs_z_com, ufs_z_uni);
        let _ = writeln!(&mut log_out, "   -> Skrypt Autorski: {} (Pula Wspólna), {} (Pula Unikalna)", scr_z_com, scr_z_uni);
        let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Plik jest widoczny na dysku, zachował oryginalną nazwę i rozmiar,");
        let _ = writeln!(&mut log_out, "      ale wewnątrz nie posiada żadnych danych użytkownika.");
        let _ = writeln!(&mut log_out, "      * Wydmuszka HDD (Zera) powstaje przy uszkodzonej alokacji przestrzeni.");
        let _ = writeln!(&mut log_out, "      * Wydmuszka SSD (Bloki 0xFF) to efekt zadziałania komendy TRIM po usunięciu pliku.\n");
    } else {
        let _ = writeln!(&mut log_out, "[ 1 ] ANALIZA WYDMUSZEK: ✔ Brak. Pliki zawierają prawdziwe dane.\n");
    }

    if ufs_e_com > 0 || ufs_e_uni > 0 || scr_e_com > 0 || scr_e_uni > 0 {
        let _ = writeln!(&mut log_out, "[ 2 ] ANALIZA ZNACZNIKÓW KOŃCA PLIKU (Brak ogona EOF / EOCD):");
        let _ = writeln!(&mut log_out, "   -> UFS Explorer:    {} (Pula Wspólna), {} (Pula Unikalna)", ufs_e_com, ufs_e_uni);
        let _ = writeln!(&mut log_out, "   -> Skrypt Autorski: {} (Pula Wspólna), {} (Pula Unikalna)", scr_e_com, scr_e_uni);
        let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Pliki strukturalne (np. JPG, PDF, ZIP, DOCX) wymagają do poprawnego");
        let _ = writeln!(&mut log_out, "      działania specjalnego kodu binarnego na samym końcu. Jego brak wskazuje, że plik");
        let _ = writeln!(&mut log_out, "      jest ucięty (np. zdjęcie załaduje się tylko do połowy).\n");
        
        let add_spoof_to_log = |out_str: &mut String, map: &HashMap<String, Vec<String>>, label: &str| {
            if !map.is_empty() {
                let _ = writeln!(out_str, "   -> MACIERZ USZKODZEŃ EOF ({})", label);
                let mut sorted: Vec<_> = map.iter().collect();
                sorted.sort_by_key(|a| std::cmp::Reverse(a.1.len())); 
                for (ext, paths) in sorted.into_iter().take(5) {
                    let _ = writeln!(out_str, "      Rozszerzenie .{:<5} | Liczba: {} | Przykład: {}", ext, paths.len(), paths.first().unwrap_or(&"".to_string()));
                }
            }
        };
        add_spoof_to_log(&mut log_out, &spoofing_matrix_ufs, "UFS Explorer");
        add_spoof_to_log(&mut log_out, &spoofing_matrix_script, "Skrypt Autorski");
    } else {
        let _ = writeln!(&mut log_out, "[ 2 ] ANALIZA ZNACZNIKÓW EOF: ✔ Brak. Wszystkie obsługiwane pliki posiadają ogony.");
    }

    // PRZYWRÓCONE: Zestawienie wagowe zeskanowanych formatów (TOP 5)
    let _ = writeln!(&mut log_out, "\n[ 3 ] WSZYSTKIE PRZESKANOWANE FORMATY (Zestawienie wagowe):");
    let print_all_exts = |out_str: &mut String, map: &HashMap<String, u64>, label: &str| {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        let _ = writeln!(out_str, "   [ {} ]", label);
        if sorted.is_empty() { let _ = writeln!(out_str, "      Brak plików."); }
        for (ext, weight) in sorted.into_iter().take(5) { 
            let e = if ext == "brak" { "brak".to_string() } else { format!(".{}", ext) };
            let _ = writeln!(out_str, "      - {:<8} : {}", e, format_bytes(*weight));
        }
    };
    print_all_exts(&mut log_out, &ufs_stats.ext_weights.lock().unwrap(), "UFS Explorer");
    print_all_exts(&mut log_out, &script_stats.ext_weights.lock().unwrap(), "Skrypt Autorski");

    if total_io_errors > 0 {
        let _ = writeln!(&mut log_out, "\n[ 🚨 ] BŁĘDY FIZYCZNE I/O (Brak dostępu / Bad Sectory):");
        let _ = writeln!(&mut log_out, "   -> Odmowy dostępu na dysku UFS Explorer:        {}", ufs_stats.errors.load(Ordering::SeqCst));
        let _ = writeln!(&mut log_out, "   -> Odmowy dostępu na dysku Skryptu:             {}", script_stats.errors.load(Ordering::SeqCst));
    }

    // Zapis do fizycznego pliku "Dziennik Końcowy" na podstawie konfiguracji Dual-Logging
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
        ufs_z_com, ufs_z_uni, scr_z_com, scr_z_uni,
        total_io_errors,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 6 zakończona"
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
    // compute_activity_slots (identyczna logika z Fazy 3/4/5)
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_activity_slots_concurrent_uses_half_threads() {
        assert_eq!(compute_activity_slots("CONCURRENT", 4, 2), 2);
    }

    #[test]
    fn test_compute_activity_slots_sequential_uses_full_actual_threads() {
        assert_eq!(compute_activity_slots("SEQUENTIAL", 4, 2), 4);
    }

    /// Pomocnik: tworzy plik tymczasowy z podaną zawartością i wymuszonym
    /// rozszerzeniem (analyze_file czyta rozszerzenie z realnej ścieżki na
    /// dysku, więc samo NamedTempFile - zwykle bez rozszerzenia - nie wystarczy).
    fn temp_file_with_ext(content: &[u8], ext: &str) -> (NamedTempFile, PathBuf) {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(content).unwrap();
        let new_path = temp_file.path().with_extension(ext);
        std::fs::rename(temp_file.path(), &new_path).unwrap();
        (temp_file, new_path)
    }

    // ------------------------------------------------------------------
    // analyze_file - wykrywanie wydmuszek (zera / 0xFF)
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_file_all_zeros_is_hdd_wydmuszka() {
        let content = vec![0x00u8; 4096];
        let (_guard, path) = temp_file_with_ext(&content, "dat");
        let result = analyze_file(&path, "test.dat").unwrap();
        assert!(result.zeros_pct > 99.0);
        assert_eq!(result.ffs_pct, 0.0);
    }

    #[test]
    fn test_analyze_file_all_ff_is_ssd_trim_wydmuszka() {
        let content = vec![0xFFu8; 4096];
        let (_guard, path) = temp_file_with_ext(&content, "dat");
        let result = analyze_file(&path, "test.dat").unwrap();
        assert!(result.ffs_pct > 99.0);
        assert_eq!(result.zeros_pct, 0.0);
    }

    // ------------------------------------------------------------------
    // REGRESJA (Gemini review — druga weryfikacja): anulowanie (CANCEL_SIGNAL)
    // w trakcie czytania zawartości pliku nie może być mylone z prawdziwym
    // błędem I/O — inaczej plik dostaje trwałe `io_error_*=1` mimo że nigdy
    // nie został faktycznie zbadany, i nie wraca do kolejki przy wznowieniu.
    // Wzorzec identyczny z `phase7::tests::test_calculate_entropy_zwraca_interrupted_gdy_cancel_signal_ustawiony`.
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_file_zwraca_interrupted_gdy_cancel_signal_ustawiony() {
        let content = vec![0u8; 500_000];
        let (_guard, path) = temp_file_with_ext(&content, "dat");

        CANCEL_SIGNAL.store(true, Ordering::Relaxed);
        let wynik = analyze_file(&path, "test.dat");
        CANCEL_SIGNAL.store(false, Ordering::Relaxed); // sprzątanie - stan globalny

        match wynik {
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::Interrupted),
            Ok(_) => panic!("oczekiwano Err(Interrupted) przy ustawionym CANCEL_SIGNAL"),
        }
    }

    /// Dowodzi, że wywołujący (`process_side_stream`) faktycznie rozróżnia
    /// `Interrupted` od prawdziwego błędu I/O na poziomie CAŁEGO strumienia:
    /// gdy CANCEL_SIGNAL włącza się W TRAKCIE czytania dużego pliku, zadanie
    /// nie trafia do bazy z `io_error=true` ani nie zwiększa licznika błędów —
    /// zostaje po prostu pominięte (żeby wrócić do kolejki przy wznowieniu).
    /// Odtwarza scenariusz Ctrl+C w środku odczytu (nie na granicy pliku),
    /// stąd plik dostatecznie duży, by wątek zdążył ustawić flagę zanim
    /// `analyze_file` skończy czytać.
    #[test]
    fn test_process_side_stream_przerwanie_w_trakcie_odczytu_nie_jest_bledem_io() {
        let content = vec![0u8; 20_000_000]; // 20 MB - wielokrotność bufora 128 KB
        let (_guard, path) = temp_file_with_ext(&content, "dat");
        let base_path = path.parent().unwrap().to_path_buf();
        let rel_path = path.file_name().unwrap().to_string_lossy().to_string();

        CANCEL_SIGNAL.store(false, Ordering::Relaxed);
        let przelacznik = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(5));
            CANCEL_SIGNAL.store(true, Ordering::Relaxed);
        });

        let stats = LiveStats::new(1);
        let (tx_db, rx_db) = mpsc::sync_channel(10);
        let (tx_ui, _rx_ui) = mpsc::channel();
        let opr_log = Arc::new(Mutex::new(tempfile::tempfile().unwrap()));
        let tasks = vec![Task { id: 1, rel_path, is_common: false }];

        process_side_stream(StreamCtx {
            base_path: &base_path, tasks: &tasks, side_label: "UFS Explorer", stats: &stats,
            tx_db, is_ufs: true, tx_ui: &tx_ui, bar_idx: 0, start_time: Instant::now(), opr_log,
        });

        przelacznik.join().unwrap();
        CANCEL_SIGNAL.store(false, Ordering::Relaxed); // sprzątanie - stan globalny

        assert_eq!(stats.errors.load(Ordering::Relaxed), 0, "Anulowanie nie może zwiększać licznika błędów I/O");

        // Zadanie mogło albo nie zostać w ogóle wysłane (przerwane na granicy
        // pliku/paczki), albo zostać wysłane z (None, None) - obie sytuacje są
        // poprawne, jedyne co jest ZABRONIONE to io_error=Some(true).
        if let Ok(ScanMsg::UfsChunk(wyniki)) = rx_db.try_recv() {
            for w in wyniki {
                assert_ne!(w.io_error, Some(true), "Anulowanie NIE MOŻE zapisać trwałego io_error=true - plik nigdy by nie wrócił do kolejki");
            }
        }
    }

    #[test]
    fn test_analyze_file_mixed_content_no_wydmuszka() {
        let content: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let (_guard, path) = temp_file_with_ext(&content, "dat");
        let result = analyze_file(&path, "test.dat").unwrap();
        assert!(result.zeros_pct < 99.0);
        assert!(result.ffs_pct < 99.0);
    }

    #[test]
    fn test_analyze_file_empty_file_eof_false() {
        let (_guard, path) = temp_file_with_ext(b"", "jpg");
        let result = analyze_file(&path, "test.jpg").unwrap();
        assert_eq!(result.eof_ok, Some(false));
        assert_eq!(result.zeros_pct, 0.0);
        assert_eq!(result.ffs_pct, 0.0);
    }

    // ------------------------------------------------------------------
    // analyze_file - weryfikacja znaczników EOF per format
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_file_jpeg_correct_eof_marker() {
        let mut content = vec![0xFFu8, 0xD8, 0xFF, 0xE0]; // nagłówek JPEG
        content.extend(vec![0x41u8; 100]); // wypełniacz
        content.extend_from_slice(&[0xFF, 0xD9]); // poprawny znacznik końca
        let (_guard, path) = temp_file_with_ext(&content, "jpg");
        let result = analyze_file(&path, "test.jpg").unwrap();
        assert_eq!(result.eof_ok, Some(true));
    }

    #[test]
    fn test_analyze_file_jpeg_truncated_missing_eof_marker() {
        let mut content = vec![0xFFu8, 0xD8, 0xFF, 0xE0];
        content.extend(vec![0x41u8; 100]);
        content.extend_from_slice(&[0x00, 0x00]); // ucięty - brak FF D9
        let (_guard, path) = temp_file_with_ext(&content, "jpg");
        let result = analyze_file(&path, "test.jpg").unwrap();
        assert_eq!(result.eof_ok, Some(false));
    }

    #[test]
    fn test_analyze_file_png_correct_iend_chunk() {
        let mut content = vec![0x89u8, b'P', b'N', b'G'];
        content.extend(vec![0x00u8; 50]);
        // Kanoniczny chunk IEND: długość(0) + "IEND" + CRC
        content.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
        let (_guard, path) = temp_file_with_ext(&content, "png");
        let result = analyze_file(&path, "test.png").unwrap();
        assert_eq!(result.eof_ok, Some(true));
    }

    #[test]
    fn test_analyze_file_png_missing_iend_chunk() {
        let mut content = vec![0x89u8, b'P', b'N', b'G'];
        content.extend(vec![0x00u8; 60]); // brak poprawnego IEND na końcu
        let (_guard, path) = temp_file_with_ext(&content, "png");
        let result = analyze_file(&path, "test.png").unwrap();
        assert_eq!(result.eof_ok, Some(false));
    }

    /// REGRESJA (świadoma zmiana zachowania, nie luka): to dawny
    /// `test_analyze_file_pdf_contains_eof_marker` — fixture ma tekst
    /// `%%EOF`, ale ZERO struktury xref za nim. Dokładnie to jest luka,
    /// którą `pdf_xref_wyglada_na_spojny` zamyka: sam tekst `%%EOF` już nie
    /// wystarcza, żeby uznać PDF za zdrowy.
    #[test]
    fn test_analyze_file_pdf_samo_eof_bez_xref_juz_nie_wystarcza() {
        let mut content = b"%PDF-1.4\n".to_vec();
        content.extend(vec![0x41u8; 100]);
        content.extend_from_slice(b"\n%%EOF");
        let (_guard, path) = temp_file_with_ext(&content, "pdf");
        let result = analyze_file(&path, "test.pdf").unwrap();
        assert_eq!(result.eof_ok, Some(false), "%%EOF bez wiarygodnego startxref/xref nie może dawać Some(true)");
    }

    #[test]
    fn test_analyze_file_pdf_missing_eof_marker() {
        let mut content = b"%PDF-1.4\n".to_vec();
        content.extend(vec![0x41u8; 100]); // brak %%EOF w ogóle
        let (_guard, path) = temp_file_with_ext(&content, "pdf");
        let result = analyze_file(&path, "test.pdf").unwrap();
        assert_eq!(result.eof_ok, Some(false));
    }

    /// Buduje minimalny, ale STRUKTURALNIE poprawny PDF z klasyczną tablicą
    /// `xref` — offset w `startxref` wyliczony programowo (pozycja bajtu,
    /// gdzie faktycznie zaczyna się `xref`), nie ręcznie policzona stała.
    fn zbuduj_pdf_z_klasycznym_xref() -> Vec<u8> {
        let mut tresc = Vec::new();
        tresc.extend_from_slice(b"%PDF-1.4\n");
        tresc.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");

        let xref_offset = tresc.len();
        tresc.extend_from_slice(b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n");
        tresc.extend_from_slice(b"trailer\n<< /Size 2 /Root 1 0 R >>\n");
        tresc.extend_from_slice(format!("startxref\n{}\n%%EOF", xref_offset).as_bytes());
        tresc
    }

    #[test]
    fn test_analyze_file_pdf_z_wiarygodnym_xref_klasycznym_przechodzi() {
        let content = zbuduj_pdf_z_klasycznym_xref();
        let (_guard, path) = temp_file_with_ext(&content, "pdf");
        let result = analyze_file(&path, "test.pdf").unwrap();
        assert_eq!(result.eof_ok, Some(true), "startxref wskazuje na prawdziwą tablicę xref - musi przejść");
    }

    #[test]
    fn test_analyze_file_pdf_ze_strumieniem_xref_przechodzi() {
        let mut tresc = Vec::new();
        tresc.extend_from_slice(b"%PDF-1.7\n");
        tresc.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");

        let xref_offset = tresc.len();
        tresc.extend_from_slice(b"2 0 obj\n<< /Type /XRef /Size 2 /Filter /FlateDecode /Length 4 >>\nstream\n");
        tresc.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // tresc strumienia - dowolne bajty, bez dekompresji
        tresc.extend_from_slice(b"\nendstream\nendobj\n");
        tresc.extend_from_slice(format!("startxref\n{}\n%%EOF", xref_offset).as_bytes());

        let (_guard, path) = temp_file_with_ext(&tresc, "pdf");
        let result = analyze_file(&path, "test.pdf").unwrap();
        assert_eq!(result.eof_ok, Some(true), "startxref wskazuje na obiekt-strumień xref (/XRef) - musi przejść");
    }

    /// Typowe uszkodzenie odzysku: liczba w `startxref` przetrwała (bo leży
    /// w ogonie pliku razem z `%%EOF`), ale to, na co wskazuje, zostało
    /// ucięte razem z resztą pliku.
    #[test]
    fn test_analyze_file_pdf_startxref_wskazuje_poza_plik_jest_odrzucany() {
        let mut content = b"%PDF-1.4\n".to_vec();
        content.extend(vec![0x41u8; 50]);
        content.extend_from_slice(b"\nstartxref\n999999\n%%EOF");
        let (_guard, path) = temp_file_with_ext(&content, "pdf");
        let result = analyze_file(&path, "test.pdf").unwrap();
        assert_eq!(result.eof_ok, Some(false), "startxref poza granicami pliku nie może dawać Some(true)");
    }

    #[test]
    fn test_analyze_file_pdf_startxref_wskazuje_na_smieci_jest_odrzucany() {
        let mut content = b"%PDF-1.4\n".to_vec();
        content.extend(vec![0x41u8; 50]); // offset 9 wskaże w te smieci, nie w xref
        content.extend_from_slice(b"\nstartxref\n9\n%%EOF");
        let (_guard, path) = temp_file_with_ext(&content, "pdf");
        let result = analyze_file(&path, "test.pdf").unwrap();
        assert_eq!(result.eof_ok, Some(false), "startxref wskazujący w przypadkowe bajty nie może dawać Some(true)");
    }

    #[test]
    fn test_analyze_file_zip_like_contains_eocd_signature() {
        let mut content = vec![0x50u8, 0x4B, 0x03, 0x04]; // lokalny nagłówek pliku ZIP
        content.extend(vec![0x00u8; 50]);
        content.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // sygnatura EOCD
        content.extend(vec![0x00u8; 18]); // reszta rekordu EOCD
        let (_guard, path) = temp_file_with_ext(&content, "docx");
        let result = analyze_file(&path, "test.docx").unwrap();
        assert_eq!(result.eof_ok, Some(true));
    }

    #[test]
    fn test_analyze_file_zip_like_missing_eocd_signature() {
        let mut content = vec![0x50u8, 0x4B, 0x03, 0x04];
        content.extend(vec![0x00u8; 68]); // brak sygnatury EOCD gdziekolwiek
        let (_guard, path) = temp_file_with_ext(&content, "zip");
        let result = analyze_file(&path, "test.zip").unwrap();
        assert_eq!(result.eof_ok, Some(false));
    }

    #[test]
    fn test_analyze_file_unknown_extension_no_eof_rule() {
        let content = vec![0x41u8; 100];
        let (_guard, path) = temp_file_with_ext(&content, "bin");
        let result = analyze_file(&path, "test.bin").unwrap();
        assert_eq!(result.eof_ok, None, "Rozszerzenie bez zdefiniowanej reguły EOF powinno dać None");
    }

    // ------------------------------------------------------------------
    // build_source_block
    // ------------------------------------------------------------------

    #[test]
    fn test_build_source_block_reports_common_and_unique_separately() {
        let stats = LiveStats::new(4);
        stats.zero_common.store(3, Ordering::Relaxed);
        stats.zero_unique.store(7, Ordering::Relaxed);
        stats.ffs_common.store(1, Ordering::Relaxed);
        stats.ffs_unique.store(2, Ordering::Relaxed);
        stats.eof_common.store(4, Ordering::Relaxed);
        stats.eof_unique.store(5, Ordering::Relaxed);
        stats.errors.store(1, Ordering::Relaxed);

        let start_time = Instant::now() - Duration::from_secs(1);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        assert!(block.starts_with("[UFS Explorer]"));
        assert!(block.contains("Wydmuszki HDD (zera): 3 wspólne / 7 unikalne"));
        assert!(block.contains("Wydmuszki SSD (TRIM/0xFF): 1 wspólne / 2 unikalne"));
        assert!(block.contains("Ucięte EOF: 4 wspólne / 5 unikalne"));
        assert!(block.contains("Błędy I/O: 1"));
    }

    #[test]
    fn test_build_source_block_shows_thread_activity_markup() {
        let stats = LiveStats::new(2);
        stats.thread_activity.mark_busy(1);

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("Skrypt Autorski", &stats, start_time);

        let line = block.lines().find(|l| l.starts_with("Wątki analizy")).expect("powinna istnieć linia Wariantu A");
        assert_eq!(line, "Wątki analizy (Wariant A): {R:1} {G:2}");
    }

    #[test]
    fn test_build_source_block_empty_ext_weights_shows_placeholder() {
        let stats = LiveStats::new(4);
        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("Skrypt Autorski", &stats, start_time);
        assert!(block.contains("Top format: Analiza danych..."));
    }

    #[test]
    fn test_build_source_block_does_not_leak_other_side_data() {
        let stats = LiveStats::new(4);
        stats.zero_unique.store(99, Ordering::Relaxed);
        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("Skrypt Autorski", &stats, start_time);
        assert!(block.contains("Wydmuszki HDD (zera): 0 wspólne / 99 unikalne"));
    }
}
