// src/phases/phase14.rs

//! # Faza 14: Rozmyte Hashowanie i Ekstremalna Korelacja Krzyżowa
//!
//! Algorytm CTPH używany do znajdowania podobieństw, badania różnic objętości (Delta Size)
//! i wyłapywania pomyłek w rozszerzeniach (Cross-Extension Matching) między programami.
//! Wykorzystuje Memory Mapping (mmap) chroniąc RAM. Posiada system logowania Ratatui i Dual-Logging.
//!
//! UWAGA ARCHITEKTONICZNA: w przeciwieństwie do Faz 1-13, ta faza ma DWA
//! zupełnie różne etapy obliczeniowe:
//! - **Etap 1 (hashowanie, [`process_side_stream`])**: standardowy wzorzec
//!   dwustronny UFS/Skrypt z dedykowanymi pulami Rayon (`half_threads`) — jak
//!   w poprzednich fazach.
//! - **Etap 4 (korelacja krzyżowa, w [`run`])**: NIE ma podziału UFS/Skrypt
//!   jako dwóch stron do zrównoleglenia — zamiast tego dla plików WSPÓLNYCH
//!   porównuje UFS-wersję ze Skrypt-wersją TEGO SAMEGO pliku (pętla
//!   sekwencyjna), a dla plików UNIKALNYCH robi porównanie "każdy z każdym"
//!   (`unique_ufs` × `unique_scr`, złożoność O(n×m)) na jednej, płaskiej puli
//!   równoległej Rayon (`par_iter`) — half_threads nie ma tu zastosowania,
//!   bo nie ma dwóch stron do podziału, jest jedno zadanie do zrównoleglenia.
//!
//! NAPRAWIONY BUG (bezpieczeństwo/UX): pętle korelacji w Etapie 4 (zarówno
//! sekwencyjna po plikach wspólnych, jak i równoległa po unikalnych) NIE
//! sprawdzały `CANCEL_SIGNAL` w ogóle — Ctrl+C podczas tego etapu (który dla
//! dużej liczby plików unikalnych może trwać najdłużej ze wszystkich w
//! całej fazie, ze względu na złożoność O(n×m)) nie miał żadnego efektu.
//! Teraz obie pętle reagują na anulowanie.
//!
//! NAPRAWIONY BUG (rozjazd dokumentacji): stała kontrolująca próg fallbacku
//! `fs::read_to_end` (gdy `mmap` zawiedzie) miała komentarz mówiący "50 MB",
//! podczas gdy wartość wynosiła `1024*1024*1024` (1 GB). Wartość była
//! prawdopodobnie poprawna, komentarz nieaktualny. Rozwiązane przez
//! przeniesienie do konfigurowalnego ustawienia `config.fuzzy_hash_fallback_max_mb`
//! (domyślnie 1024 MB = zachowanie dotychczasowe) — użytkownik decyduje
//! świadomie, zamiast zgadywać z komentarza.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::{CANCEL_SIGNAL, format_bytes, format_display_path};
use ratatui::style::Color;
use rayon::prelude::*;
use rusqlite::{Connection, Result, params};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;
use tracing::{info, instrument, warn};

const CHUNK_SIZE: usize = 100;

// ============================================================================
// POMOCNIKI I STRUKTURY DANYCH (CZYSTE FUNKCJE - PEŁNA TESTOWALNOŚĆ)
// ============================================================================

/// Formatuje różnicę wagi (bajty) ze znakiem: dodatnia różnica dostaje
/// jawny prefiks `+` (ujemna ma już `-` z natury formatowania liczby),
/// wartość bezwzględna przepuszczana przez [`format_bytes`] dla czytelności.
fn format_delta(bytes: i64) -> String {
    let sign = if bytes > 0 { "+" } else { "" };
    format!("{}{}", sign, format_bytes(bytes.unsigned_abs()))
}

/// Mapuje rozszerzenie pliku na szeroką kategorię tematyczną, używaną
/// wyłącznie do grupowania w raporcie końcowym (nie wpływa na żadną decyzję
/// klasyfikacyjną). Rozszerzenia spoza znanych list trafiają do `"inny"`,
/// dosłowny brak rozszerzenia (`"brak"`) ma własną etykietę.
fn get_file_category(ext: &str) -> &'static str {
    match ext {
        "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" => "archiwum",
        "docx" | "xlsx" | "pptx" | "pdf" | "odt" | "ods" | "csv" => "dokument",
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "heic" | "heif" | "dng" => "obraz",
        "mp4" | "mkv" | "avi" | "mov" | "webm" | "flv" | "wmv" => "wideo",
        "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" => "audio",
        "txt" | "json" | "xml" | "py" | "rs" | "js" | "html" | "css" | "sh" => "tekst/kod",
        "exe" | "dll" | "so" | "elf" | "bin" | "apk" | "jar" => "wykonywalny",
        "brak" => "brak rozsz.",
        _ => "inny",
    }
}

/// Klasyfikuje wynik porównania ssdeep DWÓCH WERSJI TEGO SAMEGO pliku (ta
/// sama ścieżka względna, obecna po obu stronach — UFS vs Skrypt). W tym
/// kontekście `0%` dopasowania JEST anomalią (zlepek śmieci — dwa
/// niepowiązane fragmenty danych pod tą samą nazwą), bo oczekujemy wysokiego
/// podobieństwa dla pliku o tej samej nazwie/ścieżce odzyskanego dwoma
/// niezależnymi programami. Próg `HIGH` (≥90%) nie jest osobno raportowany
/// jako anomalia — to oczekiwany, zdrowy wynik.
///
/// UWAGA NAZEWNICTWA: wartość `"FRANKENSTEIN"` zwracana stąd i zapisywana w
/// `phase14_analysis.match_type` NIE ZMIENIŁA SIĘ (stabilny identyfikator
/// techniczny, czytany też przez `write_category_block`/raport końcowy) —
/// w UI/Dzienniku Końcowym/panelu bocznym wyświetlana jest pod czytelniejszą
/// nazwą "Zlepek Binarny"/"Zlepki Binarne". Żeby odnaleźć te wpisy wprost:
/// `SELECT * FROM phase14_analysis WHERE match_type = 'FRANKENSTEIN'`, albo
/// plik `raport_operacyjny_faza14_frankensteiny.txt` (nazwa pliku również
/// celowo niezmieniona, dla łatwego grep).
fn classify_common_match_score(score: u32) -> &'static str {
    if score == 0 {
        "FRANKENSTEIN"
    } else if score < 90 {
        "PARTIAL"
    } else {
        "HIGH"
    }
}

/// Próg odcięcia szumu CTPH dla korelacji plików UNIKALNYCH. ssdeep
/// notorycznie zwraca niskie, przypadkowe dopasowania (kilka-kilkanaście
/// procent) między zupełnie niepowiązanymi plikami binarnymi — to znany
/// artefakt rolling-hash CTPH, nie sygnał realnego pokrewieństwa.
/// `match_type == "PARTIAL"` jest bramką do FIZYCZNEGO zszycia bajtów
/// (patrz `repair_modules::splice`), więc próg musi leżeć wyraźnie powyżej
/// typowego poziomu szumu, nie tuż nad zerem — błąd klasyfikacji tutaj
/// oznacza sklejenie dwóch niepowiązanych dowodów w jeden plik.
const UNIQUE_MATCH_NOISE_FLOOR: u32 = 25;

/// Klasyfikuje wynik korelacji krzyżowej DWÓCH RÓŻNYCH plików unikalnych
/// (różne ścieżki, potencjalnie różne nazwy, znalezione tylko po jednej
/// stronie). Tu wynik poniżej [`UNIQUE_MATCH_NOISE_FLOOR`] to zwykły BRAK
/// dopasowania (`"NONE"`), NIE anomalia — zdecydowana większość
/// przypadkowych par plików unikalnych będzie miała zerowe lub szumowe
/// podobieństwo, to oczekiwane, nie podejrzane (w przeciwieństwie do
/// [`classify_common_match_score`], gdzie ta sama ścieżka uzasadnia wyższe
/// oczekiwania).
fn classify_unique_match_score(score: u32) -> &'static str {
    if score >= 90 {
        "TWIN"
    } else if score >= UNIQUE_MATCH_NOISE_FLOOR {
        "PARTIAL"
    } else {
        "NONE"
    }
}

/// Buduje wpisy `db_updates` dla KAŻDEGO pliku unikalnego strony Skrypt —
/// symetrycznie do wyników korelacji UFS-owej. Czysta funkcja (bez I/O),
/// więc testowalna bez bazy/dysku.
///
/// NAPRAWIONY BUG: wcześniej strona Skrypt (`unique_scr`) służyła w
/// korelacji krzyżowej WYŁĄCZNIE jako bierny zbiór porównawczy — żaden plik
/// unikalny dla Skryptu nigdy nie dostawał własnego wpisu `phase14_done=1`,
/// więc był bez końca ponownie kolejkowany do korelacji przy każdym
/// uruchomieniu fazy, a moduł zszywania w Fazie 17 nigdy nie widział go
/// jako kandydata — mimo że po stronie UFS mógł istnieć bliźniak z
/// `twin_file_path` wskazującym właśnie na niego. Ta funkcja gwarantuje, że
/// KAŻDY `id` z `unique_scr_ids` dostaje dokładnie jeden wpis: albo z
/// najlepszym znalezionym dopasowaniem (`scr_best`), albo jawne "NONE".
/// Decyduje, czy wolno zapisać symetryczne wpisy dla strony Skrypt (patrz
/// [`buduj_symetryczne_wpisy_skryptu`]) po zakończeniu korelacji unikatów w
/// `run()`. Wydzielone jako czysta funkcja, żeby dało się przetestować bez
/// budowania wątków/Rayon.
///
/// NAPRAWIONY BUG (measure twice — druga weryfikacja Gemini, Punkt 5b):
/// wywołanie było wcześniej BEZWARUNKOWE. `scr_best` jest budowany
/// WYŁĄCZNIE z wyników korelacji unikatów UFS×Skrypt — jeśli ta korelacja
/// nie odbyła się wcale (`correlation_cancelled`, Ctrl+C w pętli
/// `common_rows` PRZED wejściem w Etap korelacji unikatów) albo odbyła się
/// tylko CZĘŚCIOWO (`unique_ufs_przerwane`, Ctrl+C W TRAKCIE równoległego
/// porównania "każdy z każdym"), `scr_best` jest odpowiednio pusty albo
/// niekompletny — zapisanie wtedy "NONE" dla KAŻDEGO pliku unikalnego
/// Skryptu byłoby fałszywym, trwałym wynikiem (bramkowanym przez
/// `phase14_done = 1`), mimo że jego prawdziwy bliźniak mógł być właśnie
/// wśród nieprzetworzonych/przerwanych porównań strony UFS.
fn wolno_zapisac_symetryczne_wpisy_skryptu(
    correlation_cancelled: bool,
    unique_ufs_przerwane: bool,
) -> bool {
    !correlation_cancelled && !unique_ufs_przerwane
}

fn buduj_symetryczne_wpisy_skryptu(
    unique_scr_ids: &[i32],
    scr_best: &HashMap<i32, (u32, String, i64, bool)>,
) -> Vec<(i32, String, f64, Option<String>, i64, bool)> {
    unique_scr_ids
        .iter()
        .map(|s_id| {
            if let Some((score, ufs_path, delta_dla_skryptu, ext_mismatch)) = scr_best.get(s_id) {
                let m_type = classify_unique_match_score(*score).to_string();
                (
                    *s_id,
                    m_type,
                    *score as f64,
                    Some(ufs_path.clone()),
                    *delta_dla_skryptu,
                    *ext_mismatch,
                )
            } else {
                (*s_id, "NONE".to_string(), 0.0, None, 0, false)
            }
        })
        .collect()
}

#[derive(Debug, Clone)]
pub(crate) struct Task {
    id: i32,
    rel_path: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SideFuzzyResult {
    id: i32,
    hash: Option<String>,
    io_error: Option<bool>,
}

pub(crate) enum ScanMsg {
    UfsChunk(Vec<SideFuzzyResult>),
    ScriptChunk(Vec<SideFuzzyResult>),
}

/// Liczniki live dla JEDNEJ strony w Etapie 1 (hashowanie CTPH). `computed`
/// = udane hashe. Dwie ODRĘBNE kategorie zamiast dawnego wspólnego
/// "zbyt małe": `empty_files` = plik dosłownie pusty (0 B, nie ma czego
/// hashować), `too_small_nonempty` = plik NIEPUSTY, ale ssdeep i tak go
/// odrzucił jako zbyt mały dla sensownego CTPH — inna przyczyna dowodowa
/// (0 B to np. ślad wydmuszki/placeholdera, kilkanaście bajtów to zwykle
/// fragment za mały na rolling hash). `too_large_fallback` = pliki, dla
/// których `mmap` zawiódł ORAZ rozmiar przekroczył
/// `config.fuzzy_hash_fallback_max_mb` (pominięte, nie wczytane do RAM w
/// całości). `mmap_fallback_used` = pliki, dla których `mmap` zawiódł, ale
/// zmieściły się w limicie i zostały skutecznie zhashowane przez wolniejszy
/// bufor `fs::read_to_end` — licznik zdrowia warstwy I/O: częste użycie
/// sygnalizuje np. filesystem sieciowy/FUSE, na którym `mmap` jest zawodny.
pub(crate) struct LiveStats {
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    computed: AtomicUsize,
    empty_files: AtomicUsize,
    too_small_nonempty: AtomicUsize,
    too_large_fallback: AtomicUsize,
    mmap_fallback_used: AtomicUsize,
    errors: AtomicUsize,
    extensions: Mutex<HashMap<String, usize>>,

    /// EKSPERYMENTALNE (Wariant A): śledzi zajętość logicznych slotów Rayon
    /// TEJ strony podczas liczenia sygnatury CTPH (`ssdeep::hash`) — patrz
    /// moduł `thread_activity`. Dotyczy WYŁĄCZNIE Etapu 1 (hashowanie) —
    /// Etap 4 (korelacja O(n×m)) tej fazy nie jest tu śledzony.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            processed_files: AtomicUsize::new(0),
            processed_bytes: AtomicU64::new(0),
            computed: AtomicUsize::new(0),
            empty_files: AtomicUsize::new(0),
            too_small_nonempty: AtomicUsize::new(0),
            too_large_fallback: AtomicUsize::new(0),
            mmap_fallback_used: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            extensions: Mutex::new(HashMap::new()),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }
}

/// Wylicza liczbę slotów trackera zajętości (Wariant A) odpowiednią dla
/// trybu I/O — patrz identyczna logika w `phase3::compute_activity_slots`.
fn compute_activity_slots(io_mode: &str, actual_threads: usize, half_threads: usize) -> usize {
    if io_mode == "CONCURRENT" {
        half_threads
    } else {
        actual_threads
    }
}

/// Buduje pełny, samodzielny blok live DLA JEDNEGO ŹRÓDŁA (Etap 1 —
/// hashowanie) — prędkość MB/s, top 4 rozszerzenia (licznik wystąpień, nie
/// waga — inaczej niż w innych fazach), obliczone CTPH, pliki zbyt małe,
/// pliki pominięte przez fallback RAM, błędy I/O.
fn build_source_block(label: &str, stats: &LiveStats, start_time: Instant) -> String {
    let bytes = stats.processed_bytes.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
    let speed_mb = (bytes as f64 / 1_048_576.0) / elapsed;

    let top_ext = {
        let map = stats.extensions.lock().unwrap_or_else(|e| e.into_inner());
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted
            .into_iter()
            .take(4)
            .map(|(k, v)| {
                let e = if k == "brak" {
                    "brak".to_string()
                } else {
                    format!(".{}", k)
                };
                format!("{} ({})", e, v)
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let display_top = if top_ext.is_empty() {
        "Analiza danych...".to_string()
    } else {
        top_ext
    };

    let activity_markup =
        crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot());

    format!(
        "[{}]\nPrędkość: {:.2} MB/s\nTop formaty: {}\nSygnatury CTPH obliczone: {}\nPuste (0 B): {}\nZbyt małe dla CTPH (niepuste): {}\nPominięte (fallback RAM): {}\nUżyto fallbacku RAM (mmap zawiódł): {}\nWątki CTPH (Wariant A): {}\nBłędy I/O: {}",
        label,
        speed_mb,
        display_top,
        stats.computed.load(Ordering::Relaxed),
        stats.empty_files.load(Ordering::Relaxed),
        stats.too_small_nonempty.load(Ordering::Relaxed),
        stats.too_large_fallback.load(Ordering::Relaxed),
        stats.mmap_fallback_used.load(Ordering::Relaxed),
        activity_markup,
        stats.errors.load(Ordering::Relaxed),
    )
}

/// Liczniki live dla Etapu 4 (korelacja krzyżowa). W odróżnieniu od Etapu 1
/// ([`LiveStats`]) NIE ma podziału UFS/Skrypt — pętla po plikach wspólnych i
/// porównanie "każdy z każdym" dla unikalnych działają na JEDNEJ, wspólnej
/// puli wyników, więc to jeden zestaw liczników dla całego etapu.
/// `zlepki_binarne` pochodzi WYŁĄCZNIE z pętli plików wspólnych
/// ([`classify_common_match_score`]) — dla porównań unikalnych "każdy z
/// każdym" wynik 0%/szumowy jest klasyfikowany jako zwykły brak dopasowania
/// ([`classify_unique_match_score`]), nie jako anomalia.
pub(crate) struct CorrelationStats {
    twins: AtomicUsize,
    partial: AtomicUsize,
    zlepki_binarne: AtomicUsize,
    ext_mismatches: AtomicUsize,
    total_delta_abs: AtomicI64,
}

impl CorrelationStats {
    fn new() -> Self {
        Self {
            twins: AtomicUsize::new(0),
            partial: AtomicUsize::new(0),
            zlepki_binarne: AtomicUsize::new(0),
            ext_mismatches: AtomicUsize::new(0),
            total_delta_abs: AtomicI64::new(0),
        }
    }
}

/// Buduje pełny, samodzielny blok live dla Etapu 4 (korelacja krzyżowa) —
/// analogiczny do [`build_source_block`] Etapu 1, ale bez rozróżnienia UFS/
/// Skrypt (patrz dokumentacja [`CorrelationStats`]). Wysyłany przez
/// `PhaseEvent::UpdateSideText` na pasek nr 3, z tą samą częstotliwością co
/// dotychczasowa linia paska postępu — wcześniej TYLKO ta jedna linia niosła
/// jakąkolwiek statystykę live tego etapu (liczby Bliźniaków i Złych Typów),
/// a liczby Częściowych/Zlepków Binarnych nie były widoczne na żywo wcale,
/// tylko w Dzienniku Końcowym PO zakończeniu całej fazy.
fn build_correlation_block(stats: &CorrelationStats, processed: usize, total: usize) -> String {
    format!(
        "[Korelacja Krzyżowa]\nPrzetworzono porównań: {} / {}\nBliźniaki (≥90% dla tej samej lub innej ścieżki): {}\nCzęściowe dopasowanie: {}\nZlepki Binarne (0%, ta sama ścieżka UFS/Skrypt): {}\nBłędne rozszerzenia (bliźniak pod inną nazwą formatu): {}\nSuma bezwzględnej różnicy wag (Δ): {}",
        processed,
        total,
        stats.twins.load(Ordering::Relaxed),
        stats.partial.load(Ordering::Relaxed),
        stats.zlepki_binarne.load(Ordering::Relaxed),
        stats.ext_mismatches.load(Ordering::Relaxed),
        format_bytes(stats.total_delta_abs.load(Ordering::Relaxed).unsigned_abs()),
    )
}

// Struktury dla Raportu Hierarchicznego (Korelacja)
type ExtMap = HashMap<String, Vec<(String, i64, bool)>>;

/// Agreguje statystyki jednej kategorii dopasowania (Bliźniaki/Zlepki Binarne/
/// Częściowe) do Dziennika Końcowego: liczba plików, suma różnic wag,
/// liczba pomyłek rozszerzenia, oraz mapa rozszerzenie -> lista przykładów
/// (ścieżka, delta, czy_pomylone_rozszerzenie).
struct CategoryStats {
    count: usize,
    total_delta: i64,
    ext_mismatches: usize,
    extensions: ExtMap,
}
impl CategoryStats {
    fn new() -> Self {
        Self {
            count: 0,
            total_delta: 0,
            ext_mismatches: 0,
            extensions: HashMap::new(),
        }
    }
    fn add(&mut self, ext: &str, path: String, delta: i64, ext_mismatch: bool) {
        self.count += 1;
        self.total_delta += delta;
        if ext_mismatch {
            self.ext_mismatches += 1;
        }
        self.extensions
            .entry(ext.to_string())
            .or_default()
            .push((path, delta, ext_mismatch));
    }
}

// ============================================================================
// ETAP 1: SILNIK GENEROWANIA SYGNATUR CTPH Z WYKORZYSTANIEM MMAP (I/O)
// ============================================================================

/// Skanuje wszystkie zadania (`tasks`) dla JEDNEJ strony: dla każdego pliku
/// próbuje wygenerować sygnaturę CTPH przez `mmap` (Zero-Copy). Jeśli `mmap`
/// zawiedzie, spada na klasyczny bufor `fs::read_to_end` — ale TYLKO gdy
/// rozmiar pliku nie przekracza `fallback_max_bytes` (parametr, pochodzący z
/// `config.fuzzy_hash_fallback_max_mb`), inaczej plik jest pomijany
/// (`too_large_fallback`) zamiast wczytany w całości do RAM. Rozgłasza
/// postęp i statystyki do UI co ~200 plików LUB co 250ms (hybrydowy próg —
/// wzorzec z Fazy 5-7/10-13).
pub struct StreamCtx<'a> {
    pub base_path: &'a Path,
    pub tasks: &'a [Task],
    pub side_label: &'a str,
    pub stats: &'a LiveStats,
    pub tx_db: mpsc::SyncSender<ScanMsg>,
    pub is_ufs: bool,
    pub start_time: Instant,
    pub fallback_max_bytes: u64,
    pub tx_ui: &'a mpsc::Sender<PhaseEvent>,
    pub bar_idx: usize,
    pub debug_log: crate::debug_log::DebugLog,
}

#[instrument(skip(ctx), fields(base_path = %ctx.base_path.display()))]

fn process_side_stream<'a>(ctx: StreamCtx<'a>) {
    let StreamCtx {
        base_path,
        tasks,
        side_label,
        stats,
        tx_db,
        is_ufs,
        start_time,
        fallback_max_bytes,
        tx_ui,
        bar_idx,
        debug_log,
    } = ctx;
    let metoda = "ssdeep::hash (fuzzy)";

    tasks
        .par_chunks(CHUNK_SIZE)
        .for_each_with(tx_db, |tx_db, chunk| {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) {
                return;
            }

            let mut results = Vec::with_capacity(chunk.len());
            let mut last_ui_update = Instant::now();

            for task in chunk {
                if CANCEL_SIGNAL.load(Ordering::Relaxed) {
                    break;
                }

                let full_path = base_path.join(&task.rel_path);
                let file_size = std::fs::metadata(&full_path).map(|m| m.len()).unwrap_or(0);

                let ext = Path::new(&task.rel_path)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("brak")
                    .to_lowercase();
                {
                    let mut map = stats.extensions.lock().unwrap_or_else(|e| e.into_inner());
                    *map.entry(ext).or_insert(0) += 1;
                }

                let mut hash_opt = None;
                let mut io_err = Some(false);
                let call_start = debug_log.is_active().then(Instant::now);

                if file_size == 0 {
                    stats.empty_files.fetch_add(1, Ordering::Relaxed);
                } else {
                    let file_res = std::fs::File::open(&full_path);
                    if let Ok(mut file) = file_res {
                        let mmap_res = unsafe { memmap2::MmapOptions::new().map(&file) };
                        if let Ok(mmap) = mmap_res {
                            match stats.thread_activity.track_current(|| ssdeep::hash(&mmap)) {
                                Ok(h) => {
                                    hash_opt = Some(h);
                                    stats.computed.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(_) => {
                                    stats.too_small_nonempty.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        } else {
                            if file_size > fallback_max_bytes {
                                stats.too_large_fallback.fetch_add(1, Ordering::Relaxed);
                            } else {
                                let mut buffer = Vec::new();
                                if file.read_to_end(&mut buffer).is_ok() {
                                    if let Ok(h) = stats
                                        .thread_activity
                                        .track_current(|| ssdeep::hash(&buffer))
                                    {
                                        hash_opt = Some(h);
                                        stats.computed.fetch_add(1, Ordering::Relaxed);
                                        stats.mmap_fallback_used.fetch_add(1, Ordering::Relaxed);
                                    } else {
                                        stats.too_small_nonempty.fetch_add(1, Ordering::Relaxed);
                                    }
                                } else {
                                    stats.errors.fetch_add(1, Ordering::Relaxed);
                                    io_err = Some(true);
                                }
                            }
                        }
                    } else {
                        stats.errors.fetch_add(1, Ordering::Relaxed);
                        io_err = Some(true);
                    }
                }
                if let Some(t) = call_start {
                    let wynik = if io_err == Some(true) {
                        "BŁĄD I/O".to_string()
                    } else if hash_opt.is_some() {
                        "OK".to_string()
                    } else if file_size == 0 {
                        "POMINIĘTO (pusty plik)".to_string()
                    } else {
                        "POMINIĘTO (za mały na fuzzy hash)".to_string()
                    };
                    debug_log.log(side_label, metoda, &task.rel_path, t.elapsed(), &wynik);
                }

                let current = stats.processed_files.fetch_add(1, Ordering::Relaxed) + 1;
                stats
                    .processed_bytes
                    .fetch_add(file_size, Ordering::Relaxed);

                let now = Instant::now();
                // Hybrydowy próg (wzorzec z Fazy 5-7/10-13): licznik globalny jako
                // główny wyzwalacz (nie resetuje się na granicy paczki), plus
                // siatka bezpieczeństwa czasowa.
                let should_update = current.is_multiple_of(200)
                    || now.duration_since(last_ui_update).as_millis() > 250;

                if should_update {
                    last_ui_update = now;

                    // PASEK: wyłącznie postęp + bieżący plik (bez liczników)
                    let _ = tx_ui.send(PhaseEvent::UpdateBar {
                        idx: bar_idx,
                        current: current as u64,
                        message: format_display_path(&task.rel_path),
                    });
                    let _ = tx_ui.send(PhaseEvent::UpdateBottomPath {
                        idx: bar_idx,
                        path: format!("[{}] {}", metoda, full_path.to_string_lossy()),
                    });

                    // PANEL BOCZNY: pełny, samodzielny blok TEGO źródła
                    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                        idx: bar_idx,
                        text: build_source_block(side_label, stats, start_time),
                    });
                }

                results.push(SideFuzzyResult {
                    id: task.id,
                    hash: hash_opt,
                    io_error: io_err,
                });
            }

            if !results.is_empty() {
                if is_ufs {
                    let _ = tx_db.send(ScanMsg::UfsChunk(results));
                } else {
                    let _ = tx_db.send(ScanMsg::ScriptChunk(results));
                }
            }
        });

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: stats.processed_files.load(Ordering::Relaxed) as u64,
        message: "Generowanie sygnatur ssdeep w 100% zakończone.".to_string(),
    });
}

/// Formatuje jedną kategorię dopasowania (Bliźniaki/Zlepki Binarne/Częściowe)
/// do Dziennika Końcowego: nagłówek + top 5 rozszerzeń z przykładową ścieżką
/// i deltą wagi per rozszerzenie.
fn write_category_block(out: &mut String, stats: &CategoryStats, icon: &str) {
    use std::fmt::Write as FmtWrite;

    if stats.count == 0 {
        let _ = writeln!(out, "   [ ✔ ] Brak plików w tej kategorii.");
        return;
    }

    let _ = writeln!(
        out,
        "   [ 👇 ] Zestawienie odnalezionych typów, pomyłek formatów i delt wagowych:"
    );

    let mut sorted: Vec<_> = stats.extensions.iter().collect();
    sorted.sort_by_key(|a| std::cmp::Reverse(a.1.len()));

    for (ext, paths) in sorted.into_iter().take(5) {
        let cat = get_file_category(ext);
        let _ = writeln!(
            out,
            "     - {} Typ Pliku: {:<12} [ {:<4} ]: {} plików",
            icon,
            cat,
            ext,
            paths.len()
        );

        let (sample_path, sample_delta, sample_mismatch) = &paths[0];
        let mismatch_warn = if *sample_mismatch {
            " [ 🚨 BŁĄD ROZSZERZENIA!]"
        } else {
            ""
        };
        let delta_str = format_delta(*sample_delta);

        let _ = writeln!(out, "       [ 🔍 ] Przykładowy dowód z tej grupy:");
        let _ = writeln!(
            out,
            "         - Ścieżka: \"{}\"{}",
            sample_path, mismatch_warn
        );
        let _ = writeln!(out, "         - Delta:   {}", delta_str);
    }
    let _ = writeln!(out);
}

// ============================================================================
// GŁÓWNA FUNKCJA (Entrypoint)
// ============================================================================

/// Wylicza rozmiar prywatnej puli Rayon przypisywanej JEDNEJ stronie w
/// Etapie 1 (`CONCURRENT`) — patrz `phase3::compute_half_threads` dla
/// pełnego uzasadnienia. NIE dotyczy Etapu 4 (korelacja), gdzie nie ma
/// dwóch stron do podziału — patrz dokumentacja modułu.
fn compute_half_threads(total_threads: usize) -> usize {
    std::cmp::max(1, total_threads / 2)
}

/// Punkt wejścia Fazy 14, wołany przez `menu::actions::run_phase_with_ui`.
/// Patrz dokumentacja modułu dla opisu dwuetapowej architektury (hashowanie
/// vs korelacja) i naprawionego braku `CANCEL_SIGNAL` w Etapie 4.
#[instrument(skip(conn, config, tx_ui), fields(ufs_path = %config.ufs_path, script_path = %config.script_path))]
pub fn run(
    conn: &mut Connection,
    config: &Ustawienia,
    tx_ui: mpsc::Sender<PhaseEvent>,
) -> Result<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    let _ = tx_ui.send(PhaseEvent::Log(
        "Uruchomiono Fazę 14: Rozmyte Hashowanie (CTPH / ssdeep).".to_string(),
    ));

    let actual_threads = if config.max_threads > 0 {
        config.max_threads
    } else {
        rayon::current_num_threads()
    };
    let io_text = if config.io_mode == "CONCURRENT" {
        "RÓWNOLEGŁE"
    } else {
        "SEKWENCYJNIE"
    };
    let _ = tx_ui.send(PhaseEvent::Log(format!(
        "Metodyka pracy szyny dyskowej: {}",
        io_text
    )));
    let _ = tx_ui.send(PhaseEvent::Log(format!(
        "Aktywne wątki procesora (Rayon): {}",
        actual_threads
    )));
    let _ = tx_ui.send(PhaseEvent::Log(
        "Ochrona RAM (mmap): AKTYWNA (Bypass ładowania dla limitu wagi!)".to_string(),
    ));

    let fallback_max_bytes = config
        .fuzzy_hash_fallback_max_mb
        .saturating_mul(1024 * 1024);
    let _ = tx_ui.send(PhaseEvent::Log(format!(
        "Limit fallbacku RAM (gdy mmap zawiedzie): {} MB",
        config.fuzzy_hash_fallback_max_mb
    )));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    // TWORZENIE ROZBUDOWANEJ TABELI W BAZIE SQLITE
    conn.execute(
        "CREATE TABLE IF NOT EXISTS phase14_analysis (
            file_id INTEGER PRIMARY KEY,
            match_type TEXT,
            match_pct REAL,
            twin_file_path TEXT,
            delta_bytes INTEGER,
            extension_mismatch BOOLEAN,
            FOREIGN KEY(file_id) REFERENCES files(id)
        )",
        [],
    )?;

    // INICJALIZACJA DUAL-LOGGING
    let raport_cfg = config
        .raporty_faz
        .get("Faza 14")
        .cloned()
        .unwrap_or_else(|| crate::settings::RaportFazy {
            katalog: config.log_path.clone(),
            plik_operacyjny: "raport_operacyjny_faza14.txt".to_string(),
            plik_dziennika: "dziennik_koncowy_faza14.txt".to_string(),
        });

    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();

    // Wszystkie pliki tego przebiegu fazy niosą ten sam znacznik czasu, więc
    // łatwo je ze sobą powiązać na dysku, a kolejne uruchomienia się nie
    // nadpisują.
    let stamp = crate::utils::run_timestamp();
    let log_twins_path = Path::new(&raport_cfg.katalog).join(crate::utils::stamp_filename(
        "raport_operacyjny_faza14_zaginione_blizniaki.txt",
        &stamp,
    ));
    let log_franks_path = Path::new(&raport_cfg.katalog).join(crate::utils::stamp_filename(
        "raport_operacyjny_faza14_frankensteiny.txt",
        &stamp,
    ));
    let log_partial_path = Path::new(&raport_cfg.katalog).join(crate::utils::stamp_filename(
        "raport_operacyjny_faza14_czesciowe_uszkodzenia.txt",
        &stamp,
    ));
    let dz_path = Path::new(&raport_cfg.katalog)
        .join(crate::utils::stamp_filename(&raport_cfg.plik_dziennika, &stamp));
    let debug_log = crate::debug_log::DebugLog::maybe_open(
        &raport_cfg.katalog,
        &crate::utils::stamp_filename("dziennik_debug_faza14.txt", &stamp),
        &config.log_level,
    );

    let log_twins = match File::create(&log_twins_path) {
        Ok(f) => Arc::new(Mutex::new(f)),
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!(
                "BŁĄD I/O: Nie można utworzyć pliku logu operacyjnego: {}. Sprawdź uprawnienia.",
                e
            )));
            return Ok(());
        }
    };
    let log_franks = match File::create(&log_franks_path) {
        Ok(f) => Arc::new(Mutex::new(f)),
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!(
                "BŁĄD I/O: Nie można utworzyć pliku logu operacyjnego: {}. Sprawdź uprawnienia.",
                e
            )));
            return Ok(());
        }
    };
    let log_partial = match File::create(&log_partial_path) {
        Ok(f) => Arc::new(Mutex::new(f)),
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!(
                "BŁĄD I/O: Nie można utworzyć pliku logu operacyjnego: {}. Sprawdź uprawnienia.",
                e
            )));
            return Ok(());
        }
    };

    {
        let _ = writeln!(
            log_twins.lock().unwrap_or_else(|e| e.into_inner()),
            "=== FAZA 14: ZAGINIONE BLIŹNIAKI (Cross-Korelacja Plików Unikalnych) ===\nOdnalezione pliki posiadające różne ścieżki i nazwy, ale w ponad 90% identyczne wnętrze.\nZawierają informacje o różnicy wag (Delta) i potencjalnych błędach odzyskanego rozszerzenia.\n"
        );
        let _ = writeln!(
            log_franks.lock().unwrap_or_else(|e| e.into_inner()),
            "=== FAZA 14: ZLEPKI BINARNE (dawniej \"Frankensteiny\") ===\nPliki mające identyczną ścieżkę w UFS i Skrypcie, lecz wykazujące 0% podobieństwa wewnątrz (Całkowicie zniszczone przez File Carvera).\nSzukasz tych wpisów programowo? Nazwa techniczna w bazie danych pozostaje bez zmian: phase14_analysis.match_type = 'FRANKENSTEIN'.\n"
        );
        let _ = writeln!(
            log_partial.lock().unwrap_or_else(|e| e.into_inner()),
            "=== FAZA 14: CZĘŚCIOWE USZKODZENIA (Przesunięcia Sektorowe) ===\nPliki, których wnętrze jest podobne tylko w 1% - 89% (Częściowo ucięte / zmieszane).\n"
        );
    }

    // --- ETAP 1A: POBIERANIE ZADAŃ DO HASHOWANIA ---
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, fuzzy_hash_ufs, fuzzy_hash_script 
         FROM files 
         WHERE (hash_match = 0 OR hash_match IS NULL) AND (phase14_done = 0 OR phase14_done IS NULL)"
    )?;

    let mut ufs_tasks = Vec::new();
    let mut script_tasks = Vec::new();
    let mut skipped = 0;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i32>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, bool>(2)?,
            row.get::<_, bool>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_u, in_s, h_u, h_s) = r;
        if in_u && h_u.is_none() {
            ufs_tasks.push(Task {
                id,
                rel_path: rel.clone(),
            });
        }
        if in_s && h_s.is_none() {
            script_tasks.push(Task {
                id,
                rel_path: rel.clone(),
            });
        }

        if (in_u && h_u.is_some()) || (in_s && h_s.is_some()) {
            skipped += 1;
        }
    }
    drop(stmt);

    let total_db_rows = ufs_tasks.len() + script_tasks.len();

    if skipped > 0 {
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "Wznowienie sesji: Pominięto {} plików z wyliczonym już hashem ssdeep.",
            skipped
        )));
    }

    if total_db_rows == 0 && skipped == 0 {
        let _ = tx_ui.send(PhaseEvent::Log(
            "✔ Brak plików spornych (Baza w pełni aktualna). Zamykam status fazy...".to_string(),
        ));
        // 🟢 UWAGA: Usunięto `return Ok(());`. Kod przechodzi do Etapu 4 korelacji,
        // aby upewnić się, że żadne pliki nie ugrzęzły w bazie bez domknięcia!
    } else if total_db_rows == 0 {
        let _ = tx_ui.send(PhaseEvent::Log(
            "✔ Wszystkie pliki zostały już zhashowane. Przechodzę prosto do korelacji w RAM..."
                .to_string(),
        ));
    }

    let half_threads = compute_half_threads(actual_threads);
    let activity_slots = compute_activity_slots(&config.io_mode, actual_threads, half_threads);

    let ufs_stats = LiveStats::new(activity_slots);
    let script_stats = LiveStats::new(activity_slots);
    let ufs_base = PathBuf::from(&config.ufs_path);
    let script_base = PathBuf::from(&config.script_path);

    // --- ETAP 2 & 3: PRZETWARZANIE STRUMIENIOWE (MPSC) ---
    if total_db_rows > 0 {
        let _ = tx_ui.send(PhaseEvent::SetBar {
            idx: 0,
            label: "UFS Explorer (CTPH)".to_string(),
            total: ufs_tasks.len() as u64,
            color: Color::Cyan,
        });
        let _ = tx_ui.send(PhaseEvent::SetBar {
            idx: 1,
            label: "Skrypt Autorski (CTPH)".to_string(),
            total: script_tasks.len() as u64,
            color: Color::Magenta,
        });
        let _ = tx_ui.send(PhaseEvent::SetBar {
            idx: 2,
            label: "Zapis SQLite".to_string(),
            total: total_db_rows as u64,
            color: Color::Green,
        });

        // REGRESJA (measure twice — druga weryfikacja Gemini): każdy błąd
        // SQLite w wątku bazy był wcześniej `.unwrap()`, czyli paniką w
        // wątku pisarza wewnątrz `thread::scope`. Ten sam wzorzec co
        // `phase17_repair::run`/`phase1::run`/`phase3::run` — `db_thread`
        // zwraca `Result<()>`, panika jest przechwytywana przez `.join()` i
        // zamieniana na błąd domenowy.
        let wynik_zapisu: Result<()> = std::thread::scope(|s| {
            let (tx_db, rx_db) = mpsc::sync_channel(200);

            let db_thread = s.spawn(|| -> Result<()> {
                let mut db_inserted = 0;
                let mut last_db_update = Instant::now();

                let update_sql = |c: &mut Connection, chunk: &[SideFuzzyResult], is_ufs: bool| -> Result<()> {
                    let tx_trans = c.transaction()?;
                    {
                        let mut stmt = match is_ufs {
                            true => tx_trans.prepare_cached("UPDATE files SET fuzzy_hash_ufs = COALESCE(?1, fuzzy_hash_ufs), io_error_ufs = COALESCE(?2, io_error_ufs) WHERE id = ?3")?,
                            false => tx_trans.prepare_cached("UPDATE files SET fuzzy_hash_script = COALESCE(?1, fuzzy_hash_script), io_error_script = COALESCE(?2, io_error_script) WHERE id = ?3")?
                        };

                        for res in chunk {
                            if res.hash.is_some() || res.io_error == Some(true) {
                                stmt.execute(params![res.hash, res.io_error, res.id])?;
                            }
                        }
                    }
                    tx_trans.commit()
                };

                for msg in rx_db {
                    let c_len = match &msg {
                        ScanMsg::UfsChunk(chunk) => { update_sql(conn, chunk, true)?; chunk.len() },
                        ScanMsg::ScriptChunk(chunk) => { update_sql(conn, chunk, false)?; chunk.len() },
                    };

                    db_inserted += c_len;
                    let now = Instant::now();
                    if now.duration_since(last_db_update).as_millis() > 60 {
                        last_db_update = now;
                        let _ = tx_ui.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Zapisywanie hashów CTPH...".to_string() });
                    }
                }
                let _ = tx_ui.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Hashe CTPH w 100% zsynchronizowane z SQLite.".to_string() });
                Ok(())
            });

            if config.io_mode == "CONCURRENT" {
                let tx1 = tx_db.clone();
                let tx2 = tx_db.clone();

                // Referencje (nie własność) - ufs_stats/script_stats/ufs_base/
                // script_base/tx_ui są odczytywane ponownie PO zakończeniu tego
                // bloku (korelacja Etapu 4, raport końcowy), więc domknięcia
                // `move` mogą przejąć wyłącznie te referencje, nie same wartości.
                let stat_u = &ufs_stats;
                let stat_s = &script_stats;
                let ufs_base_ref = &ufs_base;
                let script_base_ref = &script_base;
                let tx_ui_ref = &tx_ui;
                let dbg_u = debug_log.clone();
                let dbg_s = debug_log.clone();

                // NAPRAWA (ten sam bug jak w Fazie 5/6/7/10-13): dedykowana
                // pula per strona, minimum 1 wątek. Wyliczone wcześniej, tu tylko używane.

                s.spawn(move || {
                    if !ufs_tasks.is_empty() {
                        if let Ok(pool) = rayon::ThreadPoolBuilder::new()
                            .num_threads(half_threads)
                            .build()
                        {
                            pool.install(|| {
                                process_side_stream(StreamCtx {
                                    base_path: ufs_base_ref,
                                    tasks: &ufs_tasks,
                                    side_label: "UFS Explorer",
                                    stats: stat_u,
                                    tx_db: tx1,
                                    is_ufs: true,
                                    start_time,
                                    fallback_max_bytes,
                                    tx_ui: tx_ui_ref,
                                    bar_idx: 0,
                                    debug_log: dbg_u.clone(),
                                });
                            });
                        } else {
                            process_side_stream(StreamCtx {
                                base_path: ufs_base_ref,
                                tasks: &ufs_tasks,
                                side_label: "UFS Explorer",
                                stats: stat_u,
                                tx_db: tx1,
                                is_ufs: true,
                                start_time,
                                fallback_max_bytes,
                                tx_ui: tx_ui_ref,
                                bar_idx: 0,
                                debug_log: dbg_u.clone(),
                            });
                        }
                        let _ = tx_ui_ref.send(PhaseEvent::Log(
                            "✔ Hashowanie CTPH dysku UFS zakończone.".to_string(),
                        ));
                    }
                });
                s.spawn(move || {
                    if !script_tasks.is_empty() {
                        if let Ok(pool) = rayon::ThreadPoolBuilder::new()
                            .num_threads(half_threads)
                            .build()
                        {
                            pool.install(|| {
                                process_side_stream(StreamCtx {
                                    base_path: script_base_ref,
                                    tasks: &script_tasks,
                                    side_label: "Skrypt Autorski",
                                    stats: stat_s,
                                    tx_db: tx2,
                                    is_ufs: false,
                                    start_time,
                                    fallback_max_bytes,
                                    tx_ui: tx_ui_ref,
                                    bar_idx: 1,
                                    debug_log: dbg_s.clone(),
                                });
                            });
                        } else {
                            process_side_stream(StreamCtx {
                                base_path: script_base_ref,
                                tasks: &script_tasks,
                                side_label: "Skrypt Autorski",
                                stats: stat_s,
                                tx_db: tx2,
                                is_ufs: false,
                                start_time,
                                fallback_max_bytes,
                                tx_ui: tx_ui_ref,
                                bar_idx: 1,
                                debug_log: dbg_s.clone(),
                            });
                        }
                        let _ = tx_ui_ref.send(PhaseEvent::Log(
                            "✔ Hashowanie CTPH dysku Skryptu zakończone.".to_string(),
                        ));
                    }
                });
                drop(tx_db);
            } else {
                let dbg_u = debug_log.clone();
                let dbg_s = debug_log.clone();
                if !ufs_tasks.is_empty() {
                    process_side_stream(StreamCtx {
                        base_path: &ufs_base,
                        tasks: &ufs_tasks,
                        side_label: "UFS Explorer",
                        stats: &ufs_stats,
                        tx_db: tx_db.clone(),
                        is_ufs: true,
                        start_time,
                        fallback_max_bytes,
                        tx_ui: &tx_ui,
                        bar_idx: 0,
                        debug_log: dbg_u,
                    });
                    let _ = tx_ui.send(PhaseEvent::Log(
                        "✔ Hashowanie CTPH dysku UFS zakończone.".to_string(),
                    ));
                }
                if !script_tasks.is_empty() {
                    process_side_stream(StreamCtx {
                        base_path: &script_base,
                        tasks: &script_tasks,
                        side_label: "Skrypt Autorski",
                        stats: &script_stats,
                        tx_db: tx_db.clone(),
                        is_ufs: false,
                        start_time,
                        fallback_max_bytes,
                        tx_ui: &tx_ui,
                        bar_idx: 1,
                        debug_log: dbg_s,
                    });
                    let _ = tx_ui.send(PhaseEvent::Log(
                        "✔ Hashowanie CTPH dysku Skryptu zakończone.".to_string(),
                    ));
                }
                // REGRESJA (measure twice — druga weryfikacja Gemini): gdy
                // `script_tasks` jest puste, oryginalny `tx_db` nigdy nie był
                // przenoszony (poprzednio: `tx_db` bez `.clone()` w drugim
                // wywołaniu) - kanał nie zamykał się, dopóki ta zmienna nie
                // wyszła z zasięgu na końcu CAŁEGO domknięcia `thread::scope`.
                // Wcześniej to nie miało znaczenia (brak jawnego `.join()`),
                // ale teraz `db_thread.join()` niżej blokowałby się W
                // NIESKOŃCZONOŚĆ, czekając na zamknięcie kanału, który sam
                // trzyma otwarty - klasyczny deadlock. Jawny `drop` zamyka
                // kanał deterministycznie, zanim `.join()` zacznie czekać.
                drop(tx_db);
            }

            match db_thread.join() {
                Ok(wynik) => wynik,
                // `join` zwraca `Err` WYŁĄCZNIE gdy wątek spanikował. Sama
                // panika jest już odnotowana przez globalny hook w
                // `logging.rs`, więc tu zamieniamy ją na błąd domenowy, żeby
                // nie rozprzestrzeniała się dalej i żeby wywołujący nie
                // uznał przebiegu za udany.
                Err(_) => {
                    let _ = tx_ui.send(PhaseEvent::Log(
                        "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 14 mógł nie zostać w pełni zapisany.".to_string()
                    ));
                    Err(rusqlite::Error::UnwindingPanic)
                }
            }
        });
        wynik_zapisu?;
    }

    // --- ETAP 4: BŁYSKAWICZNA KORELACJA W PAMIĘCI RAM Z DELTĄ ---
    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log(
            "🛑 Skanowanie przerwane przez użytkownika.".to_string(),
        ));
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::Log(
        "🚀 Rozpoczynam korelację krzyżową sygnatur CTPH w pamięci RAM...".to_string(),
    ));

    let mut stmt = conn.prepare("SELECT id, relative_path, found_in_ufs, found_in_script, fuzzy_hash_ufs, fuzzy_hash_script FROM files WHERE (hash_match = 0 OR hash_match IS NULL) AND phase14_done = 0")?;

    struct HashRow {
        id: i32,
        rel_path: String,
        hash_u: Option<String>,
        hash_s: Option<String>,
    }
    let mut common_rows = Vec::new();
    let mut unique_ufs = Vec::new();
    let mut unique_scr = Vec::new();
    // NAPRAWIONY BUG (rozjazd stron / nieskończona re-analiza): pliki
    // jednostronne, dla których hashowanie CTPH się nie powiodło (io_error,
    // za małe dla ssdeep) wcześniej nie trafiały ANI do `unique_ufs`/
    // `unique_scr` (bo `h_u`/`h_s` to `None`), ANI do `common_rows` (bo są
    // jednostronne) — więc nigdy nie dostawały `phase14_done=1` i były
    // ponownie kolejkowane w KAŻDYM kolejnym uruchomieniu fazy, w
    // nieskończoność. Zbierane tu osobno, dostają wprost wpis "NONE".
    let mut unhashable_unique: Vec<i32> = Vec::new();

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i32>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, bool>(2)?,
            row.get::<_, bool>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_u, in_s, h_u, h_s) = r;
        if in_u && in_s {
            common_rows.push(HashRow {
                id,
                rel_path: rel,
                hash_u: h_u,
                hash_s: h_s,
            });
        } else if in_u && h_u.is_some() {
            unique_ufs.push((id, rel, h_u.expect("Wartość hash powinna być obecna")));
        } else if in_s && let Some(h) = h_s {
            unique_scr.push((id, rel, h));
        } else {
            unhashable_unique.push(id);
        }
    }
    drop(stmt);

    let total_correlations = common_rows.len() + unique_ufs.len();
    let _ = tx_ui.send(PhaseEvent::SetBar {
        idx: 3,
        label: "Korelacja Krzyżowa RAM".to_string(),
        total: total_correlations as u64,
        color: Color::Yellow,
    });

    let corr_stats = CorrelationStats::new();
    let progress_counter = Arc::new(AtomicUsize::new(0));

    let mut db_updates: Vec<(i32, String, f64, Option<String>, i64, bool)> = Vec::new();
    let db_updates_mtx = Arc::new(Mutex::new(&mut db_updates));

    let ufs_b = ufs_base.clone();
    let scr_b = script_base.clone();
    let mut correlation_cancelled = false;

    // Klasyczna pętla po wspólnych ścieżkach - NAPRAWA: sprawdza CANCEL_SIGNAL
    for row in common_rows {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) {
            correlation_cancelled = true;
            break;
        }

        let mut pct = 0.0;
        let mut m_type = "NONE".to_string();
        let mut delta = 0;
        let ext = Path::new(&row.rel_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("brak")
            .to_lowercase();

        if let (Some(hu), Some(hs)) = (&row.hash_u, &row.hash_s)
            && let Ok(score) = ssdeep::compare(hu, hs)
        {
            pct = score as f64;
            let w_ufs = std::fs::metadata(ufs_b.join(&row.rel_path))
                .map(|m| m.len() as i64)
                .unwrap_or(0);
            let w_scr = std::fs::metadata(scr_b.join(&row.rel_path))
                .map(|m| m.len() as i64)
                .unwrap_or(0);
            delta = w_ufs - w_scr;

            corr_stats
                .total_delta_abs
                .fetch_add(delta.abs(), Ordering::Relaxed);

            m_type = classify_common_match_score(score as u32).to_string();
            match m_type.as_str() {
                "FRANKENSTEIN" => {
                    corr_stats.zlepki_binarne.fetch_add(1, Ordering::Relaxed);
                    let _ = writeln!(
                        log_franks.lock().unwrap_or_else(|e| e.into_inner()),
                        "[Typ: .{:<4}] Ścieżka (0% match, zlepek): \"{}\"",
                        ext,
                        row.rel_path
                    );
                }
                "PARTIAL" => {
                    corr_stats.partial.fetch_add(1, Ordering::Relaxed);
                    let delta_s = format_delta(delta);
                    let _ = writeln!(
                        log_partial.lock().unwrap_or_else(|e| e.into_inner()),
                        "[Typ: .{:<4}] [{:>3}% match] [Δ: {}] Ścieżka: \"{}\"",
                        ext,
                        score,
                        delta_s,
                        row.rel_path
                    );
                }
                _ => {}
            }
        }
        db_updates_mtx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((row.id, m_type, pct, None, delta, false));
        let c = progress_counter.fetch_add(1, Ordering::Relaxed) + 1;

        // Zestawienie wyników korelacji w locie na pasku nr 3 + pełny panel boczny
        if c.is_multiple_of(50) {
            let m = corr_stats.ext_mismatches.load(Ordering::Relaxed);
            let d_total = format_bytes(
                corr_stats
                    .total_delta_abs
                    .load(Ordering::Relaxed)
                    .unsigned_abs(),
            );
            let _ = tx_ui.send(PhaseEvent::UpdateBar {
                idx: 3,
                current: c as u64,
                message: format!(
                    "👯‍♂️ Bliźniaki: {} | 🔄 Złe Typy: {} | ⚖️ Suma Δ: {}",
                    corr_stats.twins.load(Ordering::Relaxed),
                    m,
                    d_total
                ),
            });
            let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                idx: 3,
                text: build_correlation_block(&corr_stats, c, total_correlations),
            });
        }
    }

    let last_ui_update = Arc::new(AtomicU64::new(0));

    // REGRESJA (measure twice — druga weryfikacja Gemini, Punkt 5a): element,
    // którego porównanie O(m) zostało przerwane przez CANCEL_SIGNAL (przed
    // startem LUB w trakcie wewnętrznej pętli), musi zniknąć z wyniku, a NIE
    // dostać `best_score = 0` nie do odróżnienia od "naprawdę porównano z
    // wszystkimi kandydatami, brak dopasowania". Wcześniej takie elementy
    // dostawały trwały, fałszywy wpis "NONE" + `phase14_done = 1` i nigdy
    // więcej nie wracały do korelacji, mimo że nigdy nie zostały w pełni
    // sprawdzone (a prawdziwy bliźniak mógł istnieć dalej w `unique_scr`).
    // `unique_ufs_przerwane` śledzi, czy CHOĆ JEDEN element tej puli padł
    // ofiarą anulowania — potrzebne niżej, żeby `buduj_symetryczne_wpisy_skryptu`
    // też wiedziało, że `scr_best` mogło zostać zbudowane z niekompletnych
    // danych (patrz Punkt 5b).
    let unique_ufs_przerwane = AtomicBool::new(false);

    // Równoległa pętla "każdy z każdym" dla plików unikalnych - sprawdza
    // CANCEL_SIGNAL zarówno przed rozpoczęciem drogiego wewnętrznego
    // porównania O(m) dla danego elementu, jak i wewnątrz niego (przerywa
    // wcześniej rozpoczęte porównanie, jeśli anulowanie nadejdzie w trakcie).
    let cross_results: Vec<_> = if correlation_cancelled {
        Vec::new()
    } else {
        unique_ufs
            .par_iter()
            .filter_map(|(u_id, u_path, u_hash)| {
                let ext_ufs = Path::new(&u_path)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("brak")
                    .to_lowercase();
                let mut best_score = 0;
                let mut best_match_id: Option<i32> = None;
                let mut best_match_path = None;
                let mut delta = 0;
                let mut ext_mismatch = false;
                let mut przerwano = CANCEL_SIGNAL.load(Ordering::Relaxed);

                if !przerwano {
                    for (s_id, s_path, s_hash) in &unique_scr {
                        if CANCEL_SIGNAL.load(Ordering::Relaxed) {
                            przerwano = true;
                            break;
                        }
                        if let Ok(score) = ssdeep::compare(u_hash, s_hash)
                            && score > best_score
                        {
                            best_score = score;
                            best_match_id = Some(*s_id);
                            best_match_path = Some(s_path.clone());
                            if score == 100 {
                                break;
                            }
                        }
                    }

                    if best_score > 0
                        && let Some(ref bp) = best_match_path
                    {
                        let ext_scr = Path::new(&bp)
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("brak")
                            .to_lowercase();
                        if ext_ufs != ext_scr {
                            ext_mismatch = true;
                        }

                        let w_ufs = std::fs::metadata(ufs_b.join(u_path))
                            .map(|m| m.len() as i64)
                            .unwrap_or(0);
                        let w_scr = std::fs::metadata(scr_b.join(bp))
                            .map(|m| m.len() as i64)
                            .unwrap_or(0);
                        delta = w_ufs - w_scr;
                    }
                }

                let current = progress_counter.fetch_add(1, Ordering::Relaxed) + 1;

                let now_ms = start_time.elapsed().as_millis() as u64;
                let last_ms = last_ui_update.load(Ordering::Relaxed);

                if now_ms - last_ms > 80
                    && last_ui_update
                        .compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                {
                    let m = corr_stats.ext_mismatches.load(Ordering::Relaxed);
                    let d_total = format_bytes(
                        corr_stats
                            .total_delta_abs
                            .load(Ordering::Relaxed)
                            .unsigned_abs(),
                    );
                    let _ = tx_ui.send(PhaseEvent::UpdateBar {
                        idx: 3,
                        current: current as u64,
                        message: format!(
                            "👯‍♂️ Bliźniaki: {} | 🔄 Złe Typy: {} | ⚖️ Suma Δ: {}",
                            corr_stats.twins.load(Ordering::Relaxed),
                            m,
                            d_total
                        ),
                    });
                    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                        idx: 3,
                        text: build_correlation_block(&corr_stats, current, total_correlations),
                    });
                }

                if przerwano {
                    unique_ufs_przerwane.store(true, Ordering::Relaxed);
                    return None;
                }
                Some((
                    *u_id,
                    u_path.clone(),
                    best_score,
                    best_match_id,
                    best_match_path,
                    delta,
                    ext_mismatch,
                    ext_ufs,
                ))
            })
            .collect()
    };
    let unique_ufs_przerwane = unique_ufs_przerwane.load(Ordering::Relaxed);

    // NAPRAWIONY BUG (rozjazd stron / nieskończona re-analiza): tylko strona
    // UFS otrzymywała wpis `phase14_done=1` z tej pętli — strona Skrypt
    // (`unique_scr`) służyła wyłącznie jako bierny zbiór porównawczy, więc
    // pliki unikalne dla Skryptu były bez końca ponownie kolejkowane do
    // korelacji przy każdym uruchomieniu fazy, a moduł zszywania w Fazie 17
    // nigdy ich nie widział jako kandydatów mimo istniejącego bliźniaka po
    // stronie UFS. `scr_best` zbiera NAJLEPSZE dopasowanie per plik Skryptu
    // (jeden plik Skryptu może być najlepszym kandydatem dla wielu plików
    // UFS — bierzemy zwycięzcę po najwyższym wyniku), żeby druga pętla mogła
    // zapisać dla niego symetryczny wpis zamiast zostawić go bez wpisu.
    let mut scr_best: HashMap<i32, (u32, String, i64, bool)> = HashMap::new();

    for (u_id, u_path, score, best_id, best_path, delta, ext_mismatch, ext_ufs) in cross_results {
        if score > 0 {
            corr_stats
                .total_delta_abs
                .fetch_add(delta.abs(), Ordering::Relaxed);
        }

        let m_type = classify_unique_match_score(score as u32).to_string();
        let ma_zaliczone_dopasowanie = m_type != "NONE";
        // Poniżej progu szumu (patrz `UNIQUE_MATCH_NOISE_FLOOR`) nie
        // zapisujemy ani ścieżki, ani delty — to jest klasyfikowane jak
        // BRAK dopasowania, więc nie ma po co zostawiać śladu sugerującego
        // realny związek między plikami.
        let zapisywana_sciezka = if ma_zaliczone_dopasowanie {
            best_path.clone()
        } else {
            None
        };

        match m_type.as_str() {
            "TWIN" => {
                corr_stats.twins.fetch_add(1, Ordering::Relaxed);
                if ext_mismatch {
                    corr_stats.ext_mismatches.fetch_add(1, Ordering::Relaxed);
                }

                let p = best_path.clone().unwrap_or_default();
                let d_str = format_delta(delta);
                let bad_ext_flag = if ext_mismatch { " [ZŁY TYP!]" } else { "" };
                let _ = writeln!(
                    log_twins.lock().unwrap_or_else(|e| e.into_inner()),
                    "[{:<4}] [{:>3}%] [Δ: {:>10}]{} UFS: \"{}\" <---> Skrypt: \"{}\"",
                    ext_ufs,
                    score,
                    d_str,
                    bad_ext_flag,
                    u_path,
                    p
                );
            }
            "PARTIAL" => {
                corr_stats.partial.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        db_updates.push((
            u_id,
            m_type,
            score as f64,
            zapisywana_sciezka,
            delta,
            ext_mismatch,
        ));

        if ma_zaliczone_dopasowanie && let Some(sid) = best_id {
            let wpis_lustrzany = (score as u32, u_path.clone(), -delta, ext_mismatch);
            scr_best
                .entry(sid)
                .and_modify(|istniejacy| {
                    if wpis_lustrzany.0 > istniejacy.0 {
                        *istniejacy = wpis_lustrzany.clone();
                    }
                })
                .or_insert(wpis_lustrzany);
        }
    }

    // Symetryczny wpis dla KAŻDEGO pliku unikalnego strony Skrypt — z
    // najlepszym znalezionym dopasowaniem (jeśli jakiekolwiek przekroczyło
    // próg szumu) albo z jawnym "NONE", żeby dostał `phase14_done=1` i nie
    // był bez końca re-analizowany. Wydzielone do czystej funkcji — patrz
    // testy `buduj_symetryczne_wpisy_skryptu`.
    //
    // REGRESJA (measure twice — druga weryfikacja Gemini, Punkt 5b): to
    // wywołanie było wcześniej BEZWARUNKOWE. Gdy `correlation_cancelled`
    // (Ctrl+C podczas pętli `common_rows`, PRZED wejściem w korelację
    // unikatów) `scr_best` jest pusty, a funkcja - zgodnie ze swoją
    // udokumentowaną, poprawną logiką - zapisywała wtedy "NONE" dla
    // KAŻDEGO pliku unikalnego Skryptu, mimo że korelacja unikatów w ogóle
    // się nie zaczęła. Analogicznie, gdy `unique_ufs_przerwane` (Ctrl+C W
    // TRAKCIE równoległej korelacji, patrz wyżej) `scr_best` mógł zostać
    // zbudowany z NIEKOMPLETNYCH danych — brakuje w nim wpisów od strony
    // UFS, których porównanie zostało przerwane, więc plik Skryptu, którego
    // prawdziwy bliźniak akurat był wśród NICH, dostałby fałszywe "NONE".
    // W obu przypadkach poprawna odpowiedź to NIE zapisywać nic — pliki
    // unikalne Skryptu zostają nieoznaczone (`phase14_done` bez zmian) i
    // wracają do kolejki przy następnym, pełnym uruchomieniu fazy.
    if wolno_zapisac_symetryczne_wpisy_skryptu(correlation_cancelled, unique_ufs_przerwane) {
        let unique_scr_ids: Vec<i32> = unique_scr.iter().map(|(id, _, _)| *id).collect();
        db_updates.extend(buduj_symetryczne_wpisy_skryptu(&unique_scr_ids, &scr_best));
    }

    // NAPRAWIONY BUG: pliki jednostronne bez policzonego hasha (błąd I/O,
    // za małe dla ssdeep) — patrz `unhashable_unique` przy budowie zadań.
    for id in &unhashable_unique {
        db_updates.push((*id, "NONE".to_string(), 0.0, None, 0, false));
    }

    if correlation_cancelled {
        let _ = tx_ui.send(PhaseEvent::Log(
            "🛑 Korelacja krzyżowa przerwana przez użytkownika - zapisuję częściowe wyniki..."
                .to_string(),
        ));
    }

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: 3,
        current: total_correlations as u64,
        message: "Zderzanie sygnatur RAM zakończone sukcesem.".to_string(),
    });

    // --- ETAP 3: ZAPIS DO BAZY ---
    let _ = tx_ui.send(PhaseEvent::Log(
        "🔄 Eksportowanie relacji dowodowych (Z Deltami) do bazy danych...".to_string(),
    ));
    let tx_trans = conn.transaction()?;
    {
        // OPTYMALIZACJA: prepare_cached dla insertów/update'ów
        let mut stmt_insert = tx_trans.prepare_cached("INSERT OR REPLACE INTO phase14_analysis (file_id, match_type, match_pct, twin_file_path, delta_bytes, extension_mismatch) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?;
        let mut stmt_update =
            tx_trans.prepare_cached("UPDATE files SET phase14_done = 1 WHERE id = ?1")?;
        for (id, m_type, pct, twin_path, delta, ext_mism) in &db_updates {
            stmt_insert.execute(params![id, m_type, pct, twin_path, delta, ext_mism])?;
            stmt_update.execute(params![id])?;
        }
    }
    tx_trans.commit()?;

    // --- ETAP 4: RAPORT KRYMINALISTYCZNY HIERARCHICZNY ---
    let mut stats_twins = CategoryStats::new();
    let mut stats_franks = CategoryStats::new();
    let mut stats_partial = CategoryStats::new();

    let mut stmt = conn.prepare("SELECT f.relative_path, a.match_type, a.delta_bytes, a.extension_mismatch FROM files f JOIN phase14_analysis a ON f.id = a.file_id WHERE f.phase14_done = 1")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, bool>(3)?,
        ))
    })?;
    for r in rows.filter_map(|r| r.ok()) {
        let (path, m_type, delta, ext_mism) = r;
        let ext = Path::new(&path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("brak")
            .to_lowercase();
        match m_type.as_str() {
            "TWIN" => stats_twins.add(&ext, path, delta, ext_mism),
            "FRANKENSTEIN" => stats_franks.add(&ext, path, delta, ext_mism),
            "PARTIAL" => stats_partial.add(&ext, path, delta, ext_mism),
            _ => {}
        }
    }
    drop(stmt);

    let elapsed = start_time.elapsed();
    let total_bytes = ufs_stats.processed_bytes.load(Ordering::SeqCst)
        + script_stats.processed_bytes.load(Ordering::SeqCst);
    let avg_speed_mb = (total_bytes as f64 / 1_048_576.0) / elapsed.as_secs_f64().max(1.0);
    let total_io_errors =
        ufs_stats.errors.load(Ordering::SeqCst) + script_stats.errors.load(Ordering::SeqCst);

    // -- GENEROWANIE RAPORTU TEKSTOWEGO --
    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(
        &mut log_out,
        "=========================================================================="
    );
    let _ = writeln!(
        &mut log_out,
        "DZIENNIK KOŃCOWY - FAZA 14 (ROZMYTE HASHOWANIE I KORELACJA CTPH)"
    );
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(
        &mut log_out,
        "Sumaryczny transfer I/O: {} (Średnia prędkość: {:.2} MB/s)",
        format_bytes(total_bytes),
        avg_speed_mb
    );
    let _ = writeln!(
        &mut log_out,
        "==========================================================================\n"
    );

    let _ = writeln!(
        &mut log_out,
        "[ 1 ] ZAGINIONE BLIŹNIAKI (Korelacja Krzyżowa Plików Unikalnych):"
    );
    let _ = writeln!(
        &mut log_out,
        "   -> Odnaleziono ukryte kopie (Podobieństwo >= 90%): {}",
        stats_twins.count
    );
    if stats_twins.ext_mismatches > 0 {
        let _ = writeln!(
            &mut log_out,
            "      * W tym z pomyłką rozszerzenia: {}",
            stats_twins.ext_mismatches
        );
    }
    let _ = writeln!(
        &mut log_out,
        "      [ ZNACZENIE ]: Programy UFS i Skrypt odzyskały ten sam plik, ale pod zupełnie innymi nazwami lub w innych folderach. Dzięki ssdeep udało się je ze sobą powiązać."
    );
    write_category_block(&mut log_out, &stats_twins, "👯‍♂️");

    let _ = writeln!(
        &mut log_out,
        "[ 2 ] DETEKCJA PRZESUNIĘĆ SEKTORÓW (Częściowe Uszkodzenia):"
    );
    let _ = writeln!(
        &mut log_out,
        "   -> Zgodność częściowa (1% - 89% match): {}",
        stats_partial.count
    );
    let _ = writeln!(
        &mut log_out,
        "      [ ZNACZENIE ]: Pliki posiadają tę samą nazwę i wspólną bazę bitową, ale zauważalnie różnią się objętością. Wymagają ewentualnej, ostrożnej weryfikacji."
    );
    write_category_block(&mut log_out, &stats_partial, "🩹");

    let _ = writeln!(
        &mut log_out,
        "[ 3 ] ZLEPKI BINARNE (dawniej \"Frankensteiny\", techniczna nazwa w bazie: match_type = 'FRANKENSTEIN'):"
    );
    let _ = writeln!(
        &mut log_out,
        "   -> Całkowity brak podobieństwa (0% match): {}",
        stats_franks.count
    );
    let _ = writeln!(
        &mut log_out,
        "      [ ZNACZENIE ]: OBA programy zrzuciły pliki o identycznej nazwie i zbliżonej wadze, lecz ich struktura wewnątrz jest całkowicie inna. Są to zlepki śmieci z dysku, mylnie uznane za plik.\n"
    );
    write_category_block(&mut log_out, &stats_franks, "🧟‍♂️");

    if total_io_errors > 0 {
        let _ = writeln!(&mut log_out, "\n[ BŁĘDY FIZYCZNE I/O ]");
        let _ = writeln!(
            &mut log_out,
            "   -> Błędy odczytu mmap (OOM/Bad Sector): {}",
            total_io_errors
        );
    }

    if let Ok(mut f) = fs::File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "✔ Zapisano fizyczny Dziennik Końcowy w: {}",
            dz_path.display()
        )));
    }

    // Wysyłamy również do Ratatui Log Panel
    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    // Zrzut telemetrii do głównego pliku logów w tle
    info!(
        twins = stats_twins.count,
        franks = stats_franks.count,
        partials = stats_partial.count,
        delta_twins = stats_twins.total_delta,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 14 zakończona"
    );

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // compute_activity_slots (identyczna logika z Fazy 3-7/10-13)
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_activity_slots_concurrent_uses_half_threads() {
        assert_eq!(compute_activity_slots("CONCURRENT", 4, 2), 2);
    }

    #[test]
    fn test_compute_activity_slots_sequential_uses_full_actual_threads() {
        assert_eq!(compute_activity_slots("SEQUENTIAL", 4, 2), 4);
    }

    // ------------------------------------------------------------------
    // format_delta
    // ------------------------------------------------------------------

    #[test]
    fn test_format_delta_positive_gets_plus_sign() {
        assert_eq!(format_delta(1024), "+1.00 KB");
    }

    #[test]
    fn test_format_delta_negative_no_extra_sign() {
        // format_bytes działa na wartości bezwzględnej, minus pochodzi z
        // samego faktu, że sign="" dla ujemnych - ale liczba nie ma minusa
        // w tej implementacji (bezwzględna wartość jest formatowana bez znaku)
        let result = format_delta(-1024);
        assert!(!result.starts_with('+'));
        assert!(result.contains("1.00 KB"));
    }

    #[test]
    fn test_format_delta_zero() {
        assert_eq!(format_delta(0), "0 B");
    }

    // ------------------------------------------------------------------
    // get_file_category
    // ------------------------------------------------------------------

    #[test]
    fn test_get_file_category_known_types() {
        assert_eq!(get_file_category("zip"), "archiwum");
        assert_eq!(get_file_category("docx"), "dokument");
        assert_eq!(get_file_category("jpg"), "obraz");
        assert_eq!(get_file_category("mp4"), "wideo");
        assert_eq!(get_file_category("mp3"), "audio");
        assert_eq!(get_file_category("rs"), "tekst/kod");
        assert_eq!(get_file_category("exe"), "wykonywalny");
    }

    #[test]
    fn test_get_file_category_no_extension() {
        assert_eq!(get_file_category("brak"), "brak rozsz.");
    }

    #[test]
    fn test_get_file_category_unknown_extension() {
        assert_eq!(get_file_category("xyz123"), "inny");
    }

    // ------------------------------------------------------------------
    // classify_common_match_score
    // ------------------------------------------------------------------

    #[test]
    fn test_classify_common_zero_is_frankenstein() {
        assert_eq!(classify_common_match_score(0), "FRANKENSTEIN");
    }

    #[test]
    fn test_classify_common_below_90_is_partial() {
        assert_eq!(classify_common_match_score(1), "PARTIAL");
        assert_eq!(classify_common_match_score(89), "PARTIAL");
    }

    #[test]
    fn test_classify_common_90_and_above_is_high() {
        assert_eq!(classify_common_match_score(90), "HIGH");
        assert_eq!(classify_common_match_score(100), "HIGH");
    }

    // ------------------------------------------------------------------
    // classify_unique_match_score
    // ------------------------------------------------------------------

    #[test]
    fn test_classify_unique_zero_is_none_not_anomaly() {
        // Kluczowa różnica względem classify_common_match_score: tu 0% to
        // zwykły brak dopasowania, NIE anomalia "Frankenstein"
        assert_eq!(classify_unique_match_score(0), "NONE");
    }

    /// REGRESJA (Gemini review): wynik poniżej progu szumu CTPH nie może
    /// kwalifikować się jako "PARTIAL" — to typowy przypadkowy szum ssdeep
    /// między zupełnie niepowiązanymi plikami, a "PARTIAL" jest bramką do
    /// fizycznego zszycia bajtów w Fazie 17.
    #[test]
    fn test_classify_unique_below_noise_floor_is_none_not_partial() {
        assert_eq!(classify_unique_match_score(1), "NONE");
        assert_eq!(
            classify_unique_match_score(UNIQUE_MATCH_NOISE_FLOOR - 1),
            "NONE"
        );
    }

    #[test]
    fn test_classify_unique_from_noise_floor_below_90_is_partial() {
        assert_eq!(
            classify_unique_match_score(UNIQUE_MATCH_NOISE_FLOOR),
            "PARTIAL"
        );
        assert_eq!(classify_unique_match_score(89), "PARTIAL");
    }

    #[test]
    fn test_classify_unique_90_and_above_is_twin() {
        assert_eq!(classify_unique_match_score(90), "TWIN");
        assert_eq!(classify_unique_match_score(100), "TWIN");
    }

    // ------------------------------------------------------------------
    // buduj_symetryczne_wpisy_skryptu
    // ------------------------------------------------------------------

    /// REGRESJA (Gemini review): sedno naprawy — wcześniej strona Skrypt nie
    /// dostawała ŻADNEGO wpisu (ani "NONE", ani dopasowania), więc pliki
    /// unikalne dla Skryptu były bez końca ponownie kolejkowane do
    /// korelacji. Teraz KAŻDY id z `unique_scr_ids` dostaje dokładnie jeden
    /// wpis, niezależnie od tego, czy coś dla niego znaleziono.
    #[test]
    fn test_symetryczne_wpisy_kazdy_plik_skryptu_dostaje_dokladnie_jeden_wpis() {
        let scr_ids = vec![1, 2, 3];
        let mut scr_best = HashMap::new();
        scr_best.insert(2, (30u32, "ufs/x.bin".to_string(), 0i64, false));

        let wpisy = buduj_symetryczne_wpisy_skryptu(&scr_ids, &scr_best);

        assert_eq!(
            wpisy.len(),
            3,
            "każdy plik unikalny Skryptu musi dostać dokładnie jeden wpis"
        );
        assert!(wpisy.iter().any(|(id, ..)| *id == 1));
        assert!(wpisy.iter().any(|(id, ..)| *id == 2));
        assert!(wpisy.iter().any(|(id, ..)| *id == 3));
    }

    #[test]
    fn test_symetryczne_wpisy_plik_bez_dopasowania_dostaje_none() {
        let scr_ids = vec![42];
        let scr_best = HashMap::new();

        let wpisy = buduj_symetryczne_wpisy_skryptu(&scr_ids, &scr_best);

        assert_eq!(wpisy, vec![(42, "NONE".to_string(), 0.0, None, 0, false)]);
    }

    #[test]
    fn test_symetryczne_wpisy_plik_z_dopasowaniem_dostaje_odwrocona_delte_i_sciezke_ufs() {
        let scr_ids = vec![7];
        let mut scr_best = HashMap::new();
        // Delta zapisana w `scr_best` jest już odwrócona (patrz `run()`:
        // `-delta`) względem oryginalnej pary UFS-Skrypt.
        scr_best.insert(7, (95u32, "ufs/dawca.jpg".to_string(), -1024i64, false));

        let wpisy = buduj_symetryczne_wpisy_skryptu(&scr_ids, &scr_best);

        assert_eq!(wpisy.len(), 1);
        let (id, m_type, pct, twin, delta, mism) = &wpisy[0];
        assert_eq!(*id, 7);
        assert_eq!(m_type, "TWIN");
        assert_eq!(*pct, 95.0);
        assert_eq!(twin.as_deref(), Some("ufs/dawca.jpg"));
        assert_eq!(*delta, -1024);
        assert!(!mism);
    }

    #[test]
    fn test_symetryczne_wpisy_pusta_lista_daje_pusty_wynik() {
        assert!(buduj_symetryczne_wpisy_skryptu(&[], &HashMap::new()).is_empty());
    }

    // ------------------------------------------------------------------
    // REGRESJA (measure twice — druga weryfikacja Gemini, Punkt 5):
    // wolno_zapisac_symetryczne_wpisy_skryptu — bramka chroniąca przed
    // fałszywym "NONE" po anulowaniu w trakcie korelacji Etapu 4.
    // ------------------------------------------------------------------

    #[test]
    fn test_wolno_zapisac_symetryczne_wpisy_gdy_korelacja_pelna_i_nieprzerwana() {
        assert!(wolno_zapisac_symetryczne_wpisy_skryptu(false, false));
    }

    #[test]
    fn test_zabrania_zapisu_gdy_common_rows_zostalo_anulowane() {
        // Punkt 5b: korelacja unikatów w ogóle się nie zaczęła (Ctrl+C w
        // pętli common_rows) - scr_best jest pusty, zapis dałby fałszywe
        // "NONE" dla KAŻDEGO pliku unikalnego Skryptu.
        assert!(!wolno_zapisac_symetryczne_wpisy_skryptu(true, false));
    }

    #[test]
    fn test_zabrania_zapisu_gdy_korelacja_unikatow_zostala_przerwana_w_trakcie() {
        // Punkt 5a: część elementów unique_ufs nigdy nie dostała pełnego
        // porównania - scr_best jest niekompletny, nie tylko pusty.
        assert!(!wolno_zapisac_symetryczne_wpisy_skryptu(false, true));
    }

    #[test]
    fn test_zabrania_zapisu_gdy_oba_etapy_zostaly_dotkniete_anulowaniem() {
        assert!(!wolno_zapisac_symetryczne_wpisy_skryptu(true, true));
    }

    // ------------------------------------------------------------------
    // CategoryStats
    // ------------------------------------------------------------------

    #[test]
    fn test_category_stats_accumulates_correctly() {
        let mut stats = CategoryStats::new();
        stats.add("jpg", "a.jpg".to_string(), 100, false);
        stats.add("jpg", "b.jpg".to_string(), -50, true);
        stats.add("png", "c.png".to_string(), 20, false);

        assert_eq!(stats.count, 3);
        assert_eq!(stats.total_delta, 70); // 100 + (-50) + 20
        assert_eq!(stats.ext_mismatches, 1);
        assert_eq!(
            stats
                .extensions
                .get("jpg")
                .expect("Pobranie elementu z mapy lub słownika nie powiodło się")
                .len(),
            2
        );
        assert_eq!(
            stats
                .extensions
                .get("png")
                .expect("Pobranie elementu z mapy lub słownika nie powiodło się")
                .len(),
            1
        );
    }

    #[test]
    fn test_category_stats_empty_by_default() {
        let stats = CategoryStats::new();
        assert_eq!(stats.count, 0);
        assert_eq!(stats.total_delta, 0);
        assert_eq!(stats.ext_mismatches, 0);
        assert!(stats.extensions.is_empty());
    }

    // ------------------------------------------------------------------
    // compute_half_threads / build_source_block
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_half_threads() {
        assert_eq!(compute_half_threads(8), 4);
        assert_eq!(compute_half_threads(1), 1);
    }

    #[test]
    fn test_build_source_block_reports_counts() {
        use std::time::Duration;
        let stats = LiveStats::new(4);
        stats.computed.store(100, Ordering::Relaxed);
        stats.empty_files.store(3, Ordering::Relaxed);
        stats.too_small_nonempty.store(5, Ordering::Relaxed);
        stats.too_large_fallback.store(2, Ordering::Relaxed);
        stats.mmap_fallback_used.store(7, Ordering::Relaxed);
        stats.errors.store(1, Ordering::Relaxed);

        let start_time = Instant::now() - Duration::from_secs(1);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        assert!(block.starts_with("[UFS Explorer]"));
        assert!(block.contains("Sygnatury CTPH obliczone: 100"));
        assert!(block.contains("Puste (0 B): 3"));
        assert!(block.contains("Zbyt małe dla CTPH (niepuste): 5"));
        assert!(block.contains("Pominięte (fallback RAM): 2"));
        assert!(block.contains("Użyto fallbacku RAM (mmap zawiódł): 7"));
        assert!(block.contains("Błędy I/O: 1"));
    }

    #[test]
    fn test_build_source_block_shows_thread_activity_markup() {
        use std::time::Duration;
        let stats = LiveStats::new(2);
        stats.thread_activity.mark_busy(0);

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        let line = block
            .lines()
            .find(|l| l.starts_with("Wątki CTPH"))
            .expect("powinna istnieć linia Wariantu A");
        assert_eq!(line, "Wątki CTPH (Wariant A): {G:1} {R:2}");
    }

    #[test]
    fn test_build_source_block_placeholder_when_no_extensions() {
        use std::time::Duration;
        let stats = LiveStats::new(4);
        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("Skrypt Autorski", &stats, start_time);
        assert!(block.contains("Top formaty: Analiza danych..."));
    }

    // ------------------------------------------------------------------
    // CorrelationStats / build_correlation_block (Etap 4)
    // ------------------------------------------------------------------

    #[test]
    fn test_build_correlation_block_reports_progress_and_counts() {
        let stats = CorrelationStats::new();
        stats.twins.store(4, Ordering::Relaxed);
        stats.partial.store(2, Ordering::Relaxed);
        stats.zlepki_binarne.store(1, Ordering::Relaxed);
        stats.ext_mismatches.store(3, Ordering::Relaxed);
        stats.total_delta_abs.store(2048, Ordering::Relaxed);

        let block = build_correlation_block(&stats, 50, 200);

        assert!(block.starts_with("[Korelacja Krzyżowa]"));
        assert!(block.contains("Przetworzono porównań: 50 / 200"));
        assert!(block.contains("Bliźniaki (≥90% dla tej samej lub innej ścieżki): 4"));
        assert!(block.contains("Częściowe dopasowanie: 2"));
        assert!(block.contains("Zlepki Binarne (0%, ta sama ścieżka UFS/Skrypt): 1"));
        assert!(block.contains("Błędne rozszerzenia (bliźniak pod inną nazwą formatu): 3"));
        assert!(block.contains("Suma bezwzględnej różnicy wag (Δ): 2.00 KB"));
    }

    #[test]
    fn test_build_correlation_block_zero_counts_at_start() {
        let stats = CorrelationStats::new();
        let block = build_correlation_block(&stats, 0, 100);
        assert!(block.contains("Przetworzono porównań: 0 / 100"));
        assert!(block.contains("Bliźniaki (≥90% dla tej samej lub innej ścieżki): 0"));
    }

    // ------------------------------------------------------------------
    // opisy_anomalii: każda REALNA etykieta z OBU paneli (Etap 1 hashowanie
    // + Etap 4 korelacja) poza generycznymi musi mieć zarejestrowane
    // wyjaśnienie — inaczej Enter na tym wierszu w prawdziwym UI nie pokaże
    // nakładki. Mirror wzorca z Fazy 5-13.
    // ------------------------------------------------------------------

    #[test]
    fn test_etykiety_maja_zarejestrowane_wyjasnienia_albo_sa_generyczne() {
        const GENERYCZNE: &[&str] = &[
            "Prędkość",
            "Top formaty",
            "Wątki CTPH (Wariant A)",
            "Błędy I/O",
        ];

        let stats1 = LiveStats::new(2);
        let block1 = build_source_block("UFS Explorer", &stats1, Instant::now());

        let stats4 = CorrelationStats::new();
        let block4 = build_correlation_block(&stats4, 0, 10);

        let mut sprawdzonych = 0;
        for line in block1.lines().chain(block4.lines()) {
            if line.starts_with('[') {
                continue;
            }
            let Some((etykieta, _)) = line.split_once(": ") else {
                continue;
            };
            if GENERYCZNE.contains(&etykieta) {
                continue;
            }

            assert!(
                crate::opisy_anomalii::znajdz_opis(etykieta).is_some(),
                "etykieta \"{}\" z panelu Fazy 14 nie ma zarejestrowanego wyjaśnienia w opisy_anomalii",
                etykieta
            );
            sprawdzonych += 1;
        }
        assert_eq!(
            sprawdzonych, 11,
            "liczba sprawdzonych etykiet zmieniła się - zaktualizuj GENERYCZNE albo opisy_anomalii/faza14_hashowanie.rs"
        );
    }
}
