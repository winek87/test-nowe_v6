// src/phases/phase10.rs

//! # Faza 10: Walidacja Kodowania Znaków (Deep Text Forensics)
//!
//! Odczytuje fizycznie pierwsze 64 KB plików tekstowych.
//! Implementuje 3 nowe metody badawcze: Architektura Znaków (CRLF/LF),
//! Profilowanie Kodowania (ASCII/UTF-8/UTF-16) oraz Detekcję One-Linerów (>10KB).
//! Raportuje anomalie w locie (Dual-Logging) i obsługuje interfejs Ratatui (PhaseEvent).
//!
//! UWAGA ARCHITEKTONICZNA (UI): Pasek postępu pokazuje wyłącznie % i bieżący
//! plik. Liczniki live trafiają do panelu bocznego jako JEDEN, samodzielny blok
//! PER ŹRÓDŁO — patrz [`LiveStats::build_source_block`]. Dla Metody 1 (EOL) i
//! Metody 2 (kodowanie) liczniki są mapami `wartość -> liczba wystąpień`, NIE
//! zestawem z góry ustalonych atomików — to celowe: wcześniejsza wersja miała
//! atomiki tylko dla części możliwych wyników (`eol_crlf`/`eol_lf`,
//! `enc_ascii`/`enc_utf8`/`enc_utf16`), przez co pliki z wynikiem "Mieszane
//! (CRLF+LF)", "Mieszane/Inne" albo "Lokalne (Win-1250/ISO)" nie były zliczane
//! WCALE, nawet w raporcie końcowym. Mapa gwarantuje pełne pokrycie każdej
//! wartości, jaką zwróci [`analyze_text_file`], bez potrzeby synchronizowania
//! listy atomików z listą możliwych wyników funkcji za każdym razem, gdy ta
//! się zmieni.
//!
//! UWAGA ARCHITEKTONICZNA (WĄTKOWANIE): każda strona dostaje własną,
//! dedykowaną pulę Rayon (`half_threads`, identycznie jak Fazy 2-7).
//!
//! NAPRAWIONY BUG: `start_time` było wcześniej deklarowane wewnątrz domknięcia
//! `for_each_with` (czyli raz NA PACZKĘ 100 zadań), więc wyliczana prędkość
//! MB/s odzwierciedlała czas trwania ostatniej paczki, nie całego przebiegu
//! fazy — wartość skakała w sposób niezwiązany z rzeczywistą wydajnością
//! dysku. Teraz przekazywane przez `LiveStats::started_at` — patrz
//! [`LiveStats::new`].
//!
//! OBSŁUGA BŁĘDÓW: oba zapytania `SELECT` w [`run`] używają
//! `collect::<Result<Vec<_>>>()?` — propagują błąd mapowania wiersza zamiast
//! cicho go pomijać (poprzednie `filter_map(|r| r.ok())` gubiło wadliwe
//! wiersze bez ostrzeżenia). Anulowanie: [`CANCEL_SIGNAL`] sprawdzany jest
//! zarówno w pętli po zadaniach, jak i po synchronizacji z bazą — bez tego
//! po anulowaniu faza i tak generowała pełny raport końcowy, co było mylące.

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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;
use tracing::{info, instrument, warn};

const CHUNK_SIZE: usize = 100;

// ============================================================================
// STRUKTURY DANYCH
// ============================================================================

/// Rozszerzenia rozpoznawane jako kandydaci do analizy tekstowej — jedno
/// źródło prawdy dla [`is_text_extension`] (ten sam wzorzec co
/// `FORMATY_SKOMPRESOWANE` w Fazie 7).
///
/// REGRESJA: poprzednia, krótsza lista pomijała mnóstwo powszechnych
/// rozszerzeń kodu źródłowego i konfiguracji (c/cpp/h/java/go/rb/conf/env i
/// inne) — pliki tych formatów w ogóle NIE trafiały do analizy Fazy 10, mimo
/// że są tekstowe. Fałszywie dopasowane rozszerzenie jest tu niskiego
/// ryzyka: `analyze_text_file` i tak samodzielnie weryfikuje TREŚĆ
/// (zupa binarna, kodowanie), więc plik binarny z przypadkowo pasującym
/// rozszerzeniem zostanie poprawnie odrzucony, a nie fałszywie zaakceptowany.
const TEXT_EXTS: &[&str] = &[
    "py",
    "txt",
    "csv",
    "tsv",
    "json",
    "xml",
    "html",
    "htm",
    "svg",
    "md",
    "rst",
    "tex",
    "rs",
    "js",
    "jsx",
    "ts",
    "tsx",
    "vue",
    "css",
    "sh",
    "bash",
    "zsh",
    "fish",
    "bat",
    "ps1",
    "ini",
    "cfg",
    "conf",
    "env",
    "properties",
    "log",
    "yaml",
    "yml",
    "toml",
    "sql",
    "php",
    "c",
    "cpp",
    "cc",
    "cxx",
    "h",
    "hpp",
    "hxx",
    "java",
    "kt",
    "kts",
    "go",
    "rb",
    "pl",
    "lua",
    "cs",
    "swift",
    "dart",
    "scala",
    "r",
    "m",
    "asm",
    "s",
    "vb",
];

/// Rozstrzyga, czy dany plik (po ścieżce) jest kandydatem do analizy tekstowej
/// — dopasowanie WYŁĄCZNIE po rozszerzeniu (bez zaglądania do zawartości; to
/// robi dopiero [`analyze_text_file`]), niewrażliwe na wielkość liter.
fn is_text_extension(path_str: &str) -> bool {
    Path::new(path_str)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| TEXT_EXTS.contains(&e.to_lowercase().as_str()))
}

/// Pojedyncze zadanie: plik tekstowy oczekujący na walidację kodowania po JEDNEJ stronie.
#[derive(Debug, Clone)]
pub(crate) struct Task {
    id: i32,
    rel_path: String,
    /// `true` gdy plik jest obecny na OBU stronach — decyduje o klasyfikacji
    /// wykrytej anomalii do liczników `_common`/`_unique`.
    is_common: bool,
}

/// Wynik analizy tekstowej jednego pliku — trzy niezależne metody badawcze
/// (patrz [`analyze_text_file`]) plus ogólny werdykt poprawności.
#[derive(Debug, Clone)]
struct TextAnalysis {
    /// `false` = "zupa binarna" (twardy NULL lub >5% znaków kontrolnych) — plik
    /// rzekomo tekstowy jest w rzeczywistości uszkodzonym/błędnie rozpoznanym binarnym.
    is_valid: bool,
    /// Powód nieważności, gdy `is_valid == false`.
    reason: Option<String>,
    /// Wynik Metody 2 (Profilowanie Kodowania): jedna z `"ASCII"`, `"UTF-8"`,
    /// `"UTF-8 (BOM)"`, `"UTF-16"`, `"Lokalne (Win-1250/ISO)"`.
    encoding: String,
    /// Wynik Metody 1 (Architektura Końca Linii): jedna z `"CRLF (Windows)"`,
    /// `"LF (Unix)"`, `"Mieszane (CRLF+LF)"`, `"Mieszane/Inne"`.
    eol: String,
    /// Wynik Metody 3: `true` gdy plik >10KB nie zawiera ani jednego `\n`
    /// w pierwszych 64KB — typowy ślad kodu zminifikowanego lub payloadu Base64.
    is_oneliner: bool,
    /// `true`, gdy odsetek znaków kontrolnych mieści się w paśmie 4-6%
    /// wokół progu zupy binarnej (>5%, patrz [`analyze_text_file`]) —
    /// niezależnie od tego, po której stronie progu plik ostatecznie
    /// wylądował. Graniczny przypadek wart ręcznej weryfikacji: o włos od
    /// przeciwnej klasyfikacji.
    near_threshold: bool,
}

/// Wynik przetworzenia jednego zadania, przekazywany przez MPSC do wątku zapisu SQLite.
#[derive(Debug, Clone)]
pub(crate) struct SideValidationResult {
    id: i32,
    analysis: Option<TextAnalysis>,
    io_error: Option<bool>,
}

/// Wiadomość do wątku zapisu SQLite, oznaczona stroną pochodzenia.
pub(crate) enum ScanMsg {
    UfsChunk(Vec<SideValidationResult>),
    ScriptChunk(Vec<SideValidationResult>),
}

/// Liczniki live dla JEDNEJ strony. Metody 1 i 2 używają map (patrz dokumentacja
/// modułu — gwarancja pełnego pokrycia wszystkich możliwych wartości). Metoda 3
/// (one-liner) jest z natury binarna, więc zostaje jako atomiki `_common`/`_unique`.
/// Nigdy nie łączone z licznikami drugiej strony.
pub(crate) struct LiveStats {
    /// Moment startu przebiegu tej strony — ustawiany raz w [`LiveStats::new`].
    /// Używany przez [`LiveStats::build_source_block`] do wyliczenia prędkości
    /// MB/s.
    started_at: Instant,
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    errors: AtomicUsize,
    ext_weights: Mutex<HashMap<String, u64>>,

    encoding_counts: Mutex<HashMap<String, usize>>,
    eol_counts: Mutex<HashMap<String, usize>>,
    junk_reason_counts: Mutex<HashMap<String, usize>>,

    junk_common: AtomicUsize,
    junk_unique: AtomicUsize,
    near_threshold_common: AtomicUsize,
    near_threshold_unique: AtomicUsize,
    oneliner_common: AtomicUsize,
    oneliner_unique: AtomicUsize,

    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize, started_at: Instant) -> Self {
        Self {
            started_at,
            processed_files: AtomicUsize::new(0),
            processed_bytes: AtomicU64::new(0),
            errors: AtomicUsize::new(0),
            ext_weights: Mutex::new(HashMap::new()),
            encoding_counts: Mutex::new(HashMap::new()),
            eol_counts: Mutex::new(HashMap::new()),
            junk_reason_counts: Mutex::new(HashMap::new()),
            junk_common: AtomicUsize::new(0),
            junk_unique: AtomicUsize::new(0),
            near_threshold_common: AtomicUsize::new(0),
            near_threshold_unique: AtomicUsize::new(0),
            oneliner_common: AtomicUsize::new(0),
            oneliner_unique: AtomicUsize::new(0),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }

    /// Buduje pełny, samodzielny blok live DLA JEDNEGO ŹRÓDŁA.
    fn build_source_block(&self, label: &str) -> String {
        let bytes = self.processed_bytes.load(Ordering::Relaxed);
        let elapsed = self.started_at.elapsed().as_secs_f64().max(0.1);
        let speed_mb = (bytes as f64 / 1_048_576.0) / elapsed;

        let top_ext = {
            let map = self.ext_weights.lock().unwrap_or_else(|e| e.into_inner());
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            sorted
                .into_iter()
                .take(3)
                .map(|(ext, w)| {
                    let e = if ext == "brak" {
                        "brak".to_string()
                    } else {
                        format!(".{}", ext)
                    };
                    format!("{} ({})", e, format_bytes(*w))
                })
                .collect::<Vec<_>>()
                .join(", ")
        };

        let display_ext = if top_ext.is_empty() {
            "Analiza danych...".to_string()
        } else {
            top_ext
        };

        let full_breakdown = |map: &Mutex<HashMap<String, usize>>| -> String {
            let m = map.lock().unwrap_or_else(|e| e.into_inner());
            if m.is_empty() {
                return "-".to_string();
            }
            let mut sorted: Vec<_> = m.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            sorted
                .into_iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join(" | ")
        };

        let activity_markup =
            crate::thread_activity::format_activity_markup(&self.thread_activity.snapshot());

        format!(
            "[{}]\nPrędkość: {:.2} MB/s\nTop format: {}\nArchitektura EOL: {}\nKodowanie: {}\nZupa binarna: {} wspólne / {} unikalne\nPowody zupy binarnej: {}\nBlisko progu zupy binarnej (4-6% kontrolnych): {} wspólne / {} unikalne\nOne-Liner (>10KB): {} wspólne / {} unikalne\nWątki analizy (Wariant A): {}\nBłędy I/O: {}",
            label,
            speed_mb,
            display_ext,
            full_breakdown(&self.eol_counts),
            full_breakdown(&self.encoding_counts),
            self.junk_common.load(Ordering::Relaxed),
            self.junk_unique.load(Ordering::Relaxed),
            full_breakdown(&self.junk_reason_counts),
            self.near_threshold_common.load(Ordering::Relaxed),
            self.near_threshold_unique.load(Ordering::Relaxed),
            self.oneliner_common.load(Ordering::Relaxed),
            self.oneliner_unique.load(Ordering::Relaxed),
            activity_markup,
            self.errors.load(Ordering::Relaxed),
        )
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

// Struktury dla Raportu Hierarchicznego
type ExtMap = HashMap<String, Vec<String>>;

struct SourceAnomalies {
    ufs: ExtMap,
    script: ExtMap,
}
impl SourceAnomalies {
    fn new() -> Self {
        Self {
            ufs: HashMap::new(),
            script: HashMap::new(),
        }
    }
}

struct AnomalyCategory {
    name: &'static str,
    icon: &'static str,
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
// SILNIK DECYZYJNY (WERYFIKATOR BINARNY I 3 NOWE METODY)
// ============================================================================

fn analyze_text_file(
    path: &Path,
    file_size: u64,
) -> std::result::Result<TextAnalysis, std::io::Error> {
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 65536];
    let n = file.read(&mut buffer)?;

    if n == 0 {
        return Ok(TextAnalysis {
            is_valid: true,
            reason: None,
            encoding: "ASCII".into(),
            eol: "Brak".into(),
            is_oneliner: false,
            near_threshold: false,
        });
    }

    let slice = &buffer[..n];
    let mut is_valid = true;
    let mut reason = None;
    let mut encoding = "UTF-8";
    let mut eol = "Mieszane/Inne";
    let mut is_oneliner = false;
    let mut near_threshold = false;

    // METODA 2: Profil Kodowania (Detekcja BOM)
    let utf16_le = slice.starts_with(&[0xFF, 0xFE]);
    let utf16_be = !utf16_le && slice.starts_with(&[0xFE, 0xFF]);
    if utf16_le || utf16_be {
        encoding = "UTF-16";
        let payload = &slice[2..];
        let units: Vec<u16> = payload
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                if utf16_le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();

        if units.len() >= 16 {
            let mut decode_errors = 0usize;
            let mut ctrl = 0usize;
            for r in char::decode_utf16(units.iter().copied()) {
                match r {
                    Ok(c) => {
                        if (c as u32) < 0x20 && c != '\n' && c != '\r' && c != '\t' {
                            ctrl += 1;
                        }
                    }
                    Err(_) => decode_errors += 1,
                }
            }
            let total = units.len() as f64;
            let error_ratio = decode_errors as f64 / total;
            let ctrl_ratio = ctrl as f64 / total;
            if error_ratio > 0.01 || ctrl_ratio > 0.05 {
                is_valid = false;
                reason = Some(
                    "Zupa Binarna (nieprawidłowe jednostki UTF-16 pod podrobionym BOM)".to_string(),
                );
            }
        }
    } else if slice.starts_with(&[0xEF, 0xBB, 0xBF]) {
        encoding = "UTF-8 (BOM)";
    }

    // METODA 1: Architektura Końca Linii (CRLF / LF)
    let lf_count = slice.iter().filter(|&&b| b == b'\n').count();
    let cr_count = slice.iter().filter(|&&b| b == b'\r').count();

    if lf_count > 0 {
        if cr_count == lf_count {
            eol = "CRLF (Windows)";
        } else if cr_count == 0 {
            eol = "LF (Unix)";
        } else {
            eol = "Mieszane (CRLF+LF)";
        }
    } else if file_size > 10240 {
        is_oneliner = true;
    }

    // Klasyczna weryfikacja zupy binarnej
    if encoding != "UTF-16" {
        if slice.contains(&0) {
            is_valid = false;
            reason = Some("Twardy Bajt NULL (0x00) - Slack Space lub fałszywy odzysk".to_string());
        } else {
            match std::str::from_utf8(slice) {
                Ok(_) => {
                    if slice.iter().all(|&b| b < 128) {
                        encoding = "ASCII";
                    }
                }
                Err(e) => {
                    if e.valid_up_to() < n.saturating_sub(4) {
                        let ctrl = slice
                            .iter()
                            .filter(|&&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')
                            .count();
                        let ctrl_ratio = ctrl as f64 / n as f64;
                        if ctrl_ratio > 0.05 {
                            is_valid = false;
                            reason = Some("Zupa Binarna (>5% znaków kontrolnych)".to_string());
                        } else {
                            encoding = "Lokalne (Win-1250/ISO)";
                        }
                        near_threshold = (0.04..=0.06).contains(&ctrl_ratio);
                    }
                }
            }
        }
    }

    Ok(TextAnalysis {
        is_valid,
        reason,
        encoding: encoding.into(),
        eol: eol.into(),
        is_oneliner,
        near_threshold,
    })
}

pub struct StreamCtx<'a> {
    pub base_path: &'a Path,
    pub tasks: &'a [Task],
    pub side_label: &'a str,
    pub stats: &'a LiveStats,
    pub tx_db: mpsc::SyncSender<ScanMsg>,
    pub is_ufs: bool,
    pub tx_ui: &'a mpsc::Sender<PhaseEvent>,
    pub bar_idx: usize,
    pub log_anom: Arc<Mutex<File>>,
    pub log_info: Arc<Mutex<File>>,
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
        tx_ui,
        bar_idx,
        log_anom,
        log_info,
        debug_log,
    } = ctx;

    tasks.par_chunks(CHUNK_SIZE).for_each_with(tx_db, |tx_db, chunk| {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

        let mut results = Vec::with_capacity(chunk.len());
        let mut local_ext_weights: HashMap<String, u64> = HashMap::new();
        let mut local_encoding_counts: HashMap<String, usize> = HashMap::new();
        let mut local_eol_counts: HashMap<String, usize> = HashMap::new();
        let mut local_junk_reason_counts: HashMap<String, usize> = HashMap::new();
        let mut last_ui_update = Instant::now();

        for task in chunk {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

            let metoda_start = debug_log.is_active().then(Instant::now);
            let full_path = base_path.join(&task.rel_path);
            let ext = Path::new(&task.rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
            let file_size = std::fs::metadata(&full_path).map(|m| m.len()).unwrap_or(0);
            if let Some(t) = metoda_start {
                debug_log.log(side_label, "odczyt metadanych (fs::metadata)", &task.rel_path, t.elapsed(), "OK");
            }

            *local_ext_weights.entry(ext.clone()).or_insert(0) += file_size;
            let bytes_read = std::cmp::min(file_size, 65536);

            let metoda = "Walidacja tekstu (kodowanie/EOL)";

            // Log info: linia "Start" PRZED analizą — niezależnie od wyniku,
            // żeby operator widział ostatni plik dotknięty przez fazę, gdyby
            // ta akurat zawiesiła się w środku.
            if let Ok(mut f) = log_info.lock() {
                let _ = writeln!(
                    f,
                    "[{}] [{:<15}] [START ] [Metoda: {:<24}] Źródło: \"{}\"",
                    crate::utils::log_timestamp(), side_label, metoda, full_path.display()
                );
            }

            let call_start = debug_log.is_active().then(Instant::now);
            let (analysis_opt, io_err) = match stats.thread_activity.track_current(|| analyze_text_file(&full_path, file_size)) {
                Ok(ana) => {
                    let kategoria = if task.is_common { "Wspólne" } else { "Osobne" };

                    if ana.is_valid {
                        *local_encoding_counts.entry(ana.encoding.clone()).or_insert(0) += 1;
                        *local_eol_counts.entry(ana.eol.clone()).or_insert(0) += 1;

                        if let Ok(mut f) = log_info.lock() {
                            let _ = writeln!(f, "[{:<15}] [{:<7}] [{} | {}] Format: .{:<4} | Ścieżka: \"{}\"",
                                side_label, kategoria, ana.encoding, ana.eol, ext, full_path.display());
                        }
                    } else {
                        if task.is_common { stats.junk_common.fetch_add(1, Ordering::Relaxed); }
                        else { stats.junk_unique.fetch_add(1, Ordering::Relaxed); }

                        let reason = ana.reason.as_deref().unwrap_or("Nieznany błąd");
                        *local_junk_reason_counts.entry(reason.to_string()).or_insert(0) += 1;

                        if let Ok(mut f) = log_anom.lock() {
                            let _ = writeln!(f, "[{:<15}] [{:<7}] [{}] Format: .{:<4} | Ścieżka: \"{}\"",
                                side_label, kategoria, reason, ext, full_path.display());
                        }
                    }

                    if ana.near_threshold {
                        if task.is_common { stats.near_threshold_common.fetch_add(1, Ordering::Relaxed); }
                        else { stats.near_threshold_unique.fetch_add(1, Ordering::Relaxed); }
                    }

                    if ana.is_oneliner {
                        if task.is_common { stats.oneliner_common.fetch_add(1, Ordering::Relaxed); }
                        else { stats.oneliner_unique.fetch_add(1, Ordering::Relaxed); }

                        if let Ok(mut f) = log_anom.lock() {
                            let _ = writeln!(f, "[{:<15}] [{:<7}] [Podejrzany One-Liner (>10KB bez znaku nowej linii)] Format: .{:<4} | Ścieżka: \"{}\"",
                                side_label, kategoria, ext, full_path.display());
                        }
                    }

                    (Some(ana), Some(false))
                },
                Err(e) => {
                    warn!(path = %task.rel_path, side = side_label, error = %e, "Błąd I/O");
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    (None, Some(true))
                }
            };
            let wynik = if io_err == Some(true) {
                "BŁĄD I/O".to_string()
            } else {
                match &analysis_opt {
                    Some(ana) if ana.is_valid => "OK".to_string(),
                    Some(ana) => format!("BŁĄD: {}", ana.reason.as_deref().unwrap_or("Nieznany błąd")),
                    None => "BŁĄD: Nieznany błąd".to_string(),
                }
            };
            if let Some(t) = call_start {
                debug_log.log(side_label, metoda, &task.rel_path, t.elapsed(), &wynik);
            }

            let zapis_start = debug_log.is_active().then(Instant::now);
            if let Ok(mut f) = log_info.lock() {
                let _ = writeln!(
                    f,
                    "[{}] [{:<15}] [KONIEC] [Metoda: {:<24}] [Wynik: {}] Źródło: \"{}\"",
                    crate::utils::log_timestamp(), side_label, metoda, wynik, full_path.display()
                );
            }
            if let Some(t) = zapis_start {
                debug_log.log(side_label, "zapis wyniku (log info)", &task.rel_path, t.elapsed(), "OK");
            }

            stats.processed_files.fetch_add(1, Ordering::Relaxed);
            stats.processed_bytes.fetch_add(bytes_read, Ordering::Relaxed);

            let current = stats.processed_files.load(Ordering::Relaxed);
            let now = Instant::now();

            let should_update = current.is_multiple_of(200)
                || now.duration_since(last_ui_update).as_millis() > 250;

            if should_update {
                last_ui_update = now;

                if !local_ext_weights.is_empty() {
                    let mut global_map = stats.ext_weights.lock().unwrap_or_else(|e| e.into_inner());
                    for (k, v) in local_ext_weights.drain() { *global_map.entry(k).or_insert(0) += v; }
                }
                if !local_encoding_counts.is_empty() {
                    let mut global_map = stats.encoding_counts.lock().unwrap_or_else(|e| e.into_inner());
                    for (k, v) in local_encoding_counts.drain() { *global_map.entry(k).or_insert(0) += v; }
                }
                if !local_eol_counts.is_empty() {
                    let mut global_map = stats.eol_counts.lock().unwrap_or_else(|e| e.into_inner());
                    for (k, v) in local_eol_counts.drain() { *global_map.entry(k).or_insert(0) += v; }
                }
                if !local_junk_reason_counts.is_empty() {
                    let mut global_map = stats.junk_reason_counts.lock().unwrap_or_else(|e| e.into_inner());
                    for (k, v) in local_junk_reason_counts.drain() { *global_map.entry(k).or_insert(0) += v; }
                }

                let _ = tx_ui.send(PhaseEvent::UpdateBar {
                    idx: bar_idx,
                    current: current as u64,
                    message: format_display_path(&task.rel_path),
                });
                let _ = tx_ui.send(PhaseEvent::UpdateBottomPath {
                    idx: bar_idx,
                    path: format!("[{}] {}", metoda, full_path.to_string_lossy()),
                });

                let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                    idx: bar_idx,
                    text: stats.build_source_block(side_label),
                });
            }

            results.push(SideValidationResult { id: task.id, analysis: analysis_opt, io_error: io_err });
        }

        if !local_ext_weights.is_empty() {
            let mut global_map = stats.ext_weights.lock().unwrap_or_else(|e| e.into_inner());
            for (k, v) in local_ext_weights.drain() { *global_map.entry(k).or_insert(0) += v; }
        }

        if !local_encoding_counts.is_empty() {
            let mut global_map = stats.encoding_counts.lock().unwrap_or_else(|e| e.into_inner());
            for (k, v) in local_encoding_counts.drain() { *global_map.entry(k).or_insert(0) += v; }
        }

        if !local_eol_counts.is_empty() {
            let mut global_map = stats.eol_counts.lock().unwrap_or_else(|e| e.into_inner());
            for (k, v) in local_eol_counts.drain() { *global_map.entry(k).or_insert(0) += v; }
        }

        if !results.is_empty() {
            if is_ufs { let _ = tx_db.send(ScanMsg::UfsChunk(results)); }
            else { let _ = tx_db.send(ScanMsg::ScriptChunk(results)); }
        }
    });

    // REGRESJA (ten sam wzorzec co Faza 8): pasek zawsze dostawał komunikat
    // "w 100% zakończony", nawet gdy user anulował w połowie.
    let przetworzone = stats.processed_files.load(Ordering::Relaxed);
    let anulowano = CANCEL_SIGNAL.load(Ordering::SeqCst);
    let wiadomosc = if anulowano {
        format!("🛑 Przerwano — przetworzono {} plików.", przetworzone)
    } else {
        "Odczyt ciał tekstowych w 100% zakończony.".to_string()
    };
    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: przetworzone as u64,
        message: wiadomosc,
    });
}

// ============================================================================
// GŁÓWNA FUNKCJA KORDYNUJĄCA (Entrypoint)
// ============================================================================

fn compute_half_threads(total_threads: usize) -> usize {
    std::cmp::max(1, total_threads / 2)
}

pub fn run(
    conn: &mut Connection,
    config: &Ustawienia,
    tx_ui: mpsc::Sender<PhaseEvent>,
) -> Result<()> {
    crate::utils::CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    let actual_threads = if config.max_threads > 0 {
        config.max_threads
    } else {
        rayon::current_num_threads()
    };
    let io_text = if config.io_mode == "CONCURRENT" {
        "RÓWNOLEGŁE (SSD/NVMe)"
    } else {
        "SEKWENCYJNIE (HDD)"
    };

    let _ = tx_ui.send(PhaseEvent::Log(format!(
        "Uruchomiono Fazę 10. Metodyka szyny dyskowej: {}",
        io_text
    )));
    let _ = tx_ui.send(PhaseEvent::Log(format!(
        "Aktywne wątki procesora (Rayon): {}",
        actual_threads
    )));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    let _ = conn.execute("ALTER TABLE files ADD COLUMN text_enc_ufs TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN text_enc_script TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN text_eol_ufs TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN text_eol_script TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN is_oneliner_ufs INTEGER", []);
    let _ = conn.execute(
        "ALTER TABLE files ADD COLUMN is_oneliner_script INTEGER",
        [],
    );

    let raport_cfg = config
        .raporty_faz
        .get("Faza 10")
        .cloned()
        .unwrap_or_else(|| crate::settings::RaportFazy {
            katalog: config.log_path.clone(),
            plik_operacyjny: "raport_operacyjny_faza10.txt".to_string(),
            plik_dziennika: "dziennik_koncowy_faza10.txt".to_string(),
        });

    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    // Wszystkie pliki tego przebiegu fazy (operacyjny, dziennik końcowy,
    // info, debug) niosą ten sam znacznik czasu, więc łatwo je ze sobą
    // powiązać na dysku, a kolejne uruchomienia się nie nadpisują.
    let stamp = crate::utils::run_timestamp();
    let opr_path = Path::new(&raport_cfg.katalog)
        .join(crate::utils::stamp_filename(&raport_cfg.plik_operacyjny, &stamp));
    let dz_path = Path::new(&raport_cfg.katalog)
        .join(crate::utils::stamp_filename(&raport_cfg.plik_dziennika, &stamp));
    let info_path = Path::new(&raport_cfg.katalog).join(crate::utils::stamp_filename(
        "raport_operacyjny_faza10_zdrowe_teksty.txt",
        &stamp,
    ));
    let debug_log = crate::debug_log::DebugLog::maybe_open(
        &raport_cfg.katalog,
        &crate::utils::stamp_filename("dziennik_debug_faza10.txt", &stamp),
        &config.log_level,
    );

    let log_anom = match File::create(&opr_path) {
        Ok(f) => Arc::new(Mutex::new(f)),
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!("BŁĄD I/O: Nie udało się utworzyć pliku raportu na dysku: {}. Sprawdź uprawnienia (Write-Blocker?).", e)));
            return Ok(());
        }
    };

    let log_info = match File::create(&info_path) {
        Ok(f) => Arc::new(Mutex::new(f)),
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!(
                "BŁĄD I/O: Nie udało się utworzyć pliku informacji: {}",
                e
            )));
            return Ok(());
        }
    };

    {
        let mut f_anom = log_anom.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(
            f_anom,
            "=== RAPORT OPERACYJNY - FAZA 10 (ANOMALIE TEKSTOWE) ==="
        );
        let _ = writeln!(
            f_anom,
            "Zestawienie plików rzekomo tekstowych zniszczonych zupą binarną lub posiadających fałszywe Payloady (One-Linery).\n"
        );

        let mut f_info = log_info.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(
            f_info,
            "=== RAPORT OPERACYJNY - FAZA 10 (POPRAWNE PLIKI TEKSTOWE) ==="
        );
        let _ = writeln!(
            f_info,
            "Szczegółowa kategoryzacja prawidłowych skryptów (System Operacyjny oraz Kodowanie znaków).\n"
        );
    }

    // --- ETAP 1: POBIERANIE ZADAŃ Z BAZY ---
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, utf8_ok_ufs, utf8_ok_script, io_error_ufs, io_error_script
         FROM files WHERE phase10_done = 0 OR phase10_done IS NULL"
    )?;

    let mut ufs_tasks = Vec::new();
    let mut script_tasks = Vec::new();
    let mut non_text_ids = Vec::new();
    let mut skipped_ufs = 0;
    let mut skipped_script = 0;

    let rows: Vec<_> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, Option<bool>>(4)?,
                row.get::<_, Option<bool>>(5)?,
                row.get::<_, Option<bool>>(6)?,
                row.get::<_, Option<bool>>(7)?,
            ))
        })?
        .collect::<Result<Vec<_>>>()?;

    for (id, rel, in_ufs, in_script, u_ufs, u_scr, err_ufs, err_scr) in rows {
        if is_text_extension(&rel) {
            let is_common = in_ufs && in_script;
            if in_ufs {
                if u_ufs.is_none() && err_ufs != Some(true) {
                    ufs_tasks.push(Task {
                        id,
                        rel_path: rel.clone(),
                        is_common,
                    });
                } else {
                    skipped_ufs += 1;
                }
            }
            if in_script {
                if u_scr.is_none() && err_scr != Some(true) {
                    script_tasks.push(Task {
                        id,
                        rel_path: rel,
                        is_common,
                    });
                } else {
                    skipped_script += 1;
                }
            }
        } else {
            non_text_ids.push(id);
        }
    }
    drop(stmt);

    if !non_text_ids.is_empty() {
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "Zwalnianie {} plików nietekstowych (obrazy, wideo) z radaru kolejki...",
            non_text_ids.len()
        )));
        let tx_trans = conn.transaction()?;
        for chunk in non_text_ids.chunks(900) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let query = format!(
                "UPDATE files SET phase10_done = 1 WHERE id IN ({})",
                placeholders
            );
            tx_trans.execute(&query, rusqlite::params_from_iter(chunk))?;
        }
        tx_trans.commit()?;
    }

    if skipped_ufs > 0 || skipped_script > 0 {
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "Pominięto skrypty z wyliczonym kodowaniem. UFS: {}, Skrypt: {}",
            skipped_ufs, skipped_script
        )));
    }

    let total_db_rows = ufs_tasks.len() + script_tasks.len();
    if total_db_rows == 0 {
        let _ = tx_ui.send(PhaseEvent::Log(
            "✔ Walidacja tekstowa jest kompletna. Zamykam status fazy...".to_string(),
        ));
    }

    let _ = tx_ui.send(PhaseEvent::SetBar {
        idx: 0,
        label: "UFS Explorer (Teksty)".to_string(),
        total: ufs_tasks.len() as u64,
        color: Color::Cyan,
    });
    let _ = tx_ui.send(PhaseEvent::SetBar {
        idx: 1,
        label: "Skrypt Autorski (Teksty)".to_string(),
        total: script_tasks.len() as u64,
        color: Color::Magenta,
    });
    let _ = tx_ui.send(PhaseEvent::SetBar {
        idx: 2,
        label: "Zapis SQLite".to_string(),
        total: total_db_rows as u64,
        color: Color::Green,
    });

    let half_threads = compute_half_threads(actual_threads);
    let activity_slots = compute_activity_slots(&config.io_mode, actual_threads, half_threads);

    let ufs_stats = LiveStats::new(activity_slots, start_time);
    let script_stats = LiveStats::new(activity_slots, start_time);
    let ufs_base = PathBuf::from(&config.ufs_path);
    let script_base = PathBuf::from(&config.script_path);

    // --- ETAP 3: PRZETWARZANIE STRUMIENIOWE (MPSC) ---
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
                        let mut stmt = match &msg {
                            ScanMsg::UfsChunk(_) => tx_trans.prepare_cached(
                                "UPDATE files SET utf8_ok_ufs = COALESCE(?1, utf8_ok_ufs), text_enc_ufs = COALESCE(?2, text_enc_ufs), text_eol_ufs = COALESCE(?3, text_eol_ufs), is_oneliner_ufs = COALESCE(?4, is_oneliner_ufs), io_error_ufs = COALESCE(?5, io_error_ufs) WHERE id = ?6"
                            )?,
                            ScanMsg::ScriptChunk(_) => tx_trans.prepare_cached(
                                "UPDATE files SET utf8_ok_script = COALESCE(?1, utf8_ok_script), text_enc_script = COALESCE(?2, text_enc_script), text_eol_script = COALESCE(?3, text_eol_script), is_oneliner_script = COALESCE(?4, is_oneliner_script), io_error_script = COALESCE(?5, io_error_script) WHERE id = ?6"
                            )?,
                        };

                        let chunk = match &msg {
                            ScanMsg::UfsChunk(c) => c,
                            ScanMsg::ScriptChunk(c) => c,
                        };

                        for res in chunk {
                            if res.analysis.is_some() || res.io_error == Some(true) {
                                let (ok, enc, eol, is_one) = match &res.analysis {
                                    Some(a) => (Some(a.is_valid), Some(a.encoding.clone()), Some(a.eol.clone()), Some(a.is_oneliner)),
                                    None => (None, None, None, None)
                                };
                                stmt.execute(params![ok, enc, eol, is_one, res.io_error, res.id])?;
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
            let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Wskaźniki kodowania zaktualizowane.".to_string() });
            Ok(())
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone();
            let tx2 = tx_db.clone();
            let anom_u = log_anom.clone();
            let anom_s = log_anom.clone();
            let info_u = log_info.clone();
            let info_s = log_info.clone();
            let dbg_u = debug_log.clone();
            let dbg_s = debug_log.clone();

            let stat_u = &ufs_stats;
            let stat_s = &script_stats;

            s.spawn(move || {
                if !ufs_tasks.is_empty() {
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new()
                        .num_threads(half_threads)
                        .build()
                    {
                        pool.install(|| {
                            process_side_stream(StreamCtx {
                                base_path: &ufs_base,
                                tasks: &ufs_tasks,
                                side_label: "UFS Explorer",
                                stats: stat_u,
                                tx_db: tx1,
                                is_ufs: true,
                                tx_ui: tx_ui_ref,
                                bar_idx: 0,
                                log_anom: anom_u,
                                log_info: info_u,
                                debug_log: dbg_u.clone(),
                            });
                        });
                    } else {
                        process_side_stream(StreamCtx {
                            base_path: &ufs_base,
                            tasks: &ufs_tasks,
                            side_label: "UFS Explorer",
                            stats: stat_u,
                            tx_db: tx1,
                            is_ufs: true,
                            tx_ui: tx_ui_ref,
                            bar_idx: 0,
                            log_anom: anom_u,
                            log_info: info_u,
                            debug_log: dbg_u.clone(),
                        });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log(
                        "✔ Walidacja tekstu (UFS) zakończona.".to_string(),
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
                                base_path: &script_base,
                                tasks: &script_tasks,
                                side_label: "Skrypt Autorski",
                                stats: stat_s,
                                tx_db: tx2,
                                is_ufs: false,
                                tx_ui: tx_ui_ref,
                                bar_idx: 1,
                                log_anom: anom_s,
                                log_info: info_s,
                                debug_log: dbg_s.clone(),
                            });
                        });
                    } else {
                        process_side_stream(StreamCtx {
                            base_path: &script_base,
                            tasks: &script_tasks,
                            side_label: "Skrypt Autorski",
                            stats: stat_s,
                            tx_db: tx2,
                            is_ufs: false,
                            tx_ui: tx_ui_ref,
                            bar_idx: 1,
                            log_anom: anom_s,
                            log_info: info_s,
                            debug_log: dbg_s.clone(),
                        });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log(
                        "✔ Walidacja tekstu (Skrypt) zakończona.".to_string(),
                    ));
                }
            });
            drop(tx_db);
        } else {
            let anom_u = log_anom.clone();
            let anom_s = log_anom.clone();
            let info_u = log_info.clone();
            let info_s = log_info.clone();
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
                    tx_ui: tx_ui_ref,
                    bar_idx: 0,
                    log_anom: anom_u,
                    log_info: info_u,
                    debug_log: dbg_u,
                });
                let _ = tx_ui_ref.send(PhaseEvent::Log(
                    "✔ Walidacja tekstu (UFS) zakończona.".to_string(),
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
                    tx_ui: tx_ui_ref,
                    bar_idx: 1,
                    log_anom: anom_s,
                    log_info: info_s,
                    debug_log: dbg_s,
                });
                let _ = tx_ui_ref.send(PhaseEvent::Log(
                    "✔ Walidacja tekstu (Skrypt) zakończona.".to_string(),
                ));
            }
            drop(tx_db);
        }

        match db_thread.join() {
            Ok(wynik) => wynik,
            Err(_) => {
                let _ = tx_ui.send(PhaseEvent::Log(
                    "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 10 mógł nie zostać w pełni zapisany.".to_string()
                ));
                Err(rusqlite::Error::UnwindingPanic)
            }
        }
    });
    wynik_zapisu?;

    // REGRESJA (ten sam wzorzec co Faza 9): bez tego sprawdzenia po
    // anulowaniu faza i tak generowała pełny raport końcowy.
    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log(
            "🛑 Walidacja tekstu przerwana przez użytkownika. Postęp w bazie został zapisany."
                .to_string(),
        ));
        return Ok(());
    }

    // --- ETAP 4: SYNCHRONIZACJA Z BAZĄ DANYCH ---
    let _ = tx_ui.send(PhaseEvent::Log(
        "Trwa generowanie hierarchicznego raportu kryminalistycznego...".to_string(),
    ));

    conn.execute(
        "UPDATE files SET phase10_done = CASE
            WHEN (found_in_ufs = 0 OR utf8_ok_ufs IS NOT NULL OR io_error_ufs = 1)
             AND (found_in_script = 0 OR utf8_ok_script IS NOT NULL OR io_error_script = 1) THEN 1
            ELSE 0
        END WHERE phase10_done = 0 OR phase10_done IS NULL",
        [],
    )?;

    // --- ETAP 5: HIERARCHICZNY RAPORT KRYMINALISTYCZNY (Zapis do pliku) ---
    let mut stmt = conn.prepare(
        "SELECT relative_path, found_in_ufs, found_in_script,
                utf8_ok_ufs, utf8_ok_script, is_oneliner_ufs, is_oneliner_script
         FROM files WHERE phase10_done = 1",
    )?;

    let mut cat_junk = AnomalyCategory::new(
        "Zupa Binarna w Tekście (Twardy Null / Brak znaków ASCII)",
        "🗑️",
    );
    let mut cat_oneliner = AnomalyCategory::new(
        "Podejrzany One-Liner (>10KB brak LF, potencjalny payload)",
        "⚠️",
    );

    let rows: Vec<_> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, Option<bool>>(3)?,
                row.get::<_, Option<bool>>(4)?,
                row.get::<_, Option<bool>>(5)?,
                row.get::<_, Option<bool>>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>>>()?;

    for (rel_path, in_ufs, in_scr, u_ufs, u_scr, one_ufs, one_scr) in rows {
        let is_common = in_ufs && in_scr;
        let ext = Path::new(&rel_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("brak")
            .to_lowercase();

        let add_to_cat = |cat: &mut AnomalyCategory, is_ufs_source: bool| {
            let target = if is_common {
                &mut cat.common
            } else {
                &mut cat.unique
            };
            let map = if is_ufs_source {
                &mut target.ufs
            } else {
                &mut target.script
            };
            map.entry(ext.clone()).or_default().push(rel_path.clone());
        };

        if in_ufs {
            if u_ufs == Some(false) {
                add_to_cat(&mut cat_junk, true);
            }
            if one_ufs == Some(true) {
                add_to_cat(&mut cat_oneliner, true);
            }
        }
        if in_scr {
            if u_scr == Some(false) {
                add_to_cat(&mut cat_junk, false);
            }
            if one_scr == Some(true) {
                add_to_cat(&mut cat_oneliner, false);
            }
        }
    }
    drop(stmt);

    let elapsed = start_time.elapsed();
    let total_bytes = ufs_stats.processed_bytes.load(Ordering::SeqCst)
        + script_stats.processed_bytes.load(Ordering::SeqCst);
    let avg_speed_mb = (total_bytes as f64 / 1_048_576.0) / elapsed.as_secs_f64().max(1.0);
    let total_io_errors =
        ufs_stats.errors.load(Ordering::SeqCst) + script_stats.errors.load(Ordering::SeqCst);

    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(
        &mut log_out,
        "=========================================================================="
    );
    let _ = writeln!(
        &mut log_out,
        "DZIENNIK KOŃCOWY - FAZA 10 (WALIDACJA KODOWANIA I TEKSTU)"
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
        "[ 1 ] SEMANTYKA I WŁAŚCIWOŚCI POPRAWNYCH PLIKÓW TEKSTOWYCH (rozkład pełny, oba źródła):"
    );
    {
        let ufs_eol = ufs_stats
            .eol_counts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let scr_eol = script_stats
            .eol_counts
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut merged: HashMap<String, usize> = HashMap::new();
        for (k, v) in ufs_eol.iter().chain(scr_eol.iter()) {
            *merged.entry(k.clone()).or_insert(0) += v;
        }
        let mut sorted: Vec<_> = merged.into_iter().collect();
        sorted.sort_by_key(|a| std::cmp::Reverse(a.1));
        for (eol, count) in sorted {
            let _ = writeln!(&mut log_out, "   -> {}: {} plików", eol, count);
        }
        let _ = writeln!(
            &mut log_out,
            "      [ ZNACZENIE ]: Pliki o niespójnym lub złym zakończeniu linii mogą wywołać błędy przy uruchamianiu skryptów (np. plików .sh na Linuksie).\n"
        );
    }

    let _ = writeln!(
        &mut log_out,
        "[ 2 ] PROFILOWANIE KODOWANIA ZNAKÓW (rozkład pełny, oba źródła):"
    );
    {
        let ufs_enc = ufs_stats
            .encoding_counts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let scr_enc = script_stats
            .encoding_counts
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut merged: HashMap<String, usize> = HashMap::new();
        for (k, v) in ufs_enc.iter().chain(scr_enc.iter()) {
            *merged.entry(k.clone()).or_insert(0) += v;
        }
        let mut sorted: Vec<_> = merged.into_iter().collect();
        sorted.sort_by_key(|a| std::cmp::Reverse(a.1));
        for (enc, count) in sorted {
            let _ = writeln!(&mut log_out, "   -> {}: {} plików", enc, count);
        }
        let _ = writeln!(&mut log_out);
    }

    let write_section_txt = |out: &mut String, title: &str, is_common: bool| {
        let _ = writeln!(out, "[ KATEGORIA BŁĘDÓW: {} ]", title);
        let categories = [&cat_oneliner, &cat_junk];

        let mut has_any = false;
        for cat in &categories {
            let src_anom = if is_common { &cat.common } else { &cat.unique };
            let ufs_total: usize = src_anom.ufs.values().map(|v| v.len()).sum();
            let scr_total: usize = src_anom.script.values().map(|v| v.len()).sum();

            if ufs_total > 0 || scr_total > 0 {
                has_any = true;
                let _ = writeln!(
                    out,
                    "   {} Typ anomalii: {} (UFS: {}, Skrypt: {})",
                    cat.icon, cat.name, ufs_total, scr_total
                );
                if cat.name.contains("Zupa Binarna") {
                    let _ = writeln!(
                        out,
                        "      [ ZNACZENIE ]: Carver błędnie uznał zniszczony plik binarny (np. ucięty .dll, .exe) za plik tekstowy. To częste zjawisko zwane 'False Positive'."
                    );
                } else if cat.name.contains("One-Liner") {
                    let _ = writeln!(
                        out,
                        "      [ ZNACZENIE ]: Plik waży >10KB i nie ma żadnego entera. Może to być kod zminifikowany, lub zaszyfrowany wirus Base64."
                    );
                }

                let mut print_exts = |map: &ExtMap, label: &str| {
                    if !map.is_empty() {
                        let _ = writeln!(out, "      {} - Rozkład formatów:", label);
                        let mut sorted: Vec<_> = map.iter().collect();
                        sorted.sort_by_key(|a| std::cmp::Reverse(a.1.len()));
                        for (ext, paths) in sorted.into_iter().take(3) {
                            let _ = writeln!(
                                out,
                                "         .{:<5} : {} plików (Przykł: {})",
                                ext,
                                paths.len(),
                                paths[0]
                            );
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

    write_section_txt(&mut log_out, "Część Wspólna (Oba źródła)", true);
    write_section_txt(
        &mut log_out,
        "Osobne ścieżki (Unikalne dla jednego źródła)",
        false,
    );

    let _ = writeln!(&mut log_out, "[ PODSUMOWANIE WAGOWE FORMATÓW ]");
    let print_all_exts = |out_str: &mut String, map: &HashMap<String, u64>, label: &str| {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        let _ = writeln!(out_str, "   {}", label);
        if sorted.is_empty() {
            let _ = writeln!(out_str, "      Brak plików.");
        }
        for (ext, weight) in sorted.into_iter().take(5) {
            let e = if ext == "brak" {
                "brak".to_string()
            } else {
                format!(".{}", ext)
            };
            let _ = writeln!(out_str, "      - {:<8} : {}", e, format_bytes(*weight));
        }
    };

    print_all_exts(
        &mut log_out,
        &ufs_stats
            .ext_weights
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
        "UFS Explorer",
    );
    print_all_exts(
        &mut log_out,
        &script_stats
            .ext_weights
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
        "Skrypt Autorski",
    );

    let _ = writeln!(&mut log_out);

    if total_io_errors > 0 {
        let _ = writeln!(&mut log_out, "[ 🚨 BŁĘDY FIZYCZNE I/O ]");
        let _ = writeln!(
            &mut log_out,
            "   -> Błędy odczytu (I/O): {}",
            total_io_errors
        );
    }

    if let Ok(mut f) = fs::File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "✔ Zapisano fizyczny Dziennik Końcowy w: {}",
            dz_path.display()
        )));
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "✔ Zapisano Raporty Operacyjne (Live) w: {} oraz {}",
            opr_path.display(),
            info_path.display()
        )));
    }

    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    info!(
        total_io_errors,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 10 zakończona"
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

    #[test]
    fn test_compute_activity_slots_concurrent_uses_half_threads() {
        assert_eq!(compute_activity_slots("CONCURRENT", 4, 2), 2);
    }

    #[test]
    fn test_compute_activity_slots_sequential_uses_full_actual_threads() {
        assert_eq!(compute_activity_slots("SEQUENTIAL", 4, 2), 4);
    }

    fn make_temp_file(content: &[u8]) -> NamedTempFile {
        let mut f =
            NamedTempFile::new().expect("Nie udało się utworzyć pliku tymczasowego w teście");
        f.write_all(content)
            .expect("Nie udało się zapisać zawartości do pliku tymczasowego");
        f
    }

    #[test]
    fn test_is_text_extension_known_extensions() {
        assert!(is_text_extension("skrypt.py"));
        assert!(is_text_extension("dane.JSON"));
        assert!(is_text_extension("/sciezka/do/pliku.RS"));
    }

    #[test]
    fn test_is_text_extension_rozszerzone_formaty_kodu_i_konfiguracji() {
        for nazwa in [
            "main.c",
            "app.cpp",
            "Nagłówek.h",
            "Main.java",
            "main.go",
            "skrypt.rb",
            "app.conf",
            "zmienne.env",
        ] {
            assert!(
                is_text_extension(nazwa),
                "'{}' powinno być rozpoznane jako tekstowe",
                nazwa
            );
        }
        assert!(is_text_extension("plik.CONF"));
    }

    #[test]
    fn test_is_text_extension_unknown_extension() {
        assert!(!is_text_extension("obraz.jpg"));
        assert!(!is_text_extension("archiwum.zip"));
        assert!(!is_text_extension("bez_rozszerzenia"));
    }

    #[test]
    fn test_analyze_eol_lf_unix() {
        let f = make_temp_file(b"linia1\nlinia2\nlinia3\n");
        let a = analyze_text_file(f.path(), 21)
            .expect("Nie udało się przeanalizować pliku LF Unix w teście");
        assert_eq!(a.eol, "LF (Unix)");
    }

    #[test]
    fn test_analyze_eol_crlf_windows() {
        let f = make_temp_file(b"linia1\r\nlinia2\r\n");
        let a = analyze_text_file(f.path(), 16)
            .expect("Nie udało się przeanalizować pliku CRLF Windows w teście");
        assert_eq!(a.eol, "CRLF (Windows)");
    }

    #[test]
    fn test_analyze_eol_mixed() {
        let f = make_temp_file(b"linia1\r\nlinia2\nlinia3\n");
        let a = analyze_text_file(f.path(), 22)
            .expect("Nie udało się przeanalizować pliku mieszanego w teście");
        assert_eq!(a.eol, "Mieszane (CRLF+LF)");
    }

    #[test]
    fn test_analyze_eol_none_small_file() {
        let f = make_temp_file(b"jedna linia bez entera");
        let a = analyze_text_file(f.path(), 22)
            .expect("Nie udało się przeanalizować małego pliku w teście");
        assert_eq!(a.eol, "Mieszane/Inne");
        assert!(!a.is_oneliner);
    }

    #[test]
    fn test_analyze_oneliner_detected_above_10kb() {
        let content = vec![b'A'; 11000];
        let f = make_temp_file(&content);
        let a = analyze_text_file(f.path(), 11000)
            .expect("Nie udało się przeanalizować pliku one-liner powyżej 10KB w teście");
        assert!(a.is_oneliner);
    }

    #[test]
    fn test_analyze_no_oneliner_when_has_newlines() {
        let mut content = vec![b'A'; 11000];
        content.push(b'\n');
        let f = make_temp_file(&content);
        let a = analyze_text_file(f.path(), 11001)
            .expect("Nie udało się przeanalizować pliku z nowymi liniami w teście");
        assert!(
            !a.is_oneliner,
            "Plik z choć jednym \\n nie powinien być one-linerem"
        );
    }

    #[test]
    fn test_analyze_encoding_ascii() {
        let f = make_temp_file(b"zwykly tekst ascii\n");
        let a = analyze_text_file(f.path(), 19)
            .expect("Nie udało się przeanalizować pliku ASCII w teście");
        assert_eq!(a.encoding, "ASCII");
        assert!(a.is_valid);
    }

    #[test]
    fn test_analyze_encoding_utf8_with_diacritics() {
        let content = "zażółć gęślą jaźń\n".as_bytes();
        let f = make_temp_file(content);
        let a = analyze_text_file(f.path(), content.len() as u64)
            .expect("Nie udało się przeanalizować pliku UTF-8 z diakrytykami w teście");
        assert_eq!(a.encoding, "UTF-8");
        assert!(a.is_valid);
    }

    #[test]
    fn test_analyze_encoding_utf16_bom_le() {
        let mut content = vec![0xFF, 0xFE];
        content.extend_from_slice(b"a\0b\0c\0");
        let f = make_temp_file(&content);
        let a = analyze_text_file(f.path(), content.len() as u64)
            .expect("Nie udało się przeanalizować pliku UTF-16 BOM LE w teście");
        assert_eq!(a.encoding, "UTF-16");
    }

    #[test]
    fn test_analyze_encoding_utf16_fake_bom_random_binary_is_invalid() {
        let mut content = vec![0xFF, 0xFE];
        let mut state: u64 = 0x2545F4914F6CDD1D;
        for _ in 0..4000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            content.push((state >> 33) as u8);
        }
        let f = make_temp_file(&content);
        let a = analyze_text_file(f.path(), content.len() as u64)
            .expect("Nie udało się przeanalizować pliku z fałszywym BOM w teście");
        assert_eq!(a.encoding, "UTF-16");
        assert!(
            !a.is_valid,
            "Podrobiony BOM UTF-16 z losową zawartością musi zostać odrzucony"
        );
        assert!(
            a.reason
                .expect("Powód odrzucenia (reason) powinien być obecny dla odrzuconego pliku")
                .contains("Zupa Binarna")
        );
    }

    #[test]
    fn test_analyze_encoding_utf16_bom_genuine_text_is_valid() {
        let text = "Zażółć gęślą jaźń. Zwykly tekst UTF-16 z duza iloscia znakow.".repeat(5);
        let mut content = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            content.extend_from_slice(&unit.to_le_bytes());
        }
        let f = make_temp_file(&content);
        let a = analyze_text_file(f.path(), content.len() as u64)
            .expect("Nie udało się przeanalizować prawdziwego pliku UTF-16 w teście");
        assert_eq!(a.encoding, "UTF-16");
        assert!(
            a.is_valid,
            "Prawdziwy tekst UTF-16 nie powinien zostac odrzucony"
        );
    }

    #[test]
    fn test_analyze_encoding_utf8_bom() {
        let mut content = vec![0xEF, 0xBB, 0xBF];
        content.extend_from_slice(b"tekst\n");
        let f = make_temp_file(&content);
        let a = analyze_text_file(f.path(), content.len() as u64)
            .expect("Nie udało się przeanalizować pliku UTF-8 z BOM w teście");
        assert_eq!(a.encoding, "UTF-8 (BOM)");
        assert!(a.is_valid);
    }

    #[test]
    fn test_analyze_hard_null_byte_is_invalid() {
        let content = vec![b'a', b'b', 0x00, b'c'];
        let f = make_temp_file(&content);
        let a = analyze_text_file(f.path(), 4)
            .expect("Nie udało się przeanalizować pliku z bajtem NULL w teście");
        assert!(!a.is_valid);
        assert!(
            a.reason
                .expect("Powód odrzucenia (reason) powinien być obecny dla pliku z bajtem NULL")
                .contains("NULL")
        );
    }

    #[test]
    fn test_analyze_binary_soup_high_control_chars_ratio() {
        let mut content: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        content.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        content.extend_from_slice(b"reszta zwyklego tekstu aby miec odpowiednia dlugosc bufora");
        let f = make_temp_file(&content);
        let a = analyze_text_file(f.path(), content.len() as u64).expect(
            "Nie udało się przeanalizować pliku z wysokim udziałem znaków kontrolnych w teście",
        );
        assert!(!a.is_valid);
        assert!(
            a.reason
                .expect("Powód odrzucenia (reason) powinien być obecny dla pliku z zupą binarną")
                .contains("Zupa Binarna")
        );
    }

    #[test]
    fn test_analyze_near_threshold_flagged_even_when_still_valid() {
        let mut content: Vec<u8> = vec![0xFF];
        content.extend(vec![0x01u8; 5]);
        content.extend(vec![b'a'; 104]);
        let f = make_temp_file(&content);
        let a = analyze_text_file(f.path(), content.len() as u64)
            .expect("Nie udało się przeanalizować pliku blisko progu w teście");
        assert!(
            a.is_valid,
            "4.545% kontrolnych jest poniżej progu >5% - plik NIE powinien być odrzucony"
        );
        assert!(
            a.near_threshold,
            "4.545% mieści się w paśmie granicznym 4-6% wokół progu"
        );
    }

    #[test]
    fn test_analyze_far_from_threshold_not_flagged() {
        let content =
            b"zwykly tekst bez zadnych bajtow kontrolnych ani problemow z kodowaniem wcale";
        let f = make_temp_file(content);
        let a = analyze_text_file(f.path(), content.len() as u64)
            .expect("Nie udało się przeanalizować czystego pliku tekstu w teście");
        assert!(a.is_valid);
        assert!(
            !a.near_threshold,
            "zwykły czysty tekst nie ma żadnego ryzyka granicznego"
        );
    }

    #[test]
    fn test_analyze_empty_file_is_valid() {
        let f = make_temp_file(b"");
        let a = analyze_text_file(f.path(), 0)
            .expect("Nie udało się przeanalizować pustego pliku w teście");
        assert!(a.is_valid);
        assert_eq!(a.encoding, "ASCII");
        assert_eq!(a.eol, "Brak");
        assert!(!a.is_oneliner);
    }

    #[test]
    fn test_analyze_nonexistent_file_is_io_error() {
        let result = analyze_text_file(Path::new("/nieistniejaca/sciezka.txt"), 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_source_block_reports_counts() {
        let stats = LiveStats::new(4, Instant::now() - Duration::from_secs(1));
        stats.junk_common.store(2, Ordering::Relaxed);
        stats.junk_unique.store(1, Ordering::Relaxed);
        stats.oneliner_common.store(3, Ordering::Relaxed);
        stats.oneliner_unique.store(4, Ordering::Relaxed);
        stats.errors.store(5, Ordering::Relaxed);

        let block = stats.build_source_block("UFS Explorer");

        assert!(block.starts_with("[UFS Explorer]"));
        assert!(block.contains("Zupa binarna: 2 wspólne / 1 unikalne"));
        assert!(block.contains("One-Liner (>10KB): 3 wspólne / 4 unikalne"));
        assert!(block.contains("Błędy I/O: 5"));
    }

    #[test]
    fn test_build_source_block_junk_reason_full_breakdown() {
        let stats = LiveStats::new(4, Instant::now() - Duration::from_millis(500));
        stats
            .junk_reason_counts
            .lock()
            .expect("Nie udało się zablokować junk_reason_counts w teście")
            .insert(
                "Twardy Bajt NULL (0x00) - Slack Space lub fałszywy odzysk".to_string(),
                7,
            );
        stats
            .junk_reason_counts
            .lock()
            .expect("Nie udało się zablokować junk_reason_counts w teście")
            .insert("Zupa Binarna (>5% znaków kontrolnych)".to_string(), 3);

        let block = stats.build_source_block("UFS Explorer");

        let line = block
            .lines()
            .find(|l| l.starts_with("Powody zupy binarnej:"))
            .expect("Brak linijki 'Powody zupy binarnej:' w wygenerowanym bloku");
        assert!(line.contains("Twardy Bajt NULL (0x00) - Slack Space lub fałszywy odzysk: 7"));
        assert!(line.contains("Zupa Binarna (>5% znaków kontrolnych): 3"));
    }

    #[test]
    fn test_build_source_block_reports_near_threshold_counts() {
        let stats = LiveStats::new(4, Instant::now() - Duration::from_millis(500));
        stats.near_threshold_common.store(6, Ordering::Relaxed);
        stats.near_threshold_unique.store(2, Ordering::Relaxed);

        let block = stats.build_source_block("UFS Explorer");

        assert!(
            block.contains("Blisko progu zupy binarnej (4-6% kontrolnych): 6 wspólne / 2 unikalne")
        );
    }

    #[test]
    fn test_build_source_block_shows_thread_activity_markup() {
        let stats = LiveStats::new(2, Instant::now() - Duration::from_millis(500));
        stats.thread_activity.mark_busy(0);

        let block = stats.build_source_block("UFS Explorer");

        let line = block
            .lines()
            .find(|l| l.starts_with("Wątki analizy"))
            .expect("powinna istnieć linia Wariantu A");
        assert_eq!(line, "Wątki analizy (Wariant A): {G:1} {R:2}");
    }

    #[test]
    fn test_build_source_block_full_breakdown_not_just_top_one() {
        let stats = LiveStats::new(4, Instant::now() - Duration::from_millis(500));
        stats
            .eol_counts
            .lock()
            .expect("Nie udało się zablokować eol_counts w teście")
            .insert("LF (Unix)".to_string(), 10);
        stats
            .eol_counts
            .lock()
            .expect("Nie udało się zablokować eol_counts w teście")
            .insert("CRLF (Windows)".to_string(), 5);
        stats
            .eol_counts
            .lock()
            .expect("Nie udało się zablokować eol_counts w teście")
            .insert("Mieszane (CRLF+LF)".to_string(), 2);

        let block = stats.build_source_block("UFS Explorer");

        let eol_line = block
            .lines()
            .find(|l| l.starts_with("Architektura EOL:"))
            .expect("Brak linijki 'Architektura EOL:' w wygenerowanym bloku");
        assert!(eol_line.contains("LF (Unix): 10"));
        assert!(eol_line.contains("CRLF (Windows): 5"));
        assert!(eol_line.contains("Mieszane (CRLF+LF): 2"));
    }

    #[test]
    fn test_build_source_block_placeholder_when_no_data() {
        let stats = LiveStats::new(4, Instant::now() - Duration::from_millis(500));
        let block = stats.build_source_block("Skrypt Autorski");
        assert!(block.contains("Architektura EOL: -"));
        assert!(block.contains("Kodowanie: -"));
    }

    #[test]
    fn test_etykiety_maja_zarejestrowane_wyjasnienia_albo_sa_generyczne() {
        const GENERYCZNE: &[&str] = &[
            "Prędkość",
            "Top format",
            "Wątki analizy (Wariant A)",
            "Błędy I/O",
        ];

        let stats = LiveStats::new(1, Instant::now() - Duration::from_millis(500));
        let block = stats.build_source_block("UFS Explorer");

        let mut sprawdzonych = 0;
        for line in block.lines() {
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
                "etykieta '{}' z panelu Fazy 10 nie ma zarejestrowanego wyjaśnienia ani nie jest na liście generycznych",
                etykieta
            );
            sprawdzonych += 1;
        }
        assert_eq!(
            sprawdzonych, 6,
            "panel powinien mieć dokładnie 6 etykiet wymagających wyjaśnienia"
        );
    }

    #[test]
    fn test_compute_half_threads_basic() {
        assert_eq!(compute_half_threads(8), 4);
        assert_eq!(compute_half_threads(1), 1);
        assert_eq!(compute_half_threads(0), 1);
    }
}

// ============================================================================
// TESTY INTEGRACYJNE — run() z SQLite in-memory + tymczasowy katalog
// ============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;
    use rusqlite::{Connection, params};
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    /// Serializuje testy, które manipulują globalnym `CANCEL_SIGNAL`.
    static CANCEL_LOCK: Mutex<()> = Mutex::new(());

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("czas systemowy przed UNIX_EPOCH?")
                .as_nanos();
            let p = std::env::temp_dir().join(format!("phase10_test_{}_{}_{}", tag, pid, nanos));
            std::fs::create_dir_all(&p)
                .unwrap_or_else(|e| panic!("nie udało się utworzyć {:?}: {}", p, e));
            TempDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn config_seq(ufs: &Path, script: &Path, logs: &Path) -> Ustawienia {
        let mut u = Ustawienia {
            ufs_path: ufs.to_string_lossy().into_owned(),
            script_path: script.to_string_lossy().into_owned(),
            log_path: logs.to_string_lossy().into_owned(),
            io_mode: "SEQUENTIAL".to_string(),
            ..Default::default()
        };
        u.raporty_faz.clear();
        u
    }

    fn fresh_db() -> Connection {
        crate::db::init_db(":memory:").expect("init_db")
    }

    /// Wstawia rekord jako plik WSPÓLNY (obecny po obu stronach).
    fn insert_common(conn: &Connection, rel: &str) {
        conn.execute(
            "INSERT INTO files (relative_path, found_in_ufs, found_in_script)
             VALUES (?1, 1, 1)",
            params![rel],
        )
        .expect("INSERT");
    }

    /// Wstawia rekord jako plik tylko-UFS.
    fn insert_unique_ufs(conn: &Connection, rel: &str) {
        conn.execute(
            "INSERT INTO files (relative_path, found_in_ufs, found_in_script)
             VALUES (?1, 1, 0)",
            params![rel],
        )
        .expect("INSERT");
    }

    #[test]
    fn test_run_empty_db_completes_cleanly() {
        let ufs = TempDir::new("empty_ufs");
        let script = TempDir::new("empty_script");
        let logs = TempDir::new("empty_logs");

        let mut conn = fresh_db();
        let config = config_seq(ufs.path(), script.path(), logs.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        CANCEL_SIGNAL.store(false, Ordering::SeqCst);
        run(&mut conn, &config, tx_ui).expect("run() na pustej bazie");
    }

    #[test]
    fn test_run_marks_nontext_files_as_done() {
        let ufs = TempDir::new("nontext_ufs");
        let script = TempDir::new("nontext_script");
        let logs = TempDir::new("nontext_logs");

        let mut conn = fresh_db();
        insert_unique_ufs(&conn, "obraz.jpg");

        let config = config_seq(ufs.path(), script.path(), logs.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        CANCEL_SIGNAL.store(false, Ordering::SeqCst);
        run(&mut conn, &config, tx_ui).expect("run()");

        let (done, enc, utf8_ok): (i64, Option<String>, Option<bool>) = conn.query_row(
            "SELECT phase10_done, text_enc_ufs, utf8_ok_ufs FROM files WHERE relative_path = 'obraz.jpg'",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).expect("query_row");

        assert_eq!(
            done, 1,
            "plik nietekstowy musi być oznaczony jako przetworzony"
        );
        assert!(enc.is_none(), "nietekstowy nie ma kolumny kodowania");
        assert!(utf8_ok.is_none(), "nietekstowy nie ma kolumny utf8_ok");
    }

    #[test]
    fn test_run_processes_text_file_and_saves_encoding() {
        let ufs = TempDir::new("text_ufs");
        let script = TempDir::new("text_script");
        let logs = TempDir::new("text_logs");

        std::fs::write(ufs.path().join("skrypt.txt"), b"linia1\nlinia2\n").expect("write");

        let mut conn = fresh_db();
        insert_unique_ufs(&conn, "skrypt.txt");

        let config = config_seq(ufs.path(), script.path(), logs.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        CANCEL_SIGNAL.store(false, Ordering::SeqCst);
        run(&mut conn, &config, tx_ui).expect("run()");

        let (done, enc, eol, utf8_ok): (i64, Option<String>, Option<String>, Option<bool>) = conn.query_row(
            "SELECT phase10_done, text_enc_ufs, text_eol_ufs, utf8_ok_ufs FROM files WHERE relative_path = 'skrypt.txt'",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).expect("query_row");

        assert_eq!(done, 1);
        assert_eq!(enc.as_deref(), Some("ASCII"), "kodowanie: {:?}", enc);
        assert_eq!(eol.as_deref(), Some("LF (Unix)"), "EOL: {:?}", eol);
        assert_eq!(utf8_ok, Some(true));
    }

    #[test]
    fn test_run_marks_binary_soup_as_invalid() {
        let ufs = TempDir::new("soup_ufs");
        let script = TempDir::new("soup_script");
        let logs = TempDir::new("soup_logs");

        std::fs::write(ufs.path().join("smiec.txt"), b"abc\x00def\n").expect("write");

        let mut conn = fresh_db();
        insert_unique_ufs(&conn, "smiec.txt");

        let config = config_seq(ufs.path(), script.path(), logs.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        CANCEL_SIGNAL.store(false, Ordering::SeqCst);
        run(&mut conn, &config, tx_ui).expect("run()");

        let (done, utf8_ok): (i64, Option<bool>) = conn
            .query_row(
                "SELECT phase10_done, utf8_ok_ufs FROM files WHERE relative_path = 'smiec.txt'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query_row");

        assert_eq!(done, 1);
        assert_eq!(
            utf8_ok,
            Some(false),
            "NULL bajt w .txt musi dać utf8_ok_ufs=false"
        );
    }

    #[test]
    fn test_run_handles_io_error_on_missing_file() {
        let ufs = TempDir::new("ioerr_ufs");
        let script = TempDir::new("ioerr_script");
        let logs = TempDir::new("ioerr_logs");

        let mut conn = fresh_db();
        insert_unique_ufs(&conn, "nie_ma_mnie.txt");

        let config = config_seq(ufs.path(), script.path(), logs.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        CANCEL_SIGNAL.store(false, Ordering::SeqCst);
        run(&mut conn, &config, tx_ui).expect("run()");

        let (done, io_err): (i64, Option<bool>) = conn.query_row(
            "SELECT phase10_done, io_error_ufs FROM files WHERE relative_path = 'nie_ma_mnie.txt'",
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).expect("query_row");

        assert_eq!(
            done, 1,
            "rekord musi być oznaczony jako przetworzony mimo błędu I/O"
        );
        assert_eq!(io_err, Some(true), "brak pliku musi dać io_error_ufs=true");
    }

    /// Weryfikuje, że `run()` respektuje globalny `CANCEL_SIGNAL`.
    ///
    /// **Dwa mechanizmy detekcji postępu — celowo użyte razem:**
    ///
    /// 1. **Canceller polluje plik logu operacyjnego** (`info_path`), do
    ///    którego `run()` pisze wiersz per każdy poprawny plik tekstowy.
    ///    Header ~160 B + ~100 B na wiersz — próg 300 B oznacza min. 2 pliki
    ///    przetworzone. Poll przez `yield_now()` (bez `sleep`), bo przy
    ///    szybkim przetwarzaniu (~5 µs/plik) `sleep(1ms)` gubił moment.
    ///
    /// 2. **Asercja sprawdza `utf8_ok_ufs IS NOT NULL`, nie `phase10_done = 1`.**
    ///    Przy anulowaniu `run()` wychodzi PRZED Etapem 4 (który dopiero
    ///    ustawia `phase10_done`), więc ta kolumna zostaje na 0/NULL.
    ///    `utf8_ok_ufs` jest zapisywane przez wątek DB **w trakcie**
    ///    przetwarzania, więc odzwierciedla faktyczny postęp przed cancel.
    #[test]
    fn test_run_honors_cancel_signal() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let ufs = TempDir::new("cancel_ufs");
        let script = TempDir::new("cancel_script");
        let logs = TempDir::new("cancel_logs");

        // 5000 plików × ~18 bajtów. Faza 10 czyta tylko pierwsze 64 KB
        // każdego pliku, więc pojedynczy plik to ~5-10 µs. Całość: ~25-50 ms.
        const TOTAL: usize = 5_000;
        for i in 0..TOTAL {
            std::fs::write(
                ufs.path().join(format!("plik{:05}.txt", i)),
                b"linia1\nlinia2\nlinia3\n",
            )
            .expect("write");
        }

        let mut conn = fresh_db();
        {
            let mut stmt = conn.prepare(
                "INSERT INTO files (relative_path, found_in_ufs, found_in_script) VALUES (?1, 1, 0)"
            ).expect("prepare");
            for i in 0..TOTAL {
                stmt.execute(params![format!("plik{:05}.txt", i)])
                    .expect("INSERT");
            }
        }

        let config = config_seq(ufs.path(), script.path(), logs.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        // Katalog logów — run() pisze do pliku "zdrowe teksty" jeden wiersz
        // per każdy poprawny plik tekstowy. Nazwa niesie teraz znacznik czasu
        // (patrz `utils::stamp_filename`), więc go SZUKAMY po prefiksie
        // zamiast zakładać stałą nazwę.
        let logs_dir = logs.path().to_path_buf();

        // Busy-poll (yield_now) — setki iteracji na ms, łapie moment gdy log
        // przekracza próg NATYCHMIAST po zapisie. `sleep(1ms)` gubił moment,
        // bo run() kończył 5000 plików szybciej niż canceller się obudził.
        let canceller = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if Instant::now() > deadline {
                    break;
                }
                let znaleziono_progresz = std::fs::read_dir(&logs_dir)
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.ok())
                    .any(|e| {
                        e.file_name()
                            .to_str()
                            .is_some_and(|n| n.starts_with("raport_operacyjny_faza10_zdrowe_teksty"))
                            && e.metadata().map(|m| m.len() > 300).unwrap_or(false)
                    });
                if znaleziono_progresz {
                    break;
                }
                std::thread::yield_now();
            }
            CANCEL_SIGNAL.store(true, Ordering::SeqCst);
        });

        let result = run(&mut conn, &config, tx_ui);
        canceller
            .join()
            .expect("wątek anulujący nie może panikować");
        // Krytyczne: reset globalnego sygnału — inaczej następny test
        // (albo normalne uruchomienie w tej samej sesji) zaczyna od "anuluj".
        CANCEL_SIGNAL.store(false, Ordering::SeqCst);

        result.expect("run() nie powinno zwrócić Err po anulowaniu");

        // KLUCZOWE: przy anulowaniu run() wychodzi PRZED Etapem 4, więc
        // `phase10_done` NIE jest ustawione. Poprzednia wersja sprawdzała
        // `phase10_done = 1` i dostawała 0 — mimo że postęp był.
        let done: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE utf8_ok_ufs IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .expect("query_row");

        assert!(
            done > 0,
            "coś powinno zostać przetworzone przed cancel, jest {}",
            done
        );
        assert!(
            done < TOTAL as i64,
            "cancel powinien przerwać przed końcem — {} z {} przetworzone",
            done,
            TOTAL
        );
    }

    /// Test pliku WSPÓLNEGO (obecnego po OBU stronach): Faza 10 musi
    /// niezależnie zwalidować i zapisać kodowanie/EOL do OBU kolumn
    /// (`utf8_ok_ufs` + `text_enc_ufs` + `text_eol_ufs` oraz
    /// `utf8_ok_script` + `text_enc_script` + `text_eol_script`).
    ///
    /// Chroni przed regresją, gdyby ktoś kiedyś:
    /// - zgubił jedną ze stron przy rozdzielaniu `Task` do `ufs_tasks`/`script_tasks`,
    /// - pomylił `is_common` (klasyfikacja do liczników `_common`/`_unique`),
    /// - wprowadził bug w pętli `process_side_stream` powodujący że jedno
    ///   z dwóch źródeł jest cicho pomijane w wątku DB (np. zły `ScanMsg`
    ///   discriminant).
    #[test]
    fn test_run_processes_common_file_updates_both_sides() {
        let ufs = TempDir::new("common_ufs");
        let script = TempDir::new("common_script");
        let logs = TempDir::new("common_logs");

        // Ten sam plik tekstowy po OBU stronach (identyczna treść, ASCII z LF).
        std::fs::write(ufs.path().join("shared.txt"), b"linia1\nlinia2\n").expect("write");
        std::fs::write(script.path().join("shared.txt"), b"linia1\nlinia2\n").expect("write");

        let mut conn = fresh_db();
        insert_common(&conn, "shared.txt");

        let config = config_seq(ufs.path(), script.path(), logs.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        CANCEL_SIGNAL.store(false, Ordering::SeqCst);
        run(&mut conn, &config, tx_ui).expect("run()");

        let (done, u_ok, s_ok, u_enc, s_enc, u_eol, s_eol): (
            i64,
            Option<bool>,
            Option<bool>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = conn
            .query_row(
                "SELECT phase10_done,
                    utf8_ok_ufs, utf8_ok_script,
                    text_enc_ufs, text_enc_script,
                    text_eol_ufs, text_eol_script
             FROM files WHERE relative_path = 'shared.txt'",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .expect("query_row");

        assert_eq!(done, 1, "plik wspólny musi być oznaczony jako przetworzony");

        assert_eq!(
            u_ok,
            Some(true),
            "strona UFS musi być zwalidowana (utf8_ok_ufs=true)"
        );
        assert_eq!(
            s_ok,
            Some(true),
            "strona Skryptu musi być zwalidowana (utf8_ok_script=true)"
        );

        assert_eq!(
            u_enc.as_deref(),
            Some("ASCII"),
            "kodowanie UFS: {:?}",
            u_enc
        );
        assert_eq!(
            s_enc.as_deref(),
            Some("ASCII"),
            "kodowanie Skrypt: {:?}",
            s_enc
        );

        assert_eq!(u_eol.as_deref(), Some("LF (Unix)"), "EOL UFS: {:?}", u_eol);
        assert_eq!(
            s_eol.as_deref(),
            Some("LF (Unix)"),
            "EOL Skrypt: {:?}",
            s_eol
        );
    }
}
