// src/phases/phase4.rs

//! # Faza 4: Uniwersalna Akwizycja Sum Kontrolnych (BLAKE3) i Magicznych Bajtów
//!
//! Zintegrowany, jednoprzebiegowy silnik skanujący dla plików resztkowych 
//! (unikalnych oraz tych o różnym rozmiarze). Posiada twardy limit RAM (sync_channel),
//! zintegrowaną w locie weryfikację Magic Bytes oraz obsługę systemu Dual-Logging,
//! a komunikacja wizualna opiera się na Ratatui PhaseEvent.
//!
//! UWAGA ARCHITEKTONICZNA (UI): Pasek postępu pokazuje wyłącznie % i bieżący plik.
//! Liczniki live trafiają do panelu bocznego jako DWA tematyczne bloki, sumujące
//! OBIE strony (Wariant B) — `[Kryptografia i sygnatury (Resztki)]` (prędkość,
//! top format, sygnatury, spoofing, błędy I/O) i `[Anomalie nagłówka (Resztki)]`
//! (10 kategorii anomalii z osobna) — patrz [`build_crypto_block`]/
//! [`build_anomaly_block`]. IDENTYCZNY układ jak w Fazie 3 (patrz jej
//! dokumentacja `build_crypto_block`/`build_anomaly_block`) — świadomie ujednolicone
//! na życzenie użytkownika, mimo że zbiory plików UFS/Skrypt są tu rozłączne z
//! definicji (pliki UNIKALNE, nie wspólne jak w Fazie 3): sumowanie LICZNIKÓW
//! progresu obu równoległych stron jest sensowne niezależnie od tego, czy same
//! ZBIORY PLIKÓW się pokrywają. Dziennik końcowy (`run`) nadal rozbija wyniki
//! PER STRONA osobno — to podsumowanie kryminalistyczne, nie panel live, i tej
//! separacji nie dotyczy.
//!
//! UWAGA ARCHITEKTONICZNA (WĄTKOWANIE): W trybie `io_mode = "CONCURRENT"` obie
//! strony skanują jednocześnie, każda na własnej, tymczasowej puli Rayon o
//! rozmiarze `actual_threads / 2` (min. 1) — identyczny mechanizm jak w Fazie 3
//! (patrz `phase3::compute_half_threads`), gwarantujący, że łączne zużycie CPU
//! obu stron nie przekracza limitu `max_threads` ustawionego przez użytkownika.
//!
//! RÓŻNICA WZGLĘDEM FAZY 3 (odnotowana świadomie, nie poprawiona automatycznie):
//! budowa prywatnej puli używa tu `.build().unwrap()`, podczas gdy Faza 3 ma
//! bezpieczniejszy fallback `if let Ok(pool) = ... else { wersja bez puli }`.
//! W skrajnie rzadkim przypadku wyczerpania zasobów OS (niemożność utworzenia
//! nowego wątku) Faza 4 spanikuje, a Faza 3 kontynuuje na globalnej puli.
//! Praktyczne ryzyko jest znikome (budowa puli Rayon prawie nigdy nie zawodzi
//! na normalnie działającym systemie), ale warto to ujednolicić przy okazji
//! kolejnej rewizji tego pliku.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::{format_bytes, format_display_path, hash_file, CANCEL_SIGNAL};
use ratatui::style::Color;
use rayon::prelude::*;
use rusqlite::{params, Connection, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, instrument, warn};

// OPTYMALIZACJA: Podniesiono do 500, transakcje hybrydowe w SQLite to bez problemu obsłużą.
const CHUNK_SIZE: usize = 500;

// ============================================================================
// STRUKTURY DANYCH
// ============================================================================

/// Pojedyncze zadanie: rekord z bazy oczekujący na hash BLAKE3 i weryfikację
/// Magic Bytes po JEDNEJ stronie (plik unikalny lub resztkowy).
#[derive(Debug, Clone)]
pub(crate) struct Task {
    /// Klucz główny rekordu w tabeli `files`.
    id: i32,
    /// Ścieżka względna liczona od katalogu bazowego danej strony.
    rel_path: String,
}

/// Wynik przetworzenia jednego zadania, przekazywany przez MPSC do wątku zapisu SQLite.
#[derive(Debug, Clone)]
pub(crate) struct ScanResult {
    id: i32,
    /// Hash BLAKE3 (hex). `None` przy pustym pliku bez wyniku, błędzie I/O lub anulowaniu.
    hash: Option<String>,
    /// `Some(true)` = rozszerzenie zgodne z nagłówkiem, `Some(false)` = spoofing,
    /// `None` = plik bez rozszerzenia (nie dotyczy).
    magic_ok: Option<bool>,
    /// `Some(true)` przy błędzie I/O otwarcia/odczytu pliku.
    io_error: Option<bool>,
}

/// Wiadomość do wątku zapisu SQLite, oznaczona stroną pochodzenia (inny UPDATE per strona).
pub(crate) enum ScanMsg {
    UfsChunk(Vec<ScanResult>),
    ScriptChunk(Vec<ScanResult>),
}

/// Liczniki live dla JEDNEJ strony. Panel boczny sumuje je z licznikami drugiej
/// strony (`other_stats` w [`StreamCtx`]) — patrz [`build_crypto_block`]/
/// [`build_anomaly_block`] — a raport końcowy (`run`) dodatkowo rozbija je
/// PER STRONA, niezależnie od tego łączenia.
pub(crate) struct LiveStats {
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    /// Błędy I/O przy otwieraniu LUB przy właściwym hashowaniu ([`hash_file`]).
    hash_errors: AtomicUsize,
    magic_errors: AtomicUsize,
    valid_signatures: AtomicUsize, 
    
    /// Suma wag (bajtów) per rozszerzenie — do "Top format" w panelu bocznym.
    ext_weights: Mutex<HashMap<String, u64>>, 
    
    offset_anomalies: AtomicUsize,
    null_padding: AtomicUsize,
    ascii_trash: AtomicUsize,
    micro_files: AtomicUsize,
    sub_magic_errors: AtomicUsize,
    slack_space_contam: AtomicUsize,
    parasitic_injections: AtomicUsize,
    endian_conflicts: AtomicUsize,
    boundary_drops: AtomicUsize,
    high_volatility: AtomicUsize,

    /// EKSPERYMENTALNE (Wariant A, patrz moduł `thread_activity`): śledzi,
    /// który logiczny slot dedykowanej puli Rayon TEJ strony aktualnie liczy
    /// BLAKE3 — NIE fizyczny rdzeń CPU. Rozmiar dobierany zależnie od trybu
    /// I/O (patrz [`compute_activity_slots`]).
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    /// `slot_count` powinno odpowiadać rozmiarowi puli Rayon FAKTYCZNIE
    /// używanej przez TĘ stronę — patrz [`compute_activity_slots`].
    fn new(slot_count: usize) -> Self {
        Self {
            processed_files: AtomicUsize::new(0),
            processed_bytes: AtomicU64::new(0),
            hash_errors: AtomicUsize::new(0),
            magic_errors: AtomicUsize::new(0),
            valid_signatures: AtomicUsize::new(0),
            ext_weights: Mutex::new(HashMap::new()),
            offset_anomalies: AtomicUsize::new(0),
            null_padding: AtomicUsize::new(0),
            ascii_trash: AtomicUsize::new(0),
            micro_files: AtomicUsize::new(0),
            sub_magic_errors: AtomicUsize::new(0),
            slack_space_contam: AtomicUsize::new(0),
            parasitic_injections: AtomicUsize::new(0),
            endian_conflicts: AtomicUsize::new(0),
            boundary_drops: AtomicUsize::new(0),
            high_volatility: AtomicUsize::new(0),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }
}

/// Wylicza liczbę slotów trackera zajętości (Wariant A) odpowiednią dla
/// trybu I/O — patrz identyczna logika i uzasadnienie w `phase3::compute_activity_slots`
/// (naprawiony tam bug: `half_threads` niezależnie od trybu po cichu gubił
/// śledzenie wątków w SEQUENTIAL, gdzie w rzeczywistości działa CAŁA
/// globalna pula, nie dedykowana połówka).
fn compute_activity_slots(io_mode: &str, actual_threads: usize, half_threads: usize) -> usize {
    if io_mode == "CONCURRENT" { half_threads } else { actual_threads }
}

/// Buduje zbiorczy blok `[Kryptografia i sygnatury (Resztki)]` sumując
/// prędkość, top 3 formaty wagowo, sygnatury, spoofing i błędy I/O z OBU
/// stron — mirror `phase3::build_crypto_block` (Wariant B), patrz
/// dokumentacja modułu.
fn build_crypto_block(own: &LiveStats, other: &LiveStats, start_time: Instant) -> String {
    let combined_bytes = own.processed_bytes.load(Ordering::Relaxed) + other.processed_bytes.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
    let speed_mb = (combined_bytes as f64 / 1_048_576.0) / elapsed;

    let top_exts_str = {
        let mut merged: HashMap<String, u64> = HashMap::new();
        for (k, v) in own.ext_weights.lock().unwrap().iter() { *merged.entry(k.clone()).or_insert(0) += v; }
        for (k, v) in other.ext_weights.lock().unwrap().iter() { *merged.entry(k.clone()).or_insert(0) += v; }
        let mut sorted: Vec<_> = merged.into_iter().collect();
        sorted.sort_by_key(|a| std::cmp::Reverse(a.1));
        sorted.into_iter().take(3).map(|(ext, w)| {
            let e = if ext == "brak" { "brak".to_string() } else { format!(".{}", ext) };
            format!("{} ({})", e, format_bytes(w))
        }).collect::<Vec<_>>().join(", ")
    };
    let display_top = if top_exts_str.is_empty() { "Analiza danych...".to_string() } else { top_exts_str };

    let combined_valid = own.valid_signatures.load(Ordering::Relaxed) + other.valid_signatures.load(Ordering::Relaxed);
    let combined_io_err = own.hash_errors.load(Ordering::Relaxed) + other.hash_errors.load(Ordering::Relaxed);
    let combined_magic_err = own.magic_errors.load(Ordering::Relaxed) + other.magic_errors.load(Ordering::Relaxed);

    let activity_markup = crate::thread_activity::format_activity_markup(&own.thread_activity.snapshot());

    format!(
        "[Kryptografia i sygnatury (Resztki)]\nPrędkość: {:.2} MB/s\nTop format: {}\nPoprawne sygnatury: {}\nBłędy I/O: {}\nSpoofing (magic): {}\nWątki BLAKE3 (Wariant A): {}",
        speed_mb, display_top, combined_valid, combined_io_err, combined_magic_err, activity_markup
    )
}

/// Buduje zbiorczy blok `[Anomalie nagłówka (Resztki)]` sumując 10 kategorii
/// anomalii nagłówka z OBU stron — mirror `phase3::build_anomaly_block`
/// (Wariant B). W odróżnieniu od poprzedniej wersji tego panelu (jedna
/// zbiorcza liczba "Anomalie nagłówka (suma)") rozpisuje każdą kategorię
/// osobno, dokładnie tak jak Faza 3.
fn build_anomaly_block(own: &LiveStats, other: &LiveStats) -> String {
    let sum = |a: &AtomicUsize, b: &AtomicUsize| a.load(Ordering::Relaxed) + b.load(Ordering::Relaxed);

    format!(
        "[Anomalie nagłówka (Resztki)]\nPrzesunięty nagłówek: {}\nNull-padding: {}\nŚmieci ASCII: {}\nMikro-plik <32B: {}\nZła pod-sygnatura: {}\nSkażony slack space: {}\nIniekcja pasożytnicza: {}\nKonflikt endian: {}\nUrwana granica sektora: {}\nWysoka wolatywność: {}",
        sum(&own.offset_anomalies, &other.offset_anomalies),
        sum(&own.null_padding, &other.null_padding),
        sum(&own.ascii_trash, &other.ascii_trash),
        sum(&own.micro_files, &other.micro_files),
        sum(&own.sub_magic_errors, &other.sub_magic_errors),
        sum(&own.slack_space_contam, &other.slack_space_contam),
        sum(&own.parasitic_injections, &other.parasitic_injections),
        sum(&own.endian_conflicts, &other.endian_conflicts),
        sum(&own.boundary_drops, &other.boundary_drops),
        sum(&own.high_volatility, &other.high_volatility),
    )
}

/// Flagi anomalii wykryte w pierwszym klastrze (pierwszy odczytany fragment,
/// typowo do 128 KB) pliku. Identyczna logika detekcji jak w Fazie 3
/// ([`crate::phases::phase3`]) — patrz tamtejszy docstring dla wyjaśnienia
/// każdej heurystyki; nie duplikuję opisu tutaj, kod obu funkcji jest zgodny.
struct HeaderAnomalies {
    is_micro: bool,
    has_null: bool,
    has_offset: bool,
    has_trash: bool,
    sub_magic_err: bool,
    slack_contam: bool,
    parasitic: bool,
    endian_conflict: bool,
    boundary_drop: bool,
    high_volatility: bool,
}

// ============================================================================
// LOGIKA KRYMINALISTYCZNA (ULTIMATE HEADER FORENSICS)
// ============================================================================

/// Analizuje pierwszy fragment pliku pod kątem 10 niezależnych anomalii
/// strukturalnych nagłówka. Patrz [`crate::phases::phase3::analyze_header_cluster`]
/// — ta funkcja jest bit-identyczna z odpowiednikiem w Fazie 3 (świadomie
/// zduplikowana, nie wydzielona do wspólnego modułu — obie fazy mają być
/// niezależne i samodzielnie kompletne, zgodnie z resztą architektury projektu).
fn analyze_header_cluster(buf: &[u8], file_size: u64, ext: &str) -> HeaderAnomalies {
    let mut anom = HeaderAnomalies {
        is_micro: false, has_null: false, has_offset: false, has_trash: false,
        sub_magic_err: false, slack_contam: false, parasitic: false,
        endian_conflict: false, boundary_drop: false, high_volatility: false,
    };

    if file_size < 32 || buf.len() < 32 {
        anom.is_micro = true;
        return anom; 
    }

    anom.has_null = buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 && buf[3] == 0x00;
    
    anom.has_offset = buf.windows(4).position(|w| {
        w == b"\xFF\xD8\xFF\xE0" || w == b"\xFF\xD8\xFF\xE1" ||
        w == b"\x50\x4B\x03\x04" ||
        w == b"%PDF" ||
        w == b"\x89PNG"
    }).is_some_and(|pos| pos > 0 && pos < buf.len().saturating_sub(4));

    let is_pdf = &buf[0..4] == b"%PDF";
    anom.has_trash = !is_pdf && buf[0..4].iter().all(|b| b.is_ascii_alphanumeric() || b.is_ascii_punctuation()) 
        && !anom.has_offset 
        && matches!(ext, "jpg" | "zip" | "mp4" | "png");

    if buf.len() >= 12 && &buf[0..4] == b"RIFF" && &buf[8..12] != b"AVI " && &buf[8..12] != b"WEBP" && &buf[8..12] != b"WAVE" {
        anom.sub_magic_err = true;
    }
    
    if buf.len() >= 10 && &buf[0..2] == b"BM" && (buf[6] != 0 || buf[7] != 0 || buf[8] != 0 || buf[9] != 0) {
        anom.slack_contam = true;
    }
    
    anom.parasitic = buf[32..].windows(4).any(|w| w == b"\x50\x4B\x03\x04" || w == b"\x50\x45\x00\x00");

    if buf.len() >= 4 && &buf[0..2] == b"II" && buf[2] == 0x00 && buf[3] == 0x2A { 
        anom.endian_conflict = true;
    }

    if buf.len() >= 512 {
        anom.boundary_drop = (buf[508] == 0x00 && buf[509] == 0x00 && buf[510] == 0x00 && buf[511] == 0x00) 
                          || (buf[508] == 0xFF && buf[509] == 0xFF && buf[510] == 0xFF && buf[511] == 0xFF);
    }

    let volatility: i32 = buf.windows(2).map(|w| (w[0] as i32 - w[1] as i32).abs()).sum();
    anom.high_volatility = volatility > 60000;

    anom
}

// ============================================================================
// GŁÓWNY SKANER RDZENIOWY (JEDNOPRZEBIEGOWE I/O)
// ============================================================================

/// Skanuje wszystkie zadania (`tasks`) dla JEDNEJ strony: dla każdego pliku
/// czyta pierwszy fragment (analiza forensyczna + Magic Bytes), liczy hash
/// przez [`hash_file`], aktualizuje [`LiveStats`] i strumieniuje wyniki do
/// wątku zapisu SQLite. Rozgłasza postęp/statystyki do UI co ~60ms.
///
/// RÓŻNICA WZGLĘDEM FAZY 3: używa `par_chunks(...).for_each_init(...)` zamiast
/// `for_each_with(...)` — stan inicjalizacyjny (klon `tx_db`, `last_ui_update`,
/// lokalny bufor logów `log_buf`) jest tworzony RAZ NA WĄTEK ROBOCZY Rayon i
/// utrzymuje się między kolejnymi porcjami (`chunk`) przydzielanymi temu
/// samemu wątkowi — zamiast być tworzony od nowa przy każdej porcji. Efekt:
/// throttling UI (60ms) i log_buf są ciągłe w obrębie życia wątku, a nie
/// resetowane na granicy każdego chunka.
pub struct StreamCtx<'a> {
    pub base_path: &'a Path,
    pub tasks: &'a [Task],
    pub side_label: &'a str,
    pub stats: &'a LiveStats,
    /// Liczniki DRUGIEJ strony — patrz [`build_crypto_block`]/[`build_anomaly_block`]
    /// (Wariant B: panel boczny sumuje obie strony niezależnie od tego, która
    /// z nich wywołała aktualizację).
    pub other_stats: &'a LiveStats,
    pub tx_db: mpsc::SyncSender<ScanMsg>,
    pub is_ufs: bool,
    pub tx_ui: &'a mpsc::Sender<PhaseEvent>,
    pub bar_idx: usize,
    pub opr_log: Arc<Mutex<File>>,
    pub start_time: Instant,
}

#[instrument(skip(ctx), fields(base_path = %ctx.base_path.display()))]

#[allow(clippy::match_like_matches_macro)]
fn process_side_stream<'a>(ctx: StreamCtx<'a>) {
    let StreamCtx { base_path, tasks, side_label, stats, other_stats, tx_db, is_ufs, tx_ui, bar_idx, opr_log, start_time } = ctx;

    tasks.par_chunks(CHUNK_SIZE).for_each_init(
        || (tx_db.clone(), Instant::now(), Vec::new()),
        |(tx, last_ui_update, log_buf), chunk| {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

            let mut results = Vec::with_capacity(chunk.len());
            let mut local_ext_weights: HashMap<String, u64> = HashMap::new();

            for task in chunk {
                if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

                let full_path: PathBuf = base_path.join(&task.rel_path);
                let file_size = std::fs::metadata(&full_path).map(|m| m.len()).unwrap_or(0);

                let mut file = match File::open(&full_path) {
                    Ok(f) => f,
                    Err(_) => {
                        stats.hash_errors.fetch_add(1, Ordering::Relaxed);
                        log_buf.push(format!("[{}] Błąd I/O (Brak dostępu): \"{}\"", side_label, task.rel_path));
                        results.push(ScanResult { id: task.id, hash: None, magic_ok: None, io_error: Some(true) });
                        continue;
                    }
                };

                let mut buffer = [0u8; 131_072];

                let first_read = file.read(&mut buffer).unwrap_or(0);
                drop(file);

                if first_read == 0 {
                    let empty_hash = stats.thread_activity.track_current(|| hash_file(&full_path)).ok();
                    results.push(ScanResult {
                        id: task.id,
                        hash: empty_hash,
                        magic_ok: Some(true), io_error: Some(false)
                    });
                    continue;
                }

                let first_chunk = &buffer[..first_read];
                
                let file_name = Path::new(&task.rel_path).file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
                let ext = Path::new(&task.rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
                
                *local_ext_weights.entry(ext.clone()).or_insert(0) += file_size as u64;

                let a = analyze_header_cluster(first_chunk, file_size, &ext);
                
                let mut detected_anomalies = Vec::new();

                if a.is_micro { stats.micro_files.fetch_add(1, Ordering::Relaxed); detected_anomalies.push("Mikro-plik (<32B)"); }
                if a.has_null { stats.null_padding.fetch_add(1, Ordering::Relaxed); detected_anomalies.push("Puste bloki (Null-Padding)"); }
                if a.has_offset { stats.offset_anomalies.fetch_add(1, Ordering::Relaxed); detected_anomalies.push("Przesunięty Nagłówek"); }
                if a.has_trash { stats.ascii_trash.fetch_add(1, Ordering::Relaxed); detected_anomalies.push("Śmieci ASCII"); }
                if a.sub_magic_err { stats.sub_magic_errors.fetch_add(1, Ordering::Relaxed); detected_anomalies.push("Błąd Pod-Sygnatury"); }
                if a.slack_contam { stats.slack_space_contam.fetch_add(1, Ordering::Relaxed); detected_anomalies.push("Skażenie Slack Space"); }
                if a.parasitic { stats.parasitic_injections.fetch_add(1, Ordering::Relaxed); detected_anomalies.push("Iniekcja Pasożytnicza"); }
                if a.endian_conflict { stats.endian_conflicts.fetch_add(1, Ordering::Relaxed); detected_anomalies.push("Konflikt Endianness"); }
                if a.boundary_drop { stats.boundary_drops.fetch_add(1, Ordering::Relaxed); detected_anomalies.push("Urwana Granica Sektora"); }
                if a.high_volatility { stats.high_volatility.fetch_add(1, Ordering::Relaxed); detected_anomalies.push("Wysoka Wolatywność (HFV)"); }

                let mut magic_ok = Some(true);
                if file_name.contains('.') {
                    let parts: Vec<&str> = file_name.split('.').filter(|s| !s.is_empty()).collect();
                    let ext_parts = if parts.len() > 1 { &parts[1..] } else { &parts[0..] };

                    if let Some(kind) = infer::get(first_chunk) {
                        let kind_ext = kind.extension();
                        let matches = ext_parts.iter().any(|&e| {
                            kind_ext == e || match (kind_ext, e) {
                                ("jpg", "jpeg") | ("jpeg", "jpg") => true,
                                ("tif", "tiff") | ("tiff", "tif") | ("tif", "dng") | ("tiff", "dng") | ("tif", "cr2") | ("tif", "nef") | ("tif", "arw") => true, 
                                ("heic", "heif") | ("heif", "heic") | ("heic", "hef") | ("heif", "hef") => true,
                                ("mp4", "m4v") | ("mov", "mp4") | ("mp4", "mov") => true, 
                                ("mkv", "webm") | ("webm", "mkv") => true, 
                                ("mpeg", "mpg") | ("mpg", "mpeg") | ("mpeg", "ts") | ("mpg", "ts") => true, 
                                ("ogg", "ogv") | ("ogg", "oga") | ("ogg", "ogx") => true,
                                ("flv", "f4v") => true,
                                ("zip", "docx") | ("zip", "xlsx") | ("zip", "pptx") => true,
                                ("zip", "odt") | ("zip", "ods") | ("zip", "odp") => true,
                                ("zip", "epub") | ("zip", "apk") | ("zip", "jar") => true,
                                ("gz", "tar") | ("bz2", "tar") | ("7z", "tar") | ("rar", "tar") => true,
                                ("sqlite", "db") | ("sqlite", "sqlite3") | ("sqlite3", "db") => true,
                                ("htm", "html") | ("html", "htm") => true,
                                ("mid", "midi") | ("midi", "mid") => true,
                                _ => false,
                            }
                        });

                        if matches {
                            stats.valid_signatures.fetch_add(1, Ordering::Relaxed);
                        } else {
                            magic_ok = Some(false);
                            stats.magic_errors.fetch_add(1, Ordering::Relaxed);
                            detected_anomalies.push("Złe Magic Bytes (Spoofing)");
                        }
                    } else {
                        magic_ok = crate::utils::check_magic(&full_path);
                        if magic_ok == Some(false) {
                            stats.magic_errors.fetch_add(1, Ordering::Relaxed);
                            detected_anomalies.push("Złe/Nierozpoznane Magic Bytes");
                        }
                    }
                }

                if !detected_anomalies.is_empty() {
                    let anomalies_str = detected_anomalies.join(", ");
                    log_buf.push(format!("[{:<15}] [{}] Format: .{:<5} | Ścieżka: \"{}\"", side_label, anomalies_str, ext, full_path.display()));
                }

                let file_hash = match stats.thread_activity.track_current(|| hash_file(&full_path)) {
                    Ok(h) => Some(h),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        None
                    }
                    Err(_) => {
                        stats.hash_errors.fetch_add(1, Ordering::Relaxed);
                        log_buf.push(format!("[{}] Błąd I/O podczas właściwego hashowania: \"{}\"", side_label, task.rel_path));
                        None
                    }
                };

                if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

                stats.processed_files.fetch_add(1, Ordering::Relaxed);
                stats.processed_bytes.fetch_add(file_size, Ordering::Relaxed);

                let current = stats.processed_files.load(Ordering::Relaxed);
                let now = Instant::now();
                
                if now.duration_since(*last_ui_update).as_millis() > 60 {
                    *last_ui_update = now; 

                    if !local_ext_weights.is_empty() {
                        let mut global_map = stats.ext_weights.lock().unwrap();
                        for (k, v) in local_ext_weights.drain() {
                            *global_map.entry(k).or_insert(0) += v;
                        }
                    }

                    let _ = tx_ui.send(PhaseEvent::UpdateBar {
                        idx: bar_idx,
                        current: current as u64,
                        message: format_display_path(&task.rel_path),
                    });
                    let _ = tx_ui.send(PhaseEvent::UpdateBottomPath {
                        idx: bar_idx,
                        path: full_path.to_string_lossy().to_string(),
                    });

                    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                        idx: 0,
                        text: build_crypto_block(stats, other_stats, start_time),
                    });
                    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                        idx: 1,
                        text: build_anomaly_block(stats, other_stats),
                    });
                }

                results.push(ScanResult { 
                    id: task.id, 
                    hash: file_hash, 
                    magic_ok, 
                    io_error: Some(false) 
                });
            }

            if !local_ext_weights.is_empty() {
                let mut global_map = stats.ext_weights.lock().unwrap();
                for (k, v) in local_ext_weights.drain() {
                    *global_map.entry(k).or_insert(0) += v;
                }
            }

            if !log_buf.is_empty()
                && let Ok(mut f) = opr_log.lock() {
                    for line in log_buf.drain(..) {
                        let _ = writeln!(f, "{}", line);
                    }
                }

            if !results.is_empty() {
                if is_ufs {
                    let _ = tx.send(ScanMsg::UfsChunk(results));
                } else {
                    let _ = tx.send(ScanMsg::ScriptChunk(results));
                }
            }
        }
    );

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: stats.processed_files.load(Ordering::Relaxed) as u64,
        message: "Odczyt resztkowy w 100% zakończony.".to_string(),
    });
}

// ============================================================================
// ZAPYTANIA SQL FINALIZACJI (wydzielone, żeby dały się testować bez
// duplikowania treści — patrz analogiczne wydzielenie w Fazie 2)
// ============================================================================

/// Domknięcie macierzy hashy dla domeny Fazy 4 (resztki/unikaty).
///
/// Warunek `size_match IS NULL OR size_match = 0` jest tu KONIECZNY, nie
/// kosmetyczny: bez niego zapytanie łapało też wiersze z `size_match = 1` —
/// pliki, którymi zajęła się już Faza 3 (zgodne rozmiarowo). Te pliki mają
/// swój OSOBNY stan ukończenia (`phase3_done`) i własne liczniki w raporcie
/// Fazy 3; nadpisanie im tu `phase4_done = 1` powodowało PODWÓJNE liczenie
/// tego samego pliku w statystykach obu faz naraz.
const SQL_FINALIZACJA_HASHY: &str = "UPDATE files SET
            hash_match = CASE
                WHEN io_error_ufs = 1 OR io_error_script = 1 THEN NULL
                WHEN hash_ufs IS NULL OR hash_script IS NULL THEN NULL
                WHEN hash_ufs = hash_script THEN 1
                ELSE 0
            END,
            phase4_done = CASE
                WHEN (found_in_ufs = 0 OR hash_ufs IS NOT NULL OR io_error_ufs = 1)
                 AND (found_in_script = 0 OR hash_script IS NOT NULL OR io_error_script = 1) THEN 1
                ELSE 0
            END
         WHERE (phase4_done = 0 OR phase4_done IS NULL)
           AND (size_match IS NULL OR size_match = 0)";

/// Zapytanie raportu końcowego Fazy 4 — ten sam warunek `size_match` co w
/// [`SQL_FINALIZACJA_HASHY`] powyżej, z tego samego powodu: raport ma liczyć
/// wyłącznie pliki ze swojej domeny (resztki/unikaty), inaczej wliczyłby też
/// pliki zgodne rozmiarowo, którymi zajmuje się i raportuje już Faza 3.
const SQL_RAPORT_HASHY: &str = "SELECT relative_path, hash_match, magic_ok_ufs, magic_ok_script, found_in_ufs, found_in_script
         FROM files
         WHERE phase4_done = 1 AND (size_match IS NULL OR size_match = 0)";

// ============================================================================
// GŁÓWNA FUNKCJA KORDYNUJĄCA (Entrypoint Fazy 4)
// ============================================================================

/// Punkt wejścia Fazy 4, wołany przez `menu::actions::run_phase_with_ui`.
///
/// Przebieg: (1) wczytuje z SQLite zadania — pliki UNIKALNE dla danej strony
/// (`found_in_ufs`/`found_in_script` bez odpowiednika po drugiej stronie, lub
/// wcześniej odrzucone przez rozbieżny rozmiar), którym brakuje hasha i nie
/// mają zapisanego błędu I/O; (2) uruchamia [`process_side_stream`] dla UFS
/// i Skryptu — równolegle (dwie tymczasowe pule Rayon, patrz dokumentacja
/// modułu) lub sekwencyjnie; (3) koreluje wyniki w SQLite (`hash_match`,
/// `phase4_done` — ustawiane per plik niezależnie od strony, bo pliki są
/// unikalne); (4) zapisuje pełny Dziennik Końcowy (macierz spoofingu per
/// rozszerzenie, zaufanie carvera, rozkład anomalii) do pliku i do UI.
///
/// Wątek zapisu SQLite używa transakcji hybrydowych: commit przy 5000
/// rekordach ALBO co 500ms (co pierwsze), zamiast jednej transakcji per
/// paczka — różnica względem prostszego modelu z Fazy 3.
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    crate::utils::CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    let raport_cfg = config.raporty_faz.get("Faza 4").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza4.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza4.txt".to_string(),
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
        let _ = writeln!(f, "=== RAPORT OPERACYJNY - FAZA 4 (FAŁSZYWE ROZSZERZENIA - RESZTKOWE) ===");
        let _ = writeln!(f, "Pliki unikalne zawierające błędy strukturalne (np. ucięte nagłówki, śmieci ASCII, puste bloki, fałszywe rozszerzenia):\n");
    }

    let actual_threads = if config.max_threads > 0 { config.max_threads } else { rayon::current_num_threads() };
    let io_text = if config.io_mode == "CONCURRENT" { "RÓWNOLEGŁE (SSD/NVMe)" } else { "SEKWENCYJNIE (HDD)" };
    
    let _ = tx_ui.send(PhaseEvent::Log(format!("Uruchomiono Fazę 4. Metodyka szyny dyskowej: {}", io_text)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora (Rayon): {}", actual_threads)));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, hash_ufs, hash_script, io_error_ufs, io_error_script 
         FROM files 
         WHERE phase4_done = 0 OR phase4_done IS NULL"
    )?;
    
    let mut ufs_tasks: Vec<Task> = Vec::new();
    let mut script_tasks: Vec<Task> = Vec::new();
    
    let mut skipped_ufs = 0;
    let mut skipped_script = 0;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i32>(0)?, row.get::<_, String>(1)?, 
            row.get::<_, bool>(2)?, row.get::<_, bool>(3)?, 
            row.get::<_, Option<String>>(4)?, row.get::<_, Option<String>>(5)?, 
            row.get::<_, Option<bool>>(6)?, row.get::<_, Option<bool>>(7)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_ufs, in_script, h_ufs, h_scr, err_ufs, err_scr) = r;
        
        if in_ufs {
            if h_ufs.is_none() && err_ufs != Some(true) { 
                ufs_tasks.push(Task { id, rel_path: rel.clone() }); 
            } else {
                skipped_ufs += 1;
            }
        }
        
        if in_script {
            if h_scr.is_none() && err_scr != Some(true) { 
                script_tasks.push(Task { id, rel_path: rel }); 
            } else {
                skipped_script += 1;
            }
        }
    }
    drop(stmt);

    if skipped_ufs > 0 || skipped_script > 0 {
        let _ = tx_ui.send(PhaseEvent::Log(format!("Pominięto pliki z wyliczonym już hashem. UFS: {}, Skrypt: {}", skipped_ufs, skipped_script)));
    }

    let total_files = ufs_tasks.len() + script_tasks.len();
    if total_files == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak plików resztkowych do weryfikacji kryptograficznej. Baza aktualna.".to_string()));
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "UFS Explorer (Resztki)".to_string(), total: ufs_tasks.len() as u64, color: Color::Cyan });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 1, label: "Skrypt Autorski (Resztki)".to_string(), total: script_tasks.len() as u64, color: Color::Magenta });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 2, label: "Zapis SQLite".to_string(), total: total_files as u64, color: Color::Green });

    // Wyliczone TERAZ (nie tylko w gałęzi CONCURRENT niżej) - LiveStats
    // potrzebuje tej wartości do rozmiaru trackera zajętości niezależnie
    // od trybu I/O. Patrz dokumentacja compute_activity_slots() wyżej.
    let half_threads = std::cmp::max(1, actual_threads / 2);
    let activity_slots = compute_activity_slots(&config.io_mode, actual_threads, half_threads);

    let ufs_stats = LiveStats::new(activity_slots);
    let script_stats = LiveStats::new(activity_slots);
    let ufs_path = PathBuf::from(&config.ufs_path);
    let script_path = PathBuf::from(&config.script_path);

    // REGRESJA (measure twice — druga weryfikacja Gemini): każdy błąd SQLite
    // w wątku bazy był wcześniej `.unwrap()`, czyli paniką w wątku pisarza
    // wewnątrz `thread::scope`. Ten sam wzorzec co `phase17_repair::run`/
    // `phase1::run`/`phase3::run` — `db_thread` zwraca `Result<()>`, panika
    // jest przechwytywana przez `.join()` i zamieniana na błąd domenowy.
    let wynik_zapisu: Result<()> = std::thread::scope(|s| {
        let (tx_db, rx_db) = mpsc::sync_channel(200);
        let conn_ref = &mut *conn;
        let tx_ui_ref = &tx_ui;

        // Wątek Bazy Danych z transakcjami hybrydowymi (5000 / 500ms)
        let db_thread = s.spawn(move || -> Result<()> {
            let mut last_ui_update = Instant::now();
            let mut last_commit = Instant::now();
            let mut db_inserted = 0;
            let mut pending_records = 0;

            let mut tx_trans = conn_ref.transaction()?;

            loop {
                let msg_result = rx_db.recv_timeout(Duration::from_millis(100));
                
                let is_disconnected = matches!(&msg_result, Err(std::sync::mpsc::RecvTimeoutError::Disconnected));

                if let Ok(msg) = msg_result {
                    let chunk_len = match &msg {
                        ScanMsg::UfsChunk(c) => c.len(),
                        ScanMsg::ScriptChunk(c) => c.len(),
                    };

                    if chunk_len > 0 {
                        {
                            let mut stmt = match &msg {
                                ScanMsg::UfsChunk(_) => tx_trans.prepare_cached("UPDATE files SET hash_ufs = COALESCE(?1, hash_ufs), magic_ok_ufs = COALESCE(?2, magic_ok_ufs), io_error_ufs = COALESCE(?3, io_error_ufs) WHERE id = ?4")?,
                                ScanMsg::ScriptChunk(_) => tx_trans.prepare_cached("UPDATE files SET hash_script = COALESCE(?1, hash_script), magic_ok_script = COALESCE(?2, magic_ok_script), io_error_script = COALESCE(?3, io_error_script) WHERE id = ?4")?,
                            };

                            let chunk = match &msg {
                                ScanMsg::UfsChunk(c) => c,
                                ScanMsg::ScriptChunk(c) => c,
                            };

                            for res in chunk {
                                stmt.execute(params![res.hash, res.magic_ok, res.io_error, res.id])?;
                            }
                        }

                        db_inserted += chunk_len;
                        pending_records += chunk_len;
                    }
                }

                let now = Instant::now();

                // Transakcje hybrydowe
                if pending_records > 0 && (pending_records >= 5_000 || now.duration_since(last_commit).as_millis() > 500) {
                    tx_trans.commit()?;
                    tx_trans = conn_ref.transaction()?;
                    last_commit = now;
                    pending_records = 0;
                }

                if now.duration_since(last_ui_update).as_millis() > 60 {
                    last_ui_update = now;
                    let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { 
                        idx: 2, 
                        current: db_inserted as u64, 
                        message: format!("Synchronizacja: {} rekordów", db_inserted) 
                    });
                }

                if is_disconnected {
                    break;
                }
            }

            if pending_records > 0 {
                tx_trans.commit()?;
            }

            let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Hashe resztkowe bezpiecznie zapisane w SQLite.".to_string() });
            Ok(())
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone();
            let tx2 = tx_db.clone();
            let log_u = opr_log.clone();
            let log_s = opr_log.clone();

            let stat_u = &ufs_stats;
            let stat_s = &script_stats;

            // half_threads wyliczone wcześniej (przed konstrukcją LiveStats), tu tylko używane.

            s.spawn(move || {
                if !ufs_tasks.is_empty() {
                    let pool = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build().unwrap();
                    pool.install(|| {
                        process_side_stream(StreamCtx { base_path: &ufs_path, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, other_stats: stat_s, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: log_u, start_time, });
                    });
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Hashowanie resztkowe dysku UFS zakończone.".to_string()));
                }
            });

            s.spawn(move || {
                if !script_tasks.is_empty() {
                    let pool = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build().unwrap();
                    pool.install(|| {
                        process_side_stream(StreamCtx { base_path: &script_path, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, other_stats: stat_u, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: log_s, start_time, });
                    });
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Hashowanie resztkowe dysku Skryptu zakończone.".to_string()));
                }
            });
            drop(tx_db);

        } else {
            let log_u = opr_log.clone();
            let log_s = opr_log.clone();
            
            if !ufs_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &ufs_path, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: &ufs_stats, other_stats: &script_stats, tx_db: tx_db.clone(), is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: log_u, start_time, });
                let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Hashowanie resztkowe dysku UFS zakończone.".to_string()));
            }
            
            if !script_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &script_path, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: &script_stats, other_stats: &ufs_stats, tx_db: tx_db.clone(), is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: log_s, start_time, });
                let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Hashowanie resztkowe dysku Skryptu zakończone.".to_string()));
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
                    "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 4 mógł nie zostać w pełni zapisany.".to_string()
                ));
                Err(rusqlite::Error::UnwindingPanic)
            }
        }
    });
    wynik_zapisu?;

    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log("🛑 Skanowanie przerwane przez użytkownika.".to_string()));
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::Log("Trwa korelacja resztek i budowa macierzy w SQLite...".to_string()));
    
    conn.execute(SQL_FINALIZACJA_HASHY, [])?;

    // --- ETAP 5: GENEROWANIE RAPORTU KRYMINALISTYCZNEGO ---
    let mut spoofing_matrix_ufs: HashMap<String, Vec<String>> = HashMap::new();
    let mut spoofing_matrix_script: HashMap<String, Vec<String>> = HashMap::new();
    let mut match_count = 0;
    let mut mismatch_count = 0;

    let mut stmt = conn.prepare(SQL_RAPORT_HASHY)?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?, 
            row.get::<_, Option<bool>>(1)?, 
            row.get::<_, Option<bool>>(2)?, 
            row.get::<_, Option<bool>>(3)?,
            row.get::<_, bool>(4)?,
            row.get::<_, bool>(5)?
        ))
    })?;

    for (rel_path, hash_match, magic_ufs, magic_script, in_ufs, in_script) in rows.flatten() {
        if hash_match == Some(true) { match_count += 1; } 
        else if hash_match == Some(false) { mismatch_count += 1; }
        
        let ext = Path::new(&rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
        if in_ufs && magic_ufs == Some(false) { spoofing_matrix_ufs.entry(ext.clone()).or_default().push(rel_path.clone()); }
        if in_script && magic_script == Some(false) { spoofing_matrix_script.entry(ext).or_default().push(rel_path); }
    }
    drop(stmt);

    let elapsed = start_time.elapsed();
    let total_bytes = ufs_stats.processed_bytes.load(Ordering::SeqCst) + script_stats.processed_bytes.load(Ordering::SeqCst);
    let avg_speed_mb = (total_bytes as f64 / 1_048_576.0) / elapsed.as_secs_f64().max(1.0);
    
    let ufs_anom = ufs_stats.offset_anomalies.load(Ordering::SeqCst) + ufs_stats.null_padding.load(Ordering::SeqCst) + ufs_stats.ascii_trash.load(Ordering::SeqCst) + ufs_stats.sub_magic_errors.load(Ordering::SeqCst) + ufs_stats.slack_space_contam.load(Ordering::SeqCst) + ufs_stats.parasitic_injections.load(Ordering::SeqCst) + ufs_stats.endian_conflicts.load(Ordering::SeqCst) + ufs_stats.boundary_drops.load(Ordering::SeqCst) + ufs_stats.high_volatility.load(Ordering::SeqCst);
    let scr_anom = script_stats.offset_anomalies.load(Ordering::SeqCst) + script_stats.null_padding.load(Ordering::SeqCst) + script_stats.ascii_trash.load(Ordering::SeqCst) + script_stats.sub_magic_errors.load(Ordering::SeqCst) + script_stats.slack_space_contam.load(Ordering::SeqCst) + script_stats.parasitic_injections.load(Ordering::SeqCst) + script_stats.endian_conflicts.load(Ordering::SeqCst) + script_stats.boundary_drops.load(Ordering::SeqCst) + script_stats.high_volatility.load(Ordering::SeqCst);
    
    let all_anomalies = ufs_anom + scr_anom;
    let confidence_score = if total_files > 0 { 
        let clean = total_files.saturating_sub(all_anomalies + spoofing_matrix_ufs.values().map(|v| v.len()).sum::<usize>() + spoofing_matrix_script.values().map(|v| v.len()).sum::<usize>());
        (clean as f64 / total_files as f64) * 100.0 
    } else { 0.0 };

    // -- GENEROWANIE DZIENNIKA KOŃCOWEGO --
    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(&mut log_out, "==========================================================================");
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 4 (KRYPTOGRAFIA PLIKÓW RESZTKOWYCH I UNIKALNYCH)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "Sumaryczny transfer I/O: {} (Średnia prędkość: {:.2} MB/s)", format_bytes(total_bytes), avg_speed_mb);
    let _ = writeln!(&mut log_out, "==========================================================================\n");

    let _ = writeln!(&mut log_out, "[ 1 ] WYNIKI HASHOWANIA DLA PLIKÓW RESZTKOWYCH:");
    let _ = writeln!(&mut log_out, "   -> Zgodne hashe (BLAKE3): {} plików", match_count);
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Pliki, które początkowo miały różny rozmiar lub leżały w sierotach ($Tresh), ale w środku posiadają 100% spójne binarnie dane.");
    let _ = writeln!(&mut log_out, "   -> Różne hashe (Unikalne / Korupcja): {} plików", mismatch_count);
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Większość plików w tej fazie znajduje się tylko na JEDNYM dysku (są unikalne), więc siłą rzeczy nie mają zgodnego hasha z drugim dyskiem.\n");

    let _ = writeln!(&mut log_out, "[ 2 ] WERYFIKACJA MAGIC BYTES (Głębokie Sygnatury):");
    let _ = writeln!(&mut log_out, "   -> Potwierdzone sygnatury w UFS:    {}", ufs_stats.valid_signatures.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "   -> Potwierdzone sygnatury w Skrypt: {}", script_stats.valid_signatures.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Format zadeklarowany w nazwie zgadza się z prawdziwym nagłówkiem binarnym pliku.\n");

    if all_anomalies > 0 {
        let _ = writeln!(&mut log_out, "[ 3 ] ROZKŁAD ANOMALII PIERWSZEGO KLASTRA:");
        let _ = writeln!(&mut log_out, "   Wykryto łącznie: {} anomalii", all_anomalies);
        let _ = writeln!(&mut log_out, "   [ ZNACZENIE ]: Błędy pierwszych 512 bajtów pliku wskazujące na korupcję danych lub złe wyliczenie offsetu przez program odzyskujący.\n");
        
        let add_spoof_to_log = |out_str: &mut String, map: &HashMap<String, Vec<String>>, label: &str| {
            if !map.is_empty() {
                let _ = writeln!(out_str, "   -> MACIERZ FAŁSZERSTW ({})", label);
                let mut sorted: Vec<_> = map.iter().collect();
                sorted.sort_by_key(|a| std::cmp::Reverse(a.1.len())); 
                for (ext, paths) in sorted {
                    let _ = writeln!(out_str, "      Rozszerzenie .{:<5} | Liczba: {} | Przykład: {}", ext, paths.len(), paths.first().unwrap_or(&"".to_string()));
                }
            }
        };
        add_spoof_to_log(&mut log_out, &spoofing_matrix_ufs, "UFS Explorer");
        add_spoof_to_log(&mut log_out, &spoofing_matrix_script, "Skrypt Autorski");
        let _ = writeln!(&mut log_out);
    }

    let _ = writeln!(&mut log_out, "[ 4 ] ZAUFANIE DO ALGORYTMÓW (Carver Confidence Score):");
    let _ = writeln!(&mut log_out, "   -> Zaufanie: {:.2}%", confidence_score);
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Procent unikalnych plików resztkowych, które mimo trudnej historii odzysku posiadają poprawny pierwszy klaster.\n");

    let _ = writeln!(&mut log_out, "[ 5 ] ZESTAWIENIE WAGOWE FORMATÓW:");
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

    let tot_micro = ufs_stats.micro_files.load(Ordering::SeqCst) + script_stats.micro_files.load(Ordering::SeqCst);
    if all_anomalies > 0 || tot_micro > 0 || !spoofing_matrix_ufs.is_empty() || !spoofing_matrix_script.is_empty() {
        let _ = writeln!(&mut log_out, "[ 6 ] SZCZEGÓŁOWY ROZKŁAD ANOMALII PIERWSZEGO KLASTRA (512B):");
        
        let print_anom = |out_str: &mut String, name: &str, ufs_val: usize, scr_val: usize, icon: &str| {
            if ufs_val > 0 || scr_val > 0 {
                let _ = writeln!(out_str, "     [ {} ] {} [UFS: {} | Skrypt: {}]", icon, name, ufs_val, scr_val);
            }
        };

        print_anom(&mut log_out, "Przesunięte nagłówki (Offset)", ufs_stats.offset_anomalies.load(Ordering::SeqCst), script_stats.offset_anomalies.load(Ordering::SeqCst), "✂️ ");
        print_anom(&mut log_out, "Puste bloki na starcie (Null)", ufs_stats.null_padding.load(Ordering::SeqCst), script_stats.null_padding.load(Ordering::SeqCst), "📦");
        print_anom(&mut log_out, "Śmieci ASCII (Trash)", ufs_stats.ascii_trash.load(Ordering::SeqCst), script_stats.ascii_trash.load(Ordering::SeqCst), "🗑️ ");
        print_anom(&mut log_out, "Mikro-pliki (< 32B)", ufs_stats.micro_files.load(Ordering::SeqCst), script_stats.micro_files.load(Ordering::SeqCst), "🔬");
        print_anom(&mut log_out, "Zgubione Pod-Sygnatury", ufs_stats.sub_magic_errors.load(Ordering::SeqCst), script_stats.sub_magic_errors.load(Ordering::SeqCst), "🦠");
        print_anom(&mut log_out, "Skażenie Zarezerwowanych Bajtów", ufs_stats.slack_space_contam.load(Ordering::SeqCst), script_stats.slack_space_contam.load(Ordering::SeqCst), "🦠");
        print_anom(&mut log_out, "Iniekcje Pasożytnicze", ufs_stats.parasitic_injections.load(Ordering::SeqCst), script_stats.parasitic_injections.load(Ordering::SeqCst), "🦠");
        print_anom(&mut log_out, "Konflikty Architektury (Endian)", ufs_stats.endian_conflicts.load(Ordering::SeqCst), script_stats.endian_conflicts.load(Ordering::SeqCst), "🦠");
        print_anom(&mut log_out, "Urwane Granice Sektora", ufs_stats.boundary_drops.load(Ordering::SeqCst), script_stats.boundary_drops.load(Ordering::SeqCst), "🦠");
        print_anom(&mut log_out, "Skrajna Wolatywność (HFV)", ufs_stats.high_volatility.load(Ordering::SeqCst), script_stats.high_volatility.load(Ordering::SeqCst), "🦠");
        let _ = writeln!(&mut log_out);
    }


    let total_io_errors = ufs_stats.hash_errors.load(Ordering::SeqCst) + script_stats.hash_errors.load(Ordering::SeqCst);
    let total_magic_errors = ufs_stats.magic_errors.load(Ordering::SeqCst) + script_stats.magic_errors.load(Ordering::SeqCst);

    if total_io_errors > 0 || total_magic_errors > 0 {
        let _ = writeln!(&mut log_out);
    }
    if total_io_errors > 0 {
        let _ = writeln!(&mut log_out, "   [ 🚨 ] Błędy I/O (Brak dostępu): {} [UFS: {} | Skrypt: {}]", 
            total_io_errors, ufs_stats.hash_errors.load(Ordering::SeqCst), script_stats.hash_errors.load(Ordering::SeqCst));
    }
    if total_magic_errors > 0 {
        let _ = writeln!(&mut log_out, "   [ 🚨 ] Złe Magic Bytes (Spoofing): {} [UFS: {} | Skrypt: {}]", 
            total_magic_errors, ufs_stats.magic_errors.load(Ordering::SeqCst), script_stats.magic_errors.load(Ordering::SeqCst));
    }
    
    let _ = writeln!(&mut log_out); 

    if let Ok(mut f) = fs::File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano fizyczny Dziennik Końcowy w: {}", dz_path.display())));
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano Raport Operacyjny (Live) w: {}", opr_path.display())));
    }

    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    info!(
        total_files,
        match_count,
        mismatch_count,
        total_io_errors,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 4 zakończona pomyślnie"
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
    // compute_activity_slots
    // (logika identyczna z Fazą 3 - patrz phase3::tests dla pełnego
    // uzasadnienia scenariusza regresji Raspberry Pi 5)
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
    // analyze_header_cluster
    // (logika bit-identyczna z Fazą 3 - te same przypadki testowe, patrz
    // phase3::tests dla pełnego uzasadnienia każdego scenariusza)
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_header_micro_file_below_32_bytes() {
        let buf = vec![0xAB; 10];
        let a = analyze_header_cluster(&buf, 10, "jpg");
        assert!(a.is_micro);
        assert!(!a.has_null);
        assert!(!a.has_offset);
    }

    #[test]
    fn test_analyze_header_null_padding_detected() {
        let buf = vec![0x00; 64];
        let a = analyze_header_cluster(&buf, 64, "dat");
        assert!(a.has_null);
    }

    #[test]
    fn test_analyze_header_offset_jpeg_detected() {
        let mut buf = vec![0x41; 64];
        buf[8] = 0xFF; buf[9] = 0xD8; buf[10] = 0xFF; buf[11] = 0xE0;
        let a = analyze_header_cluster(&buf, 64, "jpg");
        assert!(a.has_offset);
    }

    #[test]
    fn test_analyze_header_offset_not_flagged_when_at_position_zero() {
        let mut buf = vec![0x00; 64];
        buf[0] = 0xFF; buf[1] = 0xD8; buf[2] = 0xFF; buf[3] = 0xE0;
        let a = analyze_header_cluster(&buf, 64, "jpg");
        assert!(!a.has_offset);
    }

    #[test]
    fn test_analyze_header_ascii_trash_for_binary_extension() {
        let mut buf = vec![0x00; 64];
        buf[0..4].copy_from_slice(b"HELO");
        let a = analyze_header_cluster(&buf, 64, "zip");
        assert!(a.has_trash);
    }

    #[test]
    fn test_analyze_header_riff_sub_magic_error() {
        let mut buf = vec![0x00; 64];
        buf[0..4].copy_from_slice(b"RIFF");
        buf[8..12].copy_from_slice(b"XXXX");
        let a = analyze_header_cluster(&buf, 64, "wav");
        assert!(a.sub_magic_err);
    }

    #[test]
    fn test_analyze_header_bmp_slack_contamination() {
        let mut buf = vec![0x00; 64];
        buf[0] = b'B'; buf[1] = b'M';
        buf[6] = 0xFF;
        let a = analyze_header_cluster(&buf, 64, "bmp");
        assert!(a.slack_contam);
    }

    #[test]
    fn test_analyze_header_parasitic_zip_injection() {
        let mut buf = vec![0x41; 64];
        buf[40] = 0x50; buf[41] = 0x4B; buf[42] = 0x03; buf[43] = 0x04;
        let a = analyze_header_cluster(&buf, 64, "jpg");
        assert!(a.parasitic);
    }

    #[test]
    fn test_analyze_header_tiff_little_endian_conflict() {
        let mut buf = vec![0x00; 64];
        buf[0] = b'I'; buf[1] = b'I'; buf[2] = 0x00; buf[3] = 0x2A;
        let a = analyze_header_cluster(&buf, 64, "tif");
        assert!(a.endian_conflict);
    }

    #[test]
    fn test_analyze_header_boundary_drop_zeros() {
        let mut buf = vec![0x41; 512];
        buf[508] = 0x00; buf[509] = 0x00; buf[510] = 0x00; buf[511] = 0x00;
        let a = analyze_header_cluster(&buf, 512, "dat");
        assert!(a.boundary_drop);
    }

    #[test]
    fn test_analyze_header_high_volatility_detected() {
        // Naprzemienne skrajne wartości bajtów maksymalizują sumę różnic sąsiednich
        // bajtów: (n-1) * 255. Próg w analyze_header_cluster to > 60000, więc
        // potrzeba n-1 > ~235, czyli co najmniej 237 bajtów (64B dawało tylko
        // 63*255=16065 - stąd wcześniejsza fałszywa porażka tego testu).
        let buf: Vec<u8> = (0..300).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect();
        let a = analyze_header_cluster(&buf, 300, "dat");
        assert!(a.high_volatility);
    }

    #[test]
    fn test_analyze_header_clean_file_no_anomalies() {
        let mut buf = vec![0u8; 600];
        buf[0] = 0xFF; buf[1] = 0xD8; buf[2] = 0xFF; buf[3] = 0xE0;
        buf[4..].fill(0x80);
        let a = analyze_header_cluster(&buf, 600, "jpg");

        assert!(!a.is_micro);
        assert!(!a.has_null);
        assert!(!a.has_offset);
        assert!(!a.has_trash);
        assert!(!a.sub_magic_err);
        assert!(!a.slack_contam);
        assert!(!a.parasitic);
        assert!(!a.endian_conflict);
        assert!(!a.boundary_drop);
        assert!(!a.high_volatility);
    }

    // ------------------------------------------------------------------
    // build_crypto_block / build_anomaly_block (Wariant B — mirror Fazy 3)
    // ------------------------------------------------------------------

    #[test]
    fn test_build_crypto_block_sums_both_sides() {
        let own = LiveStats::new(4);
        own.processed_bytes.store(1_048_576, Ordering::Relaxed); // 1 MB
        own.valid_signatures.store(5, Ordering::Relaxed);
        own.magic_errors.store(1, Ordering::Relaxed);
        own.hash_errors.store(1, Ordering::Relaxed);

        let other = LiveStats::new(4);
        other.processed_bytes.store(1_048_576, Ordering::Relaxed); // 1 MB
        other.valid_signatures.store(2, Ordering::Relaxed);
        other.magic_errors.store(3, Ordering::Relaxed);
        other.hash_errors.store(4, Ordering::Relaxed);

        let start_time = Instant::now() - Duration::from_secs(1);
        let block = build_crypto_block(&own, &other, start_time);

        assert!(block.starts_with("[Kryptografia i sygnatury (Resztki)]"));
        assert!(block.contains("Poprawne sygnatury: 7"), "5 (own) + 2 (other): {}", block);
        assert!(block.contains("Błędy I/O: 5"), "1 (own) + 4 (other): {}", block);
        assert!(block.contains("Spoofing (magic): 4"), "1 (own) + 3 (other): {}", block);
    }

    #[test]
    fn test_build_crypto_block_empty_ext_weights_shows_placeholder() {
        let own = LiveStats::new(4);
        let other = LiveStats::new(4);
        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_crypto_block(&own, &other, start_time);
        assert!(block.contains("Top format: Analiza danych..."));
    }

    #[test]
    fn test_build_crypto_block_shows_own_thread_activity_not_others() {
        let own = LiveStats::new(3);
        own.thread_activity.mark_busy(0);
        let other = LiveStats::new(3);
        other.thread_activity.mark_busy(0);
        other.thread_activity.mark_busy(1);
        other.thread_activity.mark_busy(2);

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_crypto_block(&own, &other, start_time);

        let line = block.lines().find(|l| l.starts_with("Wątki BLAKE3")).expect("powinna istnieć linia Wariantu A");
        assert_eq!(line, "Wątki BLAKE3 (Wariant A): {G:1} {R:2} {R:3}", "aktywność musi pochodzić z `own`, nie z `other`: {}", block);
    }

    #[test]
    fn test_build_anomaly_block_sums_all_ten_categories() {
        let own = LiveStats::new(4);
        own.offset_anomalies.store(2, Ordering::Relaxed);
        own.null_padding.store(1, Ordering::Relaxed);

        let other = LiveStats::new(4);
        other.offset_anomalies.store(3, Ordering::Relaxed);
        other.high_volatility.store(1, Ordering::Relaxed);

        let block = build_anomaly_block(&own, &other);

        assert!(block.starts_with("[Anomalie nagłówka (Resztki)]"));
        assert!(block.contains("Przesunięty nagłówek: 5"), "2 (own) + 3 (other): {}", block);
        assert!(block.contains("Null-padding: 1"));
        assert!(block.contains("Wysoka wolatywność: 1"));
        assert!(block.contains("Śmieci ASCII: 0"), "kategorie bez aktywności muszą dalej się pojawiać, jako 0: {}", block);
    }

    #[test]
    fn test_build_anomaly_block_all_zero_when_no_activity() {
        let own = LiveStats::new(4);
        let other = LiveStats::new(4);
        let block = build_anomaly_block(&own, &other);
        assert!(!block.contains("suma"), "nowy panel rozpisuje kategorie, nie pokazuje już jednej sumy: {}", block);
    }

    // ------------------------------------------------------------------
    // Regresja: pliki z domeny Fazy 3 (size_match = 1) NIE MOGĄ być liczone
    // podwójnie przez finalizację/raport Fazy 4
    // ------------------------------------------------------------------

    fn wstaw_plik(
        conn: &Connection,
        id: i32,
        rel: &str,
        size_match: Option<i64>,
        hash_ufs: Option<&str>,
        hash_script: Option<&str>,
        found_in_script: bool,
    ) {
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, size_match, hash_ufs, hash_script, io_error_ufs, io_error_script, phase4_done)
             VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, 0, 0, 0)",
            params![id, rel, found_in_script, size_match, hash_ufs, hash_script],
        ).unwrap();
    }

    /// Plik ZGODNY rozmiarowo (`size_match = 1`) to domena Fazy 3, nie Fazy 4
    /// — mimo że oba jego hashe są już policzone (przez Fazę 3, do TYCH
    /// SAMYCH kolumn `hash_ufs`/`hash_script`), finalizacja Fazy 4 NIE MOŻE
    /// go domknąć jako `phase4_done = 1`. Przed poprawką (brak filtra
    /// `size_match` w `WHERE`) łapała go, dając podwójne liczenie tego
    /// samego pliku w statystykach obu faz naraz.
    #[test]
    fn test_finalizacja_pomija_pliki_z_domeny_fazy_trzeciej() {
        let conn = crate::db::init_db(":memory:").unwrap();
        wstaw_plik(&conn, 1, "zgodny.jpg", Some(1), Some("abc"), Some("abc"), true);
        wstaw_plik(&conn, 2, "unikat.jpg", None, Some("def"), None, false);

        conn.execute(SQL_FINALIZACJA_HASHY, []).unwrap();

        let phase4_zgodny: bool = conn.query_row(
            "SELECT phase4_done FROM files WHERE id = 1", [], |r| r.get(0)
        ).unwrap();
        assert!(!phase4_zgodny, "plik z size_match=1 należy do Fazy 3 - Faza 4 nie może go domknąć");

        let phase4_unikat: bool = conn.query_row(
            "SELECT phase4_done FROM files WHERE id = 2", [], |r| r.get(0)
        ).unwrap();
        assert!(phase4_unikat, "plik unikalny (poza domeną Fazy 3) to właściwa domena Fazy 4 - musi zostać domknięty");
    }

    /// Raport końcowy Fazy 4 musi liczyć wyłącznie swoją domenę: gdyby
    /// wliczał też wiersze `size_match = 1`, dałoby to podwójne liczenie
    /// tego samego pliku w statystykach obu faz (Faza 3 też go raportuje).
    /// Test symuluje nawet "zepsuty" stan sprzed poprawki (`phase4_done = 1`
    /// na wierszu z `size_match = 1`) i pokazuje, że SAM raport i tak
    /// odfiltrowuje taki wiersz po `size_match`.
    #[test]
    fn test_raport_pomija_pliki_z_domeny_fazy_trzeciej() {
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, size_match, hash_match, phase4_done)
             VALUES (1, 'zgodny.jpg', 1, 1, 1, 1, 1)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, size_match, hash_match, phase4_done)
             VALUES (2, 'unikat.jpg', 1, 0, NULL, NULL, 1)",
            [],
        ).unwrap();

        let mut stmt = conn.prepare(SQL_RAPORT_HASHY).unwrap();
        let sciezki: Vec<String> = stmt.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert_eq!(
            sciezki, vec!["unikat.jpg".to_string()],
            "raport Fazy 4 nie może zawierać pliku z domeny Fazy 3, nawet jeśli ma phase4_done=1"
        );
    }
}
