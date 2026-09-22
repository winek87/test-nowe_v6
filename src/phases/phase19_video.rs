// src/phases/phase19_video.rs

//! # Faza 19: Diagnostyka Kontenerów i Strumieni Wideo
//!
//! Obsługuje SZEŚĆ różnych rodzin formatów, każdą własną ścieżką analizy:
//! - **MP4/MOV/M4V** → `video_image` (kontener ISOBMFF z tablicami indeksowymi),
//! - **MKV/WebM/MKA** → `mkv_container` (kontener EBML/Matroska),
//! - **FLV** → `flv_stream` (łańcuch tagów z polem PreviousTagSize
//!   działającym jak suma kontrolna struktury),
//! - **TS/M2TS/MTS** → `ts_stream` (ciągły strumień pakietów 188 B, gdzie
//!   liczniki ciągłości ujawniają DOKŁADNIE ile pakietów zginęło - to
//!   znacznie dokładniejsza diagnostyka niż samo "otwiera się / nie otwiera"),
//! - **WAV/AVI** → `riff_container` (kontener RIFF, fragmenty najwyższego
//!   poziomu identyfikator+rozmiar+treść). RIFF, w odróżnieniu od Matroski,
//!   nigdy nie ma sumy kontrolnej per fragment - diagnoza sprawdza tylko, czy
//!   wszystkie fragmenty najwyższego poziomu mieszczą się w pliku, więc jest
//!   SŁABSZYM sygnałem niż CRC-32 z MKV, ale wciąż dużo silniejszym niż
//!   dotychczasowe sprawdzenie samych 12 bajtów nagłówka w Fazie 17.
//! - **MP3** → `mp3_stream` (elementarny strumień ramek MPEG audio o
//!   ZMIENNEJ długości, w odróżnieniu od TS gdzie siatka jest stała - długość
//!   każdej ramki wynika z jej własnego nagłówka). Wcześniej MP3 nie miał
//!   ŻADNEJ dedykowanej diagnostyki - jedyne sprawdzenie w całym projekcie
//!   patrzyło tylko na pierwsze kilka bajtów pliku.
//!
//! Odczytuje strukturę kontenerów ISOBMFF przez `video_image` (crate `mp4`,
//! czysty Rust — zero zależności systemowych) i klasyfikuje rodzaj
//! uszkodzenia. Osobna faza, a NIE rozszerzenie Fazy 13, celowo: pozwala
//! przeskanować wideo bez ponownego przebiegu całej diagnostyki obrazów na
//! już przetworzonych plikach.
//!
//! ## Co ta faza WERYFIKUJE, a czego NIE
//!
//! Sukces oznacza, że kontener i tablice indeksowe (`moov`) są spójne —
//! **NIE** że klatki wideo się poprawnie wyświetlą. Dekodowanie H.264/HEVC
//! wymagałoby `ffmpeg` (ciężka zależność systemowa), świadomie pominięte.
//! To ta sama klasa gwarancji co przy DNG (`raw_image`), nie ta co przy
//! JPG/PNG w Fazie 18.
//!
//! ## Wartość diagnostyczna: klasyfikacja uszkodzeń
//!
//! Zamiast samego "działa/nie działa" faza rozróżnia CZTERY kategorie
//! (patrz `video_image::VideoDamage`), z których najciekawsza to
//! **brak `moov`** — klasyczny objaw przerwanego nagrywania, gdzie dane
//! klatek (`mdat`) mogą być nietknięte, brakuje tylko mapy, gdzie leżą.
//! To jedyna kategoria uszkodzenia wideo, która jest teoretycznie
//! naprawialna przez złożenie z drugiej kopii — dlatego liczona osobno.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::{CANCEL_SIGNAL, format_bytes, format_display_path};
use crate::video_image::{self, VideoDamage};
use ratatui::style::Color;
use rayon::prelude::*;
use rusqlite::{Connection, Result, params};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;
use tracing::{info, instrument, warn};

const CHUNK_SIZE: usize = 50;

// ============================================================================
// ZAPYTANIA SQL (wydzielone, żeby dały się testować bez duplikowania treści)
// ============================================================================

/// Zapis wyniku analizy dla strony UFS.
///
/// Kolejność parametrów jest nieoczywista: `?6` to `id` w klauzuli `WHERE`, a
/// `?7` (czas utworzenia) stoi w treści PRZED nim. Wiązanie jest pozycyjne, więc
/// to poprawne — ale każda zmiana listy parametrów musi tę kolejność uszanować.
///
/// `COALESCE` chroni wcześniejszy wynik: odczyt, który się nie powiódł, niesie
/// `NULL` i nie może wymazać danych zebranych w poprzednim przebiegu.
///
/// `video_created_unix` ma JEDNĄ kolumnę dla obu stron, bo opisuje TREŚĆ
/// nagrania, nie kopię — wystarczy, że odczyta go którakolwiek ze stron.
const SQL_ZAPIS_UFS: &str =
    "UPDATE files SET video_ok_ufs = COALESCE(?1, video_ok_ufs), video_reason_ufs = COALESCE(?2, video_reason_ufs),
                             video_duration_ms_ufs = COALESCE(?3, video_duration_ms_ufs), video_tracks_ufs = COALESCE(?4, video_tracks_ufs),
                             io_error_ufs = COALESCE(?5, io_error_ufs),
                             video_created_unix = COALESCE(?7, video_created_unix) WHERE id = ?6";

/// Odpowiednik [`SQL_ZAPIS_UFS`] dla strony Skryptu Autorskiego.
const SQL_ZAPIS_SCRIPT: &str =
    "UPDATE files SET video_ok_script = COALESCE(?1, video_ok_script), video_reason_script = COALESCE(?2, video_reason_script),
                             video_duration_ms_script = COALESCE(?3, video_duration_ms_script), video_tracks_script = COALESCE(?4, video_tracks_script),
                             io_error_script = COALESCE(?5, io_error_script),
                             video_created_unix = COALESCE(?7, video_created_unix) WHERE id = ?6";

/// Domknięcie fazy: `phase19_done = 1` dopiero, gdy OBIE strony są
/// rozstrzygnięte — każda ma wynik, zgłosiła błąd I/O albo w ogóle nie
/// występuje.
///
/// Lista rozszerzeń w `LIKE` MUSI pokrywać dokładnie ten sam zbiór, co bramka
/// `supported` w Ruście (patrz [`run`]). Rozjazd w którąkolwiek stronę
/// zakleszcza plik: rozszerzenie obsługiwane w Ruście, ale nieobecne tutaj,
/// nigdy nie dostanie flagi ukończenia i będzie analizowane przy każdym
/// uruchomieniu; odwrotnie — rozszerzenie tutaj, ale bez analizatora, na wieki
/// zostanie z `phase19_done = 0`. Pilnuje tego osobny test spójności.
const SQL_FINALIZACJA: &str = "UPDATE files SET phase19_done = CASE
            WHEN (found_in_ufs = 0 OR video_ok_ufs IS NOT NULL OR io_error_ufs = 1)
             AND (found_in_script = 0 OR video_ok_script IS NOT NULL OR io_error_script = 1) THEN 1
            ELSE 0 END
         WHERE (phase19_done = 0 OR phase19_done IS NULL)
           AND (LOWER(relative_path) LIKE '%.mp4' OR LOWER(relative_path) LIKE '%.mov'
             OR LOWER(relative_path) LIKE '%.m4v' OR LOWER(relative_path) LIKE '%.ts'
             OR LOWER(relative_path) LIKE '%.m2ts' OR LOWER(relative_path) LIKE '%.mts'
             OR LOWER(relative_path) LIKE '%.mkv' OR LOWER(relative_path) LIKE '%.webm'
             OR LOWER(relative_path) LIKE '%.mka' OR LOWER(relative_path) LIKE '%.flv'
             OR LOWER(relative_path) LIKE '%.wav' OR LOWER(relative_path) LIKE '%.avi'
             OR LOWER(relative_path) LIKE '%.mp3')";

// ============================================================================
// STRUKTURY DANYCH
// ============================================================================

#[derive(Debug, Clone)]
pub(crate) struct Task {
    id: i32,
    rel_path: String,
    is_common: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SideVideoResult {
    id: i32,
    ok: Option<bool>,
    reason: Option<String>,
    duration_ms: Option<i64>,
    track_count: Option<i64>,
    io_error: Option<bool>,
    /// Czas utworzenia nagrania z atomu `mvhd`, w sekundach epoki Unix.
    ///
    /// Opisuje TREŚĆ, nie kopię, więc w bazie ma JEDNĄ kolumnę
    /// (`video_created_unix`) zapisywaną przez `COALESCE` — wystarczy, że
    /// odczyta go którakolwiek ze stron. Dotyczy wyłącznie kontenerów ISOBMFF;
    /// dla MKV/WebM/FLV/TS pozostaje `None`.
    created_unix: Option<i64>,
}

pub(crate) enum ScanMsg {
    UfsChunk(Vec<SideVideoResult>),
    ScriptChunk(Vec<SideVideoResult>),
}

pub(crate) struct LiveStats {
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    ok: AtomicUsize,
    errors: AtomicUsize,
    /// Suma czasu trwania wszystkich poprawnie odczytanych plików (sekundy).
    total_duration_sec: AtomicU64,
    /// Liczniki per kategoria uszkodzenia, rozbite na wspólne/unikalne —
    /// ten sam wzorzec co w Fazach 11/12/13.
    err_ftyp_common: AtomicUsize,
    err_ftyp_unique: AtomicUsize,
    err_moov_common: AtomicUsize,
    err_moov_unique: AtomicUsize,
    err_trunc_common: AtomicUsize,
    err_trunc_unique: AtomicUsize,
    err_other_common: AtomicUsize,
    err_other_unique: AtomicUsize,
    /// Rozkład rozszerzeń (mp4/mov/m4v) — po wadze bajtów.
    ext_weights: Mutex<HashMap<String, u64>>,
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            processed_files: AtomicUsize::new(0),
            processed_bytes: AtomicU64::new(0),
            ok: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            total_duration_sec: AtomicU64::new(0),
            err_ftyp_common: AtomicUsize::new(0),
            err_ftyp_unique: AtomicUsize::new(0),
            err_moov_common: AtomicUsize::new(0),
            err_moov_unique: AtomicUsize::new(0),
            err_trunc_common: AtomicUsize::new(0),
            err_trunc_unique: AtomicUsize::new(0),
            err_other_common: AtomicUsize::new(0),
            err_other_unique: AtomicUsize::new(0),
            ext_weights: Mutex::new(HashMap::new()),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }
}

fn compute_half_threads(total_threads: usize) -> usize {
    std::cmp::max(1, total_threads / 2)
}

/// Patrz identyczna logika i uzasadnienie w `phase3::compute_activity_slots`.
fn compute_activity_slots(io_mode: &str, actual_threads: usize, half_threads: usize) -> usize {
    if io_mode == "CONCURRENT" {
        half_threads
    } else {
        actual_threads
    }
}

/// Formatuje czas trwania w sekundach do czytelnej postaci (np. "1h 23m 45s").
fn format_duration(total_sec: u64) -> String {
    let hours = total_sec / 3600;
    let mins = (total_sec % 3600) / 60;
    let secs = total_sec % 60;
    if hours > 0 {
        format!("{}h {}m {}s", hours, mins, secs)
    } else if mins > 0 {
        format!("{}m {}s", mins, secs)
    } else {
        format!("{}s", secs)
    }
}

fn build_source_block(label: &str, stats: &LiveStats, start_time: Instant) -> String {
    let bytes = stats.processed_bytes.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
    let speed_mb = (bytes as f64 / 1_048_576.0) / elapsed;

    let top_ext = {
        let map = stats.ext_weights.lock().unwrap_or_else(|e| e.into_inner());
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted
            .into_iter()
            .take(3)
            .map(|(e, w)| format!(".{} ({})", e, format_bytes(*w)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let display_ext = if top_ext.is_empty() {
        "Analiza danych...".to_string()
    } else {
        top_ext
    };
    let activity =
        crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot());

    format!(
        "[{}]\nPrędkość: {:.2} MB/s\nTop format: {}\nSpójne kontenery: {}\nŁączny materiał: {}\nBrak nagłówka ftyp: {} wspólne / {} unikalne\nBrak moov / luki TS: {} wspólne / {} unikalne\nPlik ucięty: {} wspólne / {} unikalne\nInne uszkodzenia: {} wspólne / {} unikalne\nWątki odczytu (Wariant A): {}\nBłędy I/O: {}",
        label,
        speed_mb,
        display_ext,
        stats.ok.load(Ordering::Relaxed),
        format_duration(stats.total_duration_sec.load(Ordering::Relaxed)),
        stats.err_ftyp_common.load(Ordering::Relaxed),
        stats.err_ftyp_unique.load(Ordering::Relaxed),
        stats.err_moov_common.load(Ordering::Relaxed),
        stats.err_moov_unique.load(Ordering::Relaxed),
        stats.err_trunc_common.load(Ordering::Relaxed),
        stats.err_trunc_unique.load(Ordering::Relaxed),
        stats.err_other_common.load(Ordering::Relaxed),
        stats.err_other_unique.load(Ordering::Relaxed),
        activity,
        stats.errors.load(Ordering::Relaxed),
    )
}

/// Inkrementuje właściwy licznik kategorii uszkodzenia. Wydzielone jako
/// czysta funkcja, żeby dało się przetestować bez I/O.
fn bump_damage_counter(stats: &LiveStats, damage: VideoDamage, is_common: bool) {
    let counter = match (damage, is_common) {
        (VideoDamage::MissingFtyp, true) => &stats.err_ftyp_common,
        (VideoDamage::MissingFtyp, false) => &stats.err_ftyp_unique,
        (VideoDamage::MissingMoov, true) => &stats.err_moov_common,
        (VideoDamage::MissingMoov, false) => &stats.err_moov_unique,
        (VideoDamage::TruncatedBox, true) => &stats.err_trunc_common,
        (VideoDamage::TruncatedBox, false) => &stats.err_trunc_unique,
        (VideoDamage::Other, true) => &stats.err_other_common,
        (VideoDamage::Other, false) => &stats.err_other_unique,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Etykieta metody dla logu debug/dashboardu — mirror'uje tę samą decyzję
/// dyspatchu co pętla niżej (po rozszerzeniu), czysto do NAZEWNICTWA, bez
/// dotykania właściwej logiki analizy. Ten sam wzorzec co
/// `phase13::decoding_method_for`.
fn analysis_method_for(rel_path: &str) -> &'static str {
    if crate::ts_stream::is_ts_extension(rel_path) { "analyze_ts_file (TS)" }
    else if crate::flv_stream::is_flv_extension(rel_path) { "analyze_flv_file (FLV)" }
    else if crate::mkv_container::is_mkv_extension(rel_path) { "read_mkv_file (Matroska)" }
    else if crate::riff_container::is_riff_extension(rel_path) { "read_riff_file (RIFF)" }
    else if crate::mp3_stream::is_mp3_extension(rel_path) { "analyze_mp3_file (MP3)" }
    else { "read_video_file (MP4/MOV ISOBMFF)" }
}

// ============================================================================
// PRZETWARZANIE JEDNEJ STRONY
// ============================================================================

pub struct StreamCtx<'a> {
    pub base_path: &'a Path,
    pub tasks: &'a [Task],
    pub side_label: &'a str,
    pub stats: &'a LiveStats,
    pub tx_db: mpsc::SyncSender<ScanMsg>,
    pub is_ufs: bool,
    pub start_time: Instant,
    pub tx_ui: &'a mpsc::Sender<PhaseEvent>,
    pub bar_idx: usize,
    pub debug_log: crate::debug_log::DebugLog,
}

#[instrument(skip(ctx), fields(base_path = %ctx.base_path.display()))]
#[allow(clippy::too_many_arguments)]
fn process_side_stream<'a>(ctx: StreamCtx<'a>) {
    let StreamCtx {
        base_path,
        tasks,
        side_label,
        stats,
        tx_db,
        is_ufs,
        start_time,
        tx_ui,
        bar_idx,
        debug_log,
    } = ctx;

    let last_ui_update = Arc::new(AtomicU64::new(0));

    tasks.par_chunks(CHUNK_SIZE).for_each_with(tx_db, |tx_db, chunk| {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

        let mut results = Vec::with_capacity(chunk.len());
        let mut local_ext: HashMap<String, u64> = HashMap::new();

        for task in chunk {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

            let full_path = base_path.join(&task.rel_path);
            let file_size = fs::metadata(&full_path).map(|m| m.len()).unwrap_or(0);
            let ext = Path::new(&task.rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
            *local_ext.entry(ext).or_insert(0) += file_size;

            // TRZY RÓŻNE ŚCIEŻKI ANALIZY, bo to fundamentalnie różne formaty:
            // - MP4/MOV/M4V  → kontener ISOBMFF z tablicami indeksowymi (`video_image`),
            // - MKV/WebM/MKA → kontener EBML/Matroska (`mkv_container`),
            // - TS/M2TS/MTS  → ciągły strumień pakietów 188 B (`ts_stream`),
            //   gdzie liczniki ciągłości ujawniają DOKŁADNIE ile pakietów zginęło.
            // REGRESJA (measure twice — druga weryfikacja Gemini, N2): żadna
            // z czterech ścieżek analizy kontenera nie miała tu własnej
            // osłony `catch_unwind` — MP4 jest chronione jedno wywołanie
            // głębiej (`video_image::read_video_bytes`), MKV ma jawną,
            // sfalsyfikowalną decyzję o nieużywaniu (`mkv_container.rs`
            // nagłówek modułu), a TS/FLV/`mp4_engines::boxes` są ręcznie
            // pisanymi parserami bez takiej deklaracji - bezpieczne DZIŚ
            // (ręczny przegląd: konsekwentne strażowanie długości bufora,
            // `checked_add`), ale bez żadnej sieci bezpieczeństwa, gdyby
            // przyszła zmiana złamała tę dyscyplinę. Ten sam wzorzec
            // "belt and suspenders" co YARA w Fazie 16 i
            // `applies_to`/`repair`/`verify` w Fazie 17: panika w KTÓRYMKOLWIEK
            // analizatorze nie może ubić wątku Rayon / całej sesji TUI dla
            // jednego spreparowanego pliku w korpusie.
            let metoda = analysis_method_for(&task.rel_path);
            let call_start = debug_log.is_active().then(Instant::now);
            let side_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> SideVideoResult { if crate::ts_stream::is_ts_extension(&task.rel_path) {
                match stats.thread_activity.track_current(|| crate::ts_stream::analyze_ts_file(&full_path)) {
                    Some(a) if a.is_healthy() => {
                        stats.ok.fetch_add(1, Ordering::Relaxed);
                        SideVideoResult {
                            id: task.id, ok: Some(true), reason: Some(a.describe()),
                            // Strumień TS nie niesie czasu trwania w strukturze
                            // (to ciągły transport, nie kontener) - stąd None.
                            duration_ms: None,
                            track_count: Some(a.distinct_pids as i64),
                            io_error: Some(false), created_unix: None
                        }
                    }
                    Some(a) => {
                        // Uszkodzony strumień - klasyfikujemy wg dominującego objawu.
                        let damage = if a.sync_losses > 0 { VideoDamage::Other }
                                     else if a.trailing_garbage_bytes > 0 { VideoDamage::TruncatedBox }
                                     else { VideoDamage::MissingMoov };
                        bump_damage_counter(stats, damage, task.is_common);
                        SideVideoResult {
                            id: task.id, ok: Some(false), reason: Some(a.describe()),
                            duration_ms: None, track_count: Some(a.distinct_pids as i64),
                            io_error: Some(false), created_unix: None
                        }
                    }
                    None => {
                        if !full_path.exists() {
                            stats.errors.fetch_add(1, Ordering::Relaxed);
                            warn!(path = %task.rel_path, side = side_label, "Błąd I/O - plik niedostępny");
                            SideVideoResult { id: task.id, ok: None, reason: None, duration_ms: None, track_count: None, io_error: Some(true) , created_unix: None }
                        } else {
                            bump_damage_counter(stats, VideoDamage::MissingFtyp, task.is_common);
                            SideVideoResult {
                                id: task.id, ok: Some(false),
                                reason: Some("Nie znaleziono pakietów TS - fałszywe rozszerzenie lub całkowicie zniszczona synchronizacja".to_string()),
                                duration_ms: None, track_count: None, io_error: Some(false), created_unix: None
                            }
                        }
                    }
                }
            } else if crate::flv_stream::is_flv_extension(&task.rel_path) {
                match stats.thread_activity.track_current(|| crate::flv_stream::analyze_flv_file(&full_path)) {
                    Some(a) if a.is_healthy() => {
                        stats.ok.fetch_add(1, Ordering::Relaxed);
                        stats.total_duration_sec.fetch_add((a.last_timestamp_ms / 1000) as u64, Ordering::Relaxed);
                        SideVideoResult {
                            id: task.id, ok: Some(true), reason: Some(a.describe()),
                            duration_ms: Some(a.last_timestamp_ms as i64),
                            track_count: Some(((a.video_tags > 0) as i64) + ((a.audio_tags > 0) as i64)),
                            io_error: Some(false), created_unix: None
                        }
                    }
                    Some(a) => {
                        // Mapowanie objawów FLV na wspólne liczniki fazy.
                        let damage = if a.trailing_garbage_bytes > 0 { VideoDamage::TruncatedBox }
                                     else if a.chain_errors > 0 { VideoDamage::MissingMoov }
                                     else { VideoDamage::Other };
                        bump_damage_counter(stats, damage, task.is_common);
                        SideVideoResult {
                            id: task.id, ok: Some(false), reason: Some(a.describe()),
                            duration_ms: None,
                            track_count: Some(((a.video_tags > 0) as i64) + ((a.audio_tags > 0) as i64)),
                            io_error: Some(false), created_unix: None
                        }
                    }
                    None => {
                        if !full_path.exists() {
                            stats.errors.fetch_add(1, Ordering::Relaxed);
                            warn!(path = %task.rel_path, side = side_label, "Błąd I/O - plik niedostępny");
                            SideVideoResult { id: task.id, ok: None, reason: None, duration_ms: None, track_count: None, io_error: Some(true) , created_unix: None }
                        } else {
                            bump_damage_counter(stats, VideoDamage::MissingFtyp, task.is_common);
                            SideVideoResult {
                                id: task.id, ok: Some(false),
                                reason: Some("Brak sygnatury FLV - fałszywe rozszerzenie lub zniszczony nagłówek".to_string()),
                                duration_ms: None, track_count: None, io_error: Some(false), created_unix: None
                            }
                        }
                    }
                }
            } else if crate::mkv_container::is_mkv_extension(&task.rel_path) {
                match stats.thread_activity.track_current(|| crate::mkv_container::read_mkv_file(&full_path)) {
                    Ok(info) => {
                        stats.ok.fetch_add(1, Ordering::Relaxed);
                        if let Some(ms) = info.duration_ms {
                            stats.total_duration_sec.fetch_add(ms / 1000, Ordering::Relaxed);
                        }
                        SideVideoResult {
                            id: task.id, ok: Some(true),
                            reason: Some(format!("Matroska spójna: {} ścieżek ({} wideo, {} audio), kodeki: {}",
                                info.track_count, info.video_tracks, info.audio_tracks, info.codecs.join(", "))),
                            duration_ms: info.duration_ms.map(|ms| ms as i64),
                            track_count: Some(info.track_count as i64),
                            io_error: Some(false), created_unix: None
                        }
                    }
                    Err(damage) => {
                        if !full_path.exists() {
                            stats.errors.fetch_add(1, Ordering::Relaxed);
                            warn!(path = %task.rel_path, side = side_label, "Błąd I/O - plik niedostępny");
                            SideVideoResult { id: task.id, ok: None, reason: None, duration_ms: None, track_count: None, io_error: Some(true) , created_unix: None }
                        } else {
                            // Mapowanie kategorii Matroski na wspólne liczniki fazy:
                            // Truncated → "plik ucięty", InvalidStructure → "brak
                            // nagłówka" (obejmuje też fałszywe rozszerzenie, np.
                            // zaobserwowany M4V nazwany .mkv).
                            let mapped = match damage {
                                crate::mkv_container::MkvDamage::Truncated => VideoDamage::TruncatedBox,
                                crate::mkv_container::MkvDamage::InvalidStructure => VideoDamage::MissingFtyp,
                                crate::mkv_container::MkvDamage::Other => VideoDamage::Other,
                            };
                            bump_damage_counter(stats, mapped, task.is_common);
                            SideVideoResult {
                                id: task.id, ok: Some(false),
                                reason: Some(crate::mkv_container::damage_description(damage).to_string()),
                                duration_ms: None, track_count: None, io_error: Some(false), created_unix: None
                            }
                        }
                    }
                }
            } else if crate::riff_container::is_riff_extension(&task.rel_path) {
                match stats.thread_activity.track_current(|| crate::riff_container::read_riff_file(&full_path)) {
                    Ok(info) => {
                        stats.ok.fetch_add(1, Ordering::Relaxed);
                        SideVideoResult {
                            id: task.id, ok: Some(true),
                            // duration_ms/track_count celowo `None` - ten płytki
                            // rozbiór czyta tylko nagłówki fragmentów najwyższego
                            // poziomu (patrz dokumentacja modułu), nigdy nie
                            // zagląda do treści `fmt `/`hdrl`, więc nie ma z
                            // czego uczciwie policzyć czasu trwania ani liczby
                            // ścieżek - liczba fragmentów trafia tylko do opisu.
                            reason: Some(format!("Kontener RIFF spójny: {} fragmentów najwyższego poziomu, typ formy {}",
                                info.fragment_count, String::from_utf8_lossy(&info.form_type))),
                            duration_ms: None, track_count: None,
                            io_error: Some(false), created_unix: None
                        }
                    }
                    Err(damage) => {
                        if !full_path.exists() {
                            stats.errors.fetch_add(1, Ordering::Relaxed);
                            warn!(path = %task.rel_path, side = side_label, "Błąd I/O - plik niedostępny");
                            SideVideoResult { id: task.id, ok: None, reason: None, duration_ms: None, track_count: None, io_error: Some(true) , created_unix: None }
                        } else {
                            let mapped = match damage {
                                crate::riff_container::RiffDamage::Truncated => VideoDamage::TruncatedBox,
                                crate::riff_container::RiffDamage::InvalidStructure => VideoDamage::MissingFtyp,
                                crate::riff_container::RiffDamage::Other => VideoDamage::Other,
                            };
                            bump_damage_counter(stats, mapped, task.is_common);
                            SideVideoResult {
                                id: task.id, ok: Some(false),
                                reason: Some(crate::riff_container::damage_description(damage).to_string()),
                                duration_ms: None, track_count: None, io_error: Some(false), created_unix: None
                            }
                        }
                    }
                }
            } else if crate::mp3_stream::is_mp3_extension(&task.rel_path) {
                match stats.thread_activity.track_current(|| crate::mp3_stream::analyze_mp3_file(&full_path)) {
                    Some(a) if a.is_healthy() => {
                        stats.ok.fetch_add(1, Ordering::Relaxed);
                        SideVideoResult {
                            id: task.id, ok: Some(true), reason: Some(a.describe()),
                            // duration_ms/track_count celowo `None` - elementarny
                            // strumień MP3 nie ma pojęcia "ścieżek", a ten rozbiór
                            // nie dekoduje próbek, więc nie ma z czego uczciwie
                            // policzyć czasu trwania - liczba ramek trafia tylko
                            // do opisu, ten sam wybór co przy RIFF.
                            duration_ms: None, track_count: None,
                            io_error: Some(false), created_unix: None
                        }
                    }
                    Some(a) => {
                        // Ten sam priorytet co w gałęzi TS: utrata synchronizacji
                        // (urwanie łańcucha ramek w środku pliku) jest poważniejszym
                        // objawem niż sam nierozpoznany ogon.
                        let damage = if a.sync_losses > 0 { VideoDamage::Other } else { VideoDamage::TruncatedBox };
                        bump_damage_counter(stats, damage, task.is_common);
                        SideVideoResult {
                            id: task.id, ok: Some(false), reason: Some(a.describe()),
                            duration_ms: None, track_count: None, io_error: Some(false), created_unix: None
                        }
                    }
                    None => {
                        if !full_path.exists() {
                            stats.errors.fetch_add(1, Ordering::Relaxed);
                            warn!(path = %task.rel_path, side = side_label, "Błąd I/O - plik niedostępny");
                            SideVideoResult { id: task.id, ok: None, reason: None, duration_ms: None, track_count: None, io_error: Some(true) , created_unix: None }
                        } else {
                            bump_damage_counter(stats, VideoDamage::MissingFtyp, task.is_common);
                            SideVideoResult {
                                id: task.id, ok: Some(false),
                                reason: Some("Nie znaleziono ramek MPEG audio - fałszywe rozszerzenie lub całkowicie zniszczona synchronizacja".to_string()),
                                duration_ms: None, track_count: None, io_error: Some(false), created_unix: None
                            }
                        }
                    }
                }
            } else {
                match stats.thread_activity.track_current(|| video_image::read_video_file(&full_path)) {
                    Ok(info) => {
                        stats.ok.fetch_add(1, Ordering::Relaxed);
                        stats.total_duration_sec.fetch_add(info.duration_ms / 1000, Ordering::Relaxed);
                        SideVideoResult {
                            id: task.id,
                            ok: Some(true),
                            // Opis tekstowy TAKŻE przy sukcesie — tak jak w
                            // gałęziach TS, FLV i Matroski. Wcześniej zostawało
                            // tu `None`, bo ISOBMFF wypełnia w zamian
                            // `duration_ms` i `track_count`, których tamte trzy
                            // nie mają. Dane owszem były, ale raport operacyjny
                            // czyta kolumnę `reason` i dla kontenerów MP4
                            // pokazywał pustkę przy sprawnych plikach, a opis
                            // przy pozostałych formatach — czytający nie miał
                            // jak odróżnić „brak danych" od „inny nośnik danych".
                            reason: Some(format!(
                                "Kontener spójny: {} ścieżek, {} s",
                                info.track_count,
                                info.duration_ms / 1000
                            )),
                            duration_ms: Some(info.duration_ms as i64),
                            track_count: Some(info.track_count as i64),
                            io_error: Some(false),
                            // Kontenerowy znacznik czasu — niezależny od EXIF
                            // i od metadanych systemu plików.
                            created_unix: crate::mp4_repair::boxes::czas_utworzenia_pliku(&full_path),
                        }
                    }
                    Err(damage) => {
                        // VideoDamage::Other bywa też skutkiem błędu odczytu z
                        // dysku (read_video_file mapuje błąd I/O na Other) —
                        // rozróżniamy to sprawdzeniem istnienia pliku, żeby nie
                        // mylić uszkodzonej struktury z niedostępnym plikiem.
                        let is_io = damage == VideoDamage::Other && !full_path.exists();
                        if is_io {
                            stats.errors.fetch_add(1, Ordering::Relaxed);
                            warn!(path = %task.rel_path, side = side_label, "Błąd I/O - plik niedostępny");
                            SideVideoResult { id: task.id, ok: None, reason: None, duration_ms: None, track_count: None, io_error: Some(true) , created_unix: None }
                        } else {
                            bump_damage_counter(stats, damage, task.is_common);

                            // WZBOGACENIE POWODU: `damage_description` podaje
                            // ogólną kategorię uszkodzenia, a diagnoza
                            // strukturalna mówi konkretnie, co jest w pliku —
                            // które atomy istnieją i czy offsety z `moov`
                            // wskazują wewnątrz pliku. To ta informacja
                            // rozstrzyga, którą strategię naprawy warto
                            // uruchomić w Fazie 17.
                            let ogolny = video_image::damage_description(damage).to_string();
                            let powod = match crate::mp4_repair::boxes::diagnoza_strukturalna_pliku(&full_path) {
                                Some(szczegoly) => format!("{} | {}", ogolny, szczegoly),
                                None => ogolny,
                            };

                            SideVideoResult {
                                id: task.id, ok: Some(false),
                                reason: Some(powod),
                                duration_ms: None, track_count: None, io_error: Some(false),
                                // Znacznik czasu bywa czytelny NAWET w pliku
                                // uszkodzonym — jeśli `moov` ocalał, to często
                                // jedyna informacja, kiedy powstało nagranie.
                                created_unix: crate::mp4_repair::boxes::czas_utworzenia_pliku(&full_path),
                            }
                        }
                    }
                }
            }})).unwrap_or_else(|_| {
                warn!(path = %task.rel_path, side = side_label, "PANIKA podczas analizy kontenera wideo - potraktowano jak uszkodzenie");
                bump_damage_counter(stats, VideoDamage::Other, task.is_common);
                SideVideoResult {
                    id: task.id, ok: Some(false),
                    reason: Some("Analiza kontenera spanikowała (parser/dekoder natrafił na nieoczekiwaną strukturę) - traktowane jak uszkodzenie, nie błąd I/O".to_string()),
                    duration_ms: None, track_count: None, io_error: Some(false), created_unix: None,
                }
            });
            if let Some(t) = call_start {
                let wynik = if side_result.io_error == Some(true) {
                    "BŁĄD I/O".to_string()
                } else if side_result.ok == Some(true) {
                    "OK".to_string()
                } else {
                    format!("BŁĄD: {}", side_result.reason.as_deref().unwrap_or("Nieznany błąd"))
                };
                debug_log.log(side_label, metoda, &task.rel_path, t.elapsed(), &wynik);
            }
            results.push(side_result);

            let current = stats.processed_files.fetch_add(1, Ordering::Relaxed) + 1;
            stats.processed_bytes.fetch_add(file_size, Ordering::Relaxed);

            let now_ms = start_time.elapsed().as_millis() as u64;
            let last_ms = last_ui_update.load(Ordering::Relaxed);
            let should_update = current.is_multiple_of(20) || now_ms.saturating_sub(last_ms) > 250;

            if should_update && last_ui_update.compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                if !local_ext.is_empty() {
                    let mut g = stats.ext_weights.lock().unwrap_or_else(|e| e.into_inner());
                    for (k, v) in local_ext.drain() { *g.entry(k).or_insert(0) += v; }
                }
                let _ = tx_ui.send(PhaseEvent::UpdateBar { idx: bar_idx, current: current as u64, message: format_display_path(&task.rel_path) });
                let _ = tx_ui.send(PhaseEvent::UpdateBottomPath { idx: bar_idx, path: format!("[{}] {}", metoda, full_path.to_string_lossy()) });
                let _ = tx_ui.send(PhaseEvent::UpdateSideText { idx: bar_idx, text: build_source_block(side_label, stats, start_time) });
            }
        }

        if !local_ext.is_empty() {
            let mut g = stats.ext_weights.lock().unwrap_or_else(|e| e.into_inner());
            for (k, v) in local_ext.drain() { *g.entry(k).or_insert(0) += v; }
        }

        if !results.is_empty() {
            if is_ufs { let _ = tx_db.send(ScanMsg::UfsChunk(results)); }
            else { let _ = tx_db.send(ScanMsg::ScriptChunk(results)); }
        }
    });

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: stats.processed_files.load(Ordering::Relaxed) as u64,
        message: "Diagnostyka kontenerów wideo zakończona.".to_string(),
    });
}

// ============================================================================
// GŁÓWNA FUNKCJA (Entrypoint)
// ============================================================================

pub fn run(
    conn: &mut Connection,
    config: &Ustawienia,
    tx_ui: mpsc::Sender<PhaseEvent>,
) -> Result<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);
    let _ = tx_ui.send(PhaseEvent::Log("Uruchomiono Fazę 19: Diagnostyka Wideo (MP4/MOV/M4V, MKV/WebM, FLV, strumienie TS, WAV/AVI, MP3).".to_string()));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    for col in [
        "video_ok_ufs BOOLEAN",
        "video_ok_script BOOLEAN",
        "video_reason_ufs TEXT",
        "video_reason_script TEXT",
        "video_duration_ms_ufs INTEGER",
        "video_duration_ms_script INTEGER",
        "video_tracks_ufs INTEGER",
        "video_tracks_script INTEGER",
        "phase19_done BOOLEAN DEFAULT 0",
    ] {
        let _ = conn.execute(&format!("ALTER TABLE files ADD COLUMN {}", col), []);
    }

    let raport_cfg = config
        .raporty_faz
        .get("Faza 19")
        .cloned()
        .unwrap_or_else(|| crate::settings::RaportFazy {
            katalog: config.log_path.clone(),
            plik_operacyjny: "raport_operacyjny_faza19.txt".to_string(),
            plik_dziennika: "dziennik_koncowy_faza19.txt".to_string(),
        });
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    // Wszystkie pliki tego przebiegu fazy niosą ten sam znacznik czasu, więc
    // łatwo je ze sobą powiązać na dysku, a kolejne uruchomienia się nie
    // nadpisują.
    let stamp = crate::utils::run_timestamp();
    let dz_path = Path::new(&raport_cfg.katalog)
        .join(crate::utils::stamp_filename(&raport_cfg.plik_dziennika, &stamp));
    let debug_log = crate::debug_log::DebugLog::maybe_open(
        &raport_cfg.katalog,
        &crate::utils::stamp_filename("dziennik_debug_faza19.txt", &stamp),
        &config.log_level,
    );

    // --- ETAP 1: DOBÓR ZADAŃ ---
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, video_ok_ufs, video_ok_script,
                io_error_ufs, io_error_script
         FROM files WHERE phase19_done = 0 OR phase19_done IS NULL",
    )?;

    let mut ufs_tasks = Vec::new();
    let mut script_tasks = Vec::new();
    let mut skipped = 0usize;

    let rows = stmt.query_map([], |row| {
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
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_ufs, in_scr, ok_u, ok_s, err_u, err_s) = r;
        let supported = video_image::is_video_extension(&rel)
            || crate::ts_stream::is_ts_extension(&rel)
            || crate::mkv_container::is_mkv_extension(&rel)
            || crate::flv_stream::is_flv_extension(&rel)
            || crate::riff_container::is_riff_extension(&rel)
            || crate::mp3_stream::is_mp3_extension(&rel);
        if !supported {
            continue;
        }
        let is_common = in_ufs && in_scr;
        if in_ufs {
            if ok_u.is_none() && err_u != Some(true) {
                ufs_tasks.push(Task {
                    id,
                    rel_path: rel.clone(),
                    is_common,
                });
            } else {
                skipped += 1;
            }
        }
        if in_scr {
            if ok_s.is_none() && err_s != Some(true) {
                script_tasks.push(Task {
                    id,
                    rel_path: rel,
                    is_common,
                });
            } else {
                skipped += 1;
            }
        }
    }
    drop(stmt);

    let total_db_rows = ufs_tasks.len() + script_tasks.len();
    if skipped > 0 {
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "Pominięto {} plików już przeanalizowanych.",
            skipped
        )));
    }

    if total_db_rows == 0 {
        let _ = tx_ui.send(PhaseEvent::Log(
            "✔ Diagnostyka kontenerów wideo została ukończona. Zamykam status fazy...".to_string(),
        ));
        // 🟢 UWAGA: Świadomie usuwamy `return Ok(());`. Pozwala to skryptowi gładko
        // wejść w Etap 4 i dopiąć status phase19_done dla powieszonych plików!
    }

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

    // --- ETAP 2: UI ---
    let _ = tx_ui.send(PhaseEvent::SetBar {
        idx: 0,
        label: "UFS Explorer (Wideo)".to_string(),
        total: ufs_tasks.len() as u64,
        color: Color::Cyan,
    });
    let _ = tx_ui.send(PhaseEvent::SetBar {
        idx: 1,
        label: "Skrypt Autorski (Wideo)".to_string(),
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
    let ufs_stats = LiveStats::new(activity_slots);
    let script_stats = LiveStats::new(activity_slots);
    let ufs_base = PathBuf::from(&config.ufs_path);
    let script_base = PathBuf::from(&config.script_path);

    // --- ETAP 3: PRZETWARZANIE ---
    // REGRESJA (measure twice — druga weryfikacja Gemini): błąd SQLite w
    // wątku bazy był wcześniej `.unwrap()` (transakcja/prepare/commit) albo,
    // dla samego zapisu wyniku per plik, cicho POŁYKANY przez `let _ =
    // stmt.execute(...)` — obie ścieżki są gorsze niż jawna propagacja: panika
    // ubijała cały wątek pisarza wewnątrz `thread::scope`, a ciche `let _ =`
    // gubiło zapis BEZ ŚLADU, nawet w logu. Ten sam wzorzec co
    // `phase17_repair::run`/`phase1::run` — `db_thread` zwraca `Result<()>`,
    // panika jest przechwytywana przez `.join()` i zamieniana na błąd domenowy.
    let wynik_zapisu: Result<()> = std::thread::scope(|s| {
        let (tx_db, rx_db) = mpsc::sync_channel::<ScanMsg>(200);
        let conn_ref = &mut *conn;
        let tx_ui_db = tx_ui.clone();

        let db_thread = s.spawn(move || -> Result<()> {
            let mut db_inserted = 0usize;
            let mut last_db_update = Instant::now();

            let update_sql =
                |c: &mut Connection, chunk: &[SideVideoResult], is_ufs: bool| -> Result<()> {
                    let tx = c.transaction()?;
                    {
                        let mut stmt = match is_ufs {
                            true => tx.prepare_cached(SQL_ZAPIS_UFS)?,
                            false => tx.prepare_cached(SQL_ZAPIS_SCRIPT)?,
                        };
                        for r in chunk {
                            stmt.execute(params![
                                r.ok,
                                r.reason,
                                r.duration_ms,
                                r.track_count,
                                r.io_error,
                                r.id,
                                r.created_unix
                            ])?;
                        }
                    }
                    tx.commit()
                };

            for msg in rx_db {
                let n = match &msg {
                    ScanMsg::UfsChunk(c) => {
                        update_sql(conn_ref, c, true)?;
                        c.len()
                    }
                    ScanMsg::ScriptChunk(c) => {
                        update_sql(conn_ref, c, false)?;
                        c.len()
                    }
                };
                db_inserted += n;
                let now = Instant::now();
                if now.duration_since(last_db_update).as_millis() > 60 {
                    last_db_update = now;
                    let _ = tx_ui_db.send(PhaseEvent::UpdateBar {
                        idx: 2,
                        current: db_inserted as u64,
                        message: "Zapisywanie diagnostyki wideo...".to_string(),
                    });
                }
            }
            let _ = tx_ui_db.send(PhaseEvent::UpdateBar {
                idx: 2,
                current: db_inserted as u64,
                message: "Pomyślnie zsynchronizowano z SQLite.".to_string(),
            });
            Ok(())
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone();
            let tx2 = tx_db.clone();
            let stat_u = &ufs_stats;
            let stat_s = &script_stats;
            let ufs_base_ref = &ufs_base;
            let script_base_ref = &script_base;
            let tx_ui_1 = tx_ui.clone();
            let tx_ui_2 = tx_ui.clone();
            let dbg_u = debug_log.clone();
            let dbg_s = debug_log.clone();

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
                                tx_ui: &tx_ui_1,
                                bar_idx: 0,
                                debug_log: dbg_u.clone(),
                            })
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
                            tx_ui: &tx_ui_1,
                            bar_idx: 0,
                            debug_log: dbg_u.clone(),
                        });
                    }
                    let _ =
                        tx_ui_1.send(PhaseEvent::Log("✔ Diagnostyka UFS zakończona.".to_string()));
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
                                tx_ui: &tx_ui_2,
                                bar_idx: 1,
                                debug_log: dbg_s.clone(),
                            })
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
                            tx_ui: &tx_ui_2,
                            bar_idx: 1,
                            debug_log: dbg_s.clone(),
                        });
                    }
                    let _ = tx_ui_2.send(PhaseEvent::Log(
                        "✔ Diagnostyka Skrypt zakończona.".to_string(),
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
                    tx_ui: &tx_ui,
                    bar_idx: 0,
                    debug_log: dbg_u,
                });
                let _ = tx_ui.send(PhaseEvent::Log("✔ Diagnostyka UFS zakończona.".to_string()));
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
                    tx_ui: &tx_ui,
                    bar_idx: 1,
                    debug_log: dbg_s,
                });
                let _ = tx_ui.send(PhaseEvent::Log(
                    "✔ Diagnostyka Skrypt zakończona.".to_string(),
                ));
            }
            // REGRESJA (measure twice — druga weryfikacja Gemini): gdy
            // `script_tasks` jest puste, oryginalny `tx_db` nigdy nie był
            // przenoszony - kanał nie zamykał się, dopóki ta zmienna nie
            // wyszła z zasięgu na końcu CAŁEGO domknięcia `thread::scope`,
            // czyli PO `db_thread.join()` niżej - klasyczny deadlock. Jawny
            // `drop` zamyka kanał deterministycznie, zanim `.join()` zacznie
            // czekać.
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
                    "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 19 mógł nie zostać w pełni zapisany.".to_string()
                ));
                Err(rusqlite::Error::UnwindingPanic)
            }
        }
    });
    wynik_zapisu?;

    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log(
            "🛑 Diagnostyka przerwana przez użytkownika.".to_string(),
        ));
        return Ok(());
    }

    // --- ETAP 4: FLAGA UKOŃCZENIA ---
    conn.execute(SQL_FINALIZACJA, [])?;

    // --- ETAP 5: RAPORT ---
    let elapsed = start_time.elapsed();
    let total_bytes = ufs_stats.processed_bytes.load(Ordering::SeqCst)
        + script_stats.processed_bytes.load(Ordering::SeqCst);
    let sum =
        |a: &AtomicUsize, b: &AtomicUsize| a.load(Ordering::SeqCst) + b.load(Ordering::SeqCst);

    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;
    let _ = writeln!(
        &mut log_out,
        "=========================================================================="
    );
    let _ = writeln!(
        &mut log_out,
        "DZIENNIK KOŃCOWY - FAZA 19 (DIAGNOSTYKA KONTENERÓW I STRUMIENI WIDEO)"
    );
    let _ = writeln!(
        &mut log_out,
        "Czas trwania: {:.2?} | Transfer: {}",
        elapsed,
        format_bytes(total_bytes)
    );
    let _ = writeln!(
        &mut log_out,
        "==========================================================================\n"
    );
    let _ = writeln!(
        &mut log_out,
        "Spójne kontenery: {}",
        sum(&ufs_stats.ok, &script_stats.ok)
    );
    let _ = writeln!(
        &mut log_out,
        "Łączny materiał wideo: {}",
        format_duration(
            ufs_stats.total_duration_sec.load(Ordering::SeqCst)
                + script_stats.total_duration_sec.load(Ordering::SeqCst)
        )
    );
    let _ = writeln!(&mut log_out, "\n[ KATEGORIE USZKODZEŃ ]");
    let _ = writeln!(
        &mut log_out,
        "  Brak nagłówka ftyp: {} wspólne / {} unikalne",
        sum(&ufs_stats.err_ftyp_common, &script_stats.err_ftyp_common),
        sum(&ufs_stats.err_ftyp_unique, &script_stats.err_ftyp_unique)
    );
    let moov_c = sum(&ufs_stats.err_moov_common, &script_stats.err_moov_common);
    let moov_u = sum(&ufs_stats.err_moov_unique, &script_stats.err_moov_unique);
    let _ = writeln!(
        &mut log_out,
        "  Brak tablic moov / luki w ciągłości TS: {} wspólne / {} unikalne",
        moov_c, moov_u
    );
    let _ = writeln!(
        &mut log_out,
        "  Plik ucięty:        {} wspólne / {} unikalne",
        sum(&ufs_stats.err_trunc_common, &script_stats.err_trunc_common),
        sum(&ufs_stats.err_trunc_unique, &script_stats.err_trunc_unique)
    );
    let _ = writeln!(
        &mut log_out,
        "  Inne uszkodzenia:   {} wspólne / {} unikalne",
        sum(&ufs_stats.err_other_common, &script_stats.err_other_common),
        sum(&ufs_stats.err_other_unique, &script_stats.err_other_unique)
    );
    let _ = writeln!(
        &mut log_out,
        "\nBłędy I/O: {}",
        sum(&ufs_stats.errors, &script_stats.errors)
    );

    if moov_c > 0 {
        let _ = writeln!(&mut log_out, "\n[ ℹ POTENCJAŁ NAPRAWCZY ]");
        let _ = writeln!(
            &mut log_out,
            "  {} plików WSPÓLNYCH ma uszkodzone tablice moov. To jedyna kategoria",
            moov_c
        );
        let _ = writeln!(
            &mut log_out,
            "  uszkodzenia wideo teoretycznie naprawialna przez złożenie z drugiej kopii"
        );
        let _ = writeln!(
            &mut log_out,
            "  (dane klatek mdat mogą być nietknięte - brakuje tylko mapy, gdzie leżą)."
        );
    }

    let _ = writeln!(&mut log_out, "\n[ ⚠ ZAKRES WERYFIKACJI ]");
    let _ = writeln!(
        &mut log_out,
        "  Ta faza sprawdza SPÓJNOŚĆ STRUKTURY (kontenera MP4 lub ciągłości pakietów TS),"
    );
    let _ = writeln!(&mut log_out, "  NIE poprawność samych klatek wideo.");
    let _ = writeln!(
        &mut log_out,
        "  Pełne dekodowanie H.264/HEVC wymagałoby ffmpeg (zależność systemowa)."
    );

    if let Ok(mut f) = File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "✔ Zapisano Dziennik Końcowy w: {}",
            dz_path.display()
        )));
    }
    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    info!(
        ok = sum(&ufs_stats.ok, &script_stats.ok),
        missing_moov = moov_c + moov_u,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 19 zakończona"
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
    // REGRESJA (measure twice — druga weryfikacja Gemini, N2, defense in
    // depth): panika w KTÓRYMKOLWIEK analizatorze kontenera nie może ubić
    // wątku Rayon. Uczciwie udokumentowane ograniczenie: żaden z parserów
    // TS/FLV/mp4_engines::boxes nie ma dziś znanego, stabilnego pliku
    // wejściowego wywołującego panikę deterministycznie (ręczny przegląd
    // kodu nie znalazł ścieżki panikującej) — ten sam uczciwy wzorzec testu
    // MECHANIZMU co `phase13::test_analyze_image_generic_branch_is_panic_guarded`
    // i `phase11::test_panika_w_silniku_zip_jest_bezpiecznie_przechwycona`.
    // ------------------------------------------------------------------

    #[test]
    fn test_panika_w_analizie_kontenera_jest_bezpiecznie_przechwycona() {
        let stats = LiveStats::new(1);
        let wynik: std::thread::Result<SideVideoResult> =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> SideVideoResult {
                panic!("celowa panika testowa - symuluje awarię parsera kontenera wideo");
            }));

        let s = wynik.unwrap_or_else(|_| {
            bump_damage_counter(&stats, VideoDamage::Other, false);
            SideVideoResult {
                id: 1, ok: Some(false),
                reason: Some("Analiza kontenera spanikowała (parser/dekoder natrafił na nieoczekiwaną strukturę) - traktowane jak uszkodzenie, nie błąd I/O".to_string()),
                duration_ms: None, track_count: None, io_error: Some(false), created_unix: None,
            }
        });

        assert_eq!(
            s.ok,
            Some(false),
            "Panika musi zostać zamieniona na porażkę analizy, nie propagować się dalej"
        );
        assert_eq!(
            s.io_error,
            Some(false),
            "Panika NIE jest błędem I/O - plik istnieje i jest czytelny, tylko parser go nie udźwignął"
        );
    }

    #[test]
    fn test_compute_half_threads() {
        assert_eq!(compute_half_threads(8), 4);
        assert_eq!(compute_half_threads(1), 1);
        assert_eq!(compute_half_threads(0), 1);
    }

    #[test]
    fn test_compute_activity_slots() {
        assert_eq!(compute_activity_slots("CONCURRENT", 4, 2), 2);
        assert_eq!(compute_activity_slots("SEQUENTIAL", 4, 2), 4);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(125), "2m 5s");
        assert_eq!(format_duration(3725), "1h 2m 5s");
        assert_eq!(format_duration(0), "0s");
    }

    #[test]
    fn test_bump_damage_counter_routes_to_correct_bucket() {
        let stats = LiveStats::new(2);
        bump_damage_counter(&stats, VideoDamage::MissingMoov, true);
        bump_damage_counter(&stats, VideoDamage::MissingMoov, true);
        bump_damage_counter(&stats, VideoDamage::MissingFtyp, false);
        bump_damage_counter(&stats, VideoDamage::TruncatedBox, true);
        bump_damage_counter(&stats, VideoDamage::Other, false);

        assert_eq!(stats.err_moov_common.load(Ordering::Relaxed), 2);
        assert_eq!(stats.err_moov_unique.load(Ordering::Relaxed), 0);
        assert_eq!(stats.err_ftyp_unique.load(Ordering::Relaxed), 1);
        assert_eq!(stats.err_trunc_common.load(Ordering::Relaxed), 1);
        assert_eq!(stats.err_other_unique.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_build_source_block_reports_all_categories() {
        use std::time::Duration;
        let stats = LiveStats::new(2);
        stats.ok.store(10, Ordering::Relaxed);
        stats.total_duration_sec.store(3725, Ordering::Relaxed);
        stats.err_moov_common.store(3, Ordering::Relaxed);
        stats.errors.store(1, Ordering::Relaxed);

        let block = build_source_block(
            "UFS Explorer",
            &stats,
            Instant::now() - Duration::from_secs(1),
        );
        assert!(block.starts_with("[UFS Explorer]"));
        assert!(block.contains("Spójne kontenery: 10"));
        assert!(block.contains("Łączny materiał: 1h 2m 5s"));
        assert!(block.contains("Brak moov / luki TS: 3 wspólne / 0 unikalne"));
        assert!(block.contains("Błędy I/O: 1"));
    }

    #[test]
    fn test_build_source_block_shows_thread_activity_markup() {
        use std::time::Duration;
        let stats = LiveStats::new(2);
        stats.thread_activity.mark_busy(0);
        let block = build_source_block(
            "UFS Explorer",
            &stats,
            Instant::now() - Duration::from_millis(500),
        );
        let line = block
            .lines()
            .find(|l| l.starts_with("Wątki odczytu"))
            .expect("powinna istnieć linia Wariantu A");
        assert_eq!(line, "Wątki odczytu (Wariant A): {G:1} {R:2}");
    }

    // ------------------------------------------------------------------
    // Kierowanie na właściwy analizator
    // ------------------------------------------------------------------

    /// Rozszerzenia obsługiwane przez tę fazę, wyciągnięte z listy `LIKE`
    /// w [`SQL_FINALIZACJA`] — czyli z jedynego miejsca, gdzie są zapisane
    /// jawnie. Test nie utrzymuje własnej kopii listy, bo ta rozjechałaby się
    /// przy pierwszej zmianie.
    fn rozszerzenia_z_sql() -> Vec<String> {
        let mut out = Vec::new();
        let mut reszta = SQL_FINALIZACJA;
        while let Some(p) = reszta.find("LIKE '%.") {
            let po = &reszta[p + "LIKE '%.".len()..];
            let koniec = po.find('\'').expect("wzorzec LIKE musi być domknięty");
            out.push(po[..koniec].to_string());
            reszta = &po[koniec..];
        }
        out
    }

    /// Czy faza w ogóle obsługuje to rozszerzenie — replika bramki `supported`
    /// z [`run`], złożona z tych samych sześciu predykatów.
    fn obslugiwane(nazwa: &str) -> bool {
        video_image::is_video_extension(nazwa)
            || crate::ts_stream::is_ts_extension(nazwa)
            || crate::mkv_container::is_mkv_extension(nazwa)
            || crate::flv_stream::is_flv_extension(nazwa)
            || crate::riff_container::is_riff_extension(nazwa)
            || crate::mp3_stream::is_mp3_extension(nazwa)
    }

    /// NAJWAŻNIEJSZY test spójności tej fazy.
    ///
    /// Bramka w Ruście decyduje, CO zostanie przeanalizowane, a lista `LIKE`
    /// w SQL decyduje, CO może dostać flagę ukończenia. Rozjazd zakleszcza
    /// plik: analizowany przy każdym uruchomieniu, bo nigdy nie zostaje
    /// domknięty — albo odwrotnie, domykany bez analizatora.
    #[test]
    fn test_lista_rozszerzen_w_sql_pokrywa_sie_z_bramka_w_rust() {
        let z_sql = rozszerzenia_z_sql();
        assert_eq!(
            z_sql.len(),
            13,
            "spodziewamy się 13 rozszerzeń, SQL ma: {:?}",
            z_sql
        );

        for ext in &z_sql {
            let nazwa = format!("plik.{}", ext);
            assert!(
                obslugiwane(&nazwa),
                "rozszerzenie .{} jest w SQL, ale żaden analizator go nie obsługuje - plik na wieki zostanie z phase19_done = 0",
                ext
            );
        }
    }

    #[test]
    fn test_kazde_obslugiwane_rozszerzenie_jest_w_liscie_sql() {
        let z_sql = rozszerzenia_z_sql();
        for ext in [
            "mp4", "mov", "m4v", "ts", "m2ts", "mts", "mkv", "webm", "mka", "flv", "wav", "avi",
            "mp3",
        ] {
            assert!(
                z_sql.iter().any(|e| e == ext),
                "rozszerzenie .{} jest obsługiwane w Ruście, ale brak go w liście SQL - plik byłby analizowany przy KAŻDYM uruchomieniu",
                ext
            );
        }
    }

    #[test]
    fn test_formaty_poza_zakresem_nie_sa_obslugiwane() {
        for nazwa in [
            "film.wmv",
            "film.mpg",
            "zdjecie.jpg",
            "dokument.pdf",
            "bez_rozszerzenia",
        ] {
            assert!(
                !obslugiwane(nazwa),
                "'{}' nie należy do zakresu Fazy 19",
                nazwa
            );
        }
    }

    /// Predykaty muszą być ROZŁĄCZNE. Kolejność w `process_side_stream` to
    /// `if/else if`, więc nakładające się predykaty czyniłyby późniejszą gałąź
    /// martwą — np. `.mkv` łapane przez predykat TS nigdy nie trafiłoby do
    /// parsera Matroski.
    #[test]
    fn test_predykaty_analizatorow_sa_rozlaczne() {
        for ext in [
            "mp4", "mov", "m4v", "ts", "m2ts", "mts", "mkv", "webm", "mka", "flv", "wav", "avi",
            "mp3",
        ] {
            let nazwa = format!("plik.{}", ext);
            let trafienia = [
                video_image::is_video_extension(&nazwa),
                crate::ts_stream::is_ts_extension(&nazwa),
                crate::mkv_container::is_mkv_extension(&nazwa),
                crate::flv_stream::is_flv_extension(&nazwa),
                crate::riff_container::is_riff_extension(&nazwa),
                crate::mp3_stream::is_mp3_extension(&nazwa),
            ]
            .iter()
            .filter(|t| **t)
            .count();

            assert_eq!(
                trafienia, 1,
                "rozszerzenie .{} musi pasować do DOKŁADNIE jednego analizatora, pasuje do {}",
                ext, trafienia
            );
        }
    }

    #[test]
    fn test_rozpoznawanie_rozszerzen_ignoruje_wielkosc_liter() {
        for nazwa in ["FILM.MP4", "Film.Mkv", "NAGRANIE.FLV", "strumien.M2TS"] {
            assert!(
                obslugiwane(nazwa),
                "'{}' musi być rozpoznane niezależnie od wielkości liter",
                nazwa
            );
        }
    }

    // ------------------------------------------------------------------
    // Analiza na PRAWDZIWYCH plikach
    // ------------------------------------------------------------------

    fn utworz(sciezka: &Path, bajty: &[u8]) {
        if let Some(r) = sciezka.parent() {
            fs::create_dir_all(r).expect("Nie można utworzyć katalogów nadrzędnych");
        }
        fs::write(sciezka, bajty).expect("Nie można zapisać danych do pliku");
    }

    fn uruchom(
        katalog: &Path,
        zadania: &[Task],
        is_ufs: bool,
    ) -> (LiveStats, Vec<SideVideoResult>) {
        let (tx_db, rx_db) = mpsc::sync_channel(10_000);
        let (tx_ui, _rx_ui) = mpsc::channel();
        let stats = LiveStats::new(2);

        process_side_stream(StreamCtx {
            base_path: katalog,
            tasks: zadania,
            side_label: "Test",
            stats: &stats,
            tx_db,
            is_ufs,
            start_time: Instant::now(),
            tx_ui: &tx_ui,
            bar_idx: 0,
            debug_log: crate::debug_log::DebugLog::maybe_open("", "", "INFO"),
        });

        let wyniki: Vec<SideVideoResult> = rx_db
            .into_iter()
            .flat_map(|m| match m {
                ScanMsg::UfsChunk(c) | ScanMsg::ScriptChunk(c) => c,
            })
            .collect();

        (stats, wyniki)
    }

    fn zadanie(id: i32, rel: &str, wspolny: bool) -> Task {
        Task {
            id,
            rel_path: rel.to_string(),
            is_common: wspolny,
        }
    }

    /// Brakujący plik to błąd I/O — kategoria zupełnie inna niż uszkodzenie
    /// kontenera. Zlanie ich dałoby raport mówiący o zniszczonym wideo tam,
    /// gdzie problemem jest niedostępny nośnik.
    #[test]
    fn test_brakujacy_plik_jest_bledem_io_nie_uszkodzeniem() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let zadania = [
            zadanie(1, "nie_ma.mp4", true),
            zadanie(2, "nie_ma.ts", true),
            zadanie(3, "nie_ma.flv", true),
            zadanie(4, "nie_ma.mkv", true),
        ];

        let (stats, wyniki) = uruchom(dir.path(), &zadania, true);

        assert_eq!(
            stats.errors.load(Ordering::Relaxed),
            4,
            "każdy brakujący plik to jeden błąd I/O"
        );
        assert_eq!(stats.ok.load(Ordering::Relaxed), 0);

        for w in &wyniki {
            assert_eq!(w.io_error, Some(true), "id {}", w.id);
            assert!(
                w.ok.is_none(),
                "przy błędzie I/O nie ma orzeczenia o pliku (id {})",
                w.id
            );
            assert!(w.reason.is_none());
        }

        let uszkodzenia = stats.err_ftyp_common.load(Ordering::Relaxed)
            + stats.err_moov_common.load(Ordering::Relaxed)
            + stats.err_trunc_common.load(Ordering::Relaxed)
            + stats.err_other_common.load(Ordering::Relaxed);
        assert_eq!(
            uszkodzenia, 0,
            "niedostępny plik NIE jest uszkodzeniem kontenera"
        );
    }

    /// Plik istnieje, ale nie jest tym, co obiecuje rozszerzenie — to
    /// uszkodzenie, nie błąd I/O.
    #[test]
    fn test_falszywe_rozszerzenie_jest_uszkodzeniem_nie_bledem_io() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let smieci = b"to nie jest zaden kontener wideo, tylko zwykly tekst";

        for (i, nazwa) in ["a.ts", "b.flv", "c.mkv", "d.mp4", "e.wav"]
            .iter()
            .enumerate()
        {
            utworz(&dir.path().join(nazwa), smieci);
            let (stats, wyniki) = uruchom(dir.path(), &[zadanie(i as i32, nazwa, true)], true);

            assert_eq!(
                stats.errors.load(Ordering::Relaxed),
                0,
                "'{}' istnieje, więc to nie błąd I/O",
                nazwa
            );
            assert_eq!(wyniki.len(), 1);
            assert_eq!(
                wyniki[0].ok,
                Some(false),
                "'{}' musi zostać uznany za niesprawny",
                nazwa
            );
            assert_eq!(wyniki[0].io_error, Some(false));
            assert!(
                wyniki[0].reason.is_some(),
                "uszkodzenie musi być opisane: '{}'",
                nazwa
            );

            let uszkodzenia = stats.err_ftyp_common.load(Ordering::Relaxed)
                + stats.err_moov_common.load(Ordering::Relaxed)
                + stats.err_trunc_common.load(Ordering::Relaxed)
                + stats.err_other_common.load(Ordering::Relaxed);
            assert_eq!(
                uszkodzenia, 1,
                "'{}' musi trafić do dokładnie jednego koszyka uszkodzeń",
                nazwa
            );
        }
    }

    #[test]
    fn test_kazda_gałaz_analizy_opisuje_wlasny_format() {
        // Komunikat musi nazywać format, którego dotyczy - inaczej operator nie
        // wie, czy plik trafił do właściwego parsera.
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let smieci = b"nie kontener";

        for (nazwa, fragment) in [("a.ts", "TS"), ("b.flv", "FLV"), ("c.wav", "RIFF")] {
            utworz(&dir.path().join(nazwa), smieci);
            let (_, wyniki) = uruchom(dir.path(), &[zadanie(1, nazwa, true)], true);
            let powod = wyniki[0]
                .reason
                .clone()
                .expect("Nie można utworzyć katalogu tymczasowego dla testu");
            assert!(
                powod.contains(fragment),
                "plik '{}' musi zostać opisany przez parser {}: {}",
                nazwa,
                fragment,
                powod
            );
        }
    }

    #[test]
    fn test_uszkodzenia_rozdzielone_na_wspolne_i_unikalne() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        utworz(&dir.path().join("wspolny.flv"), b"smieci");
        utworz(&dir.path().join("unikalny.flv"), b"smieci");

        let (stats, _) = uruchom(
            dir.path(),
            &[
                zadanie(1, "wspolny.flv", true),
                zadanie(2, "unikalny.flv", false),
            ],
            true,
        );

        assert_eq!(
            stats.err_ftyp_common.load(Ordering::Relaxed),
            1,
            "plik wspólny do koszyka wspólnych"
        );
        assert_eq!(
            stats.err_ftyp_unique.load(Ordering::Relaxed),
            1,
            "plik unikalny do koszyka unikalnych"
        );
    }

    // ------------------------------------------------------------------
    // Ścieżka analizy RIFF (WAV/AVI)
    // ------------------------------------------------------------------

    /// Buduje minimalny, poprawny plik WAV: nagłówek RIFF/WAVE, chunk `fmt `
    /// i chunk `data`. Powielone celowo z `riff_container::tests::zbuduj_wav`
    /// zamiast importowane - ten sam wzorzec co w `repair_modules/riff.rs`
    /// (nieimportowanie prywatnych helperów testowych między modułami).
    fn zbuduj_wav(probki: &[u8]) -> Vec<u8> {
        let fmt_body: [u8; 16] = [1, 0, 1, 0, 0x44, 0xAC, 0, 0, 0x44, 0xAC, 0, 0, 1, 0, 8, 0];

        let mut data_chunk = Vec::new();
        data_chunk.extend_from_slice(b"data");
        data_chunk.extend_from_slice(&(probki.len() as u32).to_le_bytes());
        data_chunk.extend_from_slice(probki);
        if probki.len() % 2 == 1 {
            data_chunk.push(0);
        }

        let mut fmt_chunk = Vec::new();
        fmt_chunk.extend_from_slice(b"fmt ");
        fmt_chunk.extend_from_slice(&(fmt_body.len() as u32).to_le_bytes());
        fmt_chunk.extend_from_slice(&fmt_body);

        let tresc_po_formie = 4 + fmt_chunk.len() + data_chunk.len();

        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(tresc_po_formie as u32).to_le_bytes());
        wav.extend_from_slice(b"WAVE");
        wav.extend_from_slice(&fmt_chunk);
        wav.extend_from_slice(&data_chunk);
        wav
    }

    #[test]
    fn test_riff_zdrowy_wav_jest_uznany_za_sprawny() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        utworz(
            &dir.path().join("zdrowy.wav"),
            &zbuduj_wav(&[1, 2, 3, 4, 5]),
        );

        let (stats, wyniki) = uruchom(dir.path(), &[zadanie(1, "zdrowy.wav", true)], true);

        assert_eq!(wyniki.len(), 1);
        assert_eq!(
            wyniki[0].ok,
            Some(true),
            "zdrowy WAV musi zostać uznany za sprawny"
        );
        assert_eq!(wyniki[0].io_error, Some(false));
        assert!(
            wyniki[0]
                .reason
                .as_deref()
                .expect("Nie można utworzyć katalogu tymczasowego dla testu")
                .contains("RIFF")
        );
        assert_eq!(stats.ok.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_riff_uciety_wav_jest_uszkodzeniem_typu_trunc() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let wav = zbuduj_wav(&[1, 2, 3, 4, 5]);
        utworz(&dir.path().join("uciety.wav"), &wav[..wav.len() - 3]);

        let (stats, wyniki) = uruchom(dir.path(), &[zadanie(1, "uciety.wav", true)], true);

        assert_eq!(
            wyniki[0].ok,
            Some(false),
            "ucięty WAV musi zostać uznany za uszkodzony"
        );
        assert_eq!(
            stats.err_trunc_common.load(Ordering::Relaxed),
            1,
            "ucięcie musi trafić do koszyka 'plik ucięty'"
        );
    }

    // ------------------------------------------------------------------
    // Ścieżka analizy MP3
    // ------------------------------------------------------------------

    /// Buduje `ile` kolejnych, poprawnych ramek MPEG-1/Warstwa III,
    /// 128 kbps/44100 Hz (417 B każda). Powielone celowo z
    /// `mp3_stream::tests::zbuduj_ramki` - ten sam wzorzec co przy WAV
    /// (nieimportowanie prywatnych helperów testowych między modułami).
    fn zbuduj_mp3(ile: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let naglowek = [0xFFu8, 0xFB, 0x90, 0x00]; // MPEG1/L3, 128 kbps, 44100 Hz, bez paddingu
        for _ in 0..ile {
            out.extend_from_slice(&naglowek);
            out.resize(out.len() + 417 - 4, 0xAA);
        }
        out
    }

    #[test]
    fn test_mp3_zdrowy_strumien_jest_uznany_za_sprawny() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        utworz(&dir.path().join("zdrowy.mp3"), &zbuduj_mp3(5));

        let (stats, wyniki) = uruchom(dir.path(), &[zadanie(1, "zdrowy.mp3", true)], true);

        assert_eq!(wyniki.len(), 1);
        assert_eq!(
            wyniki[0].ok,
            Some(true),
            "zdrowy strumień MP3 musi zostać uznany za sprawny"
        );
        assert!(
            wyniki[0]
                .reason
                .as_deref()
                .expect("Nie można utworzyć katalogu tymczasowego dla testu")
                .contains("ramek")
        );
        assert_eq!(stats.ok.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_mp3_uszkodzony_w_srodku_jest_wykryty() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let mut plik = zbuduj_mp3(2);
        plik.extend(vec![0x00u8; 500]); // wyspa uszkodzenia
        plik.extend(zbuduj_mp3(2));
        utworz(&dir.path().join("uszkodzony.mp3"), &plik);

        let (stats, wyniki) = uruchom(dir.path(), &[zadanie(1, "uszkodzony.mp3", true)], true);

        assert_eq!(
            wyniki[0].ok,
            Some(false),
            "strumień z wyspą uszkodzenia musi zostać uznany za niesprawny"
        );
        assert_eq!(
            stats.err_other_common.load(Ordering::Relaxed),
            1,
            "utrata synchronizacji trafia do koszyka 'inne uszkodzenia'"
        );
    }

    #[test]
    fn test_mp3_smieci_z_rozszerzeniem_mp3_to_missing_ftyp() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        utworz(
            &dir.path().join("smieci.mp3"),
            b"to nie jest strumien MPEG audio",
        );

        let (stats, wyniki) = uruchom(dir.path(), &[zadanie(1, "smieci.mp3", true)], true);

        assert_eq!(wyniki[0].ok, Some(false));
        assert_eq!(stats.err_ftyp_common.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_wagi_rozszerzen_licza_bajty_i_normalizuja_wielkosc_liter() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        utworz(&dir.path().join("a.MP4"), &vec![0u8; 300]);
        utworz(&dir.path().join("b.mp4"), &[0u8; 200]);
        utworz(&dir.path().join("c.mkv"), &[0u8; 100]);

        let (stats, _) = uruchom(
            dir.path(),
            &[
                zadanie(1, "a.MP4", true),
                zadanie(2, "b.mp4", true),
                zadanie(3, "c.mkv", true),
            ],
            true,
        );

        let m = stats.ext_weights.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            m.get("mp4"),
            Some(&500),
            "oba warianty wielkości liter w jednym koszyku: {:?}",
            *m
        );
        assert_eq!(m.get("mkv"), Some(&100));
    }

    /// Czas utworzenia nagrania pochodzi z atomu `mvhd`, więc istnieje TYLKO w
    /// kontenerach ISOBMFF. Dla TS/FLV/MKV/RIFF musi pozostać `None` —
    /// wpisanie tam czegokolwiek byłoby wymyślonym dowodem.
    #[test]
    fn test_czas_utworzenia_tylko_dla_isobmff() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        for nazwa in ["a.ts", "b.flv", "c.mkv", "d.wav"] {
            utworz(&dir.path().join(nazwa), b"smieci");
            let (_, wyniki) = uruchom(dir.path(), &[zadanie(1, nazwa, true)], true);
            assert!(
                wyniki[0].created_unix.is_none(),
                "'{}' nie jest kontenerem ISOBMFF - czas utworzenia musi zostać nieustalony",
                nazwa
            );
        }
    }

    #[test]
    fn test_wyniki_trafiaja_do_wlasciwego_kanalu() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        utworz(&dir.path().join("x.mp4"), b"smieci");
        let zadania = [zadanie(1, "x.mp4", true)];

        let (tx_db, rx_db) = mpsc::sync_channel(100);
        let (tx_ui, _rx) = mpsc::channel();
        let stats = LiveStats::new(2);
        process_side_stream(StreamCtx {
            base_path: dir.path(),
            tasks: &zadania,
            side_label: "T",
            stats: &stats,
            tx_db,
            is_ufs: false,
            start_time: Instant::now(),
            tx_ui: &tx_ui,
            bar_idx: 0,
            debug_log: crate::debug_log::DebugLog::maybe_open("", "", "INFO"),
        });

        let msgs: Vec<ScanMsg> = rx_db.into_iter().collect();
        assert!(!msgs.is_empty());
        assert!(
            msgs.iter().all(|m| matches!(m, ScanMsg::ScriptChunk(_))),
            "przy is_ufs=false tylko kanał Skryptu"
        );
    }

    #[test]
    fn test_identyfikatory_wracaja_nienaruszone() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let zadania: Vec<Task> = (0..4)
            .map(|i| {
                let nazwa = format!("p{}.mp4", i);
                utworz(&dir.path().join(&nazwa), b"smieci");
                zadanie(500 + i, &nazwa, true)
            })
            .collect();

        let (_, wyniki) = uruchom(dir.path(), &zadania, true);

        let mut id: Vec<i32> = wyniki.iter().map(|w| w.id).collect();
        id.sort();
        assert_eq!(
            id,
            vec![500, 501, 502, 503],
            "wynik wiązany jest z wierszem bazy po id"
        );
    }

    #[test]
    fn test_pusta_lista_zadan_nic_nie_wysyla() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let (stats, wyniki) = uruchom(dir.path(), &[], true);
        assert!(wyniki.is_empty());
        assert_eq!(stats.processed_files.load(Ordering::Relaxed), 0);
    }

    /// Pełna ścieżka na PRAWDZIWYCH kontenerach z `image/`.
    ///
    /// Używamy `test_fixture_real.mkv`, nie `test_fixture.mkv` — ten drugi nie
    /// jest Matroską (parser słusznie zgłasza „niespójna struktura EBML") i
    /// służy testom jednostkowym jako materiał negatywny. To samo rozróżnienie
    /// stosuje `mkv_container::tests::test_read_real_mkv_fixture`.
    #[test]
    #[ignore = "Wymaga image/test_fixture.mp4, test_fixture_real.mkv i test_fixture.flv. Uruchom z --ignored."]
    fn test_e2e_zdrowe_kontenery_sa_uznane_za_sprawne() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let mut zadania = Vec::new();

        for (i, zrodlo) in [
            "test_fixture.mp4",
            "test_fixture_real.mkv",
            "test_fixture.flv",
        ]
        .iter()
        .enumerate()
        {
            let sciezka = Path::new("image").join(zrodlo);
            if !sciezka.exists() {
                continue;
            }
            fs::copy(&sciezka, dir.path().join(zrodlo)).expect("Kopiowanie pliku nie powiodło się");
            zadania.push(zadanie(i as i32, zrodlo, true));
        }
        assert!(
            !zadania.is_empty(),
            "co najmniej jeden fixture musi istnieć"
        );

        let (stats, wyniki) = uruchom(dir.path(), &zadania, true);

        assert_eq!(
            stats.ok.load(Ordering::Relaxed),
            zadania.len(),
            "wszystkie zdrowe kontenery muszą zostać uznane za sprawne, wyniki: {:?}",
            wyniki
                .iter()
                .map(|w| (w.id, w.ok, w.reason.clone()))
                .collect::<Vec<_>>()
        );
        assert_eq!(stats.errors.load(Ordering::Relaxed), 0);

        for w in &wyniki {
            assert_eq!(
                w.ok,
                Some(true),
                "id {} musi być sprawny: {:?}",
                w.id,
                w.reason
            );
            assert!(
                w.track_count.is_some(),
                "sprawny kontener musi zgłosić liczbę ścieżek (id {})",
                w.id
            );
        }

        assert!(
            stats.total_duration_sec.load(Ordering::Relaxed) > 0,
            "sprawne kontenery muszą wnieść czas trwania do sumy"
        );
    }

    /// Ucięta Matroska musi w Fazie 19 wylądować w koszyku „plik ucięty".
    ///
    /// Zanim `mkv_container` dostał kontrolę kompletności `Segment`, ten plik
    /// był raportowany jako SPRAWNY (pełne 2023 ms, 2 ścieżki) — czyli
    /// wykluczony z naprawy w Fazie 17 i dopuszczony do wygranej w Fazie 9.
    #[test]
    #[ignore = "Wymaga image/test_fixture_mkv_truncated.mkv. Uruchom z --ignored."]
    fn test_e2e_uciety_mkv_trafia_do_kosza_uciec() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let nazwa = "test_fixture_mkv_truncated.mkv";
        fs::copy(Path::new("image").join(nazwa), dir.path().join(nazwa))
            .expect("Kopiowanie pliku nie powiodło się");

        let (stats, wyniki) = uruchom(dir.path(), &[zadanie(1, nazwa, true)], true);

        assert_eq!(
            wyniki[0].ok,
            Some(false),
            "ucięty kontener nie jest sprawny: {:?}",
            wyniki[0].reason
        );
        assert_eq!(stats.ok.load(Ordering::Relaxed), 0);
        assert_eq!(
            stats.errors.load(Ordering::Relaxed),
            0,
            "plik istnieje - to nie błąd I/O"
        );
        assert_eq!(
            stats.err_trunc_common.load(Ordering::Relaxed),
            1,
            "MkvDamage::Truncated musi trafić do koszyka „plik ucięty”"
        );
        assert!(
            wyniki[0].reason.as_deref().unwrap_or("").contains("ucięty"),
            "opis musi nazwać ucięcie: {:?}",
            wyniki[0].reason
        );
    }

    /// MP4 pod rozszerzeniem `.mkv` to fałszywe rozszerzenie, nie ucięcie —
    /// kategoria ma znaczenie dla raportu śledczego.
    #[test]
    #[ignore = "Wymaga image/test_fixture_mp4_pod_mkv.mkv. Uruchom z --ignored."]
    fn test_e2e_mp4_pod_mkv_jest_falszywym_rozszerzeniem() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let nazwa = "test_fixture_mp4_pod_mkv.mkv";
        fs::copy(Path::new("image").join(nazwa), dir.path().join(nazwa))
            .expect("Kopiowanie pliku nie powiodło się");

        let (stats, wyniki) = uruchom(dir.path(), &[zadanie(1, nazwa, true)], true);

        assert_eq!(wyniki[0].ok, Some(false));
        assert_eq!(
            stats.err_ftyp_common.load(Ordering::Relaxed),
            1,
            "niespójna struktura EBML (w tym fałszywe rozszerzenie) idzie do koszyka „brak nagłówka”"
        );
        assert_eq!(
            stats.err_trunc_common.load(Ordering::Relaxed),
            0,
            "to nie ucięcie"
        );
    }

    /// ASYMETRIA DO ROZSTRZYGNIĘCIA: gałąź ISOBMFF nie zapisuje opisu przy
    /// sukcesie, a pozostałe trzy owszem.
    ///
    /// Zdrowy MP4 zostawia `video_reason_*` puste, podczas gdy zdrowy
    /// FLV/MKV/TS wpisuje tam podsumowanie kontenera (liczba ścieżek, kodeki,
    /// czas). Test utrwala stan FAKTYCZNY, żeby różnica była widoczna, a nie
    /// przypadkowa — ale jest to niespójność warta decyzji, a nie cecha, którą
    /// należy chronić.
    #[test]
    #[ignore = "Wymaga image/test_fixture.mp4 i test_fixture.flv. Uruchom z --ignored."]
    fn test_opis_sukcesu_jest_zapisywany_przez_kazda_galaz() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");

        let mut sprawdzone = 0;
        // ISOBMFF, FLV i Matroska — trzy różne gałęzie, ta sama umowa.
        for zrodlo in [
            "test_fixture.mp4",
            "test_fixture.flv",
            "test_fixture_real.mkv",
        ] {
            let sciezka = Path::new("image").join(zrodlo);
            if !sciezka.exists() {
                continue;
            }
            fs::copy(&sciezka, dir.path().join(zrodlo)).expect("Kopiowanie pliku nie powiodło się");

            let (_, wyniki) = uruchom(dir.path(), &[zadanie(1, zrodlo, true)], true);
            assert_eq!(wyniki[0].ok, Some(true), "{} musi być sprawny", zrodlo);
            assert!(
                wyniki[0].reason.as_ref().is_some_and(|r| !r.is_empty()),
                "{}: każda gałąź musi opisać sukces, inaczej raport operacyjny \
                 pokazuje pustkę dla części formatów i czytający nie wie, czy to \
                 brak danych, czy inny nośnik informacji",
                zrodlo
            );
            sprawdzone += 1;
        }
        assert!(sprawdzone > 0, "co najmniej jeden fixture musi istnieć");
    }

    // ------------------------------------------------------------------
    // Zapis do bazy
    // ------------------------------------------------------------------

    fn baza() -> Connection {
        let conn =
            crate::db::init_db(":memory:").expect("Inicjalizacja bazy danych nie powiodła się");
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script) VALUES (1, 'a.mp4', 1, 1)",
            [],
        ).expect("Inicjalizacja bazy danych nie powiodła się");
        conn
    }

    fn zapisz(
        conn: &Connection,
        sql: &str,
        ok: Option<bool>,
        powod: Option<&str>,
        czas: Option<i64>,
    ) {
        conn.execute(
            sql,
            params![ok, powod, None::<i64>, Some(2i64), Some(false), 1, czas],
        )
        .expect("Inicjalizacja bazy danych nie powiodła się");
    }

    #[test]
    fn test_zapis_nie_miesza_kolumn_obu_stron() {
        let conn = baza();
        zapisz(&conn, SQL_ZAPIS_UFS, Some(true), Some("UFS spójny"), None);
        zapisz(
            &conn,
            SQL_ZAPIS_SCRIPT,
            Some(false),
            Some("Skrypt uszkodzony"),
            None,
        );

        let (ok_u, ok_s, pow_u, pow_s): (Option<bool>, Option<bool>, Option<String>, Option<String>) = conn.query_row(
            "SELECT video_ok_ufs, video_ok_script, video_reason_ufs, video_reason_script FROM files WHERE id = 1",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).expect("Wykonanie zapytania SQL na bazie danych nie powiodło się");

        assert_eq!((ok_u, ok_s), (Some(true), Some(false)));
        assert_eq!(pow_u.as_deref(), Some("UFS spójny"));
        assert_eq!(pow_s.as_deref(), Some("Skrypt uszkodzony"));
    }

    /// Sedno `COALESCE`: późniejszy błąd odczytu nie może wymazać wyniku
    /// zebranego wcześniej.
    #[test]
    fn test_pozniejszy_brak_danych_nie_kasuje_wyniku() {
        let conn = baza();
        zapisz(&conn, SQL_ZAPIS_UFS, Some(true), Some("spójny"), None);
        // Drugi przebieg: brak orzeczenia (NULL) plus zgłoszony błąd I/O.
        conn.execute(
            SQL_ZAPIS_UFS,
            params![
                None::<bool>,
                None::<String>,
                None::<i64>,
                None::<i64>,
                Some(true),
                1,
                None::<i64>
            ],
        )
        .expect("Wykonanie zapytania SQL na bazie danych nie powiodło się");

        let (ok, powod, blad): (Option<bool>, Option<String>, Option<bool>) = conn
            .query_row(
                "SELECT video_ok_ufs, video_reason_ufs, io_error_ufs FROM files WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("Wykonanie zapytania SQL na bazie danych nie powiodło się");

        assert_eq!(ok, Some(true), "wcześniejsze orzeczenie musi przetrwać");
        assert_eq!(powod.as_deref(), Some("spójny"));
        assert_eq!(blad, Some(true), "sam błąd zostaje odnotowany");
    }

    /// Czas utworzenia ma JEDNĄ kolumnę dla obu stron — opisuje treść, nie
    /// kopię. Wystarczy, że odczyta go którakolwiek ze stron.
    #[test]
    fn test_czas_utworzenia_jest_wspolny_dla_obu_stron() {
        let conn = baza();

        // UFS nie odczytał czasu, Skrypt owszem.
        zapisz(&conn, SQL_ZAPIS_UFS, Some(true), Some("ok"), None);
        zapisz(
            &conn,
            SQL_ZAPIS_SCRIPT,
            Some(true),
            Some("ok"),
            Some(1_669_712_412),
        );

        let czas: Option<i64> = conn
            .query_row(
                "SELECT video_created_unix FROM files WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .expect("Odczyt z bazy danych nie powiódł się");
        assert_eq!(
            czas,
            Some(1_669_712_412),
            "czas odczytany przez JEDNĄ stronę wystarcza"
        );

        // I nie zostaje nadpisany przez stronę, która go nie zna.
        zapisz(&conn, SQL_ZAPIS_UFS, Some(true), Some("ok"), None);
        let czas2: Option<i64> = conn
            .query_row(
                "SELECT video_created_unix FROM files WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .expect("Odczyt z bazy danych nie powiódł się");
        assert_eq!(
            czas2,
            Some(1_669_712_412),
            "strona bez czasu nie może go wymazać"
        );
    }

    #[test]
    fn test_zapis_trafia_we_wlasciwy_wiersz() {
        // Kolejność parametrów jest nieoczywista (`?6` to id, `?7` stoi przed
        // nim w treści) - błąd w wiązaniu podmieniłby wiersze.
        let conn = baza();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs) VALUES (2, 'b.mp4', 1)",
            [],
        )
        .expect("Wykonanie zapytania SQL na bazie danych nie powiodło się");

        zapisz(&conn, SQL_ZAPIS_UFS, Some(true), Some("pierwszy"), None);

        let pow1: Option<String> = conn
            .query_row("SELECT video_reason_ufs FROM files WHERE id = 1", [], |r| {
                r.get(0)
            })
            .expect("Wykonanie zapytania SQL na bazie danych nie powiodło się");
        let pow2: Option<String> = conn
            .query_row("SELECT video_reason_ufs FROM files WHERE id = 2", [], |r| {
                r.get(0)
            })
            .expect("Wykonanie zapytania SQL na bazie danych nie powiodło się");

        assert_eq!(pow1.as_deref(), Some("pierwszy"));
        assert_eq!(pow2, None, "drugi wiersz nie mógł zostać tknięty");
    }

    // ------------------------------------------------------------------
    // Domknięcie fazy
    // ------------------------------------------------------------------

    fn finalizuj(
        rel: &str,
        found_ufs: bool,
        found_script: bool,
        ok_ufs: Option<bool>,
        ok_script: Option<bool>,
        err_ufs: Option<bool>,
        err_script: Option<bool>,
    ) -> Option<bool> {
        let conn =
            crate::db::init_db(":memory:").expect("Inicjalizacja bazy danych nie powiodła się");
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, video_ok_ufs, video_ok_script, io_error_ufs, io_error_script, phase19_done)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
            params![rel, found_ufs, found_script, ok_ufs, ok_script, err_ufs, err_script],
        ).expect("Inicjalizacja bazy danych nie powiodła się");

        conn.execute(SQL_FINALIZACJA, [])
            .expect("Inicjalizacja bazy danych nie powiodła się");
        conn.query_row("SELECT phase19_done FROM files WHERE id = 1", [], |r| {
            r.get(0)
        })
        .expect("Inicjalizacja bazy danych nie powiodła się")
    }

    #[test]
    fn test_obie_strony_rozstrzygniete_domykaja_faze() {
        assert_eq!(
            finalizuj(
                "a.mp4",
                true,
                true,
                Some(true),
                Some(false),
                Some(false),
                Some(false)
            ),
            Some(true)
        );
    }

    #[test]
    fn test_blad_io_tez_domyka_strone() {
        // Inaczej plik z trwale niedostępnego nośnika wracałby do kolejki bez końca.
        assert_eq!(
            finalizuj(
                "a.mkv",
                true,
                true,
                Some(true),
                None,
                Some(false),
                Some(true)
            ),
            Some(true)
        );
    }

    #[test]
    fn test_strona_nieobecna_jest_z_definicji_rozstrzygnieta() {
        assert_eq!(
            finalizuj("a.flv", true, false, Some(true), None, Some(false), None),
            Some(true)
        );
    }

    #[test]
    fn test_brak_wyniku_bez_bledu_zostawia_plik_w_kolejce() {
        assert_eq!(
            finalizuj("a.ts", true, true, Some(true), None, Some(false), None),
            Some(false),
            "strona obecna, nieprzeanalizowana i bez błędu musi zostać do ponowienia"
        );
    }

    #[test]
    fn test_finalizacja_nie_rusza_plikow_niebedacych_wideo() {
        let conn =
            crate::db::init_db(":memory:").expect("Inicjalizacja bazy danych nie powiodła się");
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, phase19_done) VALUES (1, 'zdjecie.jpg', 1, 0, 0)",
            [],
        ).expect("Inicjalizacja bazy danych nie powiodła się");

        conn.execute(SQL_FINALIZACJA, [])
            .expect("Inicjalizacja bazy danych nie powiodła się");

        let gotowe: Option<bool> = conn
            .query_row("SELECT phase19_done FROM files WHERE id = 1", [], |r| {
                r.get(0)
            })
            .expect("Inicjalizacja bazy danych nie powiodła się");
        assert_eq!(
            gotowe,
            Some(false),
            "plik poza zakresem fazy nie może dostać jej flagi ukończenia"
        );
    }

    #[test]
    fn test_finalizacja_obejmuje_kazde_obslugiwane_rozszerzenie() {
        for ext in [
            "mp4", "mov", "m4v", "ts", "m2ts", "mts", "mkv", "webm", "mka", "flv", "wav", "avi",
            "mp3",
        ] {
            let nazwa = format!("film.{}", ext);
            assert_eq!(
                finalizuj(&nazwa, true, false, Some(true), None, Some(false), None),
                Some(true),
                "rozszerzenie .{} musi być objęte domknięciem fazy",
                ext
            );
        }
    }
}
