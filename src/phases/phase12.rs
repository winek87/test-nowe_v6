// src/phases/phase12.rs

//! # Faza 12: Głęboka Walidacja Metadanych Obrazów i Wideo (EXIF / HEIF / MP4)
//! 
//! Weryfikuje integralność plików multimedialnych. Wykorzystuje potężny system
//! dualnego odczytu: `exiftool-rs` jako narzędzie GŁÓWNE oraz CLI ExifTool jako Fallback.
//! Wyłapuje błędy, daty i profiluje urządzenia. Zapisuje wyniki do SQLite dla Fazy 9.
//! W pełni wspiera interfejs Ratatui (PhaseEvent) i Dual-Logging.
//!
//! UWAGA ARCHITEKTONICZNA (TESTOWALNOŚĆ): logika decyzyjna jest wydzielona do
//! czystej funkcji [`evaluate_metadata`], która przyjmuje JUŻ WCZYTANE metadane
//! (`HashMap<String, String>`) — zero I/O, zero zależności od zainstalowanego
//! `exiftool` w środowisku testowym. [`analyze_media`] jest cienkim wrapperem:
//! [`read_exif`] (I/O) + wywołanie [`evaluate_metadata`] (czysta logika).
//!
//! UWAGA ARCHITEKTONICZNA (UI): Pasek postępu pokazuje wyłącznie % i bieżący
//! plik. Liczniki live trafiają do panelu bocznego jako JEDEN, samodzielny blok
//! PER ŹRÓDŁO — patrz [`build_source_block`].
//!
//! UWAGA ARCHITEKTONICZNA (WĄTKOWANIE): każda strona dostaje własną, dedykowaną
//! pulę Rayon (`half_threads`, identycznie jak Fazy 2-7/10/11).
//!
//! NAPRAWIONY BUG: w raporcie końcowym liczenie wykorzystanych silników
//! (`total_engine_rs`/`total_engine_cli`) miało błędny warunek, przez który
//! silnik użyty po stronie Skryptu NIGDY nie był liczony dla plików WSPÓLNYCH
//! (`is_common = true`) — `eng_scr` wpadał w martwą gałąź `else if ... && !in_ufs`,
//! która dla plików wspólnych (`in_ufs = true`) nigdy się nie wykonywała. Teraz
//! obie strony liczone bezwarunkowo i niezależnie (to nie jest "to samo
//! zdarzenie" liczone podwójnie — każda strona ma WŁASNY, niezależny wynik
//! silnika dla WŁASNEJ kopii pliku).

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::{format_bytes, format_display_path, CANCEL_SIGNAL};
use ratatui::style::Color;
use rayon::prelude::*;
use rusqlite::{params, Connection, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;
use tracing::{info, instrument, warn};

const CHUNK_SIZE: usize = 100;

// Lista formatów multimedialnych obsługiwanych przez ExifTool
const MEDIA_EXTS: &[&str] = &[
    ".jpg", ".jpeg", ".tif", ".tiff", ".heic", ".heif", ".dng", ".cr2", ".nef", ".arw", ".png", ".webp", ".bmp",
    ".mp4", ".mkv", ".mov", ".avi", ".webm", ".flv", ".wmv", ".m4v", ".ts",
    ".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac"
];

/// Lata-widma: typowe wartości domyślne zegara aparatu po rozładowaniu
/// baterii/resecie ustawień. Plik "ma datę", ale ta data jest bezwartościowa
/// dowodowo — traktowana jako nieprawdopodobna razem z rokiem 0 i przyszłością.
const SENTINEL_YEARS: &[i32] = &[0, 1900, 1904];

// ============================================================================
// POMOCNIKI (CZYSTE FUNKCJE - ZERO I/O, PEŁNA TESTOWALNOŚĆ)
// ============================================================================

fn is_media_extension(path_str: &str) -> bool {
    let lower_path = path_str.to_lowercase();
    MEDIA_EXTS.iter().any(|&ext| lower_path.ends_with(ext))
}

fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let mins = (seconds % 3600) / 60;
    let secs = seconds % 60;
    if hours > 0 { format!("{}h {}m {}s", hours, mins, secs) }
    else if mins > 0 { format!("{}m {}s", mins, secs) }
    else { format!("{}s", secs) }
}

/// Wyprowadza oczekiwaną "rodzinę" MIME (`"image"`, `"video"`, `"audio"`) z
/// rozszerzenia pliku — używane jako GENERYCZNY fallback wykrywania fałszywego
/// rozszerzenia dla formatów BEZ szczegółowej reguły w [`evaluate_metadata`]
/// (dotąd tylko 6 z 26 rozszerzeń na liście [`MEDIA_EXTS`] miało dedykowaną
/// regułę — reszta, np. `.webp`, `.avi`, `.mp3`, `.flac`, przechodziła bez
/// żadnej weryfikacji zgodności MIME). Zwraca `None` dla rozszerzeń bez
/// jednoznacznej rodziny (nie blokuje ich, po prostu nie stosuje tej reguły).
fn mime_family_for_ext(ext: &str) -> Option<&'static str> {
    match ext {
        "jpg" | "jpeg" | "tif" | "tiff" | "heic" | "heif" | "dng" | "cr2" | "nef" | "arw" | "png" | "webp" | "bmp" => Some("image"),
        "mp4" | "mkv" | "mov" | "avi" | "webm" | "flv" | "wmv" | "m4v" | "ts" => Some("video"),
        "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" => Some("audio"),
        _ => None,
    }
}

/// Sprawdza, czy wymiary obrazu/wideo są DEGENERACYJNE — technicznie obecne
/// (nagłówek się sparsował), ale bezużyteczne dowodowo: `0` w którymkolwiek
/// wymiarze, albo dokładnie `1x1` piksel (typowy ślad częściowo nadpisanego
/// nagłówka, gdzie parser odczytał śmieci jako liczby zamiast zwrócić błąd).
/// Zwraca `false`, gdy któryś wymiar nie parsuje się jako liczba (to inny
/// przypadek — "brak wymiarów", obsługiwany osobno).
fn is_dimension_degenerate(width: &str, height: &str) -> bool {
    match (width.trim().parse::<u64>(), height.trim().parse::<u64>()) {
        (Ok(w), Ok(h)) => w == 0 || h == 0 || (w == 1 && h == 1),
        _ => false,
    }
}

/// Wyszukuje WSZYSTKIE poprawne liczby zmiennoprzecinkowe w dowolnym tekście,
/// dzieląc po białych znakach i przecinkach — tolerancyjne wobec różnych
/// formatów zwracanych przez `exiftool` dla pól GPS (`"52.2297"`,
/// `"52.2297 N"`, `"52.2297, 21.0122"`). Zwraca w kolejności wystąpienia.
fn parse_all_floats(s: &str) -> Vec<f64> {
    s.split(|c: char| c.is_whitespace() || c == ',')
        .filter_map(|token| token.parse::<f64>().ok())
        .collect()
}

/// Ocenia sensowność pary współrzędnych GPS: poza zakresem geograficznym
/// (szerokość poza ±90°, długość poza ±180°) LUB dokładnie `(0.0, 0.0)` —
/// znane jako "Null Island", klasyczna wartość domyślna/uszkodzona GPS,
/// wskazująca na punkt na środku Oceanu Atlantyckiego, gdzie nikt realnie
/// nie robi zdjęć w praktyce odzysku danych.
fn is_gps_suspicious(lat: f64, lon: f64) -> bool {
    if lat == 0.0 && lon == 0.0 { return true; }
    !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon)
}

/// Wyodrębnia rok z formatu daty EXIF (`"YYYY:MM:DD HH:MM:SS"` lub
/// `"YYYY-MM-DD..."`) — pierwsze 4 znaki, jeśli są cyframi.
fn extract_year(date_str: &str) -> Option<i32> {
    let prefix: String = date_str.chars().take(4).collect();
    if prefix.len() == 4 { prefix.parse::<i32>().ok() } else { None }
}

/// Rozstrzyga, czy dany rok jest nieprawdopodobny dowodowo: rok-widmo
/// (patrz [`SENTINEL_YEARS`] — zresetowany zegar aparatu) lub data w
/// przyszłości względem `current_year` (parametr, nie zegar systemowy —
/// dla pełnej determinizmu w testach).
fn is_implausible_year(year: i32, current_year: i32) -> bool {
    SENTINEL_YEARS.contains(&year) || year > current_year
}

// ============================================================================
// STRUKTURY DANYCH
// ============================================================================

#[derive(Debug, Clone)]
pub(crate) struct Task {
    id: i32,
    rel_path: String,
    is_common: bool,
}

/// Wynik analizy jednego pliku multimedialnego. `is_valid`/`reason` to wynik
/// binarny (unieważnia plik). Pozostałe flagi (`has_zero_gps`,
/// `has_implausible_date`, `has_editing_software`) są INFORMACYJNE — mogą
/// wystąpić NIEZALEŻNIE od ważności pliku, nie unieważniają go same w sobie.
#[derive(Debug, Clone)]
struct MediaAnalysis {
    is_valid: bool,
    reason: Option<String>,
    mime_type: String, 
    dimensions: Option<String>,
    device: Option<String>,
    original_date: Option<String>,
    has_gps: bool,
    duration_sec: u64,
    /// GPS obecny, ale geograficznie niewiarygodny (poza zakresem lub Null Island).
    has_suspicious_gps: bool,
    /// Data obecna, ale rok jest wartością-widmem lub przyszłością.
    has_implausible_date: bool,
    /// Plik nosi ślad przetworzenia narzędziem (pole `Software`) — nie jest
    /// surowym oryginałem z aparatu. Nazwa narzędzia w `Some(...)`.
    editing_software: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SideMediaResult {
    id: i32,
    analysis: Option<MediaAnalysis>,
    engine: Option<String>, 
    io_error: Option<bool>,
}

pub(crate) enum ScanMsg {
    UfsChunk(Vec<SideMediaResult>),
    ScriptChunk(Vec<SideMediaResult>),
}

/// Liczniki live dla JEDNEJ strony. Cztery kategorie "twardych" błędów
/// (Ucięte/Zdegenerowane wymiary/Fałszywe MIME/Śmieci-trailer) każda
/// wspólne/unikalne, plus trzy kategorie INFORMACYJNE niezależne od ważności
/// (GPS podejrzany, data nieprawdopodobna, edytowane narzędziem). Nigdy nie
/// łączone z licznikami drugiej strony.
pub(crate) struct LiveStats {
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    errors: AtomicUsize,
    ext_weights: Mutex<HashMap<String, u64>>,
    
    ok: AtomicUsize,
    engine_rs: AtomicUsize,   
    engine_cli: AtomicUsize,  
    last_engine: Mutex<String>,

    err_trunc_common: AtomicUsize,   err_trunc_unique: AtomicUsize,
    err_nodim_common: AtomicUsize,   err_nodim_unique: AtomicUsize,
    /// Wymiary obecne, ale degeneracyjne (0 lub 1x1) — patrz [`is_dimension_degenerate`].
    err_zerodim_common: AtomicUsize, err_zerodim_unique: AtomicUsize,
    err_mime_common: AtomicUsize,    err_mime_unique: AtomicUsize,
    err_trail_common: AtomicUsize,   err_trail_unique: AtomicUsize,

    feat_gps_common: AtomicUsize,    feat_gps_unique: AtomicUsize,
    feat_date_common: AtomicUsize,   feat_date_unique: AtomicUsize,
    /// INFORMACYJNE: GPS obecny, ale geograficznie niewiarygodny.
    gps_suspicious_common: AtomicUsize, gps_suspicious_unique: AtomicUsize,
    /// INFORMACYJNE: data obecna, ale rok-widmo lub przyszłość.
    date_implausible_common: AtomicUsize, date_implausible_unique: AtomicUsize,
    /// INFORMACYJNE: plik nosi ślad przetworzenia narzędziem (pole Software).
    edited_common: AtomicUsize, edited_unique: AtomicUsize,

    total_duration_sec: AtomicU64,
    top_devices: Mutex<HashMap<String, usize>>,
    /// EKSPERYMENTALNE (Wariant A): śledzi zajętość logicznych slotów Rayon —
    /// ta sama konwencja i ten sam tracker, co w pozostałych fazach
    /// równoległych, patrz `thread_activity`.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
            processed_files: AtomicUsize::new(0), processed_bytes: AtomicU64::new(0), errors: AtomicUsize::new(0),
            ext_weights: Mutex::new(HashMap::new()), ok: AtomicUsize::new(0),
            engine_rs: AtomicUsize::new(0), engine_cli: AtomicUsize::new(0),
            last_engine: Mutex::new("exiftool-rs".to_string()),
            err_trunc_common: AtomicUsize::new(0), err_trunc_unique: AtomicUsize::new(0),
            err_nodim_common: AtomicUsize::new(0), err_nodim_unique: AtomicUsize::new(0),
            err_zerodim_common: AtomicUsize::new(0), err_zerodim_unique: AtomicUsize::new(0),
            err_mime_common: AtomicUsize::new(0), err_mime_unique: AtomicUsize::new(0), 
            err_trail_common: AtomicUsize::new(0), err_trail_unique: AtomicUsize::new(0),
            feat_gps_common: AtomicUsize::new(0), feat_gps_unique: AtomicUsize::new(0),
            feat_date_common: AtomicUsize::new(0), feat_date_unique: AtomicUsize::new(0),
            gps_suspicious_common: AtomicUsize::new(0), gps_suspicious_unique: AtomicUsize::new(0),
            date_implausible_common: AtomicUsize::new(0), date_implausible_unique: AtomicUsize::new(0),
            edited_common: AtomicUsize::new(0), edited_unique: AtomicUsize::new(0),
            total_duration_sec: AtomicU64::new(0), top_devices: Mutex::new(HashMap::new()),
        }
    }
}

/// Buduje pełny, samodzielny blok live DLA JEDNEGO ŹRÓDŁA — prędkość, top 3
/// rozszerzenia, aktualnie używany silnik WRAZ z licznikiem plików
/// przetworzonych dotąd przez każdy z nich (`RS: X | CLI: Y` — widać na żywo,
/// czy i jak często aktywuje się fallback CLI), zdrowe pliki, top 2 urządzenia,
/// cztery kategorie "twardych" błędów wspólne/unikalne, trzy kategorie
/// informacyjne (GPS podejrzany / data nieprawdopodobna / edytowane), błędy I/O.
///
/// Linia silnika używa znacznika inline `{G:...}`/`{R:...}` (patrz
/// `tui::scanner_panel::parse_colored_value`) — aktywny silnik i jego licznik
/// na zielono, nieaktywny na czerwono, więc widać na pierwszy rzut oka, która
/// ścieżka (natywna biblioteka czy fallback CLI) właśnie pracuje, bez
/// czytania liczb.
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

    let top_devices = {
        let map = stats.top_devices.lock().unwrap();
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        let s = sorted.into_iter().take(2).map(|(d, c)| format!("{} ({})", d, c)).collect::<Vec<_>>().join(", ");
        if s.is_empty() { "-".to_string() } else { s }
    };

    // Aktywny silnik na zielono, nieaktywny na czerwono - patrz docstring.
    let current_engine = stats.last_engine.lock().unwrap().clone();
    let (engine_name, rs_tag, cli_tag) = if current_engine == "RS" {
        ("{G:Exiftool-rs}", "{G:RS}", "{R:CLI}")
    } else {
        ("{G:Exiftool}", "{R:RS}", "{G:CLI}")
    };
    let engine_line = format!(
        "{} ({}: {} | {}: {})",
        engine_name, rs_tag, stats.engine_rs.load(Ordering::Relaxed), cli_tag, stats.engine_cli.load(Ordering::Relaxed)
    );

    format!(
        "[{}]\n \
        Prędkość: {:.2} MB/s\n \
        Top format: {}\n \
        Silnik aktualny: {}\n \
        Zdrowe: {}\n \
        Top urządzenia: {}\n \
        Ucięte: {} wspólne / {} unikalne\n \
        Brak wymiarów: {} wspólne / {} unikalne\n \
        Wymiary zerowe/1x1: {} wspólne / {} unikalne\n \
        Fałszywe MIME: {} wspólne / {} unikalne\n \
        Śmieci (trailer): {} wspólne / {} unikalne\n \
        GPS znaleziony: {} wspólne / {} unikalne\n \
        GPS podejrzany: {} wspólne / {} unikalne\n \
        Data znaleziona: {} wspólne / {} unikalne\n \
        Data nieprawdopodobna: {} wspólne / {} unikalne\n \
        Edytowane narzędziem: {} wspólne / {} unikalne\n \
        Wątki dekodowania (Wariant A): {}\n \
        Błędy I/O: {}",
        label, speed_mb,
        display_ext,
        engine_line,
        stats.ok.load(Ordering::Relaxed),
        top_devices,
        stats.err_trunc_common.load(Ordering::Relaxed),
        stats.err_trunc_unique.load(Ordering::Relaxed),
        stats.err_nodim_common.load(Ordering::Relaxed),
        stats.err_nodim_unique.load(Ordering::Relaxed),
        stats.err_zerodim_common.load(Ordering::Relaxed),
        stats.err_zerodim_unique.load(Ordering::Relaxed),
        stats.err_mime_common.load(Ordering::Relaxed),
        stats.err_mime_unique.load(Ordering::Relaxed),
        stats.err_trail_common.load(Ordering::Relaxed),
        stats.err_trail_unique.load(Ordering::Relaxed),
        stats.feat_gps_common.load(Ordering::Relaxed),
        stats.feat_gps_unique.load(Ordering::Relaxed),
        stats.gps_suspicious_common.load(Ordering::Relaxed),
        stats.gps_suspicious_unique.load(Ordering::Relaxed),
        stats.feat_date_common.load(Ordering::Relaxed),
        stats.feat_date_unique.load(Ordering::Relaxed),
        stats.date_implausible_common.load(Ordering::Relaxed),
        stats.date_implausible_unique.load(Ordering::Relaxed),
        stats.edited_common.load(Ordering::Relaxed),
        stats.edited_unique.load(Ordering::Relaxed),
        crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot()),
        stats.errors.load(Ordering::Relaxed),
    )
}

type ExtMap = HashMap<String, Vec<String>>;
struct SourceAnomalies { ufs: ExtMap, script: ExtMap }
impl SourceAnomalies { fn new() -> Self { Self { ufs: HashMap::new(), script: HashMap::new() } } }

struct AnomalyCategory {
    name: &'static str,
    icon: &'static str,
    common: SourceAnomalies, 
    unique: SourceAnomalies,
}
impl AnomalyCategory {
    fn new(name: &'static str, icon: &'static str) -> Self {
        Self { name, icon, common: SourceAnomalies::new(), unique: SourceAnomalies::new() }
    }
}

// ============================================================================
// SILNIK DECYZYJNY (NATYWNY RS Z FALLBACKIEM DO CLI)
// ============================================================================

/// Wczytuje metadane EXIF przez `exiftool-rs` (główny silnik, w procesie).
/// Jeśli zawiedzie lub zwróci pustą mapę, spada na zewnętrzny proces CLI
/// `exiftool -S -n -fast` (Fallback). Zwraca też etykietę użytego silnika
/// (`"RS"`/`"CLI"`) do telemetrii. Jedyna funkcja w tym module dotykająca I/O
/// poza samym odczytem pliku przez EXIF — cała logika decyzyjna żyje w
/// [`evaluate_metadata`], testowalnej bez rzeczywistego wywołania tej funkcji.
fn read_exif(path: &Path) -> std::result::Result<(HashMap<String, String>, String), String> {
    let path_str = path.to_str().unwrap_or("");
    let mut map = HashMap::new();
    let keys = [
        "Error",
        "Warning",
        "MIMEType",
        "ImageWidth",
        "ImageHeight", 
        "Make",
        "Model",
        "DateTimeOriginal",
        "CreateDate",
        "GPSLatitude", 
        "GPSPosition",
        "Duration",
        "Software"
    ];

    if let Ok(info) = exiftool_rs::image_info(path_str) {
        for k in keys {
            if let Some(v) = info.get(k) {
                let val_str = v.to_string().trim_matches('"').to_string();
                if !val_str.is_empty() && val_str != "null" {
                    map.insert(k.to_string(), val_str);
                }
            }
        }
        if !map.is_empty() {
            return Ok((map, "RS".to_string()));
        }
    }

    let cli_result = std::process::Command::new("exiftool")
        .args(["-S", "-n", "-fast", path_str])
        .output();
        
    if let Ok(output) = cli_result
        && output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some((k, v)) = line.split_once(": ") {
                    map.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
            if !map.is_empty() { return Ok((map, "CLI".to_string())); }
        }

    Err("Zupa binarna - ExifTool nie potrafił odczytać pliku".into())
}

/// Silnik decyzyjny — CZYSTA FUNKCJA (zero I/O), testowana wprost na ręcznie
/// skonstruowanych mapach metadanych. Kolejność sprawdzeń (pierwsze trafienie
/// unieważniające wygrywa):
///
/// 1. **Pusta mapa** → nierozpoznany format (zupa binarna).
/// 2. **Pole `Error`** → błąd krytyczny ExifTool.
/// 3. **Pole `Warning`** zawierające "truncated"/"corrupted"/"format error" →
///    ucięty plik; zawierające "trailer"/"garbage" → doklejone śmieci binarne.
/// 4. **Fałszywy MIME**: dla 6 rozszerzeń ze szczegółową regułą (jpg/png/mp4/
///    mkv/mov/heic) — dokładne dopasowanie; dla WSZYSTKICH pozostałych —
///    generyczny fallback przez [`mime_family_for_ext`] (rodzina image/video/
///    audio musi się zgadzać). To zamyka lukę, w której 20 z 26 rozszerzeń
///    na liście [`MEDIA_EXTS`] nie miało żadnej weryfikacji MIME wcześniej.
/// 5. **Brak wymiarów** dla pliku wizualnego (image/video) → zniszczony nagłówek.
/// 6. **Wymiary degeneracyjne** (0 lub 1x1, patrz [`is_dimension_degenerate`])
///    dla pliku wizualnego → też zniszczony nagłówek, osobna kategoria licznika.
///
/// Po tym punkcie plik jest ważny. Dodatkowo (informacyjnie, NIE unieważnia):
/// ekstrakcja urządzenia (Make+Model), daty, GPS + sanity-check GPS
/// ([`is_gps_suspicious`]) i daty ([`is_implausible_year`]), oraz wykrycie
/// narzędzia edycji (pole `Software`).
fn evaluate_metadata(meta: &HashMap<String, String>, ext: &str, current_year: i32) -> MediaAnalysis {
    let empty_analysis = |reason: &str, mime: &str| MediaAnalysis {
        is_valid: false, reason: Some(reason.to_string()), mime_type: mime.to_string(),
        dimensions: None, device: None, original_date: None, has_gps: false, duration_sec: 0,
        has_suspicious_gps: false, has_implausible_date: false, editing_software: None,
    };

    if meta.is_empty() {
        return empty_analysis("Nierozpoznany Format (Zupa Binarna)", "unknown");
    }

    if let Some(err) = meta.get("Error") {
        return empty_analysis(&format!("Błąd Krytyczny Exif: {}", err), "error");
    }

    if let Some(warning) = meta.get("Warning") {
        let w = warning.to_lowercase();
        if w.contains("truncated") || w.contains("corrupted") || w.contains("format error") {
            return empty_analysis("Ucięty Plik / Brak Ogona", "corrupted");
        }
        if w.contains("trailer") || w.contains("garbage") {
            return empty_analysis("Doklejone Śmieci Binarne (Trailer Data)", "corrupted");
        }
    }

    let mime_type = meta.get("MIMEType").cloned().unwrap_or_else(|| "unknown".to_string());

    let is_fake = match ext {
        "jpg" | "jpeg" => !mime_type.contains("jpeg"),
        "png" => !mime_type.contains("png"),
        "mp4" => !mime_type.contains("mp4"),
        "mkv" => !mime_type.contains("matroska") && !mime_type.contains("webm"),
        "mov" => !mime_type.contains("quicktime"),
        "heic" | "heif" => !mime_type.contains("heic") && !mime_type.contains("heif"),
        _ => {
            // Generyczny fallback: rodzina MIME musi się zgadzać z rozszerzeniem
            match mime_family_for_ext(ext) {
                Some(family) => mime_type != "unknown" && !mime_type.starts_with(family),
                None => false,
            }
        }
    };

    if is_fake {
        return MediaAnalysis {
            is_valid: false, reason: Some(format!("Fałszywe rozszerzenie (Wewnątrz to: {})", mime_type)),
            mime_type, dimensions: None, device: None, original_date: None, has_gps: false, duration_sec: 0,
            has_suspicious_gps: false, has_implausible_date: false, editing_software: None,
        };
    }

    let width = meta.get("ImageWidth");
    let height = meta.get("ImageHeight");
    let is_visual = mime_type.starts_with("image/") || mime_type.starts_with("video/");

    let dimensions = if let (Some(w), Some(h)) = (width, height) { Some(format!("{}x{}", w, h)) } else { None };

    if is_visual && dimensions.is_none() {
        return MediaAnalysis {
            is_valid: false, reason: Some("Zniszczony Nagłówek (Brak Wymiarów X/Y)".into()),
            mime_type, dimensions: None, device: None, original_date: None, has_gps: false, duration_sec: 0,
            has_suspicious_gps: false, has_implausible_date: false, editing_software: None,
        };
    }

    if is_visual
        && let (Some(w), Some(h)) = (width, height)
            && is_dimension_degenerate(w, h) {
                return MediaAnalysis {
                    is_valid: false, reason: Some("Zniszczony Nagłówek (Wymiary zerowe/1x1)".into()),
                    mime_type, dimensions, device: None, original_date: None, has_gps: false, duration_sec: 0,
                    has_suspicious_gps: false, has_implausible_date: false, editing_software: None,
                };
            }

    let make = meta.get("Make").map(|s| s.trim().to_string());
    let model = meta.get("Model").map(|s| s.trim().to_string());
    let device = if let (Some(ma), Some(mo)) = (&make, &model) {
        if mo.starts_with(ma.as_str()) { Some(mo.clone()) } else { Some(format!("{} {}", ma, mo)) }
    } else { make.or(model) };

    let original_date = meta.get("DateTimeOriginal").or(meta.get("CreateDate")).cloned();
    let has_implausible_date = original_date.as_deref()
        .and_then(extract_year)
        .map(|y| is_implausible_year(y, current_year))
        .unwrap_or(false);

    let has_gps = meta.get("GPSLatitude").is_some() || meta.get("GPSPosition").is_some();
    let has_suspicious_gps = if has_gps {
        let raw = meta.get("GPSPosition").or(meta.get("GPSLatitude")).map(|s| s.as_str()).unwrap_or("");
        let floats = parse_all_floats(raw);
        match (floats.first(), floats.get(1)) {
            (Some(&lat), Some(&lon)) => is_gps_suspicious(lat, lon),
            (Some(&lat), None) => !(-90.0..=90.0).contains(&lat),
            _ => false,
        }
    } else { false };

    let mut duration_sec = 0;
    if let Some(dur_str) = meta.get("Duration")
        && let Ok(d) = dur_str.parse::<f64>() { duration_sec = d as u64; }

    let editing_software = meta.get("Software").cloned();

    MediaAnalysis {
        is_valid: true, reason: None, mime_type, dimensions, device, original_date, has_gps, duration_sec,
        has_suspicious_gps, has_implausible_date, editing_software,
    }
}

/// Wrapper łączący I/O ([`read_exif`]) z czystą logiką ([`evaluate_metadata`]).
fn analyze_media(path: &Path) -> std::result::Result<(MediaAnalysis, String), String> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let (meta, engine) = read_exif(path)?;
    let current_year = 1970 + (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 31_557_600)
        .unwrap_or(0)) as i32;
    Ok((evaluate_metadata(&meta, &ext, current_year), engine))
}

/// Skanuje wszystkie zadania (`tasks`) dla JEDNEJ strony: dla każdego pliku
/// woła [`analyze_media`], aktualizuje liczniki [`LiveStats`] (twarde +
/// informacyjne niezależnie od siebie — patrz [`MediaAnalysis`]), zapisuje
/// wpis do jednego z dwóch logów i strumieniuje wynik do wątku zapisu SQLite.
/// Rozgłasza postęp i statystyki do UI co ~200 plików LUB co 250ms
/// (hybrydowy próg — wzorzec z Fazy 5-7/10/11).
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
    pub opr_log: Arc<Mutex<File>>,
    pub info_log: Arc<Mutex<File>>,
}

#[instrument(skip(ctx), fields(base_path = %ctx.base_path.display()))]

fn process_side_stream<'a>(ctx: StreamCtx<'a>) {
    let StreamCtx { base_path, tasks, side_label, stats, tx_db, is_ufs, start_time, tx_ui, bar_idx, opr_log, info_log } = ctx;

    tasks.par_chunks(CHUNK_SIZE).for_each_with(tx_db, |tx_db, chunk| {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

        let mut results = Vec::with_capacity(chunk.len());
        let mut local_ext_weights: HashMap<String, u64> = HashMap::new();
        let mut local_devices: HashMap<String, usize> = HashMap::new();
        let mut last_ui_update = Instant::now();

        for task in chunk {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }
            // Wariant A: slot zajęty na czas obsługi tego pliku. Strażnik RAII
            // zwalnia go także przy panice w środku pracy.
            let _slot = stats.thread_activity.enter_current();

            let full_path = base_path.join(&task.rel_path);
            let ext = Path::new(&task.rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
            let file_size = std::fs::metadata(&full_path).map(|m| m.len()).unwrap_or(0);
            
            *local_ext_weights.entry(ext.clone()).or_insert(0) += file_size;

            let (analysis_opt, engine_opt, io_err) = match analyze_media(&full_path) {
                Ok((ana, engine_used)) => {
                    let kategoria = if task.is_common { "Wspólne" } else { "Osobne" };

                    if engine_used == "RS" { 
                        stats.engine_rs.fetch_add(1, Ordering::Relaxed); 
                        *stats.last_engine.lock().unwrap() = "RS".to_string();
                    } else { 
                        stats.engine_cli.fetch_add(1, Ordering::Relaxed); 
                        *stats.last_engine.lock().unwrap() = "CLI".to_string();
                    }

                    if ana.is_valid {
                        stats.ok.fetch_add(1, Ordering::Relaxed);
                        stats.total_duration_sec.fetch_add(ana.duration_sec, Ordering::Relaxed);

                        if ana.has_gps { if task.is_common { stats.feat_gps_common.fetch_add(1, Ordering::Relaxed); } else { stats.feat_gps_unique.fetch_add(1, Ordering::Relaxed); } }
                        if ana.original_date.is_some() { if task.is_common { stats.feat_date_common.fetch_add(1, Ordering::Relaxed); } else { stats.feat_date_unique.fetch_add(1, Ordering::Relaxed); } }
                        
                        if let Some(dev) = &ana.device { *local_devices.entry(dev.clone()).or_insert(0) += 1; }

                        if let Ok(mut f) = info_log.lock() {
                            let dims = ana.dimensions.as_deref().unwrap_or("Brak");
                            let dev = ana.device.as_deref().unwrap_or("Nieznany_Aparat");
                            let date = ana.original_date.as_deref().unwrap_or("Brak_Daty");
                            let gps = if ana.has_gps { "GPS: TAK" } else { "GPS: NIE" };
                            let mime = &ana.mime_type;
                            
                            let _ = writeln!(f, "[{:<15}] [{:<7}] [Silnik: {:<3}] [Rozdz: {:<9} | Sprzęt: {:<15} | Data: {:<10} | {} | MIME: {:<10}] Format: .{:<4} | Ścieżka: \"{}\"", 
                                side_label, kategoria, engine_used, dims, dev, date, gps, mime, ext, full_path.display());
                        }
                    } else {
                        let r = ana.reason.as_deref().unwrap_or("Nieznany błąd");
                        
                        if r.contains("Ucięty") {
                            if task.is_common { stats.err_trunc_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_trunc_unique.fetch_add(1, Ordering::Relaxed); }
                        } else if r.contains("Brak Wymiarów") {
                            if task.is_common { stats.err_nodim_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_nodim_unique.fetch_add(1, Ordering::Relaxed); }
                        } else if r.contains("zerowe/1x1") {
                            if task.is_common { stats.err_zerodim_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_zerodim_unique.fetch_add(1, Ordering::Relaxed); }
                        } else if r.contains("Fałszywe") {
                            if task.is_common { stats.err_mime_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_mime_unique.fetch_add(1, Ordering::Relaxed); }
                        } else if r.contains("Śmieci") {
                            if task.is_common { stats.err_trail_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_trail_unique.fetch_add(1, Ordering::Relaxed); }
                        }

                        if let Ok(mut f) = opr_log.lock() {
                            let _ = writeln!(f, "[{:<15}] [{:<7}] [Silnik: {:<3}] [{}] Format: .{:<4} | Ścieżka: \"{}\"", 
                                side_label, kategoria, engine_used, r, ext, full_path.display());
                        }
                    }

                    // Liczniki INFORMACYJNE - niezależne od is_valid
                    if ana.has_suspicious_gps {
                        if task.is_common { stats.gps_suspicious_common.fetch_add(1, Ordering::Relaxed); } else { stats.gps_suspicious_unique.fetch_add(1, Ordering::Relaxed); }
                    }
                    if ana.has_implausible_date {
                        if task.is_common { stats.date_implausible_common.fetch_add(1, Ordering::Relaxed); } else { stats.date_implausible_unique.fetch_add(1, Ordering::Relaxed); }
                    }
                    if ana.editing_software.is_some() {
                        if task.is_common { stats.edited_common.fetch_add(1, Ordering::Relaxed); } else { stats.edited_unique.fetch_add(1, Ordering::Relaxed); }
                    }

                    (Some(ana), Some(engine_used), Some(false))
                },
                Err(e) => {
                    warn!(path = %task.rel_path, side = side_label, error = %e, "Błąd z ExifTool / I/O");
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    (None, None, Some(true))
                }
            };

            stats.processed_files.fetch_add(1, Ordering::Relaxed);
            stats.processed_bytes.fetch_add(file_size, Ordering::Relaxed);

            let current = stats.processed_files.load(Ordering::Relaxed);
            let now = Instant::now();

            // Hybrydowy próg (wzorzec z Fazy 5-7/10/11): licznik globalny jako
            // główny wyzwalacz, plus siatka bezpieczeństwa czasowa.
            let should_update = current.is_multiple_of(200)
                || now.duration_since(last_ui_update).as_millis() > 250;

            if should_update {
                last_ui_update = now; 

                if !local_ext_weights.is_empty() {
                    let mut global_map = stats.ext_weights.lock().unwrap();
                    for (k, v) in local_ext_weights.drain() { *global_map.entry(k).or_insert(0) += v; }
                }
                if !local_devices.is_empty() {
                    let mut global_dev = stats.top_devices.lock().unwrap();
                    for (k, v) in local_devices.drain() { *global_dev.entry(k).or_insert(0) += v; }
                }

                // PASEK: wyłącznie postęp + bieżący plik (bez liczników)
                let _ = tx_ui.send(PhaseEvent::UpdateBar {
                    idx: bar_idx,
                    current: current as u64,
                    message: format_display_path(&task.rel_path),
                });

                // PANEL BOCZNY: pełny, samodzielny blok TEGO źródła
                let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                    idx: bar_idx,
                    text: build_source_block(side_label, stats, start_time),
                });
            }

            results.push(SideMediaResult { id: task.id, analysis: analysis_opt, engine: engine_opt, io_error: io_err });
        }

        if !local_ext_weights.is_empty() {
            let mut global_map = stats.ext_weights.lock().unwrap();
            for (k, v) in local_ext_weights.drain() { *global_map.entry(k).or_insert(0) += v; }
        }
        if !local_devices.is_empty() {
            let mut global_dev = stats.top_devices.lock().unwrap();
            for (k, v) in local_devices.drain() { *global_dev.entry(k).or_insert(0) += v; }
        }

        if !results.is_empty() {
            if is_ufs { let _ = tx_db.send(ScanMsg::UfsChunk(results)); } 
            else { let _ = tx_db.send(ScanMsg::ScriptChunk(results)); }
        }
    });

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: stats.processed_files.load(Ordering::Relaxed) as u64,
        message: "Walidacja EXIF w 100% zakończona.".to_string(),
    });
}

// ============================================================================
// GŁÓWNA FUNKCJA KORDYNUJĄCA (Entrypoint)
// ============================================================================

/// Wylicza rozmiar prywatnej puli Rayon przypisywanej JEDNEJ stronie w trybie
/// `CONCURRENT` — patrz `phase3::compute_half_threads` dla pełnego uzasadnienia.
fn compute_half_threads(total_threads: usize) -> usize {
    std::cmp::max(1, total_threads / 2)
}

/// Punkt wejścia Fazy 12, wołany przez `menu::actions::run_phase_with_ui`.
///
/// Przebieg: (1) wczytuje z SQLite pliki multimedialne bez jeszcze wyliczonej
/// struktury EXIF; (2) uruchamia [`process_side_stream`] dla UFS i Skryptu —
/// równolegle na dwóch dedykowanych pulach Rayon lub sekwencyjnie; (3) koreluje
/// wyniki w SQLite; (4) buduje hierarchiczny Dziennik Końcowy z kategorii
/// błędów, listą top urządzeń i statystyką wykorzystanych silników (RS/CLI,
/// liczone bezwarunkowo dla OBU stron — patrz naprawiony bug w dokumentacji modułu).
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    let actual_threads = if config.max_threads > 0 { config.max_threads } else { rayon::current_num_threads() };
    let io_text = if config.io_mode == "CONCURRENT" { "RÓWNOLEGŁE (SSD/NVMe)" } else { "SEKWENCYJNIE (HDD)" };
    
    let _ = tx_ui.send(PhaseEvent::Log(format!("Uruchomiono Fazę 12. Metodyka szyny dyskowej: {}", io_text)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora: {}", actual_threads)));
    let _ = tx_ui.send(PhaseEvent::Log("Główny silnik EXIF: exiftool-rs (Zapasowo: systemowy exiftool CLI)".to_string()));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    // ZAPIS WYNIKÓW EXIF DO BAZY DANYCH (Optymalizacja pod Fazę 9: Smart Merge)
    let _ = conn.execute("ALTER TABLE files ADD COLUMN media_reason_ufs TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN media_reason_script TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN exif_engine_ufs TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN exif_engine_script TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN media_duration_ufs INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN media_duration_script INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN media_device_ufs TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN media_device_script TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN has_gps_ufs BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN has_gps_script BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN gps_suspicious_ufs BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN gps_suspicious_script BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN date_implausible_ufs BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN date_implausible_script BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN editing_software_ufs TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN editing_software_script TEXT", []);

    // INICJALIZACJA DUAL-LOGGING
    let raport_cfg = config.raporty_faz.get("Faza 12").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza12.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza12.txt".to_string(),
    });
    
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);
    let info_path = Path::new(&raport_cfg.katalog).join("raport_operacyjny_faza12_zdrowe_media.txt");

    let log_anom = Arc::new(Mutex::new(File::create(&opr_path).unwrap()));
    let log_info = Arc::new(Mutex::new(File::create(&info_path).unwrap()));
    
    {
        let mut f_anom = log_anom.lock().unwrap();
        let _ = writeln!(f_anom, "=== RAPORT OPERACYJNY - FAZA 12 (ZEPSUTE MULTIMEDIA) ===");
        let _ = writeln!(f_anom, "Zestawienie plików multimedialnych ze zniszczonymi nagłówkami lub fałszywym MIME.\n");
        
        let mut f_info = log_info.lock().unwrap();
        let _ = writeln!(f_info, "=== RAPORT OPERACYJNY - FAZA 12 (ZDROWE MULTIMEDIA) ===");
        let _ = writeln!(f_info, "Ekstrakcja śledcza: Oryginalne daty z przeszłości, Koordynaty GPS i Typy Kamery.\n");
    }

    // --- ETAP 1: POBIERANIE ZADAŃ Z BAZY ---
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, exif_ok_ufs, exif_ok_script, io_error_ufs, io_error_script 
         FROM files WHERE phase12_done = 0 OR phase12_done IS NULL"
    )?;
    
    let mut ufs_tasks = Vec::new();
    let mut script_tasks = Vec::new();
    let mut skipped_ufs = 0;
    let mut skipped_script = 0;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i32>(0)?, row.get::<_, String>(1)?, row.get::<_, bool>(2)?, row.get::<_, bool>(3)?,
            row.get::<_, Option<bool>>(4)?, row.get::<_, Option<bool>>(5)?, row.get::<_, Option<bool>>(6)?, row.get::<_, Option<bool>>(7)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_ufs, in_script, ok_ufs, ok_scr, err_ufs, err_scr) = r;
        
        if is_media_extension(&rel) {
            let is_common = in_ufs && in_script;
            if in_ufs {
                if ok_ufs.is_none() && err_ufs != Some(true) { ufs_tasks.push(Task { id, rel_path: rel.clone(), is_common }); } 
                else { skipped_ufs += 1; }
            }
            if in_script {
                if ok_scr.is_none() && err_scr != Some(true) { script_tasks.push(Task { id, rel_path: rel, is_common }); } 
                else { skipped_script += 1; }
            }
        }
    }
    drop(stmt);

    if skipped_ufs > 0 || skipped_script > 0 {
        let _ = tx_ui.send(PhaseEvent::Log(format!("Pominięto multimedia z wyliczoną już strukturą EXIF. UFS: {}, Skrypt: {}", skipped_ufs, skipped_script)));
    }

    let total_db_rows = ufs_tasks.len() + script_tasks.len();
    if total_db_rows == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak multimediów do walidacji. Baza aktualna.".to_string()));
        return Ok(());
    }

    // Inicjalizacja pasków postępu Ratatui
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "UFS Explorer (EXIF)".to_string(), total: ufs_tasks.len() as u64, color: Color::Cyan });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 1, label: "Skrypt Autorski (EXIF)".to_string(), total: script_tasks.len() as u64, color: Color::Magenta });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 2, label: "Zapis SQLite".to_string(), total: total_db_rows as u64, color: Color::Green });

    let ufs_stats = LiveStats::new(rayon::current_num_threads());
    let script_stats = LiveStats::new(rayon::current_num_threads());
    let ufs_base = PathBuf::from(&config.ufs_path);
    let script_base = PathBuf::from(&config.script_path);

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
                        let mut stmt = match &msg {
                            ScanMsg::UfsChunk(_) => tx_trans.prepare_cached(
                                "UPDATE files SET exif_ok_ufs = COALESCE(?1, exif_ok_ufs), media_reason_ufs = COALESCE(?2, media_reason_ufs), exif_engine_ufs = COALESCE(?3, exif_engine_ufs), media_duration_ufs = COALESCE(?4, media_duration_ufs), media_device_ufs = COALESCE(?5, media_device_ufs), has_gps_ufs = COALESCE(?6, has_gps_ufs), gps_suspicious_ufs = COALESCE(?7, gps_suspicious_ufs), date_implausible_ufs = COALESCE(?8, date_implausible_ufs), editing_software_ufs = COALESCE(?9, editing_software_ufs), io_error_ufs = COALESCE(?10, io_error_ufs) WHERE id = ?11"
                            ).unwrap(),
                            ScanMsg::ScriptChunk(_) => tx_trans.prepare_cached(
                                "UPDATE files SET exif_ok_script = COALESCE(?1, exif_ok_script), media_reason_script = COALESCE(?2, media_reason_script), exif_engine_script = COALESCE(?3, exif_engine_script), media_duration_script = COALESCE(?4, media_duration_script), media_device_script = COALESCE(?5, media_device_script), has_gps_script = COALESCE(?6, has_gps_script), gps_suspicious_script = COALESCE(?7, gps_suspicious_script), date_implausible_script = COALESCE(?8, date_implausible_script), editing_software_script = COALESCE(?9, editing_software_script), io_error_script = COALESCE(?10, io_error_script) WHERE id = ?11"
                            ).unwrap(),
                        };
                        
                        let chunk = match &msg {
                            ScanMsg::UfsChunk(c) => c,
                            ScanMsg::ScriptChunk(c) => c,
                        };

                        for res in chunk {
                            if res.analysis.is_some() || res.io_error == Some(true) {
                                let (ok, reason, dur, dev, gps, gps_susp, date_impl, software) = match &res.analysis {
                                    Some(a) => (
                                        Some(a.is_valid), a.reason.clone(), Some(a.duration_sec as i64), a.device.clone(),
                                        Some(a.has_gps), Some(a.has_suspicious_gps), Some(a.has_implausible_date), a.editing_software.clone(),
                                    ),
                                    None => (None, None, None, None, None, None, None, None)
                                };
                                stmt.execute(params![ok, reason, res.engine, dur, dev, gps, gps_susp, date_impl, software, res.io_error, res.id]).unwrap();
                            }
                        }
                    }
                    tx_trans.commit().unwrap();
                }

                db_inserted += chunk_len;
                let now = Instant::now();
                if now.duration_since(last_db_update).as_millis() > 60 {
                    last_db_update = now;
                    let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Zapisywanie znaczników EXIF...".to_string() });
                }
            }
            let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Wskaźniki EXIF bezpieczne w SQLite.".to_string() });
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone(); let tx2 = tx_db.clone();
            let anom_u = log_anom.clone(); let anom_s = log_anom.clone();
            let info_u = log_info.clone(); let info_s = log_info.clone();

            let stat_u = &ufs_stats;
            let stat_s = &script_stats;

            // NAPRAWA (ten sam bug jak w Fazie 5/6/7/10/11): dedykowana pula
            // per strona, minimum 1 wątek.
            let half_threads = compute_half_threads(actual_threads);

            s.spawn(move || {
                if !ufs_tasks.is_empty() { 
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, start_time, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: anom_u, info_log: info_u, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, start_time, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: anom_u, info_log: info_u, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Walidacja EXIF (UFS) zakończona.".to_string())); 
                }
            });

            s.spawn(move || {
                if !script_tasks.is_empty() { 
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, start_time, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: anom_s, info_log: info_s, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, start_time, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: anom_s, info_log: info_s, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Walidacja EXIF (Skrypt) zakończona.".to_string())); 
                }
            });
            drop(tx_db);

        } 
            else
        {
            let anom_u = log_anom.clone(); let anom_s = log_anom.clone();
            let info_u = log_info.clone(); let info_s = log_info.clone();
            
            if !ufs_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: &ufs_stats, tx_db: tx_db.clone(), is_ufs: true, start_time, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: anom_u, info_log: info_u, }); let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Walidacja EXIF (UFS) zakończona.".to_string()));
            }
            if !script_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: &script_stats, tx_db: tx_db.clone(), is_ufs: false, start_time, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: anom_s, info_log: info_s, }); let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Walidacja EXIF (Skrypt) zakończona.".to_string()));
            }
            drop(tx_db);
        }
    });

    // --- ETAP 4: SYNCHRONIZACJA Z BAZĄ DANYCH ---
    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log("🛑 Skanowanie przerwane przez użytkownika.".to_string()));
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::Log("Trwa generowanie hierarchicznego raportu kryminalistycznego...".to_string()));
    
    conn.execute(
        "UPDATE files SET phase12_done = CASE 
            WHEN (found_in_ufs = 0 OR exif_ok_ufs IS NOT NULL OR io_error_ufs = 1) 
             AND (found_in_script = 0 OR exif_ok_script IS NOT NULL OR io_error_script = 1) THEN 1 
            ELSE 0 
        END WHERE phase12_done = 0 OR phase12_done IS NULL", []
    )?;

    // --- ETAP 5: HIERARCHICZNY RAPORT KRYMINALISTYCZNY ---
    let mut stmt = conn.prepare(
        "SELECT relative_path, found_in_ufs, found_in_script, 
                exif_ok_ufs, exif_ok_script, media_reason_ufs, media_reason_script,
                exif_engine_ufs, exif_engine_script
         FROM files WHERE phase12_done = 1"
    )?;

    let mut cat_trunc = AnomalyCategory::new("Ucięte Wideo / Zniszczony Nagłówek Obrazu", "✂️");
    let mut cat_fake = AnomalyCategory::new("Fałszywe Rozszerzenia (Niezgodność MIME Type)", "🧬");
    let mut cat_trail = AnomalyCategory::new("Doklejone Śmieci Binarne (Trailer Garbage)", "🗑️");

    // NAPRAWA: obie strony liczone bezwarunkowo i niezależnie - każda strona
    // ma WŁASNY wynik silnika dla WŁASNEJ kopii pliku, nie jest to to samo
    // zdarzenie liczone podwójnie. Poprzedni warunek (`if in_scr && !is_common
    // else if ... && !in_ufs`) miał martwą gałąź dla plików wspólnych.
    let mut total_engine_rs = 0;
    let mut total_engine_cli = 0;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?, row.get::<_, bool>(1)?, row.get::<_, bool>(2)?,
            row.get::<_, Option<bool>>(3)?, row.get::<_, Option<bool>>(4)?,
            row.get::<_, Option<String>>(5)?, row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?, row.get::<_, Option<String>>(8)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (rel_path, in_ufs, in_scr, u_ufs, u_scr, reason_ufs, reason_scr, eng_ufs, eng_scr) = r;
        let is_common = in_ufs && in_scr;
        let ext = Path::new(&rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();

        if in_ufs
            && let Some(e) = eng_ufs { if e == "RS" { total_engine_rs += 1; } else if e == "CLI" { total_engine_cli += 1; } }
        if in_scr
            && let Some(e) = eng_scr { if e == "RS" { total_engine_rs += 1; } else if e == "CLI" { total_engine_cli += 1; } }

        let add_to_cat = |cat: &mut AnomalyCategory, is_ufs_source: bool| {
            let target = if is_common { &mut cat.common } else { &mut cat.unique };
            let map = if is_ufs_source { &mut target.ufs } else { &mut target.script };
            map.entry(ext.clone()).or_default().push(rel_path.clone());
        };

        let mut process_reason = |ok: Option<bool>, reason: Option<String>, is_ufs_source: bool| {
            if ok == Some(false) {
                if let Some(r) = reason {
                    if r.contains("Fałszywe") { add_to_cat(&mut cat_fake, is_ufs_source); }
                    else if r.contains("Śmieci") { add_to_cat(&mut cat_trail, is_ufs_source); }
                    else { add_to_cat(&mut cat_trunc, is_ufs_source); }
                } else {
                    add_to_cat(&mut cat_trunc, is_ufs_source);
                }
            }
        };

        if in_ufs { process_reason(u_ufs, reason_ufs, true); }
        if in_scr { process_reason(u_scr, reason_scr, false); }
    }
    drop(stmt);

    let elapsed = start_time.elapsed();
    let total_bytes = ufs_stats.processed_bytes.load(Ordering::SeqCst) + script_stats.processed_bytes.load(Ordering::SeqCst);
    let avg_speed_mb = (total_bytes as f64 / 1_048_576.0) / elapsed.as_secs_f64().max(1.0);
    let total_io_errors = ufs_stats.errors.load(Ordering::SeqCst) + script_stats.errors.load(Ordering::SeqCst);

    // -- GENEROWANIE RAPORTU TEKSTOWEGO --
    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(&mut log_out, "==========================================================================");
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 12 (METADANE EXIF / HEIF / MP4)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "Sumaryczny transfer I/O: {} (Średnia prędkość: {:.2} MB/s)", format_bytes(total_bytes), avg_speed_mb);
    let _ = writeln!(&mut log_out, "==========================================================================\n");

    let sum_duration = format_duration(ufs_stats.total_duration_sec.load(Ordering::SeqCst) + script_stats.total_duration_sec.load(Ordering::SeqCst));
    
    let _ = writeln!(&mut log_out, "[ 1 ] WYDOBYTE DOWODY (Tylko w 100% sprawne pliki multimedialne):");
    let _ = writeln!(&mut log_out, "   -> Odnaleziono koordynaty GPS w:  {} plikach", ufs_stats.feat_gps_common.load(Ordering::SeqCst) + script_stats.feat_gps_common.load(Ordering::SeqCst) + ufs_stats.feat_gps_unique.load(Ordering::SeqCst) + script_stats.feat_gps_unique.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "   -> ...z czego geograficznie podejrzanych (poza zakresem/Null Island): {}", ufs_stats.gps_suspicious_common.load(Ordering::SeqCst) + script_stats.gps_suspicious_common.load(Ordering::SeqCst) + ufs_stats.gps_suspicious_unique.load(Ordering::SeqCst) + script_stats.gps_suspicious_unique.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "   -> Zrekonstruowano Daty w:        {} plikach", ufs_stats.feat_date_common.load(Ordering::SeqCst) + script_stats.feat_date_common.load(Ordering::SeqCst) + ufs_stats.feat_date_unique.load(Ordering::SeqCst) + script_stats.feat_date_unique.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "   -> ...z czego nieprawdopodobnych (rok-widmo/przyszłość): {}", ufs_stats.date_implausible_common.load(Ordering::SeqCst) + script_stats.date_implausible_common.load(Ordering::SeqCst) + ufs_stats.date_implausible_unique.load(Ordering::SeqCst) + script_stats.date_implausible_unique.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "   -> Pliki edytowane narzędziem (Software): {}", ufs_stats.edited_common.load(Ordering::SeqCst) + script_stats.edited_common.load(Ordering::SeqCst) + ufs_stats.edited_unique.load(Ordering::SeqCst) + script_stats.edited_unique.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "   -> Sumaryczny Czas Trwania Wideo: {}", sum_duration);
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Algorytm Smart Merge w kolejnej Fazie weźmie te wskaźniki pod uwagę, wybierając kopię wideo o najdłuższym czasie trwania i zachowanym GPS-ie.\n");

    let write_section_txt = |out: &mut String, title: &str, is_common: bool| {
        let _ = writeln!(out, "[ KATEGORIA BŁĘDÓW: {} ]", title);
        let categories = [&cat_trunc, &cat_fake, &cat_trail];
        let mut has_any = false;

        for cat in &categories {
            let src_anom = if is_common { &cat.common } else { &cat.unique };
            let ufs_total: usize = src_anom.ufs.values().map(|v| v.len()).sum();
            let scr_total: usize = src_anom.script.values().map(|v| v.len()).sum();
            
            if ufs_total > 0 || scr_total > 0 {
                has_any = true;
                let _ = writeln!(out, "   {} Typ anomalii: {} (UFS: {}, Skrypt: {})", cat.icon, cat.name, ufs_total, scr_total);
                if cat.name.contains("Ucięte") {
                    let _ = writeln!(out, "      [ ZNACZENIE ]: Plik stracił swój nagłówek definiujący rozdzielczość, lub środek wideo uległ fragmentacji. Plik po uruchomieniu zawiesi odtwarzacz.");
                } else if cat.name.contains("Fałszywe") {
                    let _ = writeln!(out, "      [ ZNACZENIE ]: Program do odzyskiwania mylnie rozpoznał początek i nadał mu złe rozszerzenie. (Np. Wideo .mov zapisane jako .mp4, lub zdjęcie webp jako jpg).");
                } else if cat.name.contains("Doklejone") {
                    let _ = writeln!(out, "      [ ZNACZENIE ]: Na samym końcu pliku skaner znalazł tzw. 'Trailer Garbage'. Są to najczęściej doklejone śmieci binarne pochodzące z innej partycji dysku.");
                }

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

    write_section_txt(&mut log_out, "Część Wspólna (Oba źródła)", true);
    write_section_txt(&mut log_out, "Osobne ścieżki (Unikalne dla jednego źródła)", false);

    let devs = ufs_stats.top_devices.lock().unwrap();
    if !devs.is_empty() {
        let _ = writeln!(&mut log_out, "[ TOP 5 URZĄDZEŃ W ZABEZPIECZONYCH ZDJĘCIACH ]");
        let mut sorted_devs: Vec<_> = devs.iter().collect();
        sorted_devs.sort_by(|a, b| b.1.cmp(a.1));
        for (dev, count) in sorted_devs.into_iter().take(5) {
            let _ = writeln!(&mut log_out, "   - {:<25} -> {} plików", dev, count);
        }
        let _ = writeln!(&mut log_out);
    }

    let _ = writeln!(&mut log_out, "[ WYKORZYSTANE SILNIKI PARSUJĄCE ]");
    let _ = writeln!(&mut log_out, "   -> Biblioteka natywna exiftool-rs: {} plików zdekodowanych w RAM", total_engine_rs);
    let _ = writeln!(&mut log_out, "   -> Zapasowy proces CLI (exiftool): {} plików odczytanych awaryjnie\n", total_engine_cli);

    if total_io_errors > 0 {
        let _ = writeln!(&mut log_out, "[ 🚨 BŁĘDY FIZYCZNE I/O ]");
        let _ = writeln!(&mut log_out, "   -> Błędy odczytu (I/O): {}", total_io_errors);
    }

    if let Ok(mut f) = fs::File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano fizyczny Dziennik Końcowy w: {}", dz_path.display())));
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano Raporty Operacyjne (Live) w: {} oraz {}", opr_path.display(), info_path.display())));
    }

    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    info!(
        total_io_errors, total_engine_rs, total_engine_cli,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 12 zakończona"
    );

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT_YEAR: i32 = 2026;

    fn meta_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    // ------------------------------------------------------------------
    // is_media_extension / format_duration
    // ------------------------------------------------------------------

    #[test]
    fn test_is_media_extension() {
        assert!(is_media_extension("zdjecie.JPG"));
        assert!(is_media_extension("nagranie.mp4"));
        assert!(!is_media_extension("dokument.pdf"));
    }

    #[test]
    fn test_format_duration_variants() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(125), "2m 5s");
        assert_eq!(format_duration(3725), "1h 2m 5s");
        assert_eq!(format_duration(0), "0s");
    }

    // ------------------------------------------------------------------
    // mime_family_for_ext
    // ------------------------------------------------------------------

    #[test]
    fn test_mime_family_known() {
        assert_eq!(mime_family_for_ext("webp"), Some("image"));
        assert_eq!(mime_family_for_ext("avi"), Some("video"));
        assert_eq!(mime_family_for_ext("flac"), Some("audio"));
    }

    #[test]
    fn test_mime_family_unknown_returns_none() {
        assert_eq!(mime_family_for_ext("xyz"), None);
    }

    // ------------------------------------------------------------------
    // is_dimension_degenerate
    // ------------------------------------------------------------------

    #[test]
    fn test_dimension_degenerate_zero() {
        assert!(is_dimension_degenerate("0", "1080"));
        assert!(is_dimension_degenerate("1920", "0"));
    }

    #[test]
    fn test_dimension_degenerate_1x1() {
        assert!(is_dimension_degenerate("1", "1"));
    }

    #[test]
    fn test_dimension_normal_not_degenerate() {
        assert!(!is_dimension_degenerate("1920", "1080"));
        assert!(!is_dimension_degenerate("1", "1080")); // 1xN to nie 1x1, to normalny wąski obraz
    }

    #[test]
    fn test_dimension_unparseable_not_degenerate() {
        assert!(!is_dimension_degenerate("abc", "1080"));
    }

    // ------------------------------------------------------------------
    // parse_all_floats / is_gps_suspicious
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_all_floats_various_formats() {
        assert_eq!(parse_all_floats("52.2297"), vec![52.2297]);
        assert_eq!(parse_all_floats("52.2297, 21.0122"), vec![52.2297, 21.0122]);
        assert_eq!(parse_all_floats("52.2297 N"), vec![52.2297]);
    }

    #[test]
    fn test_gps_null_island_is_suspicious() {
        assert!(is_gps_suspicious(0.0, 0.0));
    }

    #[test]
    fn test_gps_out_of_range_is_suspicious() {
        assert!(is_gps_suspicious(95.0, 20.0));
        assert!(is_gps_suspicious(45.0, 200.0));
    }

    #[test]
    fn test_gps_normal_coordinates_not_suspicious() {
        assert!(!is_gps_suspicious(52.2297, 21.0122)); // Warszawa
    }

    // ------------------------------------------------------------------
    // extract_year / is_implausible_year
    // ------------------------------------------------------------------

    #[test]
    fn test_extract_year_colon_format() {
        assert_eq!(extract_year("2023:05:14 10:30:00"), Some(2023));
    }

    #[test]
    fn test_extract_year_dash_format() {
        assert_eq!(extract_year("2023-05-14"), Some(2023));
    }

    #[test]
    fn test_implausible_year_sentinels() {
        assert!(is_implausible_year(0, CURRENT_YEAR));
        assert!(is_implausible_year(1900, CURRENT_YEAR));
        assert!(is_implausible_year(1904, CURRENT_YEAR));
    }

    #[test]
    fn test_implausible_year_future() {
        assert!(is_implausible_year(CURRENT_YEAR + 1, CURRENT_YEAR));
    }

    #[test]
    fn test_plausible_year_not_implausible() {
        assert!(!is_implausible_year(2023, CURRENT_YEAR));
        assert!(!is_implausible_year(1999, CURRENT_YEAR));
    }

    // ------------------------------------------------------------------
    // evaluate_metadata: przypadki unieważniające
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_empty_meta_is_unknown_format() {
        let meta = meta_map(&[]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("Nierozpoznany"));
    }

    #[test]
    fn test_evaluate_error_field_is_critical() {
        let meta = meta_map(&[("Error", "File is empty")]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("Błąd Krytyczny"));
    }

    #[test]
    fn test_evaluate_warning_truncated() {
        let meta = meta_map(&[("MIMEType", "image/jpeg"), ("Warning", "File format error - truncated")]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("Ucięty"));
    }

    #[test]
    fn test_evaluate_warning_trailer_garbage() {
        let meta = meta_map(&[("MIMEType", "image/jpeg"), ("Warning", "Trailer data after JPEG EOI")]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("Śmieci"));
    }

    #[test]
    fn test_evaluate_fake_jpg_explicit_rule() {
        let meta = meta_map(&[("MIMEType", "video/mp4"), ("ImageWidth", "100"), ("ImageHeight", "100")]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("Fałszywe"));
    }

    #[test]
    fn test_evaluate_fake_via_generic_family_fallback() {
        // .webp bez szczegółowej reguły, ale rodzina "image" nie zgadza się z audio/mpeg
        let meta = meta_map(&[("MIMEType", "audio/mpeg")]);
        let a = evaluate_metadata(&meta, "webp", CURRENT_YEAR);
        assert!(!a.is_valid, "Generyczny fallback rodziny MIME powinien złapać tę niezgodność");
        assert!(a.reason.unwrap().contains("Fałszywe"));
    }

    #[test]
    fn test_evaluate_generic_family_fallback_passes_when_matching() {
        let meta = meta_map(&[("MIMEType", "image/webp"), ("ImageWidth", "800"), ("ImageHeight", "600")]);
        let a = evaluate_metadata(&meta, "webp", CURRENT_YEAR);
        assert!(a.is_valid);
    }

    #[test]
    fn test_evaluate_missing_dimensions_for_visual_file() {
        let meta = meta_map(&[("MIMEType", "image/jpeg")]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("Brak Wymiarów"));
    }

    #[test]
    fn test_evaluate_degenerate_dimensions_for_visual_file() {
        let meta = meta_map(&[("MIMEType", "image/jpeg"), ("ImageWidth", "1"), ("ImageHeight", "1")]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("zerowe/1x1"));
    }

    #[test]
    fn test_evaluate_missing_dimensions_not_checked_for_audio() {
        // Audio nie jest "wizualne" - brak wymiarów nie unieważnia
        let meta = meta_map(&[("MIMEType", "audio/mpeg")]);
        let a = evaluate_metadata(&meta, "mp3", CURRENT_YEAR);
        assert!(a.is_valid);
    }

    // ------------------------------------------------------------------
    // evaluate_metadata: plik w pełni poprawny + ekstrakcja dowodów
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_valid_file_full_extraction() {
        let meta = meta_map(&[
            ("MIMEType", "image/jpeg"),
            ("ImageWidth", "4032"), ("ImageHeight", "3024"),
            ("Make", "Apple"), ("Model", "iPhone 13"),
            ("DateTimeOriginal", "2023:06:15 14:30:00"),
            ("GPSPosition", "52.2297, 21.0122"),
        ]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert!(a.is_valid);
        assert_eq!(a.dimensions, Some("4032x3024".to_string()));
        assert_eq!(a.device, Some("Apple iPhone 13".to_string()));
        assert!(a.has_gps);
        assert!(!a.has_suspicious_gps);
        assert!(!a.has_implausible_date);
    }

    #[test]
    fn test_evaluate_device_model_already_contains_make_no_duplication() {
        let meta = meta_map(&[
            ("MIMEType", "image/jpeg"), ("ImageWidth", "100"), ("ImageHeight", "100"),
            ("Make", "Canon"), ("Model", "Canon EOS 90D"),
        ]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert_eq!(a.device, Some("Canon EOS 90D".to_string()), "Model już zawiera Make - nie powinno się dublować");
    }

    #[test]
    fn test_evaluate_device_from_model_only() {
        let meta = meta_map(&[
            ("MIMEType", "image/jpeg"), ("ImageWidth", "100"), ("ImageHeight", "100"),
            ("Model", "Pixel 7"),
        ]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert_eq!(a.device, Some("Pixel 7".to_string()));
    }

    #[test]
    fn test_evaluate_suspicious_gps_flagged_but_still_valid() {
        let meta = meta_map(&[
            ("MIMEType", "image/jpeg"), ("ImageWidth", "100"), ("ImageHeight", "100"),
            ("GPSPosition", "0.0, 0.0"),
        ]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert!(a.is_valid, "Podejrzany GPS jest informacyjny, nie unieważnia pliku");
        assert!(a.has_gps);
        assert!(a.has_suspicious_gps);
    }

    #[test]
    fn test_evaluate_implausible_date_flagged_but_still_valid() {
        let meta = meta_map(&[
            ("MIMEType", "image/jpeg"), ("ImageWidth", "100"), ("ImageHeight", "100"),
            ("DateTimeOriginal", "1900:01:01 00:00:00"),
        ]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert!(a.is_valid);
        assert!(a.has_implausible_date);
    }

    #[test]
    fn test_evaluate_editing_software_detected_informationally() {
        let meta = meta_map(&[
            ("MIMEType", "image/jpeg"), ("ImageWidth", "100"), ("ImageHeight", "100"),
            ("Software", "Adobe Photoshop 24.0"),
        ]);
        let a = evaluate_metadata(&meta, "jpg", CURRENT_YEAR);
        assert!(a.is_valid);
        assert_eq!(a.editing_software, Some("Adobe Photoshop 24.0".to_string()));
    }

    #[test]
    fn test_evaluate_duration_parsed_for_video() {
        let meta = meta_map(&[
            ("MIMEType", "video/mp4"), ("Duration", "125.5"),
            ("ImageWidth", "1920"), ("ImageHeight", "1080"),
        ]);
        let a = evaluate_metadata(&meta, "mp4", CURRENT_YEAR);
        assert!(a.is_valid);
        assert_eq!(a.duration_sec, 125);
    }

    // ------------------------------------------------------------------
    // build_source_block / compute_half_threads
    // ------------------------------------------------------------------

    #[test]
    fn test_build_source_block_reports_new_counters() {
        use std::time::Duration;
        let stats = LiveStats::new(rayon::current_num_threads());
        stats.err_zerodim_common.store(2, Ordering::Relaxed);
        stats.gps_suspicious_unique.store(1, Ordering::Relaxed);
        stats.date_implausible_common.store(3, Ordering::Relaxed);
        stats.edited_unique.store(4, Ordering::Relaxed);

        let start_time = Instant::now() - Duration::from_secs(1);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        assert!(block.contains("Wymiary zerowe/1x1: 2 wspólne / 0 unikalne"));
        assert!(block.contains("GPS podejrzany: 0 wspólne / 1 unikalne"));
        assert!(block.contains("Data nieprawdopodobna: 3 wspólne / 0 unikalne"));
        assert!(block.contains("Edytowane narzędziem: 0 wspólne / 4 unikalne"));
    }

    #[test]
    fn test_build_source_block_shows_current_engine_and_per_engine_counts() {
        let stats = LiveStats::new(rayon::current_num_threads());
        stats.engine_rs.store(15, Ordering::Relaxed);
        stats.engine_cli.store(3, Ordering::Relaxed);
        *stats.last_engine.lock().unwrap() = "CLI".to_string();

        let start_time = Instant::now();
        let block = build_source_block("Skrypt Autorski", &stats, start_time);

        // CLI aktywne: Exiftool i CLI na zielono, RS na czerwono (patrz docstring build_source_block)
        assert!(block.contains("Silnik aktualny: {G:Exiftool} ({R:RS}: 15 | {G:CLI}: 3)"));
    }

    #[test]
    fn test_build_source_block_rs_active_colors_rs_green() {
        let stats = LiveStats::new(rayon::current_num_threads());
        stats.engine_rs.store(8, Ordering::Relaxed);
        stats.engine_cli.store(0, Ordering::Relaxed);
        *stats.last_engine.lock().unwrap() = "RS".to_string();

        let start_time = Instant::now();
        let block = build_source_block("UFS Explorer", &stats, start_time);

        // RS aktywne: Exiftool-rs i RS na zielono, CLI na czerwono
        assert!(block.contains("Silnik aktualny: {G:Exiftool-rs} ({G:RS}: 8 | {R:CLI}: 0)"));
    }

    #[test]
    fn test_compute_half_threads() {
        assert_eq!(compute_half_threads(8), 4);
        assert_eq!(compute_half_threads(1), 1);
    }

    /// Konwencja „(Wariant A)" musi być identyczna we WSZYSTKICH fazach
    /// równoległych — ułatwia maszynowe parsowanie panelu i utrzymuje spójność
    /// wizualną. Ten test utrwala ją dla tej fazy.
    #[test]
    fn test_blok_zawiera_znacznik_aktywnosci_watkow() {
        let stats = LiveStats::new(2);
        stats.thread_activity.mark_busy(1);

        let block = build_source_block("UFS Explorer", &stats, Instant::now());

        let line = block
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("Wątki dekodowania"))
            .unwrap_or_else(|| panic!("brak linii Wariantu A w bloku:\n{}", block));

        assert_eq!(line, "Wątki dekodowania (Wariant A): {R:1} {G:2}");
    }

}
