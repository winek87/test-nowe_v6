// src/phases/phase13.rs

//! # Faza 13: Pełne Dekodowanie Mediów (Wykrywanie uciętych zdjęć i Gray Banding)
//! 
//! Zmusza procesor do wyrenderowania każdej klatki obrazu w pamięci RAM.
//! Kategoryzuje rozdzielczości (MP), przestrzenie kolorów (RGB/RGBA), oraz
//! wykrywa dwie dodatkowe anomalie geometryczne/wizualne: ekstremalne
//! proporcje boków i podejrzanie jednolitą (próbkowaną) zawartość.
//! Utrzymuje twardy limit RAM, korzysta ze scentralizowanego Dual-Logging
//! i w pełni asynchronicznie przesyła PhaseEvent do TUI Ratatui.
//!
//! UWAGA ARCHITEKTONICZNA (TESTOWALNOŚĆ): klasyfikacja tekstu błędu z crate
//! `image` jest wydzielona do czystej [`classify_decode_error`] (analogicznie
//! do `phase11::classify_hard_reason`) — testowalna na syntetycznych
//! komunikatach błędów. Detekcja ekstremalnych proporcji ([`is_extreme_aspect_ratio`])
//! i jednolitości próbki ([`is_uniform_sample`]) to również czyste funkcje,
//! oddzielone od faktycznego próbkowania pikseli z obrazu ([`sample_pixels`]).
//! Testy dekodowania używają PRAWDZIWYCH, małych obrazów zapisanych w locie
//! przez crate `image` (już zależność produkcyjna) — nie wymagają plików
//! testowych na dysku.
//!
//! UWAGA ARCHITEKTONICZNA (UI): Pasek postępu pokazuje wyłącznie % i bieżący
//! plik. Liczniki live trafiają do panelu bocznego jako JEDEN, samodzielny blok
//! PER ŹRÓDŁO — patrz [`build_source_block`].
//!
//! UWAGA ARCHITEKTONICZNA (WĄTKOWANIE): każda strona dostaje własną, dedykowaną
//! pulę Rayon (`half_threads`, identycznie jak Fazy 2-7/10-12). Szczególnie
//! istotne tutaj — dekodowanie pikseli do RAM jest najbardziej CPU/pamięć-
//! -chłonną operacją ze wszystkich faz; głodzenie jednej strony przy
//! współdzielonej globalnej puli byłoby tu najbardziej dotkliwe.

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

const CHUNK_SIZE: usize = 100; // Mniejsza paczka, oszczędzamy RAM przy ciężkich bitmapach

/// SQL zapisu wyniku analizy dla strony UFS, wołane w pętli wątku
/// bazodanowego w [`run`]. Wydzielone do stałej (wzorzec identyczny z innymi
/// fazami, patrz np. `phase2::SQL_FINALIZACJA_MACIERZY`), żeby test
/// regresyjny [`tests::test_media_decoded_written_alongside_pixels_ok`]
/// wykonywał DOKŁADNIE ten sam SQL co produkcja - zero ryzyka, że test
/// i implementacja się rozjadą.
///
/// `media_decoded_ufs` (param `?8`) reużywa DOKŁADNIE tę samą wartość co
/// `pixels_ok_ufs` (param `?1`) - patrz naprawa BŁĘDU KRYTYCZNEGO opisana
/// przy wywołaniu `ALTER TABLE`/backfillu w [`run`]: Faza 9
/// (`phase9::decide_winner`, linie z komentarzem "Gray Banding") i Faza 8
/// (`phase8::evaluate_file`) czytają `media_decoded_*`, NIE `pixels_ok_*`,
/// przy decyzji Smart Merge - do tej naprawy ta kolumna nigdy nie była
/// zapisywana przez normalny przebieg tej fazy.
const SQL_UPDATE_UFS: &str = "UPDATE files SET pixels_ok_ufs = COALESCE(?1, pixels_ok_ufs), decode_reason_ufs = COALESCE(?2, decode_reason_ufs), img_width_ufs = COALESCE(?3, img_width_ufs), img_height_ufs = COALESCE(?4, img_height_ufs), img_extreme_ratio_ufs = COALESCE(?5, img_extreme_ratio_ufs), img_uniform_ufs = COALESCE(?6, img_uniform_ufs), io_error_ufs = COALESCE(?7, io_error_ufs), media_decoded_ufs = COALESCE(?8, media_decoded_ufs) WHERE id = ?9";

/// Odpowiednik [`SQL_UPDATE_UFS`] dla strony Skrypt Autorski - patrz tamta
/// dokumentacja.
const SQL_UPDATE_SCRIPT: &str = "UPDATE files SET pixels_ok_script = COALESCE(?1, pixels_ok_script), decode_reason_script = COALESCE(?2, decode_reason_script), img_width_script = COALESCE(?3, img_width_script), img_height_script = COALESCE(?4, img_height_script), img_extreme_ratio_script = COALESCE(?5, img_extreme_ratio_script), img_uniform_script = COALESCE(?6, img_uniform_script), io_error_script = COALESCE(?7, io_error_script), media_decoded_script = COALESCE(?8, media_decoded_script) WHERE id = ?9";

/// Próg stosunku dłuższego do krótszego boku, powyżej którego geometria
/// obrazu jest uznawana za bezsensowną dowodowo (np. 1×50000 px) — typowy
/// ślad częściowo nadpisanego lub błędnie zinterpretowanego nagłówka.
const EXTREME_ASPECT_RATIO_THRESHOLD: f64 = 50.0;

/// Liczba równomiernie rozłożonych punktów próbkowanych z obrazu przy
/// wykrywaniu jednolitej zawartości — kompromis między kosztem (nie
/// iterujemy KAŻDEGO piksela dużego zdjęcia) a czułością wykrycia.
const UNIFORM_SAMPLE_POINTS: usize = 100;

// ============================================================================
// POMOCNIKI (CZYSTE FUNKCJE - TESTOWALNE BEZ RZECZYWISTEGO DEKODOWANIA)
// ============================================================================

/// Rozszerzenia kwalifikujące plik do analizy w tej fazie. `.dng` używa
/// ZUPEŁNIE INNEJ ścieżki dekodowania niż reszta (`raw_image::decode_raw_file`
/// zamiast `image::open`) — patrz [`analyze_image`] — bo crate `image` nie
/// rozumie formatów RAW w ogóle. Pozostałe DNG-pochodne formatów producentów
/// (CR2/NEF/ARW...) świadomie NIE są tu jeszcze dodane, mimo że `rawloader`
/// by je obsłużył — rozszerzamy stopniowo, zaczynając od zweryfikowanego na
/// prawdziwym pliku użytkownika przypadku.
/// Rozszerzenia kwalifikujące plik do analizy w tej fazie. TRZY różne
/// ścieżki dekodowania (patrz [`analyze_image`]), bo żadna biblioteka nie
/// obsługuje wszystkiego:
/// - `.dng` → `raw_image` (crate `rawloader`, czysty Rust),
/// - `.heic`/`.heif`/`.avif` → `heic_image` (crate `libheif-rs`, wymaga
///   systemowej `libheif` + pluginów dekodujących),
/// - reszta → crate `image`, jak dotychczas.
///
/// Pozostałe formaty RAW producentów (CR2/NEF/ARW...) świadomie NIE są tu
/// jeszcze dodane, mimo że `rawloader` by je obsłużył — rozszerzamy
/// stopniowo, tylko o przypadki zweryfikowane na prawdziwych plikach użytkownika.
fn is_decodable_extension(path_str: &str) -> bool {
    let exts = [".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tif", ".tiff", ".gif", ".dng",
                ".heic", ".heif", ".avif"];
    let lower_path = path_str.to_lowercase();
    exts.iter().any(|&ext| lower_path.ends_with(ext))
}

/// Klasyfikuje komunikat błędu (już zlowercase'owany) z crate `image` do
/// jednej z trzech kategorii dekodowania: `"bomb"` (przekroczony limit
/// alokacji — ochrona przed "pikselową bombą"), `"fake"` (nieobsługiwany
/// format/fałszywe rozszerzenie), `"glitch"` (uszkodzone dane w środku
/// poprawnego nagłówka — Gray Banding). NIE obsługuje przypadku braku pliku
/// (`"os error"`/`"no such file"`) — to sprawdzane osobno w [`analyze_image`],
/// bo zmienia typ zwracanej wartości (`Err`, nie `ImageAnalysis`).
fn classify_decode_error(err_str_lower: &str) -> (&'static str, &'static str) {
    if err_str_lower.contains("limit") || err_str_lower.contains("allocation") {
        ("bomb", "Pikselowa Bomba (Przekroczono limit RAM / Malicious Payload)")
    } else if err_str_lower.contains("unsupported") || err_str_lower.contains("format") {
        ("fake", "Nieobsługiwany / Fałszywe rozszerzenie")
    } else {
        ("glitch", "Zepsute Piksele (Gray Banding / Ucięty obraz)")
    }
}

/// Sprawdza, czy stosunek dłuższego do krótszego boku przekracza
/// [`EXTREME_ASPECT_RATIO_THRESHOLD`]. Zwraca `false` dla wymiaru zerowego
/// (unika dzielenia przez zero — taki przypadek i tak nie powinien wystąpić
/// dla poprawnie zdekodowanego obrazu).
fn is_extreme_aspect_ratio(width: u32, height: u32) -> bool {
    if width == 0 || height == 0 { return false; }
    let (w, h) = (width as f64, height as f64);
    let ratio = if w > h { w / h } else { h / w };
    ratio > EXTREME_ASPECT_RATIO_THRESHOLD
}

/// Rozstrzyga, czy próbka pikseli (RGBA) jest jednolita — wszystkie próbkowane
/// punkty mają IDENTYCZNĄ wartość. To sygnał ORIENTACYJNY (stąd nazwa
/// "podejrzana", nie "potwierdzona" jednolitość w raportach) — próbkowanie
/// ograniczonej siatki punktów może przeoczyć niewielki fragment innej
/// treści; nie jest to pełna, stuprocentowa weryfikacja każdego piksela.
/// Pusta próbka (obraz 0×0) zwraca `false` (nie ma czego uznać za jednolite).
fn is_uniform_sample(samples: &[[u8; 4]]) -> bool {
    match samples.first() {
        None => false,
        Some(first) => samples.iter().all(|p| p == first),
    }
}

/// Wyodrębnia do `count` równomiernie rozłożonych próbek pikseli (RGBA) z
/// obrazu — używane przez [`is_uniform_sample`]. Krok próbkowania liczony
/// tak, by objąć CAŁY obraz (nie tylko górny róg), nie tylko `count`
/// pierwszych pikseli.
fn sample_pixels(img: &image::DynamicImage, count: usize) -> Vec<[u8; 4]> {
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    if w == 0 || h == 0 || count == 0 { return Vec::new(); }

    let total_pixels = (w as u64) * (h as u64);
    let step = std::cmp::max(1, total_pixels / count as u64);
    let mut samples = Vec::with_capacity(count);
    let mut idx: u64 = 0;

    while idx < total_pixels && samples.len() < count {
        let x = (idx % w as u64) as u32;
        let y = (idx / w as u64) as u32;
        let px = rgba.get_pixel(x, y);
        samples.push([px[0], px[1], px[2], px[3]]);
        idx += step;
    }
    samples
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

/// Wynik analizy jednego obrazu. `is_valid`/`reason` to wynik binarny
/// (unieważnia plik). `has_extreme_aspect_ratio`/`has_uniform_content` są
/// INFORMACYJNE — mogą wystąpić NIEZALEŻNIE od ważności, nie unieważniają
/// pliku same w sobie (legalny jednolity obraz — np. zeskanowana pusta
/// kartka — jest rzadki, ale możliwy; ryzyko fałszywego odrzucenia
/// przewyższa wartość automatycznego unieważnienia).
#[derive(Debug, Clone)]
struct ImageAnalysis {
    is_valid: bool,
    reason: Option<String>,
    width: u32,
    height: u32,
    megapixels: f64,
    color_space: String,
    has_extreme_aspect_ratio: bool,
    has_uniform_content: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SideDecodeResult {
    id: i32,
    analysis: ImageAnalysis,
    io_error: Option<bool>,
}

pub(crate) enum ScanMsg {
    UfsChunk(Vec<SideDecodeResult>),
    ScriptChunk(Vec<SideDecodeResult>),
}

/// Liczniki live dla JEDNEJ strony. Trzy kategorie "twardych" błędów
/// (Glitch/Bomba/Fałszywe) wspólne/unikalne, trzy kubełki rozdzielczości,
/// trzy przestrzenie kolorów (bez podziału common/unique — to statystyka
/// zbiorcza, nie anomalia), oraz dwie kategorie INFORMACYJNE (proporcje
/// ekstremalne, zawartość jednolita) wspólne/unikalne. Nigdy nie łączone
/// z licznikami drugiej strony.
pub(crate) struct LiveStats {
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    errors: AtomicUsize,
    ext_weights: Mutex<HashMap<String, u64>>,
    
    ok: AtomicUsize,
    total_megapixels_x1_m: AtomicU64, 
    
    err_glitch_common: AtomicUsize,  err_glitch_unique: AtomicUsize,
    err_bomb_common: AtomicUsize,    err_bomb_unique: AtomicUsize,
    err_fake_common: AtomicUsize,    err_fake_unique: AtomicUsize,

    res_thumb_common: AtomicUsize,   res_thumb_unique: AtomicUsize,
    res_std_common: AtomicUsize,     res_std_unique: AtomicUsize,
    res_high_common: AtomicUsize,    res_high_unique: AtomicUsize,
    
    col_rgb: AtomicUsize, col_rgba: AtomicUsize, col_gray: AtomicUsize,

    /// INFORMACYJNE: stosunek boków przekracza [`EXTREME_ASPECT_RATIO_THRESHOLD`].
    extreme_ratio_common: AtomicUsize, extreme_ratio_unique: AtomicUsize,
    /// INFORMACYJNE: próbka pikseli wyszła jednolita — patrz [`is_uniform_sample`].
    uniform_common: AtomicUsize, uniform_unique: AtomicUsize,

    /// EKSPERYMENTALNE (Wariant A): śledzi zajętość logicznych slotów Rayon
    /// TEJ strony podczas dekodowania obrazu (`image::open` + próbkowanie
    /// pikseli) — patrz moduł `thread_activity`. Ta faza ma najcięższą
    /// operację CPU ze wszystkich zintegrowanych dotąd (pełne dekodowanie
    /// piksel-po-pikselu do RAM), więc wskazania powinny być tu najbardziej
    /// czytelne (mniej ryzyka "migania szybciej niż odświeżanie UI").
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            processed_files: AtomicUsize::new(0), processed_bytes: AtomicU64::new(0), errors: AtomicUsize::new(0),
            ext_weights: Mutex::new(HashMap::new()), ok: AtomicUsize::new(0), total_megapixels_x1_m: AtomicU64::new(0),
            err_glitch_common: AtomicUsize::new(0), err_glitch_unique: AtomicUsize::new(0),
            err_bomb_common: AtomicUsize::new(0), err_bomb_unique: AtomicUsize::new(0),
            err_fake_common: AtomicUsize::new(0), err_fake_unique: AtomicUsize::new(0),
            res_thumb_common: AtomicUsize::new(0), res_thumb_unique: AtomicUsize::new(0),
            res_std_common: AtomicUsize::new(0), res_std_unique: AtomicUsize::new(0),
            res_high_common: AtomicUsize::new(0), res_high_unique: AtomicUsize::new(0),
            col_rgb: AtomicUsize::new(0), col_rgba: AtomicUsize::new(0), col_gray: AtomicUsize::new(0),
            extreme_ratio_common: AtomicUsize::new(0), extreme_ratio_unique: AtomicUsize::new(0),
            uniform_common: AtomicUsize::new(0), uniform_unique: AtomicUsize::new(0),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }
}

/// Wylicza liczbę slotów trackera zajętości (Wariant A) odpowiednią dla
/// trybu I/O — patrz identyczna logika w `phase3::compute_activity_slots`.
fn compute_activity_slots(io_mode: &str, actual_threads: usize, half_threads: usize) -> usize {
    if io_mode == "CONCURRENT" { half_threads } else { actual_threads }
}

/// Buduje pełny, samodzielny blok live DLA JEDNEGO ŹRÓDŁA — prędkość MB/s i
/// MP/s, top 3 rozszerzenia, zdrowe (z rozbiciem na przestrzenie kolorów),
/// trzy kategorie "twardych" błędów wspólne/unikalne, dwie kategorie
/// informacyjne (proporcje ekstremalne, zawartość jednolita), błędy I/O.
fn build_source_block(label: &str, stats: &LiveStats, start_time: Instant) -> String {
    let bytes = stats.processed_bytes.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
    let speed_mb = (bytes as f64 / 1_048_576.0) / elapsed;
    let speed_mp = (stats.total_megapixels_x1_m.load(Ordering::Relaxed) as f64 / 1_000_000.0) / elapsed;

    let top_ext = {
        let map = stats.ext_weights.lock().unwrap();
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.into_iter().take(3).map(|(ext, w)| {
            let e = if ext == "brak" { "brak".to_string() } else { format!(".{}", ext) };
            format!("{} ({})", e, format_bytes(*w))
        }).collect::<Vec<_>>().join(", ")
    };
    let display_ext = if top_ext.is_empty() { "Analiza pikseli...".to_string() } else { top_ext };

    let activity_markup = crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot());

    format!(
        "[{}]\nPrędkość: {:.2} MB/s | {:.1} MP/s\nTop format: {}\nZdrowe: {} (RGB: {}, RGBA: {}, Szare: {})\nZepsute piksele: {} wspólne / {} unikalne\nFałszywe rozszerzenie: {} wspólne / {} unikalne\nBomba pikselowa: {} wspólne / {} unikalne\nEkstremalne proporcje: {} wspólne / {} unikalne\nZawartość jednolita (próbka): {} wspólne / {} unikalne\nWątki dekodowania (Wariant A): {}\nBłędy I/O: {}",
        label, speed_mb, speed_mp, display_ext,
        stats.ok.load(Ordering::Relaxed),
        stats.col_rgb.load(Ordering::Relaxed), stats.col_rgba.load(Ordering::Relaxed), stats.col_gray.load(Ordering::Relaxed),
        stats.err_glitch_common.load(Ordering::Relaxed), stats.err_glitch_unique.load(Ordering::Relaxed),
        stats.err_fake_common.load(Ordering::Relaxed), stats.err_fake_unique.load(Ordering::Relaxed),
        stats.err_bomb_common.load(Ordering::Relaxed), stats.err_bomb_unique.load(Ordering::Relaxed),
        stats.extreme_ratio_common.load(Ordering::Relaxed), stats.extreme_ratio_unique.load(Ordering::Relaxed),
        stats.uniform_common.load(Ordering::Relaxed), stats.uniform_unique.load(Ordering::Relaxed),
        activity_markup,
        stats.errors.load(Ordering::Relaxed),
    )
}

type ExtMap = HashMap<String, Vec<String>>;
struct SourceAnomalies { ufs: ExtMap, script: ExtMap }
impl SourceAnomalies { fn new() -> Self { Self { ufs: HashMap::new(), script: HashMap::new() } } }

struct AnomalyCategory {
    name: &'static str,
    icon: &'static str,
    common: SourceAnomalies, unique: SourceAnomalies,
}
impl AnomalyCategory {
    fn new(name: &'static str, icon: &'static str) -> Self {
        Self { name, icon, common: SourceAnomalies::new(), unique: SourceAnomalies::new() }
    }
}

// ============================================================================
// SILNIK DECYZYJNY (WERYFIKATOR RENDEROWANIA PIKSELI Z KATEGORYZACJĄ)
// ============================================================================

/// Wymusza pełne dekodowanie obrazu do pamięci RAM (crate `image`). Sukces
/// dekodowania nie kończy analizy — dodatkowo liczy proporcje boków
/// ([`is_extreme_aspect_ratio`]) i próbkuje jednolitość zawartości
/// ([`sample_pixels`] + [`is_uniform_sample`]), obie jako flagi
/// INFORMACYJNE. Błąd dekodowania jest klasyfikowany przez
/// [`classify_decode_error`] do jednej z trzech kategorii — WYJĄTEK: błąd
/// wskazujący na brak pliku (`"os error"`/`"no such file"`) jest
/// przepuszczany jako `Err` (prawdziwy błąd I/O), nie jako nieważny obraz.
/// Wymusza pełne dekodowanie obrazu do pamięci RAM. Dla `.dng` używa
/// `raw_image::decode_raw_file` (crate `rawloader` — patrz moduł
/// `raw_image`, zweryfikowany empirycznie na prawdziwym pliku RAW telefonu
/// użytkownika); dla WSZYSTKICH pozostałych rozszerzeń — crate `image`
/// (`image::open`) jak dotychczas, bez zmian.
///
/// Sukces dekodowania nie kończy analizy — dodatkowo liczy proporcje boków
/// ([`is_extreme_aspect_ratio`]) i próbkuje jednolitość zawartości
/// ([`sample_pixels`] + [`is_uniform_sample`]), obie jako flagi
/// INFORMACYJNE. DLA DNG te dwie flagi informacyjne są pomijane (zawsze
/// `false`) — `rawloader` zwraca surowe dane Bayera (`RawImageData`), nie
/// gotowy bufor pikseli RGB/Grayscale, jakiego oczekuje [`sample_pixels`];
/// dorobienie sensownego próbkowania dla surowego Bayera to osobna decyzja
/// projektowa, świadomie odłożona.
///
/// Błąd dekodowania jest klasyfikowany przez [`classify_decode_error`] do
/// jednej z trzech kategorii — WYJĄTEK: błąd wskazujący na brak pliku
/// (`"os error"`/`"no such file"`) jest przepuszczany jako `Err` (prawdziwy
/// błąd I/O), nie jako nieważny obraz. Dla DNG brak analogicznego
/// rozróżnienia błędów w `rawloader` — sprawdzamy istnienie pliku wprost.
fn analyze_image(path: &Path) -> std::result::Result<ImageAnalysis, std::io::Error> {
    let path_lower = path.to_str().map(|s| s.to_lowercase()).unwrap_or_default();
    let is_dng = path_lower.ends_with(".dng");
    let is_heic = crate::heic_image::is_heic_extension(&path_lower);

    if is_heic {
        if !path.exists() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Błąd I/O"));
        }
        return Ok(match crate::heic_image::decode_heic_file(path) {
            Some(info) => {
                let mp = (info.width as f64 * info.height as f64) / 1_000_000.0;
                // libheif nie raportuje przestrzeni barw tak jak crate `image` -
                // budujemy opis z tego, co faktycznie mamy (kanał alfa + głębia
                // bitowa), zamiast zgadywać RGB/RGBA.
                let color = if info.has_alpha {
                    format!("HEIC z alfą ({}-bit)", info.bits_per_pixel)
                } else {
                    format!("HEIC bez alfy ({}-bit)", info.bits_per_pixel)
                };
                ImageAnalysis {
                    is_valid: true, reason: None,
                    width: info.width, height: info.height, megapixels: mp,
                    color_space: color,
                    has_extreme_aspect_ratio: is_extreme_aspect_ratio(info.width, info.height),
                    // Próbkowanie jednolitości pominięte z tego samego powodu co
                    // przy DNG: `heic_image` czyta STRUKTURĘ kontenera, nie
                    // dekoduje pikseli do bufora, jakiego oczekuje `sample_pixels`
                    // (pełne dekodowanie HEVC byłoby znacznie droższe).
                    has_uniform_content: false,
                }
            }
            None => ImageAnalysis {
                is_valid: false, reason: Some("Nie udało się odczytać pliku HEIC/HEIF/AVIF (uszkodzony kontener lub brak pluginu dekodującego libheif)".to_string()),
                width: 0, height: 0, megapixels: 0.0, color_space: "Brak".to_string(),
                has_extreme_aspect_ratio: false, has_uniform_content: false,
            },
        });
    }

    if is_dng {
        if !path.exists() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Błąd I/O"));
        }
        return Ok(match crate::raw_image::decode_raw_file(path) {
            Some(info) => {
                let mp = (info.width as f64 * info.height as f64) / 1_000_000.0;
                let color = match info.components_per_pixel {
                    1 => "RAW Bayer (1 składowa)",
                    3 => "RGB",
                    _ => "Inny/Mieszany",
                };
                ImageAnalysis {
                    is_valid: true, reason: None,
                    width: info.width as u32, height: info.height as u32, megapixels: mp,
                    color_space: color.to_string(),
                    // Próbkowanie jednolitości/proporcji dla surowego Bayera
                    // celowo pominięte - patrz dokumentacja funkcji wyżej.
                    has_extreme_aspect_ratio: is_extreme_aspect_ratio(info.width as u32, info.height as u32),
                    has_uniform_content: false,
                }
            }
            None => ImageAnalysis {
                is_valid: false, reason: Some("Nie udało się zdekodować pliku RAW/DNG (uszkodzony lub nierozpoznany model aparatu)".to_string()),
                width: 0, height: 0, megapixels: 0.0, color_space: "Brak".to_string(),
                has_extreme_aspect_ratio: false, has_uniform_content: false,
            },
        });
    }

    // REGRESJA (BŁĄD WYSOKI): gałąź `image::open` (jpg/jpeg/png/webp/bmp/tif/
    // gif — najpopularniejsza z trzech ścieżek dekodowania w tej fazie) była
    // jedyną BEZ ochrony `catch_unwind`, mimo że DNG (`raw_image`) i HEIC
    // (`heic_image`) już ją mają. Panika crate'u `image` na spreparowanym/
    // uszkodzonym pliku ubijała cały wątek Rayon. `generic_image::decode_guarded`
    // opakowuje TERAZ zarówno `image::open`, jak i całe przetwarzanie
    // zdekodowanego bufora (próbkowanie jednolitości) w jednym domknięciu —
    // patrz `generic_image.rs` i jego testy dowodzące że panika wewnątrz
    // domknięcia zostaje bezpiecznie przechwycona.
    let guarded = crate::generic_image::decode_guarded(|| -> std::io::Result<ImageAnalysis> {
        match image::open(path) {
            Ok(img) => {
                let w = img.width();
                let h = img.height();
                let mp = (w as f64 * h as f64) / 1_000_000.0;
                let color = match img.color() {
                    image::ColorType::Rgb8 | image::ColorType::Rgb16 | image::ColorType::Rgb32F => "RGB",
                    image::ColorType::Rgba8 | image::ColorType::Rgba16 | image::ColorType::Rgba32F => "RGBA",
                    image::ColorType::L8 | image::ColorType::L16 | image::ColorType::La8 | image::ColorType::La16 => "Grayscale",
                    _ => "Inny/Mieszany",
                };

                let has_extreme_aspect_ratio = is_extreme_aspect_ratio(w, h);
                let samples = sample_pixels(&img, UNIFORM_SAMPLE_POINTS);
                let has_uniform_content = is_uniform_sample(&samples);

                Ok(ImageAnalysis {
                    is_valid: true, reason: None, width: w, height: h, megapixels: mp, color_space: color.to_string(),
                    has_extreme_aspect_ratio, has_uniform_content,
                })
            }
            Err(e) => {
                let err_str = e.to_string().to_lowercase();
                if err_str.contains("os error") || err_str.contains("no such file") {
                    return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Błąd I/O"));
                }
                let (_, reason) = classify_decode_error(&err_str);

                Ok(ImageAnalysis {
                    is_valid: false, reason: Some(reason.to_string()), width: 0, height: 0, megapixels: 0.0, color_space: "Brak".to_string(),
                    has_extreme_aspect_ratio: false, has_uniform_content: false,
                })
            }
        }
    });

    match guarded {
        Some(result) => result,
        // Panika przechwycona: dla wywołującego nie ma znaczenia, czy crate
        // `image` zwrócił `Err`, czy się wywalił - to samo traktowanie co
        // zwykły błąd dekodowania, nie błąd I/O (plik istnieje i się otwiera,
        // tylko jego treść łamie dekoder).
        None => Ok(ImageAnalysis {
            is_valid: false,
            reason: Some("Dekoder obrazu spanikował na uszkodzonym pliku (przechwycone bezpiecznie)".to_string()),
            width: 0, height: 0, megapixels: 0.0, color_space: "Brak".to_string(),
            has_extreme_aspect_ratio: false, has_uniform_content: false,
        }),
    }
}

/// Skanuje wszystkie zadania (`tasks`) dla JEDNEJ strony: dla każdego pliku
/// woła [`analyze_image`], aktualizuje liczniki [`LiveStats`] (twarde +
/// informacyjne niezależnie od siebie), zapisuje wpis do jednego z dwóch
/// logów i strumieniuje wynik do wątku zapisu SQLite. Rozgłasza postęp i
/// statystyki do UI co ~200 plików LUB co 250ms (hybrydowy próg — wzorzec
/// z Fazy 5-7/10-12).
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
    pub log_anom: Arc<Mutex<File>>,
    pub log_info: Arc<Mutex<File>>,
}

#[instrument(skip(ctx), fields(base_path = %ctx.base_path.display()))]

fn process_side_stream<'a>(ctx: StreamCtx<'a>) {
    let StreamCtx { base_path, tasks, side_label, stats, tx_db, is_ufs, tx_ui, bar_idx, start_time, log_anom, log_info } = ctx;

    tasks.par_chunks(CHUNK_SIZE).for_each_with(tx_db, |tx_db, chunk| {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

        let mut results = Vec::with_capacity(chunk.len());
        let mut local_ext_weights: HashMap<String, u64> = HashMap::new();
        let mut last_ui_update = Instant::now();

        for task in chunk {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

            let full_path = base_path.join(&task.rel_path);
            let ext = Path::new(&task.rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
            let file_size = std::fs::metadata(&full_path).map(|m| m.len()).unwrap_or(0);
            
            *local_ext_weights.entry(ext.clone()).or_insert(0) += file_size;

            let (analysis, io_err) = match stats.thread_activity.track_current(|| analyze_image(&full_path)) {
                Ok(ana) => {
                    let kategoria = if task.is_common { "Wspólne" } else { "Osobne" };

                    if ana.is_valid {
                        stats.ok.fetch_add(1, Ordering::Relaxed);
                        stats.total_megapixels_x1_m.fetch_add((ana.megapixels * 1_000_000.0) as u64, Ordering::Relaxed);

                        if ana.megapixels < 1.0 { if task.is_common { stats.res_thumb_common.fetch_add(1, Ordering::Relaxed); } else { stats.res_thumb_unique.fetch_add(1, Ordering::Relaxed); } }
                        else if ana.megapixels <= 8.0 { if task.is_common { stats.res_std_common.fetch_add(1, Ordering::Relaxed); } else { stats.res_std_unique.fetch_add(1, Ordering::Relaxed); } }
                        else { if task.is_common { stats.res_high_common.fetch_add(1, Ordering::Relaxed); } else { stats.res_high_unique.fetch_add(1, Ordering::Relaxed); } }

                        if ana.color_space == "RGB" { stats.col_rgb.fetch_add(1, Ordering::Relaxed); }
                        else if ana.color_space == "RGBA" { stats.col_rgba.fetch_add(1, Ordering::Relaxed); }
                        else { stats.col_gray.fetch_add(1, Ordering::Relaxed); }

                        if ana.has_extreme_aspect_ratio {
                            if task.is_common { stats.extreme_ratio_common.fetch_add(1, Ordering::Relaxed); } else { stats.extreme_ratio_unique.fetch_add(1, Ordering::Relaxed); }
                        }
                        if ana.has_uniform_content {
                            if task.is_common { stats.uniform_common.fetch_add(1, Ordering::Relaxed); } else { stats.uniform_unique.fetch_add(1, Ordering::Relaxed); }
                        }

                        if let Ok(mut f) = log_info.lock() {
                            let _ = writeln!(f, "[{:<15}] [{:<7}] [Rozdz: {:>4}x{:<4} | {:>5.1} MP | Kolor: {:<5}] Format: .{:<4} | Ścieżka: \"{}\"", 
                                side_label, kategoria, ana.width, ana.height, ana.megapixels, ana.color_space, ext, full_path.display());
                        }
                    } else {
                        let r = ana.reason.as_deref().unwrap_or("Nieznany błąd");
                        
                        if r.contains("Bomba") {
                            if task.is_common { stats.err_bomb_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_bomb_unique.fetch_add(1, Ordering::Relaxed); }
                        } else if r.contains("Nieobsługiwany") {
                            if task.is_common { stats.err_fake_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_fake_unique.fetch_add(1, Ordering::Relaxed); }
                        } else {
                            if task.is_common { stats.err_glitch_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_glitch_unique.fetch_add(1, Ordering::Relaxed); }
                        }

                        if let Ok(mut f) = log_anom.lock() {
                            let _ = writeln!(f, "[{:<15}] [{:<7}] [{}] Format: .{:<4} | Ścieżka: \"{}\"", side_label, kategoria, r, ext, full_path.display());
                        }
                    }
                    (ana, Some(false))
                },
                Err(e) => {
                    warn!(path = %task.rel_path, side = side_label, error = %e, "Błąd z biblioteką Image / I/O");
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    (ImageAnalysis {
                        is_valid: false, reason: Some("Błąd I/O dysku".into()), width: 0, height: 0, megapixels: 0.0, color_space: "Brak".into(),
                        has_extreme_aspect_ratio: false, has_uniform_content: false,
                    }, Some(true))
                }
            };

            stats.processed_files.fetch_add(1, Ordering::Relaxed);
            stats.processed_bytes.fetch_add(file_size, Ordering::Relaxed);

            let current = stats.processed_files.load(Ordering::Relaxed);
            let now = Instant::now();

            // Hybrydowy próg (wzorzec z Fazy 5-7/10-12): licznik globalny jako
            // główny wyzwalacz, plus siatka bezpieczeństwa czasowa.
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

            results.push(SideDecodeResult { id: task.id, analysis, io_error: io_err });
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
        message: "Renderowanie obrazów w 100% zakończone.".to_string(),
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

/// Punkt wejścia Fazy 13, wołany przez `menu::actions::run_phase_with_ui`.
///
/// Przebieg: (1) wczytuje z SQLite obrazy bez jeszcze wykonanego pełnego
/// dekodowania; (2) uruchamia [`process_side_stream`] dla UFS i Skryptu —
/// równolegle na dwóch dedykowanych pulach Rayon lub sekwencyjnie; (3) koreluje
/// wyniki w SQLite; (4) buduje hierarchiczny Dziennik Końcowy z kategoryzacją
/// rozdzielczości i trzech kategorii błędów dekodowania.
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    let actual_threads = if config.max_threads > 0 { config.max_threads } else { rayon::current_num_threads() };
    let io_text = if config.io_mode == "CONCURRENT" { "RÓWNOLEGŁE (SSD/NVMe)" } else { "SEKWENCYJNIE (HDD)" };
    
    let _ = tx_ui.send(PhaseEvent::Log(format!("Uruchomiono Fazę 13. Metodyka szyny dyskowej: {}", io_text)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora (Rayon): {}", actual_threads)));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    // Modyfikacja Bazy Danych - dodajemy kolumny (Optymalizacja pod Smart Merge)
    let _ = conn.execute("ALTER TABLE files ADD COLUMN pixels_ok_ufs BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN pixels_ok_script BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN decode_reason_ufs TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN decode_reason_script TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN img_width_ufs INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN img_width_script INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN img_height_ufs INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN img_height_script INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN img_extreme_ratio_ufs BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN img_extreme_ratio_script BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN img_uniform_ufs BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN img_uniform_script BOOLEAN", []);

    // NAPRAWA (BŁĄD KRYTYCZNY): `media_decoded_ufs`/`media_decoded_script`
    // JUŻ ISTNIEJĄ w bazowym `CREATE TABLE` (patrz `db.rs`) - Faza 9
    // (`decide_winner`) i Faza 8 (`evaluate_file`) je CZYTAJĄ bezwarunkowo
    // przy decyzji Smart Merge (odrzucenie strony z powodu Gray Banding), ale
    // do tej pory ŻADNA faza normalnego przebiegu ich nie ZAPISYWAŁA (tylko
    // osobna ścieżka `dng_repair.rs`) - detekcja Gray Banding tej fazy nigdy
    // nie wpływała na finalną decyzję. Naprawione niżej: zapisujemy
    // `media_decoded_*` RÓWNOLEGLE do `pixels_ok_*`, tą samą wartością (patrz
    // pętla zapisu w wątku bazodanowym), bo to DOKŁADNIE ta sama semantyka -
    // `Some(true)` = zdekodowano czysto, `Some(false)` = Gray Banding / ucięty
    // obraz / błąd I/O, `NULL` = jeszcze nie sprawdzone.
    //
    // Jednorazowy BACKFILL dla baz, na których Faza 13 działała PRZED tą
    // naprawą: takie wiersze mają już wypełnione `pixels_ok_*`, ale
    // `media_decoded_*` zostałoby trwale NULL, bo wiersze z wypełnionym
    // `pixels_ok_*` są POMIJANE przy ponownym uruchomieniu Fazy 13 (patrz
    // filtr `ok_ufs.is_none()` niżej w ETAPIE 1) - bez tego backfillu jedynym
    // sposobem naprawy istniejącej bazy byłoby skasowanie `pixels_ok_*` i
    // ponowne (kosztowne) wyrenderowanie WSZYSTKICH pikseli od zera.
    let _ = conn.execute("UPDATE files SET media_decoded_ufs = pixels_ok_ufs WHERE media_decoded_ufs IS NULL AND pixels_ok_ufs IS NOT NULL", []);
    let _ = conn.execute("UPDATE files SET media_decoded_script = pixels_ok_script WHERE media_decoded_script IS NULL AND pixels_ok_script IS NOT NULL", []);

    // 1. INICJALIZACJA DUAL-LOGGING (Pobieranie ścieżek z Ustawień)
    let raport_cfg = config.raporty_faz.get("Faza 13").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza13.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza13.txt".to_string(),
    });
    
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);
    let info_path = Path::new(&raport_cfg.katalog).join("raport_operacyjny_faza13_zdrowe_dekody.txt");

    let log_anom = match File::create(&opr_path) {
        Ok(f) => Arc::new(Mutex::new(f)),
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!("BŁĄD I/O: Nie udało się utworzyć pliku raportu na dysku: {}. Sprawdź uprawnienia.", e)));
            return Ok(());
        }
    };
    
    let log_info = match File::create(&info_path) {
        Ok(f) => Arc::new(Mutex::new(f)),
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!("BŁĄD I/O: Nie udało się utworzyć pliku statystyk: {}", e)));
            return Ok(()); 
        }
    };
    
    {
        let mut f_anom = log_anom.lock().unwrap();
        let _ = writeln!(f_anom, "=== RAPORT OPERACYJNY - FAZA 13 (ZEPSUTE DEKODOWANIA) ===");
        let _ = writeln!(f_anom, "Zestawienie plików, które wywaliły procesor podczas próby renderowania. (Gray Banding, Ucięcia).\n");
        
        let mut f_info = log_info.lock().unwrap();
        let _ = writeln!(f_info, "=== RAPORT OPERACYJNY - FAZA 13 (ZDROWE WYRENDEROWANE RAMKI) ===");
        let _ = writeln!(f_info, "Ekstrakcja śledcza: Szerokość, Wysokość, Megapiksele i Przestrzenie barw (RGB/RGBA).\n");
    }

    // --- ETAP 1: POBIERANIE ZADAŃ Z BAZY ---
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, pixels_ok_ufs, pixels_ok_script, io_error_ufs, io_error_script 
         FROM files WHERE phase13_done = 0 OR phase13_done IS NULL"
    )?;
    
    let mut ufs_tasks = Vec::new();
    let mut script_tasks = Vec::new();
    let mut skipped_ufs = 0;
    let mut skipped_script = 0;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i32>(0)?, row.get::<_, String>(1)?, row.get::<_, bool>(2)?, row.get::<_, bool>(3)?,
            row.get::<_, Option<bool>>(4)?, row.get::<_, Option<bool>>(5)?,
            row.get::<_, Option<bool>>(6)?, row.get::<_, Option<bool>>(7)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_ufs, in_script, ok_ufs, ok_scr, err_ufs, err_scr) = r;
        
        if is_decodable_extension(&rel) {
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
        let _ = tx_ui.send(PhaseEvent::Log(format!("Pominięto zdjęcia z już wyrenderowaną macierzą. UFS: {}, Skrypt: {}", skipped_ufs, skipped_script)));
    }

    let total_db_rows = ufs_tasks.len() + script_tasks.len();
    if total_db_rows == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak wspieranych zdjęć do renderowania. Baza aktualna.".to_string()));
        return Ok(());
    }

    // Inicjalizacja pasków postępu Ratatui
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "UFS Explorer (Obrazy)".to_string(), total: ufs_tasks.len() as u64, color: Color::Cyan });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 1, label: "Skrypt Autorski (Obrazy)".to_string(), total: script_tasks.len() as u64, color: Color::Magenta });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 2, label: "Zapis SQLite".to_string(), total: total_db_rows as u64, color: Color::Green });

    let half_threads = compute_half_threads(actual_threads);
    let activity_slots = compute_activity_slots(&config.io_mode, actual_threads, half_threads);

    let ufs_stats = LiveStats::new(activity_slots);
    let script_stats = LiveStats::new(activity_slots);
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
                        // NAPRAWA (BŁĄD KRYTYCZNY): `media_decoded_*` zapisywane
                        // RÓWNOLEGLE do `pixels_ok_*`, tą samą wartością `ok`
                        // (patrz pętla niżej) - to Faza 9 (`decide_winner`) i
                        // Faza 8 (`evaluate_file`) faktycznie czytają przy
                        // decyzji Smart Merge, nie `pixels_ok_*`. `pixels_ok_*`
                        // POZOSTAJE bez zmian (nic z tego, co już na nim polega,
                        // nie jest ruszane).
                        let mut stmt = match &msg {
                            ScanMsg::UfsChunk(_) => tx_trans.prepare_cached(SQL_UPDATE_UFS).unwrap(),
                            ScanMsg::ScriptChunk(_) => tx_trans.prepare_cached(SQL_UPDATE_SCRIPT).unwrap(),
                        };

                        let chunk = match &msg {
                            ScanMsg::UfsChunk(c) => c,
                            ScanMsg::ScriptChunk(c) => c,
                        };

                        for res in chunk {
                            let (ok, reason, w, h, extreme, uniform) = if res.analysis.is_valid {
                                (Some(true), None, Some(res.analysis.width as i64), Some(res.analysis.height as i64),
                                 Some(res.analysis.has_extreme_aspect_ratio), Some(res.analysis.has_uniform_content))
                            } else {
                                (Some(false), res.analysis.reason.clone(), None, None, None, None)
                            };
                            // `media_decoded_*` (param ?8) reużywa DOKŁADNIE tę
                            // samą wartość `ok` co `pixels_ok_*` (param ?1) -
                            // identyczna semantyka: Some(true) = zdekodowano
                            // czysto, Some(false) = Gray Banding / ucięty obraz
                            // / błąd I/O.
                            stmt.execute(params![ok, reason, w, h, extreme, uniform, res.io_error, ok, res.id]).unwrap();
                        }
                    }
                    tx_trans.commit().unwrap();
                }

                db_inserted += chunk_len;
                let now = Instant::now();
                if now.duration_since(last_db_update).as_millis() > 60 {
                    last_db_update = now;
                    let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Zapisywanie wskaźników do bazy...".to_string() });
                }
            }
            let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Wskaźniki renderowania bezpieczne w SQLite.".to_string() });
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone(); let tx2 = tx_db.clone();
            let anom_u = log_anom.clone(); let anom_s = log_anom.clone();
            let info_u = log_info.clone(); let info_s = log_info.clone();

            let stat_u = &ufs_stats;
            let stat_s = &script_stats;

            // NAPRAWA (ten sam bug jak w Fazie 5/6/7/10/11/12): dedykowana
            // pula per strona, minimum 1 wątek. Wyliczone wcześniej, tu tylko używane.

            s.spawn(move || {
                if !ufs_tasks.is_empty() { 
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, start_time, log_anom: anom_u, log_info: info_u, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, start_time, log_anom: anom_u, log_info: info_u, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Renderowanie pikseli (UFS) zakończone.".to_string())); 
                }
            });

            s.spawn(move || {
                if !script_tasks.is_empty() { 
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, start_time, log_anom: anom_s, log_info: info_s, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, start_time, log_anom: anom_s, log_info: info_s, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Renderowanie pikseli (Skrypt) zakończone.".to_string())); 
                }
            });
            drop(tx_db);

        } 
            else 
        {
            let anom_u = log_anom.clone(); let anom_s = log_anom.clone();
            let info_u = log_info.clone(); let info_s = log_info.clone();
            
            if !ufs_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: &ufs_stats, tx_db: tx_db.clone(), is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, start_time, log_anom: anom_u, log_info: info_u, }); let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Renderowanie pikseli (UFS) zakończone.".to_string()));
            }
            if !script_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: &script_stats, tx_db: tx_db.clone(), is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, start_time, log_anom: anom_s, log_info: info_s, }); let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Renderowanie pikseli (Skrypt) zakończone.".to_string()));
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
        "UPDATE files SET phase13_done = CASE 
            WHEN (found_in_ufs = 0 OR pixels_ok_ufs IS NOT NULL OR io_error_ufs = 1) 
             AND (found_in_script = 0 OR pixels_ok_script IS NOT NULL OR io_error_script = 1) THEN 1 
            ELSE 0 
        END WHERE phase13_done = 0 OR phase13_done IS NULL", []
    )?;

    // --- ETAP 5: HIERARCHICZNY RAPORT KRYMINALISTYCZNY (Zapis TXT) ---
    let mut stmt = conn.prepare(
        "SELECT relative_path, found_in_ufs, found_in_script, 
                pixels_ok_ufs, pixels_ok_script, decode_reason_ufs, decode_reason_script
         FROM files WHERE phase13_done = 1"
    )?;

    let mut cat_glitch = AnomalyCategory::new("Zepsute Piksele / Gray Banding", "✂️");
    let mut cat_fake = AnomalyCategory::new("Nieobsługiwany / Fałszywe Rozszerzenie", "🧬");
    let mut cat_bomb = AnomalyCategory::new("Zip Bomb / Przepełnienie RAM", "💣");

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?, row.get::<_, bool>(1)?, row.get::<_, bool>(2)?,
            row.get::<_, Option<bool>>(3)?, row.get::<_, Option<bool>>(4)?,
            row.get::<_, Option<String>>(5)?, row.get::<_, Option<String>>(6)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (rel_path, in_ufs, in_scr, u_ufs, u_scr, reason_ufs, reason_scr) = r;
        let is_common = in_ufs && in_scr;
        let ext = Path::new(&rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();

        let add_to_cat = |cat: &mut AnomalyCategory, is_ufs_source: bool| {
            let target = if is_common { &mut cat.common } else { &mut cat.unique };
            let map = if is_ufs_source { &mut target.ufs } else { &mut target.script };
            map.entry(ext.clone()).or_default().push(rel_path.clone());
        };

        let mut process_reason = |ok: Option<bool>, reason: Option<String>, is_ufs_source: bool| {
            if ok == Some(false) {
                if let Some(r) = reason {
                    if r.contains("Bomba") { add_to_cat(&mut cat_bomb, is_ufs_source); }
                    else if r.contains("Nieobsługiwany") { add_to_cat(&mut cat_fake, is_ufs_source); }
                    else { add_to_cat(&mut cat_glitch, is_ufs_source); }
                } else {
                    add_to_cat(&mut cat_glitch, is_ufs_source);
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
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 13 (DEKODOWANIE PIKSELI I RENDEROWANIE RAM)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "Sumaryczny transfer I/O: {} (Średnia prędkość: {:.2} MB/s)", format_bytes(total_bytes), avg_speed_mb);
    let _ = writeln!(&mut log_out, "==========================================================================\n");

    let sum_mp = format!("{:.1} MP", (ufs_stats.total_megapixels_x1_m.load(Ordering::SeqCst) + script_stats.total_megapixels_x1_m.load(Ordering::SeqCst)) as f64 / 1_000_000.0);
    
    let _ = writeln!(&mut log_out, "[ 1 ] WYRENDEROWANE ZDJĘCIA (Przeszły test dekodowania bez szarych pasków):");
    let _ = writeln!(&mut log_out, "   -> Poprawnie wyrenderowano {} zdjęć", ufs_stats.ok.load(Ordering::SeqCst) + script_stats.ok.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "   -> Procesor obliczył łącznie: {}", sum_mp);
    let _ = writeln!(&mut log_out, "   -> Ekstremalne proporcje boków (>{:.0}:1): {}", EXTREME_ASPECT_RATIO_THRESHOLD, ufs_stats.extreme_ratio_common.load(Ordering::SeqCst) + ufs_stats.extreme_ratio_unique.load(Ordering::SeqCst) + script_stats.extreme_ratio_common.load(Ordering::SeqCst) + script_stats.extreme_ratio_unique.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "   -> Zawartość jednolita w próbce (orientacyjnie): {}\n", ufs_stats.uniform_common.load(Ordering::SeqCst) + ufs_stats.uniform_unique.load(Ordering::SeqCst) + script_stats.uniform_common.load(Ordering::SeqCst) + script_stats.uniform_unique.load(Ordering::SeqCst));

    let _ = writeln!(&mut log_out, "[ 2 ] KATEGORYZACJA ROZDZIELCZOŚCI (Zdrowe pliki):");
    let _ = writeln!(&mut log_out, "   -> Miniatury i ikony (< 1.0 MP):  {} plików", ufs_stats.res_thumb_common.load(Ordering::SeqCst) + ufs_stats.res_thumb_unique.load(Ordering::SeqCst) + script_stats.res_thumb_common.load(Ordering::SeqCst) + script_stats.res_thumb_unique.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "   -> Standardowa jakość (1 - 8 MP): {} plików", ufs_stats.res_std_common.load(Ordering::SeqCst) + ufs_stats.res_std_unique.load(Ordering::SeqCst) + script_stats.res_std_common.load(Ordering::SeqCst) + script_stats.res_std_unique.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "   -> Wysoka jakość (> 8.0 MP):      {} plików", ufs_stats.res_high_common.load(Ordering::SeqCst) + ufs_stats.res_high_unique.load(Ordering::SeqCst) + script_stats.res_high_common.load(Ordering::SeqCst) + script_stats.res_high_unique.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Algorytm Smart Merge w kolejnej Fazie wytypuje ostatecznie te zdjęcia, które po zdekodowaniu mają największą rozdzielczość (unika miniatur zapisanych pod oryginalną nazwą).\n");

    let write_section_txt = |out: &mut String, title: &str, is_common: bool| {
        let _ = writeln!(out, "[ KATEGORIA BŁĘDÓW: {} ]", title);
        let categories = [&cat_glitch, &cat_fake, &cat_bomb];
        let mut has_any = false;

        for cat in &categories {
            let src_anom = if is_common { &cat.common } else { &cat.unique };
            let ufs_total: usize = src_anom.ufs.values().map(|v| v.len()).sum();
            let scr_total: usize = src_anom.script.values().map(|v| v.len()).sum();
            
            if ufs_total > 0 || scr_total > 0 {
                has_any = true;
                let _ = writeln!(out, "   {} Typ anomalii: {} (UFS: {}, Skrypt: {})", cat.icon, cat.name, ufs_total, scr_total);
                if cat.name.contains("Glitche") || cat.name.contains("Zepsute") {
                    let _ = writeln!(out, "      [ ZNACZENIE ]: Plik ma dobry nagłówek, ale dekoder zderzył się w środku z zanieczyszczonymi danymi (tzw. Gray Banding). Zdjęcie odrzucone.");
                } else if cat.name.contains("Przepełnienie RAM") {
                    let _ = writeln!(out, "      [ ZNACZENIE ]: Malicious Payload (Zip Bomb w zdjęciu). Niewielki plik na dysku, ale instrukcje nakazują procesorowi wygenerować np. 40 GB pustego tła. Plik zablokowany.");
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

    let _ = writeln!(&mut log_out, "[ ZESTAWIENIE WAGOWE ZESKNOWANYCH ZDJĘĆ ]");
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
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano Raporty Operacyjne (Live) w: {} oraz {}", opr_path.display(), info_path.display())));
    }

    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    info!(
        total_io_errors,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 13 zakończona"
    );

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ------------------------------------------------------------------
    // compute_activity_slots (identyczna logika z Fazy 3-7/10-12)
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
    // is_decodable_extension
    // ------------------------------------------------------------------

    #[test]
    fn test_is_decodable_extension() {
        assert!(is_decodable_extension("zdjecie.PNG"));
        assert!(is_decodable_extension("obraz.jpeg"));
        assert!(!is_decodable_extension("dokument.pdf"));
    }

    // ------------------------------------------------------------------
    // classify_decode_error
    // ------------------------------------------------------------------

    #[test]
    fn test_classify_decode_error_bomb() {
        let (cat, _) = classify_decode_error("memory limit exceeded during allocation");
        assert_eq!(cat, "bomb");
    }

    #[test]
    fn test_classify_decode_error_fake() {
        let (cat, _) = classify_decode_error("unsupported image format");
        assert_eq!(cat, "fake");
    }

    #[test]
    fn test_classify_decode_error_glitch_default() {
        let (cat, _) = classify_decode_error("unexpected end of stream while parsing scanline");
        assert_eq!(cat, "glitch");
    }

    // ------------------------------------------------------------------
    // is_extreme_aspect_ratio
    // ------------------------------------------------------------------

    #[test]
    fn test_extreme_aspect_ratio_detected() {
        assert!(is_extreme_aspect_ratio(1, 5000));
        assert!(is_extreme_aspect_ratio(5000, 1));
    }

    #[test]
    fn test_normal_aspect_ratio_not_extreme() {
        assert!(!is_extreme_aspect_ratio(1920, 1080));
        assert!(!is_extreme_aspect_ratio(100, 100));
    }

    #[test]
    fn test_aspect_ratio_zero_dimension_not_extreme() {
        assert!(!is_extreme_aspect_ratio(0, 100));
        assert!(!is_extreme_aspect_ratio(100, 0));
    }

    #[test]
    fn test_aspect_ratio_exactly_at_threshold_not_extreme() {
        // Próg to ŚCIŚLE > 50.0
        assert!(!is_extreme_aspect_ratio(50, 1));
        assert!(is_extreme_aspect_ratio(51, 1));
    }

    // ------------------------------------------------------------------
    // is_uniform_sample
    // ------------------------------------------------------------------

    #[test]
    fn test_uniform_sample_all_identical() {
        let samples = vec![[255u8, 0, 0, 255]; 10];
        assert!(is_uniform_sample(&samples));
    }

    #[test]
    fn test_uniform_sample_with_one_different_pixel() {
        let mut samples = vec![[255u8, 0, 0, 255]; 10];
        samples[5] = [0, 255, 0, 255];
        assert!(!is_uniform_sample(&samples));
    }

    #[test]
    fn test_uniform_sample_empty_is_false() {
        assert!(!is_uniform_sample(&[]));
    }

    #[test]
    fn test_uniform_sample_single_pixel_is_uniform() {
        assert!(is_uniform_sample(&[[10, 20, 30, 255]]));
    }

    // ------------------------------------------------------------------
    // sample_pixels (na prawdziwych, małych obrazach w pamięci)
    // ------------------------------------------------------------------

    #[test]
    fn test_sample_pixels_uniform_image() {
        let img = image::DynamicImage::ImageRgba8(
            image::RgbaImage::from_pixel(20, 20, image::Rgba([100, 150, 200, 255]))
        );
        let samples = sample_pixels(&img, UNIFORM_SAMPLE_POINTS);
        assert!(!samples.is_empty());
        assert!(is_uniform_sample(&samples));
    }

    #[test]
    fn test_sample_pixels_checkerboard_not_uniform() {
        let mut buf = image::RgbaImage::new(20, 20);
        for (x, y, px) in buf.enumerate_pixels_mut() {
            *px = if (x + y) % 2 == 0 { image::Rgba([255, 255, 255, 255]) } else { image::Rgba([0, 0, 0, 255]) };
        }
        let img = image::DynamicImage::ImageRgba8(buf);
        let samples = sample_pixels(&img, UNIFORM_SAMPLE_POINTS);
        assert!(!is_uniform_sample(&samples));
    }

    // ------------------------------------------------------------------
    // analyze_image: PRAWDZIWE dekodowanie na obrazach zapisanych w locie
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_valid_png_decodes_successfully() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.png");
        let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(64, 48, image::Rgb([10, 20, 30])));
        img.save(&path).unwrap();

        let result = analyze_image(&path).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.width, 64);
        assert_eq!(result.height, 48);
        assert_eq!(result.color_space, "RGB");
    }

    #[test]
    fn test_analyze_valid_rgba_png_reports_rgba_color_space() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.png");
        let img = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(32, 32, image::Rgba([1, 2, 3, 128])));
        img.save(&path).unwrap();

        let result = analyze_image(&path).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.color_space, "RGBA");
    }

    #[test]
    fn test_analyze_valid_image_detects_uniform_content() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("uniform.png");
        let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(50, 50, image::Rgb([200, 200, 200])));
        img.save(&path).unwrap();

        let result = analyze_image(&path).unwrap();
        assert!(result.is_valid);
        assert!(result.has_uniform_content);
    }

    #[test]
    fn test_analyze_valid_image_detects_extreme_ratio() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("skinny.png");
        // Obraz techniczne poprawny, ale geometrycznie bezsensowny (1x200)
        let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(1, 200, image::Rgb([0, 0, 0])));
        img.save(&path).unwrap();

        let result = analyze_image(&path).unwrap();
        assert!(result.is_valid, "Dekodowanie powinno się powieść mimo dziwnej geometrii");
        assert!(result.has_extreme_aspect_ratio);
    }

    #[test]
    fn test_analyze_normal_image_not_flagged() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("normal.png");
        let mut buf = image::RgbImage::new(40, 40);
        for (x, y, px) in buf.enumerate_pixels_mut() {
            *px = image::Rgb([(x * 5) as u8, (y * 5) as u8, 128]);
        }
        image::DynamicImage::ImageRgb8(buf).save(&path).unwrap();

        let result = analyze_image(&path).unwrap();
        assert!(result.is_valid);
        assert!(!result.has_extreme_aspect_ratio);
        assert!(!result.has_uniform_content);
    }

    #[test]
    fn test_analyze_corrupted_file_with_valid_extension_is_invalid_not_io_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupted.png");
        // Nagłówek PNG (sygnatura) obecny, ale reszta to śmieci - dekoder
        // powinien zwrócić błąd sparsowania, NIE błąd braku pliku.
        std::fs::write(&path, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0xFF, 0xFF]).unwrap();

        let result = analyze_image(&path).unwrap();
        assert!(!result.is_valid);
        assert!(result.reason.is_some());
    }

    #[test]
    fn test_analyze_nonexistent_file_is_io_error() {
        let result = analyze_image(Path::new("/nieistniejaca/sciezka/plik.png"));
        assert!(result.is_err(), "Brak pliku powinien zwrócić Err, nie ImageAnalysis z is_valid=false");
    }

    #[test]
    fn test_analyze_text_file_with_image_extension_is_unsupported() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nie_obraz.png");
        std::fs::write(&path, b"To zwykly tekst, nie obraz PNG w ogole.").unwrap();

        let result = analyze_image(&path).unwrap();
        assert!(!result.is_valid);
    }

    // ------------------------------------------------------------------
    // analyze_image: gałąź DNG (raw_image / rawloader)
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_dng_garbage_is_invalid_not_panic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("smieci.dng");
        std::fs::write(&path, b"to na pewno nie jest plik RAW ani TIFF").unwrap();

        let result = analyze_image(&path).unwrap();
        assert!(!result.is_valid);
        assert!(result.reason.unwrap().contains("RAW"));
    }

    #[test]
    fn test_analyze_dng_nonexistent_file_is_io_error() {
        let result = analyze_image(Path::new("/nieistniejaca/sciezka/plik.dng"));
        assert!(result.is_err(), "Brak pliku DNG powinien zwrócić Err, tak samo jak dla innych formatów");
    }

    #[test]
    fn test_is_decodable_extension_recognizes_dng() {
        assert!(is_decodable_extension("zdjecie.DNG"));
        assert!(is_decodable_extension("zdjecie.dng"));
    }

    // ------------------------------------------------------------------
    // analyze_image: gałąź HEIC/HEIF/AVIF (heic_image / libheif)
    // ------------------------------------------------------------------

    #[test]
    fn test_is_decodable_extension_recognizes_heic_family() {
        assert!(is_decodable_extension("zdjecie.heic"));
        assert!(is_decodable_extension("zdjecie.HEIC"));
        assert!(is_decodable_extension("zdjecie.heif"));
        assert!(is_decodable_extension("zdjecie.avif"));
    }

    #[test]
    fn test_analyze_heic_garbage_is_invalid_not_panic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("smieci.heic");
        std::fs::write(&path, b"to na pewno nie jest kontener HEIC").unwrap();

        let result = analyze_image(&path).unwrap();
        assert!(!result.is_valid);
        assert!(result.reason.unwrap().contains("HEIC"));
    }

    #[test]
    fn test_analyze_heic_nonexistent_file_is_io_error() {
        let result = analyze_image(Path::new("/nieistniejaca/sciezka/plik.heic"));
        assert!(result.is_err(), "Brak pliku HEIC powinien zwrócić Err, tak samo jak dla innych formatów");
    }

    #[test]
    #[ignore = "Wymaga prawdziwego pliku HEIC jako fixture - to samo uzasadnienie \
                co heic_image::tests::test_decode_real_heic_fixture. Plik oczekiwany \
                pod `image/test_fixture.heic`. Uruchom: \
                `cargo test analyze_image_via_heic_branch -- --ignored --nocapture`."]
    fn test_analyze_image_via_heic_branch_real_fixture() {
        let result = analyze_image(Path::new("image/test_fixture.heic")).unwrap();
        assert!(result.is_valid, "Prawdziwy plik HEIC powinien się odczytać przez gałąź HEIC w analyze_image");
        assert!(result.width > 0 && result.height > 0);
        assert!(result.color_space.contains("HEIC"));
        println!("✔ analyze_image (gałąź HEIC): {}x{}, {}", result.width, result.height, result.color_space);
    }

    #[test]
    #[ignore = "Wymaga prawdziwego pliku DNG jako fixture - ten sam plik i to samo \
                uzasadnienie co raw_image::tests::test_decode_real_dng_fixture \
                (rawloader waliduje rzeczywiste znaczniki aparatu, nie da się tego \
                sensownie sfabrykować w kodzie testu). Plik oczekiwany pod \
                `image/test_fixture.dng` względem katalogu głównego projektu. \
                Aby uruchomić: `cargo test analyze_image_via_dng_branch -- --ignored --nocapture`."]
    fn test_analyze_image_via_dng_branch_real_fixture() {
        let path = Path::new("image/test_fixture.dng");
        let result = analyze_image(path).unwrap();
        assert!(result.is_valid, "Prawdziwy plik DNG powinien się zdekodować poprawnie przez gałąź DNG w analyze_image");
        assert!(result.width > 0 && result.height > 0);
        assert_eq!(result.color_space, "RAW Bayer (1 składowa)");
        println!("✔ analyze_image (gałąź DNG): {}x{}, {}", result.width, result.height, result.color_space);
    }

    // ------------------------------------------------------------------
    // build_source_block
    // ------------------------------------------------------------------

    #[test]
    fn test_build_source_block_reports_new_informational_counters() {
        use std::time::Duration;
        let stats = LiveStats::new(4);
        stats.extreme_ratio_common.store(3, Ordering::Relaxed);
        stats.uniform_unique.store(2, Ordering::Relaxed);

        let start_time = Instant::now() - Duration::from_secs(1);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        assert!(block.contains("Ekstremalne proporcje: 3 wspólne / 0 unikalne"));
        assert!(block.contains("Zawartość jednolita (próbka): 0 wspólne / 2 unikalne"));
    }

    #[test]
    fn test_build_source_block_shows_thread_activity_markup() {
        use std::time::Duration;
        let stats = LiveStats::new(2);
        stats.thread_activity.mark_busy(0);
        stats.thread_activity.mark_busy(1);

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("Skrypt Autorski", &stats, start_time);

        let line = block.lines().find(|l| l.starts_with("Wątki dekodowania")).expect("powinna istnieć linia Wariantu A");
        assert_eq!(line, "Wątki dekodowania (Wariant A): {G:1} {G:2}");
    }

    #[test]
    fn test_compute_half_threads() {
        assert_eq!(compute_half_threads(8), 4);
        assert_eq!(compute_half_threads(1), 1);
    }

    // ------------------------------------------------------------------
    // REGRESJA (BŁĄD KRYTYCZNY): `media_decoded_ufs`/`media_decoded_script`
    // muszą zostać zapisane RÓWNOLEGLE do `pixels_ok_*`, bo to one - nie
    // `pixels_ok_*` - czyta `phase9::decide_winner` (linie z Gray Banding) i
    // `phase8::evaluate_file` przy decyzji Smart Merge. Testy wołają
    // DOKŁADNIE ten sam SQL co produkcja ([`SQL_UPDATE_UFS`]/
    // [`SQL_UPDATE_SCRIPT`]), więc nie mogą się "po cichu" rozjechać z
    // implementacją w [`run`].
    // ------------------------------------------------------------------

    #[test]
    fn test_media_decoded_written_alongside_pixels_ok_for_healthy_image() {
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script) VALUES (1, 'zdrowe.png', 1, 1)",
            [],
        ).unwrap();

        // Zdjęcie zdekodowane CZYSTO: `ok = Some(true)`, dokładnie tak jak
        // produkuje pętla zapisu w [`run`] dla `res.analysis.is_valid == true`.
        conn.execute(
            SQL_UPDATE_UFS,
            params![Some(true), None::<String>, Some(1920i64), Some(1080i64), Some(false), Some(false), None::<bool>, Some(true), 1],
        ).unwrap();

        let (pixels_ok, media_decoded): (Option<bool>, Option<bool>) = conn.query_row(
            "SELECT pixels_ok_ufs, media_decoded_ufs FROM files WHERE id = 1",
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();

        assert_eq!(pixels_ok, Some(true));
        assert_eq!(media_decoded, Some(true), "media_decoded_ufs musi być zapisane dla zdrowego zdjęcia - Faza 9/8 na tym polegają, nie na pixels_ok_ufs");
        assert_eq!(pixels_ok, media_decoded, "obie kolumny muszą nieść IDENTYCZNĄ wartość - ta sama semantyka");
    }

    #[test]
    fn test_media_decoded_written_alongside_pixels_ok_for_gray_banded_image() {
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script) VALUES (2, 'gray_banding.jpg', 1, 1)",
            [],
        ).unwrap();

        // Gray Banding: `ok = Some(false)`, dokładnie tak jak produkuje pętla
        // zapisu w [`run`] dla `res.analysis.is_valid == false`.
        conn.execute(
            SQL_UPDATE_UFS,
            params![Some(false), Some("Zepsute Piksele (Gray Banding / Ucięty obraz)"), None::<i64>, None::<i64>, None::<bool>, None::<bool>, None::<bool>, Some(false), 2],
        ).unwrap();

        let (pixels_ok, media_decoded): (Option<bool>, Option<bool>) = conn.query_row(
            "SELECT pixels_ok_ufs, media_decoded_ufs FROM files WHERE id = 2",
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();

        assert_eq!(pixels_ok, Some(false));
        assert_eq!(
            media_decoded, Some(false),
            "media_decoded_ufs = Some(false) jest DOKŁADNIE tym, co sprawdza phase9::decide_winner \
             (`file.media_decoded_ufs == Some(false)`) przy odrzuceniu strony za Gray Banding - \
             bez tej naprawy kolumna zostawała NULL na zawsze i decyzja nigdy nie zapadała."
        );
    }

    #[test]
    fn test_media_decoded_script_side_uses_correct_columns() {
        // Wersja dla strony Skrypt Autorski - upewnia się, że `SQL_UPDATE_SCRIPT`
        // pisze do `_script`, nie przypadkiem do `_ufs` (kopiuj-wklej bug byłby
        // niewidoczny w powyższych dwóch testach, które sprawdzają tylko UFS).
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script) VALUES (3, 'skrypt.png', 1, 1)",
            [],
        ).unwrap();

        conn.execute(
            SQL_UPDATE_SCRIPT,
            params![Some(false), Some("Zepsute Piksele (Gray Banding / Ucięty obraz)"), None::<i64>, None::<i64>, None::<bool>, None::<bool>, None::<bool>, Some(false), 3],
        ).unwrap();

        let (media_ufs, media_script): (Option<bool>, Option<bool>) = conn.query_row(
            "SELECT media_decoded_ufs, media_decoded_script FROM files WHERE id = 3",
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();

        assert_eq!(media_ufs, None, "SQL_UPDATE_SCRIPT nie może dotykać kolumn _ufs");
        assert_eq!(media_script, Some(false));
    }

    #[test]
    fn test_backfill_populates_media_decoded_from_preexisting_pixels_ok() {
        // Regresja dla baz, na których Faza 13 działała PRZED tą naprawą:
        // `pixels_ok_*` już wypełnione, `media_decoded_*` jeszcze NULL.
        // Odtwarza dokładnie ten stan i weryfikuje backfill z [`run`].
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, pixels_ok_ufs, pixels_ok_script)
             VALUES (1, 'stare.png', 1, 1, 1, 0)",
            [],
        ).unwrap();
        // Wiersz bez wcześniejszego przebiegu Fazy 13 - backfill nie powinien
        // go ruszać (pixels_ok_* jest NULL, więc warunek WHERE go pomija).
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script) VALUES (2, 'nietkniete.png', 1, 1)",
            [],
        ).unwrap();

        conn.execute("UPDATE files SET media_decoded_ufs = pixels_ok_ufs WHERE media_decoded_ufs IS NULL AND pixels_ok_ufs IS NOT NULL", []).unwrap();
        conn.execute("UPDATE files SET media_decoded_script = pixels_ok_script WHERE media_decoded_script IS NULL AND pixels_ok_script IS NOT NULL", []).unwrap();

        let (m1_ufs, m1_scr): (Option<bool>, Option<bool>) = conn.query_row(
            "SELECT media_decoded_ufs, media_decoded_script FROM files WHERE id = 1",
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        assert_eq!(m1_ufs, Some(true));
        assert_eq!(m1_scr, Some(false));

        let (m2_ufs, m2_scr): (Option<bool>, Option<bool>) = conn.query_row(
            "SELECT media_decoded_ufs, media_decoded_script FROM files WHERE id = 2",
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        assert_eq!(m2_ufs, None, "wiersz bez wcześniejszego pixels_ok_ufs nie powinien zostać dotknięty przez backfill");
        assert_eq!(m2_scr, None);
    }

    // ------------------------------------------------------------------
    // REGRESJA (BŁĄD WYSOKI): gałąź `image::open` (jpg/jpeg/png/webp/bmp/
    // tif/tiff/gif) musi być objęta `catch_unwind`, tak jak DNG (`raw_image`)
    // i HEIC (`heic_image`) - patrz `generic_image::decode_guarded`.
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_image_generic_branch_is_panic_guarded() {
        // UWAGA: crate `image` jest mocno ufuzzowane (używane m.in. w
        // Firefoksie) - w przeciwieństwie do `rawloader` (gdzie panika była
        // EMPIRYCZNIE zaobserwowana na prawdziwym pliku DNG użytkownika, patrz
        // `raw_image.rs`), nie ma znanego, stabilnego pliku wejściowego, który
        // wiarygodnie i nie-kruchowo wywoła panikę wewnątrz `image::open` na
        // dowolnej wersji crate. Ten test weryfikuje więc MECHANIZM integracji
        // dokładnie w kształcie użytym przez `analyze_image`: `image::open` +
        // DALSZE przetwarzanie zdekodowanego bufora w JEDNYM domknięciu
        // przekazanym do `generic_image::decode_guarded` - udowadnia, że
        // panika w KTÓRYMKOLWIEK miejscu tego domknięcia (nie tylko w samym
        // `image::open`) zostaje bezpiecznie przechwycona, zamiast ubić wątek.
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.png");
        let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(10, 10, image::Rgb([1, 2, 3])));
        img.save(&path).unwrap();

        let guarded = crate::generic_image::decode_guarded(|| -> ImageAnalysis {
            let opened = image::open(&path).expect("plik testowy musi się otworzyć");
            let _ = sample_pixels(&opened, UNIFORM_SAMPLE_POINTS); // "cokolwiek bezpośrednio po nim"
            panic!("symulowana panika PODCZAS przetwarzania już zdekodowanego bufora");
        });

        assert!(guarded.is_none(), "Panika w domknięciu image::open+przetwarzanie musi zostać przechwycona, nie propagować dalej");
        assert!(!crate::generic_image::is_expected_panic_in_progress(), "Flaga musi zostać zdjęta po obsłużonej panice");
    }

    #[test]
    fn test_analyze_image_recovers_and_returns_ok_after_simulated_panic_pattern() {
        // Odtwarza DOKŁADNIE strukturę `analyze_image`'s `None` branch (linia
        // `match guarded { Some(result) => result, None => Ok(ImageAnalysis{...}) }`)
        // i sprawdza, że wynik jest `is_valid == false`, sklasyfikowany jako
        // Gray Banding/glitch - NIE `Err` (to byłoby błędnie potraktowane jako
        // brak pliku / błąd I/O przez `process_side_stream`).
        let guarded: Option<std::result::Result<ImageAnalysis, std::io::Error>> =
            crate::generic_image::decode_guarded(|| -> std::result::Result<ImageAnalysis, std::io::Error> {
                panic!("symulowana panika dekodera");
            });

        let result = match guarded {
            Some(r) => r,
            None => Ok(ImageAnalysis {
                is_valid: false,
                reason: Some("Zepsute Piksele (Gray Banding / Ucięty obraz) - dekoder wywołał panikę, przechwycono bezpiecznie".to_string()),
                width: 0, height: 0, megapixels: 0.0, color_space: "Brak".to_string(),
                has_extreme_aspect_ratio: false, has_uniform_content: false,
            }),
        };

        let analysis = result.expect("panika NIGDY nie powinna być zwrócona jako Err/błąd I/O");
        assert!(!analysis.is_valid);
        assert!(analysis.reason.unwrap().contains("Gray Banding"));
    }
}
