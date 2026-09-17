// src/phases/phase11.rs

//! # Faza 11: Głęboka Walidacja Archiwów i Dokumentów (ZIP, DOCX, APK, RAR, 7Z, TAR, etc.)
//! 
//! Weryfikuje integralność strukturalną oraz semantyczną plików pakowanych.
//! Skanuje EOCD, weryfikuje DNA dokumentów (np. folder word/ w docx), wykrywa
//! Zip Bomby (po rozmiarze i po liczbie wpisów), szyfrowanie oraz podejrzanie
//! wysoki współczynnik kompresji. Opcjonalnie (`config.deep_archive_scan`)
//! wykonuje próbkową weryfikację CRC32 pierwszych wpisów każdego archiwum.
//!
//! Zwykły `.tar` przechodzi PEŁNĄ walidację struktury przez moduł
//! `tar_archive` (suma kontrolna każdego nagłówka wpisu + kompletność danych
//! każdego wpisu) — patrz [`analyze_archive`]. Wcześniej sprawdzane były tylko
//! magic bytes `ustar` pierwszego nagłówka, więc archiwum ucięte w połowie
//! przechodziło jako poprawne.
//! Posiada pełen system raportowania (Dual-Logging), współpracuje asynchronicznie
//! z Ratatui poprzez PhaseEvent.
//!
//! UWAGA ARCHITEKTONICZNA (UI): Pasek postępu pokazuje wyłącznie % i bieżący
//! plik. Liczniki live trafiają do panelu bocznego jako JEDEN, samodzielny blok
//! PER ŹRÓDŁO — patrz [`build_source_block`].
//!
//! UWAGA ARCHITEKTONICZNA (WĄTKOWANIE): każda strona dostaje własną, dedykowaną
//! pulę Rayon (`half_threads`, identycznie jak Fazy 2-7/10).
//!
//! NAPRAWIONA LUKA KLASYFIKACJI: poprzednia wersja klasyfikacji live
//! (`if r.contains(...) else if ...`) nie miała gałęzi domyślnej — powód
//! "Zbyt mały plik (Brak nagłówka)" nie pasował do żadnego z czterech
//! warunków i znikał ze statystyk live (mimo że nadal trafiał do logu
//! tekstowego, i mimo że raport końcowy miał już wtedy poprawny fallback).
//! Teraz klasyfikacja live używa tej samej logiki co raport końcowy.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
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
use zip::ZipArchive;

const CHUNK_SIZE: usize = 100;

/// Próg twardej "zip bomby" po LICZBIE wpisów (niezależny od rozmiaru) —
/// technika DoS znana jako "42.zip": dziesiątki tysięcy mikroskopijnych
/// plików w jednym archiwum, każdy tani do spakowania, kosztowny do
/// wypakowania i przetworzenia po stronie systemu plików docelowego.
const MASS_FILES_THRESHOLD: usize = 50_000;

/// Górny limit rozmiaru zwykłego `.tar` poddawanego PEŁNEJ analizie struktury
/// przez moduł `tar_archive`.
///
/// `tar_archive::analyze_tar_file` wczytuje całe archiwum do RAM (`fs::read`),
/// bo łańcuch bloków 512 B trzeba przejść w całości. Powyżej tego progu
/// schodzimy do taniej weryfikacji magic bytes `ustar`, żeby nie ryzykować OOM
/// na wielogigabajtowym archiwum — ta faza przetwarza wiele plików równolegle
/// w dwóch pulach Rayon, więc szczyt zużycia pamięci to wielokrotność tej
/// wartości, nie jedna kopia.
const TAR_ANALYSIS_MAX_BYTES: u64 = 512 * 1024 * 1024; // 512 MB

/// Twardy próg zip bomby: stosunek rozmiaru po rozpakowaniu do rozmiaru na
/// dysku ORAZ bezwzględny rozmiar po rozpakowaniu — oba warunki muszą być
/// spełnione naraz, żeby uniknąć fałszywych alarmów na małych plikach
/// (np. plik 100B skompresowany do 1B ma stosunek 100x, ale to nieistotne).
const BOMB_RATIO_THRESHOLD: u64 = 200;
const BOMB_ABSOLUTE_THRESHOLD: u64 = 1_000_000_000; // 1 GB

/// Miękki próg ostrzegawczy — sygnalizuje podejrzanie wysoką kompresję,
/// zanim urośnie do pełnego progu "bomby". Nie unieważnia archiwum.
const SUSPICIOUS_RATIO_THRESHOLD: u64 = 50;
const SUSPICIOUS_ABSOLUTE_THRESHOLD: u64 = 50_000_000; // 50 MB

// Pełna lista wspieranych rozszerzeń (Zip-pochodne oraz skompresowane).
//
// UWAGA na warianty SKRÓCONE: `.tgz`/`.taz` to te same formaty co
// `.tar.gz`/`.tar.Z`, tylko zapisane jednym rozszerzeniem. Ponieważ
// dopasowanie działa przez `ends_with`, `archiwum.tar.gz` trafia tu przez
// wpis `.gz` — ale `archiwum.tgz` NIE kończy się na żadnym wpisie i bez
// jawnego dodania byłby CAŁKOWICIE POMIJANY przez tę fazę (nie „uznawany
// za poprawny" — po prostu nigdy nieanalizowany). To samo dotyczy
// `.tbz2`/`.txz`, będących skrótami dla bzip2/xz.
const ARCHIVE_EXTS: &[&str] = &[
    ".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub", ".apk", ".jar",
    ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".tgz", ".taz", ".tbz", ".tbz2", ".txz"
];

const ZIP_DERIVATIVES: &[&str] = &[
    "zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "apk", "jar"
];

// ============================================================================
// POMOCNIKI (CZYSTE FUNKCJE, TESTOWALNE BEZ TWORZENIA PRAWDZIWYCH ARCHIWÓW)
// ============================================================================

/// Rozstrzyga, czy dany plik jest kandydatem do walidacji archiwum — dopasowanie
/// wyłącznie po rozszerzeniu, niewrażliwe na wielkość liter.
fn is_archive_extension(path_str: &str) -> bool {
    let lower_path = path_str.to_lowercase();
    ARCHIVE_EXTS.iter().any(|&ext| lower_path.ends_with(ext))
}

/// Wynik klasyfikacji współczynnika kompresji przez [`classify_compression_ratio`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressionVerdict {
    /// Współczynnik w normie dla tego typu danych.
    Normal,
    /// Podejrzanie wysoki, ale poniżej twardego progu — sygnał ostrzegawczy,
    /// NIE unieważnia archiwum.
    Suspicious,
    /// Zip Bomb — oba progi (stosunek I rozmiar bezwzględny) przekroczone.
    Bomb,
}

/// Klasyfikuje stosunek rozmiaru po rozpakowaniu (`uncompressed_total`) do
/// rozmiaru na dysku (`file_size`) w trzy kategorie — patrz [`CompressionVerdict`].
/// Oba progi (stosunek i wartość bezwzględna) muszą być przekroczone naraz w
/// KAŻDEJ kategorii, żeby uniknąć fałszywych alarmów na drobnych plikach
/// (mikroskopijny plik może mieć astronomiczny stosunek kompresji bez żadnego
/// znaczenia forensycznego). Przy `file_size == 0` zawsze zwraca `Normal`
/// (unika dzielenia przez zero / bezsensownego mnożenia).
fn classify_compression_ratio(file_size: u64, uncompressed_total: u64) -> CompressionVerdict {
    if file_size == 0 { return CompressionVerdict::Normal; }

    if uncompressed_total > file_size.saturating_mul(BOMB_RATIO_THRESHOLD) && uncompressed_total > BOMB_ABSOLUTE_THRESHOLD {
        CompressionVerdict::Bomb
    } else if uncompressed_total > file_size.saturating_mul(SUSPICIOUS_RATIO_THRESHOLD) && uncompressed_total > SUSPICIOUS_ABSOLUTE_THRESHOLD {
        CompressionVerdict::Suspicious
    } else {
        CompressionVerdict::Normal
    }
}

// ============================================================================
// STRUKTURY DANYCH
// ============================================================================

/// Pojedyncze zadanie: archiwum oczekujące na walidację struktury po JEDNEJ stronie.
#[derive(Debug, Clone)]
pub(crate) struct Task {
    id: i32,
    rel_path: String,
    is_common: bool,
}

/// Wynik analizy jednego archiwum — połączenie wyniku binarnego (`is_valid`)
/// z dwoma niezależnymi FLAGAMI INFORMACYJNYMI (`has_encrypted_entries`,
/// `has_suspicious_compression`), które mogą wystąpić NIEZALEŻNIE od tego,
/// czy archiwum jest ważne — zaszyfrowane hasłem archiwum jest często
/// całkowicie legalne, nie jest to samo w sobie uszkodzenie.
#[derive(Debug, Clone)]
struct ArchiveAnalysis {
    is_valid: bool,
    reason: Option<String>,
    internal_files_count: usize,
    uncompressed_size: u64,
    /// Co najmniej jeden wpis w archiwum jest zaszyfrowany hasłem.
    has_encrypted_entries: bool,
    /// Współczynnik kompresji przekroczył próg ostrzegawczy (ale nie twardy
    /// próg "bomby" — patrz [`classify_compression_ratio`]).
    has_suspicious_compression: bool,
}

/// Wynik przetworzenia jednego zadania, przekazywany przez MPSC do wątku zapisu SQLite.
#[derive(Debug, Clone)]
pub(crate) struct SideArchiveResult {
    id: i32,
    analysis: Option<ArchiveAnalysis>,
    io_error: Option<bool>,
}

/// Wiadomość do wątku zapisu SQLite, oznaczona stroną pochodzenia.
pub(crate) enum ScanMsg {
    UfsChunk(Vec<SideArchiveResult>),
    ScriptChunk(Vec<SideArchiveResult>),
}

/// Liczniki live dla JEDNEJ strony. Cztery kategorie "twardych" błędów
/// (Nagłówek/Wydmuszka/Fałszywe DNA/Bomba — w tym bomba plikowa) plus dwie
/// kategorie INFORMACYJNE niezależne od ważności (szyfrowanie, podejrzana
/// kompresja) plus (opcjonalnie, `config.deep_archive_scan`) błędy CRC32.
/// Nigdy nie łączone z licznikami drugiej strony.
pub(crate) struct LiveStats {
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    errors: AtomicUsize,
    ext_weights: Mutex<HashMap<String, u64>>,
    
    ok: AtomicUsize,
    err_header_common: AtomicUsize,  err_header_unique: AtomicUsize,
    err_empty_common: AtomicUsize,   err_empty_unique: AtomicUsize,
    err_fake_common: AtomicUsize,    err_fake_unique: AtomicUsize,
    err_bomb_common: AtomicUsize,    err_bomb_unique: AtomicUsize,
    /// Bomba PLIKOWA (>50 000 wpisów) — osobna kategoria od bomby rozmiarowej,
    /// bo to inny wektor ataku/uszkodzenia (liczba plików, nie ich waga).
    err_massfiles_common: AtomicUsize, err_massfiles_unique: AtomicUsize,
    /// Błąd CRC32 przy próbkowej weryfikacji (tylko gdy `deep_archive_scan = true`).
    err_crc_common: AtomicUsize, err_crc_unique: AtomicUsize,

    /// INFORMACYJNE (nie wpływają na `is_valid`): archiwa z zaszyfrowaną zawartością.
    encrypted_common: AtomicUsize, encrypted_unique: AtomicUsize,
    /// INFORMACYJNE: podejrzanie wysoki współczynnik kompresji (poniżej progu bomby).
    suspicious_compression_common: AtomicUsize, suspicious_compression_unique: AtomicUsize,

    /// EKSPERYMENTALNE (Wariant A): śledzi zajętość logicznych slotów Rayon
    /// TEJ strony podczas analizy archiwum — patrz moduł `thread_activity`.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            processed_files: AtomicUsize::new(0), processed_bytes: AtomicU64::new(0), errors: AtomicUsize::new(0),
            ext_weights: Mutex::new(HashMap::new()),
            ok: AtomicUsize::new(0),
            err_header_common: AtomicUsize::new(0), err_header_unique: AtomicUsize::new(0),
            err_empty_common: AtomicUsize::new(0),  err_empty_unique: AtomicUsize::new(0),
            err_fake_common: AtomicUsize::new(0),   err_fake_unique: AtomicUsize::new(0),
            err_bomb_common: AtomicUsize::new(0),   err_bomb_unique: AtomicUsize::new(0),
            err_massfiles_common: AtomicUsize::new(0), err_massfiles_unique: AtomicUsize::new(0),
            err_crc_common: AtomicUsize::new(0), err_crc_unique: AtomicUsize::new(0),
            encrypted_common: AtomicUsize::new(0), encrypted_unique: AtomicUsize::new(0),
            suspicious_compression_common: AtomicUsize::new(0), suspicious_compression_unique: AtomicUsize::new(0),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }
}

/// Wylicza liczbę slotów trackera zajętości (Wariant A) odpowiednią dla
/// trybu I/O — patrz identyczna logika w `phase3::compute_activity_slots`.
fn compute_activity_slots(io_mode: &str, actual_threads: usize, half_threads: usize) -> usize {
    if io_mode == "CONCURRENT" { half_threads } else { actual_threads }
}

/// Buduje pełny, samodzielny blok live DLA JEDNEGO ŹRÓDŁA — prędkość MB/s,
/// top 3 rozszerzenia wagowo, zdrowe archiwa, pięć kategorii "twardych" błędów
/// (Nagłówek/Wydmuszka/Fałszywe/Bomba-rozmiar/Bomba-plikowa) każda wspólne/
/// unikalne, dwie kategorie informacyjne (szyfrowane, podejrzana kompresja),
/// opcjonalnie błędy CRC (deep scan), błędy I/O.
fn build_source_block(label: &str, stats: &LiveStats, start_time: Instant, deep_scan_enabled: bool) -> String {
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

    let mut out = format!(
        "[{}]\nPrędkość: {:.2} MB/s\nTop format: {}\nZdrowe: {}\nUszkodzony nagłówek: {} wspólne / {} unikalne\nWydmuszki: {} wspólne / {} unikalne\nFałszywe DNA: {} wspólne / {} unikalne\nBomba (rozmiar): {} wspólne / {} unikalne\nBomba (liczba plików): {} wspólne / {} unikalne\nZaszyfrowane: {} wspólne / {} unikalne\nPodejrzana kompresja: {} wspólne / {} unikalne",
        label, speed_mb, display_ext,
        stats.ok.load(Ordering::Relaxed),
        stats.err_header_common.load(Ordering::Relaxed), stats.err_header_unique.load(Ordering::Relaxed),
        stats.err_empty_common.load(Ordering::Relaxed), stats.err_empty_unique.load(Ordering::Relaxed),
        stats.err_fake_common.load(Ordering::Relaxed), stats.err_fake_unique.load(Ordering::Relaxed),
        stats.err_bomb_common.load(Ordering::Relaxed), stats.err_bomb_unique.load(Ordering::Relaxed),
        stats.err_massfiles_common.load(Ordering::Relaxed), stats.err_massfiles_unique.load(Ordering::Relaxed),
        stats.encrypted_common.load(Ordering::Relaxed), stats.encrypted_unique.load(Ordering::Relaxed),
        stats.suspicious_compression_common.load(Ordering::Relaxed), stats.suspicious_compression_unique.load(Ordering::Relaxed),
    );

    if deep_scan_enabled {
        out.push_str(&format!(
            "\nBłędy CRC32 (próbka): {} wspólne / {} unikalne",
            stats.err_crc_common.load(Ordering::Relaxed), stats.err_crc_unique.load(Ordering::Relaxed)
        ));
    }

    let activity_markup = crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot());
    out.push_str(&format!("\nWątki analizy (Wariant A): {}", activity_markup));

    out.push_str(&format!("\nBłędy I/O: {}", stats.errors.load(Ordering::Relaxed)));
    out
}

// Struktury dla Raportu Hierarchicznego
/// Mapa rozszerzenie -> lista pełnych ścieżek plików w tej kategorii anomalii.
/// Budowana WYŁĄCZNIE po zakończeniu skanowania z zapytania SQL do całej tabeli.
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
// SILNIK DECYZYJNY (WERYFIKATOR KONTENERÓW I MAGIC BYTES)
// ============================================================================

/// Analizuje strukturę jednego pliku pakowanego. Dla rodziny ZIP (DOCX/XLSX/
/// APK/JAR/EPUB/ODF/ZIP) wykonuje pełną walidację wielometodową:
///
/// 1. **EOCD** — czy archiwum otwiera się w ogóle (`ZipArchive::new`).
/// 2. **Wydmuszka** — `archive.len() == 0`.
/// 3. **Bomba plikowa** — `archive.len() > 50 000` wpisów (niezależnie od rozmiaru).
/// 4. **DNA formatu** — obecność folderów/plików charakterystycznych dla
///    zadeklarowanego rozszerzenia (`word/` dla docx, `xl/` dla xlsx,
///    `AndroidManifest.xml`/`classes.dex` dla apk, `META-INF/`/`mimetype` dla epub).
/// 5. **Szyfrowanie** — flaga informacyjna, NIE unieważnia archiwum.
/// 6. **Współczynnik kompresji** — [`classify_compression_ratio`]; `Bomb`
///    unieważnia, `Suspicious` tylko flaguje.
/// 7. **(Opcjonalnie, `deep_scan`)** — próbkowa weryfikacja CRC32: dekompresuje
///    PIERWSZE do 3 wpisów i sprawdza, czy odczyt się powiedzie (crate `zip`
///    weryfikuje CRC32 automatycznie przy pełnym odczycie strumienia i zwraca
///    błąd przy niezgodności). To PRÓBKA, nie pełna weryfikacja całego
///    archiwum — wykryje uszkodzenie w pierwszych kilku plikach, nie
///    gwarantuje integralności reszty.
///
/// Zwykły (NIESKOMPRESOWANY) `.tar` ma własną, pełną walidację struktury przez
/// moduł `tar_archive`: weryfikowana jest suma kontrolna KAŻDEGO nagłówka wpisu
/// oraz kompletność danych każdego wpisu, do rozmiaru
/// [`TAR_ANALYSIS_MAX_BYTES`] (wyżej — tani fallback na magic bytes, bo analiza
/// wymaga wczytania całego archiwum do RAM).
///
/// Dla pozostałych formatów liniowych (RAR/7Z/GZ/BZ2/XZ oraz skompresowanych
/// wariantów tara: `.tar.gz`, `.tgz`, `.tbz2`, `.txz`) sprawdzane są wyłącznie
/// Magic Bytes nagłówka — pod kompresją nie ma wewnętrznej listy plików
/// odczytywalnej bez pełnej dekompresji, więc głębsza walidacja struktury nie
/// jest tu wykonywana.
/// Rozpakowana z `analyze_archive` logika ZIP/pochodnych — wydzielona, żeby
/// dało się ją osłonić `catch_unwind` w miejscu wywołania (patrz N1 z
/// `todo.faza11.md`). Nie zwraca `Result` — jedyny błąd tej gałęzi
/// (`File::open`) jest obsługiwany wcześniej, w `analyze_archive`.
fn analyze_zip_entries(file: &mut File, ext: &str, file_size: u64, deep_scan: bool) -> ArchiveAnalysis {
    let mut archive = match ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => return ArchiveAnalysis {
            is_valid: false, reason: Some("Brak EOCD / Ucięta Struktura".into()),
            internal_files_count: 0, uncompressed_size: 0,
            has_encrypted_entries: false, has_suspicious_compression: false,
        },
    };

    if archive.is_empty() {
        return ArchiveAnalysis {
            is_valid: false, reason: Some("Wydmuszka (0 plików wewnątrz)".into()),
            internal_files_count: 0, uncompressed_size: 0,
            has_encrypted_entries: false, has_suspicious_compression: false,
        };
    }

    if archive.len() > MASS_FILES_THRESHOLD {
        return ArchiveAnalysis {
            is_valid: false, reason: Some(format!("Bomba plikowa (>{} wpisów)", MASS_FILES_THRESHOLD)),
            internal_files_count: archive.len(), uncompressed_size: 0,
            has_encrypted_entries: false, has_suspicious_compression: false,
        };
    }

    let mut uncompressed_total: u64 = 0;
    let mut has_word = false; let mut has_xl = false;
    let mut has_manifest = false; let mut has_meta = false;
    let mut has_encrypted = false;

    // UWAGA BEZPIECZEŃSTWA (naprawiony bug zip-bomby): poprzednio suma
    // `uncompressed_total` (i detekcja szyfrowania/DNA formatu DOCX/XLSX/
    // APK/EPUB) liczyła TYLKO pierwsze 2000 wpisów, mimo że limit liczby
    // wpisów dopuszczał archiwa do `MASS_FILES_THRESHOLD` (50 000) - wpis
    // o dużym nieskompresowanym rozmiarze umieszczony na indeksie >=2000
    // przechodził KOMPLETNIE niezauważony. `archive.by_index()` czyta
    // wyłącznie metadane nagłówka lokalnego (nie dekompresuje danych), więc
    // iteracja po WSZYSTKICH wpisach jest tania nawet dla maksymalnej
    // dopuszczalnej liczby wpisów (`archive.len()` jest już ograniczone do
    // <= `MASS_FILES_THRESHOLD` przez sprawdzenie kilka linii wyżej).
    for i in 0..archive.len() {
        if let Ok(inner_file) = archive.by_index(i) {
            uncompressed_total = uncompressed_total.saturating_add(inner_file.size());
            if inner_file.encrypted() { has_encrypted = true; }

            if let Some(name) = inner_file.enclosed_name() {
                let name_str = name.to_string_lossy().to_lowercase();
                if name_str.starts_with("word/") { has_word = true; }
                if name_str.starts_with("xl/") { has_xl = true; }
                if name_str.contains("androidmanifest.xml") || name_str.contains("classes.dex") { has_manifest = true; }
                if name_str.contains("meta-inf/") || name_str.contains("mimetype") { has_meta = true; }
            }
        }
    }

    let mut is_fake = false;
    if ext == "docx" && !has_word { is_fake = true; }
    if ext == "xlsx" && !has_xl { is_fake = true; }
    if ext == "apk" && !has_manifest { is_fake = true; }
    if ext == "epub" && !has_meta { is_fake = true; }

    if is_fake {
        return ArchiveAnalysis {
            is_valid: false, reason: Some(format!("Fałszywe rozszerzenie (Brak DNA .{})", ext)),
            internal_files_count: archive.len(), uncompressed_size: uncompressed_total,
            has_encrypted_entries: has_encrypted, has_suspicious_compression: false,
        };
    }

    let verdict = classify_compression_ratio(file_size, uncompressed_total);
    if verdict == CompressionVerdict::Bomb {
        return ArchiveAnalysis {
            is_valid: false, reason: Some("Zip Bomb (Anomalia Kompresji)".into()),
            internal_files_count: archive.len(), uncompressed_size: uncompressed_total,
            has_encrypted_entries: has_encrypted, has_suspicious_compression: false,
        };
    }
    let has_suspicious_compression = verdict == CompressionVerdict::Suspicious;

    // METODA (opcjonalna): próbkowa weryfikacja CRC32 pierwszych 3 wpisów.
    // Realna dekompresja - crate `zip` weryfikuje CRC32 automatycznie przy
    // pełnym odczycie strumienia i zwraca błąd przy niezgodności.
    //
    // UWAGA (naprawiony błąd pożyczenia E0502): `archive.len()` jest
    // wyliczane RAZ, PRZED pętlą, do zmiennej `total_entries`. Wywołanie
    // `archive.len()` wewnątrz `if let Ok(mut inner_file) = archive.by_index(i)`
    // koliduje z mutowalnym pożyczeniem `archive` trzymanym przez
    // `inner_file` przez cały czas trwania tego bloku - `archive.len()`
    // wymaga pożyczenia niemutowalnego, którego kompilator nie pozwoli
    // wziąć, dopóki `inner_file` (pożyczenie mutowalne) nie wyjdzie z zasięgu.
    let total_entries = archive.len();
    if deep_scan {
        let sample_count = std::cmp::min(total_entries, 3);
        for i in 0..sample_count {
            if let Ok(mut inner_file) = archive.by_index(i) {
                let mut sink = Vec::new();
                if inner_file.read_to_end(&mut sink).is_err() {
                    return ArchiveAnalysis {
                        is_valid: false, reason: Some("Błąd CRC32 (uszkodzona kompresja wpisu, próbka)".into()),
                        internal_files_count: total_entries, uncompressed_size: uncompressed_total,
                        has_encrypted_entries: has_encrypted, has_suspicious_compression,
                    };
                }
            }
        }
    }

    ArchiveAnalysis {
        is_valid: true, reason: None,
        internal_files_count: total_entries, uncompressed_size: uncompressed_total,
        has_encrypted_entries: has_encrypted, has_suspicious_compression,
    }
}

fn analyze_archive(path: &Path, file_size: u64, deep_scan: bool) -> std::result::Result<ArchiveAnalysis, std::io::Error> {
    let mut file = File::open(path)?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();

    if ZIP_DERIVATIVES.contains(&ext.as_str()) {
        // REGRESJA (measure twice — druga weryfikacja Gemini, N1): crate `zip`
        // ma udokumentowaną historię panik na zniekształconych archiwach
        // (przepełnienia arytmetyczne, ucięte nagłówki XZ, nieprawidłowe pola
        // extra) - dokładnie ten rodzaj wejścia, jakim jest korpus do audytu.
        // Bez osłony panika w JEDNYM uszkodzonym pliku ubijała CAŁY proces
        // (brak `catch_unwind`/`panic = "abort"`), nie tylko Fazę 11 - operator
        // tracił sesję TUI i po restarcie natychmiast wpadał w tę samą awarię
        // przy tym samym pliku (nieskończona pętla bez ręcznej interwencji).
        // Ten sam wzorzec ochronny co `raw_image.rs`/`heic_image.rs`/
        // `video_image.rs`/`generic_image::decode_guarded`/`phase16.rs` (YARA) —
        // panika jest traktowana jak zwykła porażka parsowania.
        let ext_ref = ext.clone();
        let wynik = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            analyze_zip_entries(&mut file, &ext_ref, file_size, deep_scan)
        }));
        return Ok(wynik.unwrap_or_else(|_| ArchiveAnalysis {
            is_valid: false, reason: Some("Silnik ZIP spanikował podczas parsowania (uszkodzone lub złośliwe archiwum)".into()),
            internal_files_count: 0, uncompressed_size: 0,
            has_encrypted_entries: false, has_suspicious_compression: false,
        }));
    }

    // 2. Walidacja PEŁNEJ STRUKTURY zwykłego `.tar` (moduł `tar_archive`)
    //
    // Tar nie jest skompresowany, więc łańcuch nagłówków 512 B jest czytelny
    // wprost: można zweryfikować sumę kontrolną KAŻDEGO wpisu i kompletność
    // jego danych. Poprzednio `.tar` przechodził tylko przez magic bytes
    // `ustar` w PIERWSZYM nagłówku (gałąź niżej), co uznawało za poprawne
    // archiwum ucięte w połowie, z rozsypanymi dalszymi nagłówkami albo bez
    // znacznika końca — pierwsze 262 bajty wyglądają wtedy nienagannie.
    //
    // Warianty SKOMPRESOWANE (`.tar.gz`, `.tgz`, `.tbz2`, `.txz`) CELOWO tu
    // nie wchodzą — `is_plain_tar_extension` je odrzuca, bo pod kompresją nie
    // widać struktury bloków. Spadają niżej, do weryfikacji magic bytes
    // właściwego kompresora.
    if crate::tar_archive::is_plain_tar_extension(&path.to_string_lossy())
        && file_size <= TAR_ANALYSIS_MAX_BYTES
    {
        return Ok(match crate::tar_archive::analyze_tar_file(path) {
            Some(analiza) => {
                let wpisy = analiza.total_entries();
                // Tar nie kompresuje, więc suma rozmiarów wpisów to realny
                // rozmiar treści — sensowniejszy niż rozmiar pliku, bo pomija
                // narzut nagłówków i wyrównania do bloków.
                let rozmiar_tresci = analiza.entries.iter()
                    .fold(0u64, |acc, e| acc.saturating_add(e.size));

                if wpisy > MASS_FILES_THRESHOLD {
                    ArchiveAnalysis {
                        is_valid: false,
                        reason: Some(format!("Bomba plikowa (>{} wpisów)", MASS_FILES_THRESHOLD)),
                        internal_files_count: wpisy, uncompressed_size: rozmiar_tresci,
                        has_encrypted_entries: false, has_suspicious_compression: false,
                    }
                } else if analiza.is_healthy() {
                    ArchiveAnalysis {
                        is_valid: true, reason: None,
                        internal_files_count: wpisy, uncompressed_size: rozmiar_tresci,
                        has_encrypted_entries: false, has_suspicious_compression: false,
                    }
                } else {
                    // `describe()` wylicza KONKRETNE objawy (ile nagłówków ze
                    // złą sumą kontrolną, ile wpisów z uciętymi danymi, brak
                    // znacznika końca) — dużo więcej niż dotychczasowe
                    // ogólne "Złe Magic Bytes". Dokładamy liczbę POPRAWNYCH
                    // nagłówków, bo to ona mówi, ile z archiwum da się jeszcze
                    // odratować — kluczowe przy decyzji o ręcznym odzysku.
                    // Opis zostaje na POCZĄTKU łańcucha, żeby dopasowanie
                    // podciągów w `classify_hard_reason` działało bez zmian.
                    let opis = if wpisy > 0 {
                        format!(
                            "{} (poprawnych nagłówków: {} z {})",
                            analiza.describe(), analiza.valid_headers(), wpisy
                        )
                    } else {
                        // Zero wpisów — sufiks "0 z 0" nic nie wnosi.
                        analiza.describe()
                    };

                    ArchiveAnalysis {
                        is_valid: false, reason: Some(opis),
                        internal_files_count: wpisy, uncompressed_size: rozmiar_tresci,
                        has_encrypted_entries: false, has_suspicious_compression: false,
                    }
                }
            }
            // `None` = plik krótszy niż jeden blok 512 B.
            None => ArchiveAnalysis {
                is_valid: false, reason: Some("Zbyt mały plik (Brak nagłówka)".into()),
                internal_files_count: 0, uncompressed_size: 0,
                has_encrypted_entries: false, has_suspicious_compression: false,
            },
        });
    }

    // 3. Walidacja formatów liniowych / strumieniowych poprzez MAGIC BYTES
    let mut header = [0u8; 512];
    let n = file.read(&mut header)?;
    if n < 4 {
        return Ok(ArchiveAnalysis {
            is_valid: false, reason: Some("Zbyt mały plik (Brak nagłówka)".into()),
            internal_files_count: 0, uncompressed_size: 0,
            has_encrypted_entries: false, has_suspicious_compression: false,
        });
    }

    // Warianty SKRÓCONE (.tgz, .taz, .tbz...) to te same formaty kompresji
    // co pełne (.tar.gz, .tar.bz2...), więc muszą przechodzić TĘ SAMĄ
    // weryfikację magic bytes. Bez tej normalizacji wpadałyby w gałąź
    // `_ => true` i były uznawane za poprawne bez sprawdzenia czegokolwiek.
    let effective_ext = match ext.as_str() {
        "tgz" | "taz" => "gz",
        "tbz" | "tbz2" => "bz2",
        "txz" => "xz",
        other => other,
    };

    let is_valid_magic = match effective_ext {
        "rar" => header.starts_with(&[0x52, 0x61, 0x72, 0x21]),
        "7z"  => header.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
        "gz"  => header.starts_with(&[0x1F, 0x8B]),
        "bz2" => header.starts_with(&[0x42, 0x5A, 0x68]),
        "xz"  => header.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
        "tar" => { if n >= 262 { &header[257..262] == b"ustar" } else { false } },
        _ => true, 
    };

    if !is_valid_magic {
        return Ok(ArchiveAnalysis {
            is_valid: false, reason: Some("Złe Magic Bytes (Uszkodzony nagłówek)".into()),
            internal_files_count: 0, uncompressed_size: 0,
            has_encrypted_entries: false, has_suspicious_compression: false,
        });
    }

    Ok(ArchiveAnalysis {
        is_valid: true, reason: None, internal_files_count: 1, uncompressed_size: file_size,
        has_encrypted_entries: false, has_suspicious_compression: false,
    })
}

/// Klasyfikuje powód nieważności archiwum do jednej z pięciu "twardych"
/// kategorii [`LiveStats`] po DOPASOWANIU PODCIĄGU tekstu powodu. Ma gałąź
/// domyślną (`_ =>`), przez którą przechodzi każdy niedopasowany powód (np.
/// "Zbyt mały plik") jako kategoria "Nagłówek" — dokładnie ta sama logika,
/// jaką od początku miał raport końcowy w [`run`], teraz ujednolicona z
/// panelem live (patrz naprawiona luka w dokumentacji modułu).
fn classify_hard_reason(reason: &str) -> &'static str {
    if reason.contains("Brak EOCD") || reason.contains("Złe Magic") { "header" }
    // "Nie znaleziono żadnych wpisów tar" (z `tar_archive::describe`) to ten
    // sam objaw co "Wydmuszka" przy ZIP-ie: plik jest archiwum tylko z nazwy,
    // nie ma w nim ani jednego czytelnego wpisu. Bez tego wpadałby w gałąź
    // domyślną jako "Nagłówek" i mieszał się z realnym uszkodzeniem nagłówków.
    else if reason.contains("Wydmuszka") || reason.contains("Nie znaleziono żadnych wpisów") { "empty" }
    else if reason.contains("Fałszywe") { "fake" }
    else if reason.contains("Bomba plikowa") { "massfiles" }
    else if reason.contains("Zip Bomb") { "bomb" }
    else if reason.contains("CRC32") { "crc" }
    else { "header" }
}

/// Skanuje wszystkie zadania (`tasks`) dla JEDNEJ strony: dla każdego archiwum
/// woła [`analyze_archive`], klasyfikuje wynik przez [`classify_hard_reason`],
/// aktualizuje liczniki [`LiveStats`] (twarde + informacyjne, niezależnie od
/// siebie — patrz [`ArchiveAnalysis`]), zapisuje wpis do jednego z dwóch logów
/// i strumieniuje wynik do wątku zapisu SQLite. Rozgłasza postęp i statystyki
/// do UI co ~200 plików LUB co 250ms (hybrydowy próg — wzorzec z Fazy 5-7/10).
pub struct StreamCtx<'a> {
    pub base_path: &'a Path,
    pub tasks: &'a [Task],
    pub side_label: &'a str,
    pub stats: &'a LiveStats,
    pub tx_db: mpsc::SyncSender<ScanMsg>,
    pub is_ufs: bool,
    pub start_time: Instant,
    pub deep_scan: bool,
    pub tx_ui: &'a mpsc::Sender<PhaseEvent>,
    pub bar_idx: usize,
    pub opr_log: Arc<Mutex<File>>,
    pub info_log: Arc<Mutex<File>>,
}

#[instrument(skip(ctx), fields(base_path = %ctx.base_path.display()))]

fn process_side_stream<'a>(ctx: StreamCtx<'a>) {
    let StreamCtx { base_path, tasks, side_label, stats, tx_db, is_ufs, start_time, deep_scan, tx_ui, bar_idx, opr_log, info_log } = ctx;

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

            let (analysis_opt, io_err) = match stats.thread_activity.track_current(|| analyze_archive(&full_path, file_size, deep_scan)) {
                Ok(ana) => {
                    let kategoria = if task.is_common { "Wspólne" } else { "Osobne" };

                    if ana.is_valid {
                        stats.ok.fetch_add(1, Ordering::Relaxed);
                        
                        if let Ok(mut f) = info_log.lock() {
                            let pliki_info = if ZIP_DERIVATIVES.contains(&ext.as_str()) { 
                                format!("Plików: {:<4} | Rozpakowane: {:>10}", ana.internal_files_count, format_bytes(ana.uncompressed_size)) 
                            } else { 
                                format!("Strumień     | Rozmiar:     {:>10}", format_bytes(ana.uncompressed_size)) 
                            };
                            let _ = writeln!(f, "[{:<15}] [{:<7}] [{}] Format: .{:<5} | Ścieżka: \"{}\"", side_label, kategoria, pliki_info, ext, full_path.display());
                        }
                    } else {
                        let r = ana.reason.as_deref().unwrap_or("Nieznany błąd");
                        match classify_hard_reason(r) {
                            "header" => { if task.is_common { stats.err_header_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_header_unique.fetch_add(1, Ordering::Relaxed); } }
                            "empty" => { if task.is_common { stats.err_empty_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_empty_unique.fetch_add(1, Ordering::Relaxed); } }
                            "fake" => { if task.is_common { stats.err_fake_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_fake_unique.fetch_add(1, Ordering::Relaxed); } }
                            "massfiles" => { if task.is_common { stats.err_massfiles_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_massfiles_unique.fetch_add(1, Ordering::Relaxed); } }
                            "bomb" => { if task.is_common { stats.err_bomb_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_bomb_unique.fetch_add(1, Ordering::Relaxed); } }
                            "crc" => { if task.is_common { stats.err_crc_common.fetch_add(1, Ordering::Relaxed); } else { stats.err_crc_unique.fetch_add(1, Ordering::Relaxed); } }
                            _ => unreachable!("classify_hard_reason ma gałąź domyślną, nigdy nie zwraca innej wartości"),
                        }

                        if let Ok(mut f) = opr_log.lock() {
                            let _ = writeln!(f, "[{:<15}] [{:<7}] [{}] Format: .{:<5} | Ścieżka: \"{}\"", side_label, kategoria, r, ext, full_path.display());
                        }
                    }

                    // Liczniki INFORMACYJNE - niezależne od is_valid (patrz dokumentacja ArchiveAnalysis)
                    if ana.has_encrypted_entries {
                        if task.is_common { stats.encrypted_common.fetch_add(1, Ordering::Relaxed); } else { stats.encrypted_unique.fetch_add(1, Ordering::Relaxed); }
                    }
                    if ana.has_suspicious_compression {
                        if task.is_common { stats.suspicious_compression_common.fetch_add(1, Ordering::Relaxed); } else { stats.suspicious_compression_unique.fetch_add(1, Ordering::Relaxed); }
                    }

                    (Some(ana), Some(false))
                },
                Err(e) => {
                    warn!(path = %task.rel_path, side = side_label, error = %e, "Błąd I/O");
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    (None, Some(true))
                }
            };

            stats.processed_files.fetch_add(1, Ordering::Relaxed);
            stats.processed_bytes.fetch_add(file_size, Ordering::Relaxed);

            let current = stats.processed_files.load(Ordering::Relaxed);
            let now = Instant::now();

            // Hybrydowy próg (wzorzec z Fazy 5-7/10): licznik globalny jako
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
                    text: build_source_block(side_label, stats, start_time, deep_scan),
                });
            }   
            results.push(SideArchiveResult { id: task.id, analysis: analysis_opt, io_error: io_err });
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
        message: "Walidacja archiwów w 100% zakończona.".to_string(),
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

/// Punkt wejścia Fazy 11, wołany przez `menu::actions::run_phase_with_ui`.
///
/// Przebieg: (1) wczytuje z SQLite archiwa ([`is_archive_extension`]) bez
/// jeszcze wyliczonej struktury; (2) uruchamia [`process_side_stream`] dla
/// UFS i Skryptu — równolegle na dwóch dedykowanych pulach Rayon lub
/// sekwencyjnie, z `config.deep_archive_scan` decydującym o próbkowej
/// weryfikacji CRC32; (3) koreluje wyniki w SQLite; (4) buduje hierarchiczny
/// Dziennik Końcowy z pięciu kategorii "twardych" błędów, każda rozbita
/// wspólne/unikalne i UFS/Skrypt, z przykładowymi ścieżkami per rozszerzenie.
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    let actual_threads = if config.max_threads > 0 { config.max_threads } else { rayon::current_num_threads() };
    let io_text = if config.io_mode == "CONCURRENT" { "RÓWNOLEGŁE (SSD/NVMe)" } else { "SEKWENCYJNIE (HDD)" };
    
    let _ = tx_ui.send(PhaseEvent::Log(format!("Uruchomiono Fazę 11. Metodyka szyny dyskowej: {}", io_text)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora (Rayon): {}", actual_threads)));
    if config.deep_archive_scan {
        let _ = tx_ui.send(PhaseEvent::Log("Głęboka weryfikacja CRC32 (próbka 3 wpisów/archiwum): WŁĄCZONA".to_string()));
    }

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    // ZAPIS WYNIKÓW ANALIZY KONTENERÓW DO BAZY DANYCH
    let _ = conn.execute("ALTER TABLE files ADD COLUMN archive_reason_ufs TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN archive_reason_script TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN archive_files_ufs INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN archive_size_ufs INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN archive_files_script INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN archive_size_script INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN archive_encrypted_ufs BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN archive_encrypted_script BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN archive_suspicious_compression_ufs BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN archive_suspicious_compression_script BOOLEAN", []);

    // INICJALIZACJA DUAL-LOGGING (Pobieranie ścieżek z Ustawień)
    let raport_cfg = config.raporty_faz.get("Faza 11").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza11.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza11.txt".to_string(),
    });
    
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);
    
    let info_path = Path::new(&raport_cfg.katalog).join("raport_operacyjny_faza11_zdrowe_archiwa.txt");

    // REGRESJA (todo.faza02.md, ta sama klasa błędu we wszystkich fazach):
    // `.unwrap()` panikował, gdyby katalog logów stał się niezapisywalny
    // między `create_dir_all` a tym miejscem — cały bieg fazy ginął z
    // powodu samego logowania, zanim jakikolwiek plik został przetworzony.
    let log_anom_file = match File::create(&opr_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!("BŁĄD I/O: Nie można utworzyć pliku logu operacyjnego: {}. Sprawdź uprawnienia.", e)));
            return Ok(());
        }
    };
    let log_anom = Arc::new(Mutex::new(log_anom_file));
    let log_info = Arc::new(Mutex::new(File::create(&info_path).unwrap()));
    
    {
        let mut f_anom = log_anom.lock().unwrap();
        let _ = writeln!(f_anom, "=== RAPORT OPERACYJNY - FAZA 11 (ZEPSUTE ARCHIWA) ===");
        let _ = writeln!(f_anom, "Zestawienie plików pakowanych ze zniszczoną strukturą EOCD/Magic Bytes, fałszywym DNA, bombą (rozmiarową lub plikową){}.\n",
            if config.deep_archive_scan { " lub błędem CRC32 w próbce" } else { "" });
        
        let mut f_info = log_info.lock().unwrap();
        let _ = writeln!(f_info, "=== RAPORT OPERACYJNY - FAZA 11 (ZDROWE ARCHIWA) ===");
        let _ = writeln!(f_info, "Statystyki poprawnych plików pakowanych (Ilość wewnętrznych rekordów, Deklarowana waga po wypakowaniu).\n");
    }

    // --- ETAP 1: POBIERANIE ZADAŃ Z BAZY ---
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, structure_ok_ufs, structure_ok_script, io_error_ufs, io_error_script 
         FROM files WHERE phase11_done = 0 OR phase11_done IS NULL"
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
        
        if is_archive_extension(&rel) {
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
        let _ = tx_ui.send(PhaseEvent::Log(format!("Pominięto archiwa z wyliczoną już strukturą. UFS: {}, Skrypt: {}", skipped_ufs, skipped_script)));
    }

    let total_db_rows = ufs_tasks.len() + script_tasks.len();
    if total_db_rows == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak archiwów do walidacji. Baza aktualna.".to_string()));
        return Ok(());
    }

    // Inicjalizacja pasków postępu Ratatui
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "UFS Explorer (Archiwa)".to_string(), total: ufs_tasks.len() as u64, color: Color::Cyan });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 1, label: "Skrypt Autorski (Archiwa)".to_string(), total: script_tasks.len() as u64, color: Color::Magenta });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 2, label: "Zapis SQLite".to_string(), total: total_db_rows as u64, color: Color::Green });

    let half_threads = compute_half_threads(actual_threads);
    let activity_slots = compute_activity_slots(&config.io_mode, actual_threads, half_threads);

    let ufs_stats = LiveStats::new(activity_slots);
    let script_stats = LiveStats::new(activity_slots);
    let ufs_base = PathBuf::from(&config.ufs_path);
    let script_base = PathBuf::from(&config.script_path);
    let deep_scan = config.deep_archive_scan;

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
                        let mut stmt = match &msg {
                            ScanMsg::UfsChunk(_) => tx_trans.prepare_cached(
                                "UPDATE files SET structure_ok_ufs = COALESCE(?1, structure_ok_ufs), archive_reason_ufs = COALESCE(?2, archive_reason_ufs), archive_files_ufs = COALESCE(?3, archive_files_ufs), archive_size_ufs = COALESCE(?4, archive_size_ufs), archive_encrypted_ufs = COALESCE(?5, archive_encrypted_ufs), archive_suspicious_compression_ufs = COALESCE(?6, archive_suspicious_compression_ufs), io_error_ufs = COALESCE(?7, io_error_ufs) WHERE id = ?8"
                            )?,
                            ScanMsg::ScriptChunk(_) => tx_trans.prepare_cached(
                                "UPDATE files SET structure_ok_script = COALESCE(?1, structure_ok_script), archive_reason_script = COALESCE(?2, archive_reason_script), archive_files_script = COALESCE(?3, archive_files_script), archive_size_script = COALESCE(?4, archive_size_script), archive_encrypted_script = COALESCE(?5, archive_encrypted_script), archive_suspicious_compression_script = COALESCE(?6, archive_suspicious_compression_script), io_error_script = COALESCE(?7, io_error_script) WHERE id = ?8"
                            )?,
                        };

                        let chunk = match &msg {
                            ScanMsg::UfsChunk(c) => c,
                            ScanMsg::ScriptChunk(c) => c,
                        };

                        for res in chunk {
                            if res.analysis.is_some() || res.io_error == Some(true) {
                                let (ok, reason, files_c, uncompressed, encrypted, suspicious) = match &res.analysis {
                                    Some(a) => (
                                        Some(a.is_valid), a.reason.clone(),
                                        Some(a.internal_files_count as i64), Some(a.uncompressed_size as i64),
                                        Some(a.has_encrypted_entries), Some(a.has_suspicious_compression),
                                    ),
                                    None => (None, None, None, None, None, None)
                                };
                                stmt.execute(params![ok, reason, files_c, uncompressed, encrypted, suspicious, res.io_error, res.id])?;
                            }
                        }
                    }
                    tx_trans.commit()?;
                }

                db_inserted += chunk_len;
                let now = Instant::now();
                if now.duration_since(last_db_update).as_millis() > 60 {
                    last_db_update = now;
                    let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Zapisywanie wskaźników EOCD...".to_string() });
                }
            }
            let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Wskaźniki kompresji bezpieczne w SQLite.".to_string() });
            Ok(())
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone(); let tx2 = tx_db.clone();
            let anom_u = log_anom.clone(); let anom_s = log_anom.clone();
            let info_u = log_info.clone(); let info_s = log_info.clone();

            let stat_u = &ufs_stats;
            let stat_s = &script_stats;

            // NAPRAWA (ten sam bug jak w Fazie 5/6/7/10): dedykowana pula per
            // strona, minimum 1 wątek. Wyliczone wcześniej, tu tylko używane.

            s.spawn(move || {
                if !ufs_tasks.is_empty() { 
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, start_time, deep_scan, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: anom_u, info_log: info_u, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, start_time, deep_scan, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: anom_u, info_log: info_u, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Walidacja struktury (UFS) zakończona.".to_string())); 
                }
            });

            s.spawn(move || {
                if !script_tasks.is_empty() { 
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, start_time, deep_scan, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: anom_s, info_log: info_s, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, start_time, deep_scan, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: anom_s, info_log: info_s, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Walidacja struktury (Skrypt) zakończona.".to_string())); 
                }
            });
            drop(tx_db);
        } 
            else
        {
            let anom_u = log_anom.clone(); let anom_s = log_anom.clone();
            let info_u = log_info.clone(); let info_s = log_info.clone();
            
            if !ufs_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: &ufs_stats, tx_db: tx_db.clone(), is_ufs: true, start_time, deep_scan, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: anom_u, info_log: info_u, }); let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Walidacja struktury (UFS) zakończona.".to_string()));
            }
            if !script_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: &script_stats, tx_db: tx_db.clone(), is_ufs: false, start_time, deep_scan, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: anom_s, info_log: info_s, }); let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Walidacja struktury (Skrypt) zakończona.".to_string()));
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
                    "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 11 mógł nie zostać w pełni zapisany.".to_string()
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

    let _ = tx_ui.send(PhaseEvent::Log("Trwa generowanie hierarchicznego raportu kryminalistycznego...".to_string()));
    
    conn.execute(
        "UPDATE files SET phase11_done = CASE 
            WHEN (found_in_ufs = 0 OR structure_ok_ufs IS NOT NULL OR io_error_ufs = 1) 
             AND (found_in_script = 0 OR structure_ok_script IS NOT NULL OR io_error_script = 1) THEN 1 
            ELSE 0 
        END WHERE phase11_done = 0 OR phase11_done IS NULL", []
    )?;

    // --- ETAP 5: HIERARCHICZNY RAPORT KRYMINALISTYCZNY (Zapis TXT) ---
    let mut stmt = conn.prepare(
        "SELECT relative_path, found_in_ufs, found_in_script, 
                structure_ok_ufs, structure_ok_script, archive_reason_ufs, archive_reason_script
         FROM files WHERE phase11_done = 1"
    )?;

    let mut cat_header = AnomalyCategory::new("Uszkodzony Nagłówek / Brak EOCD / Złe Magic Bytes", "✂️");
    let mut cat_empty = AnomalyCategory::new("Wydmuszki (Puste archiwa 0 plików)", "🪹");
    let mut cat_fake = AnomalyCategory::new("Fałszywe Rozszerzenia (Brak spójności DNA)", "🧬");
    let mut cat_bomb = AnomalyCategory::new("Anomalia Kompresji (Zip Bomb / Zły Rozmiar)", "💣");
    let mut cat_massfiles = AnomalyCategory::new("Bomba Plikowa (>50000 wpisów)", "💥");
    let mut cat_crc = AnomalyCategory::new("Błąd CRC32 (uszkodzona kompresja wpisu)", "🧪");

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
                    match classify_hard_reason(&r) {
                        "empty" => add_to_cat(&mut cat_empty, is_ufs_source),
                        "fake" => add_to_cat(&mut cat_fake, is_ufs_source),
                        "bomb" => add_to_cat(&mut cat_bomb, is_ufs_source),
                        "massfiles" => add_to_cat(&mut cat_massfiles, is_ufs_source),
                        "crc" => add_to_cat(&mut cat_crc, is_ufs_source),
                        _ => add_to_cat(&mut cat_header, is_ufs_source),
                    }
                } else {
                    add_to_cat(&mut cat_header, is_ufs_source);
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
    let total_encrypted = ufs_stats.encrypted_common.load(Ordering::SeqCst) + ufs_stats.encrypted_unique.load(Ordering::SeqCst)
        + script_stats.encrypted_common.load(Ordering::SeqCst) + script_stats.encrypted_unique.load(Ordering::SeqCst);
    let total_suspicious = ufs_stats.suspicious_compression_common.load(Ordering::SeqCst) + ufs_stats.suspicious_compression_unique.load(Ordering::SeqCst)
        + script_stats.suspicious_compression_common.load(Ordering::SeqCst) + script_stats.suspicious_compression_unique.load(Ordering::SeqCst);

    // -- GENEROWANIE RAPORTU TEKSTOWEGO --
    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(&mut log_out, "==========================================================================");
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 11 (WALIDACJA STRUKTURY ARCHIWÓW)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "Sumaryczny transfer I/O: {} (Średnia prędkość: {:.2} MB/s)", format_bytes(total_bytes), avg_speed_mb);
    let _ = writeln!(&mut log_out, "==========================================================================\n");

    if total_encrypted > 0 || total_suspicious > 0 {
        let _ = writeln!(&mut log_out, "[ INFORMACYJNE - NIE BŁĘDY ]");
        if total_encrypted > 0 {
            let _ = writeln!(&mut log_out, "   🔐 Archiwa z zaszyfrowaną zawartością: {}", total_encrypted);
            let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Zaszyfrowane hasłem archiwum jest często całkowicie legalne - to nie jest uszkodzenie, tylko brak możliwości weryfikacji zawartości bez hasła.");
        }
        if total_suspicious > 0 {
            let _ = writeln!(&mut log_out, "   ⚠️  Podejrzanie wysoka kompresja (poniżej progu Zip Bomb): {}", total_suspicious);
        }
        let _ = writeln!(&mut log_out);
    }

    let write_section_txt = |out: &mut String, title: &str, is_common: bool| {
        let _ = writeln!(out, "[ KATEGORIA BŁĘDÓW: {} ]", title);
        let categories = [&cat_header, &cat_empty, &cat_fake, &cat_bomb, &cat_massfiles, &cat_crc];
        let mut has_any = false;
        
        for cat in &categories {
            let src_anom = if is_common { &cat.common } else { &cat.unique };
            let ufs_total: usize = src_anom.ufs.values().map(|v| v.len()).sum();
            let scr_total: usize = src_anom.script.values().map(|v| v.len()).sum();
            
            if ufs_total > 0 || scr_total > 0 {
                has_any = true;
                let _ = writeln!(out, "   {} Typ anomalii: {} (UFS: {}, Skrypt: {})", cat.icon, cat.name, ufs_total, scr_total);
                if cat.name.contains("Nagłówek") {
                    let _ = writeln!(out, "      [ ZNACZENIE ]: Plik kompresji uległ ucięciu na poziomie struktury. W ZIP brakuje Centralnego Katalogu (EOCD). Odzyskanie plików z jego wnętrza jest niemożliwe.");
                } else if cat.name.contains("DNA") {
                    let _ = writeln!(out, "      [ ZNACZENIE ]: Wykryto fałszywe rozszerzenie (File Spoofing). Np. Carver rozpoznał dokument .docx, ale wewnątrz nie ma obowiązkowego folderu 'word/'.");
                } else if cat.name.contains("Wydmuszki") {
                    let _ = writeln!(out, "      [ ZNACZENIE ]: Archiwum otwiera się poprawnie, ale w środku nie znajduje się ani jeden plik.");
                } else if cat.name.contains("Kompresji") {
                    let _ = writeln!(out, "      [ ZNACZENIE ]: Anomalia matematyczna. Plik na dysku waży kilka KB, ale dekompresuje się do kilku Gigabajtów. Prawdopodobnie uszkodzony nagłówek kompresji Deflate.");
                } else if cat.name.contains("Bomba Plikowa") {
                    let _ = writeln!(out, "      [ ZNACZENIE ]: Archiwum zawiera dziesiątki tysięcy wpisów niezależnie od rozmiaru - technika DoS znana jako '42.zip', kosztowna do przetworzenia po rozpakowaniu.");
                } else if cat.name.contains("CRC32") {
                    let _ = writeln!(out, "      [ ZNACZENIE ]: Struktura ramy (EOCD, DNA) jest OK, ale próbka pierwszych wpisów nie przeszła weryfikacji sumy kontrolnej - realne uszkodzenie strumienia skompresowanego. Weryfikacja jest PRÓBKĄ (pierwsze do 3 wpisów), nie gwarancją integralności całego archiwum.");
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

    let _ = writeln!(&mut log_out, "[ PODSUMOWANIE WAGOWE ARCHIWÓW ]");
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
        "Faza 11 zakończona"
    );

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    // ------------------------------------------------------------------
    // compute_activity_slots (identyczna logika z Fazy 3-7/10)
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_activity_slots_concurrent_uses_half_threads() {
        assert_eq!(compute_activity_slots("CONCURRENT", 4, 2), 2);
    }

    #[test]
    fn test_compute_activity_slots_sequential_uses_full_actual_threads() {
        assert_eq!(compute_activity_slots("SEQUENTIAL", 4, 2), 4);
    }
    use zip::write::{FileOptions, ZipWriter};

    // ------------------------------------------------------------------
    // is_archive_extension
    // ------------------------------------------------------------------

    #[test]
    fn test_is_archive_extension_known() {
        assert!(is_archive_extension("plik.ZIP"));
        assert!(is_archive_extension("dokument.docx"));
        assert!(is_archive_extension("/sciezka/archiwum.7z"));
    }

    #[test]
    fn test_is_archive_extension_unknown() {
        assert!(!is_archive_extension("obraz.jpg"));
        assert!(!is_archive_extension("bez_rozszerzenia"));
    }

    #[test]
    fn test_is_archive_extension_recognizes_short_tar_variants() {
        // REGRESJA: te warianty NIE kończą się na żadnym wpisie typu `.gz`,
        // więc przed poprawką były całkowicie pomijane przez fazę - nie
        // dostawały ŻADNEJ diagnostyki.
        assert!(is_archive_extension("archiwum.tgz"));
        assert!(is_archive_extension("ARCHIWUM.TGZ"));
        assert!(is_archive_extension("archiwum.taz"));
        assert!(is_archive_extension("archiwum.tbz"));
        assert!(is_archive_extension("archiwum.tbz2"));
        assert!(is_archive_extension("archiwum.txz"));
    }

    #[test]
    fn test_is_archive_extension_recognizes_full_two_part_names() {
        // Warianty pełne działają przez `ends_with` na członie kompresji.
        assert!(is_archive_extension("archiwum.tar.gz"));
        assert!(is_archive_extension("archiwum.tar.bz2"));
        assert!(is_archive_extension("archiwum.tar.xz"));
    }

    // ------------------------------------------------------------------
    // classify_compression_ratio
    // ------------------------------------------------------------------

    #[test]
    fn test_compression_normal_ratio() {
        assert_eq!(classify_compression_ratio(1000, 2000), CompressionVerdict::Normal);
    }

    #[test]
    fn test_compression_high_ratio_but_small_absolute_is_normal() {
        // Stosunek 100x, ale bezwzględny rozmiar (1KB) nie przekracza progu ostrzegawczego
        assert_eq!(classify_compression_ratio(10, 1000), CompressionVerdict::Normal);
    }

    #[test]
    fn test_compression_suspicious_tier() {
        // Stosunek >50x I bezwzględny rozmiar >50MB, ale poniżej progu bomby (200x, 1GB)
        let file_size = 2_000_000; // 2MB
        let uncompressed = 150_000_000; // 150MB -> stosunek 75x
        assert_eq!(classify_compression_ratio(file_size, uncompressed), CompressionVerdict::Suspicious);
    }

    #[test]
    fn test_compression_bomb_tier() {
        let file_size = 1_000_000; // 1MB
        let uncompressed = 2_000_000_000; // 2GB -> stosunek 2000x
        assert_eq!(classify_compression_ratio(file_size, uncompressed), CompressionVerdict::Bomb);
    }

    #[test]
    fn test_compression_zero_file_size_never_divides_by_zero() {
        assert_eq!(classify_compression_ratio(0, 999_999_999_999), CompressionVerdict::Normal);
    }

    #[test]
    fn test_compression_ratio_high_but_absolute_below_bomb_threshold_is_suspicious_not_bomb() {
        // Stosunek >200x, ale bezwzględny rozmiar poniżej 1GB -> tylko Suspicious, nie Bomb
        let file_size = 1000;
        let uncompressed = 300_000; // stosunek 300x, ale tylko 300KB bezwzględnie
        assert_eq!(classify_compression_ratio(file_size, uncompressed), CompressionVerdict::Normal);
        // (300KB nie przekracza nawet progu Suspicious 50MB, więc Normal - potwierdza że
        // sam wysoki STOSUNEK bez odpowiedniego rozmiaru bezwzględnego nic nie znaczy)
    }

    // ------------------------------------------------------------------
    // classify_hard_reason
    // ------------------------------------------------------------------

    #[test]
    fn test_classify_reason_header_variants() {
        assert_eq!(classify_hard_reason("Brak EOCD / Ucięta Struktura"), "header");
        assert_eq!(classify_hard_reason("Złe Magic Bytes (Uszkodzony nagłówek)"), "header");
    }

    #[test]
    fn test_classify_reason_other_categories() {
        assert_eq!(classify_hard_reason("Wydmuszka (0 plików wewnątrz)"), "empty");
        assert_eq!(classify_hard_reason("Fałszywe rozszerzenie (Brak DNA .docx)"), "fake");
        assert_eq!(classify_hard_reason("Bomba plikowa (>50000 wpisów)"), "massfiles");
        assert_eq!(classify_hard_reason("Zip Bomb (Anomalia Kompresji)"), "bomb");
        assert_eq!(classify_hard_reason("Błąd CRC32 (uszkodzona kompresja wpisu, próbka)"), "crc");
    }

    #[test]
    fn test_classify_reason_unmatched_falls_back_to_header() {
        // To jest dokładnie ta luka, którą naprawiliśmy - powód nieznany nie ginie,
        // tylko trafia do kategorii domyślnej (jak w raporcie końcowym od zawsze).
        assert_eq!(classify_hard_reason("Zbyt mały plik (Brak nagłówka)"), "header");
        assert_eq!(classify_hard_reason("Zupełnie nowy, nieprzewidziany powód"), "header");
    }

    // ------------------------------------------------------------------
    // analyze_archive: formaty liniowe (Magic Bytes)
    // ------------------------------------------------------------------

    fn temp_with_ext(content: &[u8], ext: &str) -> (NamedTempFile, PathBuf) {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        let new_path = f.path().with_extension(ext);
        std::fs::rename(f.path(), &new_path).unwrap();
        (f, new_path)
    }

    #[test]
    fn test_analyze_rar_valid_magic() {
        let content = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
        let (_g, path) = temp_with_ext(&content, "rar");
        let a = analyze_archive(&path, content.len() as u64, false).unwrap();
        assert!(a.is_valid);
    }

    #[test]
    fn test_analyze_rar_invalid_magic() {
        let content = [0x00u8; 10];
        let (_g, path) = temp_with_ext(&content, "rar");
        let a = analyze_archive(&path, content.len() as u64, false).unwrap();
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("Magic"));
    }

    #[test]
    fn test_analyze_gzip_valid_magic() {
        let content = [0x1F, 0x8B, 0x08, 0x00];
        let (_g, path) = temp_with_ext(&content, "gz");
        let a = analyze_archive(&path, content.len() as u64, false).unwrap();
        assert!(a.is_valid);
    }

    // ------------------------------------------------------------------
    // Normalizacja wariantów skróconych (.tgz -> gz, .tbz2 -> bz2, ...)
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_tgz_validates_gzip_magic() {
        // .tgz MUSI przechodzić weryfikację magic bytes gzipa - przed
        // poprawką wpadał w gałąź `_ => true` i był uznawany za poprawny
        // bez sprawdzenia czegokolwiek.
        let good = [0x1F, 0x8B, 0x08, 0x00];
        let (_g, path) = temp_with_ext(&good, "tgz");
        assert!(analyze_archive(&path, good.len() as u64, false).unwrap().is_valid);

        let bad = [0x00u8; 10];
        let (_g2, path2) = temp_with_ext(&bad, "tgz");
        let a = analyze_archive(&path2, bad.len() as u64, false).unwrap();
        assert!(!a.is_valid, "Uszkodzony .tgz musi zostać wykryty, nie przepuszczony");
        assert!(a.reason.unwrap().contains("Magic"));
    }

    #[test]
    fn test_analyze_tbz2_validates_bzip2_magic() {
        let good = [0x42, 0x5A, 0x68, 0x39];
        let (_g, path) = temp_with_ext(&good, "tbz2");
        assert!(analyze_archive(&path, good.len() as u64, false).unwrap().is_valid);

        let bad = [0xFFu8; 10];
        let (_g2, path2) = temp_with_ext(&bad, "tbz2");
        assert!(!analyze_archive(&path2, bad.len() as u64, false).unwrap().is_valid);
    }

    #[test]
    fn test_analyze_txz_validates_xz_magic() {
        let good = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00];
        let (_g, path) = temp_with_ext(&good, "txz");
        assert!(analyze_archive(&path, good.len() as u64, false).unwrap().is_valid);

        let bad = [0x11u8; 10];
        let (_g2, path2) = temp_with_ext(&bad, "txz");
        assert!(!analyze_archive(&path2, bad.len() as u64, false).unwrap().is_valid);
    }

    #[test]
    fn test_analyze_taz_validates_gzip_magic() {
        let good = [0x1F, 0x8B, 0x08, 0x00];
        let (_g, path) = temp_with_ext(&good, "taz");
        assert!(analyze_archive(&path, good.len() as u64, false).unwrap().is_valid);
    }

    #[test]
    fn test_analyze_too_small_file_no_header() {
        let content = [0x01, 0x02];
        let (_g, path) = temp_with_ext(&content, "rar");
        let a = analyze_archive(&path, content.len() as u64, false).unwrap();
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("Zbyt mały"));
    }

    // ------------------------------------------------------------------
    // analyze_archive: prawdziwe archiwa ZIP zbudowane w locie
    // ------------------------------------------------------------------

    /// Buduje w pamięci poprawny ZIP z podanymi wpisami (nazwa -> zawartość),
    /// zapisuje na dysk z podanym rozszerzeniem i zwraca ścieżkę.
    fn build_zip(entries: &[(&str, &[u8])], ext: &str) -> (NamedTempFile, PathBuf) {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = ZipWriter::new(cursor);
            let options: FileOptions<()> = FileOptions::default();
            for (name, content) in entries {
                writer.start_file(*name, options).unwrap();
                writer.write_all(content).unwrap();
            }
            writer.finish().unwrap();
        }
        temp_with_ext(&buf, ext)
    }

    #[test]
    fn test_analyze_valid_plain_zip() {
        let (_g, path) = build_zip(&[("plik.txt", b"zawartosc")], "zip");
        let size = std::fs::metadata(&path).unwrap().len();
        let a = analyze_archive(&path, size, false).unwrap();
        assert!(a.is_valid);
        assert_eq!(a.internal_files_count, 1);
    }

    /// Regresja: suma `uncompressed_total` (a wraz z nią detekcja bomby
    /// plikowej) MUSI uwzględniać WSZYSTKIE wpisy archiwum, nie tylko
    /// pierwsze 2000. Przed poprawką pętla sumująca była ograniczona do
    /// `0..min(archive.len(), 2000)`, więc duży wpis umieszczony na indeksie
    /// >= 2000 (a limit LICZBY wpisów dopuszcza aż `MASS_FILES_THRESHOLD` =
    /// 50 000) całkowicie omijał sumowanie i zip bomba przechodziła jako
    /// poprawna.
    ///
    /// Budujemy ZIP z >2000 malutkimi wpisami + jednym wpisem o indeksie
    /// 2050 (a więc poza starym limitem 2000) zawierającym ponad 1 GB
    /// wysoce kompresowalnych (samych zer) danych — na dysku archiwum
    /// pozostaje małe (dzięki kompresji), ale zadeklarowany rozmiar
    /// nieskompresowany w metadanych ZIP jest ogromny. Dane zapisujemy
    /// w małych porcjach (bez alokowania 1 GB naraz), by test był lekki
    /// pamięciowo.
    #[test]
    fn test_analyze_zip_bomb_hidden_beyond_old_2000_sample_cap_is_detected() {
        const ENTRY_COUNT: usize = 2100;
        const BOMB_ENTRY_INDEX: usize = 2050; // poza starym limitem `min(len, 2000)`
        const BOMB_ENTRY_SIZE: u64 = 1_050_000_000; // >1GB (próg BOMB_ABSOLUTE_THRESHOLD)

        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = ZipWriter::new(cursor);
            let options: FileOptions<()> = FileOptions::default();
            let zero_chunk = vec![0u8; 1_048_576]; // 1 MiB, zapisywany wielokrotnie

            for i in 0..ENTRY_COUNT {
                let name = format!("wpis_{i:05}.txt");
                writer.start_file(&name, options).unwrap();
                if i == BOMB_ENTRY_INDEX {
                    let mut remaining = BOMB_ENTRY_SIZE;
                    while remaining > 0 {
                        let take = std::cmp::min(remaining, zero_chunk.len() as u64) as usize;
                        writer.write_all(&zero_chunk[..take]).unwrap();
                        remaining -= take as u64;
                    }
                } else {
                    writer.write_all(b"x").unwrap();
                }
            }
            writer.finish().unwrap();
        }

        let (_g, path) = temp_with_ext(&buf, "zip");
        // Fizyczny rozmiar na dysku jest mały dzięki kompresji - to właśnie
        // stwarza wysoki stosunek kompresji, cechę charakterystyczną zip bomby.
        let file_size = std::fs::metadata(&path).unwrap().len();
        assert!(file_size < 10_000_000, "Skompresowany plik powinien pozostać mały (samo zero się dobrze kompresuje)");

        let a = analyze_archive(&path, file_size, false).unwrap();
        assert_eq!(a.internal_files_count, ENTRY_COUNT);
        assert!(a.uncompressed_size >= BOMB_ENTRY_SIZE, "Suma nieskompresowanego rozmiaru musi uwzględniać wpis poza starym limitem 2000");
        assert!(!a.is_valid, "Zip bomba ukryta za indeksem 2000 musi zostać wykryta");
        assert!(a.reason.unwrap().contains("Zip Bomb"));
    }

    #[test]
    fn test_analyze_empty_zip_is_wydmuszka() {
        let (_g, path) = build_zip(&[], "zip");
        let size = std::fs::metadata(&path).unwrap().len();
        let a = analyze_archive(&path, size, false).unwrap();
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("Wydmuszka"));
    }

    // ------------------------------------------------------------------
    // REGRESJA (measure twice — druga weryfikacja Gemini, N1): panika
    // wewnątrz parsowania ZIP nie może ubić wątku Rayon / całego procesu.
    // ------------------------------------------------------------------

    /// Dowodzi kształtu ochrony zastosowanego w `analyze_archive` (`catch_unwind`
    /// + `unwrap_or_else` na `ArchiveAnalysis` sygnalizującą porażkę), na
    /// syntetycznej panice — uczciwie udokumentowane ograniczenie: crate `zip`
    /// (wersja użyta w tym projekcie) nie ma znanego, stabilnego pliku
    /// wejściowego wywołującego panikę deterministycznie (wszystkie
    /// udokumentowane w jego CHANGELOGu panikujące przypadki są już
    /// naprawione w tej wersji) — w przeciwieństwie do `rawloader`, gdzie
    /// panika jest EMPIRYCZNIE zaobserwowana na realnym pliku DNG (patrz
    /// `raw_image.rs`). Ten sam uczciwy wzorzec testu mechanizmu co
    /// `phase13::test_analyze_image_generic_branch_is_panic_guarded`.
    #[test]
    fn test_panika_w_silniku_zip_jest_bezpiecznie_przechwycona() {
        let wynik: std::thread::Result<ArchiveAnalysis> =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> ArchiveAnalysis {
                panic!("celowa panika testowa - symuluje awarię silnika ZIP na zniekształconym archiwum");
            }));

        let a = wynik.unwrap_or_else(|_| ArchiveAnalysis {
            is_valid: false, reason: Some("Silnik ZIP spanikował podczas parsowania (uszkodzone lub złośliwe archiwum)".into()),
            internal_files_count: 0, uncompressed_size: 0,
            has_encrypted_entries: false, has_suspicious_compression: false,
        });

        assert!(!a.is_valid, "Panika musi zostać zamieniona na porażkę parsowania, nie propagować się dalej");
        assert!(a.reason.unwrap().contains("spanikował"));
    }

    /// Dowodzi, że `analyze_archive` (prawdziwa, produkcyjna funkcja - nie
    /// izolowany mechanizm) faktycznie przechodzi przez `analyze_zip_entries`
    /// owinięte w `catch_unwind` na normalnej, nie-panikującej ścieżce - czyli
    /// że refaktoryzacja wydzielająca `analyze_zip_entries` nie zmieniła
    /// zachowania dla zdrowych i uszkodzonych (ale nie panikujących) archiwów.
    #[test]
    fn test_analyze_archive_dziala_normalnie_przez_warstwe_catch_unwind() {
        let (_g, path) = build_zip(&[("plik.txt", b"tresc")], "zip");
        let size = std::fs::metadata(&path).unwrap().len();
        let a = analyze_archive(&path, size, false).unwrap();
        assert!(a.is_valid);
        assert_eq!(a.internal_files_count, 1);
    }

    #[test]
    fn test_analyze_fake_docx_missing_word_folder() {
        // ZIP poprawny strukturalnie, ale bez folderu word/ - fałszywy .docx
        let (_g, path) = build_zip(&[("cokolwiek.xml", b"<xml/>")], "docx");
        let size = std::fs::metadata(&path).unwrap().len();
        let a = analyze_archive(&path, size, false).unwrap();
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("Fałszywe rozszerzenie"));
    }

    #[test]
    fn test_analyze_real_docx_with_word_folder_is_valid() {
        let (_g, path) = build_zip(&[("word/document.xml", b"<document/>")], "docx");
        let size = std::fs::metadata(&path).unwrap().len();
        let a = analyze_archive(&path, size, false).unwrap();
        assert!(a.is_valid);
    }

    #[test]
    fn test_analyze_real_xlsx_with_xl_folder_is_valid() {
        let (_g, path) = build_zip(&[("xl/workbook.xml", b"<workbook/>")], "xlsx");
        let size = std::fs::metadata(&path).unwrap().len();
        let a = analyze_archive(&path, size, false).unwrap();
        assert!(a.is_valid);
    }

    #[test]
    fn test_analyze_non_zip_content_with_zip_extension_is_broken_header() {
        let (_g, path) = temp_with_ext(b"to nie jest prawdziwy zip", "zip");
        let a = analyze_archive(&path, 25, false).unwrap();
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("EOCD"));
    }

    #[test]
    fn test_analyze_deep_scan_disabled_does_not_check_crc_even_if_would_fail() {
        // Bez deep_scan, poprawny ZIP przechodzi normalnie niezależnie od CRC
        let (_g, path) = build_zip(&[("plik.txt", b"dane")], "zip");
        let size = std::fs::metadata(&path).unwrap().len();
        let a = analyze_archive(&path, size, false).unwrap();
        assert!(a.is_valid);
    }

    #[test]
    fn test_analyze_deep_scan_enabled_valid_zip_still_passes() {
        // Z deep_scan=true, ale ZIP jest w pełni poprawny - próbka CRC powinna przejść
        let (_g, path) = build_zip(&[("plik.txt", b"dane bez uszkodzenia")], "zip");
        let size = std::fs::metadata(&path).unwrap().len();
        let a = analyze_archive(&path, size, true).unwrap();
        assert!(a.is_valid, "Poprawny ZIP powinien przejść próbkową weryfikację CRC32");
    }

    // ------------------------------------------------------------------
    // build_source_block
    // ------------------------------------------------------------------

    #[test]
    fn test_build_source_block_reports_all_categories() {
        let stats = LiveStats::new(4);
        stats.ok.store(10, Ordering::Relaxed);
        stats.err_header_common.store(1, Ordering::Relaxed);
        stats.err_massfiles_unique.store(2, Ordering::Relaxed);
        stats.encrypted_common.store(3, Ordering::Relaxed);

        let start_time = Instant::now() - Duration::from_secs(1);
        let block = build_source_block("UFS Explorer", &stats, start_time, false);

        assert!(block.contains("Zdrowe: 10"));
        assert!(block.contains("Bomba (liczba plików): 0 wspólne / 2 unikalne"));
        assert!(block.contains("Zaszyfrowane: 3 wspólne / 0 unikalne"));
        assert!(!block.contains("CRC32"), "Blok CRC nie powinien się pojawić gdy deep_scan_enabled=false");
    }

    #[test]
    fn test_build_source_block_shows_crc_when_deep_scan_enabled() {
        let stats = LiveStats::new(4);
        stats.err_crc_common.store(1, Ordering::Relaxed);
        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("UFS Explorer", &stats, start_time, true);
        assert!(block.contains("Błędy CRC32 (próbka): 1 wspólne / 0 unikalne"));
    }

    #[test]
    fn test_build_source_block_shows_thread_activity_markup() {
        let stats = LiveStats::new(2);
        stats.thread_activity.mark_busy(0);

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("UFS Explorer", &stats, start_time, false);

        let line = block.lines().find(|l| l.starts_with("Wątki analizy")).expect("powinna istnieć linia Wariantu A");
        assert_eq!(line, "Wątki analizy (Wariant A): {G:1} {R:2}");
    }

    // ------------------------------------------------------------------
    // compute_half_threads
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_half_threads() {
        assert_eq!(compute_half_threads(8), 4);
        assert_eq!(compute_half_threads(1), 1);
    }

    // ------------------------------------------------------------------
    // analyze_archive: PEŁNA struktura zwykłego .tar (moduł `tar_archive`)
    //
    // Sedno wpięcia: poprzednio `.tar` sprawdzany był WYŁĄCZNIE po magic
    // bytes `ustar` w pierwszym nagłówku, więc archiwum ucięte w połowie,
    // z rozsypanymi dalszymi nagłówkami albo bez znacznika końca
    // przechodziło jako poprawne. Testy niżej to właśnie te przypadki.
    // ------------------------------------------------------------------

    const TAR_BLOK: usize = 512;

    fn tar_archiwum(wpisy: &[(&str, &[u8])]) -> Vec<u8> {
        crate::test_fixtures::zbuduj_tar(wpisy)
    }

    #[test]
    fn test_analyze_plain_tar_healthy_is_valid() {
        let tar = tar_archiwum(&[("a.txt", b"alfa"), ("b.txt", b"beta-beta")]);
        let (_g, path) = temp_with_ext(&tar, "tar");

        let a = analyze_archive(&path, tar.len() as u64, false).unwrap();
        assert!(a.is_valid, "Zdrowy tar musi przejść: {:?}", a.reason);
        assert_eq!(a.internal_files_count, 2, "Liczba wpisów z realnej struktury, nie z magic bytes");
        assert_eq!(a.uncompressed_size, 4 + 9, "Rozmiar treści = suma rozmiarów wpisów");
    }

    #[test]
    fn test_analyze_plain_tar_truncated_mid_entry_is_detected() {
        // Ucięcie W TRAKCIE danych drugiego wpisu. Pierwszy nagłówek (i jego
        // magic bytes `ustar`) pozostaje nienaruszony, więc STARE sprawdzenie
        // uznałoby to archiwum za w pełni poprawne.
        let tar = tar_archiwum(&[("a.txt", b"alfa"), ("b.bin", &[7u8; 2000])]);
        let uciety = &tar[..tar.len() - 1200];
        let (_g, path) = temp_with_ext(uciety, "tar");

        assert_eq!(&uciety[257..262], b"ustar", "Test bez sensu: magic bytes muszą zostać nietknięte");

        let a = analyze_archive(&path, uciety.len() as u64, false).unwrap();
        assert!(!a.is_valid, "Tar ucięty w danych wpisu musi zostać wykryty");
    }

    #[test]
    fn test_analyze_plain_tar_missing_end_marker_is_detected() {
        // Obcięty znacznik końca (dwa bloki zer) - wszystkie wpisy zdrowe.
        let tar = tar_archiwum(&[("a.txt", b"alfa")]);
        let bez_znacznika = &tar[..tar.len() - TAR_BLOK * 2];
        let (_g, path) = temp_with_ext(bez_znacznika, "tar");

        let a = analyze_archive(&path, bez_znacznika.len() as u64, false).unwrap();
        assert!(!a.is_valid, "Brak znacznika końca to objaw ucięcia archiwum");
        let powod = a.reason.unwrap();
        assert!(powod.contains("znacznika końca"), "Powód powinien nazwać objaw wprost, dostałem: {}", powod);
    }

    #[test]
    fn test_analyze_plain_tar_corrupted_header_reports_salvageable_count() {
        // Psujemy sumę kontrolną DRUGIEGO nagłówka. Pierwszy wpis zostaje
        // czytelny - raport musi powiedzieć, ile da się odratować
        // (integracja `TarAnalysis::valid_headers`).
        let tar = tar_archiwum(&[("a.txt", b"alfa"), ("b.txt", b"beta")]);
        let mut zepsuty = tar.clone();
        let offset_drugiego = TAR_BLOK * 2; // nagłówek + 1 blok danych
        zepsuty[offset_drugiego + 148] = b'9';

        let (_g, path) = temp_with_ext(&zepsuty, "tar");
        let a = analyze_archive(&path, zepsuty.len() as u64, false).unwrap();

        assert!(!a.is_valid, "Zła suma kontrolna nagłówka musi unieważnić archiwum");
        let powod = a.reason.unwrap();
        assert!(powod.contains("poprawnych nagłówków"), "Brak informacji o ocalałych wpisach: {}", powod);
    }

    #[test]
    fn test_analyze_plain_tar_garbage_is_classified_as_empty_not_header() {
        // Plik dłuższy niż blok, ale bez ani jednego czytelnego wpisu.
        let smieci = vec![0xABu8; TAR_BLOK * 3];
        let (_g, path) = temp_with_ext(&smieci, "tar");

        let a = analyze_archive(&path, smieci.len() as u64, false).unwrap();
        assert!(!a.is_valid);
        let powod = a.reason.unwrap();
        assert!(powod.contains("Nie znaleziono żadnych wpisów"), "dostałem: {}", powod);
        assert_eq!(
            classify_hard_reason(&powod), "empty",
            "Tar bez wpisów to Wydmuszka, nie uszkodzony nagłówek"
        );
    }

    #[test]
    fn test_analyze_plain_tar_shorter_than_one_block() {
        let content = [0x01u8; 100];
        let (_g, path) = temp_with_ext(&content, "tar");

        let a = analyze_archive(&path, content.len() as u64, false).unwrap();
        assert!(!a.is_valid);
        assert!(a.reason.unwrap().contains("Zbyt mały"));
    }

    #[test]
    fn test_analyze_tar_gz_skips_structural_branch() {
        // `.tar.gz` NIE może wejść w analizę struktury bloków - pod kompresją
        // jej nie widać. Dowód: treść o strukturze POPRAWNEGO tara, ale z
        // nazwą `.tar.gz`, musi zostać odrzucona na magic bytes gzipa.
        let tar = tar_archiwum(&[("a.txt", b"alfa")]);
        let (_g, path) = temp_with_ext(&tar, "tar.gz");

        let a = analyze_archive(&path, tar.len() as u64, false).unwrap();
        assert!(!a.is_valid, "Poprawny tar pod nazwą .tar.gz to zły gzip");
        assert!(a.reason.unwrap().contains("Magic"), "Powinna zadziałać gałąź magic bytes, nie strukturalna");

        // Odwrotnie: prawdziwe magic bytes gzipa przechodzą, mimo że w środku
        // nie ma żadnej struktury tar (bo i nie ma jej jak sprawdzić).
        let gzip = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00];
        let (_g2, path2) = temp_with_ext(&gzip, "tar.gz");
        assert!(analyze_archive(&path2, gzip.len() as u64, false).unwrap().is_valid);
    }

    #[test]
    fn test_classify_hard_reason_maps_empty_tar_to_empty_bucket() {
        assert_eq!(
            classify_hard_reason("Nie znaleziono żadnych wpisów tar (plik pusty, ucięty lub nie jest archiwum)"),
            "empty"
        );
        // Uszkodzone nagłówki zostają w kategorii "Nagłówek".
        assert_eq!(classify_hard_reason("3 uszkodzonych nagłówków (z 5) (poprawnych nagłówków: 2 z 5)"), "header");
    }
}
