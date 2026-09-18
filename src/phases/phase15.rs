// src/phases/phase15.rs

//! # Faza 15: Ekstrakcja Rozszerzonych Atrybutów (xattr) i Metadanych (UID/GID)
//!
//! Skanuje węzły i-node w poszukiwaniu ukrytych metadanych (Alternate Data Streams).
//! Wyciąga twarde wskaźniki POSIX (Właściciel i Grupa), zlicza wagę ukrytych atrybutów
//! oraz flaguje pliki zawierające ślady przeglądarek internetowych (URL) — z rozbiciem
//! na konkretne źródło sygnału (Windows/macOS), rozkład przestrzeni nazw xattr
//! (user/security/system/trusted) oraz anomalię rozmiaru (nietypowo duży blob xattr).
//! Obejmuje pełen zapis do bazy danych, dynamiczne TUI Ratatui (PhaseEvent) i Dual-Logging.
//!
//! UWAGA ARCHITEKTONICZNA (TESTOWALNOŚĆ): `extract_metadata` łączy I/O (`xattr::list`/
//! `xattr::get`) z klasyfikacją kluczy. Klasyfikacja jest wydzielona do czystych
//! funkcji: [`classify_url_marker`], [`xattr_namespace`], [`is_large_xattr`] —
//! testowalnych na syntetycznych nazwach kluczy, bez potrzeby tworzenia
//! prawdziwych rozszerzonych atrybutów na dysku (wymagałoby systemu plików
//! wspierającego xattr, niekoniecznie dostępnego w środowisku testowym/CI).
//!
//! UWAGA ARCHITEKTONICZNA (UI): mechanizm throttlingu UI (`AtomicU64` +
//! `compare_exchange`, deklarowany RAZ na poziomie funkcji, nie per-paczka)
//! był tu JUŻ poprawny przed tą rewizją — identyczny, dobry wzorzec co w
//! równoległej pętli korelacji Fazy 14. Nie ma tu buga "skoków" paska,
//! który naprawialiśmy w innych fazach.
//!
//! UWAGA ARCHITEKTONICZNA (WĄTKOWANIE): każda strona dostaje własną,
//! dedykowaną pulę Rayon (`half_threads`, identycznie jak Fazy 2-7/10-14).

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::{format_bytes, format_display_path, CANCEL_SIGNAL};
use ratatui::style::Color;
use rayon::prelude::*;
use rusqlite::{params, Connection, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;
use tracing::{info, instrument, warn};

const CHUNK_SIZE: usize = 100;

/// Próg rozmiaru sumy wszystkich xattr pliku, powyżej którego flagujemy
/// anomalię ("nietypowo duży blob xattr") — informacyjnie, nie unieważnia
/// pliku. Normalne metadane systemowe to zwykle pojedyncze bajty/kilobajty;
/// znacznie większy blob to potencjalny wektor przemycania danych.
const LARGE_XATTR_THRESHOLD_BYTES: u64 = 64 * 1024;

// ============================================================================
// POMOCNIKI (CZYSTE FUNKCJE - TESTOWALNE BEZ RZECZYWISTEGO XATTR NA DYSKU)
// ============================================================================

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

/// Klasyfikuje pojedynczy klucz xattr (już zlowercase'owany) do jednej z
/// konkretnych kategorii śladów sieciowych, albo `None` gdy klucz nie
/// pasuje do żadnej znanej sygnatury. Rozdzielenie na cztery odrębne
/// sygnały (zamiast jednego zbiorczego `has_url`) pozwala odróżnić
/// POCHODZENIE dowodu: `"zone_identifier"` (Windows — Zone.Identifier,
/// dopisywane przez przeglądarki/Eksplorator przy pobieraniu), `"quarantine"`
/// (macOS Gatekeeper — `com.apple.quarantine`), `"wherefroms"` (macOS
/// Safari/Spotlight — `kMDItemWhereFroms`, zawiera oryginalny URL),
/// `"url_generic"` (dowolny inny klucz zawierający "url" w nazwie).
fn classify_url_marker(key_lower: &str) -> Option<&'static str> {
    if key_lower.contains("zone.identifier") { Some("zone_identifier") }
    else if key_lower.contains("quarantine") { Some("quarantine") }
    else if key_lower.contains("wherefroms") { Some("wherefroms") }
    else if key_lower.contains("url") { Some("url_generic") }
    else { None }
}

/// Wyodrębnia przestrzeń nazw POSIX xattr (część klucza przed pierwszą
/// kropką, np. `"user"` z `"user.com.dropbox.attributes"`) — cztery
/// standardowe przestrzenie to `user`/`security`/`system`/`trusted`;
/// wszystko inne (w tym klucz bez kropki) trafia do `"other"`.
fn xattr_namespace(key: &str) -> String {
    match key.split_once('.') {
        Some((ns, _)) if !ns.is_empty() => ns.to_lowercase(),
        _ => "other".to_string(),
    }
}

/// Rozstrzyga, czy suma rozmiarów wszystkich xattr pliku przekracza
/// [`LARGE_XATTR_THRESHOLD_BYTES`] — patrz uzasadnienie przy stałej.
fn is_large_xattr(total_bytes: u64) -> bool {
    total_bytes > LARGE_XATTR_THRESHOLD_BYTES
}

/// Tabela nazw uprawnień Linuksa indeksowana numerem bitu — stabilne ABI
/// jądra (`linux/capability.h`), numeracja nigdy nie jest zmieniana wstecz
/// (nowe uprawnienia tylko DOPISYWANE na końcu). Używana przez
/// [`parse_capability_names`] do przetłumaczenia surowej maski bitowej
/// `security.capability` na czytelne nazwy — plik wykonywalny z ustawionym
/// np. `CAP_SYS_ADMIN`/`CAP_SETUID` odzyskany z dysku to istotny sygnał
/// (mechanizm eskalacji uprawnień przetrwał poza standardowym SUID).
const CAPABILITY_NAMES: &[&str] = &[
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
    "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK",
    "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG",
    "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// Dekoduje maskę bitową "permitted" ze struktury binarnej `vfs_cap_data`
/// (dokładny format jądra Linux dla xattr `security.capability`) na listę
/// nazw z [`CAPABILITY_NAMES`]. Format: 4 B `magic_etc` (little-endian u32,
/// górny bajt = numer rewizji), potem 1 lub 2 pary (permitted, inheritable)
/// po 4 B każde — rewizja 1 (`0x01000000`) niesie 32-bitową maskę w jednym
/// słowie (długość całości 12 B), rewizje 2/3 (`0x02000000`/`0x03000000`,
/// V3 to bieżący standard) niosą 64-bitową maskę w dwóch słowach (długość
/// co najmniej 20 B — rewizja 3 dokleja 4 B `rootid`, nieistotne tutaj).
/// Interesuje nas WYŁĄCZNIE zestaw "permitted" (co plik MOŻE wykonać po
/// uruchomieniu) — "inheritable" pomijane celowo, bo samo dziedziczenie bez
/// odpowiadającego bitu w `permitted` procesu nadrzędnego i tak nic nie daje.
/// Wejście zbyt krótkie/nierozpoznanej rewizji zwraca pustą listę (nigdy nie
/// panikuje) — dane xattr na uszkodzonym/odzyskanym dysku mogą być ucięte.
fn parse_capability_names(raw: &[u8]) -> Vec<&'static str> {
    if raw.len() < 8 { return Vec::new(); }
    let magic_etc = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let revision = magic_etc & 0xFF000000;

    let permitted_low = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let permitted_high: u32 = if (revision == 0x02000000 || revision == 0x03000000) && raw.len() >= 20 {
        u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]])
    } else if revision == 0x01000000 {
        0
    } else {
        return Vec::new();
    };

    let mask = (permitted_low as u64) | ((permitted_high as u64) << 32);
    (0..CAPABILITY_NAMES.len())
        .filter(|bit| mask & (1u64 << bit) != 0)
        .map(|bit| CAPABILITY_NAMES[bit])
        .collect()
}

/// Formatuje sekcję `[4] ROZKŁAD PRZESTRZENI NAZW XATTR` Dziennika
/// Końcowego z połączonego (obie strony) rozkładu przestrzeni nazw. `None`,
/// gdy żadna strona nie znalazła ani jednego klucza xattr — wtedy sekcja
/// jest pomijana w raporcie, tak samo jak sekcja `[3]` przy braku anomalii
/// rozmiaru.
///
/// Wydzielona jako czysta funkcja z tego samego powodu co
/// `classify_url_marker`/`xattr_namespace`/`is_large_xattr` (patrz uwaga
/// architektoniczna na początku modułu) — testowalna na syntetycznych
/// mapach zliczeń, bez potrzeby prawdziwych xattr na dysku.
fn format_namespace_section(ufs: &HashMap<String, usize>, script: &HashMap<String, usize>) -> Option<String> {
    let mut merged: HashMap<String, usize> = HashMap::new();
    for (ns, count) in ufs.iter().chain(script.iter()) {
        *merged.entry(ns.clone()).or_insert(0) += count;
    }
    if merged.is_empty() {
        return None;
    }

    let mut sorted: Vec<_> = merged.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));

    let mut out = String::new();
    use std::fmt::Write as FmtWrite;
    let _ = writeln!(&mut out, "[ 4 ] ROZKŁAD PRZESTRZENI NAZW XATTR:");
    for (ns, count) in &sorted {
        let _ = writeln!(&mut out, "   -> {:<11} {} kluczy", format!("{}:", ns), count);
    }
    let _ = writeln!(&mut out, "      [ ZNACZENIE ]: Przestrzenie 'trusted'/'system' zwykle wymagają podwyższonych uprawnień do odczytu/zapisu - ich obecność jest sama w sobie sygnałem wartym odnotowania.\n");
    Some(out)
}

#[derive(Debug, Clone)]
pub(crate) struct Task {
    id: i32,
    rel_path: String,
    is_common: bool,
}

/// Wynik ekstrakcji metadanych jednego pliku. W przeciwieństwie do innych
/// faz ta struktura NIE ma pola `is_valid`/`reason` — Faza 15 jest czysto
/// OBSERWACYJNA (ekstrakcja i raportowanie), nie klasyfikuje plików jako
/// zdrowe/uszkodzone. Wszystkie flagi (`has_url`, `has_zone_identifier`,
/// `has_quarantine`, `has_wherefroms`, `has_large_xattr`) są informacyjne.
#[derive(Debug, Clone)]
struct MetadataAnalysis {
    uid: u32,
    gid: u32,
    xattr_count: usize,
    xattr_size_bytes: u64,
    xattr_keys: String,
    /// Zbiorczy sygnał (dowolny z poniższych czterech, dla zgodności z
    /// istniejącym schematem bazy) — patrz [`classify_url_marker`] dla
    /// rozbicia na konkretne źródło.
    has_url: bool,
    has_zone_identifier: bool,
    has_quarantine: bool,
    has_wherefroms: bool,
    has_large_xattr: bool,
    /// Zliczenia kluczy per przestrzeń nazw ([`xattr_namespace`]) DLA TEGO
    /// JEDNEGO pliku — scalane do globalnej mapy w [`process_side_stream`].
    namespace_counts: HashMap<String, usize>,
    /// Klucz `security.capability` obecny (niezależnie od tego, czy udało
    /// się zdekodować choć jedno uprawnienie z jego binarnej wartości).
    has_capability: bool,
    /// Nazwy uprawnień zdekodowane przez [`parse_capability_names`] z
    /// wartości `security.capability` DLA TEGO JEDNEGO pliku — puste, gdy
    /// klucz nieobecny LUB wartość nie rozpoznana (rewizja/długość).
    capability_names: Vec<&'static str>,
}

#[derive(Debug, Clone)]
pub(crate) struct SideXattrResult {
    id: i32,
    meta: Option<MetadataAnalysis>,
    io_error: Option<bool>,
}

pub(crate) enum ScanMsg {
    UfsChunk(Vec<SideXattrResult>),
    ScriptChunk(Vec<SideXattrResult>),
}

/// Liczniki live dla JEDNEJ strony. `found_attrs`/`found_urls` i cztery
/// sygnały URL (`zone_identifier`/`quarantine`/`wherefroms`/`large_xattr`)
/// są rozbite wspólne/unikalne — `Task::is_common` niesie tę informację od
/// razu przy budowaniu zadań (dostępna w tym samym zapytaniu SQL co reszta
/// pól `Task`, patrz `run()`), mirror wzorca z Fazy 11-14. `xattr_total_bytes`/
/// `extensions`/`top_owners`/`namespace_counts`/`capability_names_counts`
/// pozostają zbiorcze — to agregaty wagowe/opisowe, nie liczniki anomalii
/// (ten sam podział co np. `ext_weights` w innych fazach).
pub(crate) struct LiveStats {
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    found_attrs_common: AtomicUsize, found_attrs_unique: AtomicUsize,
    found_urls_common: AtomicUsize, found_urls_unique: AtomicUsize,
    xattr_total_bytes: AtomicU64,
    errors: AtomicUsize,
    extensions: Mutex<HashMap<String, usize>>,
    top_owners: Mutex<HashMap<String, usize>>,

    zone_identifier_common: AtomicUsize, zone_identifier_unique: AtomicUsize,
    quarantine_common: AtomicUsize, quarantine_unique: AtomicUsize,
    wherefroms_common: AtomicUsize, wherefroms_unique: AtomicUsize,
    large_xattr_common: AtomicUsize, large_xattr_unique: AtomicUsize,
    namespace_counts: Mutex<HashMap<String, usize>>,

    /// Pliki z kluczem `security.capability` obecnym, wspólne/unikalne.
    capability_common: AtomicUsize, capability_unique: AtomicUsize,
    /// Zliczenia WYSTĄPIEŃ każdej nazwy uprawnienia ([`parse_capability_names`])
    /// w całej puli tej strony — zbiorcze (jak `namespace_counts`), bo to
    /// rozkład opisowy, nie licznik anomalii per-plik.
    capability_names_counts: Mutex<HashMap<String, usize>>,

    /// EKSPERYMENTALNE (Wariant A): śledzi zajętość logicznych slotów Rayon
    /// TEJ strony podczas odczytu xattr (`extract_metadata`) — patrz moduł
    /// `thread_activity`.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            processed_files: AtomicUsize::new(0),
            processed_bytes: AtomicU64::new(0),
            found_attrs_common: AtomicUsize::new(0), found_attrs_unique: AtomicUsize::new(0),
            found_urls_common: AtomicUsize::new(0), found_urls_unique: AtomicUsize::new(0),
            xattr_total_bytes: AtomicU64::new(0),
            errors: AtomicUsize::new(0),
            extensions: Mutex::new(HashMap::new()),
            top_owners: Mutex::new(HashMap::new()),
            zone_identifier_common: AtomicUsize::new(0), zone_identifier_unique: AtomicUsize::new(0),
            quarantine_common: AtomicUsize::new(0), quarantine_unique: AtomicUsize::new(0),
            wherefroms_common: AtomicUsize::new(0), wherefroms_unique: AtomicUsize::new(0),
            large_xattr_common: AtomicUsize::new(0), large_xattr_unique: AtomicUsize::new(0),
            namespace_counts: Mutex::new(HashMap::new()),
            capability_common: AtomicUsize::new(0), capability_unique: AtomicUsize::new(0),
            capability_names_counts: Mutex::new(HashMap::new()),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }
}

/// Wylicza liczbę slotów trackera zajętości (Wariant A) odpowiednią dla
/// trybu I/O — patrz identyczna logika w `phase3::compute_activity_slots`.
fn compute_activity_slots(io_mode: &str, actual_threads: usize, half_threads: usize) -> usize {
    if io_mode == "CONCURRENT" { half_threads } else { actual_threads }
}

/// Buduje pełny, samodzielny blok live DLA JEDNEGO ŹRÓDŁA — prędkość w
/// plikach/s (to metadane, nie transfer danych), top 3 rozszerzenia z
/// xattr, top 2 właścicieli (UID:GID), znalezione XATTR + łączna waga,
/// rozkład przestrzeni nazw, trzy konkretne źródła śladów URL + generyczny,
/// anomalia rozmiaru, błędy I/O.
fn build_source_block(label: &str, stats: &LiveStats, start_time: Instant) -> String {
    let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
    let current = stats.processed_files.load(Ordering::Relaxed);
    let speed_files = current as f64 / elapsed;

    let ext_str = {
        let map = stats.extensions.lock().unwrap();
        let mut s: Vec<_> = map.iter().collect();
        s.sort_by(|a, b| b.1.cmp(a.1));
        s.into_iter().take(3).map(|(k, v)| format!(".{}: {}", k, v)).collect::<Vec<_>>().join(", ")
    };
    let display_ext = if ext_str.is_empty() { "-".to_string() } else { ext_str };

    let own_str = {
        let map = stats.top_owners.lock().unwrap();
        let mut s: Vec<_> = map.iter().collect();
        s.sort_by(|a, b| b.1.cmp(a.1));
        s.into_iter().take(2).map(|(k, v)| format!("{} ({})", k, v)).collect::<Vec<_>>().join(", ")
    };
    let display_own = if own_str.is_empty() { "-".to_string() } else { own_str };

    let ns_str = {
        let map = stats.namespace_counts.lock().unwrap();
        let mut s: Vec<_> = map.iter().collect();
        s.sort_by(|a, b| b.1.cmp(a.1));
        s.into_iter().map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join(", ")
    };
    let display_ns = if ns_str.is_empty() { "-".to_string() } else { ns_str };

    let cap_str = {
        let map = stats.capability_names_counts.lock().unwrap();
        let mut s: Vec<_> = map.iter().collect();
        s.sort_by(|a, b| b.1.cmp(a.1));
        s.into_iter().take(5).map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join(", ")
    };
    let display_cap = if cap_str.is_empty() { "-".to_string() } else { cap_str };

    let found_attrs_common = stats.found_attrs_common.load(Ordering::Relaxed);
    let found_attrs_unique = stats.found_attrs_unique.load(Ordering::Relaxed);
    let found_attrs_total = found_attrs_common + found_attrs_unique;
    let avg_xattr_bytes = if found_attrs_total > 0 {
        stats.xattr_total_bytes.load(Ordering::Relaxed) / found_attrs_total as u64
    } else { 0 };

    let activity_markup = crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot());

    format!(
        "[{}]\nPrędkość: {:.0} plików/s\nXATTR znalezione: {} wspólne / {} unikalne ({})\nŚr. rozmiar xattr (pliki z atrybutami): {}\nTop rozszerzenia (xattr): {}\nTop właściciele (UID:GID): {}\nPrzestrzenie nazw xattr: {}\nZone.Identifier (Windows): {} wspólne / {} unikalne\nQuarantine (macOS): {} wspólne / {} unikalne\nWhereFroms (macOS): {} wspólne / {} unikalne\nURL ogólne: {} wspólne / {} unikalne\nAnomalia rozmiaru (>64KB): {} wspólne / {} unikalne\nLinux Capabilities (security.capability): {} wspólne / {} unikalne ({})\nWątki odczytu xattr (Wariant A): {}\nBłędy I/O: {}",
        label, speed_files,
        found_attrs_common, found_attrs_unique, format_bytes(stats.xattr_total_bytes.load(Ordering::Relaxed)),
        format_bytes(avg_xattr_bytes),
        display_ext, display_own, display_ns,
        stats.zone_identifier_common.load(Ordering::Relaxed), stats.zone_identifier_unique.load(Ordering::Relaxed),
        stats.quarantine_common.load(Ordering::Relaxed), stats.quarantine_unique.load(Ordering::Relaxed),
        stats.wherefroms_common.load(Ordering::Relaxed), stats.wherefroms_unique.load(Ordering::Relaxed),
        stats.found_urls_common.load(Ordering::Relaxed), stats.found_urls_unique.load(Ordering::Relaxed),
        stats.large_xattr_common.load(Ordering::Relaxed), stats.large_xattr_unique.load(Ordering::Relaxed),
        stats.capability_common.load(Ordering::Relaxed), stats.capability_unique.load(Ordering::Relaxed), display_cap,
        activity_markup,
        stats.errors.load(Ordering::Relaxed),
    )
}

// `side` (5. pole krotki) - patrz naprawa Znaleziska 1 (todo.faza15.md):
// plik wspólny może teraz dać DWA wpisy pod tym samym rozszerzeniem, po
// jednym na fizyczną kopię - bez tego pola raport nie mógłby odróżnić,
// z której strony pochodzi który przykładowy dowód.
type ExtMap = HashMap<String, Vec<(String, u32, u32, String, String)>>;

/// Agreguje statystyki jednej puli (wspólne/tylko-UFS/tylko-Skrypt) do
/// Dziennika Końcowego: liczba plików z xattr, liczba ze śladami URL,
/// suma wagi xattr, mapa rozszerzenie -> przykłady (ścieżka, uid, gid, klucze).
struct CategoryStats {
    count: usize,
    url_count: usize,
    total_xattr_bytes: u64,
    extensions: ExtMap,
}
impl CategoryStats {
    fn new() -> Self { Self { count: 0, url_count: 0, total_xattr_bytes: 0, extensions: HashMap::new() } }
    #[allow(clippy::too_many_arguments)]
    fn add(&mut self, ext: &str, path: String, uid: u32, gid: u32, keys: String, bytes: u64, has_url: bool, side: String) {
        self.count += 1;
        self.total_xattr_bytes += bytes;
        if has_url { self.url_count += 1; }
        self.extensions.entry(ext.to_string()).or_default().push((path, uid, gid, keys, side));
    }
}

// ============================================================================
// SILNIK DECYZYJNY (WERYFIKATOR XATTR I METADANYCH)
// ============================================================================

#[cfg(not(unix))]
trait DummyUnixMeta {
    fn uid(&self) -> u32 { 0 }
    fn gid(&self) -> u32 { 0 }
}
#[cfg(not(unix))]
impl DummyUnixMeta for std::fs::Metadata {}

/// Odczytuje UID/GID i pełną listę rozszerzonych atrybutów pliku. Dla
/// każdego klucza: klasyfikuje przestrzeń nazw ([`xattr_namespace`]) i
/// sprawdza, czy pasuje do znanego markera URL ([`classify_url_marker`]);
/// dla `security.capability` (dokładne dopasowanie klucza — to JEDNA
/// konkretna, znana nazwa, nie rodzina wariantów jak przy URL) dekoduje
/// wprost binarną wartość na nazwy uprawnień ([`parse_capability_names`]).
/// Po zebraniu wszystkich kluczy sprawdza łączny rozmiar pod kątem anomalii
/// ([`is_large_xattr`]). Brak atrybutów (lub błąd `xattr::list`) nie jest
/// traktowany jako błąd funkcji — po prostu zwraca zerowe liczniki.
fn extract_metadata(path: &Path) -> std::result::Result<MetadataAnalysis, std::io::Error> {
    let metadata = std::fs::metadata(path)?;
    let uid = metadata.uid();
    let gid = metadata.gid();
    
    let mut xattr_count = 0;
    let mut xattr_size_bytes = 0;
    let mut keys_vec = Vec::new();
    let mut has_url = false;
    let mut has_zone_identifier = false;
    let mut has_quarantine = false;
    let mut has_wherefroms = false;
    let mut namespace_counts: HashMap<String, usize> = HashMap::new();
    let mut has_capability = false;
    let mut capability_names: Vec<&'static str> = Vec::new();

    if let Ok(iter) = xattr::list(path) {
        for key in iter {
            xattr_count += 1;
            let key_str = key.to_string_lossy().to_string();
            let k_lower = key_str.to_lowercase();

            *namespace_counts.entry(xattr_namespace(&key_str)).or_insert(0) += 1;

            match classify_url_marker(&k_lower) {
                Some("zone_identifier") => { has_zone_identifier = true; has_url = true; }
                Some("quarantine") => { has_quarantine = true; has_url = true; }
                Some("wherefroms") => { has_wherefroms = true; has_url = true; }
                Some(_) => { has_url = true; }
                None => {}
            }

            keys_vec.push(key_str.clone());

            if let Ok(Some(val)) = xattr::get(path, &key) {
                xattr_size_bytes += val.len() as u64;

                if k_lower == "security.capability" {
                    has_capability = true;
                    capability_names = parse_capability_names(&val);
                }
            }
        }
    }

    let has_large_xattr = is_large_xattr(xattr_size_bytes);

    Ok(MetadataAnalysis {
        uid, gid, xattr_count, xattr_size_bytes,
        xattr_keys: keys_vec.join(", "),
        has_url, has_zone_identifier, has_quarantine, has_wherefroms, has_large_xattr,
        namespace_counts, has_capability, capability_names,
    })
}

/// Formatuje jedną pulę (wspólne/tylko-UFS/tylko-Skrypt) do Dziennika
/// Końcowego: top 5 rozszerzeń z przykładową ścieżką, właścicielem i kluczami.
fn write_category_block(out: &mut String, stats: &CategoryStats) {
    use std::fmt::Write as FmtWrite;
    let mut sorted: Vec<_> = stats.extensions.iter().collect();
    sorted.sort_by_key(|a| std::cmp::Reverse(a.1.len())); 
    
    for (ext, paths) in sorted.into_iter().take(5) {
        let cat = get_file_category(ext);
        // REGRESJA (todo.faza15.md, Znalezisko 1): plik WSPÓLNY z xattr po
        // OBU stronach daje teraz DWA wpisy (po naprawie wyścigu zapisu -
        // każda fizyczna kopia ma swój własny wiersz) - stąd "wpisów", nie
        // "plików": liczba odzwierciedla POMIARY, nie unikalne ścieżki.
        let _ = writeln!(out, "     - Typ Pliku: {:<12} [ {:<4} ]: {} wpisów", cat, ext, paths.len());

        let (sample_path, s_uid, s_gid, s_keys, s_side) = &paths[0];

        let _ = writeln!(out, "       [ 🔍 ] Przykładowy dowód z tej grupy ({}):", s_side);
        let _ = writeln!(out, "         - Ścieżka:       \"{}\"", sample_path);
        let _ = writeln!(out, "         - Właściciel:    UID: {}, GID: {}", s_uid, s_gid);
        let _ = writeln!(out, "         - Ukryte klucze: {}", s_keys);
    }
    let _ = writeln!(out); 
}

// ============================================================================
// ETAP 1: STRUMIENIOWE PRZETWARZANIE I/O Z ODŚWIEŻANIEM CZASOWYM (80ms)
// ============================================================================

/// Skanuje wszystkie zadania (`tasks`) dla JEDNEJ strony: dla każdego pliku
/// woła [`extract_metadata`], scala per-plikowy rozkład przestrzeni nazw do
/// globalnej mapy, aktualizuje liczniki [`LiveStats`] (w tym cztery nowe
/// sygnały URL i anomalię rozmiaru), zapisuje wpis do logu operacyjnego
/// (tylko dla plików z jakimikolwiek xattr) i strumieniuje wynik do wątku
/// zapisu SQLite. Throttling UI: `AtomicU64` + `compare_exchange` na
/// poziomie całej funkcji — wzorzec JUŻ poprawny przed tą rewizją, patrz
/// dokumentacja modułu.
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
}

#[instrument(skip(ctx), fields(base_path = %ctx.base_path.display()))]

fn process_side_stream<'a>(ctx: StreamCtx<'a>) {
    let StreamCtx { base_path, tasks, side_label, stats, tx_db, is_ufs, start_time, tx_ui, bar_idx, opr_log } = ctx;

    let last_ui_update = Arc::new(AtomicU64::new(0));

    tasks.par_chunks(CHUNK_SIZE).for_each_with(tx_db, |tx_db, chunk| {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

        let mut results = Vec::with_capacity(chunk.len());
        let mut local_exts: HashMap<String, usize> = HashMap::new();
        let mut local_owners: HashMap<String, usize> = HashMap::new();
        let mut local_namespaces: HashMap<String, usize> = HashMap::new();
        let mut local_capabilities: HashMap<String, usize> = HashMap::new();

        for task in chunk {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

            let full_path = base_path.join(&task.rel_path);
            let ext = Path::new(&task.rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
            let file_size = std::fs::metadata(&full_path).map(|m| m.len()).unwrap_or(0);

            let (meta_opt, io_err) = match stats.thread_activity.track_current(|| extract_metadata(&full_path)) {
                Ok(meta) => {
                    let kategoria = if is_ufs { "UFS" } else { "Skrypt" };
                    let owner_key = format!("{}:{}", meta.uid, meta.gid);
                    *local_owners.entry(owner_key).or_insert(0) += 1;

                    if meta.xattr_count > 0 {
                        if task.is_common { stats.found_attrs_common.fetch_add(1, Ordering::Relaxed); } else { stats.found_attrs_unique.fetch_add(1, Ordering::Relaxed); }
                        stats.xattr_total_bytes.fetch_add(meta.xattr_size_bytes, Ordering::Relaxed);
                        *local_exts.entry(ext.clone()).or_insert(0) += 1;

                        for (ns, count) in &meta.namespace_counts {
                            *local_namespaces.entry(ns.clone()).or_insert(0) += count;
                        }

                        if meta.has_url { if task.is_common { stats.found_urls_common.fetch_add(1, Ordering::Relaxed); } else { stats.found_urls_unique.fetch_add(1, Ordering::Relaxed); } }
                        if meta.has_zone_identifier { if task.is_common { stats.zone_identifier_common.fetch_add(1, Ordering::Relaxed); } else { stats.zone_identifier_unique.fetch_add(1, Ordering::Relaxed); } }
                        if meta.has_quarantine { if task.is_common { stats.quarantine_common.fetch_add(1, Ordering::Relaxed); } else { stats.quarantine_unique.fetch_add(1, Ordering::Relaxed); } }
                        if meta.has_wherefroms { if task.is_common { stats.wherefroms_common.fetch_add(1, Ordering::Relaxed); } else { stats.wherefroms_unique.fetch_add(1, Ordering::Relaxed); } }
                        if meta.has_large_xattr { if task.is_common { stats.large_xattr_common.fetch_add(1, Ordering::Relaxed); } else { stats.large_xattr_unique.fetch_add(1, Ordering::Relaxed); } }
                        if meta.has_capability {
                            if task.is_common { stats.capability_common.fetch_add(1, Ordering::Relaxed); } else { stats.capability_unique.fetch_add(1, Ordering::Relaxed); }
                            for name in &meta.capability_names {
                                *local_capabilities.entry(name.to_string()).or_insert(0) += 1;
                            }
                        }

                        if let Ok(mut f) = opr_log.lock() {
                            let url_flag = if meta.has_url { "[ 🌐 URL!]" } else { "" };
                            let large_flag = if meta.has_large_xattr { "[ ⚠️ DUŻY XATTR!]" } else { "" };
                            let cap_flag = if meta.has_capability { "[ 🛡️ CAPABILITY!]" } else { "" };
                            let cap_suffix = if meta.capability_names.is_empty() { String::new() } else { format!(" [Uprawnienia: {}]", meta.capability_names.join(", ")) };
                            let _ = writeln!(f, "[{kategoria:<6}] [Rozsz: .{ext:<4}] [UID: {:<4} | GID: {:<4}] [Rozmiar XATTR: {:<6}] {url_flag}{large_flag}{cap_flag} [Klucze: {}]{cap_suffix} -> \"{}\"",
                                meta.uid, meta.gid, format_bytes(meta.xattr_size_bytes), meta.xattr_keys, task.rel_path);
                        }
                    }
                    (Some(meta), Some(false))
                },
                Err(e) => {
                    warn!(path = %task.rel_path, side = side_label, error = %e, "Błąd I/O węzła i-node");
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    (None, Some(true))
                }
            };

            stats.processed_files.fetch_add(1, Ordering::Relaxed);
            stats.processed_bytes.fetch_add(file_size, Ordering::Relaxed);
            
            let current = stats.processed_files.load(Ordering::Relaxed);
            let now_ms = start_time.elapsed().as_millis() as u64;
            let last_ms = last_ui_update.load(Ordering::Relaxed);
            
            if now_ms - last_ms > 80
                && last_ui_update.compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                    
                    if !local_exts.is_empty() {
                        let mut g_ext = stats.extensions.lock().unwrap();
                        for (k, v) in local_exts.drain() { *g_ext.entry(k).or_insert(0) += v; }
                    }
                    if !local_owners.is_empty() {
                        let mut g_own = stats.top_owners.lock().unwrap();
                        for (k, v) in local_owners.drain() { *g_own.entry(k).or_insert(0) += v; }
                    }
                    if !local_namespaces.is_empty() {
                        let mut g_ns = stats.namespace_counts.lock().unwrap();
                        for (k, v) in local_namespaces.drain() { *g_ns.entry(k).or_insert(0) += v; }
                    }
                    if !local_capabilities.is_empty() {
                        let mut g_cap = stats.capability_names_counts.lock().unwrap();
                        for (k, v) in local_capabilities.drain() { *g_cap.entry(k).or_insert(0) += v; }
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

            results.push(SideXattrResult { id: task.id, meta: meta_opt, io_error: io_err });
        }

        if !local_exts.is_empty() {
            let mut g_ext = stats.extensions.lock().unwrap();
            for (k, v) in local_exts.drain() { *g_ext.entry(k).or_insert(0) += v; }
        }
        if !local_owners.is_empty() {
            let mut g_own = stats.top_owners.lock().unwrap();
            for (k, v) in local_owners.drain() { *g_own.entry(k).or_insert(0) += v; }
        }
        if !local_namespaces.is_empty() {
            let mut g_ns = stats.namespace_counts.lock().unwrap();
            for (k, v) in local_namespaces.drain() { *g_ns.entry(k).or_insert(0) += v; }
        }
        if !local_capabilities.is_empty() {
            let mut g_cap = stats.capability_names_counts.lock().unwrap();
            for (k, v) in local_capabilities.drain() { *g_cap.entry(k).or_insert(0) += v; }
        }

        if !results.is_empty() {
            if is_ufs { let _ = tx_db.send(ScanMsg::UfsChunk(results)); } 
            else { let _ = tx_db.send(ScanMsg::ScriptChunk(results)); }
        }
    });

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: stats.processed_files.load(Ordering::Relaxed) as u64,
        message: "Skanowanie atrybutów węzła w 100% zakończone.".to_string(),
    });
}

// ============================================================================
// GŁÓWNA FUNKCJA (Entrypoint)
// ============================================================================

/// Wylicza rozmiar prywatnej puli Rayon przypisywanej JEDNEJ stronie w
/// trybie `CONCURRENT` — patrz `phase3::compute_half_threads` dla pełnego
/// uzasadnienia.
fn compute_half_threads(total_threads: usize) -> usize {
    std::cmp::max(1, total_threads / 2)
}

/// Punkt wejścia Fazy 15, wołany przez `menu::actions::run_phase_with_ui`.
///
/// Przebieg: (1) wczytuje z SQLite pliki bez jeszcze wykonanej inspekcji
/// xattr; (2) uruchamia [`process_side_stream`] dla UFS i Skryptu —
/// równolegle na dwóch dedykowanych pulach Rayon lub sekwencyjnie;
/// (3) koreluje wyniki w SQLite; (4) buduje Dziennik Końcowy z podziałem
/// wspólne/tylko-UFS/tylko-Skrypt (liczonym tu, z zapytania SQL — [`Task`]
/// nie niesie tej informacji podczas samego skanowania).
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    let _ = tx_ui.send(PhaseEvent::Log("Uruchomiono Fazę 15: Rozszerzone Atrybuty (XATTR)".to_string()));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    // --- TWORZENIE NOWEJ TABELI BAZODANOWEJ ---
    //
    // REGRESJA (todo.faza15.md, Znalezisko 1 — WYSOKIE): stary schemat miał
    // `file_id INTEGER PRIMARY KEY` — jeden wiersz NA PLIK, nie na stronę.
    // Dla plików WSPÓLNYCH (obecnych po obu stronach — typowy przypadek w
    // tym narzędziu: dwa niezależnie pozyskane korpusy tego samego
    // materiału) budowane są DWA niezależne zadania o tym samym `file_id`
    // (patrz pętla budująca `ufs_tasks`/`script_tasks` niżej), oba piszące
    // przez `INSERT OR REPLACE` do TEGO SAMEGO wiersza z dwóch niezależnych
    // pul Rayon przez wspólny kanał — kolejność nadejścia jest z definicji
    // niedeterministyczna, więc drugi zapis bezpowrotnie kasował pierwszy.
    // Dla plików, gdzie tylko jedna strona miała realne xattr, oznaczało to
    // CAŁKOWITY zanik dowodu z raportu (WHERE a.has_xattr = 1 odrzucał cały
    // wiersz). Klucz złożony (file_id, side) eliminuje kolizję u źródła —
    // obie strony dostają WŁASNY wiersz, więc UID/GID/klucze xattr/sygnały
    // URL obu fizycznych kopii przetrwają, w tym rozbieżności między nimi
    // (np. inny właściciel pliku), które same w sobie są wartym odnotowania
    // sygnałem kryminalistycznym, nie tylko szumem do scalenia.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS phase15_analysis (
            file_id INTEGER NOT NULL,
            side TEXT NOT NULL CHECK(side IN ('ufs','script')),
            has_xattr BOOLEAN,
            xattr_count INTEGER,
            xattr_size INTEGER,
            xattr_keys TEXT,
            uid INTEGER,
            gid INTEGER,
            has_url BOOLEAN,
            has_zone_identifier BOOLEAN,
            has_quarantine BOOLEAN,
            has_wherefroms BOOLEAN,
            has_large_xattr BOOLEAN,
            PRIMARY KEY(file_id, side),
            FOREIGN KEY(file_id) REFERENCES files(id)
        )", []
    )?;

    // Migracja jednorazowa ze STAREGO kształtu tabeli (sprzed tej naprawy,
    // bez kolumny `side`) — `CREATE TABLE IF NOT EXISTS` wyżej jest wtedy
    // no-opem, bo tabela o tej nazwie już istnieje. Wykrywamy przez
    // `PRAGMA table_info` (niezawodne niezależnie od tego, czy tabela ma
    // jakiekolwiek wiersze — w przeciwieństwie do próby SELECT, która dla
    // pustej tabeli zwróciłaby "brak wierszy", nie "brak kolumny"). Starych
    // (potencjalnie już zafałszowanych przez wyścig) danych NIE kasujemy po
    // cichu — zmieniamy nazwę do ręcznej inspekcji śledczej, budujemy nowy,
    // bezkolizyjny schemat, i resetujemy znaczniki ukończenia w `files`, żeby
    // najbliższe uruchomienie Fazy 15 przetworzyło WSZYSTKIE pliki ponownie
    // pod nowym schematem (xattr to szybki odczyt metadanych, nie
    // re-hashowanie zawartości — koszt niewielki wobec poprawności dowodu).
    let ma_kolumne_side: bool = {
        let mut stmt = conn.prepare("PRAGMA table_info(phase15_analysis)")?;
        let cols: Vec<String> = stmt.query_map([], |row| row.get::<_, String>(1))?.filter_map(|r| r.ok()).collect();
        cols.iter().any(|c| c == "side")
    };

    if !ma_kolumne_side {
        conn.execute("ALTER TABLE phase15_analysis RENAME TO phase15_analysis_legacy_wyscig_zapisu", [])?;
        conn.execute(
            "CREATE TABLE phase15_analysis (
                file_id INTEGER NOT NULL,
                side TEXT NOT NULL CHECK(side IN ('ufs','script')),
                has_xattr BOOLEAN,
                xattr_count INTEGER,
                xattr_size INTEGER,
                xattr_keys TEXT,
                uid INTEGER,
                gid INTEGER,
                has_url BOOLEAN,
                has_zone_identifier BOOLEAN,
                has_quarantine BOOLEAN,
                has_wherefroms BOOLEAN,
                has_large_xattr BOOLEAN,
                PRIMARY KEY(file_id, side),
                FOREIGN KEY(file_id) REFERENCES files(id)
            )", []
        )?;
        conn.execute(
            "UPDATE files SET has_xattr_ufs = NULL, has_xattr_script = NULL, phase15_done = 0
             WHERE has_xattr_ufs IS NOT NULL OR has_xattr_script IS NOT NULL OR phase15_done = 1", []
        )?;
        let _ = tx_ui.send(PhaseEvent::Log(
            "⚠️ Wykryto starszy schemat bazy Fazy 15 (znany wyścig zapisu UFS/Skrypt) - migruję do bezkolizyjnego schematu. \
             Stare dane zachowane w tabeli 'phase15_analysis_legacy_wyscig_zapisu', wszystkie pliki zostaną ponownie przeskanowane pod xattr.".to_string()
        ));
    }

    // INICJALIZACJA DUAL-LOGGING (Pobieranie ścieżek z Ustawień)
    let raport_cfg = config.raporty_faz.get("Faza 15").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza15.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza15.txt".to_string(),
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
        let mut f_info = opr_log.lock().unwrap();
        let _ = writeln!(f_info, "=== RAPORT OPERACYJNY - FAZA 15: ROZSZERZONE ATRYBUTY XATTR ===");
        let _ = writeln!(f_info, "Ewidencja ukrytych strumieni systemowych, właścicieli i-node (UID/GID) oraz śladów URL.\n");
    }

    // --- ETAP 1A: POBIERANIE ZADAŃ DO SKANOWANIA ---
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, has_xattr_ufs, has_xattr_script 
         FROM files 
         WHERE phase15_done = 0 OR phase15_done IS NULL"
    )?;
    
    let mut ufs_tasks = Vec::new();
    let mut script_tasks = Vec::new();
    let mut skipped = 0;

    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, i32>(0)?, row.get::<_, String>(1)?, row.get::<_, bool>(2)?, row.get::<_, bool>(3)?, row.get::<_, Option<bool>>(4)?, row.get::<_, Option<bool>>(5)?))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_ufs, in_scr, x_ufs, x_scr) = r;
        let is_common = in_ufs && in_scr;
        if in_ufs && x_ufs.is_none() { ufs_tasks.push(Task { id, rel_path: rel.clone(), is_common }); }
        if in_scr && x_scr.is_none() { script_tasks.push(Task { id, rel_path: rel.clone(), is_common }); }
        if (in_ufs && x_ufs.is_some()) || (in_scr && x_scr.is_some()) { skipped += 1; }
    }
    drop(stmt);

    let total_db_rows = ufs_tasks.len() + script_tasks.len();
    
    if skipped > 0 {
        let _ = tx_ui.send(PhaseEvent::Log(format!("Wznowienie sesji: Pominięto {} plików z wyliczonymi już atrybutami xattr.", skipped)));
    }

    if total_db_rows == 0 && skipped == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak plików wymagających inspekcji xattr. Baza aktualna.".to_string()));
        return Ok(());
    } else if total_db_rows == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Wszystkie pliki zostały już zeskanowane. Przechodzę prosto do raportowania...".to_string()));
    }

    let actual_threads = if config.max_threads > 0 { config.max_threads } else { rayon::current_num_threads() };
    let io_text = if config.io_mode == "CONCURRENT" { "RÓWNOLEGŁE" } else { "SEKWENCYJNIE" };
    let _ = tx_ui.send(PhaseEvent::Log(format!("Metodyka pracy szyny dyskowej: {}", io_text)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora (Rayon): {}", actual_threads)));

    let half_threads = compute_half_threads(actual_threads);
    let activity_slots = compute_activity_slots(&config.io_mode, actual_threads, half_threads);

    let ufs_stats = LiveStats::new(activity_slots);
    let script_stats = LiveStats::new(activity_slots);

    // --- ETAP 2 & 3: UI ORAZ PRZETWARZANIE STRUMIENIOWE (MPSC) ---
    if total_db_rows > 0 {
        let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "UFS Explorer (xattr)".to_string(), total: ufs_tasks.len() as u64, color: Color::Cyan });
        let _ = tx_ui.send(PhaseEvent::SetBar { idx: 1, label: "Skrypt Autorski (xattr)".to_string(), total: script_tasks.len() as u64, color: Color::Magenta });
        let _ = tx_ui.send(PhaseEvent::SetBar { idx: 2, label: "Zapis SQLite".to_string(), total: total_db_rows as u64, color: Color::Green });

        let ufs_base = PathBuf::from(&config.ufs_path);
        let script_base = PathBuf::from(&config.script_path);

        // REGRESJA (measure twice — druga weryfikacja Gemini): każdy błąd
        // SQLite w wątku bazy był wcześniej `.unwrap()`, czyli paniką w
        // wątku pisarza wewnątrz `thread::scope`. Ten sam wzorzec co
        // `phase17_repair::run`/`phase1::run`/`phase3::run` — `db_thread`
        // zwraca `Result<()>`, panika jest przechwytywana przez `.join()` i
        // zamieniana na błąd domenowy.
        let wynik_zapisu: Result<()> = std::thread::scope(|s| {
        let (tx_db, rx_db) = mpsc::sync_channel(200);
        let conn_ref = &mut *conn;

        // KLONUJEMY NADAJNIK UI DLA WĄTKU BAZY DANYCH
        let tx_ui_db = tx_ui.clone();

        let db_thread = s.spawn(move || -> Result<()> {
            let mut db_inserted = 0;
            let mut last_db_update = Instant::now();

            let update_sql = |c: &mut Connection, chunk: &[SideXattrResult], is_ufs: bool| -> Result<()> {
                let tx_db = c.transaction()?;
                {
                    // `side` jest teraz częścią klucza głównego (patrz
                    // naprawa Znaleziska 1, todo.faza15.md) - UFS i Skrypt
                    // dla tego samego `file_id` piszą do WŁASNYCH wierszy,
                    // nie kolidują.
                    let side = if is_ufs { "ufs" } else { "script" };

                    // OPTYMALIZACJA CPU: prepare_cached
                    let mut stmt_insert = tx_db.prepare_cached(
                        "INSERT OR REPLACE INTO phase15_analysis (file_id, side, has_xattr, xattr_count, xattr_size, xattr_keys, uid, gid, has_url, has_zone_identifier, has_quarantine, has_wherefroms, has_large_xattr)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
                    )?;

                    let mut stmt_update = match is_ufs {
                        true => tx_db.prepare_cached("UPDATE files SET has_xattr_ufs = COALESCE(?1, has_xattr_ufs), io_error_ufs = COALESCE(?2, io_error_ufs) WHERE id = ?3")?,
                        false => tx_db.prepare_cached("UPDATE files SET has_xattr_script = COALESCE(?1, has_xattr_script), io_error_script = COALESCE(?2, io_error_script) WHERE id = ?3")?
                    };

                    for res in chunk {
                        let mut has_x = None;
                        if let Some(meta) = &res.meta {
                            has_x = Some(meta.xattr_count > 0);
                            stmt_insert.execute(params![
                                res.id,
                                side,
                                has_x,
                                meta.xattr_count as i64,
                                meta.xattr_size_bytes as i64,
                                meta.xattr_keys,
                                meta.uid,
                                meta.gid,
                                meta.has_url,
                                meta.has_zone_identifier,
                                meta.has_quarantine,
                                meta.has_wherefroms,
                                meta.has_large_xattr,
                            ])?;
                        }
                        if has_x.is_some() || res.io_error == Some(true) {
                            stmt_update.execute(params![has_x, res.io_error, res.id])?;
                        }
                    }
                }
                tx_db.commit()
            };

            for msg in rx_db {
                let c_len = match &msg {
                    ScanMsg::UfsChunk(chunk) => { update_sql(conn_ref, chunk, true)?; chunk.len() }
                    ScanMsg::ScriptChunk(chunk) => { update_sql(conn_ref, chunk, false)?; chunk.len() }
                };
                
                db_inserted += c_len;
                let now = Instant::now();
                if now.duration_since(last_db_update).as_millis() > 60 {
                    last_db_update = now;
                    let _ = tx_ui_db.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Zapisywanie atrybutów xattr...".to_string() });
                }
            }
            let _ = tx_ui_db.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Atrybuty zsynchronizowane z SQLite.".to_string() });
            Ok(())
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone(); let tx2 = tx_db.clone();
            let info_u = opr_log.clone(); let info_s = opr_log.clone();
            
            let stat_u = &ufs_stats;
            let stat_s = &script_stats;
            
            // KLONUJEMY NADAJNIKI UI DLA WĄTKÓW I/O
            let tx_ui_1 = tx_ui.clone();
            let tx_ui_2 = tx_ui.clone();

            // NAPRAWA (ten sam bug jak w Fazie 5/6/7/10-14): dedykowana pula
            // per strona, minimum 1 wątek. Wyliczone wcześniej, tu tylko używane.

            s.spawn(move || { 
                if !ufs_tasks.is_empty() { 
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, start_time, tx_ui: &tx_ui_1, bar_idx: 0, opr_log: info_u, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, start_time, tx_ui: &tx_ui_1, bar_idx: 0, opr_log: info_u, });
                    }
                    let _ = tx_ui_1.send(PhaseEvent::Log("✔ Skanowanie węzłów UFS zakończone.".to_string())); 
                } 
            });
            s.spawn(move || { 
                if !script_tasks.is_empty() { 
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, start_time, tx_ui: &tx_ui_2, bar_idx: 1, opr_log: info_s, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, start_time, tx_ui: &tx_ui_2, bar_idx: 1, opr_log: info_s, });
                    }
                    let _ = tx_ui_2.send(PhaseEvent::Log("✔ Skanowanie węzłów Skrypt zakończone.".to_string())); 
                } 
            });
            drop(tx_db); 
        } else {
            let info_u = opr_log.clone(); let info_s = opr_log.clone();
            if !ufs_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: &ufs_stats, tx_db: tx_db.clone(), is_ufs: true, start_time, tx_ui: &tx_ui, bar_idx: 0, opr_log: info_u, });
                let _ = tx_ui.send(PhaseEvent::Log("✔ Skanowanie węzłów UFS zakończone.".to_string()));
            }
            if !script_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: &script_stats, tx_db: tx_db.clone(), is_ufs: false, start_time, tx_ui: &tx_ui, bar_idx: 1, opr_log: info_s, });
                let _ = tx_ui.send(PhaseEvent::Log("✔ Skanowanie węzłów Skrypt zakończone.".to_string()));
            }
            // REGRESJA (measure twice — druga weryfikacja Gemini): gdy
            // `script_tasks` jest puste, oryginalny `tx_db` nigdy nie był
            // przenoszony - kanał nie zamykał się, dopóki ta zmienna nie
            // wyszła z zasięgu na końcu CAŁEGO domknięcia `thread::scope`,
            // czyli PO `db_thread.join()` niżej - klasyczny deadlock (wątek
            // czeka na zamknięcie kanału, który sam trzyma otwarty). Jawny
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
                    "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 15 mógł nie zostać w pełni zapisany.".to_string()
                ));
                Err(rusqlite::Error::UnwindingPanic)
            }
        }
    });
    wynik_zapisu?;
}
    // --- ETAP 4: SYNCHRONIZACJA Z BAZĄ DANYCH ---
    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log("🛑 Skanowanie przerwane przez użytkownika.".to_string()));
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::Log("🔄 Trwa wiązanie dowodów xattr w bazie danych...".to_string()));
    conn.execute(
        "UPDATE files SET phase15_done = CASE 
            WHEN (found_in_ufs = 0 OR has_xattr_ufs IS NOT NULL OR io_error_ufs = 1) 
             AND (found_in_script = 0 OR has_xattr_script IS NOT NULL OR io_error_script = 1) THEN 1 
            ELSE 0 
        END WHERE phase15_done = 0 OR phase15_done IS NULL", []
    )?;

    // --- ETAP 5: RAPORT KRYMINALISTYCZNY HIERARCHICZNY ---
    let mut stats_common = CategoryStats::new();
    let mut stats_unique_ufs = CategoryStats::new();
    let mut stats_unique_scr = CategoryStats::new();

    // REGRESJA (todo.faza15.md, Znalezisko 1): `a.side` dodane do SELECT —
    // plik wspólny może teraz mieć DWA wiersze w `phase15_analysis` (jeden
    // na fizyczną kopię, patrz naprawa wyścigu zapisu wyżej), więc pętla
    // niżej może zobaczyć ten sam `relative_path` dwukrotnie, z osobnymi
    // wartościami UID/GID/kluczy dla każdej strony — obie muszą trafić do
    // raportu, żadna nie może cicho przepaść.
    let mut stmt = conn.prepare(
        "SELECT f.relative_path, f.found_in_ufs, f.found_in_script,
                a.has_xattr, a.xattr_size, a.uid, a.gid, a.xattr_keys, a.has_url, a.side
         FROM files f
         JOIN phase15_analysis a ON f.id = a.file_id
         WHERE f.phase15_done = 1 AND a.has_xattr = 1"
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, bool>(1)?,
            row.get::<_, bool>(2)?,
            row.get::<_, bool>(3)?,
            row.get::<_, i64>(4)? as u64,
            row.get::<_, u32>(5)?,
            row.get::<_, u32>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, bool>(8)?,
            row.get::<_, String>(9)?,
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (path, in_ufs, in_scr, _, size, uid, gid, keys, has_url, side) = r;
        let ext = Path::new(&path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
        let is_common = in_ufs && in_scr;
        let side_label = if side == "ufs" { "UFS Explorer".to_string() } else { "Skrypt Autorski".to_string() };

        if is_common { stats_common.add(&ext, path, uid, gid, keys, size, has_url, side_label); }
        else if in_ufs { stats_unique_ufs.add(&ext, path, uid, gid, keys, size, has_url, side_label); }
        else { stats_unique_scr.add(&ext, path, uid, gid, keys, size, has_url, side_label); }
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
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 15 (ROZSZERZONE ATRYBUTY XATTR)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "Sumaryczny transfer I/O: {} (Średnia prędkość: {:.2} MB/s)", format_bytes(total_bytes), avg_speed_mb);
    let _ = writeln!(&mut log_out, "==========================================================================\n");

    let sum_attrs = stats_common.count + stats_unique_ufs.count + stats_unique_scr.count;
    let sum_bytes = stats_common.total_xattr_bytes + stats_unique_ufs.total_xattr_bytes + stats_unique_scr.total_xattr_bytes;
    let sum_urls = stats_common.url_count + stats_unique_ufs.url_count + stats_unique_scr.url_count;

    let avg_xattr_bytes_sum = if sum_attrs > 0 { sum_bytes / sum_attrs as u64 } else { 0 };

    let _ = writeln!(&mut log_out, "[ 1 ] NISKOPOZIOMOWA INSPEKCJA METADANYCH (Extended Attributes):");
    let _ = writeln!(&mut log_out, "   -> Ocalono atrybuty z {} plików (Całkowita waga xattr: {}, średnio {} / plik)", sum_attrs, format_bytes(sum_bytes), format_bytes(avg_xattr_bytes_sum));
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Algorytm odzyskał metadane systemowe (niewchodzące w skład rozmiaru pliku). Służą one często jako flagi kwarantanny lub systemowe informacje użytkownika.\n");

    let _ = writeln!(&mut log_out, "[ 2 ] ŚLADY SIECIOWE (Web Forensics):");
    let _ = writeln!(&mut log_out, "   -> Wykryto ślady pobrania w {} plikach", sum_urls);
    let _ = writeln!(&mut log_out, "      -> Windows Zone.Identifier: {}", ufs_stats.zone_identifier_common.load(Ordering::SeqCst) + ufs_stats.zone_identifier_unique.load(Ordering::SeqCst) + script_stats.zone_identifier_common.load(Ordering::SeqCst) + script_stats.zone_identifier_unique.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "      -> macOS Quarantine:        {}", ufs_stats.quarantine_common.load(Ordering::SeqCst) + ufs_stats.quarantine_unique.load(Ordering::SeqCst) + script_stats.quarantine_common.load(Ordering::SeqCst) + script_stats.quarantine_unique.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "      -> macOS WhereFroms:        {}", ufs_stats.wherefroms_common.load(Ordering::SeqCst) + ufs_stats.wherefroms_unique.load(Ordering::SeqCst) + script_stats.wherefroms_common.load(Ordering::SeqCst) + script_stats.wherefroms_unique.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Pliki te posiadają specjalne tagi, które zawierają oryginalny adres URL przeglądarki lub datę pobrania. Ekstremalnie cenne znalezisko.\n");

    let sum_large = ufs_stats.large_xattr_common.load(Ordering::SeqCst) + ufs_stats.large_xattr_unique.load(Ordering::SeqCst) + script_stats.large_xattr_common.load(Ordering::SeqCst) + script_stats.large_xattr_unique.load(Ordering::SeqCst);
    if sum_large > 0 {
        let _ = writeln!(&mut log_out, "[ 3 ] ANOMALIA ROZMIARU XATTR (>64KB):");
        let _ = writeln!(&mut log_out, "   -> Pliki z nietypowo dużym blobem xattr: {}", sum_large);
        let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Normalne metadane systemowe to zwykle pojedyncze bajty/kilobajty. Znacznie większy blob może wskazywać na przemycone dane w rozszerzonym atrybucie.\n");
    }

    let sum_capability = ufs_stats.capability_common.load(Ordering::SeqCst) + ufs_stats.capability_unique.load(Ordering::SeqCst) + script_stats.capability_common.load(Ordering::SeqCst) + script_stats.capability_unique.load(Ordering::SeqCst);
    if sum_capability > 0 {
        let _ = writeln!(&mut log_out, "[ 3b ] UPRAWNIENIA LINUX (security.capability):");
        let _ = writeln!(&mut log_out, "   -> Pliki z ustawionymi uprawnieniami: {}", sum_capability);
        let mut merged_caps: HashMap<String, usize> = HashMap::new();
        for (k, v) in ufs_stats.capability_names_counts.lock().unwrap().iter().chain(script_stats.capability_names_counts.lock().unwrap().iter()) {
            *merged_caps.entry(k.clone()).or_insert(0) += v;
        }
        let mut sorted_caps: Vec<_> = merged_caps.iter().collect();
        sorted_caps.sort_by(|a, b| b.1.cmp(a.1));
        for (name, count) in sorted_caps.into_iter().take(10) {
            let _ = writeln!(&mut log_out, "      -> {:<22} {} wystąpień", name, count);
        }
        let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Plik wykonywalny z ustawionymi uprawnieniami (np. CAP_SYS_ADMIN/CAP_SETUID/CAP_NET_RAW) przetrwał odzysk z tym mechanizmem eskalacji uprawnień nienaruszonym - wart priorytetowej analizy bezpieczeństwa.\n");
    }

    // REGRESJA (todo.faza15.md, Znalezisko 2): rozkład przestrzeni nazw
    // xattr był liczony i agregowany globalnie (ufs_stats/script_stats.
    // namespace_counts) przez cały czas trwania fazy — dane były już w
    // pełni policzone i poprawne — ale nigdy nie trafiał do Dziennika
    // Końcowego, wyłącznie migał w panelu UI na żywo i znikał bezpowrotnie
    // po zakończeniu skanu, mimo że dokumentacja modułu reklamuje go jako
    // jedną z headline'owych funkcji tej rewizji.
    if let Some(sekcja) = format_namespace_section(
        &ufs_stats.namespace_counts.lock().unwrap(),
        &script_stats.namespace_counts.lock().unwrap(),
    ) {
        log_out.push_str(&sekcja);
    }

    let write_section_txt = |out: &mut String, title: &str, stats: &CategoryStats| {
        if stats.count > 0 {
            let _ = writeln!(out, "[ KATEGORIA ZNALEZISK: {} ]", title);
            write_category_block(out, stats);
        }
    };

    write_section_txt(&mut log_out, "Część Wspólna (Oba źródła)", &stats_common);
    write_section_txt(&mut log_out, "Osobne ścieżki (Tylko UFS Explorer)", &stats_unique_ufs);
    write_section_txt(&mut log_out, "Osobne ścieżki (Tylko Skrypt Autorski)", &stats_unique_scr);

    if total_io_errors > 0 {
        let _ = writeln!(&mut log_out, "\n[ BŁĘDY FIZYCZNE I/O ]");
        let _ = writeln!(&mut log_out, "   -> Pliki widma / Brak obsługi przez OS docelowy: {}", total_io_errors);
    }

    if let Ok(mut f) = fs::File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano fizyczny Dziennik Końcowy w: {}", dz_path.display())));
    }

    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    // Zrzut telemetrii do głównego pliku logów w tle
    info!(
        total_xattr_files = sum_attrs,
        total_xattr_bytes = sum_bytes,
        total_urls = sum_urls,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 15 zakończona"
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
    // compute_activity_slots (identyczna logika z Fazy 3-7/10-14)
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
    // get_file_category
    // ------------------------------------------------------------------

    #[test]
    fn test_get_file_category_known_and_unknown() {
        assert_eq!(get_file_category("zip"), "archiwum");
        assert_eq!(get_file_category("jpg"), "obraz");
        assert_eq!(get_file_category("brak"), "brak rozsz.");
        assert_eq!(get_file_category("xyz"), "inny");
    }

    // ------------------------------------------------------------------
    // classify_url_marker
    // ------------------------------------------------------------------

    #[test]
    fn test_classify_url_marker_zone_identifier() {
        assert_eq!(classify_url_marker("user.zone.identifier"), Some("zone_identifier"));
    }

    #[test]
    fn test_classify_url_marker_quarantine() {
        assert_eq!(classify_url_marker("com.apple.quarantine"), Some("quarantine"));
    }

    #[test]
    fn test_classify_url_marker_wherefroms() {
        assert_eq!(classify_url_marker("com.apple.metadata:kmditemwherefroms"), Some("wherefroms"));
    }

    #[test]
    fn test_classify_url_marker_generic_url() {
        assert_eq!(classify_url_marker("user.download.url"), Some("url_generic"));
    }

    #[test]
    fn test_classify_url_marker_none_for_unrelated_key() {
        assert_eq!(classify_url_marker("user.comment"), None);
        assert_eq!(classify_url_marker("security.selinux"), None);
    }

    #[test]
    fn test_classify_url_marker_quarantine_wins_over_generic_when_both_could_match() {
        // Klucz zawiera i "quarantine" - musi trafić do konkretnej kategorii,
        // nie do ogólnego "url_generic" (kolejność sprawdzeń w funkcji)
        assert_eq!(classify_url_marker("com.apple.quarantine"), Some("quarantine"));
    }

    // ------------------------------------------------------------------
    // xattr_namespace
    // ------------------------------------------------------------------

    #[test]
    fn test_xattr_namespace_standard_posix_namespaces() {
        assert_eq!(xattr_namespace("user.comment"), "user");
        assert_eq!(xattr_namespace("security.selinux"), "security");
        assert_eq!(xattr_namespace("system.posix_acl_access"), "system");
        assert_eq!(xattr_namespace("trusted.overlay.origin"), "trusted");
    }

    #[test]
    fn test_xattr_namespace_case_insensitive() {
        assert_eq!(xattr_namespace("User.Comment"), "user");
    }

    #[test]
    fn test_xattr_namespace_no_dot_is_other() {
        assert_eq!(xattr_namespace("nonamespacekey"), "other");
    }

    #[test]
    fn test_xattr_namespace_empty_prefix_is_other() {
        assert_eq!(xattr_namespace(".comment"), "other");
    }

    // ------------------------------------------------------------------
    // is_large_xattr
    // ------------------------------------------------------------------

    #[test]
    fn test_is_large_xattr_below_threshold() {
        assert!(!is_large_xattr(1024));
        assert!(!is_large_xattr(65536)); // dokładnie na progu - próg to ŚCIŚLE >
    }

    #[test]
    fn test_is_large_xattr_above_threshold() {
        assert!(is_large_xattr(65537));
        assert!(is_large_xattr(1_000_000));
    }

    // ------------------------------------------------------------------
    // parse_capability_names - syntetyczne bloki binarne `vfs_cap_data`
    // (dokładny format jądra Linux dla xattr security.capability), bez
    // potrzeby prawdziwego pliku z ustawionymi uprawnieniami na dysku.
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_capability_v1_single_bit() {
        // Rewizja 1 (0x01000000, LE): 32-bitowa maska w jednym słowie.
        // Bit 13 = CAP_NET_RAW (1 << 13 = 0x2000).
        let raw: [u8; 12] = [
            0x00, 0x00, 0x00, 0x01, // magic_etc: rewizja 1
            0x00, 0x20, 0x00, 0x00, // permitted: bit 13
            0x00, 0x00, 0x00, 0x00, // inheritable (pomijane)
        ];
        assert_eq!(parse_capability_names(&raw), vec!["CAP_NET_RAW"]);
    }

    #[test]
    fn test_parse_capability_v3_combines_low_and_high_words() {
        // Rewizja 3 (0x03000000, LE): 64-bitowa maska w dwóch słowach.
        // Bit 21 (słowo niskie) = CAP_SYS_ADMIN (1 << 21 = 0x200000).
        // Bit 35 = bit 3 słowa wysokiego (35-32=3) = CAP_WAKE_ALARM (1 << 3 = 0x08).
        let raw: [u8; 24] = [
            0x00, 0x00, 0x00, 0x03, // magic_etc: rewizja 3
            0x00, 0x00, 0x20, 0x00, // data[0].permitted: bit 21 (CAP_SYS_ADMIN)
            0x00, 0x00, 0x00, 0x00, // data[0].inheritable
            0x08, 0x00, 0x00, 0x00, // data[1].permitted: bit 3 = bit 35 (CAP_WAKE_ALARM)
            0x00, 0x00, 0x00, 0x00, // data[1].inheritable
            0x00, 0x00, 0x00, 0x00, // rootid (V3, nieużywane przez parser)
        ];
        let mut names = parse_capability_names(&raw);
        names.sort_unstable();
        assert_eq!(names, vec!["CAP_SYS_ADMIN", "CAP_WAKE_ALARM"]);
    }

    #[test]
    fn test_parse_capability_v2_revision_also_recognized() {
        let raw: [u8; 20] = [
            0x00, 0x00, 0x00, 0x02, // magic_etc: rewizja 2
            0x00, 0x00, 0x00, 0x00, // data[0].permitted: brak bitów
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, // data[1].permitted: bit 0 = bit 32 (CAP_MAC_OVERRIDE)
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(parse_capability_names(&raw), vec!["CAP_MAC_OVERRIDE"]);
    }

    #[test]
    fn test_parse_capability_too_short_is_empty() {
        assert_eq!(parse_capability_names(&[0x01, 0x00, 0x00]), Vec::<&str>::new());
        assert_eq!(parse_capability_names(&[]), Vec::<&str>::new());
    }

    #[test]
    fn test_parse_capability_unrecognized_revision_is_empty() {
        let raw: [u8; 12] = [0x00, 0x00, 0x00, 0x99, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_capability_names(&raw), Vec::<&str>::new());
    }

    #[test]
    fn test_parse_capability_v3_too_short_for_high_word_is_empty() {
        // Rewizja 3 zadeklarowana, ale bufor ucięty przed słowem wysokim
        // (poniżej 20 B) - typowy ślad uszkodzonego/odzyskanego xattr.
        let raw: [u8; 12] = [0x00, 0x00, 0x00, 0x03, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_capability_names(&raw), Vec::<&str>::new());
    }

    #[test]
    fn test_parse_capability_zero_mask_is_empty() {
        let raw: [u8; 12] = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_capability_names(&raw), Vec::<&str>::new());
    }

    // ------------------------------------------------------------------
    // format_namespace_section (Znalezisko 2, todo.faza15.md)
    // ------------------------------------------------------------------

    #[test]
    fn test_format_namespace_section_puste_obie_strony_daje_none() {
        assert_eq!(format_namespace_section(&HashMap::new(), &HashMap::new()), None);
    }

    #[test]
    fn test_format_namespace_section_laczy_obie_strony_i_sortuje_malejaco() {
        let mut ufs = HashMap::new();
        ufs.insert("user".to_string(), 10);
        ufs.insert("trusted".to_string(), 1);

        let mut script = HashMap::new();
        script.insert("user".to_string(), 5); // musi się zsumować z UFS: 10+5=15
        script.insert("security".to_string(), 3);

        let sekcja = format_namespace_section(&ufs, &script).expect("niepuste mapy muszą dać Some");

        assert!(sekcja.contains("[ 4 ] ROZKŁAD PRZESTRZENI NAZW XATTR"));
        assert!(sekcja.contains("user:       15 kluczy"), "user musi być sumą obu stron (10+5):\n{}", sekcja);

        let pos_user = sekcja.find("user:").expect("brak user");
        let pos_security = sekcja.find("security:").expect("brak security");
        let pos_trusted = sekcja.find("trusted:").expect("brak trusted");
        assert!(pos_user < pos_security, "user (15) musi być przed security (3)");
        assert!(pos_security < pos_trusted, "security (3) musi być przed trusted (1)");
    }

    #[test]
    fn test_format_namespace_section_dziala_gdy_tylko_jedna_strona_ma_dane() {
        let mut ufs = HashMap::new();
        ufs.insert("system".to_string(), 2);
        let script = HashMap::new();

        let sekcja = format_namespace_section(&ufs, &script).expect("jedna niepusta strona wystarczy do Some");
        assert!(sekcja.contains("system:     2 kluczy"));
    }

    // ------------------------------------------------------------------
    // CategoryStats
    // ------------------------------------------------------------------

    #[test]
    fn test_category_stats_accumulates() {
        let mut stats = CategoryStats::new();
        stats.add("jpg", "a.jpg".to_string(), 1000, 1000, "user.comment".to_string(), 128, false, "UFS Explorer".to_string());
        stats.add("jpg", "b.jpg".to_string(), 0, 0, "com.apple.quarantine".to_string(), 256, true, "Skrypt Autorski".to_string());

        assert_eq!(stats.count, 2);
        assert_eq!(stats.url_count, 1);
        assert_eq!(stats.total_xattr_bytes, 384);
        assert_eq!(stats.extensions.get("jpg").unwrap().len(), 2);
    }

    #[test]
    fn test_category_stats_empty_by_default() {
        let stats = CategoryStats::new();
        assert_eq!(stats.count, 0);
        assert_eq!(stats.url_count, 0);
        assert_eq!(stats.total_xattr_bytes, 0);
    }

    // ------------------------------------------------------------------
    // compute_half_threads / build_source_block
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_half_threads() {
        assert_eq!(compute_half_threads(8), 4);
        assert_eq!(compute_half_threads(1), 1);
    }

    // ------------------------------------------------------------------
    // opisy_anomalii: każda REALNA etykieta wiersza panelu (poza
    // generycznymi) musi mieć zarejestrowane wyjaśnienie — inaczej Enter na
    // tym wierszu w prawdziwym UI nie pokaże nakładki. Mirror wzorca z Fazy
    // 5-14.
    // ------------------------------------------------------------------

    #[test]
    fn test_etykiety_maja_zarejestrowane_wyjasnienia_albo_sa_generyczne() {
        const GENERYCZNE: &[&str] = &["Prędkość", "Wątki odczytu xattr (Wariant A)", "Błędy I/O"];

        let stats = LiveStats::new(2);
        let block = build_source_block("UFS Explorer", &stats, Instant::now());

        let mut sprawdzonych = 0;
        for line in block.lines() {
            if line.starts_with('[') { continue; }
            let Some((etykieta, _)) = line.split_once(": ") else { continue; };
            if GENERYCZNE.contains(&etykieta) { continue; }

            assert!(
                crate::opisy_anomalii::znajdz_opis(etykieta).is_some(),
                "etykieta \"{}\" z panelu Fazy 15 nie ma zarejestrowanego wyjaśnienia w opisy_anomalii", etykieta
            );
            sprawdzonych += 1;
        }
        assert_eq!(sprawdzonych, 11, "liczba sprawdzonych etykiet zmieniła się - zaktualizuj GENERYCZNE albo opisy_anomalii/faza15_xattr.rs");
    }

    #[test]
    fn test_build_source_block_reports_new_counters() {
        use std::time::Duration;
        let stats = LiveStats::new(4);
        stats.zone_identifier_common.store(3, Ordering::Relaxed);
        stats.quarantine_common.store(2, Ordering::Relaxed);
        stats.wherefroms_common.store(1, Ordering::Relaxed);
        stats.large_xattr_common.store(4, Ordering::Relaxed);
        stats.namespace_counts.lock().unwrap().insert("user".to_string(), 10);

        let start_time = Instant::now() - Duration::from_secs(1);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        assert!(block.contains("Zone.Identifier (Windows): 3 wspólne / 0 unikalne"));
        assert!(block.contains("Quarantine (macOS): 2 wspólne / 0 unikalne"));
        assert!(block.contains("WhereFroms (macOS): 1 wspólne / 0 unikalne"));
        assert!(block.contains("Anomalia rozmiaru (>64KB): 4 wspólne / 0 unikalne"));
        assert!(block.contains("Przestrzenie nazw xattr: user: 10"));
    }

    #[test]
    fn test_build_source_block_splits_found_attrs_and_urls_common_unique() {
        let stats = LiveStats::new(4);
        stats.found_attrs_common.store(5, Ordering::Relaxed);
        stats.found_attrs_unique.store(3, Ordering::Relaxed);
        stats.found_urls_common.store(2, Ordering::Relaxed);
        stats.found_urls_unique.store(1, Ordering::Relaxed);

        let block = build_source_block("UFS Explorer", &stats, Instant::now());
        assert!(block.contains("XATTR znalezione: 5 wspólne / 3 unikalne"));
        assert!(block.contains("URL ogólne: 2 wspólne / 1 unikalne"));
    }

    #[test]
    fn test_build_source_block_reports_average_xattr_size() {
        let stats = LiveStats::new(4);
        stats.found_attrs_common.store(2, Ordering::Relaxed);
        stats.xattr_total_bytes.store(2048, Ordering::Relaxed);

        let block = build_source_block("UFS Explorer", &stats, Instant::now());
        assert!(block.contains("Śr. rozmiar xattr (pliki z atrybutami): 1.00 KB"));
    }

    #[test]
    fn test_build_source_block_average_xattr_size_zero_when_nothing_found() {
        let stats = LiveStats::new(4);
        let block = build_source_block("UFS Explorer", &stats, Instant::now());
        assert!(block.contains("Śr. rozmiar xattr (pliki z atrybutami): 0 B"));
    }

    #[test]
    fn test_build_source_block_reports_capability_counts_and_names() {
        let stats = LiveStats::new(4);
        stats.capability_common.store(1, Ordering::Relaxed);
        stats.capability_unique.store(2, Ordering::Relaxed);
        stats.capability_names_counts.lock().unwrap().insert("CAP_NET_RAW".to_string(), 3);

        let block = build_source_block("UFS Explorer", &stats, Instant::now());
        assert!(block.contains("Linux Capabilities (security.capability): 1 wspólne / 2 unikalne (CAP_NET_RAW: 3)"));
    }

    #[test]
    fn test_build_source_block_shows_thread_activity_markup() {
        use std::time::Duration;
        let stats = LiveStats::new(2);
        stats.thread_activity.mark_busy(1);

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        let line = block.lines().find(|l| l.starts_with("Wątki odczytu xattr")).expect("powinna istnieć linia Wariantu A");
        assert_eq!(line, "Wątki odczytu xattr (Wariant A): {R:1} {G:2}");
    }

    #[test]
    fn test_build_source_block_placeholder_when_empty() {
        use std::time::Duration;
        let stats = LiveStats::new(4);
        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("Skrypt Autorski", &stats, start_time);
        assert!(block.contains("Przestrzenie nazw xattr: -"));
        assert!(block.contains("Top rozszerzenia (xattr): -"));
    }

    // ------------------------------------------------------------------
    // run() end-to-end — Znalezisko 1 (todo.faza15.md): wyścig zapisu
    // UFS×Skrypt do wspólnego wiersza phase15_analysis
    //
    // Celowo NIE polegamy tu na prawdziwych xattr na dysku (patrz uwaga
    // architektoniczna na początku modułu — mogą nie być wspierane w
    // środowisku testowym/CI). `stmt_insert` w `update_sql` jest wołane dla
    // KAŻDEGO przetworzonego pliku niezależnie od tego, czy faktycznie ma
    // jakiekolwiek xattr (`has_xattr` może być `false`) — sedno tego testu
    // to sama KOLIZJA WIERSZA w bazie, nie treść xattr.
    // ------------------------------------------------------------------

    #[test]
    fn test_run_plik_wspolny_dostaje_dwa_niekolidujace_wiersze_ufs_i_skrypt() {
        let ufs_dir = tempfile::tempdir().unwrap();
        let script_dir = tempfile::tempdir().unwrap();
        let log_dir = tempfile::tempdir().unwrap();
        std::fs::write(ufs_dir.path().join("wspolny.txt"), b"tresc ufs").unwrap();
        std::fs::write(script_dir.path().join("wspolny.txt"), b"tresc skrypt").unwrap();

        let mut conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (relative_path, found_in_ufs, found_in_script) VALUES ('wspolny.txt', 1, 1)",
            [],
        ).unwrap();
        let file_id: i64 = conn.query_row("SELECT id FROM files WHERE relative_path = 'wspolny.txt'", [], |r| r.get(0)).unwrap();

        let mut config = Ustawienia {
            ufs_path: ufs_dir.path().to_string_lossy().to_string(),
            script_path: script_dir.path().to_string_lossy().to_string(),
            log_path: log_dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        config.raporty_faz.clear();
        let (tx_ui, _rx_ui) = mpsc::channel();

        run(&mut conn, &config, tx_ui).expect("run() musi zakończyć się Ok");

        let liczba_wierszy: i64 = conn.query_row(
            "SELECT COUNT(*) FROM phase15_analysis WHERE file_id = ?1", params![file_id], |r| r.get(0)
        ).unwrap();
        assert_eq!(
            liczba_wierszy, 2,
            "plik wspólny musi dać DWA niekolidujące wiersze (jeden na fizyczną kopię) - \
             przed naprawą Znaleziska 1 drugi zapis (INSERT OR REPLACE na file_id PRIMARY KEY \
             bez rozróżnienia strony) bezpowrotnie nadpisywał pierwszy, zostawiając tylko 1 wiersz"
        );

        let mut stmt = conn.prepare("SELECT side FROM phase15_analysis WHERE file_id = ?1 ORDER BY side").unwrap();
        let sides: Vec<String> = stmt.query_map(params![file_id], |r| r.get(0)).unwrap().filter_map(|r| r.ok()).collect();
        assert_eq!(sides, vec!["script".to_string(), "ufs".to_string()], "obie strony muszą być obecne, każda pod własnym wierszem");
    }

    /// Plik UNIKALNY (tylko jedna strona) musi dać dokładnie JEDEN wiersz —
    /// kontrola pozytywna, żeby naprawa Znaleziska 1 nie zaczęła tworzyć
    /// nadmiarowych wierszy tam, gdzie druga strona w ogóle nie istnieje.
    #[test]
    fn test_run_plik_unikalny_dostaje_dokladnie_jeden_wiersz() {
        let ufs_dir = tempfile::tempdir().unwrap();
        let script_dir = tempfile::tempdir().unwrap();
        let log_dir = tempfile::tempdir().unwrap();
        std::fs::write(ufs_dir.path().join("tylko_ufs.txt"), b"tresc").unwrap();

        let mut conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (relative_path, found_in_ufs, found_in_script) VALUES ('tylko_ufs.txt', 1, 0)",
            [],
        ).unwrap();
        let file_id: i64 = conn.query_row("SELECT id FROM files WHERE relative_path = 'tylko_ufs.txt'", [], |r| r.get(0)).unwrap();

        let mut config = Ustawienia {
            ufs_path: ufs_dir.path().to_string_lossy().to_string(),
            script_path: script_dir.path().to_string_lossy().to_string(),
            log_path: log_dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        config.raporty_faz.clear();
        let (tx_ui, _rx_ui) = mpsc::channel();

        run(&mut conn, &config, tx_ui).expect("run() musi zakończyć się Ok");

        let liczba_wierszy: i64 = conn.query_row(
            "SELECT COUNT(*) FROM phase15_analysis WHERE file_id = ?1", params![file_id], |r| r.get(0)
        ).unwrap();
        assert_eq!(liczba_wierszy, 1);

        let side: String = conn.query_row("SELECT side FROM phase15_analysis WHERE file_id = ?1", params![file_id], |r| r.get(0)).unwrap();
        assert_eq!(side, "ufs");
    }

    /// Migracja ze starego kształtu tabeli (sprzed naprawy Znaleziska 1, bez
    /// kolumny `side`) — stare dane muszą przetrwać pod inną nazwą (nie
    /// zostać po cichu skasowane), a nowa tabela musi dostać kolumnę `side`.
    #[test]
    fn test_run_migruje_stary_ksztalt_tabeli_bez_utraty_danych() {
        let ufs_dir = tempfile::tempdir().unwrap();
        let script_dir = tempfile::tempdir().unwrap();
        let log_dir = tempfile::tempdir().unwrap();

        let mut conn = crate::db::init_db(":memory:").unwrap();

        // `init_db` tworzy `phase15_analysis` już przy inicjalizacji, w
        // NOWYM (naprawionym) kształcie - patrz `db.rs::create_analysis_tables`.
        // Żeby wiarygodnie zasymulować bazę SPRZED tej naprawy, musimy
        // najpierw usunąć tę już-poprawną tabelę i odtworzyć ją w STARYM
        // kształcie - `file_id INTEGER PRIMARY KEY`, bez `side`.
        conn.execute("DROP TABLE phase15_analysis", []).unwrap();
        conn.execute(
            "CREATE TABLE phase15_analysis (
                file_id INTEGER PRIMARY KEY,
                has_xattr BOOLEAN, xattr_count INTEGER, xattr_size INTEGER, xattr_keys TEXT,
                uid INTEGER, gid INTEGER, has_url BOOLEAN,
                FOREIGN KEY(file_id) REFERENCES files(id)
            )", [],
        ).unwrap();
        conn.execute(
            "INSERT INTO files (relative_path, found_in_ufs, found_in_script, has_xattr_ufs, phase15_done) VALUES ('stary.txt', 1, 0, 1, 1)",
            [],
        ).unwrap();
        let file_id: i64 = conn.query_row("SELECT id FROM files WHERE relative_path = 'stary.txt'", [], |r| r.get(0)).unwrap();
        conn.execute(
            "INSERT INTO phase15_analysis (file_id, has_xattr, uid, gid) VALUES (?1, 1, 999, 999)",
            params![file_id],
        ).unwrap();

        let mut config = Ustawienia {
            ufs_path: ufs_dir.path().to_string_lossy().to_string(),
            script_path: script_dir.path().to_string_lossy().to_string(),
            log_path: log_dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        config.raporty_faz.clear();
        let (tx_ui, _rx_ui) = mpsc::channel();

        run(&mut conn, &config, tx_ui).expect("run() musi zakończyć się Ok mimo migracji w trakcie");

        // Stara tabela musi przetrwać pod inną nazwą - z oryginalnym wierszem nietkniętym.
        let stary_uid: u32 = conn.query_row(
            "SELECT uid FROM phase15_analysis_legacy_wyscig_zapisu WHERE file_id = ?1", params![file_id], |r| r.get(0)
        ).expect("stare dane muszą przetrwać migrację pod inną nazwą, nie zniknąć");
        assert_eq!(stary_uid, 999, "stary wiersz musi zostać zachowany bez zmian");

        // Nowa tabela musi mieć kolumnę `side`.
        let mut stmt = conn.prepare("PRAGMA table_info(phase15_analysis)").unwrap();
        let cols: Vec<String> = stmt.query_map([], |row| row.get::<_, String>(1)).unwrap().filter_map(|r| r.ok()).collect();
        assert!(cols.contains(&"side".to_string()), "nowa tabela musi mieć kolumnę side: {:?}", cols);
    }
}
