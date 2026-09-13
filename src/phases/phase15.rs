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

#[derive(Debug, Clone)]
pub(crate) struct Task {
    id: i32,
    rel_path: String,
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

/// Liczniki live dla JEDNEJ strony. `found_attrs`/`found_urls` — zbiorcze
/// (bez podziału common/unique, bo [`Task`] w tej fazie nie niesie tej
/// informacji — podział wspólne/unikalne jest liczony dopiero w Etapie 5
/// z zapytania SQL po zakończeniu skanowania). Cztery nowe liczniki
/// (`zone_identifier_count`/`quarantine_count`/`wherefroms_count`/
/// `large_xattr_count`) i mapa `namespace_counts` to rozszerzenie tej
/// samej, prostej architektury.
pub(crate) struct LiveStats {
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    found_attrs: AtomicUsize,
    found_urls: AtomicUsize,
    xattr_total_bytes: AtomicU64,
    errors: AtomicUsize,
    extensions: Mutex<HashMap<String, usize>>,
    top_owners: Mutex<HashMap<String, usize>>,

    zone_identifier_count: AtomicUsize,
    quarantine_count: AtomicUsize,
    wherefroms_count: AtomicUsize,
    large_xattr_count: AtomicUsize,
    namespace_counts: Mutex<HashMap<String, usize>>,

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
            found_attrs: AtomicUsize::new(0),
            found_urls: AtomicUsize::new(0),
            xattr_total_bytes: AtomicU64::new(0),
            errors: AtomicUsize::new(0),
            extensions: Mutex::new(HashMap::new()),
            top_owners: Mutex::new(HashMap::new()),
            zone_identifier_count: AtomicUsize::new(0),
            quarantine_count: AtomicUsize::new(0),
            wherefroms_count: AtomicUsize::new(0),
            large_xattr_count: AtomicUsize::new(0),
            namespace_counts: Mutex::new(HashMap::new()),
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

    let activity_markup = crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot());

    format!(
        "[{}]\nPrędkość: {:.0} plików/s\nXATTR znalezione: {} ({})\nTop rozszerzenia (xattr): {}\nTop właściciele (UID:GID): {}\nPrzestrzenie nazw xattr: {}\nZone.Identifier (Windows): {}\nQuarantine (macOS): {}\nWhereFroms (macOS): {}\nURL ogólne: {}\nAnomalia rozmiaru (>64KB): {}\nWątki odczytu xattr (Wariant A): {}\nBłędy I/O: {}",
        label, speed_files,
        stats.found_attrs.load(Ordering::Relaxed), format_bytes(stats.xattr_total_bytes.load(Ordering::Relaxed)),
        display_ext, display_own, display_ns,
        stats.zone_identifier_count.load(Ordering::Relaxed),
        stats.quarantine_count.load(Ordering::Relaxed),
        stats.wherefroms_count.load(Ordering::Relaxed),
        stats.found_urls.load(Ordering::Relaxed),
        stats.large_xattr_count.load(Ordering::Relaxed),
        activity_markup,
        stats.errors.load(Ordering::Relaxed),
    )
}

type ExtMap = HashMap<String, Vec<(String, u32, u32, String)>>; 

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
    fn add(&mut self, ext: &str, path: String, uid: u32, gid: u32, keys: String, bytes: u64, has_url: bool) {
        self.count += 1;
        self.total_xattr_bytes += bytes;
        if has_url { self.url_count += 1; }
        self.extensions.entry(ext.to_string()).or_default().push((path, uid, gid, keys));
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
/// sprawdza, czy pasuje do znanego markera URL ([`classify_url_marker`]).
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
            }
        }
    }

    let has_large_xattr = is_large_xattr(xattr_size_bytes);

    Ok(MetadataAnalysis {
        uid, gid, xattr_count, xattr_size_bytes,
        xattr_keys: keys_vec.join(", "),
        has_url, has_zone_identifier, has_quarantine, has_wherefroms, has_large_xattr,
        namespace_counts,
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
        let _ = writeln!(out, "     - Typ Pliku: {:<12} [ {:<4} ]: {} plików", cat, ext, paths.len());
        
        let (sample_path, s_uid, s_gid, s_keys) = &paths[0];
        
        let _ = writeln!(out, "       [ 🔍 ] Przykładowy dowód z tej grupy:");
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
                        stats.found_attrs.fetch_add(1, Ordering::Relaxed);
                        stats.xattr_total_bytes.fetch_add(meta.xattr_size_bytes, Ordering::Relaxed);
                        *local_exts.entry(ext.clone()).or_insert(0) += 1;

                        for (ns, count) in &meta.namespace_counts {
                            *local_namespaces.entry(ns.clone()).or_insert(0) += count;
                        }

                        if meta.has_url { stats.found_urls.fetch_add(1, Ordering::Relaxed); }
                        if meta.has_zone_identifier { stats.zone_identifier_count.fetch_add(1, Ordering::Relaxed); }
                        if meta.has_quarantine { stats.quarantine_count.fetch_add(1, Ordering::Relaxed); }
                        if meta.has_wherefroms { stats.wherefroms_count.fetch_add(1, Ordering::Relaxed); }
                        if meta.has_large_xattr { stats.large_xattr_count.fetch_add(1, Ordering::Relaxed); }

                        if let Ok(mut f) = opr_log.lock() {
                            let url_flag = if meta.has_url { "[ 🌐 URL!]" } else { "" };
                            let large_flag = if meta.has_large_xattr { "[ ⚠️ DUŻY XATTR!]" } else { "" };
                            let _ = writeln!(f, "[{kategoria:<6}] [Rozsz: .{ext:<4}] [UID: {:<4} | GID: {:<4}] [Rozmiar XATTR: {:<6}] {url_flag}{large_flag} [Klucze: {}] -> \"{}\"", 
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
    conn.execute(
        "CREATE TABLE IF NOT EXISTS phase15_analysis (
            file_id INTEGER PRIMARY KEY,
            has_xattr BOOLEAN,
            xattr_count INTEGER,
            xattr_size INTEGER,
            xattr_keys TEXT,
            uid INTEGER,
            gid INTEGER,
            has_url BOOLEAN,
            FOREIGN KEY(file_id) REFERENCES files(id)
        )", []
    )?;
    // Kolumny dla nowych, bardziej szczegółowych sygnałów (ALTER dla zgodności
    // wstecznej z bazami utworzonymi przed tą rewizją, gdzie CREATE TABLE IF
    // NOT EXISTS powyżej jest no-opem).
    let _ = conn.execute("ALTER TABLE phase15_analysis ADD COLUMN has_zone_identifier BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE phase15_analysis ADD COLUMN has_quarantine BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE phase15_analysis ADD COLUMN has_wherefroms BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE phase15_analysis ADD COLUMN has_large_xattr BOOLEAN", []);

    // INICJALIZACJA DUAL-LOGGING (Pobieranie ścieżek z Ustawień)
    let raport_cfg = config.raporty_faz.get("Faza 15").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza15.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza15.txt".to_string(),
    });
    
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);

    let opr_log = Arc::new(Mutex::new(File::create(&opr_path).unwrap()));
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
        if in_ufs && x_ufs.is_none() { ufs_tasks.push(Task { id, rel_path: rel.clone() }); }
        if in_scr && x_scr.is_none() { script_tasks.push(Task { id, rel_path: rel.clone() }); }
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

        std::thread::scope(|s| {
        let (tx_db, rx_db) = mpsc::sync_channel(200);
        let conn_ref = &mut *conn;
        
        // KLONUJEMY NADAJNIK UI DLA WĄTKU BAZY DANYCH
        let tx_ui_db = tx_ui.clone();

        let _db_thread = s.spawn(move || {
            let mut db_inserted = 0;
            let mut last_db_update = Instant::now();

            let update_sql = |c: &mut Connection, chunk: &[SideXattrResult], is_ufs: bool| {
                let tx_db = c.transaction().unwrap();
                {
                    // OPTYMALIZACJA CPU: prepare_cached
                    let mut stmt_insert = tx_db.prepare_cached(
                        "INSERT OR REPLACE INTO phase15_analysis (file_id, has_xattr, xattr_count, xattr_size, xattr_keys, uid, gid, has_url, has_zone_identifier, has_quarantine, has_wherefroms, has_large_xattr) 
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
                    ).unwrap();

                    let mut stmt_update = match is_ufs {
                        true => tx_db.prepare_cached("UPDATE files SET has_xattr_ufs = COALESCE(?1, has_xattr_ufs), io_error_ufs = COALESCE(?2, io_error_ufs) WHERE id = ?3").unwrap(),
                        false => tx_db.prepare_cached("UPDATE files SET has_xattr_script = COALESCE(?1, has_xattr_script), io_error_script = COALESCE(?2, io_error_script) WHERE id = ?3").unwrap()
                    };

                    for res in chunk {
                        let mut has_x = None;
                        if let Some(meta) = &res.meta {
                            has_x = Some(meta.xattr_count > 0);
                            stmt_insert.execute(params![
                                res.id, 
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
                            ]).unwrap();
                        }
                        if has_x.is_some() || res.io_error == Some(true) {
                            stmt_update.execute(params![has_x, res.io_error, res.id]).unwrap();
                        }
                    }
                }
                tx_db.commit().unwrap();
            };

            for msg in rx_db {
                let c_len = match &msg {
                    ScanMsg::UfsChunk(chunk) => { update_sql(conn_ref, chunk, true); chunk.len() }
                    ScanMsg::ScriptChunk(chunk) => { update_sql(conn_ref, chunk, false); chunk.len() }
                };
                
                db_inserted += c_len;
                let now = Instant::now();
                if now.duration_since(last_db_update).as_millis() > 60 {
                    last_db_update = now;
                    let _ = tx_ui_db.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Zapisywanie atrybutów xattr...".to_string() });
                }
            }
            let _ = tx_ui_db.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Atrybuty zsynchronizowane z SQLite.".to_string() });
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
                process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: &script_stats, tx_db, is_ufs: false, start_time, tx_ui: &tx_ui, bar_idx: 1, opr_log: info_s, }); 
                let _ = tx_ui.send(PhaseEvent::Log("✔ Skanowanie węzłów Skrypt zakończone.".to_string())); 
            }
        }
    });
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

    let mut stmt = conn.prepare(
        "SELECT f.relative_path, f.found_in_ufs, f.found_in_script, 
                a.has_xattr, a.xattr_size, a.uid, a.gid, a.xattr_keys, a.has_url 
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
            row.get::<_, bool>(8)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (path, in_ufs, in_scr, _, size, uid, gid, keys, has_url) = r;
        let ext = Path::new(&path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
        let is_common = in_ufs && in_scr;

        if is_common { stats_common.add(&ext, path, uid, gid, keys, size, has_url); }
        else if in_ufs { stats_unique_ufs.add(&ext, path, uid, gid, keys, size, has_url); }
        else { stats_unique_scr.add(&ext, path, uid, gid, keys, size, has_url); }
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

    let _ = writeln!(&mut log_out, "[ 1 ] NISKOPOZIOMOWA INSPEKCJA METADANYCH (Extended Attributes):");
    let _ = writeln!(&mut log_out, "   -> Ocalono atrybuty z {} plików (Całkowita waga xattr: {})", sum_attrs, format_bytes(sum_bytes));
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Algorytm odzyskał metadane systemowe (niewchodzące w skład rozmiaru pliku). Służą one często jako flagi kwarantanny lub systemowe informacje użytkownika.\n");
    
    let _ = writeln!(&mut log_out, "[ 2 ] ŚLADY SIECIOWE (Web Forensics):");
    let _ = writeln!(&mut log_out, "   -> Wykryto ślady pobrania w {} plikach", sum_urls);
    let _ = writeln!(&mut log_out, "      -> Windows Zone.Identifier: {}", ufs_stats.zone_identifier_count.load(Ordering::SeqCst) + script_stats.zone_identifier_count.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "      -> macOS Quarantine:        {}", ufs_stats.quarantine_count.load(Ordering::SeqCst) + script_stats.quarantine_count.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "      -> macOS WhereFroms:        {}", ufs_stats.wherefroms_count.load(Ordering::SeqCst) + script_stats.wherefroms_count.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Pliki te posiadają specjalne tagi, które zawierają oryginalny adres URL przeglądarki lub datę pobrania. Ekstremalnie cenne znalezisko.\n");

    let sum_large = ufs_stats.large_xattr_count.load(Ordering::SeqCst) + script_stats.large_xattr_count.load(Ordering::SeqCst);
    if sum_large > 0 {
        let _ = writeln!(&mut log_out, "[ 3 ] ANOMALIA ROZMIARU XATTR (>64KB):");
        let _ = writeln!(&mut log_out, "   -> Pliki z nietypowo dużym blobem xattr: {}", sum_large);
        let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Normalne metadane systemowe to zwykle pojedyncze bajty/kilobajty. Znacznie większy blob może wskazywać na przemycone dane w rozszerzonym atrybucie.\n");
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
    // CategoryStats
    // ------------------------------------------------------------------

    #[test]
    fn test_category_stats_accumulates() {
        let mut stats = CategoryStats::new();
        stats.add("jpg", "a.jpg".to_string(), 1000, 1000, "user.comment".to_string(), 128, false);
        stats.add("jpg", "b.jpg".to_string(), 0, 0, "com.apple.quarantine".to_string(), 256, true);

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

    #[test]
    fn test_build_source_block_reports_new_counters() {
        use std::time::Duration;
        let stats = LiveStats::new(4);
        stats.zone_identifier_count.store(3, Ordering::Relaxed);
        stats.quarantine_count.store(2, Ordering::Relaxed);
        stats.wherefroms_count.store(1, Ordering::Relaxed);
        stats.large_xattr_count.store(4, Ordering::Relaxed);
        stats.namespace_counts.lock().unwrap().insert("user".to_string(), 10);

        let start_time = Instant::now() - Duration::from_secs(1);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        assert!(block.contains("Zone.Identifier (Windows): 3"));
        assert!(block.contains("Quarantine (macOS): 2"));
        assert!(block.contains("WhereFroms (macOS): 1"));
        assert!(block.contains("Anomalia rozmiaru (>64KB): 4"));
        assert!(block.contains("Przestrzenie nazw xattr: user: 10"));
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
}
