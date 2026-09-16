// src/phases/phase3.rs

//! # Faza 3: Zaawansowana Akwizycja Sum Kontrolnych (BLAKE3) i Forensics Pierwszego Klastra
//!
//! Zintegrowany, jednoprzebiegowy silnik skanujący dyski pod kątem fałszerstw.
//! Odczytuje zawartość, weryfikuje strukturę Magic Bytes oraz loguje anomalie
//! do Raportu Operacyjnego na żywo. Komunikuje się z Ratatui za pomocą PhaseEvent.
//!
//! UWAGA ARCHITEKTONICZNA (UI): Pasek postępu (Gauge) pokazuje wyłącznie % i bieżący
//! plik. Wszystkie liczniki live (prędkość, sygnatury, anomalie nagłówka) trafiają
//! do panelu bocznego (scanner_panel::draw_side_stats_panel) jako dwa zbiorcze
//! bloki sumowane z obu źródeł (UFS + Skrypt) — Wariant B (patrz [`build_crypto_block`],
//! [`build_anomaly_block`]).
//!
//! UWAGA ARCHITEKTONICZNA (WĄTKOWANIE): W trybie `io_mode = "CONCURRENT"` obie strony
//! (UFS i Skrypt) skanują jednocześnie, każda na WŁASNEJ, tymczasowej puli Rayon
//! o rozmiarze `total_threads / 2` (patrz [`compute_half_threads`]). Dzięki temu
//! łączne zużycie CPU obu stron razem nigdy nie przekracza limitu ustawionego
//! przez użytkownika (`max_threads`), niezależnie od tego, że fizycznie pracują
//! dwa niezależne wątki systemowe na dwóch różnych dyskach. Jeśli budowa prywatnej
//! puli się nie powiedzie (skrajnie rzadki przypadek wyczerpania zasobów OS),
//! funkcja bezpiecznie spada na globalną pulę Rayon zamiast panikować — patrz
//! blok `if let Ok(pool) = ... else { ... }` w [`run`].
//! W trybie `SEQUENTIAL` obie strony skanują po kolei i każda dostaje pełny
//! budżet globalnej puli Rayon (`actual_threads`), bez dzielenia na pół.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::{format_bytes, format_display_path, hash_file, CANCEL_SIGNAL};
use ratatui::style::Color;
use rayon::prelude::*;
use rusqlite::{params, Connection, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, instrument};

// OPTYMALIZACJA: Podniesiono rozmiar paczki, aby ograniczyć blokady na transakcjach SQLite
const CHUNK_SIZE: usize = 500;

// ============================================================================
// STRUKTURY DANYCH
// ============================================================================

/// Pojedyncze zadanie do przetworzenia: rekord z bazy danych oczekujący na
/// hashowanie BLAKE3 i weryfikację Magic Bytes.
#[derive(Debug, Clone)]
pub(crate) struct Task {
    /// Klucz główny rekordu w tabeli `files` (SQLite `id`).
    id: i32,
    /// Ścieżka względna pliku liczona od katalogu bazowego danej strony (UFS/Skrypt).
    rel_path: String,
}

/// Wynik przetworzenia jednego zadania, przekazywany przez kanał MPSC do wątku
/// zapisującego do bazy danych.
#[derive(Debug, Clone)]
pub(crate) struct ScanResult {
    id: i32,
    /// Hash BLAKE3 w postaci hex. `None` gdy plik pusty/błąd/anulowanie.
    hash: Option<String>,
    /// Wynik weryfikacji Magic Bytes: `Some(true)` = zgodne, `Some(false)` = spoofing,
    /// `None` = nie dotyczy (plik bez rozszerzenia).
    magic_ok: Option<bool>,
    /// `Some(true)` gdy wystąpił błąd I/O przy otwieraniu/odczycie pliku.
    io_error: Option<bool>,
}

/// Wiadomość wysyłana przez wątki skanujące do wątku zapisu SQLite — oznaczona
/// stroną pochodzenia, żeby writer wiedział, którego zapytania UPDATE użyć.
pub(crate) enum ScanMsg {
    UfsChunk(Vec<ScanResult>),
    ScriptChunk(Vec<ScanResult>),
}

/// Liczniki live dla JEDNEJ strony (UFS albo Skrypt). W tej fazie dwie instancje
/// (`ufs_stats`, `script_stats`) są przekazywane do [`build_crypto_block`] i
/// [`build_anomaly_block`] RAZEM (jako `own`+`other`), żeby zbudować sumaryczny
/// widok obu stron naraz — Wariant B panelu bocznego.
pub(crate) struct LiveStats {
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    /// Błędy I/O przy otwieraniu pliku LUB przy właściwym hashowaniu (patrz `hash_file`).
    hash_errors: AtomicUsize,
    /// Pliki, których rozszerzenie nie zgadza się z prawdziwym nagłówkiem binarnym.
    magic_errors: AtomicUsize,
    valid_signatures: AtomicUsize, 
    
    /// Suma wag (bajtów) per rozszerzenie — do wyliczenia "Top format" w panelu bocznym.
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

    /// EKSPERYMENTALNE (Wariant A, patrz `thread_activity`): śledzi, który
    /// logiczny slot dedykowanej puli Rayon TEJ strony aktualnie liczy
    /// BLAKE3 — NIE fizyczny rdzeń CPU, patrz zastrzeżenie w dokumentacji
    /// modułu `thread_activity`. Rozmiar odpowiada `half_threads` tej strony.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    /// `slot_count` powinno odpowiadać rozmiarowi dedykowanej puli Rayon TEJ
    /// strony (`half_threads` w trybie CONCURRENT) — patrz pole `thread_activity`.
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

/// Flagi anomalii wykryte w pierwszym klastrze (pierwsze do 128 KB) pliku.
/// Zwracane przez [`analyze_header_cluster`] — każde pole odpowiada jednej
/// niezależnej heurystyce forensycznej, opisanej przy odpowiednim sprawdzeniu
/// w ciele tamtej funkcji.
struct HeaderAnomalies {
    /// Plik krótszy niż 32 bajty — za mało danych na jakąkolwiek sensowną analizę.
    is_micro: bool,
    /// Pierwsze 4 bajty to same zera — typowe dla wyzerowanego/nienadpisanego sektora.
    has_null: bool,
    /// Znana sygnatura (JPEG/ZIP/PDF/PNG) znaleziona, ale NIE na pozycji 0 —
    /// wskazuje na przesunięty offset przy odzysku (carver źle wyliczył początek pliku).
    has_offset: bool,
    /// Pierwsze 4 bajty wyglądają jak czytelny tekst ASCII, mimo że rozszerzenie
    /// sugeruje format binarny (jpg/zip/mp4/png) — podejrzenie nadpisania śmieciami.
    has_trash: bool,
    /// Kontener RIFF (WAV/AVI/WEBP) z nierozpoznanym czterobajtowym podtypem.
    sub_magic_err: bool,
    /// Nagłówek BMP (`BM`) z niezerowymi bajtami zarezerwowanymi (offset 6-9) —
    /// pole powinno być zawsze zerowe w poprawnym pliku.
    slack_contam: bool,
    /// Sygnatura ZIP lub EXE znaleziona GŁĘBIEJ w pliku (po bajcie 32) — podejrzenie
    /// osadzonego/pasożytniczego archiwum lub pliku wykonywalnego.
    parasitic: bool,
    /// TIFF z Little-Endian byte-order markerem (`II`) — flagowane do dalszej
    /// weryfikacji spójności endianness reszty struktury.
    endian_conflict: bool,
    /// Granica sektora 512 B (bajty 508-511) to same 0x00 albo same 0xFF —
    /// typowy ślad ucięcia na granicy bloku dyskowego.
    boundary_drop: bool,
    /// Suma bezwzględnych różnic sąsiednich bajtów przekracza próg — sygnał
    /// wysokiej entropii/szumu (możliwa kompresja, szyfrowanie lub uszkodzenie).
    high_volatility: bool,
}

// ============================================================================
// LOGIKA KRYMINALISTYCZNA (ULTIMATE HEADER FORENSICS)
// ============================================================================

/// Analizuje pierwszy fragment pliku (`buf`, typowo do 128 KB) pod kątem 10
/// niezależnych anomalii strukturalnych nagłówka. Każda heurystyka jest
/// odporna na brak pozostałych — funkcja nigdy nie panikuje na krótkim buforze,
/// tylko oznacza plik jako `is_micro` i kończy wcześnie.
///
/// `file_size` to pełny rozmiar pliku na dysku (może być większy niż `buf.len()`
/// — `buf` to tylko pierwszy odczytany fragment), używany wyłącznie do progu
/// mikro-pliku. `ext` to rozszerzenie z nazwy pliku (małe litery, bez kropki),
/// używane w heurystyce `has_trash`.
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

/// Buduje zbiorczy blok "[Kryptografia i sygnatury]" sumując liczniki z OBU stron
/// (własnej i przeciwnej), zgodnie z Wariantem B panelu bocznego. Dokłada też
/// linię zajętości wątków WYŁĄCZNIE strony `own` (Wariant A, eksperymentalne) —
/// TA strona faktycznie liczy w tym wywołaniu, `other`'s pula to zupełnie
/// inna, niezależna instancja Rayon z własną numeracją slotów, więc sumowanie
/// obu numeracji razem byłoby mylące (patrz zastrzeżenie w `thread_activity`).
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
        "[Kryptografia i sygnatury]\nPrędkość: {:.2} MB/s\nTop format: {}\nPoprawne sygnatury: {}\nBłędy I/O: {}\nSpoofing (magic): {}\nWątki BLAKE3 (Wariant A): {}",
        speed_mb, display_top, combined_valid, combined_io_err, combined_magic_err, activity_markup
    )
}

/// Buduje zbiorczy blok "[Anomalie pierwszego klastra]" sumując 9 kategorii
/// anomalii nagłówka z OBU stron, zgodnie z Wariantem B panelu bocznego.
fn build_anomaly_block(own: &LiveStats, other: &LiveStats) -> String {
    let sum = |a: &AtomicUsize, b: &AtomicUsize| a.load(Ordering::Relaxed) + b.load(Ordering::Relaxed);

    format!(
        "[Anomalie pierwszego klastra]\nPrzesunięty nagłówek: {}\nNull-padding: {}\nŚmieci ASCII: {}\nMikro-plik <32B: {}\nZła pod-sygnatura: {}\nSkażony slack space: {}\nIniekcja pasożytnicza: {}\nKonflikt endian: {}\nUrwana granica sektora: {}\nWysoka wolatywność: {}",
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

// ============================================================================
// GŁÓWNY SKANER RDZENIOWY (JEDNOPRZEBIEGOWE I/O)
// ============================================================================

/// Skanuje wszystkie zadania (`tasks`) dla JEDNEJ strony (UFS albo Skrypt):
/// dla każdego pliku czyta pierwszy fragment (analiza forensyczna nagłówka +
/// weryfikacja Magic Bytes), liczy właściwy hash BLAKE3 przez [`hash_file`],
/// aktualizuje liczniki [`LiveStats`] i strumieniuje wyniki do wątku zapisu
/// SQLite przez `tx_db`. Rozgłasza postęp i statystyki do UI co ~60ms
/// (nie częściej, żeby nie zalewać kanału MPSC Ratatui).
///
/// `stats` to liczniki WŁASNEJ strony, `other_stats` to liczniki DRUGIEJ
/// strony — obie przekazywane razem do [`build_crypto_block`]/[`build_anomaly_block`],
/// żeby panel boczny pokazywał sumę UFS+Skrypt (Wariant B), niezależnie od tego,
/// która strona akurat wywołała aktualizację.
///
/// Współbieżność: funkcja jest wołana wewnątrz `rayon::ThreadPoolBuilder`
/// (lub globalnej puli w trybie SEQUENTIAL) i dzieli `tasks` na porcje
/// [`CHUNK_SIZE`] przez `par_chunks` — każda porcja przetwarzana jest przez
/// osobny wątek Rayon, z lokalnym buforem logów (`log_buf`) i lokalną mapą
/// wag rozszerzeń, scalanymi na koniec porcji, żeby zminimalizować rywalizację
/// o `Mutex<HashMap<...>>` we współdzielonym `LiveStats`.
pub struct StreamCtx<'a> {
    pub base_path: &'a Path,
    pub tasks: &'a [Task],
    pub side_label: &'a str,
    pub stats: &'a LiveStats,
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

    // Używamy for_each_init w celu zachowania stanu per-wątek (stoper UI + bufor logów)
    tasks.par_chunks(CHUNK_SIZE).for_each_init(
        || (tx_db.clone(), Instant::now(), Vec::new()),
        |(tx, last_ui_update, log_buf), chunk| {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

            let mut results = Vec::with_capacity(chunk.len());
            let mut local_ext_weights: HashMap<String, u64> = HashMap::new();

            for task in chunk {
                if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

                let full_path: PathBuf = base_path.join(&task.rel_path);

                let mut file = match File::open(&full_path) {
                    Ok(f) => f,
                    Err(_) => {
                        stats.hash_errors.fetch_add(1, Ordering::Relaxed);
                        // Logujemy do lokalnego wektora zamiast blokować Mutexa
                        log_buf.push(format!("[{}] Błąd I/O (Brak dostępu): \"{}\"", side_label, task.rel_path));
                        results.push(ScanResult { id: task.id, hash: None, magic_ok: None, io_error: Some(true) });
                        continue;
                    }
                };

                let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
                let mut buffer = [0u8; 131_072];

                // Odczyt pierwszego fragmentu WYŁĄCZNIE do analizy forensycznej nagłówka
                // (Magic Bytes, anomalie klastra). Właściwy hash liczy niżej hash_file().
                //
                // UWAGA KRYMINALISTYCZNA (nie zamieniać z powrotem na `.unwrap_or(0)`):
                // musimy rozróżnić FAKTYCZNY błąd odczytu od zwykłego EOF na pustym
                // pliku. `Ok(0)` z `Read::read()` przy świeżo otwartym pliku znaczy
                // "plik ma 0 bajtów" - to jest poprawny, oczekiwany wynik. `Err(_)`
                // znaczy realny błąd I/O (bad sector, odłączony nośnik, zniknięcie
                // pliku) i NIE WOLNO go cicho zamieniać na "pusty plik" przez
                // `unwrap_or(0)`, bo inaczej trafia w tę samą gałąź co wydmuszka 0 B.
                let read_result = file.read(&mut buffer);
                drop(file); // hash_file() otworzy plik ponownie samodzielnie (mmap/bufread)

                let first_read = match read_result {
                    Ok(n) => n,
                    Err(_) => {
                        stats.hash_errors.fetch_add(1, Ordering::Relaxed);
                        log_buf.push(format!("[{}] Błąd I/O (odczyt nagłówka): \"{}\"", side_label, task.rel_path));
                        results.push(ScanResult { id: task.id, hash: None, magic_ok: None, io_error: Some(true) });
                        continue;
                    }
                };

                if first_read == 0 {
                    // Pusty plik: hash_file() poprawnie policzy hash pustego ciągu (BLAKE3 pustki).
                    //
                    // UWAGA KRYMINALISTYCZNA: jeśli hash_file() MIMO WSZYSTKO zawiedzie
                    // (np. plik zniknął albo zmieniły się uprawnienia w okienku czasowym
                    // między `File::open()` wyżej a tym wywołaniem), to jest to FAKTYCZNY
                    // błąd I/O, a NIE pusty plik. `hash=None` razem z na sztywno wpisanym
                    // `io_error=Some(false)` dawało kombinację, która nigdy nie spełnia
                    // warunku `phase3_done` (`hash_ufs IS NOT NULL OR io_error_ufs = 1`) -
                    // plik wracał do kolejki i był przetwarzany od nowa w nieskończoność.
                    match stats.thread_activity.track_current(|| hash_file(&full_path)) {
                        Ok(h) => {
                            results.push(ScanResult {
                                id: task.id,
                                hash: Some(h),
                                magic_ok: Some(true), io_error: Some(false)
                            });
                        }
                        Err(_) => {
                            stats.hash_errors.fetch_add(1, Ordering::Relaxed);
                            log_buf.push(format!("[{}] Błąd I/O (hashowanie pustego pliku nie powiodło się): \"{}\"", side_label, task.rel_path));
                            results.push(ScanResult { id: task.id, hash: None, magic_ok: None, io_error: Some(true) });
                        }
                    }
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

                // --- WŁAŚCIWE HASHOWANIE: przez zoptymalizowaną funkcję z utils.rs ---
                // Dla plików >16MB automatycznie użyje mmap (Zero-Copy). Sama funkcja
                // sprawdza CANCEL_SIGNAL cyklicznie w środku i zwraca ErrorKind::Interrupted
                // przy anulowaniu, więc rozróżniamy to od prawdziwego błędu dysku.
                //
                // Owinięte w track_current (Wariant A, eksperymentalne): oznacza bieżący
                // slot dedykowanej puli Rayon tej strony jako zajęty na czas samego
                // hashowania — patrz dokumentacja modułu `thread_activity` co do znaczenia
                // (slot logiczny, NIE fizyczny rdzeń CPU).
                // REGRESJA (Gemini review — druga weryfikacja): ten sam wzorzec błędu co
                // przy sondzie nagłówka (patrz komentarz "UWAGA KRYMINALISTYCZNA" wyżej w
                // pliku) istniał TAKŻE tutaj, w głównej, częściej wykonywanej ścieżce
                // hashowania — `io_error` było zapisywane na sztywno jako `Some(false)`
                // (linia 544) niezależnie od tego, czy `hash_file()` faktycznie zawiodło
                // prawdziwym błędem I/O. Kombinacja `hash=None, io_error=Some(false)` nigdy
                // nie spełnia warunku `phase3_done` (`hash_ufs IS NOT NULL OR io_error_ufs = 1`),
                // więc plik z bad sectorem trafionym w środku (nagłówek 128KB odczytał się
                // poprawnie, dalsza część pliku już nie) wpadał w tę samą nieskończoną
                // pętlę ponawiania.
                let (file_hash, hash_io_error) = match stats.thread_activity.track_current(|| hash_file(&full_path)) {
                    Ok(h) => (Some(h), false),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        // Anulowanie przez użytkownika (Ctrl+C) — NIE liczymy jako błąd dysku
                        (None, false)
                    }
                    Err(_) => {
                        stats.hash_errors.fetch_add(1, Ordering::Relaxed);
                        log_buf.push(format!("[{}] Błąd I/O podczas właściwego hashowania: \"{}\"", side_label, task.rel_path));
                        (None, true)
                    }
                };

                if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

                stats.processed_files.fetch_add(1, Ordering::Relaxed);
                stats.processed_bytes.fetch_add(file_size, Ordering::Relaxed);

                let current = stats.processed_files.load(Ordering::Relaxed);
                let now = Instant::now();
                
                // Stabilne odświeżanie UI - stoper nie resetuje się na każdym 500-elementowym chunku
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

                    // REGRESJA (menu/dashboard — naprawa dolnego panelu ścieżek):
                    // brakowało tu tej wysyłki, mimo że blok odświeżania UI już
                    // istniał — dolny panel "Aktualnie skanowane ścieżki" (patrz
                    // `tui::scanner_panel::draw_bottom_paths_panel`) zostawał na
                    // "(Oczekiwanie na dane...)" przez CAŁĄ Fazę 3, w przeciwieństwie
                    // do 14 pozostałych faz. Ten sam wzorzec co `phase4.rs`/
                    // `phase5.rs`/`phase6.rs`/`phase7.rs`.
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
                    io_error: Some(hash_io_error)
                });
            }

            // --- Zrzuty zbiorcze na koniec pętli nad paczką ---

            if !local_ext_weights.is_empty() {
                let mut global_map = stats.ext_weights.lock().unwrap();
                for (k, v) in local_ext_weights.drain() {
                    *global_map.entry(k).or_insert(0) += v;
                }
            }

            // Hurtowy zapis logów do pliku tekstowego na dysku
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
        message: "Odczyt i hashowanie zakończone.".to_string(),
    });
}

// ============================================================================
// GŁÓWNA FUNKCJA KORDYNUJĄCA (Entrypoint Fazy 3)
// ============================================================================

/// Wylicza rozmiar prywatnej puli Rayon przypisywanej JEDNEJ stronie (UFS albo
/// Skrypt) w trybie `io_mode = "CONCURRENT"`, kiedy obie strony skanują
/// jednocześnie na dwóch osobnych, tymczasowych pulach wątków.
///
/// Dzieli budżet CPU na pół i zaokrągla w dół, ale nigdy nie zwraca zera —
/// nawet przy `total_threads = 1` obie strony dostają co najmniej 1 wątek
/// (łącznie 2 wątki systemowe, po jednym na fizycznie inny dysk — patrz
/// dokumentacja modułu). Przy nieparzystym `total_threads` reszta z dzielenia
/// jest tracona (np. 5 → 2+2, nie 2+3) — celowe uproszczenie, bo rozbieżność
/// o jeden wątek między stronami nie ma praktycznego znaczenia wydajnościowego.
fn compute_half_threads(total_threads: usize) -> usize {
    std::cmp::max(1, total_threads / 2)
}

/// Wylicza liczbę slotów trackera zajętości (Wariant A, `thread_activity`)
/// odpowiednią dla trybu I/O:
/// - **CONCURRENT**: każda strona dostaje WŁASNĄ, dedykowaną pulę Rayon o
///   rozmiarze `half_threads` (patrz `pool.install()` w [`run`]) — więc
///   tyle właśnie slotów ma sens śledzić.
/// - **SEQUENTIAL**: `process_side_stream` woła się BEZPOŚREDNIO, bez
///   dedykowanej puli — korzysta z CAŁEJ globalnej puli Rayon
///   (`actual_threads`), bo obie strony i tak nie pracują jednocześnie.
///
/// NAPRAWIONY BUG: użycie `half_threads` niezależnie od trybu zaniżało
/// rozmiar trackera w SEQUENTIAL i po cichu gubiło śledzenie wątków
/// o indeksie >= `half_threads` (`mark_busy`/`is_busy` z indeksem poza
/// zakresem to celowy, cichy no-op w `thread_activity` — bezpieczny, ale
/// tu maskujący błąd sizingu). Obserwowane na Raspberry Pi 5: 4 aktywne
/// wątki Rayon w trybie SEQUENTIAL, panel pokazywał tylko 2 sloty.
fn compute_activity_slots(io_mode: &str, actual_threads: usize, half_threads: usize) -> usize {
    if io_mode == "CONCURRENT" { half_threads } else { actual_threads }
}

/// Punkt wejścia Fazy 3, wołany przez `menu::actions::run_phase_with_ui`.
///
/// Przebieg: (1) wczytuje z SQLite zadania — pliki o zgodnym rozmiarze
/// (`size_match = 1`), którym brakuje jeszcze hasha po tej stronie i które
/// nie mają zapisanego błędu I/O; (2) uruchamia [`process_side_stream`] dla
/// UFS i Skryptu (równolegle lub sekwencyjnie, patrz dokumentacja modułu);
/// (3) po zakończeniu skanowania koreluje wyniki w SQLite (`hash_match`,
/// `phase3_done`); (4) generuje i zapisuje Dziennik Końcowy (statystyki
/// zgodności, spoofing, zaufanie carvera) do pliku oraz do logu Ratatui.
///
/// Idempotentna na poziomie pliku: pliki z już wyliczonym hashem lub
/// oznaczone błędem I/O są pomijane przy kolejnym uruchomieniu (`phase3_done`).
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    crate::utils::CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    // 1. INICJALIZACJA DUAL-LOGGING (Pobieranie ścieżek z Ustawień)
    let raport_cfg = config.raporty_faz.get("Faza 3").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza3.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza3.txt".to_string(),
    });
    
    std::fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);
    
    let opr_log = Arc::new(Mutex::new(File::create(&opr_path).unwrap()));
    {
        let mut f = opr_log.lock().unwrap();
        let _ = writeln!(f, "=== RAPORT OPERACYJNY - FAZA 3 (FAŁSZYWE ROZSZERZENIA I ANOMALIE KLASTRA) ===");
        let _ = writeln!(f, "Zestawienie plików, których zawartość binarna nie zgadza się z rozszerzeniem (wykrywane na żywo):\n");
    }

    let actual_threads = if config.max_threads > 0 { config.max_threads } else { rayon::current_num_threads() };
    let io_text = if config.io_mode == "CONCURRENT" { "RÓWNOLEGŁE (SSD/NVMe)" } else { "SEKWENCYJNIE (HDD)" };
    
    let _ = tx_ui.send(PhaseEvent::Log(format!("Uruchomiono Fazę 3. Metodyka szyny dyskowej: {}", io_text)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora (Rayon): {}", actual_threads)));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    // --- ETAP 1: POBIERANIE ZADAŃ Z BAZY ---
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, hash_ufs, hash_script, io_error_ufs, io_error_script 
         FROM files WHERE size_match = 1 AND phase3_done = 0"
    )?;
    
    let mut ufs_tasks: Vec<Task> = Vec::new();
    let mut script_tasks: Vec<Task> = Vec::new();
    
    let mut skipped_ufs = 0;
    let mut skipped_script = 0;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i32>(0)?, row.get::<_, String>(1)?, 
            row.get::<_, Option<String>>(2)?, row.get::<_, Option<String>>(3)?, 
            row.get::<_, Option<bool>>(4)?, row.get::<_, Option<bool>>(5)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, h_ufs, h_scr, err_ufs, err_scr) = r;
        
        if h_ufs.is_none() && err_ufs != Some(true) { ufs_tasks.push(Task { id, rel_path: rel.clone() }); } 
        else { skipped_ufs += 1; }
        
        if h_scr.is_none() && err_scr != Some(true) { script_tasks.push(Task { id, rel_path: rel }); } 
        else { skipped_script += 1; }
    }
    drop(stmt);

    if skipped_ufs > 0 || skipped_script > 0 {
        let _ = tx_ui.send(PhaseEvent::Log(format!("Pominięto pliki z wyliczonym już hashem. UFS: {}, Skrypt: {}", skipped_ufs, skipped_script)));
    }

    let total_files = ufs_tasks.len() + script_tasks.len();
    if total_files == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak plików o tym samym rozmiarze do weryfikacji. Baza aktualna.".to_string()));
        return Ok(());
    }

    // Inicjalizacja pasków postępu Ratatui
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "UFS Explorer (BLAKE3)".to_string(), total: ufs_tasks.len() as u64, color: Color::Cyan });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 1, label: "Skrypt Autorski (BLAKE3)".to_string(), total: script_tasks.len() as u64, color: Color::Magenta });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 2, label: "Zapis SQLite".to_string(), total: total_files as u64, color: Color::Green });

    // Wyliczone TERAZ (nie tylko w gałęzi CONCURRENT niżej), bo LiveStats
    // potrzebuje tej wartości do rozmiaru trackera zajętości (Wariant A,
    // patrz dokumentacja pola `thread_activity`) niezależnie od trybu I/O.
    let half_threads = compute_half_threads(actual_threads);

    // NAPRAWIONY BUG: rozmiar trackera MUSI zależeć od trybu I/O — patrz
    // dokumentacja compute_activity_slots() wyżej.
    let activity_slots = compute_activity_slots(&config.io_mode, actual_threads, half_threads);

    let ufs_stats = LiveStats::new(activity_slots);
    let script_stats = LiveStats::new(activity_slots);
    let ufs_path = PathBuf::from(&config.ufs_path);
    let script_path = PathBuf::from(&config.script_path);

    // --- ETAP 3: PRZETWARZANIE STRUMIENIOWE (MPSC) ---
    // REGRESJA (measure twice — druga weryfikacja Gemini): każdy błąd SQLite
    // w wątku bazy był wcześniej `.unwrap()`, czyli paniką w wątku pisarza
    // wewnątrz `thread::scope` — jeden transjentny błąd I/O bazy ubijałby
    // całą fazę bez żadnego komunikatu. Ten sam wzorzec co
    // `phase17_repair::run`/`phase1::run` — `db_thread` zwraca `Result<()>`,
    // panika jest przechwytywana przez `.join()` i zamieniana na błąd domenowy.
    let wynik_zapisu: Result<()> = std::thread::scope(|s| {
        let (tx_db, rx_db) = mpsc::sync_channel(200);
        let conn_ref = &mut *conn;
        let tx_ui_ref = &tx_ui;

        // Wątek Bazy Danych z zapisem transakcyjnym (Hybrydowym) dostosowanym pod ciężkie operacje (5000 / 500ms)
        let db_thread = s.spawn(move || -> Result<()> {
            let mut last_ui_update = Instant::now();
            let mut last_commit = Instant::now();
            let mut db_inserted = 0;
            let mut pending_records = 0;

            let mut tx_trans = conn_ref.transaction()?;

            loop {
                let msg_result = rx_db.recv_timeout(Duration::from_millis(100));
                
                // 1. ZAPAMIĘTUJEMY FLAGĘ
                let is_disconnected = matches!(&msg_result, Err(std::sync::mpsc::RecvTimeoutError::Disconnected));

                // 2. KONSUMUJEMY WYNIK
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

                // LOGIKA HYBRYDOWA: Commit co 5 000 rekordów LUB co 500 ms (jeśli mamy cokolwiek do zapisu)
                if pending_records > 0 && (pending_records >= 5_000 || now.duration_since(last_commit).as_millis() > 500) {
                    tx_trans.commit()?;
                    tx_trans = conn_ref.transaction()?;
                    last_commit = now;
                    pending_records = 0;
                }

                // Płynne odświeżanie paska bazy danych
                if now.duration_since(last_ui_update).as_millis() > 60 {
                    last_ui_update = now;
                    let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { 
                        idx: 2, 
                        current: db_inserted as u64, 
                        message: format!("Synchronizacja: {} rekordów", db_inserted) 
                    });
                }

                // 3. ZAMKNIĘCIE WĄTKU NA BAZIE ZAPAMIĘTANEJ FLAGI
                if is_disconnected {
                    break;
                }
            }

            if pending_records > 0 {
                tx_trans.commit()?;
            }

            let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Hashe bezpiecznie zapisane w SQLite.".to_string() });
            Ok(())
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone();
            let tx2 = tx_db.clone();
            let log_u = opr_log.clone();
            let log_s = opr_log.clone();

            let stat_u = &ufs_stats;
            let stat_s = &script_stats;

            // DZIELIMY PROCESOR NA PÓŁ (wymuszenie pracy równoległej poza globalną pulą).
            // Patrz dokumentacja compute_half_threads() niżej — gwarantuje min. 1 wątek
            // na stronę nawet przy actual_threads = 1, oraz sumaryczny budżet obu stron
            // nieprzekraczający actual_threads. Wyliczone wcześniej (przed konstrukcją
            // LiveStats), tu tylko używane.

            s.spawn(move || {
                if !ufs_tasks.is_empty() {
                    // Tworzymy prywatną pulę wątków TYLKO dla UFS
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &ufs_path, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, other_stats: stat_s, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: log_u, start_time, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &ufs_path, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, other_stats: stat_s, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: log_u, start_time, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Hashowanie dysku UFS zakończone.".to_string()));
                }
            });

            s.spawn(move || {
                if !script_tasks.is_empty() {
                    // Tworzymy prywatną pulę wątków TYLKO dla Skryptu
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &script_path, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, other_stats: stat_u, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: log_s, start_time, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &script_path, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, other_stats: stat_u, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: log_s, start_time, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Hashowanie dysku Skryptu zakończone.".to_string()));
                }
            });
            drop(tx_db);

        } else {
            let log_u = opr_log.clone();
            let log_s = opr_log.clone();
            
            if !ufs_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &ufs_path, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: &ufs_stats, other_stats: &script_stats, tx_db: tx_db.clone(), is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: log_u, start_time, });
                let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Hashowanie dysku UFS zakończone.".to_string()));
            }
            
            if !script_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &script_path, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: &script_stats, other_stats: &ufs_stats, tx_db: tx_db.clone(), is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: log_s, start_time, });
                let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Hashowanie dysku Skryptu zakończone.".to_string()));
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
                    "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 3 mógł nie zostać w pełni zapisany.".to_string()
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

    let _ = tx_ui.send(PhaseEvent::Log("Trwa korelacja danych i budowa macierzy w SQLite...".to_string()));
    
    conn.execute(
        "UPDATE files SET 
            hash_match = CASE 
                WHEN io_error_ufs = 1 OR io_error_script = 1 THEN NULL
                WHEN hash_ufs IS NULL OR hash_script IS NULL THEN NULL 
                WHEN hash_ufs = hash_script THEN 1 
                ELSE 0 
            END, 
            phase3_done = CASE 
                WHEN (hash_ufs IS NOT NULL OR io_error_ufs = 1) AND (hash_script IS NOT NULL OR io_error_script = 1) THEN 1 
                ELSE 0 
            END
         WHERE size_match = 1 AND phase3_done = 0", []
    )?;

    // --- ETAP 5: GENEROWANIE KOMPLEKSOWEGO RAPORTU KRYMINALISTYCZNEGO ---
    let mut spoofing_matrix_ufs: HashMap<String, usize> = HashMap::new();
    let mut spoofing_matrix_script: HashMap<String, usize> = HashMap::new();
    let mut match_count = 0;
    let mut mismatch_count = 0;

    let mut stmt = conn.prepare("SELECT relative_path, hash_match, magic_ok_ufs, magic_ok_script FROM files WHERE size_match = 1 AND phase3_done = 1 AND found_in_ufs = 1 AND found_in_script = 1")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<bool>>(1)?, row.get::<_, Option<bool>>(2)?, row.get::<_, Option<bool>>(3)?))
    })?;

    for (rel_path, hash_match, magic_ufs, magic_script) in rows.flatten() {
        if hash_match == Some(true) { match_count += 1; } 
        else if hash_match == Some(false) { mismatch_count += 1; }
        
        let ext = Path::new(&rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();
        if magic_ufs == Some(false) { *spoofing_matrix_ufs.entry(ext.clone()).or_insert(0) += 1; }
        if magic_script == Some(false) { *spoofing_matrix_script.entry(ext).or_insert(0) += 1; }
    }
    drop(stmt);

    let elapsed = start_time.elapsed();
    let total_bytes = ufs_stats.processed_bytes.load(Ordering::SeqCst) + script_stats.processed_bytes.load(Ordering::SeqCst);
    let avg_speed_mb = (total_bytes as f64 / 1_048_576.0) / elapsed.as_secs_f64().max(1.0);
    
    let ufs_anom = ufs_stats.offset_anomalies.load(Ordering::SeqCst) + ufs_stats.null_padding.load(Ordering::SeqCst) + ufs_stats.ascii_trash.load(Ordering::SeqCst) + ufs_stats.sub_magic_errors.load(Ordering::SeqCst) + ufs_stats.slack_space_contam.load(Ordering::SeqCst) + ufs_stats.parasitic_injections.load(Ordering::SeqCst) + ufs_stats.endian_conflicts.load(Ordering::SeqCst) + ufs_stats.boundary_drops.load(Ordering::SeqCst) + ufs_stats.high_volatility.load(Ordering::SeqCst);
    let scr_anom = script_stats.offset_anomalies.load(Ordering::SeqCst) + script_stats.null_padding.load(Ordering::SeqCst) + script_stats.ascii_trash.load(Ordering::SeqCst) + script_stats.sub_magic_errors.load(Ordering::SeqCst) + script_stats.slack_space_contam.load(Ordering::SeqCst) + script_stats.parasitic_injections.load(Ordering::SeqCst) + script_stats.endian_conflicts.load(Ordering::SeqCst) + script_stats.boundary_drops.load(Ordering::SeqCst) + script_stats.high_volatility.load(Ordering::SeqCst);
    
    let all_anomalies = ufs_anom + scr_anom;
    let tot_micro = ufs_stats.micro_files.load(Ordering::SeqCst) + script_stats.micro_files.load(Ordering::SeqCst);
    
    let confidence_score = if total_files > 0 { 
        let clean = total_files.saturating_sub(all_anomalies + spoofing_matrix_ufs.values().sum::<usize>() + spoofing_matrix_script.values().sum::<usize>());
        (clean as f64 / total_files as f64) * 100.0 
    } else { 0.0 };

    let total_io_errors = ufs_stats.hash_errors.load(Ordering::SeqCst) + script_stats.hash_errors.load(Ordering::SeqCst);
    let total_magic_errors = ufs_stats.magic_errors.load(Ordering::SeqCst) + script_stats.magic_errors.load(Ordering::SeqCst);

    // -- GENEROWANIE RAPORTU TEKSTOWEGO --
    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(&mut log_out, "==========================================================================");
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 3 (KRYPTOGRAFIA BLAKE3 I ANOMALIE NAGŁÓWKÓW)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "Sumaryczny transfer I/O: {} (Średnia prędkość: {:.2} MB/s)", format_bytes(total_bytes), avg_speed_mb);
    let _ = writeln!(&mut log_out, "==========================================================================\n");

    let _ = writeln!(&mut log_out, "[ 1 ] WYNIKI HASHOWANIA (Weryfikacja Bit-to-Bit):");
    let _ = writeln!(&mut log_out, "   -> Zgodne hashe (BLAKE3): {} plików", match_count);
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Pliki o tym samym rozmiarze posiadają w 100% identyczną zawartość binarną na obu dyskach.");
    let _ = writeln!(&mut log_out, "   -> Różne hashe (Kolizje): {} plików", mismatch_count);
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Pliki ważą tyle samo, ale różnią się wewnątrz. Oznacza to korupcję (nadpisanie innymi danymi) podczas odzyskiwania na jednym z dysków.\n");

    let _ = writeln!(&mut log_out, "[ 2 ] WERYFIKACJA MAGIC BYTES (Deep Signature):");
    let _ = writeln!(&mut log_out, "   -> Potwierdzone sygnatury w UFS:    {}", ufs_stats.valid_signatures.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "   -> Potwierdzone sygnatury w Skrypt: {}", script_stats.valid_signatures.load(Ordering::SeqCst));
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Format zadeklarowany w nazwie pliku (np. .jpg) zgadza się z prawdziwym, wbudowanym nagłówkiem binarnym pliku.\n");

    if all_anomalies > 0 || tot_micro > 0 {
        let _ = writeln!(&mut log_out, "[ 3 ] ROZKŁAD ANOMALII PIERWSZEGO KLASTRA (Uszkodzenia strukturalne):");
        let _ = writeln!(&mut log_out, "   Wykryto łącznie: {} anomalii (oraz {} mikro-plików)", all_anomalies, tot_micro);
        let _ = writeln!(&mut log_out, "   [ ZNACZENIE ]: Błędy pierwszych 512 bajtów pliku wskazują, że program odzyskujący (Carver) źle wyliczył początek pliku, lub plik został nadpisany wirusem / śmieciami z innej partycji.\n");
        let _ = writeln!(&mut log_out, "   -> Przesunięte nagłówki: {}", ufs_stats.offset_anomalies.load(Ordering::SeqCst) + script_stats.offset_anomalies.load(Ordering::SeqCst));
        let _ = writeln!(&mut log_out, "   -> Puste bloki (Null-Padding): {}", ufs_stats.null_padding.load(Ordering::SeqCst) + script_stats.null_padding.load(Ordering::SeqCst));
        let _ = writeln!(&mut log_out, "   -> Zanieczyszczenie pamięci (ASCII Trash): {}", ufs_stats.ascii_trash.load(Ordering::SeqCst) + script_stats.ascii_trash.load(Ordering::SeqCst));
        let _ = writeln!(&mut log_out, "   -> Skażenie Slack Space: {}", ufs_stats.slack_space_contam.load(Ordering::SeqCst) + script_stats.slack_space_contam.load(Ordering::SeqCst));
        let _ = writeln!(&mut log_out);
    }

    if !spoofing_matrix_ufs.is_empty() || !spoofing_matrix_script.is_empty() {
        let _ = writeln!(&mut log_out, "[ 4 ] MACIERZ FAŁSZERSTW ROZSZERZEŃ (Spoofing):");
        let _ = writeln!(&mut log_out, "   Fałszywe odzyski wygenerowane przez UFS Explorer: {}", spoofing_matrix_ufs.values().sum::<usize>());
        let _ = writeln!(&mut log_out, "   Fałszywe odzyski wygenerowane przez Skrypt Aut.:  {}\n", spoofing_matrix_script.values().sum::<usize>());
    }

    let _ = writeln!(&mut log_out, "[ 5 ] ZAUFANIE DO ALGORYTMÓW (Carver Confidence Score):");
    let _ = writeln!(&mut log_out, "   -> Zaufanie: {:.2}%", confidence_score);
    let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Ilość plików w skali całego odzysku, które posiadają w 100% zdrowy i logiczny pierwszy klaster danych.\n");

    if total_io_errors > 0 || total_magic_errors > 0 {
        let _ = writeln!(&mut log_out, "[ 6 ] PODSUMOWANIE BŁĘDÓW KRYTYCZNYCH:");
        let _ = writeln!(&mut log_out, "   -> Błędy I/O (Brak dostępu / Bad Sectory): {}", total_io_errors);
        let _ = writeln!(&mut log_out, "   -> Błędy Sygnatur (Niezgodność rozszerzeń): {}", total_magic_errors);
    }

    // Zapis do fizycznego pliku "Dziennik Końcowy" na podstawie konfiguracji Dual-Logging
    if let Ok(mut f) = std::fs::File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano fizyczny Dziennik Końcowy w: {}", dz_path.display())));
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano Raport Operacyjny (Live) w: {}", opr_path.display())));
    }

    // Wysyłamy raport również do Ratatui Log Panel
    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    // Zrzut telemetrii do głównego pliku logów w tle
    info!(
        total_files,
        match_count,
        mismatch_count,
        total_io_errors,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 3 zakończona pomyślnie"
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
    // compute_half_threads
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_half_threads_even() {
        assert_eq!(compute_half_threads(8), 4);
        assert_eq!(compute_half_threads(4), 2);
    }

    #[test]
    fn test_compute_half_threads_odd_rounds_down() {
        // Nieparzysta liczba wątków: reszta z dzielenia jest tracona (celowo, patrz docstring)
        assert_eq!(compute_half_threads(5), 2);
        assert_eq!(compute_half_threads(3), 1);
    }

    #[test]
    fn test_compute_half_threads_never_returns_zero() {
        // Krytyczne: nawet przy 1 wątku globalnym, każda strona musi dostać min. 1
        assert_eq!(compute_half_threads(1), 1);
        assert_eq!(compute_half_threads(0), 1);
    }

    // ------------------------------------------------------------------
    // compute_activity_slots
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_activity_slots_concurrent_uses_half_threads() {
        assert_eq!(compute_activity_slots("CONCURRENT", 4, 2), 2);
    }

    #[test]
    fn test_compute_activity_slots_sequential_uses_full_actual_threads() {
        assert_eq!(compute_activity_slots("SEQUENTIAL", 4, 2), 4);
    }

    #[test]
    fn test_compute_activity_slots_raspberry_pi_5_regression() {
        // Dokładny scenariusz z raportu: Raspberry Pi 5 (4 rdzenie, AUTO ->
        // actual_threads=4), tryb SEKWENCYJNY. Przed naprawą tracker był
        // sizingowany na half_threads=2, gubiąc śledzenie 2 z 4 realnie
        // aktywnych wątków globalnej puli Rayon.
        let actual_threads = 4;
        let half_threads = compute_half_threads(actual_threads);
        assert_eq!(compute_activity_slots("SEQUENTIAL", actual_threads, half_threads), 4);
    }

    // ------------------------------------------------------------------
    // analyze_header_cluster
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_header_micro_file_below_32_bytes() {
        let buf = vec![0xAB; 10];
        let a = analyze_header_cluster(&buf, 10, "jpg");
        assert!(a.is_micro);
        // Wczesny return - żadna inna anomalia nie powinna być sprawdzana/ustawiona
        assert!(!a.has_null);
        assert!(!a.has_offset);
    }

    #[test]
    fn test_analyze_header_micro_file_short_buffer_but_large_file_size() {
        // file_size duży, ale przekazany bufor (first_read) krótszy niż 32B
        // (np. urwany odczyt) - też powinno się zaflagować jako micro
        let buf = vec![0x00; 16];
        let a = analyze_header_cluster(&buf, 5_000_000, "mp4");
        assert!(a.is_micro);
    }

    #[test]
    fn test_analyze_header_null_padding_detected() {
        let mut buf = vec![0x00; 64];
        buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00;
        let a = analyze_header_cluster(&buf, 64, "dat");
        assert!(a.has_null);
    }

    #[test]
    fn test_analyze_header_offset_jpeg_detected() {
        // Sygnatura JPEG (FF D8 FF E0) przesunięta o 8 bajtów śmieci na start
        let mut buf = vec![0x41; 64]; // 'A' jako wypełniacz
        buf[8] = 0xFF; buf[9] = 0xD8; buf[10] = 0xFF; buf[11] = 0xE0;
        let a = analyze_header_cluster(&buf, 64, "jpg");
        assert!(a.has_offset, "Sygnatura JPEG na pozycji > 0 powinna być wykryta jako przesunięty nagłówek");
    }

    #[test]
    fn test_analyze_header_offset_not_flagged_when_at_position_zero() {
        // Ta sama sygnatura, ale na pozycji 0 - to jest POPRAWNY plik, nie anomalia
        let mut buf = vec![0x00; 64];
        buf[0] = 0xFF; buf[1] = 0xD8; buf[2] = 0xFF; buf[3] = 0xE0;
        let a = analyze_header_cluster(&buf, 64, "jpg");
        assert!(!a.has_offset, "Sygnatura na pozycji 0 to prawidłowy nagłówek, nie przesunięcie");
    }

    #[test]
    fn test_analyze_header_ascii_trash_for_binary_extension() {
        // Same czytelne znaki ASCII, ale rozszerzenie sugeruje format binarny
        let mut buf = vec![0x00; 64];
        buf[0..4].copy_from_slice(b"HELO");
        let a = analyze_header_cluster(&buf, 64, "zip");
        assert!(a.has_trash);
    }

    #[test]
    fn test_analyze_header_ascii_not_flagged_for_text_extension() {
        // To samo, ale rozszerzenie NIE jest na liście binarnych (jpg/zip/mp4/png) - brak flagi
        let mut buf = vec![0x00; 64];
        buf[0..4].copy_from_slice(b"HELO");
        let a = analyze_header_cluster(&buf, 64, "txt");
        assert!(!a.has_trash);
    }

    #[test]
    fn test_analyze_header_riff_sub_magic_error() {
        // RIFF ale z nierozpoznanym podtypem (nie AVI /WEBP/WAVE)
        let mut buf = vec![0x00; 64];
        buf[0..4].copy_from_slice(b"RIFF");
        buf[8..12].copy_from_slice(b"XXXX");
        let a = analyze_header_cluster(&buf, 64, "wav");
        assert!(a.sub_magic_err);
    }

    #[test]
    fn test_analyze_header_riff_valid_subtype_not_flagged() {
        let mut buf = vec![0x00; 64];
        buf[0..4].copy_from_slice(b"RIFF");
        buf[8..12].copy_from_slice(b"WAVE");
        let a = analyze_header_cluster(&buf, 64, "wav");
        assert!(!a.sub_magic_err);
    }

    #[test]
    fn test_analyze_header_bmp_slack_contamination() {
        // Nagłówek BMP ('BM') z niezerowym bajtem zarezerwowanym (offset 6)
        let mut buf = vec![0x00; 64];
        buf[0] = b'B'; buf[1] = b'M';
        buf[6] = 0xFF; // powinno być 0x00 w poprawnym pliku
        let a = analyze_header_cluster(&buf, 64, "bmp");
        assert!(a.slack_contam);
    }

    #[test]
    fn test_analyze_header_parasitic_zip_injection() {
        // Sygnatura ZIP osadzona głęboko w pliku (po bajcie 32) - podejrzenie iniekcji
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
    fn test_analyze_header_boundary_drop_ff() {
        let mut buf = vec![0x41; 512];
        buf[508] = 0xFF; buf[509] = 0xFF; buf[510] = 0xFF; buf[511] = 0xFF;
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
        // Poprawny JPEG na pozycji 0, gładki gradient bajtów (niska wolatywność),
        // rozmiar >512B żeby ominąć próg boundary_drop w sposób neutralny
        let mut buf = vec![0u8; 600];
        buf[0] = 0xFF; buf[1] = 0xD8; buf[2] = 0xFF; buf[3] = 0xE0;
        buf[4..].fill(0x80); // stała wartość = zero wolatywności
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
    // build_crypto_block / build_anomaly_block
    // ------------------------------------------------------------------

    #[test]
    fn test_build_crypto_block_sums_both_sides() {
        let own = LiveStats::new(4);
        let other = LiveStats::new(4);

        own.processed_bytes.store(1_048_576, Ordering::Relaxed); // 1 MB
        other.processed_bytes.store(1_048_576, Ordering::Relaxed); // + 1 MB = 2 MB razem
        own.valid_signatures.store(10, Ordering::Relaxed);
        other.valid_signatures.store(5, Ordering::Relaxed);
        own.hash_errors.store(1, Ordering::Relaxed);
        other.hash_errors.store(2, Ordering::Relaxed);
        own.magic_errors.store(3, Ordering::Relaxed);
        other.magic_errors.store(0, Ordering::Relaxed);

        // start_time na tyle w przeszłości, żeby elapsed > 0, ale bez zależności czasowej testu
        let start_time = Instant::now() - Duration::from_secs(1);
        let block = build_crypto_block(&own, &other, start_time);

        assert!(block.starts_with("[Kryptografia i sygnatury]"));
        assert!(block.contains("Poprawne sygnatury: 15")); // 10 + 5
        assert!(block.contains("Błędy I/O: 3"));            // 1 + 2
        assert!(block.contains("Spoofing (magic): 3"));     // 3 + 0
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
        let other = LiveStats::new(3);

        own.thread_activity.mark_busy(0);
        own.thread_activity.mark_busy(2);
        // "other" ma inny wzorzec zajętości - blok powinien pokazać TYLKO own
        other.thread_activity.mark_busy(1);

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_crypto_block(&own, &other, start_time);

        let line = block.lines().find(|l| l.starts_with("Wątki BLAKE3")).expect("powinna istnieć linia Wariantu A");
        assert_eq!(line, "Wątki BLAKE3 (Wariant A): {G:1} {R:2} {G:3}");
    }

    #[test]
    fn test_build_crypto_block_top_extension_by_weight() {
        let own = LiveStats::new(4);
        let other = LiveStats::new(4);

        own.ext_weights.lock().unwrap().insert("jpg".to_string(), 500);
        other.ext_weights.lock().unwrap().insert("jpg".to_string(), 600); // razem 1100 - powinno wygrać
        own.ext_weights.lock().unwrap().insert("png".to_string(), 200);

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_crypto_block(&own, &other, start_time);

        // .jpg (razem 1100 bajtów, poniżej 1KB więc format_bytes pokaże "B") powinien być pierwszy na liście Top format
        let top_line = block.lines().find(|l| l.starts_with("Top format:")).unwrap();
        assert!(top_line.contains(".jpg"));
    }

    #[test]
    fn test_build_anomaly_block_sums_all_nine_categories() {
        let own = LiveStats::new(4);
        let other = LiveStats::new(4);

        own.offset_anomalies.store(1, Ordering::Relaxed);
        other.offset_anomalies.store(1, Ordering::Relaxed);
        own.null_padding.store(2, Ordering::Relaxed);
        own.high_volatility.store(4, Ordering::Relaxed);
        other.high_volatility.store(1, Ordering::Relaxed);

        let block = build_anomaly_block(&own, &other);

        assert!(block.starts_with("[Anomalie pierwszego klastra]"));
        assert!(block.contains("Przesunięty nagłówek: 2"));
        assert!(block.contains("Null-padding: 2"));
        assert!(block.contains("Wysoka wolatywność: 5"));
    }

    #[test]
    fn test_build_anomaly_block_all_zero_when_no_activity() {
        let own = LiveStats::new(4);
        let other = LiveStats::new(4);
        let block = build_anomaly_block(&own, &other);

        // Każda linia poza nagłówkiem powinna kończyć się na ": 0"
        for line in block.lines().skip(1) {
            assert!(line.ends_with(": 0"), "Oczekiwano zera dla świeżo utworzonych LiveStats: {}", line);
        }
    }

    // ------------------------------------------------------------------
    // Regresja: prawdziwy błąd I/O nie może udawać pustego pliku
    // ------------------------------------------------------------------

    /// Pomocnicza konstrukcja `StreamCtx` z jednym zadaniem — resztę pól
    /// wypełnia neutralnymi wartościami, zwraca też odbiorcę `ScanMsg`, żeby
    /// test mógł zbadać wynik wysłany do wątku bazy.
    fn uruchom_strumien_z_jednym_zadaniem(
        base_path: &Path,
        rel_path: &str,
    ) -> Vec<ScanResult> {
        let tasks = vec![Task { id: 42, rel_path: rel_path.to_string() }];
        let stats = LiveStats::new(1);
        let other_stats = LiveStats::new(1);
        let (tx_db, rx_db) = mpsc::sync_channel(8);
        let (tx_ui, _rx_ui) = mpsc::channel();

        let log_dir = tempfile::tempdir().unwrap();
        let opr_log = Arc::new(Mutex::new(File::create(log_dir.path().join("log.txt")).unwrap()));

        process_side_stream(StreamCtx {
            base_path,
            tasks: &tasks,
            side_label: "UFS Explorer",
            stats: &stats,
            other_stats: &other_stats,
            tx_db,
            is_ufs: true,
            tx_ui: &tx_ui,
            bar_idx: 0,
            opr_log,
            start_time: Instant::now(),
        });

        let mut wyniki = Vec::new();
        while let Ok(msg) = rx_db.try_recv() {
            match msg {
                ScanMsg::UfsChunk(r) | ScanMsg::ScriptChunk(r) => wyniki.extend(r),
            }
        }
        wyniki
    }

    /// Odtwarza dokładnie opisany scenariusz: `File::open()` się udaje, ale
    /// właściwy odczyt zawodzi FAKTYCZNYM błędem I/O (nie EOF na pustym
    /// pliku). Na Linuksie otwarcie katalogu jako "pliku" jest legalne, ale
    /// `read()` na takim uchwycie zwraca błąd (EISDIR) — to niezawodny,
    /// przenośny w obrębie Linuksa sposób na wywołanie w teście dokładnie tej
    /// klasy błędu, bez potrzeby manipulacji uprawnieniami czy odłączania
    /// nośnika.
    ///
    /// Przed poprawką `file.read(&mut buffer).unwrap_or(0)` zamieniał ten
    /// błąd w `first_read == 0`, program traktował plik jak pustą wydmuszkę,
    /// próbował go zahashować przez `hash_file()` (co też się nie udaje na
    /// katalogu) i w efekcie zapisywał `hash = None`, `io_error = Some(false)`
    /// — kombinację, która NIGDY nie spełnia warunku `phase3_done` i
    /// powodowała nieskończone ponawianie.
    #[test]
    fn test_prawdziwy_blad_io_przy_odczycie_naglowka_nie_jest_pustym_plikiem() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("nie_jest_plikiem")).unwrap();

        let wyniki = uruchom_strumien_z_jednym_zadaniem(dir.path(), "nie_jest_plikiem");

        assert_eq!(wyniki.len(), 1);
        let r = &wyniki[0];
        assert_eq!(r.id, 42);
        assert_eq!(r.hash, None, "przy błędzie I/O nie ma sensownego hashu do zapisania");
        assert_eq!(
            r.io_error, Some(true),
            "prawdziwy błąd I/O MUSI zostać zgłoszony jako io_error=true - inaczej phase3_done \
             (hash_ufs IS NOT NULL OR io_error_ufs = 1) nigdy się nie spełnia i plik wraca do \
             kolejki w nieskończoność"
        );
    }

    /// Kontrola pozytywna dla powyższego: PRAWDZIWIE pusty plik (0 bajtów) w
    /// dalszym ciągu musi zostać poprawnie policzony i oznaczony jako
    /// `io_error = Some(false)` — rozróżnienie EOF-na-pustym-pliku od
    /// faktycznego błędu I/O nie może zepsuć poprawnej ścieżki.
    #[test]
    fn test_naprawde_pusty_plik_nadal_dostaje_hash_i_brak_bledu() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pusty.bin"), b"").unwrap();

        let wyniki = uruchom_strumien_z_jednym_zadaniem(dir.path(), "pusty.bin");

        assert_eq!(wyniki.len(), 1);
        let r = &wyniki[0];
        assert!(r.hash.is_some(), "pusty plik ma poprawny hash BLAKE3 pustego ciągu, nie None");
        assert_eq!(r.io_error, Some(false), "pusty plik to NIE jest błąd I/O");
    }
}
