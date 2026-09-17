// src/phases/phase2.rs

//! # Faza 2: Akwizycja Rozmiarów (Stat)
//!
//! Pobiera wyłącznie fizyczny rozmiar plików w bajtach.
//! Wykorzystuje strumieniowanie MPSC do bazy danych, chroniąc pamięć RAM (OOM Protection).
//! Komunikuje się z interfejsem Ratatui poprzez PhaseEvent i używa systemu Dual-Logging.
//!
//! UWAGA ARCHITEKTONICZNA:
//! - Pasek postępu pokazuje wyłącznie % i bieżącą ścieżkę pliku.
//! - Wszystkie liczniki live (przetworzono, zważono, błędy, puste pliki, top
//!   format) trafiają do panelu bocznego, ROZDZIELONE per skaner (UFS i Skrypt
//!   mają niezależne, kompletne bloki — zgodnie ze wzorcem ustalonym w Fazie 1).

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
use std::thread;
use std::time::{Duration, Instant};
use tracing::{info, instrument, warn};

// OPTYMALIZACJA: Ponieważ pobieranie samej wagi (lstat) jest ekstremalnie szybkie,
// zwiększamy rozmiar paczki do 1000, aby zredukować narzut komunikacji MPSC i przyspieszyć SQLite.
const CHUNK_SIZE: usize = 1000;

// ============================================================================
// ZAPYTANIA SQL (wydzielone, żeby dały się testować bez duplikowania treści)
// ============================================================================

/// Zapis rozmiaru i statusu I/O dla strony UFS.
///
/// `COALESCE` jest tu istotny, a nie kosmetyczny: wynik odczytu, który się nie
/// powiódł, niesie `size = NULL`. Bez `COALESCE` taki zapis **wymazywałby**
/// rozmiar odczytany wcześniej poprawnie, zamieniając udany pomiar w brak
/// danych.
const SQL_ZAPIS_UFS: &str =
    "UPDATE files SET size_ufs = COALESCE(?1, size_ufs), io_error_ufs = COALESCE(?2, io_error_ufs) WHERE id = ?3";

/// Odpowiednik [`SQL_ZAPIS_UFS`] dla strony Skryptu Autorskiego.
const SQL_ZAPIS_SCRIPT: &str =
    "UPDATE files SET size_script = COALESCE(?1, size_script), io_error_script = COALESCE(?2, io_error_script) WHERE id = ?3";

/// Domknięcie macierzy rozmiarów — najgęstsza logika tej fazy.
///
/// Ustala trzy rzeczy naraz:
///
/// * `size_match` — `1` przy zgodnych rozmiarach, `0` przy różnych, a `NULL`
///   gdy porównanie jest NIEMOŻLIWE: po błędzie I/O albo gdy brakuje rozmiaru
///   po którejś stronie. `NULL` znaczy „nie wiem", nie „nie pasuje" — Faza 8
///   opiera na tym rozróżnieniu decyzję, więc zlanie ich w jedno dałoby
///   fałszywy wniosek o niezgodności kopii.
/// * `larger_side` — która strona jest większa. Porównania z `NULL` dają w
///   SQLite `NULL`, więc przy brakującym rozmiarze gałąź sama wpada w `ELSE`.
/// * `phase2_done` — `1` dopiero, gdy OBIE strony są rozstrzygnięte: każda ma
///   rozmiar, zgłosiła błąd I/O albo w ogóle nie występuje. Dzięki temu plik
///   niedokończony wraca do kolejki przy następnym uruchomieniu.
const SQL_FINALIZACJA_MACIERZY: &str = "UPDATE files 
         SET size_match = CASE 
                WHEN io_error_ufs = 1 OR io_error_script = 1 THEN NULL
                WHEN size_ufs IS NULL OR size_script IS NULL THEN NULL 
                WHEN size_ufs = size_script THEN 1 
                ELSE 0 
             END, 
             larger_side = CASE
                WHEN size_ufs > size_script THEN 'UFS'
                WHEN size_script > size_ufs THEN 'SCRIPT'
                ELSE NULL
             END,
             phase2_done = CASE 
                WHEN (found_in_ufs = 0 OR size_ufs IS NOT NULL OR io_error_ufs = 1) 
                 AND (found_in_script = 0 OR size_script IS NOT NULL OR io_error_script = 1) THEN 1 
                ELSE 0 
            END
         WHERE phase2_done = 0 OR phase2_done IS NULL";

// ============================================================================
// STRUKTURY DANYCH
// ============================================================================

#[derive(Debug, Clone)]
pub(crate) struct Task {
    id: i32,
    rel_path: String,
}

#[derive(Debug, Clone)]
struct FileStats {
    size: i64,
}

#[derive(Debug)]
pub(crate) struct SideResult {
    id: i32,
    stats: Option<FileStats>,
    io_error: Option<bool>,
}

pub(crate) enum ScanMsg {
    UfsChunk(Vec<SideResult>),
    ScriptChunk(Vec<SideResult>),
}

pub(crate) struct LiveStats {
    processed: AtomicUsize,
    errors: AtomicUsize,
    empty_files: AtomicUsize, 
    total_bytes: AtomicU64,
    ext_weights: Mutex<HashMap<String, u64>>,
    /// EKSPERYMENTALNE (Wariant A): śledzi zajętość logicznych slotów Rayon —
    /// ta sama konwencja i ten sam tracker, co w pozostałych fazach
    /// równoległych, patrz `thread_activity`.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            processed: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            empty_files: AtomicUsize::new(0),
            total_bytes: AtomicU64::new(0),
            ext_weights: Mutex::new(HashMap::new()),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }

    /// Dostęp do mapy wag rozszerzeń ODPORNY NA ZATRUCIE muteksa.
    ///
    /// REGRESJA (measure twice — druga weryfikacja Gemini, todo.faza02.md
    /// obs. 4): `.lock().unwrap()` na zatrutym mutexie (bo jakiś wątek
    /// spanikował trzymając blokadę) zamieniałby cudzą panikę w KOLEJNĄ
    /// panikę tu, w tym wątku — wywracając całą fazę zamiast dokończyć pracę
    /// i zaraportować wynik. Ten sam wzorzec co
    /// `phase17_repair::LiveStats::liczniki` — mapa to zwykłe liczniki bez
    /// stanu, który mógłby stracić spójność przez zatrucie, więc
    /// `into_inner()` jest tu właściwym zachowaniem.
    fn wagi_rozszerzen(&self) -> std::sync::MutexGuard<'_, HashMap<String, u64>> {
        self.ext_weights.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Wylicza liczbę slotów trackera zajętości (Wariant A) odpowiednią dla
/// trybu I/O — identyczna logika jak w `phase3::compute_activity_slots`.
fn compute_activity_slots(io_mode: &str, actual_threads: usize, half_threads: usize) -> usize {
    if io_mode == "CONCURRENT" { half_threads } else { actual_threads }
}

// ============================================================================
// PANEL BOCZNY — BLOK STATYSTYK DLA JEDNEGO ŹRÓDŁA (UFS albo Skrypt)
// ============================================================================

/// Buduje pełny blok live dla JEDNEGO skanera. Nie miesza danych z drugą stroną —
/// operator ma widzieć wydajność i anomalie KONKRETNEGO silnika odzysku.
fn build_source_block(label: &str, stats: &LiveStats) -> String {
    let processed = stats.processed.load(Ordering::Relaxed);
    let errors = stats.errors.load(Ordering::Relaxed);
    let empty = stats.empty_files.load(Ordering::Relaxed);
    let bytes = stats.total_bytes.load(Ordering::Relaxed);

    let top_ext_str = {
        let map = stats.wagi_rozszerzen();
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.into_iter().take(3).map(|(ext, w)| {
            let e = if ext == "brak" { "brak".to_string() } else { format!(".{}", ext) };
            format!("{} ({})", e, format_bytes(*w))
        }).collect::<Vec<_>>().join(", ")
    };
    let top_display = if top_ext_str.is_empty() { "Analiza danych...".to_string() } else { top_ext_str };

    let activity_markup = crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot());

    format!(
        "[{}]\n📦 Przetworzono: {}\n⚖️ Zważono łącznie: {}\n🔝 Top format: {}\n🕳️ Puste pliki: {}\nWątki lstat (Wariant A): {}\n🚨 Błędy I/O: {}",
        label, processed, format_bytes(bytes), top_display, empty, activity_markup, errors
    )
}

// ============================================================================
// LOGIKA BIZNESOWA I INTEGRACJA Z RATATUI ORAZ LOGAMI
// ============================================================================

fn get_file_stats(path: &Path) -> std::result::Result<FileStats, std::io::Error> {
    fs::symlink_metadata(path).map(|meta| FileStats {
        size: meta.len() as i64,
    })
}

/// Jak często pętla oczekująca na wynik `lstat` sprawdza [`CANCEL_SIGNAL`] —
/// patrz [`StatWatchdog`]. Kompromis: krótszy interwał = szybsza reakcja na
/// Ctrl+C, ale też częstsze budzenie wątku bez powodu w normalnym,
/// nieopóźnionym przypadku (koszt pomijalny wobec samego kosztu syscalla).
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(150);

/// Domyka lukę, w której [`CANCEL_SIGNAL`] jest sprawdzany wyłącznie MIĘDZY
/// kolejnymi plikami w pętli (patrz `process_side_stream`) — jeśli sam
/// pojedynczy `fs::symlink_metadata` (lstat) zawiesi się (typowo: martwe
/// montowanie sieciowe / FUSE), operator naciskający Ctrl+C nie doczekałby
/// się reakcji, dopóki ten JEDEN syscall by nie wrócił — co przy zawieszonym
/// mountpoincie może oznaczać "nigdy" bez zewnętrznej interwencji (SIGKILL).
///
/// ## Mechanizm: stały wątek-towarzysz, NIE wątek na plik
///
/// Naiwne rozwiązanie ("odpal nowy wątek na każdy plik i czekaj z
/// timeoutem") jest niedopuszczalnie kosztowne przy milionach plików —
/// tworzenie wątku systemowego to realny koszt, wielokrotnie większy niż
/// sam `lstat` w gorącym cache. Zamiast tego KAŻDY wątek roboczy Rayon
/// (jeden `for_each_init` na wątek — patrz `process_side_stream`) tworzy
/// SWÓJ WŁASNY, DŁUGOŻYJĄCY wątek-towarzysz JEDEN RAZ na cały przebieg
/// strony, i zleca mu KOLEJNE pliki przez kanał — koszt jednorazowego
/// `thread::spawn` amortyzuje się na cały bieg, a nie na pojedynczy plik.
///
/// Prywatna para kanałów per wątek roboczy (nie pula współdzielona) jest
/// celowa: gdyby wiele wątków roboczych dzieliło JEDNĄ pulę wątków-
/// towarzyszy, zawieszony syscall jednego pliku trwale "zjadałby" jednego
/// współdzielonego workera, aż w końcu (przy kolejnych zawieszeniach)
/// wyczerpałby całą pulę i zablokował WSZYSTKICH. Przy odizolowanych parach
/// 1:1 zawieszenie dotyka wyłącznie TEGO JEDNEGO wątku roboczego Rayon —
/// pozostałe kontynuują normalnie.
///
/// ## Co się dzieje z "porzuconym" zawieszonym wywołaniem
///
/// Gdy `stat_z_limitem` zwraca `None` (bo w międzyczasie zgłoszono
/// anulowanie), wątek-towarzysz NIE jest zabijany (Rust/POSIX nie oferują
/// bezpiecznego zabijania wątku w trakcie syscalla) — zostaje PORZUCONY.
/// Jeśli kiedykolwiek dokończy swój `lstat`, spróbuje odesłać wynik, ale
/// odbiorca (`rep_rx`) nie jest już czytany (globalny `CANCEL_SIGNAL`
/// gwarantuje, że TEN wątek roboczy nigdy więcej nie zleci nowego zadania
/// ani nie odczyta odpowiedzi) — więc wynik jest po prostu cicho gubiony,
/// bez ryzyka pomylenia go z odpowiedzią na inny, późniejszy plik.
struct StatWatchdog {
    req_tx: mpsc::Sender<PathBuf>,
    rep_rx: mpsc::Receiver<std::result::Result<FileStats, std::io::Error>>,
}

impl StatWatchdog {
    fn new() -> Self {
        let (req_tx, req_rx) = mpsc::channel::<PathBuf>();
        let (rep_tx, rep_rx) = mpsc::channel::<std::result::Result<FileStats, std::io::Error>>();
        thread::spawn(move || {
            for path in req_rx {
                if rep_tx.send(get_file_stats(&path)).is_err() { break; }
            }
        });
        Self { req_tx, rep_rx }
    }

    /// Zleca `lstat` wątkowi-towarzyszowi i czeka na wynik, sprawdzając
    /// [`CANCEL_SIGNAL`] co [`CANCEL_POLL_INTERVAL`]. Zwraca `None`
    /// NATYCHMIAST po najbliższym punkcie kontrolnym po zgłoszeniu
    /// anulowania — nie czeka na faktyczne zakończenie zawieszonego
    /// wywołania (patrz dokumentacja [`StatWatchdog`]).
    fn stat_z_limitem(&self, path: PathBuf) -> Option<std::result::Result<FileStats, std::io::Error>> {
        if self.req_tx.send(path).is_err() { return None; }
        loop {
            match self.rep_rx.recv_timeout(CANCEL_POLL_INTERVAL) {
                Ok(wynik) => return Some(wynik),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if CANCEL_SIGNAL.load(Ordering::Relaxed) { return None; }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
    }
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
    pub opr_log: Arc<Mutex<File>>,
}

#[instrument(skip(ctx), fields(base_path = %ctx.base_path.display()))]

fn process_side_stream<'a>(ctx: StreamCtx<'a>) {
    let StreamCtx { base_path, tasks, side_label, stats, tx_db, is_ufs, tx_ui, bar_idx, opr_log } = ctx;

    // for_each_init inicjalizuje lokalny stan dla KAŻDEGO wątku z osobna:
    // (kanał, stoper utrzymywany między paczkami, lokalny bufor na logi
    // tekstowe, wątek-towarzysz do lstat odpornego na zawieszenie — patrz
    // dokumentacja `StatWatchdog`)
    tasks.par_chunks(CHUNK_SIZE).for_each_init(
        || (tx_db.clone(), Instant::now(), Vec::new(), StatWatchdog::new()),
        |(tx, last_ui_update, log_buf, watchdog), chunk| {
            let mut results = Vec::with_capacity(chunk.len());
            let mut local_ext_weights: HashMap<String, u64> = HashMap::new();

            for task in chunk {
                if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

                let full_path = base_path.join(&task.rel_path);

                let wynik_lstat = match stats.thread_activity.track_current(|| watchdog.stat_z_limitem(full_path.clone())) {
                    Some(w) => w,
                    None => break, // Anulowano podczas oczekiwania na zawieszone I/O — patrz `StatWatchdog`.
                };

                let (stats_opt, io_err) = match wynik_lstat {
                    Ok(s) => {
                        let size = s.size as u64;
                        stats.total_bytes.fetch_add(size, Ordering::Relaxed);
                        
                        if size == 0 {
                            stats.empty_files.fetch_add(1, Ordering::Relaxed);
                            // Logujemy do RAM-u zamiast od razu dławić dysk Mutexem
                            log_buf.push(format!("[{}] Wydmuszka (0 B): {}", side_label, task.rel_path));
                        }

                        let ext = Path::new(&task.rel_path)
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("brak")
                            .to_lowercase();

                        *local_ext_weights.entry(ext).or_insert(0) += size;

                        (Some(s), Some(false))
                    }
                    Err(e) => {
                        warn!(path = %task.rel_path, side = side_label, error = %e, "Błąd I/O (lstat)");
                        stats.errors.fetch_add(1, Ordering::Relaxed);
                        log_buf.push(format!("[{}] Błąd I/O: {} -> {}", side_label, e, task.rel_path));
                        (None, Some(true))
                    }
                };

                let current = stats.processed.fetch_add(1, Ordering::Relaxed) + 1;
                let now = Instant::now();
                
                // Stabilne odświeżanie UI - stoper nie ulega zresetowaniu po przetworzeniu małej paczki
                if now.duration_since(*last_ui_update).as_millis() > 60 {
                    *last_ui_update = now;
                    
                    if !local_ext_weights.is_empty() {
                        let mut global_map = stats.wagi_rozszerzen();
                        for (k, v) in local_ext_weights.drain() {
                            *global_map.entry(k).or_insert(0) += v;
                        }
                    }

                    // PASEK: wyłącznie postęp + bieżący plik (bez liczników)
                    let _ = tx_ui.send(PhaseEvent::UpdateBar {
                        idx: bar_idx,
                        current: current as u64,
                        message: format_display_path(&task.rel_path),
                    });

                    // REGRESJA (menu/dashboard — naprawa dolnego panelu ścieżek):
                    // brakowało tu tej wysyłki — dolny panel "Aktualnie skanowane
                    // ścieżki" zostawał pusty przez CAŁĄ Fazę 2. Ten sam wzorzec co
                    // `phase4.rs`/`phase5.rs`/`phase6.rs`/`phase7.rs`.
                    let _ = tx_ui.send(PhaseEvent::UpdateBottomPath {
                        idx: bar_idx,
                        path: full_path.to_string_lossy().to_string(),
                    });

                    // PANEL BOCZNY: pełny, samodzielny blok TEGO źródła
                    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                        idx: bar_idx,
                        text: build_source_block(side_label, stats),
                    });
                }

                results.push(SideResult { id: task.id, stats: stats_opt, io_error: io_err });
            }

            // --- Zrzuty zbiorcze na koniec pętli nad pojedynczą paczką ---

            if !local_ext_weights.is_empty() {
                let mut global_map = stats.wagi_rozszerzen();
                for (k, v) in local_ext_weights.drain() { *global_map.entry(k).or_insert(0) += v; }
            }

            // Masowy zapis logów do pliku na dysku raz na 1000 iteracji, żeby nie blokować Mutexa!
            if !log_buf.is_empty()
                && let Ok(mut f) = opr_log.lock() {
                    for line in log_buf.drain(..) {
                        let _ = writeln!(f, "{}", line);
                    }
                }

            if !results.is_empty() {
                if is_ufs { let _ = tx.send(ScanMsg::UfsChunk(results)); } 
                else { let _ = tx.send(ScanMsg::ScriptChunk(results)); }
            }
        }
    );
    
    // Zakończenie pracy paska + panelu bocznego (finalny stan)
    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: stats.processed.load(Ordering::Relaxed) as u64,
        message: "Odczyt dyskowy w 100% zakończony.".to_string(),
    });
    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
        idx: bar_idx,
        text: build_source_block(side_label, stats),
    });
}

// ============================================================================
// GŁÓWNA FUNKCJA KORDYNUJĄCA FAZĘ
// ============================================================================

pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    crate::utils::CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    let _ = conn.execute("ALTER TABLE files ADD COLUMN larger_side TEXT", []);

    // 1. INICJALIZACJA DUAL-LOGGING (Pobieranie ścieżek z Ustawień)
    let raport_cfg = config.raporty_faz.get("Faza 2").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza2.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza2.txt".to_string(),
    });
    
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);
    
    // REGRESJA (todo.faza02.md): `.unwrap()` tu panikował, gdyby katalog
    // logów stał się niezapisywalny między `create_dir_all` a tym miejscem
    // (np. zablokowany przez antywirusa, drugą równoległą instancję, wolumin
    // odmontowany w międzyczasie) — cały bieg fazy ginął z powodu samego
    // logowania, zanim jakikolwiek plik został przetworzony. Ten sam wzorzec
    // graceful fallback co w Fazie 1/10/13/17.
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
        let _ = writeln!(f, "=== RAPORT OPERACYJNY - FAZA 2 (AKWIZYCJA ROZMIARÓW) ===");
        let _ = writeln!(f, "Zawiera pliki uszkodzone I/O oraz wykryte puste wydmuszki 0 B.\n");
    }

    let actual_threads = if config.max_threads > 0 { config.max_threads } else { rayon::current_num_threads() };
    let io_text = if config.io_mode == "CONCURRENT" { "RÓWNOLEGŁE (SSD/NVMe)" } else { "SEKWENCYJNIE (HDD)" };
    
    let _ = tx_ui.send(PhaseEvent::Log(format!("Uruchomiono Fazę 2. Metodyka szyny dyskowej: {}", io_text)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora (Rayon): {}", actual_threads)));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    // --- ETAP 1: POBIERANIE ZADAŃ Z BAZY ---
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, size_ufs, size_script, io_error_ufs, io_error_script 
         FROM files WHERE phase2_done = 0 OR phase2_done IS NULL"
    )?;

    let mut ufs_tasks = Vec::new();
    let mut script_tasks = Vec::new();
    let mut skipped_ufs = 0;
    let mut skipped_script = 0;

    let rows = stmt.query_map([], |row| {
        let id: i32 = row.get(0)?;
        let rel: String = row.get(1)?;
        let in_ufs: bool = row.get(2)?;
        let in_script: bool = row.get(3)?;
        let s_ufs: Option<i64> = row.get(4)?;
        let s_scr: Option<i64> = row.get(5)?;
        let err_ufs: Option<bool> = row.get(6)?;
        let err_scr: Option<bool> = row.get(7)?;
        Ok((id, rel, in_ufs, in_script, s_ufs, s_scr, err_ufs, err_scr))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_ufs, in_script, s_ufs, s_scr, err_ufs, err_scr) = r;

        if in_ufs {
            if s_ufs.is_none() && err_ufs != Some(true) { ufs_tasks.push(Task { id, rel_path: rel.clone() }); } 
            else { skipped_ufs += 1; }
        }

        if in_script {
            if s_scr.is_none() && err_scr != Some(true) { script_tasks.push(Task { id, rel_path: rel }); } 
            else { skipped_script += 1; }
        }
    }
    drop(stmt);

    if skipped_ufs > 0 || skipped_script > 0 {
        let _ = tx_ui.send(PhaseEvent::Log(format!("Pominięto pliki z wyliczonym już rozmiarem. UFS: {}, Skrypt: {}", skipped_ufs, skipped_script)));
    }

    let total_db_rows = ufs_tasks.len() + script_tasks.len();
    if total_db_rows == 0 {
        // KRYMINALISTYCZNA POPRAWKA (nie usuwać bez zrozumienia scenariusza):
        // mimo braku NOWYCH zadań I/O w tej sesji, finalizacja MUSI się
        // wykonać. Scenariusz: proces przerwany DOKŁADNIE po zapisaniu
        // rozmiarów obu stron, ale PRZED finalizacją macierzy — przy
        // kolejnym starcie zapytanie z ETAPU 1 nie znajdzie już żadnych
        // "nowych" zadań (rozmiary są już w bazie), więc total_db_rows == 0.
        // Bez tego wywołania plik zostawałby TRWALE z size_match = NULL i
        // phase2_done = 0, nigdy więcej nie trafiając do finalizacji.
        // SQL_FINALIZACJA_MACIERZY jest idempotentny (WHERE phase2_done = 0
        // OR phase2_done IS NULL), więc wywołanie go tu "na pusto" (gdy
        // baza faktycznie jest już aktualna) jest bezpieczne i tanie.
        conn.execute(SQL_FINALIZACJA_MACIERZY, [])?;
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak plików wymagających weryfikacji rozmiarów. Baza aktualna.".to_string()));
        return Ok(());
    }

    // Inicjalizacja pasków postępu Ratatui
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "UFS Explorer".to_string(), total: ufs_tasks.len() as u64, color: Color::Cyan });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 1, label: "Skrypt Autorski".to_string(), total: script_tasks.len() as u64, color: Color::Magenta });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 2, label: "Zapis SQLite".to_string(), total: total_db_rows as u64, color: Color::Green });

    let activity_slots = compute_activity_slots(
        &config.io_mode,
        actual_threads,
        std::cmp::max(1, actual_threads / 2),
    );
    let ufs_stats = LiveStats::new(activity_slots);
    let script_stats = LiveStats::new(activity_slots);
    let ufs_base = PathBuf::from(&config.ufs_path);
    let script_base = PathBuf::from(&config.script_path);

    // --- ETAP 3: PRZETWARZANIE STRUMIENIOWE (MPSC) ---
    // REGRESJA (measure twice — druga weryfikacja Gemini): każdy błąd SQLite
    // w wątku bazy był wcześniej `.unwrap()`, czyli paniką w wątku pisarza
    // wewnątrz `thread::scope` — jeden transjentny błąd I/O bazy (dysk
    // pełny, blokada pliku WAL) ubijałby całą fazę bez żadnego komunikatu.
    // Ten sam wzorzec co `phase17_repair::run`/`phase1::run` — `db_thread`
    // zwraca `Result<()>`, panika jest przechwytywana przez `.join()` i
    // zamieniana na błąd domenowy.
    let wynik_zapisu: Result<()> = std::thread::scope(|s| {
        let (tx_db, rx_db) = mpsc::sync_channel(200);
        let conn_ref = &mut *conn;
        let tx_ui_ref = &tx_ui;

        // Wątek Bazy Danych z zapisem transakcyjnym (Hybrydowym)
        let db_thread = s.spawn(move || -> Result<()> {
            let mut last_ui_update = Instant::now();
            let mut last_commit = Instant::now();
            let mut db_inserted = 0;
            let mut pending_records = 0; // Licznik niezakomitowanych danych w obecnej transakcji

            let mut tx_trans = conn_ref.transaction()?;

            loop {
                // recv_timeout pozwala nam uwolnić bazę, jeśli długo nie ma danych, i zmusić ją do commita
                let msg_result = rx_db.recv_timeout(Duration::from_millis(100));

                // 1. ZAPAMIĘTUJEMY FLAGĘ (używając referencji `&`, nie konsumujemy wartości)
                let is_disconnected = matches!(&msg_result, Err(std::sync::mpsc::RecvTimeoutError::Disconnected));

                // 2. KONSUMUJEMY WYNIK
                if let Ok(msg) = msg_result {
                    let chunk_len = match &msg {
                        ScanMsg::UfsChunk(c) => c.len(),
                        ScanMsg::ScriptChunk(c) => c.len(),
                    };

                    {
                        let mut stmt = match &msg {
                            ScanMsg::UfsChunk(_) => tx_trans.prepare_cached(SQL_ZAPIS_UFS)?,
                            ScanMsg::ScriptChunk(_) => tx_trans.prepare_cached(SQL_ZAPIS_SCRIPT)?,
                        };

                        let chunk = match &msg {
                            ScanMsg::UfsChunk(c) => c,
                            ScanMsg::ScriptChunk(c) => c,
                        };

                        for res in chunk {
                            if res.stats.is_some() || res.io_error == Some(true) {
                                stmt.execute(params![res.stats.as_ref().map(|s| s.size), res.io_error, res.id])?;
                            }
                        }
                    }

                    db_inserted += chunk_len;
                    pending_records += chunk_len;
                }

                let now = Instant::now();

                // LOGIKA HYBRYDOWA: Commit co 10 000 rekordów LUB co 500 ms (jeśli mamy cokolwiek do zapisu)
                if pending_records > 0 && (pending_records >= 10_000 || now.duration_since(last_commit).as_millis() > 500) {
                    tx_trans.commit()?; // Fizyczny zrzut na dysk
                    tx_trans = conn_ref.transaction()?; // Natychmiastowe otwarcie nowej lufy
                    last_commit = now;
                    pending_records = 0;
                }

                // Płynne odświeżanie paska bazy danych
                if now.duration_since(last_ui_update).as_millis() > 60 {
                    last_ui_update = now;
                    let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { 
                        idx: 2, 
                        current: db_inserted as u64, 
                        message: format!("Synchronizacja: {} plików", db_inserted) 
                    });
                }

                // 3. ZAMKNIĘCIE WĄTKU NA BAZIE ZAPAMIĘTANEJ FLAGI
                if is_disconnected {
                    break;
                }
            }

            // Zamknięcie programu: zrzut resztek (np. zostało 245 niezakomitowanych rekordów na koniec)
            if pending_records > 0 {
                tx_trans.commit()?;
            }

            let _ = tx_ui_ref.send(PhaseEvent::UpdateBar {
                idx: 2,
                current: db_inserted as u64,
                message: "Rozmiary w 100% zabezpieczone na dysku.".to_string()
            });
            Ok(())
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone();
            let tx2 = tx_db.clone();
            let log_u = opr_log.clone();
            let log_s = opr_log.clone();
            
            // TWORZYMY REFERENCJE PRZED WĄTKIEM
            let stat_u = &ufs_stats;
            let stat_s = &script_stats;

            // DZIELIMY PROCESOR NA PÓŁ (np. z 8 rdzeni robimy po 4 dla każdego skanera)
            let half_threads = std::cmp::max(1, actual_threads / 2);

            s.spawn(move || {
                if !ufs_tasks.is_empty() {
                    // Tworzymy prywatną pulę wątków TYLKO dla UFS
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: log_u, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: log_u, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Zakończono odczyt I/O na UFS Explorer".to_string()));
                }
            });

            s.spawn(move || {
                if !script_tasks.is_empty() {
                    // Tworzymy prywatną pulę wątków TYLKO dla Skryptu
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: log_s, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: log_s, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Zakończono odczyt I/O na Skrypcie Autorskim".to_string()));
                }
            });
            drop(tx_db);
        } else {
            let log_u = opr_log.clone();
            let log_s = opr_log.clone();
            
            if !ufs_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: &ufs_stats, tx_db: tx_db.clone(), is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: log_u, });
                let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Zakończono odczyt I/O na UFS Explorer".to_string()));
            }
            if !script_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: &script_stats, tx_db: tx_db.clone(), is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: log_s, });
                let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Zakończono odczyt I/O na Skrypcie Autorskim".to_string()));
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
                    "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 2 mógł nie zostać w pełni zapisany.".to_string()
                ));
                Err(rusqlite::Error::UnwindingPanic)
            }
        }
    });
    wynik_zapisu?;

    // --- ETAP 4: SYNCHRONIZACJA Z BAZĄ DANYCH (Wyliczenie Larger Side) ---
    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log("🛑 Skanowanie przerwane przez użytkownika.".to_string()));
        // ŚWIADOMA DECYZJA: tu NIE wołamy pełnej finalizacji macierzy — sesja
        // jest niekompletna (część zadań I/O mogła nie zostać w ogóle
        // wysłana/zapisana przed przerwaniem), więc dociągnięcie CASE na
        // wierszach czekających jeszcze na drugą stronę byłoby przedwczesne
        // i mogłoby błędnie zamknąć plik jako "gotowy" (phase2_done = 1) bez
        // realnego pomiaru drugiej strony.
        // To NIE zostawia wierszy trwale utkniętych: te, którym faktycznie
        // zapisano już obie strony (lub błąd I/O) przed przerwaniem, zostaną
        // dociągnięte przy KOLEJNYM uruchomieniu Fazy 2 — a jeśli to będzie
        // jedyne, co zostało do zrobienia, zadziała gałąź
        // `total_db_rows == 0` powyżej, która finalizację wykonuje zawsze.
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::Log("Trwa kryminalistyczne wiązanie macierzy rozmiarów w SQLite...".to_string()));
    
    conn.execute(SQL_FINALIZACJA_MACIERZY, [])?;

    // --- ETAP 5: ZAAWANSOWANY RAPORT KRYMINALISTYCZNY ---
    let mut total_common = 0;
    let mut matches = 0;
    let mut mismatches = 0;
    let mut ufs_won = 0;
    let mut script_won = 0;
    let mut only_ufs = 0;
    let mut only_script = 0;
    let mut matched_bytes: u64 = 0;
    let mut mismatched_bytes_lost: u64 = 0;
    // REGRESJA (todo.faza02.md, "cosmetic/reporting gap"): sekcja [2] liczyła
    // wyłącznie liczbę plików unikalnych dla jednej strony, bez ich wolumenu
    // w bajtach — w przeciwieństwie do sekcji [1], która od razu pokazuje
    // "Zweryfikowany wolumen". Operator widział np. "Tylko w UFS: 40 000",
    // ale nie miał jak ocenić, czy to 40 000 pustych plików, czy 40 000
    // dużych nagrań wideo, bez ręcznego zapytania do bazy.
    let mut only_ufs_bytes: u64 = 0;
    let mut only_script_bytes: u64 = 0;

    // REGRESJA (measure twice — druga weryfikacja Gemini, todo.faza02.md
    // obs. 2): `empty_ufs`/`empty_scr`/`errors` liczone były wcześniej z
    // liczników RAM (`LiveStats`), zerowanych przy KAŻDYM `run()` — podczas
    // gdy `total_common`/`matches`/`mismatches`/`only_ufs`/`only_script`
    // liczone są zapytaniem SQL obejmującym CAŁĄ historię bazy
    // (`WHERE phase2_done = 1`). W trybie wznowienia (część plików
    // zmierzona w poprzedniej, przerwanej sesji) sekcja "ANOMALIE I BŁĘDY
    // ODCZYTU I/O" zaniżała faktyczną liczbę błędów I/O i pustych plików,
    // pokazując tylko przyrost bieżącej sesji zamiast sumy zapisanej w
    // bazie. Naprawa: te trzy liczniki liczone są teraz w TEJ SAMEJ pętli,
    // z TEGO SAMEGO zapytania SQL, w tym samym zakresie `phase2_done = 1`.
    let mut empty_ufs: u64 = 0;
    let mut empty_scr: u64 = 0;
    let mut errors: u64 = 0;

    let mut stmt = conn.prepare("SELECT found_in_ufs, found_in_script, size_match, larger_side, size_ufs, size_script, io_error_ufs, io_error_script FROM files WHERE phase2_done = 1")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, bool>(0)?, row.get::<_, bool>(1)?, row.get::<_, Option<bool>>(2)?,
            row.get::<_, Option<String>>(3)?, row.get::<_, Option<i64>>(4)?, row.get::<_, Option<i64>>(5)?,
            row.get::<_, Option<bool>>(6)?, row.get::<_, Option<bool>>(7)?,
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (in_ufs, in_script, is_match, larger, s_ufs, s_scr, err_ufs, err_scr) = r;

        if in_ufs {
            if s_ufs == Some(0) { empty_ufs += 1; }
            if err_ufs == Some(true) { errors += 1; }
        }
        if in_script {
            if s_scr == Some(0) { empty_scr += 1; }
            if err_scr == Some(true) { errors += 1; }
        }

        match (in_ufs, in_script) {
            (true, true) => {
                total_common += 1;
                if is_match == Some(true) {
                    matches += 1;
                    if let Some(s) = s_ufs { matched_bytes += s as u64; }
                }
                else if is_match == Some(false) {
                    mismatches += 1;
                    if let (Some(u), Some(s)) = (s_ufs, s_scr) { mismatched_bytes_lost += u.abs_diff(s); }
                    if larger.as_deref() == Some("UFS") { ufs_won += 1; }
                    else if larger.as_deref() == Some("SCRIPT") { script_won += 1; }
                }
            },
            (true, false) => { only_ufs += 1; if let Some(s) = s_ufs { only_ufs_bytes += s as u64; } }
            (false, true) => { only_script += 1; if let Some(s) = s_scr { only_script_bytes += s as u64; } }
            _ => {}
        }
    }
    drop(stmt);

    let elapsed = start_time.elapsed();

    let mut final_report = String::new();
    use std::fmt::Write as FmtWrite;
    let _ = writeln!(&mut final_report, "==========================================================================");
    let _ = writeln!(&mut final_report, "DZIENNIK KOŃCOWY - FAZA 2 (AKWIZYCJA ROZMIARÓW I WAGI)");
    let _ = writeln!(&mut final_report, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut final_report, "==========================================================================\n");

    let _ = writeln!(&mut final_report, "[ 1 ] CZĘŚĆ WSPÓLNA (Pliki w strefie rywalizacji odzysku): {} plików", total_common);
    let _ = writeln!(&mut final_report, "   -> Zgodna waga bitowa:         {} (Zweryfikowany wolumen: {})", matches, format_bytes(matched_bytes));
    let _ = writeln!(&mut final_report, "      Znaczenie: Pliki posiadają dokładnie taki sam rozmiar w bajtach na obu nośnikach.");
    
    if mismatches > 0 {
        let _ = writeln!(&mut final_report, "   -> Różna waga (ucięte pliki):  {} (Wyliczono stratę danych na poziomie: {})", mismatches, format_bytes(mismatched_bytes_lost));
        let _ = writeln!(&mut final_report, "      * W {} przypadkach wersja z UFS posiadała więcej danych.", ufs_won);
        let _ = writeln!(&mut final_report, "      * W {} przypadkach wersja ze Skryptu posiadała więcej danych.", script_won);
    }

    let _ = writeln!(&mut final_report, "\n[ 2 ] UNIKALNE TRAFIENIA (Tylko na jednym z nośników):");
    let _ = writeln!(&mut final_report, "   -> Tylko w UFS Explorer:       {} (Wolumen: {})", only_ufs, format_bytes(only_ufs_bytes));
    let _ = writeln!(&mut final_report, "   -> Tylko w Skrypcie Autorskim: {} (Wolumen: {})\n", only_script, format_bytes(only_script_bytes));

    let _ = writeln!(&mut final_report, "[ 3 ] ANOMALIE I BŁĘDY ODCZYTU I/O:");
    let _ = writeln!(&mut final_report, "   -> Puste pliki (Wydmuszki 0 B): {} (UFS: {}, Skrypt: {})", empty_ufs + empty_scr, empty_ufs, empty_scr);
    let _ = writeln!(&mut final_report, "   -> Trwałe błędy dyskowe (I/O):  {}", errors);

    // Zapis do fizycznego pliku "Dziennik Końcowy" na podstawie konfiguracji Dual-Logging
    if let Ok(mut f) = fs::File::create(&dz_path) {
        let _ = f.write_all(final_report.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano fizyczny Dziennik Końcowy w: {}", dz_path.display())));
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano Raport Operacyjny (Live) w: {}", opr_path.display())));
    }

    // Wysyłamy również do Ratatui Log Panel
    for line in final_report.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    // Zrzut telemetrii do głównego pliku logów w tle
    info!(
        matches,
        mismatches,
        only_ufs,
        only_script,
        errors,
        empty_files = empty_ufs + empty_scr,
        matched_volume = format_bytes(matched_bytes),
        only_ufs_volume = format_bytes(only_ufs_bytes),
        only_script_volume = format_bytes(only_script_bytes),
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 2 zakończona"
    );
    Ok(())

}

#[cfg(test)]
mod tests {
    use super::*;

    /// Konwencja „(Wariant A)" musi być identyczna we WSZYSTKICH fazach
    /// równoległych — ułatwia maszynowe parsowanie panelu i utrzymuje spójność
    /// wizualną. Ten test utrwala ją dla tej fazy.
    #[test]
    fn test_blok_zawiera_znacznik_aktywnosci_watkow() {
        let stats = LiveStats::new(2);
        stats.thread_activity.mark_busy(1);

        let block = build_source_block("UFS Explorer", &stats);

        let line = block
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("Wątki lstat"))
            .unwrap_or_else(|| panic!("brak linii Wariantu A w bloku:\n{}", block));

        assert_eq!(line, "Wątki lstat (Wariant A): {R:1} {G:2}");
    }

    /// Liczba slotów trackera musi wynikać z trybu I/O — w trybie równoległym
    /// obie strony dzielą pulę na pół, więc slotów jest o połowę mniej.
    #[test]
    fn test_liczba_slotow_zalezy_od_trybu_io() {
        assert_eq!(compute_activity_slots("CONCURRENT", 8, 4), 4);
        assert_eq!(compute_activity_slots("SEQUENTIAL", 8, 4), 8);
    }

    // ------------------------------------------------------------------
    // Odczyt rozmiaru pliku
    // ------------------------------------------------------------------

    fn utworz(sciezka: &Path, bajty: &[u8]) {
        if let Some(r) = sciezka.parent() { fs::create_dir_all(r).unwrap(); }
        fs::write(sciezka, bajty).unwrap();
    }

    #[test]
    fn test_odczyt_rozmiaru_zwyklego_pliku() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("a.bin");
        utworz(&plik, &vec![0u8; 4096]);

        assert_eq!(get_file_stats(&plik).unwrap().size, 4096);
    }

    #[test]
    fn test_pusty_plik_ma_rozmiar_zero_a_nie_blad() {
        // Wydmuszka (0 B) to poprawny wynik odczytu i osobna kategoria
        // śledcza - nie wolno jej mylić z błędem I/O.
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("pusty.bin");
        utworz(&plik, b"");

        assert_eq!(get_file_stats(&plik).unwrap().size, 0);
    }

    #[test]
    fn test_brak_pliku_daje_blad() {
        assert!(get_file_stats(Path::new("/nie/ma/takiego/pliku")).is_err());
    }

    // ------------------------------------------------------------------
    // StatWatchdog — regresja: Ctrl+C musi przerwać oczekiwanie na lstat,
    // nawet gdy sam syscall się zawiesza (np. martwe montowanie sieciowe).
    // ------------------------------------------------------------------

    #[test]
    fn test_stat_watchdog_normalny_plik_daje_taki_sam_wynik_co_bezposrednie_wywolanie() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("a.bin");
        utworz(&plik, &[0u8; 123]);

        let watchdog = StatWatchdog::new();
        let wynik = watchdog.stat_z_limitem(plik.clone()).expect("brak anulowania - musi zwrócić Some");

        assert_eq!(wynik.unwrap().size, 123);
    }

    #[test]
    fn test_stat_watchdog_propaguje_blad_io_tak_jak_wywolanie_bezposrednie() {
        let watchdog = StatWatchdog::new();
        let wynik = watchdog.stat_z_limitem(PathBuf::from("/nie/ma/takiego/pliku")).expect("brak anulowania - musi zwrócić Some");

        assert!(wynik.is_err());
    }

    #[test]
    fn test_stat_watchdog_wiele_kolejnych_zlecen_na_tym_samym_towarzyszu_dziala_poprawnie() {
        // Sedno projektu: JEDEN wątek-towarzysz obsługuje WIELE plików pod
        // rząd (reużycie, nie jednorazowe `thread::spawn` per plik) - musi
        // poprawnie parować kolejne odpowiedzi z kolejnymi zleceniami.
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.bin");
        let b = dir.path().join("b.bin");
        utworz(&a, &[0u8; 10]);
        utworz(&b, &[0u8; 20]);

        let watchdog = StatWatchdog::new();
        assert_eq!(watchdog.stat_z_limitem(a).unwrap().unwrap().size, 10);
        assert_eq!(watchdog.stat_z_limitem(b).unwrap().unwrap().size, 20);
    }

    /// Sedno naprawy: gdy `CANCEL_SIGNAL` jest już ustawiony ZANIM wątek-
    /// towarzysz zdąży odpowiedzieć, oczekiwanie musi zakończyć się przy
    /// najbliższym punkcie kontrolnym (`CANCEL_POLL_INTERVAL`), a nie czekać
    /// w nieskończoność na wynik. Symulujemy "zawieszenie" NIE wysyłając w
    /// ogóle żądania do kanału (nikt nigdy nie odpowie) - z punktu widzenia
    /// `stat_z_limitem` jest to nieodróżnialne od realnie zawieszonego
    /// `lstat` na martwym montowaniu sieciowym.
    #[test]
    #[ignore = "Mutuje globalny CANCEL_SIGNAL współdzielony ze wszystkimi testami \
                w tym binarnym pliku testowym. cargo test domyślnie uruchamia testy \
                równolegle w jednym procesie, więc równoczesny test odczytujący \
                CANCEL_SIGNAL mógłby dostać fałszywe 'true'. Uruchamiaj świadomie: \
                `cargo test -- --ignored test_stat_watchdog_anulowanie_przerywa_oczekiwanie_na_zawieszone_io`."]
    fn test_stat_watchdog_anulowanie_przerywa_oczekiwanie_na_zawieszone_io() {
        // Kanał BEZ żadnego wątku-towarzysza po drugiej stronie - żądanie
        // trafia donikąd, więc odpowiedź NIGDY nie nadejdzie. Dokładny
        // odpowiednik zawieszonego syscalla z punktu widzenia pętli
        // oczekującej w `stat_z_limitem`.
        let (req_tx, req_rx) = mpsc::channel::<PathBuf>();
        let (_rep_tx, rep_rx) = mpsc::channel::<std::result::Result<FileStats, std::io::Error>>();
        std::mem::forget(req_rx); // nikt nie odbiera - symulacja zawieszenia

        let watchdog = StatWatchdog { req_tx, rep_rx };

        CANCEL_SIGNAL.store(true, Ordering::SeqCst);
        let start = Instant::now();
        let wynik = watchdog.stat_z_limitem(PathBuf::from("/dowolna/sciezka"));
        let czas = start.elapsed();
        CANCEL_SIGNAL.store(false, Ordering::SeqCst); // Sprzątanie stanu globalnego po teście

        assert!(wynik.is_none(), "anulowanie musi dać None, nie czekać na zawieszoną odpowiedź");
        assert!(
            czas < CANCEL_POLL_INTERVAL * 5,
            "przerwanie musi nastąpić przy najbliższym punkcie kontrolnym, nie po arbitralnie długim czasie: {:?}", czas
        );
    }

    /// Faza 2 używa `symlink_metadata`, więc NIE podąża za dowiązaniem.
    ///
    /// To wybór śledczy, nie przeoczenie: rozmiar dowiązania opisuje sam wpis
    /// katalogowy. Podążanie za linkiem policzyłoby cudze bajty i zafałszowało
    /// porównanie obu kopii — a przy dowiązaniu wiszącym dałoby błąd I/O tam,
    /// gdzie plik jest w porządku.
    #[cfg(unix)]
    #[test]
    fn test_dowiazanie_nie_jest_sledzone() {
        let dir = tempfile::tempdir().unwrap();
        let cel = dir.path().join("cel.bin");
        utworz(&cel, &vec![7u8; 10_000]);

        let link = dir.path().join("link.bin");
        std::os::unix::fs::symlink(&cel, &link).unwrap();

        let rozmiar_linku = get_file_stats(&link).unwrap().size;
        assert_ne!(rozmiar_linku, 10_000, "rozmiar dowiązania nie może być rozmiarem celu");
        assert!(rozmiar_linku > 0 && rozmiar_linku < 1000, "dowiązanie waży tyle, co jego ścieżka: {}", rozmiar_linku);
    }

    #[cfg(unix)]
    #[test]
    fn test_wiszace_dowiazanie_nie_jest_bledem_io() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("wiszacy.bin");
        std::os::unix::fs::symlink(dir.path().join("nie_ma_mnie"), &link).unwrap();

        assert!(
            get_file_stats(&link).is_ok(),
            "wiszące dowiązanie ma czytelne metadane - to nie jest błąd odczytu"
        );
    }

    // ------------------------------------------------------------------
    // Panel boczny
    // ------------------------------------------------------------------

    fn stats_z_danymi() -> LiveStats {
        let s = LiveStats::new(2);
        s.processed.store(120, Ordering::Relaxed);
        s.errors.store(3, Ordering::Relaxed);
        s.empty_files.store(7, Ordering::Relaxed);
        s.total_bytes.store(1_048_576, Ordering::Relaxed);
        s
    }

    #[test]
    fn test_blok_pokazuje_wszystkie_liczniki() {
        let stats = stats_z_danymi();
        let blok = build_source_block("UFS Explorer", &stats);

        assert!(blok.starts_with("[UFS Explorer]"), "{}", blok);
        for oczekiwane in ["120", "1.00 MB", "7", "3"] {
            assert!(blok.contains(oczekiwane), "brak '{}' w bloku:\n{}", oczekiwane, blok);
        }
    }

    /// REGRESJA (measure twice — druga weryfikacja Gemini, todo.faza02.md
    /// obs. 4): dostęp do mapy wag rozszerzeń nie może panikować z powodu
    /// ZATRUCIA muteksa. Wcześniejsze `.lock().unwrap()` zamieniało panikę
    /// jednego wątku w panikę każdego następnego, wywracając całą fazę
    /// zamiast dokończyć pracę i zaraportować wynik. Ten sam wzorzec testu
    /// co `phase17_repair::tests::test_liczniki_odporne_na_zatruty_muteks`.
    #[test]
    fn test_wagi_rozszerzen_odporne_na_zatruty_muteks() {
        let stats = Arc::new(LiveStats::new(1));

        let stats_w_watku = Arc::clone(&stats);
        let _ = std::thread::spawn(move || {
            let _guard = stats_w_watku.ext_weights.lock().unwrap();
            panic!("celowa panika testowa trzymając blokadę");
        })
        .join();

        assert!(stats.ext_weights.is_poisoned(), "Setup testu: muteks MUSI być zatruty");

        {
            let mut m = stats.wagi_rozszerzen();
            m.insert("jpg".into(), 7);
        }
        assert_eq!(stats.wagi_rozszerzen().get("jpg").copied(), Some(7));

        let blok = build_source_block("UFS Explorer", &stats);
        assert!(blok.contains(".jpg"), "panel boczny musi się zbudować mimo zatrutego mutexa:\n{}", blok);
    }

    #[test]
    fn test_top_format_sortuje_po_wadze_i_bierze_trzy() {
        let stats = LiveStats::new(2);
        {
            let mut m = stats.wagi_rozszerzen();
            m.insert("jpg".into(), 100);
            m.insert("mp4".into(), 900);
            m.insert("dng".into(), 500);
            m.insert("txt".into(), 10);
        }

        let blok = build_source_block("UFS Explorer", &stats);
        let linia = blok.lines().find(|l| l.contains("Top format")).expect("linia Top format");

        let poz_mp4 = linia.find(".mp4").expect("mp4 musi być na liście");
        let poz_dng = linia.find(".dng").expect("dng musi być na liście");
        let poz_jpg = linia.find(".jpg").expect("jpg musi być na liście");
        assert!(poz_mp4 < poz_dng && poz_dng < poz_jpg, "kolejność wagowa: {}", linia);
        assert!(!linia.contains(".txt"), "czwarty format nie mieści się w Top 3: {}", linia);
    }

    #[test]
    fn test_pliki_bez_rozszerzenia_opisane_slowem_brak() {
        // Kategoria "brak" nie może dostać wiodącej kropki - to nie jest
        // rozszerzenie, tylko jego brak.
        let stats = LiveStats::new(2);
        stats.wagi_rozszerzen().insert("brak".into(), 42);

        let linia = build_source_block("UFS", &stats)
            .lines().find(|l| l.contains("Top format")).unwrap().to_string();

        assert!(linia.contains("brak ("), "kategoria bez rozszerzenia: {}", linia);
        assert!(!linia.contains(".brak"), "„brak” nie może udawać rozszerzenia: {}", linia);
    }

    #[test]
    fn test_brak_danych_daje_komunikat_zamiast_pustki() {
        let blok = build_source_block("UFS", &LiveStats::new(2));
        assert!(blok.contains("Analiza danych..."), "{}", blok);
    }

    // ------------------------------------------------------------------
    // Akwizycja na PRAWDZIWYCH plikach
    // ------------------------------------------------------------------

    fn uruchom_strumien(
        katalog: &Path,
        zadania: &[Task],
        is_ufs: bool,
    ) -> (LiveStats, Vec<ScanMsg>) {
        let (tx_db, rx_db) = mpsc::sync_channel(10_000);
        let (tx_ui, _rx_ui) = mpsc::channel();
        let stats = LiveStats::new(2);
        let log = Arc::new(Mutex::new(tempfile::tempfile().unwrap()));

        process_side_stream(StreamCtx { base_path: katalog, tasks: zadania, side_label: "Test", stats: &stats, tx_db, is_ufs, tx_ui: &tx_ui, bar_idx: 0, opr_log: log, });

        (stats, rx_db.into_iter().collect())
    }

    fn wyniki(msgs: &[ScanMsg]) -> Vec<&SideResult> {
        msgs.iter().flat_map(|m| match m {
            ScanMsg::UfsChunk(c) | ScanMsg::ScriptChunk(c) => c.iter().collect::<Vec<_>>(),
        }).collect()
    }

    #[test]
    fn test_strumien_wazy_pliki_i_sumuje_bajty() {
        let dir = tempfile::tempdir().unwrap();
        utworz(&dir.path().join("a.jpg"), &vec![0u8; 1000]);
        utworz(&dir.path().join("pod/b.jpg"), &vec![0u8; 2000]);

        let zadania = vec![
            Task { id: 1, rel_path: "a.jpg".into() },
            Task { id: 2, rel_path: "pod/b.jpg".into() },
        ];

        let (stats, msgs) = uruchom_strumien(dir.path(), &zadania, true);

        assert_eq!(stats.processed.load(Ordering::Relaxed), 2);
        assert_eq!(stats.total_bytes.load(Ordering::Relaxed), 3000);
        assert_eq!(stats.errors.load(Ordering::Relaxed), 0);

        let w = wyniki(&msgs);
        assert_eq!(w.len(), 2);
        let rozmiary: Vec<i64> = {
            let mut v: Vec<i64> = w.iter().filter_map(|r| r.stats.as_ref().map(|s| s.size)).collect();
            v.sort();
            v
        };
        assert_eq!(rozmiary, vec![1000, 2000]);
    }

    #[test]
    fn test_strumien_liczy_wydmuszki_osobno_od_bledow() {
        let dir = tempfile::tempdir().unwrap();
        utworz(&dir.path().join("pusty.bin"), b"");
        utworz(&dir.path().join("pelny.bin"), &[1u8; 10]);

        let zadania = vec![
            Task { id: 1, rel_path: "pusty.bin".into() },
            Task { id: 2, rel_path: "pelny.bin".into() },
        ];

        let (stats, _) = uruchom_strumien(dir.path(), &zadania, true);

        assert_eq!(stats.empty_files.load(Ordering::Relaxed), 1, "dokładnie jedna wydmuszka");
        assert_eq!(stats.errors.load(Ordering::Relaxed), 0, "wydmuszka NIE jest błędem I/O");
    }

    #[test]
    fn test_brakujacy_plik_jest_bledem_io_a_nie_rozmiarem_zero() {
        let dir = tempfile::tempdir().unwrap();
        let zadania = vec![Task { id: 1, rel_path: "nie_ma_mnie.bin".into() }];

        let (stats, msgs) = uruchom_strumien(dir.path(), &zadania, true);

        assert_eq!(stats.errors.load(Ordering::Relaxed), 1);
        assert_eq!(stats.empty_files.load(Ordering::Relaxed), 0, "brak pliku to nie wydmuszka");
        assert_eq!(stats.total_bytes.load(Ordering::Relaxed), 0);

        let w = wyniki(&msgs);
        assert_eq!(w.len(), 1);
        assert!(w[0].stats.is_none(), "brak rozmiaru przy błędzie odczytu");
        assert_eq!(w[0].io_error, Some(true));
    }

    #[test]
    fn test_wagi_rozszerzen_sa_sprowadzane_do_malych_liter() {
        // Odzyskane nazwy bywają w dowolnej wielkości liter; bez normalizacji
        // ".JPG" i ".jpg" konkurowałyby ze sobą w rankingu Top format.
        let dir = tempfile::tempdir().unwrap();
        utworz(&dir.path().join("a.JPG"), &[0u8; 100]);
        utworz(&dir.path().join("b.jpg"), &[0u8; 50]);
        utworz(&dir.path().join("bez_rozszerzenia"), &[0u8; 25]);

        let zadania = vec![
            Task { id: 1, rel_path: "a.JPG".into() },
            Task { id: 2, rel_path: "b.jpg".into() },
            Task { id: 3, rel_path: "bez_rozszerzenia".into() },
        ];

        let (stats, _) = uruchom_strumien(dir.path(), &zadania, true);

        let m = stats.wagi_rozszerzen();
        assert_eq!(m.get("jpg"), Some(&150), "oba warianty wielkości liter w jednym koszyku: {:?}", *m);
        assert!(!m.contains_key("JPG"), "wielkie litery nie mogą tworzyć osobnej kategorii");
        assert_eq!(m.get("brak"), Some(&25), "pliki bez rozszerzenia mają własną kategorię");
    }

    #[test]
    fn test_wyniki_trafiaja_do_wlasciwego_kanalu() {
        let dir = tempfile::tempdir().unwrap();
        utworz(&dir.path().join("x.bin"), b"x");
        let zadania = vec![Task { id: 1, rel_path: "x.bin".into() }];

        let (_, msgs_ufs) = uruchom_strumien(dir.path(), &zadania, true);
        assert!(msgs_ufs.iter().all(|m| matches!(m, ScanMsg::UfsChunk(_))), "przy is_ufs=true tylko kanał UFS");

        let (_, msgs_scr) = uruchom_strumien(dir.path(), &zadania, false);
        assert!(msgs_scr.iter().all(|m| matches!(m, ScanMsg::ScriptChunk(_))), "przy is_ufs=false tylko kanał Skryptu");
    }

    #[test]
    fn test_identyfikatory_zadan_wracaja_nienaruszone() {
        // Wynik jest wiązany z wierszem bazy po `id`. Pomyłka tutaj
        // przypisałaby rozmiar jednego pliku do zupełnie innego.
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5 {
            utworz(&dir.path().join(format!("p{}.bin", i)), &vec![0u8; (i + 1) * 100]);
        }
        let zadania: Vec<Task> = (0..5)
            .map(|i| Task { id: 1000 + i, rel_path: format!("p{}.bin", i) })
            .collect();

        let (_, msgs) = uruchom_strumien(dir.path(), &zadania, true);

        let mut pary: Vec<(i32, i64)> = wyniki(&msgs).iter()
            .map(|r| (r.id, r.stats.as_ref().unwrap().size))
            .collect();
        pary.sort();

        assert_eq!(pary, vec![(1000, 100), (1001, 200), (1002, 300), (1003, 400), (1004, 500)]);
    }

    #[test]
    fn test_pusta_lista_zadan_nic_nie_wysyla() {
        let dir = tempfile::tempdir().unwrap();
        let (stats, msgs) = uruchom_strumien(dir.path(), &[], true);

        assert_eq!(stats.processed.load(Ordering::Relaxed), 0);
        assert!(msgs.is_empty());
    }

    // ------------------------------------------------------------------
    // Zapis do bazy — ochrona wcześniejszego pomiaru
    // ------------------------------------------------------------------

    fn baza_z_plikiem() -> Connection {
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script) VALUES (1, 'a.jpg', 1, 1)",
            [],
        ).unwrap();
        conn
    }

    fn rozmiary(conn: &Connection) -> (Option<i64>, Option<i64>, Option<bool>, Option<bool>) {
        conn.query_row(
            "SELECT size_ufs, size_script, io_error_ufs, io_error_script FROM files WHERE id = 1",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).unwrap()
    }

    #[test]
    fn test_zapis_rozmiaru_z_obu_stron_nie_miesza_kolumn() {
        let conn = baza_z_plikiem();

        conn.execute(SQL_ZAPIS_UFS, params![Some(500i64), Some(false), 1]).unwrap();
        conn.execute(SQL_ZAPIS_SCRIPT, params![Some(700i64), Some(false), 1]).unwrap();

        assert_eq!(rozmiary(&conn), (Some(500), Some(700), Some(false), Some(false)));
    }

    /// Sedno `COALESCE`: nieudany odczyt niesie `size = NULL` i NIE MOŻE
    /// wymazać rozmiaru zmierzonego wcześniej poprawnie.
    #[test]
    fn test_pozniejszy_blad_nie_kasuje_zmierzonego_rozmiaru() {
        let conn = baza_z_plikiem();

        conn.execute(SQL_ZAPIS_UFS, params![Some(1234i64), Some(false), 1]).unwrap();
        conn.execute(SQL_ZAPIS_UFS, params![None::<i64>, Some(true), 1]).unwrap();

        let (rozmiar, _, blad, _) = rozmiary(&conn);
        assert_eq!(rozmiar, Some(1234), "zmierzony rozmiar musi przetrwać późniejszy błąd odczytu");
        assert_eq!(blad, Some(true), "sam błąd musi zostać odnotowany");
    }

    // ------------------------------------------------------------------
    // Finalizacja macierzy rozmiarów — najgęstsza logika fazy
    // ------------------------------------------------------------------

    /// Wstawia wiersz o zadanym stanie i zwraca wynik finalizacji:
    /// `(size_match, larger_side, phase2_done)`.
    fn finalizuj(
        found_ufs: bool, found_script: bool,
        size_ufs: Option<i64>, size_script: Option<i64>,
        err_ufs: Option<bool>, err_script: Option<bool>,
    ) -> (Option<i64>, Option<String>, bool) {
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, size_ufs, size_script, io_error_ufs, io_error_script, phase2_done)
             VALUES (1, 'a.jpg', ?1, ?2, ?3, ?4, ?5, ?6, 0)",
            params![found_ufs, found_script, size_ufs, size_script, err_ufs, err_script],
        ).unwrap();

        conn.execute(SQL_FINALIZACJA_MACIERZY, []).unwrap();

        conn.query_row(
            "SELECT size_match, larger_side, phase2_done FROM files WHERE id = 1",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap()
    }

    #[test]
    fn test_zgodne_rozmiary_daja_dopasowanie_bez_wiekszej_strony() {
        let (zgodnosc, wieksza, gotowe) = finalizuj(true, true, Some(900), Some(900), Some(false), Some(false));
        assert_eq!(zgodnosc, Some(1));
        assert_eq!(wieksza, None, "przy równych rozmiarach żadna strona nie jest większa");
        assert!(gotowe);
    }

    #[test]
    fn test_rozne_rozmiary_wskazuja_wieksza_strone() {
        let (zgodnosc, wieksza, gotowe) = finalizuj(true, true, Some(500), Some(900), Some(false), Some(false));
        assert_eq!(zgodnosc, Some(0));
        assert_eq!(wieksza.as_deref(), Some("SCRIPT"));
        assert!(gotowe);

        let (_, wieksza2, _) = finalizuj(true, true, Some(900), Some(500), Some(false), Some(false));
        assert_eq!(wieksza2.as_deref(), Some("UFS"));
    }

    /// `NULL` znaczy „nie wiem", nie „nie pasuje".
    ///
    /// Po błędzie I/O porównanie jest NIEMOŻLIWE, a nie negatywne. Zlanie tych
    /// dwóch przypadków w `0` kazałoby Fazie 8 uznać kopie za rozbieżne na
    /// podstawie nieodczytanego pliku.
    #[test]
    fn test_blad_io_daje_brak_rozstrzygniecia_a_nie_niezgodnosc() {
        let (zgodnosc, _, gotowe) = finalizuj(true, true, Some(900), Some(900), Some(true), Some(false));
        assert_eq!(zgodnosc, None, "po błędzie I/O porównanie jest niemożliwe");
        assert!(gotowe, "błąd też domyka stronę - plik nie wraca w nieskończoność do kolejki");

        let (zgodnosc2, _, _) = finalizuj(true, true, Some(100), Some(200), Some(false), Some(true));
        assert_eq!(zgodnosc2, None, "błąd po drugiej stronie działa tak samo");
    }

    #[test]
    fn test_plik_tylko_po_jednej_stronie_nie_ma_czego_porownywac() {
        let (zgodnosc, wieksza, gotowe) = finalizuj(true, false, Some(900), None, Some(false), None);
        assert_eq!(zgodnosc, None, "bez drugiej kopii nie ma porównania");
        assert_eq!(wieksza, None, "porównanie z NULL nie wskazuje większej strony");
        assert!(gotowe, "strona nieobecna jest z definicji rozstrzygnięta");
    }

    /// Plik obecny po obu stronach, ale zmierzony tylko po jednej i BEZ błędu,
    /// nie może zostać uznany za zakończony — inaczej brakujący pomiar
    /// przepadłby na zawsze.
    #[test]
    fn test_niedokonczony_pomiar_wraca_do_kolejki() {
        let (_, _, gotowe) = finalizuj(true, true, Some(900), None, Some(false), None);
        assert!(!gotowe, "brak pomiaru po jednej ze stron musi zostawić plik do ponowienia");
    }

    #[test]
    fn test_finalizacja_nie_rusza_wierszy_juz_zakonczonych() {
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, size_ufs, size_script, size_match, phase2_done)
             VALUES (1, 'stary.jpg', 1, 1, 10, 20, 1, 1)",
            [],
        ).unwrap();

        conn.execute(SQL_FINALIZACJA_MACIERZY, []).unwrap();

        let zgodnosc: Option<i64> = conn.query_row("SELECT size_match FROM files WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(
            zgodnosc, Some(1),
            "wiersz z phase2_done = 1 jest poza zakresem zapytania - jego wcześniejszy wynik zostaje nietknięty"
        );
    }

    // ------------------------------------------------------------------
    // Regresja: przerwanie MIĘDZY zapisem rozmiarów a finalizacją macierzy
    // ------------------------------------------------------------------

    /// Odtwarza proces przerwany DOKŁADNIE po zapisaniu rozmiarów obu stron,
    /// ale PRZED finalizacją macierzy: `size_ufs`/`size_script` są już w
    /// bazie, `phase2_done` wciąż 0. Przy kolejnym starcie ETAP 1 (SELECT
    /// zadań) nie znajduje żadnych NOWYCH zadań I/O — `total_db_rows == 0` —
    /// więc przed poprawką `run()` wracał natychmiast i wiersz zostawał
    /// TRWALE z `size_match = NULL`, `phase2_done = 0`.
    ///
    /// Po poprawce finalizacja (`SQL_FINALIZACJA_MACIERZY`) musi się wykonać
    /// także na tej gałęzi, więc wiersz zostaje domknięty już przy tym
    /// (pierwszym po przerwaniu) uruchomieniu.
    #[test]
    fn test_run_finalizuje_macierz_mimo_braku_nowych_zadan_io() {
        let mut conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, size_ufs, size_script, io_error_ufs, io_error_script, phase2_done)
             VALUES (1, 'utkniety.jpg', 1, 1, 500, 500, 0, 0, 0)",
            [],
        ).unwrap();

        let log_dir = tempfile::tempdir().unwrap();
        let mut config = Ustawienia::default();
        config.log_path = log_dir.path().to_string_lossy().to_string();
        config.raporty_faz.clear(); // wymusza gałąź unwrap_or_else -> katalog = log_path (tempdir)
        config.max_threads = 1;

        let (tx_ui, _rx_ui) = mpsc::channel();
        run(&mut conn, &config, tx_ui).expect("run() nie może zwrócić błędu przy pustej liście nowych zadań");

        let (zgodnosc, gotowe): (Option<i64>, bool) = conn.query_row(
            "SELECT size_match, phase2_done FROM files WHERE id = 1",
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();

        assert_eq!(
            zgodnosc, Some(1),
            "finalizacja macierzy musi się wykonać mimo braku nowych zadań I/O w tej sesji"
        );
        assert!(
            gotowe,
            "wiersz nie może zostać trwale utknięty z phase2_done = 0 tylko dlatego, że rozmiary zapisano w poprzedniej sesji"
        );
    }

    /// REGRESJA (measure twice — druga weryfikacja Gemini, todo.faza02.md
    /// obs. 2): wiersz oznaczony jako pusty/błędny w POPRZEDNIEJ sesji
    /// (phase2_done=1 już przed tym `run()`, więc liczniki RAM tej sesji
    /// zostają na zerze - nie ma żadnych nowych zadań I/O) musi mimo to
    /// trafić do sekcji "Puste pliki"/"Trwałe błędy dyskowe" Dziennika
    /// Końcowego, bo ten raport liczy CAŁĄ bazę (`WHERE phase2_done = 1`),
    /// nie tylko bieżącą sesję.
    #[test]
    fn test_dziennik_koncowy_liczy_puste_pliki_i_bledy_z_calej_bazy_nie_tylko_biezacej_sesji() {
        let mut conn = crate::db::init_db(":memory:").unwrap();
        // Dwa wiersze UDAJĄCE stan z POPRZEDNIEJ sesji: już zmierzone/oznaczone
        // jako gotowe (phase2_done=1), więc liczniki RAM (LiveStats) TEJ sesji
        // zostają na zerze dla obu - żaden z nich nie wygeneruje nowego zadania I/O.
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, size_ufs, size_script, io_error_ufs, io_error_script, phase2_done)
             VALUES (1, 'pusty_z_poprzedniej_sesji.jpg', 1, 0, 0, NULL, 0, NULL, 1)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, size_ufs, size_script, io_error_ufs, io_error_script, phase2_done)
             VALUES (2, 'blad_io_z_poprzedniej_sesji.jpg', 0, 1, NULL, NULL, NULL, 1, 1)",
            [],
        ).unwrap();
        // Trzeci wiersz, GENUINE nowe zadanie tej sesji (phase2_done=0, brak
        // zmierzonego rozmiaru) - niezbędny, żeby run() faktycznie doszedł do
        // ETAPU 5 (gałąź `total_db_rows == 0` kończy się wcześniej, bez
        // zapisania Dziennika Końcowego - to inny, celowo odrębny tor).
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, phase2_done)
             VALUES (3, 'nowy.jpg', 1, 0, 0)",
            [],
        ).unwrap();

        let ufs_dir = tempfile::tempdir().unwrap();
        let script_dir = tempfile::tempdir().unwrap();
        fs::write(ufs_dir.path().join("nowy.jpg"), b"tresc").unwrap();

        let log_dir = tempfile::tempdir().unwrap();
        let mut config = Ustawienia::default();
        config.ufs_path = ufs_dir.path().to_string_lossy().to_string();
        config.script_path = script_dir.path().to_string_lossy().to_string();
        config.log_path = log_dir.path().to_string_lossy().to_string();
        config.raporty_faz.clear();
        config.max_threads = 1;

        let (tx_ui, _rx_ui) = mpsc::channel();
        run(&mut conn, &config, tx_ui).expect("run() musi wygenerować Dziennik Końcowy");

        let dziennik = std::fs::read_to_string(log_dir.path().join("dziennik_koncowy_faza2.txt"))
            .expect("Dziennik Końcowy musi powstać nawet bez nowych zadań tej sesji");

        assert!(
            dziennik.contains("Puste pliki (Wydmuszki 0 B): 1 (UFS: 1, Skrypt: 0)"),
            "raport musi zliczyć pusty plik zapisany w POPRZEDNIEJ sesji, nie tylko bieżącej (RAM=0):\n{}", dziennik
        );
        assert!(
            dziennik.contains("Trwałe błędy dyskowe (I/O):  1"),
            "raport musi zliczyć błąd I/O zapisany w POPRZEDNIEJ sesji, nie tylko bieżącej (RAM=0):\n{}", dziennik
        );
    }

    /// REGRESJA (todo.faza02.md — sekcja [2] pokazywała tylko LICZBĘ plików
    /// unikalnych dla jednej strony, bez ich wolumenu w bajtach, w
    /// przeciwieństwie do sekcji [1]). Dziennik musi teraz wprost podawać
    /// wolumen osobno dla plików unikalnych UFS i osobno dla Skryptu.
    #[test]
    fn test_dziennik_koncowy_pokazuje_wolumen_plikow_unikalnych() {
        let mut conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, size_ufs, phase2_done)
             VALUES (1, 'tylko_ufs.bin', 1, 0, 5000, 1)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, size_script, phase2_done)
             VALUES (2, 'tylko_skrypt.bin', 0, 1, 3000, 1)",
            [],
        ).unwrap();
        // Trzeci wiersz, genuine nowe zadanie — inaczej run() kończy się
        // wcześniej w gałęzi `total_db_rows == 0`, bez zapisania Dziennika.
        // Obecny po OBU stronach (found_in_ufs=1, found_in_script=1) - musi
        // wylądować w [1] CZĘŚĆ WSPÓLNA, nie zanieczyścić liczonych tu
        // wolumenów [2] UNIKALNE TRAFIENIA.
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, phase2_done)
             VALUES (3, 'nowy.jpg', 1, 1, 0)",
            [],
        ).unwrap();

        let ufs_dir = tempfile::tempdir().unwrap();
        let script_dir = tempfile::tempdir().unwrap();
        fs::write(ufs_dir.path().join("nowy.jpg"), b"tresc").unwrap();
        fs::write(script_dir.path().join("nowy.jpg"), b"tresc").unwrap();

        let log_dir = tempfile::tempdir().unwrap();
        let mut config = Ustawienia::default();
        config.ufs_path = ufs_dir.path().to_string_lossy().to_string();
        config.script_path = script_dir.path().to_string_lossy().to_string();
        config.log_path = log_dir.path().to_string_lossy().to_string();
        config.raporty_faz.clear();
        config.max_threads = 1;

        let (tx_ui, _rx_ui) = mpsc::channel();
        run(&mut conn, &config, tx_ui).expect("run() musi wygenerować Dziennik Końcowy");

        let dziennik = std::fs::read_to_string(log_dir.path().join("dziennik_koncowy_faza2.txt")).unwrap();

        assert!(
            dziennik.contains(&format!("Tylko w UFS Explorer:       1 (Wolumen: {})", format_bytes(5000))),
            "brak wolumenu plików unikalnych UFS w raporcie:\n{}", dziennik
        );
        assert!(
            dziennik.contains(&format!("Tylko w Skrypcie Autorskim: 1 (Wolumen: {})", format_bytes(3000))),
            "brak wolumenu plików unikalnych Skryptu w raporcie:\n{}", dziennik
        );
    }
}
