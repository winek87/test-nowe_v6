// src/phases/phase1.rs

//! # Faza 1: Mapowanie Struktury Katalogów i Akwizycja Ścieżek
//!
//! Zbudowanie "płaskiej mapy" odzyskanych danych w sposób inkrementalny.
//! Hybrydowe podejście: wykrywa "Sieroty" (pliki z uszkodzonym drzewem katalogów)
//! i izoluje je w bazie danych. Komunikuje się z interfejsem Ratatui poprzez PhaseEvent.
//! Wykorzystuje system Dual-Logging (Raport Operacyjny + Dziennik Końcowy).
//!
//! UWAGA ARCHITEKTONICZNA:
//! - Rozmiary plików NIE są tu liczone (celowo) — to wyłączna odpowiedzialność Fazy 2.
//! - Statystyki per-rozszerzenie (wagi) również NIE są tu liczone — Faza 2.
//! - Panel boczny: statystyki są ROZDZIELONE per skaner (UFS vs Skrypt), a nie
//!   sumowane — inaczej niż w Fazie 3. Każde źródło ma własny, pełny blok
//!   (Pre-Skan + Akwizycja), bo operator chce widzieć wydajność KONKRETNEGO
//!   silnika odzysku, a nie sumę zbiorczą.
//!
//! OBSŁUGA BŁĘDÓW: oba SELECT-y w [`run`] używają `collect::<Result<Vec<_>>>()?`.
//! Wątki pre-skanu i zapisu DB są obsługiwane gracefulnie. Finalne liczniki z
//! bazy logują błąd zamiast cicho zwracać `0`.
//!
//! ANULOWANIE: [`CANCEL_SIGNAL`] sprawdzany jest w pre-skanie, w akwizycji,
//! i **po** akwizycji (przed raportem końcowym).

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::{CANCEL_SIGNAL, format_display_path};
use jwalk::{Parallelism, WalkDir};
use ratatui::style::Color;
use rusqlite::{Connection, Result, params};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;
use tracing::info;

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use sysinfo::{DiskKind, Disks};

const CHUNK_SIZE: usize = 200;

const INSERT_SQL_UFS: &str = "
    INSERT INTO files (relative_path, found_in_ufs, found_in_script, phase1_done, is_orphan)
    VALUES (?1, 1, 0, 1, ?2)
    ON CONFLICT(relative_path) DO UPDATE SET found_in_ufs = 1, phase1_done = 1, is_orphan = ?2,
        phase2_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase2_done END,
        phase3_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase3_done END,
        phase4_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase4_done END,
        phase5_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase5_done END,
        phase6_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase6_done END,
        phase7_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase7_done END,
        phase8_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase8_done END,
        phase9_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase9_done END,
        phase10_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase10_done END,
        phase11_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase11_done END,
        phase12_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase12_done END,
        phase13_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase13_done END,
        phase14_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase14_done END,
        phase15_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase15_done END,
        phase16_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase16_done END,
        phase17_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase17_done END,
        phase18_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase18_done END,
        phase19_done = CASE WHEN found_in_ufs = 0 THEN 0 ELSE phase19_done END
";

const INSERT_SQL_SCRIPT: &str = "
    INSERT INTO files (relative_path, found_in_ufs, found_in_script, phase1_done, is_orphan)
    VALUES (?1, 0, 1, 1, ?2)
    ON CONFLICT(relative_path) DO UPDATE SET found_in_script = 1, phase1_done = 1, is_orphan = ?2,
        phase2_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase2_done END,
        phase3_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase3_done END,
        phase4_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase4_done END,
        phase5_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase5_done END,
        phase6_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase6_done END,
        phase7_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase7_done END,
        phase8_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase8_done END,
        phase9_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase9_done END,
        phase10_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase10_done END,
        phase11_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase11_done END,
        phase12_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase12_done END,
        phase13_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase13_done END,
        phase14_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase14_done END,
        phase15_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase15_done END,
        phase16_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase16_done END,
        phase17_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase17_done END,
        phase18_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase18_done END,
        phase19_done = CASE WHEN found_in_script = 0 THEN 0 ELSE phase19_done END
";

pub(crate) enum ScanMsg {
    UfsChunk(Vec<(String, String, bool)>),
    ScriptChunk(Vec<(String, String, bool)>),
    UfsSkipped(usize),
    ScriptSkipped(usize),
}

// ============================================================================
// LICZNIKI LIVE — ROZDZIELONE PER SKANER
// ============================================================================

/// Liczniki Etapu 2 (Pre-Skan) i Etapu 3 (Akwizycja) dla JEDNEGO źródła.
struct SourceStats {
    scanned: AtomicU64,
    new_files: AtomicU64,
    db_count: AtomicU64,
    orphans: AtomicU64,
}

impl SourceStats {
    fn new() -> Self {
        Self {
            scanned: AtomicU64::new(0),
            new_files: AtomicU64::new(0),
            db_count: AtomicU64::new(0),
            orphans: AtomicU64::new(0),
        }
    }

    fn build_block(&self, label: &str) -> String {
        format!(
            "[{}]\n🔎 Przeskanowano: {}\n🆕 Nowych plików: {}\n📥 Zapisano do bazy: {}\n🛡️ Sieroty: {}",
            label,
            self.scanned.load(Ordering::Relaxed),
            self.new_files.load(Ordering::Relaxed),
            self.db_count.load(Ordering::Relaxed),
            self.orphans.load(Ordering::Relaxed),
        )
    }
}

fn build_sqlite_sync_block(ufs_inserted: usize, script_inserted: usize) -> String {
    format!(
        "[Synchronizacja SQLite]\nUFS Explorer: {}\nSkrypt Autorski: {}",
        ufs_inserted, script_inserted
    )
}

// ============================================================================
// POMOCNIKI
// ============================================================================

fn is_orphan_path(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("$tresh")
        || p.contains("$trash")
        || p.contains("lostfiles")
        || p.contains("$recycle.bin")
}

fn hash_path(path: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn sanitize_relative_path(rel: &Path) -> String {
    let raw = rel.as_os_str();
    match raw.to_str() {
        Some(s) => s.to_string(),
        None => {
            let lossy = raw.to_string_lossy().into_owned();
            let hash = fnv1a_64(raw.as_encoded_bytes());
            format!("{}__nieutf8_{:016x}", lossy, hash)
        }
    }
}

fn is_hdd(path: &Path) -> bool {
    let disks = Disks::new_with_refreshed_list();
    let mut matched_disk = None;
    let mut max_len = 0;

    for disk in disks.list() {
        if path.starts_with(disk.mount_point()) {
            let len = disk.mount_point().as_os_str().len();
            if len > max_len {
                max_len = len;
                matched_disk = Some(disk);
            }
        }
    }
    if let Some(disk) = matched_disk {
        return disk.kind() == DiskKind::HDD;
    }
    false
}

// ============================================================================
// KONTEKSTY
// ============================================================================

struct PreScanCtx<'a> {
    base_path: &'a Path,
    label: &'a str,
    known_hashes: &'a HashSet<u64>,
    parallelism: Parallelism,
    io_counter: &'a AtomicUsize,
    tx_ui: &'a mpsc::Sender<PhaseEvent>,
    panel_idx: usize,
    stats: &'a SourceStats,
}

struct StreamCtx<'a> {
    base_path: &'a Path,
    known_hashes: &'a HashSet<u64>,
    parallelism: Parallelism,
    tx_db: mpsc::SyncSender<ScanMsg>,
    is_ufs: bool,
    tx_ui: &'a mpsc::Sender<PhaseEvent>,
    bar_idx: usize,
    io_counter: &'a AtomicUsize,
    opr_log: Arc<Mutex<File>>,
    stats: &'a SourceStats,
}

// ============================================================================
// LOGIKA BIZNESOWA
// ============================================================================

fn pre_scan_directory(ctx: PreScanCtx<'_>) -> u64 {
    let PreScanCtx { base_path, label, known_hashes, parallelism, io_counter, tx_ui, panel_idx, stats } = ctx;

    if !base_path.exists() {
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "BŁĄD: Ścieżka bazowa '{}' nie istnieje!",
            label
        )));
        return 0;
    }

    let _ = tx_ui.send(PhaseEvent::Log(format!(
        "Rozpoczynam Pre-Skanowanie dysku: {}...",
        label
    )));

    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
        idx: panel_idx,
        text: stats.build_block(label),
    });

    let mut new_files: u64 = 0;
    let mut already_known: u64 = 0;
    let mut total_scanned: u64 = 0;
    let mut last_ui_update = Instant::now();

    for entry in WalkDir::new(base_path)
        .parallelism(parallelism)
        .skip_hidden(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) {
            break;
        }

        io_counter.fetch_add(1, Ordering::Relaxed);
        total_scanned += 1;

        if entry.file_type().is_file() {
            let path = entry.path();

            if let Ok(rel) = path.strip_prefix(base_path) {
                let rel_str = sanitize_relative_path(rel);
                let path_hash = hash_path(&rel_str);

                if known_hashes.contains(&path_hash) {
                    already_known += 1;
                } else {
                    new_files += 1;
                }

                stats.scanned.store(total_scanned, Ordering::Relaxed);
                stats.new_files.store(new_files, Ordering::Relaxed);

                let now = Instant::now();
                if now.duration_since(last_ui_update).as_millis() > 150 {
                    last_ui_update = now;
                    let display_path = format_display_path(&path.to_string_lossy());

                    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                        idx: panel_idx,
                        text: stats.build_block(label),
                    });
                    let _ = tx_ui.send(PhaseEvent::UpdateBottomPath {
                        idx: panel_idx,
                        path: display_path,
                    });
                }
            }
        }
    }

    stats.scanned.store(total_scanned, Ordering::Relaxed);
    stats.new_files.store(new_files, Ordering::Relaxed);
    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
        idx: panel_idx,
        text: stats.build_block(label),
    });

    let _ = tx_ui.send(PhaseEvent::Log(format!(
        "✔ Pre-Skanowanie '{}' zakończone.",
        label
    )));
    let _ = tx_ui.send(PhaseEvent::Log(format!(
        "  -> Znaleziono nowych plików: {}",
        new_files
    )));
    let _ = tx_ui.send(PhaseEvent::Log(format!(
        "  -> Ponowne skanowanie (pominięto): {}",
        already_known
    )));

    new_files
}

fn scan_directory_stream(ctx: StreamCtx<'_>) -> (usize, usize) {
    let StreamCtx { base_path, known_hashes, parallelism, tx_db, is_ufs, tx_ui, bar_idx, io_counter, opr_log, stats } = ctx;

    if !base_path.exists() {
        return (0, 0);
    }

    let side_label = if is_ufs { "UFS Explorer" } else { "Skrypt Autorski" };
    let mut buffer = Vec::with_capacity(CHUNK_SIZE);
    let mut skipped = 0;
    let mut scanned_count = 0;
    let mut orphans_count = 0;

    let mut last_ui_update = Instant::now();

    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
        idx: bar_idx,
        text: stats.build_block(side_label),
    });

    for entry_result in WalkDir::new(base_path)
        .parallelism(parallelism)
        .skip_hidden(false)
    {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) {
            break;
        }

        io_counter.fetch_add(1, Ordering::Relaxed);

        match entry_result {
            Ok(entry) => {
                if entry.file_type().is_file() {
                    let path = entry.path();
                    if let Ok(rel) = path.strip_prefix(base_path) {
                        let rel_str = sanitize_relative_path(rel);
                        let path_hash = hash_path(&rel_str);

                        if !known_hashes.contains(&path_hash) {
                            scanned_count += 1;
                            let is_orphan = is_orphan_path(&rel_str);

                            if is_orphan {
                                orphans_count += 1;
                                if let Ok(mut f) = opr_log.lock() {
                                    let _ = writeln!(
                                        f,
                                        "[{}] Odizolowano sierotę FS: {}",
                                        side_label, rel_str
                                    );
                                }
                            }

                            stats.db_count.store(scanned_count as u64, Ordering::Relaxed);
                            stats.orphans.store(orphans_count as u64, Ordering::Relaxed);

                            let now = Instant::now();
                            if now.duration_since(last_ui_update).as_millis() > 60 {
                                last_ui_update = now;

                                let display_path = format_display_path(&rel_str);

                                let _ = tx_ui.send(PhaseEvent::UpdateBar {
                                    idx: bar_idx,
                                    current: scanned_count as u64,
                                    message: "Akwizycja do bazy...".to_string(),
                                });
                                let _ = tx_ui.send(PhaseEvent::UpdateBottomPath {
                                    idx: bar_idx,
                                    path: display_path,
                                });
                                let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                                    idx: bar_idx,
                                    text: stats.build_block(side_label),
                                });
                            }

                            buffer.push((rel_str, is_orphan));

                            if buffer.len() >= CHUNK_SIZE {
                                let chunk =
                                    std::mem::replace(&mut buffer, Vec::with_capacity(CHUNK_SIZE));
                                if is_ufs {
                                    let _ = tx_db.send(ScanMsg::UfsChunk(
                                        chunk.into_iter().map(|(r, o)| (r, String::new(), o)).collect(),
                                    ));
                                } else {
                                    let _ = tx_db.send(ScanMsg::ScriptChunk(
                                        chunk.into_iter().map(|(r, o)| (r, String::new(), o)).collect(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => skipped += 1,
        }
    }

    if !buffer.is_empty() {
        let final_chunk: Vec<(String, String, bool)> = buffer
            .into_iter()
            .map(|(r, o)| (r, String::new(), o))
            .collect();
        if is_ufs {
            let _ = tx_db.send(ScanMsg::UfsChunk(final_chunk));
        } else {
            let _ = tx_db.send(ScanMsg::ScriptChunk(final_chunk));
        }
    }

    if is_ufs {
        let _ = tx_db.send(ScanMsg::UfsSkipped(skipped));
    } else {
        let _ = tx_db.send(ScanMsg::ScriptSkipped(skipped));
    }

    let anulowano = CANCEL_SIGNAL.load(Ordering::SeqCst);
    let wiadomosc = if anulowano {
        format!("🛑 Przerwano — przeskanowano {} plików.", scanned_count)
    } else {
        "Zakończono odczyt I/O dysku.".to_string()
    };
    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: scanned_count as u64,
        message: wiadomosc,
    });

    (scanned_count, orphans_count)
}

// ============================================================================
// GŁÓWNA FUNKCJA KORDYNUJĄCA FAZĘ
// ============================================================================

pub fn run(
    conn: &mut Connection,
    config: &Ustawienia,
    tx_ui: mpsc::Sender<PhaseEvent>,
) -> Result<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    let _ = conn.execute(
        "ALTER TABLE files ADD COLUMN is_orphan BOOLEAN DEFAULT 0",
        [],
    );

    let raport_cfg = config
        .raporty_faz
        .get("Faza 1")
        .cloned()
        .unwrap_or_else(|| crate::settings::RaportFazy {
            katalog: config.log_path.clone(),
            plik_operacyjny: "raport_operacyjny_faza1.txt".to_string(),
            plik_dziennika: "dziennik_koncowy_faza1.txt".to_string(),
        });

    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    // Wszystkie pliki tego przebiegu fazy niosą ten sam znacznik czasu, więc
    // łatwo je ze sobą powiązać na dysku, a kolejne uruchomienia się nie
    // nadpisują.
    let stamp = crate::utils::run_timestamp();
    let opr_path = Path::new(&raport_cfg.katalog)
        .join(crate::utils::stamp_filename(&raport_cfg.plik_operacyjny, &stamp));
    let dz_path = Path::new(&raport_cfg.katalog)
        .join(crate::utils::stamp_filename(&raport_cfg.plik_dziennika, &stamp));

    let opr_log_file = match File::create(&opr_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!(
                "BŁĄD I/O: Nie można utworzyć pliku logu operacyjnego: {}. Sprawdź uprawnienia.",
                e
            )));
            return Ok(());
        }
    };
    let opr_log = Arc::new(Mutex::new(opr_log_file));

    {
        let _ = writeln!(
            opr_log.lock().unwrap_or_else(|e| e.into_inner()),
            "=== RAPORT OPERACYJNY - FAZA 1 (MAPOWANIE) ==="
        );
        let _ = writeln!(
            opr_log.lock().unwrap_or_else(|e| e.into_inner()),
            "Zawiera ścieżki plików zidentyfikowanych jako 'Sieroty' w folderach $Tresh / LostFiles.\n"
        );
    }

    let ufs_p = Path::new(&config.ufs_path);
    let script_p = Path::new(&config.script_path);

    let mut active_io_mode = config.io_mode.clone();
    if is_hdd(ufs_p) || is_hdd(script_p) {
        active_io_mode = "SEQUENTIAL".to_string();
        let _ = tx_ui.send(PhaseEvent::Log("⚠️ WYKRYTO DYSK TALERZOWY (HDD)! Automatycznie wymuszono tryb SEKWENCYJNY dla skanowania wstępnego".to_string()));
    } else {
        let io_text = if active_io_mode == "CONCURRENT" {
            "RÓWNOLEGŁE (SSD/NVMe)"
        } else {
            "SEKWENCYJNE (HDD)"
        };
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "Uruchomiono Fazę 1. Metodyka szyny dyskowej: {}",
            io_text
        )));
    }

    let actual_threads = if config.max_threads > 0 {
        config.max_threads
    } else {
        rayon::current_num_threads()
    };
    let _ = tx_ui.send(PhaseEvent::Log(format!(
        "Aktywne wątki procesora (Rayon): {}",
        actual_threads
    )));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    let global_io_counter = AtomicUsize::new(0);
    let io_counter_ref = &global_io_counter;

    let mut known_ufs: HashSet<u64> = HashSet::new();
    let mut known_script: HashSet<u64> = HashSet::new();
    {
        let mut stmt = conn.prepare(
            "SELECT relative_path, found_in_ufs, found_in_script FROM files WHERE phase1_done = 1",
        )?;
        let rows: Vec<(String, bool, bool)> = stmt
            .query_map([], |row| {
                let path: String = row.get(0)?;
                let ufs: bool = row.get(1)?;
                let script: bool = row.get(2)?;
                Ok((path, ufs, script))
            })?
            .collect::<Result<Vec<_>>>()?;

        for (path, ufs, script) in rows {
            let path_hash = hash_path(&path);
            if ufs {
                known_ufs.insert(path_hash);
            }
            if script {
                known_script.insert(path_hash);
            }
        }
    }

    if !known_ufs.is_empty() || !known_script.is_empty() {
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "Odczytano z bazy danych ubiegłe pliki. UFS Explorer: {}, Skrypt Autorski: {}",
            known_ufs.len(),
            known_script.len()
        )));
    }

    let parallelism = if config.max_threads > 0 {
        Parallelism::RayonNewPool(config.max_threads)
    } else {
        Parallelism::RayonDefaultPool {
            busy_timeout: std::time::Duration::from_secs(1),
        }
    };

    let known_ufs_ref = &known_ufs;
    let known_script_ref = &known_script;
    let tx_ui_ref = &tx_ui;

    let mut new_ufs_count = 0;
    let mut new_script_count = 0;

    let ufs_stats = SourceStats::new();
    let script_stats = SourceStats::new();

    // `&T: Copy`, więc `move` na tych referencjach KOPIUJE je zamiast
    // przenosić `SourceStats` (fix E0382).
    let ufs_stats_ref = &ufs_stats;
    let script_stats_ref = &script_stats;

    if active_io_mode == "CONCURRENT" {
        let p1 = parallelism.clone();
        let p2 = parallelism.clone();

        std::thread::scope(|s| {
            let ufs_thread = s.spawn(move || {
                pre_scan_directory(PreScanCtx {
                    base_path: ufs_p,
                    label: "UFS Explorer",
                    known_hashes: known_ufs_ref,
                    parallelism: p1,
                    io_counter: io_counter_ref,
                    tx_ui: tx_ui_ref,
                    panel_idx: 0,
                    stats: ufs_stats_ref,
                })
            });
            let script_thread = s.spawn(move || {
                pre_scan_directory(PreScanCtx {
                    base_path: script_p,
                    label: "Skrypt Autorski",
                    known_hashes: known_script_ref,
                    parallelism: p2,
                    io_counter: io_counter_ref,
                    tx_ui: tx_ui_ref,
                    panel_idx: 1,
                    stats: script_stats_ref,
                })
            });

            new_ufs_count = match ufs_thread.join() {
                Ok(n) => n,
                Err(_) => {
                    let _ = tx_ui_ref.send(PhaseEvent::Log(
                        "⚠️ Pre-skan UFS Explorer zakończył się paniką — pomijam akwizycję tej strony.".to_string()
                    ));
                    0
                }
            };
            new_script_count = match script_thread.join() {
                Ok(n) => n,
                Err(_) => {
                    let _ = tx_ui_ref.send(PhaseEvent::Log(
                        "⚠️ Pre-skan Skrypt Autorski zakończył się paniką — pomijam akwizycję tej strony.".to_string()
                    ));
                    0
                }
            };
        });
    } else {
        let p_seq = Parallelism::Serial;
        new_ufs_count = pre_scan_directory(PreScanCtx {
            base_path: ufs_p,
            label: "UFS Explorer",
            known_hashes: known_ufs_ref,
            parallelism: p_seq.clone(),
            io_counter: io_counter_ref,
            tx_ui: tx_ui_ref,
            panel_idx: 0,
            stats: ufs_stats_ref,
        });
        new_script_count = pre_scan_directory(PreScanCtx {
            base_path: script_p,
            label: "Skrypt Autorski",
            known_hashes: known_script_ref,
            parallelism: p_seq,
            io_counter: io_counter_ref,
            tx_ui: tx_ui_ref,
            panel_idx: 1,
            stats: script_stats_ref,
        });
    }

    let total_new = new_ufs_count + new_script_count;

    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log(
            "🛑 Skanowanie przerwane przez użytkownika.".to_string(),
        ));
        return Ok(());
    }

    if total_new == 0 {
        let _ = tx_ui.send(PhaseEvent::Log(
            "✔ Brak nowych plików do wgrania. Baza jest w pełni aktualna. Zamykam status fazy..."
                .to_string(),
        ));
    }

    let _ = tx_ui.send(PhaseEvent::SetBar {
        idx: 0,
        label: "UFS Explorer".to_string(),
        total: new_ufs_count,
        color: Color::Cyan,
    });
    let _ = tx_ui.send(PhaseEvent::SetBar {
        idx: 1,
        label: "Skrypt Autorski".to_string(),
        total: new_script_count,
        color: Color::Magenta,
    });
    let _ = tx_ui.send(PhaseEvent::SetBar {
        idx: 2,
        label: "Zapis SQLite".to_string(),
        total: total_new,
        color: Color::Green,
    });

    let mut total_ufs_orphans = 0;
    let mut total_script_orphans = 0;
    let mut ufs_skipped = 0;
    let mut script_skipped = 0;
    let mut ufs_inserted = 0;
    let mut script_inserted = 0;

    let wynik_zapisu: Result<()> = std::thread::scope(|s| {
        let (tx_db, rx_db) = mpsc::sync_channel(200);

        let conn_ref = &mut *conn;
        let ufs_ins_ref = &mut ufs_inserted;
        let script_ins_ref = &mut script_inserted;
        let ufs_skip_ref = &mut ufs_skipped;
        let script_skip_ref = &mut script_skipped;

        let db_thread = s.spawn(move || -> Result<()> {
            let mut last_db_update = Instant::now();

            for msg in rx_db {
                let chunk_len = match &msg {
                    ScanMsg::UfsChunk(c) => c.len(),
                    ScanMsg::ScriptChunk(c) => c.len(),
                    _ => 0,
                };

                if chunk_len > 0 {
                    let tx_trans = conn_ref.transaction()?;
                    {
                        let mut stmt = match &msg {
                            ScanMsg::UfsChunk(_) => tx_trans.prepare_cached(INSERT_SQL_UFS)?,
                            ScanMsg::ScriptChunk(_) => tx_trans.prepare_cached(INSERT_SQL_SCRIPT)?,
                            _ => unreachable!(),
                        };

                        let chunk = match &msg {
                            ScanMsg::UfsChunk(c) => c,
                            ScanMsg::ScriptChunk(c) => c,
                            _ => unreachable!(),
                        };

                        for (rel, _, is_orphan) in chunk {
                            stmt.execute(params![rel, is_orphan])?;
                        }
                    }
                    tx_trans.commit()?;
                }

                match msg {
                    ScanMsg::UfsChunk(chunk) => {
                        *ufs_ins_ref += chunk.len();
                    }
                    ScanMsg::ScriptChunk(chunk) => {
                        *script_ins_ref += chunk.len();
                    }
                    ScanMsg::UfsSkipped(count) => *ufs_skip_ref = count,
                    ScanMsg::ScriptSkipped(count) => *script_skip_ref = count,
                }

                let now = Instant::now();
                if now.duration_since(last_db_update).as_millis() > 60 {
                    last_db_update = now;
                    let total_saved = *ufs_ins_ref + *script_ins_ref;
                    let _ = tx_ui_ref.send(PhaseEvent::UpdateBar {
                        idx: 2,
                        current: total_saved as u64,
                        message: "Zapis rekordów do bazy...".to_string(),
                    });
                    let _ = tx_ui_ref.send(PhaseEvent::UpdateSideText {
                        idx: 2,
                        text: build_sqlite_sync_block(*ufs_ins_ref, *script_ins_ref),
                    });
                }
            }

            let total_saved = *ufs_ins_ref + *script_ins_ref;
            let _ = tx_ui_ref.send(PhaseEvent::UpdateBar {
                idx: 2,
                current: total_saved as u64,
                message: "Baza danych zsynchronizowana.".to_string(),
            });
            let _ = tx_ui_ref.send(PhaseEvent::UpdateSideText {
                idx: 2,
                text: build_sqlite_sync_block(*ufs_ins_ref, *script_ins_ref),
            });
            Ok(())
        });

        if active_io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone();
            let tx2 = tx_db.clone();
            let p1 = parallelism.clone();
            let p2 = parallelism.clone();

            let ufs_orph_ref = &mut total_ufs_orphans;
            let scr_orph_ref = &mut total_script_orphans;

            let log_u = opr_log.clone();
            let log_s = opr_log.clone();

            s.spawn(move || {
                if new_ufs_count > 0 {
                    let (cnt, orph) = scan_directory_stream(StreamCtx {
                        base_path: ufs_p,
                        known_hashes: known_ufs_ref,
                        parallelism: p1,
                        tx_db: tx1,
                        is_ufs: true,
                        tx_ui: tx_ui_ref,
                        bar_idx: 0,
                        io_counter: io_counter_ref,
                        opr_log: log_u,
                        stats: ufs_stats_ref,
                    });
                    *ufs_orph_ref = orph;
                    let _ = tx_ui_ref.send(PhaseEvent::Log(format!(
                        "✔ Zakończono odczyt I/O na UFS Explorer ({} plików)",
                        cnt
                    )));
                }
            });

            s.spawn(move || {
                if new_script_count > 0 {
                    let (cnt, orph) = scan_directory_stream(StreamCtx {
                        base_path: script_p,
                        known_hashes: known_script_ref,
                        parallelism: p2,
                        tx_db: tx2,
                        is_ufs: false,
                        tx_ui: tx_ui_ref,
                        bar_idx: 1,
                        io_counter: io_counter_ref,
                        opr_log: log_s,
                        stats: script_stats_ref,
                    });
                    *scr_orph_ref = orph;
                    let _ = tx_ui_ref.send(PhaseEvent::Log(format!(
                        "✔ Zakończono odczyt I/O na Skrypt Autorski ({} plików)",
                        cnt
                    )));
                }
            });
            drop(tx_db);
        } else {
            let p_seq = Parallelism::Serial;

            if new_ufs_count > 0 {
                let (cnt, orph) = scan_directory_stream(StreamCtx {
                    base_path: ufs_p,
                    known_hashes: known_ufs_ref,
                    parallelism: p_seq.clone(),
                    tx_db: tx_db.clone(),
                    is_ufs: true,
                    tx_ui: tx_ui_ref,
                    bar_idx: 0,
                    io_counter: io_counter_ref,
                    opr_log: opr_log.clone(),
                    stats: ufs_stats_ref,
                });
                total_ufs_orphans = orph;
                let _ = tx_ui_ref.send(PhaseEvent::Log(format!(
                    "✔ Zakończono odczyt I/O na UFS Explorer ({} plików)",
                    cnt
                )));
            }

            if new_script_count > 0 {
                let (cnt, orph) = scan_directory_stream(StreamCtx {
                    base_path: script_p,
                    known_hashes: known_script_ref,
                    parallelism: p_seq,
                    tx_db: tx_db.clone(),
                    is_ufs: false,
                    tx_ui: tx_ui_ref,
                    bar_idx: 1,
                    io_counter: io_counter_ref,
                    opr_log: opr_log.clone(),
                    stats: script_stats_ref,
                });
                total_script_orphans = orph;
                let _ = tx_ui_ref.send(PhaseEvent::Log(format!(
                    "✔ Zakończono odczyt I/O na Skrypt Autorski ({} plików)",
                    cnt
                )));
            }
            // Jawny `drop(tx_db)` zamyka kanał deterministycznie, zanim
            // `db_thread.join()` zacznie czekać.
            drop(tx_db);
        }

        match db_thread.join() {
            Ok(wynik) => wynik,
            Err(_) => {
                let _ = tx_ui.send(PhaseEvent::Log(
                    "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 1 mógł nie zostać w pełni zapisany.".to_string()
                ));
                Err(rusqlite::Error::UnwindingPanic)
            }
        }
    });
    wynik_zapisu?;

    // REGRESJA: bez tego sprawdzenia po anulowaniu faza i tak generowała
    // pełny raport końcowy — myląco wyglądający jak kompletny przebieg.
    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log(
            "🛑 Akwizycja przerwana przez użytkownika. Postęp w bazie został zapisany.".to_string(),
        ));
        return Ok(());
    }

    // ETAP 4: DZIENNIK KOŃCOWY
    let final_ufs: usize = conn
        .query_row(
            "SELECT COUNT(*) FROM files WHERE found_in_ufs = 1",
            [],
            |r| Ok(r.get::<_, i64>(0)? as usize),
        )
        .unwrap_or_else(|e| {
            let _ = tx_ui.send(PhaseEvent::Log(format!(
                "⚠️ Nie udało się policzyć plików UFS w raporcie końcowym: {}",
                e
            )));
            0
        });
    let final_script: usize = conn
        .query_row(
            "SELECT COUNT(*) FROM files WHERE found_in_script = 1",
            [],
            |r| Ok(r.get::<_, i64>(0)? as usize),
        )
        .unwrap_or_else(|e| {
            let _ = tx_ui.send(PhaseEvent::Log(format!(
                "⚠️ Nie udało się policzyć plików Skryptu w raporcie końcowym: {}",
                e
            )));
            0
        });
    let total_io = global_io_counter.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed();

    let mut final_report = String::new();
    use std::fmt::Write as FmtWrite;
    let _ = writeln!(
        &mut final_report,
        "=========================================================================="
    );
    let _ = writeln!(
        &mut final_report,
        "DZIENNIK KOŃCOWY - FAZA 1 (MAPOWANIE I IZOLACJA SIEROT)"
    );
    let _ = writeln!(&mut final_report, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(
        &mut final_report,
        "==========================================================================\n"
    );

    let _ = writeln!(&mut final_report, " [ + ] ZMAPOWANE DRZEWO (Czyste pliki):");
    let _ = writeln!(
        &mut final_report,
        "   -> UFS Explorer:    {} plików",
        final_ufs
    );
    let _ = writeln!(
        &mut final_report,
        "   -> Skrypt Autorski: {} plików\n",
        final_script
    );

    if total_ufs_orphans > 0 || total_script_orphans > 0 {
        let _ = writeln!(
            &mut final_report,
            " [ ! ] KWARANTANNA SIEROT (Izolacja sztucznych folderów):"
        );
        let _ = writeln!(
            &mut final_report,
            "   -> Odizolowano w UFS Explorer:    {}",
            total_ufs_orphans
        );
        let _ = writeln!(
            &mut final_report,
            "   -> Odizolowano w Skrypt Autorski: {}",
            total_script_orphans
        );
        let _ = writeln!(
            &mut final_report,
            "      (ZNACZENIE): Pliki te znajdowały się w fałszywych folderach ($Tresh, LostFiles). Dodano flagę 'is_orphan=1'.\n"
        );
    }

    let _ = writeln!(&mut final_report, " [ * ] DIAGNOSTYKA SYSTEMU I/O:");
    let _ = writeln!(
        &mut final_report,
        "   -> Przeanalizowane węzły FS: {}",
        total_io
    );
    let _ = writeln!(
        &mut final_report,
        "      (ZNACZENIE): Całkowita liczba plików i folderów fizycznie sprawdzona przez silnik podczas tej sesji.\n"
    );

    if ufs_skipped > 0 || script_skipped > 0 {
        let _ = writeln!(
            &mut final_report,
            " [ - ] ODRZUTY (Błędy Systemowe i Odmowy Dostępu):"
        );
        let _ = writeln!(
            &mut final_report,
            "   -> UFS Explorer: {} | Skrypt Autorski: {}",
            ufs_skipped, script_skipped
        );
        let _ = writeln!(
            &mut final_report,
            "      (ZNACZENIE): Pliki zablokowane przez system, porzucone ze względów wydajnościowych."
        );
    }

    if let Ok(mut f) = fs::File::create(&dz_path) {
        let _ = f.write_all(final_report.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "✔ Zapisano fizyczny Dziennik Końcowy w: {}",
            dz_path.display()
        )));
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "✔ Zapisano Raport Operacyjny (Live) w: {}",
            opr_path.display()
        )));
    }

    for line in final_report.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    info!(
        ufs_inserted = final_ufs,
        script_inserted = final_script,
        orphans_found = total_ufs_orphans + total_script_orphans,
        total_io_nodes = total_io,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 1 zakończona sukcesem"
    );

    Ok(())
}

// ============================================================================
// GLOBALNY MUTEKS TESTOWY — wspólny dla `mod tests` i `mod integration_tests`
// ============================================================================

#[cfg(test)]
pub(crate) mod test_lock {
    use std::sync::Mutex;

    /// Serializuje **wszystkie** testy dotykające `CANCEL_SIGNAL` albo
    /// wołające funkcje, które go CZYTAJĄ w pętli
    /// (`pre_scan_directory`, `scan_directory_stream`, `run`).
    ///
    /// Bez tego cargo test uruchamia je równolegle w wielu wątkach i test
    /// anulowania (`test_run_honors_cancel_during_acquisition`) ustawia
    /// globalny sygnał w środku pętli `pre_scan_directory` innego testu —
    /// ten dostaje `0` zamiast oczekiwanej liczby plików, bez żadnego
    /// ostrzeżenia o race.
    ///
    /// Moduł jest `pub(crate)` i zdefiniowany POZA `mod tests`/`mod
    /// integration_tests`, żeby oba moduły testowe mogły współdzielić TEN
    /// SAM statyczny muteks (dwie osobne statyki w każdym z modułów NIE
    /// serializowałyby się wzajemnie).
    pub static CANCEL_LOCK: Mutex<()> = Mutex::new(());
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_lock::CANCEL_LOCK;
    use std::sync::atomic::AtomicUsize;
    use tempfile::tempdir;

    // ------------------------------------------------------------------
    // Rozpoznawanie sierot FS
    // ------------------------------------------------------------------

    #[test]
    fn test_rozpoznaje_katalogi_ratunkowe_programow_odzyskujacych() {
        for sciezka in [
            "$Tresh/plik.jpg",
            "LostFiles/DSC_0001.dng",
            "$RECYCLE.BIN/старый.txt",
            "$Trash/a/b/c.mp4",
        ] {
            assert!(
                is_orphan_path(sciezka),
                "'{}' musi być rozpoznane jako sierota",
                sciezka
            );
        }
    }

    #[test]
    fn test_rozpoznanie_sierot_jest_niewrazliwe_na_wielkosc_liter() {
        for wariant in [
            "LOSTFILES/x",
            "lostfiles/x",
            "LostFiles/x",
            "$TRESH/x",
            "$tresh/x",
        ] {
            assert!(
                is_orphan_path(wariant),
                "wariant '{}' musi być rozpoznany",
                wariant
            );
        }
    }

    #[test]
    fn test_zwykle_sciezki_nie_sa_sierotami() {
        for sciezka in [
            "zdjecia/2023/DSC_0001.jpg",
            "dokumenty/umowa.pdf",
            "",
            "trash_nie_jest_dolarem/x.txt",
            "moje_lost_files/x.txt",
        ] {
            assert!(!is_orphan_path(sciezka), "'{}' NIE jest sierotą", sciezka);
        }
    }

    // ------------------------------------------------------------------
    // Sanityzacja ścieżek spoza UTF-8
    // ------------------------------------------------------------------

    #[test]
    fn test_sanityzacja_nie_rusza_poprawnego_utf8() {
        let sciezka = Path::new("zdjecia/2023/DSC_0001.jpg");
        assert_eq!(sanitize_relative_path(sciezka), "zdjecia/2023/DSC_0001.jpg");
    }

    #[test]
    fn test_sanityzacja_polskich_znakow_nie_dodaje_sufiksu() {
        let sciezka = Path::new("zażółć/gęślą.jaźń");
        assert_eq!(sanitize_relative_path(sciezka), "zażółć/gęślą.jaźń");
    }

    #[cfg(unix)]
    #[test]
    fn test_sanityzacja_rozroznia_kolidujace_sciezki_spoza_utf8() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let a = OsStr::from_bytes(b"plik_\xFF.jpg");
        let b = OsStr::from_bytes(b"plik_\xFE.jpg");

        assert_eq!(a.to_string_lossy(), b.to_string_lossy());

        let sa = sanitize_relative_path(Path::new(a));
        let sb = sanitize_relative_path(Path::new(b));
        assert_ne!(
            sa, sb,
            "różne surowe bajty muszą dać różne klucze relative_path"
        );
    }

    // ------------------------------------------------------------------
    // fnv1a_64
    // ------------------------------------------------------------------

    #[test]
    fn test_fnv1a_64_pusty_input_daje_offset_basis() {
        assert_eq!(fnv1a_64(b""), 0xcbf29ce484222325);
    }

    #[test]
    fn test_fnv1a_64_jest_deterministyczny() {
        assert_eq!(
            fnv1a_64(b"dowolne bajty testowe"),
            fnv1a_64(b"dowolne bajty testowe")
        );
    }

    #[test]
    fn test_fnv1a_64_rozne_bajty_daja_rozne_hashe() {
        assert_ne!(fnv1a_64(b"plik_a"), fnv1a_64(b"plik_b"));
    }

    #[test]
    fn test_fnv1a_64_wrazliwy_na_kolejnosc_bajtow() {
        assert_ne!(fnv1a_64(b"ab"), fnv1a_64(b"ba"));
    }

    #[cfg(unix)]
    #[test]
    fn test_sanityzacja_jest_deterministyczna_dla_tych_samych_bajtow() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let raw = OsStr::from_bytes(b"dziwna_\xC0\xC1nazwa.bin");
        let raz = sanitize_relative_path(Path::new(raw));
        let dwa = sanitize_relative_path(Path::new(raw));
        assert_eq!(raz, dwa);
    }

    // ------------------------------------------------------------------
    // Hashowanie ścieżek
    // ------------------------------------------------------------------

    #[test]
    fn test_hash_sciezki_jest_deterministyczny() {
        let a = hash_path("zdjecia/2023/DSC_0001.jpg");
        let b = hash_path("zdjecia/2023/DSC_0001.jpg");
        assert_eq!(a, b, "ta sama ścieżka musi dać ten sam hash");
    }

    #[test]
    fn test_rozne_sciezki_daja_rozne_hashe() {
        let sciezki = [
            "a/b/c.jpg",
            "a/b/d.jpg",
            "a/c/c.jpg",
            "b/b/c.jpg",
            "a/b/c.jpeg",
            "a/b/c.jpg ",
            " a/b/c.jpg",
        ];
        let mut zbior = HashSet::new();
        for s in sciezki {
            assert!(zbior.insert(hash_path(s)), "kolizja hasha dla '{}'", s);
        }
    }

    #[test]
    fn test_hash_radzi_sobie_z_polskimi_znakami_i_pusta_sciezka() {
        let _ = hash_path("");
        assert_ne!(
            hash_path("zażółć/gęślą.jaźń"),
            hash_path("zazolc/gesla.jazn")
        );
    }

    // ------------------------------------------------------------------
    // Bloki panelu bocznego
    // ------------------------------------------------------------------

    #[test]
    fn test_blok_zrodla_pokazuje_wszystkie_cztery_liczniki() {
        let stats = SourceStats::new();
        stats.scanned.store(1500, Ordering::Relaxed);
        stats.new_files.store(900, Ordering::Relaxed);
        stats.db_count.store(850, Ordering::Relaxed);
        stats.orphans.store(12, Ordering::Relaxed);

        let blok = stats.build_block("UFS Explorer");

        assert!(
            blok.starts_with("[UFS Explorer]"),
            "blok musi zaczynać się etykietą źródła: {}",
            blok
        );
        for oczekiwana in ["1500", "900", "850", "12"] {
            assert!(
                blok.contains(oczekiwana),
                "brak licznika {} w bloku:\n{}",
                oczekiwana,
                blok
            );
        }
        assert_eq!(
            blok.lines().count(),
            5,
            "etykieta + cztery liczniki:\n{}",
            blok
        );
    }

    #[test]
    fn test_blok_synchronizacji_rozdziela_oba_zrodla() {
        let blok = build_sqlite_sync_block(120, 340);
        assert!(blok.contains("UFS Explorer: 120"), "{}", blok);
        assert!(blok.contains("Skrypt Autorski: 340"), "{}", blok);
    }

    // ------------------------------------------------------------------
    // Wykrywanie dysku talerzowego
    // ------------------------------------------------------------------

    #[test]
    fn test_sciezka_spoza_zamontowanych_dyskow_nie_jest_hdd() {
        assert!(!is_hdd(Path::new("/nie/istnieje/taka/sciezka/nigdzie")));
        assert!(!is_hdd(Path::new("")));
    }

    // ------------------------------------------------------------------
    // Pre-skan na PRAWDZIWYM katalogu
    // ------------------------------------------------------------------

    fn utworz_plik(sciezka: &Path) {
        if let Some(rodzic) = sciezka.parent() {
            fs::create_dir_all(rodzic)
                .expect("Nie można utworzyć katalogów nadrzędnych dla pliku testowego");
        }
        fs::write(sciezka, b"x").expect("Nie można zapisać pliku testowego");
    }

    fn kanal() -> (mpsc::Sender<PhaseEvent>, mpsc::Receiver<PhaseEvent>) {
        mpsc::channel()
    }

    #[test]
    fn test_pre_skan_liczy_tylko_nowe_pliki() {
        // `pre_scan_directory` czyta globalny `CANCEL_SIGNAL` w pętli —
        // bez tego locka równoległy `test_run_honors_cancel_...` ustawiłby
        // sygnał w środku naszego pre-skanu i dostalibyśmy 0 zamiast 3.
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        utworz_plik(&dir.path().join("a.jpg"));
        utworz_plik(&dir.path().join("pod/b.jpg"));
        utworz_plik(&dir.path().join("pod/glebiej/c.jpg"));

        let (tx, _rx) = kanal();
        let licznik = AtomicUsize::new(0);
        let stats = SourceStats::new();

        let nowe = pre_scan_directory(PreScanCtx {
            base_path: dir.path(),
            label: "Test",
            known_hashes: &HashSet::new(),
            parallelism: Parallelism::Serial,
            io_counter: &licznik,
            tx_ui: &tx,
            panel_idx: 0,
            stats: &stats,
        });

        assert_eq!(nowe, 3, "wszystkie trzy pliki są nowe");
        assert_eq!(stats.new_files.load(Ordering::Relaxed), 3);
        assert!(
            stats.scanned.load(Ordering::Relaxed) >= 3,
            "licznik „przeskanowano” obejmuje też katalogi, więc jest >= liczby plików"
        );
        assert!(
            licznik.load(Ordering::Relaxed) >= 3,
            "licznik I/O musi rosnąć"
        );
    }

    #[test]
    fn test_pre_skan_pomija_pliki_juz_znane() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        utworz_plik(&dir.path().join("stary.jpg"));
        utworz_plik(&dir.path().join("nowy.jpg"));

        let znane: HashSet<u64> = [hash_path("stary.jpg")].into_iter().collect();

        let (tx, _rx) = kanal();
        let licznik = AtomicUsize::new(0);
        let stats = SourceStats::new();

        let nowe = pre_scan_directory(PreScanCtx {
            base_path: dir.path(),
            label: "Test",
            known_hashes: &znane,
            parallelism: Parallelism::Serial,
            io_counter: &licznik,
            tx_ui: &tx,
            panel_idx: 0,
            stats: &stats,
        });

        assert_eq!(nowe, 1, "tylko jeden plik jest nowy");
    }

    #[test]
    fn test_pre_skan_nieistniejacej_sciezki_zwraca_zero_i_zglasza_blad() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let (tx, rx) = kanal();
        let licznik = AtomicUsize::new(0);
        let stats = SourceStats::new();

        let nowe = pre_scan_directory(PreScanCtx {
            base_path: Path::new("/nie/ma/takiej/sciezki"),
            label: "Brakujące",
            known_hashes: &HashSet::new(),
            parallelism: Parallelism::Serial,
            io_counter: &licznik,
            tx_ui: &tx,
            panel_idx: 0,
            stats: &stats,
        });

        assert_eq!(nowe, 0);

        let komunikaty: Vec<String> = rx
            .try_iter()
            .filter_map(|e| match e {
                PhaseEvent::Log(s) => Some(s),
                _ => None,
            })
            .collect();
        assert!(
            komunikaty.iter().any(|k| k.contains("nie istnieje")),
            "brak ścieżki musi zostać zgłoszony operatorowi: {:?}",
            komunikaty
        );
    }

    #[test]
    fn test_pre_skan_pustego_katalogu_daje_zero() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let (tx, _rx) = kanal();
        let licznik = AtomicUsize::new(0);
        let stats = SourceStats::new();

        assert_eq!(
            pre_scan_directory(PreScanCtx {
                base_path: dir.path(),
                label: "Pusty",
                known_hashes: &HashSet::new(),
                parallelism: Parallelism::Serial,
                io_counter: &licznik,
                tx_ui: &tx,
                panel_idx: 0,
                stats: &stats,
            }),
            0
        );
    }

    // ------------------------------------------------------------------
    // Akwizycja strumieniowa
    // ------------------------------------------------------------------

    fn uruchom_akwizycje(
        katalog: &Path,
        znane: &HashSet<u64>,
        is_ufs: bool,
    ) -> (usize, usize, Vec<ScanMsg>) {
        let (tx_db, rx_db) = mpsc::sync_channel(10_000);
        let (tx_ui, _rx_ui) = kanal();
        let licznik = AtomicUsize::new(0);
        let stats = SourceStats::new();

        let log = Arc::new(Mutex::new(
            tempfile::tempfile().expect("Nie można utworzyć pliku tymczasowego dla logów"),
        ));

        let (cnt, orph) = scan_directory_stream(StreamCtx {
            base_path: katalog,
            known_hashes: znane,
            parallelism: Parallelism::Serial,
            tx_db,
            is_ufs,
            tx_ui: &tx_ui,
            bar_idx: 0,
            io_counter: &licznik,
            opr_log: log,
            stats: &stats,
        });

        (cnt, orph, rx_db.into_iter().collect())
    }

    fn sciezki_z_paczek(msgs: &[ScanMsg]) -> Vec<String> {
        msgs.iter()
            .flat_map(|m| match m {
                ScanMsg::UfsChunk(c) | ScanMsg::ScriptChunk(c) => {
                    c.iter().map(|(r, _, _)| r.clone()).collect::<Vec<_>>()
                }
                _ => Vec::new(),
            })
            .collect()
    }

    #[test]
    fn test_akwizycja_wysyla_kazdy_nowy_plik_dokladnie_raz() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        for i in 0..5 {
            utworz_plik(&dir.path().join(format!("plik_{}.bin", i)));
        }

        let (cnt, orph, msgs) = uruchom_akwizycje(dir.path(), &HashSet::new(), true);

        assert_eq!(cnt, 5);
        assert_eq!(orph, 0);

        let mut sciezki = sciezki_z_paczek(&msgs);
        sciezki.sort();
        assert_eq!(sciezki.len(), 5, "każdy plik dokładnie raz: {:?}", sciezki);
        assert_eq!(sciezki[0], "plik_0.bin");
    }

    #[test]
    fn test_akwizycja_oznacza_sieroty() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        utworz_plik(&dir.path().join("normalny.jpg"));
        utworz_plik(&dir.path().join("LostFiles/sierota.jpg"));

        let (cnt, orph, msgs) = uruchom_akwizycje(dir.path(), &HashSet::new(), true);

        assert_eq!(cnt, 2);
        assert_eq!(orph, 1, "dokładnie jeden plik jest sierotą");

        let oznaczenia: Vec<(String, bool)> = msgs
            .iter()
            .flat_map(|m| match m {
                ScanMsg::UfsChunk(c) => c
                    .iter()
                    .map(|(r, _, o)| (r.clone(), *o))
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .collect();

        let sierota = oznaczenia
            .iter()
            .find(|(r, _)| r.contains("sierota"))
            .expect("sierota musi być wysłana");
        assert!(
            sierota.1,
            "plik z LostFiles musi mieć ustawioną flagę sieroty"
        );

        let normalny = oznaczenia
            .iter()
            .find(|(r, _)| r.contains("normalny"))
            .expect("Szukany element powinien znajdować się w kolekcji");
        assert!(
            !normalny.1,
            "zwykły plik nie może być oznaczony jako sierota"
        );
    }

    #[test]
    fn test_akwizycja_kieruje_paczki_do_wlasciwego_zrodla() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        utworz_plik(&dir.path().join("x.bin"));

        let (_, _, msgs_ufs) = uruchom_akwizycje(dir.path(), &HashSet::new(), true);
        assert!(
            msgs_ufs.iter().any(|m| matches!(m, ScanMsg::UfsChunk(_))),
            "przy is_ufs=true paczki muszą iść kanałem UFS"
        );
        assert!(
            !msgs_ufs
                .iter()
                .any(|m| matches!(m, ScanMsg::ScriptChunk(_)))
        );

        let (_, _, msgs_scr) = uruchom_akwizycje(dir.path(), &HashSet::new(), false);
        assert!(
            msgs_scr
                .iter()
                .any(|m| matches!(m, ScanMsg::ScriptChunk(_)))
        );
        assert!(!msgs_scr.iter().any(|m| matches!(m, ScanMsg::UfsChunk(_))));
    }

    #[test]
    fn test_ostatnia_niepelna_paczka_nie_ginie() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let ile = CHUNK_SIZE + 7;
        for i in 0..ile {
            utworz_plik(&dir.path().join(format!("p{:04}.bin", i)));
        }

        let (cnt, _, msgs) = uruchom_akwizycje(dir.path(), &HashSet::new(), true);

        assert_eq!(cnt, ile);
        assert_eq!(
            sciezki_z_paczek(&msgs).len(),
            ile,
            "suma plików we wszystkich paczkach musi równać się liczbie plików na dysku"
        );

        let liczby_paczek: Vec<usize> = msgs
            .iter()
            .filter_map(|m| match m {
                ScanMsg::UfsChunk(c) => Some(c.len()),
                _ => None,
            })
            .collect();
        assert_eq!(
            liczby_paczek,
            vec![CHUNK_SIZE, 7],
            "pełna paczka + reszta: {:?}",
            liczby_paczek
        );
    }

    #[test]
    fn test_akwizycja_pomija_pliki_juz_znane() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        utworz_plik(&dir.path().join("stary.bin"));
        utworz_plik(&dir.path().join("nowy.bin"));

        let znane: HashSet<u64> = [hash_path("stary.bin")].into_iter().collect();
        let (cnt, _, msgs) = uruchom_akwizycje(dir.path(), &znane, true);

        assert_eq!(cnt, 1);
        assert_eq!(sciezki_z_paczek(&msgs), vec!["nowy.bin".to_string()]);
    }

    #[test]
    fn test_akwizycja_zawsze_raportuje_liczbe_pominietych() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        utworz_plik(&dir.path().join("a.bin"));

        let (_, _, msgs) = uruchom_akwizycje(dir.path(), &HashSet::new(), true);

        assert!(
            msgs.iter().any(|m| matches!(m, ScanMsg::UfsSkipped(_))),
            "komunikat o pominiętych wpisach musi dotrzeć nawet gdy jest ich zero"
        );
    }

    #[test]
    fn test_akwizycja_nieistniejacej_sciezki_nic_nie_wysyla() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let (cnt, orph, msgs) =
            uruchom_akwizycje(Path::new("/nie/ma/takiej"), &HashSet::new(), true);
        assert_eq!((cnt, orph), (0, 0));
        assert!(
            msgs.is_empty(),
            "brak katalogu nie może produkować paczek: {}",
            msgs.len()
        );
    }

    // ------------------------------------------------------------------
    // Semantyka zapisu do bazy — sedno modelu dwóch źródeł
    // ------------------------------------------------------------------

    fn wstaw(conn: &Connection, sql: &str, rel: &str, sierota: bool) {
        conn.execute(sql, params![rel, sierota])
            .expect("Wykonanie zapytania SQL na bazie danych nie powiodło się");
    }

    fn odczytaj(conn: &Connection, rel: &str) -> (bool, bool, bool, bool) {
        conn.query_row(
            "SELECT found_in_ufs, found_in_script, phase1_done, is_orphan FROM files WHERE relative_path = ?1",
            params![rel],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).expect("Nie można odczytać statusu pliku z bazy danych")
    }

    #[test]
    fn test_plik_z_obu_zrodel_ma_obie_flagi() {
        let conn =
            crate::db::init_db(":memory:").expect("Inicjalizacja bazy danych nie powiodła się");

        wstaw(&conn, INSERT_SQL_UFS, "zdjecia/a.jpg", false);
        assert_eq!(
            odczytaj(&conn, "zdjecia/a.jpg"),
            (true, false, true, false),
            "po zapisie z UFS"
        );

        wstaw(&conn, INSERT_SQL_SCRIPT, "zdjecia/a.jpg", false);
        assert_eq!(
            odczytaj(&conn, "zdjecia/a.jpg"),
            (true, true, true, false),
            "drugie źródło DODAJE swoją flagę, nie kasuje cudzej"
        );
    }

    #[test]
    fn test_kolejnosc_zrodel_nie_ma_znaczenia() {
        let conn =
            crate::db::init_db(":memory:").expect("Inicjalizacja bazy danych nie powiodła się");

        wstaw(&conn, INSERT_SQL_SCRIPT, "b.jpg", false);
        wstaw(&conn, INSERT_SQL_UFS, "b.jpg", false);

        assert_eq!(odczytaj(&conn, "b.jpg"), (true, true, true, false));
    }

    #[test]
    fn test_plik_tylko_z_jednego_zrodla_zostaje_unikalny() {
        let conn =
            crate::db::init_db(":memory:").expect("Inicjalizacja bazy danych nie powiodła się");

        wstaw(&conn, INSERT_SQL_UFS, "tylko_ufs.jpg", false);
        wstaw(&conn, INSERT_SQL_SCRIPT, "tylko_skrypt.jpg", false);

        assert_eq!(odczytaj(&conn, "tylko_ufs.jpg"), (true, false, true, false));
        assert_eq!(
            odczytaj(&conn, "tylko_skrypt.jpg"),
            (false, true, true, false)
        );
    }

    #[test]
    fn test_flaga_sieroty_trafia_do_bazy() {
        let conn =
            crate::db::init_db(":memory:").expect("Inicjalizacja bazy danych nie powiodła się");
        wstaw(&conn, INSERT_SQL_UFS, "LostFiles/x.jpg", true);
        assert_eq!(
            odczytaj(&conn, "LostFiles/x.jpg"),
            (true, false, true, true)
        );
    }

    #[test]
    fn test_powtorny_zapis_tego_samego_zrodla_nie_duplikuje_wiersza() {
        let conn =
            crate::db::init_db(":memory:").expect("Inicjalizacja bazy danych nie powiodła się");

        for _ in 0..3 {
            wstaw(&conn, INSERT_SQL_UFS, "powtarzany.jpg", false);
        }

        let ile: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE relative_path = 'powtarzany.jpg'",
                [],
                |r| r.get(0),
            )
            .expect("Odczyt z bazy danych nie powiódł się");
        assert_eq!(ile, 1, "unikalność relative_path musi być utrzymana");
    }

    #[test]
    fn test_zapis_ustawia_znacznik_ukonczenia_fazy() {
        let conn =
            crate::db::init_db(":memory:").expect("Inicjalizacja bazy danych nie powiodła się");
        wstaw(&conn, INSERT_SQL_UFS, "x.jpg", false);

        let ile: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE phase1_done = 1",
                [],
                |r| r.get(0),
            )
            .expect("Odczyt z bazy danych nie powiódł się");
        assert_eq!(ile, 1);
    }

    // ------------------------------------------------------------------
    // Reset phaseN_done na realnej zmianie found_in_*
    // ------------------------------------------------------------------

    fn ustaw_phase_done(conn: &Connection, kolumna: &str, rel: &str, wartosc: bool) {
        conn.execute(
            &format!("UPDATE files SET {} = ?1 WHERE relative_path = ?2", kolumna),
            params![wartosc, rel],
        )
        .expect("Wykonanie zapytania SQL na bazie danych nie powiodło się");
    }

    fn phase_done(conn: &Connection, kolumna: &str, rel: &str) -> bool {
        conn.query_row(
            &format!("SELECT {} FROM files WHERE relative_path = ?1", kolumna),
            params![rel],
            |r| r.get(0),
        )
        .expect("Odczyt z bazy danych nie powiódł się")
    }

    #[test]
    fn test_dopisanie_drugiej_strony_resetuje_phase2_done() {
        let conn =
            crate::db::init_db(":memory:").expect("Inicjalizacja bazy danych nie powiodła się");

        wstaw(&conn, INSERT_SQL_UFS, "plik.jpg", false);
        ustaw_phase_done(&conn, "phase2_done", "plik.jpg", true);

        wstaw(&conn, INSERT_SQL_SCRIPT, "plik.jpg", false);

        assert!(
            !phase_done(&conn, "phase2_done", "plik.jpg"),
            "realna zmiana found_in_script 0->1 musi zresetować phase2_done"
        );
    }

    #[test]
    fn test_powtorny_zapis_tej_samej_strony_nie_resetuje_phase2_done() {
        let conn =
            crate::db::init_db(":memory:").expect("Inicjalizacja bazy danych nie powiodła się");

        wstaw(&conn, INSERT_SQL_UFS, "plik.jpg", false);
        wstaw(&conn, INSERT_SQL_SCRIPT, "plik.jpg", false);
        ustaw_phase_done(&conn, "phase2_done", "plik.jpg", true);

        wstaw(&conn, INSERT_SQL_UFS, "plik.jpg", false);

        assert!(
            phase_done(&conn, "phase2_done", "plik.jpg"),
            "brak realnej zmiany found_in_* nie może zresetować phase2_done"
        );
    }

    #[test]
    fn test_dopisanie_drugiej_strony_resetuje_phase11_i_phase14_i_phase19_done() {
        for kolumna in ["phase11_done", "phase14_done", "phase19_done"] {
            let conn = crate::db::init_db(":memory:")
                .expect("Nie można zainicjalizować bazy danych w pamięci");

            wstaw(&conn, INSERT_SQL_UFS, "plik.jpg", false);
            ustaw_phase_done(&conn, kolumna, "plik.jpg", true);

            wstaw(&conn, INSERT_SQL_SCRIPT, "plik.jpg", false);

            assert!(
                !phase_done(&conn, kolumna, "plik.jpg"),
                "realna zmiana found_in_script 0->1 musi zresetować {}",
                kolumna
            );
        }
    }

    #[test]
    fn test_powtorny_zapis_tej_samej_strony_nie_resetuje_phase11_i_phase14_i_phase19_done() {
        for kolumna in ["phase11_done", "phase14_done", "phase19_done"] {
            let conn =
                crate::db::init_db(":memory:").expect("Inicjalizacja bazy danych nie powiodła się");

            wstaw(&conn, INSERT_SQL_UFS, "plik.jpg", false);
            wstaw(&conn, INSERT_SQL_SCRIPT, "plik.jpg", false);
            ustaw_phase_done(&conn, kolumna, "plik.jpg", true);

            wstaw(&conn, INSERT_SQL_UFS, "plik.jpg", false);

            assert!(
                phase_done(&conn, kolumna, "plik.jpg"),
                "brak realnej zmiany found_in_* nie może zresetować {}",
                kolumna
            );
        }
    }
}

// ============================================================================
// TESTY INTEGRACYJNE
// ============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;
    use super::test_lock::CANCEL_LOCK;
    use rusqlite::Connection;
    use std::path::Path;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("czas systemowy przed UNIX_EPOCH?")
                .as_nanos();
            let p = std::env::temp_dir().join(format!("phase1_test_{}_{}_{}", tag, pid, nanos));
            std::fs::create_dir_all(&p)
                .unwrap_or_else(|e| panic!("nie udało się utworzyć {:?}: {}", p, e));
            TempDir(p)
        }
        fn path(&self) -> &Path { &self.0 }
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

    fn utworz_plik(sciezka: &Path) {
        if let Some(rodzic) = sciezka.parent() {
            std::fs::create_dir_all(rodzic).expect("mkdir -p");
        }
        std::fs::write(sciezka, b"x").expect("write");
    }

    #[test]
    fn test_run_empty_corpus_completes_cleanly() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let ufs = TempDir::new("empty_ufs");
        let script = TempDir::new("empty_script");
        let logs = TempDir::new("empty_logs");

        let mut conn = fresh_db();
        let config = config_seq(ufs.path(), script.path(), logs.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        CANCEL_SIGNAL.store(false, Ordering::SeqCst);
        run(&mut conn, &config, tx_ui).expect("run() na pustym korpusie");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))
            .expect("query_row");
        assert_eq!(count, 0, "pusty korpus nie może dodać wierszy");
    }

    #[test]
    fn test_run_adds_files_from_both_sources() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let ufs = TempDir::new("both_ufs");
        let script = TempDir::new("both_script");
        let logs = TempDir::new("both_logs");

        utworz_plik(&ufs.path().join("u1.txt"));
        utworz_plik(&ufs.path().join("u2.txt"));
        utworz_plik(&script.path().join("s1.txt"));
        utworz_plik(&script.path().join("s2.txt"));

        let mut conn = fresh_db();
        let config = config_seq(ufs.path(), script.path(), logs.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        CANCEL_SIGNAL.store(false, Ordering::SeqCst);
        run(&mut conn, &config, tx_ui).expect("run()");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))
            .expect("query_row");
        assert_eq!(count, 4, "2 UFS + 2 Skrypt = 4 wiersze");

        let ufs_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM files WHERE found_in_ufs = 1", [], |r| r.get(0))
            .expect("query_row");
        assert_eq!(ufs_count, 2);

        let script_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM files WHERE found_in_script = 1", [], |r| r.get(0))
            .expect("query_row");
        assert_eq!(script_count, 2);
    }

    #[test]
    fn test_run_marks_common_files_with_both_flags() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let ufs = TempDir::new("common_ufs");
        let script = TempDir::new("common_script");
        let logs = TempDir::new("common_logs");

        utworz_plik(&ufs.path().join("shared.txt"));
        utworz_plik(&script.path().join("shared.txt"));

        let mut conn = fresh_db();
        let config = config_seq(ufs.path(), script.path(), logs.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        CANCEL_SIGNAL.store(false, Ordering::SeqCst);
        run(&mut conn, &config, tx_ui).expect("run()");

        let (ufs_flag, script_flag): (bool, bool) = conn
            .query_row(
                "SELECT found_in_ufs, found_in_script FROM files WHERE relative_path = 'shared.txt'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query_row");

        assert!(ufs_flag, "shared.txt musi mieć found_in_ufs=1");
        assert!(script_flag, "shared.txt musi mieć found_in_script=1");
    }

    /// Deterministyczny test anulowania W TRAKCIE akwizycji.
    ///
    /// ## Kluczowa zmiana: JEDNO połączenie SQLite w cancellerze
    ///
    /// Poprzednia wersja otwierała NOWE połączenie w każdej iteracji busy-loopu
    /// (`Connection::open` to ~1 ms — przy spin-loopie to marnowanie czasu
    /// i, co gorsza, z każdym otwarciem trzeba wykonać ponownie handshake
    /// SQLite). 5000 plików × ~5 µs = ~25 ms całego `run()` — canceller
    /// nie zdążył zobaczyć pierwszego commitu, bo każda iteracja zajmowała
    /// więcej niż cały przebieg.
    ///
    /// Teraz: połączenie otwierane RAZ, `busy_timeout` ustawiony, w pętli
    /// tylko `query_row` + `yield_now()`.
    #[test]
    fn test_run_honors_cancel_during_acquisition_and_skips_final_report() {
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let ufs = TempDir::new("cancel_during_ufs");
        let script = TempDir::new("cancel_during_script");
        let logs = TempDir::new("cancel_during_logs");
        let db_dir = TempDir::new("cancel_during_db");

        const TOTAL: usize = 5_000;
        for i in 0..TOTAL {
            utworz_plik(&ufs.path().join(format!("p{:05}.txt", i)));
        }

        let db_path = db_dir.path().join("cancel.db");
        let db_path_str = db_path.to_string_lossy().into_owned();
        {
            let _ = crate::db::init_db(&db_path_str).expect("init_db");
        }

        let config = config_seq(ufs.path(), script.path(), logs.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        // Deterministyczny canceller — JEDNO połączenie, busy_timeout,
        // busy-poll `yield_now` (bez `sleep`, żeby nie uśpić się na moment
        // gdy run() zdąży skończyć).
        let canceller = thread::spawn({
            let db_path_str = db_path_str.clone();
            move || {
                // Otwarcie RAZ — koszt ~1 ms, jednorazowy.
                let conn = match Connection::open(&db_path_str) {
                    Ok(c) => c,
                    Err(_) => {
                        // Nie możemy otworzyć bazy → nie ma jak wykryć postępu.
                        // Ustawiamy cancel od razu, żeby test nie wisiał 30 s.
                        CANCEL_SIGNAL.store(true, Ordering::SeqCst);
                        return;
                    }
                };
                let _ = conn.busy_timeout(Duration::from_millis(100));

                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    if Instant::now() > deadline { break; }

                    let done: i64 = conn
                        .query_row(
                            "SELECT COUNT(*) FROM files WHERE phase1_done = 1",
                            [],
                            |r| r.get(0),
                        )
                        .unwrap_or(0);
                    if done > 0 { break; }

                    std::thread::yield_now();
                }
                CANCEL_SIGNAL.store(true, Ordering::SeqCst);
            }
        });

        let mut conn = Connection::open(&db_path_str).expect("reopen");
        let result = run(&mut conn, &config, tx_ui);
        canceller.join().expect("canceller panicked");
        CANCEL_SIGNAL.store(false, Ordering::SeqCst);

        result.expect("run() nie powinno zwrócić Err po anulowaniu");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))
            .expect("query_row");
        assert!(count > 0, "coś powinno być zapisane przed cancel — {}", count);
        assert!(
            count < TOTAL as i64,
            "cancel musi przerwać przed końcem — {} z {}",
            count,
            TOTAL
        );

        // Fix #2: dziennik końcowy NIE może zostać zapisany po anulowaniu.
        // Nazwa niesie teraz znacznik czasu (patrz `utils::stamp_filename`),
        // więc szukamy PO PREFIKSIE zamiast zakładać stałą nazwę.
        let znaleziono_dziennik = std::fs::read_dir(logs.path())
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("dziennik_koncowy_faza1"))
            });
        assert!(
            !znaleziono_dziennik,
            "po anulowaniu dziennik końcowy nie może być zapisany w {:?}",
            logs.path()
        );
    }
}
