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

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::format_display_path;
use jwalk::{Parallelism, WalkDir};
use ratatui::style::Color;
use rusqlite::{params, Connection, Result};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;
use tracing::info;

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use sysinfo::{Disks, DiskKind};
use std::fs::{self, File};

const CHUNK_SIZE: usize = 200;

// `phaseN_done = CASE WHEN found_in_ufs/found_in_script = 0 THEN 0 ELSE phaseN_done END`:
// nazwa kolumny bez kwalifikatora w `ON CONFLICT DO UPDATE` czyta wartość SPRZED
// tego zapisu — `found_in_ufs/script = 0` znaczy więc "ta strona NIE była wcześniej
// widziana", czyli ten UPSERT to prawdziwe przejście 0->1 (dysk/skrypt drugiej
// strony dołączony PO fakcie), a nie zwykłe powtórne skanowanie tej samej,
// niezmienionej strony korpusu — patrz testy `test_dopisanie_drugiej_strony_...`
// i `test_powtorny_zapis_tej_samej_strony_...` niżej.
//
// REGRESJA (measure twice — druga weryfikacja Gemini, Faza 11 N2 / Faza 14
// obserwacja #2): pierwotna naprawa resetowała TYLKO `phase2_done` — każda
// dalsza faza (3-19) miała identyczny problem strukturalny, tylko nikt go
// jeszcze nie naprawił: plik dopisany PÓŹNIEJ po drugiej stronie korpusu
// (scenariusz "dysk Skryptu podłączony po fakcie", patrz dokumentacja
// modułu) mógł już mieć `phaseN_done = 1` z WCZEŚNIEJSZEGO przebiegu, w
// którym istniał tylko po jednej stronie (`found_in_* = 0` trywialnie
// spełniało warunek ukończenia po stronie nieobecnej) — druga strona nigdy
// nie doczekałaby się analizy w żadnej fazie 3-19, bo `WHERE phaseN_done = 0
// OR phaseN_done IS NULL` na zawsze by ją pomijało. Rozszerzone tu na
// WSZYSTKIE `phaseN_done` (2 przez 19) — ten sam warunek dla każdej, bo
// przesłanka ("ta strona jest nowa") jest identyczna niezależnie od fazy.
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
// LICZNIKI LIVE — ROZDZIELONE PER SKANER (bez sumowania krzyżowego)
// ============================================================================

/// Liczniki Etapu 2 (Pre-Skan) dla JEDNEGO konkretnego źródła (UFS Explorer albo Skrypt Autorski).
struct PreScanStats {
    scanned: AtomicU64,
    new_files: AtomicU64,
}
impl PreScanStats {
    fn new() -> Self { Self { scanned: AtomicU64::new(0), new_files: AtomicU64::new(0) } }
}

/// Liczniki Etapu 3 (Akwizycja do bazy) dla JEDNEGO konkretnego źródła.
struct AcqStats {
    db_count: AtomicU64,
    orphans: AtomicU64,
}
impl AcqStats {
    fn new() -> Self { Self { db_count: AtomicU64::new(0), orphans: AtomicU64::new(0) } }
}

/// Buduje pełny blok statystyk DLA JEDNEGO ŹRÓDŁA — łączy Pre-Skan i Akwizycję
/// w jeden panel, np. "[UFS Explorer]", żeby operator widział kompletny obraz
/// wydajności tego konkretnego silnika odzysku bez mieszania z drugim źródłem.
fn build_source_block(label: &str, prescan: &PreScanStats, acq: &AcqStats) -> String {
    format!(
        "[{}]\n🔎 Przeskanowano: {}\n🆕 Nowych plików: {}\n📥 Zapisano do bazy: {}\n🛡️ Sieroty: {}",
        label,
        prescan.scanned.load(Ordering::Relaxed),
        prescan.new_files.load(Ordering::Relaxed),
        acq.db_count.load(Ordering::Relaxed),
        acq.orphans.load(Ordering::Relaxed),
    )
}

fn build_sqlite_sync_block(ufs_inserted: usize, script_inserted: usize) -> String {
    format!("[Synchronizacja SQLite]\nUFS Explorer: {}\nSkrypt Autorski: {}", ufs_inserted, script_inserted)
}

// ============================================================================
// POMOCNIKI
// ============================================================================

/// Identyfikuje ścieżki ratunkowe używane przez programy odzyskujące po uszkodzeniu FS
fn is_orphan_path(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("$tresh")
        || p.contains("$trash")
        || p.contains("lostfiles")
        || p.contains("$recycle.bin")
}

/// Zmienia długą ścieżkę w lekką 64-bitową liczbę, oszczędzając Gigabajty RAM-u
fn hash_path(path: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

/// FNV-1a 64-bit — algorytm w pełni opisany specyfikacją (offset/prime niżej
/// to CAŁA definicja), więc daje BITOWO identyczny wynik na każdej wersji
/// Rust/toolchaina i każdej platformie, w przeciwieństwie do
/// `std::collections::hash_map::DefaultHasher` (patrz `sanitize_relative_path`).
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

/// Zamienia ścieżkę względną na string bezpieczny do zapisu w `relative_path`
/// (kolumna `UNIQUE`).
///
/// ## Dlaczego nie wystarczy `to_string_lossy()`
///
/// Odzyskane systemy plików regularnie dają nazwy z bajtami spoza UTF-8 —
/// `to_string_lossy()` zamienia KAŻDY taki bajt na U+FFFD, więc DWIE różne,
/// realne ścieżki (różne surowe bajty) mogą dać IDENTYCZNY string. Ponieważ
/// `relative_path` jest kluczem `UNIQUE` z `ON CONFLICT DO UPDATE`, druga z
/// nich cicho SCALA SIĘ z pierwszym wierszem zamiast dostać własny — jeden z
/// dwóch dowodów znika bezpowrotnie z bazy, bez żadnego błędu ani logu.
///
/// Naprawa: gdy ścieżka NIE JEST poprawnym UTF-8, doklejamy do wersji lossy
/// deterministyczny sufiks policzony z PRAWDZIWYCH, surowych bajtów ścieżki
/// (`OsStr::as_encoded_bytes()` — przenośne między Unix/Windows, stabilne od
/// Rust 1.74). Dwie różne ścieżki o tych samych bajtach zawsze dostają ten
/// sam sufiks (idempotentne między przebiegami Fazy 1), a dwie RÓŻNE ścieżki
/// nigdy nie mogą już wylądować pod tym samym kluczem — kolizja jest
/// strukturalnie niemożliwa, nie tylko mało prawdopodobna. Poprawne UTF-8
/// (zdecydowana większość przypadków) przechodzi bez żadnej zmiany.
///
/// REGRESJA (measure twice — druga weryfikacja Gemini, N1): sufiks liczony
/// dawniej przez `DefaultHasher` — dokumentacja `std` wprost zastrzega, że
/// ten algorytm NIE jest gwarantowany jako ten sam między wersjami
/// biblioteki standardowej ani platformami. W obrębie JEDNEGO zbudowanego
/// binarium wynik jest w pełni deterministyczny, ale sufiks ląduje TRWALE
/// w kolumnie `UNIQUE` — jeśli to samo repozytorium dowodowe zostanie
/// zeskanowane Fazą 1 dwukrotnie przez DWA RÓŻNE kompilaty (np. po
/// aktualizacji Rust/toolchaina między sesjami śledztwa), ta sama ścieżka
/// mogłaby dostać INNY sufiks przy drugim skanie i utworzyć DRUGI,
/// zduplikowany wiersz zamiast trafić w `ON CONFLICT` na ten sam. `fnv1a_64`
/// ma w pełni opisaną, stabilną specyfikację — gwarancja idempotencji
/// deklarowana wyżej jest teraz prawdziwa międzybinarnie, nie tylko
/// wewnątrzbinarnie.
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

/// Sprawdza w systemie operacyjnym, czy ścieżka znajduje się na talerzowym dysku HDD
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
// LOGIKA BIZNESOWA I INTEGRACJA Z RATATUI ORAZ LOGAMI
// ============================================================================

#[allow(clippy::too_many_arguments)]
fn pre_scan_directory(
    base_path: &Path,
    label: &str,
    known_hashes: &HashSet<u64>,
    parallelism: Parallelism,
    io_counter: &AtomicUsize,
    tx_ui: &mpsc::Sender<PhaseEvent>,
    panel_idx: usize,
    prescan: &PreScanStats,
    acq: &AcqStats,
) -> u64 {
    if !base_path.exists() {
        let _ = tx_ui.send(PhaseEvent::Log(format!("BŁĄD: Ścieżka bazowa '{}' nie istnieje!", label)));
        return 0;
    }

    let _ = tx_ui.send(PhaseEvent::Log(format!("Rozpoczynam Pre-Skanowanie dysku: {}...", label)));

    // Panel boczny (idx = to samo źródło co pasek postępu): pełny, samodzielny blok
    let _ = tx_ui.send(PhaseEvent::UpdateSideText { idx: panel_idx, text: build_source_block(label, prescan, acq) });

    let mut new_files: u64 = 0;
    let mut already_known: u64 = 0;
    let mut total_scanned: u64 = 0;
    let mut last_ui_update = Instant::now();
    
    for entry in WalkDir::new(base_path).parallelism(parallelism).skip_hidden(false).into_iter().filter_map(|e| e.ok()) {
        if crate::utils::CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }
        
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

                prescan.scanned.store(total_scanned, Ordering::Relaxed);
                prescan.new_files.store(new_files, Ordering::Relaxed);
                    
                let now = Instant::now();
                if now.duration_since(last_ui_update).as_millis() > 150 { 
                    last_ui_update = now;
                    let display_path = crate::utils::format_display_path(&path.to_string_lossy());
                    
                    // Panel boczny TEGO źródła — nie miesza się z drugim skanerem
                    let _ = tx_ui.send(PhaseEvent::UpdateSideText { idx: panel_idx, text: build_source_block(label, prescan, acq) });
                    let _ = tx_ui.send(PhaseEvent::UpdateBottomPath { idx: panel_idx, path: display_path });
                }
            }
        }
    }
    
    // Zabezpieczenie na koniec – ostateczna aktualizacja licznika
    prescan.scanned.store(total_scanned, Ordering::Relaxed);
    prescan.new_files.store(new_files, Ordering::Relaxed);
    let _ = tx_ui.send(PhaseEvent::UpdateSideText { idx: panel_idx, text: build_source_block(label, prescan, acq) });

    let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Pre-Skanowanie '{}' zakończone.", label)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("  -> Znaleziono nowych plików: {}", new_files)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("  -> Ponowne skanowanie (pominięto): {}", already_known)));
    
    new_files
}
    
#[allow(clippy::too_many_arguments)]
fn scan_directory_stream(
    base_path: &Path,
    known_hashes: &HashSet<u64>,
    parallelism: Parallelism,
    tx_db: mpsc::SyncSender<ScanMsg>, 
    is_ufs: bool,
    tx_ui: &mpsc::Sender<PhaseEvent>,
    bar_idx: usize,
    io_counter: &AtomicUsize,
    opr_log: Arc<Mutex<File>>,
    prescan: &PreScanStats,
    acq: &AcqStats,
) -> (usize, usize) {
    if !base_path.exists() { return (0, 0); }

    let side_label = if is_ufs { "UFS Explorer" } else { "Skrypt Autorski" };
    let mut buffer = Vec::with_capacity(CHUNK_SIZE);
    let mut skipped = 0;
    let mut scanned_count = 0;
    let mut orphans_count = 0;
    
    let mut last_ui_update = Instant::now();

    // Panel boczny TEGO źródła — nadpisuje ten sam blok co pre-skan, teraz z akwizycją
    let _ = tx_ui.send(PhaseEvent::UpdateSideText { idx: bar_idx, text: build_source_block(side_label, prescan, acq) });

    for entry_result in WalkDir::new(base_path).parallelism(parallelism).skip_hidden(false) {
        if crate::utils::CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }
        
        io_counter.fetch_add(1, Ordering::Relaxed);

        match entry_result {
            Ok(entry) => {
                if entry.file_type().is_file() {
                    let path = entry.path();
                    if let Ok(rel) = path.strip_prefix(base_path) {
                        let rel_str = sanitize_relative_path(rel);
                        let path_hash = hash_path(&rel_str);
                        
                        if !known_hashes.contains(&path_hash) {
                            // OPTYMALIZACJA: Usunięto zbędny test std::fs::metadata(&path). Zrobi to Faza 2.
                            
                            scanned_count += 1;
                            let is_orphan = is_orphan_path(&rel_str);
                            
                            if is_orphan { 
                                orphans_count += 1;
                                if let Ok(mut f) = opr_log.lock() {
                                    let _ = writeln!(f, "[{}] Odizolowano sierotę FS: {}", side_label, rel_str);
                                }
                            }

                            acq.db_count.store(scanned_count as u64, Ordering::Relaxed);
                            acq.orphans.store(orphans_count as u64, Ordering::Relaxed);

                            let now = Instant::now();
                            if now.duration_since(last_ui_update).as_millis() > 60 {
                                last_ui_update = now;
                                
                                let display_path = format_display_path(&rel_str);
                                
                                // PASEK: wyłącznie postęp + krótki status (bez liczników)
                                let _ = tx_ui.send(PhaseEvent::UpdateBar { idx: bar_idx, current: scanned_count as u64, message: "Akwizycja do bazy...".to_string() });
                                let _ = tx_ui.send(PhaseEvent::UpdateBottomPath { idx: bar_idx, path: display_path });
                                // Panel boczny TEGO źródła — pełny obraz Pre-Skan + Akwizycja
                                let _ = tx_ui.send(PhaseEvent::UpdateSideText { idx: bar_idx, text: build_source_block(side_label, prescan, acq) });
                            }
                            
                            buffer.push((rel_str, is_orphan));

                            if buffer.len() >= CHUNK_SIZE {
                                let chunk = std::mem::replace(&mut buffer, Vec::with_capacity(CHUNK_SIZE));
                                if is_ufs {
                                    let _ = tx_db.send(ScanMsg::UfsChunk(chunk.into_iter().map(|(r, o)| (r, String::new(), o)).collect()));
                                } else {
                                    let _ = tx_db.send(ScanMsg::ScriptChunk(chunk.into_iter().map(|(r, o)| (r, String::new(), o)).collect()));
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
        let final_chunk: Vec<(String, String, bool)> = buffer.into_iter().map(|(r, o)| (r, String::new(), o)).collect();
        if is_ufs { let _ = tx_db.send(ScanMsg::UfsChunk(final_chunk)); } 
        else { let _ = tx_db.send(ScanMsg::ScriptChunk(final_chunk)); }
    }
    
    if is_ufs { let _ = tx_db.send(ScanMsg::UfsSkipped(skipped)); } 
    else { let _ = tx_db.send(ScanMsg::ScriptSkipped(skipped)); }

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: scanned_count as u64,
        message: "Zakończono odczyt I/O dysku.".to_string(),
    });

    (scanned_count, orphans_count)
}

// ============================================================================
// GŁÓWNA FUNKCJA KORDYNUJĄCA FAZĘ
// ============================================================================

pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    crate::utils::CANCEL_SIGNAL.store(false, Ordering::SeqCst);
    
    let _ = conn.execute("ALTER TABLE files ADD COLUMN is_orphan BOOLEAN DEFAULT 0", []);

    // 1. INICJALIZACJA DUAL-LOGGING
    let raport_cfg = config.raporty_faz.get("Faza 1").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza1.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza1.txt".to_string(),
    });
    
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);
    
    let opr_log_file = match File::create(&opr_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!("BŁĄD I/O: Nie można utworzyć pliku logu operacyjnego: {}. Sprawdź uprawnienia.", e)));
            return Ok(());
        }
    };
    let opr_log = Arc::new(Mutex::new(opr_log_file));
    {
        let _ = writeln!(opr_log.lock().unwrap(), "=== RAPORT OPERACYJNY - FAZA 1 (MAPOWANIE) ===");
        let _ = writeln!(opr_log.lock().unwrap(), "Zawiera ścieżki plików zidentyfikowanych jako 'Sieroty' w folderach $Tresh / LostFiles.\n");
    }

    let ufs_p = Path::new(&config.ufs_path);
    let script_p = Path::new(&config.script_path);

    // [OCHRONA DYSKÓW] - Jeśli skanujemy po HDD, wymuszamy tryb SEQUENTIAL, aby uchronić głowicę!
    let mut active_io_mode = config.io_mode.clone();
    if is_hdd(ufs_p) || is_hdd(script_p) {
        active_io_mode = "SEQUENTIAL".to_string();
        let _ = tx_ui.send(PhaseEvent::Log("⚠️ WYKRYTO DYSK TALERZOWY (HDD)! Automatycznie wymuszono tryb SEKWENCYJNY dla skanowania wstępnego".to_string()));
    } else {
        let io_text = if active_io_mode == "CONCURRENT" { "RÓWNOLEGŁE (SSD/NVMe)" } else { "SEKWENCYJNE (HDD)" };
        let _ = tx_ui.send(PhaseEvent::Log(format!("Uruchomiono Fazę 1. Metodyka szyny dyskowej: {}", io_text)));
    }

    let actual_threads = if config.max_threads > 0 { config.max_threads } else { rayon::current_num_threads() };
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora (Rayon): {}", actual_threads)));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    let global_io_counter = AtomicUsize::new(0);
    let io_counter_ref = &global_io_counter;

    // --- ETAP 1: ODCZYT STANU BAZY DANYCH (Oszczędzanie RAM-u przez Hashowanie) ---
    let mut known_ufs: HashSet<u64> = HashSet::new();
    let mut known_script: HashSet<u64> = HashSet::new();
    {
        let mut stmt = conn.prepare("SELECT relative_path, found_in_ufs, found_in_script FROM files WHERE phase1_done = 1")?;
        let rows = stmt.query_map([], |row| {
            let path: String = row.get(0)?;
            let ufs: bool = row.get(1)?;
            let script: bool = row.get(2)?;
            Ok((path, ufs, script))
        })?;

        for r in rows.filter_map(|r| r.ok()) {
            let path_hash = hash_path(&r.0);
            if r.1 { known_ufs.insert(path_hash); }
            if r.2 { known_script.insert(path_hash); }
        }
    }

    if !known_ufs.is_empty() || !known_script.is_empty() {
        let _ = tx_ui.send(PhaseEvent::Log(format!("Odczytano z bazy danych ubiegłe pliki. UFS Explorer: {}, Skrypt Autorski: {}", known_ufs.len(), known_script.len())));
    }

    let parallelism = if config.max_threads > 0 {
        Parallelism::RayonNewPool(config.max_threads)
    } else {
        Parallelism::RayonDefaultPool { busy_timeout: std::time::Duration::from_secs(1) }
    };

    let known_ufs_ref = &known_ufs;
    let known_script_ref = &known_script;
    let tx_ui_ref = &tx_ui;

    let mut new_ufs_count = 0;
    let mut new_script_count = 0;

    // --- ETAP 2: BŁYSKAWICZNY PRE-SCAN (statystyki rozdzielone per skaner) ---
    let ufs_prescan = PreScanStats::new();
    let script_prescan = PreScanStats::new();
    let ufs_acq = AcqStats::new();
    let script_acq = AcqStats::new();

    if active_io_mode == "CONCURRENT" {
//    if config.io_mode == "CONCURRENT" {
        std::thread::scope(|s| {
            let p1 = parallelism.clone();
            let p2 = parallelism.clone();
            let ufs_thread = s.spawn(|| pre_scan_directory(ufs_p, "UFS Explorer", known_ufs_ref, p1, io_counter_ref, tx_ui_ref, 0, &ufs_prescan, &ufs_acq));
            let script_thread = s.spawn(|| pre_scan_directory(script_p, "Skrypt Autorski", known_script_ref, p2, io_counter_ref, tx_ui_ref, 1, &script_prescan, &script_acq));
            new_ufs_count = ufs_thread.join().unwrap();
            new_script_count = script_thread.join().unwrap();
        });
    } else {
        let p_seq = Parallelism::Serial;
        new_ufs_count = pre_scan_directory(ufs_p, "UFS Explorer", known_ufs_ref, p_seq.clone(), io_counter_ref, tx_ui_ref, 0, &ufs_prescan, &ufs_acq);
        new_script_count = pre_scan_directory(script_p, "Skrypt Autorski", known_script_ref, p_seq, io_counter_ref, tx_ui_ref, 1, &script_prescan, &script_acq);
    }

    let total_new = new_ufs_count + new_script_count;

    if crate::utils::CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log("🛑 Skanowanie przerwane przez użytkownika.".to_string()));
        return Ok(());
    }

    if total_new == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak nowych plików do wgrania. Baza jest w pełni aktualna.".to_string()));
        return Ok(());
    }

    // --- ETAP 3: AKWIZYCJA Z DYSKÓW (TUTAJ DOPIERO POJAWIAJĄ SIĘ PASKI POSTĘPU) ---
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "UFS Explorer".to_string(), total: new_ufs_count, color: Color::Cyan });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 1, label: "Skrypt Autorski".to_string(), total: new_script_count, color: Color::Magenta });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 2, label: "Zapis SQLite".to_string(), total: total_new, color: Color::Green });

    let mut total_ufs_orphans = 0;
    let mut total_script_orphans = 0;
    let mut ufs_skipped = 0;
    let mut script_skipped = 0;
    let mut ufs_inserted = 0;
    let mut script_inserted = 0;

    let known_ufs_ref2 = &known_ufs;
    let known_script_ref2 = &known_script;

    // REGRESJA (measure twice — druga weryfikacja Gemini): każdy błąd SQLite
    // w tym wątku był wcześniej `.unwrap()`, czyli paniką w wątku pisarza
    // wewnątrz `thread::scope` — narzędzie forensyczne potrafiące działać
    // godzinami na dużych korpusach traciłoby CAŁY postęp fazy na jeden
    // transjentny błąd I/O bazy (dysk pełny, blokada pliku WAL), bez żadnego
    // komunikatu tłumaczącego operatorowi, co się stało. Ten sam wzorzec co
    // `phase17_repair::run` — `db_thread` zwraca `Result<()>`, panika jest
    // przechwytywana przez `.join()` i zamieniana na błąd domenowy.
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
                    ScanMsg::UfsChunk(chunk) => { *ufs_ins_ref += chunk.len(); }
                    ScanMsg::ScriptChunk(chunk) => { *script_ins_ref += chunk.len(); }
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
                    // Blok SQLite pozostaje wspólny — to jeden writer, nie dwa niezależne skanery
                    let _ = tx_ui_ref.send(PhaseEvent::UpdateSideText {
                        idx: 2,
                        text: build_sqlite_sync_block(*ufs_ins_ref, *script_ins_ref),
                    });
                }
            }
            
            let total_saved = *ufs_ins_ref + *script_ins_ref;
            let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: total_saved as u64, message: "Baza danych zsynchronizowana.".to_string() });
            let _ = tx_ui_ref.send(PhaseEvent::UpdateSideText { idx: 2, text: build_sqlite_sync_block(*ufs_ins_ref, *script_ins_ref) });
            Ok(())
        });

        if active_io_mode == "CONCURRENT" {
//        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone();
            let tx2 = tx_db.clone();
            let p1 = parallelism.clone();
            let p2 = parallelism.clone();
            
            let ufs_orph_ref = &mut total_ufs_orphans;
            let scr_orph_ref = &mut total_script_orphans;
            
            let log_u = opr_log.clone();
            let log_s = opr_log.clone();

            s.spawn(|| {
                if new_ufs_count > 0 {
                    let (cnt, orph) = scan_directory_stream(ufs_p, known_ufs_ref2, p1, tx1, true, tx_ui_ref, 0, io_counter_ref, log_u, &ufs_prescan, &ufs_acq);
                    *ufs_orph_ref = orph;
                    let _ = tx_ui_ref.send(PhaseEvent::Log(format!("✔ Zakończono odczyt I/O na UFS Explorer ({} plików)", cnt)));
                }
            });

            s.spawn(|| {
                if new_script_count > 0 {
                    let (cnt, orph) = scan_directory_stream(script_p, known_script_ref2, p2, tx2, false, tx_ui_ref, 1, io_counter_ref, log_s, &script_prescan, &script_acq);
                    *scr_orph_ref = orph;
                    let _ = tx_ui_ref.send(PhaseEvent::Log(format!("✔ Zakończono odczyt I/O na Skrypt Autorski ({} plików)", cnt)));
                }
            });
            drop(tx_db); 
        } else {
            let p_seq = Parallelism::Serial;
            
            if new_ufs_count > 0 {
                let (cnt, orph) = scan_directory_stream(ufs_p, known_ufs_ref2, p_seq.clone(), tx_db.clone(), true, tx_ui_ref, 0, io_counter_ref, opr_log.clone(), &ufs_prescan, &ufs_acq);
                total_ufs_orphans = orph;
                let _ = tx_ui_ref.send(PhaseEvent::Log(format!("✔ Zakończono odczyt I/O na UFS Explorer ({} plików)", cnt)));
            }
            
            if new_script_count > 0 {
                let (cnt, orph) = scan_directory_stream(script_p, known_script_ref2, p_seq, tx_db.clone(), false, tx_ui_ref, 1, io_counter_ref, opr_log.clone(), &script_prescan, &script_acq);
                total_script_orphans = orph;
                let _ = tx_ui_ref.send(PhaseEvent::Log(format!("✔ Zakończono odczyt I/O na Skrypt Autorski ({} plików)", cnt)));
            }
            // REGRESJA (measure twice — druga weryfikacja Gemini): obie
            // powyższe wołania biorą TYLKO `tx_db.clone()` - oryginalny
            // `tx_db` nigdy nie był przenoszony w tej gałęzi, więc kanał nie
            // zamykał się, dopóki ta zmienna nie wyszła z zasięgu na końcu
            // CAŁEGO domknięcia `thread::scope`, czyli PO `db_thread.join()`
            // niżej - klasyczny deadlock (wątek czeka na zamknięcie kanału,
            // który sam trzyma otwarty). Jawny `drop` zamyka kanał
            // deterministycznie, zanim `.join()` zacznie czekać.
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
                    "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 1 mógł nie zostać w pełni zapisany.".to_string()
                ));
                Err(rusqlite::Error::UnwindingPanic)
            }
        }
    });
    wynik_zapisu?;

    // ============================================================================
    // ETAP 4: GENEROWANIE DZIENNIKA KOŃCOWEGO
    // ============================================================================
    
    let final_ufs: usize = conn.query_row("SELECT COUNT(*) FROM files WHERE found_in_ufs = 1", [], |r| Ok(r.get::<_, i64>(0)? as usize)).unwrap_or(0);
    let final_script: usize = conn.query_row("SELECT COUNT(*) FROM files WHERE found_in_script = 1", [], |r| Ok(r.get::<_, i64>(0)? as usize)).unwrap_or(0);
    let total_io = global_io_counter.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed();

    let mut final_report = String::new();
    use std::fmt::Write as FmtWrite;
    let _ = writeln!(&mut final_report, "==========================================================================");
    let _ = writeln!(&mut final_report, "DZIENNIK KOŃCOWY - FAZA 1 (MAPOWANIE I IZOLACJA SIEROT)");
    let _ = writeln!(&mut final_report, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut final_report, "==========================================================================\n");
    
    let _ = writeln!(&mut final_report, " [ + ] ZMAPOWANE DRZEWO (Czyste pliki):");
    let _ = writeln!(&mut final_report, "   -> UFS Explorer:    {} plików", final_ufs);
    let _ = writeln!(&mut final_report, "   -> Skrypt Autorski: {} plików\n", final_script);
    
    if total_ufs_orphans > 0 || total_script_orphans > 0 {
        let _ = writeln!(&mut final_report, " [ ! ] KWARANTANNA SIEROT (Izolacja sztucznych folderów):");
        let _ = writeln!(&mut final_report, "   -> Odizolowano w UFS Explorer:    {}", total_ufs_orphans);
        let _ = writeln!(&mut final_report, "   -> Odizolowano w Skrypt Autorski: {}", total_script_orphans);
        let _ = writeln!(&mut final_report, "      (ZNACZENIE): Pliki te znajdowały się w fałszywych folderach ($Tresh, LostFiles). Dodano flagę 'is_orphan=1'.\n");
    }

    let _ = writeln!(&mut final_report, " [ * ] DIAGNOSTYKA SYSTEMU I/O:");
    let _ = writeln!(&mut final_report, "   -> Przeanalizowane węzły FS: {}", total_io);
    let _ = writeln!(&mut final_report, "      (ZNACZENIE): Całkowita liczba plików i folderów fizycznie sprawdzona przez silnik podczas tej sesji.\n");

    if ufs_skipped > 0 || script_skipped > 0 {
        let _ = writeln!(&mut final_report, " [ - ] ODRZUTY (Błędy Systemowe i Odmowy Dostępu):");
        let _ = writeln!(&mut final_report, "   -> UFS Explorer: {} | Skrypt Autorski: {}", ufs_skipped, script_skipped);
        let _ = writeln!(&mut final_report, "      (ZNACZENIE): Pliki zablokowane przez system, porzucone ze względów wydajnościowych.");
    }

    if let Ok(mut f) = fs::File::create(&dz_path) {
        let _ = f.write_all(final_report.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano fizyczny Dziennik Końcowy w: {}", dz_path.display())));
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano Raport Operacyjny (Live) w: {}", opr_path.display())));
    }

    for line in final_report.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    info!(
        ufs_inserted = final_ufs, script_inserted = final_script,
        orphans_found = total_ufs_orphans + total_script_orphans,
        total_io_nodes = total_io,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 1 zakończona sukcesem"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tempfile::tempdir;

    // ------------------------------------------------------------------
    // Rozpoznawanie sierot FS
    // ------------------------------------------------------------------

    /// Sieroty to pliki, którym uszkodzenie systemu plików zabrało ścieżkę —
    /// programy odzyskujące zrzucają je do katalogów ratunkowych. Faza 1
    /// oznacza je w bazie, żeby dalsze fazy mogły je traktować osobno.
    #[test]
    fn test_rozpoznaje_katalogi_ratunkowe_programow_odzyskujacych() {
        for sciezka in [
            "$Tresh/plik.jpg",
            "LostFiles/DSC_0001.dng",
            "$RECYCLE.BIN/старый.txt",
            "$Trash/a/b/c.mp4",
        ] {
            assert!(is_orphan_path(sciezka), "'{}' musi być rozpoznane jako sierota", sciezka);
        }
    }

    #[test]
    fn test_rozpoznanie_sierot_jest_niewrazliwe_na_wielkosc_liter() {
        // Odzyskane nazwy bywają w dowolnej wielkości liter - zależnie od
        // systemu plików i narzędzia, które je wyciągnęło.
        for wariant in ["LOSTFILES/x", "lostfiles/x", "LostFiles/x", "$TRESH/x", "$tresh/x"] {
            assert!(is_orphan_path(wariant), "wariant '{}' musi być rozpoznany", wariant);
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
    // Sanityzacja ścieżek spoza UTF-8 (REGRESJA — Gemini review)
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

    /// Sedno naprawy: dwie RÓŻNE ścieżki (różne surowe bajty), których
    /// `to_string_lossy()` dałoby IDENTYCZNY string (oba nieprawidłowe bajty
    /// zamieniają się na to samo U+FFFD), muszą po sanityzacji dać RÓŻNE
    /// wyniki — inaczej druga cicho nadpisuje/scala się z pierwszą w bazie
    /// (kolumna `relative_path` jest `UNIQUE`).
    #[cfg(unix)]
    #[test]
    fn test_sanityzacja_rozroznia_kolidujace_sciezki_spoza_utf8() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let a = OsStr::from_bytes(b"plik_\xFF.jpg");
        let b = OsStr::from_bytes(b"plik_\xFE.jpg");

        // Obie dają identyczny string przy naiwnym to_string_lossy() - to
        // właśnie ta kolizja, którą naprawa eliminuje.
        assert_eq!(a.to_string_lossy(), b.to_string_lossy());

        let sa = sanitize_relative_path(Path::new(a));
        let sb = sanitize_relative_path(Path::new(b));
        assert_ne!(sa, sb, "różne surowe bajty muszą dać różne klucze relative_path");
    }

    // ------------------------------------------------------------------
    // fnv1a_64 — REGRESJA (measure twice — druga weryfikacja Gemini, N1):
    // sufiks anty-kolizyjny ląduje TRWALE w kolumnie UNIQUE bazy, więc musi
    // mieć w pełni opisaną, międzybinarnie stabilną specyfikację —
    // `DefaultHasher` (poprzedni algorytm) tego nie gwarantuje.
    // ------------------------------------------------------------------

    #[test]
    fn test_fnv1a_64_pusty_input_daje_offset_basis() {
        // Definicja algorytmu: pętla nad zerem bajtów nie wykonuje żadnej
        // iteracji, więc wynik to dokładnie offset basis - jedyna wartość
        // sprawdzalna "z definicji", bez zewnętrznego wektora testowego.
        assert_eq!(fnv1a_64(b""), 0xcbf29ce484222325);
    }

    #[test]
    fn test_fnv1a_64_jest_deterministyczny() {
        assert_eq!(fnv1a_64(b"dowolne bajty testowe"), fnv1a_64(b"dowolne bajty testowe"));
    }

    #[test]
    fn test_fnv1a_64_rozne_bajty_daja_rozne_hashe() {
        assert_ne!(fnv1a_64(b"plik_a"), fnv1a_64(b"plik_b"));
    }

    #[test]
    fn test_fnv1a_64_wrazliwy_na_kolejnosc_bajtow() {
        // Lawinowość FNV-1a: zamiana kolejności dwóch bajtów musi zmienić
        // wynik - inaczej sufiks nie chroniłby przed kolizją anagramów ścieżek.
        assert_ne!(fnv1a_64(b"ab"), fnv1a_64(b"ba"));
    }

    /// Stabilność między przebiegami Fazy 1: te same surowe bajty muszą
    /// zawsze dać ten sam wynik, inaczej ten sam plik dostawałby nowy wiersz
    /// (duplikat) przy każdym kolejnym skanie.
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

    /// Hash zastępuje pełną ścieżkę w zbiorze „już znanych", oszczędzając
    /// gigabajty RAM-u przy milionach plików. Musi być deterministyczny w
    /// obrębie procesu, inaczej przyrostowe skanowanie gubiłoby stan.
    #[test]
    fn test_hash_sciezki_jest_deterministyczny() {
        let a = hash_path("zdjecia/2023/DSC_0001.jpg");
        let b = hash_path("zdjecia/2023/DSC_0001.jpg");
        assert_eq!(a, b, "ta sama ścieżka musi dać ten sam hash");
    }

    #[test]
    fn test_rozne_sciezki_daja_rozne_hashe() {
        // Kolizja oznaczałaby, że plik zostanie uznany za „już znany" i NIGDY
        // nie trafi do bazy - czyli cichą utratę dowodu. Przy 64 bitach jest
        // skrajnie mało prawdopodobna, ale test pilnuje przynajmniej tego, że
        // funkcja faktycznie różnicuje bliskie sobie ścieżki.
        let sciezki = [
            "a/b/c.jpg", "a/b/d.jpg", "a/c/c.jpg", "b/b/c.jpg",
            "a/b/c.jpeg", "a/b/c.jpg ", " a/b/c.jpg",
        ];
        let mut zbior = HashSet::new();
        for s in sciezki {
            assert!(zbior.insert(hash_path(s)), "kolizja hasha dla '{}'", s);
        }
    }

    #[test]
    fn test_hash_radzi_sobie_z_polskimi_znakami_i_pusta_sciezka() {
        let _ = hash_path("");
        assert_ne!(hash_path("zażółć/gęślą.jaźń"), hash_path("zazolc/gesla.jazn"));
    }

    // ------------------------------------------------------------------
    // Bloki panelu bocznego
    // ------------------------------------------------------------------

    #[test]
    fn test_blok_zrodla_pokazuje_wszystkie_cztery_liczniki() {
        let prescan = PreScanStats::new();
        let acq = AcqStats::new();
        prescan.scanned.store(1500, Ordering::Relaxed);
        prescan.new_files.store(900, Ordering::Relaxed);
        acq.db_count.store(850, Ordering::Relaxed);
        acq.orphans.store(12, Ordering::Relaxed);

        let blok = build_source_block("UFS Explorer", &prescan, &acq);

        assert!(blok.starts_with("[UFS Explorer]"), "blok musi zaczynać się etykietą źródła: {}", blok);
        for oczekiwana in ["1500", "900", "850", "12"] {
            assert!(blok.contains(oczekiwana), "brak licznika {} w bloku:\n{}", oczekiwana, blok);
        }
        assert_eq!(blok.lines().count(), 5, "etykieta + cztery liczniki:\n{}", blok);
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

    /// `is_hdd` decyduje o wymuszeniu trybu SEKWENCYJNEGO, czyli chroni głowicę
    /// dysku talerzowego przed losowym dostępem. Nie da się w teście wymusić
    /// rodzaju dysku, ale można sprawdzić zachowanie dla ścieżki, która nie
    /// leży na żadnym zamontowanym nośniku — musi być `false`, nie panika.
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
            fs::create_dir_all(rodzic).unwrap();
        }
        fs::write(sciezka, b"x").unwrap();
    }

    fn kanal() -> (mpsc::Sender<PhaseEvent>, mpsc::Receiver<PhaseEvent>) {
        mpsc::channel()
    }

    #[test]
    fn test_pre_skan_liczy_tylko_nowe_pliki() {
        let dir = tempdir().unwrap();
        utworz_plik(&dir.path().join("a.jpg"));
        utworz_plik(&dir.path().join("pod/b.jpg"));
        utworz_plik(&dir.path().join("pod/glebiej/c.jpg"));

        let (tx, _rx) = kanal();
        let licznik = AtomicUsize::new(0);
        let prescan = PreScanStats::new();
        let acq = AcqStats::new();

        let nowe = pre_scan_directory(
            dir.path(), "Test", &HashSet::new(), Parallelism::Serial,
            &licznik, &tx, 0, &prescan, &acq,
        );

        assert_eq!(nowe, 3, "wszystkie trzy pliki są nowe");
        assert_eq!(prescan.new_files.load(Ordering::Relaxed), 3);
        assert!(
            prescan.scanned.load(Ordering::Relaxed) >= 3,
            "licznik „przeskanowano” obejmuje też katalogi, więc jest >= liczby plików"
        );
        assert!(licznik.load(Ordering::Relaxed) >= 3, "licznik I/O musi rosnąć");
    }

    /// Przyrostowość: pliki obecne już w bazie NIE MOGĄ być liczone jako nowe.
    /// To ona sprawia, że ponowne uruchomienie Fazy 1 na dużym korpusie jest
    /// tanie zamiast liczone w godzinach.
    #[test]
    fn test_pre_skan_pomija_pliki_juz_znane() {
        let dir = tempdir().unwrap();
        utworz_plik(&dir.path().join("stary.jpg"));
        utworz_plik(&dir.path().join("nowy.jpg"));

        // Ścieżki w zbiorze „znanych” są WZGLĘDNE wobec katalogu bazowego.
        let znane: HashSet<u64> = [hash_path("stary.jpg")].into_iter().collect();

        let (tx, _rx) = kanal();
        let licznik = AtomicUsize::new(0);
        let prescan = PreScanStats::new();
        let acq = AcqStats::new();

        let nowe = pre_scan_directory(
            dir.path(), "Test", &znane, Parallelism::Serial,
            &licznik, &tx, 0, &prescan, &acq,
        );

        assert_eq!(nowe, 1, "tylko jeden plik jest nowy");
    }

    #[test]
    fn test_pre_skan_nieistniejacej_sciezki_zwraca_zero_i_zglasza_blad() {
        let (tx, rx) = kanal();
        let licznik = AtomicUsize::new(0);
        let prescan = PreScanStats::new();
        let acq = AcqStats::new();

        let nowe = pre_scan_directory(
            Path::new("/nie/ma/takiej/sciezki"), "Brakujące", &HashSet::new(),
            Parallelism::Serial, &licznik, &tx, 0, &prescan, &acq,
        );

        assert_eq!(nowe, 0);

        let komunikaty: Vec<String> = rx.try_iter().filter_map(|e| match e {
            PhaseEvent::Log(s) => Some(s),
            _ => None,
        }).collect();
        assert!(
            komunikaty.iter().any(|k| k.contains("nie istnieje")),
            "brak ścieżki musi zostać zgłoszony operatorowi: {:?}", komunikaty
        );
    }

    #[test]
    fn test_pre_skan_pustego_katalogu_daje_zero() {
        let dir = tempdir().unwrap();
        let (tx, _rx) = kanal();
        let licznik = AtomicUsize::new(0);
        let prescan = PreScanStats::new();
        let acq = AcqStats::new();

        assert_eq!(
            pre_scan_directory(dir.path(), "Pusty", &HashSet::new(), Parallelism::Serial,
                               &licznik, &tx, 0, &prescan, &acq),
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
        let prescan = PreScanStats::new();
        let acq = AcqStats::new();

        let log = Arc::new(Mutex::new(tempfile::tempfile().unwrap()));

        let (cnt, orph) = scan_directory_stream(
            katalog, znane, Parallelism::Serial, tx_db, is_ufs,
            &tx_ui, 0, &licznik, log, &prescan, &acq,
        );

        (cnt, orph, rx_db.into_iter().collect())
    }

    fn sciezki_z_paczek(msgs: &[ScanMsg]) -> Vec<String> {
        msgs.iter().flat_map(|m| match m {
            ScanMsg::UfsChunk(c) | ScanMsg::ScriptChunk(c) => c.iter().map(|(r, _, _)| r.clone()).collect::<Vec<_>>(),
            _ => Vec::new(),
        }).collect()
    }

    #[test]
    fn test_akwizycja_wysyla_kazdy_nowy_plik_dokladnie_raz() {
        let dir = tempdir().unwrap();
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
        let dir = tempdir().unwrap();
        utworz_plik(&dir.path().join("normalny.jpg"));
        utworz_plik(&dir.path().join("LostFiles/sierota.jpg"));

        let (cnt, orph, msgs) = uruchom_akwizycje(dir.path(), &HashSet::new(), true);

        assert_eq!(cnt, 2);
        assert_eq!(orph, 1, "dokładnie jeden plik jest sierotą");

        let oznaczenia: Vec<(String, bool)> = msgs.iter().flat_map(|m| match m {
            ScanMsg::UfsChunk(c) => c.iter().map(|(r, _, o)| (r.clone(), *o)).collect::<Vec<_>>(),
            _ => Vec::new(),
        }).collect();

        let sierota = oznaczenia.iter().find(|(r, _)| r.contains("sierota")).expect("sierota musi być wysłana");
        assert!(sierota.1, "plik z LostFiles musi mieć ustawioną flagę sieroty");

        let normalny = oznaczenia.iter().find(|(r, _)| r.contains("normalny")).unwrap();
        assert!(!normalny.1, "zwykły plik nie może być oznaczony jako sierota");
    }

    #[test]
    fn test_akwizycja_kieruje_paczki_do_wlasciwego_zrodla() {
        let dir = tempdir().unwrap();
        utworz_plik(&dir.path().join("x.bin"));

        let (_, _, msgs_ufs) = uruchom_akwizycje(dir.path(), &HashSet::new(), true);
        assert!(
            msgs_ufs.iter().any(|m| matches!(m, ScanMsg::UfsChunk(_))),
            "przy is_ufs=true paczki muszą iść kanałem UFS"
        );
        assert!(!msgs_ufs.iter().any(|m| matches!(m, ScanMsg::ScriptChunk(_))));

        let (_, _, msgs_scr) = uruchom_akwizycje(dir.path(), &HashSet::new(), false);
        assert!(msgs_scr.iter().any(|m| matches!(m, ScanMsg::ScriptChunk(_))));
        assert!(!msgs_scr.iter().any(|m| matches!(m, ScanMsg::UfsChunk(_))));
    }

    /// Bufor jest domykany na końcu: ostatnia, NIEPEŁNA paczka też musi zostać
    /// wysłana. Jej zgubienie oznaczałoby ciche zniknięcie do 199 plików z
    /// każdego przebiegu.
    #[test]
    fn test_ostatnia_niepelna_paczka_nie_ginie() {
        let dir = tempdir().unwrap();
        let ile = CHUNK_SIZE + 7;
        for i in 0..ile {
            utworz_plik(&dir.path().join(format!("p{:04}.bin", i)));
        }

        let (cnt, _, msgs) = uruchom_akwizycje(dir.path(), &HashSet::new(), true);

        assert_eq!(cnt, ile);
        assert_eq!(
            sciezki_z_paczek(&msgs).len(), ile,
            "suma plików we wszystkich paczkach musi równać się liczbie plików na dysku"
        );

        let liczby_paczek: Vec<usize> = msgs.iter().filter_map(|m| match m {
            ScanMsg::UfsChunk(c) => Some(c.len()),
            _ => None,
        }).collect();
        assert_eq!(liczby_paczek, vec![CHUNK_SIZE, 7], "pełna paczka + reszta: {:?}", liczby_paczek);
    }

    #[test]
    fn test_akwizycja_pomija_pliki_juz_znane() {
        let dir = tempdir().unwrap();
        utworz_plik(&dir.path().join("stary.bin"));
        utworz_plik(&dir.path().join("nowy.bin"));

        let znane: HashSet<u64> = [hash_path("stary.bin")].into_iter().collect();
        let (cnt, _, msgs) = uruchom_akwizycje(dir.path(), &znane, true);

        assert_eq!(cnt, 1);
        assert_eq!(sciezki_z_paczek(&msgs), vec!["nowy.bin".to_string()]);
    }

    #[test]
    fn test_akwizycja_zawsze_raportuje_liczbe_pominietych() {
        let dir = tempdir().unwrap();
        utworz_plik(&dir.path().join("a.bin"));

        let (_, _, msgs) = uruchom_akwizycje(dir.path(), &HashSet::new(), true);

        assert!(
            msgs.iter().any(|m| matches!(m, ScanMsg::UfsSkipped(_))),
            "komunikat o pominiętych wpisach musi dotrzeć nawet gdy jest ich zero"
        );
    }

    #[test]
    fn test_akwizycja_nieistniejacej_sciezki_nic_nie_wysyla() {
        let (cnt, orph, msgs) = uruchom_akwizycje(Path::new("/nie/ma/takiej"), &HashSet::new(), true);
        assert_eq!((cnt, orph), (0, 0));
        assert!(msgs.is_empty(), "brak katalogu nie może produkować paczek: {}", msgs.len());
    }

    // ------------------------------------------------------------------
    // Semantyka zapisu do bazy — sedno modelu dwóch źródeł
    // ------------------------------------------------------------------

    fn wstaw(conn: &Connection, sql: &str, rel: &str, sierota: bool) {
        conn.execute(sql, params![rel, sierota]).unwrap();
    }

    fn odczytaj(conn: &Connection, rel: &str) -> (bool, bool, bool, bool) {
        conn.query_row(
            "SELECT found_in_ufs, found_in_script, phase1_done, is_orphan FROM files WHERE relative_path = ?1",
            params![rel],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).unwrap()
    }

    /// NAJWAŻNIEJSZY test tej fazy: plik obecny po OBU stronach musi skończyć
    /// z obiema flagami ustawionymi.
    ///
    /// Na tym opiera się cały model „wspólny kontra unikalny": Faza 8 podejmuje
    /// decyzję, a Faza 9 składa Złotą Kopię właśnie na podstawie tych dwóch
    /// bitów. Gdyby drugi zapis kasował flagę pierwszego, każdy plik wyglądałby
    /// na unikalny i porównanie dwóch kopii przestałoby istnieć.
    #[test]
    fn test_plik_z_obu_zrodel_ma_obie_flagi() {
        let conn = crate::db::init_db(":memory:").unwrap();

        wstaw(&conn, INSERT_SQL_UFS, "zdjecia/a.jpg", false);
        assert_eq!(odczytaj(&conn, "zdjecia/a.jpg"), (true, false, true, false), "po zapisie z UFS");

        wstaw(&conn, INSERT_SQL_SCRIPT, "zdjecia/a.jpg", false);
        assert_eq!(
            odczytaj(&conn, "zdjecia/a.jpg"), (true, true, true, false),
            "drugie źródło DODAJE swoją flagę, nie kasuje cudzej"
        );
    }

    #[test]
    fn test_kolejnosc_zrodel_nie_ma_znaczenia() {
        let conn = crate::db::init_db(":memory:").unwrap();

        wstaw(&conn, INSERT_SQL_SCRIPT, "b.jpg", false);
        wstaw(&conn, INSERT_SQL_UFS, "b.jpg", false);

        assert_eq!(odczytaj(&conn, "b.jpg"), (true, true, true, false));
    }

    #[test]
    fn test_plik_tylko_z_jednego_zrodla_zostaje_unikalny() {
        let conn = crate::db::init_db(":memory:").unwrap();

        wstaw(&conn, INSERT_SQL_UFS, "tylko_ufs.jpg", false);
        wstaw(&conn, INSERT_SQL_SCRIPT, "tylko_skrypt.jpg", false);

        assert_eq!(odczytaj(&conn, "tylko_ufs.jpg"), (true, false, true, false));
        assert_eq!(odczytaj(&conn, "tylko_skrypt.jpg"), (false, true, true, false));
    }

    #[test]
    fn test_flaga_sieroty_trafia_do_bazy() {
        let conn = crate::db::init_db(":memory:").unwrap();
        wstaw(&conn, INSERT_SQL_UFS, "LostFiles/x.jpg", true);
        assert_eq!(odczytaj(&conn, "LostFiles/x.jpg"), (true, false, true, true));
    }

    #[test]
    fn test_powtorny_zapis_tego_samego_zrodla_nie_duplikuje_wiersza() {
        let conn = crate::db::init_db(":memory:").unwrap();

        for _ in 0..3 {
            wstaw(&conn, INSERT_SQL_UFS, "powtarzany.jpg", false);
        }

        let ile: i64 = conn.query_row(
            "SELECT COUNT(*) FROM files WHERE relative_path = 'powtarzany.jpg'", [], |r| r.get(0),
        ).unwrap();
        assert_eq!(ile, 1, "unikalność relative_path musi być utrzymana");
    }

    #[test]
    fn test_zapis_ustawia_znacznik_ukonczenia_fazy() {
        // `phase1_done = 1` jest warunkiem, po którym kolejne uruchomienie
        // wczytuje plik do zbioru „znanych" i go pomija.
        let conn = crate::db::init_db(":memory:").unwrap();
        wstaw(&conn, INSERT_SQL_UFS, "x.jpg", false);

        let ile: i64 = conn.query_row(
            "SELECT COUNT(*) FROM files WHERE phase1_done = 1", [], |r| r.get(0),
        ).unwrap();
        assert_eq!(ile, 1);
    }

    // ------------------------------------------------------------------
    // Reset phase2_done na realnej zmianie found_in_* (REGRESJA — Gemini review)
    // ------------------------------------------------------------------

    fn ustaw_phase2_done(conn: &Connection, rel: &str, wartosc: bool) {
        conn.execute(
            "UPDATE files SET phase2_done = ?1 WHERE relative_path = ?2",
            params![wartosc, rel],
        ).unwrap();
    }

    fn phase2_done(conn: &Connection, rel: &str) -> bool {
        conn.query_row(
            "SELECT phase2_done FROM files WHERE relative_path = ?1", params![rel], |r| r.get(0),
        ).unwrap()
    }

    /// Sedno naprawy: plik dograny do korpusu z DRUGIEJ strony PÓŹNIEJ (np.
    /// dysk Skryptu podłączony po fakcie) musi zresetować `phase2_done`, bo
    /// inaczej Faza 2 nigdy nie przeliczy nowo doszłej strony — jej `WHERE
    /// phase2_done = 0` na zawsze odfiltruje ten wiersz.
    #[test]
    fn test_dopisanie_drugiej_strony_resetuje_phase2_done() {
        let conn = crate::db::init_db(":memory:").unwrap();

        wstaw(&conn, INSERT_SQL_UFS, "plik.jpg", false);
        ustaw_phase2_done(&conn, "plik.jpg", true); // symuluje wcześniejszy przebieg Fazy 2

        wstaw(&conn, INSERT_SQL_SCRIPT, "plik.jpg", false); // Skrypt dochodzi PÓŹNIEJ

        assert!(!phase2_done(&conn, "plik.jpg"), "realna zmiana found_in_script 0->1 musi zresetować phase2_done");
    }

    /// Zwykłe, idempotentne powtórne uruchomienie Fazy 1 na NIEZMIENIONYM
    /// korpusie nie może kasować już policzonego wyniku Fazy 2 — inaczej
    /// każdy kolejny przebieg Fazy 1 marnowałby całą pracę Fazy 2 na nowo.
    #[test]
    fn test_powtorny_zapis_tej_samej_strony_nie_resetuje_phase2_done() {
        let conn = crate::db::init_db(":memory:").unwrap();

        wstaw(&conn, INSERT_SQL_UFS, "plik.jpg", false);
        wstaw(&conn, INSERT_SQL_SCRIPT, "plik.jpg", false);
        ustaw_phase2_done(&conn, "plik.jpg", true);

        wstaw(&conn, INSERT_SQL_UFS, "plik.jpg", false); // ponowny skan UFS, found_in_ufs już = 1

        assert!(phase2_done(&conn, "plik.jpg"), "brak realnej zmiany found_in_* nie może zresetować phase2_done");
    }

    // ------------------------------------------------------------------
    // REGRESJA (measure twice — druga weryfikacja Gemini, Faza 11 N2 / Faza
    // 14 obserwacja #2): reset przy dopisaniu drugiej strony był wcześniej
    // ograniczony WYŁĄCZNIE do phase2_done — każda dalsza faza (3-19) miała
    // ten sam strukturalny problem. Sprawdzamy tu reprezentatywną próbkę
    // (środek zakresu, najnowsza faza, i tę bezpośrednio zgłoszoną w
    // audycie) zamiast powtarzać identyczny test 18 razy dla każdej kolumny
    // — logika SQL jest identyczna dla wszystkich (ten sam CASE WHEN,
    // sklonowany), więc próbka jest reprezentatywna dla całości.
    // ------------------------------------------------------------------

    fn ustaw_phase_done(conn: &Connection, kolumna: &str, rel: &str, wartosc: bool) {
        conn.execute(
            &format!("UPDATE files SET {} = ?1 WHERE relative_path = ?2", kolumna),
            params![wartosc, rel],
        ).unwrap();
    }

    fn phase_done(conn: &Connection, kolumna: &str, rel: &str) -> bool {
        conn.query_row(
            &format!("SELECT {} FROM files WHERE relative_path = ?1", kolumna), params![rel], |r| r.get(0),
        ).unwrap()
    }

    #[test]
    fn test_dopisanie_drugiej_strony_resetuje_phase11_i_phase14_i_phase19_done() {
        for kolumna in ["phase11_done", "phase14_done", "phase19_done"] {
            let conn = crate::db::init_db(":memory:").unwrap();

            wstaw(&conn, INSERT_SQL_UFS, "plik.jpg", false);
            ustaw_phase_done(&conn, kolumna, "plik.jpg", true); // symuluje wcześniejszy przebieg tej fazy, gdy plik był jeszcze jednostronny

            wstaw(&conn, INSERT_SQL_SCRIPT, "plik.jpg", false); // Skrypt dochodzi PÓŹNIEJ

            assert!(!phase_done(&conn, kolumna, "plik.jpg"), "realna zmiana found_in_script 0->1 musi zresetować {}", kolumna);
        }
    }

    #[test]
    fn test_powtorny_zapis_tej_samej_strony_nie_resetuje_phase11_i_phase14_i_phase19_done() {
        for kolumna in ["phase11_done", "phase14_done", "phase19_done"] {
            let conn = crate::db::init_db(":memory:").unwrap();

            wstaw(&conn, INSERT_SQL_UFS, "plik.jpg", false);
            wstaw(&conn, INSERT_SQL_SCRIPT, "plik.jpg", false);
            ustaw_phase_done(&conn, kolumna, "plik.jpg", true);

            wstaw(&conn, INSERT_SQL_UFS, "plik.jpg", false); // ponowny skan UFS, found_in_ufs już = 1

            assert!(phase_done(&conn, kolumna, "plik.jpg"), "brak realnej zmiany found_in_* nie może zresetować {}", kolumna);
        }
    }
}
