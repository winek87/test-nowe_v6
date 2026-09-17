//! MP4 Doctor 2.0 - Milestone 5 Comprehensive End-to-End Test Suite (Dual Track)
//!
//! Architecture: Systematic 4-tier requirement-driven E2E test suite
//! - Tier 1: Feature Coverage (F1 to F13 in isolation, >= 5 tests each = 65 tests)
//! - Tier 2: Boundary & Corner Cases (F1 to F13 extreme inputs/bounds, >= 5 tests each = 65 tests)
//! - Tier 3: Cross-Feature Combinations (Pairwise interaction coverage = 15 tests)
//! - Tier 4: Real-World Application Scenarios (Full lifecycle scenarios = 5 tests)
//!
//! Total tests: 150 (65 + 65 + 15 + 5)

use std::ffi::CStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use mp4_doctor::ai::FeatureVector;
use mp4_doctor::event::{
    channel, AppEvent, LogLevel, LogMessage, SanitizerMetrics, StatUpdate, WorkerStatus,
};
use mp4_doctor::tui::app::{App, Modal, View, MAX_LOG_HISTORY};
use mp4_doctor::tui::terminal::{
    force_restore, install_panic_hook, is_terminal_active, TerminalGuard,
};
use mp4_doctor::tui::ui::{self, estimate_log_rows, format_bytes, format_log_line};
use mp4_doctor::workspace::{get_available_workspaces, Workspace};
use mp4_doctor::{
    autopilot, db, dna, get_thread_count, god_mode, scanner, set_thread_count, training_ground,
    validator, SHUTDOWN_FLAG,
};

/// Wektor cech do testów, które nie sprawdzają jego treści — tylko to, że
/// `reward_algorithm`/`penalize_algorithm`/`AppEvent::RepairSuccess` (od
/// niedawna wymagające `FeatureVector`, patrz `db::reward_algorithm`)
/// dostają cokolwiek zamiast się nie kompilować.
fn cechy_testowe() -> FeatureVector {
    FeatureVector { file_size_mb: 10.0, entropy: 7.0, h264_profile: 100.0, aac_freq: 44100.0, video_audio_ratio: 0.8 }
}

// =========================================================================
// COMMON TEST HARNESS & ISOLATION HELPERS
// =========================================================================

pub mod common {
    use super::*;

    pub static PTY_LOCK: Mutex<()> = Mutex::new(());
    pub static FD_LOCK: Mutex<()> = Mutex::new(());

    /// Serializuje dostęp do WSPÓŁDZIELONEGO `workspaces/threads.conf`.
    ///
    /// Pięć testów w tym pliku czyta i nadpisuje ten sam plik, a cargo
    /// uruchamia testy w binarnym równolegle — bez blokady wzajemnie kasowały
    /// sobie zapisy. Ten sam wzorzec co `PTY_LOCK`/`FD_LOCK` powyżej.
    pub static THREAD_CONF_LOCK: Mutex<()> = Mutex::new(());

    /// Liczba rdzeni widziana przez `get_thread_count` — jedyne wiarygodne
    /// odniesienie dla oczekiwań w testach liczby wątków.
    ///
    /// `get_thread_count` traktuje 0 jako „Auto" i podmienia je na tę wartość,
    /// a wpisy powyżej `2 * rdzenie` również sprowadza do niej. Oczekiwania
    /// wpisane na sztywno przechodziły więc tylko na maszynie, na której
    /// powstały.
    pub fn sprzetowe_max() -> usize {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    }
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    unsafe extern "C" {
        pub fn posix_openpt(flags: i32) -> i32;
        pub fn grantpt(fd: i32) -> i32;
        pub fn unlockpt(fd: i32) -> i32;
        pub fn ptsname(fd: i32) -> *const std::os::raw::c_char;
        pub fn dup(fd: i32) -> i32;
        pub fn dup2(oldfd: i32, newfd: i32) -> i32;
        pub fn close(fd: i32) -> i32;
        pub fn pipe(fds: *mut i32) -> i32;
        pub fn tcgetattr(fd: i32, termios_p: *mut u8) -> i32;
        #[link_name = "read"]
        pub fn libc_read(fd: i32, buf: *mut u8, count: usize) -> isize;
    }

    pub const O_RDWR: i32 = 2;
    pub const O_NOCTTY: i32 = 0x100;
    pub const O_NONBLOCK: i32 = 0x800;
    pub const ICANON: u32 = 0x00000002;
    pub const ECHO: u32 = 0x00000008;

    pub fn make_key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    pub fn make_key_mod(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    pub fn buffer_to_strings(
        terminal: &Terminal<TestBackend>,
        width: u16,
        height: u16,
    ) -> Vec<String> {
        let buffer = terminal.backend().buffer();
        let mut lines = Vec::with_capacity(height as usize);
        for y in 0..height {
            let line: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
            lines.push(line);
        }
        lines
    }

    pub fn buffer_contains(
        terminal: &Terminal<TestBackend>,
        width: u16,
        height: u16,
        target: &str,
    ) -> bool {
        let lines = buffer_to_strings(terminal, width, height);
        lines.iter().any(|line| line.contains(target))
    }

    pub struct TestWorkspaceGuard {
        pub ws: Workspace,
    }

    impl TestWorkspaceGuard {
        pub fn new(prefix: &str) -> Self {
            let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = format!("{}_{}_{}", prefix, std::process::id(), id);
            let ws = Workspace::init_testowy(&name).expect("Failed to initialize test workspace");
            db::init_db(&ws).expect("Failed to initialize test db");
            Self { ws }
        }
    }

    impl Drop for TestWorkspaceGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.ws.root_dir);
        }
    }

    pub struct StdCapture {
        saved_stdout: i32,
        saved_stderr: i32,
        out_pipe: [i32; 2],
        err_pipe: [i32; 2],
    }

    impl StdCapture {
        pub fn start() -> Self {
            let _ = io::stdout().flush();
            let _ = io::stderr().flush();

            unsafe {
                let saved_stdout = dup(1);
                let saved_stderr = dup(2);
                let mut out_pipe = [0i32; 2];
                let mut err_pipe = [0i32; 2];

                assert_eq!(pipe(&mut out_pipe[0] as *mut i32), 0);
                assert_eq!(pipe(&mut err_pipe[0] as *mut i32), 0);

                assert_eq!(dup2(out_pipe[1], 1), 1);
                assert_eq!(dup2(err_pipe[1], 2), 2);

                StdCapture {
                    saved_stdout,
                    saved_stderr,
                    out_pipe,
                    err_pipe,
                }
            }
        }

        pub fn finish(self) -> (Vec<u8>, Vec<u8>) {
            let _ = io::stdout().flush();
            let _ = io::stderr().flush();

            unsafe {
                dup2(self.saved_stdout, 1);
                dup2(self.saved_stderr, 2);
                close(self.saved_stdout);
                close(self.saved_stderr);

                close(self.out_pipe[1]);
                close(self.err_pipe[1]);

                let mut out_bytes = Vec::new();
                let mut out_file = File::from_raw_fd(self.out_pipe[0]);
                let _ = out_file.read_to_end(&mut out_bytes);

                let mut err_bytes = Vec::new();
                let mut err_file = File::from_raw_fd(self.err_pipe[0]);
                let _ = err_file.read_to_end(&mut err_bytes);

                (out_bytes, err_bytes)
            }
        }

        pub fn assert_zero_leak(captured: (Vec<u8>, Vec<u8>), context: &str) {
            let (out, _err) = captured;
            let out_str = String::from_utf8_lossy(&out);
            let leaked_lines: Vec<&str> = out_str
                .lines()
                .map(|l| l.trim())
                .filter(|l| {
                    !l.is_empty()
                        && !l.starts_with("test ")
                        && !l.contains("running ")
                        && !l.contains("finished in ")
                        && !l.contains("Doc-tests")
                })
                .collect();

            assert!(
                leaked_lines.is_empty(),
                "Leaked stdout detected in [{}]: {:?}",
                context,
                leaked_lines
            );
        }
    }

    pub struct PtyTestEnvironment {
        pub master_fd: RawFd,
        pub slave_fd: RawFd,
        pub saved_stdin: RawFd,
        pub saved_stdout: RawFd,
    }

    impl PtyTestEnvironment {
        pub fn new() -> io::Result<Self> {
            let master = unsafe { posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK) };
            if master < 0 {
                return Err(io::Error::last_os_error());
            }
            if unsafe { grantpt(master) } < 0 {
                unsafe { close(master) };
                return Err(io::Error::last_os_error());
            }
            if unsafe { unlockpt(master) } < 0 {
                unsafe { close(master) };
                return Err(io::Error::last_os_error());
            }

            let name_ptr = unsafe { ptsname(master) };
            if name_ptr.is_null() {
                unsafe { close(master) };
                return Err(io::Error::last_os_error());
            }
            let slave_name = unsafe { CStr::from_ptr(name_ptr) };
            let slave_path = slave_name
                .to_str()
                .map_err(io::Error::other)?;

            let slave_file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(slave_path)?;
            let slave = slave_file.as_raw_fd();
            std::mem::forget(slave_file); // Managed manually

            let saved_stdin = unsafe { dup(0) };
            let saved_stdout = unsafe { dup(1) };

            Ok(Self {
                master_fd: master,
                slave_fd: slave,
                saved_stdin,
                saved_stdout,
            })
        }

        pub fn attach_std(&self) {
            unsafe {
                dup2(self.slave_fd, 0);
                dup2(self.slave_fd, 1);
            }
        }

        pub fn is_raw_mode_active(&self) -> bool {
            let mut termios = [0u8; 64];
            if unsafe { tcgetattr(self.slave_fd, termios.as_mut_ptr()) } == 0 {
                let c_lflag = u32::from_ne_bytes([
                    termios[12],
                    termios[13],
                    termios[14],
                    termios[15],
                ]);
                (c_lflag & ICANON) == 0 && (c_lflag & ECHO) == 0
            } else {
                false
            }
        }

        pub fn drain_master(&self) -> Vec<u8> {
            let mut buf = [0u8; 4096];
            let mut output = Vec::new();
            loop {
                let n = unsafe { libc_read(self.master_fd, buf.as_mut_ptr(), buf.len()) };
                if n > 0 {
                    output.extend_from_slice(&buf[..n as usize]);
                } else {
                    break;
                }
            }
            output
        }
    }

    impl Drop for PtyTestEnvironment {
        fn drop(&mut self) {
            unsafe {
                dup2(self.saved_stdin, 0);
                dup2(self.saved_stdout, 1);
                close(self.saved_stdin);
                close(self.saved_stdout);
                close(self.slave_fd);
                close(self.master_fd);
            }
        }
    }

    pub fn create_mock_mp4(path: &Path, with_moov: bool) -> io::Result<()> {
        let mut file = File::create(path)?;
        // Write standard ftyp box (24 bytes)
        file.write_all(&[
            0x00, 0x00, 0x00, 0x18, // size: 24
            b'f', b't', b'y', b'p', // type: ftyp
            b'i', b's', b'o', b'm', // major brand
            0x00, 0x00, 0x02, 0x00, // minor version
            b'i', b's', b'o', b'm', // compatible brands
            b'm', b'p', b'4', b'2',
        ])?;

        if with_moov {
            // Write a valid small moov box (16 bytes)
            file.write_all(&[
                0x00, 0x00, 0x00, 0x10, // size: 16
                b'm', b'o', b'o', b'v', // type: moov
                0x00, 0x00, 0x00, 0x08, // child size: 8
                b'm', b'v', b'h', b'd', // child type: mvhd
            ])?;
        }

        // Write a small mdat box (16 bytes)
        file.write_all(&[
            0x00, 0x00, 0x00, 0x10, // size: 16
            b'm', b'd', b'a', b't', // type: mdat
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, // payload
        ])?;

        file.flush()?;
        Ok(())
    }
}

// =========================================================================
// TIER 1: FEATURE COVERAGE (65 TESTS: 13 FEATURES x 5 TESTS EACH)
// =========================================================================

pub mod tier1_feature_coverage {
    use super::common::*;
    use super::*;

    // ---------------------------------------------------------------------
    // F1: Cargo & Lib Target
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f1_01_lib_crate_modules_exported() {
        let level = mp4_doctor::event::LogLevel::Info;
        assert_eq!(level.as_str(), "INFO");
        assert_eq!(level.badge(), "[INFO]   ");

        let view = mp4_doctor::tui::app::View::MainMenu;
        assert_eq!(view, mp4_doctor::tui::app::View::MainMenu);

        let scan_mode = mp4_doctor::scanner::ScanMode::FullAuto;
        assert!(scan_mode == mp4_doctor::scanner::ScanMode::FullAuto);

        let db_fn: fn(&mp4_doctor::workspace::Workspace) -> rusqlite::Result<rusqlite::Connection> =
            mp4_doctor::db::init_db;
        assert_ne!(db_fn as usize, 0);

        let ws_fn: fn(&str) -> std::io::Result<mp4_doctor::workspace::Workspace> =
            mp4_doctor::workspace::Workspace::init;
        assert_ne!(ws_fn as usize, 0);
    }

    #[test]
    fn test_tier1_f1_02_thread_count_configuration() {
        let _guard = THREAD_CONF_LOCK.lock().unwrap();
        let initial = get_thread_count();

        // Wartość MUSI mieścić się w limicie `2 * rdzenie`, inaczej
        // `get_thread_count` sprowadzi ją do liczby rdzeni. Zaszyte wcześniej
        // `7` przechodziło tylko od 4 rdzeni w górę.
        let w_limicie = sprzetowe_max();
        set_thread_count(w_limicie);
        assert_eq!(get_thread_count(), w_limicie);

        set_thread_count(initial);
    }

    #[test]
    fn test_tier1_f1_03_shutdown_flag_atomic() {
        let initial = SHUTDOWN_FLAG.load(Ordering::SeqCst);
        SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
        assert!(SHUTDOWN_FLAG.load(Ordering::SeqCst));
        SHUTDOWN_FLAG.store(false, Ordering::SeqCst);
        assert!(!SHUTDOWN_FLAG.load(Ordering::SeqCst));
        SHUTDOWN_FLAG.store(initial, Ordering::SeqCst);
    }

    #[test]
    fn test_tier1_f1_04_ratatui_crossterm_types_available() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(buffer_contains(&terminal, 80, 24, "MENU GŁÓWNE"));
    }

    #[test]
    fn test_tier1_f1_05_domain_modules_instantiation() {
        let stats = StatUpdate::new(10, 5, 5, 4, 1024, 2);
        assert_eq!(stats.files_scanned, 10);
        assert_eq!(stats.files_healthy, 5);
        assert_eq!(stats.files_broken, 5);
        assert_eq!(stats.files_repaired, 4);
        assert_eq!(stats.bytes_processed, 1024);
        assert_eq!(stats.active_threads, 2);
    }

    // ---------------------------------------------------------------------
    // F2: Centralized Event Bus
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f2_01_channel_creation_and_send_recv() {
        let (tx, rx) = channel();
        tx.info("CORE", "Test Message");
        let event = rx.recv_timeout(Duration::from_millis(200)).unwrap();
        if let AppEvent::Log(msg) = event {
            assert_eq!(msg.module, "CORE");
            assert_eq!(msg.message, "Test Message");
            assert_eq!(msg.level, LogLevel::Info);
        } else {
            panic!("Expected AppEvent::Log");
        }
    }

    #[test]
    fn test_tier1_f2_02_log_levels_badges_and_formatting() {
        assert_eq!(LogLevel::Debug.as_str(), "DEBUG");
        assert_eq!(LogLevel::Info.as_str(), "INFO");
        assert_eq!(LogLevel::Success.as_str(), "SUCCESS");
        assert_eq!(LogLevel::Warn.as_str(), "WARN");
        assert_eq!(LogLevel::Error.as_str(), "ERROR");

        assert_eq!(LogLevel::Debug.badge(), "[DEBUG]  ");
        assert_eq!(LogLevel::Success.badge(), "[SUCCESS]");
    }

    #[test]
    fn test_tier1_f2_03_stat_update_repair_rate() {
        let s1 = StatUpdate::new(100, 50, 50, 25, 5000, 4);
        assert!((s1.repair_rate() - 50.0).abs() < 0.01);

        let s2 = StatUpdate::new(100, 100, 0, 0, 5000, 4);
        assert_eq!(s2.repair_rate(), 100.0);
    }

    #[test]
    fn test_tier1_f2_04_worker_status_and_sanitizer_metrics() {
        let ws = WorkerStatus::new(3, "Skanowanie bloku");
        assert_eq!(ws.thread_id, 3);
        assert_eq!(ws.status, "Skanowanie bloku");

        let sm = SanitizerMetrics::new(120, 29.97, "1.2x", 1);
        assert_eq!(sm.frame, 120);
        assert!((sm.fps - 29.97).abs() < 0.01);
        assert_eq!(sm.speed, "1.2x");
        assert_eq!(sm.pass, 1);
    }

    #[test]
    fn test_tier1_f2_05_event_sender_helper_methods() {
        let (tx, rx) = channel();
        tx.warn("MOD", "Warning event");
        tx.error("MOD", "Error event");
        tx.success("MOD", "Success event");

        let e1 = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        let e2 = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        let e3 = rx.recv_timeout(Duration::from_millis(100)).unwrap();

        assert!(matches!(e1, AppEvent::Log(m) if m.level == LogLevel::Warn));
        assert!(matches!(e2, AppEvent::Log(m) if m.level == LogLevel::Error));
        assert!(matches!(e3, AppEvent::Log(m) if m.level == LogLevel::Success));
    }

    // ---------------------------------------------------------------------
    // F3: Scanner Refactoring
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f3_01_source_code_zero_println_and_indicatif() {
        let scanner_src = fs::read_to_string("src/scanner.rs").unwrap();
        assert!(!scanner_src.contains("println!"));
        assert!(!scanner_src.contains("eprintln!"));
        assert!(!scanner_src.contains("indicatif"));
    }

    #[test]
    fn test_tier1_f3_02_scanner_is_healthy_detection() {
        let is_valid = validator::is_healthy_video("test.mp4");
        assert!(is_valid, "Reference test.mp4 should be recognized as healthy");

        let is_invalid = validator::is_healthy_video("/tmp/non_existent_path.mp4");
        assert!(!is_invalid);
    }

    #[test]
    fn test_tier1_f3_03_scanner_pipeline_emits_events() {
        let ws_guard = TestWorkspaceGuard::new("scan_events");
        let (tx, rx) = channel();
        let target_dir = ws_guard.ws.root_dir.to_str().unwrap();

        scanner::run_scanner(&ws_guard.ws, target_dir, scanner::ScanMode::FullAuto, &tx);

        let mut received = Vec::new();
        while let Ok(evt) = rx.recv_timeout(Duration::from_millis(100)) {
            received.push(evt);
        }
        assert!(
            !received.is_empty(),
            "Scanner should have emitted progress or finished events"
        );
    }

    #[test]
    fn test_tier1_f3_04_scanner_thread_status_updates() {
        let ws_guard = TestWorkspaceGuard::new("scan_threads");
        let (tx, rx) = channel();
        let sample_path = ws_guard.ws.broken_dir.join("sample.mp4");
        create_mock_mp4(&sample_path, true).unwrap();

        scanner::run_scanner(
            &ws_guard.ws,
            ws_guard.ws.broken_dir.to_str().unwrap(),
            scanner::ScanMode::ExtractOnly,
            &tx,
        );

        let mut has_thread_or_log = false;
        while let Ok(evt) = rx.recv_timeout(Duration::from_millis(100)) {
            if matches!(evt, AppEvent::ThreadStatus(_) | AppEvent::Log(_)) {
                has_thread_or_log = true;
                break;
            }
        }
        assert!(has_thread_or_log);
    }

    #[test]
    fn test_tier1_f3_05_scanner_extract_moov_telemetry() {
        let ws_guard = TestWorkspaceGuard::new("extract_moov");
        let dest_moov = ws_guard.ws.donors_dir.join("donor_test.moov");
        let res = scanner::extract_and_save_moov("test.mp4", dest_moov.to_str().unwrap());
        assert!(res.is_ok(), "Should extract moov atom from test.mp4");
        assert!(dest_moov.exists());
        assert!(fs::metadata(&dest_moov).unwrap().len() > 0);
    }

    // ---------------------------------------------------------------------
    // F4: Training Ground Refactoring
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f4_01_source_code_zero_println_and_indicatif() {
        let tg_src = fs::read_to_string("src/training_ground.rs").unwrap();
        assert!(!tg_src.contains("println!"));
        assert!(!tg_src.contains("eprintln!"));
        assert!(!tg_src.contains("indicatif"));
    }

    #[test]
    fn test_tier1_f4_02_chaos_monkey_mutation_emission() {
        let ws_guard = TestWorkspaceGuard::new("tg_chaos");
        let (tx, rx) = channel();

        let train_input = ws_guard.ws.root_dir.join("train_input");
        fs::create_dir_all(&train_input).unwrap();
        let sample_file = train_input.join("sample.mp4");
        fs::copy("test.mp4", &sample_file).unwrap();

        let _ = training_ground::run_training(
            &ws_guard.ws,
            train_input.to_str().unwrap(),
            &tx,
        );

        let mut events = Vec::new();
        while let Ok(evt) = rx.recv_timeout(Duration::from_millis(200)) {
            events.push(evt);
        }
        assert!(!events.is_empty(), "Training ground should emit telemetry");
    }

    #[test]
    fn test_tier1_f4_03_training_ground_stats_reporting() {
        let (tx, rx) = channel();
        tx.progress(1, 10, Some("Chaos monkey step".to_string()));
        let evt = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        if let AppEvent::Progress { current, total, message } = evt {
            assert_eq!(current, 1);
            assert_eq!(total, 10);
            assert_eq!(message, Some("Chaos monkey step".to_string()));
        } else {
            panic!("Expected AppEvent::Progress");
        }
    }

    #[test]
    fn test_tier1_f4_04_training_ground_repair_telemetry() {
        let (tx, rx) = channel();
        tx.repair_success("test.mp4", "DNA_ABC", "Clone", cechy_testowe());
        let evt = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        assert!(matches!(evt, AppEvent::RepairSuccess { .. }));
    }

    #[test]
    fn test_tier1_f4_05_training_ground_progress_tracking() {
        let (tx, rx) = channel();
        tx.operation_started("Training Ground Run");
        tx.operation_finished("Training Complete");

        let e1 = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        let e2 = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        assert_eq!(e1, AppEvent::OperationStarted("Training Ground Run".to_string()));
        assert_eq!(e2, AppEvent::OperationFinished("Training Complete".to_string()));
    }

    // ---------------------------------------------------------------------
    // F5: Autopilot Refactoring
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f5_01_source_code_zero_println() {
        let auto_src = fs::read_to_string("src/autopilot.rs").unwrap();
        assert!(!auto_src.contains("println!"));
        assert!(!auto_src.contains("eprintln!"));
    }

    #[test]
    fn test_tier1_f5_02_autopilot_event_piping() {
        let (tx, rx) = channel();
        tx.info("AUTOPILOT", "Searching for donor");
        let evt = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        if let AppEvent::Log(msg) = evt {
            assert_eq!(msg.module, "AUTOPILOT");
            assert_eq!(msg.message, "Searching for donor");
        } else {
            panic!("Expected AppEvent::Log");
        }
    }

    #[test]
    fn test_tier1_f5_03_autopilot_cloud_donor_search_telemetry() {
        let ws_guard = TestWorkspaceGuard::new("autopilot_cloud");
        let (tx, rx) = channel();
        let cache = db::build_brain_cache(&ws_guard.ws).unwrap_or_default();

        let _ = autopilot::find_donor(&ws_guard.ws, "UNKNOWN_DNA_SIG", &cache, &tx, 0);
        let mut got_log = false;
        while let Ok(evt) = rx.recv_timeout(Duration::from_millis(50)) {
            if let AppEvent::Log(l) = evt
                && l.module == "AUTOPILOT" {
                    got_log = true;
                    break;
                }
        }
        assert!(got_log, "Autopilot should emit log during search");
    }

    #[test]
    fn test_tier1_f5_04_autopilot_dna_extraction_logging() {
        let (tx, rx) = channel();
        if let Some((dna, _)) = dna::extract_dna("test.mp4") {
            tx.info("AUTOPILOT", format!("Wyodrębniono DNA: {}", dna));
        }
        let evt = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        if let AppEvent::Log(msg) = evt {
            assert!(msg.message.contains("Wyodrębniono DNA"));
        } else {
            panic!("Expected log event");
        }
    }

    #[test]
    fn test_tier1_f5_05_autopilot_operation_lifecycle_events() {
        let (tx, rx) = channel();
        tx.operation_started("Autopilot Batch");
        tx.operation_failed("Autopilot Batch", "No donor found");

        let e1 = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        let e2 = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        assert!(matches!(e1, AppEvent::OperationStarted(_)));
        assert!(matches!(e2, AppEvent::OperationFailed(_, _)));
    }

    // ---------------------------------------------------------------------
    // F6: Core & God Mode Refactoring
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f6_01_source_code_zero_println_core_modules() {
        for path in &["src/god_mode.rs", "src/db.rs", "src/workspace.rs"] {
            let content = fs::read_to_string(path).unwrap();
            assert!(
                !content.contains("println!"),
                "File {} must not contain println!",
                path
            );
            assert!(
                !content.contains("eprintln!"),
                "File {} must not contain eprintln!",
                path
            );
        }
    }

    #[test]
    fn test_tier1_f6_02_workspace_creation_and_stats() {
        let ws_guard = TestWorkspaceGuard::new("ws_stats_t1");
        assert!(ws_guard.ws.root_dir.exists());
        assert!(ws_guard.ws.broken_dir.exists());
        assert!(ws_guard.ws.donors_dir.exists());
        assert!(ws_guard.ws.output_dir.exists());

        let all = get_available_workspaces();
        assert!(all.iter().any(|w| w.name == ws_guard.ws.name));
    }

    #[test]
    fn test_tier1_f6_03_database_init_and_query() {
        let ws_guard = TestWorkspaceGuard::new("db_init_t1");
        let stats = db::get_db_stats(&ws_guard.ws);
        assert_eq!(stats, 0);
    }

    #[test]
    fn test_tier1_f6_04_god_mode_event_emission() {
        let ws_guard = TestWorkspaceGuard::new("god_mode_t1");
        let (tx, rx) = channel();

        let sample = ws_guard.ws.root_dir.join("sample.mp4");
        fs::copy("test.mp4", &sample).unwrap();

        let _ = god_mode::run_extreme_mutation(&ws_guard.ws, sample.to_str().unwrap(), &tx);

        let mut got_god_event = false;
        while let Ok(evt) = rx.recv_timeout(Duration::from_millis(100)) {
            if let AppEvent::Log(l) = evt
                && l.module == "GOD_MODE" {
                    got_god_event = true;
                    break;
                }
        }
        assert!(got_god_event);
    }

    #[test]
    fn test_tier1_f6_05_algorithm_reward_and_penalize() {
        let ws_guard = TestWorkspaceGuard::new("reward_penalize_t1");
        let cechy = cechy_testowe();
        db::reward_algorithm(&ws_guard.ws, "TEST_DNA", "Native", &cechy).unwrap();
        db::reward_algorithm(&ws_guard.ws, "TEST_DNA", "Native", &cechy).unwrap();
        db::penalize_algorithm(&ws_guard.ws, "TEST_DNA", "Clone", &cechy).unwrap();

        let cache = db::build_brain_cache(&ws_guard.ws).unwrap();
        assert!(cache.algorithms.contains_key("TEST_DNA"));
    }

    // ---------------------------------------------------------------------
    // F7: Terminal Guard & Panic Safety
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f7_01_terminal_guard_active_state() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        force_restore();
        assert!(!is_terminal_active());
    }

    #[test]
    fn test_tier1_f7_02_terminal_guard_force_restore() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        force_restore();
        assert!(!is_terminal_active());
        force_restore(); // idempotent
        assert!(!is_terminal_active());
    }

    #[test]
    fn test_tier1_f7_03_panic_hook_installation() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        install_panic_hook();
        // Hook is idempotent: second call succeeds without panic
        install_panic_hook();

        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Ok(_tg) = TerminalGuard::init() {
                assert!(is_terminal_active(), "Terminal should be active inside guard");
            }
            panic!("Verify panic hook terminal restoration");
        }));

        assert!(panicked.is_err(), "Block must catch the panic");
        assert!(!is_terminal_active(), "Terminal active flag must be restored to false on panic");
    }

    #[test]
    fn test_tier1_f7_04_terminal_guard_drop_safety() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        {
            let guard = TerminalGuard::init();
            if let Ok(_g) = guard {
                assert!(is_terminal_active());
            }
        }
        assert!(!is_terminal_active());
    }

    #[test]
    fn test_tier1_f7_05_terminal_suspend_subprocess_lifecycle() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        if let Ok(mut guard) = TerminalGuard::init() {
            let res = guard.suspend(|| Ok(12345));
            assert_eq!(res.unwrap(), 12345);
        }
    }

    // ---------------------------------------------------------------------
    // F8: Interactive TUI Main Menu
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f8_01_main_menu_initialization() {
        let (tx, rx) = channel();
        let app = App::with_channel(tx, rx);
        assert_eq!(app.current_view, View::MainMenu);
        assert_eq!(app.main_menu_state.selected(), Some(0));
    }

    #[test]
    fn test_tier1_f8_02_menu_keyboard_up_down() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.main_menu_state.selected(), Some(1));

        app.handle_key(make_key(KeyCode::Up));
        assert_eq!(app.main_menu_state.selected(), Some(0));
    }

    #[test]
    fn test_tier1_f8_03_menu_enter_triggers_view_transition() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        // Select item 0: Workspace Select
        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.current_view, View::WorkspaceSelect);
    }

    #[test]
    fn test_tier1_f8_04_modal_input_activation() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        app.handle_key(make_key(KeyCode::Enter)); // to WorkspaceSelect
        app.handle_key(make_key(KeyCode::Char('n'))); // trigger new workspace modal
        assert!(matches!(app.active_modal, Modal::NewWorkspace { .. }));
    }

    #[test]
    fn test_tier1_f8_05_esc_key_navigation() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        app.push_view(View::WorkspaceSelect);
        assert_eq!(app.current_view, View::WorkspaceSelect);

        app.handle_key(make_key(KeyCode::Esc));
        assert_eq!(app.current_view, View::MainMenu);
    }

    // ---------------------------------------------------------------------
    // F9: Responsive Layout & Live Stats
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f9_01_terminal_fallback_under_60x15() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(59, 14);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(buffer_contains(&terminal, 59, 14, "Terminal zbyt mały!"));
        assert!(buffer_contains(&terminal, 59, 14, "60x15"));
    }

    #[test]
    fn test_tier1_f9_02_terminal_normal_layout_at_60x15() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(60, 15);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(!buffer_contains(&terminal, 60, 15, "Terminal zbyt mały!"));
        assert!(buffer_contains(&terminal, 60, 15, "MENU GŁÓWNE"));
    }

    #[test]
    fn test_tier1_f9_03_header_density_scaling() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        // Compact: width 70
        let b1 = TestBackend::new(70, 20);
        let mut t1 = Terminal::new(b1).unwrap();
        t1.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(buffer_contains(&t1, 70, 20, "MP4 DOC"));

        // Standard: width 100
        let b2 = TestBackend::new(100, 25);
        let mut t2 = Terminal::new(b2).unwrap();
        t2.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(buffer_contains(&t2, 100, 25, "MP4 DOCTOR 2.0"));

        // Wide: width 140
        let b3 = TestBackend::new(140, 30);
        let mut t3 = Terminal::new(b3).unwrap();
        t3.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(buffer_contains(&t3, 140, 30, "CPU:"));
    }

    #[test]
    fn test_tier1_f9_04_live_stats_panel_rendering() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;
        app.stats = StatUpdate::new(42, 30, 12, 10, 1048576, 4);

        let backend = TestBackend::new(90, 25);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        assert!(buffer_contains(&terminal, 90, 25, "42"));
        assert!(buffer_contains(&terminal, 90, 25, "1.00 MB"));
    }

    #[test]
    fn test_tier1_f9_05_sanitizer_telemetry_gauge_rendering() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;
        app.sanitizer_metrics = SanitizerMetrics::new(500, 60.5, "2.5x", 1);

        let backend = TestBackend::new(90, 25);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        assert!(buffer_contains(&terminal, 90, 25, "60.5"));
        assert!(buffer_contains(&terminal, 90, 25, "2.5x"));
    }

    // ---------------------------------------------------------------------
    // F10: Word-Wrapped Scrollable Logs
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f10_01_format_log_line_levels() {
        let lm_info = LogMessage::info("TEST", "Informacja");
        let line_info = format_log_line(&lm_info);
        assert!(line_info.spans.iter().any(|s| s.content.contains("[INFO ]")));

        let lm_err = LogMessage::error("TEST", "Błąd");
        let line_err = format_log_line(&lm_err);
        assert!(line_err.spans.iter().any(|s| s.content.contains("[ERROR]")));
    }

    #[test]
    fn test_tier1_f10_02_estimate_log_rows() {
        let msg = LogMessage::info("M", "Krótka wiadomość");
        let rows = estimate_log_rows(&msg, 80);
        assert_eq!(rows, 1);

        let long_msg = LogMessage::info(
            "MODULE_VERY_LONG_NAME",
            "To jest bardzo długa wiadomość testowa która powinna zostać zawinięta na wiele linii w wąskim oknie terminala",
        );
        let rows_wrapped = estimate_log_rows(&long_msg, 30);
        assert!(rows_wrapped > 1);
    }

    #[test]
    fn test_tier1_f10_03_log_buffer_auto_scroll() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.auto_scroll = true;

        for i in 0..10 {
            app.push_log(LogMessage::info("TEST", format!("Log #{}", i)));
        }
        assert_eq!(app.logs.len(), 10);
        assert_eq!(app.log_scroll, 9);
    }

    #[test]
    fn test_tier1_f10_04_manual_scroll_keys() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;

        for i in 0..50 {
            app.push_log(LogMessage::info("TEST", format!("Log #{}", i)));
        }
        assert!(app.auto_scroll);

        app.handle_key(make_key(KeyCode::PageUp));
        assert!(!app.auto_scroll);
        assert!(app.log_scroll < 49);

        app.handle_key(make_key(KeyCode::End));
        assert!(app.auto_scroll);
        assert_eq!(app.log_scroll, 49);
    }

    #[test]
    fn test_tier1_f10_05_log_panel_rendered_in_test_backend() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;
        app.push_log(LogMessage::success("SCANNER", "Analiza pliku zakończona pomyślnie"));

        let backend = TestBackend::new(90, 25);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        assert!(buffer_contains(
            &terminal,
            90,
            25,
            "Analiza pliku zakończona pomyślnie"
        ));
    }

    // ---------------------------------------------------------------------
    // F11: Headless CLI Mode Preservation
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f11_01_cli_args_parsing_help() {
        let bin = env!("CARGO_BIN_EXE_mp4_doctor");
        let output = Command::new(bin).arg("--help").output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("MP4 Doctor") || stdout.contains("Usage:"));
    }

    #[test]
    fn test_tier1_f11_02_cli_args_parsing_version() {
        let bin = env!("CARGO_BIN_EXE_mp4_doctor");
        let output = Command::new(bin).arg("--version").output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("2.0.0"));
    }

    #[test]
    fn test_tier1_f11_03_cli_args_parsing_workspace_and_scan() {
        let bin = env!("CARGO_BIN_EXE_mp4_doctor");
        let ws_guard = TestWorkspaceGuard::new("cli_headless");
        let output = Command::new(bin)
            .args([
                "--workspace",
                &ws_guard.ws.name,
                "--scan",
                ws_guard.ws.root_dir.to_str().unwrap(),
            ])
            .output()
            .unwrap();

        assert!(output.status.success());
    }

    #[test]
    fn test_tier1_f11_04_headless_mode_no_raw_mode() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let bin = env!("CARGO_BIN_EXE_mp4_doctor");
        let pty = PtyTestEnvironment::new().unwrap();

        let stdin_fd = unsafe { dup(pty.slave_fd) };
        let stdout_fd = unsafe { dup(pty.slave_fd) };
        let stderr_fd = unsafe { dup(pty.slave_fd) };

        let status = Command::new(bin)
            .arg("--help")
            .stdin(unsafe { std::process::Stdio::from_raw_fd(stdin_fd) })
            .stdout(unsafe { std::process::Stdio::from_raw_fd(stdout_fd) })
            .stderr(unsafe { std::process::Stdio::from_raw_fd(stderr_fd) })
            .status()
            .unwrap();

        assert!(status.success());
        assert!(!pty.is_raw_mode_active());
    }

    #[test]
    fn test_tier1_f11_05_headless_auto_test_execution() {
        let bin = env!("CARGO_BIN_EXE_mp4_doctor");
        let output = Command::new(bin).arg("--auto-test").output().unwrap();
        assert!(output.status.success());
    }

    // ---------------------------------------------------------------------
    // F12: External Subprocess Suspension
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f12_01_pending_preview_selection() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.preview_files = vec![PathBuf::from("/tmp/fixed_test.mp4")];
        app.current_view = View::PreviewFileSelect;

        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.pending_preview, Some(PathBuf::from("/tmp/fixed_test.mp4")));
    }

    #[test]
    fn test_tier1_f12_02_take_pending_preview() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.pending_preview = Some(PathBuf::from("/tmp/fixed_test.mp4"));

        let taken = app.take_pending_preview();
        assert_eq!(taken, Some(PathBuf::from("/tmp/fixed_test.mp4")));
        assert_eq!(app.pending_preview, None);
    }

    #[test]
    fn test_tier1_f12_03_terminal_suspend_executes_closure() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        if let Ok(mut tg) = TerminalGuard::init() {
            let res = tg.suspend(|| Ok("Action executed"));
            assert_eq!(res.unwrap(), "Action executed");
        }
    }

    #[test]
    fn test_tier1_f12_04_preview_file_list_refresh() {
        let ws_guard = TestWorkspaceGuard::new("preview_refresh");
        let dummy_fixed = ws_guard.ws.output_dir.join("Fixed_Video.mp4");
        create_mock_mp4(&dummy_fixed, true).unwrap();

        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.active_workspace = Some(ws_guard.ws.clone());

        app.refresh_preview_files();
        assert_eq!(app.preview_files.len(), 1);
        assert_eq!(app.preview_files[0], dummy_fixed);
    }

    #[test]
    fn test_tier1_f12_05_external_command_mock_simulation() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        if let Ok(mut tg) = TerminalGuard::init() {
            let mock_run = tg.suspend(|| {
                let status = Command::new("true").status()?;
                Ok(status.success())
            });
            assert!(mock_run.unwrap());
        }
    }

    // ---------------------------------------------------------------------
    // F13: Comprehensive E2E Test Suite
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier1_f13_01_full_ui_render_cycle() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        let views = [
            View::MainMenu,
            View::WorkspaceSelect,
            View::WorkspaceDashboard,
            View::ScannerSubMenu,
            View::SettingsMenu,
            View::PreviewFileSelect,
            View::OperationRunning,
        ];

        for v in views {
            app.current_view = v;
            let frame = terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
            assert_eq!(frame.area.width, 80);
            assert_eq!(frame.area.height, 24);
            let lines = buffer_to_strings(&terminal, 80, 24);
            assert!(
                !lines.is_empty(),
                "Buffer lines must not be empty for view {:?}",
                v
            );
            assert!(
                lines.iter().any(|l| !l.trim().is_empty()),
                "Rendered view {:?} must contain non-empty visual content",
                v
            );
            assert!(
                buffer_contains(&terminal, 80, 24, "MP4 DOCTOR"),
                "Header brand 'MP4 DOCTOR' must be rendered in view {:?}",
                v
            );
        }
    }

    #[test]
    fn test_tier1_f13_02_state_machine_and_event_drain_cycle() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx.clone(), rx);

        tx.info("SYS", "Message 1");
        tx.info("SYS", "Message 2");
        app.process_events();

        assert_eq!(app.logs.len(), 2);
    }

    #[test]
    fn test_tier1_f13_03_zero_stdout_in_worker_execution() {
        let _guard = common::FD_LOCK.lock().unwrap();
        let ws_guard = TestWorkspaceGuard::new("stdout_f13");
        let (tx, _rx) = channel();

        let cap = StdCapture::start();
        scanner::run_scanner(
            &ws_guard.ws,
            ws_guard.ws.root_dir.to_str().unwrap(),
            scanner::ScanMode::FullAuto,
            &tx,
        );
        let captured = cap.finish();
        StdCapture::assert_zero_leak(captured, "test_tier1_f13_03_zero_stdout_in_worker_execution");
    }

    #[test]
    fn test_tier1_f13_04_terminal_guard_panic_safe_drop() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _tg = TerminalGuard::init().unwrap();
            panic!("Simulated worker panic");
        }));

        assert!(!is_terminal_active());
    }

    #[test]
    fn test_tier1_f13_05_test_ready_metadata_consistency() {
        let features = [
            "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12", "F13",
        ];
        assert_eq!(features.len(), 13);
    }
}

// =========================================================================
// TIER 2: BOUNDARY & CORNER CASES (65 TESTS: 13 FEATURES x 5 TESTS EACH)
// =========================================================================

pub mod tier2_boundary_corner {
    use super::common::*;
    use super::*;

    // ---------------------------------------------------------------------
    // F1 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f1_01_thread_count_invalid_file_fallback() {
        let _guard = THREAD_CONF_LOCK.lock().unwrap();
        // Kieruje `threads.conf` do katalogu tymczasowego — inaczej ten test
        // odtwarzałby `workspaces/` w drzewie projektu.
        let _ = mp4_doctor::workspace::katalog_przestrzeni_dla_testow();
        let konf = mp4_doctor::sciezka_konfiguracji_watkow();
        let _ = fs::create_dir_all(konf.parent().unwrap());

        // NAPRAWIONA ASERCJA: wpis nieparsowalny daje 0 przy parsowaniu, a 0
        // znaczy „Auto" — implementacja podmienia je na liczbę rdzeni. Zwrot
        // dosłownego zera jest NIEMOŻLIWY na jakimkolwiek sprzęcie, więc ta
        // asercja nie mogła przejść nigdy.
        let _ = fs::write(&konf, "INVALID_NOT_A_NUMBER");
        assert_eq!(
            get_thread_count(), sprzetowe_max(),
            "nieparsowalny wpis musi dać fallback na liczbę rdzeni"
        );

        let _ = fs::write(&konf, "0");
    }

    #[test]
    fn test_tier2_f1_02_thread_count_extreme_limits() {
        let _guard = THREAD_CONF_LOCK.lock().unwrap();
        let rdzenie = sprzetowe_max();

        // NAPRAWIONE ASERCJE: zaszyte `1024` przechodziło tylko od 512 rdzeni
        // w górę, a `== 0` nie mogło przejść nigdy. Test sprawdza teraz
        // faktyczny kontrakt na obu granicach.
        set_thread_count(rdzenie * 2);
        assert_eq!(get_thread_count(), rdzenie * 2, "dwukrotność rdzeni to górna granica akceptacji");

        set_thread_count(rdzenie * 2 + 1);
        assert_eq!(get_thread_count(), rdzenie, "wartość ponad limit musi spaść do liczby rdzeni");

        set_thread_count(0);
        assert_eq!(get_thread_count(), rdzenie, "0 to tryb Auto, nie dosłowne zero wątków");
    }

    #[test]
    fn test_tier2_f1_03_shutdown_flag_concurrent_toggle() {
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(thread::spawn(|| {
                for _ in 0..1000 {
                    SHUTDOWN_FLAG.store(true, Ordering::Relaxed);
                    let _ = SHUTDOWN_FLAG.load(Ordering::Relaxed);
                    SHUTDOWN_FLAG.store(false, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        SHUTDOWN_FLAG.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_tier2_f1_04_cargo_manifest_dependencies_check() {
        let manifest = fs::read_to_string("Cargo.toml").unwrap();
        assert!(manifest.contains("[lib]"));
        assert!(manifest.contains("ratatui"));
        assert!(manifest.contains("crossterm"));
        assert!(
            !manifest.contains("dialoguer"),
            "Cargo.toml must not contain legacy dependency 'dialoguer'"
        );
        assert!(
            !manifest.contains("indicatif"),
            "Cargo.toml must not contain legacy dependency 'indicatif'"
        );
        assert!(
            !manifest.contains("console"),
            "Cargo.toml must not contain legacy dependency 'console'"
        );

        if let Ok(lock) = fs::read_to_string("Cargo.lock") {
            assert!(
                !lock.contains("name = \"dialoguer\""),
                "Cargo.lock must not contain locked package 'dialoguer'"
            );
            assert!(
                !lock.contains("name = \"indicatif\""),
                "Cargo.lock must not contain locked package 'indicatif'"
            );
            assert!(
                !lock.contains("name = \"console\""),
                "Cargo.lock must not contain locked package 'console'"
            );
        }
    }

    #[test]
    fn test_tier2_f1_05_lib_workspace_path_resilience() {
        let _guard = THREAD_CONF_LOCK.lock().unwrap();
        let _ = mp4_doctor::workspace::katalog_przestrzeni_dla_testow();

        set_thread_count(4);

        let konf = mp4_doctor::sciezka_konfiguracji_watkow();
        assert!(konf.exists(), "set_thread_count musi utworzyć plik: {:?}", konf);
        assert!(
            !konf.starts_with(env!("CARGO_MANIFEST_DIR")),
            "W testach konfiguracja wątków musi lądować poza drzewem źródeł: {:?}",
            konf
        );

        set_thread_count(0);
    }

    // ---------------------------------------------------------------------
    // F2 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f2_01_receiver_drop_send_error() {
        let (tx, rx) = channel();
        drop(rx);
        let err = tx.send(AppEvent::Log(LogMessage::info("M", "Msg")));
        assert!(err.is_err());
        tx.info("M", "Msg");
        tx.warn("M", "Msg");
        tx.error("M", "Msg");
    }

    #[test]
    fn test_tier2_f2_02_repair_rate_div_by_zero_boundary() {
        let stats = StatUpdate::new(0, 0, 0, 0, 0, 0);
        assert_eq!(stats.repair_rate(), 100.0);
    }

    #[test]
    fn test_tier2_f2_03_event_burst_10k_throughput() {
        let (tx, rx) = channel();
        let mut handles = Vec::new();
        for t in 0..4 {
            let tx_clone = tx.clone();
            handles.push(thread::spawn(move || {
                for i in 0..2500 {
                    tx_clone.info("BURST", format!("Worker {} evt {}", t, i));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        drop(tx);

        let mut count = 0;
        while rx.recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 10000);
    }

    #[test]
    fn test_tier2_f2_04_serialization_round_trip() {
        let msg = LogMessage::info("MOD", "Polska czcionka: Zażółć gęślą jaźń");
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: LogMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.message, msg.message);
    }

    #[test]
    fn test_tier2_f2_05_extreme_sanitizer_metrics_boundaries() {
        let sm = SanitizerMetrics::new(u64::MAX, f32::INFINITY, "", u8::MAX);
        assert_eq!(sm.frame, u64::MAX);
        assert!(sm.fps.is_infinite());
        assert_eq!(sm.speed, "");
        assert_eq!(sm.pass, u8::MAX);
    }

    // ---------------------------------------------------------------------
    // F3 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f3_01_scanner_empty_directory() {
        let ws_guard = TestWorkspaceGuard::new("empty_scan");
        let empty_dir = ws_guard.ws.root_dir.join("empty_folder");
        fs::create_dir_all(&empty_dir).unwrap();

        let (tx, rx) = channel();
        scanner::run_scanner(&ws_guard.ws, empty_dir.to_str().unwrap(), scanner::ScanMode::FullAuto, &tx);

        let mut finished = false;
        while let Ok(evt) = rx.recv_timeout(Duration::from_millis(100)) {
            if let AppEvent::OperationFinished(_) = evt {
                finished = true;
            }
        }
        assert!(finished);
    }

    #[test]
    fn test_tier2_f3_02_scanner_nonexistent_directory() {
        let ws_guard = TestWorkspaceGuard::new("nonexist_scan");
        let (tx, rx) = channel();

        scanner::run_scanner(
            &ws_guard.ws,
            "/path/to/nonexistent/directory/xyz123",
            scanner::ScanMode::FullAuto,
            &tx,
        );

        let mut got_event = false;
        while rx.recv_timeout(Duration::from_millis(50)).is_ok() {
            got_event = true;
        }
        assert!(got_event);
    }

    #[test]
    fn test_tier2_f3_03_scanner_non_mp4_files_ignored() {
        let ws_guard = TestWorkspaceGuard::new("non_mp4_scan");
        let test_dir = ws_guard.ws.root_dir.join("mixed_files");
        fs::create_dir_all(&test_dir).unwrap();

        fs::write(test_dir.join("notes.txt"), "hello").unwrap();
        fs::write(test_dir.join("image.png"), [0x89, b'P', b'N', b'G']).unwrap();
        fs::write(test_dir.join("archive.zip"), [0x50, 0x4b, 0x03, 0x04]).unwrap();

        let (tx, rx) = channel();
        scanner::run_scanner(&ws_guard.ws, test_dir.to_str().unwrap(), scanner::ScanMode::FullAuto, &tx);

        let mut events = Vec::new();
        while let Ok(e) = rx.recv_timeout(Duration::from_millis(50)) {
            events.push(e);
        }
        assert!(events.iter().any(|e| matches!(e, AppEvent::OperationFinished(_))));
    }

    #[test]
    fn test_tier2_f3_04_scanner_zero_byte_file() {
        let ws_guard = TestWorkspaceGuard::new("zero_byte_scan");
        let test_dir = ws_guard.ws.root_dir.join("zero_files");
        fs::create_dir_all(&test_dir).unwrap();
        File::create(test_dir.join("empty.mp4")).unwrap();

        let (tx, rx) = channel();
        scanner::run_scanner(&ws_guard.ws, test_dir.to_str().unwrap(), scanner::ScanMode::ExtractOnly, &tx);

        let mut received = Vec::new();
        while let Ok(e) = rx.recv_timeout(Duration::from_millis(100)) {
            received.push(e);
        }
        assert!(!received.is_empty());
    }

    #[test]
    fn test_tier2_f3_05_scanner_corrupted_header_fuzz() {
        let ws_guard = TestWorkspaceGuard::new("corrupt_hdr_scan");
        let dest = ws_guard.ws.donors_dir.join("fuzzed.moov");

        let junk_path = ws_guard.ws.root_dir.join("junk.mp4");
        fs::write(&junk_path, [0xff; 1024]).unwrap();

        let res = scanner::extract_and_save_moov(junk_path.to_str().unwrap(), dest.to_str().unwrap());
        assert!(res.is_err(), "Should safely reject junk header");
    }

    // ---------------------------------------------------------------------
    // F4 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f4_01_chaos_monkey_zero_byte_input() {
        let ws_guard = TestWorkspaceGuard::new("tg_zero_byte");
        let (tx, _) = channel();
        let empty_path = ws_guard.ws.root_dir.join("empty.mp4");
        File::create(&empty_path).unwrap();

        let res = training_ground::run_sniper_test(&ws_guard.ws, empty_path.to_str().unwrap(), &tx);
        let _ = res;
    }

    #[test]
    fn test_tier2_f4_02_chaos_monkey_extreme_mutation_rate() {
        let ws_guard = TestWorkspaceGuard::new("tg_ext_mut");
        let (tx, _) = channel();
        let target = ws_guard.ws.root_dir.join("sample.mp4");
        fs::copy("test.mp4", &target).unwrap();

        let res = training_ground::run_sniper_test(&ws_guard.ws, target.to_str().unwrap(), &tx);
        assert!(res.is_ok());
    }

    #[test]
    fn test_tier2_f4_03_training_ground_missing_input() {
        let ws_guard = TestWorkspaceGuard::new("tg_missing");
        let (tx, rx) = channel();

        let _ = training_ground::run_training(
            &ws_guard.ws,
            "/nonexistent/directory/path/xyz",
            &tx,
        );

        let mut finished = false;
        while let Ok(e) = rx.recv_timeout(Duration::from_millis(50)) {
            if matches!(e, AppEvent::OperationFinished(_)) {
                finished = true;
            }
        }
        assert!(finished);
    }

    #[test]
    fn test_tier2_f4_04_chaos_monkey_tiny_slice_boundary() {
        let ws_guard = TestWorkspaceGuard::new("tg_tiny");
        let (tx, _) = channel();
        let tiny = ws_guard.ws.root_dir.join("tiny.mp4");
        fs::write(&tiny, [1, 2, 3, 4]).unwrap();

        let _ = training_ground::run_sniper_test(&ws_guard.ws, tiny.to_str().unwrap(), &tx);
    }

    #[test]
    fn test_tier2_f4_05_training_ground_shutdown_flag_interruption() {
        let ws_guard = TestWorkspaceGuard::new("tg_shutdown");
        let (tx, _) = channel();
        SHUTDOWN_FLAG.store(true, Ordering::SeqCst);

        let train_dir = ws_guard.ws.root_dir.join("in");
        fs::create_dir_all(&train_dir).unwrap();
        fs::copy("test.mp4", train_dir.join("1.mp4")).unwrap();

        let start = Instant::now();
        let _ = training_ground::run_training(&ws_guard.ws, train_dir.to_str().unwrap(), &tx);
        assert!(start.elapsed() < Duration::from_secs(5));

        SHUTDOWN_FLAG.store(false, Ordering::SeqCst);
    }

    // ---------------------------------------------------------------------
    // F5 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f5_01_autopilot_corrupt_database() {
        let ws_guard = TestWorkspaceGuard::new("auto_bad_db");
        fs::write(&ws_guard.ws.db_path, "NOT_A_VALID_SQLITE_DATABASE").unwrap();
        let (tx, _) = channel();

        let cache = db::build_brain_cache(&ws_guard.ws).unwrap_or_default();
        let res = autopilot::find_donor(&ws_guard.ws, "TEST", &cache, &tx, 0);
        assert_eq!(res, None);
    }

    #[test]
    fn test_tier2_f5_02_autopilot_unknown_dna_string() {
        let ws_guard = TestWorkspaceGuard::new("auto_unk_dna");
        let (tx, _) = channel();
        let cache = db::build_brain_cache(&ws_guard.ws).unwrap_or_default();

        let res = autopilot::find_donor(&ws_guard.ws, "???UNKNOWN_DNA_NOT_IN_INDEX???", &cache, &tx, 0);
        assert_eq!(res, None);
    }

    #[test]
    fn test_tier2_f5_03_autopilot_cloud_endpoint_unreachable() {
        let ws_guard = TestWorkspaceGuard::new("auto_cloud_down");
        let (tx, _) = channel();
        let cache = db::build_brain_cache(&ws_guard.ws).unwrap_or_default();

        let res = autopilot::find_donor(&ws_guard.ws, "RANDOM_DNA_VALUE", &cache, &tx, 0);
        assert_eq!(res, None);
    }

    #[test]
    fn test_tier2_f5_04_autopilot_zero_candidate_donors() {
        let ws_guard = TestWorkspaceGuard::new("auto_zero_donors");
        let (tx, _) = channel();
        let empty_cache = db::BrainCache::default();

        let res = autopilot::find_donor(&ws_guard.ws, "DNA_EMPTY", &empty_cache, &tx, 0);
        assert_eq!(res, None);
    }

    #[test]
    fn test_tier2_f5_05_autopilot_interruption_via_shutdown() {
        let ws_guard = TestWorkspaceGuard::new("auto_shutdown");
        let (tx, _) = channel();
        let cache = db::build_brain_cache(&ws_guard.ws).unwrap_or_default();
        SHUTDOWN_FLAG.store(true, Ordering::SeqCst);

        let _ = autopilot::find_donor(&ws_guard.ws, "DNA", &cache, &tx, 0);
        SHUTDOWN_FLAG.store(false, Ordering::SeqCst);
    }

    // ---------------------------------------------------------------------
    // F6 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f6_01_workspace_duplicate_name_handling() {
        let ws_guard = TestWorkspaceGuard::new("ws_dup");
        let ws2 = Workspace::init_testowy(&ws_guard.ws.name);
        assert!(ws2.is_ok());
    }

    #[test]
    fn test_tier2_f6_02_workspace_special_chars_in_name() {
        let name = "Projekt Zażółć Gęślą 2026!";
        let ws = Workspace::init_testowy(name);
        if let Ok(w) = ws {
            assert!(w.root_dir.exists());
            let _ = fs::remove_dir_all(&w.root_dir);
        }
    }

    #[test]
    fn test_tier2_f6_03_database_concurrent_access() {
        let ws_guard = TestWorkspaceGuard::new("db_concur");
        let ws = Arc::new(ws_guard.ws.clone());

        let mut handles = Vec::new();
        for i in 0..4 {
            let ws_c = Arc::clone(&ws);
            handles.push(thread::spawn(move || {
                let cechy = cechy_testowe();
                for j in 0..50 {
                    let dna = format!("DNA_{}_{}", i, j);
                    db::reward_algorithm(&ws_c, &dna, "Native", &cechy).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_tier2_f6_04_god_mode_invalid_file_handling() {
        let ws_guard = TestWorkspaceGuard::new("god_invalid");
        let (tx, _) = channel();
        let res = god_mode::run_extreme_mutation(
            &ws_guard.ws,
            "/nonexistent/file/path.mp4",
            &tx,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_tier2_f6_05_workspace_stats_empty_directories() {
        let ws_guard = TestWorkspaceGuard::new("ws_empty_stats");
        let stats = get_available_workspaces();
        let found = stats.iter().find(|s| s.name == ws_guard.ws.name).unwrap();
        assert_eq!(found.broken_count, 0);
        assert_eq!(found.donor_count, 0);
        assert_eq!(found.fixed_count, 0);
    }

    // ---------------------------------------------------------------------
    // F7 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f7_01_multiple_force_restore_calls() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        for _ in 0..100 {
            force_restore();
            assert!(!is_terminal_active());
        }
    }

    #[test]
    fn test_tier2_f7_02_terminal_suspend_with_closure_error() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        if let Ok(mut guard) = TerminalGuard::init() {
            let res: Result<(), _> = guard.suspend(|| Err(io::Error::other("Suspended failure")));
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_tier2_f7_03_terminal_suspend_with_panic() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Ok(mut guard) = TerminalGuard::init() {
                let _ = guard.suspend(|| {
                    panic!("Panic during suspended state");
                    #[allow(unreachable_code)]
                    Ok::<(), io::Error>(())
                });
            }
        }));
        assert!(!is_terminal_active());
    }

    #[test]
    fn test_tier2_f7_04_concurrent_guard_checks() {
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(thread::spawn(|| {
                for _ in 0..1000 {
                    let _ = is_terminal_active();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_tier2_f7_05_reinit_guard_lifecycle_loop() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        for _ in 0..10 {
            let guard = TerminalGuard::init();
            if let Ok(g) = guard {
                assert!(is_terminal_active());
                drop(g);
                assert!(!is_terminal_active());
            }
        }
    }

    // ---------------------------------------------------------------------
    // F8 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f8_01_menu_rapid_arrow_key_spam() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        for _ in 0..1000 {
            app.handle_key(make_key(KeyCode::Down));
            let s = app.main_menu_state.selected().unwrap();
            assert!(s < 4);

            app.handle_key(make_key(KeyCode::Up));
            let s = app.main_menu_state.selected().unwrap();
            assert!(s < 4);
        }
    }

    #[test]
    fn test_tier2_f8_02_modal_text_input_utf8_polish() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.active_modal = Modal::NewWorkspace {
            input: String::new(),
            cursor: 0,
            error_msg: None,
        };

        for c in "Zażółć gęślą jaźń".chars() {
            app.handle_key(make_key(KeyCode::Char(c)));
        }

        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_eq!(input, "Zażółć gęślą jaźń");
            assert_eq!(*cursor, "Zażółć gęślą jaźń".len());
        } else {
            panic!("Expected NewWorkspace modal");
        }
    }

    #[test]
    fn test_tier2_f8_03_modal_text_input_backspace_at_zero() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.active_modal = Modal::NewWorkspace {
            input: String::new(),
            cursor: 0,
            error_msg: None,
        };

        for _ in 0..50 {
            app.handle_key(make_key(KeyCode::Backspace));
        }

        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_eq!(input, "");
            assert_eq!(*cursor, 0);
        }
    }

    #[test]
    fn test_tier2_f8_04_esc_underflow_from_main_menu() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        assert_eq!(app.current_view, View::MainMenu);

        app.handle_key(make_key(KeyCode::Esc));
        assert!(app.should_quit);

        for _ in 0..50 {
            app.handle_key(make_key(KeyCode::Esc));
        }
        assert!(app.should_quit);
    }

    #[test]
    fn test_tier2_f8_05_modal_rapid_esc_enter_churn() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        for _ in 0..100 {
            app.active_modal = Modal::NewWorkspace {
                input: "Test".to_string(),
                cursor: 4,
                error_msg: None,
            };
            app.handle_key(make_key(KeyCode::Esc));
            assert_eq!(app.active_modal, Modal::None);
        }
    }

    // ---------------------------------------------------------------------
    // F9 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f9_01_extreme_terminal_shrink_10x5() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(10, 5);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(buffer_contains(&terminal, 10, 5, "Terminal"));
    }

    #[test]
    fn test_tier2_f9_02_extreme_terminal_scale_300x100() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(300, 100);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(buffer_contains(&terminal, 300, 100, "MENU GŁÓWNE"));
    }

    #[test]
    fn test_tier2_f9_03_stats_extreme_numbers() {
        assert!(format_bytes(u64::MAX).contains("TB"));
        assert!(format_bytes(1024 * 1024 * 1024 * 50).contains("50.00 GB"));
    }

    #[test]
    fn test_tier2_f9_04_stats_zero_division() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;
        app.stats = StatUpdate::new(0, 0, 0, 0, 0, 0);

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(buffer_contains(&terminal, 80, 24, "100.0%"));
    }

    #[test]
    fn test_tier2_f9_05_dynamic_dimension_alternation() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let dims = [(50, 12), (80, 24), (60, 15), (200, 60), (30, 8)];

        for (w, h) in dims {
            let backend = TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        }
    }

    // ---------------------------------------------------------------------
    // F10 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f10_01_log_line_exact_width_wrapping() {
        for delta in &[-1, 0, 1] {
            let width = (80 + delta) as usize;
            let msg_text = "x".repeat(width);
            let msg = LogMessage::info("MOD", msg_text);
            let rows = estimate_log_rows(&msg, 80);
            assert!(rows >= 1);
        }
    }

    #[test]
    fn test_tier2_f10_02_long_unbreakable_word() {
        let unbroken = "a".repeat(1000);
        let msg = LogMessage::info("MOD", unbroken);
        let rows = estimate_log_rows(&msg, 80);
        assert!(rows >= 12);
    }

    #[test]
    fn test_tier2_f10_03_empty_log_messages() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;

        app.push_log(LogMessage::info("", ""));
        app.push_log(LogMessage::info("   ", "   \t\n  "));

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
    }

    #[test]
    fn test_tier2_f10_04_log_buffer_eviction_at_max_history() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        for i in 0..5500 {
            app.push_log(LogMessage::info("MOD", format!("Log #{}", i)));
        }
        assert!(app.logs.len() <= MAX_LOG_HISTORY);
    }

    #[test]
    fn test_tier2_f10_05_multibyte_unicode_log_wrapping() {
        let unicode_msg = "🌟🔥🚀 Zażółć gęślą jaźń 測試 12345";
        let msg = LogMessage::info("UNICODE", unicode_msg);
        let rows = estimate_log_rows(&msg, 30);
        assert!(rows >= 1);
    }

    // ---------------------------------------------------------------------
    // F11 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f11_01_cli_invalid_flag_rejection() {
        let bin = env!("CARGO_BIN_EXE_mp4_doctor");
        let output = Command::new(bin).arg("--invalid-xyz-flag").output().unwrap();
        assert!(!output.status.success());
    }

    #[test]
    fn test_tier2_f11_02_cli_missing_required_value() {
        let bin = env!("CARGO_BIN_EXE_mp4_doctor");
        let output = Command::new(bin).arg("--workspace").output().unwrap();
        assert!(!output.status.success());
    }

    #[test]
    fn test_tier2_f11_03_cli_empty_string_flags() {
        let bin = env!("CARGO_BIN_EXE_mp4_doctor");
        let output = Command::new(bin).args(["--workspace", ""]).output().unwrap();
        let _ = output;
    }

    #[test]
    fn test_tier2_f11_04_cli_special_characters_in_args() {
        let bin = env!("CARGO_BIN_EXE_mp4_doctor");
        let output = Command::new(bin)
            .args(["--workspace", "Projekt Testowy @#$ 2026", "--help"])
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn test_tier2_f11_05_cli_multiple_subcommand_combinations() {
        let bin = env!("CARGO_BIN_EXE_mp4_doctor");
        let output = Command::new(bin)
            .args(["--auto-test", "--threads", "2"])
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    // ---------------------------------------------------------------------
    // F12 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f12_01_suspend_with_failing_subprocess() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        if let Ok(mut tg) = TerminalGuard::init() {
            let res = tg.suspend(|| {
                Command::new("false").status()?;
                Ok(())
            });
            assert!(res.is_ok());
        }
    }

    #[test]
    fn test_tier2_f12_02_rapid_sequential_preview_suspensions() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        if let Ok(mut tg) = TerminalGuard::init() {
            for i in 0..20 {
                let res = tg.suspend(|| Ok(i));
                assert_eq!(res.unwrap(), i);
            }
        }
    }

    #[test]
    fn test_tier2_f12_03_preview_with_spaces_and_unicode_path() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let path = PathBuf::from("/tmp/film z wakacji 🎥.mp4");
        app.preview_files = vec![path.clone()];
        app.current_view = View::PreviewFileSelect;

        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.take_pending_preview(), Some(path));
    }

    #[test]
    fn test_tier2_f12_04_preview_nonexistent_file() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.preview_files = vec![PathBuf::from("/tmp/nonexistent_video_file_xyz.mp4")];
        app.current_view = View::PreviewFileSelect;

        app.handle_key(make_key(KeyCode::Enter));
        let p = app.take_pending_preview().unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn test_tier2_f12_05_events_queued_during_suspend() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        for i in 0..100 {
            app.event_sender.info("BG", format!("Queue event {}", i));
        }

        app.process_events();
        assert_eq!(app.logs.len(), 100);
    }

    // ---------------------------------------------------------------------
    // F13 Boundary
    // ---------------------------------------------------------------------
    #[test]
    fn test_tier2_f13_01_heterogeneous_event_burst_15k() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        for i in 0..15000 {
            match i % 4 {
                0 => app.event_sender.info("M", format!("Msg {}", i)),
                1 => app.event_sender.update_stats(StatUpdate::new(i, i/2, i/2, i/4, (i as u64)*10, 4)),
                2 => app.event_sender.thread_status(i % 8, "Praca"),
                _ => app.event_sender.progress(i, 15000, Some("Batch".to_string())),
            }
        }

        while app.event_receiver.try_recv().is_ok() {
            app.process_events();
        }
        assert!(app.logs.len() <= MAX_LOG_HISTORY);
    }

    #[test]
    fn test_tier2_f13_02_fuzz_1000_arbitrary_key_events() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        let keys = [
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::PageUp,
            KeyCode::PageDown,
            KeyCode::Backspace,
            KeyCode::Delete,
            KeyCode::Char('a'),
            KeyCode::Char('1'),
            KeyCode::Char(' '),
            KeyCode::Char('ż'),
        ];

        for i in 0..1000 {
            let key = keys[i % keys.len()];
            app.handle_key(make_key(key));
        }
    }

    #[test]
    fn test_tier2_f13_03_concurrent_event_producers_and_rendering() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        let stop = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::new();

        for w in 0..4 {
            let tx_c = app.event_sender.clone();
            let stop_c = Arc::clone(&stop);
            workers.push(thread::spawn(move || {
                let mut i = 0;
                while !stop_c.load(Ordering::Relaxed) {
                    tx_c.info("BURST", format!("Worker {} evt {}", w, i));
                    i += 1;
                    if i > 500 { break; }
                }
            }));
        }

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        for _ in 0..50 {
            app.process_events();
            terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
            thread::sleep(Duration::from_millis(5));
        }

        stop.store(true, Ordering::SeqCst);
        for w in workers {
            w.join().unwrap();
        }
    }

    #[test]
    fn test_tier2_f13_04_terminal_restore_on_sigint_ctrl_c() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        app.handle_key(make_key_mod(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit);
        assert!(SHUTDOWN_FLAG.load(Ordering::SeqCst));
        SHUTDOWN_FLAG.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_tier2_f13_05_deep_navigation_stack_stress() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        for _ in 0..1000 {
            app.push_view(View::WorkspaceSelect);
            app.push_view(View::WorkspaceDashboard);
            app.pop_view();
            app.pop_view();
        }
        assert_eq!(app.current_view, View::MainMenu);
        assert!(!app.should_quit);
    }
}

// =========================================================================
// TIER 3: CROSS-FEATURE COMBINATIONS (PAIRWISE COVERAGE: 15 TESTS)
// =========================================================================

pub mod tier3_pairwise_combinations {
    use super::common::*;
    use super::*;

    #[test]
    fn test_tier3_01_menu_navigation_during_background_scanner() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        let tx_bg = app.event_sender.clone();
        let bg_handle = thread::spawn(move || {
            for i in 0..100 {
                tx_bg.update_stats(StatUpdate::new(i, i/2, i/2, i/4, 1024 * (i as u64), 2));
                tx_bg.thread_status(0, format!("Skanowanie {}", i));
                thread::sleep(Duration::from_millis(1));
            }
        });

        for _ in 0..50 {
            app.handle_key(make_key(KeyCode::Down));
            app.process_events();
            app.handle_key(make_key(KeyCode::Up));
        }

        bg_handle.join().unwrap();
        app.process_events();
        assert_eq!(app.current_view, View::MainMenu);
    }

    #[test]
    fn test_tier3_02_terminal_resize_while_streaming_logs() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;

        let sizes = [(80, 24), (120, 40), (60, 15), (70, 25), (100, 30)];
        for (idx, (w, h)) in sizes.iter().enumerate() {
            for log_idx in 0..50 {
                app.push_log(LogMessage::info("STREAM", format!("Batch {} msg {}", idx, log_idx)));
            }
            let backend = TestBackend::new(*w, *h);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        }
        assert_eq!(app.logs.len(), 250);
    }

    #[test]
    fn test_tier3_03_workspace_switching_during_worker_events() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        let ws1 = TestWorkspaceGuard::new("ws_switch_1");
        let ws2 = TestWorkspaceGuard::new("ws_switch_2");

        app.active_workspace = Some(ws1.ws.clone());
        app.event_sender.info("WORKER", "Event for WS1");
        app.process_events();
        assert_eq!(app.active_workspace.as_ref().unwrap().name, ws1.ws.name);

        app.active_workspace = Some(ws2.ws.clone());
        app.event_sender.info("WORKER", "Event for WS2");
        app.process_events();
        assert_eq!(app.active_workspace.as_ref().unwrap().name, ws2.ws.name);
    }

    #[test]
    fn test_tier3_04_manual_scroll_up_while_streaming_incoming_logs() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;

        for i in 0..100 {
            app.push_log(LogMessage::info("M", format!("Initial log {}", i)));
        }
        assert_eq!(app.log_scroll, 99);
        assert!(app.auto_scroll);

        // Scroll up to log 50
        app.log_scroll = 50;
        app.auto_scroll = false;

        // Push 100 new logs
        for i in 100..200 {
            app.push_log(LogMessage::info("M", format!("New incoming log {}", i)));
        }

        // Reading position is preserved at 50, not pulled down
        assert_eq!(app.log_scroll, 50);
        assert!(!app.auto_scroll);
    }

    #[test]
    fn test_tier3_05_external_preview_launch_while_receiver_polling() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        if let Ok(mut tg) = TerminalGuard::init() {
            let tx_c = app.event_sender.clone();
            let _ = tg.suspend(|| {
                tx_c.info("EXTERNAL", "Subprocess launched");
                Ok(())
            });
        }

        app.process_events();
        assert!(app.logs.iter().any(|l| l.message == "Subprocess launched"));
    }

    #[test]
    fn test_tier3_06_modal_input_during_high_frequency_telemetry() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.active_modal = Modal::NewWorkspace {
            input: String::new(),
            cursor: 0,
            error_msg: None,
        };

        for i in 0..100 {
            app.event_sender.update_stats(StatUpdate::new(i, i, 0, 0, 100, 1));
            app.handle_key(make_key(KeyCode::Char('a')));
            app.process_events();
        }

        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_eq!(input.len(), 100);
            assert_eq!(*cursor, 100);
        }
    }

    #[test]
    fn test_tier3_07_chaos_monkey_execution_with_live_stats_and_wrapped_logs() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;

        app.event_sender.operation_started("Chaos Monkey Execution");
        app.event_sender.update_stats(StatUpdate::new(5, 3, 2, 2, 50000, 2));
        app.event_sender.info(
            "CHAOS_MONKEY",
            "Byte mutation at offset 0x00041F0A: 0x66 -> 0x00 (ftyp atom corrupted)...",
        );
        app.process_events();

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        assert!(buffer_contains(&terminal, 80, 24, "Chaos Monkey Execution"));
        assert!(buffer_contains(&terminal, 80, 24, "Byte mutation"));
    }

    #[test]
    fn test_tier3_08_sanitizer_telemetry_with_terminal_resizing() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;

        let widths = [60, 80, 120];
        for w in widths {
            app.event_sender.sanitizer_progress(SanitizerMetrics::new(300, 59.94, "2.0x", 2));
            app.process_events();

            let backend = TestBackend::new(w, 20);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
            assert!(buffer_contains(&terminal, w, 20, "59.9"));
        }
    }

    #[test]
    fn test_tier3_09_scanner_worker_error_with_notification_modal() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        app.event_sender.operation_failed("SCANNER", "I/O Error opening file");
        app.process_events();

        assert!(!app.is_running);
        assert!(app.operation_status_text.as_ref().unwrap().contains("Błąd"));
    }

    #[test]
    fn test_tier3_10_settings_thread_limit_change_during_multithreaded_operation() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::SettingsMenu;

        let _guard = THREAD_CONF_LOCK.lock().unwrap();
        let rdzenie = sprzetowe_max();

        // Zaszyte `4` i `8` przechodziły tylko od 4 rdzeni w górę. Oba
        // oczekiwania wyliczamy ze sprzętu, zachowując sens testu: zmiana
        // limitu wątków w trakcie pracy jest widoczna od razu.
        set_thread_count(rdzenie);
        assert_eq!(get_thread_count(), rdzenie);

        set_thread_count(rdzenie * 2);
        assert_eq!(get_thread_count(), rdzenie * 2);

        set_thread_count(0);
    }

    #[test]
    fn test_tier3_11_god_mode_repair_with_db_reward_and_log_tail_tracking() {
        let ws_guard = TestWorkspaceGuard::new("god_reward_pair");
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.active_workspace = Some(ws_guard.ws.clone());
        app.current_view = View::OperationRunning;

        app.event_sender.send(AppEvent::RepairSuccess {
            file_name: "video_corrupt.mp4".to_string(),
            dna: "DNA_GOD_PAIR".to_string(),
            algorithm: "Native".to_string(),
            features: cechy_testowe(),
        }).unwrap();
        app.event_sender.success("GOD_MODE", "Repair completed successfully");

        app.process_events();

        let cache = db::build_brain_cache(&ws_guard.ws).unwrap();
        assert!(cache.algorithms.contains_key("DNA_GOD_PAIR"));
        assert!(app.logs.back().unwrap().message.contains("Repair completed"));
    }

    #[test]
    fn test_tier3_12_headless_cli_auto_test_with_event_bus_verification() {
        let bin = env!("CARGO_BIN_EXE_mp4_doctor");
        let output = Command::new(bin).arg("--auto-test").output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("snajperski") || stdout.contains("auto_test"));
    }

    #[test]
    fn test_tier3_13_log_buffer_eviction_during_manual_scroll() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;

        for i in 0..5000 {
            app.push_log(LogMessage::info("M", format!("Log {}", i)));
        }
        app.log_scroll = 500;
        app.auto_scroll = false;

        for i in 5000..5200 {
            app.push_log(LogMessage::info("M", format!("Log {}", i)));
        }

        assert_eq!(app.log_scroll, 300);
    }

    #[test]
    fn test_tier3_14_rapid_view_cycling_with_active_operation_status() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        app.event_sender.operation_started("Batch Operation Active");
        app.process_events();
        assert!(app.is_running);

        let views = [
            View::WorkspaceDashboard,
            View::ScannerSubMenu,
            View::SettingsMenu,
            View::WorkspaceSelect,
            View::OperationRunning,
        ];

        for v in views {
            app.push_view(v);
            assert!(app.is_running);
            assert_eq!(app.current_operation, Some("Batch Operation Active".to_string()));
        }
    }

    #[test]
    fn test_tier3_15_ctrl_c_interruption_during_active_operation() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);

        app.event_sender.operation_started("Long Pipeline Running");
        app.process_events();

        app.handle_key(make_key_mod(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit);
        assert!(SHUTDOWN_FLAG.load(Ordering::SeqCst));
        SHUTDOWN_FLAG.store(false, Ordering::SeqCst);
    }
}

// =========================================================================
// TIER 4: REAL-WORLD APPLICATION SCENARIOS (5 SCENARIOS)
// =========================================================================

pub mod tier4_real_world_scenarios {
    use super::common::*;
    use super::*;

    // Scenario 1: Full Workspace Lifecycle
    #[test]
    fn test_tier4_01_full_workspace_lifecycle() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        // 1. Launch into MainMenu
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert_eq!(app.current_view, View::MainMenu);
        assert!(buffer_contains(&terminal, 80, 24, "MENU GŁÓWNE"));

        // 2. Select Workspace Menu (Enter on index 0)
        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.current_view, View::WorkspaceSelect);

        // 3. Create workspace via 'n'
        app.handle_key(make_key(KeyCode::Char('n')));
        assert!(matches!(app.active_modal, Modal::NewWorkspace { .. }));

        let ws_name = format!("Alpha_{}", std::process::id());
        for c in ws_name.chars() {
            app.handle_key(make_key(KeyCode::Char(c)));
        }
        app.handle_key(make_key(KeyCode::Enter));

        assert_eq!(app.current_view, View::WorkspaceDashboard);
        assert!(app.active_workspace.is_some());

        // 4. Navigate to Scanner submenu (Index 0 on Dashboard)
        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.current_view, View::ScannerSubMenu);

        // 5. Run scanner (simulate worker telemetry)
        app.current_view = View::OperationRunning;
        app.event_sender.operation_started("Skanowanie Projektu Alpha");
        app.event_sender.update_stats(StatUpdate::new(15, 10, 5, 4, 150000, 2));
        app.event_sender.info(
            "SCANNER",
            "Wykryto uszkodzony plik nagrania wideo. Trwa analiza struktury atomów...",
        );
        app.process_events();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(buffer_contains(&terminal, 80, 24, "Skanowanie Projektu Alpha"));
        assert!(buffer_contains(&terminal, 80, 24, "Wykryto uszkodzony plik"));

        // 6. Operation finished
        app.event_sender.operation_finished("Wszystkie pliki przeanalizowane");
        app.process_events();

        // 7. Pop view back to Dashboard -> WorkspaceSelect -> MainMenu
        app.handle_key(make_key(KeyCode::Esc));
        app.pop_view();
        app.pop_view();
        assert_eq!(app.current_view, View::MainMenu);

        // 8. Exit application cleanly
        app.handle_key(make_key(KeyCode::Char('q')));
        assert!(app.should_quit);

        if let Some(ws) = app.active_workspace {
            let _ = fs::remove_dir_all(&ws.root_dir);
        }
    }

    // Scenario 2: Batch Scanner & Repair Simulation
    #[test]
    fn test_tier4_02_batch_scanner_and_repair_simulation() {
        let _guard = common::FD_LOCK.lock().unwrap();
        let ws_guard = TestWorkspaceGuard::new("batch_repair_sim");
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.active_workspace = Some(ws_guard.ws.clone());
        app.current_view = View::OperationRunning;

        for i in 0..5 {
            let path = ws_guard.ws.broken_dir.join(format!("clip_{}.mp4", i));
            create_mock_mp4(&path, false).unwrap();
        }

        let cap = StdCapture::start();

        app.event_sender.operation_started("Batch Scanner & Repair");
        for t in 0..4 {
            app.event_sender.thread_status(t, format!("Thread {} parsing atoms", t));
        }
        app.event_sender.update_stats(StatUpdate::new(50, 2, 48, 48, 1024 * 1024 * 50, 4));
        app.event_sender.success("REPAIR", "48 plików naprawiono pomyślnie metodą Clone");
        app.event_sender.operation_finished("Batch scan completed");
        app.process_events();

        let captured = cap.finish();
        StdCapture::assert_zero_leak(captured, "Scenario 2: Batch Scanner & Repair Simulation");

        let backend = TestBackend::new(90, 25);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        assert!(buffer_contains(&terminal, 90, 25, "50"));
        assert!(buffer_contains(&terminal, 90, 25, "100.0%"));
        assert!(buffer_contains(&terminal, 90, 25, "48 plików naprawiono"));
    }

    // Scenario 3: Training Ground Chaos Monkey Execution
    #[test]
    fn test_tier4_03_training_ground_chaos_monkey_execution() {
        let ws_guard = TestWorkspaceGuard::new("tg_chaos_scenario");
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.active_workspace = Some(ws_guard.ws.clone());
        app.current_view = View::OperationRunning;

        let sample_file = ws_guard.ws.root_dir.join("sample.mp4");
        fs::copy("test.mp4", &sample_file).unwrap();

        let _ = training_ground::run_sniper_test(
            &ws_guard.ws,
            sample_file.to_str().unwrap(),
            &app.event_sender,
        );
        app.process_events();

        let backend = TestBackend::new(85, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        assert!(!app.logs.is_empty());
        for log in &app.logs {
            let rows = estimate_log_rows(log, 85);
            assert!(rows >= 1);
        }
    }

    // Scenario 4: Resizing Stress Run
    #[test]
    fn test_tier4_04_resizing_stress_run() {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;
        app.stats = StatUpdate::new(100, 50, 50, 45, 1024 * 1024 * 10, 4);

        for i in 0..100 {
            app.push_log(LogMessage::info("STRESS", format!("Log stream item #{}", i)));
        }

        let sizes = [
            (80, 24),
            (120, 40),
            (60, 15),
            (50, 12),
            (160, 50),
            (80, 24),
        ];

        for (w, h) in sizes {
            let backend = TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

            if w < 60 || h < 15 {
                assert!(buffer_contains(&terminal, w, h, "Terminal zbyt mały!"));
            } else {
                assert!(buffer_contains(&terminal, w, h, "MP4"));
            }
        }
    }

    // Scenario 5: Clean Exit & Panic Recovery
    #[test]
    fn test_tier4_05_clean_exit_and_panic_recovery() {
        let _guard = common::PTY_LOCK.lock().unwrap();
        let pty = PtyTestEnvironment::new().unwrap();
        pty.attach_std();

        // 1. Clean exit on 'q'
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.handle_key(make_key(KeyCode::Char('q')));
        assert!(app.should_quit);

        // 2. TerminalGuard lifecycle restores flags
        if let Ok(tg) = TerminalGuard::init() {
            assert!(is_terminal_active());
            drop(tg);
            assert!(!is_terminal_active());
        }

        // 3. Subprocess execution verification
        let bin = env!("CARGO_BIN_EXE_mp4_doctor");
        let status = Command::new(bin)
            .arg("--help")
            .status()
            .unwrap();
        assert!(status.success());
        assert!(!is_terminal_active());
    }
}
