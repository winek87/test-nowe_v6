//! Milestone 2 Adversarial Verification Test Suite
//!
//! Empirically validates:
//! 1. 100% absence of `println!`, `eprintln!`, `print!`, `eprint!` in operational modules:
//!    - `src/scanner.rs`
//!    - `src/autopilot.rs`
//!    - `src/training_ground.rs`
//!    - `src/sanitizer.rs`
//!    - `src/god_mode.rs`
//!    - `src/db.rs`
//!    - `src/workspace.rs`
//! 2. 0% presence of `indicatif` anywhere across `src/`.
//! 3. Zero terminal stdout/stderr leakage during runtime execution of operational modules.
//! 4. Full telemetry routing through `EventSender` with structured `AppEvent` delivery.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Mutex;
use std::os::fd::FromRawFd;

use mp4_doctor::ai::FeatureVector;
use mp4_doctor::event::{channel, AppEvent, LogLevel};
use mp4_doctor::workspace::Workspace;
use mp4_doctor::{autopilot, db, god_mode, scanner, training_ground};

// Serialize tests that manipulate global process file descriptors (stdout/stderr)
static FD_LOCK: Mutex<()> = Mutex::new(());

unsafe extern "C" {
    fn dup(fd: i32) -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn pipe(fds: *mut i32) -> i32;
}

/// RAII Guard that redirects stdout (fd 1) and stderr (fd 2) to pipes
/// and restores them on drop, capturing any leaked bytes.
struct StdCapture {
    saved_stdout: i32,
    saved_stderr: i32,
    out_pipe: [i32; 2],
    err_pipe: [i32; 2],
}

impl StdCapture {
    fn start() -> Self {
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();

        unsafe {
            let saved_stdout = dup(1);
            let saved_stderr = dup(2);

            let mut out_pipe = [0i32; 2];
            let mut err_pipe = [0i32; 2];

            assert_eq!(pipe(&mut out_pipe[0] as *mut i32), 0, "Failed to create stdout pipe");
            assert_eq!(pipe(&mut err_pipe[0] as *mut i32), 0, "Failed to create stderr pipe");

            // Redirect stdout (1) to out_pipe[1]
            assert_eq!(dup2(out_pipe[1], 1), 1, "Failed to redirect stdout");
            // Redirect stderr (2) to err_pipe[1]
            assert_eq!(dup2(err_pipe[1], 2), 2, "Failed to redirect stderr");

            StdCapture {
                saved_stdout,
                saved_stderr,
                out_pipe,
                err_pipe,
            }
        }
    }

    fn finish(self) -> (Vec<u8>, Vec<u8>) {
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();

        unsafe {
            // Restore stdout and stderr
            dup2(self.saved_stdout, 1);
            dup2(self.saved_stderr, 2);
            close(self.saved_stdout);
            close(self.saved_stderr);

            // Close write ends so read ends hit EOF
            close(self.out_pipe[1]);
            close(self.err_pipe[1]);

            // Read captured stdout
            let mut out_bytes = Vec::new();
            let mut out_file = std::fs::File::from_raw_fd(self.out_pipe[0]);
            let _ = out_file.read_to_end(&mut out_bytes);

            // Read captured stderr
            let mut err_bytes = Vec::new();
            let mut err_file = std::fs::File::from_raw_fd(self.err_pipe[0]);
            let _ = err_file.read_to_end(&mut err_bytes);

            (out_bytes, err_bytes)
        }
    }

    fn assert_zero_leak((out, err): (Vec<u8>, Vec<u8>), context: &str) {
        let out_str = String::from_utf8_lossy(&out);
        let err_str = String::from_utf8_lossy(&err);

        // Filter out cargo test runner output from concurrent test threads
        let leaked_out: Vec<&str> = out_str
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .filter(|l| !(l.starts_with("test ") && (l.ends_with("... ok") || l.ends_with("... FAILED"))))
            .collect();

        let leaked_err: Vec<&str> = err_str
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect();

        assert!(
            leaked_out.is_empty(),
            "LEAK DETECTED: {} leaked lines to stdout: {:?}",
            context,
            leaked_out
        );
        assert!(
            leaked_err.is_empty(),
            "LEAK DETECTED: {} leaked lines to stderr: {:?}",
            context,
            leaked_err
        );
    }
}

// =========================================================================
// TEST 1: STATIC ANALYSIS OF OPERATIONAL MODULES (0 PRINT/EPRINT)
// =========================================================================

#[test]
fn test_static_absence_of_println_and_eprintln_in_operational_modules() {
    let targeted_files = [
        "src/scanner.rs",
        "src/autopilot.rs",
        "src/training_ground.rs",
        "src/sanitizer.rs",
        "src/god_mode.rs",
        "src/db.rs",
        "src/workspace.rs",
    ];

    let forbidden_patterns = ["println!", "eprintln!", "print!", "eprint!"];

    for file_path in &targeted_files {
        let path = Path::new(file_path);
        assert!(path.exists(), "Target file does not exist: {}", file_path);

        let content = fs::read_to_string(path).expect("Failed to read file");
        let mut in_test_block = false;

        for (line_idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("mod tests") {
                in_test_block = true;
            }

            // Skip comments and test code
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                continue;
            }

            for pattern in &forbidden_patterns {
                if trimmed.contains(pattern) {
                    panic!(
                        "VIOLATION: Found forbidden '{}' in {} at line {}: '{}' (in_test={})",
                        pattern,
                        file_path,
                        line_idx + 1,
                        line,
                        in_test_block
                    );
                }
            }
        }
    }
}

// =========================================================================
// TEST 2: STATIC ANALYSIS OF ZERO INDICATIF IN SRC/
// =========================================================================

#[test]
fn test_static_absence_of_indicatif_in_src() {
    fn check_dir(dir: &Path) {
        for entry in fs::read_dir(dir).expect("Failed to read dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                check_dir(&path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let content = fs::read_to_string(&path).expect("Failed to read .rs file");
                assert!(
                    !content.contains("indicatif"),
                    "VIOLATION: Found 'indicatif' in {}!",
                    path.display()
                );
            }
        }
    }

    check_dir(Path::new("src"));
}

// =========================================================================
// TEST 3: SCANNER RUNTIME ZERO STDOUT AND EVENT DELIVERY
// =========================================================================

#[test]
fn test_scanner_runtime_zero_stdout_and_event_bus_delivery() {
    let _lock = FD_LOCK.lock().unwrap();

    let ws_name = "test_ws_m2_scanner_clean";
    let ws = Workspace::init_testowy(ws_name).unwrap();

    // Create an empty input dir to scan
    let empty_dir = ws.root_dir.join("empty_scan_target");
    let _ = fs::create_dir_all(&empty_dir);

    let (tx, rx) = channel();

    let capture = StdCapture::start();
    scanner::run_scanner(&ws, empty_dir.to_str().unwrap(), scanner::ScanMode::FullAuto, &tx);
    let captured = capture.finish();
    StdCapture::assert_zero_leak(captured, "scanner::run_scanner");

    // Verify events arrived over channel
    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(!events.is_empty(), "Scanner should have emitted events to EventSender");
    let has_started = events.iter().any(|e| matches!(e, AppEvent::OperationStarted(_)));
    let has_finished = events.iter().any(|e| matches!(e, AppEvent::OperationFinished(_)));
    let has_warn = events.iter().any(|e| match e {
        AppEvent::Log(l) => l.level == LogLevel::Warn,
        _ => false,
    });

    assert!(has_started, "Scanner should emit OperationStarted");
    assert!(has_finished, "Scanner should emit OperationFinished");
    assert!(has_warn, "Scanner should emit Warn when no files found");

    // Cleanup
    let _ = fs::remove_dir_all(&ws.root_dir);
}

// =========================================================================
// TEST 4: TRAINING GROUND RUNTIME ZERO STDOUT AND TELEMETRY
// =========================================================================

#[test]
fn test_training_ground_runtime_zero_stdout_and_telemetry() {
    let _lock = FD_LOCK.lock().unwrap();

    let ws_name = "test_ws_m2_tg_clean";
    let ws = Workspace::init_testowy(ws_name).unwrap();

    let (tx, rx) = channel();

    let capture = StdCapture::start();
    // Sniper test on non-existent file
    let _ = training_ground::run_sniper_test(&ws, "non_existent_file.mp4", &tx);
    let captured = capture.finish();
    StdCapture::assert_zero_leak(captured, "training_ground::run_sniper_test");

    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(!events.is_empty(), "Training ground should emit events to EventSender");
    let has_failed = events.iter().any(|e| matches!(e, AppEvent::OperationFailed(_, _)));
    assert!(has_failed, "Training ground should emit OperationFailed on missing DNA/file");

    // Cleanup
    let _ = fs::remove_dir_all(&ws.root_dir);
}

// =========================================================================
// TEST 5: GOD MODE RUNTIME ZERO STDOUT AND FAILURE EVENT
// =========================================================================

#[test]
fn test_god_mode_runtime_zero_stdout_and_event() {
    let _lock = FD_LOCK.lock().unwrap();

    let ws_name = "test_ws_m2_god_mode_clean";
    let ws = Workspace::init_testowy(ws_name).unwrap();

    let (tx, rx) = channel();

    let capture = StdCapture::start();
    let result = god_mode::run_extreme_mutation(&ws, "non_existent_file.mp4", &tx);
    let captured = capture.finish();
    StdCapture::assert_zero_leak(captured, "god_mode::run_extreme_mutation");

    assert!(result.is_err(), "Expected error for missing file");

    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(!events.is_empty(), "God mode should emit events");
    assert!(events.iter().any(|e| matches!(e, AppEvent::OperationStarted(_))));

    // Cleanup
    let _ = fs::remove_dir_all(&ws.root_dir);
}

// =========================================================================
// TEST 6: AUTOPILOT RUNTIME ZERO STDOUT ON ERROR PATH
// =========================================================================

#[test]
fn test_autopilot_runtime_zero_stdout_on_error_path() {
    let _lock = FD_LOCK.lock().unwrap();

    let ws_name = "test_ws_m2_autopilot_clean";
    let ws = Workspace::init_testowy(ws_name).unwrap();
    let brain_cache = db::build_brain_cache(&ws).unwrap_or_default();

    let (tx, rx) = channel();

    let capture = StdCapture::start();
    let res = autopilot::run(&ws, "non_existent_broken.mp4", &brain_cache, &tx, 0);
    let captured = capture.finish();
    StdCapture::assert_zero_leak(captured, "autopilot::run");

    assert!(res.is_err(), "Autopilot must return Err for missing DNA");

    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(!events.is_empty(), "Autopilot should emit events to EventSender");
    let has_error = events.iter().any(|e| match e {
        AppEvent::Log(l) => l.level == LogLevel::Error,
        _ => false,
    });
    assert!(has_error, "Autopilot should emit Error log message when file has no DNA");

    // Cleanup
    let _ = fs::remove_dir_all(&ws.root_dir);
}

// =========================================================================
// TEST 7: WORKSPACE DIRECTORY CREATION AND OPTIMIZATION ZERO STDOUT
// =========================================================================

#[test]
fn test_workspace_zero_stdout_operations() {
    let _lock = FD_LOCK.lock().unwrap();

    let ws_name = "test_ws_m2_workspace_clean";

    let capture = StdCapture::start();
    let ws = Workspace::init_testowy(ws_name).unwrap();
    let _ = ws.has_broken_files();
    let _ = ws.optimize_storage();
    let _ = mp4_doctor::workspace::get_available_workspaces();
    let captured = capture.finish();
    StdCapture::assert_zero_leak(captured, "Workspace operations");

    // Cleanup
    let _ = fs::remove_dir_all(&ws.root_dir);
}

// =========================================================================
// TEST 8: DB CLOUD SYNC AND KNOWLEDGE BASE ZERO STDOUT
// =========================================================================

#[test]
fn test_db_operations_zero_stdout() {
    let _lock = FD_LOCK.lock().unwrap();

    let ws_name = "test_ws_m2_db_clean";
    let ws = Workspace::init_testowy(ws_name).unwrap();

    let (tx, rx) = channel();

    let capture = StdCapture::start();
    let conn = db::init_db(&ws);
    assert!(conn.is_ok(), "Failed to init db");

    let _ = db::save_donor(&ws, "TEST_DNA_123", "/fake/path/donor.moov");
    let cechy = FeatureVector { file_size_mb: 1.0, entropy: 1.0, h264_profile: 0.0, aac_freq: 0.0, video_audio_ratio: 0.0 };
    let _ = db::reward_algorithm(&ws, "TEST_DNA_123", "Native", &cechy);
    let _ = db::penalize_algorithm(&ws, "TEST_DNA_123", "Clone", &cechy);
    db::mark_trained(&ws, "abc123hash");
    let _ = db::get_all_trained(&ws);
    let _ = db::build_brain_cache(&ws);
    let _ = db::get_db_stats(&ws);

    // sync_with_cloud with event_sender (unreachable test endpoint http://127.0.0.1:3000)
    let _ = db::sync_with_cloud(&ws, Some(&tx));
    let captured = capture.finish();
    StdCapture::assert_zero_leak(captured, "db operations");

    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }
    // sync_with_cloud should have routed messages through EventSender
    assert!(!events.is_empty(), "db::sync_with_cloud should emit events to EventSender");

    // Cleanup
    let _ = fs::remove_dir_all(&ws.root_dir);
}
