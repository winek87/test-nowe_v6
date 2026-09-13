//! Milestone 3 Adversarial Verification Test Suite
//!
//! Empirically validates:
//! 1. `TerminalGuard` lifecycle: init, active state, PTY raw mode enablement,
//!    alternate screen entry, cursor hiding.
//! 2. `TerminalGuard` teardown & idempotency: multiple `restore()` calls, `force_restore()`.
//! 3. RAII `Drop` cleanup: ensures drop cleanly restores terminal state.
//! 4. Subprocess suspension (`TerminalGuard::suspend`): cooked mode and primary screen
//!    during external execution, clean re-entry to raw mode and alternate screen,
//!    resumption guarantees even when the suspended action fails with `io::Error`.
//! 5. Panic safety: process-wide panic hook restores terminal state, disables raw mode,
//!    and leaves alternate screen before printing panic backtraces.

use std::ffi::CStr;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::Mutex;
use std::thread;

use mp4_doctor::tui::terminal::{
    force_restore, install_panic_hook, is_terminal_active, TerminalGuard,
};

// Serialize tests that alter process-global terminal descriptors or modes
static PTY_TEST_LOCK: Mutex<()> = Mutex::new(());

// Standard POSIX / C library bindings for PTY manipulation
unsafe extern "C" {
    fn posix_openpt(flags: i32) -> i32;
    fn grantpt(fd: i32) -> i32;
    fn unlockpt(fd: i32) -> i32;
    fn ptsname(fd: i32) -> *const std::os::raw::c_char;
    fn dup(fd: i32) -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn tcgetattr(fd: i32, termios_p: *mut u8) -> i32;
}

const O_RDWR: i32 = 2;
const O_NOCTTY: i32 = 0x100;
const O_NONBLOCK: i32 = 0x800;

// Size of struct termios in Linux (glibc x86_64: 60 bytes)
const TERMIOS_SIZE: usize = 64;

// Indices and bitmasks for termios in Linux
// c_lflag is at offset 12 in termios (4 bytes: u32)
const ICANON: u32 = 0x00000002;
const ECHO: u32 = 0x00000008;
#[allow(dead_code)]
const ISIG: u32 = 0x00000001;

/// RAII helper that creates a real Linux pseudo-terminal (PTY) pair
/// and temporarily redirects standard input (fd 0) and standard output (fd 1)
/// to the slave PTY device.
struct PtyTestEnvironment {
    master_fd: RawFd,
    slave_fd: RawFd,
    saved_stdin: RawFd,
    saved_stdout: RawFd,
}

impl PtyTestEnvironment {
    fn new() -> io::Result<Self> {
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

        let pts_ptr = unsafe { ptsname(master) };
        if pts_ptr.is_null() {
            unsafe { close(master) };
            return Err(io::Error::last_os_error());
        }
        let pts_cstr = unsafe { CStr::from_ptr(pts_ptr) };
        let pts_path = pts_cstr.to_str().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let slave_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pts_path)?;
        let slave = slave_file.as_raw_fd();
        std::mem::forget(slave_file); // Keep fd open, managed manually

        let saved_stdin = unsafe { dup(0) };
        let saved_stdout = unsafe { dup(1) };
        if saved_stdin < 0 || saved_stdout < 0 {
            unsafe {
                close(slave);
                close(master);
            }
            return Err(io::Error::last_os_error());
        }

        // Redirect stdin (0) and stdout (1) to the PTY slave
        unsafe {
            dup2(slave, 0);
            dup2(slave, 1);
        }

        Ok(Self {
            master_fd: master,
            slave_fd: slave,
            saved_stdin,
            saved_stdout,
        })
    }

    /// Reads all currently available output written to the slave from the master fd.
    fn drain_master(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 8192];
        let mut output = Vec::new();
        loop {
            let n = unsafe {
                libc_read(self.master_fd, buf.as_mut_ptr(), buf.len())
            };
            if n > 0 {
                output.extend_from_slice(&buf[..n as usize]);
            } else {
                break;
            }
        }
        output
    }

    /// Checks whether raw mode is enabled on the slave terminal
    /// (ICANON and ECHO bits cleared in c_lflag).
    fn is_raw_mode_active(&self) -> bool {
        let mut termios = [0u8; TERMIOS_SIZE];
        let ret = unsafe { tcgetattr(self.slave_fd, termios.as_mut_ptr()) };
        if ret != 0 {
            return false;
        }
        // Offset 12: c_lflag (u32, little-endian on x86_64)
        let lflag = u32::from_ne_bytes([
            termios[12],
            termios[13],
            termios[14],
            termios[15],
        ]);
        (lflag & (ICANON | ECHO)) == 0
    }
}

unsafe extern "C" {
    #[link_name = "read"]
    fn libc_read(fd: i32, buf: *mut u8, count: usize) -> isize;
}

impl Drop for PtyTestEnvironment {
    fn drop(&mut self) {
        // Restore original stdin and stdout
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

// ---------------------------------------------------------------------------
// TEST 1: Full Lifecycle (init, active state, restore, idempotency)
// ---------------------------------------------------------------------------
#[test]
fn test_terminal_guard_lifecycle_and_idempotency_pty() {
    let _guard = PTY_TEST_LOCK.lock().unwrap();
    let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY");

    // 1. Initial State: Terminal not active, not in raw mode
    assert!(!is_terminal_active(), "TERMINAL_ACTIVE should be false initially");
    assert!(!pty.is_raw_mode_active(), "Terminal should initially be in cooked mode");

    // 2. Initialize TerminalGuard inside PTY environment
    let mut term_guard = TerminalGuard::init().expect("TerminalGuard::init failed in PTY");
    assert!(term_guard.is_active(), "Guard should report is_active == true");
    assert!(is_terminal_active(), "Global TERMINAL_ACTIVE should be true");
    assert!(pty.is_raw_mode_active(), "PTY should now have raw mode enabled (ICANON/ECHO cleared)");

    // Drain master output and verify escape sequences
    let init_output = pty.drain_master();
    let init_str = String::from_utf8_lossy(&init_output);
    assert!(
        init_str.contains("\x1b[?1049h") || init_str.contains("?1049h"),
        "init() must write EnterAlternateScreen escape sequence to stdout. Got: {:?}",
        init_str
    );
    assert!(
        init_str.contains("\x1b[?25l") || init_str.contains("?25l"),
        "init() must write Hide cursor escape sequence to stdout. Got: {:?}",
        init_str
    );

    // 3. First restore(): cleanly return to cooked mode
    term_guard.restore().expect("First restore() failed");
    assert!(!term_guard.is_active(), "Guard should report is_active == false");
    assert!(!is_terminal_active(), "Global TERMINAL_ACTIVE should be false");
    assert!(!pty.is_raw_mode_active(), "PTY should return to cooked mode");

    let restore_output = pty.drain_master();
    let restore_str = String::from_utf8_lossy(&restore_output);
    assert!(
        restore_str.contains("\x1b[?1049l") || restore_str.contains("?1049l"),
        "restore() must write LeaveAlternateScreen escape sequence to stdout. Got: {:?}",
        restore_str
    );
    assert!(
        restore_str.contains("\x1b[?25h") || restore_str.contains("?25h"),
        "restore() must write Show cursor escape sequence to stdout. Got: {:?}",
        restore_str
    );

    // 4. Idempotency: multiple restore() calls must succeed without side-effects or errors
    for i in 1..=5 {
        assert!(
            term_guard.restore().is_ok(),
            "Repeated restore() call #{} should succeed idempotently",
            i
        );
        assert!(!term_guard.is_active());
        assert!(!is_terminal_active());
        assert!(!pty.is_raw_mode_active());
    }

    // Master should have received 0 redundant escape codes during idempotent calls
    let redundant_output = pty.drain_master();
    assert_eq!(
        redundant_output.len(),
        0,
        "Idempotent restore() calls should emit zero duplicate escape sequences"
    );
}

// ---------------------------------------------------------------------------
// TEST 2: RAII Drop Cleanup in PTY
// ---------------------------------------------------------------------------
#[test]
fn test_terminal_guard_drop_cleanup_pty() {
    let _guard = PTY_TEST_LOCK.lock().unwrap();
    let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY");

    {
        let term_guard = TerminalGuard::init().expect("TerminalGuard::init failed in PTY");
        assert!(term_guard.is_active());
        assert!(is_terminal_active());
        assert!(pty.is_raw_mode_active());
        let _ = pty.drain_master();
        // Guard dropped implicitly here
    }

    // After drop:
    assert!(!is_terminal_active(), "Drop must reset TERMINAL_ACTIVE to false");
    assert!(!pty.is_raw_mode_active(), "Drop must restore cooked mode");

    let drop_output = pty.drain_master();
    let drop_str = String::from_utf8_lossy(&drop_output);
    assert!(
        drop_str.contains("\x1b[?1049l") || drop_str.contains("?1049l"),
        "Drop must emit LeaveAlternateScreen. Got: {:?}",
        drop_str
    );
    assert!(
        drop_str.contains("\x1b[?25h") || drop_str.contains("?25h"),
        "Drop must emit Show cursor. Got: {:?}",
        drop_str
    );
}

// ---------------------------------------------------------------------------
// TEST 3: Subprocess Suspension (TerminalGuard::suspend)
// ---------------------------------------------------------------------------
#[test]
fn test_terminal_guard_suspend_subprocess_lifecycle() {
    let _guard = PTY_TEST_LOCK.lock().unwrap();
    let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY");

    let mut term_guard = TerminalGuard::init().expect("TerminalGuard::init failed in PTY");
    let _ = pty.drain_master();

    assert!(term_guard.is_active());
    assert!(is_terminal_active());
    assert!(pty.is_raw_mode_active());

    let mut action_executed = false;

    // Suspend TUI mode to execute simulated external command
    let suspend_res = term_guard.suspend(|| {
        action_executed = true;

        // VERIFY SUSPENDED STATE:
        // 1. Guard and global active flags must be false
        assert!(!is_terminal_active(), "During suspend, TERMINAL_ACTIVE must be false");

        // 2. Terminal must be in cooked mode so external subprocess has standard echo/line buffering
        assert!(!pty.is_raw_mode_active(), "During suspend, PTY must be in cooked mode");

        // 3. Verify LeaveAlternateScreen and Show cursor were emitted before running action
        let suspended_output = pty.drain_master();
        let s_str = String::from_utf8_lossy(&suspended_output);
        assert!(
            s_str.contains("\x1b[?1049l") || s_str.contains("?1049l"),
            "suspend must leave alternate screen before running subprocess. Got: {:?}",
            s_str
        );
        assert!(
            s_str.contains("\x1b[?25h") || s_str.contains("?25h"),
            "suspend must show cursor before running subprocess. Got: {:?}",
            s_str
        );

        // Simulate external subprocess writing to stdout
        let mut stdout = io::stdout();
        stdout.write_all(b"[EXTERNAL_SUBPROCESS_OUTPUT]\n")?;
        stdout.flush()?;

        Ok(999usize)
    });

    assert!(action_executed, "Suspension closure must execute");
    assert_eq!(suspend_res.unwrap(), 999, "Suspension result must match closure return value");

    // VERIFY RESUMED STATE:
    // 1. Terminal guard and global active flags must be restored to true
    assert!(term_guard.is_active(), "After suspend, guard must be active again");
    assert!(is_terminal_active(), "After suspend, TERMINAL_ACTIVE must be true again");

    // 2. PTY must be back in raw mode
    assert!(pty.is_raw_mode_active(), "After suspend, PTY must be back in raw mode");

    // 3. Alternate screen and cursor hiding must be re-emitted
    let resumed_output = pty.drain_master();
    let r_str = String::from_utf8_lossy(&resumed_output);
    assert!(
        r_str.contains("[EXTERNAL_SUBPROCESS_OUTPUT]"),
        "PTY master should have captured external subprocess stdout"
    );
    assert!(
        r_str.contains("\x1b[?1049h") || r_str.contains("?1049h"),
        "suspend must re-enter alternate screen upon resumption"
    );
    assert!(
        r_str.contains("\x1b[?25l") || r_str.contains("?25l"),
        "suspend must re-hide cursor upon resumption"
    );

    // Clean teardown
    term_guard.restore().expect("Clean teardown failed");
}

// ---------------------------------------------------------------------------
// TEST 4: Subprocess Suspension When External Action Fails (Resumption Invariance)
// ---------------------------------------------------------------------------
#[test]
fn test_terminal_guard_suspend_error_resumes_cleanly() {
    let _guard = PTY_TEST_LOCK.lock().unwrap();
    let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY");

    let mut term_guard = TerminalGuard::init().expect("TerminalGuard::init failed in PTY");
    let _ = pty.drain_master();

    // Action returns an error (simulating ffplay not found or exit failure)
    let action_err: io::Result<()> = term_guard.suspend(|| {
        Err(io::Error::new(io::ErrorKind::NotFound, "ffplay: command not found"))
    });

    assert!(action_err.is_err(), "Action error should be propagated");
    assert_eq!(action_err.unwrap_err().kind(), io::ErrorKind::NotFound);

    // CRITICAL REQUIREMENT:
    // Even when the action fails, the terminal MUST be cleanly resumed so TUI can report the error
    assert!(term_guard.is_active(), "Terminal guard must resume active state even after error");
    assert!(is_terminal_active(), "TERMINAL_ACTIVE must be true after error resumption");
    assert!(pty.is_raw_mode_active(), "PTY must be back in raw mode even after error");

    term_guard.restore().expect("Clean teardown failed");
}

// ---------------------------------------------------------------------------
// TEST 5: Panic Safety — Hook Restoration in Isolated Subprocess
// ---------------------------------------------------------------------------
#[test]
fn test_panic_safety_subprocess_hook_restoration() {
    // We execute a child process with a PTY that enters raw mode, installs panic hook,
    // and panics. We inspect the master PTY to ensure:
    // 1. LeaveAlternateScreen and Show cursor are emitted.
    // 2. Terminal returns to cooked mode without corrupting the parent.
    // Child execution path must run before parent PTY setup
    if std::env::var("MP4_DOCTOR_TEST_PANIC_WORKER").is_ok() {
        install_panic_hook();
        let guard = TerminalGuard::init().expect("Child failed TerminalGuard::init");
        assert!(guard.is_active());
        assert!(is_terminal_active());
        // Deliberate panic while guard is active
        panic!("ADVERSARIAL_PANIC_TEST_TRIGGER");
    }

    let _guard = PTY_TEST_LOCK.lock().unwrap();

    let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY");

    let exe_path = std::env::current_exe().expect("Failed to get current_exe");
    let mut cmd = std::process::Command::new(exe_path);
    let stdin_fd = unsafe { dup(pty.slave_fd) };
    let stdout_fd = unsafe { dup(pty.slave_fd) };
    let stderr_fd = unsafe { dup(pty.slave_fd) };
    cmd.arg("test_panic_safety_subprocess_hook_restoration")
        .arg("--nocapture")
        .env("MP4_DOCTOR_TEST_PANIC_WORKER", "1")
        .stdin(unsafe { std::process::Stdio::from_raw_fd(stdin_fd) })
        .stdout(unsafe { std::process::Stdio::from_raw_fd(stdout_fd) })
        .stderr(unsafe { std::process::Stdio::from_raw_fd(stderr_fd) });

    let status = cmd.status().expect("Failed to wait on panic child");
    assert!(!status.success(), "Child process should exit with failure due to panic");

    // Read all output emitted by child during panic
    let child_output = pty.drain_master();
    let child_str = String::from_utf8_lossy(&child_output);

    // Verify child panic message was printed
    assert!(
        child_str.contains("ADVERSARIAL_PANIC_TEST_TRIGGER"),
        "Child output must contain panic message. Got: {:?}",
        child_str
    );

    // Verify panic hook restored terminal BEFORE printing panic message:
    // Must contain LeaveAlternateScreen and Show cursor
    assert!(
        child_str.contains("\x1b[?1049l") || child_str.contains("?1049l"),
        "Panic hook must emit LeaveAlternateScreen escape sequence on panic. Output was: {:?}",
        child_str
    );
    assert!(
        child_str.contains("\x1b[?25h") || child_str.contains("?25h"),
        "Panic hook must emit Show cursor escape sequence on panic. Output was: {:?}",
        child_str
    );
}

// ---------------------------------------------------------------------------
// TEST 6: Emergency force_restore Concurrency Stress
// ---------------------------------------------------------------------------
#[test]
fn test_force_restore_concurrency_stress() {
    let _guard = PTY_TEST_LOCK.lock().unwrap();

    let mut handles = Vec::new();
    for _ in 0..20 {
        handles.push(thread::spawn(|| {
            for _ in 0..100 {
                force_restore();
                assert!(!is_terminal_active());
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert!(!is_terminal_active());
}

// ---------------------------------------------------------------------------
// TEST 7: Headless Execution in Real PTY — Zero Alternate Screen / No Raw Mode
// ---------------------------------------------------------------------------
#[test]
fn test_headless_execution_in_pty_no_alternate_screen_no_raw_mode() {
    let _guard = PTY_TEST_LOCK.lock().unwrap();

    let binary_path = env!("CARGO_BIN_EXE_mp4_doctor");

    for flag in &["--help", "-h", "--version"] {
        let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY for headless test");

        let stdin_fd = unsafe { dup(pty.slave_fd) };
        let stdout_fd = unsafe { dup(pty.slave_fd) };
        let stderr_fd = unsafe { dup(pty.slave_fd) };

        let mut cmd = std::process::Command::new(binary_path);
        cmd.arg(flag)
            .stdin(unsafe { std::process::Stdio::from_raw_fd(stdin_fd) })
            .stdout(unsafe { std::process::Stdio::from_raw_fd(stdout_fd) })
            .stderr(unsafe { std::process::Stdio::from_raw_fd(stderr_fd) });

        let status = cmd.status().expect("Failed to execute headless binary");
        assert!(status.success(), "Command 'mp4_doctor {}' must exit with code 0", flag);

        // Verify the PTY remained strictly in cooked mode
        assert!(
            !pty.is_raw_mode_active(),
            "Headless command '{}' must never put terminal into raw mode",
            flag
        );

        let output = pty.drain_master();
        let out_str = String::from_utf8_lossy(&output);

        // Verify no alternate screen escape sequence was emitted
        assert!(
            !out_str.contains("\x1b[?1049h") && !out_str.contains("?1049h"),
            "Headless command '{}' must NOT emit EnterAlternateScreen. Got: {:?}",
            flag,
            out_str
        );

        // Verify cursor was not hidden
        assert!(
            !out_str.contains("\x1b[?25l") && !out_str.contains("?25l"),
            "Headless command '{}' must NOT emit Hide cursor. Got: {:?}",
            flag,
            out_str
        );

        // Verify output contains expected text
        if *flag == "--version" {
            assert!(out_str.contains("mp4_doctor 2.0.0"), "Expected version string, got: {:?}", out_str);
        } else {
            assert!(
                out_str.contains("MP4 Doctor Enterprise AI") || out_str.contains("Usage: mp4_doctor"),
                "Expected help text, got: {:?}",
                out_str
            );
        }
    }
}

// ---------------------------------------------------------------------------
// TEST 8: TerminalGuard Rapid Re-init & Drop Churn Stress
// ---------------------------------------------------------------------------
// Zmierzone empirycznie: ~2s na każdy cykl `TerminalGuard::init()`/drop w
// prawdziwym PTY (prawdopodobnie zapytanie DSR o pozycję kursora, na które w
// sztucznym PTY bez prawdziwego emulatora terminala nikt nie odpowiada, aż do
// timeoutu) - przy 50 cyklach to ~100s. Razem z analogicznymi testami w
// `m6_adversarial_hardening.rs` te kilka testów odpowiadało za większość
// czasu całego `cargo test --workspace` w tym repo. Pozostałe testy PTY w tym
// pliku są znacznie szybsze (pojedyncze cykle, <5s) i zostają uruchamiane
// domyślnie.
#[test]
#[ignore = "Test PTY - 50 cykli init/drop w prawdziwym pseudoterminalu, ~100s. Uruchom z --ignored."]
fn test_terminal_guard_rapid_reinit_churn_stress() {
    let _guard = PTY_TEST_LOCK.lock().unwrap();
    let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY for churn stress");

    for cycle in 1..=50 {
        assert!(!is_terminal_active(), "Cycle {}: Terminal must not be active before init", cycle);
        assert!(!pty.is_raw_mode_active(), "Cycle {}: Terminal must be cooked before init", cycle);

        {
            let guard = TerminalGuard::init().expect("Init failed during rapid churn");
            assert!(guard.is_active(), "Cycle {}: Guard must report active", cycle);
            assert!(is_terminal_active(), "Cycle {}: Global active must be true", cycle);
            assert!(pty.is_raw_mode_active(), "Cycle {}: Raw mode must be active", cycle);

            let init_out = pty.drain_master();
            let init_str = String::from_utf8_lossy(&init_out);
            assert!(
                init_str.contains("?1049h"),
                "Cycle {}: Must emit EnterAlternateScreen",
                cycle
            );
            assert!(
                init_str.contains("?25l"),
                "Cycle {}: Must emit Hide cursor",
                cycle
            );
            // guard drops here
        }

        assert!(!is_terminal_active(), "Cycle {}: Global active must be false after drop", cycle);
        assert!(!pty.is_raw_mode_active(), "Cycle {}: Raw mode must be cleared after drop", cycle);

        let drop_out = pty.drain_master();
        let drop_str = String::from_utf8_lossy(&drop_out);
        assert!(
            drop_str.contains("?1049l"),
            "Cycle {}: Must emit LeaveAlternateScreen on drop",
            cycle
        );
        assert!(
            drop_str.contains("?25h"),
            "Cycle {}: Must emit Show cursor on drop",
            cycle
        );
    }
}

// ---------------------------------------------------------------------------
// TEST 9: TerminalGuard Concurrency & Race Condition Challenge
// ---------------------------------------------------------------------------
// Ten sam koszt ~2s/cykl co `test_terminal_guard_rapid_reinit_churn_stress`
// wyżej, tu przez 20 cykli init/restore pod współbieżnym spamem force_restore.
#[test]
#[ignore = "Test PTY - 20 cykli init/restore w prawdziwym pseudoterminalu pod współbieżnym obciążeniem, ~40s. Uruchom z --ignored."]
fn test_terminal_guard_concurrent_force_restore_during_lifecycle() {
    let _guard = PTY_TEST_LOCK.lock().unwrap();
    let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY for race challenge");

    // Spawn 10 background threads aggressively calling force_restore
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut threads = Vec::new();

    for _ in 0..10 {
        let stop_clone = std::sync::Arc::clone(&stop);
        threads.push(thread::spawn(move || {
            while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                force_restore();
                thread::yield_now();
            }
        }));
    }

    // Main thread creates and drops terminal guards under concurrent force_restore spam
    for _ in 0..20 {
        if let Ok(mut guard) = TerminalGuard::init() {
            // Either guard remains active or background thread forcefully restored it
            let _ = guard.restore();
        }
    }

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for t in threads {
        t.join().unwrap();
    }

    // Final state must be fully restored and cooked
    force_restore();
    assert!(!is_terminal_active());
    assert!(!pty.is_raw_mode_active());
}

