//! Milestone 6 Adversarial Coverage Hardening & Verification Suite (Tier 5)
//!
//! White-box adversarial stress testing against MP4 Doctor TUI & operational subsystems:
//! 1. Concurrency & Event Bus Stress:
//!    - 50,000 heterogeneous events pushed concurrently from 16 worker threads through `EventSender`.
//!    - Verifies zero dropped events, zero deadlocks, and bounded memory consumption in `App.logs`.
//! 2. Terminal Lifecycle & Signal Stress:
//!    - Rapidly toggles raw mode and alternate screen 100 times in a real Linux PTY environment.
//!    - 100 RAII drop cycles ensuring cooked mode and primary screen restoration.
//!    - Tests signal recovery (SIGINT) in PTY: ensures `force_restore()` guarantees cooked mode.
//!    - Tests panic recovery in PTY: ensures custom panic hook guarantees primary screen restoration.
//! 3. Interactive Navigation Fuzzing:
//!    - Fuzzes keyboard event loop with 2,000+ random crossterm events (special keys, modifiers,
//!      Polish UTF-8 characters, function keys, and resize events) during active operation states.
//!    - Verifies bounded log scroll, invariant preservation, and zero panic during drawing.

use std::ffi::CStr;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use mp4_doctor::ai::FeatureVector;
use mp4_doctor::event::{
    channel, AppEvent, LogLevel, LogMessage, SanitizerMetrics, StatUpdate, WorkerStatus,
};
use mp4_doctor::tui::app::{App, View, MAX_LOG_HISTORY};
use mp4_doctor::tui::terminal::{
    force_restore, install_panic_hook, is_terminal_active, TerminalGuard,
};
use mp4_doctor::tui::ui;
use mp4_doctor::SHUTDOWN_FLAG;

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
    fn kill(pid: i32, sig: i32) -> i32;
    #[link_name = "read"]
    fn libc_read(fd: i32, buf: *mut u8, count: usize) -> isize;
}

const O_RDWR: i32 = 2;
const O_NOCTTY: i32 = 0x100;
const O_NONBLOCK: i32 = 0x800;

// Size of struct termios in Linux (glibc x86_64: 60 bytes)
const TERMIOS_SIZE: usize = 64;

// Indices and bitmasks for termios in Linux
const ICANON: u32 = 0x00000002;
const ECHO: u32 = 0x00000008;

/// RAII helper managing a real Linux pseudo-terminal (PTY) pair
/// and redirecting standard input (fd 0) and standard output (fd 1)
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
        let pts_path = pts_cstr
            .to_str()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let slave_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pts_path)?;
        let slave = slave_file.as_raw_fd();
        std::mem::forget(slave_file); // Managed manually

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
            let n = unsafe { libc_read(self.master_fd, buf.as_mut_ptr(), buf.len()) };
            if n > 0 {
                output.extend_from_slice(&buf[..n as usize]);
            } else {
                break;
            }
        }
        output
    }

    /// Checks whether raw mode is enabled on the slave terminal (ICANON and ECHO bits cleared).
    fn is_raw_mode_active(&self) -> bool {
        let mut termios = [0u8; TERMIOS_SIZE];
        let ret = unsafe { tcgetattr(self.slave_fd, termios.as_mut_ptr()) };
        if ret != 0 {
            return false;
        }
        let lflag = u32::from_ne_bytes([
            termios[12],
            termios[13],
            termios[14],
            termios[15],
        ]);
        (lflag & (ICANON | ECHO)) == 0
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

// =========================================================================
// SUITE 1: CONCURRENCY & EVENT BUS STRESS
// =========================================================================

/// Generates a deterministic heterogeneous AppEvent based on thread ID and sequence index.
fn make_heterogeneous_event(thread_id: usize, seq: usize) -> AppEvent {
    let kind = (thread_id * 3125 + seq) % 10;
    match kind {
        0 => AppEvent::Log(LogMessage::new(
            LogLevel::Debug,
            format!("THR_{}", thread_id),
            format!("Debug atom offset: 0x{:08x} / seq {}", seq * 16, seq),
        )),
        1 => AppEvent::Log(LogMessage::new(
            LogLevel::Info,
            format!("THR_{}", thread_id),
            format!(
                "Przetwarzanie z polskimi znakami: zażółć gęślą jaźń seq {} t{}",
                seq, thread_id
            ),
        )),
        2 => AppEvent::Log(LogMessage::new(
            LogLevel::Success,
            format!("THR_{}", thread_id),
            format!("Naprawiono kontener wideo pomyślnie - kamień milowy {}", seq),
        )),
        3 => AppEvent::Log(LogMessage::new(
            LogLevel::Warn,
            format!("THR_{}", thread_id),
            format!("Wykryto anomalię deskryptora w pliku test_{}.mp4", seq),
        )),
        4 => AppEvent::Log(LogMessage::new(
            LogLevel::Error,
            format!("THR_{}", thread_id),
            format!("Krytyczny brak atomu MOOV pod przesunięciem {}", seq * 1024),
        )),
        5 => AppEvent::Stats(StatUpdate::new(
            seq + 1,
            (seq * 8) / 10,
            (seq * 2) / 10,
            seq / 5,
            (seq as u64) * 1024 * 512,
            16,
        )),
        6 => AppEvent::ThreadStatus(WorkerStatus::new(
            thread_id,
            format!("Skanowanie potokowe ramki {}", seq * 30),
        )),
        7 => AppEvent::SanitizerProgress(SanitizerMetrics::new(
            (seq as u64) * 60,
            30.0 + ((seq % 60) as f32),
            format!("{}.5x", (seq % 4) + 1),
            ((seq % 2) + 1) as u8,
        )),
        8 => AppEvent::Progress {
            current: seq,
            total: 3125,
            message: Some(format!("Postęp potoku wątku {}", thread_id)),
        },
        _ => {
            if seq % 3 == 0 {
                AppEvent::OperationStarted(format!("Op_{}_{}", thread_id, seq))
            } else if seq % 3 == 1 {
                AppEvent::DonorFound {
                    dna: format!("DNA_{}_{:x}", thread_id, seq),
                    moov_path: format!("/tmp/moov_{}_{}.bin", thread_id, seq),
                }
            } else {
                AppEvent::RepairSuccess {
                    file_name: format!("corrupt_{}_{}.mp4", thread_id, seq),
                    dna: format!("DNA_{}", thread_id),
                    algorithm: "engine_recontainer".to_string(),
                    features: FeatureVector { file_size_mb: 10.0, entropy: 7.0, h264_profile: 100.0, aac_freq: 44100.0, video_audio_ratio: 0.8 },
                }
            }
        }
    }
}

#[test]
fn test_m6_concurrency_stress_50k_events_16_threads() {
    const NUM_THREADS: usize = 16;
    const EVENTS_PER_THREAD: usize = 3_125;
    const TOTAL_EVENTS: usize = NUM_THREADS * EVENTS_PER_THREAD; // Exactly 50,000

    let (tx, rx) = channel();
    let mut app = App::with_channel(tx.clone(), rx);

    let barrier = Arc::new(Barrier::new(NUM_THREADS + 1));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    let start_time = Instant::now();

    for t_id in 0..NUM_THREADS {
        let thread_tx = tx.clone();
        let thread_barrier = barrier.clone();

        handles.push(thread::spawn(move || {
            // Synchronize all 16 worker threads to start concurrently
            thread_barrier.wait();

            for seq in 0..EVENTS_PER_THREAD {
                let ev = make_heterogeneous_event(t_id, seq);
                thread_tx
                    .send(ev)
                    .expect("EventSender::send must not fail while receiver is alive");
            }
        }));
    }

    // Release all 16 workers simultaneously
    barrier.wait();

    // Drain events on the TUI thread while workers are actively producing
    let mut total_drained = 0;
    let mut log_count = 0;
    let mut stat_count = 0;
    let mut thread_status_count = 0;
    let mut other_count = 0;

    let drain_timeout = Duration::from_secs(30);
    let loop_start = Instant::now();

    while total_drained < TOTAL_EVENTS {
        let mut got_any = false;
        while let Ok(event) = app.event_receiver.try_recv() {
            got_any = true;
            match &event {
                AppEvent::Log(_) => log_count += 1,
                AppEvent::Stats(_) => stat_count += 1,
                AppEvent::ThreadStatus(_) => thread_status_count += 1,
                _ => other_count += 1,
            }
            app.handle_app_event(event);
            total_drained += 1;
        }

        if !got_any {
            if loop_start.elapsed() > drain_timeout {
                panic!(
                    "Deadlock detected! Only drained {}/{} events after {:?}",
                    total_drained, TOTAL_EVENTS, drain_timeout
                );
            }
            thread::yield_now();
        }
    }

    // Ensure all 16 worker threads terminate cleanly without deadlocks
    for (i, h) in handles.into_iter().enumerate() {
        h.join()
            .unwrap_or_else(|e| panic!("Worker thread {} panicked: {:?}", i, e));
    }

    let elapsed = start_time.elapsed();

    // EMPIRICAL VERIFICATIONS:
    // 1. Zero dropped events: exact count is 50,000
    assert_eq!(
        total_drained, TOTAL_EVENTS,
        "Total drained events must match exactly 50,000"
    );
    assert_eq!(
        log_count + stat_count + thread_status_count + other_count,
        TOTAL_EVENTS
    );

    // 2. Zero deadlocks: completed within timeout
    assert!(
        elapsed < drain_timeout,
        "50,000 events must complete without deadlocks in <30s (took {:?})",
        elapsed
    );

    // 3. Channel is completely empty
    assert!(
        app.event_receiver.try_recv().is_err(),
        "Channel should be empty after draining"
    );

    // 4. Bounded memory consumption in App.logs:
    // Exactly 5 out of 10 events are logs => 25,000 logs sent.
    // MAX_LOG_HISTORY is 5,000. Logs must be bounded!
    assert!(
        app.logs.len() <= MAX_LOG_HISTORY,
        "App.logs.len() ({}) must never exceed MAX_LOG_HISTORY ({})",
        app.logs.len(),
        MAX_LOG_HISTORY
    );
    assert!(
        app.logs.len() >= 4_900,
        "App.logs.len() ({}) should be near capacity",
        app.logs.len()
    );

    // VecDeque capacity must not balloon excessively (bounded memory)
    assert!(
        app.logs.capacity() <= MAX_LOG_HISTORY * 2,
        "App.logs capacity ({}) should remain bounded near MAX_LOG_HISTORY",
        app.logs.capacity()
    );
}

#[test]
fn test_m6_concurrency_stress_live_rendering_during_event_burst() {
    const NUM_THREADS: usize = 16;
    const EVENTS_PER_THREAD: usize = 1_500;
    const TOTAL_EVENTS: usize = NUM_THREADS * EVENTS_PER_THREAD; // 24,000 events

    let (tx, rx) = channel();
    let mut app = App::with_channel(tx.clone(), rx);

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();

    let barrier = Arc::new(Barrier::new(NUM_THREADS + 1));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for t_id in 0..NUM_THREADS {
        let thread_tx = tx.clone();
        let thread_barrier = barrier.clone();

        handles.push(thread::spawn(move || {
            thread_barrier.wait();
            for seq in 0..EVENTS_PER_THREAD {
                let ev = make_heterogeneous_event(t_id, seq);
                let _ = thread_tx.send(ev);
            }
        }));
    }

    barrier.wait();

    let mut total_drained = 0;
    let mut frame_renders = 0;
    let timeout = Duration::from_secs(30);
    let start = Instant::now();

    while total_drained < TOTAL_EVENTS {
        // Drain tick
        let mut count = 0;
        while let Ok(event) = app.event_receiver.try_recv() {
            app.handle_app_event(event);
            total_drained += 1;
            count += 1;
            if count >= 200 {
                break;
            }
        }

        // Render frame concurrently
        terminal
            .draw(|f| ui::draw(f, &mut app))
            .expect("Drawing during live burst must not panic");
        frame_renders += 1;

        if start.elapsed() > timeout {
            panic!("Timeout during concurrent render stress");
        }
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(total_drained, TOTAL_EVENTS);
    assert!(frame_renders > 10, "Multiple frames rendered concurrently");
    assert!(app.logs.len() <= MAX_LOG_HISTORY);
}

// =========================================================================
// SUITE 2: TERMINAL LIFECYCLE & SIGNAL STRESS
// =========================================================================

// Zmierzone empirycznie na tym środowisku: ~2s na każdy cykl
// `TerminalGuard::init()`/`restore()` w prawdziwym PTY (prawdopodobnie
// zapytanie DSR o pozycję kursora, na które w sztucznym PTY bez
// prawdziwego emulatora terminala nikt nie odpowiada, aż do timeoutu) - przy
// 100 cyklach to ~200s. Ten jeden test odpowiadał za połowę czasu całego
// `cargo test --workspace` w tym repo. Reszta testów w tym pliku jest szybka
// (<10s każdy) i zostaje uruchamiana domyślnie.
#[test]
#[ignore = "Test PTY - 100 cykli init/restore w prawdziwym pseudoterminalu, ~200s. Uruchom z --ignored."]
fn test_m6_terminal_lifecycle_100_rapid_toggles_pty() {
    let _guard = PTY_TEST_LOCK.lock().unwrap();
    let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY");

    assert!(!is_terminal_active());
    assert!(!pty.is_raw_mode_active());

    // 100 Rapid sequential init() -> restore() toggles
    for cycle in 1..=100 {
        let mut term_guard = TerminalGuard::init()
            .unwrap_or_else(|e| panic!("Cycle {}: TerminalGuard::init failed: {}", cycle, e));

        assert!(
            term_guard.is_active(),
            "Cycle {}: Guard should be active",
            cycle
        );
        assert!(
            is_terminal_active(),
            "Cycle {}: Global active flag must be true",
            cycle
        );
        assert!(
            pty.is_raw_mode_active(),
            "Cycle {}: Raw mode must be active in PTY",
            cycle
        );

        let init_output = pty.drain_master();
        let init_str = String::from_utf8_lossy(&init_output);
        assert!(
            init_str.contains("?1049h"),
            "Cycle {}: Must emit EnterAlternateScreen sequence",
            cycle
        );
        assert!(
            init_str.contains("?25l"),
            "Cycle {}: Must emit Hide cursor sequence",
            cycle
        );

        term_guard
            .restore()
            .unwrap_or_else(|e| panic!("Cycle {}: restore failed: {}", cycle, e));

        assert!(
            !term_guard.is_active(),
            "Cycle {}: Guard should be inactive",
            cycle
        );
        assert!(
            !is_terminal_active(),
            "Cycle {}: Global active flag must be false",
            cycle
        );
        assert!(
            !pty.is_raw_mode_active(),
            "Cycle {}: Terminal must return to cooked mode",
            cycle
        );

        let restore_output = pty.drain_master();
        let restore_str = String::from_utf8_lossy(&restore_output);
        assert!(
            restore_str.contains("?1049l"),
            "Cycle {}: Must emit LeaveAlternateScreen sequence",
            cycle
        );
        assert!(
            restore_str.contains("?25h"),
            "Cycle {}: Must emit Show cursor sequence",
            cycle
        );
    }

    assert!(!is_terminal_active());
    assert!(!pty.is_raw_mode_active());
}

// Ten sam koszt ~2s/cykl co `test_m6_terminal_lifecycle_100_rapid_toggles_pty`
// wyżej, tu przez 100 cykli RAII drop zamiast jawnego `restore()`.
#[test]
#[ignore = "Test PTY - 100 cykli RAII drop w prawdziwym pseudoterminalu, ~200s. Uruchom z --ignored."]
fn test_m6_terminal_lifecycle_100_raii_drops_pty() {
    let _guard = PTY_TEST_LOCK.lock().unwrap();
    let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY");

    // 100 Rapid RAII drop cycles
    for cycle in 1..=100 {
        {
            let guard = TerminalGuard::init()
                .unwrap_or_else(|e| panic!("Cycle {}: init failed: {}", cycle, e));
            assert!(guard.is_active());
            assert!(is_terminal_active());
            assert!(pty.is_raw_mode_active());
            let _ = pty.drain_master();
            // Drop guard implicitly
        }

        assert!(
            !is_terminal_active(),
            "Cycle {}: Global active flag must be false after drop",
            cycle
        );
        assert!(
            !pty.is_raw_mode_active(),
            "Cycle {}: Terminal must return to cooked mode after drop",
            cycle
        );

        let drop_output = pty.drain_master();
        let drop_str = String::from_utf8_lossy(&drop_output);
        assert!(
            drop_str.contains("?1049l"),
            "Cycle {}: Drop must emit LeaveAlternateScreen",
            cycle
        );
        assert!(
            drop_str.contains("?25h"),
            "Cycle {}: Drop must emit Show cursor",
            cycle
        );
    }
}

#[test]
fn test_m6_terminal_panic_recovery_pty() {
    // Child process branch: executes inside PTY and panics
    if std::env::var("MP4_DOCTOR_M6_PANIC_WORKER").is_ok() {
        install_panic_hook();
        let guard = TerminalGuard::init().expect("Child failed TerminalGuard::init");
        assert!(guard.is_active());
        assert!(is_terminal_active());
        panic!("M6_ADVERSARIAL_PANIC_KILL_TRIGGER");
    }

    let _guard = PTY_TEST_LOCK.lock().unwrap();
    let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY");

    let exe_path = std::env::current_exe().expect("Failed to get current_exe");
    let stdin_fd = unsafe { dup(pty.slave_fd) };
    let stdout_fd = unsafe { dup(pty.slave_fd) };
    let stderr_fd = unsafe { dup(pty.slave_fd) };

    let mut cmd = std::process::Command::new(exe_path);
    cmd.arg("test_m6_terminal_panic_recovery_pty")
        .arg("--nocapture")
        .env("MP4_DOCTOR_M6_PANIC_WORKER", "1")
        .stdin(unsafe { std::process::Stdio::from_raw_fd(stdin_fd) })
        .stdout(unsafe { std::process::Stdio::from_raw_fd(stdout_fd) })
        .stderr(unsafe { std::process::Stdio::from_raw_fd(stderr_fd) });

    let status = cmd.status().expect("Failed to wait on panic child");
    assert!(!status.success(), "Child should exit with error due to panic");

    let child_output = pty.drain_master();
    let child_str = String::from_utf8_lossy(&child_output);

    // Verify panic message and terminal restoration
    assert!(
        child_str.contains("M6_ADVERSARIAL_PANIC_KILL_TRIGGER"),
        "Panic message must be present"
    );
    assert!(
        child_str.contains("?1049l"),
        "Panic hook must emit LeaveAlternateScreen before exiting"
    );
    assert!(
        child_str.contains("?25h"),
        "Panic hook must emit Show cursor before exiting"
    );
}

#[test]
fn test_m6_terminal_signal_recovery_pty() {
    // Child process branch: installs signal handler, enters TUI mode, waits for signal
    if std::env::var("MP4_DOCTOR_M6_SIGNAL_WORKER").is_ok() {
        // Install signal handler calling force_restore
        ctrlc::set_handler(move || {
            force_restore();
            std::process::exit(0);
        })
        .expect("Failed to install ctrlc handler");

        let guard = TerminalGuard::init().expect("Child failed TerminalGuard::init");
        assert!(guard.is_active());
        assert!(is_terminal_active());

        // Notify parent that terminal guard is initialized
        let mut stdout = io::stdout();
        let _ = stdout.write_all(b"READY\r\n");
        let _ = stdout.flush();

        // Wait for SIGINT from parent
        thread::sleep(Duration::from_secs(10));
        std::process::exit(1);
    }

    let _guard = PTY_TEST_LOCK.lock().unwrap();
    let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY");

    let exe_path = std::env::current_exe().expect("Failed to get current_exe");
    let stdin_fd = unsafe { dup(pty.slave_fd) };
    let stdout_fd = unsafe { dup(pty.slave_fd) };
    let stderr_fd = unsafe { dup(pty.slave_fd) };

    let mut child = std::process::Command::new(exe_path)
        .arg("test_m6_terminal_signal_recovery_pty")
        .arg("--nocapture")
        .env("MP4_DOCTOR_M6_SIGNAL_WORKER", "1")
        .stdin(unsafe { std::process::Stdio::from_raw_fd(stdin_fd) })
        .stdout(unsafe { std::process::Stdio::from_raw_fd(stdout_fd) })
        .stderr(unsafe { std::process::Stdio::from_raw_fd(stderr_fd) })
        .spawn()
        .expect("Failed to spawn signal child");

    let child_pid = child.id() as i32;

    // Wait until child outputs "READY"
    let start = Instant::now();
    let mut ready = false;
    while start.elapsed() < Duration::from_secs(5) {
        let output = pty.drain_master();
        let s = String::from_utf8_lossy(&output);
        if s.contains("READY") {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "Child process failed to become READY");

    // Send SIGINT (signal 2) to child
    unsafe {
        kill(child_pid, 2);
    }

    let status = child.wait().expect("Failed to wait on signal child");
    assert!(
        status.success(),
        "Signal handler should exit cleanly with code 0"
    );

    let final_output = pty.drain_master();
    let final_str = String::from_utf8_lossy(&final_output);

    // Verify force_restore emitted LeaveAlternateScreen and Show cursor
    assert!(
        final_str.contains("?1049l"),
        "force_restore must emit LeaveAlternateScreen on SIGINT"
    );
    assert!(
        final_str.contains("?25h"),
        "force_restore must emit Show cursor on SIGINT"
    );
}

#[test]
fn test_m6_terminal_force_restore_direct_stress() {
    let _guard = PTY_TEST_LOCK.lock().unwrap();
    let pty = PtyTestEnvironment::new().expect("Failed to initialize PTY");

    // Initialize guard
    let guard = TerminalGuard::init().expect("Failed to init guard");
    assert!(is_terminal_active());
    assert!(pty.is_raw_mode_active());

    // Call force_restore directly
    force_restore();

    assert!(
        !is_terminal_active(),
        "force_restore must clear TERMINAL_ACTIVE"
    );
    assert!(
        !pty.is_raw_mode_active(),
        "force_restore must restore cooked mode"
    );

    let output = pty.drain_master();
    let s = String::from_utf8_lossy(&output);
    assert!(s.contains("?1049l"));
    assert!(s.contains("?25h"));

    // Multiple subsequent calls must be safe and idempotent
    for _ in 0..50 {
        force_restore();
        assert!(!is_terminal_active());
        assert!(!pty.is_raw_mode_active());
    }

    drop(guard);
    assert!(!is_terminal_active());
    assert!(!pty.is_raw_mode_active());
}

// =========================================================================
// SUITE 3: INTERACTIVE NAVIGATION FUZZING
// =========================================================================

/// Simple, deterministic Xorshift64 pseudo-random number generator.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0xdeadbeef } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn gen_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        min + (self.next_u64() as usize % (max - min))
    }

    fn random_key_event(&mut self) -> KeyEvent {
        let codes = [
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::PageUp,
            KeyCode::PageDown,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Tab,
            KeyCode::BackTab,
            KeyCode::Backspace,
            KeyCode::Delete,
            KeyCode::Insert,
            KeyCode::F(1),
            KeyCode::F(5),
            KeyCode::F(12),
            KeyCode::Char('k'),
            KeyCode::Char('j'),
            KeyCode::Char('g'),
            KeyCode::Char('G'),
            KeyCode::Char('s'),
            KeyCode::Char('q'),
            KeyCode::Char(' '),
            KeyCode::Char('a'),
            KeyCode::Char('z'),
            KeyCode::Char('1'),
            KeyCode::Char('9'),
            KeyCode::Char('ą'),
            KeyCode::Char('ę'),
            KeyCode::Char('ó'),
            KeyCode::Char('ł'),
            KeyCode::Char('ś'),
            KeyCode::Char('ż'),
            KeyCode::Char('ź'),
            KeyCode::Char('ć'),
            KeyCode::Char('ń'),
            KeyCode::Char('\0'),
        ];

        let modifiers = [
            KeyModifiers::NONE,
            KeyModifiers::SHIFT,
            KeyModifiers::ALT,
            KeyModifiers::CONTROL,
            KeyModifiers::SUPER,
        ];

        let code = codes[self.gen_range(0, codes.len())];
        let modifier = modifiers[self.gen_range(0, modifiers.len())];

        KeyEvent {
            code,
            modifiers: modifier,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }
}

#[test]
fn test_m6_interactive_navigation_fuzzing_active_operation() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    // Enter active operation mode
    app.current_view = View::OperationRunning;
    app.is_running = true;
    app.current_operation = Some("Adversarial Hardening Run".to_string());
    app.operation_status_text = Some("Trwa zaawansowane testowanie TUI...".to_string());

    // Pre-populate with initial logs and telemetry
    for i in 0..250 {
        app.push_log(LogMessage::info(
            "INIT",
            format!("Inicjalizacja bufora logów {}", i),
        ));
    }
    app.stats = StatUpdate::new(250, 200, 50, 48, 1024 * 1024 * 100, 16);
    app.sanitizer_metrics = SanitizerMetrics::new(1800, 60.0, "2.5x".to_string(), 1);

    let mut rng = Rng::new(42);

    let viewports = [
        (10, 5),   // Degenerate small
        (59, 14),  // Boundary sub-threshold
        (60, 15),  // Minimal threshold
        (80, 24),  // Standard VT100
        (100, 30), // Mid-size
        (120, 40), // Wide
        (200, 60), // Ultrawide
        (300, 100),// Mega
        (40, 12),  // Small custom
        (1, 1),    // Degenerate 1x1
    ];

    let mut current_vp_idx = 3; // Start at 80x24
    let (mut cur_w, mut cur_h) = viewports[current_vp_idx];
    let mut backend = TestBackend::new(cur_w, cur_h);
    let mut terminal = Terminal::new(backend).unwrap();

    const FUZZ_EVENTS: usize = 2_000;

    for i in 0..FUZZ_EVENTS {
        let key = rng.random_key_event();

        // Dispatch key to application
        app.handle_key(key);

        // If Ctrl+C was triggered, reset shutdown flag and should_quit so fuzzing continues
        if app.should_quit {
            app.should_quit = false;
            SHUTDOWN_FLAG.store(false, Ordering::SeqCst);
        }

        // Periodically inject new background logs to test live reflow under key spam
        if i % 10 == 0 {
            app.push_log(LogMessage::info("BURST", format!("Live log burst {}", i)));
        }

        // Periodically trigger viewport resize
        if i % 40 == 0 {
            current_vp_idx = (current_vp_idx + 1) % viewports.len();
            let (w, h) = viewports[current_vp_idx];
            cur_w = w;
            cur_h = h;
            backend = TestBackend::new(cur_w, cur_h);
            terminal = Terminal::new(backend).unwrap();
        }

        // Draw frame and verify zero crash / no panic
        terminal
            .draw(|f| ui::draw(f, &mut app))
            .unwrap_or_else(|e| {
                panic!(
                    "Fuzz step {} failed to render at {}x{}: {}",
                    i, cur_w, cur_h, e
                )
            });

        // ASSERT INVARIANTS:
        // 1. While is_running, app must remain in View::OperationRunning (Esc/Enter must NOT close active operation)
        assert_eq!(
            app.current_view,
            View::OperationRunning,
            "Fuzz step {}: Key {:?} illegally exited OperationRunning while is_running == true",
            i, key
        );

        // 2. Memory bound on logs
        assert!(
            app.logs.len() <= MAX_LOG_HISTORY,
            "Fuzz step {}: Logs exceeded limit",
            i
        );

        // 3. Scroll position validity
        if app.logs.is_empty() {
            assert_eq!(app.log_scroll, 0);
        } else {
            assert!(
                app.log_scroll < app.logs.len(),
                "Fuzz step {}: log_scroll {} exceeds logs.len() {}",
                i,
                app.log_scroll,
                app.logs.len()
            );
        }
    }
}

#[test]
fn test_m6_interactive_navigation_post_operation_completion() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    app.push_view(View::WorkspaceDashboard);
    app.push_view(View::OperationRunning);
    app.is_running = true;

    // Finish the operation
    app.handle_app_event(AppEvent::OperationFinished("Operacja ukończona pomyślnie".into()));
    assert!(!app.is_running);

    // In finished state: Esc or Enter MUST pop the view back to WorkspaceDashboard
    app.handle_key(KeyEvent {
        code: KeyCode::Esc,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    });

    assert_eq!(
        app.current_view,
        View::WorkspaceDashboard,
        "Esc should return to previous view after operation completion"
    );
}

#[test]
fn test_m6_interactive_navigation_all_views_fuzzing() {
    let all_views = [
        View::MainMenu,
        View::WorkspaceSelect,
        View::WorkspaceDashboard,
        View::ScannerSubMenu,
        View::SettingsMenu,
        View::PreviewFileSelect,
    ];

    let mut rng = Rng::new(999);

    for view in all_views {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = view;

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        // 200 random keys per view
        for _ in 0..200 {
            let key = rng.random_key_event();
            app.handle_key(key);
            if app.should_quit {
                app.should_quit = false;
                SHUTDOWN_FLAG.store(false, Ordering::SeqCst);
            }

            terminal
                .draw(|f| ui::draw(f, &mut app))
                .expect("Rendering view must never panic under key fuzzing");
        }
    }
}
