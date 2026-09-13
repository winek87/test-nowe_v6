//! MP4 Doctor 2.0 - Milestone 4 Adversarial Empirical Tests
//!
//! Adversarial stress testing of:
//! 1. Word wrapping under extreme inputs (500+, 1000+, 5000+ unbroken chars, empty logs, UTF-8, emojis).
//! 2. Memory bounded log eviction (6,000 log entries vs MAX_LOG_HISTORY = 5,000) and scroll anchor stability.
//! 3. Keyboard navigation fuzzing (Up, Down, PgUp, PgDn, Home, End) under empty, single, and 5,000-log states.
//! 4. TestBackend rendering validation with zero panics and zero index out-of-bounds errors across varied resolutions.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};

use mp4_doctor::{
    event::{channel, LogMessage, SanitizerMetrics, StatUpdate},
    tui::{
        app::{App, View, MAX_LOG_HISTORY},
        ui::{self, estimate_log_rows, str_width},
    },
};

fn make_key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn buffer_to_strings(terminal: &Terminal<TestBackend>, width: u16, height: u16) -> Vec<String> {
    let buffer = terminal.backend().buffer();
    let mut lines = Vec::new();
    for y in 0..height {
        let line: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
        lines.push(line);
    }
    lines
}

fn buffer_contains(terminal: &Terminal<TestBackend>, width: u16, height: u16, target: &str) -> bool {
    let lines = buffer_to_strings(terminal, width, height);
    lines.iter().any(|line| line.contains(target))
}

// =========================================================================
// 1. Extreme Edge Cases: Long Unbroken Strings, Empty Logs, UTF-8 & Emojis
// =========================================================================

#[test]
fn test_adversarial_unbroken_strings_500_1000_5000_chars() {
    let lengths = [500, 1_000, 5_000];

    for &len in &lengths {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;
        app.is_running = true;

        // Create continuous hexadecimal string without any whitespace
        let chunk = "deadbeefcafebabe0123456789abcdef";
        let unbroken: String = chunk.chars().cycle().take(len).collect();
        assert_eq!(unbroken.len(), len);

        let msg = LogMessage::warn("STRESS_HEX", &unbroken);
        let estimated_rows_80 = estimate_log_rows(&msg, 78);
        assert!(
            estimated_rows_80 >= len / 78,
            "Row estimation {} should account for at least {} rows for len {}",
            estimated_rows_80,
            len / 78,
            len
        );

        app.push_log(msg);

        // Test drawing on 60x15, 80x24, and 120x40
        for (w, h) in [(60, 15), (80, 24), (120, 40)] {
            let backend = TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();

            // Must NOT panic, hang, or index out of bounds
            terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

            assert!(
                buffer_contains(&terminal, w, h, "[STRESS_HEX]"),
                "Module badge missing on {}x{}",
                w,
                h
            );
            assert!(
                buffer_contains(&terminal, w, h, "deadbeef"),
                "Payload prefix missing on {}x{}",
                w,
                h
            );
        }
    }
}

#[test]
fn test_adversarial_empty_whitespace_and_control_logs() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    let test_messages = [
        "",                             // completely empty
        "   ",                          // whitespace only
        "\t\t\t",                       // tabs only
        " \t \t ",                      // mixed spaces and tabs
        "\n\r\n",                       // newlines
        "\x00\x01\x02\x03\x04",         // non-printable control chars
        "Line with \x00 null byte",     // embedded null
        "   leading whitespace",
        "trailing whitespace   ",
    ];

    for (i, &raw_msg) in test_messages.iter().enumerate() {
        let msg = LogMessage::info(format!("M_{}", i), raw_msg);
        let rows = estimate_log_rows(&msg, 78);
        assert!(rows >= 1, "Estimated rows should be at least 1 for msg index {}", i);
        app.push_log(msg);
    }

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    assert!(buffer_contains(&terminal, 80, 24, "DZIENNIK OPERACJI"));
    assert!(buffer_contains(&terminal, 80, 24, "leading whitespace"));
    assert!(buffer_contains(&terminal, 80, 24, "trailing whitespace"));
}

#[test]
fn test_adversarial_multibyte_polish_and_cjk_unicode() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    // Polish pangram with all diacritics
    let polish_pangram = "Doświadczalna zażółć gęślą jaźń — ZAŻÓŁĆ GĘŚLĄ JAŹŃ 1234567890";
    app.push_log(LogMessage::info("POLISH", polish_pangram));

    // Long unbroken Polish string without spaces (600 chars)
    let unbroken_polish: String = "ZażółćGęśląJaźń".chars().cycle().take(600).collect();
    app.push_log(LogMessage::warn("PL_LONG", &unbroken_polish));

    // CJK and international characters
    let cjk_message = "Naprawa kontenera MP4: 東京 映画 ビデオ 修复视频 文件 100% OK";
    app.push_log(LogMessage::success("CJK", cjk_message));

    // On 80x40 viewport, all messages fit simultaneously
    let backend_tall = TestBackend::new(80, 40);
    let mut terminal_tall = Terminal::new(backend_tall).unwrap();
    terminal_tall.draw(|f| ui::draw(f, &mut app)).unwrap();

    assert!(buffer_contains(&terminal_tall, 80, 40, "[POLISH]"));
    assert!(buffer_contains(&terminal_tall, 80, 40, "zażółć gęślą jaźń"));
    assert!(buffer_contains(&terminal_tall, 80, 40, "[PL_LONG]"));
    assert!(buffer_contains(&terminal_tall, 80, 40, "[CJK]"));

    // On standard 80x24 viewport, auto-scroll pins newest logs (CJK and tail of PL_LONG)
    let backend_std = TestBackend::new(80, 24);
    let mut terminal_std = Terminal::new(backend_std).unwrap();
    terminal_std.draw(|f| ui::draw(f, &mut app)).unwrap();
    assert!(buffer_contains(&terminal_std, 80, 24, "[CJK]"));

    // Press Home to jump to the top -> POLISH must now be visible
    app.handle_key(make_key(KeyCode::Home));
    terminal_std.draw(|f| ui::draw(f, &mut app)).unwrap();
    assert!(buffer_contains(&terminal_std, 80, 24, "[POLISH]"));
}

#[test]
fn test_adversarial_emojis_and_special_symbols() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    let emojis = "🚀 🦀 💥 🔥 ⚡ 🎬 📽️ 🛠️ 🔬 🧪 🛡️ ⚠️ ❌ ✅";
    app.push_log(LogMessage::info("EMOJI_MIX", emojis));

    // Continuous unbroken line of 300 emojis without spaces
    let unbroken_emojis: String = "🦀".repeat(300);
    app.push_log(LogMessage::error("EMOJI_WALL", &unbroken_emojis));

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    assert!(buffer_contains(&terminal, 80, 24, "[EMOJI_MIX]"));
    assert!(buffer_contains(&terminal, 80, 24, "[EMOJI_WALL]"));
}

// =========================================================================
// 2. Log Buffer Eviction Bounds: 6,000 Log Entries vs MAX_LOG_HISTORY (5,000)
// =========================================================================

#[test]
fn test_log_buffer_eviction_exceeding_max_history_6000_entries() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    assert_eq!(MAX_LOG_HISTORY, 5_000);

    // Push 6,000 log entries sequentially
    for i in 0..6_000 {
        let msg = format!("Sequential high-throughput log packet #{:05} with payload data", i);
        app.push_log(LogMessage::info("EVICTION", msg));

        // Invariant: buffer size must NEVER exceed MAX_LOG_HISTORY
        assert!(
            app.logs.len() <= MAX_LOG_HISTORY,
            "Buffer length {} exceeded MAX_LOG_HISTORY {} at iteration {}",
            app.logs.len(),
            MAX_LOG_HISTORY,
            i
        );
    }

    // At 6,000 pushes:
    // Started at 0, hit 5000 -> drained 100 to 4900, pushed 1 -> 4901
    // 1000 additional entries pushed. 1000 % 100 == 0, so 10 drain cycles occurred.
    // Length must be between 4900 and 5000.
    assert!(app.logs.len() >= 4_900 && app.logs.len() <= MAX_LOG_HISTORY);

    // Latest entry #05999 MUST be at the back of the queue
    let last_log = app.logs.back().unwrap();
    assert!(
        last_log.message.contains("#05999"),
        "Back of queue does not contain the newest log! Got: {}",
        last_log.message
    );

    // Oldest entries (e.g. #00000 .. #00999) MUST have been evicted
    let first_log = app.logs.front().unwrap();
    assert!(
        !first_log.message.contains("#00000"),
        "Oldest log #00000 was not evicted after 6,000 pushes!"
    );

    // Render under TestBackend with evicted buffer
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    assert!(
        buffer_contains(&terminal, 80, 24, "#05999"),
        "Latest log after 6,000 pushes missing from viewport!"
    );
}

#[test]
fn test_eviction_scroll_preservation_under_sustained_inflow() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    // Fill to 5,000
    for i in 0..5_000 {
        app.push_log(LogMessage::info("INIT", format!("Initial entry {}", i)));
    }
    assert_eq!(app.logs.len(), 5_000);

    // Freeze reading position in manual mode at index 350
    app.auto_scroll = false;
    app.log_scroll = 350;

    // Push 250 new logs:
    // - Push #0 triggers drain #1 (len 5000 -> 4900 -> 4901): log_scroll: 350 -> 250
    // - Pushes #1..99 bring len to 5000
    // - Push #100 triggers drain #2 (len 5000 -> 4900 -> 4901): log_scroll: 250 -> 150
    // - Pushes #101..199 bring len to 5000
    // - Push #200 triggers drain #3 (len 5000 -> 4900 -> 4901): log_scroll: 150 -> 50
    // - Pushes #201..249 bring len to 4950
    for i in 0..250 {
        app.push_log(LogMessage::warn("OVERFLOW", format!("Overflow entry {}", i)));
    }

    // 3 drain cycles occurred: log_scroll shifted down by 300 to exactly 50
    assert_eq!(app.log_scroll, 50);

    // Push another 100 new logs:
    // - Pushes #250..299 bring len to 5000
    // - Push #300 triggers drain #4: log_scroll: 50.saturating_sub(100) = 0
    // 50.saturating_sub(100) should clamp safely to 0 without underflow panic
    for i in 0..100 {
        app.push_log(LogMessage::error("EXTRA", format!("Extra overflow {}", i)));
    }
    assert_eq!(app.log_scroll, 0);

    // Draw to terminal to verify viewport renders without panics
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    assert!(buffer_contains(&terminal, 80, 24, "DZIENNIK OPERACJI"));
    assert!(buffer_contains(&terminal, 80, 24, "[PRZEGLĄDANIE]"));
}

// =========================================================================
// 3. Rapid Keyboard Navigation Fuzzing in View::OperationRunning
// =========================================================================

#[test]
fn test_rapid_keyboard_navigation_fuzzing_various_buffer_sizes() {
    let buffer_sizes = [0, 1, 5, 20, 200, 5_000];

    let nav_keys = [
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::PageUp,
        KeyCode::PageDown,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::Char('k'),
        KeyCode::Char('j'),
        KeyCode::Char('g'),
        KeyCode::Char('G'),
    ];

    for &size in &buffer_sizes {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;
        app.is_running = true;

        for i in 0..size {
            app.push_log(LogMessage::info("FUZZ", format!("Fuzz log item {:04}", i)));
        }

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        // Perform 500 rapid key transitions
        for step in 0..500 {
            let key = nav_keys[step % nav_keys.len()];
            app.handle_key(make_key(key));

            // Log scroll index must NEVER be greater than logs.len().saturating_sub(1)
            // (unless logs is empty, where it's 0)
            if app.logs.is_empty() {
                assert_eq!(app.log_scroll, 0);
            } else {
                assert!(
                    app.log_scroll < app.logs.len(),
                    "log_scroll {} exceeded logs.len() {} at step {}",
                    app.log_scroll,
                    app.logs.len(),
                    step
                );
            }

            // Periodically draw to test ratatui viewport rendering
            if step % 50 == 0 {
                terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
            }
        }

        // Final draw
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
    }
}

#[test]
fn test_concurrent_log_inflow_during_rapid_keyboard_scrolling() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let nav_keys = [
        KeyCode::Up,
        KeyCode::PageUp,
        KeyCode::Down,
        KeyCode::PageDown,
        KeyCode::Home,
        KeyCode::End,
    ];

    // Interleave 1,000 log pushes with 1,000 key events and frame draws
    for i in 0..1_000 {
        app.push_log(LogMessage::info("BURST", format!("Interleaved msg #{}", i)));

        let key = nav_keys[i % nav_keys.len()];
        app.handle_key(make_key(key));

        if i % 100 == 0 {
            terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
            assert!(
                app.log_scroll < app.logs.len(),
                "log_scroll {} must remain strictly valid < {}",
                app.log_scroll,
                app.logs.len()
            );
        }
    }
}

// =========================================================================
// 4. Viewport Resolution Boundaries and Fallback Checks
// =========================================================================

#[test]
fn test_rendering_across_wide_range_of_valid_terminal_dimensions() {
    let dimensions = [
        (60, 15),  // Minimum supported threshold
        (61, 15),
        (60, 16),
        (79, 23),
        (80, 24),  // Standard terminal
        (100, 30),
        (120, 40), // Wide terminal
        (200, 60), // Ultrawide terminal
        (60, 100), // Tall & narrow
        (250, 15), // Very wide & short
    ];

    for (w, h) in dimensions {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.current_view = View::OperationRunning;
        app.is_running = true;

        app.stats = StatUpdate {
            files_scanned: 1000,
            files_healthy: 800,
            files_broken: 200,
            files_repaired: 190,
            bytes_processed: 10737418240, // 10.00 GB
            active_threads: 16,
        };
        app.sanitizer_metrics = SanitizerMetrics::new(5000, 75.0, "3.5x", 1);

        for i in 0..50 {
            app.push_log(LogMessage::info(
                "LAYOUT",
                format!("Telemetry line {} testing wrapping on dimension {}x{}", i, w, h),
            ));
        }

        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();

        // Verify zero panics on every resolution
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        assert!(
            !buffer_contains(&terminal, w, h, "Terminal zbyt mały!"),
            "Dimension {}x{} wrongly triggered fallback screen!",
            w,
            h
        );
        assert!(
            buffer_contains(&terminal, w, h, "DZIENNIK OPERACJI"),
            "Log panel missing on {}x{}",
            w,
            h
        );
    }
}

#[test]
fn test_str_width_and_row_estimation_invariants() {
    // Basic widths
    assert_eq!(str_width(""), 0);
    assert_eq!(str_width("abc"), 3);
    assert_eq!(str_width("Zażółć"), 6); // Polish diacritics count as 1 column each
    assert_eq!(str_width("東京"), 4);   // CJK characters count as 2 columns each
    assert_eq!(str_width("🦀"), 2);     // Emoji counts as 2 columns

    // Row estimation invariant: when terminal width is very small (< 10), returns 1 without crashing
    let msg = LogMessage::info("MOD", "A very long message that should wrap");
    assert_eq!(estimate_log_rows(&msg, 5), 1);
    assert_eq!(estimate_log_rows(&msg, 9), 1);

    // For normal widths, rows must be >= 1
    assert!(estimate_log_rows(&msg, 60) >= 1);

    // Empty message row estimation
    let empty_msg = LogMessage::info("MOD", "");
    assert_eq!(estimate_log_rows(&empty_msg, 60), 1);
}
