//! MP4 Doctor 2.0 - Milestone 4 Responsive Layout & UI Integration Tests
//!
//! Verifies Requirement R2, Features F9 & F10:
//! - Terminal fallback threshold at 60x15 with diagnostic dimension display
//! - Responsive header density across compact (<80), standard (80..120), and wide (>=120) viewports
//! - Enhanced live statistics panel with repair rate gauge, formatted byte counts, active threads, and FFmpeg metrics
//! - Word-wrapped scrollable logs with tail-tracking under line wrapping and zero dead zone on manual scroll
//! - Keybindings (Home, End) and eviction reading-position preservation

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};
use mp4_doctor::{
    event::{channel, LogMessage, SanitizerMetrics, StatUpdate},
    tui::{
        app::{App, Modal, View},
        ui::{self, format_bytes, format_log_line},
    },
};

fn make_key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::empty())
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

#[test]
fn test_terminal_fallback_triggers_under_60x15() {
    let test_cases = [
        (59, 20, "59x20"),
        (80, 14, "80x14"),
        (50, 12, "50x12"),
        (30, 10, "30x10"),
    ];

    for (width, height, dim_str) in test_cases {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        assert!(
            buffer_contains(&terminal, width, height, "Terminal zbyt mały!"),
            "Fallback warning not triggered at {}x{}", width, height
        );
        assert!(
            buffer_contains(&terminal, width, height, "Wymagane minimum: 60x15"),
            "Minimum requirement missing in warning at {}x{}", width, height
        );
        assert!(
            buffer_contains(&terminal, width, height, dim_str),
            "Current dimensions '{}' missing in warning at {}x{}", dim_str, width, height
        );
        // Ensure MainMenu is NOT rendered when fallback is active
        assert!(
            !buffer_contains(&terminal, width, height, "MENU GŁÓWNE"),
            "Main menu rendered under fallback at {}x{}", width, height
        );
    }
}

#[test]
fn test_terminal_passes_at_exact_60x15_threshold() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    let backend = TestBackend::new(60, 15);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    assert!(
        !buffer_contains(&terminal, 60, 15, "Terminal zbyt mały!"),
        "Fallback should NOT trigger at exact threshold 60x15"
    );
    assert!(
        buffer_contains(&terminal, 60, 15, "MP4 DOC"),
        "Compact header missing at 60x15"
    );
    assert!(
        buffer_contains(&terminal, 60, 15, "MENU GŁÓWNE"),
        "Main menu missing at 60x15"
    );
}

#[test]
fn test_responsive_header_densities() {
    // 1. Compact profile (< 80 columns)
    {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(60, 15);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(buffer_contains(&terminal, 60, 15, "MP4 DOC"));
        assert!(buffer_contains(&terminal, 60, 15, "Brak proj."));
    }

    // 2. Standard profile (80..120 columns)
    {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(buffer_contains(&terminal, 80, 24, "MP4 DOCTOR 2.0"));
        assert!(buffer_contains(&terminal, 80, 24, "Brak wybranego projektu"));
    }

    // 3. Wide profile (>= 120 columns)
    {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
        assert!(buffer_contains(&terminal, 120, 40, "MP4 DOCTOR 2.0"));
        assert!(buffer_contains(&terminal, 120, 40, "CPU:"));
    }
}

#[test]
fn test_live_statistics_panel_rendering() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;
    app.current_operation = Some("Skanowanie folderu".to_string());

    app.stats = StatUpdate {
        files_scanned: 150,
        files_healthy: 120,
        files_broken: 30,
        files_repaired: 27,
        bytes_processed: 5242880, // 5.00 MB
        active_threads: 8,
    };

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    assert!(buffer_contains(&terminal, 80, 24, "150"), "Scanned files count missing");
    assert!(buffer_contains(&terminal, 80, 24, "120"), "Healthy files count missing");
    assert!(buffer_contains(&terminal, 80, 24, "30"), "Broken files count missing");
    assert!(buffer_contains(&terminal, 80, 24, "27"), "Repaired files count missing");
    assert!(buffer_contains(&terminal, 80, 24, "90.0%"), "Repair rate 90.0% missing");
    assert!(buffer_contains(&terminal, 80, 24, "5.00 MB"), "Formatted bytes 5.00 MB missing");
    assert!(buffer_contains(&terminal, 80, 24, "8"), "Active threads count missing");
    assert!(buffer_contains(&terminal, 80, 24, "Postęp napraw: 90.0%"), "Visual progress gauge label missing");
}

#[test]
fn test_sanitizer_telemetry_rendering() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;
    app.current_operation = Some("Sanityzacja FFmpeg".to_string());

    app.sanitizer_metrics = SanitizerMetrics::new(1250, 59.9, "2.0x", 2);

    // Standard 80x24 view
    {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        assert!(buffer_contains(&terminal, 80, 24, "59.9 FPS"), "Sanitizer FPS missing");
        assert!(buffer_contains(&terminal, 80, 24, "2.0x"), "Sanitizer speed missing");
        assert!(buffer_contains(&terminal, 80, 24, "Pasaż: 2"), "Sanitizer pass missing");
    }

    // Compact 60x15 view
    {
        let backend = TestBackend::new(60, 15);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        assert!(buffer_contains(&terminal, 60, 15, "59.9 FPS"), "Sanitizer FPS missing on compact view");
        assert!(buffer_contains(&terminal, 60, 15, "2.0x"), "Sanitizer speed missing on compact view");
        assert!(buffer_contains(&terminal, 60, 15, "Pasaż: 2"), "Sanitizer pass missing on compact view");
    }
}

#[test]
fn test_word_wrapped_logs_tail_tracking_no_cutoff() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    // Push 30 messages, each wrapping across 3 rows on an 80-column screen
    for i in 0..30 {
        let msg = format!(
            "Event {:02}: Comprehensive diagnostic payload detailing heuristic inspection of fragmented MP4 atoms and cluster offsets within sector {}",
            i, 1000 + i
        );
        app.push_log(LogMessage::info("SCANNER", msg));
    }
    app.auto_scroll = true;

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    // The newest message (Event 29) MUST be drawn in the viewport
    assert!(
        buffer_contains(&terminal, 80, 24, "Event 29"),
        "Latest log message (Event 29) was clipped off screen in auto_scroll mode!"
    );
}

#[test]
fn test_word_wrapped_300_char_unbroken_string() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    // 300 continuous hexadecimal characters without spaces
    let unbroken = "a1b2c3d4e5f60718293a4b5c6d7e8f90".repeat(10); // 320 chars
    assert!(unbroken.len() >= 300);

    app.push_log(LogMessage::warn("HEXDUMP", &unbroken));
    app.auto_scroll = true;

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    // Verify it rendered without panics and prefix is drawn
    assert!(buffer_contains(&terminal, 80, 24, "[HEXDUMP]"));
    assert!(buffer_contains(&terminal, 80, 24, "a1b2c3d4"));
}

#[test]
fn test_long_line_word_wrapping() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    // 500+ character continuous unbroken string without whitespace
    let long_continuous = "X".repeat(550);
    app.push_log(LogMessage::info("LONG", &long_continuous));

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    assert!(buffer_contains(&terminal, 80, 24, "[LONG]"));
    assert!(buffer_contains(&terminal, 80, 24, "XXXXX"));
}

#[test]
fn test_manual_scroll_up_responsiveness_no_dead_zone() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    for i in 0..100 {
        app.push_log(LogMessage::info("TEST", format!("LogEntry_{:03}", i)));
    }
    app.auto_scroll = true;
    app.log_scroll = 99;

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    // Initially at bottom, LogEntry_099 is visible
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
    assert!(buffer_contains(&terminal, 80, 24, "LogEntry_099"));

    // Press Up once
    app.handle_key(make_key(KeyCode::Up));
    assert_eq!(app.log_scroll, 98);
    assert!(!app.auto_scroll);

    // Draw again: LogEntry_099 MUST NO LONGER BE VISIBLE! LogEntry_098 must be at the bottom!
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
    assert!(
        !buffer_contains(&terminal, 80, 24, "LogEntry_099"),
        "LogEntry_099 is still visible after pressing Up! Dead zone detected."
    );
    assert!(
        buffer_contains(&terminal, 80, 24, "LogEntry_098"),
        "LogEntry_098 should be visible at bottom after scrolling up!"
    );
}

#[test]
fn test_home_and_end_navigation() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    for i in 0..100 {
        app.push_log(LogMessage::info("TEST", format!("LogItem_{:03}", i)));
    }

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    // Press Home -> jump to beginning
    app.handle_key(make_key(KeyCode::Home));
    assert_eq!(app.log_scroll, 0);
    assert!(!app.auto_scroll);

    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
    assert!(buffer_contains(&terminal, 80, 24, "LogItem_000"));
    assert!(!buffer_contains(&terminal, 80, 24, "LogItem_099"));

    // Press End -> jump back to bottom
    app.handle_key(make_key(KeyCode::End));
    assert_eq!(app.log_scroll, 99);
    assert!(app.auto_scroll);

    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
    assert!(buffer_contains(&terminal, 80, 24, "LogItem_099"));
}

#[test]
fn test_buffer_eviction_scroll_adjustment() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    // Fill buffer up to MAX_LOG_HISTORY (5000)
    for i in 0..5_000 {
        app.push_log(LogMessage::info("SYS", format!("Init log {}", i)));
    }
    assert_eq!(app.logs.len(), 5_000);

    // Freeze reading position at log 250
    app.auto_scroll = false;
    app.log_scroll = 250;

    // Push 1 new log -> triggers drain(0..100)
    app.push_log(LogMessage::info("SYS", "Overflow log 5001"));

    // Reading position should adjust down by 100 to stay anchored at the same content
    assert_eq!(app.log_scroll, 150);
}

#[test]
fn test_byte_formatting_utility() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1024), "1.0 KB");
    assert_eq!(format_bytes(1536), "1.5 KB");
    assert_eq!(format_bytes(1048576), "1.00 MB");
    assert_eq!(format_bytes(5242880), "5.00 MB");
    assert_eq!(format_bytes(1073741824), "1.00 GB");
    assert_eq!(format_bytes(1099511627776), "1.00 TB");
}

#[test]
fn test_log_level_formatting_and_alignment() {
    let msg_debug = LogMessage::debug("CORE", "debug text");
    let msg_info = LogMessage::info("SCANNER", "info text");
    let msg_succ = LogMessage::success("REPAIR", "success text");
    let msg_warn = LogMessage::warn("POLIGON", "warn text");
    let msg_err = LogMessage::error("AUTOPILOT", "error text");

    let line_debug = format_log_line(&msg_debug);
    let line_info = format_log_line(&msg_info);
    let line_succ = format_log_line(&msg_succ);
    let line_warn = format_log_line(&msg_warn);
    let line_err = format_log_line(&msg_err);

    // Each badge span is the second span (index 1) and must be exactly 7 characters
    assert_eq!(line_debug.spans[1].content, "[DEBUG]");
    assert_eq!(line_info.spans[1].content, "[INFO ]");
    assert_eq!(line_succ.spans[1].content, "[SUCC ]");
    assert_eq!(line_warn.spans[1].content, "[WARN ]");
    assert_eq!(line_err.spans[1].content, "[ERROR]");

    for line in &[&line_debug, &line_info, &line_succ, &line_warn, &line_err] {
        assert_eq!(line.spans[1].content.len(), 7);
        // Span 0 is timestamp (HH:MM:SS + space = 9 chars)
        assert_eq!(line.spans[0].content.len(), 9);
    }
}

#[test]
fn test_modal_centering_minimum_dimensions_at_60x15() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.active_modal = Modal::NewWorkspace {
        input: "MojProjekt".to_string(),
        cursor: 10,
        error_msg: None,
    };

    let backend = TestBackend::new(60, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    assert!(buffer_contains(&terminal, 60, 15, "Podaj nazwę nowego projektu:"));
    assert!(buffer_contains(&terminal, 60, 15, "MojProjekt"));
    assert!(buffer_contains(&terminal, 60, 15, "[Enter] Utwórz"));
}
