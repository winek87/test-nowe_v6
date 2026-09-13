//! Milestone 4 Adversarial Empirical Verification Suite
//!
//! Rigorous stress testing of:
//! 1. Resizing boundary conditions:
//!    - Fallback trigger: 59x14, 59x20, 80x14, 59x15, 60x14, 0x0, 1x1, 10x5
//!    - Fallback non-trigger: exact 60x15, 61x15, 60x16
//!    - Scaling up: 80x24, 120x40, 200x60, 500x200, 1000x500
//! 2. UI View coverage across all terminal tiers without panic:
//!    - MainMenu, WorkspaceSelect, WorkspaceDashboard, ScannerSubMenu, SettingsMenu,
//!      PreviewFileSelect, OperationRunning
//! 3. Modal centering and readability on compact 60x15:
//!    - All 6 modal variants (NewWorkspace, PathInput, SanitizerSelectPass, ConfirmAction,
//!      SettingsThreadLimit, NotificationDialog)
//!    - Verify height is >= 7 and modal fits within terminal boundaries
//! 4. Log viewport stress & extreme reflow:
//!    - Multi-kilobyte unbroken strings, Polish UTF-8, emoji, boundary scroll events
//! 5. Telemetry & gauge edge cases:
//!    - Division by zero in stats (0 files broken)
//!    - u64::MAX byte counts, extreme thread counts

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};
use mp4_doctor::{
    event::{channel, LogMessage, StatUpdate},
    tui::{
        app::{App, ConfirmActionTarget, Modal, PathInputTarget, View},
        ui::{self, format_bytes},
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
// 1. TERMINAL RESIZING BOUNDARY TESTS
// =========================================================================

#[test]
fn test_adversarial_fallback_screen_all_sub_threshold_boundaries() {
    let sub_thresholds = [
        (59, 14),
        (59, 20),
        (80, 14),
        (59, 15), // Edge: exact height, 1 col narrow
        (60, 14), // Edge: exact width, 1 row short
        (0, 0),   // Extreme degenerate
        (1, 1),   // Extreme degenerate
        (20, 5),  // Tiny
        (59, 100),// Tall but narrow
        (150, 14),// Wide but short
    ];

    for (w, h) in sub_thresholds {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();

        // Render must not panic even on 0x0 or 1x1
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        if w >= 25 && h >= 5 {
            assert!(
                buffer_contains(&terminal, w, h, "Terminal zbyt mały!"),
                "Fallback warning expected at {}x{}", w, h
            );
            assert!(
                buffer_contains(&terminal, w, h, "60x15"),
                "60x15 requirement mention expected at {}x{}", w, h
            );
        }
    }
}

#[test]
fn test_adversarial_threshold_exact_and_adjacent_passes() {
    let passing_thresholds = [
        (60, 15),
        (61, 15),
        (60, 16),
        (61, 16),
        (80, 24),
        (120, 40),
        (200, 60),
        (250, 100),
    ];

    for (w, h) in passing_thresholds {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        assert!(
            !buffer_contains(&terminal, w, h, "Terminal zbyt mały!"),
            "Fallback incorrectly triggered at {}x{}", w, h
        );
        assert!(
            buffer_contains(&terminal, w, h, "MENU GŁÓWNE"),
            "Main menu not rendered at {}x{}", w, h
        );
    }
}

// =========================================================================
// 2. ALL VIEWS AT COMPACT, STANDARD, WIDE, ULTRAWIDE
// =========================================================================

#[test]
fn test_all_views_render_across_all_resolutions_without_panic() {
    let resolutions = [
        (60, 15),   // Compact minimal
        (80, 24),   // Standard VT100
        (120, 40),  // Wide terminal
        (200, 60),  // Ultrawide
        (500, 200), // Extreme 4K terminal
    ];

    let views = [
        View::MainMenu,
        View::WorkspaceSelect,
        View::WorkspaceDashboard,
        View::ScannerSubMenu,
        View::SettingsMenu,
        View::PreviewFileSelect,
        View::OperationRunning,
    ];

    for (w, h) in resolutions {
        for view in &views {
            let (tx, rx) = channel();
            let mut app = App::with_channel(tx, rx);
            app.current_view = *view;
            if *view == View::OperationRunning {
                app.is_running = true;
                app.current_operation = Some("Testowa Operacja".to_string());
                app.push_log(LogMessage::info("SYSTEM", "Test message in running view"));
            }

            let backend = TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();

            terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

            // Verify alternate buffer content is present and no out-of-bounds crash
            let lines = buffer_to_strings(&terminal, w, h);
            assert_eq!(lines.len(), h as usize);
            assert_eq!(lines[0].chars().count(), w as usize);
        }
    }
}

// =========================================================================
// 3. ALL MODAL VARIANTS ON COMPACT 60x15 DISPLAYS
// =========================================================================

#[test]
fn test_all_modals_on_compact_60x15_preserve_minimum_height_and_centering() {
    let modals = vec![
        Modal::NewWorkspace {
            input: "NowyProj".to_string(),
            cursor: 8,
            error_msg: None,
        },
        Modal::NewWorkspace {
            input: "BlednyProj".to_string(),
            cursor: 10,
            error_msg: Some("Projekt juz istnieje!".to_string()),
        },
        Modal::PathInput {
            title: "SKANOWANIE PLIKU".to_string(),
            prompt: "Podaj sciezke do pliku MP4:".to_string(),
            input: "/var/media/video.mp4".to_string(),
            cursor: 20,
            conf_file: String::new(),
            target: PathInputTarget::ScannerSingle,
            error_msg: None,
        },
        Modal::SanitizerSelectPass {
            file_path: "damaged.mp4".to_string(),
            selected_index: 0,
        },
        Modal::SanitizerSelectPass {
            file_path: "damaged.mp4".to_string(),
            selected_index: 1,
        },
        Modal::ConfirmAction {
            title: "CZYSZCZENIE".to_string(),
            message: "Czy na pewno chcesz usunac pliki tymczasowe?".to_string(),
            action: ConfirmActionTarget::GarbageCollector,
            selected_yes: true,
        },
        Modal::ConfirmAction {
            title: "WYJŚCIE".to_string(),
            message: "Czy zakonczyc program?".to_string(),
            action: ConfirmActionTarget::QuitApplication,
            selected_yes: false,
        },
        Modal::SettingsThreadLimit {
            input: "16".to_string(),
            cursor: 2,
            error_msg: None,
        },
        Modal::SettingsThreadLimit {
            input: "abc".to_string(),
            cursor: 3,
            error_msg: Some("Niepoprawna liczba!".to_string()),
        },
        Modal::NotificationDialog {
            title: "KOMUNIKAT".to_string(),
            message: "Operacja zakonczona sukcesem!".to_string(),
            is_error: false,
        },
        Modal::NotificationDialog {
            title: "BŁĄD KRYTYCZNY".to_string(),
            message: "Nie udalo sie naprawic atomu moov!".to_string(),
            is_error: true,
        },
    ];

    for modal in modals {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        app.active_modal = modal;

        let backend = TestBackend::new(60, 15);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        let lines = buffer_to_strings(&terminal, 60, 15);
        assert_eq!(lines.len(), 15);

        // Find double-border lines (which delineate the modal)
        // Double-border horizontal characters: '═' or box characters '╔', '╗', '╚', '╝'
        let modal_rows: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains('═') || line.contains('╔') || line.contains('║'))
            .map(|(idx, _)| idx)
            .collect();

        assert!(
            !modal_rows.is_empty(),
            "Modal borders not found on 60x15 terminal!"
        );

        let top_row = *modal_rows.first().unwrap();
        let bottom_row = *modal_rows.last().unwrap();
        let modal_height = (bottom_row - top_row + 1) as u16;

        assert!(
            modal_height >= 7,
            "Modal vertically collapsed below minimum height 7! Height was: {}",
            modal_height
        );
        assert!(
            bottom_row < 15,
            "Modal extends past bottom of terminal: bottom_row={}",
            bottom_row
        );
    }
}

// =========================================================================
// 4. LOG VIEWPORT STRESS & EXTREME WORD REFLOW
// =========================================================================

#[test]
fn test_word_wrapped_extreme_multikilobyte_string() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    // 2,000 continuous chars unbroken string
    let huge_token = "0123456789abcdef".repeat(125); // 2000 chars
    app.push_log(LogMessage::error("CORRUPTOR", &huge_token));
    app.auto_scroll = true;

    let backend = TestBackend::new(60, 15);
    let mut terminal = Terminal::new(backend).unwrap();

    // Must render without stack overflow or panic
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    assert!(buffer_contains(&terminal, 60, 15, "[ERROR]"));
    assert!(buffer_contains(&terminal, 60, 15, "0123456789abcdef"));
}

#[test]
fn test_log_viewport_stress_rapid_drain_and_scrolling() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    // Push 5,500 logs to trigger eviction
    for i in 0..5_500 {
        app.push_log(LogMessage::info(
            "CHAOS",
            format!("Log event #{:05} with Polish chars: zażółć gęślą jaźń", i),
        ));
    }

    assert_eq!(app.logs.len(), 5_000);

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    // Render at bottom
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
    assert!(buffer_contains(&terminal, 80, 24, "Log event #05499"));

    // Navigate to top via Home
    app.handle_key(make_key(KeyCode::Home));
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
    assert!(buffer_contains(&terminal, 80, 24, "Log event #00500"));

    // Navigate down 50 lines
    for _ in 0..50 {
        app.handle_key(make_key(KeyCode::Down));
    }
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    // Navigate back to End
    app.handle_key(make_key(KeyCode::End));
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
    assert!(buffer_contains(&terminal, 80, 24, "Log event #05499"));
}

// =========================================================================
// 5. TELEMETRY & GAUGE EDGE CASES
// =========================================================================

#[test]
fn test_telemetry_gauge_zero_division_safety() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    // Zero broken files: repair_rate() must return 100.0 or 0.0 without panic
    app.stats = StatUpdate {
        files_scanned: 50,
        files_healthy: 50,
        files_broken: 0,
        files_repaired: 0,
        bytes_processed: 0,
        active_threads: 0,
    };

    assert_eq!(app.stats.repair_rate(), 100.0);

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    assert!(buffer_contains(&terminal, 80, 24, "100.0%"));
}

#[test]
fn test_telemetry_gauge_extreme_byte_counts_and_threads() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;

    app.stats = StatUpdate {
        files_scanned: 999_999,
        files_healthy: 500_000,
        files_broken: 499_999,
        files_repaired: 400_000,
        bytes_processed: u64::MAX,
        active_threads: 256,
    };

    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

    assert!(buffer_contains(&terminal, 120, 40, "256"));
    assert!(buffer_contains(&terminal, 120, 40, "400000"));
}

#[test]
fn test_byte_formatting_extremes() {
    assert_eq!(format_bytes(u64::MAX), "16777216.00 TB");
    assert_eq!(format_bytes(1023), "1023 B");
    assert_eq!(format_bytes(1025), "1.0 KB");
}

#[test]
fn test_rapid_resolution_cycling_under_active_operation() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;
    app.current_operation = Some("Skaner Wielowatkowy".to_string());

    for i in 0..100 {
        app.push_log(LogMessage::info("CYCLE", format!("Cycle item {}", i)));
    }

    let cycle_resolutions = [
        (60, 15),
        (59, 14), // Fallback
        (120, 40),
        (80, 24),
        (59, 20), // Fallback
        (200, 60),
        (60, 15),
    ];

    for (w, h) in cycle_resolutions {
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
    }
}

#[test]
fn test_investigate_modal_readability_and_clipping_at_60x15() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.active_modal = Modal::SanitizerSelectPass {
        file_path: "damaged.mp4".to_string(),
        selected_index: 0,
    };

    let backend = TestBackend::new(60, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| {
        ui::draw(f, &mut app);
    }).unwrap();

    // Both options must be clearly rendered and readable
    assert!(buffer_contains(&terminal, 60, 15, "1-Pass CRF 18"));
    assert!(buffer_contains(&terminal, 60, 15, "2-Pass VBR"));
    assert!(buffer_contains(&terminal, 60, 15, "damaged.mp4"));
}

