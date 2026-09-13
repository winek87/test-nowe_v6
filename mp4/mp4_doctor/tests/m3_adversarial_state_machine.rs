//! Milestone 3 Adversarial Verification Test Suite: State Machine & Keyboard Navigation
//!
//! Empirical validation of:
//! 1. Rapid keyboard navigation across all views (MainMenu, WorkspaceSelect, WorkspaceDashboard,
//!    ScannerSubMenu, SettingsMenu, PreviewFileSelect, OperationRunning) without panics or deadlocks.
//! 2. Text input boundaries and UTF-8 safety (Polish multi-byte characters `zażółć gęślą jaźń`,
//!    emojis, empty strings, backspacing at index 0, delete key at boundaries).
//! 3. Bounded event draining (500 events/tick limit) and memory bounding (5,000 logs max)
//!    under high-volume event bursts (1,000+ to 15,000+ events).

use std::sync::atomic::Ordering;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use mp4_doctor::event::{
    channel, LogMessage, StatUpdate,
};
use mp4_doctor::tui::app::{
    App, Modal, PathInputTarget, View, MAX_EVENTS_PER_TICK, MAX_LOG_HISTORY,
};
use mp4_doctor::SHUTDOWN_FLAG;

fn make_key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn make_key_with_mod(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent {
        code,
        modifiers,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

// =========================================================================
// 1. RAPID NAVIGATION & STATE MACHINE INTEGRITY
// =========================================================================

#[test]
fn test_rapid_navigation_main_menu_wrapping() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    // Spam 5,000 Up and Down keys in MainMenu
    for _ in 0..2500 {
        app.handle_key(make_key(KeyCode::Up));
        let sel = app.main_menu_state.selected().unwrap();
        assert!(sel < 3, "Selected index out of bounds: {}", sel);

        app.handle_key(make_key(KeyCode::Down));
        let sel = app.main_menu_state.selected().unwrap();
        assert!(sel < 3, "Selected index out of bounds: {}", sel);
    }
    assert_eq!(app.current_view, View::MainMenu);
}

#[test]
fn test_rapid_view_transitions_push_pop_spam() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    // Rapidly push and pop views 1,000 times
    for _ in 0..1000 {
        app.push_view(View::WorkspaceSelect);
        assert_eq!(app.current_view, View::WorkspaceSelect);
        assert_eq!(app.view_stack.len(), 1);

        app.push_view(View::WorkspaceDashboard);
        assert_eq!(app.current_view, View::WorkspaceDashboard);
        assert_eq!(app.view_stack.len(), 2);

        app.pop_view();
        assert_eq!(app.current_view, View::WorkspaceSelect);

        app.pop_view();
        assert_eq!(app.current_view, View::MainMenu);
    }
    assert!(!app.should_quit);
}

#[test]
fn test_pop_view_underflow_safety() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    // Pop from MainMenu when stack is empty -> sets should_quit = true
    app.pop_view();
    assert!(app.should_quit);

    // Spam pop_view() 500 more times on empty stack -> must never panic
    for _ in 0..500 {
        app.pop_view();
        assert!(app.should_quit);
        assert!(app.view_stack.is_empty());
    }
}

#[test]
fn test_esc_spam_from_main_menu_quits_cleanly() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    app.handle_key(make_key(KeyCode::Esc));
    assert!(app.should_quit);

    // Subsequent keys do not crash
    for _ in 0..100 {
        app.handle_key(make_key(KeyCode::Esc));
        app.handle_key(make_key(KeyCode::Down));
        app.handle_key(make_key(KeyCode::Enter));
    }
}

#[test]
fn test_ctrl_c_signals_global_shutdown() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    SHUTDOWN_FLAG.store(false, Ordering::SeqCst);
    assert!(!SHUTDOWN_FLAG.load(Ordering::SeqCst));

    let ctrl_c = make_key_with_mod(KeyCode::Char('c'), KeyModifiers::CONTROL);
    app.handle_key(ctrl_c);

    assert!(app.should_quit);
    assert!(SHUTDOWN_FLAG.load(Ordering::SeqCst));
}

#[test]
fn test_operation_running_rapid_scroll_boundaries() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);
    app.push_view(View::OperationRunning);
    app.is_running = true;

    // 1. With 0 logs: rapid scroll keys must not panic
    let nav_keys = [
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::PageUp,
        KeyCode::PageDown,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::Char('j'),
        KeyCode::Char('k'),
        KeyCode::Char('g'),
        KeyCode::Char('G'),
    ];

    for &key in &nav_keys {
        for _ in 0..100 {
            app.handle_key(make_key(key));
            assert_eq!(app.log_scroll, 0);
        }
    }

    // 2. Add 200 logs
    for i in 0..200 {
        app.logs.push_back(LogMessage::info("TEST", format!("Message {}", i)));
    }
    app.log_scroll = 199;
    app.auto_scroll = true;

    // Spam PageUp and PageDown
    for _ in 0..500 {
        app.handle_key(make_key(KeyCode::PageUp));
        assert!(app.log_scroll <= 199);
        assert!(!app.auto_scroll);
    }
    assert_eq!(app.log_scroll, 0);

    for _ in 0..500 {
        app.handle_key(make_key(KeyCode::PageDown));
        assert!(app.log_scroll <= 199);
    }
    assert_eq!(app.log_scroll, 199);
    assert!(app.auto_scroll);

    // Enter / Esc while is_running = true must NOT pop view
    app.handle_key(make_key(KeyCode::Enter));
    assert_eq!(app.current_view, View::OperationRunning);
    app.handle_key(make_key(KeyCode::Esc));
    assert_eq!(app.current_view, View::OperationRunning);

    // Stop operation and pop back to MainMenu
    app.is_running = false;
    app.handle_key(make_key(KeyCode::Esc));
    assert_eq!(app.current_view, View::MainMenu);
}

#[test]
fn test_fuzzer_10000_random_inputs_no_panics() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    let key_pool = [
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Enter,
        KeyCode::Esc,
        KeyCode::Backspace,
        KeyCode::Delete,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::PageUp,
        KeyCode::PageDown,
        KeyCode::Tab,
        KeyCode::Char('j'),
        KeyCode::Char('k'),
        KeyCode::Char('q'),
        KeyCode::Char('s'),
        KeyCode::Char('a'),
        KeyCode::Char('n'),
        KeyCode::Char('y'),
        KeyCode::Char(' '),
        KeyCode::Char('ż'),
        KeyCode::Char('ó'),
        KeyCode::Char('ł'),
    ];

    // Simple pseudo-random LCG for deterministic reproducibility
    let mut rng_state: u64 = 0xDEADBEEF_CAFEBABE;
    let mut next_rand = || -> usize {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (rng_state >> 32) as usize
    };

    for _ in 0..10_000 {
        let idx = next_rand() % key_pool.len();
        let key = key_pool[idx];
        app.handle_key(make_key(key));
        // Ensure app never crashed and remains in a valid View
        match app.current_view {
            View::MainMenu
            | View::WorkspaceSelect
            | View::WorkspaceDashboard
            | View::ScannerSubMenu
            | View::SettingsMenu
            | View::PreviewFileSelect
            | View::OperationRunning => {}
        }
    }
}

// =========================================================================
// 2. TEXT INPUT BOUNDARIES & UTF-8 / MULTI-BYTE RESILIENCE
// =========================================================================

#[test]
fn test_polish_pangram_text_editing() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    app.active_modal = Modal::NewWorkspace {
        input: String::new(),
        cursor: 0,
        error_msg: None,
    };

    let pangram = "zażółć gęślą jaźń";

    // Type the entire Polish pangram
    for c in pangram.chars() {
        app.handle_key(make_key(KeyCode::Char(c)));
    }

    if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
        assert_eq!(input, pangram);
        assert_eq!(*cursor, pangram.len());
        assert!(input.is_char_boundary(*cursor));
    } else {
        panic!("Modal should be NewWorkspace");
    }

    // Move left character-by-character to the beginning
    // Each step MUST land on a valid UTF-8 character boundary
    for _ in 0..pangram.chars().count() {
        app.handle_key(make_key(KeyCode::Left));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert!(
                input.is_char_boundary(*cursor),
                "Cursor {} not on char boundary in '{}'",
                cursor,
                input
            );
        }
    }

    if let Modal::NewWorkspace { cursor, .. } = &app.active_modal {
        assert_eq!(*cursor, 0);
    }

    // Move right character-by-character back to the end
    for _ in 0..pangram.chars().count() {
        app.handle_key(make_key(KeyCode::Right));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert!(
                input.is_char_boundary(*cursor),
                "Cursor {} not on char boundary in '{}'",
                cursor,
                input
            );
        }
    }

    if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
        assert_eq!(*cursor, input.len());
    }

    // Backspace the entire string character-by-character
    for _ in 0..pangram.chars().count() {
        app.handle_key(make_key(KeyCode::Backspace));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert!(
                input.is_char_boundary(*cursor),
                "Cursor {} not on char boundary after backspace in '{}'",
                cursor,
                input
            );
        }
    }

    if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
        assert_eq!(input, "");
        assert_eq!(*cursor, 0);
    }
}

#[test]
fn test_emoji_and_surrogate_boundary_editing() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    app.active_modal = Modal::NewWorkspace {
        input: String::new(),
        cursor: 0,
        error_msg: None,
    };

    // Emojis: 4-byte UTF-8 codepoints
    let emojis = ['🦀', '🔥', '🚀', '🌟', '🎉'];
    for &e in &emojis {
        app.handle_key(make_key(KeyCode::Char(e)));
    }

    if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
        assert_eq!(input, "🦀🔥🚀🌟🎉");
        assert_eq!(*cursor, 20); // 5 emojis * 4 bytes each = 20 bytes
        assert!(input.is_char_boundary(*cursor));
    }

    // Backspace single emoji
    app.handle_key(make_key(KeyCode::Backspace));
    if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
        assert_eq!(input, "🦀🔥🚀🌟");
        assert_eq!(*cursor, 16);
        assert!(input.is_char_boundary(*cursor));
    }

    // Move left twice (over 🌟 and 🚀)
    app.handle_key(make_key(KeyCode::Left));
    app.handle_key(make_key(KeyCode::Left));
    if let Modal::NewWorkspace { cursor, .. } = &app.active_modal {
        assert_eq!(*cursor, 8); // Points before 🚀
    }

    // Delete key removes 🚀 (at cursor 8)
    app.handle_key(make_key(KeyCode::Delete));
    if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
        assert_eq!(input, "🦀🔥🌟");
        assert_eq!(*cursor, 8);
        assert!(input.is_char_boundary(*cursor));
    }
}

#[test]
fn test_empty_string_boundary_conditions() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    app.active_modal = Modal::NewWorkspace {
        input: String::new(),
        cursor: 0,
        error_msg: None,
    };

    // Backspace 100 times on empty string
    for _ in 0..100 {
        app.handle_key(make_key(KeyCode::Backspace));
    }

    // Delete 100 times on empty string
    for _ in 0..100 {
        app.handle_key(make_key(KeyCode::Delete));
    }

    // Left / Right / Home / End on empty string
    for _ in 0..50 {
        app.handle_key(make_key(KeyCode::Left));
        app.handle_key(make_key(KeyCode::Right));
        app.handle_key(make_key(KeyCode::Home));
        app.handle_key(make_key(KeyCode::End));
    }

    if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
        assert_eq!(input, "");
        assert_eq!(*cursor, 0);
    }
}

#[test]
fn test_path_input_modal_boundary_editing() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    app.active_modal = Modal::PathInput {
        title: "Test".into(),
        prompt: "Enter path:".into(),
        input: "/ścieżka/do/danych_żółw".into(),
        cursor: "/ścieżka/do/danych_żółw".len(),
        conf_file: "test.conf".into(),
        target: PathInputTarget::ScannerSingle,
        error_msg: None,
    };

    // Home key moves cursor to 0
    app.handle_key(make_key(KeyCode::Home));
    if let Modal::PathInput { cursor, .. } = &app.active_modal {
        assert_eq!(*cursor, 0);
    }

    // Delete at index 0 removes '/'
    app.handle_key(make_key(KeyCode::Delete));
    if let Modal::PathInput { input, cursor, .. } = &app.active_modal {
        assert_eq!(input, "ścieżka/do/danych_żółw");
        assert_eq!(*cursor, 0);
    }

    // End key moves cursor to end
    app.handle_key(make_key(KeyCode::End));
    if let Modal::PathInput { input, cursor, .. } = &app.active_modal {
        assert_eq!(*cursor, input.len());
    }

    // Delete at end does nothing
    app.handle_key(make_key(KeyCode::Delete));
    if let Modal::PathInput { input, cursor, .. } = &app.active_modal {
        assert_eq!(*cursor, input.len());
    }

    // Esc cancels modal cleanly
    app.handle_key(make_key(KeyCode::Esc));
    assert_eq!(app.active_modal, Modal::None);
}

// =========================================================================
// 3. EVENT DRAINING & BOUNDED MEMORY CONSUMPTION
// =========================================================================

#[test]
fn test_bounded_batch_consumption_500_per_tick() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx.clone(), rx);

    // Send 1,200 events into the channel
    for i in 0..1200 {
        tx.info("DRAIN", format!("Event {}", i));
    }

    // Tick 1: drains exactly MAX_EVENTS_PER_TICK (500)
    app.process_events();
    assert_eq!(
        app.logs.len(),
        MAX_EVENTS_PER_TICK,
        "Tick 1 must drain exactly {} events",
        MAX_EVENTS_PER_TICK
    );
    assert_eq!(app.logs[0].message, "Event 0");
    assert_eq!(app.logs[499].message, "Event 499");

    // Tick 2: drains next 500 events
    app.process_events();
    assert_eq!(app.logs.len(), 1000);
    assert_eq!(app.logs[999].message, "Event 999");

    // Tick 3: drains remaining 200 events
    app.process_events();
    assert_eq!(app.logs.len(), 1200);
    assert_eq!(app.logs[1199].message, "Event 1199");

    // Tick 4: channel empty, 0 events drained
    app.process_events();
    assert_eq!(app.logs.len(), 1200);
}

#[test]
fn test_bounded_memory_under_high_volume_log_burst() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx.clone(), rx);

    // Send 15,000 log events through the channel
    // Memory limit is MAX_LOG_HISTORY = 5,000
    for i in 0..15_000 {
        tx.info("BURST", format!("Burst item {}", i));
    }

    // Drain all events over 30 ticks (30 * 500 = 15,000)
    for _ in 0..30 {
        app.process_events();
        assert!(
            app.logs.len() <= MAX_LOG_HISTORY,
            "Log history exceeded MAX_LOG_HISTORY ({}): got {}",
            MAX_LOG_HISTORY,
            app.logs.len()
        );
    }

    // Memory buffer must be clamped at bounded size
    assert!(
        app.logs.len() <= MAX_LOG_HISTORY,
        "Final log size {} exceeds {}",
        app.logs.len(),
        MAX_LOG_HISTORY
    );

    // Auto-scroll must track latest log index
    assert_eq!(app.log_scroll, app.logs.len().saturating_sub(1));

    // The most recent event should be near the end
    let last_msg = app.logs.back().unwrap();
    assert_eq!(last_msg.message, "Burst item 14999");
}

#[test]
fn test_heterogeneous_event_burst_integrity() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx.clone(), rx);

    // Send a barrage of mixed event types
    for i in 0..200 {
        tx.update_stats(StatUpdate::new(i * 10, i * 5, i * 2, i * 3, 1024 * i as u64, 4));
        tx.update_thread(i % 8, format!("Thread working on chunk {}", i));
        tx.sanitizer_metrics(i as u64 * 100, 30.0, "2.5x", 1);
        tx.info("MIXED", format!("Status message {}", i));
    }

    // Tick 1: Consumes exactly 500 events (125 iterations * 4 events = 500 events)
    app.process_events();
    assert_eq!(app.sanitizer_metrics.frame, 12400, "Tick 1 must cap at 500 events");

    // Tick 2: Consumes remaining 300 events (75 iterations * 4 events = 300 events)
    app.process_events();
    assert_eq!(app.sanitizer_metrics.frame, 19900, "Tick 2 drains remaining events to 19900");
    assert!(app.stats.files_scanned >= 1000);
    assert_eq!(app.thread_statuses.len(), 8);
}

#[test]
fn test_auto_scroll_preservation_under_incoming_logs() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx.clone(), rx);

    // Feed 100 initial logs
    for i in 0..100 {
        tx.info("SYS", format!("Log {}", i));
    }
    app.process_events();
    assert_eq!(app.log_scroll, 99);
    assert!(app.auto_scroll);

    // User scrolls up manually
    app.current_view = View::OperationRunning;
    app.handle_key(make_key(KeyCode::PageUp));
    assert_eq!(app.log_scroll, 89);
    assert!(!app.auto_scroll);

    // 500 new logs arrive
    for i in 100..600 {
        tx.info("SYS", format!("Log {}", i));
    }
    app.process_events();

    // User's scroll position must NOT jump to the bottom because auto_scroll is false
    assert_eq!(app.log_scroll, 89);
    assert!(!app.auto_scroll);

    // User presses End / 'G' to re-enable auto_scroll
    app.handle_key(make_key(KeyCode::End));
    assert!(app.auto_scroll);
    assert_eq!(app.log_scroll, app.logs.len().saturating_sub(1));
}
