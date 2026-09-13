//! Adversarial empirical verification of:
//! 1. Unicode boundary safety and multi-byte text editing (Polish chars, emojis, combining marks)
//! 2. Rapid keyboard spamming across views and modals
//! 3. Stack overflow / underflow safety during rapid Esc/Enter navigation

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use mp4_doctor::event::channel;
use mp4_doctor::tui::app::{App, Modal, PathInputTarget, View};

fn make_key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn assert_text_cursor_boundary_invariant(text: &str, cursor: usize) {
    assert!(
        cursor <= text.len(),
        "Cursor {} exceeds text length {}",
        cursor,
        text.len()
    );
    assert!(
        text.is_char_boundary(cursor),
        "Cursor {} is not on a UTF-8 character boundary in string {:?}",
        cursor,
        text
    );
    // Emulate ratatui ui::render_text_with_cursor slice operations
    let _before = &text[..cursor];
    let _after = &text[cursor..];
}

#[test]
fn test_polish_alphabet_all_characters_editing() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    app.active_modal = Modal::NewWorkspace {
        input: String::new(),
        cursor: 0,
        error_msg: None,
    };

    let polish_chars = [
        'ą', 'ć', 'ę', 'ł', 'ń', 'ó', 'ś', 'ź', 'ż',
        'Ą', 'Ć', 'Ę', 'Ł', 'Ń', 'Ó', 'Ś', 'Ź', 'Ż',
    ];

    // 1. Type all Polish characters and check boundary at every step
    for &c in &polish_chars {
        app.handle_key(make_key(KeyCode::Char(c)));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }

    let expected_str: String = polish_chars.iter().collect();
    if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
        assert_eq!(input, &expected_str);
        assert_eq!(*cursor, expected_str.len());
    }

    // 2. Move left through all characters
    for _ in 0..polish_chars.len() {
        app.handle_key(make_key(KeyCode::Left));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }
    if let Modal::NewWorkspace { cursor, .. } = &app.active_modal {
        assert_eq!(*cursor, 0);
    }

    // Extra lefts at boundary 0
    for _ in 0..10 {
        app.handle_key(make_key(KeyCode::Left));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_eq!(*cursor, 0);
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }

    // 3. Move right through all characters
    for _ in 0..polish_chars.len() {
        app.handle_key(make_key(KeyCode::Right));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }
    if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
        assert_eq!(*cursor, input.len());
    }

    // Extra rights at end boundary
    for _ in 0..10 {
        app.handle_key(make_key(KeyCode::Right));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_eq!(*cursor, input.len());
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }

    // 4. Move to middle and insert chars
    app.handle_key(make_key(KeyCode::Home));
    for _ in 0..5 {
        app.handle_key(make_key(KeyCode::Right));
    }
    // Insert "ŚĆŻ" in the middle
    for &c in &['Ś', 'Ć', 'Ż'] {
        app.handle_key(make_key(KeyCode::Char(c)));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }

    // 5. Delete characters at cursor
    for _ in 0..3 {
        app.handle_key(make_key(KeyCode::Delete));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }

    // 6. Backspace characters
    for _ in 0..5 {
        app.handle_key(make_key(KeyCode::Backspace));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }
}

#[test]
fn test_complex_emoji_and_zwj_sequences() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    app.active_modal = Modal::NewWorkspace {
        input: String::new(),
        cursor: 0,
        error_msg: None,
    };

    // Various complex Unicode strings:
    // 1. Single 4-byte emojis
    // 2. Skin tone modifier: 👍 + \u{1F3FD}
    // 3. ZWJ sequence: 👨 + \u{200D} + 👩 + \u{200D} + 👧 + \u{200D} + 👦
    // 4. Combining diacritical: e + \u{0301}
    // 5. Regional indicator flags: \u{1F1F5} + \u{1F1F1} (PL)
    let test_codepoints = [
        '🦀', '🚀', '🔥',
        '👍', '\u{1F3FD}', // 👍🏽
        '👨', '\u{200D}', '👩', '\u{200D}', '👧', '\u{200D}', '👦', // 👨‍👩‍👧‍👦
        'e', '\u{0301}', // é
        '\u{1F1F5}', '\u{1F1F1}', // 🇵🇱
    ];

    for &c in &test_codepoints {
        app.handle_key(make_key(KeyCode::Char(c)));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }

    // Traverse left and right across all codepoints
    let count = test_codepoints.len();
    for _ in 0..count {
        app.handle_key(make_key(KeyCode::Left));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }

    for _ in 0..count {
        app.handle_key(make_key(KeyCode::Right));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }

    // Delete from end (no-op)
    app.handle_key(make_key(KeyCode::Delete));
    if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
        assert_text_cursor_boundary_invariant(input, *cursor);
    }

    // Backspace everything to empty
    for _ in 0..count + 5 {
        app.handle_key(make_key(KeyCode::Backspace));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }

    if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
        assert_eq!(input, "");
        assert_eq!(*cursor, 0);
    }
}

#[test]
fn test_rapid_esc_enter_view_navigation_bounded_stack() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    // Rapidly alternate Enter (enter WorkspaceSelect) and Esc (pop back to MainMenu)
    for _ in 0..10_000 {
        assert_eq!(app.current_view, View::MainMenu);
        assert_eq!(app.view_stack.len(), 0);

        // Enter from MainMenu item 0 (WorkspaceSelect)
        app.handle_key(make_key(KeyCode::Enter));
        assert_eq!(app.current_view, View::WorkspaceSelect);
        assert_eq!(app.view_stack.len(), 1);

        // Esc back to MainMenu
        app.handle_key(make_key(KeyCode::Esc));
        assert_eq!(app.current_view, View::MainMenu);
        assert_eq!(app.view_stack.len(), 0);
        assert!(!app.should_quit);
    }
}

#[test]
fn test_esc_underflow_spam_resilience() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    assert_eq!(app.view_stack.len(), 0);

    // Spam Esc 10,000 times on empty stack
    for _ in 0..10_000 {
        app.handle_key(make_key(KeyCode::Esc));
        assert!(app.should_quit);
        assert_eq!(app.view_stack.len(), 0);
    }

    // Interleave Enter and other keys
    for _ in 0..1_000 {
        app.handle_key(make_key(KeyCode::Enter));
        app.handle_key(make_key(KeyCode::Left));
        app.handle_key(make_key(KeyCode::Right));
        app.handle_key(make_key(KeyCode::Esc));
    }
}

#[test]
fn test_rapid_keyboard_spamming_on_text_modal() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    app.active_modal = Modal::PathInput {
        title: "Test Modal".to_string(),
        prompt: "Path:".to_string(),
        input: "/usr/local/wideo/zażółć_gęślą_jaźń.mp4".to_string(),
        cursor: "/usr/local/wideo/zażółć_gęślą_jaźń.mp4".len(),
        conf_file: "test.conf".to_string(),
        target: PathInputTarget::ScannerSingle,
        error_msg: None,
    };

    let actions = [
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::Backspace,
        KeyCode::Delete,
        KeyCode::Char('a'),
        KeyCode::Char('ż'),
        KeyCode::Char('🚀'),
        KeyCode::Char(' '),
        KeyCode::Char('/'),
    ];

    let mut state: u64 = 0x12345678_9ABCDEF0;
    for _ in 0..20_000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let key = actions[(state >> 32) as usize % actions.len()];
        app.handle_key(make_key(key));

        if let Modal::PathInput { input, cursor, .. } = &app.active_modal {
            assert_text_cursor_boundary_invariant(input, *cursor);
        }
    }
}

#[test]
fn test_settings_thread_limit_numerical_boundaries() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    app.active_modal = Modal::SettingsThreadLimit {
        input: String::new(),
        cursor: 0,
        error_msg: None,
    };

    // Non-digit input is strictly ignored
    for c in ['a', 'x', 'ż', ' ', '-', '+', '!', '.'] {
        app.handle_key(make_key(KeyCode::Char(c)));
        if let Modal::SettingsThreadLimit { input, .. } = &app.active_modal {
            assert_eq!(input, "");
        }
    }

    // Type 0 (Auto) -> valid
    app.handle_key(make_key(KeyCode::Char('0')));
    app.handle_key(make_key(KeyCode::Enter));
    assert_eq!(app.active_modal, Modal::None);

    // Reopen and type a number causing integer overflow on parse
    app.active_modal = Modal::SettingsThreadLimit {
        input: String::new(),
        cursor: 0,
        error_msg: None,
    };
    for _ in 0..40 {
        app.handle_key(make_key(KeyCode::Char('9')));
    }
    app.handle_key(make_key(KeyCode::Enter));
    // Must gracefully display error without panic
    if let Modal::SettingsThreadLimit { error_msg, .. } = &app.active_modal {
        assert!(error_msg.is_some());
    } else {
        panic!("Expected SettingsThreadLimit modal to remain open with error message");
    }
}

#[test]
fn test_fuzzer_100_000_arbitrary_events() {
    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    let key_codes = [
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
        KeyCode::Char('a'),
        KeyCode::Char('z'),
        KeyCode::Char('0'),
        KeyCode::Char('9'),
        KeyCode::Char(' '),
        KeyCode::Char('ę'),
        KeyCode::Char('ź'),
        KeyCode::Char('🔥'),
    ];

    let mut state: u64 = 0xCAFEBABE_DEADBEEF;
    for _ in 0..100_000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let key = key_codes[(state >> 32) as usize % key_codes.len()];
        app.handle_key(make_key(key));

        // Invariants:
        // 1. If modal is text-based, cursor is always on valid char boundary
        match &app.active_modal {
            Modal::NewWorkspace { input, cursor, .. }
            | Modal::PathInput { input, cursor, .. }
            | Modal::SettingsThreadLimit { input, cursor, .. } => {
                assert_text_cursor_boundary_invariant(input, *cursor);
            }
            _ => {}
        }

        // 2. View stack never exceeds reasonable depth (menu tree depth <= 10)
        assert!(
            app.view_stack.len() <= 10,
            "View stack grew unexpectedly deep: {}",
            app.view_stack.len()
        );
    }
}
