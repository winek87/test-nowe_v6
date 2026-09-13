//! RAII Terminal Lifecycle Management & Panic Safety
//!
//! Provides `TerminalGuard` for managing raw mode, alternate screen buffers,
//! cursor visibility, subprocess suspension, and custom panic hooks.

use std::io::{self, Stdout, Write};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

use crossterm::{
    cursor::{Hide, Show},
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use ratatui::{backend::CrosstermBackend, CompletedFrame, Frame, Terminal};

/// Process-global flag indicating if the terminal is currently leased in TUI mode.
/// Used by the panic hook and signal handlers to coordinate safe restoration.
static TERMINAL_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Ensures the custom panic hook is installed exactly once per process.
static PANIC_HOOK_INSTALLED: Once = Once::new();

/// Installs a process-wide panic hook that restores the terminal before printing panic backtraces.
///
/// This function is idempotent and lock-free. If a panic occurs while `TerminalGuard` is active,
/// this hook disables raw mode, leaves the alternate screen buffer, and makes the cursor visible,
/// preventing terminal corruption and staircase formatting on `stderr`.
pub fn install_panic_hook() {
    PANIC_HOOK_INSTALLED.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            // Atomically check and reset the terminal active flag
            if TERMINAL_ACTIVE.swap(false, Ordering::SeqCst) {
                let _ = disable_raw_mode();
                let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
                let _ = io::stdout().flush();
            }
            // Delegate to the standard hook to print panic message and backtrace to stderr
            default_hook(panic_info);
        }));
    });
}

/// Emergency fallback to restore terminal state from signal handlers (e.g. SIGTERM, SIGINT).
/// Lock-free and idempotent.
pub fn force_restore() {
    if TERMINAL_ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
        let _ = io::stdout().flush();
    }
}

/// Returns true if the terminal is currently leased in TUI mode.
pub fn is_terminal_active() -> bool {
    TERMINAL_ACTIVE.load(Ordering::SeqCst)
}

/// RAII Guard managing terminal raw mode, alternate screen buffer, and cursor visibility.
///
/// Implements `Deref` and `DerefMut` targeting `ratatui::Terminal<CrosstermBackend<Stdout>>`,
/// allowing direct access to `draw()`, `size()`, and `clear()`.
///
/// On `Drop`, the terminal is automatically restored to cooked mode and the primary screen.
pub struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    active: bool,
    raw_mode_enabled: bool,
    alt_screen_enabled: bool,
    cursor_hidden: bool,
}

impl TerminalGuard {
    /// Initializes the terminal for TUI execution:
    /// 1. Installs the custom panic hook.
    /// 2. Enables raw mode on standard input/output.
    /// 3. Enters the alternate screen buffer.
    /// 4. Hides the cursor.
    /// 5. Initializes the `ratatui::Terminal` with `CrosstermBackend`.
    ///
    /// # Errors
    /// Returns `io::Error` if raw mode or alternate screen cannot be initialized.
    /// In case of failure, any intermediate state is automatically rolled back.
    pub fn init() -> io::Result<Self> {
        // 1. Install panic hook first so setup panics are protected
        install_panic_hook();

        // 2. Enable raw mode
        enable_raw_mode()?;

        let mut stdout = io::stdout();

        // 3. Enter alternate screen and hide cursor
        if let Err(e) = execute!(stdout, EnterAlternateScreen, Hide) {
            let _ = execute!(stdout, Show, LeaveAlternateScreen);
            let _ = disable_raw_mode();
            return Err(e);
        }

        // 4. Initialize Ratatui terminal backend
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = match Terminal::new(backend) {
            Ok(term) => term,
            Err(e) => {
                let mut stdout = io::stdout();
                let _ = execute!(stdout, Show, LeaveAlternateScreen);
                let _ = disable_raw_mode();
                return Err(e);
            }
        };

        // Clear initial screen state.
        //
        // NIEPOWODZENIE JEST TU NIEGROŹNE I NIE MOŻE PRZERWAĆ STARTU.
        // Od ratatui 0.30 `Terminal::clear()` zapisuje i przywraca pozycję
        // kursora, czyli w backendzie crossterm wysyła zapytanie DSR (`ESC[6n`)
        // i czeka na odpowiedź terminala. W środowisku, w którym nikt nie
        // odpowiada — PTY bez emulatora, wyjście przekierowane do pliku,
        // potok w CI — kończy się to błędem „cursor position could not be
        // read". Wcześniej (0.29) `clear()` niczego nie pytało, więc ten sam
        // kod startował wszędzie.
        //
        // Samo czyszczenie jest zbędne dla `Viewport::Fullscreen`: ekran
        // alternatywny jest po wejściu pusty, a świeżo utworzony `Terminal` ma
        // pusty bufor poprzedni, więc pierwszy `draw()` i tak rysuje całość.
        // Zostawiamy próbę (gdy terminal odpowiada, stan jest jawnie czysty),
        // ale odmowa nie może blokować uruchomienia programu.
        // `println!` w trakcie inicjalizacji interfejsu zniszczyłby ekran,
        // a `mp4_doctor` nie ma `tracing` - stąd świadomie ciche pominięcie.
        let _ = terminal.clear();

        // 5. Mark terminal as active
        TERMINAL_ACTIVE.store(true, Ordering::SeqCst);

        Ok(Self {
            terminal,
            active: true,
            raw_mode_enabled: true,
            alt_screen_enabled: true,
            cursor_hidden: true,
        })
    }

    /// Explicitly restores the terminal to cooked mode, main screen, and visible cursor.
    /// Idempotent: safe to call multiple times.
    pub fn restore(&mut self) -> io::Result<()> {
        if !self.active && !self.raw_mode_enabled && !self.alt_screen_enabled && !self.cursor_hidden {
            return Ok(());
        }

        self.active = false;
        TERMINAL_ACTIVE.store(false, Ordering::SeqCst);

        let mut stdout = io::stdout();

        if self.cursor_hidden {
            let _ = execute!(stdout, Show);
            self.cursor_hidden = false;
        }

        if self.alt_screen_enabled {
            let _ = execute!(stdout, LeaveAlternateScreen);
            self.alt_screen_enabled = false;
        }

        if self.raw_mode_enabled {
            let _ = disable_raw_mode();
            self.raw_mode_enabled = false;
        }

        stdout.flush()?;
        Ok(())
    }

    /// Temporarily suspends the TUI environment to execute an external subprocess or action
    /// (e.g. launching `ffplay` in Confidence Player).
    ///
    /// # Lifecycle:
    /// 1. Flushes pending stdout buffers.
    /// 2. Switches from alternate screen to primary screen and displays cursor.
    /// 3. Disables raw mode (restores cooked mode).
    /// 4. Marks `TERMINAL_ACTIVE = false`.
    /// 5. Executes the supplied `action` closure.
    /// 6. Re-enables raw mode, re-enters alternate screen, and hides cursor.
    /// 7. Clears and invalidates the Ratatui buffer to force a full redraw.
    /// 8. Returns the result of `action`.
    ///
    /// # Error Handling:
    /// If `action` returns an `Err`, the terminal environment is STILL cleanly resumed
    /// before returning, allowing the TUI to report the error in a modal dialog.
    pub fn suspend<F, R>(&mut self, action: F) -> io::Result<R>
    where
        F: FnOnce() -> io::Result<R>,
    {
        if !self.active {
            return action();
        }

        // 1. Flush any pending output
        io::stdout().flush()?;

        // 2. Leave alternate screen and show cursor
        execute!(io::stdout(), LeaveAlternateScreen, Show)?;

        // 3. Disable raw mode
        disable_raw_mode()?;

        // 4. Mark inactive so nested panics don't emit redundant sequences
        self.active = false;
        self.raw_mode_enabled = false;
        self.alt_screen_enabled = false;
        self.cursor_hidden = false;
        TERMINAL_ACTIVE.store(false, Ordering::SeqCst);

        // 5. Execute external action
        let action_result = action();

        // 6. Resume TUI environment
        let mut resume_err = None;

        if let Err(e) = enable_raw_mode() {
            resume_err = Some(e);
        } else if let Err(e) = execute!(io::stdout(), EnterAlternateScreen, Hide) {
            let _ = disable_raw_mode();
            resume_err = Some(e);
        } else {
            self.active = true;
            self.raw_mode_enabled = true;
            self.alt_screen_enabled = true;
            self.cursor_hidden = true;
            TERMINAL_ACTIVE.store(true, Ordering::SeqCst);

            // Invalidate Ratatui internal buffer so next draw repaints full UI.
            //
            // Ta sama przyczyna co w `init()`: od ratatui 0.30 `clear()` pyta
            // terminal o pozycję kursora (DSR `ESC[6n`), więc w środowisku bez
            // odpowiadającego terminala zwraca błąd. Wznowienie interfejsu
            // JEST udane — ekran alternatywny i tryb raw wróciły — a samo
            // czyszczenie jest tylko optymalizacją odrysowania. Potraktowanie
            // go jako błędu wznowienia wywracało `suspend()` tam, gdzie nic
            // złego się nie stało.
            let _ = self.terminal.clear();
        }

        // Resumption error takes priority over action error if terminal is broken
        if let Some(err) = resume_err {
            return Err(err);
        }

        action_result
    }

    /// Renders a frame using the underlying Ratatui terminal.
    pub fn draw<F>(&mut self, f: F) -> io::Result<CompletedFrame<'_>>
    where
        F: FnOnce(&mut Frame),
    {
        self.terminal.draw(f)
    }

    /// Provides immutable access to the underlying `ratatui::Terminal`.
    pub fn terminal(&self) -> &Terminal<CrosstermBackend<Stdout>> {
        &self.terminal
    }

    /// Provides mutable access to the underlying `ratatui::Terminal`.
    pub fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        &mut self.terminal
    }

    /// Returns whether the terminal guard is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Deref for TerminalGuard {
    type Target = Terminal<CrosstermBackend<Stdout>>;

    fn deref(&self) -> &Self::Target {
        &self.terminal
    }
}

impl DerefMut for TerminalGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.terminal
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panic_hook_installation() {
        install_panic_hook();
        // Idempotent second call
        install_panic_hook();
        assert!(!is_terminal_active());
    }

    #[test]
    fn test_force_restore_idempotent() {
        force_restore();
        force_restore();
        assert!(!is_terminal_active());
    }

    #[test]
    fn test_terminal_active_toggle() {
        TERMINAL_ACTIVE.store(true, Ordering::SeqCst);
        assert!(is_terminal_active());
        force_restore();
        assert!(!is_terminal_active());
    }

    #[test]
    fn test_terminal_guard_init_or_notty() {
        install_panic_hook();
        match TerminalGuard::init() {
            Ok(mut guard) => {
                assert!(guard.is_active());
                assert!(is_terminal_active());
                assert!(guard.restore().is_ok());
                assert!(!guard.is_active());
                assert!(!is_terminal_active());
                // Idempotent restore
                assert!(guard.restore().is_ok());
            }
            Err(e) => {
                // In headless CI or piped stdout, ENOTTY / Inappropriate ioctl is expected
                assert!(
                    e.raw_os_error().is_some()
                        || e.kind() == io::ErrorKind::Unsupported
                        || e.kind() == io::ErrorKind::Other
                );
                assert!(!is_terminal_active());
            }
        }
    }
}
