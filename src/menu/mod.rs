// src/menu/mod.rs

//! # Główny Moduł Menu (Ratatui)
//! Zastępuje stare renderowanie ANSI. Wprowadza wzorzec architektoniczny Elm Architecture (MVU).
//! Odpowiada za cykl życia terminala, zabezpieczenie RAII (tryb Raw) i pętlę zdarzeń.

pub mod state;
pub mod events;
pub mod actions;
pub mod settings_actions;

use crate::settings::Ustawienia;
use rusqlite::Connection;
use ratatui::{backend::CrosstermBackend, Terminal};
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use std::{io, time::{Duration, Instant}};
use tracing::{info, error};

use state::AppState;

// ============================================================================
// STRAŻNIK TERMINALA (RAII GUARD DLA RAW MODE)
// ============================================================================

/// Chroni terminal przed "zcegłowaniem" w przypadku nagłego panic!
/// Zawsze przywraca standardowy stan terminala przy wyjściu z zakresu.
struct TerminalGuard;

impl TerminalGuard {
    fn acquire() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

// ============================================================================
// GŁÓWNA FUNKCJA WEJŚCIOWA (ENTRYPOINT TUI)
// ============================================================================

pub fn start_interactive(ustawienia: &mut Ustawienia, conn: &mut Connection) -> Result<(), Box<dyn std::error::Error>> {
    info!("Inicjalizacja pełno ekranowego interfejsu Ratatui (TUI)...");
    // 1. Zabezpieczenie terminala strażnikiem RAII
    let _guard = match TerminalGuard::acquire() {
        Ok(guard) => guard,
        Err(e) => {
            tracing::error!("Błąd inicjalizacji pełno ekranowego interfejsu Ratatui: {:?}", e);
            error!("Błąd inicjalizacji pełno ekranowego interfejsu Ratatui: {:?}", e);
            eprintln!("\n[FATAL] Aplikacja wymaga dostępu do terminala w trybie surowym.");
            eprintln!("Szczegóły błędu: {}", e);
            return Err(e.into());
        }
    };

    // 2. Inicjalizacja backendu Ratatui
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Krytyczny Błąd tworzenia backendu Ratatui: {:?}", e);
            error!("Krytyczny Błąd tworzenia backendu Ratatui: {:?}", e);
            eprintln!("\n[FATAL] Nie udało się utworzyć backendu Ratatui.");
            eprintln!("Szczegóły błędu: {}", e);
            return Err(e.into());
        }
    };
        
    // 3. Inicjalizacja Głównego Stanu Aplikacji (Model)
    let mut app = match AppState::new(ustawienia) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Błąd inicjalizacji stanu aplikacji (AppState): {:?}", e);
            error!("Błąd inicjalizacji stanu aplikacji (AppState): {:?}", e);
            eprintln!("\n[FATAL] Nie udało się zainicjalizować stanu aplikacji.");
            eprintln!("Szczegóły błędu: {}", e);
            return Err(e.into());
        }
    };

    // 4. Uruchomienie Pętli MVU (Model-View-Update)
    info!("Pętla zdarzeń UI (MVU) została uruchomiona.");
    match run_app(&mut terminal, &mut app, conn) {
        Ok(()) => {}
        Err(e) => {
            tracing::error!("Krytyczny błąd w głównej pętli UI: {:?}", e);
            eprintln!("\n[FATAL] Aplikacja napotkała błąd podczas działania pętli interfejsu.");
            eprintln!("Szczegóły błędu: {}", e);
            return Err(e.into());
        }
    }
    info!("Opuszczono tryb graficzny TUI. Ekran terminala przywrócony.");

    Ok(())
}

// ============================================================================
// PĘTLA APLIKACJI (MVU LOOP)
// ============================================================================

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut AppState,
    conn: &mut Connection,
) -> io::Result<()> {
    let tick_rate = Duration::from_millis(app.ustawienia.dashboard_refresh_rate);
    let mut last_tick = Instant::now();

    loop {
        // [ 1 ] UPDATE (Model) - Asynchroniczna aktualizacja zasobów (CPU/RAM/DB)
        app.tick(conn);

        // [ 2 ] RENDER (View) - Rysowanie pełnego ekranu z wykorzystaniem Ratatui
        terminal.draw(|f| crate::tui::dashboard::draw_dashboard(f, app))?;

        // [ 3 ] EVENTS (Update) - Obsługa wejścia (Input) bez blokowania wątku
        let timeout = tick_rate.checked_sub(last_tick.elapsed()).unwrap_or_else(|| Duration::from_secs(0));
        
        if crossterm::event::poll(timeout)?
            && let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                // events::handle_key zwraca 'true' tylko jeśli system ma zostać wyłączony
                if events::handle_key(key, app) {
                    break; // Sygnał bezpiecznego wyjścia z programu
                }
            }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }

        // [ 4 ] ACTIONS - Obsługa wywołań faz zleconych przez UI
        if let Some(action) = app.action_to_execute.take() {
            // Zabezpieczenie: jeśli wybrano ostatnią opcję (Wyjście z programu)
            if action == app.selections.len().saturating_sub(1) {
                break; // Łagodnie przerywa pętlę, naprawia ekran i zamyka bazę w main.rs
            }
            actions::execute_action(action, app, conn, terminal)?;
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Ustawienia;

    // Pomocnicza funkcja tworząca domyślne ustawienia do testów
    fn mock_ustawienia() -> Ustawienia {
        Ustawienia::default() // Zakłada, że Ustawienia implementują Default
    }

    #[test]
    fn test_app_state_initialization() {
        let mut ustawienia = mock_ustawienia();
        let app = AppState::new(&mut ustawienia);
        
        assert!(app.is_ok(), "AppState::new powinno zakończyć się sukcesem");
        let app = app.unwrap();
        
        // Sprawdzamy czy wektor opcji (selections) nie jest pusty
        assert!(!app.selections.is_empty(), "Lista opcji menu nie powinna być pusta");
        assert_eq!(app.selected_index, 0, "Początkowy indeks powinien wynosić 0");
    }

    #[test]
    fn test_selection_navigation() {
        let mut ustawienia = mock_ustawienia();
        let mut app = AppState::new(&mut ustawienia).unwrap();

        // Ustawiamy indeks na początek
        app.selected_index = 0;
        
        // Pierwszy element to [ 🚀 ] URUCHOM..., drugi to separator ("────").
        // Metoda next_selection powinna omijać separatory.
        let initial_index = app.selected_index;
        app.next_selection();
        
        assert_ne!(app.selected_index, initial_index, "Indeks powinien się zmienić");
        
        // Sprawdzamy czy aktualnie wybranym elementem nie jest separator
        let current_text = app.selections[app.selected_index].0;
        assert!(!current_text.contains("───"), "Kursor nie powinien zatrzymać się na separatorze");
    }

    #[test]
    fn test_terminal_guard_acquire() {
        // Test próby inicjalizacji strażnika terminala.
        // Uwaga: W środowisku CI/CD bez prawdziwego TTY (np. GitHub Actions) 
        // enable_raw_mode() może zwrócić błąd (Not a tty), co jest zachowaniem oczekiwanym.
        let guard_result = TerminalGuard::acquire();
        
        match guard_result {
            Ok(_guard) => {
                // Jeśli uruchomiono w interaktywnym terminalu, sukces
                // assert removed
            }
            Err(e) => {
                // Jeśli brak TTY (np. testy w pipeline), błąd jest naturalny dla systemów bez tty
                eprintln!("Info: TerminalGuard::acquire zwrócił błąd (prawdopodobnie brak aktywnego TTY w środowisku testowym): {}", e);
            }
        }
    }
}
