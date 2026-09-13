// src/menu/events.rs

//! # Moduł Zdarzeń Klawiatury (Update)
//! Odpowiada za reagowanie na akcje użytkownika, manipulację stanem menu
//! oraz awaryjne przechwytywanie kombinacji klawiszy w trybie RAW.

use crate::menu::state::AppState;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tracing::{info, debug};

/// Analizuje wciśnięty klawisz i mutuje AppState.
/// Zwraca `true` tylko wtedy, gdy żąda natychmiastowego przerwania pętli głównej.
pub fn handle_key(key: KeyEvent, app: &mut AppState) -> bool {
    // 1. Twarde wyjście awaryjne (Zabezpieczenie trybu RAW)
    // Terminal w trybie Raw połyka sygnały SIGINT. Musimy je obsłużyć manualnie.
    // 1. Twarde wyjście awaryjne
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        info!("Przechwycono sygnał Ctrl+C w menu. Zlecam bezpieczne zamknięcie aplikacji.");
        return true; // Łagodnie wyłamuje pętlę Ratatui pozwalając na naturalne zamknięcie aplikacji
    }

    // 2. Obsługa nawigacji i potwierdzeń
    match key.code {
        // Strzałki w górę (i alternatywa VIM-owa)
        KeyCode::Up | KeyCode::Char('k') => {
            app.previous_selection();
            debug!("Ruch kursora (Góra): Aktualny indeks -> {}", app.selected_index);
        }
        
        // Strzałki w dół (i alternatywa VIM-owa)
        KeyCode::Down | KeyCode::Char('j') => {
            app.next_selection();
            debug!("Ruch kursora (Dół): Aktualny indeks -> {}", app.selected_index);
        }
        
        // Zatwierdzenie akcji
        KeyCode::Enter => {
            // Zapisujemy indeks akcji w State. 
            // Plik mod.rs zauważy tę flagę i uruchomi odpowiednią funkcję.
            info!("Zatwierdzono wybór klawiszem ENTER. Wybrano akcję o indeksie: {}", app.selected_index);
            app.action_to_execute = Some(app.selected_index);
        }
        
        // Klawisze wyjścia (Esc / Q) - Zwracamy true, aby wyłamać pętlę w mod.rs
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
            info!("Wciśnięto klawisz wyjścia (Esc / Q). Zlecam bezpieczne zamknięcie aplikacji.");
            return true; 
        }
        _ => {}
    }

    // Domyślnie pozwalamy pętli działać dalej
    false
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Ustawienia;
    use crossterm::event::{KeyEventKind, KeyEventState};

    fn klawisz(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn klawisz_z_ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    /// Buduje stan menu na konfiguracji wskazującej katalog tymczasowy.
    macro_rules! ze_stanem {
        (|$app:ident| $cialo:block) => {{
            let dir = tempfile::tempdir().unwrap();
            let mut u = Ustawienia {
                db_path: dir.path().to_string_lossy().to_string(),
                log_path: dir.path().to_string_lossy().to_string(),
                ..Default::default()
            };
            let mut $app = AppState::new(&mut u).expect("stan menu musi się zbudować");
            $cialo
        }};
    }

    // ------------------------------------------------------------------
    // WYJŚCIE
    // ------------------------------------------------------------------

    /// Terminal w trybie RAW połyka SIGINT, więc Ctrl+C MUSI być obsłużone
    /// ręcznie — inaczej operator nie ma jak wyjść z menu.
    #[test]
    fn test_ctrl_c_zleca_zakonczenie() {
        ze_stanem!(|app| {
            assert!(handle_key(klawisz_z_ctrl(KeyCode::Char('c')), &mut app));
        });
    }

    #[test]
    fn test_samo_c_bez_ctrl_nie_konczy_programu() {
        ze_stanem!(|app| {
            assert!(
                !handle_key(klawisz(KeyCode::Char('c')), &mut app),
                "Litera 'c' bez modyfikatora to zwykły znak, nie wyjście"
            );
        });
    }

    #[test]
    fn test_klawisze_wyjscia_koncza_petle() {
        for kod in [KeyCode::Esc, KeyCode::Char('q'), KeyCode::Char('Q')] {
            ze_stanem!(|app| {
                assert!(handle_key(klawisz(kod), &mut app), "Klawisz {:?} musi kończyć pętlę", kod);
            });
        }
    }

    // ------------------------------------------------------------------
    // NAWIGACJA
    // ------------------------------------------------------------------

    #[test]
    fn test_strzalka_w_dol_przesuwa_kursor() {
        ze_stanem!(|app| {
            let przed = app.selected_index;
            assert!(!handle_key(klawisz(KeyCode::Down), &mut app));
            assert_ne!(app.selected_index, przed, "Kursor musi się ruszyć");
        });
    }

    /// Alternatywa VIM-owa musi działać identycznie jak strzałki — to jedyny
    /// sposób nawigacji na terminalach gubiących sekwencje strzałek.
    #[test]
    fn test_klawisze_vim_dzialaja_jak_strzalki() {
        ze_stanem!(|app| {
            handle_key(klawisz(KeyCode::Down), &mut app);
            let po_strzalce = app.selected_index;

            app.selected_index = 0;
            handle_key(klawisz(KeyCode::Char('j')), &mut app);
            assert_eq!(app.selected_index, po_strzalce, "'j' musi działać jak strzałka w dół");

            handle_key(klawisz(KeyCode::Up), &mut app);
            let po_strzalce_gora = app.selected_index;

            app.selected_index = po_strzalce;
            handle_key(klawisz(KeyCode::Char('k')), &mut app);
            assert_eq!(app.selected_index, po_strzalce_gora, "'k' musi działać jak strzałka w górę");
        });
    }

    #[test]
    fn test_nawigacja_nigdy_nie_zatrzymuje_sie_na_separatorze() {
        ze_stanem!(|app| {
            for _ in 0..40 {
                handle_key(klawisz(KeyCode::Down), &mut app);
                assert!(
                    !app.selections[app.selected_index].0.contains("───"),
                    "Kursor stanął na separatorze (indeks {})", app.selected_index
                );
            }
        });
    }

    // ------------------------------------------------------------------
    // ZATWIERDZENIE
    // ------------------------------------------------------------------

    /// Enter NIE uruchamia akcji samodzielnie — tylko odkłada jej indeks do
    /// stanu. Wykonaniem zajmuje się pętla główna, dzięki czemu obsługa
    /// klawiszy pozostaje czysta i testowalna.
    #[test]
    fn test_enter_zleca_akcje_o_biezacym_indeksie() {
        ze_stanem!(|app| {
            handle_key(klawisz(KeyCode::Down), &mut app);
            let wybrany = app.selected_index;

            assert!(!handle_key(klawisz(KeyCode::Enter), &mut app), "Enter nie kończy pętli");
            assert_eq!(app.action_to_execute, Some(wybrany));
        });
    }

    #[test]
    fn test_nieobslugiwany_klawisz_niczego_nie_zmienia() {
        ze_stanem!(|app| {
            let przed_indeks = app.selected_index;

            assert!(!handle_key(klawisz(KeyCode::Char('x')), &mut app));
            assert!(!handle_key(klawisz(KeyCode::Tab), &mut app));
            assert!(!handle_key(klawisz(KeyCode::F(5)), &mut app));

            assert_eq!(app.selected_index, przed_indeks);
            assert!(app.action_to_execute.is_none(), "Żaden z tych klawiszy nie zleca akcji");
        });
    }
}
