// src/tui/dashboard.rs

//! # Komponent Głównego Menu (Dashboard)
//!
//! Zastępuje dawny plik `src/menu/ui.rs`. Scala sprzęt, dyski, konfigurację
//! i interaktywną listę opcji w jeden główny ekran powitalny.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::menu::state::AppState;
use crate::tui::hardware_panel::{draw_disks_panel, draw_hw_panel, draw_paths_panel};

/// Główna funkcja rysująca cały dashboard Ratatui (Menu Główne)
pub fn draw_dashboard(f: &mut Frame, app: &AppState) {
    let size = f.area();

    // Definiowanie głównych stref ekranu (Siatka układu)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // 0: Tytuł
            Constraint::Length(3),  // 1: Zasoby systemowe (CPU/RAM)
            Constraint::Length(8),  // 2: Tablica Dysków
            Constraint::Length(10), // 3: Ścieżki i Parametry (7 stałych linii + 1 warunkowa "DNG do przeglądu" + obramowanie)
            // Menu: `Min(0)`, nie `Min(13)`. Sztywny próg powodował, że na
            // niskim terminalu suma ograniczeń przekraczała wysokość ekranu.
            // Przy `Min(0)` lista kompresuje się do dostępnego miejsca, a
            // przewijanie (patrz `ListState` niżej) i tak utrzymuje zaznaczony
            // element w polu widzenia.
            Constraint::Min(0),     // 4: Lista Menu
            Constraint::Length(1),  // 5: Stopka (Instrukcje)
        ])
        .split(size);

    // --- 0: TYTUŁ ---
    let title_block = Block::default()
        .borders(Borders::ALL)
        .title(" [ 🔍 ] WERYFIKATOR KRYMINALISTYCZNY (Advanced File Carving) ")
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(title_block, chunks[0]);

    // --- 1: ZASOBY SYSTEMOWE (CPU/RAM) ---
    draw_hw_panel(f, app, chunks[1]);

    // --- 2: TABELA DYSKÓW FIZYCZNYCH ---
    draw_disks_panel(f, app, chunks[2]);

    // --- 3: KONFIGURACJA ŚRODOWISKA ---
    draw_paths_panel(f, app, chunks[3]);

    // --- 4: MENU LISTA WYBORU ---
    let items: Vec<ListItem> = app.selections.iter().enumerate().map(|(idx, (title, desc))| {
        let is_selected = idx == app.selected_index;
        
        let style = if is_selected {
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        } else if title.contains("───") {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        };

        let content = if is_selected {
            if desc.is_empty() {
                format!(" ❯ {}", title)
            } else {
                format!(" ❯ {} - {}", title, desc)
            }
        } else {
            format!("   {}", title)
        };

        ListItem::new(content).style(style)
    }).collect();

    let menu_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Wybierz moduł do uruchomienia "));

    // Lista MUSI być renderowana stanowo. `render_widget` rysuje widget
    // bezstanowy, który zawsze zaczyna od pierwszego elementu - pozycje poniżej
    // dolnej krawędzi były nieosiągalne wzrokowo mimo działającej nawigacji
    // strzałkami. `ListState` przekazuje Ratatui zaznaczenie, a silnik sam
    // przesuwa offset widoku tak, żeby zaznaczony element był widoczny.
    let mut list_state = ListState::default();
    list_state.select(Some(app.selected_index));
    f.render_stateful_widget(menu_list, chunks[4], &mut list_state);

    // --- 5: STOPKA ---
    let footer = Paragraph::new(" [↑/↓] Nawigacja | [ENTER] Wybierz | [Ctrl+C] lub [Q] Wyjście z programu ")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    f.render_widget(footer, chunks[5]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::menu::state::AppState;
    use crate::settings::Ustawienia;
    use ratatui::{backend::TestBackend, Terminal};

    fn ekran(bufor: &ratatui::buffer::Buffer) -> String {
        (0..bufor.area.height)
            .map(|y| (0..bufor.area.width).map(|x| bufor[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn wyrenderuj(szer: u16, wys: u16, zaznaczony: usize) -> String {
        let mut u = Ustawienia::default();
        let mut app = AppState::new(&mut u).expect("stan menu musi się zbudować");
        app.selected_index = zaznaczony;

        let mut terminal = Terminal::new(TestBackend::new(szer, wys)).unwrap();
        terminal.draw(|f| draw_dashboard(f, &app)).unwrap();
        ekran(terminal.backend().buffer())
    }

    /// Sedno punktu 2: pozycja z KOŃCA listy musi być widoczna po zaznaczeniu.
    ///
    /// Przy renderowaniu bezstanowym widget zawsze zaczyna od elementu 0, więc
    /// przy 26 pozycjach menu i kilkunastu wierszach miejsca ostatnie pozycje
    /// były nieosiągalne wzrokowo, mimo że nawigacja strzałkami działała.
    #[test]
    fn test_menu_przewija_do_zaznaczonej_pozycji_na_koncu_listy() {
        let mut u = Ustawienia::default();
        let app = AppState::new(&mut u).unwrap();
        let ostatni = app.selections.len() - 1;
        let (etykieta_ostatniej, _) = app.selections[ostatni];
        let (etykieta_pierwszej, _) = app.selections[0];
        drop(app);

        // Porównujemy po znakach alfanumerycznych, bo w buforze dochodzą
        // odstępy układu i podwójna szerokość emoji - normalizujemy OBIE
        // strony, inaczej test mierzyłby formatowanie, a nie widoczność.
        let znormalizuj = |s: &str| s.chars().filter(|c| c.is_alphanumeric()).collect::<String>();
        let fragment = |s: &str| znormalizuj(s).chars().take(12).collect::<String>();

        let widok_gora = wyrenderuj(120, 40, 0);
        assert!(
            znormalizuj(&widok_gora).contains(&fragment(etykieta_pierwszej)),
            "przy zaznaczeniu 0 pierwsza pozycja musi być widoczna:\n{}", widok_gora
        );

        let widok_dol = wyrenderuj(120, 40, ostatni);
        assert!(
            znormalizuj(&widok_dol).contains(&fragment(etykieta_ostatniej)),
            "po zaznaczeniu OSTATNIEJ pozycji ({}) musi ona wjechać w pole widzenia:\n{}",
            etykieta_ostatniej, widok_dol
        );

        // Kontrola sensu testu: przy zaznaczeniu 0 ostatnia pozycja NIE MOŻE
        // być widoczna - inaczej lista mieści się w całości i test niczego
        // nie mierzy.
        assert!(
            !znormalizuj(&widok_gora).contains(&fragment(etykieta_ostatniej)),
            "lista mieści się w całości - test nie mierzy przewijania:\n{}", widok_gora
        );
    }

    /// Sedno punktu 3: brak paniki przy skurczonym oknie.
    ///
    /// Suma sztywnych ograniczeń wysokości (1+3+8+10+13+1 = 36) przekraczała
    /// wysokość niskiego terminala. Lista menu ma teraz `Min(0)`, więc
    /// kompresuje się zamiast wypychać układ poza ekran.
    #[test]
    fn test_dashboard_nie_panikuje_na_niskim_terminalu() {
        for (szer, wys) in [(120u16, 40u16), (120, 24), (120, 12), (80, 8), (40, 5), (20, 3), (10, 1)] {
            let _ = wyrenderuj(szer, wys, 0);
        }
    }
}

