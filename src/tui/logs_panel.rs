// src/tui/logs_panel.rs

//! # Komponent Dziennika (Logi Operacyjne)
//! 
//! Odpowiada wyłącznie za renderowanie okna logów (zdarzeń systemowych).
//! Wyodrębniony z głównego pliku UI, aby ułatwić zarządzanie i czytelność.

use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::Span,
    widgets::{Block, Borders, List, ListItem},
    Frame,
};

// Zakładamy, że po refaktoryzacji stan UI znajdzie się w module `state`
use crate::tui::state::PhaseUIState;

/// Rysuje historyczne logi w formie listy. 
/// Samodzielnie oblicza wcięcia i potrafi zawijać długie ciągi znaków 
/// (Intelligent Word-Wrap), aby uniknąć obcinania ważnych informacji.
pub fn draw_logs(f: &mut Frame, state: &PhaseUIState, area: Rect) {
    let max_width = area.width.saturating_sub(4).max(1) as usize; 
    let mut display_lines = Vec::new();

    for log in &state.logs {
        // Koloryzujemy logi na podstawie ich zawartości (Heurystyka)
        let style = if log.contains("BŁĄD") || log.contains("Odrzucono") || log.contains("Brak") {
            Style::default().fg(Color::Red)
        } else if log.contains("✔") || log.contains("Sukces") || log.contains("Zakończono") {
            Style::default().fg(Color::Green)
        } else if log.contains("⚠") || log.contains("Ostrzeżenie") || log.contains("Puste") {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::Gray)
        };

        let mut current_line = String::new();
        let mut current_width = 0;

        // Zaawansowany algorytm zawijania tekstu, uwzględniający dwukomórkowe znaki Unicode
        for c in log.chars() {
            let char_width = if c as u32 > 0x2000 { 2 } else { 1 };
            
            if current_width + char_width > max_width {
                display_lines.push(ListItem::new(Span::styled(current_line.clone(), style)));
                
                // Nowa linia tworzy 4 spacje wcięcia dla przejrzystości drzewka logów
                current_line = String::from("    "); 
                current_width = 4;
            }
            current_line.push(c);
            current_width += char_width;
        }
        if !current_line.is_empty() {
            display_lines.push(ListItem::new(Span::styled(current_line, style)));
        }
    }

    // Wyliczamy, ile linii można wyświetlić i tniemy początek (Auto-Scroll do dołu)
    let visible_lines = area.height.saturating_sub(2) as usize;
    let start_idx = if display_lines.len() > visible_lines {
        display_lines.len() - visible_lines
    } else {
        0
    };

    let list = List::new(display_lines[start_idx..].to_vec())
        .block(Block::default()
            .borders(Borders::ALL)
            .title(" Logi Operacyjne (Auto-Scroll) ")
            .border_style(Style::default().fg(Color::DarkGray)));

    f.render_widget(list, area);
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::{PhaseEvent, PhaseUIState};
    use ratatui::{backend::TestBackend, Terminal};

    fn ekran(bufor: &ratatui::buffer::Buffer) -> String {
        (0..bufor.area.height)
            .map(|y| (0..bufor.area.width).map(|x| bufor[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn wyrenderuj(szer: u16, wys: u16, state: &PhaseUIState) -> String {
        let mut terminal = Terminal::new(TestBackend::new(szer, wys)).unwrap();
        terminal.draw(|f| { let obszar = f.area(); draw_logs(f, state, obszar); }).unwrap();
        ekran(terminal.backend().buffer())
    }

    fn stan_z_logami(ile: usize) -> PhaseUIState {
        let mut s = PhaseUIState::new("🔍", "Faza", "Kategoria", "Opis");
        for i in 0..ile {
            s.process_event(PhaseEvent::Log(format!("wpis numer {}", i)));
        }
        s
    }

    #[test]
    fn test_pusty_panel_nie_panikuje() {
        let s = PhaseUIState::new("🔍", "Faza", "Kategoria", "Opis");
        let _ = wyrenderuj(80, 20, &s);
    }

    #[test]
    fn test_logi_sa_widoczne() {
        let widok = wyrenderuj(80, 20, &stan_z_logami(3));
        assert!(widok.contains("wpis numer 0"), "Brak pierwszego wpisu:\n{}", widok);
        assert!(widok.contains("wpis numer 2"), "Brak ostatniego wpisu:\n{}", widok);
    }

    /// Sedno panelu logów: przy nadmiarze wpisów operator ma widzieć NAJNOWSZE.
    /// Gdyby panel pokazywał początek listy, w trwającej fazie widok stałby w
    /// miejscu przy pierwszych wpisach.
    #[test]
    fn test_przy_nadmiarze_widac_najnowsze_wpisy() {
        let widok = wyrenderuj(80, 10, &stan_z_logami(100));

        assert!(widok.contains("wpis numer 99"), "Najnowszy wpis musi być widoczny:\n{}", widok);
        assert!(!widok.contains("wpis numer 0 "), "Najstarszy wpis nie mieści się w oknie:\n{}", widok);
    }

    #[test]
    fn test_dlugi_wpis_nie_wywraca_renderu() {
        let mut s = PhaseUIState::new("🔍", "Faza", "Kategoria", "Opis");
        s.process_event(PhaseEvent::Log("x".repeat(5000)));
        let _ = wyrenderuj(80, 20, &s);
    }

    #[test]
    fn test_polskie_znaki_w_logach_nie_wywracaja_renderu() {
        let mut s = PhaseUIState::new("🔍", "Faza", "Kategoria", "Opis");
        s.process_event(PhaseEvent::Log("zażółć gęślą jaźń — ✔ 🚀".to_string()));
        let widok = wyrenderuj(80, 10, &s);
        assert!(widok.contains("zażółć"), "Polskie znaki muszą się renderować:\n{}", widok);
    }

    #[test]
    fn test_render_nie_panikuje_na_skrajnych_rozmiarach() {
        let s = stan_z_logami(50);
        for (szer, wys) in [(1u16, 1u16), (5, 2), (20, 3), (200, 60)] {
            let _ = wyrenderuj(szer, wys, &s);
        }
    }
}
