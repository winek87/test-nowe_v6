// src/tui/phase_screen.rs

//! # Komponent Ekranu Fazy
//!
//! Orkiestruje prawą stronę głównego widoku podczas działania aktywnej fazy.
//! Łączy dynamiczny nagłówek, paski postępu oraz okno logów.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::tui::state::PhaseUIState;
use crate::tui::progress::draw_progress_bars;
use crate::tui::logs_panel::draw_logs;

/// Główny orkiestrator rysowania roboczego ekranu Fazy (Zajmuje prawą stronę Dashboardu).
/// Automatycznie dzieli powierzony mu `Rect` na Nagłówek, Paski Postępu i Logi na całej szerokości.
pub fn draw_phase_screen(f: &mut Frame, state: &PhaseUIState, area: Rect) {
    let bars_height = (state.progress_bars.len() as u16) * 3;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),            // Tytuł i kategoria fazy
            Constraint::Length(bars_height),  // Paski postępu
            Constraint::Min(10),              // Okno logów operacyjnych (reszta miejsca)
        ])
        .split(area);

    draw_header(f, state, chunks[0]);
    
    if bars_height > 0 { 
        draw_progress_bars(f, state, chunks[1]); 
    }
    
    // Logi zajmują całą szerokość prawej strony ekranu
    draw_logs(f, state, chunks[2]);
}

// --- KOMPONENT Wewnętrzny: NAGŁÓWEK FAZY ---
fn draw_header(f: &mut Frame, state: &PhaseUIState, area: Rect) {
    let text = vec![
        Line::from(vec![
            Span::styled(format!("{} ", state.icon), Style::default().fg(Color::Cyan)),
            Span::styled(&state.title, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Kategoria: ", Style::default().fg(Color::Yellow)),
            Span::raw(&state.category),
        ]),
        Line::from(vec![
            Span::styled(&state.description, Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Informacje o Fazie ");

    let paragraph = Paragraph::new(text).block(block);
    f.render_widget(paragraph, area);
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::{PhaseEvent, PhaseUIState};
    use ratatui::{backend::TestBackend, style::Color, Terminal};

    fn ekran(bufor: &ratatui::buffer::Buffer) -> String {
        (0..bufor.area.height)
            .map(|y| (0..bufor.area.width).map(|x| bufor[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn wyrenderuj(szer: u16, wys: u16, state: &PhaseUIState) -> String {
        let mut terminal = Terminal::new(TestBackend::new(szer, wys)).unwrap();
        terminal.draw(|f| { let obszar = f.area(); draw_phase_screen(f, state, obszar); }).unwrap();
        ekran(terminal.backend().buffer())
    }

    fn stan_z_paskiem(current: u64, total: u64) -> PhaseUIState {
        let mut s = PhaseUIState::new("🔍", "Faza 03 Hashowanie", "Kryptografia", "Liczy sumy BLAKE3");
        s.process_event(PhaseEvent::SetBar { idx: 0, label: "UFS".into(), total, color: Color::Green });
        s.process_event(PhaseEvent::UpdateBar { idx: 0, current, message: "plik.bin".into() });
        s
    }

    #[test]
    fn test_naglowek_pokazuje_tytul_fazy() {
        let widok = wyrenderuj(100, 20, &stan_z_paskiem(0, 100));
        assert!(widok.contains("Faza 03"), "Brak tytułu fazy:\n{}", widok);
    }

    #[test]
    fn test_pasek_pokazuje_etykiete_i_komunikat() {
        let widok = wyrenderuj(100, 20, &stan_z_paskiem(42, 100));
        assert!(widok.contains("UFS"), "Brak etykiety paska:\n{}", widok);
        assert!(widok.contains("plik.bin"), "Brak bieżącego komunikatu:\n{}", widok);
    }

    /// Pasek z zerową całością to realny przypadek: faza zakłada pasek, zanim
    /// policzy, ile plików ma przerobić. Dzielenie przez zero w liczeniu
    /// proporcji wywróciłoby cały interfejs.
    #[test]
    fn test_pasek_o_zerowej_calosci_nie_wywraca_renderu() {
        let _ = wyrenderuj(100, 20, &stan_z_paskiem(0, 0));
    }

    /// Licznik większy od całości zdarza się, gdy faza doliczy pliki w trakcie
    /// pracy. Ratatui panikuje przy proporcji spoza zakresu 0..=1.
    #[test]
    fn test_licznik_wiekszy_od_calosci_nie_wywraca_renderu() {
        let _ = wyrenderuj(100, 20, &stan_z_paskiem(500, 100));
    }

    #[test]
    fn test_wiele_paskow_naraz() {
        let mut s = PhaseUIState::new("🔍", "Faza", "Kat", "Opis");
        s.process_event(PhaseEvent::SetBar { idx: 0, label: "UFS".into(), total: 10, color: Color::Green });
        s.process_event(PhaseEvent::SetBar { idx: 1, label: "SKRYPT".into(), total: 20, color: Color::Blue });

        let widok = wyrenderuj(100, 25, &s);
        assert!(widok.contains("UFS"), "Brak pierwszego paska:\n{}", widok);
        assert!(widok.contains("SKRYPT"), "Brak drugiego paska:\n{}", widok);
    }

    #[test]
    fn test_render_bez_zadnego_paska_nie_panikuje() {
        let s = PhaseUIState::new("🔍", "Faza", "Kat", "Opis");
        let _ = wyrenderuj(100, 20, &s);
    }

    #[test]
    fn test_render_nie_panikuje_na_skrajnych_rozmiarach() {
        let s = stan_z_paskiem(5, 10);
        for (szer, wys) in [(1u16, 1u16), (10, 3), (30, 6), (200, 60)] {
            let _ = wyrenderuj(szer, wys, &s);
        }
    }
}
