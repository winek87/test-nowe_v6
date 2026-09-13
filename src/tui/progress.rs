// src/tui/progress.rs

//! # Komponent Pasków Postępu (Gauges)
//!
//! Renderuje dynamiczne paski postępu dla aktywnych zadań w fazie roboczej.
//! Obsługuje zarówno paski ze znanym limitem końcowym (standardowe),
//! jak i paski pulsujące (tryb pre-scan / infinite).
//!
//! UWAGA ARCHITEKTONICZNA: Ten komponent celowo NIE wyświetla już rozbudowanych
//! statystyk live (MB/s, top rozszerzenia, liczniki anomalii). Te dane trafiają
//! do panelu bocznego `scanner_panel::draw_side_stats_panel` poprzez
//! `PhaseEvent::UpdateSideText`. Pasek pokazuje wyłącznie postęp i bieżący plik,
//! ponieważ widget `Gauge` w Ratatui nie zawija tekstu wielowierszowego.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Gauge},
    Frame,
};

use crate::tui::state::PhaseUIState;

/// Maksymalna długość segmentu ścieżki pliku pokazywanego w etykiecie paska.
/// Zabezpiecza przed urwaniem etykiety przez zbyt długie ścieżki I/O.
const MAX_LABEL_PATH_LEN: usize = 48;

/// Wyciąga z `message` sam ogon (nazwę/ścieżkę pliku), odrzucając ewentualne
/// wcześniejsze segmenty statystyk oddzielone znakiem nowej linii lub strzałką "👉".
/// Działa poprawnie zarówno dla już przepisanych faz (message = sama ścieżka),
/// jak i dla faz jeszcze nieprzepisanych (message = pełny blok statystyk),
/// dzięki czemu pasek nigdy nie wyświetli urwanego wielowierszowego tekstu.
fn extract_display_segment(message: &str) -> String {
    let tail = message
        .rsplit("👉")
        .next()
        .unwrap_or(message)
        .lines()
        .next_back()
        .unwrap_or(message)
        .trim();

    let chars: Vec<char> = tail.chars().collect();
    if chars.len() > MAX_LABEL_PATH_LEN {
        let half = (MAX_LABEL_PATH_LEN.saturating_sub(3)) / 2;
        if half == 0 { return tail.to_string(); }
        let start: String = chars[..half].iter().collect();
        let end: String = chars[chars.len() - half..].iter().collect();
        format!("{}...{}", start, end)
    } else {
        tail.to_string()
    }
}

/// Wysokość pojedynczego paska postępu w wierszach: górne obramowanie, treść,
/// dolne obramowanie.
const WYSOKOSC_PASKA: u16 = 3;

/// Rysuje ułożone pionowo paski postępu na podstawie danych napływających ze
/// stanu UI, nigdy nie przekraczając pojemności okna (patrz kod poniżej).
pub fn draw_progress_bars(f: &mut Frame, state: &PhaseUIState, area: Rect) {
    // Ile pasków FIZYCZNIE mieści się w oknie. Każdy zajmuje 3 wiersze
    // (obramowanie + treść + obramowanie), więc pojemność to prosta arytmetyka.
    //
    // Bez tego ograniczenia liczba pasków rosła z liczbą wątków, a ograniczenia
    // układu sumowały się ponad wysokość obszaru. Po skurczeniu terminala
    // kończyło się to rysowaniem po obszarze o zerowej wysokości. Paski, które
    // się nie mieszczą, po prostu nie są rysowane - to jedyne sensowne
    // zachowanie, bo nie ma ich gdzie pokazać.
    let pojemnosc = (area.height / WYSOKOSC_PASKA) as usize;
    if pojemnosc == 0 {
        return;
    }

    let widoczne: Vec<&crate::tui::state::ProgressBarState> =
        state.progress_bars.iter().take(pojemnosc).collect();

    let constraints: Vec<Constraint> = widoczne.iter().map(|_| Constraint::Length(WYSOKOSC_PASKA)).collect();
    let bar_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    for (i, bar_state) in widoczne.into_iter().enumerate() {
        let display_segment = extract_display_segment(&bar_state.message);

        let (ratio, label) = if bar_state.total > 0 {
            // STANDARDOWY PASEK (Znamy końcowy limit)
            let r = (bar_state.current as f64 / bar_state.total as f64).clamp(0.0, 1.0);
            let pct = (r * 100.0) as u32;
            let l = format!("{} [{}/{}] ({}%) — {}", bar_state.label, bar_state.current, bar_state.total, pct, display_segment);
            (r, l)
        } else {
            // TRYB PRE-SCAN (Nie znamy limitu)
            // Pasek pulsuje, odświeżając postęp jako wskaźnik aktywności
            let r = ((bar_state.current % 5000) as f64 / 5000.0).clamp(0.0, 1.0);
            let l = format!("{} [Przeskanowano: {}] — {}", bar_state.label, bar_state.current, display_segment);
            (r, l)
        };

        let gauge = Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(bar_state.label.clone())
                    .border_style(Style::default().fg(Color::DarkGray))
            )
            .gauge_style(Style::default().fg(bar_state.color).bg(Color::Rgb(40, 40, 40)))
            .ratio(ratio)
            .label(Span::styled(label, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)));

        f.render_widget(gauge, bar_chunks[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::ProgressBarState;
    use ratatui::{backend::TestBackend, Terminal};

    fn pasek(nazwa: &str) -> ProgressBarState {
        ProgressBarState {
            label: nazwa.to_string(),
            current: 40,
            total: 100,
            message: format!("plik z {}", nazwa),
            color: Color::Green,
        }
    }

    fn stan(ile: usize) -> PhaseUIState {
        let mut st = PhaseUIState::new("x", "t", "k", "o");
        st.progress_bars = (0..ile).map(|i| pasek(&format!("W{}", i))).collect();
        st
    }

    fn ekran(szer: u16, wys: u16, st: &PhaseUIState) -> String {
        let mut terminal = Terminal::new(TestBackend::new(szer, wys)).unwrap();
        terminal.draw(|f| draw_progress_bars(f, st, f.area())).unwrap();
        let bufor = terminal.backend().buffer().clone();
        (0..bufor.area.height)
            .map(|y| (0..bufor.area.width).map(|x| bufor[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Sedno punktu 3: liczba pasków rośnie z liczbą wątków, a wysokość okna
    /// nie — rysujemy tylko tyle, ile fizycznie się mieści.
    #[test]
    fn test_liczba_paskow_nie_przekracza_pojemnosci_okna() {
        let st = stan(32);

        // Okno na 3 paski (9 wierszy) przy 32 zgłoszonych.
        let widok = ekran(80, 9, &st);

        assert!(widok.contains("W0") && widok.contains("W2"), "mieszczące się paski muszą być widoczne:\n{}", widok);
        assert!(
            !widok.contains("W5"),
            "pasek, który się nie mieści, nie może być rysowany:\n{}", widok
        );
    }

    #[test]
    fn test_brak_paniki_przy_wielu_paskach_i_malym_oknie() {
        let st = stan(64);
        for (szer, wys) in [(80u16, 1u16), (80, 2), (80, 3), (40, 6), (10, 9), (1, 1), (200, 5)] {
            let _ = ekran(szer, wys, &st);
        }
    }

    #[test]
    fn test_okno_ponizej_jednego_paska_nic_nie_rysuje() {
        // Mniej niż 3 wiersze to zero pojemności - funkcja musi wyjść od razu,
        // zamiast rysować po obszarze o zerowej wysokości.
        let widok = ekran(80, 2, &stan(4));
        assert!(!widok.contains("W0"), "przy zerowej pojemności nic nie może zostać narysowane:\n{}", widok);
    }

    #[test]
    fn test_pusta_lista_paskow_nie_panikuje() {
        let _ = ekran(80, 20, &stan(0));
    }
}

