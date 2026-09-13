// src/tui/dng_repair_screen.rs

//! # Komponent Ekranu: Składanie Strukturalne DNG (Pełne Ratatui)
//!
//! Renderuje ekran narzędzia w tym samym stylu wizualnym co reszta aplikacji.
//! Cała logika (stan, dostęp do bazy/dysku, decyzje) żyje w `dng_repair` —
//! ten plik WYŁĄCZNIE rysuje na podstawie przekazanego stanu.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use crate::dng_repair::{DngRepairState, Mode};

pub fn draw_dng_repair_screen(f: &mut Frame, state: &DngRepairState) {
    let area = f.area();
    match state.mode {
        Mode::ChooseMode => draw_choose_mode(f, state, area),
        Mode::Reviewing => draw_reviewing(f, state, area),
        Mode::AutoRunning => draw_auto_running(f, state, area),
        Mode::Done => draw_done(f, state, area),
    }
}

fn warning_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled("⚠ UWAGA: udane dekodowanie złożenia potwierdza WYŁĄCZNIE poprawność", Style::default().fg(Color::Yellow))),
        Line::from(Span::styled("  struktury pliku (nagłówek/IFD), NIGDY poprawność treści pikseli.", Style::default().fg(Color::Yellow))),
    ]
}

fn draw_choose_mode(f: &mut Frame, state: &DngRepairState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Length(6), Constraint::Length(2)])
        .split(area);

    let mut info = warning_lines();
    info.push(Line::from(""));
    info.push(Line::from(Span::styled(format!("Znaleziono {} plików kwalifikujących się do przeglądu.", state.tasks.len()), Style::default().fg(Color::White))));
    let info_p = Paragraph::new(info).block(Block::default().borders(Borders::ALL).title(" [ 🧩 ] Składanie Strukturalne DNG (Eksperymentalne) "));
    f.render_widget(info_p, chunks[0]);

    let options = ["Ręczny (pytaj o każdy plik) - ZALECANE", "Automatyczny (decyzja wg entropii, BEZ pytania) - RYZYKOWNE"];
    let items: Vec<ListItem> = options.iter().enumerate().map(|(i, opt)| {
        let selected = i == state.mode_selection;
        let style = if selected { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::White) };
        let prefix = if selected { " ❯ " } else { "   " };
        ListItem::new(Line::from(Span::styled(format!("{}{}", prefix, opt), style)))
    }).collect();
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(" Wybierz tryb pracy "));
    // Renderowanie STANOWE: bez `ListState` widget zaczyna zawsze od
    // pierwszego elementu, więc pozycje poniżej dolnej krawędzi są
    // nieosiągalne wzrokowo mimo działającej nawigacji.
    let mut list_state = ListState::default();
    list_state.select(Some(state.mode_selection));
    f.render_stateful_widget(list, chunks[1], &mut list_state);

    let footer = Paragraph::new(" [↑/↓] Wybór | [ENTER] Zatwierdź | [ESC] Anuluj i wróć ")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[2]);
}

fn draw_reviewing(f: &mut Frame, state: &DngRepairState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(2)])
        .split(area);

    let header_text = match state.current_task() {
        Some(task) => format!(" Plik {}/{}: {} ", state.current_task_idx + 1, state.tasks.len(), task.rel_path),
        None => " Brak zadań ".to_string(),
    };
    let header = Paragraph::new(Line::from(Span::styled(
        format!("Zaakceptowane: {}  |  Pominięte: {}", state.accepted_count, state.skipped_count),
        Style::default().fg(Color::Cyan),
    ))).block(Block::default().borders(Borders::ALL).title(header_text));
    f.render_widget(header, chunks[0]);

    let mut body = warning_lines();
    body.push(Line::from(""));

    if let Some(candidate) = state.current_candidate() {
        let n = state.current_candidates.len();
        body.push(Line::from(Span::styled(
            format!("Kandydat {}/{}: {}", state.current_candidate_idx + 1, n, candidate.description),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )));
        body.push(Line::from(vec![
            Span::styled("Wymiary: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}x{}", candidate.width, candidate.height), Style::default().fg(Color::White)),
            Span::raw("   "),
            Span::styled("Model: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:?}", candidate.camera_model), Style::default().fg(Color::White)),
        ]));
        body.push(Line::from(vec![
            Span::styled("Pewność: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:?}", candidate.confidence), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        ]));
        let plausibility_color = if candidate.plausible { Color::Green } else { Color::Red };
        let plausibility_text = if candidate.plausible { "wygląda na realny szum sensora" } else { "PODEJRZANE - zbyt niska/wysoka entropia" };
        body.push(Line::from(vec![
            Span::styled("Entropia przeniesionych danych: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:.2} bit/bajt ({})", candidate.entropy, plausibility_text), Style::default().fg(plausibility_color).add_modifier(Modifier::BOLD)),
        ]));
    } else {
        body.push(Line::from(Span::styled("Brak kandydatów dla tego pliku.", Style::default().fg(Color::DarkGray))));
    }

    let body_p = Paragraph::new(body).wrap(Wrap { trim: false }).block(Block::default().borders(Borders::ALL).title(" Szczegóły kandydata "));
    f.render_widget(body_p, chunks[1]);

    let has_multiple = state.current_candidates.len() > 1;
    let footer_text = if has_multiple {
        " [←/→] Inny kandydat | [A] Akceptuj | [P/N] Pomiń plik | [ESC] Zakończ przegląd "
    } else {
        " [A] Akceptuj | [P/N] Pomiń plik | [ESC] Zakończ przegląd "
    };
    let footer = Paragraph::new(footer_text).style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[2]);
}

fn draw_auto_running(f: &mut Frame, state: &DngRepairState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(6), Constraint::Length(2)])
        .split(area);

    let mut info = warning_lines();
    info.push(Line::from(Span::styled("TRYB AUTOMATYCZNY - decyzje wg entropii, bez pytania o każdy plik.", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))));
    let info_p = Paragraph::new(info).block(Block::default().borders(Borders::ALL).title(" [ ⚙ ] Przebieg automatyczny "));
    f.render_widget(info_p, chunks[0]);

    let current_name = state.current_task().map(|t| t.rel_path.clone()).unwrap_or_default();
    let progress = vec![
        Line::from(Span::styled(format!("Przetworzono: {}/{}", state.current_task_idx, state.tasks.len()), Style::default().fg(Color::White))),
        Line::from(Span::styled(format!("Zaakceptowano: {}", state.accepted_count), Style::default().fg(Color::Green))),
        Line::from(Span::styled(format!("Pominięto: {}", state.skipped_count), Style::default().fg(Color::Yellow))),
        Line::from(""),
        Line::from(Span::styled(format!("Aktualnie: {}", current_name), Style::default().fg(Color::Cyan))),
    ];
    let progress_p = Paragraph::new(progress).block(Block::default().borders(Borders::ALL).title(" Postęp "));
    f.render_widget(progress_p, chunks[1]);

    let footer = Paragraph::new(" [ESC] Przerwij ").style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[2]);
}

fn draw_done(f: &mut Frame, state: &DngRepairState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(2)])
        .split(area);

    let mut lines = vec![
        Line::from(Span::styled("✔ Przegląd zakończony.", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(format!("Zaakceptowano: {}", state.accepted_count)),
        Line::from(format!("Pominięto: {}", state.skipped_count)),
        Line::from(format!("Tryb: {}", if state.auto_mode { "AUTOMATYCZNY" } else { "RĘCZNY" })),
        Line::from(""),
        Line::from(Span::styled("Zaakceptowane pliki leżą w katalogu przeglądowym - NIE zostały", Style::default().fg(Color::DarkGray))),
        Line::from(Span::styled("automatycznie użyte w Złotej Kopii. Przenieś je ręcznie po weryfikacji.", Style::default().fg(Color::DarkGray))),
    ];
    if let Some(path) = &state.log_path {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Dziennik decyzji: {}", path.display())));
    }

    let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(Block::default().borders(Borders::ALL).title(" Podsumowanie "));
    f.render_widget(p, chunks[0]);

    let footer = Paragraph::new(" [ENTER] / [ESC] Wróć do podmenu ").style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[1]);
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dng_repair::{DisplayCandidate, ReviewTask};
    use crate::dng_splice::SpliceConfidence;
    use ratatui::{backend::TestBackend, Terminal};

    fn ekran(bufor: &ratatui::buffer::Buffer) -> String {
        (0..bufor.area.height)
            .map(|y| (0..bufor.area.width).map(|x| bufor[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn wyrenderuj(szer: u16, wys: u16, state: &DngRepairState) -> String {
        let mut terminal = Terminal::new(TestBackend::new(szer, wys)).unwrap();
        terminal.draw(|f| draw_dng_repair_screen(f, state)).unwrap();
        ekran(terminal.backend().buffer())
    }

    fn zadania() -> Vec<ReviewTask> {
        vec![
            ReviewTask { id: 1, rel_path: "zdjecia/DSC_0001.dng".to_string() },
            ReviewTask { id: 2, rel_path: "zdjecia/DSC_0002.dng".to_string() },
        ]
    }

    fn kandydat(plausible: bool, entropy: f64) -> DisplayCandidate {
        DisplayCandidate {
            bytes: vec![0u8; 32],
            description: "nagłówek z UFS + dane ze Skryptu".to_string(),
            confidence: SpliceConfidence::StructuralOnly,
            entropy,
            plausible,
            width: 6000,
            height: 4000,
            camera_model: Some("NIKON D850".to_string()),
        }
    }

    // ------------------------------------------------------------------
    // EKRAN WYBORU TRYBU
    // ------------------------------------------------------------------

    #[test]
    fn test_ekran_wyboru_trybu_pokazuje_obie_opcje() {
        let state = DngRepairState::new(zadania());
        let widok = wyrenderuj(120, 30, &state);

        assert!(
            widok.to_lowercase().contains("ręczn") || widok.to_lowercase().contains("reczn"),
            "Brak trybu ręcznego:\n{}", widok
        );
        assert!(
            widok.to_lowercase().contains("automat"),
            "Brak trybu automatycznego:\n{}", widok
        );
    }

    #[test]
    fn test_zaznaczenie_trybu_zmienia_obraz() {
        let mut state = DngRepairState::new(zadania());
        let pierwszy = wyrenderuj(120, 30, &state);

        state.mode_selection = 1;
        let drugi = wyrenderuj(120, 30, &state);

        assert_ne!(pierwszy, drugi, "Przesunięcie zaznaczenia musi być widoczne");
    }

    // ------------------------------------------------------------------
    // PRZEGLĄD RĘCZNY
    // ------------------------------------------------------------------

    #[test]
    fn test_przeglad_pokazuje_sciezke_i_opis_kandydata() {
        let mut state = DngRepairState::new(zadania());
        state.mode = Mode::Reviewing;
        state.current_candidates = vec![kandydat(true, 5.2)];

        let widok = wyrenderuj(140, 35, &state);

        assert!(widok.contains("DSC_0001"), "Brak nazwy przeglądanego pliku:\n{}", widok);
        assert!(widok.contains("nagłówek z UFS"), "Brak opisu kandydata:\n{}", widok);
    }

    /// Gwarancja przy składaniu strukturalnym jest SŁABA i operator musi to
    /// widzieć PRZED akceptacją — to cała stawka tego ekranu.
    #[test]
    fn test_przeglad_melduje_slabosc_gwarancji() {
        let mut state = DngRepairState::new(zadania());
        state.mode = Mode::Reviewing;
        state.current_candidates = vec![kandydat(true, 5.2)];

        let widok = wyrenderuj(140, 35, &state);

        assert!(
            widok.contains("SŁAB") || widok.contains("struktur"),
            "Ekran musi jasno mówić, że dowód dotyczy struktury, nie treści:\n{}", widok
        );
    }

    /// Kandydat nieplauzybilny musi wyglądać inaczej niż plauzybilny —
    /// inaczej operator zaakceptowałby obszar zer jako odzyskane zdjęcie.
    #[test]
    fn test_kandydat_nieplauzybilny_wyglada_inaczej() {
        let mut state = DngRepairState::new(zadania());
        state.mode = Mode::Reviewing;

        state.current_candidates = vec![kandydat(true, 5.2)];
        let plauzybilny = wyrenderuj(140, 35, &state);

        state.current_candidates = vec![kandydat(false, 0.1)];
        let nieplauzybilny = wyrenderuj(140, 35, &state);

        assert_ne!(
            plauzybilny, nieplauzybilny,
            "Ocena plauzybilności musi być widoczna na ekranie"
        );
    }

    #[test]
    fn test_przeglad_bez_kandydatow_nie_panikuje() {
        let mut state = DngRepairState::new(zadania());
        state.mode = Mode::Reviewing;
        state.current_candidates = Vec::new();

        let _ = wyrenderuj(140, 35, &state);
    }

    // ------------------------------------------------------------------
    // TRYB AUTOMATYCZNY I PODSUMOWANIE
    // ------------------------------------------------------------------

    #[test]
    fn test_tryb_automatyczny_pokazuje_postep() {
        let mut state = DngRepairState::new(zadania());
        state.mode = Mode::AutoRunning;
        state.auto_mode = true;
        state.current_task_idx = 1;
        state.accepted_count = 1;

        let widok = wyrenderuj(140, 35, &state);
        assert!(!widok.trim().is_empty(), "Ekran automatu nie może być pusty");
    }

    #[test]
    fn test_podsumowanie_pokazuje_liczniki() {
        let mut state = DngRepairState::new(zadania());
        state.mode = Mode::Done;
        state.accepted_count = 7;
        state.skipped_count = 3;

        let widok = wyrenderuj(140, 35, &state);

        assert!(widok.contains('7'), "Brak liczby przyjętych:\n{}", widok);
        assert!(widok.contains('3'), "Brak liczby pominiętych:\n{}", widok);
    }

    #[test]
    fn test_podsumowanie_dla_pustej_listy_nie_panikuje() {
        let mut state = DngRepairState::new(Vec::new());
        state.mode = Mode::Done;
        let _ = wyrenderuj(140, 35, &state);
    }

    // ------------------------------------------------------------------
    // ODPORNOŚĆ
    // ------------------------------------------------------------------

    #[test]
    fn test_render_nie_panikuje_na_skrajnych_rozmiarach() {
        let mut state = DngRepairState::new(zadania());
        state.current_candidates = vec![kandydat(true, 5.2)];

        for tryb in [Mode::ChooseMode, Mode::Reviewing, Mode::AutoRunning, Mode::Done] {
            state.mode = tryb;
            for (szer, wys) in [(1u16, 1u16), (20, 5), (40, 10), (200, 60)] {
                let _ = wyrenderuj(szer, wys, &state);
            }
        }
    }
}
