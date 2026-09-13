// src/tui/settings_screen.rs

//! # Komponent Ekranu Ustawień (Pełne Ratatui)
//!
//! Renderuje ekran ustawień w tym samym stylu wizualnym co reszta aplikacji
//! (lista nawigowana ↑/↓/Enter, identyczna stylistyka co `dashboard.rs`).
//! Cała logika (stan, walidacja, obsługa klawiszy) żyje w
//! `menu::settings_actions` — ten plik WYŁĄCZNIE rysuje na podstawie
//! przekazanego stanu, bez żadnej mutacji.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::menu::settings_actions::{
    choice_options, get_display_value, get_report_value, sorted_phase_keys, EditMode, PasswordStage,
    Screen, SettingsUiState, FIELD_LABELS, REPORT_FIELD_LABELS,
};
use crate::settings::Ustawienia;

// ============================================================================
// PUNKT WEJŚCIA
// ============================================================================

/// Rysuje cały ekran ustawień: aktualny poziom nawigacji (`state.screen`)
/// jako tło, plus ewentualną aktywną nakładkę edycji (`state.edit`) na wierzchu.
pub fn draw_settings_screen(f: &mut Frame, state: &SettingsUiState, u: &Ustawienia) {
    let area = f.area();

    match &state.screen {
        Screen::Main => draw_main_list(f, state, u, area),
        Screen::Reports { selected } => draw_reports_list(f, u, *selected, area),
        Screen::ReportsEdit { phase, selected } => draw_reports_edit(f, u, phase, *selected, area),
    }

    match &state.edit {
        EditMode::None => {}
        EditMode::Text { buffer, cursor, error, .. } => draw_text_popup(f, area, "Edycja wartości", buffer, *cursor, error.as_deref(), false),
        EditMode::Choice { idx, selected } => draw_choice_popup(f, area, *idx, *selected),
        EditMode::Password { stage, old_buf, new_buf, confirm_buf, error } => {
            draw_password_popup(f, area, *stage, old_buf, new_buf, confirm_buf, error.as_deref())
        }
    }
}

// ============================================================================
// EKRAN GŁÓWNY (LISTA PÓL)
// ============================================================================

fn draw_main_list(f: &mut Frame, state: &SettingsUiState, u: &Ustawienia, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(2)])
        .split(area);

    let last_idx = FIELD_LABELS.len() - 1;
    let items: Vec<ListItem> = FIELD_LABELS.iter().enumerate().map(|(i, label)| {
        let is_selected = i == state.selected_main;
        let is_back = i == last_idx;
        let value = if is_back { String::new() } else { get_display_value(u, i) };

        let label_style = if is_selected {
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        } else if is_back {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Cyan)
        };
        let value_style = if is_selected {
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Yellow)
        };

        let prefix = if is_selected { " ❯ " } else { "   " };
        let line = if value.is_empty() {
            Line::from(vec![Span::styled(format!("{}{}", prefix, label), label_style)])
        } else {
            Line::from(vec![
                Span::styled(format!("{}{:<48}", prefix, label), label_style),
                Span::styled(value, value_style),
            ])
        };

        ListItem::new(line)
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" [ 🧰 ] USTAWIENIA I KONFIGURACJA "));
    // Renderowanie STANOWE: bez `ListState` widget zaczyna zawsze od
    // pierwszego elementu, więc pozycje poniżej dolnej krawędzi są
    // nieosiągalne wzrokowo mimo działającej nawigacji.
    let mut list_state = ListState::default();
    list_state.select(Some(state.selected_main));
    f.render_stateful_widget(list, chunks[0], &mut list_state);

    let footer = Paragraph::new(" [↑/↓] Nawigacja | [ENTER] Edytuj/Przełącz | [ESC] Wyjdź bez zapisu tej pozycji ")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[1]);
}

// ============================================================================
// PODMENU: LISTA FAZ (RAPORTY DUAL-LOGGING)
// ============================================================================

fn draw_reports_list(f: &mut Frame, u: &Ustawienia, selected: usize, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(2)])
        .split(area);

    let keys = sorted_phase_keys(u);
    let mut items: Vec<ListItem> = keys.iter().enumerate().map(|(i, key)| {
        let is_selected = i == selected;
        let raport = &u.raporty_faz[key];
        let prefix = if is_selected { " ❯ " } else { "   " };
        let style = if is_selected { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Cyan) };

        let line = Line::from(vec![
            Span::styled(format!("{}{:<10}", prefix, key), style),
            Span::styled(format!(" Kat: {} ", raport.katalog), Style::default().fg(Color::Yellow)),
            Span::styled(format!("| Opr: {} ", raport.plik_operacyjny), Style::default().fg(Color::White)),
            Span::styled(format!("| Dz: {}", raport.plik_dziennika), Style::default().fg(Color::White)),
        ]);
        ListItem::new(line)
    }).collect();

    let is_back_selected = selected >= keys.len();
    let back_style = if is_back_selected { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Red) };
    let back_prefix = if is_back_selected { " ❯ " } else { "   " };
    items.push(ListItem::new(Line::from(Span::styled(format!("{}[ 🔙 ] Wróć do ustawień głównych", back_prefix), back_style))));

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" [ 📜 ] RAPORTY DUAL-LOGGING — WYBIERZ FAZĘ "));
    // Renderowanie STANOWE: bez `ListState` widget zaczyna zawsze od
    // pierwszego elementu, więc pozycje poniżej dolnej krawędzi są
    // nieosiągalne wzrokowo mimo działającej nawigacji.
    let mut list_state = ListState::default();
    list_state.select(Some(selected));
    f.render_stateful_widget(list, chunks[0], &mut list_state);

    let footer = Paragraph::new(" [↑/↓] Nawigacja | [ENTER] Edytuj fazę | [ESC] Wróć ")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[1]);
}

// ============================================================================
// PODMENU: EDYCJA 3 PÓL JEDNEJ FAZY
// ============================================================================

fn draw_reports_edit(f: &mut Frame, u: &Ustawienia, phase: &str, selected: usize, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(2)])
        .split(area);

    let items: Vec<ListItem> = REPORT_FIELD_LABELS.iter().enumerate().map(|(i, label)| {
        let is_selected = i == selected;
        let value = get_report_value(u, phase, i);
        let label_style = if is_selected { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Cyan) };
        let value_style = if is_selected { Style::default().fg(Color::White).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Yellow) };
        let prefix = if is_selected { " ❯ " } else { "   " };

        ListItem::new(Line::from(vec![
            Span::styled(format!("{}{:<30}", prefix, label), label_style),
            Span::styled(value, value_style),
        ]))
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(format!(" [ 📜 ] EDYCJA RAPORTU — {} ", phase)));
    // Renderowanie STANOWE: bez `ListState` widget zaczyna zawsze od
    // pierwszego elementu, więc pozycje poniżej dolnej krawędzi są
    // nieosiągalne wzrokowo mimo działającej nawigacji.
    let mut list_state = ListState::default();
    list_state.select(Some(selected));
    f.render_stateful_widget(list, chunks[0], &mut list_state);

    let footer = Paragraph::new(" [↑/↓] Nawigacja | [ENTER] Edytuj pole | [ESC] Wróć do listy faz ")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[1]);
}

// ============================================================================
// NAKŁADKI EDYCJI (POPUP)
// ============================================================================

/// Wylicza wyśrodkowany prostokąt o zadanym procencie szerokości/wysokości
/// ekranu — standardowy idiom popupów w Ratatui.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

/// Rysuje pojedynczą nakładkę tekstową: etykieta, bufor z kursorem
/// (blok `█`) rysowanym DOKŁADNIE w miejscu pozycji edycji — nie zawsze na
/// końcu, dzięki czemu Left/Right/Home/End/Delete mają widoczny efekt.
/// Opcjonalny komunikat błędu na czerwono. Gdy `masked` jest `true` (pola
/// hasła), bufor jest wyświetlany jako gwiazdki (pozycja kursora liczona
/// tak samo, bo maskowanie 1:1 zamienia znak na `*`, zachowując długość).
fn draw_text_popup(f: &mut Frame, area: Rect, title: &str, buffer: &str, cursor: usize, error: Option<&str>, masked: bool) {
    let popup_area = centered_rect(60, 20, area);
    f.render_widget(Clear, popup_area);

    let display_text = if masked { "*".repeat(buffer.chars().count()) } else { buffer.to_string() };
    let cursor_byte = display_text.char_indices().nth(cursor).map(|(b, _)| b).unwrap_or(display_text.len());
    let (before, after) = display_text.split_at(cursor_byte);

    let mut lines = vec![
        Line::from(vec![
            Span::styled(before.to_string(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled("█", Style::default().fg(Color::Yellow)),
            Span::styled(after.to_string(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
    ];
    if let Some(e) = error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(format!("⚠ {}", e), Style::default().fg(Color::Red))));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("[←/→] Ruch  [Home/End] Skrajnie  [Del] Usuń dalej  [ENTER] Zatwierdź  [ESC] Anuluj", Style::default().fg(Color::DarkGray))));

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", title))
            .border_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(paragraph, popup_area);
}

/// Rysuje nakładkę wyboru z listy opcji (np. `io_mode`, `log_level`).
fn draw_choice_popup(f: &mut Frame, area: Rect, idx: usize, selected: usize) {
    let popup_area = centered_rect(40, 30, area);
    f.render_widget(Clear, popup_area);

    let options = choice_options(idx);
    let items: Vec<ListItem> = options.iter().enumerate().map(|(i, opt)| {
        let is_selected = i == selected;
        let style = if is_selected { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::White) };
        let prefix = if is_selected { " ❯ " } else { "   " };
        ListItem::new(Line::from(Span::styled(format!("{}{}", prefix, opt), style)))
    }).collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Wybierz wartość ")
            .border_style(Style::default().fg(Color::Yellow)),
    );
    // Renderowanie STANOWE: bez `ListState` widget zaczyna zawsze od
    // pierwszego elementu, więc pozycje poniżej dolnej krawędzi są
    // nieosiągalne wzrokowo mimo działającej nawigacji.
    let mut list_state = ListState::default();
    list_state.select(Some(selected));
    f.render_stateful_widget(list, popup_area, &mut list_state);
}

/// Rysuje 3-etapową nakładkę zmiany hasła — pokazuje TYLKO pole odpowiadające
/// aktualnemu etapowi kreatora, reszta jest pusta/nieaktywna.
fn draw_password_popup(f: &mut Frame, area: Rect, stage: PasswordStage, old_buf: &str, new_buf: &str, confirm_buf: &str, error: Option<&str>) {
    let popup_area = centered_rect(60, 25, area);
    f.render_widget(Clear, popup_area);

    let (prompt, buffer) = match stage {
        PasswordStage::Old => ("Obecne hasło:", old_buf),
        PasswordStage::New => ("Nowe hasło:", new_buf),
        PasswordStage::Confirm => ("Powtórz nowe hasło:", confirm_buf),
    };
    let masked = "*".repeat(buffer.chars().count());

    let mut lines = vec![
        Line::from(Span::styled(prompt, Style::default().fg(Color::Cyan))),
        Line::from(Span::styled(format!("{}█", masked), Style::default().fg(Color::White).add_modifier(Modifier::BOLD))),
    ];
    if let Some(e) = error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(format!("⚠ {}", e), Style::default().fg(Color::Red))));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("[ENTER] Dalej   [ESC] Anuluj", Style::default().fg(Color::DarkGray))));

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Zmiana hasła administratora ")
            .border_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(paragraph, popup_area);
}

// ============================================================================
// TESTY JEDNOSTKOWE
//
// Ten plik WYŁĄCZNIE rysuje, więc testy są oparte na `TestBackend`: renderują
// ekran do bufora i sprawdzają, co operator faktycznie zobaczy. Ten sam
// wzorzec co w `tui::dashboard`.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::menu::settings_actions::{EditTarget, PasswordStage, Screen};
    use ratatui::{backend::TestBackend, Terminal};

    /// Spłaszcza bufor terminala do tekstu — tak, jak zobaczy go operator.
    fn ekran(bufor: &ratatui::buffer::Buffer) -> String {
        (0..bufor.area.height)
            .map(|y| (0..bufor.area.width).map(|x| bufor[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn wyrenderuj(szer: u16, wys: u16, state: &SettingsUiState, u: &Ustawienia) -> String {
        let mut terminal = Terminal::new(TestBackend::new(szer, wys)).unwrap();
        terminal.draw(|f| draw_settings_screen(f, state, u)).unwrap();
        ekran(terminal.backend().buffer())
    }

    fn stan_glowny(zaznaczony: usize) -> SettingsUiState {
        SettingsUiState { screen: Screen::Main, selected_main: zaznaczony, edit: EditMode::None, should_exit: false }
    }

    // ------------------------------------------------------------------
    // EKRAN GŁÓWNY
    // ------------------------------------------------------------------

    #[test]
    fn test_ekran_glowny_pokazuje_etykiety_pol() {
        let u = Ustawienia::default();
        let widok = wyrenderuj(120, 40, &stan_glowny(0), &u);

        assert!(widok.contains("Ścieżka UFS Explorer"), "Brak pierwszego pola:\n{}", widok);
        assert!(widok.contains("Poziom Logów"), "Brak pola z dalszej części listy:\n{}", widok);
    }

    /// Ostatnia pozycja listy jest wyjściem z ekranu — musi być widoczna po
    /// zaznaczeniu, inaczej operator nie ma jak zapisać ustawień. Ten sam
    /// przypadek, który był poprawiany w `dashboard`.
    #[test]
    fn test_ostatnia_pozycja_jest_widoczna_po_zaznaczeniu() {
        let u = Ustawienia::default();
        let ostatnia = FIELD_LABELS.len() - 1;
        let widok = wyrenderuj(120, 20, &stan_glowny(ostatnia), &u);

        assert!(
            widok.contains("Zapisz i wróć"),
            "Zaznaczona ostatnia pozycja musi być widoczna na ekranie:\n{}", widok
        );
    }

    #[test]
    fn test_ekran_glowny_pokazuje_wartosci_z_konfiguracji() {
        let mut u = Ustawienia::default();
        u.target_path = "/moj/wlasny/cel".to_string();
        let widok = wyrenderuj(140, 40, &stan_glowny(0), &u);

        assert!(
            widok.contains("/moj/wlasny/cel"),
            "Ekran musi pokazywać AKTUALNĄ wartość, nie domyślną:\n{}", widok
        );
    }

    /// Hasło administratora to hash BLAKE3 — nie ma prawa trafić na ekran.
    #[test]
    fn test_hash_hasla_nie_wycieka_na_ekran() {
        let u = Ustawienia::default();
        let widok = wyrenderuj(140, 40, &stan_glowny(0), &u);

        assert!(
            !widok.contains(&u.admin_password_hash),
            "Hash hasła nie może być widoczny w interfejsie:\n{}", widok
        );
    }

    // ------------------------------------------------------------------
    // PODEKRANY RAPORTÓW
    // ------------------------------------------------------------------

    #[test]
    fn test_lista_raportow_pokazuje_fazy_w_kolejnosci_numerycznej() {
        let u = Ustawienia::default();
        let state = SettingsUiState {
            screen: Screen::Reports { selected: 0 },
            selected_main: 0, edit: EditMode::None, should_exit: false,
        };
        let widok = wyrenderuj(140, 40, &state, &u);

        let poz_1 = widok.find("Faza 1").expect("Faza 1 musi być widoczna");
        let poz_2 = widok.find("Faza 2").expect("Faza 2 musi być widoczna");
        assert!(
            poz_1 < poz_2,
            "Faza 1 musi stać przed Fazą 2 - to pilnuje sortowania numerycznego:\n{}", widok
        );
    }

    #[test]
    fn test_edycja_raportu_pokazuje_trzy_pola() {
        let u = Ustawienia::default();
        let state = SettingsUiState {
            screen: Screen::ReportsEdit { phase: "Faza 7".to_string(), selected: 0 },
            selected_main: 0, edit: EditMode::None, should_exit: false,
        };
        let widok = wyrenderuj(140, 30, &state, &u);

        for etykieta in REPORT_FIELD_LABELS {
            assert!(widok.contains(etykieta), "Brak pola '{}':\n{}", etykieta, widok);
        }
    }

    // ------------------------------------------------------------------
    // NAKŁADKI EDYCJI
    // ------------------------------------------------------------------

    #[test]
    fn test_nakladka_tekstowa_pokazuje_bufor_i_blad() {
        let u = Ustawienia::default();
        let state = SettingsUiState {
            screen: Screen::Main,
            selected_main: 0,
            edit: EditMode::Text {
                target: EditTarget::Main(0),
                buffer: "/wpisywana/sciezka".to_string(),
                // Kursor NA KOŃCU bufora. Przy kursorze w środku renderer
                // wstawia w tekst blok `█` (`/wp█isywana/...`), więc asercja na
                // ciągłym napisie nie miałaby prawa przejść - to właściwość
                // rysowania kursora, nie wada.
                cursor: "/wpisywana/sciezka".chars().count(),
                error: Some("katalog nie istnieje".to_string()),
            },
            should_exit: false,
        };
        let widok = wyrenderuj(140, 30, &state, &u);

        assert!(widok.contains("/wpisywana/sciezka"), "Brak treści bufora:\n{}", widok);
        assert!(
            widok.contains("katalog nie istnieje"),
            "Komunikat błędu MUSI być widoczny - inaczej operator nie wie, czemu zapis nie przechodzi:\n{}", widok
        );
    }

    /// Nakładka rysuje się NA WIERZCHU listy — to ona jest w tej chwili
    /// przedmiotem uwagi operatora.
    #[test]
    fn test_nakladka_zasłania_liste_pod_spodem() {
        let u = Ustawienia::default();
        let bez = wyrenderuj(140, 30, &stan_glowny(0), &u);
        let z_nakladka = wyrenderuj(140, 30, &SettingsUiState {
            screen: Screen::Main,
            selected_main: 0,
            edit: EditMode::Text {
                target: EditTarget::Main(0),
                buffer: "ZNACZNIK_NAKLADKI".to_string(),
                cursor: 0,
                error: None,
            },
            should_exit: false,
        }, &u);

        assert_ne!(bez, z_nakladka, "Nakładka musi zmienić obraz ekranu");
        assert!(z_nakladka.contains("ZNACZNIK_NAKLADKI"));
    }

    #[test]
    fn test_nakladka_wyboru_pokazuje_dostepne_opcje() {
        let u = Ustawienia::default();
        // Pole 12 to „Tryb dyskowy (I/O Mode)" — pole wyboru.
        let idx = FIELD_LABELS.iter().position(|e| e.contains("Tryb dyskowy")).unwrap();
        let state = SettingsUiState {
            screen: Screen::Main,
            selected_main: idx,
            edit: EditMode::Choice { idx, selected: 0 },
            should_exit: false,
        };
        let widok = wyrenderuj(140, 30, &state, &u);

        for opcja in choice_options(idx) {
            assert!(widok.contains(opcja), "Brak opcji '{}':\n{}", opcja, widok);
        }
    }

    /// Kreator hasła NIE MOŻE pokazywać wpisywanych znaków — ani starego, ani
    /// nowego hasła.
    #[test]
    fn test_kreator_hasla_nie_pokazuje_wpisywanych_znakow() {
        let u = Ustawienia::default();
        let tajne_stare = "MojeStareHaslo123";
        let tajne_nowe = "MojeNoweHaslo456";

        for etap in [PasswordStage::Old, PasswordStage::New, PasswordStage::Confirm] {
            let state = SettingsUiState {
                screen: Screen::Main,
                selected_main: 0,
                edit: EditMode::Password {
                    stage: etap,
                    old_buf: tajne_stare.to_string(),
                    new_buf: tajne_nowe.to_string(),
                    confirm_buf: tajne_nowe.to_string(),
                    error: None,
                },
                should_exit: false,
            };
            let widok = wyrenderuj(140, 30, &state, &u);

            assert!(!widok.contains(tajne_stare), "Stare hasło wyciekło na ekran przy etapie {:?}", etap);
            assert!(!widok.contains(tajne_nowe), "Nowe hasło wyciekło na ekran przy etapie {:?}", etap);
        }
    }

    #[test]
    fn test_kreator_hasla_pokazuje_blad() {
        let u = Ustawienia::default();
        let state = SettingsUiState {
            screen: Screen::Main,
            selected_main: 0,
            edit: EditMode::Password {
                stage: PasswordStage::Confirm,
                old_buf: String::new(),
                new_buf: "a".to_string(),
                confirm_buf: "b".to_string(),
                error: Some("hasła się różnią".to_string()),
            },
            should_exit: false,
        };
        let widok = wyrenderuj(140, 30, &state, &u);
        assert!(widok.contains("hasła się różnią"), "Brak komunikatu błędu:\n{}", widok);
    }

    // ------------------------------------------------------------------
    // ODPORNOŚĆ NA ROZMIAR TERMINALU
    // ------------------------------------------------------------------

    /// Rysowanie nie może panikować na skrajnie małym terminalu — operator
    /// bywa na konsoli szeregowej albo w wąskim panelu.
    #[test]
    fn test_rysowanie_nie_panikuje_na_malym_terminalu() {
        let u = Ustawienia::default();
        for (szer, wys) in [(20u16, 5u16), (40, 10), (1, 1), (200, 60)] {
            let _ = wyrenderuj(szer, wys, &stan_glowny(0), &u);
        }
    }

    #[test]
    fn test_rysowanie_nakladek_nie_panikuje_na_malym_terminalu() {
        let u = Ustawienia::default();
        let state = SettingsUiState {
            screen: Screen::Main,
            selected_main: 0,
            edit: EditMode::Text {
                target: EditTarget::Main(0),
                buffer: "x".repeat(300),
                cursor: 299,
                error: Some("y".repeat(300)),
            },
            should_exit: false,
        };
        for (szer, wys) in [(20u16, 5u16), (1, 1), (200, 60)] {
            let _ = wyrenderuj(szer, wys, &state, &u);
        }
    }
}
