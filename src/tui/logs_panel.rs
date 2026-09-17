// src/tui/logs_panel.rs

//! # Komponent Dziennika (Logi Operacyjne)
//! 
//! Odpowiada wyłącznie za renderowanie okna logów (zdarzeń systemowych).
//! Wyodrębniony z głównego pliku UI, aby ułatwić zarządzanie i czytelność.

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, List, ListItem},
    Frame,
};

// Zakładamy, że po refaktoryzacji stan UI znajdzie się w module `state`
use crate::tui::hardware_panel::KOLOR_FOKUSU;
use crate::tui::state::PhaseUIState;

/// Rysuje historyczne logi w formie listy.
/// Samodzielnie oblicza wcięcia i potrafi zawijać długie ciągi znaków
/// (Intelligent Word-Wrap), aby uniknąć obcinania ważnych informacji.
///
/// `focused` steruje WYŁĄCZNIE wizualnym sygnałem fokusu (obramowanie/tytuł)
/// na ekranie fazy na żywo (Tab między panelami, `menu/actions.rs`) — dane
/// przewijania (`state.log_scroll`) są od niego całkowicie niezależne, ten
/// panel ma zawsze klawiaturowy fokus domyślnie (patrz `PanelWFokusie::Logi`
/// jako wartość startowa), więc dotychczasowe zachowanie PageUp/PageDown/End
/// dla kogoś, kto nigdy nie naciśnie Tab, zostaje bez zmian.
pub fn draw_logs(f: &mut Frame, state: &PhaseUIState, area: Rect, focused: bool) {
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

    // Wyliczamy, ile linii można wyświetlić i tniemy początek.
    //
    // Bez ręcznego przewijania (`log_scroll == None`): Auto-Scroll do dołu,
    // jak dotąd — pokazujemy ogon.
    //
    // Z ręcznym przewijaniem (`log_scroll == Some(n)`): cofamy punkt startu o
    // `n` (już ZAWINIĘTYCH — patrz `display_lines` wyżej — nie surowych
    // wpisów `state.logs`) linii od dołu, tak żeby PageUp/PageDown operowały
    // na tym, co operator faktycznie widzi na ekranie, a nie na logicznych
    // wpisach, które mogą zajmować różną liczbę linii po zawinięciu.
    // `saturating_sub` dociska do 0, gdy `n` przekracza dostępną historię —
    // przewinięcie "za daleko" po prostu pokazuje sam początek, bez panic.
    let visible_lines = area.height.saturating_sub(2) as usize;
    let bottom_start = display_lines.len().saturating_sub(visible_lines);
    let start_idx = match state.log_scroll {
        None => bottom_start,
        Some(cofniecie) => bottom_start.saturating_sub(cofniecie),
    };

    let tryb = if state.log_scroll.is_some() {
        "Przewijanie ręczne — [End] wróć do końca"
    } else {
        "Auto-Scroll"
    };
    let tytul = if focused {
        format!(" ▶ Logi Operacyjne ({}) (aktywny — ↑↓ PgUp/PgDn) ", tryb)
    } else {
        format!(" Logi Operacyjne ({}) [Tab] ", tryb)
    };
    let border_styl = if focused {
        Style::default().fg(KOLOR_FOKUSU).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let list = List::new(display_lines[start_idx..].to_vec())
        .block(Block::default()
            .borders(Borders::ALL)
            .title(tytul)
            .border_style(border_styl));

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
        terminal.draw(|f| { let obszar = f.area(); draw_logs(f, state, obszar, false); }).unwrap();
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

    // ------------------------------------------------------------------
    // RĘCZNE PRZEWIJANIE (PageUp/PageDown/End)
    // ------------------------------------------------------------------

    #[test]
    fn test_reczne_przewiniecie_pokazuje_starsze_wpisy_nie_najnowsze() {
        let mut s = stan_z_logami(100);
        s.scroll_logs_up(20);

        let widok = wyrenderuj(80, 10, &s);

        assert!(!widok.contains("wpis numer 99"), "po przewinięciu w górę najnowszy wpis nie może być widoczny:\n{}", widok);
    }

    #[test]
    fn test_bez_przewiniecia_tytul_mowi_auto_scroll() {
        let widok = wyrenderuj(80, 10, &stan_z_logami(5));
        assert!(widok.contains("Auto-Scroll"), "domyślny tytuł musi wprost nazywać tryb:\n{}", widok);
    }

    #[test]
    fn test_po_przewinieciu_tytul_ostrzega_o_recznym_trybie() {
        let mut s = stan_z_logami(100);
        s.scroll_logs_up(10);

        let widok = wyrenderuj(80, 10, &s);
        assert!(
            widok.contains("Przewijanie ręczne") && widok.contains("End"),
            "tytuł musi ostrzec, że operator NIE patrzy na najnowsze wpisy, i podpowiedzieć jak wrócić:\n{}", widok
        );
    }

    #[test]
    fn test_powrot_do_konca_przywraca_widok_najnowszych() {
        let mut s = stan_z_logami(100);
        s.scroll_logs_up(20);
        s.jump_to_latest_log();

        let widok = wyrenderuj(80, 10, &s);
        assert!(widok.contains("wpis numer 99"), "po End najnowszy wpis musi znowu być widoczny:\n{}", widok);
        assert!(widok.contains("Auto-Scroll"), "tytuł musi wrócić do trybu domyślnego:\n{}", widok);
    }

    #[test]
    fn test_przewiniecie_dalej_niz_historia_nie_panikuje_i_pokazuje_poczatek() {
        let mut s = stan_z_logami(20);
        s.scroll_logs_up(1000);
        let widok = wyrenderuj(80, 10, &s);
        assert!(widok.contains("wpis numer 0"), "przewinięcie za daleko musi dociskać do samego początku, nie panikować:\n{}", widok);
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

    // ------------------------------------------------------------------
    // FOKUS (Tab między panelami na ekranie fazy na żywo)
    // ------------------------------------------------------------------

    fn wyrenderuj_z_fokusem(szer: u16, wys: u16, state: &PhaseUIState, focused: bool) -> String {
        let mut terminal = Terminal::new(TestBackend::new(szer, wys)).unwrap();
        terminal.draw(|f| { let obszar = f.area(); draw_logs(f, state, obszar, focused); }).unwrap();
        ekran(terminal.backend().buffer())
    }

    #[test]
    fn test_tytul_logow_odzwierciedla_fokus_niezaleznie_od_trybu_przewijania() {
        let s = stan_z_logami(5);

        let bez_fokusu = wyrenderuj_z_fokusem(80, 10, &s, false);
        assert!(bez_fokusu.contains("Tab"), "widok:\n{}", bez_fokusu);
        assert!(bez_fokusu.contains("Auto-Scroll"), "tryb przewijania musi zostać widoczny mimo braku fokusu:\n{}", bez_fokusu);

        let z_fokusem = wyrenderuj_z_fokusem(80, 10, &s, true);
        assert!(z_fokusem.contains("aktywny"), "widok:\n{}", z_fokusem);
        assert!(z_fokusem.contains("Auto-Scroll"), "tryb przewijania musi zostać widoczny mimo fokusu:\n{}", z_fokusem);
    }

    #[test]
    fn test_tytul_logow_w_recznym_przewijaniu_z_fokusem_pokazuje_oba_sygnaly() {
        let mut s = stan_z_logami(100);
        s.scroll_logs_up(10);

        let widok = wyrenderuj_z_fokusem(80, 10, &s, true);
        assert!(widok.contains("aktywny"), "widok:\n{}", widok);
        assert!(widok.contains("Przewijanie ręczne"), "widok:\n{}", widok);
    }
}
