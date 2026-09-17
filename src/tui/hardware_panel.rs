// src/tui/hardware_panel.rs

//! # Komponenty Sprzętowe i Konfiguracyjne
//!
//! Zawiera logikę renderowania bocznych paneli systemowych:
//! 1. Zużycie procesora i pamięci RAM (Z systemem barw termowizyjnych).
//! 2. Lista wykrytych i podłączonych dysków.
//! 3. Aktywna konfiguracja programu (ścieżki, limity, środowisko).

use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

use crate::menu::state::AppState;

/// Barwa obramowania i tytułu panelu, gdy to ON ma fokus klawiatury (ekran
/// fazy na żywo, `menu/actions.rs::run_phase_z_opcjami` — Tab między
/// panelami). Wspólna dla wszystkich fokusowalnych paneli, żeby operator
/// rozpoznawał "aktywny panel" jednym spójnym kolorem niezależnie od tego,
/// który to panel — patrz też `scanner_panel.rs`/`logs_panel.rs`.
pub const KOLOR_FOKUSU: Color = Color::Magenta;

/// Konwersja procentu obciążenia (0-100) na barwę krytyczną dla TUI (System Termowizji).
pub fn get_thermal_color_ratatui(pct: f64) -> Color {
    if pct > 80.0 { Color::Red } 
    else if pct > 50.0 { Color::Yellow } 
    else { Color::Green }
}

/// Wewnętrzna funkcja do bezpiecznego przycinania długich ścieżek, 
/// pozostawiająca początek i koniec (np. /mnt/.../data)
fn truncate_path(path: &str, max_len: usize) -> String {
    let chars: Vec<char> = path.chars().collect();
    if chars.len() > max_len {
        let half = (max_len.saturating_sub(3)) / 2;
        if half == 0 { return path.to_string(); }
        let start: String = chars[..half].iter().collect();
        let end: String = chars[chars.len() - half..].iter().collect();
        format!("{}...{}", start, end)
    } else {
        path.to_string()
    }
}

pub fn draw_hw_panel(f: &mut Frame, app: &AppState, area: Rect) {
    let cpu_color = get_thermal_color_ratatui(app.cpu_usage as f64);
    let ram_color = get_thermal_color_ratatui(app.ram_pct);

    let hw_text = Line::from(vec![
        Span::styled(" [ 💻 ] CPU: ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{:>5.1}%", app.cpu_usage), Style::default().fg(cpu_color).add_modifier(Modifier::BOLD)),
        Span::raw("   |   "),
        Span::styled("[ 🧠 ] RAM: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{:.1} / {:.1} GB ({:.1}%)", app.ram_used_gb, app.ram_total_gb, app.ram_pct),
            Style::default().fg(ram_color).add_modifier(Modifier::BOLD),
        ),
    ]);
    let hw_paragraph = Paragraph::new(hw_text).block(Block::default().borders(Borders::ALL).title(" Zasoby Systemowe "));
    f.render_widget(hw_paragraph, area);
}

/// Rysuje tabelę zamontowanych dysków. Podczas ekranu fazy na żywo
/// (`menu/actions.rs`) tabela jest stanowa i fokusowalna klawiszem Tab —
/// `table_state.selected()` wskazuje podświetlony wiersz (Ratatui sam
/// przesuwa widoczny zakres, żeby zaznaczenie było zawsze widoczne — ten
/// sam mechanizm co `ListState` w `dashboard.rs`), a `focused` steruje TYLKO
/// warstwą wizualną (kolor obramowania/tytuł) — podświetlenie wiersza jest
/// widoczne niezależnie od fokusu, dokładnie jak zaznaczenie w
/// `dashboard.rs`. Na bezczynnym ekranie menu (`dashboard.rs`) wywołujący
/// przekazuje jednorazowy, odrzucany `TableState` i `focused: false`.
pub fn draw_disks_panel(f: &mut Frame, app: &AppState, area: Rect, table_state: &mut TableState, focused: bool) {
    // Samoleczący zatrzask: jeśli dysk zniknął (np. odpięty nośnik) między
    // naciśnięciami klawiszy a tą klatką, zaznaczenie wraca w zakres zamiast
    // trwale wskazywać "donikąd" — patrz identyczny wzorzec w
    // `scanner_panel::draw_side_stats_panel`.
    if let Some(i) = table_state.selected()
        && i >= app.disk_list.len() {
            table_state.select(if app.disk_list.is_empty() { None } else { Some(app.disk_list.len() - 1) });
        }
    let wybrany = table_state.selected();
    let mut disk_rows = Vec::new();
    for (i, disk) in app.disk_list.iter().enumerate() {
        let free_color = if disk.available_gb > 50.0 { Color::Green } else if disk.available_gb > 10.0 { Color::Yellow } else { Color::Red };
        let zaznaczony = wybrany == Some(i);
        let prefix = if zaznaczony { "❯ " } else { "  " };
        let nazwa_styl = if zaznaczony {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Cyan)
        };
        disk_rows.push(Row::new(vec![
            Cell::from(format!("{}[ 💽 ] /dev/{}", prefix, disk.name)).style(nazwa_styl),
            Cell::from(disk.mount_point.clone()),
            Cell::from(format!("{:.1} / {:.1} GB", disk.used_gb, disk.total_gb)),
            Cell::from(format!("{:.1} GB", disk.available_gb)).style(Style::default().fg(free_color)),
            Cell::from(format!("{:.1}%", disk.usage_pct)),
        ]));
    }
    let tytul = if focused { " ▶ Dyski Fizyczne (aktywny — ↑↓ PgUp/PgDn) " } else { " Dyski Fizyczne [Tab] " };
    let border_styl = if focused { Style::default().fg(KOLOR_FOKUSU).add_modifier(Modifier::BOLD) } else { Style::default() };
    let disks_table = Table::new(disk_rows, &[
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(20),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
    ])
    .header(Row::new(vec![
        "[ 💽 ] URZĄDZENIE", "PUNKT MONTOWANIA", "ZAJĘTE / RAZEM GB", "WOLNE GB", "Zajętość %"]).style(Style::default().fg(Color::DarkGray)))
    .block(Block::default().borders(Borders::ALL).title(tytul).border_style(border_styl));
    f.render_stateful_widget(disks_table, area, table_state);
}

/// Wysokość (w wierszach terminala) wymagana przez [`draw_paths_panel`], żeby
/// zmieścić CAŁĄ treść bez obcięcia: 8 stałych linii (UFS, Skrypt, Ścieżka
/// Docelowa, Baza Danych, Logi, Tryb I/O, Wątki CPU, Szybki Skan) + 1
/// warunkowa ("DNG do przeglądu", widoczna tylko gdy jest coś do przejrzenia)
/// + 2 linie obramowania (`Borders::ALL`).
///
/// JEDYNE źródło prawdy dla WSZYSTKICH miejsc wywołania tego panelu — patrz
/// `dashboard.rs`/`menu/actions.rs` (dwie zduplikowane kopie layoutu ekranu
/// fazy). Historia: `5c444f5` dodał linię "Ścieżka Docelowa" i podniósł
/// wysokość TYLKO w `dashboard.rs`, zostawiając obie kopie w `actions.rs`
/// obcięte (`todo.menu.md`) — druga, niezależna weryfikacja to potwierdziła.
/// Stała istnieje właśnie po to, żeby TA KONKRETNA klasa błędu (jedno miejsce
/// zaktualizowane, inne zapomniane) nie mogła się powtórzyć przy kolejnej
/// zmianie treści panelu — zmiana liczby linii wymaga zmiany TYLKO tutaj.
pub const WYSOKOSC_PANELU_SCIEZEK_MAX: u16 = 11;

/// Rysuje panel "Konfiguracja Środowiska". Fokusowalny i przewijalny klawiszem
/// Tab na ekranie fazy na żywo — patrz dokumentacja [`draw_disks_panel`] dla
/// ogólnego wzorca `table_state`/`focused`. RÓŻNICA: to `Paragraph`, nie
/// `Table` — nie ma dyskretnych "wierszy" do zaznaczania, więc `table_state`
/// jest tu wykorzystywany WYŁĄCZNIE jako licznik przewinięcia w dół (liczba
/// linii schowanych nad widocznym oknem), nie jako zaznaczenie — stąd brak
/// prefiksu `❯` przy którejkolwiek linii, w odróżnieniu od pozostałych
/// czterech paneli. Pozwala to na ponowne użycie [`table_select_next`] i
/// reszty rodziny `table_select_*` z `menu/actions.rs` bez pisania nowego,
/// równoległego mechanizmu — matematyka przewijania listy i przewijania
/// akapitu jest identyczna (zatrzask do `[0, N-1]`).
///
/// Treść panelu jest dziś zawsze krótsza niż widoczna wysokość (`WYSOKOSC_PANELU_SCIEZEK_MAX`
/// dobrana dokładnie pod nią), więc przewinięcie faktycznie nic nie zmienia —
/// ale gdy przybędzie kolejnych pól (np. limit fallbacku ssdeep, poziom logów),
/// panel automatycznie zacznie się przewijać zamiast ciąć treść, bez potrzeby
/// dalszych zmian tutaj.
pub fn draw_paths_panel(f: &mut Frame, app: &AppState, area: Rect, table_state: &mut TableState, focused: bool) {
    let max_path_len = area.width.saturating_sub(25) as usize;
    let ufs_trunc = truncate_path(&app.ustawienia.ufs_path, max_path_len);
    let scr_trunc = truncate_path(&app.ustawienia.script_path, max_path_len);
    let target_trunc = truncate_path(&app.ustawienia.target_path, max_path_len);
    let log_trunc = truncate_path(&app.ustawienia.log_path, max_path_len);

    let db_info = format!("{} ({:.1} MB | Zabezpieczone: {})", app.ustawienia.db_file_name, app.db_file_size_mb, app.db_records_count);
    
    let io_str = if app.ustawienia.io_mode == "CONCURRENT" { "RÓWNOLEGŁY" } else { "SEKWENCYJNY" };
    let threads_str = if app.ustawienia.max_threads == 0 { "AUTO".to_string() } else { app.ustawienia.max_threads.to_string() };
    let fast_str = if app.ustawienia.phase13_fast_mode { "TAK" } else { "NIE" };

    let mut paths_text = vec![
        Line::from(vec![
            Span::styled(" [ 📂 ] Źródło UFS:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(ufs_trunc, Style::default().fg(Color::Yellow))
        ]),
        Line::from(vec![
            Span::styled(" [ 📂 ] Skrypt Aut.:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(scr_trunc, Style::default().fg(Color::Yellow))
        ]),
        Line::from(vec![
            Span::styled(" [ 🎯 ] Ścieżka Docelowa: ", Style::default().fg(Color::DarkGray)),
            Span::styled(target_trunc, Style::default().fg(Color::Magenta))
        ]),
        Line::from(vec![
            Span::styled(" [ 📚 ] Baza Danych:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(truncate_path(&db_info, max_path_len), Style::default().fg(Color::Green))
        ]),
        Line::from(vec![
            Span::styled(" [ 📝 ] Ścieżka Logów: ", Style::default().fg(Color::DarkGray)),
            Span::styled(log_trunc, Style::default().fg(Color::Cyan))
        ]),
        Line::from(vec![
            Span::styled(" [ 💡 ] Parametry:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("Tryb I/O:     {}", io_str), Style::default().fg(Color::White))
        ]),
        Line::from(vec![
            Span::styled("                      ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("Wątki CPU:   {}", threads_str), Style::default().fg(Color::White))
        ]),
        Line::from(vec![
            Span::styled("                      ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("Szybki Skan: {}", fast_str), Style::default().fg(Color::White))
        ]),
    ];

    // Widoczne TYLKO gdy jest faktycznie coś do przejrzenia - nie zaśmieca
    // dashboardu, gdy narzędzie Składania Strukturalnego DNG nigdy nie było
    // używane albo wszystko zostało już przejrzane.
    if app.dng_pending_review > 0 {
        paths_text.push(Line::from(vec![
            Span::styled(" [ 🧩 ] DNG do przeglądu: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", app.dng_pending_review), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]));
    }

    // Samoleczący zatrzask przewinięcia — ten sam wzorzec co
    // `scanner_panel::draw_side_stats_panel`: liczba linii jest znana dopiero
    // TUTAJ (po zbudowaniu `paths_text`), więc to ta funkcja, nie wywołujący,
    // pilnuje granicy `[0, max(0, linie - widoczna_wysokosc)]`.
    let widoczna_wysokosc = area.height.saturating_sub(2) as usize; // minus obramowanie
    let max_offset = paths_text.len().saturating_sub(widoczna_wysokosc);
    if let Some(i) = table_state.selected()
        && i > max_offset {
            table_state.select(Some(max_offset));
        }
    let offset = table_state.selected().unwrap_or(0) as u16;

    let tytul = if focused { " ▶ Konfiguracja Środowiska (aktywny — ↑↓ PgUp/PgDn) " } else { " Konfiguracja Środowiska [Tab] " };
    let border_styl = if focused { Style::default().fg(KOLOR_FOKUSU).add_modifier(Modifier::BOLD) } else { Style::default() };

    let paths_paragraph = Paragraph::new(paths_text)
        .block(Block::default().borders(Borders::ALL).title(tytul).border_style(border_styl))
        .scroll((offset, 0));
    f.render_widget(paths_paragraph, area);
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Ustawienia;
    use ratatui::{backend::TestBackend, layout::Rect, Terminal};

    fn ekran(bufor: &ratatui::buffer::Buffer) -> String {
        (0..bufor.area.height)
            .map(|y| (0..bufor.area.width).map(|x| bufor[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Renderuje wskazany panel na pustym terminalu i zwraca to, co widać.
    fn wyrenderuj(
        szer: u16,
        wys: u16,
        u: &mut Ustawienia,
        rysuj: impl Fn(&mut Frame, &AppState, Rect),
    ) -> String {
        let mut app = AppState::new(u).expect("stan menu musi się zbudować");
        app.tick_hw();
        let mut terminal = Terminal::new(TestBackend::new(szer, wys)).unwrap();
        terminal.draw(|f| { let obszar = f.area(); rysuj(f, &app, obszar); }).unwrap();
        ekran(terminal.backend().buffer())
    }

    // ------------------------------------------------------------------
    // PRÓG TERMICZNY
    // ------------------------------------------------------------------

    /// Kolor jest jedynym sygnałem obciążenia, jaki operator widzi kątem oka —
    /// progi muszą być dokładnie tam, gdzie je zadeklarowano.
    #[test]
    fn test_progi_kolorow_obciazenia() {
        assert_eq!(get_thermal_color_ratatui(0.0), Color::Green);
        assert_eq!(get_thermal_color_ratatui(50.0), Color::Green, "Równo 50 to jeszcze zielony");
        assert_eq!(get_thermal_color_ratatui(50.1), Color::Yellow);
        assert_eq!(get_thermal_color_ratatui(80.0), Color::Yellow, "Równo 80 to jeszcze żółty");
        assert_eq!(get_thermal_color_ratatui(80.1), Color::Red);
        assert_eq!(get_thermal_color_ratatui(100.0), Color::Red);
    }

    #[test]
    fn test_wartosci_spoza_zakresu_nie_wywracaja_progow() {
        assert_eq!(get_thermal_color_ratatui(-5.0), Color::Green);
        assert_eq!(get_thermal_color_ratatui(500.0), Color::Red);
        assert_eq!(get_thermal_color_ratatui(f64::NAN), Color::Green, "NaN nie przechodzi porównań");
    }

    // ------------------------------------------------------------------
    // SKRACANIE ŚCIEŻEK
    // ------------------------------------------------------------------

    #[test]
    fn test_krotka_sciezka_zostaje_nietknieta() {
        assert_eq!(truncate_path("/mnt/dane", 40), "/mnt/dane");
    }

    #[test]
    fn test_dluga_sciezka_zachowuje_poczatek_i_koniec() {
        let dluga = "/mnt/skrypt_sdb1_ro_root/@snapshots/@data/zdjecia/2026";
        let skrocona = truncate_path(dluga, 20);

        assert!(skrocona.len() < dluga.len(), "Ścieżka musi zostać skrócona");
        assert!(skrocona.contains("..."), "Skrócenie musi być widoczne");
        assert!(skrocona.starts_with("/mnt"), "Początek mówi, który to dysk");
        assert!(skrocona.ends_with("2026"), "Koniec mówi, co jest przetwarzane");
    }

    /// Skracanie działa na ZNAKACH, nie bajtach — inaczej cięcie polskiej
    /// ścieżki rozwaliłoby znak wielobajtowy i wysypało render.
    #[test]
    fn test_skracanie_nie_tnie_znakow_wielobajtowych() {
        let z_ogonkami = "/mnt/zdjęcia/wakacje_zażółć_gęślą_jaźń/plik.dng";
        let skrocona = truncate_path(z_ogonkami, 20);
        assert!(skrocona.chars().count() <= 21, "Długość liczona w znakach: {}", skrocona);
    }

    #[test]
    fn test_skrajnie_maly_limit_nie_wywraca_skracania() {
        for limit in [0usize, 1, 2, 3] {
            let _ = truncate_path("/bardzo/dluga/sciezka/do/pliku", limit);
        }
    }

    // ------------------------------------------------------------------
    // RENDEROWANIE
    // ------------------------------------------------------------------

    #[test]
    fn test_panel_sprzetu_pokazuje_cpu_i_ram() {
        let mut u = Ustawienia::default();
        let widok = wyrenderuj(80, 12, &mut u, draw_hw_panel);
        assert!(widok.contains("CPU"), "Brak sekcji CPU:\n{}", widok);
        assert!(widok.contains("RAM"), "Brak sekcji RAM:\n{}", widok);
    }

    /// Panel pokazuje źródła (UFS/Skrypt), ŚCIEŻKĘ DOCELOWĄ, bazę, logi i
    /// parametry pracy — `target_path` była jedynym polem tej klasy pominiętym
    /// w tym panelu (operator widział ją tylko w ekranie Ustawień), naprawione
    /// na wyraźną prośbę.
    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_panel_sciezek_pokazuje_zrodla_cel_i_parametry() {
        let mut u = Ustawienia::default();
        u.ufs_path = "/moje/zrodlo/ufs".to_string();
        u.target_path = "/moje/miejsce/docelowe".to_string();
        u.io_mode = "SEQUENTIAL".to_string();
        u.max_threads = 0;

        let widok = wyrenderuj(140, 14, &mut u, |f, app, area| {
            draw_paths_panel(f, app, area, &mut TableState::default(), false)
        });

        assert!(widok.contains("/moje/zrodlo/ufs"), "Brak ścieżki UFS:\n{}", widok);
        assert!(widok.contains("/moje/miejsce/docelowe"), "Brak ścieżki docelowej:\n{}", widok);
        assert!(widok.contains("SEKWENCYJNY"), "Tryb I/O musi być rozwinięty do słowa:\n{}", widok);
        assert!(widok.contains("AUTO"), "Zero wątków musi być pokazane jako AUTO:\n{}", widok);
    }

    /// Rysowanie nie może panikować na skrajnych rozmiarach — operator bywa na
    /// konsoli szeregowej albo w wąskim panelu bocznym.
    #[test]
    fn test_panele_nie_panikuja_na_skrajnych_rozmiarach() {
        let mut u = Ustawienia::default();
        for (szer, wys) in [(1u16, 1u16), (10, 3), (20, 5), (200, 60)] {
            let _ = wyrenderuj(szer, wys, &mut u, draw_hw_panel);
            let _ = wyrenderuj(szer, wys, &mut u, |f, app, area| {
                draw_paths_panel(f, app, area, &mut TableState::default(), false)
            });
            let _ = wyrenderuj(szer, wys, &mut u, |f, app, area| {
                draw_disks_panel(f, app, area, &mut TableState::default(), false)
            });
        }
    }

    // ------------------------------------------------------------------
    // FOKUS I ZAZNACZENIE (Tab między panelami na ekranie fazy na żywo)
    // ------------------------------------------------------------------

    fn dysk(nazwa: &str) -> crate::menu::state::DiskInfo {
        crate::menu::state::DiskInfo {
            name: nazwa.to_string(),
            mount_point: format!("/mnt/{}", nazwa),
            used_gb: 10.0,
            total_gb: 100.0,
            available_gb: 90.0,
            usage_pct: 10.0,
        }
    }

    #[test]
    fn test_tytul_panelu_dyskow_odzwierciedla_fokus() {
        let mut u = Ustawienia::default();
        let mut app = AppState::new(&mut u).expect("stan menu musi się zbudować");
        app.tick_hw();

        let mut terminal = Terminal::new(TestBackend::new(100, 10)).unwrap();
        let mut ts = TableState::default();

        terminal.draw(|f| draw_disks_panel(f, &app, f.area(), &mut ts, false)).unwrap();
        let bez_fokusu = ekran(terminal.backend().buffer());
        assert!(bez_fokusu.contains("Tab"), "Bez fokusu tytuł musi podpowiadać klawisz:\n{}", bez_fokusu);

        terminal.draw(|f| draw_disks_panel(f, &app, f.area(), &mut ts, true)).unwrap();
        let z_fokusem = ekran(terminal.backend().buffer());
        assert!(z_fokusem.contains("aktywny"), "Z fokusem tytuł musi to jawnie nazwać:\n{}", z_fokusem);
    }

    #[test]
    fn test_zaznaczony_dysk_ma_widoczny_prefiks_niezaleznie_od_fokusu() {
        let mut u = Ustawienia::default();
        let mut app = AppState::new(&mut u).expect("stan menu musi się zbudować");
        app.tick_hw();
        app.disk_list = vec![dysk("sda"), dysk("sdb"), dysk("sdc")];

        let mut terminal = Terminal::new(TestBackend::new(100, 10)).unwrap();
        let mut ts = TableState::default();
        ts.select(Some(1));

        terminal.draw(|f| draw_disks_panel(f, &app, f.area(), &mut ts, false)).unwrap();
        let widok = ekran(terminal.backend().buffer());
        assert!(widok.contains("❯"), "Zaznaczenie musi być widoczne nawet bez fokusu (jak w dashboard.rs):\n{}", widok);
    }

    /// `selected()` wskazujący poza aktualną liczbą dysków (np. lista dysków
    /// skurczyła się między klatkami po odpięciu nośnika) nie może panikować.
    #[test]
    fn test_zaznaczenie_poza_zakresem_nie_panikuje() {
        let mut u = Ustawienia::default();
        let mut app = AppState::new(&mut u).expect("stan menu musi się zbudować");
        app.tick_hw();
        app.disk_list = vec![dysk("sda")];

        let mut terminal = Terminal::new(TestBackend::new(100, 10)).unwrap();
        let mut ts = TableState::default();
        ts.select(Some(999));

        let _ = terminal.draw(|f| draw_disks_panel(f, &app, f.area(), &mut ts, true));
    }

    // ------------------------------------------------------------------
    // REGRESJA (measure twice — druga weryfikacja Gemini, todo.menu.md):
    // WYSOKOSC_PANELU_SCIEZEK_MAX musi faktycznie starczyć na WSZYSTKIE
    // linie treści panelu, łącznie z warunkową ("DNG do przeglądu") - inaczej
    // każde miejsce wywołania, które ją wykorzystuje (dashboard.rs,
    // menu/actions.rs ×2), dziedziczyłoby to samo obcięcie, mimo współdzielenia
    // JEDNEJ stałej. Ten test to jedyne miejsce, które musiałoby się zmienić,
    // gdyby `draw_paths_panel` kiedyś zyskało kolejną linię treści bez
    // odpowiedniej aktualizacji stałej — dokładnie ta "realna przyczyna, dla
    // której problem przetrwał dwie niezależne rundy audytu", którą wskazał
    // raport.
    // ------------------------------------------------------------------

    #[test]
    fn test_wysokosc_panelu_sciezek_miesci_wszystkie_linie_wliczajac_warunkowa() {
        let mut u = Ustawienia::default();
        let mut app = AppState::new(&mut u).expect("stan menu musi się zbudować");
        app.tick_hw();
        // Najgorszy przypadek: linia warunkowa "DNG do przeglądu" WIDOCZNA.
        app.dng_pending_review = 3;

        let mut terminal = Terminal::new(TestBackend::new(80, WYSOKOSC_PANELU_SCIEZEK_MAX)).unwrap();
        terminal.draw(|f| draw_paths_panel(f, &app, f.area(), &mut TableState::default(), false)).unwrap();
        let widok = ekran(terminal.backend().buffer());

        for etykieta in ["Źródło UFS", "Skrypt Aut.", "Ścieżka Docelowa", "Baza Danych", "Ścieżka Logów", "Parametry", "Wątki CPU", "Szybki Skan", "DNG do przeglądu"] {
            assert!(widok.contains(etykieta), "etykieta \"{}\" musi zmieścić się w WYSOKOSC_PANELU_SCIEZEK_MAX={} wierszach, ale nie ma jej w renderze:\n{}", etykieta, WYSOKOSC_PANELU_SCIEZEK_MAX, widok);
        }
    }

    // ------------------------------------------------------------------
    // FOKUS I PRZEWIJANIE (Tab między panelami na ekranie fazy na żywo)
    // ------------------------------------------------------------------

    #[test]
    fn test_tytul_panelu_konfiguracji_odzwierciedla_fokus() {
        let mut u = Ustawienia::default();
        let mut app = AppState::new(&mut u).expect("stan menu musi się zbudować");
        app.tick_hw();

        let mut terminal = Terminal::new(TestBackend::new(80, WYSOKOSC_PANELU_SCIEZEK_MAX)).unwrap();
        let mut ts = TableState::default();

        terminal.draw(|f| draw_paths_panel(f, &app, f.area(), &mut ts, false)).unwrap();
        let bez_fokusu = ekran(terminal.backend().buffer());
        assert!(bez_fokusu.contains("Tab"), "widok:\n{}", bez_fokusu);

        terminal.draw(|f| draw_paths_panel(f, &app, f.area(), &mut ts, true)).unwrap();
        let z_fokusem = ekran(terminal.backend().buffer());
        assert!(z_fokusem.contains("aktywny"), "widok:\n{}", z_fokusem);
    }

    /// Sedno funkcji: przy treści krótszej niż widoczna wysokość (dzisiejszy
    /// stan — 9 linii w 9 widocznych wierszach) przewinięcie w dół musi się
    /// samo zatrzasnąć na zero, NIE chować treści poza ekranem.
    #[test]
    fn test_przewiniecie_gdy_tresc_miesci_sie_w_calosci_nie_chowa_niczego() {
        let mut u = Ustawienia::default();
        let mut app = AppState::new(&mut u).expect("stan menu musi się zbudować");
        app.tick_hw();

        let mut terminal = Terminal::new(TestBackend::new(80, WYSOKOSC_PANELU_SCIEZEK_MAX)).unwrap();
        let mut ts = TableState::default();
        ts.select(Some(500)); // "za daleko" przewinięte przed renderem

        terminal.draw(|f| draw_paths_panel(f, &app, f.area(), &mut ts, true)).unwrap();
        let widok = ekran(terminal.backend().buffer());

        assert_eq!(ts.selected(), Some(0), "zatrzask musi sprowadzić przewinięcie do zera, gdy cała treść i tak się mieści");
        assert!(widok.contains("Źródło UFS"), "pierwsza linia musi zostać widoczna:\n{}", widok);
    }

    /// Gdy treści faktycznie przybędzie ponad widoczną wysokość (przyszły
    /// scenariusz z dodatkowymi polami ustawień), przewinięcie musi realnie
    /// przesunąć widok, a nie zablokować się na zerze.
    #[test]
    fn test_przewiniecie_na_niskim_oknie_pokazuje_pozniejsze_linie() {
        let mut u = Ustawienia::default();
        let mut app = AppState::new(&mut u).expect("stan menu musi się zbudować");
        app.tick_hw();

        // Okno niższe niż treść (9 linii w oknie o wysokości 5, minus 2
        // obramowania = 3 widoczne wiersze) - symuluje sytuację, jaką da
        // dodanie kolejnych pól ustawień bez zmiany WYSOKOSC_PANELU_SCIEZEK_MAX.
        let mut terminal = Terminal::new(TestBackend::new(80, 5)).unwrap();
        let mut ts = TableState::default();

        terminal.draw(|f| draw_paths_panel(f, &app, f.area(), &mut ts, true)).unwrap();
        let od_gory = ekran(terminal.backend().buffer());
        assert!(od_gory.contains("Źródło UFS"), "bez przewinięcia widoczny musi być początek:\n{}", od_gory);
        assert!(!od_gory.contains("Szybki Skan"), "bez przewinięcia koniec NIE powinien być jeszcze widoczny:\n{}", od_gory);

        ts.select(Some(999));
        terminal.draw(|f| draw_paths_panel(f, &app, f.area(), &mut ts, true)).unwrap();
        let od_dolu = ekran(terminal.backend().buffer());
        assert!(od_dolu.contains("Szybki Skan"), "po przewinięciu do końca ostatnia linia musi być widoczna:\n{}", od_dolu);
    }
}
