// src/tui/scanner_panel.rs

//! # Komponent Paneli Skanera (Tabele)
//!
//! Zawiera logikę renderowania tabel Ratatui dla:
//! 1. Aktywnego Skanera (Live) - lewy panel ze statystykami.
//! 2. Dolnego paska ścieżek - szeroki panel pokazujący aktualne operacje I/O.

use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};

use crate::tui::hardware_panel::KOLOR_FOKUSU;
use crate::tui::settings_screen::centered_rect;
use crate::tui::state::PhaseUIState;

// ============================================================================
// ZNACZNIK INLINE DLA CZĘŚCIOWEGO KOLOROWANIA WARTOŚCI
// ============================================================================

/// Mapuje jednoliterowy kod koloru na `ratatui::style::Color`. Używane przez
/// [`parse_colored_value`] do interpretacji znacznika `{X:tekst}`.
fn markup_color(code: char) -> Option<Color> {
    match code {
        'G' => Some(Color::Green),
        'R' => Some(Color::Red),
        'Y' => Some(Color::Yellow),
        'C' => Some(Color::Cyan),
        'W' => Some(Color::White),
        'D' => Some(Color::DarkGray),
        'M' => Some(Color::Magenta),
        _ => None,
    }
}

/// Rozbija tekst WARTOŚCI (prawa strona linii `Etykieta: Wartość` w panelu
/// bocznym) na kolorowane fragmenty na podstawie lekkiego znacznika inline
/// `{X:tekst}`, gdzie `X` to jedna wielka litera koloru (patrz
/// [`markup_color`] — `G`=zielony, `R`=czerwony, `Y`=żółty, `C`=cyjan,
/// `W`=biały, `D`=szary, `M`=magenta).
///
/// Tekst POZA znacznikami dostaje domyślny styl (cyjan, pogrubiony) —
/// DOKŁADNIE taki sam, jaki wcześniej dostawała CAŁA wartość. Dzięki temu
/// fazy, które nie używają tego znacznika (16 z 17 na dzień wprowadzenia
/// tego mechanizmu), renderują się IDENTYCZNIE jak przed jego wprowadzeniem —
/// pełna wsteczna kompatybilność, zero zmian wizualnych bez świadomego
/// dodania znacznika w tekście źródłowym danej fazy.
///
/// Znaczniki niekompletne (brak `}`) lub z nieznaną literą koloru są
/// traktowane jako zwykły tekst — funkcja nigdy nie panikuje na
/// zniekształconym wejściu, po prostu wyświetla je dosłownie.
fn parse_colored_value(value: &str) -> Line<'static> {
    let default_style = Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut rest = value;

    while let Some(start) = rest.find('{') {
        if start > 0 {
            spans.push(Span::styled(rest[..start].to_string(), default_style));
        }
        let after_brace = &rest[start + 1..];
        let mut chars = after_brace.chars();
        let code = chars.next();
        let after_code = chars.as_str();

        let matched = match (code, after_code.strip_prefix(':')) {
            (Some(code_char), Some(after_colon)) => {
                match (markup_color(code_char), after_colon.find('}')) {
                    (Some(color), Some(end)) => Some((color, after_colon, end)),
                    _ => None,
                }
            }
            _ => None,
        };

        if let Some((color, after_colon, end)) = matched {
            let content = &after_colon[..end];
            spans.push(Span::styled(content.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD)));
            rest = &after_colon[end + 1..];
        } else {
            // Znacznik niekompletny/nieznany - '{' traktowany jako zwykły znak
            spans.push(Span::styled("{".to_string(), default_style));
            rest = &rest[start + 1..];
        }
    }

    if !rest.is_empty() {
        spans.push(Span::styled(rest.to_string(), default_style));
    }
    if spans.is_empty() {
        spans.push(Span::styled(String::new(), default_style));
    }

    Line::from(spans)
}

// ============================================================================
// TABELA STATYSTYK "AKTYWNY SKANER (LIVE)"
// ============================================================================

/// Minimalna szerokość kolumny wartości, poniżej której nie schodzimy nawet na
/// bardzo wąskim terminalu — przy mniejszej zawijanie produkowałoby kolumnę
/// jednoznakową, czyli nieczytelną kaszę.
const MIN_SZEROKOSC_WARTOSCI: usize = 12;

/// Górny limit szerokości kolumny etykiet.
///
/// Etykiety są krótkie („Prędkość", „Top format"), ale jedna nietypowo długa
/// linia z fazy nie może zabrać całej szerokości wartościom. Limit działa jak
/// bezpiecznik: kolumna dopasowuje się do treści, ale tylko do tego progu.
const MAKS_SZEROKOSC_ETYKIETY: usize = 34;

/// Jeden wiersz przygotowany do renderowania.
enum WierszPanelu {
    /// Nagłówek sekcji, np. `[UFS Explorer]` — zajmuje całą szerokość.
    Naglowek(String),
    /// Para `Etykieta: Wartość(ci)`.
    Para(String, Vec<Line<'static>>),
    /// Linia bez dwukropka — luźny komunikat.
    Luzna(String),
}

/// Zawija `Line` na linie o zadanej szerokości, ZACHOWUJĄC style fragmentów.
///
/// Ratatui nie łamie zawartości komórek zbudowanych z [`Line`] — nadmiar jest
/// po prostu ucinany przez silnik renderujący. Sztywne procenty szerokości
/// kolumn powodowały więc, że na wąskim terminalu długie wartości (np. lista
/// „Top format": `.mp4 (300GB), .jpg (100GB), …`) znikały bez śladu.
///
/// Łamanie odbywa się na granicy znaku, z preferencją spacji blisko limitu,
/// żeby nie ciąć słów w połowie. Podział przebiega WEWNĄTRZ fragmentów, więc
/// kolorowanie z [`parse_colored_value`] przeżywa zawinięcie — fragment
/// przecięty na dwie linie zachowuje swój styl po obu stronach.
fn wrap_line(line: &Line<'static>, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);

    let mut linie: Vec<Line<'static>> = Vec::new();
    let mut biezaca: Vec<Span<'static>> = Vec::new();
    let mut zajete = 0usize;

    for span in &line.spans {
        let styl = span.style;
        let znaki: Vec<char> = span.content.chars().collect();
        let mut i = 0usize;

        while i < znaki.len() {
            let wolne = width.saturating_sub(zajete);
            if wolne == 0 {
                linie.push(Line::from(std::mem::take(&mut biezaca)));
                zajete = 0;
                continue;
            }

            let mut ile = wolne.min(znaki.len() - i);

            // Jeśli tniemy w środku fragmentu, spróbuj cofnąć się do spacji -
            // ale tylko w drugiej połowie okna, żeby nie produkować linii
            // złożonych z kilku znaków.
            if i + ile < znaki.len()
                && let Some(sp) = znaki[i..i + ile].iter().rposition(|c| *c == ' ')
                    && sp + 1 > ile / 2 {
                        ile = sp + 1;
                    }

            let tekst: String = znaki[i..i + ile].iter().collect();
            biezaca.push(Span::styled(tekst, styl));
            zajete += ile;
            i += ile;

            if zajete >= width && i < znaki.len() {
                linie.push(Line::from(std::mem::take(&mut biezaca)));
                zajete = 0;
            }
        }
    }

    if !biezaca.is_empty() || linie.is_empty() {
        linie.push(Line::from(biezaca));
    }

    linie
}

/// Rysuje panel boczny w lewej kolumnie: "Aktywny Skaner (Live)" jako tabelę.
/// Wiersze w nawiasach kwadratowych `[...]` traktowane są jako nagłówki sekcji
/// (np. "[UFS Explorer]") i wyróżniane pogrubieniem. Wiersze z dwukropkiem
/// (`Etykieta: Wartość`) trafiają do dwóch kolumn tabeli.
///
/// Szerokości kolumn NIE są procentowe. Kolumna etykiet dostaje tyle, ile
/// faktycznie potrzebuje najdłuższa etykieta (z limitem
/// [`MAKS_SZEROKOSC_ETYKIETY`]), a cała reszta idzie na wartości, które są
/// ZAWIJANE przez [`wrap_line`], a nie przycinane. Dzięki temu treść rośnie w
/// dół, zamiast znikać za prawą krawędzią wąskiego terminala.
/// Paruje `state.side_texts` na wiersze gotowe do renderowania. Wydzielona
/// z [`draw_side_stats_panel`], żeby [`etykieta_wiersza`] mogła znać etykietę
/// zaznaczonego wiersza (np. do wyjaśnienia po Enter, patrz
/// `crate::opisy_anomalii`) BEZ duplikowania tej samej logiki parsowania —
/// jedno źródło prawdy dla „co panel pokazuje" i „co panel ma na wierszu N".
fn buduj_wiersze(state: &PhaseUIState) -> Vec<WierszPanelu> {
    let mut wiersze: Vec<WierszPanelu> = Vec::new();

    for block in &state.side_texts {
        if block.trim().is_empty() { continue; }

        for raw_line in block.lines() {
            let line = raw_line.trim();
            if line.is_empty() { continue; }

            // Nagłówek sekcji: "[UFS Explorer]", "[Skrypt Autorski]" itp.
            if line.starts_with('[') && line.ends_with(']') {
                wiersze.push(WierszPanelu::Naglowek(line.to_string()));
                continue;
            }

            // Standardowy wiersz "Etykieta: Wartość" (dopuszczamy emoji na początku etykiety)
            if let Some((label, value)) = line.split_once(": ") {
                let trimmed_label = label.trim().to_string();
                let mut lines = Vec::new();

                if trimmed_label.starts_with("Top ") {
                    let parts: Vec<&str> = value.trim().split(", ").collect();
                    for (i, part) in parts.iter().enumerate() {
                        let text = if i < parts.len() - 1 {
                            format!("{},", part)
                        } else {
                            part.to_string()
                        };
                        lines.push(parse_colored_value(&text));
                    }
                } else if value.contains(" | ") {
                    let parts: Vec<&str> = value.trim().split(" | ").collect();
                    for part in parts {
                        lines.push(parse_colored_value(part));
                    }
                } else {
                    lines.push(parse_colored_value(value.trim()));
                }

                wiersze.push(WierszPanelu::Para(trimmed_label, lines));
            } else {
                wiersze.push(WierszPanelu::Luzna(line.to_string()));
            }
        }
    }

    if wiersze.is_empty() {
        wiersze.push(WierszPanelu::Luzna("Oczekiwanie na dane telemetryczne...".to_string()));
    }

    wiersze
}

/// Etykieta wiersza pod danym indeksem (jak by go zobaczył operator w
/// panelu), do użytku poza renderem — np. wyszukanie wyjaśnienia po
/// naciśnięciu Enter na zaznaczonym wierszu. `None` dla nagłówków sekcji,
/// luźnych linii (bez dwukropka) i indeksu poza zakresem — te przypadki nie
/// mają etykiety w sensie "Etykieta: Wartość", więc bezpiecznie nic się nie
/// dzieje, zamiast szukać wyjaśnienia dla czegoś, co go nie ma.
pub fn etykieta_wiersza(state: &PhaseUIState, indeks: usize) -> Option<String> {
    match buduj_wiersze(state).into_iter().nth(indeks) {
        Some(WierszPanelu::Para(etykieta, _)) => Some(etykieta),
        _ => None,
    }
}

/// Rysuje nakładkę z wyjaśnieniem etykiety wiersza (Enter na zaznaczonym
/// wierszu "Aktywny Skaner Live", patrz `crate::opisy_anomalii` i
/// `menu::actions::run_phase_z_opcjami`). Ten sam idiom co popupy
/// `settings_screen.rs` (`centered_rect` + `Clear` + `Paragraph` w `Block`),
/// z jedną różnicą: treść wyjaśnienia bywa dłuższa niż jedna linia, więc
/// dostaje `Wrap` zamiast pozostać nieprzycięta.
pub fn draw_opis_popup(f: &mut Frame, area: Rect, etykieta: &str, wyjasnienie: &str) {
    let popup_area = centered_rect(60, 40, area);
    f.render_widget(Clear, popup_area);

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(wyjasnienie.to_string(), Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(Span::styled("[ENTER]/[ESC] Zamknij", Style::default().fg(Color::DarkGray))),
    ];

    let paragraph = Paragraph::new(lines)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", etykieta))
                .border_style(Style::default().fg(KOLOR_FOKUSU).add_modifier(Modifier::BOLD)),
        );
    f.render_widget(paragraph, popup_area);
}

/// Rysuje panel statystyk "Aktywny Skaner (Live)". Fokusowalny klawiszem Tab
/// na ekranie fazy na żywo — patrz dokumentacja `hardware_panel::draw_disks_panel`
/// dla wyjaśnienia `table_state`/`focused` (ten sam wzorzec).
pub fn draw_side_stats_panel(f: &mut Frame, state: &PhaseUIState, area: Rect, table_state: &mut TableState, focused: bool) {
    let wiersze = buduj_wiersze(state);

    // Zatrzask WEWNĄTRZ funkcji, nie w wywołującym: liczba wierszy tego
    // panelu wynika z parsowania `state.side_texts` WYŻEJ (nagłówki, pary
    // etykieta/wartość, luźne linie) — jedyne miejsce, które faktycznie zna
    // aktualną liczbę wierszy w danej klatce. Klawiatura (`menu/actions.rs`)
    // przesuwa `table_state.selected()` bez znajomości tej liczby (rośnie/maleje
    // swobodnie); ten zatrzask samoleczy się na KAŻDEJ klatce, więc np.
    // skurczenie się `side_texts` między naciśnięciami klawiszy nigdy nie
    // zostawia zaznaczenia poza zakresem.
    if let Some(i) = table_state.selected()
        && i >= wiersze.len() {
            table_state.select(if wiersze.is_empty() { None } else { Some(wiersze.len() - 1) });
        }
    let wybrany = table_state.selected();

    // --- Dynamiczny podział szerokości ---
    let najdluzsza_etykieta = wiersze
        .iter()
        .filter_map(|w| match w {
            WierszPanelu::Para(etykieta, _) => Some(etykieta.chars().count()),
            _ => None,
        })
        .max()
        .unwrap_or(0);

    // Wnętrze bloku: szerokość minus obramowanie (1+1) i odstęp między
    // kolumnami, jaki Ratatui wstawia domyślnie.
    let dostepne = area.width.saturating_sub(3) as usize;

    let szerokosc_etykiety = najdluzsza_etykieta
        .min(MAKS_SZEROKOSC_ETYKIETY)
        .min(dostepne.saturating_sub(MIN_SZEROKOSC_WARTOSCI))
        .max(1);
    let szerokosc_wartosci = dostepne.saturating_sub(szerokosc_etykiety).max(1);

    let rows: Vec<Row> = wiersze
        .into_iter()
        .enumerate()
        .map(|(i, w)| {
            let zaznaczony = wybrany == Some(i);
            let prefix = if zaznaczony { "❯ " } else { "" };
            match w {
                WierszPanelu::Naglowek(tekst) => Row::new(vec![
                    Cell::from(format!("{}{}", prefix, tekst)).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Cell::from(""),
                ]),
                WierszPanelu::Luzna(tekst) => Row::new(vec![
                    Cell::from(format!("{}{}", prefix, tekst)).style(Style::default().fg(Color::White)),
                    Cell::from(""),
                ]),
                WierszPanelu::Para(etykieta, wartosci) => {
                    let mut wszystkie_zawiniete = Vec::new();
                    for w in wartosci {
                        wszystkie_zawiniete.extend(wrap_line(&w, szerokosc_wartosci));
                    }

                    let wysokosc = wszystkie_zawiniete.len().max(1) as u16;
                    let etykieta_styl = if zaznaczony {
                        Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    Row::new(vec![
                        Cell::from(format!("{}{}", prefix, etykieta)).style(etykieta_styl),
                        Cell::from(Text::from(wszystkie_zawiniete)),
                    ])
                    .height(wysokosc)
                }
            }
        })
        .collect();

    let tytul = if focused { " ▶ Aktywny Skaner — Statystyki (Live) (aktywny — ↑↓ PgUp/PgDn) " } else { " Aktywny Skaner — Statystyki (Live) [Tab] " };
    let border_styl = if focused { Style::default().fg(KOLOR_FOKUSU).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Yellow) };

    let table = Table::new(
        rows,
        &[
            Constraint::Length(szerokosc_etykiety as u16),
            Constraint::Min(MIN_SZEROKOSC_WARTOSCI as u16),
        ],
    )
        .header(
            Row::new(vec!["METRYKA", "WARTOŚĆ"])
                .style(Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD))
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(tytul)
                .border_style(border_styl)
        );

    f.render_stateful_widget(table, area, table_state);
}

// ============================================================================
// TABELA PEŁNYCH ŚCIEŻEK SKANOWANYCH PLIKÓW
// ============================================================================

/// Rysuje szeroki panel na samym dole ekranu: "Aktualnie skanowane ścieżki" jako tabelę.
/// Obsługuje dowolną liczbę źródeł (nie tylko sztywne UFS/Skrypt) — jeśli `bottom_paths`
/// będzie mieć więcej niż 2 wpisy w przyszłości (np. trzecie źródło danych), tabela
/// automatycznie doda kolejny wiersz z etykietą "Źródło N".
/// Dzieli tekst na linie o maksymalnej długości `width` ZNAKÓW (nie bajtów —
/// bezpieczne dla wielobajtowych znaków UTF-8, np. polskich nazw plików).
/// Preferuje łamanie na granicy `/` blisko limitu (nie przecina nazwy pliku
/// ani katalogu w połowie, o ile granica `/` mieści się w drugiej połowie
/// okna); w przeciwnym razie twardo łamie dokładnie na `width` znaków.
/// Nigdy nie zwraca pustego wektora — pusty tekst wejściowy daje jedną,
/// pustą linię (żeby wiersz tabeli miał sensowną wysokość min. 1).
fn wrap_path(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() { return vec![String::new()]; }

    let mut lines = Vec::new();
    let mut start = 0;
    while start < chars.len() {
        let mut end = (start + width).min(chars.len());
        if end < chars.len()
            && let Some(slash_pos) = chars[start..end].iter().rposition(|&c| c == '/') {
                let candidate = start + slash_pos + 1;
                if candidate > start + width / 2 {
                    end = candidate;
                }
            }
        lines.push(chars[start..end].iter().collect());
        start = end;
    }
    lines
}

/// Rysuje szeroki panel na samym dole ekranu: "Aktualnie skanowane ścieżki" jako tabelę.
/// Obsługuje dowolną liczbę źródeł (nie tylko sztywne UFS/Skrypt) — jeśli `bottom_paths`
/// będzie mieć więcej niż 2 wpisy w przyszłości (np. trzecie źródło danych), tabela
/// automatycznie doda kolejny wiersz z etykietą "Źródło N".
///
/// Długie ścieżki są ZAWIJANE na wiele linii (patrz [`wrap_path`]), nie przycinane —
/// wysokość każdego wiersza dopasowuje się do liczby linii, jakich wymaga JEGO ścieżka.
/// Fokusowalny klawiszem Tab na ekranie fazy na żywo — patrz dokumentacja
/// `hardware_panel::draw_disks_panel` dla wyjaśnienia `table_state`/`focused`.
/// Etykiety źródeł wbudowane na stałe. Jedyne miejsce prawdy o tym, ILE
/// wierszy ma [`draw_bottom_paths_panel`] przy braku danych — dzieli je z
/// [`liczba_wierszy_sciezek`], którego używa klawiatura ekranu fazy
/// (`menu/actions.rs`) do Home/End/PageUp/PageDown, żeby nigdy nie rozjechać
/// się z tym, co panel faktycznie rysuje.
const ZNANE_ZRODLA: [&str; 2] = ["UFS Explorer", "Skrypt Autorski"];

/// Liczba wierszy, jaką [`draw_bottom_paths_panel`] narysuje dla danego
/// stanu — patrz [`ZNANE_ZRODLA`].
pub fn liczba_wierszy_sciezek(state: &PhaseUIState) -> usize {
    ZNANE_ZRODLA.len().max(state.bottom_paths.len())
}

pub fn draw_bottom_paths_panel(f: &mut Frame, state: &PhaseUIState, area: Rect, table_state: &mut TableState, focused: bool) {
    let known_labels = ZNANE_ZRODLA;

    const SOURCE_COL_WIDTH: u16 = 20;
    // Odejmujemy: kolumnę źródła, obramowanie bloku (1+1) i odstęp między
    // kolumnami Ratatui (domyślnie 1) — konserwatywny margines, żeby zawsze
    // zmieścić się faktycznie dostępnej szerokości, nigdy jej nie przekroczyć.
    let path_col_width = area.width.saturating_sub(SOURCE_COL_WIDTH + 4).max(10) as usize;

    // Liczba wierszy wynika z ARCHITEKTURY (ile źródeł znamy), a nie z tego,
    // ile z nich zdążyło już przysłać dane. Wcześniej pętla szła po
    // `bottom_paths` i odfiltrowywała puste wpisy, więc dopóki drugie źródło
    // milczało, tabela miała jeden wiersz i layout „podskakiwał" przy każdym
    // napływie danych z wątku logującego. Teraz wysokość panelu jest stabilna
    // od pierwszej klatki.
    let liczba_zrodel = liczba_wierszy_sciezek(state);

    // Samoleczący zatrzask — patrz identyczny wzorzec i uzasadnienie w
    // `draw_side_stats_panel`/`hardware_panel::draw_disks_panel`.
    if let Some(i) = table_state.selected()
        && i >= liczba_zrodel {
            table_state.select(if liczba_zrodel == 0 { None } else { Some(liczba_zrodel - 1) });
        }
    let wybrany = table_state.selected();

    let rows: Vec<Row> = (0..liczba_zrodel)
        .map(|i| {
            let source_label = known_labels.get(i).copied()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("Źródło {}", i + 1));

            let sciezka = state.bottom_paths.get(i).map(String::as_str).unwrap_or("");

            let (path_text, row_height, styl) = if sciezka.is_empty() {
                (
                    Text::from(Line::from("(Oczekiwanie na dane...)")),
                    1u16,
                    Style::default().fg(Color::DarkGray),
                )
            } else {
                // format_display_path zabezpiecza terminal przed znakami kontrolnymi/emoji
                // w nazwach plików (patrz utils.rs) PRZED zawinięciem na linie.
                let sanitized = crate::utils::format_display_path(sciezka);
                let wrapped_lines = wrap_path(&sanitized, path_col_width);
                let wysokosc = wrapped_lines.len() as u16;
                (
                    Text::from(wrapped_lines.into_iter().map(Line::from).collect::<Vec<_>>()),
                    wysokosc,
                    Style::default().fg(Color::White),
                )
            };

            let zaznaczony = wybrany == Some(i);
            let prefix = if zaznaczony { "❯ " } else { "" };

            Row::new(vec![
                Cell::from(format!("{}{}", prefix, source_label)).style(
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                ),
                Cell::from(path_text).style(styl),
            ]).height(row_height)
        })
        .collect();

    let tytul = if focused { " ▶ Aktualnie skanowane ścieżki (I/O) (aktywny — ↑↓ PgUp/PgDn) " } else { " Aktualnie skanowane ścieżki (I/O) [Tab] " };
    let border_styl = if focused { Style::default().fg(KOLOR_FOKUSU).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Cyan) };

    let table = Table::new(rows, &[Constraint::Length(SOURCE_COL_WIDTH), Constraint::Min(20)])
        .header(
            Row::new(vec!["ŹRÓDŁO", "PEŁNA ŚCIEŻKA PLIKU (I/O)"])
                .style(Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD))
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(tytul)
                .border_style(border_styl)
        );

    f.render_stateful_widget(table, area, table_state);
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn span_texts_and_colors(line: &Line) -> Vec<(String, Option<Color>)> {
        line.spans.iter().map(|s| (s.content.to_string(), s.style.fg)).collect()
    }

    #[test]
    fn test_markup_color_known_codes() {
        assert_eq!(markup_color('G'), Some(Color::Green));
        assert_eq!(markup_color('R'), Some(Color::Red));
        assert_eq!(markup_color('Y'), Some(Color::Yellow));
        assert_eq!(markup_color('D'), Some(Color::DarkGray));
    }

    #[test]
    fn test_markup_color_unknown_code_is_none() {
        assert_eq!(markup_color('Z'), None);
        assert_eq!(markup_color('x'), None); // małe litery celowo nieobsługiwane
    }

    #[test]
    fn test_parse_colored_value_plain_text_no_markup() {
        // Wsteczna kompatybilność: brak znaczników = jeden span, domyślny styl
        let line = parse_colored_value("15 plików wspólnych");
        let spans = span_texts_and_colors(&line);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].0, "15 plików wspólnych");
        assert_eq!(spans[0].1, Some(Color::Cyan));
    }

    #[test]
    fn test_parse_colored_value_single_marker() {
        let line = parse_colored_value("{G:Exiftool-rs}");
        let spans = span_texts_and_colors(&line);
        assert_eq!(spans, vec![("Exiftool-rs".to_string(), Some(Color::Green))]);
    }

    #[test]
    fn test_parse_colored_value_marker_with_surrounding_text() {
        let line = parse_colored_value("Silnik: {G:RS} aktywny");
        let spans = span_texts_and_colors(&line);
        assert_eq!(spans, vec![
            ("Silnik: ".to_string(), Some(Color::Cyan)),
            ("RS".to_string(), Some(Color::Green)),
            (" aktywny".to_string(), Some(Color::Cyan)),
        ]);
    }

    #[test]
    fn test_parse_colored_value_multiple_markers_and_colons_inside() {
        // Dokładnie ten przypadek z Fazy 12: kolory + literalne dwukropki
        // wewnątrz tekstu, poza samą składnią znacznika.
        let line = parse_colored_value("{G:Exiftool-rs} ({G:RS}: 15 | {R:CLI}: 3)");
        let spans = span_texts_and_colors(&line);
        assert_eq!(spans, vec![
            ("Exiftool-rs".to_string(), Some(Color::Green)),
            (" (".to_string(), Some(Color::Cyan)),
            ("RS".to_string(), Some(Color::Green)),
            (": 15 | ".to_string(), Some(Color::Cyan)),
            ("CLI".to_string(), Some(Color::Red)),
            (": 3)".to_string(), Some(Color::Cyan)),
        ]);
    }

    #[test]
    fn test_parse_colored_value_unknown_color_code_is_literal() {
        let line = parse_colored_value("{Z:tekst}");
        let spans = span_texts_and_colors(&line);
        // Nieznany kod koloru -> '{' dosłowny, reszta jako zwykły ciąg
        assert_eq!(spans, vec![
            ("{".to_string(), Some(Color::Cyan)),
            ("Z:tekst}".to_string(), Some(Color::Cyan)),
        ]);
    }

    #[test]
    fn test_parse_colored_value_unclosed_marker_is_literal() {
        let line = parse_colored_value("{G:brak zamkniecia");
        let spans = span_texts_and_colors(&line);
        assert_eq!(spans, vec![
            ("{".to_string(), Some(Color::Cyan)),
            ("G:brak zamkniecia".to_string(), Some(Color::Cyan)),
        ]);
    }

    #[test]
    fn test_parse_colored_value_empty_string() {
        let line = parse_colored_value("");
        let spans = span_texts_and_colors(&line);
        assert_eq!(spans, vec![("".to_string(), Some(Color::Cyan))]);
    }

    #[test]
    fn test_parse_colored_value_never_panics_on_lone_brace() {
        // Regresja: samotny '{' na końcu stringu nie powinien crashować
        let _ = parse_colored_value("tekst {");
        let _ = parse_colored_value("{");
        let _ = parse_colored_value("{G:");
        let _ = parse_colored_value("{G");
    }

    // ------------------------------------------------------------------
    // wrap_path
    // ------------------------------------------------------------------

    #[test]
    fn test_wrap_path_short_text_single_line() {
        assert_eq!(wrap_path("krotka/sciezka.txt", 50), vec!["krotka/sciezka.txt".to_string()]);
    }

    #[test]
    fn test_wrap_path_empty_text_returns_one_empty_line() {
        assert_eq!(wrap_path("", 20), vec!["".to_string()]);
    }

    #[test]
    fn test_wrap_path_breaks_at_slash_when_near_limit() {
        // "/mnt/dane" (9 znaków) + "/plik.txt" - limit 12 znaków.
        // Okno [0..12) = "/mnt/dane/pl" - ostatni '/' na pozycji 9, w drugiej połowie okna (>6) - powinno złamać tam.
        let result = wrap_path("/mnt/dane/plik.txt", 12);
        assert_eq!(result[0], "/mnt/dane/");
        assert_eq!(result[1], "plik.txt");
    }

    #[test]
    fn test_wrap_path_hard_wraps_when_no_good_slash_boundary() {
        // Brak '/' w ogóle - musi twardo złamać dokładnie na `width` znaków.
        let result = wrap_path("abcdefghijklmnop", 5);
        assert_eq!(result, vec!["abcde", "fghij", "klmno", "p"]);
    }

    #[test]
    fn test_wrap_path_never_loses_characters() {
        let original = "/mnt/skrypt_sdb1_ro_root/@snapshots/@data/bardzo/dlugi/plik_z_polskimi_znakami_zazolc.txt";
        let wrapped = wrap_path(original, 15);
        let rejoined: String = wrapped.concat();
        assert_eq!(rejoined, original, "Zawijanie nie może gubić ani duplikować żadnego znaku");
    }

    #[test]
    fn test_wrap_path_handles_polish_diacritics_correctly() {
        // Znaki wielobajtowe UTF-8 - liczone jako pojedyncze znaki, nie bajty.
        let result = wrap_path("źółć/ęąśń/plik.txt", 5);
        // Suma znaków we wszystkich liniach musi się zgadzać ze znakami oryginału
        let total_chars: usize = result.iter().map(|l| l.chars().count()).sum();
        assert_eq!(total_chars, "źółć/ęąśń/plik.txt".chars().count());
    }

    #[test]
    fn test_wrap_path_minimum_width_of_one_never_panics() {
        // width=0 powinno być bezpiecznie podniesione do minimum 1, nie zapętlić się w nieskończoność.
        let result = wrap_path("abc", 0);
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    // ------------------------------------------------------------------
    // RESPONSYWNOŚĆ — render do bufora (ratatui TestBackend)
    //
    // Ratatui nie łamie zawartości komórek: nadmiar jest przycinany przez
    // silnik renderujący. Testy poniżej renderują panele na WĄSKIM terminalu
    // i sprawdzają w buforze, że treść faktycznie tam jest — przycięcie
    // objawiłoby się brakiem końcówki wartości.
    // ------------------------------------------------------------------

    use ratatui::{backend::TestBackend, Terminal};

    fn ekran(bufor: &ratatui::buffer::Buffer) -> String {
        (0..bufor.area.height)
            .map(|y| (0..bufor.area.width).map(|x| bufor[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn stan_z_tekstem(tekst: &str) -> PhaseUIState {
        let mut st = PhaseUIState::new("x", "t", "k", "o");
        st.side_texts.push(tekst.to_string());
        st
    }

    fn wyrenderuj<F: FnOnce(&mut ratatui::Frame)>(szer: u16, wys: u16, f: F) -> ratatui::buffer::Buffer {
        let mut terminal = Terminal::new(TestBackend::new(szer, wys)).unwrap();
        terminal.draw(|frame| f(frame)).unwrap();
        terminal.backend().buffer().clone()
    }

    // --- wrap_line ---

    #[test]
    fn test_wrap_line_zachowuje_style_fragmentow() {
        let linia = Line::from(vec![
            Span::styled("zielony_dlugi ", Style::default().fg(Color::Green)),
            Span::styled("czerwony_dlugi", Style::default().fg(Color::Red)),
        ]);

        let zawiniete = wrap_line(&linia, 10);

        assert!(zawiniete.len() > 1, "tekst dłuższy niż okno musi zostać zawinięty");

        // Każdy fragment zachowuje swój kolor po obu stronach podziału.
        let kolory: Vec<Option<Color>> = zawiniete.iter()
            .flat_map(|l| l.spans.iter().map(|s| s.style.fg))
            .collect();
        assert!(kolory.contains(&Some(Color::Green)), "kolor pierwszego fragmentu musi przeżyć: {:?}", kolory);
        assert!(kolory.contains(&Some(Color::Red)), "kolor drugiego fragmentu musi przeżyć: {:?}", kolory);

        // Nic nie ginie: suma znaków po zawinięciu równa się wejściu.
        let razem: String = zawiniete.iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect();
        assert_eq!(razem, "zielony_dlugi czerwony_dlugi", "zawijanie nie może gubić ani dodawać znaków");
    }

    #[test]
    fn test_wrap_line_nie_przekracza_szerokosci() {
        let linia = Line::from("a".repeat(95));
        for l in wrap_line(&linia, 20) {
            let dlugosc: usize = l.spans.iter().map(|s| s.content.chars().count()).sum();
            assert!(dlugosc <= 20, "linia ma {} znaków przy limicie 20", dlugosc);
        }
    }

    #[test]
    fn test_wrap_line_na_pustym_wejsciu_daje_jedna_linie() {
        // Wiersz tabeli musi mieć wysokość co najmniej 1.
        assert_eq!(wrap_line(&Line::from(""), 10).len(), 1);
    }

    // --- panel statystyk ---

    /// Sedno punktu 1: długa wartość na wąskim terminalu ma się ZAWINĄĆ, a nie
    /// zniknąć za prawą krawędzią.
    #[test]
    fn test_dluga_wartosc_nie_jest_przycinana_na_waskim_terminalu() {
        let st = stan_z_tekstem("Top format: .mp4 (300GB), .jpg (100GB), .dng (55GB), .heic (12GB)");

        let bufor = wyrenderuj(46, 12, |f| draw_side_stats_panel(f, &st, f.area(), &mut TableState::default(), false));
        let widok = ekran(&bufor);

        assert!(widok.contains("Top format"), "etykieta musi być widoczna:\n{}", widok);
        assert!(widok.contains(".mp4 (300GB)"), "początek wartości musi być widoczny:\n{}", widok);
        assert!(
            widok.contains(".heic (12GB)"),
            "KOŃCÓWKA wartości musi przetrwać zawinięcie - jej brak oznacza przycięcie:\n{}", widok
        );
    }

    #[test]
    fn test_kolumna_etykiet_dopasowuje_sie_do_tresci() {
        // Krótkie etykiety nie mogą zabierać połowy szerokości, jak robiły to
        // sztywne procenty - wartość musi dostać resztę miejsca.
        let st = stan_z_tekstem("Cel: /bardzo/dluga/sciezka/ktora/potrzebuje/miejsca/zeby/sie/zmiescic");

        let bufor = wyrenderuj(60, 10, |f| draw_side_stats_panel(f, &st, f.area(), &mut TableState::default(), false));
        let widok = ekran(&bufor);

        assert!(widok.contains("/bardzo/dluga/sciezka"), "widok:\n{}", widok);
        assert!(widok.contains("zmiescic"), "końcówka musi być widoczna:\n{}", widok);
    }

    #[test]
    fn test_panel_statystyk_nie_panikuje_na_skrajnie_malym_oknie() {
        let st = stan_z_tekstem("[UFS Explorer]\nPrędkość: 12.5 MB/s\nTop format: .mp4 (300GB), .jpg (100GB)");

        for (szer, wys) in [(10u16, 3u16), (5, 5), (20, 1), (1, 1), (80, 2)] {
            let _ = wyrenderuj(szer, wys, |f| draw_side_stats_panel(f, &st, f.area(), &mut TableState::default(), false));
        }
    }

    // --- dolny panel ścieżek ---

    /// Sedno punktu 4: wiersz na każde znane źródło, także zanim spłyną dane.
    #[test]
    fn test_panel_sciezek_pokazuje_wszystkie_zrodla_mimo_braku_danych() {
        let mut st = PhaseUIState::new("x", "t", "k", "o");
        st.bottom_paths = vec!["/mnt/ufs/zdjecia/DSC_0001.dng".to_string()]; // Źródło B jeszcze milczy

        let bufor = wyrenderuj(90, 10, |f| draw_bottom_paths_panel(f, &st, f.area(), &mut TableState::default(), false));
        let widok = ekran(&bufor);

        assert!(widok.contains("UFS Explorer"), "widok:\n{}", widok);
        assert!(
            widok.contains("Skrypt Autorski"),
            "drugie źródło musi mieć wiersz mimo braku danych - inaczej layout skacze przy każdym napływie:\n{}", widok
        );
        assert!(widok.contains("Oczekiwanie na dane"), "brak danych musi być nazwany wprost:\n{}", widok);
    }

    #[test]
    fn test_panel_sciezek_obsluguje_trzecie_zrodlo() {
        let mut st = PhaseUIState::new("x", "t", "k", "o");
        st.bottom_paths = vec!["/a/1".to_string(), "/b/2".to_string(), "/c/3".to_string()];

        let widok = ekran(&wyrenderuj(90, 12, |f| draw_bottom_paths_panel(f, &st, f.area(), &mut TableState::default(), false)));

        assert!(widok.contains("UFS Explorer") && widok.contains("Skrypt Autorski"));
        assert!(widok.contains("Źródło 3"), "nadmiarowe źródła dostają etykietę generyczną:\n{}", widok);
    }

    #[test]
    fn test_panel_sciezek_nie_panikuje_na_malym_oknie() {
        let mut st = PhaseUIState::new("x", "t", "k", "o");
        st.bottom_paths = vec!["/bardzo/dluga/sciezka/do/pliku.dng".to_string(), String::new()];

        for (szer, wys) in [(12u16, 3u16), (30, 1), (1, 1), (200, 4)] {
            let _ = wyrenderuj(szer, wys, |f| draw_bottom_paths_panel(f, &st, f.area(), &mut TableState::default(), false));
        }
    }

    // ------------------------------------------------------------------
    // FOKUS I ZAZNACZENIE (Tab między panelami na ekranie fazy na żywo)
    // ------------------------------------------------------------------

    #[test]
    fn test_tytul_panelu_statystyk_odzwierciedla_fokus() {
        let st = stan_z_tekstem("Prędkość: 12.5 MB/s");

        let bez_fokusu = ekran(&wyrenderuj(70, 10, |f| draw_side_stats_panel(f, &st, f.area(), &mut TableState::default(), false)));
        assert!(bez_fokusu.contains("Tab"), "widok:\n{}", bez_fokusu);

        let z_fokusem = ekran(&wyrenderuj(70, 10, |f| draw_side_stats_panel(f, &st, f.area(), &mut TableState::default(), true)));
        assert!(z_fokusem.contains("aktywny"), "widok:\n{}", z_fokusem);
    }

    #[test]
    fn test_zaznaczony_wiersz_statystyk_ma_widoczny_prefiks() {
        let st = stan_z_tekstem("Prędkość: 12.5 MB/s");
        let mut ts = TableState::default();
        ts.select(Some(0));

        let widok = ekran(&wyrenderuj(70, 10, |f| draw_side_stats_panel(f, &st, f.area(), &mut ts, false)));
        assert!(widok.contains("❯"), "zaznaczenie musi być widoczne niezależnie od fokusu:\n{}", widok);
    }

    /// `selected()` poza aktualną liczbą wierszy (np. `side_texts` się
    /// skurczyło między klatkami) nie może panikować.
    #[test]
    fn test_zaznaczenie_statystyk_poza_zakresem_nie_panikuje() {
        let st = stan_z_tekstem("Prędkość: 12.5 MB/s");
        let mut ts = TableState::default();
        ts.select(Some(999));

        let _ = wyrenderuj(70, 10, |f| draw_side_stats_panel(f, &st, f.area(), &mut ts, true));
    }

    #[test]
    fn test_tytul_panelu_sciezek_odzwierciedla_fokus() {
        let st = PhaseUIState::new("x", "t", "k", "o");

        let bez_fokusu = ekran(&wyrenderuj(90, 10, |f| draw_bottom_paths_panel(f, &st, f.area(), &mut TableState::default(), false)));
        assert!(bez_fokusu.contains("Tab"), "widok:\n{}", bez_fokusu);

        let z_fokusem = ekran(&wyrenderuj(90, 10, |f| draw_bottom_paths_panel(f, &st, f.area(), &mut TableState::default(), true)));
        assert!(z_fokusem.contains("aktywny"), "widok:\n{}", z_fokusem);
    }

    #[test]
    fn test_zaznaczone_zrodlo_ma_widoczny_prefiks() {
        let st = PhaseUIState::new("x", "t", "k", "o");
        let mut ts = TableState::default();
        ts.select(Some(1));

        let widok = ekran(&wyrenderuj(90, 10, |f| draw_bottom_paths_panel(f, &st, f.area(), &mut ts, false)));
        assert!(widok.contains("❯"), "zaznaczenie musi być widoczne niezależnie od fokusu:\n{}", widok);
    }

    #[test]
    fn test_zaznaczenie_sciezek_poza_zakresem_nie_panikuje() {
        let st = PhaseUIState::new("x", "t", "k", "o");
        let mut ts = TableState::default();
        ts.select(Some(999));

        let _ = wyrenderuj(90, 10, |f| draw_bottom_paths_panel(f, &st, f.area(), &mut ts, true));
    }

    // ------------------------------------------------------------------
    // ETYKIETA WIERSZA I NAKŁADKA WYJAŚNIENIA (Enter na "Aktywny Skaner Live")
    // ------------------------------------------------------------------

    fn stan_anomalii() -> PhaseUIState {
        stan_z_tekstem("[Anomalie pierwszego klastra]\nPrzesunięty nagłówek: 2\nNull-padding: 0")
    }

    #[test]
    fn test_etykieta_wiersza_zwraca_etykiete_pary() {
        let st = stan_anomalii();
        // indeks 0 = nagłówek "[Anomalie pierwszego klastra]", 1 = pierwsza para
        assert_eq!(etykieta_wiersza(&st, 1).as_deref(), Some("Przesunięty nagłówek"));
        assert_eq!(etykieta_wiersza(&st, 2).as_deref(), Some("Null-padding"));
    }

    #[test]
    fn test_etykieta_wiersza_nagłówka_sekcji_to_none() {
        let st = stan_anomalii();
        assert_eq!(etykieta_wiersza(&st, 0), None, "wiersz [Anomalie pierwszego klastra] to nagłówek, nie para etykieta:wartość");
    }

    #[test]
    fn test_etykieta_wiersza_poza_zakresem_to_none() {
        let st = stan_anomalii();
        assert_eq!(etykieta_wiersza(&st, 999), None);
    }

    #[test]
    fn test_etykieta_wiersza_luznej_linii_to_none() {
        let st = stan_z_tekstem("linia bez dwukropka");
        assert_eq!(etykieta_wiersza(&st, 0), None);
    }

    #[test]
    fn test_nakladka_opisu_pokazuje_tytul_i_tresc() {
        let widok = ekran(&wyrenderuj(80, 24, |f| {
            draw_opis_popup(f, f.area(), "Przesunięty nagłówek", "Sygnatura pliku znaleziona nie na początku klastra.")
        }));
        assert!(widok.contains("Przesunięty nagłówek"), "widok:\n{}", widok);
        assert!(widok.contains("Sygnatura pliku"), "widok:\n{}", widok);
        assert!(widok.contains("Zamknij"), "widok:\n{}", widok);
    }

    #[test]
    fn test_nakladka_opisu_nie_panikuje_na_skrajnych_rozmiarach() {
        for (szer, wys) in [(1u16, 1u16), (10, 3), (20, 5), (200, 60)] {
            let _ = wyrenderuj(szer, wys, |f| draw_opis_popup(f, f.area(), "X", "długi tekst wyjaśnienia ".repeat(20).as_str()));
        }
    }
}
