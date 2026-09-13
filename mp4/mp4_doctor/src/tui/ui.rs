//! MP4 Doctor 2.0 - Responsive TUI Layout & Widget Rendering
//!
//! Provides rendering routines for the header, interactive menu lists,
//! operation status dashboard, modal dialogs, and navigation footer.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Clear, LineGauge, List, ListItem, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Wrap,
    },
    Frame,
};

use crate::tui::app::{App, Modal, View};

/// Returns the terminal display width of a string.
pub fn str_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

fn char_width(c: char) -> usize {
    if c == '\t' {
        4
    } else if (c as u32) >= 0x1100
        && ((c as u32) <= 0x115f
            || (c as u32) >= 0x2329 && (c as u32) <= 0x232a
            || (c as u32) >= 0x2e80 && (c as u32) <= 0xa4cf
            || (c as u32) >= 0xac00 && (c as u32) <= 0xd7a3
            || (c as u32) >= 0xf900 && (c as u32) <= 0xfaff
            || (c as u32) >= 0xfe10 && (c as u32) <= 0xfe19
            || (c as u32) >= 0xfe30 && (c as u32) <= 0xfe6f
            || (c as u32) >= 0xff00 && (c as u32) <= 0xff60
            || (c as u32) >= 0xffe0 && (c as u32) <= 0xffe6
            || (c as u32) >= 0x1f000 && (c as u32) <= 0x1f9ff)
    {
        2
    } else if c.is_control() {
        0
    } else {
        1
    }
}

/// Formats raw byte counts into human-readable binary units (B, KB, MB, GB, TB).
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Truncates a string to at most max_len visible characters, appending '…' if truncated.
pub fn truncate_str(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_len.saturating_sub(1)).collect();
        format!("{}…", truncated)
    }
}

/// Formats a LogMessage into an aligned, color-coded Ratatui Line.
pub fn format_log_line(msg: &crate::event::LogMessage) -> Line<'static> {
    let time_span = Span::styled(
        format!("{} ", msg.formatted_time()),
        Style::default().fg(Color::DarkGray),
    );

    let (badge_style, badge_text, msg_style) = match msg.level {
        crate::event::LogLevel::Debug => (
            Style::default().fg(Color::DarkGray),
            "[DEBUG]",
            Style::default().fg(Color::DarkGray),
        ),
        crate::event::LogLevel::Info => (
            Style::default().fg(Color::Cyan),
            "[INFO ]",
            Style::default().fg(Color::White),
        ),
        crate::event::LogLevel::Success => (
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            "[SUCC ]",
            Style::default().fg(Color::LightGreen),
        ),
        crate::event::LogLevel::Warn => (
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            "[WARN ]",
            Style::default().fg(Color::Yellow),
        ),
        crate::event::LogLevel::Error => (
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            "[ERROR]",
            Style::default().fg(Color::LightRed),
        ),
    };
    let badge_span = Span::styled(badge_text, badge_style);

    let module_span = Span::styled(
        format!(" [{}] ", msg.module),
        Style::default().fg(Color::Gray),
    );

    let msg_span = Span::styled(msg.message.clone(), msg_style);

    Line::from(vec![time_span, badge_span, module_span, msg_span])
}

/// Estimates the number of visual rows a LogMessage occupies when wrapped at max_width columns.
pub fn estimate_log_rows(msg: &crate::event::LogMessage, max_width: u16) -> usize {
    if max_width < 10 {
        return 1;
    }
    let prefix_width = 20 + str_width(&msg.module);
    let max_w = max_width as usize;

    let mut rows = 1;
    let mut cur_col = prefix_width;

    for word in msg.message.split(' ') {
        let word_w = str_width(word);
        if word_w == 0 {
            if cur_col < max_w {
                cur_col += 1;
            } else {
                rows += 1;
                cur_col = 1;
            }
            continue;
        }

        let needed = if cur_col == prefix_width || cur_col == 0 {
            word_w
        } else {
            1 + word_w
        };

        if cur_col + needed <= max_w {
            cur_col += needed;
        } else {
            rows += 1;
            cur_col = word_w;
            while cur_col > max_w {
                rows += 1;
                cur_col = cur_col.saturating_sub(max_w);
            }
        }
    }
    rows
}

/// Master render dispatch for the TUI interface.
pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    // Small terminal fallback (minimum 60x15 per PROJECT.md)
    if area.width < 60 || area.height < 15 {
        let warning_text = format!(
            "Terminal zbyt mały!\nWymagane minimum: 60x15.\nAktualny rozmiar: {}x{}",
            area.width, area.height
        );
        let warning = Paragraph::new(warning_text)
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" OSTRZEŻENIE ")
                    .border_type(BorderType::Double),
            );
        frame.render_widget(warning, area);
        return;
    }

    // 3-zone vertical layout: Header, Body, Footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(6),    // Main content
            Constraint::Length(3), // Footer / Keybindings
        ])
        .split(area);

    render_header(frame, chunks[0], app);
    render_body(frame, chunks[1], app);
    render_footer(frame, chunks[2], app);

    // If a modal is active, render it centered on top of everything
    if app.active_modal != Modal::None {
        render_modal(frame, area, app);
    }
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default().fg(Color::White));

    let header_line = if area.width < 80 {
        // Compact profile (<80 cols)
        let ws_name = match &app.active_workspace {
            Some(ws) => format!("Proj: {}", truncate_str(&ws.name, 12)),
            None => "Brak proj.".to_string(),
        };
        let op_status = if app.is_running {
            truncate_str(app.current_operation.as_deref().unwrap_or("Praca"), 14)
        } else {
            "Gotowy".to_string()
        };
        Line::from(vec![
            Span::styled("🚀 MP4 DOC ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("│ "),
            Span::styled(ws_name, Style::default().fg(Color::Yellow)),
            Span::raw(" │ "),
            Span::styled(
                format!("● {}", op_status),
                if app.is_running {
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                },
            ),
        ])
    } else if area.width < 120 {
        // Standard profile (80..120 cols)
        let ws_name = match &app.active_workspace {
            Some(ws) => format!("Projekt: {}", truncate_str(&ws.name, 25)),
            None => "Brak wybranego projektu".to_string(),
        };
        let op_status = if app.is_running {
            app.current_operation
                .as_deref()
                .unwrap_or("Operacja w toku")
        } else {
            "Gotowy"
        };
        Line::from(vec![
            Span::styled(" 🚀 MP4 DOCTOR 2.0 ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("│ "),
            Span::styled(ws_name, Style::default().fg(Color::Yellow)),
            Span::raw(" │ Status: "),
            Span::styled(
                op_status,
                if app.is_running {
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                },
            ),
        ])
    } else {
        // Wide profile (>=120 cols)
        let ws_name = match &app.active_workspace {
            Some(ws) => format!("Projekt: {}", ws.name),
            None => "Brak wybranego projektu".to_string(),
        };
        let op_status = if app.is_running {
            app.current_operation
                .as_deref()
                .unwrap_or("Operacja w toku")
        } else {
            "Gotowy"
        };
        let cpu_count = crate::get_thread_count();
        let cpu_str = if cpu_count == 0 {
            "Auto".to_string()
        } else {
            format!("{} wątków", cpu_count)
        };
        Line::from(vec![
            Span::styled(" 🚀 MP4 DOCTOR 2.0 ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("│ "),
            Span::styled(ws_name, Style::default().fg(Color::Yellow)),
            Span::raw(" │ Status: "),
            Span::styled(
                op_status,
                if app.is_running {
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                },
            ),
            Span::raw(" │ CPU: "),
            Span::styled(cpu_str, Style::default().fg(Color::Magenta)),
        ])
    };

    let paragraph = Paragraph::new(header_line).block(block);
    frame.render_widget(paragraph, area);
}

fn render_body(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.current_view {
        View::MainMenu => render_main_menu(frame, area, app),
        View::WorkspaceSelect => render_workspace_select(frame, area, app),
        View::WorkspaceDashboard => render_workspace_dashboard(frame, area, app),
        View::ScannerSubMenu => render_scanner_submenu(frame, area, app),
        View::SettingsMenu => render_settings_menu(frame, area, app),
        View::PreviewFileSelect => render_preview_file_select(frame, area, app),
        View::OperationRunning => render_operation_running(frame, area, app),
    }
}

fn render_main_menu(frame: &mut Frame, area: Rect, app: &mut App) {
    let items = vec![
        ListItem::new("  📂 Wybierz / Utwórz Przestrzeń Roboczą (Workspace)"),
        ListItem::new("  ⚙️  Ustawienia Silnika (Zarządzanie CPU)"),
        ListItem::new("  🚪 Wyjście z programu"),
    ];

    let list = List::new(items)
        .block(
            Block::default()
                .title(" MENU GŁÓWNE ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(Style::default().fg(Color::White)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, area, &mut app.main_menu_state);
}

fn render_workspace_select(frame: &mut Frame, area: Rect, app: &mut App) {
    let mut items: Vec<ListItem> = app
        .workspaces
        .iter()
        .map(|ws| {
            ListItem::new(format!(
                "  📁 {} (Zepsute: {}, Dawcy: {}, Gotowe: {})",
                ws.name, ws.broken_count, ws.donor_count, ws.fixed_count
            ))
        })
        .collect();

    items.push(ListItem::new("  ➕ [UTWÓRZ NOWY PROJEKT]"));
    items.push(ListItem::new("  🔙 Wróć do Menu Głównego"));

    let list = List::new(items)
        .block(
            Block::default()
                .title(" WYBIERZ PROJEKT (WORKSPACE) ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(Style::default().fg(Color::White)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, area, &mut app.workspace_list_state);
}

fn render_workspace_dashboard(frame: &mut Frame, area: Rect, app: &mut App) {
    let items = vec![
        ListItem::new("  🔬 Centrum Diagnostyczno-Naprawcze (Skaner)"),
        ListItem::new("  🐒 Poligon: Chaos Monkey (Generowanie Odporności)"),
        ListItem::new("  🎯 Poligon Snajperski (Test Celowany na Pliku)"),
        ListItem::new("  ☢️  Komora Radiacyjna (God Mode - Mutacja Bitowa)"),
        ListItem::new("  🧼 Sanityzator Wideo (Głęboka Rekonstrukcja FFmpeg)"),
        ListItem::new("  🎬 Odtwarzacz Zaufania (Podgląd Uratowanego Wideo)"),
        ListItem::new("  🗑️  Garbage Collector (Czyszczenie Oryginałów)"),
        ListItem::new("  📊 Generuj Raport HTML dla Klienta"),
        ListItem::new("  💾 Eksport Wiedzy AI (Kolektywny Rój - JSON)"),
        ListItem::new("  📥 Import Wiedzy AI (Kolektywny Rój - JSON)"),
        ListItem::new("  🌐 Synchronizacja Wiedzy z Chmurą (Federated)"),
        ListItem::new("  🌐 Wymuszone Pobieranie Wszystkich Wzorców z Chmury"),
        ListItem::new("  🔙 Wróć do Wyboru Projektów"),
    ];

    let title = match &app.active_workspace {
        Some(ws) => format!(" PULPIT PROJEKTU: {} ", ws.name.to_uppercase()),
        None => " PULPIT PROJEKTU ".to_string(),
    };

    let list = List::new(items)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(Style::default().fg(Color::White)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, area, &mut app.dashboard_menu_state);
}

fn render_scanner_submenu(frame: &mut Frame, area: Rect, app: &mut App) {
    let items = vec![
        ListItem::new("  ⚡ Szybka Naprawa (Pojedynczy Plik)"),
        ListItem::new("  📂 Masowe Skanowanie i Naprawa (Katalog)"),
        ListItem::new("  🧬 Pobór Krwi (Ekstrakcja Dawców ze Zdrowych Plików)"),
        ListItem::new("  🔙 Wróć do Pulpitu Projektu"),
    ];

    let list = List::new(items)
        .block(
            Block::default()
                .title(" CENTRUM DIAGNOSTYCZNO-NAPRAWCZE (SKANER) ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(Style::default().fg(Color::White)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, area, &mut app.scanner_menu_state);
}

fn render_settings_menu(frame: &mut Frame, area: Rect, app: &mut App) {
    let threads = crate::get_thread_count();
    let thread_str = if threads == 0 {
        "Auto (Domyślnie)".to_string()
    } else {
        threads.to_string()
    };

    let items = vec![
        ListItem::new(format!("  ⚙️  Limit wątków CPU: {}", thread_str)),
        ListItem::new("  🔙 Wróć do Menu Głównego"),
    ];

    let list = List::new(items)
        .block(
            Block::default()
                .title(" USTAWIENIA SILNIKA ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(Style::default().fg(Color::White)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, area, &mut app.settings_menu_state);
}

fn render_preview_file_select(frame: &mut Frame, area: Rect, app: &mut App) {
    let mut items: Vec<ListItem> = app
        .preview_files
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "Nieznany plik".to_string());
            ListItem::new(format!("  🎬 {}", name))
        })
        .collect();

    items.push(ListItem::new("  🔙 Wróć do Pulpitu Projektu"));

    let list = List::new(items)
        .block(
            Block::default()
                .title(" ODTWARZACZ ZAUFANIA - WYBIERZ PLIK DO PODGLĄDU ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(Style::default().fg(Color::White)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, area, &mut app.preview_list_state);
}

fn render_operation_running(frame: &mut Frame, area: Rect, app: &App) {
    let sanitizer_active = app.sanitizer_metrics.frame > 0
        || app.sanitizer_metrics.fps > 0.0
        || (app.sanitizer_metrics.speed != "0x" && !app.sanitizer_metrics.speed.is_empty());

    let stats_height = if area.height < 18 {
        5
    } else if sanitizer_active {
        7
    } else {
        6
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(stats_height), // Live telemetry summary & gauge
            Constraint::Min(4),               // Scrolling logs
        ])
        .split(area);

    // --- Telemetry Panel ---
    let stats_block = Block::default()
        .title(format!(
            " LIVE TELEMETRIA: {} ",
            app.current_operation.as_deref().unwrap_or("Operacja")
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);
    let stats_inner = stats_block.inner(chunks[0]);
    frame.render_widget(stats_block, chunks[0]);

    // Metric line 1
    let stat_line1 = if area.width < 80 {
        Line::from(vec![
            Span::raw(" Skan: "),
            Span::styled(app.stats.files_scanned.to_string(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" │ OK: "),
            Span::styled(app.stats.files_healthy.to_string(), Style::default().fg(Color::Green)),
            Span::raw(" │ Złe: "),
            Span::styled(app.stats.files_broken.to_string(), Style::default().fg(Color::Red)),
            Span::raw(" │ Napr: "),
            Span::styled(app.stats.files_repaired.to_string(), Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
            Span::raw(" │ Wątki: "),
            Span::styled(app.stats.active_threads.to_string(), Style::default().fg(Color::Yellow)),
        ])
    } else if area.width < 110 {
        Line::from(vec![
            Span::raw(" Skan: "),
            Span::styled(app.stats.files_scanned.to_string(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" │ Zdrowe: "),
            Span::styled(app.stats.files_healthy.to_string(), Style::default().fg(Color::Green)),
            Span::raw(" │ Uszkodzone: "),
            Span::styled(app.stats.files_broken.to_string(), Style::default().fg(Color::Red)),
            Span::raw(" │ Uratowane: "),
            Span::styled(app.stats.files_repaired.to_string(), Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
            Span::raw(" │ Wątki: "),
            Span::styled(app.stats.active_threads.to_string(), Style::default().fg(Color::Yellow)),
        ])
    } else {
        Line::from(vec![
            Span::raw(" Przeanalizowano: "),
            Span::styled(app.stats.files_scanned.to_string(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" │ Zdrowe: "),
            Span::styled(app.stats.files_healthy.to_string(), Style::default().fg(Color::Green)),
            Span::raw(" │ Uszkodzone: "),
            Span::styled(app.stats.files_broken.to_string(), Style::default().fg(Color::Red)),
            Span::raw(" │ Uratowane: "),
            Span::styled(app.stats.files_repaired.to_string(), Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
            Span::raw(" │ Aktywne wątki: "),
            Span::styled(app.stats.active_threads.to_string(), Style::default().fg(Color::Yellow)),
        ])
    };

    // Metric line 2
    let repair_rate = app.stats.repair_rate();
    let formatted_bytes = format_bytes(app.stats.bytes_processed);

    let line2_spans = if area.width < 80 {
        if sanitizer_active {
            vec![
                Span::raw(" "),
                Span::styled(formatted_bytes, Style::default().fg(Color::Cyan)),
                Span::raw(" │ "),
                Span::styled(format!("{:.1}%", repair_rate), Style::default().fg(Color::Green)),
                Span::raw(" │ "),
                Span::styled(format!("{:.1} FPS", app.sanitizer_metrics.fps), Style::default().fg(Color::Yellow)),
                Span::raw(" │ "),
                Span::styled(app.sanitizer_metrics.speed.clone(), Style::default().fg(Color::Green)),
                Span::raw(" │ Pasaż: "),
                Span::styled(app.sanitizer_metrics.pass.to_string(), Style::default().fg(Color::Magenta)),
            ]
        } else {
            vec![
                Span::raw(" Przetworzono: "),
                Span::styled(formatted_bytes, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(" │ Skuteczność: "),
                Span::styled(
                    format!("{:.1}%", repair_rate),
                    Style::default()
                        .fg(if repair_rate >= 80.0 {
                            Color::Green
                        } else if repair_rate >= 50.0 {
                            Color::Yellow
                        } else {
                            Color::Red
                        })
                        .add_modifier(Modifier::BOLD),
                ),
            ]
        }
    } else {
        let mut spans = vec![
            Span::raw(" Przetworzono: "),
            Span::styled(formatted_bytes, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" │ Skuteczność: "),
            Span::styled(
                format!("{:.1}%", repair_rate),
                Style::default()
                    .fg(if repair_rate >= 80.0 {
                        Color::Green
                    } else if repair_rate >= 50.0 {
                        Color::Yellow
                    } else {
                        Color::Red
                    })
                    .add_modifier(Modifier::BOLD),
            ),
        ];
        if area.height < 18 && sanitizer_active {
            spans.push(Span::raw(" │ "));
            spans.push(Span::styled(
                format!("{:.1} FPS │ Prędkość: {} │ Pasaż: {}", app.sanitizer_metrics.fps, app.sanitizer_metrics.speed, app.sanitizer_metrics.pass),
                Style::default().fg(Color::Yellow),
            ));
        } else if let Some(ref status_text) = app.operation_status_text {
            spans.push(Span::raw(" │ Status: "));
            spans.push(Span::styled(
                truncate_str(status_text, (area.width.saturating_sub(60)) as usize),
                Style::default().fg(if app.is_running { Color::Yellow } else { Color::Green }),
            ));
        }
        spans
    };

    let mut stat_lines = vec![stat_line1, Line::from(line2_spans)];

    // Metric line 3 (if height >= 18 and sanitizer active)
    if area.height >= 18 && sanitizer_active {
        let sanitizer_line = Line::from(vec![
            Span::raw(" Sanitizer FFmpeg: "),
            Span::styled(format!("{} klatek", app.sanitizer_metrics.frame), Style::default().fg(Color::Cyan)),
            Span::raw(" │ "),
            Span::styled(format!("{:.1} FPS", app.sanitizer_metrics.fps), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" │ Prędkość: "),
            Span::styled(app.sanitizer_metrics.speed.clone(), Style::default().fg(Color::Green)),
            Span::raw(" │ Pasaż: "),
            Span::styled(app.sanitizer_metrics.pass.to_string(), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        ]);
        stat_lines.push(sanitizer_line);
    }

    if stats_inner.height >= 3 {
        let stat_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(stats_inner.height.saturating_sub(1)),
                Constraint::Length(1),
            ])
            .split(stats_inner);

        frame.render_widget(Paragraph::new(stat_lines), stat_chunks[0]);

        let repair_ratio = (repair_rate as f64 / 100.0).clamp(0.0, 1.0);
        let gauge = LineGauge::default()
            .filled_style(
                Style::default()
                    .fg(if repair_ratio >= 0.8 {
                        Color::Green
                    } else if repair_ratio >= 0.5 {
                        Color::Yellow
                    } else {
                        Color::Red
                    })
                    .add_modifier(Modifier::BOLD),
            )
            .unfilled_style(Style::default().fg(Color::DarkGray))
            // ratatui 0.30 rozdzieliło symbol wypełnienia od symbolu tła —
            // `line_set` jest wycofane, oba trzeba podać osobno.
            .filled_symbol(ratatui::symbols::line::THICK.horizontal)
            .unfilled_symbol(ratatui::symbols::line::THICK.horizontal)
            .ratio(repair_ratio)
            .label(format!(" Postęp napraw: {:.1}% ", repair_rate));

        frame.render_widget(gauge, stat_chunks[1]);
    } else {
        frame.render_widget(Paragraph::new(stat_lines), stats_inner);
    }

    // --- Logs Panel ---
    let visible_lines = chunks[1].height.saturating_sub(2) as usize;
    let inner_width = chunks[1].width.saturating_sub(2);
    let total_logs = app.logs.len();

    let log_lines: Vec<Line> = if total_logs == 0 || visible_lines == 0 {
        Vec::new()
    } else if app.auto_scroll {
        let mut accumulated_rows = 0;
        let mut start_idx = total_logs.saturating_sub(1);
        for idx in (0..total_logs).rev() {
            let rows = estimate_log_rows(&app.logs[idx], inner_width);
            if accumulated_rows + rows > visible_lines && accumulated_rows > 0 {
                start_idx = idx + 1;
                break;
            }
            accumulated_rows += rows;
            start_idx = idx;
            if accumulated_rows >= visible_lines {
                break;
            }
        }
        app.logs.iter().skip(start_idx).map(format_log_line).collect()
    } else {
        let anchor = app.log_scroll.min(total_logs.saturating_sub(1));
        let mut accumulated_rows = 0;
        let mut start_idx = anchor;

        for idx in (0..=anchor).rev() {
            let rows = estimate_log_rows(&app.logs[idx], inner_width);
            if accumulated_rows + rows > visible_lines && accumulated_rows > 0 {
                start_idx = idx + 1;
                break;
            }
            accumulated_rows += rows;
            start_idx = idx;
            if accumulated_rows >= visible_lines {
                break;
            }
        }

        let mut end_idx = anchor;
        if start_idx == 0 && accumulated_rows < visible_lines {
            for idx in (anchor + 1)..total_logs {
                let rows = estimate_log_rows(&app.logs[idx], inner_width);
                if accumulated_rows + rows > visible_lines && accumulated_rows > 0 {
                    break;
                }
                accumulated_rows += rows;
                end_idx = idx;
                if accumulated_rows >= visible_lines {
                    break;
                }
            }
        }

        let take_count = end_idx.saturating_sub(start_idx) + 1;
        app.logs.iter().skip(start_idx).take(take_count).map(format_log_line).collect()
    };

    let scroll_mode_label = if app.auto_scroll {
        " [AUTO-SCROLL]"
    } else {
        " [PRZEGLĄDANIE]"
    };

    let logs_widget = Paragraph::new(log_lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(format!(
                    " DZIENNIK OPERACJI ({} wpisów{}) ",
                    total_logs, scroll_mode_label
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );
    frame.render_widget(logs_widget, chunks[1]);

    if total_logs > visible_lines {
        let mut scrollbar_state = ScrollbarState::new(total_logs)
            .position(if app.auto_scroll { total_logs } else { app.log_scroll });
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼"));
        frame.render_stateful_widget(scrollbar, chunks[1], &mut scrollbar_state);
    }
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let is_compact = area.width < 80;
    let help_text = match app.current_view {
        View::OperationRunning => {
            if is_compact {
                if app.is_running {
                    " [s] Stop | [↑/↓] Logi | [End] Koniec "
                } else {
                    " [Esc/Enter] Menu | [↑/↓] Logi "
                }
            } else if app.is_running {
                " [s] Zatrzymaj wątki | [↑/↓/PgUp/PgDn] Przeglądaj logi | [End] Skocz na koniec "
            } else {
                " [Enter / Esc] Wróć do menu | [↑/↓/PgUp/PgDn] Przeglądaj logi "
            }
        }
        _ => {
            if is_compact {
                " [↑/↓] Wybór  [Enter] OK  [Esc] Wróć  [Ctrl+C] Koniec "
            } else {
                " [↑/k] Góra  [↓/j] Dół  [Enter] Wybierz  [Esc/q] Wróć/Wyjście  [Ctrl+C] Zakończ "
            }
        }
    };

    let footer = Paragraph::new(help_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::DarkGray))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );

    frame.render_widget(footer, area);
}

// --- Modal Overlays ---

fn render_modal(frame: &mut Frame, area: Rect, app: &App) {
    match &app.active_modal {
        Modal::None => {}
        Modal::NewWorkspace { input, cursor, error_msg } => {
            let modal_area = centered_rect(60, 25, area);
            frame.render_widget(Clear, modal_area);

            let mut text_lines = vec![
                Line::from(Span::raw("Podaj nazwę nowego projektu:")),
                Line::from(render_text_with_cursor(input, *cursor)),
            ];

            if let Some(err) = error_msg {
                text_lines.push(Line::from(Span::styled(
                    format!("Błąd: {}", err),
                    Style::default().fg(Color::Red),
                )));
            } else {
                text_lines.push(Line::from(Span::styled(
                    "[Enter] Utwórz  │  [Esc] Anuluj",
                    Style::default().fg(Color::DarkGray),
                )));
            }

            let block = Block::default()
                .title(" NOWY PROJEKT (WORKSPACE) ")
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::White).bg(Color::Black));

            let p = Paragraph::new(text_lines).block(block).alignment(Alignment::Left);
            frame.render_widget(p, modal_area);
        }
        Modal::PathInput { title, prompt, input, cursor, error_msg, .. } => {
            let modal_area = centered_rect(70, 25, area);
            frame.render_widget(Clear, modal_area);

            let mut text_lines = vec![
                Line::from(Span::raw(prompt.as_str())),
                Line::from(render_text_with_cursor(input, *cursor)),
            ];

            if let Some(err) = error_msg {
                text_lines.push(Line::from(Span::styled(
                    format!("Błąd: {}", err),
                    Style::default().fg(Color::Red),
                )));
            } else {
                text_lines.push(Line::from(Span::styled(
                    "[Enter] Zatwierdź  │  [Esc] Anuluj",
                    Style::default().fg(Color::DarkGray),
                )));
            }

            let block = Block::default()
                .title(format!(" {} ", title))
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::White).bg(Color::Black));

            let p = Paragraph::new(text_lines).block(block).alignment(Alignment::Left);
            frame.render_widget(p, modal_area);
        }
        Modal::SanitizerSelectPass { file_path, selected_index } => {
            let modal_area = centered_rect(60, 30, area);
            frame.render_widget(Clear, modal_area);

            let pass1_style = if *selected_index == 0 {
                Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let pass2_style = if *selected_index == 1 {
                Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let text_lines = vec![
                Line::from(Span::raw(format!("Plik: {}", file_path))),
                Line::from(""),
                Line::from(Span::styled(" [1] 1-Pass CRF 18 (Rekomendowany, szybki) ", pass1_style)),
                Line::from(Span::styled(" [2] 2-Pass VBR (Maksymalna czystość NAL) ", pass2_style)),
                Line::from(""),
                Line::from(Span::styled(
                    "[↑/↓/Tab] Przełącz  │  [Enter] Uruchom  │  [Esc] Anuluj",
                    Style::default().fg(Color::DarkGray),
                )),
            ];

            let block = Block::default()
                .title(" WYBÓR TRYBU TRANSKODOWANIA ")
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::White).bg(Color::Black));

            let p = Paragraph::new(text_lines).block(block);
            frame.render_widget(p, modal_area);
        }
        Modal::ConfirmAction { title, message, selected_yes, .. } => {
            let modal_area = centered_rect(50, 25, area);
            frame.render_widget(Clear, modal_area);

            let yes_style = if *selected_yes {
                Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let no_style = if !*selected_yes {
                Style::default().fg(Color::Black).bg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let text_lines = vec![
                Line::from(Span::raw(message.as_str())),
                Line::from(""),
                Line::from(vec![
                    Span::raw("    "),
                    Span::styled(" [ TAK ] ", yes_style),
                    Span::raw("       "),
                    Span::styled(" [ NIE ] ", no_style),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "[Tab / ← / →] Wybór  │  [Enter] Potwierdź  │  [Esc] Anuluj",
                    Style::default().fg(Color::DarkGray),
                )),
            ];

            let block = Block::default()
                .title(format!(" {} ", title))
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::White).bg(Color::Black));

            let p = Paragraph::new(text_lines).block(block).alignment(Alignment::Center);
            frame.render_widget(p, modal_area);
        }
        Modal::SettingsThreadLimit { input, cursor, error_msg } => {
            let modal_area = centered_rect(50, 25, area);
            frame.render_widget(Clear, modal_area);

            let mut text_lines = vec![
                Line::from(Span::raw("Podaj limit wątków CPU (0 = Auto):")),
                Line::from(render_text_with_cursor(input, *cursor)),
            ];

            if let Some(err) = error_msg {
                text_lines.push(Line::from(Span::styled(
                    format!("Błąd: {}", err),
                    Style::default().fg(Color::Red),
                )));
            } else {
                text_lines.push(Line::from(Span::styled(
                    "[Enter] Zapisz  │  [Esc] Anuluj",
                    Style::default().fg(Color::DarkGray),
                )));
            }

            let block = Block::default()
                .title(" KONFIGURACJA WĄTKÓW CPU ")
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::White).bg(Color::Black));

            let p = Paragraph::new(text_lines).block(block);
            frame.render_widget(p, modal_area);
        }
        Modal::NotificationDialog { title, message, is_error } => {
            let modal_area = centered_rect(60, 25, area);
            frame.render_widget(Clear, modal_area);

            let color = if *is_error { Color::Red } else { Color::Green };

            let text_lines = vec![
                Line::from(Span::styled(message.as_str(), Style::default().fg(color))),
                Line::from(""),
                Line::from(Span::styled(
                    "[Enter / Spacja / Esc] Zamknij",
                    Style::default().fg(Color::DarkGray),
                )),
            ];

            let block = Block::default()
                .title(format!(" {} ", title))
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::White).bg(Color::Black));

            let p = Paragraph::new(text_lines).block(block).alignment(Alignment::Center);
            frame.render_widget(p, modal_area);
        }
    }
}

fn render_text_with_cursor(text: &str, cursor: usize) -> Vec<Span<'_>> {
    let clamped_cursor = cursor.min(text.len());
    let before = &text[..clamped_cursor];
    let after = &text[clamped_cursor..];

    vec![
        Span::styled(before, Style::default().fg(Color::White)),
        Span::styled("█", Style::default().fg(Color::Cyan).add_modifier(Modifier::RAPID_BLINK)),
        Span::styled(after, Style::default().fg(Color::White)),
    ]
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let w = (r.width * percent_x / 100)
        .max(46)
        .min(r.width.saturating_sub(2).max(1));
    let h = (r.height * percent_y / 100)
        .max(7)
        .min(r.height.saturating_sub(2).max(1));
    let x = r.x + (r.width.saturating_sub(w)) / 2;
    let y = r.y + (r.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}
