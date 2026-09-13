//! MP4 Doctor 2.0 - TUI Application State Machine
//!
//! Manages view transitions, keyboard interactions, modal text inputs,
//! telemetry ingestion from the centralized event bus, and operational worker orchestration.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;

use crate::event::{
    AppEvent, EventSender, LogMessage, SanitizerMetrics, StatUpdate,
};
use crate::workspace::{get_available_workspaces, Workspace, WorkspaceStats};
use crate::SHUTDOWN_FLAG;

/// Maximum log messages kept in memory buffer.
pub const MAX_LOG_HISTORY: usize = 5_000;

/// Maximum events drained in a single frame tick to prevent UI rendering starvation.
pub const MAX_EVENTS_PER_TICK: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    MainMenu,
    WorkspaceSelect,
    WorkspaceDashboard,
    ScannerSubMenu,
    SettingsMenu,
    PreviewFileSelect,
    OperationRunning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathInputTarget {
    ScannerSingle,
    ScannerFull,
    ScannerExtract,
    TrainingGround,
    SniperTest,
    GodMode,
    SanitizerFile,
    BrainImport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmActionTarget {
    GarbageCollector,
    QuitApplication,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    None,
    NewWorkspace {
        input: String,
        cursor: usize,
        error_msg: Option<String>,
    },
    PathInput {
        title: String,
        prompt: String,
        input: String,
        cursor: usize,
        conf_file: String,
        target: PathInputTarget,
        error_msg: Option<String>,
    },
    SanitizerSelectPass {
        file_path: String,
        selected_index: usize, // 0: 1-Pass CRF 18, 1: 2-Pass VBR
    },
    ConfirmAction {
        title: String,
        message: String,
        action: ConfirmActionTarget,
        selected_yes: bool,
    },
    SettingsThreadLimit {
        input: String,
        cursor: usize,
        error_msg: Option<String>,
    },
    NotificationDialog {
        title: String,
        message: String,
        is_error: bool,
    },
}

pub struct App {
    pub current_view: View,
    pub view_stack: Vec<View>,
    pub active_modal: Modal,

    pub main_menu_state: ListState,
    pub workspace_list_state: ListState,
    pub dashboard_menu_state: ListState,
    pub scanner_menu_state: ListState,
    pub settings_menu_state: ListState,
    pub preview_list_state: ListState,

    pub workspaces: Vec<WorkspaceStats>,
    pub active_workspace: Option<Workspace>,
    pub preview_files: Vec<PathBuf>,

    pub event_sender: EventSender,
    pub event_receiver: Receiver<AppEvent>,

    pub is_running: bool,
    pub current_operation: Option<String>,
    pub stats: StatUpdate,
    pub sanitizer_metrics: SanitizerMetrics,
    pub thread_statuses: BTreeMap<usize, String>,
    pub logs: VecDeque<LogMessage>,
    pub log_scroll: usize,
    pub auto_scroll: bool,
    pub operation_status_text: Option<String>,
    pub progress: Option<(usize, usize)>,

    pub pending_preview: Option<PathBuf>,
    pub should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let (tx, rx) = crate::event::channel();
        Self::with_channel(tx, rx)
    }

    pub fn with_channel(sender: EventSender, receiver: Receiver<AppEvent>) -> Self {
        let mut main_menu_state = ListState::default();
        main_menu_state.select(Some(0));

        let mut workspace_list_state = ListState::default();
        workspace_list_state.select(Some(0));

        let mut dashboard_menu_state = ListState::default();
        dashboard_menu_state.select(Some(0));

        let mut scanner_menu_state = ListState::default();
        scanner_menu_state.select(Some(0));

        let mut settings_menu_state = ListState::default();
        settings_menu_state.select(Some(0));

        let mut preview_list_state = ListState::default();
        preview_list_state.select(Some(0));

        let mut app = Self {
            current_view: View::MainMenu,
            view_stack: Vec::new(),
            active_modal: Modal::None,

            main_menu_state,
            workspace_list_state,
            dashboard_menu_state,
            scanner_menu_state,
            settings_menu_state,
            preview_list_state,

            workspaces: Vec::new(),
            active_workspace: None,
            preview_files: Vec::new(),

            event_sender: sender,
            event_receiver: receiver,

            is_running: false,
            current_operation: None,
            stats: StatUpdate::default(),
            sanitizer_metrics: SanitizerMetrics::default(),
            thread_statuses: BTreeMap::new(),
            logs: VecDeque::with_capacity(MAX_LOG_HISTORY),
            log_scroll: 0,
            auto_scroll: true,
            operation_status_text: None,
            progress: None,

            pending_preview: None,
            should_quit: false,
        };
        app.refresh_workspaces();
        app
    }

    // --- Navigation Helpers ---

    pub fn push_view(&mut self, next: View) {
        self.view_stack.push(self.current_view);
        self.current_view = next;
    }

    pub fn pop_view(&mut self) {
        if let Some(prev) = self.view_stack.pop() {
            self.current_view = prev;
        } else {
            self.should_quit = true;
        }
    }

    pub fn refresh_workspaces(&mut self) {
        self.workspaces = get_available_workspaces();
        if self.workspace_list_state.selected().is_none() {
            self.workspace_list_state.select(Some(0));
        }
    }

    pub fn refresh_preview_files(&mut self) {
        self.preview_files.clear();
        if let Some(ref ws) = self.active_workspace {
            if let Ok(entries) = std::fs::read_dir(&ws.output_dir) {
                for entry in entries.flatten() {
                    if entry.path().is_file() {
                        self.preview_files.push(entry.path());
                    }
                }
            }
        }
        self.preview_list_state.select(Some(0));
    }

    pub fn take_pending_preview(&mut self) -> Option<PathBuf> {
        self.pending_preview.take()
    }

    // --- Event Channel Ingestion ---

    pub fn process_events(&mut self) {
        let mut count = 0;
        while let Ok(event) = self.event_receiver.try_recv() {
            self.handle_app_event(event);
            count += 1;
            if count >= MAX_EVENTS_PER_TICK {
                break;
            }
        }
    }

    /// Appends a log message to the log buffer, enforcing MAX_LOG_HISTORY memory bounds
    /// and adjusting log_scroll during eviction to preserve reading position.
    pub fn push_log(&mut self, msg: LogMessage) {
        if self.logs.len() >= MAX_LOG_HISTORY {
            self.logs.drain(0..100);
            if !self.auto_scroll {
                self.log_scroll = self.log_scroll.saturating_sub(100);
            }
        }
        self.logs.push_back(msg);
        if self.auto_scroll {
            self.log_scroll = self.logs.len().saturating_sub(1);
        }
    }

    pub fn handle_app_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Log(msg) => {
                self.push_log(msg);
            }
            AppEvent::Stats(stats) => {
                self.stats = stats;
            }
            AppEvent::ThreadStatus(status) => {
                self.thread_statuses.insert(status.thread_id, status.status);
            }
            AppEvent::SanitizerProgress(metrics) => {
                self.sanitizer_metrics = metrics;
            }
            AppEvent::Progress { current, total, message } => {
                if let Some(msg) = message {
                    self.operation_status_text = Some(msg);
                }
                self.progress = if total > 0 { Some((current, total)) } else { None };
            }
            AppEvent::OperationStarted(title) => {
                crate::SHUTDOWN_FLAG.store(false, std::sync::atomic::Ordering::SeqCst);
            self.is_running = true;
                self.current_operation = Some(title);
                self.operation_status_text = Some("Operacja w toku...".to_string());
                self.progress = None;
            }
            AppEvent::OperationFinished(summary) => {
                self.is_running = false;
                self.progress = None;
                self.operation_status_text = Some(format!(
                    "Zakończono: {}. Naciśnij [Esc] lub [Enter], aby wrócić.",
                    summary
                ));
                self.push_log(LogMessage::info("SYSTEM", summary));
            }
            AppEvent::OperationFailed(op, err) => {
                self.is_running = false;
                self.progress = None;
                self.operation_status_text = Some(format!(
                    "Błąd [{}]: {}. Naciśnij [Esc], aby wrócić.",
                    op, err
                ));
                self.push_log(LogMessage::error(op, err));
            }
            AppEvent::DonorFound { dna, moov_path } => {
                if let Some(ref ws) = self.active_workspace {
                    let _ = crate::db::save_donor(ws, &dna, &moov_path);
                }
            }
            AppEvent::RepairSuccess { dna, algorithm, .. } => {
                if let Some(ref ws) = self.active_workspace {
                    let _ = crate::db::reward_algorithm(ws, &dna, &algorithm);
                }
            }
            AppEvent::RepairFailure { dna, algorithm, .. } => {
                if let Some(ref ws) = self.active_workspace {
                    let _ = crate::db::penalize_algorithm(ws, &dna, &algorithm);
                }
            }
        }
    }

    // --- Key Event Routing ---

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
            self.should_quit = true;
            return;
        }

        if self.active_modal != Modal::None {
            self.handle_modal_key(key);
        } else {
            self.handle_view_key(key);
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        match &mut self.active_modal {
            Modal::None => {}
            Modal::NotificationDialog { .. } => {
                if matches!(key.code, KeyCode::Enter | KeyCode::Esc | KeyCode::Char(' ')) {
                    self.active_modal = Modal::None;
                }
            }
            Modal::ConfirmAction { action, selected_yes, .. } => match key.code {
                KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                    *selected_yes = !*selected_yes;
                }
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Char('t') | KeyCode::Char('T') => {
                    *selected_yes = true;
                }
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    *selected_yes = false;
                }
                KeyCode::Enter => {
                    let confirmed = *selected_yes;
                    let target_action = *action;
                    self.active_modal = Modal::None;
                    if confirmed {
                        self.execute_confirmed_action(target_action);
                    }
                }
                KeyCode::Esc => {
                    self.active_modal = Modal::None;
                }
                _ => {}
            },
            Modal::SanitizerSelectPass { file_path, selected_index } => match key.code {
                KeyCode::Up | KeyCode::Down | KeyCode::Tab => {
                    *selected_index = if *selected_index == 0 { 1 } else { 0 };
                }
                KeyCode::Enter => {
                    let path = file_path.clone();
                    let use_2pass = *selected_index == 1;
                    self.active_modal = Modal::None;
                    self.launch_sanitizer(path, use_2pass);
                }
                KeyCode::Esc => {
                    self.active_modal = Modal::None;
                }
                _ => {}
            },
            Modal::NewWorkspace { input, cursor, error_msg } => match key.code {
                KeyCode::Char(c) => {
                    insert_char_at_cursor(input, cursor, c);
                    *error_msg = None;
                }
                KeyCode::Backspace => {
                    delete_char_before_cursor(input, cursor);
                    *error_msg = None;
                }
                KeyCode::Delete => {
                    delete_char_at_cursor(input, *cursor);
                    *error_msg = None;
                }
                KeyCode::Left => move_cursor_left(input, cursor),
                KeyCode::Right => move_cursor_right(input, cursor),
                KeyCode::Home => *cursor = 0,
                KeyCode::End => *cursor = input.len(),
                KeyCode::Enter => {
                    let trimmed = input.trim().to_string();
                    if trimmed.is_empty() {
                        *error_msg = Some("Nazwa nie może być pusta!".to_string());
                    } else {
                        match Workspace::init(&trimmed) {
                            Ok(ws) => {
                                let _ = crate::db::init_db(&ws);
                                self.active_workspace = Some(ws);
                                self.refresh_workspaces();
                                self.active_modal = Modal::None;
                                self.push_view(View::WorkspaceDashboard);
                            }
                            Err(e) => {
                                *error_msg = Some(format!("Błąd tworzenia: {}", e));
                            }
                        }
                    }
                }
                KeyCode::Esc => {
                    self.active_modal = Modal::None;
                }
                _ => {}
            },
            Modal::PathInput { input, cursor, target, conf_file, error_msg, .. } => match key.code {
                KeyCode::Char(c) => {
                    insert_char_at_cursor(input, cursor, c);
                    *error_msg = None;
                }
                KeyCode::Backspace => {
                    delete_char_before_cursor(input, cursor);
                    *error_msg = None;
                }
                KeyCode::Delete => {
                    delete_char_at_cursor(input, *cursor);
                    *error_msg = None;
                }
                KeyCode::Left => move_cursor_left(input, cursor),
                KeyCode::Right => move_cursor_right(input, cursor),
                KeyCode::Home => *cursor = 0,
                KeyCode::End => *cursor = input.len(),
                KeyCode::Enter => {
                    let trimmed = input.trim().to_string();
                    let target_kind = *target;
                    let conf_path = conf_file.clone();

                    if trimmed.is_empty() {
                        *error_msg = Some("Ścieżka nie może być pusta!".to_string());
                    } else {
                        if let Some(ref ws) = self.active_workspace {
                            let _ = std::fs::write(ws.root_dir.join(&conf_path), &trimmed);
                        }
                        self.active_modal = Modal::None;
                        self.execute_path_action(target_kind, trimmed);
                    }
                }
                KeyCode::Esc => {
                    self.active_modal = Modal::None;
                }
                _ => {}
            },
            Modal::SettingsThreadLimit { input, cursor, error_msg } => match key.code {
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    insert_char_at_cursor(input, cursor, c);
                    *error_msg = None;
                }
                KeyCode::Backspace => {
                    delete_char_before_cursor(input, cursor);
                    *error_msg = None;
                }
                KeyCode::Delete => {
                    delete_char_at_cursor(input, *cursor);
                    *error_msg = None;
                }
                KeyCode::Left => move_cursor_left(input, cursor),
                KeyCode::Right => move_cursor_right(input, cursor),
                KeyCode::Enter => {
                    if let Ok(limit) = input.trim().parse::<usize>() {
                        crate::set_thread_count(limit);
                        self.active_modal = Modal::None;
                    } else {
                        *error_msg = Some("Podaj poprawną liczbę całkowitą (0 = Auto)".to_string());
                    }
                }
                KeyCode::Esc => {
                    self.active_modal = Modal::None;
                }
                _ => {}
            },
        }
    }

    fn handle_view_key(&mut self, key: KeyEvent) {
        match self.current_view {
            View::MainMenu => match key.code {
                KeyCode::Up | KeyCode::Char('k') => Self::nav_up(&mut self.main_menu_state, 3),
                KeyCode::Down | KeyCode::Char('j') => Self::nav_down(&mut self.main_menu_state, 3),
                KeyCode::Enter => match self.main_menu_state.selected().unwrap_or(0) {
                    0 => {
                        self.refresh_workspaces();
                        self.push_view(View::WorkspaceSelect);
                    }
                    1 => self.push_view(View::SettingsMenu),
                    2 => self.should_quit = true,
                    _ => {}
                },
                KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                _ => {}
            },
            View::WorkspaceSelect => {
                let total_items = self.workspaces.len() + 2; // workspaces + New + Back
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => Self::nav_up(&mut self.workspace_list_state, total_items),
                    KeyCode::Down | KeyCode::Char('j') => Self::nav_down(&mut self.workspace_list_state, total_items),
                    KeyCode::Char('n') | KeyCode::Char('a') => self.open_new_workspace_modal(),
                    KeyCode::Enter => {
                        let selected = self.workspace_list_state.selected().unwrap_or(0);
                        if selected < self.workspaces.len() {
                            let name = &self.workspaces[selected].name;
                            if let Ok(ws) = Workspace::init(name) {
                                let _ = crate::db::init_db(&ws);
                                self.active_workspace = Some(ws);
                                self.push_view(View::WorkspaceDashboard);
                            }
                        } else if selected == self.workspaces.len() {
                            self.open_new_workspace_modal();
                        } else {
                            self.pop_view();
                        }
                    }
                    KeyCode::Char('q') | KeyCode::Esc => self.pop_view(),
                    _ => {}
                }
            }
            View::WorkspaceDashboard => {
                const DASHBOARD_ITEM_COUNT: usize = 12;
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => Self::nav_up(&mut self.dashboard_menu_state, DASHBOARD_ITEM_COUNT),
                    KeyCode::Down | KeyCode::Char('j') => Self::nav_down(&mut self.dashboard_menu_state, DASHBOARD_ITEM_COUNT),
                    KeyCode::Enter => self.handle_dashboard_selection(),
                    KeyCode::Char('q') | KeyCode::Esc => self.pop_view(),
                    _ => {}
                }
            }
            View::ScannerSubMenu => {
                const SCANNER_ITEMS: usize = 4;
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => Self::nav_up(&mut self.scanner_menu_state, SCANNER_ITEMS),
                    KeyCode::Down | KeyCode::Char('j') => Self::nav_down(&mut self.scanner_menu_state, SCANNER_ITEMS),
                    KeyCode::Enter => match self.scanner_menu_state.selected().unwrap_or(0) {
                        0 => self.open_path_modal(
                            "Szybka Naprawa",
                            "Podaj ścieżkę do pliku:",
                            "last_scan_single.conf",
                            PathInputTarget::ScannerSingle,
                        ),
                        1 => self.open_path_modal(
                            "Masowe Skanowanie",
                            "Podaj ścieżkę do katalogu:",
                            "last_scan.conf",
                            PathInputTarget::ScannerFull,
                        ),
                        2 => self.open_path_modal(
                            "Pobór Krwi",
                            "Podaj ścieżkę do zdrowych nagrań:",
                            "last_scan_extract.conf",
                            PathInputTarget::ScannerExtract,
                        ),
                        3 => self.pop_view(),
                        _ => {}
                    },
                    KeyCode::Char('q') | KeyCode::Esc => self.pop_view(),
                    _ => {}
                }
            }
            View::SettingsMenu => match key.code {
                KeyCode::Up | KeyCode::Down | KeyCode::Char('k') | KeyCode::Char('j') => {
                    let cur = self.settings_menu_state.selected().unwrap_or(0);
                    self.settings_menu_state.select(Some(if cur == 0 { 1 } else { 0 }));
                }
                KeyCode::Enter => match self.settings_menu_state.selected().unwrap_or(0) {
                    0 => {
                        let cur_threads = crate::get_thread_count().to_string();
                        let len = cur_threads.len();
                        self.active_modal = Modal::SettingsThreadLimit {
                            input: cur_threads,
                            cursor: len,
                            error_msg: None,
                        };
                    }
                    1 => self.pop_view(),
                    _ => {}
                },
                KeyCode::Char('q') | KeyCode::Esc => self.pop_view(),
                _ => {}
            },
            View::PreviewFileSelect => {
                let count = self.preview_files.len() + 1; // files + Back
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => Self::nav_up(&mut self.preview_list_state, count),
                    KeyCode::Down | KeyCode::Char('j') => Self::nav_down(&mut self.preview_list_state, count),
                    KeyCode::Enter => {
                        let sel = self.preview_list_state.selected().unwrap_or(0);
                        if sel < self.preview_files.len() {
                            self.pending_preview = Some(self.preview_files[sel].clone());
                        } else {
                            self.pop_view();
                        }
                    }
                    KeyCode::Char('q') | KeyCode::Esc => self.pop_view(),
                    _ => {}
                }
            }
            View::OperationRunning => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.auto_scroll = false;
                    self.log_scroll = self.log_scroll.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.log_scroll = (self.log_scroll + 1).min(self.logs.len().saturating_sub(1));
                    if self.log_scroll >= self.logs.len().saturating_sub(1) {
                        self.auto_scroll = true;
                    }
                }
                KeyCode::PageUp => {
                    self.auto_scroll = false;
                    self.log_scroll = self.log_scroll.saturating_sub(10);
                }
                KeyCode::PageDown => {
                    self.log_scroll = (self.log_scroll + 10).min(self.logs.len().saturating_sub(1));
                    if self.log_scroll >= self.logs.len().saturating_sub(1) {
                        self.auto_scroll = true;
                    }
                }
                KeyCode::Char('G') | KeyCode::End => {
                    self.auto_scroll = true;
                    self.log_scroll = self.logs.len().saturating_sub(1);
                }
                KeyCode::Char('g') | KeyCode::Home => {
                    self.auto_scroll = false;
                    self.log_scroll = 0;
                }
                KeyCode::Char('s') => {
                    if self.is_running {
                        SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
                        self.operation_status_text = Some("Zatrzymywanie operacji... Czekam na wątki.".to_string());
                    }
                }
                KeyCode::Enter | KeyCode::Esc => {
                    if !self.is_running {
                        self.pop_view();
                    }
                }
                _ => {}
            },
        }
    }

    fn handle_dashboard_selection(&mut self) {
        match self.dashboard_menu_state.selected().unwrap_or(0) {
            0 => self.push_view(View::ScannerSubMenu),
            1 => self.open_path_modal(
                "Poligon (Chaos Monkey)",
                "Katalog z plikami testowymi:",
                "last_training.conf",
                PathInputTarget::TrainingGround,
            ),
            2 => self.open_path_modal(
                "Poligon Snajperski",
                "Ścieżka do pliku testowego:",
                "last_snipe.conf",
                PathInputTarget::SniperTest,
            ),
            3 => self.open_path_modal(
                "Komora Radiacyjna (God Mode)",
                "Ścieżka do zdrowego pliku:",
                "last_god.conf",
                PathInputTarget::GodMode,
            ),
            4 => self.open_path_modal(
                "Sanityzator Wideo",
                "Ścieżka do pliku wideo:",
                "last_sanitizer.conf",
                PathInputTarget::SanitizerFile,
            ),
            5 => {
                self.refresh_preview_files();
                if self.preview_files.is_empty() {
                    self.active_modal = Modal::NotificationDialog {
                        title: "Odtwarzacz Zaufania".to_string(),
                        message: "Brak zrekonstruowanych plików w folderze wyjściowym!".to_string(),
                        is_error: false,
                    };
                } else {
                    self.push_view(View::PreviewFileSelect);
                }
            }
            6 => {
                self.active_modal = Modal::ConfirmAction {
                    title: "Garbage Collector".to_string(),
                    message: "Trwale usunąć zrekonstruowane uszkodzone oryginały?".to_string(),
                    action: ConfirmActionTarget::GarbageCollector,
                    selected_yes: false,
                };
            }
            7 => self.generate_report(),
            8 => self.export_brain(),
            9 => self.open_path_modal(
                "Import Wiedzy AI",
                "Ścieżka do pliku JSON:",
                "brain_export.json",
                PathInputTarget::BrainImport,
            ),
            10 => self.sync_cloud(),
            11 => self.force_download_all(),
            12 => self.pop_view(),
            _ => {}
        }
    }

    fn open_new_workspace_modal(&mut self) {
        self.active_modal = Modal::NewWorkspace {
            input: String::new(),
            cursor: 0,
            error_msg: None,
        };
    }

    fn open_path_modal(&mut self, title: &str, prompt: &str, conf: &str, target: PathInputTarget) {
        let default_path = if let Some(ref ws) = self.active_workspace {
            std::fs::read_to_string(ws.root_dir.join(conf))
                .unwrap_or_default()
                .trim()
                .to_string()
        } else {
            String::new()
        };
        let len = default_path.len();
        self.active_modal = Modal::PathInput {
            title: title.to_string(),
            prompt: prompt.to_string(),
            input: default_path,
            cursor: len,
            conf_file: conf.to_string(),
            target,
            error_msg: None,
        };
    }

    fn execute_path_action(&mut self, target: PathInputTarget, path: String) {
        match target {
            PathInputTarget::ScannerSingle => self.launch_scanner(path, crate::scanner::ScanMode::SingleRepair),
            PathInputTarget::ScannerFull => self.launch_scanner(path, crate::scanner::ScanMode::FullAuto),
            PathInputTarget::ScannerExtract => self.launch_scanner(path, crate::scanner::ScanMode::ExtractOnly),
            PathInputTarget::TrainingGround => self.launch_training(path),
            PathInputTarget::SniperTest => self.launch_sniper(path),
            PathInputTarget::GodMode => self.launch_god_mode(path),
            PathInputTarget::SanitizerFile => {
                self.active_modal = Modal::SanitizerSelectPass {
                    file_path: path,
                    selected_index: 0,
                };
            }
            PathInputTarget::BrainImport => self.import_brain(path),
        }
    }

    fn execute_confirmed_action(&mut self, action: ConfirmActionTarget) {
        match action {
            ConfirmActionTarget::GarbageCollector => {
                if let Some(ref ws) = self.active_workspace {
                    match ws.optimize_storage() {
                        Ok((count, bytes)) => {
                            let mb = bytes as f64 / (1024.0 * 1024.0);
                            self.active_modal = Modal::NotificationDialog {
                                title: "Garbage Collector".to_string(),
                                message: format!("Usunięto {} plików. Zwolniono: {:.2} MB.", count, mb),
                                is_error: false,
                            };
                        }
                        Err(e) => {
                            self.active_modal = Modal::NotificationDialog {
                                title: "Błąd Garbage Collector".to_string(),
                                message: format!("Błąd: {}", e),
                                is_error: true,
                            };
                        }
                    }
                }
            }
            ConfirmActionTarget::QuitApplication => {
                self.should_quit = true;
            }
        }
    }

    // --- Worker Launchers ---

    pub fn launch_scanner(&mut self, path: String, mode: crate::scanner::ScanMode) {
        if let Some(ws) = self.active_workspace.clone() {
            let sender = self.event_sender.clone();
            crate::SHUTDOWN_FLAG.store(false, std::sync::atomic::Ordering::SeqCst);
            self.is_running = true;
            self.current_operation = Some(match mode {
                crate::scanner::ScanMode::SingleRepair => "Szybka Naprawa Pliku".to_string(),
                crate::scanner::ScanMode::FullAuto => "Masowe Skanowanie Katalogu".to_string(),
                crate::scanner::ScanMode::ExtractOnly => "Pobór Krwi (Ekstrakcja Dawców)".to_string(),
            });
            self.stats = StatUpdate::default();
            self.thread_statuses.clear();
            self.operation_status_text = Some("Trwa skanowanie... Naciśnij [s], aby zatrzymać.".to_string());
            self.push_view(View::OperationRunning);

            std::thread::spawn(move || {
                crate::scanner::run_scanner(&ws, &path, mode, &sender);
            });
        }
    }

    pub fn launch_training(&mut self, path: String) {
        if let Some(ws) = self.active_workspace.clone() {
            let sender = self.event_sender.clone();
            crate::SHUTDOWN_FLAG.store(false, std::sync::atomic::Ordering::SeqCst);
            self.is_running = true;
            self.current_operation = Some("Poligon: Chaos Monkey".to_string());
            self.stats = StatUpdate::default();
            self.thread_statuses.clear();
            self.operation_status_text = Some("Trwa trening bazy wiedzy... Naciśnij [s], aby zatrzymać.".to_string());
            self.push_view(View::OperationRunning);

            std::thread::spawn(move || {
                let _ = crate::training_ground::run_training(&ws, &path, &sender);
            });
        }
    }

    pub fn launch_sniper(&mut self, path: String) {
        if let Some(ws) = self.active_workspace.clone() {
            let sender = self.event_sender.clone();
            crate::SHUTDOWN_FLAG.store(false, std::sync::atomic::Ordering::SeqCst);
            self.is_running = true;
            self.current_operation = Some("Poligon: Test Snajperski".to_string());
            self.stats = StatUpdate::default();
            self.thread_statuses.clear();
            self.operation_status_text = Some("Trwa test celowany... Naciśnij [s], aby zatrzymać.".to_string());
            self.push_view(View::OperationRunning);

            std::thread::spawn(move || {
                let _ = crate::training_ground::run_sniper_test(&ws, &path, &sender);
            });
        }
    }

    pub fn launch_god_mode(&mut self, path: String) {
        if let Some(ws) = self.active_workspace.clone() {
            let sender = self.event_sender.clone();
            crate::SHUTDOWN_FLAG.store(false, std::sync::atomic::Ordering::SeqCst);
            self.is_running = true;
            self.current_operation = Some("Komora Radiacyjna (God Mode)".to_string());
            self.stats = StatUpdate::default();
            self.thread_statuses.clear();
            self.operation_status_text = Some("Trwa mutacja bitowa... Naciśnij [s], aby zatrzymać.".to_string());
            self.push_view(View::OperationRunning);

            std::thread::spawn(move || {
                let _ = crate::god_mode::run_extreme_mutation(&ws, &path, &sender);
            });
        }
    }

    pub fn launch_sanitizer(&mut self, path: String, use_2pass: bool) {
        if let Some(ws) = self.active_workspace.clone() {
            let sender = self.event_sender.clone();
            crate::SHUTDOWN_FLAG.store(false, std::sync::atomic::Ordering::SeqCst);
            self.is_running = true;
            self.current_operation = Some("Głęboka Sanityzacja FFmpeg".to_string());
            self.sanitizer_metrics = SanitizerMetrics::default();
            self.operation_status_text = Some("Trwa transkodowanie... Naciśnij [s], aby zatrzymać.".to_string());
            self.push_view(View::OperationRunning);

            std::thread::spawn(move || {
                let _ = crate::sanitizer::run_deep_sanitization(&ws, &path, &sender, use_2pass);
            });
        }
    }

    pub fn generate_report(&mut self) {
        if let Some(ref ws) = self.active_workspace {
            let report_path = ws.root_dir.join("raport_klienta.html");
            let date_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let html_content = format!(
                "<!DOCTYPE html><html lang=\"pl\"><head><meta charset=\"UTF-8\"><title>Raport Odzyskiwania - {}</title></head><body><h1>Raport Odzyskiwania - {}</h1><p>Data: {}</p></body></html>",
                ws.name.to_uppercase(),
                ws.name,
                date_str
            );
            if std::fs::write(&report_path, html_content).is_ok() {
                self.active_modal = Modal::NotificationDialog {
                    title: "Raport Klienta".to_string(),
                    message: format!("Wygenerowano raport HTML w:\n{:?}", report_path),
                    is_error: false,
                };
            } else {
                self.active_modal = Modal::NotificationDialog {
                    title: "Błąd Raportu".to_string(),
                    message: "Nie udało się zapisać raportu na dysku.".to_string(),
                    is_error: true,
                };
            }
        }
    }

    pub fn export_brain(&mut self) {
        if let Some(ref ws) = self.active_workspace {
            let path = ws.root_dir.join("brain_export.json");
            if crate::db::export_brain_to_json(ws, path.to_str().unwrap_or_default()).is_ok() {
                self.active_modal = Modal::NotificationDialog {
                    title: "Eksport AI".to_string(),
                    message: format!("Wyeksportowano bazę wiedzy do:\n{:?}", path),
                    is_error: false,
                };
            } else {
                self.active_modal = Modal::NotificationDialog {
                    title: "Błąd Eksportu".to_string(),
                    message: "Błąd podczas eksportu bazy wiedzy do formatu JSON.".to_string(),
                    is_error: true,
                };
            }
        }
    }

    pub fn import_brain(&mut self, path: String) {
        if let Some(ref ws) = self.active_workspace {
            if Path::new(&path).exists() {
                if let Ok(count) = crate::db::import_brain_from_json(ws, &path) {
                    self.active_modal = Modal::NotificationDialog {
                        title: "Import AI".to_string(),
                        message: format!("Pomyślnie zaimportowano {} rekordów bazy wiedzy z: {}", count, path),
                        is_error: false,
                    };
                } else {
                    self.active_modal = Modal::NotificationDialog {
                        title: "Błąd Importu".to_string(),
                        message: "Nie udało się sparsować pliku JSON bazy wiedzy.".to_string(),
                        is_error: true,
                    };
                }
            } else {
                self.active_modal = Modal::NotificationDialog {
                    title: "Błąd Importu".to_string(),
                    message: "Wskazany plik nie istnieje!".to_string(),
                    is_error: true,
                };
            }
        }
    }

    pub fn sync_cloud(&mut self) {
        if let Some(ws) = self.active_workspace.clone() {
            let sender = self.event_sender.clone();
            
            crate::SHUTDOWN_FLAG.store(false, std::sync::atomic::Ordering::SeqCst);
            self.is_running = true;
            self.current_operation = Some("Federated Learning (Synchronizacja Chmury)".to_string());
            self.stats = crate::event::StatUpdate::default();
            self.thread_statuses.clear();
            self.operation_status_text = Some("Trwa synchronizacja Mózgu z siecią... Naciśnij [s], aby zatrzymać.".to_string());
            self.push_view(View::OperationRunning);
            
            std::thread::spawn(move || {
                match crate::db::sync_with_cloud(&ws, Some(&sender)) {
                    Ok(count) => {
                        sender.operation_finished(format!("Synchronizacja z Rój zakończona pomyślnie. Nowe wzorce: {}", count));
                    }
                    Err(e) => {
                        sender.operation_failed("Synchronizacja chmury", &e.to_string());
                    }
                }
            });
        }
    }

    pub fn force_download_all(&mut self) {
        if let Some(ws) = self.active_workspace.clone() {
            let sender = self.event_sender.clone();
            
            crate::SHUTDOWN_FLAG.store(false, std::sync::atomic::Ordering::SeqCst);
            self.is_running = true;
            self.current_operation = Some("Wymuszone Pobieranie (Cloud Download)".to_string());
            self.stats = crate::event::StatUpdate::default();
            self.thread_statuses.clear();
            self.operation_status_text = Some("Pobieranie brakujących dawców... Naciśnij [s], aby zatrzymać.".to_string());
            self.push_view(View::OperationRunning);
            
            std::thread::spawn(move || {
                match crate::db::download_missing_donors(&ws, Some(&sender)) {
                    Ok(count) => {
                        sender.operation_finished(format!("Pobieranie zakończone. Pomyślnie zrekonstruowano {} plików moov.", count));
                    }
                    Err(e) => {
                        sender.operation_failed("Pobieranie chmury", &e.to_string());
                    }
                }
            });
        }
    }

    // --- List Navigation Utilities ---

    fn nav_up(state: &mut ListState, count: usize) {
        if count == 0 {
            state.select(None);
            return;
        }
        let i = match state.selected() {
            Some(i) => {
                if i == 0 {
                    count - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        state.select(Some(i));
    }

    fn nav_down(state: &mut ListState, count: usize) {
        if count == 0 {
            state.select(None);
            return;
        }
        let i = match state.selected() {
            Some(i) => {
                if i + 1 >= count {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        state.select(Some(i));
    }
}

// --- UTF-8 Safe Text Editing Helpers ---

fn insert_char_at_cursor(buffer: &mut String, cursor: &mut usize, c: char) {
    buffer.insert(*cursor, c);
    *cursor += c.len_utf8();
}

fn delete_char_before_cursor(buffer: &mut String, cursor: &mut usize) {
    if *cursor > 0 {
        let prev_index = buffer[..*cursor]
            .char_indices()
            .last()
            .map(|(i, _)| i)
            .unwrap_or(0);
        buffer.remove(prev_index);
        *cursor = prev_index;
    }
}

fn delete_char_at_cursor(buffer: &mut String, cursor: usize) {
    if cursor < buffer.len() {
        buffer.remove(cursor);
    }
}

fn move_cursor_left(buffer: &str, cursor: &mut usize) {
    if *cursor > 0 {
        *cursor = buffer[..*cursor]
            .char_indices()
            .last()
            .map(|(i, _)| i)
            .unwrap_or(0);
    }
}

fn move_cursor_right(buffer: &str, cursor: &mut usize) {
    if *cursor < buffer.len() {
        *cursor = buffer[*cursor..]
            .char_indices()
            .nth(1)
            .map(|(i, _)| *cursor + i)
            .unwrap_or_else(|| buffer.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventState;

    fn make_key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: crossterm::event::KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn test_menu_navigation_wrapping() {
        let (tx, rx) = crate::event::channel();
        let mut app = App::with_channel(tx, rx);
        assert_eq!(app.current_view, View::MainMenu);
        assert_eq!(app.main_menu_state.selected(), Some(0));

        // Up from 0 wraps to 2
        app.handle_key(make_key(KeyCode::Up));
        assert_eq!(app.main_menu_state.selected(), Some(2));

        // Down from 2 wraps to 0
        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.main_menu_state.selected(), Some(0));

        // 'j' and 'k' navigation also works
        app.handle_key(make_key(KeyCode::Char('k')));
        assert_eq!(app.main_menu_state.selected(), Some(2));
        app.handle_key(make_key(KeyCode::Char('j')));
        assert_eq!(app.main_menu_state.selected(), Some(0));
    }

    #[test]
    fn test_modal_text_editing_unicode() {
        let (tx, rx) = crate::event::channel();
        let mut app = App::with_channel(tx, rx);

        app.active_modal = Modal::NewWorkspace {
            input: String::new(),
            cursor: 0,
            error_msg: None,
        };

        // Type "żółw" (multi-byte UTF-8 characters)
        for c in ['ż', 'ó', 'ł', 'w'] {
            app.handle_key(make_key(KeyCode::Char(c)));
        }

        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_eq!(input, "żółw");
            assert_eq!(*cursor, "żółw".len());
        } else {
            panic!("Expected NewWorkspace modal");
        }

        // Backspace 'w'
        app.handle_key(make_key(KeyCode::Backspace));
        if let Modal::NewWorkspace { input, cursor, .. } = &app.active_modal {
            assert_eq!(input, "żół");
            assert_eq!(*cursor, "żół".len());
        } else {
            panic!("Expected NewWorkspace modal");
        }

        // Left arrow moves back one char 'ł'
        app.handle_key(make_key(KeyCode::Left));
        if let Modal::NewWorkspace { cursor, .. } = &app.active_modal {
            assert_eq!(*cursor, "żó".len());
        }

        // Right arrow moves back to end
        app.handle_key(make_key(KeyCode::Right));
        if let Modal::NewWorkspace { cursor, .. } = &app.active_modal {
            assert_eq!(*cursor, "żół".len());
        }

        // Esc cancels modal
        app.handle_key(make_key(KeyCode::Esc));
        assert_eq!(app.active_modal, Modal::None);
    }

    #[test]
    fn test_event_channel_draining_bounded() {
        let (tx, rx) = crate::event::channel();
        let mut app = App::with_channel(tx.clone(), rx);

        for i in 0..1000 {
            tx.info("TEST", format!("Log {}", i));
        }

        app.process_events();
        assert_eq!(app.logs.len(), 500);

        app.process_events();
        assert_eq!(app.logs.len(), 1000);
    }

    #[test]
    fn test_view_stack_push_pop() {
        let (tx, rx) = crate::event::channel();
        let mut app = App::with_channel(tx, rx);
        assert_eq!(app.current_view, View::MainMenu);

        app.push_view(View::WorkspaceSelect);
        assert_eq!(app.current_view, View::WorkspaceSelect);
        assert_eq!(app.view_stack.len(), 1);

        app.push_view(View::WorkspaceDashboard);
        assert_eq!(app.current_view, View::WorkspaceDashboard);
        assert_eq!(app.view_stack.len(), 2);

        // Pop back to WorkspaceSelect
        app.pop_view();
        assert_eq!(app.current_view, View::WorkspaceSelect);

        // Pop back to MainMenu
        app.pop_view();
        assert_eq!(app.current_view, View::MainMenu);

        // Pop from MainMenu sets should_quit
        app.pop_view();
        assert!(app.should_quit);
    }

    #[test]
    fn test_rapid_keyboard_spamming() {
        let (tx, rx) = crate::event::channel();
        let mut app = App::with_channel(tx, rx);

        let keys = [
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Char('j'),
            KeyCode::Char('k'),
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Home,
            KeyCode::End,
        ];

        for i in 0..1000 {
            let key = keys[i % keys.len()];
            app.handle_key(make_key(key));
        }

        // Ensure state remains valid and bounded
        assert_eq!(app.current_view, View::MainMenu);
        assert!(app.main_menu_state.selected().unwrap() < 3);
    }

    #[test]
    fn test_take_pending_preview() {
        let (tx, rx) = crate::event::channel();
        let mut app = App::with_channel(tx, rx);

        assert_eq!(app.take_pending_preview(), None);

        let test_path = PathBuf::from("/tmp/preview.mp4");
        app.pending_preview = Some(test_path.clone());
        assert_eq!(app.take_pending_preview(), Some(test_path));
        assert_eq!(app.take_pending_preview(), None);
    }

    #[test]
    fn test_app_event_handling() {
        let (tx, rx) = crate::event::channel();
        let mut app = App::with_channel(tx.clone(), rx);

        // Stats update
        let stats = StatUpdate::new(10, 5, 5, 4, 1024, 2);
        let _ = tx.send(AppEvent::Stats(stats));
        app.process_events();
        assert_eq!(app.stats.files_scanned, 10);
        assert_eq!(app.stats.files_repaired, 4);

        // Thread status
        let _ = tx.send(AppEvent::ThreadStatus((1, "Scanning").into()));
        app.process_events();
        assert_eq!(app.thread_statuses.get(&1), Some(&"Scanning".to_string()));

        // Operation lifecycle
        let _ = tx.send(AppEvent::OperationStarted("Test Op".to_string()));
        app.process_events();
        assert!(app.is_running);
        assert_eq!(app.current_operation, Some("Test Op".to_string()));

        let _ = tx.send(AppEvent::OperationFinished("Success".to_string()));
        app.process_events();
        assert!(!app.is_running);
        assert!(app.operation_status_text.as_ref().unwrap().contains("Zakończono: Success"));
    }
}
