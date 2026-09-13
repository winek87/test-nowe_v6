//! MP4 Doctor Terminal User Interface (TUI)
//!
//! Exposes terminal lifecycle management, the interactive application state machine,
//! and responsive Ratatui rendering widgets.

pub mod terminal;
pub mod app;
pub mod ui;

pub use terminal::TerminalGuard;
pub use app::App;
