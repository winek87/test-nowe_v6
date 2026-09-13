// src/tui/mod.rs

//! # Moduł TUI (Text User Interface)
//! 
//! Odpowiada za wszystkie komponenty graficzne oparte na bibliotece Ratatui.
//! Wyodrębnia logikę renderowania z logiki biznesowej, wdrażając architekturę 
//! bazującą na komponentach (Component-Based UI).

pub mod state;
pub mod logs_panel;
pub mod scanner_panel;
pub mod progress;
pub mod hardware_panel;
pub mod phase_screen;
pub mod dashboard;
pub mod settings_screen;
pub mod dng_repair_screen;
