// src/menu/actions.rs

//! # Moduł Akcji (Wykonawca Zadań / Orkiestrator Ratatui)
//! Serce systemu kryminalistycznego. Odbiera polecenia z Menu, uruchamia 
//! poszczególne Fazy w tle na osobnych wątkach, nasłuchuje ich komunikatów MPSC 
//! i na żywo rysuje złożony, podzielony na sekcje interfejs TUI.

use crate::menu::state::AppState;
use crate::menu::settings_actions::{self, SettingsUiState};
use crate::settings::Ustawienia;
use crate::{diag, dng_repair, duplicate_finder, phases, reset, workspace_cleanup};
use crate::tui::state::{PhaseEvent, PhaseUIState};

use colored::Colorize;
use crossterm::{
    event::{self, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
    Terminal,
};

use rusqlite::Connection;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Definicja standardowego interfejsu dla każdej Fazy Kryminalistycznej.
/// `Box<dyn FnOnce...>` (nie goły wskaźnik funkcji) celowo — pozwala to
/// domknięciom z przechwyconymi danymi (np. już wybranymi regułami YARA dla
/// Fazy 16, albo listą aktywnych modułów naprawczych dla Fazy 17) trafiać
/// do tego samego `run_phase_with_ui` co zwykłe `fn` wskaźniki pozostałych
/// faz — każdy element `fn(...)` automatycznie spełnia ten typ.
pub type PhaseFn = Box<dyn FnOnce(&mut Connection, &Ustawienia, mpsc::Sender<PhaseEvent>) -> rusqlite::Result<()> + Send>;

// ============================================================================
// GŁÓWNY DYSTRYBUTOR AKCJI
// ============================================================================

/// Odbiera numer akcji wybrany z menu, mapuje go na odpowiedni moduł programu
/// i zleca jego wykonanie, oddając mu kontrolę nad ekranem.
pub fn execute_action(
    idx: usize,
    app: &mut AppState,
    conn: &mut Connection,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> io::Result<()> {
    info!("Orkiestrator odbiera zadanie. Wykonywanie akcji przypisanej do indeksu: {}", idx);
    debug!("Wywołanie systemowe (Match) dla akcji: {}", idx);
    
    match idx {
        // [ 0 ] TRYB AUTO-PILOT
        0 => run_autopilot(terminal, conn, app)?,

        // [ 2..18 ] WYWOŁANIA POJEDYNCZYCH FAZ (Wewnątrz Ratatui TUI)
        2 => { let _ = run_phase_with_ui(terminal, conn, app, "[  🗺️  ]", "Faza 01: Mapowanie struktury", "Akwizycja", "Wczytuje ścieżki i buduje drzewo bazy danych.", Box::new(phases::phase1::run)); }
        3 => { let _ = run_phase_with_ui(terminal, conn, app, "[ 📏  ]", "Faza 02: Akwizycja Metadanych", "Rozmiary", "Oblicza rozmiary i wagi plików, eliminuje puste wydmuszki.", Box::new(phases::phase2::run)); }
        4 => { let _ = run_phase_with_ui(terminal, conn, app, "[ 🧬  ]", "Faza 03: Hashe BLAKE3 (Zgodne pliki)", "Kryptografia", "Generuje z prędkością NVMe kryptograficzne skróty plików wspólnych.", Box::new(phases::phase3::run)); }
        5 => { let _ = run_phase_with_ui(terminal, conn, app, "[ 🧬  ]", "Faza 04: Hashe BLAKE3 (Brakujące)", "Kryptografia", "Skanuje pliki resztkowe i odrzuty.", Box::new(phases::phase4::run)); }
        6 => { let _ = run_phase_with_ui(terminal, conn, app, "[ 📅  ]", "Faza 05: Czas modyfikacji i prawa", "i-node", "Ekstrakcja uprawnień Unix (SUID/ROOT) i Timestampów modyfikacji.", Box::new(phases::phase5::run)); }
        7 => { let _ = run_phase_with_ui(terminal, conn, app, "[ 👻  ]", "Faza 06: Detekcja Pustych Plików", "Zawartość", "Szuka uciętych ogonów (Brak EOF) oraz wydmuszek po TRIM.", Box::new(phases::phase6::run)); }
        8 => { let _ = run_phase_with_ui(terminal, conn, app, "[ 🎲  ]", "Faza 07: Analiza Entropii", "Matematyka", "Szum informacyjny, zaszyfrowanie Ransomware i zepsuta kompresja.", Box::new(phases::phase7::run)); }
        9 => { let _ = run_phase_with_ui(terminal, conn, app, "[ 📜  ]", "Faza 10: Walidacja Tekstu (MIME)", "Semantyka", "Weryfikuje czystość znaków ASCII/UTF-8. Szuka ukrytych ładunków.", Box::new(phases::phase10::run)); }
        10 => { let _ = run_phase_with_ui(terminal, conn, app, "[ 📦  ]", "Faza 11: Walidacja Archiwów", "Kontenery", "Sprawdza drzewa Central Directory i zwalcza Zip Bomby.", Box::new(phases::phase11::run)); }
        11 => { let _ = run_phase_with_ui(terminal, conn, app, "[ 📸  ]", "Faza 12: Struktury Obrazów (EXIF)", "Multimedia", "Odzyskuje GPS, oryginalne daty wykonania i sprzęt foto/wideo.", Box::new(phases::phase12::run)); }
        12 => { let _ = run_phase_with_ui(terminal, conn, app, "[  🖼️  ]", "Faza 13: Dekodowanie Mediów", "Multimedia", "Renderuje obrazy piksel po pikselu w poszukiwaniu Gray Banding.", Box::new(phases::phase13::run)); }
        // [ 12 ] FAZA 19 - OSOBNA diagnostyka wideo, celowo NIE rozszerzenie
        // Fazy 13: pozwala przeskanować wideo bez ponownego przebiegu całej
        // diagnostyki obrazów na już przetworzonych plikach.
        13 => { let _ = run_phase_with_ui(terminal, conn, app, "[  🎬  ]", "Faza 19: Diagnostyka Kontenerów Wideo", "Multimedia", "MP4/MOV/M4V, MKV/WebM, FLV oraz strumienie TS z dokładną analizą utraty pakietów.", Box::new(phases::phase19_video::run)); }
        14 => { let _ = run_phase_with_ui(terminal, conn, app, "[ 👯‍♂️ ]", "Faza 14: Rozmyte Hashowanie", "Korelacja", "Ssdeep. Łączy pofragmentowane i zmienione pliki (Zaginione bliźniaki).", Box::new(phases::phase14::run)); }
        15 => { let _ = run_phase_with_ui(terminal, conn, app, "[  🏷️  ]", "Faza 15: Rozszerzone Atrybuty", "Metadane", "Analizuje ukryte strumienie systemowe XATTR i ślady pobrań z Sieci.", Box::new(phases::phase15::run)); }

        // [ 15 ] FAZA 16 (YARA) - wybór reguł MUSI nastąpić PRZED trybem Raw
        // (patrz dokumentacja `phases::phase16::select_and_compile_rules` —
        // naprawiony konflikt terminala między `dialoguer` a aktywnym Ratatui).
        16 => {
            let rules = suspend_tui_for_cli(terminal, phases::phase16::select_and_compile_rules);
            match rules {
                Some(rules) => {
                    let phase_fn: PhaseFn = Box::new(move |conn, u, tx| phases::phase16::run(conn, u, tx, rules));
                    let _ = run_phase_with_ui(terminal, conn, app, "[  ☢  ]", "Faza 16: Skanowanie YARA", "Malware", "Rozpoznaje zagrożenia wirusowe, notatki hakerskie i skrypty.", phase_fn);
                }
                None => info!("Faza 16 pominięta - nie wybrano żadnych reguł YARA."),
            }
        }
        // [ 16 ] NAPRAWA I REKONSTRUKCJA - podmenu grupujące Fazę 17, Fazę 18
        // i narzędzie Składania Strukturalnego DNG (patrz run_repair_submenu).
        17 => { let _ = run_repair_submenu(terminal, app, conn); }
        18 => { let _ = run_phase_with_ui(terminal, conn, app, "[ 📝  ]", "Faza 08: Raport Końcowy (CSV)", "Eksport", "Agreguje wszystkie wskaźniki i wypuszcza arkusz decyzyjny Euro-CSV.", Box::new(phases::phase8::run)); }
        19 => { let _ = run_phase_with_ui(terminal, conn, app, "[ 👑  ]", "Faza 09: Smart Merge (Złota Kopia)", "Fuzja", "Zlewa zrekonstruowane i zdrowe dane w wyczyszczoną kopię finalną.", Box::new(phases::phase9::run)); }

        // [ 19 ] WYKRYWANIE DUPLIKATÓW TREŚCI - szybki, jednorazowy raport (bez
        // wątków/postępu, sama analiza SQL) - ten sam CLI-suspended wzorzec co diag/reset.
        20 => execute_with_cli_suspension(terminal, || { let _ = duplicate_finder::run(conn, app.ustawienia); }),
        // [ 21..22 ] ZAWIESZENIE TUI DO TRYBU CLI DLA MODUŁÓW ZEWNĘTRZNYCH (bez zmian)
        22 => execute_with_cli_suspension(terminal, || { let _ = diag::run(conn); }),
        23 => execute_with_cli_suspension(terminal, || { let _ = reset::run(conn, app.ustawienia); }),
        // [ 24 ] SPRZĄTANIE PRZESTRZENI ROBOCZEJ - raport zajętości katalogów
        // technicznych Faz 17/18 i usuwanie plików osieroconych. Ten sam
        // CLI-suspended wzorzec co diag/reset, bo operacja jest interaktywna.
        24 => execute_with_cli_suspension(terminal, || { let _ = workspace_cleanup::run(conn, app.ustawienia); }),
        // [ 25 ] MP4 DOCTOR - interfejs zewnętrznego projektu, prowadzony w
        // NASZYM terminalu (patrz `run_mp4_doctor_with_ui`).
        25 => { let _ = run_mp4_doctor_with_ui(terminal, app); }
        // [ 26 ] USTAWIENIA - PEŁNY EKRAN RATATUI (spójny z resztą aplikacji, bez zawieszania TUI)
        26 => { let _ = run_settings_with_ui(terminal, app); }
        _ => {
            warn!("Nieznany indeks akcji ({}). Opcja nieistniejąca.", idx);
        }
    }
        
    info!("Akcja o indeksie {} zakończyła działanie. Powrót do menu głównego.", idx);
    Ok(())
}

// ============================================================================
// ASYNCHRONICZNY ORKIESTRATOR POJEDYNCZEJ FAZY (RATATUI)
// ============================================================================

/// Otwiera sub-ekran Fazy w TUI Ratatui, uruchamia proces Fazy w tle i na żywo renderuje 
/// wielopanelowy układ ekranu (Sprzęt z lewej, Faza z prawej, Ścieżki na dole).
/// Uruchamia fazę i po zakończeniu CZEKA na potwierdzenie użytkownika.
///
/// Wariant dla menu ręcznego — operator chce zobaczyć wynik i sam zdecydować,
/// kiedy wrócić. Autopilot używa [`run_phase_bez_czekania`].
#[allow(clippy::too_many_arguments)]
fn run_phase_with_ui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    conn: &mut Connection,
    app: &mut AppState,
    icon: &str,
    title: &str,
    category: &str,
    desc: &str,
    phase_fn: PhaseFn,
) -> rusqlite::Result<Duration> {
    run_phase_z_opcjami(terminal, conn, app, icon, title, category, desc, phase_fn, true)
}

/// Uruchamia fazę i wraca NATYCHMIAST po jej zakończeniu.
///
/// Wariant dla autopilota. Tryb bezobsługowy ma sens tylko wtedy, gdy nie
/// wymaga obsługi — a poprzednio autopilot wołał wariant czekający, więc
/// zatrzymywał się na Enter po KAŻDEJ fazie i „puszczenie systemu na noc"
/// (co obiecuje dokumentacja `run_autopilot`) w praktyce nie działało.
///
/// Ekran końcowy fazy jest rysowany RAZ, żeby jej wynik był widoczny, zanim
/// zacznie się następna. Podsumowanie całego przebiegu na końcu autopilota
/// nadal czeka na Enter — tam zatrzymanie jest pożądane.
#[allow(clippy::too_many_arguments)]
fn run_phase_bez_czekania(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    conn: &mut Connection,
    app: &mut AppState,
    icon: &str,
    title: &str,
    category: &str,
    desc: &str,
    phase_fn: PhaseFn,
) -> rusqlite::Result<Duration> {
    run_phase_z_opcjami(terminal, conn, app, icon, title, category, desc, phase_fn, false)
}

#[allow(clippy::too_many_arguments)]
fn run_phase_z_opcjami(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    conn: &mut Connection,
    app: &mut AppState,
    icon: &str,
    title: &str,
    category: &str,
    desc: &str,
    phase_fn: PhaseFn,
    czekaj_na_potwierdzenie: bool,
) -> rusqlite::Result<Duration> {
    let mut ui_state = PhaseUIState::new(icon, title, category, desc);
    info!("Rozpoczęto wywołanie Fazy Roboczej: {} ({})", title, category);
    
    let (tx, rx) = mpsc::channel();
    let start_time = Instant::now();

    crate::utils::CANCEL_SIGNAL.store(false, std::sync::atomic::Ordering::SeqCst);

    // Klonujemy WYŁĄCZNIE ustawienia dla wątku roboczego, dzięki czemu główny wątek (UI)
    // zachowuje prawo do mutowania `app` (odświeżanie procesora i dysków podczas działania).
    let ustawienia_clone = app.ustawienia.clone();

    // Utworzenie Scope, dzięki czemu kompilator ufa, że referencje w wątku nie wyciekną
    std::thread::scope(|s| {
        // [WĄTEK ROBOCZY] - Ciężkie operacje I/O, Rayon i baza SQLite
        s.spawn(move || {
            if let Err(e) = phase_fn(conn, &ustawienia_clone, tx.clone()) {
                let _ = tx.send(PhaseEvent::Log(format!("BŁĄD KRYTYCZNY BAZY DANYCH: {}", e)));
            }
            let _ = tx.send(PhaseEvent::Done);
        });

        let mut last_tick = Instant::now();
        let tick_rate = Duration::from_millis(app.ustawienia.dashboard_refresh_rate);
        // Śledzi moment naciśnięcia Ctrl+C, żeby wyświetlać żywy licznik
        // oczekiwania na bezpieczne zamknięcie zamiast milczącego ekranu.
        let mut cancel_requested_at: Option<Instant> = None;
        let mut last_cancel_tick_shown: u64 = 0;

        // [GŁÓWNY WĄTEK UI] - Nasłuchuje logów i rysuje ekran na żywo
        loop {
            // 1. Odbiór wiadomości od wątku roboczego (Paski, Logi, Ścieżki)
            match rx.recv_timeout(Duration::from_millis(16)) {
                Ok(event) => {
                    if matches!(event, PhaseEvent::Done) { break; }
                    ui_state.process_event(event);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {} 
                Err(mpsc::RecvTimeoutError::Disconnected) => break, 
            }

            // 2. Odświeżanie statystyk sprzętowych w tle
            if last_tick.elapsed() >= tick_rate {
                app.tick_hw();
                last_tick = Instant::now();
            }

            // 3. Przechwytywanie klawiatury użytkownika (Ratunkowe Ctrl+C)
            if event::poll(Duration::from_millis(0)).unwrap_or(false)
                && let Ok(event::Event::Key(key)) = event::read()
                    && key.kind == KeyEventKind::Press && key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                        crate::utils::CANCEL_SIGNAL.store(true, std::sync::atomic::Ordering::SeqCst);
                        if cancel_requested_at.is_none() {
                            cancel_requested_at = Some(Instant::now());
                            ui_state.process_event(PhaseEvent::Log("⚠️ WYKRYTO PRZERWANIE UŻYTKOWNIKA (Ctrl+C). Oczekiwanie na bezpieczne zamknięcie szyny I/O...".to_string()));
                        }
                    }

            // 3b. Żywy licznik sekund oczekiwania na dogaszenie wątków roboczych.
            // Bez tego ekran milczy między komunikatem o przerwaniu a faktycznym
            // powrotem do menu, co sprawia wrażenie zawieszenia programu.
            if let Some(started) = cancel_requested_at {
                let elapsed_secs = started.elapsed().as_secs();
                if elapsed_secs > last_cancel_tick_shown {
                    last_cancel_tick_shown = elapsed_secs;
                    ui_state.process_event(PhaseEvent::Log(format!(
                        "   ...oczekiwanie na dogaszenie wątków roboczych ({}s)",
                        elapsed_secs
                    )));
                }
            }

            // 4. GŁÓWNY PODZIAŁ EKRANU RATATUI
            let _ = terminal.draw(|f| {
                let full_screen = f.area();
                
                // Krok A: Tniemy ekran w poziomie (Góra: 100%, Dół: 5 linijek na ścieżki)
                let main_vertical = ratatui::layout::Layout::default()
                    .direction(ratatui::layout::Direction::Vertical)
                    .constraints([ratatui::layout::Constraint::Min(10), ratatui::layout::Constraint::Length(9)])
                    .split(full_screen);

                // Krok B: Tniemy górę w pionie na lewą i prawą stronę
                let top_horizontal = ratatui::layout::Layout::default()
                    .direction(ratatui::layout::Direction::Horizontal)
                    .constraints([ratatui::layout::Constraint::Percentage(50), ratatui::layout::Constraint::Percentage(50)])
                    .split(main_vertical[0]);

                // Krok C: Dynamiczny podział LEWEJ strony
                // REGRESJA (measure twice — druga weryfikacja Gemini, todo.menu.md):
                // ten sam panel co `dashboard.rs` (`draw_paths_panel`), teraz
                // przez WSPÓLNĄ stałą (`hardware_panel::WYSOKOSC_PANELU_SCIEZEK_MAX`)
                // zamiast osobnego magicznego `11` — ta zduplikowana kopia layoutu
                // nie dostała bumpu przy dodaniu linii "Ścieżka Docelowa" w
                // `5c444f5`, więc panel był tu obcinany na każdym ekranie fazy
                // "na żywo". Wspólna stała eliminuje TĘ KLASĘ błędu na przyszłość.
                let left_constraints = if !ui_state.side_texts.is_empty() {
                    vec![
                        ratatui::layout::Constraint::Length(3),  // HW
                        ratatui::layout::Constraint::Length(8),  // Disks
                        ratatui::layout::Constraint::Length(crate::tui::hardware_panel::WYSOKOSC_PANELU_SCIEZEK_MAX), // Config
                        ratatui::layout::Constraint::Min(5),     // Aktywny Skaner (Live) pod spodem
                    ]
                } else {
                    vec![
                        ratatui::layout::Constraint::Length(3),  // HW
                        ratatui::layout::Constraint::Length(8),  // Disks
                        ratatui::layout::Constraint::Min(crate::tui::hardware_panel::WYSOKOSC_PANELU_SCIEZEK_MAX), // Config do końca
                    ]
                };

                let left_chunks = ratatui::layout::Layout::default()
                    .direction(ratatui::layout::Direction::Vertical)
                    .constraints(left_constraints)
                    .split(top_horizontal[0]);

                // Rysujemy Lewą Stronę
                crate::tui::hardware_panel::draw_hw_panel(f, app, left_chunks[0]);
                crate::tui::hardware_panel::draw_disks_panel(f, app, left_chunks[1]);
                crate::tui::hardware_panel::draw_paths_panel(f, app, left_chunks[2]);
                
                if !ui_state.side_texts.is_empty() {
                    crate::tui::scanner_panel::draw_side_stats_panel(f, &ui_state, left_chunks[3]);
                }

                // Rysujemy Prawą Stronę (Logi operacyjne i Paski)
                crate::tui::phase_screen::draw_phase_screen(f, &ui_state, top_horizontal[1]);
                
                // Rysujemy Dół Ekranu (Szeroki panel na ekstremalnie długie ścieżki I/O)
                crate::tui::scanner_panel::draw_bottom_paths_panel(f, &ui_state, main_vertical[1]);
            });
        }
    });

    ui_state.process_event(PhaseEvent::Log(
        if czekaj_na_potwierdzenie {
            "\n✅ FAZA ZAKOŃCZONA! Naciśnij [ENTER], aby wrócić do Menu Głównego...".to_string()
        } else {
            "\n✅ FAZA ZAKOŃCZONA — autopilot przechodzi do następnej.".to_string()
        }
    ));

    // ========================================================================
    // EKRAN KOŃCOWY FAZY
    //
    // W menu ręcznym czeka na [ENTER]/[ESC]. W autopilocie rysuje się RAZ i
    // oddaje sterowanie — patrz `run_phase_bez_czekania`.
    // ========================================================================
    loop {
        let _ = terminal.draw(|f| {
            let full_screen = f.area();
            
            let main_vertical = ratatui::layout::Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([ratatui::layout::Constraint::Min(10), ratatui::layout::Constraint::Length(9)])
                .split(full_screen);

            let top_horizontal = ratatui::layout::Layout::default()
                .direction(ratatui::layout::Direction::Horizontal)
                .constraints([ratatui::layout::Constraint::Percentage(50), ratatui::layout::Constraint::Percentage(50)])
                .split(main_vertical[0]);

            // REGRESJA (measure twice — druga weryfikacja Gemini, todo.menu.md):
            // ten sam panel co `dashboard.rs` (`draw_paths_panel`), teraz przez
            // WSPÓLNĄ stałą (`hardware_panel::WYSOKOSC_PANELU_SCIEZEK_MAX`)
            // zamiast osobnego magicznego `11` — ta zduplikowana kopia layoutu
            // (ekran końcowy fazy/autopilota) nie dostała bumpu przy dodaniu
            // linii "Ścieżka Docelowa" w `5c444f5`. Wspólna stała eliminuje TĘ
            // KLASĘ błędu na przyszłość.
            let left_constraints = if !ui_state.side_texts.is_empty() {
                vec![
                    ratatui::layout::Constraint::Length(3),
                    ratatui::layout::Constraint::Length(8),
                    ratatui::layout::Constraint::Length(crate::tui::hardware_panel::WYSOKOSC_PANELU_SCIEZEK_MAX),
                    ratatui::layout::Constraint::Min(5),
                ]
            } else {
                vec![
                    ratatui::layout::Constraint::Length(3),
                    ratatui::layout::Constraint::Length(8),
                    ratatui::layout::Constraint::Min(crate::tui::hardware_panel::WYSOKOSC_PANELU_SCIEZEK_MAX),
                ]
            };

            let left_chunks = ratatui::layout::Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints(left_constraints)
                .split(top_horizontal[0]);

            crate::tui::hardware_panel::draw_hw_panel(f, app, left_chunks[0]);
            crate::tui::hardware_panel::draw_disks_panel(f, app, left_chunks[1]);
            crate::tui::hardware_panel::draw_paths_panel(f, app, left_chunks[2]);
            
            if !ui_state.side_texts.is_empty() {
                crate::tui::scanner_panel::draw_side_stats_panel(f, &ui_state, left_chunks[3]);
            }

            crate::tui::phase_screen::draw_phase_screen(f, &ui_state, top_horizontal[1]);
            crate::tui::scanner_panel::draw_bottom_paths_panel(f, &ui_state, main_vertical[1]);
        });

        if !czekaj_na_potwierdzenie {
            break;
        }

        if event::poll(Duration::from_millis(50)).unwrap_or(false)
            && let Ok(event::Event::Key(key)) = event::read()
                && key.kind == KeyEventKind::Press && (key.code == KeyCode::Enter || key.code == KeyCode::Esc) {
                    break;
                }
    }

    Ok(start_time.elapsed())
}

// ============================================================================
// NIEZMIENNIKI KOLEJNOŚCI FAZ AUTOPILOTA
//
// Ten plik decyduje, KTÓRE fazy się uruchomią i W JAKIEJ KOLEJNOŚCI — i długo
// nie miał ani jednego testu. Kosztowało to dwie ciche luki: autopilot czekał
// na [ENTER] po każdej fazie (więc tryb „bezobsługowy" nie działał) oraz w
// ogóle nie uruchamiał Fazy 18 (więc Faza 09 miała w hierarchii decyzyjnej
// gałąź, do której nigdy nie dochodziła).
//
// Lista faz musi zostać napisana wprost, bo niesie domknięcia `PhaseFn`, ale
// jej WŁASNOŚCI dają się sprawdzić osobno — i to robi ta sekcja. Kontrola jest
// wołana na prawdziwej liście przy każdym uruchomieniu autopilota, a testy
// karmią ją przypadkami syntetycznymi.
// ============================================================================

/// Zależności danych między fazami: `(wcześniejsza, późniejsza, powód)`.
///
/// Każda pozycja wynika z KODU, nie z intuicji — Faza 17 buduje `RepairContext`
/// z kolumn wypełnianych przez fazy wcześniejsze, a Faza 09 konsumuje ścieżki
/// wytworzone przez Fazy 17 i 18.
const ZALEZNOSCI_FAZ: &[(u32, u32, &str)] = &[
    (6,  17, "moduł przycinania śmieci kwalifikuje pliki po `eof_ok` z Fazy 06"),
    (10, 17, "moduł sanityzacji tekstu kwalifikuje po `utf8_ok`/`is_oneliner` z Fazy 10"),
    (12, 17, "moduły nagłówków i korekty rozszerzeń kwalifikują po `media_reason` z Fazy 12"),
    (14, 17, "moduł zszywania kwalifikuje po `match_type` z korelacji Fazy 14"),
    (19, 17, "moduły naprawy MP4 kwalifikują po `video_ok` z Fazy 19"),
    (14, 18, "Smart Splice kwalifikuje pliki po `match_type` z korelacji Fazy 14"),
    (17, 9,  "Faza 09 konsumuje `repaired_path_*` wytworzone przez Fazę 17"),
    (18, 9,  "Faza 09 konsumuje `smart_splice_path` wytworzone przez Fazę 18"),
];

/// Fazy, które autopilot może POMINĄĆ warunkowo — ich brak na liście nie jest
/// błędem.
const FAZY_WARUNKOWE: &[(u32, &str)] = &[
    (16, "pomijana, gdy w `yara_rules/` nie ma żadnej reguły"),
    (17, "pomijana, gdy nie wybrano ani jednego modułu naprawczego"),
];

/// Wyciąga numer fazy z jej tytułu (`"Faza 07: Analiza Entropii"` → `7`).
fn numer_fazy(tytul: &str) -> Option<u32> {
    let reszta = tytul.strip_prefix("Faza ")?;
    let cyfry: String = reszta.chars().take_while(|c| c.is_ascii_digit()).collect();
    cyfry.parse().ok()
}

/// Sprawdza niezmienniki listy faz autopilota. Pusta lista = wszystko w porządku.
///
/// Weryfikuje dwie rzeczy: czy nie brakuje fazy, która nie jest warunkowa, oraz
/// czy zachowana jest kolejność wymagana przez [`ZALEZNOSCI_FAZ`]. Brak fazy
/// spełnia jej zależności w sposób próżny, więc obie kontrole są niezależne.
fn sprawdz_kolejnosc_autopilota(tytuly: &[&str]) -> Vec<String> {
    let kolejnosc: Vec<u32> = tytuly.iter().filter_map(|t| numer_fazy(t)).collect();
    let pozycja = |faza: u32| kolejnosc.iter().position(|&f| f == faza);
    let mut naruszenia = Vec::new();

    // 1. Kompletność — z wyłączeniem faz warunkowych.
    for faza in 1..=19u32 {
        if pozycja(faza).is_some() {
            continue;
        }
        if let Some((_, powod)) = FAZY_WARUNKOWE.iter().find(|(f, _)| *f == faza) {
            continue_warunkowa(&mut naruszenia, faza, powod);
        } else {
            naruszenia.push(format!("Faza {:02} NIE JEST uruchamiana przez autopilota", faza));
        }
    }

    // 2. Kolejność zależności.
    for &(wczesniejsza, pozniejsza, powod) in ZALEZNOSCI_FAZ {
        if let (Some(a), Some(b)) = (pozycja(wczesniejsza), pozycja(pozniejsza))
            && a > b {
                naruszenia.push(format!(
                    "Faza {:02} musi poprzedzać Fazę {:02}: {}",
                    wczesniejsza, pozniejsza, powod
                ));
            }
    }

    // 3. Złota Kopia zamyka przebieg.
    if let Some(p) = pozycja(9)
        && p != kolejnosc.len().saturating_sub(1) {
            naruszenia.push("Faza 09 (Złota Kopia) musi być OSTATNIA - konsumuje wyniki wszystkich pozostałych".to_string());
        }

    naruszenia
}

/// Brak fazy warunkowej to nie naruszenie — funkcja istnieje, żeby ten wyjątek
/// był jawny w kodzie, a nie ukryty w pustej gałęzi `if`.
fn continue_warunkowa(_naruszenia: &mut Vec<String>, faza: u32, powod: &str) {
    debug!("Autopilot: Faza {:02} nieobecna, ale to dozwolone - {}", faza, powod);
}

// ============================================================================
// TRYB AUTO-PILOT (Kombinacja wielu faz naraz z ekranem podsumowania)
// ============================================================================

/// Wbudowany orkiestrator sekwencyjny. Pozwala na bezobsługowe puszczenie systemu na noc.
/// Przelatuje płynnie przez wszystkie 17 zdefiniowanych faz.
fn run_autopilot(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    conn: &mut Connection,
    app: &mut AppState,
) -> io::Result<()> {
    let start_total = Instant::now();
    let mut completed_phases = Vec::new();
    let mut aborted = false;
    
    // Fazy 16/17 wymagają dodatkowych danych (reguły YARA / lista modułów).
    // W trybie Autopilota NIE MA promptu interaktywnego (bezobsługowy przebieg) -
    // domyślnie używamy WSZYSTKICH dostępnych reguł/modułów. `compile_all_available_rules`
    // i `all_module_ids` nie robią żadnego `println!`/`dialoguer` (tylko `tracing`),
    // więc są bezpieczne do wywołania tutaj, mimo że ekran Ratatui już działa.
    let phase16_rules = phases::phase16::compile_all_available_rules();
    let phase17_module_ids = phases::phase17_repair::all_module_ids();

    let mut phases_to_run: Vec<(&str, &str, &str, &str, PhaseFn)> = vec![
        ("[  🗺️  ]", "Faza 01: Mapowanie struktury", "Akwizycja Systemu Plików", "Wczytuje ścieżki i buduje drzewo bazy danych.", Box::new(phases::phase1::run)),
        ("[ 📏  ]", "Faza 02: Akwizycja Metadanych", "Rozmiary", "Oblicza rozmiary i wagi plików, eliminuje puste wydmuszki.", Box::new(phases::phase2::run)),
        ("[ 🧬  ]", "Faza 03: Hashe BLAKE3 (Zgodne pliki)", "Kryptografia", "Generuje skróty plików wspólnych z prędkością NVMe.", Box::new(phases::phase3::run)),
        ("[ 🧬  ]", "Faza 04: Hashe BLAKE3 (Brakujące)", "Kryptografia", "Skanuje pliki resztkowe i odrzuty.", Box::new(phases::phase4::run)),
        ("[ 📅  ]", "Faza 05: Czas modyfikacji i prawa", "i-node", "Ekstrakcja uprawnień Unix i Timestampów modyfikacji.", Box::new(phases::phase5::run)),
        ("[ 👻  ]", "Faza 06: Detekcja Pustych Plików", "Zawartość", "Szuka uciętych ogonów (Brak EOF) oraz wydmuszek po TRIM.", Box::new(phases::phase6::run)),
        ("[ 🎲  ]", "Faza 07: Analiza Entropii", "Matematyka", "Szum informacyjny i zaszyfrowanie Ransomware.", Box::new(phases::phase7::run)),
        ("[ 📜  ]", "Faza 10: Walidacja Tekstu (MIME)", "Semantyka", "Weryfikuje czystość znaków ASCII/UTF-8.", Box::new(phases::phase10::run)),
        ("[ 📦  ]", "Faza 11: Walidacja Archiwów", "Kontenery", "Sprawdza drzewa Central Directory i Zip Bomby.", Box::new(phases::phase11::run)),
        ("[ 📸  ]", "Faza 12: Struktury Obrazów (EXIF)", "Multimedia", "Odzyskuje GPS, oryginalne daty wykonania i sprzęt.", Box::new(phases::phase12::run)),
        ("[ 🖼️   ]", "Faza 13: Dekodowanie Mediów", "Multimedia", "Renderuje obrazy w poszukiwaniu Gray Banding.", Box::new(phases::phase13::run)),
        ("[  🎬  ]", "Faza 19: Diagnostyka Kontenerów Wideo", "Multimedia", "MP4/MOV/M4V, MKV/WebM, FLV oraz strumienie transportowe TS.", Box::new(phases::phase19_video::run)),
        ("[ 👯‍♂️ ]", "Faza 14: Rozmyte Hashowanie", "Korelacja", "Szuka zaginionych bliźniaków (ssdeep).", Box::new(phases::phase14::run)),
        ("[  🏷️  ]", "Faza 15: Rozszerzone Atrybuty", "Metadane", "Analizuje ukryte strumienie systemowe XATTR.", Box::new(phases::phase15::run)),
    ];

    match phase16_rules {
        Some(rules) => phases_to_run.push((
            "[  ☢  ]", "Faza 16: Skanowanie YARA", "Malware", "Rozpoznaje zagrożenia wirusowe, notatki hakerskie.",
            Box::new(move |conn, u, tx| phases::phase16::run(conn, u, tx, rules)),
        )),
        None => info!("Autopilot: Faza 16 pominięta (brak reguł YARA w 'yara_rules/')."),
    }

    if !phase17_module_ids.is_empty() {
        phases_to_run.push((
            "[  🛠️  ]", "Faza 17: Aktywne Moduły Naprawcze", "Rekonstrukcja", "Fizycznie łata błędy w kodzie binarnym plików.",
            Box::new(move |conn, u, tx| phases::phase17_repair::run(conn, u, tx, phase17_module_ids)),
        ));
    }

    // FAZA 18 — kolejność NIE jest tu dowolna.
    //
    // Musi stać PO Fazie 14, bo kwalifikuje pliki po `match_type = PARTIAL`
    // z jej korelacji, i PRZED Fazą 09, bo to ona konsumuje `smart_splice_path`
    // — w `decide_winner` złożenie ma NAJWYŻSZY priorytet, wyżej niż
    // którakolwiek ze stron i wyżej niż naprawa z Fazy 17. Miejsce zaraz po
    // Fazie 17 spełnia oba warunki.
    //
    // NAPRAWIONY BRAK: Faza 18 nie była w tej liście wcale. Autopilot obiecuje
    // pełny przebieg, a w praktyce `smart_splice_path` nigdy nie powstawało,
    // więc Faza 09 miała w swojej hierarchii decyzyjnej gałąź, do której nie
    // dochodziła nigdy. Samo Smart Splice działało — ale tylko po ręcznym
    // uruchomieniu z podmenu napraw.
    phases_to_run.push((
        "[  🧩  ]", "Faza 18: Inteligentna Rekonstrukcja (Smart Splice)", "Rekonstrukcja",
        "Składa sprawny plik z dwóch uszkodzonych kopii (JPG/PNG, archiwa ZIP-podobne, TAR) z obowiązkową weryfikacją wyniku.",
        Box::new(phases::phase18_smart_splice::run),
    ));

    phases_to_run.push(("[ 📝  ]", "Faza 08: Raport Końcowy (CSV)", "Eksport", "Wypuszcza ostateczny arkusz decyzyjny Euro-CSV.", Box::new(phases::phase8::run)));
    phases_to_run.push(("[ 👑  ]", "Faza 09: Smart Merge (Złota Kopia)", "Fuzja", "Zlewa naprawione i zdrowe dane w wyczyszczoną kopię finalną.", Box::new(phases::phase9::run)));

    // SAMOKONTROLA: sprawdza kompletność listy i kolejność wymaganą przez
    // zależności danych między fazami. Naruszenie nie przerywa przebiegu —
    // operator ma dostać wynik, a nie odmowę — ale trafia do dziennika jako
    // ostrzeżenie. Ta kontrola wyłapałaby brak Fazy 18, który przez długi czas
    // cicho wyłączał Smart Splice w trybie bezobsługowym.
    {
        let tytuly: Vec<&str> = phases_to_run.iter().map(|(_, t, _, _, _)| *t).collect();
        for naruszenie in sprawdz_kolejnosc_autopilota(&tytuly) {
            // WYŁĄCZNIE `warn!` do dziennika. Autopilot działa w alternate
            // screen Ratatui, więc `println!`/`eprintln!` w tym miejscu
            // rozjechałoby ekran — ten sam powód, dla którego reszta projektu
            // raportuje przez `PhaseEvent`, a moduły naprawcze przez `tracing`.
            warn!("Autopilot - naruszenie niezmiennika kolejności faz: {}", naruszenie);
        }
    }

    for (icon, title, category, desc, phase_fn) in phases_to_run {
        let dur_res = run_phase_bez_czekania(terminal, conn, app, icon, title, category, desc, phase_fn);
        
        let duration = dur_res.unwrap_or(Duration::from_secs(0));

        if crate::utils::CANCEL_SIGNAL.load(std::sync::atomic::Ordering::SeqCst) {
            completed_phases.push((title.to_string(), duration, "PRZERWANA (CTRL-C)".to_string()));
            aborted = true;
            break; // Awaryjne zatrzymanie całego autopilota
        } else {
            completed_phases.push((title.to_string(), duration, "ZAKOŃCZONA".to_string()));
        }
    }

    let status_final = if aborted { "PRZERWANY" } else { "SUKCES" };
    let total_dur = start_total.elapsed();
    
    // Zrzut danych dla celów audytu do bazy
    let _ = conn.execute(
        "INSERT INTO autopilot_runs (duration_sec, status, phases_run) VALUES (?1, ?2, ?3)",
        rusqlite::params![total_dur.as_secs_f64(), status_final, completed_phases.len() as i32]
    );

    show_autopilot_summary(terminal, &completed_phases, total_dur, aborted)
}

/// Rysuje piękny ekran podsumowania po zakończeniu Auto-Pilota.
fn show_autopilot_summary(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    results: &[(String, Duration, String)],
    total_time: Duration,
    aborted: bool
) -> io::Result<()> {
    loop {
        terminal.draw(|f| {
            let size = f.area();
            let block = Block::default().borders(Borders::ALL)
                .title(if aborted { " [ 🛑 ] Podsumowanie Auto-Pilota (PRZERWANO) " } else { " [ 🚀 ] Podsumowanie Auto-Pilota (SUKCES) " })
                .border_style(Style::default().fg(if aborted { Color::Red } else { Color::Green }));

            let mut lines = vec![
                ListItem::new(Span::styled(format!("Całkowity czas analizy: {:.2?}", total_time), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                ListItem::new(Span::raw("")),
            ];

            for (i, (name, dur, stat)) in results.iter().enumerate() {
                let stat_color = if stat.contains("ZAKOŃCZONA") { Color::Green } else { Color::Red };
                lines.push(ListItem::new(Line::from(vec![
                    Span::styled(format!("[{:02}] ", i + 1), Style::default().fg(Color::DarkGray)),
                    Span::styled(format!("{:<40}", name), Style::default().fg(Color::White)),
                    Span::raw(" -> "),
                    Span::styled(format!("{:<15}", stat), Style::default().fg(stat_color)),
                    Span::styled(format!("({:.2?})", dur), Style::default().fg(Color::DarkGray)),
                ])));
            }
            lines.push(ListItem::new(Span::raw("")));
            lines.push(ListItem::new(Span::styled("Naciśnij [ENTER], aby wrócić do Menu Głównego...", Style::default().fg(Color::Cyan))));

            f.render_widget(List::new(lines).block(block), size);
        })?;

        if event::poll(Duration::from_millis(100))?
            && let Ok(event::Event::Key(key)) = event::read()
                && key.kind == KeyEventKind::Press && (key.code == KeyCode::Enter || key.code == KeyCode::Esc) {
                    break;
                }
    }
    Ok(())
}

// ============================================================================
// MOSTEK DO STARYCH MODUŁÓW (CLI SUSPENSION)
// ============================================================================

/// Tymczasowo usypia Ratatui, oddaje kontrole do zwykłej, klasycznej konsoli (CLI), wykonuje stary kod,
/// a następnie budzi się, powraca do trybu RAW i odbudowuje ekran Ratatui w nienaruszonym stanie.
fn execute_with_cli_suspension<F>(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, mut f: F) 
where F: FnMut() 
{
    info!("Zawieszanie środowiska graficznego (TUI) i przekazanie kontroli do tradycyjnego CLI...");
    disable_raw_mode().unwrap();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).unwrap();
    terminal.show_cursor().unwrap();

    f(); // Odpalenie wstrzykniętego kodu (Moduł CLI: np. reset, ustawienia)

    crate::utils::CANCEL_SIGNAL.store(false, std::sync::atomic::Ordering::SeqCst);
    println!("\n{}", "Naciśnij [ENTER], aby wrócić do centrum dowodzenia...".bright_black());
    let mut dummy = String::new();
    let _ = io::stdin().read_line(&mut dummy);

    info!("Przywracanie sesji środowiska graficznego (TUI)...");
    enable_raw_mode().unwrap();
    execute!(terminal.backend_mut(), EnterAlternateScreen).unwrap();
    // NIE `unwrap()`: od ratatui 0.30 `clear()` zapisuje i przywraca pozycję
    // kursora, czyli wysyła zapytanie DSR (`ESC[6n`) i czeka na odpowiedź
    // terminala. Tam, gdzie nikt nie odpowiada (wyjście przekierowane, potok,
    // CI), panika wywracałaby program w miejscu, w którym nic złego się nie
    // stało - ekran alternatywny już wrócił, a czyszczenie jest tylko
    // optymalizacją odrysowania.
    let _ = terminal.clear();
}

/// Wariant [`execute_with_cli_suspension`] zwracający wartość z zawieszonego
/// bloku CLI, BEZ monitu "Naciśnij ENTER" na końcu (interaktywne prompty typu
/// `MultiSelect` już same wymagają swojego ENTER do zatwierdzenia — dodatkowy
/// monit byłby zbędnym powtórzeniem). Używane do wyboru reguł YARA (Faza 16)
/// i modułów naprawczych (Faza 17) PRZED wejściem w tryb Raw dla ekranu danej
/// fazy — `dialoguer` wymaga normalnego trybu terminala i wyłącznego dostępu
/// do stdin, więc wołanie interaktywnego promptu, gdy główny wątek UI już
/// rysuje ekran Ratatui i nasłuchuje klawiatury, powodowało realny konflikt
/// o terminal (obserwowany bug: prompt nigdy się nie pojawiał, faza cicho
/// ruszała dalej bez rzeczywistego wyboru użytkownika).
fn suspend_tui_for_cli<F, R>(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, f: F) -> R
where F: FnOnce() -> R
{
    info!("Zawieszanie środowiska graficznego (TUI) na czas interaktywnego wyboru...");
    disable_raw_mode().unwrap();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).unwrap();
    terminal.show_cursor().unwrap();

    let result = f();

    info!("Przywracanie sesji środowiska graficznego (TUI) po wyborze...");
    enable_raw_mode().unwrap();
    execute!(terminal.backend_mut(), EnterAlternateScreen).unwrap();
    terminal.clear().unwrap();

    result
}

// ============================================================================
// PODMENU: NAPRAWA I REKONSTRUKCJA (Faza 17 / Faza 18 / Składanie DNG)
// ============================================================================

/// Podmenu grupujące wszystkie narzędzia naprawcze/rekonstrukcyjne pod
/// jedną pozycją głównego menu. Faza 17 i Faza 18 pozostają W PEŁNI
/// automatyczne (Ratatui, paski postępu) — bez zmian merytorycznych
/// względem tego, jak działały jako osobne pozycje. Składanie Strukturalne
/// DNG jest CELOWO inne: narzędzie CLI, ręczne, z obowiązkową akceptacją
/// użytkownika per plik — patrz dokumentacja `dng_repair` co do dlaczego
/// (pewność wyłącznie `StructuralOnly`, brak dowodu poprawności pikseli).
/// Dlatego NIE jest wpięte do Autopilota ani do `decide_winner` Fazy 9.
fn run_repair_submenu(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut AppState,
    conn: &mut Connection,
) -> io::Result<()> {
    loop {
        let choice = suspend_tui_for_cli(terminal, || {
            println!("\n{}", "[ 🛠️ ] NAPRAWA I REKONSTRUKCJA".cyan().bold());
            dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("Wybierz narzędzie (Esc = wróć)")
                .items([
                    "Faza 17: Aktywne Moduły Naprawcze (nagłówki JPG/PNG, MP4, SQLite, teksty, przycinanie śmieci - automatyczne)",
                    "Faza 18: Smart Splice (JPG/PNG, archiwa ZIP-podobne, TAR - składanie z obowiązkową weryfikacją)",
                    "Składanie Strukturalne DNG (EKSPERYMENTALNE - wymaga ręcznej akceptacji każdego pliku)",
                    "[ 🔙 ] Wróć do menu głównego",
                ])
                .default(0)
                .interact_opt()
                .unwrap_or(None)
        });

        match choice {
            Some(0) => {
                // Wybór modułów MUSI nastąpić PRZED trybem Raw (ten sam
                // powód co Faza 16 - konflikt dialoguer z aktywnym Ratatui).
                let module_ids = suspend_tui_for_cli(terminal, phases::phase17_repair::select_active_module_ids);
                match module_ids {
                    Some(module_ids) => {
                        let phase_fn: PhaseFn = Box::new(move |conn, u, tx| phases::phase17_repair::run(conn, u, tx, module_ids));
                        let _ = run_phase_with_ui(terminal, conn, app, "[  🛠️  ]", "Faza 17: Aktywne Moduły Naprawcze", "Rekonstrukcja", "Fizycznie łata błędy w kodzie binarnym zniszczonych plików.", phase_fn);
                    }
                    None => info!("Faza 17 pominięta - nie wybrano żadnych modułów naprawczych."),
                }
            }
            Some(1) => {
                let _ = run_phase_with_ui(terminal, conn, app, "[  🧩  ]", "Faza 18: Inteligentna Rekonstrukcja (Smart Splice)", "Rekonstrukcja", "Składa sprawny plik z dwóch uszkodzonych kopii (JPG/PNG, archiwa ZIP-podobne, TAR) z obowiązkową weryfikacją wyniku.", Box::new(phases::phase18_smart_splice::run));
            }
            Some(2) => {
                let _ = run_dng_repair_with_ui(terminal, app, conn);
            }
            _ => break, // Wróć / Esc / Ctrl+C w Select
        }
    }
    Ok(())
}

// ============================================================================
// EKRAN USTAWIEŃ (PEŁNE RATATUI, SPÓJNE Z RESZTĄ APLIKACJI)
// ============================================================================

/// Prowadzi interfejs `mp4_doctor` w TERMINALU WERYFIKATORA.
///
/// # Dlaczego nie oddajemy terminala
///
/// `mp4_doctor` ma własny `TerminalGuard`, który wchodzi na ekran alternatywny,
/// włącza tryb raw i **instaluje globalny hak paniki**. Uruchomienie go obok
/// naszego dałoby dwa haki (wygrywa ostatni zarejestrowany, więc przywracanie
/// terminala mogłoby przestać działać) i dwa niezależne znaczniki przerwania.
///
/// Dlatego prowadzimy jego pętlę tak samo, jak `run_dng_repair_with_ui` prowadzi
/// narzędzie DNG: rysujemy JEGO ekran w NASZYM terminalu. Wszystko, czego ta
/// pętla potrzebuje, jest publiczne — `App::new`, `process_events`,
/// `take_pending_preview`, `ui::draw`, `handle_key`, `should_quit` — więc
/// `TerminalGuard` nie jest w ogóle tworzony.
///
/// # Podgląd wideo
///
/// `mp4_doctor` potrafi zlecić odtworzenie naprawionego pliku w `ffplay`, co
/// wymaga oddania terminala na czas działania procesu zewnętrznego. Robimy to
/// ręcznie i tolerancyjnie: nieudane zejście z ekranu alternatywnego nie może
/// wywrócić całej sesji.
fn run_mp4_doctor_with_ui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    stan: &AppState,
) -> io::Result<()> {
    use mp4_doctor::tui::{app::App, ui};

    info!("Przekazanie ekranu do interfejsu MP4 Doctor (w terminalu Weryfikatora).");

    // Przestrzenie robocze `mp4_doctor` powstawały w katalogu URUCHOMIENIA
    // (ścieżka `workspaces` była względna), czyli zaśmiecały katalog, z
    // którego odpalono Weryfikator, i leżały gdzie indziej niż wszystkie
    // pozostałe wytwory. Wskazujemy je pod `target_path`, obok
    // `_phase17_repaired`, `_smart_splice_repaired` i `_dng_structural_review`.
    //
    // Ustawienie jest jednorazowe (`OnceLock`), więc kolejne wejścia w ten
    // ekran nie próbują go zmieniać — i słusznie, bo w połowie sesji
    // unieważniłoby otwarte ścieżki.
    let katalog = PathBuf::from(&stan.ustawienia.target_path).join("_mp4_doctor");
    if mp4_doctor::workspace::ustaw_katalog_przestrzeni(katalog.clone()) {
        info!(katalog = %katalog.display(), "Wskazano katalog przestrzeni roboczych MP4 Doctor.");
    }

    // Znacznik przerwania mógł zostać podniesiony przez wcześniejsze Ctrl+C
    // (np. przy przerwanej fazie). Wchodząc w nowe narzędzie, zdejmujemy oba —
    // ten sam wzorzec co w `execute_with_cli_suspension`.
    crate::utils::zdejmij_przerwanie();

    let mut app = App::new();
    let tick = Duration::from_millis(33); // ~30 FPS, tak jak w oryginale

    while !app.should_quit {
        // Odbiór zdarzeń z wątków roboczych mp4_doctor.
        app.process_events();

        // Podgląd zewnętrzny: zejdź z ekranu alternatywnego, odpal proces,
        // wróć. Każdy krok tolerancyjny - patrz dokumentacja funkcji.
        if let Some(sciezka) = app.take_pending_preview() {
            let _ = disable_raw_mode();
            let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
            let _ = terminal.show_cursor();

            let _ = std::process::Command::new("ffplay")
                .args(["-autoexit", "-t", "3", "-v", "warning", "-window_title", "MP4 Doctor - podglad"])
                .arg(&sciezka)
                .status();

            let _ = enable_raw_mode();
            let _ = execute!(terminal.backend_mut(), EnterAlternateScreen);
            let _ = terminal.hide_cursor();
            // Od ratatui 0.30 `clear()` pyta terminal o pozycję kursora
            // (DSR), więc może zawieść tam, gdzie nikt nie odpowiada.
            let _ = terminal.clear();
        }

        terminal.draw(|f| ui::draw(f, &mut app))?;

        if event::poll(tick)?
            && let event::Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press { continue; }
                // Ctrl+C wychodzi z podekranu do menu Weryfikatora, nie zabija
                // programu - ten sam kontrakt co w narzędziu DNG.
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    break;
                }
                app.handle_key(key);
            }
    }

    // Wyjście z podekranu nie może zostawić podniesionego znacznika —
    // inaczej kolejne wejście tu albo następna faza zatrzymałyby się od razu.
    crate::utils::zdejmij_przerwanie();

    // Ekran należy teraz znowu do menu Weryfikatora.
    let _ = terminal.clear();
    info!("Powrót z interfejsu MP4 Doctor do centrum dowodzenia.");
    Ok(())
}

/// Uruchamia w pełni graficzny ekran Składania Strukturalnego DNG — bez
/// zawieszania trybu Raw, bez `dialoguer`. Ten sam model interakcji co
/// reszta aplikacji. Cała logika (stan, dostęp do bazy/dysku, decyzje) żyje
/// w module `dng_repair` — ta funkcja to wyłącznie pętla zdarzeń +
/// rysowanie, plus "tykanie" trybu automatycznego (jeden plik na klatkę,
/// żeby ekran mógł się odświeżać w trakcie długiego przebiegu).
fn run_dng_repair_with_ui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut AppState,
    conn: &mut Connection,
) -> io::Result<()> {
    let tasks = dng_repair::fetch_review_tasks(conn).unwrap_or_default();
    let mut state = dng_repair::DngRepairState::new(tasks);
    let paths = dng_repair::RepairPaths {
        ufs_base: PathBuf::from(&app.ustawienia.ufs_path),
        script_base: PathBuf::from(&app.ustawienia.script_path),
        target_base: PathBuf::from(&app.ustawienia.target_path).join("_dng_structural_review"),
    };
    let mut log_file: Option<File> = None;

    loop {
        terminal.draw(|f| crate::tui::dng_repair_screen::draw_dng_repair_screen(f, &state))?;

        if event::poll(Duration::from_millis(50))?
            && let event::Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press { continue; }
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    break;
                }
                dng_repair::handle_key(key, &mut state, conn, &paths, &mut log_file);
                if state.should_exit { break; }
            }

        // Tryb automatyczny przetwarza jeden plik PER KLATKA (nie czeka na
        // klawisz) - żeby ekran mógł się odświeżać w trakcie długiego
        // przebiegu i pokazywać żywy postęp, z możliwością przerwania (Esc).
        if state.mode == dng_repair::Mode::AutoRunning {
            dng_repair::advance_auto_tick(&mut state, conn, &paths, &mut log_file);
        }
    }
    Ok(())
}

// ============================================================================
// EKRAN USTAWIEŃ (PEŁNE RATATUI, SPÓJNE Z RESZTĄ APLIKACJI)
// ============================================================================

/// Uruchamia w pełni graficzny ekran ustawień — bez zawieszania trybu Raw,
/// bez `dialoguer`. Ten sam model interakcji co dashboard i ekrany faz
/// (↑/↓/Enter/Esc, natychmiastowy zapis po każdej zmianie). Cała logika
/// (walidacja, automat stanu edycji) żyje w `menu::settings_actions` —
/// ta funkcja to wyłącznie pętla zdarzeń + rysowanie.
fn run_settings_with_ui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut AppState,
) -> io::Result<()> {
    info!("Otwarto ekran ustawień (pełne Ratatui).");
    let mut state = SettingsUiState::new();

    loop {
        terminal.draw(|f| crate::tui::settings_screen::draw_settings_screen(f, &state, app.ustawienia))?;

        if event::poll(Duration::from_millis(100))?
            && let event::Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press { continue; }

                // Awaryjne twarde wyjście (Ctrl+C) - spójne z resztą aplikacji
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    info!("Przechwycono Ctrl+C na ekranie ustawień. Powrót do menu głównego.");
                    break;
                }

                settings_actions::handle_key(key, &mut state, app.ustawienia);
                if state.should_exit { break; }
            }
    }

    info!("Zamknięto ekran ustawień.");
    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
//
// Pierwsze testy w tym pliku. `execute_action` i `run_autopilot` wymagają
// terminala i domknięć `PhaseFn`, więc nie dają się wywołać bezpośrednio — ale
// WŁASNOŚCI listy faz, czyli to, co faktycznie zawiodło w praktyce, sprawdzają
// się bez żadnego z tych elementów.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Odwzorowanie kolejności z [`run_autopilot`] — WEJŚCIE DLA TESTÓW, nie
    /// źródło prawdy.
    ///
    /// Prawdziwa lista musi zostać napisana wprost w `run_autopilot`, bo niesie
    /// domknięcia `PhaseFn`, których nie da się trzymać w stałej. Rozdzielenie
    /// jest więc świadome i ma jasny podział ról:
    ///
    /// - **Testy niżej** dowodzą, że [`sprawdz_kolejnosc_autopilota`] FAKTYCZNIE
    ///   wyłapuje realne pomyłki (brak Fazy 18, odwrócone 18/09, odwrócone
    ///   19/17, Faza 09 nie na końcu) — bo kontrola, która nie potrafi paść,
    ///   jest bezwartościowa.
    /// - **Samokontrola w `run_autopilot`** wywołuje tę samą funkcję na
    ///   PRAWDZIWEJ liście przy każdym uruchomieniu i loguje naruszenia. To ona
    ///   jest właściwym zabezpieczeniem: widzi rzeczywistość, nie kopię.
    ///
    /// Gdyby ktoś zmienił listę w `run_autopilot`, nie ruszając tej stałej,
    /// testy nadal przejdą — ale samokontrola zgłosi naruszenie w dzienniku
    /// przy pierwszym przebiegu autopilota.
    const KOLEJNOSC_AUTOPILOTA: &[&str] = &[
        "Faza 01: Mapowanie struktury",
        "Faza 02: Akwizycja Metadanych",
        "Faza 03: Hashe BLAKE3 (Zgodne pliki)",
        "Faza 04: Hashe BLAKE3 (Brakujące)",
        "Faza 05: Czas modyfikacji i prawa",
        "Faza 06: Detekcja Pustych Plików",
        "Faza 07: Analiza Entropii",
        "Faza 10: Walidacja Tekstu (MIME)",
        "Faza 11: Walidacja Archiwów",
        "Faza 12: Struktury Obrazów (EXIF)",
        "Faza 13: Dekodowanie Mediów",
        "Faza 19: Diagnostyka Kontenerów Wideo",
        "Faza 14: Rozmyte Hashowanie",
        "Faza 15: Rozszerzone Atrybuty",
        "Faza 16: Skanowanie YARA",
        "Faza 17: Aktywne Moduły Naprawcze",
        "Faza 18: Inteligentna Rekonstrukcja (Smart Splice)",
        "Faza 08: Raport Końcowy (CSV)",
        "Faza 09: Smart Merge (Złota Kopia)",
    ];

    // ------------------------------------------------------------------
    // numer_fazy
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // ZGODNOŚĆ POZYCJI MENU Z DYSPOZYTOREM AKCJI
    // ------------------------------------------------------------------

    /// `action_to_execute` to WPROST indeks w liście menu (patrz
    /// `menu::events`), a `execute_action` rozgałęzia się po tym samym
    /// numerze. Wstawienie pozycji w środku listy przesuwa więc wszystkie
    /// kolejne — i jeśli dyspozytor nie zostanie poprawiony, menu cicho
    /// uruchamia nie to, co pokazuje.
    ///
    /// Ten test utrwala numery, na które dyspozytor faktycznie reaguje.
    #[test]
    fn test_pozycje_menu_zgadzaja_sie_z_numerami_w_dyspozytorze() {
        let mut u = crate::settings::Ustawienia::default();
        let app = crate::menu::state::AppState::new(&mut u).expect("stan menu musi się zbudować");

        let tytul = |i: usize| app.selections.get(i).map(|(t, _)| *t).unwrap_or("");

        assert!(tytul(25).contains("MP4 DOCTOR"), "indeks 25 musi być MP4 Doctor, jest: {:?}", tytul(25));
        assert!(tytul(26).contains("USTAWIENIA"), "indeks 26 musi być ustawieniami, jest: {:?}", tytul(26));

        // Wyjście rozpoznawane jest dynamicznie jako OSTATNIA pozycja
        // (patrz `menu::run`), więc musi nią pozostać.
        let ostatni = app.selections.len() - 1;
        assert!(
            tytul(ostatni).contains("WYJŚCIE"),
            "ostatnia pozycja musi być wyjściem, jest: {:?}", tytul(ostatni)
        );
    }

    /// Separatory są zwykłymi pozycjami listy i też zajmują numery — dlatego
    /// indeks w menu nie równa się numerowi fazy. Test utrwala ich miejsca,
    /// bo ich przesunięcie rozjeżdża cały dyspozytor.
    #[test]
    fn test_separatory_zajmuja_ustalone_pozycje() {
        let mut u = crate::settings::Ustawienia::default();
        let app = crate::menu::state::AppState::new(&mut u).unwrap();

        let separatory: Vec<usize> = app.selections.iter().enumerate()
            .filter(|(_, (t, _))| t.starts_with('─'))
            .map(|(i, _)| i)
            .collect();

        assert_eq!(separatory, vec![1, 21], "separatory na innych pozycjach przesuwają akcje: {:?}", separatory);
    }

    #[test]
    fn test_numer_fazy_czyta_z_tytulu() {
        assert_eq!(numer_fazy("Faza 01: Mapowanie struktury"), Some(1));
        assert_eq!(numer_fazy("Faza 19: Diagnostyka Kontenerów Wideo"), Some(19));
        assert_eq!(numer_fazy("Faza 8: bez zera wiodącego"), Some(8));
    }

    #[test]
    fn test_numer_fazy_odrzuca_to_co_nie_jest_faza() {
        assert_eq!(numer_fazy("NAPRAWA I REKONSTRUKCJA"), None);
        assert_eq!(numer_fazy("Faza bez numeru"), None);
        assert_eq!(numer_fazy(""), None);
    }

    // ------------------------------------------------------------------
    // NAJWAŻNIEJSZY TEST: rzeczywista lista autopilota
    // ------------------------------------------------------------------

    /// Kolejność, którą autopilot naprawdę wykonuje, musi spełniać WSZYSTKIE
    /// zależności danych między fazami.
    #[test]
    fn test_rzeczywista_kolejnosc_spelnia_niezmienniki() {
        let naruszenia = sprawdz_kolejnosc_autopilota(KOLEJNOSC_AUTOPILOTA);
        assert!(
            naruszenia.is_empty(),
            "Kolejność faz autopilota narusza niezmienniki:\n  - {}",
            naruszenia.join("\n  - ")
        );
    }

    /// Ta lista ma 19 pozycji, bo tyle jest faz. Gdyby ktoś dodał Fazę 20 i
    /// zapomniał o autopilocie, ten test pada jako pierwszy.
    #[test]
    fn test_autopilot_obejmuje_wszystkie_19_faz() {
        assert_eq!(KOLEJNOSC_AUTOPILOTA.len(), 19);

        let numery: Vec<u32> = KOLEJNOSC_AUTOPILOTA.iter().filter_map(|t| numer_fazy(t)).collect();
        for faza in 1..=19u32 {
            assert!(numery.contains(&faza), "Faza {:02} nie jest uruchamiana przez autopilota", faza);
        }
    }

    // ------------------------------------------------------------------
    // REGRESJE: kontrola musi WYŁAPYWAĆ realne pomyłki
    // ------------------------------------------------------------------

    /// Dokładnie ten błąd żył w kodzie: autopilot nie uruchamiał Fazy 18, więc
    /// `smart_splice_path` nigdy nie powstawało, a Faza 09 miała w hierarchii
    /// decyzyjnej gałąź, do której nie dochodziła.
    #[test]
    fn test_kontrola_wylapuje_brak_fazy_18() {
        let bez_18: Vec<&str> = KOLEJNOSC_AUTOPILOTA
            .iter().copied()
            .filter(|t| numer_fazy(t) != Some(18))
            .collect();

        let naruszenia = sprawdz_kolejnosc_autopilota(&bez_18);
        assert!(
            naruszenia.iter().any(|n| n.contains("Faza 18")),
            "brak Fazy 18 MUSI zostać wychwycony, dostałem: {:?}", naruszenia
        );
    }

    #[test]
    fn test_kontrola_wylapuje_faze_18_po_fazie_09() {
        // Smart Splice po scalaniu nie ma sensu — Faza 09 już zdążyła wybrać
        // zwycięzców, nie widząc żadnego złożenia.
        let zla = ["Faza 14: x", "Faza 09: Smart Merge", "Faza 18: Smart Splice"];
        let naruszenia = sprawdz_kolejnosc_autopilota(&zla);

        assert!(
            naruszenia.iter().any(|n| n.contains("Faza 18") && n.contains("Faza 09")),
            "odwrócona kolejność 18/09 musi zostać wychwycona: {:?}", naruszenia
        );
    }

    /// Zależność, którą wprowadziłem razem z portem MP4: moduły naprawy MP4
    /// kwalifikują pliki po `video_ok` z Fazy 19, więc 19 musi być wcześniej.
    #[test]
    fn test_kontrola_wylapuje_faze_19_po_fazie_17() {
        let zla = ["Faza 17: Naprawa", "Faza 19: Wideo"];
        let naruszenia = sprawdz_kolejnosc_autopilota(&zla);

        assert!(
            naruszenia.iter().any(|n| n.contains("Faza 19") && n.contains("video_ok")),
            "odwrócona kolejność 19/17 musi zostać wychwycona wraz z powodem: {:?}", naruszenia
        );
    }

    #[test]
    fn test_kontrola_wylapuje_gdy_zlota_kopia_nie_jest_ostatnia() {
        let zla = ["Faza 09: Smart Merge", "Faza 08: Raport"];
        let naruszenia = sprawdz_kolejnosc_autopilota(&zla);

        assert!(
            naruszenia.iter().any(|n| n.contains("OSTATNIA")),
            "Faza 09 nie na końcu musi zostać wychwycona: {:?}", naruszenia
        );
    }

    // ------------------------------------------------------------------
    // Fazy warunkowe
    // ------------------------------------------------------------------

    /// Fazy 16 i 17 autopilot POMIJA legalnie (brak reguł YARA / brak wybranych
    /// modułów), więc ich nieobecność nie może być raportowana jako błąd —
    /// inaczej kontrola krzyczałaby przy każdym normalnym przebiegu bez YARA.
    #[test]
    fn test_brak_faz_warunkowych_nie_jest_naruszeniem() {
        for pomijana in [16u32, 17u32] {
            let lista: Vec<&str> = KOLEJNOSC_AUTOPILOTA
                .iter().copied()
                .filter(|t| numer_fazy(t) != Some(pomijana))
                .collect();

            let naruszenia = sprawdz_kolejnosc_autopilota(&lista);
            assert!(
                !naruszenia.iter().any(|n| n.contains(&format!("Faza {:02} NIE JEST", pomijana))),
                "Faza {:02} jest warunkowa - jej brak nie może być błędem: {:?}", pomijana, naruszenia
            );
        }
    }

    #[test]
    fn test_lista_faz_warunkowych_pokrywa_sie_z_kodem() {
        // Autopilot pomija dokładnie te dwie fazy — 16 przy braku reguł YARA,
        // 17 przy braku wybranych modułów. Gdyby doszła trzecia, ta lista musi
        // zostać uzupełniona, inaczej kontrola zacznie fałszywie alarmować.
        let numery: Vec<u32> = FAZY_WARUNKOWE.iter().map(|(f, _)| *f).collect();
        assert_eq!(numery, vec![16, 17]);

        for (_, powod) in FAZY_WARUNKOWE {
            assert!(!powod.is_empty(), "każda faza warunkowa musi mieć zapisany powód");
        }
    }

    // ------------------------------------------------------------------
    // Spójność samych zależności
    // ------------------------------------------------------------------

    #[test]
    fn test_zaleznosci_maja_powody_i_sensowne_numery() {
        assert!(!ZALEZNOSCI_FAZ.is_empty());

        for &(a, b, powod) in ZALEZNOSCI_FAZ {
            assert!((1..=19).contains(&a) && (1..=19).contains(&b), "numery faz poza zakresem: {} -> {}", a, b);
            assert_ne!(a, b, "faza nie może zależeć od siebie samej");
            assert!(
                powod.len() > 20,
                "zależność {} -> {} potrzebuje powodu wyjaśniającego JAKĄ daną przekazuje", a, b
            );
        }
    }

    #[test]
    fn test_zaleznosci_nie_tworza_cyklu() {
        // Cykl uniemożliwiłby jakąkolwiek poprawną kolejność — lepiej wykryć go
        // testem niż zastanawiać się, czemu kontrola zawsze krzyczy.
        for &(a, b, _) in ZALEZNOSCI_FAZ {
            assert!(
                !ZALEZNOSCI_FAZ.iter().any(|&(c, d, _)| c == b && d == a),
                "sprzeczne zależności między Fazą {:02} i {:02}", a, b
            );
        }
    }

    #[test]
    fn test_pusta_lista_nie_panikuje() {
        // Nie zgłasza kolejności, ale zgłosi brak faz nieopcjonalnych.
        let naruszenia = sprawdz_kolejnosc_autopilota(&[]);
        assert!(!naruszenia.is_empty(), "pusta lista to brak wszystkich faz obowiązkowych");
        assert!(!naruszenia.iter().any(|n| n.contains("Faza 16 NIE JEST")), "16 jest warunkowa");
    }
}
