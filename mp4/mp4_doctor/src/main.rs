//! MP4 Doctor 2.0 - Autonomiczny Silnik Heurystyczny (Enterprise AI)
//!
//! Główny punkt wejścia do aplikacji. 
//!
//! # Funkcje Wersji Enterprise:
//! - **Headless Mode (CLI):** Automatyzacja przy użyciu argumentów z wiersza poleceń.
//! - **Responsive TUI:** Pełnoekranowy interfejs Ratatui & Crossterm z cyklem życia RAII.

use std::process;
use std::sync::atomic::Ordering;
use std::time::Duration;

use clap::Parser;
use crossterm::event::{self as ct_event, Event, KeyEventKind};

use mp4_doctor::*;
use mp4_doctor::event;
use mp4_doctor::tui::app::App;
use mp4_doctor::tui::terminal::{force_restore, TerminalGuard};
use mp4_doctor::tui::ui;

fn init_shutdown_handler() {
    ctrlc::set_handler(move || {
        SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
        force_restore();
        std::process::exit(0);
    })
    .expect("Krytyczny błąd: Nie można zainicjować detektora sygnałów (Ctrl+C)!");
}

fn check_dependencies() {
    let ffmpeg_check = std::process::Command::new("ffmpeg").arg("-version").output();
    if ffmpeg_check.is_err() {
        eprintln!("❌ [BŁĄD KRYTYCZNY] Nie znaleziono narzędzia 'ffmpeg' w systemie (zmienna PATH)!");
        eprintln!("💡 Zainstaluj FFmpeg i upewnij się, że jest dostępny z wiersza poleceń.");
        process::exit(1);
    }
    
    let ffprobe_check = std::process::Command::new("ffprobe").arg("-version").output();
    if ffprobe_check.is_err() {
        eprintln!("❌ [BŁĄD KRYTYCZNY] Nie znaleziono narzędzia 'ffprobe' w systemie!");
        process::exit(1);
    }
}

// --- CLI (HEADLESS MODE) ---

#[derive(Parser, Debug)]
#[command(author, version, about = "MP4 Doctor Enterprise AI", long_about = None)]
struct Cli {
    #[arg(short, long, help = "Nazwa projektu (Workspace) do utworzenia/załadowania")]
    workspace: Option<String>,
    
    #[arg(short, long, help = "Ścieżka do katalogu ze zepsutymi plikami (uruchamia Skaner)")]
    scan: Option<String>,
    
    #[arg(short, long, help = "Nadpisz limit wątków dla trybu automatycznego")]
    threads: Option<usize>,
    
    #[arg(long, help = "Uruchom zautomatyzowany test snajperski na pliku test.mp4")]
    auto_test: bool,

    // --- OPERACJE WSADOWE (wymagają --workspace) ---
    //
    // Biblioteka od dawna miała komplet wejść bezgłowych, ale nic ich nie
    // wywoływało: z poziomu CLI dało się uruchomić wyłącznie skaner, a z
    // Weryfikatora tylko interfejs TUI. Poniższe flagi są brakującym
    // dyspozytorem. Każda z nich odbiera zdarzenia przez
    // `bezglowe::z_odbiorem`, więc operacja wypisuje postęp i zapisuje naukę
    // do bazy wiedzy.
    #[arg(long, value_name = "KATALOG", help = "Poligon Chaos Monkey: trening Mózgu na zdrowych nagraniach")]
    train: Option<String>,

    #[arg(long, value_name = "PLIK", help = "Poligon snajperski: trening celowany na jednym pliku")]
    sniper: Option<String>,

    #[arg(long, value_name = "PLIK", help = "Głęboka sanityzacja odzyskanego pliku przez ffmpeg")]
    sanitize: Option<String>,

    #[arg(long, help = "Sanityzacja dwuprzebiegowa (wolniejsza, dokładniejsza) - działa z --sanitize")]
    two_pass: bool,

    #[arg(long, value_name = "PLIK", help = "Tryb ekstremalny: mutacje zdrowego pliku do testów odporności")]
    mutate: Option<String>,

    #[arg(long, value_name = "PLIK", help = "Autopilot: naprawa jednego uszkodzonego pliku")]
    autopilot: Option<String>,
}

/// Mówi wprost, gdzie trafią przestrzenie robocze, gdy NIE jest to domyślne
/// `workspaces` obok katalogu uruchomienia.
///
/// Powód: `.cargo/config.toml` w korzeniu workspace'u ustawia
/// `MP4_DOCTOR_KATALOG_PRZESTRZENI` dla każdego procesu uruchamianego przez
/// cargo — także dla `cargo run`. Bez tej informacji programista szukałby
/// swojego projektu w `./workspaces` i go tam nie znalazł.
/// Kieruje przestrzenie ZWYKŁEGO uruchomienia do własnego podkatalogu.
///
/// `.cargo/config.toml` ustawia `MP4_DOCTOR_KATALOG_PRZESTRZENI` dla każdego
/// procesu spod cargo, więc `cargo run` i testy trafiałyby do jednego worka —
/// a sprzątanie po testach kasowałoby projekty programisty. Rozdzielamy to:
/// testy mają podkatalog `testy`, zwykłe uruchomienia `uruchomienia`.
///
/// Gdy zmienna wskazuje już katalog testowy, NIE przekierowujemy: to znaczy,
/// że binarkę uruchomił test jako podproces i ma pracować tam, gdzie rodzic.
/// Zbudowana binarka uruchomiona wprost nie widzi zmiennej i zachowuje
/// dotychczasowe `./workspaces`.
fn ustaw_katalog_uruchomien() {
    let Some(wskazany) = std::env::var_os(workspace::ZMIENNA_KATALOGU_PRZESTRZENI) else {
        return;
    };
    if wskazany.is_empty() {
        return;
    }
    let sciezka = std::path::PathBuf::from(wskazany);
    if sciezka.file_name().and_then(|n| n.to_str()) == Some("testy") {
        return;
    }
    let _ = workspace::ustaw_katalog_przestrzeni(sciezka.join(workspace::PODKATALOG_URUCHOMIEN));
}

fn zamelduj_katalog_przestrzeni() {
    let katalog = workspace::katalog_przestrzeni();
    if katalog != std::path::Path::new("workspaces") {
        println!("📁 Przestrzenie robocze: {}", katalog.display());
    }
}

fn run_headless(cli: Cli) {
    ustaw_katalog_uruchomien();
    zamelduj_katalog_przestrzeni();

    if let Some(thread_override) = cli.threads {
        set_thread_count(thread_override);
    }

    if cli.auto_test {
        println!("🚀 Uruchamiam zautomatyzowany test snajperski bez interfejsu TUI...");
        let ws = workspace::Workspace::init("auto_test_workspace").unwrap();
        db::init_db(&ws).unwrap();
        let target_file = "/mnt2/gemini_cli/mp4_doctor_v2/test.mp4";
        let donor_path = ws.donors_dir.join("DONOR_test.moov");
        scanner::extract_and_save_moov(target_file, donor_path.to_str().unwrap()).unwrap();
        println!("🧬 Sztucznie wyizolowano dawcę (Wzorzec) do: {:?}", donor_path);
        
        let (tx, _rx) = event::channel();
        if let Some((dna, _)) = dna::extract_dna(target_file) {
            db::save_donor(&ws, &dna, donor_path.to_str().unwrap()).unwrap();
            println!("🌐 Wykonuję synchronizację z chmurą (Wysyłam dawców)...");
            let _ = db::sync_with_cloud(&ws, Some(&tx));
            
            println!("🗑️ Usuwam lokalnego dawcę, aby wymusić pobranie z chmury przez Autopilota...");
            let _ = std::fs::remove_file(&donor_path);
        }

        let cache = db::build_brain_cache(&ws).unwrap();
        if let Some((dna, _)) = dna::extract_dna(target_file) {
            println!("\n--- SYMULACJA POBRANIA Z CHMURY (AUTOPILOT) ---");
            let cloud_donor = autopilot::find_donor(&ws, &dna, &cache, &tx, 0);
            println!("Wynik pobierania: {:?}", cloud_donor);
        }

        let _ = training_ground::run_sniper_test(&ws, target_file, &tx);
        return;
    }

    // `as_deref`, nie `if let Some(x) = cli.workspace` — inaczej pole zostaje
    // przeniesione z `cli`, a dyspozytor poniżej potrzebuje całej struktury.
    if let Some(workspace_name) = cli.workspace.as_deref() {
        let ws = match workspace::Workspace::init(workspace_name) {
            Ok(ws) => ws,
            Err(e) => {
                eprintln!("❌ [BŁĄD KRYTYCZNY] Inicjalizacja projektu zawiodła: {}", e);
                process::exit(1);
            }
        };
        let _ = db::init_db(&ws);

        process::exit(wykonaj_operacje_wsadowa(&ws, workspace_name, &cli));
    }
}

/// Wybiera i wykonuje operację wsadową wskazaną flagami. Zwraca kod wyjścia.
///
/// Flagi są rozłączne i sprawdzane w ustalonej kolejności — gdy podano więcej
/// niż jedną, wykonuje się pierwsza z listy. Wypisujemy wtedy ostrzeżenie,
/// zamiast po cichu ignorować resztę.
fn wykonaj_operacje_wsadowa(ws: &workspace::Workspace, nazwa_projektu: &str, cli: &Cli) -> i32 {
    let wybrane = [
        cli.scan.is_some(),
        cli.train.is_some(),
        cli.sniper.is_some(),
        cli.sanitize.is_some(),
        cli.mutate.is_some(),
        cli.autopilot.is_some(),
    ]
    .iter()
    .filter(|w| **w)
    .count();

    if wybrane > 1 {
        eprintln!(
            "⚠️  [HEADLESS] Podano {} naraz. Wykonuję pierwszą; reszta zignorowana.",
            odmien_operacje(wybrane)
        );
    }

    if let Some(sciezka) = &cli.scan {
        // Brzmienie komunikatu ZOSTAJE takie jak przed refaktorem — jest
        // sprawdzane przez test integracyjny i może być wyszukiwane w logach
        // operacyjnych.
        println!("🚀 [HEADLESS] Uruchamianie Skanera Potokowego dla projektu: {}", nazwa_projektu);
        scanner::run_scanner_standalone(ws, sciezka, scanner::ScanMode::FullAuto);
        return 0;
    }

    if let Some(katalog) = &cli.train {
        println!("🚀 [HEADLESS] Poligon Chaos Monkey: {}", katalog);
        return zglos(training_ground::run_training_headless(ws, katalog));
    }

    if let Some(plik) = &cli.sniper {
        println!("🚀 [HEADLESS] Poligon snajperski: {}", plik);
        return zglos(training_ground::run_sniper_test_headless(ws, plik));
    }

    if let Some(plik) = &cli.sanitize {
        println!(
            "🚀 [HEADLESS] Głęboka sanityzacja ({}): {}",
            if cli.two_pass { "dwa przebiegi" } else { "jeden przebieg" },
            plik
        );
        return match sanitizer::run_deep_sanitization_headless(ws, plik, cli.two_pass) {
            Ok(wynik) => {
                println!("✔ Zapisano: {}", wynik);
                0
            }
            Err(e) => {
                eprintln!("❌ Sanityzacja zawiodła: {}", e);
                1
            }
        };
    }

    if let Some(plik) = &cli.mutate {
        println!("🚀 [HEADLESS] Tryb ekstremalny (mutacje): {}", plik);
        return zglos(god_mode::run_extreme_mutation_headless(ws, plik));
    }

    if let Some(plik) = &cli.autopilot {
        println!("🚀 [HEADLESS] Autopilot: {}", plik);
        // Autopilot potrzebuje wiedzy zebranej w poprzednich przebiegach —
        // bez niej ma tylko domyślną kaskadę algorytmów.
        let cache = match db::build_brain_cache(ws) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("❌ Nie udało się zbudować pamięci Mózgu: {}", e);
                return 1;
            }
        };
        return zglos(autopilot::run_headless(ws, plik, &cache));
    }

    println!("⚠️  [HEADLESS] Nie wskazano żadnej operacji. Dostępne: --scan, --train, --sniper, --sanitize, --mutate, --autopilot.");
    0
}

/// Poprawna odmiana rzeczownika po liczebniku: „2 operacje", ale „5 operacji".
///
/// Polszczyzna ma trzy formy liczby mnogiej i sklejenie `{} operacji` daje
/// błąd gramatyczny dla 2, 3 i 4.
fn odmien_operacje(ile: usize) -> String {
    let ostatnia = ile % 10;
    let dwie_ostatnie = ile % 100;
    let forma = if (2..=4).contains(&ostatnia) && !(12..=14).contains(&dwie_ostatnie) {
        "operacje"
    } else {
        "operacji"
    };
    format!("{} {}", ile, forma)
}

/// Sprowadza dowolny `Result` operacji wsadowej do kodu wyjścia, meldując błąd.
fn zglos<T, E: std::fmt::Display>(wynik: Result<T, E>) -> i32 {
    match wynik {
        Ok(_) => {
            println!("✔ Operacja zakończona.");
            0
        }
        Err(e) => {
            eprintln!("❌ Operacja zawiodła: {}", e);
            1
        }
    }
}

fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    let mut terminal_guard = TerminalGuard::init()?;
    let mut app = App::new();

    let tick_rate = Duration::from_millis(33); // ~30 FPS

    while !app.should_quit {
        // 1. Drain background worker events from channel
        app.process_events();

        // 2. Check for external preview requests (suspend TUI before launching ffplay)
        if let Some(preview_path) = app.take_pending_preview() {
            terminal_guard.suspend(|| {
                let mut cmd = std::process::Command::new("ffplay");
                cmd.arg("-autoexit")
                    .arg("-t").arg("3")
                    .arg("-v").arg("warning")
                    .arg("-window_title").arg("MP4 Doctor - Weryfikacja Uratowanego Wideo")
                    .arg(preview_path.to_str().unwrap_or_default());
                let _ = cmd.status();
                Ok(())
            })?;
        }

        // 3. Render frame
        terminal_guard.draw(|frame| {
            ui::draw(frame, &mut app);
        })?;

        // 4. Poll keyboard events
        if ct_event::poll(tick_rate)?
            && let Event::Key(key) = ct_event::read()?
                && key.kind == KeyEventKind::Press {
                    app.handle_key(key);
                }
    }

    // Explicit restore (Drop also handles this idempotently)
    let _ = terminal_guard.restore();
    Ok(())
}

fn main() {
    check_dependencies();
    init_shutdown_handler();

    let cli = Cli::parse();
    if cli.auto_test || cli.workspace.is_some() {
        run_headless(cli);
    } else {
        if let Err(e) = run_tui() {
            eprintln!("Błąd interfejsu TUI: {}", e);
            process::exit(1);
        }
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE DYSPOZYTORA
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Odmiana liczebnika
    // ------------------------------------------------------------------

    #[test]
    fn test_odmiana_dla_dwoch_trzech_czterech() {
        assert_eq!(odmien_operacje(2), "2 operacje");
        assert_eq!(odmien_operacje(3), "3 operacje");
        assert_eq!(odmien_operacje(4), "4 operacje");
    }

    #[test]
    fn test_odmiana_dla_piatki_i_wyzej() {
        assert_eq!(odmien_operacje(5), "5 operacji");
        assert_eq!(odmien_operacje(6), "6 operacji");
    }

    /// Pułapka polszczyzny: 12, 13 i 14 idą jak „operacji", mimo że kończą się
    /// na 2, 3 i 4. Bez tego wyjątku wychodziłoby „13 operacje".
    #[test]
    fn test_odmiana_dla_nastek_jest_wyjatkiem() {
        assert_eq!(odmien_operacje(12), "12 operacji");
        assert_eq!(odmien_operacje(13), "13 operacji");
        assert_eq!(odmien_operacje(14), "14 operacji");
    }

    #[test]
    fn test_odmiana_dla_dwudziestu_dwoch_wraca_do_formy_mnogiej() {
        assert_eq!(odmien_operacje(22), "22 operacje");
        assert_eq!(odmien_operacje(23), "23 operacje");
    }

    // ------------------------------------------------------------------
    // Kod wyjścia
    // ------------------------------------------------------------------

    #[test]
    fn test_zglos_sukces_daje_zero() {
        let ok: Result<(), String> = Ok(());
        assert_eq!(zglos(ok), 0);
    }

    /// Kod wyjścia różny od zera jest jedynym sygnałem, po którym skrypt
    /// wsadowy pozna, że operacja zawiodła — operacje bezgłowe nikt nie
    /// ogląda na żywo.
    #[test]
    fn test_zglos_porazka_daje_jeden() {
        let blad: Result<(), String> = Err("coś poszło nie tak".to_string());
        assert_eq!(zglos(blad), 1);
    }
}
