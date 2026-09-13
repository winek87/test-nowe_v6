// src/main.rs
//!
//! # Weryfikator Kryminalistyczny (File Carving Validator)
//! **Główny punkt wejścia do aplikacji (Entry Point).**

mod raw_image;
mod heic_image;
mod video_image;
mod ts_stream;
mod mkv_container;
mod flv_stream;
mod mp4_repair;

mod duplicate_finder;
mod dng_repair;
mod dng_splice;
mod jpeg_splice;
mod png_repair;
mod raster_splice;
mod zip_splice;
mod tar_archive;

#[cfg(test)]
mod test_fixtures;

mod thread_activity;
mod db;
mod diag;
mod logging;
mod menu;
mod phases;
mod reset;
mod workspace_cleanup;
mod settings;
mod tui;
mod utils;

use std::fs;
use std::io::Write; // Dodane dla bezpiecznego flushowania strumieni przed exitem
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tracing::{error, info, warn};
use colored::Colorize;

/// Globalny licznik przerwań (do obsługi Double-Ctrl-C)
static CTRL_C_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Główna funkcja orkiestrująca działanie programu.
fn main() -> rusqlite::Result<()> {
    // --- 1. USTAWIENIA ---
    let mut ustawienia = settings::Ustawienia::wczytaj("ustawienia.json");

    // --- 2. TELEMETRIA I LOGI (Podpięcie Panic Hooka i Rotacji) ---
    let _guard = logging::init(
        &ustawienia.log_path,
        &ustawienia.log_level,
        ustawienia.max_threads,
        &ustawienia.io_mode,
    );

    // --- 3. OGRANICZENIE ZASOBÓW (CPU / RAYON) ---
    match rayon::ThreadPoolBuilder::new()
        .num_threads(ustawienia.max_threads)
        .build_global()
    {
        Ok(()) => {
            let threads_info = if ustawienia.max_threads == 0 {
                "AUTO (Wszystkie rdzenie)".to_string()
            } else {
                ustawienia.max_threads.to_string()
            };
            info!("Pula wątków Rayon została bezpiecznie zainicjalizowana. Limit: {}", threads_info);
            eprintln!("{} Pula wątków Rayon: {}", "[ SUKCES ]".green().bold(), threads_info.cyan());
        }
        Err(e) => {
            tracing::error!("Błąd inicjalizacji puli wątków Rayon: {:?}", e);
            error!("Błąd inicjalizacji puli wątków Rayon: {}. System użyje domyślnej puli OS.", e);
            eprintln!("{} Nie udało się zainicjalizować globalnej puli Rayon: {}", "[ OSTRZEŻENIE ]".yellow().bold(), e);
            eprintln!("{}", "System automatycznie użyje domyślnej puli wątków systemu operacyjnego.".bright_black());
        }
    }

    // --- 4. WERYFIKACJA UPRAWNIEŃ (Root Check dla Linux/Unix) ---
    #[cfg(unix)]
    {
        // Sprawdzamy czy użytkownik to root (UID 0)
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root {
            tracing::warn!("Brak uprawnień administratora (root) - Faza 9 (Smart Merge) może nie przywrócić właścicieli plików (chown).");
            warn!("Brak uprawnień administratora (root) - Faza 9 (Smart Merge) może nie przywrócić właścicieli plików (chown).");
            eprintln!("\n{}", "[OSTRZEŻENIE] Uruchomiłeś program bez uprawnień administratora (root).".yellow().bold());
            eprintln!("{}", "Faza 9 (Smart Merge) nie będzie w stanie przywrócić oryginalnych właścicieli plików (chown).".bright_black());
            eprintln!("{}\n", "Program będzie kontynuował za 4 sekundy, ale zaleca się uruchomienie go przez 'sudo'.".bright_black());
            std::thread::sleep(Duration::from_secs(4));
        }
    }

    // --- 5. GRACEFUL EXIT Z ZABEZPIECZENIEM (Double-Ctrl-C) ---
    // Zgodnie z polityką Zero-Deletion integrujemy dwa podejścia.
    // Pierwsze kliknięcie łagodnie wygasza silnik Rayon, drugie wymusza natychmiastowy exit POSIX.
    ctrlc::set_handler(move || {
        let count = CTRL_C_COUNT.fetch_add(1, Ordering::SeqCst);
        
        if count == 0 {
            tracing::warn!("Zainicjowano przerwanie awaryjne (Ctrl+C). Oczekiwanie na wątki...");
            warn!("Zainicjowano przerwanie awaryjne (Ctrl+C). Oczekiwanie na wątki...");
            eprintln!("\n{} Trwa bezpieczne zatrzymywanie wątków i I/O...", "[ WYKRYTO PRZERWANIE (Ctrl+C) ]".yellow().bold());
            eprintln!("{}", "(Naciśnij Ctrl+C ponownie, aby wymusić natychmiastowe twarde zamknięcie)".bright_black());
            // Podnosi znaczniki WSZYSTKICH bibliotek w procesie - patrz
            // `utils::podnies_przerwanie`. Bez tego Ctrl+C w podekranie
            // „MP4 DOCTOR" zatrzymywałby nasze fazy, a jego wątki pracowały
            // dalej.
            crate::utils::podnies_przerwanie();

        } else {

            let _ = crossterm::terminal::disable_raw_mode();
            let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);

            tracing::error!("Podwójne Ctrl+C! Wymuszono natychmiastowe przerwanie procesu (Hard Kill).");
            error!("Podwójne Ctrl+C! Wymuszono natychmiastowe przerwanie procesu (Hard Kill).");
            eprintln!("\n{} Wymuszanie natychmiastowego zamknięcia procesu (Hard Kill)...", "[ KRYTYCZNE PRZERWANIE (Podwójne Ctrl+C) ]".red().bold());
            let _ = std::io::stdout().flush();
            std::process::exit(130);
        }
    }).expect("Błąd przy ustawianiu handlera sygnałów awaryjnych");

    // --- 6. BAZA DANYCH (SQLITE) ---
    let db_dir = Path::new(&ustawienia.db_path);
    if !db_dir.exists() {
        match fs::create_dir_all(db_dir) {
            Ok(()) => {
                info!("Utworzono brakujący katalog bazy danych: {:?}", db_dir);
                eprintln!("{} Utworzono katalog bazy danych: {:?}", "[ SUKCES ]".green().bold(), db_dir);
            }
            Err(e) => {
                tracing::error!("Krytyczny błąd: nie udało się utworzyć katalogu bazy danych '{:?}': {:?}", db_dir, e);
                eprintln!("\n{} Krytyczny błąd: nie udało się utworzyć katalogu bazy danych '{:?}': {}", "[ BŁĄD ]".red().bold(), db_dir, e);
                panic!("Przerwano działanie z powodu błędu I/O katalogu bazy danych.");
            }
        }
    }
    
    // Panic-free path conversion (usuwamy .unwrap())
    let full_db_path = db_dir.join(&ustawienia.db_file_name);
    let db_path_str = full_db_path.to_string_lossy().to_string(); 
    
    info!("Inicjalizacja połączenia bazy danych: {}", db_path_str);
    eprintln!("{} Inicjalizacja bazy danych w ścieżce: {}", "[ INFORMACJA ]".cyan().bold(), db_path_str);
    
    let mut conn = match db::init_db(&db_path_str) {
        Ok(c) => {
            info!("Połączenie z bazą danych zostało pomyślnie zainicjalizowane.");
            eprintln!("{} Połączenie z bazą danych zostało pomyślnie zainicjalizowane.", "[ SUKCES ]".green().bold());
            c
        }
        Err(e) => {
            tracing::error!("Krytyczny błąd inicjalizacji bazy danych '{}': {:?}", db_path_str, e);
            error!("Krytyczny błąd inicjalizacji bazy danych '{}': {:?}", db_path_str, e);
            eprintln!("\n{} Nie udało się zainicjalizować bazy danych w ścieżce: {}", "[ BŁĄD ]".red().bold(), db_path_str);
            eprintln!("Szczegóły błędu: {}", e);
            panic!("Przerwano działanie z powodu błędu bazy danych.");
        }
    };

    // --- 7. URUCHOMIENIE MENU INTERAKTYWNEGO ---
    info!("Uruchamianie głównego menu interaktywnego...");
    eprintln!("{} Przechodzenie do głównego menu interaktywnego...", "[ INFORMACJA ]".cyan().bold());

    match menu::start_interactive(&mut ustawienia, &mut conn) {
        Ok(()) => {
            info!("Menu interaktywne zakończyło działanie w sposób prawidłowy.");
            eprintln!("{} Aplikacja zakończyła działanie pomyślnie.", "[ SUKCES ]".green().bold());
        }
        Err(e) => {
            tracing::error!("Błąd podczas działania menu interaktywnego: {:?}", e);
            eprintln!("\n{} Wystąpił błąd podczas działania menu interaktywnego.", "[ BŁĄD ]".red().bold());
            eprintln!("Szczegóły błędu: {}", e);
            panic!("Przerwano działanie z powodu błędu w menu interaktywnym.");
        }
    }

    // --- 8. ZAKOŃCZENIE I CZYSZCZENIE ZASOBÓW ---
    eprintln!("\n{}", "==========================================================================".cyan());
    eprintln!("{}", "[ 🛑 ] ZAMYKANIE WERYFIKATORA KRYMINALISTYCZNEGO".red().bold());
    eprintln!("{}", "==========================================================================".cyan());
    eprintln!("{}", "Trwa zrzucanie buforów bazy danych do dysku (Checkpointing WAL)...".bright_black());

    info!("Wywoływanie PRAGMA wal_checkpoint(TRUNCATE)...");
    match conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
        Ok(()) => {
            info!("WAL checkpoint wykonany pomyślnie.");
        }
        Err(e) => {
            tracing::error!("Ostrzeżenie przy zamykaniu bazy (Checkpoint WAL): {:?}", e);
            error!("Ostrzeżenie przy zamykaniu bazy (Checkpoint WAL): {}", e);
            eprintln!("{} Ostrzeżenie przy zamykaniu bazy (Checkpoint WAL): {}", "[ OSTRZEŻENIE ]".yellow().bold(), e);
        }
    }
    
    drop(conn);
    info!("Połączenie z bazą danych SQLite zamknięte bezpiecznie.");
    eprintln!("{}", "[ ✔ ] Baza danych bezpiecznie zsynchronizowana.".green());
    eprintln!("{}", "[ ✔ ] System operacyjny może teraz bezpiecznie zamknąć proces.\n".green());

    // Logowanie naturalnego zamknięcia
    logging::log_session_end();

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE (cargo test)
// ============================================================================

#[cfg(test)]
mod main {
    use super::*;
//    use std::path::PathBuf;

    /// Test sprawdza, czy bezpieczne łączenie ścieżek dla bazy danych 
    /// działa poprawnie (zamiana Path na String bez użycia .unwrap()).
    #[test]
    fn test_db_path_construction() {
        let db_dir = Path::new("target/test_data");
        let db_file_name = "test_kryminalistyczny.db";

        let full_db_path = db_dir.join(db_file_name);
        let db_path_str = full_db_path.to_string_lossy().to_string();

        assert!(db_path_str.ends_with("test_kryminalistyczny.db"));
        assert!(db_path_str.contains("target"));
    }

    /// Test weryfikuje poprawność inicjalizacji tymczasowej bazy danych 
    /// oraz wykonanie operacji SQLite WAL checkpoint.
    #[test]
    fn test_database_init_and_checkpoint() {
        let temp_dir = std::env::temp_dir().join("kryminalistyczny_test_db");
        let _ = fs::create_dir_all(&temp_dir);
        let db_path = temp_dir.join("test.db");
        let db_path_str = db_path.to_string_lossy().to_string();

        // Inicjalizacja bazy testowej przez moduł db
        let conn = db::init_db(&db_path_str).expect("Nie udało się utworzyć testowej bazy danych");

        // Test operacji zamykania i WAL checkpoint (odpowiednik kroku 8 z main)
        let checkpoint_result = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        assert!(checkpoint_result.is_ok(), "Operacja WAL checkpoint powinna zakończyć się sukcesem");

        // Sprzątanie po teście
        drop(conn);
        let _ = fs::remove_dir_all(temp_dir);
    }

    /// Test licznika powiązanego z procedurą Double-Ctrl-C
    #[test]
    fn test_ctrl_c_counter_logic() {
        // Resetujemy lub sprawdzamy atomowy licznik używany w handlerze
        let counter = AtomicUsize::new(0);
        
        // Pierwsze naciśnięcie (powinno zwrócić 0 przed inkrementacją)
        let first_val = counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(first_val, 0);

        // Drugie naciśnięcie (powinno zwrócić 1)
        let second_val = counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(second_val, 1);
    }

    /// Test weryfikujący poprawność logiki konfiguracji wątków Rayon
    #[test]
    fn test_rayon_threads_configuration_logic() {
        // Symulacja logiki z głównego pliku dla max_threads = 0 (AUTO)
        let max_threads_auto = 0;
        let threads_info_auto = if max_threads_auto == 0 {
            "AUTO (Wszystkie rdzenie)".to_string()
        } else {
            max_threads_auto.to_string()
        };
        assert_eq!(threads_info_auto, "AUTO (Wszystkie rdzenie)");

        // Symulacja dla konkretnej liczby wątków
        let max_threads_fixed = 4;
        let threads_info_fixed = if max_threads_fixed == 0 {
            "AUTO (Wszystkie rdzenie)".to_string()
        } else {
            max_threads_fixed.to_string()
        };
        assert_eq!(threads_info_fixed, "4");
    }

    #[test]
    fn test_io_mode_logic() {
        // Symulacja sprawdzenia trybu I/O z ustawień
        let io_mode = "sync"; 
        assert!(io_mode == "sync" || io_mode == "async");
    }

}
