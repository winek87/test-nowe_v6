// src/logger.rs

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref GLOBAL_LOGGER: Mutex<Option<File>> = Mutex::new(None);
}

/// Inicjuje logowanie do pliku dla danego projektu (Przestrzeni Roboczej)
pub fn init(log_path: &Path) {
    if let Ok(file) = OpenOptions::new().create(true).append(true).open(log_path) {
        if let Ok(mut lock) = GLOBAL_LOGGER.lock() {
            *lock = Some(file);
        }
    }
}

/// Makro zastępujące `println!`. Zapisuje tekst do pliku bez niszczenia interfejsu (HUD).
#[macro_export]
macro_rules! dlog {
    ($($arg:tt)*) => {{
        // MAGIA RUSTA: Importujemy cechę Write wewnątrz izolowanego bloku makra.
        // Dzięki temu metoda .write_fmt() (używana przez writeln!) będzie działać 
        // we wszystkich plikach bez konieczności ręcznego dodawania importów!
        use std::io::Write;
        
        let msg = format!($($arg)*);
        if let Ok(mut lock) = $crate::logger::GLOBAL_LOGGER.lock() {
            if let Some(file) = lock.as_mut() {
                let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                let _ = writeln!(file, "[{}] {}", timestamp, msg);
            }
        }
    }};
}

// ============================================================================
// TESTY JEDNOSTKOWE
//
// `GLOBAL_LOGGER` jest stanem globalnym procesu, więc testy dzielą go z całą
// binarką testową. Kierujemy go do pliku tymczasowego — `dlog!` nigdzie indziej
// nie jest asercjonowany, więc przekierowanie nikomu nie szkodzi, a chroni
// drzewo projektu przed plikami dziennika.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Serializuje testy dotykające globalnego uchwytu dziennika.
    static MUTEKS: Mutex<()> = Mutex::new(());

    #[test]
    fn test_dlog_bez_inicjalizacji_nie_panikuje() {
        let _s = MUTEKS.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(mut lock) = GLOBAL_LOGGER.lock() {
            *lock = None;
        }

        // Cała wartość tego makra polega na tym, że wolno go użyć zawsze —
        // także zanim powstanie przestrzeń robocza i plik dziennika.
        crate::dlog!("wpis bez zainicjowanego dziennika {}", 1);
    }

    #[test]
    fn test_dlog_zapisuje_do_wskazanego_pliku() {
        let _s = MUTEKS.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("mp4_doctor_logger_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let plik = dir.join("dziennik.log");
        let _ = std::fs::remove_file(&plik);

        init(&plik);
        crate::dlog!("ZNACZNIK_TESTOWY wartość={}", 42);

        // Domykamy uchwyt, żeby bufor trafił na dysk.
        if let Ok(mut lock) = GLOBAL_LOGGER.lock() {
            *lock = None;
        }

        let mut tresc = String::new();
        std::fs::File::open(&plik).unwrap().read_to_string(&mut tresc).unwrap();

        assert!(tresc.contains("ZNACZNIK_TESTOWY wartość=42"), "Brak wpisu w dzienniku: {}", tresc);
        assert!(tresc.contains('['), "Wpis musi być opatrzony znacznikiem czasu: {}", tresc);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Dziennik jest DOPISYWANY, nie nadpisywany — inaczej każde wejście do
    /// projektu kasowałoby historię poprzednich przebiegów.
    #[test]
    fn test_ponowna_inicjalizacja_dopisuje_a_nie_kasuje() {
        let _s = MUTEKS.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("mp4_doctor_logger_append_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let plik = dir.join("dziennik.log");
        let _ = std::fs::remove_file(&plik);

        init(&plik);
        crate::dlog!("PIERWSZA_SESJA");
        if let Ok(mut lock) = GLOBAL_LOGGER.lock() { *lock = None; }

        init(&plik);
        crate::dlog!("DRUGA_SESJA");
        if let Ok(mut lock) = GLOBAL_LOGGER.lock() { *lock = None; }

        let tresc = std::fs::read_to_string(&plik).unwrap();
        assert!(tresc.contains("PIERWSZA_SESJA"), "Historia poprzedniej sesji przepadła: {}", tresc);
        assert!(tresc.contains("DRUGA_SESJA"), "Brak nowego wpisu: {}", tresc);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nieosiągalna ścieżka nie może wywrócić programu — dziennik jest
    /// udogodnieniem, nie warunkiem pracy.
    #[test]
    fn test_inicjalizacja_na_nieosiagalnej_sciezce_nie_panikuje() {
        let _s = MUTEKS.lock().unwrap_or_else(|e| e.into_inner());
        init(Path::new("/nie/ma/takiego/katalogu/dziennik.log"));
        crate::dlog!("wpis po nieudanej inicjalizacji");
    }
}
