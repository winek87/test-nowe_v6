// src/debug_log.rs

//! Lekki, opcjonalny log techniczny PER FAZA.
//!
//! W odróżnieniu od logu operacyjnego (notuje WYNIK — zdrowy/uszkodzony —
//! per plik) ten zapisuje KAŻDE wywołanie rdzennej metody analizy danej fazy
//! wraz z czasem jej trwania — do diagnozowania, który konkretny plik/silnik
//! zawiesza lub nienaturalnie spowalnia fazę. Świadomie oddzielny od logu
//! operacyjnego (inny cel, inna objętość — potencjalnie milion+ wierszy).
//!
//! Aktywny WYŁĄCZNIE gdy `config.log_level` to `DEBUG`/`TRACE` — patrz
//! [`DebugLog::maybe_open`]. Przy niższym poziomie [`DebugLog::log`] jest
//! zerokosztowym no-opem (nawet plik na dysku nie powstaje), więc włączenie
//! tego mechanizmu nie ma żadnego wpływu na normalny przebieg fazy.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct DebugLog {
    /// `None` = wyłączony (poziom logowania poniżej DEBUG, albo nie udało
    /// się utworzyć pliku — brak logu debug NIGDY nie wywraca fazy).
    file: Option<Arc<Mutex<File>>>,
}

impl DebugLog {
    /// Tworzy log debug TYLKO gdy `log_level` to DEBUG/TRACE. `plik` powinien
    /// już nieść znacznik czasu (patrz `utils::stamp_filename`) — ten sam,
    /// co pozostałe raporty tego przebiegu fazy.
    pub fn maybe_open(katalog: &str, plik: &str, log_level: &str) -> Self {
        let aktywny = log_level.eq_ignore_ascii_case("DEBUG") || log_level.eq_ignore_ascii_case("TRACE");
        if !aktywny {
            return Self { file: None };
        }
        let path = Path::new(katalog).join(plik);
        match File::create(&path) {
            Ok(mut f) => {
                let _ = writeln!(f, "=== DZIENNIK DEBUG === (metoda | czas trwania | ścieżka)\n");
                Self { file: Some(Arc::new(Mutex::new(f))) }
            }
            // Brak logu debug nie jest błędem krytycznym - faza działa dalej
            // bez niego, po prostu bez tej dodatkowej diagnostyki.
            Err(_) => Self { file: None },
        }
    }

    /// `true`, gdy ten log faktycznie pisze na dysk (poziom DEBUG/TRACE i
    /// plik otwarty poprawnie) — pozwala wywołującemu pominąć drogi
    /// `Instant::now()`/pomiar czasu, gdy i tak nic by z nim nie zrobiono.
    pub fn is_active(&self) -> bool {
        self.file.is_some()
    }

    /// Zapisuje jeden wiersz: znacznik czasu, strona, metoda, czas trwania,
    /// WYNIK, ścieżka. `wynik` to zwięzły status ("OK", "BŁĄD: <przyczyna>",
    /// "UCIĘTY (Gray Banding)", itp.) — dostarczany przez wywołującego, bo
    /// każda faza ma własny kształt wyniku analizy; ten moduł niczego nie
    /// zgaduje. Odporny na zatruty mutex (panika w innym wątku trzymającym
    /// blokadę nie blokuje dalszego logowania) — ten sam wzorzec co
    /// `phase16::LiveStats::top_rules`.
    pub fn log(&self, side_label: &str, metoda: &str, rel_path: &str, czas: Duration, wynik: &str) {
        let Some(file) = &self.file else { return };
        let mut f = file.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(
            f,
            "[{}] [{:<15}] [{:<24}] {:>9.2} ms [{}] -> \"{}\"",
            crate::utils::log_timestamp(),
            side_label,
            metoda,
            czas.as_secs_f64() * 1000.0,
            wynik,
            rel_path
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maybe_open_inactive_below_debug_level() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        for poziom in ["INFO", "WARN", "ERROR", "info", "nieznany"] {
            let log = DebugLog::maybe_open(dir.path().to_str().unwrap(), "test.txt", poziom);
            assert!(!log.is_active(), "poziom {} nie powinien aktywować logu debug", poziom);
        }
    }

    #[test]
    fn test_maybe_open_active_for_debug_and_trace_case_insensitive() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        for poziom in ["DEBUG", "debug", "TRACE", "Trace"] {
            let log = DebugLog::maybe_open(dir.path().to_str().unwrap(), "test.txt", poziom);
            assert!(log.is_active(), "poziom {} powinien aktywować log debug", poziom);
        }
    }

    #[test]
    fn test_inactive_log_writes_nothing_to_disk() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let log = DebugLog::maybe_open(dir.path().to_str().unwrap(), "nieaktywny.txt", "INFO");
        log.log("UFS Explorer", "analyze_x", "plik.bin", Duration::from_millis(5), "OK");
        assert!(!dir.path().join("nieaktywny.txt").exists(), "log nieaktywny nie powinien nawet utworzyć pliku");
    }

    #[test]
    fn test_active_log_writes_method_timing_status_and_path() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let log = DebugLog::maybe_open(dir.path().to_str().unwrap(), "aktywny.txt", "DEBUG");
        log.log("Skrypt Autorski", "analyze_image_dng", "zdjecie.dng", Duration::from_millis(123), "OK");

        let tresc = std::fs::read_to_string(dir.path().join("aktywny.txt")).expect("Nie można odczytać pliku");
        assert!(tresc.contains("Skrypt Autorski"));
        assert!(tresc.contains("analyze_image_dng"));
        assert!(tresc.contains("zdjecie.dng"));
        assert!(tresc.contains("123.00 ms"));
        assert!(tresc.contains("[OK]"));
    }

    /// Zgłoszenie użytkownika: gdy metoda zwróci błąd, log debug musi to
    /// jawnie pokazać, nie tylko czas trwania jakby wszystko poszło dobrze.
    #[test]
    fn test_active_log_shows_error_status_when_method_failed() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let log = DebugLog::maybe_open(dir.path().to_str().unwrap(), "bledy.txt", "DEBUG");
        log.log("UFS Explorer", "analyze_image", "uszkodzony.jpg", Duration::from_millis(7), "BŁĄD: Zepsute Piksele (Gray Banding)");

        let tresc = std::fs::read_to_string(dir.path().join("bledy.txt")).expect("Nie można odczytać pliku");
        assert!(tresc.contains("[BŁĄD: Zepsute Piksele (Gray Banding)]"), "wynik: {}", tresc);
        assert!(tresc.contains("uszkodzony.jpg"));
    }

    #[test]
    fn test_maybe_open_missing_directory_degrades_gracefully_not_panicking() {
        // Katalog nieistniejący (np. usunięty write-blocker) - `File::create`
        // zawiedzie, ale to NIE MOŻE spanikować całej fazy z powodu samego
        // logu diagnostycznego.
        let log = DebugLog::maybe_open("/nieistniejaca/sciezka/do/logow", "cokolwiek.txt", "DEBUG");
        assert!(!log.is_active());
        // Wołanie log() na nieaktywnym logu też nie może panikować.
        log.log("UFS Explorer", "metoda", "plik", Duration::from_secs(1), "OK");
    }

    #[test]
    fn test_clone_shares_same_underlying_file() {
        let dir = tempfile::tempdir().expect("Nie można utworzyć katalogu tymczasowego dla testu");
        let log = DebugLog::maybe_open(dir.path().to_str().unwrap(), "wspolny.txt", "DEBUG");
        let klon = log.clone();
        log.log("UFS Explorer", "m1", "a.bin", Duration::from_millis(1), "OK");
        klon.log("Skrypt Autorski", "m2", "b.bin", Duration::from_millis(2), "OK");

        let tresc = std::fs::read_to_string(dir.path().join("wspolny.txt")).expect("Nie można odczytać pliku");
        assert!(tresc.contains("a.bin"));
        assert!(tresc.contains("b.bin"), "klon musi pisać do TEGO SAMEGO pliku co oryginał");
    }
}
