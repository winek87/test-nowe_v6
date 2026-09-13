// src/logging.rs

//! Moduł odpowiedzialny za zaawansowany system logowania zdarzeń (tracing).
//! 
//! Zapewnia asynchroniczny, bezkolizyjny zapis logów do plików na dysku,
//! zapobiegając zniekształceniom interfejsu (TUI). Posiada rotację na podstawie
//! rozmiaru (Max 10 MB, 5 plików) oraz system ratunkowy zrzutu błędów krytycznych.

use rolling_file::{BasicRollingFileAppender, RollingConditionBasic};
use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::time::LocalTime;
use tracing_subscriber::{fmt, EnvFilter};

/// Inicjalizuje globalny subskrybent (logger) dla biblioteki `tracing`.
pub fn init(log_dir: &str, log_level: &str, max_threads: usize, io_mode: &str) -> WorkerGuard {
    // 1. Upewniamy się, że folder na logi istnieje
    std::fs::create_dir_all(log_dir).unwrap_or_else(|e| {
        panic!(
            "BŁĄD KRYTYCZNY: Nie udało się utworzyć katalogu logów '{}': {}",
            log_dir, e
        )
    });

    let log_file_path = Path::new(log_dir).join("weryfikator.log");

    // 2. Konfiguracja rotacji (Max 10 MB per plik, Max 5 plików archiwalnych)
    let file_appender = BasicRollingFileAppender::new(
        log_file_path,
        RollingConditionBasic::new().max_size(10 * 1024 * 1024), // 10 MB
        5 // Zatrzymuje 5 starych plików
    ).unwrap();
    
    // 3. Włączenie logowania asynchronicznego (nie blokuje wątków CPU!)
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // 4. Inicjalizacja z poziomem zdefiniowanym z menu TUI (np. INFO, WARN, DEBUG)
    let filter = EnvFilter::new(log_level);

    fmt()
        .with_env_filter(filter)
        .with_writer(non_blocking)
        .with_ansi(false) // Plik tekstowy nie znosi kolorów
        .with_timer(LocalTime::rfc_3339()) 
        .with_target(true)
        .with_thread_ids(false)
        .init();

    // Ładne formatowanie dla wątków procesora w logu
    let threads_str = if max_threads == 0 { "AUTO (Maksymalna wydajność)".to_string() } else { max_threads.to_string() };

    // Wyraźne odcięcie nowej sesji w pliku logów
    tracing::info!("======================================================");
    tracing::info!("=== SESJA WZNOWIONA (Uruchomienie Weryfikatora) ===");
    tracing::info!("Poziom Logowania   : {}", log_level);
    tracing::info!("Limit CPU (Rayon)  : {}", threads_str);
    tracing::info!("Tryb Dyskowy (I/O) : {}", io_mode);
    tracing::info!("======================================================");

    // 5. Globalny Panic Hook (Ratowanie logów po wysypaniu się programu)
    //
    // NAPRAWIONY BUG (znaleziony na prawdziwym pliku DNG użytkownika): ten
    // hook uruchamia się PRZY KAŻDEJ panice w programie, NIEZALEŻNIE od tego,
    // czy zostanie ona później bezpiecznie przechwycona przez
    // `std::panic::catch_unwind` gdzieś wyżej na stosie (hooki wykonują się
    // ZAWSZE, w momencie paniki, zanim w ogóle zacznie się rozwijanie stosu
    // do miejsca przechwycenia). Moduł `raw_image` (dekodowanie DNG/RAW)
    // celowo i bezpiecznie łapie panikę `rawloader` na pewnych uszkodzonych
    // plikach (`catch_unwind`) — ale bez poniższego sprawdzenia, TEN hook i
    // tak zdążyłby wyłączyć tryb Raw i opuścić alternatywny ekran Ratatui,
    // niszcząc cały interfejs TUI w środku normalnie kontynuującego się
    // skanowania Fazy 13, mimo że sam program by przeżył. Flaga
    // `is_expected_panic_in_progress()` (thread-local — bezpieczna
    // przy równoległym skanowaniu wieloma wątkami Rayon naraz) pozwala
    // odróżnić tę oczekiwaną, obsłużoną sytuację od prawdziwej katastrofy.
    //
    // MUSZĄ tu być wymienione WSZYSTKIE moduły używające `catch_unwind`
    // wokół zewnętrznych dekoderów — pominięcie któregokolwiek oznacza, że
    // jego bezpiecznie obsłużona panika i tak zniszczyłaby ekran TUI:
    //   - `raw_image`   → rawloader (DNG) - tu panika ZAOBSERWOWANA w praktyce,
    //   - `heic_image`  → libheif (HEIC/HEIF/AVIF),
    //   - `video_image` → crate mp4 (MP4/MOV/M4V).
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let expected = crate::raw_image::is_expected_panic_in_progress()
            || crate::heic_image::is_expected_panic_in_progress()
            || crate::video_image::is_expected_panic_in_progress();
        if expected {
            // Oczekiwana, bezpiecznie obsługiwana panika (np. rawloader na
            // uszkodzonym DNG) - logujemy jako ostrzeżenie, ale NIE ruszamy
            // terminala i NIE wywołujemy domyślnego hooka (który wypisałby
            // hałaśliwy komunikat na stderr w środku działającego skanu).
            tracing::warn!(panic = %panic_info, "Przechwycona oczekiwana panika (obsłużona przez catch_unwind) - kontynuuję.");
            return;
        }

        // Awaryjne przywrócenie terminala w przypadku PRAWDZIWEGO krytycznego
        // błędu (zapobiega rozwaleniu ekranu).
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);

        tracing::error!(panic = %panic_info, "=== BŁĄD KRYTYCZNY: SESJA PRZERWANA (PANIC) ===");

        // Zabezpieczenie asynchroniczne: Dajemy pobocznemu wątkowi logującemu 
        // 500 milisekund na fizyczny zapis buforów na dysk, zanim OS zabije program.
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        default_hook(panic_info);
    }));

    guard
}

pub fn log_session_end() {
    tracing::info!("======================================================");
    tracing::info!("=== SESJA ZAKOŃCZONA (Wyjście z menu programu) ===");
    tracing::info!("======================================================");
}

// ============================================================================
// TESTY JEDNOSTKOWE
//
// [`init`] nie jest tu testowany w procesie testowym i jest to decyzja, nie
// przeoczenie: instaluje GLOBALNY subskrybent `tracing` oraz GLOBALNY panic
// hook. Jedno i drugie działa raz na proces i zmieniłoby zachowanie wszystkich
// pozostałych testów w tej samej binarce — z panic hookiem włącznie, czyli
// z tym, co dzieje się przy każdej celowo wywoływanej panice w innych testach.
// Sprawdzamy więc to, co da się sprawdzić bez dotykania stanu globalnego.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Ścieżka do katalogu `src/` niezależna od katalogu uruchomienia.
    fn katalog_zrodel() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    /// Wypisuje pliki `.rs` z `src/` rekurencyjnie.
    fn pliki_zrodlowe(katalog: &Path, zebrane: &mut Vec<std::path::PathBuf>) {
        let Ok(wpisy) = std::fs::read_dir(katalog) else { return };
        for wpis in wpisy.flatten() {
            let sciezka = wpis.path();
            if sciezka.is_dir() {
                pliki_zrodlowe(&sciezka, zebrane);
            } else if sciezka.extension().and_then(|e| e.to_str()) == Some("rs") {
                zebrane.push(sciezka);
            }
        }
    }

    /// STRAŻNIK NAJWAŻNIEJSZEJ UMOWY TEGO MODUŁU.
    ///
    /// Panic hook wykonuje się przy KAŻDEJ panice, także tej bezpiecznie
    /// przechwyconej przez `catch_unwind` wyżej na stosie — hooki działają
    /// zanim zacznie się rozwijanie stosu. Moduł, który opakowuje zewnętrzny
    /// dekoder i wystawia flagę `is_expected_panic_in_progress`, ale NIE jest
    /// wymieniony w hooku, i tak zniszczy ekran TUI w środku normalnie
    /// kontynuującego się skanowania. Dokładnie to wydarzyło się kiedyś na
    /// prawdziwym pliku DNG.
    ///
    /// Ten test wychwyci taki brak przy dodaniu kolejnego dekodera, zamiast
    /// zostawiać go do wykrycia przez rozwalony interfejs u operatora.
    #[test]
    fn test_kazdy_modul_z_flaga_paniki_jest_wymieniony_w_hooku() {
        let zrodla = katalog_zrodel();
        let mut pliki = Vec::new();
        pliki_zrodlowe(&zrodla, &mut pliki);
        assert!(!pliki.is_empty(), "Nie znaleziono źródeł — test nie mierzyłby niczego");

        let hook = std::fs::read_to_string(zrodla.join("logging.rs"))
            .expect("logging.rs musi być czytelny");

        let mut z_flaga = Vec::new();
        for plik in &pliki {
            if plik.file_name().and_then(|n| n.to_str()) == Some("logging.rs") {
                continue;
            }
            let tresc = std::fs::read_to_string(plik).unwrap_or_default();
            if tresc.contains("pub fn is_expected_panic_in_progress") {
                let modul = plik.file_stem().unwrap().to_str().unwrap().to_string();
                z_flaga.push(modul);
            }
        }

        assert!(!z_flaga.is_empty(), "Co najmniej `raw_image` musi wystawiać tę flagę");

        for modul in &z_flaga {
            let oczekiwane = format!("crate::{}::is_expected_panic_in_progress", modul);
            assert!(
                hook.contains(&oczekiwane),
                "Moduł `{}` wystawia flagę oczekiwanej paniki, ale NIE JEST wymieniony w panic hooku. \
                 Jego bezpiecznie obsłużona panika zniszczy ekran TUI w środku skanowania. \
                 Dopisz `{}` do warunku w `logging::init`.",
                modul, oczekiwane
            );
        }
    }

    // Odwrotnej kontroli (moduł wymieniony w hooku, ale nieistniejący) nie ma
    // świadomie: taki wpis nie przeszedłby kompilacji, więc test dublowałby
    // pracę kompilatora.

    /// Bez zainstalowanego subskrybenta `tracing` te wywołania są puste — ale
    /// nie mogą panikować, bo `log_session_end` woła się przy każdym wyjściu
    /// z menu, także wtedy, gdy inicjalizacja logowania zawiodła.
    #[test]
    fn test_zamkniecie_sesji_bez_subskrybenta_nie_panikuje() {
        log_session_end();
    }
}
