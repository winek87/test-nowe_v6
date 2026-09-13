// src/bezglowe.rs

//! # Wspólna obsługa trybu bezgłowego (bez interfejsu TUI)
//!
//! ## Problem, który ten moduł rozwiązuje
//!
//! Każda długa operacja (`scanner`, `training_ground`, `sanitizer`, `god_mode`,
//! `autopilot`) raportuje postęp WYŁĄCZNIE przez szynę zdarzeń
//! [`crate::event`]. Żaden z tych modułów nie ma ani jednego `println!`, a
//! makro `dlog!` pisze tylko do pliku dziennika, i to pod warunkiem, że
//! dziennik został wcześniej zainicjowany.
//!
//! Punkty wejścia `*_headless` tworzyły kanał w postaci
//! `let (tx, _rx) = channel();` i nigdy z niego nie czytały. Skutki były dwa:
//!
//! 1. **Operacja była ślepa.** Zdarzenia trafiały do nieodbieranego kanału i
//!    ginęły, więc operator nie widział ani postępu, ani wyniku — polecenie
//!    milczało przez kilkanaście minut i kończyło się bez słowa.
//! 2. **Baza się nie uczyła.** Zdarzenia `DonorFound`, `RepairSuccess`
//!    i `RepairFailure` są JEDYNĄ drogą, którą wiedza trafia do SQLite. Bez
//!    odbiornika cały dorobek przebiegu przepadał.
//!
//! Jedynym wyjątkiem był `scanner::run_scanner_standalone`, który miał własny
//! wątek odbierający — i to on jest tu wzorcem. Ten moduł wyciąga ten wzorzec
//! do jednego miejsca, żeby wszystkie wejścia bezgłowe zachowywały się tak
//! samo.
//!
//! ## Dlaczego kanał nie może się zapchać
//!
//! `event::channel()` jest NIEOGRANICZONY, więc brak odbiornika nigdy nie
//! blokował nadawcy — za to zdarzenia narastały w pamięci do końca operacji.
//! Odbieranie na bieżąco usuwa i ten problem.

use crate::event::{AppEvent, EventSender, LogLevel};
use crate::workspace::Workspace;

/// Uruchamia operację bezgłową, odbierając jej zdarzenia na bieżąco:
/// wypisuje postęp na `stdout` i zapisuje naukę do bazy wiedzy.
///
/// Zwraca to, co zwróciła przekazana praca. Odbiornik jest domykany dopiero po
/// jej zakończeniu, więc żadne zdarzenie nie ginie.
///
/// ```ignore
/// let wynik = bezglowe::z_odbiorem(&ws, |tx| training_ground::run_training(&ws, katalog, tx));
/// ```
pub fn z_odbiorem<T>(ws: &Workspace, praca: impl FnOnce(&EventSender) -> T) -> T {
    let (nadajnik, odbiornik) = crate::event::channel();
    let ws_watku = ws.clone();

    let watek = std::thread::spawn(move || {
        while let Ok(zdarzenie) = odbiornik.recv() {
            obsluz_zdarzenie(&ws_watku, zdarzenie);
        }
    });

    let wynik = praca(&nadajnik);

    // Zamknięcie nadajnika kończy pętlę odbiornika — bez tego `join` wisiałby
    // w nieskończoność.
    drop(nadajnik);
    let _ = watek.join();

    wynik
}

/// Pojedyncze zdarzenie: co pokazać operatorowi i co zapisać do bazy.
///
/// Trzy warianty niosące naukę (`DonorFound`, `RepairSuccess`,
/// `RepairFailure`) MUSZĄ trafić do bazy — to dokładnie ta sama obsługa, jaką
/// miał dotąd wyłącznie skaner.
fn obsluz_zdarzenie(ws: &Workspace, zdarzenie: AppEvent) {
    match zdarzenie {
        AppEvent::DonorFound { dna, moov_path } => {
            let _ = crate::db::save_donor(ws, &dna, &moov_path);
            println!("[ DAWCA ] {} -> {}", dna, moov_path);
        }
        AppEvent::RepairSuccess { file_name, dna, algorithm } => {
            let _ = crate::db::reward_algorithm(ws, &dna, &algorithm);
            println!("[  ✔   ] {} naprawiony algorytmem {}", file_name, algorithm);
        }
        AppEvent::RepairFailure { file_name, dna, algorithm } => {
            let _ = crate::db::penalize_algorithm(ws, &dna, &algorithm);
            println!("[  ✘   ] {} - algorytm {} zawiódł", file_name, algorithm);
        }

        AppEvent::OperationStarted(nazwa) => println!("[ START ] {}", nazwa),
        AppEvent::OperationFinished(podsumowanie) => println!("[ KONIEC] {}", podsumowanie),
        AppEvent::OperationFailed(nazwa, powod) => eprintln!("[ BŁĄD  ] {}: {}", nazwa, powod),

        AppEvent::Progress { current, total, message } => {
            let opis = message.unwrap_or_default();
            println!("[ {:>3}%  ] {}/{} {}", procent(current, total), current, total, opis);
        }

        // Poziom Debug pomijamy — w trybie wsadowym zalałby wyjście.
        AppEvent::Log(log) if log.level != LogLevel::Debug => {
            println!("[{:^7}] {}: {}", log.level.as_str(), log.module, log.message);
        }

        _ => {}
    }
}

/// Procent postępu odporny na `total == 0` (dzielenie przez zero przy pustym
/// katalogu wejściowym jest realnym przypadkiem, nie hipotezą).
///
/// Mnożenie idzie przez `u128`, a nie przez `saturating_mul` na `usize`.
/// Nasycenie wyglądało na bezpieczne, ale daje CICHO BŁĘDNY wynik: przy
/// wielkich licznikach `current * 100` zatrzymuje się na `usize::MAX`, więc
/// dzielenie zwraca 1 zamiast 100. Złapał to własny test tej funkcji.
fn procent(current: usize, total: usize) -> usize {
    if total == 0 {
        return 0;
    }
    ((current as u128) * 100 / (total as u128)) as usize
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_procent_przy_zerowej_calosci_nie_dzieli_przez_zero() {
        assert_eq!(procent(0, 0), 0);
        assert_eq!(procent(5, 0), 0);
    }

    #[test]
    fn test_procent_liczy_poprawnie() {
        assert_eq!(procent(0, 10), 0);
        assert_eq!(procent(5, 10), 50);
        assert_eq!(procent(10, 10), 100);
    }

    #[test]
    fn test_procent_nie_przepelnia_sie_przy_ogromnych_wartosciach() {
        // `current * 100` na dużych licznikach przepełniłoby `usize` bez
        // `saturating_mul` - przy skanie milionów plików to realny zakres.
        assert_eq!(procent(usize::MAX, usize::MAX), 100);
    }

    /// Praca musi dostać działający nadajnik, a jej wynik ma wrócić do
    /// wywołującego nietknięty.
    #[test]
    fn test_z_odbiorem_zwraca_wynik_pracy() {
        let ws = Workspace::init_testowy("bezglowe_wynik").unwrap();

        let wynik = z_odbiorem(&ws, |tx| {
            tx.info("TEST", "wiadomość z operacji");
            42
        });

        assert_eq!(wynik, 42);
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    /// Sedno modułu: zdarzenia niosące naukę muszą trafić do bazy. Bez
    /// odbiornika `RepairSuccess` przepadał i przebieg niczego nie uczył.
    #[test]
    fn test_z_odbiorem_zapisuje_nauke_do_bazy() {
        let ws = Workspace::init_testowy("bezglowe_nauka").unwrap();
        crate::db::init_db(&ws).expect("baza musi się utworzyć");

        z_odbiorem(&ws, |tx| {
            tx.repair_success("plik.mp4", "DNA_TESTOWE", "Clone");
        });

        // Nagroda dla algorytmu jest widoczna w bazie wiedzy.
        let conn = crate::db::init_db(&ws).unwrap();
        let ile: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM knowledge_base WHERE dna_signature = ?1",
                [&"DNA_TESTOWE"],
                |r| r.get(0),
            )
            .unwrap_or(0);

        assert!(ile > 0, "Zdarzenie RepairSuccess musi zostawić ślad w bazie wiedzy");
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    /// Odbiornik musi domknąć się sam po zakończeniu pracy — inaczej `join`
    /// wisiałby, a polecenie nigdy by nie wróciło.
    #[test]
    fn test_z_odbiorem_konczy_sie_a_nie_wisi() {
        let ws = Workspace::init_testowy("bezglowe_domkniecie").unwrap();

        let start = std::time::Instant::now();
        z_odbiorem(&ws, |tx| {
            for i in 0..200 {
                tx.info("TEST", format!("wiadomość {}", i));
            }
        });

        assert!(start.elapsed() < std::time::Duration::from_secs(10), "Odbiornik zawiesił się");
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }
}
