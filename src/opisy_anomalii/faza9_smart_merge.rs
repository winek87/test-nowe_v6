// src/opisy_anomalii/faza9_smart_merge.rs

//! Wyjaśnienia etykiet z panelu bocznego Fazy 9 —
//! `phases::phase9::build_summary_block`. Treść jest bezpośrednim opisem
//! REALNEJ logiki `decide_winner`/`copy_file_and_meta` — nie ma tu niczego
//! zgadywanego. Jeśli kolejność priorytetów albo kategorie się zmienią, ten
//! plik musi zostać zaktualizowany razem z nimi.
//!
//! UWAGA na format etykiet: trzy wiersze panelu pakują DWIE strony w jedną
//! linię `Etykieta — UFS: X | Skrypt: Y` (konwencja tego panelu, nie błąd) —
//! ponieważ `scanner_panel::buduj_wiersze` dzieli linię na etykietę/wartość
//! po PIERWSZYM ": ", faktyczna etykieta wiersza to CAŁE "Etykieta — UFS"
//! (patrz testy niżej, które to potwierdzają wprost na formacie
//! `build_summary_block`).
//!
//! Pominięte celowo (generyczne, nie wymagają wyjaśnienia — ten sam wybór co
//! w `faza3_anomalie_klastra.rs`): "Prędkość", "Wątki kopiowania (Wariant A)".

use super::OpisAnomalii;

pub fn opisy() -> Vec<OpisAnomalii> {
    vec![
        OpisAnomalii {
            etykieta: "Wspólne — UFS",
            wyjasnienie: "Dla plików obecnych po OBU stronach: ile razy wygrała kopia UFS, ile razy Skrypt, i ile zostało zastąpionych złożeniem z Fazy 18 (Smart Splice, gdy żadna pojedyncza kopia nie była w pełni sprawna, ale dało się je połączyć). Zwycięzcę wybiera decide_winner wg ścisłej hierarchii priorytetów: YARA, potem Smart Splice, potem naprawa Fazy 17, potem kolejne testy strukturalne, na końcu rozmiar/remis.",
        },
        OpisAnomalii {
            etykieta: "Unikalne skopiowane — UFS",
            wyjasnienie: "Pliki obecne TYLKO po jednej stronie (UFS albo Skrypt) — kopiowane automatycznie bez przechodzenia przez hierarchię porównawczą decide_winner, bo nie ma z czym porównywać.",
        },
        OpisAnomalii {
            etykieta: "Dowiązania odtworzone",
            wyjasnienie: "Liczba dowiązań symbolicznych (symlink) odtworzonych w Złotej Kopii przez wywołanie symlink(2) na docelowej ścieżce, zamiast kopiowania treści pliku.",
        },
        OpisAnomalii {
            etykieta: "Użyto wersji naprawionej — UFS",
            wyjasnienie: "Ile razy zwycięska strona miała wersję fizycznie zrekonstruowaną przez Fazę 17 (repaired_path_ufs/repaired_path_script) — w takim przypadku kopiowana jest TA naprawiona wersja, nie uszkodzony oryginał, a weryfikacja rozmiaru po kopiowaniu jest celowo pomijana (naprawiony plik z definicji ma inny rozmiar niż uszkodzony oryginał).",
        },
        OpisAnomalii {
            etykieta: "Przemianowane (kolizja nazw)",
            wyjasnienie: "Plik zapisany pod ZMIENIONĄ nazwą (dopisek _[UFS]/_[SKRYPT]/_[ZLOZONY], a przy kolejnych kolizjach tej samej pary _v2, _v3...), bo w katalogu docelowym istniał już inny plik o tej samej nazwie względnej. Typowo skutek wcześniejszych anomalii w danych źródłowych.",
        },
        OpisAnomalii {
            etykieta: "Błędy I/O",
            wyjasnienie: "Fizyczne kopiowanie/odtworzenie dowiązania się nie powiodło: nieudany odczyt źródła, zapis do pliku tymczasowego, albo atomowe zatwierdzenie pod nazwą docelową (hard_link). Plik NIE trafił do Złotej Kopii.",
        },
        OpisAnomalii {
            etykieta: "Błędy weryfikacji rozmiaru",
            wyjasnienie: "Kopiowanie źródła do pliku tymczasowego zakończyło się sukcesem, ale rozmiar wyniku NIE zgadza się z oczekiwanym rozmiarem z bazy danych — inny rodzaj problemu niż zwykły błąd I/O: tu dane fizycznie się skopiowały, ale nie te, których oczekiwano (możliwy wyścig ze zmianą pliku źródłowego w międzyczasie, albo nieaktualny rozmiar w bazie). Plik NIE trafia do Złotej Kopii pod finalną nazwą.",
        },
        OpisAnomalii {
            etykieta: "Błędy metadanych",
            wyjasnienie: "Sam plik został skopiowany poprawnie, ale przywrócenie czasu modyfikacji, uprawnień (chmod) albo właściciela (chown) się nie powiodło — typowo brak uprawnień roota do zmiany właściciela. Mniej krytyczna kategoria: treść pliku jest bezpieczna, tylko metadane mogą się różnić od oryginału.",
        },
        OpisAnomalii {
            etykieta: "Top powody decyzji",
            wyjasnienie: "Najczęściej występujące uzasadnienia zwrócone przez decide_winner (np. \"Wybrano UFS (Większy rozmiar pliku)\"), posortowane od najliczniejszego, z liczbą wystąpień — pozwala ocenić, który czynnik najczęściej rozstrzygał o wyborze zwycięskiej kopii w tym przebiegu.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dziewiec_wpisow_z_unikalnymi_etykietami() {
        let lista = opisy();
        assert_eq!(lista.len(), 9, "panel Fazy 9 ma dokładnie 9 etykiet wymagających wyjaśnienia (bez generycznych)");

        let mut etykiety: Vec<&str> = lista.iter().map(|o| o.etykieta).collect();
        etykiety.sort_unstable();
        etykiety.dedup();
        assert_eq!(etykiety.len(), 9, "etykiety muszą być unikalne, inaczej znajdz_opis znajdzie losowo pierwszą pasującą");
    }

    #[test]
    fn test_zadne_wyjasnienie_nie_jest_puste() {
        for o in opisy() {
            assert!(!o.wyjasnienie.trim().is_empty(), "etykieta \"{}\" nie ma treści wyjaśnienia", o.etykieta);
        }
    }

    /// Etykiety MUSZĄ być bajt-w-bajt zgodne z tym, co faktycznie wysyła
    /// `phase9.rs::build_summary_block` — inaczej `znajdz_opis` nigdy nie
    /// znajdzie dopasowania dla prawdziwego wiersza panelu.
    #[test]
    fn test_etykiety_zgadzaja_sie_z_formatem_wysylanym_przez_faze_9() {
        let oczekiwane = [
            "Wspólne — UFS", "Unikalne skopiowane — UFS", "Dowiązania odtworzone",
            "Użyto wersji naprawionej — UFS", "Przemianowane (kolizja nazw)",
            "Błędy I/O", "Błędy weryfikacji rozmiaru", "Błędy metadanych", "Top powody decyzji",
        ];
        let lista = opisy();
        for e in oczekiwane {
            assert!(lista.iter().any(|o| o.etykieta == e), "brak opisu dla realnej etykiety Fazy 9: \"{}\"", e);
        }
    }
}
