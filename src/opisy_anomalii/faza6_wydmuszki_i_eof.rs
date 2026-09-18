// src/opisy_anomalii/faza6_wydmuszki_i_eof.rs

//! Wyjaśnienia etykiet z panelu bocznego Fazy 6 —
//! `phases::phase6::build_source_block`. Treść jest bezpośrednim opisem
//! REALNYCH kryteriów wykrywania z `phase6.rs` (funkcje `analyze_file` i
//! `process_side_stream`) — nie ma tu niczego zgadywanego. Jeśli progi albo
//! kryteria detekcji się zmienią, ten plik musi zostać zaktualizowany razem
//! z nimi.
//!
//! Pominięte celowo (generyczne, nie wymagają wyjaśnienia — ten sam wybór co
//! w `faza3_anomalie_klastra.rs` dla "Top format"/"Prędkość"/"Błędy I/O"):
//! "Prędkość", "Top format", "Wątki analizy (Wariant A)", "Błędy I/O".

use super::OpisAnomalii;

pub fn opisy() -> Vec<OpisAnomalii> {
    vec![
        OpisAnomalii {
            etykieta: "Wydmuszki HDD (zera)",
            wyjasnienie: "Ponad 99% bajtów CAŁEGO pliku to zera (0x00). Typowy ślad sektora wyzerowanego po skasowaniu/nadpisaniu na dysku talerzowym (HDD) — treść pliku fizycznie już nie istnieje na nośniku.",
        },
        OpisAnomalii {
            etykieta: "Wydmuszki SSD (TRIM/0xFF)",
            wyjasnienie: "Ponad 99% bajtów CAŁEGO pliku to 0xFF. Typowy ślad polecenia TRIM na dysku SSD — kontroler oznaczył blok jako pusty i zwraca same jedynki zamiast realnych danych, które już zniknęły.",
        },
        OpisAnomalii {
            etykieta: "Częściowa wydmuszka (50-99%)",
            wyjasnienie: "Plik ma od 50% do 99% bajtów równych 0x00 ALBO 0xFF — poniżej progu pełnej wydmuszki, ale wciąż silny sygnał częściowego skasowania/nadpisania: tylko FRAGMENT pliku fizycznie zniknął z nośnika, nie cała treść.",
        },
        OpisAnomalii {
            etykieta: "Puste pliki (0 B)",
            wyjasnienie: "Plik ma zerowy rozmiar — INNY przypadek niż wydmuszka: tu nigdy nic nie zostało fizycznie zapisane (np. sam wpis katalogowy przetrwał, dane nie), a nie realna treść później nadpisana/wyzerowana.",
        },
        OpisAnomalii {
            etykieta: "Ucięte EOF",
            wyjasnienie: "Plik NIE ma zerowego rozmiaru, ale brakuje mu poprawnego znacznika końca dla jego formatu (JPG: bajty FF D9 na końcu; PDF: %%EOF ORAZ wiarygodny xref wskazywany przez startxref; PNG: chunk IEND; ZIP-podobne: sygnatura EOCD) — realna treść pliku urwała się przed naturalnym końcem.",
        },
        OpisAnomalii {
            etykieta: "Top formaty uciętego EOF",
            wyjasnienie: "Rozszerzenia plików z uciętym znacznikiem EOF, posortowane od najczęstszego, z liczbą wystąpień. Pozwala ocenić, czy uszkodzenie koncentruje się w jednym konkretnym formacie (np. same PDF-y) czy jest rozproszone po całym korpusie.",
        },
        OpisAnomalii {
            etykieta: "Średni % zer w próbce",
            wyjasnienie: "Średni procent bajtów 0x00 policzony ze WSZYSTKICH poprawnie przeanalizowanych plików tej strony (nie tylko tych sklasyfikowanych jako wydmuszka) — ogólny wskaźnik \"jak bardzo zaszumiony zerami\" jest cały nośnik, niezależny od pojedynczych ekstremalnych przypadków.",
        },
        OpisAnomalii {
            etykieta: "Średni % 0xFF w próbce",
            wyjasnienie: "Ten sam wskaźnik co \"Średni % zer w próbce\" wyżej, dla bajtów 0xFF zamiast 0x00 — ogólny poziom aktywności TRIM/SSD w całej próbce.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osiem_wpisow_z_unikalnymi_etykietami() {
        let lista = opisy();
        assert_eq!(lista.len(), 8, "panel Fazy 6 ma dokładnie 8 etykiet wymagających wyjaśnienia (bez generycznych)");

        let mut etykiety: Vec<&str> = lista.iter().map(|o| o.etykieta).collect();
        etykiety.sort_unstable();
        etykiety.dedup();
        assert_eq!(etykiety.len(), 8, "etykiety muszą być unikalne, inaczej znajdz_opis znajdzie losowo pierwszą pasującą");
    }

    #[test]
    fn test_zadne_wyjasnienie_nie_jest_puste() {
        for o in opisy() {
            assert!(!o.wyjasnienie.trim().is_empty(), "etykieta \"{}\" nie ma treści wyjaśnienia", o.etykieta);
        }
    }

    /// Etykiety MUSZĄ być bajt-w-bajt zgodne z tym, co faktycznie wysyła
    /// `phase6.rs::build_source_block` — inaczej `znajdz_opis` nigdy nie
    /// znajdzie dopasowania dla prawdziwego wiersza panelu.
    #[test]
    fn test_etykiety_zgadzaja_sie_z_formatem_wysylanym_przez_faze_6() {
        let oczekiwane = [
            "Wydmuszki HDD (zera)", "Wydmuszki SSD (TRIM/0xFF)", "Częściowa wydmuszka (50-99%)",
            "Puste pliki (0 B)", "Ucięte EOF", "Top formaty uciętego EOF",
            "Średni % zer w próbce", "Średni % 0xFF w próbce",
        ];
        let lista = opisy();
        for e in oczekiwane {
            assert!(lista.iter().any(|o| o.etykieta == e), "brak opisu dla realnej etykiety Fazy 6: \"{}\"", e);
        }
    }
}
