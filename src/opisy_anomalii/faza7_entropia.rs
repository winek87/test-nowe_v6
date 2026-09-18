// src/opisy_anomalii/faza7_entropia.rs

//! Wyjaśnienia etykiet z panelu bocznego Fazy 7 —
//! `phases::phase7::build_source_block`. Treść jest bezpośrednim opisem
//! REALNYCH progów klasyfikacji z `phase7.rs` (funkcja `klasyfikuj_entropie`
//! i stała `FORMATY_SKOMPRESOWANE`) — nie ma tu niczego zgadywanego. Jeśli
//! progi się zmienią, ten plik musi zostać zaktualizowany razem z nimi.
//!
//! Pominięte celowo (generyczne, nie wymagają wyjaśnienia — ten sam wybór co
//! w `faza3_anomalie_klastra.rs` dla "Top format"/"Prędkość"/"Błędy I/O"):
//! "Prędkość", "Top format", "Wątki entropii (Wariant A)", "Błędy I/O".

use super::OpisAnomalii;

pub fn opisy() -> Vec<OpisAnomalii> {
    vec![
        OpisAnomalii {
            etykieta: "Szum/Śmieci (H>7.99)",
            wyjasnienie: "Entropia Shannona całej zawartości pliku przekracza 7.99 bit/bajt (skala 0-8) — bliska teoretycznemu maksimum, wszystkie 256 wartości bajtu występują niemal jednakowo często. Typowy ślad białego szumu/danych losowych, nie ustrukturyzowanej zawartości żadnego znanego formatu.",
        },
        OpisAnomalii {
            etykieta: "Szyfrowanie (H>7.5)",
            wyjasnienie: "Entropia przekracza 7.5 bit/bajt dla formatu, który NIE jest z założenia skompresowany (patrz lista w dokumentacji modułu) — sugeruje szyfrowanie (np. ransomware) albo nadpisanie danymi losowymi, bo zwykła, nieskompresowana treść tego formatu nie powinna osiągać tak wysokiej losowości.",
        },
        OpisAnomalii {
            etykieta: "Zepsuta kompresja (H<6.0)",
            wyjasnienie: "Entropia spada poniżej 6.0 bit/bajt dla formatu Z ZAŁOŻENIA skompresowanego (zip/jpg/mp4/mp3 i inne z listy w dokumentacji modułu) — skompresowane dane powinny wyglądać niemal losowo, więc nienaturalnie NISKA entropia sugeruje przerwaną/uszkodzoną kompresję albo nadpisanie fragmentu pliku czytelną, ustrukturyzowaną treścią.",
        },
        OpisAnomalii {
            etykieta: "Wydmuszki (H<1.0)",
            wyjasnienie: "Entropia mieści się w przedziale 0.0-1.0 bit/bajt — plik złożony niemal wyłącznie z jednej powtarzającej się wartości bajtu (albo bardzo niewielu różnych wartości). Klasyczny ślad wyzerowanego/pustego bloku, niezależnie od deklarowanego rozszerzenia.",
        },
        OpisAnomalii {
            etykieta: "Średnia entropia w próbce",
            wyjasnienie: "Średnia entropia policzona ze WSZYSTKICH poprawnie przeanalizowanych plików tej strony (nie tylko tych sklasyfikowanych jako anomalia) — ogólny wskaźnik \"jak losowa\" jest cała próbka, niezależny od pojedynczych ekstremalnych przypadków.",
        },
        OpisAnomalii {
            etykieta: "Zakres entropii w próbce",
            wyjasnienie: "Najniższa i najwyższa entropia zaobserwowana w tej próbce. Uzupełnia średnią o informację, jak bardzo rozproszone są wyniki — ta sama średnia może kryć zarówno wąski, jednorodny rozrzut, jak i skrajnie różne pliki obok siebie.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_szesc_wpisow_z_unikalnymi_etykietami() {
        let lista = opisy();
        assert_eq!(lista.len(), 6, "panel Fazy 7 ma dokładnie 6 etykiet wymagających wyjaśnienia (bez generycznych)");

        let mut etykiety: Vec<&str> = lista.iter().map(|o| o.etykieta).collect();
        etykiety.sort_unstable();
        etykiety.dedup();
        assert_eq!(etykiety.len(), 6, "etykiety muszą być unikalne, inaczej znajdz_opis znajdzie losowo pierwszą pasującą");
    }

    #[test]
    fn test_zadne_wyjasnienie_nie_jest_puste() {
        for o in opisy() {
            assert!(!o.wyjasnienie.trim().is_empty(), "etykieta \"{}\" nie ma treści wyjaśnienia", o.etykieta);
        }
    }

    /// Etykiety MUSZĄ być bajt-w-bajt zgodne z tym, co faktycznie wysyła
    /// `phase7.rs::build_source_block` — inaczej `znajdz_opis` nigdy nie
    /// znajdzie dopasowania dla prawdziwego wiersza panelu.
    #[test]
    fn test_etykiety_zgadzaja_sie_z_formatem_wysylanym_przez_faze_7() {
        let oczekiwane = [
            "Szum/Śmieci (H>7.99)", "Szyfrowanie (H>7.5)", "Zepsuta kompresja (H<6.0)",
            "Wydmuszki (H<1.0)", "Średnia entropia w próbce", "Zakres entropii w próbce",
        ];
        let lista = opisy();
        for e in oczekiwane {
            assert!(lista.iter().any(|o| o.etykieta == e), "brak opisu dla realnej etykiety Fazy 7: \"{}\"", e);
        }
    }
}
