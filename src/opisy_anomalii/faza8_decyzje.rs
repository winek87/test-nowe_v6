// src/opisy_anomalii/faza8_decyzje.rs

//! Wyjaśnienia etykiet z panelu bocznego Fazy 8 —
//! `phases::phase8::build_summary_block`. Treść jest bezpośrednim opisem
//! REALNEJ logiki silnika decyzyjnego `evaluate_file` — nie ma tu niczego
//! zgadywanego. Jeśli kolejność priorytetów albo kategorie się zmienią, ten
//! plik musi zostać zaktualizowany razem z nimi.
//!
//! W odróżnieniu od Faz 3/5/6/7 panel Fazy 8 NIE ma generycznych etykiet do
//! pominięcia ("Prędkość"/"Błędy I/O" itp.) — to jednoprzebiegowy silnik
//! decyzyjny czytający już gotowe dane z bazy, nie skaner I/O, więc każda
//! etykieta niesie realną informację kryminalistyczną.

use super::OpisAnomalii;

pub fn opisy() -> Vec<OpisAnomalii> {
    vec![
        OpisAnomalii {
            etykieta: "Zdrowe",
            wyjasnienie: "Plik przeszedł WSZYSTKIE sprawdzenia silnika decyzyjnego bez zastrzeżeń: albo obie kopie są bit-w-bit identyczne (zgodny hash i rozmiar), albo plik jest unikalny dla jednej strony i nie ma żadnej wykrytej anomalii.",
        },
        OpisAnomalii {
            etykieta: "Podejrzane",
            wyjasnienie: "Plik NIE został odrzucony, ale coś w nim budzi wątpliwość: skrajna entropia (biały szum albo nienaturalnie pusta pamięć) ALBO niezgodność między kopiami UFS/Skrypt (różny hash przy tym samym rozmiarze, różny rozmiar, częściowe podobieństwo fuzzy) — wymaga ręcznej weryfikacji, ale nie jest jednoznacznie bezużyteczny.",
        },
        OpisAnomalii {
            etykieta: "Odrzucone",
            wyjasnienie: "Plik nie przeszedł jednego z twardych testów strukturalnych, w kolejności priorytetu: błąd I/O na OBU stronach, wydmuszka (>99% zer), nieudany dekoding obrazu/wideo, uszkodzony kontener wideo, zły UTF-8, zła struktura kontenera (ZIP/DOCX/APK), zepsuty EXIF albo brak znacznika EOF. Pierwsze trafienie wygrywa i przerywa dalszą ocenę.",
        },
        OpisAnomalii {
            etykieta: "Naprawione (Smart Splice)",
            wyjasnienie: "Faza 18 (Smart Splice) pomyślnie złożyła ten plik z fragmentów OBU kopii jednocześnie — inny mechanizm niż pojedynczy silnik naprawczy Fazy 17. Ma priorytet nad wszystkimi anomaliami poniżej (ale nie nad YARA).",
        },
        OpisAnomalii {
            etykieta: "Naprawione (Silnik Fazy 17)",
            wyjasnienie: "Jeden z dedykowanych modułów naprawczych Fazy 17 (repair_modules) fizycznie zrekonstruował ten plik z pojedynczej uszkodzonej kopii — inny mechanizm niż Smart Splice (Faza 18), który składa OBIE kopie naraz.",
        },
        OpisAnomalii {
            etykieta: "Wirusy",
            wyjasnienie: "Plik dopasowany przez skaner sygnatur YARA (Faza 16) — priorytet ABSOLUTNY w silniku decyzyjnym, wygrywa nawet nad udaną rekonstrukcją: zrekonstruowany plik nadal może zawierać złośliwy kod.",
        },
        OpisAnomalii {
            etykieta: "Wskaźnik zaufania",
            wyjasnienie: "Procent plików sklasyfikowanych jako Zdrowe spośród wszystkich dotąd ocenionych w tym przebiegu — szybki, ogólny \"stan zdrowia\" korpusu bez liczenia w głowie z osobnych liczników.",
        },
        OpisAnomalii {
            etykieta: "Top powody odrzuceń",
            wyjasnienie: "Najczęściej występujące kategorie odrzucenia (patrz \"Odrzucone\" wyżej), posortowane od najliczniejszej, z liczbą wystąpień. Pozwala ocenić, czy uszkodzenie korpusu koncentruje się w jednej konkretnej przyczynie.",
        },
        OpisAnomalii {
            etykieta: "Top powody podejrzeń",
            wyjasnienie: "Najczęściej występujące kategorie podejrzenia (patrz \"Podejrzane\" wyżej), posortowane od najliczniejszej, z liczbą wystąpień.",
        },
        OpisAnomalii {
            etykieta: "Top reguły YARA",
            wyjasnienie: "Nazwy reguł YARA, które dopasowały najwięcej plików, posortowane od najliczniejszej — pozwala ocenić, czy wykryte zagrożenie to pojedynczy incydent, czy jedna sygnatura odpowiada za większość trafień.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dziesiec_wpisow_z_unikalnymi_etykietami() {
        let lista = opisy();
        assert_eq!(lista.len(), 10, "panel Fazy 8 ma dokładnie 10 etykiet wymagających wyjaśnienia");

        let mut etykiety: Vec<&str> = lista.iter().map(|o| o.etykieta).collect();
        etykiety.sort_unstable();
        etykiety.dedup();
        assert_eq!(etykiety.len(), 10, "etykiety muszą być unikalne, inaczej znajdz_opis znajdzie losowo pierwszą pasującą");
    }

    #[test]
    fn test_zadne_wyjasnienie_nie_jest_puste() {
        for o in opisy() {
            assert!(!o.wyjasnienie.trim().is_empty(), "etykieta \"{}\" nie ma treści wyjaśnienia", o.etykieta);
        }
    }

    /// Etykiety MUSZĄ być bajt-w-bajt zgodne z tym, co faktycznie wysyła
    /// `phase8.rs::build_summary_block` — inaczej `znajdz_opis` nigdy nie
    /// znajdzie dopasowania dla prawdziwego wiersza panelu.
    #[test]
    fn test_etykiety_zgadzaja_sie_z_formatem_wysylanym_przez_faze_8() {
        let oczekiwane = [
            "Zdrowe", "Podejrzane", "Odrzucone", "Naprawione (Smart Splice)",
            "Naprawione (Silnik Fazy 17)", "Wirusy", "Wskaźnik zaufania",
            "Top powody odrzuceń", "Top powody podejrzeń", "Top reguły YARA",
        ];
        let lista = opisy();
        for e in oczekiwane {
            assert!(lista.iter().any(|o| o.etykieta == e), "brak opisu dla realnej etykiety Fazy 8: \"{}\"", e);
        }
    }
}
