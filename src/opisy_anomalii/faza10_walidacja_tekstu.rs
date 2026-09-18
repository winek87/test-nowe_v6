// src/opisy_anomalii/faza10_walidacja_tekstu.rs

//! Wyjaśnienia etykiet z panelu bocznego Fazy 10 —
//! `phases::phase10::build_source_block`. Treść jest bezpośrednim opisem
//! REALNYCH kryteriów z `analyze_text_file` — nie ma tu niczego zgadywanego.
//! Jeśli progi/kryteria się zmienią, ten plik musi zostać zaktualizowany
//! razem z nimi.
//!
//! Pominięte celowo (generyczne, nie wymagają wyjaśnienia — ten sam wybór co
//! w `faza3_anomalie_klastra.rs`): "Prędkość", "Top format",
//! "Wątki analizy (Wariant A)", "Błędy I/O".

use super::OpisAnomalii;

pub fn opisy() -> Vec<OpisAnomalii> {
    vec![
        OpisAnomalii {
            etykieta: "Architektura EOL",
            wyjasnienie: "Metoda 1: pełny rozkład znaczników końca linii wśród POPRAWNYCH plików tekstowych. \"CRLF (Windows)\" = tyle samo \\r co \\n; \"LF (Unix)\" = same \\n bez \\r; \"Mieszane (CRLF+LF)\" = oba obecne w nierównej liczbie (może sugerować sklejenie fragmentów z dwóch różnych źródeł); \"Mieszane/Inne\" = brak \\n w ogóle (plik bardzo krótki albo bez podziału na linie).",
        },
        OpisAnomalii {
            etykieta: "Kodowanie",
            wyjasnienie: "Metoda 2: pełny rozkład wykrytego kodowania znaków wśród POPRAWNYCH plików. Wykrywane przez BOM (\"UTF-16\", \"UTF-8 (BOM)\") albo walidację treści: poprawny UTF-8 z samych bajtów <128 → \"ASCII\"; poprawny UTF-8 z bajtami ≥128 → \"UTF-8\"; niepoprawny UTF-8 z niewielkim odsetkiem znaków kontrolnych → \"Lokalne (Win-1250/ISO)\" (prawdopodobnie stara strona kodowa, nie uszkodzenie).",
        },
        OpisAnomalii {
            etykieta: "Zupa binarna",
            wyjasnienie: "Plik rzekomo tekstowy (po rozszerzeniu), który w rzeczywistości okazał się uszkodzonym lub błędnie rozpoznanym plikiem binarnym — typowo carver pomylił ucięty plik binarny (.dll, .exe) z tekstem. Zawiera twardy bajt NULL, ponad 5% znaków kontrolnych, albo nieprawidłowe jednostki UTF-16 pod podrobionym BOM — patrz \"Powody zupy binarnej\" dla rozbicia po konkretnej przyczynie.",
        },
        OpisAnomalii {
            etykieta: "Powody zupy binarnej",
            wyjasnienie: "Rozbicie kategorii \"Zupa binarna\" po DOKŁADNEJ przyczynie odrzucenia: \"Twardy Bajt NULL\" (obecność bajtu 0x00 — ślad slack space albo fałszywego odzysku), \"Zupa Binarna (>5% znaków kontrolnych)\" (niepoprawny UTF-8 ze zbyt dużym udziałem bajtów kontrolnych), albo \"Zupa Binarna (nieprawidłowe jednostki UTF-16 pod podrobionym BOM)\" (2 bajty BOM na starcie pliku podrobione, żeby przemycić dowolny binarny payload jako rzekomy UTF-16). Pozwala ocenić, która metoda detekcji dominuje w korpusie.",
        },
        OpisAnomalii {
            etykieta: "Blisko progu zupy binarnej (4-6% kontrolnych)",
            wyjasnienie: "Plik NIE odrzucony, ale z odsetkiem znaków kontrolnych w paśmie 4-6% wokół progu odrzucenia (>5%) — o włos od przeciwnej klasyfikacji. Graniczny przypadek wart ręcznej weryfikacji: niewielka różnica w treści zdecydowałaby o zupełnie innym werdykcie.",
        },
        OpisAnomalii {
            etykieta: "One-Liner (>10KB)",
            wyjasnienie: "Metoda 3: plik większy niż 10 KB, który w pierwszych 64 KB nie zawiera ani jednego znaku nowej linii (\\n). Typowy ślad kodu zminifikowanego albo payloadu zakodowanego w Base64 (np. ukryty złośliwy skrypt) — wart ręcznej inspekcji.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_szesc_wpisow_z_unikalnymi_etykietami() {
        let lista = opisy();
        assert_eq!(lista.len(), 6, "panel Fazy 10 ma dokładnie 6 etykiet wymagających wyjaśnienia (bez generycznych)");

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
    /// `phase10.rs::build_source_block` — inaczej `znajdz_opis` nigdy nie
    /// znajdzie dopasowania dla prawdziwego wiersza panelu.
    #[test]
    fn test_etykiety_zgadzaja_sie_z_formatem_wysylanym_przez_faze_10() {
        let oczekiwane = [
            "Architektura EOL", "Kodowanie", "Zupa binarna", "Powody zupy binarnej",
            "Blisko progu zupy binarnej (4-6% kontrolnych)", "One-Liner (>10KB)",
        ];
        let lista = opisy();
        for e in oczekiwane {
            assert!(lista.iter().any(|o| o.etykieta == e), "brak opisu dla realnej etykiety Fazy 10: \"{}\"", e);
        }
    }
}
