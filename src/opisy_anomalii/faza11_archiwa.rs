// src/opisy_anomalii/faza11_archiwa.rs

//! Wyjaśnienia etykiet z panelu bocznego Fazy 11 —
//! `phases::phase11::build_source_block`. Treść jest bezpośrednim opisem
//! REALNYCH kryteriów z `analyze_archive`/`analyze_zip_entries`/
//! `classify_compression_ratio` — nie ma tu niczego zgadywanego.
//!
//! Pominięte celowo (generyczne, ten sam wybór co w innych modułach tego
//! katalogu): "Prędkość", "Top format", "Wątki analizy (Wariant A)",
//! "Błędy I/O".

use super::OpisAnomalii;

pub fn opisy() -> Vec<OpisAnomalii> {
    vec![
        OpisAnomalii {
            etykieta: "Zdrowe",
            wyjasnienie: "Archiwum otworzyło się poprawnie i przeszło wszystkie zastosowane metody weryfikacji (EOCD/struktura, brak wydmuszki, zgodne DNA formatu, współczynnik kompresji w normie, opcjonalnie próbka CRC32). \"Wspólne\" = plik obecny po obu stronach (UFS i Skrypt), \"unikalne\" = tylko po tej stronie.",
        },
        OpisAnomalii {
            etykieta: "Uszkodzony nagłówek",
            wyjasnienie: "Dla rodziny ZIP: brak EOCD (Centralnego Katalogu) — archiwum ucięte lub zniszczone na poziomie struktury, odzyskanie plików z jego wnętrza jest niemożliwe. Dla `.tar`: uszkodzone sumy kontrolne nagłówków wpisów. Dla formatów liniowych (RAR/7Z/GZ/BZ2/XZ/skompresowany TAR): niezgodne magic bytes nagłówka. Kategoria domyślna — obejmuje też rzadkie, niedopasowane do żadnej innej kategorii powody (np. plik krótszy niż minimalny nagłówek).",
        },
        OpisAnomalii {
            etykieta: "Wydmuszki",
            wyjasnienie: "Archiwum otwiera się poprawnie strukturalnie, ale wewnątrz nie ma ani jednego pliku (ZIP: `archive.len() == 0`; TAR: brak jakiegokolwiek czytelnego wpisu).",
        },
        OpisAnomalii {
            etykieta: "Fałszywe DNA",
            wyjasnienie: "File Spoofing: rozszerzenie deklaruje jeden format OOXML/ZIP-pochodny, ale wewnątrz brakuje jego obowiązkowej sygnatury strukturalnej — folder `word/` dla .docx/.docm, `xl/` dla .xlsx/.xlsm, `AndroidManifest.xml`/`classes.dex` dla .apk, `META-INF/`/`mimetype` dla .epub. Archiwum jest strukturalnie poprawnym ZIP-em, tylko nie tym, za co się podaje.",
        },
        OpisAnomalii {
            etykieta: "Bomba (rozmiar)",
            wyjasnienie: "Zip Bomb — stosunek rozmiaru po rozpakowaniu do rozmiaru na dysku przekracza 200x ORAZ rozmiar po rozpakowaniu przekracza 1 GB (oba progi naraz, żeby uniknąć fałszywych alarmów na drobnych plikach). Poniżej tych progów, ale powyżej 50x/50MB, plik trafia tylko do \"Podejrzana kompresja\" (ostrzeżenie, nie unieważnienie).",
        },
        OpisAnomalii {
            etykieta: "Bomba (liczba plików)",
            wyjasnienie: "Bomba plikowa (technika \"42.zip\"): archiwum zawiera ponad 50 000 wpisów, niezależnie od ich rozmiaru — każdy tani do spakowania, kosztowny do wypakowania i przetworzenia po stronie systemu plików docelowego. Osobna kategoria od bomby rozmiarowej, bo to inny wektor.",
        },
        OpisAnomalii {
            etykieta: "Zaszyfrowane",
            wyjasnienie: "INFORMACYJNE, nie błąd: co najmniej jeden wpis archiwum jest zaszyfrowany hasłem. Zaszyfrowane hasłem archiwum jest często całkowicie legalne — oznacza tylko brak możliwości weryfikacji zawartości bez hasła, nie wpływa na klasyfikację \"Zdrowe\"/\"Uszkodzone\".",
        },
        OpisAnomalii {
            etykieta: "Podejrzana kompresja",
            wyjasnienie: "INFORMACYJNE, nie błąd: współczynnik kompresji przekroczył próg ostrzegawczy (>50x ORAZ >50MB po rozpakowaniu), ale nie sięgnął twardego progu \"Bomby\" (200x i 1GB). Sygnał do ręcznej weryfikacji, archiwum pozostaje ważne.",
        },
        OpisAnomalii {
            etykieta: "Błędy CRC32 (próbka)",
            wyjasnienie: "Widoczne tylko przy włączonej opcji głębokiego skanu. Struktura archiwum (EOCD, DNA) jest poprawna, ale próbkowa dekompresja PIERWSZYCH do 3 wpisów wykryła niezgodność sumy kontrolnej CRC32 — realne uszkodzenie strumienia skompresowanego. To PRÓBKA, nie pełna weryfikacja całego archiwum: wykrywa uszkodzenie w pierwszych plikach, nie gwarantuje integralności reszty.",
        },
        OpisAnomalii {
            etykieta: "Rozmiar po rozpakowaniu (zdrowe)",
            wyjasnienie: "Suma zadeklarowanego rozmiaru po rozpakowaniu (`uncompressed_size`) WYŁĄCZNIE archiwów uznanych za zdrowe tej strony — orientacyjny obraz, ile realnie danych \"chowa się\" w skorygowanym korpusie po odsianiu uszkodzonych plików.",
        },
        OpisAnomalii {
            etykieta: "Śr. współczynnik kompresji (zdrowe)",
            wyjasnienie: "Suma rozmiaru po rozpakowaniu podzielona przez sumę rozmiaru na dysku, liczona WYŁĄCZNIE po zdrowych archiwach tej strony (0.0x, gdy jeszcze żadne archiwum nie przeszło analizy). Nagły skok tej wartości w trakcie skanu sygnalizuje napotkanie archiwum o niecodziennie wysokiej kompresji, nawet jeśli pojedynczo nie przekroczyło progu \"Podejrzana kompresja\"/\"Bomba\".",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jedenascie_wpisow_z_unikalnymi_etykietami() {
        let lista = opisy();
        assert_eq!(lista.len(), 11, "panel Fazy 11 ma dokładnie 11 etykiet wymagających wyjaśnienia (bez generycznych)");

        let mut etykiety: Vec<&str> = lista.iter().map(|o| o.etykieta).collect();
        etykiety.sort_unstable();
        etykiety.dedup();
        assert_eq!(etykiety.len(), 11, "etykiety muszą być unikalne, inaczej znajdz_opis znajdzie losowo pierwszą pasującą");
    }

    #[test]
    fn test_zadne_wyjasnienie_nie_jest_puste() {
        for o in opisy() {
            assert!(!o.wyjasnienie.trim().is_empty(), "etykieta \"{}\" nie ma treści wyjaśnienia", o.etykieta);
        }
    }

    /// Etykiety MUSZĄ być bajt-w-bajt zgodne z tym, co faktycznie wysyła
    /// `phase11.rs::build_source_block` — inaczej `znajdz_opis` nigdy nie
    /// znajdzie dopasowania dla prawdziwego wiersza panelu.
    #[test]
    fn test_etykiety_zgadzaja_sie_z_formatem_wysylanym_przez_faze_11() {
        let oczekiwane = [
            "Zdrowe", "Uszkodzony nagłówek", "Wydmuszki", "Fałszywe DNA",
            "Bomba (rozmiar)", "Bomba (liczba plików)", "Zaszyfrowane", "Podejrzana kompresja",
            "Błędy CRC32 (próbka)", "Rozmiar po rozpakowaniu (zdrowe)", "Śr. współczynnik kompresji (zdrowe)",
        ];
        let lista = opisy();
        for e in oczekiwane {
            assert!(lista.iter().any(|o| o.etykieta == e), "brak opisu dla realnej etykiety Fazy 11: \"{}\"", e);
        }
    }
}
