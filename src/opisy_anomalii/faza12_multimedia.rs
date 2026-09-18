// src/opisy_anomalii/faza12_multimedia.rs

//! Wyjaśnienia etykiet z panelu bocznego Fazy 12 —
//! `phases::phase12::build_source_block`. Treść jest bezpośrednim opisem
//! REALNYCH kryteriów z `evaluate_metadata`/`read_exif` — nie ma tu niczego
//! zgadywanego.
//!
//! Pominięte celowo (generyczne, ten sam wybór co w innych modułach tego
//! katalogu): "Prędkość", "Top format", "Wątki dekodowania (Wariant A)",
//! "Błędy I/O".

use super::OpisAnomalii;

pub fn opisy() -> Vec<OpisAnomalii> {
    vec![
        OpisAnomalii {
            etykieta: "Silnik aktualny",
            wyjasnienie: "Faza 12 czyta metadane dwoma silnikami: GŁÓWNYM jest biblioteka natywna exiftool-rs (w procesie, szybka), FALLBACKIEM jest zewnętrzny proces CLI systemowego exiftool, uruchamiany tylko gdy silnik natywny zawiedzie lub zwróci pustą mapę. Nazwa aktywnego silnika (ostatnio użytego) jest podświetlona na zielono, drugi na czerwono, a liczby przy RS/CLI pokazują, ile plików dotąd przeszło przez każdy z nich — częste przełączanie na CLI sygnalizuje pliki trudne do odczytania natywnie.",
        },
        OpisAnomalii {
            etykieta: "Zdrowe",
            wyjasnienie: "Plik multimedialny przeszedł wszystkie sprawdzenia unieważniające (brak błędu krytycznego ExifTool, brak ostrzeżenia o ucięciu/śmieciach, zgodny MIME z rozszerzeniem, obecne i sensowne wymiary dla plików wizualnych). \"Wspólne\" = plik obecny po obu stronach (UFS i Skrypt), \"unikalne\" = tylko po tej stronie.",
        },
        OpisAnomalii {
            etykieta: "Top urządzenia",
            wyjasnienie: "Dwa najczęściej występujące urządzenia (pola Make+Model z EXIF) wśród ZDROWYCH plików tej strony, wraz z liczbą plików. Pozwala szybko ocenić, z ilu i jakich urządzeń pochodzi korpus.",
        },
        OpisAnomalii {
            etykieta: "Ucięte",
            wyjasnienie: "ExifTool zwrócił ostrzeżenie zawierające \"truncated\"/\"corrupted\"/\"format error\" — plik stracił nagłówek definiujący rozdzielczość lub środek wideo uległ fragmentacji. Plik po uruchomieniu zawiesi odtwarzacz.",
        },
        OpisAnomalii {
            etykieta: "Brak wymiarów",
            wyjasnienie: "Plik wizualny (rodzina MIME image/video), dla którego ExifTool nie zwrócił pól ImageWidth/ImageHeight w ogóle — zniszczony nagłówek. Nie dotyczy plików audio, dla których brak wymiarów jest normalny.",
        },
        OpisAnomalii {
            etykieta: "Wymiary zerowe/1x1",
            wyjasnienie: "Plik wizualny z wymiarami TECHNICZNIE obecnymi, ale degeneracyjnymi: 0 w którymkolwiek wymiarze, albo dokładnie 1×1 piksel — typowy ślad częściowo nadpisanego nagłówka, gdzie parser odczytał śmieci jako liczby zamiast zwrócić błąd. Osobna kategoria od \"Brak wymiarów\", bo to inny symptom tego samego problemu.",
        },
        OpisAnomalii {
            etykieta: "Fałszywe MIME",
            wyjasnienie: "Rozszerzenie pliku deklaruje jeden format, ale ExifTool wykrył w środku inny MIME type — File Spoofing (np. wideo .mov zapisane jako .mp4). Dla jpg/png/mp4/mkv/mov/heic stosowana jest dokładna reguła dopasowania; dla pozostałych 20 z 26 rozszerzeń na liście — generyczny fallback: sama RODZINA MIME (image/video/audio) musi się zgadzać z rozszerzeniem.",
        },
        OpisAnomalii {
            etykieta: "Śmieci (trailer)",
            wyjasnienie: "ExifTool zwrócił ostrzeżenie zawierające \"trailer\"/\"garbage\" — na samym końcu pliku znaleziono doklejone śmieci binarne, najczęściej pochodzące z innej partycji dysku podczas procesu odzysku.",
        },
        OpisAnomalii {
            etykieta: "GPS znaleziony",
            wyjasnienie: "Liczba ZDROWYCH plików z obecnym polem GPSLatitude lub GPSPosition w metadanych — niezależnie od tego, czy współrzędne są geograficznie wiarygodne (patrz \"GPS podejrzany\" niżej).",
        },
        OpisAnomalii {
            etykieta: "GPS podejrzany",
            wyjasnienie: "INFORMACYJNE, nie błąd: GPS jest obecny, ale geograficznie niewiarygodny — współrzędne poza zakresem (szerokość poza ±90°, długość poza ±180°) LUB dokładnie (0.0, 0.0) — tzw. \"Null Island\", klasyczna wartość domyślna/uszkodzona GPS wskazująca punkt na środku Oceanu Atlantyckiego, gdzie nikt realnie nie robi zdjęć.",
        },
        OpisAnomalii {
            etykieta: "Data znaleziona",
            wyjasnienie: "Liczba ZDROWYCH plików z obecnym polem DateTimeOriginal lub CreateDate w metadanych — niezależnie od tego, czy rok jest wiarygodny (patrz kategorie \"Data nieprawdopodobna\" niżej).",
        },
        OpisAnomalii {
            etykieta: "Data nieprawdopodobna (rok-widmo)",
            wyjasnienie: "Data obecna, ale rok to jedna z typowych wartości domyślnych zegara aparatu po rozładowaniu baterii/resecie ustawień (0, 1900 lub 1904). Plik \"ma datę\", ale ta data jest bezwartościowa dowodowo — nic nie mówi o realnej manipulacji, tylko o zresetowanym zegarze.",
        },
        OpisAnomalii {
            etykieta: "Data nieprawdopodobna (przyszłość)",
            wyjasnienie: "Data obecna, ale rok jest PÓŹNIEJSZY niż bieżący — dowodowo istotniejsze niż rok-widmo: może sygnalizować manipulację metadanymi, uszkodzony zegar aparatu ustawiony błędnie w przyszłość, albo wadliwy zapis podczas odzysku.",
        },
        OpisAnomalii {
            etykieta: "Edytowane narzędziem",
            wyjasnienie: "INFORMACYJNE, nie błąd: plik nosi ślad przetworzenia narzędziem (pole Software w EXIF, np. \"Adobe Photoshop 24.0\") — nie jest surowym oryginałem prosto z aparatu.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_czternascie_wpisow_z_unikalnymi_etykietami() {
        let lista = opisy();
        assert_eq!(lista.len(), 14, "panel Fazy 12 ma dokładnie 14 etykiet wymagających wyjaśnienia (bez generycznych)");

        let mut etykiety: Vec<&str> = lista.iter().map(|o| o.etykieta).collect();
        etykiety.sort_unstable();
        etykiety.dedup();
        assert_eq!(etykiety.len(), 14, "etykiety muszą być unikalne, inaczej znajdz_opis znajdzie losowo pierwszą pasującą");
    }

    #[test]
    fn test_zadne_wyjasnienie_nie_jest_puste() {
        for o in opisy() {
            assert!(!o.wyjasnienie.trim().is_empty(), "etykieta \"{}\" nie ma treści wyjaśnienia", o.etykieta);
        }
    }

    /// Etykiety MUSZĄ być bajt-w-bajt zgodne z tym, co faktycznie wysyła
    /// `phase12.rs::build_source_block` — inaczej `znajdz_opis` nigdy nie
    /// znajdzie dopasowania dla prawdziwego wiersza panelu.
    #[test]
    fn test_etykiety_zgadzaja_sie_z_formatem_wysylanym_przez_faze_12() {
        let oczekiwane = [
            "Silnik aktualny", "Zdrowe", "Top urządzenia", "Ucięte", "Brak wymiarów",
            "Wymiary zerowe/1x1", "Fałszywe MIME", "Śmieci (trailer)", "GPS znaleziony",
            "GPS podejrzany", "Data znaleziona", "Data nieprawdopodobna (rok-widmo)",
            "Data nieprawdopodobna (przyszłość)", "Edytowane narzędziem",
        ];
        let lista = opisy();
        for e in oczekiwane {
            assert!(lista.iter().any(|o| o.etykieta == e), "brak opisu dla realnej etykiety Fazy 12: \"{}\"", e);
        }
    }
}
