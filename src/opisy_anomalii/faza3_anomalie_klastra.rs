// src/opisy_anomalii/faza3_anomalie_klastra.rs

//! Wyjaśnienia 10 etykiet z bloku "[Anomalie pierwszego klastra]" —
//! `phases::phase3::build_anomaly_block`. Treść jest bezpośrednim opisem
//! słownym REALNYCH kryteriów wykrywania z `phase3.rs` (funkcja analizująca
//! pierwsze 512 bajtów pliku, linie ok. 190-236 tamtego pliku) — nie ma tu
//! niczego zgadywanego. Jeśli kryteria detekcji się zmienią, ten plik musi
//! zostać zaktualizowany razem z nimi.

use super::OpisAnomalii;

pub fn opisy() -> Vec<OpisAnomalii> {
    vec![
        OpisAnomalii {
            etykieta: "Przesunięty nagłówek",
            wyjasnienie: "Rozpoznana sygnatura pliku (JPG, ZIP, PDF lub PNG) została znaleziona w pierwszym klastrze, ale NIE na samym początku (offset > 0). Sugeruje to, że przed właściwym nagłówkiem znajdują się obce dane — resztki innego pliku, śmieci po carvingu albo uszkodzony fragment dysku — a prawdziwa zawartość zaczyna się dopiero dalej.",
        },
        OpisAnomalii {
            etykieta: "Null-padding",
            wyjasnienie: "Pierwsze 4 bajty pliku to same zera (0x00 0x00 0x00 0x00). Typowy ślad \"wydmuszki\" — sektora wyzerowanego po skasowaniu/nadpisaniu, albo pliku, którego początek nigdy nie został fizycznie zapisany na nośniku.",
        },
        OpisAnomalii {
            etykieta: "Śmieci ASCII",
            wyjasnienie: "Pierwsze 4 bajty wyglądają jak zwykły tekst (litery, cyfry, znaki interpunkcyjne) zamiast binarnej sygnatury magicznej, mimo że rozszerzenie pliku (jpg/zip/mp4/png) zapowiada zawartość binarną — a nie jest to ani plik PDF (który celowo zaczyna się od tekstu \"%PDF\"), ani przypadek \"Przesunięty nagłówek\" opisany wyżej.",
        },
        OpisAnomalii {
            etykieta: "Mikro-plik <32B",
            wyjasnienie: "Plik ma mniej niż 32 bajty — stanowczo za mało danych, żeby cokolwiek sensownie przeanalizować. Klasyfikowany od razu jako anomalia, bez dalszych testów sygnatur.",
        },
        OpisAnomalii {
            etykieta: "Zła pod-sygnatura",
            wyjasnienie: "Plik zaczyna się od nagłówka kontenera \"RIFF\", ale jego czterobajtowy podtyp (bajty 8-11) to nie \"AVI \", \"WEBP\" ani \"WAVE\" — deklaruje się jako znany kontener RIFF, którego faktyczny rodzaj zawartości jest nierozpoznany albo niepoprawny.",
        },
        OpisAnomalii {
            etykieta: "Skażony slack space",
            wyjasnienie: "Plik BMP (sygnatura \"BM\"), którego zarezerwowane bajty nagłówka (offset 6-9 — z definicji formatu powinny być zerowe) zawierają niezerowe dane. Ślad \"slack space\": resztki starych danych z dysku przeciekające do pól, które teoretycznie zawsze są puste.",
        },
        OpisAnomalii {
            etykieta: "Iniekcja pasożytnicza",
            wyjasnienie: "W głębi pierwszego klastra (od 33. bajtu) znaleziono DRUGĄ sygnaturę pliku (ZIP albo EXE) osadzoną wewnątrz. Sugeruje pasożytniczo doklejony lub wstrzyknięty plik — albo świadome ukrycie danych, albo artefakt odzysku łączący fragmenty dwóch różnych plików.",
        },
        OpisAnomalii {
            etykieta: "Konflikt endian",
            wyjasnienie: "Plik zaczyna się od znacznika little-endian TIFF (\"II\"), ale kolejne bajty nie pasują do tego, czego ten format oczekuje zaraz po takim znaczniku — sprzeczność między deklarowaną a faktyczną kolejnością bajtów w nagłówku.",
        },
        OpisAnomalii {
            etykieta: "Urwana granica sektora",
            wyjasnienie: "Bajty tuż przy granicy 512-bajtowego sektora dysku (offset 508-511) to same zera albo same 0xFF. Typowy ślad ucięcia danych dokładnie na granicy fizycznego sektora — plik urwał się tam, gdzie kończy się jeden blok odczytu dysku.",
        },
        OpisAnomalii {
            etykieta: "Wysoka wolatywność",
            wyjasnienie: "Suma bezwzględnych różnic między kolejnymi bajtami pierwszego klastra przekracza ustalony próg — dane są statystycznie bardzo \"chaotyczne\", jak przy silnym szyfrowaniu albo kompresji, a nie jak przy zwykłej, ustrukturyzowanej zawartości typowego formatu pliku.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dziesiec_wpisow_z_unikalnymi_etykietami() {
        let lista = opisy();
        assert_eq!(lista.len(), 10, "blok ma dokładnie 10 kategorii anomalii w phase3.rs");

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
    /// `phase3.rs::build_anomaly_block` — inaczej `znajdz_opis` nigdy nie
    /// znajdzie dopasowania dla prawdziwego wiersza panelu.
    #[test]
    fn test_etykiety_zgadzaja_sie_z_formatem_wysylanym_przez_faze_3() {
        let oczekiwane = [
            "Przesunięty nagłówek", "Null-padding", "Śmieci ASCII", "Mikro-plik <32B",
            "Zła pod-sygnatura", "Skażony slack space", "Iniekcja pasożytnicza",
            "Konflikt endian", "Urwana granica sektora", "Wysoka wolatywność",
        ];
        let lista = opisy();
        for e in oczekiwane {
            assert!(lista.iter().any(|o| o.etykieta == e), "brak opisu dla realnej etykiety Fazy 3: \"{}\"", e);
        }
    }
}
