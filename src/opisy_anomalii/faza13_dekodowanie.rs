// src/opisy_anomalii/faza13_dekodowanie.rs

//! Wyjaśnienia etykiet z panelu bocznego Fazy 13 —
//! `phases::phase13::build_source_block`. Treść jest bezpośrednim opisem
//! REALNYCH kryteriów z `analyze_image`/`classify_color_bucket` — nie ma tu
//! niczego zgadywanego.
//!
//! Pominięte celowo (generyczne, ten sam wybór co w innych modułach tego
//! katalogu): "Prędkość", "Top format", "Wątki dekodowania (Wariant A)",
//! "Błędy I/O".

use super::OpisAnomalii;

pub fn opisy() -> Vec<OpisAnomalii> {
    vec![
        OpisAnomalii {
            etykieta: "Zdrowe",
            wyjasnienie: "Plik przeszedł pełne dekodowanie do bufora pikseli w RAM bez błędu — dla jpg/png/webp/bmp/tif/gif przez crate `image`, dla .dng przez `rawloader`, dla .heic/.heif/.avif przez `libheif`. \"Wspólne\" = plik obecny po obu stronach (UFS i Skrypt), \"unikalne\" = tylko po tej stronie.",
        },
        OpisAnomalii {
            etykieta: "Śr. megapikseli (zdrowe)",
            wyjasnienie: "Łączna liczba wyrenderowanych megapikseli podzielona przez liczbę ZDROWYCH plików tej strony (0.00 MP, gdy jeszcze żaden plik nie przeszedł analizy). Szybki ogląd, czy korpus to głównie miniatury czy pełne zdjęcia, bez liczenia w głowie z trzech kubełków rozdzielczości.",
        },
        OpisAnomalii {
            etykieta: "Przestrzenie kolorów",
            wyjasnienie: "Rozkład ZDROWYCH plików po przestrzeni kolorów zwróconej przez dekoder: RGB/RGBA/Grayscale (crate `image`), RAW (\"RAW Bayer\" z `rawloader` dla .dng), HEIC (z/bez kanału alfy, z `libheif`), Inne (rzadkie typy jak CMYK, albo DNG o nietypowej liczbie składowych). REGRESJA naprawiona: wcześniej RAW i HEIC wpadały błędnie do kubełka Grayscale przez gałąź domyślną, myląc realny rozkład formatów w korpusie.",
        },
        OpisAnomalii {
            etykieta: "Zepsute piksele",
            wyjasnienie: "Gray Banding / ucięty obraz: plik ma poprawny nagłówek, ale dekoder natrafił w środku na zanieczyszczone/niekompletne dane. Kategoria domyślna klasyfikacji błędu — obejmuje wszystkie komunikaty dekodera niepasujące do \"Bomba pikselowa\" ani \"Fałszywe rozszerzenie\".",
        },
        OpisAnomalii {
            etykieta: "Fałszywe rozszerzenie",
            wyjasnienie: "Komunikat błędu dekodera zawiera \"unsupported\"/\"format\" — treść pliku nie odpowiada żadnemu formatowi obrazu rozpoznawanemu przez dekoder mimo rozszerzenia sugerującego inaczej (nieobsługiwany format lub File Spoofing).",
        },
        OpisAnomalii {
            etykieta: "Bomba pikselowa",
            wyjasnienie: "Komunikat błędu dekodera zawiera \"limit\"/\"allocation\" — dekoder odmówił zaalokowania pamięci na wyrenderowanie klatki, bo nagłówek deklaruje absurdalnie dużą rozdzielczość (Malicious Payload / ochrona przed Denial-of-Service przez spreparowany plik).",
        },
        OpisAnomalii {
            etykieta: "Ekstremalne proporcje",
            wyjasnienie: "INFORMACYJNE, nie błąd: obraz zdekodował się poprawnie, ale stosunek dłuższego do krótszego boku przekracza 50:1 (np. 1×5000 px) — geometria bezsensowna dowodowo, typowy ślad częściowo nadpisanego lub błędnie zinterpretowanego nagłówka.",
        },
        OpisAnomalii {
            etykieta: "Zawartość jednolita (próbka)",
            wyjasnienie: "INFORMACYJNE, nie błąd: 100 równomiernie rozłożonych próbek pikseli ma IDENTYCZNĄ wartość — orientacyjny sygnał (nie potwierdzona pewność), bo próbkowanie ograniczonej siatki punktów może przeoczyć niewielki fragment innej treści. Legalny jednolity obraz (np. zeskanowana pusta kartka) jest rzadki, ale możliwy — dlatego to flaga informacyjna, nie unieważnienie. Pomijane dla .dng/.heic — te ścieżki dekodowania nie dają bufora pikseli w formacie oczekiwanym przez próbkowanie.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osiem_wpisow_z_unikalnymi_etykietami() {
        let lista = opisy();
        assert_eq!(lista.len(), 8, "panel Fazy 13 ma dokładnie 8 etykiet wymagających wyjaśnienia (bez generycznych)");

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
    /// `phase13.rs::build_source_block` — inaczej `znajdz_opis` nigdy nie
    /// znajdzie dopasowania dla prawdziwego wiersza panelu.
    #[test]
    fn test_etykiety_zgadzaja_sie_z_formatem_wysylanym_przez_faze_13() {
        let oczekiwane = [
            "Zdrowe", "Śr. megapikseli (zdrowe)", "Przestrzenie kolorów", "Zepsute piksele",
            "Fałszywe rozszerzenie", "Bomba pikselowa", "Ekstremalne proporcje", "Zawartość jednolita (próbka)",
        ];
        let lista = opisy();
        for e in oczekiwane {
            assert!(lista.iter().any(|o| o.etykieta == e), "brak opisu dla realnej etykiety Fazy 13: \"{}\"", e);
        }
    }
}
