// src/opisy_anomalii/faza14_hashowanie.rs

//! Wyjaśnienia etykiet z DWÓCH paneli bocznych Fazy 14 —
//! `phases::phase14::build_source_block` (Etap 1: hashowanie CTPH, panel PER
//! ŹRÓDŁO) i `phases::phase14::build_correlation_block` (Etap 4: korelacja
//! krzyżowa, panel WSPÓLNY, bez podziału UFS/Skrypt — patrz dokumentacja
//! `CorrelationStats`). Treść jest bezpośrednim opisem REALNYCH kryteriów z
//! `process_side_stream`/`classify_common_match_score`/`classify_unique_match_score`
//! — nie ma tu niczego zgadywanego.
//!
//! Pominięte celowo (generyczne, ten sam wybór co w innych modułach tego
//! katalogu): "Prędkość", "Top formaty", "Wątki CTPH (Wariant A)",
//! "Błędy I/O".
//!
//! UWAGA NAZEWNICTWA: etykieta "Zlepki Binarne" to nazwa wyświetlana
//! WYŁĄCZNIE w UI/Dzienniku/panelu — wewnętrzna wartość zapisywana w bazie
//! (`phase14_analysis.match_type`) pozostaje `"FRANKENSTEIN"` (patrz
//! `classify_common_match_score`), a plik operacyjny wciąż nosi nazwę
//! `raport_operacyjny_faza14_frankensteiny.txt` — oba celowo niezmienione,
//! dla łatwego wyszukania po starej nazwie.

use super::OpisAnomalii;

pub fn opisy() -> Vec<OpisAnomalii> {
    vec![
        // --- Etap 1: hashowanie CTPH (panel per źródło) ---
        OpisAnomalii {
            etykieta: "Sygnatury CTPH obliczone",
            wyjasnienie: "Liczba plików tej strony, dla których udało się policzyć sygnaturę rozmytego hashowania (ssdeep/CTPH) — przez `mmap` (Zero-Copy) albo, gdy `mmap` zawiedzie, przez wolniejszy fallback `fs::read_to_end`. To baza dla Etapu 4 (korelacja krzyżowa): tylko pliki z policzoną sygnaturą biorą w niej udział.",
        },
        OpisAnomalii {
            etykieta: "Puste (0 B)",
            wyjasnienie: "Plik dosłownie pusty (0 bajtów) — nie ma czego hashować, ssdeep nie jest nawet wywoływany. Osobna kategoria od \"Zbyt małe dla CTPH\": inna przyczyna dowodowa (0 B to typowo ślad wydmuszki/placeholdera, nie fragment danych za mały dla rolling hash).",
        },
        OpisAnomalii {
            etykieta: "Zbyt małe dla CTPH (niepuste)",
            wyjasnienie: "Plik ma treść (rozmiar > 0 B), ale ssdeep i tak odrzucił go jako zbyt mały dla sensownego rozmytego hashowania — algorytm CTPH potrzebuje minimalnej ilości danych, żeby rolling hash miał sens statystyczny.",
        },
        OpisAnomalii {
            etykieta: "Pominięte (fallback RAM)",
            wyjasnienie: "Plik, dla którego `mmap` zawiódł ORAZ rozmiar przekroczył próg `config.fuzzy_hash_fallback_max_mb` — pominięty całkowicie (NIE wczytany do RAM w całości), żeby uniknąć wyczerpania pamięci na pojedynczym dużym pliku.",
        },
        OpisAnomalii {
            etykieta: "Użyto fallbacku RAM (mmap zawiódł)",
            wyjasnienie: "Plik, dla którego `mmap` zawiódł, ale zmieścił się w limicie `config.fuzzy_hash_fallback_max_mb` i został skutecznie zhashowany przez wolniejszy bufor `fs::read_to_end`. Wskaźnik kondycji warstwy I/O: częste użycie tej ścieżki (np. na systemie plików sieciowym/FUSE) sygnalizuje, że `mmap` jest tam notorycznie zawodny, nie pojedynczy incydent.",
        },
        // --- Etap 4: korelacja krzyżowa (panel wspólny, bez podziału UFS/Skrypt) ---
        OpisAnomalii {
            etykieta: "Przetworzono porównań",
            wyjasnienie: "Postęp Etapu 4: pliki wspólne (jedno porównanie UFS-wersji ze Skrypt-wersją tej samej ścieżki) plus pliki unikalne strony UFS (każdy porównywany \"każdy z każdym\" ze wszystkimi unikalnymi plikami Skryptu, złożoność O(n×m)) — to WŁAŚNIE ta druga pula zwykle dominuje czas trwania etapu.",
        },
        OpisAnomalii {
            etykieta: "Bliźniaki (≥90% dla tej samej lub innej ścieżki)",
            wyjasnienie: "Podobieństwo CTPH ≥90%: dla plików wspólnych (ta sama ścieżka) to oczekiwany, zdrowy wynik; dla plików unikalnych (różne ścieżki/nazwy) to \"zaginiony bliźniak\" — Algorytm Smart Merge kolejnej fazy potraktuje takie pary jako potencjalnie tę samą treść odzyskaną pod różnymi nazwami przez UFS i Skrypt.",
        },
        OpisAnomalii {
            etykieta: "Częściowe dopasowanie",
            wyjasnienie: "Podobieństwo pośrednie — ani pełny bliźniak, ani brak związku. Próg różni się zależnie od pary: dla plików wspólnych to każdy wynik >0% i <90%; dla plików unikalnych to wynik od progu szumu CTPH (25%) do <90% (poniżej 25% to zwykły, nieistotny szum rolling-hash, klasyfikowany jako brak dopasowania, nie anomalia). Kategoria \"PARTIAL\" jest bramką do fizycznego zszycia bajtów w Fazie 17 — błąd klasyfikacji tutaj oznacza ryzyko sklejenia dwóch niepowiązanych dowodów w jeden plik.",
        },
        OpisAnomalii {
            etykieta: "Zlepki Binarne (0%, ta sama ścieżka UFS/Skrypt)",
            wyjasnienie: "WYŁĄCZNIE dla plików wspólnych (ta sama ścieżka względna po obu stronach): 0% podobieństwa CTPH, mimo że oczekiwano wysokiego podobieństwa dla pliku o tej samej nazwie odzyskanego dwoma niezależnymi programami. Sygnalizuje, że co najmniej jedna kopia to zlepek niepowiązanych fragmentów danych spod tej samej nazwy (zniszczony przez File Carvera). Nazwa techniczna w bazie danych pozostaje 'FRANKENSTEIN' (`phase14_analysis.match_type`), plik operacyjny: raport_operacyjny_faza14_frankensteiny.txt.",
        },
        OpisAnomalii {
            etykieta: "Błędne rozszerzenia (bliźniak pod inną nazwą formatu)",
            wyjasnienie: "Wśród ODNALEZIONYCH bliźniaków plików unikalnych: rozszerzenie pliku UFS różni się od rozszerzenia jego najlepiej dopasowanego odpowiednika w Skrypcie — sygnał, że co najmniej jedna strona nadała plikowi błędne rozszerzenie podczas odzysku (File Spoofing albo pomyłka narzędzia carvującego).",
        },
        OpisAnomalii {
            etykieta: "Suma bezwzględnej różnicy wag (Δ)",
            wyjasnienie: "Suma wartości bezwzględnych różnic rozmiaru (UFS minus Skrypt, dla plików wspólnych; lub między parą bliźniaków, dla unikalnych) po wszystkich dotąd znalezionych dopasowaniach — orientacyjny wskaźnik, ile danych \"zgubiło się\" między dwoma niezależnymi próbami odzysku tej samej treści.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jedenascie_wpisow_z_unikalnymi_etykietami() {
        let lista = opisy();
        assert_eq!(lista.len(), 11, "dwa panele Fazy 14 mają łącznie dokładnie 11 etykiet wymagających wyjaśnienia (bez generycznych)");

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

    /// Etykiety MUSZĄ być bajt-w-bajt zgodne z tym, co faktycznie wysyłają
    /// `phase14.rs::build_source_block`/`build_correlation_block` — inaczej
    /// `znajdz_opis` nigdy nie znajdzie dopasowania dla prawdziwego wiersza panelu.
    #[test]
    fn test_etykiety_zgadzaja_sie_z_formatem_wysylanym_przez_faze_14() {
        let oczekiwane = [
            "Sygnatury CTPH obliczone", "Puste (0 B)", "Zbyt małe dla CTPH (niepuste)",
            "Pominięte (fallback RAM)", "Użyto fallbacku RAM (mmap zawiódł)",
            "Przetworzono porównań", "Bliźniaki (≥90% dla tej samej lub innej ścieżki)",
            "Częściowe dopasowanie", "Zlepki Binarne (0%, ta sama ścieżka UFS/Skrypt)",
            "Błędne rozszerzenia (bliźniak pod inną nazwą formatu)",
            "Suma bezwzględnej różnicy wag (Δ)",
        ];
        let lista = opisy();
        for e in oczekiwane {
            assert!(lista.iter().any(|o| o.etykieta == e), "brak opisu dla realnej etykiety Fazy 14: \"{}\"", e);
        }
    }
}
