// src/opisy_anomalii/mod.rs

//! # Rejestr Wyjaśnień Etykiet Diagnostycznych
//!
//! Panel "Aktywny Skaner — Statystyki (Live)" (`tui::scanner_panel`) pokazuje
//! zwięzłe etykiety anomalii/statystyk (np. „Przesunięty nagłówek"), których
//! znaczenie nie zawsze jest oczywiste. Ten moduł dostarcza dla nich krótkie
//! wyjaśnienia pokazywane w nakładce po naciśnięciu Enter na zaznaczonym
//! wierszu (`menu::actions::run_phase_z_opcjami`).
//!
//! Struktura mirroruje `phases::repair_modules`: każdy blok diagnostyczny
//! (np. „[Anomalie pierwszego klastra]" Fazy 3) ma WŁASNY plik z opisami
//! WŁAŚCIWYCH mu etykiet. DODANIE KOLEJNEGO BLOKU: (1) nowy plik w tym
//! katalogu eksponujący `pub fn opisy() -> Vec<OpisAnomalii>`, (2) jedna
//! linia `mod` tutaj i jedna linia w [`znajdz_opis`]. Zero zmian w
//! `scanner_panel.rs`/`menu/actions.rs` — one znają tylko [`znajdz_opis`].

mod faza3_anomalie_klastra;
mod faza5_metadane_inode;
mod faza6_wydmuszki_i_eof;
mod faza7_entropia;

/// Jedno wyjaśnienie: dokładna etykieta wiersza (musi bajt-w-bajt zgadzać
/// się z tym, co wysyła dana faza przez `PhaseEvent::UpdateSideText`) +
/// krótkie, technicznie poprawne wyjaśnienie po polsku.
pub struct OpisAnomalii {
    pub etykieta: &'static str,
    pub wyjasnienie: &'static str,
}

/// Szuka wyjaśnienia dla etykiety zaznaczonego wiersza panelu. Liniowe
/// przeszukanie kilkudziesięciu krótkich stringów na naciśnięcie klawisza —
/// nieistotne wydajnościowo, więc celowo bez `HashMap`/`OnceLock`.
pub fn znajdz_opis(etykieta: &str) -> Option<&'static str> {
    faza3_anomalie_klastra::opisy()
        .into_iter()
        .chain(faza5_metadane_inode::opisy())
        .chain(faza6_wydmuszki_i_eof::opisy())
        .chain(faza7_entropia::opisy())
        .find(|o| o.etykieta == etykieta)
        .map(|o| o.wyjasnienie)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_znajduje_opis_znanej_etykiety() {
        assert!(znajdz_opis("Null-padding").is_some());
    }

    #[test]
    fn test_nie_znajduje_opisu_nieznanej_etykiety() {
        assert_eq!(znajdz_opis("Coś, czego nie ma w żadnym module"), None);
    }

    #[test]
    fn test_wyszukiwanie_jest_dokladne_nie_czesciowe() {
        // "Przesunięty" samo w sobie nie jest pełną etykietą - dopasowanie
        // musi być całościowe, inaczej Enter na przypadkowym wierszu
        // trafiłby w niewłaściwe wyjaśnienie.
        assert_eq!(znajdz_opis("Przesunięty"), None);
        assert!(znajdz_opis("Przesunięty nagłówek").is_some());
    }
}
