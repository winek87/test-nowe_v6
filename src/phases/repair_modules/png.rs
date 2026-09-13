// src/phases/repair_modules/png.rs

//! Moduły naprawcze PNG — naprawa na poziomie fragmentów, z dawcą i bez niego.
//!
//! ## Dlaczego PNG dostaje DWA moduły, a JPEG i HEIC po jednym
//!
//! Każdy fragment PNG nosi własny CRC32, a specyfikacja dzieli fragmenty na
//! krytyczne i pomocnicze — te drugie dekoder ma prawo pominąć. Z tego wynika
//! możliwość, której nie ma żaden inny format w tym projekcie: **naprawa z
//! jednej kopii**, bez bliźniaka. Uzasadnienie podziału i granice obu
//! strategii opisuje [`crate::png_repair`].
//!
//! Stąd dwa moduły, w tej kolejności:
//!
//! 1. [`PngCloneModule`] — wybiera zdrowe fragmenty spośród dwóch kopii.
//!    Mocniejszy, bo ratuje też fragmenty krytyczne (`IHDR`, `IDAT`), ale
//!    wymaga bliźniaka.
//! 2. [`PngSanitizeModule`] — odrzuca uszkodzone fragmenty pomocnicze,
//!    dopełnia `IEND`, odcina śmieci. Słabszy zakres, zero wymagań.
//!
//! Degradacja jest łagodna: bez bliźniaka pierwszy zwraca `None`, dyspozytor
//! Fazy 17 przechodzi do drugiego, a gdy i ten odmówi — do `header_png`, który
//! potrafi wstrzyknąć samą sygnaturę. Trzy szczeble, od najpełniejszej naprawy
//! do najbardziej rozpaczliwej.
//!
//! ## Skąd się wzięła ta naprawa
//!
//! Składanie PNG po fragmentach istniało w projekcie od dawna, ale wyłącznie
//! wewnątrz Fazy 18 (Smart Splice), która kwalifikuje pliki po `match_type`.
//! Faza 17 — czyli właściwa faza naprawy — widziała dla PNG tylko
//! wstrzyknięcie sygnatury. Te moduły domykają tę lukę, korzystając z
//! istniejącego silnika zamiast pisać drugi.

use super::{RepairContext, RepairModule, WynikWeryfikacji};
use crate::png_repair;
use std::path::{Path, PathBuf};

/// Rozstrzyga, czy plik jest uszkodzonym PNG-iem.
///
/// Przesłanki uszkodzenia: powód z Fazy 12 zawierający `"Nagłówek"` albo brak
/// znacznika końca z Fazy 6. Druga jest dla PNG szczególnie trafna — `IEND`
/// jest właśnie takim znacznikiem, a jego brak to jeden z przypadków, które
/// [`PngSanitizeModule`] naprawia wprost.
fn jest_uszkodzonym_png(ctx: &RepairContext) -> bool {
    ctx.ext == "png" && (ctx.eof_ok == Some(false) || ctx.media_reason.is_some_and(|r| r.contains("Nagłówek")))
}

/// Weryfikacja przez realne dekodowanie pikseli — gwarancja MOCNA.
///
/// Wspólna dla obu modułów: wynik jest w obu przypadkach normalnym PNG-iem,
/// więc i dowód poprawności jest ten sam.
fn weryfikuj(repaired: &Path) -> WynikWeryfikacji {
    super::weryfikuj_naprawiony_plik(repaired)
}

// ============================================================================
// Wariant z dawcą
// ============================================================================

pub struct PngCloneModule;

impl RepairModule for PngCloneModule {
    fn id(&self) -> &'static str { "png_clone" }

    fn display_name(&self) -> &'static str {
        "PNG wybór zdrowych fragmentów z dwóch kopii (CRC32)"
    }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        jest_uszkodzonym_png(ctx)
    }

    /// Składa plik, biorąc każdy fragment z tej kopii, w której jego CRC32 się
    /// zgadza.
    ///
    /// Zwraca `None` bez bliźniaka oraz wtedy, gdy ten sam fragment jest
    /// uszkodzony po obu stronach — w obu przypadkach kolejny moduł na liście
    /// dostaje szansę.
    fn repair(&self, source: &Path, _ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let dawca = twin?;

        let stem = source.file_stem()?.to_str()?;
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_png.png", stem));

        match png_repair::zloz_z_dawcy(source, dawca, &cel) {
            Some(()) => Some((
                cel,
                format!(
                    "Złożono z dwóch kopii, wybierając fragmenty o zgodnym CRC32 (dawca: {}).",
                    dawca.display()
                ),
            )),
            None => {
                tracing::debug!(
                    plik = %source.display(), dawca = %dawca.display(),
                    "png_clone: brak zdrowej wersji któregoś fragmentu po obu stronach"
                );
                let _ = std::fs::remove_file(&cel);
                None
            }
        }
    }

    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        weryfikuj(repaired)
    }
}

// ============================================================================
// Wariant bez dawcy
// ============================================================================

pub struct PngSanitizeModule;

impl RepairModule for PngSanitizeModule {
    fn id(&self) -> &'static str { "png_sanitize" }

    fn display_name(&self) -> &'static str {
        "PNG odrzucenie uszkodzonych fragmentów pomocniczych (bez dawcy)"
    }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        jest_uszkodzonym_png(ctx)
    }

    /// Odrzuca uszkodzone fragmenty pomocnicze, dopełnia `IEND` i odcina
    /// śmieci za nim — wszystko operacje bezstratne dla samego obrazu.
    ///
    /// Zwraca `None`, gdy uszkodzony jest fragment krytyczny (tego z jednej
    /// kopii naprawić nie można) albo gdy nie było czego naprawiać. Ten drugi
    /// warunek jest istotny dla uczciwości liczników Fazy 17: plik już spójny
    /// nie może zostać policzony jako naprawiony.
    fn repair(&self, source: &Path, _ctx: &RepairContext, _twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let stem = source.file_stem()?.to_str()?;
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_png_sanit.png", stem));

        match png_repair::napraw_plik(source, &cel) {
            Some(raport) => Some((cel, format!("Naprawa bez dawcy: {}.", raport.opis()))),
            None => {
                tracing::debug!(
                    plik = %source.display(),
                    "png_sanitize: uszkodzenie dotyczy fragmentu krytycznego albo nie ma czego naprawiać"
                );
                let _ = std::fs::remove_file(&cel);
                None
            }
        }
    }

    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        weryfikuj(repaired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Materiał testowy pochodzi z silnika, żeby model uszkodzenia był
    // DOKŁADNIE ten sam, co w testach `png_repair`.
    use png_repair::pomoce_testowe::{wstaw_fragment, zdrowy_png, zepsuj_crc_fragmentu};

    fn ctx(ext: &'static str, eof_ok: Option<bool>, media_reason: Option<&'static str>) -> RepairContext<'static> {
        RepairContext {
            ext, media_reason, utf8_ok: None, is_oneliner: None,
            eof_ok, match_type: None, video_ok: None, structure_ok: None
        }
    }

    // ------------------------------------------------------------------
    // Kwalifikacja
    // ------------------------------------------------------------------

    #[test]
    fn test_oba_moduly_kwalifikuja_uszkodzony_png() {
        let kontekst = ctx("png", Some(false), None);
        assert!(PngCloneModule.applies_to(&kontekst));
        assert!(PngSanitizeModule.applies_to(&kontekst));
    }

    #[test]
    fn test_reaguja_na_powod_z_fazy12() {
        let kontekst = ctx("png", None, Some("Zniszczony Nagłówek obrazu"));
        assert!(PngCloneModule.applies_to(&kontekst));
        assert!(PngSanitizeModule.applies_to(&kontekst));
    }

    #[test]
    fn test_nie_ruszaja_zdrowego_png() {
        assert!(!PngCloneModule.applies_to(&ctx("png", Some(true), None)));
        assert!(!PngSanitizeModule.applies_to(&ctx("png", None, None)));
    }

    #[test]
    fn test_nie_ruszaja_innych_formatow() {
        for ext in ["jpg", "heic", "dng", "mp4", "txt"] {
            let kontekst = ctx(ext, Some(false), None);
            assert!(!PngCloneModule.applies_to(&kontekst), "ext .{}", ext);
            assert!(!PngSanitizeModule.applies_to(&kontekst), "ext .{}", ext);
        }
    }

    // ------------------------------------------------------------------
    // Kolejność w dyspozytorze - od niej zależy jakość wyniku
    // ------------------------------------------------------------------

    fn pozycja(id: &str) -> usize {
        super::super::all_modules()
            .iter()
            .position(|m| m.id() == id)
            .unwrap_or_else(|| panic!("moduł {} musi być zarejestrowany", id))
    }

    #[test]
    fn test_kolejnosc_od_najpelniejszej_naprawy() {
        let ids: Vec<&str> = super::super::all_modules().iter().map(|m| m.id()).collect();

        assert!(
            pozycja("png_clone") < pozycja("png_sanitize"),
            "naprawa z dwóch kopii ratuje też fragmenty krytyczne, więc musi być próbowana pierwsza (kolejność: {:?})", ids
        );
        assert!(
            pozycja("png_sanitize") < pozycja("header_png"),
            "naprawa po fragmentach jest pełniejsza od wstrzyknięcia samej sygnatury (kolejność: {:?})", ids
        );
        assert!(
            pozycja("png_sanitize") < pozycja("splice"),
            "bajtowe zszycie nie zna struktury PNG i nie może wyprzedzać naprawy świadomej fragmentów (kolejność: {:?})", ids
        );
    }

    // ------------------------------------------------------------------
    // Naprawa bez dawcy
    // ------------------------------------------------------------------

    #[test]
    fn test_e2e_sanitize_bez_blizniaka() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = zdrowy_png(64, 48);
        let zepsuty = wstaw_fragment(&zdrowy, b"tEXt", b"Comment\0zepsute", false);

        let plik = dir.path().join("obraz.png");
        std::fs::write(&plik, &zepsuty).unwrap();

        let kontekst = ctx("png", Some(false), None);

        // Bez dawcy wariant mocniejszy musi ustąpić.
        assert!(
            PngCloneModule.repair(&plik, &kontekst, None, &wynik).is_none(),
            "png_clone bez bliźniaka musi oddać sprawę dalej"
        );

        let (naprawiony, log) = PngSanitizeModule
            .repair(&plik, &kontekst, None, &wynik)
            .expect("naprawa bez dawcy musi się udać");

        assert!(log.contains("tEXt"), "log musi nazwać odrzucony fragment: {}", log);

        let ocena = PngSanitizeModule.verify(&naprawiony, &kontekst).expect("wynik musi przejść weryfikację");
        assert!(ocena.contains("MOCNA"), "dekodowanie pikseli daje gwarancję MOCNĄ, dostaliśmy: {}", ocena);
    }

    #[test]
    fn test_sanitize_odmawia_przy_uszkodzeniu_krytycznym() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zepsuty = zepsuj_crc_fragmentu(&zdrowy_png(32, 24), b"IDAT");
        let plik = dir.path().join("obraz.png");
        std::fs::write(&plik, &zepsuty).unwrap();

        assert!(
            PngSanitizeModule.repair(&plik, &ctx("png", Some(false), None), None, &wynik).is_none(),
            "uszkodzonego IDAT nie da się naprawić z jednej kopii"
        );

        let pozostalo: Vec<String> = std::fs::read_dir(&wynik).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(pozostalo.is_empty(), "po odmowie nie może zostać plik: {:?}", pozostalo);
    }

    #[test]
    fn test_sanitize_nie_raportuje_naprawy_zdrowego_pliku() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let plik = dir.path().join("zdrowy.png");
        std::fs::write(&plik, zdrowy_png(32, 24)).unwrap();

        assert!(
            PngSanitizeModule.repair(&plik, &ctx("png", Some(false), None), None, &wynik).is_none(),
            "plik bez uszkodzeń nie może zostać policzony jako naprawiony"
        );
    }

    // ------------------------------------------------------------------
    // Naprawa z dawcą
    // ------------------------------------------------------------------

    #[test]
    fn test_e2e_clone_ratuje_fragment_krytyczny() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = zdrowy_png(80, 60);
        // Uszkodzenia w różnych fragmentach krytycznych: żadna kopia nie
        // poradzi sobie sama, razem dają komplet.
        let strona_a = zepsuj_crc_fragmentu(&zdrowy, b"IHDR");
        let strona_b = zepsuj_crc_fragmentu(&zdrowy, b"IDAT");

        let plik = dir.path().join("obraz.png");
        let dawca = dir.path().join("blizniak.png");
        std::fs::write(&plik, &strona_a).unwrap();
        std::fs::write(&dawca, &strona_b).unwrap();

        let kontekst = ctx("png", Some(false), None);

        // Kontrola sensu testu: wariant bez dawcy MUSI tu odmówić.
        assert!(
            PngSanitizeModule.repair(&plik, &kontekst, None, &wynik).is_none(),
            "uszkodzenie krytyczne jest poza zasięgiem naprawy z jednej kopii - inaczej test nie mierzy wartości dawcy"
        );

        let (naprawiony, log) = PngCloneModule
            .repair(&plik, &kontekst, Some(&dawca), &wynik)
            .expect("złożenie z dwóch kopii musi się udać");

        assert!(log.contains("CRC32"), "log musi nazwać kryterium wyboru: {}", log);

        let ocena = PngCloneModule.verify(&naprawiony, &kontekst).expect("wynik musi przejść weryfikację");
        assert!(ocena.contains("MOCNA"), "dostaliśmy: {}", ocena);

        assert_eq!(
            std::fs::read(&naprawiony).unwrap(), zdrowy,
            "złożenie dwóch kopii tego samego pliku musi odtworzyć oryginał bajt w bajt"
        );
    }

    #[test]
    fn test_clone_odmawia_gdy_ten_sam_fragment_zepsuty_po_obu_stronach() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zepsuty = zepsuj_crc_fragmentu(&zdrowy_png(32, 24), b"IDAT");
        let plik = dir.path().join("a.png");
        let dawca = dir.path().join("b.png");
        std::fs::write(&plik, &zepsuty).unwrap();
        std::fs::write(&dawca, &zepsuty).unwrap();

        assert!(
            PngCloneModule.repair(&plik, &ctx("png", Some(false), None), Some(&dawca), &wynik).is_none(),
            "nie ma z czego wybrać - naprawa musi odmówić, a nie zapisać uszkodzony fragment"
        );

        let pozostalo: Vec<String> = std::fs::read_dir(&wynik).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(pozostalo.is_empty(), "po odmowie nie może zostać plik: {:?}", pozostalo);
    }

    #[test]
    fn test_weryfikacja_odrzuca_plik_ktory_nie_jest_obrazem() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("smieci.png");
        std::fs::write(&plik, b"to nie jest obraz").unwrap();

        let kontekst = ctx("png", Some(false), None);
        assert!(PngCloneModule.verify(&plik, &kontekst).is_err());
        assert!(PngSanitizeModule.verify(&plik, &kontekst).is_err());
    }
}
