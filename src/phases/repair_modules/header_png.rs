// src/phases/repair_modules/header_png.rs

//! Moduł naprawczy (NOWY): wstrzykiwanie utraconej sygnatury PNG.
//! Analogiczny do [`super::header_jpg`], dla drugiego najpopularniejszego
//! formatu rastrowego — wcześniej naprawa nagłówków obejmowała WYŁĄCZNIE JPG.

use super::{RepairContext, RepairModule};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Standardowa 8-bajtowa sygnatura PNG (RFC 2083): pozwala odróżnić PNG od
/// tekstu i wykryć uszkodzenie transferu (np. konwersję CRLF/LF w trybie
/// tekstowym), niezależnie od treści właściwych danych obrazu.
const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

pub struct HeaderPngModule;

impl RepairModule for HeaderPngModule {
    fn id(&self) -> &'static str { "header_png" }
    fn display_name(&self) -> &'static str { "Nagłówek PNG (wstrzyknięcie sygnatury)" }

    /// Stosuje się do plików `.png`, dla których Faza 12 zgłosiła powód
    /// zawierający `"Nagłówek"`, ALBO Faza 13 nie zdołała ich zdekodować
    /// (`media_decoded == Some(false)`) — patrz `header_jpg` dla pełnego
    /// uzasadnienia tego drugiego warunku.
    fn applies_to(&self, ctx: &RepairContext) -> bool {
        ctx.ext == "png"
            && (ctx.media_reason.is_some_and(|r| r.contains("Nagłówek")) || ctx.media_decoded == Some(false))
    }

    /// Jeśli plik nie zaczyna się od standardowej sygnatury PNG, doklejana
    /// jest ona z przodu oryginalnej zawartości. Zwraca `None`, gdy sygnatura
    /// już była poprawna.
    fn repair(&self, source: &Path, _ctx: &RepairContext, _twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let mut file = File::open(source).ok()?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).ok()?;

        if buffer.starts_with(&PNG_SIGNATURE) {
            return None;
        }

        let mut fixed_buffer = PNG_SIGNATURE.to_vec();
        fixed_buffer.extend_from_slice(&buffer);

        let stem = source.file_stem()?.to_str()?;
        let target = katalog_wyjsciowy.join(format!("{}_repaired.png", stem));

        let mut out_file = File::create(&target).ok()?;
        out_file.write_all(&fixed_buffer).ok()?;

        Some((target, "Wstrzyknięto utraconą sygnaturę PNG (89 50 4E 47 0D 0A 1A 0A).".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dummy_ctx() -> RepairContext<'static> {
        RepairContext { ext: "png", media_reason: None, utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None, media_decoded: None }
    }

    #[test]
    fn test_applies_to_png_with_header_reason() {
        let m = HeaderPngModule;
        let ctx = RepairContext { ext: "png", media_reason: Some("Zniszczony Nagłówek (Brak Wymiarów X/Y)"), utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None, media_decoded: None };
        assert!(m.applies_to(&ctx));
    }

    #[test]
    fn test_does_not_apply_to_jpg() {
        let m = HeaderPngModule;
        let ctx = RepairContext { ext: "jpg", media_reason: Some("Zniszczony Nagłówek"), utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None, media_decoded: None };
        assert!(!m.applies_to(&ctx));
    }

    /// Patrz analogiczny test w `header_jpg.rs` — ten sam silniejszy sygnał
    /// z Fazy 13, niezależny od powodu z Fazy 12.
    #[test]
    fn test_applies_to_png_gdy_faza13_nie_zdekodowala() {
        let m = HeaderPngModule;
        let ctx = RepairContext { ext: "png", media_reason: None, utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None, video_ok: None, structure_ok: None, media_decoded: Some(false) };
        assert!(m.applies_to(&ctx));
    }

    #[test]
    fn test_repair_injects_signature_when_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("uszkodzony.png");
        std::fs::write(&path, b"dane obrazu bez sygnatury").unwrap();

        let m = HeaderPngModule;
        let (target, log) = m.repair(&path, &dummy_ctx(), None, dir.path()).expect("naprawa powinna się powieść");
        let content = std::fs::read(&target).unwrap();
        assert!(content.starts_with(&PNG_SIGNATURE));
        assert!(log.contains("PNG"));
    }

    #[test]
    fn test_repair_returns_none_when_signature_already_valid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("zdrowy.png");
        let mut content = PNG_SIGNATURE.to_vec();
        content.extend_from_slice(b"reszta danych");
        std::fs::write(&path, &content).unwrap();

        let m = HeaderPngModule;
        assert!(m.repair(&path, &dummy_ctx(), None, dir.path()).is_none());
    }

    // ------------------------------------------------------------------
    // Materiał z PRAWDZIWEGO kodera
    // ------------------------------------------------------------------

    use crate::png_repair::pomoce_testowe::zdrowy_png;

    /// Sedno tego modułu na prawdziwym pliku: PNG, któremu carving urwał
    /// 8-bajtową sygnaturę, musi po naprawie **dać się zdekodować**.
    ///
    /// Wcześniej żaden test tego nie sprawdzał — wszystkie operowały na
    /// literałach w rodzaju `b"dane obrazu bez sygnatury"`, więc potwierdzały
    /// tylko, że moduł dokleja osiem bajtów, a nie że produkuje obraz.
    #[test]
    fn test_e2e_odtwarza_dekodowalny_png() {
        let dir = tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = zdrowy_png(64, 48);
        let bez_sygnatury = &zdrowy[PNG_SIGNATURE.len()..];

        // Kontrola sensu testu: bez sygnatury plik NIE MOŻE się dekodować.
        assert!(
            image::load_from_memory(bez_sygnatury).is_err(),
            "PNG bez sygnatury nie powinien się dekodować - inaczej test nie mierzy naprawy"
        );

        let plik = dir.path().join("obraz.png");
        std::fs::write(&plik, bez_sygnatury).unwrap();

        let (naprawiony, _) = HeaderPngModule
            .repair(&plik, &dummy_ctx(), None, &wynik)
            .expect("brakująca sygnatura musi zostać wstrzyknięta");

        let odzyskany = std::fs::read(&naprawiony).unwrap();
        assert_eq!(odzyskany, zdrowy, "utrata samej sygnatury jest w pełni odwracalna");

        let obraz = image::load_from_memory(&odzyskany).expect("naprawiony PNG musi się dekodować");
        assert_eq!((obraz.width(), obraz.height()), (64, 48), "wymiary muszą zostać odtworzone");
    }

    /// Weryfikacja wyniku musi orzec gwarancję MOCNĄ — dla PNG-a osiąga ją
    /// realnym dekodowaniem pikseli.
    #[test]
    fn test_naprawiony_png_przechodzi_weryfikacje_z_mocna_gwarancja() {
        let dir = tempdir().unwrap();
        let wynik = dir.path().join("w");
        std::fs::create_dir_all(&wynik).unwrap();

        let plik = dir.path().join("obraz.png");
        std::fs::write(&plik, &zdrowy_png(32, 32)[PNG_SIGNATURE.len()..]).unwrap();

        let (naprawiony, _) = HeaderPngModule.repair(&plik, &dummy_ctx(), None, &wynik).unwrap();

        let ocena = HeaderPngModule
            .verify(&naprawiony, &dummy_ctx())
            .expect("naprawiony obraz musi przejść weryfikację");
        assert!(ocena.contains("MOCNA"), "dekodowanie pikseli daje gwarancję MOCNĄ: {}", ocena);
    }
}
