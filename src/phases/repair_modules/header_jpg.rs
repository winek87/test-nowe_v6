// src/phases/repair_modules/header_jpg.rs

//! Moduł naprawczy: wstrzykiwanie utraconego nagłówka JPEG (SOI/JFIF).

use super::{RepairContext, RepairModule};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub struct HeaderJpgModule;

impl RepairModule for HeaderJpgModule {
    fn id(&self) -> &'static str { "header_jpg" }
    fn display_name(&self) -> &'static str { "Nagłówek JPG (wstrzyknięcie SOI/JFIF)" }

    /// Stosuje się do plików `.jpg`/`.jpeg`, dla których Faza 12 zgłosiła
    /// powód zawierający `"Nagłówek"` (zniszczony nagłówek obrazu).
    fn applies_to(&self, ctx: &RepairContext) -> bool {
        (ctx.ext == "jpg" || ctx.ext == "jpeg")
            && ctx.media_reason.is_some_and(|r| r.contains("Nagłówek"))
    }

    /// Jeśli plik NIE zaczyna się od `FF D8` (Start Of Image), doklejany jest
    /// z przodu standardowy, minimalny nagłówek JFIF przed oryginalną
    /// zawartością. Zwraca `None`, gdy nagłówek już był poprawny (nic do
    /// naprawienia tą metodą — orkiestrator spróbuje kolejnego modułu).
    fn repair(&self, source: &Path, _ctx: &RepairContext, _twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let mut file = File::open(source).ok()?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).ok()?;

        if buffer.starts_with(&[0xFF, 0xD8]) {
            return None;
        }

        let mut fixed_buffer = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x01, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00];
        fixed_buffer.extend_from_slice(&buffer);

        let stem = source.file_stem()?.to_str()?;
        let target = katalog_wyjsciowy.join(format!("{}_repaired.jpg", stem));

        let mut out_file = File::create(&target).ok()?;
        out_file.write_all(&fixed_buffer).ok()?;

        Some((target, "Wstrzyknięto utracony nagłówek Magic Bytes (SOI/JFIF).".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dummy_ctx() -> RepairContext<'static> {
        RepairContext { ext: "jpg", media_reason: None, utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None }
    }

    #[test]
    fn test_applies_to_jpg_with_header_reason() {
        let m = HeaderJpgModule;
        let ctx = RepairContext { ext: "jpg", media_reason: Some("Zniszczony Nagłówek (Brak Wymiarów X/Y)"), utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        assert!(m.applies_to(&ctx));
    }

    #[test]
    fn test_does_not_apply_to_png() {
        let m = HeaderJpgModule;
        let ctx = RepairContext { ext: "png", media_reason: Some("Zniszczony Nagłówek"), utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        assert!(!m.applies_to(&ctx));
    }

    #[test]
    fn test_does_not_apply_without_header_reason() {
        let m = HeaderJpgModule;
        let ctx = RepairContext { ext: "jpg", media_reason: Some("Fałszywe rozszerzenie"), utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        assert!(!m.applies_to(&ctx));
    }

    #[test]
    fn test_repair_injects_header_when_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("uszkodzony.jpg");
        std::fs::write(&path, b"to nie jest prawdziwy naglowek jpg").unwrap();

        let m = HeaderJpgModule;
        let (target, log) = m.repair(&path, &dummy_ctx(), None, dir.path()).expect("naprawa powinna się powieść");
        let content = std::fs::read(&target).unwrap();
        assert!(content.starts_with(&[0xFF, 0xD8]));
        assert!(log.contains("SOI/JFIF"));
    }

    #[test]
    fn test_repair_returns_none_when_header_already_valid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("zdrowy.jpg");
        std::fs::write(&path, [0xFF, 0xD8, 0xFF, 0xE0]).unwrap();

        let m = HeaderJpgModule;
        assert!(m.repair(&path, &dummy_ctx(), None, dir.path()).is_none());
    }

    // ------------------------------------------------------------------
    // Materiał z PRAWDZIWEGO kodera
    // ------------------------------------------------------------------

    use crate::jpeg_splice::pomoce_testowe::zdrowy_jpeg;

    /// Długość segmentów SOI + APP0/JFIF, czyli tego, co moduł wstrzykuje.
    ///
    /// Koder zapisuje dokładnie tyle samo bajtów co nasz nagłówek zastępczy —
    /// różnią się jedynie polami wersji i gęstości JFIF, nieistotnymi dla
    /// dekodowania. Dzięki temu naprawa odtwarza plik o tej samej długości.
    const DLUGOSC_SOI_APP0: usize = 20;

    /// Sedno tego modułu na prawdziwym pliku: JPEG, któremu carving urwał
    /// nagłówek, musi po naprawie **dać się zdekodować**.
    ///
    /// Wcześniej testy operowały na literałach typu
    /// `b"to nie jest prawdziwy naglowek jpg"`, więc sprawdzały jedynie, czy
    /// moduł dokleja bajty — nie czy powstaje obraz.
    #[test]
    fn test_e2e_odtwarza_dekodowalny_jpeg() {
        let dir = tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = zdrowy_jpeg(96, 64);
        assert_eq!(&zdrowy[..2], &[0xFF, 0xD8], "kontrola: materiał źródłowy zaczyna się od SOI");

        // Plik po carvingu: nagłówek SOI+APP0 przepadł, reszta segmentów została.
        let bez_naglowka = &zdrowy[DLUGOSC_SOI_APP0..];
        assert!(
            image::load_from_memory(bez_naglowka).is_err(),
            "JPEG bez nagłówka nie powinien się dekodować - inaczej test nie mierzy naprawy"
        );

        let plik = dir.path().join("zdjecie.jpg");
        std::fs::write(&plik, bez_naglowka).unwrap();

        let (naprawiony, _) = HeaderJpgModule
            .repair(&plik, &dummy_ctx(), None, &wynik)
            .expect("brakujący nagłówek musi zostać wstrzyknięty");

        let odzyskany = std::fs::read(&naprawiony).unwrap();
        let obraz = image::load_from_memory(&odzyskany).expect("naprawiony JPEG musi się dekodować");
        assert_eq!((obraz.width(), obraz.height()), (96, 64), "wymiary muszą zostać odtworzone");

        assert_eq!(
            odzyskany.len(), zdrowy.len(),
            "wstrzyknięty nagłówek ma tę samą długość co utracony"
        );
    }

    #[test]
    fn test_naprawiony_jpeg_przechodzi_weryfikacje_z_mocna_gwarancja() {
        let dir = tempdir().unwrap();
        let wynik = dir.path().join("w");
        std::fs::create_dir_all(&wynik).unwrap();

        let plik = dir.path().join("zdjecie.jpg");
        std::fs::write(&plik, &zdrowy_jpeg(48, 32)[DLUGOSC_SOI_APP0..]).unwrap();

        let (naprawiony, _) = HeaderJpgModule.repair(&plik, &dummy_ctx(), None, &wynik).unwrap();

        let ocena = HeaderJpgModule
            .verify(&naprawiony, &dummy_ctx())
            .expect("naprawiony obraz musi przejść weryfikację");
        assert!(ocena.contains("MOCNA"), "dekodowanie pikseli daje gwarancję MOCNĄ: {}", ocena);
    }
}
