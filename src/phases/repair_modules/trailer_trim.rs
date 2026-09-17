// src/phases/repair_modules/trailer_trim.rs

//! Moduł naprawczy (NOWY): przycinanie doklejonych śmieci binarnych po
//! prawidłowym znaczniku końca pliku (EOF). Fazy 6 i 12 od dawna WYKRYWAJĄ
//! ten problem (`eof_ok_ufs`/`_script` = `false`, "Doklejone Śmieci Binarne
//! (Trailer Data)"), ale przed tym modułem nie istniała ŻADNA naprawa dla
//! tej konkretnej anomalii — plik z doklejonymi śmieciami trafiał od razu
//! do klasyfikacji "uszkodzony", mimo że właściwa zawartość przed śmieciami
//! mogła być w pełni odzyskiwalna przez proste obcięcie.

use super::{RepairContext, RepairModule};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Wyszukuje OSTATNIE wystąpienie znacznika EOF właściwego dla danego
/// rozszerzenia i zwraca indeks BYTE PO znaczniku (czyli długość, do jakiej
/// należy obciąć bufor). `None`, gdy znacznik nie występuje wcale (nie ma
/// czego przyciąć tą metodą) albo rozszerzenie nie jest obsługiwane.
fn find_trim_length(buffer: &[u8], ext: &str) -> Option<usize> {
    match ext {
        "jpg" | "jpeg" => {
            // Koniec obrazu JPEG: marker EOI = FF D9.
            find_last_subslice(buffer, &[0xFF, 0xD9]).map(|pos| pos + 2)
        }
        "png" => {
            // Chunk IEND (długość=0, typ="IEND", CRC stałe dla pustych danych)
            // to zawsze te same 12 bajtów kończące poprawny plik PNG.
            const IEND: [u8; 12] = [0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82];
            find_last_subslice(buffer, &IEND).map(|pos| pos + IEND.len())
        }
        "pdf" => {
            find_last_subslice(buffer, b"%%EOF").map(|pos| pos + 5)
        }
        _ => None,
    }
}

/// Wyszukuje OSTATNIE wystąpienie `needle` w `haystack`, zwraca indeks
/// początku dopasowania. Implementacja liniowa (wystarczająca dla krótkich
/// znaczników szukanych w plikach rzędu megabajtów, nie wymaga zależności
/// zewnętrznej jak w wyszukiwaniu podciągów w algorytmach typu Boyer-Moore).
fn find_last_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() { return None; }
    (0..=haystack.len() - needle.len()).rev().find(|&i| &haystack[i..i + needle.len()] == needle)
}

pub struct TrailerTrimModule;

impl RepairModule for TrailerTrimModule {
    fn id(&self) -> &'static str { "trailer_trim" }
    fn display_name(&self) -> &'static str { "Przycinanie doklejonych śmieci binarnych (JPG/PNG/PDF)" }

    /// Stosuje się do plików `.jpg`/`.jpeg`/`.png`/`.pdf`, dla których Faza 6
    /// zgłosiła `eof_ok == Some(false)` — brak lub uszkodzenie znacznika EOF
    /// (co obejmuje też przypadek doklejonych śmieci PO poprawnym znaczniku).
    fn applies_to(&self, ctx: &RepairContext) -> bool {
        ctx.eof_ok == Some(false) && matches!(ctx.ext, "jpg" | "jpeg" | "png" | "pdf")
    }

    /// Wczytuje cały plik, znajduje OSTATNIE wystąpienie właściwego
    /// znacznika EOF i zapisuje nową wersję obciętą dokładnie po nim —
    /// wszystko po tym punkcie (doklejone śmieci) zostaje odrzucone. Zwraca
    /// `None`, gdy znacznik w ogóle nie występuje (nic do przycięcia tą
    /// metodą — orkiestrator spróbuje innego modułu) lub gdy przycięcie nic
    /// by nie zmieniło (znacznik już jest na samym końcu pliku).
    fn repair(&self, source: &Path, ctx: &RepairContext, _twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let mut file = File::open(source).ok()?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).ok()?;

        let trim_len = find_trim_length(&buffer, ctx.ext)?;
        if trim_len >= buffer.len() {
            return None; // znacznik już na końcu, nic do obcięcia
        }

        let trimmed_bytes = buffer.len() - trim_len;
        buffer.truncate(trim_len);

        let stem = source.file_stem()?.to_str()?;
        let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("bin");
        let target = katalog_wyjsciowy.join(format!("{}_repaired.{}", stem, ext));

        let mut out_file = File::create(&target).ok()?;
        out_file.write_all(&buffer).ok()?;

        Some((target, format!("Przycięto {} bajtów doklejonych śmieci binarnych po znaczniku EOF.", trimmed_bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dummy_ctx(ext: &'static str, eof_ok: Option<bool>) -> RepairContext<'static> {
        RepairContext { ext, media_reason: None, utf8_ok: None, is_oneliner: None, eof_ok, match_type: None , video_ok: None, structure_ok: None, media_decoded: None }
    }

    // ------------------------------------------------------------------
    // find_last_subslice / find_trim_length
    // ------------------------------------------------------------------

    #[test]
    fn test_find_last_subslice_finds_last_not_first() {
        let hay = b"AABBAABBAA";
        let pos = find_last_subslice(hay, b"AA");
        assert_eq!(pos, Some(8));
    }

    #[test]
    fn test_find_last_subslice_none_when_absent() {
        assert_eq!(find_last_subslice(b"ABCDEF", b"XY"), None);
    }

    #[test]
    fn test_find_trim_length_jpeg_eoi() {
        let buf = [0xFF, 0xD8, 0x01, 0x02, 0xFF, 0xD9, 0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(find_trim_length(&buf, "jpg"), Some(6));
    }

    #[test]
    fn test_find_trim_length_unsupported_extension() {
        assert_eq!(find_trim_length(b"cokolwiek", "txt"), None);
    }

    // ------------------------------------------------------------------
    // applies_to
    // ------------------------------------------------------------------

    #[test]
    fn test_applies_to_bad_eof_supported_ext() {
        let m = TrailerTrimModule;
        assert!(m.applies_to(&dummy_ctx("jpg", Some(false))));
        assert!(m.applies_to(&dummy_ctx("png", Some(false))));
        assert!(m.applies_to(&dummy_ctx("pdf", Some(false))));
    }

    #[test]
    fn test_does_not_apply_when_eof_ok() {
        let m = TrailerTrimModule;
        assert!(!m.applies_to(&dummy_ctx("jpg", Some(true))));
    }

    #[test]
    fn test_does_not_apply_to_unsupported_extension() {
        let m = TrailerTrimModule;
        assert!(!m.applies_to(&dummy_ctx("docx", Some(false))));
    }

    // ------------------------------------------------------------------
    // repair
    // ------------------------------------------------------------------

    #[test]
    fn test_repair_trims_trailing_garbage_after_jpeg_eoi() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("plik.jpg");
        let mut content = vec![0xFF, 0xD8, 0x01, 0x02, 0xFF, 0xD9];
        content.extend_from_slice(b"SMIECI_Z_INNEJ_PARTYCJI");
        std::fs::write(&path, &content).unwrap();

        let m = TrailerTrimModule;
        let ctx = dummy_ctx("jpg", Some(false));
        let (target, log) = m.repair(&path, &ctx, None, dir.path()).expect("przycięcie powinno się powieść");
        let result = std::fs::read(&target).unwrap();
        assert_eq!(result, vec![0xFF, 0xD8, 0x01, 0x02, 0xFF, 0xD9]);
        assert!(log.contains("Przycięto"));
    }

    #[test]
    fn test_repair_returns_none_when_no_marker_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("plik.jpg");
        std::fs::write(&path, b"zadnego znacznika EOI tutaj nie ma").unwrap();

        let m = TrailerTrimModule;
        let ctx = dummy_ctx("jpg", Some(false));
        assert!(m.repair(&path, &ctx, None, dir.path()).is_none());
    }

    #[test]
    fn test_repair_returns_none_when_marker_already_at_end() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("plik.jpg");
        std::fs::write(&path, [0xFF, 0xD8, 0x01, 0xFF, 0xD9]).unwrap();

        let m = TrailerTrimModule;
        let ctx = dummy_ctx("jpg", Some(false));
        assert!(m.repair(&path, &ctx, None, dir.path()).is_none());
    }

    // ------------------------------------------------------------------
    // Materiał z PRAWDZIWEGO kodera
    // ------------------------------------------------------------------

    use crate::jpeg_splice::pomoce_testowe::zdrowy_jpeg;
    use crate::png_repair::pomoce_testowe::zdrowy_png;

    /// Uruchamia naprawę na pliku z doklejonymi śmieciami i zwraca jego treść.
    fn napraw_ze_smieciami(zdrowy: &[u8], ext: &'static str, ile_smieci: usize) -> Vec<u8> {
        let dir = tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let mut ze_smieciami = zdrowy.to_vec();
        ze_smieciami.extend(std::iter::repeat_n(0xDEu8, ile_smieci));

        let plik = dir.path().join(format!("obraz.{}", ext));
        std::fs::write(&plik, &ze_smieciami).unwrap();

        let (naprawiony, log) = TrailerTrimModule
            .repair(&plik, &dummy_ctx(ext, Some(false)), None, &wynik)
            .unwrap_or_else(|| panic!("doklejone śmieci w .{} muszą zostać przycięte", ext));

        assert!(
            log.contains(&ile_smieci.to_string()),
            "log musi podać liczbę odciętych bajtów: {}", log
        );
        std::fs::read(&naprawiony).unwrap()
    }

    /// Sedno tego modułu na prawdziwym obrazie: przycięcie musi trafić
    /// DOKŁADNIE w znacznik końca, więc wynik jest bajtowo równy oryginałowi.
    ///
    /// Wcześniejsze testy operowały na ciągach typu `b"AABBAABBAA"` — mierzyły
    /// samo wyszukiwanie podciągu, a nie to, czy po naprawie powstaje obraz.
    #[test]
    fn test_e2e_przyciecie_jpeg_odtwarza_oryginal_co_do_bajtu() {
        let zdrowy = zdrowy_jpeg(80, 60);
        let odzyskany = napraw_ze_smieciami(&zdrowy, "jpg", 512);

        assert_eq!(odzyskany, zdrowy, "przycięcie musi trafić dokładnie w znacznik EOI");

        let obraz = image::load_from_memory(&odzyskany).expect("przycięty JPEG musi się dekodować");
        assert_eq!((obraz.width(), obraz.height()), (80, 60));
    }

    #[test]
    fn test_e2e_przyciecie_png_odtwarza_oryginal_co_do_bajtu() {
        let zdrowy = zdrowy_png(64, 48);
        let odzyskany = napraw_ze_smieciami(&zdrowy, "png", 300);

        assert_eq!(odzyskany, zdrowy, "przycięcie musi trafić dokładnie za chunkiem IEND");

        let obraz = image::load_from_memory(&odzyskany).expect("przycięty PNG musi się dekodować");
        assert_eq!((obraz.width(), obraz.height()), (64, 48));
    }

    /// Śmieci zawierające ciąg udający znacznik końca nie mogą przesunąć cięcia.
    ///
    /// Moduł szuka OSTATNIEGO wystąpienia znacznika — na materiale, w którym
    /// doklejone śmieci same zawierają `FF D9`, naiwne szukanie pierwszego
    /// wystąpienia obcięłoby plik w złym miejscu.
    #[test]
    fn test_e2e_smieci_udajace_znacznik_konca() {
        let dir = tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = zdrowy_jpeg(48, 32);
        let mut ze_smieciami = zdrowy.clone();
        ze_smieciami.extend_from_slice(&[0x00; 64]);
        ze_smieciami.extend_from_slice(&[0xFF, 0xD9]); // fałszywy EOI w śmieciach
        ze_smieciami.extend_from_slice(&[0x11; 32]);

        let plik = dir.path().join("zdjecie.jpg");
        std::fs::write(&plik, &ze_smieciami).unwrap();

        let (naprawiony, _) = TrailerTrimModule
            .repair(&plik, &dummy_ctx("jpg", Some(false)), None, &wynik)
            .expect("naprawa musi się udać");

        let odzyskany = std::fs::read(&naprawiony).unwrap();

        // Moduł tnie po OSTATNIM znaczniku, więc zachowuje też śmieci przed
        // nim. Obraz i tak musi się dekodować - to jest miara sukcesu.
        assert!(
            odzyskany.len() >= zdrowy.len(),
            "cięcie po ostatnim znaczniku nie może skrócić pliku poniżej oryginału"
        );
        assert_eq!(
            &odzyskany[odzyskany.len() - 2..], &[0xFF, 0xD9],
            "wynik musi kończyć się znacznikiem EOI"
        );
        assert!(
            image::load_from_memory(&odzyskany).is_ok(),
            "przycięty obraz musi pozostać dekodowalny"
        );
    }

    #[test]
    fn test_naprawiony_obraz_przechodzi_weryfikacje_z_mocna_gwarancja() {
        let dir = tempdir().unwrap();
        let wynik = dir.path().join("w");
        std::fs::create_dir_all(&wynik).unwrap();

        let mut ze_smieciami = zdrowy_png(32, 32);
        ze_smieciami.extend_from_slice(&[0xAB; 128]);

        let plik = dir.path().join("obraz.png");
        std::fs::write(&plik, &ze_smieciami).unwrap();

        let (naprawiony, _) = TrailerTrimModule
            .repair(&plik, &dummy_ctx("png", Some(false)), None, &wynik)
            .expect("naprawa musi się udać");

        let ocena = TrailerTrimModule
            .verify(&naprawiony, &dummy_ctx("png", Some(false)))
            .expect("naprawiony obraz musi przejść weryfikację");
        assert!(ocena.contains("MOCNA"), "dekodowanie pikseli daje gwarancję MOCNĄ: {}", ocena);
    }
}
