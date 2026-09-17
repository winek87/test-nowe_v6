// src/phases/repair_modules/header_raster.rs

//! Moduł naprawczy: wstrzykiwanie utraconej sygnatury dla pozostałych
//! formatów rastrowych — GIF, BMP, TIFF i WEBP.
//!
//! ## Czym różni się od [`super::header_jpg`] i [`super::header_png`]
//!
//! Tamte obsługują po jednym formacie i doklejają stałą sygnaturę w ciemno.
//! Tutaj dochodzą dwie rzeczy, których tam nie było:
//!
//! 1. **Warianty sygnatury.** TIFF istnieje w dwóch porządkach bajtów
//!    (`II*\0` little-endian, `MM\0*` big-endian), a GIF w dwóch wersjach
//!    (`GIF89a`, `GIF87a`). Przy utraconym nagłówku nie ma jak odgadnąć
//!    którego użyto, więc próbujemy po kolei.
//! 2. **Samokontrola przed zapisem.** Moduł sam sprawdza kandydata przez
//!    `image::load_from_memory` i zapisuje dopiero ten, który realnie się
//!    dekoduje. Bez tego wybór wariantu byłby zgadywaniem, a na dysk trafiałby
//!    plik, który i tak odrzuci obowiązkowa weryfikacja Fazy 17.
//!
//! ## Podstawa empiryczna
//!
//! Zachowanie sprawdzone na plikach z prawdziwego kodera (ffmpeg), osobno dla
//! każdego z czterech formatów: zdrowy plik się dekoduje, po usunięciu
//! sygnatury przestaje, a po jej doklejeniu dekoduje się ponownie. Dotyczy to
//! także BMP i WEBP, mimo że oba trzymają w nagłówku pole długości pliku —
//! dekoder tolerował tam niezgodność. To był realny powód do sprawdzenia, a
//! nie założenia.

use super::{RepairContext, RepairModule};
use std::fs;
use std::path::{Path, PathBuf};

/// Sygnatury do wypróbowania dla danego rozszerzenia, w kolejności od
/// najbardziej prawdopodobnej.
///
/// Zwraca `None` dla formatów, których ten moduł nie obsługuje — JPG i PNG
/// mają własne moduły, a ich tu nie dublujemy.
fn sygnatury_dla(ext: &str) -> Option<&'static [&'static [u8]]> {
    match ext {
        // GIF89a jest dziś powszechny; GIF87a to starszy wariant.
        "gif" => Some(&[b"GIF89a", b"GIF87a"]),
        "bmp" => Some(&[b"BM"]),
        // Little-endian (`II`) dominuje; big-endian (`MM`) bywa w materiale
        // z aparatów.
        "tif" | "tiff" => Some(&[&[0x49, 0x49, 0x2A, 0x00], &[0x4D, 0x4D, 0x00, 0x2A]]),
        "webp" => Some(&[b"RIFF"]),
        _ => None,
    }
}

/// Czy bufor już zaczyna się którąś ze znanych sygnatur tego formatu.
fn ma_juz_sygnature(bajty: &[u8], warianty: &[&[u8]]) -> bool {
    warianty.iter().any(|s| bajty.starts_with(s))
}

pub struct HeaderRasterModule;

impl RepairModule for HeaderRasterModule {
    fn id(&self) -> &'static str { "header_raster" }
    fn display_name(&self) -> &'static str { "Nagłówek GIF/BMP/TIFF/WEBP (wstrzyknięcie sygnatury)" }

    /// Ta sama bramka co w [`super::header_png`]: format z listy plus zgłoszony
    /// przez Fazę 12 powód zawierający `"Nagłówek"`, ALBO nieudane pełne
    /// dekodowanie z Fazy 13. Bez tego warunku moduł próbowałby doklejać
    /// sygnaturę do plików uszkodzonych zupełnie inaczej.
    fn applies_to(&self, ctx: &RepairContext) -> bool {
        sygnatury_dla(ctx.ext).is_some()
            && (ctx.media_reason.is_some_and(|r| r.contains("Nagłówek")) || ctx.media_decoded == Some(false))
    }

    fn repair(
        &self,
        source: &Path,
        ctx: &RepairContext,
        _twin: Option<&Path>,
        katalog_wyjsciowy: &Path,
    ) -> Option<(PathBuf, String)> {
        let warianty = sygnatury_dla(ctx.ext)?;
        let bajty = fs::read(source).ok()?;

        // Sygnatura na miejscu = nie ma czego naprawiać tym modułem.
        if ma_juz_sygnature(&bajty, warianty) {
            return None;
        }

        for sygnatura in warianty {
            let mut kandydat = sygnatura.to_vec();
            kandydat.extend_from_slice(&bajty);

            // Samokontrola: zapisujemy WYŁĄCZNIE wariant, który realnie się
            // dekoduje. Przy dwóch wariantach sygnatury inaczej byłoby to
            // zgadywanie.
            if image::load_from_memory(&kandydat).is_err() {
                continue;
            }

            let stem = source.file_stem()?.to_str()?;
            let target = katalog_wyjsciowy.join(format!("{}_repaired.{}", stem, ctx.ext));
            fs::write(&target, &kandydat).ok()?;

            return Some((
                target,
                format!(
                    "Wstrzyknięto utraconą sygnaturę {} ({}).",
                    ctx.ext.to_uppercase(),
                    sygnatura
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            ));
        }

        None
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn ctx(ext: &'static str, powod: Option<&'static str>) -> RepairContext<'static> {
        RepairContext {
            ext,
            media_reason: powod,
            utf8_ok: None,
            is_oneliner: None,
            eof_ok: None,
            match_type: None,
            video_ok: None,
            structure_ok: None, media_decoded: None,
        }
    }

    // ------------------------------------------------------------------
    // ZAKRES STOSOWANIA
    // ------------------------------------------------------------------

    #[test]
    fn test_stosuje_sie_do_czterech_formatow_przy_powodzie_naglowka() {
        let m = HeaderRasterModule;
        for ext in ["gif", "bmp", "tif", "tiff", "webp"] {
            assert!(
                m.applies_to(&ctx(ext, Some("Zniszczony Nagłówek (Brak Wymiarów X/Y)"))),
                ".{} powinien być obsługiwany", ext
            );
        }
    }

    /// JPG i PNG mają własne moduły — dublowanie ich tutaj dałoby dwa moduły
    /// walczące o ten sam plik.
    #[test]
    fn test_nie_wchodzi_w_kompetencje_jpg_i_png() {
        let m = HeaderRasterModule;
        for ext in ["jpg", "jpeg", "png"] {
            assert!(!m.applies_to(&ctx(ext, Some("Zniszczony Nagłówek"))));
        }
    }

    /// Patrz analogiczny test w `header_jpg.rs` — ten sam silniejszy sygnał
    /// z Fazy 13, niezależny od powodu z Fazy 12.
    #[test]
    fn test_stosuje_sie_gdy_faza13_nie_zdekodowala() {
        let m = HeaderRasterModule;
        let kontekst = RepairContext {
            ext: "bmp", media_reason: None, utf8_ok: None, is_oneliner: None,
            eof_ok: None, match_type: None, video_ok: None, structure_ok: None,
            media_decoded: Some(false),
        };
        assert!(m.applies_to(&kontekst));
    }

    #[test]
    fn test_nie_stosuje_sie_bez_powodu_naglowkowego() {
        let m = HeaderRasterModule;
        assert!(!m.applies_to(&ctx("gif", None)));
        assert!(
            !m.applies_to(&ctx("gif", Some("Ucięty plik"))),
            "Inny rodzaj uszkodzenia nie jest zadaniem tego modułu"
        );
    }

    // ------------------------------------------------------------------
    // ROZPOZNAWANIE SYGNATUR
    // ------------------------------------------------------------------

    #[test]
    fn test_rozpoznaje_oba_warianty_gif() {
        let w = sygnatury_dla("gif").unwrap();
        assert!(ma_juz_sygnature(b"GIF89a reszta", w));
        assert!(ma_juz_sygnature(b"GIF87a reszta", w), "Starszy wariant też jest poprawny");
        assert!(!ma_juz_sygnature(b"cokolwiek innego", w));
    }

    #[test]
    fn test_rozpoznaje_oba_porzadki_bajtow_tiff() {
        let w = sygnatury_dla("tiff").unwrap();
        assert!(ma_juz_sygnature(&[0x49, 0x49, 0x2A, 0x00, 0x11], w), "little-endian");
        assert!(ma_juz_sygnature(&[0x4D, 0x4D, 0x00, 0x2A, 0x11], w), "big-endian");
    }

    #[test]
    fn test_nieobslugiwane_rozszerzenie_nie_ma_sygnatur() {
        assert!(sygnatury_dla("mp4").is_none());
        assert!(sygnatury_dla("png").is_none());
    }

    // ------------------------------------------------------------------
    // NAPRAWA NA PRAWDZIWYCH PLIKACH
    // ------------------------------------------------------------------

    /// Pełny obieg dla każdego z czterech formatów: bierzemy plik z prawdziwego
    /// kodera, odcinamy sygnaturę i sprawdzamy, że moduł przywraca plik do
    /// stanu dekodowalnego.
    #[test]
    #[ignore = "Wymaga image/test_fixture.{gif,bmp,tiff,webp}. Uruchom z --ignored."]
    fn test_e2e_przywraca_dekodowalnosc_kazdego_formatu() {
        let m = HeaderRasterModule;
        let dir = tempdir().unwrap();

        for (ext, dlugosc_sygnatury) in [("gif", 6usize), ("bmp", 2), ("tiff", 4), ("webp", 4)] {
            let pelny = fs::read(format!("image/test_fixture.{}", ext))
                .unwrap_or_else(|_| panic!("brak fixture dla {}", ext));

            assert!(
                image::load_from_memory(&pelny).is_ok(),
                "Test bez sensu: zdrowy fixture {} musi się dekodować", ext
            );

            let uszkodzony = &pelny[dlugosc_sygnatury..];
            assert!(
                image::load_from_memory(uszkodzony).is_err(),
                "Test bez sensu: {} bez sygnatury musi przestać się dekodować", ext
            );

            let wejscie = dir.path().join(format!("bez_sygnatury.{}", ext));
            fs::write(&wejscie, uszkodzony).unwrap();

            let ext_statyczny: &'static str = match ext {
                "gif" => "gif", "bmp" => "bmp", "tiff" => "tiff", _ => "webp",
            };
            let (wynik, opis) = m
                .repair(&wejscie, &ctx(ext_statyczny, Some("Nagłówek")), None, dir.path())
                .unwrap_or_else(|| panic!("naprawa {} musi się udać", ext));

            assert!(opis.contains("sygnaturę"), "Opis musi mówić, co zrobiono: {}", opis);
            let naprawiony = fs::read(&wynik).unwrap();
            assert!(
                image::load_from_memory(&naprawiony).is_ok(),
                "Naprawiony {} musi się dekodować", ext
            );
        }
    }

    /// Plik ze zdrową sygnaturą nie jest zadaniem tego modułu — zwrócenie
    /// `Some` oznaczałoby fałszywy sukces i zablokowało moduły, które
    /// faktycznie potrafiłyby coś naprawić.
    #[test]
    #[ignore = "Wymaga image/test_fixture.gif. Uruchom z --ignored."]
    fn test_zdrowy_plik_nie_jest_ruszany() {
        let m = HeaderRasterModule;
        let dir = tempdir().unwrap();
        let pelny = fs::read("image/test_fixture.gif").expect("fixture musi istnieć");
        let wejscie = dir.path().join("zdrowy.gif");
        fs::write(&wejscie, &pelny).unwrap();

        assert!(
            m.repair(&wejscie, &ctx("gif", Some("Nagłówek")), None, dir.path()).is_none(),
            "Sygnatura na miejscu = nie ma czego naprawiać"
        );
    }

    /// Śmieci pozostają śmieciami: doklejenie sygnatury nie zrobi z nich
    /// obrazu, a moduł nie ma prawa zgłosić sukcesu.
    #[test]
    fn test_smieci_nie_daja_falszywego_sukcesu() {
        let m = HeaderRasterModule;
        let dir = tempdir().unwrap();
        let wejscie = dir.path().join("smieci.gif");
        fs::write(&wejscie, b"to zupelnie nie jest obraz, tylko zwykly tekst").unwrap();

        assert!(
            m.repair(&wejscie, &ctx("gif", Some("Nagłówek")), None, dir.path()).is_none(),
            "Samokontrola musi odrzucić kandydata, który się nie dekoduje"
        );
    }

    #[test]
    fn test_pusty_plik_nie_wywraca_modulu() {
        let m = HeaderRasterModule;
        let dir = tempdir().unwrap();
        let wejscie = dir.path().join("pusty.bmp");
        fs::write(&wejscie, b"").unwrap();

        assert!(m.repair(&wejscie, &ctx("bmp", Some("Nagłówek")), None, dir.path()).is_none());
    }
}
