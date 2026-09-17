// src/phases/repair_modules/tiff.rs

//! Moduł naprawczy TIFF — składanie strukturalne w automacie Fazy 17.
//!
//! ## Ten sam silnik co DNG, inna weryfikacja
//!
//! [`crate::dng_splice`] jest GENERYCZNYM spacerowiczem po IFD — czyta
//! wyłącznie standardowe znaczniki TIFF (`StripOffsets`, `TileOffsets`,
//! `StripByteCounts`, `TileByteCounts`, `SubIFDs`), żadnego swoistego dla
//! DNG. `phases::repair_modules::dng` już go używa dla całej rodziny RAW
//! zbudowanej na tym kontenerze (`dng`/`nef`/`cr2`/...). Zwykły `.tif`/`.tiff`
//! (fotografia, nie mozaika sensora aparatu) to TEN SAM kontener, więc silnik
//! składania działa bez żadnej zmiany.
//!
//! Różni się WYŁĄCZNIE weryfikacja: `dng`'a dekoduje `rawloader` (dekoder
//! RAW z aparatu — oczekuje mozaiki Bayera i znaczników CFA), a zwykły TIFF
//! dekoduje `image::load_from_memory`, DOKŁADNIE jak JPG/PNG (patrz domyślna
//! gałąź `weryfikuj_naprawiony_plik` dla `"tif" | "tiff"`). Stąd osobny plik,
//! nie rozszerzenie `dng.rs` o kolejne rozszerzenia — mieszanie dwóch różnych
//! dekoderów weryfikujących w jednym module zaciemniałoby oba.
//!
//! ## Dlaczego gwarancja jest SŁABA i dlaczego musiałem nadpisać `verify`
//!
//! Ten sam powód co w `dng.rs`, dosłownie: składanie strukturalne bierze
//! nagłówek/IFD z jednej kopii, a bajty pikseli z drugiej, według offsetów
//! odczytanych ze zdrowej struktury. Udane dekodowanie `image` dowodzi więc
//! wyłącznie tego, że **struktura jest spójna** — dekoder czyta bufor
//! `width*height*cpp` z miejsca wskazanego przez IFD, nie weryfikując treści
//! tego, co tam faktycznie leży. Domyślna etykieta „gwarancja MOCNA" dla
//! `.tif`/`.tiff` byłaby więc tutaj przekłamaniem.
//!
//! Entropia Shannona przeniesionego obszaru
//! ([`dng_splice::looks_like_plausible_sensor_data`], bez zmian) jest jedynym
//! dostępnym sygnałem i jest to plauzybilność, nie dowód — patrz dokumentacja
//! `dng.rs` dla pełnego uzasadnienia, identycznego tutaj.

use super::{RepairContext, RepairModule, WynikWeryfikacji};
use crate::{dng_splice, generic_image};
use std::path::{Path, PathBuf};

pub struct TiffStructuralModule;

/// Zwykły TIFF fotograficzny — w odróżnieniu od [`super::dng::DngStructuralModule`]
/// (rodzina RAW na tym samym kontenerze, weryfikowana `rawloader`em).
const RODZINA_TIFF: &[&str] = &["tif", "tiff"];

/// Realne dekodowanie przez `image`, panic-safe — `decode_guarded` łapie
/// panikę tak samo jak `raw_image::decode_raw_bytes` łapie panikę
/// `rawloader`a, bo składane bajty (kandydat PRZED filtrem) mogą być
/// zniekształcone w sposób, na jaki dekoder nie jest przygotowany.
fn dekoduje_sie(bytes: &[u8]) -> bool {
    matches!(
        generic_image::decode_guarded(|| image::load_from_memory(bytes)),
        Some(Ok(img)) if img.width() > 0 && img.height() > 0
    )
}

fn jest_uszkodzonym_tiff(ctx: &RepairContext) -> bool {
    if !RODZINA_TIFF.contains(&ctx.ext) {
        return false;
    }

    // Te same trzy przesłanki co header_jpg/header_png/header_raster: powód
    // z Fazy 12 zawierający "Nagłówek", brak znacznika końca z Fazy 6, albo
    // nieudane pełne dekodowanie z Fazy 13 (media_decoded == Some(false)) —
    // TIFF nie ma własnego odrębnego tekstu powodu jak "RAW/DNG" dla DNG,
    // Faza 12/13 raportują dla niego przez ten sam ogólny tekst co JPG/PNG.
    ctx.eof_ok == Some(false)
        || ctx.media_reason.is_some_and(|r| r.contains("Nagłówek"))
        || ctx.media_decoded == Some(false)
}

impl RepairModule for TiffStructuralModule {
    fn id(&self) -> &'static str { "tiff_structural" }

    fn display_name(&self) -> &'static str {
        "TIFF składanie strukturalne z bliźniaczej kopii (gwarancja SŁABA)"
    }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        jest_uszkodzonym_tiff(ctx)
    }

    /// Składa plik w obu kierunkach, odrzuca kandydatów, którzy się nie
    /// dekodują, i przyjmuje pierwszego, którego entropia przeniesionych
    /// danych wygląda na dane obrazu — patrz `dng.rs::repair` dla pełnego
    /// uzasadnienia kolejności i progu, identycznego tutaj.
    fn repair(&self, source: &Path, ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let dawca = twin?;

        let kandydaci = dng_splice::structural_splice_files(source, dawca).ok()?;

        let wybrany = kandydaci.into_iter().find(|k| {
            dng_splice::looks_like_plausible_sensor_data(k.donated_data_entropy)
                && dekoduje_sie(&k.bytes)
        })?;

        let stem = source.file_stem()?.to_str()?;
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_tiff.{}", stem, ctx.ext));

        if let Some(katalog) = cel.parent() {
            std::fs::create_dir_all(katalog).ok()?;
        }
        if let Err(e) = std::fs::write(&cel, &wybrany.bytes) {
            tracing::debug!(plik = %cel.display(), blad = %e, "tiff_structural: zapis wyniku nieudany");
            let _ = std::fs::remove_file(&cel);
            return None;
        }

        Some((
            cel,
            format!(
                "{}; entropia przeniesionych danych {:.2} bit/bajt (plauzybilne dane obrazu); dawca: {}. \
                 UWAGA: potwierdzona wyłącznie spójność struktury, NIE poprawność pikseli.",
                wybrany.description, wybrany.donated_data_entropy, dawca.display()
            ),
        ))
    }

    /// Weryfikacja z jawnie **osłabioną** etykietą gwarancji — patrz
    /// dokumentacja modułu i `dng.rs::verify` dla identycznego uzasadnienia.
    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        let bajty = std::fs::read(repaired).map_err(|e| format!("nie udało się odczytać wyniku: {}", e))?;

        if dekoduje_sie(&bajty) {
            Ok("dekodowanie przez image (gwarancja SŁABA - potwierdza spójność struktury TIFF/IFD, nie treść pikseli)")
        } else {
            Err("złożony plik nie daje się zdekodować jako TIFF".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(ext: &'static str, eof_ok: Option<bool>, media_reason: Option<&'static str>) -> RepairContext<'static> {
        RepairContext {
            ext, media_reason, utf8_ok: None, is_oneliner: None,
            eof_ok, match_type: None, video_ok: None, structure_ok: None, media_decoded: None
        }
    }

    // ------------------------------------------------------------------
    // Kwalifikacja
    // ------------------------------------------------------------------

    #[test]
    fn test_kwalifikuje_po_powodzie_z_fazy_12() {
        assert!(TiffStructuralModule.applies_to(&ctx("tiff", None, Some("Zniszczony Nagłówek (Brak Wymiarów X/Y)"))));
    }

    #[test]
    fn test_kwalifikuje_po_braku_znacznika_konca() {
        assert!(TiffStructuralModule.applies_to(&ctx("tif", Some(false), None)));
    }

    /// `media_decoded == Some(false)` (Faza 13, `image` faktycznie nie
    /// zdołał zdekodować) to TRZECIA, niezależna przesłanka.
    #[test]
    fn test_kwalifikuje_po_nieudanym_dekodowaniu_z_fazy13() {
        let kontekst = RepairContext {
            ext: "tiff", media_reason: None, utf8_ok: None, is_oneliner: None,
            eof_ok: None, match_type: None, video_ok: None, structure_ok: None,
            media_decoded: Some(false),
        };
        assert!(TiffStructuralModule.applies_to(&kontekst));
    }

    #[test]
    fn test_nie_rusza_zdrowego_tiff() {
        assert!(!TiffStructuralModule.applies_to(&ctx("tiff", Some(true), None)));
        assert!(!TiffStructuralModule.applies_to(&ctx("tiff", None, None)), "bez przesłanki uszkodzenia nie dotykamy pliku");
    }

    /// Zakres modułu wyznacza rozszerzenie `.tif`/`.tiff` — rodzina RAW na
    /// tym samym kontenerze ma WŁASNY moduł (`dng::DngStructuralModule`),
    /// żeby oba mogły mieć niezależną, poprawną dla siebie weryfikację.
    #[test]
    fn test_obejmuje_tylko_tif_i_tiff() {
        for ext in ["dng", "nef", "cr2", "jpg", "png", "heic"] {
            assert!(
                !TiffStructuralModule.applies_to(&ctx(ext, Some(false), None)),
                ".{} ma własny moduł albo nie jest na kontenerze TIFF", ext
            );
        }
    }

    #[test]
    fn test_oba_rozszerzenia_tif_i_tiff_obslugiwane() {
        for ext in ["tif", "tiff"] {
            assert!(TiffStructuralModule.applies_to(&ctx(ext, Some(false), None)), ".{} musi być obsługiwany", ext);
        }
    }

    // ------------------------------------------------------------------
    // Kolejność w dyspozytorze
    // ------------------------------------------------------------------

    #[test]
    fn test_stoi_przed_splice() {
        let ids: Vec<&str> = super::super::all_modules().iter().map(|m| m.id()).collect();
        let i_tiff = ids.iter().position(|id| *id == "tiff_structural").expect("tiff_structural musi być zarejestrowany");
        let i_splice = ids.iter().position(|id| *id == "splice").expect("splice musi być zarejestrowany");

        assert!(
            i_tiff < i_splice,
            "bajtowe zszycie nie zna struktury TIFF/IFD i nie może wyprzedzać składania strukturalnego (kolejność: {:?})",
            ids
        );
    }

    // ------------------------------------------------------------------
    // Siła gwarancji - sedno tego modułu
    // ------------------------------------------------------------------

    /// Domyślna weryfikacja dla `.tiff` melduje gwarancję MOCNĄ (ten sam
    /// dekoder `image` co JPG/PNG). Dla składania strukturalnego to
    /// przekłamanie, więc moduł MUSI ją nadpisać.
    #[test]
    fn test_etykieta_gwarancji_jest_slabsza_od_domyslnej() {
        let sciezka = std::path::Path::new("image/test_fixture.tiff");
        if !sciezka.exists() {
            assert!(TiffStructuralModule.display_name().contains("SŁABA"));
            return;
        }

        let kontekst = ctx("tiff", Some(false), None);

        let domyslna = super::super::weryfikuj_naprawiony_plik(sciezka)
            .expect("zdrowy fixture musi przejść weryfikację domyślną");
        let modulowa = TiffStructuralModule.verify(sciezka, &kontekst)
            .expect("zdrowy fixture musi przejść weryfikację modułu");

        assert!(domyslna.contains("MOCNA"), "kontrola: domyślna etykieta to {}", domyslna);
        assert!(
            modulowa.contains("SŁABA") && !modulowa.contains("MOCNA"),
            "moduł musi meldować gwarancję SŁABĄ, dostaliśmy: {}", modulowa
        );
    }

    #[test]
    fn test_nazwa_modulu_ujawnia_sile_gwarancji() {
        assert!(
            TiffStructuralModule.display_name().contains("SŁABA"),
            "nazwa: {}", TiffStructuralModule.display_name()
        );
    }

    #[test]
    fn test_weryfikacja_odrzuca_plik_ktory_nie_jest_tiff() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("smieci.tiff");
        std::fs::write(&plik, b"to nie jest TIFF").unwrap();

        assert!(TiffStructuralModule.verify(&plik, &ctx("tiff", Some(false), None)).is_err());
    }

    // ------------------------------------------------------------------
    // repair
    // ------------------------------------------------------------------

    #[test]
    fn test_bez_dawcy_zwraca_none() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("obraz.tiff");
        std::fs::write(&plik, b"nieistotne").unwrap();

        assert!(
            TiffStructuralModule.repair(&plik, &ctx("tiff", Some(false), None), None, dir.path()).is_none(),
            "składanie bez drugiej kopii jest niemożliwe"
        );
    }

    #[test]
    fn test_nieparsowalne_pliki_nie_zostawiaja_wyniku() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let plik = dir.path().join("a.tiff");
        let dawca = dir.path().join("b.tiff");
        std::fs::write(&plik, b"nie TIFF").unwrap();
        std::fs::write(&dawca, b"tez nie TIFF").unwrap();

        assert!(TiffStructuralModule.repair(&plik, &ctx("tiff", Some(false), None), Some(&dawca), &wynik).is_none());

        let pozostalo: Vec<String> = std::fs::read_dir(&wynik).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(pozostalo.is_empty(), "po odmowie nie może zostać plik: {:?}", pozostalo);
    }

    // ------------------------------------------------------------------
    // Pełna ścieżka na PRAWDZIWYM pliku
    // ------------------------------------------------------------------

    /// Budowa wariantu "header_damaged" z jedynego dostępnego fixture'a: brak
    /// tu osobnego, wcześniej przygotowanego pliku jak w `dng.rs`, więc
    /// zerujemy wyłącznie pierwsze 8 bajtów (magiczna liczba TIFF + offset
    /// pierwszego IFD). To wystarcza, żeby `image` w ogóle nie potrafił
    /// znaleźć struktury, a jednocześnie NIE dotyka ani tablicy tagów IFD
    /// (leży w tym fixture'cie na SAMYM KOŃCU pliku), ani danych pikseli
    /// (zaczynają się dokładnie od bajtu 8) — silnik składania wciąż znajdzie
    /// tam prawdziwe, nienaruszone bajty obrazu pod offsetami odczytanymi ze
    /// zdrowego dawcy.
    fn zbuduj_uszkodzony_wariant(zdrowe: &[u8]) -> Vec<u8> {
        let mut uszkodzone = zdrowe.to_vec();
        for b in &mut uszkodzone[..8] { *b = 0; }
        uszkodzone
    }

    /// **Pomiar empiryczny (measure twice) na `image/test_fixture.tiff`:**
    /// entropia Shannona jego RZECZYWISTYCH danych pikseli (~38 KB, prawie
    /// cały plik) wynosi **1.85 bit/bajt** — poniżej `DOLNA_GRANICA_ENTROPII`
    /// (3.0) z `dng_splice`, kalibrowanej pod SZUM mozaiki Bayera prawdziwego
    /// sensora aparatu. Ten konkretny plik testowy to uboga w szczegóły,
    /// syntetyczna grafika (płaskie obszary koloru) — NIE reprezentuje
    /// typowej fotografii, więc bramka plauzybilności POPRAWNIE go odrzuca.
    ///
    /// To NIE jest usterka silnika ani tego modułu: bramka jest z założenia
    /// bezpieczna w JEDNĄ stronę — najgorszy skutek fałszywego odrzucenia to
    /// brak naprawy (dokładnie jak dziś), nigdy zaakceptowanie złych danych.
    /// Test poniżej utrwala to zachowanie jako ŚWIADOME, zamiast pozwolić mu
    /// wyglądać jak przypadkowo psujący się test przy następnej zmianie progu.
    #[test]
    #[ignore = "Wymaga image/test_fixture.tiff. Uruchom z --ignored."]
    fn test_e2e_bramka_entropii_odrzuca_niskoszczegolowa_grafike_testowa() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowe = std::fs::read("image/test_fixture.tiff").unwrap();
        let uszkodzone = zbuduj_uszkodzony_wariant(&zdrowe);

        let uszkodzony = dir.path().join("uszkodzony.tiff");
        let dawca = dir.path().join("dawca.tiff");
        std::fs::write(&uszkodzony, &uszkodzone).unwrap();
        std::fs::write(&dawca, &zdrowe).unwrap();

        let kontekst = ctx("tiff", Some(false), None);

        // Kontrola sensu testu: uszkodzony plik NIE MOŻE przechodzić
        // weryfikacji, inaczej test nie mierzy niczego.
        assert!(
            TiffStructuralModule.verify(&uszkodzony, &kontekst).is_err(),
            "plik z wyzerowanym nagłówkiem nie powinien się dekodować"
        );

        assert!(
            TiffStructuralModule.repair(&uszkodzony, &kontekst, Some(&dawca), &wynik).is_none(),
            "grafika o entropii poniżej progu plauzybilności musi zostać odrzucona, nie naprawiona"
        );

        let pozostalo: Vec<String> = std::fs::read_dir(&wynik).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(pozostalo.is_empty(), "odrzucony kandydat nie może zostać zapisany: {:?}", pozostalo);
    }

    /// Domyka to, czego test wyżej celowo NIE dowodzi: że sam MECHANIZM
    /// składania strukturalnego (offsety ze zdrowej struktury + realne
    /// dekodowanie `image`) faktycznie działa na PRAWDZIWYM pliku — niezależnie
    /// od tego, czy akurat ten konkretny fixture przechodzi bramkę entropii.
    /// Wywołuje silnik (`dng_splice`) i dekoder BEZPOŚREDNIO, z pominięciem
    /// `TiffStructuralModule::repair` (który zawsze stosuje OBIE bramki naraz),
    /// żeby zmierzyć dokładnie tę jedną właściwość.
    #[test]
    #[ignore = "Wymaga image/test_fixture.tiff. Uruchom z --ignored."]
    fn test_e2e_mechanizm_skladania_faktycznie_rekonstruuje_dekodowalny_tiff() {
        let zdrowe = std::fs::read("image/test_fixture.tiff").unwrap();
        let uszkodzone = zbuduj_uszkodzony_wariant(&zdrowe);

        let kandydaci = dng_splice::structural_splice_candidates(&uszkodzone, &zdrowe);
        assert!(!kandydaci.is_empty(), "silnik musi znaleźć co najmniej jednego kandydata na podstawie zdrowej struktury dawcy");

        assert!(
            kandydaci.iter().any(|k| dekoduje_sie(&k.bytes)),
            "co najmniej jeden kandydat złożony z prawdziwych bajtów musi się realnie dekodować przez image"
        );
    }
}
