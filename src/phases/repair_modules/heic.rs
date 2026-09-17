// src/phases/repair_modules/heic.rs

//! Moduł naprawczy HEIC/HEIF/AVIF — przeszczep indeksu `meta` z bliźniaczej kopii.
//!
//! ## Skąd się wziął
//!
//! Do tej pory HEIC był w projekcie formatem, który potrafiliśmy **wykryć** i
//! **zweryfikować**, ale nie naprawić. Faza 13 rozpoznawała uszkodzenie przez
//! `libheif`, dyspozytor Fazy 17 umiał ocenić wynik naprawy — tylko nic takiego
//! wyniku nie produkowało. Jedyną ścieżką był generyczny `splice`, czyli
//! bajtowe zszycie dwóch kopii, bez żadnej wiedzy o strukturze kontenera.
//!
//! Luka domknęła się po porcie silników MP4, bo HEIC to **ten sam kontener
//! ISOBMFF**: atom `meta` pełni rolę `moov`, a `iloc` rolę `stco`/`co64`. Ten
//! moduł stosuje więc tę samą strategię, co [`super::mp4`] w wariancie
//! przeszczepu — patrz [`crate::mp4_repair::heic_clone`] co do tego, dlaczego
//! nie trzeba tu przepisywać offsetów.
//!
//! ## Czego ten moduł NIE robi
//!
//! Nie ma odpowiednika Zero-Donor: odbudowa indeksu HEIC od zera wymagałaby
//! parsowania strumienia HEVC i rekonstrukcji `iinf`/`iprp`/`iloc`, co jest
//! osobnym zadaniem o zupełnie innym rozmiarze. Bez bliźniaczej kopii ten
//! moduł nie pomoże i uczciwie zwraca `None`.

use super::{RepairContext, RepairModule, WynikWeryfikacji};
use crate::mp4_repair::{heic_clone, heic_native};
use std::path::{Path, PathBuf};

pub struct HeicCloneModule;

/// Rozstrzyga, czy plik jest uszkodzonym HEIC-iem.
///
/// Rozpoznanie rozszerzenia deleguje do [`crate::heic_image::is_heic_extension`],
/// żeby lista formatów żyła w JEDNYM miejscu — tym samym, którego używa
/// diagnostyka Fazy 13 i weryfikacja wyniku.
///
/// Sygnał uszkodzenia: powód z Fazy 12 zawierający `"Nagłówek"` albo brak
/// znacznika końca z Fazy 6, albo nieudane pełne dekodowanie z Fazy 13
/// (`media_decoded == Some(false)`). Faza 19 nie dotyczy HEIC (to nie jest
/// wideo), więc `video_ok` tu nie pomaga.
fn jest_uszkodzonym_heic(ctx: &RepairContext) -> bool {
    // `is_heic_extension` oczekuje nazwy pliku, a `ctx.ext` to samo
    // rozszerzenie bez kropki — doklejamy ją, żeby dopasowanie działało.
    if !crate::heic_image::is_heic_extension(&format!(".{}", ctx.ext)) {
        return false;
    }

    ctx.eof_ok == Some(false)
        || ctx.media_reason.is_some_and(|r| r.contains("Nagłówek"))
        || ctx.media_decoded == Some(false)
}

impl RepairModule for HeicCloneModule {
    fn id(&self) -> &'static str { "heic_clone" }

    fn display_name(&self) -> &'static str {
        "HEIC/HEIF przeszczep indeksu meta z bliźniaczej kopii"
    }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        jest_uszkodzonym_heic(ctx)
    }

    /// Składa sprawny plik z indeksu `meta` bliźniaczej kopii i danych obrazu
    /// (`mdat`) pliku uszkodzonego.
    ///
    /// Zwraca `None`, gdy bliźniak nie został podany — ten moduł bezwzględnie go
    /// wymaga, analogicznie do zszywania i do przeszczepu MP4.
    fn repair(&self, source: &Path, _ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let dawca = twin?;

        let stem = source.file_stem()?.to_str()?;
        let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("heic");
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_heic.{}", stem, ext));

        match heic_clone::repair(source.to_str()?, dawca.to_str()?, cel.to_str()?) {
            Ok(()) => Some((
                cel,
                format!("Przeszczepiono indeks `meta` od dawcy {} z zachowaniem danych obrazu.", dawca.display()),
            )),
            Err(e) => {
                tracing::debug!(
                    plik = %source.display(), dawca = %dawca.display(), blad = %e,
                    "heic_clone: przeszczep nieudany"
                );
                // Silnik zapisuje wynik dopiero po udanym złożeniu, ale gdyby
                // zapis padł w połowie, nie zostawiamy pozornej naprawy.
                let _ = std::fs::remove_file(&cel);
                None
            }
        }
    }

    /// Weryfikacja przez `libheif` — realne odczytanie struktury kontenera.
    ///
    /// Domyślna implementacja z [`super::weryfikuj_naprawiony_plik`] i tak
    /// trafiłaby w gałąź HEIC, ale nadpisujemy ją jawnie: dzięki temu
    /// zależność tego modułu od `libheif` widać wprost w jego własnym kodzie.
    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        super::weryfikuj_naprawiony_plik(repaired)
    }
}

// ============================================================================
// Wariant bez dawcy (Zero-Donor)
// ============================================================================

/// Odbudowa indeksu `meta` wyłącznie z zawartości `mdat`, bez bliźniaczej kopii.
///
/// Działa tylko wtedy, gdy materiał na to pozwala — a zwykle nie pozwala.
/// Zestawy parametrów HEVC (VPS/SPS/PPS) HEIC trzyma w `hvcC`, czyli WEWNĄTRZ
/// `meta`, więc zniszczenie `meta` zabiera je razem z indeksem. Silnik
/// odbudowuje plik tylko wtedy, gdy zestawy parametrów znajdą się „w pasmie"
/// w `mdat`, a materiał nie wskazuje na siatkę kafli — w pozostałych
/// przypadkach odmawia z konkretną diagnozą, zamiast zgadywać. Pełne
/// uzasadnienie i pomiary: [`crate::mp4_repair::heic_native`].
///
/// Stoi ZA [`HeicCloneModule`], bo przeszczep od bliźniaka jest zawsze
/// pełniejszy. Ten moduł jest ostatnią szansą, gdy bliźniaka nie ma.
pub struct HeicNativeModule;

impl RepairModule for HeicNativeModule {
    fn id(&self) -> &'static str { "heic_native" }

    fn display_name(&self) -> &'static str {
        "HEIC odbudowa indeksu meta bez dawcy (Zero-Donor)"
    }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        jest_uszkodzonym_heic(ctx)
    }

    fn repair(&self, source: &Path, _ctx: &RepairContext, _twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let stem = source.file_stem()?.to_str()?;
        let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("heic");
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_native.{}", stem, ext));

        match heic_native::repair(source.to_str()?, cel.to_str()?) {
            Ok(odbudowa) => Some((cel, odbudowa.opis())),
            Err(e) => {
                // Odmowa jest tu normalnym, częstym wynikiem - stąd `debug`,
                // nie `warn`. Treść błędu niesie konkretną diagnozę.
                tracing::debug!(plik = %source.display(), powod = %e, "heic_native: odbudowa bez dawcy niemożliwa");
                let _ = std::fs::remove_file(&cel);
                None
            }
        }
    }

    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        super::weryfikuj_naprawiony_plik(repaired)
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
    // applies_to
    // ------------------------------------------------------------------

    #[test]
    fn test_stosuje_sie_do_calej_rodziny_heif() {
        for ext in ["heic", "heif", "avif"] {
            assert!(
                HeicCloneModule.applies_to(&ctx(ext, Some(false), None)),
                "rozszerzenie .{} musi być rozpoznane", ext
            );
        }
    }

    #[test]
    fn test_reaguje_na_powod_z_fazy12() {
        assert!(HeicCloneModule.applies_to(&ctx("heic", None, Some("Zniszczony Nagłówek obrazu"))));
    }

    /// Nagłówek formalnie poprawny, ale Faza 13 (libheif) nie zdołała
    /// zdekodować — musi zareagować samodzielnie.
    #[test]
    fn test_reaguje_na_nieudane_dekodowanie_z_fazy13() {
        let kontekst = RepairContext {
            ext: "heic", media_reason: None, utf8_ok: None, is_oneliner: None,
            eof_ok: None, match_type: None, video_ok: None, structure_ok: None,
            media_decoded: Some(false),
        };
        assert!(HeicCloneModule.applies_to(&kontekst));
    }

    #[test]
    fn test_nie_rusza_zdrowego_heic() {
        assert!(!HeicCloneModule.applies_to(&ctx("heic", Some(true), None)));
        assert!(!HeicCloneModule.applies_to(&ctx("heic", None, None)), "bez przesłanki uszkodzenia nie dotykamy pliku");
    }

    #[test]
    fn test_nie_rusza_innych_formatow() {
        for ext in ["jpg", "png", "mp4", "dng", "txt"] {
            assert!(
                !HeicCloneModule.applies_to(&ctx(ext, Some(false), None)),
                "ext .{} nie należy do rodziny HEIF", ext
            );
        }
    }

    /// Lista rozszerzeń musi pochodzić z `heic_image`, a nie być tu
    /// zduplikowana — inaczej dodanie formatu w jednym miejscu ominęłoby drugie.
    #[test]
    fn test_rozpoznawanie_rozszerzen_pochodzi_z_heic_image() {
        for ext in ["heic", "heif", "avif"] {
            assert_eq!(
                crate::heic_image::is_heic_extension(&format!(".{}", ext)),
                HeicCloneModule.applies_to(&ctx(ext, Some(false), None)),
                "rozbieżność dla .{}", ext
            );
        }
    }

    // ------------------------------------------------------------------
    // Kolejność w dyspozytorze
    // ------------------------------------------------------------------

    /// Przeszczep od bliźniaka jest zawsze pełniejszy niż odbudowa z samego
    /// `mdat`, a bajtowe zszycie nie zna struktury ISOBMFF — stąd ta kolejność.
    #[test]
    fn test_kolejnosc_clone_przed_native_przed_splice() {
        let ids: Vec<&str> = super::super::all_modules().iter().map(|m| m.id()).collect();
        let poz = |id: &str| ids.iter().position(|x| *x == id)
            .unwrap_or_else(|| panic!("moduł {} musi być zarejestrowany (kolejność: {:?})", id, ids));

        assert!(poz("heic_clone") < poz("heic_native"), "kolejność: {:?}", ids);
        assert!(poz("heic_native") < poz("splice"), "kolejność: {:?}", ids);
    }

    /// Oba warianty kwalifikują tak samo — różni je wyłącznie to, czego
    /// wymagają do pracy. Dzięki temu brak bliźniaka przesuwa plik z jednego
    /// na drugi, zamiast wypadać z naprawy w ogóle.
    #[test]
    fn test_oba_warianty_kwalifikuja_tak_samo() {
        for kontekst in [ctx("heic", Some(false), None), ctx("heif", None, Some("Nagłówek")), ctx("jpg", Some(false), None)] {
            assert_eq!(
                HeicCloneModule.applies_to(&kontekst),
                HeicNativeModule.applies_to(&kontekst),
                "rozbieżna kwalifikacja dla .{}", kontekst.ext
            );
        }
    }

    // ------------------------------------------------------------------
    // repair
    // ------------------------------------------------------------------

    #[test]
    fn test_bez_dawcy_zwraca_none() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("zdjecie.heic");
        std::fs::write(&plik, b"nieistotne").unwrap();

        assert!(
            HeicCloneModule.repair(&plik, &ctx("heic", Some(false), None), None, dir.path()).is_none(),
            "przeszczep bez dawcy nie ma sensu"
        );
    }

    #[test]
    fn test_nieudana_naprawa_nie_zostawia_pliku() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        // Ani jeden, ani drugi nie jest kontenerem ISOBMFF.
        let plik = dir.path().join("nie_heic.heic");
        let dawca = dir.path().join("tez_nie.heic");
        std::fs::write(&plik, b"to nie jest heic").unwrap();
        std::fs::write(&dawca, b"to tez nie").unwrap();

        assert!(HeicCloneModule.repair(&plik, &ctx("heic", Some(false), None), Some(&dawca), &wynik).is_none());

        let pozostalo: Vec<String> = std::fs::read_dir(&wynik).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(pozostalo.is_empty(), "po nieudanej naprawie nie może zostać plik: {:?}", pozostalo);
    }

    #[test]
    fn test_nazwa_wyniku_zachowuje_rozszerzenie() {
        // Rozszerzenie decyduje o doborze metody weryfikacji, więc musi przeżyć.
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("w");
        std::fs::create_dir_all(&wynik).unwrap();

        let dawca_bajty = {
            let mut b = 16u32.to_be_bytes().to_vec();
            b.extend_from_slice(b"ftyp");
            b.extend_from_slice(b"heic\x00\x00\x00\x00");
            let mut meta = 14u32.to_be_bytes().to_vec();
            meta.extend_from_slice(b"meta");
            meta.extend_from_slice(b"INDEKS");
            b.extend(meta);
            let mut mdat = 40u32.to_be_bytes().to_vec();
            mdat.extend_from_slice(b"mdat");
            mdat.extend_from_slice(&[0xAAu8; 32]);
            b.extend(mdat);
            b
        };

        let plik = dir.path().join("foto.heif");
        let dawca = dir.path().join("dawca.heif");
        std::fs::write(&plik, &dawca_bajty).unwrap();
        std::fs::write(&dawca, &dawca_bajty).unwrap();

        let (cel, log) = HeicCloneModule
            .repair(&plik, &ctx("heif", Some(false), None), Some(&dawca), &wynik)
            .expect("identyczne kopie muszą się złożyć");

        assert_eq!(cel.extension().and_then(|e| e.to_str()), Some("heif"));
        assert!(log.contains("meta"), "log musi nazwać wykonaną operację: {}", log);
    }

    // ------------------------------------------------------------------
    // verify
    // ------------------------------------------------------------------

    #[test]
    fn test_weryfikacja_odrzuca_plik_ktory_nie_jest_heic() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("smieci.heic");
        std::fs::write(&plik, b"to nie jest obraz heic").unwrap();

        assert!(
            HeicCloneModule.verify(&plik, &ctx("heic", Some(false), None)).is_err(),
            "plik niebędący HEIC-iem musi zostać odrzucony"
        );
    }

    /// Odbudowany kafel HEVC musi dać się ODCZYTAĆ przez `libheif`.
    ///
    /// Test mieszkał w `mp4_engines::heic_native`, ale ten crate świadomie nie
    /// zależy od `libheif-rs` — wciąganie natywnej biblioteki C dla jednego
    /// testu obciążyłoby build obu projektów. Dowód dekodowalności należy więc
    /// do warstwy, która libheif i tak ma: modułu naprawczego.
    ///
    /// Zestawy parametrów HEVC pochodzą z `hvcC` fixture'a — patrz
    /// `mp4_engines::heic_native`, gdzie są wyjęte i opisane.
    #[test]
    #[ignore = "Wymaga image/test_fixture.heic i libheif. Uruchom z --ignored."]
    fn test_e2e_odbudowany_kafel_dekoduje_sie_przez_libheif() {
        use crate::mp4_repair::{boxes, heic_native};

        const VPS: [u8; 24] = [
            0x40, 0x01, 0x0c, 0x01, 0xff, 0xff, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00,
            0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x78, 0x3c, 0x09,
        ];
        const SPS: [u8; 36] = [
            0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00,
            0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x78, 0xa0, 0x04, 0x02, 0x00, 0x80,
            0x5a, 0x3d, 0x2b, 0xb2, 0x5b, 0xc0, 0x1b, 0x82, 0x83, 0x03, 0x00, 0x40,
        ];
        const PPS: [u8; 9] = [0x44, 0x01, 0xc0, 0x24, 0x11, 0x58, 0x19, 0x8c, 0x80];

        /// Dokleja 4-bajtowy prefiks długości NAL-a.
        fn z_prefiksem(nal: &[u8]) -> Vec<u8> {
            let mut v = (nal.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(nal);
            v
        }

        fn pudelko(typ: &[u8; 4], tresc: &[u8]) -> Vec<u8> {
            crate::test_fixtures::box_isobmff(typ, tresc)
        }

        let bajty = std::fs::read("image/test_fixture.heic").expect("fixture musi istnieć");
        let atomy = boxes::parse_top_level_boxes(&bajty);
        let mdat = boxes::find_box(&atomy, b"mdat").expect("fixture ma mdat");
        let (od, do_) = mdat.body_range();
        let dane = &bajty[od..do_];

        // Pierwszy duży slice IDR z 4-bajtowym prefiksem to pierwszy kafel.
        // Nie zakładamy offsetów bezwzględnych, żeby test nie zależał od
        // układu konkretnego pliku.
        let mut kafel = None;
        for p in 0..dane.len().saturating_sub(8) {
            let dl = u32::from_be_bytes([dane[p], dane[p + 1], dane[p + 2], dane[p + 3]]) as usize;
            if dl > 4096 && p + 4 + dl <= dane.len() {
                let typ = (dane[p + 4] >> 1) & 0x3F;
                if typ <= 31 && dane[p + 6] & 0x80 != 0 {
                    kafel = Some(dane[p + 4..p + 4 + dl].to_vec());
                    break;
                }
            }
        }
        let kafel = kafel.expect("w mdat musi być co najmniej jeden duży slice IDR");

        let mut ladunek = z_prefiksem(&VPS);
        ladunek.extend(z_prefiksem(&SPS));
        ladunek.extend(z_prefiksem(&PPS));
        ladunek.extend(z_prefiksem(&kafel));

        // Plik bez `meta` - dokładnie to, co Zero-Donor ma odbudować.
        let mut plik = pudelko(b"ftyp", b"heic\x00\x00\x00\x00mif1heic");
        plik.extend(pudelko(b"mdat", &ladunek));

        let odbudowa = heic_native::odbuduj_bajty(&plik)
            .expect("materiał z zestawami parametrów w pasmie musi się odbudować");
        assert_eq!((odbudowa.szerokosc, odbudowa.wysokosc), (512, 512));

        let obraz = crate::heic_image::decode_heic_bytes(&odbudowa.bajty)
            .expect("odbudowany HEIC musi dać się odczytać przez libheif");
        assert_eq!(
            (obraz.width, obraz.height), (512, 512),
            "libheif musi zgłosić wymiary kafla odczytane z odbudowanego `ispe`"
        );
    }

    /// Pełna ścieżka na PRAWDZIWYM pliku: psujemy indeks, naprawiamy z dawcy i
    /// weryfikujemy wynik przez `libheif`. To jedyny test, który dowodzi, że
    /// moduł działa na realnym materiale.
    #[test]
    #[ignore = "Wymaga image/test_fixture.heic i libheif. Uruchom z --ignored."]
    fn test_e2e_naprawa_prawdziwego_heic() {
        let zdrowy_bajty = std::fs::read("image/test_fixture.heic")
            .expect("fixture image/test_fixture.heic musi istnieć");

        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let dawca = dir.path().join("dawca.heic");
        std::fs::write(&dawca, &zdrowy_bajty).unwrap();

        // Psujemy treść atomu `meta` — indeks przestaje się nadawać do użytku,
        // ale dane obrazu w `mdat` są nietknięte.
        let atomy = crate::mp4_repair::boxes::parse_top_level_boxes(&zdrowy_bajty);
        let meta = crate::mp4_repair::boxes::find_box(&atomy, b"meta").unwrap();
        let (od, do_) = meta.body_range();

        let mut zepsute = zdrowy_bajty.clone();
        for b in &mut zepsute[od..do_] { *b = 0xFF; }

        let zepsuty = dir.path().join("zepsuty.heic");
        std::fs::write(&zepsuty, &zepsute).unwrap();

        let kontekst = ctx("heic", Some(false), None);

        // Kontrola sensu testu: zepsuty plik NIE MOŻE przechodzić weryfikacji.
        assert!(
            HeicCloneModule.verify(&zepsuty, &kontekst).is_err(),
            "plik z zepsutym indeksem nie powinien przechodzić weryfikacji - inaczej test nie mierzy naprawy"
        );

        let (naprawiony, _) = HeicCloneModule
            .repair(&zepsuty, &kontekst, Some(&dawca), &wynik)
            .expect("przeszczep od identycznej kopii musi się udać");

        assert!(
            HeicCloneModule.verify(&naprawiony, &kontekst).is_ok(),
            "naprawiony HEIC musi przejść weryfikację przez libheif"
        );
    }
}
