// src/phases/repair_modules/jpeg.rs

//! Moduł naprawczy JPEG — przeszczep tablic DQT/DHT/SOF z bliźniaczej kopii.
//!
//! ## Miejsce w kolejce i relacja do `header_jpg`
//!
//! Ten moduł stoi **przed** [`super::header_jpg`], bo przenosi prawdziwe
//! tablice tego konkretnego zdjęcia, a `header_jpg` potrafi tylko wstrzyknąć
//! sztuczny, minimalny nagłówek JFIF. Oba warunki kwalifikacji zachodzą na
//! siebie, więc kolejność decyduje o jakości wyniku.
//!
//! Zależność jest jednak nieszkodliwa w drugą stronę: bez bliźniaka ten moduł
//! zwraca `None`, a dyspozytor Fazy 17 przechodzi wtedy do następnego modułu
//! na liście — czyli `header_jpg` nadal dostaje swoją szansę. Degradacja jest
//! więc łagodna: mamy bliźniaka to naprawiamy porządnie, nie mamy to
//! przynajmniej próbujemy wstrzyknięcia.
//!
//! Silnik i jego ograniczenia opisuje [`crate::jpeg_splice`].

use super::{RepairContext, RepairModule, WynikWeryfikacji};
use crate::jpeg_splice;
use std::path::{Path, PathBuf};

pub struct JpegCloneModule;

/// Rozszerzenia obsługiwane przez przeszczep.
///
/// Świadomie NIE obejmuje `.jfif`/`.jpe`: Faza 12 nie klasyfikuje ich jako
/// obrazów, więc nie dostarczyłaby przesłanki uszkodzenia, a weryfikacja w
/// [`super::weryfikuj_naprawiony_plik`] nie ma dla nich gałęzi dekodowania.
/// Dodanie ich wymagałoby zmiany w tych trzech miejscach naraz.
const ROZSZERZENIA: [&str; 2] = ["jpg", "jpeg"];

/// Rozstrzyga, czy plik jest uszkodzonym JPEG-iem.
///
/// Przesłanki uszkodzenia: powód z Fazy 12 zawierający `"Nagłówek"` albo brak
/// znacznika końca z Fazy 6. Pierwsza łapie zniszczone tablice, druga plik
/// ucięty — przeszczep pomaga w obu, bo w obu nagłówek bliźniaka jest
/// wiarygodniejszy od tego, co zostało.
fn jest_uszkodzonym_jpeg(ctx: &RepairContext) -> bool {
    if !ROZSZERZENIA.contains(&ctx.ext) {
        return false;
    }

    ctx.eof_ok == Some(false) || ctx.media_reason.is_some_and(|r| r.contains("Nagłówek"))
}

impl RepairModule for JpegCloneModule {
    fn id(&self) -> &'static str { "jpeg_clone" }

    fn display_name(&self) -> &'static str {
        "JPEG przeszczep tablic DQT/DHT/SOF z bliźniaczej kopii"
    }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        jest_uszkodzonym_jpeg(ctx)
    }

    /// Składa sprawny plik z nagłówka bliźniaczej kopii i danych skanu pliku
    /// uszkodzonego.
    ///
    /// Zwraca `None`, gdy bliźniak nie został podany albo gdy silnik odmówił
    /// złożenia (np. kopie opisują różne wymiary) — w obu przypadkach kolejny
    /// moduł na liście dostaje szansę.
    fn repair(&self, source: &Path, _ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let dawca = twin?;

        let stem = source.file_stem()?.to_str()?;
        let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("jpg");
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_jpeg.{}", stem, ext));

        match jpeg_splice::repair(source.to_str()?, dawca.to_str()?, cel.to_str()?) {
            Ok(()) => {
                // Opis czytamy z plików PO udanej naprawie, żeby dziennik
                // operacyjny mówił, co konkretnie zostało przeniesione.
                let opis = match (std::fs::read(source), std::fs::read(dawca)) {
                    (Ok(u), Ok(d)) => jpeg_splice::opis_przeszczepu(&u, &d),
                    _ => "przeniesiono nagłówek dawcy, dane skanu zachowane z kopii uszkodzonej".to_string(),
                };
                Some((cel, format!("{} (dawca: {})", opis, dawca.display())))
            }
            Err(e) => {
                tracing::debug!(
                    plik = %source.display(), dawca = %dawca.display(), blad = %e,
                    "jpeg_clone: przeszczep nieudany"
                );
                // Silnik zapisuje wynik dopiero po udanym złożeniu, ale gdyby
                // padł sam zapis, nie zostawiamy pozornej naprawy.
                let _ = std::fs::remove_file(&cel);
                None
            }
        }
    }

    /// Weryfikacja przez realne dekodowanie pikseli — gwarancja MOCNA.
    ///
    /// Nadpisane jawnie (mimo że domyślna implementacja trafiłaby w tę samą
    /// gałąź), żeby siła gwarancji tego modułu była widoczna w jego własnym
    /// kodzie. Uwaga: dekodowanie dowodzi, że nagłówek pasuje do skanu — nie
    /// dowodzi, że piksele są identyczne z oryginałem.
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
            eof_ok, match_type: None, video_ok: None, structure_ok: None
        }
    }

    // Materiał testowy pochodzi z silnika, żeby model uszkodzenia był
    // DOKŁADNIE ten sam, co w testach `jpeg_splice` - patrz uzasadnienie przy
    // `jpeg_splice::pomoce_testowe`.
    use jpeg_splice::pomoce_testowe::{zdrowy_jpeg, zepsuj_naglowek};

    // ------------------------------------------------------------------
    // applies_to
    // ------------------------------------------------------------------

    #[test]
    fn test_stosuje_sie_do_jpg_i_jpeg() {
        for ext in ["jpg", "jpeg"] {
            assert!(
                JpegCloneModule.applies_to(&ctx(ext, Some(false), None)),
                "rozszerzenie .{} musi być rozpoznane", ext
            );
        }
    }

    #[test]
    fn test_reaguje_na_powod_z_fazy12() {
        assert!(JpegCloneModule.applies_to(&ctx("jpg", None, Some("Zniszczony Nagłówek obrazu"))));
    }

    #[test]
    fn test_nie_rusza_zdrowego_jpeg() {
        assert!(!JpegCloneModule.applies_to(&ctx("jpg", Some(true), None)));
        assert!(!JpegCloneModule.applies_to(&ctx("jpg", None, None)), "bez przesłanki uszkodzenia nie dotykamy pliku");
    }

    #[test]
    fn test_nie_rusza_innych_formatow() {
        for ext in ["png", "heic", "dng", "mp4", "txt"] {
            assert!(
                !JpegCloneModule.applies_to(&ctx(ext, Some(false), None)),
                "ext .{} nie należy do tego modułu", ext
            );
        }
    }

    /// Ten moduł i `header_jpg` celowo zachodzą na siebie — kolejność w
    /// `all_modules()` decyduje, który spróbuje pierwszy. Test pilnuje, żeby
    /// przeszczep nie wypadł przypadkiem za wstrzyknięcie nagłówka.
    #[test]
    fn test_stoi_przed_header_jpg_w_kolejce() {
        let ids: Vec<&str> = super::super::all_modules().iter().map(|m| m.id()).collect();
        let i_clone = ids.iter().position(|id| *id == "jpeg_clone").expect("jpeg_clone musi być zarejestrowany");
        let i_header = ids.iter().position(|id| *id == "header_jpg").expect("header_jpg musi być zarejestrowany");

        assert!(
            i_clone < i_header,
            "przeszczep prawdziwych tablic musi być próbowany przed wstrzyknięciem sztucznego nagłówka (kolejność: {:?})",
            ids
        );
    }

    /// `splice` łapie dowolne rozszerzenie przy `match_type = PARTIAL`, więc
    /// bez tej kolejności bajtowe zszycie wyprzedziłoby naprawę świadomą
    /// struktury.
    #[test]
    fn test_stoi_przed_splice() {
        let ids: Vec<&str> = super::super::all_modules().iter().map(|m| m.id()).collect();
        let i_clone = ids.iter().position(|id| *id == "jpeg_clone").unwrap();
        let i_splice = ids.iter().position(|id| *id == "splice").expect("splice musi być zarejestrowany");
        assert!(i_clone < i_splice, "kolejność: {:?}", ids);
    }

    // ------------------------------------------------------------------
    // repair
    // ------------------------------------------------------------------

    #[test]
    fn test_bez_dawcy_zwraca_none() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("zdjecie.jpg");
        std::fs::write(&plik, zdrowy_jpeg(32, 32)).unwrap();

        assert!(
            JpegCloneModule.repair(&plik, &ctx("jpg", Some(false), None), None, dir.path()).is_none(),
            "przeszczep bez dawcy nie ma sensu - miejsce dla header_jpg"
        );
    }

    #[test]
    fn test_nieudana_naprawa_nie_zostawia_pliku() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let plik = dir.path().join("nie_jpeg.jpg");
        let dawca = dir.path().join("tez_nie.jpg");
        std::fs::write(&plik, b"to nie jest jpeg").unwrap();
        std::fs::write(&dawca, b"to tez nie").unwrap();

        assert!(JpegCloneModule.repair(&plik, &ctx("jpg", Some(false), None), Some(&dawca), &wynik).is_none());

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

        let zdrowy = zdrowy_jpeg(48, 32);
        let plik = dir.path().join("foto.jpeg");
        let dawca = dir.path().join("dawca.jpeg");
        std::fs::write(&plik, zepsuj_naglowek(&zdrowy)).unwrap();
        std::fs::write(&dawca, &zdrowy).unwrap();

        let (cel, log) = JpegCloneModule
            .repair(&plik, &ctx("jpeg", Some(false), None), Some(&dawca), &wynik)
            .expect("przeszczep od bliźniaka musi się udać");

        assert_eq!(cel.extension().and_then(|e| e.to_str()), Some("jpeg"));
        assert!(log.contains("DQT"), "log musi nazwać przeniesione tablice: {}", log);
        assert!(log.contains("dawca"), "log musi wskazać dawcę: {}", log);
    }

    // ------------------------------------------------------------------
    // Pełna ścieżka: kwalifikacja -> naprawa -> weryfikacja
    // ------------------------------------------------------------------

    #[test]
    fn test_e2e_naprawa_i_weryfikacja() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = zdrowy_jpeg(120, 80);
        let zepsuty = zepsuj_naglowek(&zdrowy);

        let p_zepsuty = dir.path().join("zdjecie.jpg");
        let p_dawca = dir.path().join("blizniak.jpg");
        std::fs::write(&p_zepsuty, &zepsuty).unwrap();
        std::fs::write(&p_dawca, &zdrowy).unwrap();

        let kontekst = ctx("jpg", Some(false), None);

        assert!(JpegCloneModule.applies_to(&kontekst), "plik musi się kwalifikować");

        // Kontrola sensu testu: zepsuty plik NIE MOŻE przechodzić weryfikacji.
        assert!(
            JpegCloneModule.verify(&p_zepsuty, &kontekst).is_err(),
            "plik ze zniszczonym nagłówkiem nie powinien przechodzić weryfikacji - inaczej test nie mierzy naprawy"
        );

        let (naprawiony, _) = JpegCloneModule
            .repair(&p_zepsuty, &kontekst, Some(&p_dawca), &wynik)
            .expect("przeszczep musi się udać");

        let ocena = JpegCloneModule.verify(&naprawiony, &kontekst).expect("naprawiony JPEG musi przejść weryfikację");
        assert!(ocena.contains("MOCNA"), "weryfikacja JPEG daje gwarancję MOCNĄ, dostaliśmy: {}", ocena);
    }

    #[test]
    fn test_weryfikacja_odrzuca_plik_ktory_nie_jest_obrazem() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("smieci.jpg");
        std::fs::write(&plik, b"to nie jest obraz").unwrap();

        assert!(
            JpegCloneModule.verify(&plik, &ctx("jpg", Some(false), None)).is_err(),
            "plik niebędący obrazem musi zostać odrzucony"
        );
    }
}
