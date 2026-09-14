// src/phases/repair_modules/stream.rs

//! Moduły naprawcze strumieni: MPEG-TS i FLV — składanie z dwóch kopii.
//!
//! ## Dlaczego te dwa formaty trafiły tu na końcu
//!
//! PNG, ZIP i Matroska dały się naprawiać po fragmentach, bo każdy fragment
//! niesie **sumę kontrolną swojej treści**. TS i FLV takiej sumy nie mają — i
//! dlatego zostały na koniec, z otwartym pytaniem, czy da się tu cokolwiek
//! sensownego zrobić.
//!
//! Da się, ale trzeba nazwać rzecz po imieniu: oba formaty niosą obiektywne
//! sygnały **ramowania**, nie treści.
//!
//! | Format | Sędzia | Co dowodzi |
//! |---|---|---|
//! | MPEG-TS | `transport_error_indicator` + licznik ciągłości per PID | żaden pakiet nie zginął ani nie jest oznaczony jako błędny |
//! | FLV | `PreviousTagSize` za każdym tagiem | nagłówek tagu nie jest przekłamany |
//!
//! W TS flaga błędu jest **wpisana w format** — ustawia ją sprzęt na pakiecie,
//! który dotarł uszkodzony. W FLV długość tagu jest zapisana dwa razy, przed i
//! po danych, więc jej rozjazd dowodzi przekłamania.
//!
//! ## Gwarancja: SŁABA — i to nie jest formalność
//!
//! Poprawne ramowanie nie mówi nic o bajtach obrazu. Pakiet TS z czystym
//! licznikiem może nieść przekłamany payload, a tag FLV o zgodnej długości —
//! uszkodzoną klatkę. To ta sama klasa gwarancji co tar, gdzie suma chroni
//! wyłącznie nagłówki wpisów, i mocno słabsza niż PNG, ZIP czy Matroska.
//!
//! Etykietę wpisuje [`super::weryfikuj_naprawiony_plik`], które dostało dla
//! tych formatów osobne gałęzie — wcześniej wpadały w domyślny wariant „brak
//! metody weryfikacji", czyli bajtowe zszycie przez `splice` przechodziło bez
//! oporu.

use super::{RepairContext, RepairModule};
use std::path::{Path, PathBuf};

/// Górny limit rozmiaru pojedynczej kopii wczytywanej do składania.
///
/// Oba silniki wymagają OBU kopii w pamięci naraz, a Faza 17 pracuje
/// równolegle. Nagrania transportowe bywają wielogigabajtowe.
const LIMIT_W_RAM: u64 = 512 * 1024 * 1024; // 512 MB

/// Czy strumień nosi ślad uszkodzenia.
///
/// `video_ok == Some(false)` to wynik diagnostyki z Fazy 19, która dla TS
/// liczy utraty synchronizacji i luki ciągłości, a dla FLV błędy łańcucha.
/// `eof_ok == Some(false)` łapie plik ucięty, którego Faza 19 mogła nie zdążyć
/// zbadać.
fn nosi_slad_uszkodzenia(ctx: &RepairContext) -> bool {
    ctx.video_ok == Some(false) || ctx.eof_ok == Some(false)
}

/// Wczytuje obie kopie, pilnując limitu pamięci.
fn wczytaj_pare(uszkodzony: &Path, dawca: &Path) -> Option<(Vec<u8>, Vec<u8>)> {
    for sciezka in [uszkodzony, dawca] {
        let rozmiar = std::fs::metadata(sciezka).ok()?.len();
        if rozmiar > LIMIT_W_RAM {
            tracing::debug!(
                plik = %sciezka.display(), rozmiar, limit = LIMIT_W_RAM,
                "strumień przekracza limit składania w RAM"
            );
            return None;
        }
    }
    Some((std::fs::read(uszkodzony).ok()?, std::fs::read(dawca).ok()?))
}

/// Zapisuje wynik; przy nieudanym zapisie nie zostawia pliku-widma.
fn zapisz_wynik(cel: &Path, dane: &[u8]) -> bool {
    if let Some(katalog) = cel.parent()
        && std::fs::create_dir_all(katalog).is_err()
    {
        return false;
    }
    if std::fs::write(cel, dane).is_err() {
        let _ = std::fs::remove_file(cel);
        return false;
    }
    true
}

// ============================================================================
// MPEG-TS
// ============================================================================

pub struct TsSpliceModule;

impl RepairModule for TsSpliceModule {
    fn id(&self) -> &'static str { "ts_splice" }

    fn display_name(&self) -> &'static str {
        "MPEG-TS składanie pakietów z dwóch kopii (gwarancja SŁABA - dowodzi ramowania, nie treści)"
    }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        crate::ts_stream::is_ts_extension(&format!(".{}", ctx.ext)) && nosi_slad_uszkodzenia(ctx)
    }

    fn repair(&self, source: &Path, _ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let dawca = twin?;
        let (a, b) = wczytaj_pare(source, dawca)?;

        let wynik = crate::ts_stream::splice_ts(&a, &b)?;

        let stem = source.file_stem()?.to_str()?;
        let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("ts");
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_ts.{}", stem, ext));

        if !zapisz_wynik(&cel, &wynik) {
            return None;
        }

        Some((
            cel,
            format!(
                "Złożono strumień z dwóch kopii, wybierając pakiety bez flagi błędu transportu \
                 i z zachowaną ciągłością licznika (dawca: {}). \
                 UWAGA: potwierdzone poprawne RAMOWANIE, nie treść obrazu.",
                dawca.display()
            ),
        ))
    }
}

// ============================================================================
// FLV
// ============================================================================

pub struct FlvSpliceModule;

impl RepairModule for FlvSpliceModule {
    fn id(&self) -> &'static str { "flv_splice" }

    fn display_name(&self) -> &'static str {
        "FLV składanie tagów z dwóch kopii (gwarancja SŁABA - dowodzi ramowania, nie treści)"
    }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        crate::flv_stream::is_flv_extension(&format!(".{}", ctx.ext)) && nosi_slad_uszkodzenia(ctx)
    }

    fn repair(&self, source: &Path, _ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let dawca = twin?;
        let (a, b) = wczytaj_pare(source, dawca)?;

        let wynik = crate::flv_stream::splice_flv(&a, &b)?;

        let stem = source.file_stem()?.to_str()?;
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_flv.flv", stem));

        if !zapisz_wynik(&cel, &wynik) {
            return None;
        }

        Some((
            cel,
            format!(
                "Złożono kontener z dwóch kopii, wybierając tagi o domykającym się \
                 łańcuchu PreviousTagSize (dawca: {}). \
                 UWAGA: potwierdzone poprawne RAMOWANIE tagów, nie treść klatek.",
                dawca.display()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(ext: &'static str, video_ok: Option<bool>, eof_ok: Option<bool>) -> RepairContext<'static> {
        RepairContext {
            ext, media_reason: None, utf8_ok: None, is_oneliner: None,
            eof_ok, match_type: None, video_ok, structure_ok: None,
        }
    }

    // ------------------------------------------------------------------
    // Kwalifikacja
    // ------------------------------------------------------------------

    #[test]
    fn test_ts_obejmuje_cala_rodzine_strumieni() {
        for ext in ["ts", "m2ts", "mts"] {
            assert!(
                TsSpliceModule.applies_to(&ctx(ext, Some(false), None)),
                ".{} to strumień transportowy i musi być objęty", ext
            );
        }
    }

    #[test]
    fn test_kwalifikacja_po_diagnozie_fazy_19_i_po_ucieciu() {
        assert!(TsSpliceModule.applies_to(&ctx("ts", Some(false), None)));
        assert!(TsSpliceModule.applies_to(&ctx("ts", None, Some(false))));
        assert!(FlvSpliceModule.applies_to(&ctx("flv", Some(false), None)));
        assert!(FlvSpliceModule.applies_to(&ctx("flv", None, Some(false))));
    }

    #[test]
    fn test_zdrowe_strumienie_nie_sa_ruszane() {
        assert!(!TsSpliceModule.applies_to(&ctx("ts", Some(true), Some(true))));
        assert!(!TsSpliceModule.applies_to(&ctx("ts", None, None)));
        assert!(!FlvSpliceModule.applies_to(&ctx("flv", Some(true), Some(true))));
        assert!(!FlvSpliceModule.applies_to(&ctx("flv", None, None)));
    }

    #[test]
    fn test_moduly_nie_zachodza_na_siebie_ani_na_inne_formaty() {
        assert!(!TsSpliceModule.applies_to(&ctx("flv", Some(false), None)));
        assert!(!FlvSpliceModule.applies_to(&ctx("ts", Some(false), None)));

        for ext in ["mp4", "mkv", "webm", "jpg", "png", "zip"] {
            assert!(!TsSpliceModule.applies_to(&ctx(ext, Some(false), None)), "ext .{}", ext);
            assert!(!FlvSpliceModule.applies_to(&ctx(ext, Some(false), None)), "ext .{}", ext);
        }
    }

    /// Listy rozszerzeń muszą pochodzić z silników, nie być tu zduplikowane.
    #[test]
    fn test_listy_rozszerzen_pochodza_z_silnikow() {
        for ext in ["ts", "m2ts", "mts", "flv", "mp4", "mkv"] {
            assert_eq!(
                TsSpliceModule.applies_to(&ctx(ext, Some(false), None)),
                crate::ts_stream::is_ts_extension(&format!(".{}", ext)),
                "TS: rozbieżność dla .{}", ext
            );
            assert_eq!(
                FlvSpliceModule.applies_to(&ctx(ext, Some(false), None)),
                crate::flv_stream::is_flv_extension(&format!(".{}", ext)),
                "FLV: rozbieżność dla .{}", ext
            );
        }
    }

    #[test]
    fn test_oba_stoja_przed_splice() {
        let ids: Vec<&str> = super::super::all_modules().iter().map(|m| m.id()).collect();
        let poz = |id: &str| ids.iter().position(|x| *x == id)
            .unwrap_or_else(|| panic!("moduł {} musi być zarejestrowany (kolejność: {:?})", id, ids));

        assert!(poz("ts_splice") < poz("splice"), "kolejność: {:?}", ids);
        assert!(poz("flv_splice") < poz("splice"), "kolejność: {:?}", ids);
    }

    /// Nazwa modułu trafia do UI Fazy 17 i do dziennika — operator musi widzieć
    /// siłę gwarancji bez czytania kodu.
    #[test]
    fn test_nazwy_ujawniaja_slaba_gwarancje() {
        assert!(TsSpliceModule.display_name().contains("SŁABA"), "{}", TsSpliceModule.display_name());
        assert!(FlvSpliceModule.display_name().contains("SŁABA"), "{}", FlvSpliceModule.display_name());
    }

    // ------------------------------------------------------------------
    // Naprawa
    // ------------------------------------------------------------------

    #[test]
    fn test_bez_dawcy_oba_zwracaja_none() {
        let dir = tempfile::tempdir().unwrap();
        let ts = dir.path().join("a.ts");
        let flv = dir.path().join("a.flv");
        std::fs::write(&ts, b"x").unwrap();
        std::fs::write(&flv, b"x").unwrap();

        assert!(TsSpliceModule.repair(&ts, &ctx("ts", Some(false), None), None, dir.path()).is_none());
        assert!(FlvSpliceModule.repair(&flv, &ctx("flv", Some(false), None), None, dir.path()).is_none());
    }

    #[test]
    fn test_nieudana_naprawa_nie_zostawia_pliku() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        for (nazwa, modul) in [
            ("a.ts", &TsSpliceModule as &dyn RepairModule),
            ("a.flv", &FlvSpliceModule as &dyn RepairModule),
        ] {
            let plik = dir.path().join(nazwa);
            let dawca = dir.path().join(format!("dawca_{}", nazwa));
            std::fs::write(&plik, b"to nie jest strumien").unwrap();
            std::fs::write(&dawca, b"to tez nie").unwrap();

            let ext: &'static str = if nazwa.ends_with("ts") { "ts" } else { "flv" };
            assert!(modul.repair(&plik, &ctx(ext, Some(false), None), Some(&dawca), &wynik).is_none(), "{}", nazwa);
        }

        assert_eq!(std::fs::read_dir(&wynik).unwrap().count(), 0, "po odmowie nie może zostać plik");
    }

    // ------------------------------------------------------------------
    // MPEG-TS na materiale z PRAWDZIWEGO kodera
    // ------------------------------------------------------------------

    use crate::test_fixtures::ffmpeg_dostepny as ffmpeg_jest;

    /// Koduje prawdziwy strumień transportowy.
    ///
    /// Materiał ma komplet struktur, jakich spodziewamy się po nagraniu: PAT
    /// (PID 0), PMT, SDT i strumień wideo — a nie tylko pakiety, które sami
    /// byśmy poskładali.
    fn zakoduj_ts(katalog: &Path) -> Vec<u8> {
        let cel = katalog.join("zrodlo.ts");
        let status = std::process::Command::new("ffmpeg")
            .args(["-nostdin", "-loglevel", "quiet", "-y", "-f", "lavfi", "-i",
                   "testsrc=size=320x240:rate=25:duration=2",
                   "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p",
                   "-f", "mpegts"])
            .arg(&cel).status().expect("uruchomienie ffmpeg");
        assert!(status.success(), "kodowanie strumienia TS musi się udać");
        std::fs::read(&cel).expect("odczyt strumienia")
    }

    /// Sedno składania TS na prawdziwym materiale: jedna kopia traci
    /// synchronizację pakietu, druga jest zdrowa — wynik musi być bajtowo
    /// równy oryginałowi.
    #[test]
    #[ignore = "Wymaga ffmpeg. Uruchom z --ignored."]
    fn test_e2e_ts_odzyskuje_pakiet_bez_synchronizacji() {
        if !ffmpeg_jest() { panic!("brak ffmpeg - test wymaga prawdziwego kodera"); }

        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = zakoduj_ts(dir.path());
        let rozmiar_pakietu = crate::ts_stream::TS_PACKET_SIZE;
        assert!(zdrowy.len() / rozmiar_pakietu > 50, "materiał musi mieć sensowną liczbę pakietów");

        // Kontrola sensu testu: materiał wyjściowy jest zdrowy.
        let analiza = crate::ts_stream::analyze_ts(&zdrowy).expect("ffmpeg musi dać rozpoznawalny TS");
        assert!(analiza.is_healthy(), "materiał źródłowy musi być zdrowy: {}", analiza.describe());

        // Niszczymy jeden pakiet w środku strumienia - znika bajt
        // synchronizacji, co jest klasycznym objawem uszkodzenia nośnika.
        let numer = 30;
        let mut zepsuty = zdrowy.clone();
        for b in &mut zepsuty[numer * rozmiar_pakietu..(numer + 1) * rozmiar_pakietu] {
            *b = 0x00;
        }

        let po_uszkodzeniu = crate::ts_stream::analyze_ts(&zepsuty).expect("nadal rozpoznawalny");
        assert!(!po_uszkodzeniu.is_healthy(), "uszkodzony strumień nie może uchodzić za zdrowy");

        let p_zepsuty = dir.path().join("nagranie.ts");
        let p_dawca = dir.path().join("blizniak.ts");
        std::fs::write(&p_zepsuty, &zepsuty).unwrap();
        std::fs::write(&p_dawca, &zdrowy).unwrap();

        let kontekst = ctx("ts", Some(false), None);
        let (naprawiony, log) = TsSpliceModule
            .repair(&p_zepsuty, &kontekst, Some(&p_dawca), &wynik)
            .expect("składanie ze zdrowego bliźniaka musi się udać");

        assert!(log.contains("RAMOWANIE"), "log musi ujawnić granicę dowodu: {}", log);
        assert_eq!(
            std::fs::read(&naprawiony).unwrap(), zdrowy,
            "utrata pojedynczego pakietu jest w pełni odwracalna - wynik musi równać się oryginałowi"
        );

        let ocena = TsSpliceModule.verify(&naprawiony, &kontekst).expect("wynik musi przejść weryfikację");
        assert!(ocena.contains("SŁABA"), "TS daje gwarancję SŁABĄ: {}", ocena);
    }

    /// Flaga błędu transportu na PRAWDZIWYM pakiecie wideo.
    ///
    /// Ten test ćwiczy sędziego, którego nie da się pokazać na uszkodzeniu
    /// synchronizacji: pakiet jest kompletny i poprawnie umieszczony w siatce,
    /// a mimo to oznaczony przez sprzęt jako błędny.
    #[test]
    #[ignore = "Wymaga ffmpeg. Uruchom z --ignored."]
    fn test_e2e_ts_odrzuca_pakiet_z_flaga_bledu_transportu() {
        if !ffmpeg_jest() { panic!("brak ffmpeg - test wymaga prawdziwego kodera"); }

        let dir = tempfile::tempdir().unwrap();
        let zdrowy = zakoduj_ts(dir.path());
        let rozmiar_pakietu = crate::ts_stream::TS_PACKET_SIZE;

        let numer = 40;
        let mut zepsuty = zdrowy.clone();
        zepsuty[numer * rozmiar_pakietu + 1] |= crate::ts_stream::MASKA_BLEDU_TRANSPORTU;

        assert_ne!(zepsuty, zdrowy, "kontrola: materiał faktycznie się różni");

        // Diagnostyka MUSI zauważyć oflagowany pakiet - inaczej Faza 19
        // zapisałaby `video_ok = true` i ten moduł nigdy by się nie
        // zakwalifikował, mimo że potrafi taki pakiet zastąpić.
        let analiza = crate::ts_stream::analyze_ts(&zepsuty).expect("nadal rozpoznawalny TS");
        assert_eq!(analiza.transport_errors, 1, "flaga błędu transportu musi zostać policzona");
        assert!(
            !analiza.is_healthy(),
            "strumień z oflagowanym pakietem nie może uchodzić za spójny: {}", analiza.describe()
        );
        assert!(analiza.describe().contains("flagą błędu transportu"), "opis: {}", analiza.describe());

        let zlozony = crate::ts_stream::splice_ts(&zepsuty, &zdrowy)
            .expect("kopia zdrowa ma ten pakiet bez flagi błędu");

        assert_eq!(
            zlozony, zdrowy,
            "pakiet z flagą błędu musi zostać zastąpiony wersją z drugiej kopii"
        );
        assert_eq!(
            zlozony[numer * rozmiar_pakietu + 1] & crate::ts_stream::MASKA_BLEDU_TRANSPORTU, 0,
            "wynik nie może nieść flagi błędu transportu"
        );
    }

    /// Pełna ścieżka na PRAWDZIWYM pliku FLV z `image/`.
    #[test]
    #[ignore = "Wymaga image/test_fixture.flv. Uruchom z --ignored."]
    fn test_e2e_flv_z_uszkodzonym_lancuchem() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = std::fs::read("image/test_fixture.flv").unwrap();

        // Psujemy pole PreviousTagSize pierwszego tagu - łańcuch się rozjeżdża,
        // a dane klatek pozostają nietknięte.
        let poczatek = crate::flv_stream::poczatek_tagow(&zdrowy).expect("fixture ma czytelny nagłówek");
        let pierwszy = crate::flv_stream::tag_pod(&zdrowy, poczatek).expect("fixture ma tagi");
        let pole = pierwszy.offset + pierwszy.dlugosc_calkowita - 4;

        let mut zepsuty = zdrowy.clone();
        zepsuty[pole] ^= 0xFF;

        let p_zepsuty = dir.path().join("film.flv");
        let p_dawca = dir.path().join("blizniak.flv");
        std::fs::write(&p_zepsuty, &zepsuty).unwrap();
        std::fs::write(&p_dawca, &zdrowy).unwrap();

        let kontekst = ctx("flv", Some(false), None);

        let (naprawiony, log) = FlvSpliceModule
            .repair(&p_zepsuty, &kontekst, Some(&p_dawca), &wynik)
            .expect("składanie ze zdrowego bliźniaka musi się udać");

        assert!(log.contains("PreviousTagSize"), "log musi nazwać kryterium: {}", log);
        assert!(log.contains("RAMOWANIE"), "log musi ujawnić granicę dowodu: {}", log);

        assert_eq!(
            std::fs::read(&naprawiony).unwrap(), zdrowy,
            "naprawa uszkodzenia samego łańcucha musi odtworzyć oryginał bajt w bajt"
        );

        let ocena = FlvSpliceModule.verify(&naprawiony, &kontekst).expect("wynik musi przejść weryfikację");
        assert!(ocena.contains("SŁABA"), "FLV daje gwarancję SŁABĄ: {}", ocena);
    }
}
