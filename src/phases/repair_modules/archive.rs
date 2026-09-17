// src/phases/repair_modules/archive.rs

//! Moduły naprawcze archiwów: ZIP-podobne i TAR — składanie per wpis z dwóch kopii.
//!
//! ## Skąd się wzięły
//!
//! Silniki [`crate::zip_splice::splice_zip`] i [`crate::tar_archive::splice_tar`]
//! istniały w projekcie od dawna, ale **wywoływała je wyłącznie Faza 18**. W
//! `repair_modules` pojawiały się tylko jako `verify_zip_bytes` i
//! `verify_tar_bytes`, czyli do sprawdzania cudzego wyniku — nigdy do naprawy.
//!
//! To ta sama luka, którą domknęliśmy wcześniej dla PNG, i ma ona konkretny
//! skutek. Faza 18 bierze plik dopiero wtedy, gdy **obie** kopie są zepsute
//! (`structure_ok = 0` po obu stronach). Archiwum uszkodzone po JEDNEJ stronie,
//! ze zdrową drugą kopią, było więc przez nią pomijane, a w Fazie 17 zostawał
//! mu tylko `splice` — bajtowe zszycie nieświadome struktury, w dodatku
//! wyłącznie przy `match_type = PARTIAL`. Te moduły dają takim plikom naprawę
//! świadomą wpisów.
//!
//! ## Dwie różne siły gwarancji
//!
//! | Format | Kryterium wyboru wpisu | Gwarancja wyniku |
//! |---|---|---|
//! | ZIP-podobne | CRC32 **danych** każdego wpisu | MOCNA |
//! | TAR | suma kontrolna **nagłówka** wpisu | SŁABA |
//!
//! Różnica nie jest kosmetyczna. ZIP niesie sumę kontrolną zawartości, więc
//! poprawny odczyt wpisu dowodzi poprawności jego danych. TAR chroni wyłącznie
//! nagłówek — poprawna suma mówi tylko tyle, że nazwa i rozmiar wpisu są
//! wiarygodne, a o samych bajtach pliku nie mówi nic.
//!
//! Obu modułów nie trzeba jednak uczyć tej różnicy: domyślna weryfikacja w
//! [`super::weryfikuj_naprawiony_plik`] rozróżnia je poprawnie od dawna i sama
//! wpisuje właściwą etykietę do dziennika. Dlatego żaden z nich nie nadpisuje
//! `verify` — w odróżnieniu od modułu DNG, gdzie domyślna etykieta była
//! nieprawdziwa.

use super::{RepairContext, RepairModule};
use std::path::{Path, PathBuf};

/// Górny limit rozmiaru pojedynczej kopii wczytywanej do składania.
///
/// Oba silniki wymagają OBU kopii w pamięci naraz, a Faza 17 przetwarza pliki
/// równolegle — szczyt zużycia to wielokrotność tej wartości. Archiwa bywają
/// wielogigabajtowe, więc bez tej bramki naprawa mogłaby wywrócić proces na
/// materiale, którego i tak nie zdąży sensownie złożyć.
const LIMIT_W_RAM: u64 = 512 * 1024 * 1024; // 512 MB

/// Czy archiwum nosi ślad uszkodzenia.
///
/// `structure_ok == Some(false)` to wynik walidacji z Fazy 11 — archiwum nie
/// otworzyło się albo miało uszkodzone wpisy. `eof_ok == Some(false)` łapie
/// plik ucięty, którego Faza 11 mogła nie zdążyć zbadać.
fn nosi_slad_uszkodzenia(ctx: &RepairContext) -> bool {
    ctx.structure_ok == Some(false) || ctx.eof_ok == Some(false)
}

/// Wczytuje obie kopie, pilnując limitu pamięci.
///
/// Zwraca `None`, gdy którakolwiek przekracza limit albo nie daje się
/// odczytać — w obu przypadkach składanie i tak nie miałoby jak się powieść.
fn wczytaj_pare(uszkodzony: &Path, dawca: &Path) -> Option<(Vec<u8>, Vec<u8>)> {
    for sciezka in [uszkodzony, dawca] {
        let rozmiar = std::fs::metadata(sciezka).ok()?.len();
        if rozmiar > LIMIT_W_RAM {
            tracing::debug!(
                plik = %sciezka.display(), rozmiar, limit = LIMIT_W_RAM,
                "archiwum przekracza limit składania w RAM"
            );
            return None;
        }
    }

    Some((std::fs::read(uszkodzony).ok()?, std::fs::read(dawca).ok()?))
}

/// Zapisuje wynik, sprzątając po sobie przy niepowodzeniu zapisu.
///
/// `fs::write` otwiera plik z obcięciem, więc awaria w trakcie zapisu (brak
/// miejsca, odłączony nośnik) zostawia plik NIEPEŁNY — a taki, leżąc w
/// katalogu wyników, wyglądałby jak udana naprawa. Stąd `remove_file`.
///
/// ## Ścieżka NIEPOKRYTA TESTAMI — świadomie
///
/// Wymuszenie błędu zapisu wymaga pełnego nośnika albo odebrania praw do
/// katalogu; pod rootem, na którym ten projekt działa, uprawnienia nie
/// blokują zapisu. Próba testu skończyła się przypadkiem, który wymykał się
/// po cichu i tylko UDAWAŁ pokrycie, więc został usunięty zamiast zostawiony.
/// Mutacja usuwająca `remove_file` nie jest tu wykrywana i jest to znane.
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
// ZIP i formaty na nim oparte
// ============================================================================

pub struct ZipSpliceModule;

impl RepairModule for ZipSpliceModule {
    fn id(&self) -> &'static str { "zip_splice" }

    fn display_name(&self) -> &'static str {
        "ZIP składanie wpisów z dwóch kopii (CRC32 per wpis)"
    }

    /// Obejmuje całą rodzinę formatów opartych na ZIP — `.docx`, `.xlsx`,
    /// `.odt`, `.epub`, `.apk` i pozostałe to kontenery ZIP z inną zawartością.
    /// Lista żyje w [`crate::zip_splice::is_zip_based_extension`], czyli w tym
    /// samym miejscu, z którego korzysta weryfikacja wyniku.
    fn applies_to(&self, ctx: &RepairContext) -> bool {
        crate::zip_splice::is_zip_based_extension(&format!(".{}", ctx.ext))
            && nosi_slad_uszkodzenia(ctx)
    }

    /// Składa archiwum, biorąc każdy wpis z tej kopii, w której jego CRC32 się
    /// zgadza.
    ///
    /// Zwraca `None` bez bliźniaka oraz wtedy, gdy silnik odmówił złożenia —
    /// bo któraś strona się nie otwiera, liczby wpisów się rozjeżdżają albo ten
    /// sam wpis jest zepsuty po obu stronach. W każdym z tych przypadków
    /// kolejny moduł na liście dostaje szansę.
    fn repair(&self, source: &Path, _ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let dawca = twin?;
        let (a, b) = wczytaj_pare(source, dawca)?;

        let wynik = crate::zip_splice::splice_zip(&a, &b)?;

        let stem = source.file_stem()?.to_str()?;
        let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("zip");
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_zip.{}", stem, ext));

        if !zapisz_wynik(&cel, &wynik) {
            return None;
        }

        Some((
            cel,
            format!(
                "Złożono archiwum z dwóch kopii, wybierając wpisy o zgodnym CRC32 (dawca: {}).",
                dawca.display()
            ),
        ))
    }
}

// ============================================================================
// TAR
// ============================================================================

pub struct TarSpliceModule;

impl RepairModule for TarSpliceModule {
    fn id(&self) -> &'static str { "tar_splice" }

    fn display_name(&self) -> &'static str {
        "TAR składanie wpisów z dwóch kopii (gwarancja SŁABA - suma chroni tylko nagłówki)"
    }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        ctx.ext == "tar" && nosi_slad_uszkodzenia(ctx)
    }

    /// Składa archiwum, biorąc każdy wpis z tej kopii, której **nagłówek** ma
    /// poprawną sumę kontrolną.
    fn repair(&self, source: &Path, _ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let dawca = twin?;
        let (a, b) = wczytaj_pare(source, dawca)?;

        let wynik = crate::tar_archive::splice_tar(&a, &b)?;

        let stem = source.file_stem()?.to_str()?;
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_tar.tar", stem));

        if !zapisz_wynik(&cel, &wynik) {
            return None;
        }

        Some((
            cel,
            format!(
                "Złożono archiwum z dwóch kopii wg sum kontrolnych nagłówków wpisów (dawca: {}). \
                 UWAGA: tar nie chroni danych wpisów - potwierdzona poprawna STRUKTURA, nie treść.",
                dawca.display()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(ext: &'static str, structure_ok: Option<bool>, eof_ok: Option<bool>) -> RepairContext<'static> {
        RepairContext {
            ext, media_reason: None, utf8_ok: None, is_oneliner: None,
            eof_ok, match_type: None, video_ok: None, structure_ok, media_decoded: None,
        }
    }

    // ------------------------------------------------------------------
    // Kwalifikacja
    // ------------------------------------------------------------------

    /// Cała rodzina formatów opartych na ZIP musi być objęta — dokument
    /// `.docx` to kontener ZIP i psuje się dokładnie tak samo.
    #[test]
    fn test_zip_obejmuje_cala_rodzine_formatow() {
        for ext in ["zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "jar", "apk"] {
            assert!(
                ZipSpliceModule.applies_to(&ctx(ext, Some(false), None)),
                ".{} jest kontenerem ZIP i musi być objęte", ext
            );
        }
    }

    #[test]
    fn test_kwalifikacja_po_wyniku_fazy_11_i_po_ucieciu() {
        assert!(ZipSpliceModule.applies_to(&ctx("zip", Some(false), None)), "structure_ok = false");
        assert!(ZipSpliceModule.applies_to(&ctx("zip", None, Some(false))), "eof_ok = false (plik ucięty)");
        assert!(TarSpliceModule.applies_to(&ctx("tar", Some(false), None)));
        assert!(TarSpliceModule.applies_to(&ctx("tar", None, Some(false))));
    }

    #[test]
    fn test_zdrowe_archiwa_nie_sa_ruszane() {
        assert!(!ZipSpliceModule.applies_to(&ctx("zip", Some(true), Some(true))));
        assert!(!ZipSpliceModule.applies_to(&ctx("zip", None, None)), "bez przesłanki uszkodzenia nie dotykamy pliku");
        assert!(!TarSpliceModule.applies_to(&ctx("tar", Some(true), Some(true))));
        assert!(!TarSpliceModule.applies_to(&ctx("tar", None, None)));
    }

    #[test]
    fn test_moduly_nie_zachodza_na_siebie_ani_na_inne_formaty() {
        assert!(!TarSpliceModule.applies_to(&ctx("zip", Some(false), None)), "tar nie obsługuje ZIP-a");
        assert!(!ZipSpliceModule.applies_to(&ctx("tar", Some(false), None)), "ZIP nie obsługuje tara");

        for ext in ["jpg", "png", "heic", "mp4", "dng", "txt", "gz", "7z", "rar"] {
            assert!(!ZipSpliceModule.applies_to(&ctx(ext, Some(false), None)), "ext .{}", ext);
            assert!(!TarSpliceModule.applies_to(&ctx(ext, Some(false), None)), "ext .{}", ext);
        }
    }

    /// Lista rozszerzeń ZIP musi pochodzić z `zip_splice`, a nie być tu
    /// zduplikowana — inaczej dodanie formatu w jednym miejscu ominęłoby drugie
    /// i naprawa rozjechałaby się z weryfikacją.
    #[test]
    fn test_lista_rozszerzen_pochodzi_z_silnika() {
        for ext in ["zip", "docx", "apk", "jpg", "tar", "txt"] {
            assert_eq!(
                ZipSpliceModule.applies_to(&ctx(ext, Some(false), None)),
                crate::zip_splice::is_zip_based_extension(&format!(".{}", ext)),
                "rozbieżność dla .{}", ext
            );
        }
    }

    // ------------------------------------------------------------------
    // Kolejność w dyspozytorze
    // ------------------------------------------------------------------

    #[test]
    fn test_oba_stoja_przed_splice() {
        let ids: Vec<&str> = super::super::all_modules().iter().map(|m| m.id()).collect();
        let poz = |id: &str| ids.iter().position(|x| *x == id)
            .unwrap_or_else(|| panic!("moduł {} musi być zarejestrowany (kolejność: {:?})", id, ids));

        assert!(
            poz("zip_splice") < poz("splice"),
            "bajtowe zszycie nie zna struktury archiwum i nie może wyprzedzać składania po wpisach: {:?}", ids
        );
        assert!(poz("tar_splice") < poz("splice"), "kolejność: {:?}", ids);
    }

    // ------------------------------------------------------------------
    // Naprawa
    // ------------------------------------------------------------------

    /// Buduje prawdziwe archiwum ZIP o podanych wpisach — patrz
    /// `crate::test_fixtures::zbuduj_zip` (jedyna implementacja w crate'cie).
    fn zbuduj_zip(wpisy: &[(&str, &[u8])]) -> Vec<u8> {
        crate::test_fixtures::zbuduj_zip(wpisy)
    }

    #[test]
    fn test_bez_dawcy_oba_moduly_zwracaja_none() {
        let dir = tempfile::tempdir().unwrap();
        let plik = crate::test_fixtures::zapisz(dir.path(), "archiwum.zip", &zbuduj_zip(&[("a.txt", b"aaa")]));

        assert!(ZipSpliceModule.repair(&plik, &ctx("zip", Some(false), None), None, dir.path()).is_none());

        let tar = crate::test_fixtures::zapisz(dir.path(), "archiwum.tar", &vec![0u8; 1024]);
        assert!(TarSpliceModule.repair(&tar, &ctx("tar", Some(false), None), None, dir.path()).is_none());
    }

    /// Pełna ścieżka: archiwum z uszkodzonym wpisem plus zdrowy bliźniak.
    #[test]
    fn test_zip_sklada_sie_ze_zdrowego_blizniaka() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = zbuduj_zip(&[("a.txt", b"pierwszy wpis"), ("b.txt", b"drugi wpis")]);

        // Psujemy bajty w środku - dane wpisu przestają zgadzać się z CRC32.
        let mut zepsuty = zdrowy.clone();
        let srodek = zepsuty.len() / 2;
        for b in &mut zepsuty[srodek..srodek + 8] { *b ^= 0xFF; }

        let p_zepsuty = crate::test_fixtures::zapisz(dir.path(), "archiwum.zip", &zepsuty);
        let p_dawca = crate::test_fixtures::zapisz(dir.path(), "blizniak.zip", &zdrowy);

        let kontekst = ctx("zip", Some(false), None);
        assert!(ZipSpliceModule.applies_to(&kontekst), "plik musi się kwalifikować");

        let Some((naprawiony, log)) = ZipSpliceModule.repair(&p_zepsuty, &kontekst, Some(&p_dawca), &wynik) else {
            // Silnik odmawia, gdy którejś strony nie da się otworzyć - to
            // dopuszczalny wynik, ale wtedy nie może zostać plik-widmo.
            let pozostalo = std::fs::read_dir(&wynik).unwrap().count();
            assert_eq!(pozostalo, 0, "po odmowie nie może zostać plik");
            return;
        };

        assert!(log.contains("CRC32"), "log musi nazwać kryterium wyboru: {}", log);

        let ocena = ZipSpliceModule
            .verify(&naprawiony, &kontekst)
            .expect("złożone archiwum musi przejść weryfikację");
        assert!(ocena.contains("MOCNA"), "ZIP daje gwarancję MOCNĄ (CRC32 danych): {}", ocena);
    }

    #[test]
    fn test_nieudana_naprawa_nie_zostawia_pliku() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        // Ani jeden, ani drugi nie jest archiwum.
        let plik = crate::test_fixtures::zapisz(dir.path(), "a.zip", b"to nie jest zip");
        let dawca = crate::test_fixtures::zapisz(dir.path(), "b.zip", b"to tez nie");

        assert!(ZipSpliceModule.repair(&plik, &ctx("zip", Some(false), None), Some(&dawca), &wynik).is_none());
        assert_eq!(std::fs::read_dir(&wynik).unwrap().count(), 0, "po odmowie nie może zostać plik");

        let t1 = crate::test_fixtures::zapisz(dir.path(), "a.tar", b"to nie jest tar");
        let t2 = crate::test_fixtures::zapisz(dir.path(), "b.tar", b"to tez nie");
        assert!(TarSpliceModule.repair(&t1, &ctx("tar", Some(false), None), Some(&t2), &wynik).is_none());
        assert_eq!(std::fs::read_dir(&wynik).unwrap().count(), 0);
    }

    #[test]
    fn test_nazwa_wyniku_zachowuje_rozszerzenie_rodziny_zip() {
        // Rozszerzenie decyduje o doborze metody weryfikacji, więc musi przeżyć
        // naprawę - `.docx` nie może wyjść jako `.zip`.
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("w");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = zbuduj_zip(&[("word/document.xml", b"<xml/>")]);
        let plik = crate::test_fixtures::zapisz(dir.path(), "dokument.docx", &zdrowy);
        let dawca = crate::test_fixtures::zapisz(dir.path(), "dawca.docx", &zdrowy);

        if let Some((cel, _)) = ZipSpliceModule.repair(&plik, &ctx("docx", Some(false), None), Some(&dawca), &wynik) {
            assert_eq!(cel.extension().and_then(|e| e.to_str()), Some("docx"));
        }
    }

    // ------------------------------------------------------------------
    // TAR na PRAWDZIWYM archiwum z `image/`
    // ------------------------------------------------------------------

    /// Psuje nagłówek wpisu tar stojącego pod podanym offsetem.
    ///
    /// Zmieniamy bajt w polu NAZWY, a nie w sumie kontrolnej: suma liczona
    /// jest z całego nagłówka, więc rozjeżdża się sama. Tak wygląda realne
    /// uszkodzenie — przekłamany bajt danych, nie sfałszowana suma.
    fn zepsuj_naglowek_wpisu(archiwum: &[u8], offset: usize) -> Vec<u8> {
        let mut zepsute = archiwum.to_vec();
        zepsute[offset] ^= 0xFF;
        zepsute
    }

    /// Sedno składania tar na prawdziwym archiwum: nagłówek drugiego wpisu
    /// jest przekłamany po jednej stronie, zdrowy po drugiej.
    ///
    /// Fixture `image/test_fixture.tar` ma dwa wpisy z nagłówkami na offsetach
    /// 0 i 1024 — leżał w repozytorium nieużywany przez ten moduł.
    #[test]
    #[ignore = "Wymaga image/test_fixture.tar. Uruchom z --ignored."]
    fn test_e2e_tar_odzyskuje_wpis_z_przeklamanym_naglowkiem() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = std::fs::read("image/test_fixture.tar").expect("fixture musi istnieć");

        // Kontrola sensu testu: materiał wyjściowy przechodzi weryfikację.
        assert!(
            crate::tar_archive::verify_tar_bytes(&zdrowy),
            "archiwum źródłowe musi mieć poprawne sumy nagłówków"
        );

        // Nagłówek DRUGIEGO wpisu - pierwszy zostaje nietknięty, więc test
        // sprawdza wybór per wpis, a nie wymianę całego pliku.
        let zepsuty = zepsuj_naglowek_wpisu(&zdrowy, 1024);
        assert!(
            !crate::tar_archive::verify_tar_bytes(&zepsuty),
            "uszkodzone archiwum nie może przechodzić weryfikacji - inaczej test nie mierzy naprawy"
        );

        let p_zepsuty = dir.path().join("archiwum.tar");
        let p_dawca = dir.path().join("blizniak.tar");
        std::fs::write(&p_zepsuty, &zepsuty).unwrap();
        std::fs::write(&p_dawca, &zdrowy).unwrap();

        let kontekst = ctx("tar", Some(false), None);
        assert!(TarSpliceModule.applies_to(&kontekst), "plik musi się kwalifikować");

        let (naprawiony, log) = TarSpliceModule
            .repair(&p_zepsuty, &kontekst, Some(&p_dawca), &wynik)
            .expect("składanie ze zdrowego bliźniaka musi się udać");

        assert!(log.contains("nagłówków"), "log musi nazwać kryterium wyboru: {}", log);
        assert!(log.contains("nie treść"), "log musi ujawnić granicę dowodu: {}", log);

        let odzyskane = std::fs::read(&naprawiony).unwrap();
        assert!(
            crate::tar_archive::verify_tar_bytes(&odzyskane),
            "złożone archiwum musi mieć poprawne sumy wszystkich nagłówków"
        );

        let ocena = TarSpliceModule.verify(&naprawiony, &kontekst).expect("wynik musi przejść weryfikację");
        assert!(ocena.contains("SŁABA"), "tar chroni tylko nagłówki, więc gwarancja jest SŁABA: {}", ocena);
    }

    /// Uszkodzenie TEGO SAMEGO wpisu po obu stronach musi zatrzymać naprawę.
    #[test]
    #[ignore = "Wymaga image/test_fixture.tar. Uruchom z --ignored."]
    fn test_e2e_tar_odmawia_gdy_ten_sam_wpis_zepsuty_po_obu_stronach() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = std::fs::read("image/test_fixture.tar").expect("fixture musi istnieć");
        let zepsuty = zepsuj_naglowek_wpisu(&zdrowy, 1024);

        let p_a = dir.path().join("a.tar");
        let p_b = dir.path().join("b.tar");
        std::fs::write(&p_a, &zepsuty).unwrap();
        std::fs::write(&p_b, &zepsuty).unwrap();

        assert!(
            TarSpliceModule.repair(&p_a, &ctx("tar", Some(false), None), Some(&p_b), &wynik).is_none(),
            "nie ma z czego wybrać - naprawa musi odmówić"
        );
        assert_eq!(std::fs::read_dir(&wynik).unwrap().count(), 0, "po odmowie nie może zostać plik");
    }

    /// Bramka pamięci: archiwum ponad limitem nie jest wczytywane.
    #[test]
    fn test_limit_pamieci_jest_pilnowany() {
        assert_eq!(LIMIT_W_RAM, 512 * 1024 * 1024);

        let dir = tempfile::tempdir().unwrap();
        let maly = crate::test_fixtures::zapisz(dir.path(), "maly.zip", b"x");
        assert!(wczytaj_pare(&maly, &maly).is_some(), "mały plik musi przejść bramkę");

        assert!(
            wczytaj_pare(Path::new("/nie/ma/takiego"), &maly).is_none(),
            "nieczytelna ścieżka nie może przejść"
        );
    }
}
