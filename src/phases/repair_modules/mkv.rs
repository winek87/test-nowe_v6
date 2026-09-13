// src/phases/repair_modules/mkv.rs

//! Moduł naprawczy Matroski — składanie elementów `Segment` z dwóch kopii.
//!
//! ## Odpowiednik `png_clone`, i to dosłowny
//!
//! PNG dawał się naprawiać po fragmentach, bo każdy chunk niesie własny CRC32 —
//! obiektywnego sędziego, a nie heurystykę. Matroska wygląda z początku na
//! format bez takiej możliwości, bo samo EBML sum kontrolnych nie ma. Ma je
//! jednak **Matroska**: definiuje opcjonalny element `CRC-32` dla elementów
//! nadrzędnych, a muxery go zapisują. Sprawdzone na `image/test_fixture.mkv` —
//! sumę niosą wszystkie elementy `Segment` poza `Void`:
//!
//! ```text
//! SeekHead  CRC 0x0E9635DD  (pokrywa 58 B)
//! Info      CRC 0x31FF6A2E  (67 B)
//! Tracks    CRC 0x815969FD  (222 B)
//! Tags      CRC 0x98FA3EC9  (210 B)
//! Cluster   CRC 0x676DF7B2  (54 086 B)
//! Cues      CRC 0xA1ADD9F4  (18 B)
//! ```
//!
//! Naprawa jest więc tym samym mechanizmem co w PNG: dla każdego elementu bierz
//! tę kopię, której suma się zgadza. Silnik i jego warunki opisuje
//! [`crate::mkv_container::splice_mkv`].
//!
//! ## Co to realnie ratuje
//!
//! Najczęstsze uszkodzenie przy odzysku to **ucięcie ogona** — plik traci
//! końcowe klastry i `Cues`. Jeśli druga kopia sięga dalej, te elementy wracają
//! w całości, a offsety w `SeekHead`/`Cues` pozostają poprawne, bo wynik
//! zachowuje kolejność i rozmiary wszystkich elementów.
//!
//! ## Siła gwarancji
//!
//! Wynik weryfikuje [`super::weryfikuj_naprawiony_plik`], które dla Matroski
//! sprawdza strukturę ORAZ wszystkie sumy `CRC-32`. Gdy sumy są obecne i
//! zgodne, gwarancja jest MOCNA; gdy muxer ich nie zapisał, zostaje sama
//! struktura i etykieta mówi to wprost. Dlatego moduł nie nadpisuje `verify` —
//! rozróżnienie jest już we właściwym miejscu.

use super::{RepairContext, RepairModule};
use std::path::{Path, PathBuf};

/// Górny limit rozmiaru pojedynczej kopii wczytywanej do składania.
///
/// Silnik wymaga OBU kopii w pamięci naraz, a Faza 17 przetwarza pliki
/// równolegle. Materiał wideo bywa wielogigabajtowy, więc bez tej bramki
/// naprawa mogłaby wywrócić proces.
const LIMIT_W_RAM: u64 = 512 * 1024 * 1024; // 512 MB

pub struct MkvCloneModule;

/// Czy plik jest Matroską noszącą ślad uszkodzenia.
///
/// `video_ok == Some(false)` to wynik diagnostyki z Fazy 19 — obejmuje też
/// ucięcie, odkąd `mkv_container` sprawdza kompletność elementu `Segment`.
/// `eof_ok == Some(false)` łapie plik ucięty, którego Faza 19 mogła nie zdążyć
/// zbadać.
fn jest_uszkodzona_matroska(ctx: &RepairContext) -> bool {
    crate::mkv_container::is_mkv_extension(&format!(".{}", ctx.ext))
        && (ctx.video_ok == Some(false) || ctx.eof_ok == Some(false))
}

impl RepairModule for MkvCloneModule {
    fn id(&self) -> &'static str { "mkv_clone" }

    fn display_name(&self) -> &'static str {
        "Matroska składanie elementów z dwóch kopii (CRC-32 per element)"
    }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        jest_uszkodzona_matroska(ctx)
    }

    fn repair(&self, source: &Path, _ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let dawca = twin?;

        for sciezka in [source, dawca] {
            let rozmiar = std::fs::metadata(sciezka).ok()?.len();
            if rozmiar > LIMIT_W_RAM {
                tracing::debug!(
                    plik = %sciezka.display(), rozmiar, limit = LIMIT_W_RAM,
                    "mkv_clone: plik przekracza limit składania w RAM"
                );
                return None;
            }
        }

        let a = std::fs::read(source).ok()?;
        let b = std::fs::read(dawca).ok()?;

        let wynik = crate::mkv_container::splice_mkv(&a, &b)?;

        let stem = source.file_stem()?.to_str()?;
        let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("mkv");
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_mkv.{}", stem, ext));

        if let Some(katalog) = cel.parent()
            && std::fs::create_dir_all(katalog).is_err()
        {
            return None;
        }
        if std::fs::write(&cel, &wynik).is_err() {
            let _ = std::fs::remove_file(&cel);
            return None;
        }

        Some((
            cel,
            format!(
                "Złożono Matroskę z dwóch kopii, wybierając elementy `Segment` o zgodnym CRC-32 (dawca: {}).",
                dawca.display()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mkv_container::{dzieci_segmentu, splice_mkv};

    fn ctx(ext: &'static str, video_ok: Option<bool>, eof_ok: Option<bool>) -> RepairContext<'static> {
        RepairContext {
            ext, media_reason: None, utf8_ok: None, is_oneliner: None,
            eof_ok, match_type: None, video_ok, structure_ok: None,
        }
    }

    // ------------------------------------------------------------------
    // Kwalifikacja i kolejność
    // ------------------------------------------------------------------

    #[test]
    fn test_obejmuje_cala_rodzine_matroski() {
        for ext in ["mkv", "webm", "mka"] {
            assert!(
                MkvCloneModule.applies_to(&ctx(ext, Some(false), None)),
                ".{} to kontener Matroska i musi być objęte", ext
            );
        }
    }

    #[test]
    fn test_kwalifikacja_po_diagnozie_fazy_19_i_po_ucieciu() {
        assert!(MkvCloneModule.applies_to(&ctx("mkv", Some(false), None)), "video_ok = false");
        assert!(MkvCloneModule.applies_to(&ctx("mkv", None, Some(false))), "eof_ok = false");
    }

    #[test]
    fn test_zdrowa_matroska_nie_jest_ruszana() {
        assert!(!MkvCloneModule.applies_to(&ctx("mkv", Some(true), Some(true))));
        assert!(!MkvCloneModule.applies_to(&ctx("mkv", None, None)), "bez przesłanki uszkodzenia nie dotykamy pliku");
    }

    #[test]
    fn test_nie_rusza_innych_formatow() {
        for ext in ["mp4", "mov", "ts", "flv", "jpg", "png", "zip"] {
            assert!(!MkvCloneModule.applies_to(&ctx(ext, Some(false), None)), "ext .{}", ext);
        }
    }

    /// Lista rozszerzeń musi pochodzić z `mkv_container`, a nie być tu
    /// zduplikowana — inaczej naprawa rozjechałaby się z weryfikacją.
    #[test]
    fn test_lista_rozszerzen_pochodzi_z_silnika() {
        for ext in ["mkv", "webm", "mka", "mp4", "zip"] {
            assert_eq!(
                MkvCloneModule.applies_to(&ctx(ext, Some(false), None)),
                crate::mkv_container::is_mkv_extension(&format!(".{}", ext)),
                "rozbieżność dla .{}", ext
            );
        }
    }

    #[test]
    fn test_stoi_przed_splice() {
        let ids: Vec<&str> = super::super::all_modules().iter().map(|m| m.id()).collect();
        let poz = |id: &str| ids.iter().position(|x| *x == id)
            .unwrap_or_else(|| panic!("moduł {} musi być zarejestrowany (kolejność: {:?})", id, ids));

        assert!(
            poz("mkv_clone") < poz("splice"),
            "bajtowe zszycie nie zna struktury EBML i nie może wyprzedzać składania po elementach: {:?}", ids
        );
    }

    // ------------------------------------------------------------------
    // Naprawa
    // ------------------------------------------------------------------

    #[test]
    fn test_bez_dawcy_zwraca_none() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("film.mkv");
        std::fs::write(&plik, b"cokolwiek").unwrap();

        assert!(MkvCloneModule.repair(&plik, &ctx("mkv", Some(false), None), None, dir.path()).is_none());
    }

    #[test]
    fn test_nieudana_naprawa_nie_zostawia_pliku() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let plik = dir.path().join("a.mkv");
        let dawca = dir.path().join("b.mkv");
        std::fs::write(&plik, b"to nie jest matroska").unwrap();
        std::fs::write(&dawca, b"to tez nie").unwrap();

        assert!(MkvCloneModule.repair(&plik, &ctx("mkv", Some(false), None), Some(&dawca), &wynik).is_none());
        assert_eq!(std::fs::read_dir(&wynik).unwrap().count(), 0, "po odmowie nie może zostać plik");
    }

    // ------------------------------------------------------------------
    // Pełna ścieżka na PRAWDZIWYCH plikach
    // ------------------------------------------------------------------

    /// Sedno modułu: ucięta Matroska plus zdrowa druga kopia dają z powrotem
    /// komplet elementów — łącznie z `Cues`, których w uciętym pliku nie ma.
    #[test]
    #[ignore = "Wymaga image/test_fixture.mkv i test_fixture_mkv_truncated.mkv. Uruchom z --ignored."]
    fn test_e2e_uciety_plik_odzyskuje_brakujace_elementy() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let uszkodzony = dir.path().join("film.mkv");
        let dawca = dir.path().join("blizniak.mkv");
        std::fs::copy("image/test_fixture_mkv_truncated.mkv", &uszkodzony).unwrap();
        std::fs::copy("image/test_fixture.mkv", &dawca).unwrap();

        let kontekst = ctx("mkv", Some(false), None);

        // Kontrola sensu testu: plik uszkodzony NIE MOŻE przechodzić weryfikacji.
        assert!(
            MkvCloneModule.verify(&uszkodzony, &kontekst).is_err(),
            "ucięta Matroska nie powinna przechodzić weryfikacji - inaczej test nie mierzy naprawy"
        );

        let (naprawiony, log) = MkvCloneModule
            .repair(&uszkodzony, &kontekst, Some(&dawca), &wynik)
            .expect("składanie ze zdrowego bliźniaka musi się udać");

        assert!(log.contains("CRC-32"), "log musi nazwać kryterium wyboru: {}", log);

        let ocena = MkvCloneModule.verify(&naprawiony, &kontekst).expect("wynik musi przejść weryfikację");
        assert!(ocena.contains("MOCNA"), "sumy CRC-32 są obecne, więc gwarancja jest MOCNA: {}", ocena);

        // Odzyskany komplet elementów: ucięty miał o jeden mniej (brak `Cues`).
        let przed = dzieci_segmentu(&std::fs::read(&uszkodzony).unwrap()).unwrap().2.len();
        let po = dzieci_segmentu(&std::fs::read(&naprawiony).unwrap()).unwrap().2.len();
        assert!(po > przed, "naprawa musi przywrócić brakujące elementy ({} -> {})", przed, po);

        // Wynik jest bajtowo równy zdrowemu oryginałowi - uszkodzenie dotknęło
        // wyłącznie ogona, a wszystkie elementy wróciły na swoje miejsca.
        assert_eq!(
            std::fs::read(&naprawiony).unwrap(),
            std::fs::read("image/test_fixture.mkv").unwrap(),
            "złożenie dwóch kopii tego samego pliku musi odtworzyć oryginał"
        );
    }

    /// Weryfikacja musi odrzucić plik, który CZYTA SIĘ strukturalnie, ale ma
    /// rozminiętą sumę `CRC-32`.
    ///
    /// To najgroźniejszy przypadek: struktura Matroski jest nietknięta, więc
    /// parser kontenera nie zgłasza zastrzeżeń, a przekłamane są dane klatek.
    /// Bez kontroli sum taki plik przechodziłby jako udana naprawa.
    #[test]
    #[ignore = "Wymaga image/test_fixture.mkv. Uruchom z --ignored."]
    fn test_weryfikacja_odrzuca_rozminiete_crc_przy_czytelnej_strukturze() {
        let dir = tempfile::tempdir().unwrap();
        let zdrowy = std::fs::read("image/test_fixture.mkv").unwrap();

        // Psujemy bajt WEWNĄTRZ klastra - najdłuższego elementu, niosącego
        // dane klatek. Struktura kontenera (Info, Tracks) zostaje nietknięta.
        let (_, _, dzieci) = dzieci_segmentu(&zdrowy).unwrap();
        let klaster = dzieci.iter().max_by_key(|e| e.dlugosc_calkowita).expect("plik ma elementy");

        let mut zepsuty = zdrowy.clone();
        let pozycja = klaster.offset + klaster.dlugosc_calkowita / 2;
        zepsuty[pozycja] ^= 0xFF;

        let plik = dir.path().join("zepsuty.mkv");
        std::fs::write(&plik, &zepsuty).unwrap();

        // Kontrola sensu testu: parser STRUKTURY nadal ten plik przyjmuje.
        assert!(
            crate::mkv_container::read_mkv_bytes(&zepsuty).is_ok(),
            "struktura musi pozostać czytelna - inaczej test nie mierzy kontroli sum"
        );
        assert_eq!(
            crate::mkv_container::wszystkie_crc_zgodne(&zepsuty), Some(false),
            "suma klastra musi się rozminąć"
        );

        let wynik = MkvCloneModule.verify(&plik, &ctx("mkv", Some(false), None));
        assert!(wynik.is_err(), "rozminięta suma CRC-32 musi zostać odrzucona, dostaliśmy: {:?}", wynik);
    }

    /// Silnik musi odmówić, gdy kopie nie pochodzą z tego samego pliku.
    #[test]
    #[ignore = "Wymaga image/test_fixture.mkv i test_fixture_real.mkv. Uruchom z --ignored."]
    fn test_rozne_pliki_nie_sa_skladane() {
        let a = std::fs::read("image/test_fixture.mkv").unwrap();
        let b = std::fs::read("image/test_fixture_real.mkv").unwrap();

        assert!(
            splice_mkv(&a, &b).is_none(),
            "dwie różne Matroski to nie dwa odzyski tego samego pliku - składanie musi odmówić"
        );
    }

    #[test]
    #[ignore = "Wymaga image/test_fixture.mkv. Uruchom z --ignored."]
    fn test_zdrowa_kopia_zlozona_sama_ze_soba_daje_oryginal() {
        let a = std::fs::read("image/test_fixture.mkv").unwrap();
        assert_eq!(splice_mkv(&a, &a).as_deref(), Some(a.as_slice()), "składanie nie może niczego zmieniać");
    }
}
