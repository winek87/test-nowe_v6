// src/phases/repair_modules/asf.rs

//! Moduł naprawczy WMV/WMA — składanie obiektów ASF z dwóch kopii.
//!
//! ## Ten sam wzorzec co `riff_clone`, jeden format krócej
//!
//! ASF (patrz [`crate::asf_container`]) jest formatem kawałkowym bez sumy
//! kontrolnej per obiekt, dokładnie jak czysty RIFF — wybór między dwiema
//! kopiami obiektu opiera się na jedynym dostępnym, bezpiecznym sygnale:
//! "czy obiekt nie wygląda na oczywistą wydmuszkę". Ten moduł jest więc,
//! jak `riff_clone`, ZAWSZE gwarancją SŁABĄ i MUSI nadpisać `verify()`.
//!
//! ## Skąd sygnał kwalifikacji
//!
//! Faza 19 (diagnostyka kontenerów wideo) nie obejmuje WMV/WMA — żadna faza
//! w projekcie nie diagnozuje ASF. Jedyny dostępny sygnał to `match_type ==
//! Some("PARTIAL")` z korelacji Fazy 14 — DOKŁADNIE ten sam warunek, którego
//! używa [`super::splice::SpliceModule`] dla DOWOLNEGO rozszerzenia. Ten
//! moduł musi więc stać PRZED `splice` w rejestrze — ten sam sygnał, ale
//! świadomy struktury ASF zamiast ślepego zszycia bajt po bajcie.
//!
//! ## Co to realnie ratuje
//!
//! Najczęstsze uszkodzenie przy odzysku to ucięcie ogona. `Data Object` —
//! zwykle ostatni i największy obiekt najwyższego poziomu, niosący same
//! próbki/klatki — wraca w całości, jeśli druga kopia sięga dalej.

use super::{RepairContext, RepairModule, WynikWeryfikacji};
use crate::asf_container;
use std::path::{Path, PathBuf};

/// Górny limit rozmiaru pojedynczej kopii wczytywanej do składania — ten sam
/// powód i ta sama wartość co `riff_clone`/`mkv_clone`.
const LIMIT_W_RAM: u64 = 512 * 1024 * 1024; // 512 MB

pub struct AsfCloneModule;

fn jest_kandydatem_do_skladania(ctx: &RepairContext) -> bool {
    asf_container::is_asf_extension(&format!(".{}", ctx.ext)) && ctx.match_type == Some("PARTIAL")
}

impl RepairModule for AsfCloneModule {
    fn id(&self) -> &'static str { "asf_clone" }

    fn display_name(&self) -> &'static str {
        "WMV/WMA składanie obiektów ASF (gwarancja SŁABA)"
    }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        jest_kandydatem_do_skladania(ctx)
    }

    fn repair(&self, source: &Path, _ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let dawca = twin?;

        for sciezka in [source, dawca] {
            let rozmiar = std::fs::metadata(sciezka).ok()?.len();
            if rozmiar > LIMIT_W_RAM {
                tracing::debug!(
                    plik = %sciezka.display(), rozmiar, limit = LIMIT_W_RAM,
                    "asf_clone: plik przekracza limit składania w RAM"
                );
                return None;
            }
        }

        let a = std::fs::read(source).ok()?;
        let b = std::fs::read(dawca).ok()?;

        let wynik = asf_container::splice_asf(&a, &b)?;

        let stem = source.file_stem()?.to_str()?;
        let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("wmv");
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_asf.{}", stem, ext));

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
                "Złożono kontener ASF z dwóch kopii, wybierając obiekty niewyglądające na wydmuszkę (dawca: {}). \
                 UWAGA: ASF nie niesie sumy kontrolnej per obiekt — potwierdzona wyłącznie spójność struktury.",
                dawca.display()
            ),
        ))
    }

    /// Weryfikacja z jawnie **osłabioną** etykietą gwarancji — NADPISANIE
    /// KONIECZNE (w odróżnieniu od `mkv_clone`): domyślna gałąź dla
    /// `.wmv`/`.wma` sprawdza dziś wyłącznie GUID nagłówka na starcie pliku,
    /// a ASF nigdy nie ma sumy kontrolnej per obiekt, więc etykieta MOCNA
    /// nie jest tu nigdy osiągalna. Ta implementacja jest mimo to SILNIEJSZA
    /// niż domyślna: rozbiera CAŁĄ strukturę obiektów i potwierdza, że żaden
    /// nie jest ucięty — nie tylko ogląda pierwsze 16 bajtów.
    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        let bajty = std::fs::read(repaired).map_err(|e| format!("nie udało się odczytać wyniku: {}", e))?;

        match asf_container::wszystkie_obiekty_spojne(&bajty) {
            Some(true) => Ok("struktura obiektów ASF spójna (gwarancja SŁABA - ASF nie niesie sumy kontrolnej per obiekt, treść próbek NIE zweryfikowana)"),
            Some(false) => Err("plik ma ucięty/niespójny obiekt ASF".to_string()),
            None => Err("plik nie ma czytelnego nagłówka ASF albo nie ma ani jednego obiektu".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(ext: &'static str, match_type: Option<&'static str>) -> RepairContext<'static> {
        RepairContext {
            ext, media_reason: None, utf8_ok: None, is_oneliner: None,
            eof_ok: None, match_type, video_ok: None, structure_ok: None, media_decoded: None,
        }
    }

    const DATA_OBJECT_GUID: [u8; 16] = [
        0x36, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
    ];

    fn obiekt(guid: [u8; 16], tresc: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&guid);
        out.extend_from_slice(&((24 + tresc.len()) as u64).to_le_bytes());
        out.extend_from_slice(tresc);
        out
    }

    /// Buduje minimalny, poprawny plik ASF — ta sama konstrukcja co
    /// `asf_container::tests::zbuduj_asf`, powtórzona tutaj celowo (moduł
    /// naprawczy nie powinien zależeć od prywatnych detali testowych
    /// silnika, tylko od jego publicznego interfejsu).
    fn zbuduj_asf(tresc_danych: &[u8]) -> Vec<u8> {
        let mut plik = obiekt(asf_container::ASF_HEADER_GUID, &[0xAA; 10]);
        plik.extend(obiekt(DATA_OBJECT_GUID, tresc_danych));
        plik
    }

    // ------------------------------------------------------------------
    // Kwalifikacja i kolejność
    // ------------------------------------------------------------------

    #[test]
    fn test_obejmuje_wmv_i_wma() {
        for ext in ["wmv", "wma"] {
            assert!(
                AsfCloneModule.applies_to(&ctx(ext, Some("PARTIAL"))),
                ".{} to kontener ASF i musi być objęte", ext
            );
        }
    }

    #[test]
    fn test_kwalifikacja_wylacznie_po_match_type_partial() {
        assert!(AsfCloneModule.applies_to(&ctx("wmv", Some("PARTIAL"))));
        assert!(!AsfCloneModule.applies_to(&ctx("wmv", Some("FULL"))), "inny match_type nie kwalifikuje");
        assert!(!AsfCloneModule.applies_to(&ctx("wmv", None)), "brak match_type nie kwalifikuje");
    }

    #[test]
    fn test_nie_rusza_innych_formatow() {
        for ext in ["mp3", "mkv", "mp4", "jpg", "png", "zip", "wav", "avi"] {
            assert!(!AsfCloneModule.applies_to(&ctx(ext, Some("PARTIAL"))), "ext .{}", ext);
        }
    }

    #[test]
    fn test_lista_rozszerzen_pochodzi_z_silnika() {
        for ext in ["wmv", "wma", "mp4", "zip"] {
            assert_eq!(
                AsfCloneModule.applies_to(&ctx(ext, Some("PARTIAL"))),
                asf_container::is_asf_extension(&format!(".{}", ext)),
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
            poz("asf_clone") < poz("splice"),
            "bajtowe zszycie nie zna struktury ASF i nie może wyprzedzać składania po obiektach: {:?}", ids
        );
    }

    // ------------------------------------------------------------------
    // Siła gwarancji
    // ------------------------------------------------------------------

    #[test]
    fn test_nazwa_modulu_ujawnia_sile_gwarancji() {
        assert!(AsfCloneModule.display_name().contains("SŁABA"), "nazwa: {}", AsfCloneModule.display_name());
    }

    #[test]
    fn test_weryfikacja_zdrowego_pliku_jest_zawsze_slaba_nigdy_mocna() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("zdrowy.wmv");
        std::fs::write(&plik, zbuduj_asf(&[1, 2, 3, 4])).unwrap();

        let wynik = AsfCloneModule.verify(&plik, &ctx("wmv", None)).expect("zdrowy plik musi przejść weryfikację");
        assert!(wynik.contains("SŁABA"), "gwarancja musi być zadeklarowana jako SŁABA: {}", wynik);
        assert!(!wynik.contains("MOCNA"), "ASF nigdy nie osiąga MOCNEJ gwarancji: {}", wynik);
    }

    #[test]
    fn test_weryfikacja_odrzuca_plik_ktory_nie_jest_asf() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("smieci.wmv");
        std::fs::write(&plik, b"to nie jest ASF, tylko przypadkowe bajty!!").unwrap();

        assert!(AsfCloneModule.verify(&plik, &ctx("wmv", None)).is_err());
    }

    #[test]
    fn test_weryfikacja_odrzuca_uciety_plik() {
        let dir = tempfile::tempdir().unwrap();
        let pelny = zbuduj_asf(&[1, 2, 3, 4, 5]);
        let plik = dir.path().join("uciety.wmv");
        std::fs::write(&plik, &pelny[..pelny.len() - 3]).unwrap();

        assert!(AsfCloneModule.verify(&plik, &ctx("wmv", None)).is_err());
    }

    // ------------------------------------------------------------------
    // repair
    // ------------------------------------------------------------------

    #[test]
    fn test_bez_dawcy_zwraca_none() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("wideo.wmv");
        std::fs::write(&plik, b"cokolwiek").unwrap();

        assert!(AsfCloneModule.repair(&plik, &ctx("wmv", Some("PARTIAL")), None, dir.path()).is_none());
    }

    #[test]
    fn test_nieparsowalne_pliki_nie_zostawiaja_wyniku() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let plik = dir.path().join("a.wmv");
        let dawca = dir.path().join("b.wmv");
        std::fs::write(&plik, b"to nie jest ASF, tylko przypadkowe bajty!!").unwrap();
        std::fs::write(&dawca, b"to tez nie, kompletnie inne smieci tutaj!!").unwrap();

        assert!(AsfCloneModule.repair(&plik, &ctx("wmv", Some("PARTIAL")), Some(&dawca), &wynik).is_none());
        assert_eq!(std::fs::read_dir(&wynik).unwrap().count(), 0, "po odmowie nie może zostać plik");
    }

    // ------------------------------------------------------------------
    // Pełna ścieżka naprawy — NORMALNY test (bez #[ignore])
    //
    // ASF, jak WAV, nie wymaga zewnętrznego narzędzia (ffmpeg) do
    // zbudowania prawdziwego, strukturalnie poprawnego pliku.
    // ------------------------------------------------------------------

    /// Ucinamy obiekt Data W ŚRODKU (nie dokładnie na granicy) — typowe
    /// uszkodzenie przy odzysku. NIE na granicy celowo: ASF, w odróżnieniu
    /// od RIFF, nie ma zewnętrznego pola z deklarowanym łącznym rozmiarem
    /// (patrz dokumentacja modułu `asf_container`), więc ucięcie DOKŁADNIE
    /// na granicy obiektu jest architektonicznie niewykrywalne przez
    /// `verify()` — ten test mierzy naprawę na przypadku, który JEST
    /// wykrywalny (i najczęstszy w praktyce).
    #[test]
    fn test_e2e_uciety_plik_odzyskuje_brakujacy_obiekt() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = zbuduj_asf(&[10, 20, 30, 40, 50, 60, 70, 80]);
        let ucieta = &zdrowy[..zdrowy.len() - 5]; // ucięcie w środku obiektu Data

        let uszkodzony = dir.path().join("wideo.wmv");
        let dawca = dir.path().join("blizniak.wmv");
        std::fs::write(&uszkodzony, ucieta).unwrap();
        std::fs::write(&dawca, &zdrowy).unwrap();

        let kontekst = ctx("wmv", Some("PARTIAL"));

        assert!(
            AsfCloneModule.verify(&uszkodzony, &kontekst).is_err(),
            "ucięty ASF nie powinien przechodzić weryfikacji - inaczej test nie mierzy naprawy"
        );

        let (naprawiony, log) = AsfCloneModule
            .repair(&uszkodzony, &kontekst, Some(&dawca), &wynik)
            .expect("składanie ze zdrowego bliźniaka musi się udać");

        assert!(log.contains("wydmuszk") || log.contains("ASF"), "log musi opisać kryterium/ograniczenie: {}", log);

        let ocena = AsfCloneModule.verify(&naprawiony, &kontekst).expect("wynik musi przejść weryfikację");
        assert!(ocena.contains("SŁABA"), "gwarancja musi być zadeklarowana jako SŁABA: {}", ocena);

        assert_eq!(
            std::fs::read(&naprawiony).unwrap(), zdrowy,
            "złożenie ucięcia ze zdrowym bliźniakiem musi odtworzyć oryginał"
        );
    }
}
