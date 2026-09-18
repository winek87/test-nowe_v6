// src/phases/repair_modules/riff.rs

//! Moduł naprawczy WAV/AVI — składanie fragmentów RIFF z dwóch kopii.
//!
//! ## Ten sam wzorzec co `mkv_clone`, jedna różnica: brak sędziego
//!
//! Matroska daje się naprawiać po elementach, bo (zwykle) niesie opcjonalny
//! `CRC-32` per element — obiektywny dowód. Czysty RIFF (WAV, AVI) **nigdy
//! nie ma żadnej sumy kontrolnej dla fragmentu** — patrz dokumentacja
//! [`crate::riff_container`]. Wybór między dwiema kopiami fragmentu opiera
//! się więc na jedynym dostępnym, bezpiecznym sygnale: "czy fragment nie
//! wygląda na oczywistą wydmuszkę" (same zera/same `0xFF`). Stąd ten moduł, w
//! odróżnieniu od `mkv_clone`, jest ZAWSZE gwarancją SŁABĄ i dlatego MUSI
//! nadpisać `verify()` — nie ma szansy na etykietę MOCNĄ.
//!
//! ## Skąd sygnał kwalifikacji, skoro nie ma diagnostyki z wcześniejszej fazy
//!
//! Faza 19 (diagnostyka kontenerów wideo) obejmuje WYŁĄCZNIE MP4/MOV/M4V,
//! MKV/WebM/MKA, FLV i TS/M2TS/MTS — WAV i AVI nie są objęte żadną
//! dedykowaną fazą. Jedyny dostępny sygnał to `match_type ==
//! Some("PARTIAL")` z korelacji Fazy 14 — DOKŁADNIE ten sam warunek, którego
//! używa [`super::splice::SpliceModule`] dla DOWOLNEGO rozszerzenia. Ten
//! moduł musi więc stać PRZED `splice` w rejestrze — ten sam sygnał, ale
//! świadomy struktury RIFF zamiast ślepego zszycia bajt po bajcie.
//!
//! ## Co to realnie ratuje
//!
//! Tak jak `mkv_clone`: najczęstsze uszkodzenie przy odzysku to ucięcie
//! ogona. Jeśli druga kopia sięga dalej, brakujące fragmenty najwyższego
//! poziomu (np. `idx1` w AVI, `LIST` z metadanymi w WAV) wracają w całości.

use super::{RepairContext, RepairModule, WynikWeryfikacji};
use crate::riff_container;
use std::path::{Path, PathBuf};

/// Górny limit rozmiaru pojedynczej kopii wczytywanej do składania — ten sam
/// powód i ta sama wartość co `mkv_clone` (materiał wideo/audio bywa duży,
/// Faza 17 przetwarza pliki równolegle).
const LIMIT_W_RAM: u64 = 512 * 1024 * 1024; // 512 MB

pub struct RiffCloneModule;

fn jest_kandydatem_do_skladania(ctx: &RepairContext) -> bool {
    riff_container::is_riff_extension(&format!(".{}", ctx.ext)) && ctx.match_type == Some("PARTIAL")
}

impl RepairModule for RiffCloneModule {
    fn id(&self) -> &'static str { "riff_clone" }

    fn display_name(&self) -> &'static str {
        "WAV/AVI składanie fragmentów RIFF (gwarancja SŁABA)"
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
                    "riff_clone: plik przekracza limit składania w RAM"
                );
                return None;
            }
        }

        let a = std::fs::read(source).ok()?;
        let b = std::fs::read(dawca).ok()?;

        let wynik = riff_container::splice_riff(&a, &b)?;

        let stem = source.file_stem()?.to_str()?;
        let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("wav");
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_riff.{}", stem, ext));

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
                "Złożono kontener RIFF z dwóch kopii, wybierając fragmenty niewyglądające na wydmuszkę (dawca: {}). \
                 UWAGA: RIFF nie niesie sumy kontrolnej per fragment — potwierdzona wyłącznie spójność struktury.",
                dawca.display()
            ),
        ))
    }

    /// Weryfikacja z jawnie **osłabioną** etykietą gwarancji — NADPISANIE
    /// KONIECZNE (w odróżnieniu od `mkv_clone`, które polega na domyślnej
    /// implementacji): domyślna gałąź dla `.wav`/`.avi` sprawdza dziś
    /// wyłącznie pierwsze 12 bajtów nagłówka, a RIFF nigdy nie ma sumy
    /// kontrolnej per fragment jak Matroska, więc etykieta MOCNA nie jest tu
    /// nigdy osiągalna. Ta implementacja jest mimo to SILNIEJSZA niż
    /// domyślna: rozbiera CAŁĄ strukturę fragmentów i potwierdza, że żaden
    /// nie jest ucięty — nie tylko ogląda pierwsze 12 bajtów.
    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        let bajty = std::fs::read(repaired).map_err(|e| format!("nie udało się odczytać wyniku: {}", e))?;

        match riff_container::wszystkie_fragmenty_spojne(&bajty) {
            Some(true) => Ok("struktura fragmentów RIFF spójna (gwarancja SŁABA - RIFF nie niesie sumy kontrolnej per fragment, treść próbek NIE zweryfikowana)"),
            Some(false) => Err("plik ma ucięty/niespójny fragment RIFF".to_string()),
            None => Err("plik nie ma czytelnego nagłówka RIFF albo nie ma ani jednego fragmentu".to_string()),
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

    /// Buduje minimalny, poprawny plik WAV — ta sama konstrukcja co
    /// `riff_container::tests::zbuduj_wav`, powtórzona tutaj celowo (moduł
    /// naprawczy nie powinien zależeć od prywatnych detali testowych
    /// silnika, tylko od jego publicznego interfejsu).
    fn zbuduj_wav(probki: &[u8]) -> Vec<u8> {
        let fmt_body: [u8; 16] = [1, 0, 1, 0, 0x44, 0xAC, 0, 0, 0x44, 0xAC, 0, 0, 1, 0, 8, 0];

        let mut data_chunk = Vec::new();
        data_chunk.extend_from_slice(b"data");
        data_chunk.extend_from_slice(&(probki.len() as u32).to_le_bytes());
        data_chunk.extend_from_slice(probki);
        if probki.len() % 2 == 1 {
            data_chunk.push(0);
        }

        let mut fmt_chunk = Vec::new();
        fmt_chunk.extend_from_slice(b"fmt ");
        fmt_chunk.extend_from_slice(&(fmt_body.len() as u32).to_le_bytes());
        fmt_chunk.extend_from_slice(&fmt_body);

        let tresc_po_formie = 4 + fmt_chunk.len() + data_chunk.len();

        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(tresc_po_formie as u32).to_le_bytes());
        wav.extend_from_slice(b"WAVE");
        wav.extend_from_slice(&fmt_chunk);
        wav.extend_from_slice(&data_chunk);
        wav
    }

    // ------------------------------------------------------------------
    // Kwalifikacja i kolejność
    // ------------------------------------------------------------------

    #[test]
    fn test_obejmuje_wav_i_avi() {
        for ext in ["wav", "avi"] {
            assert!(
                RiffCloneModule.applies_to(&ctx(ext, Some("PARTIAL"))),
                ".{} to kontener RIFF i musi być objęte", ext
            );
        }
    }

    #[test]
    fn test_kwalifikacja_wylacznie_po_match_type_partial() {
        assert!(RiffCloneModule.applies_to(&ctx("wav", Some("PARTIAL"))));
        assert!(!RiffCloneModule.applies_to(&ctx("wav", Some("FULL"))), "inny match_type nie kwalifikuje");
        assert!(!RiffCloneModule.applies_to(&ctx("wav", None)), "brak match_type nie kwalifikuje");
    }

    #[test]
    fn test_nie_rusza_innych_formatow() {
        for ext in ["mp3", "mkv", "mp4", "jpg", "png", "zip"] {
            assert!(!RiffCloneModule.applies_to(&ctx(ext, Some("PARTIAL"))), "ext .{}", ext);
        }
    }

    /// Lista rozszerzeń musi pochodzić z `riff_container`, a nie być tu
    /// zduplikowana — inaczej naprawa rozjechałaby się z weryfikacją.
    #[test]
    fn test_lista_rozszerzen_pochodzi_z_silnika() {
        for ext in ["wav", "avi", "mp4", "zip"] {
            assert_eq!(
                RiffCloneModule.applies_to(&ctx(ext, Some("PARTIAL"))),
                riff_container::is_riff_extension(&format!(".{}", ext)),
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
            poz("riff_clone") < poz("splice"),
            "bajtowe zszycie nie zna struktury RIFF i nie może wyprzedzać składania po fragmentach: {:?}", ids
        );
    }

    // ------------------------------------------------------------------
    // Siła gwarancji
    // ------------------------------------------------------------------

    #[test]
    fn test_nazwa_modulu_ujawnia_sile_gwarancji() {
        assert!(RiffCloneModule.display_name().contains("SŁABA"), "nazwa: {}", RiffCloneModule.display_name());
    }

    #[test]
    fn test_weryfikacja_zdrowego_pliku_jest_zawsze_slaba_nigdy_mocna() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("zdrowy.wav");
        std::fs::write(&plik, zbuduj_wav(&[1, 2, 3, 4])).unwrap();

        let wynik = RiffCloneModule.verify(&plik, &ctx("wav", None)).expect("zdrowy plik musi przejść weryfikację");
        assert!(wynik.contains("SŁABA"), "gwarancja musi być zadeklarowana jako SŁABA: {}", wynik);
        assert!(!wynik.contains("MOCNA"), "RIFF nigdy nie osiąga MOCNEJ gwarancji: {}", wynik);
    }

    #[test]
    fn test_weryfikacja_odrzuca_plik_ktory_nie_jest_riff() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("smieci.wav");
        std::fs::write(&plik, b"to nie jest RIFF").unwrap();

        assert!(RiffCloneModule.verify(&plik, &ctx("wav", None)).is_err());
    }

    #[test]
    fn test_weryfikacja_odrzuca_uciety_plik() {
        let dir = tempfile::tempdir().unwrap();
        let pelny = zbuduj_wav(&[1, 2, 3, 4, 5]);
        let plik = dir.path().join("uciety.wav");
        std::fs::write(&plik, &pelny[..pelny.len() - 3]).unwrap();

        assert!(RiffCloneModule.verify(&plik, &ctx("wav", None)).is_err());
    }

    // ------------------------------------------------------------------
    // repair
    // ------------------------------------------------------------------

    #[test]
    fn test_bez_dawcy_zwraca_none() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("dzwiek.wav");
        std::fs::write(&plik, b"cokolwiek").unwrap();

        assert!(RiffCloneModule.repair(&plik, &ctx("wav", Some("PARTIAL")), None, dir.path()).is_none());
    }

    #[test]
    fn test_nieparsowalne_pliki_nie_zostawiaja_wyniku() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let plik = dir.path().join("a.wav");
        let dawca = dir.path().join("b.wav");
        std::fs::write(&plik, b"to nie jest RIFF").unwrap();
        std::fs::write(&dawca, b"to tez nie").unwrap();

        assert!(RiffCloneModule.repair(&plik, &ctx("wav", Some("PARTIAL")), Some(&dawca), &wynik).is_none());
        assert_eq!(std::fs::read_dir(&wynik).unwrap().count(), 0, "po odmowie nie może zostać plik");
    }

    // ------------------------------------------------------------------
    // Pełna ścieżka naprawy — NORMALNY test (bez #[ignore])
    //
    // WAV nie wymaga zewnętrznego narzędzia (ffmpeg) do zbudowania
    // prawdziwego, poprawnego pliku, więc test pełnej ścieżki może być
    // częścią zwykłego przebiegu `cargo test`, w odróżnieniu od
    // dng_structural/mkv_clone/tiff_structural.
    // ------------------------------------------------------------------

    #[test]
    fn test_e2e_uciety_plik_odzyskuje_brakujacy_fragment() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = zbuduj_wav(&[10, 20, 30, 40, 50, 60, 70, 80]);
        // Ucinamy chunk "data" (ostatnie 8 B nagłówka + 8 próbek) - typowe
        // uszkodzenie przy odzysku: ogon pliku przepadł.
        let (_, _, _, fragmenty) = riff_container::dzieci_riff(&zdrowy).unwrap();
        let data = &fragmenty[1];
        let ucieta = &zdrowy[..data.offset];

        let uszkodzony = dir.path().join("dzwiek.wav");
        let dawca = dir.path().join("blizniak.wav");
        std::fs::write(&uszkodzony, ucieta).unwrap();
        std::fs::write(&dawca, &zdrowy).unwrap();

        let kontekst = ctx("wav", Some("PARTIAL"));

        // Kontrola sensu testu: plik ucięty NIE MOŻE przechodzić weryfikacji.
        assert!(
            RiffCloneModule.verify(&uszkodzony, &kontekst).is_err(),
            "ucięty WAV nie powinien przechodzić weryfikacji - inaczej test nie mierzy naprawy"
        );

        let (naprawiony, log) = RiffCloneModule
            .repair(&uszkodzony, &kontekst, Some(&dawca), &wynik)
            .expect("składanie ze zdrowego bliźniaka musi się udać");

        assert!(log.contains("wydmuszk") || log.contains("RIFF"), "log musi opisać kryterium/ograniczenie: {}", log);

        let ocena = RiffCloneModule.verify(&naprawiony, &kontekst).expect("wynik musi przejść weryfikację");
        assert!(ocena.contains("SŁABA"), "gwarancja musi być zadeklarowana jako SŁABA: {}", ocena);

        // Wynik jest bajtowo równy zdrowemu oryginałowi - uszkodzenie dotknęło
        // wyłącznie ogona, a brakujący fragment wrócił w całości.
        assert_eq!(
            std::fs::read(&naprawiony).unwrap(), zdrowy,
            "złożenie ucięcia ze zdrowym bliźniakiem musi odtworzyć oryginał"
        );
    }
}
