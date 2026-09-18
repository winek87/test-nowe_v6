// src/phases/repair_modules/mp3.rs

//! Moduł naprawczy MP3 — składanie ramek MPEG audio z dwóch kopii.
//!
//! ## Ten sam wzorzec co `riff_clone`/`asf_clone`, jedna różnica: brak listy
//!
//! MP3 (patrz [`crate::mp3_stream`]) jest, jak RIFF i ASF, formatem bez sumy
//! kontrolnej per jednostkę — wybór między dwiema kopiami ramki opiera się
//! na tej samej heurystyce "czy nie wygląda na wydmuszkę". Ten moduł jest
//! więc, jak `riff_clone`/`asf_clone`, ZAWSZE gwarancją SŁABĄ i MUSI
//! nadpisać `verify()`. Różnica: ramki mają DŁUGOŚĆ ZMIENNĄ (wyliczaną z
//! nagłówka), więc `splice_mp3` idzie po pozycji bajtowej, nie po liście
//! fragmentów — patrz dokumentacja `mp3_stream::splice_mp3`.
//!
//! ## Skąd sygnał kwalifikacji
//!
//! Żadna faza w projekcie nie diagnozuje MP3 osobno od tego modułu — Faza 19
//! wprawdzie ROZBIERA strumień MP3 (patrz `mp3_stream`/Faza 19), ale to
//! diagnostyka, nie kolumna w `RepairContext`. Jedyny dostępny sygnał to
//! `match_type == Some("PARTIAL")` z korelacji Fazy 14 — DOKŁADNIE ten sam
//! warunek, którego używa [`super::splice::SpliceModule`] dla DOWOLNEGO
//! rozszerzenia. Ten moduł musi więc stać PRZED `splice` w rejestrze — ten
//! sam sygnał, ale świadomy struktury ramek MPEG audio zamiast ślepego
//! zszycia bajt po bajcie.
//!
//! ## Co to realnie ratuje
//!
//! Najczęstsze uszkodzenie przy odzysku to nadpisane/uszkodzone sektory W
//! ŚRODKU pliku (nie tylko ucięty ogon, jak przy RIFF/ASF) — `splice_mp3`
//! zastępuje uszkodzone ramki (na dowolnej pozycji, nie tylko na końcu)
//! wersją z drugiej kopii, dopóki obie kopie zgadzają się co do długości
//! ramek na tej pozycji.

use super::{RepairContext, RepairModule, WynikWeryfikacji};
use crate::mp3_stream;
use std::path::{Path, PathBuf};

/// Górny limit rozmiaru pojedynczej kopii wczytywanej do składania — ten sam
/// powód i ta sama wartość co `riff_clone`/`asf_clone`/`mkv_clone`.
const LIMIT_W_RAM: u64 = 512 * 1024 * 1024; // 512 MB

pub struct Mp3CloneModule;

fn jest_kandydatem_do_skladania(ctx: &RepairContext) -> bool {
    ctx.ext.eq_ignore_ascii_case("mp3") && ctx.match_type == Some("PARTIAL")
}

impl RepairModule for Mp3CloneModule {
    fn id(&self) -> &'static str { "mp3_clone" }

    fn display_name(&self) -> &'static str {
        "MP3 składanie ramek MPEG audio (gwarancja SŁABA)"
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
                    "mp3_clone: plik przekracza limit składania w RAM"
                );
                return None;
            }
        }

        let a = std::fs::read(source).ok()?;
        let b = std::fs::read(dawca).ok()?;

        let wynik = mp3_stream::splice_mp3(&a, &b)?;

        let stem = source.file_stem()?.to_str()?;
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_mp3.mp3", stem));

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
                "Złożono strumień MP3 z dwóch kopii, wybierając ramki niewyglądające na wydmuszkę (dawca: {}). \
                 UWAGA: MP3 nie niesie sumy kontrolnej per ramkę — potwierdzona wyłącznie spójność łańcucha ramek.",
                dawca.display()
            ),
        ))
    }

    /// Weryfikacja z jawnie **osłabioną** etykietą gwarancji — NADPISANIE
    /// KONIECZNE: domyślna gałąź dla `.mp3` sprawdza dziś wyłącznie pierwsze
    /// kilka bajtów (tag ID3 albo synchronizacja JEDNEJ ramki), a MP3 nigdy
    /// nie ma sumy kontrolnej per ramkę, więc etykieta MOCNA nie jest tu
    /// nigdy osiągalna. Reużywa `mp3_stream::analyze_mp3` — DOKŁADNIE ten
    /// sam rozbiór, którego używa diagnostyka Fazy 19 — więc naprawa i
    /// weryfikacja nigdy nie mogą się rozjechać w ocenie tego samego pliku.
    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        let bajty = std::fs::read(repaired).map_err(|e| format!("nie udało się odczytać wyniku: {}", e))?;

        match mp3_stream::analyze_mp3(&bajty) {
            Some(a) if a.is_healthy() => Ok("łańcuch ramek MP3 spójny (gwarancja SŁABA - MP3 nie niesie sumy kontrolnej per ramkę, treść próbek NIE zweryfikowana)"),
            Some(a) => Err(format!("plik ma urwany/niespójny łańcuch ramek MP3: {}", a.describe())),
            None => Err("plik nie ma ani jednej wiarygodnej ramki MPEG audio".to_string()),
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

    /// Buduje `ile` kolejnych, poprawnych ramek MPEG-1/Warstwa III,
    /// 128 kbps/44100 Hz (417 B każda) — ta sama konstrukcja co
    /// `mp3_stream::tests::zbuduj_ramki`, powtórzona tutaj celowo (moduł
    /// naprawczy nie powinien zależeć od prywatnych detali testowych
    /// silnika, tylko od jego publicznego interfejsu).
    fn zbuduj_ramki(ile: usize, wypelniacz: u8) -> Vec<u8> {
        let mut out = Vec::new();
        let naglowek = [0xFFu8, 0xFB, 0x90, 0x00]; // MPEG1/L3, 128 kbps, 44100 Hz, bez paddingu
        for _ in 0..ile {
            out.extend_from_slice(&naglowek);
            out.resize(out.len() + 417 - 4, wypelniacz);
        }
        out
    }

    // ------------------------------------------------------------------
    // Kwalifikacja i kolejność
    // ------------------------------------------------------------------

    #[test]
    fn test_obejmuje_mp3() {
        assert!(Mp3CloneModule.applies_to(&ctx("mp3", Some("PARTIAL"))));
        assert!(Mp3CloneModule.applies_to(&ctx("MP3", Some("PARTIAL"))), "rozszerzenie bez rozróżniania wielkości liter");
    }

    #[test]
    fn test_kwalifikacja_wylacznie_po_match_type_partial() {
        assert!(Mp3CloneModule.applies_to(&ctx("mp3", Some("PARTIAL"))));
        assert!(!Mp3CloneModule.applies_to(&ctx("mp3", Some("FULL"))), "inny match_type nie kwalifikuje");
        assert!(!Mp3CloneModule.applies_to(&ctx("mp3", None)), "brak match_type nie kwalifikuje");
    }

    #[test]
    fn test_nie_rusza_innych_formatow() {
        for ext in ["wav", "wmv", "mkv", "mp4", "jpg", "png", "zip"] {
            assert!(!Mp3CloneModule.applies_to(&ctx(ext, Some("PARTIAL"))), "ext .{}", ext);
        }
    }

    #[test]
    fn test_stoi_przed_splice() {
        let ids: Vec<&str> = super::super::all_modules().iter().map(|m| m.id()).collect();
        let poz = |id: &str| ids.iter().position(|x| *x == id)
            .unwrap_or_else(|| panic!("moduł {} musi być zarejestrowany (kolejność: {:?})", id, ids));

        assert!(
            poz("mp3_clone") < poz("splice"),
            "bajtowe zszycie nie zna struktury ramek MP3 i nie może wyprzedzać składania po ramkach: {:?}", ids
        );
    }

    // ------------------------------------------------------------------
    // Siła gwarancji
    // ------------------------------------------------------------------

    #[test]
    fn test_nazwa_modulu_ujawnia_sile_gwarancji() {
        assert!(Mp3CloneModule.display_name().contains("SŁABA"), "nazwa: {}", Mp3CloneModule.display_name());
    }

    #[test]
    fn test_weryfikacja_zdrowego_pliku_jest_zawsze_slaba_nigdy_mocna() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("zdrowy.mp3");
        std::fs::write(&plik, zbuduj_ramki(4, 0xAA)).unwrap();

        let wynik = Mp3CloneModule.verify(&plik, &ctx("mp3", None)).expect("zdrowy plik musi przejść weryfikację");
        assert!(wynik.contains("SŁABA"), "gwarancja musi być zadeklarowana jako SŁABA: {}", wynik);
        assert!(!wynik.contains("MOCNA"), "MP3 nigdy nie osiąga MOCNEJ gwarancji: {}", wynik);
    }

    #[test]
    fn test_weryfikacja_odrzuca_plik_ktory_nie_jest_mp3() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("smieci.mp3");
        std::fs::write(&plik, b"to nie jest strumien MPEG audio, tylko zwykly tekst").unwrap();

        assert!(Mp3CloneModule.verify(&plik, &ctx("mp3", None)).is_err());
    }

    #[test]
    fn test_weryfikacja_odrzuca_uszkodzony_w_srodku_plik() {
        let dir = tempfile::tempdir().unwrap();
        let mut plik_bajty = zbuduj_ramki(2, 0xAA);
        plik_bajty.extend(vec![0x00u8; 500]);
        plik_bajty.extend(zbuduj_ramki(2, 0xBB));
        let plik = dir.path().join("uszkodzony.mp3");
        std::fs::write(&plik, plik_bajty).unwrap();

        assert!(Mp3CloneModule.verify(&plik, &ctx("mp3", None)).is_err());
    }

    // ------------------------------------------------------------------
    // repair
    // ------------------------------------------------------------------

    #[test]
    fn test_bez_dawcy_zwraca_none() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("dzwiek.mp3");
        std::fs::write(&plik, b"cokolwiek").unwrap();

        assert!(Mp3CloneModule.repair(&plik, &ctx("mp3", Some("PARTIAL")), None, dir.path()).is_none());
    }

    #[test]
    fn test_nieparsowalne_pliki_nie_zostawiaja_wyniku() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let plik = dir.path().join("a.mp3");
        let dawca = dir.path().join("b.mp3");
        std::fs::write(&plik, b"to nie jest mp3, tylko zwykly tekst nic wiecej").unwrap();
        std::fs::write(&dawca, b"to tez nie, kompletnie inne smieci tu stoja").unwrap();

        assert!(Mp3CloneModule.repair(&plik, &ctx("mp3", Some("PARTIAL")), Some(&dawca), &wynik).is_none());
        assert_eq!(std::fs::read_dir(&wynik).unwrap().count(), 0, "po odmowie nie może zostać plik");
    }

    // ------------------------------------------------------------------
    // Pełna ścieżka naprawy — NORMALNY test (bez #[ignore])
    //
    // MP3, jak WAV/ASF, nie wymaga zewnętrznego narzędzia (ffmpeg) do
    // zbudowania prawdziwego, strukturalnie poprawnego strumienia.
    // ------------------------------------------------------------------

    #[test]
    fn test_e2e_uszkodzenie_w_srodku_zostaje_naprawione() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowy = zbuduj_ramki(6, 0xAA);
        // Psujemy TRZECIĄ ramkę (indeks 2) - w środku, nie na końcu - to
        // scenariusz, którego RIFF/ASF (tylko ucięty ogon) NIE naprawiają.
        let mut uszkodzony = zdrowy.clone();
        uszkodzony[2 * 417 + 4..2 * 417 + 417].fill(0);

        let plik = dir.path().join("dzwiek.mp3");
        let dawca = dir.path().join("blizniak.mp3");
        std::fs::write(&plik, &uszkodzony).unwrap();
        std::fs::write(&dawca, &zdrowy).unwrap();

        let kontekst = ctx("mp3", Some("PARTIAL"));

        assert!(
            Mp3CloneModule.verify(&plik, &kontekst).is_ok(),
            "uszkodzenie jednej ramki w środku NIE psuje łańcucha - to celowe, verify() sprawdza tylko ciągłość nagłówków"
        );

        let (naprawiony, log) = Mp3CloneModule
            .repair(&plik, &kontekst, Some(&dawca), &wynik)
            .expect("składanie ze zdrowego bliźniaka musi się udać");

        assert!(log.contains("wydmuszk") || log.contains("MP3"), "log musi opisać kryterium/ograniczenie: {}", log);

        let ocena = Mp3CloneModule.verify(&naprawiony, &kontekst).expect("wynik musi przejść weryfikację");
        assert!(ocena.contains("SŁABA"), "gwarancja musi być zadeklarowana jako SŁABA: {}", ocena);

        assert_eq!(
            std::fs::read(&naprawiony).unwrap(), zdrowy,
            "złożenie musi odtworzyć zdrowy oryginał, łącznie z naprawą ramki W ŚRODKU strumienia"
        );
    }
}
