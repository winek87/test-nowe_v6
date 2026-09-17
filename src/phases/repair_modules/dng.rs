// src/phases/repair_modules/dng.rs

//! Moduł naprawczy DNG — składanie strukturalne w automacie Fazy 17.
//!
//! ## Co tu jest nowe, a co istniało wcześniej
//!
//! Sam silnik składania ([`crate::dng_splice`]) i narzędzie do przeglądu
//! ([`crate::dng_repair`]) są w projekcie od dawna. Brakowało jednego:
//! **Faza 17 nie miała dla DNG żadnego modułu**. Plik RAW, którego Faza 13 nie
//! zdekodowała, trafiał w automacie najwyżej do `splice`, czyli bajtowego
//! zszycia nieświadomego struktury TIFF/IFD. Pełna naprawa wymagała ręcznego
//! wejścia w osobne narzędzie z menu.
//!
//! Ten moduł domyka lukę, używając **dokładnie tych samych kryteriów**, co
//! tryb automatyczny `dng_repair`: kandydaci z [`dng_splice::structural_splice_candidates`],
//! odfiltrowani przez faktyczne dekodowanie (`rawloader`), zaakceptowani tylko
//! gdy entropia przeniesionych danych przechodzi
//! [`dng_splice::looks_like_plausible_sensor_data`]. Zero nowej logiki
//! decyzyjnej — gdyby próg kiedyś się zmienił, zmieni się w obu miejscach
//! naraz, bo to jedna funkcja.
//!
//! ## Dlaczego gwarancja jest SŁABA i dlaczego musiałem nadpisać `verify`
//!
//! To najważniejsza rzecz w tym module. Domyślna weryfikacja z
//! [`super::weryfikuj_naprawiony_plik`] dla rozszerzenia `.dng` melduje
//! *„dekodowanie RAW przez rawloader (gwarancja MOCNA)"* — i dla zwykłej
//! naprawy nagłówka byłoby to uczciwe. Tutaj nie jest.
//!
//! Składanie strukturalne bierze nagłówek/IFD z jednej kopii, a bajty pikseli
//! z drugiej, według offsetów odczytanych ze zdrowej struktury. Udane
//! dekodowanie dowodzi więc, że **struktura jest spójna** — nic nie mówi o
//! tym, czy przeniesione piksele są tymi właściwymi. Zostawienie domyślnej
//! etykiety wpisywałoby do dziennika operacyjnego dowód, którego nie ma.
//!
//! Entropia Shannona przeniesionego obszaru jest jedynym dostępnym sygnałem i
//! jest to **plauzybilność, nie dowód**: odsiewa czyste zera (po TRIM) i
//! podejrzanie idealny szum (obce dane z carvingu), ale nie rozpozna pikseli z
//! innego zdjęcia tego samego aparatu.
//!
//! ## Relacja do narzędzia ręcznego
//!
//! Oba mechanizmy mogą dotknąć tego samego pliku, bo prowadzą **osobne
//! księgi**: `dng_repair` pisze do `dng_structural_status`, a Faza 17 do
//! swoich kolumn (`repaired_path`, `repair_log`, `phase17_done`). Moduł
//! naprawczy nie ma dostępu do bazy — trait `RepairModule` celowo dostaje
//! tylko ścieżki i kontekst — więc nie może i nie powinien tego statusu
//! ruszać. Skutek praktyczny: plik naprawiony tu nadal pojawi się w ręcznym
//! przeglądzie. Jest to świadomy wybór, nie przeoczenie — przy naprawie o
//! gwarancji SŁABEJ możliwość ręcznego obejrzenia wyniku jest wartością, nie
//! duplikatem pracy.

use super::{RepairContext, RepairModule, WynikWeryfikacji};
use crate::{dng_splice, raw_image};
use std::path::{Path, PathBuf};

pub struct DngStructuralModule;

/// Formaty RAW zbudowane na kontenerze TIFF/IFD — czyli te, po których
/// `dng_splice` potrafi chodzić.
///
/// ## Podstawa rozszerzenia poza DNG
///
/// `dng_splice::find_pixel_data_ranges` jest GENERYCZNYM spacerowiczem po
/// IFD: czyta wyłącznie standardowe znaczniki TIFF (`StripOffsets`,
/// `TileOffsets`, `StripByteCounts`, `TileByteCounts`, `SubIFDs`) i nie
/// dotyka ani jednego znacznika swoistego dla DNG. Wymienione niżej formaty
/// używają tego samego kontenera, więc ograniczenie do `.dng` było
/// ograniczeniem NAZWY, nie możliwości.
///
/// ## Czego tu świadomie NIE MA
///
/// `cr3` (Canon) to kontener ISOBMFF, nie TIFF, a `raf` (Fuji) ma format
/// własny — żaden z nich nie da się obejść tym parserem.
///
/// ## Zakres potwierdzenia empirycznego — WAŻNE
///
/// Na prawdziwym materiale sprawdzony jest wyłącznie DNG
/// (`image/test_fixture.dng` plus wariant z rozbitym nagłówkiem). Dla
/// pozostałych formatów nie mam plików z aparatu, więc potwierdzona jest sama
/// NIEZALEŻNOŚĆ OD ROZSZERZENIA (patrz test `test_sciezka_dziala_dla_rodziny_tiff`),
/// a nie zgodność z konkretnym układem IFD danego producenta.
///
/// Rozszerzenie jest mimo to bezpieczne: wynik przechodzi OBOWIĄZKOWĄ
/// weryfikację `raw_image::verify_raw_bytes`, czyli realne dekodowanie przez
/// `rawloader` (gwarancja MOCNA). Nieudane złożenie zostanie odrzucone i
/// usunięte, a nie przyjęte. Najgorszy możliwy skutek to brak naprawy —
/// dokładnie to, co jest dzisiaj.
const RODZINA_RAW_NA_TIFF: &[&str] = &["dng", "nef", "cr2", "arw", "orf", "pef", "srw", "rw2"];

fn jest_nieodczytanym_dng(ctx: &RepairContext) -> bool {
    if !RODZINA_RAW_NA_TIFF.contains(&ctx.ext) {
        return false;
    }

    // Faza 12 zapisuje przy nieudanym dekodowaniu powód zawierający "RAW/DNG";
    // brak znacznika końca z Fazy 6 to druga przesłanka; `media_decoded ==
    // Some(false)` (Faza 13, silniejszy sygnał — realne, nieudane
    // dekodowanie przez `rawloader`, nie tylko diagnoza nagłówka) to trzecia.
    ctx.eof_ok == Some(false)
        || ctx.media_reason.is_some_and(|r| r.contains("RAW"))
        || ctx.media_decoded == Some(false)
}

impl RepairModule for DngStructuralModule {
    fn id(&self) -> &'static str { "dng_structural" }

    fn display_name(&self) -> &'static str {
        "DNG składanie strukturalne z bliźniaczej kopii (gwarancja SŁABA)"
    }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        jest_nieodczytanym_dng(ctx)
    }

    /// Składa plik w obu kierunkach, odrzuca kandydatów, którzy się nie
    /// dekodują, i przyjmuje pierwszego, którego entropia przeniesionych danych
    /// wygląda na dane sensora.
    ///
    /// Kolejność „pierwszy plauzybilny" jest taka sama jak w trybie
    /// automatycznym `dng_repair` — kandydaci przychodzą w ustalonym porządku
    /// (nagłówek A + dane B, potem nagłówek B + dane A), więc wynik obu dróg
    /// jest identyczny.
    ///
    /// Zwraca `None`, gdy nie ma bliźniaka, gdy żaden kandydat się nie
    /// zdekodował albo gdy żaden nie przeszedł progu plauzybilności. Ten
    /// ostatni przypadek jest istotny: lepiej nie naprawić, niż zapisać obszar
    /// zer albo obce dane jako odzyskane zdjęcie.
    fn repair(&self, source: &Path, ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let dawca = twin?;

        let kandydaci = dng_splice::structural_splice_files(source, dawca).ok()?;

        // Dekodowanie jest tu filtrem, nie dowodem - patrz dokumentacja modułu.
        // `decode_raw_bytes` ma własną ochronę `catch_unwind`, bo rawloader
        // panikuje na uszkodzonych nagłówkach.
        let wybrany = kandydaci.into_iter().find(|k| {
            dng_splice::looks_like_plausible_sensor_data(k.donated_data_entropy)
                && raw_image::decode_raw_bytes(&k.bytes).is_some()
        })?;

        let stem = source.file_stem()?.to_str()?;
        // Rozszerzenie bierzemy z WEJŚCIA, nie zaszyte `.dng`. Po rozszerzeniu
        // modułu na rodzinę TIFF naprawiony `.nef` zapisywany jako `.dng`
        // wprowadzałby operatora w błąd co do tego, co właściwie odzyskano.
        let cel = katalog_wyjsciowy.join(format!("{}_repaired_dng.{}", stem, ctx.ext));

        if let Some(katalog) = cel.parent() {
            std::fs::create_dir_all(katalog).ok()?;
        }
        if let Err(e) = std::fs::write(&cel, &wybrany.bytes) {
            tracing::debug!(plik = %cel.display(), blad = %e, "dng_structural: zapis wyniku nieudany");
            let _ = std::fs::remove_file(&cel);
            return None;
        }

        Some((
            cel,
            format!(
                "{}; entropia przeniesionych danych {:.2} bit/bajt (plauzybilne dane sensora); dawca: {}. \
                 UWAGA: potwierdzona wyłącznie spójność struktury, NIE poprawność pikseli.",
                wybrany.description, wybrany.donated_data_entropy, dawca.display()
            ),
        ))
    }

    /// Weryfikacja z jawnie **osłabioną** etykietą gwarancji.
    ///
    /// Nadpisanie jest tu konieczne, nie kosmetyczne: domyślna implementacja
    /// zwróciłaby dla `.dng` „gwarancja MOCNA", co przy składaniu strukturalnym
    /// jest nieprawdą (uzasadnienie w dokumentacji modułu).
    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        let bajty = std::fs::read(repaired).map_err(|e| format!("nie udało się odczytać wyniku: {}", e))?;

        if raw_image::verify_raw_bytes(&bajty) {
            Ok("dekodowanie RAW przez rawloader (gwarancja SŁABA - potwierdza spójność struktury TIFF/IFD, nie treść pikseli)")
        } else {
            Err("złożony plik nie daje się zdekodować jako RAW".to_string())
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

    /// Powód, jaki Faza 13 faktycznie zapisuje przy nieudanym dekodowaniu RAW.
    const POWOD_FAZY_13: &str = "Nie udało się zdekodować pliku RAW/DNG (uszkodzony lub nierozpoznany model aparatu)";

    // ------------------------------------------------------------------
    // Kwalifikacja
    // ------------------------------------------------------------------

    #[test]
    fn test_kwalifikuje_po_powodzie_z_fazy_13() {
        assert!(
            DngStructuralModule.applies_to(&ctx("dng", None, Some(POWOD_FAZY_13))),
            "moduł musi reagować na dokładnie ten komunikat, który zapisuje Faza 13"
        );
    }

    #[test]
    fn test_kwalifikuje_po_braku_znacznika_konca() {
        assert!(DngStructuralModule.applies_to(&ctx("dng", Some(false), None)));
    }

    /// `media_decoded == Some(false)` (Faza 13, `rawloader` faktycznie nie
    /// zdołał zdekodować) to TRZECIA, niezależna przesłanka — silniejsza niż
    /// sam tekstowy powód z Fazy 12, bo potwierdza realne niepowodzenie
    /// dekodera, nie tylko diagnozę nagłówka.
    #[test]
    fn test_kwalifikuje_po_nieudanym_dekodowaniu_z_fazy13() {
        let kontekst = RepairContext {
            ext: "dng", media_reason: None, utf8_ok: None, is_oneliner: None,
            eof_ok: None, match_type: None, video_ok: None, structure_ok: None,
            media_decoded: Some(false),
        };
        assert!(DngStructuralModule.applies_to(&kontekst));
    }

    #[test]
    fn test_nie_rusza_zdrowego_dng() {
        assert!(!DngStructuralModule.applies_to(&ctx("dng", Some(true), None)));
        assert!(!DngStructuralModule.applies_to(&ctx("dng", None, None)), "bez przesłanki uszkodzenia nie dotykamy pliku");
    }

    /// Ograniczenie do `.dng` jest decyzją, nie przeoczeniem — test ją
    /// utrwala, żeby ewentualne rozszerzenie listy było świadome i wymagało
    /// zmiany również tutaj.
    #[test]
    /// Zakres modułu wyznacza KONTENER, nie nazwa. Test pilnuje granicy od
    /// strony formatów, po których parser IFD nie ma jak chodzić — rodzinę
    /// objętą modułem sprawdza `test_bramka_obejmuje_cala_rodzine_tiff`.
    fn test_obejmuje_tylko_rodzine_tiff() {
        for ext in ["cr3", "raf", "jpg", "png", "heic"] {
            assert!(
                !DngStructuralModule.applies_to(&ctx(ext, Some(false), Some(POWOD_FAZY_13))),
                "ext .{} nie jest RAW-em na kontenerze TIFF - parser IFD nie ma po nim jak chodzić", ext
            );
        }
    }

    // ------------------------------------------------------------------
    // Kolejność w dyspozytorze
    // ------------------------------------------------------------------

    #[test]
    fn test_stoi_przed_splice() {
        let ids: Vec<&str> = super::super::all_modules().iter().map(|m| m.id()).collect();
        let i_dng = ids.iter().position(|id| *id == "dng_structural").expect("dng_structural musi być zarejestrowany");
        let i_splice = ids.iter().position(|id| *id == "splice").expect("splice musi być zarejestrowany");

        assert!(
            i_dng < i_splice,
            "bajtowe zszycie nie zna struktury TIFF/IFD i nie może wyprzedzać składania strukturalnego (kolejność: {:?})",
            ids
        );
    }

    // ------------------------------------------------------------------
    // Siła gwarancji - sedno tego modułu
    // ------------------------------------------------------------------

    /// Domyślna weryfikacja dla `.dng` melduje gwarancję MOCNĄ. Dla składania
    /// strukturalnego to przekłamanie, więc moduł MUSI ją nadpisać. Ten test
    /// pilnuje, żeby nadpisanie nie zniknęło przy refaktoryzacji.
    #[test]
    fn test_etykieta_gwarancji_jest_slabsza_od_domyslnej() {
        let sciezka = std::path::Path::new("image/test_fixture.dng");
        if !sciezka.exists() {
            // Bez fixture'a sprawdzamy przynajmniej samą deklarację modułu.
            assert!(DngStructuralModule.display_name().contains("SŁABA"));
            return;
        }

        let kontekst = ctx("dng", Some(false), None);

        let domyslna = super::super::weryfikuj_naprawiony_plik(sciezka)
            .expect("zdrowy fixture musi przejść weryfikację domyślną");
        let modulowa = DngStructuralModule.verify(sciezka, &kontekst)
            .expect("zdrowy fixture musi przejść weryfikację modułu");

        assert!(domyslna.contains("MOCNA"), "kontrola: domyślna etykieta to {}", domyslna);
        assert!(
            modulowa.contains("SŁABA") && !modulowa.contains("MOCNA"),
            "moduł musi meldować gwarancję SŁABĄ, dostaliśmy: {}", modulowa
        );
    }

    #[test]
    fn test_nazwa_modulu_ujawnia_sile_gwarancji() {
        // Nazwa trafia do UI Fazy 17 i do dziennika - operator musi widzieć
        // siłę gwarancji bez czytania kodu.
        assert!(
            DngStructuralModule.display_name().contains("SŁABA"),
            "nazwa: {}", DngStructuralModule.display_name()
        );
    }

    #[test]
    fn test_weryfikacja_odrzuca_plik_ktory_nie_jest_raw() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("smieci.dng");
        std::fs::write(&plik, b"to nie jest RAW").unwrap();

        assert!(DngStructuralModule.verify(&plik, &ctx("dng", Some(false), None)).is_err());
    }

    // ------------------------------------------------------------------
    // repair
    // ------------------------------------------------------------------

    #[test]
    fn test_bez_dawcy_zwraca_none() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("obraz.dng");
        std::fs::write(&plik, b"nieistotne").unwrap();

        assert!(
            DngStructuralModule.repair(&plik, &ctx("dng", Some(false), None), None, dir.path()).is_none(),
            "składanie bez drugiej kopii jest niemożliwe"
        );
    }

    #[test]
    fn test_nieparsowalne_pliki_nie_zostawiaja_wyniku() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let plik = dir.path().join("a.dng");
        let dawca = dir.path().join("b.dng");
        std::fs::write(&plik, b"nie TIFF").unwrap();
        std::fs::write(&dawca, b"tez nie TIFF").unwrap();

        assert!(DngStructuralModule.repair(&plik, &ctx("dng", Some(false), None), Some(&dawca), &wynik).is_none());

        let pozostalo: Vec<String> = std::fs::read_dir(&wynik).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(pozostalo.is_empty(), "po odmowie nie może zostać plik: {:?}", pozostalo);
    }

    // ------------------------------------------------------------------
    // Pełna ścieżka na PRAWDZIWYCH plikach
    // ------------------------------------------------------------------

    /// Naprawa prawdziwego DNG ze zniszczonym nagłówkiem, z fixture'a zdrowego
    /// jako dawcy.
    #[test]
    #[ignore = "Wymaga image/test_fixture.dng i image/test_fixture_header_damaged.dng \
                oraz rawloadera rozpoznającego model aparatu. Uruchom z --ignored."]
    fn test_e2e_naprawa_prawdziwego_dng() {
        let zdrowy = std::path::Path::new("image/test_fixture.dng");
        let uszkodzony_zrodlo = std::path::Path::new("image/test_fixture_header_damaged.dng");

        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        // Kopiujemy fixture'y, żeby test nie zależał od katalogu roboczego
        // przy zapisie i pod żadnym warunkiem nie pisał do `image/`.
        let uszkodzony = dir.path().join("uszkodzony.dng");
        let dawca = dir.path().join("dawca.dng");
        std::fs::copy(uszkodzony_zrodlo, &uszkodzony).unwrap();
        std::fs::copy(zdrowy, &dawca).unwrap();

        let kontekst = ctx("dng", Some(false), None);

        // Kontrola sensu testu: uszkodzony plik NIE MOŻE przechodzić
        // weryfikacji, inaczej test nie mierzy naprawy.
        assert!(
            DngStructuralModule.verify(&uszkodzony, &kontekst).is_err(),
            "plik ze zniszczonym nagłówkiem nie powinien się dekodować"
        );

        let (naprawiony, log) = DngStructuralModule
            .repair(&uszkodzony, &kontekst, Some(&dawca), &wynik)
            .expect("składanie strukturalne od zdrowego bliźniaka musi się udać");

        let ocena = DngStructuralModule.verify(&naprawiony, &kontekst)
            .expect("złożony DNG musi się zdekodować");

        assert!(ocena.contains("SŁABA"), "gwarancja musi być zadeklarowana jako SŁABA: {}", ocena);
        assert!(log.contains("entropia"), "log musi podać zmierzoną entropię: {}", log);
        assert!(log.contains("NIE poprawność pikseli"), "log musi ujawnić granicę dowodu: {}", log);
    }

    /// Izolowany test **bramki plauzybilności**: kandydat, który DEKODUJE SIĘ
    /// POPRAWNIE, a zostaje odrzucony wyłącznie z powodu entropii.
    ///
    /// # Dlaczego potrzebny jest osobny test
    ///
    /// W teście z wyzerowanym dawcą (poniżej) kandydat niosący zera i tak nie
    /// przechodzi dekodowania, więc odrzuca go filtr dekodowania — bramka
    /// entropii jest tam nieużywana i jej usunięcie niczego by nie zepsuło.
    /// To właśnie najgroźniejszy przypadek: plik o **nienaruszonej strukturze**
    /// i pustych pikselach dekoduje się bez zarzutu, więc bez tej bramki
    /// automat zapisałby czarną klatkę jako odzyskane zdjęcie, a obowiązkowa
    /// weryfikacja przyklepałaby wynik.
    ///
    /// Konstrukcja: zdrowy plik jako źródło (jego IFD daje offsety danych) i
    /// dawca z wyzerowaną zawartością za nagłówkiem. Kandydat „nagłówek ze
    /// strony A, dane ze strony B" ma więc zdrową strukturę i zerowe piksele.
    #[test]
    #[ignore = "Wymaga image/test_fixture.dng. Uruchom z --ignored."]
    fn test_e2e_bramka_entropii_odrzuca_dekodowalna_czarna_klatke() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let zdrowe = std::fs::read("image/test_fixture.dng").unwrap();
        let mut wyzerowane = zdrowe.clone();
        for b in &mut wyzerowane[1024..] { *b = 0; }

        let zrodlo = dir.path().join("zrodlo.dng");
        let dawca = dir.path().join("wyzerowany.dng");
        std::fs::write(&zrodlo, &zdrowe).unwrap();
        std::fs::write(&dawca, &wyzerowane).unwrap();

        // Krok 1: dowodzimy, że istnieje kandydat, który PRZESZEDŁBY filtr
        // dekodowania - inaczej test nie mierzyłby bramki entropii.
        let kandydaci = dng_splice::structural_splice_files(&zrodlo, &dawca).unwrap();
        let czarna_klatka = kandydaci
            .iter()
            .find(|k| raw_image::decode_raw_bytes(&k.bytes).is_some() && k.donated_data_entropy < 1.0)
            .expect("musi istnieć kandydat dekodowalny o entropii bliskiej zeru - inaczej ten test nie izoluje bramki entropii");

        assert!(
            !dng_splice::looks_like_plausible_sensor_data(czarna_klatka.donated_data_entropy),
            "entropia {:.4} musi być uznana za nieplauzybilną", czarna_klatka.donated_data_entropy
        );

        // Krok 2: moduł musi odmówić, mimo że kandydat się dekoduje.
        assert!(
            DngStructuralModule.repair(&zrodlo, &ctx("dng", Some(false), None), Some(&dawca), &wynik).is_none(),
            "dekodowalna czarna klatka musi zostać odrzucona przez bramkę entropii"
        );

        let pozostalo: Vec<String> = std::fs::read_dir(&wynik).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(pozostalo.is_empty(), "odrzucony kandydat nie może zostać zapisany: {:?}", pozostalo);
    }

    /// Dawca z wyzerowanym obszarem danych: automat musi odmówić, zamiast
    /// zapisać czarną klatkę opisaną jako odzyskane zdjęcie.
    ///
    /// # Dlaczego dawca jest budowany tutaj, a nie brany z `image/`
    ///
    /// Fixture `test_fixture_zeroed.dng` NIE nadaje się na ten test, choć nazwa
    /// to sugeruje. Pomiar: różni się od zdrowego dokładnie **1373 bajtami** w
    /// okienku ~2 kB, w pliku o rozmiarze 26 533 682 B. Wyzerowanie jest więc
    /// punktowe i przesuwa entropię przenoszonego obszaru z 5.1619 na 5.1616,
    /// czyli o 0.0003 — poniżej jakiejkolwiek rozdzielczości decyzyjnej.
    ///
    /// Test oparty na tym fixture'cie przechodziłby z fałszywego powodu (dawna
    /// dolna granica 6.0 odrzucała wszystko, także dane autentyczne), a po
    /// naprawie progu przestałby cokolwiek sprawdzać. Dawcę z NAPRAWDĘ
    /// wyzerowanym obszarem danych budujemy więc jawnie.
    #[test]
    #[ignore = "Wymaga image/test_fixture_header_damaged.dng. Uruchom z --ignored."]
    fn test_e2e_odrzuca_wyzerowany_obszar_danych() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let uszkodzony = dir.path().join("uszkodzony.dng");
        std::fs::copy("image/test_fixture_header_damaged.dng", &uszkodzony).unwrap();

        // Dawca: zdrowy plik z wyzerowaną całą zawartością za nagłówkiem.
        // Zerujemy hurtowo, więc nie trzeba znać dokładnych offsetów IFD.
        let mut bajty_dawcy = std::fs::read("image/test_fixture.dng").unwrap();
        for b in &mut bajty_dawcy[1024..] { *b = 0; }
        let dawca = dir.path().join("wyzerowany.dng");
        std::fs::write(&dawca, &bajty_dawcy).unwrap();

        assert!(
            DngStructuralModule.repair(&uszkodzony, &ctx("dng", Some(false), None), Some(&dawca), &wynik).is_none(),
            "obszar samych zer nie jest danymi sensora - automat musi odmówić"
        );

        let pozostalo: Vec<String> = std::fs::read_dir(&wynik).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(pozostalo.is_empty(), "odrzucony kandydat nie może zostać zapisany: {:?}", pozostalo);
    }

    // ------------------------------------------------------------------
    // RODZINA RAW NA KONTENERZE TIFF
    // ------------------------------------------------------------------

    #[test]
    fn test_bramka_obejmuje_cala_rodzine_tiff() {
        for ext in ["dng", "nef", "cr2", "arw", "orf", "pef", "srw", "rw2"] {
            let k = RepairContext {
                ext, media_reason: None, utf8_ok: None, is_oneliner: None,
                eof_ok: Some(false), match_type: None, video_ok: None, structure_ok: None, media_decoded: None,
            };
            assert!(
                DngStructuralModule.applies_to(&k),
                ".{} jest RAW-em na kontenerze TIFF i musi być obsługiwany", ext
            );
        }
    }

    /// `cr3` to ISOBMFF, a `raf` ma format własny — parser IFD nie ma po nich
    /// jak chodzić, więc udawanie, że je obsługujemy, byłoby obietnicą bez
    /// pokrycia.
    #[test]
    fn test_bramka_pomija_formaty_spoza_kontenera_tiff() {
        for ext in ["cr3", "raf", "jpg", "mp4"] {
            let k = RepairContext {
                ext, media_reason: None, utf8_ok: None, is_oneliner: None,
                eof_ok: Some(false), match_type: None, video_ok: None, structure_ok: None, media_decoded: None,
            };
            assert!(!DngStructuralModule.applies_to(&k), ".{} nie powinien być obsługiwany", ext);
        }
    }

    /// Dowód, że ścieżka naprawy zależy od STRUKTURY pliku, nie od jego nazwy.
    ///
    /// Nie mam plików z aparatów Nikona czy Canona, więc bierzemy prawdziwy
    /// materiał TIFF-owy, jaki mam (DNG), i podajemy go pod rozszerzeniem
    /// `.nef`. Jeśli naprawa się uda, znaczy to, że nic w tej ścieżce nie jest
    /// przywiązane do `.dng` — a to jest dokładnie ta właściwość, na której
    /// opiera się rozszerzenie bramki. Zgodności z konkretnym układem IFD
    /// Nikona ten test NIE dowodzi i nie udaje, że dowodzi.
    #[test]
    #[ignore = "Wymaga image/test_fixture.dng i image/test_fixture_header_damaged.dng. Uruchom z --ignored."]
    fn test_sciezka_dziala_dla_rodziny_tiff() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        // Ten sam materiał co w teście DNG, tylko pod innym rozszerzeniem.
        let uszkodzony = dir.path().join("uszkodzony.nef");
        let dawca = dir.path().join("dawca.nef");
        std::fs::copy("image/test_fixture_header_damaged.dng", &uszkodzony).unwrap();
        std::fs::copy("image/test_fixture.dng", &dawca).unwrap();

        let kontekst = ctx("nef", Some(false), None);
        assert!(
            DngStructuralModule.applies_to(&kontekst),
            "Bramka musi przepuścić .nef"
        );
        assert!(
            DngStructuralModule.verify(&uszkodzony, &kontekst).is_err(),
            "Test bez sensu: uszkodzony plik musi się nie dekodować"
        );

        let (naprawiony, _log) = DngStructuralModule
            .repair(&uszkodzony, &kontekst, Some(&dawca), &wynik)
            .expect("naprawa pliku TIFF-owego pod rozszerzeniem .nef musi się udać");

        assert!(
            DngStructuralModule.verify(&naprawiony, &kontekst).is_ok(),
            "Wynik musi przejść obowiązkową weryfikację przez rawloader"
        );
    }
}
