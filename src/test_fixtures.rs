// src/test_fixtures.rs

//! # Jedno miejsce budowy fizycznych plików testowych
//!
//! Dziesiątki modułów w tym crate potrzebowały "dajcie mi prawdziwy, poprawny
//! plik formatu X" do testowania logiki naprawczej — i każdy budował go OD
//! ZERA lokalnie. Skutek: PNG, JPEG, ZIP, TAR i minimalny box ISOBMFF
//! istniały jednocześnie w co najmniej dwóch, osobno utrzymywanych kopiach
//! (np. `repair_modules::mod::prawdziwy_png` obok `png_repair`'owej wersji,
//! `repair_modules::archive::zbuduj_zip` obok `zip_splice`'owej), z realnym
//! ryzykiem, że dwie kopie po cichu się rozjadą.
//!
//! ## Zasada: format ma JEDNEGO właściciela
//!
//! Gdy kanoniczna logika formatu (parsowanie, naprawa) już mieszka w module
//! produkcyjnym — PNG w [`crate::png_repair`], JPEG w [`crate::jpeg_splice`],
//! ZIP w [`crate::zip_splice`], TAR w [`crate::tar_archive`] — budowniczy
//! testowy TEŻ tam mieszka, w podmodule `pomoce_testowe`. Ten plik jest
//! wyłącznie CIENKĄ WARSTWĄ delegującą, żeby wszystkie testy w crate'cie
//! miały jedno miejsce importu niezależnie od formatu, zamiast pamiętać,
//! który moduł produkcyjny "jest właścicielem" którego budowniczego.
//!
//! Formaty bez jednego naturalnego właściciela (generyczny box ISOBMFF,
//! używany identycznie przez `video_image`, `repair_modules::heic` i
//! `repair_modules::mp4`) mają swoją JEDYNĄ implementację wprost tutaj.
//!
//! ## Czego tu ŚWIADOMIE nie ma
//!
//! Budowniczych wymagających DROBNOZIARNISTEJ kontroli nad wewnętrzną
//! strukturą pliku (np. `phase18_smart_splice`'owe `build_valid_png`/
//! `build_minimal_jpeg`, przyjmujące gotowe bajty `IHDR`/`IDAT` czy nagłówka
//! SOS) — to nie są budowniczy "dajcie mi poprawny plik", tylko narzędzia do
//! składania KONKRETNYCH, kontrolowanych bajtowo przypadków testowych dla
//! jednego modułu. Zostają tam, gdzie są.

use std::path::{Path, PathBuf};

/// Zapisuje bajty jako plik `nazwa` w katalogu `dir` (tworząc katalogi
/// pośrednie, gdy `nazwa` niesie podkatalogi), zwraca pełną ścieżkę.
pub(crate) fn zapisz(dir: &Path, nazwa: &str, dane: &[u8]) -> PathBuf {
    let p = dir.join(nazwa);
    if let Some(rodzic) = p.parent() {
        let _ = std::fs::create_dir_all(rodzic);
    }
    std::fs::write(&p, dane).expect("zapis pliku testowego musi się udać");
    p
}

/// Prawdziwy, dekodowalny PNG o podanych wymiarach.
///
/// Deleguje do [`crate::png_repair::pomoce_testowe::zdrowy_png`] — kanoniczna
/// implementacja mieszka tam, obok reszty logiki formatu PNG.
pub(crate) fn prawdziwy_png(szer: u32, wys: u32) -> Vec<u8> {
    crate::png_repair::pomoce_testowe::zdrowy_png(szer, wys)
}

/// Buduje prawdziwe archiwum ZIP z podanych wpisów (nazwa, treść).
///
/// Deleguje do [`crate::zip_splice::pomoce_testowe::build_zip`].
pub(crate) fn zbuduj_zip(wpisy: &[(&str, &[u8])]) -> Vec<u8> {
    crate::zip_splice::pomoce_testowe::build_zip(wpisy)
}

/// Buduje prawdziwe archiwum TAR z podanych wpisów (nazwa, treść).
///
/// Deleguje do [`crate::tar_archive::pomoce_testowe::build_tar`].
pub(crate) fn zbuduj_tar(wpisy: &[(&str, &[u8])]) -> Vec<u8> {
    crate::tar_archive::pomoce_testowe::build_tar(wpisy)
}

/// Buduje minimalny box ISOBMFF: rozmiar (BE, 32-bitowy) + typ + treść.
///
/// Ten sam kształt bajtowy potrzebny jest identycznie w `video_image`,
/// `repair_modules::heic` i `repair_modules::mp4` — żaden z nich nie jest
/// "właścicielem" formatu MP4/HEIC bardziej niż pozostałe (to
/// [`mp4_engines::boxes`], osobny crate, dzieli logikę PRODUKCYJNĄ), więc w
/// odróżnieniu od PNG/JPEG/ZIP/TAR ta implementacja mieszka wprost tutaj,
/// zamiast delegować do jednego z nich.
pub(crate) fn box_isobmff(typ: &[u8; 4], tresc: &[u8]) -> Vec<u8> {
    let mut out = ((8 + tresc.len()) as u32).to_be_bytes().to_vec();
    out.extend_from_slice(typ);
    out.extend_from_slice(tresc);
    out
}

/// Czy binarka `ffmpeg` jest dostępna w `PATH` — bramka dla testów e2e, które
/// kodują prawdziwy materiał (`mp4`, `stream`) zamiast składać go ręcznie
/// bajt po bajcie.
pub(crate) fn ffmpeg_dostepny() -> bool {
    std::process::Command::new("ffmpeg")
        .arg("-version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
