// src/video_image.rs

//! # Diagnostyka Kontenerów Wideo (MP4/MOV/M4V)
//!
//! **STATUS: WPIĘTY.** Używany przez `phases::phase19_video`,
//! `phases::repair_modules::mod` (gałąź ISOBMFF `weryfikuj_naprawiony_plik`)
//! i `logging`. Nagłówek wcześniej twierdził „jeszcze niewpięty w żadną
//! fazę" — to przestało być prawdą, ten sam wzorzec co `raw_image` (DNG) i
//! `heic_image` (HEIC).
//!
//! ## Co ten moduł ROBI, a czego NIE robi
//!
//! Odczytuje **strukturę kontenera ISOBMFF** (boxy `ftyp`/`moov`/`mdat`,
//! ścieżki, czas trwania, kodeki) przez crate `mp4` — **czysty Rust, zero
//! zależności systemowych**, w odróżnieniu od `heic_image` (wymaga
//! `libheif`). To ważna zaleta wdrożeniowa.
//!
//! **NIE dekoduje klatek wideo.** To nie jest przeoczenie, tylko realne
//! ograniczenie: dekodowanie H.264/HEVC wymagałoby `ffmpeg` jako ciężkiej
//! zależności systemowej. Sukces odczytu oznacza więc "kontener i tablice
//! indeksowe są spójne", NIE "obraz się wyświetli".
//!
//! ## Wnioski co do NAPRAWY (ważne — patrz `video_repair`)
//!
//! Zweryfikowane empirycznie: MP4/MOV **nie mają sum kontrolnych per box**
//! (w odróżnieniu od chunków PNG czy wpisów ZIP, gdzie CRC32 daje obiektywny
//! dowód). To stawia wideo w tej samej klasie co DNG — możliwa jest tylko
//! naprawa STRUKTURALNA, bez dowodu na poprawność treści klatek.
//!
//! Zweryfikowano też, że komunikaty błędów crate'a `mp4` są konkretne
//! (`ftyp not found`, `moov not found`, `box with a larger size than it`),
//! co pozwala klasyfikować RODZAJ uszkodzenia — patrz [`classify_video_error`].

use std::io::Cursor;
use std::path::Path;

/// Informacje o poprawnie odczytanym kontenerze wideo.
#[derive(Debug, Clone, PartialEq)]
pub struct VideoInfo {
    /// Czas trwania w milisekundach.
    pub duration_ms: u64,
    /// Liczba ścieżek (wideo + audio + napisy).
    pub track_count: usize,
    /// Rozmiar zadeklarowany w strukturze kontenera.
    pub declared_size: u64,
}

/// Kategoria uszkodzenia kontenera — wywiedziona z konkretnego komunikatu
/// crate'a `mp4` (zweryfikowane empirycznie, nie zgadywane).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoDamage {
    /// Brak nagłówka `ftyp` — plik nie zaczyna się jak kontener ISOBMFF
    /// (fałszywe rozszerzenie albo urwany początek).
    MissingFtyp,
    /// Brak boxu `moov` — TABLICE INDEKSOWE (gdzie leżą klatki) zniszczone
    /// albo ucięte. Najczęstszy realny przypadek przy przerwanym nagrywaniu:
    /// `mdat` (właściwe dane) jest, ale `moov` nie zdążył się zapisać.
    MissingMoov,
    /// Zadeklarowany rozmiar boxu wykracza poza fizyczny rozmiar pliku —
    /// klasyczny objaw UCIĘCIA pliku w trakcie kopiowania/odzysku.
    TruncatedBox,
    /// Inne uszkodzenie struktury.
    Other,
}

/// Klasyfikuje komunikat błędu (już zlowercase'owany) do kategorii
/// [`VideoDamage`]. Wzorce potwierdzone empirycznie na realnych błędach
/// zwracanych przez crate `mp4` w wersji 0.14.
pub fn classify_video_error(err_lower: &str) -> VideoDamage {
    if err_lower.contains("ftyp not found") { VideoDamage::MissingFtyp }
    else if err_lower.contains("moov not found") { VideoDamage::MissingMoov }
    else if err_lower.contains("larger size") || err_lower.contains("unexpected eof") { VideoDamage::TruncatedBox }
    else { VideoDamage::Other }
}

/// Zwraca opis kategorii uszkodzenia po polsku — do zapisania w
/// `decode_reason_*` (Faza 13) i pokazania użytkownikowi.
pub fn damage_description(damage: VideoDamage) -> &'static str {
    match damage {
        VideoDamage::MissingFtyp => "Brak nagłówka kontenera ISOBMFF (ftyp) - fałszywe rozszerzenie lub urwany początek",
        VideoDamage::MissingMoov => "Brak tablic indeksowych (moov) - dane klatek mogą istnieć, ale nie ma mapy gdzie leżą",
        VideoDamage::TruncatedBox => "Plik ucięty - zadeklarowany rozmiar struktury wykracza poza fizyczny koniec pliku",
        VideoDamage::Other => "Uszkodzona struktura kontenera wideo",
    }
}

thread_local! {
    /// Patrz `raw_image::EXPECTED_PANIC_IN_PROGRESS` — ta sama rola.
    /// Zweryfikowano empirycznie, że crate `mp4` zwraca bezpieczny `Err` na
    /// wszystkich testowanych uszkodzeniach, ale zabezpieczamy tak samo jak
    /// przy `rawloader` — tam też wstępne testy wypadły czysto, a panika
    /// pojawiła się dopiero na konkretnym pliku z praktyki.
    static EXPECTED_PANIC_IN_PROGRESS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub fn is_expected_panic_in_progress() -> bool {
    EXPECTED_PANIC_IN_PROGRESS.with(|f| f.get())
}

fn with_expected_panic_guard<T>(f: impl FnOnce() -> T) -> std::thread::Result<T> {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) { EXPECTED_PANIC_IN_PROGRESS.with(|f| f.set(false)); }
    }
    EXPECTED_PANIC_IN_PROGRESS.with(|f| f.set(true));
    let _guard = Guard;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
}

/// Rozpoznaje rozszerzenia obsługiwane przez ten moduł. MKV/WebM CELOWO
/// pominięte — to inna rodzina kontenerów (Matroska, nie ISOBMFF), crate
/// `mp4` ich nie obsługuje.
pub fn is_video_extension(path_str: &str) -> bool {
    let lower = path_str.to_lowercase();
    lower.ends_with(".mp4") || lower.ends_with(".mov") || lower.ends_with(".m4v")
}

/// Odczytuje strukturę kontenera z bufora w pamięci. `Ok` = kontener spójny,
/// `Err(VideoDamage)` = sklasyfikowane uszkodzenie.
pub fn read_video_bytes(bytes: &[u8]) -> std::result::Result<VideoInfo, VideoDamage> {
    let size = bytes.len() as u64;
    let outcome = with_expected_panic_guard(|| {
        mp4::Mp4Reader::read_header(Cursor::new(bytes), size)
    });
    match outcome {
        Ok(Ok(reader)) => Ok(VideoInfo {
            duration_ms: reader.duration().as_millis() as u64,
            track_count: reader.tracks().len(),
            declared_size: reader.size(),
        }),
        Ok(Err(e)) => Err(classify_video_error(&e.to_string().to_lowercase())),
        Err(_) => Err(VideoDamage::Other),
    }
}

/// Wariant [`read_video_bytes`] operujący na pliku na dysku.
pub fn read_video_file(path: &Path) -> std::result::Result<VideoInfo, VideoDamage> {
    let bytes = std::fs::read(path).map_err(|_| VideoDamage::Other)?;
    read_video_bytes(&bytes)
}

/// Jedyny warunek "kontener ISOBMFF jest spójny": daje się sparsować i ma co
/// najmniej jedną ścieżkę. UWAGA: to weryfikacja STRUKTURY, nie treści klatek
/// (patrz dokumentacja modułu) — ta sama klasa gwarancji co przy DNG.
///
/// ## Dlaczego istnieje obok ffmpeg-owej weryfikacji Fazy 17
///
/// Dla `.mp4`/`.mov`/`.m4v`/`.3gp`/`.3g2`/`.f4v` mocniejszym dowodem jest pełne
/// dekodowanie klatek (`repair_modules::mp4::weryfikuj_wideo`), więc tam ta
/// funkcja nie jest potrzebna. Ale ten sam kontener nosi też materiał
/// WYŁĄCZNIE AUDIO (`.m4a`, `.m4b`), a ffmpeg-owy sędzia (`is_healthy_video`)
/// wymaga w TEST 2 strumienia `v:0` z szerokością i wysokością. Sprawdzone
/// empirycznie na pliku z ffmpeg: dla `.m4a` zapytanie o `v:0` zwraca pusty
/// wynik, więc poprawnie naprawiony plik audio zostałby uznany za zepsuty i
/// USUNIĘTY. Dlatego gałąź audio w
/// `phases::repair_modules::weryfikuj_naprawiony_plik` używa tej funkcji:
/// [`VideoInfo::track_count`] liczy WSZYSTKIE ścieżki (obraz, dźwięk, napisy),
/// więc plik audio-only przechodzi uczciwie, bez zawyżania gwarancji.
pub fn verify_video_bytes(bytes: &[u8]) -> bool {
    match read_video_bytes(bytes) {
        Ok(info) => info.track_count > 0,
        Err(_) => false,
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Buduje minimalny box ISOBMFF: 4 bajty rozmiaru (big-endian) + 4 bajty
    /// typu + dane.
    fn build_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let size = (8 + payload.len()) as u32;
        let mut out = size.to_be_bytes().to_vec();
        out.extend_from_slice(box_type);
        out.extend_from_slice(payload);
        out
    }

    fn build_ftyp() -> Vec<u8> {
        let mut payload = b"isom".to_vec();
        payload.extend_from_slice(&[0x00, 0x00, 0x02, 0x00]);
        payload.extend_from_slice(b"isomiso2");
        build_box(b"ftyp", &payload)
    }

    // ------------------------------------------------------------------
    // classify_video_error - wzorce potwierdzone empirycznie
    // ------------------------------------------------------------------

    #[test]
    fn test_classify_missing_ftyp() {
        assert_eq!(classify_video_error("ftyp not found"), VideoDamage::MissingFtyp);
    }

    #[test]
    fn test_classify_missing_moov() {
        assert_eq!(classify_video_error("moov not found"), VideoDamage::MissingMoov);
    }

    #[test]
    fn test_classify_truncated() {
        assert_eq!(classify_video_error("file contains a box with a larger size than it"), VideoDamage::TruncatedBox);
        assert_eq!(classify_video_error("unexpected eof while reading"), VideoDamage::TruncatedBox);
    }

    #[test]
    fn test_classify_unknown_falls_back_to_other() {
        assert_eq!(classify_video_error("jakis zupelnie inny blad"), VideoDamage::Other);
    }

    #[test]
    fn test_damage_description_never_empty() {
        for d in [VideoDamage::MissingFtyp, VideoDamage::MissingMoov, VideoDamage::TruncatedBox, VideoDamage::Other] {
            assert!(!damage_description(d).is_empty());
        }
    }

    // ------------------------------------------------------------------
    // read_video_bytes - odporność (zweryfikowana empirycznie przed napisaniem)
    // ------------------------------------------------------------------

    #[test]
    fn test_read_garbage_is_classified_not_panic() {
        let result = read_video_bytes(b"to na pewno nie jest plik MP4 w ogole");
        assert!(result.is_err());
    }

    #[test]
    fn test_read_empty_buffer_is_missing_ftyp() {
        assert_eq!(read_video_bytes(b""), Err(VideoDamage::MissingFtyp));
    }

    #[test]
    fn test_read_ftyp_only_is_missing_moov() {
        // Realny scenariusz: nagrywanie przerwane zanim moov został zapisany.
        let ftyp = build_ftyp();
        assert_eq!(read_video_bytes(&ftyp), Err(VideoDamage::MissingMoov));
    }

    #[test]
    fn test_read_absurd_box_size_is_truncated() {
        let mut bogus = build_ftyp();
        bogus.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xF0]);
        bogus.extend_from_slice(b"mdat");
        assert_eq!(read_video_bytes(&bogus), Err(VideoDamage::TruncatedBox));
    }

    #[test]
    fn test_verify_rejects_all_damaged_inputs() {
        assert!(!verify_video_bytes(b""));
        assert!(!verify_video_bytes(b"smieci"));
        assert!(!verify_video_bytes(&build_ftyp()));
    }

    #[test]
    fn test_read_video_file_nonexistent_is_error() {
        assert!(read_video_file(Path::new("/nie/ma/takiego.mp4")).is_err());
    }

    // ------------------------------------------------------------------
    // is_video_extension
    // ------------------------------------------------------------------

    #[test]
    fn test_is_video_extension_recognizes_isobmff_family() {
        assert!(is_video_extension("film.mp4"));
        assert!(is_video_extension("FILM.MP4"));
        assert!(is_video_extension("film.mov"));
        assert!(is_video_extension("film.m4v"));
    }

    #[test]
    fn test_is_video_extension_excludes_matroska() {
        // MKV/WebM to inna rodzina kontenerów - crate `mp4` ich nie obsługuje,
        // więc świadomie NIE deklarujemy ich jako obsługiwanych.
        assert!(!is_video_extension("film.mkv"));
        assert!(!is_video_extension("film.webm"));
        assert!(!is_video_extension("film.avi"));
    }

    // ------------------------------------------------------------------
    // Flaga oczekiwanej paniki (ten sam kontrakt co raw_image/heic_image)
    // ------------------------------------------------------------------

    #[test]
    fn test_expected_panic_flag_cleared_after_call() {
        let _ = read_video_bytes(b"smieci");
        assert!(!is_expected_panic_in_progress());
    }

    #[test]
    fn test_expected_panic_flag_cleared_even_when_closure_panics() {
        let result = with_expected_panic_guard(|| -> () { panic!("symulowana panika") });
        assert!(result.is_err());
        assert!(!is_expected_panic_in_progress());
    }

    #[test]
    #[ignore = "Wymaga prawdziwego pliku MP4 jako fixture. Umieść plik pod \
                `image/test_fixture.mp4` i uruchom: \
                `cargo test read_real_video_fixture -- --ignored --nocapture`."]
    fn test_read_real_video_fixture() {
        let info = read_video_file(Path::new("image/test_fixture.mp4"))
            .expect("Prawdziwy plik MP4 powinien się odczytać");
        assert!(info.track_count > 0);
        println!("✔ Odczytano MP4: {} ścieżek, {} ms, {} bajtów", info.track_count, info.duration_ms, info.declared_size);
    }

    // ------------------------------------------------------------------
    // verify_video_bytes — weryfikacja strukturalna gałęzi audio Fazy 17
    // ------------------------------------------------------------------

    #[test]
    fn test_verify_video_bytes_odrzuca_smieci() {
        assert!(!verify_video_bytes(b"to na pewno nie jest kontener isobmff"));
    }

    #[test]
    fn test_verify_video_bytes_odrzuca_pusty_bufor() {
        assert!(!verify_video_bytes(&[]));
    }

    /// Powód istnienia tej funkcji: kontener ISOBMFF bez ścieżki obrazu.
    /// `track_count` liczy wszystkie ścieżki, więc plik audio-only musi
    /// przejść — inaczej gałąź `.m4a` w Fazie 17 kasowałaby zdrowe pliki.
    #[test]
    #[ignore = "Wymaga image/test_fixture.m4a. Uruchom z --ignored."]
    fn test_verify_video_bytes_przyjmuje_kontener_bez_obrazu() {
        let bajty = std::fs::read("image/test_fixture.m4a").expect("fixture musi istnieć");
        assert!(
            verify_video_bytes(&bajty),
            "Kontener audio-only musi przejść kontrolę strukturalną"
        );

        let info = read_video_bytes(&bajty).expect("kontener musi się sparsować");
        assert!(info.track_count > 0, "Musi zobaczyć ścieżkę dźwiękową");
    }

    #[test]
    #[ignore = "Wymaga image/test_fixture.m4a. Uruchom z --ignored."]
    fn test_verify_video_bytes_odrzuca_uciety_kontener() {
        let pelny = std::fs::read("image/test_fixture.m4a").expect("fixture musi istnieć");
        assert!(verify_video_bytes(&pelny), "Test bez sensu, jeśli pełny plik nie przechodzi");
        assert!(
            !verify_video_bytes(&pelny[..pelny.len() / 2]),
            "Ucięty kontener nie może przejść"
        );
    }
}
