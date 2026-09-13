// src/raw_image.rs

//! # Dekodowanie Formatów RAW (DNG i pochodne) — Moduł Eksperymentalny
//!
//! **STATUS: WPIĘTY.** Faza 13 (żywa diagnostyka) woła [`decode_raw_file`],
//! a `phases::repair_modules::weryfikuj_naprawiony_plik` używa
//! [`verify_raw_bytes`] jako obowiązkowej weryfikacji po naprawie dla całej
//! rodziny RAW — w tym dla wyniku modułu `dng_structural`. Nagłówek mówił
//! wcześniej „JESZCZE NIEWPIĘTY W ŻADNĄ FAZĘ", co przestało być prawdą.
//!
//! ## Dlaczego DNG, a nie HEIC/HEIF
//!
//! `rawloader` to CZYSTY Rust — zero zależności systemowych. Obsługuje DNG i
//! pokrewne formaty RAW producentów (CR2, NEF, ARW, ORF...), bo DNG to w
//! istocie ustandaryzowany, otwarty format RAW oparty na TIFF.
//!
//! HEIC/HEIF to inna rodzina zupełnie (kontener ISOBMFF, kompresja HEVC) i
//! wymagałyby `libheif` — biblioteki C zainstalowanej w systemie operacyjnym,
//! nie tylko zależności Cargo. To osobna, poważniejsza decyzja wdrożeniowa
//! (szczególnie na Raspberry Pi), świadomie odłożona na później.
//!
//! ## Zweryfikowane API (nie zgadywane) — i jeden przypadek, który to obalił
//!
//! Nazwy pól `RawImage` (`width`, `height`, `cpp`, `model`, `data`) zostały
//! sprawdzone empirycznie z prawdziwego kodu źródłowego crate'a, nie
//! wyczytane z dokumentacji na słowo.
//!
//! Zachowanie na śmieciowych bajtach, pustym buforze i nieistniejącej
//! ścieżce (bezpieczny `Err`) TAKŻE zostało zweryfikowane empirycznie —
//! ale to nie był koniec historii. Na PRAWDZIWYM pliku użytkownika,
//! strukturalnie złożonym przez `dng_splice` (nagłówek jednej kopii + dane
//! drugiej), `rawloader` **PANIKOWAŁ** (`range start index ... out of range
//! for slice of length ...`) zamiast zwrócić `Err` — konkretny przypadek
//! wewnętrznie niespójnego, ale "wystarczająco poprawnego żeby zacząć
//! parsować" nagłówka. Stąd `std::panic::catch_unwind` wokół KAŻDEGO
//! wywołania `rawloader` w tym module — bez tego jeden taki plik zabiłby
//! cały wątek roboczy Rayon w Fazie 13, tracąc resztę partii zadań.

use std::io::Cursor;
use std::path::Path;

/// Podstawowe informacje wyciągnięte z poprawnie zdekodowanego pliku RAW —
/// analogiczne do tego, co Faza 13 przechowuje dla zwykłych obrazów
/// (`img_width`/`img_height` w bazie).
#[derive(Debug, Clone, PartialEq)]
pub struct RawImageInfo {
    pub width: usize,
    pub height: usize,
    /// Liczba składowych koloru na piksel (1 dla surowego Bayera, 3 dla RGB).
    pub components_per_pixel: usize,
    /// Model aparatu odczytany z metadanych pliku, jeśli obecny w nagłówku.
    pub camera_model: Option<String>,
}

/// Wspólna logika ekstrakcji [`RawImageInfo`] z już zdekodowanego
/// `rawloader::RawImage`, plus jedyna reguła sanity-check: wymiary muszą być
/// niezerowe (analogiczna do `verify_image_bytes` w Fazie 18 dla JPG/PNG).
fn extract_info(raw: rawloader::RawImage) -> Option<RawImageInfo> {
    if raw.width == 0 || raw.height == 0 { return None; }
    Some(RawImageInfo {
        width: raw.width,
        height: raw.height,
        components_per_pixel: raw.cpp,
        camera_model: if raw.model.is_empty() { None } else { Some(raw.model) },
    })
}

thread_local! {
    /// Sygnalizuje globalnemu panic hookowi (`logging.rs`), że panika
    /// zdarzająca się TERAZ, na TYM wątku, jest OCZEKIWANA i zostanie
    /// bezpiecznie przechwycona przez `catch_unwind` poniżej — hook nie
    /// powinien traktować jej jak katastrofy (nie wyłączać trybu Raw ani nie
    /// opuszczać alternatywnego ekranu Ratatui). Bez tego, mimo że
    /// `catch_unwind` poprawnie chroni kontrolę programu, GLOBALNY hook i
    /// tak by się uruchomił PRZED przechwyceniem (hooki uruchamiają się
    /// zawsze, niezależnie od tego, czy panika jest później złapana wyżej
    /// na stosie) i zniszczyłby ekran TUI w środku normalnie działającego
    /// skanowania Fazy 13 — zaobserwowane empirycznie na prawdziwym pliku.
    static EXPECTED_PANIC_IN_PROGRESS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Odczytywane przez globalny panic hook w `logging.rs`. `true` oznacza
/// "ta panika jest oczekiwana na tym wątku - pomiń awaryjne odzyskiwanie
/// terminala, tylko zaloguj".
pub fn is_expected_panic_in_progress() -> bool {
    EXPECTED_PANIC_IN_PROGRESS.with(|f| f.get())
}

/// Uruchamia `f` z ustawioną flagą [`is_expected_panic_in_progress`] na czas
/// jej trwania, gwarantując zdjęcie flagi PO zakończeniu niezależnie od tego,
/// czy `f` faktycznie spanikowała (strażnik RAII poniżej).
fn with_expected_panic_guard<T>(f: impl FnOnce() -> T) -> std::thread::Result<T> {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) { EXPECTED_PANIC_IN_PROGRESS.with(|f| f.set(false)); }
    }
    EXPECTED_PANIC_IN_PROGRESS.with(|f| f.set(true));
    let _guard = Guard;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
}

/// Próbuje zdekodować plik RAW spod podanej ścieżki na dysku. Zwraca `None`
/// zarówno dla plików fizycznie uszkodzonych, jak i dla formatów
/// nierozpoznawanych przez `rawloader` — z punktu widzenia "czy ten plik
/// jest sprawny" to rozróżnienie nie ma znaczenia, więc celowo nie jest
/// zachowywane (podobnie jak `image::open(...).ok()` w Fazie 13).
///
/// ## NAPRAWIONY KRYTYCZNY BUG BEZPIECZEŃSTWA (znaleziony na prawdziwym pliku)
/// `rawloader` może PANIKOWAĆ (nie tylko bezpiecznie zwrócić `Err`) na
/// pewnych konkretnych, wewnętrznie niespójnych strukturach — zaobserwowane
/// empirycznie: `range start index ... out of range for slice of length ...`
/// przy próbie złożenia strukturalnego DNG (`dng_splice`), gdzie nagłówek
/// pozostał uszkodzony w polu INNYM niż offsety pasków danych (np. w tabeli
/// modelu aparatu). Bez tej ochrony pojedynczy taki plik zabiłby CAŁY wątek
/// roboczy Rayon skanujący DNG w Fazie 13, tracąc resztę partii zadań bez
/// żadnego komunikatu w UI. `std::panic::catch_unwind` (poprzez
/// [`with_expected_panic_guard`]) przechwytuje to i zamienia na bezpieczny
/// `None`, dokładnie jak każdy inny błąd dekodowania.
pub fn decode_raw_file(path: &Path) -> Option<RawImageInfo> {
    let path = path.to_path_buf();
    let raw = with_expected_panic_guard(move || rawloader::decode_file(&path)).ok()?.ok()?;
    extract_info(raw)
}

/// Wariant [`decode_raw_file`] operujący na buforze w pamięci — potrzebny
/// tam, gdzie plik jest już wczytany do RAM (np. weryfikacja złożenia w
/// `dng_splice`, analogicznie do `image::load_from_memory` w Fazie 18 dla
/// JPG/PNG). Ta sama ochrona `catch_unwind` + flaga oczekiwanej paniki co
/// [`decode_raw_file`] — patrz dokumentacja [`EXPECTED_PANIC_IN_PROGRESS`]
/// co do KONKRETNEGO, empirycznie potwierdzonego przypadku paniki
/// `rawloader` na strukturalnie złożonym pliku.
pub fn decode_raw_bytes(bytes: &[u8]) -> Option<RawImageInfo> {
    let raw = with_expected_panic_guard(|| {
        let mut cursor = Cursor::new(bytes);
        rawloader::decode(&mut cursor)
    }).ok()?.ok()?;
    extract_info(raw)
}

/// Jedyny warunek "plik RAW jest sprawny". Odpowiednik `verify_image_bytes`
/// z Fazy 18, ale dla formatów RAW zamiast JPG/PNG.
///
/// Faza 13 (żywa diagnostyka) woła [`decode_raw_file`] wprost, bo potrzebuje
/// pełnego `RawImageInfo`, nie samej flagi. Tę funkcję wywołuje
/// `phases::repair_modules::weryfikuj_naprawiony_plik` jako OBOWIĄZKOWĄ
/// WERYFIKACJĘ PO NAPRAWIE dla całej rodziny RAW (`dng nef cr2 cr3 arw orf
/// rw2 raf srw pef`) — także dla wyniku modułu `dng_structural`.
pub fn verify_raw_bytes(bytes: &[u8]) -> bool {
    decode_raw_bytes(bytes).is_some()
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Odporność na dane uszkodzone/nieistniejące (zweryfikowane empirycznie
    // jako bezpieczne - patrz dokumentacja modułu)
    // ------------------------------------------------------------------

    #[test]
    fn test_decode_raw_bytes_rejects_garbage() {
        assert!(decode_raw_bytes(b"to na pewno nie jest plik RAW").is_none());
    }

    #[test]
    fn test_decode_raw_bytes_rejects_empty_buffer() {
        assert!(decode_raw_bytes(b"").is_none());
    }

    #[test]
    fn test_decode_raw_file_rejects_nonexistent_path() {
        assert!(decode_raw_file(Path::new("/na/pewno/nieistniejacy/plik.dng")).is_none());
    }

    #[test]
    fn test_verify_raw_bytes_rejects_garbage() {
        assert!(!verify_raw_bytes(b"absolutnie nie jest to RAW"));
    }

    #[test]
    fn test_decode_raw_bytes_never_panics_on_truncated_tiff_like_header() {
        // Zaczyna się jak poprawny nagłówek TIFF little-endian (DNG jest
        // oparty na TIFF), ale jest drastycznie ucięty zaraz potem - typowy
        // realny scenariusz uszkodzonego pliku z odzysku, nie tylko czyste
        // śmieci od zera.
        let truncated_tiff_header: &[u8] = &[0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00];
        let result = decode_raw_bytes(truncated_tiff_header);
        assert!(result.is_none(), "Ucięty nagłówek nie powinien się zdekodować, ale też nie powinien panikować");
    }

    #[test]
    fn test_decode_raw_bytes_never_panics_on_ifd_with_absurd_offset() {
        // Regresja dla realnego incydentu: nagłówek TIFF poprawny na tyle,
        // żeby rawloader zaczął parsować IFD, ale z wpisem wskazującym
        // absurdalnie duży, spoza bufora offset (dokładnie klasa błędu, która
        // na prawdziwym pliku użytkownika (po strukturalnym złożeniu w
        // dng_splice) spowodowała `range start index ... out of range` -
        // panikę wewnątrz rawloader, nie bezpieczny Err. catch_unwind musi
        // to złapać niezależnie od tego, w którym dokładnie polu tkwi przyczyna.
        let mut bogus = vec![0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00]; // nagłówek TIFF little-endian, IFD @ offset 8
        bogus.extend_from_slice(&1u16.to_le_bytes()); // IFD: 1 wpis
        bogus.extend_from_slice(&0x0100u16.to_le_bytes()); // tag: ImageWidth
        bogus.extend_from_slice(&4u16.to_le_bytes()); // typ: LONG
        bogus.extend_from_slice(&1u32.to_le_bytes()); // count: 1
        bogus.extend_from_slice(&0xFFFFFFFEu32.to_le_bytes()); // wartość: absurdalny, prawie-maksymalny offset/rozmiar
        bogus.extend_from_slice(&0u32.to_le_bytes()); // brak kolejnego IFD

        let result = decode_raw_bytes(&bogus);
        assert!(result.is_none(), "Absurdalny offset w IFD nie powinien zdekodować się poprawnie, ale KLUCZOWE: nie powinien panikować programu");
    }

    #[test]
    fn test_expected_panic_flag_is_false_outside_decode_calls() {
        assert!(!is_expected_panic_in_progress(), "Flaga nie powinna być ustawiona poza wywołaniem decode_raw_*");
    }

    #[test]
    fn test_expected_panic_flag_cleared_after_successful_decode() {
        let _ = decode_raw_bytes(b"smieci, dekodowanie sie nie powiedzie ale bez paniki");
        assert!(!is_expected_panic_in_progress(), "Flaga musi zostać zdjęta PO zakończeniu decode_raw_bytes, niezależnie od wyniku");
    }

    #[test]
    fn test_expected_panic_flag_cleared_even_when_closure_actually_panics() {
        // Strażnik RAII (Drop) musi zdjąć flagę NAWET gdy panika faktycznie
        // nastąpi - inaczej flaga zostałaby "zapalona na stałe" po pierwszym
        // uszkodzonym pliku, maskując prawdziwe katastrofy na tym samym wątku
        // do końca sesji.
        let result = with_expected_panic_guard(|| -> () { panic!("symulowana panika testowa") });
        assert!(result.is_err(), "Panika powinna faktycznie zostać przechwycona (test sprawdza odzysk po niej)");
        assert!(!is_expected_panic_in_progress(), "Flaga musi zostać zdjęta mimo realnej paniki wewnątrz strażnika");
    }

    // ------------------------------------------------------------------
    // Test z prawdziwym plikiem DNG - WYMAGA fixture, patrz uwaga niżej
    // ------------------------------------------------------------------

    #[test]
    #[ignore = "Wymaga prawdziwego pliku DNG jako fixture - rawloader waliduje \
                rzeczywiste znaczniki TIFF/EXIF specyficzne dla modeli aparatów, \
                więc syntetyczny/ręcznie sklecony plik (jak dla PNG w Fazie 18, \
                gdzie CRC32 jest w pełni niezależny od treści) nie jest tu \
                praktyczny do zbudowania w kodzie testu. Plik oczekiwany pod \
                `image/test_fixture.dng` (ścieżka WZGLĘDNA DO KATALOGU, z \
                którego wołasz `cargo test` - normalnie katalog główny \
                projektu). Aby uruchomić: \
                `cargo test --lib raw_image::tests::test_decode_real_dng_fixture -- --ignored --nocapture`."]
    fn test_decode_real_dng_fixture() {
        const RAWLOADER_TEST_FIXTURE: &str = "image/test_fixture.dng";
        let info = decode_raw_file(Path::new(RAWLOADER_TEST_FIXTURE))
            .expect("Prawdziwy plik DNG pod image/test_fixture.dng powinien się zdekodować - sprawdź, czy uruchamiasz `cargo test` z katalogu głównego projektu");
        assert!(info.width > 0);
        assert!(info.height > 0);
        println!("✔ Zdekodowano: {}x{}, {} składowych/piksel, model: {:?}", info.width, info.height, info.components_per_pixel, info.camera_model);
    }

    // ------------------------------------------------------------------
    // RODZINA RAW POZA DNG
    //
    // Plików NEF/CR2/ARW/ORF/PEF/SRW/RW2 NIE DA SIĘ WYGENEROWAĆ: to zamknięte
    // formaty aparatów i żadne dostępne narzędzie ich nie ZAPISUJE (rawloader,
    // dcraw i LibRaw wyłącznie czytają). Muszą przyjść z prawdziwego sprzętu.
    //
    // Test niżej jest przygotowany z wyprzedzeniem: sprawdza DNG, który mamy,
    // a każdy dołożony plik z rodziny obejmuje automatycznie, bez żadnej zmiany
    // w kodzie. Wystarczy wrzucić `image/test_fixture.<ext>`.
    // ------------------------------------------------------------------

    /// Rozszerzenia, dla których `dng_structural` deklaruje obsługę.
    const RODZINA_RAW: &[&str] = &["dng", "nef", "cr2", "arw", "orf", "pef", "srw", "rw2"];

    #[test]
    #[ignore = "Wymaga image/test_fixture.dng; pliki NEF/CR2/ARW/ORF/PEF/SRW/RW2 obejmuje automatycznie, jeśli je dołożysz. Uruchom z --ignored."]
    fn test_rawloader_czyta_kazdy_dostepny_plik_rodziny() {
        let mut sprawdzone = Vec::new();

        for ext in RODZINA_RAW {
            let sciezka = format!("image/test_fixture.{}", ext);
            let Ok(bajty) = std::fs::read(&sciezka) else { continue };

            assert!(
                verify_raw_bytes(&bajty),
                "Zdrowy plik {} musi się zdekodować przez rawloader — to warunek \
                 obowiązkowej weryfikacji Fazy 17 dla tego formatu",
                sciezka
            );
            sprawdzone.push(*ext);
        }

        // DNG mamy na pewno; gdyby zniknął, test przestałby cokolwiek mierzyć.
        assert!(
            sprawdzone.contains(&"dng"),
            "Brak image/test_fixture.dng — bez niego ten test niczego nie sprawdza"
        );

        println!("Sprawdzone formaty rodziny RAW: {:?}", sprawdzone);
        let brakujace: Vec<&&str> = RODZINA_RAW.iter().filter(|e| !sprawdzone.contains(e)).collect();
        if !brakujace.is_empty() {
            println!(
                "Bez pokrycia (brak fixture'a, patrz TODO.md): {:?}",
                brakujace
            );
        }
    }

    /// Uszkodzony plik z rodziny RAW MUSI zostać odrzucony — inaczej bramka
    /// Fazy 17 przepuściłaby nieudane złożenie.
    #[test]
    #[ignore = "Wymaga image/test_fixture.dng; pozostałe formaty rodziny obejmuje automatycznie. Uruchom z --ignored."]
    fn test_rawloader_odrzuca_uszkodzony_plik_kazdego_formatu() {
        let mut sprawdzone = 0;

        for ext in RODZINA_RAW {
            let Ok(pelny) = std::fs::read(format!("image/test_fixture.{}", ext)) else { continue };
            // Ucięcie do połowy: nagłówek zostaje, dane pikseli przepadają.
            let uciety = &pelny[..pelny.len() / 2];

            assert!(
                !verify_raw_bytes(uciety),
                "Ucięty plik .{} MUSI zostać odrzucony przez rawloader", ext
            );
            sprawdzone += 1;
        }

        assert!(sprawdzone > 0, "Brak jakiegokolwiek pliku rodziny RAW do sprawdzenia");
    }
}
