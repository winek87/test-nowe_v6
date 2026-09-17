// src/generic_image.rs

//! Bezpieczny wrapper `catch_unwind` wokół crate `image` (`image::open` +
//! całe przetwarzanie zdekodowanego bufora pikseli w tej samej funkcji),
//! używany przez Fazę 13 dla WSZYSTKICH formatów rastrowych obsługiwanych
//! wprost przez crate `image` (jpg/jpeg/png/webp/bmp/tif/tiff/gif) — czyli
//! NAJPOPULARNIEJSZEJ z trzech gałęzi dekodowania w tej fazie.
//!
//! ## Dlaczego ten moduł istnieje
//! Analogiczna ochrona już istnieje dla pozostałych dwóch gałęzi Fazy 13:
//! DNG (`raw_image`, crate `rawloader`) i HEIC/HEIF/AVIF (`heic_image`,
//! crate `libheif`) — patrz dokumentacja tamtych modułów, gdzie panika
//! `rawloader` była EMPIRYCZNIE zaobserwowana na prawdziwym pliku
//! użytkownika. Crate `image` może panikować z tych samych powodów
//! (wewnętrznie niespójne struktury w spreparowanym/uszkodzonym pliku), a ta
//! gałąź jest przy tym NAJBARDZIEJ ruchliwa ze wszystkich trzech
//! (jpg/jpeg/png/webp/bmp/tif/tiff/gif). Bez tej ochrony pojedynczy taki
//! plik zabiłby CAŁY wątek roboczy Rayon skanujący obrazy w Fazie 13 —
//! `tx.send(Done)` nigdy by nie nadszedł, więc UI wisiałoby w nieskończoność
//! zamiast bezpiecznie sklasyfikować plik jako niedekodowalny i iść dalej.
//!
//! UWAGA ARCHITEKTONICZNA: w odróżnieniu od `raw_image`/`heic_image`, które
//! opakowują konkretną funkcję dekodującą, ten moduł wystawia [`decode_guarded`]
//! — generyczny wrapper przyjmujący domknięcie. Powód: Faza 13 wymaga objęcia
//! `catch_unwind`-em NIE TYLKO samego `image::open`, ale też całego
//! przetwarzania zdekodowanego bufora w tej samej funkcji (dopasowanie
//! przestrzeni barw, próbkowanie jednolitości pikseli) — ta logika należy
//! do `phases::phase13`, nie do tego modułu, więc nie da się jej tu
//! zamknąć w jedną konkretną funkcję bez duplikowania kodu Fazy 13.

use std::cell::Cell;
use std::panic::AssertUnwindSafe;

thread_local! {
    /// Patrz `raw_image::EXPECTED_PANIC_IN_PROGRESS` — identyczna rola: pozwala
    /// globalnemu panic hookowi (`logging.rs`) odróżnić oczekiwaną, bezpiecznie
    /// obsłużoną panikę od prawdziwej katastrofy (thread-local — bezpieczne przy
    /// równoległym skanowaniu wieloma wątkami Rayon naraz).
    static EXPECTED_PANIC_IN_PROGRESS: Cell<bool> = const { Cell::new(false) };
}

/// Odczytywane przez globalny panic hook w `logging.rs`. `true` oznacza "ta
/// panika jest oczekiwana na tym wątku — pomiń awaryjne odzyskiwanie
/// terminala, tylko zaloguj".
pub fn is_expected_panic_in_progress() -> bool {
    EXPECTED_PANIC_IN_PROGRESS.with(|f| f.get())
}

/// Uruchamia `f` z ustawioną flagą [`is_expected_panic_in_progress`] na czas
/// jej trwania, gwarantując zdjęcie flagi PO zakończeniu (strażnik RAII),
/// niezależnie od tego, czy `f` faktycznie spanikowała.
fn with_expected_panic_guard<T>(f: impl FnOnce() -> T) -> std::thread::Result<T> {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) { EXPECTED_PANIC_IN_PROGRESS.with(|f| f.set(false)); }
    }
    EXPECTED_PANIC_IN_PROGRESS.with(|f| f.set(true));
    let _guard = Guard;
    std::panic::catch_unwind(AssertUnwindSafe(f))
}

/// Uruchamia `f` (typowo: `image::open(...)` + przetworzenie zdekodowanego
/// bufora) pod osłoną `catch_unwind`. Zwraca `None`, gdy `f` spanikowała —
/// wywołujący powinien to potraktować IDENTYCZNIE jak zwykły błąd
/// dekodowania (Gray Banding / uszkodzone piksele), bo z punktu widzenia
/// "czy plik jest sprawny" nie ma znaczenia, czy crate `image` zwróciło
/// `Err`, czy się wywaliło.
pub fn decode_guarded<T>(f: impl FnOnce() -> T) -> Option<T> {
    with_expected_panic_guard(f).ok()
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_panic_flag_is_false_outside_calls() {
        assert!(!is_expected_panic_in_progress());
    }

    #[test]
    fn test_decode_guarded_returns_some_on_success() {
        let result = decode_guarded(|| 42);
        assert_eq!(result, Some(42));
        assert!(!is_expected_panic_in_progress(), "Flaga musi zostać zdjęta po zakończeniu, niezależnie od wyniku");
    }

    #[test]
    fn test_decode_guarded_returns_none_on_panic() {
        // Symuluje realny scenariusz: panika WEWNĄTRZ domknięcia, które w
        // Fazie 13 zawiera `image::open(...)` + przetwarzanie bufora.
        let result = decode_guarded(|| -> i32 {
            panic!("symulowana panika testowa - dekoder image::open")
        });
        assert_eq!(result, None, "Panika wewnątrz f musi zostać przechwycona i zamieniona na None, nie propagować dalej i nie ubijać wątku");
    }

    #[test]
    fn test_expected_panic_flag_cleared_even_when_closure_panics() {
        // Strażnik RAII (Drop) musi zdjąć flagę NAWET gdy panika faktycznie
        // nastąpi - inaczej flaga zostałaby "zapalona na stałe" po pierwszym
        // uszkodzonym pliku, maskując prawdziwe katastrofy na tym samym wątku
        // do końca sesji.
        let result = with_expected_panic_guard(|| -> () { panic!("symulowana panika testowa") });
        assert!(result.is_err(), "Panika powinna faktycznie zostać przechwycona (test sprawdza odzysk po niej)");
        assert!(!is_expected_panic_in_progress(), "Flaga musi zostać zdjęta mimo realnej paniki wewnątrz strażnika");
    }

    /// Wszystkie pozostałe testy tego modułu sprawdzają MECHANIZM
    /// (`catch_unwind`) na SYMULOWANYCH panikach — uzasadnienie w
    /// `phases::phase13::tests::test_analyze_image_generic_branch_is_panic_guarded`:
    /// crate `image` jest mocno ufuzzowane (Firefox), więc nie ma znanego,
    /// stabilnego pliku wejściowego, który wiarygodnie wywoła w nim panikę.
    /// Ten test domyka inną, węższą lukę: dowodzi, że `decode_guarded`
    /// faktycznie POPRAWNIE PRZEPUSZCZA wynik prawdziwego, udanego
    /// dekodowania (nie tylko poprawnie łapie sztuczne awarie) — na
    /// prawdziwym pliku z dysku (`image/test_fixture.bmp`), tą samą drogą
    /// (`image::open`), której używa Faza 13.
    #[test]
    #[ignore = "Wymaga image/test_fixture.bmp (already checked into repo). Uruchom z --ignored."]
    fn test_decode_guarded_przepuszcza_prawdziwy_udany_odczyt_obrazu() {
        let sciezka = std::path::Path::new("image/test_fixture.bmp");
        let wynik = decode_guarded(|| image::open(sciezka));

        let obraz = wynik
            .expect("decode_guarded nie może zgubić wyniku udanego wywołania")
            .expect("prawdziwy plik BMP z korpusu testowego musi się poprawnie zdekodować");
        assert!(obraz.width() > 0 && obraz.height() > 0, "zdekodowany obraz musi mieć realne wymiary");
        assert!(!is_expected_panic_in_progress(), "flaga musi pozostać zdjęta po udanym, niepanikującym wywołaniu");
    }

    #[test]
    fn test_decode_guarded_nested_panics_do_not_leak_flag_state() {
        // Dwa kolejne wywołania na tym samym wątku (dokładnie jak w pętli
        // `par_chunks` Fazy 13, gdzie kolejne pliki są przetwarzane
        // sekwencyjnie na tym samym wątku Rayon) - flaga nie może "przeciekać"
        // między nimi.
        let _ = decode_guarded(|| -> i32 { panic!("pierwsza symulowana panika") });
        assert!(!is_expected_panic_in_progress());
        let ok = decode_guarded(|| 7);
        assert_eq!(ok, Some(7));
        assert!(!is_expected_panic_in_progress());
    }
}
