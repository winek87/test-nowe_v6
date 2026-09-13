// src/heic_image.rs

//! # Dekodowanie Formatów HEIC/HEIF/AVIF
//!
//! **STATUS: WPIĘTY.** Faza 13 (żywa diagnostyka) woła [`decode_heic_file`],
//! a Faza 17 weryfikuje wynik naprawy przez [`verify_heic_pixels`] — moduły
//! `heic_clone` i `heic_native` istnieją i ich wyniki przechodzą przez tę
//! bramkę. Nagłówek mówił wcześniej „JESZCZE NIEWPIĘTY W ŻADNĄ FAZĘ", co
//! przestało być prawdą wraz z powstaniem tych modułów.
//!
//! ## Dwa poziomy dowodu — nie mylić ich
//!
//! [`decode_heic_file`]/[`decode_heic_bytes`] otwierają KONTENER i czytają
//! uchwyt obrazu (wymiary, alfa, głębia) — to dowód STRUKTURY, tani, w sam
//! raz dla diagnostyki całego nośnika w Fazie 13. [`verify_heic_pixels`] żąda
//! od dekodera pełnej klatki pikseli — to dowód TREŚCI, droższy, stosowany
//! tam, gdzie stawką jest przyjęcie naprawionego pliku jako sprawnego.
//!
//! ## Zależność systemowa (WAŻNE przy wdrożeniu)
//!
//! W przeciwieństwie do `rawloader` (czysty Rust), ten moduł wymaga
//! biblioteki systemowej **`libheif`** ORAZ **`libclang`** (to drugie
//! potrzebne tylko przy KOMPILACJI — `libheif-rs` generuje wiązania przez
//! `bindgen`). Zweryfikowane empirycznie: bez `libclang-dev` kompilacja
//! zawodzi komunikatem "Unable to find libclang", mimo poprawnie
//! zainstalowanego `libheif-dev`.
//!
//! Na docelowej maszynie (Raspberry Pi, Debian 13) potwierdzono
//! `libheif-dev 1.19.8` wraz z pluginami dekodującymi `libde265` (HEIC) i
//! `dav1d` (AVIF) — bez tych PLUGINÓW sama biblioteka nie zdekoduje
//! właściwej treści obrazu, mimo że kontener się otworzy.
//!
//! ## Zweryfikowane API (nie zgadywane)
//!
//! Nazwy i zachowanie `HeifContext::read_from_bytes`/`read_from_file`,
//! `primary_image_handle()`, `width()`/`height()` sprawdzone bezpośrednio w
//! kodzie źródłowym crate'a. Odporność na uszkodzone dane przetestowana
//! empirycznie na czterech przypadkach (śmieci, pusty bufor, ucięty nagłówek
//! `ftyp` kontenera ISOBMFF, nieistniejąca ścieżka) — WSZYSTKIE zwracają
//! bezpieczny `Err`, żaden nie panikuje.
//!
//! Mimo to każde wywołanie jest owinięte w `catch_unwind` — dokładnie z tej
//! samej lekcji co `raw_image`: tam `rawloader` też przechodził wstępne
//! testy odporności, a mimo to panikował na konkretnym, strukturalnie
//! złożonym pliku, który pojawił się dopiero w praktyce.

use std::path::Path;

/// Podstawowe informacje z poprawnie zdekodowanego pliku HEIC/HEIF/AVIF —
/// analogiczne do `raw_image::RawImageInfo` i do tego, co Faza 13
/// przechowuje dla zwykłych obrazów.
#[derive(Debug, Clone, PartialEq)]
pub struct HeicImageInfo {
    pub width: u32,
    pub height: u32,
    /// Czy plik zawiera kanał alfa (przezroczystość).
    pub has_alpha: bool,
    /// Liczba bitów na kanał (HEIC często używa 10-bitowej głębi, w
    /// odróżnieniu od typowych 8 bitów w JPEG) — przydatne przy ocenie,
    /// czy odzyskany plik zachował pełną jakość.
    pub bits_per_pixel: u8,
}

thread_local! {
    /// Patrz `raw_image::EXPECTED_PANIC_IN_PROGRESS` — ta sama rola i ten
    /// sam powód istnienia (globalny panic hook w `logging.rs` musi
    /// odróżnić oczekiwaną, obsłużoną panikę od prawdziwej katastrofy,
    /// żeby nie niszczyć ekranu TUI w środku działającego skanu).
    static EXPECTED_PANIC_IN_PROGRESS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Odczytywane przez globalny panic hook w `logging.rs`.
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

/// Wspólna ekstrakcja informacji z uchwytu obrazu głównego. Jedyny
/// sanity-check: wymiary muszą być niezerowe (analogicznie do
/// `raw_image::extract_info` i `verify_image_bytes` w Fazie 18).
fn extract_info(ctx: &libheif_rs::HeifContext) -> Option<HeicImageInfo> {
    let handle = ctx.primary_image_handle().ok()?;
    let width = handle.width();
    let height = handle.height();
    if width == 0 || height == 0 { return None; }
    Some(HeicImageInfo {
        width,
        height,
        has_alpha: handle.has_alpha_channel(),
        bits_per_pixel: handle.luma_bits_per_pixel(),
    })
}

/// Próbuje odczytać strukturę pliku HEIC/HEIF/AVIF spod ścieżki na dysku.
///
/// ## UWAGA co do znaczenia sukcesu
/// Sukces oznacza, że KONTENER się otworzył i uchwyt obrazu głównego jest
/// dostępny z sensownymi wymiarami — NIE że każdy piksel został fizycznie
/// zdekodowany. Pełne dekodowanie pikseli jest znacznie droższe (HEVC), a
/// dla celów diagnostyki Fazy 13 (czy plik jest strukturalnie sprawny)
/// odczyt uchwytu wystarcza. To świadomy kompromis wydajnościowy, nie
/// przeoczenie. Mocniejszą gwarancję — pełną klatkę pikseli — daje
/// [`verify_heic_pixels`], której Faza 17 używa do weryfikacji po naprawie.
pub fn decode_heic_file(path: &Path) -> Option<HeicImageInfo> {
    let path_str = path.to_str()?.to_string();
    let result = with_expected_panic_guard(move || {
        libheif_rs::HeifContext::read_from_file(&path_str)
    }).ok()?.ok()?;
    extract_info(&result)
}

/// Wariant [`decode_heic_file`] operujący na buforze w pamięci.
///
/// Faza 13 (żywa diagnostyka) woła [`decode_heic_file`], bo pracuje na plikach
/// z dysku. Ten wariant jest JEDYNĄ definicją „strukturalnie sprawnego HEIC"
/// dla danych w pamięci i jako taki stanowi PIERWSZY KROK
/// [`verify_heic_pixels`] — bramki, przez którą Faza 17 przepuszcza wyniki
/// modułów `heic_clone` i `heic_native`.
///
/// Sam w sobie NIE jest dowodem treści: otwiera kontener i czyta uchwyt
/// obrazu, nie dekodując ani jednego piksela.
pub fn decode_heic_bytes(bytes: &[u8]) -> Option<HeicImageInfo> {
    let result = with_expected_panic_guard(|| {
        libheif_rs::HeifContext::read_from_bytes(bytes)
    }).ok()?.ok()?;
    extract_info(&result)
}

/// Wynik realnego dekodowania pikseli — patrz [`verify_heic_pixels`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeryfikacjaHeic {
    /// Dekoder zwrócił pełną klatkę pikseli. Gwarancja MOCNA.
    PikseleZdekodowane,
    /// Kontener się otwiera i uchwyt obrazu ma sensowne wymiary, ale
    /// dekodowania pikseli NIE DA SIĘ przeprowadzić — w systemie brakuje
    /// pluginu kodeka (`libde265` dla HEIC, `dav1d` dla AVIF). To nie jest
    /// wada pliku, tylko braki środowiska. Gwarancja SŁABA.
    TylkoStruktura,
    /// Plik nie nadaje się do użytku.
    Odrzucony,
}

/// Rozstrzyga, czy nieudane dekodowanie obciąża PLIK, czy ŚRODOWISKO.
///
/// ## Dlaczego to nie może być zwykłe „`Err` = brak kodeka"
///
/// Pierwsza wersja tej weryfikacji mapowała każdy błąd dekodowania na
/// [`WeryfikacjaHeic::TylkoStruktura`], czyli na „brak pluginu, gwarancja
/// SŁABA". Test na prawdziwym pliku z zasypanym `mdat` (7,6 mln zmienionych
/// bajtów przy nietkniętych metadanych) to obnażył: uszkodzony materiał
/// dostawał wtedy stempel PRZYJĘTY. To błąd gorszy od wyjściowego, bo Faza 17
/// przyjęłaby zepsute zdjęcie zamiast próbować kolejnego modułu naprawczego.
///
/// ## Podstawa rozróżnienia
///
/// Sprawdzone empirycznie na tym pliku: uszkodzony strumień daje
/// `DecoderPluginError` — plugin ruszył i poległ na danych. Kody mówiące
/// o BRAKU możliwości dekodowania (`UnsupportedFeature` z podkodem
/// `UnsupportedCodec`, `PluginLoadingError`, `UnsupportedFileType`) pochodzą
/// z taksonomii błędów `libheif`, nie z eksperymentu — na tej maszynie
/// zainstalowanych jest pięć pluginów (`dav1d`, `libde265`, `aom`, `jpeg`,
/// `openjpeg`), więc przypadku „brak kodeka" nie dało się wywołać bez
/// odinstalowywania pakietów systemowych. Rozstrzygnięcie jest tu świadomie
/// ZACHOWAWCZE tylko dla tych trzech kodów; każdy inny błąd obciąża plik.
fn zaklasyfikuj_blad_dekodera(kod: libheif_rs::HeifErrorCode) -> WeryfikacjaHeic {
    use libheif_rs::HeifErrorCode as K;
    match kod {
        // Brak możliwości dekodowania w TYM systemie — wada środowiska.
        K::UnsupportedFeature | K::PluginLoadingError | K::UnsupportedFileType => {
            WeryfikacjaHeic::TylkoStruktura
        }
        // Wszystko inne, w tym potwierdzony empirycznie `DecoderPluginError`
        // przy rozsypanym strumieniu — wada pliku.
        _ => WeryfikacjaHeic::Odrzucony,
    }
}

/// Realne dekodowanie pikseli HEIC/HEIF/AVIF — najmocniejszy dowód sprawności,
/// jaki ten format daje.
///
/// ## Dlaczego samo [`decode_heic_bytes`] nie wystarcza
///
/// [`extract_info`] czyta wyłącznie UCHWYT obrazu głównego: szerokość,
/// wysokość, kanał alfa, bity na piksel. Ani jeden piksel nie jest przy tym
/// dekodowany. Odbudowany kafel HEIC potrafi więc otworzyć kontener i podać
/// sensowne wymiary, mając przy tym rozsypany strumień HEVC — a Faza 17
/// kwitowała to jako „gwarancja MOCNA", czyli deklarowała dowód treści tam,
/// gdzie miała wyłącznie dowód struktury. Ta funkcja domyka tę lukę: żąda od
/// dekodera pełnej klatki.
///
/// ## Co dokładnie udowadnia sukces
///
/// Że `libheif` wraz z pluginem kodeka przeszedł cały strumień obrazu głównego
/// i wyprodukował bufor pikseli o wymiarach zgodnych z uchwytem. To ta sama
/// klasa dowodu co `image::load_from_memory` dla JPG/PNG w Fazie 18.
/// NIE dowodzi, że treść jest tą właściwą — na to nie ma metody przy braku
/// oryginału.
///
/// ## Dlaczego brak pluginu to osobny wynik, a nie porażka
///
/// Pluginy dekodujące (`libde265`, `dav1d`) są osobnymi pakietami systemowymi.
/// Gdyby ich brak traktować jak uszkodzenie pliku, Faza 17 odrzucałaby
/// POPRAWNIE naprawione zdjęcia i usuwała je przez `sprzataj` — dokładnie ten
/// sam błąd, co przepuszczenie `.m4a` przez ffmpeg-owego sędziego wymagającego
/// strumienia obrazu. Dlatego brak kodeka schodzi do
/// [`WeryfikacjaHeic::TylkoStruktura`] i jest jawnie meldowany jako gwarancja
/// SŁABA, zamiast kasować materiał dowodowy.
pub fn verify_heic_pixels(bytes: &[u8]) -> WeryfikacjaHeic {
    // KROK 1 — struktura. Świadomie przez [`decode_heic_bytes`], a nie przez
    // powtórzone tu otwarcie kontenera: definicja „strukturalnie sprawnego
    // HEIC" ma zostać JEDNA, wspólna z Fazą 13. Powtórzenie jej tutaj
    // znaczyłoby, że obie mogą się z czasem rozjechać.
    let Some(info) = decode_heic_bytes(bytes) else {
        return WeryfikacjaHeic::Odrzucony;
    };
    let (szerokosc, wysokosc) = (info.width, info.height);

    // KROK 2 — piksele.
    let wynik = with_expected_panic_guard(|| {
        let ctx = libheif_rs::HeifContext::read_from_bytes(bytes).ok()?;
        let handle = ctx.primary_image_handle().ok()?;

        // Dekodowanie do przeplatanego RGB — jeden ciągły bufor, najprostszy
        // do sprawdzenia. `None` jako opcje = ustawienia domyślne biblioteki.
        let lib = libheif_rs::LibHeif::new();
        let obraz = match lib.decode(
            &handle,
            libheif_rs::ColorSpace::Rgb(libheif_rs::RgbChroma::Rgb),
            None,
        ) {
            Ok(o) => o,
            Err(e) => return Some(zaklasyfikuj_blad_dekodera(e.code)),
        };

        let plaszczyzna = match obraz.planes().interleaved {
            Some(p) => p,
            None => return Some(WeryfikacjaHeic::Odrzucony),
        };

        // Bufor musi realnie pomieścić zadeklarowaną klatkę. `stride` bywa
        // większy od szerokości wiersza (wyrównanie), więc porównujemy z nim,
        // a nie z samą szerokością.
        let potrzebne = plaszczyzna.stride.saturating_mul(wysokosc as usize);
        if plaszczyzna.data.len() < potrzebne || potrzebne == 0 {
            return Some(WeryfikacjaHeic::Odrzucony);
        }

        // Wymiary zdekodowanej klatki muszą zgadzać się z uchwytem — inaczej
        // dekoder zwrócił coś innego niż obraz, który obiecywał kontener.
        if obraz.width() != szerokosc || obraz.height() != wysokosc {
            return Some(WeryfikacjaHeic::Odrzucony);
        }

        Some(WeryfikacjaHeic::PikseleZdekodowane)
    });

    match wynik {
        Ok(Some(w)) => w,
        // Panika w dekoderze albo `None` z któregokolwiek `?` = odrzucenie.
        Ok(None) | Err(_) => WeryfikacjaHeic::Odrzucony,
    }
}

/// Rozpoznaje rozszerzenia obsługiwane przez ten moduł. AVIF używa tego
/// samego kontenera (ISOBMFF) i tej samej biblioteki, tylko innego kodeka
/// (`dav1d` zamiast `libde265`) — stąd wspólna obsługa.
pub fn is_heic_extension(path_str: &str) -> bool {
    let lower = path_str.to_lowercase();
    lower.ends_with(".heic") || lower.ends_with(".heif") || lower.ends_with(".avif")
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_heic_bytes_rejects_garbage() {
        assert!(decode_heic_bytes(b"to na pewno nie jest plik HEIC ani AVIF").is_none());
    }

    #[test]
    fn test_decode_heic_bytes_rejects_empty_buffer() {
        assert!(decode_heic_bytes(b"").is_none());
    }

    #[test]
    fn test_decode_heic_bytes_rejects_truncated_ftyp_container() {
        // Zaczyna się jak poprawny kontener ISOBMFF (box `ftyp` z marką
        // `heic`), ale urywa się natychmiast po nagłówku - typowy realny
        // scenariusz uszkodzonego pliku z odzysku, nie czyste śmieci.
        let mut truncated: Vec<u8> = vec![0x00, 0x00, 0x00, 0x18];
        truncated.extend_from_slice(b"ftypheic");
        truncated.extend_from_slice(&[0x00; 8]);
        assert!(decode_heic_bytes(&truncated).is_none());
    }

    #[test]
    fn test_decode_heic_file_rejects_nonexistent_path() {
        assert!(decode_heic_file(Path::new("/na/pewno/nie/ma/takiego.heic")).is_none());
    }

    #[test]
    fn test_expected_panic_flag_is_false_outside_calls() {
        assert!(!is_expected_panic_in_progress());
    }

    #[test]
    fn test_expected_panic_flag_cleared_after_call() {
        let _ = decode_heic_bytes(b"smieci");
        assert!(!is_expected_panic_in_progress(), "Flaga musi zostać zdjęta po zakończeniu, niezależnie od wyniku");
    }

    #[test]
    fn test_expected_panic_flag_cleared_even_when_closure_panics() {
        let result = with_expected_panic_guard(|| -> () { panic!("symulowana panika testowa") });
        assert!(result.is_err());
        assert!(!is_expected_panic_in_progress(), "Strażnik RAII musi zdjąć flagę mimo realnej paniki");
    }

    #[test]
    fn test_is_heic_extension_recognizes_all_supported() {
        assert!(is_heic_extension("zdjecie.heic"));
        assert!(is_heic_extension("ZDJECIE.HEIC"));
        assert!(is_heic_extension("zdjecie.heif"));
        assert!(is_heic_extension("zdjecie.avif"));
        assert!(!is_heic_extension("zdjecie.jpg"));
        assert!(!is_heic_extension("zdjecie.dng"));
    }

    #[test]
    #[ignore = "Wymaga prawdziwego pliku HEIC jako fixture - libheif waliduje \
                rzeczywistą strukturę kontenera i strumień HEVC, więc syntetyczny \
                plik nie jest praktyczny do zbudowania w kodzie testu (ta sama \
                sytuacja co raw_image::tests dla DNG). Umieść prawdziwy plik pod \
                `image/test_fixture.heic` i uruchom: \
                `cargo test decode_real_heic_fixture -- --ignored --nocapture`."]
    fn test_decode_real_heic_fixture() {
        let info = decode_heic_file(Path::new("image/test_fixture.heic"))
            .expect("Prawdziwy plik HEIC pod image/test_fixture.heic powinien się odczytać");
        assert!(info.width > 0 && info.height > 0);
        println!("✔ Odczytano HEIC: {}x{}, alpha: {}, bity/kanał: {}", info.width, info.height, info.has_alpha, info.bits_per_pixel);
    }

    // ------------------------------------------------------------------
    // REALNE DEKODOWANIE PIKSELI (verify_heic_pixels)
    //
    // Bramka Fazy 17 dla wyników `heic_clone` i `heic_native`.
    // ------------------------------------------------------------------

    #[test]
    fn test_piksele_odrzucaja_smieci() {
        assert_eq!(verify_heic_pixels(b"to na pewno nie jest heic"), WeryfikacjaHeic::Odrzucony);
    }

    #[test]
    fn test_piksele_odrzucaja_pusty_bufor() {
        assert_eq!(verify_heic_pixels(&[]), WeryfikacjaHeic::Odrzucony);
    }

    #[test]
    fn test_piksele_odrzucaja_sam_naglowek_ftyp() {
        // Poprawna sygnatura ISOBMFF, żadnej treści obrazu. Sprawdzenie
        // magic bytes by to przepuściło.
        let mut bajty = vec![0u8, 0, 0, 0x18];
        bajty.extend_from_slice(b"ftypheic");
        bajty.extend_from_slice(&[0u8; 16]);
        assert_eq!(verify_heic_pixels(&bajty), WeryfikacjaHeic::Odrzucony);
    }

    /// Sedno poprawki: zdrowy plik musi dać dowód TREŚCI, nie tylko struktury.
    #[test]
    #[ignore = "Wymaga image/test_fixture.heic oraz pluginu libde265. Uruchom z --ignored."]
    fn test_piksele_zdrowego_pliku_sie_dekoduja() {
        let bajty = std::fs::read("image/test_fixture.heic").expect("fixture musi istnieć");
        assert_eq!(
            verify_heic_pixels(&bajty),
            WeryfikacjaHeic::PikseleZdekodowane,
            "Zdrowy HEIC musi przejść pełne dekodowanie pikseli"
        );
    }

    /// NAJWAŻNIEJSZY TEST: plik, który OTWIERA kontener, ale ma rozsypany
    /// strumień obrazu. Dotychczasowa weryfikacja (`decode_heic_bytes`) taki
    /// plik PRZEPUSZCZAŁA ze stemplem „gwarancja MOCNA", bo czyta wyłącznie
    /// uchwyt. Dopiero dekodowanie pikseli go łapie.
    #[test]
    #[ignore = "Wymaga image/test_fixture.heic oraz pluginu libde265. Uruchom z --ignored."]
    fn test_uszkodzona_tresc_przy_zdrowej_strukturze_jest_odrzucona() {
        let mut bajty = std::fs::read("image/test_fixture.heic").expect("fixture musi istnieć");

        // Niszczymy wyłącznie DANE OBRAZU (`mdat`/`idat`), nie metadane.
        // Szukamy pudełka z danymi i zasypujemy jego treść stałą wartością.
        let pozycja = (0..bajty.len().saturating_sub(4))
            .find(|&i| &bajty[i..i + 4] == b"mdat")
            .expect("fixture musi mieć pudełko mdat");
        let od = pozycja + 4;
        for b in bajty[od..].iter_mut() {
            *b = 0x5A;
        }

        // Założenie testu: struktura NADAL jest czytelna — inaczej test nie
        // sprawdzałby tego, co ma sprawdzać, tylko zwykłe zepsucie pliku.
        assert!(
            decode_heic_bytes(&bajty).is_some(),
            "Test bez sensu: po uszkodzeniu treści kontener musi się nadal otwierać"
        );

        assert_eq!(
            verify_heic_pixels(&bajty),
            WeryfikacjaHeic::Odrzucony,
            "Rozsypany strumień obrazu przy zdrowej strukturze MUSI zostać odrzucony"
        );
    }

    // ------------------------------------------------------------------
    // KLASYFIKACJA BŁĘDU DEKODERA (czysta funkcja, bez plików)
    // ------------------------------------------------------------------

    /// Potwierdzone empirycznie na pliku z zasypanym `mdat`: rozsypany
    /// strumień daje `DecoderPluginError`. Musi obciążać PLIK.
    #[test]
    fn test_blad_pluginu_obciaza_plik() {
        assert_eq!(
            zaklasyfikuj_blad_dekodera(libheif_rs::HeifErrorCode::DecoderPluginError),
            WeryfikacjaHeic::Odrzucony
        );
    }

    #[test]
    fn test_uszkodzone_wejscie_obciaza_plik() {
        assert_eq!(
            zaklasyfikuj_blad_dekodera(libheif_rs::HeifErrorCode::InvalidInput),
            WeryfikacjaHeic::Odrzucony
        );
    }

    /// Brak kodeka w systemie to wada ŚRODOWISKA. Gdyby obciążał plik, Faza 17
    /// kasowałaby poprawnie naprawione zdjęcia przez `sprzataj`.
    #[test]
    fn test_brak_kodeka_obciaza_srodowisko() {
        for kod in [
            libheif_rs::HeifErrorCode::UnsupportedFeature,
            libheif_rs::HeifErrorCode::PluginLoadingError,
            libheif_rs::HeifErrorCode::UnsupportedFileType,
        ] {
            assert_eq!(
                zaklasyfikuj_blad_dekodera(kod),
                WeryfikacjaHeic::TylkoStruktura,
                "Kod {:?} mówi o braku możliwości dekodowania, nie o wadzie pliku", kod
            );
        }
    }

    /// Domyślnie obciążamy PLIK, nie środowisko — przy wątpliwości lepiej
    /// spróbować kolejnego modułu naprawczego niż przyjąć zepsuty wynik.
    #[test]
    fn test_nieznany_blad_domyslnie_obciaza_plik() {
        assert_eq!(
            zaklasyfikuj_blad_dekodera(libheif_rs::HeifErrorCode::MemoryAllocationError),
            WeryfikacjaHeic::Odrzucony
        );
    }

    /// AVIF to ten sam kontener HEIF, ale INNY KODEK — dekoduje go `dav1d`,
    /// nie `libde265`. Bez tego fixture'a cała ścieżka AVIF była nietknięta
    /// przez testy, mimo że `is_heic_extension` ją obejmuje.
    #[test]
    #[ignore = "Wymaga image/test_fixture.avif oraz pluginu dav1d. Uruchom z --ignored."]
    fn test_piksele_avif_dekoduja_sie_drugim_kodekiem() {
        let bajty = std::fs::read("image/test_fixture.avif").expect("fixture musi istnieć");
        assert_eq!(
            verify_heic_pixels(&bajty),
            WeryfikacjaHeic::PikseleZdekodowane,
            "Zdrowy AVIF musi przejść pełne dekodowanie pikseli"
        );
    }

    #[test]
    #[ignore = "Wymaga image/test_fixture.avif. Uruchom z --ignored."]
    fn test_uszkodzony_avif_jest_odrzucony() {
        let mut bajty = std::fs::read("image/test_fixture.avif").expect("fixture musi istnieć");
        let pozycja = (0..bajty.len().saturating_sub(4))
            .find(|&i| &bajty[i..i + 4] == b"mdat")
            .expect("fixture musi mieć pudełko mdat");
        for b in bajty[pozycja + 4..].iter_mut() {
            *b = 0x5A;
        }
        assert_eq!(verify_heic_pixels(&bajty), WeryfikacjaHeic::Odrzucony);
    }
}
