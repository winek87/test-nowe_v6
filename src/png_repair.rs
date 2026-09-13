// src/png_repair.rs

//! # Naprawa PNG na Poziomie Fragmentów (CRC32 jako sędzia)
//!
//! PNG jest formatem, który **sam mówi, co w nim jest zepsute**. Plik to ciąg
//! fragmentów (chunków), a każdy nosi własny CRC32:
//!
//! ```text
//! 89 50 4E 47 0D 0A 1A 0A   sygnatura (8 B)
//! [dlugosc:4][typ:4][dane:dlugosc][crc32:4]   IHDR  <- wymiary, głębia, tryb
//! [dlugosc:4][typ:4][dane:dlugosc][crc32:4]   tEXt  <- metadane (pomocniczy)
//! [dlugosc:4][typ:4][dane:dlugosc][crc32:4]   IDAT  <- dane obrazu
//! [00 00 00 00][IEND][AE 42 60 82]            IEND  <- znacznik końca
//! ```
//!
//! To stawia PNG w zupełnie innej sytuacji niż JPEG czy HEIC, gdzie uszkodzenie
//! trzeba wywnioskować z nieudanego dekodowania. Tutaj mamy **obiektywny
//! sygnał per fragment**, więc naprawa może być chirurgiczna.
//!
//! ## Dwie strategie, dwa różne wymagania
//!
//! | Strategia | Potrzebuje bliźniaka | Co naprawia |
//! |---|---|---|
//! | [`splice_png`] | TAK | dowolny fragment, o ile jest zdrowy po jednej ze stron |
//! | [`napraw_pojedyncza_kopie`] | NIE | fragmenty **pomocnicze** + brak `IEND` + śmieci na końcu |
//!
//! Pierwsza jest mocniejsza i pochodzi z Fazy 18 (Smart Splice), która od
//! początku składała PNG-i po fragmentach. Druga to nowa możliwość i jedyna
//! dostępna, gdy **druga kopia nie istnieje** albo gdy ten sam fragment jest
//! zepsuty po obu stronach.
//!
//! ## Dlaczego naprawa bez dawcy jest ograniczona do fragmentów pomocniczych
//!
//! Specyfikacja PNG dzieli fragmenty na **krytyczne** (`IHDR`, `PLTE`, `IDAT`,
//! `IEND` — wielka pierwsza litera) i **pomocnicze** (`tEXt`, `gAMA`, `iCCP`,
//! `eXIf`, … — mała pierwsza litera). Ten podział nie jest konwencją, a
//! kontraktem: dekoder **ma prawo zignorować** fragment pomocniczy, więc jego
//! usunięcie jest operacją bezpieczną i bezstratną dla samego obrazu.
//!
//! Fragmentu krytycznego usunąć nie można — bez `IHDR` nie ma wymiarów, a
//! usunięcie jednego `IDAT` z kilku rozrywa strumień zlib i niszczy obraz od
//! tego miejsca w dół. Dlatego przy uszkodzonym fragmencie krytycznym
//! [`napraw_pojedyncza_kopie`] **odmawia** i oddaje sprawę wariantowi z dawcą,
//! zamiast produkować plik, który wygląda na naprawiony.
//!
//! ## Czego świadomie NIE robimy: przeliczania CRC „w miejscu"
//!
//! Najprostsza „naprawa" PNG to przeliczenie błędnego CRC na zgodny z danymi.
//! Byłaby to jednak naprawa **objawu**, nie choroby: niezgodny CRC prawie
//! zawsze znaczy, że przekłamane są DANE, a nie cztery bajty sumy. Przeliczenie
//! sumy zamieniłoby plik z wykrywalnym uszkodzeniem na plik z uszkodzeniem
//! ukrytym — i to w narzędziu, którego cały sens polega na wykrywaniu
//! uszkodzeń. CRC przeliczamy więc tylko przy **zapisie fragmentów, które i tak
//! uznaliśmy za zdrowe** (patrz [`write_png_chunk`]).

// ============================================================================
// CRC32 (implementacja własna - PNG używa standardowego CRC-32/ISO-HDLC,
// tego samego co ZIP/gzip - unikamy nowej zależności Cargo dla jednej funkcji)
// ============================================================================

pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    !crc
}

// ============================================================================
// PNG: SKŁADANIE PO CHUNKACH (CRC32 JAKO OBIEKTYWNY SĘDZIA)
// ============================================================================

pub(crate) const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
pub(crate) const CANONICAL_IEND: [u8; 12] = [0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82];

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PngChunk {
    pub(crate) ctype: [u8; 4],
    pub(crate) data: Vec<u8>,
    pub(crate) crc_valid: bool,
}

impl PngChunk {
    /// Czy fragment jest **pomocniczy**, czyli taki, który dekoder ma prawo
    /// pominąć.
    ///
    /// Rozstrzyga o tym mała pierwsza litera typu — to nie konwencja
    /// nazewnicza, a bit zdefiniowany w specyfikacji PNG (bit 5 pierwszego
    /// bajtu, zwany „ancillary bit").
    pub(crate) fn jest_pomocniczy(&self) -> bool {
        self.ctype[0].is_ascii_lowercase()
    }

    /// Typ fragmentu w postaci czytelnej dla dziennika.
    pub(crate) fn nazwa(&self) -> String {
        String::from_utf8_lossy(&self.ctype).to_string()
    }
}

/// Parsuje plik PNG na listę chunków, oznaczając każdy jako poprawny/uszkodzony
/// na podstawie weryfikacji JEGO WŁASNEGO CRC32 — obiektywny sygnał, nie
/// heurystyka. Zatrzymuje się (bez błędu) na pierwszym chunku, którego
/// zadeklarowana długość wykracza poza koniec bufora — plik ucięty w tym
/// miejscu nadal ma wartościowe chunki na początku, które chcemy zachować.
pub(crate) fn parse_png_chunks(bytes: &[u8]) -> Option<Vec<PngChunk>> {
    if bytes.len() < 8 || bytes[0..8] != PNG_SIGNATURE { return None; }
    let mut chunks = Vec::new();
    let mut pos = 8;
    while pos + 8 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
        let ctype: [u8; 4] = bytes[pos + 4..pos + 8].try_into().ok()?;
        let data_start = pos + 8;
        let data_end = match data_start.checked_add(len) { Some(v) => v, None => break };
        if data_end + 4 > bytes.len() { break; }
        let data = bytes[data_start..data_end].to_vec();
        let crc_stored = u32::from_be_bytes(bytes[data_end..data_end + 4].try_into().ok()?);
        let mut crc_input = Vec::with_capacity(4 + data.len());
        crc_input.extend_from_slice(&ctype);
        crc_input.extend_from_slice(&data);
        let crc_valid = crc32(&crc_input) == crc_stored;
        let is_iend = &ctype == b"IEND";
        chunks.push(PngChunk { ctype, data, crc_valid });
        pos = data_end + 4;
        if is_iend { break; }
    }
    Some(chunks)
}

pub(crate) fn write_png_chunk(out: &mut Vec<u8>, chunk: &PngChunk) {
    out.extend_from_slice(&(chunk.data.len() as u32).to_be_bytes());
    out.extend_from_slice(&chunk.ctype);
    out.extend_from_slice(&chunk.data);
    let mut crc_input = Vec::with_capacity(4 + chunk.data.len());
    crc_input.extend_from_slice(&chunk.ctype);
    crc_input.extend_from_slice(&chunk.data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

/// Składa jedną, poprawną kopię PNG z dwóch uszkodzonych, wybierając NA
/// POZIOMIE KAŻDEGO CHUNKA tę stronę, której CRC32 się zgadza. Zawsze
/// przelicza CRC na nowo przy zapisie (nie kopiuje surowych bajtów CRC) —
/// tanie i eliminuje ryzyko subtelnego błędu przy ponownym użyciu starych bajtów.
///
/// Zwraca `None`, gdy:
/// - żadna strona nie parsuje się jako poprawny PNG,
/// - struktura obu kopii się rozjeżdża (różne typy chunków na tej samej
///   pozycji — nie próbujemy realignować, to sygnał głębszego uszkodzenia),
/// - TEN SAM chunk jest uszkodzony w OBU kopiach jednocześnie (nie ma z
///   czego wybrać).
///
/// Brakujący `IEND` na końcu (obie kopie ucięte przed nim) jest dopełniany
/// kanonicznym, stałym chunkiem `IEND` (ten sam bajt-w-bajt dla każdego
/// poprawnego PNG, bo jego dane są zawsze puste).
pub(crate) fn splice_png(bytes_a: &[u8], bytes_b: &[u8]) -> Option<Vec<u8>> {
    let chunks_a = parse_png_chunks(bytes_a)?;
    let chunks_b = parse_png_chunks(bytes_b)?;
    let max_len = chunks_a.len().max(chunks_b.len());
    if max_len == 0 { return None; }

    let mut result = PNG_SIGNATURE.to_vec();
    let mut has_iend = false;

    for i in 0..max_len {
        let a = chunks_a.get(i);
        let b = chunks_b.get(i);
        let chosen: &PngChunk = match (a, b) {
            (Some(ca), Some(cb)) => {
                if ca.ctype != cb.ctype { return None; }
                if ca.crc_valid { ca } else if cb.crc_valid { cb } else { return None; }
            }
            (Some(ca), None) => { if ca.crc_valid { ca } else { return None; } }
            (None, Some(cb)) => { if cb.crc_valid { cb } else { return None; } }
            (None, None) => unreachable!(),
        };
        if &chosen.ctype == b"IEND" { has_iend = true; }
        write_png_chunk(&mut result, chosen);
    }

    if !has_iend {
        result.extend_from_slice(&CANONICAL_IEND);
    }
    Some(result)
}

// ============================================================================
// PNG: NAPRAWA POJEDYNCZEJ KOPII (bez dawcy)
// ============================================================================

/// Co zmieniła naprawa pojedynczej kopii — do dziennika operacyjnego.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RaportNaprawy {
    /// Typy odrzuconych fragmentów pomocniczych o niezgodnym CRC.
    pub usuniete_pomocnicze: Vec<String>,
    /// Czy dopełniono brakujący `IEND`.
    pub dopelniono_iend: bool,
    /// Liczba bajtów śmieci odrzuconych za znacznikiem `IEND`.
    pub odrzucone_bajty_za_iend: usize,
}

impl RaportNaprawy {
    /// Czy naprawa w ogóle cokolwiek zmieniła.
    pub fn cokolwiek_zmieniono(&self) -> bool {
        !self.usuniete_pomocnicze.is_empty() || self.dopelniono_iend || self.odrzucone_bajty_za_iend > 0
    }

    /// Opis dla dziennika operacyjnego.
    pub fn opis(&self) -> String {
        let mut czesci = Vec::new();
        if !self.usuniete_pomocnicze.is_empty() {
            czesci.push(format!(
                "odrzucono uszkodzone fragmenty pomocnicze ({})",
                self.usuniete_pomocnicze.join(", ")
            ));
        }
        if self.dopelniono_iend {
            czesci.push("dopełniono brakujący znacznik końca IEND".to_string());
        }
        if self.odrzucone_bajty_za_iend > 0 {
            czesci.push(format!("odcięto {} B śmieci za IEND", self.odrzucone_bajty_za_iend));
        }
        if czesci.is_empty() {
            return "brak zmian".to_string();
        }
        czesci.join("; ")
    }
}

/// Naprawia PNG **bez drugiej kopii**, korzystając z tego, że fragmenty
/// pomocnicze są opcjonalne.
///
/// Wykonywane operacje — wszystkie bezstratne dla samego obrazu:
///
/// 1. fragment **pomocniczy** o niezgodnym CRC zostaje odrzucony (dekoder i tak
///    ma prawo go pominąć, a jego obecność wywraca dekodery rygorystyczne),
/// 2. brakujący `IEND` zostaje dopełniony kanonicznym fragmentem,
/// 3. bajty za `IEND` zostają odcięte.
///
/// Zwraca `None`, gdy:
///
/// * plik nie parsuje się jako PNG (brak sygnatury) — to przypadek dla
///   `header_png`,
/// * uszkodzony jest fragment **krytyczny** — usunąć go nie można, a
///   zignorowanie uszkodzenia byłoby pozorną naprawą; sprawę przejmuje wariant
///   z dawcą ([`splice_png`]),
/// * brakuje `IHDR` albo `IDAT` — nie ma obrazu do uratowania,
/// * nie było czego naprawiać (plik jest już spójny) — żeby Faza 17 nie
///   raportowała naprawy tam, gdzie jej nie wykonano.
pub fn napraw_pojedyncza_kopie(dane: &[u8]) -> Option<(Vec<u8>, RaportNaprawy)> {
    let chunki = parse_png_chunks(dane)?;
    if chunki.is_empty() {
        return None;
    }

    let mut raport = RaportNaprawy::default();
    let mut wynik = PNG_SIGNATURE.to_vec();
    let mut ma_ihdr = false;
    let mut ma_idat = false;
    let mut ma_iend = false;

    for chunk in &chunki {
        if !chunk.crc_valid {
            if chunk.jest_pomocniczy() {
                raport.usuniete_pomocnicze.push(chunk.nazwa());
                continue;
            }
            // Fragment krytyczny z niezgodnym CRC - tu kończą się możliwości
            // naprawy z jednej kopii.
            return None;
        }

        match &chunk.ctype {
            b"IHDR" => ma_ihdr = true,
            b"IDAT" => ma_idat = true,
            b"IEND" => ma_iend = true,
            _ => {}
        }

        write_png_chunk(&mut wynik, chunk);
    }

    if !ma_ihdr || !ma_idat {
        return None;
    }

    if !ma_iend {
        wynik.extend_from_slice(&CANONICAL_IEND);
        raport.dopelniono_iend = true;
    }

    // Bajty za IEND: `parse_png_chunks` przerywa na IEND, więc wszystko, co
    // zostało w wejściu za ostatnim odczytanym fragmentem, jest nadwyżką.
    let dlugosc_odczytana = PNG_SIGNATURE.len()
        + chunki.iter().map(|c| 12 + c.data.len()).sum::<usize>();
    if dane.len() > dlugosc_odczytana {
        raport.odrzucone_bajty_za_iend = dane.len() - dlugosc_odczytana;
    }

    if !raport.cokolwiek_zmieniono() {
        return None;
    }

    Some((wynik, raport))
}

/// Naprawia PNG z jednej kopii, operując na plikach.
///
/// Wynik zapisywany jest dopiero po udanym złożeniu w pamięci, więc nieudana
/// naprawa nie zostawia pliku-widma.
pub fn napraw_plik(sciezka: &std::path::Path, wyjscie: &std::path::Path) -> Option<RaportNaprawy> {
    let dane = std::fs::read(sciezka).ok()?;
    let (wynik, raport) = napraw_pojedyncza_kopie(&dane)?;

    if let Some(katalog) = wyjscie.parent()
        && !katalog.as_os_str().is_empty() {
            std::fs::create_dir_all(katalog).ok()?;
        }
    std::fs::write(wyjscie, &wynik).ok()?;

    Some(raport)
}

/// Składa PNG z dwóch kopii, operując na plikach.
pub fn zloz_z_dawcy(
    uszkodzony: &std::path::Path,
    dawca: &std::path::Path,
    wyjscie: &std::path::Path,
) -> Option<()> {
    let a = std::fs::read(uszkodzony).ok()?;
    let b = std::fs::read(dawca).ok()?;
    let wynik = splice_png(&a, &b)?;

    if let Some(katalog) = wyjscie.parent()
        && !katalog.as_os_str().is_empty() {
            std::fs::create_dir_all(katalog).ok()?;
        }
    std::fs::write(wyjscie, &wynik).ok()?;

    Some(())
}

// ============================================================================
// Materiał testowy
// ============================================================================

/// Pomoce wspólne dla tego modułu i dla
/// [`crate::phases::repair_modules::png`].
///
/// Trzymane w jednym miejscu świadomie: dwie kopie generatora rozjechałyby się
/// przy pierwszej zmianie modelu uszkodzenia i jeden z zestawów testów cicho
/// przestałby sprawdzać to, co obiecuje.
#[cfg(test)]
pub(crate) mod pomoce_testowe {
    use super::*;

    /// Generuje PRAWDZIWY plik PNG o podanych wymiarach.
    pub fn zdrowy_png(szer: u32, wys: u32) -> Vec<u8> {
        let mut img = image::RgbImage::new(szer, wys);
        for (x, y, px) in img.enumerate_pixels_mut() {
            *px = image::Rgb([(x * 7 % 256) as u8, (y * 11 % 256) as u8, ((x * y) % 256) as u8]);
        }
        let mut bajty = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut bajty, image::ImageFormat::Png)
            .expect("kodowanie PNG musi się udać");
        bajty.into_inner()
    }

    /// Wstawia fragment o podanym typie i danych przed `IEND`.
    ///
    /// `poprawny_crc = false` daje fragment, który parser oznaczy jako
    /// uszkodzony — dokładnie to, co naprawa ma rozpoznać.
    pub fn wstaw_fragment(png: &[u8], typ: &[u8; 4], dane: &[u8], poprawny_crc: bool) -> Vec<u8> {
        let chunki = parse_png_chunks(png).expect("wejście musi być PNG");

        let mut wynik = PNG_SIGNATURE.to_vec();
        for chunk in &chunki {
            if &chunk.ctype == b"IEND" {
                wynik.extend_from_slice(&(dane.len() as u32).to_be_bytes());
                wynik.extend_from_slice(typ);
                wynik.extend_from_slice(dane);

                let mut wejscie_crc = typ.to_vec();
                wejscie_crc.extend_from_slice(dane);
                let crc = crc32(&wejscie_crc);
                let crc = if poprawny_crc { crc } else { crc ^ 0xFFFF_FFFF };
                wynik.extend_from_slice(&crc.to_be_bytes());
            }
            write_png_chunk(&mut wynik, chunk);
        }
        wynik
    }

    /// Psuje CRC pierwszego fragmentu o podanym typie, nie ruszając danych.
    pub fn zepsuj_crc_fragmentu(png: &[u8], typ: &[u8; 4]) -> Vec<u8> {
        let mut pos = PNG_SIGNATURE.len();
        let mut wynik = png.to_vec();

        while pos + 8 <= png.len() {
            let len = u32::from_be_bytes(png[pos..pos + 4].try_into().unwrap()) as usize;
            let ctype = &png[pos + 4..pos + 8];
            let koniec_danych = pos + 8 + len;
            if koniec_danych + 4 > png.len() { break; }

            if ctype == typ {
                for b in &mut wynik[koniec_danych..koniec_danych + 4] {
                    *b ^= 0xFF;
                }
                return wynik;
            }
            pos = koniec_danych + 4;
        }

        panic!("nie znaleziono fragmentu {}", String::from_utf8_lossy(typ));
    }
}

#[cfg(test)]
mod tests {
    use super::pomoce_testowe::*;
    use super::*;

    // ------------------------------------------------------------------
    // Rozpoznawanie fragmentów pomocniczych - fundament całej naprawy
    // ------------------------------------------------------------------

    #[test]
    fn test_podzial_na_krytyczne_i_pomocnicze() {
        let pomocniczy = |typ: &[u8; 4]| PngChunk { ctype: *typ, data: vec![], crc_valid: true }.jest_pomocniczy();

        for typ in [b"IHDR", b"PLTE", b"IDAT", b"IEND"] {
            assert!(!pomocniczy(typ), "{} jest fragmentem KRYTYCZNYM", String::from_utf8_lossy(typ));
        }
        for typ in [b"tEXt", b"gAMA", b"iCCP", b"eXIf", b"pHYs", b"tRNS"] {
            assert!(pomocniczy(typ), "{} jest fragmentem pomocniczym", String::from_utf8_lossy(typ));
        }
    }

    // ------------------------------------------------------------------
    // Naprawa bez dawcy
    // ------------------------------------------------------------------

    #[test]
    fn test_odrzuca_uszkodzony_fragment_pomocniczy() {
        let zdrowy = zdrowy_png(32, 24);
        // Komentarz tEXt z rozjechanym CRC - rygorystyczny dekoder ma prawo
        // odrzucić na tym cały plik, choć obraz jest nietknięty.
        let zepsuty = wstaw_fragment(&zdrowy, b"tEXt", b"Comment\0uszkodzony", false);

        let (wynik, raport) = napraw_pojedyncza_kopie(&zepsuty).expect("naprawa bez dawcy musi się udać");

        assert_eq!(raport.usuniete_pomocnicze, vec!["tEXt"], "raport musi nazwać odrzucony fragment");
        assert!(!raport.dopelniono_iend, "IEND był na miejscu");

        let chunki = parse_png_chunks(&wynik).unwrap();
        assert!(chunki.iter().all(|c| c.crc_valid), "w wyniku nie może zostać fragment z błędnym CRC");
        assert!(!chunki.iter().any(|c| &c.ctype == b"tEXt"), "uszkodzony tEXt musi zniknąć");

        let obraz = image::load_from_memory(&wynik).expect("wynik musi się dekodować");
        assert_eq!((obraz.width(), obraz.height()), (32, 24));
    }

    #[test]
    fn test_zachowuje_zdrowe_fragmenty_pomocnicze() {
        let zdrowy = zdrowy_png(32, 24);
        let z_metadanymi = wstaw_fragment(&zdrowy, b"tEXt", b"Autor\0Weryfikator", true);
        let zepsuty = wstaw_fragment(&z_metadanymi, b"gAMA", b"\x00\x00\xB1\x8F", false);

        let (wynik, raport) = napraw_pojedyncza_kopie(&zepsuty).unwrap();

        assert_eq!(raport.usuniete_pomocnicze, vec!["gAMA"]);
        let chunki = parse_png_chunks(&wynik).unwrap();
        assert!(
            chunki.iter().any(|c| &c.ctype == b"tEXt"),
            "zdrowe metadane muszą przeżyć - naprawa nie jest czyszczeniem wszystkiego"
        );
    }

    #[test]
    fn test_dopelnia_brakujacy_iend() {
        let zdrowy = zdrowy_png(32, 24);
        // Ucinamy dokładnie kanoniczny IEND (12 B).
        let bez_iend = &zdrowy[..zdrowy.len() - CANONICAL_IEND.len()];

        let (wynik, raport) = napraw_pojedyncza_kopie(bez_iend).expect("brak IEND musi być naprawialny");

        assert!(raport.dopelniono_iend);
        assert!(wynik.ends_with(&CANONICAL_IEND));
        assert!(image::load_from_memory(&wynik).is_ok(), "domknięty plik musi się dekodować");
    }

    #[test]
    fn test_odcina_smieci_za_iend() {
        let zdrowy = zdrowy_png(16, 16);
        let mut ze_smieciami = zdrowy.clone();
        ze_smieciami.extend_from_slice(&[0xDE; 500]);

        let (wynik, raport) = napraw_pojedyncza_kopie(&ze_smieciami).expect("śmieci za IEND są naprawialne");

        assert_eq!(raport.odrzucone_bajty_za_iend, 500, "raport musi podać liczbę odciętych bajtów");
        assert_eq!(wynik.len(), zdrowy.len(), "wynik musi mieć długość zdrowego pliku");
        assert!(wynik.ends_with(&CANONICAL_IEND));
    }

    #[test]
    fn test_odmawia_gdy_uszkodzony_fragment_krytyczny() {
        let zdrowy = zdrowy_png(32, 24);

        for typ in [b"IHDR", b"IDAT"] {
            let zepsuty = zepsuj_crc_fragmentu(&zdrowy, typ);
            assert!(
                napraw_pojedyncza_kopie(&zepsuty).is_none(),
                "uszkodzony {} nie może być naprawiony z jednej kopii - usunięcie go zniszczyłoby obraz",
                String::from_utf8_lossy(typ)
            );
        }
    }

    /// Uszkodzony `IDAT` przy WIELU fragmentach `IDAT` — izolowany test
    /// strażnika fragmentów krytycznych.
    ///
    /// Przy jednym `IDAT` odmowa wynika też z warunku „brak danych obrazu",
    /// więc ten pierwszy test nie odróżniałby jednego zabezpieczenia od
    /// drugiego. Prawdziwe PNG-i z aparatów i edytorów regularnie mają `IDAT`
    /// podzielony na wiele fragmentów (specyfikacja pozwala ciąć strumień zlib
    /// na dowolnej granicy bajtu) — i wtedy usunięcie jednego z nich rozrywa
    /// strumień, zamiast tylko zabrać metadane.
    #[test]
    fn test_odmawia_gdy_uszkodzony_jeden_z_wielu_idat() {
        let zdrowy = zdrowy_png(96, 64);
        let chunki = parse_png_chunks(&zdrowy).unwrap();
        let idat = chunki.iter().find(|c| &c.ctype == b"IDAT").expect("PNG musi mieć IDAT");
        assert!(idat.data.len() > 40, "potrzebujemy IDAT-a, który da się podzielić");

        let polowa = idat.data.len() / 2;

        // Przepisujemy plik, dzieląc IDAT na dwa fragmenty. Pierwszy dostaje
        // przekłamane CRC, drugi zostaje zdrowy.
        let mut wielo_idat = PNG_SIGNATURE.to_vec();
        let mut liczba_idat = 0;
        for chunk in &chunki {
            if &chunk.ctype == b"IDAT" {
                let pierwszy = PngChunk { ctype: *b"IDAT", data: idat.data[..polowa].to_vec(), crc_valid: true };
                let drugi = PngChunk { ctype: *b"IDAT", data: idat.data[polowa..].to_vec(), crc_valid: true };

                write_png_chunk(&mut wielo_idat, &pierwszy);
                // Psujemy CRC pierwszego IDAT-a, nie ruszając jego danych.
                let dlugosc = wielo_idat.len();
                for b in &mut wielo_idat[dlugosc - 4..] { *b ^= 0xFF; }

                write_png_chunk(&mut wielo_idat, &drugi);
                liczba_idat = 2;
            } else {
                write_png_chunk(&mut wielo_idat, chunk);
            }
        }
        assert_eq!(liczba_idat, 2, "plik testowy musi mieć dwa fragmenty IDAT");

        // Kontrola: drugi IDAT jest zdrowy, więc warunek „brak IDAT" NIE
        // zadziała - o odmowie decyduje wyłącznie strażnik fragmentów
        // krytycznych.
        let odczytane = parse_png_chunks(&wielo_idat).unwrap();
        let zdrowe_idat = odczytane.iter().filter(|c| &c.ctype == b"IDAT" && c.crc_valid).count();
        assert_eq!(zdrowe_idat, 1, "dokładnie jeden IDAT musi zostać zdrowy");

        assert!(
            napraw_pojedyncza_kopie(&wielo_idat).is_none(),
            "usunięcie jednego z kilku IDAT-ów rozrywa strumień zlib - naprawa musi odmówić"
        );
    }

    #[test]
    fn test_odmawia_gdy_nie_ma_czego_naprawiac() {
        // Kluczowe dla uczciwości raportowania Fazy 17: plik zdrowy nie może
        // zostać policzony jako naprawiony.
        let zdrowy = zdrowy_png(32, 24);
        assert!(
            napraw_pojedyncza_kopie(&zdrowy).is_none(),
            "zdrowy plik nie jest naprawą"
        );
    }

    #[test]
    fn test_odmawia_bez_sygnatury_png() {
        assert!(napraw_pojedyncza_kopie(b"to nie jest png").is_none());
    }

    #[test]
    fn test_odmawia_gdy_brak_idat() {
        // Sama sygnatura + IHDR + IEND: struktura poprawna, obrazu nie ma.
        let zdrowy = zdrowy_png(16, 16);
        let chunki = parse_png_chunks(&zdrowy).unwrap();

        let mut bez_idat = PNG_SIGNATURE.to_vec();
        for chunk in chunki.iter().filter(|c| &c.ctype != b"IDAT") {
            write_png_chunk(&mut bez_idat, chunk);
        }
        bez_idat.extend_from_slice(&[0xAB; 10]); // żeby było „co naprawiać"

        assert!(napraw_pojedyncza_kopie(&bez_idat).is_none(), "bez IDAT nie ma obrazu do uratowania");
    }

    #[test]
    fn test_crc_nie_jest_przeliczane_na_uszkodzonych_danych() {
        // Sedno uzasadnienia z dokumentacji modułu: nie zamieniamy uszkodzenia
        // wykrywalnego na ukryte. Przekłamujemy DANE fragmentu krytycznego -
        // naprawa musi odmówić, a nie „naprawić" sumę kontrolną.
        let zdrowy = zdrowy_png(32, 24);
        let chunki = parse_png_chunks(&zdrowy).unwrap();
        let idat = chunki.iter().find(|c| &c.ctype == b"IDAT").unwrap();

        let mut zepsuty = PNG_SIGNATURE.to_vec();
        for chunk in &chunki {
            if &chunk.ctype == b"IDAT" {
                let mut uszkodzone = idat.clone();
                uszkodzone.data[0] ^= 0xFF;
                // CRC zapisany dla ORYGINALNYCH danych - niezgodny z nowymi.
                zepsuty.extend_from_slice(&(uszkodzone.data.len() as u32).to_be_bytes());
                zepsuty.extend_from_slice(&uszkodzone.ctype);
                zepsuty.extend_from_slice(&uszkodzone.data);
                let mut wejscie = idat.ctype.to_vec();
                wejscie.extend_from_slice(&idat.data);
                zepsuty.extend_from_slice(&crc32(&wejscie).to_be_bytes());
            } else {
                write_png_chunk(&mut zepsuty, chunk);
            }
        }

        assert!(
            napraw_pojedyncza_kopie(&zepsuty).is_none(),
            "przekłamane dane obrazu nie mogą zostać zalegalizowane przeliczeniem CRC"
        );
    }

    #[test]
    fn test_raport_opisuje_wszystkie_operacje() {
        let raport = RaportNaprawy {
            usuniete_pomocnicze: vec!["tEXt".to_string(), "gAMA".to_string()],
            dopelniono_iend: true,
            odrzucone_bajty_za_iend: 42,
        };

        let opis = raport.opis();
        assert!(opis.contains("tEXt") && opis.contains("gAMA"), "opis: {}", opis);
        assert!(opis.contains("IEND"), "opis: {}", opis);
        assert!(opis.contains("42 B"), "opis: {}", opis);
        assert!(raport.cokolwiek_zmieniono());

        assert!(!RaportNaprawy::default().cokolwiek_zmieniono());
        assert_eq!(RaportNaprawy::default().opis(), "brak zmian");
    }

    // ------------------------------------------------------------------
    // Warstwa plikowa
    // ------------------------------------------------------------------

    #[test]
    fn test_napraw_plik_zapisuje_wynik() {
        let dir = tempfile::tempdir().unwrap();
        let zdrowy = zdrowy_png(48, 32);
        let zepsuty = wstaw_fragment(&zdrowy, b"tEXt", b"k\0v", false);

        let wejscie = dir.path().join("obraz.png");
        let wyjscie = dir.path().join("wyniki").join("naprawiony.png");
        std::fs::write(&wejscie, &zepsuty).unwrap();

        let raport = napraw_plik(&wejscie, &wyjscie).expect("naprawa musi się udać");
        assert_eq!(raport.usuniete_pomocnicze, vec!["tEXt"]);

        let obraz = image::load_from_memory(&std::fs::read(&wyjscie).unwrap()).unwrap();
        assert_eq!((obraz.width(), obraz.height()), (48, 32));
    }

    #[test]
    fn test_napraw_plik_nie_zapisuje_gdy_brak_naprawy() {
        let dir = tempfile::tempdir().unwrap();
        let wejscie = dir.path().join("zdrowy.png");
        let wyjscie = dir.path().join("nie_powinien_istniec.png");
        std::fs::write(&wejscie, zdrowy_png(16, 16)).unwrap();

        assert!(napraw_plik(&wejscie, &wyjscie).is_none());
        assert!(!wyjscie.exists(), "brak naprawy nie może tworzyć pliku");
    }

    #[test]
    fn test_zloz_z_dawcy_na_plikach() {
        let dir = tempfile::tempdir().unwrap();
        let zdrowy = zdrowy_png(64, 48);

        // Uszkodzenia w RÓŻNYCH fragmentach krytycznych po obu stronach -
        // żadnej z kopii nie da się naprawić samodzielnie.
        let strona_a = zepsuj_crc_fragmentu(&zdrowy, b"IHDR");
        let strona_b = zepsuj_crc_fragmentu(&zdrowy, b"IDAT");

        assert!(napraw_pojedyncza_kopie(&strona_a).is_none(), "kontrola: A wymaga dawcy");
        assert!(napraw_pojedyncza_kopie(&strona_b).is_none(), "kontrola: B wymaga dawcy");

        let p_a = dir.path().join("a.png");
        let p_b = dir.path().join("b.png");
        let p_wynik = dir.path().join("w").join("zlozony.png");
        std::fs::write(&p_a, &strona_a).unwrap();
        std::fs::write(&p_b, &strona_b).unwrap();

        zloz_z_dawcy(&p_a, &p_b, &p_wynik).expect("złożenie z dwóch kopii musi się udać");

        let odczyt = std::fs::read(&p_wynik).unwrap();
        assert_eq!(odczyt, zdrowy, "złożenie dwóch kopii tego samego pliku musi odtworzyć oryginał");
    }
}
