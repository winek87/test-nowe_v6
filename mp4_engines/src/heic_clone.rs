// src/mp4_repair/heic_clone.rs

//! # Przeszczep Metadanych HEIC/HEIF/AVIF
//!
//! HEIC to **zwyczajny ISOBMFF** — ta sama rodzina kontenerów co MP4, z inną
//! obsadą atomów. Sprawdzone na prawdziwym pliku z telefonu:
//!
//! ```text
//! ftyp   24 B
//! meta   1991 B        <- indeks: `iinf`, `iprp`, `iloc`
//! sefd   7 233 909 B   <- własnościowy box producenta
//! mdat   442 080 B     <- surowe dane obrazu
//! ```
//!
//! Rola `meta` odpowiada roli `moov` w MP4, a atom `iloc` (item location)
//! odpowiada `stco`/`co64` — trzyma offsety do danych w `mdat`. Naprawa polega
//! więc na tym samym, co [`super::engine_clone`] robi dla MP4: wziąć zdrowy
//! indeks od bliźniaczej kopii i połączyć go z danymi obrazu z kopii
//! uszkodzonej.
//!
//! ## Dlaczego tu NIE trzeba przepisywać offsetów
//!
//! Wynik składamy jako: **wszystkie atomy dawcy sprzed `mdat`, skopiowane
//! bajt w bajt** + **atom `mdat` z pliku uszkodzonego**. Dzięki temu `mdat`
//! ląduje pod DOKŁADNIE tym samym offsetem, co u dawcy, więc offsety w `iloc`
//! pozostają poprawne bez żadnej ingerencji.
//!
//! To nie jest uproszczenie, a świadomie dobrany wariant. W badanym pliku
//! `iloc` ma wersję 1, offsety 4-bajtowe i 34 elementy — z czego 33 extenty
//! wskazują w `mdat`, a **jeden poza niego** (w zachowywany prefiks). Ręczne
//! przesuwanie offsetów wymagałoby rozróżniania tych przypadków i groziło
//! zepsuciem tego jednego; kopiowanie prefiksu bajt w bajt jest poprawne dla
//! OBU naraz.
//!
//! ## Warunki, które muszą być spełnione
//!
//! 1. Dawca ma `meta` i `mdat`, a `mdat` jest u niego **ostatnim** atomem
//!    najwyższego poziomu. Inaczej jego podmiana przesunęłaby atomy za nim i
//!    unieważniła offsety wskazujące w nie.
//! 2. `mdat` pliku uszkodzonego jest **nie krótszy** niż `mdat` dawcy —
//!    inaczej część offsetów wypadłaby za koniec pliku.
//!
//! Oba warunki są sprawdzane i dają jasny błąd, zamiast produkować plik, który
//! wygląda na naprawiony. Ostateczne rozstrzygnięcie należy i tak do
//! obowiązkowej weryfikacji przez `libheif` (patrz `repair_modules::heic`).

use super::boxes::{find_box, parse_top_level_boxes, BoxInfo};
use std::io;
use std::path::Path;

/// Górny limit rozmiaru pliku wczytywanego do przeszczepu.
///
/// Operacja wymaga obu plików w pamięci naraz (parsowanie łańcucha atomów), a
/// Faza 17 przetwarza pliki równolegle — szczyt zużycia to wielokrotność tej
/// wartości. Zdjęcia HEIC mieszczą się w tym z ogromnym zapasem; limit chroni
/// przed patologicznym wejściem, nie przed normalnym materiałem.
pub const LIMIT_W_RAM: u64 = 256 * 1024 * 1024; // 256 MB

fn blad(rodzaj: io::ErrorKind, opis: String) -> io::Error {
    io::Error::new(rodzaj, opis)
}

/// Wczytuje plik, pilnując limitu pamięci.
fn wczytaj(sciezka: &Path) -> io::Result<Vec<u8>> {
    let rozmiar = std::fs::metadata(sciezka)?.len();
    if rozmiar > LIMIT_W_RAM {
        return Err(blad(
            io::ErrorKind::InvalidInput,
            format!("plik {} ma {} B i przekracza limit przeszczepu w RAM ({} B)", sciezka.display(), rozmiar, LIMIT_W_RAM),
        ));
    }
    std::fs::read(sciezka)
}

/// Zwraca atom `mdat` najwyższego poziomu wraz z informacją, czy jest ostatni.
fn znajdz_mdat(atomy: &[BoxInfo]) -> Option<(BoxInfo, bool)> {
    let mdat = find_box(atomy, b"mdat")?;
    let ostatni = atomy.last().map(|b| b.offset == mdat.offset).unwrap_or(false);
    Some((mdat, ostatni))
}

/// Składa sprawny HEIC z indeksu dawcy i danych obrazu pliku uszkodzonego.
///
/// Zwraca gotowe bajty wyniku. Wydzielone z [`repair`], żeby dało się testować
/// bez dotykania dysku.
pub fn zloz_bajty(uszkodzony: &[u8], dawca: &[u8]) -> io::Result<Vec<u8>> {
    let atomy_dawcy = parse_top_level_boxes(dawca);
    let atomy_uszkodzonego = parse_top_level_boxes(uszkodzony);

    if atomy_dawcy.is_empty() {
        return Err(blad(io::ErrorKind::InvalidData, "dawca nie zawiera czytelnych atomów ISOBMFF".to_string()));
    }

    if find_box(&atomy_dawcy, b"meta").is_none() {
        return Err(blad(io::ErrorKind::NotFound, "dawca nie ma atomu `meta` - bez indeksu nie ma czego przeszczepiać".to_string()));
    }

    let (mdat_dawcy, mdat_ostatni) = znajdz_mdat(&atomy_dawcy)
        .ok_or_else(|| blad(io::ErrorKind::NotFound, "dawca nie ma atomu `mdat`".to_string()))?;

    if !mdat_ostatni {
        return Err(blad(
            io::ErrorKind::InvalidData,
            format!(
                "u dawcy `mdat` nie jest ostatnim atomem (offset {}) - jego podmiana przesunęłaby atomy za nim i unieważniła offsety",
                mdat_dawcy.offset
            ),
        ));
    }

    let mdat_uszkodzonego = find_box(&atomy_uszkodzonego, b"mdat")
        .ok_or_else(|| blad(io::ErrorKind::NotFound, "plik uszkodzony nie ma atomu `mdat` - nie ma danych obrazu do odratowania".to_string()))?;

    let (dane_od_dawcy, dane_do_dawcy) = mdat_dawcy.body_range();
    let (dane_od_uszk, dane_do_uszk) = mdat_uszkodzonego.body_range();

    let dlugosc_dawcy = dane_do_dawcy.saturating_sub(dane_od_dawcy);
    let dlugosc_uszk = dane_do_uszk.saturating_sub(dane_od_uszk);

    if dane_do_uszk > uszkodzony.len() {
        return Err(blad(io::ErrorKind::UnexpectedEof, "atom `mdat` pliku uszkodzonego wychodzi za koniec pliku".to_string()));
    }

    if dlugosc_uszk < dlugosc_dawcy {
        return Err(blad(
            io::ErrorKind::InvalidData,
            format!(
                "`mdat` pliku uszkodzonego jest KRÓTSZY niż u dawcy ({} vs {} B) - część offsetów z `iloc` wypadłaby za koniec pliku",
                dlugosc_uszk, dlugosc_dawcy
            ),
        ));
    }

    // Prefiks dawcy (wszystko przed `mdat`) kopiowany BAJT W BAJT — to on
    // gwarantuje, że offsety w `iloc` pozostają poprawne, także te wskazujące
    // poza `mdat`.
    let prefiks = &dawca[..mdat_dawcy.offset];
    let mdat_uszkodzonego_bajty = &uszkodzony[mdat_uszkodzonego.offset..dane_do_uszk];

    let mut wynik = Vec::with_capacity(prefiks.len() + mdat_uszkodzonego_bajty.len());
    wynik.extend_from_slice(prefiks);
    wynik.extend_from_slice(mdat_uszkodzonego_bajty);

    Ok(wynik)
}

/// Wykonuje przeszczep i zapisuje wynik na dysk.
///
/// Sygnatura celowo taka sama jak [`super::engine_clone::repair`] — oba silniki
/// realizują ten sam pomysł na dwóch odmianach ISOBMFF.
pub fn repair(broken_file: &str, donor_file: &str, output_file: &str) -> io::Result<()> {
    tracing::debug!("🖼️ [HEIC-CLONE] Przeszczep indeksu `meta` od dawcy: {}", donor_file);

    let uszkodzony = wczytaj(Path::new(broken_file))?;
    let dawca = wczytaj(Path::new(donor_file))?;

    let wynik = zloz_bajty(&uszkodzony, &dawca)?;

    tracing::debug!(
        "🖼️ [HEIC-CLONE] Złożono {} B (prefiks dawcy + mdat pliku uszkodzonego). Zapis: {}",
        wynik.len(), output_file
    );

    std::fs::write(output_file, &wynik)?;
    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Buduje atom ISOBMFF: rozmiar (BE) + typ + treść.
    fn atom(typ: &[u8; 4], tresc: &[u8]) -> Vec<u8> {
        let mut b = ((tresc.len() + 8) as u32).to_be_bytes().to_vec();
        b.extend_from_slice(typ);
        b.extend_from_slice(tresc);
        b
    }

    /// Minimalny HEIC: ftyp + meta + mdat (mdat ostatni, jak w realnych plikach).
    fn heic(meta_tresc: &[u8], mdat_dane: &[u8]) -> Vec<u8> {
        let mut plik = atom(b"ftyp", b"heic\x00\x00\x00\x00");
        plik.extend(atom(b"meta", meta_tresc));
        plik.extend(atom(b"mdat", mdat_dane));
        plik
    }

    // ------------------------------------------------------------------
    // Ścieżka udana
    // ------------------------------------------------------------------

    #[test]
    fn test_bierze_indeks_od_dawcy_i_dane_od_uszkodzonego() {
        let dawca = heic(b"ZDROWY-INDEKS", &[0xAAu8; 64]);
        let uszkodzony = heic(b"ZEPSUTY!!!!!!", &[0xBBu8; 64]);

        let wynik = zloz_bajty(&uszkodzony, &dawca).expect("przeszczep powinien się udać");

        assert!(wynik.windows(13).any(|w| w == b"ZDROWY-INDEKS"), "indeks musi pochodzić od DAWCY");
        assert!(!wynik.windows(13).any(|w| w == b"ZEPSUTY!!!!!!"), "zepsuty indeks nie może przeżyć");
        assert!(wynik.windows(8).any(|w| w == [0xBBu8; 8]), "dane obrazu muszą pochodzić z pliku USZKODZONEGO");
        assert!(!wynik.windows(8).any(|w| w == [0xAAu8; 8]), "dane dawcy nie mogą trafić do wyniku");
    }

    /// Sedno projektu: `mdat` musi wylądować pod TYM SAMYM offsetem, co u
    /// dawcy — tylko wtedy offsety w `iloc` pozostają poprawne bez przepisywania.
    #[test]
    fn test_mdat_lezy_pod_tym_samym_offsetem_co_u_dawcy() {
        let dawca = heic(b"INDEKS-DAWCY", &[0xAAu8; 100]);
        let uszkodzony = heic(b"INNY-INDEKS!", &[0xBBu8; 250]);

        let wynik = zloz_bajty(&uszkodzony, &dawca).unwrap();

        let off_dawcy = find_box(&parse_top_level_boxes(&dawca), b"mdat").unwrap().offset;
        let off_wyniku = find_box(&parse_top_level_boxes(&wynik), b"mdat").unwrap().offset;

        assert_eq!(off_wyniku, off_dawcy, "przesunięcie mdat unieważniłoby wszystkie offsety iloc");
    }

    #[test]
    fn test_prefiks_dawcy_jest_kopiowany_bajt_w_bajt() {
        // Dzięki temu poprawne zostają także offsety wskazujące POZA `mdat` —
        // w realnym pliku był dokładnie jeden taki extent.
        let dawca = heic(b"PREFIKS-WAZNY", &[0xAAu8; 32]);
        let uszkodzony = heic(b"cokolwiek....", &[0xBBu8; 32]);

        let wynik = zloz_bajty(&uszkodzony, &dawca).unwrap();
        let mdat_off = find_box(&parse_top_level_boxes(&dawca), b"mdat").unwrap().offset;

        assert_eq!(&wynik[..mdat_off], &dawca[..mdat_off], "prefiks musi być identyczny z dawcą");
    }

    #[test]
    fn test_dluzszy_mdat_uszkodzonego_jest_dopuszczalny() {
        // Offsety dawcy nadal mieszczą się w pliku, więc to bezpieczne.
        let dawca = heic(b"INDEKS", &[0xAAu8; 50]);
        let uszkodzony = heic(b"INDEKS", &[0xBBu8; 500]);

        let wynik = zloz_bajty(&uszkodzony, &dawca).expect("dłuższy mdat nie jest przeszkodą");
        assert!(wynik.len() > dawca.len());
    }

    // ------------------------------------------------------------------
    // Warunki odrzucenia
    // ------------------------------------------------------------------

    #[test]
    fn test_odrzuca_krotszy_mdat_uszkodzonego() {
        // Offsety z iloc dawcy wypadłyby za koniec pliku.
        let dawca = heic(b"INDEKS", &[0xAAu8; 500]);
        let uszkodzony = heic(b"INDEKS", &[0xBBu8; 50]);

        let e = zloz_bajty(&uszkodzony, &dawca).expect_err("krótszy mdat musi zostać odrzucony");
        assert!(e.to_string().contains("KRÓTSZY"), "błąd musi nazwać przyczynę: {}", e);
    }

    #[test]
    fn test_odrzuca_dawce_bez_meta() {
        let mut dawca = atom(b"ftyp", b"heic\x00\x00\x00\x00");
        dawca.extend(atom(b"mdat", &[0xAAu8; 32]));
        let uszkodzony = heic(b"INDEKS", &[0xBBu8; 32]);

        let e = zloz_bajty(&uszkodzony, &dawca).expect_err("dawca bez meta jest bezużyteczny");
        assert!(e.to_string().contains("meta"), "{}", e);
    }

    #[test]
    fn test_odrzuca_dawce_bez_mdat() {
        let mut dawca = atom(b"ftyp", b"heic\x00\x00\x00\x00");
        dawca.extend(atom(b"meta", b"INDEKS"));
        let uszkodzony = heic(b"INDEKS", &[0xBBu8; 32]);

        let e = zloz_bajty(&uszkodzony, &dawca).expect_err("bez mdat dawcy nie da się wyznaczyć układu");
        assert!(e.to_string().contains("mdat"), "{}", e);
    }

    #[test]
    fn test_odrzuca_uszkodzony_bez_mdat() {
        let dawca = heic(b"INDEKS", &[0xAAu8; 32]);
        let mut uszkodzony = atom(b"ftyp", b"heic\x00\x00\x00\x00");
        uszkodzony.extend(atom(b"meta", b"INDEKS"));

        let e = zloz_bajty(&uszkodzony, &dawca).expect_err("nie ma czego ratować");
        assert!(e.to_string().contains("danych obrazu"), "błąd musi nazwać brak danych: {}", e);
    }

    /// Gdy `mdat` dawcy nie jest ostatni, jego podmiana przesunęłaby atomy za
    /// nim i unieważniła offsety wskazujące w nie — odrzucamy, zamiast
    /// produkować plik, który wygląda na naprawiony.
    #[test]
    fn test_odrzuca_gdy_mdat_dawcy_nie_jest_ostatni() {
        let mut dawca = atom(b"ftyp", b"heic\x00\x00\x00\x00");
        dawca.extend(atom(b"mdat", &[0xAAu8; 32]));
        dawca.extend(atom(b"meta", b"INDEKS-PO-MDAT"));

        let uszkodzony = heic(b"INDEKS", &[0xBBu8; 32]);

        let e = zloz_bajty(&uszkodzony, &dawca).expect_err("taki układ nie jest obsługiwany");
        assert!(e.to_string().contains("ostatnim"), "błąd musi nazwać warunek: {}", e);
    }

    #[test]
    fn test_odrzuca_smieci_jako_dawce() {
        let uszkodzony = heic(b"INDEKS", &[0xBBu8; 32]);
        assert!(zloz_bajty(&uszkodzony, b"to zupelnie nie jest kontener").is_err());
        assert!(zloz_bajty(&uszkodzony, b"").is_err());
    }

    // ------------------------------------------------------------------
    // Prawdziwy plik z telefonu
    // ------------------------------------------------------------------

    /// Weryfikacja na PRAWDZIWYM HEIC: psujemy indeks `meta`, przeszczepiamy
    /// zdrowy od nietkniętej kopii i sprawdzamy, że wynik ma poprawną strukturę
    /// oraz DANE OBRAZU z pliku uszkodzonego.
    #[test]
    #[ignore = "Wymaga image/test_fixture.heic. Uruchom z --ignored."]
    fn test_przeszczep_na_prawdziwym_heic() {
        let zdrowy = std::fs::read(crate::sciezka_fixture("test_fixture.heic"))
            .expect("fixture image/test_fixture.heic musi istnieć");

        let atomy = parse_top_level_boxes(&zdrowy);
        let meta = find_box(&atomy, b"meta").expect("prawdziwy HEIC ma meta");
        let mdat = find_box(&atomy, b"mdat").expect("prawdziwy HEIC ma mdat");

        assert_eq!(
            atomy.last().map(|b| b.offset), Some(mdat.offset),
            "w tym pliku mdat jest ostatni - na tym opiera się cały przeszczep"
        );

        // Psujemy WYŁĄCZNIE treść `meta`, zostawiając nagłówek atomu — tak
        // wygląda typowe uszkodzenie indeksu przy odzysku.
        let mut uszkodzony = zdrowy.clone();
        let (meta_od, meta_do) = meta.body_range();
        for b in &mut uszkodzony[meta_od..meta_do] {
            *b = 0xFF;
        }

        let wynik = zloz_bajty(&uszkodzony, &zdrowy).expect("przeszczep na prawdziwym pliku musi się udać");

        // 1. Indeks pochodzi od zdrowej kopii.
        assert_eq!(&wynik[meta_od..meta_do], &zdrowy[meta_od..meta_do], "meta musi pochodzić od dawcy");

        // 2. Dane obrazu pochodzą z pliku uszkodzonego (tu identyczne, bo
        //    psuliśmy tylko indeks) i leżą pod właściwym offsetem.
        let (mdat_od, mdat_do) = mdat.body_range();
        assert_eq!(&wynik[mdat_od..mdat_do], &zdrowy[mdat_od..mdat_do], "dane mdat muszą zostać na miejscu");

        // 3. Rozmiar i układ atomów zachowane.
        assert_eq!(wynik.len(), zdrowy.len(), "przeszczep nie zmienia rozmiaru, gdy mdat jest równy");
        let atomy_wyniku = parse_top_level_boxes(&wynik);
        assert_eq!(
            atomy_wyniku.iter().map(|b| b.type_str()).collect::<Vec<_>>(),
            atomy.iter().map(|b| b.type_str()).collect::<Vec<_>>(),
            "układ atomów najwyższego poziomu musi zostać zachowany"
        );
    }
}
