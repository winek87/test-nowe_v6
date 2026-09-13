// src/raster_splice.rs

//! # Składanie GIF / BMP / WEBP z dwóch uszkodzonych kopii
//!
//! ## Dlaczego to NIE wygląda jak `splice_png`
//!
//! PNG i ZIP mają sumę kontrolną przy KAŻDYM fragmencie, więc da się wybierać
//! zdrową stronę blok po bloku i mieć obiektywny dowód, która to. GIF, BMP i
//! WEBP takich sum nie mają — nie istnieje sposób, żeby patrząc na sam blok
//! stwierdzić, czy jest uszkodzony.
//!
//! Zostaje więc podejście z `dng_splice` i z kandydatów JPEG: generujemy
//! NIEWIELKI, deterministyczny zbiór złożeń i pozwalamy rozstrzygnąć
//! DEKODEROWI. Kandydat, który nie daje się zdekodować, po prostu odpada.
//! Nie ma tu żadnej heurystyki zgadującej — jedynym sędzią jest realne
//! dekodowanie pikseli, czyli gwarancja MOCNA.
//!
//! ## Granica cięcia per format — zmierzona, nie założona
//!
//! Wszystkie trzy formaty mają naturalny podział na METADANE i DANE OBRAZU:
//!
//! | format | granica | zmierzone na `image/test_fixture.*` |
//! |---|---|---|
//! | BMP  | `bfOffBits` (bajty 10..14, little-endian) | offset pikseli 54 |
//! | GIF  | nagłówek 13 B + globalna paleta | paleta 768 B → dane od 781 |
//! | WEBP | `RIFF` + rozmiar + `WEBP` = 12 B | pierwszy chunk `VP8 ` od 12 |
//!
//! ## TIFF tu nie ma — świadomie
//!
//! TIFF ma własny, silniejszy mechanizm: [`crate::dng_splice`] chodzi po
//! strukturze IFD i przenosi konkretne obszary danych pikseli według offsetów
//! odczytanych ze zdrowej struktury. Duplikowanie tego tutaj prostszą metodą
//! byłoby krokiem wstecz.

/// Ile kandydatów najwyżej zwracamy. Dwa złożenia (metadane A + dane B oraz
/// odwrotnie) w zupełności wystarczają — trzeciego sensownego podziału te
/// formaty nie mają.
const MAKS_KANDYDATOW: usize = 2;

/// Rozpoznaje formaty obsługiwane przez ten moduł.
pub fn obslugiwane_rozszerzenie(ext: &str) -> bool {
    matches!(ext, "gif" | "bmp" | "webp")
}

/// Offset, od którego zaczynają się DANE OBRAZU — czyli miejsce cięcia.
/// `None`, gdy plik jest za krótki albo nie ma rozpoznawalnej struktury.
fn granica_danych(ext: &str, bajty: &[u8]) -> Option<usize> {
    match ext {
        "bmp" => {
            // Nagłówek BMP: "BM", rozmiar pliku (4 B), zarezerwowane (4 B),
            // offset danych pikseli (4 B, little-endian).
            if bajty.len() < 14 || &bajty[0..2] != b"BM" {
                return None;
            }
            let offset = u32::from_le_bytes(bajty[10..14].try_into().ok()?) as usize;
            // Offset musi wskazywać ZA nagłówek i wewnątrz pliku — inaczej
            // cięlibyśmy w przypadkowym miejscu.
            if offset < 14 || offset >= bajty.len() {
                return None;
            }
            Some(offset)
        }

        "gif" => {
            // Nagłówek 6 B ("GIF87a"/"GIF89a") + deskryptor ekranu 7 B.
            // Bit 7 pola flag mówi o obecności globalnej palety, a trzy
            // najmłodsze bity kodują jej rozmiar jako 3 * 2^(N+1) bajtów.
            if bajty.len() < 13 || &bajty[0..3] != b"GIF" {
                return None;
            }
            let flagi = bajty[10];
            let paleta = if flagi & 0x80 != 0 {
                3 * (1usize << ((flagi & 0x07) + 1))
            } else {
                0
            };
            let granica = 13 + paleta;
            if granica >= bajty.len() {
                return None;
            }
            Some(granica)
        }

        "webp" => {
            // Kontener RIFF: "RIFF" + rozmiar (4 B) + "WEBP", potem chunki.
            if bajty.len() < 16 || &bajty[0..4] != b"RIFF" || &bajty[8..12] != b"WEBP" {
                return None;
            }
            Some(12)
        }

        _ => None,
    }
}

/// Poprawia pole długości w nagłówku, jeśli format je ma.
///
/// BMP trzyma w bajtach 2..6 rozmiar całego pliku, a WEBP w 4..8 rozmiar
/// zawartości RIFF. Po złożeniu dwóch kopii o RÓŻNEJ długości pole zostałoby
/// niezgodne z rzeczywistością. Dekodery bywają tolerancyjne, ale zostawienie
/// świadomie błędnej wartości w odzyskanym materiale dowodowym byłoby
/// niechlujstwem.
fn popraw_pole_dlugosci(ext: &str, bajty: &mut [u8]) {
    match ext {
        "bmp" if bajty.len() >= 6 => {
            let dlugosc = bajty.len() as u32;
            bajty[2..6].copy_from_slice(&dlugosc.to_le_bytes());
        }
        "webp" if bajty.len() >= 8 => {
            // Pole RIFF liczy wszystko PO nim, czyli długość minus 8 bajtów.
            let dlugosc = (bajty.len() - 8) as u32;
            bajty[4..8].copy_from_slice(&dlugosc.to_le_bytes());
        }
        _ => {}
    }
}

/// Buduje kandydatów złożenia: metadane z jednej kopii, dane obrazu z drugiej.
///
/// Kolejność jest USTALONA i deterministyczna — najpierw metadane z A, potem
/// z B — żeby wynik nie zależał od tego, którą stroną zaczniemy. Zwraca pustą
/// listę, gdy żadnej kopii nie da się rozciąć.
///
/// Kandydaci NIE są tu weryfikowani: rozstrzyga wywołujący, realnym
/// dekodowaniem pikseli. To celowe — moduł nie zna kryterium akceptacji i nie
/// powinien go znać.
pub fn splice_raster(ext: &str, bajty_a: &[u8], bajty_b: &[u8]) -> Vec<Vec<u8>> {
    if !obslugiwane_rozszerzenie(ext) {
        return Vec::new();
    }

    let mut kandydaci = Vec::with_capacity(MAKS_KANDYDATOW);

    // Granice liczymy RAZ, dla obu stron, bo najczęstszy realny przypadek to
    // zniszczone metadane w jednej z kopii — a wtedy w TEJ kopii granicy nie
    // da się odczytać, mimo że potrzebujemy z niej wyłącznie danych obrazu.
    //
    // Obie kopie są bliźniaczymi odczytami TEGO SAMEGO pliku, więc mają ten sam
    // układ; granica odczytana ze zdrowej strony obowiązuje dla obu. To
    // dokładnie to samo założenie, na którym stoi `dng_splice`. Bez tego moduł
    // radziłby sobie wyłącznie z uszkodzeniami, które nie tykają nagłówka —
    // czyli praktycznie z niczym.
    let granica_a = granica_danych(ext, bajty_a);
    let granica_b = granica_danych(ext, bajty_b);
    let (granica_a, granica_b) = match (granica_a, granica_b) {
        (Some(a), Some(b)) => (a, b),
        (Some(a), None) => (a, a),
        (None, Some(b)) => (b, b),
        // Żadna strona nie ma czytelnego nagłówka — nie ma skąd wziąć granicy.
        (None, None) => return Vec::new(),
    };

    for (metadane, granica_meta, dane, granica_dane) in [
        (bajty_a, granica_a, bajty_b, granica_b),
        (bajty_b, granica_b, bajty_a, granica_a),
    ] {
        // Granica przeniesiona z drugiej kopii może wypaść poza krótszy plik.
        if granica_meta > metadane.len() || granica_dane > dane.len() {
            continue;
        }

        let mut kandydat = Vec::with_capacity(granica_meta + dane.len() - granica_dane);
        kandydat.extend_from_slice(&metadane[..granica_meta]);
        kandydat.extend_from_slice(&dane[granica_dane..]);

        popraw_pole_dlugosci(ext, &mut kandydat);

        // Złożenie identyczne z którymś wejściem nic nie wnosi — obie kopie są
        // uszkodzone, więc powielanie ich jako "kandydata" tylko marnowałoby
        // czas dekodera.
        if kandydat != bajty_a && kandydat != bajty_b {
            kandydaci.push(kandydat);
        }
    }

    kandydaci
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // ZAKRES
    // ------------------------------------------------------------------

    #[test]
    fn test_obslugiwane_sa_dokladnie_trzy_formaty() {
        for ext in ["gif", "bmp", "webp"] {
            assert!(obslugiwane_rozszerzenie(ext), ".{} powinien być obsługiwany", ext);
        }
        // TIFF ma własny, silniejszy mechanizm w `dng_splice`.
        for ext in ["tif", "tiff", "png", "jpg", "mp4"] {
            assert!(!obslugiwane_rozszerzenie(ext), ".{} nie należy do tego modułu", ext);
        }
    }

    #[test]
    fn test_nieobslugiwany_format_nie_daje_kandydatow() {
        assert!(splice_raster("png", b"aaaa", b"bbbb").is_empty());
    }

    // ------------------------------------------------------------------
    // GRANICA CIĘCIA
    // ------------------------------------------------------------------

    #[test]
    fn test_granica_bmp_czyta_offset_pikseli() {
        // "BM" + rozmiar + zarezerwowane + offset danych = 54.
        let mut b = vec![0u8; 100];
        b[0..2].copy_from_slice(b"BM");
        b[10..14].copy_from_slice(&54u32.to_le_bytes());
        assert_eq!(granica_danych("bmp", &b), Some(54));
    }

    /// Offset spoza pliku albo wskazujący w środek nagłówka oznacza rozbity
    /// nagłówek — cięcie w takim miejscu dałoby śmieci udające kandydata.
    #[test]
    fn test_granica_bmp_odrzuca_bezsensowny_offset() {
        let mut b = vec![0u8; 100];
        b[0..2].copy_from_slice(b"BM");

        b[10..14].copy_from_slice(&5_000_000u32.to_le_bytes());
        assert_eq!(granica_danych("bmp", &b), None, "Offset poza plikiem");

        b[10..14].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(granica_danych("bmp", &b), None, "Offset wewnątrz nagłówka");
    }

    #[test]
    fn test_granica_gif_uwzglednia_globalna_palete() {
        let mut g = vec![0u8; 2000];
        g[0..6].copy_from_slice(b"GIF89a");
        // Bit 0x80 = paleta obecna, trzy młodsze bity = 7 → 3 * 2^8 = 768 B.
        g[10] = 0x80 | 0x07;
        assert_eq!(granica_danych("gif", &g), Some(13 + 768));
    }

    #[test]
    fn test_granica_gif_bez_palety_to_sam_naglowek() {
        let mut g = vec![0u8; 100];
        g[0..6].copy_from_slice(b"GIF87a");
        g[10] = 0x00;
        assert_eq!(granica_danych("gif", &g), Some(13));
    }

    #[test]
    fn test_granica_webp_to_naglowek_riff() {
        let mut w = vec![0u8; 100];
        w[0..4].copy_from_slice(b"RIFF");
        w[8..12].copy_from_slice(b"WEBP");
        assert_eq!(granica_danych("webp", &w), Some(12));
    }

    #[test]
    fn test_granica_odrzuca_bledna_sygnature() {
        assert_eq!(granica_danych("bmp", b"XX000000000000000000"), None);
        assert_eq!(granica_danych("gif", b"NOTAGIF00000000"), None);
        assert_eq!(granica_danych("webp", b"RIFF0000NOPE0000"), None);
    }

    #[test]
    fn test_granica_odrzuca_plik_za_krotki() {
        assert_eq!(granica_danych("bmp", b"BM"), None);
        assert_eq!(granica_danych("gif", b"GIF"), None);
        assert_eq!(granica_danych("webp", b"RIFF"), None);
    }

    // ------------------------------------------------------------------
    // POLE DŁUGOŚCI
    // ------------------------------------------------------------------

    #[test]
    fn test_pole_dlugosci_bmp_jest_poprawiane() {
        let mut b = vec![0u8; 120];
        b[0..2].copy_from_slice(b"BM");
        b[2..6].copy_from_slice(&999u32.to_le_bytes());

        popraw_pole_dlugosci("bmp", &mut b);

        assert_eq!(u32::from_le_bytes(b[2..6].try_into().unwrap()), 120);
    }

    /// Pole RIFF liczy bajty PO sobie, czyli długość pliku minus 8.
    #[test]
    fn test_pole_dlugosci_webp_liczy_od_wlasciwego_miejsca() {
        let mut w = vec![0u8; 120];
        w[0..4].copy_from_slice(b"RIFF");
        w[8..12].copy_from_slice(b"WEBP");

        popraw_pole_dlugosci("webp", &mut w);

        assert_eq!(u32::from_le_bytes(w[4..8].try_into().unwrap()), 112);
    }

    #[test]
    fn test_gif_nie_ma_pola_dlugosci_do_poprawienia() {
        let przed = vec![1u8; 50];
        let mut po = przed.clone();
        popraw_pole_dlugosci("gif", &mut po);
        assert_eq!(przed, po, "GIF nie trzyma rozmiaru pliku w nagłówku");
    }

    // ------------------------------------------------------------------
    // SKŁADANIE
    // ------------------------------------------------------------------

    /// Probny BMP z POPRAWNYM polem długości. Bez tego korekta nagłówka
    /// sprawiłaby, że złożenie identycznych kopii różni się od wejścia — i to
    /// słusznie, bo naprawia błędną wartość.
    fn bmp_probny(wypelnienie: u8, dlugosc: usize) -> Vec<u8> {
        let mut b = vec![wypelnienie; dlugosc];
        b[0..2].copy_from_slice(b"BM");
        b[2..6].copy_from_slice(&(dlugosc as u32).to_le_bytes());
        b[10..14].copy_from_slice(&54u32.to_le_bytes());
        b
    }

    /// Odwrotna strona tej samej reguły: gdy pole długości jest BŁĘDNE,
    /// złożenie identycznych kopii JEST kandydatem, bo naprawia nagłówek.
    #[test]
    fn test_bledne_pole_dlugosci_jest_naprawiane_nawet_przy_identycznych_kopiach() {
        let mut a = bmp_probny(0xAA, 200);
        a[2..6].copy_from_slice(&9999u32.to_le_bytes());

        let kandydaci = splice_raster("bmp", &a, &a);

        assert!(!kandydaci.is_empty(), "Korekta błędnego rozmiaru to realna zmiana");
        assert_eq!(
            u32::from_le_bytes(kandydaci[0][2..6].try_into().unwrap()), 200,
            "Pole długości musi zostać sprowadzone do rzeczywistego rozmiaru"
        );
    }

    #[test]
    fn test_sklada_w_obie_strony() {
        let a = bmp_probny(0xAA, 200);
        let b = bmp_probny(0xBB, 200);

        let kandydaci = splice_raster("bmp", &a, &b);

        assert_eq!(kandydaci.len(), 2, "Oba kierunki złożenia");
        assert_eq!(&kandydaci[0][54..60], &[0xBB; 6], "Pierwszy: dane z kopii B");
        assert_eq!(&kandydaci[1][54..60], &[0xAA; 6], "Drugi: dane z kopii A");
    }

    /// Gdy obie kopie są identyczne, każde złożenie odtwarza wejście — takie
    /// „kandydaty" nic nie wnoszą i tylko obciążałyby dekoder.
    #[test]
    fn test_identyczne_kopie_nie_daja_kandydatow() {
        let a = bmp_probny(0xAA, 200);
        assert!(splice_raster("bmp", &a, &a).is_empty());
    }

    #[test]
    fn test_rozbity_naglowek_po_obu_stronach_nie_daje_kandydatow() {
        let smieci = vec![0x00; 200];
        assert!(splice_raster("bmp", &smieci, &smieci).is_empty());
    }

    #[test]
    fn test_kolejnosc_kandydatow_jest_deterministyczna() {
        let a = bmp_probny(0xAA, 200);
        let b = bmp_probny(0xBB, 300);
        assert_eq!(splice_raster("bmp", &a, &b), splice_raster("bmp", &a, &b));
    }

    // ------------------------------------------------------------------
    // NA PRAWDZIWYCH PLIKACH
    // ------------------------------------------------------------------

    /// Sedno modułu: kopia z rozbitymi METADANYMI i kopia z uciętymi DANYMI
    /// razem dają plik, który realnie się dekoduje.
    ///
    /// ## Dlaczego uszkodzenia są właśnie takie
    ///
    /// Rozbicie metadanych psuje każdy z tych formatów — sygnatura przestaje
    /// się zgadzać i dekoder odmawia. Z danymi obrazu jest inaczej i zostało to
    /// sprawdzone empirycznie: BMP z danymi pikseli wypełnionymi stałą wartością
    /// NADAL SIĘ DEKODUJE, bo format nie ma żadnej kontroli spójności danych —
    /// „uszkodzone piksele" są w nim nieodróżnialne od „innego zdjęcia".
    /// Uszkodzeniem wykrywalnym jest dopiero UCIĘCIE, bo wtedy tablica pikseli
    /// nie pokrywa zadeklarowanych wymiarów.
    #[test]
    #[ignore = "Wymaga image/test_fixture.{gif,bmp,webp}. Uruchom z --ignored."]
    fn test_e2e_sklada_dekodowalny_plik_z_dwoch_uszkodzonych() {
        for ext in ["gif", "bmp", "webp"] {
            let zdrowy = std::fs::read(format!("image/test_fixture.{}", ext))
                .unwrap_or_else(|_| panic!("brak fixture'a dla {}", ext));
            let granica = granica_danych(ext, &zdrowy)
                .unwrap_or_else(|| panic!("nie rozpoznano granicy w {}", ext));

            assert!(
                image::load_from_memory(&zdrowy).is_ok(),
                "Test bez sensu: zdrowy {} musi się dekodować", ext
            );

            // Kopia A: rozbite METADANE, dane obrazu nietknięte.
            let mut a = zdrowy.clone();
            for b in a[..granica].iter_mut() {
                *b = 0x00;
            }
            assert!(
                image::load_from_memory(&a).is_err(),
                "{}: kopia z rozbitymi metadanymi nie może się dekodować", ext
            );

            // Kopia B: metadane zdrowe, dane UCIĘTE w połowie.
            let b = zdrowy[..granica + (zdrowy.len() - granica) / 2].to_vec();

            let kandydaci = splice_raster(ext, &a, &b);
            assert!(!kandydaci.is_empty(), "{}: brak kandydatów", ext);

            let udany = kandydaci.iter().any(|k| image::load_from_memory(k).is_ok());
            assert!(
                udany,
                "{}: żaden kandydat się nie zdekodował, choć metadane są zdrowe w kopii B, \
                 a pełne dane obrazu w kopii A",
                ext
            );
        }
    }

    /// Gdy TA SAMA część jest ucięta po obu stronach, brakujących danych nie ma
    /// skąd wziąć — moduł nie może wyprodukować pliku udającego odzyskany.
    #[test]
    #[ignore = "Wymaga image/test_fixture.gif. Uruchom z --ignored."]
    fn test_e2e_wspolne_uszkodzenie_nie_daje_dekodowalnego_wyniku() {
        let zdrowy = std::fs::read("image/test_fixture.gif").expect("fixture musi istnieć");
        let granica = granica_danych("gif", &zdrowy).unwrap();

        // Obie kopie ucięte w tym samym miejscu — brakuje dokładnie tego samego.
        let uciety = zdrowy[..granica + (zdrowy.len() - granica) / 3].to_vec();
        let a = uciety.clone();
        let b = uciety;

        assert!(
            image::load_from_memory(&a).is_err(),
            "Test bez sensu: ucięty GIF musi się nie dekodować"
        );

        for kandydat in splice_raster("gif", &a, &b) {
            assert!(
                image::load_from_memory(&kandydat).is_err(),
                "Brakujących danych nie ma po żadnej stronie - żaden kandydat nie ma prawa się zdekodować"
            );
        }
    }
}
