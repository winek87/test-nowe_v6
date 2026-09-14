// src/jpeg_splice.rs

//! # Przeszczep Tablic JPEG (składanie strukturalne z bliźniaczej kopii)
//!
//! Ta sama idea, co [`crate::mp4_repair::heic_clone`], przełożona na format,
//! który nie jest kontenerem ISOBMFF. Plik JPEG dzieli się na dwie części o
//! zupełnie różnej wrażliwości na uszkodzenie:
//!
//! ```text
//! FFD8  SOI
//! FFE0  APP0/JFIF          \
//! FFE1  APP1/EXIF           |  NAGŁÓWEK: tablice i parametry.
//! FFDB  DQT  kwantyzacja    |  Kilka kilobajtów. Uszkodzenie = plik
//! FFC4  DHT  Huffman        |  nie otwiera się W CAŁOŚCI.
//! FFC0  SOF0 ramka (w×h)    |
//! FFDA  SOS  nagłówek skanu /
//! ....  dane entropijne     <- SKAN: tu siedzi cały obraz (99% pliku)
//! FFD9  EOI
//! ```
//!
//! Nagłówek to **kilka kilobajtów**, które decydują o czytelności całości, a
//! przy tym są **identyczne w obu kopiach tego samego zdjęcia**. Skan to reszta
//! pliku i jest niezastępowalny. Naprawa polega więc na wzięciu nagłówka od
//! bliźniaka i doklejeniu do niego skanu z kopii uszkodzonej.
//!
//! ## Czym to się różni od modułu `header_jpg`
//!
//! [`crate::phases::repair_modules::header_jpg`] wstrzykuje *minimalny,
//! sztuczny* nagłówek JFIF, gdy brakuje samego `SOI`. Nie ma z czego odtworzyć
//! tablic DQT/DHT ani wymiarów z `SOF`, więc pomaga tylko w jednym, wąskim
//! przypadku. Ten moduł przenosi **prawdziwe tablice tego konkretnego zdjęcia**,
//! więc obejmuje uszkodzenia całego obszaru nagłówka.
//!
//! ## Dlaczego szukanie `SOS` ma ścieżkę awaryjną
//!
//! W pliku uszkodzonym łańcuch segmentów jest przerwany — i to przerwany
//! DOKŁADNIE w miejscu, którego naprawa dotyczy. Normalne przejście po
//! długościach segmentów urwie się przed `SOS`, dlatego [`analizuj`] po
//! zerwaniu łańcucha przechodzi w tryb szukania sygnatury `FFDA`.
//!
//! To wyszukiwanie **nie startuje od początku pliku**, a od miejsca, w którym
//! łańcuch się urwał. Powód jest konkretny: segment `APP1/EXIF` potrafi
//! zawierać **osadzoną miniaturę, która sama jest pełnym plikiem JPEG** — z
//! własnym `FFDA`. Naiwne szukanie trafiłoby w miniaturę i wyprodukowało plik,
//! który *daje się zdekodować* (więc przeszedłby weryfikację!), tylko byłby
//! podglądem 160×120 zamiast zdjęcia. Zaczynanie za sprawnie sparsowanymi
//! segmentami omija ten dół, a [`MINIMALNY_UDZIAL_SKANU`] domyka go w
//! przypadku, gdy zniszczony jest również sam `SOI`.
//!
//! ## Granice gwarancji
//!
//! Poprawne zdekodowanie wyniku dowodzi, że nagłówek pasuje do skanu — nie
//! dowodzi, że piksele są takie jak w oryginale. Jeśli skan kopii uszkodzonej
//! ma przekłamane bajty w środku, obraz otworzy się z artefaktami i to jest
//! najlepsze, co da się zrobić bez trzeciej kopii. Ta sama uczciwość
//! obowiązuje w `dng_splice` i `tar_archive`.

use std::io;
use std::path::Path;

/// Górny limit rozmiaru pliku wczytywanego do przeszczepu.
///
/// Operacja wymaga obu plików w pamięci naraz, a Faza 17 przetwarza pliki
/// równolegle — szczyt zużycia to wielokrotność tej wartości. Zdjęcia JPEG
/// mieszczą się w tym z ogromnym zapasem.
pub const LIMIT_W_RAM: u64 = 256 * 1024 * 1024; // 256 MB

/// Minimalny udział, jaki skan kopii uszkodzonej musi mieć w długości skanu
/// dawcy, żeby przeszczep został uznany za sensowny.
///
/// Obie kopie pochodzą z TEGO SAMEGO pliku, więc ich skany powinny mieć
/// praktycznie identyczną długość. Ten warunek nie jest więc dopasowywaniem
/// „podobnych" plików, a wyłapywaniem sytuacji, w której zlokalizowaliśmy ZŁY
/// `SOS` — przede wszystkim `SOS` osadzonej miniatury EXIF, która jest
/// mniejsza od zdjęcia o rzędy wielkości. Próg jest rozluźniony do połowy, żeby
/// nie odrzucać plików faktycznie uciętych na końcu, gdzie przeszczep wciąż
/// może uratować widoczną część obrazu.
pub const MINIMALNY_UDZIAL_SKANU: f64 = 0.5;

/// Segment JPEG najwyższego poziomu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Bajt znacznika, czyli to, co stoi za `0xFF` (np. `0xDB` dla `DQT`).
    pub marker: u8,
    /// Offset bajtu `0xFF` rozpoczynającego znacznik.
    pub offset: usize,
    /// Pełna długość segmentu wraz ze znacznikiem: `2` dla znaczników
    /// samodzielnych, `2 + pole_dlugosci` dla pozostałych.
    pub dlugosc_calkowita: usize,
}

impl Segment {
    /// Zakres treści segmentu, czyli bajty za znacznikiem i polem długości.
    ///
    /// Dla znaczników samodzielnych (bez treści) zwraca zakres pusty.
    pub fn zakres_tresci(&self) -> (usize, usize) {
        if self.dlugosc_calkowita <= 4 {
            let k = self.offset + self.dlugosc_calkowita;
            return (k, k);
        }
        (self.offset + 4, self.offset + self.dlugosc_calkowita)
    }
}

/// Parametry ramki obrazu odczytane z segmentu `SOF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamkaObrazu {
    /// Bajt znacznika `SOF` — rozróżnia tryb kodowania (`0xC0` bazowy,
    /// `0xC2` progresywny, …). Musi się zgadzać między kopiami, bo decyduje
    /// o sposobie interpretacji danych skanu.
    pub marker_sof: u8,
    pub szerokosc: u16,
    pub wysokosc: u16,
    pub komponenty: u8,
}

/// Wynik rozbioru pliku JPEG.
#[derive(Debug, Clone)]
pub struct AnalizaJpeg {
    /// Segmenty odczytane po łańcuchu długości, w kolejności występowania.
    pub segmenty: Vec<Segment>,
    /// Offset, na którym przejście po łańcuchu się zatrzymało. Dla pliku
    /// zdrowego to początek danych skanu; dla uszkodzonego — miejsce zerwania.
    pub koniec_lancucha: usize,
    /// Offset pierwszego bajtu danych entropijnych (za nagłówkiem `SOS`).
    pub poczatek_skanu: Option<usize>,
    /// `true`, gdy `SOS` znaleziono dopiero szukaniem sygnatury, a nie po
    /// łańcuchu segmentów. Oznacza plik z uszkodzonym nagłówkiem.
    pub skan_z_szukania: bool,
}

impl AnalizaJpeg {
    /// Czy plik zaczyna się od `SOI`.
    pub fn ma_soi(&self) -> bool {
        self.segmenty.first().map(|s| s.marker == MARKER_SOI).unwrap_or(false)
    }

    /// Pierwszy segment o podanym znaczniku.
    pub fn segment(&self, marker: u8) -> Option<Segment> {
        self.segmenty.iter().copied().find(|s| s.marker == marker)
    }
}

pub const MARKER_SOI: u8 = 0xD8;
pub const MARKER_EOI: u8 = 0xD9;
pub const MARKER_DQT: u8 = 0xDB;
pub const MARKER_DHT: u8 = 0xC4;
pub const MARKER_SOS: u8 = 0xDA;

/// Minimalny, poprawny segment `APP0`/JFIF (bez `SOI`) — jedyna kopia w
/// crate'cie. Wcześniej ten sam literał był powielony osobno w
/// `repair_modules::header_jpg` (naprawa: doklejany przed uciętym plikiem) i
/// w teście Fazy 18 (`build_minimal_jpeg`, budowa syntetycznego JPEG-a).
pub(crate) const APP0_JFIF_MINIMALNY: [u8; 18] = [
    0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F',
    0x00, 0x01, 0x01, 0x01, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00,
];

/// Czy znacznik jest segmentem `SOF` (Start Of Frame).
///
/// Zakres `0xC0..=0xCF` to prawie wyłącznie `SOF`, ale z trzema wyjątkami,
/// które trzeba wykluczyć: `0xC4` to `DHT` (tablice Huffmana), `0xC8` to
/// zarezerwowany `JPG`, a `0xCC` to `DAC` (kodowanie arytmetyczne).
pub fn jest_sof(marker: u8) -> bool {
    matches!(marker, 0xC0..=0xCF) && !matches!(marker, 0xC4 | 0xC8 | 0xCC)
}

/// Czy znacznik jest samodzielny, czyli nie ma po sobie pola długości.
///
/// To `SOI`, `EOI`, `TEM` oraz znaczniki restartu `RST0..RST7`.
fn jest_samodzielny(marker: u8) -> bool {
    matches!(marker, 0x01 | 0xD0..=0xD9)
}

fn blad(rodzaj: io::ErrorKind, opis: String) -> io::Error {
    io::Error::new(rodzaj, opis)
}

/// Wczytuje plik, pilnując limitu pamięci.
fn wczytaj(sciezka: &Path) -> io::Result<Vec<u8>> {
    let rozmiar = std::fs::metadata(sciezka)?.len();
    if rozmiar > LIMIT_W_RAM {
        return Err(blad(
            io::ErrorKind::InvalidInput,
            format!(
                "plik {} ma {} B i przekracza limit przeszczepu w RAM ({} B)",
                sciezka.display(), rozmiar, LIMIT_W_RAM
            ),
        ));
    }
    std::fs::read(sciezka)
}

/// Przechodzi po łańcuchu segmentów JPEG i lokalizuje początek danych skanu.
///
/// Przejście kończy się na `SOS` (za nim nie ma już segmentów, tylko dane
/// entropijne) albo w miejscu, w którym łańcuch przestaje być spójny. W drugim
/// przypadku włącza się szukanie sygnatury `FFDA` — od miejsca zerwania, nigdy
/// od początku pliku (uzasadnienie w dokumentacji modułu).
pub fn analizuj(dane: &[u8]) -> AnalizaJpeg {
    let mut segmenty = Vec::new();
    let mut pos = 0usize;

    if dane.len() >= 2 && dane[0] == 0xFF && dane[1] == MARKER_SOI {
        segmenty.push(Segment { marker: MARKER_SOI, offset: 0, dlugosc_calkowita: 2 });
        pos = 2;
    }

    let mut poczatek_skanu = None;

    while pos + 1 < dane.len() {
        if dane[pos] != 0xFF {
            break;
        }

        // Bajty wypełniające: dopuszczalny jest ciąg 0xFF przed znacznikiem.
        let mut p_marker = pos + 1;
        while p_marker < dane.len() && dane[p_marker] == 0xFF {
            p_marker += 1;
        }
        if p_marker >= dane.len() {
            break;
        }

        let marker = dane[p_marker];
        let offset_znacznika = p_marker - 1;

        if marker == 0x00 {
            // 0xFF00 to zabezpieczone 0xFF w danych, nie znacznik - łańcuch
            // segmentów się tu kończy.
            break;
        }

        if jest_samodzielny(marker) {
            segmenty.push(Segment { marker, offset: offset_znacznika, dlugosc_calkowita: 2 });
            pos = offset_znacznika + 2;
            continue;
        }

        if offset_znacznika + 4 > dane.len() {
            break;
        }
        let dlugosc = u16::from_be_bytes([dane[offset_znacznika + 2], dane[offset_znacznika + 3]]) as usize;

        // Pole długości liczy siebie samo, więc poniżej 2 jest bezsensowne, a
        // wyjście za koniec pliku oznacza zerwany łańcuch.
        if dlugosc < 2 || offset_znacznika + 2 + dlugosc > dane.len() {
            break;
        }

        let koniec = offset_znacznika + 2 + dlugosc;

        // Za każdym segmentem MUSI stać następny znacznik, czyli bajt `0xFF`
        // (albo koniec pliku). Bez tego sprawdzenia przekłamane pole długości
        // przenosiłoby nas w losowe miejsce — i, co gorsza, mogło przeskoczyć
        // PONAD prawdziwym `SOS`. Szukanie awaryjne startuje od miejsca
        // zerwania, więc taki przeskok oznaczałby szukanie już za celem i
        // uznanie pliku za nienaprawialny. Odrzucamy więc segment, którego
        // długość nie prowadzi do kolejnego znacznika, i zatrzymujemy łańcuch
        // PRZED nim — wtedy szukanie zaczyna się z właściwej strony.
        //
        // Wyjątek to `SOS`: za nim stoją dane entropijne, nie znacznik.
        if marker != MARKER_SOS && koniec < dane.len() && dane[koniec] != 0xFF {
            break;
        }

        let segment = Segment { marker, offset: offset_znacznika, dlugosc_calkowita: 2 + dlugosc };
        segmenty.push(segment);
        pos = offset_znacznika + 2 + dlugosc;

        if marker == MARKER_SOS {
            poczatek_skanu = Some(pos);
            break;
        }
    }

    let koniec_lancucha = pos;
    let mut skan_z_szukania = false;

    if poczatek_skanu.is_none()
        && let Some(znaleziony) = szukaj_sos(dane, koniec_lancucha) {
            poczatek_skanu = Some(znaleziony);
            skan_z_szukania = true;
        }

    AnalizaJpeg { segmenty, koniec_lancucha, poczatek_skanu, skan_z_szukania }
}

/// Szuka nagłówka `SOS` od podanego offsetu i zwraca początek danych skanu.
///
/// Przyjmowany jest pierwszy `FFDA` o sensownym polu długości. „Pierwszy" jest
/// tu istotne: pliki progresywne mają wiele segmentów `SOS`, a zachować trzeba
/// wszystkie — więc cięcie musi nastąpić przed pierwszym z nich.
fn szukaj_sos(dane: &[u8], od: usize) -> Option<usize> {
    let mut pos = od.min(dane.len());

    while pos + 3 < dane.len() {
        let wzgledny = memchr::memchr(0xFF, &dane[pos..])?;
        let i = pos + wzgledny;

        if i + 3 >= dane.len() {
            return None;
        }

        if dane[i + 1] == MARKER_SOS {
            let dlugosc = u16::from_be_bytes([dane[i + 2], dane[i + 3]]) as usize;
            // Najkrótszy sensowny SOS to 1 komponent: 2 (długość) + 1 (liczba
            // komponentów) + 2 (para na komponent) + 3 (parametry skanu).
            if dlugosc >= 6 && i + 2 + dlugosc <= dane.len() {
                return Some(i + 2 + dlugosc);
            }
        }

        pos = i + 1;
    }

    None
}

/// Odczytuje parametry ramki z pierwszego segmentu `SOF`.
///
/// Treść `SOF` to: precyzja (1 B), wysokość (2 B), szerokość (2 B), liczba
/// komponentów (1 B), a potem opis komponentów.
pub fn ramka_obrazu(dane: &[u8], analiza: &AnalizaJpeg) -> Option<RamkaObrazu> {
    let sof = analiza.segmenty.iter().copied().find(|s| jest_sof(s.marker))?;
    let (od, do_) = sof.zakres_tresci();

    if do_ > dane.len() || do_.saturating_sub(od) < 6 {
        return None;
    }

    Some(RamkaObrazu {
        marker_sof: sof.marker,
        wysokosc: u16::from_be_bytes([dane[od + 1], dane[od + 2]]),
        szerokosc: u16::from_be_bytes([dane[od + 3], dane[od + 4]]),
        komponenty: dane[od + 5],
    })
}

/// Składa sprawny JPEG z nagłówka dawcy i danych skanu pliku uszkodzonego.
///
/// Zwraca gotowe bajty wyniku. Wydzielone z [`repair`], żeby dało się testować
/// bez dotykania dysku.
///
/// # Warunki
///
/// 1. Dawca musi mieć **spójny łańcuch segmentów** aż do `SOS` oraz segmenty
///    `DQT` i `SOF`. Dawca, którego trzeba szukać po sygnaturze, jest sam
///    uszkodzony i nie nadaje się na źródło tablic.
/// 2. W pliku uszkodzonym musi dać się zlokalizować początek skanu.
/// 3. Jeśli plik uszkodzony ma czytelny `SOF`, jego tryb kodowania, wymiary i
///    liczba komponentów muszą się zgadzać z dawcą.
/// 4. Skan kopii uszkodzonej musi stanowić co najmniej
///    [`MINIMALNY_UDZIAL_SKANU`] długości skanu dawcy.
pub fn zloz_bajty(uszkodzony: &[u8], dawca: &[u8]) -> io::Result<Vec<u8>> {
    let analiza_dawcy = analizuj(dawca);

    if !analiza_dawcy.ma_soi() {
        return Err(blad(
            io::ErrorKind::InvalidData,
            "dawca nie zaczyna się znacznikiem SOI - to nie jest plik JPEG".to_string(),
        ));
    }

    if analiza_dawcy.skan_z_szukania {
        return Err(blad(
            io::ErrorKind::InvalidData,
            "u dawcy łańcuch segmentów jest zerwany przed SOS - dawca sam jest uszkodzony i nie nadaje się na źródło tablic".to_string(),
        ));
    }

    let poczatek_skanu_dawcy = analiza_dawcy.poczatek_skanu.ok_or_else(|| {
        blad(io::ErrorKind::NotFound, "dawca nie ma segmentu SOS - brak nagłówka skanu do przeszczepu".to_string())
    })?;

    if analiza_dawcy.segment(MARKER_DQT).is_none() {
        return Err(blad(
            io::ErrorKind::NotFound,
            "dawca nie ma segmentu DQT - bez tablic kwantyzacji przeszczep nie ma sensu".to_string(),
        ));
    }

    let ramka_dawcy = ramka_obrazu(dawca, &analiza_dawcy).ok_or_else(|| {
        blad(io::ErrorKind::NotFound, "dawca nie ma czytelnego segmentu SOF - brak wymiarów obrazu".to_string())
    })?;

    let analiza_uszkodzonego = analizuj(uszkodzony);
    let poczatek_skanu_uszk = analiza_uszkodzonego.poczatek_skanu.ok_or_else(|| {
        blad(
            io::ErrorKind::NotFound,
            "w pliku uszkodzonym nie udało się zlokalizować początku skanu (brak czytelnego SOS) - nie ma danych obrazu do odratowania".to_string(),
        )
    })?;

    // Punkt 3: jeśli `SOF` uszkodzonego jeszcze się czyta, musi opisywać TEN
    // SAM obraz. Rozbieżność znaczy, że to nie są kopie jednego pliku i
    // przeszczep dałby śmieci wyglądające na naprawę.
    if let Some(ramka_uszk) = ramka_obrazu(uszkodzony, &analiza_uszkodzonego) {
        if ramka_uszk.marker_sof != ramka_dawcy.marker_sof {
            return Err(blad(
                io::ErrorKind::InvalidData,
                format!(
                    "różny tryb kodowania: dawca ma SOF 0x{:02X}, plik uszkodzony 0x{:02X} - dane skanu są nieprzenośne między trybami",
                    ramka_dawcy.marker_sof, ramka_uszk.marker_sof
                ),
            ));
        }
        if ramka_uszk.szerokosc != ramka_dawcy.szerokosc
            || ramka_uszk.wysokosc != ramka_dawcy.wysokosc
            || ramka_uszk.komponenty != ramka_dawcy.komponenty
        {
            return Err(blad(
                io::ErrorKind::InvalidData,
                format!(
                    "różne wymiary obrazu: dawca {}x{} ({} komp.), plik uszkodzony {}x{} ({} komp.) - to nie są kopie tego samego zdjęcia",
                    ramka_dawcy.szerokosc, ramka_dawcy.wysokosc, ramka_dawcy.komponenty,
                    ramka_uszk.szerokosc, ramka_uszk.wysokosc, ramka_uszk.komponenty
                ),
            ));
        }
    }

    if poczatek_skanu_dawcy > dawca.len() || poczatek_skanu_uszk > uszkodzony.len() {
        return Err(blad(io::ErrorKind::InvalidData, "offset początku skanu wypada za koniec pliku".to_string()));
    }

    let dlugosc_skanu_dawcy = dawca.len() - poczatek_skanu_dawcy;
    let dlugosc_skanu_uszk = uszkodzony.len() - poczatek_skanu_uszk;

    if dlugosc_skanu_uszk == 0 {
        return Err(blad(
            io::ErrorKind::InvalidData,
            "plik uszkodzony nie ma żadnych danych za nagłówkiem SOS".to_string(),
        ));
    }

    // Punkt 4: obrona przed trafieniem w SOS osadzonej miniatury EXIF.
    let prog = (dlugosc_skanu_dawcy as f64 * MINIMALNY_UDZIAL_SKANU) as usize;
    if dlugosc_skanu_uszk < prog {
        return Err(blad(
            io::ErrorKind::InvalidData,
            format!(
                "skan pliku uszkodzonego ma {} B i jest KRÓTSZY niż wymagane {} B ({:.0}% skanu dawcy, który ma {} B) - prawdopodobnie zlokalizowano SOS osadzonej miniatury, nie zdjęcia",
                dlugosc_skanu_uszk, prog, MINIMALNY_UDZIAL_SKANU * 100.0, dlugosc_skanu_dawcy
            ),
        ));
    }

    let mut wynik = Vec::with_capacity(poczatek_skanu_dawcy + dlugosc_skanu_uszk + 2);
    wynik.extend_from_slice(&dawca[..poczatek_skanu_dawcy]);
    wynik.extend_from_slice(&uszkodzony[poczatek_skanu_uszk..]);

    // Dekodery bywają wyrozumiałe dla braku EOI, ale plik bez znacznika końca
    // jest formalnie niedomknięty - a Faza 6 traktuje to jako uszkodzenie.
    if !wynik.ends_with(&[0xFF, MARKER_EOI]) {
        wynik.extend_from_slice(&[0xFF, MARKER_EOI]);
    }

    Ok(wynik)
}

/// Opisuje, co dokładnie zostało przeniesione — do dziennika operacyjnego.
pub fn opis_przeszczepu(uszkodzony: &[u8], dawca: &[u8]) -> String {
    let analiza = analizuj(dawca);
    let mut tablice = Vec::new();
    if analiza.segment(MARKER_DQT).is_some() { tablice.push("DQT"); }
    if analiza.segment(MARKER_DHT).is_some() { tablice.push("DHT"); }
    if analiza.segmenty.iter().any(|s| jest_sof(s.marker)) { tablice.push("SOF"); }

    let wymiary = ramka_obrazu(dawca, &analiza)
        .map(|r| format!("{}x{}", r.szerokosc, r.wysokosc))
        .unwrap_or_else(|| "nieznane".to_string());

    let analiza_uszk = analizuj(uszkodzony);
    // Offset zerwania łańcucha wskazuje, DO KTÓREGO miejsca nagłówek kopii
    // uszkodzonej był jeszcze spójny - przy analizie powtarzających się
    // uszkodzeń w korpusie to konkretna wskazówka, nie ozdoba.
    let tryb = if analiza_uszk.skan_z_szukania {
        format!(
            "SOS zlokalizowany szukaniem sygnatury (łańcuch segmentów zerwany na offsecie {})",
            analiza_uszk.koniec_lancucha
        )
    } else {
        "SOS odczytany z łańcucha segmentów".to_string()
    };

    format!(
        "przeniesiono nagłówek dawcy ({}) dla obrazu {}; dane skanu zachowane z kopii uszkodzonej; {}",
        tablice.join("+"), wymiary, tryb
    )
}

/// Składa sprawny JPEG z dwóch plików na dysku.
///
/// Wynik zapisywany jest dopiero po udanym złożeniu w pamięci, więc
/// nieudana naprawa nie zostawia pliku-widma.
pub fn repair(broken_file: &str, donor_file: &str, output_file: &str) -> io::Result<()> {
    let uszkodzony = wczytaj(Path::new(broken_file))?;
    let dawca = wczytaj(Path::new(donor_file))?;

    let wynik = zloz_bajty(&uszkodzony, &dawca)?;

    if let Some(katalog) = Path::new(output_file).parent()
        && !katalog.as_os_str().is_empty() {
            std::fs::create_dir_all(katalog)?;
        }
    std::fs::write(output_file, &wynik)?;

    Ok(())
}

/// Materiał testowy wspólny dla tego modułu i dla
/// [`crate::phases::repair_modules::jpeg`].
///
/// Trzymany w jednym miejscu świadomie: dwie kopie tych samych pomocy
/// rozjechałyby się przy pierwszej zmianie modelu uszkodzenia, a wtedy jeden z
/// zestawów testów cicho przestałby sprawdzać to, co obiecuje.
#[cfg(test)]
pub(crate) mod pomoce_testowe {
    use super::*;

    /// Generuje PRAWDZIWY plik JPEG o podanych wymiarach.
    ///
    /// Testy nie potrzebują więc fixture'a na dysku ani `#[ignore]` — materiał
    /// jest realny, bo przechodzi przez ten sam koder, którego użyje dekoder
    /// przy weryfikacji.
    pub fn zdrowy_jpeg(szer: u32, wys: u32) -> Vec<u8> {
        let mut img = image::RgbImage::new(szer, wys);
        for (x, y, px) in img.enumerate_pixels_mut() {
            // Gradient z szumem - dane o niezerowej entropii, żeby skan nie
            // skompresował się do kilku bajtów.
            *px = image::Rgb([
                (x * 7 % 256) as u8,
                (y * 11 % 256) as u8,
                ((x * y) % 256) as u8,
            ]);
        }

        let mut bajty = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut bajty, image::ImageFormat::Jpeg)
            .expect("kodowanie JPEG musi się udać");
        bajty.into_inner()
    }

    /// Niszczy obszar tablic (za `SOI`, przed `SOS`), zachowując nagłówek
    /// skanu i same dane skanu.
    ///
    /// Model uszkodzenia jest dobrany pod to, co naprawa ma umieć: zniszczone
    /// `DQT`/`DHT`/`SOF` przy nietkniętym obrazie. Dwa szczegóły są istotne:
    ///
    /// * wypełniacz **nigdy nie jest `0xFF`** — inaczej powstałby legalny ciąg
    ///   bajtów wypełniających, parser przeskoczyłby go zgodnie ze
    ///   specyfikacją i plik dalej by się parsował, więc test nie mierzyłby
    ///   ścieżki awaryjnej;
    /// * segment `SOS` zostaje **nietknięty** — jego zniszczenie odbiera
    ///   naprawie punkt zaczepienia i jest osobnym przypadkiem, sprawdzanym
    ///   przez `test_odrzuca_plik_bez_czytelnego_sos`.
    pub fn zepsuj_naglowek(zdrowy: &[u8]) -> Vec<u8> {
        let analiza = analizuj(zdrowy);
        let sos = analiza
            .segmenty
            .iter()
            .find(|s| s.marker == MARKER_SOS)
            .expect("zdrowy JPEG musi mieć SOS");

        let mut zepsuty = zdrowy.to_vec();
        for (i, b) in zepsuty[2..sos.offset].iter_mut().enumerate() {
            // Deterministyczne śmieci z zakresu 0x01..=0xFE.
            *b = (i % 254 + 1) as u8;
        }
        zepsuty
    }
}

#[cfg(test)]
mod tests {
    use super::pomoce_testowe::{zdrowy_jpeg, zepsuj_naglowek};
    use super::*;

    // ------------------------------------------------------------------
    // Rozbiór pliku
    // ------------------------------------------------------------------

    #[test]
    fn test_analizuj_zdrowy_jpeg() {
        let zdrowy = zdrowy_jpeg(64, 48);
        let analiza = analizuj(&zdrowy);

        assert!(analiza.ma_soi(), "pierwszy segment musi być SOI");
        assert!(!analiza.skan_z_szukania, "zdrowy plik nie potrzebuje ścieżki awaryjnej");
        assert!(analiza.segment(MARKER_DQT).is_some(), "JPEG musi mieć DQT");
        assert!(analiza.segment(MARKER_DHT).is_some(), "JPEG bazowy musi mieć DHT");
        assert_eq!(
            analiza.segmenty.last().map(|s| s.marker),
            Some(MARKER_SOS),
            "przejście po łańcuchu musi zatrzymać się na SOS"
        );
        assert_eq!(analiza.poczatek_skanu, Some(analiza.koniec_lancucha));
    }

    #[test]
    fn test_ramka_obrazu_czyta_wymiary() {
        let zdrowy = zdrowy_jpeg(64, 48);
        let ramka = ramka_obrazu(&zdrowy, &analizuj(&zdrowy)).expect("SOF musi być czytelny");

        assert_eq!((ramka.szerokosc, ramka.wysokosc), (64, 48));
        assert_eq!(ramka.komponenty, 3, "RGB koduje się na 3 komponenty YCbCr");
        assert!(jest_sof(ramka.marker_sof));
    }

    #[test]
    fn test_dht_nie_jest_mylone_z_sof() {
        // 0xC4 leży w zakresie 0xC0..=0xCF, ale to tablice Huffmana. Pomyłka
        // tutaj dawałaby losowe „wymiary" czytane z tablicy.
        assert!(!jest_sof(MARKER_DHT), "DHT nie jest SOF");
        assert!(!jest_sof(0xC8), "JPG (zarezerwowany) nie jest SOF");
        assert!(!jest_sof(0xCC), "DAC nie jest SOF");
        assert!(jest_sof(0xC0) && jest_sof(0xC2), "SOF0 i SOF2 są ramkami");
    }

    #[test]
    fn test_sciezka_awaryjna_znajduje_skan_w_zepsutym_naglowku() {
        let zdrowy = zdrowy_jpeg(64, 48);
        let zepsuty = zepsuj_naglowek(&zdrowy);

        let analiza = analizuj(&zepsuty);
        assert!(analiza.skan_z_szukania, "zerwany łańcuch musi uruchomić szukanie sygnatury");
        assert_eq!(
            analiza.poczatek_skanu,
            analizuj(&zdrowy).poczatek_skanu,
            "szukanie musi wskazać dokładnie ten sam początek skanu"
        );
    }

    /// Przekłamane pole długości NIE MOŻE przenieść parsera ponad `SOS`.
    ///
    /// To najbardziej podstępny wariant uszkodzenia nagłówka: zamiast zepsuć
    /// treść tablicy, przekłamuje jej *długość*. Parser idący na ślepo po
    /// łańcuchu wyląduje wtedy w środku danych skanu — a skoro szukanie
    /// awaryjne startuje od miejsca zerwania, szukałoby już ZA celem. Plik
    /// naprawialny zostałby uznany za nienaprawialny.
    #[test]
    fn test_przeklamana_dlugosc_nie_przeskakuje_ponad_sos() {
        let zdrowy = zdrowy_jpeg(96, 64);
        let analiza = analizuj(&zdrowy);
        let poczatek_skanu = analiza.poczatek_skanu.unwrap();

        // Ostatni segment przed SOS - jego długość przekłamiemy.
        let poprzedni = analiza.segmenty[analiza.segmenty.len() - 2];
        assert_ne!(poprzedni.marker, MARKER_SOS, "bierzemy segment PRZED nagłówkiem skanu");

        // Cel skoku: pierwszy bajt w danych skanu, który nie jest 0xFF (żeby
        // kontrola „za segmentem stoi znacznik" faktycznie się uruchomiła).
        let cel = (poczatek_skanu + 1..zdrowy.len())
            .find(|&i| zdrowy[i] != 0xFF)
            .expect("dane skanu muszą mieć bajt inny niż 0xFF");

        let mut podstepny = zdrowy.clone();
        let falszywa_dlugosc = (cel - poprzedni.offset - 2) as u16;
        podstepny[poprzedni.offset + 2..poprzedni.offset + 4]
            .copy_from_slice(&falszywa_dlugosc.to_be_bytes());

        let analiza_podstepna = analizuj(&podstepny);

        assert_eq!(
            analiza_podstepna.poczatek_skanu,
            Some(poczatek_skanu),
            "parser musi zatrzymać się PRZED segmentem o niespójnej długości, żeby szukanie awaryjne zaczęło się przed SOS, a nie za nim"
        );
        assert!(
            analiza_podstepna.koniec_lancucha <= poprzedni.offset,
            "łańcuch nie może objąć segmentu o przekłamanej długości (zerwanie na {}, segment na {})",
            analiza_podstepna.koniec_lancucha, poprzedni.offset
        );

        // I skutek praktyczny: taki plik nadal daje się naprawić.
        let wynik = zloz_bajty(&podstepny, &zdrowy).expect("przekłamana długość nie może blokować naprawy");
        assert!(image::load_from_memory(&wynik).is_ok(), "wynik musi się dekodować");
    }

    // ------------------------------------------------------------------
    // Przeszczep
    // ------------------------------------------------------------------

    #[test]
    fn test_przeszczep_przywraca_dekodowalny_obraz() {
        let zdrowy = zdrowy_jpeg(96, 64);
        let zepsuty = zepsuj_naglowek(&zdrowy);

        // Kontrola sensu testu: uszkodzony plik NIE MOŻE się dekodować,
        // inaczej test nie mierzyłby naprawy.
        assert!(
            image::load_from_memory(&zepsuty).is_err(),
            "plik ze zniszczonym nagłówkiem nie powinien się dekodować"
        );

        let wynik = zloz_bajty(&zepsuty, &zdrowy).expect("przeszczep od bliźniaka musi się udać");

        let obraz = image::load_from_memory(&wynik).expect("naprawiony JPEG musi się dekodować");
        assert_eq!((obraz.width(), obraz.height()), (96, 64), "wymiary muszą zostać odtworzone");

        // Najmocniejsza asercja, jaką da się tu postawić: skoro uszkodzenie
        // dotknęło WYŁĄCZNIE obszaru tablic, a przeszczep odtwarza dokładnie
        // ten obszar z bliźniaka, wynik musi być bajtowo równy oryginałowi.
        // Sam fakt „dekoduje się" tego nie dowodzi — przeszczep mógłby
        // wyprodukować czytelny, ale inny obraz.
        assert_eq!(wynik, zdrowy, "naprawa uszkodzenia samego nagłówka musi odtworzyć oryginał bajt w bajt");

        let oryginal = image::load_from_memory(&zdrowy).unwrap();
        assert_eq!(obraz.to_rgb8(), oryginal.to_rgb8(), "piksele muszą się zgadzać z oryginałem");
    }

    #[test]
    fn test_dane_skanu_pochodza_z_pliku_uszkodzonego() {
        // Dowód, że to naprawa, a nie podmiana pliku na kopię dawcy: ogon
        // wyniku musi być bajt w bajt ogonem pliku uszkodzonego.
        let zdrowy = zdrowy_jpeg(64, 48);
        let mut zepsuty = zepsuj_naglowek(&zdrowy);

        // Znacznik w danych skanu, którego dawca nie ma. Wstawiony za 0xFF00
        // nie ryzykuje utworzenia fałszywego znacznika.
        let dlugosc = zepsuty.len();
        zepsuty[dlugosc - 4] = 0x5A;

        let wynik = zloz_bajty(&zepsuty, &zdrowy).expect("przeszczep musi się udać");

        assert_eq!(wynik[wynik.len() - 4], 0x5A, "ogon wyniku musi pochodzić z kopii uszkodzonej");
        assert_ne!(
            wynik, zdrowy,
            "wynik nie może być zwykłą kopią dawcy - to byłaby podmiana, nie naprawa"
        );
    }

    #[test]
    fn test_naglowek_pochodzi_od_dawcy() {
        let zdrowy = zdrowy_jpeg(64, 48);
        let zepsuty = zepsuj_naglowek(&zdrowy);
        let poczatek = analizuj(&zdrowy).poczatek_skanu.unwrap();

        let wynik = zloz_bajty(&zepsuty, &zdrowy).unwrap();

        assert_eq!(&wynik[..poczatek], &zdrowy[..poczatek], "nagłówek musi być kopią nagłówka dawcy");
    }

    #[test]
    fn test_wynik_konczy_sie_eoi() {
        let zdrowy = zdrowy_jpeg(48, 32);
        let mut zepsuty = zepsuj_naglowek(&zdrowy);

        // Ucinamy znacznik końca - naprawa musi go dołożyć.
        zepsuty.truncate(zepsuty.len() - 2);
        assert!(!zepsuty.ends_with(&[0xFF, MARKER_EOI]));

        let wynik = zloz_bajty(&zepsuty, &zdrowy).expect("ucięty EOI nie blokuje naprawy");
        assert!(wynik.ends_with(&[0xFF, MARKER_EOI]), "wynik musi być domknięty znacznikiem EOI");
    }

    // ------------------------------------------------------------------
    // Odmowy - każda z nich chroni przed pozorną naprawą
    // ------------------------------------------------------------------

    #[test]
    fn test_odrzuca_dawce_ktory_nie_jest_jpeg() {
        let zdrowy = zdrowy_jpeg(32, 32);
        let blad = zloz_bajty(&zdrowy, b"to nie jest jpeg").unwrap_err();
        assert!(blad.to_string().contains("SOI"), "komunikat musi nazwać brakujący znacznik: {}", blad);
    }

    #[test]
    fn test_odrzuca_uszkodzonego_dawce() {
        let zdrowy = zdrowy_jpeg(32, 32);
        let zepsuty = zepsuj_naglowek(&zdrowy);

        let blad = zloz_bajty(&zepsuty, &zepsuty).unwrap_err();
        assert!(
            blad.to_string().contains("dawca sam jest uszkodzony"),
            "dawca z zerwanym łańcuchem musi być odrzucony: {}", blad
        );
    }

    #[test]
    fn test_odrzuca_rozne_wymiary() {
        let maly = zdrowy_jpeg(32, 32);
        let duzy = zdrowy_jpeg(128, 96);

        let blad = zloz_bajty(&maly, &duzy).unwrap_err();
        let tekst = blad.to_string();
        assert!(tekst.contains("różne wymiary"), "komunikat musi wskazać rozbieżność: {}", tekst);
        assert!(tekst.contains("32") && tekst.contains("128"), "komunikat musi podać oba wymiary: {}", tekst);
    }

    #[test]
    fn test_odrzuca_rozny_tryb_kodowania() {
        let zdrowy = zdrowy_jpeg(64, 48);
        let analiza = analizuj(&zdrowy);
        let sof = analiza.segmenty.iter().copied().find(|s| jest_sof(s.marker)).unwrap();

        // SOF0 (bazowy) -> SOF2 (progresywny). Dane skanu są nieprzenośne
        // między trybami, więc przeszczep dałby obraz-śmieć.
        let mut inny_tryb = zdrowy.clone();
        inny_tryb[sof.offset + 1] = 0xC2;

        let blad = zloz_bajty(&inny_tryb, &zdrowy).unwrap_err();
        assert!(
            blad.to_string().contains("różny tryb kodowania"),
            "rozbieżny SOF musi być odrzucony: {}", blad
        );
    }

    #[test]
    fn test_odrzuca_skan_miniatury() {
        // Odwzorowanie realnego zagrożenia: trafiamy w SOS osadzonej
        // miniatury, więc „skan" jest o rzędy wielkości za krótki. Bez tego
        // warunku wynik dałby się ZDEKODOWAĆ (jako podglądzik) i przeszedłby
        // weryfikację jako udana naprawa.
        let zdrowy = zdrowy_jpeg(128, 96);
        let zepsuty = zepsuj_naglowek(&zdrowy);
        let poczatek = analizuj(&zepsuty).poczatek_skanu.unwrap();

        let mut okrojony = zepsuty[..poczatek].to_vec();
        let ogon = zepsuty.len() - poczatek;
        okrojony.extend_from_slice(&zepsuty[poczatek..poczatek + ogon / 10]);

        let blad = zloz_bajty(&okrojony, &zdrowy).unwrap_err();
        let tekst = blad.to_string();
        assert!(tekst.contains("KRÓTSZY"), "komunikat musi nazwać problem: {}", tekst);
        assert!(tekst.contains("miniatury"), "komunikat musi wskazać prawdopodobną przyczynę: {}", tekst);
    }

    #[test]
    fn test_odrzuca_plik_bez_czytelnego_sos() {
        let zdrowy = zdrowy_jpeg(32, 32);
        let bez_sos = vec![0xAAu8; 4096];

        let blad = zloz_bajty(&bez_sos, &zdrowy).unwrap_err();
        assert!(
            blad.to_string().contains("nie udało się zlokalizować początku skanu"),
            "brak SOS musi dać jasny błąd: {}", blad
        );
    }

    #[test]
    fn test_odrzuca_pusty_skan() {
        let zdrowy = zdrowy_jpeg(32, 32);
        let poczatek = analizuj(&zdrowy).poczatek_skanu.unwrap();
        let bez_danych = zdrowy[..poczatek].to_vec();

        let blad = zloz_bajty(&bez_danych, &zdrowy).unwrap_err();
        let tekst = blad.to_string();
        assert!(
            tekst.contains("nie ma żadnych danych") || tekst.contains("KRÓTSZY"),
            "plik bez danych skanu musi być odrzucony: {}", tekst
        );
    }

    // ------------------------------------------------------------------
    // Warstwa plikowa
    // ------------------------------------------------------------------

    #[test]
    fn test_repair_na_plikach() {
        let dir = tempfile::tempdir().unwrap();
        let zdrowy = zdrowy_jpeg(80, 60);
        let zepsuty = zepsuj_naglowek(&zdrowy);

        let p_zepsuty = dir.path().join("uszkodzony.jpg");
        let p_dawca = dir.path().join("dawca.jpg");
        let p_wynik = dir.path().join("wyniki").join("naprawiony.jpg");

        std::fs::write(&p_zepsuty, &zepsuty).unwrap();
        std::fs::write(&p_dawca, &zdrowy).unwrap();

        repair(p_zepsuty.to_str().unwrap(), p_dawca.to_str().unwrap(), p_wynik.to_str().unwrap())
            .expect("naprawa na plikach musi się udać");

        let odczyt = std::fs::read(&p_wynik).unwrap();
        let obraz = image::load_from_memory(&odczyt).expect("zapisany plik musi się dekodować");
        assert_eq!((obraz.width(), obraz.height()), (80, 60));
    }

    #[test]
    fn test_nieudana_naprawa_nie_zapisuje_pliku() {
        let dir = tempfile::tempdir().unwrap();
        let p_zepsuty = dir.path().join("a.jpg");
        let p_dawca = dir.path().join("b.jpg");
        let p_wynik = dir.path().join("nie_powinien_istniec.jpg");

        std::fs::write(&p_zepsuty, b"smieci").unwrap();
        std::fs::write(&p_dawca, b"tez smieci").unwrap();

        assert!(repair(p_zepsuty.to_str().unwrap(), p_dawca.to_str().unwrap(), p_wynik.to_str().unwrap()).is_err());
        assert!(!p_wynik.exists(), "po nieudanej naprawie nie może zostać plik-widmo");
    }

    #[test]
    fn test_opis_przeszczepu_wymienia_przeniesione_tablice() {
        let zdrowy = zdrowy_jpeg(64, 48);
        let zepsuty = zepsuj_naglowek(&zdrowy);

        let opis = opis_przeszczepu(&zepsuty, &zdrowy);
        assert!(opis.contains("DQT"), "opis musi wymienić tablice kwantyzacji: {}", opis);
        assert!(opis.contains("64x48"), "opis musi podać wymiary: {}", opis);
        assert!(opis.contains("szukaniem sygnatury"), "opis musi ujawnić użytą ścieżkę: {}", opis);
    }

    #[test]
    fn test_limit_ramu_jest_pilnowany() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("wielki.jpg");
        std::fs::write(&plik, b"x").unwrap();

        // Nie tworzymy pliku 256 MB - sprawdzamy samą stałą i to, że bramka
        // czyta rozmiar z metadanych przed alokacją.
        assert_eq!(LIMIT_W_RAM, 256 * 1024 * 1024);
        assert!(wczytaj(&plik).is_ok(), "mały plik musi przejść bramkę limitu");
    }
}
