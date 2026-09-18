// src/asf_container.rs

//! # Rozbiór i Składanie Kontenera ASF (WMV/WMA)
//!
//! ## Ten sam kształt problemu co RIFF, jeszcze prostszy
//!
//! ASF (Advanced Systems Format — kontener WMV/WMA), tak jak RIFF (patrz
//! [`crate::riff_container`]) i EBML/Matroska (patrz [`crate::mkv_container`]),
//! jest formatem KAWAŁKOWYM — płaską sekwencją samoopisujących się obiektów
//! (GUID + rozmiar + treść). W odróżnieniu od RIFF, ASF nie ma nawet
//! zewnętrznego nagłówka-koperty (`"RIFF"` + rozmiar + typ formy) — sam
//! `Header Object` jest pierwszym obiektem najwyższego poziomu, sekwencja
//! zaczyna się nim wprost od bajtu 0.
//!
//! Tak jak czysty RIFF, ASF **nie ma żadnej sumy kontrolnej per obiekt** —
//! specyfikacja Microsoftu nie przewiduje pola CRC dla obiektów najwyższego
//! poziomu. Wybór między dwiema kopiami tego samego obiektu opiera się więc
//! na tej samej heurystyce co RIFF: "czy treść nie wygląda na oczywistą
//! wydmuszkę". [`splice_asf`] jest więc ZAWSZE gwarancją SŁABĄ, bez wyjątku.
//!
//! ## Poziom ziarnistości: obiekty NAJWYŻSZEGO poziomu
//!
//! `Header Object` sam jest kontenerem (niesie w treści zagnieżdżone
//! podobiekty — Ficzę File Properties, Stream Properties itd.), ale ten
//! moduł NIE schodzi w głąb — traktuje go jako jeden nieprzezroczysty
//! obiekt najwyższego poziomu, dokładnie tak jak [`crate::riff_container`]
//! nie schodzi w głąb `LIST`. Naprawia to samo, co tamten moduł naprawia dla
//! RIFF: ucięty/uszkodzony OGON pliku (typowe przy odzysku — zwykle to
//! `Data Object`, ostatni i największy obiekt, niosący same próbki/klatki).
//!
//! ## Struktura pliku
//!
//! Sekwencja obiektów najwyższego poziomu, każdy: GUID (16 B) + rozmiar jako
//! `u64` little-endian (8 B, liczony OD POCZĄTKU tego obiektu — obejmuje
//! własny 24-bajtowy nagłówek) + treść. Bez bajtu dopełnienia (w odróżnieniu
//! od RIFF) — pola rozmiaru w ASF nie wymagają wyrównania parzystości.
//!
//! ## Uczciwe ograniczenie: ucięcie DOKŁADNIE na granicy obiektu jest ślepe
//!
//! W odróżnieniu od RIFF (zewnętrzny nagłówek niesie deklarowany rozmiar
//! CAŁEJ zawartości, więc pętla wie, ile obiektów OCZEKIWAĆ, nawet gdy
//! bufor się urwał wcześniej) ASF nie ma ŻADNEGO pola deklarującego łączną
//! liczbę/rozmiar obiektów najwyższego poziomu — pętla [`dzieci_asf`] kończy
//! się naturalnie, gdy `p == dane.len()`. Plik ucięty TUŻ PRZED kolejnym
//! obiektem (np. brakuje całego `Data Object`) wygląda więc identycznie jak
//! plik, który po prostu kończy się tam naturalnie — nie da się tego
//! rozróżnić bez zejścia w treść `Header Object` (pole "File Size" w jego
//! zagnieżdżonym `File Properties Object`), co ten moduł świadomie pomija
//! (patrz wyżej: obiekty najwyższego poziomu traktowane jako nieprzezroczyste).
//! Ucięcie W ŚRODKU obiektu (najczęstszy realny przypadek) jest wykrywane
//! normalnie — sentinel triggeruje się, gdy zadeklarowany koniec obiektu
//! wykracza poza bufor.

/// GUID nagłówka ASF (`Header Object`):
/// `{75B22630-668E-11CF-A6D9-00AA0062CE6C}`, zapisany w kolejności bajtów
/// pliku (mieszany endian GUID-a) — ta sama stała co
/// `repair_modules::mod::ASF_HEADER_GUID`, celowo zduplikowana (stały,
/// niezmienny element specyfikacji, ten sam wybór co magiczne stałe
/// RIFF/TIFF w tej sesji).
pub const ASF_HEADER_GUID: [u8; 16] = [
    0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
];

/// Czy ścieżka/rozszerzenie (z kropką, np. `.wmv`) wskazuje na kontener ASF
/// obsługiwany przez ten moduł.
pub fn is_asf_extension(path_str: &str) -> bool {
    let lower = path_str.to_lowercase();
    lower.ends_with(".wmv") || lower.ends_with(".wma")
}

/// Jeden obiekt ASF najwyższego poziomu.
#[derive(Debug, Clone, Copy)]
pub struct ObiektAsf {
    pub guid: [u8; 16],
    /// Offset bajtu rozpoczynającego GUID obiektu.
    pub offset: usize,
    /// Pełna długość: GUID (16 B) + pole rozmiaru (8 B) + treść — dokładny
    /// krok do KOLEJNEGO obiektu.
    pub dlugosc_calkowita: usize,
    /// Czy obiekt mieści się w buforze (jego zadeklarowany koniec nie
    /// wykracza poza dane).
    pub spojny: bool,
}

/// Rozbiera plik na obiekty najwyższego poziomu. Zwraca `None`, gdy plik NIE
/// zaczyna się GUID-em nagłówka ASF — to nie jest (fałszywe rozszerzenie)
/// albo w ogóle nie zaczyna się od Header Object.
///
/// Przejście kończy się na pierwszym obiekcie, którego nagłówek (GUID +
/// rozmiar) nie mieści się w danych, którego zadeklarowany rozmiar jest
/// mniejszy niż jego własny 24-bajtowy nagłówek, albo którego zadeklarowany
/// koniec przepełnia arytmetykę — KAŻDA z tych ścieżek dopisuje na listę
/// SENTINEL oznaczony `spojny = false` przed przerwaniem, ten sam wzorzec co
/// [`crate::riff_container::dzieci_riff`]/[`crate::mkv_container::dzieci_segmentu`]
/// (patrz ich dokumentacja dla pełnego uzasadnienia).
pub fn dzieci_asf(dane: &[u8]) -> Option<Vec<ObiektAsf>> {
    if dane.len() < 24 || dane[0..16] != ASF_HEADER_GUID {
        return None;
    }

    let mut obiekty = Vec::new();
    let mut p = 0usize;

    let sentinel = |p: usize| ObiektAsf {
        guid: [0; 16],
        offset: p,
        dlugosc_calkowita: dane.len().saturating_sub(p),
        spojny: false,
    };

    while p < dane.len() {
        let Some(naglowek) = dane.get(p..p + 24) else {
            obiekty.push(sentinel(p));
            break;
        };
        let guid: [u8; 16] = naglowek[0..16].try_into().unwrap();
        let rozmiar = u64::from_le_bytes(naglowek[16..24].try_into().unwrap());

        // Rozmiar musi obejmować co najmniej własny nagłówek - inaczej
        // struktura jest niespójna, nie tylko ucięta.
        if rozmiar < 24 {
            obiekty.push(sentinel(p));
            break;
        }
        let Ok(dlugosc_calkowita) = usize::try_from(rozmiar) else {
            obiekty.push(sentinel(p));
            break;
        };
        let Some(koniec) = p.checked_add(dlugosc_calkowita) else {
            obiekty.push(sentinel(p));
            break;
        };
        let spojny = koniec <= dane.len();

        obiekty.push(ObiektAsf { guid, offset: p, dlugosc_calkowita, spojny });

        if !spojny {
            break;
        }
        p = koniec;
    }

    Some(obiekty)
}

/// Czy bufor to oczywista wydmuszka: same zera albo same `0xFF`. Ten sam
/// sygnał co [`crate::riff_container`] — ASF nie ma sumy kontrolnej per
/// obiekt, więc to jedyny bezpieczny, dostępny sygnał wyboru.
fn wyglada_na_wydmuszke(bytes: &[u8]) -> bool {
    !bytes.is_empty() && (bytes.iter().all(|&b| b == 0) || bytes.iter().all(|&b| b == 0xFF))
}

/// Czy obiekt nadaje się do przepisania do wyniku: mieści się w buforze ORAZ
/// jego treść nie jest oczywistą wydmuszką.
fn uzyteczny(o: &ObiektAsf, dane: &[u8]) -> bool {
    o.spojny
        && dane
            .get(o.offset + 24..o.offset + o.dlugosc_calkowita)
            .is_some_and(|tresc| !wyglada_na_wydmuszke(tresc))
}

/// Składa jeden plik ASF z dwóch uszkodzonych kopii, wybierając NA POZIOMIE
/// KAŻDEGO OBIEKTU tę stronę, która nie wygląda na wydmuszkę — mirror
/// [`crate::riff_container::splice_riff`] 1:1 (bez osobnego porównania
/// nagłówka-koperty, bo ASF go nie ma).
///
/// ## Kiedy odmawia CAŁKOWICIE (`None`)
///
/// - któraś strona nie zaczyna się GUID-em nagłówka ASF,
/// - na tej samej pozycji stoją DWA PRAWDZIWIE sparsowane (`spojny`)
///   obiekty o różnym GUID-zie lub długości (struktury się rozjechały — nie
///   realignujemy; sentinel niekompletności jest z tego porównania
///   wykluczony, tym samym wyjątkiem co w `splice_riff`),
/// - żaden pojedynczy obiekt nie dał się złożyć.
///
/// ## Kiedy OBCINA wynik zamiast odmawiać
///
/// Gdy TEN SAM obiekt jest niezdatny po OBU stronach — ten sam wzorzec
/// "obetnij i zachowaj" co `splice_riff`/`splice_mkv`/`splice_flv`.
pub fn splice_asf(bytes_a: &[u8], bytes_b: &[u8]) -> Option<Vec<u8>> {
    let obiekty_a = dzieci_asf(bytes_a)?;
    let obiekty_b = dzieci_asf(bytes_b)?;

    if obiekty_a.is_empty() && obiekty_b.is_empty() {
        return None;
    }

    let mut wynik = Vec::new();
    let mut obiektow = 0usize;

    let ile = obiekty_a.len().max(obiekty_b.len());
    for i in 0..ile {
        let a = obiekty_a.get(i);
        let b = obiekty_b.get(i);

        if let (Some(oa), Some(ob)) = (a, b)
            && oa.spojny && ob.spojny
            && (oa.guid != ob.guid || oa.dlugosc_calkowita != ob.dlugosc_calkowita)
        {
            return None;
        }

        let wybrany = match (a, b) {
            (Some(oa), _) if uzyteczny(oa, bytes_a) => (oa, bytes_a),
            (_, Some(ob)) if uzyteczny(ob, bytes_b) => (ob, bytes_b),
            _ => break,
        };

        let (o, zrodlo) = wybrany;
        wynik.extend_from_slice(zrodlo.get(o.offset..o.offset + o.dlugosc_calkowita)?);
        obiektow += 1;
    }

    if obiektow == 0 {
        return None;
    }

    Some(wynik)
}

/// Czy WSZYSTKIE obiekty najwyższego poziomu mieszczą się w pliku (żaden
/// sentinel niekompletności). `None`, gdy plik nie ma czytelnego nagłówka
/// ASF albo nie ma ani jednego obiektu.
pub fn wszystkie_obiekty_spojne(dane: &[u8]) -> Option<bool> {
    let obiekty = dzieci_asf(dane)?;
    if obiekty.is_empty() {
        return None;
    }
    Some(obiekty.iter().all(|o| o.spojny))
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Buduje jeden obiekt ASF: GUID + rozmiar (24 + treść.len()) + treść.
    fn obiekt(guid: [u8; 16], tresc: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&guid);
        out.extend_from_slice(&((24 + tresc.len()) as u64).to_le_bytes());
        out.extend_from_slice(tresc);
        out
    }

    const DATA_OBJECT_GUID: [u8; 16] = [
        0x36, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
    ];

    /// Buduje minimalny, poprawny plik ASF: Header Object + Data Object.
    fn zbuduj_asf(tresc_danych: &[u8]) -> Vec<u8> {
        let mut plik = obiekt(ASF_HEADER_GUID, &[0xAA; 10]);
        plik.extend(obiekt(DATA_OBJECT_GUID, tresc_danych));
        plik
    }

    // ------------------------------------------------------------------
    // is_asf_extension
    // ------------------------------------------------------------------

    #[test]
    fn test_rozpoznaje_wmv_i_wma_niezaleznie_od_wielkosci_liter() {
        for p in [".wmv", ".WMV", ".wma", ".WMA", "plik.wmv", "plik.wma"] {
            assert!(is_asf_extension(p), "{} powinno być rozpoznane", p);
        }
    }

    #[test]
    fn test_nie_rozpoznaje_innych_rozszerzen() {
        for p in [".avi", ".mkv", ".mp4", ".asf"] {
            assert!(!is_asf_extension(p), "{} nie powinno być rozpoznane", p);
        }
    }

    // ------------------------------------------------------------------
    // dzieci_asf
    // ------------------------------------------------------------------

    #[test]
    fn test_parsuje_zdrowy_asf_na_dwa_obiekty() {
        let plik = zbuduj_asf(&[1, 2, 3, 4, 5]);
        let obiekty = dzieci_asf(&plik).expect("zdrowy ASF musi się sparsować");

        assert_eq!(obiekty.len(), 2, "Header + Data");
        assert_eq!(obiekty[0].guid, ASF_HEADER_GUID);
        assert_eq!(obiekty[1].guid, DATA_OBJECT_GUID);
        assert!(obiekty.iter().all(|o| o.spojny));
    }

    #[test]
    fn test_odrzuca_smieci_bez_naglowka_asf() {
        assert!(dzieci_asf(b"to nie jest ASF, tylko przypadkowe bajty!!").is_none());
    }

    #[test]
    fn test_odrzuca_zbyt_krotki_bufor() {
        assert!(dzieci_asf(&ASF_HEADER_GUID).is_none());
    }

    #[test]
    fn test_odrzuca_rozmiar_mniejszy_niz_wlasny_naglowek() {
        let mut plik = ASF_HEADER_GUID.to_vec();
        plik.extend_from_slice(&10u64.to_le_bytes()); // 10 < 24 - niespójne
        plik.extend_from_slice(&[0u8; 20]);
        let obiekty = dzieci_asf(&plik).unwrap();
        assert!(!obiekty[0].spojny);
    }

    /// Ucięcie w środku obiektu musi zostawić SENTINEL (`spojny = false`).
    #[test]
    fn test_uciecie_w_srodku_obiektu_zostawia_sentinel() {
        let plik = zbuduj_asf(&[1, 2, 3, 4, 5]);
        let ucieta = &plik[..plik.len() - 3];

        let obiekty = dzieci_asf(ucieta).unwrap();
        assert!(!obiekty.last().unwrap().spojny, "ostatni obiekt musi być oznaczony jako niespójny");
    }

    // ------------------------------------------------------------------
    // splice_asf
    // ------------------------------------------------------------------

    #[test]
    fn test_zdrowa_kopia_zlozona_sama_ze_soba_daje_oryginal() {
        let plik = zbuduj_asf(&[10, 20, 30, 40]);
        assert_eq!(splice_asf(&plik, &plik).as_deref(), Some(plik.as_slice()));
    }

    #[test]
    fn test_odmawia_gdy_obiekty_na_tej_samej_pozycji_maja_rozne_guid() {
        let a = zbuduj_asf(&[1, 2, 3, 4]);
        let mut b = a.clone();
        b[0..16].copy_from_slice(&DATA_OBJECT_GUID); // psujemy GUID pierwszego obiektu
        assert!(splice_asf(&a, &b).is_none());
    }

    /// REGRESJA (ten sam przypadek co w `splice_riff`): ucięcie DOKŁADNIE na
    /// granicy obiektu zostawia sentinel z placeholderowym GUID-em - bez
    /// wyjątku w porównaniu ten sentinel fałszywie wyglądałby jak obiekt
    /// SPRZECZNY z prawdziwym obiektem po stronie zdrowej.
    #[test]
    fn test_uciecie_dokladnie_na_granicy_obiektu_obcina_zamiast_odmawiac() {
        let zdrowe = zbuduj_asf(&[10, 20, 30, 40, 50]);
        let obiekty = dzieci_asf(&zdrowe).unwrap();
        let data = &obiekty[1];
        let ucieta = &zdrowe[..data.offset];

        let wynik = splice_asf(ucieta, &zdrowe).expect("ucięcie na granicy obiektu musi dać się obciąć, nie odrzucić w całości");
        assert_eq!(wynik, zdrowe, "brakujący obiekt musi wrócić w całości ze zdrowego bliźniaka");
    }

    /// Sedno silnika: obiekt Data wyzerowany po stronie A, zdrowy po
    /// stronie B - wynik musi wziąć zdrowe dane z B.
    #[test]
    fn test_wybiera_strone_bez_wydmuszki() {
        let zdrowe = zbuduj_asf(&[10, 20, 30, 40, 50]);
        let mut wyzerowane = zdrowe.clone();
        let obiekty = dzieci_asf(&zdrowe).unwrap();
        let data = &obiekty[1];
        for b in &mut wyzerowane[data.offset + 24..data.offset + data.dlugosc_calkowita] {
            *b = 0;
        }

        let wynik = splice_asf(&wyzerowane, &zdrowe).expect("złożenie musi się udać");
        assert_eq!(wynik, zdrowe, "wynik musi odtworzyć zdrowy oryginał");
    }

    #[test]
    fn test_obiekt_zepsuty_po_obu_stronach_obcina_wynik() {
        let zdrowe = zbuduj_asf(&[10, 20, 30, 40, 50]);
        let mut a = zdrowe.clone();
        let mut b = zdrowe.clone();
        let obiekty = dzieci_asf(&zdrowe).unwrap();
        let data = &obiekty[1];
        for buf in [&mut a, &mut b] {
            for byte in &mut buf[data.offset + 24..data.offset + data.dlugosc_calkowita] {
                *byte = 0;
            }
        }

        let wynik = splice_asf(&a, &b).expect("Header samo w sobie musi się złożyć");
        assert_eq!(wynik.len(), data.offset, "wynik musi kończyć się dokładnie tam, gdzie zaczynał się odcięty obiekt Data");
        assert_eq!(&wynik[0..16], ASF_HEADER_GUID, "jedyny złożony obiekt to Header");
    }

    #[test]
    fn test_wszystkie_obiekty_zepsute_po_obu_stronach_daje_none() {
        let zdrowe = zbuduj_asf(&[10, 20, 30]);
        let mut a = zdrowe.clone();
        let mut b = zdrowe.clone();
        let obiekty = dzieci_asf(&zdrowe).unwrap();
        for buf in [&mut a, &mut b] {
            for o in &obiekty {
                for byte in &mut buf[o.offset + 24..o.offset + o.dlugosc_calkowita] {
                    *byte = 0;
                }
            }
        }
        assert!(splice_asf(&a, &b).is_none());
    }

    // ------------------------------------------------------------------
    // wszystkie_obiekty_spojne
    // ------------------------------------------------------------------

    #[test]
    fn test_wszystkie_obiekty_spojne_na_zdrowym_pliku() {
        let plik = zbuduj_asf(&[1, 2, 3]);
        assert_eq!(wszystkie_obiekty_spojne(&plik), Some(true));
    }

    #[test]
    fn test_wszystkie_obiekty_spojne_wykrywa_uciecie() {
        let plik = zbuduj_asf(&[1, 2, 3, 4, 5]);
        let ucieta = &plik[..plik.len() - 3];
        assert_eq!(wszystkie_obiekty_spojne(ucieta), Some(false));
    }

    #[test]
    fn test_wszystkie_obiekty_spojne_na_smieciach_daje_none() {
        assert_eq!(wszystkie_obiekty_spojne(b"to nie jest ASF, tylko przypadkowe bajty!!"), None);
    }
}
