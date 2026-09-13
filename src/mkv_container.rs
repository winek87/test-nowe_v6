// src/mkv_container.rs

//! # Diagnostyka Kontenerów Matroska (MKV/WebM/MKA)
//!
//! Czysty Rust (crate `matroska`) — **zero zależności systemowych**, w
//! odróżnieniu od `heic_image` (wymaga `libheif` + `libclang`).
//!
//! ## Odporność zweryfikowana empirycznie PRZED napisaniem tego modułu
//!
//! Program `mkv_probe` uruchomiony na docelowej maszynie potwierdził, że
//! `matroska` zwraca **bezpieczny `Err` na wszystkich testowanych
//! uszkodzeniach** (śmieci, pusty bufor, ucięty nagłówek EBML, absurdalny
//! rozmiar elementu) — **żadnej paniki**. Dlatego ten moduł NIE potrzebuje
//! maszynerii `catch_unwind` + flagi panic hooka, którą musiał dostać
//! `raw_image` po tym, jak `rawloader` spanikował na prawdziwym pliku.
//!
//! Gdyby to założenie kiedyś padło (jak przy `rawloader`), objawem będzie
//! zniszczony ekran TUI w trakcie skanowania — wtedy trzeba dodać ochronę
//! wzorowaną na `raw_image` i dopisać moduł do listy w `logging.rs`.
//!
//! ## Co ten moduł WERYFIKUJE, a czego NIE
//!
//! Sukces oznacza spójność **struktury kontenera EBML/Matroska** (nagłówek,
//! segment, tablice ścieżek) — **NIE** poprawność samych klatek wideo.
//! Pełne dekodowanie H.264/VP9 wymagałoby `ffmpeg`, świadomie pominięte —
//! ta sama klasa gwarancji co `video_image` dla MP4.

use std::path::Path;

/// Informacje o poprawnie odczytanym kontenerze Matroska.
#[derive(Debug, Clone, PartialEq)]
pub struct MkvInfo {
    /// Czas trwania w milisekundach (`None`, gdy kontener go nie deklaruje —
    /// zdarza się przy strumieniach zapisywanych na żywo).
    pub duration_ms: Option<u64>,
    pub track_count: usize,
    pub video_tracks: usize,
    pub audio_tracks: usize,
    pub subtitle_tracks: usize,
    /// Identyfikatory kodeków (np. `V_MPEG4/ISO/AVC`, `A_AAC`) — przydatne
    /// przy ocenie, czy odzyskany plik zachował oryginalną ścieżkę.
    pub codecs: Vec<String>,
    /// Aplikacja, która utworzyła plik — bywa jedynym śladem pochodzenia
    /// przy plikach bez metadanych EXIF.
    pub writing_app: String,
}

/// Kategoria uszkodzenia kontenera Matroska, wywiedziona z komunikatu
/// crate'a. Wzorce potwierdzone empirycznie przez `mkv_probe` na docelowej
/// maszynie (nie zgadywane z dokumentacji).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkvDamage {
    /// Plik urywa się w trakcie odczytu struktury — klasyczny objaw ucięcia
    /// przy kopiowaniu/odzysku. Komunikat: "failed to fill whole buffer".
    Truncated,
    /// Struktura EBML jest obecna, ale wewnętrznie niespójna (błędne
    /// identyfikatory lub rozmiary elementów). Obejmuje też przypadek
    /// FAŁSZYWEGO ROZSZERZENIA — plik `.mkv`, który w rzeczywistości jest
    /// innym formatem (zaobserwowane na prawdziwym pliku użytkownika:
    /// M4V nazwany `.mkv` dał "invalid element ID").
    InvalidStructure,
    /// Inne uszkodzenie.
    Other,
}

/// Klasyfikuje komunikat błędu (już zlowercase'owany).
pub fn classify_mkv_error(err_lower: &str) -> MkvDamage {
    if err_lower.contains("fill whole buffer") || err_lower.contains("unexpected eof") {
        MkvDamage::Truncated
    } else if err_lower.contains("invalid element") || err_lower.contains("invalid id") {
        MkvDamage::InvalidStructure
    } else {
        MkvDamage::Other
    }
}

/// Opis kategorii po polsku — do zapisania w bazie i pokazania użytkownikowi.
pub fn damage_description(damage: MkvDamage) -> &'static str {
    match damage {
        MkvDamage::Truncated => "Plik ucięty - struktura Matroska urywa się przed końcem",
        MkvDamage::InvalidStructure => "Niespójna struktura EBML - uszkodzenie lub fałszywe rozszerzenie (plik nie jest Matroską)",
        MkvDamage::Other => "Uszkodzona struktura kontenera Matroska",
    }
}

/// Rozpoznaje rozszerzenia rodziny Matroska. WebM to podzbiór Matroski
/// (ten sam kontener, ograniczony zestaw kodeków), więc obsługiwany tym
/// samym parserem.
pub fn is_mkv_extension(path_str: &str) -> bool {
    let lower = path_str.to_lowercase();
    lower.ends_with(".mkv") || lower.ends_with(".webm") || lower.ends_with(".mka")
}

// ============================================================================
// KONTROLA KOMPLETNOŚCI SEGMENTU
// ============================================================================

const ID_NAGLOWKA_EBML: u64 = 0x1A45_DFA3;
const ID_SEGMENTU: u64 = 0x1853_8067;

/// Ile bajtów początku pliku wystarczy, żeby odczytać nagłówek EBML i nagłówek
/// `Segment`. W praktyce to kilkadziesiąt bajtów; 256 daje zapas przy zerowym
/// koszcie.
const BAJTOW_DO_KONTROLI: usize = 256;

/// Wynik kontroli kompletności elementu `Segment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KompletnoscSegmentu {
    /// Zadeklarowany koniec `Segment` mieści się w pliku.
    Kompletny,
    /// `Segment` deklaruje więcej bajtów, niż plik zawiera — dowód ucięcia.
    Uciety { brakuje: u64 },
    /// Nie da się rozstrzygnąć: `Segment` ma rozmiar „nieznany" (tak zapisują
    /// się strumienie na żywo) albo początek pliku nie daje się sparsować.
    /// **Nie jest to orzeczenie o uszkodzeniu** — po prostu brak dowodu.
    Nieokreslona,
}

/// Czyta liczbę zmiennej długości (VINT) EBML od pozycji `p`.
///
/// Zwraca `(wartość, długość_w_bajtach, czy_rozmiar_nieznany)`. Dla
/// identyfikatorów (`jako_rozmiar = false`) bity znacznika są **zachowane**,
/// bo identyfikator EBML to dosłownie te bajty. Dla rozmiarów znacznik jest
/// usuwany, a ustawienie wszystkich bitów wartości oznacza rozmiar nieznany.
fn czytaj_vint(dane: &[u8], p: usize, jako_rozmiar: bool) -> Option<(u64, usize, bool)> {
    let pierwszy = *dane.get(p)?;
    if pierwszy == 0 {
        // VINT dłuższy niż 8 bajtów - niedozwolony w EBML.
        return None;
    }

    let dlugosc = pierwszy.leading_zeros() as usize + 1;
    if dlugosc > 8 || p + dlugosc > dane.len() {
        return None;
    }

    if !jako_rozmiar {
        let mut wartosc = 0u64;
        for i in 0..dlugosc {
            wartosc = (wartosc << 8) | dane[p + i] as u64;
        }
        return Some((wartosc, dlugosc, false));
    }

    let maska = 0x80u8 >> (dlugosc - 1);
    let bity_wartosci = pierwszy & (maska - 1);
    let mut wartosc = bity_wartosci as u64;
    let mut nieznany = bity_wartosci == maska - 1;

    for i in 1..dlugosc {
        wartosc = (wartosc << 8) | dane[p + i] as u64;
        nieznany = nieznany && dane[p + i] == 0xFF;
    }

    Some((wartosc, dlugosc, nieznany))
}

/// Sprawdza, czy element `Segment` sięga tak daleko, jak deklaruje.
///
/// ## Po co to istnieje
///
/// `matroska::open` czyta nagłówek EBML, `Info` i `Tracks` — wszystkie leżące
/// na POCZĄTKU pliku. Plik ucięty w ogonie ma je nietknięte, więc parsował się
/// bez zarzutu i Faza 19 orzekała `video_ok = true`. Zmierzone na
/// `image/test_fixture_mkv_truncated.mkv` (Matroska przycięta do 60% długości):
/// zgłaszała 2 ścieżki i pełne 2023 ms czasu trwania, mimo braku 21 950 bajtów.
///
/// Ucięcie ogona to najczęstszy typ uszkodzenia przy odzysku danych, a
/// orzeczenie „sprawny" wyklucza plik z naprawy w Fazie 17 i pozwala mu wygrać
/// w Fazie 9. Ta kontrola zamyka dziurę tą samą techniką, jakiej reszta
/// projektu używa do kontenerów: porównaniem zadeklarowanego rozmiaru z
/// faktycznym (jak `boxes::rozmiary_mdat_zgodne` dla ISOBMFF).
///
/// ## Czego NIE zgłasza
///
/// Nadmiar bajtów za `Segment` (`koniec < rozmiar_pliku`) **nie** jest
/// uszkodzeniem — Matroska dopuszcza wiele segmentów w jednym pliku, więc
/// dalsze bajty mogą być całkowicie legalne.
pub fn sprawdz_kompletnosc_segmentu(dane: &[u8], rozmiar_pliku: u64) -> KompletnoscSegmentu {
    let Some((id, dl_id, _)) = czytaj_vint(dane, 0, false) else { return KompletnoscSegmentu::Nieokreslona };
    if id != ID_NAGLOWKA_EBML {
        return KompletnoscSegmentu::Nieokreslona;
    }

    let Some((rozmiar_naglowka, dl_rozm, nieznany)) = czytaj_vint(dane, dl_id, true) else {
        return KompletnoscSegmentu::Nieokreslona;
    };
    if nieznany {
        return KompletnoscSegmentu::Nieokreslona;
    }

    // Przeskakujemy treść nagłówka EBML - interesuje nas element za nim.
    let Some(po_naglowku) = (dl_id + dl_rozm).checked_add(rozmiar_naglowka as usize) else {
        return KompletnoscSegmentu::Nieokreslona;
    };

    let Some((id_seg, dl_id_seg, _)) = czytaj_vint(dane, po_naglowku, false) else {
        return KompletnoscSegmentu::Nieokreslona;
    };
    if id_seg != ID_SEGMENTU {
        return KompletnoscSegmentu::Nieokreslona;
    }

    let Some((rozmiar_seg, dl_rozm_seg, nieznany_seg)) = czytaj_vint(dane, po_naglowku + dl_id_seg, true) else {
        return KompletnoscSegmentu::Nieokreslona;
    };
    if nieznany_seg {
        // Strumień zapisywany na żywo - rozmiar z definicji nieznany.
        return KompletnoscSegmentu::Nieokreslona;
    }

    let poczatek_tresci = (po_naglowku + dl_id_seg + dl_rozm_seg) as u64;
    let Some(zadeklarowany_koniec) = poczatek_tresci.checked_add(rozmiar_seg) else {
        return KompletnoscSegmentu::Nieokreslona;
    };

    if zadeklarowany_koniec > rozmiar_pliku {
        KompletnoscSegmentu::Uciety { brakuje: zadeklarowany_koniec - rozmiar_pliku }
    } else {
        KompletnoscSegmentu::Kompletny
    }
}

// ============================================================================
// SKŁADANIE Z DWÓCH KOPII (CRC-32 ELEMENTU JAKO SĘDZIA)
// ============================================================================

/// Identyfikator elementu `CRC-32` (EBML).
const ID_CRC32: u64 = 0xBF;

/// Element najwyższego poziomu wewnątrz `Segment`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementSegmentu {
    pub id: u64,
    /// Offset bajtu rozpoczynającego identyfikator elementu.
    pub offset: usize,
    /// Pełna długość: identyfikator + pole rozmiaru + treść.
    pub dlugosc_calkowita: usize,
    /// Czy element mieści się w buforze (jego zadeklarowany koniec nie
    /// wykracza poza dane).
    pub spojny: bool,
    /// Wynik kontroli `CRC-32`. `None` oznacza, że element nie niesie sumy —
    /// tak jest np. dla `Void`, a także w plikach z muxerów, które CRC nie
    /// zapisują.
    pub crc_ok: Option<bool>,
}

/// Sprawdza `CRC-32` elementu nadrzędnego.
///
/// W Matrosce suma, gdy występuje, jest **pierwszym dzieckiem** elementu
/// nadrzędnego, ma 4 bajty zapisane little-endian i pokrywa **całą pozostałą
/// treść** tego elementu. Zweryfikowane na prawdziwym pliku: wszystkie 6 sum w
/// `image/test_fixture.mkv` zgadza się co do bitu przy tej interpretacji.
///
/// Zwraca `None`, gdy element nie zaczyna się od `CRC-32` — brak sumy nie jest
/// błędem, tylko brakiem dowodu.
fn sprawdz_crc_elementu(dane: &[u8], tresc_od: usize, koniec: usize) -> Option<bool> {
    let (id, dl_id, _) = czytaj_vint(dane, tresc_od, false)?;
    if id != ID_CRC32 {
        return None;
    }

    let (rozmiar, dl_rozm, _) = czytaj_vint(dane, tresc_od + dl_id, true)?;
    if rozmiar != 4 {
        return None;
    }

    let od = tresc_od + dl_id + dl_rozm;
    let dane_crc = dane.get(od..od + 4)?;
    let zapisany = u32::from_le_bytes([dane_crc[0], dane_crc[1], dane_crc[2], dane_crc[3]]);

    let reszta = dane.get(od + 4..koniec)?;
    Some(crate::png_repair::crc32(reszta) == zapisany)
}

/// Rozbiera plik na elementy najwyższego poziomu wewnątrz `Segment`.
///
/// Zwraca `(offset_treści_segmentu, deklarowany_rozmiar_segmentu, elementy)`.
/// Przejście kończy się na pierwszym elemencie, który nie mieści się w danych —
/// taki element trafia na listę oznaczony `spojny = false`, żeby indeksy obu
/// kopii dało się zestawić ze sobą.
pub fn dzieci_segmentu(dane: &[u8]) -> Option<(usize, u64, Vec<ElementSegmentu>)> {
    let (id, dl_id, _) = czytaj_vint(dane, 0, false)?;
    if id != ID_NAGLOWKA_EBML {
        return None;
    }
    let (rozmiar_naglowka, dl_rozm, nieznany) = czytaj_vint(dane, dl_id, true)?;
    if nieznany {
        return None;
    }

    let po_naglowku = (dl_id + dl_rozm).checked_add(rozmiar_naglowka as usize)?;
    let (id_seg, dl_id_seg, _) = czytaj_vint(dane, po_naglowku, false)?;
    if id_seg != ID_SEGMENTU {
        return None;
    }
    let (rozmiar_seg, dl_rozm_seg, nieznany_seg) = czytaj_vint(dane, po_naglowku + dl_id_seg, true)?;
    if nieznany_seg {
        return None;
    }

    let tresc_od = po_naglowku + dl_id_seg + dl_rozm_seg;
    let deklarowany_koniec = (tresc_od as u64).checked_add(rozmiar_seg)? as usize;

    let mut elementy = Vec::new();
    let mut p = tresc_od;

    while p < deklarowany_koniec {
        let Some((eid, dle, _)) = czytaj_vint(dane, p, false) else { break };
        let Some((rozm, dlr, niezn)) = czytaj_vint(dane, p + dle, true) else { break };
        if niezn {
            break;
        }

        let tresc = p + dle + dlr;
        let Some(koniec) = tresc.checked_add(rozm as usize) else { break };
        let spojny = koniec <= dane.len();

        elementy.push(ElementSegmentu {
            id: eid,
            offset: p,
            dlugosc_calkowita: koniec - p,
            spojny,
            crc_ok: if spojny { sprawdz_crc_elementu(dane, tresc, koniec) } else { None },
        });

        if !spojny {
            break;
        }
        p = koniec;
    }

    Some((tresc_od, rozmiar_seg, elementy))
}

/// Czy element nadaje się do przepisania do wyniku.
fn uzyteczny(e: &ElementSegmentu) -> bool {
    e.spojny && e.crc_ok != Some(false)
}

/// Składa jedną poprawną Matroskę z dwóch uszkodzonych kopii, wybierając NA
/// POZIOMIE KAŻDEGO ELEMENTU `Segment` tę stronę, której `CRC-32` się zgadza.
///
/// ## Dlaczego to w ogóle działa
///
/// EBML sam z siebie nie ma sum kontrolnych, ale Matroska definiuje opcjonalny
/// element `CRC-32` dla elementów nadrzędnych — i muxery go zapisują (w
/// `image/test_fixture.mkv` mają go wszystkie elementy poza `Void`). Daje to
/// **obiektywnego sędziego per element**, dokładnie jak CRC32 chunka w PNG, a
/// nie samą heurystykę spójności.
///
/// ## Dlaczego offsety zostają poprawne
///
/// `SeekHead` i `Cues` przechowują POZYCJE bezwzględne wewnątrz `Segment`.
/// Wynik składamy zachowując **kolejność i rozmiary** wszystkich elementów, a
/// obie kopie pochodzą z tego samego pliku, więc ich układ był identyczny —
/// żaden offset się nie przesuwa. To ta sama zasada, na której stoi przeszczep
/// HEIC (`heic_clone`).
///
/// ## Kiedy odmawia
///
/// - któraś strona nie ma czytelnego nagłówka EBML albo `Segment`,
/// - kopie deklarują różny rozmiar `Segment` lub różny układ nagłówka (to nie
///   są dwa odzyski tego samego pliku),
/// - na tej samej pozycji stoją elementy o różnych identyfikatorach lub
///   długościach (struktury się rozjechały — nie realignujemy),
/// - TEN SAM element jest niezdatny po OBU stronach.
pub fn splice_mkv(bytes_a: &[u8], bytes_b: &[u8]) -> Option<Vec<u8>> {
    let (tresc_a, rozmiar_a, dzieci_a) = dzieci_segmentu(bytes_a)?;
    let (tresc_b, rozmiar_b, dzieci_b) = dzieci_segmentu(bytes_b)?;

    if tresc_a != tresc_b || rozmiar_a != rozmiar_b {
        return None;
    }
    if dzieci_a.is_empty() && dzieci_b.is_empty() {
        return None;
    }

    // Nagłówek bierzemy ze strony A - obie sparsowały się identycznie, co
    // właśnie sprawdziliśmy porównaniem offsetu treści i rozmiaru `Segment`.
    let mut wynik = bytes_a.get(..tresc_a)?.to_vec();

    let ile = dzieci_a.len().max(dzieci_b.len());
    for i in 0..ile {
        let a = dzieci_a.get(i);
        let b = dzieci_b.get(i);

        if let (Some(ea), Some(eb)) = (a, b)
            && (ea.id != eb.id || ea.dlugosc_calkowita != eb.dlugosc_calkowita)
        {
            return None;
        }

        let wybrany = match (a, b) {
            (Some(ea), _) if uzyteczny(ea) => (ea, bytes_a),
            (_, Some(eb)) if uzyteczny(eb) => (eb, bytes_b),
            _ => return None,
        };

        let (e, zrodlo) = wybrany;
        wynik.extend_from_slice(zrodlo.get(e.offset..e.offset + e.dlugosc_calkowita)?);
    }

    Some(wynik)
}

/// Czy WSZYSTKIE elementy `Segment`, które niosą `CRC-32`, mają go zgodnego.
///
/// Zwraca `None`, gdy plik nie daje się rozebrać albo żaden element nie niesie
/// sumy — wtedy nie ma czego sprawdzać i nie wolno udawać dowodu.
pub fn wszystkie_crc_zgodne(dane: &[u8]) -> Option<bool> {
    let (_, _, dzieci) = dzieci_segmentu(dane)?;

    let z_suma: Vec<&ElementSegmentu> = dzieci.iter().filter(|e| e.crc_ok.is_some()).collect();
    if z_suma.is_empty() {
        return None;
    }

    Some(z_suma.iter().all(|e| e.crc_ok == Some(true)) && dzieci.iter().all(|e| e.spojny))
}

/// Wczytuje początek pliku na potrzeby kontroli kompletności.
fn przeczytaj_prefiks(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut plik = std::fs::File::open(path)?;
    let mut bufor = vec![0u8; BAJTOW_DO_KONTROLI];
    let odczytane = plik.read(&mut bufor)?;
    bufor.truncate(odczytane);
    Ok(bufor)
}

fn extract_info(m: matroska::Matroska) -> MkvInfo {
    use matroska::Tracktype;
    let mut video = 0usize;
    let mut audio = 0usize;
    let mut subtitle = 0usize;
    let mut codecs = Vec::new();

    for t in &m.tracks {
        match t.tracktype {
            Tracktype::Video => video += 1,
            Tracktype::Audio => audio += 1,
            Tracktype::Subtitle => subtitle += 1,
            _ => {}
        }
        if !codecs.contains(&t.codec_id) {
            codecs.push(t.codec_id.clone());
        }
    }

    MkvInfo {
        duration_ms: m.info.duration.map(|d| d.as_millis() as u64),
        track_count: m.tracks.len(),
        video_tracks: video,
        audio_tracks: audio,
        subtitle_tracks: subtitle,
        codecs,
        writing_app: m.info.writing_app.clone(),
    }
}

/// Odczytuje strukturę kontenera z pliku na dysku.
pub fn read_mkv_file(path: &Path) -> std::result::Result<MkvInfo, MkvDamage> {
    match matroska::open(path) {
        Ok(m) => {
            // Parser czyta tylko początek pliku, więc ucięcie ogona przechodzi
            // mu niezauważone - patrz [`sprawdz_kompletnosc_segmentu`].
            if let Ok(rozmiar) = std::fs::metadata(path).map(|m| m.len())
                && let Ok(prefiks) = przeczytaj_prefiks(path)
                && let KompletnoscSegmentu::Uciety { .. } = sprawdz_kompletnosc_segmentu(&prefiks, rozmiar)
            {
                return Err(MkvDamage::Truncated);
            }
            Ok(extract_info(m))
        }
        Err(e) => Err(classify_mkv_error(&e.to_string().to_lowercase())),
    }
}

/// Wariant [`read_mkv_file`] operujący na buforze w pamięci.
///
/// To pierwszy stopień OBOWIĄZKOWEJ WERYFIKACJI PO NAPRAWIE dla `.mkv`,
/// `.webm` i `.mka`: `phases::repair_modules::weryfikuj_naprawiony_plik`
/// najpierw żąda odczytu struktury przez tę funkcję, a dopiero potem sprawdza
/// sumy przez [`wszystkie_crc_zgodne`]. Broni wyniku modułu `mkv_clone` oraz
/// wyników ślepego `splice`, który bez tej gałęzi przechodził bez oporu.
pub fn read_mkv_bytes(bytes: &[u8]) -> std::result::Result<MkvInfo, MkvDamage> {
    match matroska::Matroska::open(std::io::Cursor::new(bytes.to_vec())) {
        Ok(m) => {
            // Ta sama kontrola co w [`read_mkv_file`] - tu nawet tańsza, bo
            // cały bufor jest już w pamięci.
            if let KompletnoscSegmentu::Uciety { .. } =
                sprawdz_kompletnosc_segmentu(bytes, bytes.len() as u64)
            {
                return Err(MkvDamage::Truncated);
            }
            Ok(extract_info(m))
        }
        Err(e) => Err(classify_mkv_error(&e.to_string().to_lowercase())),
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // classify_mkv_error - wzorce potwierdzone empirycznie przez mkv_probe
    // ------------------------------------------------------------------

    #[test]
    fn test_classify_truncated() {
        assert_eq!(classify_mkv_error("failed to fill whole buffer"), MkvDamage::Truncated);
        assert_eq!(classify_mkv_error("unexpected eof reading segment"), MkvDamage::Truncated);
    }

    #[test]
    fn test_classify_invalid_structure() {
        // Dokładnie ten komunikat zaobserwowano na prawdziwym pliku M4V
        // nazwanym .mkv oraz przy absurdalnym rozmiarze elementu.
        assert_eq!(classify_mkv_error("invalid element id"), MkvDamage::InvalidStructure);
        assert_eq!(classify_mkv_error("invalid element size"), MkvDamage::InvalidStructure);
    }

    #[test]
    fn test_classify_unknown_falls_back_to_other() {
        assert_eq!(classify_mkv_error("jakis zupelnie inny blad"), MkvDamage::Other);
    }

    #[test]
    fn test_damage_description_never_empty() {
        for d in [MkvDamage::Truncated, MkvDamage::InvalidStructure, MkvDamage::Other] {
            assert!(!damage_description(d).is_empty());
        }
    }

    // ------------------------------------------------------------------
    // Odporność na uszkodzone dane (potwierdzona przez mkv_probe: brak panik)
    // ------------------------------------------------------------------

    #[test]
    fn test_read_garbage_is_classified_not_panic() {
        assert!(read_mkv_bytes(b"to na pewno nie jest plik Matroska").is_err());
    }

    #[test]
    fn test_read_empty_buffer_is_error() {
        assert!(read_mkv_bytes(b"").is_err());
    }

    #[test]
    fn test_read_truncated_ebml_header_is_truncated() {
        // Poprawny magiczny nagłówek EBML, ale plik urywa się natychmiast.
        let ebml: &[u8] = &[0x1A, 0x45, 0xDF, 0xA3, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_mkv_bytes(ebml), Err(MkvDamage::Truncated));
    }

    #[test]
    fn test_read_nonexistent_file_is_error() {
        assert!(read_mkv_file(Path::new("/na/pewno/nie/ma/takiego.mkv")).is_err());
    }

    // ------------------------------------------------------------------
    // is_mkv_extension
    // ------------------------------------------------------------------

    #[test]
    fn test_is_mkv_extension_recognizes_matroska_family() {
        assert!(is_mkv_extension("film.mkv"));
        assert!(is_mkv_extension("FILM.MKV"));
        assert!(is_mkv_extension("klip.webm"));
        assert!(is_mkv_extension("audio.mka"));
    }

    #[test]
    fn test_is_mkv_extension_excludes_other_containers() {
        assert!(!is_mkv_extension("film.mp4"));
        assert!(!is_mkv_extension("film.avi"));
        assert!(!is_mkv_extension("strumien.ts"));
    }

    // ------------------------------------------------------------------
    // Prawdziwy plik MKV - fixture wygenerowany ffmpegiem
    // ------------------------------------------------------------------

    #[test]
    #[ignore = "Wymaga prawdziwego pliku MKV jako fixture. Wygeneruj go poleceniem: \
                ffmpeg -f lavfi -i testsrc=duration=2:size=320x240:rate=10 \
                -f lavfi -i sine=frequency=440:duration=2 -c:v libx264 -preset ultrafast \
                -c:a aac -shortest -y image/test_fixture_real.mkv \
                Potem uruchom: `cargo test read_real_mkv_fixture -- --ignored --nocapture`."]
    fn test_read_real_mkv_fixture() {
        let info = read_mkv_file(Path::new("image/test_fixture_real.mkv"))
            .expect("Prawdziwy plik MKV powinien się odczytać");
        assert!(info.track_count > 0);
        println!("✔ Odczytano MKV: {} ścieżek ({} wideo, {} audio, {} napisy)",
            info.track_count, info.video_tracks, info.audio_tracks, info.subtitle_tracks);
        println!("  Czas: {:?} ms | Kodeki: {:?}", info.duration_ms, info.codecs);
        println!("  Zapisane przez: {}", info.writing_app);
    }

    // ------------------------------------------------------------------
    // Kontrola kompletności Segmentu
    // ------------------------------------------------------------------

    /// Buduje minimalny początek pliku Matroska: nagłówek EBML plus nagłówek
    /// `Segment` deklarujący `rozmiar_segmentu` (`None` = rozmiar nieznany).
    fn naglowek_mkv(rozmiar_segmentu: Option<u32>) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x1A, 0x45, 0xDF, 0xA3]);
        b.push(0x84); // VINT 1-bajtowy, wartość 4
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(&[0x18, 0x53, 0x80, 0x67]);
        match rozmiar_segmentu {
            Some(r) => {
                b.push(0x08); // VINT 5-bajtowy - pomieści dowolne u32
                b.extend_from_slice(&r.to_be_bytes());
            }
            None => b.push(0xFF), // rozmiar NIEZNANY (strumień na żywo)
        }
        b
    }

    #[test]
    fn test_vint_czyta_identyfikatory_i_rozmiary() {
        // Identyfikator: bity znacznika ZACHOWANE.
        assert_eq!(czytaj_vint(&[0x1A, 0x45, 0xDF, 0xA3], 0, false), Some((0x1A45DFA3, 4, false)));

        // Rozmiar: znacznik usunięty.
        assert_eq!(czytaj_vint(&[0x84], 0, true), Some((4, 1, false)));
        assert_eq!(czytaj_vint(&[0x40, 0x7F], 0, true), Some((127, 2, false)));

        // Rozmiar nieznany: wszystkie bity wartości ustawione.
        assert_eq!(czytaj_vint(&[0xFF], 0, true), Some((127, 1, true)));
        assert_eq!(czytaj_vint(&[0x7F, 0xFF], 0, true), Some((0x3FFF, 2, true)));
    }

    #[test]
    fn test_vint_odrzuca_niepoprawne_wejscie() {
        assert_eq!(czytaj_vint(&[0x00], 0, true), None, "VINT dłuższy niż 8 bajtów jest niedozwolony");
        assert_eq!(czytaj_vint(&[0x40], 0, true), None, "urwany VINT - brakuje drugiego bajtu");
        assert_eq!(czytaj_vint(&[], 0, true), None, "puste wejście");
    }

    #[test]
    fn test_segment_konczacy_sie_na_rozmiarze_pliku_jest_kompletny() {
        let naglowek = naglowek_mkv(Some(1000));
        let rozmiar = naglowek.len() as u64 + 1000;
        assert_eq!(sprawdz_kompletnosc_segmentu(&naglowek, rozmiar), KompletnoscSegmentu::Kompletny);
    }

    #[test]
    fn test_segment_wykraczajacy_za_koniec_pliku_to_uciecie() {
        let naglowek = naglowek_mkv(Some(1000));
        let rozmiar = naglowek.len() as u64 + 400;
        assert_eq!(
            sprawdz_kompletnosc_segmentu(&naglowek, rozmiar),
            KompletnoscSegmentu::Uciety { brakuje: 600 },
            "brakującą liczbę bajtów trzeba podać, nie tylko sam fakt ucięcia"
        );
    }

    /// Nadmiar bajtów za `Segment` NIE jest uszkodzeniem — Matroska dopuszcza
    /// wiele segmentów w jednym pliku.
    #[test]
    fn test_dodatkowe_bajty_za_segmentem_nie_sa_uszkodzeniem() {
        let naglowek = naglowek_mkv(Some(1000));
        let rozmiar = naglowek.len() as u64 + 5000;
        assert_eq!(sprawdz_kompletnosc_segmentu(&naglowek, rozmiar), KompletnoscSegmentu::Kompletny);
    }

    /// Strumień zapisywany na żywo deklaruje rozmiar „nieznany". Brak dowodu
    /// nie może zostać zamieniony na orzeczenie o uszkodzeniu.
    #[test]
    fn test_nieznany_rozmiar_segmentu_nie_jest_orzeczeniem() {
        assert_eq!(
            sprawdz_kompletnosc_segmentu(&naglowek_mkv(None), 10),
            KompletnoscSegmentu::Nieokreslona,
            "rozmiar nieznany znaczy „nie wiem”, nie „uszkodzony”"
        );
    }

    #[test]
    fn test_material_niebedacy_matroska_daje_brak_rozstrzygniecia() {
        for dane in [
            &b"to nie jest matroska"[..],
            &[0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70][..], // nagłówek MP4
            &[][..],
        ] {
            assert_eq!(
                sprawdz_kompletnosc_segmentu(dane, 1000),
                KompletnoscSegmentu::Nieokreslona,
                "obcy materiał nie jest uciętą Matroską - to inna kategoria"
            );
        }
    }

    // ------------------------------------------------------------------
    // Zestaw fixture'ów na dysku
    // ------------------------------------------------------------------

    /// Zdrowa Matroska musi być rozpoznana i opisana.
    ///
    /// Fixture generowany poleceniem:
    /// ```text
    /// ffmpeg -f lavfi -i "testsrc=size=320x240:rate=25:duration=2" \
    ///        -f lavfi -i "sine=frequency=440:duration=2" \
    ///        -c:v libx264 -preset ultrafast -pix_fmt yuv420p -c:a aac -shortest \
    ///        -y image/test_fixture.mkv
    /// ```
    #[test]
    #[ignore = "Wymaga image/test_fixture.mkv. Uruchom z --ignored."]
    fn test_zdrowy_fixture_mkv_jest_rozpoznany() {
        let info = read_mkv_file(Path::new("image/test_fixture.mkv"))
            .expect("zdrowa Matroska musi się odczytać");

        assert_eq!(info.track_count, 2, "ścieżka wideo + audio");
        assert_eq!(info.video_tracks, 1);
        assert_eq!(info.audio_tracks, 1);
        assert!(info.duration_ms.unwrap_or(0) > 1000, "czas trwania ~2 s: {:?}", info.duration_ms);
    }

    /// Sedno tej poprawki na PRAWDZIWYM pliku: Matroska ucięta w ogonie musi
    /// zostać wykryta, choć jej nagłówek i tablice ścieżek są nietknięte.
    ///
    /// Fixture: `image/test_fixture.mkv` przycięty do 60% długości.
    #[test]
    #[ignore = "Wymaga image/test_fixture_mkv_truncated.mkv. Uruchom z --ignored."]
    fn test_uciety_fixture_mkv_jest_wykryty() {
        let sciezka = Path::new("image/test_fixture_mkv_truncated.mkv");
        let bajty = std::fs::read(sciezka).unwrap();

        // Kontrola sensu testu: sam parser struktury NIE widzi problemu -
        // nagłówek i Tracks leżą na początku pliku i są nietknięte.
        assert!(
            matroska::Matroska::open(std::io::Cursor::new(bajty.clone())).is_ok(),
            "parser struktury musi uznać ten plik za czytelny - inaczej test nie mierzy nowej kontroli"
        );

        assert_eq!(
            read_mkv_file(sciezka), Err(MkvDamage::Truncated),
            "ucięcie ogona musi zostać wykryte przez kontrolę kompletności Segmentu"
        );
        assert_eq!(read_mkv_bytes(&bajty), Err(MkvDamage::Truncated), "ta sama ocena z bufora w pamięci");
    }

    /// Plik ze zniszczonym nagłówkiem EBML to inna kategoria niż ucięcie.
    #[test]
    #[ignore = "Wymaga image/test_fixture_mkv_header_damaged.mkv. Uruchom z --ignored."]
    fn test_fixture_ze_zniszczonym_naglowkiem_nie_jest_matroska() {
        let wynik = read_mkv_file(Path::new("image/test_fixture_mkv_header_damaged.mkv"));
        assert!(wynik.is_err(), "zniszczony nagłówek EBML musi zostać odrzucony");
        assert_ne!(wynik, Err(MkvDamage::Truncated), "to nie ucięcie, a niespójna struktura");
    }

    /// MP4 podrzucony pod rozszerzeniem `.mkv` — realny artefakt carvingu
    /// z korpusu użytkownika (H.264 720×1280 + AAC, 26 s, 20,7 MB).
    ///
    /// Plik JEST poprawnym wideo, tylko nie tym formatem, który obiecuje jego
    /// nazwa. Parser Matroski musi to odrzucić, a nie próbować interpretować.
    #[test]
    #[ignore = "Wymaga image/test_fixture_mp4_pod_mkv.mkv. Uruchom z --ignored."]
    fn test_mp4_pod_rozszerzeniem_mkv_jest_odrzucony() {
        assert!(is_mkv_extension("plik.mkv"), "kontrola: rozszerzenie kieruje do tego parsera");

        let wynik = read_mkv_file(Path::new("image/test_fixture_mp4_pod_mkv.mkv"));
        assert!(wynik.is_err(), "MP4 nie jest Matroską, niezależnie od nazwy pliku");
        assert_ne!(
            wynik, Err(MkvDamage::Truncated),
            "fałszywe rozszerzenie to niespójna struktura, nie ucięcie - kategoria ma znaczenie dla raportu"
        );
    }

    // ------------------------------------------------------------------
    // Składanie z dwóch kopii — materiał budowany bajt po bajcie
    // ------------------------------------------------------------------

    /// Zapisuje element EBML: identyfikator (surowe bajty) + rozmiar + treść.
    fn element(id: &[u8], tresc: &[u8]) -> Vec<u8> {
        let mut b = id.to_vec();
        b.push(0x08); // VINT 5-bajtowy: znacznik + 4 bajty wartości
        b.extend_from_slice(&(tresc.len() as u32).to_be_bytes());
        b.extend_from_slice(tresc);
        b
    }

    /// Treść elementu nadrzędnego poprzedzona elementem `CRC-32`.
    ///
    /// `poprawny = false` daje sumę celowo rozminiętą z danymi — dokładnie to,
    /// co składanie ma rozpoznać.
    fn tresc_z_crc(dane: &[u8], poprawny: bool) -> Vec<u8> {
        let suma = crate::png_repair::crc32(dane);
        let suma = if poprawny { suma } else { suma ^ 0xFFFF_FFFF };

        let mut b = vec![0xBF, 0x84];
        b.extend_from_slice(&suma.to_le_bytes());
        b.extend_from_slice(dane);
        b
    }

    /// Buduje plik: nagłówek EBML + `Segment` o podanych dzieciach.
    /// Każde dziecko to `(identyfikator, dane, czy_CRC_poprawny)`.
    fn zbuduj_mkv(dzieci: &[(&[u8], &[u8], bool)]) -> Vec<u8> {
        let mut zawartosc = Vec::new();
        for (id, dane, crc_ok) in dzieci {
            zawartosc.extend(element(id, &tresc_z_crc(dane, *crc_ok)));
        }

        let mut plik = element(&[0x1A, 0x45, 0xDF, 0xA3], &[0u8; 4]);
        plik.extend(element(&[0x18, 0x53, 0x80, 0x67], &zawartosc));
        plik
    }

    const ID_INFO: &[u8] = &[0x15, 0x49, 0xA9, 0x66];
    const ID_TRACKS: &[u8] = &[0x16, 0x54, 0xAE, 0x6B];
    const ID_CLUSTER: &[u8] = &[0x1F, 0x43, 0xB6, 0x75];

    #[test]
    fn test_rozbior_rozpoznaje_elementy_i_sprawdza_ich_sumy() {
        let plik = zbuduj_mkv(&[
            (ID_INFO, b"informacje", true),
            (ID_TRACKS, b"sciezki", false),
        ]);

        let (_, _, dzieci) = dzieci_segmentu(&plik).expect("plik musi się rozebrać");

        assert_eq!(dzieci.len(), 2);
        assert_eq!(dzieci[0].crc_ok, Some(true), "pierwszy element ma poprawną sumę");
        assert_eq!(dzieci[1].crc_ok, Some(false), "drugi ma sumę celowo rozminiętą");
        assert!(dzieci.iter().all(|e| e.spojny));
    }

    /// Sedno mechanizmu: o wyborze decyduje SUMA, nie kolejność stron.
    #[test]
    fn test_suma_crc_decyduje_z_ktorej_kopii_wziac_element() {
        // Ta sama struktura, ale w kopii A drugi element ma rozminiętą sumę.
        let a = zbuduj_mkv(&[(ID_INFO, b"informacje", true), (ID_TRACKS, b"sciezki", false)]);
        let b = zbuduj_mkv(&[(ID_INFO, b"informacje", true), (ID_TRACKS, b"sciezki", true)]);

        let wynik = splice_mkv(&a, &b).expect("składanie musi się udać - B ma zdrowy element");

        assert_eq!(wynik, b, "element o błędnej sumie musi zostać zastąpiony wersją z kopii B");
        assert_ne!(wynik, a);

        // I symetrycznie: gdy zepsuty jest element w B, wygrywa A.
        let wynik2 = splice_mkv(&b, &a).expect("kierunek nie ma znaczenia");
        assert_eq!(wynik2, b, "zdrowa wersja wygrywa niezależnie od tego, po której stronie leży");
    }

    #[test]
    fn test_element_zepsuty_po_obu_stronach_blokuje_skladanie() {
        let a = zbuduj_mkv(&[(ID_INFO, b"informacje", true), (ID_TRACKS, b"sciezki", false)]);
        let b = zbuduj_mkv(&[(ID_INFO, b"informacje", true), (ID_TRACKS, b"sciezki", false)]);

        assert!(
            splice_mkv(&a, &b).is_none(),
            "nie ma z czego wybrać - składanie musi odmówić, a nie zapisać uszkodzony element"
        );
    }

    /// Rozjazd układu: na tej samej pozycji stoją elementy o różnej długości.
    /// Realignowania nie próbujemy — to sygnał, że kopie nie opisują tego
    /// samego pliku, a przesunięcie zepsułoby offsety w `SeekHead`/`Cues`.
    #[test]
    fn test_rozjazd_dlugosci_elementow_blokuje_skladanie() {
        let a = zbuduj_mkv(&[(ID_INFO, b"informacje", true), (ID_TRACKS, b"sciezki", true)]);
        let b = zbuduj_mkv(&[(ID_INFO, b"informacje", true), (ID_TRACKS, b"znacznie dluzsze sciezki", true)]);

        assert!(splice_mkv(&a, &b).is_none(), "różne długości na tej samej pozycji");
    }

    #[test]
    fn test_rozjazd_identyfikatorow_blokuje_skladanie() {
        let a = zbuduj_mkv(&[(ID_INFO, b"dane", true)]);
        let b = zbuduj_mkv(&[(ID_TRACKS, b"dane", true)]);

        assert!(splice_mkv(&a, &b).is_none(), "inny identyfikator na tej samej pozycji");
    }

    /// Różny rozmiar `Segment` znaczy, że to nie są dwa odzyski tego samego
    /// pliku — nawet gdyby pierwsze elementy wyglądały identycznie.
    #[test]
    fn test_rozny_rozmiar_segmentu_blokuje_skladanie() {
        let a = zbuduj_mkv(&[(ID_INFO, b"dane", true)]);
        let b = zbuduj_mkv(&[(ID_INFO, b"dane", true), (ID_CLUSTER, b"dodatkowy element", true)]);

        assert!(
            splice_mkv(&a, &b).is_none(),
            "kopie deklarują różny rozmiar Segmentu - składanie musi odmówić"
        );
    }

    #[test]
    fn test_skladanie_zdrowej_kopii_samej_ze_soba_nic_nie_zmienia() {
        let a = zbuduj_mkv(&[(ID_INFO, b"informacje", true), (ID_TRACKS, b"sciezki", true)]);
        assert_eq!(splice_mkv(&a, &a).as_deref(), Some(a.as_slice()));
    }

    #[test]
    fn test_material_niebedacy_matroska_nie_da_sie_zlozyc() {
        assert!(splice_mkv(b"smieci", b"tez smieci").is_none());
        let a = zbuduj_mkv(&[(ID_INFO, b"dane", true)]);
        assert!(splice_mkv(&a, b"smieci").is_none(), "jedna strona nieczytelna");
    }

    #[test]
    fn test_kontrola_sum_wykrywa_rozminiecie() {
        let zdrowy = zbuduj_mkv(&[(ID_INFO, b"dane", true), (ID_TRACKS, b"wiecej", true)]);
        assert_eq!(wszystkie_crc_zgodne(&zdrowy), Some(true));

        let zepsuty = zbuduj_mkv(&[(ID_INFO, b"dane", true), (ID_TRACKS, b"wiecej", false)]);
        assert_eq!(wszystkie_crc_zgodne(&zepsuty), Some(false));

        assert_eq!(wszystkie_crc_zgodne(b"to nie matroska"), None, "brak rozbioru to brak dowodu");
    }
}
