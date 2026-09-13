// src/mp4_repair/boxes.rs

//! Prymitywy parsowania kontenera ISOBMFF: nagłówki atomów, wyszukiwanie
//! boxów, walidacja tablic offsetów i czytelna diagnoza strukturalna.
//!
//! ## Pochodzenie
//!
//! Kod przeniesiony z modułu `mp4_moov`, który przed portem silników z
//! projektu `mp4_doctor` był jedyną obsługą MP4 w projekcie. Same prymitywy są
//! sprawne i przetestowane, więc przeżyły przebudowę. Zniknęła natomiast
//! tamtejsza logika „ożywiania" (`try_revive_with_donors` i spółka),
//! zastąpiona przez [`super::engine_clone`] — który dodatkowo PRZESUWA tablice
//! `stco`/`co64`, więc radzi sobie także gdy `mdat` wylądował pod innym
//! offsetem — oraz przez [`super::engine_native`], nieporzebujący dawcy w
//! ogóle. Weryfikację `ffmpegiem` przejął [`super::validator`], dający
//! mocniejszą gwarancję (wykrywa pliki „puste").
//!
//! [`validate_moov_offsets`] zostaje, bo to tania kontrola strukturalna
//! przydatna PRZED kosztownym dekodowaniem, a [`diagnoza_strukturalna`]
//! zamienia ją w czytelny opis dla Fazy 19.

/// Nagłówek jednego boxu ISOBMFF.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BoxInfo {
    pub box_type: [u8; 4],
    /// Offset początku boxu (łącznie z jego nagłówkiem).
    pub offset: usize,
    /// Pełny rozmiar boxu wraz z nagłówkiem.
    pub size: usize,
    /// Rozmiar samego nagłówka (8 lub 16 przy rozszerzonym rozmiarze).
    pub header_size: usize,
}

impl BoxInfo {
    pub fn type_str(&self) -> String {
        self.box_type.iter().map(|&b| b as char).collect()
    }
    /// Zakres bajtowy zawartości boxu (bez nagłówka).
    pub fn body_range(&self) -> (usize, usize) {
        (self.offset + self.header_size, self.offset + self.size)
    }
}

/// Odczytuje listę boxów najwyższego poziomu. Zatrzymuje się (bez błędu) na
/// pierwszym boxie o niespójnym rozmiarze — plik uszkodzony w tym miejscu
/// nadal ma wartościowe boxy przed nim.
pub fn parse_top_level_boxes(bytes: &[u8]) -> Vec<BoxInfo> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 8 <= bytes.len() {
        let size32 = u32::from_be_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]) as usize;
        let box_type = [bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7]];
        let (size, header_size) = if size32 == 1 {
            if offset + 16 > bytes.len() { break; }
            let big = u64::from_be_bytes([
                bytes[offset+8], bytes[offset+9], bytes[offset+10], bytes[offset+11],
                bytes[offset+12], bytes[offset+13], bytes[offset+14], bytes[offset+15],
            ]) as usize;
            (big, 16)
        } else if size32 == 0 {
            // Rozmiar 0 = box ciągnie się do końca pliku.
            (bytes.len() - offset, 8)
        } else {
            (size32, 8)
        };
        if size < header_size || offset + size > bytes.len() { break; }
        out.push(BoxInfo { box_type, offset, size, header_size });
        offset += size;
    }
    out
}

/// Znajduje box najwyższego poziomu o podanym typie.
pub fn find_box(boxes: &[BoxInfo], box_type: &[u8; 4]) -> Option<BoxInfo> {
    boxes.iter().find(|b| &b.box_type == box_type).copied()
}

/// Rekurencyjnie zbiera boxy podanego typu z zagnieżdżonej struktury
/// (`moov` → `trak` → `mdia` → `minf` → `stbl` → `stco`).
fn collect_nested(bytes: &[u8], start: usize, end: usize, target: &[u8; 4], out: &mut Vec<BoxInfo>) {
    const CONTAINERS: &[&[u8; 4]] = &[b"moov", b"trak", b"mdia", b"minf", b"stbl"];
    let mut offset = start;
    while offset + 8 <= end {
        let size32 = u32::from_be_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]) as usize;
        let box_type = [bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7]];
        let (size, header_size) = if size32 == 1 {
            if offset + 16 > end { break; }
            let big = u64::from_be_bytes([
                bytes[offset+8], bytes[offset+9], bytes[offset+10], bytes[offset+11],
                bytes[offset+12], bytes[offset+13], bytes[offset+14], bytes[offset+15],
            ]) as usize;
            (big, 16)
        } else if size32 == 0 { (end - offset, 8) } else { (size32, 8) };

        if size < header_size || offset + size > end { break; }
        let info = BoxInfo { box_type, offset, size, header_size };
        if &box_type == target { out.push(info); }
        if CONTAINERS.contains(&&box_type) {
            collect_nested(bytes, offset + header_size, offset + size, target, out);
        }
        offset += size;
    }
}

/// Wynik walidacji offsetów z `moov` względem `mdat` odbiorcy.
#[derive(Debug, Clone, PartialEq)]
pub struct OffsetValidation {
    /// Liczba sprawdzonych tablic `stco`/`co64`.
    pub tables_checked: usize,
    /// Łączna liczba offsetów chunków.
    pub total_offsets: usize,
    /// Offsety wskazujące POZA fizyczny koniec pliku odbiorcy.
    pub out_of_range: usize,
    /// Najwyższy napotkany offset — musi mieścić się w pliku.
    pub max_offset: u64,
}

impl OffsetValidation {
    pub fn is_valid(&self) -> bool {
        self.total_offsets > 0 && self.out_of_range == 0
    }
}

/// **KONTROLA nr 2:** sprawdza, czy wszystkie offsety chunków zapisane w
/// tablicach `stco`/`co64` dawcy mieszczą się w pliku wynikowym.
///
/// To wyłapuje przeszczep z INNEGO nagrania (offsety wskazują w próżnię),
/// zanim w ogóle sięgniemy po kosztowną weryfikację `ffmpegiem`.
pub fn validate_moov_offsets(moov_bytes: &[u8], result_file_size: usize) -> OffsetValidation {
    let mut stco_boxes = Vec::new();
    collect_nested(moov_bytes, 0, moov_bytes.len(), b"stco", &mut stco_boxes);
    let mut co64_boxes = Vec::new();
    collect_nested(moov_bytes, 0, moov_bytes.len(), b"co64", &mut co64_boxes);

    let mut total_offsets = 0usize;
    let mut out_of_range = 0usize;
    let mut max_offset = 0u64;
    let tables_checked = stco_boxes.len() + co64_boxes.len();

    for b in &stco_boxes {
        let (body_start, body_end) = b.body_range();
        // 4 bajty wersji/flag, potem liczba wpisów, potem offsety po 4 bajty.
        if body_start + 8 > body_end { continue; }
        let count = u32::from_be_bytes([
            moov_bytes[body_start+4], moov_bytes[body_start+5],
            moov_bytes[body_start+6], moov_bytes[body_start+7],
        ]) as usize;
        for i in 0..count {
            let p = body_start + 8 + i * 4;
            if p + 4 > body_end { break; }
            let off = u32::from_be_bytes([moov_bytes[p], moov_bytes[p+1], moov_bytes[p+2], moov_bytes[p+3]]) as u64;
            total_offsets += 1;
            max_offset = max_offset.max(off);
            if off as usize >= result_file_size { out_of_range += 1; }
        }
    }
    for b in &co64_boxes {
        let (body_start, body_end) = b.body_range();
        if body_start + 8 > body_end { continue; }
        let count = u32::from_be_bytes([
            moov_bytes[body_start+4], moov_bytes[body_start+5],
            moov_bytes[body_start+6], moov_bytes[body_start+7],
        ]) as usize;
        for i in 0..count {
            let p = body_start + 8 + i * 8;
            if p + 8 > body_end { break; }
            let off = u64::from_be_bytes([
                moov_bytes[p], moov_bytes[p+1], moov_bytes[p+2], moov_bytes[p+3],
                moov_bytes[p+4], moov_bytes[p+5], moov_bytes[p+6], moov_bytes[p+7],
            ]);
            total_offsets += 1;
            max_offset = max_offset.max(off);
            if off as usize >= result_file_size { out_of_range += 1; }
        }
    }

    OffsetValidation { tables_checked, total_offsets, out_of_range, max_offset }
}

// ============================================================================
// ROZMIAR DANYCH `mdat` (odczyt po nagłówkach, bez wczytywania pliku)
// ============================================================================

/// Odczytuje rozmiar DANYCH atomu `mdat` (bez nagłówka), przewijając łańcuch
/// atomów najwyższego poziomu.
///
/// Czyta wyłącznie 8-16-bajtowe nagłówki i przeskakuje treść, więc działa na
/// plikach dowolnej wielkości bez wczytywania ich do pamięci. Zastąpiło
/// poprzedni `check_mdat_size_match`, który do porównania dwóch nagrań wymagał
/// trzymania OBU filmów w RAM naraz.
///
/// Obsługuje rozszerzony rozmiar 64-bitowy (`size == 1`) oraz atom sięgający
/// do końca pliku (`size == 0`). Zwraca `None`, gdy `mdat` nie występuje albo
/// łańcuch atomów jest uszkodzony.
pub fn rozmiar_danych_mdat(plik: &std::path::Path) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};

    let mut f = std::fs::File::open(plik).ok()?;
    let dlugosc = f.metadata().ok()?.len();

    let mut offset: u64 = 0;
    let mut naglowek = [0u8; 16];

    while offset + 8 <= dlugosc {
        f.seek(SeekFrom::Start(offset)).ok()?;
        if f.read(&mut naglowek[..8]).ok()? < 8 {
            break;
        }

        let rozmiar32 = u32::from_be_bytes([naglowek[0], naglowek[1], naglowek[2], naglowek[3]]) as u64;
        let mut typ = [0u8; 4];
        typ.copy_from_slice(&naglowek[4..8]);

        let (rozmiar, dlugosc_naglowka) = if rozmiar32 == 1 {
            // Rozszerzony rozmiar 64-bitowy leży zaraz za typem atomu.
            f.read_exact(&mut naglowek[8..16]).ok()?;
            let duzy = u64::from_be_bytes([
                naglowek[8], naglowek[9], naglowek[10], naglowek[11],
                naglowek[12], naglowek[13], naglowek[14], naglowek[15],
            ]);
            (duzy, 16u64)
        } else if rozmiar32 == 0 {
            // Atom sięga do końca pliku.
            (dlugosc - offset, 8u64)
        } else {
            (rozmiar32, 8u64)
        };

        if rozmiar < dlugosc_naglowka || offset + rozmiar > dlugosc {
            // Uszkodzony nagłówek albo atom wychodzący za plik — dalej iść nie
            // ma sensu, bo łańcuch jest już niewiarygodny.
            break;
        }

        if &typ == b"mdat" {
            return Some(rozmiar - dlugosc_naglowka);
        }

        offset += rozmiar;
    }

    None
}

/// Porównuje rozmiary danych `mdat` dwóch plików — tani filtr przed próbą
/// przeszczepu atomu `moov`.
///
/// `moov` zawiera tablice czasu i indeksy próbek opisujące KONKRETNĄ treść
/// `mdat`. Przeszczep od dawcy będącego innym nagraniem daje plik, który
/// wygląda na spójny, ale sypie się przy dekodowaniu. Identyczny rozmiar
/// `mdat` to mocna przesłanka, że to dwa odzyski TEGO SAMEGO materiału.
///
/// Zwraca `None`, gdy w którymkolwiek pliku nie udało się odnaleźć `mdat` —
/// wywołujący powinien wtedy PRÓBOWAĆ DALEJ, bo brak odpowiedzi nie jest
/// odpowiedzią przeczącą. Ostateczne rozstrzygnięcie daje i tak obowiązkowa
/// weryfikacja wyniku (pełne dekodowanie klatek).
pub fn rozmiary_mdat_zgodne(plik_a: &std::path::Path, plik_b: &std::path::Path) -> Option<bool> {
    let a = rozmiar_danych_mdat(plik_a)?;
    let b = rozmiar_danych_mdat(plik_b)?;
    Some(a == b)
}

// ============================================================================
// CZAS UTWORZENIA NAGRANIA (atom `mvhd`)
// ============================================================================

/// Przesunięcie epoki ISOBMFF (1904-01-01 UTC) do epoki Unix (1970-01-01 UTC).
const EPOKA_ISOBMFF_DO_UNIX: i64 = 2_082_844_800;

/// Odczytuje czas utworzenia nagrania z atomu `mvhd`, w sekundach epoki Unix.
///
/// ## Dlaczego właśnie to pole, a nie całe `mvhd`
///
/// `mvhd` niesie też `timescale`, `next_track_id` i czas modyfikacji, a `udta`
/// obok — lokalizację i dane urządzenia. Z tego zestawu do bazy warto dołożyć
/// WYŁĄCZNIE czas utworzenia: pozostałe albo dubluje Faza 12 przez exiftool
/// (lokalizacja → `has_gps`, urządzenie → `media_device`), albo nie mają
/// samodzielnej wartości śledczej (`timescale`, `next_track_id`). Jedno dobrze
/// wybrane pole jest lepsze niż pięć kolumn w większości powtarzających dane.
///
/// Wartość jest KONTENEROWA, niezależna od EXIF — przy odzysku bywa jedynym
/// ocalałym znacznikiem czasu, gdy metadane systemu plików zostały wyzerowane
/// (Faza 5 zgłasza wtedy „Utracona Data (Epoka 1970 r.)").
///
/// Zwraca `None`, gdy `mvhd` nie istnieje, wersja atomu jest nieznana, pole
/// jest zerowe (brak znacznika) albo wychodzi data sprzed 1970 — czyli
/// niewiarygodna.
pub fn czas_utworzenia(bajty: &[u8]) -> Option<i64> {
    let mut znalezione = Vec::new();
    collect_nested(bajty, 0, bajty.len(), b"mvhd", &mut znalezione);
    let mvhd = znalezione.first()?;

    let (od, do_) = mvhd.body_range();
    if do_ > bajty.len() || od >= do_ {
        return None;
    }
    let cialo = &bajty[od..do_];

    // Układ `mvhd`: wersja (1 B) + flagi (3 B), potem czas utworzenia —
    // 32-bitowy w wersji 0, 64-bitowy w wersji 1.
    let surowy: u64 = match cialo.first()? {
        0 => {
            if cialo.len() < 8 { return None; }
            u32::from_be_bytes(cialo[4..8].try_into().ok()?) as u64
        }
        1 => {
            if cialo.len() < 12 { return None; }
            u64::from_be_bytes(cialo[4..12].try_into().ok()?)
        }
        _ => return None,
    };

    if surowy == 0 {
        return None;
    }

    let unix = surowy as i64 - EPOKA_ISOBMFF_DO_UNIX;
    if unix <= 0 { None } else { Some(unix) }
}

/// Wariant [`czas_utworzenia`] operujący na pliku, z limitem pamięci.
///
/// `mvhd` leży wewnątrz `moov`, a ten bywa umieszczony na KOŃCU pliku, więc nie
/// da się go odczytać samym prefiksem — potrzebna jest całość. Powyżej
/// [`LIMIT_DIAGNOZY_W_RAM`] rezygnujemy, zamiast ryzykować OOM.
pub fn czas_utworzenia_pliku(sciezka: &std::path::Path) -> Option<i64> {
    let rozmiar = std::fs::metadata(sciezka).ok()?.len();
    if rozmiar == 0 || rozmiar > LIMIT_DIAGNOZY_W_RAM {
        return None;
    }
    czas_utworzenia(&std::fs::read(sciezka).ok()?)
}

// ============================================================================
// DIAGNOZA STRUKTURALNA (dla Fazy 19)
// ============================================================================

/// Górny limit rozmiaru pliku wczytywanego do diagnozy strukturalnej.
///
/// Diagnoza wymaga całych bajtów w pamięci, a Faza 19 przetwarza pliki
/// równolegle, więc szczyt zużycia to wielokrotność tej wartości.
pub const LIMIT_DIAGNOZY_W_RAM: u64 = 256 * 1024 * 1024; // 256 MB

/// Odczytuje główną markę kontenera (`major_brand`) z atomu `ftyp`.
///
/// Marka mówi, według którego profilu ISOBMFF plik został zapisany —
/// `isom`/`mp42` to typowe MP4, `qt  ` to QuickTime, a marki producenckie
/// (`3gp5`, `MSNV`, `avc1`) bywają charakterystyczne dla konkretnego urządzenia
/// lub oprogramowania nagrywającego. Faza 19 nie zbierała tej informacji
/// wcale, a przy identyfikacji pochodzenia materiału jest to realna wskazówka.
///
/// Zwraca `None`, gdy `ftyp` nie występuje albo jest za krótki na markę.
pub fn marka_kontenera(boxy: &[BoxInfo], bajty: &[u8]) -> Option<String> {
    let ftyp = find_box(boxy, b"ftyp")?;
    let (od, do_) = ftyp.body_range();
    if do_ > bajty.len() || do_ - od < 4 {
        return None;
    }

    let marka: String = bajty[od..od + 4]
        .iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '?' })
        .collect();

    Some(marka.trim_end().to_string())
}

/// Buduje CZYTELNY opis struktury kontenera ISOBMFF — do wzbogacenia powodu
/// uszkodzenia zgłaszanego przez Fazę 19.
///
/// ## Co to wnosi
///
/// `video_image::damage_description` zwraca ogólną kategorię („ucięty box",
/// „brak moov"). Ta funkcja mówi KONKRETNIE, co jest w pliku: które atomy
/// najwyższego poziomu istnieją, czy `moov` jest na miejscu i czy jego tablice
/// offsetów wskazują wewnątrz pliku. To właśnie ta informacja rozstrzyga, którą
/// strategię naprawy warto uruchomić w Fazie 17:
/// - brak `moov`, ale `mdat` obecny → kandydat na przeszczep albo Zero-Donor,
/// - `moov` obecny, offsety poza plikiem → plik ucięty, `mdat` niekompletny,
/// - brak `mdat` → nie ma czego ratować.
pub fn diagnoza_strukturalna(bajty: &[u8]) -> String {
    let boxy = parse_top_level_boxes(bajty);

    if boxy.is_empty() {
        return "Brak czytelnych atomów ISOBMFF - plik nie jest kontenerem MP4 albo jest zniszczony od pierwszych bajtów".to_string();
    }

    let obecne: Vec<String> = boxy.iter().map(|b| b.type_str()).collect();
    let mut czesci = vec![format!("atomy: {}", obecne.join(", "))];

    if let Some(marka) = marka_kontenera(&boxy, bajty) {
        czesci.push(format!("marka: {}", marka));
    }

    let mdat = find_box(&boxy, b"mdat");
    let moov = find_box(&boxy, b"moov");

    match (&moov, &mdat) {
        (None, Some(m)) => {
            let (od, do_) = m.body_range();
            czesci.push(format!(
                "BRAK atomu moov, ale mdat obecny ({} B, dane {}..{}) - kandydat na przeszczep lub odbudowę Zero-Donor",
                m.size, od, do_
            ));
        }
        (Some(_), None) => {
            czesci.push("moov obecny, ale BRAK mdat - nie ma surowych danych do odratowania".to_string());
        }
        (None, None) => {
            czesci.push("brak zarówno moov, jak i mdat - tą drogą nie ma czego odzyskać".to_string());
        }
        (Some(mv), Some(_)) => {
            let (od, do_) = mv.body_range();
            let dane_moov = &bajty[od.min(bajty.len())..do_.min(bajty.len())];
            let walidacja = validate_moov_offsets(dane_moov, bajty.len());

            if walidacja.is_valid() {
                czesci.push(format!(
                    "moov i mdat obecne, wszystkie {} offsetów mieści się w pliku",
                    walidacja.total_offsets
                ));
            } else {
                czesci.push(format!(
                    "moov obecny, ale {} z {} offsetów wskazuje POZA plik - dane mdat są niekompletne (plik ucięty)",
                    walidacja.out_of_range, walidacja.total_offsets
                ));
            }
        }
    }

    czesci.join("; ")
}

/// Czy kontener ma SPÓJNĄ STRUKTURĘ: obecne `moov` i `mdat`, a wszystkie
/// offsety z tablic `stco`/`co64` mieszczą się w pliku.
///
/// To NIE jest dowód, że plik się odtworzy — offsety mogą mieścić się w pliku i
/// wskazywać na niewłaściwe bajty. Jest to jednak najmocniejsza kontrola
/// dostępna BEZ `ffmpeg`, używana jako awaryjna weryfikacja naprawy MP4 na
/// maszynach bez tej binarki (patrz `repair_modules::mp4`). Gwarancja jest tam
/// jawnie oznaczana jako SŁABA.
pub fn struktura_kontenera_poprawna(bajty: &[u8]) -> bool {
    let boxy = parse_top_level_boxes(bajty);

    let Some(mv) = find_box(&boxy, b"moov") else { return false };
    if find_box(&boxy, b"mdat").is_none() {
        return false;
    }

    let (od, do_) = mv.body_range();
    if od >= bajty.len() || do_ > bajty.len() {
        return false;
    }

    validate_moov_offsets(&bajty[od..do_], bajty.len()).is_valid()
}

/// Wariant [`struktura_kontenera_poprawna`] operujący na pliku, z limitem
/// pamięci. Zwraca `None`, gdy pliku nie da się wczytać w limicie.
pub fn struktura_kontenera_poprawna_pliku(sciezka: &std::path::Path) -> Option<bool> {
    let rozmiar = std::fs::metadata(sciezka).ok()?.len();
    if rozmiar == 0 || rozmiar > LIMIT_DIAGNOZY_W_RAM {
        return None;
    }
    let bajty = std::fs::read(sciezka).ok()?;
    Some(struktura_kontenera_poprawna(&bajty))
}

/// Wariant [`diagnoza_strukturalna`] operujący na pliku, z limitem pamięci.
///
/// Zwraca `None`, gdy plik jest pusty, przekracza [`LIMIT_DIAGNOZY_W_RAM`] albo
/// nie da się go odczytać — wywołujący zostaje wtedy przy ogólnym opisie
/// uszkodzenia.
pub fn diagnoza_strukturalna_pliku(sciezka: &std::path::Path) -> Option<String> {
    let rozmiar = std::fs::metadata(sciezka).ok()?.len();
    if rozmiar == 0 || rozmiar > LIMIT_DIAGNOZY_W_RAM {
        return None;
    }
    let bajty = std::fs::read(sciezka).ok()?;
    Some(diagnoza_strukturalna(&bajty))
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Buduje minimalny box ISOBMFF: rozmiar (BE) + typ + zawartość.
    fn make_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let size = (8 + payload.len()) as u32;
        let mut out = size.to_be_bytes().to_vec();
        out.extend_from_slice(box_type);
        out.extend_from_slice(payload);
        out
    }

    /// Buduje tablicę `stco` z podanymi offsetami chunków.
    fn make_stco(offsets: &[u32]) -> Vec<u8> {
        let mut body = vec![0u8; 4]; // wersja + flagi
        body.extend_from_slice(&(offsets.len() as u32).to_be_bytes());
        for &o in offsets { body.extend_from_slice(&o.to_be_bytes()); }
        make_box(b"stco", &body)
    }

    /// Owija `stco` w pełną hierarchię moov/trak/mdia/minf/stbl.
    fn make_moov_with_offsets(offsets: &[u32]) -> Vec<u8> {
        let stco = make_stco(offsets);
        let stbl = make_box(b"stbl", &stco);
        let minf = make_box(b"minf", &stbl);
        let mdia = make_box(b"mdia", &minf);
        let trak = make_box(b"trak", &mdia);
        make_box(b"moov", &trak)
    }

    fn make_mp4(mdat_size: usize, moov_offsets: &[u32]) -> Vec<u8> {
        let mut out = make_box(b"ftyp", b"isomiso2avc1mp41");
        out.extend(make_box(b"mdat", &vec![0xAAu8; mdat_size]));
        out.extend(make_moov_with_offsets(moov_offsets));
        out
    }

    // ------------------------------------------------------------------
    // parse_top_level_boxes
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Test na PRAWDZIWYCH plikach - wymaga ffmpega do wygenerowania
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_finds_all_top_level_boxes() {
        let mp4 = make_mp4(100, &[48]);
        let boxes = parse_top_level_boxes(&mp4);
        let types: Vec<String> = boxes.iter().map(|b| b.type_str()).collect();
        assert_eq!(types, vec!["ftyp", "mdat", "moov"]);
    }

    #[test]
    fn test_parse_stops_at_inconsistent_size() {
        let mut mp4 = make_mp4(100, &[48]);
        // Deklarujemy absurdalny rozmiar drugiego boxu
        let ftyp_size = parse_top_level_boxes(&mp4)[0].size;
        mp4[ftyp_size..ftyp_size + 4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        let boxes = parse_top_level_boxes(&mp4);
        assert_eq!(boxes.len(), 1, "Powinien zatrzymać się przed niespójnym boxem");
    }

    #[test]
    fn test_parse_handles_empty_and_short_input() {
        assert!(parse_top_level_boxes(b"").is_empty());
        assert!(parse_top_level_boxes(b"abc").is_empty());
    }

    #[test]
    fn test_find_box_locates_by_type() {
        let boxes = parse_top_level_boxes(&make_mp4(100, &[48]));
        assert!(find_box(&boxes, b"mdat").is_some());
        assert!(find_box(&boxes, b"moov").is_some());
        assert!(find_box(&boxes, b"xxxx").is_none());
    }

    #[test]
    fn test_validate_offsets_accepts_in_range() {
        let moov = make_moov_with_offsets(&[48, 100, 200]);
        let v = validate_moov_offsets(&moov, 1000);
        assert_eq!(v.total_offsets, 3);
        assert_eq!(v.out_of_range, 0);
        assert_eq!(v.max_offset, 200);
        assert!(v.is_valid());
    }

    #[test]
    fn test_validate_offsets_rejects_out_of_range() {
        // Offsety wskazujące poza plik = dawca z innego nagrania.
        let moov = make_moov_with_offsets(&[48, 5000, 9000]);
        let v = validate_moov_offsets(&moov, 1000);
        assert_eq!(v.out_of_range, 2);
        assert!(!v.is_valid());
    }

    #[test]
    fn test_validate_offsets_finds_nested_stco() {
        // stco leży 5 poziomów głęboko - parser musi tam dotrzeć.
        let moov = make_moov_with_offsets(&[48]);
        let v = validate_moov_offsets(&moov, 1000);
        assert_eq!(v.tables_checked, 1, "Musi znaleźć zagnieżdżoną tablicę stco");
    }

    #[test]
    fn test_validate_offsets_empty_moov_is_invalid() {
        let empty = make_box(b"moov", b"");
        let v = validate_moov_offsets(&empty, 1000);
        assert_eq!(v.total_offsets, 0);
        assert!(!v.is_valid(), "moov bez tablic offsetów nie może być uznany za poprawny");
    }

    // ------------------------------------------------------------------
    // Diagnoza strukturalna (dla Fazy 19)
    // ------------------------------------------------------------------

    #[test]
    fn test_diagnoza_wykrywa_brak_moov() {
        // mdat obecny, moov brak - kandydat na przeszczep / Zero-Donor.
        let mut plik = make_box(b"ftyp", b"isom\x00\x00\x02\x00");
        plik.extend(make_box(b"mdat", &[0xAA; 64]));

        let opis = diagnoza_strukturalna(&plik);
        assert!(opis.contains("BRAK atomu moov"), "dostałem: {}", opis);
        assert!(opis.contains("kandydat"), "opis musi podpowiadać strategię: {}", opis);
        assert!(opis.contains("marka: isom"), "marka z ftyp musi trafić do opisu: {}", opis);
    }

    #[test]
    fn test_diagnoza_wykrywa_brak_mdat() {
        let mut plik = make_box(b"ftyp", b"mp42\x00\x00\x00\x00");
        plik.extend(make_moov_with_offsets(&[48]));

        let opis = diagnoza_strukturalna(&plik);
        assert!(opis.contains("BRAK mdat"), "dostałem: {}", opis);
    }

    #[test]
    fn test_diagnoza_wykrywa_offsety_poza_plikiem() {
        // moov i mdat obecne, ale offsety wskazują daleko za koniec pliku.
        let plik = make_mp4(64, &[50_000, 60_000]);

        let opis = diagnoza_strukturalna(&plik);
        assert!(opis.contains("POZA plik"), "dostałem: {}", opis);
        assert!(opis.contains("ucięty"), "opis musi nazwać skutek: {}", opis);
    }

    #[test]
    fn test_diagnoza_zdrowego_pliku_nie_alarmuje() {
        let plik = make_mp4(200, &[48]);
        let opis = diagnoza_strukturalna(&plik);
        assert!(opis.contains("mieści się w pliku"), "dostałem: {}", opis);
        assert!(!opis.contains("POZA plik"));
    }

    #[test]
    fn test_diagnoza_smieci_nie_udaje_ze_zna_strukture() {
        let opis = diagnoza_strukturalna(b"to zupelnie nie jest kontener mp4");
        assert!(opis.contains("Brak czytelnych atomów"), "dostałem: {}", opis);
    }

    #[test]
    fn test_marka_kontenera_odporna_na_bajty_niedrukowalne() {
        let plik = make_box(b"ftyp", &[0x00, 0xFF, b'p', b'4', 0, 0, 0, 0]);
        let boxy = parse_top_level_boxes(&plik);
        let marka = marka_kontenera(&boxy, &plik).expect("ftyp jest obecny");
        assert_eq!(marka, "??p4", "Bajty niedrukowalne muszą być zastąpione, nie wysypać odczytu");
    }

    #[test]
    fn test_marka_kontenera_none_bez_ftyp() {
        let plik = make_box(b"mdat", &[0u8; 16]);
        let boxy = parse_top_level_boxes(&plik);
        assert!(marka_kontenera(&boxy, &plik).is_none());
    }

    // ------------------------------------------------------------------
    // rozmiar_danych_mdat / rozmiary_mdat_zgodne
    // ------------------------------------------------------------------

    #[test]
    fn test_rozmiar_danych_mdat_czyta_po_naglowkach() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("a.mp4");
        std::fs::write(&plik, make_mp4(256, &[48])).unwrap();

        assert_eq!(rozmiar_danych_mdat(&plik), Some(256));
    }

    #[test]
    fn test_rozmiar_danych_mdat_none_bez_mdat() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("bez.mp4");
        std::fs::write(&plik, make_moov_with_offsets(&[48])).unwrap();

        assert!(rozmiar_danych_mdat(&plik).is_none());
    }

    #[test]
    fn test_rozmiary_mdat_zgodne_rozpoznaje_ten_sam_material() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.mp4");
        let b = dir.path().join("b.mp4");
        let c = dir.path().join("c.mp4");

        std::fs::write(&a, make_mp4(512, &[48])).unwrap();
        std::fs::write(&b, make_mp4(512, &[48])).unwrap();
        std::fs::write(&c, make_mp4(999, &[48])).unwrap();

        assert_eq!(rozmiary_mdat_zgodne(&a, &b), Some(true), "ten sam rozmiar mdat");
        assert_eq!(rozmiary_mdat_zgodne(&a, &c), Some(false), "inny rozmiar = inne nagranie");
    }

    /// Brak odpowiedzi NIE jest odpowiedzią przeczącą — wywołujący ma wtedy
    /// próbować dalej, a nie rezygnować.
    #[test]
    fn test_rozmiary_mdat_none_gdy_nie_da_sie_odczytac() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.mp4");
        std::fs::write(&a, make_mp4(128, &[48])).unwrap();
        let brak = dir.path().join("nie_ma.mp4");

        assert_eq!(rozmiary_mdat_zgodne(&a, &brak), None);
    }

    // ------------------------------------------------------------------
    // struktura_kontenera_poprawna — awaryjna weryfikacja bez ffmpeg
    //
    // To NIE jest dowód odtwarzalności (offsety mogą mieścić się w pliku i
    // wskazywać na niewłaściwe bajty), ale najmocniejsza kontrola dostępna bez
    // zewnętrznej binarki. Moduły MP4 oznaczają ją jawnie jako gwarancję SŁABĄ.
    // ------------------------------------------------------------------

    #[test]
    fn test_struktura_przyjmuje_spojny_kontener() {
        assert!(struktura_kontenera_poprawna(&make_mp4(200, &[48])));
    }

    #[test]
    fn test_struktura_odrzuca_offsety_poza_plikiem() {
        // moov i mdat są, ale tablice adresów wskazują daleko za koniec pliku —
        // dane mdat są niekompletne.
        assert!(!struktura_kontenera_poprawna(&make_mp4(64, &[50_000])));
    }

    #[test]
    fn test_struktura_odrzuca_brak_moov() {
        let mut plik = make_box(b"ftyp", b"isom\x00\x00\x02\x00");
        plik.extend(make_box(b"mdat", &[0xAA; 64]));
        assert!(!struktura_kontenera_poprawna(&plik));
    }

    #[test]
    fn test_struktura_odrzuca_brak_mdat() {
        let mut plik = make_box(b"ftyp", b"mp42\x00\x00\x00\x00");
        plik.extend(make_moov_with_offsets(&[48]));
        assert!(!struktura_kontenera_poprawna(&plik));
    }

    #[test]
    fn test_struktura_odrzuca_smieci() {
        assert!(!struktura_kontenera_poprawna(b"to zupelnie nie jest kontener mp4"));
        assert!(!struktura_kontenera_poprawna(b""));
    }

    #[test]
    fn test_struktura_pliku_odrzuca_pusty_i_nieistniejacy() {
        let dir = tempfile::tempdir().unwrap();

        let pusty = dir.path().join("pusty.mp4");
        std::fs::write(&pusty, b"").unwrap();
        assert_eq!(struktura_kontenera_poprawna_pliku(&pusty), None, "pusty plik = brak odpowiedzi");

        assert_eq!(struktura_kontenera_poprawna_pliku(&dir.path().join("nie_ma.mp4")), None);
    }

    #[test]
    fn test_struktura_pliku_zgadza_sie_z_wariantem_na_bajtach() {
        let dir = tempfile::tempdir().unwrap();

        let dobry = dir.path().join("dobry.mp4");
        std::fs::write(&dobry, make_mp4(256, &[48])).unwrap();
        assert_eq!(struktura_kontenera_poprawna_pliku(&dobry), Some(true));

        let zly = dir.path().join("zly.mp4");
        std::fs::write(&zly, make_mp4(64, &[99_000])).unwrap();
        assert_eq!(struktura_kontenera_poprawna_pliku(&zly), Some(false));
    }

    // ------------------------------------------------------------------
    // czas_utworzenia (mvhd)
    // ------------------------------------------------------------------

    /// Buduje `moov` z atomem `mvhd` o podanym czasie utworzenia.
    fn make_moov_z_mvhd(czas_isobmff: u64, wersja: u8) -> Vec<u8> {
        let mut cialo = vec![wersja, 0, 0, 0]; // wersja + flagi
        if wersja == 0 {
            cialo.extend_from_slice(&(czas_isobmff as u32).to_be_bytes());
            cialo.extend_from_slice(&0u32.to_be_bytes());  // czas modyfikacji
            cialo.extend_from_slice(&1000u32.to_be_bytes()); // timescale
            cialo.extend_from_slice(&5000u32.to_be_bytes()); // duration
        } else {
            cialo.extend_from_slice(&czas_isobmff.to_be_bytes());
            cialo.extend_from_slice(&0u64.to_be_bytes());
            cialo.extend_from_slice(&1000u32.to_be_bytes());
            cialo.extend_from_slice(&5000u64.to_be_bytes());
        }
        make_box(b"moov", &make_box(b"mvhd", &cialo))
    }

    /// 2022-11-29 09:00:12 UTC w epoce Unix.
    const PRZYKLAD_UNIX: i64 = 1_669_712_412;

    #[test]
    fn test_czas_utworzenia_wersja0() {
        let czas_isobmff = (PRZYKLAD_UNIX + 2_082_844_800) as u64;
        let plik = make_moov_z_mvhd(czas_isobmff, 0);

        assert_eq!(czas_utworzenia(&plik), Some(PRZYKLAD_UNIX));
    }

    #[test]
    fn test_czas_utworzenia_wersja1_64bit() {
        let czas_isobmff = (PRZYKLAD_UNIX + 2_082_844_800) as u64;
        let plik = make_moov_z_mvhd(czas_isobmff, 1);

        assert_eq!(czas_utworzenia(&plik), Some(PRZYKLAD_UNIX), "wariant 64-bitowy musi dać ten sam wynik");
    }

    #[test]
    fn test_czas_utworzenia_odrzuca_zero() {
        // Zero w mvhd znaczy „brak znacznika", nie rok 1904.
        assert_eq!(czas_utworzenia(&make_moov_z_mvhd(0, 0)), None);
        assert_eq!(czas_utworzenia(&make_moov_z_mvhd(0, 1)), None);
    }

    #[test]
    fn test_czas_utworzenia_odrzuca_date_sprzed_1970() {
        // Wartość mniejsza niż przesunięcie epok daje datę sprzed 1970 —
        // niewiarygodną przy nagraniu cyfrowym.
        assert_eq!(czas_utworzenia(&make_moov_z_mvhd(1000, 0)), None);
    }

    #[test]
    fn test_czas_utworzenia_odrzuca_nieznana_wersje() {
        assert_eq!(czas_utworzenia(&make_moov_z_mvhd(2_082_845_800, 7)), None);
    }

    #[test]
    fn test_czas_utworzenia_none_bez_mvhd() {
        assert_eq!(czas_utworzenia(&make_mp4(128, &[48])), None, "make_mp4 nie zawiera mvhd");
        assert_eq!(czas_utworzenia(b"smieci"), None);
        assert_eq!(czas_utworzenia(b""), None);
    }

    #[test]
    fn test_czas_utworzenia_znajduje_mvhd_zagnieżdżone_w_moov() {
        // mvhd jest dzieckiem moov, nie atomem najwyższego poziomu — parser
        // musi tam zejść.
        let mut plik = make_box(b"ftyp", b"isom\x00\x00\x02\x00");
        plik.extend(make_box(b"mdat", &[0u8; 32]));
        plik.extend(make_moov_z_mvhd((PRZYKLAD_UNIX + 2_082_844_800) as u64, 0));

        assert_eq!(czas_utworzenia(&plik), Some(PRZYKLAD_UNIX));
    }

    /// Weryfikacja na PRAWDZIWYM pliku z telefonu: nazwa pliku niesie datę
    /// nagrania, więc odczyt z `mvhd` musi się z nią zgadzać. To niezależne
    /// potwierdzenie zarówno parsowania atomu, jak i konwersji epoki 1904→1970.
    #[test]
    #[ignore = "Wymaga image/test_fixture.mp4. Uruchom z --ignored."]
    fn test_czas_utworzenia_na_prawdziwym_pliku() {
        let bajty = std::fs::read(crate::sciezka_fixture("test_fixture.mp4"))
            .expect("fixture image/test_fixture.mp4 musi istnieć");

        let czas = czas_utworzenia(&bajty).expect("prawdziwe nagranie ma znacznik czasu w mvhd");

        // 2022-11-29 09:00:12 UTC — zgodnie z nazwą pliku źródłowego
        // `2022-11-29_09.00.12.mp4`, z którego fixture pochodzi.
        assert_eq!(czas, 1_669_712_412, "odczyt musi zgadzać się z datą w nazwie nagrania");
    }
}
