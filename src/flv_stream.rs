// src/flv_stream.rs

//! # Diagnostyka Kontenerów FLV (Flash Video)
//!
//! **ZERO ZALEŻNOŚCI ZEWNĘTRZNYCH** — struktura FLV jest na tyle prosta, że
//! pełna analiza mieści się w czystym `std`, tak jak przy `ts_stream`.
//!
//! ## Struktura (zweryfikowana empirycznie na prawdziwym pliku)
//!
//! - **Nagłówek (9 bajtów):** sygnatura `FLV`, wersja, flagi obecności
//!   audio/wideo, offset początku danych.
//! - **Łańcuch tagów:** każdy tag to 11 bajtów nagłówka (typ, rozmiar
//!   danych, znacznik czasu) + dane, a po nim **4-bajtowe pole
//!   `PreviousTagSize`**.
//!
//! ## Dlaczego FLV daje lepszą diagnostykę niż MP4
//!
//! Pole `PreviousTagSize` **musi** równać się `11 + rozmiar_danych`
//! poprzedniego tagu. To działa jak **suma kontrolna struktury**: rozjazd
//! natychmiast ujawnia uszkodzenie łańcucha, nawet gdy sam plik nadal
//! wygląda na spójny. Dodatkowo znaczniki czasu muszą rosnąć — ich cofnięcie
//! się to kolejny niezależny sygnał uszkodzenia.
//!
//! ## Ograniczenie (uczciwie)
//! To analiza WARSTWY KONTENERA, nie treści wideo — tak samo jak przy
//! `video_image`/`ts_stream`. Tag może mieć idealnie poprawny nagłówek i
//! zawierać uszkodzone dane H.264 w środku.

/// Rozmiar nagłówka pliku FLV.
const FLV_HEADER_SIZE: usize = 9;
/// Rozmiar nagłówka pojedynczego tagu (typ + rozmiar + znacznik czasu + stream ID).
const TAG_HEADER_SIZE: usize = 11;

/// Typy tagów wg specyfikacji FLV.
const TAG_TYPE_AUDIO: u8 = 8;
const TAG_TYPE_VIDEO: u8 = 9;
const TAG_TYPE_SCRIPT: u8 = 18;

/// Wynik analizy kontenera FLV.
#[derive(Debug, Clone, PartialEq)]
pub struct FlvAnalysis {
    /// Wersja formatu z nagłówka (zwykle 1).
    pub version: u8,
    /// Czy nagłówek deklaruje obecność ścieżki audio.
    pub has_audio_flag: bool,
    /// Czy nagłówek deklaruje obecność ścieżki wideo.
    pub has_video_flag: bool,
    pub audio_tags: usize,
    pub video_tags: usize,
    pub script_tags: usize,
    /// Tagi o nierozpoznanym typie — objaw uszkodzenia lub obcej struktury.
    pub unknown_tags: usize,
    /// Rozjazdy pola `PreviousTagSize` — patrz dokumentacja modułu. Każdy
    /// oznacza przerwany łańcuch tagów.
    pub chain_errors: usize,
    /// Cofnięcia znacznika czasu, liczone OSOBNO DLA KAŻDEGO TYPU STRUMIENIA.
    ///
    /// To rozróżnienie jest konieczne, nie kosmetyczne: audio i wideo to
    /// niezależne strumienie, które naturalnie się PRZEPLATAJĄ (tag audio o
    /// znaczniku 23 ms potrafi wystąpić po tagu wideo o znaczniku 46 ms i
    /// jest to całkowicie poprawne). Globalne porównywanie znaczników dawało
    /// fałszywe alarmy na zdrowych plikach — wykryte na prawdziwym pliku z
    /// ffmpega, którego syntetyczne testy nie ujawniły.
    pub timestamp_regressions: usize,
    /// Ostatni odczytany znacznik czasu w milisekundach — przybliżony czas
    /// trwania materiału, który udało się odczytać.
    pub last_timestamp_ms: u32,
    /// Bajty na końcu niepasujące do żadnego pełnego tagu — objaw ucięcia.
    pub trailing_garbage_bytes: usize,
}

impl FlvAnalysis {
    /// Czy kontener jest w pełni spójny.
    pub fn is_healthy(&self) -> bool {
        self.total_tags() > 0
            && self.chain_errors == 0
            && self.timestamp_regressions == 0
            && self.unknown_tags == 0
            && self.trailing_garbage_bytes == 0
    }

    pub fn total_tags(&self) -> usize {
        self.audio_tags + self.video_tags + self.script_tags + self.unknown_tags
    }

    /// Zwięzły opis stanu do zapisania w bazie i pokazania użytkownikowi.
    pub fn describe(&self) -> String {
        if self.total_tags() == 0 {
            return "Nagłówek FLV poprawny, ale nie znaleziono żadnych tagów (plik pusty lub ucięty tuż za nagłówkiem)".to_string();
        }
        if self.is_healthy() {
            return format!(
                "Kontener spójny: {} tagów ({} wideo, {} audio, {} skryptowych), materiał ~{:.1}s",
                self.total_tags(), self.video_tags, self.audio_tags, self.script_tags,
                self.last_timestamp_ms as f64 / 1000.0
            );
        }
        let mut parts = Vec::new();
        if self.chain_errors > 0 { parts.push(format!("{} przerwań łańcucha tagów", self.chain_errors)); }
        if self.timestamp_regressions > 0 { parts.push(format!("{} cofnięć znacznika czasu", self.timestamp_regressions)); }
        if self.unknown_tags > 0 { parts.push(format!("{} tagów nieznanego typu", self.unknown_tags)); }
        if self.trailing_garbage_bytes > 0 { parts.push(format!("{} bajtów niepełnego tagu na końcu (ucięty plik)", self.trailing_garbage_bytes)); }
        parts.join("; ")
    }
}

/// Rozpoznaje rozszerzenia Flash Video. F4V CELOWO pominięty — mimo
/// pokrewnej nazwy to kontener ISOBMFF (rodzina MP4), obsługiwany przez
/// `video_image`, nie tym parserem.
pub fn is_flv_extension(path_str: &str) -> bool {
    path_str.to_lowercase().ends_with(".flv")
}

/// Analizuje kontener FLV: weryfikuje nagłówek, przechodzi łańcuch tagów i
/// sprawdza spójność pól `PreviousTagSize` oraz monotoniczność znaczników
/// czasu. Zwraca `None`, gdy plik nie ma poprawnej sygnatury FLV.
pub fn analyze_flv(bytes: &[u8]) -> Option<FlvAnalysis> {
    if bytes.len() < FLV_HEADER_SIZE || &bytes[0..3] != b"FLV" {
        return None;
    }
    let version = bytes[3];
    let flags = bytes[4];
    let has_audio_flag = (flags & 0x04) != 0;
    let has_video_flag = (flags & 0x01) != 0;
    let data_offset = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;

    // Offset danych musi mieścić się w pliku i nie może wskazywać wstecz.
    if data_offset < FLV_HEADER_SIZE || data_offset > bytes.len() {
        return Some(FlvAnalysis {
            version, has_audio_flag, has_video_flag,
            audio_tags: 0, video_tags: 0, script_tags: 0, unknown_tags: 0,
            chain_errors: 1, timestamp_regressions: 0, last_timestamp_ms: 0,
            trailing_garbage_bytes: bytes.len().saturating_sub(FLV_HEADER_SIZE),
        });
    }

    let mut audio_tags = 0usize;
    let mut video_tags = 0usize;
    let mut script_tags = 0usize;
    let mut unknown_tags = 0usize;
    let mut chain_errors = 0usize;
    let mut timestamp_regressions = 0usize;
    let mut last_timestamp_ms = 0u32;
    // Osobny znacznik dla każdego typu strumienia - patrz dokumentacja
    // pola `timestamp_regressions`.
    let mut last_ts_per_type: std::collections::HashMap<u8, u32> = std::collections::HashMap::new();

    // Zaraz po nagłówku stoi PreviousTagSize pierwszego (nieistniejącego)
    // tagu - zawsze zero. Rozjazd tutaj to pierwszy sygnał uszkodzenia.
    let mut offset = data_offset;
    if offset + 4 <= bytes.len() {
        let first_prev = u32::from_be_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]);
        if first_prev != 0 { chain_errors += 1; }
        offset += 4;
    }

    while offset + TAG_HEADER_SIZE <= bytes.len() {
        // Górne 3 bity to flagi filtrowania/rezerwa - typ siedzi w dolnych 5.
        let tag_type = bytes[offset] & 0x1F;
        let data_size = u32::from_be_bytes([0, bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]) as usize;
        // Znacznik czasu: 3 bajty + rozszerzenie w 4. bajcie jako najstarszy.
        let ts = u32::from_be_bytes([bytes[offset + 7], bytes[offset + 4], bytes[offset + 5], bytes[offset + 6]]);

        match tag_type {
            TAG_TYPE_AUDIO => audio_tags += 1,
            TAG_TYPE_VIDEO => video_tags += 1,
            TAG_TYPE_SCRIPT => script_tags += 1,
            _ => unknown_tags += 1,
        }

        // Regresja liczona TYLKO w obrębie tego samego typu strumienia.
        let prev_ts = last_ts_per_type.entry(tag_type).or_insert(0);
        if ts < *prev_ts { timestamp_regressions += 1; }
        *prev_ts = (*prev_ts).max(ts);
        last_timestamp_ms = last_timestamp_ms.max(ts);

        let next_offset = match offset.checked_add(TAG_HEADER_SIZE).and_then(|v| v.checked_add(data_size)) {
            Some(v) => v,
            None => { chain_errors += 1; break; }
        };
        if next_offset + 4 > bytes.len() { break; }

        // KLUCZOWA WERYFIKACJA: PreviousTagSize musi równać się rozmiarowi
        // tagu, który właśnie minęliśmy - patrz dokumentacja modułu.
        let prev_tag_size = u32::from_be_bytes([
            bytes[next_offset], bytes[next_offset + 1], bytes[next_offset + 2], bytes[next_offset + 3],
        ]) as usize;
        if prev_tag_size != TAG_HEADER_SIZE + data_size {
            chain_errors += 1;
            // Łańcuch przerwany - dalsza wędrówka po offsetach nie ma sensu,
            // bo nie wiemy, gdzie faktycznie zaczyna się kolejny tag.
            offset = next_offset + 4;
            break;
        }
        offset = next_offset + 4;
    }

    Some(FlvAnalysis {
        version, has_audio_flag, has_video_flag,
        audio_tags, video_tags, script_tags, unknown_tags,
        chain_errors, timestamp_regressions, last_timestamp_ms,
        trailing_garbage_bytes: bytes.len().saturating_sub(offset),
    })
}

// ============================================================================
// SKŁADANIE Z DWÓCH KOPII (ŁAŃCUCH PreviousTagSize JAKO SĘDZIA)
// ============================================================================

/// Jeden tag zlokalizowany w buforze, wraz z domykającym go
/// `PreviousTagSize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagFlv {
    pub offset: usize,
    /// Nagłówek (11 B) + dane + `PreviousTagSize` (4 B).
    pub dlugosc_calkowita: usize,
    pub typ: u8,
}

/// Odczytuje tag stojący pod podanym offsetem i sprawdza jego spójność.
///
/// Zwraca `None`, gdy tag jest niespójny — a to znaczy jedno z trzech: typ
/// poza zbiorem zdefiniowanym w formacie, wyjście poza bufor, albo — i to jest
/// właściwy sędzia — **`PreviousTagSize` niezgodny z rozmiarem tagu**.
///
/// To pole jest redundantnym zapisem długości umieszczonym ZA każdym tagiem.
/// Jego zgodność dowodzi, że nagłówek nie jest przekłamany, bo obie wartości
/// musiałyby zostać sfałszowane spójnie.
pub fn tag_pod(bytes: &[u8], offset: usize) -> Option<TagFlv> {
    let naglowek = bytes.get(offset..offset + TAG_HEADER_SIZE)?;

    let typ = naglowek[0] & 0x1F;
    if !matches!(typ, TAG_TYPE_AUDIO | TAG_TYPE_VIDEO | TAG_TYPE_SCRIPT) {
        return None;
    }

    let rozmiar_danych = u32::from_be_bytes([0, naglowek[1], naglowek[2], naglowek[3]]) as usize;
    let po_danych = offset.checked_add(TAG_HEADER_SIZE)?.checked_add(rozmiar_danych)?;

    let pole = bytes.get(po_danych..po_danych + 4)?;
    let zapisany = u32::from_be_bytes([pole[0], pole[1], pole[2], pole[3]]) as usize;

    if zapisany != TAG_HEADER_SIZE + rozmiar_danych {
        return None;
    }

    Some(TagFlv { offset, dlugosc_calkowita: TAG_HEADER_SIZE + rozmiar_danych + 4, typ })
}

/// Zwraca offset pierwszego tagu, po nagłówku pliku i zerowym
/// `PreviousTagSize`.
pub fn poczatek_tagow(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < FLV_HEADER_SIZE || &bytes[0..3] != b"FLV" {
        return None;
    }
    let data_offset = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
    if data_offset < FLV_HEADER_SIZE || data_offset + 4 > bytes.len() {
        return None;
    }
    Some(data_offset + 4)
}

/// Składa jeden kontener z dwóch uszkodzonych kopii, wybierając NA POZIOMIE
/// KAŻDEGO TAGU tę stronę, której łańcuch `PreviousTagSize` się domyka.
///
/// ## Czym tu sędziujemy, skoro FLV nie ma sum kontrolnych
///
/// Za każdym tagiem stoi 4-bajtowe pole `PreviousTagSize` powtarzające jego
/// długość. To **redundancja wpisana w format**: rozjazd tej wartości z
/// nagłówkiem tagu dowodzi przekłamania, bo poprawne uszkodzenie musiałoby
/// zmienić spójnie dwa niezależne miejsca.
///
/// Gwarancja jest jednak **SŁABA**: dowodzimy poprawności RAMOWANIA tagów, a
/// nie zawartości klatek — tej w FLV nie ma czym sprawdzić.
///
/// ## Dlaczego scalamy po OFFSETACH, a nie po numerach tagów
///
/// Przekłamany nagłówek zabiera informację o tym, gdzie kończy się tag, więc
/// po takim tagu numeracja jednej kopii rozjeżdża się z drugą. Scalanie po
/// offsetach jest odporne na to z natury: w każdym punkcie pytamy obie kopie,
/// czy stoi tu spójny tag, i idziemy dalej o jego długość. Układ obu kopii jest
/// identyczny (to ten sam plik), więc offsety się zgadzają, a wynik zachowuje
/// je co do bajtu — istotne, bo indeks klatek kluczowych w `onMetaData`
/// przechowuje POZYCJE bezwzględne.
///
/// ## Kiedy odmawia
///
/// - któraś strona nie ma czytelnego nagłówka FLV,
/// - kopie deklarują różny offset początku danych,
/// - nie udało się złożyć ani jednego tagu.
///
/// Bajty za ostatnim spójnym tagiem są **odcinane** — to te same śmieci, które
/// `analyze_flv` raportuje jako `trailing_garbage_bytes`.
pub fn splice_flv(bytes_a: &[u8], bytes_b: &[u8]) -> Option<Vec<u8>> {
    let start_a = poczatek_tagow(bytes_a)?;
    let start_b = poczatek_tagow(bytes_b)?;
    if start_a != start_b {
        return None;
    }

    let mut wynik = bytes_a.get(..start_a)?.to_vec();
    let mut poz = start_a;
    let mut tagow = 0usize;
    let mut z_dawcy = 0usize;

    let koniec = bytes_a.len().max(bytes_b.len());
    while poz < koniec {
        let z_a = tag_pod(bytes_a, poz);
        let z_b = tag_pod(bytes_b, poz);

        let (tag, zrodlo, dawca) = match (z_a, z_b) {
            (Some(t), _) => (t, bytes_a, false),
            (None, Some(t)) => (t, bytes_b, true),
            // Żadna strona nie ma tu spójnego tagu - koniec strumienia albo
            // śmieci; jedno i drugie kończy składanie.
            (None, None) => break,
        };

        if dawca {
            z_dawcy += 1;
        }
        wynik.extend_from_slice(zrodlo.get(tag.offset..tag.offset + tag.dlugosc_calkowita)?);
        poz += tag.dlugosc_calkowita;
        tagow += 1;
    }

    if tagow == 0 {
        return None;
    }

    tracing::debug!(tagow, z_dawcy, "splice_flv: złożono kontener");
    Some(wynik)
}

/// Wariant [`analyze_flv`] operujący na pliku na dysku.
pub fn analyze_flv_file(path: &std::path::Path) -> Option<FlvAnalysis> {
    let bytes = std::fs::read(path).ok()?;
    analyze_flv(&bytes)
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Buduje pojedynczy tag FLV wraz z następującym po nim polem
    /// `PreviousTagSize` (poprawnym, chyba że `corrupt_chain`).
    fn build_tag(tag_type: u8, timestamp: u32, payload: &[u8], corrupt_chain: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(tag_type);
        let size = payload.len() as u32;
        out.extend_from_slice(&size.to_be_bytes()[1..4]);
        out.extend_from_slice(&timestamp.to_be_bytes()[1..4]);
        out.push((timestamp >> 24) as u8);
        out.extend_from_slice(&[0, 0, 0]); // StreamID, zawsze 0
        out.extend_from_slice(payload);
        let prev = if corrupt_chain { 999_999u32 } else { (TAG_HEADER_SIZE + payload.len()) as u32 };
        out.extend_from_slice(&prev.to_be_bytes());
        out
    }

    fn build_flv(tags: &[(u8, u32, usize)], corrupt_at: Option<usize>) -> Vec<u8> {
        let mut out = b"FLV".to_vec();
        out.push(1);
        out.push(0x05); // audio + wideo
        out.extend_from_slice(&9u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // pierwszy PreviousTagSize
        for (i, &(t, ts, len)) in tags.iter().enumerate() {
            out.extend(build_tag(t, ts, &vec![0xAAu8; len], corrupt_at == Some(i)));
        }
        out
    }

    // ------------------------------------------------------------------
    // Rozpoznawanie i nagłówek
    // ------------------------------------------------------------------

    #[test]
    fn test_is_flv_extension() {
        assert!(is_flv_extension("nagranie.flv"));
        assert!(is_flv_extension("NAGRANIE.FLV"));
        assert!(!is_flv_extension("film.mp4"));
        // F4V to ISOBMFF, nie FLV - obsługiwany przez inny moduł.
        assert!(!is_flv_extension("film.f4v"));
    }

    #[test]
    fn test_analyze_rejects_non_flv() {
        assert!(analyze_flv(b"to nie jest plik FLV w ogole").is_none());
        assert!(analyze_flv(b"").is_none());
        assert!(analyze_flv(b"FL").is_none());
    }

    #[test]
    fn test_analyze_reads_header_flags() {
        let flv = build_flv(&[(TAG_TYPE_VIDEO, 0, 10)], None);
        let a = analyze_flv(&flv).unwrap();
        assert_eq!(a.version, 1);
        assert!(a.has_audio_flag);
        assert!(a.has_video_flag);
    }

    // ------------------------------------------------------------------
    // Zdrowy plik
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_healthy_file() {
        let flv = build_flv(&[
            (TAG_TYPE_SCRIPT, 0, 100),
            (TAG_TYPE_VIDEO, 0, 50),
            (TAG_TYPE_AUDIO, 23, 30),
            (TAG_TYPE_VIDEO, 46, 60),
        ], None);
        let a = analyze_flv(&flv).unwrap();
        assert_eq!(a.total_tags(), 4);
        assert_eq!(a.video_tags, 2);
        assert_eq!(a.audio_tags, 1);
        assert_eq!(a.script_tags, 1);
        assert_eq!(a.chain_errors, 0);
        assert_eq!(a.timestamp_regressions, 0);
        assert_eq!(a.last_timestamp_ms, 46);
        assert_eq!(a.trailing_garbage_bytes, 0);
        assert!(a.is_healthy());
    }

    // ------------------------------------------------------------------
    // Wykrywanie uszkodzeń
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_detects_broken_chain() {
        // Drugi tag ma błędne PreviousTagSize - łańcuch przerwany.
        let flv = build_flv(&[
            (TAG_TYPE_VIDEO, 0, 50),
            (TAG_TYPE_AUDIO, 23, 30),
            (TAG_TYPE_VIDEO, 46, 60),
        ], Some(1));
        let a = analyze_flv(&flv).unwrap();
        assert!(a.chain_errors > 0, "Rozjazd PreviousTagSize musi zostać wykryty");
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_detects_timestamp_regression_within_same_stream() {
        // Znacznik cofa się z 100 na 20 W TYM SAMYM strumieniu wideo -
        // objaw pomieszanych fragmentów, prawdziwe uszkodzenie.
        let flv = build_flv(&[
            (TAG_TYPE_VIDEO, 0, 20),
            (TAG_TYPE_VIDEO, 100, 20),
            (TAG_TYPE_VIDEO, 20, 20),
        ], None);
        let a = analyze_flv(&flv).unwrap();
        assert_eq!(a.timestamp_regressions, 1);
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_ignores_interleaved_audio_video_timestamps() {
        // REGRESJA wykryta na PRAWDZIWYM pliku z ffmpega: audio i wideo to
        // niezależne strumienie, ich przeplot z "cofającymi się" znacznikami
        // jest NORMALNY. Globalne porównywanie dawało tu fałszywy alarm.
        let flv = build_flv(&[
            (TAG_TYPE_VIDEO, 0, 20),
            (TAG_TYPE_VIDEO, 46, 20),
            (TAG_TYPE_AUDIO, 23, 20),   // "cofnięcie" względem wideo - poprawne!
            (TAG_TYPE_AUDIO, 46, 20),
        ], None);
        let a = analyze_flv(&flv).unwrap();
        assert_eq!(a.timestamp_regressions, 0, "Przeplot audio/wideo nie jest regresją");
        assert!(a.is_healthy());
    }

    #[test]
    fn test_analyze_detects_unknown_tag_type() {
        let flv = build_flv(&[(TAG_TYPE_VIDEO, 0, 20), (7, 10, 20)], None);
        let a = analyze_flv(&flv).unwrap();
        assert_eq!(a.unknown_tags, 1);
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_detects_truncated_file() {
        let mut flv = build_flv(&[(TAG_TYPE_VIDEO, 0, 100), (TAG_TYPE_AUDIO, 23, 100)], None);
        flv.truncate(flv.len() - 60); // ucinamy w środku ostatniego tagu
        let a = analyze_flv(&flv).unwrap();
        assert!(a.trailing_garbage_bytes > 0, "Ucięcie musi zostać wykryte");
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_detects_bogus_data_offset() {
        let mut flv = b"FLV".to_vec();
        flv.push(1);
        flv.push(0x05);
        flv.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // absurdalny offset
        flv.extend_from_slice(&[0u8; 100]);
        let a = analyze_flv(&flv).unwrap();
        assert!(a.chain_errors > 0);
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_header_only_reports_no_tags() {
        let mut flv = b"FLV".to_vec();
        flv.push(1);
        flv.push(0x05);
        flv.extend_from_slice(&9u32.to_be_bytes());
        flv.extend_from_slice(&0u32.to_be_bytes());
        let a = analyze_flv(&flv).unwrap();
        assert_eq!(a.total_tags(), 0);
        assert!(!a.is_healthy());
        assert!(a.describe().contains("nie znaleziono żadnych tagów"));
    }

    // ------------------------------------------------------------------
    // describe
    // ------------------------------------------------------------------

    #[test]
    fn test_describe_healthy_mentions_counts_and_duration() {
        let flv = build_flv(&[(TAG_TYPE_VIDEO, 0, 20), (TAG_TYPE_AUDIO, 2000, 20)], None);
        let d = analyze_flv(&flv).unwrap().describe();
        assert!(d.contains("spójny"));
        assert!(d.contains("2 tagów"));
        assert!(d.contains("2.0s"));
    }

    #[test]
    fn test_describe_damaged_lists_problems() {
        let flv = build_flv(&[(TAG_TYPE_VIDEO, 0, 50), (TAG_TYPE_AUDIO, 23, 30)], Some(0));
        let d = analyze_flv(&flv).unwrap().describe();
        assert!(d.contains("łańcucha"), "Opis powinien wymienić przerwanie łańcucha: {}", d);
    }

    #[test]
    #[ignore = "Wymaga prawdziwego pliku FLV jako fixture. Wygeneruj poleceniem: \
                ffmpeg -f lavfi -i testsrc=duration=2:size=320x240:rate=10 \
                -f lavfi -i sine=frequency=440:duration=2 -c:v libx264 -preset ultrafast \
                -c:a aac -shortest -y image/test_fixture.flv \
                Potem: `cargo test analyze_real_flv_fixture -- --ignored --nocapture`."]
    fn test_analyze_real_flv_fixture() {
        let a = analyze_flv_file(std::path::Path::new("image/test_fixture.flv"))
            .expect("Prawdziwy plik FLV powinien się sparsować");
        println!("✔ {}", a.describe());
        assert!(a.is_healthy(), "Świeżo wygenerowany plik powinien być spójny");
        assert!(a.video_tags > 0 && a.audio_tags > 0);
    }

    // ------------------------------------------------------------------
    // Składanie z dwóch kopii — materiał budowany bajt po bajcie
    // ------------------------------------------------------------------

    /// Buduje tag wraz z domykającym go `PreviousTagSize`.
    ///
    /// `poprawny_lancuch = false` daje pole celowo rozminięte z rozmiarem tagu —
    /// dokładnie to, co składanie ma rozpoznać.
    fn tag(typ: u8, dane: &[u8], poprawny_lancuch: bool) -> Vec<u8> {
        let mut t = Vec::new();
        t.push(typ);
        t.extend_from_slice(&(dane.len() as u32).to_be_bytes()[1..]); // 3 bajty rozmiaru
        t.extend_from_slice(&[0, 0, 0, 0]); // znacznik czasu + rozszerzenie
        t.extend_from_slice(&[0, 0, 0]);    // stream id
        t.extend_from_slice(dane);

        let rozmiar = (TAG_HEADER_SIZE + dane.len()) as u32;
        let zapisany = if poprawny_lancuch { rozmiar } else { rozmiar ^ 0xFFFF };
        t.extend_from_slice(&zapisany.to_be_bytes());
        t
    }

    /// Buduje plik FLV: nagłówek + zerowy `PreviousTagSize` + podane tagi.
    fn plik_flv(tagi: &[Vec<u8>]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"FLV");
        b.push(1);    // wersja
        b.push(0x05); // obecne audio i wideo
        b.extend_from_slice(&(FLV_HEADER_SIZE as u32).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]); // PreviousTagSize0 = 0
        for t in tagi {
            b.extend_from_slice(t);
        }
        b
    }

    #[test]
    fn test_zdrowy_kontener_zlozony_sam_ze_soba_nic_nie_zmienia() {
        let a = plik_flv(&[tag(TAG_TYPE_VIDEO, b"klatka", true), tag(TAG_TYPE_AUDIO, b"dzwiek", true)]);
        assert_eq!(splice_flv(&a, &a).as_deref(), Some(a.as_slice()));
    }

    /// Sedno mechanizmu FLV: rozjazd `PreviousTagSize` dyskwalifikuje tag.
    #[test]
    fn test_tag_o_rozminietym_lancuchu_jest_zastepowany() {
        let a = plik_flv(&[
            tag(TAG_TYPE_VIDEO, b"klatka A", true),
            tag(TAG_TYPE_AUDIO, b"dzwiek A", false), // łańcuch przekłamany
        ]);
        let b = plik_flv(&[
            tag(TAG_TYPE_VIDEO, b"klatka B", true),
            tag(TAG_TYPE_AUDIO, b"dzwiek B", true),
        ]);

        let wynik = splice_flv(&a, &b).expect("kopia B ma zdrowy tag");

        assert!(wynik.windows(8).any(|w| w == b"klatka A"), "pierwszy tag zostaje z kopii A");
        assert!(wynik.windows(8).any(|w| w == b"dzwiek B"), "tag z rozminiętym łańcuchem musi przyjść z B");
        assert!(!wynik.windows(8).any(|w| w == b"dzwiek A"), "uszkodzony tag nie może trafić do wyniku");
    }

    /// Typ tagu spoza zbioru zdefiniowanego w formacie też dyskwalifikuje —
    /// to niezależny sygnał od łańcucha długości.
    #[test]
    fn test_tag_o_nieznanym_typie_jest_zastepowany() {
        // Typ 7 nie istnieje w FLV; łańcuch długości pozostaje POPRAWNY, więc
        // odrzucenie może wynikać wyłącznie z kontroli typu.
        let a = plik_flv(&[tag(TAG_TYPE_VIDEO, b"klatka A", true), tag(7, b"obcy AAA", true)]);
        let b = plik_flv(&[tag(TAG_TYPE_VIDEO, b"klatka B", true), tag(TAG_TYPE_AUDIO, b"dzwiek B", true)]);

        let wynik = splice_flv(&a, &b).expect("kopia B ma tag poprawnego typu");

        assert!(wynik.windows(8).any(|w| w == b"dzwiek B"), "tag o nieznanym typie musi zostać zastąpiony");
        assert!(!wynik.windows(8).any(|w| w == b"obcy AAA"), "tag o nieznanym typie nie może trafić do wyniku");
    }

    #[test]
    fn test_tag_zepsuty_po_obu_stronach_konczy_skladanie() {
        let a = plik_flv(&[tag(TAG_TYPE_VIDEO, b"klatka", true), tag(TAG_TYPE_AUDIO, b"dzwiek", false)]);
        let b = plik_flv(&[tag(TAG_TYPE_VIDEO, b"klatka", true), tag(TAG_TYPE_AUDIO, b"dzwiek", false)]);

        let wynik = splice_flv(&a, &b).expect("pierwszy tag jest zdrowy po obu stronach");

        let analiza = analyze_flv(&wynik).expect("wynik musi być czytelnym FLV");
        assert_eq!(analiza.total_tags(), 1, "drugi tag jest niezdatny po obu stronach - zostaje odcięty");
        assert_eq!(analiza.chain_errors, 0, "wynik musi mieć domknięty łańcuch");
    }

    #[test]
    fn test_smieci_za_ostatnim_tagiem_sa_odcinane() {
        let mut a = plik_flv(&[tag(TAG_TYPE_VIDEO, b"klatka", true)]);
        let czysty_rozmiar = a.len();
        a.extend_from_slice(&[0xDE; 300]);

        let wynik = splice_flv(&a, &a).expect("składanie musi się udać");
        assert_eq!(wynik.len(), czysty_rozmiar, "bajty za ostatnim spójnym tagiem muszą zostać odcięte");
    }

    #[test]
    fn test_brak_naglowka_flv_blokuje_skladanie() {
        let a = plik_flv(&[tag(TAG_TYPE_VIDEO, b"klatka", true)]);
        assert!(splice_flv(b"to nie jest flv", b"to tez nie").is_none());
        assert!(splice_flv(&a, b"smieci").is_none(), "jedna strona nieczytelna");
    }

    #[test]
    fn test_brak_ani_jednego_spojnego_tagu_blokuje_skladanie() {
        let a = plik_flv(&[tag(TAG_TYPE_VIDEO, b"klatka", false)]);
        assert!(
            splice_flv(&a, &a).is_none(),
            "bez choćby jednego spójnego tagu nie ma czego zapisać"
        );
    }
}
