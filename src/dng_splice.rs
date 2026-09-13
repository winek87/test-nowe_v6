// src/dng_splice.rs

//! # Składanie Strukturalne DNG (Header/IFD + Dane Pikseli)
//!
//! **STATUS: WPIĘTY.** Silnik obsługuje dwie drogi:
//!
//! * [`crate::dng_repair`] — ręczny przegląd z menu, z decyzją operatora na
//!   każdy plik (oraz trybem automatycznym),
//! * `phases::repair_modules::dng::DngStructuralModule` — automat Fazy 17,
//!   używający DOKŁADNIE tych samych kryteriów co tryb automatyczny wyżej.
//!
//! Oba oznaczają wynik gwarancją SŁABĄ — patrz ograniczenie poniżej, ono się
//! przez wpięcie nie zmieniło.
//!
//! ## ⚠️ KLUCZOWE OGRANICZENIE — PRZECZYTAJ PRZED UŻYCIEM
//!
//! W przeciwieństwie do PNG (Faza 18, `phase18_smart_splice`), gdzie każdy
//! fragment ma OBIEKTYWNY dowód poprawności (CRC32 chunka), DNG **nie ma
//! żadnego takiego mechanizmu dla danych pikseli**. Zweryfikowaliśmy to
//! EMPIRYCZNIE na prawdziwym pliku: `rawloader` "dekoduje się poprawnie"
//! nawet gdy 2000 bajtów w środku danych obrazu to czysty losowy szum —
//! dekoder po prostu czyta bufor o rozmiarze `width*height*cpp` z miejsca
//! wskazanego przez IFD, nie weryfikując SPÓJNOŚCI TEGO, co tam faktycznie leży.
//!
//! To znaczy: **udane dekodowanie złożonego pliku DNG dowodzi WYŁĄCZNIE
//! poprawności struktury (nagłówka/IFD), NIGDY poprawności treści pikseli.**
//! Każdy wynik tego modułu jest oznaczony [`SpliceConfidence::StructuralOnly`]
//! właśnie z tego powodu — żeby nigdy nie pomylić tego z mocną gwarancją,
//! jaką daje weryfikacja dekodowaniem dla PNG/JPEG w Fazie 18.
//!
//! ## Co NADAL ma sens zrobić
//!
//! Zweryfikowaliśmy też EMPIRYCZNIE, że uszkodzenie nagłówka/IFD jest
//! WYKRYWALNE W 100% — plik z takim uszkodzeniem po prostu nie dekoduje się
//! wcale. Skoro obie kopie pochodzą z tego samego oryginalnego pliku (dwie
//! próby odzysku tych samych bajtów), ich układ przed uszkodzeniem był
//! identyczny — więc offsety `StripOffsets`/`TileOffsets` odczytane ze
//! ZDROWEJ struktury jednej kopii mówią, GDZIE w pliku (nawet w tej
//! uszkodzonej) powinny leżeć dane pikseli. To jedyna sensowna interwencja,
//! jaką ten moduł oferuje: nagłówek jednej strony + dane pikseli drugiej,
//! z offsetów odczytanych ze zdrowej struktury.

use std::path::Path;

// ============================================================================
// MINIMALNY PARSER STRUKTURY TIFF/IFD
// ============================================================================

const TAG_STRIP_OFFSETS: u16 = 273;
const TAG_STRIP_BYTE_COUNTS: u16 = 279;
const TAG_SUB_IFDS: u16 = 330;
const TAG_TILE_OFFSETS: u16 = 324;
const TAG_TILE_BYTE_COUNTS: u16 = 325;

/// Czyta pola liczbowe pliku TIFF/DNG respektując zadeklarowaną kolejność
/// bajtów (`II` = little-endian, `MM` = big-endian) — DNG dziedziczy to
/// wprost po TIFF.
struct TiffReader<'a> {
    data: &'a [u8],
    little_endian: bool,
}

impl<'a> TiffReader<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 8 { return None; }
        let little_endian = match &data[0..2] {
            b"II" => true,
            b"MM" => false,
            _ => return None,
        };
        let magic = if little_endian {
            u16::from_le_bytes([data[2], data[3]])
        } else {
            u16::from_be_bytes([data[2], data[3]])
        };
        if magic != 42 { return None; }
        Some(Self { data, little_endian })
    }

    fn u16_at(&self, pos: usize) -> Option<u16> {
        let b = self.data.get(pos..pos + 2)?;
        Some(if self.little_endian { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
    }

    fn u32_at(&self, pos: usize) -> Option<u32> {
        let b = self.data.get(pos..pos + 4)?;
        Some(if self.little_endian { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) } else { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) })
    }

    fn first_ifd_offset(&self) -> Option<u32> {
        self.u32_at(4)
    }

    fn type_size(typ: u16) -> usize {
        match typ {
            1 | 2 | 6 | 7 => 1,
            3 | 8 => 2,
            4 | 9 | 11 => 4,
            5 | 10 | 12 => 8,
            _ => 1,
        }
    }

    /// Odczytuje tablicę wartości liczbowych dla wpisu IFD zaczynającego się
    /// pod `entry_offset` (12 bajtów: tag+type+count+value/offset), poprawnie
    /// rozróżniając przechowanie WEWNĄTRZ pola wartości (gdy się mieści w 4
    /// bajtach) od przechowania POD OFFSETEM (gdy nie). Zwraca `None` dla
    /// nieoczekiwanego typu danych (nasze tagi zainteresowania to zawsze
    /// SHORT lub LONG) albo gdy dane wykraczają poza bufor.
    fn read_value_array(&self, entry_offset: usize) -> Option<Vec<u32>> {
        let typ = self.u16_at(entry_offset + 2)?;
        let count = self.u32_at(entry_offset + 4)? as usize;
        if count == 0 { return Some(Vec::new()); }
        let elem_size = Self::type_size(typ);
        let total_size = elem_size.checked_mul(count)?;
        let value_pos = entry_offset + 8;
        let data_start = if total_size <= 4 { value_pos } else { self.u32_at(value_pos)? as usize };

        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let pos = data_start + i * elem_size;
            let v = match typ {
                3 | 8 => self.u16_at(pos)? as u32,
                4 | 9 => self.u32_at(pos)?,
                1 | 6 | 7 => *self.data.get(pos)? as u32,
                _ => return None,
            };
            out.push(v);
        }
        Some(out)
    }

    /// Zwraca listę wpisów `(tag, entry_offset)` danego IFD oraz offset
    /// kolejnego IFD w łańcuchu (`0` = brak).
    fn read_ifd(&self, ifd_offset: u32) -> Option<(Vec<(u16, usize)>, u32)> {
        let base = ifd_offset as usize;
        let count = self.u16_at(base)? as usize;
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let entry_offset = base + 2 + i * 12;
            let tag = self.u16_at(entry_offset)?;
            entries.push((tag, entry_offset));
        }
        let next_ifd_pos = base + 2 + count * 12;
        let next_ifd = self.u32_at(next_ifd_pos)?;
        Some((entries, next_ifd))
    }
}

/// Przeszukuje WSZYSTKIE IFD (włącznie z SubIFD wskazywanymi tagiem `330`,
/// standardowe miejsce, gdzie DNG trzyma pełnorozdzielczy obraz RAW obok
/// osobnej miniaturki w IFD głównym) w poszukiwaniu bloków danych pikseli
/// (`StripOffsets`+`StripByteCounts` lub `TileOffsets`+`TileByteCounts`).
/// Gdy więcej niż jeden IFD ma taką parę tagów (typowe: miniaturka + obraz
/// główny), wybiera ten o NAJWIĘKSZEJ sumarycznej objętości danych — to
/// prawie zawsze pełnorozdzielczy obraz główny, nie podgląd.
fn find_pixel_data_ranges(bytes: &[u8]) -> Option<Vec<(usize, usize)>> {
    let reader = TiffReader::new(bytes)?;
    let mut queue = vec![reader.first_ifd_offset()?];
    let mut best: Option<Vec<(usize, usize)>> = None;
    let mut visited = std::collections::HashSet::new();

    while let Some(ifd_off) = queue.pop() {
        if ifd_off == 0 || !visited.insert(ifd_off) { continue; }
        let Some((entries, next_ifd)) = reader.read_ifd(ifd_off) else { continue };
        if next_ifd != 0 { queue.push(next_ifd); }

        let mut offsets_entry = None;
        let mut counts_entry = None;
        for &(tag, entry_offset) in &entries {
            match tag {
                TAG_STRIP_OFFSETS | TAG_TILE_OFFSETS => offsets_entry = Some(entry_offset),
                TAG_STRIP_BYTE_COUNTS | TAG_TILE_BYTE_COUNTS => counts_entry = Some(entry_offset),
                TAG_SUB_IFDS => {
                    if let Some(sub_offsets) = reader.read_value_array(entry_offset) {
                        queue.extend(sub_offsets);
                    }
                }
                _ => {}
            }
        }

        if let (Some(off_e), Some(cnt_e)) = (offsets_entry, counts_entry)
            && let (Some(offsets), Some(counts)) = (reader.read_value_array(off_e), reader.read_value_array(cnt_e))
                && !offsets.is_empty() && offsets.len() == counts.len() {
                    let ranges: Vec<(usize, usize)> = offsets.iter().zip(counts.iter())
                        .map(|(&o, &c)| (o as usize, c as usize))
                        .collect();
                    let total: usize = ranges.iter().map(|(_, l)| l).sum();
                    let is_better = best.as_ref()
                        .map(|b: &Vec<(usize, usize)>| total > b.iter().map(|(_, l)| l).sum())
                        .unwrap_or(true);
                    if is_better { best = Some(ranges); }
                }
    }
    best
}

/// Podmienia bajty w `base` na pozycjach `ranges` na odpowiadające bajty
/// z `donor`. Zwraca `None`, gdy `donor` jest za krótki, żeby pokryć
/// KTÓRYKOLWIEK zakres (np. ucięty wcześniej niż sięgają dane obrazu) —
/// brak częściowych/niepełnych podmian. Razem ze złożonym buforem zwraca
/// entropię Shannona (bity/bajt) POLICZONĄ WYŁĄCZNIE na przeniesionych
/// bajtach (nie całego pliku) — patrz [`estimate_plausibility`].
fn apply_data_ranges(base: &[u8], donor: &[u8], ranges: &[(usize, usize)]) -> Option<(Vec<u8>, f64)> {
    let mut result = base.to_vec();
    let mut donated_bytes: Vec<u8> = Vec::new();
    for &(offset, length) in ranges {
        let end = offset.checked_add(length)?;
        if end > donor.len() || end > result.len() { return None; }
        result[offset..end].copy_from_slice(&donor[offset..end]);
        donated_bytes.extend_from_slice(&donor[offset..end]);
    }
    let entropy = estimate_plausibility(&donated_bytes);
    Some((result, entropy))
}

/// Oblicza entropię Shannona (bity/bajt, zakres 0.0-8.0) podanego wycinka
/// bajtów — DOKŁADNIE ta sama metoda co Faza 7 (analiza entropii Shannon),
/// zastosowana tu WYŁĄCZNIE do obszaru danych pikseli faktycznie
/// przeniesionego między kopiami. **To NIE jest dowód poprawności treści**
/// (patrz ograniczenie modułu) — to PLAUZYBILNOŚĆ: prawdziwe dane sensora
/// RAW mają charakterystyczną entropię (zwykle ok. 6.0-7.95 bitów/bajt),
/// podczas gdy czyste zera (np. po TRIM) dają entropię bliską `0.0`, a
/// przypadkowy szum spoza sensora (np. dane innego pliku wklejone przez
/// błąd carvingu) bywa podejrzanie blisko idealnych `8.0` (maksymalnie
/// losowe, czego prawdziwy sensor obrazu praktycznie nigdy nie daje).
pub fn estimate_plausibility(bytes: &[u8]) -> f64 {
    if bytes.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in bytes { counts[b as usize] += 1; }
    let len = bytes.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / len;
        -p * p.log2()
    }).sum()
}

/// Dolna granica plauzybilności — patrz [`looks_like_plausible_sensor_data`]
/// co do tego, skąd wzięła się ta konkretna wartość.
pub const DOLNA_GRANICA_ENTROPII: f64 = 3.0;

/// Górna granica plauzybilności: entropia bliska idealnym 8.0 bitom/bajt
/// znaczy dane maksymalnie losowe, czego prawdziwy sensor praktycznie nigdy
/// nie daje — to sygnatura obcych danych (np. wklejonych przez błąd carvingu)
/// albo zaszyfrowanego materiału.
pub const GORNA_GRANICA_ENTROPII: f64 = 7.95;

/// Próg plauzybilności używany zarówno do wyświetlenia sygnału w trybie
/// ręcznym, jak i jako kryterium decyzyjne w trybie automatycznym
/// `dng_repair` oraz w module Fazy 17 (`repair_modules::dng`).
/// NIGDY nie traktować jako dowodu, wyłącznie jako filtr zmniejszający
/// (nie eliminujący) ryzyko zaakceptowania czystego szumu/zer.
///
/// # Skąd dolna granica 3.0 (i dlaczego NIE 6.0)
///
/// Pierwotny przedział `6.0..=7.95` zakładał milcząco, że dane sensora są
/// **skompresowane** — wtedy entropia faktycznie siedzi blisko 7.9. Pomiar na
/// prawdziwym fixture'cie (`image/test_fixture.dng`, 26 533 682 B) pokazał, że
/// to założenie jest w praktyce fałszywe:
///
/// ```text
/// entropia przenoszonego obszaru danych pikseli:  5.1619 bit/bajt
/// udział bajtów zerowych w całym pliku:           39.3 %
/// ```
///
/// Tak wygląda RAW **nieskompresowany/upakowany**: wysokie bajty próbek
/// 12/14-bitowych są w większości zerowe, co ściąga entropię bajtową daleko
/// poniżej 6.0. Stary przedział odrzucał więc **autentyczne dane sensora**, co
/// oznacza, że tryb automatyczny `dng_repair` nie przyjąłby ani jednego pliku z
/// tego aparatu. Granica 3.0 zostawia szeroki margines pod zmierzonymi 5.16, a
/// jednocześnie nadal odsiewa to, co ma odsiewać: obszar po TRIM (same zera)
/// daje entropię `0.0`, a obszar o kilku powtarzających się wartościach nie
/// przekracza ~2.
///
/// Wartość jest skalibrowana **pomiarem, nie teorią** — przy nowym materiale
/// referencyjnym należy ją sprawdzić ponownie.
pub fn looks_like_plausible_sensor_data(entropy: f64) -> bool {
    (DOLNA_GRANICA_ENTROPII..=GORNA_GRANICA_ENTROPII).contains(&entropy)
}

// ============================================================================
// SKŁADANIE (Z JAWNYM POZIOMEM PEWNOŚCI)
// ============================================================================

/// Poziom pewności złożenia. Na razie jeden wariant — patrz zastrzeżenie w
/// dokumentacji modułu — zarezerwowane pod przyszłe rozróżnienie, gdyby
/// kiedyś pojawił się sposób na silniejszą weryfikację treści pikseli DNG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceConfidence {
    /// Nagłówek/IFD wzięty z JEDNEJ strony, dane pikseli z DRUGIEJ, na
    /// podstawie offsetów odczytanych ze zdrowej struktury. Udane
    /// dekodowanie potwierdza WYŁĄCZNIE spójność struktury — NIGDY
    /// poprawność treści pikseli (patrz dokumentacja modułu).
    StructuralOnly,
}

#[derive(Debug, Clone)]
pub struct SpliceCandidate {
    pub bytes: Vec<u8>,
    pub confidence: SpliceConfidence,
    pub description: String,
    /// Entropia Shannona (bity/bajt) przeniesionego fragmentu danych pikseli
    /// — patrz [`estimate_plausibility`]. Sygnał plauzybilności, NIE dowód.
    pub donated_data_entropy: f64,
}

/// Generuje kandydatów złożenia w OBU kierunkach: nagłówek A + dane B (wg
/// offsetów z A), oraz nagłówek B + dane A (wg offsetów z B) — niezależnie
/// od tego, czy druga strona dekoduje się samodzielnie. Każdy zwrócony
/// kandydat jest oznaczony [`SpliceConfidence::StructuralOnly`] — dekodowanie
/// go z sukcesem NIE jest dowodem poprawności treści, tylko struktury.
pub fn structural_splice_candidates(bytes_a: &[u8], bytes_b: &[u8]) -> Vec<SpliceCandidate> {
    let mut out = Vec::new();

    if let Some(ranges_a) = find_pixel_data_ranges(bytes_a)
        && let Some((spliced, entropy)) = apply_data_ranges(bytes_a, bytes_b, &ranges_a) {
            out.push(SpliceCandidate {
                bytes: spliced,
                confidence: SpliceConfidence::StructuralOnly,
                description: "Nagłówek/IFD ze strony A, dane pikseli ze strony B (wg offsetów A)".to_string(),
                donated_data_entropy: entropy,
            });
        }
    if let Some(ranges_b) = find_pixel_data_ranges(bytes_b)
        && let Some((spliced, entropy)) = apply_data_ranges(bytes_b, bytes_a, &ranges_b) {
            out.push(SpliceCandidate {
                bytes: spliced,
                confidence: SpliceConfidence::StructuralOnly,
                description: "Nagłówek/IFD ze strony B, dane pikseli ze strony A (wg offsetów B)".to_string(),
                donated_data_entropy: entropy,
            });
        }
    out
}

/// Wygodny wariant [`structural_splice_candidates`] operujący na ścieżkach
/// plików zamiast gotowych buforów.
pub fn structural_splice_files(path_a: &Path, path_b: &Path) -> std::io::Result<Vec<SpliceCandidate>> {
    let bytes_a = std::fs::read(path_a)?;
    let bytes_b = std::fs::read(path_b)?;
    Ok(structural_splice_candidates(&bytes_a, &bytes_b))
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Buduje minimalny, syntetyczny plik TIFF little-endian z JEDNYM IFD
    /// zawierającym dokładnie jeden pasek danych (`StripOffsets`/
    /// `StripByteCounts`, count=1). W przeciwieństwie do walidacji `rawloader`
    /// (która sprawdza rzeczywiste znaczniki aparatu — nie da się tego
    /// sfabrykować, patrz `raw_image::tests`), sama STRUKTURA TIFF/IFD nie
    /// ma żadnej sumy kontrolnej zależnej od treści — możemy ją budować
    /// ręcznie i testować w pełni deterministycznie.
    fn build_minimal_tiff_single_strip(strip_data: &[u8]) -> Vec<u8> {
        let ifd_offset: u32 = 8; // IFD zaraz po 8-bajtowym nagłówku
        let num_entries: u16 = 2;
        let ifd_size = 2 + (num_entries as usize) * 12 + 4;
        let data_offset = ifd_offset as usize + ifd_size;

        let mut out = Vec::new();
        out.extend_from_slice(b"II");
        out.extend_from_slice(&42u16.to_le_bytes());
        out.extend_from_slice(&ifd_offset.to_le_bytes());

        out.extend_from_slice(&num_entries.to_le_bytes());
        // StripOffsets (273), LONG(4), count=1, value=data_offset
        out.extend_from_slice(&273u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(data_offset as u32).to_le_bytes());
        // StripByteCounts (279), LONG(4), count=1, value=len
        out.extend_from_slice(&279u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(strip_data.len() as u32).to_le_bytes());
        // brak kolejnego IFD
        out.extend_from_slice(&0u32.to_le_bytes());

        out.extend_from_slice(strip_data);
        out
    }

    /// Jak wyżej, ale z DWOMA IFD w łańcuchu głównym (symulacja: IFD0 =
    /// miniaturka mała, IFD1 = obraz główny duży) — sprawdza, czy
    /// [`find_pixel_data_ranges`] poprawnie wybiera WIĘKSZY.
    fn build_tiff_with_thumbnail_and_main(thumb_data: &[u8], main_data: &[u8]) -> Vec<u8> {
        let ifd0_offset: u32 = 8;
        let ifd0_size = 2 + 2 * 12 + 4;
        let ifd1_offset = ifd0_offset as usize + ifd0_size;
        let ifd1_size = 2 + 2 * 12 + 4;
        let thumb_data_offset = ifd1_offset + ifd1_size;
        let main_data_offset = thumb_data_offset + thumb_data.len();

        let mut out = Vec::new();
        out.extend_from_slice(b"II");
        out.extend_from_slice(&42u16.to_le_bytes());
        out.extend_from_slice(&ifd0_offset.to_le_bytes());

        // IFD0 (miniaturka) - wskazuje na IFD1 jako next
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&273u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(thumb_data_offset as u32).to_le_bytes());
        out.extend_from_slice(&279u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(thumb_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(ifd1_offset as u32).to_le_bytes()); // next_ifd = IFD1

        // IFD1 (obraz główny) - brak kolejnego
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&273u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(main_data_offset as u32).to_le_bytes());
        out.extend_from_slice(&279u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(main_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());

        out.extend_from_slice(thumb_data);
        out.extend_from_slice(main_data);
        out
    }

    // ------------------------------------------------------------------
    // TiffReader / find_pixel_data_ranges
    // ------------------------------------------------------------------

    #[test]
    fn test_find_pixel_data_ranges_single_strip() {
        let strip_data = vec![0xABu8; 100];
        let tiff = build_minimal_tiff_single_strip(&strip_data);

        let ranges = find_pixel_data_ranges(&tiff).unwrap();
        assert_eq!(ranges.len(), 1);
        let (off, len) = ranges[0];
        assert_eq!(len, 100);
        assert_eq!(&tiff[off..off + len], &strip_data[..]);
    }

    #[test]
    fn test_find_pixel_data_ranges_picks_larger_ifd_not_thumbnail() {
        let thumb = vec![0x11u8; 20];
        let main = vec![0x22u8; 5000];
        let tiff = build_tiff_with_thumbnail_and_main(&thumb, &main);

        let ranges = find_pixel_data_ranges(&tiff).unwrap();
        let total: usize = ranges.iter().map(|(_, l)| l).sum();
        assert_eq!(total, 5000, "Powinien wybrać IFD obrazu głównego (5000 B), nie miniaturki (20 B)");
    }

    #[test]
    fn test_find_pixel_data_ranges_rejects_non_tiff() {
        assert!(find_pixel_data_ranges(b"to na pewno nie jest TIFF ani DNG").is_none());
    }

    #[test]
    fn test_find_pixel_data_ranges_accepts_big_endian() {
        // Odwracamy ręcznie na wariant big-endian ("MM"), przeliczając pola
        // wielobajtowe - potwierdza, że TiffReader respektuje endianness,
        // nie zakłada na sztywno little-endian.
        let strip_data = vec![0x33u8; 50];
        let ifd_offset: u32 = 8;
        let data_offset = ifd_offset as usize + 2 + 2 * 12 + 4;

        let mut out = Vec::new();
        out.extend_from_slice(b"MM");
        out.extend_from_slice(&42u16.to_be_bytes());
        out.extend_from_slice(&ifd_offset.to_be_bytes());
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(&273u16.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&(data_offset as u32).to_be_bytes());
        out.extend_from_slice(&279u16.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&(strip_data.len() as u32).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&strip_data);

        let ranges = find_pixel_data_ranges(&out).unwrap();
        assert_eq!(ranges[0].1, 50);
    }

    #[test]
    fn test_find_pixel_data_ranges_truncated_header_returns_none() {
        let garbage = vec![0x00u8; 4]; // za krótkie nawet na nagłówek TIFF (8 bajtów)
        assert!(find_pixel_data_ranges(&garbage).is_none());
    }

    // ------------------------------------------------------------------
    // apply_data_ranges
    // ------------------------------------------------------------------

    #[test]
    fn test_apply_data_ranges_swaps_correct_bytes_only() {
        let base = vec![0xAAu8; 20];
        let donor = vec![0xBBu8; 20];
        let ranges = vec![(5, 5)]; // podmieniamy tylko bajty 5..10

        let (result, _entropy) = apply_data_ranges(&base, &donor, &ranges).unwrap();
        assert_eq!(&result[0..5], &[0xAA; 5]);
        assert_eq!(&result[5..10], &[0xBB; 5]);
        assert_eq!(&result[10..20], &[0xAA; 10]);
    }

    #[test]
    fn test_apply_data_ranges_fails_when_donor_too_short() {
        let base = vec![0xAAu8; 20];
        let donor = vec![0xBBu8; 8]; // za krótki, żeby pokryć zakres (5,10)
        let ranges = vec![(5, 10)];
        assert!(apply_data_ranges(&base, &donor, &ranges).is_none());
    }

    // ------------------------------------------------------------------
    // estimate_plausibility / looks_like_plausible_sensor_data
    // ------------------------------------------------------------------

    #[test]
    fn test_estimate_plausibility_all_zeros_is_zero_entropy() {
        // Wyzerowany fragment (typowe po TRIM) - entropia dokładnie 0.0,
        // bo jest tylko JEDNA wartość bajtowa w całym wycinku.
        let zeros = vec![0u8; 1000];
        assert_eq!(estimate_plausibility(&zeros), 0.0);
        assert!(!looks_like_plausible_sensor_data(estimate_plausibility(&zeros)));
    }

    #[test]
    fn test_estimate_plausibility_uniform_random_is_near_maximum() {
        // Idealnie równomierny rozkład wszystkich 256 wartości bajtowych -
        // matematyczne maksimum entropii Shannona to dokładnie 8.0 bit/bajt.
        let mut uniform = Vec::with_capacity(256 * 50);
        for _ in 0..50 {
            for b in 0..=255u8 { uniform.push(b); }
        }
        let h = estimate_plausibility(&uniform);
        assert!((h - 8.0).abs() < 0.01, "Idealnie równomierny rozkład powinien dać entropię bliską 8.0, otrzymano {}", h);
    }

    #[test]
    fn test_estimate_plausibility_empty_is_zero() {
        assert_eq!(estimate_plausibility(&[]), 0.0);
    }

    #[test]
    fn test_looks_like_plausible_sensor_data_boundary_values() {
        assert!(looks_like_plausible_sensor_data(DOLNA_GRANICA_ENTROPII));
        assert!(looks_like_plausible_sensor_data(GORNA_GRANICA_ENTROPII));
        assert!(looks_like_plausible_sensor_data(7.0));
        assert!(!looks_like_plausible_sensor_data(DOLNA_GRANICA_ENTROPII - 0.01));
        assert!(!looks_like_plausible_sensor_data(GORNA_GRANICA_ENTROPII + 0.01));
        assert!(!looks_like_plausible_sensor_data(0.0));
        assert!(!looks_like_plausible_sensor_data(8.0));
    }

    /// Wartość ZMIERZONA na prawdziwym, nieskompresowanym DNG musi przechodzić
    /// próg.
    ///
    /// To test regresji na konkretną pomyłkę: poprzednia dolna granica (6.0)
    /// odrzucała autentyczne dane sensora o entropii 5.16, czyniąc tryb
    /// automatyczny bezużytecznym dla tego materiału. Uzasadnienie i pomiar są
    /// w dokumentacji [`looks_like_plausible_sensor_data`].
    #[test]
    fn test_prog_przyjmuje_zmierzona_entropie_nieskompresowanego_raw() {
        let zmierzona = 5.1619;
        assert!(
            looks_like_plausible_sensor_data(zmierzona),
            "entropia {} zmierzona na image/test_fixture.dng to autentyczne dane sensora i MUSI przechodzić próg",
            zmierzona
        );

        // A jednocześnie próg nadal odsiewa to, po co istnieje.
        assert!(!looks_like_plausible_sensor_data(0.0), "obszar po TRIM (same zera)");
        assert!(!looks_like_plausible_sensor_data(1.5), "obszar o kilku powtarzających się wartościach");
        assert!(!looks_like_plausible_sensor_data(7.99), "dane maksymalnie losowe (obce/zaszyfrowane)");
    }

    #[test]
    fn test_structural_splice_candidate_carries_donated_entropy() {
        // Dane zerowe jako "przenoszone" - kandydat powinien nieść entropię
        // 0.0 i jasno sygnalizować niską plauzybilność.
        let zeros = vec![0u8; 200];
        let file_a = build_minimal_tiff_single_strip(&[0x55u8; 200]);
        let file_b_with_zeros = build_minimal_tiff_single_strip(&zeros);

        let candidates = structural_splice_candidates(&file_a, &file_b_with_zeros);
        // Kandydat "nagłówek A + dane B" przenosi ZEROWE dane z B do A
        let cand = candidates.iter().find(|c| c.description.contains("ze strony A")).unwrap();
        assert_eq!(cand.donated_data_entropy, 0.0);
        assert!(!looks_like_plausible_sensor_data(cand.donated_data_entropy));
    }

    // ------------------------------------------------------------------
    // structural_splice_candidates - test end-to-end na syntetycznych plikach
    // ------------------------------------------------------------------

    #[test]
    fn test_structural_splice_recombines_header_and_data_correctly() {
        // "Zdrowa" wersja B: nagłówek OK, dane OK.
        let healthy_data = vec![0x77u8; 200];
        let file_b = build_minimal_tiff_single_strip(&healthy_data);

        // "Uszkodzona" wersja A: SAMA STRUKTURA IFD też poprawna w tym teście
        // (bo testujemy tu logikę składania, nie odporność na uszkodzony
        // nagłówek - to osobny test wyżej), ale dane inne - symulacja
        // "różne dane w tym samym układzie bajtów".
        let different_data = vec![0x99u8; 200];
        let file_a = build_minimal_tiff_single_strip(&different_data);

        let candidates = structural_splice_candidates(&file_a, &file_b);
        assert_eq!(candidates.len(), 2, "Obie strony mają poprawną strukturę - oczekujemy dwóch kandydatów");

        for c in &candidates {
            assert_eq!(c.confidence, SpliceConfidence::StructuralOnly);
        }

        // Kandydat "nagłówek A + dane B": w miejscu danych powinny być bajty 0x77 (z B)
        let cand_header_a = candidates.iter().find(|c| c.description.contains("ze strony A")).unwrap();
        let ranges = find_pixel_data_ranges(&file_a).unwrap();
        let (off, len) = ranges[0];
        assert_eq!(&cand_header_a.bytes[off..off + len], &vec![0x77u8; len][..]);
    }

    #[test]
    fn test_structural_splice_only_one_candidate_when_one_side_unparseable() {
        let healthy_data = vec![0x77u8; 100];
        let file_b = build_minimal_tiff_single_strip(&healthy_data);
        // Musi być DŁUŻSZE niż zasięg danych wymagany przez file_b (żeby
        // apply_data_ranges miało z czego czerpać), ale wciąż NIE zaczynać
        // się od "II"/"MM" (żeby find_pixel_data_ranges go odrzucił jako TIFF).
        let garbage_a = vec![0x00u8; file_b.len() + 50];

        let candidates = structural_splice_candidates(&garbage_a, &file_b);
        assert_eq!(candidates.len(), 1, "Tylko strona B ma odczytywalną strukturę - jeden kandydat");
        assert!(candidates[0].description.contains("ze strony B"));
    }

    #[test]
    fn test_structural_splice_empty_when_neither_side_parseable() {
        let garbage_a = vec![0x00u8; 50];
        let garbage_b = vec![0xFFu8; 50];
        assert!(structural_splice_candidates(&garbage_a, &garbage_b).is_empty());
    }

    // ------------------------------------------------------------------
    // Test na PRAWDZIWYCH plikach użytkownika (Samsung SM-G991B) - WYMAGA fixture
    // ------------------------------------------------------------------

    #[test]
    #[ignore = "Wymaga prawdziwych plików DNG jako fixture - dokładnie ten scenariusz, \
                który zdiagnozowaliśmy empirycznie: `image/test_fixture.dng` (zdrowy) \
                i `image/test_fixture_header_damaged.dng` (nagłówek zniszczony przez \
                nadpisanie bajtów 8-108 losowymi danymi). Aby uruchomić: \
                `cargo test structural_splice_real_header_damaged -- --ignored --nocapture`."]
    fn test_structural_splice_real_header_damaged_fixture() {
        let healthy_path = Path::new("image/test_fixture.dng");
        let damaged_path = Path::new("image/test_fixture_header_damaged.dng");

        let candidates = structural_splice_files(damaged_path, healthy_path)
            .expect("Odczyt obu plików fixture powinien się powieść");

        assert!(!candidates.is_empty(), "Powinien powstać co najmniej jeden kandydat (strona zdrowa ma odczytywalną strukturę)");

        let mut any_decoded = false;
        for c in &candidates {
            println!("Kandydat: {} ({} bajtów, pewność: {:?})", c.description, c.bytes.len(), c.confidence);
            if crate::raw_image::decode_raw_bytes(&c.bytes).is_some() {
                any_decoded = true;
                println!("  -> ✔ zdekodowano strukturalnie (PRZYPOMNIENIE: to NIE dowodzi poprawności pikseli)");
            } else {
                println!("  -> ✖ nie zdekodowano");
            }
        }
        assert!(any_decoded, "Co najmniej jeden kandydat powinien się zdekodować strukturalnie");
    }
}
