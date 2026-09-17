// src/tar_archive.rs

//! # Analiza i Składanie Archiwów TAR
//!
//! **ZERO ZALEŻNOŚCI ZEWNĘTRZNYCH** — format tar jest na tyle prosty, że
//! pełna analiza mieści się w czystym `std`, tak jak przy `ts_stream` i
//! `flv_stream`.
//!
//! ## Dlaczego TAR należy do MOCNEJ klasy (jak ZIP/PNG, nie jak DNG)
//!
//! Każdy wpis w archiwum tar zaczyna się 512-bajtowym nagłówkiem, który
//! zawiera **własną sumę kontrolną** (offset 148, 8 bajtów, ósemkowo). To
//! obiektywny dowód poprawności nagłówka per wpis — dokładnie ta sama
//! własność, którą wykorzystujemy przy chunkach PNG i wpisach ZIP.
//!
//! Algorytm sumy (zweryfikowany empirycznie na prawdziwym archiwum
//! `tar cf`): suma wszystkich 512 bajtów nagłówka, przy czym **pole sumy
//! traktuje się tak, jakby zawierało spacje** (0x20).
//!
//! ## Ograniczenie, które trzeba nazwać wprost
//!
//! Suma kontrolna chroni **wyłącznie nagłówek**, NIE dane pliku. Wpis może
//! mieć idealnie poprawny nagłówek i całkowicie zniszczoną treść — tar nie
//! przechowuje żadnej sumy dla samych danych. To znaczy:
//! - **wykrywanie** uszkodzonych nagłówków: pewne i obiektywne,
//! - **składanie** z dwóch kopii: bezpieczne na poziomie STRUKTURY, ale bez
//!   gwarancji, że przeniesione dane pliku są poprawne.
//!
//! Dlatego [`splice_tar`] składa wyłącznie tam, gdzie nagłówek jednej ze
//! stron jest zdrowy, i NIE udaje, że weryfikuje treść.

/// Rozmiar bloku tar (stały w całym formacie).
const BLOCK_SIZE: usize = 512;
/// Offset i długość pola sumy kontrolnej w nagłówku.
const CHECKSUM_OFFSET: usize = 148;
const CHECKSUM_LEN: usize = 8;

/// Jeden wpis w archiwum.
#[derive(Debug, Clone, PartialEq)]
pub struct TarEntry {
    pub name: String,
    /// Rozmiar danych w bajtach (bez wyrównania do pełnych bloków).
    pub size: u64,
    /// Offset bajtowy nagłówka tego wpisu w pliku.
    pub header_offset: usize,
    /// Czy suma kontrolna nagłówka się zgadza — obiektywny dowód, patrz
    /// dokumentacja modułu.
    pub header_valid: bool,
    /// Czy dane wpisu w całości mieszczą się w pliku (`false` = archiwum
    /// ucięte w trakcie tego wpisu).
    pub data_complete: bool,
}

/// Wynik analizy całego archiwum.
#[derive(Debug, Clone, PartialEq)]
pub struct TarAnalysis {
    pub entries: Vec<TarEntry>,
    /// Czy archiwum kończy się prawidłowym znacznikiem końca (dwa bloki zer).
    pub has_end_marker: bool,
    /// Bajty na końcu nietworzące pełnego bloku 512 B — objaw ucięcia.
    pub trailing_partial_bytes: usize,
}

impl TarAnalysis {
    pub fn total_entries(&self) -> usize { self.entries.len() }
    pub fn valid_headers(&self) -> usize { self.entries.iter().filter(|e| e.header_valid).count() }
    pub fn corrupted_headers(&self) -> usize { self.entries.iter().filter(|e| !e.header_valid).count() }
    pub fn incomplete_entries(&self) -> usize { self.entries.iter().filter(|e| !e.data_complete).count() }

    pub fn is_healthy(&self) -> bool {
        !self.entries.is_empty()
            && self.corrupted_headers() == 0
            && self.incomplete_entries() == 0
            && self.has_end_marker
            && self.trailing_partial_bytes == 0
    }

    pub fn describe(&self) -> String {
        if self.entries.is_empty() {
            return "Nie znaleziono żadnych wpisów tar (plik pusty, ucięty lub nie jest archiwum)".to_string();
        }
        if self.is_healthy() {
            return format!("Archiwum spójne: {} wpisów, wszystkie nagłówki poprawne", self.total_entries());
        }
        let mut parts = Vec::new();
        if self.corrupted_headers() > 0 {
            parts.push(format!("{} uszkodzonych nagłówków (z {})", self.corrupted_headers(), self.total_entries()));
        }
        if self.incomplete_entries() > 0 {
            parts.push(format!("{} wpisów z uciętymi danymi", self.incomplete_entries()));
        }
        if !self.has_end_marker { parts.push("brak znacznika końca archiwum".to_string()); }
        if self.trailing_partial_bytes > 0 {
            parts.push(format!("{} bajtów niepełnego bloku na końcu", self.trailing_partial_bytes));
        }
        parts.join("; ")
    }
}

/// Oblicza sumę kontrolną nagłówka wg specyfikacji tar: suma wszystkich
/// bajtów bloku, gdzie **pole sumy liczy się jako spacje** (0x20).
/// Algorytm zweryfikowany empirycznie na archiwum z `tar cf`.
fn compute_header_checksum(block: &[u8]) -> u32 {
    block.iter().enumerate().map(|(i, &b)| {
        if (CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_LEN).contains(&i) { 32u32 } else { b as u32 }
    }).sum()
}

/// Odczytuje pole zapisane ósemkowo jako tekst (tar przechowuje liczby w
/// takiej postaci). Zwraca `None` dla pola pustego lub niepoprawnego.
fn parse_octal(field: &[u8]) -> Option<u64> {
    let s: String = field.iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .map(|&b| b as char)
        .collect();
    if s.is_empty() { return None; }
    u64::from_str_radix(&s, 8).ok()
}

/// Sprawdza, czy blok wygląda na nagłówek tar (obecność sygnatury `ustar`
/// na offsecie 257). Starsze archiwa V7 jej nie mają, więc brak sygnatury
/// NIE dyskwalifikuje bloku — decyduje suma kontrolna.
fn has_ustar_magic(block: &[u8]) -> bool {
    block.len() >= 263 && &block[257..262] == b"ustar"
}

/// Rozpoznaje rozszerzenia archiwów tar. Warianty SKOMPRESOWANE
/// (`.tar.gz`, `.tgz`...) CELOWO nie są tu ujęte — pod kompresją nie widać
/// struktury bloków, więc ten parser nie miałby czego analizować.
pub fn is_plain_tar_extension(path_str: &str) -> bool {
    path_str.to_lowercase().ends_with(".tar")
}

/// Analizuje archiwum: przechodzi łańcuch bloków, weryfikuje sumę kontrolną
/// KAŻDEGO nagłówka i sprawdza kompletność danych.
///
/// Zwraca `None`, gdy plik jest za krótki na choćby jeden blok.
pub fn analyze_tar(bytes: &[u8]) -> Option<TarAnalysis> {
    if bytes.len() < BLOCK_SIZE { return None; }

    let mut entries = Vec::new();
    let mut has_end_marker = false;
    let mut offset = 0usize;

    while offset + BLOCK_SIZE <= bytes.len() {
        let block = &bytes[offset..offset + BLOCK_SIZE];

        // Dwa kolejne bloki zerowe = prawidłowy koniec archiwum.
        if block.iter().all(|&b| b == 0) {
            let second = offset + BLOCK_SIZE;
            has_end_marker = second + BLOCK_SIZE <= bytes.len()
                && bytes[second..second + BLOCK_SIZE].iter().all(|&b| b == 0);
            offset += BLOCK_SIZE * if has_end_marker { 2 } else { 1 };
            break;
        }

        let stored = parse_octal(&block[CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_LEN]);
        let computed = compute_header_checksum(block);
        let header_valid = stored == Some(computed as u64);

        // NAPRAWIONY BŁĄD: blok bez sumy kontrolnej ORAZ bez sygnatury
        // `ustar` to prawie na pewno BLOK DANYCH poprzedniego wpisu, nie
        // uszkodzony nagłówek. Pierwotnie zliczałem takie bloki jako wpisy,
        // przez co uszkodzenie jednego nagłówka produkowało FIKCYJNE wpisy
        // (nazwane fragmentami treści pliku) i rozjeżdżało liczbę wpisów
        // między kopiami — co uniemożliwiało jakiekolwiek składanie.
        // Wykryte dopiero przez test składania, nie przez testy analizy.
        if !header_valid && !has_ustar_magic(block) {
            offset += BLOCK_SIZE;
            continue;
        }

        let name: String = block[0..100].iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();

        // Rozmiar z nagłówka. Przy uszkodzonej sumie pole rozmiaru CZĘSTO
        // jest nadal czytelne (uszkodzenie trafiło gdzie indziej), więc
        // próbujemy je odczytać — to pozwala przeskoczyć dane tego wpisu i
        // zachować SYNCHRONIZACJĘ OFFSETÓW z drugą kopią, co jest warunkiem
        // koniecznym składania. Gdy pole jest nieczytelne, przesuwamy się o
        // jeden blok (tryb odzyskiwania).
        let parsed_size = parse_octal(&block[124..136]);
        let size = parsed_size.unwrap_or(0);
        let data_blocks = (size as usize).div_ceil(BLOCK_SIZE);
        let data_end = offset + BLOCK_SIZE + data_blocks * BLOCK_SIZE;
        let data_complete = data_end <= bytes.len();

        entries.push(TarEntry {
            name, size, header_offset: offset, header_valid, data_complete,
        });

        if parsed_size.is_none() {
            // Nie wiemy, ile danych przeskoczyć - szukamy kolejnego nagłówka
            // blok po bloku.
            offset += BLOCK_SIZE;
            continue;
        }
        if !data_complete { offset = bytes.len(); break; }
        offset = data_end;
    }

    Some(TarAnalysis {
        entries,
        has_end_marker,
        trailing_partial_bytes: bytes.len().saturating_sub(offset) % BLOCK_SIZE,
    })
}

/// Wariant [`analyze_tar`] operujący na pliku na dysku.
pub fn analyze_tar_file(path: &std::path::Path) -> Option<TarAnalysis> {
    let bytes = std::fs::read(path).ok()?;
    analyze_tar(&bytes)
}

/// Składa jedno archiwum z dwóch uszkodzonych kopii, wybierając per wpis tę
/// stronę, której **nagłówek** ma poprawną sumę kontrolną.
///
/// ## Czego to NIE gwarantuje (patrz dokumentacja modułu)
/// Suma kontrolna tar chroni wyłącznie nagłówek. Ten mechanizm zapewnia
/// więc poprawną STRUKTURĘ wynikowego archiwum, ale NIE dowodzi, że dane
/// samych plików są nieuszkodzone — w tar nie ma czym tego sprawdzić.
///
/// Zwraca `None`, gdy:
/// - któraś strona nie parsuje się jako tar,
/// - liczba wpisów się nie zgadza (struktury się rozjechały),
/// - TEN SAM wpis ma uszkodzony nagłówek po OBU stronach.
pub fn splice_tar(bytes_a: &[u8], bytes_b: &[u8]) -> Option<Vec<u8>> {
    let a = analyze_tar(bytes_a)?;
    let b = analyze_tar(bytes_b)?;
    if a.entries.len() != b.entries.len() || a.entries.is_empty() { return None; }

    let mut out = Vec::new();
    for (ea, eb) in a.entries.iter().zip(b.entries.iter()) {
        // REGRESJA (todo.dng_archive_repair.md, ŚREDNI): w odróżnieniu od
        // siostrzanej `zip_splice::splice_zip`, ta funkcja nie sprawdzała w
        // ogóle, czy wpisy na TEJ SAMEJ pozycji mają tę samą nazwę —
        // bezpieczeństwo składania opierało się WYŁĄCZNIE na zgodności
        // LICZBY wpisów. Dwa archiwa o tej samej liczbie wpisów, ale innej
        // zawartości/kolejności (np. dwie różne wersje tego samego archiwum
        // źródłowego, albo dwa niezwiązane archiwa, które przypadkiem mają
        // tyle samo wpisów) mogły zostać cicho "złożone" w bezsensowny,
        // hybrydowy wynik mieszający dane z dwóch niepowiązanych pozycji.
        // Nazwa pusta oznacza nieczytelny nagłówek — bierzemy ją z tej
        // strony, która ją ma; gdy obie są niepuste i się różnią, struktury
        // się rozjechały i nie realignujemy (ten sam wzorzec co splice_zip).
        if !ea.name.is_empty() && !eb.name.is_empty() && ea.name != eb.name {
            return None;
        }

        // Wybieramy stronę ze zdrowym nagłówkiem; przy remisie preferujemy A.
        let (src, entry) = if ea.header_valid && ea.data_complete {
            (bytes_a, ea)
        } else if eb.header_valid && eb.data_complete {
            (bytes_b, eb)
        } else {
            return None;
        };

        let blocks = 1 + (entry.size as usize).div_ceil(BLOCK_SIZE);
        let start = entry.header_offset;
        let end = start + blocks * BLOCK_SIZE;
        if end > src.len() { return None; }
        out.extend_from_slice(&src[start..end]);
    }

    // Prawidłowe zakończenie archiwum: dwa bloki zer.
    out.extend_from_slice(&[0u8; BLOCK_SIZE * 2]);
    Some(out)
}

/// Weryfikuje złożone archiwum: musi mieć wpisy, wszystkie nagłówki
/// poprawne i kompletne dane. Odpowiednik `verify_zip_bytes` z Fazy 18 —
/// z zastrzeżeniem, że dla tar dotyczy to struktury, nie treści plików.
pub fn verify_tar_bytes(bytes: &[u8]) -> bool {
    match analyze_tar(bytes) {
        Some(a) => !a.entries.is_empty() && a.corrupted_headers() == 0 && a.incomplete_entries() == 0,
        None => false,
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

/// Budowniczy prawdziwych archiwów TAR do testów — jedyna kopia w crate'cie
/// (patrz `crate::test_fixtures`, które tylko deleguje tutaj). Mieszka obok
/// reszty logiki formatu TAR, tym samym wzorcem co `png_repair::pomoce_testowe`.
#[cfg(test)]
pub(crate) mod pomoce_testowe {
    use super::*;

    /// Buduje poprawny nagłówek tar z prawidłowo policzoną sumą kontrolną.
    pub fn build_header(name: &str, size: u64) -> Vec<u8> {
        let mut h = vec![0u8; BLOCK_SIZE];
        h[..name.len().min(100)].copy_from_slice(&name.as_bytes()[..name.len().min(100)]);
        let size_field = format!("{:011o}\0", size);
        h[124..124 + size_field.len()].copy_from_slice(size_field.as_bytes());
        h[257..262].copy_from_slice(b"ustar");
        h[262] = b' ';
        h[148..156].copy_from_slice(b"        "); // spacje przed policzeniem
        let sum = compute_header_checksum(&h);
        let sum_field = format!("{:06o}\0 ", sum);
        h[148..148 + sum_field.len()].copy_from_slice(sum_field.as_bytes());
        h
    }

    pub fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in entries {
            out.extend(build_header(name, data.len() as u64));
            let blocks = data.len().div_ceil(BLOCK_SIZE);
            let mut padded = data.to_vec();
            padded.resize(blocks * BLOCK_SIZE, 0);
            out.extend(padded);
        }
        out.extend_from_slice(&[0u8; BLOCK_SIZE * 2]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::pomoce_testowe::{build_header, build_tar};

    /// Psuje sumę kontrolną nagłówka wpisu o podanym indeksie.
    fn corrupt_header(tar: &[u8], entry_idx: usize) -> Vec<u8> {
        let a = analyze_tar(tar).unwrap();
        let mut out = tar.to_vec();
        let off = a.entries[entry_idx].header_offset;
        out[off + CHECKSUM_OFFSET] = b'9'; // rozjazd sumy
        out
    }

    // ------------------------------------------------------------------
    // Podstawy: suma kontrolna i parsowanie
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_octal() {
        assert_eq!(parse_octal(b"00000000033\0"), Some(27));
        assert_eq!(parse_octal(b"0000000\0    "), Some(0));
        assert_eq!(parse_octal(b"\0\0\0"), None);
        assert_eq!(parse_octal(b"999\0"), None, "9 nie jest cyfrą ósemkową");
    }

    #[test]
    fn test_checksum_treats_own_field_as_spaces() {
        // Dwa nagłówki różniące się WYŁĄCZNIE zawartością pola sumy muszą
        // dawać identyczny wynik - to sedno algorytmu.
        let mut h1 = vec![0u8; BLOCK_SIZE];
        h1[0] = b'a';
        let mut h2 = h1.clone();
        h1[CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_LEN].copy_from_slice(b"12345678");
        h2[CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_LEN].copy_from_slice(b"87654321");
        assert_eq!(compute_header_checksum(&h1), compute_header_checksum(&h2));
    }

    #[test]
    fn test_has_ustar_magic() {
        let h = build_header("plik.txt", 10);
        assert!(has_ustar_magic(&h));
        assert!(!has_ustar_magic(&vec![0u8; BLOCK_SIZE]));
    }

    #[test]
    fn test_is_plain_tar_extension_excludes_compressed() {
        assert!(is_plain_tar_extension("archiwum.tar"));
        assert!(is_plain_tar_extension("ARCHIWUM.TAR"));
        // Skompresowane warianty NIE mają czytelnej struktury bloków.
        assert!(!is_plain_tar_extension("archiwum.tar.gz"));
        assert!(!is_plain_tar_extension("archiwum.tgz"));
    }

    // ------------------------------------------------------------------
    // analyze_tar - archiwum zdrowe
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_healthy_archive() {
        let tar = build_tar(&[
            ("plik1.txt", b"zawartosc pierwszego"),
            ("plik2.txt", b"drugi plik, dluzsza tresc"),
            ("katalog/plik3.txt", b"trzeci"),
        ]);
        let a = analyze_tar(&tar).unwrap();
        assert_eq!(a.total_entries(), 3);
        assert_eq!(a.valid_headers(), 3);
        assert_eq!(a.corrupted_headers(), 0);
        assert!(a.has_end_marker);
        assert!(a.is_healthy());
        assert_eq!(a.entries[0].name, "plik1.txt");
        assert_eq!(a.entries[0].size, 20);
    }

    #[test]
    fn test_analyze_rejects_too_short_file() {
        assert!(analyze_tar(b"za krotkie").is_none());
    }

    #[test]
    fn test_analyze_garbage_finds_no_valid_entries() {
        let garbage = vec![0xAAu8; BLOCK_SIZE * 3];
        let a = analyze_tar(&garbage).unwrap();
        assert_eq!(a.valid_headers(), 0, "Śmieci nie mogą dać poprawnych nagłówków");
        assert!(!a.is_healthy());
    }

    // ------------------------------------------------------------------
    // analyze_tar - wykrywanie uszkodzeń
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_detects_corrupted_header() {
        let tar = build_tar(&[("a.txt", b"aaa"), ("b.txt", b"bbb")]);
        let corrupted = corrupt_header(&tar, 0);
        let a = analyze_tar(&corrupted).unwrap();
        assert!(a.corrupted_headers() >= 1, "Rozjazd sumy kontrolnej musi zostać wykryty");
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_continues_past_corrupted_header() {
        // KLUCZOWE dla odzysku: uszkodzenie pierwszego wpisu NIE może
        // przerwać analizy - pozostałe wpisy wciąż są wartościowe.
        let tar = build_tar(&[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")]);
        let corrupted = corrupt_header(&tar, 0);
        let a = analyze_tar(&corrupted).unwrap();
        let found: Vec<&str> = a.entries.iter().filter(|e| e.header_valid).map(|e| e.name.as_str()).collect();
        assert!(found.contains(&"b.txt"), "Wpisy po uszkodzonym muszą zostać znalezione: {:?}", found);
        assert!(found.contains(&"c.txt"));
    }

    #[test]
    fn test_analyze_detects_missing_end_marker() {
        let mut tar = build_tar(&[("a.txt", b"aaa")]);
        tar.truncate(tar.len() - BLOCK_SIZE * 2); // usuwamy znacznik końca
        let a = analyze_tar(&tar).unwrap();
        assert!(!a.has_end_marker);
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_detects_truncated_data() {
        let tar = build_tar(&[("duzy.bin", &vec![0x42u8; 2000])]);
        let truncated = &tar[..BLOCK_SIZE + BLOCK_SIZE]; // nagłówek + 1 blok danych z 4
        let a = analyze_tar(truncated).unwrap();
        assert_eq!(a.incomplete_entries(), 1, "Ucięte dane muszą zostać wykryte");
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_detects_trailing_partial_block() {
        let mut tar = build_tar(&[("a.txt", b"aaa")]);
        tar.extend_from_slice(&[0xFFu8; 100]); // niepełny blok na końcu
        let a = analyze_tar(&tar).unwrap();
        assert_eq!(a.trailing_partial_bytes, 100);
    }

    // ------------------------------------------------------------------
    // splice_tar - kluczowy scenariusz: uszkodzenia w RÓŻNYCH wpisach
    // ------------------------------------------------------------------

    #[test]
    fn test_splice_recovers_when_damage_in_different_entries() {
        let base = build_tar(&[
            ("a.txt", b"zawartosc A"),
            ("b.txt", b"zawartosc B"),
            ("c.txt", b"zawartosc C"),
        ]);
        let side_a = corrupt_header(&base, 0); // zepsuty wpis 0
        let side_b = corrupt_header(&base, 1); // zepsuty wpis 1

        assert!(!verify_tar_bytes(&side_a));
        assert!(!verify_tar_bytes(&side_b));

        let spliced = splice_tar(&side_a, &side_b).expect("złożenie powinno się powieść");
        assert!(verify_tar_bytes(&spliced), "Złożone archiwum musi mieć wszystkie nagłówki poprawne");

        let a = analyze_tar(&spliced).unwrap();
        assert_eq!(a.total_entries(), 3);
        assert!(a.is_healthy());
    }

    #[test]
    fn test_splice_preserves_content() {
        let base = build_tar(&[("a.txt", b"tresc pierwsza"), ("b.txt", b"tresc druga")]);
        let spliced = splice_tar(&corrupt_header(&base, 0), &corrupt_header(&base, 1)).unwrap();
        let a = analyze_tar(&spliced).unwrap();
        assert_eq!(a.entries[0].name, "a.txt");
        assert_eq!(a.entries[1].name, "b.txt");
        assert_eq!(a.entries[0].size, 14);
    }

    #[test]
    fn test_splice_fails_when_same_entry_corrupted_on_both_sides() {
        let base = build_tar(&[("a.txt", b"aaa"), ("b.txt", b"bbb")]);
        let side_a = corrupt_header(&base, 0);
        let side_b = corrupt_header(&base, 0); // TEN SAM wpis
        assert!(splice_tar(&side_a, &side_b).is_none());
    }

    #[test]
    fn test_splice_fails_on_different_entry_counts() {
        let a = build_tar(&[("a.txt", b"aaa"), ("b.txt", b"bbb")]);
        let b = build_tar(&[("a.txt", b"aaa")]);
        assert!(splice_tar(&a, &b).is_none());
    }

    /// REGRESJA (todo.dng_archive_repair.md, ŚREDNI): w odróżnieniu od
    /// siostrzanej `zip_splice::splice_zip`, `splice_tar` nie sprawdzało w
    /// ogóle, czy wpisy na tej samej pozycji mają tę samą nazwę — poleganie
    /// WYŁĄCZNIE na zgodności liczby wpisów pozwalało "złożyć" dwa RÓŻNE
    /// archiwa o przypadkowo tej samej liczbie wpisów w bezsensowny,
    /// hybrydowy wynik. Tu: te same liczby (2), ta sama nazwa na pozycji 0,
    /// ale zupełnie inna nazwa na pozycji 1 — musi się to teraz zablokować.
    #[test]
    fn test_splice_fails_when_entry_names_diverge_at_same_position() {
        let a = build_tar(&[("wspolny.txt", b"aaa"), ("tylko_w_a.txt", b"bbb")]);
        let b = build_tar(&[("wspolny.txt", b"aaa"), ("zupelnie_inny_plik.bin", b"ccc")]);

        assert!(
            splice_tar(&a, &b).is_none(),
            "wpisy o różnych nazwach na tej samej pozycji nie mogą zostać cicho złożone - struktury się rozjechały"
        );
    }

    #[test]
    fn test_splice_healthy_pair_produces_valid_archive() {
        let base = build_tar(&[("a.txt", b"aaa"), ("b.txt", b"bbb")]);
        let spliced = splice_tar(&base, &base).expect("dwie zdrowe kopie powinny się złożyć");
        assert!(verify_tar_bytes(&spliced));
    }

    // ------------------------------------------------------------------
    // verify_tar_bytes
    // ------------------------------------------------------------------

    #[test]
    fn test_verify_accepts_healthy_rejects_damaged() {
        let tar = build_tar(&[("a.txt", b"aaa")]);
        assert!(verify_tar_bytes(&tar));
        assert!(!verify_tar_bytes(&corrupt_header(&tar, 0)));
        assert!(!verify_tar_bytes(b"nie jest to archiwum tar w ogole"));
        assert!(!verify_tar_bytes(&vec![0u8; BLOCK_SIZE * 2]), "Samo puste zakończenie to nie archiwum");
    }

    #[test]
    fn test_describe_healthy_and_damaged() {
        let tar = build_tar(&[("a.txt", b"aaa"), ("b.txt", b"bbb")]);
        assert!(analyze_tar(&tar).unwrap().describe().contains("spójne"));
        let d = analyze_tar(&corrupt_header(&tar, 0)).unwrap().describe();
        assert!(d.contains("nagłówk"), "Opis powinien wymienić uszkodzone nagłówki: {}", d);
    }

    // ------------------------------------------------------------------
    // Prawdziwe archiwum z systemowego `tar`
    // ------------------------------------------------------------------

    #[test]
    #[ignore = "Wymaga prawdziwego archiwum tar. Wygeneruj: \
                mkdir -p /tmp/tartest && cd /tmp/tartest && echo test > a.txt && \
                echo test2 > b.txt && tar cf image/test_fixture.tar a.txt b.txt \
                Potem: `cargo test analyze_real_tar_fixture -- --ignored --nocapture`."]
    fn test_analyze_real_tar_fixture() {
        let a = analyze_tar_file(std::path::Path::new("image/test_fixture.tar"))
            .expect("Prawdziwe archiwum tar powinno się sparsować");
        println!("✔ {}", a.describe());
        for e in &a.entries {
            println!("   {} ({} B) nagłówek_ok={}", e.name, e.size, e.header_valid);
        }
        assert!(a.is_healthy(), "Świeżo utworzone archiwum powinno być spójne");
    }
}
