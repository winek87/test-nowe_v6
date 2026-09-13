// src/zip_splice.rs

//! # Składanie Archiwów ZIP-podobnych z Dwóch Uszkodzonych Kopii
//!
//! Obsługuje wszystkie formaty oparte na kontenerze ZIP: `.zip`, `.docx`,
//! `.xlsx`, `.pptx`, `.odt`, `.ods`, `.odp`, `.epub`, `.jar`, `.apk`.
//!
//! ## Dlaczego to jest MOCNY mechanizm (jak PNG, nie jak DNG)
//!
//! Każdy wpis w archiwum ZIP ma **własną sumę kontrolną CRC32**, dokładnie
//! jak chunki PNG. Co więcej — zweryfikowane empirycznie na prawdziwym
//! archiwum — crate `zip` **sam sprawdza to CRC podczas czytania**: odczyt
//! uszkodzonego wpisu zwraca `Err`, podczas gdy nietknięty wpis w TYM SAMYM,
//! uszkodzonym archiwum czyta się poprawnie. Nie musimy więc liczyć CRC
//! ręcznie — dostajemy obiektywny, per-wpis dowód poprawności za darmo.
//!
//! To stawia archiwa w tej samej klasie co PNG/JPEG w Fazie 18 (twarda
//! weryfikacja), a NIE w klasie DNG (`StructuralOnly`, brak dowodu na treść).
//!
//! ## Algorytm
//! 1. Otwórz obie kopie, wylistuj wpisy.
//! 2. Dla każdego wpisu: weź zawartość z tej strony, gdzie czyta się bez błędu.
//! 3. Zbuduj NOWE archiwum z zebranych, zweryfikowanych wpisów.
//! 4. Wynik przechodzi obowiązkową weryfikację ([`verify_zip_bytes`]) —
//!    ponowne otwarcie i odczyt KAŻDEGO wpisu. Brak tego = zero zapisu.

use std::io::{Cursor, Read, Write};
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};

/// Rozpoznaje rozszerzenia oparte na kontenerze ZIP.
pub fn is_zip_based_extension(path_str: &str) -> bool {
    let lower = path_str.to_lowercase();
    [".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub", ".jar", ".apk"]
        .iter().any(|ext| lower.ends_with(ext))
}

/// Wynik próby odczytu jednego wpisu — treść albo informacja o uszkodzeniu.
struct EntryRead {
    name: String,
    content: Option<Vec<u8>>,
}

/// Czyta WSZYSTKIE wpisy archiwum, zwracając dla każdego treść (gdy CRC się
/// zgadza) albo `None` (gdy odczyt zawiódł — uszkodzony strumień). Zwraca
/// `None` dla całości, gdy samo archiwum się nie otwiera (zniszczony EOCD).
fn read_all_entries(bytes: &[u8]) -> Option<Vec<EntryRead>> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).ok()?;
    let mut out = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(i) else {
            // Sam nagłówek wpisu nieczytelny - zachowujemy pozycję z pustą
            // nazwą, żeby indeksy obu stron pozostały porównywalne.
            out.push(EntryRead { name: String::new(), content: None });
            continue;
        };
        // Nazwa MUSI być skopiowana przed read_to_end - inaczej błąd
        // pożyczenia E0502 (ten sam, który naprawialiśmy w Fazie 11).
        let name = entry.name().to_string();
        let is_dir = entry.is_dir();
        let mut content = Vec::new();
        let content = if is_dir {
            Some(Vec::new())
        } else if entry.read_to_end(&mut content).is_ok() {
            Some(content)
        } else {
            None
        };
        out.push(EntryRead { name, content });
    }
    Some(out)
}

/// Składa jedno archiwum z dwóch uszkodzonych kopii, wybierając per wpis tę
/// stronę, której CRC32 się zgadza. Zwraca `None`, gdy:
/// - żadna strona się nie otwiera,
/// - struktury się rozjeżdżają (różne nazwy wpisów na tej samej pozycji —
///   nie próbujemy realignować, to sygnał głębszego uszkodzenia),
/// - TEN SAM wpis jest uszkodzony w OBU kopiach (nie ma z czego wybrać).
///
/// Wynik NIE jest tu weryfikowany — to zadanie wywołującego (patrz
/// [`verify_zip_bytes`]), analogicznie do rozdziału odpowiedzialności w Fazie 18.
pub fn splice_zip(bytes_a: &[u8], bytes_b: &[u8]) -> Option<Vec<u8>> {
    let entries_a = read_all_entries(bytes_a);
    let entries_b = read_all_entries(bytes_b);

    let (entries_a, entries_b) = match (entries_a, entries_b) {
        (Some(a), Some(b)) => (a, b),
        // Gdy tylko jedna strona się otwiera, składanie nie ma sensu -
        // to zwykły wybór całościowy, który i tak zrobi Faza 8/9.
        _ => return None,
    };

    if entries_a.len() != entries_b.len() || entries_a.is_empty() { return None; }

    let mut out: Vec<u8> = Vec::new();
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut out));
        for (a, b) in entries_a.iter().zip(entries_b.iter()) {
            // Nazwa pusta oznacza nieczytelny nagłówek wpisu - bierzemy nazwę
            // z tej strony, która ją ma; gdy obie puste, nie da się złożyć.
            let name = if !a.name.is_empty() { &a.name } else if !b.name.is_empty() { &b.name } else { return None; };
            if !a.name.is_empty() && !b.name.is_empty() && a.name != b.name { return None; }

            let content = a.content.as_ref().or(b.content.as_ref())?;

            if name.ends_with('/') {
                writer.add_directory(name.clone(), SimpleFileOptions::default()).ok()?;
            } else {
                writer.start_file(name.clone(), SimpleFileOptions::default()).ok()?;
                writer.write_all(content).ok()?;
            }
        }
        writer.finish().ok()?;
    }
    Some(out)
}

/// Obowiązkowa weryfikacja złożonego archiwum: musi się otworzyć ORAZ każdy
/// jego wpis musi się poprawnie odczytać (co crate `zip` sprawdza przez
/// CRC32). To odpowiednik `verify_image_bytes` z Fazy 18 dla JPG/PNG —
/// jedyny warunek zaakceptowania wyniku i zapisania czegokolwiek na dysk.
pub fn verify_zip_bytes(bytes: &[u8]) -> bool {
    let Ok(mut archive) = ZipArchive::new(Cursor::new(bytes)) else { return false; };
    if archive.is_empty() { return false; }
    for i in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(i) else { return false; };
        if entry.is_dir() { continue; }
        let mut sink = Vec::new();
        if entry.read_to_end(&mut sink).is_err() { return false; }
    }
    true
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

/// Budowniczy prawdziwych archiwów ZIP do testów — jedyna kopia w crate'cie
/// (patrz `crate::test_fixtures`, które tylko deleguje tutaj). Mieszka obok
/// reszty logiki formatu ZIP, tym samym wzorcem co `png_repair::pomoce_testowe`
/// i `jpeg_splice::pomoce_testowe`.
#[cfg(test)]
pub(crate) mod pomoce_testowe {
    use super::*;

    /// Buduje prawdziwe archiwum ZIP z podanych par (nazwa, treść).
    pub fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = ZipWriter::new(Cursor::new(&mut buf));
            for (name, content) in entries {
                w.start_file(*name, SimpleFileOptions::default()).unwrap(); // <-- TUTAJ
                w.write_all(content).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::pomoce_testowe::build_zip;

    /// Psuje jeden bajt pod podanym offsetem — symuluje uszkodzenie
    /// strumienia skompresowanego (CRC przestanie się zgadzać przy odczycie).
    fn corrupt_byte(data: &[u8], offset: usize) -> Vec<u8> {
        let mut out = data.to_vec();
        out[offset] ^= 0xFF;
        out
    }

    /// Znajduje offset, którego uszkodzenie psuje DOKŁADNIE wpis o podanym
    /// indeksie (a nie inny) — szuka empirycznie, bo dokładny układ bajtów
    /// zależy od implementacji kompresji.
    fn find_offset_breaking_entry(base: &[u8], target_idx: usize) -> Option<usize> {
        for offset in 30..base.len().saturating_sub(60) {
            let corrupted = corrupt_byte(base, offset);
            let Some(entries) = read_all_entries(&corrupted) else { continue; };
            if entries.len() != read_all_entries(base)?.len() { continue; }
            let broken: Vec<usize> = entries.iter().enumerate()
                .filter(|(_, e)| e.content.is_none()).map(|(i, _)| i).collect();
            if broken.len() == 1 && broken[0] == target_idx {
                return Some(offset);
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // is_zip_based_extension
    // ------------------------------------------------------------------

    #[test]
    fn test_is_zip_based_extension_recognizes_office_formats() {
        assert!(is_zip_based_extension("dokument.docx"));
        assert!(is_zip_based_extension("arkusz.XLSX"));
        assert!(is_zip_based_extension("prezentacja.pptx"));
        assert!(is_zip_based_extension("archiwum.zip"));
        assert!(is_zip_based_extension("ksiazka.epub"));
        assert!(!is_zip_based_extension("zdjecie.jpg"));
        assert!(!is_zip_based_extension("plik.rar"));
    }

    // ------------------------------------------------------------------
    // verify_zip_bytes
    // ------------------------------------------------------------------

    #[test]
    fn test_verify_accepts_healthy_archive() {
        let zip = build_zip(&[("a.txt", b"tresc A"), ("b.txt", b"tresc B")]);
        assert!(verify_zip_bytes(&zip));
    }

    #[test]
    fn test_verify_rejects_garbage() {
        assert!(!verify_zip_bytes(b"to na pewno nie jest archiwum ZIP"));
    }

    #[test]
    fn test_verify_rejects_empty_archive() {
        let empty = build_zip(&[]);
        assert!(!verify_zip_bytes(&empty), "Puste archiwum to wydmuszka - nie akceptujemy");
    }

    #[test]
    fn test_verify_rejects_archive_with_corrupted_entry() {
        let zip = build_zip(&[("a.txt", b"dluzsza tresc do uszkodzenia"), ("b.txt", b"druga tresc")]);
        let offset = find_offset_breaking_entry(&zip, 0).expect("powinien istnieć offset psujący wpis 0");
        let corrupted = corrupt_byte(&zip, offset);
        assert!(!verify_zip_bytes(&corrupted), "Archiwum z uszkodzonym wpisem musi zostać odrzucone");
    }

    // ------------------------------------------------------------------
    // splice_zip - kluczowy scenariusz: uszkodzenia w RÓŻNYCH wpisach
    // ------------------------------------------------------------------

    #[test]
    fn test_splice_recovers_when_damage_is_in_different_entries() {
        let base = build_zip(&[
            ("a.txt", b"zawartosc pliku A wystarczajaco dluga"),
            ("b.txt", b"zawartosc pliku B wystarczajaco dluga"),
            ("c.txt", b"zawartosc pliku C wystarczajaco dluga"),
        ]);

        let off_a = find_offset_breaking_entry(&base, 0).expect("offset psujący wpis 0");
        let off_b = find_offset_breaking_entry(&base, 1).expect("offset psujący wpis 1");
        let side_a = corrupt_byte(&base, off_a); // zepsuty wpis 0
        let side_b = corrupt_byte(&base, off_b); // zepsuty wpis 1

        // Każda strona z osobna jest niesprawna...
        assert!(!verify_zip_bytes(&side_a));
        assert!(!verify_zip_bytes(&side_b));

        // ...ale złożenie daje w pełni sprawne archiwum.
        let spliced = splice_zip(&side_a, &side_b).expect("złożenie powinno się powieść");
        assert!(verify_zip_bytes(&spliced), "Złożone archiwum musi przejść pełną weryfikację CRC");
    }

    #[test]
    fn test_splice_preserves_original_content() {
        let base = build_zip(&[
            ("a.txt", b"oryginalna tresc A dostatecznie dluga"),
            ("b.txt", b"oryginalna tresc B dostatecznie dluga"),
        ]);
        let off_a = find_offset_breaking_entry(&base, 0).expect("offset psujący wpis 0");
        let off_b = find_offset_breaking_entry(&base, 1).expect("offset psujący wpis 1");

        let spliced = splice_zip(&corrupt_byte(&base, off_a), &corrupt_byte(&base, off_b)).unwrap();

        let mut archive = ZipArchive::new(Cursor::new(&spliced)).unwrap();
        let mut found = Vec::new();
        for i in 0..archive.len() {
            let mut e = archive.by_index(i).unwrap();
            let name = e.name().to_string();
            let mut c = Vec::new();
            e.read_to_end(&mut c).unwrap();
            found.push((name, c));
        }
        assert_eq!(found[0].0, "a.txt");
        assert_eq!(found[0].1, b"oryginalna tresc A dostatecznie dluga");
        assert_eq!(found[1].0, "b.txt");
        assert_eq!(found[1].1, b"oryginalna tresc B dostatecznie dluga");
    }

    #[test]
    fn test_splice_fails_when_same_entry_corrupted_on_both_sides() {
        let base = build_zip(&[
            ("a.txt", b"zawartosc pliku A wystarczajaco dluga"),
            ("b.txt", b"zawartosc pliku B wystarczajaco dluga"),
        ]);
        let off = find_offset_breaking_entry(&base, 0).expect("offset psujący wpis 0");
        let side_a = corrupt_byte(&base, off);
        let side_b = corrupt_byte(&base, off); // TEN SAM wpis zepsuty po obu stronach

        assert!(splice_zip(&side_a, &side_b).is_none(), "Brak zdrowej kopii wpisu po którejkolwiek stronie - nie da się złożyć");
    }

    #[test]
    fn test_splice_rejects_structurally_different_archives() {
        let a = build_zip(&[("a.txt", b"tresc"), ("b.txt", b"tresc")]);
        let b = build_zip(&[("a.txt", b"tresc"), ("INNA_NAZWA.txt", b"tresc")]);
        assert!(splice_zip(&a, &b).is_none(), "Rozjazd nazw wpisów nie powinien być naprawiany");
    }

    #[test]
    fn test_splice_rejects_different_entry_counts() {
        let a = build_zip(&[("a.txt", b"tresc"), ("b.txt", b"tresc")]);
        let b = build_zip(&[("a.txt", b"tresc")]);
        assert!(splice_zip(&a, &b).is_none());
    }

    #[test]
    fn test_splice_returns_none_when_one_side_unopenable() {
        let healthy = build_zip(&[("a.txt", b"tresc")]);
        let garbage = b"to nie jest archiwum".to_vec();
        assert!(splice_zip(&garbage, &healthy).is_none());
        assert!(splice_zip(&healthy, &garbage).is_none());
    }

    #[test]
    fn test_splice_healthy_pair_produces_valid_archive() {
        // Obie strony zdrowe - złożenie nadal powinno dać poprawne archiwum
        // (nieszkodliwy przypadek, choć w praktyce Faza 18 go nie wywoła).
        let base = build_zip(&[("a.txt", b"tresc A"), ("b.txt", b"tresc B")]);
        let spliced = splice_zip(&base, &base).expect("dwie zdrowe kopie powinny się złożyć");
        assert!(verify_zip_bytes(&spliced));
    }

    /// Archiwum z PRAWDZIWEGO archiwizatora, nie zbudowane w pamięci przez
    /// crate `zip`. Różne implementacje inaczej zapisują EOCD i nagłówki
    /// lokalne, więc syntetyczne archiwum nie dowodzi zgodności z materiałem
    /// z zewnątrz.
    #[test]
    #[ignore = "Wymaga image/test_fixture.zip. Uruchom z --ignored."]
    fn test_prawdziwe_archiwum_przechodzi_weryfikacje() {
        let bajty = std::fs::read("image/test_fixture.zip").expect("fixture musi istnieć");
        assert!(verify_zip_bytes(&bajty), "Zdrowe archiwum z archiwizatora musi przejść CRC32");
    }

    #[test]
    #[ignore = "Wymaga image/test_fixture.zip. Uruchom z --ignored."]
    fn test_uciete_prawdziwe_archiwum_jest_odrzucone() {
        let pelny = std::fs::read("image/test_fixture.zip").expect("fixture musi istnieć");
        let uciety = &pelny[..pelny.len() / 2];
        assert!(
            !verify_zip_bytes(uciety),
            "Ucięte archiwum traci katalog centralny i MUSI zostać odrzucone"
        );
    }
}
