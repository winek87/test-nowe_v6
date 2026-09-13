// src/phases/repair_modules/splice.rs

//! Moduł naprawczy: zszywanie strumieniowe dwóch uciętych fragmentów (UFS + Skrypt).

use super::{RepairContext, RepairModule};
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

/// Rozmiar bufora odczytu jednej strony (zabezpieczenie OOM — nie ładujemy
/// całych plików do RAM, niezależnie od ich rozmiaru).
const ROZMIAR_BUFORA: usize = 131_072; // 128 KB

pub struct SpliceModule;

/// Wypełnia bufor danymi ze strumienia, powtarzając odczyt aż do zapełnienia
/// bufora ALBO osiągnięcia końca pliku. Zwraca liczbę wczytanych bajtów.
///
/// ## Dlaczego to jest konieczne (naprawiony bug desynchronizacji)
///
/// `Read::read` wolno zwrócić MNIEJ bajtów, niż zmieści się w buforze, bez
/// osiągnięcia końca pliku — tak zwany krótki odczyt. Poprzednia wersja
/// zszywania wołała `read` po jednym razie na stronę i parowała wynik pozycja
/// w pozycję. Gdy jedna strona zwróciła krótki odczyt, a druga pełny, dalsze
/// iteracje czytały OBIE strony od rozjechanych offsetów i zszywały bajty z
/// NIEODPOWIADAJĄCYCH SOBIE pozycji — plik „naprawiony" wychodził cicho
/// uszkodzony, bez żadnego błędu.
///
/// Po zapełnieniu bufora tą funkcją krótki odczyt oznacza już wyłącznie koniec
/// pliku, więc obie strony postępują dokładnie tym samym krokiem.
///
/// `ErrorKind::Interrupted` (EINTR) jest ponawiane — to nie błąd, tylko
/// przerwanie sygnałem. Każdy inny błąd zwraca `None`: odróżnienie realnego
/// błędu I/O od końca pliku jest tu krytyczne, bo traktowanie go jak EOF dawało
/// cicho UCIĘTY wynik.
fn wypelnij_bufor(strumien: &mut impl Read, bufor: &mut [u8]) -> Option<usize> {
    let mut wczytane = 0;

    while wczytane < bufor.len() {
        match strumien.read(&mut bufor[wczytane..]) {
            Ok(0) => break, // koniec pliku
            Ok(n) => wczytane += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }

    Some(wczytane)
}

/// Zszywa dwa strumienie bajt po bajcie do strumienia wyjściowego.
///
/// Dla każdej pozycji wybiera wartość NIEZEROWĄ, preferując `a` nad `b` przy
/// konflikcie obu niezerowych. Wydzielone z [`SpliceModule::repair`], żeby
/// wywołujący mógł po nieudanym zszyciu posprzątać plik częściowy.
fn zszyj_strumienie(a: &mut impl Read, b: &mut impl Read, wyjscie: &mut impl Write) -> Option<()> {
    let mut buf_a = [0u8; ROZMIAR_BUFORA];
    let mut buf_b = [0u8; ROZMIAR_BUFORA];
    let mut zszyte = [0u8; ROZMIAR_BUFORA];

    loop {
        let n_a = wypelnij_bufor(a, &mut buf_a)?;
        let n_b = wypelnij_bufor(b, &mut buf_b)?;

        if n_a == 0 && n_b == 0 { break; }

        let dlugosc = std::cmp::max(n_a, n_b);

        for i in 0..dlugosc {
            let bajt_a = if i < n_a { buf_a[i] } else { 0 };
            let bajt_b = if i < n_b { buf_b[i] } else { 0 };

            // Priorytet dla niezerowych bajtów z A, potem B.
            zszyte[i] = if bajt_a != 0 { bajt_a } else { bajt_b };
        }

        wyjscie.write_all(&zszyte[..dlugosc]).ok()?;
    }

    Some(())
}

impl RepairModule for SpliceModule {
    fn id(&self) -> &'static str { "splice" }
    fn display_name(&self) -> &'static str { "Zszywanie fragmentów (korelacja Fazy 14)" }

    /// Stosuje się, gdy korelacja Fazy 14 sklasyfikowała parę wersji pliku
    /// jako `"PARTIAL"` (częściowe podobieństwo — sugeruje, że dwie kopie
    /// mają różne fragmenty ucięte/zniszczone, więc złożenie ich razem
    /// bajt-po-bajcie może dać komplet).
    fn applies_to(&self, ctx: &RepairContext) -> bool {
        ctx.match_type == Some("PARTIAL")
    }

    /// Czyta OBA pliki strumieniowo (bufor 128 KB — bezpieczne dla RAM
    /// niezależnie od rozmiaru wejścia) i dla każdej pozycji bajtu wybiera
    /// wartość NIEZEROWĄ, preferując źródło `source` nad `twin` przy
    /// konflikcie obu niezerowych.
    ///
    /// Zwraca `None`, gdy: `twin` nie podano (ten moduł bezwzględnie go
    /// wymaga), któregoś pliku nie da się otworzyć, albo wystąpił błąd I/O w
    /// trakcie zszywania. W tym ostatnim przypadku plik częściowo zapisany
    /// jest USUWANY — patrz niżej.
    fn repair(&self, source: &Path, _ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let twin_path = twin?;
        let mut file_a = File::open(source).ok()?;
        let mut file_b = File::open(twin_path).ok()?;

        let stem = source.file_stem()?.to_str()?;
        let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("bin");

        let target = katalog_wyjsciowy.join(format!("{}_spliced.{}", stem, ext));
        let mut out_file = File::create(&target).ok()?;

        let wynik = zszyj_strumienie(&mut file_a, &mut file_b, &mut out_file);

        if wynik.is_none() {
            // Błąd I/O w połowie zszywania zostawiłby na dysku plik z sufiksem
            // `_spliced`, wyglądający na gotowy wynik naprawy, a w istocie
            // ucięty. Orkiestrator nie zapisze go do bazy (dostaje `None`), ale
            // plik leżałby w katalogu i wprowadzał w błąd przy ręcznej analizie
            // oraz przy kolejnym mapowaniu struktury. Usuwamy go.
            drop(out_file);
            let _ = std::fs::remove_file(&target);
            return None;
        }

        Some((target, "Wykonano fizyczny Splicing strumieniowy (bezpieczne dla RAM).".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dummy_ctx(match_type: Option<&'static str>) -> RepairContext<'static> {
        RepairContext { ext: "bin", media_reason: None, utf8_ok: None, is_oneliner: None, eof_ok: None, match_type, video_ok: None, structure_ok: None }
    }

    #[test]
    fn test_applies_to_partial_match() {
        let m = SpliceModule;
        assert!(m.applies_to(&dummy_ctx(Some("PARTIAL"))));
    }

    #[test]
    fn test_does_not_apply_to_other_match_types() {
        let m = SpliceModule;
        assert!(!m.applies_to(&dummy_ctx(Some("TWIN"))));
        assert!(!m.applies_to(&dummy_ctx(None)));
    }

    #[test]
    fn test_repair_returns_none_without_twin() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.bin");
        std::fs::write(&path, b"dane").unwrap();

        let m = SpliceModule;
        assert!(m.repair(&path, &dummy_ctx(Some("PARTIAL")), None, dir.path()).is_none());
    }

    #[test]
    fn test_repair_merges_nonzero_bytes_preferring_source() {
        let dir = tempdir().unwrap();
        let path_a = dir.path().join("a.bin");
        let path_b = dir.path().join("b.bin");

        // A ma zera tam, gdzie B ma dane - i odwrotnie; tam gdzie oba niezerowe, A wygrywa
        std::fs::write(&path_a, [0x00, 0x00, 0xAA, 0xFF]).unwrap();
        std::fs::write(&path_b, [0xBB, 0xCC, 0x00, 0x11]).unwrap();

        let m = SpliceModule;
        let (target, _log) = m.repair(&path_a, &dummy_ctx(Some("PARTIAL")), Some(&path_b), dir.path()).expect("zszycie powinno się powieść");
        let result = std::fs::read(&target).unwrap();
        assert_eq!(result, vec![0xBB, 0xCC, 0xAA, 0xFF]);
    }

    // ------------------------------------------------------------------
    // REGRESJA: desynchronizacja przy KRÓTKIM ODCZYCIE
    //
    // Poprzednia wersja wołała `read` raz na stronę i parowała wyniki pozycja
    // w pozycję. Gdy jedna strona zwróciła mniej bajtów niż druga (bez końca
    // pliku), dalsze iteracje zszywały bajty z rozjechanych offsetów — cicha
    // korupcja. Testy niżej wymuszają dokładnie ten scenariusz.
    // ------------------------------------------------------------------

    /// Strumień oddający dane w porcjach po `porcja` bajtów — symuluje KRÓTKI
    /// ODCZYT, do którego `Read::read` ma pełne prawo.
    struct UrywanyStrumien { dane: Vec<u8>, pozycja: usize, porcja: usize }

    impl Read for UrywanyStrumien {
        fn read(&mut self, bufor: &mut [u8]) -> std::io::Result<usize> {
            let zostalo = self.dane.len() - self.pozycja;
            if zostalo == 0 { return Ok(0); }
            let n = self.porcja.min(zostalo).min(bufor.len());
            bufor[..n].copy_from_slice(&self.dane[self.pozycja..self.pozycja + n]);
            self.pozycja += n;
            Ok(n)
        }
    }

    /// Strumień, który po oddaniu `przed_bledem` bajtów zwraca błąd I/O.
    struct StrumienZBledem { przed_bledem: usize, oddane: usize }

    impl Read for StrumienZBledem {
        fn read(&mut self, bufor: &mut [u8]) -> std::io::Result<usize> {
            if self.oddane >= self.przed_bledem {
                return Err(std::io::Error::other("symulowany błąd I/O"));
            }
            let n = bufor.len().min(self.przed_bledem - self.oddane);
            for b in &mut bufor[..n] { *b = 0xAA; }
            self.oddane += n;
            Ok(n)
        }
    }

    /// Dane zależne od POZYCJI — każde przesunięcie offsetu zmienia wynik,
    /// więc test wykrywa desynchronizację, a nie tylko zły rozmiar.
    fn dane_testowe(dlugosc: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let a: Vec<u8> = (0..dlugosc)
            .map(|i| if i % 2 == 0 { 0 } else { ((i % 255) + 1) as u8 })
            .collect();
        let b: Vec<u8> = (0..dlugosc).map(|i| ((i % 251) + 1) as u8).collect();
        let oczekiwane: Vec<u8> = (0..dlugosc)
            .map(|i| if a[i] != 0 { a[i] } else { b[i] })
            .collect();
        (a, b, oczekiwane)
    }

    #[test]
    fn test_wypelnij_bufor_sklada_krotkie_odczyty() {
        let mut strumien = UrywanyStrumien { dane: vec![7u8; 1000], pozycja: 0, porcja: 3 };
        let mut bufor = [0u8; 1000];

        let n = wypelnij_bufor(&mut strumien, &mut bufor).unwrap();
        assert_eq!(n, 1000, "Bufor musi zostać zapełniony w całości, mimo porcji po 3 bajty");
        assert!(bufor.iter().all(|&b| b == 7));
    }

    #[test]
    fn test_wypelnij_bufor_zwraca_none_przy_bledzie_a_nie_zero() {
        let mut strumien = StrumienZBledem { przed_bledem: 10, oddane: 0 };
        let mut bufor = [0u8; 1000];

        assert!(
            wypelnij_bufor(&mut strumien, &mut bufor).is_none(),
            "Błąd I/O NIE może być zgłoszony jako koniec pliku - to dawało cicho ucięty wynik"
        );
    }

    #[test]
    fn test_zszywanie_odporne_na_krotki_odczyt_jednej_strony() {
        // Ponad dwa pełne bufory (128 KB), żeby wymusić wiele iteracji pętli.
        let dlugosc = ROZMIAR_BUFORA * 2 + 5_000;
        let (a, b, oczekiwane) = dane_testowe(dlugosc);

        // Strona A oddaje po 7 bajtów na odczyt, strona B po pełnym buforze.
        let mut strumien_a = UrywanyStrumien { dane: a, pozycja: 0, porcja: 7 };
        let mut strumien_b = UrywanyStrumien { dane: b, pozycja: 0, porcja: ROZMIAR_BUFORA };
        let mut wyjscie: Vec<u8> = Vec::new();

        zszyj_strumienie(&mut strumien_a, &mut strumien_b, &mut wyjscie).expect("zszycie powinno się powieść");

        assert_eq!(wyjscie.len(), dlugosc, "Rozmiar wyniku");
        assert_eq!(wyjscie, oczekiwane, "Bajty muszą pochodzić z ODPOWIADAJĄCYCH SOBIE pozycji obu stron");
    }

    #[test]
    fn test_zszywanie_gdy_obie_strony_urywaja_inaczej() {
        let dlugosc = ROZMIAR_BUFORA + 777;
        let (a, b, oczekiwane) = dane_testowe(dlugosc);

        let mut strumien_a = UrywanyStrumien { dane: a, pozycja: 0, porcja: 13 };
        let mut strumien_b = UrywanyStrumien { dane: b, pozycja: 0, porcja: 101 };
        let mut wyjscie: Vec<u8> = Vec::new();

        zszyj_strumienie(&mut strumien_a, &mut strumien_b, &mut wyjscie).unwrap();
        assert_eq!(wyjscie, oczekiwane);
    }

    #[test]
    fn test_zszywanie_stron_o_roznej_dlugosci_ponad_granica_bufora() {
        // A dłuższa niż dwa bufory, B krótsza niż jeden - po wyczerpaniu B
        // reszta musi pochodzić wyłącznie z A, bez przesunięcia.
        let dlugosc_a = ROZMIAR_BUFORA * 2 + 100;
        let dlugosc_b = 5_000;

        let a: Vec<u8> = (0..dlugosc_a).map(|i| ((i % 255) + 1) as u8).collect();
        let b: Vec<u8> = vec![0xFF; dlugosc_b];
        // A jest wszędzie niezerowa, więc wygrywa na całej długości.
        let oczekiwane = a.clone();

        let mut strumien_a = UrywanyStrumien { dane: a, pozycja: 0, porcja: 9 };
        let mut strumien_b = UrywanyStrumien { dane: b, pozycja: 0, porcja: 4_096 };
        let mut wyjscie: Vec<u8> = Vec::new();

        zszyj_strumienie(&mut strumien_a, &mut strumien_b, &mut wyjscie).unwrap();
        assert_eq!(wyjscie.len(), dlugosc_a);
        assert_eq!(wyjscie, oczekiwane);
    }

    #[test]
    fn test_zszywanie_krotszej_strony_a_niz_b() {
        // Odwrotnie: A krótsza, B dłuższa - ogon musi przyjść z B.
        let dlugosc_a = 3_000;
        let dlugosc_b = ROZMIAR_BUFORA + 2_000;

        let a: Vec<u8> = vec![0x00; dlugosc_a]; // same zera, więc nigdy nie wygrywa
        let b: Vec<u8> = (0..dlugosc_b).map(|i| ((i % 253) + 1) as u8).collect();
        let oczekiwane = b.clone();

        let mut strumien_a = UrywanyStrumien { dane: a, pozycja: 0, porcja: 11 };
        let mut strumien_b = UrywanyStrumien { dane: b, pozycja: 0, porcja: 6_000 };
        let mut wyjscie: Vec<u8> = Vec::new();

        zszyj_strumienie(&mut strumien_a, &mut strumien_b, &mut wyjscie).unwrap();
        assert_eq!(wyjscie, oczekiwane);
    }

    #[test]
    fn test_zszywanie_zwraca_none_gdy_strona_sypie_bledem() {
        let mut strumien_a = StrumienZBledem { przed_bledem: 100, oddane: 0 };
        let mut strumien_b = UrywanyStrumien { dane: vec![1u8; 5_000], pozycja: 0, porcja: 5_000 };
        let mut wyjscie: Vec<u8> = Vec::new();

        assert!(
            zszyj_strumienie(&mut strumien_a, &mut strumien_b, &mut wyjscie).is_none(),
            "Błąd I/O musi przerwać zszywanie, a nie dać cicho ucięty plik"
        );
    }

    #[test]
    fn test_repair_na_duzych_plikach_daje_poprawne_zszycie() {
        // Test przez PRAWDZIWE pliki na dysku, nie mocki - ponad dwa bufory.
        let dir = tempdir().unwrap();
        let dlugosc = ROZMIAR_BUFORA * 2 + 333;
        let (a, b, oczekiwane) = dane_testowe(dlugosc);

        let path_a = dir.path().join("duzy.bin");
        let path_b = dir.path().join("blizniak.bin");
        std::fs::write(&path_a, &a).unwrap();
        std::fs::write(&path_b, &b).unwrap();

        let m = SpliceModule;
        let (target, _) = m.repair(&path_a, &dummy_ctx(Some("PARTIAL")), Some(&path_b), dir.path()).expect("zszycie powinno się powieść");

        assert_eq!(std::fs::read(&target).unwrap(), oczekiwane);
    }

    /// REGRESJA D1: zszyty plik trafia do wskazanego katalogu, nie obok
    /// żadnej ze stron źródłowych.
    #[test]
    fn test_zapisuje_do_wskazanego_katalogu_nie_obok_zrodla() {
        let zrodlo = tempdir().unwrap();
        let wynik = tempdir().unwrap();

        let path_a = zrodlo.path().join("a.bin");
        let path_b = zrodlo.path().join("b.bin");
        std::fs::write(&path_a, [0x00, 0x00, 0xAA, 0xFF]).unwrap();
        std::fs::write(&path_b, [0xBB, 0xCC, 0x00, 0x11]).unwrap();

        let m = SpliceModule;
        let (target, _) = m.repair(&path_a, &dummy_ctx(Some("PARTIAL")), Some(&path_b), wynik.path())
            .expect("zszycie powinno się powieść");

        assert!(target.starts_with(wynik.path()), "Wynik musi leżeć we wskazanym katalogu: {}", target.display());
        assert_eq!(std::fs::read(&target).unwrap(), vec![0xBB, 0xCC, 0xAA, 0xFF]);

        let mut w_zrodle: Vec<String> = std::fs::read_dir(zrodlo.path()).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        w_zrodle.sort();
        assert_eq!(w_zrodle, vec!["a.bin".to_string(), "b.bin".to_string()], "Katalog źródłowy musi zostać nietknięty");
    }

    #[test]
    fn test_repair_nie_zostawia_pliku_czesciowego_po_bledzie_io() {
        let dir = tempdir().unwrap();
        let path_a = dir.path().join("plik.bin");
        std::fs::write(&path_a, vec![1u8; 10_000]).unwrap();

        // Katalog otwiera się jako `File`, ale odczyt z niego zwraca EISDIR -
        // tani sposób na wywołanie realnego błędu I/O w trakcie zszywania.
        let katalog_jako_blizniak = dir.path().join("podkatalog");
        std::fs::create_dir(&katalog_jako_blizniak).unwrap();

        let m = SpliceModule;
        let wynik = m.repair(&path_a, &dummy_ctx(Some("PARTIAL")), Some(&katalog_jako_blizniak), dir.path());

        assert!(wynik.is_none(), "Błąd I/O musi dać None");
        assert!(
            !dir.path().join("plik_spliced.bin").exists(),
            "Po nieudanym zszyciu nie może zostać plik z sufiksem _spliced - wyglądałby na gotowy wynik naprawy"
        );
    }
}
