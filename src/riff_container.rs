// src/riff_container.rs

//! # Rozbiór i Składanie Kontenera RIFF (WAV/AVI)
//!
//! ## Ten sam problem co Matroska, inne rozwiązanie
//!
//! RIFF, tak jak EBML/Matroska (patrz [`crate::mkv_container`]), jest
//! formatem KAWAŁKOWYM — ciągiem samoopisujących się fragmentów
//! (identyfikator + rozmiar + treść). Różnica: Matroska definiuje OPCJONALNY
//! element `CRC-32`, który muxery zwykle zapisują, dając obiektywnego sędziego
//! per element. **Czysty RIFF nie ma i nigdy nie miał żadnego pola sumy
//! kontrolnej dla fragmentu** — ani w WAV, ani w AVI, w żadnej wersji
//! specyfikacji Microsoftu/IBM z 1991 r. Składanie po fragmentach jest tu
//! więc możliwe (struktura wciąż mówi, GDZIE w pliku leży który fragment), ale
//! wybór między dwiema kopiami tego samego fragmentu nie może się oprzeć na
//! dowodzie — tylko na heurystyce "czy to nie jest oczywista wydmuszka"
//! ([`wyglada_na_wydmuszke`]). Stąd [`splice_riff`] jest ZAWSZE gwarancją
//! SŁABĄ, bez wyjątku (w odróżnieniu od `splice_mkv`, który bywa MOCNY, gdy
//! CRC-32 jest obecne).
//!
//! ## Poziom ziarnistości: fragmenty NAJWYŻSZEGO poziomu, nie rekursja w `LIST`
//!
//! AVI zagnieżdża fragmenty `LIST` (własny 4-bajtowy podtyp + fragmenty w
//! środku, np. `LIST "hdrl"`, `LIST "movi"`). Ten moduł NIE schodzi w głąb
//! `LIST` — traktuje go jako jeden nieprzezroczysty fragment najwyższego
//! poziomu, dokładnie tak jak [`crate::mkv_container::splice_mkv`] nie
//! schodzi w głąb `Cluster`. Naprawia to samo, co tamten moduł naprawia dla
//! Matroski: ucięty/uszkodzony OGON pliku (typowe przy odzysku), nie
//! pojedyncze klatki/próbki w środku.
//!
//! ## Struktura pliku
//!
//! Nagłówek (12 B): `"RIFF"` (4 B) + rozmiar reszty pliku jako `u32`
//! little-endian (4 B, liczony OD bajtu 8. do końca pliku — obejmuje typ
//! formy i wszystkie fragmenty) + typ formy `"WAVE"`/`"AVI "` (4 B). Dalej
//! ciąg fragmentów: identyfikator 4-bajtowy + rozmiar `u32` little-endian
//! (4 B) + treść, dopełniona JEDNYM bajtem `0x00`, gdy rozmiar jest
//! nieparzysty (word-alignment) — [`FragmentRiff::dlugosc_calkowita`] liczy
//! TEN bajt dopełnienia, żeby stanowił bezpośredni krok do kolejnego
//! fragmentu.

/// Czy ścieżka/rozszerzenie (z kropką, np. `.wav`) wskazuje na kontener RIFF
/// obsługiwany przez ten moduł.
pub fn is_riff_extension(path_str: &str) -> bool {
    let lower = path_str.to_lowercase();
    lower.ends_with(".wav") || lower.ends_with(".avi")
}

/// Informacje o poprawnie odczytanym kontenerze RIFF (Faza 19).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RiffInfo {
    pub form_type: [u8; 4],
    /// Liczba fragmentów NAJWYŻSZEGO poziomu (patrz dokumentacja modułu) —
    /// NIE liczba ścieżek audio/wideo, których ten płytki rozbiór nagłówków
    /// nie ustala (wymagałoby zejścia w `LIST "hdrl"`).
    pub fragment_count: usize,
}

/// Kategoria uszkodzenia kontenera RIFF, wywiedziona przez [`read_riff_file`].
/// Ten sam podział co [`crate::mkv_container::MkvDamage`], bez wariantu
/// odpowiadającego "InvalidStructure z powodu nierozpoznanych elementów" —
/// RIFF nie ma zamkniętego słownika identyfikatorów fragmentów do
/// zwalidowania, więc jedyne dwie odróżnialne kategorie to "nie ma nagłówka
/// RIFF w ogóle" i "urywa się w trakcie".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiffDamage {
    /// Brak czytelnego nagłówka `"RIFF"`, albo plik parsuje się na zero
    /// fragmentów — w tym fałszywe rozszerzenie (plik `.wav`/`.avi`, który w
    /// rzeczywistości jest innym formatem).
    InvalidStructure,
    /// Zadeklarowany koniec fragmentu wykracza poza plik, albo odczyt
    /// nagłówka fragmentu urywa się w trakcie — klasyczny objaw ucięcia.
    Truncated,
    /// Błąd odczytu pliku z dysku. Rozmyślnie NIE rozstrzyga "plik nie
    /// istnieje" — to sprawdza wywołujący (Faza 19) przez `full_path.exists()`,
    /// dokładnie tak jak przy [`crate::mkv_container::read_mkv_file`].
    Other,
}

/// Opis kategorii po polsku — do zapisania w bazie i pokazania użytkownikowi.
pub fn damage_description(damage: RiffDamage) -> &'static str {
    match damage {
        RiffDamage::Truncated => "Plik ucięty - struktura RIFF urywa się przed zadeklarowanym końcem",
        RiffDamage::InvalidStructure => "Niespójna struktura RIFF - uszkodzenie lub fałszywe rozszerzenie (plik nie jest WAV/AVI)",
        RiffDamage::Other => "Błąd odczytu pliku RIFF z dysku",
    }
}

/// Wariant [`dzieci_riff`] czytający z DYSKU zamiast z bufora w pamięci —
/// główna ścieżka Fazy 19 (diagnostyka całego korpusu, łącznie z dużymi
/// plikami AVI, które mogą ważyć gigabajty).
///
/// Przechodzi WYŁĄCZNIE po 8-bajtowych nagłówkach fragmentów (`seek` +
/// `read_exact`), nigdy nie wczytuje ich treści do pamięci — ten sam
/// kompromis co [`crate::mkv_container::read_mkv_file`] (patrz jej
/// dokumentacja: `matroska::open` też czyta tylko konkretne elementy przez
/// `BufReader`, nigdy całego pliku). Dlatego, w odróżnieniu od
/// [`dzieci_riff`]/[`splice_riff`] (operujących na buforze już w RAM, bo
/// Faza 17 działa na już-wybranych kandydatach do naprawy), ta funkcja NIE
/// potrzebuje żadnego limitu rozmiaru pliku.
pub fn read_riff_file(path: &std::path::Path) -> std::result::Result<RiffInfo, RiffDamage> {
    use std::io::{Read, Seek, SeekFrom};

    let mut f = std::fs::File::open(path).map_err(|_| RiffDamage::Other)?;
    let file_len = f.metadata().map(|m| m.len()).map_err(|_| RiffDamage::Other)?;

    let mut naglowek = [0u8; 12];
    if f.read_exact(&mut naglowek).is_err() {
        return Err(RiffDamage::InvalidStructure);
    }
    if &naglowek[0..4] != b"RIFF" {
        return Err(RiffDamage::InvalidStructure);
    }
    let rozmiar_naglowka = u32::from_le_bytes(naglowek[4..8].try_into().unwrap());
    let forma: [u8; 4] = naglowek[8..12].try_into().unwrap();

    let Some(deklarowany_koniec) = 8u64.checked_add(rozmiar_naglowka as u64) else {
        return Err(RiffDamage::Truncated);
    };

    let mut p: u64 = 12;
    let mut fragment_count = 0usize;

    while p < deklarowany_koniec {
        if f.seek(SeekFrom::Start(p)).is_err() {
            return Err(RiffDamage::Truncated);
        }
        let mut naglowek_fragmentu = [0u8; 8];
        if f.read_exact(&mut naglowek_fragmentu).is_err() {
            return Err(RiffDamage::Truncated);
        }
        let rozmiar = u32::from_le_bytes(naglowek_fragmentu[4..8].try_into().unwrap()) as u64;
        let dopelnienie = rozmiar % 2;

        let Some(dlugosc_calkowita) = 8u64.checked_add(rozmiar).and_then(|d| d.checked_add(dopelnienie)) else {
            return Err(RiffDamage::Truncated);
        };
        let Some(koniec) = p.checked_add(dlugosc_calkowita) else {
            return Err(RiffDamage::Truncated);
        };
        if koniec > file_len {
            return Err(RiffDamage::Truncated);
        }

        fragment_count += 1;
        p = koniec;
    }

    if fragment_count == 0 {
        return Err(RiffDamage::InvalidStructure);
    }

    Ok(RiffInfo { form_type: forma, fragment_count })
}

/// Jeden fragment RIFF najwyższego poziomu.
#[derive(Debug, Clone, Copy)]
pub struct FragmentRiff {
    pub id: [u8; 4],
    /// Offset bajtu rozpoczynającego identyfikator fragmentu.
    pub offset: usize,
    /// Pełna długość: identyfikator (4 B) + pole rozmiaru (4 B) + treść +
    /// bajt dopełnienia, gdy obecny — czyli dokładny krok do KOLEJNEGO
    /// fragmentu, nie tylko to, co niesie pole rozmiaru.
    pub dlugosc_calkowita: usize,
    /// Czy fragment mieści się w buforze (jego zadeklarowany koniec nie
    /// wykracza poza dane).
    pub spojny: bool,
}

/// Rozbiera plik na fragmenty najwyższego poziomu wewnątrz nagłówka RIFF.
///
/// Zwraca `(offset_treści, zadeklarowany_rozmiar_z_nagłówka, typ_formy,
/// fragmenty)`. Przejście kończy się na pierwszym fragmencie, którego
/// nagłówek (identyfikator + rozmiar) nie mieści się w danych, albo którego
/// zadeklarowany koniec przepełnia arytmetykę — KAŻDA z tych ścieżek dopisuje
/// na listę SENTINEL oznaczony `spojny = false` przed przerwaniem, tym samym
/// wzorcem co [`crate::mkv_container::dzieci_segmentu`] (patrz jej
/// dokumentacja dla pełnego uzasadnienia: bez sentinela konsumenci
/// [`splice_riff`]/[`wszystkie_fragmenty_spojne`] widzieliby listę, która
/// milcząco wygląda jak kompletna, naturalnie zakończona enumeracja).
pub fn dzieci_riff(dane: &[u8]) -> Option<(usize, u32, [u8; 4], Vec<FragmentRiff>)> {
    if dane.len() < 12 || &dane[0..4] != b"RIFF" {
        return None;
    }
    let rozmiar_naglowka = u32::from_le_bytes(dane[4..8].try_into().ok()?);
    let typ_formy: [u8; 4] = dane[8..12].try_into().ok()?;

    let tresc_od = 12usize;
    let deklarowany_koniec = 8usize.checked_add(rozmiar_naglowka as usize)?;

    let mut fragmenty = Vec::new();
    let mut p = tresc_od;

    let sentinel_niekompletny = |p: usize| FragmentRiff {
        id: [0; 4],
        offset: p,
        dlugosc_calkowita: dane.len().saturating_sub(p),
        spojny: false,
    };

    while p < deklarowany_koniec {
        let Some(naglowek) = dane.get(p..p + 8) else {
            fragmenty.push(sentinel_niekompletny(p));
            break;
        };
        let id: [u8; 4] = naglowek[0..4].try_into().unwrap();
        let rozmiar = u32::from_le_bytes(naglowek[4..8].try_into().unwrap()) as usize;
        let dopelnienie = rozmiar % 2;

        let Some(dlugosc_calkowita) = 8usize.checked_add(rozmiar).and_then(|d| d.checked_add(dopelnienie)) else {
            fragmenty.push(sentinel_niekompletny(p));
            break;
        };
        let Some(koniec) = p.checked_add(dlugosc_calkowita) else {
            fragmenty.push(sentinel_niekompletny(p));
            break;
        };
        let spojny = koniec <= dane.len();

        fragmenty.push(FragmentRiff { id, offset: p, dlugosc_calkowita, spojny });

        if !spojny {
            break;
        }
        p = koniec;
    }

    Some((tresc_od, rozmiar_naglowka, typ_formy, fragmenty))
}

/// Czy bufor to oczywista wydmuszka: same zera albo same `0xFF`. Pusty bufor
/// NIE jest wydmuszką w tym sensie — nie ma czego ocenić, więc nie odrzucamy
/// wyłącznie za bycie pustym.
fn wyglada_na_wydmuszke(bytes: &[u8]) -> bool {
    !bytes.is_empty() && (bytes.iter().all(|&b| b == 0) || bytes.iter().all(|&b| b == 0xFF))
}

/// Czy fragment nadaje się do przepisania do wyniku: mieści się w buforze
/// ORAZ jego treść nie jest oczywistą wydmuszką. Brak sumy kontrolnej w RIFF
/// (patrz dokumentacja modułu) wyklucza obiektywny dowód — to jedyny
/// dostępny, bezpieczny sygnał.
fn uzyteczny(f: &FragmentRiff, dane: &[u8]) -> bool {
    f.spojny
        && dane
            .get(f.offset + 8..f.offset + f.dlugosc_calkowita)
            .is_some_and(|tresc| !wyglada_na_wydmuszke(tresc))
}

/// Składa jeden plik RIFF z dwóch uszkodzonych kopii, wybierając NA POZIOMIE
/// KAŻDEGO FRAGMENTU tę stronę, która nie wygląda na wydmuszkę — patrz
/// dokumentacja modułu, dlaczego to (nie CRC) jest tu jedynym dostępnym
/// sygnałem.
///
/// ## Kiedy odmawia CAŁKOWICIE (`None`)
///
/// - któraś strona nie ma czytelnego nagłówka RIFF,
/// - kopie deklarują różny typ formy (`WAVE` vs `AVI `) albo różny rozmiar —
///   to nie są dwa odzyski tego samego pliku,
/// - na tej samej pozycji stoją fragmenty o różnym identyfikatorze lub
///   długości (struktury się rozjechały — nie realignujemy),
/// - żaden pojedynczy fragment nie dał się złożyć.
///
/// ## Kiedy OBCINA wynik zamiast odmawiać
///
/// Gdy TEN SAM fragment jest niezdatny po OBU stronach (obie kopie
/// niespójne/wydmuszka, albo jedna strona w ogóle nie ma tylu fragmentów) —
/// ten sam wzorzec "obetnij i zachowaj" co `splice_mkv`/`splice_flv`.
/// Struktura obu kopii zgadzała się aż do tej pozycji, więc to, co już
/// złożono, jest w pełni wiarygodne.
pub fn splice_riff(bytes_a: &[u8], bytes_b: &[u8]) -> Option<Vec<u8>> {
    let (tresc_a, rozmiar_a, forma_a, dzieci_a) = dzieci_riff(bytes_a)?;
    let (tresc_b, rozmiar_b, forma_b, dzieci_b) = dzieci_riff(bytes_b)?;

    if tresc_a != tresc_b || rozmiar_a != rozmiar_b || forma_a != forma_b {
        return None;
    }
    if dzieci_a.is_empty() && dzieci_b.is_empty() {
        return None;
    }

    // Nagłówek bierzemy ze strony A - obie sparsowały się identycznie, co
    // właśnie sprawdziliśmy porównaniem typu formy i rozmiaru z nagłówka.
    let mut wynik = bytes_a.get(..tresc_a)?.to_vec();
    let mut fragmentow = 0usize;

    let ile = dzieci_a.len().max(dzieci_b.len());
    for i in 0..ile {
        let a = dzieci_a.get(i);
        let b = dzieci_b.get(i);

        // Porównanie odmawiające tylko dla DWÓCH PRAWDZIWYCH fragmentów
        // (obu `spojny`) o różnym id/długości — to jedyny wiarygodny dowód,
        // że struktury się rozjechały. Sentinel niekompletności (`spojny =
        // false`, id bywa placeholderem `[0;0;0;0]`, gdy urwanie nastąpiło
        // DOKŁADNIE na granicy fragmentu, więc nawet nagłówek nowego
        // fragmentu nie dał się odczytać) NIE bierze udziału w tym
        // porównaniu — reprezentuje "parsowanie się urwało tutaj", nie
        // prawdziwą, sprzeczną informację o strukturze. Bez tego wyjątku
        // plik ucięty DOKŁADNIE na granicy fragmentu (a nie w jego środku)
        // fałszywie wyglądałby jak dwie NIEPOWIĄZANE struktury i dostawałby
        // całkowitą odmowę zamiast poprawnego obcięcia — `uzyteczny` niżej
        // już poprawnie odrzuca sentinel przez `f.spojny`, więc wystarczy go
        // tu tylko wykluczyć z TEGO konkretnego porównania.
        if let (Some(fa), Some(fb)) = (a, b)
            && fa.spojny && fb.spojny
            && (fa.id != fb.id || fa.dlugosc_calkowita != fb.dlugosc_calkowita)
        {
            return None;
        }

        let wybrany = match (a, b) {
            (Some(fa), _) if uzyteczny(fa, bytes_a) => (fa, bytes_a),
            (_, Some(fb)) if uzyteczny(fb, bytes_b) => (fb, bytes_b),
            _ => break,
        };

        let (f, zrodlo) = wybrany;
        wynik.extend_from_slice(zrodlo.get(f.offset..f.offset + f.dlugosc_calkowita)?);
        fragmentow += 1;
    }

    if fragmentow == 0 {
        return None;
    }

    Some(wynik)
}

/// Czy WSZYSTKIE fragmenty najwyższego poziomu mieszczą się w pliku (żaden
/// sentinel niekompletności). `None`, gdy plik nie ma czytelnego nagłówka
/// RIFF albo nie ma ani jednego fragmentu — wtedy nie ma czego sprawdzać.
pub fn wszystkie_fragmenty_spojne(dane: &[u8]) -> Option<bool> {
    let (_, _, _, dzieci) = dzieci_riff(dane)?;
    if dzieci.is_empty() {
        return None;
    }
    Some(dzieci.iter().all(|f| f.spojny))
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Buduje minimalny, poprawny plik WAV: nagłówek RIFF/WAVE + chunk `fmt `
    /// (16 B, PCM mono 8-bit) + chunk `data` z podanymi próbkami. Rozmiar w
    /// nagłówku wyliczony poprawnie, żeby test mierzył PARSOWANIE, nie własne
    /// błędy konstrukcji fixture'a.
    fn zbuduj_wav(probki: &[u8]) -> Vec<u8> {
        let fmt_body: [u8; 16] = [
            1, 0,          // AudioFormat = 1 (PCM)
            1, 0,          // NumChannels = 1
            0x44, 0xAC, 0, 0, // SampleRate = 44100
            0x44, 0xAC, 0, 0, // ByteRate = 44100
            1, 0,          // BlockAlign = 1
            8, 0,          // BitsPerSample = 8
        ];

        let mut dane = Vec::new();
        dane.extend_from_slice(b"data");
        dane.extend_from_slice(&(probki.len() as u32).to_le_bytes());
        dane.extend_from_slice(probki);
        if probki.len() % 2 == 1 {
            dane.push(0);
        }
        let data_chunk = dane;

        let mut fmt_chunk = Vec::new();
        fmt_chunk.extend_from_slice(b"fmt ");
        fmt_chunk.extend_from_slice(&(fmt_body.len() as u32).to_le_bytes());
        fmt_chunk.extend_from_slice(&fmt_body);

        let tresc_po_formie = 4 + fmt_chunk.len() + data_chunk.len(); // "WAVE" + fragmenty

        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(tresc_po_formie as u32).to_le_bytes());
        wav.extend_from_slice(b"WAVE");
        wav.extend_from_slice(&fmt_chunk);
        wav.extend_from_slice(&data_chunk);
        wav
    }

    // ------------------------------------------------------------------
    // is_riff_extension
    // ------------------------------------------------------------------

    #[test]
    fn test_rozpoznaje_wav_i_avi_niezaleznie_od_wielkosci_liter() {
        for p in [".wav", ".WAV", ".avi", ".AVI", "plik.wav", "plik.avi"] {
            assert!(is_riff_extension(p), "{} powinno być rozpoznane", p);
        }
    }

    #[test]
    fn test_nie_rozpoznaje_innych_rozszerzen() {
        for p in [".mp3", ".mkv", ".mp4", ".riff"] {
            assert!(!is_riff_extension(p), "{} nie powinno być rozpoznane", p);
        }
    }

    // ------------------------------------------------------------------
    // dzieci_riff
    // ------------------------------------------------------------------

    #[test]
    fn test_parsuje_zdrowy_wav_na_dwa_fragmenty() {
        let wav = zbuduj_wav(&[1, 2, 3, 4, 5]);
        let (tresc_od, _, forma, fragmenty) = dzieci_riff(&wav).expect("zdrowy WAV musi się sparsować");

        assert_eq!(tresc_od, 12);
        assert_eq!(&forma, b"WAVE");
        assert_eq!(fragmenty.len(), 2, "fmt + data");
        assert_eq!(&fragmenty[0].id, b"fmt ");
        assert_eq!(&fragmenty[1].id, b"data");
        assert!(fragmenty.iter().all(|f| f.spojny));
    }

    #[test]
    fn test_odrzuca_smieci_bez_naglowka_riff() {
        assert!(dzieci_riff(b"to nie jest RIFF").is_none());
    }

    #[test]
    fn test_odrzuca_zbyt_krotki_bufor() {
        assert!(dzieci_riff(b"RIFF").is_none());
    }

    #[test]
    fn test_dopelnienie_nieparzystego_fragmentu_wliczone_w_dlugosc() {
        let wav = zbuduj_wav(&[1, 2, 3]); // 3 bajty -> 1 bajt dopełnienia
        let (_, _, _, fragmenty) = dzieci_riff(&wav).unwrap();
        let data = &fragmenty[1];
        assert_eq!(data.dlugosc_calkowita, 8 + 3 + 1, "8 B nagłówka fragmentu + 3 B danych + 1 B dopełnienia");
    }

    /// Ucięcie w środku fragmentu musi zostawić SENTINEL (`spojny = false`),
    /// nie milcząco skończoną listę — patrz dokumentacja `dzieci_riff` i
    /// regresja 4.1 w `mkv_container.rs`, ten sam wzorzec.
    #[test]
    fn test_uciecie_w_srodku_fragmentu_zostawia_sentinel() {
        let wav = zbuduj_wav(&[1, 2, 3, 4, 5]);
        let ucieta = &wav[..wav.len() - 3]; // ucinamy końcówkę chunku "data"

        let (_, _, _, fragmenty) = dzieci_riff(ucieta).unwrap();
        assert!(!fragmenty.last().unwrap().spojny, "ostatni fragment musi być oznaczony jako niespójny");
    }

    // ------------------------------------------------------------------
    // splice_riff
    // ------------------------------------------------------------------

    #[test]
    fn test_zdrowa_kopia_zlozona_sama_ze_soba_daje_oryginal() {
        let wav = zbuduj_wav(&[10, 20, 30, 40]);
        assert_eq!(splice_riff(&wav, &wav).as_deref(), Some(wav.as_slice()));
    }

    #[test]
    fn test_odmawia_gdy_typ_formy_sie_rozni() {
        let wav = zbuduj_wav(&[1, 2, 3]);
        let mut inna_forma = wav.clone();
        inna_forma[8..12].copy_from_slice(b"AVI ");
        assert!(splice_riff(&wav, &inna_forma).is_none());
    }

    /// REGRESJA: plik ucięty DOKŁADNIE na granicy fragmentu (nie w jego
    /// środku) zostawia SENTINEL z placeholderowym id `[0;4]` (nawet nagłówek
    /// nowego fragmentu nie dał się odczytać) — bez wyjątku w porównaniu
    /// id/długości ten sentinel fałszywie wyglądałby jak fragment SPRZECZNY
    /// z prawdziwym fragmentem po stronie zdrowej, dając CAŁKOWITĄ odmowę
    /// zamiast poprawnego obcięcia. Musi zadziałać dokładnie jak ucięcie W
    /// ŚRODKU fragmentu (`test_wybiera_strone_bez_wydmuszki` i pokrewne).
    #[test]
    fn test_uciecie_dokladnie_na_granicy_fragmentu_obcina_zamiast_odmawiac() {
        let zdrowe = zbuduj_wav(&[10, 20, 30, 40, 50]);
        let (_, _, _, fragmenty) = dzieci_riff(&zdrowe).unwrap();
        let data = &fragmenty[1];
        let ucieta = &zdrowe[..data.offset]; // urwane DOKŁADNIE przed "data", ani bajtu więcej

        let wynik = splice_riff(ucieta, &zdrowe).expect("ucięcie na granicy fragmentu musi dać się obciąć, nie odrzucić w całości");
        assert_eq!(wynik, zdrowe, "brakujący fragment musi wrócić w całości ze zdrowego bliźniaka");
    }

    #[test]
    fn test_odmawia_gdy_fragmenty_na_tej_samej_pozycji_maja_rozne_id() {
        let a = zbuduj_wav(&[1, 2, 3, 4]);
        let mut b = a.clone();
        b[12..16].copy_from_slice(b"xxxx"); // psujemy id pierwszego fragmentu ("fmt ")
        assert!(splice_riff(&a, &b).is_none());
    }

    /// Sedno silnika: fragment `data` wyzerowany po stronie A, zdrowy po
    /// stronie B — wynik musi wziąć zdrowe dane z B.
    #[test]
    fn test_wybiera_strone_bez_wydmuszki() {
        let zdrowe = zbuduj_wav(&[10, 20, 30, 40, 50]);
        let mut wyzerowane = zdrowe.clone();
        let (_, _, _, fragmenty) = dzieci_riff(&zdrowe).unwrap();
        let data = &fragmenty[1];
        for b in &mut wyzerowane[data.offset + 8..data.offset + data.dlugosc_calkowita] {
            *b = 0;
        }

        let wynik = splice_riff(&wyzerowane, &zdrowe).expect("złożenie musi się udać");
        assert_eq!(wynik, zdrowe, "wynik musi odtworzyć zdrowy oryginał");
    }

    /// Gdy fragment jest wydmuszką po OBU stronach, silnik obcina wynik
    /// (zachowując poprzednio złożone fragmenty), zamiast odmawiać całości.
    #[test]
    fn test_fragment_zepsuty_po_obu_stronach_obcina_wynik() {
        let zdrowe = zbuduj_wav(&[10, 20, 30, 40, 50]);
        let mut a = zdrowe.clone();
        let mut b = zdrowe.clone();
        let (_, _, _, fragmenty) = dzieci_riff(&zdrowe).unwrap();
        let data = &fragmenty[1];
        for buf in [&mut a, &mut b] {
            for byte in &mut buf[data.offset + 8..data.offset + data.dlugosc_calkowita] {
                *byte = 0;
            }
        }

        // UWAGA: `wynik` jest CELOWO krótszy niż rozmiar zadeklarowany w jego
        // własnym nagłówku (skopiowanym ze strony A, obejmującym oryginalnie
        // OBA fragmenty) — dokładnie tak samo jak ucięty plik wygląda w
        // rzeczywistości. Ponowne parsowanie `dzieci_riff(&wynik)` poprawnie
        // zgłosiłoby to jako sentinel niekompletności (ten sam mechanizm, co
        // `mkv_container`), więc test sprawdza SUROWĄ długość i zawartość
        // wyniku wprost, zamiast polegać na ponownym rozbiorze.
        let wynik = splice_riff(&a, &b).expect("fmt samo w sobie musi się złożyć");
        assert_eq!(wynik.len(), data.offset, "wynik musi kończyć się dokładnie tam, gdzie zaczynał się odcięty fragment data");
        assert_eq!(&wynik[12..16], b"fmt ", "jedyny złożony fragment to fmt");
    }

    /// Gdy KAŻDY fragment (łącznie z pierwszym) jest wydmuszką po obu
    /// stronach, silnik nie ma czego złożyć i odmawia całości — w
    /// odróżnieniu od testu wyżej, gdzie przynajmniej PIERWSZY fragment
    /// (fmt) był użyteczny.
    #[test]
    fn test_wszystkie_fragmenty_zepsute_po_obu_stronach_daje_none() {
        let zdrowe = zbuduj_wav(&[10, 20, 30]);
        let mut a = zdrowe.clone();
        let mut b = zdrowe.clone();
        let (_, _, _, fragmenty) = dzieci_riff(&zdrowe).unwrap();
        for buf in [&mut a, &mut b] {
            // Zerujemy WYŁĄCZNIE treść każdego fragmentu (od bajtu 8. po
            // jego identyfikatorze/rozmiarze) - identyfikatory i rozmiary
            // zostają nietknięte, żeby struktura dalej się parsowała (to
            // treść ma wyglądać na wydmuszkę, nie sama struktura).
            for f in &fragmenty {
                for byte in &mut buf[f.offset + 8..f.offset + f.dlugosc_calkowita] {
                    *byte = 0;
                }
            }
        }
        assert!(splice_riff(&a, &b).is_none());
    }

    // ------------------------------------------------------------------
    // wszystkie_fragmenty_spojne
    // ------------------------------------------------------------------

    #[test]
    fn test_wszystkie_fragmenty_spojne_na_zdrowym_pliku() {
        let wav = zbuduj_wav(&[1, 2, 3]);
        assert_eq!(wszystkie_fragmenty_spojne(&wav), Some(true));
    }

    #[test]
    fn test_wszystkie_fragmenty_spojne_wykrywa_uciecie() {
        let wav = zbuduj_wav(&[1, 2, 3, 4, 5]);
        let ucieta = &wav[..wav.len() - 3];
        assert_eq!(wszystkie_fragmenty_spojne(ucieta), Some(false));
    }

    #[test]
    fn test_wszystkie_fragmenty_spojne_na_smieciach_daje_none() {
        assert_eq!(wszystkie_fragmenty_spojne(b"to nie jest RIFF"), None);
    }

    // ------------------------------------------------------------------
    // read_riff_file (ścieżka dyskowa, Faza 19)
    // ------------------------------------------------------------------

    #[test]
    fn test_read_riff_file_na_zdrowym_wav() {
        let dir = tempfile::tempdir().unwrap();
        let sciezka = dir.path().join("zdrowy.wav");
        std::fs::write(&sciezka, zbuduj_wav(&[1, 2, 3, 4, 5])).unwrap();

        let info = read_riff_file(&sciezka).expect("zdrowy WAV musi się odczytać");
        assert_eq!(&info.form_type, b"WAVE");
        assert_eq!(info.fragment_count, 2, "fmt + data");
    }

    #[test]
    fn test_read_riff_file_na_smieciach() {
        let dir = tempfile::tempdir().unwrap();
        let sciezka = dir.path().join("smieci.wav");
        std::fs::write(&sciezka, b"to nie jest RIFF").unwrap();

        assert_eq!(read_riff_file(&sciezka), Err(RiffDamage::InvalidStructure));
    }

    #[test]
    fn test_read_riff_file_ucieta_w_srodku_fragmentu() {
        let dir = tempfile::tempdir().unwrap();
        let wav = zbuduj_wav(&[1, 2, 3, 4, 5]);
        let sciezka = dir.path().join("ucieta.wav");
        std::fs::write(&sciezka, &wav[..wav.len() - 3]).unwrap();

        assert_eq!(read_riff_file(&sciezka), Err(RiffDamage::Truncated));
    }

    #[test]
    fn test_read_riff_file_ucieta_dokladnie_na_granicy_fragmentu() {
        let dir = tempfile::tempdir().unwrap();
        let wav = zbuduj_wav(&[1, 2, 3, 4, 5]);
        let (_, _, _, fragmenty) = dzieci_riff(&wav).unwrap();
        let data = &fragmenty[1];
        let sciezka = dir.path().join("ucieta_na_granicy.wav");
        std::fs::write(&sciezka, &wav[..data.offset]).unwrap();

        assert_eq!(read_riff_file(&sciezka), Err(RiffDamage::Truncated));
    }

    #[test]
    fn test_read_riff_file_nieistniejacy_plik_to_other() {
        let dir = tempfile::tempdir().unwrap();
        let sciezka = dir.path().join("nie_ma.wav");
        assert_eq!(read_riff_file(&sciezka), Err(RiffDamage::Other));
    }

    #[test]
    fn test_read_riff_file_pusta_tresc_to_invalid_structure() {
        let dir = tempfile::tempdir().unwrap();
        let sciezka = dir.path().join("puste.wav");
        // Nagłówek RIFF/WAVE bez ŻADNEGO fragmentu (rozmiar = 4, tylko typ formy).
        let mut dane = Vec::new();
        dane.extend_from_slice(b"RIFF");
        dane.extend_from_slice(&4u32.to_le_bytes());
        dane.extend_from_slice(b"WAVE");
        std::fs::write(&sciezka, dane).unwrap();

        assert_eq!(read_riff_file(&sciezka), Err(RiffDamage::InvalidStructure));
    }
}


