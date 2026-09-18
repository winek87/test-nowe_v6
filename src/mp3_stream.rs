// src/mp3_stream.rs

//! # Diagnostyka Elementarnego Strumienia MP3 (łańcuch ramek MPEG audio)
//!
//! **ZERO ZALEŻNOŚCI ZEWNĘTRZNYCH** — ten sam wybór co [`crate::ts_stream`]:
//! format ramek MPEG audio jest częścią stabilnej, niezmiennej od lat 90.
//! specyfikacji MPEG-1/2 Audio, więc pełna analiza STRUKTURY (nie treści
//! dźwiękowej) mieści się w czystym `std`.
//!
//! ## Ten sam kształt problemu co TS, jedna kluczowa różnica
//!
//! MP3 to, jak TS, CIĄGŁY strumień samoopisujących się jednostek — ale w
//! odróżnieniu od TS (siatka o STAŁEJ długości 188/192 B, gdzie resynchro po
//! uszkodzeniu jest automatyczne: kolejny slot i tak stoi w tym samym
//! miejscu), ramka MPEG audio ma długość ZMIENNĄ, wyliczaną z jej własnego
//! nagłówka (bitrate, częstotliwość próbkowania, warstwa). Gdy nagłówek w
//! oczekiwanym miejscu się nie zgadza, NIE wiadomo z góry, gdzie zaczyna się
//! kolejna ramka — trzeba jej poszukać, tak jak przy zmiennej długości tagów
//! [`crate::flv_stream`].
//!
//! ## Wartość diagnostyczna
//!
//! Dziś jedyne sprawdzenie MP3 w całym projekcie to pierwsze kilka bajtów
//! (tag ID3 albo synchronizacja JEDNEJ ramki na starcie —
//! `repair_modules::mod::weryfikuj_naprawiony_plik`). Ten moduł idzie dalej:
//! liczy WSZYSTKIE ramki i KAŻDE miejsce, gdzie łańcuch się urywa — więc
//! zamiast "otwiera się / nie otwiera" mówi, ile realnie audio przetrwało i
//! gdzie leży uszkodzenie.
//!
//! ## Ograniczenie (uczciwie)
//! To analiza WARSTWY RAMKOWANIA, nie treści dźwiękowej. Strumień może mieć
//! idealny łańcuch ramek i nadal nieść zniekształcone próbki w środku — do
//! tego trzeba by dekodera, świadomie pominiętego, tak samo jak przy
//! `video_image`/`ts_stream`.

use std::path::Path;

/// Tabele bitrate (kbps) wg specyfikacji MPEG audio. Indeks 0 = "free"
/// (nieużywany tu, traktowany jak nieprawidłowy), indeks 15 = "bad"
/// (zarezerwowany, zawsze nieprawidłowy) — oba kodowane jako `0`.
/// Wiersze: [Warstwa I, Warstwa II, Warstwa III].
const BITRATE_MPEG1: [[u16; 16]; 3] = [
    [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0],
    [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0],
    [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0],
];
/// MPEG-2 i MPEG-2.5 dzielą tę samą tabelę bitrate. Warstwa II i III też
/// dzielą jeden wiersz (w odróżnieniu od MPEG-1, gdzie mają osobne).
const BITRATE_MPEG2: [[u16; 16]; 3] = [
    [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0],
    [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0],
    [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0],
];
/// Częstotliwości próbkowania (Hz), indeksowane wersją MPEG. Indeks 3
/// (zarezerwowany) nie występuje w tej tabeli - odsiewany przed odczytem.
const SAMPLERATE: [[u32; 3]; 3] = [
    [44_100, 48_000, 32_000], // MPEG-1
    [22_050, 24_000, 16_000], // MPEG-2
    [11_025, 12_000, 8_000],  // MPEG-2.5
];

/// Wynik rozbioru nagłówka JEDNEJ ramki - tylko to, co potrzebne do
/// wyliczenia jej długości i przejścia do kolejnej.
struct NaglowekRamki {
    dlugosc_bajtow: usize,
}

/// Rozbiera 4-bajtowy nagłówek ramki MPEG audio spod `b[0..4]`. Zwraca
/// `None`, gdy synchronizacja albo którekolwiek pole jest nieprawidłowe
/// (zarezerwowana wersja/warstwa, bitrate "free"/"bad", częstotliwość
/// zarezerwowana) — to znaczy, że TU nie stoi prawdziwa ramka.
fn parsuj_naglowek_ramki(b: &[u8]) -> Option<NaglowekRamki> {
    if b.len() < 4 {
        return None;
    }
    if b[0] != 0xFF || (b[1] & 0xE0) != 0xE0 {
        return None;
    }

    let wersja = (b[1] >> 3) & 0x03; // 00=MPEG2.5, 01=zarezerwowana, 10=MPEG2, 11=MPEG1
    let warstwa = (b[1] >> 1) & 0x03; // 00=zarezerwowana, 01=III, 10=II, 11=I
    if wersja == 0b01 || warstwa == 0b00 {
        return None;
    }

    let bitrate_idx = ((b[2] >> 4) & 0x0F) as usize;
    let samplerate_idx = ((b[2] >> 2) & 0x03) as usize;
    if bitrate_idx == 0 || bitrate_idx == 0x0F || samplerate_idx == 0x03 {
        return None;
    }
    let padding = ((b[2] >> 1) & 0x01) as usize;

    let grupa_warstwy = match warstwa {
        0b11 => 0, // Warstwa I
        0b10 => 1, // Warstwa II
        0b01 => 2, // Warstwa III
        _ => unreachable!("warstwa==0b00 odsiana wyżej"),
    };
    let bitrate_kbps = if wersja == 0b11 {
        BITRATE_MPEG1[grupa_warstwy][bitrate_idx]
    } else {
        BITRATE_MPEG2[grupa_warstwy][bitrate_idx]
    } as usize;
    if bitrate_kbps == 0 {
        return None;
    }

    let wersja_sr = match wersja {
        0b11 => 0, // MPEG-1
        0b10 => 1, // MPEG-2
        0b00 => 2, // MPEG-2.5
        _ => unreachable!("wersja==0b01 odsiana wyżej"),
    };
    let samplerate_hz = SAMPLERATE[wersja_sr][samplerate_idx] as usize;
    if samplerate_hz == 0 {
        return None;
    }

    let (probek_na_ramke, rozmiar_slotu) = match warstwa {
        0b11 => (384usize, 4usize), // Warstwa I: slot = 4 B
        0b10 => (1152usize, 1usize), // Warstwa II: 1152 próbek, wszystkie wersje
        0b01 => (if wersja == 0b11 { 1152usize } else { 576usize }, 1usize), // Warstwa III
        _ => unreachable!("warstwa==0b00 odsiana wyżej"),
    };

    let rdzen = (probek_na_ramke / 8) * bitrate_kbps * 1000 / samplerate_hz;
    let dlugosc_bajtow = rdzen + padding * rozmiar_slotu;
    if dlugosc_bajtow < 4 {
        return None;
    }
    Some(NaglowekRamki { dlugosc_bajtow })
}

/// Rozmiar (w bajtach, licząc od bajtu 0) opcjonalnego nagłówka ID3v2 na
/// starcie pliku - `0`, gdy nieobecny. Rozmiar w nagłówku jest kodowany jako
/// "syncsafe integer" (tylko dolne 7 bitów każdego z 4 bajtów), zgodnie ze
/// specyfikacją ID3v2 - to metadane, nie audio, więc muszą zostać pominięte
/// przed szukaniem pierwszej ramki.
fn wielkosc_id3v2(bytes: &[u8]) -> usize {
    if bytes.len() < 10 || &bytes[0..3] != b"ID3" {
        return 0;
    }
    let rozmiar = ((bytes[6] & 0x7F) as usize) << 21
        | ((bytes[7] & 0x7F) as usize) << 14
        | ((bytes[8] & 0x7F) as usize) << 7
        | (bytes[9] & 0x7F) as usize;
    let ma_stopke = (bytes[5] & 0x10) != 0; // opcjonalna 10-bajtowa stopka ID3v2
    10 + rozmiar + if ma_stopke { 10 } else { 0 }
}

/// Wykrywa opcjonalną 128-bajtową stopkę ID3v1 (`"TAG"` na starcie) na końcu
/// pliku. Zwraca `(offset_poczatku_audio_od_konca, obecna)` - to legalna,
/// oczekiwana końcówka, NIE uszkodzenie.
fn wykryj_id3v1(bytes: &[u8]) -> (usize, bool) {
    if bytes.len() >= 128 {
        let start = bytes.len() - 128;
        if &bytes[start..start + 3] == b"TAG" {
            return (start, true);
        }
    }
    (bytes.len(), false)
}

/// Szerokość okna resynchronizacji po urwaniu łańcucha ramek - ten sam próg
/// i uzasadnienie co `ts_stream::OKNO_WYKRYWANIA_SIATKI_BAJTOW`: komfortowo
/// pokrywa realistyczne "wyspy uszkodzenia", a koszt pozostaje pomijalny.
const OKNO_RESYNCHRO_BAJTOW: usize = 1024 * 1024;
/// Górny limit liczby prób resynchronizacji na plik - chroni przed
/// patologicznym kosztem na pliku w pełni zaśmieconym poza pierwszą ramką
/// (bez tego limitu: do `OKNO_RESYNCHRO_BAJTOW` prób skanowania PRZY KAŻDEJ
/// z potencjalnie bardzo wielu mikroskopijnych "wysp").
const MAX_PROB_RESYNCHRO: usize = 1000;

/// Szuka pierwszej WIARYGODNEJ ramki od pozycji `from` (wyłącznie), w
/// granicach `[from, limit)`. "Wiarygodna" wymaga POTWIERDZENIA: albo
/// znaleziona ramka sięga dokładnie do `limit` (koniec dostępnych danych),
/// albo kolejna ramka TUŻ PO niej też parsuje się poprawnie - bez tego
/// pojedynczy przypadkowy bajt `0xFF` w danych nie-audio (np. w obrazku
/// okładki osadzonym w ID3v2) dawałby fałszywe rozpoznanie.
fn znajdz_pierwsza_ramke(bytes: &[u8], from: usize, limit: usize) -> Option<usize> {
    let limit = limit.min(bytes.len());
    for i in from..limit {
        let Some(naglowek) = parsuj_naglowek_ramki(&bytes[i..]) else { continue };
        let koniec = i + naglowek.dlugosc_bajtow;
        if koniec > limit {
            continue;
        }
        let potwierdzone = koniec == limit || parsuj_naglowek_ramki(&bytes[koniec..]).is_some();
        if potwierdzone {
            return Some(i);
        }
    }
    None
}

/// Wynik analizy elementarnego strumienia MP3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mp3Analysis {
    /// Liczba poprawnie rozebranych ramek MPEG audio.
    pub total_frames: usize,
    /// Liczba miejsc, gdzie łańcuch ramek się urywa (nagłówek w oczekiwanym
    /// miejscu jest nieprawidłowy) - każde to jedna "wyspa uszkodzenia".
    pub sync_losses: usize,
    /// Rozmiar nagłówka ID3v2 na starcie pliku (`0`, gdy nieobecny).
    pub id3v2_size: usize,
    /// Czy na końcu pliku stoi legalna 128-bajtowa stopka ID3v1.
    pub id3v1_present: bool,
    /// Bajty na końcu (albo po ostatniej udanej resynchronizacji), których
    /// nie dało się rozpoznać jako kolejną ramkę - objaw ucięcia/uszkodzenia.
    pub trailing_garbage_bytes: usize,
}

impl Mp3Analysis {
    /// Czy strumień jest w pełni zdrowy - brak urwań łańcucha, brak
    /// nierozpoznanego ogona.
    pub fn is_healthy(&self) -> bool {
        self.total_frames > 0 && self.sync_losses == 0 && self.trailing_garbage_bytes == 0
    }

    /// Zwięzły opis stanu do zapisania w bazie i pokazania użytkownikowi.
    pub fn describe(&self) -> String {
        if self.is_healthy() {
            return format!(
                "Strumień MP3 spójny: {} ramek{}",
                self.total_frames,
                if self.id3v1_present { ", tag ID3v1 na końcu" } else { "" }
            );
        }
        let mut parts = vec![format!("{} ramek", self.total_frames)];
        if self.sync_losses > 0 {
            parts.push(format!("{} urwań łańcucha ramek", self.sync_losses));
        }
        if self.trailing_garbage_bytes > 0 {
            parts.push(format!("{} bajtów nierozpoznanych na końcu", self.trailing_garbage_bytes));
        }
        parts.join("; ")
    }
}

/// Rozpoznaje rozszerzenie MP3.
pub fn is_mp3_extension(path_str: &str) -> bool {
    path_str.to_lowercase().ends_with(".mp3")
}

/// Analizuje elementarny strumień MP3: liczy ramki i miejsca, gdzie łańcuch
/// się urywa. Zwraca `None`, gdy NIE znaleziono ani jednej wiarygodnej ramki
/// w całym pliku - fałszywe rozszerzenie albo kompletnie zniszczona
/// synchronizacja.
pub fn analyze_mp3(bytes: &[u8]) -> Option<Mp3Analysis> {
    let id3v2_size = wielkosc_id3v2(bytes);
    let (id3v1_start, id3v1_present) = wykryj_id3v1(bytes);
    let koniec_audio = if id3v1_present { id3v1_start } else { bytes.len() };
    if id3v2_size >= koniec_audio {
        return None; // ID3v2 sam zjada cały dostępny obszar - nie ma czego analizować
    }

    let mut p = znajdz_pierwsza_ramke(bytes, id3v2_size, koniec_audio)?;

    let mut total_frames = 0usize;
    let mut sync_losses = 0usize;
    let mut trailing_garbage_bytes = 0usize;
    let mut proby_resynchro = 0usize;

    while p < koniec_audio {
        if let Some(naglowek) = parsuj_naglowek_ramki(&bytes[p..])
            && p + naglowek.dlugosc_bajtow <= koniec_audio
        {
            total_frames += 1;
            p += naglowek.dlugosc_bajtow;
            continue;
        }

        sync_losses += 1;
        proby_resynchro += 1;
        if proby_resynchro > MAX_PROB_RESYNCHRO {
            trailing_garbage_bytes = koniec_audio - p;
            break;
        }

        let okno_koniec = koniec_audio.min(p + 1 + OKNO_RESYNCHRO_BAJTOW);
        match znajdz_pierwsza_ramke(bytes, p + 1, okno_koniec) {
            Some(q) => p = q,
            None => {
                trailing_garbage_bytes = koniec_audio - p;
                break;
            }
        }
    }

    Some(Mp3Analysis { total_frames, sync_losses, id3v2_size, id3v1_present, trailing_garbage_bytes })
}

/// Górny limit rozmiaru pliku wczytywanego w całości do pamięci przed
/// analizą. Ten sam próg i uzasadnienie co `ts_stream::LIMIT_DIAGNOZY_W_RAM`.
const LIMIT_DIAGNOZY_W_RAM: u64 = 256 * 1024 * 1024; // 256 MB

/// Wariant [`analyze_mp3`] operujący na pliku na dysku. Odmawia wczytania
/// plików większych niż [`LIMIT_DIAGNOZY_W_RAM`].
pub fn analyze_mp3_file(path: &Path) -> Option<Mp3Analysis> {
    let rozmiar = std::fs::metadata(path).ok()?.len();
    if rozmiar > LIMIT_DIAGNOZY_W_RAM {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    analyze_mp3(&bytes)
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // parsuj_naglowek_ramki - wartości referencyjne
    // ------------------------------------------------------------------

    /// Buduje 4-bajtowy nagłówek ramki MPEG-1 Warstwa III.
    fn naglowek_mpeg1_l3(bitrate_idx: u8, samplerate_idx: u8, padding: bool) -> [u8; 4] {
        [
            0xFF,
            0xE0 | (0b11 << 3) | (0b01 << 1), // sync + MPEG1 + Layer III
            (bitrate_idx << 4) | (samplerate_idx << 2) | if padding { 0x02 } else { 0 },
            0x00,
        ]
    }

    /// Wartość powszechnie znana w narzędziach do MP3: MPEG-1/Warstwa III,
    /// 128 kbps, 44100 Hz, bez paddingu, daje ramkę DOKŁADNIE 417 B.
    #[test]
    fn test_dlugosc_ramki_128kbps_44100hz_referencyjna_wartosc_417() {
        let naglowek = naglowek_mpeg1_l3(9, 0, false); // idx 9 = 128 kbps (tabela MPEG1 L3), idx 0 = 44100 Hz
        let wynik = parsuj_naglowek_ramki(&naglowek).expect("nagłówek musi się rozebrać");
        assert_eq!(wynik.dlugosc_bajtow, 417);
    }

    #[test]
    fn test_padding_dodaje_jeden_bajt_dla_warstwy_iii() {
        let bez = parsuj_naglowek_ramki(&naglowek_mpeg1_l3(9, 0, false)).unwrap();
        let z = parsuj_naglowek_ramki(&naglowek_mpeg1_l3(9, 0, true)).unwrap();
        assert_eq!(z.dlugosc_bajtow, bez.dlugosc_bajtow + 1);
    }

    #[test]
    fn test_odrzuca_brak_synchronizacji() {
        assert!(parsuj_naglowek_ramki(&[0x00, 0xE0, 0x90, 0x00]).is_none());
        assert!(parsuj_naglowek_ramki(&[0xFF, 0x00, 0x90, 0x00]).is_none());
    }

    #[test]
    fn test_odrzuca_zarezerwowana_wersje_i_warstwe() {
        // Wersja 01 = zarezerwowana.
        assert!(parsuj_naglowek_ramki(&[0xFF, 0xE0 | (0b01 << 3) | (0b01 << 1), 0x90, 0x00]).is_none());
        // Warstwa 00 = zarezerwowana.
        assert!(parsuj_naglowek_ramki(&[0xFF, 0xE0 | (0b11 << 3), 0x90, 0x00]).is_none());
    }

    #[test]
    fn test_odrzuca_bitrate_free_i_bad() {
        assert!(parsuj_naglowek_ramki(&naglowek_mpeg1_l3(0, 0, false)).is_none(), "indeks 0 = free");
        assert!(parsuj_naglowek_ramki(&naglowek_mpeg1_l3(15, 0, false)).is_none(), "indeks 15 = bad");
    }

    #[test]
    fn test_odrzuca_zarezerwowana_czestotliwosc() {
        assert!(parsuj_naglowek_ramki(&naglowek_mpeg1_l3(9, 3, false)).is_none());
    }

    #[test]
    fn test_zbyt_krotki_bufor_nie_panikuje() {
        assert!(parsuj_naglowek_ramki(&[0xFF, 0xE0]).is_none());
        assert!(parsuj_naglowek_ramki(&[]).is_none());
    }

    // ------------------------------------------------------------------
    // Budowanie strumieni testowych
    // ------------------------------------------------------------------

    /// Buduje `ile` kolejnych, poprawnych ramek MPEG-1/Warstwa III,
    /// 128 kbps/44100 Hz (417 B każda), wypełnionych `wypelniacz`.
    fn zbuduj_ramki(ile: usize, wypelniacz: u8) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..ile {
            let naglowek = naglowek_mpeg1_l3(9, 0, false);
            let dlugosc = parsuj_naglowek_ramki(&naglowek).unwrap().dlugosc_bajtow;
            out.extend_from_slice(&naglowek);
            out.resize(out.len() + dlugosc - 4, wypelniacz);
        }
        out
    }

    // ------------------------------------------------------------------
    // analyze_mp3 - strumień zdrowy
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_zdrowy_strumien() {
        let strumien = zbuduj_ramki(5, 0xAA);
        let a = analyze_mp3(&strumien).unwrap();
        assert_eq!(a.total_frames, 5);
        assert_eq!(a.sync_losses, 0);
        assert_eq!(a.trailing_garbage_bytes, 0);
        assert!(a.is_healthy());
    }

    #[test]
    fn test_analyze_pomija_id3v2_na_starcie() {
        let mut plik = Vec::new();
        plik.extend_from_slice(b"ID3");
        plik.extend_from_slice(&[0x03, 0x00, 0x00]); // wersja 2.3, flagi=0
        plik.extend_from_slice(&[0x00, 0x00, 0x00, 0x20]); // syncsafe: 0x20 = 32 B treści tagu
        plik.extend(vec![0u8; 32]);
        plik.extend(zbuduj_ramki(3, 0xBB));

        let a = analyze_mp3(&plik).unwrap();
        assert_eq!(a.id3v2_size, 10 + 32);
        assert_eq!(a.total_frames, 3);
        assert!(a.is_healthy());
    }

    #[test]
    fn test_analyze_wykrywa_id3v1_na_koncu_bez_traktowania_jako_smieci() {
        let mut plik = zbuduj_ramki(4, 0xCC);
        plik.extend_from_slice(b"TAG");
        plik.extend(vec![0u8; 125]); // razem 128 B stopki

        let a = analyze_mp3(&plik).unwrap();
        assert!(a.id3v1_present);
        assert_eq!(a.total_frames, 4);
        assert_eq!(a.trailing_garbage_bytes, 0, "ID3v1 to legalna stopka, nie uszkodzenie");
        assert!(a.is_healthy());
    }

    /// Sedno silnika: wyspa uszkodzenia (śmieci) MIĘDZY dwiema seriami
    /// poprawnych ramek musi zostać policzona jako JEDNO urwanie łańcucha,
    /// a ramki PRZED i PO wyspie muszą się doliczyć.
    #[test]
    fn test_analyze_wykrywa_wyspe_uszkodzenia_w_srodku() {
        let mut plik = zbuduj_ramki(3, 0xAA);
        plik.extend(vec![0x00u8; 500]); // śmieci - żadna prawdziwa ramka
        plik.extend(zbuduj_ramki(3, 0xBB));

        let a = analyze_mp3(&plik).unwrap();
        assert_eq!(a.sync_losses, 1, "jedna wyspa uszkodzenia");
        assert_eq!(a.total_frames, 6, "3 ramki przed + 3 ramki po wyspie");
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_ucieta_ostatnia_ramka_daje_trailing_garbage() {
        let mut plik = zbuduj_ramki(3, 0xAA);
        plik.truncate(plik.len() - 10); // ostatnia ramka niepełna

        let a = analyze_mp3(&plik).unwrap();
        assert_eq!(a.total_frames, 2);
        assert_eq!(a.trailing_garbage_bytes, 417 - 10);
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_plik_bez_zadnej_ramki_daje_none() {
        assert!(analyze_mp3(b"to nie jest strumien MPEG audio, tylko zwykly tekst").is_none());
        assert!(analyze_mp3(&vec![0u8; 2000]).is_none());
    }

    #[test]
    fn test_analyze_pojedynczy_przypadkowy_bajt_ff_nie_daje_falszywego_rozpoznania() {
        // Pojedynczy bajt 0xFF w danych nie-audio (np. fragment obrazka)
        // otoczony śmieciami - bez potwierdzenia DRUGĄ ramką dałoby to
        // fałszywe rozpoznanie jednej "ramki" o absurdalnej długości.
        let mut dane = vec![0x00u8; 200];
        dane[100] = 0xFF;
        dane[101] = 0xFB; // wygląda na sync, ale nic po nim nie potwierdza ramki
        assert!(analyze_mp3(&dane).is_none());
    }

    // ------------------------------------------------------------------
    // is_mp3_extension
    // ------------------------------------------------------------------

    #[test]
    fn test_is_mp3_extension() {
        assert!(is_mp3_extension("nagranie.mp3"));
        assert!(is_mp3_extension("NAGRANIE.MP3"));
        assert!(!is_mp3_extension("film.mp4"));
        assert!(!is_mp3_extension("dokument.pdf"));
    }

    // ------------------------------------------------------------------
    // analyze_mp3_file
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_mp3_file_odrzuca_plik_wiekszy_niz_limit() {
        let dir = tempfile::tempdir().unwrap();
        let sciezka = dir.path().join("ogromny.mp3");
        let plik = std::fs::File::create(&sciezka).unwrap();
        plik.set_len(LIMIT_DIAGNOZY_W_RAM + 1).unwrap();
        drop(plik);

        assert_eq!(analyze_mp3_file(&sciezka), None);
    }

    #[test]
    fn test_analyze_mp3_file_na_zdrowym_strumieniu() {
        let dir = tempfile::tempdir().unwrap();
        let sciezka = dir.path().join("zdrowy.mp3");
        std::fs::write(&sciezka, zbuduj_ramki(3, 0xAA)).unwrap();

        let a = analyze_mp3_file(&sciezka).expect("plik musi się odczytać");
        assert!(a.is_healthy());
    }

    // ------------------------------------------------------------------
    // describe
    // ------------------------------------------------------------------

    #[test]
    fn test_describe_zdrowy_wspomina_liczbe_ramek() {
        let a = analyze_mp3(&zbuduj_ramki(7, 0xAA)).unwrap();
        let d = a.describe();
        assert!(d.contains("spójny"));
        assert!(d.contains("7 ramek"));
    }

    #[test]
    fn test_describe_uszkodzony_wymienia_urwania_i_ogon() {
        let mut plik = zbuduj_ramki(2, 0xAA);
        plik.extend(vec![0x00u8; 500]);
        plik.truncate(plik.len() - 5); // ogon też nierozpoznany po wyspie

        let a = analyze_mp3(&plik).unwrap();
        let d = a.describe();
        assert!(d.contains("urwań"), "opis: {}", d);
    }
}
