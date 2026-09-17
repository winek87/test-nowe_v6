// src/utils.rs
//! Moduł z centralnymi narzędziami (utilities) dla silnika walidacji.
//! 
//! Posiada turbodoładowany strumień kryptograficzny (BLAKE3 + mmap),
//! Hybrydowy Silnik Walidacji (infer + exiftool-rs + fast-text-check) 
//! do wykrywania fałszerstw rozszerzeń oraz globalne formatowanie danych.

use memmap2::MmapOptions;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use tracing::{debug, error, info, instrument, warn};
use std::sync::atomic::{AtomicBool, Ordering};

/// Globalna flaga bezpiecznego przerwania (Ctrl+C). 
/// Jeśli true, wszystkie fazy natychmiast przerywają pracę i zapisują postęp.
pub static CANCEL_SIGNAL: AtomicBool = AtomicBool::new(false);

/// Podnosi WSZYSTKIE znaczniki przerwania żyjące w tym procesie.
///
/// # Dlaczego jest ich więcej niż jeden
///
/// Biblioteka `mp4_doctor` ma własny `SHUTDOWN_FLAG`, czytany przez jej długie
/// pętle (poligon treningowy, pobieranie dawców). Nie zlewamy go z naszym
/// [`CANCEL_SIGNAL`], bo `mp4_doctor` ma też własną binarkę i musi dalej
/// działać samodzielnie — ale proces należy do Weryfikatora, więc to my
/// odpowiadamy za podniesienie obu. Jedna funkcja zamiast pary zapisów
/// rozsianych po kodzie: przy dodaniu trzeciej biblioteki z własnym
/// znacznikiem jest DOKŁADNIE jedno miejsce do poprawienia.
pub fn podnies_przerwanie() {
    CANCEL_SIGNAL.store(true, Ordering::SeqCst);
    mp4_doctor::SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
}

/// Zdejmuje wszystkie znaczniki przerwania — patrz [`podnies_przerwanie`].
///
/// Wołane przy wejściu w nowe narzędzie i przy wyjściu z niego: znacznik
/// podniesiony przez wcześniejsze Ctrl+C nie może zatrzymać kolejnej operacji
/// zaraz po jej rozpoczęciu.
pub fn zdejmij_przerwanie() {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);
    mp4_doctor::SHUTDOWN_FLAG.store(false, Ordering::SeqCst);
}

// ============================================================================
// FORMATOWANIE UI I DANYCH
// ============================================================================

/// Przygotowuje pełną ścieżkę do wyświetlenia na ekranie terminala. 
/// Posiada zabezpieczenie przed emotikonami i znakami kontrolnymi ukrytymi w nazwach plików,
/// które mogłyby zepsuć bufor rysowania (Anti-Terminal-Breaking).
pub fn format_display_path(full_path: &str) -> String {
    let sanitize = |c: char| {
        if c.is_control() { return '_'; }

        let cp = c as u32;
        if cp <= 0x25FF { return c; }

        // REGRESJA (todo.core_infra.md): próg `> 0x25FF` blokował WSZYSTKO
        // powyżej tej wartości bez rozróżnienia - w tym całe legalne
        // alfabety powszechne w realnych korpusach danych: japoński/chiński
        // (Hiragana/Katakana/CJK zaczynają się od U+3040), koreański
        // (Hangul Jamo od U+1100, Hangul Syllables od U+AC00) - zamieniając
        // poprawne nazwy plików w ciąg podkreślników w UI. Jawnie
        // dopuszczamy te bloki, zachowując blokadę dla wszystkiego innego
        // powyżej progu (w tym emoji, które nadal ma zostać zablokowane -
        // stąd próg pozostaje, nie jest usuwany całkowicie).
        let jest_dopuszczonym_alfabetem =
            (0x1100..=0x11FF).contains(&cp)    // Hangul Jamo
            || (0x3000..=0x303F).contains(&cp) // Interpunkcja CJK (、。「」)
            || (0x3040..=0x30FF).contains(&cp) // Hiragana + Katakana
            || (0x3400..=0x4DBF).contains(&cp) // CJK Unified Ideographs Extension A
            || (0x4E00..=0x9FFF).contains(&cp) // CJK Unified Ideographs
            || (0xAC00..=0xD7A3).contains(&cp); // Hangul Syllables

        if jest_dopuszczonym_alfabetem { c } else { '_' }
    };

    full_path.chars().map(sanitize).collect()
}

/// Dynamicznie formatuje wartość w bajtach do czytelnej postaci (KB, MB, GB, TB).
/// Minimalizuje zużycie miejsca w konsoli i logach zachowując precyzję do 2 miejsc po przecinku.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB { format!("{:.2} TB", bytes as f64 / TB as f64) }
    else if bytes >= GB { format!("{:.2} GB", bytes as f64 / GB as f64) }
    else if bytes >= MB { format!("{:.2} MB", bytes as f64 / MB as f64) }
    else if bytes >= KB { format!("{:.2} KB", bytes as f64 / KB as f64) }
    else { format!("{} B", bytes) }
}

// ============================================================================
// KRYPTOGRAFIA (BLAKE3 EXTREME)
// ============================================================================

/// Rozmiar segmentu, po którym sprawdzamy sygnał anulowania podczas hashowania
/// przez mmap. Wystarczająco duży, by nie tracić korzyści Zero-Copy, wystarczająco
/// mały, by Ctrl+C reagował w rozsądnym czasie nawet na wielogigabajtowych plikach.
const CANCEL_CHECK_CHUNK: usize = 8 * 1024 * 1024; // 8 MB

/// Weryfikuje integralność danych z prędkością fizycznego nośnika.
/// Dla małych plików używa szybkiego bufora w RAM, 
/// dla dużych (>16MB) używa Zero-Copy (mmap) oraz akceleracji SIMD / Rayon.
///
/// UWAGA: Sprawdza globalny `CANCEL_SIGNAL` cyklicznie w trakcie hashowania
/// (co ~8MB w trybie mmap, co każdy odczyt 128KB w trybie buforowanym). Jeśli
/// użytkownik przerwie program (Ctrl+C) w trakcie hashowania pojedynczego, bardzo
/// dużego pliku, funkcja zwróci błąd `io::ErrorKind::Interrupted` zamiast kończyć
/// hash — wywołujący powinien odróżnić to od prawdziwego błędu dysku.
#[instrument(level = "debug", skip(path), fields(path = %path.display()))]
pub fn hash_file(path: &Path) -> io::Result<String> {
    let file = File::open(path).map_err(|e| {
        warn!(error = %e, "Błąd I/O: Nie udało się otworzyć pliku do hashowania (Bad Sector?)");
        e
    })?;

    let meta = file.metadata()?;
    let mut hasher = blake3::Hasher::new();
    let file_size = meta.len();

    // Próg odcięcia: 16 MB. Powyżej tej wagi opłaca się alokować stronę wirtualną (mmap).
    const MMAP_THRESHOLD: u64 = 16 * 1024 * 1024; 

    if file_size >= MMAP_THRESHOLD {
        debug!("Plik >16MB. Aktywacja Memory Mapping (mmap) i wielowątkowości Rayon.");
        // Używamy mmap by ominąć narzut kopiowania jądra systemu (Syscall -> RAM -> User Space)
        let mmap = unsafe { MmapOptions::new().map(&file).map_err(|e| {
            error!(error = %e, "Krytyczny błąd alokacji mmap. Dysk odłączony?");
            e
        })? };

        // Dzielimy mmap na segmenty, żeby móc sprawdzić CANCEL_SIGNAL między nimi.
        // Nadal Zero-Copy — to tylko granice pętli po tym samym buforze pamięci.
        for segment in mmap.chunks(CANCEL_CHECK_CHUNK) {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) {
                warn!("Hashowanie przerwane przez użytkownika (Ctrl+C) w trakcie mmap.");
                return Err(io::Error::new(io::ErrorKind::Interrupted, "Hashowanie anulowane przez użytkownika"));
            }
            hasher.update(segment);
        }
    } else {
        // Dla drobnicy używamy standardowego odczytu by nie zaśmiecać tablicy stron (Page Table)
        let mut buffer = [0u8; 131_072]; // 128KB pakiety dyskowe (I/O na sterydach)
        let mut reader = io::BufReader::with_capacity(262_144, file);
        
        loop {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) {
                warn!("Hashowanie przerwane przez użytkownika (Ctrl+C) w trakcie odczytu bufora.");
                return Err(io::Error::new(io::ErrorKind::Interrupted, "Hashowanie anulowane przez użytkownika"));
            }

            let count = reader.read(&mut buffer).map_err(|e| {
                warn!(error = %e, "Przerwano strumieniowanie. Potencjalny błąd sektora dysku.");
                e
            })?;
            if count == 0 { break; }
            hasher.update(&buffer[..count]);
        }
    }

    let result_hash = hasher.finalize().to_hex().to_string();
    Ok(result_hash)
}

// ============================================================================
// INŻYNIERIA WSTECZNA (MAGIC BYTES, HEURYSTYKA & EXIFTOOL)
// ============================================================================

/// Weryfikuje strukturę i prawdziwe pochodzenie pliku na podstawie nagłówków.
#[instrument(level = "debug", skip(path), fields(path = %path.display()))]
pub fn check_magic(path: &Path) -> Option<bool> {
    let file_name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    if !file_name.contains('.') {
        return Some(true); // Brak rozszerzenia -> brak punktu odniesienia do falsyfikacji
    }

    // REGRESJA (todo.core_infra.md): ukryte pliki uniksowe (`.bashrc`,
    // `.xauthority`, `.gitignore`) mają wiodącą kropkę jako część KONWENCJI
    // NAZEWNICZEJ, nie jako separator rozszerzenia - cała nazwa PO kropce to
    // ich WŁAŚCIWA NAZWA, nie rozszerzenie do zweryfikowania. Bez tego
    // rozróżnienia `.bashrc` trafiał w tę samą gałąź co `plik.jpg` -
    // `ext_parts` stawało się `["bashrc"]`, więc KAŻDY ukryty plik z realnie
    // rozpoznawalną sygnaturą binarną (np. ukryty JPG/PNG/ZIP zapisany bez
    // właściwego rozszerzenia - dokładnie scenariusz, który to narzędzie ma
    // WYKRYWAĆ, nie fałszywie oskarżać) dostawał fałszywy "Spoofing Alert"
    // tylko dlatego, że jego WŁASNA NAZWA nie zgadzała się z jego prawdziwym
    // typem. Sprawdzamy więc, czy poza WIODĄCĄ kropką istnieje jeszcze
    // JAKAKOLWIEK inna - jeśli nie, traktujemy to tak samo jak "brak
    // rozszerzenia" wyżej.
    let nazwa_bez_wiodacej_kropki = file_name.strip_prefix('.').unwrap_or(file_name.as_str());
    if !nazwa_bez_wiodacej_kropki.contains('.') {
        return Some(true);
    }

    let parts: Vec<&str> = file_name.split('.').filter(|s| !s.is_empty()).collect();
    let ext_parts = if parts.len() > 1 { &parts[1..] } else { &parts[0..] };

    // ETAP 1: Szybki rzut okiem do wbudowanej bazy (biblioteka `infer`)
    match infer::get_from_path(path) {
        Ok(Some(kind)) => {
            let kind_ext = kind.extension();
            let matches = ext_parts.iter().any(|&ext| {
                kind_ext == ext || matches!((kind_ext, ext), 
                    ("jpg", "jpeg") | ("jpeg", "jpg") |
                    ("tif", "tiff") | ("tiff", "tif") |
                    ("tif", "dng") | ("tiff", "dng") | ("tif", "cr2") | ("tif", "nef") | ("tif", "arw") |
                    ("heic", "heif") | ("heif", "heic") | ("heic", "hef") | ("heif", "hef") |
                    ("mp4", "m4v") | ("mov", "mp4") | ("mp4", "mov") |
                    ("mkv", "webm") | ("webm", "mkv") |
                    ("mpeg", "mpg") | ("mpg", "mpeg") | ("mpeg", "ts") | ("mpg", "ts") |
                    ("ogg", "ogv") | ("ogg", "oga") | ("ogg", "ogx") |
                    ("flv", "f4v") |
                    ("zip", "docx") | ("zip", "xlsx") | ("zip", "pptx") |
                    ("zip", "odt") | ("zip", "ods") | ("zip", "odp") |
                    ("zip", "epub") | ("zip", "apk") | ("zip", "jar") |
                    ("gz", "tar") | ("bz2", "tar") | ("7z", "tar") | ("rar", "tar") |
                    ("sqlite", "db") | ("sqlite", "sqlite3") | ("sqlite3", "db") |
                    ("htm", "html") | ("html", "htm") |
                    ("mid", "midi") | ("midi", "mid")
                )
            });

            if !matches {
                warn!(
                    nazwa = %file_name, wykryte_magic = %kind_ext,
                    "Zapisano w dzienniku: Spoofing Alert - Niezgodność binarnych Magic Bytes."
                );
            }
            Some(matches)
        }
        Ok(None) => {
            // ETAP 2: Heurystyka Tekstowa (Złota Tarcza oszczędzająca procesor)
            if let Ok(mut file) = File::open(path) {
                let mut buf = [0u8; 512];
                if let Ok(bytes_read) = file.read(&mut buf) {
                    if bytes_read == 0 {
                        return Some(true); // Pusty plik to wciąż poprawny plik
                    }
                    let printable = buf[..bytes_read].iter().filter(|&&b| (32..=126).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t').count();
                    if (printable as f32 / bytes_read as f32) > 0.90 {
                        info!("Oszczędzono procesor: Wykryto bezpieczny kod źródłowy/tekst.");
                        return Some(true);
                    }
                }
            }

            // ETAP 3: Ciężki Parser (exiftool_rs)
            debug!("Zupa binarna nierozpoznana przez 'infer'. Odpalam ciężki analizator exiftool_rs.");
            if let Ok(meta) = exiftool_rs::image_info(path.to_str().unwrap_or(""))
                && let Some(mime) = meta.get("MIMEType") {
                    let mime_str = mime.to_lowercase();
                    if mime_str.starts_with("text/") || mime_str == "application/json" || mime_str == "application/xml" {
                        return Some(true);
                    } else {
                        warn!(
                            wykryte_mime = %mime_str,
                            "Zapisano w dzienniku: Plik posiada wadliwe formatowanie systemowe."
                        );
                    }
                }
            Some(true)
        }
        Err(e) => {
            error!(error = %e, "Krytyczny błąd I/O przy odczycie nagłówka systemowego");
            None
        }
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_format_display_path_no_truncation() {
        let long_path = "/bardzo/dluga/sciezka/do/zrodla/ktora/ma/ponad/sto/znakow/poniewaz/uzytkownik/chce/widziec/calosc/plik.txt";
        let result = format_display_path(long_path);
        assert_eq!(result, long_path);
    }

    /// REGRESJA (todo.core_infra.md): próg sanityzacji blokował CAŁE
    /// alfabety CJK/Hangul, nie tylko emoji/znaki kontrolne. Nazwy plików w
    /// tych alfabetach są częste w realnych korpusach (np. zrzuty z
    /// urządzeń japońskich/koreańskich) i muszą przechodzić bez zmian.
    #[test]
    fn test_znaki_cjk_i_hangul_przechodza_bez_zmian() {
        assert_eq!(format_display_path("/dane/写真.jpg"), "/dane/写真.jpg", "CJK Unified Ideographs");
        assert_eq!(format_display_path("/dane/ひらがな.jpg"), "/dane/ひらがな.jpg", "Hiragana");
        assert_eq!(format_display_path("/dane/カタカナ.jpg"), "/dane/カタカナ.jpg", "Katakana");
        assert_eq!(format_display_path("/dane/한글파일.jpg"), "/dane/한글파일.jpg", "Hangul Syllables");
    }

    /// Kontrola pozytywna: naprawa nie może wyłączyć blokady w ogóle -
    /// prawdziwe emoji (płaszczyzna dodatkowa, znacznie powyżej progu) nadal
    /// musi zostać zamienione na `_`.
    #[test]
    fn test_prawdziwe_emoji_nadal_jest_blokowane() {
        let wynik = format_display_path("/dane/plik😀.jpg");
        assert!(!wynik.contains('😀'), "emoji musi zostać zablokowane: {}", wynik);
        assert_eq!(wynik, "/dane/plik_.jpg");
    }

    #[test]
    fn test_znaki_kontrolne_nadal_sa_blokowane() {
        let wynik = format_display_path("/dane/plik\x07dzwonek.jpg");
        assert_eq!(wynik, "/dane/plik_dzwonek.jpg");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2048), "2.00 KB");
        assert_eq!(format_bytes(1572864), "1.50 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_hash_file_correctness() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Weryfikator3a Kryminalistyka").unwrap();
        let hash = hash_file(temp_file.path()).expect("Nie udało się zhashować");
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64);
    }

    #[test]
    #[ignore = "Mutuje globalny CANCEL_SIGNAL współdzielony ze wszystkimi testami \
                w tym binarnym pliku testowym. cargo test domyślnie uruchamia testy \
                równolegle w jednym procesie, więc równoczesny test odczytujący \
                CANCEL_SIGNAL mógłby dostać fałszywe 'true'. Uruchamiaj świadomie: \
                `cargo test -- --ignored test_hash_file_respects_cancel_signal`."]
    fn test_hash_file_respects_cancel_signal() {
        // Weryfikuje, że hash_file() natychmiast przerywa pracę i zwraca
        // ErrorKind::Interrupted, gdy globalny CANCEL_SIGNAL jest już ustawiony
        // przed rozpoczęciem odczytu (ścieżka buforowana, plik < 16MB).
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Dane testowe do przerwanego hashowania").unwrap();

        CANCEL_SIGNAL.store(true, Ordering::SeqCst);
        let result = hash_file(temp_file.path());
        CANCEL_SIGNAL.store(false, Ordering::SeqCst); // Sprzątanie stanu globalnego po teście

        match result {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Interrupted),
            Ok(_) => panic!("hash_file powinno zwrócić błąd Interrupted, gdy CANCEL_SIGNAL = true"),
        }
    }

    #[test]
    fn test_fast_text_heuristic_bypasses_exiftool() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"{\"status\": \"ok\", \"value\": 1}").unwrap();
        let new_path = temp_file.path().with_extension("nietypowe_rozszerzenie");
        std::fs::rename(temp_file.path(), &new_path).unwrap();

        let is_ok = check_magic(&new_path);
        assert_eq!(is_ok, Some(true));
    }

    // Sygnatura GZIP - wystarczy do rozpoznania przez `infer`, nie musi być
    // kompletnym, poprawnym strumieniem (sniffing nagłówka, nie dekodowanie).
    const GZIP_MAGIC: &[u8] = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03reszta danych";

    /// REGRESJA (todo.core_infra.md): plik ukryty uniksowy (`.bashrc` i
    /// podobne) ma wiodącą kropkę jako KONWENCJĘ NAZEWNICZĄ, nie separator
    /// rozszerzenia - jego treść nie ma z czym porównać, więc NIE MOŻE
    /// dostać fałszywego alarmu "Spoofing", nawet gdy rozpoznawalna binarnie
    /// (dokładnie odwrotność tego, co narzędzie ma wykrywać).
    #[test]
    fn test_ukryty_plik_bez_prawdziwego_rozszerzenia_nie_dostaje_falszywego_alarmu() {
        let dir = tempfile::tempdir().unwrap();
        let sciezka = dir.path().join(".ukryty_bez_rozszerzenia");
        std::fs::write(&sciezka, GZIP_MAGIC).unwrap();

        assert_eq!(
            check_magic(&sciezka), Some(true),
            "plik ukryty BEZ prawdziwego rozszerzenia nie może dostać fałszywego alarmu spoofing"
        );
    }

    /// Kontrola pozytywna: gdy ukryty plik MA realne (drugie) rozszerzenie,
    /// wykrywanie fałszerstwa musi nadal działać poprawnie - naprawa dotyczy
    /// wyłącznie przypadku "brak rozszerzenia", nie wyłącza detekcji w ogóle.
    #[test]
    fn test_ukryty_plik_z_prawdziwym_zlym_rozszerzeniem_nadal_wykrywa_spoofing() {
        let dir = tempfile::tempdir().unwrap();
        let sciezka = dir.path().join(".ukryty.txt");
        std::fs::write(&sciezka, GZIP_MAGIC).unwrap();

        assert_eq!(
            check_magic(&sciezka), Some(false),
            "GZIP zadeklarowany jako .txt musi zostać wykryty jako spoofing, nawet dla pliku ukrytego"
        );
    }

    /// Skrajny przypadek: nazwa złożona z samych kropek nie może panikować
    /// (regresja od strony bezpieczeństwa naprawy - `parts` może wyjść puste).
    #[test]
    fn test_nazwa_z_samych_kropek_nie_panikuje() {
        let dir = tempfile::tempdir().unwrap();
        let sciezka = dir.path().join("...");
        std::fs::write(&sciezka, b"cokolwiek").unwrap();

        let _ = check_magic(&sciezka);
    }

    // ------------------------------------------------------------------
    // POGODZENIE ZNACZNIKÓW PRZERWANIA MIĘDZY BIBLIOTEKAMI
    // ------------------------------------------------------------------

    /// Podniesienie przerwania musi dotknąć OBU znaczników.
    ///
    /// Zanim to powstało, `Ctrl+C` ustawiał wyłącznie nasz `CANCEL_SIGNAL`, a
    /// długie pętle `mp4_doctor` (poligon treningowy, pobieranie dawców)
    /// czytały swój własny `SHUTDOWN_FLAG` i pracowały dalej.
    ///
    /// Test mutuje stan GLOBALNY procesu, więc na końcu sprząta po sobie —
    /// inaczej zostawiłby podniesiony znacznik i zatrzymał inne testy.
    #[test]
    #[ignore = "Mutuje globalne znaczniki przerwania współdzielone ze wszystkimi \
                testami w tej binarce. Uruchom z --ignored."]
    fn test_podniesienie_przerwania_dotyka_obu_znacznikow() {
        let nasz_przed = CANCEL_SIGNAL.load(Ordering::SeqCst);
        let ich_przed = mp4_doctor::SHUTDOWN_FLAG.load(Ordering::SeqCst);

        zdejmij_przerwanie();
        assert!(!CANCEL_SIGNAL.load(Ordering::SeqCst));
        assert!(!mp4_doctor::SHUTDOWN_FLAG.load(Ordering::SeqCst));

        podnies_przerwanie();
        assert!(CANCEL_SIGNAL.load(Ordering::SeqCst), "nasz znacznik musi zostać podniesiony");
        assert!(
            mp4_doctor::SHUTDOWN_FLAG.load(Ordering::SeqCst),
            "znacznik mp4_doctor też - inaczej jego wątki pracują po Ctrl+C"
        );

        zdejmij_przerwanie();
        assert!(!CANCEL_SIGNAL.load(Ordering::SeqCst), "zdjęcie musi działać w drugą stronę");
        assert!(!mp4_doctor::SHUTDOWN_FLAG.load(Ordering::SeqCst));

        // Przywrócenie stanu wyjściowego procesu.
        CANCEL_SIGNAL.store(nasz_przed, Ordering::SeqCst);
        mp4_doctor::SHUTDOWN_FLAG.store(ich_przed, Ordering::SeqCst);
    }

    // ------------------------------------------------------------------
    // KATALOG PRZESTRZENI ROBOCZYCH MP4 DOCTOR
    // ------------------------------------------------------------------

    /// Baza i katalogi `mp4_doctor` muszą powstawać tam, gdzie wskażemy, a nie
    /// w katalogu uruchomienia.
    ///
    /// Wcześniej ścieżka `workspaces` była WZGLĘDNA, więc przestrzenie robocze
    /// powstawały tam, skąd odpalono program — obok cudzych plików i z dala od
    /// `target_path`, gdzie Weryfikator trzyma wszystkie pozostałe wytwory.
    ///
    /// UWAGA: katalog jest procesowym `OnceLock`, więc PIERWSZE wskazanie w
    /// tej binarce wygrywa na zawsze — niezależnie, z którego testu przyjdzie.
    ///
    /// Od czasu, gdy `phases::phase17_repair::run` zaczęła sama wskazywać ten
    /// katalog (żeby moduł `mp4_autopilot` dzielił pulę dawców z ręcznym menu
    /// „[25] MP4 DOCTOR"), ten test PRZESTAŁ być jedynym wywołującym w
    /// binarce `weryfikator` — testy `phase17_repair` też wołają `run()`, a
    /// kolejność testów w jednym binarze nie jest gwarantowana. Test nie może
    /// więc już zakładać, że TO ON ustawi katalog jako pierwszy — sprawdza
    /// więc oba możliwe wyniki wyścigu, zamiast zakładać jeden z nich.
    #[test]
    fn test_katalog_przestrzeni_mp4_doctor_daje_sie_wskazac() {
        let dir = tempfile::tempdir().unwrap();
        let cel = dir.path().join("_mp4_doctor");

        let ustawiono = mp4_doctor::workspace::ustaw_katalog_przestrzeni(cel.clone());

        if ustawiono {
            // Wygraliśmy wyścig: pełna asercja, tak jak wcześniej.
            assert_eq!(mp4_doctor::workspace::katalog_przestrzeni(), cel);

            // Jednorazowość: drugie wskazanie nie może podmienić katalogu w
            // trakcie pracy, bo unieważniłoby już otwarte ścieżki.
            assert!(
                !mp4_doctor::workspace::ustaw_katalog_przestrzeni(dir.path().join("inny")),
                "drugie wskazanie musi zostać odrzucone"
            );
            assert_eq!(mp4_doctor::workspace::katalog_przestrzeni(), cel, "katalog nie mógł się zmienić");

            // I skutek praktyczny: przestrzeń robocza powstaje pod wskazanym
            // katalogiem, razem z plikiem bazy wiedzy.
            let ws = mp4_doctor::workspace::Workspace::init("sprawa_testowa")
                .expect("przestrzeń robocza musi się utworzyć");

            assert!(ws.root_dir.starts_with(&cel), "korzeń przestrzeni: {}", ws.root_dir.display());
            assert!(ws.db_path.starts_with(&cel), "baza wiedzy: {}", ws.db_path.display());
            assert!(ws.root_dir.exists(), "katalogi muszą powstać fizycznie");
            assert!(cel.join("sprawa_testowa").exists(), "przestrzeń musi leżeć pod WSKAZANYM katalogiem");
        } else {
            // Przegraliśmy wyścig z innym testem tej samej binarki (np.
            // `phase17_repair`'owym `run()`) — katalog jest już zajęty przez
            // kogoś innego. Sprawdzamy tylko, że odczyt daje spójny,
            // faktycznie istniejący katalog, a nie NASZ `cel` — bo `cel`
            // nigdy nie wygrał.
            let aktywny = mp4_doctor::workspace::katalog_przestrzeni();
            assert_ne!(aktywny, cel, "skoro przegraliśmy, katalog NIE MOŻE być naszym `cel`");

            let ws = mp4_doctor::workspace::Workspace::init("sprawa_testowa_przegrany_wyscig")
                .expect("przestrzeń robocza musi się utworzyć nawet po przegranym wyścigu");
            assert!(ws.root_dir.starts_with(&aktywny), "korzeń przestrzeni: {}", ws.root_dir.display());
            assert!(ws.root_dir.exists(), "katalogi muszą powstać fizycznie");
        }

        // Asercję w formie „nic nie powstało w ./workspaces" świadomie
        // odrzuciłem: zależy od całej historii procesu i katalogu roboczego,
        // więc padała od śmiecia zostawionego przez inny przebieg. Forma
        // pozytywna — „powstało DOKŁADNIE tam, gdzie wskazano" — mierzy to
        // samo, a nie zależy od otoczenia.
    }
}
