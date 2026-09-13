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
        if c.is_control() || c as u32 > 0x25FF {
            '_'
        } else {
            c
        }
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
    /// UWAGA: katalog jest procesowym `OnceLock` ustawianym RAZ, więc taki test
    /// może istnieć tylko JEDEN w tej binarce. Kolejny nie miałby czego ustawić.
    #[test]
    fn test_katalog_przestrzeni_mp4_doctor_daje_sie_wskazac() {
        let dir = tempfile::tempdir().unwrap();
        let cel = dir.path().join("_mp4_doctor");

        let ustawiono = mp4_doctor::workspace::ustaw_katalog_przestrzeni(cel.clone());
        assert!(ustawiono, "pierwsze wskazanie musi się udać");
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

        // Asercję w formie „nic nie powstało w ./workspaces" świadomie
        // odrzuciłem: zależy od całej historii procesu i katalogu roboczego,
        // więc padała od śmiecia zostawionego przez inny przebieg. Forma
        // pozytywna — „powstało DOKŁADNIE tam, gdzie wskazano" — mierzy to
        // samo, a nie zależy od otoczenia.
    }
}
