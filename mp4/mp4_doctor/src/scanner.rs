// src/scanner.rs

//! Moduł `scanner` realizuje autonomiczną analizę folderów w architekturze Enterprise.
//! 
//! Przeszukuje rekursywnie wskazany katalog i ocenia stan każdego pliku wideo.
//! Wersja ta wykorzystuje zaawansowany wzorzec potoku współbieżnego (Pipeline MPSC).
//! 
//! # Architektura Linia Montażowa (MPSC)
//! Aby uniknąć problemu "database is locked" (częstego dla SQLite przy wielu wątkach),
//! oddzieliliśmy ciężką pracę od zapisu do bazy:
//! 1. **Producenci (Wątki Rayon):** Skanują pliki, analizują binarne DNA, przeprowadzają naprawę. 
//!    Nie dotykają bazy danych bezpośrednio! Zamiast tego wysyłają wiadomości przez kanał.
//! 2. **Konsument (Wątek UI/DB):** Odbiera wiadomości od producentów. Aktualizuje 
//!    estetyczne paski postępu (HUD) w terminalu i bezpiecznie, synchronicznie zapisuje 
//!    zdobytą wiedzę do bazy SQLite.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};

use byteorder::{BigEndian, ReadBytesExt};
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;

use crate::workspace::Workspace;
use crate::{autopilot, db, dna};
use crate::SHUTDOWN_FLAG;
use crate::get_thread_count;
use crate::event::{EventSender, StatUpdate};

// =========================================================
// STRUKTURY KOMUNIKACYJNE (Wiadomości na linii montażowej)
// =========================================================

/// System wiadomości przesyłanych od wątków roboczych (Workerów) do wątku zarządzającego (Konsumenta).
#[allow(dead_code)]
pub enum PipelineMsg {
    /// Informacja o tym, nad czym aktualnie pracuje dany wątek (Do aktualizacji spinnera).
    /// Zawiera: (ID wątku, Treść wiadomości)
    ThreadStatus(usize, String),
    /// Wątek znalazł zdrowego dawcę i wyodrębnił jego nagłówek na dysk.
    /// Zawiera: (Sygnatura DNA, Ścieżka do nagłówka .moov)
    FoundDonor(String, String),
    /// Wątek natrafił na uszkodzony plik i zaczyna walkę o jego ożywienie.
    /// Zawiera: (Nazwa uszkodzonego pliku)
    Broken(String),
    /// Wątek (Autopilot) z sukcesem naprawił plik, sędzia to zatwierdził. Należy nagrodzić algorytm w bazie.
    /// Zawiera: (Nazwa pliku, Sygnatura DNA, Nazwa wygranego algorytmu)
    Repaired(String, String, String),
    /// Wątek (Autopilot) poniósł porażkę z danym algorytmem. Należy ukarać algorytm punktami ujemnymi.
    /// Zawiera: (Nazwa pliku, Sygnatura DNA, Nazwa przegranego algorytmu)
    Failed(String, String, String),
    Processed,
}

// =========================================================
// FUNKCJE POMOCNICZE (Narzędzia Workerów)
// =========================================================

/// Szybka sonda weryfikująca, czy plik jest w miarę sprawny na poziomie kontenera.
/// Wykorzystuje `ffprobe` do odpytania pliku o czas trwania.
fn is_healthy(file_path: &str) -> bool {
    let out = Command::new("ffprobe")
        .arg("-v").arg("error")
        .arg("-show_entries").arg("format=duration")
        .arg("-of").arg("default=noprint_wrappers=1:nokey=1")
        .arg(file_path)
        .output();

    if let Ok(res) = out {
        res.status.success() && !String::from_utf8_lossy(&res.stdout).trim().is_empty()
    } else {
        false
    }
}

/// Chirurgicznie wycina sam atom `moov` (nagłówek MP4) ze zdrowego pliku 
/// i zapisuje go na dysk w folderze dawców. Ignoruje ciężkie dane `mdat`.
pub fn extract_and_save_moov(source_mp4: &str, dest_moov: &str) -> io::Result<()> {
    let mut file = File::open(source_mp4)?;
    let file_size = file.metadata()?.len();
    let mut position = 0;

    while position < file_size {
        let size_32 = match file.read_u32::<BigEndian>() {
            Ok(s) => s,
            Err(_) => break,
        };
        
        let mut box_type = [0u8; 4];
        file.read_exact(&mut box_type)?;
        
        let mut actual_size = size_32 as u64;
        if size_32 == 1 {
            actual_size = file.read_u64::<BigEndian>()?;
        } else if size_32 < 8 {
            break; 
        }

        // NAPRAWIONE PRZEPEŁNIENIE: `position += actual_size` przy złośliwie
        // dużym rozmiarze atomu (0xFFFFFFFF albo rozszerzony 64-bitowy bliski
        // `u64::MAX`) przepełniało dodawanie — w profilu debug panikowało
        // („attempt to add with overflow"), a w release zawijało się cicho,
        // dając błędny `seek` i nieskończoną pętlę. `saturating_add` plus
        // kontrola granic zamykają oba warianty.
        let koniec_atomu = position.saturating_add(actual_size);

        if actual_size == 0 {
            break;
        }

        if &box_type == b"moov" {
            // NAPRAWIONE CICHE UCIĘCIE: `io::copy` kończy się SUKCESEM także
            // wtedy, gdy źródło urwało się wcześniej — funkcja zwracała więc
            // `Ok(())`, zapisawszy NIEPEŁNY atom `moov`. Wywołujący dostawał
            // plik dawcy, który wyglądał na gotowy, a nie był.
            if koniec_atomu > file_size {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "Atom moov ucięty: deklaruje {} B, a od offsetu {} zostaje w pliku tylko {} B",
                        actual_size, position, file_size.saturating_sub(position)
                    ),
                ));
            }

            file.seek(SeekFrom::Start(position))?;
            let mut out = File::create(dest_moov)?;
            let mut taker = file.take(actual_size);
            let skopiowane = io::copy(&mut taker, &mut out)?;

            if skopiowane != actual_size {
                // Nie zostawiamy połowicznego pliku dawcy na dysku.
                drop(out);
                let _ = fs::remove_file(dest_moov);
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("Atom moov ucięty: zapisano {} z {} bajtów", skopiowane, actual_size),
                ));
            }

            return Ok(());
        }

        if koniec_atomu > file_size {
            // Atom wychodzi za koniec pliku — dalej łańcuch jest już
            // niewiarygodny, nie ma sensu iść w losowe offsety.
            break;
        }

        position = koniec_atomu;
        file.seek(SeekFrom::Start(position))?;
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "Nie znaleziono atomu moov w pliku."))
}

/// Przeszukuje rekursywnie wskazany katalog i zbiera wszystkie pliki .mp4 lub .mov.
fn gather_files(dir: &Path, files: &mut Vec<String>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                gather_files(&path, files);
            } else if path.is_file()
                && let Some(ext) = path.extension().and_then(|e| e.to_str())
                    && (ext.eq_ignore_ascii_case("mp4") || ext.eq_ignore_ascii_case("mov")) {
                        files.push(path.to_str().unwrap().to_string());
                    }
        }
    }
}

// =========================================================
// GŁÓWNY EGZEKUTOR (System Potokowy)
// =========================================================

/// Odpala wielowątkowy skaner oparty o architekturę Producent-Konsument.
#[derive(PartialEq, Clone, Copy)]
pub enum ScanMode {
    SingleRepair,
    ExtractOnly,
    FullAuto,
}

pub fn run_scanner(
    ws: &Workspace, 
    target_dir: &str, 
    mode: ScanMode,
    event_sender: &EventSender,
) {
    event_sender.operation_started(format!("Skanowanie: {}", target_dir));
    event_sender.info("SCANNER", format!("Głęboka analiza drzewa katalogów: {}", target_dir));
    
    // 1. Inicjalizacja izolowanego logowania do pliku
    crate::logger::init(&ws.root_dir.join("doktor_raport.log"));
    
    // 2. Zarządzanie zasobami (CPU)
    let thread_limit = get_thread_count();
    let thread_num = if thread_limit > 0 { 
        event_sender.info("RAYON", format!("Limitowanie zasobów CPU: {} wątek/wątków.", thread_limit));
        thread_limit 
    } else { 
        let cpus = num_cpus::get();
        event_sender.info("RAYON", format!("Tryb AUTO: Pełna moc wielordzeniowa ({} wątków).", cpus));
        cpus 
    };

    let pool = ThreadPoolBuilder::new().num_threads(thread_num).build().unwrap();

    let mut files = Vec::new();
    gather_files(Path::new(target_dir), &mut files);
    let total_files = files.len();
    
    if total_files == 0 {
        event_sender.warn("SCANNER", "Nie znaleziono żadnych plików MP4/MOV w podanym katalogu.");
        event_sender.operation_finished("Skanowanie zakończone: brak plików");
        return;
    }

    // 3. Ładowanie pamięci RAM Cache
    event_sender.debug("SCANNER", "Ładowanie bazy wiedzy o algorytmach do pamięci RAM...");
    let brain_cache = db::build_brain_cache(ws).unwrap_or_default();

    // 4. Inicjalizacja telemetryczna przez EventSender
    for i in 0..thread_num {
        event_sender.update_thread(i, "Oczekiwanie...");
    }
    event_sender.progress(0, total_files, Some(format!("0/{} plików", total_files)));
    
    let processed_count = AtomicUsize::new(0);
    let healthy_count = AtomicUsize::new(
        std::fs::read_dir(&ws.donors_dir).map(|i| i.count()).unwrap_or(0)
    );
    let broken_count = AtomicUsize::new(
        std::fs::read_dir(&ws.broken_dir).map(|i| i.count()).unwrap_or(0)
    );
    let repaired_count = AtomicUsize::new(
        std::fs::read_dir(&ws.output_dir).map(|i| i.count()).unwrap_or(0)
    );
    let bytes_processed = AtomicU64::new(0);

    event_sender.update_stats(StatUpdate::new(
        0,
        healthy_count.load(Ordering::Relaxed),
        broken_count.load(Ordering::Relaxed),
        repaired_count.load(Ordering::Relaxed),
        0,
        thread_num,
    ));

    // =========================================================
    // PRODUCENCI (Praca wielowątkowa w puli Rayon)
    // =========================================================
    pool.install(|| {
        files.into_par_iter().for_each(|file| {
            if SHUTDOWN_FLAG.load(Ordering::Relaxed) { return; }
            
            let tid = rayon::current_thread_index().unwrap_or(0) % thread_num;
            let file_name = Path::new(&file).file_name().unwrap().to_string_lossy().to_string();
            let file_bytes = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
            bytes_processed.fetch_add(file_bytes, Ordering::Relaxed);
            
            event_sender.debug("SCANNER", format!("Przetwarzanie pliku: {}", file));
            event_sender.update_thread(tid, format!("🔍 Skanowanie: {}", file_name));

            if is_healthy(&file) {
                healthy_count.fetch_add(1, Ordering::Relaxed);
                if mode != ScanMode::SingleRepair
                    && let Some((dna, _)) = dna::extract_dna(&file) {
                        // Nazwa dawcy to sama sygnatura DNA — tak indeksuje ich
                        // Kolektywny Rój (`/v1/swarm/donor/{dna}`), więc jeden
                        // dawca na DNA jest zamierzony.
                        //
                        // Stał tu wcześniej `short_hash` z `DefaultHasher` po
                        // nazwie pliku, nigdzie nieużywany: hasher powstawał i
                        // liczył się dla KAŻDEGO zdrowego pliku, a wynik był
                        // natychmiast wyrzucany.
                        let safe_name = format!("DONOR_{}.moov", dna);
                        let donor_path = ws.donors_dir.join(&safe_name);
                        
                        if extract_and_save_moov(&file, donor_path.to_str().unwrap()).is_ok() {
                            event_sender.donor_found(&dna, donor_path.to_str().unwrap());
                        }
                    }
            } else {
                broken_count.fetch_add(1, Ordering::Relaxed);
                if mode != ScanMode::ExtractOnly {
                    event_sender.warn("SCANNER", format!("Wykryto uszkodzony plik: {}", file_name));
                    event_sender.update_thread(tid, format!("🛠️ Naprawa: {}", file_name));
                    
                    let repair_res = autopilot::run(ws, &file, &brain_cache, event_sender, tid);
                    if repair_res.is_ok() {
                        repaired_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            
            let cur = processed_count.fetch_add(1, Ordering::Relaxed) + 1;
            event_sender.progress(cur, total_files, Some(format!("{}/{} plików", cur, total_files)));
            event_sender.update_stats(StatUpdate::new(
                cur,
                healthy_count.load(Ordering::Relaxed),
                broken_count.load(Ordering::Relaxed),
                repaired_count.load(Ordering::Relaxed),
                bytes_processed.load(Ordering::Relaxed),
                thread_num,
            ));
            event_sender.update_thread(tid, "Oczekiwanie...");
        });
    });

    for i in 0..thread_num {
        event_sender.update_thread(i, "Zakończono");
    }
    event_sender.operation_finished(format!(
        "Zakończono analizę potokową: {} plików, {} zdrowych/dawców, {} uszkodzonych, {} naprawionych",
        total_files,
        healthy_count.load(Ordering::Relaxed),
        broken_count.load(Ordering::Relaxed),
        repaired_count.load(Ordering::Relaxed),
    ));
}

/// Alias dla skanowania katalogu przyjmujący EventSender (zarówno przez referencję, jak i wartość)
pub fn scan_directory<E: std::borrow::Borrow<EventSender>>(
    ws: &Workspace,
    target_dir: &str,
    mode: ScanMode,
    event_sender: E,
) {
    run_scanner(ws, target_dir, mode, event_sender.borrow());
}

/// Samodzielny punkt wejścia bez jawnej szyny TUI (headless CLI, testy).
///
/// Odbiór zdarzeń robi [`crate::bezglowe::z_odbiorem`] — wcześniej ta funkcja
/// miała własny, wklejony tu wątek odbierający, powielony jeszcze raz w
/// `main.rs`. Wspólny odbiornik dokłada do tego wypisywanie postępu na
/// `stdout`, którego ta wersja nie miała.
pub fn run_scanner_standalone(ws: &Workspace, target_dir: &str, mode: ScanMode) {
    crate::bezglowe::z_odbiorem(ws, |tx| run_scanner(ws, target_dir, mode, tx));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_healthy_scanner() {
        let path = "tests/assets/test_video.mp4";
        assert!(is_healthy(path), "Skaner powinien uznać plik za zdrowy.");
    }

    #[test]
    fn test_gather_files() {
        let mut files = Vec::new();
        gather_files(Path::new("tests/assets"), &mut files);
        assert!(!files.is_empty(), "Skaner powinien znaleźć nasz wygenerowany plik testowy.");
    }
}
