use crate::workspace::Workspace;
use crate::autopilot;
use crate::event::EventSender;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Prosty generator liczb pseudolosowych bez dodawania ciężkich zależności (LCG)
struct SimpleRng {
    state: u64,
}
impl SimpleRng {
    fn new() -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        SimpleRng { state: now }
    }
    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 32) as u32
    }
}

/// Aplikuje przepięcia termiczne i uszkodzenia karty SD (Bit Flipping i gubienie pakietów)
pub fn run_extreme_mutation(
    ws: &Workspace,
    healthy_path: &str,
    event_sender: &EventSender,
) -> Result<(), Box<dyn std::error::Error>> {
    event_sender.operation_started("God Mode: Komora Radiacyjna");
    
    let path = if healthy_path.trim().is_empty() {
        Path::new(".")
    } else {
        Path::new(healthy_path)
    };

    let mut files_to_process = Vec::new();
    
    if path.is_file() {
        files_to_process.push(path.to_path_buf());
    } else if path.is_dir() {
        event_sender.info("GOD_MODE", format!("Skanowanie katalogu w poszukiwaniu plików do mutacji: {:?}", path));
        
        fn gather_god_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        gather_god_files(&p, files);
                    } else if p.is_file() {
                        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                        if ext == "mp4" || ext == "mov" || ext == "m4v" {
                            files.push(p.clone());
                        }
                    }
                }
            }
        }
        
        gather_god_files(path, &mut files_to_process);
    } else {
        let err_msg = format!("Podana ścieżka nie istnieje lub jest nieprawidłowa: {:?}", path);
        event_sender.error("GOD_MODE", &err_msg);
        event_sender.operation_failed("God Mode", &err_msg);
        return Err(err_msg.into());
    }
    
    if files_to_process.is_empty() {
        let err_msg = "Nie znaleziono żadnych plików wideo do zmutowania.";
        event_sender.error("GOD_MODE", err_msg);
        event_sender.operation_failed("God Mode", err_msg);
        return Ok(());
    }

    let cache = crate::db::build_brain_cache(ws).unwrap_or_default();
    let mut success_count = 0;
    let total_files = files_to_process.len();

    for (idx, p) in files_to_process.iter().enumerate() {
        if crate::SHUTDOWN_FLAG.load(std::sync::atomic::Ordering::Relaxed) {
            event_sender.warn("GOD_MODE", "Przerwano przez użytkownika.");
            break;
        }
        
        let file_name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
        event_sender.info("GOD_MODE", format!("[{}/{}] Inicjalizacja komory radiacyjnej dla: {}", idx + 1, total_files, file_name));
        
        let mut in_file = match File::open(p) {
            Ok(f) => f,
            Err(e) => {
                event_sender.error("GOD_MODE", format!("Nie można otworzyć pliku {}: {}", file_name, e));
                continue;
            }
        };
        
        let mut data = Vec::new();
        if let Err(e) = in_file.read_to_end(&mut data) {
            event_sender.error("GOD_MODE", format!("Błąd odczytu {}: {}", file_name, e));
            continue;
        }
        
        // 1. Zniszczenie atomu MOOV
        let mut moov_start = None;
        for i in 0..data.len().saturating_sub(8) {
            if &data[i..i+4] == b"moov" {
                moov_start = Some(i.saturating_sub(4));
                break;
            }
        }
        
        if let Some(start) = moov_start {
            data.truncate(start);
        }
        
        // 2. Ekstremalne mutacje bitowe
        let mut rng = SimpleRng::new();
        let mutations_count = data.len() / 500_000;
        
        for _ in 0..mutations_count {
            let idx = (rng.next_u32() as usize) % data.len();
            let corruption_length = (rng.next_u32() % 100) as usize + 1;
            for j in 0..corruption_length {
                if idx + j < data.len() {
                    data[idx + j] ^= (rng.next_u32() % 255) as u8;
                }
            }
        }
        
        let mutant_path = ws.broken_dir.join(format!("MUTANT_{}", file_name));
        if let Ok(mut out_file) = File::create(&mutant_path) {
            let _ = out_file.write_all(&data);
        }
        
        event_sender.info("GOD_MODE", format!("Wygenerowano zmutowany plik MP4: {:?}", mutant_path));
        
        let mutant_str = mutant_path.to_str().unwrap();
        match autopilot::run(ws, mutant_str, &cache, event_sender, 0) {
            Ok(_) => {
                event_sender.success("GOD_MODE", "AI zdołało wyleczyć radioaktywny plik! Tarcza zadziałała.");
                success_count += 1;
            }
            Err(e) => {
                event_sender.error("GOD_MODE", format!("Mutant okazał się zbyt zniszczony dla obecnego AI: {}", e));
            }
        }
    }
    
    event_sender.operation_finished(format!("God Mode: Zakończono. Uratowano {}/{} zmutowanych plików.", success_count, total_files));
    Ok(())
}

/// Pomocniczy punkt wejścia w trybie headless
pub fn run_extreme_mutation_headless(
    ws: &Workspace,
    healthy_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::bezglowe::z_odbiorem(ws, |tx| run_extreme_mutation(ws, healthy_file, tx))
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::Workspace;

    fn przestrzen(nazwa: &str) -> Workspace {
        let ws = Workspace::init_testowy(nazwa).expect("przestrzeń testowa musi powstać");
        crate::db::init_db(&ws).expect("baza musi się utworzyć");
        ws
    }

    /// Pusty katalog to realny przypadek: operator wskazuje świeżo utworzone
    /// miejsce. Musi zakończyć się spokojnie, a nie błędem ani paniką.
    #[test]
    fn test_pusty_katalog_konczy_sie_spokojnie() {
        let ws = przestrzen("god_pusty_katalog");
        let pusty = ws.root_dir.join("pusto");
        std::fs::create_dir_all(&pusty).unwrap();
        let (tx, _rx) = crate::event::channel();

        let wynik = run_extreme_mutation(&ws, pusty.to_str().unwrap(), &tx);

        assert!(wynik.is_ok(), "Brak plików do mutacji to nie jest błąd: {:?}", wynik.err());
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    #[test]
    fn test_nieistniejacy_katalog_nie_panikuje() {
        let ws = przestrzen("god_brak_katalogu");
        let (tx, _rx) = crate::event::channel();

        let _ = run_extreme_mutation(&ws, "/nie/ma/takiego/katalogu", &tx);
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    /// Skanowanie bierze wyłącznie kontenery ISOBMFF — plik tekstowy obok
    /// nagrań nie może trafić do mutacji.
    #[test]
    fn test_pliki_spoza_zakresu_sa_pomijane() {
        let ws = przestrzen("god_filtr_rozszerzen");
        let zrodlo = ws.root_dir.join("zrodlo");
        std::fs::create_dir_all(&zrodlo).unwrap();
        std::fs::write(zrodlo.join("notatka.txt"), b"to nie jest wideo").unwrap();
        std::fs::write(zrodlo.join("obraz.jpg"), b"ani to").unwrap();
        let (tx, _rx) = crate::event::channel();

        let wynik = run_extreme_mutation(&ws, zrodlo.to_str().unwrap(), &tx);

        assert!(wynik.is_ok(), "Katalog bez wideo to nie błąd: {:?}", wynik.err());
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }
}
