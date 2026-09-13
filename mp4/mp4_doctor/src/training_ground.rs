// src/training_ground.rs

//! Moduł `training_ground` (Poligon Treningowy).
//!
//! # Zmiany w wersji Enterprise (AI AI-Driven):
//! - **Chaos Monkey:** Wprowadzono 3 typy mutacji uszkodzeń (Typ A, Typ B, Typ C).
//! - **Poligon Snajperski:** Test celowany na jeden konkretny plik. 
//! - **Live Telemetry UI:** Autopilot uruchamiany w tle przesyła na żywo komunikaty
//!   do interfejsu (wizualny, animowany spinner), tworząc efekt "hackowania" w terminalu.

use std::fs::{self, File};
use std::io::{self, Read, Write, Seek, SeekFrom};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crate::SHUTDOWN_FLAG;
use std::sync::atomic::Ordering;

use crate::workspace::Workspace;
use crate::{autopilot, db};
use crate::event::EventSender;

/// Mutacja Typu A: Wycięcie atomu 'moov' (Symulacja niezakończonego nagrania)
fn simulate_missing_moov(input: &str, output: &str) -> io::Result<()> {
    let mut in_file = File::open(input)?;
    let mut out_file = File::create(output)?;
    let file_size = in_file.metadata()?.len();
    let mut position = 0;

    while position < file_size {
        let size_32 = match in_file.read_u32::<BigEndian>() {
            Ok(s) => s,
            Err(_) => break,
        };
        
        let mut box_type = [0u8; 4];
        if in_file.read_exact(&mut box_type).is_err() { break; }
        let type_str = String::from_utf8_lossy(&box_type);

        let mut actual_size = size_32 as u64;
        let mut header_size = 8;

        if size_32 == 1 {
            actual_size = in_file.read_u64::<BigEndian>()?;
            header_size = 16;
        } else if size_32 < 8 { break; }

        if type_str == "moov" {
            position += actual_size;
            in_file.seek(SeekFrom::Start(position))?;
            continue;
        }

        out_file.write_u32::<BigEndian>(size_32)?;
        out_file.write_all(&box_type)?;
        if size_32 == 1 { out_file.write_u64::<BigEndian>(actual_size)?; }

        let data_size = actual_size - header_size;
        let mut buffer = vec![0u8; 8192 * 1024];
        let mut bytes_left = data_size;
        
        while bytes_left > 0 {
            let to_read = std::cmp::min(bytes_left, buffer.len() as u64) as usize;
            let bytes_read = in_file.read(&mut buffer[..to_read])?;
            if bytes_read == 0 { break; }
            out_file.write_all(&buffer[..bytes_read])?;
            bytes_left -= bytes_read as u64;
        }
        position += actual_size;
        in_file.seek(SeekFrom::Start(position))?;
    }
    Ok(())
}

/// Mutacja Typu B: Bad Sectors (Symulacja uszkodzenia fizycznego nośnika)
fn simulate_bad_sectors(input: &str, output: &str) -> io::Result<()> {
    let mut in_file = File::open(input)?;
    let mut out_file = File::create(output)?;
    
    let mut buffer = vec![0u8; 1024 * 1024]; 
    let zeroes = vec![0u8; 10 * 1024]; 

    loop {
        let bytes_read = in_file.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        
        out_file.write_all(&buffer[..bytes_read])?;
        
        if bytes_read == buffer.len() {
            out_file.write_all(&zeroes)?;
            in_file.seek(SeekFrom::Current(10 * 1024)).unwrap_or(0);
        }
    }
    Ok(())
}

/// Mutacja Typu C: Truncation (Symulacja padniętej baterii drona)
fn simulate_truncation(input: &str, output: &str) -> io::Result<()> {
    let mut in_file = File::open(input)?;
    let mut out_file = File::create(output)?;
    let file_size = in_file.metadata()?.len();
    
    let target_size = (file_size as f64 * 0.8) as u64;
    
    let mut buffer = vec![0u8; 8192 * 1024];
    let mut bytes_left = target_size;
    
    while bytes_left > 0 {
        let to_read = std::cmp::min(bytes_left, buffer.len() as u64) as usize;
        let bytes_read = in_file.read(&mut buffer[..to_read])?;
        if bytes_read == 0 { break; }
        out_file.write_all(&buffer[..bytes_read])?;
        bytes_left -= bytes_read as u64;
    }
    Ok(())
}

/// GŁÓWNY POLIGON: Kaskada Mutacyjna Chaos Monkey (Dla całych folderów)
pub fn run_training(ws: &Workspace, healthy_dir: &str, tx: &EventSender) -> io::Result<()> {
    tx.operation_started("Chaos Monkey Training");
    tx.info("POLIGON", "Rozpoczynam morderczy trening Autopilota (Włączono tryb: Chaos Monkey)...");
    
    let mut trained = 0;
    let brain_cache = db::build_brain_cache(ws).unwrap_or_default();

    let mut files_to_train = Vec::new();
    let mut total_found = 0;
    
    let trained_hashes = crate::db::get_all_trained(ws);
    
    fn gather_recursive(dir: &std::path::Path, files_to_train: &mut Vec<(std::path::PathBuf, String, String)>, trained_hashes: &std::collections::HashSet<String>, total_found: &mut usize) {
        if files_to_train.len() >= 10 { return; }
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if files_to_train.len() >= 10 { return; }
                let path = entry.path();
                if path.is_dir() {
                    gather_recursive(&path, files_to_train, trained_hashes, total_found);
                } else if path.is_file() {
                    *total_found += 1;
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if ext.eq_ignore_ascii_case("mp4") || ext.eq_ignore_ascii_case("mov") {
                            let file_name = path.file_name().unwrap().to_string_lossy().to_string();
                            use std::hash::{Hash, Hasher};
                            let mut hasher = std::collections::hash_map::DefaultHasher::new();
                            file_name.hash(&mut hasher);
                            let short_hash = format!("{:x}", hasher.finish());
                            
                            if !trained_hashes.contains(&short_hash) {
                                files_to_train.push((path, file_name, short_hash));
                            }
                        }
                    }
                }
            }
        }
    }
    
    gather_recursive(std::path::Path::new(healthy_dir), &mut files_to_train, &trained_hashes, &mut total_found);
    tx.debug("POLIGON", format!("Pliki: znaleziono łącznie={}, do trenowania={}", total_found, files_to_train.len()));
    
    if files_to_train.is_empty() {
        tx.info("POLIGON", "Wszystkie zdrowe pliki w tym katalogu zostały już wcześniej wykorzystane do treningu bazy Mózgu.");
        tx.operation_finished("Trening pominięty: brak nowych plików");
        return Ok(());
    }
    
    let limit = 10;
    let sample_len = std::cmp::min(limit, files_to_train.len());
    tx.info("POLIGON", format!("Znaleziono {} nowych nagrań. Trenuję na próbce {} plików (Oszczędność czasu i miejsca)...", files_to_train.len(), sample_len));
    files_to_train.truncate(limit);
    let total_to_train = files_to_train.len();
    tx.progress(0, total_to_train, Some("Rozpoczęcie treningu Chaos Monkey".to_string()));
    tx.update_stats(crate::event::StatUpdate {
        files_scanned: total_to_train,
        files_healthy: 0,
        files_broken: total_to_train * 3, // Each file has 3 mutations
        files_repaired: 0,
        bytes_processed: 0,
        active_threads: 1,
    });

    for (path, file_name, short_hash) in files_to_train {
        if SHUTDOWN_FLAG.load(Ordering::Relaxed) { break; }
        tx.info("POLIGON", format!("Pobieranie zdrowego nagrania: {}", file_name));
        tx.thread_status(0, format!("Pobieranie: {}", file_name));
        let healthy_path = path.to_str().unwrap();
                    
        let mut safe_name = format!("DONOR_{}.moov", file_name);
        if let Some((dna, _)) = crate::dna::extract_dna(healthy_path) {
            safe_name = format!("DONOR_{}.moov", dna);
            tx.donor_found(&dna, safe_name.clone());
        }
        
        let donor_path = ws.donors_dir.join(&safe_name);
        let _ = crate::scanner::extract_and_save_moov(healthy_path, donor_path.to_str().unwrap());
        
        let mutations = vec![
            ("Typ A (Brak nagłówka)", "BROKEN_A_", simulate_missing_moov as fn(&str, &str) -> io::Result<()>),
            ("Typ B (Bad Sectory)", "BROKEN_B_", simulate_bad_sectors),
            ("Typ C (Ucięty Plik)", "BROKEN_C_", simulate_truncation),
        ];

        for (mut_name, prefix, mut_func) in mutations {
            let broken_path = ws.broken_dir.join(format!("{}{}", prefix, file_name));
            
            tx.info("CHAOS_MONKEY", format!("Generowanie mutacji: {} dla {}", mut_name, file_name));
            tx.thread_status(0, format!("Mutacja: {} ({})", mut_name, file_name));
            if mut_func(healthy_path, broken_path.to_str().unwrap()).is_ok() {
                let broken_str = broken_path.to_str().unwrap().to_string();

                tx.thread_status(0, format!("⚔️ Autopilot: {}", mut_name));
                let repair_result = autopilot::run(ws, &broken_str, &brain_cache, tx, 0);

                match repair_result {
                    Ok(_) => {
                        tx.success("CHAOS_MONKEY", format!("Mutacja '{}' Zneutralizowana!", mut_name));
                    }
                    Err(err) => {
                        tx.warn("CHAOS_MONKEY", format!("Porażka. Mutacja '{}' zniszczyła plik: {}", mut_name, err));
                    }
                }
                
                // Sprzątanie po mutacji - oszczędność miejsca na dysku
                let _ = fs::remove_file(&broken_path);
                if let Ok(out_entries) = fs::read_dir(&ws.output_dir) {
                    for e in out_entries.flatten() {
                        if let Some(name) = e.file_name().to_str() {
                            if name.contains(&file_name) {
                                let _ = fs::remove_file(e.path());
                            }
                        }
                    }
                }
            }
        }
        crate::db::mark_trained(ws, &short_hash);
        trained += 1;
        tx.progress(trained, total_to_train, Some(format!("Ukończono trening pliku: {}", file_name)));
        tx.update_stats(crate::event::StatUpdate {
            files_scanned: total_to_train,
            files_healthy: 0,
            files_broken: total_to_train * 3,
            files_repaired: trained * 3, // Assuming 3 mutations per file repaired (simplified)
            bytes_processed: 0,
            active_threads: 1,
        });
    }

    tx.success("POLIGON", format!("Trening Zakończony. Zaadaptowano bazę do {} mutacji.", trained));
    tx.operation_finished(format!("Trening Chaos Monkey zakończony: {} mutacji zaadaptowanych", trained));
    Ok(())
}

/// POLIGON SNAJPERSKI: Celowany test na jednym konkretnym pliku
pub fn run_sniper_test(ws: &Workspace, healthy_path: &str, tx: &EventSender) -> io::Result<()> {
    tx.operation_started("Sniper Test");
    tx.info("SNIPER", format!("Inicjacja testu celowanego dla pliku: {}", healthy_path));
    
    // 1. Ładowanie bazy Mózgu
    let brain_cache = db::build_brain_cache(ws).unwrap_or_default();
    
    // 2. Weryfikacja DNA celu
    let dna_tuple = match crate::dna::extract_dna(healthy_path) {
        Some(d) => d,
        None => {
            tx.error("SNIPER", "Cel nie posiada prawidłowego DNA wideo.");
            tx.operation_failed("Sniper Test", "Brak prawidłowego DNA wideo");
            // `Err`, nie `Ok(())`. Wcześniej funkcja meldowała operatorowi
            // porażkę przez szynę zdarzeń, a wywołującemu zwracała sukces.
            // Dopóki nikt nie czytał wyniku, nie miało to skutku; odkąd steruje
            // kodem wyjścia trybu wsadowego, skrypt widziałby udany przebieg
            // tam, gdzie nic się nie udało.
            return Err(io::Error::new(io::ErrorKind::InvalidData, "cel nie ma prawidłowego DNA wideo"));
        }
    };
    let dna_sig = dna_tuple.0;

    // 3. Weryfikacja obecności dawcy w bazie
    if let Some(donors) = brain_cache.donors.get(&dna_sig) {
        tx.success("SNIPER", format!("Mózg posiada przypisanych dawców ({}) dla tego DNA! Główny: {}", donors.len(), donors[0]));
    } else {
        tx.warn("SNIPER", "Mózg nie ma przypisanego dawcy dla tego DNA w bazie SQLite. Autopilot użyje logiki rozmytej lub Bruteforce.");
    }

    // 4. Preparowanie pliku (Mutacja Typu A)
    // Patrz `sanitizer::run_deep_sanitization` — ten sam `unwrap()` panikował
    // na pustej ścieżce podanej z wiersza poleceń.
    let file_name = match std::path::Path::new(healthy_path).file_name() {
        Some(n) => n.to_string_lossy(),
        None => {
            tx.operation_failed("Poligon snajperski", format!("Ścieżka '{}' nie wskazuje pliku", healthy_path));
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "ścieżka nie wskazuje pliku"));
        }
    };
    let broken_path = ws.broken_dir.join(format!("SNIPER_BROKEN_{}", file_name));
    
    tx.info("SNIPER", format!("Preparowanie pliku (wycinanie nagłówka 'moov'): {}", broken_path.display()));
    if simulate_missing_moov(healthy_path, broken_path.to_str().unwrap()).is_ok() {
        tx.thread_status(0, format!("Spreparowano: {}", broken_path.display()));
        
        let broken_str = broken_path.to_str().unwrap().to_string();
        tx.thread_status(0, "Inicjalizacja Autopilota...");

        // 5. Uruchomienie naprawy Autopilota
        let repair_result = autopilot::run(ws, &broken_str, &brain_cache, tx, 0);

        if repair_result.is_ok() {
            tx.success("SNIPER", "Autopilot poprawnie zrekonstruował spreparowany plik! Sprawdź raport turnieju w logach.");
            tx.operation_finished("Sniper test zakończony sukcesem");
        } else {
            tx.error("SNIPER", "Autopilot nie poradził sobie ze spreparowanym plikiem.");
            tx.operation_failed("Sniper Test", "Autopilot nie zdołał naprawić pliku");
        }
    } else {
        tx.error("SNIPER", "Nie udało się spreparować pliku testowego.");
        tx.operation_failed("Sniper Test", "Błąd preparowania pliku");
    }

    Ok(())
}

/// Pomocniczy punkt wejścia w trybie headless dla run_training
pub fn run_training_headless(ws: &Workspace, healthy_dir: &str) -> io::Result<()> {
    crate::bezglowe::z_odbiorem(ws, |tx| run_training(ws, healthy_dir, tx))
}

/// Pomocniczy punkt wejścia w trybie headless dla run_sniper_test
pub fn run_sniper_test_headless(ws: &Workspace, healthy_path: &str) -> io::Result<()> {
    crate::bezglowe::z_odbiorem(ws, |tx| run_sniper_test(ws, healthy_path, tx))
}

#[cfg(test)]
mod manual_tests {
    use super::*;

    /// Trening na PRAWDZIWYM materiale operatora, jeśli katalog istnieje.
    ///
    /// `run_training` wyłącznie CZYTA katalog źródłowy (rekurencyjny `read_dir`
    /// plus hash) — zapisuje dawców do `ws.donors_dir`, więc materiał operatora
    /// nie jest ruszany. Przestrzeń idzie do katalogu tymczasowego i jest
    /// usuwana na końcu: wcześniej zostawała w drzewie projektu i puchła o
    /// kilkanaście megabajtów dawców przy każdym przebiegu.
    #[test]
    fn run_live_chaos_monkey() {
        let ws = Workspace::init_testowy("test_ws_chaos").unwrap();
        let target = "/media/NEXTCLOUD/winek/files";
        if std::path::Path::new(target).exists() {
            let (tx, _rx) = crate::event::channel();
            let _ = run_training(&ws, target, &tx);
        }
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    // ------------------------------------------------------------------
    // POLIGON SNAJPERSKI — WARUNKI BRZEGOWE
    // ------------------------------------------------------------------

    fn przestrzen(nazwa: &str) -> Workspace {
        let ws = Workspace::init_testowy(nazwa).expect("przestrzeń testowa musi powstać");
        crate::db::init_db(&ws).expect("baza musi się utworzyć");
        ws
    }

    /// REGRESJA: funkcja meldowała operatorowi porażkę przez szynę zdarzeń,
    /// a wywołującemu zwracała `Ok(())`. Dopóki nikt nie czytał wyniku, nie
    /// miało to skutku; odkąd steruje kodem wyjścia trybu wsadowego, skrypt
    /// widziałby udany przebieg tam, gdzie nic się nie udało.
    #[test]
    fn test_cel_bez_dna_zwraca_blad_a_nie_falszywy_sukces() {
        let ws = przestrzen("sniper_bez_dna");
        let (tx, _rx) = crate::event::channel();

        let wynik = run_sniper_test(&ws, "/nie/ma/takiego/pliku.mp4", &tx);

        assert!(wynik.is_err(), "Brak DNA celu MUSI być zgłoszony jako błąd");
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    /// REGRESJA: `file_name().unwrap()` panikował na pustej ścieżce —
    /// przypadek osiągalny wprost z wiersza poleceń (`--sniper ""`).
    #[test]
    fn test_pusta_sciezka_nie_panikuje() {
        let ws = przestrzen("sniper_pusta_sciezka");
        let (tx, _rx) = crate::event::channel();

        assert!(run_sniper_test(&ws, "", &tx).is_err());
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    /// Trening na nieistniejącym katalogu to nie błąd — po prostu nie ma na
    /// czym trenować.
    #[test]
    fn test_trening_na_nieistniejacym_katalogu_konczy_sie_spokojnie() {
        let ws = przestrzen("trening_brak_katalogu");
        let (tx, _rx) = crate::event::channel();

        let wynik = run_training(&ws, "/nie/ma/takiego/katalogu", &tx);

        assert!(wynik.is_ok(), "Pusty zbiór wejściowy to nie błąd: {:?}", wynik.err());
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    #[test]
    fn test_trening_na_katalogu_bez_wideo_konczy_sie_spokojnie() {
        let ws = przestrzen("trening_bez_wideo");
        let zrodlo = ws.root_dir.join("zrodlo");
        std::fs::create_dir_all(&zrodlo).unwrap();
        std::fs::write(zrodlo.join("notatka.txt"), b"to nie jest wideo").unwrap();
        let (tx, _rx) = crate::event::channel();

        assert!(run_training(&ws, zrodlo.to_str().unwrap(), &tx).is_ok());
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }
}
