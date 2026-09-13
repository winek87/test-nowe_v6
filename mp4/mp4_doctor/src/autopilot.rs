// src/autopilot.rs

//! Moduł `autopilot` to główny silnik decyzyjny (Mózg) programu.
//!
//! # Zmiany w wersji Enterprise (AI AI-Driven):
//! * **Logika Rozmyta:** Wykorzystanie dystansu Levenshteina do dobierania algorytmów.
//! * **Kontekst Środowiskowy:** Analiza rozmiaru pliku (FAT32 > 4GB limits).
//! * **Turnieje Genetyczne (Testy A/B):** Uruchamianie wszystkich algorytmów i wybór 
//!   tego, który odzyskał najwięcej klatek.
//! * **Live Telemetry:** Przekazywanie kanału MPSC do natywnych silników.

use std::fs;
use std::path::Path;

use crate::workspace::Workspace;
use crate::{dna, validator, dlog};
use crate::{engine_clone, engine_recontainer, engine_native};
use crate::db::BrainCache;
use crate::event::EventSender;

pub fn find_donor(
    ws: &Workspace, 
    dna_sig: &str, 
    cache: &BrainCache, 
    event_sender: &EventSender,
    thread_id: usize,
) -> Option<String> {
    if let Some(donors) = cache.donors.get(dna_sig) {
        if let Some(first_donor) = donors.first() {
            if std::path::Path::new(first_donor).exists() {
                dlog!("🧠 [AUTOPILOT] Znalazłem dawcę w cache RAM: {}", first_donor);
                return Some(first_donor.clone());
            } else {
                dlog!("⚠️ [AUTOPILOT] Dawca z cache RAM ({}) nie istnieje fizycznie na dysku!", first_donor);
            }
        }
    }
    // Fallback do dowolnego pliku moov usunięty: teraz zmuszamy system do pobrania dokładnego dawcy z chmury.    
    // =========================================================================
    // NOWOŚĆ: POBIERANIE DAWCA Z CHMURY (ZASZYFROWANEGO)
    // =========================================================================
    let dummy_feat = crate::ai::FeatureVector { file_size_mb: 0.0, entropy: 7.9, h264_profile: 0.0, aac_freq: 0.0, video_audio_ratio: 0.0 };
    let human_name = crate::dna::get_human_readable_diagnosis(dna_sig, &dummy_feat);
    event_sender.info("AUTOPILOT", format!("Brak lokalnego dawcy dla: [{}]. Szukam w Roju AI...", human_name));
    event_sender.update_thread(thread_id, format!("Szukam dawcy w chmurze: {}", human_name));

    let temp_enc_path = ws.root_dir.join(format!("temp_download_{}.enc", dna_sig));
    let curl_status = std::process::Command::new("curl")
        .arg("-s")
        .arg("-o").arg(temp_enc_path.to_str().unwrap())
        .arg("-w").arg("%{http_code}")
        .arg(format!("http://127.0.0.1:3000/v1/swarm/donor/{}", dna_sig))
        .output();
        
    if let Ok(res) = curl_status {
        let http_code = String::from_utf8_lossy(&res.stdout);
        if http_code.trim() == "200" {
            let decrypted_path = ws.donors_dir.join(format!("DONOR_{}.moov", dna_sig));
            event_sender.info("AUTOPILOT", "[CHMURA] Pobrano zaszyfrowany plik. Odszyfrowuję w locie...");
            event_sender.update_thread(thread_id, "🔐 Odszyfrowywanie dawcy...");
            
            if crate::crypto::encrypt_decrypt_file(temp_enc_path.to_str().unwrap(), decrypted_path.to_str().unwrap()).is_ok() {
                let _ = std::fs::remove_file(&temp_enc_path);
                event_sender.success("AUTOPILOT", "[CHMURA] Tymczasowy dawca chmurowy gotowy do użycia!");
                event_sender.update_thread(thread_id, "Gotowy dawca chmurowy");
                
                let cleanup_path = decrypted_path.clone();
                let tx_clone = event_sender.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    let _ = std::fs::remove_file(cleanup_path);
                    tx_clone.debug("AUTOPILOT", "[PRYWATNOŚĆ] Usunięto tymczasowego dawcę chmurowego z dysku.");
                });
                
                return Some(decrypted_path.to_str().unwrap().to_string());
            }
        } else {
            event_sender.warn("AUTOPILOT", format!("[CHMURA] Serwer nie posiada tego dawcy (kod HTTP {}).", http_code.trim()));
            let _ = std::fs::remove_file(&temp_enc_path);
        }
    }
    
    None
}

/// Pomocniczy punkt wejścia dla find_donor z opcjonalnym EventSenderem
pub fn find_donor_optional(
    ws: &Workspace,
    dna_sig: &str,
    cache: &BrainCache,
    event_sender: Option<&EventSender>,
    thread_id: usize,
) -> Option<String> {
    if let Some(tx) = event_sender {
        find_donor(ws, dna_sig, cache, tx, thread_id)
    } else {
        let (tx, _rx) = crate::event::channel();
        find_donor(ws, dna_sig, cache, &tx, thread_id)
    }
}

/// Zbiera dawców ze WSZYSTKICH projektów — wspólna pula ratunkowa.
///
/// Katalog bierze się z [`crate::workspace::katalog_przestrzeni`], a nie z
/// zaszytego `"workspaces"`. Literał był ścieżką względną wobec katalogu
/// uruchomienia, więc po osadzeniu biblioteki w innej aplikacji (przestrzenie
/// lądują wtedy pod `<cel>/_mp4_doctor`) ta funkcja czytała katalog, którego
/// tam nie ma, i cicho zwracała pustą pulę — autopilot tracił dostęp do
/// wszystkich dawców z innych projektów, nie zgłaszając żadnego błędu.
fn get_all_global_donors() -> Vec<String> {
    let mut global_donors = Vec::new();
    let workspaces_dir = crate::workspace::katalog_przestrzeni();

    if let Ok(projects) = fs::read_dir(&workspaces_dir) {
        for proj in projects.flatten() {
            if proj.path().is_dir() {
                let donors_dir = proj.path().join("2_donors");
                if let Ok(entries) = fs::read_dir(donors_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            global_donors.push(path.to_str().unwrap().to_string());
                        }
                    }
                }
            }
        }
    }
    global_donors
}

pub fn run(
    ws: &Workspace, 
    broken_file: &str, 
    cache: &BrainCache, 
    event_sender: &EventSender,
    thread_id: usize,
) -> Result<(), String> {
    dlog!("\n==================================================");
    dlog!("🤖 [AUTOPILOT] Przejęcie kontroli nad plikiem: {}", broken_file);
    
    let (dna_sig, features) = match dna::extract_dna(broken_file) {
        Some((sig, feat)) => (sig, feat),
        None => {
            event_sender.error("AUTOPILOT", format!("Brak DNA w pliku: {}. Odrzucam plik.", broken_file));
            event_sender.update_thread(thread_id, "❌ Brak DNA. Odrzucam plik.");
            return Err("Brak DNA.".to_string());
        }
    };

    let human_report = crate::dna::get_human_readable_diagnosis(&dna_sig, &features);
    event_sender.info("AUTOPILOT", format!("Profil Sprzętowy: {}", human_report));
    event_sender.update_thread(thread_id, format!("🔍 Profil Sprzętowy: {}", human_report));

    let mut algorithms = cache.get_best_algorithms(&dna_sig, &features);
    if algorithms.is_empty() {
        algorithms = vec!["Clone".to_string(), "Native".to_string(), "Recontainer".to_string()];
    }

    let file_size = fs::metadata(broken_file).map(|m| m.len()).unwrap_or(0);
    if file_size > 4 * 1024 * 1024 * 1024 {
        if let Some(pos) = algorithms.iter().position(|x| x == "Native") {
            let native = algorithms.remove(pos);
            algorithms.insert(0, native);
        }
    }

    // Patrz `sanitizer::run_deep_sanitization` — ten sam `unwrap()` panikował
    // na pustej ścieżce podanej z wiersza poleceń.
    let file_name = match Path::new(broken_file).file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => {
            let powod = format!("Ścieżka '{}' nie wskazuje pliku", broken_file);
            event_sender.error("AUTOPILOT", powod.clone());
            return Err(powod);
        }
    };
    let mut successful_repairs = Vec::new();

    for algo in &algorithms {
        event_sender.update_thread(thread_id, format!("▶️ Kaskada: Testuję algorytm '{}'...", algo));
        event_sender.debug("AUTOPILOT", format!("Kaskada: Testuję algorytm '{}'...", algo));
        
        let out_file = ws.output_dir.join(format!("{}_{}.mp4", algo, file_name));
        let out_str = out_file.to_str().unwrap();

        let execution_result = match algo.as_str() {
            "Clone" => {
                if let Some(donor) = find_donor(ws, &dna_sig, cache, event_sender, thread_id) {
                    // Ten sam wzorzec co przy `broken_file` wyżej: ścieżka
                    // dawcy nie jest tu literałem programisty, tylko wynikiem
                    // `find_donor`/cache'a - w skrajnym przypadku (np. wpis
                    // `donors_cache` zasilony przez zsynchronizowaną,
                    // niezaufaną bazę roju) `unwrap()` na `file_name()`
                    // panikowałby na źle sformowanej ścieżce.
                    let donor_name = Path::new(&donor).file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| donor.clone());
                    event_sender.update_thread(thread_id, format!("🧬 Clone: Wstrzykuję dawcę '{}'...", donor_name));
                    engine_clone::repair(broken_file, &donor, out_str)
                } else {
                    continue; 
                }
            }
            "Recontainer" => engine_recontainer::repair(broken_file, out_str),
            "Native" => engine_native::repair(broken_file, out_str, None),
            _ => continue,
        };

        if execution_result.is_ok() && validator::is_healthy_video(out_str) {
            let out_size = fs::metadata(out_str).map(|m| m.len()).unwrap_or(0);
            event_sender.update_thread(thread_id, format!("✅ Kaskada: Algorytm '{}' ZADZIAŁAŁ!", algo));
            event_sender.info("AUTOPILOT", format!("Kaskada: Algorytm '{}' ZADZIAŁAŁ dla {}!", algo, file_name));
            successful_repairs.push((algo.clone(), out_str.to_string(), out_size));
        } else {
            event_sender.update_thread(thread_id, format!("❌ Kaskada: Algorytm '{}' odrzucony.", algo));
            let _ = fs::remove_file(out_str); 
            event_sender.repair_failure(&file_name, &dna_sig, algo, features.clone());
        }
    }

    if !successful_repairs.is_empty() {
        successful_repairs.sort_by(|a, b| b.2.cmp(&a.2));
        let (best_algo, _best_file, _best_size) = &successful_repairs[0];
        
        for (algo, file_path, _) in &successful_repairs {
            if algo == best_algo {
                event_sender.repair_success(&file_name, &dna_sig, algo, features.clone());
                event_sender.success("AUTOPILOT", format!("Sukces naprawy pliku {} za pomocą algorytmu '{}'!", file_name, algo));
            } else {
                let _ = fs::remove_file(file_path);
            }
        }
        return Ok(());
    }

    event_sender.update_thread(thread_id, "🚨 Inicjacja protokołu BRUTEFORCE!");
    event_sender.warn("AUTOPILOT", format!("Inicjacja protokołu BRUTEFORCE dla: {}", file_name));
    
    // Pobierz wszystkie znane dawcy z bazy danych wraz z ich precyzyjnymi sygnaturami DNA
    let mut global_donors: Vec<(String, String)> = Vec::new();
    if let Ok(conn) = crate::db::init_db(ws) {
        if let Ok(mut stmt) = conn.prepare("SELECT donor_path, dna_signature FROM donors_cache") {
            let _ = stmt.query_map([], |row| {
                let path: String = row.get(0)?;
                let sig: String = row.get(1)?;
                global_donors.push((path, sig));
                Ok(())
            });
        }
    }
    
    // Jeśli baza pusta (rzadki przypadek), weź z dysku z pustym DNA
    if global_donors.is_empty() {
        for path in get_all_global_donors() {
            global_donors.push((path, "".to_string()));
        }
    }
    
    let target_parts: Vec<&str> = dna_sig.split('_').collect();
    
    // HEURYSTYKA: Prawdziwe sortowanie po precyzyjnym DNA z bazy, a nie po nazwie pliku!
    global_donors.sort_by_key(|(_, donor_dna)| {
        let mut penalty = 10000;
        let donor_parts: Vec<&str> = donor_dna.split('_').collect();
        
        for part in &target_parts {
            if part.len() > 2 && donor_parts.contains(part) {
                // Ścisłe dopasowanie członów DNA (H264, Profil, AAC itp.)
                penalty -= 1000 * part.len() as i32; 
            }
        }
        penalty
    });
    
    // Wyciągamy same ścieżki po posortowaniu
    let global_donors: Vec<String> = global_donors.into_iter().map(|(p, _)| p).collect();

    if !global_donors.is_empty() {
        let total_donors = global_donors.len();
        for (i, foreign_donor) in global_donors.iter().enumerate() {
            // Ścieżki tutaj pochodzą z `donors_cache` (ewentualnie
            // zasilanej synchronizacją z serwerem roju) lub z przeszukania
            // dysku - ten sam powód co przy `find_donor` wyżej, żeby nie
            // ufać bezwarunkowo `unwrap()`.
            let donor_name = Path::new(foreign_donor).file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| foreign_donor.clone());
            let progress_msg = format!("🧪 Bruteforce [{}/{}]: Przymierzam nagłówek '{}'...", i + 1, total_donors, donor_name);
            event_sender.update_thread(thread_id, &progress_msg);
            event_sender.debug("BRUTEFORCE", progress_msg);
            
            let out_file = ws.output_dir.join(format!("Frankenstein_{}.mp4", file_name));
            let out_str = out_file.to_str().unwrap();

            if engine_clone::repair(broken_file, foreign_donor, out_str).is_ok() {
                if validator::is_healthy_video(out_str) {
                    event_sender.update_thread(thread_id, format!("🧟 SUKCES! Plik zmartwychwstał używając moov nr {}!", i + 1));
                    // CELOWO bez `event_sender.repair_success(..., "Bruteforce")`:
                    // to jedyne miejsce w tej kaskadzie, gdzie nazwa algorytmu
                    // NIE JEST jedną z gałęzi rozpoznawanych w `match algo.as_str()`
                    // wyżej (`Clone`/`Native`/`Recontainer`). Zapisanie jej jako
                    // nauczonego algorytmu zatruwało `get_best_algorithms` dla
                    // TEJ sygnatury DNA na zawsze: kolejne przebiegi dostawały
                    // `algorithms == ["Bruteforce"]`, kaskada nie miała jak tego
                    // wykonać (`_ => continue`), i tak wpadały w pełny bruteforce
                    // ponownie — nauka nigdy nie przyspieszała kolejnych prób,
                    // wbrew obietnicy silnika samouczącego się. Bez tego zapisu
                    // `get_best_algorithms` wraca do domyślnej trójki
                    // (Clone/Native/Recontainer), która ma choć szansę zadziałać
                    // szybciej przy innym zestawie dawców.
                    event_sender.success("AUTOPILOT", format!("Bruteforce: Sukces z dawcą moov #{} dla {}!", i + 1, file_name));
                    return Ok(());
                }
            }
            
            event_sender.update_thread(thread_id, format!("❌ Bruteforce: moov nr {} FAIL.", i + 1));
            event_sender.debug("BRUTEFORCE", format!("Odrzucono kandydata nr {} (Plik wciąż uszkodzony).", i + 1));
            let _ = fs::remove_file(out_str); 
        }
    }

    event_sender.update_thread(thread_id, "☠️ Błąd krytyczny. Wszystkie metody zawiodły.");
    event_sender.error("AUTOPILOT", format!("Awaria krytyczna dla pliku {}: wszystkie metody zawiodły.", file_name));
    Err("Awaria krytyczna. Plik martwy.".to_string())
}

/// Pomocniczy punkt wejścia w trybie headless dla autopilot::run
pub fn run_headless(
    ws: &Workspace,
    broken_file: &str,
    cache: &BrainCache,
) -> Result<(), String> {
    crate::bezglowe::z_odbiorem(ws, |tx| run(ws, broken_file, cache, tx, 0))
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::BrainCache;

    fn przestrzen(nazwa: &str) -> Workspace {
        let ws = Workspace::init_testowy(nazwa).expect("przestrzeń testowa musi powstać");
        crate::db::init_db(&ws).expect("baza musi się utworzyć");
        ws
    }

    /// REGRESJA: `file_name().unwrap()` panikował na pustej ścieżce —
    /// przypadek osiągalny wprost z wiersza poleceń (`--autopilot ""`).
    #[test]
    fn test_pusta_sciezka_daje_blad_zamiast_paniki() {
        let ws = przestrzen("autopilot_pusta_sciezka");
        let (tx, _rx) = crate::event::channel();
        let cache = BrainCache::default();

        assert!(run(&ws, "", &cache, &tx, 0).is_err());
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    #[test]
    fn test_nieistniejacy_plik_daje_blad() {
        let ws = przestrzen("autopilot_brak_pliku");
        let (tx, _rx) = crate::event::channel();
        let cache = BrainCache::default();

        let wynik = run(&ws, "/nie/ma/takiego/pliku.mp4", &cache, &tx, 0);

        assert!(wynik.is_err(), "Plik bez DNA musi zostać odrzucony");
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    /// Wspólna pula dawców czyta katalog przestrzeni roboczych. Gdy nie ma tam
    /// żadnego projektu z dawcami, wynik musi być pustą listą, a nie paniką.
    #[test]
    fn test_pula_dawcow_bez_projektow_jest_pusta_a_nie_panikuje() {
        let ws = przestrzen("autopilot_pula_dawcow");
        let _ = get_all_global_donors();
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    /// `find_donor_optional` bez nadajnika musi zachować się tak samo jak
    /// z nadajnikiem — to jedyny powód jego istnienia.
    #[test]
    fn test_wyszukiwanie_dawcy_bez_nadajnika_nie_panikuje() {
        let ws = przestrzen("autopilot_bez_nadajnika");
        let cache = BrainCache::default();

        let _ = find_donor_optional(&ws, "NIEISTNIEJACE_DNA", &cache, None, 0);
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }
}
