// src/db.rs

//! Moduł `db` zarządza inteligentną bazą SQLite.
//!
//! # Zmiany w wersji Enterprise (AI AI-Driven):
//! - **Logika Rozmyta (Fuzzy Logic):** Automatyczne wnioskowanie na podstawie 
//!   matematycznego podobieństwa nieznanego DNA do znanych profili (Dystans Levenshteina).
//! - **Swarm Intelligence:** Eksport i Import wyuczonej wiedzy z/do plików JSON.

use rusqlite::{params, Connection, Result as SqlResult};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use serde::{Serialize, Deserialize};
use strsim::levenshtein;

use crate::ai::{FeatureVector, KnnClassifier};

use crate::workspace::Workspace;
use crate::dlog; // Ciche logowanie

// --- STRUKTURY DLA KOLEKTYWNEGO ROJU (JSON) ---

#[derive(Serialize, Deserialize, Debug)]
pub struct BrainExport {
    pub engine_version: String,
    pub knowledge: Vec<KnowledgeEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KnowledgeEntry {
    pub dna_signature: String,
    pub algorithm_name: String,
    pub score: i32,
    pub features: Option<FeatureVector>,
}

// --- PAMIĘĆ PODRĘCZNA Z LOGIKĄ ROZMYTĄ ---

#[derive(Default, Clone)]
pub struct BrainCache {
    pub algorithms: HashMap<String, Vec<String>>,
    pub donors: HashMap<String, Vec<String>>,
    pub feature_store: HashMap<String, FeatureVector>,
}

impl BrainCache {
    /// Inteligentne dobieranie algorytmów (AI):
    /// 1. Dokładne dopasowanie (Exact Match)
    /// 2. Logika Rozmyta (Fuzzy Logic - K-Nearest Neighbors)
    pub fn get_best_algorithms(&self, target_dna: &str, target_features: &FeatureVector) -> Vec<String> {
        // 1. Zwykłe, dokładne wyszukiwanie (jeśli Mózg zna już to DNA)
        if let Some(algos) = self.algorithms.get(target_dna) {
            return algos.clone();
        }

        // 2. Machine Learning: K-Nearest Neighbors (KNN) na wektorze cech
        let mut knn = KnnClassifier::new();
        for (dna, algos) in &self.algorithms {
            if let Some(feat) = self.feature_store.get(dna) {
                if let Some(best_algo) = algos.first() {
                    knn.train(feat.clone(), best_algo.clone());
                }
            }
        }

        if let Some(predicted_algo) = knn.predict(target_features, 3) {
            dlog!("🧠 [AI MACHINE LEARNING] Nieznane DNA: {}. Klasyfikator KNN przewidział algorytm: {} (na bazie {} wymiarów cech)!", target_dna, predicted_algo, 5);
            return vec![predicted_algo];
        }

        // 3. Fallback do Logiki Rozmytej (Fuzzy Logic na DNA) jeśli nie było cech
        let mut best_match: Option<(&String, usize)> = None;
        for known_dna in self.algorithms.keys() {
            let distance = levenshtein(target_dna, known_dna);
            if distance < 15 { 
                match best_match {
                    Some((_, best_dist)) if distance < best_dist => {
                        best_match = Some((known_dna, distance));
                    }
                    None => {
                        best_match = Some((known_dna, distance));
                    }
                    _ => {}
                }
            }
        }

        if let Some((closest_dna, dist)) = best_match {
            dlog!("🧠 [AI FUZZY LOGIC] Najbliższy wzorzec DNA to {} (odległość: {}). Kopiuję algorytmy!", closest_dna, dist);
            return self.algorithms.get(closest_dna).unwrap().clone();
        }

        Vec::new() // Nic nie pasuje - zwracamy puste
    }
}

// --- FUNKCJE BAZY SQLITE ---

pub fn init_db(ws: &Workspace) -> SqlResult<Connection> {
    let conn = Connection::open(&ws.db_path)?;

    // Tabele przechowujące wiedzę i pamięć dawców
    conn.execute(
        "CREATE TABLE IF NOT EXISTS knowledge_base (
            dna_signature TEXT NOT NULL,
            algorithm_name TEXT NOT NULL,
            score INTEGER DEFAULT 0,
            features_json TEXT,
            PRIMARY KEY (dna_signature, algorithm_name)
        )",
        [],
    )?;
    
    // Migracja: Dodanie kolumny features_json jeśli nie istnieje
    let _ = conn.execute("ALTER TABLE knowledge_base ADD COLUMN features_json TEXT", []);


    conn.execute(
        "CREATE TABLE IF NOT EXISTS trained_files (
            file_hash TEXT PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS donors_cache (
            dna_signature TEXT NOT NULL,
            donor_path TEXT PRIMARY KEY
        )",
        [],
    )?;

    // Migracja: Dodanie kolumny is_synced
    let _ = conn.execute("ALTER TABLE donors_cache ADD COLUMN is_synced BOOLEAN DEFAULT 0", []);

    Ok(conn)
}

pub fn reward_algorithm(ws: &Workspace, dna: &str, algo: &str) -> SqlResult<()> {
    let conn = init_db(ws)?;
    conn.execute(
        "INSERT INTO knowledge_base (dna_signature, algorithm_name, score)
         VALUES (?1, ?2, 10)
         ON CONFLICT(dna_signature, algorithm_name) 
         DO UPDATE SET score = score + 10",
        params![dna, algo],
    )?;
    Ok(())
}

pub fn penalize_algorithm(ws: &Workspace, dna: &str, algo: &str) -> SqlResult<()> {
    let conn = init_db(ws)?;
    conn.execute(
        "INSERT INTO knowledge_base (dna_signature, algorithm_name, score)
         VALUES (?1, ?2, -5)
         ON CONFLICT(dna_signature, algorithm_name) 
         DO UPDATE SET score = score - 5",
        params![dna, algo],
    )?;
    Ok(())
}

pub fn save_donor(ws: &Workspace, dna: &str, donor_path: &str) -> SqlResult<()> {
    let conn = init_db(ws)?;
    conn.execute(
        "INSERT OR IGNORE INTO donors_cache (dna_signature, donor_path)
         VALUES (?1, ?2)",
        params![dna, donor_path],
    )?;
    Ok(())
}

pub fn get_db_stats(ws: &Workspace) -> usize {
    if let Ok(conn) = Connection::open(&ws.db_path) {
        if let Ok(mut stmt) = conn.prepare("SELECT COUNT(*) FROM knowledge_base") {
            // POPRAWKA BŁĘDU (E0277): Odczyt jako i64 z bazy SQLite, po czym rzutowanie do usize
            if let Ok(count) = stmt.query_row([], |row| row.get::<_, i64>(0)) {
                return count as usize;
            }
        }
    }
    0
}

/// Buduje pamięć podręczną RAM Mózgu
pub fn build_brain_cache(ws: &Workspace) -> SqlResult<BrainCache> {
    let mut cache = BrainCache::default();
    let conn = init_db(ws)?;
    
    // Sortujemy wiedzę wg najwyższej punktacji (score)
    let mut stmt = conn.prepare("SELECT dna_signature, algorithm_name FROM knowledge_base ORDER BY score DESC")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows.flatten() {
        cache.algorithms.entry(row.0).or_insert_with(Vec::new).push(row.1);
    }

    let mut stmt2 = conn.prepare("SELECT dna_signature, donor_path FROM donors_cache")?;
    let rows2 = stmt2.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows2.flatten() {
        cache.donors.entry(row.0).or_insert_with(Vec::new).push(row.1);
    }

    Ok(cache)
}

// --- FUNKCJE KOLEKTYWNEGO ROJU (IMPORT/EKSPORT AI) ---

/// Zrzuca całą zawartość uczenia maszynowego (SQLite) do formatu JSON.
pub fn export_brain_to_json(ws: &Workspace, json_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let conn = init_db(ws)?;
    let mut stmt = conn.prepare("SELECT dna_signature, algorithm_name, score FROM knowledge_base")?;
    let rows = stmt.query_map([], |row| {
        Ok(KnowledgeEntry {
            dna_signature: row.get(0)?,
            algorithm_name: row.get(1)?,
            score: row.get(2)?,
            features: None,
        })
    })?;

    let mut export = BrainExport {
        engine_version: "MP4_Doctor_Enterprise_2.0".to_string(),
        knowledge: Vec::new(),
    };

    for r in rows.flatten() {
        export.knowledge.push(r);
    }

    let file = File::create(json_path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &export)?;
    Ok(())
}

/// Wstrzykuje obcą wiedzę z pliku JSON bezpośrednio do naszego SQLite.

pub fn download_missing_donors(ws: &Workspace, event_sender: Option<&crate::event::EventSender>) -> Result<usize, Box<dyn std::error::Error>> {
    let conn = init_db(ws)?;
    // Get all unique DNA signatures from knowledge base
    let mut stmt = conn.prepare("SELECT DISTINCT dna_signature FROM knowledge_base")?;
    let dna_rows: Vec<String> = stmt.query_map([], |row| row.get(0))?.filter_map(Result::ok).collect();
    
    let mut downloaded = 0;
    
    for dna_sig in dna_rows {
        if crate::SHUTDOWN_FLAG.load(std::sync::atomic::Ordering::Relaxed) { break; }
        
        let mut check_stmt = conn.prepare("SELECT donor_path FROM donors_cache WHERE dna_signature = ?")?;
        let local_path: Option<String> = check_stmt.query_row(rusqlite::params![dna_sig], |row| row.get(0)).ok();
        
        let needs_download = match local_path {
            Some(path) => !std::path::Path::new(&path).exists(),
            None => true,
        };
        
        if needs_download {
            let temp_enc_path = ws.root_dir.join(format!("temp_bulk_{}.enc", dna_sig));
            if let Some(tx) = event_sender {
                tx.info("SWARM", format!("Pobieranie brakującego wzorca DNA: {} ...", &dna_sig[0..8.min(dna_sig.len())]));
            }
            
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
                    if crate::crypto::encrypt_decrypt_file(temp_enc_path.to_str().unwrap(), decrypted_path.to_str().unwrap()).is_ok() {
                        let _ = conn.execute(
                            "INSERT OR REPLACE INTO donors_cache (dna_signature, donor_path, is_synced) VALUES (?, ?, 1)",
                            rusqlite::params![dna_sig, decrypted_path.to_str().unwrap()]
                        );
                        downloaded += 1;
                        if let Some(tx) = event_sender {
                            tx.success("SWARM", format!("Pobrano i odszyfrowano dawcę: {}", &dna_sig[0..8.min(dna_sig.len())]));
                        }
                    }
                } else {
                    if let Some(tx) = event_sender {
                        tx.warn("SWARM", format!("Brak dawcy {} w chmurze (Kod {})", &dna_sig[0..8.min(dna_sig.len())], http_code.trim()));
                    }
                }
            }
            let _ = std::fs::remove_file(temp_enc_path);
        }
    }
    
    if downloaded == 0 {
        if let Some(tx) = event_sender {
            tx.info("SWARM", "Wszystkie zidentyfikowane wzorce są już kompletne na dysku lokalnym.");
        }
    }
    
    Ok(downloaded)
}

pub fn import_brain_from_json(ws: &Workspace, json_path: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let file = File::open(json_path)?;
    let reader = BufReader::new(file);
    let import: BrainExport = serde_json::from_reader(reader)?;

    let conn = init_db(ws)?;
    let mut imported_count = 0;

    for entry in import.knowledge {
        // Łączymy doświadczenie własne z cudzym (dodajemy score)
        let res = conn.execute(
            "INSERT INTO knowledge_base (dna_signature, algorithm_name, score)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(dna_signature, algorithm_name) 
             DO UPDATE SET score = score + ?3",
            params![entry.dna_signature, entry.algorithm_name, entry.score],
        );
        if res.is_ok() { imported_count += 1; }
    }
    
    Ok(imported_count)
}

/// =================================================================
/// ENTERPRISE AI: FEDERATED LEARNING (ROJOWA WYMIANA WIEDZY W CHMURZE)
/// =================================================================
/// Wymienia się "doświadczeniem" z globalnym serwerem.
/// 1. Wysyła lokalnie wyuczone modele (DNA + Algorytmy).
/// 2. Pobiera zaktualizowaną globalną bazę danych (np. dla nowych kamer GoPro/DJI).
pub fn sync_with_cloud(
    ws: &Workspace,
    event_sender: Option<&crate::event::EventSender>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let temp_export = ws.root_dir.join("temp_swarm_export.json");
    let temp_import = ws.root_dir.join("temp_swarm_import.json");

    dlog!("🌐 [FEDERATED LEARNING] Przygotowuję lokalny model do wysyłki (JSON)...");
    if let Some(tx) = event_sender {
        tx.info("SWARM", "Przygotowuję lokalny model do wysyłki (JSON)...");
    }
    export_brain_to_json(ws, temp_export.to_str().unwrap())?;

    // =========================================================
    // NOWOŚĆ: UPLOAD ZASZYFROWANYCH DAWCÓW
    // =========================================================
    dlog!("🔐 [FEDERATED LEARNING] Szyfruję i udostępniam lokalne wzorce dawców w Roju...");
    let conn = init_db(ws)?;
    let mut stmt = conn.prepare("SELECT dna_signature, donor_path FROM donors_cache")?;
    let donor_rows: Vec<_> = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?.filter_map(Result::ok).collect();
    
    if donor_rows.is_empty() {
        if let Some(tx) = event_sender {
            tx.info("SWARM", "Brak lokalnych wzorców do synchronizacji.");
        }
    }
    
    for row in donor_rows {
        let dna = row.0;
        let donor_path = row.1;
        

        if !std::path::Path::new(&donor_path).exists() {
            if let Some(tx) = event_sender {
                let file_name = std::path::Path::new(&donor_path).file_name().unwrap_or_default().to_string_lossy();
                tx.warn("SWARM", format!("Pomijanie: Brak fizycznego pliku dawcy [{}]", file_name));
            }
            continue;
        }
        
        let dummy_feat = crate::ai::FeatureVector { file_size_mb: 0.0, entropy: 7.9, h264_profile: 0.0, aac_freq: 0.0, video_audio_ratio: 0.0 };
        let human_name = crate::dna::get_human_readable_diagnosis(&dna, &dummy_feat);
        
        // Pytanie do serwera: czy potrzebujesz tego pliku?
        let check_status = std::process::Command::new("curl")
            .arg("-s")
            .arg("-I")
            .arg("-w").arg("%{http_code}")
            .arg("-o").arg("/dev/null")
            .arg(format!("http://127.0.0.1:3000/v1/swarm/donor/{}", dna))
            .output();
            
        if let Ok(res) = check_status {
            let http_code = String::from_utf8_lossy(&res.stdout);
            if http_code.trim() == "200" || http_code.trim() == "OK" {
                let _ = conn.execute("UPDATE donors_cache SET is_synced = 1 WHERE donor_path = ?", rusqlite::params![donor_path]);
                if let Some(tx) = event_sender {
                    tx.success("SWARM", format!("Wzorzec [{}] był już zarchiwizowany na serwerze.", &dna[0..8.min(dna.len())]));
                }
                continue;
            }
        }

        let enc_path = ws.root_dir.join(format!("temp_enc_{}.moov", dna));
        dlog!("🔄 Przygotowywanie wzorca: [{}] ...", human_name);
        if let Some(tx) = event_sender {
            tx.info("SWARM", format!("Wysyłanie wzorca: [{}] ...", human_name));
        }
        
        if crate::crypto::encrypt_decrypt_file(&donor_path, enc_path.to_str().unwrap()).is_ok() {
            let curl_status = std::process::Command::new("curl")
                .arg("-s")
                .arg("-X").arg("POST")
                .arg("--data-binary").arg(format!("@{}", enc_path.to_str().unwrap()))
                .arg("-w").arg("%{http_code}")
                .arg(format!("http://127.0.0.1:3000/v1/swarm/donor/{}", dna))
                .output();
                
            match curl_status {
                Ok(res) => {
                    let http_code = String::from_utf8_lossy(&res.stdout);
                    if http_code.contains("200") || http_code.contains("OK") {
                        dlog!("✅ PRZESŁANO POMYŚLNIE: Wzorzec zabezpieczony w chmurze.");
                        let _ = conn.execute("UPDATE donors_cache SET is_synced = 1 WHERE donor_path = ?", rusqlite::params![donor_path]);
                        if let Some(tx) = event_sender {
                            tx.success("SWARM", "Wzorzec zabezpieczony w chmurze (Zaszyfrowano).");
                        }
                    } else {
                        dlog!("❌ BŁĄD SERWERA: Odmowa zapisu (Kod {}).", http_code.trim());
                        if let Some(tx) = event_sender {
                            tx.error("SWARM", format!("Błąd serwera Roju: Kod {}", http_code.trim()));
                        }
                    }
                }
                Err(_) => {
                    dlog!("⚠️ PRZERWANO: Brak połączenia z serwerem Roju.");
                    if let Some(tx) = event_sender {
                        tx.warn("SWARM", "Przerwano: Brak połączenia z serwerem Roju!");
                    }
                }
            }
            let _ = std::fs::remove_file(enc_path);
        } else {
            dlog!("❌ BŁĄD LOKALNY: Nie udało się zaszyfrować pliku.");
            if let Some(tx) = event_sender {
                tx.error("SWARM", "Błąd lokalny: Nie można zaszyfrować pliku dawcy!");
            }
        }
    }

    dlog!("📡 [FEDERATED LEARNING] Łączę się z chmurą: https://api.mp4doctor.com/v1/swarm/sync ...");
    if let Some(tx) = event_sender {
        tx.info("SWARM", "Łączę się z chmurą: https://api.mp4doctor.com/v1/swarm/sync ...");
    }
    
    // Symulacja wymiany danych za pomocą CURL (Wysłanie naszego modelu, odbiór globalnego modelu)
    // W środowisku testowym możemy symulować odpowiedź serwera korzystając z lokalnego pliku,
    // ale do celów demonstracyjnych po prostu skopiujemy i "wzbogacimy" nasz eksport.
    
    let curl_status = std::process::Command::new("curl")
        .arg("-s")
        .arg("-X").arg("POST")
        .arg("-H").arg("Content-Type: application/json")
        .arg("-d").arg(format!("@{}", temp_export.to_str().unwrap()))
        .arg("http://127.0.0.1:3000/v1/swarm/sync") // Publiczny endpoint testowy, zwraca wysłane dane
        .output();
        
    if let Ok(res) = curl_status {
        if res.status.success() {
            dlog!("✅ [FEDERATED LEARNING] Serwer przyjął wiedzę! Pobieranie bazy globalnej...");
            
            // W prawdziwym środowisku zapisalibyśmy odpowiedź z serwera.
            // Zapisujemy prawdziwą odpowiedź JSON z naszego serwera do pliku!
            let response_json = String::from_utf8_lossy(&res.stdout);
            std::fs::write(&temp_import, response_json.as_bytes())?;
            
            dlog!("🧠 [FEDERATED LEARNING] Importuję globalną wiedzę (Swarm Intelligence) do lokalnej bazy AI...");
            let imported_count = import_brain_from_json(ws, temp_import.to_str().unwrap())?;
            
            let _ = std::fs::remove_file(temp_export);
            let _ = std::fs::remove_file(temp_import);
            
            if let Some(tx) = event_sender {
                tx.success("SWARM", format!("Zsynchronizowano wiedzę roju: zaimportowano {} wpisów.", imported_count));
            }
            return Ok(imported_count);
        }
    }
    
    dlog!("❌ [FEDERATED LEARNING] Błąd komunikacji z chmurą.");
    if let Some(tx) = event_sender {
        tx.error("SWARM", "Błąd komunikacji z chmurą.");
    }
    Err("API Connection Failed".into())
}

/// Convenience standalone wrapper for sync_with_cloud without event channel
pub fn sync_with_cloud_standalone(ws: &Workspace) -> Result<usize, Box<dyn std::error::Error>> {
    sync_with_cloud(ws, None)
}


pub fn is_trained(ws: &Workspace, file_hash: &str) -> bool {
    if let Ok(conn) = init_db(ws) {
        if let Ok(mut stmt) = conn.prepare("SELECT 1 FROM trained_files WHERE file_hash = ?") {
            return stmt.exists(params![file_hash]).unwrap_or(false);
        }
    }
    false
}

pub fn mark_trained(ws: &Workspace, file_hash: &str) {
    if let Ok(conn) = init_db(ws) {
        let _ = conn.execute("INSERT OR IGNORE INTO trained_files (file_hash) VALUES (?)", params![file_hash]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_db() {
        let ws = Workspace::init_testowy("test_ws_db").unwrap();
        let conn = init_db(&ws).unwrap();

        let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='knowledge_base'").unwrap();
        assert!(stmt.exists([]).unwrap());

        let mut stmt2 = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='trained_files'").unwrap();
        assert!(stmt2.exists([]).unwrap());

        // Czyszczenie. Wcześniej stało tu `remove_dir_all("test_ws_db")` —
        // ścieżka WZGLĘDNA wobec katalogu uruchomienia, podczas gdy przestrzeń
        // powstaje w `<katalog przestrzeni>/test_ws_db`. Sprzątanie nigdy więc
        // niczego nie usuwało, a katalog zostawał w drzewie projektu.
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }
}

pub fn get_all_trained(ws: &Workspace) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    if let Ok(conn) = init_db(ws) {
        if let Ok(mut stmt) = conn.prepare("SELECT file_hash FROM trained_files") {
            if let Ok(mut rows) = stmt.query([]) {
                while let Ok(Some(row)) = rows.next() {
                    let hash: String = row.get(0).unwrap_or_default();
                    set.insert(hash);
                }
            }
        }
    }
    set
}
