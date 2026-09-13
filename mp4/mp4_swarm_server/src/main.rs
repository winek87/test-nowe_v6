use axum::{
    // `.head(check_donor)` niżej to metoda łańcucha `MethodRouter`, a nie wolna
    // funkcja `routing::head` — jej import był zbędny.
    routing::{get, post},
    Router,
    Json,
    extract::Path,
    body::Bytes,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use rusqlite::{params, Connection, Result as SqlResult};

// =====================================================================
// STRUKTURY DANYCH (Zgodne z klientem MP4 Doctor)
// =====================================================================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BrainExport {
    pub engine_version: String,
    pub knowledge: Vec<KnowledgeEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KnowledgeEntry {
    pub dna_signature: String,
    pub algorithm_name: String,
    pub score: i32,
    pub features: Option<serde_json::Value>,
}

// Stan współdzielony między wątkami Axum

fn get_human_readable_diagnosis(sig: &str) -> String {
    let mut parts = Vec::new();
    
    if sig.contains("H264_") {
        if let Some(start) = sig.find("H264_") {
            let hex_str = &sig[start+5..start+11];
            if hex_str.len() == 6 {
                let profile = &hex_str[0..2];
                let level_hex = &hex_str[4..6];
                
                let prof_name = match profile {
                    "42" => "Baseline Profile",
                    "4D" => "Main Profile",
                    "64" => "High Profile",
                    "F4" => "High 10 Profile",
                    _ => "Nieznany Profil",
                };
                
                let level = u8::from_str_radix(level_hex, 16).unwrap_or(0);
                let level_str = format!("{}.{}", level / 10, level % 10);
                
                parts.push(format!("Wideo: {} @ Level {}", prof_name, level_str));
            }
        }
    }
    
    if sig.contains("AAC_") {
        if let Some(start) = sig.find("AAC_") {
            let hex_str = &sig[start+4..start+8];
            if hex_str.len() == 4 {
                let freq_idx = u8::from_str_radix(&hex_str[2..4], 16).unwrap_or(255);
                let freq = match freq_idx {
                    3 => "48 kHz",
                    4 => "44.1 kHz",
                    5 => "32 kHz",
                    6 => "24 kHz",
                    8 => "16 kHz",
                    11 => "8 kHz",
                    _ => "Niestandardowe",
                };
                parts.push(format!("Audio: AAC ({})", freq));
            }
        }
    } else if !sig.contains("RAW") {
        parts.push("Audio: Brak (Mute)".to_string());
    }

    if parts.is_empty() {
        return "Niestandardowy zrzut RAW".to_string();
    }
    
    parts.join(" | ")
}

struct AppState {
    db_conn: Mutex<Connection>,
}

// =====================================================================
// INICJALIZACJA BAZY DANYCH
// =====================================================================
fn init_db() -> SqlResult<Connection> {
    let conn = Connection::open("swarm_global.db")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS global_knowledge (
            dna_signature TEXT NOT NULL,
            algorithm_name TEXT NOT NULL,
            score INTEGER NOT NULL DEFAULT 0,
            features_json TEXT,
            PRIMARY KEY (dna_signature, algorithm_name)
        )",
        [],
    )?;
    
    // Wstrzyknięcie domyślnej wiedzy (Seed) jeśli pusto
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM global_knowledge", [], |row| row.get(0))?;
    if count == 0 {
        println!("🌱 Inicjalizacja pustej bazy startowej chmury...");
        conn.execute(
            "INSERT INTO global_knowledge (dna_signature, algorithm_name, score) VALUES (?1, ?2, ?3)",
            params!["DNA_H264_640033_AAC_0104", "Native", 500],
        )?;
        conn.execute(
            "INSERT INTO global_knowledge (dna_signature, algorithm_name, score) VALUES (?1, ?2, ?3)",
            params!["DNA_H264_4D4032_NOAUDIO", "Clone", 850],
        )?;
    }
    
    Ok(conn)
}

// =====================================================================
// ENDPOINT: /v1/swarm/sync
// =====================================================================
async fn swarm_sync(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(payload): Json<BrainExport>,
) -> Json<BrainExport> {
    println!("📡 Otrzymano synchronizację (Wersja: {}) od klienta. Rekordów: {}", payload.engine_version, payload.knowledge.len());
    
    let conn = state.db_conn.lock().unwrap();
    
    // 1. Zapis wiedzy klienta do chmury (Federated Learning - łączenie score)
    for entry in payload.knowledge {
        let features_str = entry.features.map(|f| f.to_string());
        
        let _ = conn.execute(
            "INSERT INTO global_knowledge (dna_signature, algorithm_name, score, features_json)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(dna_signature, algorithm_name) 
             DO UPDATE SET score = score + ?3",
            params![entry.dna_signature, entry.algorithm_name, entry.score, features_str],
        );
    }
    
    // 2. Odczyt wzbogaconej wiedzy z chmury do odesłania klientowi
    let mut stmt = conn.prepare("SELECT dna_signature, algorithm_name, score, features_json FROM global_knowledge").unwrap();
    let rows = stmt.query_map([], |row| {
        let feat_str: Option<String> = row.get(3)?;
        let features = feat_str.and_then(|s| serde_json::from_str(&s).ok());
        
        Ok(KnowledgeEntry {
            dna_signature: row.get(0)?,
            algorithm_name: row.get(1)?,
            score: row.get(2)?,
            features,
        })
    }).unwrap();
    
    let mut global_knowledge = Vec::new();
    for r in rows.flatten() {
        global_knowledge.push(r);
    }
    
    println!("✅ Zwracam zaktualizowany model globalny (Rekordów: {})", global_knowledge.len());
    
    Json(BrainExport {
        engine_version: "SwarmServer_1.0".to_string(),
        knowledge: global_knowledge,
    })
}

// =====================================================================
// WSPÓŁDZIELENIE DAWCOW (Encrypted .moov)
// =====================================================================

async fn upload_donor(Path(dna): Path<String>, body: Bytes) -> &'static str {
    let _ = std::fs::create_dir_all("encrypted_donors");
    let path = format!("encrypted_donors/{}.enc", dna);
    let human = get_human_readable_diagnosis(&dna);
    println!("📥 [UPLOAD] Otrzymano dawcę: [{}] (Zaszyfrowany)", human);
    std::fs::write(&path, body).unwrap();
    "OK"
}

async fn download_donor(Path(dna): Path<String>) -> Result<Vec<u8>, axum::http::StatusCode> {
    let path = format!("encrypted_donors/{}.enc", dna);
    let human = get_human_readable_diagnosis(&dna);
    println!("📤 [DOWNLOAD] Klient z Japonii prosi o: [{}]", human);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

// =====================================================================
// SERWER GŁÓWNY
// =====================================================================
#[tokio::main]
async fn main() {
    println!("🐝 Uruchamianie serwera MP4 Swarm Cloud API na porcie 3000...");
    
    let conn = init_db().expect("Nie udało się zainicjować bazy SQLite.");
    let state = Arc::new(AppState { db_conn: Mutex::new(conn) });
    
    let app = Router::new()
        .route("/", get(|| async { "MP4 Doctor Federated Learning API is running!" }))
        .route("/v1/swarm/sync", post(swarm_sync))
        .route("/v1/swarm/donor/{dna}", post(upload_donor).get(download_donor).head(check_donor))
        .with_state(state);
        
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Serwer nasłuchuje na http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn check_donor(Path(dna): Path<String>) -> Result<(), axum::http::StatusCode> {
    let path = format!("encrypted_donors/{}.enc", dna);
    if std::path::Path::new(&path).exists() {
        Ok(())
    } else {
        Err(axum::http::StatusCode::NOT_FOUND)
    }
}
