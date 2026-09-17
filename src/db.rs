// src/db.rs

//! # Moduł Zarządzania Bazą Danych (SQLite)
//!
//! Rdzeń Stanu (State Machine) aplikacji kryminalistycznej.

use rusqlite::{Connection, Result};
use std::fs;
use std::path::Path;
use tracing::{debug, info, instrument, warn};

// ============================================================================
// INICJALIZACJA I BUDOWA STRUKTURY
// ============================================================================

#[instrument(skip(db_path), fields(db_path = %db_path))]
pub fn init_db(db_path: &str) -> Result<Connection> {
    info!("Otwieranie i inicjalizacja kryminalistycznej bazy danych: {}", db_path);

    // 1. Zabezpieczenie inicjalizacji katalogu (Panic-Free)
    if db_path != ":memory:"
        && let Some(parent) = Path::new(db_path).parent()
            && !parent.as_os_str().is_empty() && !parent.exists() {
                debug!("Katalog bazy danych nie istnieje. Tworzenie: {:?}", parent);
                fs::create_dir_all(parent).unwrap_or_else(|e| {
                    warn!("Nie udało się utworzyć katalogu bazy danych, próba kontynuacji: {}", e);
                });
            }

    let conn = Connection::open(db_path)?;

    // 2. Aplikacja ekstremalnych reguł wydajnościowych ZANIM utworzymy gigantyczną tabelę
    configure_pragmas(&conn)?;

    // 3. Budowa potężnej płaskiej tabeli (Flat Table Architecture)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            relative_path TEXT UNIQUE NOT NULL,
            
            found_in_ufs BOOLEAN DEFAULT 0,
            found_in_script BOOLEAN DEFAULT 0,
            size_ufs INTEGER,
            size_script INTEGER,
            size_match BOOLEAN,
            
            hash_ufs TEXT,
            hash_script TEXT,
            hash_match BOOLEAN,
            
            magic_ok_ufs BOOLEAN,
            io_error_ufs BOOLEAN DEFAULT 0,
            magic_ok_script BOOLEAN,
            io_error_script BOOLEAN DEFAULT 0,
            
            uid_ufs INTEGER,
            uid_script INTEGER,
            gid_ufs INTEGER,
            gid_script INTEGER,
            mode_ufs INTEGER,
            mode_script INTEGER,
            mtime_ufs INTEGER,
            mtime_script INTEGER,
            is_symlink_ufs BOOLEAN,
            is_symlink_script BOOLEAN,
            meta_match BOOLEAN,
            
            zeros_pct_ufs REAL,
            zeros_pct_script REAL,
            eof_ok_ufs BOOLEAN,
            eof_ok_script BOOLEAN,
            
            ino_ufs INTEGER,
            ino_script INTEGER,
            nlink_ufs INTEGER,
            nlink_script INTEGER,
            has_xattr_ufs BOOLEAN,
            has_xattr_script BOOLEAN,
            
            entropy_ufs REAL,
            entropy_script REAL,
            
            name_anomaly BOOLEAN DEFAULT 0,
            
            merge_source TEXT,
            merge_success BOOLEAN DEFAULT 0,
            merge_reason TEXT,
            target_saved_path TEXT,
            merge_source_path TEXT,
            utf8_ok_ufs BOOLEAN,
            utf8_ok_script BOOLEAN,
            is_oneliner_ufs BOOLEAN,
            is_oneliner_script BOOLEAN,
            text_enc_ufs TEXT,
            text_enc_script TEXT,
            text_eol_ufs TEXT,
            text_eol_script TEXT,
            structure_ok_ufs BOOLEAN,
            structure_ok_script BOOLEAN,
            archive_reason_ufs TEXT,
            archive_reason_script TEXT,
            archive_files_ufs INTEGER,
            archive_size_ufs INTEGER,
            archive_files_script INTEGER,
            archive_size_script INTEGER,
            exif_ok_ufs BOOLEAN,
            exif_ok_script BOOLEAN,
            media_reason_ufs TEXT,
            media_reason_script TEXT,
            exif_engine_ufs TEXT,
            exif_engine_script TEXT,
            media_duration_ufs INTEGER,
            media_duration_script INTEGER,
            media_device_ufs TEXT,
            media_device_script TEXT,
            has_gps_ufs BOOLEAN,
            has_gps_script BOOLEAN,
            media_decoded_ufs BOOLEAN,
            media_decoded_script BOOLEAN,
            pixels_ok_ufs BOOLEAN,
            pixels_ok_script BOOLEAN,
            decode_reason_ufs TEXT,
            decode_reason_script TEXT,
            img_width_ufs INTEGER,
            img_width_script INTEGER,
            img_height_ufs INTEGER,
            img_height_script INTEGER,
            fuzzy_hash_ufs TEXT,
            fuzzy_hash_script TEXT,
            fuzzy_match_pct REAL,
            yara_match_ufs TEXT,
            yara_match_script TEXT,
            repaired_path_ufs TEXT,
            repaired_path_script TEXT,
            repair_log_ufs TEXT,
            repair_log_script TEXT,
            
            phase1_done BOOLEAN DEFAULT 0,
            phase2_done BOOLEAN DEFAULT 0,
            phase3_done BOOLEAN DEFAULT 0,
            phase4_done BOOLEAN DEFAULT 0,
            phase5_done BOOLEAN DEFAULT 0,
            phase6_done BOOLEAN DEFAULT 0,
            phase7_done BOOLEAN DEFAULT 0,
            phase8_done BOOLEAN DEFAULT 0,
            phase9_done BOOLEAN DEFAULT 0,
            phase10_done BOOLEAN DEFAULT 0,
            phase11_done BOOLEAN DEFAULT 0,
            phase12_done BOOLEAN DEFAULT 0,
            phase13_done BOOLEAN DEFAULT 0,
            phase14_done BOOLEAN DEFAULT 0,
            phase15_done BOOLEAN DEFAULT 0,
            phase16_done BOOLEAN DEFAULT 0,
            phase17_done BOOLEAN DEFAULT 0,

            /* Kolumny Fazy 18 (Smart Splice). MUSZĄ istnieć od inicjalizacji,
               bo SELECT Fazy 9 czyta `smart_splice_path` BEZWARUNKOWO (patrz
               `phase9::run`) - a Faza 9 może zostać uruchomiona, gdy Faza 18
               nigdy nie działała. */
            smart_splice_path TEXT,
            smart_splice_log TEXT,
            phase18_done BOOLEAN DEFAULT 0,

            /* Kolumny Fazy 19 (Diagnostyka Wideo) - komplet od startu, z tego
               samego powodu co wyżej. */
            video_ok_ufs BOOLEAN,
            video_ok_script BOOLEAN,
            video_reason_ufs TEXT,
            video_reason_script TEXT,
            video_duration_ms_ufs INTEGER,
            video_duration_ms_script INTEGER,
            video_tracks_ufs INTEGER,
            video_tracks_script INTEGER,
            /* Czas utworzenia nagrania odczytany z atomu `mvhd` kontenera,
               w sekundach epoki Unix. Wartość KONTENEROWA, niezależna od EXIF
               i od metadanych systemu plików — przy odzysku bywa jedynym
               ocalałym znacznikiem czasu. */
            video_created_unix INTEGER,
            phase19_done BOOLEAN DEFAULT 0
        )",
        [],
    )?;

    // 4. Domknięcie schematu na bazach utworzonych PRZED tą rewizją
    migrate_schema(&conn);

    // 5. Tabele pomocnicze faz - tworzone tu, nie dopiero w swojej fazie
    create_analysis_tables(&conn)?;

    // 6. Budowa struktur indeksowania B-Tree (Partial Indexes)
    create_indexes(&conn)?;

    // 7. Elastyczna weryfikacja schematu
    verify_schema(&conn)?;

    info!("Baza danych gotowa do działania w trybie wysokiej wydajności.");
    Ok(conn)
}

// ============================================================================
// DOMKNIĘCIE SCHEMATU (MIGRACJA BAZ STARSZYCH REWIZJI)
// ============================================================================

/// Pełna lista kolumn tabeli `files`, które historycznie były dodawane przez
/// `ALTER TABLE` w samych fazach, a nie w bazowym `CREATE TABLE` powyżej.
///
/// ## Dlaczego to musi być TUTAJ, a nie tylko w fazach
///
/// Fazy nie są niezależne: kilka z nich czyta kolumny NALEŻĄCE DO INNEJ fazy w
/// jednym dużym `SELECT`. Sztandarowy przykład to Faza 9 (Złota Kopia), która
/// czyta `smart_splice_path` (własność Fazy 18) i `repaired_path_*` (własność
/// Fazy 17). Jeżeli kolumnę zakłada dopiero jej własna faza, to uruchomienie
/// Fazy 9 na bazie, na której Faza 18 nigdy nie działała, wywala `prepare()`
/// błędem `no such column: smart_splice_path` — zgłoszone jako "BŁĄD KRYTYCZNY
/// BAZY DANYCH" w `menu::actions`. SQLite rozwiązuje nazwy kolumn i tabel już
/// przy przygotowaniu zapytania, więc żaden warunek w `WHERE` (np.
/// `phase18_done = 1 AND ...`) przed tym NIE chroni.
///
/// Dlatego schemat jest domykany RAZ, przy inicjalizacji bazy: każda faza
/// może być odpalona w dowolnej kolejności i pojedynczo. `ALTER TABLE` w
/// samych fazach zostaje jako obrona w głębi (staje się no-opem).
const KOLUMNY_MIGRACJI: &[&str] = &[
    // Faza 1 / 2
    "is_orphan BOOLEAN DEFAULT 0",
    "larger_side TEXT",
    // Faza 9
    "merge_reason TEXT",
    "target_saved_path TEXT",
    "merge_source_path TEXT",
    // Faza 11 - sygnały nieobecne w bazowym schemacie
    "archive_encrypted_ufs BOOLEAN",
    "archive_encrypted_script BOOLEAN",
    "archive_suspicious_compression_ufs BOOLEAN",
    "archive_suspicious_compression_script BOOLEAN",
    // Faza 12 - sygnały nieobecne w bazowym schemacie
    "gps_suspicious_ufs BOOLEAN",
    "gps_suspicious_script BOOLEAN",
    "date_implausible_ufs BOOLEAN",
    "date_implausible_script BOOLEAN",
    "editing_software_ufs TEXT",
    "editing_software_script TEXT",
    // Faza 13 - sygnały nieobecne w bazowym schemacie
    "img_extreme_ratio_ufs BOOLEAN",
    "img_extreme_ratio_script BOOLEAN",
    "img_uniform_ufs BOOLEAN",
    "img_uniform_script BOOLEAN",
    // Faza 17 (czytane przez Fazę 9)
    "repaired_path_ufs TEXT",
    "repaired_path_script TEXT",
    "repair_log_ufs TEXT",
    "repair_log_script TEXT",
    // Faza 18 (czytane przez Fazę 9) - bezpośrednia przyczyna zgłoszonego błędu
    "smart_splice_path TEXT",
    "smart_splice_log TEXT",
    "phase18_done BOOLEAN DEFAULT 0",
    // Faza 19
    "video_ok_ufs BOOLEAN",
    "video_ok_script BOOLEAN",
    "video_reason_ufs TEXT",
    "video_reason_script TEXT",
    "video_duration_ms_ufs INTEGER",
    "video_duration_ms_script INTEGER",
    "video_tracks_ufs INTEGER",
    "video_tracks_script INTEGER",
    "video_created_unix INTEGER",
    "phase19_done BOOLEAN DEFAULT 0",
    // Narzędzia poza numerowanymi fazami
    "dng_structural_status TEXT",
    // Ścieżka wyniku narzędzia DNG. Bez niej sprzątanie przestrzeni roboczej
    // nie umiało powiązać plików w `_dng_structural_review` z rekordami i
    // musiało traktować cały katalog jako nieśledzony.
    "dng_structural_path TEXT",
    "duplicate_count_ufs INTEGER",
    "duplicate_count_script INTEGER",
    "duplicate_canonical_id_ufs INTEGER",
    "duplicate_canonical_id_script INTEGER",
];

/// Dodaje brakujące kolumny do istniejącej tabeli `files`.
///
/// Celowo NIE zwraca błędu: `ALTER TABLE ... ADD COLUMN` na kolumnie, która
/// już istnieje, kończy się błędem `duplicate column name` i to jest tu
/// normalny, oczekiwany stan (baza jest już domknięta). Liczymy tylko realnie
/// dodane kolumny, żeby zostawić ślad w logu.
#[instrument(skip(conn))]
fn migrate_schema(conn: &Connection) {
    let mut dodane = Vec::new();

    for kolumna in KOLUMNY_MIGRACJI {
        if conn.execute(&format!("ALTER TABLE files ADD COLUMN {}", kolumna), []).is_ok() {
            dodane.push(*kolumna);
        }
    }

    if dodane.is_empty() {
        debug!("Schemat tabeli `files` był już domknięty - brak kolumn do dodania.");
    } else {
        info!(
            liczba = dodane.len(),
            ?dodane,
            "Domknięto schemat tabeli `files` (migracja bazy starszej rewizji)."
        );
    }
}

/// Tworzy tabele pomocnicze faz 14/15/16 JUŻ PRZY INICJALIZACJI.
///
/// Powód identyczny jak przy [`KOLUMNY_MIGRACJI`], tylko dotyczy tabel, a nie
/// kolumn: Faza 17 robi `LEFT JOIN phase14_analysis` (patrz
/// `phase17_repair::run`), a `diag` odpytuje `phase14_analysis` i
/// `phase15_analysis` w podzapytaniach. Gdy tabelę zakłada dopiero jej własna
/// faza, uruchomienie Fazy 17 albo diagnostyki przed Fazą 14 kończy się
/// błędem `no such table: phase14_analysis`.
///
/// Definicje są tu KOMPLETNE — łącznie z kolumnami, które `phase15` dodaje
/// swoimi `ALTER TABLE` — więc te `ALTER`-y stają się no-opami.
#[instrument(skip(conn))]
fn create_analysis_tables(conn: &Connection) -> Result<()> {
    debug!("Weryfikacja/Budowa tabel pomocniczych faz (14/15/16)");

    conn.execute(
        "CREATE TABLE IF NOT EXISTS phase14_analysis (
            file_id INTEGER PRIMARY KEY,
            match_type TEXT,
            match_pct REAL,
            twin_file_path TEXT,
            delta_bytes INTEGER,
            extension_mismatch BOOLEAN,
            FOREIGN KEY(file_id) REFERENCES files(id)
        )",
        [],
    )?;

    // REGRESJA (todo.faza15.md, Znalezisko 1 — WYSOKIE): stary schemat miał
    // `file_id INTEGER PRIMARY KEY` — jeden wiersz NA PLIK, nie na stronę.
    // Dla plików WSPÓLNYCH (obecnych po obu stronach) `phases::phase15`
    // buduje dwa niezależne zadania o tym samym `file_id`, oba piszące przez
    // `INSERT OR REPLACE` — drugi zapis bezpowrotnie kasował pierwszy,
    // tracąc UID/GID/klucze xattr/sygnały URL jednej z dwóch fizycznych
    // kopii. Klucz złożony (file_id, side) eliminuje kolizję u źródła. TA
    // definicja (tworzona JUŻ PRZY INICJALIZACJI bazy, patrz dokumentacja
    // funkcji) MUSI zostać zsynchronizowana z definicją w
    // `phases::phase15::run` — inaczej ta, kanoniczna, tworzona jako
    // pierwsza, zawsze "wygrywałaby" nad własnym, spóźnionym
    // `CREATE TABLE IF NOT EXISTS` Fazy 15 (który wtedy staje się no-opem),
    // a mechanizm migracji Fazy 15 uruchamiałby się niepotrzebnie przy
    // KAŻDYM pierwszym uruchomieniu na świeżej bazie.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS phase15_analysis (
            file_id INTEGER NOT NULL,
            side TEXT NOT NULL CHECK(side IN ('ufs','script')),
            has_xattr BOOLEAN,
            xattr_count INTEGER,
            xattr_size INTEGER,
            xattr_keys TEXT,
            uid INTEGER,
            gid INTEGER,
            has_url BOOLEAN,
            has_zone_identifier BOOLEAN,
            has_quarantine BOOLEAN,
            has_wherefroms BOOLEAN,
            has_large_xattr BOOLEAN,
            PRIMARY KEY(file_id, side),
            FOREIGN KEY(file_id) REFERENCES files(id)
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS phase16_analysis (
            file_id INTEGER PRIMARY KEY,
            yara_matched BOOLEAN,
            rules_triggered TEXT,
            FOREIGN KEY(file_id) REFERENCES files(id)
        )",
        [],
    )?;

    Ok(())
}

// ============================================================================
// OPTYMALIZACJA WYDAJNOŚCI BAZY (PRAGMA)
// ============================================================================

#[instrument(skip(conn))]
fn configure_pragmas(conn: &Connection) -> Result<()> {
    debug!("Aplikacja strategii wielowątkowości i I/O (MMAP, WAL, RAM Cache)");
    conn.execute_batch(r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA busy_timeout = 15000;
        PRAGMA mmap_size = 2147483648;
        PRAGMA temp_store = MEMORY;
        PRAGMA wal_autocheckpoint = 10000;
        PRAGMA cache_size = -262144; /* ~256 MB RAM na bufor stron SQLite */
        PRAGMA journal_size_limit = 67108864; /* 64 MB twardego limitu pliku WAL */
    "#)?;
    Ok(())
}

// ============================================================================
// TWORZENIE INDEKSÓW (B-TREES) - PARTIAL INDEXING
// ============================================================================

#[instrument(skip(conn))]
fn create_indexes(conn: &Connection) -> Result<()> {
    info!("Weryfikacja/Budowa map indeksowania B-Tree dla szybkiego wyszukiwania");

    // Główne indeksy biznesowe
    conn.execute("CREATE INDEX IF NOT EXISTS idx_found_both ON files (found_in_ufs, found_in_script, phase1_done)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_size_match ON files (size_match, hash_match, phase3_done)", [])?;
    
    // Optymalizacja dla faz kryptograficznych
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hash_ufs_null ON files (found_in_ufs) WHERE hash_ufs IS NULL", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hash_script_null ON files (found_in_script) WHERE hash_script IS NULL", [])?;

    // Przechodzimy po WSZYSTKICH 19 FAZACH z użyciem PARTIAL INDEXES.
    // Indeks śledzi tylko rekordy, gdzie faza NIE JEST jeszcze zrobiona.
    // Fazy 18/19 były tu wcześniej pominięte, choć `phase18_done`/`phase19_done`
    // są używane jako filtr postępu dokładnie tak samo jak pozostałe.
    for phase in 1..=19 {
        let query = format!(
            "CREATE INDEX IF NOT EXISTS idx_phase{p}_done ON files (phase{p}_done) WHERE phase{p}_done = 0 OR phase{p}_done IS NULL",
            p = phase
        );
        conn.execute(&query, [])?;
    }

    Ok(())
}

// ============================================================================
// SYSTEM DIAGNOSTYCZNY BAZY DANYCH
// ============================================================================

fn verify_schema(conn: &Connection) -> Result<()> {
    let column_count: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('files')", [], |row| row.get(0))?;
    let index_count: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name='files'", [], |row| row.get(0))?;
    
    info!(kolumny = column_count, indeksy = index_count, "Weryfikacja schematu SQLite zakończona pomyślnie.");
    
    // Uelastyczniony limit. Posiadamy potężną tabelę, niech sprawdza minimalny próg sensowności
    let expected_min_columns = 60;
    if column_count < expected_min_columns {
        warn!("UWAGA: Tabela 'files' wydaje się niekompletna (znaleziono {} kolumn, oczekiwano min. {}). Może to oznaczać uszkodzoną migrację.", column_count, expected_min_columns);
    }
    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE (cargo test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_init_db_in_memory() {
        // Test inicjalizacji bazy w pamięci operacyjnej (szybki, izolowany)
        let conn = init_db(":memory:").expect("Nie udało się zainicjalizować bazy in-memory");
        
        // Weryfikacja czy tabela `files` istnieje
        let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='files'").unwrap();
        let exists = stmt.exists([]).unwrap();
        assert!(exists, "Tabela files nie została utworzona");
    }

    #[test]
    fn test_init_db_on_disk() {
        // Test tworzenia struktury katalogów i pliku DB na fizycznym nośniku w katalogu tymczasowym
        let dir = tempdir().expect("Błąd tworzenia katalogu tymczasowego");
        let db_path = dir.path().join("test_baza.db");
        
        let conn = init_db(db_path.to_str().unwrap()).expect("Nie udało się zainicjalizować bazy dyskowej");
        assert!(db_path.exists(), "Plik bazy danych nie powstał fizycznie na dysku");
        
        let pragmas_ok: i64 = conn.query_row("PRAGMA journal_size_limit", [], |row| row.get(0)).unwrap();
        assert_eq!(pragmas_ok, 67108864, "PRAGMA journal_size_limit nie została zaaplikowana poprawnie");
    }

    #[test]
    fn test_partial_indexes_functionality() {
        let conn = init_db(":memory:").unwrap();
        
        // Dodajemy dwa rekordy: jeden zrobiony, drugi do zrobienia (Faza 1)
        conn.execute("INSERT INTO files (relative_path, phase1_done) VALUES ('plik1.txt', 1)", []).unwrap();
        conn.execute("INSERT INTO files (relative_path, phase1_done) VALUES ('plik2.txt', 0)", []).unwrap();
        
        // Sprawdzamy czy query planner rzeczywiście używa naszego indeksu częściowego
        let mut stmt = conn.prepare("EXPLAIN QUERY PLAN SELECT * FROM files WHERE phase1_done = 0").unwrap();
        let mut plan_rows = stmt.query([]).unwrap();
        
        let mut used_idx = false;
        while let Some(row) = plan_rows.next().unwrap() {
            let detail: String = row.get(3).unwrap_or_default();
            if detail.contains("idx_phase1_done") {
                used_idx = true;
                break;
            }
        }
        assert!(used_idx, "Query planner nie użył zoptymalizowanego indeksu częściowego!");
    }

    // ------------------------------------------------------------------
    // REGRESJA: kolumny i tabele czytane MIĘDZY fazami
    // Zgłoszony objaw: "BŁĄD KRYTYCZNY BAZY DANYCH: no such column:
    // smart_splice_path" przy uruchomieniu Fazy 9 bez przebiegu Fazy 18.
    // ------------------------------------------------------------------

    /// Faza 9 czyta kolumny należące do Faz 17 i 18 w jednym `SELECT`.
    /// Na świeżo zainicjalizowanej bazie `prepare()` MUSI się udać, nawet
    /// jeśli żadna z tych faz nigdy nie działała.
    #[test]
    fn test_select_fazy9_przygotowuje_sie_na_swiezej_bazie() {
        let conn = init_db(":memory:").unwrap();

        conn.prepare(
            "SELECT id, relative_path, repaired_path_ufs, repaired_path_script, smart_splice_path
             FROM files WHERE phase9_done = 0 OR phase9_done IS NULL",
        )
        .expect("SELECT Fazy 9 musi się przygotować bez przebiegu Faz 17/18");
    }

    /// Faza 17 robi `LEFT JOIN phase14_analysis`. Tabela musi istnieć od
    /// inicjalizacji, bo Faza 17 bywa uruchamiana bez Fazy 14.
    #[test]
    fn test_join_fazy17_przygotowuje_sie_bez_przebiegu_fazy14() {
        let conn = init_db(":memory:").unwrap();

        conn.prepare(
            "SELECT f.id, a.match_type, a.twin_file_path
             FROM files f LEFT JOIN phase14_analysis a ON f.id = a.file_id",
        )
        .expect("LEFT JOIN Fazy 17 musi się przygotować bez przebiegu Fazy 14");
    }

    /// Podzapytania `diag` sięgają do tabel pomocniczych Faz 14/15.
    #[test]
    fn test_tabele_pomocnicze_istnieja_po_inicjalizacji() {
        let conn = init_db(":memory:").unwrap();

        for tabela in ["phase14_analysis", "phase15_analysis", "phase16_analysis"] {
            let istnieje: bool = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?1")
                .unwrap()
                .exists([tabela])
                .unwrap();
            assert!(istnieje, "Brak tabeli pomocniczej {}", tabela);
        }
    }

    /// Kolumny Faz 18/19 są w bazowym `CREATE TABLE`, więc na nowej bazie
    /// migracja nie ma nic do roboty — ale `phase19_done` musi tam być.
    #[test]
    fn test_kolumny_faz18_19_obecne_na_nowej_bazie() {
        let conn = init_db(":memory:").unwrap();

        for kolumna in ["smart_splice_path", "smart_splice_log", "phase18_done", "phase19_done"] {
            let istnieje: bool = conn
                .prepare("SELECT 1 FROM pragma_table_info('files') WHERE name = ?1")
                .unwrap()
                .exists([kolumna])
                .unwrap();
            assert!(istnieje, "Brak kolumny {} w schemacie bazowym", kolumna);
        }
    }

    /// Najważniejszy scenariusz: baza ISTNIEJĄCA, utworzona przed tą rewizją.
    /// `CREATE TABLE IF NOT EXISTS` jest na niej no-opem, więc kolumny może
    /// dodać WYŁĄCZNIE migracja.
    #[test]
    fn test_migracja_domyka_baze_starszej_rewizji() {
        let conn = Connection::open_in_memory().unwrap();

        // Tabela w kształcie "sprzed rewizji" - bez kolumn Faz 17/18/19.
        conn.execute(
            "CREATE TABLE files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                relative_path TEXT UNIQUE NOT NULL,
                phase9_done BOOLEAN DEFAULT 0
            )",
            [],
        )
        .unwrap();

        assert!(
            conn.prepare("SELECT smart_splice_path FROM files").is_err(),
            "Test bez sensu: kolumna nie powinna istnieć PRZED migracją"
        );

        migrate_schema(&conn);

        conn.prepare("SELECT repaired_path_ufs, repaired_path_script, smart_splice_path FROM files")
            .expect("Po migracji kolumny czytane przez Fazę 9 muszą istnieć");
    }

    /// Kolumny narzędzi spoza numerowanych faz też muszą przejść migrację.
    ///
    /// `dng_structural_path` jest tu kluczowa: bez niej sprzątanie przestrzeni
    /// roboczej nie potrafi powiązać plików w `_dng_structural_review` z
    /// rekordami, a narzędzie DNG wywala się przy zapisie. Na bazie założonej
    /// przed tą rewizją dodać ją może WYŁĄCZNIE migracja.
    #[test]
    fn test_migracja_dodaje_kolumny_narzedzi_dng() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                relative_path TEXT UNIQUE NOT NULL
            )",
            [],
        )
        .unwrap();

        assert!(
            conn.prepare("SELECT dng_structural_path FROM files").is_err(),
            "Test bez sensu: kolumna nie powinna istnieć PRZED migracją"
        );

        migrate_schema(&conn);

        conn.prepare("SELECT dng_structural_status, dng_structural_path FROM files")
            .expect("Po migracji obie kolumny narzędzia DNG muszą istnieć");
    }

    /// Migracja musi być idempotentna — uruchamiana przy KAŻDYM starcie.
    #[test]
    fn test_migracja_jest_idempotentna() {
        let conn = init_db(":memory:").unwrap();

        // Druga i trzecia migracja na domkniętej bazie nie mogą nic zepsuć.
        migrate_schema(&conn);
        migrate_schema(&conn);

        conn.prepare("SELECT smart_splice_path FROM files")
            .expect("Powtórna migracja nie może uszkodzić schematu");
    }
}
