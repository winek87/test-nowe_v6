// src/diag.rs

//! # Moduł Diagnostyczny Bazy Danych (Kryminalistyczny Drill-Down)
//!
//! Ostateczne Centrum Dowodzenia. Integruje analitykę ze WSZYSTKICH 19 faz.
//! Wyświetla logiczne statusy, anomalie YARA, błędy pikseli, zupę binarną,
//! zaginione bliźniaki, złożenia Smart Splice i diagnostykę wideo. W pełni
//! oparty na interfejsie Ratatui.
//!
//! NAPRAWIONY BRAK (Fazy 18 i 19): lista faz kończyła się na 17, więc ekran
//! diagnostyczny w ogóle nie raportował ani złożeń Fazy 18, ani wyników
//! Fazy 19 — mimo że obie zapisują do bazy własne kolumny. To ten sam wzorzec
//! „18/19 zapomniane", który wcześniej wystąpił w bazowym schemacie (`db.rs`)
//! i w narzędziu resetu (`reset.rs`).
//!
//! Kolejność na liście jest CHRONOLOGICZNA wobec przebiegu odzysku: Fazy 17-19
//! wytwarzają dane (naprawy, złożenia, diagnostykę), a Faza 9 (Smart Merge)
//! konsumuje je na końcu, budując Złotą Kopię — dlatego "8/9" zamyka listę.

use rusqlite::{Connection, Result};
use std::io;
use std::time::Duration;

use crossterm::{
    event::{poll, read, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table, TableState},
    Terminal, Frame,
};

// ============================================================================
// POMOCNIKI I STRAŻNICY
// ============================================================================

/// Chroni terminal przed "zcegłowaniem" w przypadku nagłego panic!
struct TerminalGuard;
impl TerminalGuard {
    fn acquire() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let mut s2: String = s.chars().take(max.saturating_sub(3)).collect();
        s2.push_str("...");
        s2
    } else {
        s.to_string()
    }
}

// ============================================================================
// MODELE DANYCH
// ============================================================================

#[derive(Clone)]
struct PhaseMetric {
    pub name: String,
    pub cond: String,
    pub count: i64,
}

#[derive(Clone)]
struct PhaseDiag {
    pub id: &'static str,
    pub name: &'static str,
    pub metrics: Vec<PhaseMetric>,
    pub done_count: i64,
    pub anomaly_count: i64,
}

struct TableData {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub ufs_top: Vec<String>,
    pub script_top: Vec<String>,
}

enum ViewState {
    PhaseList,
    StatusList { phase_idx: usize },
    DataView { phase_idx: usize, data: TableData },
}

struct DiagApp {
    phases: Vec<PhaseDiag>,
    view_state: ViewState,
    phase_list_state: ListState,
    status_list_state: ListState,
    table_state: TableState,
}

impl DiagApp {
    fn new(phases: Vec<PhaseDiag>) -> Self {
        let mut phase_list_state = ListState::default();
        phase_list_state.select(Some(0));

        Self {
            phases,
            view_state: ViewState::PhaseList,
            phase_list_state,
            status_list_state: ListState::default(),
            table_state: TableState::default(),
        }
    }
}

// ============================================================================
// BAZA DANYCH - DEFINICJE METRYK DLA 19 FAZ
// ============================================================================

/// Krotka opisująca JEDNĄ fazę na ekranie diagnostycznym:
/// `(id, nazwa, warunek_postępu, metryki, warunek_anomalii)`.
///
/// `warunek_postępu` i każdy warunek metryki to fragment `WHERE` wstawiany do
/// `SELECT COUNT(*) FROM files WHERE ...`.
type DefinicjaFazy = (
    &'static str,
    &'static str,
    &'static str,
    Vec<(&'static str, &'static str)>,
    Option<&'static str>,
);

/// Definicje wszystkich faz pokazywanych w diagnostyce.
///
/// Wydzielone z [`fetch_phases`] CELOWO: warunki są zwykłymi napisami SQL, a
/// `fetch_phases` tłumi błędy zapytań przez `unwrap_or(0)` — literówka albo
/// odwołanie do nieistniejącej kolumny pokazywałoby się jako spokojne „0",
/// bez śladu awarii. Osobna funkcja pozwala testom przejść WSZYSTKIE warunki
/// i sprawdzić, że każdy jest poprawnym SQL-em wobec realnego schematu bazy.
///
/// KOLEJNOŚĆ jest chronologiczna wobec przebiegu odzysku — patrz dokumentacja
/// modułu co do tego, dlaczego „8/9" zamyka listę.
fn phase_definitions() -> Vec<DefinicjaFazy> {
    vec![
        ("1", "Mapowanie struktury wolumenów", "phase1_done = 1", vec![
            ("Wszystkie znalezione pliki", "phase1_done = 1"),
            ("Część wspólna (OBA WOLUMENY)", "phase1_done = 1 AND found_in_ufs = 1 AND found_in_script = 1"),
            ("Unikalne dla UFS", "phase1_done = 1 AND found_in_ufs = 1 AND found_in_script = 0"),
            ("Unikalne dla Skryptu", "phase1_done = 1 AND found_in_ufs = 0 AND found_in_script = 1"),
        ], None),

        ("2", "Analiza wolumetrii (Rozmiary)", "phase2_done = 1", vec![
            ("Rozmiary zgodne (size_match = 1)", "phase2_done = 1 AND size_match = 1"),
            ("Rozmiary RÓŻNE (size_match = 0)", "phase2_done = 1 AND size_match = 0"),
        ], Some("phase2_done = 0 AND (size_ufs IS NOT NULL OR size_script IS NOT NULL)")),

        ("3", "Kryptografia BLAKE3 (Wspólne)", "phase3_done = 1", vec![
            ("Zgodne Bit-to-Bit (hash_match = 1)", "phase3_done = 1 AND hash_match = 1"),
            ("Różne Hashe (KOLIZJA / KORUPCJA)", "phase3_done = 1 AND hash_match = 0"),
        ], Some("phase3_done = 0 AND (hash_ufs IS NOT NULL OR hash_script IS NOT NULL)")),

        ("4", "Kryptografia BLAKE3 (Resztkowe)", "phase4_done = 1", vec![
            ("Zhashowane pliki unikalne", "phase4_done = 1 AND hash_match IS NULL"),
        ], None),

        ("5", "Atrybuty Zewnętrzne (MFT/i-node)", "phase5_done = 1", vec![
            ("Zgodne w 100% (Data i Prawa)", "phase5_done = 1 AND meta_match = 1"),
            ("Utracona Data (Epoka 1970 r.)", "phase5_done = 1 AND (mtime_ufs <= 0 OR mtime_script <= 0)"),
            ("Złamanie Właściciela (UID = 0 / ROOT)", "phase5_done = 1 AND (uid_ufs = 0 OR uid_script = 0)"),
        ], Some("phase5_done = 0 AND (uid_ufs IS NOT NULL OR uid_script IS NOT NULL)")),

        ("6", "Wydmuszki i Znaczniki EOF", "phase6_done = 1", vec![
            ("Zdrowe zawartości", "phase6_done = 1 AND (zeros_pct_ufs < 90.0 OR zeros_pct_script < 90.0)"),
            ("Wydmuszki HDD/SSD (Zera > 99%)", "phase6_done = 1 AND (zeros_pct_ufs > 99.0 OR zeros_pct_script > 99.0)"),
            ("Brak Ogona (Ucięte / Brak EOF)", "phase6_done = 1 AND (eof_ok_ufs = 0 OR eof_ok_script = 0)"),
        ], Some("phase6_done = 0 AND (zeros_pct_ufs IS NOT NULL)")),

        ("7", "Entropia Shannona", "phase7_done = 1", vec![
            ("Biały Szum / Zniszczone (H > 7.99)", "phase7_done = 1 AND (entropy_ufs > 7.995 OR entropy_script > 7.995)"),
            ("Zaszyfrowane Ransomware (H > 7.5)", "phase7_done = 1 AND (entropy_ufs > 7.5 OR entropy_script > 7.5)"),
            ("Wydmuszki (Puste bloki, H < 1.0)", "phase7_done = 1 AND (entropy_ufs < 1.0 OR entropy_script < 1.0)"),
        ], Some("phase7_done = 0 AND (entropy_ufs IS NOT NULL)")),

        ("10", "Tekst (Deep Text Forensics)", "phase10_done = 1", vec![
            ("Zupa Binarna (Błędny Carver, Brak UTF-8)", "phase10_done = 1 AND (utf8_ok_ufs = 0 OR utf8_ok_script = 0)"),
            ("Podejrzany One-Liner (Payload >10KB)", "phase10_done = 1 AND (is_oneliner_ufs = 1 OR is_oneliner_script = 1)"),
        ], None),

        ("11", "Archiwa (ZIP/DOCX/APK)", "phase11_done = 1", vec![
            ("Zdrowe archiwa (Zgodne EOCD)", "phase11_done = 1 AND (structure_ok_ufs = 1 OR structure_ok_script = 1)"),
            ("Zepsuta Struktura / Zip Bomb", "phase11_done = 1 AND (structure_ok_ufs = 0 OR structure_ok_script = 0)"),
        ], None),

        ("12", "Metadane EXIF/HEIF", "phase12_done = 1", vec![
            ("Zniszczony Nagłówek / Fałszywe Rozsz.", "phase12_done = 1 AND (exif_ok_ufs = 0 OR exif_ok_script = 0)"),
            ("Odzyskane Koordynaty GPS", "phase12_done = 1 AND (has_gps_ufs = 1 OR has_gps_script = 1)"),
        ], None),

        ("13", "Renderowanie RAM (Gray Banding)", "phase13_done = 1", vec![
            ("Zepsute Piksele / Przepełnienie RAM", "phase13_done = 1 AND (pixels_ok_ufs = 0 OR pixels_ok_script = 0)"),
            ("W pełni zdekodowane klatki", "phase13_done = 1 AND (pixels_ok_ufs = 1 OR pixels_ok_script = 1)"),
        ], None),

        ("14", "Fuzzy Hashing (Zaginione Bliźniaki)", "phase14_done = 1", vec![
            ("Zaginione Bliźniaki (>= 90% Match)", "phase14_done = 1 AND id IN (SELECT file_id FROM phase14_analysis WHERE match_type = 'TWIN')"),
            ("Częściowo Uszkodzone (1-89%)", "phase14_done = 1 AND id IN (SELECT file_id FROM phase14_analysis WHERE match_type = 'PARTIAL')"),
            ("Frankensteiny (0% podobieństwa)", "phase14_done = 1 AND id IN (SELECT file_id FROM phase14_analysis WHERE match_type = 'FRANKENSTEIN')"),
        ], None),

        ("15", "Atrybuty XATTR", "phase15_done = 1", vec![
            ("Pliki z ukrytymi atrybutami", "phase15_done = 1 AND id IN (SELECT file_id FROM phase15_analysis)"),
            ("Ślady sieciowe (URL / Pobrane z WWW)", "phase15_done = 1 AND id IN (SELECT file_id FROM phase15_analysis WHERE has_url = 1)"),
        ], None),

        ("16", "Skaner Sygnatur (YARA)", "phase16_done = 1", vec![
            ("⚠️ ZAINFEKOWANE (Wykryto Malware) ⚠️", "phase16_done = 1 AND (yara_match_ufs IS NOT NULL OR yara_match_script IS NOT NULL)"),
            ("Czyste pliki", "phase16_done = 1 AND yara_match_ufs IS NULL AND yara_match_script IS NULL"),
        ], None),

        // Faza 17 ustawia już `phase17_done` dla KAŻDEGO przetworzonego pliku
        // (także takiego, którego nie udało się naprawić) — patrz naprawiony
        // brak w `phase17_repair`. Postęp liczymy więc normalną flagą, tak jak
        // przy wszystkich innych fazach. Wcześniej moduł liczył go po kolumnie
        // `id`, czyli pokazywał liczbę WSZYSTKICH plików w bazie.
        ("17", "Moduł Naprawczy (Rekonstrukcja)", "phase17_done = 1", vec![
            ("Skutecznie Naprawione / Zrekonstruowane", "repaired_path_ufs IS NOT NULL OR repaired_path_script IS NOT NULL"),
            ("Naprawiona wersja UFS", "repaired_path_ufs IS NOT NULL"),
            ("Naprawiona wersja Skryptu", "repaired_path_script IS NOT NULL"),
            ("Naprawione OBIE strony", "repaired_path_ufs IS NOT NULL AND repaired_path_script IS NOT NULL"),
        ], None),

        ("18", "Smart Splice (Składanie z 2 kopii)", "phase18_done = 1", vec![
            ("Złożone i ZWERYFIKOWANE (gotowe dla Fazy 9)", "phase18_done = 1 AND smart_splice_path IS NOT NULL"),
            ("Przetworzone bez udanego złożenia", "phase18_done = 1 AND smart_splice_path IS NULL"),
        ], Some("phase18_done = 0 AND smart_splice_path IS NOT NULL")),

        ("19", "Diagnostyka Wideo (MP4/MKV/TS/FLV)", "phase19_done = 1", vec![
            ("Sprawne kontenery wideo", "phase19_done = 1 AND (video_ok_ufs = 1 OR video_ok_script = 1)"),
            ("USZKODZONE WIDEO (ucięty moov / zła struktura)", "phase19_done = 1 AND (video_ok_ufs = 0 OR video_ok_script = 0)"),
            ("Odzyskany czas trwania (metadane obecne)", "phase19_done = 1 AND (video_duration_ms_ufs > 0 OR video_duration_ms_script > 0)"),
            ("Rozpoznane ścieżki A/V", "phase19_done = 1 AND (video_tracks_ufs > 0 OR video_tracks_script > 0)"),
            // Znacznik czasu z atomu `mvhd` kontenera — niezależny od EXIF i od
            // metadanych systemu plików. Przy odzysku bywa JEDYNYM ocalałym
            // śladem, kiedy powstało nagranie (Faza 5 zgłasza wtedy „Utracona
            // Data (Epoka 1970 r.)").
            ("Odzyskany czas utworzenia nagrania (mvhd)", "phase19_done = 1 AND video_created_unix IS NOT NULL"),
        ], Some("phase19_done = 0 AND (video_ok_ufs IS NOT NULL OR video_ok_script IS NOT NULL)")),

        ("8/9", "Smart Merge (Złota Kopia)", "phase9_done = 1", vec![
            ("Pomyślnie Skopiowano (Złota Kopia)", "phase9_done = 1 AND merge_success = 1"),
            ("Odrzucono przez heurystykę", "phase9_done = 1 AND merge_success = 0"),
            // SKĄD wzięto bajty — rozbicie po zwycięskiej stronie.
            ("Zwycięzcą strona UFS Explorer", "phase9_done = 1 AND merge_source = 'ufs'"),
            ("Zwycięzcą strona Skrypt Autorski", "phase9_done = 1 AND merge_source = 'script'"),
            ("Zwycięzcą złożenie z Fazy 18", "phase9_done = 1 AND merge_source = 'splice'"),
            // `merge_source_path` to BEZWZGLĘDNA ścieżka, z której realnie
            // czytano. Odpowiada na pytanie, którego `merge_source` nie
            // rozstrzygał: czy skopiowano oryginał z korpusu, czy wersję
            // wytworzoną przez Fazę 17/18 w przestrzeni roboczej.
            ("Bajty z przestrzeni roboczej (naprawa/złożenie)", "phase9_done = 1 AND (merge_source_path LIKE '%_phase17_repaired%' OR merge_source_path LIKE '%_smart_splice_repaired%')"),
            ("Bajty wprost z korpusu źródłowego", "phase9_done = 1 AND merge_source_path IS NOT NULL AND merge_source_path NOT LIKE '%_phase17_repaired%' AND merge_source_path NOT LIKE '%_smart_splice_repaired%'"),
        ], None),
    ]
}

fn fetch_phases(conn: &Connection) -> Result<Vec<PhaseDiag>> {
    let mut phases = Vec::new();
    
    let has_files: bool = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='files'", [], |r| r.get::<_, i32>(0)).unwrap_or(0) > 0;
    if !has_files { return Ok(phases); }

    for (id, name, done_cond, metric_defs, anomaly_cond) in phase_definitions() {

        let mut loaded_metrics = Vec::new();
        for (m_name, m_cond) in metric_defs {
            let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM files WHERE {}", m_cond), [], |r| r.get(0)).unwrap_or(0);
            if count > 0 {
                loaded_metrics.push(PhaseMetric { name: m_name.to_string(), cond: m_cond.to_string(), count });
            }
        }

        let mut anomaly_count = 0;
        if let Some(cond) = anomaly_cond {
            anomaly_count = conn.query_row(&format!("SELECT COUNT(*) FROM files WHERE {}", cond), [], |r| r.get(0)).unwrap_or(0);
            if anomaly_count > 0 {
                loaded_metrics.push(PhaseMetric { name: "⚠️ WYKRYTO ANOMALIE (OSIEROCONE DANE)".to_string(), cond: cond.to_string(), count: anomaly_count });
            }
        }

        // Każda faza deklaruje WŁASNY warunek postępu — nie ma już wyjątku
        // "jeśli to Faza 17, licz po kolumnie `id`", który dawał tam liczbę
        // wszystkich plików w bazie zamiast rzeczywistego postępu.
        let done_count = conn.query_row(&format!("SELECT COUNT(*) FROM files WHERE {}", done_cond), [], |r| r.get(0)).unwrap_or(0);

        phases.push(PhaseDiag {
            id, name, metrics: loaded_metrics, done_count, anomaly_count
        });
    }

    Ok(phases)
}

fn fetch_metric_data(conn: &Connection, metric: &PhaseMetric) -> TableData {
    let mut cols = Vec::new();
    let mut rows = Vec::new();
    let mut ufs_top = Vec::new();
    let mut script_top = Vec::new();

    if let Ok(mut stmt) = conn.prepare("PRAGMA table_info(files)") {
        let rows_iter = stmt.query_map([], |row| row.get::<_, String>(1));
        if let Ok(iter) = rows_iter {
            cols = iter.filter_map(|r| r.ok()).collect();
        }
    }

    if let Ok(mut stmt) = conn.prepare(&format!("SELECT * FROM files WHERE {} LIMIT 200", metric.cond)) {
        let col_count = stmt.column_count();
        if let Ok(mut result_rows) = stmt.query([]) {
            while let Ok(Some(row)) = result_rows.next() {
                let mut row_data = Vec::new();
                for i in 0..col_count {
                    let val: rusqlite::types::Value = row.get(i).unwrap_or(rusqlite::types::Value::Null);
                    let raw_str = match val {
                        rusqlite::types::Value::Null => "-".to_string(),
                        rusqlite::types::Value::Integer(v) => v.to_string(),
                        rusqlite::types::Value::Real(v) => format!("{:.2}", v),
                        rusqlite::types::Value::Text(v) => v,
                        rusqlite::types::Value::Blob(_) => "<BIN>".to_string(),
                    };
                    row_data.push(truncate(&raw_str, 20));
                }
                rows.push(row_data);
            }
        }
    }

    if let Ok(mut stmt) = conn.prepare(&format!("SELECT relative_path FROM files WHERE ({}) AND found_in_ufs = 1 LIMIT 5", metric.cond))
        && let Ok(mut r) = stmt.query([]) { while let Ok(Some(row)) = r.next() { ufs_top.push(row.get::<_, String>(0).unwrap_or_default()); } }
    if let Ok(mut stmt) = conn.prepare(&format!("SELECT relative_path FROM files WHERE ({}) AND found_in_script = 1 LIMIT 5", metric.cond))
        && let Ok(mut r) = stmt.query([]) { while let Ok(Some(row)) = r.next() { script_top.push(row.get::<_, String>(0).unwrap_or_default()); } }

    TableData { columns: cols, rows, ufs_top, script_top }
}

// ============================================================================
// GŁÓWNY INTERFEJS RATATUI
// ============================================================================

pub fn run(conn: &Connection) -> Result<()> {
    // Zabezpieczenie terminala
    let _guard = TerminalGuard::acquire().expect("Błąd inicjalizacji trybu graficznego Ratatui");
    
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).expect("Błąd tworzenia backendu Ratatui");

    // Pobieranie danych (bez sztucznych opóźnień)
    let phases = fetch_phases(conn)?;
    let mut app = DiagApp::new(phases);

    loop {
        // Używamy expect zamiast ?, ponieważ błąd rysowania to błąd I/O, a nie błąd bazy danych
        terminal.draw(|f| draw_ui(f, &mut app)).expect("Błąd renderowania interfejsu diagnostycznego");

        if poll(Duration::from_millis(50)).unwrap_or(false)
            && let Ok(Event::Key(key)) = read()
                && key.kind == KeyEventKind::Press {
                    match &mut app.view_state {
                        ViewState::PhaseList => {
                            match key.code {
                                KeyCode::Up => {
                                    let i = match app.phase_list_state.selected() {
                                        Some(i) => if i == 0 { app.phases.len() - 1 } else { i - 1 },
                                        None => 0,
                                    };
                                    app.phase_list_state.select(Some(i));
                                }
                                KeyCode::Down => {
                                    let i = match app.phase_list_state.selected() {
                                        Some(i) => if i >= app.phases.len() - 1 { 0 } else { i + 1 },
                                        None => 0,
                                    };
                                    app.phase_list_state.select(Some(i));
                                }
                                KeyCode::Enter => {
                                    if let Some(idx) = app.phase_list_state.selected()
                                        && !app.phases.is_empty() {
                                            app.status_list_state.select(Some(0));
                                            app.view_state = ViewState::StatusList { phase_idx: idx };
                                        }
                                }
                                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => break, 
                                _ => {}
                            }
                        }
                        ViewState::StatusList { phase_idx } => {
                            let phase = &app.phases[*phase_idx];
                            match key.code {
                                KeyCode::Up => {
                                    let i = match app.status_list_state.selected() {
                                        Some(i) => if i == 0 { phase.metrics.len().saturating_sub(1) } else { i - 1 },
                                        None => 0,
                                    };
                                    app.status_list_state.select(Some(i));
                                }
                                KeyCode::Down => {
                                    let i = match app.status_list_state.selected() {
                                        Some(i) => if i >= phase.metrics.len().saturating_sub(1) { 0 } else { i + 1 },
                                        None => 0,
                                    };
                                    app.status_list_state.select(Some(i));
                                }
                                KeyCode::Enter => {
                                    if let Some(m_idx) = app.status_list_state.selected()
                                        && !phase.metrics.is_empty() {
                                            let metric = phase.metrics[m_idx].clone();
                                            if metric.count > 0 {
                                                let data = fetch_metric_data(conn, &metric);
                                                app.table_state.select(Some(0));
                                                app.view_state = ViewState::DataView { phase_idx: *phase_idx, data };
                                            }
                                        }
                                }
                                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => { 
                                    app.view_state = ViewState::PhaseList; 
                                }
                                _ => {}
                            }
                        }
                        ViewState::DataView { phase_idx, data } => {
                            match key.code {
                                KeyCode::Up => {
                                    let i = match app.table_state.selected() {
                                        Some(i) => if i == 0 { data.rows.len().saturating_sub(1) } else { i - 1 },
                                        None => 0,
                                    };
                                    app.table_state.select(Some(i));
                                }
                                KeyCode::Down => {
                                    let i = match app.table_state.selected() {
                                        Some(i) => if i >= data.rows.len().saturating_sub(1) { 0 } else { i + 1 },
                                        None => 0,
                                    };
                                    app.table_state.select(Some(i));
                                }
                                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => { 
                                    app.view_state = ViewState::StatusList { phase_idx: *phase_idx }; 
                                }
                                _ => {}
                            }
                        }
                    }
                }
    }

    Ok(())
}

// ============================================================================
// RYSOWANIE WIDOKÓW (RATATUI)
// ============================================================================

fn draw_ui(f: &mut Frame, app: &mut DiagApp) {
    let size = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // 0: Tytuł (górna krawędź ramki z tytułem)
            Constraint::Min(10),   // 1: Treść główna
            Constraint::Length(1), // 2: Stopka (instrukcje)
        ])
        .split(size);

    // --- 0: TYTUŁ ---
    // Konwencja spójna z `tui::dashboard`: jednoliniowy obramowany blok w
    // kolorze cyan, z tytułem w formacie " [ emoji ] NAZWA (opis) ". Wcześniej
    // był tu wyśrodkowany paragraf na NIEBIESKIM TLE w ramce o wysokości 3 —
    // jedyny taki element w całej aplikacji.
    let title_block = Block::default()
        .borders(Borders::ALL)
        .title(" [ 🩺 ] CENTRUM DOWODZENIA (Diagnostyka Wszystkich Faz) ")
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(title_block, chunks[0]);

    // MAIN CONTENT
    match &app.view_state {
        ViewState::PhaseList => {
            let items: Vec<ListItem> = app.phases.iter().map(|p| {
                let anom_color = if p.anomaly_count > 0 { Color::Red } else { Color::DarkGray };
                let done_color = if p.done_count > 0 { Color::Green } else { Color::DarkGray };

                let line = Line::from(vec![
                    Span::styled(format!("Faza {:<4}", p.id), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::raw(format!(" | {:<35} | Przetworzono: ", p.name)),
                    Span::styled(format!("{:<10}", p.done_count), Style::default().fg(done_color).add_modifier(Modifier::BOLD)),
                    Span::raw(" | Błędy Systemowe: "),
                    Span::styled(format!("{}", p.anomaly_count), Style::default().fg(anom_color).add_modifier(Modifier::BOLD)),
                ]);
                ListItem::new(line)
            }).collect();

            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)).title(" Wybierz Fazę "))
                .highlight_style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                .highlight_symbol(" ❯ ");

            f.render_stateful_widget(list, chunks[1], &mut app.phase_list_state);

            let footer = Paragraph::new(" [↑/↓] Nawigacja | [ENTER] Wejdź w anomalię | [Q/ESC] Wyjście ")
                .style(Style::default().fg(Color::DarkGray)).alignment(Alignment::Center);
            f.render_widget(footer, chunks[2]);
        }
        ViewState::StatusList { phase_idx } => {
            let phase = &app.phases[*phase_idx];
            
            let items: Vec<ListItem> = phase.metrics.iter().map(|m| {
                let mut metric_color = Color::Cyan;
                if m.name.contains("ANOMALIE") || m.name.contains("ZAINFEKOWANE") || m.name.contains("KOLIZJA")
                    || m.name.contains("USZKODZONE") { metric_color = Color::Red; }
                else if m.name.contains("Biały Szum") || m.name.contains("Zip Bomb") || m.name.contains("Zupa Binarna") { metric_color = Color::Magenta; }
                else if m.name.contains("Zepsute Piksele") || m.name.contains("Frankensteiny") { metric_color = Color::LightRed; }

                let line = Line::from(vec![
                    Span::styled(format!("{:<60}", m.name), Style::default().fg(metric_color).add_modifier(Modifier::BOLD)),
                    Span::raw(" | Ilość plików: "),
                    Span::styled(format!("{}", m.count), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                ]);
                ListItem::new(line)
            }).collect();

            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)).title(format!(" Podgląd metryk: {} ", phase.name)))
                .highlight_style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                .highlight_symbol(" ❯ ");

            f.render_stateful_widget(list, chunks[1], &mut app.status_list_state);

            let footer = Paragraph::new(" [↑/↓] Nawigacja | [ENTER] Wyświetl rekordy | [Q/ESC] Powrót ")
                .style(Style::default().fg(Color::DarkGray)).alignment(Alignment::Center);
            f.render_widget(footer, chunks[2]);
        }
        ViewState::DataView { phase_idx: _, data } => {
            let data_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(5),    // Tabela
                    Constraint::Length(7), // Top 5 list
                ])
                .split(chunks[1]);

            // Tabela
            let header_cells = data.columns.iter().map(|h| Cell::from(h.as_str()).style(Style::default().fg(Color::Cyan)));
            let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD)).bottom_margin(1);

            let rows = data.rows.iter().map(|row_data| {
                let cells = row_data.iter().map(|c| {
                    let color = if c == "-" { Color::DarkGray } else if c.parse::<f64>().is_ok() && c != "0" { Color::Green } else { Color::White };
                    Cell::from(c.as_str()).style(Style::default().fg(color))
                });
                Row::new(cells)
            });

            let widths: Vec<Constraint> = data.columns.iter().map(|_| Constraint::Length(15)).collect();

            let table = Table::new(rows, widths)
                .header(header)
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)).title(" Rekordy Bazy Danych "))
                .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
                .highlight_symbol(">> ");

            f.render_stateful_widget(table, data_chunks[0], &mut app.table_state);

            // Top 5 Listy
            let top_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(data_chunks[1]);

            let ufs_items: Vec<ListItem> = data.ufs_top.iter().enumerate().map(|(i, p)| ListItem::new(format!("{}. {}", i+1, p)).style(Style::default().fg(Color::Cyan))).collect();
            let scr_items: Vec<ListItem> = data.script_top.iter().enumerate().map(|(i, p)| ListItem::new(format!("{}. {}", i+1, p)).style(Style::default().fg(Color::Magenta))).collect();

            let ufs_list = List::new(ufs_items).block(Block::default().borders(Borders::ALL).title(" [ W PRÓBCE (UFS) ] "));
            let scr_list = List::new(scr_items).block(Block::default().borders(Borders::ALL).title(" [ W PRÓBCE (SKRYPT) ] "));

            f.render_widget(ufs_list, top_chunks[0]);
            f.render_widget(scr_list, top_chunks[1]);

            let footer = Paragraph::new(" [↑/↓] Przewijanie tabeli | [Q/ESC] Powrót ")
                .style(Style::default().fg(Color::DarkGray)).alignment(Alignment::Center);
            f.render_widget(footer, chunks[2]);
        }
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Maksymalna szerokość kolumny nazwy fazy na liście (`{:<35}` w
    /// [`draw_ui`]). Dłuższa nazwa rozjeżdża wszystkie kolumny obok.
    const SZEROKOSC_KOLUMNY_NAZWY: usize = 35;

    fn swieza_baza() -> Connection {
        crate::db::init_db(":memory:").expect("inicjalizacja bazy w pamięci")
    }

    /// NAJWAŻNIEJSZY TEST tego modułu: każdy warunek `WHERE` musi być
    /// poprawnym SQL-em wobec REALNEGO schematu bazy.
    ///
    /// `fetch_phases` tłumi błędy zapytań przez `unwrap_or(0)`, więc literówka
    /// albo odwołanie do nieistniejącej kolumny nie wywala aplikacji — po
    /// prostu pokazuje spokojne „0" i metryka jest martwa na zawsze. Ten test
    /// odbiera tłumieniu tę możliwość: sprawdza KAŻDY warunek jawnie.
    #[test]
    fn test_wszystkie_warunki_sa_poprawnym_sql() {
        let conn = swieza_baza();

        for (id, nazwa, warunek_postepu, metryki, warunek_anomalii) in phase_definitions() {
            let mut do_sprawdzenia: Vec<(&str, &str)> = vec![("warunek postępu", warunek_postepu)];
            for (nazwa_metryki, warunek) in &metryki {
                do_sprawdzenia.push((nazwa_metryki, warunek));
            }
            if let Some(w) = warunek_anomalii {
                do_sprawdzenia.push(("warunek anomalii", w));
            }

            for (opis, warunek) in do_sprawdzenia {
                let sql = format!("SELECT COUNT(*) FROM files WHERE {}", warunek);
                let wynik: rusqlite::Result<i64> = conn.query_row(&sql, [], |r| r.get(0));
                assert!(
                    wynik.is_ok(),
                    "Faza {} ({}), {}: niepoprawny SQL\n  warunek: {}\n  błąd: {:?}",
                    id, nazwa, opis, warunek, wynik.err()
                );
            }
        }
    }

    /// REGRESJA: lista kończyła się na Fazie 17, więc diagnostyka w ogóle nie
    /// raportowała Faz 18 i 19, mimo że obie zapisują własne kolumny.
    #[test]
    fn test_lista_zawiera_fazy_18_i_19() {
        let identyfikatory: Vec<&str> = phase_definitions().into_iter().map(|(id, ..)| id).collect();

        assert!(identyfikatory.contains(&"18"), "Brak Fazy 18 (Smart Splice). Mam: {:?}", identyfikatory);
        assert!(identyfikatory.contains(&"19"), "Brak Fazy 19 (Diagnostyka Wideo). Mam: {:?}", identyfikatory);
    }

    /// Kolejność jest chronologiczna wobec przebiegu odzysku: Fazy 17-19
    /// wytwarzają dane, a Faza 9 (Smart Merge) konsumuje je na końcu.
    #[test]
    fn test_smart_merge_zamyka_liste_a_18_19_stoja_po_17() {
        let identyfikatory: Vec<&str> = phase_definitions().into_iter().map(|(id, ..)| id).collect();

        assert_eq!(identyfikatory.last(), Some(&"8/9"), "Smart Merge powinien zamykać listę");

        let poz = |szukany: &str| identyfikatory.iter().position(|x| *x == szukany).expect("faza musi być na liście");
        assert!(poz("17") < poz("18"), "Faza 18 powinna stać po 17");
        assert!(poz("18") < poz("19"), "Faza 19 powinna stać po 18");
        assert!(poz("19") < poz("8/9"), "Smart Merge konsumuje wyniki Faz 17-19, więc idzie po nich");
    }

    /// Spójność WIZUALNA listy faz: nazwa nie może przekroczyć szerokości
    /// kolumny, bo rozjeżdża wszystkie kolumny obok niej.
    #[test]
    fn test_nazwy_faz_mieszcza_sie_w_kolumnie() {
        for (id, nazwa, ..) in phase_definitions() {
            let dlugosc = nazwa.chars().count();
            assert!(
                dlugosc <= SZEROKOSC_KOLUMNY_NAZWY,
                "Faza {}: nazwa ma {} znaków, limit to {} — rozjedzie kolumny listy: \"{}\"",
                id, dlugosc, SZEROKOSC_KOLUMNY_NAZWY, nazwa
            );
        }
    }

    #[test]
    fn test_identyfikatory_faz_sa_unikalne() {
        let mut identyfikatory: Vec<&str> = phase_definitions().into_iter().map(|(id, ..)| id).collect();
        let przed = identyfikatory.len();
        identyfikatory.sort_unstable();
        identyfikatory.dedup();
        assert_eq!(identyfikatory.len(), przed, "Zduplikowany identyfikator fazy na liście diagnostyki");
    }

    #[test]
    fn test_kazda_faza_ma_co_najmniej_jedna_metryke() {
        for (id, nazwa, _, metryki, _) in phase_definitions() {
            assert!(!metryki.is_empty(), "Faza {} ({}) nie ma ani jednej metryki", id, nazwa);
        }
    }

    /// Na świeżej, pustej bazie diagnostyka musi się policzyć bez paniki i bez
    /// błędu — wszystkie liczniki po prostu wychodzą zerowe.
    #[test]
    fn test_fetch_phases_na_pustej_bazie() {
        let conn = swieza_baza();
        let fazy = fetch_phases(&conn).expect("diagnostyka na pustej bazie nie może zwrócić błędu");

        // Metryki o zerowej liczności są celowo pomijane, więc lista faz jest
        // pusta — istotne jest, że nic nie wybuchło.
        for faza in &fazy {
            assert_eq!(faza.done_count, 0, "Faza {} na pustej bazie", faza.id);
            assert_eq!(faza.anomaly_count, 0, "Faza {} na pustej bazie", faza.id);
        }
    }

    /// Postęp Fazy 17 liczy się po fladze `phase17_done` — obejmuje też pliki
    /// PRZETWORZONE, których nie udało się naprawić. Wcześniej liczono po
    /// kolumnie `id`, co pokazywało liczbę WSZYSTKICH plików w bazie.
    #[test]
    fn test_postep_fazy17_liczy_przetworzone_a_nie_wszystkie_pliki() {
        let conn = swieza_baza();
        // Plik nietknięty przez Fazę 17.
        conn.execute("INSERT INTO files (relative_path) VALUES ('a.txt')", []).unwrap();
        // Przetworzony, ale żaden moduł nie pomógł.
        conn.execute("INSERT INTO files (relative_path, phase17_done) VALUES ('b.txt', 1)", []).unwrap();
        // Przetworzony i naprawiony.
        conn.execute(
            "INSERT INTO files (relative_path, phase17_done, repaired_path_ufs) VALUES ('c.jpg', 1, '/praca/zlota_kopia/_phase17_repaired/ufs/c_repaired.jpg')",
            [],
        ).unwrap();

        let fazy = fetch_phases(&conn).unwrap();
        let faza17 = fazy.iter().find(|f| f.id == "17").expect("Faza 17 musi być na liście");

        assert_eq!(faza17.done_count, 2, "Przetworzone = 2 (naprawiony + nienaprawiony), a nie 3 pliki z bazy");

        let naprawione = faza17.metrics.iter()
            .find(|m| m.name.contains("Skutecznie Naprawione"))
            .expect("brak metryki skutecznych napraw");
        assert_eq!(naprawione.count, 1, "Skutecznie naprawiony jest tylko jeden");
    }

    /// Faza 18 rozróżnia „przetworzone" od „udanie złożone" — to dwie różne
    /// informacje śledcze i obie muszą być widoczne.
    #[test]
    fn test_metryki_fazy18_rozdzielaja_sukces_od_proby() {
        let conn = swieza_baza();
        conn.execute(
            "INSERT INTO files (relative_path, phase18_done, smart_splice_path) VALUES ('ok.png', 1, '/praca/zlota_kopia/_smart_splice_repaired/ok_smartsplice.png')",
            [],
        ).unwrap();
        conn.execute("INSERT INTO files (relative_path, phase18_done) VALUES ('proba.png', 1)", []).unwrap();

        let fazy = fetch_phases(&conn).unwrap();
        let faza18 = fazy.iter().find(|f| f.id == "18").expect("Faza 18 musi być na liście");

        assert_eq!(faza18.done_count, 2, "Obie próby są przetworzone");

        let znajdz = |fragment: &str| faza18.metrics.iter()
            .find(|m| m.name.contains(fragment))
            .map(|m| m.count)
            .unwrap_or_else(|| panic!("brak metryki zawierającej \"{}\" w {:?}", fragment, faza18.metrics.iter().map(|m| &m.name).collect::<Vec<_>>()));

        assert_eq!(znajdz("ZWERYFIKOWANE"), 1, "Jedno udane złożenie");
        assert_eq!(znajdz("bez udanego złożenia"), 1, "Jedna próba bez wyniku");
    }

    /// Faza 19 musi raportować uszkodzone wideo — to jej główny produkt.
    #[test]
    fn test_metryki_fazy19_raportuja_uszkodzone_wideo() {
        let conn = swieza_baza();
        conn.execute("INSERT INTO files (relative_path, phase19_done, video_ok_ufs) VALUES ('zdrowy.mp4', 1, 1)", []).unwrap();
        conn.execute(
            "INSERT INTO files (relative_path, phase19_done, video_ok_ufs, video_reason_ufs) VALUES ('zly.mp4', 1, 0, 'Ucięty box moov')",
            [],
        ).unwrap();

        let fazy = fetch_phases(&conn).unwrap();
        let faza19 = fazy.iter().find(|f| f.id == "19").expect("Faza 19 musi być na liście");

        let uszkodzone = faza19.metrics.iter().find(|m| m.name.contains("USZKODZONE")).expect("brak metryki uszkodzonego wideo");
        assert_eq!(uszkodzone.count, 1);

        let sprawne = faza19.metrics.iter().find(|m| m.name.contains("Sprawne")).expect("brak metryki sprawnego wideo");
        assert_eq!(sprawne.count, 1);
    }

    // ------------------------------------------------------------------
    // SPÓJNOŚĆ WIZUALNA — render do bufora (ratatui TestBackend)
    //
    // Konwencja całej aplikacji (patrz `tui::dashboard`): tytuł to
    // JEDNOLINIOWY obramowany blok w kolorze cyan, a stopka to
    // JEDNOLINIOWY paragraf BEZ ramki. Ekran diagnostyczny miał wcześniej
    // tytuł na niebieskim tle w ramce o wysokości 3 i stopkę w ramce —
    // jedyne takie elementy w programie.
    // ------------------------------------------------------------------

    use ratatui::backend::TestBackend;

    fn wiersz(bufor: &ratatui::buffer::Buffer, y: u16) -> String {
        (0..bufor.area.width).map(|x| bufor[(x, y)].symbol()).collect()
    }

    fn wyrenderuj(szerokosc: u16, wysokosc: u16) -> ratatui::buffer::Buffer {
        let fazy = vec![
            PhaseDiag { id: "18", name: "Smart Splice (Składanie z 2 kopii)", metrics: vec![], done_count: 7, anomaly_count: 0 },
            PhaseDiag { id: "19", name: "Diagnostyka Wideo (MP4/MKV/TS/FLV)", metrics: vec![], done_count: 3, anomaly_count: 2 },
        ];
        let mut app = DiagApp::new(fazy);
        let mut terminal = Terminal::new(TestBackend::new(szerokosc, wysokosc)).unwrap();
        terminal.draw(|f| draw_ui(f, &mut app)).unwrap();
        terminal.backend().buffer().clone()
    }

    #[test]
    fn test_tytul_jest_jednoliniowa_ramka_w_konwencji_aplikacji() {
        let bufor = wyrenderuj(120, 20);
        let gora = wiersz(&bufor, 0);

        assert!(gora.starts_with('\u{250c}'), "Tytuł musi być górną krawędzią ramki (jak w dashboardzie), mam: {:?}", &gora[..12.min(gora.len())]);
        assert!(gora.contains("CENTRUM DOWODZENIA"), "Brak tytułu w pierwszym wierszu: {}", gora);

        // Wiersz 1 to już treść główna, a nie dalsza część nagłówka —
        // dowód, że nagłówek zajmuje DOKŁADNIE jedną linię.
        let drugi = wiersz(&bufor, 1);
        assert!(drugi.contains("Wybierz Fazę"), "Treść powinna zaczynać się w wierszu 1, mam: {}", drugi);
    }

    #[test]
    fn test_stopka_jest_bez_ramki_i_jednoliniowa() {
        let bufor = wyrenderuj(120, 20);
        let ostatni = wiersz(&bufor, 19);

        assert!(ostatni.contains("[Q/ESC]"), "Stopka powinna być w ostatnim wierszu: {}", ostatni);
        assert!(
            !ostatni.contains('\u{2502}') && !ostatni.contains('\u{2514}'),
            "Stopka nie może mieć ramki (konwencja aplikacji), mam: {}", ostatni
        );
    }

    #[test]
    fn test_lista_faz_ma_wyrownane_kolumny() {
        let bufor = wyrenderuj(120, 20);

        // Obie fazy mają nazwy różnej długości, ale kolumna "Przetworzono"
        // musi zaczynać się w tej samej pozycji w obu wierszach.
        let a = wiersz(&bufor, 2);
        let b = wiersz(&bufor, 3);

        // UWAGA: pozycję liczymy w ZNAKACH, nie w bajtach. `str::find` zwraca
        // offset bajtowy, a wiersze różnią się liczbą znaków wielobajtowych
        // (symbol zaznaczenia „❯" to 3 bajty, „ł" w „Składanie" to 2) — przez
        // co wyrównane wizualnie kolumny dawały różne offsety bajtowe.
        let pozycja_w_znakach = |w: &str| -> usize {
            let bajt = w.find("Przetworzono:").unwrap_or_else(|| panic!("brak kolumny w wierszu: {}", w));
            w[..bajt].chars().count()
        };

        assert_eq!(
            pozycja_w_znakach(&a), pozycja_w_znakach(&b),
            "Kolumny rozjechały się:\n{}\n{}", a, b
        );
    }

    /// Zrzuca CAŁY wyrenderowany ekran diagnostyczny na standardowe wyjście —
    /// do oglądania układu bez uruchamiania aplikacji i podłączania terminala.
    ///
    /// Uruchomienie:
    /// `cargo test --bin weryfikator podglad_ekranu -- --ignored --nocapture`
    ///
    /// `#[ignore]` bo to narzędzie podglądowe, nie asercja — wzorzec zgodny z
    /// pozostałymi testami projektu wymagającymi świadomego uruchomienia.
    #[test]
    #[ignore = "Narzędzie podglądowe: zrzuca układ ekranu. Uruchom z --ignored --nocapture."]
    fn podglad_ekranu_diagnostyki() {
        let conn = swieza_baza();
        conn.execute_batch("
            INSERT INTO files (relative_path, phase1_done, found_in_ufs, found_in_script) VALUES ('foto/a.jpg', 1, 1, 1);
            INSERT INTO files (relative_path, phase1_done, found_in_ufs, found_in_script) VALUES ('foto/b.jpg', 1, 1, 0);
            INSERT INTO files (relative_path, phase16_done, yara_match_ufs) VALUES ('trojan.exe', 1, 'Win32_Generic');
            INSERT INTO files (relative_path, repaired_path_ufs) VALUES ('skan.png', '/praca/zlota_kopia/_phase17_repaired/ufs/skan_repaired.png');
            INSERT INTO files (relative_path, phase18_done, smart_splice_path) VALUES ('klip.png', 1, '/praca/zlota_kopia/_smart_splice_repaired/klip_smartsplice.png');
            INSERT INTO files (relative_path, phase18_done) VALUES ('inny.png', 1);
            INSERT INTO files (relative_path, phase19_done, video_ok_ufs, video_duration_ms_ufs, video_tracks_ufs) VALUES ('film.mp4', 1, 1, 42000, 2);
            INSERT INTO files (relative_path, phase19_done, video_ok_ufs, video_reason_ufs) VALUES ('urwany.mp4', 1, 0, 'Uciety box moov');
            INSERT INTO files (relative_path, phase9_done, merge_success, merge_source) VALUES ('gotowe.jpg', 1, 1, 'splice');
        ").unwrap();

        let fazy = fetch_phases(&conn).expect("diagnostyka");
        let mut app = DiagApp::new(fazy);

        let mut terminal = Terminal::new(TestBackend::new(120, 26)).unwrap();
        terminal.draw(|f| draw_ui(f, &mut app)).unwrap();
        let bufor = terminal.backend().buffer().clone();

        println!();
        for y in 0..bufor.area.height {
            println!("{}", wiersz(&bufor, y));
        }
        println!();
    }

    /// Znacznik czasu z `mvhd` to niezależne od EXIF źródło daty nagrania —
    /// musi być widoczny w diagnostyce, inaczej nowa kolumna nikomu nie służy.
    #[test]
    fn test_metryka_czasu_utworzenia_z_mvhd() {
        let conn = swieza_baza();
        conn.execute(
            "INSERT INTO files (relative_path, phase19_done, video_ok_ufs, video_created_unix)
             VALUES ('film.mp4', 1, 1, 1669712412)", []).unwrap();
        conn.execute(
            "INSERT INTO files (relative_path, phase19_done, video_ok_ufs) VALUES ('bez_czasu.mp4', 1, 1)", []).unwrap();

        let fazy = fetch_phases(&conn).unwrap();
        let faza19 = fazy.iter().find(|f| f.id == "19").expect("Faza 19 musi być na liście");

        let metryka = faza19.metrics.iter()
            .find(|m| m.name.contains("czas utworzenia"))
            .expect("brak metryki czasu utworzenia");
        assert_eq!(metryka.count, 1, "tylko jeden plik ma odczytany znacznik z mvhd");
    }
}
