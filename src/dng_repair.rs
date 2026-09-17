// src/dng_repair.rs

//! # Logika Narzędzia: Składanie Strukturalne DNG (Pełne Ratatui)
//!
//! Zastępuje dawny CLI (`dialoguer`) pełnoekranowym widokiem Ratatui, spójnym
//! z resztą aplikacji. Ten plik zawiera WYŁĄCZNIE logikę (stan, dostęp do
//! bazy/dysku, decyzje) — zero kodu rysującego, ten żyje w
//! `tui::dng_repair_screen`.
//!
//! ## Fizyczne porównanie obu lokacji
//! Dla każdego kwalifikującego się pliku [`compute_candidates`] czyta
//! NAPRAWDĘ oba fizyczne pliki (`ufs_base/<rel_path>` i
//! `script_base/<rel_path>`) i próbuje je złożyć przez
//! `dng_splice::structural_splice_files` — to realne czytanie i łączenie
//! zawartości obu kopii, nie porównanie samych metadanych z bazy.
//!
//! ## Przypomnienie kluczowego ograniczenia (patrz `dng_splice`)
//! Udane dekodowanie kandydata potwierdza WYŁĄCZNIE poprawność struktury
//! (nagłówek/IFD), NIGDY treści pikseli. Dlatego nawet tryb automatyczny
//! (oparty o entropię przeniesionych danych) jest jedynie plauzybilnością,
//! nie dowodem — patrz [`DisplayCandidate::plausible`].

use crate::dng_splice;
use crate::raw_image;
use rusqlite::{params, Connection, Result};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// DANE
// ============================================================================

/// Jeden plik do przejrzenia — identyfikator DB + ścieżka względna.
#[derive(Clone, Debug)]
pub struct ReviewTask {
    pub id: i32,
    pub rel_path: String,
}

/// Jeden kandydat złożenia GOTOWY DO WYŚWIETLENIA — już zdekodowany (inaczej
/// w ogóle by tu nie trafił, patrz [`compute_candidates`]), z policzoną
/// plauzybilnością na podstawie entropii przeniesionych danych.
#[derive(Clone)]
pub struct DisplayCandidate {
    pub bytes: Vec<u8>,
    pub description: String,
    pub confidence: dng_splice::SpliceConfidence,
    pub entropy: f64,
    pub plausible: bool,
    pub width: usize,
    pub height: usize,
    pub camera_model: Option<String>,
}

/// Pobiera listę plików kwalifikujących się do przeglądu — pliki WSPÓLNE
/// (obecne po obu stronach), format DNG, obie strony nie zdekodowały się
/// poprawnie w Fazie 13, jeszcze nieprzejrzane w tym narzędziu.
pub fn fetch_review_tasks(conn: &Connection) -> Result<Vec<ReviewTask>> {
    let _ = conn.execute("ALTER TABLE files ADD COLUMN dng_structural_status TEXT", []);
    let mut stmt = conn.prepare(
        "SELECT id, relative_path FROM files
         WHERE found_in_ufs = 1 AND found_in_script = 1
           AND LOWER(relative_path) LIKE '%.dng'
           AND (media_decoded_ufs = 0 OR media_decoded_ufs IS NULL OR pixels_ok_ufs = 0)
           AND (media_decoded_script = 0 OR media_decoded_script IS NULL OR pixels_ok_script = 0)
           AND dng_structural_status IS NULL"
    )?;
    let tasks = stmt.query_map([], |row| {
        Ok(ReviewTask { id: row.get(0)?, rel_path: row.get(1)? })
    })?.filter_map(|r| r.ok()).collect();
    Ok(tasks)
}

/// Wczytuje NAPRAWDĘ obie fizyczne kopie źródłowe (UFS Explorer + Skrypt
/// Autorski) dla danego pliku, składa strukturalnie w obu kierunkach i
/// zwraca TYLKO kandydatów, którzy faktycznie się zdekodowali — kandydaci
/// nieudani są tu odfiltrowywani, użytkownik nigdy ich nie widzi.
pub fn compute_candidates(task: &ReviewTask, ufs_base: &Path, script_base: &Path) -> Vec<DisplayCandidate> {
    let path_a = ufs_base.join(&task.rel_path);
    let path_b = script_base.join(&task.rel_path);

    let Ok(candidates) = dng_splice::structural_splice_files(&path_a, &path_b) else { return Vec::new(); };

    candidates.into_iter().filter_map(|c| {
        let info = raw_image::decode_raw_bytes(&c.bytes)?;
        Some(DisplayCandidate {
            plausible: dng_splice::looks_like_plausible_sensor_data(c.donated_data_entropy),
            entropy: c.donated_data_entropy,
            width: info.width,
            height: info.height,
            camera_model: info.camera_model,
            confidence: c.confidence,
            bytes: c.bytes,
            description: c.description,
        })
    }).collect()
}

/// Buduje nazwę pliku wynikowego, unikalną per PEŁNA ścieżka źródłowa — nie
/// tylko jej `file_stem()`. Ten sam wzorzec co Faza 18
/// (`phase18_smart_splice::unikalna_nazwa_wyniku`): hash pełnej `rel_path`
/// dopisany do czytelnego dla człowieka trzonu nazwy.
///
/// REGRESJA (todo.dng_archive_repair.md, Ustalenie 2): poprzednia wersja
/// budowała nazwę WYŁĄCZNIE z `file_stem()`, zapisując do JEDNEGO, płaskiego
/// katalogu wspólnego dla CAŁEGO korpusu (`target_path/_dng_structural_review`,
/// patrz `menu::actions`). Dwa pliki o tej samej nazwie bazowej z różnych
/// podkatalogów źródłowych (typowy układ przy konsolidacji wielu kart/
/// folderów DCIM w jeden korpus odzysku — dokładnie scenariusz, dla którego
/// Faza 18 dostała tę samą poprawkę) dawały IDENTYCZNĄ nazwę docelową — drugi
/// zaakceptowany kandydat cicho nadpisywał bajty pierwszego, a OBA wiersze
/// bazy wskazywały na tę samą ścieżkę (`dng_structural_path`), mimo że
/// fizycznie zawierała tylko jednego z dwóch plików. Operator otwierający
/// "zweryfikowaną rekonstrukcję" pierwszego pliku dostawał w rzeczywistości
/// bajty zupełnie innego pliku źródłowego.
fn unikalna_nazwa_wyniku(rel_path: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    rel_path.hash(&mut hasher);
    let hash = hasher.finish();
    let stem = Path::new(rel_path).file_stem().and_then(|s| s.to_str()).unwrap_or("plik");
    format!("{}_{:016x}_dngsplice.dng", stem, hash)
}

/// Zapisuje zaakceptowanego kandydata do katalogu przeglądowego (NIGDY do
/// Złotej Kopii bezpośrednio) i aktualizuje status w bazie — `accepted` dla
/// decyzji ręcznej, `accepted_auto` dla trybu automatycznego (rozróżnialne
/// w danych, nie ukryte).
///
/// Razem ze statusem zapisywana jest **ścieżka wytworzonego pliku**
/// (`dng_structural_path`). Bez niej sprzątanie przestrzeni roboczej widziało
/// pliki w `_dng_structural_review`, ale nie potrafiło ich powiązać z żadnym
/// rekordem, więc musiało traktować cały katalog jako nieśledzony i tylko
/// raportować jego zajętość — patrz [`crate::workspace_cleanup`]. Ścieżka jest
/// **absolutna**, bo tak samo zapisują ją Faza 17 i Faza 18 i tak porównuje je
/// sprzątanie.
pub fn accept_candidate(conn: &Connection, task: &ReviewTask, candidate: &DisplayCandidate, target_base: &Path, auto: bool) -> std::io::Result<PathBuf> {
    let target_path = target_base.join(unikalna_nazwa_wyniku(&task.rel_path));
    if let Some(parent) = target_path.parent() { fs::create_dir_all(parent)?; }
    fs::write(&target_path, &candidate.bytes)?;
    let status = if auto { "accepted_auto" } else { "accepted" };
    let _ = conn.execute(
        "UPDATE files SET dng_structural_status = ?1, dng_structural_path = ?2 WHERE id = ?3",
        params![status, target_path.to_string_lossy().to_string(), task.id],
    );
    Ok(target_path)
}

/// Oznacza plik jako pominięty (bez zapisu na dysk) — `status` rozróżnia
/// powód: `"skipped"` (ręcznie odrzucony), `"skipped_auto"` (auto-tryb
/// uznał wszystkich kandydatów za niewystarczająco plauzybilnych),
/// `"unparseable"` (żadna strona nie ma odczytywalnej struktury TIFF/IFD).
pub fn mark_status(conn: &Connection, task: &ReviewTask, status: &str) {
    let _ = conn.execute("UPDATE files SET dng_structural_status = ?1 WHERE id = ?2", params![status, task.id]);
}

/// Otwiera (w trybie dopisywania) plik dziennika decyzji, zapisując nagłówek
/// nowej sesji ze znacznikiem czasu i trybem pracy.
pub fn open_decision_log(target_base: &Path, auto_mode: bool) -> Option<(File, PathBuf)> {
    let _ = fs::create_dir_all(target_base);
    let log_path = target_base.join("dziennik_decyzji.txt");
    let mut f = fs::OpenOptions::new().create(true).append(true).open(&log_path).ok()?;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let _ = writeln!(f, "\n=== Sesja (unix ts {}) - tryb: {} ===", ts, if auto_mode { "AUTOMATYCZNY (entropia)" } else { "RĘCZNY" });
    Some((f, log_path))
}

pub fn log_decision(log_file: &mut Option<File>, rel_path: &str, description: &str, entropy: f64, plausible: bool, accepted: bool) {
    if let Some(f) = log_file.as_mut() {
        let _ = writeln!(f, "{} | {} | entropia={:.3} | plauzybilne={} | decyzja={}",
            rel_path, description, entropy, plausible, if accepted { "AKCEPTUJ" } else { "POMIŃ" });
    }
}

// ============================================================================
// STAN EKRANU (RATATUI)
// ============================================================================

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    /// Ekran wyboru trybu pracy (Ręczny / Automatyczny).
    #[allow(clippy::enum_variant_names)]
    ChooseMode,
    /// Przegląd ręczny — jeden plik na raz, użytkownik decyduje.
    Reviewing,
    /// Przebieg automatyczny — jeden plik na "tykacz" pętli zdarzeń,
    /// decyzja wg [`DisplayCandidate::plausible`], bez pytania.
    AutoRunning,
    /// Zakończono (wyczerpano listę albo użytkownik przerwał) — ekran
    /// podsumowania, Enter/Esc wraca do podmenu.
    Done,
}

pub struct DngRepairState {
    pub mode: Mode,
    pub mode_selection: usize, // 0 = Ręczny, 1 = Automatyczny (na ekranie ChooseMode)
    pub tasks: Vec<ReviewTask>,
    pub current_task_idx: usize,
    pub current_candidates: Vec<DisplayCandidate>,
    pub current_candidate_idx: usize,
    pub accepted_count: usize,
    pub skipped_count: usize,
    pub auto_mode: bool,
    pub log_path: Option<PathBuf>,
    pub should_exit: bool,
}

impl DngRepairState {
    pub fn new(tasks: Vec<ReviewTask>) -> Self {
        Self {
            mode: Mode::ChooseMode,
            mode_selection: 0,
            tasks,
            current_task_idx: 0,
            current_candidates: Vec::new(),
            current_candidate_idx: 0,
            accepted_count: 0,
            skipped_count: 0,
            auto_mode: false,
            log_path: None,
            should_exit: false,
        }
    }

    pub fn current_task(&self) -> Option<&ReviewTask> {
        self.tasks.get(self.current_task_idx)
    }

    pub fn current_candidate(&self) -> Option<&DisplayCandidate> {
        self.current_candidates.get(self.current_candidate_idx)
    }
}

/// Kontekst wołań I/O (ścieżki bazowe) — grupowane, żeby nie przeciągać
/// czterech osobnych parametrów przez każdą funkcję obsługi klawiszy.
pub struct RepairPaths {
    pub ufs_base: PathBuf,
    pub script_base: PathBuf,
    pub target_base: PathBuf,
}

/// Ładuje kandydatów dla BIEŻĄCEGO zadania do stanu. Gdy lista kandydatów
/// wychodzi pusta (żadna kombinacja się nie zdekodowała), automatycznie
/// oznacza plik jako `unparseable`/`skipped` w bazie i PRZECHODZI DALEJ
/// rekurencyjnie, aż znajdzie plik z co najmniej jednym kandydatem albo
/// wyczerpie listę (-> [`Mode::Done`]).
pub fn load_current_or_advance(state: &mut DngRepairState, conn: &Connection, paths: &RepairPaths, log_file: &mut Option<File>) {
    loop {
        let Some(task) = state.current_task().cloned() else {
            state.mode = Mode::Done;
            return;
        };

        let candidates = compute_candidates(&task, &paths.ufs_base, &paths.script_base);
        if candidates.is_empty() {
            mark_status(conn, &task, "unparseable");
            state.skipped_count += 1;
            log_decision(log_file, &task.rel_path, "(brak kandydatów)", 0.0, false, false);
            state.current_task_idx += 1;
            continue;
        }

        state.current_candidates = candidates;
        state.current_candidate_idx = 0;
        return;
    }
}

/// Przechodzi do KOLEJNEGO pliku (po decyzji o bieżącym) i ładuje jego
/// kandydatów (albo pomija automatycznie, patrz [`load_current_or_advance`]).
pub fn advance_to_next_task(state: &mut DngRepairState, conn: &Connection, paths: &RepairPaths, log_file: &mut Option<File>) {
    state.current_task_idx += 1;
    load_current_or_advance(state, conn, paths, log_file);
}

// ============================================================================
// OBSŁUGA KLAWISZY
// ============================================================================

use crossterm::event::{KeyCode, KeyEvent};

/// Główny punkt wejścia obsługi klawiatury — deleguje wg `state.mode`.
pub fn handle_key(key: KeyEvent, state: &mut DngRepairState, conn: &Connection, paths: &RepairPaths, log_file: &mut Option<File>) {
    match state.mode {
        Mode::ChooseMode => handle_choose_mode_key(key, state, conn, paths, log_file),
        Mode::Reviewing => handle_reviewing_key(key, state, conn, paths, log_file),
        Mode::AutoRunning => handle_auto_running_key(key, state),
        Mode::Done => handle_done_key(key, state),
    }
}

fn handle_choose_mode_key(key: KeyEvent, state: &mut DngRepairState, conn: &Connection, paths: &RepairPaths, log_file: &mut Option<File>) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => { state.mode_selection = if state.mode_selection == 0 { 1 } else { 0 }; }
        KeyCode::Down | KeyCode::Char('j') => { state.mode_selection = (state.mode_selection + 1) % 2; }
        KeyCode::Esc => { state.should_exit = true; }
        KeyCode::Enter => {
            state.auto_mode = state.mode_selection == 1;
            let (f, path) = open_decision_log(&paths.target_base, state.auto_mode).unzip();
            *log_file = f;
            state.log_path = path;
            state.mode = if state.auto_mode { Mode::AutoRunning } else { Mode::Reviewing };
            load_current_or_advance(state, conn, paths, log_file);
        }
        _ => {}
    }
}

fn handle_reviewing_key(key: KeyEvent, state: &mut DngRepairState, conn: &Connection, paths: &RepairPaths, log_file: &mut Option<File>) {
    match key.code {
        KeyCode::Esc => { state.mode = Mode::Done; }
        // Przełączanie między kandydatami (gdy plik ma więcej niż jednego)
        KeyCode::Left | KeyCode::Char('h') => {
            if !state.current_candidates.is_empty() {
                state.current_candidate_idx = if state.current_candidate_idx == 0 { state.current_candidates.len() - 1 } else { state.current_candidate_idx - 1 };
            }
        }
        KeyCode::Right | KeyCode::Char('l') => {
            if !state.current_candidates.is_empty() {
                state.current_candidate_idx = (state.current_candidate_idx + 1) % state.current_candidates.len();
            }
        }
        // Akceptacja bieżącego kandydata
        KeyCode::Char('a') | KeyCode::Char('A') => {
            if let (Some(task), Some(candidate)) = (state.current_task().cloned(), state.current_candidate().cloned())
                && accept_candidate(conn, &task, &candidate, &paths.target_base, false).is_ok() {
                    state.accepted_count += 1;
                    log_decision(log_file, &task.rel_path, &candidate.description, candidate.entropy, candidate.plausible, true);
                    advance_to_next_task(state, conn, paths, log_file);
                }
        }
        // Pominięcie CAŁEGO pliku (żaden kandydat nie odpowiada)
        KeyCode::Char('p') | KeyCode::Char('P') | KeyCode::Char('n') | KeyCode::Char('N') => {
            if let Some(task) = state.current_task().cloned() {
                mark_status(conn, &task, "skipped");
                state.skipped_count += 1;
                if let Some(candidate) = state.current_candidate() {
                    log_decision(log_file, &task.rel_path, &candidate.description, candidate.entropy, candidate.plausible, false);
                }
                advance_to_next_task(state, conn, paths, log_file);
            }
        }
        _ => {}
    }
}

fn handle_auto_running_key(key: KeyEvent, state: &mut DngRepairState) {
    // Jedyna interakcja w trybie automatycznym to możliwość przerwania -
    // sam postęp napędzany jest przez `advance_auto_tick`, wołane co klatkę
    // pętli zdarzeń niezależnie od naciśnięcia klawisza.
    if key.code == KeyCode::Esc {
        state.mode = Mode::Done;
    }
}

fn handle_done_key(key: KeyEvent, state: &mut DngRepairState) {
    if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
        state.should_exit = true;
    }
}

/// Przetwarza JEDEN plik w trybie automatycznym — wołane raz na "klatkę"
/// pętli zdarzeń (nie czeka na klawisz), żeby ekran mógł się odświeżać w
/// trakcie długiego przebiegu i pokazywać żywy postęp. Decyzja: akceptuje
/// PIERWSZEGO kandydata uznanego za plauzybilnego (patrz
/// [`DisplayCandidate::plausible`]), inaczej pomija cały plik.
pub fn advance_auto_tick(state: &mut DngRepairState, conn: &Connection, paths: &RepairPaths, log_file: &mut Option<File>) {
    if state.mode != Mode::AutoRunning { return; }

    let Some(task) = state.current_task().cloned() else {
        state.mode = Mode::Done;
        return;
    };

    let accepted_candidate = state.current_candidates.iter().find(|c| c.plausible).cloned();
    match accepted_candidate {
        Some(candidate) => {
            if accept_candidate(conn, &task, &candidate, &paths.target_base, true).is_ok() {
                state.accepted_count += 1;
                log_decision(log_file, &task.rel_path, &candidate.description, candidate.entropy, candidate.plausible, true);
            } else {
                mark_status(conn, &task, "io_error");
                state.skipped_count += 1;
            }
        }
        None => {
            mark_status(conn, &task, "skipped_auto");
            state.skipped_count += 1;
            if let Some(candidate) = state.current_candidates.first() {
                log_decision(log_file, &task.rel_path, &candidate.description, candidate.entropy, candidate.plausible, false);
            }
        }
    }

    advance_to_next_task(state, conn, paths, log_file);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent};

    fn baza() -> Connection {
        crate::db::init_db(":memory:").unwrap()
    }

    /// Wstawia plik w stanie, w jakim zostawia go Faza 13: obecny po obu
    /// stronach, żadna kopia nie zdekodowała pikseli.
    fn wstaw_kandydata_do_przegladu(conn: &Connection, id: i32, sciezka: &str) {
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script,
                                media_decoded_ufs, media_decoded_script, pixels_ok_ufs, pixels_ok_script)
             VALUES (?1, ?2, 1, 1, 0, 0, 0, 0)",
            params![id, sciezka],
        ).unwrap();
    }

    fn kandydat(opis: &str, entropia: f64, plauzybilny: bool) -> DisplayCandidate {
        DisplayCandidate {
            bytes: vec![0xAB; 256],
            description: opis.to_string(),
            confidence: dng_splice::SpliceConfidence::StructuralOnly,
            entropy: entropia,
            plausible: plauzybilny,
            width: 4000,
            height: 3000,
            camera_model: Some("TEST".to_string()),
        }
    }

    fn sciezki(katalog: &Path) -> RepairPaths {
        RepairPaths {
            ufs_base: katalog.join("ufs"),
            script_base: katalog.join("script"),
            target_base: katalog.join("_dng_structural_review"),
        }
    }

    fn klawisz(kod: KeyCode) -> KeyEvent {
        KeyEvent::from(kod)
    }

    // ------------------------------------------------------------------
    // Kwalifikacja do przeglądu — decyduje, co w ogóle trafi przed operatora
    // ------------------------------------------------------------------

    #[test]
    fn test_do_przegladu_trafia_plik_nieodczytany_po_obu_stronach() {
        let conn = baza();
        wstaw_kandydata_do_przegladu(&conn, 1, "zdjecia/DSC_1.dng");

        let zadania = fetch_review_tasks(&conn).unwrap();
        assert_eq!(zadania.len(), 1);
        assert_eq!(zadania[0].rel_path, "zdjecia/DSC_1.dng");
    }

    /// Składanie strukturalne wymaga DWÓCH kopii — plik obecny tylko po jednej
    /// stronie nie ma z czym być składany.
    #[test]
    fn test_plik_tylko_z_jednego_zrodla_nie_trafia_do_przegladu() {
        let conn = baza();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script, media_decoded_ufs, pixels_ok_ufs)
             VALUES (1, 'a.dng', 1, 0, 0, 0)", [],
        ).unwrap();

        assert!(fetch_review_tasks(&conn).unwrap().is_empty());
    }

    /// Gdy którakolwiek kopia zdekodowała się poprawnie, nie ma czego
    /// naprawiać — Faza 9 po prostu wybierze tę zdrową.
    #[test]
    fn test_plik_z_jedna_zdrowa_kopia_nie_trafia_do_przegladu() {
        let conn = baza();
        conn.execute(
            "INSERT INTO files (id, relative_path, found_in_ufs, found_in_script,
                                media_decoded_ufs, pixels_ok_ufs, media_decoded_script, pixels_ok_script)
             VALUES (1, 'a.dng', 1, 1, 1, 1, 0, 0)", [],
        ).unwrap();

        assert!(
            fetch_review_tasks(&conn).unwrap().is_empty(),
            "zdrowa kopia po stronie UFS wyklucza plik z przeglądu"
        );
    }

    #[test]
    fn test_inne_formaty_nie_trafiaja_do_przegladu() {
        let conn = baza();
        for (id, nazwa) in [(1, "a.jpg"), (2, "b.nef"), (3, "c.cr2"), (4, "d.png")] {
            wstaw_kandydata_do_przegladu(&conn, id, nazwa);
        }

        assert!(
            fetch_review_tasks(&conn).unwrap().is_empty(),
            "narzędzie obsługuje wyłącznie .dng - patrz ograniczenie silnika"
        );
    }

    #[test]
    fn test_rozszerzenie_dng_rozpoznawane_niezaleznie_od_wielkosci_liter() {
        let conn = baza();
        wstaw_kandydata_do_przegladu(&conn, 1, "ZDJECIA/DSC_2.DNG");

        assert_eq!(fetch_review_tasks(&conn).unwrap().len(), 1, "odzyskane nazwy bywają wielkimi literami");
    }

    /// Plik już rozstrzygnięty nie może wrócić do kolejki — inaczej operator
    /// oglądałby w kółko to samo.
    #[test]
    fn test_plik_z_ustawionym_statusem_nie_wraca_do_przegladu() {
        let conn = baza();
        wstaw_kandydata_do_przegladu(&conn, 1, "a.dng");

        for status in ["accepted", "accepted_auto", "skipped", "skipped_auto", "unparseable"] {
            conn.execute("UPDATE files SET dng_structural_status = ?1 WHERE id = 1", params![status]).unwrap();
            assert!(
                fetch_review_tasks(&conn).unwrap().is_empty(),
                "status '{}' musi wykluczać plik z ponownego przeglądu", status
            );
        }
    }

    // ------------------------------------------------------------------
    // Zapis statusu i dziennik decyzji
    // ------------------------------------------------------------------

    #[test]
    fn test_status_rozroznia_decyzje_reczna_od_automatycznej() {
        let dir = tempfile::tempdir().unwrap();
        let conn = baza();
        wstaw_kandydata_do_przegladu(&conn, 1, "a.dng");
        let zadanie = ReviewTask { id: 1, rel_path: "a.dng".to_string() };

        accept_candidate(&conn, &zadanie, &kandydat("ręcznie", 5.0, true), dir.path(), false).unwrap();
        let reczny: String = conn.query_row("SELECT dng_structural_status FROM files WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(reczny, "accepted", "decyzja operatora musi być rozróżnialna w danych");

        accept_candidate(&conn, &zadanie, &kandydat("automat", 5.0, true), dir.path(), true).unwrap();
        let auto: String = conn.query_row("SELECT dng_structural_status FROM files WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(auto, "accepted_auto");
    }

    #[test]
    fn test_dziennik_decyzji_zapisuje_entropie_i_werdykt() {
        let dir = tempfile::tempdir().unwrap();
        let (plik, sciezka) = open_decision_log(dir.path(), true).expect("dziennik musi się otworzyć");
        let mut plik = Some(plik);

        log_decision(&mut plik, "zdjecia/a.dng", "Nagłówek A + dane B", 5.1619, true, true);
        log_decision(&mut plik, "zdjecia/b.dng", "Nagłówek B + dane A", 0.2, false, false);
        drop(plik);

        let tresc = std::fs::read_to_string(&sciezka).unwrap();
        assert!(tresc.contains("zdjecia/a.dng") && tresc.contains("zdjecia/b.dng"), "obie decyzje w dzienniku:\n{}", tresc);
        assert!(tresc.contains("5.16"), "entropia musi zostać odnotowana:\n{}", tresc);
        assert!(tresc.contains("AKCEPTUJ") && tresc.contains("POMIŃ"), "werdykt musi być jawny:\n{}", tresc);
    }

    #[test]
    fn test_brak_dziennika_nie_wywraca_logowania() {
        // Gdy pliku dziennika nie udało się otworzyć, decyzje nadal muszą
        // przechodzić - dziennik jest dodatkiem, nie warunkiem pracy.
        let mut brak: Option<File> = None;
        log_decision(&mut brak, "a.dng", "opis", 1.0, false, true);
    }

    // ------------------------------------------------------------------
    // Maszyna stanów ekranu
    // ------------------------------------------------------------------

    fn stan_i_baza(zadania: Vec<ReviewTask>) -> (DngRepairState, Connection) {
        (DngRepairState::new(zadania), baza())
    }

    #[test]
    fn test_nowy_stan_zaczyna_od_wyboru_trybu() {
        let stan = DngRepairState::new(Vec::new());
        assert_eq!(stan.mode, Mode::ChooseMode);
        assert_eq!(stan.mode_selection, 0, "domyślnie tryb ręczny");
        assert!(!stan.auto_mode);
        assert!(!stan.should_exit);
    }

    #[test]
    fn test_wybor_trybu_przelacza_sie_w_obie_strony() {
        let dir = tempfile::tempdir().unwrap();
        let (mut stan, conn) = stan_i_baza(Vec::new());
        let p = sciezki(dir.path());
        let mut log = None;

        handle_key(klawisz(KeyCode::Down), &mut stan, &conn, &p, &mut log);
        assert_eq!(stan.mode_selection, 1, "strzałka w dół wybiera tryb automatyczny");

        handle_key(klawisz(KeyCode::Down), &mut stan, &conn, &p, &mut log);
        assert_eq!(stan.mode_selection, 0, "lista zawija się na dwóch pozycjach");

        handle_key(klawisz(KeyCode::Up), &mut stan, &conn, &p, &mut log);
        assert_eq!(stan.mode_selection, 1, "strzałka w górę też zawija");
    }

    #[test]
    fn test_esc_na_ekranie_wyboru_konczy_prace() {
        let dir = tempfile::tempdir().unwrap();
        let (mut stan, conn) = stan_i_baza(Vec::new());
        handle_key(klawisz(KeyCode::Esc), &mut stan, &conn, &sciezki(dir.path()), &mut None);
        assert!(stan.should_exit);
    }

    /// Zatwierdzenie trybu otwiera dziennik decyzji i przechodzi do właściwego
    /// ekranu. Pusta lista zadań od razu kończy pracę.
    #[test]
    fn test_zatwierdzenie_trybu_otwiera_dziennik_i_ustawia_ekran() {
        let dir = tempfile::tempdir().unwrap();
        let (mut stan, conn) = stan_i_baza(Vec::new());
        let p = sciezki(dir.path());
        let mut log = None;

        stan.mode_selection = 1; // automatyczny
        handle_key(klawisz(KeyCode::Enter), &mut stan, &conn, &p, &mut log);

        assert!(stan.auto_mode, "wybrano tryb automatyczny");
        assert!(log.is_some(), "dziennik decyzji musi zostać otwarty");
        assert!(stan.log_path.is_some(), "ścieżka dziennika musi trafić do stanu");
        assert_eq!(stan.mode, Mode::Done, "pusta lista zadań kończy pracę od razu");
    }

    #[test]
    fn test_przelaczanie_kandydatow_zawija_sie_w_obie_strony() {
        let dir = tempfile::tempdir().unwrap();
        let (mut stan, conn) = stan_i_baza(vec![ReviewTask { id: 1, rel_path: "a.dng".into() }]);
        let p = sciezki(dir.path());
        let mut log = None;

        stan.mode = Mode::Reviewing;
        stan.current_candidates = vec![kandydat("A", 5.0, true), kandydat("B", 5.0, true)];

        handle_key(klawisz(KeyCode::Right), &mut stan, &conn, &p, &mut log);
        assert_eq!(stan.current_candidate_idx, 1);
        handle_key(klawisz(KeyCode::Right), &mut stan, &conn, &p, &mut log);
        assert_eq!(stan.current_candidate_idx, 0, "w prawo zawija na początek");
        handle_key(klawisz(KeyCode::Left), &mut stan, &conn, &p, &mut log);
        assert_eq!(stan.current_candidate_idx, 1, "w lewo zawija na koniec");
    }

    #[test]
    fn test_przelaczanie_bez_kandydatow_nie_panikuje() {
        let dir = tempfile::tempdir().unwrap();
        let (mut stan, conn) = stan_i_baza(Vec::new());
        let p = sciezki(dir.path());
        stan.mode = Mode::Reviewing;

        handle_key(klawisz(KeyCode::Left), &mut stan, &conn, &p, &mut None);
        handle_key(klawisz(KeyCode::Right), &mut stan, &conn, &p, &mut None);
        assert_eq!(stan.current_candidate_idx, 0);
    }

    /// Akceptacja zapisuje plik, odnotowuje status i przechodzi dalej.
    #[test]
    fn test_akceptacja_zapisuje_plik_i_przechodzi_dalej() {
        let dir = tempfile::tempdir().unwrap();
        let conn = baza();
        wstaw_kandydata_do_przegladu(&conn, 1, "a.dng");

        let mut stan = DngRepairState::new(vec![ReviewTask { id: 1, rel_path: "a.dng".into() }]);
        stan.mode = Mode::Reviewing;
        stan.current_candidates = vec![kandydat("Nagłówek A + dane B", 5.16, true)];

        let p = sciezki(dir.path());
        handle_key(klawisz(KeyCode::Char('a')), &mut stan, &conn, &p, &mut None);

        assert_eq!(stan.accepted_count, 1);
        assert_eq!(stan.current_task_idx, 1, "po decyzji przechodzimy do kolejnego pliku");
        assert_eq!(stan.mode, Mode::Done, "lista wyczerpana");

        let status: String = conn.query_row("SELECT dng_structural_status FROM files WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(status, "accepted");

        let sciezka: String = conn.query_row("SELECT dng_structural_path FROM files WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert!(Path::new(&sciezka).exists(), "zapisany plik musi istnieć: {}", sciezka);
    }

    /// REGRESJA (todo.dng_archive_repair.md, Ustalenie 2): dwa pliki o tej
    /// samej nazwie bazowej z RÓŻNYCH podkatalogów źródłowych (typowy układ
    /// przy konsolidacji wielu kart/folderów DCIM) muszą dostać RÓŻNE ścieżki
    /// docelowe w płaskim katalogu przeglądowym — inaczej drugi zaakceptowany
    /// kandydat cicho nadpisuje bajty pierwszego, a oba wiersze bazy
    /// wskazują na tę samą ścieżkę, mimo że fizycznie zawiera tylko jednego
    /// z dwóch plików.
    #[test]
    fn test_akceptacja_dwoch_plikow_o_tej_samej_nazwie_z_roznych_katalogow_nie_koliduje() {
        let dir = tempfile::tempdir().unwrap();
        let conn = baza();
        wstaw_kandydata_do_przegladu(&conn, 1, "karta1/IMG_0001.dng");
        wstaw_kandydata_do_przegladu(&conn, 2, "karta2/IMG_0001.dng");

        let p = sciezki(dir.path());
        let task1 = ReviewTask { id: 1, rel_path: "karta1/IMG_0001.dng".into() };
        let task2 = ReviewTask { id: 2, rel_path: "karta2/IMG_0001.dng".into() };

        let mut kandydat1 = kandydat("Karta 1", 5.0, true);
        kandydat1.bytes = vec![0x11; 256];
        let mut kandydat2 = kandydat("Karta 2", 5.0, true);
        kandydat2.bytes = vec![0x22; 256];

        let sciezka1 = accept_candidate(&conn, &task1, &kandydat1, &p.target_base, false).unwrap();
        let sciezka2 = accept_candidate(&conn, &task2, &kandydat2, &p.target_base, false).unwrap();

        assert_ne!(sciezka1, sciezka2, "różne pliki źródłowe o tej samej nazwie bazowej muszą dostać różne ścieżki docelowe");
        assert_eq!(fs::read(&sciezka1).unwrap(), vec![0x11; 256], "plik z karty 1 nie może zostać nadpisany bajtami z karty 2");
        assert_eq!(fs::read(&sciezka2).unwrap(), vec![0x22; 256], "plik z karty 2 musi zawierać własne bajty");

        let db_sciezka1: String = conn.query_row("SELECT dng_structural_path FROM files WHERE id = 1", [], |r| r.get(0)).unwrap();
        let db_sciezka2: String = conn.query_row("SELECT dng_structural_path FROM files WHERE id = 2", [], |r| r.get(0)).unwrap();
        assert_eq!(db_sciezka1, sciezka1.to_string_lossy());
        assert_eq!(db_sciezka2, sciezka2.to_string_lossy());
    }

    #[test]
    fn test_pominiecie_oznacza_status_i_nie_zapisuje_pliku() {
        let dir = tempfile::tempdir().unwrap();
        let conn = baza();
        wstaw_kandydata_do_przegladu(&conn, 1, "a.dng");

        let mut stan = DngRepairState::new(vec![ReviewTask { id: 1, rel_path: "a.dng".into() }]);
        stan.mode = Mode::Reviewing;
        stan.current_candidates = vec![kandydat("opis", 5.0, true)];

        let p = sciezki(dir.path());
        handle_key(klawisz(KeyCode::Char('p')), &mut stan, &conn, &p, &mut None);

        assert_eq!(stan.skipped_count, 1);
        assert_eq!(stan.accepted_count, 0);

        let status: String = conn.query_row("SELECT dng_structural_status FROM files WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(status, "skipped");
        assert!(!p.target_base.exists(), "pominięcie nie może niczego zapisywać na dysk");
    }

    #[test]
    fn test_esc_w_przegladzie_konczy_a_w_podsumowaniu_wychodzi() {
        let dir = tempfile::tempdir().unwrap();
        let (mut stan, conn) = stan_i_baza(Vec::new());
        let p = sciezki(dir.path());

        stan.mode = Mode::Reviewing;
        handle_key(klawisz(KeyCode::Esc), &mut stan, &conn, &p, &mut None);
        assert_eq!(stan.mode, Mode::Done, "Esc w przeglądzie kończy przebieg, nie program");
        assert!(!stan.should_exit);

        handle_key(klawisz(KeyCode::Enter), &mut stan, &conn, &p, &mut None);
        assert!(stan.should_exit, "Enter w podsumowaniu zamyka narzędzie");
    }

    #[test]
    fn test_w_trybie_automatycznym_reaguje_tylko_esc() {
        let dir = tempfile::tempdir().unwrap();
        let (mut stan, conn) = stan_i_baza(Vec::new());
        let p = sciezki(dir.path());
        stan.mode = Mode::AutoRunning;

        for kod in [KeyCode::Char('a'), KeyCode::Char('p'), KeyCode::Enter, KeyCode::Left] {
            handle_key(klawisz(kod), &mut stan, &conn, &p, &mut None);
            assert_eq!(stan.mode, Mode::AutoRunning, "przebieg automatyczny nie słucha decyzji operatora");
        }

        handle_key(klawisz(KeyCode::Esc), &mut stan, &conn, &p, &mut None);
        assert_eq!(stan.mode, Mode::Done, "Esc musi dać się przerwać");
    }

    // ------------------------------------------------------------------
    // Przebieg automatyczny
    // ------------------------------------------------------------------

    #[test]
    fn test_automat_przyjmuje_kandydata_plauzybilnego() {
        let dir = tempfile::tempdir().unwrap();
        let conn = baza();
        wstaw_kandydata_do_przegladu(&conn, 1, "a.dng");

        let mut stan = DngRepairState::new(vec![ReviewTask { id: 1, rel_path: "a.dng".into() }]);
        stan.mode = Mode::AutoRunning;
        stan.current_candidates = vec![kandydat("nieplauzybilny", 0.1, false), kandydat("plauzybilny", 5.16, true)];

        advance_auto_tick(&mut stan, &conn, &sciezki(dir.path()), &mut None);

        assert_eq!(stan.accepted_count, 1);
        let status: String = conn.query_row("SELECT dng_structural_status FROM files WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(status, "accepted_auto", "automat musi być rozróżnialny od decyzji operatora");
    }

    /// Gdy żaden kandydat nie przechodzi progu plauzybilności, automat POMIJA
    /// plik. To jest sedno bezpieczeństwa trybu bezobsługowego: lepiej nie
    /// naprawić, niż zapisać obszar zer jako odzyskane zdjęcie.
    #[test]
    fn test_automat_pomija_gdy_zaden_kandydat_nie_jest_plauzybilny() {
        let dir = tempfile::tempdir().unwrap();
        let conn = baza();
        wstaw_kandydata_do_przegladu(&conn, 1, "a.dng");

        let mut stan = DngRepairState::new(vec![ReviewTask { id: 1, rel_path: "a.dng".into() }]);
        stan.mode = Mode::AutoRunning;
        stan.current_candidates = vec![kandydat("zera", 0.0, false), kandydat("szum", 7.99, false)];

        let p = sciezki(dir.path());
        advance_auto_tick(&mut stan, &conn, &p, &mut None);

        assert_eq!(stan.accepted_count, 0);
        assert_eq!(stan.skipped_count, 1);
        let status: String = conn.query_row("SELECT dng_structural_status FROM files WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(status, "skipped_auto");
        assert!(!p.target_base.exists(), "odrzucony kandydat nie może zostać zapisany");
    }

    #[test]
    fn test_automat_nie_rusza_gdy_nie_jest_w_swoim_trybie() {
        let dir = tempfile::tempdir().unwrap();
        let conn = baza();
        let mut stan = DngRepairState::new(vec![ReviewTask { id: 1, rel_path: "a.dng".into() }]);
        stan.mode = Mode::Reviewing;

        advance_auto_tick(&mut stan, &conn, &sciezki(dir.path()), &mut None);

        assert_eq!(stan.current_task_idx, 0, "tykacz automatu nie może działać w trybie ręcznym");
        assert_eq!(stan.accepted_count, 0);
    }

    // ------------------------------------------------------------------
    // Składanie kandydatów na PRAWDZIWYCH plikach DNG
    // ------------------------------------------------------------------

    /// Przygotowuje dwie „kopie odzysku" z fixture'ów i zwraca kandydatów.
    fn kandydaci_z_fixtureow(katalog: &Path, ufs: &str, script: &str) -> Vec<DisplayCandidate> {
        let p = sciezki(katalog);
        fs::create_dir_all(&p.ufs_base).unwrap();
        fs::create_dir_all(&p.script_base).unwrap();
        fs::copy(Path::new("image").join(ufs), p.ufs_base.join("foto.dng")).unwrap();
        fs::copy(Path::new("image").join(script), p.script_base.join("foto.dng")).unwrap();

        compute_candidates(
            &ReviewTask { id: 1, rel_path: "foto.dng".to_string() },
            &p.ufs_base, &p.script_base,
        )
    }

    /// Uszkodzenie w ŚRODKU danych obrazu: struktura obu kopii jest czytelna,
    /// więc składanie daje kandydatów w obu kierunkach.
    ///
    /// Fixture `test_fixture_middle_damaged.dng` leżał w repozytorium
    /// nieużywany przez żaden test.
    #[test]
    #[ignore = "Wymaga image/test_fixture_middle_damaged.dng i test_fixture.dng. Uruchom z --ignored."]
    fn test_e2e_kandydaci_dla_uszkodzenia_w_srodku_danych() {
        let dir = tempfile::tempdir().unwrap();
        let kandydaci = kandydaci_z_fixtureow(dir.path(), "test_fixture_middle_damaged.dng", "test_fixture.dng");

        assert!(!kandydaci.is_empty(), "obie kopie mają czytelną strukturę - kandydaci muszą powstać");
        for k in &kandydaci {
            assert_eq!(k.confidence, dng_splice::SpliceConfidence::StructuralOnly,
                       "każdy kandydat musi nieść jawne ograniczenie gwarancji");
            assert!(k.width > 0 && k.height > 0, "kandydat przeszedł dekodowanie, więc zna wymiary");
            assert!(k.plausible, "entropia prawdziwych danych sensora musi przechodzić próg: {:.4}", k.entropy);
        }
    }

    /// Plik UCIĘTY nie ma czytelnej struktury po stronie uszkodzonej, więc
    /// kandydatów nie ma wcale — a wtedy narzędzie musi sam z siebie oznaczyć
    /// plik jako `unparseable` i przejść dalej, zamiast pokazywać operatorowi
    /// pusty ekran.
    ///
    /// Fixture `test_fixture_truncated.dng` również leżał nieużywany.
    #[test]
    #[ignore = "Wymaga image/test_fixture_truncated.dng i test_fixture.dng. Uruchom z --ignored."]
    fn test_e2e_uciety_plik_jest_pomijany_automatycznie() {
        let dir = tempfile::tempdir().unwrap();
        let kandydaci = kandydaci_z_fixtureow(dir.path(), "test_fixture_truncated.dng", "test_fixture.dng");
        assert!(kandydaci.is_empty(), "kontrola: dla pliku uciętego nie powstaje żaden kandydat");

        let conn = baza();
        wstaw_kandydata_do_przegladu(&conn, 1, "foto.dng");

        let mut stan = DngRepairState::new(vec![ReviewTask { id: 1, rel_path: "foto.dng".into() }]);
        stan.mode = Mode::Reviewing;

        load_current_or_advance(&mut stan, &conn, &sciezki(dir.path()), &mut None);

        assert_eq!(stan.mode, Mode::Done, "po wyczerpaniu listy narzędzie kończy pracę");
        assert_eq!(stan.skipped_count, 1);
        let status: String = conn.query_row("SELECT dng_structural_status FROM files WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(status, "unparseable", "brak kandydatów ma własną, rozróżnialną kategorię");
    }
}
