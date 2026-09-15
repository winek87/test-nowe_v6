// src/phases/phase16.rs

//! # Faza 16: Skanowanie Sygnatur (YARA Rules)
//!
//! Kompiluje zasady YARA i skanuje fizycznie odzyskane pliki w poszukiwaniu
//! złośliwego kodu, notatek hakerskich, wycieków danych lub ukrytych zagrożeń.
//! Posiada dedykowaną tabelę SQLite, logi Dual-Logging, wielowątkowy silnik
//! i 100% integrację z interfejsem Ratatui (PhaseEvent).
//!
//! NAPRAWIONY BUG (utrata danych dla plików wspólnych): tabela pomocnicza
//! `phase16_analysis` ma `file_id INTEGER PRIMARY KEY` — jeden wiersz NA
//! PLIK, nie na stronę. Dla pliku WSPÓLNEGO (obecnego po obu stronach)
//! budowane są DWA niezależne zadania o tym samym `id` (jedno w `ufs_tasks`,
//! jedno w `script_tasks`), oba trafiające do tego samego wątku zapisu przez
//! `INSERT OR REPLACE INTO phase16_analysis (file_id, ...)` — czyli DRUGI
//! zapis bezpowrotnie NADPISYWAŁ pierwszy (kolejność zależna od tego, który
//! wątek dotarł do pliku szybciej, więc niedeterministyczna). Raport końcowy
//! (Etap 5) czytał WYŁĄCZNIE z tej racującej tabeli — dla plików wspólnych z
//! różnymi trafieniami po obu stronach jedna strona znikała bezpowrotnie z
//! zestawienia częstości reguł, mimo że w głównej tabeli `files`
//! (`yara_match_ufs`/`yara_match_script` — osobne kolumny per strona,
//! bez kolizji) dane były zapisane poprawnie i kompletnie. Naprawione przez
//! przebudowę zapytania Etapu 5 na czytanie bezpośrednio z `files`.
//! Tabela `phase16_analysis` zostaje (przydatna do ręcznej inspekcji
//! pojedynczego pliku), ale NIE nadaje się do zbiorczych statystyk plików
//! wspólnych — patrz komentarz przy jej tworzeniu.
//!
//! UWAGA ARCHITEKTONICZNA (UI): mechanizm throttlingu UI (`AtomicU64` +
//! `compare_exchange`, na poziomie całej funkcji) był tu już poprawny przed
//! tą rewizją — ten sam dobry wzorzec co w Fazie 14/15.
//!
//! UWAGA ARCHITEKTONICZNA (WĄTKOWANIE): każda strona dostaje własną,
//! dedykowaną pulę Rayon (`half_threads`, identycznie jak Fazy 2-7/10-15).
//!
//! NAPRAWIONY BUG KRYTYCZNY (pliki czyste nigdy nie kończyły fazy): zapis
//! wyniku używał `yara_match_ufs = COALESCE(?, yara_match_ufs)`, gdzie `?`
//! to `None` dla pliku BEZ trafień. `COALESCE` na `None` zostawia kolumnę BEZ
//! ZMIAN — czyli wiecznie `NULL`. Kryterium `phase16_done` wymagało
//! `yara_match_ufs IS NOT NULL OR io_error_ufs = 1`, więc dla pliku czystego
//! (oba fałszywe) `phase16_done` NIGDY się nie ustawiało — każde wznowienie
//! fazy skanowało od nowa CAŁY dotychczas-czysty korpus (w praktyce niemal
//! wszystko, bo trafienia malware są rzadkością). Klasyczne pomylenie
//! semantyki `NULL`: `None` oznaczał jednocześnie "nieprzeskanowany" I
//! "przeskanowany, czysty" — nie do odróżnienia.
//!
//! ŚWIADOMIE ODRZUCONE ROZWIĄZANIE: zamiana sentinela "brak trafień" z
//! `None` na `Some(String::new())` w `yara_match_ufs`/`_script` (pusty
//! string = "przeskanowano, czysto"). Techniczne najprostsze, ale
//! NIEBEZPIECZNE tutaj: `phases::phase8` (raport CSV) i `phases::phase9`
//! (Smart Merge) czytają te SAME kolumny gdzie indziej z konwencją
//! `.is_some() == zainfekowany` (np. `phase9::wybierz_strone_odrzucona`) —
//! każdy przeskanowany-czysty plik zacząłby wyglądać jak zainfekowany dla
//! tamtych faz. Ponieważ ten plik jest jedynym dozwolonym miejscem zmian w
//! tej naprawie, semantyka `yara_match_ufs`/`_script` (`NULL` = brak
//! trafienia LUB nieprzeskanowany, `Some(nazwy)` = realne trafienie)
//! zostaje BEZ ZMIAN.
//!
//! ZASTOSOWANE ROZWIĄZANIE: nowa para kolumn `yara_scanned_ufs`/
//! `yara_scanned_script` (BOOLEAN, `ALTER TABLE ... ADD COLUMN`, ten sam
//! wzorzec no-opowej migracji co reszta faz — patrz `db.rs::migrate_schema`)
//! ustawiana na `1` przy KAŻDYM zapisie wyniku tej strony (czysty,
//! zainfekowany LUB błąd I/O — bezwarunkowo, bez `COALESCE`). Kryterium
//! `phase16_done` i selekcja zadań (Etap 1) sprawdzają teraz `yara_scanned_*
//! = 1` OBOK starych warunków (`yara_match_* IS NOT NULL OR io_error_* = 1`)
//! — stare wiersze sprzed tej naprawy (infekcja/błąd I/O już zapisane, ale
//! bez nowej kolumny) zostają natychmiast rozpoznane jako gotowe, BEZ
//! ponownego skanowania; tylko wiersze faktycznie dotknięte bugiem (czyste,
//! nieoznaczone) wpadają do zadań RAZ, dostają `yara_scanned_* = 1` i odtąd
//! są trwale pomijane.
//!
//! NAPRAWIONY BUG WYSOKI (brak `catch_unwind` wokół silnika YARA):
//! `scan_file_yara` woła `rules.scan_file` — silnik YARA (C) i, przy
//! `features = ["module-magic"]` w `Cargo.toml`, pośrednio libmagic (C, ze
//! zweryfikowaną historią awarii na spreparowanych danych) — na plikach z
//! odzysku danych, z definicji niezaufanych/potencjalnie uszkodzonych, bez
//! żadnej ochrony przed paniką. Niespójne z resztą projektu: `raw_image`,
//! `heic_image`, `video_image` (dekodery zewnętrznych bibliotek) i
//! `phases::phase17_repair` (moduły naprawcze operujące na uszkodzonych
//! plikach) owijają analogiczne wywołania w `std::panic::catch_unwind` —
//! bez tego jedna patologiczna próbka ubija cały wątek roboczy Rayon,
//! tracąc resztę partii zadań tej strony. Naprawione przez
//! [`catch_yara_panic`], wołane z `scan_file_yara` DOKŁADNIE tym samym
//! wzorcem (`catch_unwind(AssertUnwindSafe(...))`) co `phase17_repair`. Ten
//! plik CELOWO NIE dodaje thread-local flagi `is_expected_panic_in_progress`
//! + rejestracji w globalnym panic hooku (`logging.rs`) jak `raw_image` —
//! ten mechanizm wymagałby edycji `logging.rs`, poza dozwolonym zakresem tej
//! naprawy — i zamiast tego świadomie stosuje prostszy, już obecny w
//! projekcie wzorzec `phase17_repair` (goły `catch_unwind` bez rejestracji w
//! hooku): panika nadal NIE ubija wątku/procesu, kosztem tego, że globalny
//! hook potraktuje ją jako "niespodziewaną" (zaloguje `BŁĄD KRYTYCZNY` i
//! przywróci terminal), zamiast po cichu przełknąć jak przy `raw_image`.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::{format_bytes, format_display_path, CANCEL_SIGNAL};
use dialoguer::{theme::ColorfulTheme, MultiSelect};
use ratatui::style::Color;
use rayon::prelude::*;
use rusqlite::{params, Connection, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;
use tracing::{error, info, instrument, warn};
use yara::{Compiler, Rules};
use colored::Colorize;

const CHUNK_SIZE: usize = 100;

// ============================================================================
// STRUKTURY DANYCH I POMOCNIKI
// ============================================================================

#[derive(Debug, Clone)]
pub(crate) struct Task {
    id: i32,
    rel_path: String,
    is_common: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SideYaraResult {
    id: i32,
    matches: Option<String>,
    io_error: Option<bool>,
}

pub(crate) enum ScanMsg {
    UfsChunk(Vec<SideYaraResult>),
    ScriptChunk(Vec<SideYaraResult>),
}

/// Liczniki live dla JEDNEJ strony. `top_rules` i `multi_rule_files` to
/// nowe liczniki: reguły są już zbierane w `matches` od zawsze, tylko
/// wcześniej agregowane WYŁĄCZNIE w raporcie końcowym, nie pokazywane na
/// żywo w trakcie skanowania.
pub(crate) struct LiveStats {
    processed_files: AtomicUsize,
    processed_bytes: AtomicU64,
    clean: AtomicUsize,
    infected: AtomicUsize,
    errors: AtomicUsize,
    /// Zliczenia wystąpień per NAZWA reguły — do "Top reguły" w panelu live.
    top_rules: Mutex<HashMap<String, usize>>,
    /// Pliki, które wyzwoliły WIĘCEJ NIŻ JEDNĄ regułę jednocześnie —
    /// silniejszy sygnał zagrożenia niż pojedyncze trafienie.
    multi_rule_files: AtomicUsize,

    /// EKSPERYMENTALNE (Wariant A): śledzi zajętość logicznych slotów Rayon
    /// TEJ strony podczas skanowania YARA (`scan_file_yara`) — patrz moduł
    /// `thread_activity`.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            processed_files: AtomicUsize::new(0),
            processed_bytes: AtomicU64::new(0),
            clean: AtomicUsize::new(0),
            infected: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            top_rules: Mutex::new(HashMap::new()),
            multi_rule_files: AtomicUsize::new(0),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }
}

/// Wylicza liczbę slotów trackera zajętości (Wariant A) odpowiednią dla
/// trybu I/O — patrz identyczna logika w `phase3::compute_activity_slots`.
fn compute_activity_slots(io_mode: &str, actual_threads: usize, half_threads: usize) -> usize {
    if io_mode == "CONCURRENT" { half_threads } else { actual_threads }
}

/// Buduje pełny, samodzielny blok live DLA JEDNEGO ŹRÓDŁA — prędkość MB/s,
/// czyste/zainfekowane, top 3 wyzwolone reguły na żywo, pliki z wieloma
/// jednoczesnymi trafieniami, błędy I/O.
fn build_source_block(label: &str, stats: &LiveStats, start_time: Instant) -> String {
    let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
    let bytes = stats.processed_bytes.load(Ordering::Relaxed);
    let speed_mb = (bytes as f64 / 1_048_576.0) / elapsed;

    let top_rules_str = {
        let map = stats.top_rules.lock().unwrap();
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.into_iter().take(3).map(|(r, c)| format!("{} ({})", r, c)).collect::<Vec<_>>().join(", ")
    };
    let display_rules = if top_rules_str.is_empty() { "-".to_string() } else { top_rules_str };

    let activity_markup = crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot());

    format!(
        "[{}]\nPrędkość: {:.2} MB/s\nCzyste: {}\nZainfekowane: {}\nTop reguły (live): {}\nWiele reguł jednocześnie: {}\nWątki YARA (Wariant A): {}\nBłędy I/O: {}",
        label, speed_mb,
        stats.clean.load(Ordering::Relaxed),
        stats.infected.load(Ordering::Relaxed),
        display_rules,
        stats.multi_rule_files.load(Ordering::Relaxed),
        activity_markup,
        stats.errors.load(Ordering::Relaxed),
    )
}

/// Mapa nazwa_reguły -> (liczba trafień, przykładowa ścieżka) — do Dziennika
/// Końcowego. Uwaga: liczona z zapytania SQL do `files.yara_match_*`
/// (patrz naprawiony bug w dokumentacji modułu), nie z tabeli `phase16_analysis`.
type RuleMap = HashMap<String, (usize, String)>;
struct CategoryStats {
    count: usize,
    rules: RuleMap,
}
impl CategoryStats {
    fn new() -> Self { Self { count: 0, rules: HashMap::new() } }
    fn add(&mut self, rule_name: &str, path: String) {
        self.count += 1;
        let entry = self.rules.entry(rule_name.to_string()).or_insert((0, path));
        entry.0 += 1;
    }
}

// ============================================================================
// SILNIK DECYZYJNY (WERYFIKATOR YARA)
// ============================================================================

/// Wykonuje `f` chronione przed paniką — dokładnie ten sam wzorzec
/// (`std::panic::catch_unwind(std::panic::AssertUnwindSafe(...))`) co
/// `phases::phase17_repair` wokół wywołań modułów naprawczych operujących na
/// uszkodzonych/niezaufanych plikach. Zamienia panikę silnika YARA (C) —
/// albo, przy `features = ["module-magic"]`, pośrednio libmagic (C) — na
/// bezpieczny `Err`, zamiast ubić cały wątek roboczy Rayon i stracić resztę
/// partii zadań tej strony. Wydzielone jako osobna funkcja generyczna, żeby
/// dało się to przetestować jednostkowo bez potrzeby spreparowania pliku,
/// który faktycznie wywoła panikę WEWNĄTRZ `libyara`/`libmagic`.
fn catch_yara_panic<F, T>(f: F) -> std::thread::Result<T>
where
    F: FnOnce() -> T,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
}

/// Skanuje jeden plik skompilowanym zestawem reguł (limit 10s na plik, żeby
/// pojedyncza patologiczna reguła/plik nie zawiesiła całej fazy). Zwraca
/// `Ok(None)` dla pliku czystego, `Ok(Some("Regula1, Regula2"))` dla
/// dopasowań (połączone przecinkiem), `Err` dla braku pliku, błędu silnika
/// YARA (w tym timeout) lub PANIKI wewnątrz `rules.scan_file` przechwyconej
/// przez [`catch_yara_panic`] (patrz dokumentacja modułu — NAPRAWIONY BUG
/// WYSOKI).
fn scan_file_yara(path: &Path, rel_path: &str, side_label: &str, rules: &Rules) -> std::result::Result<Option<String>, std::io::Error> {
    if !path.exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Plik nie istnieje"));
    }

    match catch_yara_panic(|| rules.scan_file(path, 10)) {
        Ok(Ok(matches)) => {
            if matches.is_empty() {
                Ok(None)
            } else {
                let rule_names: Vec<String> = matches.iter().map(|m| m.identifier.to_string()).collect();
                Ok(Some(rule_names.join(", ")))
            }
        }
        Ok(Err(e)) => {
            warn!(path = rel_path, side = side_label, error = %e, "Błąd I/O lub Timeout YARA");
            Err(std::io::Error::other("YARA Scan Error"))
        }
        Err(panika) => {
            let opis = panika
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panika.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "nieznana przyczyna".to_string());
            error!(path = rel_path, side = side_label, panika = %opis, "PANIKA silnika YARA (scan_file) - przechwycona, plik traktowany jak błąd I/O");
            Err(std::io::Error::other("Panika silnika YARA (przechwycona przez catch_unwind)"))
        }
    }
}

/// Skanuje wszystkie zadania (`tasks`) dla JEDNEJ strony: dla każdego pliku
/// woła [`scan_file_yara`], aktualizuje liczniki [`LiveStats`] (w tym nowe
/// `top_rules`/`multi_rule_files`), zapisuje wpis do logu operacyjnego dla
/// każdego trafienia i strumieniuje wynik do wątku zapisu SQLite.
pub struct StreamCtx<'a> {
    pub base_path: &'a Path,
    pub tasks: &'a [Task],
    pub side_label: &'a str,
    pub rules: &'a Rules,
    pub stats: &'a LiveStats,
    pub tx_db: mpsc::SyncSender<ScanMsg>,
    pub is_ufs: bool,
    pub start_time: Instant,
    pub tx_ui: &'a mpsc::Sender<PhaseEvent>,
    pub bar_idx: usize,
    pub log_infected: Arc<Mutex<File>>,
}

#[instrument(skip(ctx), fields(base_path = %ctx.base_path.display()))]

fn process_side_stream<'a>(ctx: StreamCtx<'a>) {
    let StreamCtx { base_path, tasks, side_label, rules, stats, tx_db, is_ufs, start_time, tx_ui, bar_idx, log_infected } = ctx;

    let last_ui_update = Arc::new(AtomicU64::new(0));

    tasks.par_chunks(CHUNK_SIZE).for_each_with(tx_db, |tx_db, chunk| {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

        let mut results = Vec::with_capacity(chunk.len());
        let mut local_rules: HashMap<String, usize> = HashMap::new();

        for task in chunk {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

            let full_path = base_path.join(&task.rel_path);
            let file_size = std::fs::metadata(&full_path).map(|m| m.len()).unwrap_or(0);

            let (matches_opt, io_err) = match stats.thread_activity.track_current(|| scan_file_yara(&full_path, &task.rel_path, side_label, rules)) {
                Ok(Some(m)) => {
                    stats.infected.fetch_add(1, Ordering::Relaxed);
                    let kategoria = if task.is_common { "Wspólne" } else { "Unikalne" };

                    let rule_names: Vec<&str> = m.split(", ").collect();
                    if rule_names.len() > 1 {
                        stats.multi_rule_files.fetch_add(1, Ordering::Relaxed);
                    }
                    for rn in &rule_names {
                        *local_rules.entry(rn.to_string()).or_insert(0) += 1;
                    }
                    
                    if let Ok(mut f) = log_infected.lock() {
                        let _ = writeln!(f, "[{:<15}] [{:<8}] [Reguły: {}] -> \"{}\"", side_label, kategoria, m, full_path.display());
                    }
                    (Some(m), Some(false))
                },
                Ok(None) => {
                    stats.clean.fetch_add(1, Ordering::Relaxed);
                    (None, Some(false))
                },
                Err(_) => {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    (None, Some(true))
                }
            };

            if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

            let current = stats.processed_files.fetch_add(1, Ordering::Relaxed) + 1;
            stats.processed_bytes.fetch_add(file_size, Ordering::Relaxed);

            let now_ms = start_time.elapsed().as_millis() as u64;
            let last_ms = last_ui_update.load(Ordering::Relaxed);
            
            if now_ms - last_ms > 80
                && last_ui_update.compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed).is_ok() {

                    if !local_rules.is_empty() {
                        let mut g_rules = stats.top_rules.lock().unwrap();
                        for (k, v) in local_rules.drain() { *g_rules.entry(k).or_insert(0) += v; }
                    }

                    // PASEK: wyłącznie postęp + bieżący plik (bez liczników)
                    let _ = tx_ui.send(PhaseEvent::UpdateBar {
                        idx: bar_idx,
                        current: current as u64,
                        message: format_display_path(&task.rel_path),
                    });
                    let _ = tx_ui.send(PhaseEvent::UpdateBottomPath {
                        idx: bar_idx,
                        path: full_path.to_string_lossy().to_string(),
                    });

                    // PANEL BOCZNY: pełny, samodzielny blok TEGO źródła
                    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                        idx: bar_idx,
                        text: build_source_block(side_label, stats, start_time),
                    });
                }

            results.push(SideYaraResult { id: task.id, matches: matches_opt, io_error: io_err });
        }

        if !local_rules.is_empty() {
            let mut g_rules = stats.top_rules.lock().unwrap();
            for (k, v) in local_rules.drain() { *g_rules.entry(k).or_insert(0) += v; }
        }

        if !results.is_empty() {
            if is_ufs { let _ = tx_db.send(ScanMsg::UfsChunk(results)); } 
            else { let _ = tx_db.send(ScanMsg::ScriptChunk(results)); }
        }
    });

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: stats.processed_files.load(Ordering::Relaxed) as u64,
        message: "Skanowanie YARA w 100% zakończone.".to_string(),
    });
}

/// Formatuje jedną pulę (wspólne-UFS/wspólne-Skrypt/tylko-UFS/tylko-Skrypt)
/// do Dziennika Końcowego: top 5 reguł wg liczby trafień z przykładową ścieżką.
fn write_category_block(out: &mut String, stats: &CategoryStats) {
    use std::fmt::Write as FmtWrite;
    if stats.count == 0 { 
        let _ = writeln!(out, "   [ ✔ ] Brak wykrytych zagrożeń w tej puli.");
        return; 
    }
    
    let _ = writeln!(out, "   [ 👇 ] Zidentyfikowane sygnatury YARA i próbki:");
    
    let mut sorted: Vec<_> = stats.rules.iter().collect();
    sorted.sort_by_key(|a| std::cmp::Reverse(a.1.0)); 
    
    for (rule_name, (count, example_path)) in sorted.into_iter().take(5) {
        let _ = writeln!(out, "     - 🦠 Sygnatura: {:<25} | Trafienia: {}", rule_name, count);
        let _ = writeln!(out, "       [ 🔍 ] Przykładowy zainfekowany plik:");
        let _ = writeln!(out, "         - Ścieżka: \"{}\"", example_path);
    }
    let _ = writeln!(out); 
}

/// Wylicza rozmiar prywatnej puli Rayon przypisywanej JEDNEJ stronie w
/// trybie `CONCURRENT` — patrz `phase3::compute_half_threads` dla pełnego
/// uzasadnienia.
fn compute_half_threads(total_threads: usize) -> usize {
    std::cmp::max(1, total_threads / 2)
}

// ============================================================================
// GŁÓWNA FUNKCJA (Entrypoint)
// ============================================================================

/// Skanuje katalog `yara_rules/` w poszukiwaniu plików `.yar`/`.yara`. Czysta
/// funkcja I/O bez żadnej interakcji z użytkownikiem — bezpieczna do wołania
/// z dowolnego kontekstu (CLI zawieszone, wnętrze wątku roboczego, autopilot).
pub fn discover_rule_files() -> Vec<PathBuf> {
    let rules_dir = Path::new("yara_rules");
    let mut found = Vec::new();
    if let Ok(entries) = fs::read_dir(rules_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file()
                && let Some(ext) = path.extension().and_then(|e| e.to_str())
                    && (ext == "yar" || ext == "yara") { found.push(path); }
        }
    }
    found
}

/// Kompiluje podaną listę plików reguł do jednego zestawu `Rules`. Używa
/// wyłącznie `tracing` do raportowania błędów (BEZ `println!`) — ta funkcja
/// może zostać wywołana z wnętrza aktywnego ekranu Ratatui (Autopilot), gdzie
/// pisanie bezpośrednio do stdout zniszczyłoby bufor rysowania.
fn compile_rule_files(rule_files: &[PathBuf]) -> Option<Rules> {
    let mut compiler = match Compiler::new() {
        Ok(c) => c,
        Err(e) => { error!("Nie udało się zainicjalizować kompilatora YARA: {}", e); return None; }
    };
    for rule_path in rule_files {
        compiler = match compiler.add_rules_file(rule_path) {
            Ok(c) => c,
            Err(e) => {
                error!(plik = ?rule_path.file_name(), "Błąd kompilacji reguł YARA: {}", e);
                return None;
            }
        };
    }
    compiler.compile_rules().ok()
}

/// Kompiluje WSZYSTKIE odnalezione reguły bez żadnego pytania użytkownika —
/// używane przez Autopilota (przebieg bezobsługowy, nie ma kto odpowiedzieć
/// na `MultiSelect`). Zwraca `None`, gdy nie znaleziono żadnych plików reguł
/// lub kompilacja się nie powiedzie — Autopilot pomija wtedy Fazę 16 po cichu.
pub fn compile_all_available_rules() -> Option<Rules> {
    let files = discover_rule_files();
    if files.is_empty() {
        warn!("Autopilot: brak plików reguł YARA w 'yara_rules/'. Pomijanie Fazy 16.");
        return None;
    }
    compile_rule_files(&files)
}

/// Skanuje dysk, pokazuje `MultiSelect` i kompiluje wybrane reguły. MUSI być
/// wołane PRZED wejściem w tryb Raw Ratatui (z `actions.rs`, w tym samym
/// zawieszonym CLI co `diag`/`reset`) — `dialoguer` wymaga normalnego trybu
/// terminala i wyłącznego dostępu do stdin; wołanie tego w trakcie, gdy
/// główny wątek UI już rysuje ekran Ratatui i nasłuchuje klawiatury,
/// powodowało realny konflikt o terminal (obserwowany bug: prompt wyboru
/// nigdy się nie pojawiał, faza cicho ruszała z pustym/domyślnym wyborem).
/// Zwraca `None`, gdy brak folderu/plików, użytkownik nic nie wybrał, albo
/// kompilacja się nie powiedzie (błąd składni już wypisany na `stdout`) —
/// wywołujący powinien wtedy pominąć Fazę 16 bez w ogóle wchodzenia w ekran Ratatui.
pub fn select_and_compile_rules() -> Option<Rules> {
    let rules_dir = Path::new("yara_rules");
    if !rules_dir.exists() {
        println!("\x1b[38;5;208m[ ⚠ ] Brak folderu 'yara_rules'. Faza 16 pominięta.\x1b[0m");
        warn!("Brak folderu reguł YARA. Pomijanie Fazy 16.");
        return None;
    }

    let available_rules = discover_rule_files();
    if available_rules.is_empty() {
        println!("\x1b[38;5;208m[ ⚠ ] Folder 'yara_rules' jest pusty. Faza 16 pominięta.\x1b[0m");
        return None;
    }

    let rule_names: Vec<String> = available_rules.iter().map(|p| p.file_name().unwrap().to_string_lossy().to_string()).collect();

    println!("\n{}", "[ 🧰 ] ZNALEZIONO REGUŁY YARA NA DYSKU".cyan().bold());
    let selections = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Wybierz reguły do skompilowania (Spacja = zaznacz, ENTER = zatwierdź)")
        .items(&rule_names)
        .interact_opt()
        .unwrap_or(None);

    let selected_indices = match selections {
        Some(s) if !s.is_empty() => s,
        _ => {
            println!("{}", "[ ℹ ] Nie wybrano żadnych reguł. Pomijam skanowanie YARA.".bright_black());
            return None;
        }
    };

    println!("\n{}", "[ ⚙ ] Kompilacja wybranych reguł do pamięci RAM...".cyan());
    let selected_files: Vec<PathBuf> = selected_indices.iter().map(|&idx| available_rules[idx].clone()).collect();

    let mut compiler = Compiler::new().unwrap();
    for rule_path in &selected_files {
        compiler = match compiler.add_rules_file(rule_path) {
            Ok(c) => c,
            Err(e) => {
                println!("{} Błąd składni w pliku {:?}: {}", "[ ✖ ]".red().bold(), rule_path.file_name().unwrap(), e);
                error!("Błąd kompilacji reguł YARA: {}", e);
                return None;
            }
        };
    }

    let rules = compiler.compile_rules().unwrap();
    println!("{}\n", "[ ✔ ] Reguły załadowane pomyślnie.".green());
    Some(rules)
}

/// Punkt wejścia Fazy 16, wołany przez `menu::actions::run_phase_with_ui`.
/// Przyjmuje JUŻ SKOMPILOWANE reguły (patrz [`select_and_compile_rules`]/
/// [`compile_all_available_rules`] wołane przez wywołującego PRZED wejściem
/// w tryb Raw) — ta funkcja sama nie robi już żadnej interakcji z użytkownikiem.
#[instrument(skip(conn, config, tx_ui, rules), fields(ufs_path = %config.ufs_path, script_path = %config.script_path))]
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>, rules: Rules) -> Result<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    // START FAZY RATATUI
    let _ = tx_ui.send(PhaseEvent::Log("Uruchomiono Fazę 16. Silnik YARA zintegrowany z pamięcią RAM.".to_string()));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    // UWAGA: `file_id` jest PRIMARY KEY tej tabeli — jeden wiersz NA PLIK, nie
    // na stronę. Dla plików WSPÓLNYCH drugi zapis (z drugiej strony) nadpisuje
    // pierwszy przez INSERT OR REPLACE. Ta tabela jest przydatna do ręcznego
    // podglądu pojedynczego pliku, ale Etap 5 (raport zbiorczy) CELOWO NIE
    // czyta z niej — patrz dokumentacja modułu.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS phase16_analysis (
            file_id INTEGER PRIMARY KEY,
            yara_matched BOOLEAN,
            rules_triggered TEXT,
            FOREIGN KEY(file_id) REFERENCES files(id)
        )", []
    )?;

    // NAPRAWA BUGU KRYTYCZNEGO (patrz dokumentacja modułu): dodatkowa para
    // kolumn oznaczających WPROST "ta strona TEGO pliku przeszła przez
    // skaner YARA", niezależnie od wyniku (czysty/zainfekowany/błąd I/O).
    // Celowo NIE zwraca błędu — `ALTER TABLE ... ADD COLUMN` na kolumnie,
    // która już istnieje (kolejne uruchomienia), kończy się oczekiwanym
    // `duplicate column name`, dokładnie ten sam no-opowy wzorzec migracji
    // co w innych fazach (patrz `db.rs::migrate_schema` i np.
    // `phase18_smart_splice::run`).
    let _ = conn.execute("ALTER TABLE files ADD COLUMN yara_scanned_ufs BOOLEAN", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN yara_scanned_script BOOLEAN", []);

    // INICJALIZACJA DUAL-LOGGING
    let raport_cfg = config.raporty_faz.get("Faza 16").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza16.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza16.txt".to_string(),
    });
    
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);

    let log_infected = Arc::new(Mutex::new(File::create(&opr_path).unwrap()));
    {
        let mut f = log_infected.lock().unwrap();
        let _ = writeln!(f, "=== RAPORT OPERACYJNY - FAZA 16: WYKRYTE ZAGROŻENIA YARA ===");
        let _ = writeln!(f, "Ewidencja plików, które wyzwoliły reguły skanowania antywirusowego na żywo.\n");
    }

    // --- ETAP 1: POBIERANIE ZADAŃ ---
    //
    // NAPRAWA BUGU KRYTYCZNEGO: kryterium "trzeba przeskanować" sprawdza
    // teraz TAKŻE nową kolumnę `yara_scanned_*` (`scanned_ufs`/`scanned_scr`
    // poniżej), nie tylko `yara_match_* IS NULL`. Bez tego dodatku plik
    // czysty (`y_ufs = None`, `err_ufs != true`, ale `scanned_ufs` USTAWIONE
    // na `1` przez poprzedni przebieg) wpadałby tu w nieskończoność z
    // powrotem do zadań — dokładnie ten sam bug, tylko przeniesiony z Etapu 4
    // do Etapu 1. Stare warunki (`y_ufs.is_none()`, `err_ufs != Some(true)`)
    // zostają, żeby wiersze sprzed tej naprawy (infekcja/błąd I/O zapisane,
    // ale bez nowej kolumny) NIE zostały przypadkiem ponownie zakolejkowane.
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, yara_match_ufs, yara_match_script, io_error_ufs, io_error_script, yara_scanned_ufs, yara_scanned_script
         FROM files WHERE phase16_done = 0 OR phase16_done IS NULL"
    )?;

    let mut ufs_tasks = Vec::new();
    let mut script_tasks = Vec::new();
    let mut skipped = 0;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i32>(0)?, row.get::<_, String>(1)?, row.get::<_, bool>(2)?, row.get::<_, bool>(3)?,
            row.get::<_, Option<String>>(4)?, row.get::<_, Option<String>>(5)?, row.get::<_, Option<bool>>(6)?, row.get::<_, Option<bool>>(7)?,
            row.get::<_, Option<bool>>(8)?, row.get::<_, Option<bool>>(9)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_ufs, in_script, y_ufs, y_scr, err_ufs, err_scr, scanned_ufs, scanned_scr) = r;
        if in_ufs {
            if y_ufs.is_none() && err_ufs != Some(true) && scanned_ufs != Some(true) { ufs_tasks.push(Task { id, rel_path: rel.clone(), is_common: in_ufs && in_script }); }
            else { skipped += 1; }
        }
        if in_script {
            if y_scr.is_none() && err_scr != Some(true) && scanned_scr != Some(true) { script_tasks.push(Task { id, rel_path: rel, is_common: in_ufs && in_script }); }
            else { skipped += 1; }
        }
    }
    drop(stmt);

    let total_db_rows = ufs_tasks.len() + script_tasks.len();

    if skipped > 0 {
        let _ = tx_ui.send(PhaseEvent::Log(format!("Pominięto {} plików już przeskanowanych YARA.", skipped)));
    }

    if total_db_rows == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak plików wymagających skanowania YARA. Baza aktualna.".to_string()));
        return Ok(());
    }

    let actual_threads = if config.max_threads > 0 { config.max_threads } else { rayon::current_num_threads() };
    let io_text = if config.io_mode == "CONCURRENT" { "RÓWNOLEGŁE" } else { "SEKWENCYJNIE" };
    let _ = tx_ui.send(PhaseEvent::Log(format!("Metodyka pracy szyny dyskowej: {}", io_text)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora (Rayon): {}", actual_threads)));

    // --- ETAP 2: INICJALIZACJA UI ---
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "UFS Explorer (YARA)".to_string(), total: ufs_tasks.len() as u64, color: Color::Cyan });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 1, label: "Skrypt Autorski (YARA)".to_string(), total: script_tasks.len() as u64, color: Color::Magenta });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 2, label: "Zapis SQLite".to_string(), total: total_db_rows as u64, color: Color::Green });

    let half_threads = compute_half_threads(actual_threads);
    let activity_slots = compute_activity_slots(&config.io_mode, actual_threads, half_threads);

    let ufs_stats = LiveStats::new(activity_slots);
    let script_stats = LiveStats::new(activity_slots);
    let ufs_base = PathBuf::from(&config.ufs_path);
    let script_base = PathBuf::from(&config.script_path);

    // --- ETAP 3: PRZETWARZANIE STRUMIENIOWE (MPSC) ---
    std::thread::scope(|s| {
        let (tx_db, rx_db) = mpsc::sync_channel(200);
        let conn_ref = &mut *conn;

        // KLONUJEMY NADAJNIK UI DLA WĄTKU BAZY DANYCH
        let tx_ui_db = tx_ui.clone();

        let _db_thread = s.spawn(move || {
            let mut db_inserted = 0;
            let mut last_db_update = Instant::now();

            let update_sql = |c: &mut Connection, chunk: &[SideYaraResult], is_ufs: bool| {
                let tx_db = c.transaction().unwrap();
                {
                    // OPTYMALIZACJA CPU: prepare_cached
                    let mut stmt_insert = tx_db.prepare_cached(
                        "INSERT OR REPLACE INTO phase16_analysis (file_id, yara_matched, rules_triggered) VALUES (?1, ?2, ?3)"
                    ).unwrap();

                    let mut stmt_update = match is_ufs {
                        true => tx_db.prepare_cached("UPDATE files SET yara_match_ufs = COALESCE(?1, yara_match_ufs), io_error_ufs = COALESCE(?2, io_error_ufs) WHERE id = ?3").unwrap(),
                        false => tx_db.prepare_cached("UPDATE files SET yara_match_script = COALESCE(?1, yara_match_script), io_error_script = COALESCE(?2, io_error_script) WHERE id = ?3").unwrap()
                    };

                    for res in chunk {
                        let matched = res.matches.is_some();
                        stmt_insert.execute(params![res.id, matched, res.matches]).unwrap();
                        stmt_update.execute(params![res.matches, res.io_error, res.id]).unwrap();
                    }
                }
                tx_db.commit().unwrap();
            };

            for msg in rx_db {
                let c_len = match &msg {
                    ScanMsg::UfsChunk(chunk) => { update_sql(conn_ref, chunk, true); chunk.len() },
                    ScanMsg::ScriptChunk(chunk) => { update_sql(conn_ref, chunk, false); chunk.len() },
                };
                
                db_inserted += c_len;
                let now = Instant::now();
                if now.duration_since(last_db_update).as_millis() > 60 {
                    last_db_update = now;
                    let _ = tx_ui_db.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Zapisywanie logów antywirusowych...".to_string() });
                }
            }
            let _ = tx_ui_db.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Pomyślnie zsynchronizowano z SQLite.".to_string() });
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone(); let tx2 = tx_db.clone();
            let inf_u = log_infected.clone(); let inf_s = log_infected.clone();
            
            // TWORZYMY REFERENCJE PRZED WĄTKIEM
            let stat_u = &ufs_stats;
            let stat_s = &script_stats;
            let rules_ref = &rules;

            // KLONUJEMY NADAJNIKI UI DLA WĄTKÓW I/O
            let tx_ui_1 = tx_ui.clone();
            let tx_ui_2 = tx_ui.clone();

            // NAPRAWA (ten sam bug jak w Fazie 5/6/7/10-15): dedykowana pula
            // per strona, minimum 1 wątek. Wyliczone wcześniej, tu tylko używane.

            s.spawn(move || { 
                if !ufs_tasks.is_empty() { 
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", rules: rules_ref, stats: stat_u, tx_db: tx1, is_ufs: true, start_time, tx_ui: &tx_ui_1, bar_idx: 0, log_infected: inf_u, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", rules: rules_ref, stats: stat_u, tx_db: tx1, is_ufs: true, start_time, tx_ui: &tx_ui_1, bar_idx: 0, log_infected: inf_u, });
                    }
                    let _ = tx_ui_1.send(PhaseEvent::Log("✔ Skanowanie UFS zakończone.".to_string())); 
                } 
            });
            s.spawn(move || { 
                if !script_tasks.is_empty() { 
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", rules: rules_ref, stats: stat_s, tx_db: tx2, is_ufs: false, start_time, tx_ui: &tx_ui_2, bar_idx: 1, log_infected: inf_s, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", rules: rules_ref, stats: stat_s, tx_db: tx2, is_ufs: false, start_time, tx_ui: &tx_ui_2, bar_idx: 1, log_infected: inf_s, });
                    }
                    let _ = tx_ui_2.send(PhaseEvent::Log("✔ Skanowanie Skrypt zakończone.".to_string())); 
                } 
            });
            drop(tx_db); 
        } else {
            let inf_u = log_infected.clone(); let inf_s = log_infected.clone();
            if !ufs_tasks.is_empty() { 
                process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", rules: &rules, stats: &ufs_stats, tx_db: tx_db.clone(), is_ufs: true, start_time, tx_ui: &tx_ui, bar_idx: 0, log_infected: inf_u, }); 
                let _ = tx_ui.send(PhaseEvent::Log("✔ Skanowanie UFS zakończone.".to_string())); 
            }
            if !script_tasks.is_empty() { 
                process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", rules: &rules, stats: &script_stats, tx_db, is_ufs: false, start_time, tx_ui: &tx_ui, bar_idx: 1, log_infected: inf_s, }); 
                let _ = tx_ui.send(PhaseEvent::Log("✔ Skanowanie Skrypt zakończone.".to_string())); 
            }
        }
    });

    // --- ETAP 4: SYNCHRONIZACJA Z BAZĄ DANYCH ---
    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log("🛑 Skanowanie przerwane przez użytkownika.".to_string()));
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::Log("Trwa wiązanie macierzy sygnatur w bazie SQLite...".to_string()));
    conn.execute(
        "UPDATE files SET phase16_done = CASE 
            WHEN (found_in_ufs = 0 OR yara_match_ufs IS NOT NULL OR io_error_ufs = 1) 
             AND (found_in_script = 0 OR yara_match_script IS NOT NULL OR io_error_script = 1) THEN 1 
            ELSE 0 
        END WHERE phase16_done = 0 OR phase16_done IS NULL", []
    )?;

    // --- ETAP 5: GENEROWANIE RAPORTU HIERARCHICZNEGO ---
    // NAPRAWIONE ŹRÓDŁO DANYCH: czytamy bezpośrednio z `files.yara_match_ufs`/
    // `yara_match_script` (osobne kolumny per strona, bez kolizji zapisu),
    // NIE z `phase16_analysis` (racuje przy plikach wspólnych — patrz
    // dokumentacja modułu). Każda strona pliku wspólnego jest teraz zliczana
    // NIEZALEŻNIE, obie zachowane.
    let mut stats_common_ufs = CategoryStats::new();
    let mut stats_common_scr = CategoryStats::new();
    let mut stats_unique_ufs = CategoryStats::new();
    let mut stats_unique_scr = CategoryStats::new();

    let mut stmt = conn.prepare(
        "SELECT relative_path, found_in_ufs, found_in_script, yara_match_ufs, yara_match_script 
         FROM files 
         WHERE phase16_done = 1 AND (yara_match_ufs IS NOT NULL OR yara_match_script IS NOT NULL)"
    )?;
    
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?, row.get::<_, bool>(1)?, row.get::<_, bool>(2)?,
            row.get::<_, Option<String>>(3)?, row.get::<_, Option<String>>(4)?,
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (path, in_ufs, in_scr, rules_ufs, rules_scr) = r;
        let is_common = in_ufs && in_scr;

        if let Some(r_list) = rules_ufs {
            for r_name in r_list.split(", ") {
                if is_common { stats_common_ufs.add(r_name, path.clone()); }
                else { stats_unique_ufs.add(r_name, path.clone()); }
            }
        }
        if let Some(r_list) = rules_scr {
            for r_name in r_list.split(", ") {
                if is_common { stats_common_scr.add(r_name, path.clone()); }
                else { stats_unique_scr.add(r_name, path.clone()); }
            }
        }
    }
    drop(stmt);

    let elapsed = start_time.elapsed();
    let total_bytes = ufs_stats.processed_bytes.load(Ordering::SeqCst) + script_stats.processed_bytes.load(Ordering::SeqCst);
    let avg_speed_mb = (total_bytes as f64 / 1_048_576.0) / elapsed.as_secs_f64().max(1.0);
    let total_io_errors = ufs_stats.errors.load(Ordering::SeqCst) + script_stats.errors.load(Ordering::SeqCst);

    // -- GENEROWANIE RAPORTU TEKSTOWEGO (Z ZAPISEM DO PLIKU) --
    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(&mut log_out, "==========================================================================");
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 16 (DETEKCJA SYGNATUR YARA)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "Sumaryczny transfer I/O: {} (Średnia prędkość: {:.2} MB/s)", format_bytes(total_bytes), avg_speed_mb);
    let _ = writeln!(&mut log_out, "==========================================================================\n");

    let total_infected = stats_common_ufs.count + stats_unique_ufs.count + stats_common_scr.count + stats_unique_scr.count;

    if total_infected == 0 {
        let _ = writeln!(&mut log_out, "[ ✔ ] Brak wykrytych zagrożeń. System nie odnalazł plików pasujących do wybranych reguł YARA.\n");
    } else {
        let _ = writeln!(&mut log_out, "[ 🚨 ] UWAGA! ODNALEZIONO {} ZAINFEKOWANYCH PLIKÓW:", total_infected);
        let _ = writeln!(&mut log_out, "   [ ZNACZENIE ]: Pliki wyzwoliły reguły YARA. Wskazuje to na potencjalną obecność kodu Malware, złośliwych makr lub skompilowanych skryptów.\n");
        
        let write_section_txt = |out: &mut String, title: &str, stats: &CategoryStats| {
            if stats.count > 0 {
                let _ = writeln!(out, "[ KATEGORIA ZNALEZISK: {} ]", title);
                write_category_block(out, stats);
            }
        };

        write_section_txt(&mut log_out, "Część Wspólna (UFS Explorer)", &stats_common_ufs);
        write_section_txt(&mut log_out, "Część Wspólna (Skrypt Autorski)", &stats_common_scr);
        write_section_txt(&mut log_out, "Osobne ścieżki (Tylko UFS Explorer)", &stats_unique_ufs);
        write_section_txt(&mut log_out, "Osobne ścieżki (Tylko Skrypt Autorski)", &stats_unique_scr);
    }

    if total_io_errors > 0 {
        let _ = writeln!(&mut log_out, "\n[ BŁĘDY FIZYCZNE I/O ]");
        let _ = writeln!(&mut log_out, "   -> Błędy odczytu dysku: {}", total_io_errors);
    }

    if let Ok(mut f) = fs::File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano fizyczny Dziennik Końcowy w: {}", dz_path.display())));
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano Raport Operacyjny (Live) w: {}", opr_path.display())));
    }

    // Wysyłamy również do Ratatui Log Panel
    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    // Zrzut telemetrii do głównego pliku logów w tle
    info!(
        infected_ufs = stats_common_ufs.count + stats_unique_ufs.count,
        infected_scr = stats_common_scr.count + stats_unique_scr.count,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 16 zakończona"
    );

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{NamedTempFile, tempdir};

    // ------------------------------------------------------------------
    // compute_activity_slots (identyczna logika z Fazy 3-7/10-15)
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_activity_slots_concurrent_uses_half_threads() {
        assert_eq!(compute_activity_slots("CONCURRENT", 4, 2), 2);
    }

    #[test]
    fn test_compute_activity_slots_sequential_uses_full_actual_threads() {
        assert_eq!(compute_activity_slots("SEQUENTIAL", 4, 2), 4);
    }

    // ------------------------------------------------------------------
    // CategoryStats
    // ------------------------------------------------------------------

    #[test]
    fn test_category_stats_accumulates_hits_per_rule() {
        let mut stats = CategoryStats::new();
        stats.add("EICAR_Test", "a.exe".to_string());
        stats.add("EICAR_Test", "b.exe".to_string());
        stats.add("Trojan.Generic", "c.exe".to_string());

        assert_eq!(stats.count, 3);
        assert_eq!(stats.rules.get("EICAR_Test").unwrap().0, 2);
        assert_eq!(stats.rules.get("Trojan.Generic").unwrap().0, 1);
    }

    #[test]
    fn test_category_stats_keeps_first_example_path() {
        let mut stats = CategoryStats::new();
        stats.add("RuleA", "pierwszy.exe".to_string());
        stats.add("RuleA", "drugi.exe".to_string());
        // or_insert ustawia przykładową ścieżkę TYLKO przy pierwszym wystąpieniu
        assert_eq!(stats.rules.get("RuleA").unwrap().1, "pierwszy.exe");
    }

    #[test]
    fn test_category_stats_empty_by_default() {
        let stats = CategoryStats::new();
        assert_eq!(stats.count, 0);
        assert!(stats.rules.is_empty());
    }

    // ------------------------------------------------------------------
    // write_category_block
    // ------------------------------------------------------------------

    #[test]
    fn test_write_category_block_empty_shows_checkmark() {
        let stats = CategoryStats::new();
        let mut out = String::new();
        write_category_block(&mut out, &stats);
        assert!(out.contains("Brak wykrytych zagrożeń"));
    }

    #[test]
    fn test_write_category_block_sorts_by_hit_count_descending() {
        let mut stats = CategoryStats::new();
        stats.add("Rzadka", "a.exe".to_string());
        stats.add("Czesta", "b.exe".to_string());
        stats.add("Czesta", "c.exe".to_string());
        stats.add("Czesta", "d.exe".to_string());

        let mut out = String::new();
        write_category_block(&mut out, &stats);

        let pos_czesta = out.find("Czesta").expect("powinno zawierać Czesta");
        let pos_rzadka = out.find("Rzadka").expect("powinno zawierać Rzadka");
        assert!(pos_czesta < pos_rzadka, "Reguła z większą liczbą trafień powinna być wymieniona pierwsza");
    }

    // ------------------------------------------------------------------
    // compute_half_threads
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_half_threads() {
        assert_eq!(compute_half_threads(8), 4);
        assert_eq!(compute_half_threads(1), 1);
    }

    // ------------------------------------------------------------------
    // build_source_block
    // ------------------------------------------------------------------

    #[test]
    fn test_build_source_block_reports_top_rules_and_multi_rule_count() {
        use std::time::Duration;
        let stats = LiveStats::new(4);
        stats.clean.store(100, Ordering::Relaxed);
        stats.infected.store(5, Ordering::Relaxed);
        stats.multi_rule_files.store(2, Ordering::Relaxed);
        stats.top_rules.lock().unwrap().insert("EICAR_Test".to_string(), 3);
        stats.top_rules.lock().unwrap().insert("Trojan.Generic".to_string(), 8);

        let start_time = Instant::now() - Duration::from_secs(1);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        assert!(block.contains("Czyste: 100"));
        assert!(block.contains("Zainfekowane: 5"));
        assert!(block.contains("Wiele reguł jednocześnie: 2"));
        // Trojan.Generic (8) powinien pojawić się przed EICAR_Test (3)
        let pos_trojan = block.find("Trojan.Generic (8)").expect("powinien zawierać Trojan.Generic");
        let pos_eicar = block.find("EICAR_Test (3)").expect("powinien zawierać EICAR_Test");
        assert!(pos_trojan < pos_eicar);
    }

    #[test]
    fn test_build_source_block_shows_thread_activity_markup() {
        use std::time::Duration;
        let stats = LiveStats::new(2);
        stats.thread_activity.mark_busy(0);
        stats.thread_activity.mark_busy(1);

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("Skrypt Autorski", &stats, start_time);

        let line = block.lines().find(|l| l.starts_with("Wątki YARA")).expect("powinna istnieć linia Wariantu A");
        assert_eq!(line, "Wątki YARA (Wariant A): {G:1} {G:2}");
    }

    #[test]
    fn test_build_source_block_placeholder_when_no_rules_triggered() {
        use std::time::Duration;
        let stats = LiveStats::new(4);
        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("Skrypt Autorski", &stats, start_time);
        assert!(block.contains("Top reguły (live): -"));
    }

    // ------------------------------------------------------------------
    // compile_rule_files: kompilacja z prawdziwych plików .yar na dysku
    // ------------------------------------------------------------------

    #[test]
    fn test_compile_rule_files_valid_rule_succeeds() {
        let dir = tempdir().unwrap();
        let rule_path = dir.path().join("test.yar");
        std::fs::write(&rule_path, r#"
            rule valid_rule {
                strings:
                    $a = "TESTOWY_LADUNEK"
                condition:
                    $a
            }
        "#).unwrap();

        let result = compile_rule_files(&[rule_path]);
        assert!(result.is_some(), "Poprawna reguła powinna się skompilować");
    }

    #[test]
    fn test_compile_rule_files_syntax_error_returns_none() {
        let dir = tempdir().unwrap();
        let rule_path = dir.path().join("zla_skladnia.yar");
        std::fs::write(&rule_path, "to nie jest poprawna regula yara { } (((").unwrap();

        let result = compile_rule_files(&[rule_path]);
        assert!(result.is_none(), "Błędna składnia powinna zwrócić None, nie panikować");
    }

    #[test]
    fn test_compile_rule_files_empty_list_still_compiles() {
        // Pusta lista reguł to poprawny (choć bezużyteczny) zestaw - kompilator
        // nie powinien się na tym wywalić.
        let result = compile_rule_files(&[]);
        assert!(result.is_some());
    }

    // ------------------------------------------------------------------
    // scan_file_yara: PRAWDZIWA kompilacja reguły YARA i skanowanie w locie
    // ------------------------------------------------------------------

    /// Kompiluje trywialną regułę YARA szukającą stałego ciągu znaków -
    /// bez zależności od zewnętrznych plików .yar na dysku.
    fn compile_test_rule() -> Rules {
        let rule_src = r#"
            rule test_marker {
                strings:
                    $a = "MALWARE_TEST_MARKER_XYZ"
                condition:
                    $a
            }
        "#;
        let compiler = Compiler::new().unwrap();
        let compiler = compiler.add_rules_str(rule_src).expect("Reguła testowa powinna się skompilować");
        compiler.compile_rules().expect("Kompilacja reguł powinna się powieść")
    }

    #[test]
    fn test_scan_file_yara_detects_matching_content() {
        let rules = compile_test_rule();
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"jakas tresc przed MALWARE_TEST_MARKER_XYZ i po nim").unwrap();

        let result = scan_file_yara(f.path(), "test.bin", "UFS Explorer", &rules);
        let matched = result.expect("Skanowanie nie powinno zwrócić błędu");
        assert_eq!(matched, Some("test_marker".to_string()));
    }

    #[test]
    fn test_scan_file_yara_clean_file_returns_none() {
        let rules = compile_test_rule();
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"zupelnie niewinna zawartosc pliku bez zadnych sygnatur").unwrap();

        let result = scan_file_yara(f.path(), "test.bin", "UFS Explorer", &rules);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_scan_file_yara_nonexistent_file_is_error() {
        let rules = compile_test_rule();
        let result = scan_file_yara(Path::new("/nieistniejaca/sciezka/plik.exe"), "plik.exe", "UFS Explorer", &rules);
        assert!(result.is_err());
    }
}
