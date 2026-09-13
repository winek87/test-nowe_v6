// src/phases/phase17_repair.rs

//! # Faza 17: Aktywne Moduły Naprawcze (Active Data Repair)
//!
//! Fizyczna rekonstrukcja zniszczonych plików. Orkiestrator dobiera zadania
//! na podstawie diagnostyki zebranej w poprzednich fazach i deleguje samą
//! naprawę do niezależnych MODUŁÓW (`repair_modules/`) — Header Injection
//! (JPG/PNG), Text Sanitization, SQLite Checkpointing, Extension Fix,
//! Trailer Trim, Splicing. Użytkownik wybiera, które moduły są aktywne
//! (analogicznie do wyboru reguł YARA w Fazie 16), domyślnie wszystkie.
//!
//! UWAGA ARCHITEKTONICZNA (MODUŁOWOŚĆ): dodanie NOWEJ metody naprawczej to
//! nowy plik w `repair_modules/` implementujący `RepairModule` + jedna linia
//! w `repair_modules::all_modules()`. Orkiestrator nie zna żadnych
//! szczegółów konkretnej naprawy — patrz `repair_modules/mod.rs`.
//!
//! NAPRAWIONY BUG (zły plik źródłowy dla strony Skrypt): oryginalna funkcja
//! przetwarzająca przyjmowała JEDEN `base_path` dla CAŁEJ listy zadań
//! (zarówno `side: "ufs"`, jak i `side: "script"`), zawsze `ufs_base`.
//! Wszystkie naprawy inne niż zszywanie (tekst/nagłówek/rozszerzenie/SQLite)
//! dla plików ze strony Skrypt czytały plik z KATALOGU UFS, nie ze Skryptu —
//! błędne źródło danych dla całej tej klasy napraw. Zszywanie działało
//! przypadkiem poprawnie, bo kwalifikujące się do niego zadania zawsze mają
//! `side: "ufs"` z konstrukcji zapytania (korelacja Fazy 14 dla plików
//! unikalnych populuje `twin_file_path` wyłącznie dla wpisów jednostronnych
//! UFS). Naprawione: katalog bazowy wybierany per `task.side`.
//!
//! NAPRAWIONY BUG (martwa naprawa rozszerzeń): patrz
//! `repair_modules::extension` — `true_mime` nigdy nie było wypełniane,
//! więc ta naprawa nigdy się nie uruchamiała.
//!
//! NAPRAWIONY BUG (zapis w korpusie źródłowym): moduły naprawcze wyliczały
//! miejsce zapisu jako `source.parent()`, czyli tworzyły pliki `*_repaired.*`
//! OBOK oryginałów — w środku analizowanego korpusu, który jest materiałem
//! dowodowym tylko do odczytu (zasady katalogów: zapisywać wolno wyłącznie w
//! `/praca/`). Drugi, cichszy skutek: nigdzie nie ma filtra na te sufiksy, więc
//! kolejne mapowanie struktury (Faza 1) zliczało naprawione kopie jako
//! SAMODZIELNE pliki korpusu. Teraz orkiestrator wskazuje katalog wyjściowy w
//! przestrzeni roboczej pod `target_path` (patrz [`KATALOG_NAPRAW`] i
//! [`katalog_naprawy`]), a do bazy trafia ścieżka ABSOLUTNA — tak samo jak
//! `smart_splice_path` z Fazy 18. Faza 9 obsługuje oba formaty, żeby nie
//! unieważnić baz zapisanych wcześniej (patrz `phase9::sciezka_naprawiona`).
//!
//! NAPRAWIONY BRAK (`phase17_done` nigdy nie ustawiane): zapis do bazy
//! aktualizował wyłącznie `repaired_path_*`/`repair_log_*`, więc flaga
//! ukończenia zostawała na zawsze zerowa. Skutki: partycjonowany indeks
//! `idx_phase17_done` był bezużyteczny, reset tej flagi w `reset` nic nie
//! robił, diagnostyka musiała liczyć postęp po kolumnie `id` (pokazując liczbę
//! WSZYSTKICH plików w bazie), a sama faza przy każdym uruchomieniu mielila od
//! nowa CAŁĄ listę plików — nie była wznawialna, w odróżnieniu od wszystkich
//! pozostałych faz.
//!
//! Teraz rekord do bazy idzie dla KAŻDEGO przetworzonego zadania, także gdy
//! żaden moduł nie pomógł (`repaired_path: None`), i ustawia `phase17_done`.
//! Zapytanie dobierające zadania filtruje po tej fladze, więc powtórne
//! uruchomienie kontynuuje pracę, zamiast powtarzać ją w całości.
//!
//! UWAGA: pliki, dla których ŻADEN aktywny moduł nie pasuje, celowo NIE są
//! oznaczane — nie powstaje dla nich zadanie. To zamierzone: po zmianie
//! zestawu aktywnych modułów stają się ponownie kandydatami, a ich ponowne
//! rozpatrzenie jest darmowe (samo `applies_to`, zero I/O).
//!
//! NAPRAWIONY BRAK (weryfikacja wyniku): Faza 18 od początku miała obowiązkową
//! weryfikację kandydata przed zapisem i właśnie dlatego wolno jej było
//! działać automatycznie. Faza 17 nie miała ŻADNEJ — moduł zwracał `Some`,
//! plik trafiał do bazy jako „naprawiony", a Faza 9 kopiowała go do Złotej
//! Kopii, JAWNIE pomijając przy tym kontrolę rozmiaru dla plików naprawionych
//! (`phase9::copy_file_and_meta`). Nic w łańcuchu nie sprawdzało, czy naprawa
//! cokolwiek naprawiła. Teraz po KAŻDEJ udanej naprawie wołane jest
//! `RepairModule::verify`; wynik odrzucony jest usuwany z dysku, nie trafia do
//! bazy i jest liczony osobno (`rejected_by_verification`).

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::{format_display_path, CANCEL_SIGNAL};
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
use tracing::{info, instrument, warn};
use colored::Colorize;

use super::repair_modules::{self, RepairContext, RepairModule};

const CHUNK_SIZE: usize = 100;

/// Podkatalog w przestrzeni roboczej (`config.target_path`), w którym lądują
/// WSZYSTKIE pliki wytworzone przez moduły naprawcze.
///
/// Konwencja zgodna z Fazą 18 (`_smart_splice_repaired`) i narzędziem DNG
/// (`_dng_structural_review`) — te fazy od początku zapisywały poza korpusem.
const KATALOG_NAPRAW: &str = "_phase17_repaired";

/// Buduje i tworzy na dysku katalog wyjściowy dla naprawionych plików JEDNEGO
/// zadania: `<baza>/<strona>/<katalogi z rel_path>`.
///
/// ## Dlaczego struktura katalogów musi być odwzorowana
///
/// Nazwa wynikowa to `<stem>_repaired.<ext>`, więc `foto/a.jpg` i `skany/a.jpg`
/// dałyby w płaskim katalogu ten sam `a_repaired.jpg` — drugi plik nadpisałby
/// pierwszy, cicho tracąc jedną z napraw. Przy zapisie obok oryginału problem
/// nie istniał, bo katalogi źródłowe były różne.
///
/// Podział per STRONA jest konieczny z tego samego powodu: ten sam `rel_path`
/// istnieje po stronie UFS i Skryptu, Faza 17 tworzy zadanie dla każdej z nich
/// osobno i obie mogą zostać naprawione.
fn katalog_naprawy(baza: &Path, strona: &str, rel_path: &str) -> Option<PathBuf> {
    let mut katalog = baza.join(strona);

    if let Some(rodzic) = Path::new(rel_path).parent()
        && !rodzic.as_os_str().is_empty() {
            katalog = katalog.join(rodzic);
        }

    fs::create_dir_all(&katalog).ok()?;
    Some(katalog)
}

// ============================================================================
// STRUKTURY DANYCH
// ============================================================================

/// Pojedyncze zadanie naprawcze dla JEDNEJ strony jednego pliku. Niesie
/// całą diagnostykę potrzebną do zbudowania [`RepairContext`] w wątku
/// przetwarzającym — same dane, bez logiki decyzyjnej (ta żyje w modułach).
#[derive(Debug, Clone)]
pub(crate) struct RepairTask {
    id: i32,
    rel_path: String,
    side: &'static str,
    ext: String,
    media_reason: Option<String>,
    utf8_ok: Option<bool>,
    is_oneliner: Option<bool>,
    eof_ok: Option<bool>,
    match_type: Option<String>,
    twin_path: Option<String>,
    /// Diagnoza kontenera wideo z Fazy 19 dla TEJ strony — sygnał dla modułów
    /// naprawy MP4 (patrz `repair_modules::mp4`).
    video_ok: Option<bool>,
    /// Wynik walidacji struktury archiwum z Fazy 11 dla TEJ strony — sygnał
    /// dla modułów naprawy ZIP i TAR (patrz `repair_modules::zip` i `::tar`).
    structure_ok: Option<bool>,
}

impl RepairTask {
    fn context(&self) -> RepairContext<'_> {
        RepairContext {
            ext: &self.ext,
            media_reason: self.media_reason.as_deref(),
            utf8_ok: self.utf8_ok,
            is_oneliner: self.is_oneliner,
            eof_ok: self.eof_ok,
            match_type: self.match_type.as_deref(),
            video_ok: self.video_ok,
            structure_ok: self.structure_ok,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RepairResult {
    id: i32,
    side: &'static str,
    /// `None`, gdy ŻADEN aktywny moduł nie naprawił pliku.
    ///
    /// Rekord jest wysyłany do wątku zapisu RÓWNIEŻ w tym przypadku — inaczej
    /// nie dałoby się oznaczyć `phase17_done`, bo plik bez naprawy nie
    /// generowałby żadnego wpisu do bazy. Patrz dokumentacja modułu.
    repaired_path: Option<String>,
    repair_log: Option<String>,
}

pub(crate) enum ScanMsg {
    Chunk(Vec<RepairResult>),
}

/// Liczniki live. `repairs_by_module` jest GENERYCZNA — zliczana po
/// `module.id()` zwróconym przez orkiestrator, więc nowy moduł dodany do
/// rejestru automatycznie dostaje własny licznik w panelu bocznym, bez
/// żadnej zmiany w tym pliku.
pub(crate) struct LiveStats {
    total_processed: AtomicUsize,
    errors: AtomicUsize,
    /// Naprawy, które moduł wykonał, ale które NIE PRZESZŁY obowiązkowej
    /// weryfikacji wyniku — plik został usunięty i nie trafił do bazy. Liczone
    /// osobno od `errors`, bo to zupełnie inna informacja śledcza: moduł
    /// zadziałał technicznie, ale wynik okazał się niesprawny.
    rejected_by_verification: AtomicUsize,
    repairs_by_module: Mutex<HashMap<&'static str, usize>>,
    /// EKSPERYMENTALNE (Wariant A): śledzi zajętość logicznych slotów Rayon —
    /// ta sama konwencja i ten sam tracker, co w pozostałych fazach
    /// równoległych, patrz `thread_activity`.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            total_processed: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            rejected_by_verification: AtomicUsize::new(0),
            repairs_by_module: Mutex::new(HashMap::new()),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }

    /// Dostęp do mapy liczników ODPORNY NA ZATRUCIE muteksa.
    ///
    /// Zatrucie (`PoisonError`) znaczy tylko tyle, że któryś wątek spanikował
    /// trzymając blokadę. Sama mapa to zwykłe liczniki — nie ma stanu, który
    /// mógłby przez to stracić spójność — więc `into_inner()` jest tu
    /// właściwym zachowaniem. Wcześniejsze `.lock().unwrap()` zamieniało cudzą
    /// panikę w KOLEJNĄ panikę, i to w wątku Rayon, wywracając całą fazę
    /// zamiast dokończyć pracę i zaraportować wynik.
    fn liczniki(&self) -> std::sync::MutexGuard<'_, HashMap<&'static str, usize>> {
        self.repairs_by_module.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Buduje panel boczny "Podsumowanie na żywo": prędkość (plików/s), licznik
/// napraw PER MODUŁ (generyczny — patrz [`LiveStats`]), błędy.
fn build_source_block(stats: &LiveStats, start_time: Instant) -> String {
    let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
    let current = stats.total_processed.load(Ordering::Relaxed);
    let speed = current as f64 / elapsed;

    let modules_str = {
        let map = stats.liczniki();
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.into_iter().map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\n")
    };
    let display_modules = if modules_str.is_empty() { "-".to_string() } else { modules_str };

    format!(
        "[Podsumowanie]\nPrędkość: {:.1} plików/s\nPrzetworzone: {}\n{}\nOdrzucone przez weryfikację: {}\nWątki naprawy (Wariant A): {}\nBłędy (żaden moduł nie pomógł): {}",
        speed, current, display_modules,
        stats.rejected_by_verification.load(Ordering::Relaxed),
        crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot()),
        stats.errors.load(Ordering::Relaxed),
    )
}

// ============================================================================
// WĄTEK PRZETWARZANIA (I/O)
// ============================================================================

/// Przetwarza wszystkie zadania: dla każdego buduje [`RepairContext`],
/// wybiera właściwy katalog bazowy PER `task.side` (patrz naprawiony bug w
/// dokumentacji modułu) i próbuje kolejne AKTYWNE moduły z `active_modules`
/// w kolejności priorytetu, aż jeden zwróci sukces. Rozgłasza postęp co
/// ~20 plików LUB co 250ms (hybrydowy próg — wzorzec z Fazy 5-7/10-16).
pub struct RepairCtx<'a> {
    pub ufs_base: &'a Path,
    pub script_base: &'a Path,
    pub repair_base: &'a Path,
    pub active_modules: &'a [&'a dyn RepairModule],
    pub tasks: &'a [RepairTask],
    pub stats: &'a LiveStats,
    pub tx_db: mpsc::SyncSender<ScanMsg>,
    pub tx_ui: &'a mpsc::Sender<PhaseEvent>,
    pub bar_idx: usize,
    pub start_time: Instant,
    pub opr_log: Arc<Mutex<File>>,
}

#[instrument(skip(ctx))]

fn process_repair_stream<'a>(ctx: RepairCtx<'a>) {
    let RepairCtx { ufs_base, script_base, repair_base, active_modules, tasks, stats, tx_db, tx_ui, bar_idx, start_time, opr_log } = ctx;

    let last_ui_update = Arc::new(AtomicU64::new(0));

    tasks.par_chunks(CHUNK_SIZE).for_each_with(tx_db, |tx_db, chunk| {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

        let mut results = Vec::new();
        let mut local_module_counts: HashMap<&'static str, usize> = HashMap::new();

        for task in chunk {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }
            // Wariant A: slot zajęty na czas obsługi tego pliku. Strażnik RAII
            // zwalnia go także przy panice w środku pracy.
            let _slot = stats.thread_activity.enter_current();

            // Katalog bazowy WYBRANY PER STRONA - patrz naprawiony bug w dokumentacji modułu.
            let own_base = if task.side == "ufs" { ufs_base } else { script_base };
            let other_base = if task.side == "ufs" { script_base } else { ufs_base };

            let full_path = own_base.join(&task.rel_path);
            let twin_full = task.twin_path.as_ref().map(|p| other_base.join(p));
            let ctx = task.context();

            // Naprawione pliki NIE trafiają obok oryginału (korpus jest
            // materiałem dowodowym tylko do odczytu) — patrz `katalog_naprawy`.
            // Gdy katalogu nie da się utworzyć, `result_opt` zostaje `None` i
            // zadanie wpada w zwykłą ścieżkę błędu niżej.
            let katalog_wyjsciowy = katalog_naprawy(repair_base, task.side, &task.rel_path);

            let mut result_opt: Option<(&'static str, PathBuf, String)> = None;
            for module in active_modules {
                if !module.applies_to(&ctx) { continue; }

                let Some(katalog) = katalog_wyjsciowy.as_deref() else { break };
                let Some((new_path, log)) = module.repair(&full_path, &ctx, twin_full.as_deref(), katalog) else { continue };

                // OBOWIĄZKOWA WERYFIKACJA WYNIKU (patrz `RepairModule::verify`).
                // Bez niej naprawiony plik szedł do bazy i dalej do Złotej
                // Kopii bez żadnego dowodu sprawności — a Faza 9 pomija dla
                // takich plików nawet kontrolę rozmiaru.
                match module.verify(&new_path, &ctx) {
                    Ok(dowod) => {
                        result_opt = Some((module.id(), new_path, format!("{} | Weryfikacja: {}", log, dowod)));
                        break;
                    }
                    Err(powod) => {
                        // Niesprawny wynik NIE MOŻE zostać na dysku: wyglądałby
                        // na gotową naprawę przy ręcznej analizie i przy
                        // kolejnym mapowaniu struktury.
                        let _ = fs::remove_file(&new_path);
                        stats.rejected_by_verification.fetch_add(1, Ordering::Relaxed);

                        if let Ok(mut f) = opr_log.lock() {
                            let _ = writeln!(
                                f, "[✖] [{}] {} | ODRZUCONO PRZEZ WERYFIKACJĘ: {}",
                                module.id(), task.rel_path, powod
                            );
                        }
                        // Próbujemy KOLEJNEGO pasującego modułu - tak samo jak
                        // przy porażce fizycznej samej naprawy.
                    }
                }
            }

            let current = stats.total_processed.fetch_add(1, Ordering::Relaxed) + 1;

            if let Some((module_id, new_p, log_msg)) = result_opt {
                *local_module_counts.entry(module_id).or_insert(0) += 1;

                // Ścieżka ABSOLUTNA. Naprawiony plik leży w przestrzeni
                // roboczej pod `target_path`, a nie pod bazą źródłową, więc nie
                // da się go wyrazić relatywnie względem `ufs_path`/`script_path`
                // — a właśnie tak Faza 9 rozwiązywała dotąd `repaired_path_*`.
                // Ten sam wzorzec co `smart_splice_path` z Fazy 18, które od
                // początku jest absolutne (patrz `phase9::copy_file_and_meta`).
                let clean_path = new_p.to_string_lossy().to_string();

                if let Ok(mut f) = opr_log.lock() {
                    let _ = writeln!(f, "[✔] [{}] {} | {}", module_id, clean_path, log_msg);
                }

                results.push(RepairResult {
                    id: task.id,
                    side: task.side,
                    repaired_path: Some(clean_path),
                    repair_log: Some(log_msg),
                });
            } else {
                stats.errors.fetch_add(1, Ordering::Relaxed);

                // Plik PRZETWORZONY, choć nienaprawiony — rekord idzie do bazy
                // po to, żeby oznaczyć `phase17_done`. Bez tego flaga nigdy nie
                // była ustawiana i faza mielila od nowa całą listę przy każdym
                // uruchomieniu (patrz dokumentacja modułu).
                results.push(RepairResult {
                    id: task.id,
                    side: task.side,
                    repaired_path: None,
                    repair_log: None,
                });
            }

            let now_ms = start_time.elapsed().as_millis() as u64;
            let last_ms = last_ui_update.load(Ordering::Relaxed);
            let should_update = current.is_multiple_of(20) || now_ms.saturating_sub(last_ms) > 250;

            if should_update && last_ui_update.compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                if !local_module_counts.is_empty() {
                    let mut g_map = stats.liczniki();
                    for (k, v) in local_module_counts.drain() { *g_map.entry(k).or_insert(0) += v; }
                }

                // PASEK: wyłącznie postęp + bieżący plik (bez liczników)
                let _ = tx_ui.send(PhaseEvent::UpdateBar {
                    idx: bar_idx,
                    current: current as u64,
                    message: format_display_path(&task.rel_path),
                });

                // PANEL BOCZNY: pełne podsumowanie (generyczne, per moduł)
                let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                    idx: bar_idx,
                    text: build_source_block(stats, start_time),
                });
            }
        }

        if !local_module_counts.is_empty() {
            let mut g_map = stats.liczniki();
            for (k, v) in local_module_counts.drain() { *g_map.entry(k).or_insert(0) += v; }
        }

        if !results.is_empty() {
            let _ = tx_db.send(ScanMsg::Chunk(results));
        }
    });

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: stats.total_processed.load(Ordering::Relaxed) as u64,
        message: "Inżynieria plików zakończona.".to_string(),
    });
}

// ============================================================================
// GŁÓWNA FUNKCJA KORDYNUJĄCA (Entrypoint Fazy 17)
// ============================================================================

/// Zwraca identyfikatory WSZYSTKICH zarejestrowanych modułów naprawczych,
/// bez żadnego pytania użytkownika — używane przez Autopilota (przebieg
/// bezobsługowy, nie ma kto odpowiedzieć na `MultiSelect`) oraz jako
/// domyślny zestaw "wszystko aktywne".
pub fn all_module_ids() -> Vec<&'static str> {
    repair_modules::all_modules().iter().map(|m| m.id()).collect()
}

/// Pokazuje `MultiSelect` z listą dostępnych modułów naprawczych i zwraca
/// identyfikatory wybranych. MUSI być wołane PRZED wejściem w tryb Raw
/// Ratatui (z `actions.rs`, w tym samym zawieszonym CLI co `diag`/`reset`) —
/// patrz identyczne uzasadnienie w `phase16::select_and_compile_rules`
/// (konflikt `dialoguer` z aktywnym ekranem Ratatui, obserwowany jako
/// całkowity brak promptu wyboru na ekranie fazy). Zwraca `None`, gdy
/// użytkownik nic nie wybrał — wywołujący powinien wtedy pominąć Fazę 17
/// bez w ogóle wchodzenia w ekran Ratatui.
pub fn select_active_module_ids() -> Option<Vec<&'static str>> {
    let modules = repair_modules::all_modules();
    let module_labels: Vec<String> = modules.iter().map(|m| m.display_name().to_string()).collect();
    let defaults = vec![true; modules.len()];

    println!("\n{}", "[ 🧰 ] DOSTĘPNE MODUŁY NAPRAWCZE".cyan().bold());
    let selections = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Wybierz aktywne moduły (Spacja = zaznacz/odznacz, ENTER = zatwierdź; domyślnie wszystkie)")
        .items(&module_labels)
        .defaults(&defaults)
        .interact_opt()
        .unwrap_or(None);

    let selected_indices = match selections {
        Some(s) if !s.is_empty() => s,
        _ => {
            println!("{}", "[ ℹ ] Nie wybrano żadnych modułów naprawczych. Pomijam Fazę 17.".bright_black());
            return None;
        }
    };

    let ids: Vec<&'static str> = selected_indices.iter().map(|&i| modules[i].id()).collect();
    println!("{}\n", "[ ✔ ] Moduły naprawcze aktywowane.".green());
    Some(ids)
}

/// Punkt wejścia Fazy 17, wołany przez `menu::actions::run_phase_with_ui`.
/// Przyjmuje JUŻ WYBRANE identyfikatory aktywnych modułów (patrz
/// [`select_active_module_ids`]/[`all_module_ids`] wołane przez wywołującego
/// PRZED wejściem w tryb Raw) — ta funkcja sama nie robi już żadnej
/// interakcji z użytkownikiem.
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>, active_module_ids: Vec<&'static str>) -> Result<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    let modules = repair_modules::all_modules();
    let active_modules: Vec<&dyn RepairModule> = modules.iter()
        .filter(|m| active_module_ids.contains(&m.id()))
        .map(|m| m.as_ref())
        .collect();

    if active_modules.is_empty() {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak aktywnych modułów naprawczych. Faza 17 pominięta.".to_string()));
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::Log("Uruchomiono Fazę 17: Aktywne Moduły Naprawcze (Active Repair).".to_string()));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne moduły: {}", active_modules.iter().map(|m| m.display_name()).collect::<Vec<_>>().join(", "))));

    // Stan `ffmpeg` meldowany RAZ, na wejściu — od niego zależy zarówno
    // dostępność przepakowania kontenera, jak i SIŁA weryfikacji napraw wideo.
    // Bez tego komunikatu operator nie miał jak odróżnić „naprawy nie działają"
    // od „brakuje binarki w systemie".
    if active_modules.iter().any(|m| m.id().starts_with("mp4_")) {
        if crate::mp4_repair::validator::ffmpeg_dostepny() {
            let _ = tx_ui.send(PhaseEvent::Log(
                "✔ ffmpeg/ffprobe dostępne — naprawy wideo weryfikowane PEŁNYM DEKODOWANIEM klatek.".to_string()
            ));
        } else {
            let _ = tx_ui.send(PhaseEvent::Log(
                "⚠ BRAK ffmpeg/ffprobe — przepakowanie kontenera niedostępne, a naprawy wideo weryfikowane tylko STRUKTURALNIE (gwarancja słabsza).".to_string()
            ));
            warn!("Faza 17: brak ffmpeg/ffprobe - obniżona gwarancja weryfikacji napraw wideo");
        }
    }

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    let _ = conn.execute("ALTER TABLE files ADD COLUMN repaired_path_ufs TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN repaired_path_script TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN repair_log_ufs TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN repair_log_script TEXT", []);

    // INICJALIZACJA DUAL-LOGGING (Pobieranie ścieżek z Ustawień)
    let raport_cfg = config.raporty_faz.get("Faza 17").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza17.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza17.txt".to_string(),
    });

    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);

    // Brak pliku raportu operacyjnego to nie powód do paniki — melduje się go
    // użytkownikowi i przerywa fazę czysto, tym samym wzorcem co niemożliwość
    // utworzenia katalogu docelowego w Fazie 9. Faza 17 FIZYCZNIE modyfikuje
    // dane, więc uruchamianie jej bez ewidencji operacji byłoby gorsze niż
    // nieuruchomienie wcale.
    let opr_file = match File::create(&opr_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!(
                "BŁĄD KRYTYCZNY: nie udało się utworzyć raportu operacyjnego ({}): {}. Faza 17 przerwana — nie prowadzimy napraw bez ewidencji.",
                opr_path.display(), e
            )));
            return Ok(());
        }
    };

    let opr_log = Arc::new(Mutex::new(opr_file));
    if let Ok(mut f_info) = opr_log.lock() {
        let _ = writeln!(f_info, "=== RAPORT OPERACYJNY - FAZA 17: AKTYWNE MODUŁY NAPRAWCZE ===");
        let _ = writeln!(f_info, "Ewidencja plików, które zostały fizycznie naprawione przez skrypt (utworzono nowe pliki z sufiksem _repaired/_spliced na dysku).\n");
    }

    // --- LOGIKA DOBIERANIA ZADAŃ (na podstawie wskaźników z poprzednich faz) ---
    let mut stmt = conn.prepare(
        "SELECT f.id, f.relative_path, f.found_in_ufs, f.found_in_script,
                f.media_reason_ufs, f.media_reason_script,
                f.utf8_ok_ufs, f.utf8_ok_script, f.is_oneliner_ufs, f.is_oneliner_script,
                f.eof_ok_ufs, f.eof_ok_script,
                f.video_ok_ufs, f.video_ok_script,
                f.structure_ok_ufs, f.structure_ok_script,
                a.match_type, a.twin_file_path
         FROM files f 
         LEFT JOIN phase14_analysis a ON f.id = a.file_id
         WHERE f.phase17_done = 0 OR f.phase17_done IS NULL"
    )?;

    let mut repair_tasks = Vec::new();

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i32>(0)?, row.get::<_, String>(1)?,
            row.get::<_, bool>(2)?, row.get::<_, bool>(3)?,
            row.get::<_, Option<String>>(4)?, row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<bool>>(6)?, row.get::<_, Option<bool>>(7)?,
            row.get::<_, Option<bool>>(8)?, row.get::<_, Option<bool>>(9)?,
            row.get::<_, Option<bool>>(10)?, row.get::<_, Option<bool>>(11)?,
            row.get::<_, Option<bool>>(12)?, row.get::<_, Option<bool>>(13)?,
            row.get::<_, Option<bool>>(14)?, row.get::<_, Option<bool>>(15)?,
            row.get::<_, Option<String>>(16)?, row.get::<_, Option<String>>(17)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_ufs, in_scr, m_rs_u, m_rs_s, utf_u, utf_s, one_u, one_s, eof_u, eof_s, vid_u, vid_s, str_u, str_s, match_type, twin) = r;
        let ext = Path::new(&rel).extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();

        if in_ufs {
            let ctx = RepairContext { ext: &ext, media_reason: m_rs_u.as_deref(), utf8_ok: utf_u, is_oneliner: one_u, eof_ok: eof_u, match_type: match_type.as_deref(), video_ok: vid_u, structure_ok: str_u };
            if active_modules.iter().any(|m| m.applies_to(&ctx)) {
                repair_tasks.push(RepairTask {
                    id, rel_path: rel.clone(), side: "ufs", ext: ext.clone(),
                    media_reason: m_rs_u, utf8_ok: utf_u, is_oneliner: one_u, eof_ok: eof_u,
                    match_type: match_type.clone(), twin_path: twin.clone(),
                    video_ok: vid_u, structure_ok: str_u,
                });
            }
        }

        if in_scr {
            let ctx = RepairContext { ext: &ext, media_reason: m_rs_s.as_deref(), utf8_ok: utf_s, is_oneliner: one_s, eof_ok: eof_s, match_type: match_type.as_deref(), video_ok: vid_s, structure_ok: str_s };
            if active_modules.iter().any(|m| m.applies_to(&ctx)) {
                repair_tasks.push(RepairTask {
                    id, rel_path: rel.clone(), side: "script", ext,
                    media_reason: m_rs_s, utf8_ok: utf_s, is_oneliner: one_s, eof_ok: eof_s,
                    match_type, twin_path: twin,
                    video_ok: vid_s, structure_ok: str_s,
                });
            }
        }
    }
    drop(stmt);

    if repair_tasks.is_empty() {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak plików kwalifikujących się do fizycznej naprawy. Baza w 100% czysta.".to_string()));
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "Silnik Rekonstrukcji Danych (I/O)".to_string(), total: repair_tasks.len() as u64, color: Color::Red });

    let ufs_base = PathBuf::from(&config.ufs_path);
    let script_base = PathBuf::from(&config.script_path);

    // Przestrzeń robocza napraw — POZA korpusem źródłowym.
    let repair_base = PathBuf::from(&config.target_path).join(KATALOG_NAPRAW);
    if let Err(e) = fs::create_dir_all(&repair_base) {
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "BŁĄD KRYTYCZNY: nie udało się utworzyć katalogu napraw ({}): {}. Faza 17 przerwana.",
            repair_base.display(), e
        )));
        return Ok(());
    }
    let _ = tx_ui.send(PhaseEvent::Log(format!("Naprawione pliki będą zapisywane w: {}", repair_base.display())));

    let stats = LiveStats::new(rayon::current_num_threads());

    // Wynik wątku zapisu do bazy jest PRZENOSZONY na zewnątrz zakresu wątków i
    // zgłaszany przez `?` niżej. Wcześniej każdy błąd SQLite w tym wątku był
    // `.unwrap()`, czyli paniką w wątku w środku `thread::scope` — wbrew
    // zasadzie „obsługa błędów przez `Result`/`?`, bez paniki", i w dodatku
    // bez żadnego komunikatu tłumaczącego użytkownikowi, co się stało.
    let wynik_zapisu: Result<()> = std::thread::scope(|s| {
        let (tx_db, rx_db) = mpsc::sync_channel(200);
        let conn_ref = &mut *conn;
        let tx_ui_ref = &tx_ui;

        let db_thread = s.spawn(move || -> Result<()> {
            let tx_trans = conn_ref.transaction()?;
            {
                // Zapis naprawy USTAWIA RÓWNIEŻ `phase17_done` — jedno zapytanie
                // zamiast dwóch dla najczęstszego przypadku.
                let mut stmt_u = tx_trans.prepare_cached("UPDATE files SET repaired_path_ufs = ?1, repair_log_ufs = ?2, phase17_done = 1 WHERE id = ?3")?;
                let mut stmt_s = tx_trans.prepare_cached("UPDATE files SET repaired_path_script = ?1, repair_log_script = ?2, phase17_done = 1 WHERE id = ?3")?;
                // Plik przetworzony bez naprawy — sama flaga ukończenia.
                let mut stmt_done = tx_trans.prepare_cached("UPDATE files SET phase17_done = 1 WHERE id = ?1")?;

                for ScanMsg::Chunk(chunk) in rx_db {
                    for res in chunk {
                        match (res.repaired_path.as_deref(), res.repair_log.as_deref()) {
                            (Some(sciezka), Some(log)) => {
                                let stmt = if res.side == "ufs" { &mut stmt_u } else { &mut stmt_s };
                                stmt.execute(params![sciezka, log, res.id])?;
                            }
                            _ => { stmt_done.execute(params![res.id])?; }
                        }
                    }
                }
            }
            tx_trans.commit()?;
            let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Informacje o naprawionych plikach zabezpieczone w bazie.".to_string()));
            Ok(())
        });

        process_repair_stream(RepairCtx { ufs_base: &ufs_base, script_base: &script_base, repair_base: &repair_base, active_modules: &active_modules, tasks: &repair_tasks, stats: &stats, tx_db, tx_ui: &tx_ui, bar_idx: 0, start_time, opr_log: opr_log.clone(), });

        match db_thread.join() {
            Ok(wynik) => wynik,
            // `join` zwraca `Err` WYŁĄCZNIE gdy wątek spanikował. Sama panika
            // jest już odnotowana przez globalny hook w `logging.rs`, więc tu
            // zamieniamy ją na błąd domenowy, żeby nie rozprzestrzeniała się
            // dalej i żeby wywołujący nie uznał przebiegu za udany.
            Err(_) => {
                let _ = tx_ui.send(PhaseEvent::Log(
                    "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 17 NIE został zapisany.".to_string()
                ));
                Err(rusqlite::Error::UnwindingPanic)
            }
        }
    });

    if let Err(e) = &wynik_zapisu {
        // Naprawione pliki LEŻĄ już na dysku (w przestrzeni roboczej), więc
        // sama utrata wpisów w bazie nie jest utratą pracy — ale Faza 9 ich nie
        // zobaczy, dopóki Faza 17 nie zostanie powtórzona. Mówimy to wprost.
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "✖ Zapis wyników Fazy 17 do bazy zawiódł: {}. Naprawione pliki są w {}, ale baza ich nie zna — powtórz Fazę 17.",
            e, repair_base.display()
        )));
        warn!(blad = %e, "Faza 17: zapis wyników do bazy zawiódł");
    }
    wynik_zapisu?;

    let elapsed = start_time.elapsed();

    // -- GENEROWANIE DZIENNIKA KOŃCOWEGO --
    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(&mut log_out, "==========================================================================");
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 17 (AKTYWNA REKONSTRUKCJA I INŻYNIERIA)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "==========================================================================\n");

    let _ = writeln!(&mut log_out, "[ 1 ] ZESTAWIENIE OŻYWIONYCH PLIKÓW (Zostaną wykorzystane przez Złotą Kopię):");
    {
        let map = stats.liczniki();
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        if sorted.is_empty() {
            let _ = writeln!(&mut log_out, "   -> Żaden moduł nie zgłosił naprawy.");
        }
        for (module_id, count) in sorted {
            let display = active_modules.iter().find(|m| m.id() == *module_id).map(|m| m.display_name()).unwrap_or(module_id);
            let _ = writeln!(&mut log_out, "   -> {:<55} {} plików", display, count);
        }
    }
    let _ = writeln!(&mut log_out, "   -> Odrzucone przez obowiązkową weryfikację wyniku: {} plików", stats.rejected_by_verification.load(Ordering::Relaxed));
    let _ = writeln!(&mut log_out, "      (moduł wykonał naprawę, ale wynik nie przeszedł dowodu sprawności - plik usunięty, NIE trafił do bazy)");
    let _ = writeln!(&mut log_out, "   -> Błędy (żaden aktywny moduł nie pomógł): {} plików\n", stats.errors.load(Ordering::Relaxed));

    let _ = writeln!(&mut log_out, "[ ℹ ] Wszystkie naprawione wersje zostały oznaczone sufiksem '_repaired'/'_spliced' i zapisane w:");
    let _ = writeln!(&mut log_out, "      {}", repair_base.display());
    let _ = writeln!(&mut log_out, "      (struktura: <strona>/<oryginalne katalogi>; korpus źródłowy pozostaje NIETKNIĘTY)");

    if let Ok(mut f) = fs::File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano fizyczny Dziennik Końcowy w: {}", dz_path.display())));
    }

    // Wysyłamy również do Ratatui Log Panel
    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    // Zrzut telemetrii do głównego pliku logów w tle
    let repairs_snapshot: Vec<(String, usize)> = {
        let map = stats.liczniki();
        map.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    };
    info!(
        ?repairs_snapshot,
        errors = stats.errors.load(Ordering::Relaxed),
        odrzucone_weryfikacja = stats.rejected_by_verification.load(Ordering::Relaxed),
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 17 zakończona"
    );

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_module_ids_matches_registry_length() {
        let ids = all_module_ids();
        assert_eq!(ids.len(), repair_modules::all_modules().len());
    }

    #[test]
    fn test_all_module_ids_are_unique() {
        let mut ids = all_module_ids();
        let original_len = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "all_module_ids nie powinno zwracać duplikatów");
    }

    #[test]
    fn test_all_module_ids_nonempty() {
        assert!(!all_module_ids().is_empty(), "Rejestr modułów naprawczych nie powinien być pusty");
    }

    // ------------------------------------------------------------------
    // katalog_naprawy — przestrzeń robocza POZA korpusem źródłowym
    // ------------------------------------------------------------------

    use tempfile::tempdir;

    #[test]
    fn test_katalog_naprawy_odwzorowuje_strukture_katalogow() {
        let baza = tempdir().unwrap();
        let k = katalog_naprawy(baza.path(), "ufs", "foto/2024/wakacje/a.jpg").expect("katalog powinien powstać");

        assert_eq!(k, baza.path().join("ufs").join("foto/2024/wakacje"));
        assert!(k.is_dir(), "Katalog musi zostać fizycznie utworzony przed wywołaniem modułu");
    }

    #[test]
    fn test_katalog_naprawy_dla_pliku_w_korzeniu() {
        let baza = tempdir().unwrap();
        let k = katalog_naprawy(baza.path(), "script", "plik.txt").expect("katalog powinien powstać");

        assert_eq!(k, baza.path().join("script"));
        assert!(k.is_dir());
    }

    /// Sedno odwzorowania katalogów: nazwa wynikowa to `<stem>_repaired.<ext>`,
    /// więc dwa pliki o tej samej nazwie w różnych katalogach MUSZĄ dostać
    /// różne katalogi wyjściowe. W płaskiej przestrzeni drugi nadpisałby
    /// pierwszy, cicho tracąc jedną z napraw.
    #[test]
    fn test_katalog_naprawy_rozdziela_pliki_o_tej_samej_nazwie() {
        let baza = tempdir().unwrap();
        let a = katalog_naprawy(baza.path(), "ufs", "foto/a.jpg").unwrap();
        let b = katalog_naprawy(baza.path(), "ufs", "skany/a.jpg").unwrap();

        assert_ne!(a, b, "Pliki o tej samej nazwie z różnych katalogów nie mogą kolidować");
    }

    /// Ten sam `rel_path` istnieje po obu stronach i Faza 17 tworzy dla każdej
    /// osobne zadanie — obie naprawy muszą mieć własne miejsce.
    #[test]
    fn test_katalog_naprawy_rozdziela_strony() {
        let baza = tempdir().unwrap();
        let ufs = katalog_naprawy(baza.path(), "ufs", "foto/a.jpg").unwrap();
        let script = katalog_naprawy(baza.path(), "script", "foto/a.jpg").unwrap();

        assert_ne!(ufs, script, "Strona UFS i Skrypt nie mogą dzielić katalogu wyjściowego");
    }

    #[test]
    fn test_katalog_naprawy_jest_zawsze_pod_baza() {
        // Żadna kombinacja nie może wyprowadzić zapisu poza przestrzeń roboczą.
        let baza = tempdir().unwrap();
        for rel in ["a.jpg", "kat/a.jpg", "gleboko/bardzo/gleboko/a.jpg"] {
            let k = katalog_naprawy(baza.path(), "ufs", rel).unwrap();
            assert!(k.starts_with(baza.path()), "{} wyszło poza bazę: {}", rel, k.display());
        }
    }

    /// REGRESJA D4: dostęp do liczników nie może panikować z powodu ZATRUCIA
    /// muteksa. Wcześniejsze `.lock().unwrap()` zamieniało panikę jednego
    /// wątku Rayon w panikę każdego następnego, wywracając całą fazę zamiast
    /// dokończyć pracę i zaraportować wynik.
    #[test]
    fn test_liczniki_odporne_na_zatruty_muteks() {
        let stats = Arc::new(LiveStats::new(rayon::current_num_threads()));

        // Zatruwamy muteks: wątek panikuje trzymając blokadę.
        let stats_w_watku = Arc::clone(&stats);
        let _ = std::thread::spawn(move || {
            let _guard = stats_w_watku.repairs_by_module.lock().unwrap();
            panic!("celowa panika testowa trzymając blokadę");
        })
        .join();

        assert!(stats.repairs_by_module.is_poisoned(), "Setup testu: muteks MUSI być zatruty");

        // Mimo zatrucia liczniki muszą być dostępne do czytania i pisania.
        {
            let mut liczniki = stats.liczniki();
            *liczniki.entry("splice").or_insert(0) += 3;
        }
        assert_eq!(stats.liczniki().get("splice").copied(), Some(3));

        // I panel boczny musi się zbudować, a nie wywalić fazę.
        let blok = build_source_block(&stats, Instant::now());
        assert!(blok.contains("splice: 3"), "dostałem: {}", blok);
    }

    #[test]
    fn test_nazwa_katalogu_napraw_jest_zgodna_z_konwencja_faz() {
        // Faza 18 używa `_smart_splice_repaired`, narzędzie DNG
        // `_dng_structural_review` - podkatalogi przestrzeni roboczej zaczynają
        // się od podkreślenia, żeby nie mieszały się z odzyskaną treścią.
        assert!(KATALOG_NAPRAW.starts_with('_'), "Katalog techniczny powinien zaczynać się od podkreślenia");
    }

    // ------------------------------------------------------------------
    // TEST INTEGRACYJNY: pełny przebieg `run` na prawdziwych plikach
    //
    // Sprawdza naraz trzy rzeczy naprawione w tej fazie: ustawianie
    // `phase17_done`, zapis POZA korpus źródłowy i wznawialność.
    // ------------------------------------------------------------------

    use crate::settings::Ustawienia;

    /// Buduje konfigurację wskazującą WYŁĄCZNIE na katalogi tymczasowe.
    ///
    /// `raporty_faz` jest czyszczone celowo: domyślna konfiguracja kieruje
    /// raporty do `./dziennik/fazy`, czyli do katalogu PROJEKTU — test nie może
    /// tam nic zapisać. Po wyczyszczeniu mapy faza używa `log_path`.
    fn konfiguracja_testowa(ufs: &Path, script: &Path, target: &Path, logi: &Path) -> Ustawienia {
        let mut u = Ustawienia {
            ufs_path: ufs.to_string_lossy().to_string(),
            script_path: script.to_string_lossy().to_string(),
            target_path: target.to_string_lossy().to_string(),
            log_path: logi.to_string_lossy().to_string(),
            ..Default::default()
        };
        u.raporty_faz.clear();
        u
    }

    #[test]
    fn test_przebieg_oznacza_phase17_done_i_zapisuje_poza_korpus() {
        let ufs = tempdir().unwrap();
        let script = tempdir().unwrap();
        let target = tempdir().unwrap();
        let logi = tempdir().unwrap();

        // JPEG bez sygnatury SOI - moduł `header_jpg` wstrzyknie nagłówek.
        // Treść to prawdziwy, minimalny obraz, żeby przeszedł OBOWIĄZKOWĄ
        // weryfikację wyniku (realne dekodowanie pikseli).
        let obraz = image::RgbImage::new(2, 2);
        let mut jpeg = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(obraz)
            .write_to(&mut jpeg, image::ImageFormat::Jpeg)
            .unwrap();
        let jpeg = jpeg.into_inner();
        // Obcinamy dwubajtowy znacznik SOI - dokładnie ta anomalia, którą
        // moduł naprawia (wstrzyknięcie SOI/JFIF przed resztą danych).
        std::fs::create_dir_all(ufs.path().join("foto")).unwrap();
        std::fs::write(ufs.path().join("foto/bez_soi.jpg"), &jpeg[2..]).unwrap();

        let mut conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (relative_path, found_in_ufs, found_in_script, media_reason_ufs)
             VALUES ('foto/bez_soi.jpg', 1, 0, 'Zniszczony Nagłówek obrazu')",
            [],
        ).unwrap();

        let config = konfiguracja_testowa(ufs.path(), script.path(), target.path(), logi.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        run(&mut conn, &config, tx_ui, all_module_ids()).expect("Faza 17 powinna zakończyć się bez błędu");

        // 1. Flaga ukończenia ustawiona.
        let done: i64 = conn.query_row("SELECT phase17_done FROM files WHERE relative_path = 'foto/bez_soi.jpg'", [], |r| r.get(0)).unwrap();
        assert_eq!(done, 1, "phase17_done musi zostać ustawione dla przetworzonego pliku");

        // 2. Naprawa zapisana ze ścieżką ABSOLUTNĄ w przestrzeni roboczej.
        let sciezka: String = conn.query_row("SELECT repaired_path_ufs FROM files WHERE relative_path = 'foto/bez_soi.jpg'", [], |r| r.get(0))
            .expect("naprawa powinna zostać zapisana");
        assert!(Path::new(&sciezka).is_absolute(), "ścieżka naprawy musi być absolutna: {}", sciezka);
        assert!(sciezka.contains(KATALOG_NAPRAW), "naprawa musi leżeć w przestrzeni roboczej: {}", sciezka);
        assert!(Path::new(&sciezka).exists(), "naprawiony plik musi istnieć na dysku");

        // 3. Odwzorowana struktura katalogów i podział per strona.
        assert!(sciezka.contains("ufs"), "brak podziału per strona: {}", sciezka);
        assert!(sciezka.contains("foto"), "brak odwzorowania katalogów: {}", sciezka);

        // 4. KORPUS ŹRÓDŁOWY NIETKNIĘTY - żadnego pliku `_repaired` obok oryginału.
        let w_korpusie: Vec<String> = std::fs::read_dir(ufs.path().join("foto")).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(w_korpusie, vec!["bez_soi.jpg".to_string()], "Korpus musi zostać nietknięty, znalazłem: {:?}", w_korpusie);
    }

    #[test]
    fn test_powtorny_przebieg_pomija_pliki_juz_przetworzone() {
        let ufs = tempdir().unwrap();
        let script = tempdir().unwrap();
        let target = tempdir().unwrap();
        let logi = tempdir().unwrap();

        std::fs::write(ufs.path().join("brudny.txt"), b"tekst\x00z zerem").unwrap();

        let mut conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (relative_path, found_in_ufs, found_in_script, utf8_ok_ufs, phase17_done)
             VALUES ('brudny.txt', 1, 0, 0, 1)",
            [],
        ).unwrap();

        let config = konfiguracja_testowa(ufs.path(), script.path(), target.path(), logi.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        run(&mut conn, &config, tx_ui, all_module_ids()).expect("Faza 17 powinna zakończyć się bez błędu");

        // Plik był już oznaczony jako przetworzony, więc nie powstało zadanie
        // i nic się nie naprawiło — to jest sedno wznawialności.
        let naprawa: Option<String> = conn.query_row("SELECT repaired_path_ufs FROM files WHERE relative_path = 'brudny.txt'", [], |r| r.get(0)).unwrap();
        assert!(naprawa.is_none(), "Plik z phase17_done = 1 nie może zostać przetworzony ponownie");
    }

    /// Konwencja „(Wariant A)" musi być identyczna we WSZYSTKICH fazach
    /// równoległych — ułatwia maszynowe parsowanie panelu i utrzymuje spójność
    /// wizualną. Ten test utrwala ją dla tej fazy.
    #[test]
    fn test_blok_zawiera_znacznik_aktywnosci_watkow() {
        let stats = LiveStats::new(2);
        stats.thread_activity.mark_busy(1);

        let block = build_source_block(&stats, Instant::now());

        let line = block
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("Wątki naprawy"))
            .unwrap_or_else(|| panic!("brak linii Wariantu A w bloku:\n{}", block));

        assert_eq!(line, "Wątki naprawy (Wariant A): {R:1} {G:2}");
    }

}
