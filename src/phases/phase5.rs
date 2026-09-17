// src/phases/phase5.rs

//! # Faza 5: Akwizycja Czasów Modyfikacji, Uprawnień i Symlinków
//!
//! Pobiera precyzyjne atrybuty i-node (Uprawnienia, Czas do nanosekund, Hardlinki).
//! W pełni wspiera interfejs Ratatui TUI poprzez `PhaseEvent` oraz generuje
//! na bieżąco Raport Operacyjny i Dziennik Końcowy (Dual-Logging).
//!
//! UWAGA ARCHITEKTONICZNA (UI): Pasek postępu pokazuje wyłącznie % i bieżący
//! plik. Liczniki live trafiają do panelu bocznego jako JEDEN, samodzielny blok
//! PER ŹRÓDŁO (`[UFS Explorer]` / `[Skrypt Autorski]`) — patrz [`build_source_block`].
//! Zapytanie SQL w [`run`] przetwarza WSZYSTKIE pliki niezależnie (każda strona
//! osobno, tak jak Faza 2), a nie tylko pliki wspólne — stąd brak sumowania
//! krzyżowego jak w Fazie 3 (Wariant B).
//!
//! UWAGA ARCHITEKTONICZNA (WĄTKOWANIE) — POPRAWIONE: w trybie `CONCURRENT` obie
//! strony dostają WŁASNĄ, dedykowaną pulę Rayon o rozmiarze `actual_threads / 2`
//! (min. 1), identycznie jak w Fazach 3/4 (patrz `half_threads` w [`run`]).
//! Wcześniejsza wersja tego komentarza twierdziła, że współdzielona globalna
//! pula wystarczy, bo `lstat()` jest lekkie i work-stealing sam się rozdzieli —
//! to było błędne dla niskiej liczby wątków (np. `max_threads = 1`): pojedynczy
//! wspólny worker Rayona, otrzymując dwa niezależnie zlecone zadania
//! (`par_chunks` z dwóch osobnych wątków OS), zagłębiał się rekurencyjnie w
//! JEDNO z nich przez swoją lokalną kolejkę LIFO i nie zaglądał do globalnej
//! kolejki drugiej strony, dopóki własna kolejka się nie wyczerpała — efekt:
//! jedna strona stała w miejscu (0%), druga szła do 100% sama. Dedykowane pule
//! usuwają tę rywalizację całkowicie, każda strona ma gwarantowany budżet.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent; // <--- NAPRAWIONY IMPORT
use crate::utils::{format_bytes, format_display_path, CANCEL_SIGNAL};
use ratatui::style::Color;
use rayon::prelude::*;
use rusqlite::{params, Connection, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

// --- FALLBACKS DLA WINDOWS (Aby IDE nie świeciło na czerwono) ---
#[cfg(not(unix))]
trait DummyUnixMeta {
    fn uid(&self) -> u32 { 0 }
    fn gid(&self) -> u32 { 0 }
    fn mode(&self) -> u32 { 0o777 }
}
#[cfg(not(unix))]
impl DummyUnixMeta for std::fs::Metadata {}

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;
use tracing::{info, instrument, warn};

const CHUNK_SIZE: usize = 100;

// ============================================================================
// POMOCNIKI
// ============================================================================

/// Tłumaczy maszynowy kod CHMOD (+ flagi symlink/katalog) na czytelny,
/// dziesięcioznakowy format uniksowy w stylu `ls -l`, np. `drwxr-xr-x`,
/// `-rwsr-xr-x` (SUID), `lrwxrwxrwx` (dowiązanie symboliczne).
///
/// Pierwsza litera: `l` = symlink, `d` = katalog, `-` = zwykły plik.
/// Kolejne 9 znaków: trzy trójki (user/group/other) `rwx`, z podmianą bitu
/// wykonywalnego na `s`/`S` (SUID/SGID) lub `t`/`T` (sticky bit) gdy ustawiony.
fn format_permissions(mode: u32, is_symlink: bool, is_dir: bool) -> String {
    let mut s = String::with_capacity(10);
    
    if is_symlink { s.push('l'); }
    else if is_dir { s.push('d'); }
    else { s.push('-'); }

    s.push(if mode & 0o400 != 0 { 'r' } else { '-' });
    s.push(if mode & 0o200 != 0 { 'w' } else { '-' });
    s.push(if mode & 0o4000 != 0 { if mode & 0o100 != 0 { 's' } else { 'S' } } else { if mode & 0o100 != 0 { 'x' } else { '-' } });

    s.push(if mode & 0o040 != 0 { 'r' } else { '-' });
    s.push(if mode & 0o020 != 0 { 'w' } else { '-' });
    s.push(if mode & 0o2000 != 0 { if mode & 0o010 != 0 { 's' } else { 'S' } } else { if mode & 0o010 != 0 { 'x' } else { '-' } });

    s.push(if mode & 0o004 != 0 { 'r' } else { '-' });
    s.push(if mode & 0o002 != 0 { 'w' } else { '-' });
    s.push(if mode & 0o1000 != 0 { if mode & 0o001 != 0 { 't' } else { 'T' } } else { if mode & 0o001 != 0 { 'x' } else { '-' } });

    s
}

/// Wylicza precyzyjny czas modyfikacji w nanosekundach od epoki Unix
/// (`sekundy * 1_000_000_000 + nanosekundy`) w sposób ODPORNY na przepełnienie.
///
/// ## Dlaczego to jest konieczne (nie kosmetyka)
///
/// `meta.mtime()` pochodzi z surowego pola i-node (`st_mtime`, `i64`). Na
/// ZDROWYM systemie plików mieści się to w rozsądnym zakresie dat. Ale to
/// narzędzie działa właśnie na USZKODZONYCH i-node'ach po nieudanym odzysku —
/// bity pola czasu mogą być fizycznie zniszczone i przyjąć DOWOLNĄ wartość
/// `i64`, łącznie z wartościami bliskimi `i64::MIN`/`i64::MAX`. Naiwne mnożenie
/// `meta.mtime() * 1_000_000_000` na takiej wartości przepełnia zakres `i64`:
/// w trybie debug to panika (crash całej Fazy 5 na jednym uszkodzonym pliku
/// wśród tysięcy), w trybie release — CICHE zawinięcie (wraparound) na losową
/// wartość, która trafia do bazy jako rzekomo "precyzyjny" znacznik czasu i
/// dalej zasila raport kryminalistyczny fałszywą datą.
///
/// Rozwiązanie: liczymy pośrednio w `i128` (który fizycznie nie może przepełnić
/// się przy mnożeniu/dodawaniu dwóch wartości `i64`), a dopiero na końcu
/// próbujemy bezpiecznie zwęzić wynik z powrotem do `i64` przez `try_from`.
/// Gdy wynik nie mieści się w `i64` (anomalia i-node), zwracamy jawnie `None`
/// zamiast panikować lub ciszej fałszować wartość — wołający zapisuje to jako
/// `mtime_ns: None` i osobną anomalię "Przepełnienie znacznika czasu" w
/// dziennikach (patrz `process_side_stream`), więc plik NIE znika po cichu z
/// raportu — widać wprost, że jego i-node jest uszkodzony w polu czasu.
fn compute_precise_mtime(sec: i64, nsec: i64) -> Option<i64> {
    let sec = sec as i128;
    let nsec = nsec as i128;
    sec.checked_mul(1_000_000_000)
        .and_then(|whole| whole.checked_add(nsec))
        .and_then(|total| i64::try_from(total).ok())
}

/// Rozstrzyga, czy plik (jedna strona: UFS albo Skrypt) musi wrócić na listę
/// zadań ETAP 1. Wydzielone jako czysta funkcja — testowalna bez budowania
/// bazy/wątków, mirror wzorca z `phase14::wolno_zapisac_symetryczne_wpisy_skryptu`.
///
/// NAPRAWIONY BUG (measure twice — druga weryfikacja Gemini, N2): plik z
/// TRWALE uszkodzonym polem czasu i-node ma `lstat()` udane
/// (`io_error_ufs = Some(false)`, zapisane jawnie — patrz komentarz przy
/// zapisie w `process_side_stream`), ale `compute_precise_mtime`
/// deterministycznie zwraca `None` za KAŻDYM razem — `mtime_ufs` w bazie
/// zostaje `NULL` na zawsze. Wcześniejszy warunek (`mtime.is_none() &&
/// io_error != Some(true)`) dopuszczał zarówno "nigdy nie przetworzono"
/// (`io_error IS NULL`), jak i "przetworzono, ale nie da się policzyć
/// mtime" (`io_error == Some(false)`) — taki plik trafiał z powrotem na
/// listę zadań przy KAŻDYM uruchomieniu Fazy 5, bez końca, bez żadnej
/// korzyści (wynik i tak zawsze `None`). Teraz wymagane jest jawnie "nigdy
/// nie przetworzono" — plik raz przetworzony (z dowolnym wynikiem
/// `io_error`) nie wraca do kolejki.
fn wymaga_ponownego_odczytu(mtime: Option<i64>, io_error: Option<bool>) -> bool {
    mtime.is_none() && io_error.is_none()
}

// ============================================================================
// STRUKTURY DANYCH
// ============================================================================

/// Pojedyncze zadanie: plik oczekujący na odczyt metadanych i-node po JEDNEJ stronie.
#[derive(Debug, Clone)]
pub(crate) struct Task {
    /// Klucz główny rekordu w tabeli `files`.
    id: i32,
    /// Ścieżka względna liczona od katalogu bazowego danej strony.
    rel_path: String,
}

/// Atrybuty i-node jednego pliku, wyliczone przez `lstat()` (NIE podąża za
/// symlinkami — stąd `symlink_metadata`, a nie `metadata`).
#[derive(Debug, Clone)]
struct FileStats {
    uid: u32,
    gid: u32,
    /// Same bity uprawnień (maska `0o7777`) — bez typu pliku, gotowe do zapisu w SQLite.
    mode: u32,
    /// Czas modyfikacji w nanosekundach od epoki Unix — pełna precyzja (sekundy × 1e9 + nsec).
    /// `None` gdy `sekundy × 1e9 + nsec` przepełnia `i64` (uszkodzony i-node —
    /// patrz [`compute_precise_mtime`]); w tym wypadku `mtime_ufs`/`mtime_script`
    /// w bazie CELOWO pozostaje `NULL` zamiast fałszywej, zawiniętej wartości.
    mtime_ns: Option<i64>,
    is_symlink: bool,
}

/// Wynik przetworzenia jednego zadania, przekazywany przez MPSC do wątku zapisu SQLite.
#[derive(Debug)]
pub(crate) struct SideResult {
    id: i32,
    /// `None` przy błędzie I/O (plik zniknął/brak dostępu między fazami).
    stats: Option<FileStats>,
    io_error: Option<bool>,
}

/// Wiadomość do wątku zapisu SQLite, oznaczona stroną pochodzenia.
pub(crate) enum ScanMsg {
    UfsChunk(Vec<SideResult>),
    ScriptChunk(Vec<SideResult>),
}

/// Liczniki live dla JEDNEJ strony (UFS albo Skrypt) — nigdy nie łączone
/// z licznikami drugiej strony (patrz uzasadnienie w dokumentacji modułu).
pub(crate) struct LiveStats {
    processed: AtomicUsize,
    /// Suma rozmiarów plików (bajty) — używana wyłącznie do `ext_weights`,
    /// NIE do prędkości transferu (ta faza raportuje prędkość w plikach/s,
    /// bo koszt to liczba wywołań `lstat()`, nie objętość odczytanych danych).
    processed_bytes: AtomicU64,
    errors: AtomicUsize,
    
    ext_weights: Mutex<HashMap<String, u64>>,
    /// Zliczenia wystąpień per UID właściciela — do wykrycia dominującego konta.
    uid_counts: Mutex<HashMap<u32, usize>>,
    /// Zliczenia wystąpień per czytelny string uprawnień (np. "-rwxr-xr-x").
    mode_counts: Mutex<HashMap<String, usize>>,
    
    symlinks: AtomicUsize,
    /// Pliki z >1 dowiązaniem twardym (nlink > 1), z pominięciem symlinków.
    hardlinks: AtomicUsize,
    /// Pliki należące do UID 0 (root) — potencjalnie podejrzane w kontekście odzysku.
    root_owned: AtomicUsize,
    suid_sgid: AtomicUsize,
    executables: AtomicUsize,
    /// Pliki z czasem modyfikacji <= 0 (epoka Unix 1970) — typowy ślad
    /// uszkodzonych metadanych po nieudanym odzysku.
    epoch_zero: AtomicUsize,
    /// Pliki, gdzie `sekundy × 1e9 + nsec` przepełnia `i64` — i-node fizycznie
    /// uszkodzony w polu czasu na tyle, że nawet nie mieści się w typie danych.
    /// `mtime_ns` zapisany jako `None` (patrz [`compute_precise_mtime`]).
    mtime_overflow: AtomicUsize,

    /// EKSPERYMENTALNE (Wariant A): śledzi zajętość logicznych slotów Rayon
    /// TEJ strony podczas wywołań `lstat()` — patrz moduł `thread_activity`.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            processed: AtomicUsize::new(0),
            processed_bytes: AtomicU64::new(0),
            errors: AtomicUsize::new(0),
            ext_weights: Mutex::new(HashMap::new()),
            uid_counts: Mutex::new(HashMap::new()),
            mode_counts: Mutex::new(HashMap::new()),
            symlinks: AtomicUsize::new(0),
            hardlinks: AtomicUsize::new(0),
            root_owned: AtomicUsize::new(0),
            suid_sgid: AtomicUsize::new(0),
            executables: AtomicUsize::new(0),
            epoch_zero: AtomicUsize::new(0),
            mtime_overflow: AtomicUsize::new(0),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }
}

/// Wylicza liczbę slotów trackera zajętości (Wariant A) odpowiednią dla
/// trybu I/O — patrz identyczna logika w `phase3::compute_activity_slots`.
fn compute_activity_slots(io_mode: &str, actual_threads: usize, half_threads: usize) -> usize {
    if io_mode == "CONCURRENT" { half_threads } else { actual_threads }
}

/// Buduje pełny, samodzielny blok live DLA JEDNEGO ŹRÓDŁA (UFS albo Skrypt) —
/// prędkość w plikach/s (NIE MB/s — koszt tu to liczba syscalli `lstat`, nie
/// objętość danych), top 3 rozszerzenia wagowo, top 3 UID, top 3 zestawy
/// uprawnień, oraz liczniki anomalii i-node (symlinki, hardlinki, root,
/// SUID/SGID, wykonywalne, epoka zerowa) i błędów I/O. Bez sumowania z drugą
/// stroną — patrz uzasadnienie w dokumentacji modułu.
fn build_source_block(label: &str, stats: &LiveStats, start_time: Instant) -> String {
    let processed = stats.processed.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
    let speed_files = processed as f64 / elapsed;

    let top_ext = {
        let map = stats.ext_weights.lock().unwrap();
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.into_iter().take(3).map(|(ext, w)| {
            let e = if ext == "brak" { "brak".to_string() } else { format!(".{}", ext) };
            format!("{} ({})", e, format_bytes(*w))
        }).collect::<Vec<_>>().join(", ")
    };
    let display_ext = if top_ext.is_empty() { "Analiza danych...".to_string() } else { top_ext };

    let top_uid = {
        let map = stats.uid_counts.lock().unwrap();
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.into_iter().take(3).map(|(u, c)| format!("UID {} ({})", u, c)).collect::<Vec<_>>().join(", ")
    };
    let display_uid = if top_uid.is_empty() { "...".to_string() } else { top_uid };

    let top_mode = {
        let map = stats.mode_counts.lock().unwrap();
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.into_iter().take(3).map(|(m, c)| format!("{} ({})", m, c)).collect::<Vec<_>>().join(", ")
    };
    let display_mode = if top_mode.is_empty() { "...".to_string() } else { top_mode };

    let activity_markup = crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot());

    format!(
        "[{}]\nPrędkość: {:.0} plików/s\nTop format: {}\nTop UID: {}\nTop uprawnienia: {}\nDowiązania miękkie: {}\nDowiązania twarde: {}\nWłaściciel root: {}\nSUID/SGID: {}\nPliki wykonywalne: {}\nEpoka zerowa (1970): {}\nPrzepełnienie znacznika czasu: {}\nWątki lstat (Wariant A): {}\nBłędy I/O: {}",
        label, speed_files, display_ext, display_uid, display_mode,
        stats.symlinks.load(Ordering::Relaxed),
        stats.hardlinks.load(Ordering::Relaxed),
        stats.root_owned.load(Ordering::Relaxed),
        stats.suid_sgid.load(Ordering::Relaxed),
        stats.executables.load(Ordering::Relaxed),
        stats.epoch_zero.load(Ordering::Relaxed),
        stats.mtime_overflow.load(Ordering::Relaxed),
        activity_markup,
        stats.errors.load(Ordering::Relaxed),
    )
}

// ============================================================================
// GŁÓWNY SKANER RDZENIOWY (I/O & i-node forensics)
// ============================================================================

/// Skanuje wszystkie zadania (`tasks`) dla JEDNEJ strony: dla każdego pliku
/// wywołuje `lstat()` (przez `fs::symlink_metadata`, żeby NIE podążać za
/// symlinkami), wylicza precyzyjny czas modyfikacji w nanosekundach, wykrywa
/// anomalie i-node (symlinki, hardlinki, właściciel root, SUID/SGID, epoka
/// zerowa), aktualizuje [`LiveStats`] i strumieniuje wyniki do wątku zapisu
/// SQLite przez `tx_db`. Rozgłasza postęp i statystyki do UI co ~60ms.
pub struct StreamCtx<'a> {
    pub base_path: &'a Path,
    pub tasks: &'a [Task],
    pub side_label: &'a str,
    pub stats: &'a LiveStats,
    pub tx_db: mpsc::SyncSender<ScanMsg>,
    pub is_ufs: bool,
    pub tx_ui: &'a mpsc::Sender<PhaseEvent>,
    pub bar_idx: usize,
    pub opr_log: Arc<Mutex<File>>,
    pub start_time: Instant,
}

#[instrument(skip(ctx), fields(base_path = %ctx.base_path.display()))]

fn process_side_stream<'a>(ctx: StreamCtx<'a>) {
    let StreamCtx { base_path, tasks, side_label, stats, tx_db, is_ufs, tx_ui, bar_idx, opr_log, start_time } = ctx;

    tasks.par_chunks(CHUNK_SIZE).for_each_with(tx_db, |tx_db, chunk| {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

        let mut results = Vec::with_capacity(chunk.len());
        let mut local_ext_weights: HashMap<String, u64> = HashMap::new();
        let mut local_uid_counts: HashMap<u32, usize> = HashMap::new();
        let mut local_mode_counts: HashMap<String, usize> = HashMap::new();
        let mut last_ui_update = Instant::now();

        for task in chunk {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

            let full_path = base_path.join(&task.rel_path);
            let ext = Path::new(&task.rel_path).extension().and_then(|e| e.to_str()).unwrap_or("brak").to_lowercase();

            let (stats_opt, io_err) = match stats.thread_activity.track_current(|| fs::symlink_metadata(&full_path)) {
                Ok(meta) => {
                    // NAPRAWA (przepełnienie i64): patrz dokumentacja `compute_precise_mtime`.
                    // Na uszkodzonym i-node `meta.mtime()` może być dowolną wartością i64 -
                    // mnożenie przez 1e9 potrafi przepełnić zakres. Liczymy pośrednio w i128
                    // (nie przepełnia się), a `None` (zamiast paniki lub cichego zawinięcia)
                    // oznacza jawną anomalię, zapisaną niżej.
                    let precise_mtime = compute_precise_mtime(meta.mtime(), meta.mtime_nsec());
                    let forensic_mode = meta.mode() & 0o7777;
                    let file_size = meta.len();
                    let is_sym = meta.file_type().is_symlink();
                    let is_dir = meta.is_dir();
                    let nlink = meta.nlink();
                    
                    let uid = meta.uid();
                    let gid = meta.gid();
                    let human_permissions = format_permissions(meta.mode(), is_sym, is_dir);
                    
                    stats.processed_bytes.fetch_add(file_size, Ordering::Relaxed);
                    *local_ext_weights.entry(ext.clone()).or_insert(0) += file_size;
                    *local_uid_counts.entry(uid).or_insert(0) += 1;
                    *local_mode_counts.entry(human_permissions.clone()).or_insert(0) += 1;

                    let mut anomalies: Vec<String> = Vec::new();

                    if is_sym { stats.symlinks.fetch_add(1, Ordering::Relaxed); anomalies.push("Dowiązanie Miękkie".to_string()); }
                    if nlink > 1 && !is_sym { stats.hardlinks.fetch_add(1, Ordering::Relaxed); anomalies.push(format!("Hardlink ({})", nlink)); }
                    if uid == 0 { stats.root_owned.fetch_add(1, Ordering::Relaxed); anomalies.push("Właściciel ROOT".to_string()); }
                    if forensic_mode & 0o6000 != 0 { stats.suid_sgid.fetch_add(1, Ordering::Relaxed); anomalies.push("SUID/SGID".to_string()); }
                    if forensic_mode & 0o0111 != 0 && !is_sym { stats.executables.fetch_add(1, Ordering::Relaxed); }
                    match precise_mtime {
                        Some(v) if v <= 0 => { stats.epoch_zero.fetch_add(1, Ordering::Relaxed); anomalies.push("Epoka 1970".to_string()); }
                        Some(_) => {}
                        None => {
                            stats.mtime_overflow.fetch_add(1, Ordering::Relaxed);
                            anomalies.push("Nieprawidłowy znacznik czasu (przepełnienie)".to_string());
                        }
                    }

                    if !anomalies.is_empty()
                        && let Ok(mut f) = opr_log.lock() {
                            let anomalies_str = anomalies.join(", ");
                            let _ = writeln!(f, "[{:<15}] [{}] UID: {:<4} | Prawa: {} | Ścieżka: \"{}\"", side_label, anomalies_str, uid, human_permissions, full_path.display());
                        }

                    let s = FileStats { uid, gid, mode: forensic_mode, mtime_ns: precise_mtime, is_symlink: is_sym };
                    (Some(s), Some(false))
                },
                Err(e) => {
                    warn!(path = %task.rel_path, side = side_label, error = %e, "Błąd I/O (lstat)");
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut f) = opr_log.lock() {
                        let _ = writeln!(f, "[{:<15}] [Błąd I/O: {}] Ścieżka: \"{}\"", side_label, e, full_path.display());
                    }
                    (None, Some(true))
                }
            };

            let current = stats.processed.fetch_add(1, Ordering::Relaxed) + 1;
            
            let now = Instant::now();
            // Hybrydowy próg: licznik globalny (stats.processed - atomik
            // współdzielony między WSZYSTKIMI paczkami tej strony, nie resetuje
            // się na granicy chunku - w przeciwieństwie do samego czasu, który
            // z last_ui_update deklarowanym raz na paczkę CHUNK_SIZE=100 mógł
            // nigdy nie przekroczyć progu, jeśli 100 wywołań lstat() zdążyło
            // wykonać się w mniej niż próg czasowy - stąd "skoki" paska zamiast
            // płynnego przyrostu) jako główny wyzwalacz na szybkich dyskach,
            // plus siatka bezpieczeństwa czasowa na wypadek wolnego/zawodzącego
            // nośnika (gwarancja, że UI nie zamrozi się na długo między
            // aktualizacjami, nawet gdy do kolejnej wielokrotności licznika
            // daleko).
            let should_update = current.is_multiple_of(200)
                || now.duration_since(last_ui_update).as_millis() > 250;

            if should_update {
                last_ui_update = now;

                if !local_ext_weights.is_empty() {
                    let mut global_map = stats.ext_weights.lock().unwrap();
                    for (k, v) in local_ext_weights.drain() { *global_map.entry(k).or_insert(0) += v; }
                }
                if !local_uid_counts.is_empty() {
                    let mut global_uid = stats.uid_counts.lock().unwrap();
                    for (k, v) in local_uid_counts.drain() { *global_uid.entry(k).or_insert(0) += v; }
                }
                if !local_mode_counts.is_empty() {
                    let mut global_mode = stats.mode_counts.lock().unwrap();
                    for (k, v) in local_mode_counts.drain() { *global_mode.entry(k).or_insert(0) += v; }
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

            results.push(SideResult { id: task.id, stats: stats_opt, io_error: io_err });
        }

        if !local_ext_weights.is_empty() {
            let mut global_map = stats.ext_weights.lock().unwrap();
            for (k, v) in local_ext_weights.drain() { *global_map.entry(k).or_insert(0) += v; }
        }
        if !local_uid_counts.is_empty() {
            let mut global_uid = stats.uid_counts.lock().unwrap();
            for (k, v) in local_uid_counts.drain() { *global_uid.entry(k).or_insert(0) += v; }
        }
        if !local_mode_counts.is_empty() {
            let mut global_mode = stats.mode_counts.lock().unwrap();
            for (k, v) in local_mode_counts.drain() { *global_mode.entry(k).or_insert(0) += v; }
        }

        if !results.is_empty() {
            if is_ufs { let _ = tx_db.send(ScanMsg::UfsChunk(results)); } 
            else { let _ = tx_db.send(ScanMsg::ScriptChunk(results)); }
        }
    });

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: bar_idx,
        current: stats.processed.load(Ordering::Relaxed) as u64,
        message: "Odczyt i-node w 100% zakończony.".to_string(),
    });
}

// ============================================================================
// GŁÓWNA FUNKCJA KORDYNUJĄCA FAZĘ
// ============================================================================

/// Punkt wejścia Fazy 5, wołany przez `menu::actions::run_phase_with_ui`.
///
/// Przebieg: (1) wczytuje z SQLite zadania — WSZYSTKIE pliki obecne po danej
/// stronie (`found_in_ufs`/`found_in_script`), którym brakuje jeszcze
/// `mtime` po tej stronie i bez zapisanego błędu I/O (podobnie jak Faza 2 —
/// nie tylko pliki wspólne, w przeciwieństwie do Faz 3/4); (2) uruchamia
/// [`process_side_stream`] dla UFS i Skryptu — równolegle (dwie dedykowane
/// pule Rayon, `half_threads`, identycznie jak w Fazach 3/4) lub sekwencyjnie
/// (jedna po drugiej na pełnej globalnej puli); (3) koreluje metadane w SQLite
/// (`meta_match` — porównanie uprawnień/właściciela/czasu między stronami dla
/// plików obecnych na obu); (4) generuje Dziennik Końcowy (rozkład anomalii
/// i-node, top UID/uprawnienia) do pliku i do UI.
#[instrument(skip(conn, config, tx_ui), fields(ufs_path = %config.ufs_path, script_path = %config.script_path))]
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    crate::utils::CANCEL_SIGNAL.store(false, Ordering::SeqCst);

    // 1. INICJALIZACJA DUAL-LOGGING (Pobieranie ścieżek z Ustawień)
    let raport_cfg = config.raporty_faz.get("Faza 5").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza5.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza5.txt".to_string(),
    });
    
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);
    
    // REGRESJA (todo.faza02.md, ta sama klasa błędu we wszystkich fazach):
    // `.unwrap()` panikował, gdyby katalog logów stał się niezapisywalny
    // między `create_dir_all` a tym miejscem — cały bieg fazy ginął z
    // powodu samego logowania, zanim jakikolwiek plik został przetworzony.
    let opr_log_file = match File::create(&opr_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = tx_ui.send(PhaseEvent::Log(format!("BŁĄD I/O: Nie można utworzyć pliku logu operacyjnego: {}. Sprawdź uprawnienia.", e)));
            return Ok(());
        }
    };
    let opr_log = Arc::new(Mutex::new(opr_log_file));
    {
        let mut f = opr_log.lock().unwrap();
        let _ = writeln!(f, "=== RAPORT OPERACYJNY - FAZA 5 (STRUKTURY I-NODE) ===");
        let _ = writeln!(f, "Zestawienie plików z podejrzanymi atrybutami (Błędy odzysku Epoki 0, Hardlinki, SUID/ROOT):\n");
    }

    let actual_threads = if config.max_threads > 0 { config.max_threads } else { rayon::current_num_threads() };
    let io_text = if config.io_mode == "CONCURRENT" { "RÓWNOLEGŁE (SSD/NVMe)" } else { "SEKWENCYJNIE (HDD)" };
    
    let _ = tx_ui.send(PhaseEvent::Log(format!("Uruchomiono Fazę 5. Metodyka szyny dyskowej: {}", io_text)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora (Rayon): {}", actual_threads)));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    // --- ETAP 1: POBIERANIE ZADAŃ ---
    let mut stmt = conn.prepare(
        "SELECT id, relative_path, found_in_ufs, found_in_script, mtime_ufs, mtime_script, io_error_ufs, io_error_script 
         FROM files WHERE phase5_done = 0 OR phase5_done IS NULL"
    )?;
    
    let mut ufs_tasks = Vec::new();
    let mut script_tasks = Vec::new();
    let mut skipped_ufs = 0;
    let mut skipped_script = 0;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i32>(0)?, row.get::<_, String>(1)?, row.get::<_, bool>(2)?, row.get::<_, bool>(3)?,
            row.get::<_, Option<i64>>(4)?, row.get::<_, Option<i64>>(5)?, row.get::<_, Option<bool>>(6)?, row.get::<_, Option<bool>>(7)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel, in_ufs, in_script, m_ufs, m_scr, err_ufs, err_scr) = r;

        if in_ufs {
            if wymaga_ponownego_odczytu(m_ufs, err_ufs) { ufs_tasks.push(Task { id, rel_path: rel.clone() }); }
            else { skipped_ufs += 1; }
        }

        if in_script {
            if wymaga_ponownego_odczytu(m_scr, err_scr) { script_tasks.push(Task { id, rel_path: rel }); }
            else { skipped_script += 1; }
        }
    }
    drop(stmt);

    if skipped_ufs > 0 || skipped_script > 0 {
        let _ = tx_ui.send(PhaseEvent::Log(format!("Pominięto pliki z wyliczonymi metadanymi. UFS: {}, Skrypt: {}", skipped_ufs, skipped_script)));
    }

    let total_db_rows = ufs_tasks.len() + script_tasks.len();
    if total_db_rows == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak plików wymagających weryfikacji i-node. Baza aktualna.".to_string()));
        return Ok(());
    }

    // Inicjalizacja pasków postępu Ratatui
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "UFS Explorer (Metadane)".to_string(), total: ufs_tasks.len() as u64, color: Color::Cyan });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 1, label: "Skrypt Autorski (Metadane)".to_string(), total: script_tasks.len() as u64, color: Color::Magenta });
    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 2, label: "Zapis SQLite".to_string(), total: total_db_rows as u64, color: Color::Green });

    let half_threads = std::cmp::max(1, actual_threads / 2);
    let activity_slots = compute_activity_slots(&config.io_mode, actual_threads, half_threads);

    let ufs_stats = LiveStats::new(activity_slots);
    let script_stats = LiveStats::new(activity_slots);
    let ufs_base = PathBuf::from(&config.ufs_path);
    let script_base = PathBuf::from(&config.script_path);

    // --- ETAP 3: PRZETWARZANIE STRUMIENIOWE (MPSC) ---
    // REGRESJA (measure twice — druga weryfikacja Gemini): każdy błąd SQLite
    // w wątku bazy był wcześniej `.unwrap()`, czyli paniką w wątku pisarza
    // wewnątrz `thread::scope`. Ten sam wzorzec co `phase17_repair::run`/
    // `phase1::run`/`phase3::run` — `db_thread` zwraca `Result<()>`, panika
    // jest przechwytywana przez `.join()` i zamieniana na błąd domenowy.
    let wynik_zapisu: Result<()> = std::thread::scope(|s| {
        let (tx_db, rx_db) = mpsc::sync_channel(200);
        let conn_ref = &mut *conn;
        let tx_ui_ref = &tx_ui;

        let db_thread = s.spawn(move || -> Result<()> {
            let mut last_db_update = Instant::now();
            let mut db_inserted = 0;

            for msg in rx_db {
                let chunk_len = match &msg {
                    ScanMsg::UfsChunk(c) => c.len(),
                    ScanMsg::ScriptChunk(c) => c.len(),
                };

                if chunk_len > 0 {
                    let tx_trans = conn_ref.transaction()?;
                    {
                        let mut stmt = match &msg {
                            ScanMsg::UfsChunk(_) => tx_trans.prepare_cached(
                                "UPDATE files SET uid_ufs = COALESCE(?1, uid_ufs), gid_ufs = COALESCE(?2, gid_ufs), mode_ufs = COALESCE(?3, mode_ufs), mtime_ufs = COALESCE(?4, mtime_ufs), is_symlink_ufs = COALESCE(?5, is_symlink_ufs), io_error_ufs = COALESCE(?6, io_error_ufs) WHERE id = ?7"
                            )?,
                            ScanMsg::ScriptChunk(_) => tx_trans.prepare_cached(
                                "UPDATE files SET uid_script = COALESCE(?1, uid_script), gid_script = COALESCE(?2, gid_script), mode_script = COALESCE(?3, mode_script), mtime_script = COALESCE(?4, mtime_script), is_symlink_script = COALESCE(?5, is_symlink_script), io_error_script = COALESCE(?6, io_error_script) WHERE id = ?7"
                            )?,
                        };
                        
                        let chunk = match &msg {
                            ScanMsg::UfsChunk(c) => c,
                            ScanMsg::ScriptChunk(c) => c,
                        };

                        for res in chunk {
                            if res.stats.is_some() || res.io_error == Some(true) {
                                stmt.execute(params![
                                    res.stats.as_ref().map(|s| s.uid), res.stats.as_ref().map(|s| s.gid),
                                    res.stats.as_ref().map(|s| s.mode),
                                    // NAPRAWA: mtime_ns jest teraz Option<i64> (patrz
                                    // compute_precise_mtime) - .and_then() spłaszcza
                                    // Option<Option<i64>> zamiast panikować/zawijać wartość
                                    // przy przepełnieniu. Gdy None, COALESCE zostawia
                                    // mtime_ufs/script jak było (NULL) - ALE `io_error_ufs`
                                    // (kilka parametrów niżej) i tak dostaje jawne `Some(false)`
                                    // z `res.io_error`, więc plik NIE wraca do kolejki w ETAP 1
                                    // (`err_ufs.is_none()`) ani nie blokuje `phase5_done`
                                    // (`io_error_ufs IS NOT NULL` w ETAP 4) - "podjęto próbę,
                                    // wynik trwale nieobliczalny" jest odróżnione od "nigdy nie
                                    // podjęto próby". Patrz N2 w todo.faza05.md.
                                    res.stats.as_ref().and_then(|s| s.mtime_ns),
                                    res.stats.as_ref().map(|s| s.is_symlink), res.io_error, res.id
                                ])?;
                            }
                        }
                    }
                    tx_trans.commit()?;
                }

                db_inserted += chunk_len;

                let now = Instant::now();
                if now.duration_since(last_db_update).as_millis() > 60 {
                    last_db_update = now;
                    let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Zapisywanie metadanych...".to_string() });
                }
            }
            let _ = tx_ui_ref.send(PhaseEvent::UpdateBar { idx: 2, current: db_inserted as u64, message: "Metadane bezpiecznie zapisane w SQLite.".to_string() });
            Ok(())
        });

        if config.io_mode == "CONCURRENT" {
            let tx1 = tx_db.clone();
            let tx2 = tx_db.clone();
            let log_u = opr_log.clone();
            let log_s = opr_log.clone();

            let stat_u = &ufs_stats;
            let stat_s = &script_stats;

            // NAPRAWA: przy niskim actual_threads (np. 1) dzielona globalna pula
            // powodowała głodzenie jednej strony — worker Rayona wybierał JEDNO
            // zlecone zadanie (par_chunks) i rekurencyjnie zagłębiał się w nie
            // przez swoją lokalną kolejkę LIFO, nie zaglądając do globalnej
            // kolejki drugiej strony, dopóki własna kolejka się nie wyczerpała.
            // Efekt: jedna strona stała w miejscu, druga szła do 100%.
            // Rozwiązanie identyczne jak w Fazie 3/4: każda strona dostaje
            // WŁASNĄ, dedykowaną pulę o rozmiarze min. 1 wątek — nawet przy
            // actual_threads=1 obie strony realnie pracują równolegle (2 wątki
            // fizyczne łącznie, po jednym na stronę). Wyliczone wcześniej,
            // przed konstrukcją LiveStats, tu tylko używane.

            s.spawn(move || {
                if !ufs_tasks.is_empty() {
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: log_u, start_time, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: stat_u, tx_db: tx1, is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: log_u, start_time, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Odczyt atrybutów UFS zakończony.".to_string()));
                }
            });

            s.spawn(move || {
                if !script_tasks.is_empty() {
                    if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(half_threads).build() {
                        pool.install(|| {
                            process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: log_s, start_time, });
                        });
                    } else {
                        process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: stat_s, tx_db: tx2, is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: log_s, start_time, });
                    }
                    let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Odczyt atrybutów Skryptu zakończony.".to_string()));
                }
            });
            drop(tx_db);

        } else {
            let log_u = opr_log.clone();
            let log_s = opr_log.clone();
            
            if !ufs_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &ufs_base, tasks: &ufs_tasks, side_label: "UFS Explorer", stats: &ufs_stats, tx_db: tx_db.clone(), is_ufs: true, tx_ui: tx_ui_ref, bar_idx: 0, opr_log: log_u, start_time, });
                let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Odczyt atrybutów UFS zakończony.".to_string()));
            }
            
            if !script_tasks.is_empty() {
                process_side_stream(StreamCtx { base_path: &script_base, tasks: &script_tasks, side_label: "Skrypt Autorski", stats: &script_stats, tx_db: tx_db.clone(), is_ufs: false, tx_ui: tx_ui_ref, bar_idx: 1, opr_log: log_s, start_time, });
                let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Odczyt atrybutów Skryptu zakończony.".to_string()));
            }
            drop(tx_db);
        }

        match db_thread.join() {
            Ok(wynik) => wynik,
            // `join` zwraca `Err` WYŁĄCZNIE gdy wątek spanikował. Sama panika
            // jest już odnotowana przez globalny hook w `logging.rs`, więc tu
            // zamieniamy ją na błąd domenowy, żeby nie rozprzestrzeniała się
            // dalej i żeby wywołujący nie uznał przebiegu za udany.
            Err(_) => {
                let _ = tx_ui.send(PhaseEvent::Log(
                    "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Postęp Fazy 5 mógł nie zostać w pełni zapisany.".to_string()
                ));
                Err(rusqlite::Error::UnwindingPanic)
            }
        }
    });
    wynik_zapisu?;

    // --- ETAP 4: SYNCHRONIZACJA Z BAZĄ DANYCH ---
    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log("🛑 Skanowanie przerwane przez użytkownika.".to_string()));
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::Log("Trwa wiązanie macierzy metadanych w SQLite...".to_string()));
    
    conn.execute(
        "UPDATE files 
         SET meta_match = CASE 
                WHEN io_error_ufs = 1 OR io_error_script = 1 THEN NULL
                WHEN uid_ufs IS NULL OR uid_script IS NULL THEN NULL 
                WHEN uid_ufs = uid_script AND gid_ufs = gid_script AND mode_ufs = mode_script AND mtime_ufs = mtime_script AND is_symlink_ufs = is_symlink_script THEN 1 
                ELSE 0 
             END, 
             phase5_done = CASE
                -- REGRESJA (measure twice, N2): io_error_ufs = 1 dopuszczało
                -- jako ukonczone WYLACZNIE realny blad I/O - plik z udanym
                -- lstat() ale TRWALE nieobliczalnym mtime (io_error_ufs = 0,
                -- jawnie zapisane, patrz komentarz przy zapisie w
                -- process_side_stream) nigdy nie spelnial zadnego warunku i
                -- wracal do kolejki bez konca. IS NOT NULL obejmuje OBA
                -- jawnie zapisane wyniki (0 i 1) - ukonczone znaczy teraz
                -- podjeto probe, nie proba sie powiodla.
                WHEN (found_in_ufs = 0 OR mtime_ufs IS NOT NULL OR io_error_ufs IS NOT NULL)
                 AND (found_in_script = 0 OR mtime_script IS NOT NULL OR io_error_script IS NOT NULL) THEN 1
                ELSE 0
            END
         WHERE phase5_done = 0 OR phase5_done IS NULL",
        []
    )?;

    // --- ETAP 5: GENEROWANIE DZIENNIKA KOŃCOWEGO ---
    let mut match_count = 0;
    let mut mismatch_mtime_count = 0;
    let mut ufs_older_count = 0;
    let mut script_older_count = 0;
    let mut mismatch_perms_count = 0;
    let mut mismatch_uid_count = 0;
    let mut mismatch_mode_count = 0;

    let mut stmt = conn.prepare(
        "SELECT uid_ufs, uid_script, gid_ufs, gid_script, mode_ufs, mode_script, mtime_ufs, mtime_script, is_symlink_ufs, is_symlink_script 
         FROM files WHERE phase5_done = 1 AND found_in_ufs = 1 AND found_in_script = 1 AND io_error_ufs = 0 AND io_error_script = 0"
    )?;
    
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, u32>(0)?, row.get::<_, u32>(1)?, row.get::<_, u32>(2)?, row.get::<_, u32>(3)?,
            row.get::<_, u32>(4)?, row.get::<_, u32>(5)?, row.get::<_, i64>(6)?, row.get::<_, i64>(7)?,
            row.get::<_, bool>(8)?, row.get::<_, bool>(9)?
        ))
    })?;

    for r in rows.filter_map(|r| r.ok()) {
        let (u_uid, s_uid, u_gid, s_gid, u_mode, s_mode, u_mtime, s_mtime, u_sym, s_sym) = r;
        
        if u_uid == s_uid && u_gid == s_gid && u_mode == s_mode && u_mtime == s_mtime && u_sym == s_sym {
            match_count += 1;
        } else {
            if u_mtime != s_mtime {
                mismatch_mtime_count += 1;
                if u_mtime < s_mtime { ufs_older_count += 1; } else { script_older_count += 1; }
            } else {
                mismatch_perms_count += 1;
                if u_uid != s_uid || u_gid != s_gid { mismatch_uid_count += 1; }
                if u_mode != s_mode { mismatch_mode_count += 1; }
            }
        }
    }
    drop(stmt);

    let errors = ufs_stats.errors.load(Ordering::SeqCst) + script_stats.errors.load(Ordering::SeqCst);
    let elapsed = start_time.elapsed();

    // -- GENEROWANIE RAPORTU TEKSTOWEGO --
    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(&mut log_out, "==========================================================================");
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 5 (ATRYBUTY ZEWNĘTRZNE I-NODE)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "==========================================================================\n");
    
    let _ = writeln!(&mut log_out, "[ 1 ] FIZYCZNY ROZKŁAD STRUKTURY (Anomalie Systemu Plików):");
    let print_anom_txt = |out: &mut String, name: &str, u_val: usize, s_val: usize, explanation: &str| {
        if u_val > 0 || s_val > 0 {
            let _ = writeln!(out, "   -> {}: UFS [{}], Skrypt [{}]", name, u_val, s_val);
            let _ = writeln!(out, "      [ ZNACZENIE ]: {}", explanation);
        }
    };
    print_anom_txt(&mut log_out, "Utracone Daty (Epoka 1970 r.)", ufs_stats.epoch_zero.load(Ordering::SeqCst), script_stats.epoch_zero.load(Ordering::SeqCst), "Data modyfikacji pliku została zniszczona lub system przywrócił ją do absolutnego zera (1 Stycznia 1970).");
    print_anom_txt(&mut log_out, "Dowiązania Twarde (Hardlinks)", ufs_stats.hardlinks.load(Ordering::SeqCst), script_stats.hardlinks.load(Ordering::SeqCst), "Kilka różnych plików wskazuje na ten sam fizyczny blok danych na dysku. Ważne dla deduplikacji.");
    print_anom_txt(&mut log_out, "Dowiązania Miękkie (Symlinks)", ufs_stats.symlinks.load(Ordering::SeqCst), script_stats.symlinks.load(Ordering::SeqCst), "Są to tylko skróty do innych ścieżek. Po odzyskaniu często prowadzą donikąd.");
    print_anom_txt(&mut log_out, "Złamanie Właściciela (UID = 0 / ROOT)", ufs_stats.root_owned.load(Ordering::SeqCst), script_stats.root_owned.load(Ordering::SeqCst), "Pliki z uprawnieniami superużytkownika. Może to być systemowy sterownik, lub ślad iniekcji.");
    print_anom_txt(&mut log_out, "Podwyższone Uprawnienia (SUID/SGID)", ufs_stats.suid_sgid.load(Ordering::SeqCst), script_stats.suid_sgid.load(Ordering::SeqCst), "Krytyczne ryzyko bezpieczeństwa. Uruchomienie tego pliku nadaje użytkownikowi prawa właściciela pliku.");
    print_anom_txt(&mut log_out, "Przepełnienie Znacznika Czasu (i64)", ufs_stats.mtime_overflow.load(Ordering::SeqCst), script_stats.mtime_overflow.load(Ordering::SeqCst), "Pole czasu i-node jest fizycznie zniszczone do wartości, której nie da się już zapisać jako precyzyjny znacznik nanosekundowy. mtime pozostaje NULL w bazie (zamiast fałszywej, zawiniętej daty).");
    let _ = writeln!(&mut log_out);

    let _ = writeln!(&mut log_out, "[ 2 ] KORELACJA Z BAZĄ DANYCH (Porównanie Odzysków):");
    let _ = writeln!(&mut log_out, "   -> Zgodne w 100% (Prawa + Data): {}", match_count);
    
    if mismatch_mtime_count > 0 {
        let _ = writeln!(&mut log_out, "   -> Różne Daty Modyfikacji:       {}", mismatch_mtime_count);
        let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Metadane czasu uległy uszkodzeniu w jednym ze skanerów.");
        let _ = writeln!(&mut log_out, "      * W {} przypadkach UFS Explorer odratował STARSZĄ (prawdopodobnie oryginalną) datę.", ufs_older_count);
        let _ = writeln!(&mut log_out, "      * W {} przypadkach Skrypt Autorski odratował STARSZĄ datę.", script_older_count);
    }
    if mismatch_perms_count > 0 {
        let _ = writeln!(&mut log_out, "   -> Różne Prawa/Właściciel:       {}", mismatch_perms_count);
        let _ = writeln!(&mut log_out, "      [ ZNACZENIE ]: Podczas odzyskiwania, system nadpisał strukturę i-node domyślnymi uprawnieniami.");
        if mismatch_uid_count > 0 {
            let _ = writeln!(&mut log_out, "      * Różni właściciele pliku w:         {} przypadkach", mismatch_uid_count);
        }
        if mismatch_mode_count > 0 {
            let _ = writeln!(&mut log_out, "      * Złamana flaga CHMOD w:             {} przypadkach", mismatch_mode_count);
        }
    }
    
    // PRZYWRÓCONE: Zestawienie wagowe formatów i-node
    let _ = writeln!(&mut log_out, "\n[ 3 ] ZESTAWIENIE WAGOWE FORMATÓW (Top 5):");
    let print_all_exts = |out_str: &mut String, map: &HashMap<String, u64>, label: &str| {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        let _ = writeln!(out_str, "   {}", label);
        if sorted.is_empty() { let _ = writeln!(out_str, "      Brak plików."); }
        for (ext, weight) in sorted.into_iter().take(5) { 
            let e = if ext == "brak" { "brak".to_string() } else { format!(".{}", ext) };
            let _ = writeln!(out_str, "      - {:<8} : {}", e, format_bytes(*weight));
        }
    };
    print_all_exts(&mut log_out, &ufs_stats.ext_weights.lock().unwrap(), "UFS Explorer");
    print_all_exts(&mut log_out, &script_stats.ext_weights.lock().unwrap(), "Skrypt Autorski");

    // PRZYWRÓCONE: Zestawienie Właścicieli
    let _ = writeln!(&mut log_out, "\n[ 4 ] TOP 3 WŁAŚCICIELI PLIKÓW (UID):");
    let print_top_uid = |out_str: &mut String, map: &HashMap<u32, usize>, label: &str| {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        let _ = writeln!(out_str, "   {}", label);
        for (uid, count) in sorted.into_iter().take(3) { 
            let _ = writeln!(out_str, "      - UID: {:<5} przypisano do {} plików", uid, count);
        }
    };
    print_top_uid(&mut log_out, &ufs_stats.uid_counts.lock().unwrap(), "UFS Explorer");
    print_top_uid(&mut log_out, &script_stats.uid_counts.lock().unwrap(), "Skrypt Autorski");

    // PRZYWRÓCONE: Zestawienie Uprawnień
    let _ = writeln!(&mut log_out, "\n[ 5 ] TOP 3 STRUKTUR UPRAWNIEŃ (CHMOD):");
    let print_top_mode = |out_str: &mut String, map: &HashMap<String, usize>, label: &str| {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        let _ = writeln!(out_str, "   {}", label);
        for (mode, count) in sorted.into_iter().take(3) { 
            let _ = writeln!(out_str, "      - Prawa: {:<12} wystąpiły w {} plikach", mode, count);
        }
    };
    print_top_mode(&mut log_out, &ufs_stats.mode_counts.lock().unwrap(), "UFS Explorer");
    print_top_mode(&mut log_out, &script_stats.mode_counts.lock().unwrap(), "Skrypt Autorski");

    if errors > 0 {
        let _ = writeln!(&mut log_out, "\n[ 6 ] BŁĘDY FIZYCZNE I/O (Brak dostępu do węzła):");
        let _ = writeln!(&mut log_out, "   -> Błędy odczytu (I/O): {}", errors);
    }

    // Zapis do fizycznego pliku "Dziennik Końcowy"
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
        match_count,
        mismatch_mtime_count,
        mismatch_perms_count,
        errors,
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 5 zakończona"
    );
    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ------------------------------------------------------------------
    // compute_activity_slots (identyczna logika z Fazy 3/4)
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
    // compute_precise_mtime — REGRESJA (measure twice — druga weryfikacja
    // Gemini, N1): brak bezpośredniego testu na tę funkcję pozwoliłby
    // przyszłej refaktoryzacji (np. powrót do zwykłego `*`/`i64` "dla
    // wydajności") po cichu przywrócić panikę/przepełnienie i przejść
    // `cargo test` bez ostrzeżenia — ta funkcja jest odpowiedzialna
    // dokładnie za błąd, który ta naprawa miała wyeliminować.
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_precise_mtime_normal_value() {
        assert_eq!(compute_precise_mtime(1_700_000_000, 123_456_789), Some(1_700_000_000_123_456_789));
    }

    #[test]
    fn test_compute_precise_mtime_negative_epoch_is_valid_not_overflow() {
        // Data sprzed 1970 (ujemny mtime) jest samym w sobie poprawną,
        // policzalną wartością (osobna anomalia "Epoka 1970" wykrywa to
        // wyżej, w process_side_stream, nie tutaj) - odróżnić od `None`
        // (fizycznego przepełnienia i64).
        assert_eq!(compute_precise_mtime(-1_000, 0), Some(-1_000_000_000_000));
    }

    #[test]
    fn test_compute_precise_mtime_exact_i64_max_boundary_fits() {
        // sec * 1e9 + nsec == i64::MAX dokładnie - musi się zmieścić.
        assert_eq!(compute_precise_mtime(9_223_372_036, 854_775_807), Some(i64::MAX));
    }

    #[test]
    fn test_compute_precise_mtime_one_nanosecond_past_i64_max_overflows_to_none() {
        // Ten sam `sec` co wyżej, +1ns - o jeden krok za granicą i64::MAX.
        assert_eq!(compute_precise_mtime(9_223_372_036, 854_775_808), None);
    }

    #[test]
    fn test_compute_precise_mtime_i64_max_sec_overflows_to_none() {
        assert_eq!(compute_precise_mtime(i64::MAX, 0), None);
    }

    #[test]
    fn test_compute_precise_mtime_i64_min_sec_overflows_to_none() {
        assert_eq!(compute_precise_mtime(i64::MIN, 0), None);
    }

    // ------------------------------------------------------------------
    // wymaga_ponownego_odczytu — REGRESJA N2: plik z trwale nieobliczalnym
    // mtime (lstat udane, io_error=Some(false)) nie może wracać do kolejki
    // w nieskończoność.
    // ------------------------------------------------------------------

    #[test]
    fn test_wymaga_ponownego_odczytu_gdy_nigdy_nie_przetworzono() {
        assert!(wymaga_ponownego_odczytu(None, None));
    }

    #[test]
    fn test_nie_wymaga_ponownego_odczytu_gdy_mtime_policzone() {
        assert!(!wymaga_ponownego_odczytu(Some(1_700_000_000_000_000_000), None));
    }

    #[test]
    fn test_nie_wymaga_ponownego_odczytu_przy_prawdziwym_bledzie_io() {
        assert!(!wymaga_ponownego_odczytu(None, Some(true)));
    }

    #[test]
    fn test_nie_wymaga_ponownego_odczytu_gdy_lstat_udane_ale_mtime_trwale_nieobliczalne() {
        // Sedno naprawy: lstat się powiodło (io_error jawnie zapisane jako
        // false), ale mtime pozostaje NULL (przepełnienie i64) - plik NIE
        // może wrócić do kolejki, bo wynik będzie identyczny przy każdej
        // kolejnej próbie.
        assert!(!wymaga_ponownego_odczytu(None, Some(false)));
    }

    // ------------------------------------------------------------------
    // format_permissions
    // ------------------------------------------------------------------

    #[test]
    fn test_format_permissions_regular_file_rwxr_xr_x() {
        // 0o755 = rwxr-xr-x
        assert_eq!(format_permissions(0o755, false, false), "-rwxr-xr-x");
    }

    #[test]
    fn test_format_permissions_regular_file_rw_r_r() {
        // 0o644 = rw-r--r-- (podwójne myślniki w komentarzu, nie w nazwie testu -
        // nazwa funkcji zgodna z sugestią kompilatora, dokładne bity dokumentuje komentarz)
        assert_eq!(format_permissions(0o644, false, false), "-rw-r--r--");
    }

    #[test]
    fn test_format_permissions_directory_prefix() {
        assert_eq!(format_permissions(0o755, false, true), "drwxr-xr-x");
    }

    #[test]
    fn test_format_permissions_symlink_prefix() {
        // Symlink zwykle ma 0o777, ale prefix 'l' liczy się niezależnie od trybu
        assert_eq!(format_permissions(0o777, true, false), "lrwxrwxrwx");
    }

    #[test]
    fn test_format_permissions_suid_lowercase_s_when_executable() {
        // SUID (0o4000) + bit wykonywalny user (0o100) -> mała litera 's'
        assert_eq!(format_permissions(0o4755, false, false), "-rwsr-xr-x");
    }

    #[test]
    fn test_format_permissions_suid_uppercase_s_when_not_executable() {
        // SUID (0o4000) BEZ bitu wykonywalnego user -> wielka litera 'S'
        assert_eq!(format_permissions(0o4644, false, false), "-rwSr--r--");
    }

    #[test]
    fn test_format_permissions_sgid_lowercase_s() {
        // SGID (0o2000) + bit wykonywalny group (0o010) -> mała litera 's' w trójce group
        assert_eq!(format_permissions(0o2755, false, false), "-rwxr-sr-x");
    }

    #[test]
    fn test_format_permissions_sticky_bit_lowercase_t() {
        // Sticky (0o1000) + bit wykonywalny other (0o001) -> mała litera 't'
        assert_eq!(format_permissions(0o1777, false, true), "drwxrwxrwt");
    }

    #[test]
    fn test_format_permissions_sticky_bit_uppercase_t_when_not_executable() {
        // Sticky (0o1000) BEZ bitu wykonywalnego other -> wielka litera 'T'
        assert_eq!(format_permissions(0o1666, false, true), "drw-rw-rwT");
    }

    #[test]
    fn test_format_permissions_no_access_at_all() {
        assert_eq!(format_permissions(0o000, false, false), "----------");
    }

    #[test]
    fn test_format_permissions_full_access_all_groups() {
        assert_eq!(format_permissions(0o777, false, false), "-rwxrwxrwx");
    }

    // ------------------------------------------------------------------
    // build_source_block
    // ------------------------------------------------------------------

    #[test]
    fn test_build_source_block_reports_own_stats_only() {
        let stats = LiveStats::new(4);
        stats.symlinks.store(3, Ordering::Relaxed);
        stats.hardlinks.store(2, Ordering::Relaxed);
        stats.root_owned.store(1, Ordering::Relaxed);
        stats.suid_sgid.store(4, Ordering::Relaxed);
        stats.executables.store(10, Ordering::Relaxed);
        stats.epoch_zero.store(5, Ordering::Relaxed);
        stats.mtime_overflow.store(6, Ordering::Relaxed);
        stats.errors.store(2, Ordering::Relaxed);

        let start_time = Instant::now() - Duration::from_secs(1);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        assert!(block.starts_with("[UFS Explorer]"));
        assert!(block.contains("Dowiązania miękkie: 3"));
        assert!(block.contains("Dowiązania twarde: 2"));
        assert!(block.contains("Właściciel root: 1"));
        assert!(block.contains("SUID/SGID: 4"));
        assert!(block.contains("Pliki wykonywalne: 10"));
        assert!(block.contains("Epoka zerowa (1970): 5"));
        assert!(block.contains("Przepełnienie znacznika czasu: 6"));
        assert!(block.contains("Błędy I/O: 2"));
    }

    #[test]
    fn test_build_source_block_shows_thread_activity_markup() {
        let stats = LiveStats::new(2);
        stats.thread_activity.mark_busy(0);

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        let line = block.lines().find(|l| l.starts_with("Wątki lstat")).expect("powinna istnieć linia Wariantu A");
        assert_eq!(line, "Wątki lstat (Wariant A): {G:1} {R:2}");
    }

    #[test]
    fn test_build_source_block_empty_stats_show_placeholders() {
        let stats = LiveStats::new(4);
        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("Skrypt Autorski", &stats, start_time);

        assert!(block.contains("Top format: Analiza danych..."));
        assert!(block.contains("Top UID: ..."));
        assert!(block.contains("Top uprawnienia: ..."));
    }

    #[test]
    fn test_build_source_block_top_uid_by_frequency() {
        let stats = LiveStats::new(4);
        stats.uid_counts.lock().unwrap().insert(1000, 5);
        stats.uid_counts.lock().unwrap().insert(0, 20); // root - powinien wygrać

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("UFS Explorer", &stats, start_time);

        let uid_line = block.lines().find(|l| l.starts_with("Top UID:")).unwrap();
        // UID 0 (20 wystąpień) powinien pojawić się przed UID 1000 (5 wystąpień)
        let pos_root = uid_line.find("UID 0 (20)").expect("UID 0 powinien być na liście");
        let pos_other = uid_line.find("UID 1000 (5)").expect("UID 1000 powinien być na liście");
        assert!(pos_root < pos_other, "Częstszy UID powinien być wymieniony pierwszy");
    }

    #[test]
    fn test_build_source_block_does_not_leak_other_side_data() {
        // Kontrakt architektoniczny: build_source_block przyjmuje TYLKO jeden
        // LiveStats - nie ma możliwości wmieszania drugiej strony (w przeciwieństwie
        // do Fazy 3). Test dokumentuje ten kontrakt przez samą sygnaturę + wynik.
        let stats = LiveStats::new(4);
        stats.symlinks.store(42, Ordering::Relaxed);

        let start_time = Instant::now() - Duration::from_millis(500);
        let block = build_source_block("Skrypt Autorski", &stats, start_time);
        assert!(block.contains("Dowiązania miękkie: 42"));
    }
}
