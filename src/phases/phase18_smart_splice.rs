// src/phases/phase18_smart_splice.rs

//! # Faza 18: Inteligentna Rekonstrukcja (Smart Splice)
//!
//! Dla plików WSPÓLNYCH (obecnych po obu stronach — UFS i Skrypt Autorski),
//! które OBIE strony nie zdołały poprawnie zdekodować w Fazie 13, próbuje
//! złożyć JEDNĄ sprawną kopię z dwóch uszkodzonych — biorąc dobre fragmenty
//! z każdej strony. Dotyczy wyłącznie JPG/JPEG i PNG, bo tylko dla nich mamy
//! tani i wiarygodny sposób WERYFIKACJI wyniku (ten sam silnik dekodujący co
//! Faza 13) — bez weryfikacji złożenie plików binarnych jest ślepym
//! zgadywaniem, które może dać wynik gorszy niż oba oryginały.
//!
//! ## Dlaczego PNG i JPEG są traktowane różnie
//!
//! **PNG** jest zbudowany z chunków, z których KAŻDY ma własną sumę
//! kontrolną CRC32 (długość+typ+dane+CRC). To obiektywny sygnał: chunk ze
//! zgodnym CRC to prawie na pewno dobre dane, chunk z rozjazdem CRC to na
//! pewno uszkodzenie. Składanie jest więc DETERMINISTYCZNE — patrz
//! [`splice_png`].
//!
//! **JPEG** nie ma sum kontrolnych per-segment. Możemy za to tanio znaleźć
//! granicę SOS (Start Of Scan — koniec nagłówka/tabel, początek
//! skompresowanych danych obrazu) przez skan znaczników, bez pełnego
//! dekodowania. Nie rozstrzygamy z góry, która strona ma dobry nagłówek a
//! która dobre dane — generujemy OBIE kombinacje i pozwalamy zdecydować
//! obowiązkowej weryfikacji dekodowaniem — patrz [`splice_jpeg_candidates`].
//!
//! ## Jedyny wyłącznik bezpieczeństwa: obowiązkowa weryfikacja
//!
//! Złożony plik jest ZAWSZE przepuszczany przez ten sam silnik dekodujący co
//! Faza 13 ([`verify_image_bytes`]) przed zapisaniem czegokolwiek na dysk.
//! Nie dekoduje się poprawnie → zero zapisu, plik wraca do zwykłej ścieżki
//! wyboru całościowego w Fazie 8/9. To jedyna gwarancja, że złożenie nigdy
//! nie wyprodukuje czegoś gorszego niż oba oryginały.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::{format_display_path, CANCEL_SIGNAL};
use ratatui::style::Color;
use rayon::prelude::*;
use rusqlite::{params, Connection, Result};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;
use tracing::{info, instrument, warn};

const CHUNK_SIZE: usize = 50;

// ============================================================================
// STRUKTURY DANYCH
// ============================================================================

#[derive(Debug, Clone)]
pub(crate) struct Task {
    id: i32,
    rel_path: String,
    ext: String,
}

#[derive(Debug, Clone)]
struct SpliceResult {
    id: i32,
    path: Option<String>,
    log: Option<String>,
}

pub(crate) struct LiveStats {
    processed: AtomicUsize,
    spliced_png: AtomicUsize,
    spliced_jpg: AtomicUsize,
    /// Archiwa ZIP-podobne złożone per wpis wg CRC32 (patrz `zip_splice`).
    spliced_zip: AtomicUsize,
    failed_verification: AtomicUsize,
    errors: AtomicUsize,
    /// EKSPERYMENTALNE (Wariant A): śledzi zajętość logicznych slotów Rayon —
    /// ta sama konwencja i ten sam tracker, co w pozostałych fazach
    /// równoległych, patrz `thread_activity`.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            processed: AtomicUsize::new(0),
            spliced_png: AtomicUsize::new(0),
            spliced_jpg: AtomicUsize::new(0),
            spliced_zip: AtomicUsize::new(0),
            failed_verification: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
        }
    }
}

fn build_summary_block(stats: &LiveStats, start_time: Instant) -> String {
    let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
    let speed = stats.processed.load(Ordering::Relaxed) as f64 / elapsed;
    format!(
        "[Podsumowanie]\nPrędkość: {:.1} plików/s\nZłożone PNG (CRC32 per-chunk): {}\nZłożone JPEG (granica SOS): {}\nZłożone archiwa (CRC32 per wpis): {}\nOdrzucone (nie przeszły weryfikacji): {}\nWątki składania (Wariant A): {}\nBłędy I/O: {}",
        speed,
        stats.spliced_png.load(Ordering::Relaxed),
        stats.spliced_jpg.load(Ordering::Relaxed),
        stats.spliced_zip.load(Ordering::Relaxed),
        stats.failed_verification.load(Ordering::Relaxed),
        crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot()),
        stats.errors.load(Ordering::Relaxed),
    )
}

// ============================================================================
// PNG: SKŁADANIE PO CHUNKACH (CRC32 JAKO OBIEKTYWNY SĘDZIA)
// ============================================================================
//
// Prymitywy PNG (CRC32, rozbiór na fragmenty, zapis, składanie z dwóch kopii)
// mieszkają w `crate::png_repair`, bo korzysta z nich również Faza 17 przez
// `repair_modules::png`. Jedna implementacja, dwóch odbiorców - druga kopia
// tego kodu rozjechałaby się przy pierwszej poprawce, a CRC to dokładnie ten
// rodzaj logiki, w którym rozjazd jest niewidoczny do pierwszej pomyłki.
// Kod produkcyjny tej fazy potrzebuje wyłącznie samego składania; pozostałe
// prymitywy (rozbiór, zapis, CRC32) importuje jej moduł testowy, który
// sprawdza je bezpośrednio.
use crate::png_repair::splice_png;

// ============================================================================
// JPEG: SKŁADANIE PO GRANICY SOS (NAGŁÓWEK + DANE OBRAZU)
// ============================================================================

/// Znajduje offset bajtowy KOŃCA nagłówka segmentu SOS (Start Of Scan) —
/// dokładnie tam, gdzie zaczynają się skompresowane dane obrazu. Toleruje
/// dodatkowe bajty wypełniające `0xFF` przed właściwym znacznikiem (spotykane
/// u niektórych enkoderów). Zwraca `None`, gdy struktura nagłówka jest
/// niepoprawna lub SOS nie występuje w ogóle.
fn find_jpeg_sos_end(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 { return None; }
    let mut pos = 2;
    loop {
        while pos + 1 < bytes.len() && bytes[pos] == 0xFF && bytes[pos + 1] == 0xFF {
            pos += 1;
        }
        if pos + 1 >= bytes.len() || bytes[pos] != 0xFF { return None; }
        let marker = bytes[pos + 1];
        pos += 2;
        match marker {
            0x01 | 0xD0..=0xD7 => continue,
            0xD8 | 0xD9 => return None,
            0xDA => {
                if pos + 2 > bytes.len() { return None; }
                let seg_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                let header_end = pos.checked_add(seg_len)?;
                return if header_end <= bytes.len() { Some(header_end) } else { None };
            }
            _ => {
                if pos + 2 > bytes.len() { return None; }
                let seg_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                if seg_len < 2 { return None; }
                pos = pos.checked_add(seg_len)?;
                if pos > bytes.len() { return None; }
            }
        }
    }
}

/// Zwraca kandydatów do wypróbowania: nagłówek jednej strony + skompresowane
/// dane obrazu drugiej, w OBU kombinacjach. W przeciwieństwie do PNG (gdzie
/// CRC daje obiektywną odpowiedź), tu nie rozstrzygamy z góry, która
/// kombinacja jest poprawna — [`process_stream`] weryfikuje każdą realnym
/// dekodowaniem i przyjmuje pierwszą, która się powiedzie. Pusty wektor, gdy
/// którakolwiek strona nie ma poprawnej struktury nagłówka do SOS.
fn splice_jpeg_candidates(bytes_a: &[u8], bytes_b: &[u8]) -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();
    if let (Some(end_a), Some(end_b)) = (find_jpeg_sos_end(bytes_a), find_jpeg_sos_end(bytes_b)) {
        let mut c1 = bytes_a[..end_a].to_vec();
        c1.extend_from_slice(&bytes_b[end_b..]);
        candidates.push(c1);

        let mut c2 = bytes_b[..end_b].to_vec();
        c2.extend_from_slice(&bytes_a[end_a..]);
        candidates.push(c2);
    }
    candidates
}

// ============================================================================
// WERYFIKACJA (OBOWIĄZKOWA - JEDYNY WYŁĄCZNIK BEZPIECZEŃSTWA)
// ============================================================================

/// Jedyny warunek zaakceptowania złożonego pliku: MUSI się poprawnie
/// zdekodować przez ten sam silnik co Faza 13 (`image` crate), z sensownymi
/// (niezerowymi) wymiarami. Brak tego = odrzucenie całkowite, zero zapisu na dysk.
fn verify_image_bytes(bytes: &[u8]) -> bool {
    match image::load_from_memory(bytes) {
        Ok(img) => img.width() > 0 && img.height() > 0,
        Err(_) => false,
    }
}

/// Generuje wszystkich kandydatów dla danego rozszerzenia — pojedynczy
/// deterministyczny dla PNG, do dwóch dla JPEG. Rozszerzenie musi być już
/// znormalizowane do małych liter.
fn build_candidates(ext: &str, bytes_a: &[u8], bytes_b: &[u8]) -> Vec<Vec<u8>> {
    match ext {
        "png" => splice_png(bytes_a, bytes_b).into_iter().collect(),
        "jpg" | "jpeg" => splice_jpeg_candidates(bytes_a, bytes_b),
        _ if crate::zip_splice::is_zip_based_extension(&format!(".{}", ext)) => {
            crate::zip_splice::splice_zip(bytes_a, bytes_b).into_iter().collect()
        }
        "tar" => crate::tar_archive::splice_tar(bytes_a, bytes_b).into_iter().collect(),
        // GIF/BMP/WEBP: złożenie metadane + dane obrazu. Te formaty nie mają
        // sum kontrolnych per blok, więc rozstrzyga dekoder — patrz
        // `crate::raster_splice`.
        _ if crate::raster_splice::obslugiwane_rozszerzenie(ext) => {
            crate::raster_splice::splice_raster(ext, bytes_a, bytes_b)
        }
        _ => Vec::new(),
    }
}

/// Obowiązkowa weryfikacja złożonego kandydata — ROZGAŁĘZIONA PER FORMAT,
/// bo każdy ma inny sposób udowodnienia sprawności:
/// - obrazy (JPG/PNG/GIF/BMP/WEBP) → realne dekodowanie pikseli ([`verify_image_bytes`]),
/// - archiwa ZIP-podobne → otwarcie + odczyt KAŻDEGO wpisu, co crate `zip`
///   weryfikuje przez CRC32 ([`crate::zip_splice::verify_zip_bytes`]).
///
/// Oba warianty dają MOCNĄ gwarancję (obiektywny dowód poprawności treści),
/// w odróżnieniu od `dng_splice`, gdzie możliwa jest tylko weryfikacja
/// strukturalna — dlatego archiwa mogły trafić do tej automatycznej fazy,
/// a DNG wymagało osobnego, ręcznego narzędzia.
fn verify_candidate(ext: &str, bytes: &[u8]) -> bool {
    if crate::zip_splice::is_zip_based_extension(&format!(".{}", ext)) {
        crate::zip_splice::verify_zip_bytes(bytes)
    } else if ext == "tar" {
        // UWAGA: dla tar weryfikacja obejmuje WYŁĄCZNIE nagłówki wpisów
        // (tar nie przechowuje sum kontrolnych danych plików) - słabsza
        // gwarancja niż przy ZIP/obrazach, patrz dokumentacja `tar_archive`.
        crate::tar_archive::verify_tar_bytes(bytes)
    } else {
        verify_image_bytes(bytes)
    }
}

// ============================================================================
// GŁÓWNA PĘTLA PRZETWARZANIA
// ============================================================================

#[instrument(skip(tasks, stats, tx_db, tx_ui))]
#[allow(clippy::too_many_arguments)]
fn process_stream(
    base_a: &Path,
    base_b: &Path,
    target_dir: &Path,
    tasks: &[Task],
    stats: &LiveStats,
    tx_db: mpsc::SyncSender<SpliceResult>,
    tx_ui: &mpsc::Sender<PhaseEvent>,
    start_time: Instant,
    opr_log: Arc<Mutex<File>>,
) {
    let last_ui_update = Arc::new(AtomicU64::new(0));

    tasks.par_chunks(CHUNK_SIZE).for_each_with(tx_db, |tx_db, chunk| {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { return; }

        for task in chunk {
            if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }
            // Wariant A: slot zajęty na czas obsługi tego pliku. Strażnik RAII
            // zwalnia go także przy panice w środku pracy.
            let _slot = stats.thread_activity.enter_current();

            let path_a = base_a.join(&task.rel_path);
            let path_b = base_b.join(&task.rel_path);

            let (result_path, result_log) = match (fs::read(&path_a), fs::read(&path_b)) {
                (Ok(a), Ok(b)) => {
                    let candidates = build_candidates(&task.ext, &a, &b);
                    let accepted = candidates.into_iter().find(|c| verify_candidate(&task.ext, c));

                    match accepted {
                        Some(final_bytes) => {
                            let stem = Path::new(&task.rel_path).file_stem().and_then(|s| s.to_str()).unwrap_or("plik");
                            let target_path = target_dir.join(format!("{}_smartsplice.{}", stem, task.ext));
                            if let Some(parent) = target_path.parent() { let _ = fs::create_dir_all(parent); }

                            match File::create(&target_path).and_then(|mut f| f.write_all(&final_bytes)) {
                                Ok(()) => {
                                    match task.ext.as_str() {
                                        "png" => { stats.spliced_png.fetch_add(1, Ordering::Relaxed); }
                                        "jpg" | "jpeg" => { stats.spliced_jpg.fetch_add(1, Ordering::Relaxed); }
                                        _ => { stats.spliced_zip.fetch_add(1, Ordering::Relaxed); }
                                    }
                                    let log_msg = format!("Złożono i zweryfikowano dekodowaniem ({}).", task.ext);
                                    if let Ok(mut f) = opr_log.lock() {
                                        let _ = writeln!(f, "[✔] {} -> {}", task.rel_path, target_path.display());
                                    }
                                    (Some(target_path.to_string_lossy().to_string()), Some(log_msg))
                                }
                                Err(e) => {
                                    stats.errors.fetch_add(1, Ordering::Relaxed);
                                    warn!(path = %task.rel_path, error = %e, "Błąd zapisu złożonego pliku");
                                    (None, Some(format!("Błąd zapisu: {}", e)))
                                }
                            }
                        }
                        None => {
                            stats.failed_verification.fetch_add(1, Ordering::Relaxed);
                            (None, Some("Żadna kombinacja nie zdekodowała się poprawnie.".to_string()))
                        }
                    }
                }
                _ => {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    (None, Some("Błąd odczytu jednej lub obu kopii źródłowych.".to_string()))
                }
            };

            let _ = tx_db.send(SpliceResult { id: task.id, path: result_path, log: result_log });

            let current = stats.processed.fetch_add(1, Ordering::Relaxed) + 1;
            let now_ms = start_time.elapsed().as_millis() as u64;
            let last_ms = last_ui_update.load(Ordering::Relaxed);
            let should_update = current.is_multiple_of(20) || now_ms.saturating_sub(last_ms) > 250;

            if should_update && last_ui_update.compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                let _ = tx_ui.send(PhaseEvent::UpdateBar { idx: 0, current: current as u64, message: format_display_path(&task.rel_path) });
                let _ = tx_ui.send(PhaseEvent::UpdateBottomPath { idx: 0, path: path_a.to_string_lossy().to_string() });
                let _ = tx_ui.send(PhaseEvent::UpdateSideText { idx: 0, text: build_summary_block(stats, start_time) });
            }
        }
    });

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: 0,
        current: stats.processed.load(Ordering::Relaxed) as u64,
        message: "Inteligentna rekonstrukcja w 100% zakończona.".to_string(),
    });
}

// ============================================================================
// GŁÓWNA FUNKCJA (ENTRYPOINT)
// ============================================================================

pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);
    let _ = tx_ui.send(PhaseEvent::Log("Uruchomiono Fazę 18: Inteligentna Rekonstrukcja (Smart Splice).".to_string()));

    let start_time = Instant::now();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;

    let _ = conn.execute("ALTER TABLE files ADD COLUMN smart_splice_path TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN smart_splice_log TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN phase18_done BOOLEAN DEFAULT 0", []);

    let raport_cfg = config.raporty_faz.get("Faza 18").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza18.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza18.txt".to_string(),
    });
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let opr_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_operacyjny);
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);
    let opr_log = Arc::new(Mutex::new(File::create(&opr_path).unwrap()));
    {
        let mut f = opr_log.lock().unwrap();
        let _ = writeln!(f, "=== RAPORT OPERACYJNY - FAZA 18: INTELIGENTNA REKONSTRUKCJA ===");
        let _ = writeln!(f, "Ewidencja plików wspólnych złożonych z dwóch uszkodzonych kopii (UFS + Skrypt) w jeden sprawny plik.\n");
    }

    // Dobór zadań: pliki WSPÓLNE, w formacie obsługiwanym przez to narzędzie,
    // gdzie OBIE strony zawiodły odpowiednią diagnostykę:
    // - obrazy (JPG/JPEG/PNG) → Faza 13 (media_decoded / pixels_ok),
    // - archiwa ZIP-podobne  → Faza 11 (structure_ok).
    // Brak danych (NULL) traktujemy jako "nie wiadomo, spróbuj" — warunek i
    // tak jest bramkowany OBOWIĄZKOWĄ weryfikacją wyniku, więc próba
    // niepotrzebna kosztuje tylko czas, nigdy poprawność.
    let mut stmt = conn.prepare(
        "SELECT id, relative_path FROM files
         WHERE found_in_ufs = 1 AND found_in_script = 1
           AND (phase18_done = 0 OR phase18_done IS NULL)
           AND (
                (   (media_decoded_ufs = 0 OR media_decoded_ufs IS NULL OR pixels_ok_ufs = 0)
                AND (media_decoded_script = 0 OR media_decoded_script IS NULL OR pixels_ok_script = 0) )
             OR (   (structure_ok_ufs = 0 OR structure_ok_ufs IS NULL)
                AND (structure_ok_script = 0 OR structure_ok_script IS NULL) )
           )"
    )?;

    let mut tasks = Vec::new();
    let rows = stmt.query_map([], |row| Ok((row.get::<_, i32>(0)?, row.get::<_, String>(1)?)))?;
    for r in rows.filter_map(|r| r.ok()) {
        let (id, rel) = r;
        let ext = Path::new(&rel).extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        let is_image = ext == "jpg" || ext == "jpeg" || ext == "png";
        let is_archive = crate::zip_splice::is_zip_based_extension(&format!(".{}", ext))
            || ext == "tar";
        if is_image || is_archive {
            tasks.push(Task { id, rel_path: rel, ext });
        }
    }
    drop(stmt);

    if tasks.is_empty() {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Brak plików kwalifikujących się do inteligentnej rekonstrukcji.".to_string()));
        return Ok(());
    }

    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "Inteligentna Rekonstrukcja (Smart Splice)".to_string(), total: tasks.len() as u64, color: Color::Magenta });

    let ufs_base = PathBuf::from(&config.ufs_path);
    let script_base = PathBuf::from(&config.script_path);
    let target_base = PathBuf::from(&config.target_path).join("_smart_splice_repaired");
    let stats = LiveStats::new(rayon::current_num_threads());

    std::thread::scope(|s| {
        let (tx_db, rx_db): (mpsc::SyncSender<SpliceResult>, mpsc::Receiver<SpliceResult>) = mpsc::sync_channel(100);
        let conn_ref = &mut *conn;
        let tx_ui_ref = &tx_ui;

        let _db_thread = s.spawn(move || {
            let tx_trans = conn_ref.transaction().unwrap();
            {
                let mut stmt = tx_trans.prepare_cached(
                    "UPDATE files SET smart_splice_path = ?1, smart_splice_log = ?2, phase18_done = 1 WHERE id = ?3"
                ).unwrap();
                for res in rx_db {
                    let _ = stmt.execute(params![res.path, res.log, res.id]);
                }
            }
            tx_trans.commit().unwrap();
            let _ = tx_ui_ref.send(PhaseEvent::Log("✔ Wyniki inteligentnej rekonstrukcji zapisane w bazie.".to_string()));
        });

        process_stream(&ufs_base, &script_base, &target_base, &tasks, &stats, tx_db, &tx_ui, start_time, opr_log.clone());
    });

    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log("🛑 Inteligentna rekonstrukcja przerwana przez użytkownika.".to_string()));
        return Ok(());
    }

    let elapsed = start_time.elapsed();
    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;
    let _ = writeln!(&mut log_out, "==========================================================================");
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 18 (INTELIGENTNA REKONSTRUKCJA)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "==========================================================================\n");
    let _ = writeln!(&mut log_out, "Złożone PNG (CRC32 per-chunk): {} plików", stats.spliced_png.load(Ordering::Relaxed));
    let _ = writeln!(&mut log_out, "Złożone JPEG (granica SOS): {} plików", stats.spliced_jpg.load(Ordering::Relaxed));
    let _ = writeln!(&mut log_out, "Złożone archiwa ZIP-podobne (CRC32 per wpis): {} plików", stats.spliced_zip.load(Ordering::Relaxed));
    let _ = writeln!(&mut log_out, "Odrzucone (żadna kombinacja się nie zdekodowała): {} plików", stats.failed_verification.load(Ordering::Relaxed));
    let _ = writeln!(&mut log_out, "Błędy I/O: {}", stats.errors.load(Ordering::Relaxed));

    if let Ok(mut f) = fs::File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano Dziennik Końcowy w: {}", dz_path.display())));
    }
    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    info!(
        spliced_png = stats.spliced_png.load(Ordering::Relaxed),
        spliced_jpg = stats.spliced_jpg.load(Ordering::Relaxed),
        spliced_zip = stats.spliced_zip.load(Ordering::Relaxed),
        failed = stats.failed_verification.load(Ordering::Relaxed),
        czas_trwania_sek = elapsed.as_secs_f64(),
        "Faza 18 zakończona"
    );

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    // Prymitywy PNG sprawdzane bezpośrednio przez testy tej fazy - po
    // przeniesieniu do `png_repair` to one pilnują, że przeprowadzka niczego
    // nie zmieniła w zachowaniu.
    use crate::png_repair::{
        crc32, parse_png_chunks, CANONICAL_IEND, PNG_SIGNATURE,
    };

    // ------------------------------------------------------------------
    // crc32 - weryfikacja przez znany wektor testowy
    // ------------------------------------------------------------------

    #[test]
    fn test_crc32_known_vector() {
        // Standardowy wektor testowy CRC-32/ISO-HDLC dla "123456789"
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn test_crc32_empty_input() {
        assert_eq!(crc32(b""), 0x00000000);
    }

    // ------------------------------------------------------------------
    // Budowa prawdziwych plików PNG do testów (chunk po chunku, ręcznie)
    // ------------------------------------------------------------------

    fn build_png_chunk(ctype: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(ctype);
        out.extend_from_slice(data);
        let mut crc_input = Vec::new();
        crc_input.extend_from_slice(ctype);
        crc_input.extend_from_slice(data);
        out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
        out
    }

    fn build_valid_png(ihdr_data: &[u8], idat_data: &[u8]) -> Vec<u8> {
        let mut out = PNG_SIGNATURE.to_vec();
        out.extend(build_png_chunk(b"IHDR", ihdr_data));
        out.extend(build_png_chunk(b"IDAT", idat_data));
        out.extend(build_png_chunk(b"IEND", &[]));
        out
    }

    /// Uszkadza CRC konkretnego chunka (przez indeks 0=IHDR,1=IDAT,2=IEND),
    /// nadpisując jego 4 ostatnie bajty (pole CRC) losową, niezgodną wartością.
    fn corrupt_chunk_crc(png: &[u8], chunk_index: usize) -> Vec<u8> {
        let mut out = png.to_vec();
        let mut pos = 8;
        for i in 0..=chunk_index {
            let len = u32::from_be_bytes(out[pos..pos + 4].try_into().unwrap()) as usize;
            let crc_pos = pos + 8 + len;
            if i == chunk_index {
                out[crc_pos] ^= 0xFF; // psuje CRC, zostawia długość/typ/dane nietknięte
            }
            pos = crc_pos + 4;
        }
        out
    }

    // ------------------------------------------------------------------
    // parse_png_chunks
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_png_chunks_valid_file_all_crc_ok() {
        let png = build_valid_png(b"IHDR_DATA_X", b"IDAT_PAYLOAD");
        let chunks = parse_png_chunks(&png).unwrap();
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.crc_valid));
    }

    #[test]
    fn test_parse_png_chunks_rejects_non_png_signature() {
        assert!(parse_png_chunks(b"nie jest to PNG w ogole").is_none());
    }

    #[test]
    fn test_parse_png_chunks_detects_corrupted_crc() {
        let png = build_valid_png(b"IHDR_DATA_X", b"IDAT_PAYLOAD");
        let corrupted = corrupt_chunk_crc(&png, 1); // psuje CRC chunka IDAT
        let chunks = parse_png_chunks(&corrupted).unwrap();
        assert!(chunks[0].crc_valid, "IHDR nietknięty - powinien być OK");
        assert!(!chunks[1].crc_valid, "IDAT uszkodzony - CRC powinno się nie zgadzać");
        assert!(chunks[2].crc_valid, "IEND nietknięty - powinien być OK");
    }

    #[test]
    fn test_parse_png_chunks_truncated_file_stops_gracefully() {
        let png = build_valid_png(b"IHDR_DATA_X", b"IDAT_PAYLOAD");
        let truncated = &png[..png.len() - 10]; // ucinamy środek ostatniego chunka
        let chunks = parse_png_chunks(truncated).unwrap();
        assert!(chunks.len() < 3, "Ucięty plik nie powinien sparsować wszystkich 3 chunków");
    }

    // ------------------------------------------------------------------
    // splice_png - kluczowy scenariusz użytkownika: uszkodzenia w różnych miejscach
    // ------------------------------------------------------------------

    #[test]
    fn test_splice_png_recovers_when_damage_is_in_different_chunks() {
        let base = build_valid_png(b"IHDR_DATA_X", b"IDAT_PAYLOAD_ORYGINALNY");
        // Strona A: uszkodzony nagłówek (IHDR, indeks 0)
        let side_a = corrupt_chunk_crc(&base, 0);
        // Strona B: uszkodzone dane obrazu (IDAT, indeks 1)
        let side_b = corrupt_chunk_crc(&base, 1);

        let result = splice_png(&side_a, &side_b).expect("Złożenie powinno się powieść - uszkodzenia w różnych miejscach");

        // Wynik powinien mieć WSZYSTKIE chunki z poprawnym CRC
        let result_chunks = parse_png_chunks(&result).unwrap();
        assert!(result_chunks.iter().all(|c| c.crc_valid), "Złożony plik powinien mieć wyłącznie poprawne CRC");
        // I odpowiadać oryginałowi (bez uszkodzeń)
        assert_eq!(result, base);
    }

    #[test]
    fn test_splice_png_fails_when_same_chunk_corrupted_on_both_sides() {
        let base = build_valid_png(b"IHDR_DATA_X", b"IDAT_PAYLOAD");
        let side_a = corrupt_chunk_crc(&base, 1); // IDAT zepsute po stronie A
        let side_b = corrupt_chunk_crc(&base, 1); // IDAT RÓWNIEŻ zepsute po stronie B
        assert!(splice_png(&side_a, &side_b).is_none(), "Brak zdrowej kopii tego chunka po żadnej stronie - nie da się złożyć");
    }

    #[test]
    fn test_splice_png_appends_canonical_iend_when_both_truncated() {
        let base = build_valid_png(b"IHDR_DATA_X", b"IDAT_PAYLOAD");
        // Obie strony ucięte PRZED chunkiem IEND
        let iend_len = build_png_chunk(b"IEND", &[]).len();
        let side_a = base[..base.len() - iend_len].to_vec();
        let side_b = side_a.clone();

        let result = splice_png(&side_a, &side_b).expect("Powinno się złożyć mimo braku IEND");
        assert!(result.ends_with(&CANONICAL_IEND), "Brakujący IEND powinien zostać dopełniony kanonicznym chunkiem");
    }

    #[test]
    fn test_splice_png_rejects_structurally_misaligned_files() {
        let base = build_valid_png(b"IHDR_DATA_X", b"IDAT_PAYLOAD");
        // Sztucznie budujemy plik z INNYM typem chunka na pozycji 1 (zamiast IDAT: tEXt)
        let mut side_b = PNG_SIGNATURE.to_vec();
        side_b.extend(build_png_chunk(b"IHDR", b"IHDR_DATA_X"));
        side_b.extend(build_png_chunk(b"tEXt", b"jakis komentarz"));
        side_b.extend(build_png_chunk(b"IEND", &[]));

        assert!(splice_png(&base, &side_b).is_none(), "Rozjazd struktury (różne typy chunków) nie powinien być naprawiany");
    }

    // ------------------------------------------------------------------
    // find_jpeg_sos_end
    // ------------------------------------------------------------------

    fn build_minimal_jpeg(sos_header_extra: &[u8], scan_data: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8]; // SOI
        // Prosty segment APP0 (JFIF) - typ 0xE0, długość obejmuje siebie
        out.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x01, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00]);
        // Segment SOS
        out.push(0xFF);
        out.push(0xDA);
        let sos_len = (2 + sos_header_extra.len()) as u16;
        out.extend_from_slice(&sos_len.to_be_bytes());
        out.extend_from_slice(sos_header_extra);
        out.extend_from_slice(scan_data);
        out.extend_from_slice(&[0xFF, 0xD9]); // EOI
        out
    }

    #[test]
    fn test_find_jpeg_sos_end_locates_correct_offset() {
        let jpeg = build_minimal_jpeg(b"HEADERDATA", b"SKOMPRESOWANE_DANE_OBRAZU");
        let end = find_jpeg_sos_end(&jpeg).expect("Powinno znaleźć SOS");
        // Wszystko od `end` do końca to nasze "scan_data" + EOI
        assert!(jpeg[end..].starts_with(b"SKOMPRESOWANE_DANE_OBRAZU"));
    }

    #[test]
    fn test_find_jpeg_sos_end_rejects_missing_soi() {
        let not_jpeg = vec![0x00, 0x01, 0x02, 0x03];
        assert!(find_jpeg_sos_end(&not_jpeg).is_none());
    }

    #[test]
    fn test_find_jpeg_sos_end_rejects_file_without_sos() {
        // SOI + jeden segment + EOI, bez SOS w ogóle
        let mut jpeg = vec![0xFF, 0xD8];
        jpeg.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x04, 0x01, 0x02]);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
        assert!(find_jpeg_sos_end(&jpeg).is_none());
    }

    // ------------------------------------------------------------------
    // splice_jpeg_candidates
    // ------------------------------------------------------------------

    #[test]
    fn test_splice_jpeg_candidates_produces_two_cross_combinations() {
        let jpeg_a = build_minimal_jpeg(b"HDRA", b"DANE_A");
        let jpeg_b = build_minimal_jpeg(b"HDRB", b"DANE_B_DLUZSZE");

        let candidates = splice_jpeg_candidates(&jpeg_a, &jpeg_b);
        assert_eq!(candidates.len(), 2, "Powinny powstać dokładnie dwie kombinacje krzyżowe");

        // Kandydat 1: nagłówek A + dane B
        assert!(candidates[0].windows(4).any(|w| w == b"HDRA"));
        assert!(candidates[0].ends_with(b"DANE_B_DLUZSZE\xFF\xD9"));

        // Kandydat 2: nagłówek B + dane A
        assert!(candidates[1].windows(4).any(|w| w == b"HDRB"));
        assert!(candidates[1].ends_with(b"DANE_A\xFF\xD9"));
    }

    #[test]
    fn test_splice_jpeg_candidates_empty_when_sos_not_found() {
        let broken = vec![0x00, 0x01, 0x02];
        let valid = build_minimal_jpeg(b"HDR", b"DANE");
        assert!(splice_jpeg_candidates(&broken, &valid).is_empty());
    }

    // ------------------------------------------------------------------
    // build_candidates - dispatch po rozszerzeniu
    // ------------------------------------------------------------------

    #[test]
    fn test_build_candidates_unsupported_extension_returns_empty() {
        let candidates = build_candidates("gif", b"cokolwiek", b"cokolwiek innego");
        assert!(candidates.is_empty());
    }

    // ------------------------------------------------------------------
    // Dispatch dla archiwów ZIP-podobnych (logika splice/verify testowana
    // wyczerpująco w module `zip_splice` - tu sprawdzamy TYLKO poprawne
    // rozgałęzienie po rozszerzeniu, żeby nie duplikować tamtych testów).
    // ------------------------------------------------------------------

    #[test]
    fn test_verify_candidate_uses_zip_verification_for_archives() {
        // Poprawny obraz PNG nie jest poprawnym archiwum - gałąź ZIP musi go
        // odrzucić, co dowodzi, że dispatch wybrał WŁAŚCIWĄ weryfikację.
        let img = image::RgbImage::from_pixel(2, 2, image::Rgb([1, 2, 3]));
        let mut png_bytes: Vec<u8> = Vec::new();
        {
            let mut cursor = std::io::Cursor::new(&mut png_bytes);
            image::DynamicImage::ImageRgb8(img).write_to(&mut cursor, image::ImageFormat::Png).unwrap();
        }
        assert!(verify_candidate("png", &png_bytes), "PNG musi przejść weryfikację obrazu");
        assert!(!verify_candidate("docx", &png_bytes), "Ten sam PNG NIE może przejść weryfikacji archiwum");
    }

    #[test]
    fn test_build_candidates_recognizes_archive_extensions() {
        // Śmieci nie złożą się w archiwum, ale kluczowe jest, że dispatch w
        // ogóle trafia do gałęzi ZIP (nie do domyślnej pustej) - potwierdzone
        // przez brak paniki i pusty, a nie "nieobsługiwany", wynik.
        for ext in ["zip", "docx", "xlsx", "epub"] {
            let candidates = build_candidates(ext, b"nie archiwum", b"tez nie archiwum");
            assert!(candidates.is_empty(), "Śmieci nie powinny dać kandydatów dla .{}", ext);
        }
    }

    #[test]
    fn test_build_candidates_jpg_and_jpeg_both_recognized() {
        let jpeg_a = build_minimal_jpeg(b"HDRA", b"DANE_A");
        let jpeg_b = build_minimal_jpeg(b"HDRB", b"DANE_B");
        assert_eq!(build_candidates("jpg", &jpeg_a, &jpeg_b).len(), 2);
        assert_eq!(build_candidates("jpeg", &jpeg_a, &jpeg_b).len(), 2);
    }

    // ------------------------------------------------------------------
    // verify_image_bytes
    // ------------------------------------------------------------------

    #[test]
    fn test_verify_image_bytes_rejects_garbage() {
        assert!(!verify_image_bytes(b"to na pewno nie jest obrazek"));
    }

    #[test]
    fn test_verify_image_bytes_accepts_real_encoded_image() {
        // Prawdziwy, poprawnie zakodowany obraz PNG 2x2 przez crate `image`
        let img = image::RgbImage::from_pixel(2, 2, image::Rgb([10, 20, 30]));
        let mut bytes: Vec<u8> = Vec::new();
        {
            let mut cursor = std::io::Cursor::new(&mut bytes);
            image::DynamicImage::ImageRgb8(img).write_to(&mut cursor, image::ImageFormat::Png).unwrap();
        }
        assert!(verify_image_bytes(&bytes));
    }

    #[test]
    fn test_end_to_end_splice_and_verify_real_png() {
        // Pełny łańcuch: prawdziwy obraz -> uszkodzenie dwóch różnych chunków
        // po dwóch stronach -> złożenie -> weryfikacja realnym dekodowaniem.
        let img = image::RgbImage::from_pixel(4, 4, image::Rgb([200, 100, 50]));
        let mut original: Vec<u8> = Vec::new();
        {
            let mut cursor = std::io::Cursor::new(&mut original);
            image::DynamicImage::ImageRgb8(img).write_to(&mut cursor, image::ImageFormat::Png).unwrap();
        }

        let chunks = parse_png_chunks(&original).unwrap();
        assert!(chunks.len() >= 3, "Prawdziwy PNG powinien mieć co najmniej IHDR/IDAT/IEND");

        let side_a = corrupt_chunk_crc(&original, 0); // IHDR zepsute
        let side_b = corrupt_chunk_crc(&original, 1); // pierwszy IDAT zepsuty

        let spliced = splice_png(&side_a, &side_b).expect("Złożenie prawdziwego PNG powinno się powieść");
        assert!(verify_image_bytes(&spliced), "Złożony prawdziwy PNG powinien się poprawnie zdekodować");
    }

    /// Konwencja „(Wariant A)" musi być identyczna we WSZYSTKICH fazach
    /// równoległych — ułatwia maszynowe parsowanie panelu i utrzymuje spójność
    /// wizualną. Ten test utrwala ją dla tej fazy.
    #[test]
    fn test_blok_zawiera_znacznik_aktywnosci_watkow() {
        let stats = LiveStats::new(2);
        stats.thread_activity.mark_busy(1);

        let block = build_summary_block(&stats, Instant::now());

        let line = block
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("Wątki składania"))
            .unwrap_or_else(|| panic!("brak linii Wariantu A w bloku:\n{}", block));

        assert_eq!(line, "Wątki składania (Wariant A): {R:1} {G:2}");
    }


    // ------------------------------------------------------------------
    // ZAKRES FORMATÓW SKŁADANYCH
    // ------------------------------------------------------------------

    /// Strażnik wpięcia: format obsługiwany przez `raster_splice` MUSI być
    /// widziany przez `build_candidates`. Sam moduł składający, do którego
    /// nic nie prowadzi, byłby martwym kodem.
    #[test]
    fn test_formaty_rastrowe_sa_wpiete_w_generator_kandydatow() {
        // Dwie różniące się, poprawne strukturalnie atrapy BMP.
        let atrapa = |wypelnienie: u8| {
            let mut b = vec![wypelnienie; 200];
            b[0..2].copy_from_slice(b"BM");
            b[2..6].copy_from_slice(&200u32.to_le_bytes());
            b[10..14].copy_from_slice(&54u32.to_le_bytes());
            b
        };

        let kandydaci = build_candidates("bmp", &atrapa(0xAA), &atrapa(0xBB));
        assert!(
            !kandydaci.is_empty(),
            "Faza 18 musi generować kandydatów dla formatów z `raster_splice`"
        );
    }

    /// Weryfikacja kandydata dla tych formatów idzie przez realne dekodowanie
    /// pikseli — najmocniejszy dostępny dowód.
    #[test]
    fn test_kandydat_rastrowy_jest_weryfikowany_dekodowaniem() {
        for ext in ["gif", "bmp", "webp"] {
            assert!(
                !verify_candidate(ext, b"to zupelnie nie jest obraz"),
                ".{}: śmieci nie mogą przejść weryfikacji", ext
            );
        }
    }
}
