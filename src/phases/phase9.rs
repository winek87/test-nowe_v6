// src/phases/phase9.rs

//! # Faza 9: SMART MERGE (Złota Kopia - Fuzja, Kopiowanie i Weryfikacja)
//!
//! Ostateczna faza operacyjna. Silnik Heurystyczny ocenia każdy plik, wybiera
//! najlepszą wersję (z naciskiem na fizycznie zrekonstruowane pliki z Fazy 17),
//! po czym kopiuje zwycięzcę do folderu docelowego i odtwarza metadane.
//! W pełni zintegrowana z Ratatui (PhaseEvent) oraz systemem Dual-Logging.
//!
//! UWAGA ARCHITEKTONICZNA (UI/WĄTKOWANIE): w przeciwieństwie do Faz 1-7, ta
//! faza NIE dzieli pracy na UFS/Skrypt jako dwa konkurujące wątki — jedna,
//! ujednolicona lista kandydatów (każdy rekord już zawiera decyzję
//! `decide_winner` do podjęcia) jest przetwarzana JEDNYM `par_chunks(...)`
//! na globalnej puli Rayon. Nie ma tu buga głodzenia z Faz 5-7 (nie ma
//! dwóch stron rywalizujących o pulę), więc `half_threads` nie jest
//! potrzebne. Panel boczny — patrz [`build_summary_block`] — jest jeden,
//! bez podziału per-źródło, analogicznie do Fazy 8.
//!
//! UWAGA ARCHITEKTONICZNA (PAMIĘĆ): lista kandydatów NIE jest materializowana
//! w całości. Wcześniej cały zbiór plików do scalenia wchodził do jednego
//! `Vec<MergeCandidate>` przed startem kopiowania — przy milionach plików
//! setki megabajtów zajęte, zanim ruszyła pierwsza operacja I/O. Teraz praca
//! idzie STRONAMI po [`ROZMIAR_STRONY`] rekordów, stronicowanych kluczem
//! głównym (patrz [`wczytaj_strone`]), więc szczyt zużycia pamięci nie zależy
//! od rozmiaru korpusu.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent; // <--- NAPRAWIONY IMPORT
use crate::utils::{format_bytes, format_display_path, CANCEL_SIGNAL};
use filetime::{set_symlink_file_times, FileTime};
use ratatui::style::Color;
use rayon::prelude::*;
use rusqlite::{params, Connection, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, instrument, warn};

const CHUNK_SIZE: usize = 100;

/// Próg commitu hybrydowego: liczba rekordów, po której transakcja zapisu jest
/// zatwierdzana i otwierana na nowo (drugim warunkiem jest 500 ms). Ta sama
/// wartość co w Fazie 3 — utrzymuje jeden wzorzec trwałości w całym projekcie.
const PROG_COMMITU: usize = 5_000;

// ============================================================================
// STRUKTURY DANYCH I MODELE WIEDZY
// ============================================================================

/// Pełny zestaw danych forensycznych jednego pliku z tabeli `files`, wejście
/// do [`decide_winner`]. Analogiczne do `FileRecord` z Fazy 8, ale z dodatkowymi
/// polami metadanych i-node (uid/gid/mode/mtime/symlink) potrzebnymi do
/// odtworzenia pliku w [`copy_file_and_meta`].
#[derive(Debug, Clone)]
struct MergeCandidate {
    id: i32, rel_path: String, in_ufs: bool, in_script: bool,
    hash_match: Option<bool>, size_ufs: Option<i64>, size_script: Option<i64>,
    uid_ufs: Option<u32>, uid_script: Option<u32>, gid_ufs: Option<u32>, gid_script: Option<u32>,
    mode_ufs: Option<u32>, mode_script: Option<u32>, mtime_ufs: Option<i64>, mtime_script: Option<i64>,
    is_symlink_ufs: Option<bool>, is_symlink_script: Option<bool>,
    zeros_pct_ufs: Option<f64>, zeros_pct_script: Option<f64>, eof_ok_ufs: Option<bool>, eof_ok_script: Option<bool>,
    entropy_ufs: Option<f64>, entropy_script: Option<f64>, utf8_ok_ufs: Option<bool>, utf8_ok_script: Option<bool>,
    structure_ok_ufs: Option<bool>, structure_ok_script: Option<bool>, exif_ok_ufs: Option<bool>, exif_ok_script: Option<bool>,
    media_decoded_ufs: Option<bool>, media_decoded_script: Option<bool>, has_xattr_ufs: Option<bool>, has_xattr_script: Option<bool>,
    io_error_ufs: Option<bool>, io_error_script: Option<bool>, yara_match_ufs: Option<String>, yara_match_script: Option<String>,
    repaired_path_ufs: Option<String>, repaired_path_script: Option<String>,
    /// Ścieżka do pliku złożonego przez Fazę 18 (Smart Splice) z dwóch
    /// uszkodzonych kopii — obecna TYLKO gdy Faza 18 znalazła i zweryfikowała
    /// (realnym dekodowaniem) udane złożenie. Ma priorytet nad zwykłym
    /// wyborem strony, bo reprezentuje dane lepsze niż KAŻDA z osobna.
    smart_splice_path: Option<String>,
}

/// Wynik przetworzenia jednego kandydata: zwycięska strona, powód decyzji
/// (dopisany "| BŁĄD KOPIOWANIA" gdy fizyczne kopiowanie zawiodło), czy
/// operacja się powiodła, oraz ostateczna ścieżka zapisu (może się różnić od
/// `rel_path` przy kolizji nazw — patrz [`get_safe_target_path`]).
#[derive(Debug)]
struct CopyResult {
    id: i32, winner: &'static str, reason: String, success: bool, saved_path: String,
    /// Bezwzględna ścieżka, z której plik został FAKTYCZNIE skopiowany:
    /// oryginał z korpusu, naprawa z Fazy 17 albo złożenie z Fazy 18.
    /// Zapisywana do bazy jako `merge_source_path` — ślad rewizyjny
    /// odpowiadający na pytanie "skąd wzięły się te bajty".
    source_path: String,
}

/// Liczniki live całego przebiegu (jeden zestaw, bez podziału UFS/Skrypt jako
/// "źródła" — te liczniki już ODZWIERCIEDLAJĄ decyzję `decide_winner`, więc
/// "UFS" tutaj znaczy "ile razy UFS wygrał", nie "ile plików po stronie UFS").
pub(crate) struct LiveStats {
    processed_files: AtomicUsize, processed_bytes: AtomicU64,
    /// Wygrane UFS dla plików WSPÓLNYCH (obecnych po obu stronach).
    copied_ufs_common: AtomicUsize,
    /// Wygrane Skrypt dla plików WSPÓLNYCH.
    copied_script_common: AtomicUsize,
    /// Skopiowane pliki UNIKALNE dla UFS (obecne tylko tam).
    copied_ufs_unique: AtomicUsize,
    /// Skopiowane pliki UNIKALNE dla Skryptu.
    copied_script_unique: AtomicUsize,
    /// Pliki złożone przez Fazę 18 (Smart Splice) i użyte jako zwycięzca —
    /// zawsze WSPÓLNE z definicji (splice dotyczy wyłącznie plików obecnych
    /// po obu stronach), stąd brak rozbicia common/unique jak przy UFS/Skrypt.
    copied_splice: AtomicUsize,
    symlinks_recreated: AtomicUsize,
    /// Pliki zapisane pod zmienioną nazwą z powodu kolizji w katalogu docelowym.
    renamed_files: AtomicUsize, 
    io_errors: AtomicUsize,
    /// Błędy przywracania metadanych (czas/uprawnienia/właściciel) — PLIK i tak
    /// został skopiowany poprawnie, to osobna, mniej krytyczna kategoria błędu.
    meta_errors: AtomicUsize,
    /// Liczba przypadków, gdy zwycięzcą była wersja fizycznie zrekonstruowana przez Fazę 17.
    repaired_used: AtomicUsize, 
    /// Zliczenia wystąpień per dokładny tekst powodu decyzji — do "Top powody" w panelu.
    reasons: Mutex<HashMap<String, usize>>,
    /// EKSPERYMENTALNE (Wariant A): śledzi zajętość logicznych slotów Rayon —
    /// ta sama konwencja i ten sam tracker, co w pozostałych fazach
    /// równoległych, patrz `thread_activity`.
    thread_activity: crate::thread_activity::ThreadActivityTracker,
}

impl LiveStats {
    fn new(slot_count: usize) -> Self {
        Self {
            thread_activity: crate::thread_activity::ThreadActivityTracker::new(slot_count),
            processed_files: AtomicUsize::new(0), processed_bytes: AtomicU64::new(0),
            copied_ufs_common: AtomicUsize::new(0), copied_script_common: AtomicUsize::new(0),
            copied_ufs_unique: AtomicUsize::new(0), copied_script_unique: AtomicUsize::new(0),
            copied_splice: AtomicUsize::new(0),
            symlinks_recreated: AtomicUsize::new(0), renamed_files: AtomicUsize::new(0), 
            io_errors: AtomicUsize::new(0), meta_errors: AtomicUsize::new(0),
            repaired_used: AtomicUsize::new(0),
            reasons: Mutex::new(HashMap::new()),
        }
    }
}

/// Buduje panel boczny "Podsumowanie na żywo" — jeden, wspólny panel bez
/// podziału per-źródło (analogicznie do Fazy 8, patrz dokumentacja modułu).
fn build_summary_block(stats: &LiveStats, start_time: Instant) -> String {
    let elapsed = start_time.elapsed().as_secs_f64().max(0.1);
    let bytes = stats.processed_bytes.load(Ordering::Relaxed);
    let speed_mb = (bytes as f64 / 1_048_576.0) / elapsed;

    let top_reasons = {
        let map = stats.reasons.lock().unwrap();
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        let s = sorted.into_iter().take(3)
            .map(|(reason, count)| format!("{} ({})", reason, count))
            .collect::<Vec<_>>().join(", ");
        if s.is_empty() { "-".to_string() } else { s }
    };

    format!(
        "[Podsumowanie]\nPrędkość: {:.2} MB/s\nWspólne — UFS: {} | Skrypt: {} | Złożone (Faza 18): {}\nUnikalne skopiowane: {}\nDowiązania odtworzone: {}\nUżyto wersji naprawionej: {}\nPrzemianowane (kolizja nazw): {}\nWątki kopiowania (Wariant A): {}\nBłędy I/O: {}\nBłędy metadanych: {}\nTop powody decyzji: {}",
        speed_mb,
        stats.copied_ufs_common.load(Ordering::Relaxed), stats.copied_script_common.load(Ordering::Relaxed), stats.copied_splice.load(Ordering::Relaxed),
        stats.copied_ufs_unique.load(Ordering::Relaxed) + stats.copied_script_unique.load(Ordering::Relaxed),
        stats.symlinks_recreated.load(Ordering::Relaxed),
        stats.repaired_used.load(Ordering::Relaxed),
        stats.renamed_files.load(Ordering::Relaxed),
        crate::thread_activity::format_activity_markup(&stats.thread_activity.snapshot()),
        stats.io_errors.load(Ordering::Relaxed),
        stats.meta_errors.load(Ordering::Relaxed),
        top_reasons,
    )
}

// ============================================================================
// SILNIK DECYZYJNY (HEURYSTYKA SMART MERGE Z PRIORYTETEM NAPRAW)
// ============================================================================

/// Wybiera zwycięską stronę ("ufs" albo "script") dla jednego kandydata do
/// scalenia, wraz z czytelnym powodem decyzji do logu/raportu. Odpowiednik
/// [`crate::phases::phase8::evaluate_file`], ale rozstrzyga PORÓWNANIE
/// WZGLĘDNE (który z dwóch lepszy), nie klasyfikację bezwzględną — stąd inny
/// dobór progów niż w Fazach 7/8 tam, gdzie to uzasadnione (patrz niżej).
///
/// Kolejność priorytetu (pierwsze trafienie wygrywa):
/// 0. **YARA** — strona zainfekowana zawsze przegrywa z czystą, niezależnie
///    od wszystkiego innego (nawet gdy czysta strona ma gorsze metadane).
/// 1. **Rekonstrukcja Fazy 17** — wygrywa nad wszystkimi anomaliami poniżej;
///    gdy obie strony mają wersję naprawioną, domyślnie wygrywa Skrypt.
/// 2. Dla plików WSPÓLNYCH (obecnych po obu stronach), w kolejności: błąd I/O,
///    nieudany dekoding obrazu, zła struktura kontenera, zły UTF-8, zły EXIF,
///    brak EOF — każda para sprawdzana symetrycznie (X zawiódł, Y nie zawiódł
///    → Y wygrywa), więc identyczny stan po obu stronach przechodzi dalej.
/// 3. **Wydmuszka** (próg **>99.0%** zer — UJEDNOLICONE z Fazą 8, patrz niżej)
///    i **entropia skrajna** (próg **>7.995** — UJEDNOLICONE z Fazą 7).
/// 4. **Atrybuty xattr** — strona, która je zachowała, wygrywa (dane
///    dodatkowe, nie da się ich odtworzyć z drugiej strony).
/// 5. **Większy rozmiar pliku** — sugeruje mniej ucięcia.
/// 6. **Remis** — hash identyczny lub zupełny remis heurystyczny: domyślnie
///    wygrywa Skrypt (konwencja przyjęta w tym projekcie).
///    Pliki UNIKALNE (obecne tylko po jednej stronie) trafiają tam automatycznie,
///    bez przechodzenia przez powyższą hierarchię.
///
/// # Uwaga o progach entropii/zer (ujednolicone z Fazami 7/8)
/// Wcześniej ta funkcja używała niższych progów (entropia >7.9, zera >95.0%)
/// niż Fazy 7/8. To było ryzykowne akurat tutaj: gdy kod dochodzi do tego
/// sprawdzenia, WSZYSTKIE twardsze sygnały (I/O, struktura, EXIF, UTF-8, EOF)
/// już przeszły czysto po OBU stronach — pozostają tylko subtelne różnice.
/// Entropia 7.85 vs 7.92 to normalny szum pomiarowy dwóch zdrowych kopii tego
/// samego skompresowanego pliku, nie oznaka uszkodzenia; niski próg odrzucał
/// dobry plik na podstawie różnicy, która nic nie znaczyła. Ponieważ Faza 9
/// (w przeciwieństwie do Faz 7/8, które tylko OZNACZAJĄ plik) fizycznie
/// PRZESTAJE kopiować przegraną stronę do Złotej Kopii, koszt fałszywego
/// odrzucenia dobrego pliku jest tu wyższy niż koszt nierozstrzygniętego
/// remisu (remis ma bezpieczny fallback na Skrypt, remis niczego nie traci).
fn decide_winner(file: &MergeCandidate) -> (&'static str, &'static str) {
    if file.yara_match_ufs.is_some() && file.yara_match_script.is_none() { return ("script", "UFS odrzucony (Zainfekowany Malware/YARA)"); }
    if file.yara_match_script.is_some() && file.yara_match_ufs.is_none() { return ("ufs", "Skrypt odrzucony (Zainfekowany Malware/YARA)"); }

    // NAJWYŻSZY PRIORYTET PO YARA: Faza 18 (Smart Splice) złożyła jeden
    // sprawny plik z dwóch uszkodzonych kopii i ZWERYFIKOWAŁA go realnym
    // dekodowaniem (nie samą heurystyką) — to mocniejszy dowód sprawności niż
    // fizyczna naprawa nagłówka niżej, bo obejmuje CAŁĄ zawartość, nie tylko
    // wstrzyknięty nagłówek. Sprawdzane PRZED YARA nie jest bezpieczne z
    // zamysłu: jeśli któraś strona źródłowa jest zainfekowana, powyższe dwie
    // linie już to złapały i zwróciły wcześniej.
    if file.smart_splice_path.is_some() {
        return ("splice", "Złożono z dwóch uszkodzonych kopii i zweryfikowano dekodowaniem (Faza 18)");
    }

    if file.repaired_path_ufs.is_some() && file.repaired_path_script.is_none() { return ("ufs", "Wybrano UFS (Użyto wersji fizycznie zrekonstruowanej przez system)"); }
    if file.repaired_path_script.is_some() && file.repaired_path_ufs.is_none() { return ("script", "Wybrano Skrypt (Użyto wersji fizycznie zrekonstruowanej przez system)"); }
    if file.repaired_path_ufs.is_some() && file.repaired_path_script.is_some() { return ("script", "Obydwa zrekonstruowane (Priorytet domyślny: Skrypt)"); }

    if file.in_ufs && file.in_script {
        if file.io_error_ufs == Some(true) && file.io_error_script != Some(true) { return ("script", "UFS odrzucony (Błąd I/O / Bad Sector)"); }
        if file.io_error_script == Some(true) && file.io_error_ufs != Some(true) { return ("ufs", "Skrypt odrzucony (Błąd I/O / Bad Sector)"); }
        if file.media_decoded_ufs == Some(false) && file.media_decoded_script != Some(false) { return ("script", "UFS odrzucony (Ucięty obraz / Gray Banding)"); }
        if file.media_decoded_script == Some(false) && file.media_decoded_ufs != Some(false) { return ("ufs", "Skrypt odrzucony (Ucięty obraz / Gray Banding)"); }
        if file.structure_ok_ufs == Some(false) && file.structure_ok_script != Some(false) { return ("script", "UFS odrzucony (Zepsuta struktura ZIP/DOCX)"); }
        if file.structure_ok_script == Some(false) && file.structure_ok_ufs != Some(false) { return ("ufs", "Skrypt odrzucony (Zepsuta struktura ZIP/DOCX)"); }
        if file.utf8_ok_ufs == Some(false) && file.utf8_ok_script != Some(false) { return ("script", "UFS odrzucony (Zupa binarna w pliku tekstowym)"); }
        if file.utf8_ok_script == Some(false) && file.utf8_ok_ufs != Some(false) { return ("ufs", "Skrypt odrzucony (Zupa binarna w pliku tekstowym)"); }
        if file.exif_ok_ufs == Some(false) && file.exif_ok_script != Some(false) { return ("script", "UFS odrzucony (Zepsute offsety EXIF)"); }
        if file.exif_ok_script == Some(false) && file.exif_ok_ufs != Some(false) { return ("ufs", "Skrypt odrzucony (Zepsute offsety EXIF)"); }
        if file.eof_ok_ufs == Some(false) && file.eof_ok_script != Some(false) { return ("script", "UFS odrzucony (Brak znacznika końca pliku EOF)"); }
        if file.eof_ok_script == Some(false) && file.eof_ok_ufs != Some(false) { return ("ufs", "Skrypt odrzucony (Brak znacznika końca pliku EOF)"); }

        let z_ufs = file.zeros_pct_ufs.unwrap_or(0.0); let z_scr = file.zeros_pct_script.unwrap_or(0.0);
        if z_ufs > 99.0 && z_scr < 99.0 { return ("script", "UFS odrzucony (Wydmuszka wypełniona zerami)"); }
        if z_scr > 99.0 && z_ufs < 99.0 { return ("ufs", "Skrypt odrzucony (Wydmuszka wypełniona zerami)"); }

        let e_ufs = file.entropy_ufs.unwrap_or(4.0); let e_scr = file.entropy_script.unwrap_or(4.0);
        if e_ufs > 7.995 && e_scr <= 7.995 { return ("script", "UFS odrzucony (Skrajna entropia / Szum)"); }
        if e_scr > 7.995 && e_ufs <= 7.995 { return ("ufs", "Skrypt odrzucony (Skrajna entropia / Szum)"); }

        if file.has_xattr_ufs == Some(true) && file.has_xattr_script != Some(true) { return ("ufs", "Wybrano UFS (Ocalił ukryte atrybuty xattr)"); }
        if file.has_xattr_script == Some(true) && file.has_xattr_ufs != Some(true) { return ("script", "Wybrano Skrypt (Ocalił ukryte atrybuty xattr)"); }

        if let (Some(size_u), Some(size_s)) = (file.size_ufs, file.size_script) {
            if size_u > size_s { return ("ufs", "Wybrano UFS (Większy rozmiar pliku)"); }
            if size_s > size_u { return ("script", "Wybrano Skrypt (Większy rozmiar pliku)"); }
        }

        if file.hash_match == Some(true) { return ("script", "Zgodne bit-do-bitu (Priorytet domyślny: Skrypt Autorski)"); }
        ("script", "Remis heurystyczny (Priorytet domyślny: Skrypt Autorski)") 
    } else if file.in_script {
        ("script", "Plik unikalny (Tylko Skrypt Autorski)") 
    } else {
        ("ufs", "Plik unikalny (Tylko UFS Explorer)") 
    }
}

// ============================================================================
// SYSTEM KOPIOWANIA I REKONSTRUKCJI (I/O)
// ============================================================================

/// Sprawdza, że katalog docelowy (`target_path`, gdzie faza fizycznie
/// zapisuje Złotą Kopię) jest ROZŁĄCZNY z obydwoma katalogami źródłowymi
/// materiału dowodowego — ani nie jest tym samym katalogiem, ani nie jest
/// przodkiem/potomkiem żadnego z nich. Bez tej kontroli błędna konfiguracja
/// operatora (np. `target_path` przypadkiem ustawiony na `ufs_path`)
/// prowadziłaby do fizycznego nadpisania oryginalnego materiału dowodowego
/// przez `copy_file_and_meta`.
///
/// Kanonikalizuje ścieżkę tam, gdzie się da (rozwiązuje symlinki/`..`), z
/// fallbackiem na najbliższego ISTNIEJĄCEGO przodka + doklejenie reszty
/// składników, gdy sama ścieżka jeszcze fizycznie nie istnieje na dysku
/// (typowy przypadek dla `target_path` przy pierwszym uruchomieniu). Wydzielona
/// jako samodzielna funkcja modułu (nie zagnieżdżona w `sciezki_bezpieczne`),
/// żeby dało się ją przetestować bezpośrednio, bez mutowania globalnego CWD
/// procesu testowego.
///
/// REGRESJA (Gemini review — druga weryfikacja): zwykły
/// `canonicalize().unwrap_or(surowa_sciezka)` zawodzi cicho dla
/// `target_path`, który typowo JESZCZE NIE ISTNIEJE przy pierwszym
/// uruchomieniu — funkcja porównywałaby wtedy surowy, potencjalnie
/// WZGLĘDNY string operatora ze skanonikalizowanymi, BEZWZGLĘDNYMI
/// ścieżkami źródłowymi. Taka ścieżka nigdy nie spełni `==`/`starts_with`
/// nawet jeśli faktycznie leży wewnątrz źródła (np. przez symlink) —
/// walidacja przechodziłaby bezpiecznie WYGLĄDAJĄCO, nic nie sprawdzając.
fn kanon(p: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(p) {
        return real;
    }
    let mut ogon: Vec<std::ffi::OsString> = Vec::new();
    let mut biezacy = p;
    loop {
        match std::fs::canonicalize(biezacy) {
            Ok(real) => {
                let mut wynik = real;
                for skladnik in ogon.iter().rev() {
                    wynik.push(skladnik);
                }
                return wynik;
            }
            Err(_) => match biezacy.file_name() {
                Some(nazwa) => {
                    ogon.push(nazwa.to_os_string());
                    biezacy = match biezacy.parent() {
                        Some(rodzic) if !rodzic.as_os_str().is_empty() => rodzic,
                        // REGRESJA (measure twice — druga weryfikacja
                        // Gemini, N1): rodzic PUSTY nie znaczy "koniec
                        // drogi" — znaczy "ostatni składnik ścieżki
                        // WZGLĘDNEJ" (np. samo "wyniki", albo "sub" po
                        // odcięciu z "sub/wyniki"). Poprzednio pętla
                        // poddawała się tutaj i zwracała SUROWĄ,
                        // nieznormalizowaną ścieżkę względem CWD — dwie
                        // ścieżki względne bez wspólnego istniejącego
                        // przodka na dysku (typowy pierwszy przebieg,
                        // `target_path` jeszcze nieistniejący) nigdy nie
                        // miały jak wykazać wspólnego prefiksu, nawet
                        // jeśli faktycznie wskazywały w to samo miejsce.
                        // Bieżący katalog roboczy ZAWSZE istnieje, więc
                        // `canonicalize(".")` w kolejnej iteracji na
                        // pewno się powiedzie.
                        _ => Path::new("."),
                    };
                }
                // Korzeń ("/") nie istnieje — nic więcej nie da się
                // zrobić (nie powinno się zdarzyć w praktyce).
                None => return p.to_path_buf(),
            },
        }
    }
}

/// Sprawdza, że katalog docelowy (`target_path`, gdzie faza fizycznie
/// zapisuje Złotą Kopię) jest ROZŁĄCZNY z obydwoma katalogami źródłowymi
/// materiału dowodowego — ani nie jest tym samym katalogiem, ani nie jest
/// przodkiem/potomkiem żadnego z nich. Bez tej kontroli błędna konfiguracja
/// operatora (np. `target_path` przypadkiem ustawiony na `ufs_path`)
/// prowadziłaby do fizycznego nadpisania oryginalnego materiału dowodowego
/// przez `copy_file_and_meta`. Kanonikalizacja przez [`kanon`] — patrz jej
/// dokumentacja.
pub(crate) fn sciezki_bezpieczne(target_path: &Path, ufs_path: &Path, script_path: &Path) -> std::result::Result<(), String> {
    let target = kanon(target_path);
    let ufs = kanon(ufs_path);
    let script = kanon(script_path);

    for (nazwa, zrodlo) in [("UFS", &ufs), ("Skrypt", &script)] {
        if target == *zrodlo {
            return Err(format!(
                "Ścieżka docelowa ({}) jest TAKA SAMA jak źródło {} ({}) — zapis nadpisałby materiał dowodowy.",
                target_path.display(), nazwa, zrodlo.display()
            ));
        }
        if target.starts_with(zrodlo) {
            return Err(format!(
                "Ścieżka docelowa ({}) leży WEWNĄTRZ źródła {} ({}) — zapis zaśmieciłby/nadpisałby materiał dowodowy.",
                target_path.display(), nazwa, zrodlo.display()
            ));
        }
        if zrodlo.starts_with(&target) {
            return Err(format!(
                "Źródło {} ({}) leży WEWNĄTRZ ścieżki docelowej ({}) — zapis nadpisałby materiał dowodowy.",
                nazwa, zrodlo.display(), target_path.display()
            ));
        }
    }

    Ok(())
}

/// Etykieta źródła osadzana w nazwie pliku przy kolizji nazw — patrz
/// [`get_safe_target_path`] i [`commit_bez_nadpisania`].
fn etykieta_zwyciezcy(winner: &str) -> &'static str {
    if winner == "splice" { "ZLOZONY" } else if winner == "script" { "SKRYPT" } else { "UFS" }
}

/// Nazwa N-tego kandydata przy kolizji nazw: dla `counter == 1` sam tag
/// źródła (bez numeru wersji), dla kolejnych kolizji tej samej pary —
/// dopisek `_vN`. Wspólna między optymistycznym sprawdzeniem w
/// [`get_safe_target_path`] a atomowym domknięciem wyścigu wątków w
/// [`commit_bez_nadpisania`] — jedno miejsce prawdy o formacie nazwy,
/// żeby obie ścieżki kodu nigdy nie rozjechały się w konwencji nazewnictwa.
fn nazwa_kandydata(stem: &str, tag: &str, ext: &str, counter: u32) -> String {
    if counter == 1 { format!("{}_[{}]{}", stem, tag, ext) } else { format!("{}_[{}]_v{}{}", stem, tag, counter, ext) }
}

/// Wylicza OPTYMISTYCZNĄ bezpieczną ścieżkę docelową, unikając nadpisania już
/// istniejącego pliku o tej samej nazwie (może się zdarzyć, gdy dwa różne
/// wpisy z bazy mapują się na tę samą ścieżkę względną z powodu wcześniejszych
/// anomalii). Przy kolizji dopisuje sufiks `_[UFS]`/`_[SKRYPT]` do nazwy pliku
/// (przed rozszerzeniem), a przy kolejnych kolizjach tej samej pary — `_v2`,
/// `_v3` itd. Zwraca `(pełna_ścieżka_docelowa, ścieżka_względna_finalna,
/// czy_zmieniono_nazwę)`.
///
/// ## UWAGA: to tylko "best effort" pierwsza próba, NIE ostateczna decyzja
///
/// Sprawdzenie opiera się o `Path::exists()` — a między tym sprawdzeniem a
/// faktycznym zapisem pliku inny wątek Rayon (przetwarzający RÓWNOLEGLE inną
/// paczkę kandydatów) mógł w międzyczasie zarezerwować dokładnie tę samą
/// nazwę. Ten wynik wystarcza do wcześniejszego utworzenia katalogu
/// nadrzędnego i do rekonstrukcji dowiązań symbolicznych (`symlink(2)` sam z
/// siebie nigdy nie nadpisuje — zawodzi z `AlreadyExists`, więc jest z
/// natury bezpieczny na wyścig). Dla zwykłych plików ostateczną, odporną na
/// wyścig decyzję podejmuje dopiero [`commit_bez_nadpisania`].
fn get_safe_target_path(target_base: &Path, rel_path: &str, winner: &str) -> (PathBuf, String, bool) {
    let mut target_path = target_base.join(rel_path);
    let mut final_rel_path = rel_path.to_string();
    let mut renamed = false;

    if target_path.exists() {
        renamed = true;
        let original_path = Path::new(rel_path);
        let stem = original_path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
        let ext = original_path.extension().and_then(|e| e.to_str()).map(|e| format!(".{}", e)).unwrap_or_default();
        let parent = original_path.parent().unwrap_or(Path::new(""));
        let source_tag = etykieta_zwyciezcy(winner);

        let mut counter = 1;
        loop {
            let new_name = nazwa_kandydata(stem, source_tag, &ext, counter);
            let new_rel_path = parent.join(&new_name);
            target_path = target_base.join(&new_rel_path);

            if !target_path.exists() {
                final_rel_path = new_rel_path.to_string_lossy().to_string();
                break;
            }
            counter += 1;
        }
    }
    (target_path, final_rel_path, renamed)
}

/// Atomowo "zatwierdza" gotowy plik tymczasowy `tmp_path` pod bezpieczną
/// nazwą docelową, GWARANTUJĄC brak cichego nadpisania przy wyścigu wątków —
/// domyka lukę TOCTOU pozostawioną celowo otwartą przez
/// [`get_safe_target_path`] (patrz jej dokumentacja).
///
/// ## Dlaczego `fs::hard_link`, nie `fs::rename`
///
/// `fs::rename` na Uniksie ZAWSZE cicho nadpisuje istniejący cel — to
/// dokładnie sedno luki: dwa wątki Rayon przetwarzające różne paczki mogą
/// obliczyć TĘ SAMĄ nazwę bezpieczną (oba widziały ją jako wolną w chwili
/// optymistycznego sprawdzenia `Path::exists()`), skopiować swoje pliki do
/// osobnych plików tymczasowych, po czym oba zakończyć `rename` na ten sam
/// cel — drugi cicho kasuje wynik pierwszego, bez żadnego sygnału błędu.
/// `fs::hard_link` ma odwrotną semantykę z definicji POSIX: NIGDY nie
/// nadpisuje, zawsze zawodzi z `AlreadyExists`, jeśli cel już istnieje. Więc
/// przy realnej kolizji bezpiecznie próbujemy KOLEJNEJ nazwy (ten sam
/// mechanizm `_v2`, `_v3` co przy pierwszej, optymistycznej próbie) — aż
/// trafimy na nazwę, którą faktycznie uda się zarezerwować atomowo. Treść
/// pliku jest już w pełni zapisana i zweryfikowana w `tmp_path` PRZED
/// wywołaniem tej funkcji, więc retry nigdy nie kopiuje niczego ponownie —
/// tylko próbuje innej nazwy dla tego samego, gotowego pliku. Po sukcesie
/// oryginalny `tmp_path` jest usuwany (treść jest już dostępna pod nazwą
/// docelową jako drugie dowiązanie do tego samego i-node).
///
/// Wymaga, żeby `tmp_path` i katalog docelowy leżały na TYM SAMYM systemie
/// plików — dokładnie to samo założenie, które już obowiązywało dla
/// `fs::rename` (`sciezka_tymczasowa` celowo tworzy plik tymczasowy w tym
/// samym katalogu co cel).
///
/// Zwraca `(pełna_ścieżka_docelowa, ścieżka_względna_finalna,
/// czy_zmieniono_nazwę)` — AUTORYTATYWNY wynik, który może różnić się od
/// optymistycznej podpowiedzi [`get_safe_target_path`], jeśli w
/// międzyczasie doszło do realnej kolizji wyścigu.
fn commit_bez_nadpisania(tmp_path: &Path, target_base: &Path, rel_path: &str, winner: &str) -> std::io::Result<(PathBuf, String, bool)> {
    let original_path = Path::new(rel_path);
    let stem = original_path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = original_path.extension().and_then(|e| e.to_str()).map(|e| format!(".{}", e)).unwrap_or_default();
    let parent = original_path.parent().unwrap_or(Path::new(""));
    let source_tag = etykieta_zwyciezcy(winner);

    let mut counter: u32 = 0; // 0 = nazwa oryginalna (bez tagu), próbowana jako pierwsza
    loop {
        let (final_rel_path, final_path) = if counter == 0 {
            (rel_path.to_string(), target_base.join(rel_path))
        } else {
            let new_rel_path = parent.join(nazwa_kandydata(stem, source_tag, &ext, counter));
            (new_rel_path.to_string_lossy().to_string(), target_base.join(&new_rel_path))
        };

        match fs::hard_link(tmp_path, &final_path) {
            Ok(()) => {
                let _ = fs::remove_file(tmp_path);
                return Ok((final_path, final_rel_path, counter != 0));
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                counter += 1;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Rozwiązuje ścieżkę wersji naprawionej przez Fazę 17.
///
/// ## Dwa formaty, oba obsługiwane
///
/// Od rewizji, w której Faza 17 przestała zapisywać naprawy W KORPUSIE
/// ŹRÓDŁOWYM, `repaired_path_*` jest ścieżką **absolutną** do przestrzeni
/// roboczej pod `target_path` — dokładnie tak jak `smart_splice_path` z Fazy 18.
///
/// Bazy zapisane WCZEŚNIEJ trzymają tam ścieżkę **względną** wobec
/// `ufs_path`/`script_path`, bo naprawiony plik leżał obok oryginału. Dla nich
/// zachowujemy stare rozwiązywanie — inaczej istniejące wyniki Fazy 17
/// przestałyby się odnajdywać i Faza 9 cicho kopiowałaby uszkodzone oryginały
/// zamiast napraw.
fn sciezka_naprawiona(zapisana: &str, baza_zrodlowa: &Path) -> PathBuf {
    let sciezka = Path::new(zapisana);
    if sciezka.is_absolute() {
        sciezka.to_path_buf()
    } else {
        baza_zrodlowa.join(sciezka)
    }
}

/// Kopiuje zwycięski plik (lub odtwarza dowiązanie symboliczne) do katalogu
/// docelowego i przywraca metadane (czas modyfikacji, uprawnienia, właściciela).
/// Jeśli zwycięska strona ma wersję zrekonstruowaną przez Fazę 17
/// (`repaired_path_*`), kopiuje TĘ wersję z tamtej ścieżki, nie oryginał —
/// i w takim przypadku POMIJA weryfikację rozmiaru (naprawiony plik z
/// definicji ma inny rozmiar niż uszkodzony oryginał, więc porównanie
/// straciłoby sens). Błędy metadanych (`meta_errors`) są odnotowywane
/// niezależnie od sukcesu samego kopiowania — plik może zostać poprawnie
/// skopiowany, ale np. `chown` zawiedzie bez uprawnień roota; to nie unieważnia
/// samej kopii, stąd nie wpływa na wartość zwracaną `success`.
/// Licznik dla [`sciezka_tymczasowa`] — zapewnia unikalność nazwy pliku
/// tymczasowego, gdy wiele plików o tej samej nazwie bazowej jest
/// kopiowanych "jednocześnie" na tym samym wątku w krótkim odstępie czasu
/// (PID sam w sobie nie wystarcza, bo cała faza działa w jednym procesie).
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Ścieżka pliku tymczasowego w TYM SAMYM katalogu co `docelowa` — konieczne,
/// żeby końcowy `fs::rename` był atomowy (rename między różnymi systemami
/// plików/punktami montowania NIE jest atomowy i może się nie udać z EXDEV).
/// Górny limit (w bajtach) osadzanej w nazwie tymczasowej oryginalnej nazwy
/// pliku — patrz dokumentacja [`sciezka_tymczasowa`].
const MAX_OSADZONEJ_NAZWY_BAJTOW: usize = 200;

/// Obcina `s` do co najwyżej `max_bajtow` bajtów, cofając się do najbliższej
/// granicy znaku UTF-8 — nigdy nie tnie w środku wielobajtowego znaku.
fn obetnij_do_granicy_utf8(s: &str, max_bajtow: usize) -> &str {
    if s.len() <= max_bajtow {
        return s;
    }
    let mut koniec = max_bajtow;
    while koniec > 0 && !s.is_char_boundary(koniec) {
        koniec -= 1;
    }
    &s[..koniec]
}

fn sciezka_tymczasowa(docelowa: &Path) -> PathBuf {
    let nazwa = docelowa.file_name().and_then(|n| n.to_str()).unwrap_or("plik");
    let licznik = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    // REGRESJA (measure twice — druga weryfikacja Gemini, todo.faza09.md N2):
    // poprzednia wersja doklejała stały sufiks DO PEŁNEJ oryginalnej nazwy —
    // plik o nazwie bliskiej limitowi `NAME_MAX` (255 B na typowych systemach
    // Linux) dostawał `ENAMETOOLONG` na `fs::copy` do pliku tymczasowego i
    // był odnotowywany jako błąd I/O, mimo że dałby się skopiować pod
    // finalną (krótszą) nazwą — realna regresja wobec stanu SPRZED wzorca
    // tmp+rename. Nazwa tymczasowa jest i tak odrzucana zaraz po `rename`,
    // więc jej pełna czytelność nie ma znaczenia — tylko unikalność
    // (licznik) i mieszczenie się w limicie systemu plików.
    let obcieta = obetnij_do_granicy_utf8(nazwa, MAX_OSADZONEJ_NAZWY_BAJTOW);
    docelowa.with_file_name(format!(".{}.tmp-{}-{}", obcieta, std::process::id(), licznik))
}

fn copy_file_and_meta(file: &MergeCandidate, winner: &'static str, ufs_path: &Path, script_path: &Path, target_base: &Path, stats: &LiveStats) -> (bool, String, String) {
    let source_path = if winner == "splice" {
        // Plik już złożony i zweryfikowany przez Fazę 18 - leży pod własną,
        // absolutną ścieżką, niezależną od ufs_path/script_path.
        PathBuf::from(file.smart_splice_path.as_ref().expect("winner=splice implikuje Some(smart_splice_path) - patrz decide_winner"))
    } else if winner == "script" {
        if let Some(ref p) = file.repaired_path_script {
            stats.repaired_used.fetch_add(1, Ordering::Relaxed);
            sciezka_naprawiona(p, script_path)
        } else {
            script_path.join(&file.rel_path)
        }
    } else {
        if let Some(ref p) = file.repaired_path_ufs {
            stats.repaired_used.fetch_add(1, Ordering::Relaxed);
            sciezka_naprawiona(p, ufs_path)
        } else {
            ufs_path.join(&file.rel_path)
        }
    };

    // ŚCIEŻKA ŹRÓDŁOWA, z której faktycznie kopiujemy — trafia do bazy jako
    // `merge_source_path`. Sama kolumna `merge_source` mówi tylko "ufs" albo
    // "script", więc nie dawała odpowiedzi na pytanie, czy skopiowano ORYGINAŁ,
    // naprawę z Fazy 17, czy złożenie z Fazy 18. Teraz widać to wprost.
    let zrodlo_txt = source_path.to_string_lossy().to_string();

    let (expected_size, uid, gid, mode, mtime, is_symlink) = if winner == "splice" {
        // Złożenie nie mapuje się czysto na metadane żadnej ze stron -
        // bierzemy metadane Skryptu jeśli dostępne (konwencja domyślna tego
        // projektu przy remisach), inaczej UFS. `expected_size: None`
        // celowo pomija weryfikację rozmiaru niżej - rozmiar złożenia z
        // natury różni się od obu oryginałów (dokładnie jak przy plikach
        // fizycznie naprawionych).
        (None, file.uid_script.or(file.uid_ufs), file.gid_script.or(file.gid_ufs),
         file.mode_script.or(file.mode_ufs), file.mtime_script.or(file.mtime_ufs), Some(false))
    } else if winner == "script" {
        (file.size_script, file.uid_script, file.gid_script, file.mode_script, file.mtime_script, file.is_symlink_script)
    } else {
        (file.size_ufs, file.uid_ufs, file.gid_ufs, file.mode_ufs, file.mtime_ufs, file.is_symlink_ufs)
    };

    let (mut target_path_full, mut final_rel_path, mut renamed) = get_safe_target_path(target_base, &file.rel_path, winner);

    if let Some(parent) = target_path_full.parent() { let _ = fs::create_dir_all(parent); }

    let is_sym = is_symlink.unwrap_or(false);

    if is_sym {
        if let Ok(target_link) = fs::read_link(&source_path) {
            if std::os::unix::fs::symlink(&target_link, &target_path_full).is_err() {
                stats.io_errors.fetch_add(1, Ordering::Relaxed); return (false, final_rel_path, zrodlo_txt);
            }
            stats.symlinks_recreated.fetch_add(1, Ordering::Relaxed);
        } else { stats.io_errors.fetch_add(1, Ordering::Relaxed); return (false, final_rel_path, zrodlo_txt); }
    } else {
        // Kopiowanie do pliku TYMCZASOWEGO w tym samym katalogu, a dopiero po
        // potwierdzonym sukcesie (i weryfikacji rozmiaru, gdy dotyczy) —
        // atomowy `fs::rename` na finalną nazwę. `fs::copy` prosto pod
        // `target_path_full` tworzy/skraca plik wyjściowy PRZED skopiowaniem
        // bajtów — przerwanie (crash/ENOSPC) w trakcie zostawiałoby wtedy
        // uszkodzony plik TRWALE pod finalną nazwą (przy wznowieniu
        // `get_safe_target_path` widziałby "kolizję" i dokleiłby nową,
        // poprawną kopię pod INNĄ nazwą, zamiast nadpisać uszkodzony wynik).
        let tmp_path = sciezka_tymczasowa(&target_path_full);

        if fs::copy(&source_path, &tmp_path).is_err() {
            let _ = fs::remove_file(&tmp_path);
            stats.io_errors.fetch_add(1, Ordering::Relaxed); return (false, final_rel_path, zrodlo_txt);
        }

        let used_repaired = (winner == "script" && file.repaired_path_script.is_some()) || (winner == "ufs" && file.repaired_path_ufs.is_some());

        if !used_repaired {
            match fs::metadata(&tmp_path) {
                Ok(meta) if expected_size.is_none() || Some(meta.len() as i64) == expected_size => {}
                Ok(_) => {
                    warn!(path = %file.rel_path, "Błąd weryfikacji po skopiowaniu - rozmiar nie zgadza się!");
                    let _ = fs::remove_file(&tmp_path);
                    stats.io_errors.fetch_add(1, Ordering::Relaxed); return (false, final_rel_path, zrodlo_txt);
                }
                Err(_) => {
                    let _ = fs::remove_file(&tmp_path);
                    stats.io_errors.fetch_add(1, Ordering::Relaxed); return (false, final_rel_path, zrodlo_txt);
                }
            }
        }

        match commit_bez_nadpisania(&tmp_path, target_base, &file.rel_path, winner) {
            Ok((path, rel, czy_zmieniono)) => {
                target_path_full = path;
                final_rel_path = rel;
                renamed = czy_zmieniono;
            }
            Err(_) => {
                let _ = fs::remove_file(&tmp_path);
                stats.io_errors.fetch_add(1, Ordering::Relaxed); return (false, final_rel_path, zrodlo_txt);
            }
        }
    }

    if renamed { stats.renamed_files.fetch_add(1, Ordering::Relaxed); }

    let mut meta_err = false;
    if let Some(m_ns) = mtime {
        let sec = m_ns / 1_000_000_000; let nsec = (m_ns % 1_000_000_000) as u32;
        let ft = FileTime::from_unix_time(sec, nsec);
        if set_symlink_file_times(&target_path_full, ft, ft).is_err() { meta_err = true; }
    }
    if !is_sym && let Some(md) = mode && fs::set_permissions(&target_path_full, fs::Permissions::from_mode(md)).is_err() { meta_err = true; }
    if let (Some(u), Some(g)) = (uid, gid) && std::os::unix::fs::lchown(&target_path_full, Some(u), Some(g)).is_err() { meta_err = true; }
    if meta_err { stats.meta_errors.fetch_add(1, Ordering::Relaxed); }

    (true, final_rel_path, zrodlo_txt)
}

/// Przetwarza jedną paczkę kandydatów: dla każdego woła [`decide_winner`],
/// kopiuje zwycięzcę przez [`copy_file_and_meta`], aktualizuje [`LiveStats`]
/// i zapisuje wynik do `raport_operacyjny_faza9.txt` (sukces/błąd + powód).
/// Wysyła zbiorczy wynik paczki przez `tx` do wątku zapisu SQLite.
///
/// UWAGA: `last_ui_update` jest deklarowane raz PRZY KAŻDYM WYWOŁANIU tej
/// funkcji (czyli raz na paczkę `CHUNK_SIZE=100`, bo `par_chunks` wywołuje ją
/// osobno dla każdej porcji) — dokładnie ten sam wzorzec, który w Fazach 5-7
/// powodował "skoki" paska zamiast płynnego przyrostu (próg czasowy mógł
/// nigdy nie zostać przekroczony w obrębie jednej szybkiej paczki). Dlatego
/// próg aktualizacji UI niżej jest hybrydowy: licznik globalny
/// (`stats.processed_files`, nie resetuje się na granicy paczki) jako główny
/// wyzwalacz, plus siatka bezpieczeństwa czasowa.
#[instrument(skip(chunk, stats, tx, tx_ui, opr_log), fields(chunk_size = chunk.len()))]
#[allow(clippy::too_many_arguments)]
fn process_chunk(
    chunk: &[MergeCandidate], 
    ufs_path: &Path, 
    script_path: &Path, 
    target_base: &Path, 
    stats: &LiveStats, 
    tx: mpsc::SyncSender<Vec<CopyResult>>, 
    start_time: Instant,
    tx_ui: &mpsc::Sender<PhaseEvent>,
    bar_idx: usize,
    opr_log: Arc<Mutex<File>>, // <--- PRZYWRÓCONY ZGUBIONY ARGUMENT
) {
    let mut results = Vec::with_capacity(chunk.len());
    let mut last_ui_update = Instant::now();

    for file in chunk {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }
        // Wariant A: slot zajęty na czas obsługi tego pliku. Strażnik RAII
        // zwalnia go także przy panice w środku pracy.
        let _slot = stats.thread_activity.enter_current();

        let (winner, reason) = decide_winner(file);
        let (success, saved_path, source_path) = copy_file_and_meta(file, winner, ufs_path, script_path, target_base, stats);

        let final_reason = if success { reason.to_string() } else { format!("{} | BŁĄD KOPIOWANIA (Odmowa I/O)", reason) };

        if success {
            let is_common = file.in_ufs && file.in_script;
            if winner == "splice" {
                stats.copied_splice.fetch_add(1, Ordering::Relaxed);
            } else if winner == "script" {
                if is_common { stats.copied_script_common.fetch_add(1, Ordering::Relaxed); } else { stats.copied_script_unique.fetch_add(1, Ordering::Relaxed); }
            } else {
                if is_common { stats.copied_ufs_common.fetch_add(1, Ordering::Relaxed); } else { stats.copied_ufs_unique.fetch_add(1, Ordering::Relaxed); }
            }

            let mut map = stats.reasons.lock().unwrap();
            *map.entry(reason.to_string()).or_insert(0) += 1;
            
            if let Ok(mut f) = opr_log.lock() {
                let _ = writeln!(f, "[SUKCES] {} -> {}", reason, saved_path);
            }
        } else {
            if let Ok(mut f) = opr_log.lock() {
                let _ = writeln!(f, "[BŁĄD I/O] {} -> {}", reason, saved_path);
            }
        }

        let expected_size = if winner == "splice" {
            // Złożenie nie ma "swojego" rozmiaru w bazie (ten pochodzi z
            // dwóch różnych oryginałów) - liczymy realny rozmiar zapisanego
            // pliku wprost z dysku, tylko gdy kopiowanie się powiodło.
            if success {
                file.smart_splice_path.as_ref().and_then(|p| fs::metadata(p).ok()).map(|m| m.len() as i64)
            } else {
                None
            }
        } else if winner == "script" { file.size_script } else { file.size_ufs };
        if let Some(s) = expected_size { stats.processed_bytes.fetch_add(s as u64, Ordering::Relaxed); }

        let current = stats.processed_files.fetch_add(1, Ordering::Relaxed) + 1;

        let now = Instant::now();
        // Hybrydowy próg (wzorzec z Fazy 5-7): licznik globalny jako główny
        // wyzwalacz (nie resetuje się na granicy paczki CHUNK_SIZE=100),
        // plus siatka bezpieczeństwa czasowa na wolne/duże pliki.
        let should_update = current.is_multiple_of(200)
            || now.duration_since(last_ui_update).as_millis() > 250;

        if should_update {
            last_ui_update = now;

            // PASEK: wyłącznie postęp + bieżący plik (bez liczników)
            let _ = tx_ui.send(PhaseEvent::UpdateBar {
                idx: bar_idx,
                current: current as u64,
                message: format_display_path(&file.rel_path),
            });
            // DOLNY PANEL: pełna ścieżka DOCELOWA (Złota Kopia) - to jest
            // faktyczna operacja I/O tej fazy (kopiowanie NA tę ścieżkę).
            let _ = tx_ui.send(PhaseEvent::UpdateBottomPath {
                idx: bar_idx,
                path: saved_path.clone(),
            });

            // PANEL BOCZNY: jedno, wspólne podsumowanie (bez podziału per-źródło)
            let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                idx: bar_idx,
                text: build_summary_block(stats, start_time),
            });
        }

        results.push(CopyResult { id: file.id, winner, reason: final_reason, success, saved_path, source_path });
    }
    if !results.is_empty() { let _ = tx.send(results); }
}

// ============================================================================
// GŁÓWNA FUNKCJA (Entrypoint)
// ============================================================================

// ============================================================================
// STRUMIENIOWE WCZYTYWANIE KANDYDATÓW (STRONICOWANIE)
// ============================================================================

/// Liczba kandydatów wczytywanych do pamięci JEDNORAZOWO.
///
/// Faza 9 materializowała wcześniej CAŁĄ listę plików do scalenia w jednym
/// `Vec<MergeCandidate>` przed rozpoczęciem kopiowania. Rekord ma ~40 pól, w
/// tym kilka `String`ów, więc przy milionach plików to setki megabajtów
/// zajętych, zanim ruszyła pierwsza operacja I/O. Teraz lista jest czytana
/// stronami i szczyt zużycia zależy od tej stałej, nie od rozmiaru korpusu.
const ROZMIAR_STRONY: usize = 10_000;

/// Filtr plików jeszcze nie scalonych. Pokryty indeksem cząstkowym
/// `idx_phase9_done` (patrz `db::create_indexes`).
const WARUNEK_NIESCALONE: &str = "(phase9_done = 0 OR phase9_done IS NULL)";

/// Lista kolumn wczytywanych do [`MergeCandidate`].
///
/// Trzymana w JEDNYM miejscu, żeby kolejność w `SELECT` nie rozjechała się z
/// indeksami pozycyjnymi w [`zmapuj_kandydata`] — po rozdzieleniu zapytania na
/// strony ten sam zestaw kolumn jest używany w więcej niż jednym miejscu.
const KOLUMNY_KANDYDATA: &str =
    "id, relative_path, found_in_ufs, found_in_script, hash_match, size_ufs, size_script,
     uid_ufs, uid_script, gid_ufs, gid_script, mode_ufs, mode_script, mtime_ufs, mtime_script,
     is_symlink_ufs, is_symlink_script, zeros_pct_ufs, zeros_pct_script, eof_ok_ufs, eof_ok_script,
     entropy_ufs, entropy_script, utf8_ok_ufs, utf8_ok_script, structure_ok_ufs, structure_ok_script,
     exif_ok_ufs, exif_ok_script, media_decoded_ufs, media_decoded_script, has_xattr_ufs, has_xattr_script,
     io_error_ufs, io_error_script, yara_match_ufs, yara_match_script,
     repaired_path_ufs, repaired_path_script, smart_splice_path";

/// Buduje [`MergeCandidate`] z wiersza zapytania o kolumnach
/// [`KOLUMNY_KANDYDATA`] — indeksy pozycyjne muszą odpowiadać tamtej kolejności.
fn zmapuj_kandydata(row: &rusqlite::Row) -> rusqlite::Result<MergeCandidate> {
    Ok(MergeCandidate {
        id: row.get(0)?, rel_path: row.get(1)?, in_ufs: row.get(2)?, in_script: row.get(3)?,
        hash_match: row.get(4)?, size_ufs: row.get(5)?, size_script: row.get(6)?,
        uid_ufs: row.get(7)?, uid_script: row.get(8)?, gid_ufs: row.get(9)?, gid_script: row.get(10)?,
        mode_ufs: row.get(11)?, mode_script: row.get(12)?, mtime_ufs: row.get(13)?, mtime_script: row.get(14)?,
        is_symlink_ufs: row.get(15)?, is_symlink_script: row.get(16)?,
        zeros_pct_ufs: row.get(17)?, zeros_pct_script: row.get(18)?, eof_ok_ufs: row.get(19)?, eof_ok_script: row.get(20)?,
        entropy_ufs: row.get(21)?, entropy_script: row.get(22)?, utf8_ok_ufs: row.get(23)?, utf8_ok_script: row.get(24)?,
        structure_ok_ufs: row.get(25)?, structure_ok_script: row.get(26)?, exif_ok_ufs: row.get(27)?, exif_ok_script: row.get(28)?,
        media_decoded_ufs: row.get(29)?, media_decoded_script: row.get(30)?, has_xattr_ufs: row.get(31)?, has_xattr_script: row.get(32)?,
        io_error_ufs: row.get(33)?, io_error_script: row.get(34)?, yara_match_ufs: row.get(35)?, yara_match_script: row.get(36)?,
        repaired_path_ufs: row.get(37)?, repaired_path_script: row.get(38)?,
        smart_splice_path: row.get(39)?,
    })
}

/// Wczytuje JEDNĄ stronę kandydatów: rekordy o `id` większym niż `po_id`,
/// uporządkowane po `id`.
///
/// ## Dlaczego stronicowanie KLUCZEM, a nie `OFFSET`
///
/// W trakcie pracy Faza 9 ustawia `phase9_done = 1` na przetwarzanych
/// rekordach, więc zbiór pasujący do [`WARUNEK_NIESCALONE`] KURCZY SIĘ w
/// trakcie przeglądania. Przy `LIMIT/OFFSET` kolejne strony przeskakiwałyby
/// rekordy (klasyczny błąd „ruchomego okna"). Warunek `id > po_id` daje
/// stabilny, monotoniczny postęp niezależnie od zmian w tabeli i gwarantuje
/// zakończenie pętli — także wtedy, gdy jakiś rekord nie zostanie oznaczony
/// (np. po anulowaniu w trakcie paczki), co przy przepytywaniu „daj
/// nieprzetworzone" mogłoby dać pętlę nieskończoną.
fn wczytaj_strone(conn: &Connection, po_id: i32, limit: usize) -> Result<Vec<MergeCandidate>> {
    let sql = format!(
        "SELECT {} FROM files WHERE {} AND id > ?1 ORDER BY id LIMIT ?2",
        KOLUMNY_KANDYDATA, WARUNEK_NIESCALONE
    );

    let mut stmt = conn.prepare(&sql)?;
    let strona: Vec<MergeCandidate> = stmt
        .query_map(params![po_id, limit as i64], zmapuj_kandydata)?
        .filter_map(|r| r.ok())
        .collect();

    Ok(strona)
}

/// Punkt wejścia Fazy 9, wołany przez `menu::actions::run_phase_with_ui`.
///
/// Przebieg: (1) tworzy katalog docelowy jeśli nie istnieje; (2) wczytuje
/// z SQLite wszystkie rekordy jeszcze nie scalone (`phase9_done = 0`);
/// (3) przetwarza je jednym `par_chunks(...)` (CONCURRENT) lub sekwencyjnie
/// paczka-po-paczce (SEQUENTIAL) — patrz dokumentacja modułu, dlaczego nie
/// ma tu podziału na dedykowane pule per-strona jak w Fazach 3-7; (4) po
/// zakończeniu generuje Dziennik Końcowy z pełnym rozkładem wygranych,
/// błędów i powodów decyzji.
#[instrument(skip(conn, config, tx_ui))]
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> Result<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);
    let ufs_path = Path::new(&config.ufs_path);
    let script_path = Path::new(&config.script_path);
    let target_path = Path::new(&config.target_path);

    let _ = tx_ui.send(PhaseEvent::Log("Uruchomiono Fazę 9: SMART MERGE (Złota Kopia).".to_string()));

    // Ta faza FIZYCZNIE ZAPISUJE finalny wynik na dysk (`copy_file_and_meta`,
    // w tym `lchown`/`set_permissions`/`set_symlink_file_times`). Błędna
    // konfiguracja operatora (target_path == ufs_path/script_path, albo
    // jeden zagnieżdżony w drugim) fizycznie NADPISAŁABY materiał dowodowy —
    // sprawdzamy PRZED jakimkolwiek zapisem, nie po fakcie.
    if let Err(powod) = sciezki_bezpieczne(target_path, ufs_path, script_path) {
        let _ = tx_ui.send(PhaseEvent::Log(format!("BŁĄD KRYTYCZNY: {}", powod)));
        return Ok(());
    }

    let start_time = Instant::now();

    if !target_path.exists()
        && let Err(e) = fs::create_dir_all(target_path) {
            let _ = tx_ui.send(PhaseEvent::Log(format!("BŁĄD KRYTYCZNY: Nie udało się utworzyć katalogu docelowego ({}). Sprawdź uprawnienia!", e)));
            return Ok(());
        }

    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
    let _ = conn.execute("ALTER TABLE files ADD COLUMN merge_reason TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN target_saved_path TEXT", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN merge_source_path TEXT", []);

    // Sama LICZBA kandydatów — do paska postępu. Lista jest czytana stronami
    // dopiero w pętli niżej, patrz [`ROZMIAR_STRONY`].
    let total_files: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM files WHERE {}", WARUNEK_NIESCALONE),
        [],
        |r| r.get(0),
    )?;

    if total_files == 0 {
        let _ = tx_ui.send(PhaseEvent::Log("✔ Kopiowanie SMART MERGE zostało w pełni ukończone podczas poprzednich uruchomień.".to_string()));
        return Ok(());
    }

    let actual_threads = rayon::current_num_threads();
    let io_text = if config.io_mode == "CONCURRENT" { "RÓWNOLEGŁE" } else { "SEKWENCYJNIE" };
    let _ = tx_ui.send(PhaseEvent::Log(format!("Metodyka pracy szyny dyskowej: {}", io_text)));
    let _ = tx_ui.send(PhaseEvent::Log(format!("Aktywne wątki procesora (Rayon): {}", actual_threads)));

    // PRZYWRÓCONE INICJALIZACJE ŚCIEŻEK LOGOWANIA Z CONFIGU DLA TXT
    let raport_cfg = config.raporty_faz.get("Faza 9").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza9.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza9.txt".to_string(),
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
        let mut f_info = opr_log.lock().unwrap();
        let _ = writeln!(f_info, "=== RAPORT OPERACYJNY - FAZA 9: ZŁOTA KOPIA (SMART MERGE) ===");
        let _ = writeln!(f_info, "Ślad rewizyjny (Audit Trail) wszystkich przenoszonych plików (wygrane instancje).\n");
    }

    let _ = tx_ui.send(PhaseEvent::SetBar {
        idx: 0,
        label: "Kopiowanie (Smart Merge)".to_string(),
        total: total_files as u64,
        color: Color::Yellow,
    });

    let stats = LiveStats::new(rayon::current_num_threads());

    // Licznik zapisanych rekordów PONAD wszystkie strony — pojedynczy komunikat
    // na koniec, zamiast jednego na każdą stronę.
    let zapisane_lacznie = AtomicUsize::new(0);
    let mut ostatni_id: i32 = 0;

    // ========================================================================
    // PĘTLA STRON: wczytaj stronę -> skopiuj -> zapisz wyniki -> następna.
    //
    // Wczytywanie i zapis są ROZŁĄCZNE W CZASIE, bo jedno połączenie SQLite nie
    // może być jednocześnie pożyczone niemutowalnie (odczyt strony) i
    // mutowalnie (transakcja wątku zapisu). Wewnątrz jednej strony zostaje
    // dotychczasowa architektura: równoległe kopiowanie na puli Rayon plus
    // dedykowany wątek zapisu z kanałem ograniczonym (backpressure).
    // ========================================================================
    loop {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }

        let strona = wczytaj_strone(conn, ostatni_id, ROZMIAR_STRONY)?;
        if strona.is_empty() { break; }

        // Klucz kolejnej strony — rekordy przychodzą po rosnącym `id`.
        ostatni_id = strona[strona.len() - 1].id;

        let zapisane_ref = &zapisane_lacznie;

        // Wynik wątku zapisu jest przenoszony na zewnątrz zakresu i zgłaszany
        // przez `?` niżej — zamiast panikować w środku `thread::scope`.
        let wynik_zapisu: Result<()> = std::thread::scope(|s| {
            let (tx, rx): (mpsc::SyncSender<Vec<CopyResult>>, mpsc::Receiver<Vec<CopyResult>>) = mpsc::sync_channel(50);
            let conn_ref = &mut *conn;

            let db_thread = s.spawn(move || -> Result<()> {
                // COMMIT HYBRYDOWY (wzorzec z Fazy 3): co `PROG_COMMITU` rekordów
                // ALBO co 500 ms. Wcześniej cały przebieg mieścił się w JEDNEJ
                // transakcji, zatwierdzanej dopiero na końcu — twarda awaria po
                // godzinach kopiowania traciła CAŁY zapis postępu (pliki leżały
                // już w Złotej Kopii, ale baza o nich nie wiedziała, więc ponowny
                // przebieg kopiował wszystko od zera), a WAL rósł do rozmiaru
                // całego przebiegu.
                let mut tx_db = conn_ref.transaction()?;
                let mut oczekujace: usize = 0;
                let mut ostatni_commit = Instant::now();

                loop {
                    let odebrane = rx.recv_timeout(Duration::from_millis(100));
                    // Flagę rozłączenia zapamiętujemy PRZED skonsumowaniem wyniku.
                    let rozlaczony = matches!(&odebrane, Err(mpsc::RecvTimeoutError::Disconnected));

                    if let Ok(paczka) = odebrane {
                        {
                            let mut stmt = tx_db.prepare_cached(
                                "UPDATE files SET phase9_done = 1, merge_source = ?1, merge_success = ?2,
                                                  merge_reason = ?3, target_saved_path = ?4, merge_source_path = ?5
                                 WHERE id = ?6"
                            )?;
                            for res in &paczka {
                                stmt.execute(params![res.winner, res.success, res.reason, res.saved_path, res.source_path, res.id])?;
                            }
                        }
                        oczekujace += paczka.len();
                        zapisane_ref.fetch_add(paczka.len(), Ordering::Relaxed);
                    }

                    let teraz = Instant::now();
                    if oczekujace > 0
                        && (oczekujace >= PROG_COMMITU || teraz.duration_since(ostatni_commit).as_millis() > 500)
                    {
                        tx_db.commit()?;
                        tx_db = conn_ref.transaction()?;
                        ostatni_commit = teraz;
                        oczekujace = 0;
                    }

                    if rozlaczony { break; }
                }

                tx_db.commit()?;
                Ok(())
            });

            if config.io_mode == "CONCURRENT" {
                strona.par_chunks(CHUNK_SIZE).for_each_with(tx, |tx, chunk| {
                    process_chunk(chunk, ufs_path, script_path, target_path, &stats, tx.clone(), start_time, &tx_ui, 0, opr_log.clone());
                });
            } else {
                for chunk in strona.chunks(CHUNK_SIZE) {
                    process_chunk(chunk, ufs_path, script_path, target_path, &stats, tx.clone(), start_time, &tx_ui, 0, opr_log.clone());
                }
            }

            match db_thread.join() {
                Ok(wynik) => wynik,
                // `join` zwraca `Err` wyłącznie przy panice wątku; sama panika jest
                // już odnotowana przez globalny hook w `logging.rs`.
                Err(_) => {
                    let _ = tx_ui.send(PhaseEvent::Log(
                        "✖ BŁĄD: wątek zapisu do bazy zakończył się paniką. Część postępu mogła nie zostać zapisana.".to_string()
                    ));
                    Err(rusqlite::Error::UnwindingPanic)
                }
            }
        });

        if let Err(e) = &wynik_zapisu {
            // Dzięki commitowi hybrydowemu wcześniejsze paczki są JUŻ zatwierdzone,
            // więc powtórny przebieg dokończy pracę, zamiast zaczynać od zera.
            let _ = tx_ui.send(PhaseEvent::Log(format!(
                "✖ Zapis stanu Fazy 9 do bazy zawiódł: {}. Zatwierdzone wcześniej paczki są bezpieczne — uruchom Fazę 9 ponownie, dokończy od miejsca przerwania.",
                e
            )));
            warn!(blad = %e, "Faza 9: zapis stanu do bazy zawiódł");
        }
        wynik_zapisu?;
    }

    let _ = tx_ui.send(PhaseEvent::Log(format!(
        "✔ Zapisano w bazie stan {} scalonych rekordów.",
        zapisane_lacznie.load(Ordering::Relaxed)
    )));

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: 0,
        current: total_files as u64,
        message: "Kopiowanie Złotej Kopii w 100% zakończone.".to_string(),
    });

    // --- RAPORT KRYMINALISTYCZNY ---
    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log("🛑 Kopiowanie przerwane przez użytkownika. Zapisano dotychczasowy postęp.".to_string()));
        return Ok(());
    }

    let elapsed = start_time.elapsed();
    let total_bytes = stats.processed_bytes.load(Ordering::SeqCst);
    let avg_speed_mb = (total_bytes as f64 / 1_048_576.0) / elapsed.as_secs_f64().max(1.0);
    
    let ufs_c = stats.copied_ufs_common.load(Ordering::SeqCst); let scr_c = stats.copied_script_common.load(Ordering::SeqCst);
    let ufs_u = stats.copied_ufs_unique.load(Ordering::SeqCst); let scr_u = stats.copied_script_unique.load(Ordering::SeqCst);
    let symlinks = stats.symlinks_recreated.load(Ordering::SeqCst); let renamed = stats.renamed_files.load(Ordering::SeqCst);
    let io_err = stats.io_errors.load(Ordering::SeqCst); let meta_err = stats.meta_errors.load(Ordering::SeqCst);
    let repaired_used = stats.repaired_used.load(Ordering::SeqCst);

    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;
    let _ = writeln!(&mut log_out, "==========================================================================");
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 9 (ZŁOTA KOPIA I SMART MERGE)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "Sumaryczny transfer zapisu: {} (Średnia prędkość: {:.2} MB/s)", format_bytes(total_bytes), avg_speed_mb);
    let _ = writeln!(&mut log_out, "==========================================================================\n");
    
    let _ = writeln!(&mut log_out, "[ 1 ] STATYSTYKI FUZJI:");
    let _ = writeln!(&mut log_out, "   -> Uratowano z puli wspólnej: UFS ({}), Skrypt ({})", ufs_c, scr_c);
    let _ = writeln!(&mut log_out, "   -> Skopiowano pliki unikalne: UFS ({}), Skrypt ({})", ufs_u, scr_u);
    let _ = writeln!(&mut log_out, "   -> Wykorzystano Aktywnie Zrekonstruowane Wersje (Faza 17): {} plików\n", repaired_used);
    
    let _ = writeln!(&mut log_out, "[ 2 ] ŚLAD REWIZYJNY (Dlaczego algorytm odrzucał/wybierał poszczególne pliki):");
    let reasons_map = stats.reasons.lock().unwrap();
    let mut sorted_reasons: Vec<_> = reasons_map.iter().collect();
    sorted_reasons.sort_by(|a, b| b.1.cmp(a.1));
    for (reason, count) in sorted_reasons.iter() { let _ = writeln!(&mut log_out, "   -> {} (Ilość: {})", reason, count); }
    
    if io_err > 0 || meta_err > 0 || renamed > 0 { 
        let _ = writeln!(&mut log_out, "\n[ 3 ] BŁĘDY I ZMIANY SYSTEMOWE:"); 
        if renamed > 0 { let _ = writeln!(&mut log_out, "   -> Zmieniono nazwę (Ochrona przed nadpisaniem): {}", renamed); }
        if symlinks > 0 { let _ = writeln!(&mut log_out, "   -> Odtworzono symlinki: {}", symlinks); }
        if io_err > 0 { let _ = writeln!(&mut log_out, "   -> Błędy I/O zapisu: {}", io_err); }
    }

    // PRZYWRÓCONE: Zapis fizyczny z odpowiednimi ścieżkami zadeklarowanymi wcześniej
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
        ufs_c,
        scr_c,
        ufs_u,
        scr_u,
        repaired_used,
        io_err,
        "Faza 9 zakończona"
    );

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Bazowy kandydat "remisowy": plik obecny po obu stronach, identyczny
    /// rozmiar, zgodny hash - domyślnie ląduje na "Zgodne bit-do-bitu" (Skrypt).
    /// Testy nadpisują tylko pola istotne dla danego priorytetu.
    fn base_candidate() -> MergeCandidate {
        MergeCandidate {
            id: 1, rel_path: "test.dat".to_string(), in_ufs: true, in_script: true,
            hash_match: Some(true), size_ufs: Some(100), size_script: Some(100),
            uid_ufs: None, uid_script: None, gid_ufs: None, gid_script: None,
            mode_ufs: None, mode_script: None, mtime_ufs: None, mtime_script: None,
            is_symlink_ufs: None, is_symlink_script: None,
            zeros_pct_ufs: None, zeros_pct_script: None, eof_ok_ufs: None, eof_ok_script: None,
            entropy_ufs: None, entropy_script: None, utf8_ok_ufs: None, utf8_ok_script: None,
            structure_ok_ufs: None, structure_ok_script: None, exif_ok_ufs: None, exif_ok_script: None,
            media_decoded_ufs: None, media_decoded_script: None, has_xattr_ufs: None, has_xattr_script: None,
            io_error_ufs: None, io_error_script: None, yara_match_ufs: None, yara_match_script: None,
            repaired_path_ufs: None, repaired_path_script: None,
            smart_splice_path: None,
        }
    }

    // ------------------------------------------------------------------
    // decide_winner: priorytet 0 - YARA
    // ------------------------------------------------------------------

    #[test]
    fn test_decide_yara_ufs_infected_script_wins() {
        let c = MergeCandidate { yara_match_ufs: Some("Trojan".to_string()), ..base_candidate() };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "script");
        assert!(reason.contains("Zainfekowany"));
    }

    #[test]
    fn test_decide_yara_script_infected_ufs_wins() {
        let c = MergeCandidate { yara_match_script: Some("Trojan".to_string()), ..base_candidate() };
        assert_eq!(decide_winner(&c).0, "ufs");
    }

    #[test]
    fn test_decide_yara_wins_over_repair() {
        let c = MergeCandidate {
            yara_match_ufs: Some("Malware".to_string()),
            repaired_path_ufs: Some("test.repaired".to_string()),
            ..base_candidate()
        };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "script");
        assert!(reason.contains("Zainfekowany"), "YARA musi wygrać nad rekonstrukcją: {}", reason);
    }

    // ------------------------------------------------------------------
    // decide_winner: priorytet 1a (po YARA) - Smart Splice Fazy 18
    // ------------------------------------------------------------------

    #[test]
    fn test_decide_smart_splice_wins_when_present() {
        let c = MergeCandidate { smart_splice_path: Some("/tmp/x_smartsplice.png".to_string()), ..base_candidate() };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "splice");
        assert!(reason.contains("Faza 18"));
    }

    #[test]
    fn test_decide_smart_splice_wins_over_physical_repair() {
        // Złożenie (dowód: realne dekodowanie) jest silniejszym sygnałem niż
        // sama naprawa nagłówka - powinno wygrać, gdy oba są obecne.
        let c = MergeCandidate {
            smart_splice_path: Some("/tmp/x_smartsplice.jpg".to_string()),
            repaired_path_ufs: Some("x.repaired".to_string()),
            ..base_candidate()
        };
        assert_eq!(decide_winner(&c).0, "splice");
    }

    #[test]
    fn test_decide_yara_wins_over_smart_splice() {
        // Bezpieczeństwo ponad wszystko: zainfekowana strona źródłowa dyskwalifikuje
        // nawet zweryfikowane dekodowaniem złożenie zbudowane częściowo z niej.
        let c = MergeCandidate {
            yara_match_ufs: Some("Malware".to_string()),
            smart_splice_path: Some("/tmp/x_smartsplice.png".to_string()),
            ..base_candidate()
        };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "script");
        assert!(reason.contains("Zainfekowany"), "YARA musi wygrać nad Smart Splice: {}", reason);
    }

    #[test]
    fn test_decide_no_smart_splice_falls_through_to_normal_logic() {
        // Brak smart_splice_path (None) - zwykła hierarchia decyzyjna działa dalej bez zmian.
        let c = MergeCandidate { hash_match: Some(true), ..base_candidate() };
        assert_eq!(decide_winner(&c).0, "script");
    }

    // ------------------------------------------------------------------
    // decide_winner: priorytet 1 - rekonstrukcja Fazy 17
    // ------------------------------------------------------------------

    #[test]
    fn test_decide_repaired_ufs_only() {
        let c = MergeCandidate { repaired_path_ufs: Some("x.repaired".to_string()), ..base_candidate() };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "ufs");
        assert!(reason.contains("zrekonstruowanej"));
    }

    #[test]
    fn test_decide_repaired_script_only() {
        let c = MergeCandidate { repaired_path_script: Some("x.repaired".to_string()), ..base_candidate() };
        assert_eq!(decide_winner(&c).0, "script");
    }

    #[test]
    fn test_decide_repaired_both_defaults_to_script() {
        let c = MergeCandidate {
            repaired_path_ufs: Some("a.repaired".to_string()),
            repaired_path_script: Some("b.repaired".to_string()),
            ..base_candidate()
        };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "script");
        assert!(reason.contains("Priorytet domyślny"));
    }

    // ------------------------------------------------------------------
    // decide_winner: priorytet 2 - anomalie strukturalne (symetryczne)
    // ------------------------------------------------------------------

    #[test]
    fn test_decide_io_error_ufs_only_script_wins() {
        let c = MergeCandidate { io_error_ufs: Some(true), ..base_candidate() };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "script");
        assert!(reason.contains("Błąd I/O"));
    }

    #[test]
    fn test_decide_io_error_script_only_ufs_wins() {
        let c = MergeCandidate { io_error_script: Some(true), ..base_candidate() };
        assert_eq!(decide_winner(&c).0, "ufs");
    }

    #[test]
    fn test_decide_io_error_both_sides_falls_through_to_default() {
        // Symetryczny błąd po OBU stronach nie pasuje do warunku asymetrycznego
        // (X zawiódł, Y nie) - ocena kontynuuje do dalszych priorytetów.
        let c = MergeCandidate { io_error_ufs: Some(true), io_error_script: Some(true), ..base_candidate() };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "script"); // domyślny remis (Zgodne bit-do-bitu)
        assert!(!reason.contains("Błąd I/O"));
    }

    #[test]
    fn test_decide_media_decode_failure_ufs() {
        let c = MergeCandidate { media_decoded_ufs: Some(false), ..base_candidate() };
        assert_eq!(decide_winner(&c).0, "script");
    }

    #[test]
    fn test_decide_structure_failure_script() {
        let c = MergeCandidate { structure_ok_script: Some(false), ..base_candidate() };
        assert_eq!(decide_winner(&c).0, "ufs");
    }

    #[test]
    fn test_decide_utf8_failure_ufs() {
        let c = MergeCandidate { utf8_ok_ufs: Some(false), ..base_candidate() };
        assert_eq!(decide_winner(&c).0, "script");
    }

    #[test]
    fn test_decide_exif_failure_script() {
        let c = MergeCandidate { exif_ok_script: Some(false), ..base_candidate() };
        assert_eq!(decide_winner(&c).0, "ufs");
    }

    #[test]
    fn test_decide_eof_failure_ufs() {
        let c = MergeCandidate { eof_ok_ufs: Some(false), ..base_candidate() };
        assert_eq!(decide_winner(&c).0, "script");
    }

    // ------------------------------------------------------------------
    // decide_winner: priorytet 3 - progi ujednolicone (99.0% zer, 7.995 entropii)
    // ------------------------------------------------------------------

    #[test]
    fn test_decide_wydmuszka_ufs() {
        let c = MergeCandidate { zeros_pct_ufs: Some(99.5), zeros_pct_script: Some(10.0), ..base_candidate() };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "script");
        assert!(reason.contains("Wydmuszka"));
    }

    #[test]
    fn test_decide_wydmuszka_threshold_exactly_99_not_triggered() {
        // Próg to ŚCIŚLE > 99.0 (ujednolicone z Fazą 8)
        let c = MergeCandidate { zeros_pct_ufs: Some(99.0), ..base_candidate() };
        let (_, reason) = decide_winner(&c);
        assert!(!reason.contains("Wydmuszka"));
    }

    #[test]
    fn test_decide_high_entropy_ufs() {
        let c = MergeCandidate { entropy_ufs: Some(8.0), entropy_script: Some(4.0), ..base_candidate() };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "script");
        assert!(reason.contains("entropia"));
    }

    #[test]
    fn test_decide_entropy_threshold_exactly_7995_not_triggered() {
        // Próg to ŚCIŚLE > 7.995 (ujednolicone z Fazą 7)
        let c = MergeCandidate { entropy_ufs: Some(7.995), ..base_candidate() };
        let (_, reason) = decide_winner(&c);
        assert!(!reason.contains("entropia"));
    }

    // ------------------------------------------------------------------
    // decide_winner: priorytety 4-6 - xattr, rozmiar, remis
    // ------------------------------------------------------------------

    #[test]
    fn test_decide_xattr_preserved_only_ufs_wins() {
        let c = MergeCandidate { has_xattr_ufs: Some(true), ..base_candidate() };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "ufs");
        assert!(reason.contains("xattr"));
    }

    #[test]
    fn test_decide_larger_size_wins() {
        let c = MergeCandidate { size_ufs: Some(500), size_script: Some(100), ..base_candidate() };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "ufs");
        assert!(reason.contains("Większy rozmiar"));
    }

    #[test]
    fn test_decide_identical_hash_defaults_to_script() {
        let c = base_candidate(); // hash_match: Some(true), rozmiary równe
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "script");
        assert!(reason.contains("Zgodne bit-do-bitu"));
    }

    #[test]
    fn test_decide_total_tie_defaults_to_script() {
        let c = MergeCandidate { hash_match: Some(false), ..base_candidate() };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "script");
        assert!(reason.contains("Remis heurystyczny"));
    }

    // ------------------------------------------------------------------
    // decide_winner: pliki unikalne
    // ------------------------------------------------------------------

    #[test]
    fn test_decide_unique_ufs_only() {
        let c = MergeCandidate { in_ufs: true, in_script: false, ..base_candidate() };
        let (winner, reason) = decide_winner(&c);
        assert_eq!(winner, "ufs");
        assert!(reason.contains("unikalny"));
    }

    #[test]
    fn test_decide_unique_script_only() {
        let c = MergeCandidate { in_ufs: false, in_script: true, ..base_candidate() };
        assert_eq!(decide_winner(&c).0, "script");
    }

    // ------------------------------------------------------------------
    // get_safe_target_path
    // ------------------------------------------------------------------

    #[test]
    fn test_safe_path_no_collision() {
        let dir = tempdir().unwrap();
        let (path, rel, renamed) = get_safe_target_path(dir.path(), "plik.txt", "script");
        assert!(!renamed);
        assert_eq!(rel, "plik.txt");
        assert_eq!(path, dir.path().join("plik.txt"));
    }

    #[test]
    fn test_safe_path_single_collision_gets_source_tag() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("plik.txt"), b"istniejacy").unwrap();

        let (_, rel, renamed) = get_safe_target_path(dir.path(), "plik.txt", "script");
        assert!(renamed);
        assert_eq!(rel, "plik_[SKRYPT].txt");
    }

    #[test]
    fn test_safe_path_ufs_tag_when_winner_is_ufs() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("plik.txt"), b"istniejacy").unwrap();

        let (_, rel, _) = get_safe_target_path(dir.path(), "plik.txt", "ufs");
        assert_eq!(rel, "plik_[UFS].txt");
    }

    #[test]
    fn test_safe_path_zlozony_tag_when_winner_is_splice() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("plik.txt"), b"istniejacy").unwrap();

        let (_, rel, _) = get_safe_target_path(dir.path(), "plik.txt", "splice");
        assert_eq!(rel, "plik_[ZLOZONY].txt");
    }

    #[test]
    fn test_safe_path_double_collision_gets_version_suffix() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("plik.txt"), b"a").unwrap();
        std::fs::write(dir.path().join("plik_[SKRYPT].txt"), b"b").unwrap();

        let (_, rel, renamed) = get_safe_target_path(dir.path(), "plik.txt", "script");
        assert!(renamed);
        assert_eq!(rel, "plik_[SKRYPT]_v2.txt");
    }

    #[test]
    fn test_safe_path_file_without_extension() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("README"), b"a").unwrap();

        let (_, rel, _) = get_safe_target_path(dir.path(), "README", "ufs");
        assert_eq!(rel, "README_[UFS]");
    }

    #[test]
    fn test_safe_path_preserves_subdirectory_structure() {
        let dir = tempdir().unwrap();
        // Brak kolizji - podkatalog nie musi fizycznie istnieć do samego sprawdzenia .exists()
        let (path, rel, renamed) = get_safe_target_path(dir.path(), "sub/dir/plik.txt", "script");
        assert!(!renamed);
        assert_eq!(rel, "sub/dir/plik.txt");
        assert_eq!(path, dir.path().join("sub/dir/plik.txt"));
    }

    // ------------------------------------------------------------------
    // commit_bez_nadpisania — regresja na TOCTOU między optymistycznym
    // `get_safe_target_path` a faktycznym zapisem (dwa wątki Rayon widzą tę
    // samą nazwę jako "wolną" i oba próbują ją "zatwierdzić").
    // ------------------------------------------------------------------

    /// Sedno naprawy: kiedy dwa "wątki" (symulowane tu sekwencyjnie — sam
    /// mechanizm jest deterministyczny per wywołanie, więc kolejność
    /// wywołań odpowiada dokładnie temu, co by się stało przy realnym
    /// wyścigu) kończą kopiowanie do RÓŻNYCH plików tymczasowych, ale oba
    /// celują w tę samą nazwę docelową — drugi NIE MOŻE nadpisać treści
    /// pierwszego. Ze starym `fs::rename` ten test by nie przeszedł: drugi
    /// `rename` cicho skasowałby zawartość pierwszego pliku.
    #[test]
    fn test_commit_bez_nadpisania_drugi_watek_nie_nadpisuje_pierwszego() {
        let dir = tempdir().unwrap();

        let tmp1 = dir.path().join(".tmp1");
        let tmp2 = dir.path().join(".tmp2");
        std::fs::write(&tmp1, b"TRESC_WATKU_A").unwrap();
        std::fs::write(&tmp2, b"TRESC_WATKU_B").unwrap();

        let (path1, rel1, renamed1) = commit_bez_nadpisania(&tmp1, dir.path(), "plik.txt", "script").unwrap();
        let (path2, rel2, renamed2) = commit_bez_nadpisania(&tmp2, dir.path(), "plik.txt", "script").unwrap();

        assert!(!renamed1, "Pierwszy 'wątek' nie miał kolizji — powinien dostać nazwę oryginalną");
        assert!(renamed2, "Drugi 'wątek' musiał dostać INNĄ nazwę, bo oryginalna była już zajęta");
        assert_ne!(path1, path2, "Obie kopie muszą wylądować pod różnymi ścieżkami");

        assert_eq!(std::fs::read(&path1).unwrap(), b"TRESC_WATKU_A", "Treść pierwszego pliku nie może zostać nadpisana");
        assert_eq!(std::fs::read(&path2).unwrap(), b"TRESC_WATKU_B", "Treść drugiego pliku musi być zachowana pod jego własną nazwą");

        assert_eq!(rel1, "plik.txt");
        assert_eq!(rel2, "plik_[SKRYPT].txt");

        assert!(!tmp1.exists(), "Plik tymczasowy musi zniknąć po zatwierdzeniu");
        assert!(!tmp2.exists(), "Plik tymczasowy musi zniknąć po zatwierdzeniu");
    }

    /// Trzeci "wątek" trafiający na tę samą nazwę po tym, jak i oryginał, i
    /// pierwszy sufiks `_[TAG]` są już zajęte — musi dostać `_v2`, dokładnie
    /// jak przy optymistycznej ścieżce w `get_safe_target_path`.
    #[test]
    fn test_commit_bez_nadpisania_trzecia_kolizja_dostaje_wersje_v2() {
        let dir = tempdir().unwrap();

        let tmp1 = dir.path().join(".tmp1");
        let tmp2 = dir.path().join(".tmp2");
        let tmp3 = dir.path().join(".tmp3");
        std::fs::write(&tmp1, b"A").unwrap();
        std::fs::write(&tmp2, b"B").unwrap();
        std::fs::write(&tmp3, b"C").unwrap();

        let (_, rel1, _) = commit_bez_nadpisania(&tmp1, dir.path(), "plik.txt", "ufs").unwrap();
        let (_, rel2, _) = commit_bez_nadpisania(&tmp2, dir.path(), "plik.txt", "ufs").unwrap();
        let (path3, rel3, renamed3) = commit_bez_nadpisania(&tmp3, dir.path(), "plik.txt", "ufs").unwrap();

        assert_eq!(rel1, "plik.txt");
        assert_eq!(rel2, "plik_[UFS].txt");
        assert!(renamed3);
        assert_eq!(rel3, "plik_[UFS]_v2.txt");
        assert_eq!(std::fs::read(&path3).unwrap(), b"C");
    }

    /// Brak kolizji w ogóle: musi zachowywać się identycznie jak prosty
    /// `fs::rename` w typowym, nieskonfliktowanym przypadku.
    #[test]
    fn test_commit_bez_nadpisania_bez_kolizji_zachowuje_oryginalna_nazwe() {
        let dir = tempdir().unwrap();
        // Katalog nadrzędny musi istnieć PRZED wywołaniem — dokładnie tak,
        // jak w produkcji robi to `fs::create_dir_all` w `copy_file_and_meta`
        // (na podstawie optymistycznej ścieżki z `get_safe_target_path`)
        // ZANIM wywoła `commit_bez_nadpisania`. Sama funkcja nie tworzy
        // katalogów — odpowiada wyłącznie za bezpieczną rezerwację nazwy.
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        let tmp = dir.path().join(".tmp");
        std::fs::write(&tmp, b"tresc").unwrap();

        let (path, rel, renamed) = commit_bez_nadpisania(&tmp, dir.path(), "sub/plik.txt", "script").unwrap();

        assert!(!renamed);
        assert_eq!(rel, "sub/plik.txt");
        assert_eq!(path, dir.path().join("sub/plik.txt"));
        assert_eq!(std::fs::read(&path).unwrap(), b"tresc");
        assert!(!tmp.exists());
    }

    // ------------------------------------------------------------------
    // copy_file_and_meta (bez chown - wymaga uprawnień roota)
    // ------------------------------------------------------------------

    #[test]
    fn test_copy_regular_file_success() {
        let ufs_dir = tempdir().unwrap();
        let script_dir = tempdir().unwrap();
        let target_dir = tempdir().unwrap();
        std::fs::write(ufs_dir.path().join("plik.txt"), b"zawartosc testowa").unwrap();

        let candidate = MergeCandidate { rel_path: "plik.txt".to_string(), size_ufs: Some(17), ..base_candidate() };
        let stats = LiveStats::new(rayon::current_num_threads());

        let (success, saved_path, _source_path) = copy_file_and_meta(&candidate, "ufs", ufs_dir.path(), script_dir.path(), target_dir.path(), &stats);

        assert!(success);
        assert_eq!(saved_path, "plik.txt");
        let copied = std::fs::read(target_dir.path().join("plik.txt")).unwrap();
        assert_eq!(copied, b"zawartosc testowa");
        assert_eq!(stats.io_errors.load(Ordering::Relaxed), 0);

        // REGRESJA: kopiowanie idzie teraz przez plik tymczasowy + rename -
        // po sukcesie w katalogu docelowym nie może zostać ŻADEN plik `.tmp-*`.
        let pozostale: Vec<_> = std::fs::read_dir(target_dir.path()).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(pozostale.is_empty(), "plik tymczasowy nie został posprzątany: {:?}", pozostale);
    }

    // ------------------------------------------------------------------
    // REGRESJA (Gemini review): `fs::copy` prosto pod finalną nazwą zostawiał
    // uszkodzony/niekompletny plik TRWALE pod tą nazwą przy błędzie w trakcie
    // kopiowania (np. niezgodność rozmiaru wykryta po fakcie) - teraz idzie
    // przez plik tymczasowy + atomowy `rename`, więc porażka nie może
    // zostawić NICZEGO pod finalną nazwą.
    // ------------------------------------------------------------------

    #[test]
    fn test_copy_bledny_rozmiar_nie_zostawia_zadnego_pliku_pod_finalna_nazwa() {
        let ufs_dir = tempdir().unwrap();
        let script_dir = tempdir().unwrap();
        let target_dir = tempdir().unwrap();
        std::fs::write(ufs_dir.path().join("plik.txt"), b"tresc o innej dlugosci niz oczekiwana").unwrap();

        // size_ufs celowo NIEZGODNY z rzeczywistą długością zapisanego pliku -
        // wymusza porażkę weryfikacji rozmiaru w copy_file_and_meta.
        let candidate = MergeCandidate { rel_path: "plik.txt".to_string(), size_ufs: Some(999_999), ..base_candidate() };
        let stats = LiveStats::new(rayon::current_num_threads());

        let (success, _, _) = copy_file_and_meta(&candidate, "ufs", ufs_dir.path(), script_dir.path(), target_dir.path(), &stats);

        assert!(!success);
        assert!(!target_dir.path().join("plik.txt").exists(), "błąd weryfikacji rozmiaru nie może zostawić pliku pod finalną nazwą");
        let pozostale: Vec<_> = std::fs::read_dir(target_dir.path()).unwrap().filter_map(|e| e.ok()).collect();
        assert!(pozostale.is_empty(), "katalog docelowy musi zostać pusty (bez osieroconych plików .tmp-*), znaleziono: {:?}",
            pozostale.iter().map(|e| e.file_name()).collect::<Vec<_>>());
    }

    // ------------------------------------------------------------------
    // REGRESJA (Gemini review): sciezki_bezpieczne — brak walidacji
    // target_path vs ufs_path/script_path pozwalał błędnej konfiguracji
    // operatora fizycznie nadpisać materiał dowodowy.
    // ------------------------------------------------------------------

    #[test]
    fn test_sciezki_bezpieczne_akceptuje_rozlaczne_katalogi() {
        let ufs = tempdir().unwrap();
        let script = tempdir().unwrap();
        let target = tempdir().unwrap();
        assert!(sciezki_bezpieczne(target.path(), ufs.path(), script.path()).is_ok());
    }

    #[test]
    fn test_sciezki_bezpieczne_odrzuca_identyczna_sciezke_z_ufs() {
        let ufs = tempdir().unwrap();
        let script = tempdir().unwrap();
        assert!(sciezki_bezpieczne(ufs.path(), ufs.path(), script.path()).is_err());
    }

    #[test]
    fn test_sciezki_bezpieczne_odrzuca_identyczna_sciezke_z_script() {
        let ufs = tempdir().unwrap();
        let script = tempdir().unwrap();
        assert!(sciezki_bezpieczne(script.path(), ufs.path(), script.path()).is_err());
    }

    #[test]
    fn test_sciezki_bezpieczne_odrzuca_target_wewnatrz_ufs() {
        let ufs = tempdir().unwrap();
        let script = tempdir().unwrap();
        let target = ufs.path().join("podkatalog_docelowy");
        std::fs::create_dir_all(&target).unwrap();
        assert!(sciezki_bezpieczne(&target, ufs.path(), script.path()).is_err());
    }

    #[test]
    fn test_sciezki_bezpieczne_odrzuca_ufs_wewnatrz_target() {
        let script = tempdir().unwrap();
        let target = tempdir().unwrap();
        let ufs = target.path().join("podkatalog_zrodlowy");
        std::fs::create_dir_all(&ufs).unwrap();
        assert!(sciezki_bezpieczne(target.path(), &ufs, script.path()).is_err());
    }

    // ------------------------------------------------------------------
    // kanon() — REGRESJA (measure twice — druga weryfikacja Gemini, N1):
    // ścieżka WZGLĘDNA bez ŻADNEGO istniejącego przodka na dysku (typowy
    // pierwszy przebieg — nic pod `target_path` jeszcze nie istnieje)
    // wcześniej powodowała, że pętla ancestor-walk poddawała się i zwracała
    // SUROWĄ, nieznormalizowaną ścieżkę zamiast rozwiązać ją względem CWD.
    // ------------------------------------------------------------------

    #[test]
    fn test_kanon_wzgledna_jednoskladnikowa_bez_istniejacego_przodka_rozwiazuje_wzgledem_cwd() {
        let nazwa = "___test_kanon_jednoskladnikowa_nieistniejaca___";
        let wynik = kanon(Path::new(nazwa));
        let oczekiwane = std::env::current_dir().unwrap().join(nazwa);
        assert_eq!(wynik, oczekiwane, "ścieżka względna bez istniejącego przodka musi zostać rozwiązana względem CWD, nie zwrócona surowo");
        assert!(wynik.is_absolute(), "wynik kanon() musi być zawsze bezwzględny, żeby porównania starts_with miały sens");
    }

    #[test]
    fn test_kanon_wzgledna_wieloskladnikowa_bez_istniejacego_przodka_rozwiazuje_wzgledem_cwd() {
        let wynik = kanon(Path::new("___test_kanon_a___/___test_kanon_b___/___test_kanon_c___"));
        let oczekiwane = std::env::current_dir().unwrap()
            .join("___test_kanon_a___").join("___test_kanon_b___").join("___test_kanon_c___");
        assert_eq!(wynik, oczekiwane);
    }

    #[test]
    fn test_kanon_katalog_istniejacy_zwraca_kanoniczna_sciezke() {
        let dir = tempdir().unwrap();
        assert_eq!(kanon(dir.path()), std::fs::canonicalize(dir.path()).unwrap());
    }

    #[test]
    fn test_kanon_lisc_nieistniejacy_pod_istniejacym_rodzicem() {
        let dir = tempdir().unwrap();
        let cel = dir.path().join("jeszcze_nieutworzony_lisc");
        let oczekiwane = std::fs::canonicalize(dir.path()).unwrap().join("jeszcze_nieutworzony_lisc");
        assert_eq!(kanon(&cel), oczekiwane);
    }

    /// Dowodzi, że dwie ścieżki WZGLĘDNE bez wspólnego istniejącego przodka,
    /// ale faktycznie wskazujące w to samo miejsce (przez CWD), są teraz
    /// poprawnie rozpoznawane jako identyczne — dokładnie scenariusz z N1
    /// (`sciezki_bezpieczne` z operatorem, który wpisał ścieżki względne).
    #[test]
    fn test_kanon_dwie_wzgledne_sciezki_do_tego_samego_miejsca_sa_rowne() {
        assert_eq!(
            kanon(Path::new("___test_kanon_wspolny___")),
            kanon(Path::new("./___test_kanon_wspolny___")),
        );
    }

    // ------------------------------------------------------------------
    // sciezka_tymczasowa / obetnij_do_granicy_utf8 — REGRESJA (measure
    // twice — druga weryfikacja Gemini, todo.faza09.md N2): nazwa
    // tymczasowa nie może przekroczyć NAME_MAX dla plików o nazwie
    // źródłowej bliskiej limitowi.
    // ------------------------------------------------------------------

    #[test]
    fn test_sciezka_tymczasowa_nie_przekracza_name_max_dla_dlugiej_nazwy() {
        const NAME_MAX: usize = 255;
        // Nazwa na granicy typowego NAME_MAX systemu plików Linux.
        let dlugie_imie = "a".repeat(250);
        let docelowa = Path::new("/tmp").join(format!("{}.jpg", dlugie_imie));

        let tmp = sciezka_tymczasowa(&docelowa);
        let tmp_nazwa = tmp.file_name().and_then(|n| n.to_str()).unwrap();

        assert!(
            tmp_nazwa.len() <= NAME_MAX,
            "nazwa tymczasowa ({} bajtów) musi mieścić się w NAME_MAX={}: {:?}",
            tmp_nazwa.len(), NAME_MAX, tmp_nazwa
        );
    }

    #[test]
    fn test_sciezka_tymczasowa_krotka_nazwa_pozostaje_nietknieta() {
        let docelowa = Path::new("/tmp/plik.jpg");
        let tmp = sciezka_tymczasowa(docelowa);
        let tmp_nazwa = tmp.file_name().and_then(|n| n.to_str()).unwrap();
        assert!(tmp_nazwa.contains("plik.jpg"), "krótka nazwa nie powinna być obcinana: {:?}", tmp_nazwa);
    }

    #[test]
    fn test_sciezka_tymczasowa_dwa_wywolania_daja_rozne_nazwy() {
        let docelowa = Path::new("/tmp/plik.jpg");
        assert_ne!(sciezka_tymczasowa(docelowa), sciezka_tymczasowa(docelowa), "licznik musi zapewniać unikalność nazw tymczasowych");
    }

    #[test]
    fn test_obetnij_do_granicy_utf8_nie_tnie_w_srodku_wielobajtowego_znaku() {
        // "ó" to 2 bajty w UTF-8 - obcięcie dokładnie w środku tego znaku
        // musiałoby cofnąć się o jeden bajt, żeby zostać poprawnym UTF-8.
        let s = "zdjęcie_wakacje_nad_jeziorem_długi_tytuł_pliku";
        for limit in 0..=s.len() {
            let wynik = obetnij_do_granicy_utf8(s, limit);
            assert!(std::str::from_utf8(wynik.as_bytes()).is_ok(), "wynik musi być poprawnym UTF-8 dla limitu {}", limit);
            assert!(wynik.len() <= limit, "wynik nie może przekroczyć limitu {} (jest {})", limit, wynik.len());
        }
    }

    #[test]
    fn test_obetnij_do_granicy_utf8_krotszy_niz_limit_nie_jest_zmieniany() {
        assert_eq!(obetnij_do_granicy_utf8("krotka", 200), "krotka");
    }

    /// REGRESJA (Gemini review — druga weryfikacja): `target_path` JESZCZE
    /// NIEISTNIEJĄCY na dysku (typowy przypadek pierwszego uruchomienia) był
    /// wcześniej porównywany jako surowy string zamiast skanonikalizowanej
    /// ścieżki, więc zagnieżdżenie wewnątrz źródła przechodziło niewykryte.
    #[test]
    fn test_sciezki_bezpieczne_wykrywa_zagniezdzenie_gdy_target_jeszcze_nie_istnieje() {
        let ufs = tempdir().unwrap();
        let script = tempdir().unwrap();
        // Katalog docelowy NIE jest tworzony — tylko wyliczona ścieżka wewnątrz UFS.
        let target_nieistniejacy = ufs.path().join("jeszcze_nieutworzony_katalog_docelowy");
        assert!(!target_nieistniejacy.exists(), "test musi sprawdzać ścieżkę, która faktycznie nie istnieje");

        let wynik = sciezki_bezpieczne(&target_nieistniejacy, ufs.path(), script.path());
        assert!(wynik.is_err(), "zagnieżdżenie musi zostać wykryte nawet gdy target_path jeszcze nie istnieje na dysku");
    }

    /// Kontrola przeciwna: nieistniejący, ale FAKTYCZNIE rozłączny target_path
    /// (rodzic istnieje, sam katalog jeszcze nie) musi zostać zaakceptowany —
    /// naprawa nie może fałszywie odrzucać normalnego, poprawnego przypadku.
    #[test]
    fn test_sciezki_bezpieczne_akceptuje_rozlaczny_target_ktory_jeszcze_nie_istnieje() {
        let ufs = tempdir().unwrap();
        let script = tempdir().unwrap();
        let rodzic_targetu = tempdir().unwrap();
        let target_nieistniejacy = rodzic_targetu.path().join("nowy_katalog_docelowy");
        assert!(!target_nieistniejacy.exists());

        assert!(sciezki_bezpieczne(&target_nieistniejacy, ufs.path(), script.path()).is_ok());
    }

    #[test]
    fn test_copy_splice_reads_from_smart_splice_path_not_ufs_or_script() {
        let ufs_dir = tempdir().unwrap();
        let script_dir = tempdir().unwrap();
        let target_dir = tempdir().unwrap();
        let splice_dir = tempdir().unwrap();

        // Celowo RÓŻNA zawartość w UFS/Skrypt vs. w pliku złożonym - test
        // musi potwierdzić, że kopiowane jest złożenie, nie któraś ze stron.
        std::fs::write(ufs_dir.path().join("obraz.png"), b"UFS - uszkodzona wersja").unwrap();
        std::fs::write(script_dir.path().join("obraz.png"), b"SKRYPT - inna uszkodzona wersja").unwrap();
        let splice_path = splice_dir.path().join("obraz_smartsplice.png");
        std::fs::write(&splice_path, b"ZLOZONY - zweryfikowana wersja").unwrap();

        let candidate = MergeCandidate {
            rel_path: "obraz.png".to_string(),
            smart_splice_path: Some(splice_path.to_string_lossy().to_string()),
            ..base_candidate()
        };
        let stats = LiveStats::new(rayon::current_num_threads());

        let (success, _, _) = copy_file_and_meta(&candidate, "splice", ufs_dir.path(), script_dir.path(), target_dir.path(), &stats);

        assert!(success);
        let copied = std::fs::read(target_dir.path().join("obraz.png")).unwrap();
        assert_eq!(copied, b"ZLOZONY - zweryfikowana wersja", "Powinno skopiować złożenie, nie żadną ze stron źródłowych");
    }

    #[test]
    fn test_copy_missing_source_is_io_error() {
        let ufs_dir = tempdir().unwrap();
        let script_dir = tempdir().unwrap();
        let target_dir = tempdir().unwrap();
        // Celowo NIE tworzymy pliku źródłowego

        let candidate = MergeCandidate { rel_path: "nieistniejacy.txt".to_string(), ..base_candidate() };
        let stats = LiveStats::new(rayon::current_num_threads());

        let (success, _, _) = copy_file_and_meta(&candidate, "ufs", ufs_dir.path(), script_dir.path(), target_dir.path(), &stats);

        assert!(!success);
        assert_eq!(stats.io_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_copy_symlink_recreation() {
        let ufs_dir = tempdir().unwrap();
        let script_dir = tempdir().unwrap();
        let target_dir = tempdir().unwrap();

        std::fs::write(ufs_dir.path().join("cel.txt"), b"dane").unwrap();
        std::os::unix::fs::symlink("cel.txt", ufs_dir.path().join("link.txt")).unwrap();

        let candidate = MergeCandidate {
            rel_path: "link.txt".to_string(),
            is_symlink_ufs: Some(true),
            ..base_candidate()
        };
        let stats = LiveStats::new(rayon::current_num_threads());

        let (success, _, _) = copy_file_and_meta(&candidate, "ufs", ufs_dir.path(), script_dir.path(), target_dir.path(), &stats);

        assert!(success);
        assert_eq!(stats.symlinks_recreated.load(Ordering::Relaxed), 1);
        assert!(target_dir.path().join("link.txt").symlink_metadata().unwrap().file_type().is_symlink());
    }

    // ------------------------------------------------------------------
    // build_summary_block
    // ------------------------------------------------------------------

    #[test]
    fn test_build_summary_block_reports_counts() {
        let stats = LiveStats::new(rayon::current_num_threads());
        stats.copied_ufs_common.store(3, Ordering::Relaxed);
        stats.copied_script_common.store(7, Ordering::Relaxed);
        stats.copied_ufs_unique.store(2, Ordering::Relaxed);
        stats.io_errors.store(1, Ordering::Relaxed);

        let start_time = Instant::now();
        let block = build_summary_block(&stats, start_time);

        assert!(block.contains("Wspólne — UFS: 3 | Skrypt: 7"));
        assert!(block.contains("Unikalne skopiowane: 2"));
        assert!(block.contains("Błędy I/O: 1"));
    }

    #[test]
    fn test_build_summary_block_placeholder_when_no_reasons() {
        let stats = LiveStats::new(rayon::current_num_threads());
        let block = build_summary_block(&stats, Instant::now());
        assert!(block.contains("Top powody decyzji: -"));
    }

    // ------------------------------------------------------------------
    // sciezka_naprawiona — dwa formaty `repaired_path_*`
    //
    // Faza 17 zapisuje naprawy w przestrzeni roboczej pod `target_path` i
    // trzyma w bazie ścieżkę ABSOLUTNĄ. Bazy zapisane wcześniej mają tam
    // ścieżkę WZGLĘDNĄ wobec bazy źródłowej (naprawa leżała obok oryginału).
    // Oba formaty muszą się rozwiązywać poprawnie, inaczej Faza 9 cicho
    // skopiowałaby uszkodzony oryginał zamiast naprawy.
    // ------------------------------------------------------------------

    #[test]
    fn test_sciezka_naprawiona_absolutna_jest_uzywana_wprost() {
        let baza = Path::new("/mnt/zrodlo");
        let zapisana = "/praca/zlota_kopia/_phase17_repaired/ufs/foto/a_repaired.jpg";

        let wynik = sciezka_naprawiona(zapisana, baza);

        assert_eq!(wynik, PathBuf::from(zapisana));
        assert!(!wynik.starts_with(baza), "Ścieżka absolutna nie może zostać doklejona do bazy źródłowej");
    }

    #[test]
    fn test_sciezka_naprawiona_wzgledna_jest_doklejana_do_bazy_zgodnosc_wstecz() {
        let baza = Path::new("/mnt/zrodlo");

        let wynik = sciezka_naprawiona("foto/a_repaired.jpg", baza);

        assert_eq!(wynik, baza.join("foto/a_repaired.jpg"));
    }

    #[test]
    fn test_sciezka_naprawiona_czyta_realny_plik_z_przestrzeni_roboczej() {
        // Test end-to-end na prawdziwych plikach: naprawa leży w KATALOGU
        // INNYM niż baza źródłowa, a mimo to musi zostać odnaleziona.
        let zrodlo = tempdir().unwrap();
        let przestrzen = tempdir().unwrap();

        let naprawiony = przestrzen.path().join("a_repaired.txt");
        std::fs::write(&naprawiony, b"tresc naprawiona").unwrap();

        let rozwiazana = sciezka_naprawiona(naprawiony.to_str().unwrap(), zrodlo.path());

        assert_eq!(std::fs::read(&rozwiazana).unwrap(), b"tresc naprawiona");
    }

    // ------------------------------------------------------------------
    // merge_source_path — ślad rewizyjny „skąd wzięły się te bajty"
    // ------------------------------------------------------------------

    #[test]
    fn test_prog_commitu_jest_zgodny_z_faza3() {
        // Jeden wzorzec trwałości w całym projekcie — patrz commit hybrydowy
        // w Fazie 3. Rozjazd wartości byłby niespójnością, nie optymalizacją.
        assert_eq!(PROG_COMMITU, 5_000);
    }

    #[test]
    fn test_zwraca_sciezke_zrodlowa_oryginalu_z_korpusu() {
        let ufs_dir = tempdir().unwrap();
        let script_dir = tempdir().unwrap();
        let target_dir = tempdir().unwrap();

        std::fs::write(ufs_dir.path().join("plik.txt"), b"tresc").unwrap();
        // `size_ufs` MUSI odpowiadać realnemu rozmiarowi — Faza 9 weryfikuje
        // rozmiar po skopiowaniu (pomija to tylko dla wersji naprawionych).
        let candidate = MergeCandidate { rel_path: "plik.txt".to_string(), size_ufs: Some(5), ..base_candidate() };
        let stats = LiveStats::new(rayon::current_num_threads());

        let (success, _, zrodlo) = copy_file_and_meta(&candidate, "ufs", ufs_dir.path(), script_dir.path(), target_dir.path(), &stats);

        assert!(success);
        assert_eq!(zrodlo, ufs_dir.path().join("plik.txt").to_string_lossy());
    }

    #[test]
    fn test_zwraca_sciezke_zrodlowa_naprawy_z_fazy17() {
        // Sedno poprawki: `merge_source` mówiłby tylko "ufs", co NIE
        // rozstrzyga, czy skopiowano oryginał, czy naprawę z przestrzeni
        // roboczej. `merge_source_path` rozstrzyga.
        let ufs_dir = tempdir().unwrap();
        let script_dir = tempdir().unwrap();
        let target_dir = tempdir().unwrap();
        let przestrzen = tempdir().unwrap();

        std::fs::write(ufs_dir.path().join("obraz.png"), b"ORYGINAL uszkodzony").unwrap();
        let naprawiony = przestrzen.path().join("_phase17_repaired/ufs/obraz_repaired.png");
        std::fs::create_dir_all(naprawiony.parent().unwrap()).unwrap();
        std::fs::write(&naprawiony, b"NAPRAWIONY").unwrap();

        let candidate = MergeCandidate {
            rel_path: "obraz.png".to_string(),
            repaired_path_ufs: Some(naprawiony.to_string_lossy().to_string()),
            ..base_candidate()
        };
        let stats = LiveStats::new(rayon::current_num_threads());

        let (success, _, zrodlo) = copy_file_and_meta(&candidate, "ufs", ufs_dir.path(), script_dir.path(), target_dir.path(), &stats);

        assert!(success);
        assert_eq!(zrodlo, naprawiony.to_string_lossy(), "Ścieżka źródłowa musi wskazywać naprawę, nie oryginał");
        assert!(zrodlo.contains("_phase17_repaired"), "Po tej ścieżce diagnostyka rozpoznaje pochodzenie bajtów");
        assert_eq!(std::fs::read(target_dir.path().join("obraz.png")).unwrap(), b"NAPRAWIONY");
    }

    #[test]
    fn test_zwraca_sciezke_zrodlowa_zlozenia_z_fazy18() {
        let ufs_dir = tempdir().unwrap();
        let script_dir = tempdir().unwrap();
        let target_dir = tempdir().unwrap();
        let splice_dir = tempdir().unwrap();

        std::fs::write(ufs_dir.path().join("obraz.png"), b"UFS").unwrap();
        std::fs::write(script_dir.path().join("obraz.png"), b"SKRYPT").unwrap();
        let splice_path = splice_dir.path().join("_smart_splice_repaired/obraz_smartsplice.png");
        std::fs::create_dir_all(splice_path.parent().unwrap()).unwrap();
        std::fs::write(&splice_path, b"ZLOZONY").unwrap();

        let candidate = MergeCandidate {
            rel_path: "obraz.png".to_string(),
            smart_splice_path: Some(splice_path.to_string_lossy().to_string()),
            ..base_candidate()
        };
        let stats = LiveStats::new(rayon::current_num_threads());

        let (success, _, zrodlo) = copy_file_and_meta(&candidate, "splice", ufs_dir.path(), script_dir.path(), target_dir.path(), &stats);

        assert!(success);
        assert!(zrodlo.contains("_smart_splice_repaired"), "dostałem: {}", zrodlo);
    }

    #[test]
    fn test_sciezka_zrodlowa_jest_zwracana_takze_przy_bledzie_kopiowania() {
        // Przy błędzie I/O ślad rewizyjny jest szczególnie potrzebny — mówi,
        // CZEGO nie udało się odczytać.
        let ufs_dir = tempdir().unwrap();
        let script_dir = tempdir().unwrap();
        let target_dir = tempdir().unwrap();

        // Plik źródłowy celowo NIE istnieje.
        let candidate = MergeCandidate { rel_path: "nie_ma.txt".to_string(), ..base_candidate() };
        let stats = LiveStats::new(rayon::current_num_threads());

        let (success, _, zrodlo) = copy_file_and_meta(&candidate, "ufs", ufs_dir.path(), script_dir.path(), target_dir.path(), &stats);

        assert!(!success, "Kopiowanie nieistniejącego pliku musi się nie udać");
        assert_eq!(zrodlo, ufs_dir.path().join("nie_ma.txt").to_string_lossy());
    }

    // ------------------------------------------------------------------
    // STRONICOWANIE (wczytaj_strone) — ograniczenie zużycia pamięci
    // ------------------------------------------------------------------

    fn baza_z_plikami(ile: usize) -> Connection {
        let conn = crate::db::init_db(":memory:").unwrap();
        for i in 1..=ile {
            conn.execute(
                "INSERT INTO files (relative_path, found_in_ufs, found_in_script, size_ufs) VALUES (?1, 1, 0, 10)",
                params![format!("plik{:03}.dat", i)],
            ).unwrap();
        }
        conn
    }

    #[test]
    fn test_wczytaj_strone_respektuje_limit_i_kolejnosc() {
        let conn = baza_z_plikami(7);

        let strona = wczytaj_strone(&conn, 0, 3).unwrap();

        assert_eq!(strona.len(), 3, "Strona nie może przekroczyć limitu");
        let identyfikatory: Vec<i32> = strona.iter().map(|k| k.id).collect();
        assert_eq!(identyfikatory, vec![1, 2, 3], "Rekordy muszą iść po rosnącym id");
    }

    #[test]
    fn test_wczytaj_strone_pomija_juz_scalone() {
        let conn = baza_z_plikami(5);
        conn.execute("UPDATE files SET phase9_done = 1 WHERE id IN (1, 2)", []).unwrap();

        let strona = wczytaj_strone(&conn, 0, 10).unwrap();

        let identyfikatory: Vec<i32> = strona.iter().map(|k| k.id).collect();
        assert_eq!(identyfikatory, vec![3, 4, 5], "Scalone rekordy nie mogą wrócić");
    }

    /// NAJWAŻNIEJSZY test stronicowania: w trakcie pracy Faza 9 oznacza
    /// przetworzone rekordy, więc zbiór pasujący do filtra KURCZY SIĘ.
    /// Przy `LIMIT/OFFSET` kolejne strony przeskakiwałyby rekordy. Warunek
    /// `id > po_id` musi dać komplet bez luk i bez powtórzeń.
    #[test]
    fn test_stronicowanie_kluczem_nie_przeskakuje_rekordow() {
        let conn = baza_z_plikami(10);

        let mut zebrane: Vec<i32> = Vec::new();
        let mut ostatni_id = 0;

        loop {
            let strona = wczytaj_strone(&conn, ostatni_id, 3).unwrap();
            if strona.is_empty() { break; }
            ostatni_id = strona[strona.len() - 1].id;

            let ids: Vec<i32> = strona.iter().map(|k| k.id).collect();
            // Symulujemy to, co robi wątek zapisu: oznaczamy stronę jako scaloną.
            for id in &ids {
                conn.execute("UPDATE files SET phase9_done = 1 WHERE id = ?1", params![id]).unwrap();
            }
            zebrane.extend(ids);
        }

        assert_eq!(zebrane, (1..=10).collect::<Vec<i32>>(), "Każdy rekord musi zostać zwrócony DOKŁADNIE raz");
    }

    #[test]
    fn test_wczytaj_strone_konczy_sie_na_pustej_stronie() {
        let conn = baza_z_plikami(2);
        assert!(wczytaj_strone(&conn, 2, 10).unwrap().is_empty(), "Za ostatnim id nie ma już nic");
    }

    /// Nawet gdy rekord NIE zostanie oznaczony (np. anulowanie w trakcie
    /// paczki), stronicowanie kluczem posuwa się dalej — przy przepytywaniu
    /// „daj nieprzetworzone" dałoby to pętlę nieskończoną.
    #[test]
    fn test_stronicowanie_posuwa_sie_takze_gdy_rekord_nie_zostal_oznaczony() {
        let conn = baza_z_plikami(4);

        let pierwsza = wczytaj_strone(&conn, 0, 2).unwrap();
        let ostatni_id = pierwsza[pierwsza.len() - 1].id;
        // Celowo NIC nie oznaczamy.
        let druga = wczytaj_strone(&conn, ostatni_id, 2).unwrap();

        let ids: Vec<i32> = druga.iter().map(|k| k.id).collect();
        assert_eq!(ids, vec![3, 4], "Druga strona musi ruszyć dalej, nie powtórzyć pierwszej");
    }

    #[test]
    fn test_kolumny_kandydata_zgadzaja_sie_z_mapowaniem() {
        // Liczba kolumn w `SELECT` musi odpowiadać najwyższemu indeksowi
        // używanemu w `zmapuj_kandydata` (39) + 1.
        let liczba = KOLUMNY_KANDYDATA.split(',').count();
        assert_eq!(liczba, 40, "Rozjazd listy kolumn z mapowaniem pozycyjnym");

        // I musi dać się wykonać na realnym schemacie.
        let conn = baza_z_plikami(1);
        let strona = wczytaj_strone(&conn, 0, 1).unwrap();
        assert_eq!(strona.len(), 1);
        assert_eq!(strona[0].rel_path, "plik001.dat");
    }

    #[test]
    fn test_rozmiar_strony_jest_sensowny() {
        // Za mało = nadmiar zapytań i transakcji; za dużo = wraca problem z
        // pamięcią, który ta zmiana usuwa.
        const { assert!(ROZMIAR_STRONY >= 1_000 && ROZMIAR_STRONY <= 100_000) };
    }

    // ------------------------------------------------------------------
    // TEST INTEGRACYJNY: pełny przebieg `run` przez pętlę stron
    // ------------------------------------------------------------------

    use crate::settings::Ustawienia;

    /// Konfiguracja wskazująca WYŁĄCZNIE na katalogi tymczasowe.
    ///
    /// `raporty_faz` czyszczone celowo — domyślnie kieruje raporty do
    /// `./dziennik/fazy`, czyli do katalogu PROJEKTU.
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
    fn test_przebieg_kopiuje_wszystko_i_konczy_petle_stron() {
        let ufs = tempdir().unwrap();
        let script = tempdir().unwrap();
        let target = tempdir().unwrap();
        let logi = tempdir().unwrap();

        let tresc: &[u8] = b"zawartosc pliku";
        std::fs::create_dir_all(ufs.path().join("dane")).unwrap();
        for i in 1..=5 {
            std::fs::write(ufs.path().join(format!("dane/plik{}.dat", i)), tresc).unwrap();
        }

        let mut conn = crate::db::init_db(":memory:").unwrap();
        for i in 1..=5 {
            conn.execute(
                "INSERT INTO files (relative_path, found_in_ufs, found_in_script, size_ufs)
                 VALUES (?1, 1, 0, ?2)",
                params![format!("dane/plik{}.dat", i), tresc.len() as i64],
            ).unwrap();
        }

        let config = konfiguracja_testowa(ufs.path(), script.path(), target.path(), logi.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        CANCEL_SIGNAL.store(false, Ordering::SeqCst);
        run(&mut conn, &config, tx_ui).expect("Faza 9 powinna zakończyć się bez błędu");

        // 1. Pętla stron ZAKOŃCZYŁA SIĘ i objęła wszystkie rekordy.
        let niescalone: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM files WHERE {}", WARUNEK_NIESCALONE), [], |r| r.get(0)).unwrap();
        assert_eq!(niescalone, 0, "Po przebiegu nie może zostać ani jeden nieprzetworzony rekord");

        // 2. Pliki fizycznie w Złotej Kopii.
        for i in 1..=5 {
            let docelowy = target.path().join(format!("dane/plik{}.dat", i));
            assert!(docelowy.exists(), "brak pliku w Złotej Kopii: {}", docelowy.display());
            assert_eq!(std::fs::read(&docelowy).unwrap(), tresc);
        }

        // 3. Ślad rewizyjny: strona zwycięska i ścieżka źródłowa zapisane.
        let (zrodlo, sciezka_zrodlowa): (String, String) = conn.query_row(
            "SELECT merge_source, merge_source_path FROM files WHERE relative_path = 'dane/plik1.dat'",
            [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(zrodlo, "ufs", "Plik unikalny dla UFS musi mieć UFS jako źródło");
        assert!(sciezka_zrodlowa.starts_with(&ufs.path().to_string_lossy().to_string()),
            "merge_source_path musi wskazywać realne źródło: {}", sciezka_zrodlowa);
    }

    #[test]
    fn test_przebieg_na_bazie_bez_kandydatow_konczy_sie_od_razu() {
        let ufs = tempdir().unwrap();
        let script = tempdir().unwrap();
        let target = tempdir().unwrap();
        let logi = tempdir().unwrap();

        let mut conn = crate::db::init_db(":memory:").unwrap();
        conn.execute("INSERT INTO files (relative_path, phase9_done) VALUES ('gotowe.dat', 1)", []).unwrap();

        let config = konfiguracja_testowa(ufs.path(), script.path(), target.path(), logi.path());
        let (tx_ui, _rx_ui) = mpsc::channel();

        CANCEL_SIGNAL.store(false, Ordering::SeqCst);
        run(&mut conn, &config, tx_ui).expect("brak kandydatów to nie błąd");
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
            .find(|l| l.starts_with("Wątki kopiowania"))
            .unwrap_or_else(|| panic!("brak linii Wariantu A w bloku:\n{}", block));

        assert_eq!(line, "Wątki kopiowania (Wariant A): {R:1} {G:2}");
    }

}
