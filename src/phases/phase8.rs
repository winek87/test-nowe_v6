// src/phases/phase8.rs

//! # Faza 8: Generowanie Raportu i Decyzji Kryminalistycznych (CSV)
//!
//! Ostateczna synteza zebranych danych. Silnik Heurystyczny ocenia każdy plik,
//! uwzględniając akcje wykonane przez Moduł Naprawczy (Faza 17). Wyniki są 
//! strumieniowo zapisywane do potężnego pliku Euro-CSV (z UTF-8 BOM).
//! Wspiera logowanie przez PhaseEvent do interfejsu Ratatui.
//!
//! UWAGA ARCHITEKTONICZNA: w przeciwieństwie do Faz 1-7, ta faza NIE dzieli
//! pracy na UFS/Skrypt — każdy rekord w tabeli `files` już zawiera dane z OBU
//! stron naraz, więc przetwarzanie jest jednym, sekwencyjnym przebiegiem po
//! całej tabeli (bez `std::thread::scope`, bez `half_threads` — nie ma tu
//! dwóch stron do zrównoleglenia). Pasek postępu pokazuje wyłącznie % i
//! bieżącą ścieżkę; liczniki na żywo (Zdrowe/Odrzucone/Naprawione/Wirusy oraz
//! top powody odrzuceń/podejrzeń) trafiają do panelu bocznego — patrz
//! [`build_summary_block`] — dla spójności z Fazami 1-7, choć poprzednia
//! wersja (jednoliniowy komunikat w `UpdateBar.message`) nie była zepsuta,
//! tylko niespójna stylistycznie.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::{format_display_path, CANCEL_SIGNAL};
use ratatui::style::Color;
use rusqlite::{Connection, Result as SqlResult};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Instant;
use tracing::{info, instrument, warn};

// ============================================================================
// STRUKTURY DANYCH I MODELE
// ============================================================================

/// Pełny zestaw danych forensycznych dla jednego pliku, zebrany przez Fazy 1-7
/// i (opcjonalnie) 17, wczytany z jednego wiersza tabeli `files`. Wejście do
/// [`evaluate_file`] — każde pole odpowiada kolumnie SQL o tej samej nazwie
/// z sufiksem `_ufs`/`_script` tam, gdzie dana cecha jest mierzona osobno
/// dla każdej strony.
#[derive(Debug, Clone)]
pub struct FileRecord {
    pub relative_path: String,
    pub found_in_ufs: bool,
    pub found_in_script: bool,
    pub size_ufs: Option<i64>,
    pub size_script: Option<i64>,
    pub size_match: Option<bool>,
    pub hash_ufs: Option<String>,
    pub hash_script: Option<String>,
    pub hash_match: Option<bool>,
    /// Procent podobieństwa rozmytego (CTPH/ssdeep, Faza 14) między wersjami
    /// UFS i Skrypt — używane tylko gdy `hash_match == Some(false)`, żeby
    /// odróżnić "pliki niemal identyczne" od "zupełnie różnej zawartości".
    pub fuzzy_match_pct: Option<f64>,
    pub zeros_pct_ufs: Option<f64>,
    pub zeros_pct_script: Option<f64>,
    pub eof_ok_ufs: Option<bool>,
    pub eof_ok_script: Option<bool>,
    pub entropy_ufs: Option<f64>,
    pub entropy_script: Option<f64>,
    pub utf8_ok_ufs: Option<bool>,
    pub utf8_ok_script: Option<bool>,
    pub structure_ok_ufs: Option<bool>,
    pub structure_ok_script: Option<bool>,
    pub exif_ok_ufs: Option<bool>,
    pub exif_ok_script: Option<bool>,
    pub media_decoded_ufs: Option<bool>,
    pub media_decoded_script: Option<bool>,
    pub has_xattr_ufs: Option<bool>,
    pub has_xattr_script: Option<bool>,
    pub io_error_ufs: Option<bool>,
    pub io_error_script: Option<bool>,
    pub yara_match_ufs: Option<String>,
    pub yara_match_script: Option<String>,
    /// `Some(ścieżka)` gdy Faza 17 fizycznie zrekonstruowała ten plik po tej
    /// stronie — ma priorytet nad wszystkimi innymi anomaliami poza YARA.
    pub repaired_path_ufs: Option<String>,
    pub repaired_path_script: Option<String>,
    pub repair_log_ufs: Option<String>,
    pub repair_log_script: Option<String>,
}

/// Wynik oceny jednego pliku przez [`evaluate_file`]: status kategoryczny
/// (używany też do zliczania statystyk w [`run`] przez dopasowanie podłańcucha,
/// np. `"USZKODZONY"`), rekomendacja czytelna dla człowieka, oraz nazwa
/// reguły YARA (jeśli dotyczy, inaczej `"Brak"`).
#[derive(Debug, PartialEq)]
pub struct Evaluation {
    pub status: String,
    pub recommendation: String,
    pub yara_rule: String,
}

// ============================================================================
// SILNIK DECYZYJNY (HEURYSTYKA Z UWZGLĘDNIENIEM REKONSTRUKCJI)
// ============================================================================

/// Główny silnik decyzyjny narzędzia — jedna, czysta funkcja bez efektów
/// ubocznych, testowana wprost na sztucznie skonstruowanych rekordach.
/// Sprawdzenia wykonywane są w ŚCIŚLE OKREŚLONEJ KOLEJNOŚCI PRIORYTETU
/// (pierwsze trafienie wygrywa, `return` przerywa dalszą ocenę):
///
/// 0. **YARA (malware)** — priorytet absolutny, wygrywa nawet nad błędem I/O
///    czy rekonstrukcją. Plik z dopasowaniem YARA jest zawsze KWARANTANNĄ.
/// 1. **Naprawiony przez Fazę 17** — priorytet nad wszystkimi anomaliami
///    poniżej (ale NIE nad YARA — zrekonstruowany plik nadal może zawierać
///    złośliwy kod).
/// 2. **Błąd I/O na OBU stronach jednocześnie** — plik fizycznie
///    nieodczytywalny (uszkodzone sektory), odrzucany bezwarunkowo.
/// 3. **Wydmuszka** — >99% zer po którejkolwiek stronie.
/// 4. **Nieudany dekoding obrazu/wideo** (Gray Banding, Faza 13).
/// 5. **Zły UTF-8** dla plików tekstowych (Faza 10).
/// 6. **Zła struktura kontenera** (ZIP/DOCX/APK bez EOCD, Faza 11).
/// 7. **Zły EXIF** (Faza 12).
/// 8. **Brak znacznika EOF** (Faza 6).
/// 9. **Entropia skrajna** (Faza 7): `>7.995` = biały szum, `0.0 < H < 1.0` =
///    nienaturalnie pusta pamięć — oba przypadki to OSTRZEŻENIE, nie odrzucenie.
/// 10. **Finalne porównanie wersji** (dopiero gdy WSZYSTKIE powyższe testy
///     przeszły czysto): zgodny hash → ZGODNY; różny hash z danymi fuzzy →
///     stopniowana ocena podobieństwa (≥90% / >0% / =0% "Frankenstein" — plik
///     złożony z fragmentów różnych oryginałów); różny rozmiar → zachować
///     większy; plik obecny tylko po jednej stronie → skopiować unikalny;
///     plik nieobecny po żadnej stronie → BŁĄD KRYTYCZNY (widmo, nie powinno
///     wystąpić przy poprawnym przebiegu Faz 1-2).
pub fn evaluate_file(record: &FileRecord) -> Evaluation {
    // 0. PRIORYTET ABSOLUTNY: Złośliwe oprogramowanie (YARA)
    let yara_u = record.yara_match_ufs.clone();
    let yara_s = record.yara_match_script.clone();
    if yara_u.is_some() || yara_s.is_some() {
        let rule = yara_u.or(yara_s).unwrap_or_else(|| "Nieznana Reguła".to_string());
        return Evaluation {
            status: "ZAINFEKOWANY (MALWARE)".to_string(),
            recommendation: "KWARANTANNA - Plik zawiera złośliwy kod lub notatkę hakerską!".to_string(),
            yara_rule: rule,
        };
    }

    // PRIORYTET NAPRAWCZY: Plik odratowany przez Fazę 17
    if record.repaired_path_ufs.is_some() || record.repaired_path_script.is_some() {
        let action = record.repair_log_ufs.as_deref().or(record.repair_log_script.as_deref()).unwrap_or("Zrekonstruowano plik");
        return Evaluation {
            status: "ZREKONSTRUOWANY (NAPRAWIONY)".to_string(),
            recommendation: format!("Użyć wersji zrekonstruowanej (.repaired) - {}", action),
            yara_rule: "Brak".to_string(),
        };
    }

    // 1. Błędy fizyczne I/O (Bad Sectory)
    if record.io_error_ufs == Some(true) && record.io_error_script == Some(true) {
        return Evaluation { status: "BŁĄD ODCZYTU (I/O)".to_string(), recommendation: "Odrzucić - Plik widmo. Fizyczne uszkodzenie sektorów.".to_string(), yara_rule: "Brak".to_string() };
    }

    // 2. Wydmuszki (Zera / FF po TRIM)
    let zeros_u = record.zeros_pct_ufs.unwrap_or(0.0);
    let zeros_s = record.zeros_pct_script.unwrap_or(0.0);
    if zeros_u > 99.0 || zeros_s > 99.0 {
        return Evaluation { status: "USZKODZONY (WYDMUSZKA)".to_string(), recommendation: "Odrzucić - plik wypełniony w >99% pustymi blokami".to_string(), yara_rule: "Brak".to_string() };
    }

    // 3. Walidacja wizualna (Gray Banding / Przepełnienie)
    if record.media_decoded_ufs == Some(false) || record.media_decoded_script == Some(false) {
        return Evaluation { status: "USZKODZONY (UCIĘTY OBRAZ)".to_string(), recommendation: "Odrzucić - niedekodowalny obraz / wideo (Gray Banding)".to_string(), yara_rule: "Brak".to_string() };
    }

    // 4. Walidacja kodowania znaków (UTF-8 / Zupa Binarna)
    if record.utf8_ok_ufs == Some(false) || record.utf8_ok_script == Some(false) {
        return Evaluation { status: "USZKODZONY (BINARNY ŚMIEĆ)".to_string(), recommendation: "Odrzucić - plik rzekomo tekstowy zawiera niedozwolone znaki binarne".to_string(), yara_rule: "Brak".to_string() };
    }

    // 5. Walidacja struktury kontenerów (ZIP/DOCX/APK)
    if record.structure_ok_ufs == Some(false) || record.structure_ok_script == Some(false) {
        return Evaluation { status: "USZKODZONY (ZŁA STRUKTURA)".to_string(), recommendation: "Odrzucić - dokument/archiwum nie posiada kluczowej tablicy EOCD".to_string(), yara_rule: "Brak".to_string() };
    }

    // 6. Walidacja EXIF
    if record.exif_ok_ufs == Some(false) || record.exif_ok_script == Some(false) {
        return Evaluation { status: "USZKODZONY (BŁĘDNY EXIF)".to_string(), recommendation: "Odrzucić - zdjęcie/wideo posiada zepsutą strukturę EXIF".to_string(), yara_rule: "Brak".to_string() };
    }

    // 7. Sygnatury EOF
    if record.eof_ok_ufs == Some(false) || record.eof_ok_script == Some(false) {
        return Evaluation { status: "USZKODZONY (BRAK EOF)".to_string(), recommendation: "Sprawdzić ręcznie - marker końca pliku zaginął. Ucięcie.".to_string(), yara_rule: "Brak".to_string() };
    }

    // 8. Entropia Shannona
    let ent_u = record.entropy_ufs.unwrap_or(4.0);
    let ent_s = record.entropy_script.unwrap_or(4.0);
    if ent_u > 7.995 || ent_s > 7.995 { return Evaluation { status: "PODEJRZANY (WYSOKA ENTROPIA)".to_string(), recommendation: "Ostrzeżenie - skrajny stopień chaosu (Biały Szum)".to_string(), yara_rule: "Brak".to_string() }; }
    if (ent_u < 1.0 && ent_u > 0.0) || (ent_s < 1.0 && ent_s > 0.0) { return Evaluation { status: "PODEJRZANY (NISKA ENTROPIA)".to_string(), recommendation: "Ostrzeżenie - nienaturalnie niska złożoność (Pusta Pamięć)".to_string(), yara_rule: "Brak".to_string() }; }

    // 9. Ostateczne porównanie wersji
    if record.found_in_ufs && record.found_in_script {
        match (record.size_match, record.hash_match) {
            (Some(true), Some(true)) => Evaluation { status: "ZGODNY".to_string(), recommendation: "Zachować - obydwa programy odzyskały w 100% identyczny plik".to_string(), yara_rule: "Brak".to_string() },
            (Some(true), Some(false)) => {
                if let Some(pct) = record.fuzzy_match_pct {
                    if pct >= 90.0 { Evaluation { status: format!("RÓŻNY HASH (PODOBNE W {:.0}%)", pct), recommendation: "Zachować. Ostrzeżenie: Pliki bardzo podobne".to_string(), yara_rule: "Brak".to_string() } }
                    else if pct > 0.0 { Evaluation { status: format!("RÓŻNY HASH (PODOBNE W {:.0}%)", pct), recommendation: "Ostrzeżenie - Pliki mają tylko część wspólną".to_string(), yara_rule: "Brak".to_string() } }
                    else { Evaluation { status: "RÓŻNY HASH (FRANKENSTEIN)".to_string(), recommendation: "Krytyczne Ostrzeżenie - Zlepek MFT.".to_string(), yara_rule: "Brak".to_string() } }
                } else {
                    Evaluation { status: "RÓŻNY HASH".to_string(), recommendation: "Różne kryptograficznie pliki o tej samej wielkości".to_string(), yara_rule: "Brak".to_string() }
                }
            },
            (Some(false), _) => Evaluation { status: "RÓŻNY ROZMIAR".to_string(), recommendation: "Zachować większy plik. Mniejszy plik został ucięty.".to_string(), yara_rule: "Brak".to_string() },
            _ => Evaluation { status: "BRAK DANYCH".to_string(), recommendation: "Brak wystarczających wskaźników".to_string(), yara_rule: "Brak".to_string() },
        }
    } else if record.found_in_ufs { Evaluation { status: "TYLKO UFS".to_string(), recommendation: "Skopiować z UFS Explorer - Plik unikalny".to_string(), yara_rule: "Brak".to_string() } } 
      else if record.found_in_script { Evaluation { status: "TYLKO SKRYPT".to_string(), recommendation: "Skopiować ze Skryptu Autorskiego - Plik unikalny".to_string(), yara_rule: "Brak".to_string() } } 
      else { Evaluation { status: "BŁĄD KRYTYCZNY".to_string(), recommendation: "Plik widmo (Ghost) - brak dostępu fizycznego".to_string(), yara_rule: "Brak".to_string() } }
}

// ============================================================================
// NARZĘDZIA EKSPORTOWE (EURO-CSV Z BOM)
// ============================================================================

/// Ucieka wartość do formatu Euro-CSV (separator `;`): jeśli tekst zawiera
/// średnik, cudzysłów lub nową linię, otacza go cudzysłowami i podwaja
/// wewnętrzne cudzysłowy (standard RFC 4180). W przeciwnym razie zwraca
/// tekst bez zmian — nie każda wartość wymaga otoczenia.
fn escape_csv(val: &str) -> String { if val.contains(';') || val.contains('"') || val.contains('\n') { format!("\"{}\"", val.replace('"', "\"\"")) } else { val.to_string() } }
/// `Some(true)` → "Tak", `Some(false)` → "Nie", `None` → "Brak" (kolumna nie dotyczy/nie zbadano).
fn fmt_opt_bool(o: Option<bool>) -> String { o.map(|b| if b { "Tak" } else { "Nie" }).unwrap_or("Brak").to_string() }
/// Formatuje z 2 miejscami po przecinku, z przecinkiem dziesiętnym (konwencja
/// Euro-CSV/Excel PL) zamiast kropki. `None` → "Brak".
fn fmt_opt_f64(o: Option<f64>) -> String { o.map(|f| format!("{:.2}", f).replace('.', ",")).unwrap_or_else(|| "Brak".to_string()) }
/// `None` → "Brak", w przeciwnym razie liczba jako tekst.
fn fmt_opt_i64(o: Option<i64>) -> String { o.map(|i| i.to_string()).unwrap_or_else(|| "Brak".to_string()) }
/// `None` → "Brak", w przeciwnym razie tekst bez zmian (ucieczka CSV robiona osobno przez [`escape_csv`]).
fn fmt_opt_str(o: Option<String>) -> String { o.unwrap_or_else(|| "Brak".to_string()) }

// ============================================================================
// GŁÓWNA FUNKCJA (Entrypoint)
// ============================================================================

/// Buduje panel boczny "Podsumowanie na żywo": cztery liczniki kategorii
/// (Zdrowe/Odrzucone/Naprawione/Wirusy) oraz do 3 najczęstszych powodów
/// odrzucenia i do 3 najczęstszych powodów podejrzenia, posortowane malejąco
/// po liczności. W przeciwieństwie do Faz 1-7 nie ma tu podziału per-źródło —
/// jeden, wspólny panel dla całego przebiegu (patrz dokumentacja modułu).
fn build_summary_block(
    ok_count: usize,
    to_reject_count: usize,
    repaired_count: usize,
    infected_count: usize,
    reject_reasons: &HashMap<String, usize>,
    suspect_reasons: &HashMap<String, usize>,
) -> String {
    let top_reasons = |map: &HashMap<String, usize>| -> String {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        let s = sorted.into_iter().take(3)
            .map(|(reason, count)| format!("{} ({})", reason, count))
            .collect::<Vec<_>>().join(", ");
        if s.is_empty() { "-".to_string() } else { s }
    };

    format!(
        "[Podsumowanie]\nZdrowe: {}\nOdrzucone: {}\nNaprawione: {}\nWirusy: {}\nTop powody odrzuceń: {}\nTop powody podejrzeń: {}",
        ok_count, to_reject_count, repaired_count, infected_count,
        top_reasons(reject_reasons), top_reasons(suspect_reasons),
    )
}

/// Punkt wejścia Fazy 8, wołany przez `menu::actions::run_phase_with_ui`.
///
/// Przebieg: (1) liczy wszystkie rekordy w `files`; (2) otwiera plik CSV
/// docelowy (`config.csv_report_path`) z UTF-8 BOM i nagłówkiem Euro-CSV;
/// (3) sekwencyjnie iteruje CAŁĄ tabelę (jeden przebieg, bez podziału
/// UFS/Skrypt — patrz dokumentacja modułu), dla każdego rekordu woła
/// [`evaluate_file`], zapisuje wiersz CSV i aktualizuje liczniki kategorii;
/// (4) po zakończeniu zapisuje Dziennik Końcowy z pełnym rozkładem powodów
/// odrzuceń/podejrzeń do pliku i do UI.
#[instrument(skip(conn, config, tx_ui))]
pub fn run(conn: &mut Connection, config: &Ustawienia, tx_ui: mpsc::Sender<PhaseEvent>) -> SqlResult<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);
    let report_path = &config.csv_report_path;
    
    let _ = tx_ui.send(PhaseEvent::Log("Uruchomiono Fazę 8: Generowanie Raportu i Decyzji Kryminalistycznych (Euro-CSV).".to_string()));

    let start_time = Instant::now();

    let total_files: usize = conn.query_row("SELECT COUNT(*) FROM files", [], |row| Ok(row.get::<_, i64>(0)? as usize))?;
    if total_files == 0 {
        warn!("Baza danych pusta, brak danych do wygenerowania raportu CSV");
        let _ = tx_ui.send(PhaseEvent::Log("Baza danych jest pusta, przerywam eksport.".to_string()));
        return Ok(());
    }

    let file = File::create(report_path).unwrap_or_else(|e| panic!("Nie można utworzyć pliku raportu '{}': {}", report_path, e));
    let mut writer = BufWriter::new(file);

    writer.write_all(b"\xEF\xBB\xBF").unwrap(); // UTF-8 BOM

    // Rozbudowany nagłówek o Akcje Naprawcze
    writeln!(writer, "Sciezka;Lokacja;Rozmiar_UFS;Rozmiar_Skrypt;Zgodnosc_Rozmiaru;Hash_UFS;Hash_Skrypt;Zgodnosc_Hash;Podobienstwo_Fuzzy_Pct;Zera_UFS_Pct;Zera_Skrypt_Pct;EOF_UFS;EOF_Skrypt;Entropia_UFS;Entropia_Skrypt;UTF8_UFS;UTF8_Skrypt;Struktura_UFS;Struktura_Skrypt;EXIF_UFS;EXIF_Skrypt;Obraz_UFS;Obraz_Skrypt;Xattr_UFS;Xattr_Skrypt;Blad_IO_UFS;Blad_IO_Skrypt;Regula_YARA;Sciezka_Naprawiona_UFS;Sciezka_Naprawiona_Skrypt;Log_Naprawy_UFS;Log_Naprawy_Skrypt;Status_Decyzyjny;Rekomendacja_Silnika").unwrap();

    let _ = tx_ui.send(PhaseEvent::SetBar { idx: 0, label: "Silnik Heurystyczny (Ewaluacja)".to_string(), total: total_files as u64, color: Color::Yellow });

    let mut to_reject_count = 0; let mut suspect_count = 0; let mut ok_count = 0; let mut infected_count = 0; let mut repaired_count = 0;
    let mut reject_reasons: HashMap<String, usize> = HashMap::new(); let mut suspect_reasons: HashMap<String, usize> = HashMap::new();

    let mut stmt = conn.prepare(
        "SELECT
            relative_path, found_in_ufs, found_in_script, size_ufs, size_script, size_match,
            hash_ufs, hash_script, hash_match, fuzzy_match_pct, zeros_pct_ufs, zeros_pct_script, eof_ok_ufs, eof_ok_script,
            entropy_ufs, entropy_script, utf8_ok_ufs, utf8_ok_script, structure_ok_ufs, structure_ok_script, exif_ok_ufs, exif_ok_script,
            media_decoded_ufs, media_decoded_script, has_xattr_ufs, has_xattr_script, io_error_ufs, io_error_script, yara_match_ufs, yara_match_script,
            repaired_path_ufs, repaired_path_script, repair_log_ufs, repair_log_script
         FROM files"
    )?;

    let records_iter = stmt.query_map([], |row| {
        Ok(FileRecord {
            relative_path: row.get(0)?, found_in_ufs: row.get(1)?, found_in_script: row.get(2)?,
            size_ufs: row.get(3)?, size_script: row.get(4)?, size_match: row.get(5)?,
            hash_ufs: row.get(6)?, hash_script: row.get(7)?, hash_match: row.get(8)?, fuzzy_match_pct: row.get(9)?,
            zeros_pct_ufs: row.get(10)?, zeros_pct_script: row.get(11)?, eof_ok_ufs: row.get(12)?, eof_ok_script: row.get(13)?,
            entropy_ufs: row.get(14)?, entropy_script: row.get(15)?, utf8_ok_ufs: row.get(16)?, utf8_ok_script: row.get(17)?,
            structure_ok_ufs: row.get(18)?, structure_ok_script: row.get(19)?, exif_ok_ufs: row.get(20)?, exif_ok_script: row.get(21)?,
            media_decoded_ufs: row.get(22)?, media_decoded_script: row.get(23)?, has_xattr_ufs: row.get(24)?, has_xattr_script: row.get(25)?,
            io_error_ufs: row.get(26)?, io_error_script: row.get(27)?, yara_match_ufs: row.get(28)?, yara_match_script: row.get(29)?,
            repaired_path_ufs: row.get(30)?, repaired_path_script: row.get(31)?, repair_log_ufs: row.get(32)?, repair_log_script: row.get(33)?,
        })
    })?;

    let mut i = 0;
    let mut last_ui_update = Instant::now();

    for record_result in records_iter {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) { break; }
        let rec = record_result?;
        let eval = evaluate_file(&rec);

        if eval.status.contains("ZAINFEKOWANY") { infected_count += 1; } 
        else if eval.status.contains("ZREKONSTRUOWANY") { repaired_count += 1; }
        else if eval.status.contains("USZKODZONY") || eval.status.contains("BŁĄD") { to_reject_count += 1; *reject_reasons.entry(eval.status.clone()).or_insert(0) += 1; } 
        else if eval.status.contains("PODEJRZANY") || eval.status.contains("RÓŻNY") { suspect_count += 1; *suspect_reasons.entry(eval.status.clone()).or_insert(0) += 1; } 
        else { ok_count += 1; }

        let lokacja = match (rec.found_in_ufs, rec.found_in_script) { (true, true) => "Oba", (true, false) => "UFS", (false, true) => "Skrypt", _ => "Brak" };

        writeln!(writer, "{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{};{}",
            escape_csv(&rec.relative_path), lokacja, fmt_opt_i64(rec.size_ufs), fmt_opt_i64(rec.size_script), fmt_opt_bool(rec.size_match),
            fmt_opt_str(rec.hash_ufs), fmt_opt_str(rec.hash_script), fmt_opt_bool(rec.hash_match), fmt_opt_f64(rec.fuzzy_match_pct),
            fmt_opt_f64(rec.zeros_pct_ufs), fmt_opt_f64(rec.zeros_pct_script), fmt_opt_bool(rec.eof_ok_ufs), fmt_opt_bool(rec.eof_ok_script),
            fmt_opt_f64(rec.entropy_ufs), fmt_opt_f64(rec.entropy_script), fmt_opt_bool(rec.utf8_ok_ufs), fmt_opt_bool(rec.utf8_ok_script),
            fmt_opt_bool(rec.structure_ok_ufs), fmt_opt_bool(rec.structure_ok_script), fmt_opt_bool(rec.exif_ok_ufs), fmt_opt_bool(rec.exif_ok_script),
            fmt_opt_bool(rec.media_decoded_ufs), fmt_opt_bool(rec.media_decoded_script), fmt_opt_bool(rec.has_xattr_ufs), fmt_opt_bool(rec.has_xattr_script),
            fmt_opt_bool(rec.io_error_ufs), fmt_opt_bool(rec.io_error_script), escape_csv(&eval.yara_rule),
            fmt_opt_str(rec.repaired_path_ufs), fmt_opt_str(rec.repaired_path_script), fmt_opt_str(rec.repair_log_ufs), fmt_opt_str(rec.repair_log_script),
            escape_csv(&eval.status), escape_csv(&eval.recommendation),
        ).unwrap();

        i += 1;

        let now = Instant::now();
        if now.duration_since(last_ui_update).as_millis() > 80 {
            last_ui_update = now;

            // PASEK: wyłącznie postęp + bieżący plik (bez liczników)
            let _ = tx_ui.send(PhaseEvent::UpdateBar {
                idx: 0,
                current: i as u64,
                message: format_display_path(&rec.relative_path),
            });

            // PANEL BOCZNY: podsumowanie na żywo (bez podziału per-źródło - patrz dokumentacja modułu)
            let _ = tx_ui.send(PhaseEvent::UpdateSideText {
                idx: 0,
                text: build_summary_block(ok_count, to_reject_count, repaired_count, infected_count, &reject_reasons, &suspect_reasons),
            });
        }
    }

    writer.flush().unwrap();
    let _ = tx_ui.send(PhaseEvent::UpdateBar { idx: 0, current: total_files as u64, message: "Ewaluacja CSV w 100% zakończona.".to_string() });
    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
        idx: 0,
        text: build_summary_block(ok_count, to_reject_count, repaired_count, infected_count, &reject_reasons, &suspect_reasons),
    });
    
    if CANCEL_SIGNAL.load(Ordering::SeqCst) {
        let _ = tx_ui.send(PhaseEvent::Log("🛑 Przerwano przez użytkownika.".to_string()));
        return Ok(());
    }

    // --- RAPORT KOŃCOWY DUAL-LOGGING ---
    let raport_cfg = config.raporty_faz.get("Faza 8").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_faza8.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_faza8.txt".to_string(),
    });
    
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);

    let elapsed = start_time.elapsed();
    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(&mut log_out, "==========================================================================");
    let _ = writeln!(&mut log_out, "DZIENNIK KOŃCOWY - FAZA 8 (PODSUMOWANIE HEURYSTYKI I DECYZJE)");
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(&mut log_out, "==========================================================================\n");

    let _ = writeln!(&mut log_out, "Pomyślnie oceniono plików łącznie: {}\n", i);
    let _ = writeln!(&mut log_out, "[ 🦠 ] Pliki Zainfekowane (Malware/Ransomware): {}", infected_count);
    let _ = writeln!(&mut log_out, "[ 🛠️ ] Pliki Zrekonstruowane (Aktywna Naprawa): {}", repaired_count);
    let _ = writeln!(&mut log_out, "[ ✔ ] Pliki w 100% Zdrowe (Zgodne lub Unikalne): {}", ok_count);
    let _ = writeln!(&mut log_out, "[ ⚠ ] Pliki Podejrzane (Częściowe anomalie):     {}", suspect_count);
    let _ = writeln!(&mut log_out, "[ ✖ ] Pliki Odrzucone (Bezużyteczne Śmieci):     {}\n", to_reject_count);

    // PRZYWRÓCONE: Zestawienie uszkodzeń ucięte w nowej wersji
    if !reject_reasons.is_empty() {
        let _ = writeln!(&mut log_out, "SZCZEGÓŁOWE ROZBICIE KATEGORII ODRZUTÓW (Pliki Śmieciowe):");
        let mut sorted_rejections: Vec<_> = reject_reasons.iter().collect();
        sorted_rejections.sort_by(|a, b| b.1.cmp(a.1));
        for (reason, count) in sorted_rejections {
            let _ = writeln!(&mut log_out, "   -> {}: {} plików", reason, count);
        }
        let _ = writeln!(&mut log_out);
    }

    if !suspect_reasons.is_empty() {
        let _ = writeln!(&mut log_out, "SZCZEGÓŁOWE ROZBICIE KATEGORII PODEJRZANYCH:");
        let mut sorted_suspects: Vec<_> = suspect_reasons.iter().collect();
        sorted_suspects.sort_by(|a, b| b.1.cmp(a.1));
        for (reason, count) in sorted_suspects { // <--- TO ZMIEŃ! Błąd w iteracji
            let _ = writeln!(&mut log_out, "   -> {}: {} plików", reason, count);
        }
        let _ = writeln!(&mut log_out);
    }

    if let Ok(mut f) = std::fs::File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano fizyczny Dziennik Końcowy w: {}", dz_path.display())));
        let _ = tx_ui.send(PhaseEvent::Log(format!("✔ Zapisano kompletny arkusz Euro-CSV w: {}", report_path)));
    }

    // Wysyłamy również do Ratatui Log Panel
    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    // Zrzut telemetrii do głównego pliku logów w tle
    info!(
        report_path,
        total_files,
        ok_count,
        repaired_count,
        suspect_count,
        to_reject_count,
        infected_count,
        "Faza 8 zakończona"
    );

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Bazowy, "czysty" rekord: plik obecny po obu stronach, identyczny
    /// rozmiar i hash, brak jakichkolwiek anomalii. Testy nadpisują tylko
    /// pola istotne dla danego scenariusza (składnia aktualizacji struktury).
    fn base_clean_record() -> FileRecord {
        FileRecord {
            relative_path: "test/plik.dat".to_string(),
            found_in_ufs: true,
            found_in_script: true,
            size_ufs: Some(1024),
            size_script: Some(1024),
            size_match: Some(true),
            hash_ufs: Some("aaaa".to_string()),
            hash_script: Some("aaaa".to_string()),
            hash_match: Some(true),
            fuzzy_match_pct: None,
            zeros_pct_ufs: None,
            zeros_pct_script: None,
            eof_ok_ufs: None,
            eof_ok_script: None,
            entropy_ufs: None,
            entropy_script: None,
            utf8_ok_ufs: None,
            utf8_ok_script: None,
            structure_ok_ufs: None,
            structure_ok_script: None,
            exif_ok_ufs: None,
            exif_ok_script: None,
            media_decoded_ufs: None,
            media_decoded_script: None,
            has_xattr_ufs: None,
            has_xattr_script: None,
            io_error_ufs: None,
            io_error_script: None,
            yara_match_ufs: None,
            yara_match_script: None,
            repaired_path_ufs: None,
            repaired_path_script: None,
            repair_log_ufs: None,
            repair_log_script: None,
        }
    }

    // ------------------------------------------------------------------
    // Priorytet 0: YARA (wygrywa nad wszystkim innym)
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_yara_match_ufs_is_infected() {
        let r = FileRecord { yara_match_ufs: Some("EICAR_Test".to_string()), ..base_clean_record() };
        let eval = evaluate_file(&r);
        assert_eq!(eval.status, "ZAINFEKOWANY (MALWARE)");
        assert_eq!(eval.yara_rule, "EICAR_Test");
    }

    #[test]
    fn test_evaluate_yara_match_script_is_infected() {
        let r = FileRecord { yara_match_script: Some("Trojan.Generic".to_string()), ..base_clean_record() };
        let eval = evaluate_file(&r);
        assert_eq!(eval.status, "ZAINFEKOWANY (MALWARE)");
        assert_eq!(eval.yara_rule, "Trojan.Generic");
    }

    #[test]
    fn test_evaluate_yara_prefers_ufs_rule_when_both_match() {
        let r = FileRecord {
            yara_match_ufs: Some("RuleA".to_string()),
            yara_match_script: Some("RuleB".to_string()),
            ..base_clean_record()
        };
        let eval = evaluate_file(&r);
        assert_eq!(eval.yara_rule, "RuleA");
    }

    #[test]
    fn test_evaluate_yara_wins_over_io_error() {
        let r = FileRecord {
            yara_match_ufs: Some("Malware.X".to_string()),
            io_error_ufs: Some(true),
            io_error_script: Some(true),
            ..base_clean_record()
        };
        let eval = evaluate_file(&r);
        assert_eq!(eval.status, "ZAINFEKOWANY (MALWARE)", "YARA musi wygrać nawet przy błędzie I/O na obu stronach");
    }

    #[test]
    fn test_evaluate_yara_wins_over_repair() {
        let r = FileRecord {
            yara_match_ufs: Some("Malware.Y".to_string()),
            repaired_path_ufs: Some("plik.repaired".to_string()),
            ..base_clean_record()
        };
        let eval = evaluate_file(&r);
        assert_eq!(eval.status, "ZAINFEKOWANY (MALWARE)", "YARA musi wygrać nawet nad rekonstrukcją Fazy 17");
    }

    // ------------------------------------------------------------------
    // Priorytet 1: Naprawiony (wygrywa nad anomaliami poniżej, ale nie nad YARA)
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_repaired_wins_over_wydmuszka() {
        let r = FileRecord {
            repaired_path_ufs: Some("plik.repaired".to_string()),
            repair_log_ufs: Some("Naprawiono nagłówek JPEG".to_string()),
            zeros_pct_ufs: Some(100.0), // normalnie dałoby WYDMUSZKA
            ..base_clean_record()
        };
        let eval = evaluate_file(&r);
        assert_eq!(eval.status, "ZREKONSTRUOWANY (NAPRAWIONY)");
        assert!(eval.recommendation.contains("Naprawiono nagłówek JPEG"));
    }

    #[test]
    fn test_evaluate_repaired_script_side() {
        let r = FileRecord { repaired_path_script: Some("x.repaired".to_string()), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "ZREKONSTRUOWANY (NAPRAWIONY)");
    }

    // ------------------------------------------------------------------
    // Priorytet 2: Błąd I/O TYLKO gdy obie strony zawiodły jednocześnie
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_io_error_both_sides_rejected() {
        let r = FileRecord { io_error_ufs: Some(true), io_error_script: Some(true), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "BŁĄD ODCZYTU (I/O)");
    }

    #[test]
    fn test_evaluate_io_error_only_one_side_does_not_trigger_rejection() {
        // Błąd tylko po jednej stronie NIE powinien dać "BŁĄD ODCZYTU (I/O)" -
        // ocena przechodzi dalej do finalnego porównania wersji.
        let r = FileRecord { io_error_ufs: Some(true), ..base_clean_record() };
        assert_ne!(evaluate_file(&r).status, "BŁĄD ODCZYTU (I/O)");
    }

    // ------------------------------------------------------------------
    // Priorytet 3: Wydmuszka (>99% zer)
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_wydmuszka_ufs() {
        let r = FileRecord { zeros_pct_ufs: Some(99.5), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (WYDMUSZKA)");
    }

    #[test]
    fn test_evaluate_wydmuszka_script() {
        let r = FileRecord { zeros_pct_script: Some(100.0), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (WYDMUSZKA)");
    }

    #[test]
    fn test_evaluate_zeros_exactly_99_percent_not_wydmuszka() {
        // Próg to ŚCIŚLE > 99.0, więc dokładnie 99.0 nie powinno się kwalifikować
        let r = FileRecord { zeros_pct_ufs: Some(99.0), ..base_clean_record() };
        assert_ne!(evaluate_file(&r).status, "USZKODZONY (WYDMUSZKA)");
    }

    // ------------------------------------------------------------------
    // Priorytety 4-8: pojedyncze walidacje strukturalne
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_media_decode_failure() {
        let r = FileRecord { media_decoded_ufs: Some(false), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (UCIĘTY OBRAZ)");
    }

    #[test]
    fn test_evaluate_utf8_failure() {
        let r = FileRecord { utf8_ok_script: Some(false), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (BINARNY ŚMIEĆ)");
    }

    #[test]
    fn test_evaluate_structure_failure() {
        let r = FileRecord { structure_ok_ufs: Some(false), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (ZŁA STRUKTURA)");
    }

    #[test]
    fn test_evaluate_exif_failure() {
        let r = FileRecord { exif_ok_script: Some(false), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (BŁĘDNY EXIF)");
    }

    #[test]
    fn test_evaluate_eof_failure() {
        let r = FileRecord { eof_ok_ufs: Some(false), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (BRAK EOF)");
    }

    // ------------------------------------------------------------------
    // Priorytet 9: Entropia skrajna
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_high_entropy_is_suspect() {
        let r = FileRecord { entropy_ufs: Some(7.999), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "PODEJRZANY (WYSOKA ENTROPIA)");
    }

    #[test]
    fn test_evaluate_entropy_exactly_threshold_not_suspect() {
        // Próg to ŚCIŚLE > 7.995
        let r = FileRecord { entropy_ufs: Some(7.995), ..base_clean_record() };
        assert_ne!(evaluate_file(&r).status, "PODEJRZANY (WYSOKA ENTROPIA)");
    }

    #[test]
    fn test_evaluate_low_entropy_is_suspect() {
        let r = FileRecord { entropy_script: Some(0.5), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "PODEJRZANY (NISKA ENTROPIA)");
    }

    #[test]
    fn test_evaluate_entropy_exactly_zero_not_suspect() {
        // Wykluczone jawnie (`ent_u > 0.0`) - zero to inna kategoria (wydmuszka, sprawdzana wcześniej)
        let r = FileRecord { entropy_ufs: Some(0.0), ..base_clean_record() };
        assert_ne!(evaluate_file(&r).status, "PODEJRZANY (NISKA ENTROPIA)");
    }

    #[test]
    fn test_evaluate_entropy_exactly_one_not_suspect() {
        // Próg górny to ŚCIŚLE < 1.0
        let r = FileRecord { entropy_ufs: Some(1.0), ..base_clean_record() };
        assert_ne!(evaluate_file(&r).status, "PODEJRZANY (NISKA ENTROPIA)");
    }

    // ------------------------------------------------------------------
    // Priorytet 10: finalna macierz porównania wersji
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_identical_versions_is_zgodny() {
        let r = base_clean_record();
        assert_eq!(evaluate_file(&r).status, "ZGODNY");
    }

    #[test]
    fn test_evaluate_different_hash_high_fuzzy_match() {
        let r = FileRecord { hash_match: Some(false), fuzzy_match_pct: Some(95.0), ..base_clean_record() };
        let eval = evaluate_file(&r);
        assert!(eval.status.starts_with("RÓŻNY HASH (PODOBNE W"));
        assert!(eval.status.contains("95"));
    }

    #[test]
    fn test_evaluate_different_hash_partial_fuzzy_match() {
        let r = FileRecord { hash_match: Some(false), fuzzy_match_pct: Some(40.0), ..base_clean_record() };
        let eval = evaluate_file(&r);
        assert!(eval.status.starts_with("RÓŻNY HASH (PODOBNE W"));
        assert!(eval.recommendation.contains("tylko część wspólną"));
    }

    #[test]
    fn test_evaluate_different_hash_zero_fuzzy_is_frankenstein() {
        let r = FileRecord { hash_match: Some(false), fuzzy_match_pct: Some(0.0), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "RÓŻNY HASH (FRANKENSTEIN)");
    }

    #[test]
    fn test_evaluate_different_hash_no_fuzzy_data() {
        let r = FileRecord { hash_match: Some(false), fuzzy_match_pct: None, ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "RÓŻNY HASH");
    }

    #[test]
    fn test_evaluate_different_size_overrides_hash_result() {
        // Różny rozmiar ma priorytet w dopasowaniu match - niezależnie od hash_match
        let r = FileRecord { size_match: Some(false), hash_match: Some(true), ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "RÓŻNY ROZMIAR");
    }

    #[test]
    fn test_evaluate_missing_comparison_data() {
        let r = FileRecord { size_match: None, hash_match: None, ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "BRAK DANYCH");
    }

    #[test]
    fn test_evaluate_only_in_ufs() {
        let r = FileRecord { found_in_ufs: true, found_in_script: false, ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "TYLKO UFS");
    }

    #[test]
    fn test_evaluate_only_in_script() {
        let r = FileRecord { found_in_ufs: false, found_in_script: true, ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "TYLKO SKRYPT");
    }

    #[test]
    fn test_evaluate_ghost_file_found_nowhere() {
        let r = FileRecord { found_in_ufs: false, found_in_script: false, ..base_clean_record() };
        assert_eq!(evaluate_file(&r).status, "BŁĄD KRYTYCZNY");
    }

    // ------------------------------------------------------------------
    // escape_csv
    // ------------------------------------------------------------------

    #[test]
    fn test_escape_csv_plain_text_unchanged() {
        assert_eq!(escape_csv("zwykly_tekst.txt"), "zwykly_tekst.txt");
    }

    #[test]
    fn test_escape_csv_semicolon_gets_quoted() {
        assert_eq!(escape_csv("a;b"), "\"a;b\"");
    }

    #[test]
    fn test_escape_csv_quote_gets_doubled_and_quoted() {
        assert_eq!(escape_csv("powiedział \"cześć\""), "\"powiedział \"\"cześć\"\"\"");
    }

    #[test]
    fn test_escape_csv_newline_gets_quoted() {
        assert_eq!(escape_csv("linia1\nlinia2"), "\"linia1\nlinia2\"");
    }

    // ------------------------------------------------------------------
    // fmt_opt_*
    // ------------------------------------------------------------------

    #[test]
    fn test_fmt_opt_bool_variants() {
        assert_eq!(fmt_opt_bool(Some(true)), "Tak");
        assert_eq!(fmt_opt_bool(Some(false)), "Nie");
        assert_eq!(fmt_opt_bool(None), "Brak");
    }

    #[test]
    fn test_fmt_opt_f64_uses_comma_decimal() {
        assert_eq!(fmt_opt_f64(Some(7.5)), "7,50");
        assert_eq!(fmt_opt_f64(None), "Brak");
    }

    #[test]
    fn test_fmt_opt_i64_variants() {
        assert_eq!(fmt_opt_i64(Some(42)), "42");
        assert_eq!(fmt_opt_i64(None), "Brak");
    }

    #[test]
    fn test_fmt_opt_str_variants() {
        assert_eq!(fmt_opt_str(Some("wartość".to_string())), "wartość");
        assert_eq!(fmt_opt_str(None), "Brak");
    }

    // ------------------------------------------------------------------
    // build_summary_block
    // ------------------------------------------------------------------

    #[test]
    fn test_build_summary_block_reports_counts() {
        let reject_reasons: HashMap<String, usize> = HashMap::new();
        let suspect_reasons: HashMap<String, usize> = HashMap::new();
        let block = build_summary_block(10, 3, 1, 2, &reject_reasons, &suspect_reasons);
        assert!(block.contains("Zdrowe: 10"));
        assert!(block.contains("Odrzucone: 3"));
        assert!(block.contains("Naprawione: 1"));
        assert!(block.contains("Wirusy: 2"));
    }

    #[test]
    fn test_build_summary_block_top_reasons_sorted_by_frequency() {
        let mut reject_reasons: HashMap<String, usize> = HashMap::new();
        reject_reasons.insert("USZKODZONY (WYDMUSZKA)".to_string(), 5);
        reject_reasons.insert("USZKODZONY (BRAK EOF)".to_string(), 20);
        let suspect_reasons: HashMap<String, usize> = HashMap::new();

        let block = build_summary_block(0, 25, 0, 0, &reject_reasons, &suspect_reasons);
        let line = block.lines().find(|l| l.starts_with("Top powody odrzuceń:")).unwrap();
        let pos_eof = line.find("USZKODZONY (BRAK EOF) (20)").expect("powinien zawierać powód EOF");
        let pos_wydmuszka = line.find("USZKODZONY (WYDMUSZKA) (5)").expect("powinien zawierać powód wydmuszki");
        assert!(pos_eof < pos_wydmuszka, "Częstszy powód powinien być wymieniony pierwszy");
    }

    #[test]
    fn test_build_summary_block_placeholder_when_no_reasons() {
        let empty: HashMap<String, usize> = HashMap::new();
        let block = build_summary_block(5, 0, 0, 0, &empty, &empty);
        assert!(block.contains("Top powody odrzuceń: -"));
        assert!(block.contains("Top powody podejrzeń: -"));
    }
}
