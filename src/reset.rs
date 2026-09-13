// src/reset.rs

//! Moduł odpowiedzialny za bezpieczne i GŁĘBOKIE resetowanie postępu w bazie danych.

use crate::settings::Ustawienia;
use rusqlite::{Connection, Result};
use dialoguer::{theme::ColorfulTheme, MultiSelect, Password};
use std::collections::HashMap;
use std::io::Write;
use std::time::Instant;
use tracing::info;
use colored::Colorize;

// ============================================================================
// MAPOWANIE KOLUMN
// ============================================================================

/// Nazwy faz pokazywane w `MultiSelect`, W KOLEJNOŚCI NUMERÓW — indeks `i`
/// odpowiada fazie `i + 1`.
///
/// Stała modułowa, nie lokalny `vec!`, z dwóch powodów: (1) długość listy
/// wyznacza granicę między pozycjami "faza" i "tabela powiązana" w menu, więc
/// nie może być nigdzie zapisana liczbą — wcześniej było tu zahardkodowane
/// `17` i to ono sprawiło, że Fazy 18/19 dało się wybrać z listy tylko
/// teoretycznie (lista i tak ich nie zawierała), a każda nowa faza cicho
/// przesuwałaby indeksy tabel; (2) dzięki temu spójność listy z
/// [`belongs_to_phase`] da się sprawdzić testem.
const PHASE_NAMES: &[&str] = &[
    "Faza 1: Mapowanie struktury", "Faza 2: Akwizycja Metadanych", "Faza 3: Hashe BLAKE3 (Zgodne)",
    "Faza 4: Hashe BLAKE3 (Brakujące)", "Faza 5: Czas modyfikacji", "Faza 6: Puste Pliki",
    "Faza 7: Entropia (Shannon)", "Faza 8: Raport Końcowy CSV", "Faza 9: Smart Merge",
    "Faza 10: Walidacja Tekstu", "Faza 11: Walidacja Archiwów", "Faza 12: Struktury Obrazów",
    "Faza 13: Dekodowanie Mediów", "Faza 14: Rozmyte Hashowanie", "Faza 15: Atrybuty xattr",
    "Faza 16: Skanowanie YARA", "Faza 17: Aktywne Moduły Naprawcze",
    "Faza 18: Smart Splice (Składanie)", "Faza 19: Diagnostyka Wideo",
];

/// Rozstrzyga, czy kolumna tabeli `files` należy do danej fazy i ma zostać
/// wyczyszczona przy jej resecie.
///
/// Kolumna `phase{N}_done` jest dopasowywana generycznie (pierwsza linia), więc
/// nie trzeba jej wymieniać w żadnej gałęzi. Kolumny `io_error_*` CELOWO
/// należą do wielu faz naraz — każda z nich może je ustawić i każda powinna je
/// po sobie sprzątnąć.
fn belongs_to_phase(col_name: &str, phase_num: usize) -> bool {
    if col_name == format!("phase{}_done", phase_num) { return true; }

    match phase_num {
        2 => matches!(col_name, "size_ufs" | "size_script" | "size_match" | "larger_side" | "io_error_ufs" | "io_error_script"),
        3 | 4 => matches!(col_name, "hash_ufs" | "hash_script" | "hash_match" | "magic_ok_ufs" | "magic_ok_script" | "io_error_ufs" | "io_error_script"),
        5 => matches!(col_name, "uid_ufs" | "uid_script" | "gid_ufs" | "gid_script" | "mode_ufs" | "mode_script" | "mtime_ufs" | "mtime_script" | "is_symlink_ufs" | "is_symlink_script" | "meta_match" | "io_error_ufs" | "io_error_script"),
        6 => matches!(col_name, "zeros_pct_ufs" | "zeros_pct_script" | "eof_ok_ufs" | "eof_ok_script" | "io_error_ufs" | "io_error_script"),
        7 => matches!(col_name, "entropy_ufs" | "entropy_script" | "io_error_ufs" | "io_error_script"),
        9 => matches!(col_name, "merge_source" | "merge_success" | "merge_reason" | "target_saved_path" | "merge_source_path"),
        10 => matches!(col_name, "utf8_ok_ufs" | "utf8_ok_script" | "io_error_ufs" | "io_error_script" | "is_oneliner_ufs" | "is_oneliner_script" | "text_enc_ufs" | "text_enc_script" | "text_eol_ufs" | "text_eol_script"),
        11 => matches!(col_name, "structure_ok_ufs" | "structure_ok_script" | "archive_reason_ufs" | "archive_reason_script" | "archive_files_ufs" | "archive_size_ufs" | "archive_files_script" | "archive_size_script" | "io_error_ufs" | "io_error_script"),
        12 => matches!(col_name, "exif_ok_ufs" | "exif_ok_script" | "media_reason_ufs" | "media_reason_script" | "exif_engine_ufs" | "exif_engine_script" | "media_duration_ufs" | "media_duration_script" | "media_device_ufs" | "media_device_script" | "has_gps_ufs" | "has_gps_script" | "io_error_ufs" | "io_error_script"),
        13 => matches!(col_name, "media_decoded_ufs" | "media_decoded_script" | "pixels_ok_ufs" | "pixels_ok_script" | "decode_reason_ufs" | "decode_reason_script" | "img_width_ufs" | "img_width_script" | "img_height_ufs" | "img_height_script" | "io_error_ufs" | "io_error_script"),
        14 => matches!(col_name, "fuzzy_hash_ufs" | "fuzzy_hash_script" | "fuzzy_match_pct" | "io_error_ufs" | "io_error_script"),
        15 => matches!(col_name, "has_xattr_ufs" | "has_xattr_script" | "io_error_ufs" | "io_error_script"),
        16 => matches!(col_name, "yara_match_ufs" | "yara_match_script" | "io_error_ufs" | "io_error_script"),
        17 => matches!(col_name, "repaired_path_ufs" | "repaired_path_script" | "repair_log_ufs" | "repair_log_script"),
        // UWAGA: `smart_splice_path` wskazuje na REALNE pliki złożone na dysku
        // (pod `target_path/_smart_splice_repaired`, ścieżką absolutną). Reset
        // czyści tylko wpis w bazie — pliki zostają na dysku jako osierocone,
        // dokładnie tak samo jak `repaired_path_*` przy Fazie 17. Usunięcie
        // ich to świadoma decyzja użytkownika, nie efekt uboczny resetu.
        18 => matches!(col_name, "smart_splice_path" | "smart_splice_log"),
        19 => matches!(col_name,
            "video_ok_ufs" | "video_ok_script"
            | "video_reason_ufs" | "video_reason_script"
            | "video_duration_ms_ufs" | "video_duration_ms_script"
            | "video_tracks_ufs" | "video_tracks_script"
            | "video_created_unix"
            | "io_error_ufs" | "io_error_script"),
        _ => false,
    }
}

pub fn run(conn: &mut Connection, config: &Ustawienia) -> Result<()> {
    println!("{}", "==========================================================================".cyan());
    println!("{} {}", "[ 🧹 ]".cyan(), "Narzędzie Głębokiego Resetowania Postępu".bold());
    println!("{}", "Zarządzanie Bazą Danych".yellow());
    println!("{}", "Pobiera pełną listę kolumn, weryfikuje ich przynależność i dynamicznie czyści.".bright_black());
    println!("{}", "==========================================================================\n".cyan());

    let mut options: Vec<String> = PHASE_NAMES.iter().map(|s| s.to_string()).collect();
    let mut stmt_tables = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'files' ORDER BY name")?;
    let extra_tables: Vec<String> = stmt_tables.query_map([], |row| row.get(0))?.filter_map(|r| r.ok()).collect();
    drop(stmt_tables);

    if !extra_tables.is_empty() { 
        for t in &extra_tables { 
            options.push(format!("Wyczyść tabelę powiązaną: 📦 {}", t)); 
        } 
    }

    let selections = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Wybierz fazy do zresetowania (Spacja = zaznacz, ENTER = zatwierdź)")
        .items(&options)
        .interact_opt()
        .unwrap_or(None);
        
    let selected_indices = match selections { 
        Some(s) if !s.is_empty() => s, 
        _ => return Ok(()) 
    };

    let pw = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Hasło administratora")
        .interact()
        .unwrap_or_default();
        
    if blake3::hash(pw.as_bytes()).to_hex().to_string() != config.admin_password_hash {
        println!("\n{} Odmowa dostępu. Błędne hasło.", "[ ✖ ]".red().bold()); 
        return Ok(());
    }

    let mut schema_cols: HashMap<String, Option<String>> = HashMap::new();
    {
        let mut stmt = conn.prepare("PRAGMA table_info(files)")?;
        let rows = stmt.query_map([], |row| { Ok((row.get::<_, String>(1)?, row.get::<_, Option<String>>(4)?)) })?;
        for r in rows.filter_map(|r| r.ok()) { schema_cols.insert(r.0, r.1); }
    }

    let start_time = Instant::now();
    let mut stdout = std::io::stdout().lock();
    let tx = conn.transaction()?;

    for &idx in &selected_indices {
        if idx < PHASE_NAMES.len() {
            let phase_num = idx + 1;
            writeln!(stdout, "\n{} {}", ">>>".yellow().bold(), PHASE_NAMES[idx].bold()).unwrap();
            let mut cols_to_clean = Vec::new();
            for (col_name, dflt_val) in &schema_cols { 
                if belongs_to_phase(col_name, phase_num) { 
                    cols_to_clean.push((col_name.clone(), dflt_val.clone())); 
                } 
            }

            if cols_to_clean.is_empty() { continue; }
            cols_to_clean.sort_by(|a, b| a.0.cmp(&b.0));

            for (col_name, dflt_val) in cols_to_clean {
                let (set_val, check_cond) = if let Some(d) = dflt_val { 
                    if d == "0" || d == "'0'" { ("0", format!("{} != 0", col_name)) } 
                    else { ("NULL", format!("{} IS NOT NULL", col_name)) } 
                } else { 
                    ("NULL", format!("{} IS NOT NULL", col_name)) 
                };
                
                let count: i64 = tx.query_row(&format!("SELECT COUNT(*) FROM files WHERE {}", check_cond), [], |r| r.get(0)).unwrap_or(0);
                if count == 0 { 
                    writeln!(stdout, "   - Kolumna {:<22} [ {} ]", col_name, "Czysta".green()).unwrap(); 
                    continue; 
                }

                if tx.execute(&format!("UPDATE files SET {} = {}", col_name, set_val), []).is_err() { 
                    tx.rollback()?; 
                    return Ok(()); 
                }
                
                let verify_count: i64 = tx.query_row(&format!("SELECT COUNT(*) FROM files WHERE {}", check_cond), [], |r| r.get(0)).unwrap_or(0);

                if verify_count == 0 { 
                    writeln!(stdout, "   - Kolumna {:<22} [ {} ] (usunięto: {})", col_name, "Wyczyszczono".green(), count).unwrap(); 
                } else { 
                    tx.rollback()?; 
                    return Ok(()); 
                }
            }
        } else {
            let table_name = &extra_tables[idx - PHASE_NAMES.len()];
            writeln!(stdout, "\n{} Czyszczenie tabeli: {}", ">>>".yellow().bold(), table_name.bold()).unwrap();
            if tx.execute(&format!("DELETE FROM \"{}\"", table_name), []).is_ok() { 
                writeln!(stdout, "   - Tabela  {:<22} [ {} ]", table_name, "Wyczyszczono".green()).unwrap(); 
            } else { 
                tx.rollback()?; 
                return Ok(()); 
            }
        }
    }
    
    tx.commit()?;

    writeln!(stdout, "\n{}", "══════════════════════════════════════════════════════════════════════════════".cyan()).unwrap();
    writeln!(stdout, "{} ({:.2?})", "[ ✔ ] GŁĘBOKI RESET ZAKOŃCZONY SUKCESEM".green().bold(), start_time.elapsed()).unwrap();
    info!("Reset bazy zakończony sukcesem.");

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Liczba faz w projekcie. Gdy dojdzie Faza 20, ten test ma padnąć jako
    /// pierwszy — to celowa przypominajka, że trzeba dopisać ją TAKŻE do
    /// [`PHASE_NAMES`] i do [`belongs_to_phase`].
    const LICZBA_FAZ: usize = 19;

    #[test]
    fn test_phase_names_zawiera_wszystkie_fazy() {
        assert_eq!(
            PHASE_NAMES.len(), LICZBA_FAZ,
            "Lista faz w menu resetu musi pokrywać wszystkie fazy - Fazy 18/19 były tu wcześniej pominięte"
        );
    }

    /// Indeks w [`PHASE_NAMES`] MUSI odpowiadać numerowi fazy (`idx + 1`),
    /// bo `run` wylicza `phase_num` właśnie z pozycji na liście. Przestawienie
    /// albo wstawienie wpisu w środku czyściłoby kolumny złej fazy.
    #[test]
    fn test_kolejnosc_phase_names_zgadza_sie_z_numerami() {
        for (idx, nazwa) in PHASE_NAMES.iter().enumerate() {
            let oczekiwany_prefiks = format!("Faza {}:", idx + 1);
            assert!(
                nazwa.starts_with(&oczekiwany_prefiks),
                "Pozycja {} to \"{}\", a powinna zaczynać się od \"{}\"",
                idx, nazwa, oczekiwany_prefiks
            );
        }
    }

    #[test]
    fn test_flaga_done_nalezy_tylko_do_swojej_fazy() {
        for faza in 1..=LICZBA_FAZ {
            let flaga = format!("phase{}_done", faza);
            assert!(belongs_to_phase(&flaga, faza), "{} powinna należeć do Fazy {}", flaga, faza);

            for inna in 1..=LICZBA_FAZ {
                if inna == faza { continue; }
                assert!(
                    !belongs_to_phase(&flaga, inna),
                    "{} nie może należeć do Fazy {} - reset czyściłby cudzy postęp",
                    flaga, inna
                );
            }
        }
    }

    #[test]
    fn test_kolumny_fazy18_sa_mapowane() {
        for kolumna in ["smart_splice_path", "smart_splice_log", "phase18_done"] {
            assert!(belongs_to_phase(kolumna, 18), "Faza 18 nie sprząta po sobie kolumny {}", kolumna);
        }
    }

    #[test]
    fn test_kolumny_fazy19_sa_mapowane() {
        for kolumna in [
            "video_ok_ufs", "video_ok_script",
            "video_reason_ufs", "video_reason_script",
            "video_duration_ms_ufs", "video_duration_ms_script",
            "video_tracks_ufs", "video_tracks_script",
            "phase19_done",
        ] {
            assert!(belongs_to_phase(kolumna, 19), "Faza 19 nie sprząta po sobie kolumny {}", kolumna);
        }
    }

    /// Kolumny Faz 18/19 nie mogą być przypisane do żadnej innej fazy —
    /// inaczej reset np. Fazy 9 wyczyściłby ścieżki złożeń Fazy 18.
    #[test]
    fn test_kolumny_faz18_19_nie_naleza_do_innych_faz() {
        let wlasciciele: &[(&str, usize)] = &[
            ("smart_splice_path", 18),
            ("smart_splice_log", 18),
            ("video_ok_ufs", 19),
            ("video_reason_script", 19),
            ("video_tracks_ufs", 19),
        ];

        for &(kolumna, wlasciciel) in wlasciciele {
            for faza in 1..=LICZBA_FAZ {
                if faza == wlasciciel { continue; }
                assert!(
                    !belongs_to_phase(kolumna, faza),
                    "Kolumna {} (własność Fazy {}) jest błędnie przypisana też do Fazy {}",
                    kolumna, wlasciciel, faza
                );
            }
        }
    }

    /// `io_error_*` jest współdzielone CELOWO — ten test pilnuje, żeby ktoś
    /// przy porządkach nie "naprawił" tego na wyłączność jednej fazy.
    #[test]
    fn test_io_error_jest_wspoldzielone_miedzy_fazami() {
        let ile = (1..=LICZBA_FAZ).filter(|&f| belongs_to_phase("io_error_ufs", f)).count();
        assert!(ile > 1, "io_error_ufs ma należeć do wielu faz, znaleziono {}", ile);
    }
}