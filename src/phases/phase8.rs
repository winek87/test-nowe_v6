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
//! [`Stats::build_summary_block`] — dla spójności z Fazami 1-7, choć
//! poprzednia wersja (jednoliniowy komunikat w `UpdateBar.message`) nie była
//! zepsuta, tylko niespójna stylistycznie.
//!
//! OBSŁUGA BŁĘDÓW: funkcja [`run`] zwraca `SqlResult<()>`, ale w środku
//! zapisuje też do plików przez `std::io`. Aby uniknąć panik w gorącej
//! pętli po plikach, wszystkie błędy I/O są propagowane przez [`io_err`]
//! (most `std::io::Error` → `rusqlite::Error`). Jedyny wyjątek to
//! `create_dir_all` dla katalogu raportów oraz zapis Dziennika Końcowego,
//! gdzie celowo stosujemy best-effort (brak dostępu do dziennika nie
//! przerywa Fazy 8 — CSV już jest zapisany, dziennik to dodatek).
//!
//! ANULOWANIE: [`CANCEL_SIGNAL`] sprawdzany jest na wejściu każdej iteracji
//! pętli po rekordach. Po wyjściu z pętli (naturalnym lub przez cancel)
//! pasek postępu dostaje FAKTYCZNĄ liczbę przetworzonych rekordów — nie
//! `total_files`. Zapobiega to mylącemu "100% zakończone" przy przerwanym
//! przebiegu. Przy anulowaniu Dziennik Końcowy NIE jest zapisywany (wczesny
//! `return Ok(())` przed jego budową) — tylko częściowy CSV.

use crate::settings::Ustawienia;
use crate::tui::state::PhaseEvent;
use crate::utils::{CANCEL_SIGNAL, format_display_path};
use ratatui::style::Color;
use rusqlite::{Connection, Result as SqlResult};
use std::borrow::Cow;
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
    /// `Some(ścieżka)` gdy Faza 18 (Smart Splice) złożyła ten plik z
    /// fragmentów OBU kopii jednocześnie — kolumna WSPÓLNA, nie per-strona
    /// (Smart Splice miesza obie strony w jeden wynik, tak samo jak czyta ją
    /// `phase9::decide_winner`).
    pub smart_splice_path: Option<String>,
    /// Diagnostyka kontenera wideo z Fazy 19 — `Some(false)` = uszkodzona
    /// struktura (MP4/MOV/MKV/TS).
    pub video_ok_ufs: Option<bool>,
    pub video_ok_script: Option<bool>,
    pub video_reason_ufs: Option<String>,
    pub video_reason_script: Option<String>,
}

impl FileRecord {
    /// Odczytuje jeden wiersz tabeli `files` do struktury. Wydzielone z
    /// `query_map` w [`run`], żeby: (a) 39 `row.get(N)?` nie zaśmiecało
    /// pętli, (b) dało się to przetestować bez SQL (choć testy integracyjne
    /// i tak to pokrywają), (c) przyszłe zmiany schematu miały jedno miejsce
    /// do edycji.
    ///
    /// UWAGA: zakłada kolejność kolumn zgodną z SELECT-em w [`run`] — jeśli
    /// zmieniasz SELECT (dodajesz/przestawiasz kolumnę), zaktualizuj też
    /// tę funkcję ORAZ `nagłówek` CSV (stała liczba 34 kolumn) i tablicę
    /// `fields` w pętli. Kompilator pilnuje tylko długości tablicy CSV —
    /// zgodności z SELECT-em NIE, bo to pozycyjne `row.get(N)?`.
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(FileRecord {
            relative_path: row.get(0)?,
            found_in_ufs: row.get(1)?,
            found_in_script: row.get(2)?,
            size_ufs: row.get(3)?,
            size_script: row.get(4)?,
            size_match: row.get(5)?,
            hash_ufs: row.get(6)?,
            hash_script: row.get(7)?,
            hash_match: row.get(8)?,
            fuzzy_match_pct: row.get(9)?,
            zeros_pct_ufs: row.get(10)?,
            zeros_pct_script: row.get(11)?,
            eof_ok_ufs: row.get(12)?,
            eof_ok_script: row.get(13)?,
            entropy_ufs: row.get(14)?,
            entropy_script: row.get(15)?,
            utf8_ok_ufs: row.get(16)?,
            utf8_ok_script: row.get(17)?,
            structure_ok_ufs: row.get(18)?,
            structure_ok_script: row.get(19)?,
            exif_ok_ufs: row.get(20)?,
            exif_ok_script: row.get(21)?,
            media_decoded_ufs: row.get(22)?,
            media_decoded_script: row.get(23)?,
            has_xattr_ufs: row.get(24)?,
            has_xattr_script: row.get(25)?,
            io_error_ufs: row.get(26)?,
            io_error_script: row.get(27)?,
            yara_match_ufs: row.get(28)?,
            yara_match_script: row.get(29)?,
            repaired_path_ufs: row.get(30)?,
            repaired_path_script: row.get(31)?,
            repair_log_ufs: row.get(32)?,
            repair_log_script: row.get(33)?,
            smart_splice_path: row.get(34)?,
            video_ok_ufs: row.get(35)?,
            video_ok_script: row.get(36)?,
            video_reason_ufs: row.get(37)?,
            video_reason_script: row.get(38)?,
        })
    }
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
        let rule = yara_u
            .or(yara_s)
            .unwrap_or_else(|| "Nieznana Reguła".to_string());
        return Evaluation {
            status: "ZAINFEKOWANY (MALWARE)".to_string(),
            recommendation: "KWARANTANNA - Plik zawiera złośliwy kod lub notatkę hakerską!"
                .to_string(),
            yara_rule: rule,
        };
    }

    // PRIORYTET: Plik złożony przez Fazę 18 (Smart Splice) z fragmentów OBU
    // kopii — ten sam priorytet ("NAJWYŻSZY PO YARA") co w `phase9::decide_winner`.
    // Bez tego sprawdzenia plik pomyślnie złożony przez Fazę 18 dostawał tu
    // gwarantowaną rekomendację odrzucenia (kolumny structure_ok_*/media_decoded_*
    // wciąż pokazują stan SPRZED złożenia), mimo że system sam uznaje go za
    // w pełni odzyskany.
    if record.smart_splice_path.is_some() {
        return Evaluation {
            status: "ZREKONSTRUOWANY (SMART SPLICE)".to_string(),
            recommendation:
                "Użyć wersji złożonej (Smart Splice) - plik zrekonstruowany z fragmentów obu kopii"
                    .to_string(),
            yara_rule: "Brak".to_string(),
        };
    }

    // PRIORYTET NAPRAWCZY: Plik odratowany przez Fazę 17
    if record.repaired_path_ufs.is_some() || record.repaired_path_script.is_some() {
        let action = record
            .repair_log_ufs
            .as_deref()
            .or(record.repair_log_script.as_deref())
            .unwrap_or("Zrekonstruowano plik");
        return Evaluation {
            status: "ZREKONSTRUOWANY (NAPRAWIONY)".to_string(),
            recommendation: format!("Użyć wersji zrekonstruowanej (.repaired) - {}", action),
            yara_rule: "Brak".to_string(),
        };
    }

    // 1. Błędy fizyczne I/O (Bad Sectory)
    if record.io_error_ufs == Some(true) && record.io_error_script == Some(true) {
        return Evaluation {
            status: "BŁĄD ODCZYTU (I/O)".to_string(),
            recommendation: "Odrzucić - Plik widmo. Fizyczne uszkodzenie sektorów.".to_string(),
            yara_rule: "Brak".to_string(),
        };
    }

    // 2. Wydmuszki (Zera / FF po TRIM)
    let zeros_u = record.zeros_pct_ufs.unwrap_or(0.0);
    let zeros_s = record.zeros_pct_script.unwrap_or(0.0);
    if zeros_u > 99.0 || zeros_s > 99.0 {
        return Evaluation {
            status: "USZKODZONY (WYDMUSZKA)".to_string(),
            recommendation: "Odrzucić - plik wypełniony w >99% pustymi blokami".to_string(),
            yara_rule: "Brak".to_string(),
        };
    }

    // 3. Walidacja wizualna (Gray Banding / Przepełnienie)
    if record.media_decoded_ufs == Some(false) || record.media_decoded_script == Some(false) {
        return Evaluation {
            status: "USZKODZONY (UCIĘTY OBRAZ)".to_string(),
            recommendation: "Odrzucić - niedekodowalny obraz / wideo (Gray Banding)".to_string(),
            yara_rule: "Brak".to_string(),
        };
    }

    // 3b. Diagnostyka kontenera wideo (Faza 19) — MP4/MOV/MKV/TS z uszkodzoną
    // strukturą. Wcześniej Faza 8 w ogóle nie znała tych kolumn, więc
    // uszkodzenia kontenerów wideo wykryte przez Fazę 19 nigdy nie wpływały
    // na Status_Decyzyjny.
    if record.video_ok_ufs == Some(false) || record.video_ok_script == Some(false) {
        let powod = record
            .video_reason_ufs
            .clone()
            .or_else(|| record.video_reason_script.clone())
            .unwrap_or_else(|| "uszkodzona struktura kontenera wideo".to_string());
        return Evaluation {
            status: "USZKODZONY (KONTENER WIDEO)".to_string(),
            recommendation: format!("Odrzucić - {}", powod),
            yara_rule: "Brak".to_string(),
        };
    }

    // 4. Walidacja kodowania znaków (UTF-8 / Zupa Binarna)
    if record.utf8_ok_ufs == Some(false) || record.utf8_ok_script == Some(false) {
        return Evaluation {
            status: "USZKODZONY (BINARNY ŚMIEĆ)".to_string(),
            recommendation: "Odrzucić - plik rzekomo tekstowy zawiera niedozwolone znaki binarne"
                .to_string(),
            yara_rule: "Brak".to_string(),
        };
    }

    // 5. Walidacja struktury kontenerów (ZIP/DOCX/APK)
    if record.structure_ok_ufs == Some(false) || record.structure_ok_script == Some(false) {
        return Evaluation {
            status: "USZKODZONY (ZŁA STRUKTURA)".to_string(),
            recommendation: "Odrzucić - dokument/archiwum nie posiada kluczowej tablicy EOCD"
                .to_string(),
            yara_rule: "Brak".to_string(),
        };
    }

    // 6. Walidacja EXIF
    if record.exif_ok_ufs == Some(false) || record.exif_ok_script == Some(false) {
        return Evaluation {
            status: "USZKODZONY (BŁĘDNY EXIF)".to_string(),
            recommendation: "Odrzucić - zdjęcie/wideo posiada zepsutą strukturę EXIF".to_string(),
            yara_rule: "Brak".to_string(),
        };
    }

    // 7. Sygnatury EOF
    if record.eof_ok_ufs == Some(false) || record.eof_ok_script == Some(false) {
        return Evaluation {
            status: "USZKODZONY (BRAK EOF)".to_string(),
            recommendation: "Sprawdzić ręcznie - marker końca pliku zaginął. Ucięcie.".to_string(),
            yara_rule: "Brak".to_string(),
        };
    }

    // 8. Entropia Shannona
    let ent_u = record.entropy_ufs.unwrap_or(4.0);
    let ent_s = record.entropy_script.unwrap_or(4.0);
    if ent_u > 7.995 || ent_s > 7.995 {
        return Evaluation {
            status: "PODEJRZANY (WYSOKA ENTROPIA)".to_string(),
            recommendation: "Ostrzeżenie - skrajny stopień chaosu (Biały Szum)".to_string(),
            yara_rule: "Brak".to_string(),
        };
    }
    if (ent_u < 1.0 && ent_u > 0.0) || (ent_s < 1.0 && ent_s > 0.0) {
        return Evaluation {
            status: "PODEJRZANY (NISKA ENTROPIA)".to_string(),
            recommendation: "Ostrzeżenie - nienaturalnie niska złożoność (Pusta Pamięć)"
                .to_string(),
            yara_rule: "Brak".to_string(),
        };
    }

    // 9. Ostateczne porównanie wersji
    if record.found_in_ufs && record.found_in_script {
        match (record.size_match, record.hash_match) {
            (Some(true), Some(true)) => Evaluation {
                status: "ZGODNY".to_string(),
                recommendation: "Zachować - obydwa programy odzyskały w 100% identyczny plik"
                    .to_string(),
                yara_rule: "Brak".to_string(),
            },
            (Some(true), Some(false)) => {
                if let Some(pct) = record.fuzzy_match_pct {
                    if pct >= 90.0 {
                        Evaluation {
                            status: format!("RÓŻNY HASH (PODOBNE W {:.0}%)", pct),
                            recommendation: "Zachować. Ostrzeżenie: Pliki bardzo podobne"
                                .to_string(),
                            yara_rule: "Brak".to_string(),
                        }
                    } else if pct > 0.0 {
                        Evaluation {
                            status: format!("RÓŻNY HASH (PODOBNE W {:.0}%)", pct),
                            recommendation: "Ostrzeżenie - Pliki mają tylko część wspólną"
                                .to_string(),
                            yara_rule: "Brak".to_string(),
                        }
                    } else {
                        Evaluation {
                            status: "RÓŻNY HASH (FRANKENSTEIN)".to_string(),
                            recommendation: "Krytyczne Ostrzeżenie - Zlepek MFT.".to_string(),
                            yara_rule: "Brak".to_string(),
                        }
                    }
                } else {
                    Evaluation {
                        status: "RÓŻNY HASH".to_string(),
                        recommendation: "Różne kryptograficznie pliki o tej samej wielkości"
                            .to_string(),
                        yara_rule: "Brak".to_string(),
                    }
                }
            }
            (Some(false), _) => Evaluation {
                status: "RÓŻNY ROZMIAR".to_string(),
                recommendation: "Zachować większy plik. Mniejszy plik został ucięty.".to_string(),
                yara_rule: "Brak".to_string(),
            },
            _ => Evaluation {
                status: "BRAK DANYCH".to_string(),
                recommendation: "Brak wystarczających wskaźników".to_string(),
                yara_rule: "Brak".to_string(),
            },
        }
    } else if record.found_in_ufs {
        Evaluation {
            status: "TYLKO UFS".to_string(),
            recommendation: "Skopiować z UFS Explorer - Plik unikalny".to_string(),
            yara_rule: "Brak".to_string(),
        }
    } else if record.found_in_script {
        Evaluation {
            status: "TYLKO SKRYPT".to_string(),
            recommendation: "Skopiować ze Skryptu Autorskiego - Plik unikalny".to_string(),
            yara_rule: "Brak".to_string(),
        }
    } else {
        Evaluation {
            status: "BŁĄD KRYTYCZNY".to_string(),
            recommendation: "Plik widmo (Ghost) - brak dostępu fizycznego".to_string(),
            yara_rule: "Brak".to_string(),
        }
    }
}

// ============================================================================
// NARZĘDZIA EKSPORTOWE (EURO-CSV Z BOM)
// ============================================================================

/// Ucieka wartość do formatu Euro-CSV (separator `;`): jeśli tekst zawiera
/// średnik, cudzysłów lub nową linię, otacza go cudzysłowami i podwaja
/// wewnętrzne cudzysłowy (standard RFC 4180). W przeciwnym razie zwraca
/// tekst bez zmian — nie każda wartość wymaga otoczenia.
///
/// Zwraca [`Cow`] zamiast [`String`], żeby uniknąć alokacji w typowym
/// przypadku (ścieżki, statusy — zdecydowana większość nie zawiera znaków
/// specjalnych). Gałąź `Borrowed` to zero kopii; `Owned` tylko gdy trzeba
/// realnie escapować.
///
/// UWAGA o MSRV: celowo używamy łańcucha `||` zamiast tablicy znaków
/// `[';', '"', '\n', '\r']` w `str::contains`, bo tablica wymaga Rusta 1.71+.
/// Gdy projekt podniesie MSRV — można skrócić.
fn escape_csv(val: &str) -> Cow<'_, str> {
    if val.contains(';') || val.contains('"') || val.contains('\n') || val.contains('\r') {
        Cow::Owned(format!("\"{}\"", val.replace('"', "\"\"")))
    } else {
        Cow::Borrowed(val)
    }
}

/// `Some(true)` → "Tak", `Some(false)` → "Nie", `None` → "Brak" (kolumna nie dotyczy/nie zbadano).
fn fmt_opt_bool(o: Option<bool>) -> String {
    o.map(|b| if b { "Tak" } else { "Nie" })
        .unwrap_or("Brak")
        .to_string()
}
/// Formatuje z 2 miejscami po przecinku, z przecinkiem dziesiętnym (konwencja
/// Euro-CSV/Excel PL) zamiast kropki. `None` → "Brak".
fn fmt_opt_f64(o: Option<f64>) -> String {
    o.map(|f| format!("{:.2}", f).replace('.', ","))
        .unwrap_or_else(|| "Brak".to_string())
}
/// `None` → "Brak", w przeciwnym razie liczba jako tekst.
fn fmt_opt_i64(o: Option<i64>) -> String {
    o.map(|i| i.to_string())
        .unwrap_or_else(|| "Brak".to_string())
}
/// `None` → "Brak", w przeciwnym razie tekst bez zmian (ucieczka CSV robiona osobno przez [`escape_csv`]).
fn fmt_opt_str(o: Option<String>) -> String {
    o.unwrap_or_else(|| "Brak".to_string())
}

// ============================================================================
// MOST BŁĘDÓW I/O → SQL
// ============================================================================

/// Most między [`std::io::Error`] a [`rusqlite::Error`] — pozwala propagować
/// błędy zapisu pliku (CSV, Dziennik Końcowy) przez `?` w funkcji zwracającej
/// `SqlResult<()>`, zamiast kończyć proces panikiem w środku pętli po plikach.
///
/// `ToSqlConversionFailure` to najbliższy semantycznie wariant w
/// `rusqlite::Error` dla "błąd z zewnętrznego źródła" — sam rusqlite nie ma
/// generycznego `External(Box<dyn Error>)`. `Box<dyn Error + Send + Sync>`
/// jest zgodny z wymaganiami rusqlite co do `Send + Sync + 'static`.
fn io_err(e: std::io::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(e))
}

// ============================================================================
// STATYSTYKI PRZEBIEGU (LICZNIKI + MAPY POWODÓW)
// ============================================================================

/// Wszystkie liczniki kategorii i mapy powodów zbierane w trakcie jednego
/// przebiegu Fazy 8. Zamiast 10 luźnych `let mut ... = 0;` w [`run`] i
/// 10-argumentowej funkcji budującej panel, trzymamy to razem w jednej
/// strukturze — kompilator pilnuje, żeby nic nie zginęło przy przekazywaniu,
/// a wywołanie jest jedno: `stats.build_summary_block(i)`.
///
/// `#[derive(Default)]` daje `Stats::default()` = wszystkie zera i puste
/// mapy — dokładnie stan początkowy pętli w [`run`].
#[derive(Debug, Default)]
struct Stats {
    // --- Liczniki kategorii (te same, które trafiają do panelu i Dziennika) ---
    ok: usize,
    suspect: usize,
    reject: usize,
    infected: usize,
    /// Łączna liczba plików ZREKONSTRUOWANYCH (Faza 17 + Faza 18 razem).
    /// Trzymany redundantnie obok `smart_splice` + `naprawiony`, bo jest
    /// używany w Dzienniku Końcowym jako jedna liczba.
    repaired: usize,
    /// Rozbicie `repaired` — Faza 18 (składanie z OBU kopii).
    smart_splice: usize,
    /// Rozbicie `repaired` — Faza 17 (pojedyncze silniki repair_modules).
    naprawiony: usize,

    // --- Mapy powodów (status → liczba wystąpień) ---
    reject_reasons: HashMap<String, usize>,
    suspect_reasons: HashMap<String, usize>,
    yara_rule_counts: HashMap<String, usize>,
}

impl Stats {
    /// Klasyfikuje jeden [`Evaluation`] i zwiększa odpowiednie liczniki
    /// oraz mapy powodów. Wydzielone z pętli w [`run`], żeby:
    /// (a) `run()` zajmował się wyłącznie I/O (odczyt rekordu, zapis CSV, UI),
    /// (b) logika kategoryzacji była testowalna jednostkowo bez SQL i plików,
    /// (c) reguły priorytetu były w jednym miejscu — komentarz o kolejności
    ///     gałęzi obowiązuje TU, nie w pętli.
    ///
    /// Kolejność gałęzi ma znaczenie — pierwsze trafienie wygrywa. NIE
    /// zamieniać miejscami bez zrozumienia priorytetów z [`evaluate_file`]:
    ///   ZAINFEKOWANY > ZREKONSTRUOWANY > USZKODZONY/BŁĄD > PODEJRZANY/RÓŻNY > reszta
    fn zakwalifikuj(&mut self, eval: &Evaluation) {
        // Predykaty złożone (dwa `contains` w OR) wyciągnięte na zmienne —
        // czytelność + jedno miejsce prawdy, gdyby progi się zmieniły.
        let is_reject = eval.status.contains("USZKODZONY") || eval.status.contains("BŁĄD");
        let is_suspect = eval.status.contains("PODEJRZANY") || eval.status.contains("RÓŻNY");

        if eval.status.contains("ZAINFEKOWANY") {
            self.infected += 1;
            *self
                .yara_rule_counts
                .entry(eval.yara_rule.clone())
                .or_insert(0) += 1;
        } else if eval.status.contains("ZREKONSTRUOWANY") {
            self.repaired += 1;
            if eval.status.contains("SMART SPLICE") {
                self.smart_splice += 1;
            } else {
                self.naprawiony += 1;
            }
        } else if is_reject {
            self.reject += 1;
            *self.reject_reasons.entry(eval.status.clone()).or_insert(0) += 1;
        } else if is_suspect {
            self.suspect += 1;
            *self.suspect_reasons.entry(eval.status.clone()).or_insert(0) += 1;
        } else {
            self.ok += 1;
        }
    }

    /// Buduje panel boczny "Podsumowanie na żywo": liczniki kategorii
    /// (Zdrowe/Podejrzane/Odrzucone/Naprawione — rozbite na Smart Splice vs
    /// silnik Fazy 17/Wirusy), wskaźnik zaufania ogólnego (% zdrowych spośród
    /// dotąd ocenionych), oraz do 3 najczęstszych powodów odrzucenia,
    /// podejrzenia i dopasowanych reguł YARA, posortowane malejąco po
    /// liczności. W przeciwieństwie do Faz 1-7 nie ma tu podziału per-źródło
    /// — jeden, wspólny panel dla całego przebiegu (patrz dokumentacja modułu).
    ///
    /// `processed_so_far` to liczba rekordów ocenionych do tej pory —
    /// używana wyłącznie do wyliczenia wskaźnika zaufania. NIE jest częścią
    /// `Stats`, bo zmienia się co iterację pętli, a stan `Stats` narasta
    /// przyrostowo.
    ///
    /// REGRESJA: `suspect` był już liczony w [`run`] i używany w Dzienniku
    /// Końcowym, ale nigdy nie docierał do TEGO panelu — operator widział
    /// "Top powody podejrzeń" (listę), ale nie samą łączną liczbę
    /// podejrzanych plików w trakcie skanowania.
    fn build_summary_block(&self, processed_so_far: usize) -> String {
        let top_reasons = |map: &HashMap<String, usize>| -> String {
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            let s = sorted
                .into_iter()
                .take(3)
                .map(|(reason, count)| format!("{} ({})", reason, count))
                .collect::<Vec<_>>()
                .join(", ");
            if s.is_empty() { "-".to_string() } else { s }
        };

        let confidence = if processed_so_far > 0 {
            (self.ok as f64 / processed_so_far as f64) * 100.0
        } else {
            0.0
        };

        format!(
            "[Podsumowanie]\nZdrowe: {}\nPodejrzane: {}\nOdrzucone: {}\nNaprawione (Smart Splice): {}\nNaprawione (Silnik Fazy 17): {}\nWirusy: {}\nWskaźnik zaufania: {:.1}%\nTop powody odrzuceń: {}\nTop powody podejrzeń: {}\nTop reguły YARA: {}",
            self.ok,
            self.suspect,
            self.reject,
            self.smart_splice,
            self.naprawiony,
            self.infected,
            confidence,
            top_reasons(&self.reject_reasons),
            top_reasons(&self.suspect_reasons),
            top_reasons(&self.yara_rule_counts),
        )
    }
}

// ============================================================================
// GŁÓWNA FUNKCJA (Entrypoint)
// ============================================================================

/// Punkt wejścia Fazy 8, wołany przez `menu::actions::run_phase_with_ui`.
///
/// Przebieg: (1) liczy wszystkie rekordy w `files`; (2) otwiera plik CSV
/// docelowy (`config.csv_report_path`) z UTF-8 BOM i nagłówkiem Euro-CSV;
/// (3) sekwencyjnie iteruje CAŁĄ tabelę (jeden przebieg, bez podziału
/// UFS/Skrypt — patrz dokumentacja modułu), dla każdego rekordu woła
/// [`evaluate_file`], zapisuje wiersz CSV i aktualizuje [`Stats`];
/// (4) po zakończeniu zapisuje Dziennik Końcowy z pełnym rozkładem powodów
/// odrzuceń/podejrzeń/napraw/YARA do pliku i do UI.
///
/// ## Obsługa błędów
///
/// Wszystkie operacje I/O (utworzenie CSV, zapis BOM, nagłówka, wierszy,
/// flush) propagują błąd przez [`io_err`] + `?`. Dzięki temu pojedynczy
/// problem z dyskiem nie zabija procesu panicem w połowie iteracji — błąd
/// wraca do wołającego jako `SqlResult::Err` i tam może być obsłużony
/// (log, UI, retry).
///
/// ## Anulowanie
///
/// [`CANCEL_SIGNAL`] sprawdzany jest na wejściu każdej iteracji. Po wyjściu
/// z pętli (naturalnym lub przez cancel) pasek postępu dostaje FAKTYCZNĄ
/// liczbę przetworzonych rekordów — nie `total_files`. Zapobiega to
/// mylącemu "100% zakończone" przy przerwanym przebiegu.
///
/// Przy anulowaniu Dziennik Końcowy NIE jest zapisywany — funkcja zwraca
/// `Ok(())` wczesnym `return` przed jego budową. CSV zostaje w stanie
/// częściowym (tyle wierszy, ile zdążono zapisać), co jest zamierzone.
#[instrument(skip(conn, config, tx_ui))]
pub fn run(
    conn: &mut Connection,
    config: &Ustawienia,
    tx_ui: mpsc::Sender<PhaseEvent>,
) -> SqlResult<()> {
    CANCEL_SIGNAL.store(false, Ordering::SeqCst);
    let report_path = &config.csv_report_path;

    let _ = tx_ui.send(PhaseEvent::Log(
        "Uruchomiono Fazę 8: Generowanie Raportu i Decyzji Kryminalistycznych (Euro-CSV)."
            .to_string(),
    ));

    let start_time = Instant::now();

    let total_files: usize = conn.query_row("SELECT COUNT(*) FROM files", [], |row| {
        Ok(row.get::<_, i64>(0)? as usize)
    })?;
    if total_files == 0 {
        warn!("Baza danych pusta, brak danych do wygenerowania raportu CSV");
        let _ = tx_ui.send(PhaseEvent::Log(
            "✔ Baza danych jest pusta. Generuję pusty szablon raportu CSV i domykam fazę..."
                .to_string(),
        ));
        // 🟢 UWAGA: Usunięto `return Ok(());`. Kod przechodzi dalej, tworząc
        // pusty plik CSV z nagłówkami i bezpiecznie zamykając paski w interfejsie Ratatui!
    }

    let file = File::create(report_path).map_err(io_err)?;
    let mut writer = BufWriter::new(file);

    writer.write_all(b"\xEF\xBB\xBF").map_err(io_err)?; // UTF-8 BOM

    // Rozbudowany nagłówek o Akcje Naprawcze. 34 kolumny — MUSI się zgadzać
    // z długością tablicy `fields` w pętli poniżej. Kompilator tego nie
    // sprawdza (bo nagłówek to `&str`), ale test integracyjny
    // `test_run_generates_csv_with_header_and_data_rows` to wyłapie.
    writeln!(writer, "Sciezka;Lokacja;Rozmiar_UFS;Rozmiar_Skrypt;Zgodnosc_Rozmiaru;Hash_UFS;Hash_Skrypt;Zgodnosc_Hash;Podobienstwo_Fuzzy_Pct;Zera_UFS_Pct;Zera_Skrypt_Pct;EOF_UFS;EOF_Skrypt;Entropia_UFS;Entropia_Skrypt;UTF8_UFS;UTF8_Skrypt;Struktura_UFS;Struktura_Skrypt;EXIF_UFS;EXIF_Skrypt;Obraz_UFS;Obraz_Skrypt;Xattr_UFS;Xattr_Skrypt;Blad_IO_UFS;Blad_IO_Skrypt;Regula_YARA;Sciezka_Naprawiona_UFS;Sciezka_Naprawiona_Skrypt;Log_Naprawy_UFS;Log_Naprawy_Skrypt;Status_Decyzyjny;Rekomendacja_Silnika").map_err(io_err)?;

    let _ = tx_ui.send(PhaseEvent::SetBar {
        idx: 0,
        label: "Silnik Heurystyczny (Ewaluacja)".to_string(),
        total: total_files as u64,
        color: Color::Yellow,
    });

    // Wszystkie liczniki + mapy powodów w jednej strukturze — patrz `Stats`.
    // `Default` = zera i puste mapy, dokładnie stan startowy.
    let mut stats = Stats::default();

    let mut stmt = conn.prepare(
        "SELECT
            relative_path,
            found_in_ufs,
            found_in_script,
            size_ufs,
            size_script,
            size_match,
            hash_ufs,
            hash_script,
            hash_match,
            fuzzy_match_pct,
            zeros_pct_ufs,
            zeros_pct_script,
            eof_ok_ufs,
            eof_ok_script,
            entropy_ufs,
            entropy_script,
            utf8_ok_ufs,
            utf8_ok_script,
            structure_ok_ufs,
            structure_ok_script,
            exif_ok_ufs,
            exif_ok_script,
            media_decoded_ufs,
            media_decoded_script,
            has_xattr_ufs,
            has_xattr_script,
            io_error_ufs,
            io_error_script,
            yara_match_ufs,
            yara_match_script,
            repaired_path_ufs,
            repaired_path_script,
            repair_log_ufs,
            repair_log_script,
            smart_splice_path,
            video_ok_ufs,
            video_ok_script,
            video_reason_ufs,
            video_reason_script
         FROM files",
    )?;

    // 39 `row.get(N)?` wydzielone do `FileRecord::from_row` — czytelniej
    // i jedno miejsce aktualizacji przy zmianie schematu.
    let records_iter = stmt.query_map([], FileRecord::from_row)?;

    let mut i = 0;
    let mut last_ui_update = Instant::now();

    for record_result in records_iter {
        if CANCEL_SIGNAL.load(Ordering::Relaxed) {
            break;
        }
        let rec = record_result?;
        let eval = evaluate_file(&rec);

        // Cała logika kategoryzacji w jednej metodzie — patrz Stats::zakwalifikuj.
        stats.zakwalifikuj(&eval);

        let lokacja: &'static str = match (rec.found_in_ufs, rec.found_in_script) {
            (true, true) => "Oba",
            (true, false) => "UFS",
            (false, true) => "Skrypt",
            (false, false) => "Brak",
        };

        // Kolejność pól MUSI odpowiadać kolejności kolumn w nagłówku CSV
        // (patrz `writeln!(writer, "Sciezka;Lokacja;...")` wyżej). Tablica o
        // STAŁEJ długości (nie Vec) sprawia, że kompilator sam pilnuje liczby
        // elementów — gdy dojdzie/ujdzie kolumna, dostaniesz błąd tutaj, a nie
        // ciche przesunięcie danych w CSV.
        //
        // `join(";")` zamiast 34 `{}` w `writeln!`:
        //  - separator w jednym miejscu (koniec z liczeniem średników),
        //  - łatwo dodać/usunąć kolumnę,
        //  - jedno `{}` w `writeln!` = jedno miejsce na błąd formatu.
        //
        // `.into_owned()` na `escape_csv(...)`: tablica musi mieć jednorodny
        // typ (String), a `Cow<str>` nie może tu wskazywać na tymczasowe
        // Stringi z `fmt_opt_str(...)` (E0716). Koszt: jedna alokacja na pole
        // z escapowaniem — dokładnie tyle, ile robiła stara wersja escape_csv.
        let fields: [String; 34] = [
            escape_csv(&rec.relative_path).into_owned(),
            lokacja.to_string(),
            fmt_opt_i64(rec.size_ufs),
            fmt_opt_i64(rec.size_script),
            fmt_opt_bool(rec.size_match),
            escape_csv(&fmt_opt_str(rec.hash_ufs)).into_owned(),
            escape_csv(&fmt_opt_str(rec.hash_script)).into_owned(),
            fmt_opt_bool(rec.hash_match),
            fmt_opt_f64(rec.fuzzy_match_pct),
            fmt_opt_f64(rec.zeros_pct_ufs),
            fmt_opt_f64(rec.zeros_pct_script),
            fmt_opt_bool(rec.eof_ok_ufs),
            fmt_opt_bool(rec.eof_ok_script),
            fmt_opt_f64(rec.entropy_ufs),
            fmt_opt_f64(rec.entropy_script),
            fmt_opt_bool(rec.utf8_ok_ufs),
            fmt_opt_bool(rec.utf8_ok_script),
            fmt_opt_bool(rec.structure_ok_ufs),
            fmt_opt_bool(rec.structure_ok_script),
            fmt_opt_bool(rec.exif_ok_ufs),
            fmt_opt_bool(rec.exif_ok_script),
            fmt_opt_bool(rec.media_decoded_ufs),
            fmt_opt_bool(rec.media_decoded_script),
            fmt_opt_bool(rec.has_xattr_ufs),
            fmt_opt_bool(rec.has_xattr_script),
            fmt_opt_bool(rec.io_error_ufs),
            fmt_opt_bool(rec.io_error_script),
            escape_csv(&eval.yara_rule).into_owned(),
            escape_csv(&fmt_opt_str(rec.repaired_path_ufs)).into_owned(),
            escape_csv(&fmt_opt_str(rec.repaired_path_script)).into_owned(),
            escape_csv(&fmt_opt_str(rec.repair_log_ufs)).into_owned(),
            escape_csv(&fmt_opt_str(rec.repair_log_script)).into_owned(),
            escape_csv(&eval.status).into_owned(),
            escape_csv(&eval.recommendation).into_owned(),
        ];
        writeln!(writer, "{}", fields.join(";")).map_err(io_err)?;

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
                text: stats.build_summary_block(i),
            });
        }
    }

    writer.flush().map_err(io_err)?;

    // REGRESJA (poprzednia wersja): pasek zawsze dostawał `total_files` i
    // komunikat "100% zakończona", nawet gdy user anulował w połowie —
    // operator widział sprzeczność ("100%" + "Przerwano" w logu). Teraz
    // stan końcowy zależy od `cancelled` i pokazuje FAKTYCZNĄ liczbę
    // przetworzonych rekordów.
    let cancelled = CANCEL_SIGNAL.load(Ordering::SeqCst);
    let (final_current, final_message) = if cancelled {
        (
            i as u64,
            format!(
                "🛑 Przerwano — przetworzono {} z {} plików.",
                i, total_files
            ),
        )
    } else {
        (
            total_files as u64,
            "Ewaluacja CSV w 100% zakończona.".to_string(),
        )
    };

    let _ = tx_ui.send(PhaseEvent::UpdateBar {
        idx: 0,
        current: final_current,
        message: final_message,
    });
    let _ = tx_ui.send(PhaseEvent::UpdateSideText {
        idx: 0,
        text: stats.build_summary_block(i),
    });

    if cancelled {
        let _ = tx_ui.send(PhaseEvent::Log(
            "🛑 Przerwano przez użytkownika.".to_string(),
        ));
        return Ok(());
    }

    // --- RAPORT KOŃCOWY DUAL-LOGGING ---
    let raport_cfg = config
        .raporty_faz
        .get("Faza 8")
        .cloned()
        .unwrap_or_else(|| crate::settings::RaportFazy {
            katalog: config.log_path.clone(),
            plik_operacyjny: "raport_operacyjny_faza8.txt".to_string(),
            plik_dziennika: "dziennik_koncowy_faza8.txt".to_string(),
        });

    // Best-effort: jeśli katalog nie powstanie (np. istnieje jako plik),
    // i tak spróbujemy zapisać CSV poniżej — błąd wyjdzie dopiero przy
    // File::create. Świadomie NIE propagujemy go przez `?`, żeby brak
    // katalogu nie przerywał Fazy 8 przed próbą zapisu.
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    // Ten sam znacznik czasu co pozostałe fazy (patrz `utils::stamp_filename`)
    // — kolejne uruchomienia się nie nadpisują.
    let dz_path = Path::new(&raport_cfg.katalog).join(crate::utils::stamp_filename(
        &raport_cfg.plik_dziennika,
        &crate::utils::run_timestamp(),
    ));

    let elapsed = start_time.elapsed();
    let mut log_out = String::new();
    use std::fmt::Write as FmtWrite;

    let _ = writeln!(
        &mut log_out,
        "=========================================================================="
    );
    let _ = writeln!(
        &mut log_out,
        "DZIENNIK KOŃCOWY - FAZA 8 (PODSUMOWANIE HEURYSTYKI I DECYZJE)"
    );
    let _ = writeln!(&mut log_out, "Czas trwania: {:.2?}", elapsed);
    let _ = writeln!(
        &mut log_out,
        "==========================================================================\n"
    );

    let _ = writeln!(&mut log_out, "Pomyślnie oceniono plików łącznie: {}\n", i);
    let _ = writeln!(
        &mut log_out,
        "[ 🦠 ] Pliki Zainfekowane (Malware/Ransomware): {}",
        stats.infected
    );
    let _ = writeln!(
        &mut log_out,
        "[ 🛠️ ] Pliki Zrekonstruowane (Aktywna Naprawa): {}",
        stats.repaired
    );
    let _ = writeln!(
        &mut log_out,
        "[ ✔ ] Pliki w 100% Zdrowe (Zgodne lub Unikalne): {}",
        stats.ok
    );
    let _ = writeln!(
        &mut log_out,
        "[ ⚠ ] Pliki Podejrzane (Częściowe anomalie):     {}",
        stats.suspect
    );
    let _ = writeln!(
        &mut log_out,
        "[ ✖ ] Pliki Odrzucone (Bezużyteczne Śmieci):     {}\n",
        stats.reject
    );

    // PRZYWRÓCONE: Zestawienie uszkodzeń ucięte w nowej wersji
    if !stats.reject_reasons.is_empty() {
        let _ = writeln!(
            &mut log_out,
            "SZCZEGÓŁOWE ROZBICIE KATEGORII ODRZUTÓW (Pliki Śmieciowe):"
        );
        let mut sorted_rejections: Vec<_> = stats.reject_reasons.iter().collect();
        sorted_rejections.sort_by(|a, b| b.1.cmp(a.1));
        for (reason, count) in sorted_rejections {
            let _ = writeln!(&mut log_out, "   -> {}: {} plików", reason, count);
        }
        let _ = writeln!(&mut log_out);
    }

    if !stats.suspect_reasons.is_empty() {
        let _ = writeln!(&mut log_out, "SZCZEGÓŁOWE ROZBICIE KATEGORII PODEJRZANYCH:");
        let mut sorted_suspects: Vec<_> = stats.suspect_reasons.iter().collect();
        sorted_suspects.sort_by(|a, b| b.1.cmp(a.1));
        for (reason, count) in sorted_suspects {
            let _ = writeln!(&mut log_out, "   -> {}: {} plików", reason, count);
        }
        let _ = writeln!(&mut log_out);
    }

    // REGRESJA: wcześniej operator widział tylko łączną liczbę
    // "Zrekonstruowanych", bez rozbicia na dwa mechanizmy. Teraz — gdy
    // cokolwiek zostało naprawione — pokazujemy jawne rozbicie Smart Splice
    // (Faza 18) vs silnik naprawczy (Faza 17).
    if stats.repaired > 0 {
        let _ = writeln!(
            &mut log_out,
            "ROZBICIE REKONSTRUKCJI ({} łącznie):",
            stats.repaired
        );
        let _ = writeln!(
            &mut log_out,
            "   -> Smart Splice (Faza 18, składanie z OBU kopii): {}",
            stats.smart_splice
        );
        let _ = writeln!(
            &mut log_out,
            "   -> Silnik naprawczy (Faza 17, pojedyncze moduły): {}",
            stats.naprawiony
        );
        let _ = writeln!(&mut log_out);
    }

    // REGRESJA: wcześniej reguły YARA nigdy nie trafiały do Dziennika
    // Końcowego — operator widział tylko łączną liczbę zainfekowanych
    // plików, bez informacji, KTÓRE reguły zadziałały. Teraz — gdy
    // cokolwiek dopasowano — pokazujemy rozkład malejąco po liczności.
    if !stats.yara_rule_counts.is_empty() {
        let _ = writeln!(&mut log_out, "DOPASOWANE REGUŁY YARA:");
        let mut sorted_yara: Vec<_> = stats.yara_rule_counts.iter().collect();
        sorted_yara.sort_by(|a, b| b.1.cmp(a.1));
        for (rule, count) in sorted_yara {
            let _ = writeln!(&mut log_out, "   -> {}: {} plików", rule, count);
        }
        let _ = writeln!(&mut log_out);
    }

    // Best-effort: brak dostępu do dziennika nie przerywa Fazy 8 — CSV już
    // jest zapisany, a dziennik to dodatek. Cichy `if let Ok` jest tu
    // świadomym wyborem (nie przez `?`).
    if let Ok(mut f) = std::fs::File::create(&dz_path) {
        let _ = f.write_all(log_out.as_bytes());
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "✔ Zapisano fizyczny Dziennik Końcowy w: {}",
            dz_path.display()
        )));
        let _ = tx_ui.send(PhaseEvent::Log(format!(
            "✔ Zapisano kompletny arkusz Euro-CSV w: {}",
            report_path
        )));
    }

    // Wysyłamy również do Ratatui Log Panel
    for line in log_out.lines() {
        let _ = tx_ui.send(PhaseEvent::Log(line.to_string()));
    }

    // Zrzut telemetrii do głównego pliku logów w tle. Składnia `field = value`
    // (nie skrót `field`), bo `stats.ok` nie może być skrócone do samego `ok`.
    info!(
        report_path,
        total_files,
        ok_count = stats.ok,
        repaired_count = stats.repaired,
        suspect_count = stats.suspect,
        to_reject_count = stats.reject,
        infected_count = stats.infected,
        "Faza 8 zakończona"
    );

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

/// Dziennik Końcowy niesie teraz znacznik czasu w nazwie (patrz
/// `utils::stamp_filename`) — testy (w `mod tests` i `mod integration_tests`)
/// nie mogą już czytać stałej nazwy pliku, muszą odnaleźć go po prefiksie w
/// katalogu logów.
#[cfg(test)]
fn znajdz_dziennik_koncowy_faza8(log_dir: &Path) -> std::path::PathBuf {
    std::fs::read_dir(log_dir)
        .expect("Nie można odczytać katalogu logów")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("dziennik_koncowy_faza8"))
        })
        .expect("Dziennik Końcowy (ze znacznikiem czasu) musi powstać w katalogu logów")
}

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
            smart_splice_path: None,
            video_ok_ufs: None,
            video_ok_script: None,
            video_reason_ufs: None,
            video_reason_script: None,
        }
    }

    // ------------------------------------------------------------------
    // Priorytet 0: YARA (wygrywa nad wszystkim innym)
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_yara_match_ufs_is_infected() {
        let r = FileRecord {
            yara_match_ufs: Some("EICAR_Test".to_string()),
            ..base_clean_record()
        };
        let eval = evaluate_file(&r);
        assert_eq!(eval.status, "ZAINFEKOWANY (MALWARE)");
        assert_eq!(eval.yara_rule, "EICAR_Test");
    }

    #[test]
    fn test_evaluate_yara_match_script_is_infected() {
        let r = FileRecord {
            yara_match_script: Some("Trojan.Generic".to_string()),
            ..base_clean_record()
        };
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
        assert_eq!(
            eval.status, "ZAINFEKOWANY (MALWARE)",
            "YARA musi wygrać nawet przy błędzie I/O na obu stronach"
        );
    }

    #[test]
    fn test_evaluate_yara_wins_over_repair() {
        let r = FileRecord {
            yara_match_ufs: Some("Malware.Y".to_string()),
            repaired_path_ufs: Some("plik.repaired".to_string()),
            ..base_clean_record()
        };
        let eval = evaluate_file(&r);
        assert_eq!(
            eval.status, "ZAINFEKOWANY (MALWARE)",
            "YARA musi wygrać nawet nad rekonstrukcją Fazy 17"
        );
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
        let r = FileRecord {
            repaired_path_script: Some("x.repaired".to_string()),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "ZREKONSTRUOWANY (NAPRAWIONY)");
    }

    // ------------------------------------------------------------------
    // Priorytet 2: Błąd I/O TYLKO gdy obie strony zawiodły jednocześnie
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_io_error_both_sides_rejected() {
        let r = FileRecord {
            io_error_ufs: Some(true),
            io_error_script: Some(true),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "BŁĄD ODCZYTU (I/O)");
    }

    #[test]
    fn test_evaluate_io_error_only_one_side_does_not_trigger_rejection() {
        // Błąd tylko po jednej stronie NIE powinien dać "BŁĄD ODCZYTU (I/O)" -
        // ocena przechodzi dalej do finalnego porównania wersji.
        let r = FileRecord {
            io_error_ufs: Some(true),
            ..base_clean_record()
        };
        assert_ne!(evaluate_file(&r).status, "BŁĄD ODCZYTU (I/O)");
    }

    // ------------------------------------------------------------------
    // Priorytet 3: Wydmuszka (>99% zer)
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_wydmuszka_ufs() {
        let r = FileRecord {
            zeros_pct_ufs: Some(99.5),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (WYDMUSZKA)");
    }

    #[test]
    fn test_evaluate_wydmuszka_script() {
        let r = FileRecord {
            zeros_pct_script: Some(100.0),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (WYDMUSZKA)");
    }

    #[test]
    fn test_evaluate_zeros_exactly_99_percent_not_wydmuszka() {
        // Próg to ŚCIŚLE > 99.0, więc dokładnie 99.0 nie powinno się kwalifikować
        let r = FileRecord {
            zeros_pct_ufs: Some(99.0),
            ..base_clean_record()
        };
        assert_ne!(evaluate_file(&r).status, "USZKODZONY (WYDMUSZKA)");
    }

    // ------------------------------------------------------------------
    // Priorytety 4-8: pojedyncze walidacje strukturalne
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_media_decode_failure() {
        let r = FileRecord {
            media_decoded_ufs: Some(false),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (UCIĘTY OBRAZ)");
    }

    #[test]
    fn test_evaluate_utf8_failure() {
        let r = FileRecord {
            utf8_ok_script: Some(false),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (BINARNY ŚMIEĆ)");
    }

    #[test]
    fn test_evaluate_structure_failure() {
        let r = FileRecord {
            structure_ok_ufs: Some(false),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (ZŁA STRUKTURA)");
    }

    #[test]
    fn test_evaluate_exif_failure() {
        let r = FileRecord {
            exif_ok_script: Some(false),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (BŁĘDNY EXIF)");
    }

    #[test]
    fn test_evaluate_eof_failure() {
        let r = FileRecord {
            eof_ok_ufs: Some(false),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (BRAK EOF)");
    }

    // ------------------------------------------------------------------
    // Priorytet 9: Entropia skrajna
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_high_entropy_is_suspect() {
        let r = FileRecord {
            entropy_ufs: Some(7.999),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "PODEJRZANY (WYSOKA ENTROPIA)");
    }

    #[test]
    fn test_evaluate_entropy_exactly_threshold_not_suspect() {
        // Próg to ŚCIŚLE > 7.995
        let r = FileRecord {
            entropy_ufs: Some(7.995),
            ..base_clean_record()
        };
        assert_ne!(evaluate_file(&r).status, "PODEJRZANY (WYSOKA ENTROPIA)");
    }

    #[test]
    fn test_evaluate_low_entropy_is_suspect() {
        let r = FileRecord {
            entropy_script: Some(0.5),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "PODEJRZANY (NISKA ENTROPIA)");
    }

    #[test]
    fn test_evaluate_entropy_exactly_zero_not_suspect() {
        // Wykluczone jawnie (`ent_u > 0.0`) - zero to inna kategoria (wydmuszka, sprawdzana wcześniej)
        let r = FileRecord {
            entropy_ufs: Some(0.0),
            ..base_clean_record()
        };
        assert_ne!(evaluate_file(&r).status, "PODEJRZANY (NISKA ENTROPIA)");
    }

    #[test]
    fn test_evaluate_entropy_exactly_one_not_suspect() {
        // Próg górny to ŚCIŚLE < 1.0
        let r = FileRecord {
            entropy_ufs: Some(1.0),
            ..base_clean_record()
        };
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
        let r = FileRecord {
            hash_match: Some(false),
            fuzzy_match_pct: Some(95.0),
            ..base_clean_record()
        };
        let eval = evaluate_file(&r);
        assert!(eval.status.starts_with("RÓŻNY HASH (PODOBNE W"));
        assert!(eval.status.contains("95"));
    }

    #[test]
    fn test_evaluate_different_hash_partial_fuzzy_match() {
        let r = FileRecord {
            hash_match: Some(false),
            fuzzy_match_pct: Some(40.0),
            ..base_clean_record()
        };
        let eval = evaluate_file(&r);
        assert!(eval.status.starts_with("RÓŻNY HASH (PODOBNE W"));
        assert!(eval.recommendation.contains("tylko część wspólną"));
    }

    #[test]
    fn test_evaluate_different_hash_zero_fuzzy_is_frankenstein() {
        let r = FileRecord {
            hash_match: Some(false),
            fuzzy_match_pct: Some(0.0),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "RÓŻNY HASH (FRANKENSTEIN)");
    }

    #[test]
    fn test_evaluate_different_hash_no_fuzzy_data() {
        let r = FileRecord {
            hash_match: Some(false),
            fuzzy_match_pct: None,
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "RÓŻNY HASH");
    }

    #[test]
    fn test_evaluate_different_size_overrides_hash_result() {
        // Różny rozmiar ma priorytet w dopasowaniu match - niezależnie od hash_match
        let r = FileRecord {
            size_match: Some(false),
            hash_match: Some(true),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "RÓŻNY ROZMIAR");
    }

    #[test]
    fn test_evaluate_missing_comparison_data() {
        let r = FileRecord {
            size_match: None,
            hash_match: None,
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "BRAK DANYCH");
    }

    #[test]
    fn test_evaluate_only_in_ufs() {
        let r = FileRecord {
            found_in_ufs: true,
            found_in_script: false,
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "TYLKO UFS");
    }

    #[test]
    fn test_evaluate_only_in_script() {
        let r = FileRecord {
            found_in_ufs: false,
            found_in_script: true,
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "TYLKO SKRYPT");
    }

    #[test]
    fn test_evaluate_ghost_file_found_nowhere() {
        let r = FileRecord {
            found_in_ufs: false,
            found_in_script: false,
            ..base_clean_record()
        };
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
        assert_eq!(
            escape_csv("powiedział \"cześć\""),
            "\"powiedział \"\"cześć\"\"\""
        );
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
    // Stats::zakwalifikuj — klasyfikacja pojedynczego Evaluation
    // ------------------------------------------------------------------

    fn eval_with(status: &str, yara: &str) -> Evaluation {
        Evaluation {
            status: status.to_string(),
            recommendation: "rekomendacja testowa".to_string(),
            yara_rule: yara.to_string(),
        }
    }

    #[test]
    fn test_zakwalifikuj_infected_increments_infected_and_yara_map() {
        let mut stats = Stats::default();
        stats.zakwalifikuj(&eval_with("ZAINFEKOWANY (MALWARE)", "EICAR_Test"));
        assert_eq!(stats.infected, 1);
        assert_eq!(stats.ok, 0);
        assert_eq!(stats.yara_rule_counts.get("EICAR_Test"), Some(&1));
    }

    #[test]
    fn test_zakwalifikuj_smart_splice_splits_repaired_counter() {
        let mut stats = Stats::default();
        stats.zakwalifikuj(&eval_with("ZREKONSTRUOWANY (SMART SPLICE)", "Brak"));
        assert_eq!(stats.repaired, 1);
        assert_eq!(stats.smart_splice, 1);
        assert_eq!(stats.naprawiony, 0);
    }

    #[test]
    fn test_zakwalifikuj_naprawiony_splits_repaired_counter() {
        let mut stats = Stats::default();
        stats.zakwalifikuj(&eval_with("ZREKONSTRUOWANY (NAPRAWIONY)", "Brak"));
        assert_eq!(stats.repaired, 1);
        assert_eq!(stats.smart_splice, 0);
        assert_eq!(stats.naprawiony, 1);
    }

    #[test]
    fn test_zakwalifikuj_reject_matches_uszkodzony_and_blad() {
        let mut stats = Stats::default();
        stats.zakwalifikuj(&eval_with("USZKODZONY (WYDMUSZKA)", "Brak"));
        stats.zakwalifikuj(&eval_with("BŁĄD ODCZYTU (I/O)", "Brak"));
        assert_eq!(stats.reject, 2);
        assert_eq!(stats.reject_reasons.get("USZKODZONY (WYDMUSZKA)"), Some(&1));
        assert_eq!(stats.reject_reasons.get("BŁĄD ODCZYTU (I/O)"), Some(&1));
    }

    #[test]
    fn test_zakwalifikuj_suspect_matches_podejrzany_and_rozny() {
        let mut stats = Stats::default();
        stats.zakwalifikuj(&eval_with("PODEJRZANY (WYSOKA ENTROPIA)", "Brak"));
        stats.zakwalifikuj(&eval_with("RÓŻNY HASH (FRANKENSTEIN)", "Brak"));
        assert_eq!(stats.suspect, 2);
    }

    #[test]
    fn test_zakwalifikuj_zgodny_is_ok() {
        let mut stats = Stats::default();
        stats.zakwalifikuj(&eval_with("ZGODNY", "Brak"));
        assert_eq!(stats.ok, 1);
        assert_eq!(stats.reject, 0);
        assert_eq!(stats.suspect, 0);
    }

    #[test]
    fn test_zakwalifikuj_infected_beats_reject_when_both_keywords_present() {
        // Sztuczny status z oboma słowami — priorytet ZAINFEKOWANY wygrywa.
        // Chroni przed regresją, gdyby ktoś przestawił kolejność gałęzi.
        let mut stats = Stats::default();
        stats.zakwalifikuj(&eval_with("ZAINFEKOWANY (MALWARE) - USZKODZONY", "Test"));
        assert_eq!(stats.infected, 1);
        assert_eq!(stats.reject, 0);
    }

    #[test]
    fn test_zakwalifikuj_accumulates_across_calls() {
        let mut stats = Stats::default();
        stats.zakwalifikuj(&eval_with("ZGODNY", "Brak"));
        stats.zakwalifikuj(&eval_with("ZGODNY", "Brak"));
        stats.zakwalifikuj(&eval_with("ZAINFEKOWANY (MALWARE)", "R1"));
        stats.zakwalifikuj(&eval_with("ZAINFEKOWANY (MALWARE)", "R1"));
        stats.zakwalifikuj(&eval_with("ZAINFEKOWANY (MALWARE)", "R2"));
        assert_eq!(stats.ok, 2);
        assert_eq!(stats.infected, 3);
        assert_eq!(stats.yara_rule_counts.get("R1"), Some(&2));
        assert_eq!(stats.yara_rule_counts.get("R2"), Some(&1));
    }

    // ------------------------------------------------------------------
    // Stats::build_summary_block — NOWE API (po kroku 8)
    // ------------------------------------------------------------------

    #[test]
    fn test_build_summary_block_reports_counts() {
        let stats = Stats {
            ok: 10,
            suspect: 4,
            reject: 3,
            smart_splice: 1,
            naprawiony: 2,
            infected: 5,
            ..Default::default()
        };
        let block = stats.build_summary_block(20);
        assert!(block.contains("Zdrowe: 10"));
        assert!(block.contains("Podejrzane: 4"));
        assert!(block.contains("Odrzucone: 3"));
        assert!(block.contains("Naprawione (Smart Splice): 1"));
        assert!(block.contains("Naprawione (Silnik Fazy 17): 2"));
        assert!(block.contains("Wirusy: 5"));
        assert!(
            block.contains("Wskaźnik zaufania: 50.0%"),
            "10 zdrowych z 20 ocenionych = 50.0%: {}",
            block
        );
    }

    #[test]
    fn test_build_summary_block_confidence_is_zero_when_nothing_processed() {
        let block = Stats::default().build_summary_block(0);
        assert!(
            block.contains("Wskaźnik zaufania: 0.0%"),
            "dzielenie przez zero musi dać 0.0, nie NaN/panikę: {}",
            block
        );
    }

    #[test]
    fn test_build_summary_block_top_reasons_sorted_by_frequency() {
        let mut stats = Stats {
            reject: 25,
            ..Default::default()
        };
        stats
            .reject_reasons
            .insert("USZKODZONY (WYDMUSZKA)".to_string(), 5);
        stats
            .reject_reasons
            .insert("USZKODZONY (BRAK EOF)".to_string(), 20);

        let block = stats.build_summary_block(25);
        let line = block
            .lines()
            .find(|l| l.starts_with("Top powody odrzuceń:"))
            .expect("Szukany element powinien znajdować się w kolekcji");
        let pos_eof = line
            .find("USZKODZONY (BRAK EOF) (20)")
            .expect("powinien zawierać powód EOF");
        let pos_wydmuszka = line
            .find("USZKODZONY (WYDMUSZKA) (5)")
            .expect("powinien zawierać powód wydmuszki");
        assert!(
            pos_eof < pos_wydmuszka,
            "Częstszy powód powinien być wymieniony pierwszy"
        );
    }

    #[test]
    fn test_build_summary_block_top_yara_rules_sorted_by_frequency() {
        let mut stats = Stats {
            infected: 11,
            ..Default::default()
        };
        stats
            .yara_rule_counts
            .insert("Ransomware_Generic".to_string(), 2);
        stats
            .yara_rule_counts
            .insert("Trojan_Downloader".to_string(), 9);

        let block = stats.build_summary_block(11);
        let line = block
            .lines()
            .find(|l| l.starts_with("Top reguły YARA:"))
            .expect("Szukany element powinien znajdować się w kolekcji");
        let pos_trojan = line
            .find("Trojan_Downloader (9)")
            .expect("powinien zawierać regułę Trojan_Downloader");
        let pos_ransom = line
            .find("Ransomware_Generic (2)")
            .expect("powinien zawierać regułę Ransomware_Generic");
        assert!(
            pos_trojan < pos_ransom,
            "Częściej dopasowana reguła powinna być wymieniona pierwsza"
        );
    }

    #[test]
    fn test_build_summary_block_placeholder_when_no_reasons() {
        let stats = Stats {
            ok: 5,
            ..Default::default()
        };
        let block = stats.build_summary_block(5);
        assert!(block.contains("Top powody odrzuceń: -"));
        assert!(block.contains("Top powody podejrzeń: -"));
        assert!(block.contains("Top reguły YARA: -"));
    }

    // ------------------------------------------------------------------
    // REGRESJA (Gemini review): Faza 8 była ślepa na wynik Fazy 18 (Smart
    // Splice) i Fazy 19 (diagnostyka wideo) — każdy pomyślnie złożony/
    // naprawiony plik dostawał gwarantowaną rekomendację odrzucenia, mimo
    // że system sam uznaje go za w pełni odzyskany.
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_smart_splice_path_present_is_reconstructed_not_rejected() {
        // Celowo z "starymi" structure_ok/media_decoded=false (stan sprzed
        // złożenia) - dokładnie scenariusz z PoC review.
        let r = FileRecord {
            smart_splice_path: Some("_smart_splice_repaired/plik.jpg".to_string()),
            structure_ok_ufs: Some(false),
            media_decoded_ufs: Some(false),
            ..base_clean_record()
        };
        let eval = evaluate_file(&r);
        assert_eq!(eval.status, "ZREKONSTRUOWANY (SMART SPLICE)");
        assert!(!eval.status.contains("USZKODZONY"));
        assert!(!eval.recommendation.to_lowercase().contains("odrzucić"));
    }

    #[test]
    fn test_evaluate_smart_splice_wins_over_repaired_path() {
        let r = FileRecord {
            smart_splice_path: Some("x".to_string()),
            repaired_path_ufs: Some("y".to_string()),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "ZREKONSTRUOWANY (SMART SPLICE)");
    }

    #[test]
    fn test_evaluate_yara_wins_over_smart_splice() {
        let r = FileRecord {
            smart_splice_path: Some("x".to_string()),
            yara_match_ufs: Some("EICAR".to_string()),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "ZAINFEKOWANY (MALWARE)");
    }

    #[test]
    fn test_evaluate_video_ok_false_ufs_is_rejected() {
        let r = FileRecord {
            video_ok_ufs: Some(false),
            video_reason_ufs: Some("Brak tablic indeksowych (moov)".to_string()),
            ..base_clean_record()
        };
        let eval = evaluate_file(&r);
        assert_eq!(eval.status, "USZKODZONY (KONTENER WIDEO)");
        assert!(
            eval.recommendation
                .contains("Brak tablic indeksowych (moov)")
        );
    }

    #[test]
    fn test_evaluate_video_ok_false_script_is_rejected() {
        let r = FileRecord {
            video_ok_script: Some(false),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "USZKODZONY (KONTENER WIDEO)");
    }

    #[test]
    fn test_evaluate_video_ok_true_is_not_rejected() {
        let r = FileRecord {
            video_ok_ufs: Some(true),
            video_ok_script: Some(true),
            ..base_clean_record()
        };
        assert_eq!(evaluate_file(&r).status, "ZGODNY");
    }

    #[test]
    fn test_escape_csv_lone_carriage_return_gets_quoted() {
        let out = escape_csv("linia1\rlinia2");
        assert!(
            out.starts_with('"') && out.ends_with('"'),
            "samotny CR musi wymusić cudzysłów: {}",
            out
        );
    }

    #[test]
    fn test_escape_csv_repair_log_with_semicolon_and_quote_roundtrips_without_column_shift() {
        // Dokładnie PoC z review: log naprawy z nazwą pliku-dawcy zawierającą
        // średnik i cudzysłów.
        let log = r#"donor;"plik z cudzysłowem".jpg"#;
        let escaped = escape_csv(log);

        // Minimalny parser CSV zgodny z RFC4180 - tylko na potrzeby tego testu.
        fn parse_csv_row(row: &str) -> Vec<String> {
            let mut fields = Vec::new();
            let mut current = String::new();
            let mut in_quotes = false;
            let mut chars = row.chars().peekable();
            while let Some(c) = chars.next() {
                match c {
                    '"' if in_quotes && chars.peek() == Some(&'"') => {
                        current.push('"');
                        chars.next();
                    }
                    '"' => in_quotes = !in_quotes,
                    ';' if !in_quotes => {
                        fields.push(std::mem::take(&mut current));
                    }
                    other => current.push(other),
                }
            }
            fields.push(current);
            fields
        }

        let row = format!("PRZED;{};PO", escaped);
        let fields = parse_csv_row(&row);
        assert_eq!(
            fields.len(),
            3,
            "log ze średnikiem/cudzysłowem nie może przesunąć kolumn: {:?}",
            fields
        );
        assert_eq!(fields[0], "PRZED");
        assert_eq!(
            fields[1], log,
            "treść loga musi wrócić bajt w bajt po eskejpowaniu i parsowaniu"
        );
        assert_eq!(fields[2], "PO");
    }

    /// REGRESJA: każda etykieta wiersza w panelu Fazy 8 musi mieć
    /// zarejestrowane wyjaśnienie (`crate::opisy_anomalii`) — w odróżnieniu
    /// od Faz 5/6/7 nie ma tu żadnych generycznych etykiet do pominięcia
    /// (panel Fazy 8 nie ma "Prędkość"/"Błędy I/O" - to jednoprzebiegowy
    /// silnik decyzyjny, nie skaner I/O).
    #[test]
    fn test_etykiety_maja_zarejestrowane_wyjasnienia() {
        let block = Stats::default().build_summary_block(0);

        let mut sprawdzonych = 0;
        for line in block.lines() {
            if line.starts_with('[') {
                continue;
            }
            let Some((etykieta, _)) = line.split_once(": ") else {
                continue;
            };

            assert!(
                crate::opisy_anomalii::znajdz_opis(etykieta).is_some(),
                "etykieta '{}' z panelu Fazy 8 nie ma zarejestrowanego wyjaśnienia",
                etykieta
            );
            sprawdzonych += 1;
        }
        assert_eq!(
            sprawdzonych, 10,
            "panel powinien mieć dokładnie 10 etykiet wymagających wyjaśnienia"
        );
    }
}

// ============================================================================
// TESTY INTEGRACYJNE — run() z SQLite in-memory + tymczasowy katalog
// ============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;
    use rusqlite::{Connection, params};
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    /// Serializuje testy, które manipulują globalnym `CANCEL_SIGNAL`.
    /// Bez tego dwa równoległe testy anulowania (albo cancel + normalny)
    /// mogłyby się wzajemnie sabotować — cargo test domyślnie uruchamia
    /// testy w wielu wątkach. Nie używamy crata `serial_test`, bo to
    /// jedna linia więcej i zero zależności.
    static CANCEL_LOCK: Mutex<()> = Mutex::new(());

    // ------------------------------------------------------------------
    // Pomocnicze: tymczasowy katalog, schema, insert, config
    // ------------------------------------------------------------------

    /// Tymczasowy katalog usuwany w `Drop`. Bez zewnętrznych zależności
    /// (`tempfile` byłby wygodniejszy, ale unikamy dokładania crate tylko
    /// dla testów). Unikalna nazwa = PID + nanos, więc równoległe testy
    /// nie kolidują.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("czas systemowy przed UNIX_EPOCH?")
                .as_nanos();
            let p = std::env::temp_dir().join(format!("phase8_test_{}_{}_{}", tag, pid, nanos));
            std::fs::create_dir_all(&p)
                .unwrap_or_else(|e| panic!("nie udało się utworzyć {:?}: {}", p, e));
            TempDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Schema `files` — dokładnie te 39 kolumn, których oczekuje SELECT
    /// w `run()`. Kolejność ma znaczenie (pozycyjny `row.get(N)` w
    /// `FileRecord::from_row`).
    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().expect("SQLite in-memory");
        conn.execute_batch(
            "CREATE TABLE files (
                relative_path       TEXT NOT NULL,
                found_in_ufs        BOOLEAN NOT NULL,
                found_in_script     BOOLEAN NOT NULL,
                size_ufs            INTEGER,
                size_script         INTEGER,
                size_match          BOOLEAN,
                hash_ufs            TEXT,
                hash_script         TEXT,
                hash_match          BOOLEAN,
                fuzzy_match_pct     REAL,
                zeros_pct_ufs       REAL,
                zeros_pct_script    REAL,
                eof_ok_ufs          BOOLEAN,
                eof_ok_script       BOOLEAN,
                entropy_ufs         REAL,
                entropy_script      REAL,
                utf8_ok_ufs         BOOLEAN,
                utf8_ok_script      BOOLEAN,
                structure_ok_ufs    BOOLEAN,
                structure_ok_script BOOLEAN,
                exif_ok_ufs         BOOLEAN,
                exif_ok_script      BOOLEAN,
                media_decoded_ufs   BOOLEAN,
                media_decoded_script BOOLEAN,
                has_xattr_ufs       BOOLEAN,
                has_xattr_script    BOOLEAN,
                io_error_ufs        BOOLEAN,
                io_error_script     BOOLEAN,
                yara_match_ufs      TEXT,
                yara_match_script   TEXT,
                repaired_path_ufs   TEXT,
                repaired_path_script TEXT,
                repair_log_ufs      TEXT,
                repair_log_script   TEXT,
                smart_splice_path   TEXT,
                video_ok_ufs        BOOLEAN,
                video_ok_script     BOOLEAN,
                video_reason_ufs    TEXT,
                video_reason_script TEXT
            );",
        )
        .expect("CREATE TABLE");
        conn
    }

    /// Wstawia rekord przez `params!` — wartości mapują się 1:1 na kolumny
    /// w tej samej kolejności co SELECT / `FileRecord::from_row`.
    fn insert_record(conn: &Connection, r: &FileRecord) {
        conn.execute(
            "INSERT INTO files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                &r.relative_path,
                r.found_in_ufs,
                r.found_in_script,
                r.size_ufs,
                r.size_script,
                r.size_match,
                &r.hash_ufs,
                &r.hash_script,
                r.hash_match,
                r.fuzzy_match_pct,
                r.zeros_pct_ufs,
                r.zeros_pct_script,
                r.eof_ok_ufs,
                r.eof_ok_script,
                r.entropy_ufs,
                r.entropy_script,
                r.utf8_ok_ufs,
                r.utf8_ok_script,
                r.structure_ok_ufs,
                r.structure_ok_script,
                r.exif_ok_ufs,
                r.exif_ok_script,
                r.media_decoded_ufs,
                r.media_decoded_script,
                r.has_xattr_ufs,
                r.has_xattr_script,
                r.io_error_ufs,
                r.io_error_script,
                &r.yara_match_ufs,
                &r.yara_match_script,
                &r.repaired_path_ufs,
                &r.repaired_path_script,
                &r.repair_log_ufs,
                &r.repair_log_script,
                &r.smart_splice_path,
                r.video_ok_ufs,
                r.video_ok_script,
                &r.video_reason_ufs,
                &r.video_reason_script,
            ],
        )
        .expect("INSERT");
    }

    /// Minimalna konfiguracja do testów `run()`. Wypełnia tylko pola, które
    /// `run()` faktycznie czyta: `csv_report_path`, `log_path`. `raporty_faz`
    /// zostaje puste → `run()` użyje fallbacku z `katalog = log_path`.
    ///
    /// UWAGA: jeśli `Ustawienia` nie ma `#[derive(Default)]` w `settings.rs`,
    /// dopisz je (wszystkie pola są Default-owalne: PathBuf, String, HashMap,
    /// typy liczbowe, bool).
    fn test_config(temp_dir: &Path) -> Ustawienia {
        let mut cfg = Ustawienia::default();
        cfg.csv_report_path = temp_dir.join("raport.csv").to_string_lossy().into_owned();
        cfg.log_path = temp_dir.to_string_lossy().into_owned();

        // `Ustawienia::default()` zawiera wpis "Faza 8" w `raporty_faz`
        // (patrz `default_raporty_faz` w settings.rs) z katalogiem
        // produkcyjnym `./dziennik/fazy`. `run()` robi `get("Faza 8")` →
        // trafia na `Some(...)` → NIE wchodzi w fallback z `log_path`.
        // Skutek: dziennik lądował w `./dziennik/fazy/`, a test szukał go
        // w `temp_dir` — stąd wszystkie błędy "brak dziennika".
        //
        // Czyścimy mapę, żeby `run()` użył fallbacku (`katalog = log_path`,
        // `dziennik_koncowy_faza8.txt`). Nie modyfikujemy `settings.rs`,
        // bo to fix lokalny wyłącznie dla testów Fazy 8.
        cfg.raporty_faz.clear();
        cfg
    }

    /// Bazowy rekord "czysty" — plik obecny po obu stronach, identyczny
    /// rozmiar i hash, brak anomalii. Ten sam co w `mod tests`, ale
    /// zamknięty w tym module, żeby integration_tests były samowystarczalne.
    fn clean_record(path: &str) -> FileRecord {
        FileRecord {
            relative_path: path.to_string(),
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
            smart_splice_path: None,
            video_ok_ufs: None,
            video_ok_script: None,
            video_reason_ufs: None,
            video_reason_script: None,
        }
    }

    /// Minimalny parser CSV (RFC 4180) — tylko na potrzeby testów.
    /// Duplikat z `mod tests::test_escape_csv_repair_log...`, żeby oba
    /// moduły testowe były niezależne.
    fn parse_csv_row(row: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut chars = row.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' if in_quotes && chars.peek() == Some(&'"') => {
                    current.push('"');
                    chars.next();
                }
                '"' => in_quotes = !in_quotes,
                ';' if !in_quotes => {
                    fields.push(std::mem::take(&mut current));
                }
                other => current.push(other),
            }
        }
        fields.push(current);
        fields
    }

    /// Czyta plik CSV i zwraca (nagłówek, wiersze_danych). Obcina BOM
    /// z początku pierwszej linii, żeby porównania były naturalne.
    fn read_csv(path: &Path) -> (String, Vec<String>) {
        let raw = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("nie można odczytać {:?}: {}", path, e));
        let mut lines = raw.lines();
        let header = lines
            .next()
            .expect("CSV bez nagłówka")
            .trim_start_matches('\u{FEFF}')
            .to_string();
        let rows = lines.map(|s| s.to_string()).collect();
        (header, rows)
    }

    // ------------------------------------------------------------------
    // Testy: happy path, pusta baza, kolejność kolumn, eskejpowanie
    // ------------------------------------------------------------------

    #[test]
    fn test_run_generates_csv_with_header_and_data_rows() {
        let tmp = TempDir::new("happy");
        let mut conn = setup_db();
        insert_record(&conn, &clean_record("a.txt"));
        insert_record(&conn, &clean_record("b.txt"));

        let cfg = test_config(tmp.path());
        let (tx, _rx) = mpsc::channel();

        run(&mut conn, &cfg, tx).expect("run() nie powinno zwrócić błędu");

        let csv_path = tmp.path().join("raport.csv");
        let (header, rows) = read_csv(&csv_path);

        assert_eq!(rows.len(), 2, "2 rekordy w bazie = 2 wiersze danych");
        assert_eq!(
            header.split(';').count(),
            34,
            "nagłówek musi mieć 34 kolumny"
        );

        let cols_0 = parse_csv_row(&rows[0]);
        assert_eq!(
            cols_0.len(),
            34,
            "wiersz danych musi mieć 34 kolumny (zgodność z nagłówkiem)"
        );
        assert_eq!(cols_0[0], "a.txt", "pierwsza kolumna = relative_path");
        assert_eq!(
            cols_0[1], "Oba",
            "druga kolumna = lokacja (znaleziony po obu stronach)"
        );
        assert_eq!(
            cols_0[32], "ZGODNY",
            "Status_Decyzyjny = ZGODNY dla czystego rekordu"
        );
    }

    #[test]
    fn test_run_empty_db_creates_csv_with_header_only() {
        let tmp = TempDir::new("empty");
        let mut conn = setup_db();
        // celowo zero INSERT

        let cfg = test_config(tmp.path());
        let (tx, _rx) = mpsc::channel();

        run(&mut conn, &cfg, tx).expect("run() musi obsłużyć pustą bazę bez błędu");

        let csv_path = tmp.path().join("raport.csv");
        let (header, rows) = read_csv(&csv_path);

        assert_eq!(rows.len(), 0, "pusta baza = CSV z samym nagłówkiem");
        assert_eq!(
            header.split(';').count(),
            34,
            "nagłówek musi mieć 34 kolumny"
        );
    }

    #[test]
    fn test_run_counts_reflect_record_statuses_in_final_report() {
        let tmp = TempDir::new("counts");
        let mut conn = setup_db();

        // 1 zdrowy + 1 zainfekowany + 1 odrzucony + 1 podejrzany
        insert_record(&conn, &clean_record("zdrowy.txt"));

        let mut infected = clean_record("wirus.exe");
        infected.yara_match_ufs = Some("EICAR_Test".to_string());
        insert_record(&conn, &infected);

        let mut rejected = clean_record("smiec.bin");
        rejected.zeros_pct_ufs = Some(100.0);
        insert_record(&conn, &rejected);

        let mut suspect = clean_record("podejrzany.bin");
        suspect.entropy_ufs = Some(7.999);
        insert_record(&conn, &suspect);

        let cfg = test_config(tmp.path());
        let (tx, _rx) = mpsc::channel();
        run(&mut conn, &cfg, tx).expect("run()");

        // Dziennik końcowy ląduje w log_path (bo raporty_faz puste → default),
        // ale nazwa niesie teraz znacznik czasu (patrz `utils::stamp_filename`)
        // — szukamy po prefiksie.
        let dz_path = znajdz_dziennik_koncowy_faza8(tmp.path());
        let dz = std::fs::read_to_string(&dz_path)
            .unwrap_or_else(|e| panic!("brak dziennika {:?}: {}", dz_path, e));

        assert!(
            dz.contains("Pliki Zainfekowane (Malware/Ransomware): 1"),
            "dziennik:\n{}",
            dz
        );
        assert!(
            dz.contains("Pliki w 100% Zdrowe (Zgodne lub Unikalne): 1"),
            "dziennik:\n{}",
            dz
        );
        assert!(
            dz.contains("Pliki Podejrzane (Częściowe anomalie):     1"),
            "dziennik:\n{}",
            dz
        );
        assert!(
            dz.contains("Pliki Odrzucone (Bezużyteczne Śmieci):     1"),
            "dziennik:\n{}",
            dz
        );

        assert!(
            dz.contains("USZKODZONY (WYDMUSZKA): 1"),
            "brak rozbicia odrzuceń"
        );
        assert!(
            dz.contains("PODEJRZANY (WYSOKA ENTROPIA): 1"),
            "brak rozbicia podejrzeń"
        );
        assert!(dz.contains("DOPASOWANE REGUŁY YARA:"), "brak sekcji YARA");
        assert!(dz.contains("EICAR_Test: 1"), "brak konkretnej reguły YARA");
    }

    #[test]
    fn test_run_report_contains_reconstruction_breakdown() {
        let tmp = TempDir::new("repaired");
        let mut conn = setup_db();

        // 1 smart splice + 1 naprawiony przez Fazę 17
        let mut smart = clean_record("smart.bin");
        smart.smart_splice_path = Some("out/smart.bin".to_string());
        insert_record(&conn, &smart);

        let mut repaired = clean_record("rep.bin");
        repaired.repaired_path_ufs = Some("out/rep.bin".to_string());
        repaired.repair_log_ufs = Some("naprawiono nagłówek".to_string());
        insert_record(&conn, &repaired);

        let cfg = test_config(tmp.path());
        let (tx, _rx) = mpsc::channel();
        run(&mut conn, &cfg, tx).expect("run()");

        let dz = std::fs::read_to_string(znajdz_dziennik_koncowy_faza8(tmp.path()))
            .expect("dziennik istnieje");

        assert!(
            dz.contains("ROZBICIE REKONSTRUKCJI (2 łącznie):"),
            "dziennik:\n{}",
            dz
        );
        assert!(
            dz.contains("Smart Splice (Faza 18, składanie z OBU kopii): 1"),
            "dziennik:\n{}",
            dz
        );
        assert!(
            dz.contains("Silnik naprawczy (Faza 17, pojedyncze moduły): 1"),
            "dziennik:\n{}",
            dz
        );
    }

    #[test]
    fn test_run_writes_csv_in_same_field_order_as_header() {
        let tmp = TempDir::new("order");
        let mut conn = setup_db();

        // Rekord, który ma różne wartości w każdej kolumnie — łatwo zweryfikować.
        let mut r = clean_record("order_test.dat");
        r.size_ufs = Some(111);
        r.size_script = Some(222);
        r.hash_ufs = Some("hashA".to_string());
        r.hash_script = Some("hashB".to_string());
        r.fuzzy_match_pct = Some(77.5);
        r.entropy_ufs = Some(3.25);
        r.utf8_ok_ufs = Some(true);
        r.media_decoded_script = Some(false); // → USZKODZONY (UCIĘTY OBRAZ)
        insert_record(&conn, &r);

        let cfg = test_config(tmp.path());
        let (tx, _rx) = mpsc::channel();
        run(&mut conn, &cfg, tx).expect("run()");

        let (_, rows) = read_csv(&tmp.path().join("raport.csv"));
        assert_eq!(rows.len(), 1);
        let cols = parse_csv_row(&rows[0]);

        // Sprawdzamy wyrywkowo kilka kolumn — te, które mają unikalne wartości.
        assert_eq!(cols[0], "order_test.dat"); // Sciezka
        assert_eq!(cols[1], "Oba"); // Lokacja
        assert_eq!(cols[2], "111"); // Rozmiar_UFS
        assert_eq!(cols[3], "222"); // Rozmiar_Skrypt
        assert_eq!(cols[5], "hashA"); // Hash_UFS
        assert_eq!(cols[6], "hashB"); // Hash_Skrypt
        assert_eq!(cols[8], "77,50"); // Podobienstwo_Fuzzy_Pct (przecinek!)
        assert_eq!(cols[13], "3,25"); // Entropia_UFS
        assert_eq!(cols[22], "Nie"); // Obraz_Skrypt (media_decoded_script=false)
        assert_eq!(cols[32], "USZKODZONY (UCIĘTY OBRAZ)");
    }

    #[test]
    fn test_run_csv_escapes_semicolon_and_quote_in_path() {
        let tmp = TempDir::new("escape");
        let mut conn = setup_db();

        // Ścieżka z `;` i `"` — musi zostać otoczona cudzysłowami i mieć
        // podwojony wewnętrzny cudzysłów, inaczej parser CSV rozjedzie kolumny.
        let mut r = clean_record("katalog;zły/plik\"x\".txt");
        r.hash_ufs = Some("h1".to_string());
        insert_record(&conn, &r);

        let cfg = test_config(tmp.path());
        let (tx, _rx) = mpsc::channel();
        run(&mut conn, &cfg, tx).expect("run()");

        let (_, rows) = read_csv(&tmp.path().join("raport.csv"));
        let cols = parse_csv_row(&rows[0]);

        assert_eq!(cols.len(), 34, "escapowanie nie może rozjechać kolumn");
        assert_eq!(
            cols[0], "katalog;zły/plik\"x\".txt",
            "ścieżka musi wrócić bajt w bajt"
        );
    }

    #[test]
    fn test_run_creates_final_report_file_even_with_no_data() {
        let tmp = TempDir::new("empty_dz");
        let mut conn = setup_db();

        let cfg = test_config(tmp.path());
        let (tx, _rx) = mpsc::channel();
        run(&mut conn, &cfg, tx).expect("run()");

        // Dziennik końcowy powinien istnieć nawet przy pustej bazie
        // (sekcje z powodami po prostu się nie pojawią — patrz `if !map.is_empty()`).
        let dz_path = znajdz_dziennik_koncowy_faza8(tmp.path());

        let dz = std::fs::read_to_string(&dz_path).expect("Nie można odczytać pliku");
        assert!(dz.contains("DZIENNIK KOŃCOWY - FAZA 8"));
        assert!(dz.contains("Pomyślnie oceniono plików łącznie: 0"));
    }

    // ------------------------------------------------------------------
    // Anulowanie: przerwanie w połowie pętli przez CANCEL_SIGNAL
    // ------------------------------------------------------------------

    #[test]
    fn test_run_honors_cancel_signal_and_reports_partial_progress() {
        // Serializuj — ten test bawi się globalnym CANCEL_SIGNAL.
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let tmp = TempDir::new("cancel");
        let mut conn = setup_db();

        // 20_000 rekordów × ~40µs (zmierzone empirycznie: 500 rekordów < 20ms)
        // ≈ 800 ms — komfortowo więcej niż opóźnienie wątku (5 ms).
        // Wcześniejsze 500 kończyło się przed odpaleniem cancel, przez co
        // run() zapisywał wszystkie wiersze i asercja `rows < TOTAL` padała
        // (komunikat: "po anulowaniu powinno być mniej wierszy niż 500, a jest 500").
        const TOTAL: usize = 20_000;
        for n in 0..TOTAL {
            insert_record(&conn, &clean_record(&format!("plik_{:05}.bin", n)));
        }

        let cfg = test_config(tmp.path());
        let (tx, _rx) = mpsc::channel();

        // Wątek-anulacz: po 5 ms ustawia globalny sygnał. `run()` na starcie
        // robi `CANCEL_SIGNAL.store(false)`, więc musi minąć chwila, żeby
        // nasz `true` nie został skasowany — stąd opóźnienie, a nie
        // natychmiastowy store.
        let canceller = thread::spawn(|| {
            thread::sleep(Duration::from_millis(5));
            CANCEL_SIGNAL.store(true, Ordering::SeqCst);
        });

        let result = run(&mut conn, &cfg, tx);

        // Czekamy na wątek anulujący (żeby nie zostawić go w tle).
        canceller.join().expect("wątek anulujący panikował");

        // RESET — krytyczne. Kolejny test korzystający z CANCEL_SIGNAL
        // (albo normalne uruchomienie w tej samej sesji) musi zacząć od zera.
        CANCEL_SIGNAL.store(false, Ordering::SeqCst);

        result.expect("run() nie powinno zwrócić Err po anulowaniu");

        // 1. CSV musi istnieć i mieć MNIEJ wierszy niż TOTAL (przerwano wcześniej)
        let (header, rows) = read_csv(&tmp.path().join("raport.csv"));
        assert_eq!(header.split(';').count(), 34);
        assert!(
            rows.len() < TOTAL,
            "po anulowaniu powinno być mniej wierszy niż {}, a jest {}",
            TOTAL,
            rows.len()
        );
        assert!(
            rows.len() > 0,
            "anulowanie po 20ms powinno zdążyć przetworzyć choć kilka rekordów"
        );

        // 2. Dziennik końcowy NIE powstaje przy anulowaniu (wczesny return).
        // Nazwa niesie teraz znacznik czasu — szukamy PO PREFIKSIE zamiast
        // zakładać stałą nazwę.
        let znaleziono_dziennik = std::fs::read_dir(tmp.path())
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("dziennik_koncowy_faza8"))
            });
        assert!(
            !znaleziono_dziennik,
            "przy anulowaniu dziennik końcowy nie powinien być zapisany"
        );

        // 3. Każdy wiersz musi mieć 34 kolumny — anulowanie nie może
        //    zostawić „urwanego" wiersza w środku.
        for (idx, row) in rows.iter().enumerate() {
            let cols = parse_csv_row(row);
            assert_eq!(
                cols.len(),
                34,
                "wiersz {} po anulowaniu ma {} kolumn zamiast 34: {:?}",
                idx,
                cols.len(),
                row
            );
        }
    }

    #[test]
    fn test_run_without_cancel_processes_all_records() {
        // Kontrola: ten sam setup co wyżej, ale bez wątku anulującego —
        // wszystkie rekordy muszą trafić do CSV. Chroni przed regresją,
        // gdyby ktoś np. zostawił CANCEL_SIGNAL=true z poprzedniego testu.
        let _guard = CANCEL_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Prewencyjny reset — na wypadek gdyby poprzedni test nie zdążył.
        CANCEL_SIGNAL.store(false, Ordering::SeqCst);

        let tmp = TempDir::new("no_cancel");
        let mut conn = setup_db();

        const TOTAL: usize = 50;
        for n in 0..TOTAL {
            insert_record(&conn, &clean_record(&format!("plik_{:04}.bin", n)));
        }

        let cfg = test_config(tmp.path());
        let (tx, _rx) = mpsc::channel();
        run(&mut conn, &cfg, tx).expect("run() bez anulowania");

        let (_, rows) = read_csv(&tmp.path().join("raport.csv"));
        assert_eq!(
            rows.len(),
            TOTAL,
            "bez anulowania wszystkie {} rekordów powinny trafić do CSV",
            TOTAL
        );

        // Dziennik końcowy MUSI powstać przy normalnym zakończeniu. Nazwa
        // niesie teraz znacznik czasu — szukamy po prefiksie.
        let znaleziono_dziennik = std::fs::read_dir(tmp.path())
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("dziennik_koncowy_faza8"))
            });
        assert!(
            znaleziono_dziennik,
            "bez anulowania dziennik końcowy powinien być zapisany"
        );
    }
}
