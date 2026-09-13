// src/phases/repair_modules/sqlite.rs

//! NAPRAWIONY BUG (martwe scalanie WAL): sukces checkpointu był warunkowany
//! na `conn.execute("PRAGMA wal_checkpoint(TRUNCATE);", []).is_ok()`. Ten
//! pragma ZWRACA wiersz wyniku (`busy`, `log`, `checkpointed`), a
//! `Connection::execute` odrzuca każde zapytanie zwracające wiersze błędem
//! `ExecuteReturnedResults` — warunek był więc ZAWSZE fałszywy i moduł nigdy
//! nie zgłaszał naprawy. Każdy plik bazy z osieroconym `-wal` trafiał do
//! statystyk jako „żaden moduł nie pomógł". Poprawka: `execute_batch`, który
//! ignoruje zwrócone wiersze.
//!
//! Bug przeżył, bo test `test_repair_merges_wal_when_present` zamykał
//! połączenie przed sprawdzeniem — SQLite usuwa wtedy `-wal` — i wychodził
//! wczesnym `return`, nie testując niczego. Test trzyma teraz połączenie
//! otwarte, a osobny test pilnuje samego zachowania `execute` vs `execute_batch`.
//! To ta sama klasa błędu co „martwa naprawa rozszerzeń" opisana w nagłówku
//! Fazy 17.

//! Moduł naprawczy: scalanie osieroconego pliku WAL z główną bazą SQLite.

use super::{RepairContext, RepairModule};
use std::fs;
use std::path::{Path, PathBuf};

pub struct SqliteModule;

impl RepairModule for SqliteModule {
    fn id(&self) -> &'static str { "sqlite" }
    fn display_name(&self) -> &'static str { "Scalenie WAL z bazą SQLite (checkpoint)" }

    /// Stosuje się do plików `.db`/`.sqlite`/`.sqlite3` — decyzja o
    /// obecności odpowiadającego pliku `-wal` zapada dopiero w `repair()`
    /// (wymaga sprawdzenia systemu plików, nie samej diagnostyki bazy).
    fn applies_to(&self, ctx: &RepairContext) -> bool {
        ctx.ext == "db" || ctx.ext == "sqlite" || ctx.ext == "sqlite3"
    }

    /// Kopiuje główny plik bazy i jego `-wal` pod nowe nazwy `_repaired`,
    /// otwiera skopiowaną bazę i wymusza `PRAGMA wal_checkpoint(TRUNCATE)`,
    /// co fizycznie zapisuje zawartość WAL do głównego pliku i pozwala
    /// bezpiecznie usunąć osierocony `-wal`. Zwraca `None`, gdy plik `-wal`
    /// nie istnieje (nic do scalenia) lub checkpoint się nie powiedzie.
    fn repair(&self, source: &Path, _ctx: &RepairContext, _twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let wal_path = source.with_extension(format!("{}-wal", source.extension()?.to_str()?));
        if !wal_path.exists() { return None; }

        let stem = source.file_stem()?.to_str()?;
        let ext = source.extension()?.to_str()?;

        let target_db = katalog_wyjsciowy.join(format!("{}_repaired.{}", stem, ext));
        let target_wal = katalog_wyjsciowy.join(format!("{}_repaired.{}-wal", stem, ext));

        fs::copy(source, &target_db).ok()?;
        fs::copy(&wal_path, &target_wal).ok()?;

        let scalono = match rusqlite::Connection::open(&target_db) {
            Ok(conn) => {
                // `execute_batch`, NIE `execute` — patrz naprawiony bug w
                // dokumentacji modułu. `PRAGMA wal_checkpoint(TRUNCATE)`
                // ZWRACA wiersz, a `Connection::execute` odrzuca każde
                // zapytanie zwracające wiersze błędem `ExecuteReturnedResults`.
                let ok = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").is_ok();
                // Połączenie zamykamy PRZED usunięciem `-wal`, żeby SQLite nie
                // trzymał pliku otwartego ani go nie odtworzył.
                drop(conn);
                ok
            }
            Err(_) => false,
        };

        if !scalono {
            // Nie zostawiamy połowicznego wyniku: skopiowane pliki z sufiksem
            // `_repaired` wyglądałyby na gotową naprawę, którą nie są.
            let _ = fs::remove_file(&target_db);
            let _ = fs::remove_file(&target_wal);
            return None;
        }

        let _ = fs::remove_file(&target_wal);
        Some((target_db, "Zespolono plik WAL z głównym plikiem bazy danych.".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dummy_ctx() -> RepairContext<'static> {
        RepairContext { ext: "db", media_reason: None, utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None }
    }

    #[test]
    fn test_applies_to_known_sqlite_extensions() {
        let m = SqliteModule;
        for ext in ["db", "sqlite", "sqlite3"] {
            let ctx = RepairContext { ext, media_reason: None, utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
            assert!(m.applies_to(&ctx), "powinno pasować dla .{}", ext);
        }
    }

    #[test]
    fn test_does_not_apply_to_unrelated_extension() {
        let m = SqliteModule;
        let ctx = RepairContext { ext: "txt", media_reason: None, utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        assert!(!m.applies_to(&ctx));
    }

    #[test]
    fn test_repair_returns_none_without_wal_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("baza.db");
        // Prawdziwa, pusta baza SQLite bez towarzyszącego -wal
        rusqlite::Connection::open(&path).unwrap();

        let m = SqliteModule;
        assert!(m.repair(&path, &dummy_ctx(), None, dir.path()).is_none());
    }

    /// Tworzy bazę w trybie WAL i ZWRACA otwarte połączenie.
    ///
    /// Połączenie MUSI zostać otwarte przez cały czas trwania testu: czyste
    /// zamknięcie ostatniego połączenia powoduje checkpoint i USUNIĘCIE pliku
    /// `-wal` przez SQLite. Poprzednia wersja testu robiła `drop(conn)` i
    /// sprawdzała, czy `-wal` istnieje — nigdy nie istniał, więc test wychodził
    /// przez wczesny `return` i NIE TESTOWAŁ NICZEGO. To dlatego bug
    /// `ExecuteReturnedResults` (niżej) przeżył niezauważony.
    fn baza_w_trybie_wal(path: &Path) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        conn.execute("CREATE TABLE t (x INTEGER)", []).unwrap();
        conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
        conn
    }

    #[test]
    fn test_repair_merges_wal_when_present() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("baza.db");
        let _zywe_polaczenie = baza_w_trybie_wal(&path);

        assert!(
            dir.path().join("baza.db-wal").exists(),
            "Setup testu: plik -wal MUSI istnieć, inaczej test nie sprawdza nic"
        );

        let m = SqliteModule;
        let result = m.repair(&path, &dummy_ctx(), None, dir.path());
        assert!(result.is_some(), "scalenie powinno się powieść, gdy -wal istnieje");

        let (target, _log) = result.unwrap();
        assert!(target.exists());
        let target_wal = dir.path().join("baza_repaired.db-wal");
        assert!(!target_wal.exists(), "osierocony -wal po scaleniu powinien zostać usunięty");
    }

    /// REGRESJA: `PRAGMA wal_checkpoint(TRUNCATE)` ZWRACA wiersz wyniku
    /// (busy, log, checkpointed), więc `Connection::execute` odrzuca go
    /// błędem `ExecuteReturnedResults`. Poprzednia wersja modułu warunkowała
    /// sukces na `.is_ok()` tego właśnie wywołania — warunek był ZAWSZE
    /// fałszywy, więc moduł nigdy nie zgłaszał naprawy, a każdy plik bazy
    /// lądował w statystykach jako „żaden moduł nie pomógł".
    #[test]
    fn test_pragma_checkpoint_przez_execute_zwraca_blad() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("kontrola.db");
        let conn = baza_w_trybie_wal(&path);

        assert!(
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);", []).is_err(),
            "Gdyby `execute` na tym pragmie przestało zwracać błąd, komentarz w module jest do aktualizacji"
        );
        assert!(
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").is_ok(),
            "`execute_batch` ignoruje zwrócone wiersze i jest tu właściwym wywołaniem"
        );
    }

    /// REGRESJA D1: naprawa nie może zostawić NICZEGO w katalogu źródłowym —
    /// ani skopiowanej bazy `_repaired`, ani jej pliku `-wal`. Ten moduł jest
    /// tu najbardziej narażony, bo tworzy plik towarzyszący.
    #[test]
    fn test_zapisuje_do_wskazanego_katalogu_nie_obok_zrodla() {
        let zrodlo = tempdir().unwrap();
        let wynik = tempdir().unwrap();

        let path = zrodlo.path().join("baza.db");
        let _zywe_polaczenie = baza_w_trybie_wal(&path);

        let m = SqliteModule;
        let (target, _) = m.repair(&path, &dummy_ctx(), None, wynik.path()).expect("scalenie powinno się powieść");

        assert!(target.starts_with(wynik.path()), "Wynik musi leżeć we wskazanym katalogu: {}", target.display());

        // W źródle zostaje tylko oryginalna baza i jej własne pliki WAL/SHM
        // (te są dziełem żywego połączenia z setupu, nie naprawy).
        let w_zrodle: Vec<String> = std::fs::read_dir(zrodlo.path()).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            w_zrodle.iter().all(|n| n.starts_with("baza.db")),
            "Naprawa nie może tworzyć nowych plików w źródle, znalazłem: {:?}", w_zrodle
        );
        assert!(
            !w_zrodle.iter().any(|n| n.contains("_repaired")),
            "Plik _repaired nie może powstać w katalogu źródłowym, znalazłem: {:?}", w_zrodle
        );
    }

    #[test]
    fn test_scalona_baza_jest_odczytywalna_po_naprawie() {
        // Naprawa musi dać bazę, z której realnie da się czytać dane -
        // samo powstanie pliku to za mało.
        let dir = tempdir().unwrap();
        let path = dir.path().join("baza.db");
        let _zywe_polaczenie = baza_w_trybie_wal(&path);

        let m = SqliteModule;
        let (target, _) = m.repair(&path, &dummy_ctx(), None, dir.path()).expect("scalenie powinno się powieść");

        let odczyt = rusqlite::Connection::open(&target).unwrap();
        let x: i64 = odczyt.query_row("SELECT x FROM t", [], |r| r.get(0)).expect("dane muszą być czytelne");
        assert_eq!(x, 1);
    }
}
