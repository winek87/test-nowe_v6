// src/duplicate_finder.rs

//! # Narzędzie: Wykrywanie Dokładnych Duplikatów Treści (BLAKE3)
//!
//! Grupuje pliki po DOKŁADNEJ wartości hasha BLAKE3 (`hash_ufs`/`hash_script`
//! z Faz 3/4), niezależnie od ścieżki — wykrywa przeniesione/zdublowane
//! kopie identycznej zawartości. To dopełnienie Fazy 14 (rozmyte hashowanie
//! ssdeep), nie jej zastępstwo: Faza 14 szuka PODOBNYCH plików (zmienionych
//! o kilka bajtów), to narzędzie szuka BAJT-W-BAJT IDENTYCZNYCH — tańsze
//! obliczeniowo (zwykłe grupowanie, nie porównanie każdy-z-każdym) i dużo
//! silniejszy sygnał tam, gdzie pasuje.
//!
//! ## Wynik zapisany TRWALE w bazie — do ponownego wykorzystania
//! W przeciwieństwie do zwykłego raportu, wynik trafia do nowych kolumn
//! `duplicate_count_ufs`/`_script` i `duplicate_canonical_id_ufs`/`_script`
//! w tabeli `files`. Dowolna przyszła faza może to odpytać przez zwykły
//! `JOIN`, żeby np. pominąć ponowną analizę znanej treści albo podstawić
//! zdrową kopię zamiast naprawiać zepsutą — patrz dokumentacja modułu w
//! rozmowie projektowej co do tego, które fazy realnie na tym skorzystają
//! (analiza treści: 6/7/10-16, Smart Merge: 9) a które nie (struktura/
//! uprawnienia: 1/2/5, gdzie identyczna treść nic nie mówi o metadanych).
//!
//! Traktujemy `hash_ufs` i `hash_script` KAŻDEGO wiersza jako NIEZALEŻNE
//! wystąpienia treści — mogą się dublować także WZAJEMNIE (np. UFS pliku A
//! może być identyczny ze Skryptem pliku B), nie tylko w obrębie tej samej strony.

use crate::settings::Ustawienia;
use crate::utils::format_bytes;
use rusqlite::{params, Connection, Result};
use colored::Colorize;
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File};
use std::io::Write as IoWrite;
use std::path::Path;

/// Jedno "fizyczne wystąpienie" hasza — wiersz bazy + strona + sam hash.
struct HashOccurrence {
    id: i32,
    side: &'static str,
    rel_path: String,
    hash: String,
    size: Option<i64>,
}

pub fn run(conn: &mut Connection, config: &Ustawienia) -> Result<()> {
    println!("\n{}", "==========================================================================".cyan());
    println!("{} {}", "[ 🔗 ]".cyan(), "Wykrywanie Dokładnych Duplikatów Treści (BLAKE3)".bold());
    println!("{}", "Grupuje pliki po dokładnym haszu, niezależnie od ścieżki - wykrywa".bright_black());
    println!("{}", "przeniesione/zdublowane kopie tej samej zawartości.".bright_black());
    println!("{}", "==========================================================================\n".cyan());

    let _ = conn.execute("ALTER TABLE files ADD COLUMN duplicate_count_ufs INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN duplicate_count_script INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN duplicate_canonical_id_ufs INTEGER", []);
    let _ = conn.execute("ALTER TABLE files ADD COLUMN duplicate_canonical_id_script INTEGER", []);

    let mut stmt = conn.prepare(
        "SELECT id, relative_path, hash_ufs, hash_script, size_ufs, size_script
         FROM files WHERE hash_ufs IS NOT NULL OR hash_script IS NOT NULL"
    )?;
    let rows: Vec<_> = stmt.query_map([], |row| {
        Ok((row.get::<_, i32>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, Option<String>>(3)?, row.get::<_, Option<i64>>(4)?, row.get::<_, Option<i64>>(5)?))
    })?.filter_map(|r: Result<_, rusqlite::Error>| r.ok()).collect();
    drop(stmt);

    let mut occurrences: Vec<HashOccurrence> = Vec::new();
    for (id, rel_path, hash_ufs, hash_script, size_ufs, size_script) in &rows {
        if let Some(h) = hash_ufs {
            occurrences.push(HashOccurrence { id: *id, side: "ufs", rel_path: rel_path.clone(), hash: h.clone(), size: *size_ufs });
        }
        if let Some(h) = hash_script {
            occurrences.push(HashOccurrence { id: *id, side: "script", rel_path: rel_path.clone(), hash: h.clone(), size: *size_script });
        }
    }

    if occurrences.is_empty() {
        println!("{}", "Brak policzonych haszy w bazie - uruchom najpierw Fazę 3 (i opcjonalnie 4).".yellow());
        return Ok(());
    }

    // Grupowanie po haszu. Kanoniczne wystąpienie w grupie = najniższe `id`
    // (deterministyczny, powtarzalny wybór - zawsze ten sam plik "wygrywa"
    // rolę odniesienia niezależnie od tego, w jakiej kolejności SQLite
    // zwróci wiersze).
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, occ) in occurrences.iter().enumerate() {
        groups.entry(occ.hash.clone()).or_default().push(i);
    }

    let mut duplicate_groups = 0usize;
    let mut duplicate_files_total = 0usize;
    let mut report = String::new();

    let tx = conn.transaction()?;
    {
        let mut stmt_ufs = tx.prepare_cached("UPDATE files SET duplicate_count_ufs = ?1, duplicate_canonical_id_ufs = ?2 WHERE id = ?3")?;
        let mut stmt_script = tx.prepare_cached("UPDATE files SET duplicate_count_script = ?1, duplicate_canonical_id_script = ?2 WHERE id = ?3")?;

        let mut sorted_groups: Vec<(&String, &Vec<usize>)> = groups.iter().collect();
        sorted_groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));

        for (hash, indices) in sorted_groups {
            let count = indices.len();
            let canonical_idx = *indices.iter().min_by_key(|&&i| occurrences[i].id).unwrap();
            let canonical_id = occurrences[canonical_idx].id;

            for &i in indices {
                let occ = &occurrences[i];
                match occ.side {
                    "ufs" => stmt_ufs.execute(params![count as i64, canonical_id, occ.id])?,
                    _ => stmt_script.execute(params![count as i64, canonical_id, occ.id])?,
                };
            }

            if count > 1 {
                duplicate_groups += 1;
                duplicate_files_total += count;
                let size_str = occurrences[canonical_idx].size.map(|s| format_bytes(s.max(0) as u64)).unwrap_or_else(|| "? B".to_string());
                let short_hash: String = hash.chars().take(12).collect();
                let _ = writeln!(report, "\n[ Grupa: {} wystąpień, ~{} każde, hash {}... ]", count, size_str, short_hash);
                for &i in indices {
                    let occ = &occurrences[i];
                    let tag = if occ.id == canonical_id { " (kanoniczny)" } else { "" };
                    let _ = writeln!(report, "  - [{}] {}{}", occ.side.to_uppercase(), occ.rel_path, tag);
                }
            }
        }
    }
    tx.commit()?;

    println!("Przeanalizowano {} wystąpień haszy ({} wierszy z policzonym co najmniej jednym hashem).", occurrences.len(), rows.len());
    println!("{} {} grup duplikatów, obejmujących łącznie {} kopii.\n", "[ 🔗 ]".cyan().bold(), duplicate_groups, duplicate_files_total);

    if duplicate_groups == 0 {
        println!("{}", "✔ Nie znaleziono żadnych dokładnych duplikatów treści.".green());
        return Ok(());
    }

    let raport_cfg = config.raporty_faz.get("Duplikaty").cloned().unwrap_or_else(|| crate::settings::RaportFazy {
        katalog: config.log_path.clone(),
        plik_operacyjny: "raport_operacyjny_duplikaty.txt".to_string(),
        plik_dziennika: "dziennik_koncowy_duplikaty.txt".to_string(),
    });
    fs::create_dir_all(&raport_cfg.katalog).unwrap_or_default();
    let dz_path = Path::new(&raport_cfg.katalog).join(&raport_cfg.plik_dziennika);

    let mut header = String::new();
    let _ = writeln!(header, "==========================================================================");
    let _ = writeln!(header, "RAPORT: DOKŁADNE DUPLIKATY TREŚCI (BLAKE3)");
    let _ = writeln!(header, "Grup duplikatów: {} | Łącznie kopii: {}", duplicate_groups, duplicate_files_total);
    let _ = writeln!(header, "==========================================================================");

    if let Ok(mut f) = File::create(&dz_path) {
        let _ = f.write_all(header.as_bytes());
        let _ = f.write_all(report.as_bytes());
        println!("{} Pełny raport zapisany w: {}", "[ ✔ ]".green(), dz_path.display());
    }

    println!("{}", "Kolumny duplicate_count_*/duplicate_canonical_id_* zapisane w bazie -".bright_black());
    println!("{}", "dostępne do wykorzystania przez inne fazy (np. pomijanie ponownej analizy".bright_black());
    println!("{}", "znanej treści, podstawianie zdrowej kopii zamiast naprawy).".bright_black());

    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
//
// Testy używają PRAWDZIWEGO schematu bazy (`db::init_db`), nie atrapy tabeli —
// inaczej nie wykryłyby rozjazdu między tym modułem a schematem.
//
// Żaden test nie może pisać do drzewa projektu: domyślna konfiguracja kieruje
// raport Duplikatów do `./dziennik/fazy`, więc KAŻDY test podstawia własny
// katalog tymczasowy.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, TempDir};

    /// Baza o prawdziwym schemacie, w katalogu tymczasowym.
    fn baza_testowa(dir: &Path) -> Connection {
        let p = dir.join("baza.db");
        crate::db::init_db(p.to_str().unwrap()).expect("baza testowa musi powstać")
    }

    /// Konfiguracja kierująca raport Duplikatów WYŁĄCZNIE do katalogu
    /// tymczasowego. Ustawiamy wpis `"Duplikaty"` wprost — dzięki temu test
    /// sprawdza przy okazji, że ten klucz jest realnie czytany (przez większość
    /// życia projektu nazwy kluczy nie trafiały w wyszukiwanie, patrz
    /// `settings::default_raporty_faz`).
    fn konfiguracja_testowa(dir: &Path) -> Ustawienia {
        let mut u = Ustawienia {
            log_path: dir.to_string_lossy().to_string(),
            ..Default::default()
        };
        u.raporty_faz.clear();
        u.raporty_faz.insert(
            "Duplikaty".to_string(),
            crate::settings::RaportFazy {
                katalog: dir.to_string_lossy().to_string(),
                plik_operacyjny: "opr_duplikaty.txt".to_string(),
                plik_dziennika: "dziennik_duplikaty.txt".to_string(),
            },
        );
        u
    }

    fn wstaw(
        conn: &Connection,
        sciezka: &str,
        hash_ufs: Option<&str>,
        hash_script: Option<&str>,
        rozmiar: Option<i64>,
    ) -> i32 {
        conn.execute(
            "INSERT INTO files (relative_path, hash_ufs, hash_script, size_ufs, size_script)
             VALUES (?1, ?2, ?3, ?4, ?4)",
            params![sciezka, hash_ufs, hash_script, rozmiar],
        )
        .expect("wstawienie wiersza testowego");
        conn.last_insert_rowid() as i32
    }

    /// Odczytuje czwórkę kolumn wyniku dla danego wiersza.
    fn wynik(conn: &Connection, id: i32) -> (Option<i64>, Option<i64>, Option<i64>, Option<i64>) {
        conn.query_row(
            "SELECT duplicate_count_ufs, duplicate_canonical_id_ufs,
                    duplicate_count_script, duplicate_canonical_id_script
             FROM files WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("wiersz musi istnieć")
    }

    fn srodowisko() -> (TempDir, Connection, Ustawienia) {
        let dir = tempdir().unwrap();
        let conn = baza_testowa(dir.path());
        let cfg = konfiguracja_testowa(dir.path());
        (dir, conn, cfg)
    }

    // ------------------------------------------------------------------
    // PRZYPADKI BRZEGOWE
    // ------------------------------------------------------------------

    #[test]
    fn test_pusta_baza_konczy_sie_bez_bledu_i_bez_raportu() {
        let (dir, mut conn, cfg) = srodowisko();
        assert!(run(&mut conn, &cfg).is_ok());
        assert!(
            !dir.path().join("dziennik_duplikaty.txt").exists(),
            "Bez haszy nie ma czego raportować"
        );
    }

    #[test]
    fn test_wiersze_bez_haszy_sa_pomijane() {
        let (dir, mut conn, cfg) = srodowisko();
        let id = wstaw(&conn, "bez_hasza.bin", None, None, Some(10));

        assert!(run(&mut conn, &cfg).is_ok());

        assert_eq!(
            wynik(&conn, id), (None, None, None, None),
            "Wiersz bez policzonego hasza nie może dostać żadnej wartości"
        );
        assert!(!dir.path().join("dziennik_duplikaty.txt").exists());
    }

    #[test]
    fn test_same_unikaty_nie_daja_grup_duplikatow() {
        let (dir, mut conn, cfg) = srodowisko();
        let a = wstaw(&conn, "a.bin", Some("aaa"), None, Some(100));
        let b = wstaw(&conn, "b.bin", Some("bbb"), None, Some(200));

        assert!(run(&mut conn, &cfg).is_ok());

        // Pojedyncze wystąpienie też dostaje wpis: licznik 1, kanoniczny = ono samo.
        assert_eq!(wynik(&conn, a).0, Some(1));
        assert_eq!(wynik(&conn, a).1, Some(a as i64));
        assert_eq!(wynik(&conn, b).0, Some(1));
        assert!(
            !dir.path().join("dziennik_duplikaty.txt").exists(),
            "Brak duplikatów = brak raportu"
        );
    }

    // ------------------------------------------------------------------
    // GRUPOWANIE
    // ------------------------------------------------------------------

    #[test]
    fn test_dwa_pliki_o_tym_samym_haszu_tworza_grupe() {
        let (_dir, mut conn, cfg) = srodowisko();
        let a = wstaw(&conn, "oryginal.bin", Some("taki_sam"), None, Some(1024));
        let b = wstaw(&conn, "kopia/oryginal.bin", Some("taki_sam"), None, Some(1024));

        assert!(run(&mut conn, &cfg).is_ok());

        assert_eq!(wynik(&conn, a).0, Some(2), "Obie kopie muszą znać rozmiar grupy");
        assert_eq!(wynik(&conn, b).0, Some(2));
        assert_eq!(wynik(&conn, a).1, Some(a as i64), "Kanoniczny to niższe id");
        assert_eq!(wynik(&conn, b).1, Some(a as i64), "Kopia wskazuje na kanoniczny");
    }

    /// Sedno modułu opisane w jego nagłówku: `hash_ufs` i `hash_script` to
    /// NIEZALEŻNE wystąpienia treści, więc duplikat może przebiegać MIĘDZY
    /// stronami — UFS pliku A równy Skryptowi pliku B.
    #[test]
    fn test_duplikat_miedzy_stronami_ufs_i_script() {
        let (_dir, mut conn, cfg) = srodowisko();
        let a = wstaw(&conn, "a.bin", Some("wspolna_tresc"), None, Some(50));
        let b = wstaw(&conn, "b.bin", None, Some("wspolna_tresc"), Some(50));

        assert!(run(&mut conn, &cfg).is_ok());

        let (cnt_ufs_a, kan_ufs_a, _, _) = wynik(&conn, a);
        let (_, _, cnt_script_b, kan_script_b) = wynik(&conn, b);

        assert_eq!(cnt_ufs_a, Some(2), "Strona UFS pliku A należy do grupy dwuelementowej");
        assert_eq!(cnt_script_b, Some(2), "Strona Skryptu pliku B też");
        assert_eq!(kan_ufs_a, Some(a as i64));
        assert_eq!(kan_script_b, Some(a as i64), "Obie strony wskazują ten sam kanoniczny wiersz");
    }

    /// Najczęstszy realny przypadek: obie kopie ratunkowe tego samego pliku
    /// są bajt w bajt identyczne. To JEDEN wiersz z dwoma równymi haszami.
    #[test]
    fn test_obie_strony_tego_samego_wiersza_licza_sie_jako_dwa_wystapienia() {
        let (_dir, mut conn, cfg) = srodowisko();
        let id = wstaw(&conn, "zgodny.bin", Some("identyczne"), Some("identyczne"), Some(7));

        assert!(run(&mut conn, &cfg).is_ok());

        let (cnt_ufs, kan_ufs, cnt_script, kan_script) = wynik(&conn, id);
        assert_eq!(cnt_ufs, Some(2));
        assert_eq!(cnt_script, Some(2));
        assert_eq!(kan_ufs, Some(id as i64));
        assert_eq!(kan_script, Some(id as i64));
    }

    /// Wybór kanonicznego musi być POWTARZALNY, niezależny od kolejności, w
    /// jakiej SQLite zwróci wiersze — zawsze najniższe `id`.
    #[test]
    fn test_kanoniczny_to_zawsze_najnizsze_id() {
        let (_dir, mut conn, cfg) = srodowisko();
        let pierwszy = wstaw(&conn, "z_ostatni.bin", Some("h"), None, Some(1));
        let drugi = wstaw(&conn, "a_pierwszy.bin", Some("h"), None, Some(1));
        let trzeci = wstaw(&conn, "m_srodkowy.bin", Some("h"), None, Some(1));

        assert!(run(&mut conn, &cfg).is_ok());

        for id in [pierwszy, drugi, trzeci] {
            assert_eq!(wynik(&conn, id).0, Some(3), "Grupa ma trzy wystąpienia");
            assert_eq!(
                wynik(&conn, id).1, Some(pierwszy as i64),
                "Kanoniczny to najniższe id, nie nazwa alfabetycznie pierwsza"
            );
        }
    }

    // ------------------------------------------------------------------
    // RAPORT
    // ------------------------------------------------------------------

    #[test]
    fn test_raport_powstaje_pod_sciezka_ze_wskazanej_konfiguracji() {
        let (dir, mut conn, cfg) = srodowisko();
        wstaw(&conn, "a.bin", Some("dup"), None, Some(2048));
        wstaw(&conn, "b.bin", Some("dup"), None, Some(2048));

        assert!(run(&mut conn, &cfg).is_ok());

        let raport = dir.path().join("dziennik_duplikaty.txt");
        assert!(raport.exists(), "Raport musi trafić pod ścieżkę z `raporty_faz[\"Duplikaty\"]`");

        let tresc = fs::read_to_string(&raport).unwrap();
        assert!(tresc.contains("DOKŁADNE DUPLIKATY TREŚCI"), "Brak nagłówka raportu");
        assert!(tresc.contains("Grup duplikatów: 1"), "Zła liczba grup: {}", tresc);
        assert!(tresc.contains("Łącznie kopii: 2"), "Zła liczba kopii: {}", tresc);
        assert!(tresc.contains("a.bin") && tresc.contains("b.bin"), "Brak ścieżek w raporcie");
        assert!(tresc.contains("(kanoniczny)"), "Raport musi wskazywać kopię odniesienia");
    }

    #[test]
    fn test_raport_nie_zawiera_grup_jednoelementowych() {
        let (dir, mut conn, cfg) = srodowisko();
        wstaw(&conn, "dup1.bin", Some("dup"), None, Some(10));
        wstaw(&conn, "dup2.bin", Some("dup"), None, Some(10));
        wstaw(&conn, "unikat.bin", Some("inny"), None, Some(10));

        assert!(run(&mut conn, &cfg).is_ok());

        let tresc = fs::read_to_string(dir.path().join("dziennik_duplikaty.txt")).unwrap();
        assert!(tresc.contains("dup1.bin"));
        assert!(
            !tresc.contains("unikat.bin"),
            "Plik bez duplikatu nie ma czego robić w raporcie duplikatów"
        );
    }

    // ------------------------------------------------------------------
    // POWTARZALNOŚĆ
    // ------------------------------------------------------------------

    /// Kolumny dokłada `ALTER TABLE`, które przy drugim uruchomieniu zawodzi i
    /// jest celowo ignorowane. Drugi przebieg musi dać identyczny wynik, a nie
    /// błąd ani zdublowane liczniki.
    #[test]
    fn test_drugie_uruchomienie_daje_ten_sam_wynik() {
        let (_dir, mut conn, cfg) = srodowisko();
        let a = wstaw(&conn, "a.bin", Some("dup"), None, Some(10));
        let b = wstaw(&conn, "b.bin", Some("dup"), None, Some(10));

        assert!(run(&mut conn, &cfg).is_ok());
        let po_pierwszym = (wynik(&conn, a), wynik(&conn, b));

        assert!(run(&mut conn, &cfg).is_ok(), "Drugi przebieg nie może się wywrócić");
        assert_eq!((wynik(&conn, a), wynik(&conn, b)), po_pierwszym);
    }

    /// Wynik ma przetrwać w bazie do użytku innych faz — to główna obietnica
    /// z nagłówka modułu. Sprawdzamy przez ZAMKNIĘCIE i ponowne otwarcie pliku.
    #[test]
    fn test_wynik_jest_trwaly_po_ponownym_otwarciu_bazy() {
        let dir = tempdir().unwrap();
        let cfg = konfiguracja_testowa(dir.path());
        let sciezka = dir.path().join("baza.db");

        let a;
        {
            let mut conn = crate::db::init_db(sciezka.to_str().unwrap()).unwrap();
            a = wstaw(&conn, "a.bin", Some("dup"), None, Some(10));
            wstaw(&conn, "b.bin", Some("dup"), None, Some(10));
            run(&mut conn, &cfg).unwrap();
        }

        let conn = Connection::open(&sciezka).unwrap();
        assert_eq!(
            wynik(&conn, a).0, Some(2),
            "Kolumny duplikatów muszą być zapisane trwale, nie tylko w pamięci"
        );
    }
}
