// src/workspace_cleanup.rs

//! # Sprzątanie Przestrzeni Roboczej Napraw
//!
//! Fazy 17 i 18 oraz narzędzie DNG zapisują wytworzone pliki do podkatalogów
//! technicznych pod `target_path`:
//!
//! | katalog | producent | ścieżka w bazie |
//! |---|---|---|
//! | `_phase17_repaired` | Faza 17 | `repaired_path_ufs` / `repaired_path_script` |
//! | `_smart_splice_repaired` | Faza 18 | `smart_splice_path` |
//! | `_dng_structural_review` | narzędzie DNG | `dng_structural_path` |
//!
//! Te pliki MUSZĄ przeżyć zakończenie Fazy 9: `merge_source_path` wskazuje na
//! nie jako ślad rewizyjny („skąd wzięły się te bajty"), a reset pozwala wrócić
//! do sprawy i powtórzyć scalanie. Nic ich jednak nie sprzątało, więc rosły
//! bezterminowo — przy dużym korpusie to podwojenie zajętości bez żadnego
//! sygnału dla operatora.
//!
//! ## Co to znaczy „osierocony"
//!
//! Plik, na który NIE wskazuje żaden wpis w bazie. Powstaje w dwóch
//! sytuacjach: po zresetowaniu Fazy 17 lub 18 (reset czyści kolumny, ale nie
//! dotyka dysku — patrz `reset`) oraz po zmianie `target_path`, gdy stare
//! wyniki zostają w poprzedniej lokalizacji.
//!
//! ## Katalogi nieśledzone
//!
//! Flaga `sledzony = false` opisuje producenta, który nie zapisuje ścieżek
//! wyników do bazy. Takiego katalogu nie da się klasyfikować — nie wiadomo,
//! który plik jest jeszcze potrzebny — więc jest wyłącznie raportowany, a
//! wszystko w nim traktowane jako zachowane. Lepiej pokazać zajętość i
//! powiedzieć to wprost, niż zgadywać i skasować dowód.
//!
//! Obecnie **żaden katalog nie korzysta z tej ścieżki**. Ostatnim był
//! `_dng_structural_review`: narzędzie DNG zapisywało sam status
//! (`dng_structural_status`), bez ścieżki pliku. Domknęliśmy to, dodając
//! kolumnę `dng_structural_path` zapisywaną przez
//! [`crate::dng_repair::accept_candidate`] — katalog jest więc śledzony na
//! równi z wynikami Faz 17 i 18. Mechanizm zostaje, bo jest jedyną poprawną
//! odpowiedzią, gdyby doszedł producent bez śladu w bazie.
//!
//! ## Bezpieczeństwo
//!
//! Domyślnie moduł tylko RAPORTUJE. Usunięcie wymaga jawnego wyboru katalogu i
//! hasła administratora — ten sam wzorzec co `reset`. Kasowane są wyłącznie
//! pliki wskazane przez przejście TYCH katalogów, więc operacja nie ma jak
//! wyjść poza przestrzeń roboczą.

use crate::settings::Ustawienia;
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, MultiSelect, Password};
use rusqlite::{Connection, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Podkatalogi techniczne przestrzeni roboczej.
///
/// `sledzony = false` oznacza, że producent nie zapisuje ścieżek wyników do
/// bazy, więc osieroceń nie da się wyznaczyć — katalog jest tylko raportowany.
const KATALOGI: &[(&str, &str, bool)] = &[
    ("_phase17_repaired", "Faza 17 (moduły naprawcze)", true),
    ("_smart_splice_repaired", "Faza 18 (Smart Splice)", true),
    ("_dng_structural_review", "Narzędzie DNG (składanie strukturalne)", true),
];

/// Jeden plik znaleziony w przestrzeni roboczej.
struct Plik {
    sciezka: PathBuf,
    rozmiar: u64,
}

/// Podsumowanie jednego katalogu technicznego.
struct Podsumowanie {
    nazwa: &'static str,
    opis: &'static str,
    sledzony: bool,
    istnieje: bool,
    powiazane: Vec<Plik>,
    osierocone: Vec<Plik>,
}

impl Podsumowanie {
    fn bajty_powiazane(&self) -> u64 { self.powiazane.iter().map(|p| p.rozmiar).sum() }
    fn bajty_osierocone(&self) -> u64 { self.osierocone.iter().map(|p| p.rozmiar).sum() }
}

/// Rekurencyjnie zbiera pliki z katalogu. Błędy odczytu pomija — brak dostępu
/// do podkatalogu nie może wywrócić całego raportu.
fn zbierz_pliki(katalog: &Path, wynik: &mut Vec<Plik>) {
    let Ok(wpisy) = std::fs::read_dir(katalog) else { return };

    for wpis in wpisy.filter_map(|w| w.ok()) {
        let sciezka = wpis.path();
        match wpis.file_type() {
            Ok(t) if t.is_dir() => zbierz_pliki(&sciezka, wynik),
            Ok(t) if t.is_file() => {
                let rozmiar = wpis.metadata().map(|m| m.len()).unwrap_or(0);
                wynik.push(Plik { sciezka, rozmiar });
            }
            _ => {}
        }
    }
}

/// Wczytuje z bazy WSZYSTKIE ścieżki, na które wskazują wyniki napraw.
///
/// Porównanie jest po ścieżce absolutnej, bo tak właśnie zapisują je Faza 17
/// (od rewizji przenoszącej naprawy poza korpus) i Faza 18. Starsze bazy mogą
/// mieć w `repaired_path_*` ścieżkę WZGLĘDNĄ wobec korpusu — taka nie wskazuje
/// na przestrzeń roboczą, więc nie trafi do tego zbioru i nie zafałszuje
/// klasyfikacji.
fn wczytaj_powiazane_sciezki(conn: &Connection) -> Result<HashSet<String>> {
    let mut zbior = HashSet::new();

    for kolumna in ["repaired_path_ufs", "repaired_path_script", "smart_splice_path", "dng_structural_path"] {
        let sql = format!("SELECT {} FROM files WHERE {} IS NOT NULL", kolumna, kolumna);
        let mut stmt = conn.prepare(&sql)?;
        let wiersze = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for sciezka in wiersze.filter_map(|r| r.ok()) {
            zbior.insert(sciezka);
        }
    }

    Ok(zbior)
}

/// Czy wszystkie przyjęte wyniki narzędzia DNG mają zapisaną ścieżkę.
///
/// Kolumna `dng_structural_path` doszła później niż samo narzędzie, więc w
/// bazie założonej wcześniej mogą siedzieć wiersze ze statusem `accepted`,
/// ale bez ścieżki. Pliki, które je wytworzyły, leżą w
/// `_dng_structural_review` i NIE MOGĄ zostać uznane za osierocone tylko
/// dlatego, że powstały przed tą zmianą — to byłoby skasowanie materiału,
/// którego nie da się odtworzyć.
///
/// Gdy taki wiersz istnieje, katalog wraca na czas tego przebiegu do trybu
/// „tylko raportuj". Naprawia się sam: każda kolejna akceptacja zapisuje już
/// ścieżkę, a stare wpisy operator może rozstrzygnąć ręcznie.
fn slad_dng_jest_kompletny(conn: &Connection) -> bool {
    let niekompletne: rusqlite::Result<i64> = conn.query_row(
        "SELECT COUNT(*) FROM files \
         WHERE dng_structural_status LIKE 'accepted%' AND dng_structural_path IS NULL",
        [],
        |r| r.get(0),
    );

    // Błąd odczytu (np. brak kolumny na bazie przed migracją) traktujemy jako
    // niekompletność - bezpieczniejszy wariant.
    matches!(niekompletne, Ok(0))
}

/// Klasyfikuje zawartość jednego katalogu technicznego.
fn zbadaj_katalog(
    baza: &Path,
    (nazwa, opis, sledzony): (&'static str, &'static str, bool),
    powiazane: &HashSet<String>,
) -> Podsumowanie {
    let katalog = baza.join(nazwa);

    if !katalog.is_dir() {
        return Podsumowanie {
            nazwa, opis, sledzony, istnieje: false,
            powiazane: Vec::new(), osierocone: Vec::new(),
        };
    }

    let mut pliki = Vec::new();
    zbierz_pliki(&katalog, &mut pliki);

    // W katalogu bez śladu w bazie KAŻDY plik trafia do „powiązanych", bo nie
    // mamy podstaw uznać go za zbędny. Lepiej zostawić za dużo niż skasować
    // materiał, którego nie da się odtworzyć.
    if !sledzony {
        return Podsumowanie { nazwa, opis, sledzony, istnieje: true, powiazane: pliki, osierocone: Vec::new() };
    }

    let (powiazane_pliki, osierocone): (Vec<Plik>, Vec<Plik>) = pliki
        .into_iter()
        .partition(|p| powiazane.contains(&p.sciezka.to_string_lossy().to_string()));

    Podsumowanie { nazwa, opis, sledzony, istnieje: true, powiazane: powiazane_pliki, osierocone }
}

/// Usuwa wskazane pliki i przycina puste katalogi, jakie po nich zostały.
///
/// Zwraca `(liczba_usunietych, zwolnione_bajty, bledy)`.
fn usun_pliki(pliki: &[Plik], korzen: &Path) -> (usize, u64, usize) {
    let mut usuniete = 0;
    let mut zwolnione = 0;
    let mut bledy = 0;

    for plik in pliki {
        match std::fs::remove_file(&plik.sciezka) {
            Ok(()) => { usuniete += 1; zwolnione += plik.rozmiar; }
            Err(e) => {
                warn!(sciezka = %plik.sciezka.display(), blad = %e, "Nie udało się usunąć osieroconego pliku");
                bledy += 1;
            }
        }
    }

    przytnij_puste_katalogi(korzen);
    (usuniete, zwolnione, bledy)
}

/// Usuwa puste podkatalogi (od najgłębszych), zostawiając sam korzeń.
fn przytnij_puste_katalogi(korzen: &Path) {
    let Ok(wpisy) = std::fs::read_dir(korzen) else { return };

    for wpis in wpisy.filter_map(|w| w.ok()) {
        if wpis.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            let podkatalog = wpis.path();
            przytnij_puste_katalogi(&podkatalog);
            // `remove_dir` kończy się błędem, gdy katalog nie jest pusty — to
            // dokładnie zabezpieczenie, jakiego tu chcemy.
            let _ = std::fs::remove_dir(&podkatalog);
        }
    }
}

/// Formatuje bajty w czytelnej postaci.
fn format_bajtow(bajty: u64) -> String {
    const JEDNOSTKI: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut wartosc = bajty as f64;
    let mut i = 0;
    while wartosc >= 1024.0 && i < JEDNOSTKI.len() - 1 {
        wartosc /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{} {}", bajty, JEDNOSTKI[0]) } else { format!("{:.2} {}", wartosc, JEDNOSTKI[i]) }
}

pub fn run(conn: &Connection, config: &Ustawienia) -> Result<()> {
    println!("{}", "==========================================================================".cyan());
    println!("{} {}", "[ 🧽 ]".cyan(), "Sprzątanie Przestrzeni Roboczej Napraw".bold());
    println!("{}", "Pliki wytworzone przez Fazy 17/18 i narzędzie DNG".yellow());
    println!("{}", "Osierocony = taki, na który nie wskazuje żaden wpis w bazie danych.".bright_black());
    println!("{}", "==========================================================================\n".cyan());

    let baza = PathBuf::from(&config.target_path);
    println!("{} {}\n", "Przestrzeń robocza:".bright_black(), baza.display().to_string().cyan());

    let powiazane = wczytaj_powiazane_sciezki(conn)?;

    // Bezpiecznik dla baz sprzed wprowadzenia `dng_structural_path`: patrz
    // `slad_dng_jest_kompletny`.
    let dng_kompletny = slad_dng_jest_kompletny(conn);
    if !dng_kompletny {
        println!(
            "  {} {}\n",
            "[ ! ]".yellow(),
            "W bazie są starsze wyniki narzędzia DNG bez zapisanej ścieżki - katalog \
             `_dng_structural_review` jest tylko raportowany, bez wyznaczania osieroceń."
                .yellow()
        );
    }

    let podsumowania: Vec<Podsumowanie> = KATALOGI
        .iter()
        .map(|&(nazwa, opis, sledzony)| {
            let sledzony = sledzony && (nazwa != "_dng_structural_review" || dng_kompletny);
            zbadaj_katalog(&baza, (nazwa, opis, sledzony), &powiazane)
        })
        .collect();

    // --- RAPORT ---
    let mut suma_osieroconych = 0u64;
    for p in &podsumowania {
        if !p.istnieje {
            println!("  {:<24} {}", p.nazwa, "nie istnieje".bright_black());
            continue;
        }

        println!("  {}", p.nazwa.bold());
        println!("     {:<30} {:>6} plików, {:>12}", "Powiązane z bazą:", p.powiazane.len(), format_bajtow(p.bajty_powiazane()));

        if p.sledzony {
            let kolor_osieroconych = if p.osierocone.is_empty() { "green" } else { "yellow" };
            let opis = format!("{:>6} plików, {:>12}", p.osierocone.len(), format_bajtow(p.bajty_osierocone()));
            let opis = if kolor_osieroconych == "green" { opis.green() } else { opis.yellow() };
            println!("     {:<30} {}", "Osierocone (do usunięcia):", opis);
            suma_osieroconych += p.bajty_osierocone();
        } else {
            println!("     {:<30} {}", "Osierocone:", "nie da się ustalić".bright_black());
            println!("        {}", format!("{} nie zapisuje ścieżek wyników do bazy - te pliki zostają.", p.opis).bright_black());
        }
        println!();
    }

    let do_usuniecia: Vec<&Podsumowanie> = podsumowania.iter().filter(|p| !p.osierocone.is_empty()).collect();

    if do_usuniecia.is_empty() {
        println!("{}", "[ ✔ ] Brak plików osieroconych - nie ma czego sprzątać.".green().bold());
        info!("Sprzątanie przestrzeni roboczej: brak osieroceń.");
        return Ok(());
    }

    println!(
        "{} {}\n",
        "[ ℹ ] Do odzyskania:".cyan(),
        format_bajtow(suma_osieroconych).yellow().bold()
    );

    // --- WYBÓR I POTWIERDZENIE ---
    let etykiety: Vec<String> = do_usuniecia
        .iter()
        .map(|p| format!("{} — {} plików, {}", p.nazwa, p.osierocone.len(), format_bajtow(p.bajty_osierocone())))
        .collect();

    let wybor = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Wybierz katalogi do wyczyszczenia (Spacja = zaznacz, ENTER = zatwierdź, Esc = anuluj)")
        .items(&etykiety)
        .interact_opt()
        .unwrap_or(None);

    let wybrane = match wybor {
        Some(w) if !w.is_empty() => w,
        _ => {
            println!("\n{}", "[ ℹ ] Nic nie wybrano. Żaden plik nie został usunięty.".bright_black());
            return Ok(());
        }
    };

    let haslo = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Hasło administratora (operacja USUWA pliki z dysku)")
        .interact()
        .unwrap_or_default();

    if blake3::hash(haslo.as_bytes()).to_hex().to_string() != config.admin_password_hash {
        println!("\n{} Odmowa dostępu. Błędne hasło. Nic nie usunięto.", "[ ✖ ]".red().bold());
        return Ok(());
    }

    // --- USUWANIE ---
    let mut razem_usuniete = 0;
    let mut razem_zwolnione = 0u64;
    let mut razem_bledy = 0;

    for &idx in &wybrane {
        let p = do_usuniecia[idx];
        let korzen = baza.join(p.nazwa);
        let (usuniete, zwolnione, bledy) = usun_pliki(&p.osierocone, &korzen);

        println!(
            "  {} {:<24} usunięto {} plików, zwolniono {}{}",
            "->".yellow(), p.nazwa, usuniete, format_bajtow(zwolnione),
            if bledy > 0 { format!(", {} błędów", bledy).red().to_string() } else { String::new() }
        );

        razem_usuniete += usuniete;
        razem_zwolnione += zwolnione;
        razem_bledy += bledy;
    }

    println!("\n{}", "══════════════════════════════════════════════════════════════════════════════".cyan());
    println!(
        "{} usunięto {} plików, zwolniono {}",
        "[ ✔ ] SPRZĄTANIE ZAKOŃCZONE".green().bold(),
        razem_usuniete,
        format_bajtow(razem_zwolnione).green().bold()
    );
    if razem_bledy > 0 {
        println!("{} {} plików nie udało się usunąć - szczegóły w dzienniku.", "[ ⚠ ]".yellow(), razem_bledy);
    }

    info!(usuniete = razem_usuniete, zwolnione_bajtow = razem_zwolnione, bledy = razem_bledy, "Sprzątanie przestrzeni roboczej zakończone");
    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn zapisz(sciezka: &Path, bajty: usize) {
        if let Some(rodzic) = sciezka.parent() {
            std::fs::create_dir_all(rodzic).unwrap();
        }
        std::fs::write(sciezka, vec![0xAB; bajty]).unwrap();
    }

    // ------------------------------------------------------------------
    // format_bajtow
    // ------------------------------------------------------------------

    #[test]
    fn test_format_bajtow_dobiera_jednostke() {
        assert_eq!(format_bajtow(0), "0 B");
        assert_eq!(format_bajtow(512), "512 B");
        assert_eq!(format_bajtow(1024), "1.00 KB");
        assert_eq!(format_bajtow(1024 * 1024), "1.00 MB");
        assert_eq!(format_bajtow(3 * 1024 * 1024 * 1024), "3.00 GB");
    }

    // ------------------------------------------------------------------
    // zbierz_pliki
    // ------------------------------------------------------------------

    #[test]
    fn test_zbierz_pliki_przechodzi_rekurencyjnie() {
        let dir = tempdir().unwrap();
        zapisz(&dir.path().join("a.jpg"), 10);
        zapisz(&dir.path().join("ufs/foto/b.jpg"), 20);
        zapisz(&dir.path().join("script/gleboko/bardzo/c.png"), 30);

        let mut pliki = Vec::new();
        zbierz_pliki(dir.path(), &mut pliki);

        assert_eq!(pliki.len(), 3, "musi zejść na dowolną głębokość");
        assert_eq!(pliki.iter().map(|p| p.rozmiar).sum::<u64>(), 60);
    }

    #[test]
    fn test_zbierz_pliki_na_nieistniejacym_katalogu_nie_panikuje() {
        let dir = tempdir().unwrap();
        let mut pliki = Vec::new();
        zbierz_pliki(&dir.path().join("nie_ma"), &mut pliki);
        assert!(pliki.is_empty());
    }

    // ------------------------------------------------------------------
    // Klasyfikacja: powiązane vs osierocone
    // ------------------------------------------------------------------

    #[test]
    fn test_klasyfikacja_rozdziela_powiazane_od_osieroconych() {
        let baza = tempdir().unwrap();
        let katalog = baza.path().join("_phase17_repaired");

        let powiazany = katalog.join("ufs/a_repaired.jpg");
        let osierocony = katalog.join("ufs/b_repaired.jpg");
        zapisz(&powiazany, 100);
        zapisz(&osierocony, 250);

        let mut wskazania = HashSet::new();
        wskazania.insert(powiazany.to_string_lossy().to_string());

        let p = zbadaj_katalog(baza.path(), KATALOGI[0], &wskazania);

        assert!(p.istnieje);
        assert_eq!(p.powiazane.len(), 1);
        assert_eq!(p.bajty_powiazane(), 100);
        assert_eq!(p.osierocone.len(), 1);
        assert_eq!(p.bajty_osierocone(), 250);
        assert_eq!(p.osierocone[0].sciezka, osierocony);
    }

    /// Po zresetowaniu Fazy 17 baza nie wskazuje na nic — WSZYSTKO w katalogu
    /// staje się osierocone. To główny scenariusz, dla którego to narzędzie
    /// istnieje.
    #[test]
    fn test_po_resecie_wszystko_jest_osierocone() {
        let baza = tempdir().unwrap();
        let katalog = baza.path().join("_phase17_repaired");
        zapisz(&katalog.join("ufs/a.jpg"), 10);
        zapisz(&katalog.join("script/b.jpg"), 20);

        let p = zbadaj_katalog(baza.path(), KATALOGI[0], &HashSet::new());

        assert!(p.powiazane.is_empty());
        assert_eq!(p.osierocone.len(), 2);
        assert_eq!(p.bajty_osierocone(), 30);
    }

    #[test]
    fn test_nieistniejacy_katalog_jest_zglaszany_jako_brak() {
        let baza = tempdir().unwrap();
        let p = zbadaj_katalog(baza.path(), KATALOGI[0], &HashSet::new());

        assert!(!p.istnieje);
        assert!(p.powiazane.is_empty());
        assert!(p.osierocone.is_empty());
    }

    /// Katalog DNG jest śledzony na równi z wynikami Faz 17 i 18.
    ///
    /// Wcześniej nie był, bo narzędzie DNG nie zapisywało ścieżki wyniku —
    /// dopiero kolumna `dng_structural_path` pozwala odróżnić plik wciąż
    /// opisany w bazie od pozostałości po resecie albo zmianie `target_path`.
    #[test]
    fn test_katalog_dng_jest_sledzony_i_wykrywa_osierocenia() {
        let baza = tempdir().unwrap();
        let dng = KATALOGI.iter().find(|(n, _, _)| *n == "_dng_structural_review").unwrap();
        assert!(dng.2, "katalog DNG musi być oznaczony jako śledzony");

        let zachowany = baza.path().join("_dng_structural_review/opisany_dngsplice.dng");
        let porzucony = baza.path().join("_dng_structural_review/po_resecie_dngsplice.dng");
        zapisz(&zachowany, 500);
        zapisz(&porzucony, 700);

        let powiazane: HashSet<String> = [zachowany.to_string_lossy().to_string()].into_iter().collect();
        let p = zbadaj_katalog(baza.path(), *dng, &powiazane);

        assert_eq!(p.powiazane.len(), 1, "plik wskazany przez bazę musi zostać zachowany");
        assert_eq!(p.bajty_powiazane(), 500);
        assert_eq!(p.osierocone.len(), 1, "plik bez wpisu w bazie jest osierocony");
        assert_eq!(p.bajty_osierocone(), 700);
    }

    /// Mechanizm katalogu nieśledzonego zostaje w kodzie, choć żaden katalog
    /// z niego teraz nie korzysta — test trzyma go sprawnym na wypadek
    /// producenta, który nie zapisuje ścieżek do bazy.
    #[test]
    fn test_katalog_niesledzony_nigdy_nie_ma_osieroceń() {
        let baza = tempdir().unwrap();
        let wpis = ("_test_niesledzony", "Producent bez śladu w bazie", false);

        zapisz(&baza.path().join("_test_niesledzony/cokolwiek.bin"), 500);

        let p = zbadaj_katalog(baza.path(), wpis, &HashSet::new());

        assert!(p.osierocone.is_empty(), "w katalogu nieśledzonym nie wolno wyznaczać osieroceń");
        assert_eq!(p.powiazane.len(), 1, "plik musi zostać zaraportowany jako zachowany");
        assert_eq!(p.bajty_powiazane(), 500);
    }

    /// Żaden zarejestrowany katalog nie jest dziś nieśledzony — gdyby doszedł,
    /// ten test przypomni o świadomym udokumentowaniu powodu.
    #[test]
    fn test_wszystkie_zarejestrowane_katalogi_sa_sledzone() {
        let niesledzone: Vec<&str> = KATALOGI.iter().filter(|(_, _, s)| !s).map(|(n, _, _)| *n).collect();
        assert!(
            niesledzone.is_empty(),
            "katalogi bez śledzenia wymagają uzasadnienia w dokumentacji modułu: {:?}", niesledzone
        );
    }

    // ------------------------------------------------------------------
    // Usuwanie
    // ------------------------------------------------------------------

    #[test]
    fn test_usuwanie_kasuje_tylko_wskazane_i_przycina_puste_katalogi() {
        let baza = tempdir().unwrap();
        let katalog = baza.path().join("_phase17_repaired");

        let zostaje = katalog.join("ufs/zostaje.jpg");
        let ginie = katalog.join("script/gleboko/ginie.jpg");
        zapisz(&zostaje, 10);
        zapisz(&ginie, 20);

        let do_usuniecia = vec![Plik { sciezka: ginie.clone(), rozmiar: 20 }];
        let (usuniete, zwolnione, bledy) = usun_pliki(&do_usuniecia, &katalog);

        assert_eq!((usuniete, zwolnione, bledy), (1, 20, 0));
        assert!(!ginie.exists(), "wskazany plik musi zniknąć");
        assert!(zostaje.exists(), "plik niewskazany MUSI zostać nietknięty");

        // Puste katalogi po usuniętym pliku są przycinane, ale korzeń zostaje.
        assert!(!katalog.join("script/gleboko").exists(), "pusty podkatalog powinien zostać przycięty");
        assert!(katalog.is_dir(), "korzeń przestrzeni roboczej musi zostać");
        assert!(katalog.join("ufs").is_dir(), "katalog z zachowanym plikiem musi zostać");
    }

    #[test]
    fn test_usuwanie_zglasza_blad_dla_nieistniejacego_pliku() {
        let baza = tempdir().unwrap();
        let katalog = baza.path().join("_phase17_repaired");
        std::fs::create_dir_all(&katalog).unwrap();

        let brak = vec![Plik { sciezka: katalog.join("nie_ma.jpg"), rozmiar: 5 }];
        let (usuniete, zwolnione, bledy) = usun_pliki(&brak, &katalog);

        assert_eq!((usuniete, zwolnione, bledy), (0, 0, 1));
    }

    // ------------------------------------------------------------------
    // Odczyt powiązań z bazy
    // ------------------------------------------------------------------

    #[test]
    fn test_wczytuje_sciezki_ze_wszystkich_kolumn_producentow() {
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (relative_path, repaired_path_ufs, repaired_path_script, smart_splice_path, dng_structural_path)
             VALUES ('a.jpg', '/w/_phase17_repaired/ufs/a.jpg', '/w/_phase17_repaired/script/a.jpg', \
                     '/w/_smart_splice_repaired/a.jpg', '/w/_dng_structural_review/a_dngsplice.dng')",
            [],
        ).unwrap();

        let zbior = wczytaj_powiazane_sciezki(&conn).unwrap();

        assert_eq!(zbior.len(), 4, "każda kolumna producenta musi zostać uwzględniona");
        assert!(zbior.contains("/w/_phase17_repaired/ufs/a.jpg"));
        assert!(zbior.contains("/w/_phase17_repaired/script/a.jpg"));
        assert!(zbior.contains("/w/_smart_splice_repaired/a.jpg"));
        assert!(zbior.contains("/w/_dng_structural_review/a_dngsplice.dng"), "ścieżka z narzędzia DNG musi być czytana");
    }

    /// Uścisk dłoni między narzędziem DNG a sprzątaniem, sprawdzony na
    /// PRAWDZIWYM przebiegu `accept_candidate`, a nie na ręcznie wpisanej
    /// ścieżce.
    ///
    /// To jest sedno tej zmiany: dopóki producent nie zapisywał ścieżki, obie
    /// strony mogły być poprawne z osobna, a mimo to katalog pozostawał
    /// nieklasyfikowalny. Test wiąże je ze sobą, więc rozjazd formatu ścieżki
    /// (np. zapis względnej zamiast absolutnej) zostanie wykryty.
    #[test]
    fn test_narzedzie_dng_zapisuje_sciezke_ktora_sprzatanie_odnajduje() {
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute("INSERT INTO files (id, relative_path) VALUES (7, 'zdjecia/DSC_1.dng')", []).unwrap();

        let baza = tempdir().unwrap();
        let katalog = baza.path().join("_dng_structural_review");

        let zadanie = crate::dng_repair::ReviewTask { id: 7, rel_path: "zdjecia/DSC_1.dng".to_string() };
        let kandydat = crate::dng_repair::DisplayCandidate {
            bytes: vec![0xAB; 320],
            description: "Nagłówek/IFD ze strony B, dane pikseli ze strony A".to_string(),
            confidence: crate::dng_splice::SpliceConfidence::StructuralOnly,
            entropy: 5.16,
            plausible: true,
            width: 4000,
            height: 3000,
            camera_model: None,
        };

        let zapisany = crate::dng_repair::accept_candidate(&conn, &zadanie, &kandydat, &katalog, false)
            .expect("zapis kandydata musi się udać");

        // 1. Plik faktycznie powstał tam, gdzie sprzątanie będzie go szukać.
        assert!(zapisany.starts_with(&katalog), "wynik musi trafić do katalogu przeglądowego");
        assert_eq!(std::fs::read(&zapisany).unwrap().len(), 320);

        // 2. Baza zna jego ścieżkę...
        let zbior = wczytaj_powiazane_sciezki(&conn).unwrap();
        assert!(
            zbior.contains(&zapisany.to_string_lossy().to_string()),
            "sprzątanie musi odnaleźć ścieżkę zapisaną przez narzędzie DNG (zbiór: {:?})", zbior
        );

        // 3. ...więc plik jest klasyfikowany jako zachowany, a nie osierocony.
        let wpis = KATALOGI.iter().find(|(n, _, _)| *n == "_dng_structural_review").unwrap();
        let p = zbadaj_katalog(baza.path(), *wpis, &zbior);
        assert_eq!(p.powiazane.len(), 1, "plik opisany w bazie musi zostać zachowany");
        assert!(p.osierocone.is_empty(), "nic nie może zostać uznane za osierocone");
    }

    // ------------------------------------------------------------------
    // Bezpiecznik dla baz sprzed wprowadzenia kolumny ze ścieżką
    // ------------------------------------------------------------------

    #[test]
    fn test_slad_dng_kompletny_na_pustej_bazie() {
        let conn = crate::db::init_db(":memory:").unwrap();
        assert!(slad_dng_jest_kompletny(&conn), "brak wyników DNG to stan kompletny");
    }

    #[test]
    fn test_slad_dng_kompletny_gdy_kazdy_wynik_ma_sciezke() {
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (relative_path, dng_structural_status, dng_structural_path)
             VALUES ('a.dng', 'accepted', '/w/_dng_structural_review/a_dngsplice.dng')",
            [],
        ).unwrap();
        assert!(slad_dng_jest_kompletny(&conn));
    }

    /// Wiersz sprzed wprowadzenia kolumny MUSI zablokować wyznaczanie
    /// osieroceń — inaczej pierwszy przebieg po aktualizacji uznałby stare
    /// wyniki za śmieci i zaproponował ich skasowanie.
    #[test]
    fn test_stary_wynik_bez_sciezki_blokuje_wyznaczanie_osieroceń() {
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute(
            "INSERT INTO files (relative_path, dng_structural_status) VALUES ('stary.dng', 'accepted')",
            [],
        ).unwrap();

        assert!(!slad_dng_jest_kompletny(&conn), "wynik bez ścieżki to ślad niekompletny");

        // I skutek praktyczny: katalog schodzi do trybu „tylko raportuj".
        let baza = tempdir().unwrap();
        zapisz(&baza.path().join("_dng_structural_review/stary_dngsplice.dng"), 900);

        let wpis = KATALOGI.iter().find(|(n, _, _)| *n == "_dng_structural_review").unwrap();
        let obnizony = (wpis.0, wpis.1, false);
        let p = zbadaj_katalog(baza.path(), obnizony, &HashSet::new());

        assert!(p.osierocone.is_empty(), "stary wynik nie może zostać uznany za osierocony");
        assert_eq!(p.bajty_powiazane(), 900, "musi zostać zaraportowany jako zachowany");
    }

    /// Status pominięcia nie wytwarza pliku, więc nie może blokować
    /// klasyfikacji — bezpiecznik ma reagować wyłącznie na akceptacje.
    #[test]
    fn test_pominiete_wyniki_nie_blokuja_klasyfikacji() {
        let conn = crate::db::init_db(":memory:").unwrap();
        for status in ["skipped", "skipped_auto", "unparseable"] {
            conn.execute(
                "INSERT INTO files (relative_path, dng_structural_status) VALUES (?1, ?2)",
                rusqlite::params![format!("{}.dng", status), status],
            ).unwrap();
        }
        assert!(slad_dng_jest_kompletny(&conn), "pominięcia nie zostawiają plików na dysku");
    }

    /// Status też musi zostać zapisany — ścieżka go nie zastępuje, bo to on
    /// wyklucza plik z ponownego przeglądu (`dng_structural_status IS NULL`).
    #[test]
    fn test_narzedzie_dng_zapisuje_status_obok_sciezki() {
        let conn = crate::db::init_db(":memory:").unwrap();
        conn.execute("INSERT INTO files (id, relative_path) VALUES (3, 'a.dng')", []).unwrap();

        let baza = tempdir().unwrap();
        let zadanie = crate::dng_repair::ReviewTask { id: 3, rel_path: "a.dng".to_string() };
        let kandydat = crate::dng_repair::DisplayCandidate {
            bytes: vec![1, 2, 3],
            description: String::new(),
            confidence: crate::dng_splice::SpliceConfidence::StructuralOnly,
            entropy: 5.0, plausible: true, width: 1, height: 1, camera_model: None,
        };

        crate::dng_repair::accept_candidate(&conn, &zadanie, &kandydat, baza.path(), true).unwrap();

        let (status, sciezka): (String, String) = conn.query_row(
            "SELECT dng_structural_status, dng_structural_path FROM files WHERE id = 3",
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();

        assert_eq!(status, "accepted_auto", "tryb automatyczny musi być rozróżnialny w danych");
        // REGRESJA (todo.dng_archive_repair.md, Ustalenie 2): nazwa pliku
        // wynikowego zawiera teraz hash pełnej ścieżki źródłowej (unikalność
        // między podkatalogami — patrz dng_repair::unikalna_nazwa_wyniku),
        // więc dokładny sufiks "a_dngsplice.dng" już nie pasuje — sprawdzamy
        // stabilną część: rozszerzenie i czytelny dla człowieka trzon nazwy.
        assert!(sciezka.ends_with("_dngsplice.dng"), "ścieżka: {}", sciezka);
        let nazwa_pliku = Path::new(&sciezka).file_name().unwrap().to_str().unwrap();
        assert!(nazwa_pliku.starts_with("a_"), "trzon nazwy (stem źródła) musi pozostać czytelny: {}", sciezka);
    }

    #[test]
    fn test_pusta_baza_daje_pusty_zbior_powiazan() {
        let conn = crate::db::init_db(":memory:").unwrap();
        assert!(wczytaj_powiazane_sciezki(&conn).unwrap().is_empty());
    }

    #[test]
    fn test_run_na_pustej_przestrzeni_konczy_sie_bez_bledu() {
        let baza = tempdir().unwrap();
        let conn = crate::db::init_db(":memory:").unwrap();

        let config = Ustawienia {
            target_path: baza.path().to_string_lossy().to_string(),
            ..Default::default()
        };

        // Brak katalogów technicznych = brak osieroceń = wyjście bez pytania
        // użytkownika o cokolwiek.
        run(&conn, &config).expect("brak przestrzeni roboczej to nie błąd");
    }
}
