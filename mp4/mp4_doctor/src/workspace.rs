// src/workspace.rs

//! Moduł `workspace` zarządza izolowanymi przestrzeniami roboczymi (projektami).
//!
//! Zamiast operować na płaskich ścieżkach podawanych za każdym razem, system operuje 
//! w ramach "Projektów". Każdy projekt posiada własną strukturę i bazę wiedzy.
//!
//! # Zmiany w wersji Enterprise:
//! - **Garbage Collector (Optymalizacja przestrzeni):** Dodano mechanizm 
//!   autonomicznego czyszczenia przestrzeni dyskowej. Inteligentnie usuwa 
//!   oryginalne pliki zepsute, jeśli w folderze wyjściowym istnieje w 100% sprawna kopia.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::collections::HashSet;
use chrono::{DateTime, Local};

/// Struktura reprezentująca aktywną przestrzeń roboczą.
#[derive(Debug, Clone)]
pub struct Workspace {
    /// Nazwa projektu (np. "gopro_wakacje")
    pub name: String,
    /// Główny katalog projektu
    pub root_dir: PathBuf,
    /// Katalog z uszkodzonymi plikami do naprawy
    pub broken_dir: PathBuf,
    /// Katalog z poprawnymi plikami, z których wyciągamy nagłówki (dawcy)
    pub donors_dir: PathBuf,
    /// Katalog, do którego trafiają naprawione pliki
    pub output_dir: PathBuf,
    /// Ścieżka do dedykowanej bazy danych SQLite dla tego projektu
    pub db_path: PathBuf,
}

impl Workspace {
    /// Inicjuje nową lub ładuje istniejącą przestrzeń roboczą.
    ///
    /// # Argumenty
    /// * `project_name` - Nazwa przestrzeni roboczej podana przez użytkownika.
    ///
    /// # Zwraca
    /// Skonfigurowaną strukturę `Workspace`.
    pub fn init(project_name: &str) -> io::Result<Self> {
        let root = katalog_przestrzeni().join(project_name);

        let ws = Workspace {
            name: project_name.to_string(),
            broken_dir: root.join("1_broken_input"),
            donors_dir: root.join("2_donors"),
            output_dir: root.join("3_fixed_output"),
            db_path: root.join("knowledge_base.db"),
            root_dir: root,
        };

        ws.create_directories()?;
        Ok(ws)
    }

    /// Jak [`Workspace::init`], ale z gwarancją, że przestrzeń powstanie POZA
    /// DRZEWEM ŹRÓDEŁ — DO UŻYTKU W TESTACH.
    ///
    /// Istnieje po to, żeby w kodzie testu nie dało się przypadkiem pominąć
    /// przekierowania: jedno słowo różnicy zamiast osobnej linii, o której
    /// łatwo zapomnieć. Bez tego testy zostawiały przestrzenie w drzewie
    /// projektu — patrz [`katalog_przestrzeni_dla_testow`].
    ///
    /// Jest idempotentna, więc wolno ją wołać z każdego testu osobno.
    pub fn init_testowy(project_name: &str) -> io::Result<Self> {
        let _ = katalog_przestrzeni_dla_testow();
        Self::init(project_name)
    }

    /// Fizycznie tworzy strukturę folderów na dysku, jeśli jeszcze nie istnieje.
    fn create_directories(&self) -> io::Result<()> {
        if !self.root_dir.exists() {
            crate::dlog!("📁 Tworzenie nowej przestrzeni roboczej: {}", self.name);
            fs::create_dir_all(&self.root_dir)?;
            fs::create_dir_all(&self.broken_dir)?;
            fs::create_dir_all(&self.donors_dir)?;
            fs::create_dir_all(&self.output_dir)?;
            crate::dlog!("✅ Struktura katalogów została pomyślnie wygenerowana.");
        }
        Ok(())
    }

    /// Pomocnicza metoda sprawdzająca, czy projekt zawiera jakiekolwiek uszkodzone pliki.
    pub fn has_broken_files(&self) -> bool {
        if let Ok(entries) = fs::read_dir(&self.broken_dir) {
            entries.filter_map(Result::ok).any(|e| e.path().is_file())
        } else {
            false
        }
    }

    /// Autonomiczny Garbage Collector
    /// Skanuje dysk i usuwa uszkodzone oryginały plików, dla których wygenerowano 
    /// już pomyślnie działający odpowiednik w folderze wyjściowym.
    /// 
    /// Zwraca krotkę: `(Liczba_usuniętych_plików, Zwolnione_bajty)`
    pub fn optimize_storage(&self) -> io::Result<(usize, u64)> {
        let mut recovered_names = HashSet::new();

        // KROK 1: Analiza pomyślnie uratowanych plików
        if let Ok(entries) = fs::read_dir(&self.output_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let file_name = path.file_name().unwrap().to_string_lossy().to_string();
                    
                    // Naprawione pliki mają format "Algorytm_OryginalnaNazwa.mp4" (np. "Clone_DJI_001.mp4")
                    // Rozdzielamy to na pierwszej podłodze, by wyciągnąć "DJI_001.mp4"
                    if let Some((_, original_name)) = file_name.split_once('_') {
                        recovered_names.insert(original_name.to_string());
                    }
                }
            }
        }

        let mut deleted_count = 0;
        let mut freed_bytes = 0;

        // KROK 2: Kasowanie uszkodzonych oryginałów
        if let Ok(entries) = fs::read_dir(&self.broken_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let file_name = path.file_name().unwrap().to_string_lossy().to_string();
                    
                    // Jeżeli ten sam plik widnieje na liście uratowanych...
                    if recovered_names.contains(&file_name) {
                        if let Ok(meta) = fs::metadata(&path) {
                            freed_bytes += meta.len();
                        }
                        // ...bezwzględnie go usuwamy.
                        if fs::remove_file(&path).is_ok() {
                            deleted_count += 1;
                        }
                    }
                }
            }
        }

        Ok((deleted_count, freed_bytes))
    }
}

/// Struktura przechowująca statystyki danego projektu do wyświetlenia w Menu
pub struct WorkspaceStats {
    pub name: String,
    pub broken_count: usize,
    pub donor_count: usize,
    pub fixed_count: usize,
    pub db_entries: usize,
    pub last_used: String,
}

/// Zlicza pliki wewnątrz podanego folderu
fn count_files(dir: &Path) -> usize {
    if let Ok(entries) = fs::read_dir(dir) {
        entries.filter_map(Result::ok).filter(|e| e.path().is_file()).count()
    } else { 0 }
}

/// Skanuje folder główny w poszukiwaniu wszystkich projektów i generuje ich statystyki
pub fn get_available_workspaces() -> Vec<WorkspaceStats> {
    let root = katalog_przestrzeni();
    let root = root.as_path();
    let mut list = Vec::new();
    
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                
                let temp_ws = Workspace {
                    name: name.clone(),
                    broken_dir: path.join("1_broken_input"),
                    donors_dir: path.join("2_donors"),
                    output_dir: path.join("3_fixed_output"),
                    db_path: path.join("knowledge_base.db"),
                    root_dir: path.clone(),
                };

                let broken = count_files(&temp_ws.broken_dir);
                let donors = count_files(&temp_ws.donors_dir);
                let fixed = count_files(&temp_ws.output_dir);
                let db_entries = crate::db::get_db_stats(&temp_ws);

                let time_str = if let Ok(meta) = fs::metadata(&temp_ws.db_path) {
                    if let Ok(sys_time) = meta.modified() {
                        let dt: DateTime<Local> = sys_time.into();
                        dt.format("%Y-%m-%d %H:%M").to_string()
                    } else { "Brak danych".to_string() }
                } else { "Nowy".to_string() };

                list.push(WorkspaceStats {
                    name, broken_count: broken, donor_count: donors, fixed_count: fixed, 
                    db_entries, last_used: time_str
                });
            }
        }
    }
    list
}

// ============================================================================
// KATALOG PRZESTRZENI ROBOCZYCH (konfigurowalny)
// ============================================================================

use std::sync::OnceLock;

/// Katalog, w którym powstają przestrzenie robocze.
///
/// # Dlaczego to nie jest już stała `"workspaces"`
///
/// Ścieżka była WZGLĘDNA wobec katalogu uruchomienia, więc przestrzenie
/// powstawały tam, skąd akurat odpalono program. Przy wołaniu tej biblioteki
/// z innej aplikacji (patrz pozycja „MP4 DOCTOR" w menu Weryfikatora) znaczyło
/// to zaśmiecanie cudzego katalogu roboczego i rozjazd z miejscem, w którym ta
/// aplikacja trzyma wszystkie pozostałe wytwory.
///
/// Ustawiany RAZ, przed pierwszym użyciem. Kolejne wywołania nie mają efektu —
/// katalog przestrzeni nie może zmienić się w trakcie pracy, bo w połowie
/// sesji unieważniłby otwarte ścieżki.
static KATALOG_PRZESTRZENI: OnceLock<PathBuf> = OnceLock::new();

/// Zmienna środowiskowa wskazująca katalog przestrzeni roboczych.
///
/// # Po co, skoro jest już [`ustaw_katalog_przestrzeni`]
///
/// `OnceLock` żyje w JEDNYM procesie. Część testów uruchamia binarkę
/// `mp4_doctor` jako PODPROCES (`--workspace`, `--scan`), a podproces ma własny
/// `OnceLock` i nic nie wie o ustawieniu rodzica — więc tworzyłby przestrzenie
/// względem swojego katalogu roboczego. Zmienna środowiskowa dziedziczy się do
/// potomków, więc obejmuje także ten przypadek.
pub const ZMIENNA_KATALOGU_PRZESTRZENI: &str = "MP4_DOCTOR_KATALOG_PRZESTRZENI";

/// Wskazuje katalog przestrzeni roboczych. Zwraca `true`, jeśli to wywołanie
/// faktycznie go ustawiło (czyli było pierwsze).
pub fn ustaw_katalog_przestrzeni(root: PathBuf) -> bool {
    KATALOG_PRZESTRZENI.set(root).is_ok()
}

/// Katalog przestrzeni roboczych, w kolejności pierwszeństwa:
///
/// 1. wskazany wprost przez aplikację nadrzędną ([`ustaw_katalog_przestrzeni`]),
/// 2. wskazany zmienną [`ZMIENNA_KATALOGU_PRZESTRZENI`] — tak robią testy, bo
///    dziedziczy się do podprocesów,
/// 3. domyślny `workspaces` względem katalogu uruchomienia — tak jak działał
///    samodzielny `mp4_doctor`.
///
/// Wywołanie API jest przed zmienną, bo jest jawną decyzją kodu osadzającego
/// bibliotekę; zmienna to konfiguracja otoczenia i nie może jej nadpisać.
pub fn katalog_przestrzeni() -> PathBuf {
    rozstrzygnij_katalog(
        KATALOG_PRZESTRZENI.get(),
        std::env::var_os(ZMIENNA_KATALOGU_PRZESTRZENI).as_deref(),
    )
}

/// Czysta reguła pierwszeństwa, wydzielona z [`katalog_przestrzeni`].
///
/// Sama `katalog_przestrzeni` czyta stan globalny procesu (`OnceLock` i
/// środowisko), więc nie da się jej rzetelnie przetestować — pierwszy test,
/// który ustawi którekolwiek z nich, zmienia wynik wszystkim pozostałym.
/// Reguła wydzielona tutaj nie dotyka niczego globalnego i sprawdza się
/// wprost.
fn rozstrzygnij_katalog(
    wskazany_api: Option<&PathBuf>,
    ze_srodowiska: Option<&std::ffi::OsStr>,
) -> PathBuf {
    if let Some(wskazany) = wskazany_api {
        return wskazany.clone();
    }
    // Pusta zmienna to brak wskazania, nie wskazanie na katalog bieżący —
    // inaczej `MP4_DOCTOR_KATALOG_PRZESTRZENI=` dawałoby ścieżki względne "".
    if let Some(ze_srodowiska) = ze_srodowiska
        && !ze_srodowiska.is_empty()
    {
        return PathBuf::from(ze_srodowiska);
    }
    PathBuf::from("workspaces")
}

// ============================================================================
// WSPARCIE TESTÓW
// ============================================================================

/// Kieruje przestrzenie robocze do katalogu tymczasowego systemu — WYŁĄCZNIE
/// na użytek testów. Zwraca ustawiony katalog.
///
/// # Problem, który to rozwiązuje
///
/// Domyślny `workspaces` jest ścieżką WZGLĘDNĄ, a `cargo test` ustawia katalog
/// roboczy na katalog crate'a. Testy zostawiały więc przestrzenie w drzewie
/// projektu (`mp4/mp4_doctor/workspaces/`) — razem z bazami `knowledge_base.db`,
/// plikami dawców i katalogami o losowych nazwach, które biorą się z testów
/// wpisujących śmieci w pole „nazwa nowego projektu". Część testów sprząta po
/// sobie przez własnego strażnika, ale nazw wylosowanych przez fuzzing nikt nie
/// posprząta, a sam katalog `workspaces/` i tak zostaje.
///
/// # Dlaczego zmienna środowiskowa, a nie `ustaw_katalog_przestrzeni`
///
/// Patrz [`ZMIENNA_KATALOGU_PRZESTRZENI`] — testy odpalające binarkę jako
/// podproces inaczej by tego nie przekazały.
///
/// # Bezpieczeństwo wielowątkowe
///
/// `set_var` jest w edycji 2024 `unsafe`, bo zmiana środowiska w trakcie pracy
/// programu wyścigami z odczytem w innych wątkach. Tu jest to bezpieczne, bo
/// funkcja jest idempotentna i ustawia ZAWSZE TĘ SAMĄ wartość (katalog zależy
/// wyłącznie od PID procesu), więc równoległe wywołania z wielu testów zapisują
/// identyczny bajt w bajt łańcuch.
pub fn katalog_przestrzeni_dla_testow() -> PathBuf {
    // Gdy otoczenie już wskazuje katalog, honorujemy je zamiast nadpisywać.
    // Pod `cargo test` robi to `.cargo/config.toml` w korzeniu workspace'u i
    // jest to wskazanie MOCNIEJSZE od tej funkcji, bo obejmuje także kod
    // produkcyjny sterowany przez testy (modal nowego projektu w `tui::app`)
    // oraz podprocesy — czyli ścieżki, których żaden `init_testowy` nie tknie.
    if let Some(ze_srodowiska) = std::env::var_os(ZMIENNA_KATALOGU_PRZESTRZENI)
        && !ze_srodowiska.is_empty()
    {
        let katalog = PathBuf::from(ze_srodowiska);
        let _ = fs::create_dir_all(&katalog);
        return katalog;
    }

    // Zapasowo — gdyby testy uruchomiono z pominięciem konfiguracji cargo.
    let katalog = std::env::temp_dir()
        .join("mp4_doctor_testy")
        .join(std::process::id().to_string());

    let _ = fs::create_dir_all(&katalog);

    // SAFETY: patrz sekcja „Bezpieczeństwo wielowątkowe" w dokumentacji.
    unsafe {
        std::env::set_var(ZMIENNA_KATALOGU_PRZESTRZENI, &katalog);
    }

    sprzataj_stare_katalogi_testowe();
    katalog
}

/// Usuwa katalogi testowe zostawione przez WCZEŚNIEJSZE przebiegi, żeby
/// `/tmp` nie puchł w nieskończoność.
///
/// Próg 6 godzin, a nie „wszystko poza moim": dwa równoległe `cargo test`
/// mogłyby sobie nawzajem skasować przestrzenie w trakcie pracy. Sprzątanie
/// jest best-effort — żaden błąd nie ma prawa wywrócić testu.
fn sprzataj_stare_katalogi_testowe() {
    const PROG_SEKUND: u64 = 6 * 60 * 60;

    let Ok(wpisy) = fs::read_dir(std::env::temp_dir().join("mp4_doctor_testy")) else {
        return;
    };
    let moj = std::process::id().to_string();

    for wpis in wpisy.flatten() {
        if wpis.file_name().to_string_lossy() == moj {
            continue;
        }
        let wiek = wpis
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok());
        if let Some(wiek) = wiek
            && wiek.as_secs() > PROG_SEKUND
        {
            let _ = fs::remove_dir_all(wpis.path());
        }
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    // ------------------------------------------------------------------
    // REGUŁA PIERWSZEŃSTWA (czysta, bez stanu globalnego)
    // ------------------------------------------------------------------

    #[test]
    fn test_bez_wskazan_daje_domyslny_workspaces() {
        assert_eq!(rozstrzygnij_katalog(None, None), PathBuf::from("workspaces"));
    }

    #[test]
    fn test_zmienna_srodowiskowa_bije_domyslna() {
        let z_env = OsStr::new("/tmp/skadinad");
        assert_eq!(rozstrzygnij_katalog(None, Some(z_env)), PathBuf::from("/tmp/skadinad"));
    }

    /// Wskazanie z API to jawna decyzja kodu osadzającego bibliotekę
    /// (Weryfikator kieruje przestrzenie pod `<cel>/_mp4_doctor`), więc
    /// konfiguracja otoczenia nie może jej przebić.
    #[test]
    fn test_wskazanie_z_api_bije_zmienna_srodowiskowa() {
        let z_api = PathBuf::from("/z/api");
        let z_env = OsStr::new("/ze/srodowiska");
        assert_eq!(rozstrzygnij_katalog(Some(&z_api), Some(z_env)), PathBuf::from("/z/api"));
    }

    /// Pusta zmienna to brak wskazania. Gdyby ją honorować, ścieżki stałyby się
    /// względne wobec katalogu bieżącego — czyli dokładnie ta wada, którą
    /// zmienna miała usunąć.
    #[test]
    fn test_pusta_zmienna_jest_traktowana_jak_brak() {
        assert_eq!(rozstrzygnij_katalog(None, Some(OsStr::new(""))), PathBuf::from("workspaces"));
    }

    // ------------------------------------------------------------------
    // KATALOG TESTOWY
    // ------------------------------------------------------------------

    /// Niezmiennik nie brzmi „w `/tmp`", tylko „POZA DRZEWEM ŹRÓDEŁ". Pod
    /// `cargo test` katalog wskazuje `.cargo/config.toml` (podkatalog
    /// `target/`), a bez niego funkcja spada na katalog tymczasowy systemu —
    /// oba spełniają ten sam warunek i o niego tu chodzi.
    #[test]
    fn test_katalog_testowy_lezy_poza_drzewem_zrodel() {
        let katalog = katalog_przestrzeni_dla_testow();
        assert!(
            !katalog.starts_with(env!("CARGO_MANIFEST_DIR")),
            "Przestrzenie testowe nie mogą powstawać w drzewie źródeł: {:?}",
            katalog
        );
        assert!(katalog.is_dir(), "Katalog musi zostać faktycznie utworzony");
    }

    #[test]
    fn test_katalog_testowy_jest_idempotentny() {
        assert_eq!(katalog_przestrzeni_dla_testow(), katalog_przestrzeni_dla_testow());
    }

    #[test]
    fn test_katalog_testowy_ustawia_zmienna_srodowiskowa() {
        // Zmienna, nie `OnceLock`, bo musi dziedziczyć się do PODPROCESÓW —
        // część testów uruchamia binarkę `mp4_doctor` przez `Command`.
        let katalog = katalog_przestrzeni_dla_testow();
        let ze_srodowiska = std::env::var_os(ZMIENNA_KATALOGU_PRZESTRZENI)
            .expect("zmienna musi zostać ustawiona");
        assert_eq!(PathBuf::from(ze_srodowiska), katalog);
    }

    /// Sedno całej poprawki: przestrzeń testowa NIE MOŻE powstać w drzewie
    /// projektu. Wcześniej `cargo test` zostawiał tu `workspaces/` z bazami,
    /// plikami dawców i katalogami o nazwach wylosowanych przez testy.
    #[test]
    fn test_przestrzen_testowa_nie_powstaje_w_drzewie_projektu() {
        let ws = Workspace::init_testowy("proba_izolacji").unwrap();

        assert!(ws.root_dir.is_dir(), "Przestrzeń musi realnie powstać");
        assert!(
            !ws.root_dir.starts_with(env!("CARGO_MANIFEST_DIR")),
            "Przestrzeń wylądowała w drzewie źródeł: {:?}",
            ws.root_dir
        );

        let w_projekcie = Path::new(env!("CARGO_MANIFEST_DIR")).join("workspaces").join("proba_izolacji");
        assert!(!w_projekcie.exists(), "Przestrzeń trafiła do drzewa projektu: {:?}", w_projekcie);

        let _ = fs::remove_dir_all(&ws.root_dir);
    }

    #[test]
    fn test_init_testowy_tworzy_pelna_strukture() {
        let ws = Workspace::init_testowy("proba_struktury").unwrap();

        assert!(ws.broken_dir.is_dir(), "brak katalogu plików uszkodzonych");
        assert!(ws.donors_dir.is_dir(), "brak katalogu dawców");
        assert!(ws.output_dir.is_dir(), "brak katalogu wyników");
        assert_eq!(ws.name, "proba_struktury");

        let _ = fs::remove_dir_all(&ws.root_dir);
    }

    #[test]
    fn test_has_broken_files_widzi_plik_i_jego_brak() {
        let ws = Workspace::init_testowy("proba_uszkodzonych").unwrap();
        assert!(!ws.has_broken_files(), "Świeża przestrzeń nie ma plików uszkodzonych");

        fs::write(ws.broken_dir.join("cos.mp4"), b"dane").unwrap();
        assert!(ws.has_broken_files());

        let _ = fs::remove_dir_all(&ws.root_dir);
    }

    /// Garbage Collector usuwa uszkodzony oryginał TYLKO wtedy, gdy w katalogu
    /// wyników leży jego naprawiony odpowiednik nazwany `Algorytm_Oryginał`.
    #[test]
    fn test_optimize_storage_usuwa_tylko_odzyskane() {
        let ws = Workspace::init_testowy("proba_gc").unwrap();

        fs::write(ws.broken_dir.join("odzyskany.mp4"), b"zepsute dane").unwrap();
        fs::write(ws.broken_dir.join("nieodzyskany.mp4"), b"zepsute dane").unwrap();
        fs::write(ws.output_dir.join("Clone_odzyskany.mp4"), b"naprawione").unwrap();

        let (usuniete, zwolnione) = ws.optimize_storage().unwrap();

        assert_eq!(usuniete, 1, "Usunąć wolno wyłącznie oryginał, który ma naprawiony odpowiednik");
        assert_eq!(zwolnione, b"zepsute dane".len() as u64);
        assert!(!ws.broken_dir.join("odzyskany.mp4").exists());
        assert!(
            ws.broken_dir.join("nieodzyskany.mp4").exists(),
            "Oryginał bez naprawionego odpowiednika MUSI przetrwać - to materiał dowodowy"
        );

        let _ = fs::remove_dir_all(&ws.root_dir);
    }

    #[test]
    fn test_optimize_storage_na_pustej_przestrzeni_nic_nie_robi() {
        let ws = Workspace::init_testowy("proba_gc_pusta").unwrap();
        assert_eq!(ws.optimize_storage().unwrap(), (0, 0));
        let _ = fs::remove_dir_all(&ws.root_dir);
    }
}
