// src/settings.rs

//! # Moduł Zarządzania Konfiguracją (`settings`)
//!
//! Ten moduł stanowi serce konfiguracji aplikacji. Odpowiada za definicję
//! struktury ustawień (`Ustawienia`), jej bezpieczną serializację i deserializację
//! (z/do formatu JSON) oraz gwarancję wstecznej kompatybilności.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use colored::Colorize;

// ============================================================================
// KONFIGURACJA RAPORTOWANIA DUAL-LOGGING (DLA KAŻDEJ FAZY OSOBNO)
// ============================================================================

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RaportFazy {
    pub katalog: String,
    pub plik_operacyjny: String,
    pub plik_dziennika: String,
}

/// Nazwy robocze wszystkich pozycji macierzy raportów — źródło prawdy dla
/// [`default_raporty_faz`] i dla naprawy starych konfiguracji
/// ([`Ustawienia::napraw_klucze_raportow`]).
///
/// Pierwszy element to KLUCZ MAPY i musi być dokładnie taki, jakiego szuka
/// odpowiedni konsument (`config.raporty_faz.get("Faza 7")`,
/// `get("Duplikaty")`). Patrz komentarz przy [`default_raporty_faz`].
const POZYCJE_RAPORTOW: &[(&str, &str)] = &[
    ("Faza 1", "faza1_mapowanie"),
    ("Faza 2", "faza2_rozmiary"),
    ("Faza 3", "faza3_blake3_zgodne"),
    ("Faza 4", "faza4_blake3_resztkowe"),
    ("Faza 5", "faza5_inode"),
    ("Faza 6", "faza6_zawartosc"),
    ("Faza 7", "faza7_entropia"),
    ("Faza 8", "faza8_raport_decyzyjny"),
    ("Faza 9", "faza9_smart_merge"),
    ("Faza 10", "faza10_walidacja_tekstu"),
    ("Faza 11", "faza11_walidacja_archiwow"),
    ("Faza 12", "faza12_exif_media"),
    ("Faza 13", "faza13_dekodowanie_ram"),
    ("Faza 14", "faza14_rozmyte_hashowanie"),
    ("Faza 15", "faza15_xattr"),
    ("Faza 16", "faza16_yara"),
    ("Faza 17", "faza17_naprawa_aktywna"),
    ("Faza 18", "faza18_inteligentne_zlozenie"),
    ("Faza 19", "faza19_diagnostyka_wideo"),
    ("Duplikaty", "duplikaty"),
];

/// Domyślna macierz raportów dual-logging.
///
/// ## Dlaczego klucze NIE są uzupełniane zerem
///
/// Wcześniej ta funkcja zapisywała klucze `"Faza 01"` … `"Faza 17"`, ale fazy
/// pytają o nie w postaci bez zera wiodącego — `raporty_faz.get("Faza 7")`.
/// Dla Faz 1–9 wyszukiwanie NIGDY nie trafiało, więc każda z nich cicho
/// spadała na swój awaryjny `unwrap_or_else`, a wartości wpisane przez
/// operatora w ekranie ustawień nie miały ŻADNEGO efektu. Ekran pokazywał
/// dziewięć pozycji, których zmiana niczego nie zmieniała. Fazy 10–17
/// działały, bo dla liczb dwucyfrowych oba zapisy są identyczne.
///
/// Brakowało też trzech pozycji, o które ktoś pyta: `"Faza 18"`, `"Faza 19"`
/// i `"Duplikaty"`.
///
/// Zero wiodące pełniło jednak realną funkcję: `sorted_phase_keys` sortuje
/// klucze, a sortowanie leksykograficzne ustawiłoby `"Faza 10"` przed
/// `"Faza 2"`. Dlatego razem z tą zmianą sortowanie w
/// `menu::settings_actions::sorted_phase_keys` zostało zmienione na
/// NUMERYCZNE — kolejność w ekranie ustawień zostaje naturalna.
fn default_raporty_faz() -> HashMap<String, RaportFazy> {
    POZYCJE_RAPORTOW
        .iter()
        .map(|(klucz, nazwa)| {
            (
                (*klucz).to_string(),
                RaportFazy {
                    katalog: "./dziennik/fazy".to_string(),
                    plik_operacyjny: format!("raport_operacyjny_{}.log", nazwa),
                    plik_dziennika: format!("dziennik_koncowy_{}.log", nazwa),
                },
            )
        })
        .collect()
}

// ============================================================================
// FUNKCJE POMOCNICZE DLA WSTECZNEJ KOMPATYBILNOŚCI (SERDE DEFAULTS)
// ============================================================================

/// Ścieżki
fn default_ufs_path() -> String { "/mnt/skrypt_sdb1_ro_root/@snapshots/@data".to_string() }
fn default_script_path() -> String { "/mnt/skrypt_sdb1_ro_root/sda1/@data".to_string() }
fn default_target_path() -> String { "/media/kopia".to_string() }

/// Dziennik Głównego Systemu Tracingu (YARA / Błędy systemowe I/O)
fn default_log_path() -> String { "./dziennik".to_string() }
fn default_log_file_name() -> String { "weryfikator.log".to_string() }
fn default_log_level() -> String { "INFO".to_string() }

/// Baza DB
fn default_db_path() -> String { ".db".to_string() }
fn default_db_file_name() -> String { "baza.db".to_string() }

/// Raport Końcowy
fn default_csv_report_path() -> String { "./raport_koncowy.csv".to_string() }

fn default_dashboard_refresh_rate() -> u64 { 1000 }
fn default_max_threads() -> usize { 1 }
fn default_io_mode() -> String { "CONCURRENT".to_string() }
fn default_phase13_fast_mode() -> bool { false }
/// Włącza próbkową weryfikację CRC32 pierwszych 3 wpisów w każdym archiwum
/// ZIP-podobnym (Faza 11) — realna dekompresja, nie tylko metadane. Domyślnie
/// wyłączone: wydłuża czas fazy proporcjonalnie do liczby/rozmiaru archiwów.
fn default_deep_archive_scan() -> bool { false }
/// Faza 14: gdy `mmap` się nie powiedzie (rzadkie, np. pliki zerowej długości
/// lub osobliwości systemu plików), silnik CTPH/ssdeep spada na klasyczny
/// bufor `fs::read_to_end` w pamięci RAM — ale TYLKO dla plików mniejszych
/// niż ten próg (w MB), żeby nie zapchać RAM-u jednym gigantycznym plikiem.
/// Domyślnie 1024 MB (1 GB) — zachowuje dotychczasowe zachowanie kodu.
fn default_fuzzy_hash_fallback_max_mb() -> u64 { 1024 }

/// Domyślny hash BLAKE3 dla hasła "admin"
fn default_admin_password_hash() -> String { 
    "d289b2da9b7051f36b4e396e0af3e069e78cf119a7fdcb6437b685c4875e9f9e".to_string()
}

// ============================================================================
// STRUKTURA GŁÓWNA KONFIGURACJI
// ============================================================================

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Ustawienia {

    #[serde(default = "default_ufs_path")]
    pub ufs_path: String,

    #[serde(default = "default_script_path")]
    pub script_path: String,

    #[serde(default = "default_target_path")]
    pub target_path: String,

    #[serde(default = "default_db_path")]
    pub db_path: String,
    
    #[serde(default = "default_db_file_name")]
    pub db_file_name: String,
    
    #[serde(default = "default_log_path")]
    pub log_path: String,
    
    #[serde(default = "default_log_file_name")]
    pub log_file_name: String,

    #[serde(default = "default_csv_report_path")]
    pub csv_report_path: String,

    // [NOWOŚĆ] Macierz ustawień raportów dla każdej fazy osobno
    #[serde(default = "default_raporty_faz")]
    pub raporty_faz: HashMap<String, RaportFazy>,

    /// Faza 13: tryb szybki (pomija część dekodowania w RAM).
    ///
    /// `#[serde(default)]` jest tu KONIECZNE, nie ozdobne. Bez niego to było
    /// jedyne pole struktury bez wartości domyślnej, więc każda konfiguracja
    /// zapisana przed jego dodaniem NIE DAWAŁA SIĘ sparsować — a
    /// [`Ustawienia::wczytaj`] reaguje na błąd parsowania nadpisaniem całego
    /// pliku wartościami domyślnymi. Skutkiem był cichy kasownik ścieżek
    /// `ufs_path`, `script_path` i `target_path` operatora, mimo że moduł
    /// obiecuje w nagłówku wsteczną kompatybilność.
    #[serde(default = "default_phase13_fast_mode")]
    pub phase13_fast_mode: bool,

    /// Faza 11: włącza próbkową weryfikację CRC32 (dekompresja pierwszych 3
    /// wpisów każdego archiwum) — wykrywa ciche uszkodzenie strumienia
    /// skompresowanego, którego nie złapie sama walidacja struktury EOCD/DNA.
    #[serde(default = "default_deep_archive_scan")]
    pub deep_archive_scan: bool,

    /// Faza 14: górny limit (w MB) dla klasycznego bufora `fs::read_to_end`
    /// używanego wyłącznie jako fallback, gdy `mmap` zawiedzie. Powyżej tego
    /// progu plik jest pomijany (kategoria "too_large_fallback") zamiast
    /// wczytywany w całości do RAM.
    #[serde(default = "default_fuzzy_hash_fallback_max_mb")]
    pub fuzzy_hash_fallback_max_mb: u64,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default = "default_dashboard_refresh_rate")]
    pub dashboard_refresh_rate: u64,

    /// Limit użycia wątków procesora dla operacji wielowątkowych (Rayon).
    /// Wartość 0 oznacza automatyczne użycie wszystkich dostępnych rdzeni.
    #[serde(default = "default_max_threads")]
    pub max_threads: usize,

    /// Tryb pracy dysków: "CONCURRENT" (równolegle) lub "SEQUENTIAL" (jeden po drugim).
    #[serde(default = "default_io_mode")]
    pub io_mode: String,

    /// Zabezpieczenie kryptograficzne (Hash BLAKE3) dla akcji destrukcyjnych.
    #[serde(default = "default_admin_password_hash")]
    pub admin_password_hash: String,

}

// ============================================================================
// IMPLEMENTACJA LOGIKI
// ============================================================================

impl Default for Ustawienia {
    fn default() -> Self {
        Ustawienia {
            ufs_path: default_ufs_path(),
            script_path: default_script_path(),
            target_path: default_target_path(),
            db_path: default_db_path(), 
            db_file_name: default_db_file_name(),
            log_path: default_log_path(),
            log_file_name: default_log_file_name(),
            csv_report_path: default_csv_report_path(),
            raporty_faz: default_raporty_faz(),
            phase13_fast_mode: default_phase13_fast_mode(),
            deep_archive_scan: default_deep_archive_scan(),
            fuzzy_hash_fallback_max_mb: default_fuzzy_hash_fallback_max_mb(),
            log_level: default_log_level(),
            dashboard_refresh_rate: default_dashboard_refresh_rate(),
            max_threads: default_max_threads(),
            io_mode: default_io_mode(),
            admin_password_hash: default_admin_password_hash(),
        }
    }
}

impl Ustawienia {
    /// Sprowadza klucze [`Self::raporty_faz`] do postaci, o jaką pytają fazy, i
    /// dokłada pozycje, których w starej konfiguracji jeszcze nie było.
    ///
    /// ## Dlaczego to działa W PAMIĘCI, a nie przez zapis na dysk
    ///
    /// Konfiguracje zapisane wcześniej trzymają klucze `"Faza 01"` …
    /// `"Faza 09"`, których żaden konsument nie znajdzie (patrz
    /// [`default_raporty_faz`]). Sama poprawka wartości domyślnych nie
    /// wystarcza, bo `#[serde(default)]` uzupełnia pole tylko wtedy, gdy jest
    /// NIEOBECNE — istniejąca mapa zostaje taka, jaka była.
    ///
    /// Naprawa dzieje się więc przy wczytaniu, w pamięci. Plik operatora nie
    /// jest przy tym ruszany: zapis następuje wyłącznie wtedy, gdy operator
    /// sam zapisze ustawienia. Wartości są przenoszone, nie nadpisywane — to,
    /// co wpisał w ekranie ustawień dla Faz 1–9, zaczyna wreszcie działać.
    ///
    /// Zwraca `true`, jeśli cokolwiek zmieniła (używane w testach jako dowód).
    pub fn napraw_klucze_raportow(&mut self) -> bool {
        let mut zmieniono = false;

        // Krok 1: przeniesienie wartości ze starego klucza z zerem wiodącym.
        for numer in 1..=9 {
            let stary = format!("Faza 0{}", numer);
            let nowy = format!("Faza {}", numer);
            if let Some(wartosc) = self.raporty_faz.remove(&stary) {
                // Gdy z jakiegoś powodu istnieją OBA zapisy, wygrywa ten, o
                // który faza faktycznie pyta — nie nadpisujemy go starym.
                self.raporty_faz.entry(nowy).or_insert(wartosc);
                zmieniono = true;
            }
        }

        // Krok 2: dołożenie pozycji, których w starej konfiguracji nie było
        // (Faza 18, Faza 19, Duplikaty — i każda przyszła).
        let domyslne = default_raporty_faz();
        for (klucz, wartosc) in domyslne {
            if let std::collections::hash_map::Entry::Vacant(e) = self.raporty_faz.entry(klucz) {
                e.insert(wartosc);
                zmieniono = true;
            }
        }

        zmieniono
    }

    pub fn wczytaj(sciezka: &str) -> Self {
        if let Ok(zawartosc) = fs::read_to_string(sciezka) {
            match serde_json::from_str::<Self>(&zawartosc) {
                Ok(mut wczytane) => {
                    wczytane.napraw_klucze_raportow();
                    wczytane
                }
                Err(e) => {
                    let warning_prefix = "[UWAGA]".yellow().bold();
                    eprintln!("{} Błąd parsowania ustawień ({}). Wymuszam domyślne.\n", warning_prefix, e);
                    let u = Self::default();
                    u.zapisz(sciezka);
                    u
                }
            }
        } else {
            let u = Self::default();
            u.zapisz(sciezka);
            u
        }
    }

    pub fn zapisz(&self, sciezka: &str) {
        match serde_json::to_string_pretty(self) {
            Ok(json) => {
                if let Err(e) = fs::write(sciezka, json) {
                    let error_prefix = "[ 🚨 BŁĄD ZAPISU ]".red().bold();
                    let error_desc = "Upewnij się, że dysk nie jest zablokowany do odczytu (Write-Blocker) i masz uprawnienia.".bright_black();
                    
                    eprintln!("\n{} Nie udało się zapisać konfiguracji do pliku '{}': {}", error_prefix, sciezka, e);
                    eprintln!("{}", error_desc);
                    
                    std::thread::sleep(std::time::Duration::from_secs(3));
                }
            }
            Err(e) => {
                let error_prefix = "[ 🚨 BŁĄD WEWNĘTRZNY ]".red().bold();
                eprintln!("\n{} Nie udało się przetworzyć danych do formatu JSON: {}", error_prefix, e);
            }
        }
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE
//
// ŻADEN test w tym pliku nie wolno kierować na prawdziwe `ustawienia.json`.
// `wczytaj` przy błędzie parsowania NADPISUJE wskazany plik wartościami
// domyślnymi, a `zapisz` nadpisuje go bezwarunkowo — więc każdy test operuje
// wyłącznie na `tempfile::tempdir()`.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Zapisuje treść do pliku w katalogu tymczasowym i zwraca ścieżkę jako
    /// `String`, bo `wczytaj`/`zapisz` przyjmują `&str`.
    fn plik_z_trescia(dir: &std::path::Path, nazwa: &str, tresc: &str) -> String {
        let p = dir.join(nazwa);
        fs::write(&p, tresc).expect("zapis materiału testowego musi się udać");
        p.to_string_lossy().into_owned()
    }

    // ------------------------------------------------------------------
    // WSTECZNA KOMPATYBILNOŚĆ (obietnica z nagłówka modułu)
    // ------------------------------------------------------------------

    /// Straż nad KAŻDYM przyszłym polem: pusty obiekt JSON musi dać się
    /// sparsować i wyjść równy `Default`.
    ///
    /// To jeden test, który wyłapuje całą klasę błędów — pole dodane bez
    /// `#[serde(default)]` wywala ten test natychmiast. Właśnie w ten sposób
    /// wykryto brak domyślnej wartości dla `phase13_fast_mode`.
    #[test]
    fn test_pusty_json_daje_dokladnie_domyslne_ustawienia() {
        let z_pustego: Ustawienia = serde_json::from_str("{}")
            .expect("KAŻDE pole musi mieć #[serde(default)] - inaczej stara konfiguracja przepada");
        assert_eq!(z_pustego, Ustawienia::default());
    }

    /// Regresja na cichy kasownik ścieżek operatora.
    ///
    /// Dopóki `phase13_fast_mode` nie miało `#[serde(default)]`, konfiguracja
    /// zapisana przed dodaniem tego pola nie dawała się sparsować, `wczytaj`
    /// wchodziło w gałąź błędu i NADPISYWAŁO plik wartościami domyślnymi —
    /// razem ze ścieżkami do obu kopii i do dysku docelowego.
    #[test]
    fn test_stara_konfiguracja_bez_phase13_fast_mode_zachowuje_sciezki() {
        let dir = tempdir().unwrap();
        let stara = r#"{
            "ufs_path": "/moja/kopia/ufs",
            "script_path": "/moja/kopia/skrypt",
            "target_path": "/moj/dysk/docelowy"
        }"#;
        let sciezka = plik_z_trescia(dir.path(), "ustawienia.json", stara);

        let u = Ustawienia::wczytaj(&sciezka);

        assert_eq!(u.ufs_path, "/moja/kopia/ufs", "Ścieżka UFS operatora przepadła");
        assert_eq!(u.script_path, "/moja/kopia/skrypt", "Ścieżka skryptu operatora przepadła");
        assert_eq!(u.target_path, "/moj/dysk/docelowy", "Ścieżka docelowa operatora przepadła");
        assert_eq!(u.phase13_fast_mode, default_phase13_fast_mode(), "Brakujące pole musi dostać domyślną");
    }

    #[test]
    fn test_wczytaj_nieistniejacy_plik_daje_domyslne_i_tworzy_go() {
        let dir = tempdir().unwrap();
        let sciezka = dir.path().join("nie_ma_mnie.json").to_string_lossy().into_owned();

        let u = Ustawienia::wczytaj(&sciezka);

        assert_eq!(u, Ustawienia::default());
        assert!(std::path::Path::new(&sciezka).exists(), "wczytaj musi utworzyć brakujący plik");
    }

    #[test]
    fn test_wczytaj_uszkodzony_json_daje_domyslne_i_nadpisuje_plik() {
        let dir = tempdir().unwrap();
        let sciezka = plik_z_trescia(dir.path(), "zepsute.json", "{ to nie jest json");

        let u = Ustawienia::wczytaj(&sciezka);
        assert_eq!(u, Ustawienia::default());

        // Po nadpisaniu plik musi być już poprawny - drugie wczytanie nie może
        // znowu wpadać w gałąź błędu.
        let ponownie: Ustawienia = serde_json::from_str(&fs::read_to_string(&sciezka).unwrap())
            .expect("nadpisany plik musi być poprawnym JSON-em");
        assert_eq!(ponownie, Ustawienia::default());
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_pelny_obieg_zapisz_wczytaj_zachowuje_wartosci() {
        let dir = tempdir().unwrap();
        let sciezka = dir.path().join("obieg.json").to_string_lossy().into_owned();

        let mut u = Ustawienia::default();
        u.target_path = "/inny/cel".to_string();
        u.max_threads = 7;
        u.io_mode = "SEQUENTIAL".to_string();
        u.deep_archive_scan = true;
        u.fuzzy_hash_fallback_max_mb = 2048;
        u.zapisz(&sciezka);

        assert_eq!(Ustawienia::wczytaj(&sciezka), u, "Obieg zapis→wczytanie musi być bezstratny");
    }

    // ------------------------------------------------------------------
    // MACIERZ RAPORTÓW: KLUCZE MUSZĄ TRAFIAĆ W WYSZUKIWANIE
    // ------------------------------------------------------------------

    /// Dokładna lista kluczy, o które pytają konsumenci — przepisana z
    /// wywołań `config.raporty_faz.get(...)` w fazach, `phase18`, `phase19`
    /// i `duplicate_finder`. Gdy powstaje nowa faza, ta lista i
    /// [`POZYCJE_RAPORTOW`] muszą rosnąć razem.
    const KLUCZE_PYTANE_PRZEZ_KONSUMENTOW: &[&str] = &[
        "Faza 1", "Faza 2", "Faza 3", "Faza 4", "Faza 5", "Faza 6", "Faza 7",
        "Faza 8", "Faza 9", "Faza 10", "Faza 11", "Faza 12", "Faza 13",
        "Faza 14", "Faza 15", "Faza 16", "Faza 17", "Faza 18", "Faza 19",
        "Duplikaty",
    ];

    /// Sedno poprawki: wcześniej domyślne klucze miały zero wiodące
    /// (`"Faza 07"`), więc dla Faz 1–9 to wyszukiwanie NIGDY nie trafiało i
    /// ustawienia operatora były martwe.
    #[test]
    fn test_kazdy_klucz_pytany_przez_konsumentow_istnieje_w_domyslnych() {
        let domyslne = default_raporty_faz();
        for klucz in KLUCZE_PYTANE_PRZEZ_KONSUMENTOW {
            assert!(
                domyslne.contains_key(*klucz),
                "Nikt nie znajdzie konfiguracji dla '{}' - faza cicho spadnie na awaryjny fallback",
                klucz
            );
        }
    }

    /// Druga strona tej samej umowy: w domyślnych nie może być pozycji, o
    /// którą nikt nie pyta — bo ekran ustawień pokazywałby martwy wiersz.
    #[test]
    fn test_zadna_domyslna_pozycja_nie_jest_martwa() {
        for klucz in default_raporty_faz().keys() {
            assert!(
                KLUCZE_PYTANE_PRZEZ_KONSUMENTOW.contains(&klucz.as_str()),
                "Pozycja '{}' nie jest przez nikogo czytana - ekran ustawień pokazywałby martwy wiersz",
                klucz
            );
        }
    }

    #[test]
    fn test_klucze_raportow_nie_maja_zera_wiodacego() {
        for klucz in default_raporty_faz().keys() {
            assert!(
                !klucz.contains(" 0"),
                "Klucz '{}' ma zero wiodące - nie trafi w `get(\"Faza N\")`",
                klucz
            );
        }
    }

    #[test]
    fn test_nazwy_plikow_raportow_sa_unikalne() {
        let domyslne = default_raporty_faz();
        let mut operacyjne: Vec<&str> = domyslne.values().map(|r| r.plik_operacyjny.as_str()).collect();
        let ile = operacyjne.len();
        operacyjne.sort_unstable();
        operacyjne.dedup();
        assert_eq!(operacyjne.len(), ile, "Dwie pozycje pisałyby do tego samego pliku raportu");
    }

    #[test]
    fn test_pozycje_raportow_pokrywaja_dziewietnascie_faz_i_duplikaty() {
        assert_eq!(POZYCJE_RAPORTOW.len(), 20, "19 faz + Duplikaty");
        assert_eq!(default_raporty_faz().len(), POZYCJE_RAPORTOW.len(), "Każda pozycja musi wejść do mapy");
    }

    // ------------------------------------------------------------------
    // NAPRAWA STARYCH KLUCZY
    // ------------------------------------------------------------------

    #[test]
    fn test_naprawa_przenosi_stary_klucz_z_zerem_zachowujac_wartosc() {
        let mut u = Ustawienia::default();
        u.raporty_faz.clear();
        u.raporty_faz.insert(
            "Faza 07".to_string(),
            RaportFazy {
                katalog: "/moj/katalog".to_string(),
                plik_operacyjny: "moj_operacyjny.log".to_string(),
                plik_dziennika: "moj_dziennik.log".to_string(),
            },
        );

        assert!(u.napraw_klucze_raportow(), "Naprawa musi zgłosić, że coś zmieniła");

        assert!(!u.raporty_faz.contains_key("Faza 07"), "Stary klucz musi zniknąć");
        let przeniesiony = u.raporty_faz.get("Faza 7").expect("Musi istnieć pod kluczem, o który pyta Faza 7");
        assert_eq!(przeniesiony.katalog, "/moj/katalog", "Wartość operatora musi zostać PRZENIESIONA, nie nadpisana");
        assert_eq!(przeniesiony.plik_operacyjny, "moj_operacyjny.log");
        assert_eq!(przeniesiony.plik_dziennika, "moj_dziennik.log");
    }

    #[test]
    fn test_naprawa_przy_obu_zapisach_zostawia_ten_o_ktory_pytaja_fazy() {
        let raport = |k: &str| RaportFazy {
            katalog: k.to_string(),
            plik_operacyjny: "o.log".to_string(),
            plik_dziennika: "d.log".to_string(),
        };
        let mut u = Ustawienia::default();
        u.raporty_faz.insert("Faza 03".to_string(), raport("STARY"));
        u.raporty_faz.insert("Faza 3".to_string(), raport("AKTUALNY"));

        u.napraw_klucze_raportow();

        assert_eq!(u.raporty_faz["Faza 3"].katalog, "AKTUALNY", "Stary zapis nie może nadpisać aktualnego");
        assert!(!u.raporty_faz.contains_key("Faza 03"));
    }

    #[test]
    fn test_naprawa_doklada_brakujace_pozycje() {
        let mut u = Ustawienia::default();
        u.raporty_faz.remove("Faza 18");
        u.raporty_faz.remove("Faza 19");
        u.raporty_faz.remove("Duplikaty");

        assert!(u.napraw_klucze_raportow());

        for klucz in ["Faza 18", "Faza 19", "Duplikaty"] {
            assert!(u.raporty_faz.contains_key(klucz), "Brakująca pozycja '{}' musi zostać dołożona", klucz);
        }
    }

    #[test]
    fn test_naprawa_na_domyslnych_niczego_nie_zmienia() {
        let mut u = Ustawienia::default();
        let przed = u.raporty_faz.clone();
        assert!(!u.napraw_klucze_raportow(), "Na poprawnej konfiguracji naprawa nie ma nic do roboty");
        assert_eq!(u.raporty_faz, przed);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_naprawa_nie_rusza_pozostalych_ustawien() {
        let mut u = Ustawienia::default();
        u.target_path = "/nie/dotykaj".to_string();
        u.max_threads = 13;
        u.raporty_faz.insert("Faza 05".to_string(), RaportFazy {
            katalog: "x".to_string(), plik_operacyjny: "y".to_string(), plik_dziennika: "z".to_string(),
        });

        u.napraw_klucze_raportow();

        assert_eq!(u.target_path, "/nie/dotykaj");
        assert_eq!(u.max_threads, 13);
    }

    /// Cały łańcuch: stara konfiguracja z dysku wychodzi z `wczytaj` już
    /// naprawiona, a PLIK zostaje nietknięty — naprawa dzieje się w pamięci.
    #[test]
    fn test_wczytaj_naprawia_stare_klucze_nie_dotykajac_pliku() {
        let dir = tempdir().unwrap();
        let stara = r#"{
            "raporty_faz": {
                "Faza 01": { "katalog": "/stary/kat", "plik_operacyjny": "o1.log", "plik_dziennika": "d1.log" }
            }
        }"#;
        let sciezka = plik_z_trescia(dir.path(), "stara.json", stara);
        let przed = fs::read_to_string(&sciezka).unwrap();

        let u = Ustawienia::wczytaj(&sciezka);

        assert_eq!(u.raporty_faz["Faza 1"].katalog, "/stary/kat", "Ustawienie Faz 1-9 musi wreszcie działać");
        assert!(!u.raporty_faz.contains_key("Faza 01"));
        assert_eq!(
            fs::read_to_string(&sciezka).unwrap(), przed,
            "wczytaj NIE MOŻE nadpisywać pliku operatora, gdy JSON był poprawny"
        );
    }

    // ------------------------------------------------------------------
    // POZOSTAŁE WARTOŚCI DOMYŚLNE
    // ------------------------------------------------------------------

    #[test]
    fn test_hash_hasla_admin_jest_blake3_dla_admin() {
        // Dowód, że zaszyty hash odpowiada hasłu "admin" - inaczej akcje
        // destrukcyjne byłyby zablokowane nieznanym hasłem.
        assert_eq!(
            blake3::hash(b"admin").to_hex().to_string(),
            default_admin_password_hash()
        );
    }

    #[test]
    fn test_domyslny_tryb_io_jest_jednym_z_dopuszczalnych() {
        assert!(matches!(default_io_mode().as_str(), "CONCURRENT" | "SEQUENTIAL"));
    }

    #[test]
    fn test_domyslne_limity_sa_niezerowe() {
        assert!(default_dashboard_refresh_rate() > 0, "Zerowe odświeżanie zablokowałoby panel");
        assert!(default_max_threads() > 0, "Zero wątków to brak pracy");
        assert!(default_fuzzy_hash_fallback_max_mb() > 0, "Zerowy limit wyłączyłby fallback Fazy 14");
    }

    #[test]
    fn test_domyslny_poziom_logowania_jest_rozpoznawalny() {
        assert!(matches!(default_log_level().as_str(), "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR"));
    }
}
