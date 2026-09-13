// src/menu/state.rs

//! # Model Stanu (State) dla Ratatui
//! Przechowuje wszystkie dane potrzebne do wyrenderowania menu: 
//! pozycję kursora, zużycie CPU/RAM, odczyty dysków oraz informacje z bazy SQLite.

use crate::settings::Ustawienia;
use rusqlite::Connection;
use sysinfo::{Disks, System};
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

/// Struktura reprezentująca pojedynczy dysk fizyczny w systemie
#[derive(Clone)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub used_gb: f64,
    pub total_gb: f64,
    pub available_gb: f64,
    pub usage_pct: f64,
}

/// Główny stan aplikacji TUI
pub struct AppState<'a> {
    pub ustawienia: &'a mut Ustawienia,
    
    // Nawigacja
    pub selections: Vec<(&'static str, &'static str)>,
    pub selected_index: usize,
    pub action_to_execute: Option<usize>, // Flaga zlecająca uruchomienie konkretnej fazy

    // Sprzęt (Sysinfo)
    sys: System,
    disks: Disks,
    pub cpu_usage: f32,
    pub ram_used_gb: f64,
    pub ram_total_gb: f64,
    pub ram_pct: f64,
    pub disk_list: Vec<DiskInfo>,

    // Baza Danych
    pub db_file_size_mb: f64,
    pub db_records_count: i64,
    /// Liczba plików DNG czekających na ręczny przegląd w narzędziu
    /// Składania Strukturalnego DNG (`dng_repair`) — patrz odświeżanie w
    /// `tick()`. `0`, gdy narzędzie nigdy nie było uruchomione (kolumna
    /// `dng_structural_status` jeszcze nie istnieje w bazie) lub gdy
    /// wszystko zostało już przejrzane.
    pub dng_pending_review: i64,
    last_db_check: Instant,
}

impl<'a> AppState<'a> {
    pub fn new(ustawienia: &'a mut Ustawienia) -> Result<Self, String> {
        // Możemy opcjonalnie zabezpieczyć inicjalizację sysinfo, jeśli np. obawiasz się paniki
        let mut sys = System::new();
        sys.refresh_cpu_usage();
        sys.refresh_memory();

        let mut disks = Disks::new();
        disks.refresh(true);

        Ok(Self {
            ustawienia,
            selections: vec![
                ("[ 🚀 ] URUCHOM WSZYSTKIE FAZY (Auto-Pilot)", "Bezobsługowa sekwencja wszystkich 19 faz, od mapowania do Złotej Kopii"),
                ("────────────────────────────────────────────────────────────", ""),
                ("[ 01 ] Faza 01: Mapowanie struktury", "Wczytuje ścieżki do bazy danych (Inkrementalnie)"),
                ("[ 02 ] Faza 02: Akwizycja Metadanych", "Oblicza rozmiary i zbiera indeksy i-node"),
                ("[ 03 ] Faza 03: Hashe BLAKE3 (Zgodne pliki)", "Kryptograficznie hashuj pliki obecne na obu dyskach"),
                ("[ 04 ] Faza 04: Hashe BLAKE3 (Brakujące)", "Kryptograficznie hashuj pliki unikalne (UFS lub Skrypt)"),
                ("[ 05 ] Faza 05: Czas modyfikacji i prawa", "Ekstrakcja uprawnień Unix i Timestampów modyfikacji"),
                ("[ 06 ] Faza 06: Detekcja Pustych Plików", "Identyfikuje puste miejsca na dysku (Sektor 100% Zer)"),
                ("[ 07 ] Faza 07: Analiza Entropii (Shannon)", "Wykrywa wysokie szyfrowanie, kompresję i Ransomware"),
                ("[ 08 ] Faza 10: Walidacja Tekstu (MIME)", "Rozpoznaje formaty kodowania i błędy znaków"),
                ("[ 09 ] Faza 11: Walidacja Archiwów", "Analizuje struktury kontenerów ZIP/DOCX"),
                ("[ 10 ] Faza 12: Struktury Obrazów (EXIF)", "Parsuje nagłówki metadanych fotograficznych (HEIF/JPEG)"),
                ("[ 11 ] Faza 13: Dekodowanie Mediów", "Analizuje klatki wideo i wychwytuje błędy (Gray Banding)"),
                ("[ 🎬 ] Faza 19: Diagnostyka Wideo", "MP4/MOV/M4V, MKV/WebM, FLV oraz strumienie TS z analizą utraty pakietów"),
                ("[ 12 ] Faza 14: Rozmyte Hashowanie (CTPH)", "Szuka bliźniaków algorytmem ssdeep"),
                ("[ 13 ] Faza 15: Rozszerzone Atrybuty", "Wydobywa ukryte ślady XATTR i strefy pobierania URL"),
                ("[ 14 ] Faza 16: Skanowanie YARA", "Skanuje odzysk w poszukiwaniu Malware'u i notatek hackerskich"),
                ("[ 🛠️ ] NAPRAWA I REKONSTRUKCJA", "Faza 17, Faza 18 (Smart Splice) i eksperymentalne Składanie DNG"),
                ("[ 16 ] Faza 08: Raport Końcowy (CSV)", "Eksportuje decyzyjne dane do arkusza analitycznego"),
                ("[ 17 ] Faza 09: Smart Merge (Złota Kopia)", "Łączy i kopiuje najlepsze i naprawione wersje plików"),
                ("[ 🔗 ] WYKRYWANIE DUPLIKATÓW TREŚCI", "Grupuje pliki po dokładnym haszu BLAKE3, niezależnie od ścieżki"),
                ("────────────────────────────────────────────────────────────", ""),
                ("[ 🩺 ] DIAGNOSTYKA BAZY DANYCH", "Sprawdza spójność, indeksy i kondycję pliku roboczego SQLite"),
                ("[ 🧹 ] RESETOWANIE POSTĘPU", "Zdejmuje flagi wykonania z faz pozwalając na rescan"),
                ("[ 🧽 ] SPRZĄTANIE PRZESTRZENI ROBOCZEJ", "Pokazuje zajętość katalogów napraw i usuwa pliki osierocone"),
                ("[ 🎬 ] MP4 DOCTOR (Naprawa Kontenerów MP4)", "Skaner, sanityzator i poligon z projektu mp4_doctor - osobny interfejs"),
                ("[ 🧰 ] USTAWIENIA I KONFIGURACJA", "Zmień ścieżki, przydział wątków procesora, I/O i limity"),
                ("[ 🚪 ] WYJŚCIE Z PROGRAMU", "Bezpiecznie synchronizuje system WAL i zamyka narzędzie"),
            ],
            selected_index: 0,
            action_to_execute: None,
            sys,
            disks,
            cpu_usage: 0.0,
            ram_used_gb: 0.0,
            ram_total_gb: 0.0,
            ram_pct: 0.0,
            disk_list: Vec::new(),
            db_file_size_mb: 0.0,
            db_records_count: 0,
            dng_pending_review: 0,
            last_db_check: Instant::now().checked_sub(std::time::Duration::from_secs(10)).unwrap(),
        })
    }

    /// Cykliczna aktualizacja stanu (wywoływana co tick z mod.rs)
    pub fn tick_hw(&mut self) {
        // 1. Odświeżanie statystyk CPU i RAM
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.disks.refresh(true);

        self.cpu_usage = self.sys.global_cpu_usage();
        self.ram_used_gb = self.sys.used_memory() as f64 / 1_073_741_824.0;
        self.ram_total_gb = self.sys.total_memory() as f64 / 1_073_741_824.0;
        self.ram_pct = if self.ram_total_gb > 0.0 { (self.ram_used_gb / self.ram_total_gb) * 100.0 } else { 0.0 };

        // 2. Filtrowanie, deduplikacja i aktualizacja listy dysków (SMART SELECTION)
        let mut disk_map: HashMap<String, DiskInfo> = HashMap::new();

        for disk in self.disks.list() {
            let mut name = disk.name().to_string_lossy().to_string();
            let fs = disk.file_system().to_string_lossy().to_lowercase();
            let mount_point = disk.mount_point().to_string_lossy().to_string();

            // Omijamy wirtualne i nieistotne systemy plików
            if fs.contains("tmpfs")
                || fs.contains("overlay")
                || fs.contains("squashfs") 
                || fs.contains("fuse.rclone")
                || fs.contains("devtmpfs")
                || fs.contains("shm")
                || fs.contains("autofs")
                || fs.contains("efivarfs")
                || fs.contains("cifs")
                || fs.contains("fusectl")
                || fs.contains("securityfs")
                || fs.contains("proc")
                || fs.contains("sysfs")
                || fs.contains("cifs")
                || fs.contains("nfs")
                || fs.contains("smb")
            {
                continue;
            }
            
            if name.starts_with("/dev/")
            { 
                name = name.replace("/dev/", "");
            }

            if name.contains("loop")
                || name.contains("zram")
                || name.contains("docker")
                || name.contains("rclone")
                || name.contains("gdrive")
            {
                continue;
            }
            
            let total = disk.total_space() as f64 / 1_073_741_824.0;
            if total > 0.0 {
                let available = disk.available_space() as f64 / 1_073_741_824.0;
                let used = total - available;
                let usage_pct = (used / total) * 100.0;

                let new_info = DiskInfo {
                    name: name.clone(),
                    mount_point: mount_point.clone(),
                    used_gb: used,
                    total_gb: total,
                    available_gb: available,
                    usage_pct,
                };

                // HEURYSTYKA: Jeśli dysk jest zamontowany w kilku miejscach (np. bind mount, subvolume),
                // zachowujemy ten punkt montowania, którego ścieżka jest krótsza (główny punkt wejścia).
                if let Some(existing) = disk_map.get_mut(&name) {
                    if mount_point.len() < existing.mount_point.len() {
                        *existing = new_info;
                    }
                } else {
                    disk_map.insert(name, new_info);
                }
            }
        }
        // Kopiowanie wartości z mapy do wektora UI i sortowanie alfabetyczne (zapobiega skakaniu elementów)
        self.disk_list = disk_map.into_values().collect();
        self.disk_list.sort_by(|a, b| a.name.cmp(&b.name));
    }

    /// Cykliczna aktualizacja stanu z uwzględnieniem bazy danych
    pub fn tick(&mut self, conn: &mut Connection) {
        self.tick_hw(); // Aktualizuj sprzęt

        // 3. Aktualizacja bazy danych SQLite (Co 3 sekundy, żeby nie obciążać I/O)
        if self.last_db_check.elapsed().as_secs() >= 3 {
            self.db_records_count = conn.query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0)).unwrap_or(self.db_records_count);

            // 0 gdy kolumna dng_structural_status jeszcze nie istnieje (narzędzie
            // Składania Strukturalnego DNG nigdy nie było uruchomione) - błąd
            // zapytania w tym przypadku jest oczekiwany, nie realny problem.
            self.dng_pending_review = conn.query_row(
                "SELECT COUNT(*) FROM files
                 WHERE found_in_ufs = 1 AND found_in_script = 1
                   AND LOWER(relative_path) LIKE '%.dng'
                   AND (media_decoded_ufs = 0 OR media_decoded_ufs IS NULL OR pixels_ok_ufs = 0)
                   AND (media_decoded_script = 0 OR media_decoded_script IS NULL OR pixels_ok_script = 0)
                   AND dng_structural_status IS NULL",
                [], |row| row.get(0)
            ).unwrap_or(0);
            
            let full_db_path = Path::new(&self.ustawienia.db_path).join(&self.ustawienia.db_file_name);
            self.db_file_size_mb = std::fs::metadata(&full_db_path).map(|m| m.len()).unwrap_or(0) as f64 / 1_048_576.0;
            
            self.last_db_check = Instant::now();
        }
    }

    /// Skok kursora w dół (pomijając linie z "───")
    pub fn next_selection(&mut self) {
        loop {
            if self.selected_index < self.selections.len() - 1 {
                self.selected_index += 1;
            } else {
                self.selected_index = 0;
            }
            if !self.selections[self.selected_index].0.contains("───") { break; }
        }
    }

    /// Skok kursora w górę (pomijając linie z "───")
    pub fn previous_selection(&mut self) {
        loop {
            if self.selected_index > 0 {
                self.selected_index -= 1;
            } else {
                self.selected_index = self.selections.len() - 1;
            }
            if !self.selections[self.selected_index].0.contains("───") { break; }
        }
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE
//
// `tick` czyta ścieżkę bazy z `Ustawienia`, więc KAŻDY test podstawia własny
// katalog tymczasowy — domyślna konfiguracja wskazuje `.db/baza.db` w drzewie
// projektu.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, TempDir};

    const SEPARATOR: &str = "───";

    /// Konfiguracja wskazująca wyłącznie na katalog tymczasowy.
    fn ustawienia_testowe(dir: &Path) -> Ustawienia {
        Ustawienia {
            db_path: dir.to_string_lossy().to_string(),
            db_file_name: "baza.db".to_string(),
            log_path: dir.to_string_lossy().to_string(),
            ..Default::default()
        }
    }

    fn srodowisko() -> (TempDir, Ustawienia) {
        let dir = tempdir().unwrap();
        let u = ustawienia_testowe(dir.path());
        (dir, u)
    }

    // ------------------------------------------------------------------
    // LISTA POZYCJI
    // ------------------------------------------------------------------

    #[test]
    fn test_lista_pozycji_nie_jest_pusta_ani_sama_z_separatorow() {
        let (_d, mut u) = srodowisko();
        let stan = AppState::new(&mut u).unwrap();

        // Obie właściwości są ZAŁOŻENIAMI nawigacji: `next_selection` indeksuje
        // `len() - 1` (pusta lista = przepełnienie), a pętla szukająca
        // niesparatorowej pozycji nigdy by się nie zakończyła, gdyby wszystkie
        // pozycje były separatorami.
        assert!(!stan.selections.is_empty(), "Pusta lista wywróciłaby nawigację");
        assert!(
            stan.selections.iter().any(|(etykieta, _)| !etykieta.contains(SEPARATOR)),
            "Lista z samych separatorów zapętliłaby nawigację w nieskończoność"
        );
    }

    #[test]
    fn test_kazda_pozycja_ma_etykiete() {
        let (_d, mut u) = srodowisko();
        let stan = AppState::new(&mut u).unwrap();
        for (etykieta, _) in &stan.selections {
            assert!(!etykieta.is_empty(), "Pozycja bez etykiety byłaby niewidoczna w menu");
        }
    }

    /// Separatory mają puste opisy — to one odróżniają je od pozycji
    /// wykonywalnych w renderowaniu.
    #[test]
    fn test_separatory_maja_pusty_opis() {
        let (_d, mut u) = srodowisko();
        let stan = AppState::new(&mut u).unwrap();
        for (etykieta, opis) in &stan.selections {
            if etykieta.contains(SEPARATOR) {
                assert!(opis.is_empty(), "Separator nie może mieć opisu: {}", etykieta);
            }
        }
    }

    #[test]
    fn test_kursor_startuje_na_pozycji_wykonywalnej() {
        let (_d, mut u) = srodowisko();
        let stan = AppState::new(&mut u).unwrap();
        assert_eq!(stan.selected_index, 0);
        assert!(
            !stan.selections[0].0.contains(SEPARATOR),
            "Kursor nie może startować na separatorze"
        );
    }

    #[test]
    fn test_start_bez_zleconej_akcji() {
        let (_d, mut u) = srodowisko();
        let stan = AppState::new(&mut u).unwrap();
        assert!(stan.action_to_execute.is_none(), "Menu nie może startować z zleconą fazą");
    }

    // ------------------------------------------------------------------
    // NAWIGACJA
    // ------------------------------------------------------------------

    /// Sedno obu metod nawigacji: separator to linia ozdobna, na której kursor
    /// NIE MOŻE się zatrzymać.
    #[test]
    fn test_nawigacja_w_dol_nigdy_nie_staje_na_separatorze() {
        let (_d, mut u) = srodowisko();
        let mut stan = AppState::new(&mut u).unwrap();

        for krok in 0..(stan.selections.len() * 2) {
            stan.next_selection();
            assert!(
                !stan.selections[stan.selected_index].0.contains(SEPARATOR),
                "Krok {} zatrzymał kursor na separatorze (indeks {})", krok, stan.selected_index
            );
        }
    }

    #[test]
    fn test_nawigacja_w_gore_nigdy_nie_staje_na_separatorze() {
        let (_d, mut u) = srodowisko();
        let mut stan = AppState::new(&mut u).unwrap();

        for krok in 0..(stan.selections.len() * 2) {
            stan.previous_selection();
            assert!(
                !stan.selections[stan.selected_index].0.contains(SEPARATOR),
                "Krok {} zatrzymał kursor na separatorze (indeks {})", krok, stan.selected_index
            );
        }
    }

    #[test]
    fn test_nawigacja_zawija_sie_z_konca_na_poczatek() {
        let (_d, mut u) = srodowisko();
        let mut stan = AppState::new(&mut u).unwrap();

        // Wędrujemy w dół aż do zawinięcia.
        let mut widziane = Vec::new();
        for _ in 0..stan.selections.len() {
            stan.next_selection();
            widziane.push(stan.selected_index);
            if stan.selected_index == 0 { break; }
        }
        assert_eq!(
            stan.selected_index, 0,
            "Ruch w dół z ostatniej pozycji musi wrócić na początek, a nie stanąć"
        );
    }

    #[test]
    fn test_ruch_w_gore_z_pierwszej_pozycji_idzie_na_koniec() {
        let (_d, mut u) = srodowisko();
        let mut stan = AppState::new(&mut u).unwrap();
        assert_eq!(stan.selected_index, 0);

        stan.previous_selection();

        assert!(stan.selected_index > 0, "Ruch w górę z zera musi zawinąć się na koniec listy");
        assert!(!stan.selections[stan.selected_index].0.contains(SEPARATOR));
    }

    /// Ruch w dół i z powrotem w górę musi wrócić dokładnie tam, skąd wyszedł —
    /// inaczej kursor „dryfowałby" przy przewijaniu tam i z powrotem.
    #[test]
    fn test_ruch_tam_i_z_powrotem_wraca_na_to_samo_miejsce() {
        let (_d, mut u) = srodowisko();
        let mut stan = AppState::new(&mut u).unwrap();

        for _ in 0..5 {
            let przed = stan.selected_index;
            stan.next_selection();
            stan.previous_selection();
            assert_eq!(stan.selected_index, przed, "Kursor zdryfował");
            stan.next_selection();
        }
    }

    // ------------------------------------------------------------------
    // ODCZYT SPRZĘTU
    // ------------------------------------------------------------------

    #[test]
    fn test_odczyt_sprzetu_daje_wartosci_w_sensownym_zakresie() {
        let (_d, mut u) = srodowisko();
        let mut stan = AppState::new(&mut u).unwrap();
        stan.tick_hw();

        assert!((0.0..=100.0).contains(&stan.cpu_usage), "CPU poza zakresem: {}", stan.cpu_usage);
        assert!((0.0..=100.0).contains(&stan.ram_pct), "RAM% poza zakresem: {}", stan.ram_pct);
        assert!(stan.ram_total_gb > 0.0, "Maszyna musi mieć jakąkolwiek pamięć");
        assert!(
            stan.ram_used_gb <= stan.ram_total_gb,
            "Zużycie nie może przekraczać całości: {} > {}", stan.ram_used_gb, stan.ram_total_gb
        );
    }

    #[test]
    fn test_odczyt_dyskow_jest_spojny_i_posortowany() {
        let (_d, mut u) = srodowisko();
        let mut stan = AppState::new(&mut u).unwrap();
        stan.tick_hw();

        for d in &stan.disk_list {
            assert!(d.used_gb <= d.total_gb + 0.01, "Dysk {}: zużycie > całość", d.name);
            assert!((0.0..=100.0).contains(&d.usage_pct), "Dysk {}: procent poza zakresem", d.name);
        }

        let nazwy: Vec<&String> = stan.disk_list.iter().map(|d| &d.name).collect();
        let mut posortowane = nazwy.clone();
        posortowane.sort();
        assert_eq!(nazwy, posortowane, "Lista dysków musi być deterministycznie posortowana");
    }

    // ------------------------------------------------------------------
    // ODCZYT BAZY
    // ------------------------------------------------------------------

    #[test]
    fn test_tick_liczy_wiersze_z_bazy() {
        let (dir, mut u) = srodowisko();
        let sciezka = dir.path().join("baza.db");
        let mut conn = crate::db::init_db(sciezka.to_str().unwrap()).unwrap();
        conn.execute("INSERT INTO files (relative_path) VALUES ('a.txt')", []).unwrap();
        conn.execute("INSERT INTO files (relative_path) VALUES ('b.txt')", []).unwrap();

        let mut stan = AppState::new(&mut u).unwrap();
        stan.tick(&mut conn);

        assert_eq!(stan.db_records_count, 2);
        assert!(stan.db_file_size_mb > 0.0, "Plik bazy istnieje, więc ma niezerowy rozmiar");
    }

    /// Kolumna `dng_structural_status` powstaje dopiero przy pierwszym użyciu
    /// narzędzia DNG. Jej brak to stan NORMALNY, a nie błąd — licznik ma wtedy
    /// pokazać zero, a nie wywrócić odświeżanie menu.
    #[test]
    fn test_brak_kolumny_dng_daje_zero_zamiast_bledu() {
        let (dir, mut u) = srodowisko();
        let sciezka = dir.path().join("baza.db");
        let mut conn = crate::db::init_db(sciezka.to_str().unwrap()).unwrap();

        let mut stan = AppState::new(&mut u).unwrap();
        stan.tick(&mut conn);

        assert_eq!(stan.dng_pending_review, 0);
    }

    /// Odczyt bazy jest dławiony do raz na 3 sekundy, żeby nie obciążać I/O.
    /// Drugi `tick` tuż po pierwszym nie może więc zobaczyć nowego wiersza.
    #[test]
    fn test_odczyt_bazy_jest_dlawiony() {
        let (dir, mut u) = srodowisko();
        let sciezka = dir.path().join("baza.db");
        let mut conn = crate::db::init_db(sciezka.to_str().unwrap()).unwrap();
        conn.execute("INSERT INTO files (relative_path) VALUES ('a.txt')", []).unwrap();

        let mut stan = AppState::new(&mut u).unwrap();
        stan.tick(&mut conn);
        assert_eq!(stan.db_records_count, 1);

        conn.execute("INSERT INTO files (relative_path) VALUES ('b.txt')", []).unwrap();
        stan.tick(&mut conn);

        assert_eq!(
            stan.db_records_count, 1,
            "Drugi odczyt w tej samej sekundzie musi zostać zdławiony"
        );
    }

    /// Nieistniejący plik bazy nie może wywrócić odświeżania — menu ma działać
    /// także zanim jakakolwiek faza cokolwiek zapisze.
    #[test]
    fn test_brak_pliku_bazy_nie_wywraca_ticku() {
        let (dir, mut u) = srodowisko();
        u.db_file_name = "nie_ma_mnie.db".to_string();

        let sciezka = dir.path().join("inna.db");
        let mut conn = crate::db::init_db(sciezka.to_str().unwrap()).unwrap();

        let mut stan = AppState::new(&mut u).unwrap();
        stan.tick(&mut conn);

        assert_eq!(stan.db_file_size_mb, 0.0, "Brak pliku = rozmiar zero, nie panika");
    }
}
