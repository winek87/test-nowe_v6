// src/menu/settings_actions.rs

//! # Logika Ekranu Ustawień (Pełne Ratatui)
//!
//! Zastępuje dawny `menu_settings`/`menu_reports` (CLI zawieszające TUI,
//! `dialoguer`) pełnoekranowym widokiem Ratatui, spójnym z resztą aplikacji
//! (ten sam model interakcji ↑/↓/Enter/Esc co dashboard i ekrany faz).
//!
//! Ten plik zawiera WYŁĄCZNIE logikę (stan, walidację, obsługę klawiszy) —
//! zero kodu rysującego. Rysowanie żyje w `tui::settings_screen`, dzięki
//! czemu logika jest w pełni testowalna bez terminala (patrz testy niżej).

use crate::settings::Ustawienia;
use crossterm::event::{KeyCode, KeyEvent};

// ============================================================================
// EDYCJA BUFORA TEKSTOWEGO PO POZYCJACH ZNAKOWYCH (KURSOR)
// ============================================================================

/// Zwraca liczbę znaków (nie bajtów) w `s` — jednostka, w jakiej wyrażana
/// jest pozycja kursora, żeby polskie znaki diakrytyczne (2-bajtowe w UTF-8)
/// liczyły się jako JEDEN krok kursora, nie dwa.
fn char_count(s: &str) -> usize { s.chars().count() }

/// Zwraca bajtowy offset odpowiadający `char_idx`-tej pozycji ZNAKOWEJ w `s`
/// (0 = początek, `char_count(s)` = koniec, za ostatnim znakiem). Konieczne,
/// bo `String::insert`/`remove` operują na offsetach bajtowych, a pozycja
/// kursora w tym module jest liczona w znakach.
fn byte_offset(s: &str, char_idx: usize) -> usize {
    s.char_indices().nth(char_idx).map(|(b, _)| b).unwrap_or(s.len())
}

/// Wstawia znak `c` w buforze na pozycji kursora (przed znakiem, który tam
/// dotąd stał — klasyczne zachowanie trybu wstawiania, nie nadpisywania).
fn insert_char_at(buffer: &mut String, cursor: usize, c: char) {
    let offset = byte_offset(buffer, cursor);
    buffer.insert(offset, c);
}

/// Usuwa znak TUŻ PRZED kursorem (Backspace). Zwraca nową pozycję kursora
/// (o jeden mniejszą) — no-op, gdy kursor już jest na początku.
fn remove_before_cursor(buffer: &mut String, cursor: usize) -> usize {
    if cursor == 0 { return 0; }
    let offset = byte_offset(buffer, cursor - 1);
    buffer.remove(offset);
    cursor - 1
}

/// Usuwa znak TUŻ PO kursorze (Delete). Pozycja kursora się nie zmienia —
/// no-op, gdy kursor jest już na samym końcu (nie ma czego usunąć "do przodu").
fn remove_after_cursor(buffer: &mut String, cursor: usize) {
    if cursor >= char_count(buffer) { return; }
    let offset = byte_offset(buffer, cursor);
    buffer.remove(offset);
}

// ============================================================================
// DEFINICJA PÓL (LISTA GŁÓWNA)
// ============================================================================

/// Rodzaj pola determinuje, jaka nakładka edycji otworzy się po Enter —
/// patrz `tui::settings_screen` dla renderowania każdego wariantu.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum FieldKind {
    /// Dowolny tekst (ścieżka, nazwa pliku) - nakładka z buforem tekstowym.
    Text,
    /// Liczba całkowita - ta sama nakładka co Text, ale z walidacją parsowania.
    Number,
    /// Wartość logiczna - Enter przełącza natychmiast, bez nakładki.
    Toggle,
    /// Wybór z ustalonej listy opcji (patrz [`choice_options`]).
    Choice,
    /// Zmiana hasła administratora - 3-etapowa nakładka (stare/nowe/potwierdzenie).
    Password,
    /// Przechodzi do osobnego ekranu (konfiguracja raportów per faza).
    Submenu,
    /// Ostatnia pozycja listy - Enter kończy ekran ustawień.
    Back,
}

/// Etykiety pól listy głównej, w kolejności wyświetlania. Indeks w tej
/// tablicy jest jedynym identyfikatorem pola używanym przez funkcje
/// get/set/validate poniżej - musi być zsynchronizowany z [`FIELD_KINDS`].
pub const FIELD_LABELS: [&str; 18] = [
    "Ścieżka UFS Explorer",
    "Ścieżka Skrypt Autorski",
    "Ścieżka Docelowa (Merge)",
    "Katalog Bazy Danych",
    "Nazwa Pliku Bazy (SQLite)",
    "Raport Końcowy CSV",
    "Katalog Główny Logów Systemowych",
    "Nazwa Pliku Tracing Log",
    "Konfiguracja Raportów Dual-Logging (per Faza)",
    "Przełącznik Fazy 13 (Tryb Szybki)",
    "Głęboka weryfikacja CRC32 (Faza 11)",
    "Limit fallbacku RAM ssdeep w MB (Faza 14)",
    "Tryb dyskowy (I/O Mode)",
    "Poziom Logów",
    "Odświeżanie UI (RAM/CPU) w ms",
    "Limit Wątków CPU (Rayon)",
    "Hasło administratora",
    "Zapisz i wróć do menu głównego",
];

/// Rodzaj każdego pola, indeks 1:1 z [`FIELD_LABELS`].
pub const FIELD_KINDS: [FieldKind; 18] = [
    FieldKind::Text, FieldKind::Text, FieldKind::Text, FieldKind::Text, FieldKind::Text,
    FieldKind::Text, FieldKind::Text, FieldKind::Text,
    FieldKind::Submenu,
    FieldKind::Toggle, FieldKind::Toggle,
    FieldKind::Number,
    FieldKind::Choice, FieldKind::Choice,
    FieldKind::Number, FieldKind::Number,
    FieldKind::Password,
    FieldKind::Back,
];

/// Zwraca wartość pola do wyświetlenia na liście (już sformatowaną dla
/// człowieka - np. hash hasła skrócony, MB dopisane do liczby).
pub fn get_display_value(u: &Ustawienia, idx: usize) -> String {
    match idx {
        0 => u.ufs_path.clone(),
        1 => u.script_path.clone(),
        2 => u.target_path.clone(),
        3 => u.db_path.clone(),
        4 => u.db_file_name.clone(),
        5 => u.csv_report_path.clone(),
        6 => u.log_path.clone(),
        7 => u.log_file_name.clone(),
        8 => format!("{} faz skonfigurowanych", u.raporty_faz.len()),
        9 => bool_label(u.phase13_fast_mode),
        10 => bool_label(u.deep_archive_scan),
        11 => format!("{} MB", u.fuzzy_hash_fallback_max_mb),
        12 => u.io_mode.clone(),
        13 => u.log_level.clone(),
        14 => format!("{} ms", u.dashboard_refresh_rate),
        15 => if u.max_threads == 0 { "AUTO (wszystkie rdzenie)".to_string() } else { u.max_threads.to_string() },
        16 => shorten_hash(&u.admin_password_hash),
        _ => String::new(),
    }
}

fn bool_label(v: bool) -> String {
    if v { "WŁĄCZONY".to_string() } else { "WYŁĄCZONY".to_string() }
}

fn shorten_hash(hash: &str) -> String {
    if hash.len() >= 16 { format!("{}...{}", &hash[..8], &hash[hash.len() - 8..]) } else { "Brak Hasha!".to_string() }
}

/// Zwraca surową wartość pola tekstowego/liczbowego do wypełnienia bufora
/// edycji (bez formatowania kosmetycznego, w przeciwieństwie do
/// [`get_display_value`] - np. `max_threads` jako `"0"`, nie `"AUTO"`).
pub fn get_edit_buffer(u: &Ustawienia, idx: usize) -> String {
    match idx {
        0 => u.ufs_path.clone(),
        1 => u.script_path.clone(),
        2 => u.target_path.clone(),
        3 => u.db_path.clone(),
        4 => u.db_file_name.clone(),
        5 => u.csv_report_path.clone(),
        6 => u.log_path.clone(),
        7 => u.log_file_name.clone(),
        11 => u.fuzzy_hash_fallback_max_mb.to_string(),
        14 => u.dashboard_refresh_rate.to_string(),
        15 => u.max_threads.to_string(),
        _ => String::new(),
    }
}

/// Waliduje i zapisuje nową wartość pola tekstowego/liczbowego. Zwraca
/// `Err(komunikat)` bez modyfikowania `u`, jeśli walidacja zawiedzie —
/// ścieżki UFS/Skrypt muszą istnieć na dysku, pola liczbowe muszą się
/// poprawnie sparsować.
pub fn validate_and_set_text(u: &mut Ustawienia, idx: usize, val: &str) -> Result<(), String> {
    match idx {
        0 => {
            if !std::path::Path::new(val).exists() { return Err("Katalog nie istnieje na dysku!".to_string()); }
            u.ufs_path = val.to_string();
        }
        1 => {
            if !std::path::Path::new(val).exists() { return Err("Katalog nie istnieje na dysku!".to_string()); }
            u.script_path = val.to_string();
        }
        2 => u.target_path = val.to_string(),
        3 => u.db_path = val.to_string(),
        4 => u.db_file_name = val.to_string(),
        5 => u.csv_report_path = val.to_string(),
        6 => u.log_path = val.to_string(),
        7 => u.log_file_name = val.to_string(),
        11 => match val.parse::<u64>() {
            Ok(v) => u.fuzzy_hash_fallback_max_mb = v,
            Err(_) => return Err("Wprowadź poprawną liczbę całkowitą (MB).".to_string()),
        },
        14 => match val.parse::<u64>() {
            Ok(v) => u.dashboard_refresh_rate = v,
            Err(_) => return Err("Wprowadź poprawną liczbę całkowitą (ms).".to_string()),
        },
        15 => match val.parse::<usize>() {
            Ok(v) => u.max_threads = v,
            Err(_) => return Err("Wprowadź poprawną liczbę całkowitą (0 = AUTO).".to_string()),
        },
        _ => {}
    }
    Ok(())
}

/// Lista opcji dla pola typu [`FieldKind::Choice`] o danym indeksie.
pub fn choice_options(idx: usize) -> &'static [&'static str] {
    match idx {
        12 => &["CONCURRENT", "SEQUENTIAL"],
        13 => &["TRACE", "DEBUG", "INFO", "WARN", "ERROR"],
        _ => &[],
    }
}

/// Indeks aktualnie wybranej opcji w [`choice_options`] dla danego pola.
pub fn get_choice_current(u: &Ustawienia, idx: usize) -> usize {
    match idx {
        12 => if u.io_mode == "SEQUENTIAL" { 1 } else { 0 },
        13 => choice_options(13).iter().position(|&s| s == u.log_level).unwrap_or(2),
        _ => 0,
    }
}

/// Zapisuje wybraną opcję z powrotem do `Ustawienia`.
pub fn set_choice(u: &mut Ustawienia, idx: usize, choice_idx: usize) {
    match idx {
        12 => u.io_mode = choice_options(12).get(choice_idx).copied().unwrap_or("CONCURRENT").to_string(),
        13 => u.log_level = choice_options(13).get(choice_idx).copied().unwrap_or("INFO").to_string(),
        _ => {}
    }
}

/// Przełącza pole logiczne o danym indeksie.
pub fn toggle_bool(u: &mut Ustawienia, idx: usize) {
    match idx {
        9 => u.phase13_fast_mode = !u.phase13_fast_mode,
        10 => u.deep_archive_scan = !u.deep_archive_scan,
        _ => {}
    }
}

// ============================================================================
// PODMENU: RAPORTY DUAL-LOGGING PER FAZA
// ============================================================================

/// Etykiety trzech pól edytowalnych dla każdej fazy w podmenu raportów.
pub const REPORT_FIELD_LABELS: [&str; 3] = ["Katalog docelowy", "Plik Operacyjny (Live)", "Plik Dziennika (Końcowy)"];

/// Klucze faz z `raporty_faz`, posortowane NUMERYCZNIE po numerze fazy
/// (kolejność wyświetlania w podmenu — deterministyczna, niezależna od
/// `HashMap`).
///
/// ## Dlaczego nie zwykłe `sort()`
///
/// Klucze mają postać `"Faza 7"` — bez zera wiodącego, bo dokładnie o taką
/// pyta każda faza (`raporty_faz.get("Faza 7")`, patrz
/// `settings::default_raporty_faz`). Sortowanie leksykograficzne ustawiłoby
/// wtedy `"Faza 10"` przed `"Faza 2"`, czyli pomieszałoby listę w ekranie
/// ustawień. Wcześniej klucze były zapisywane z zerem (`"Faza 07"`) właśnie po
/// to, żeby zwykłe `sort()` wystarczyło — ale ta postać nie trafiała w
/// wyszukiwanie i czyniła ustawienia Faz 1–9 martwymi.
///
/// Pozycje bez numeru (np. `"Duplikaty"`) idą na koniec, alfabetycznie.
pub fn sorted_phase_keys(u: &Ustawienia) -> Vec<String> {
    let mut keys: Vec<String> = u.raporty_faz.keys().cloned().collect();
    keys.sort_by(|a, b| match (numer_fazy(a), numer_fazy(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        // Klucz z numerem zawsze przed kluczem bez numeru.
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.cmp(b),
    });
    keys
}

/// Wyciąga numer fazy z klucza `raporty_faz` (`"Faza 7"` → `Some(7)`).
/// Zwraca `None` dla pozycji, które nie są fazą — np. `"Duplikaty"`.
fn numer_fazy(klucz: &str) -> Option<u32> {
    klucz.strip_prefix("Faza ")?.trim().parse().ok()
}

/// Wartość jednego z trzech pól raportu danej fazy.
pub fn get_report_value(u: &Ustawienia, phase: &str, field_idx: usize) -> String {
    match u.raporty_faz.get(phase) {
        Some(r) => match field_idx {
            0 => r.katalog.clone(),
            1 => r.plik_operacyjny.clone(),
            2 => r.plik_dziennika.clone(),
            _ => String::new(),
        },
        None => String::new(),
    }
}

/// Waliduje ścieżkę katalogu docelowego raportów (pole 0 podmenu raportów,
/// `RaportFazy::katalog`).
///
/// ## Dlaczego to w ogóle istnieje
///
/// `raport_cfg.katalog` trafia bezpośrednio, bez żadnej dalszej walidacji, do
/// `fs::create_dir_all(...).unwrap_or_default()` (tolerancyjne - błąd
/// ignorowany), a zaraz potem do `File::create(...).unwrap()` (NIE
/// tolerancyjne - panika) w co najmniej 12 fazach (patrz `phase1..phase18`,
/// `duplicate_finder`). Operator wpisujący tu pusty string, ścieżkę do
/// istniejącego PLIKU albo ścieżkę na niezamontowanym wolumenie do tej pory
/// widział zapis zaakceptowany bez ostrzeżenia - a odkrywał błąd dopiero jako
/// panikę wątku roboczego pierwszej uruchomionej fazy, tracąc cały bieżący
/// przebieg.
///
/// ## Reguła akceptacji
///
/// - Pusty string (także sam biały znak) - odrzucony.
/// - Ścieżka, która już istnieje jako katalog - zaakceptowana.
/// - Ścieżka, która już istnieje, ale NIE jest katalogiem (zwykły plik,
///   urządzenie, ...) - odrzucona (`create_dir_all` na takiej ścieżce zawsze
///   zawiedzie, a `File::create` na dziecku takiej ścieżki też).
/// - Ścieżka jeszcze nieistniejąca - szukamy jej NAJBLIŻSZEGO ISTNIEJĄCEGO
///   PRZODKA. Jeśli taki przodek istnieje, jest katalogiem i wygląda na
///   zapisywalny (heurystyka - próba utworzenia i natychmiastowego usunięcia
///   unikalnego podkatalogu tymczasowego w jego obrębie) - akceptujemy
///   (`create_dir_all` dotworzy resztę drzewa przy starcie fazy). W
///   przeciwnym razie (żaden przodek nie istnieje - np. niezamontowany
///   wolumen sieciowy - albo istniejący przodek jest bez prawa zapisu) -
///   odrzucamy.
fn validate_report_katalog(val: &str) -> Result<(), String> {
    if val.trim().is_empty() {
        return Err("Katalog docelowy nie może być pusty.".to_string());
    }
    let path = std::path::Path::new(val);
    if path.exists() {
        if path.is_dir() {
            return Ok(());
        }
        return Err("Ta ścieżka już istnieje, ale nie jest katalogiem (wskazuje na plik).".to_string());
    }
    // Ścieżka jeszcze nie istnieje - poszukaj najbliższego istniejącego przodka.
    //
    // `Path::ancestors()` dla ścieżki WZGLĘDNEJ (np. "nowy_katalog") kończy
    // na pustym `""`, nie na `"."` - a `Path::new("").exists()` zawsze zwraca
    // `false`, mimo że semantycznie to katalog roboczy procesu, który
    // najczęściej istnieje. Bez tej normalizacji prosta względna nazwa bez
    // separatora ścieżki byłaby zawsze odrzucana. Dotyczy to WYŁĄCZNIE ścieżek
    // względnych - `ancestors()` ścieżki bezwzględnej zawsze kończy na `"/"`,
    // nie na pustym stringu.
    let ancestor = path.ancestors().skip(1).map(|a| if a.as_os_str().is_empty() { std::path::Path::new(".") } else { a }).find(|a| a.exists());
    match ancestor {
        None => Err("Ścieżka wskazuje na wolumin/dysk, który nie jest dostępny.".to_string()),
        Some(a) if !a.is_dir() => {
            Err("Najbliższy istniejący element tej ścieżki nie jest katalogiem.".to_string())
        }
        Some(a) => {
            // Heurystyka zapisywalności: spróbuj utworzyć i natychmiast usunąć
            // unikalny podkatalog tymczasowy wewnątrz `a`.
            let probe = a.join(format!(".weryfikator_probe_{}", std::process::id()));
            match std::fs::create_dir(&probe) {
                Ok(()) => {
                    let _ = std::fs::remove_dir(&probe);
                    Ok(())
                }
                Err(_) => Err(format!(
                    "Katalog '{}' nie jest zapisywalny - nie można w nim utworzyć nowej ścieżki.",
                    a.display()
                )),
            }
        }
    }
}

/// Zapisuje nową wartość jednego z trzech pól raportu danej fazy.
///
/// Pole 0 (`katalog`) przechodzi przez [`validate_report_katalog`] -
/// niepoprawna wartość jest ODRZUCANA (`Err`, `u` NIETKNIĘTE), analogicznie do
/// [`validate_and_set_text`] dla `ufs_path`/`script_path`. Pola 1 i 2 to
/// same NAZWY plików (dołączane do `katalog` przez fazy przez `Path::join`),
/// nie ścieżki - bez walidacji istnienia, tak jak dotąd.
pub fn set_report_value(u: &mut Ustawienia, phase: &str, field_idx: usize, val: String) -> Result<(), String> {
    if field_idx == 0 {
        validate_report_katalog(&val)?;
    }
    if let Some(r) = u.raporty_faz.get_mut(phase) {
        match field_idx {
            0 => r.katalog = val,
            1 => r.plik_operacyjny = val,
            2 => r.plik_dziennika = val,
            _ => {}
        }
    }
    Ok(())
}

// ============================================================================
// HASŁO ADMINISTRATORA
// ============================================================================

/// Sprawdza, czy podana próba hasła zgadza się z zapisanym hashem BLAKE3.
pub fn verify_password(u: &Ustawienia, attempt: &str) -> bool {
    blake3::hash(attempt.as_bytes()).to_hex().to_string() == u.admin_password_hash
}

/// Zapisuje nowy hash BLAKE3 dla podanego hasła w postaci jawnej.
pub fn set_new_password(u: &mut Ustawienia, new_password: &str) {
    u.admin_password_hash = blake3::hash(new_password.as_bytes()).to_hex().to_string();
}

// ============================================================================
// STAN EKRANU (AUTOMAT STANU)
// ============================================================================

/// Który z trzech poziomów ekranu jest aktualnie widoczny.
#[derive(Clone, Debug, PartialEq)]
pub enum Screen {
    Main,
    Reports { selected: usize },
    ReportsEdit { phase: String, selected: usize },
}

/// Etap kreatora zmiany hasła.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PasswordStage {
    Old,
    New,
    Confirm,
}

/// Dokąd zapisać wynik aktywnej edycji tekstu — pole listy głównej, czy
/// jedno z trzech pól raportu konkretnej fazy.
#[derive(Clone, Debug, PartialEq)]
pub enum EditTarget {
    Main(usize),
    Report { phase: String, field_idx: usize },
}

/// Aktywna nakładka edycji (rysowana NA WIERZCHU aktualnego `Screen`).
/// `None` oznacza zwykłą nawigację listą, bez żadnej nakładki.
#[derive(Clone, Debug, PartialEq)]
pub enum EditMode {
    None,
    Text { target: EditTarget, buffer: String, cursor: usize, error: Option<String> },
    Choice { idx: usize, selected: usize },
    Password { stage: PasswordStage, old_buf: String, new_buf: String, confirm_buf: String, error: Option<String> },
}

/// Pełny stan ekranu ustawień - żyje lokalnie w pętli `run_settings_with_ui`
/// (analogicznie do `PhaseUIState` dla ekranów faz), nie w `AppState`.
pub struct SettingsUiState {
    pub screen: Screen,
    pub selected_main: usize,
    pub edit: EditMode,
    pub should_exit: bool,
}

impl SettingsUiState {
    pub fn new() -> Self {
        Self { screen: Screen::Main, selected_main: 0, edit: EditMode::None, should_exit: false }
    }
}

impl Default for SettingsUiState {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// OBSŁUGA KLAWISZY
// ============================================================================

/// Domyślna ścieżka pliku konfiguracyjnego — ta sama, którą wczytuje `main`.
///
/// Celowo WZGLĘDNA, bo taka była dotąd i zmiana tego zachowania w produkcji
/// nie jest przedmiotem tej poprawki. Istotne jest, że nie jest już wpisana
/// literałem w czterech miejscach w głębi obsługi klawiszy — patrz
/// [`handle_key_do_pliku`].
const DOMYSLNA_SCIEZKA_USTAWIEN: &str = "ustawienia.json";

/// Rozmiar "strony" dla PageUp/PageDown w listach ekranu ustawień.
const STRONA_USTAWIEN: usize = 10;

/// Przesuwa zaznaczenie listy ustawień o `delta` pozycji (dodatnie = w dół),
/// DOCISKAJĄC do granic `0..len-1` zamiast zawijać.
///
/// W przeciwieństwie do `AppState::next_selection`/`page_down` (dashboard,
/// gdzie zawinięcie krótkiej listy jest naturalne), page-jump w dłuższych
/// listach ustawień NIE powinien teleportować operatora z góry na dół listy —
/// to zaskakujące i utrudnia orientację. Stąd `clamp`, nie modulo.
fn clamp_page_jump(current: usize, delta: isize, len: usize) -> usize {
    if len == 0 { return 0; }
    let max = (len - 1) as isize;
    (current as isize + delta).clamp(0, max) as usize
}

/// Główny punkt wejścia obsługi klawiatury — zapisuje zmiany do domyślnego
/// pliku konfiguracyjnego ([`DOMYSLNA_SCIEZKA_USTAWIEN`]).
///
/// Cała logika siedzi w [`handle_key_do_pliku`]; ta funkcja tylko podstawia
/// ścieżkę, żeby wywołujący z `menu::actions` nie musiał jej znać.
pub fn handle_key(key: KeyEvent, state: &mut SettingsUiState, u: &mut Ustawienia) {
    handle_key_do_pliku(key, state, u, DOMYSLNA_SCIEZKA_USTAWIEN)
}

/// Obsługa klawiatury z JAWNIE wskazanym plikiem docelowym zapisu.
///
/// ## Dlaczego ścieżka jest parametrem
///
/// Wcześniej cztery miejsca w głębi tego modułu wołały
/// `u.zapisz("ustawienia.json")` z literałem — ścieżką WZGLĘDNĄ, rozwiązywaną
/// względem katalogu roboczego procesu. Ponieważ `cargo test` uruchamia testy
/// z katalogu projektu, każdy test naciskający Enter w edytorze ustawień
/// nadpisywał PRAWDZIWY `ustawienia.json` projektu. Zaobserwowano m.in.
/// podmianę `target_path` na testową wartość "nowa_wartosc".
///
/// Teraz miejsce zapisu jest wstrzykiwane, więc testy podają plik tymczasowy.
/// Produkcja (`handle_key`) zachowuje się dokładnie jak dotąd.
pub fn handle_key_do_pliku(key: KeyEvent, state: &mut SettingsUiState, u: &mut Ustawienia, sciezka: &str) {
    let edit = std::mem::replace(&mut state.edit, EditMode::None);
    match edit {
        EditMode::None => handle_navigation_key(key, state, u, sciezka),
        EditMode::Text { target, buffer, cursor, error } => handle_text_edit_key(key, state, u, sciezka, target, buffer, cursor, error),
        EditMode::Choice { idx, selected } => handle_choice_edit_key(key, state, u, sciezka, idx, selected),
        EditMode::Password { stage, old_buf, new_buf, confirm_buf, error } => {
            handle_password_edit_key(key, state, u, sciezka, stage, old_buf, new_buf, confirm_buf, error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_text_edit_key(
    key: KeyEvent,
    state: &mut SettingsUiState,
    u: &mut Ustawienia,
    sciezka: &str,
    target: EditTarget,
    mut buffer: String,
    mut cursor: usize,
    mut error: Option<String>,
) {
    match key.code {
        KeyCode::Esc => { state.edit = EditMode::None; return; }
        KeyCode::Enter => {
            let result = match &target {
                EditTarget::Main(idx) => validate_and_set_text(u, *idx, &buffer),
                EditTarget::Report { phase, field_idx } => set_report_value(u, phase, *field_idx, buffer.clone()),
            };
            match result {
                Ok(()) => {
                    u.zapisz(sciezka);
                    state.edit = EditMode::None;
                    return;
                }
                Err(e) => { error = Some(e); }
            }
        }
        KeyCode::Backspace => {
            cursor = remove_before_cursor(&mut buffer, cursor);
            error = None;
        }
        KeyCode::Delete => {
            remove_after_cursor(&mut buffer, cursor);
            error = None;
        }
        KeyCode::Left => {
            cursor = cursor.saturating_sub(1);
        }
        KeyCode::Right => {
            let len = char_count(&buffer);
            if cursor < len { cursor += 1; }
        }
        KeyCode::Home => { cursor = 0; }
        KeyCode::End => { cursor = char_count(&buffer); }
        KeyCode::Char(c) => {
            insert_char_at(&mut buffer, cursor, c);
            cursor += 1;
            error = None;
        }
        _ => {}
    }
    state.edit = EditMode::Text { target, buffer, cursor, error };
}

fn handle_choice_edit_key(key: KeyEvent, state: &mut SettingsUiState, u: &mut Ustawienia, sciezka: &str, idx: usize, mut selected: usize) {
    let options = choice_options(idx);
    match key.code {
        KeyCode::Esc => { state.edit = EditMode::None; }
        KeyCode::Up | KeyCode::Char('k') => {
            selected = if selected == 0 { options.len().saturating_sub(1) } else { selected - 1 };
            state.edit = EditMode::Choice { idx, selected };
        }
        KeyCode::Down | KeyCode::Char('j') => {
            selected = if options.is_empty() { 0 } else { (selected + 1) % options.len() };
            state.edit = EditMode::Choice { idx, selected };
        }
        KeyCode::Enter => {
            set_choice(u, idx, selected);
            u.zapisz(sciezka);
            state.edit = EditMode::None;
        }
        _ => { state.edit = EditMode::Choice { idx, selected }; }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_password_edit_key(
    key: KeyEvent,
    state: &mut SettingsUiState,
    u: &mut Ustawienia,
    sciezka: &str,
    mut stage: PasswordStage,
    mut old_buf: String,
    mut new_buf: String,
    mut confirm_buf: String,
    mut error: Option<String>,
) {
    match key.code {
        KeyCode::Esc => { state.edit = EditMode::None; return; }
        KeyCode::Backspace => {
            match stage {
                PasswordStage::Old => { old_buf.pop(); }
                PasswordStage::New => { new_buf.pop(); }
                PasswordStage::Confirm => { confirm_buf.pop(); }
            }
            error = None;
        }
        KeyCode::Char(c) => {
            match stage {
                PasswordStage::Old => old_buf.push(c),
                PasswordStage::New => new_buf.push(c),
                PasswordStage::Confirm => confirm_buf.push(c),
            }
            error = None;
        }
        KeyCode::Enter => {
            match stage {
                PasswordStage::Old => {
                    if verify_password(u, &old_buf) {
                        stage = PasswordStage::New;
                    } else {
                        error = Some("Błędne hasło!".to_string());
                        old_buf.clear();
                    }
                }
                PasswordStage::New => {
                    if new_buf.is_empty() {
                        error = Some("Hasło nie może być puste.".to_string());
                    } else {
                        stage = PasswordStage::Confirm;
                    }
                }
                PasswordStage::Confirm => {
                    if confirm_buf == new_buf {
                        set_new_password(u, &new_buf);
                        u.zapisz(sciezka);
                        state.edit = EditMode::None;
                        return;
                    } else {
                        error = Some("Hasła się nie zgadzają. Wpisz nowe hasło ponownie.".to_string());
                        new_buf.clear();
                        confirm_buf.clear();
                        stage = PasswordStage::New;
                    }
                }
            }
        }
        _ => {}
    }
    state.edit = EditMode::Password { stage, old_buf, new_buf, confirm_buf, error };
}

fn handle_navigation_key(key: KeyEvent, state: &mut SettingsUiState, u: &mut Ustawienia, sciezka: &str) {
    match state.screen.clone() {
        Screen::Main => handle_main_navigation(key, state, u, sciezka),
        // Ekrany raportów same nic nie zapisują (zapis następuje dopiero przy
        // zatwierdzeniu edycji tekstu), więc nie potrzebują ścieżki.
        Screen::Reports { selected } => handle_reports_navigation(key, state, u, selected),
        Screen::ReportsEdit { phase, selected } => handle_reports_edit_navigation(key, state, u, phase, selected),
    }
}

fn handle_main_navigation(key: KeyEvent, state: &mut SettingsUiState, u: &mut Ustawienia, sciezka: &str) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            state.selected_main = if state.selected_main == 0 { FIELD_LABELS.len() - 1 } else { state.selected_main - 1 };
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.selected_main = (state.selected_main + 1) % FIELD_LABELS.len();
        }
        KeyCode::PageUp => {
            state.selected_main = clamp_page_jump(state.selected_main, -(STRONA_USTAWIEN as isize), FIELD_LABELS.len());
        }
        KeyCode::PageDown => {
            state.selected_main = clamp_page_jump(state.selected_main, STRONA_USTAWIEN as isize, FIELD_LABELS.len());
        }
        KeyCode::Esc => { state.should_exit = true; }
        KeyCode::Enter => {
            let idx = state.selected_main;
            match FIELD_KINDS[idx] {
                FieldKind::Text | FieldKind::Number => {
                    let buffer = get_edit_buffer(u, idx);
                    let cursor = char_count(&buffer);
                    state.edit = EditMode::Text { target: EditTarget::Main(idx), buffer, cursor, error: None };
                }
                FieldKind::Toggle => {
                    toggle_bool(u, idx);
                    u.zapisz(sciezka);
                }
                FieldKind::Choice => {
                    state.edit = EditMode::Choice { idx, selected: get_choice_current(u, idx) };
                }
                FieldKind::Password => {
                    state.edit = EditMode::Password {
                        stage: PasswordStage::Old, old_buf: String::new(), new_buf: String::new(), confirm_buf: String::new(), error: None,
                    };
                }
                FieldKind::Submenu => { state.screen = Screen::Reports { selected: 0 }; }
                FieldKind::Back => { state.should_exit = true; }
            }
        }
        _ => {}
    }
}

fn handle_reports_navigation(key: KeyEvent, state: &mut SettingsUiState, u: &mut Ustawienia, selected: usize) {
    let keys = sorted_phase_keys(u);
    let count = keys.len() + 1; // +1 dla pozycji "Wróć"
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            state.screen = Screen::Reports { selected: if selected == 0 { count.saturating_sub(1) } else { selected - 1 } };
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.screen = Screen::Reports { selected: (selected + 1) % count.max(1) };
        }
        KeyCode::PageUp => {
            state.screen = Screen::Reports { selected: clamp_page_jump(selected, -(STRONA_USTAWIEN as isize), count) };
        }
        KeyCode::PageDown => {
            state.screen = Screen::Reports { selected: clamp_page_jump(selected, STRONA_USTAWIEN as isize, count) };
        }
        KeyCode::Esc => { state.screen = Screen::Main; }
        KeyCode::Enter => {
            if selected >= keys.len() {
                state.screen = Screen::Main;
            } else {
                state.screen = Screen::ReportsEdit { phase: keys[selected].clone(), selected: 0 };
            }
        }
        _ => {}
    }
}

fn handle_reports_edit_navigation(key: KeyEvent, state: &mut SettingsUiState, u: &mut Ustawienia, phase: String, selected: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            state.screen = Screen::ReportsEdit { phase, selected: if selected == 0 { 2 } else { selected - 1 } };
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.screen = Screen::ReportsEdit { phase, selected: (selected + 1) % 3 };
        }
        KeyCode::Esc => { state.screen = Screen::Reports { selected: 0 }; }
        KeyCode::Enter => {
            let buffer = get_report_value(u, &phase, selected);
            let cursor = char_count(&buffer);
            state.edit = EditMode::Text { target: EditTarget::Report { phase: phase.clone(), field_idx: selected }, buffer, cursor, error: None };
            state.screen = Screen::ReportsEdit { phase, selected };
        }
        _ => {}
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE (zero I/O terminala; zapis WYŁĄCZNIE do pliku tymczasowego)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use tempfile::NamedTempFile;

    /// PRZESŁANIA produkcyjne [`super::handle_key`] w obrębie tego modułu
    /// testów, przekierowując zapis konfiguracji do pliku TYMCZASOWEGO.
    ///
    /// ## Dlaczego przesłonięcie, a nie osobna nazwa
    ///
    /// Produkcyjne `handle_key` pisze do `ustawienia.json` ze ścieżką
    /// WZGLĘDNĄ, a `cargo test` startuje z katalogu projektu — więc każdy test
    /// naciskający Enter w edytorze ustawień nadpisywał PRAWDZIWĄ konfigurację
    /// projektu (zaobserwowano podmianę `target_path` na "nowa_wartosc").
    ///
    /// Elementy zadeklarowane w module mają pierwszeństwo nad importem `*`,
    /// więc każde `handle_key(...)` w testach niżej trafia TUTAJ. To celowo
    /// mocniejsze zabezpieczenie niż przepisanie wywołań na inną nazwę: nowy
    /// test dopisany w przyszłości jest bezpieczny automatycznie, bez pamiętania
    /// o niczym. Testowana logika jest ta sama — różni się wyłącznie plik
    /// docelowy zapisu.
    ///
    /// Test, który chce sprawdzić SAM zapis, niech woła
    /// [`super::handle_key_do_pliku`] wprost z własną ścieżką.
    fn handle_key(key: KeyEvent, state: &mut SettingsUiState, u: &mut Ustawienia) {
        let tmp = NamedTempFile::new().expect("nie udało się utworzyć pliku tymczasowego na konfigurację testową");
        let sciezka = tmp.path().to_str().expect("ścieżka pliku tymczasowego nie jest poprawnym UTF-8");
        handle_key_do_pliku(key, state, u, sciezka);
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent { code, modifiers: KeyModifiers::NONE, kind: KeyEventKind::Press, state: KeyEventState::NONE }
    }

    fn char_key(c: char) -> KeyEvent { key(KeyCode::Char(c)) }

    // ------------------------------------------------------------------
    // Spójność definicji pól
    // ------------------------------------------------------------------

    #[test]
    fn test_field_labels_and_kinds_same_length() {
        assert_eq!(FIELD_LABELS.len(), FIELD_KINDS.len());
    }

    #[test]
    fn test_last_field_is_back() {
        assert_eq!(FIELD_KINDS[FIELD_KINDS.len() - 1], FieldKind::Back);
    }

    // ------------------------------------------------------------------
    // validate_and_set_text
    // ------------------------------------------------------------------

    #[test]
    fn test_validate_nonexistent_ufs_path_rejected() {
        let mut u = Ustawienia::default();
        let original = u.ufs_path.clone();
        let result = validate_and_set_text(&mut u, 0, "/na/pewno/nie/istnieje/xyz123");
        assert!(result.is_err());
        assert_eq!(u.ufs_path, original, "Pole nie powinno się zmienić przy nieudanej walidacji");
    }

    #[test]
    fn test_validate_existing_path_accepted() {
        let mut u = Ustawienia::default();
        let tmp = std::env::temp_dir();
        let result = validate_and_set_text(&mut u, 0, tmp.to_str().unwrap());
        assert!(result.is_ok());
        assert_eq!(u.ufs_path, tmp.to_str().unwrap());
    }

    #[test]
    fn test_validate_number_field_rejects_non_numeric() {
        let mut u = Ustawienia::default();
        let original = u.max_threads;
        let result = validate_and_set_text(&mut u, 15, "nie liczba");
        assert!(result.is_err());
        assert_eq!(u.max_threads, original);
    }

    #[test]
    fn test_validate_number_field_accepts_valid_number() {
        let mut u = Ustawienia::default();
        let result = validate_and_set_text(&mut u, 15, "8");
        assert!(result.is_ok());
        assert_eq!(u.max_threads, 8);
    }

    #[test]
    fn test_validate_text_field_no_validation_needed() {
        let mut u = Ustawienia::default();
        let result = validate_and_set_text(&mut u, 2, "/dowolna/nieistniejaca/sciezka");
        assert!(result.is_ok(), "target_path nie ma walidacji istnienia");
        assert_eq!(u.target_path, "/dowolna/nieistniejaca/sciezka");
    }

    // ------------------------------------------------------------------
    // choice fields
    // ------------------------------------------------------------------

    #[test]
    fn test_choice_io_mode_roundtrip() {
        let mut u = Ustawienia {
            io_mode: "SEQUENTIAL".to_string(),
            ..Default::default()
        };
        assert_eq!(get_choice_current(&u, 12), 1);
        set_choice(&mut u, 12, 0);
        assert_eq!(u.io_mode, "CONCURRENT");
    }

    #[test]
    fn test_choice_log_level_roundtrip() {
        let mut u = Ustawienia {
            log_level: "WARN".to_string(),
            ..Default::default()
        };
        assert_eq!(get_choice_current(&u, 13), 3);
        set_choice(&mut u, 13, 4);
        assert_eq!(u.log_level, "ERROR");
    }

    // ------------------------------------------------------------------
    // toggle fields
    // ------------------------------------------------------------------

    #[test]
    fn test_toggle_phase13_fast_mode() {
        let mut u = Ustawienia::default();
        let original = u.phase13_fast_mode;
        toggle_bool(&mut u, 9);
        assert_eq!(u.phase13_fast_mode, !original);
    }

    #[test]
    fn test_toggle_deep_archive_scan() {
        let mut u = Ustawienia::default();
        let original = u.deep_archive_scan;
        toggle_bool(&mut u, 10);
        assert_eq!(u.deep_archive_scan, !original);
    }

    // ------------------------------------------------------------------
    // password
    // ------------------------------------------------------------------

    #[test]
    fn test_verify_password_default_admin() {
        let u = Ustawienia::default();
        // Domyślne hasło to "admin" (patrz default_admin_password_hash)
        assert!(verify_password(&u, "admin"));
        assert!(!verify_password(&u, "zle_haslo"));
    }

    #[test]
    fn test_set_new_password_changes_hash() {
        let mut u = Ustawienia::default();
        let old_hash = u.admin_password_hash.clone();
        set_new_password(&mut u, "nowe_bezpieczne_haslo");
        assert_ne!(u.admin_password_hash, old_hash);
        assert!(verify_password(&u, "nowe_bezpieczne_haslo"));
        assert!(!verify_password(&u, "admin"));
    }

    // ------------------------------------------------------------------
    // reports submenu
    // ------------------------------------------------------------------

    #[test]
    fn test_sorted_phase_keys_deterministic_order() {
        let u = Ustawienia::default();
        let keys1 = sorted_phase_keys(&u);
        let keys2 = sorted_phase_keys(&u);
        assert_eq!(keys1, keys2, "Kolejność nie może zależeć od losowego układu HashMap");
    }

    /// Klucze nie mają już zera wiodącego (musiały je stracić, żeby trafiać w
    /// `raporty_faz.get("Faza 7")`), więc zwykłe `sort()` ustawiłoby
    /// `"Faza 10"` przed `"Faza 2"`. Ten test pilnuje, że sortowanie jest
    /// numeryczne i lista w ekranie ustawień zostaje czytelna.
    #[test]
    fn test_sorted_phase_keys_sortuje_numerycznie_nie_leksykograficznie() {
        let u = Ustawienia::default();
        let keys = sorted_phase_keys(&u);

        let numery: Vec<u32> = keys
            .iter()
            .filter_map(|k| k.strip_prefix("Faza ").and_then(|n| n.parse().ok()))
            .collect();

        assert_eq!(numery.len(), 19, "Powinno być 19 faz");
        assert!(
            numery.windows(2).all(|w| w[0] < w[1]),
            "Fazy muszą iść rosnąco po NUMERZE, a wyszły: {:?}", numery
        );
        assert_eq!(numery[0], 1, "Pierwsza pozycja to Faza 1");
        assert_eq!(numery[18], 19, "Ostatnia faza to Faza 19");

        // Dowód, że sortowanie leksykograficzne dałoby inny wynik — bez tego
        // test przechodziłby także dla zwykłego `sort()`.
        let mut leksykograficznie = keys.clone();
        leksykograficznie.sort();
        assert_ne!(keys, leksykograficznie, "Test bez sensu, jeśli oba sortowania dają to samo");
    }

    /// Pozycje bez numeru (`"Duplikaty"`) idą na koniec, żeby nie rozrywać
    /// ciągu faz w połowie listy.
    #[test]
    fn test_sorted_phase_keys_pozycje_bez_numeru_na_koncu() {
        let u = Ustawienia::default();
        let keys = sorted_phase_keys(&u);
        assert_eq!(keys.last().map(|s| s.as_str()), Some("Duplikaty"));
    }

    #[test]
    fn test_sorted_phase_keys_zawiera_kazda_pozycje_z_mapy() {
        let u = Ustawienia::default();
        assert_eq!(sorted_phase_keys(&u).len(), u.raporty_faz.len());
    }

    #[test]
    fn test_report_value_roundtrip() {
        let mut u = Ustawienia::default();
        let phase = sorted_phase_keys(&u)[0].clone();
        // "nowy_katalog" - względna nazwa bez separatora, jeszcze nieutworzona,
        // ale jej przodek (katalog roboczy ".") istnieje i jest zapisywalny
        // (uruchamiamy testy z katalogu projektu) -> musi zostać zaakceptowana.
        let result = set_report_value(&mut u, &phase, 0, "nowy_katalog".to_string());
        assert!(result.is_ok(), "Poprawna, jeszcze nieutworzona ścieżka z zapisywalnym rodzicem powinna być zaakceptowana: {:?}", result);
        assert_eq!(get_report_value(&u, &phase, 0), "nowy_katalog");
    }

    #[test]
    fn test_report_value_pole_1_i_2_bez_walidacji() {
        // plik_operacyjny / plik_dziennika to same NAZWY plików, nie ścieżki
        // katalogów - nie przechodzą przez walidację `katalog` i akceptują
        // dowolny string, tak jak dotąd (żeby nie zepsuć istniejącego
        // zachowania dla pól, które nie są przedmiotem tej poprawki).
        let mut u = Ustawienia::default();
        let phase = sorted_phase_keys(&u)[0].clone();
        assert!(set_report_value(&mut u, &phase, 1, String::new()).is_ok());
        assert!(set_report_value(&mut u, &phase, 2, "  ".to_string()).is_ok());
    }

    // ------------------------------------------------------------------
    // REGRESJA: walidacja katalogu raportów per faza (set_report_value, pole 0)
    //
    // Bez tej walidacji dowolny string wpisany przez operatora w podmenu
    // raportów trafiał NIEWALIDOWANY do `ustawienia.json`, a stamtąd do
    // `fs::create_dir_all(...).unwrap_or_default()` (tolerancyjne) i zaraz
    // potem `File::create(...).unwrap()` (panika) w co najmniej 12 fazach
    // przy starcie pierwszej uruchomionej fazy — utrata całego przebiegu.
    // ------------------------------------------------------------------

    #[test]
    fn test_report_katalog_pusty_string_odrzucony() {
        let mut u = Ustawienia::default();
        let phase = sorted_phase_keys(&u)[0].clone();
        let original = get_report_value(&u, &phase, 0);

        let result = set_report_value(&mut u, &phase, 0, String::new());

        assert!(result.is_err(), "Pusty katalog musi zostać odrzucony");
        assert_eq!(get_report_value(&u, &phase, 0), original, "Poprzednia poprawna wartość musi pozostać nietknięta");
    }

    #[test]
    fn test_report_katalog_sam_bialy_znak_odrzucony() {
        let mut u = Ustawienia::default();
        let phase = sorted_phase_keys(&u)[0].clone();
        let original = get_report_value(&u, &phase, 0);

        let result = set_report_value(&mut u, &phase, 0, "   ".to_string());

        assert!(result.is_err(), "Sam biały znak nie jest poprawnym katalogiem");
        assert_eq!(get_report_value(&u, &phase, 0), original);
    }

    #[test]
    fn test_report_katalog_wskazujacy_na_plik_regularny_odrzucony() {
        let mut u = Ustawienia::default();
        let phase = sorted_phase_keys(&u)[0].clone();
        let original = get_report_value(&u, &phase, 0);

        // Prawdziwy, istniejący PLIK (nie katalog) - operator pomylił pole.
        let plik = NamedTempFile::new().expect("nie udało się utworzyć pliku tymczasowego");
        let sciezka_pliku = plik.path().to_str().unwrap().to_string();

        let result = set_report_value(&mut u, &phase, 0, sciezka_pliku);

        assert!(result.is_err(), "Ścieżka do istniejącego PLIKU nie może zostać zaakceptowana jako katalog raportów");
        assert_eq!(get_report_value(&u, &phase, 0), original, "Zła wartość nie może nadpisać poprzedniej poprawnej");
    }

    #[test]
    fn test_report_katalog_niedostepny_wolumin_odrzucony() {
        // Test zakłada, że proces NIE MOŻE pisać bezpośrednio w "/" - prawda
        // dla każdego zwykłego użytkownika, ale fałsz dla roota (który może
        // zapisać wszędzie). `validate_report_katalog` wtedy POPRAWNIE
        // akceptuje ścieżkę (root faktycznie może ją utworzyć) - to test, nie
        // walidacja, ma tu błędne założenie, więc pomijamy go pod rootem
        // zamiast osłabiać samą walidację.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("Pominięto: test zakłada brak uprawnień roota do zapisu w '/'.");
            return;
        }

        let mut u = Ustawienia::default();
        let phase = sorted_phase_keys(&u)[0].clone();
        let original = get_report_value(&u, &phase, 0);

        // Prefiks tej ścieżki (/na/pewno/nie/istnieje/...) na pewno nie
        // istnieje w żadnym rozsądnym środowisku CI/deweloperskim - symuluje
        // niezamontowany dysk sieciowy: ŻADEN przodek tej ścieżki nie istnieje.
        let result = set_report_value(&mut u, &phase, 0, "/na/pewno/nie/istnieje/xyz123/podkatalog/raporty".to_string());

        assert!(result.is_err(), "Ścieżka na całkowicie niedostępnym wolumenie musi zostać odrzucona");
        assert_eq!(get_report_value(&u, &phase, 0), original);
    }

    #[test]
    fn test_report_katalog_poprawna_nieutworzona_sciezka_z_zapisywalnym_rodzicem_akceptowana() {
        let mut u = Ustawienia::default();
        let phase = sorted_phase_keys(&u)[0].clone();

        // Rodzic (std::env::temp_dir()) istnieje i jest zapisywalny; sam
        // podkatalog jeszcze nie istnieje - dokładnie ten przypadek, który
        // walidacja MUSI dopuścić, żeby nie blokować legalnej konfiguracji
        // nowych, jeszcze nieutworzonych katalogów raportów.
        let nowy = std::env::temp_dir().join(format!("weryfikator_test_katalog_raportow_{}", std::process::id()));
        // Sprzątanie na wypadek pozostałości po poprzednim (przerwanym) uruchomieniu.
        let _ = std::fs::remove_dir(&nowy);
        let sciezka = nowy.to_str().unwrap().to_string();

        let result = set_report_value(&mut u, &phase, 0, sciezka.clone());

        assert!(result.is_ok(), "Nowa, jeszcze nieutworzona ścieżka z zapisywalnym rodzicem musi być zaakceptowana: {:?}", result);
        assert_eq!(get_report_value(&u, &phase, 0), sciezka);
        assert!(!nowy.exists(), "Walidacja NIE powinna sama tworzyć katalogu - to zadanie `create_dir_all` przy starcie fazy");
    }

    #[test]
    fn test_report_katalog_istniejacy_katalog_akceptowany() {
        let mut u = Ustawienia::default();
        let phase = sorted_phase_keys(&u)[0].clone();
        let tmp = std::env::temp_dir();

        let result = set_report_value(&mut u, &phase, 0, tmp.to_str().unwrap().to_string());

        assert!(result.is_ok());
        assert_eq!(get_report_value(&u, &phase, 0), tmp.to_str().unwrap());
    }

    #[test]
    fn test_text_edit_key_enter_z_nieprawidlowym_katalogiem_raportu_pokazuje_blad_i_nie_zapisuje() {
        // Ten sam kontrakt UI co `test_text_edit_enter_with_invalid_value_shows_error_and_stays_open`
        // dla pola listy głównej, ale dla ścieżki EditTarget::Report - dowodzi,
        // że handler klawisza Enter faktycznie korzysta z wyniku
        // `set_report_value` (a nie ignoruje go), pokazuje błąd operatorowi i
        // zostawia nakładkę otwartą zamiast cicho zapisać złą wartość.
        let mut u = Ustawienia::default();
        let phase = sorted_phase_keys(&u)[0].clone();
        let original = get_report_value(&u, &phase, 0);
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text {
            target: EditTarget::Report { phase: phase.clone(), field_idx: 0 },
            buffer: String::new(),
            cursor: 0,
            error: None,
        };

        handle_key(key(KeyCode::Enter), &mut state, &mut u);

        match state.edit {
            EditMode::Text { error: Some(_), target: EditTarget::Report { field_idx: 0, .. }, .. } => {}
            _ => panic!("Pusty katalog raportu powinien zostawić nakładkę otwartą z komunikatem błędu"),
        }
        assert_eq!(get_report_value(&u, &phase, 0), original, "Zła wartość nie mogła trafić do stanu");
    }

    // ------------------------------------------------------------------
    // Automat stanu - nawigacja listy głównej
    // ------------------------------------------------------------------

    #[test]
    fn test_navigation_down_wraps_around() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.selected_main = FIELD_LABELS.len() - 1;
        handle_key(char_key('j'), &mut state, &mut u);
        assert_eq!(state.selected_main, 0);
    }

    #[test]
    fn test_navigation_up_wraps_around() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.selected_main = 0;
        handle_key(key(KeyCode::Up), &mut state, &mut u);
        assert_eq!(state.selected_main, FIELD_LABELS.len() - 1);
    }

    #[test]
    fn test_clamp_page_jump_nie_przekracza_gornej_granicy() {
        assert_eq!(clamp_page_jump(5, 10, 8), 7, "Musi się zatrzymać na ostatnim indeksie, nie zawinąć na początek");
    }

    #[test]
    fn test_clamp_page_jump_nie_schodzi_ponizej_zera() {
        assert_eq!(clamp_page_jump(3, -10, 8), 0, "Musi się zatrzymać na zerze, nie zawinąć na koniec");
    }

    #[test]
    fn test_clamp_page_jump_pusta_lista_daje_zero() {
        assert_eq!(clamp_page_jump(0, 5, 0), 0);
    }

    #[test]
    fn test_page_down_na_liscie_glownej_przesuwa_o_strone_bez_zawijania() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.selected_main = 0;
        handle_key(key(KeyCode::PageDown), &mut state, &mut u);
        assert_eq!(state.selected_main, STRONA_USTAWIEN.min(FIELD_LABELS.len() - 1));
    }

    #[test]
    fn test_page_down_blisko_konca_listy_glownej_docisketa_do_ostatniej_pozycji() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.selected_main = FIELD_LABELS.len() - 1;
        handle_key(key(KeyCode::PageDown), &mut state, &mut u);
        assert_eq!(state.selected_main, FIELD_LABELS.len() - 1, "PageDown na końcu nie może zawinąć na początek listy");
    }

    #[test]
    fn test_page_up_na_poczatku_listy_glownej_zostaje_na_zerze() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.selected_main = 0;
        handle_key(key(KeyCode::PageUp), &mut state, &mut u);
        assert_eq!(state.selected_main, 0, "PageUp na początku nie może zawinąć na koniec listy");
    }

    #[test]
    fn test_page_up_po_page_down_wraca_blisko_poczatku() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.selected_main = FIELD_LABELS.len() - 1;
        handle_key(key(KeyCode::PageUp), &mut state, &mut u);
        assert_eq!(state.selected_main, FIELD_LABELS.len() - 1 - STRONA_USTAWIEN);
    }

    #[test]
    fn test_page_down_w_liscie_raportow_przesuwa_bez_zawijania() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.screen = Screen::Reports { selected: 0 };
        handle_key(key(KeyCode::PageDown), &mut state, &mut u);
        let count = sorted_phase_keys(&u).len() + 1;
        match state.screen {
            Screen::Reports { selected } => assert_eq!(selected, STRONA_USTAWIEN.min(count - 1)),
            _ => panic!("Ekran musi pozostać Reports"),
        }
    }

    #[test]
    fn test_esc_on_main_screen_exits() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        handle_key(key(KeyCode::Esc), &mut state, &mut u);
        assert!(state.should_exit);
    }

    #[test]
    fn test_enter_on_back_field_exits() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.selected_main = FIELD_LABELS.len() - 1;
        handle_key(key(KeyCode::Enter), &mut state, &mut u);
        assert!(state.should_exit);
    }

    #[test]
    fn test_enter_on_toggle_field_flips_immediately_without_popup() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.selected_main = 9; // phase13_fast_mode
        let original = u.phase13_fast_mode;
        handle_key(key(KeyCode::Enter), &mut state, &mut u);
        assert_eq!(u.phase13_fast_mode, !original);
        assert_eq!(state.edit, EditMode::None, "Przełącznik nie powinien otwierać żadnej nakładki");
    }

    #[test]
    fn test_enter_on_text_field_opens_text_popup() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.selected_main = 2; // target_path
        handle_key(key(KeyCode::Enter), &mut state, &mut u);
        match state.edit {
            EditMode::Text { target: EditTarget::Main(2), .. } => {}
            _ => panic!("Oczekiwano EditMode::Text dla pola tekstowego"),
        }
    }

    #[test]
    fn test_enter_on_submenu_field_navigates_to_reports() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.selected_main = 8; // raporty_faz
        handle_key(key(KeyCode::Enter), &mut state, &mut u);
        assert_eq!(state.screen, Screen::Reports { selected: 0 });
    }

    // ------------------------------------------------------------------
    // Automat stanu - edycja tekstu
    // ------------------------------------------------------------------

    #[test]
    fn test_text_edit_typing_and_backspace() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: String::new(), cursor: 0, error: None };

        handle_key(char_key('a'), &mut state, &mut u);
        handle_key(char_key('b'), &mut state, &mut u);
        handle_key(char_key('c'), &mut state, &mut u);
        if let EditMode::Text { buffer, cursor, .. } = &state.edit { assert_eq!(buffer, "abc"); assert_eq!(*cursor, 3); } else { panic!("Powinno pozostać w trybie edycji"); }

        handle_key(key(KeyCode::Backspace), &mut state, &mut u);
        if let EditMode::Text { buffer, cursor, .. } = &state.edit { assert_eq!(buffer, "ab"); assert_eq!(*cursor, 2); } else { panic!("Powinno pozostać w trybie edycji"); }
    }

    #[test]
    fn test_text_edit_left_right_navigation() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "abc".to_string(), cursor: 3, error: None };

        handle_key(key(KeyCode::Left), &mut state, &mut u);
        handle_key(key(KeyCode::Left), &mut state, &mut u);
        if let EditMode::Text { cursor, .. } = &state.edit { assert_eq!(*cursor, 1); } else { panic!(); }

        handle_key(key(KeyCode::Right), &mut state, &mut u);
        if let EditMode::Text { cursor, .. } = &state.edit { assert_eq!(*cursor, 2); } else { panic!(); }
    }

    #[test]
    fn test_text_edit_left_stops_at_zero() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "abc".to_string(), cursor: 0, error: None };

        handle_key(key(KeyCode::Left), &mut state, &mut u);
        if let EditMode::Text { cursor, .. } = &state.edit { assert_eq!(*cursor, 0, "Kursor nie powinien zejść poniżej zera"); } else { panic!(); }
    }

    #[test]
    fn test_text_edit_right_stops_at_end() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "abc".to_string(), cursor: 3, error: None };

        handle_key(key(KeyCode::Right), &mut state, &mut u);
        if let EditMode::Text { cursor, .. } = &state.edit { assert_eq!(*cursor, 3, "Kursor nie powinien wyjść poza koniec bufora"); } else { panic!(); }
    }

    #[test]
    fn test_text_edit_home_and_end() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "abcde".to_string(), cursor: 2, error: None };

        handle_key(key(KeyCode::Home), &mut state, &mut u);
        if let EditMode::Text { cursor, .. } = &state.edit { assert_eq!(*cursor, 0); } else { panic!(); }

        handle_key(key(KeyCode::End), &mut state, &mut u);
        if let EditMode::Text { cursor, .. } = &state.edit { assert_eq!(*cursor, 5); } else { panic!(); }
    }

    #[test]
    fn test_text_edit_insert_in_middle_of_buffer() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        // "ac" z kursorem między a i c -> wpisanie 'b' powinno dać "abc"
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "ac".to_string(), cursor: 1, error: None };

        handle_key(char_key('b'), &mut state, &mut u);
        if let EditMode::Text { buffer, cursor, .. } = &state.edit {
            assert_eq!(buffer, "abc");
            assert_eq!(*cursor, 2, "Kursor powinien przesunąć się o jeden po wstawieniu");
        } else { panic!(); }
    }

    #[test]
    fn test_text_edit_delete_removes_char_after_cursor() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        // "abc" z kursorem PRZED 'b' (pozycja 1) -> Delete usuwa 'b', zostaje "ac"
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "abc".to_string(), cursor: 1, error: None };

        handle_key(key(KeyCode::Delete), &mut state, &mut u);
        if let EditMode::Text { buffer, cursor, .. } = &state.edit {
            assert_eq!(buffer, "ac");
            assert_eq!(*cursor, 1, "Delete nie powinien przesuwać kursora");
        } else { panic!(); }
    }

    #[test]
    fn test_text_edit_delete_at_end_is_noop() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "abc".to_string(), cursor: 3, error: None };

        handle_key(key(KeyCode::Delete), &mut state, &mut u);
        if let EditMode::Text { buffer, cursor, .. } = &state.edit {
            assert_eq!(buffer, "abc", "Delete na końcu bufora nie powinien niczego usuwać");
            assert_eq!(*cursor, 3);
        } else { panic!(); }
    }

    #[test]
    fn test_text_edit_backspace_in_middle_of_buffer() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        // "abc" z kursorem PO 'b' (pozycja 2) -> Backspace usuwa 'b', zostaje "ac", kursor na 1
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "abc".to_string(), cursor: 2, error: None };

        handle_key(key(KeyCode::Backspace), &mut state, &mut u);
        if let EditMode::Text { buffer, cursor, .. } = &state.edit {
            assert_eq!(buffer, "ac");
            assert_eq!(*cursor, 1);
        } else { panic!(); }
    }

    #[test]
    fn test_text_edit_backspace_at_start_is_noop() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "abc".to_string(), cursor: 0, error: None };

        handle_key(key(KeyCode::Backspace), &mut state, &mut u);
        if let EditMode::Text { buffer, cursor, .. } = &state.edit {
            assert_eq!(buffer, "abc", "Backspace na początku bufora nie powinien niczego usuwać");
            assert_eq!(*cursor, 0);
        } else { panic!(); }
    }

    #[test]
    fn test_text_edit_cursor_starts_at_end_of_prefilled_buffer() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.selected_main = 2; // target_path, ma niepustą domyślną wartość
        let expected_len = char_count(&u.target_path);

        handle_key(key(KeyCode::Enter), &mut state, &mut u);

        match state.edit {
            EditMode::Text { cursor, .. } => assert_eq!(cursor, expected_len, "Kursor powinien startować na końcu istniejącej wartości"),
            _ => panic!("Oczekiwano EditMode::Text"),
        }
    }

    #[test]
    fn test_text_edit_handles_polish_diacritics_as_single_char_steps() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        // "źółć" - znaki wielobajtowe w UTF-8; kursor musi poruszać się PO ZNAKACH, nie bajtach
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "źółć".to_string(), cursor: 4, error: None };

        handle_key(key(KeyCode::Left), &mut state, &mut u);
        handle_key(key(KeyCode::Backspace), &mut state, &mut u);
        if let EditMode::Text { buffer, cursor, .. } = &state.edit {
            assert_eq!(buffer, "źóć", "Backspace powinien usunąć CAŁY znak 'ł', nie jego pojedynczy bajt");
            assert_eq!(*cursor, 2);
        } else { panic!(); }
    }

    #[test]
    fn test_text_edit_esc_cancels_without_saving() {
        let mut u = Ustawienia::default();
        let original = u.target_path.clone();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "cos_innego".to_string(), cursor: 10, error: None };

        handle_key(key(KeyCode::Esc), &mut state, &mut u);
        assert_eq!(state.edit, EditMode::None);
        assert_eq!(u.target_path, original, "Esc nie powinien zapisywać zmian");
    }

    #[test]
    fn test_text_edit_enter_saves_and_closes_popup() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "nowa_wartosc".to_string(), cursor: 12, error: None };

        handle_key(key(KeyCode::Enter), &mut state, &mut u);
        assert_eq!(u.target_path, "nowa_wartosc");
        assert_eq!(state.edit, EditMode::None);
    }

    #[test]
    fn test_text_edit_enter_with_invalid_value_shows_error_and_stays_open() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text { target: EditTarget::Main(15), buffer: "nie_liczba".to_string(), cursor: 10, error: None }; // max_threads

        handle_key(key(KeyCode::Enter), &mut state, &mut u);
        match state.edit {
            EditMode::Text { error: Some(_), .. } => {}
            _ => panic!("Błędna wartość powinna zostawić nakładkę otwartą z komunikatem błędu"),
        }
    }

    // ------------------------------------------------------------------
    // Automat stanu - edycja wyboru (Choice)
    // ------------------------------------------------------------------

    #[test]
    fn test_choice_edit_navigation_and_confirm() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Choice { idx: 12, selected: 0 }; // io_mode

        handle_key(key(KeyCode::Down), &mut state, &mut u);
        if let EditMode::Choice { selected, .. } = state.edit { assert_eq!(selected, 1); } else { panic!("Powinno pozostać w trybie wyboru"); }

        handle_key(key(KeyCode::Enter), &mut state, &mut u);
        assert_eq!(u.io_mode, "SEQUENTIAL");
        assert_eq!(state.edit, EditMode::None);
    }

    // ------------------------------------------------------------------
    // Automat stanu - kreator hasła
    // ------------------------------------------------------------------

    #[test]
    fn test_password_wizard_full_success_flow() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Password { stage: PasswordStage::Old, old_buf: String::new(), new_buf: String::new(), confirm_buf: String::new(), error: None };

        for c in "admin".chars() { handle_key(char_key(c), &mut state, &mut u); }
        handle_key(key(KeyCode::Enter), &mut state, &mut u);
        match &state.edit { EditMode::Password { stage: PasswordStage::New, .. } => {}, _ => panic!("Powinno przejść do etapu New") }

        for c in "nowehaslo".chars() { handle_key(char_key(c), &mut state, &mut u); }
        handle_key(key(KeyCode::Enter), &mut state, &mut u);
        match &state.edit { EditMode::Password { stage: PasswordStage::Confirm, .. } => {}, _ => panic!("Powinno przejść do etapu Confirm") }

        for c in "nowehaslo".chars() { handle_key(char_key(c), &mut state, &mut u); }
        handle_key(key(KeyCode::Enter), &mut state, &mut u);

        assert_eq!(state.edit, EditMode::None);
        assert!(verify_password(&u, "nowehaslo"));
    }

    #[test]
    fn test_password_wizard_wrong_old_password_shows_error() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Password { stage: PasswordStage::Old, old_buf: String::new(), new_buf: String::new(), confirm_buf: String::new(), error: None };

        for c in "zlehaslo".chars() { handle_key(char_key(c), &mut state, &mut u); }
        handle_key(key(KeyCode::Enter), &mut state, &mut u);

        match &state.edit {
            EditMode::Password { stage: PasswordStage::Old, error: Some(_), old_buf, .. } => assert!(old_buf.is_empty(), "Bufor błędnego hasła powinien się wyczyścić"),
            _ => panic!("Powinno zostać na etapie Old z komunikatem błędu"),
        }
        assert!(verify_password(&u, "admin"), "Hasło nie powinno się zmienić");
    }

    #[test]
    fn test_password_wizard_mismatched_confirmation_returns_to_new_stage() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Password { stage: PasswordStage::Confirm, old_buf: "admin".to_string(), new_buf: "abc".to_string(), confirm_buf: "xyz".to_string(), error: None };

        handle_key(key(KeyCode::Enter), &mut state, &mut u);

        match &state.edit {
            EditMode::Password { stage: PasswordStage::New, new_buf, confirm_buf, error: Some(_), .. } => {
                assert!(new_buf.is_empty());
                assert!(confirm_buf.is_empty());
            }
            _ => panic!("Niezgodne potwierdzenie powinno wrócić do etapu New z wyczyszczonymi buforami"),
        }
    }

    // ------------------------------------------------------------------
    // Podmenu raportów - nawigacja
    // ------------------------------------------------------------------

    #[test]
    fn test_reports_navigation_enter_opens_edit_screen() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.screen = Screen::Reports { selected: 0 };

        let first_phase = sorted_phase_keys(&u)[0].clone();
        handle_key(key(KeyCode::Enter), &mut state, &mut u);

        assert_eq!(state.screen, Screen::ReportsEdit { phase: first_phase, selected: 0 });
    }

    #[test]
    fn test_reports_navigation_esc_returns_to_main() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.screen = Screen::Reports { selected: 0 };
        handle_key(key(KeyCode::Esc), &mut state, &mut u);
        assert_eq!(state.screen, Screen::Main);
    }

    #[test]
    fn test_reports_edit_esc_returns_to_reports_list() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        let phase = sorted_phase_keys(&u)[0].clone();
        state.screen = Screen::ReportsEdit { phase, selected: 1 };
        handle_key(key(KeyCode::Esc), &mut state, &mut u);
        assert_eq!(state.screen, Screen::Reports { selected: 0 });
    }

    #[test]
    fn test_reports_edit_enter_opens_text_popup_with_prefilled_buffer() {
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        let phase = sorted_phase_keys(&u)[0].clone();
        let expected = get_report_value(&u, &phase, 0);
        state.screen = Screen::ReportsEdit { phase: phase.clone(), selected: 0 };

        handle_key(key(KeyCode::Enter), &mut state, &mut u);

        match state.edit {
            EditMode::Text { target: EditTarget::Report { phase: p, field_idx: 0 }, buffer, .. } => {
                assert_eq!(p, phase);
                assert_eq!(buffer, expected);
            }
            _ => panic!("Oczekiwano EditMode::Text dla pola raportu"),
        }
    }

    // ------------------------------------------------------------------
    // REGRESJA: miejsce zapisu konfiguracji
    //
    // Testy niżej wołają `handle_key_do_pliku` WPROST, z własnym plikiem
    // tymczasowym, i odczytują go z powrotem — dowodzą, że zapis trafia tam,
    // gdzie wskazano, a nie pod zaszyty w kodzie literał "ustawienia.json".
    // Pokryte są WSZYSTKIE cztery ścieżki zapisu w tym module.
    // ------------------------------------------------------------------

    /// Odczytuje konfigurację zapisaną przez obsługę klawiszy.
    fn odczytaj(plik: &NamedTempFile) -> Ustawienia {
        let tresc = std::fs::read_to_string(plik.path()).expect("plik konfiguracji powinien zostać zapisany");
        serde_json::from_str(&tresc).expect("zapisana konfiguracja powinna być poprawnym JSON-em")
    }

    #[test]
    fn test_domyslna_sciezka_pozostaje_niezmieniona_dla_produkcji() {
        // Produkcja musi zachować dotychczasowe zachowanie - poprawka dotyczy
        // wyłącznie możliwości wstrzyknięcia innej ścieżki.
        assert_eq!(DOMYSLNA_SCIEZKA_USTAWIEN, "ustawienia.json");
    }

    #[test]
    fn test_zapis_edycji_tekstu_trafia_do_wskazanego_pliku() {
        let plik = NamedTempFile::new().unwrap();
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "/praca/inny_cel".to_string(), cursor: 15, error: None };

        handle_key_do_pliku(key(KeyCode::Enter), &mut state, &mut u, plik.path().to_str().unwrap());

        assert_eq!(u.target_path, "/praca/inny_cel", "Wartość w pamięci");
        assert_eq!(odczytaj(&plik).target_path, "/praca/inny_cel", "Wartość w pliku docelowym");
    }

    #[test]
    fn test_zapis_przelacznika_trafia_do_wskazanego_pliku() {
        let plik = NamedTempFile::new().unwrap();
        let mut u = Ustawienia::default();
        let przed = u.phase13_fast_mode;
        let mut state = SettingsUiState::new();
        state.selected_main = 9; // phase13_fast_mode (FieldKind::Toggle)

        handle_key_do_pliku(key(KeyCode::Enter), &mut state, &mut u, plik.path().to_str().unwrap());

        assert_eq!(u.phase13_fast_mode, !przed, "Przełącznik powinien zmienić stan");
        assert_eq!(odczytaj(&plik).phase13_fast_mode, !przed, "Nowy stan musi być w pliku");
    }

    #[test]
    fn test_zapis_wyboru_z_listy_trafia_do_wskazanego_pliku() {
        let plik = NamedTempFile::new().unwrap();
        let mut u = Ustawienia::default();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Choice { idx: 12, selected: 1 }; // io_mode

        handle_key_do_pliku(key(KeyCode::Enter), &mut state, &mut u, plik.path().to_str().unwrap());

        assert_eq!(odczytaj(&plik).io_mode, u.io_mode, "Wybrany tryb I/O musi być w pliku");
    }

    #[test]
    fn test_zapis_nowego_hasla_trafia_do_wskazanego_pliku() {
        let plik = NamedTempFile::new().unwrap();
        let mut u = Ustawienia::default();
        let hash_przed = u.admin_password_hash.clone();
        let mut state = SettingsUiState::new();
        state.edit = EditMode::Password {
            stage: PasswordStage::Confirm,
            old_buf: String::new(),
            new_buf: "nowe_haslo".to_string(),
            confirm_buf: "nowe_haslo".to_string(),
            error: None,
        };

        handle_key_do_pliku(key(KeyCode::Enter), &mut state, &mut u, plik.path().to_str().unwrap());

        assert_ne!(u.admin_password_hash, hash_przed, "Hash hasła powinien się zmienić");
        assert_eq!(odczytaj(&plik).admin_password_hash, u.admin_password_hash, "Nowy hash musi być w pliku");
    }

    /// Pilnuje, że pomocnik przesłaniający `handle_key` faktycznie kieruje
    /// zapis POZA katalog projektu — gdyby ktoś go kiedyś uprościł z powrotem
    /// do wywołania produkcyjnego, ten test nie wykryje tego wprost, ale
    /// przynajmniej dokumentuje kontrakt i sprawdza, że przejście przez
    /// pomocnika nie panikuje na żadnej z czterech ścieżek zapisu.
    #[test]
    fn test_pomocnik_testowy_obsluguje_wszystkie_sciezki_zapisu() {
        let mut u = Ustawienia::default();

        let mut state = SettingsUiState::new();
        state.edit = EditMode::Text { target: EditTarget::Main(2), buffer: "/praca/x".to_string(), cursor: 8, error: None };
        handle_key(key(KeyCode::Enter), &mut state, &mut u);

        let mut state = SettingsUiState::new();
        state.selected_main = 9;
        handle_key(key(KeyCode::Enter), &mut state, &mut u);

        let mut state = SettingsUiState::new();
        state.edit = EditMode::Choice { idx: 12, selected: 1 };
        handle_key(key(KeyCode::Enter), &mut state, &mut u);

        let mut state = SettingsUiState::new();
        state.edit = EditMode::Password {
            stage: PasswordStage::Confirm,
            old_buf: String::new(),
            new_buf: "h".to_string(),
            confirm_buf: "h".to_string(),
            error: None,
        };
        handle_key(key(KeyCode::Enter), &mut state, &mut u);

        assert_eq!(u.target_path, "/praca/x");
    }
}
