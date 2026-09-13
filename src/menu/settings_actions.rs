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

/// Zapisuje nową wartość jednego z trzech pól raportu danej fazy.
pub fn set_report_value(u: &mut Ustawienia, phase: &str, field_idx: usize, val: String) {
    if let Some(r) = u.raporty_faz.get_mut(phase) {
        match field_idx {
            0 => r.katalog = val,
            1 => r.plik_operacyjny = val,
            2 => r.plik_dziennika = val,
            _ => {}
        }
    }
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
                EditTarget::Report { phase, field_idx } => {
                    set_report_value(u, phase, *field_idx, buffer.clone());
                    Ok(())
                }
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
        set_report_value(&mut u, &phase, 0, "nowy_katalog".to_string());
        assert_eq!(get_report_value(&u, &phase, 0), "nowy_katalog");
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
