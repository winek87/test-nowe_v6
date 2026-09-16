// src/tui/state.rs

//! # Stan Interfejsu Faz Roboczych (State)
//! 
//! Zawiera struktury przechowujące dane napływające asynchronicznie z wątków
//! skanujących (paski postępu, logi, ścieżki, telemetria).
//! Reprezentuje architekturę MVU (Model) dla dynamicznych komponentów.

use ratatui::style::Color;

// ============================================================================
// SYSTEM KOMUNIKACJI ASYNCHRONICZNEJ (EVENTY Z WĄTKÓW ROBOCZYCH)
// ============================================================================

/// Typy komunikatów wysyłanych przez Fazy operujące w tle do głównego wątku UI.
/// Pozwala to na całkowite odseparowanie ciężkich obliczeń I/O od rysowania ekranu.
pub enum PhaseEvent {
    /// Tworzy lub resetuje pasek postępu (np. indeks 0 dla UFS, indeks 1 dla Skryptu).
    SetBar { idx: usize, label: String, total: u64, color: Color },
    
    /// Aktualizuje wartość liczbową i komunikat na istniejącym pasku postępu.
    UpdateBar { idx: usize, current: u64, message: String },
    
    /// Dodaje nową linijkę do okna Logów Operacyjnych (Auto-Scroll).
    Log(String),
    
    /// Aktualizuje wielolinijkowe statystyki w lewym panelu pod Konfiguracją (Aktywny Skaner).
    UpdateSideText { idx: usize, text: String },

    /// Aktualizuje długą ścieżkę I/O w panelu na samym dole ekranu.
    UpdateBottomPath { idx: usize, path: String },

    /// Sygnał zakończenia pracy przez Fazę (zatrzymuje nasłuchiwanie i pozwala wyjść do Menu).
    Done,
}

// ============================================================================
// WSPÓŁDZIELONY STAN DLA INTERFEJSU FAZ (Architektura MVU)
// ============================================================================

/// Reprezentuje stan pojedynczego paska postępu na ekranie.
pub struct ProgressBarState {
    pub label: String,
    pub current: u64,
    pub total: u64,
    pub message: String,
    pub color: Color,
}

/// Główna struktura reprezentująca stan graficzny trwającej Fazy roboczej.
/// Przechowuje wszystkie dane napływające asynchronicznie z wątków skanujących.
pub struct PhaseUIState {
    // --- Informacje nagłówkowe (góra prawego ekranu) ---
    pub icon: String,
    pub title: String,
    pub category: String,
    pub description: String,
    
    /// Paski postępu (Wsparcie dla wielu równoległych pasków naraz)
    pub progress_bars: Vec<ProgressBarState>,
    
    /// Logi terminalowe przewijające się w prawym oknie
    pub logs: Vec<String>,
    pub max_logs: usize,

    /// Ręczne przewijanie panelu logów (PageUp/PageDown/End). `None` = tryb
    /// domyślny, śledzenie najnowszych wpisów (jak dotąd - zawsze pokazuje
    /// ogon). `Some(n)` = operator ręcznie cofnął widok o `n` (zawiniętych,
    /// czyli już po zawinięciu długich linii — patrz `logs_panel::draw_logs`)
    /// linii od dołu. Celowo liczone OD DOŁU, nie jako bezwzględny indeks
    /// początku: `logs` to bufor FIFO ograniczony do `max_logs` wpisów
    /// (`process_event` usuwa najstarsze przy przepełnieniu) — bezwzględny
    /// indeks zapamiętany podczas przewijania cicho rozjechałby się z
    /// rzeczywistą treścią, gdy w międzyczasie coś wypadnie z początku
    /// bufora. Przy tym podejściu nowy log NIE psuje przewijania (patrz
    /// `scroll_logs_up`/`_down`) - widok po prostu przesuwa się razem z nowym
    /// wpisem, zachowując tę samą odległość od aktualnego dołu.
    pub log_scroll: Option<usize>,

    /// Teksty w lewym panelu "Aktywny Skaner (Live)" (Indeks 0 = UFS, 1 = Skrypt)
    pub side_texts: Vec<String>,

    /// Ścieżki wyświetlane w szerokim dolnym panelu (Indeks 0 = UFS, 1 = Skrypt)
    pub bottom_paths: Vec<String>,
}

impl PhaseUIState {
    /// Inicjalizuje nowy, pusty stan dla wywołanej Fazy.
    pub fn new(icon: &str, title: &str, category: &str, description: &str) -> Self {
        Self {
            icon: icon.to_string(),
            title: title.to_string(),
            category: category.to_string(),
            description: description.to_string(),
            progress_bars: Vec::new(),
            logs: Vec::new(),
            max_logs: 250, // Ograniczenie do 250 linii chroni pamięć RAM przed wyciekiem
            log_scroll: None,
            side_texts: Vec::new(),
            bottom_paths: Vec::new(),
        }
    }

    /// Przewija panel logów o `n` (zawiniętych) linii W GÓRĘ, wstecz do
    /// starszych wpisów. Wchodzi w tryb ręcznego przewijania, jeśli jeszcze w
    /// nim nie byliśmy — dopóki operator nie wróci na sam dół
    /// ([`scroll_logs_down`]) albo nie naciśnie End
    /// ([`jump_to_latest_log`]), nowe logi nie przesuwają już widoku same z
    /// siebie tak agresywnie jak w trybie domyślnym.
    ///
    /// Górny limit (`self.logs.len()`) to tylko bezpiecznik przeciw
    /// nieograniczonemu wzrostowi przy przytrzymanym PageUp — rzeczywiste
    /// dociśnięcie do najstarszego wpisu widocznego na ekranie liczy render
    /// (`logs_panel::draw_logs`, zna faktyczną wysokość panelu).
    pub fn scroll_logs_up(&mut self, n: usize) {
        let obecny = self.log_scroll.unwrap_or(0);
        self.log_scroll = Some((obecny + n).min(self.logs.len()));
    }

    /// Przewija panel logów o `n` linii W DÓŁ, do przodu, do nowszych wpisów.
    /// Po dojechaniu do samego dołu WYŁĄCZA ręczne przewijanie (powrót do
    /// `None`) — dokładnie tak, jakby operator nacisnął End.
    pub fn scroll_logs_down(&mut self, n: usize) {
        if let Some(obecny) = self.log_scroll {
            let nowy = obecny.saturating_sub(n);
            self.log_scroll = if nowy == 0 { None } else { Some(nowy) };
        }
    }

    /// Natychmiastowy powrót do najnowszych wpisów (klawisz End) — bez
    /// względu na to, jak daleko operator odjechał w górę.
    pub fn jump_to_latest_log(&mut self) {
        self.log_scroll = None;
    }

    /// Odbiera eventy z kanału MPSC i odpowiednio mutuje stan widoku.
    pub fn process_event(&mut self, event: PhaseEvent) {
        match event {
            PhaseEvent::SetBar { idx, label, total, color } => {
                // Automatycznie powiększa wektor pasków, jeśli użyjemy wyższego indeksu (np. 0, 1)
                if idx >= self.progress_bars.len() {
                    self.progress_bars.resize_with(idx + 1, || ProgressBarState {
                        label: String::new(), current: 0, total: 0, message: String::new(), color: Color::White
                    });
                }
                self.progress_bars[idx] = ProgressBarState { label, current: 0, total, message: String::new(), color };
            }
            PhaseEvent::UpdateBar { idx, current, message } => {
                if let Some(bar) = self.progress_bars.get_mut(idx) {
                    bar.current = current;
                    bar.message = message;
                }
            }
            PhaseEvent::Log(msg) => {
                // Mechanizm FIFO: Usuwa najstarszy log, by zrobić miejsce na nowy (Auto-Scroll)
                if self.logs.len() >= self.max_logs {
                    self.logs.remove(0); 
                }
                self.logs.push(msg);
            }
            PhaseEvent::UpdateSideText { idx, text } => {
                // Aktualizacja w miejscu dla lewego panelu statystyk (Live)
                if idx >= self.side_texts.len() { self.side_texts.resize(idx + 1, String::new()); }
                self.side_texts[idx] = text;
            }
            PhaseEvent::UpdateBottomPath { idx, path } => {
                // Aktualizacja dolnego paska z szybko zmieniającymi się ścieżkami
                if idx >= self.bottom_paths.len() { self.bottom_paths.resize(idx + 1, String::new()); }
                self.bottom_paths[idx] = path;
            }
            PhaseEvent::Done => {}
        }
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn stan() -> PhaseUIState {
        PhaseUIState::new("🔍", "Faza testowa", "Diagnostyka", "Opis fazy")
    }

    // ------------------------------------------------------------------
    // STAN POCZĄTKOWY
    // ------------------------------------------------------------------

    #[test]
    fn test_nowy_stan_jest_pusty_ale_opisany() {
        let s = stan();
        assert_eq!(s.icon, "🔍");
        assert_eq!(s.title, "Faza testowa");
        assert!(s.progress_bars.is_empty());
        assert!(s.logs.is_empty());
        assert!(s.side_texts.is_empty());
        assert!(s.bottom_paths.is_empty());
    }

    /// Limit logów chroni RAM przy fazach przetwarzających miliony plików —
    /// zero oznaczałoby albo brak logów, albo dzielenie przez zero w renderze.
    #[test]
    fn test_limit_logow_jest_niezerowy() {
        assert!(stan().max_logs > 0);
    }

    // ------------------------------------------------------------------
    // PASKI POSTĘPU
    // ------------------------------------------------------------------

    #[test]
    fn test_set_bar_tworzy_pasek_pod_wskazanym_indeksem() {
        let mut s = stan();
        s.process_event(PhaseEvent::SetBar { idx: 0, label: "UFS".into(), total: 100, color: Color::Green });

        assert_eq!(s.progress_bars.len(), 1);
        assert_eq!(s.progress_bars[0].label, "UFS");
        assert_eq!(s.progress_bars[0].total, 100);
        assert_eq!(s.progress_bars[0].current, 0, "Nowy pasek startuje od zera");
    }

    /// Fazy zakładają paski „w przód" (najpierw indeks 1, potem 0), więc wektor
    /// musi rosnąć sam, bez wcześniejszej rezerwacji.
    #[test]
    fn test_set_bar_powieksza_wektor_przy_wyzszym_indeksie() {
        let mut s = stan();
        s.process_event(PhaseEvent::SetBar { idx: 3, label: "czwarty".into(), total: 10, color: Color::Blue });

        assert_eq!(s.progress_bars.len(), 4, "Wektor musi urosnąć do wskazanego indeksu");
        assert_eq!(s.progress_bars[3].label, "czwarty");
        assert_eq!(s.progress_bars[0].label, "", "Wypełniacze zostają puste");
    }

    #[test]
    fn test_set_bar_na_istniejacym_indeksie_resetuje_postep() {
        let mut s = stan();
        s.process_event(PhaseEvent::SetBar { idx: 0, label: "A".into(), total: 100, color: Color::Green });
        s.process_event(PhaseEvent::UpdateBar { idx: 0, current: 50, message: "w toku".into() });
        s.process_event(PhaseEvent::SetBar { idx: 0, label: "B".into(), total: 200, color: Color::Red });

        assert_eq!(s.progress_bars[0].label, "B");
        assert_eq!(s.progress_bars[0].current, 0, "Ponowne założenie paska musi wyzerować licznik");
        assert_eq!(s.progress_bars[0].message, "", "…i wyczyścić komunikat");
    }

    #[test]
    fn test_update_bar_aktualizuje_licznik_i_komunikat() {
        let mut s = stan();
        s.process_event(PhaseEvent::SetBar { idx: 0, label: "UFS".into(), total: 100, color: Color::Green });
        s.process_event(PhaseEvent::UpdateBar { idx: 0, current: 42, message: "plik.txt".into() });

        assert_eq!(s.progress_bars[0].current, 42);
        assert_eq!(s.progress_bars[0].message, "plik.txt");
        assert_eq!(s.progress_bars[0].total, 100, "Aktualizacja nie rusza całości");
    }

    /// Zdarzenie dla nieistniejącego paska to realny wyścig: wątek roboczy
    /// może wysłać `UpdateBar` zanim UI przetworzy `SetBar`. Musi być
    /// pominięte, a nie wywrócić interfejs.
    #[test]
    fn test_update_bar_na_nieistniejacym_indeksie_jest_pomijany() {
        let mut s = stan();
        s.process_event(PhaseEvent::UpdateBar { idx: 7, current: 1, message: "x".into() });
        assert!(s.progress_bars.is_empty(), "Nie wolno tworzyć paska z samej aktualizacji");
    }

    // ------------------------------------------------------------------
    // LOGI (FIFO)
    // ------------------------------------------------------------------

    #[test]
    fn test_logi_dopisuja_sie_w_kolejnosci() {
        let mut s = stan();
        for i in 0..3 {
            s.process_event(PhaseEvent::Log(format!("linia {}", i)));
        }
        assert_eq!(s.logs, vec!["linia 0", "linia 1", "linia 2"]);
    }

    /// Sedno ochrony pamięci: po przekroczeniu limitu najstarsze linie
    /// wypadają, a długość przestaje rosnąć.
    #[test]
    fn test_logi_nie_przekraczaja_limitu_i_gubia_najstarsze() {
        let mut s = stan();
        let limit = s.max_logs;

        for i in 0..(limit + 50) {
            s.process_event(PhaseEvent::Log(format!("linia {}", i)));
        }

        assert_eq!(s.logs.len(), limit, "Długość musi zatrzymać się na limicie");
        assert_eq!(s.logs.last().unwrap(), &format!("linia {}", limit + 49), "Najnowsza linia zostaje");
        assert!(
            !s.logs.iter().any(|l| l == "linia 0"),
            "Najstarsze linie muszą wypaść"
        );
    }

    // ------------------------------------------------------------------
    // PANELE BOCZNY I DOLNY
    // ------------------------------------------------------------------

    #[test]
    fn test_tekst_boczny_rosnie_i_nadpisuje_w_miejscu() {
        let mut s = stan();
        s.process_event(PhaseEvent::UpdateSideText { idx: 1, text: "drugi".into() });
        assert_eq!(s.side_texts.len(), 2);
        assert_eq!(s.side_texts[1], "drugi");

        s.process_event(PhaseEvent::UpdateSideText { idx: 1, text: "nadpisany".into() });
        assert_eq!(s.side_texts.len(), 2, "Nadpisanie nie może wydłużać wektora");
        assert_eq!(s.side_texts[1], "nadpisany");
    }

    #[test]
    fn test_sciezka_dolna_rosnie_i_nadpisuje_w_miejscu() {
        let mut s = stan();
        s.process_event(PhaseEvent::UpdateBottomPath { idx: 0, path: "/a".into() });
        s.process_event(PhaseEvent::UpdateBottomPath { idx: 0, path: "/b".into() });

        assert_eq!(s.bottom_paths, vec!["/b"]);
    }

    #[test]
    fn test_done_nie_zmienia_stanu() {
        let mut s = stan();
        s.process_event(PhaseEvent::Log("cokolwiek".into()));
        let logow_przed = s.logs.len();

        s.process_event(PhaseEvent::Done);

        assert_eq!(s.logs.len(), logow_przed, "Done to wyłącznie sygnał zakończenia");
    }

    // ------------------------------------------------------------------
    // PRZEWIJANIE PANELU LOGÓW (PageUp/PageDown/End)
    // ------------------------------------------------------------------

    fn stan_z_n_logami(n: usize) -> PhaseUIState {
        let mut s = stan();
        for i in 0..n {
            s.process_event(PhaseEvent::Log(format!("wpis {}", i)));
        }
        s
    }

    #[test]
    fn test_nowy_stan_ma_wylaczone_reczne_przewijanie() {
        assert_eq!(stan().log_scroll, None);
    }

    #[test]
    fn test_scroll_logs_up_wlacza_reczne_przewijanie() {
        let mut s = stan_z_n_logami(50);
        s.scroll_logs_up(5);
        assert_eq!(s.log_scroll, Some(5));
    }

    #[test]
    fn test_scroll_logs_up_kumuluje_sie_przy_kolejnych_wywolaniach() {
        let mut s = stan_z_n_logami(50);
        s.scroll_logs_up(5);
        s.scroll_logs_up(3);
        assert_eq!(s.log_scroll, Some(8));
    }

    #[test]
    fn test_scroll_logs_up_nie_przekracza_liczby_wpisow() {
        let mut s = stan_z_n_logami(10);
        s.scroll_logs_up(1000);
        assert_eq!(s.log_scroll, Some(10), "przewinięcie dalej niż jest historii musi się zatrzymać na jej długości");
    }

    #[test]
    fn test_scroll_logs_down_zmniejsza_cofniecie() {
        let mut s = stan_z_n_logami(50);
        s.scroll_logs_up(8);
        s.scroll_logs_down(3);
        assert_eq!(s.log_scroll, Some(5));
    }

    #[test]
    fn test_scroll_logs_down_do_zera_wylacza_reczne_przewijanie() {
        let mut s = stan_z_n_logami(50);
        s.scroll_logs_up(5);
        s.scroll_logs_down(5);
        assert_eq!(s.log_scroll, None, "dojechanie do samego dołu musi wrócić do trybu Auto-Scroll");
    }

    #[test]
    fn test_scroll_logs_down_za_daleko_zatrzymuje_sie_na_dole_nie_panikuje() {
        let mut s = stan_z_n_logami(50);
        s.scroll_logs_up(3);
        s.scroll_logs_down(1000);
        assert_eq!(s.log_scroll, None);
    }

    #[test]
    fn test_scroll_logs_down_bez_wczesniejszego_przewiniecia_nic_nie_robi() {
        let mut s = stan_z_n_logami(50);
        s.scroll_logs_down(5);
        assert_eq!(s.log_scroll, None, "nie ma jak przewinąć w dół, skoro już jesteśmy na dole");
    }

    #[test]
    fn test_jump_to_latest_log_resetuje_z_dowolnego_cofniecia() {
        let mut s = stan_z_n_logami(50);
        s.scroll_logs_up(30);
        s.jump_to_latest_log();
        assert_eq!(s.log_scroll, None);
    }

    /// Regresja: nowy log NIE MOŻE po cichu zresetować ręcznego przewijania —
    /// operator czytający historię musi zostać na miejscu, dopóki sam nie
    /// wróci (patrz dokumentacja `log_scroll`).
    #[test]
    fn test_nowy_log_nie_resetuje_recznego_przewijania() {
        let mut s = stan_z_n_logami(50);
        s.scroll_logs_up(10);
        s.process_event(PhaseEvent::Log("swiezy wpis".into()));
        assert_eq!(s.log_scroll, Some(10), "napływający log nie może przerwać przewijania w toku");
    }
}
