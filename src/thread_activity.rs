// src/thread_activity.rs

//! # Śledzenie Zajętości Logicznych Slotów Puli Rayon (Wariant A)
//!
//! **STATUS: MODUŁ EKSPERYMENTALNY, JESZCZE NIEWPIĘTY W ŻADNĄ FAZĘ.**
//! Zbudowany i przetestowany samodzielnie, na żądanie, jako krok pośredni
//! przed ewentualną integracją z panelem live którejś z faz.
//!
//! ## Kluczowe zastrzeżenie (przeczytaj przed użyciem)
//!
//! Ten moduł śledzi zajętość **logicznych slotów w puli wątków Rayon**
//! (`rayon::current_thread_index()`), **NIE fizycznych rdzeni CPU**. System
//! operacyjny swobodnie migruje wątki między rdzeniami — Rayon domyślnie nie
//! ustawia CPU affinity. "Slot #2 zajęty" oznacza "drugi wątek roboczy w puli
//! Rayon aktualnie coś liczy", nie "fizyczny rdzeń #2 jest obciążony". Numeracja
//! slotów to czysto umowna etykieta (indeks w puli), nie odpowiada żadnemu
//! identyfikatorowi z `/proc/cpuinfo` ani z `sysinfo`.
//!
//! Jeśli zamiast tego zależy Ci na PRAWDZIWYM zużyciu per-rdzeń widocznym
//! w `htop` — to jest Wariant B (`sysinfo::System::cpus()`), osobna sprawa,
//! nieobjęta tym modułem.
//!
//! ## Ograniczenie praktyczne
//!
//! Przy bardzo szybkim przetwarzaniu (mikrosekundy na jednostkę pracy) stan
//! może migać szybciej niż jakikolwiek rozsądny interwał odświeżania UI —
//! w skrajnym przypadku panel pokazywałby "wszystko zielone" niemal stale,
//! nawet gdy pojedyncze zadania są bardzo krótkie. To nie jest błąd tego
//! modułu, tylko naturalne ograniczenie tej metody obserwacji.

use std::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// ŚLEDZENIE STANU
// ============================================================================

/// Tablica flag zajętości, jedna na slot puli Rayon. Bezpieczna do
/// współdzielenia między wątkami (`Sync` automatycznie, dzięki `AtomicBool`).
pub struct ThreadActivityTracker {
    slots: Vec<AtomicBool>,
}

impl ThreadActivityTracker {
    /// Tworzy tracker o podanej liczbie slotów (typowo: `config.max_threads`,
    /// albo `rayon::current_num_threads()` gdy `max_threads == 0` / AUTO).
    /// Zawsze co najmniej jeden slot, nawet gdy poproszono o zero.
    pub fn new(slot_count: usize) -> Self {
        let count = slot_count.max(1);
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            slots.push(AtomicBool::new(false));
        }
        Self { slots }
    }

    /// Liczba śledzonych slotów. Część publicznego API modułu — obecnie
    /// wywoływana wyłącznie w testach (żadna zintegrowana faza jej nie
    /// potrzebuje, korzystają z [`snapshot`](Self::snapshot) zamiast tego),
    /// stąd `#[allow(dead_code)]` przy `cargo build` (który nie kompiluje
    /// `#[cfg(test)]`).
    #[allow(dead_code)]
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Oznacza slot o podanym indeksie jako zajęty. Indeks spoza zakresu jest
    /// po cichu ignorowany (nigdy nie panikuje) — przydatne, gdyby
    /// `rayon::current_thread_index()` kiedyś zwrócił coś spoza założonego
    /// zakresu (np. po dynamicznej zmianie rozmiaru globalnej puli).
    pub fn mark_busy(&self, idx: usize) {
        if let Some(slot) = self.slots.get(idx) {
            slot.store(true, Ordering::Relaxed);
        }
    }

    /// Oznacza slot o podanym indeksie jako wolny. Jak [`mark_busy`](Self::mark_busy),
    /// indeks spoza zakresu jest po cichu ignorowany.
    pub fn mark_idle(&self, idx: usize) {
        if let Some(slot) = self.slots.get(idx) {
            slot.store(false, Ordering::Relaxed);
        }
    }

    /// Odczytuje bieżący stan slotu. `false` też dla indeksu spoza zakresu
    /// (traktowane jak "nieistniejący slot = nie może być zajęty"). Część
    /// publicznego API — obecnie wywoływana wyłącznie w testach, patrz
    /// uzasadnienie przy [`slot_count`](Self::slot_count).
    #[allow(dead_code)]
    pub fn is_busy(&self, idx: usize) -> bool {
        self.slots.get(idx).map(|s| s.load(Ordering::Relaxed)).unwrap_or(false)
    }

    /// Migawka stanu wszystkich slotów naraz — do renderowania panelu.
    pub fn snapshot(&self) -> Vec<bool> {
        self.slots.iter().map(|s| s.load(Ordering::Relaxed)).collect()
    }

    /// Oznacza BIEŻĄCY slot Rayon (z wnętrza którego jest to wołane) jako
    /// zajęty, tworząc strażnika RAII, który automatycznie zwolni slot przy
    /// wyjściu z zakresu (`Drop`) — W TYM przy panice w trakcie pracy
    /// (odwijanie stosu i tak wykona `Drop`). To BEZPIECZNIEJSZY wariant niż
    /// [`track_current`](Self::track_current) dla kodu, który może
    /// panikować w środku. Gdy wołane spoza puli Rayon
    /// (`current_thread_index()` zwraca `None`), strażnik nic nie robi.
    pub fn enter_current(&self) -> BusyGuard<'_> {
        let idx = rayon::current_thread_index();
        if let Some(i) = idx {
            self.mark_busy(i);
        }
        BusyGuard { tracker: self, idx }
    }

    /// Wygodny wrapper na [`enter_current`](Self::enter_current) dla
    /// prostego przypadku "wykonaj `work`, oznaczając bieżący slot jako
    /// zajęty na czas jej trwania". Gdy wołane spoza puli Rayon, po prostu
    /// wykonuje `work` bez żadnego śledzenia.
    pub fn track_current<T>(&self, work: impl FnOnce() -> T) -> T {
        let _guard = self.enter_current();
        work()
    }
}

/// Strażnik RAII zwracany przez [`ThreadActivityTracker::enter_current`].
/// Zwalnia slot automatycznie przy `Drop` — w tym podczas odwijania stosu
/// po panice, więc slot nigdy nie zostaje "zablokowany" na zawsze przez
/// błąd w środku śledzonej pracy.
pub struct BusyGuard<'a> {
    tracker: &'a ThreadActivityTracker,
    idx: Option<usize>,
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        if let Some(idx) = self.idx {
            self.tracker.mark_idle(idx);
        }
    }
}

// ============================================================================
// FORMATOWANIE DO PANELU (GOTOWE POD scanner_panel::parse_colored_value)
// ============================================================================

/// Formatuje migawkę zajętości jako tekst ze znacznikami kolorów
/// `{G:...}`/`{R:...}` — DOKŁADNIE ten sam mechanizm inline, który już
/// obsługuje `tui::scanner_panel::parse_colored_value` (wprowadzony przy
/// kolorowaniu silnika RS/CLI w Fazie 12). Zielony = zajęty, czerwony =
/// wolny. Etykiety slotów liczone od 1 (czytelniejsze dla człowieka niż
/// indeksy od zera). Gotowe do wklejenia jako WARTOŚĆ linii
/// `Etykieta: Wartość` w dowolnym panelu bocznym — integracja z
/// konkretną fazą to już tylko jedna linijka w jej `build_source_block`.
pub fn format_activity_markup(snapshot: &[bool]) -> String {
    snapshot.iter().enumerate()
        .map(|(i, &busy)| {
            let label = i + 1;
            if busy { format!("{{G:{}}}", label) } else { format!("{{R:{}}}", label) }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Podstawowa mechanika (bez Rayon - czysty stan)
    // ------------------------------------------------------------------

    #[test]
    fn test_new_creates_correct_slot_count() {
        let t = ThreadActivityTracker::new(4);
        assert_eq!(t.slot_count(), 4);
    }

    #[test]
    fn test_new_with_zero_still_creates_one_slot() {
        let t = ThreadActivityTracker::new(0);
        assert_eq!(t.slot_count(), 1, "Zero slotów nie ma sensu - zawsze co najmniej jeden");
    }

    #[test]
    fn test_all_slots_start_idle() {
        let t = ThreadActivityTracker::new(4);
        for i in 0..4 {
            assert!(!t.is_busy(i), "Slot {} powinien startować jako wolny", i);
        }
    }

    #[test]
    fn test_mark_busy_and_idle_roundtrip() {
        let t = ThreadActivityTracker::new(4);
        t.mark_busy(2);
        assert!(t.is_busy(2));
        assert!(!t.is_busy(0), "Oznaczenie slotu 2 nie powinno wpłynąć na slot 0");

        t.mark_idle(2);
        assert!(!t.is_busy(2));
    }

    #[test]
    fn test_out_of_bounds_index_never_panics() {
        let t = ThreadActivityTracker::new(4);
        // Żadna z tych operacji nie powinna panikować, mimo indeksu spoza zakresu.
        t.mark_busy(999);
        t.mark_idle(999);
        assert!(!t.is_busy(999), "Indeks spoza zakresu traktowany jako 'nie może być zajęty'");
    }

    #[test]
    fn test_snapshot_reflects_current_state() {
        let t = ThreadActivityTracker::new(3);
        t.mark_busy(0);
        t.mark_busy(2);
        assert_eq!(t.snapshot(), vec![true, false, true]);
    }

    // ------------------------------------------------------------------
    // Integracja z prawdziwą pulą Rayon
    // ------------------------------------------------------------------

    #[test]
    fn test_track_current_outside_rayon_pool_still_runs_work() {
        // Wołane bezpośrednio z wątku testu (nie z wnętrza puli Rayon) -
        // current_thread_index() zwróci None, ale praca i tak musi się wykonać.
        let t = ThreadActivityTracker::new(4);
        let mut executed = false;
        t.track_current(|| { executed = true; });
        assert!(executed, "Praca powinna się wykonać nawet bez aktywnej puli Rayon");
    }

    #[test]
    fn test_track_current_marks_busy_during_work_and_idle_after() {
        let t = ThreadActivityTracker::new(4);
        rayon::scope(|s| {
            s.spawn(|_| {
                if let Some(idx) = rayon::current_thread_index() {
                    let observed_busy_during = std::cell::Cell::new(false);
                    t.track_current(|| {
                        observed_busy_during.set(t.is_busy(idx));
                    });
                    assert!(observed_busy_during.get(), "Slot powinien być zajęty W TRAKCIE wykonywania pracy");
                    assert!(!t.is_busy(idx), "Slot powinien wrócić do wolnego PO zakończeniu pracy");
                }
                // Jeśli current_thread_index() zwróci None nawet tutaj (nietypowe,
                // ale teoretycznie możliwe w zależności od konfiguracji Rayon),
                // test i tak przechodzi - nie ma czego sprawdzić bez indeksu.
            });
        });
    }

    #[test]
    fn test_enter_current_guard_marks_idle_on_drop() {
        let t = ThreadActivityTracker::new(4);
        rayon::scope(|s| {
            s.spawn(|_| {
                if let Some(idx) = rayon::current_thread_index() {
                    {
                        let _guard = t.enter_current();
                        assert!(t.is_busy(idx), "Slot powinien być zajęty, gdy strażnik jest żywy");
                    }
                    assert!(!t.is_busy(idx), "Slot powinien być wolny zaraz po Drop strażnika");
                }
            });
        });
    }

    #[test]
    fn test_enter_current_guard_releases_slot_even_on_panic() {
        let t = ThreadActivityTracker::new(4);
        rayon::scope(|s| {
            s.spawn(|_| {
                if let Some(idx) = rayon::current_thread_index() {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _guard = t.enter_current();
                        panic!("symulowany błąd w trakcie śledzonej pracy");
                    }));
                    assert!(result.is_err(), "Panika powinna faktycznie nastąpić (test sprawdza odzysk po niej)");
                    assert!(!t.is_busy(idx), "Strażnik powinien zwolnić slot mimo paniki (Drop działa podczas odwijania stosu)");
                }
            });
        });
    }

    // ------------------------------------------------------------------
    // format_activity_markup
    // ------------------------------------------------------------------

    #[test]
    fn test_format_activity_markup_all_idle() {
        assert_eq!(format_activity_markup(&[false, false, false]), "{R:1} {R:2} {R:3}");
    }

    #[test]
    fn test_format_activity_markup_all_busy() {
        assert_eq!(format_activity_markup(&[true, true]), "{G:1} {G:2}");
    }

    #[test]
    fn test_format_activity_markup_mixed_state() {
        assert_eq!(format_activity_markup(&[true, false, true, false]), "{G:1} {R:2} {G:3} {R:4}");
    }

    #[test]
    fn test_format_activity_markup_empty_snapshot() {
        assert_eq!(format_activity_markup(&[]), "");
    }

    #[test]
    fn test_format_activity_markup_labels_start_at_one_not_zero() {
        let out = format_activity_markup(&[true]);
        assert_eq!(out, "{G:1}", "Etykiety dla człowieka powinny liczyć się od 1, nie od 0");
    }


    // ------------------------------------------------------------------
    // SPÓJNOŚĆ KONWENCJI W CAŁYM PROGRAMIE
    // ------------------------------------------------------------------

    /// Każda faza RÓWNOLEGŁA musi raportować zajętość wątków w konwencji
    /// „Wątki <co> (Wariant A)".
    ///
    /// Test czyta źródła, bo tylko tak da się wykryć fazę dodaną BEZ tego
    /// mechanizmu — sam tracker nie wie, kto go nie użył. Kryterium
    /// „równoległa" to obecność konstrukcji Rayona; faza sekwencyjna nie ma
    /// czego pokazywać i jest z tego wymagania wyłączona.
    ///
    /// Powód istnienia: pięć faz (2, 9, 12, 17, 18) było równoległych, a mimo
    /// to nie pokazywało ani jednego wątku. Panel sugerował więc pracę
    /// jednowątkową tam, gdzie w rzeczywistości pracowała cała pula.
    #[test]
    fn test_wszystkie_fazy_rownolegle_raportuja_watki() {
        let katalog = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/phases");

        let mut brakujace: Vec<String> = Vec::new();
        let mut sprawdzone = 0usize;

        for wpis in std::fs::read_dir(&katalog).expect("katalog faz musi istnieć") {
            let sciezka = wpis.expect("wpis katalogu").path();
            let nazwa = sciezka.file_name().unwrap().to_string_lossy().to_string();

            if !nazwa.starts_with("phase") || !nazwa.ends_with(".rs") {
                continue;
            }

            let tresc = std::fs::read_to_string(&sciezka).expect("odczyt pliku fazy");

            let rownolegla = ["par_iter", "par_chunks", "par_bridge"]
                .iter()
                .any(|w| tresc.contains(w));
            if !rownolegla {
                continue;
            }

            sprawdzone += 1;

            // Szukamy wzorca z FORMATOWANIA, nie samego napisu „(Wariant A)".
            // Ten drugi występuje też w komentarzach przy polu struktury, więc
            // faza opisana, ale nieraportująca, przechodziłaby test -
            // sprawdzone mutacją, która dokładnie tak psuła phase18.
            if !tresc.contains("(Wariant A): {}") {
                brakujace.push(nazwa);
            }
        }

        assert!(sprawdzone >= 10, "test musi obejmować realną liczbę faz, objął {}", sprawdzone);
        assert!(
            brakujace.is_empty(),
            "fazy równoległe bez raportowania wątków w konwencji „(Wariant A)”: {:?}",
            brakujace
        );
    }
}
