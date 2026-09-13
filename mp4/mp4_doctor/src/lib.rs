//! MP4 Doctor 2.0 - Core Library Crate
//!
//! Exposes domain modules, the centralized event bus, and shared state
//! for the MP4 Doctor CLI binary and integration test harness.

use std::sync::atomic::AtomicBool;
use lazy_static::lazy_static;

// --- DOMAIN MODULES ---
pub mod ai;
pub mod autopilot;
pub mod bezglowe;
pub mod crypto;
pub mod db;
pub mod dna;
// Silniki naprawy przyszły ze wspólnego crate'a `mp4_engines` — patrz
// `Cargo.toml`. Re-eksport zachowuje dotychczasowe ścieżki
// (`crate::engine_clone::repair` itd.), więc miejsca wywołań w `autopilot`,
// `scanner` i `test_native` zostają bez zmian.
pub use mp4_engines::{engine_clone, engine_native, engine_recontainer, validator};
pub mod god_mode;
pub mod logger;
pub mod sanitizer;
pub mod scanner;
pub mod training_ground;
pub mod workspace;

// --- ARCHITECTURE / EVENT BUS (Milestone 1) ---
pub mod event;

// --- TUI MIGRATION (Milestone 3 & 4) ---
pub mod tui;

// --- TEST / DIAGNOSTICS ---
//
// `test_m3_adversarial` mieszkał tu jako DRUGA, znak w znak identyczna kopia
// `tests/m3_adversarial_state_machine.rs` (598 linii, te same 15 testów pod
// tymi samymi nazwami — jedyną różnicą było `crate::` zamiast `mp4_doctor::`).
// Obie kopie się wykonywały, więc te 15 testów biegało dwa razy, a poprawka
// naniesiona w jednej z nich mogła ominąć drugą. Została wersja w `tests/`,
// bo to testy INTEGRACYJNE: sterują aplikacją wyłącznie przez publiczne API
// (`App`, `View`, `Modal`, `MAX_EVENTS_PER_TICK`), więc nic nie tracą na tym,
// że nie widzą wnętrza biblioteki.
// `test_native` usunięty: było to ręczne narzędzie diagnostyczne silnika
// Zero-Donor, którego nic nie wywoływało. Jego zadanie przejęły testy samego
// silnika w `mp4_engines::engine_native` (27 testów, w tym e2e na materiale
// z prawdziwego kodera). Przy okazji znika źródło śmieci: `run_diagnostic`
// zapisywał `debug_broken.mp4` i `debug_fixed.mp4` pod ścieżką WZGLĘDNĄ,
// czyli do katalogu uruchomienia.

// --- GLOBAL SHUTDOWN FLAG ---
lazy_static! {
    pub static ref SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);
}

// --- THREAD MANAGEMENT ---

/// Ścieżka pliku z limitem wątków — `threads.conf` w katalogu przestrzeni
/// roboczych.
///
/// # Dlaczego to nie jest już literał `"workspaces/threads.conf"`
///
/// Zaszyta ścieżka była WZGLĘDNA wobec katalogu uruchomienia i nie miała nic
/// wspólnego z [`workspace::katalog_przestrzeni`]. Skutki były dwa. W testach
/// `cargo test` ustawia katalog roboczy na katalog crate'a, więc każdy przebieg
/// odtwarzał `mp4/mp4_doctor/workspaces/` w drzewie projektu — nawet po
/// przekierowaniu samych przestrzeni. A przy osadzeniu biblioteki w
/// Weryfikatorze limit wątków lądował gdzie indziej niż wszystkie pozostałe
/// wytwory tej aplikacji.
///
/// Dla samodzielnego `mp4_doctor` wynik jest dokładnie taki jak wcześniej,
/// bo domyślny katalog przestrzeni to `workspaces`.
pub fn sciezka_konfiguracji_watkow() -> std::path::PathBuf {
    workspace::katalog_przestrzeni().join("threads.conf")
}

/// Reads configured CPU thread limit from `threads.conf` (0 = Auto)
pub fn get_thread_count() -> usize {
    let mut configured: usize = std::fs::read_to_string(sciezka_konfiguracji_watkow())
        .unwrap_or_default()
        .trim()
        .parse()
        .unwrap_or(0);

    let hardware_max = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

    // Auto (0) or blindly large numbers like 909 fall back to hardware reality
    if configured == 0 || configured > hardware_max * 2 {
        configured = hardware_max;
    }
    configured
}

/// Saves CPU thread limit to `threads.conf`
pub fn set_thread_count(count: usize) {
    let sciezka = sciezka_konfiguracji_watkow();
    if let Some(katalog) = sciezka.parent() {
        let _ = std::fs::create_dir_all(katalog);
    }
    let _ = std::fs::write(sciezka, count.to_string());
}
