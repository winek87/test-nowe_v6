// src/phases/repair_modules/mp4_autopilot.rs

//! Ostatnia szansa dla MP4: kiedy Clone/Native/Recontainer (patrz
//! [`super::mp4`]) już zawiodły, ten moduł oddaje plik autopilotowi
//! `mp4_doctor` — jego kaskadzie uczącej się (KNN na cechach + baza wiedzy
//! SQLite) i, gdy trzeba, wyszukiwaniu dawcy w lokalnej puli LUB w Roju
//! (sieć — zapytanie do `mp4_swarm_server`).
//!
//! ## Dlaczego osobny moduł, a nie scalenie z `mp4.rs`
//!
//! Trzy moduły `mp4.rs` próbują w ustalonej z góry kolejności WIERNOŚCI
//! (clone → native → recontainer) — CELOWO, niezależnie od statystyk
//! sukcesu; to kolejność forensycznej wierności, nie skuteczności (patrz
//! nagłówek `mp4.rs`, sekcja „Kolejność prób"). Autopilot robi coś innego:
//! uczy się, który algorytm statystycznie WYGRYWA dla danego DNA pliku, a
//! gdy WSZYSTKIE trzy ustalone strategie zawiodą, sięga po całą pulę dawców
//! zebraną przez `mp4_doctor` — lokalnie i, w ostateczności, przez sieć. To
//! DODATKOWA, czwarta warstwa uruchamiana wyłącznie wtedy, gdy reszta już
//! przegrała, nie ich zamiennik.
//!
//! ## Baza wiedzy jest WSPÓLNA z ręcznym menu „[25] MP4 DOCTOR"
//!
//! Katalog przestrzeni roboczych (`<target_path>/_mp4_doctor`) wskazuje ta
//! sama funkcja [`mp4_doctor::workspace::ustaw_katalog_przestrzeni`], którą
//! woła `menu::actions::run_mp4_doctor_with_ui` — pierwsze wywołanie
//! (manualne lub automatyczne, zależnie co uruchomi się wcześniej w danej
//! sesji) wygrywa (`OnceLock`), a oba wejścia i tak trafiają do tego samego
//! katalogu przestrzeni, więc dzielą globalną pulę dawców
//! (`autopilot::run`'s bruteforce przeszukuje WSZYSTKIE projekty pod tym
//! katalogiem). Automatyczne przebiegi Fazy 17 dostają jednak WŁASNY projekt
//! ([`PROJEKT_AUTOMATYCZNY`]), żeby ich statystyki KNN nie mieszały się z
//! ręcznie nazwanymi projektami operatora.
//!
//! ## Zdarzenia bez `println!`
//!
//! [`mp4_doctor::bezglowe::z_odbiorem`] — wzorzec trybu bezgłowego — pisze
//! surowo na `stdout`. W Fazie 17 `stdout` należy do aktywnego ekranu
//! ratatui: taki zapis połamałby rysowany interfejs. Ten moduł ma WŁASNY,
//! CICHY odbiornik zdarzeń ([`uruchom_cicho`]): zapisuje naukę
//! (`RepairSuccess`/`RepairFailure`/`DonorFound`) do tej samej bazy co
//! `bezglowe::obsluz_zdarzenie`, ale bez żadnego wypisywania na standardowe
//! wyjście.

use super::{RepairContext, RepairModule, WynikWeryfikacji};
use std::path::{Path, PathBuf};

use mp4_doctor::event::AppEvent;
use mp4_doctor::workspace::Workspace;

/// Nazwa projektu `mp4_doctor` dedykowana automatycznym przebiegom Fazy 17 —
/// odrębna od projektów zakładanych ręcznie w menu „[25] MP4 DOCTOR", choć
/// dzieląca ten sam katalog przestrzeni i tę samą globalną pulę dawców.
const PROJEKT_AUTOMATYCZNY: &str = "faza17_automatyczny";

/// Otwiera (lub zakłada) dedykowaną przestrzeń automatycznego przebiegu, pod
/// katalogiem już wskazanym przez [`mp4_doctor::workspace::ustaw_katalog_przestrzeni`]
/// (wołane raz, na wejściu do [`super::super::phase17_repair::run`]).
///
/// `output_dir` jest tu WSPÓLNY dla całego projektu — POPRAWNY dla
/// `db_path`/`donors_dir` (baza wiedzy i pula dawców MAJĄ być współdzielone
/// między plikami, o to w nich chodzi), ale NIEBEZPIECZNY jako miejsce
/// zapisu wyników: `autopilot::run` nazywa swój plik wynikowy wyłącznie po
/// nazwie pliku źródłowego (`{Algorytm}_{nazwa}.mp4`, bez katalogu), więc
/// dwa RÓŻNE pliki dowodowe o tej samej nazwie (typowe: `IMG_0001.mp4` w
/// dwóch różnych folderach korpusu) przetwarzane równolegle przez Rayon
/// pisałyby pod TĘ SAMĄ ścieżkę. [`przestrzen_dla_pliku`] naprawia to,
/// nadpisując `output_dir` unikalnym podkatalogiem per plik źródłowy —
/// użyj TEJ funkcji do zapisu wyników, nie tej.
fn przestrzen_automatyczna() -> std::io::Result<Workspace> {
    Workspace::init(PROJEKT_AUTOMATYCZNY)
}

/// Jak [`przestrzen_automatyczna`], ale z `output_dir` przekierowanym do
/// unikalnego podkatalogu skrótu PEŁNEJ ścieżki `source` — patrz dokumentacja
/// [`przestrzen_automatyczna`] dla uzasadnienia. `db_path`/`donors_dir`
/// zostają WSPÓLNE (dzielona nauka i pula dawców), zmienia się wyłącznie
/// miejsce zapisu wyniku.
fn przestrzen_dla_pliku(source: &Path) -> std::io::Result<Workspace> {
    let baza = przestrzen_automatyczna()?;
    let output_dir = baza.output_dir.join(unikalny_podkatalog(source));
    std::fs::create_dir_all(&output_dir)?;

    Ok(Workspace { output_dir, ..baza })
}

/// Skrót PEŁNEJ ścieżki `source` jako nazwa podkatalogu — wydzielone z
/// [`przestrzen_dla_pliku`] jako czysta funkcja (bez I/O, bez stanu
/// globalnego), żeby dało się ją przetestować bez dotykania
/// `OnceLock`a `mp4_doctor::workspace` (patrz testy `utils.rs`/
/// `phase17_repair.rs` na ten sam temat).
fn unikalny_podkatalog(source: &Path) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    source.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Cichy odbiornik zdarzeń autopilota: zapisuje naukę do bazy identycznie
/// jak [`mp4_doctor::bezglowe`], ale bez `println!` — patrz dokumentacja
/// modułu.
fn zapisz_nauke(ws: &Workspace, zdarzenie: AppEvent) {
    match zdarzenie {
        AppEvent::DonorFound { dna, moov_path } => {
            let _ = mp4_doctor::db::save_donor(ws, &dna, &moov_path);
        }
        AppEvent::RepairSuccess { dna, algorithm, features, .. } => {
            let _ = mp4_doctor::db::reward_algorithm(ws, &dna, &algorithm, &features);
        }
        AppEvent::RepairFailure { dna, algorithm, features, .. } => {
            let _ = mp4_doctor::db::penalize_algorithm(ws, &dna, &algorithm, &features);
        }
        _ => {}
    }
}

/// Uruchamia `autopilot::run`, odbierając jego zdarzenia CICHO — wzorowane
/// na [`mp4_doctor::bezglowe::z_odbiorem`], ale bezpieczne do wołania z
/// wnętrza aktywnego ekranu ratatui (patrz dokumentacja modułu).
///
/// ## Dlaczego wątek odbiornika NIE jest joinowany
///
/// `bezglowe::z_odbiorem` joinuje po zamknięciu kanału (`drop(nadajnik)`),
/// zakładając że to jedyny nadajnik. Fałszywe założenie: `find_donor` przy
/// udanym pobraniu dawcy z Roju odpala WŁASNY, odłączony wątek czyszczący
/// (`std::thread::sleep(30s)` przed usunięciem tymczasowego pliku), który
/// trzyma WŁASNY klon `EventSender` przez pełne 30 sekund. Dopóki ten
/// odłączony wątek nie zaśnie i nie porzuci klonu, kanał się nie zamyka —
/// `join()` tutaj blokowałby wątek Rayon do 30s PO zakończeniu naprawy, za
/// każdym razem gdy trafi się dawca z chmury. Wątek odbiornika żyje więc
/// dalej w tle, niejoinowany — jego jedyna praca to zapis do SQLite, bez
/// żadnego stanu współdzielonego z resztą Fazy 17.
fn uruchom_cicho(ws: &Workspace, plik: &str, cache: &mp4_doctor::db::BrainCache) -> Result<(), String> {
    let (nadajnik, odbiornik) = mp4_doctor::event::channel();
    let ws_watku = ws.clone();

    std::thread::spawn(move || {
        while let Ok(zdarzenie) = odbiornik.recv() {
            zapisz_nauke(&ws_watku, zdarzenie);
        }
    });

    mp4_doctor::autopilot::run(ws, plik, cache, &nadajnik, 0)
}

/// `autopilot::run` zapisuje zwycięski plik pod `ws.output_dir` nazwany
/// `{Algorytm}_{nazwa_pliku_zrodlowego}.mp4` (kaskada) albo
/// `Frankenstein_{nazwa_pliku_zrodlowego}.mp4` (bruteforce) — funkcja nie
/// zwraca, który to plik, więc szukamy go po sufiksie nazwy.
///
/// BEZPIECZNE wyłącznie dlatego, że `ws` tutaj to zawsze wynik
/// [`przestrzen_dla_pliku`] — `output_dir` unikalny DLA TEGO source, więc w
/// katalogu mogą leżeć wyłącznie wyniki NALEŻĄCE do niego (różne algorytmy
/// tej samej naprawy, nigdy pliki innego pliku źródłowego). Dopasowanie po
/// samym sufiksie nazwy w katalogu WSPÓLNYM dla wielu plików (dawniej: cały
/// `output_dir` projektu) było błędem — dwa różne pliki dowodowe o tej samej
/// nazwie z różnych folderów korpusu (typowe w praktyce) mogłyby się
/// wzajemnie podmienić. Nie wołaj tej funkcji z `ws` pochodzącym z
/// [`przestrzen_automatyczna`] wprost.
fn znajdz_wynik(ws: &Workspace, nazwa_zrodlowa: &str) -> Option<PathBuf> {
    let sufiks = format!("_{}.mp4", nazwa_zrodlowa);
    std::fs::read_dir(&ws.output_dir).ok()?
        .flatten()
        .map(|w| w.path())
        .find(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(&sufiks)))
}

pub struct Mp4AutopilotModule;

impl RepairModule for Mp4AutopilotModule {
    fn id(&self) -> &'static str { "mp4_autopilot" }
    fn display_name(&self) -> &'static str { "MP4 Autopilot (kaskada ucząca się + Rój, ostatnia szansa)" }

    /// Ta sama przesłanka uszkodzenia co pozostałe trzy silniki MP4 — patrz
    /// [`super::mp4::jest_uszkodzonym_mp4`]. Orkiestrator Fazy 17 dociera tu
    /// tylko wtedy, gdy Clone, Native i Recontainer WSZYSTKIE zawiodły
    /// (kolejność w [`super::all_modules`]), więc nie potrzeba żadnego
    /// dodatkowego warunku „czy to już ostatnia szansa".
    fn applies_to(&self, ctx: &RepairContext) -> bool {
        super::mp4::jest_uszkodzonym_mp4(ctx)
    }

    /// Oddaje plik `autopilot::run`: DNA + cechy pliku decydują o kolejności
    /// prób (KNN na bazie wiedzy), a przy porażce kaskady — o pełnym
    /// bruteforce po globalnej puli dawców (lokalnie i przez sieć).
    ///
    /// `twin` jest tu celowo ignorowany: autopilot znajduje WŁASNEGO dawcę
    /// przez sygnaturę DNA (lokalną pulę i Rój), niezależnie od bliźniaka,
    /// jakiego znalazł orkiestrator Fazy 17 dla pozostałych modułów.
    fn repair(&self, source: &Path, _ctx: &RepairContext, _twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let zrodlo = source.to_str()?;
        let nazwa_zrodlowa = source.file_name()?.to_str()?;

        // `output_dir` unikalny dla TEGO source — patrz dokumentacja
        // `przestrzen_dla_pliku`: bez tego dwa różne pliki dowodowe o tej
        // samej nazwie (różne foldery korpusu) mogłyby dzielić jeden plik
        // wynikowy przy równoległym przetwarzaniu przez Rayon.
        let ws = przestrzen_dla_pliku(source).ok()?;
        let cache = mp4_doctor::db::build_brain_cache(&ws).ok()?;

        uruchom_cicho(&ws, zrodlo, &cache).ok()?;

        let wynik_autopilota = znajdz_wynik(&ws, nazwa_zrodlowa)?;
        let cel = super::mp4::sciezka_wyniku(source, katalog_wyjsciowy, "autopilot")?;

        // Autopilot pisze do WŁASNEGO katalogu wyjściowego (`ws.output_dir`),
        // nieznanego reszcie Fazy 17 — przenosimy zwycięski plik pod ścieżkę
        // wskazaną przez orkiestrator. `rename` najpierw: atomowe i tanie
        // (bez podwójnego zapisu materiału wideo) w obrębie tego samego
        // systemu plików, gdzie zwykle leżą oba katalogi (pod `target_path`).
        // `copy`+`remove` to zapasowa ścieżka dla `EXDEV` (różne punkty
        // montowania) — a gdy i ta zawiedzie, logujemy PRZED `None`, żeby
        // porzucony plik w `ws.output_dir` był widoczny w dzienniku, a nie
        // tylko cichym „naprawa się nie udała".
        if std::fs::rename(&wynik_autopilota, &cel).is_err() {
            if let Err(e) = std::fs::copy(&wynik_autopilota, &cel) {
                tracing::warn!(
                    plik = %source.display(), wynik_autopilota = %wynik_autopilota.display(), blad = %e,
                    "mp4_autopilot: nie udało się przenieść wyniku - zostaje osierocony w ws.output_dir"
                );
                return None;
            }
            let _ = std::fs::remove_file(&wynik_autopilota);
        }

        Some((cel, "Odzyskano kaskadą ucząca się mp4_doctor (KNN + pula dawców/Rój) po porażce Clone/Native/Recontainer.".to_string()))
    }

    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        super::mp4::weryfikuj_wideo(repaired)
    }
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phases::repair_modules::RepairContext;

    fn ctx<'a>(ext: &'a str, video_ok: Option<bool>) -> RepairContext<'a> {
        RepairContext {
            ext,
            media_reason: None,
            utf8_ok: None,
            is_oneliner: None,
            eof_ok: None,
            match_type: None,
            video_ok,
            structure_ok: None, media_decoded: None,
        }
    }

    #[test]
    fn test_stosuje_sie_do_tej_samej_przeslanki_co_pozostale_silniki_mp4() {
        assert!(Mp4AutopilotModule.applies_to(&ctx("mp4", Some(false))));
        assert!(!Mp4AutopilotModule.applies_to(&ctx("mp4", Some(true))), "zdrowego wideo nie rusza");
        assert!(!Mp4AutopilotModule.applies_to(&ctx("txt", Some(false))), "poza rozszerzeniami MP4 nie działa");
    }

    #[test]
    fn test_identyfikator_i_nazwa_sa_stabilne_i_opisowe() {
        assert_eq!(Mp4AutopilotModule.id(), "mp4_autopilot");
        assert!(Mp4AutopilotModule.display_name().to_lowercase().contains("autopilot"));
    }

    /// REGRESJA: dwa różne pliki dowodowe o TEJ SAMEJ nazwie z różnych
    /// folderów korpusu (typowy przypadek w dużym zbiorze odzyskanych
    /// plików) muszą dostać RÓŻNE podkatalogi wynikowe — inaczej
    /// `znajdz_wynik` mogłoby dopasować wynik naprawy JEDNEGO pliku
    /// dowodowego jako wynik dla DRUGIEGO. Wykryte w niezależnym code
    /// review (Gemini): pierwsza wersja liczyła cały `ws.output_dir` po
    /// samym sufiksie nazwy pliku, bez katalogu.
    #[test]
    fn test_unikalny_podkatalog_rozroznia_pliki_o_tej_samej_nazwie() {
        let a = Path::new("/korpus/folder1/IMG_0001.mp4");
        let b = Path::new("/korpus/folder2/IMG_0001.mp4");
        assert_ne!(unikalny_podkatalog(a), unikalny_podkatalog(b));

        // Stabilność: ten sam plik zawsze daje ten sam podkatalog (ważne przy
        // ponownym przebiegu Fazy 17 na tym samym korpusie).
        assert_eq!(unikalny_podkatalog(a), unikalny_podkatalog(a));
    }

    /// Plik bez żadnej wydobywalnej sygnatury DNA (pusty/nieistniejący) musi
    /// dać czytelną porażkę (`None`), nie panikę — `autopilot::run` sam to
    /// gwarantuje (patrz `mp4_doctor::autopilot::test_nieistniejacy_plik_daje_blad`),
    /// tu sprawdzamy, że opakowanie tego nie psuje.
    #[test]
    fn test_plik_bez_dna_daje_porazke_bez_paniki() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let nieistniejacy = dir.path().join("nie_ma_takiego.mp4");
        let kontekst = ctx("mp4", Some(false));

        assert!(
            Mp4AutopilotModule.repair(&nieistniejacy, &kontekst, None, &wynik).is_none(),
            "brak DNA (plik nieistniejący) musi dać None, nie panikę"
        );
    }

    #[test]
    fn test_znajdz_wynik_rozpoznaje_kazdy_prefiks_algorytmu() {
        let dir = tempfile::tempdir().unwrap();
        let ws = Workspace {
            name: "test".to_string(),
            root_dir: dir.path().to_path_buf(),
            broken_dir: dir.path().join("broken"),
            donors_dir: dir.path().join("donors"),
            output_dir: dir.path().to_path_buf(),
            db_path: dir.path().join("db.sqlite"),
        };

        std::fs::write(dir.path().join("Recontainer_material.mov.mp4"), b"dane").unwrap();

        let znaleziony = znajdz_wynik(&ws, "material.mov").expect("musi znaleźć plik niezależnie od prefiksu algorytmu");
        assert_eq!(znaleziony.file_name().unwrap().to_str().unwrap(), "Recontainer_material.mov.mp4");
    }

    #[test]
    fn test_znajdz_wynik_pusty_gdy_nic_nie_pasuje() {
        let dir = tempfile::tempdir().unwrap();
        let ws = Workspace {
            name: "test".to_string(),
            root_dir: dir.path().to_path_buf(),
            broken_dir: dir.path().join("broken"),
            donors_dir: dir.path().join("donors"),
            output_dir: dir.path().to_path_buf(),
            db_path: dir.path().join("db.sqlite"),
        };

        // Nazwa innego pliku źródłowego - nie powinna pasować.
        std::fs::write(dir.path().join("Clone_inny.mp4.mp4"), b"dane").unwrap();

        assert!(znajdz_wynik(&ws, "material.mov").is_none());
    }

    // ------------------------------------------------------------------
    // TEST END-TO-END na PRAWDZIWYM materiale (wymaga ffmpeg)
    //
    // Dowodzi, że wpięcie działa fizycznie: plik, który Clone/Native/
    // Recontainer NIE POTRAFIĄ naprawić (dawca ma inny rozmiar `mdat`, więc
    // `mp4_clone`'owy filtr wstępny odrzuca parę na starcie — patrz
    // `Mp4CloneModule::repair`), zostaje odzyskany przez `Mp4AutopilotModule`
    // z LOKALNEJ puli dawców (bez sieci — DNA złamanego pliku jest znane z
    // góry, więc `find_donor` trafia w pamięć podręczną RAM zanim w ogóle
    // rozważy Rój).
    // ------------------------------------------------------------------

    use super::super::mp4::pomoce_testowe::{wygeneruj_mp4, usun_moov, katalog_wynikow};
    use crate::test_fixtures::ffmpeg_dostepny;

    #[test]
    #[ignore = "Wymaga ffmpeg do wygenerowania materiału. Uruchom z --ignored."]
    fn test_e2e_autopilot_odzyskuje_plik_z_lokalnej_puli_dawcow_bez_sieci() {
        if !ffmpeg_dostepny() { panic!("brak ffmpeg"); }
        let dir = tempfile::tempdir().unwrap();
        let wynik_dir = katalog_wynikow(dir.path());

        // Dawca i odbiorca to dwie kopie TEGO SAMEGO materiału - identycznie
        // jak w `mp4::tests::test_e2e_clone_odzyskuje_mp4_bez_moov`.
        let dawca = wygeneruj_mp4(dir.path(), "dawca.mp4");
        let zepsuty = dir.path().join("zepsuty.mp4");
        usun_moov(&dawca, &zepsuty);

        let zepsuty_str = zepsuty.to_str().unwrap();
        let (dna_sig, _cechy) = mp4_doctor::dna::extract_dna(zepsuty_str)
            .expect("złamany plik musi dać się sprofilować (DNA)");

        // Wskazujemy TĘ SAMĄ przestrzeń, którą `Mp4AutopilotModule::repair`
        // zbuduje sobie WEWNĘTRZNIE przez `przestrzen_automatyczna()` — inaczej
        // zasiew dawcy trafiłby do innej bazy niż ta, którą moduł faktycznie
        // odpyta. Bezpieczne mimo `OnceLock`: ten test jest `#[ignore]`owany,
        // więc pod zwykłym `cargo test --workspace` nigdy nie dzieli procesu z
        // `utils::tests::test_katalog_przestrzeni_mp4_doctor_daje_sie_wskazac`
        // ani z testami `phase17_repair` (obie te ścieżki NIE są ignorowane).
        mp4_doctor::workspace::ustaw_katalog_przestrzeni(dir.path().to_path_buf());
        let ws = przestrzen_automatyczna().expect("przestrzeń robocza musi się utworzyć");

        // Zasiew lokalnej puli dawców POD PRAWDZIWĄ sygnaturą DNA złamanego
        // pliku - dokładnie to, co normalnie zapisałoby wcześniejsze
        // `AppEvent::DonorFound` z udanego przebiegu.
        mp4_doctor::db::save_donor(&ws, &dna_sig, dawca.to_str().unwrap())
            .expect("zapis dawcy musi się udać");

        let kontekst = ctx("mp4", Some(false));
        let (plik, log) = Mp4AutopilotModule
            .repair(&zepsuty, &kontekst, None, &wynik_dir)
            .expect("autopilot musi odzyskać plik z lokalnej puli dawców");

        assert!(log.to_lowercase().contains("autopilot") || log.to_lowercase().contains("mp4_doctor"),
            "log powinien nazwać wykonaną operację: {}", log);
        assert!(
            Mp4AutopilotModule.verify(&plik, &kontekst).is_ok(),
            "naprawiony plik musi przejść pełną weryfikację wideo"
        );

        // Autopilot nie mógł sięgnąć po sieć: cała pula dawców w bazie liczy
        // dokładnie JEDEN wpis, zasiany lokalnie wyżej.
        let cache = mp4_doctor::db::build_brain_cache(&ws).unwrap();
        assert_eq!(cache.donors.get(&dna_sig).map(|d| d.len()), Some(1));
    }
}
