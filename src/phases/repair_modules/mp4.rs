// src/phases/repair_modules/mp4.rs

//! Moduły naprawcze kontenera MP4/MOV — trzy NIEZALEŻNE strategie oparte na
//! silnikach z [`crate::mp4_repair`].
//!
//! ## Dlaczego trzy osobne moduły, a nie jeden z wewnętrznym `match`
//!
//! Każda strategia jest osobną implementacją [`RepairModule`], bo dzięki temu
//! architektura Fazy 17 robi za nas trzy rzeczy bez ani jednej linii dodatkowego
//! kodu: (1) panel live pokazuje ODDZIELNY licznik dla każdego silnika, więc od
//! razu widać, który realnie działa na danym materiale; (2) obowiązkowa
//! weryfikacja wyniku uruchamia się po KAŻDEJ próbie, a odrzucony plik jest
//! usuwany, zanim spróbuje kolejny silnik; (3) użytkownik może wyłączyć
//! pojedynczy silnik w `MultiSelect` — np. zostawić tylko bezzależnościowy
//! Zero-Donor, gdy nie chce dopuszczać `ffmpeg` do materiału dowodowego.
//!
//! ## Domeny silników — USTALONE EMPIRYCZNIE
//!
//! Dokumentacja źródłowa `mp4_doctor` opisuje `engine_native` jako „w 100%
//! niezależny", co sugeruje, że poradzi sobie z każdym MP4. Sprawdzenie na
//! prawdziwym materiale pokazało co innego, więc warunki uruchamiania oparto na
//! pomiarach, nie na opisie:
//!
//! | uszkodzenie | clone | native | recontainer |
//! |---|---|---|---|
//! | MP4 bez atomu `moov`, dostępna druga kopia | **działa** | nie | nie |
//! | MP4 bez atomu `moov`, bez dawcy | nie | nie | nie |
//! | surowy strumień Annex B (`.h264` po carverze) | nie | **działa** | nie |
//! | MP4 z całym kontenerem, zepsute dane klatek | nie | nie | **działa** |
//!
//! Wniosek, który ukształtował warunki `applies_to`: `native` szuka
//! startcode'ów Annex B, a w `mdat` zwykłego MP4 NAL-e są w formacie AVCC
//! (prefiks długości), więc tam nie ma czego znaleźć. Jego prawdziwą wartością
//! jest zamiana WYCIĘTEGO strumienia w grywalny kontener — zdolność, której
//! projekt dotąd nie miał wcale.
//!
//! ## Kolejność prób (ustalona w [`super::all_modules`])
//!
//! `clone` → `native` → `recontainer`, od najwierniejszej metody do najbardziej
//! inwazyjnej:
//! 1. **clone** przeszczepia PRAWDZIWY `moov` bliźniaczej kopii, więc zachowuje
//!    oryginalne tablice czasu i indeksy — najwierniejszy wynik, ale wymaga
//!    dawcy.
//! 2. **native** odbudowuje `moov` od zera z surowych jednostek NAL. Nie
//!    potrzebuje niczego poza samym plikiem, ale metadane (timescale, tablice
//!    czasu) są rekonstruowane heurystycznie, nie odzyskane.
//! 3. **recontainer** przepuszcza materiał przez `ffmpeg` — najskuteczniejszy
//!    przy popsutych strumieniach, ale przepisuje cały plik i wymaga
//!    zewnętrznej binarki.
//!
//! Wszystkie trzy nadpisują [`RepairModule::verify`], żeby użyć
//! [`crate::mp4_repair::validator::is_healthy_video`] — pełnego dekodowania
//! klatek. To najmocniejszy dowód dostępny dla wideo: wykrywa także pliki
//! „puste", w których kontener został naprawiony, ale obraz się nie ładuje.

use super::{RepairContext, RepairModule, WynikWeryfikacji};
use crate::mp4_repair::{engine_clone, engine_native, engine_recontainer, validator};
use std::path::{Path, PathBuf};

/// Rozszerzenia KONTENERÓW ISOBMFF **NIOSĄCYCH OBRAZ**.
///
/// ## Dlaczego lista jest dłuższa niż `mp4/mov/m4v`
///
/// Silniki (`engine_clone`, `engine_native`, `engine_recontainer`) operują na
/// pudełkach ISOBMFF — `ftyp`, `moov`, `mdat` — a nie na rozszerzeniu nazwy.
/// `.3gp`, `.3g2` i `.f4v` to ten sam kontener, więc ograniczenie do trzech
/// nazw było ograniczeniem NAZWY, nie możliwości.
///
/// Ta lista musi pokrywać się z gałęzią ISOBMFF w
/// [`super::weryfikuj_naprawiony_plik`]. Przez pewien czas nie pokrywała się:
/// weryfikacja obejmowała już `.3gp`/`.3g2`/`.f4v`, a naprawa nie — więc
/// Faza 17 potrafiła sprawdzić wynik dla tych plików, ale nie miała czym go
/// wytworzyć i zostawał sam ślepy `splice`. Pilnuje tego test
/// `test_lista_rozszerzen_pokrywa_sie_z_weryfikacja`.
///
/// ## Czego tu świadomie NIE MA
///
/// `.m4a` i `.m4b` to ten sam kontener, ale BEZ ścieżki obrazu. Wszystkie trzy
/// moduły weryfikują wynik przez [`weryfikuj_wideo`], a ten w trybie z ffmpeg
/// żąda strumienia `v:0` z wymiarami. Poprawnie naprawiony plik audio zostałby
/// więc uznany za zepsuty i USUNIĘTY — sprawdzone empirycznie: dla `.m4a`
/// zapytanie ffprobe o `v:0` zwraca pusty wynik.
const ROZSZERZENIA_MP4: &[&str] = &["mp4", "mov", "m4v", "3gp", "3g2", "f4v"];

/// Rozszerzenia SUROWYCH strumieni elementarnych H.264 (Annex B).
///
/// Takie pliki produkuje carver, gdy wyciągnie z nośnika same dane klatek bez
/// kontenera. Nie są grywalne z definicji — nie mają `moov`, bo nie mają wcale
/// struktury MP4 — więc KAŻDY taki plik jest kandydatem do odbudowy, bez
/// potrzeby jakiejkolwiek przesłanki uszkodzenia.
const ROZSZERZENIA_SUROWEGO_H264: &[&str] = &["h264", "264", "avc"];

/// Rozstrzyga, czy plik jest kandydatem do naprawy MP4.
///
/// ## Dobór sygnału uszkodzenia
///
/// Głównym sygnałem jest `video_ok == Some(false)` z Fazy 19 — to jedyna faza,
/// która realnie czyta strukturę kontenera wideo. Dopuszczamy też dwa sygnały
/// zastępcze, żeby moduł działał również wtedy, gdy Faza 19 nie była
/// uruchomiona: brak/uszkodzenie znacznika końca z Fazy 6 (`eof_ok`) oraz
/// zniszczony nagłówek zgłoszony przez Fazę 12 (`media_reason`).
///
/// Warunek jest CELOWO wymagający — nie ruszamy plików bez żadnej przesłanki
/// uszkodzenia. Ale nie jest zależny od jednej, konkretnej fazy, bo wtedy
/// moduł byłby martwy przy każdym przebiegu bez tamtej fazy (dokładnie ta
/// pułapka, w którą wpadła naprawa rozszerzeń — patrz nagłówek Fazy 17).
pub(super) fn jest_uszkodzonym_mp4(ctx: &RepairContext) -> bool {
    if !ROZSZERZENIA_MP4.contains(&ctx.ext) {
        return false;
    }

    ctx.video_ok == Some(false)
        || ctx.eof_ok == Some(false)
        || ctx.media_reason.is_some_and(|r| r.contains("Nagłówek"))
}

/// Buduje ścieżkę wyniku z sufiksem właściwym dla silnika.
///
/// Każdy silnik pisze pod WŁASNĄ nazwą, nie pod wspólnym `_repaired`. Po
/// pierwsze widać wtedy w logu i na dysku, która strategia dała wynik. Po
/// drugie nie ma szansy na kolizję, gdy orkiestrator próbuje kolejnego silnika
/// po odrzuceniu poprzedniego.
pub(super) fn sciezka_wyniku(source: &Path, katalog_wyjsciowy: &Path, sufiks: &str) -> Option<PathBuf> {
    let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("mp4").to_string();
    sciezka_wyniku_z_rozszerzeniem(source, katalog_wyjsciowy, sufiks, &ext)
}

/// Wariant [`sciezka_wyniku`] z JAWNIE narzuconym rozszerzeniem.
///
/// Potrzebny silnikowi Zero-Donor: gdy wejściem jest surowy strumień `.h264`,
/// wyjściem jest KONTENER MP4, więc zachowanie rozszerzenia wejściowego byłoby
/// zwyczajnym kłamstwem o zawartości pliku (a przy okazji zepsułoby dobór
/// metody weryfikacji, który idzie po rozszerzeniu).
fn sciezka_wyniku_z_rozszerzeniem(source: &Path, katalog_wyjsciowy: &Path, sufiks: &str, ext: &str) -> Option<PathBuf> {
    let stem = source.file_stem()?.to_str()?;
    Some(katalog_wyjsciowy.join(format!("{}_repaired_{}.{}", stem, sufiks, ext)))
}

/// Wspólna weryfikacja wyniku dla wszystkich silników wideo.
///
/// ## Dwa poziomy gwarancji, zależne od środowiska
///
/// Z dostępnym `ffmpeg` weryfikacja to PEŁNE DEKODOWANIE klatek — najmocniejszy
/// możliwy dowód, wykrywa także pliki „puste" (kontener naprawiony, obraz się
/// nie ładuje).
///
/// Bez `ffmpeg` schodzimy do kontroli STRUKTURALNEJ (obecność `moov` i `mdat`,
/// offsety w granicach pliku) i JAWNIE oznaczamy słabszą gwarancję. Poprzednio
/// w tej sytuacji `is_healthy_video` zwracało `false` dla każdego pliku, więc
/// KAŻDA naprawa MP4 była odrzucana i usuwana, a licznik odrzuceń rósł bez
/// wskazania przyczyny — operator widział „naprawy nie działają" zamiast
/// „brakuje binarki". Teraz naprawa jest możliwa także bez `ffmpeg`, tylko z
/// uczciwie zaniżoną gwarancją.
pub(super) fn weryfikuj_wideo(repaired: &Path) -> WynikWeryfikacji {
    let sciezka = match repaired.to_str() {
        Some(s) => s,
        None => return Err("ścieżka wyniku nie jest poprawnym UTF-8".to_string()),
    };

    if validator::ffmpeg_dostepny() {
        return if validator::is_healthy_video(sciezka) {
            Ok("pełne dekodowanie klatek wideo, bez pustych strumieni (gwarancja MOCNA)")
        } else {
            Err("plik nie przechodzi pełnego dekodowania wideo (brak klatek lub zepsute offsety)".to_string())
        };
    }

    match crate::mp4_repair::boxes::struktura_kontenera_poprawna_pliku(repaired) {
        Some(true) => Ok("brak ffmpeg - sprawdzono strukturę kontenera: moov i mdat obecne, offsety w granicach pliku (gwarancja SŁABA)"),
        Some(false) => Err("struktura kontenera niespójna: brak moov/mdat albo offsety wskazują poza plik".to_string()),
        None => Err("nie udało się wczytać wyniku do kontroli strukturalnej (brak ffmpeg, plik zbyt duży lub nieczytelny)".to_string()),
    }
}

/// Usuwa nieudany wynik, żeby nie został na dysku jako pozorna naprawa.
///
/// Silniki zapisują plik wyjściowy w trakcie pracy, więc nieudany przebieg
/// zostawia plik częściowy. Orkiestrator usuwa tylko wyniki ODRZUCONE PRZEZ
/// WERYFIKACJĘ — o porażce samego silnika (zwrócone `None`) nie wie nic, bo
/// nie zna nawet ścieżki, jaką silnik zamierzał zapisać.
fn sprzataj(sciezka: &Path) {
    let _ = std::fs::remove_file(sciezka);
}

// ============================================================================
// ZERO-DONOR (engine_native)
// ============================================================================

pub struct Mp4NativeModule;

impl RepairModule for Mp4NativeModule {
    fn id(&self) -> &'static str { "mp4_native" }
    fn display_name(&self) -> &'static str { "MP4 Zero-Donor (odbudowa moov od zera, bez dawcy)" }

    /// ## Domena tego silnika (ustalona EMPIRYCZNIE, nie z dokumentacji)
    ///
    /// Silnik szuka startcode'ów Annex B (`00 00 00 01`), więc jego naturalnym
    /// wejściem jest SUROWY STRUMIEŃ elementarny — taki, jaki carver wyciąga z
    /// nośnika bez kontenera. Sprawdzone: `.h264` wycięty z nagrania zostaje
    /// odbudowany w grywalny MP4, przechodzący pełne dekodowanie.
    ///
    /// W danych `mdat` zwykłego MP4 NAL-e są zapisane w formacie AVCC (prefiks
    /// długości, nie startcode), więc tam silnik nic sensownego nie znajdzie —
    /// sprawdzone: na MP4 pozbawionym `moov` zwraca porażkę. Rozszerzenia
    /// kontenerowe zostawiamy jednak w warunku, bo próba jest tania (silnik
    /// kończy szybko, gdy nie widzi startcode'ów), a pliki po carverze bywają
    /// nazwane `.mp4` mimo braku kontenera.
    fn applies_to(&self, ctx: &RepairContext) -> bool {
        // Surowy strumień elementarny NIE JEST grywalny z definicji — nie
        // potrzeba żadnej dodatkowej przesłanki uszkodzenia.
        ROZSZERZENIA_SUROWEGO_H264.contains(&ctx.ext) || jest_uszkodzonym_mp4(ctx)
    }

    /// Odbudowuje kontener wyłącznie z zawartości pliku wejściowego: skanuje
    /// jednostki NAL strumienia Annex B, grupuje je w klatki, wykrywa
    /// keyframe'y i buduje kompletne drzewo `moov` ze ścieżkami `vide`/`soun`.
    ///
    /// To jedyna strategia, która NIE POTRZEBUJE dawcy — decydująca dla plików
    /// unikalnych, gdzie druga kopia nie istnieje.
    ///
    /// Wynik ZAWSZE dostaje rozszerzenie `.mp4`, bo produktem jest kontener,
    /// niezależnie od tego, czym był plik wejściowy.
    fn repair(&self, source: &Path, _ctx: &RepairContext, _twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let zrodlo = source.to_str()?;
        let cel = sciezka_wyniku_z_rozszerzeniem(source, katalog_wyjsciowy, "native", "mp4")?;
        let cel_txt = cel.to_str()?;

        // Postęp silnika trafia do logu diagnostycznego, nie do UI — Faza 17
        // raportuje postęp per PLIK, a nie per etap wewnątrz jednego pliku.
        let postep = |msg: String| tracing::trace!(silnik = "mp4_native", "{}", msg);

        match engine_native::repair(zrodlo, cel_txt, Some(&postep)) {
            Ok(()) => Some((cel, "Odbudowano kontener MP4 od zera (Zero-Donor, bez dawcy).".to_string())),
            Err(e) => {
                tracing::debug!(plik = %source.display(), blad = %e, "mp4_native: odbudowa nieudana");
                sprzataj(&cel);
                None
            }
        }
    }

    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        weryfikuj_wideo(repaired)
    }
}

// ============================================================================
// PRZESZCZEP MOOV OD DAWCY (engine_clone)
// ============================================================================

pub struct Mp4CloneModule;

impl RepairModule for Mp4CloneModule {
    fn id(&self) -> &'static str { "mp4_clone" }
    fn display_name(&self) -> &'static str { "MP4 przeszczep moov z bliźniaczej kopii (stco/co64)" }

    fn applies_to(&self, ctx: &RepairContext) -> bool {
        jest_uszkodzonym_mp4(ctx)
    }

    /// Kopiuje sprawny atom `moov` z bliźniaczej kopii i łączy go z surowymi
    /// danymi `mdat` uszkodzonego pliku, PRZESUWAJĄC tablice adresów
    /// `stco`/`co64` pod nową pozycję `mdat`.
    ///
    /// Zwraca `None`, gdy bliźniak nie został podany — ten moduł bezwzględnie
    /// go wymaga, analogicznie do modułu zszywania.
    fn repair(&self, source: &Path, _ctx: &RepairContext, twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let dawca = twin?;

        // FILTR WSTĘPNY: `moov` opisuje konkretną treść `mdat`, więc dawca z
        // INNEGO nagrania da plik pozornie spójny, ale niedekodowalny. Rozjazd
        // rozmiaru `mdat` to mocna przesłanka, że to inny materiał — nie ma po
        // co uruchamiać przeszczepu ani kosztownego dekodowania.
        //
        // `None` (nie udało się odczytać `mdat` którejkolwiek strony) NIE
        // blokuje próby: brak odpowiedzi nie jest odpowiedzią przeczącą, a
        // ostateczne rozstrzygnięcie daje obowiązkowa weryfikacja wyniku.
        if crate::mp4_repair::boxes::rozmiary_mdat_zgodne(source, dawca) == Some(false) {
            tracing::debug!(
                plik = %source.display(), dawca = %dawca.display(),
                "mp4_clone: pominięto - rozmiar mdat dawcy się nie zgadza (inne nagranie)"
            );
            return None;
        }

        let zrodlo = source.to_str()?;
        let dawca_txt = dawca.to_str()?;
        let cel = sciezka_wyniku(source, katalog_wyjsciowy, "clone")?;
        let cel_txt = cel.to_str()?;

        match engine_clone::repair(zrodlo, dawca_txt, cel_txt) {
            Ok(()) => Some((cel, format!("Przeszczepiono moov od dawcy {} z korektą tablic stco/co64.", dawca.display()))),
            Err(e) => {
                tracing::debug!(plik = %source.display(), dawca = %dawca.display(), blad = %e, "mp4_clone: przeszczep nieudany");
                sprzataj(&cel);
                None
            }
        }
    }

    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        weryfikuj_wideo(repaired)
    }
}

// ============================================================================
// PRZEPAKOWANIE FFMPEGIEM (engine_recontainer)
// ============================================================================

pub struct Mp4RecontainerModule;

impl RepairModule for Mp4RecontainerModule {
    fn id(&self) -> &'static str { "mp4_recontainer" }
    fn display_name(&self) -> &'static str { "MP4 przepakowanie ffmpegiem (korekta dryfu A/V)" }

    /// W odróżnieniu od pozostałych dwóch silników ten BEZWZGLĘDNIE wymaga
    /// `ffmpeg` — cała jego praca to wywołanie tej binarki. Bez niej nie ma
    /// sensu nawet próbować, więc odpadamy już na `applies_to`: nie powstaje
    /// plik do usunięcia i nie rośnie licznik odrzuceń.
    fn applies_to(&self, ctx: &RepairContext) -> bool {
        validator::ffmpeg_dostepny() && jest_uszkodzonym_mp4(ctx)
    }

    /// Przepuszcza materiał przez `ffmpeg` z flagami korygującymi i korektą
    /// asynchronizacji audio-wideo.
    ///
    /// WYMAGA zewnętrznej binarki `ffmpeg`. Gdy jej nie ma, silnik zwróci błąd,
    /// a orkiestrator potraktuje to jak każdą inną porażkę modułu i przejdzie
    /// dalej — nie ma potrzeby osobnego sprawdzania dostępności.
    fn repair(&self, source: &Path, _ctx: &RepairContext, _twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let zrodlo = source.to_str()?;
        let cel = sciezka_wyniku(source, katalog_wyjsciowy, "recontainer")?;
        let cel_txt = cel.to_str()?;

        match engine_recontainer::repair(zrodlo, cel_txt) {
            Ok(()) => Some((cel, "Przepakowano kontener ffmpegiem z korektą dryfu A/V.".to_string())),
            Err(e) => {
                tracing::debug!(plik = %source.display(), blad = %e, "mp4_recontainer: przepakowanie nieudane");
                sprzataj(&cel);
                None
            }
        }
    }

    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        weryfikuj_wideo(repaired)
    }
}

/// Budowniczy prawdziwego materiału wideo (przez `ffmpeg`) do testów e2e —
/// jedyna kopia w crate'cie (patrz [`mp4_autopilot`](super::mp4_autopilot),
/// która reużywa go dla WŁASNEGO testu e2e zamiast duplikować wywołania
/// `ffmpeg`). Ten sam wzorzec co `png_repair::pomoce_testowe`.
#[cfg(test)]
pub(super) mod pomoce_testowe {
    use std::path::{Path, PathBuf};

    pub fn ffmpeg_dostepny() -> bool {
        std::process::Command::new("ffmpeg").arg("-version").output()
            .map(|o| o.status.success()).unwrap_or(false)
    }

    pub fn wygeneruj_mp4(katalog: &Path, nazwa: &str) -> PathBuf {
        let cel = katalog.join(nazwa);
        let ok = std::process::Command::new("ffmpeg")
            .args(["-nostdin", "-loglevel", "quiet", "-y",
                   "-f", "lavfi", "-i", "testsrc=duration=2:size=128x128:rate=15",
                   "-pix_fmt", "yuv420p"])
            .arg(&cel).status().map(|s| s.success()).unwrap_or(false);
        assert!(ok && cel.exists(), "ffmpeg nie wygenerował materiału testowego");
        cel
    }

    /// Kopiuje plik, USUWAJĄC z niego atom `moov` — dokładnie to uszkodzenie,
    /// dla którego istnieje przeszczep.
    pub fn usun_moov(zrodlo: &Path, cel: &Path) {
        let bajty = std::fs::read(zrodlo).unwrap();
        let boxy = crate::mp4_repair::boxes::parse_top_level_boxes(&bajty);
        let moov = crate::mp4_repair::boxes::find_box(&boxy, b"moov")
            .expect("wygenerowany plik musi mieć moov");

        let mut wynik = Vec::with_capacity(bajty.len());
        wynik.extend_from_slice(&bajty[..moov.offset]);
        wynik.extend_from_slice(&bajty[moov.offset + moov.size..]);
        std::fs::write(cel, &wynik).unwrap();
    }

    pub fn katalog_wynikow(dir: &Path) -> PathBuf {
        let w = dir.join("wyniki");
        std::fs::create_dir_all(&w).unwrap();
        w
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::pomoce_testowe::{ffmpeg_dostepny, wygeneruj_mp4, usun_moov, katalog_wynikow};

    fn ctx(ext: &'static str, video_ok: Option<bool>, eof_ok: Option<bool>, media_reason: Option<&'static str>) -> RepairContext<'static> {
        RepairContext {
            ext, media_reason, utf8_ok: None, is_oneliner: None,
            eof_ok, match_type: None, video_ok, structure_ok: None,
        }
    }

    fn wszystkie() -> Vec<Box<dyn RepairModule>> {
        vec![Box::new(Mp4NativeModule), Box::new(Mp4CloneModule), Box::new(Mp4RecontainerModule)]
    }

    // ------------------------------------------------------------------
    // applies_to — sygnał uszkodzenia
    // ------------------------------------------------------------------

    #[test]
    fn test_stosuje_sie_do_uszkodzonego_wideo_z_fazy19() {
        for m in wszystkie() {
            assert!(m.applies_to(&ctx("mp4", Some(false), None, None)), "{}", m.id());
        }
    }

    #[test]
    fn test_stosuje_sie_do_wszystkich_rozszerzen_isobmff() {
        for ext in ["mp4", "mov", "m4v", "3gp", "3g2", "f4v"] {
            assert!(Mp4NativeModule.applies_to(&ctx(ext, Some(false), None, None)), "ext {}", ext);
        }
    }

    /// Naprawa i weryfikacja MUSZĄ obejmować ten sam zbiór rozszerzeń.
    ///
    /// Przez pewien czas się rozjeżdżały: weryfikacja znała już `.3gp`/`.3g2`/
    /// `.f4v`, a naprawa nie — więc Faza 17 potrafiła sprawdzić wynik dla tych
    /// plików, ale nie miała czym go wytworzyć. Ten test wychwyci powtórkę.
    #[test]
    fn test_lista_rozszerzen_pokrywa_sie_z_weryfikacja() {
        let dir = tempfile::tempdir().unwrap();

        for ext in ROZSZERZENIA_MP4 {
            // Śmieci z danym rozszerzeniem muszą zostać ODRZUCONE przez
            // weryfikację. Gałąź domyślna by je przyjęła (niepuste, nie same
            // zera), więc odrzucenie dowodzi, że format ma własną gałąź.
            let p = dir.path().join(format!("smieci.{}", ext));
            std::fs::write(&p, b"to zupelnie nie jest kontener isobmff").unwrap();

            assert!(
                super::super::weryfikuj_naprawiony_plik(&p).is_err(),
                ".{} jest w ROZSZERZENIA_MP4, ale weryfikacja nie ma dla niego gałęzi \
                 - moduł wytworzyłby wynik, którego nikt nie potrafi sprawdzić", ext
            );
        }
    }

    /// `.m4a`/`.m4b` NIE MOGĄ trafić do tych modułów: ich `verify` żąda od
    /// ffprobe strumienia obrazu, więc poprawnie naprawiony plik audio
    /// zostałby odrzucony i usunięty.
    #[test]
    fn test_kontenery_audio_sa_poza_zakresem() {
        for ext in ["m4a", "m4b"] {
            for m in wszystkie() {
                assert!(
                    !m.applies_to(&ctx(ext, Some(false), Some(false), Some("Nagłówek"))),
                    "{} nie może zgłaszać się do .{}", m.id(), ext
                );
            }
        }
    }

    #[test]
    fn test_nie_rusza_zdrowego_wideo() {
        // Brak jakiejkolwiek przesłanki uszkodzenia = nie dotykamy pliku.
        for m in wszystkie() {
            assert!(!m.applies_to(&ctx("mp4", Some(true), Some(true), None)), "{}", m.id());
            assert!(!m.applies_to(&ctx("mp4", None, None, None)), "{} bez diagnostyki", m.id());
        }
    }

    #[test]
    fn test_nie_rusza_innych_formatow() {
        for ext in ["jpg", "mkv", "txt", "zip", "flv"] {
            assert!(!Mp4NativeModule.applies_to(&ctx(ext, Some(false), None, None)), "ext {}", ext);
        }
    }

    /// Sygnały zastępcze: moduł musi działać także bez przebiegu Fazy 19,
    /// inaczej byłby martwy przy każdym uruchomieniu bez tamtej fazy.
    #[test]
    fn test_sygnaly_zastepcze_gdy_faza19_nie_dzialala() {
        assert!(
            Mp4NativeModule.applies_to(&ctx("mp4", None, Some(false), None)),
            "eof_ok = false z Fazy 6 musi wystarczyć"
        );
        assert!(
            Mp4NativeModule.applies_to(&ctx("mp4", None, None, Some("Zniszczony Nagłówek obrazu"))),
            "powód z Fazy 12 zawierający Nagłówek musi wystarczyć"
        );
    }

    // ------------------------------------------------------------------
    // Identyfikatory i nazwy
    // ------------------------------------------------------------------

    #[test]
    fn test_identyfikatory_sa_rozne_i_opisowe() {
        let ids: Vec<&str> = wszystkie().iter().map(|m| m.id()).collect();
        assert_eq!(ids, vec!["mp4_native", "mp4_clone", "mp4_recontainer"]);

        for m in wszystkie() {
            assert!(!m.display_name().is_empty(), "{}", m.id());
        }
    }

    // ------------------------------------------------------------------
    // Ścieżka wyniku
    // ------------------------------------------------------------------

    #[test]
    fn test_kazdy_silnik_pisze_pod_wlasna_nazwa() {
        let zrodlo = Path::new("/korpus/foto/film.mp4");
        let katalog = Path::new("/praca/wynik");

        let native = sciezka_wyniku(zrodlo, katalog, "native").unwrap();
        let clone = sciezka_wyniku(zrodlo, katalog, "clone").unwrap();
        let recont = sciezka_wyniku(zrodlo, katalog, "recontainer").unwrap();

        assert_eq!(native, Path::new("/praca/wynik/film_repaired_native.mp4"));
        assert_ne!(native, clone);
        assert_ne!(clone, recont);

        // Rozszerzenie MUSI zostać zachowane — po nim dobierana jest metoda
        // weryfikacji.
        for p in [&native, &clone, &recont] {
            assert_eq!(p.extension().and_then(|e| e.to_str()), Some("mp4"));
        }
    }

    #[test]
    fn test_sciezka_wyniku_zachowuje_rozszerzenie_mov() {
        let p = sciezka_wyniku(Path::new("/a/klip.mov"), Path::new("/w"), "clone").unwrap();
        assert_eq!(p, Path::new("/w/klip_repaired_clone.mov"));
    }

    // ------------------------------------------------------------------
    // repair — warunki brzegowe (bez wywoływania ffmpeg)
    // ------------------------------------------------------------------

    #[test]
    fn test_clone_bez_dawcy_zwraca_none() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("film.mp4");
        std::fs::write(&plik, b"nieistotne").unwrap();

        assert!(
            Mp4CloneModule.repair(&plik, &ctx("mp4", Some(false), None, None), None, dir.path()).is_none(),
            "Przeszczep bez dawcy nie ma sensu"
        );
    }

    #[test]
    fn test_nieudana_naprawa_nie_zostawia_pliku() {
        // Wejście to nie jest wideo, więc każdy silnik musi polec — i po sobie
        // posprzątać.
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("nie_wideo.mp4");
        std::fs::write(&plik, b"to zupelnie nie jest kontener mp4").unwrap();

        let wynik = dir.path().join("wyniki");
        std::fs::create_dir_all(&wynik).unwrap();

        let kontekst = ctx("mp4", Some(false), None, None);
        assert!(Mp4NativeModule.repair(&plik, &kontekst, None, &wynik).is_none());

        let pozostalo: Vec<String> = std::fs::read_dir(&wynik).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(pozostalo.is_empty(), "Po nieudanej naprawie nie może zostać plik: {:?}", pozostalo);
    }

    // ------------------------------------------------------------------
    // verify
    // ------------------------------------------------------------------

    #[test]
    fn test_weryfikacja_odrzuca_plik_ktory_nie_jest_wideo() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("smieci.mp4");
        std::fs::write(&plik, b"to nie jest wideo").unwrap();

        let kontekst = ctx("mp4", Some(false), None, None);
        for m in wszystkie() {
            assert!(
                m.verify(&plik, &kontekst).is_err(),
                "{} przepuścił plik, który nie jest wideo", m.id()
            );
        }
    }

    #[test]
    fn test_weryfikacja_odrzuca_plik_nieistniejacy() {
        let dir = tempfile::tempdir().unwrap();
        let brak = dir.path().join("nie_ma.mp4");
        assert!(Mp4NativeModule.verify(&brak, &ctx("mp4", None, None, None)).is_err());
    }

    // ------------------------------------------------------------------
    // TESTY END-TO-END na PRAWDZIWYM materiale (wymagają ffmpeg)
    //
    // To one ustaliły domeny silników z tabeli w nagłówku modułu. Każdy
    // sprawdza JEDEN scenariusz uszkodzenia od końca do końca: generuje
    // materiał, psuje go w określony sposób, naprawia i weryfikuje wynik
    // pełnym dekodowaniem.
    // ------------------------------------------------------------------


    #[test]
    #[ignore = "Wymaga ffmpeg do wygenerowania materiału. Uruchom z --ignored."]
    fn test_e2e_clone_odzyskuje_mp4_bez_moov() {
        if !ffmpeg_dostepny() { panic!("brak ffmpeg"); }
        let dir = tempfile::tempdir().unwrap();
        let wynik = katalog_wynikow(dir.path());

        // Dawca i odbiorca to dwie kopie TEGO SAMEGO materiału.
        let dawca = wygeneruj_mp4(dir.path(), "dawca.mp4");
        let zepsuty = dir.path().join("zepsuty.mp4");
        usun_moov(&dawca, &zepsuty);

        let kontekst = ctx("mp4", Some(false), None, None);
        let (plik, log) = Mp4CloneModule
            .repair(&zepsuty, &kontekst, Some(&dawca), &wynik)
            .expect("przeszczep moov musi się udać dla identycznego materiału");

        assert!(log.contains("moov"), "log powinien nazwać wykonaną operację: {}", log);
        assert!(
            Mp4CloneModule.verify(&plik, &kontekst).is_ok(),
            "naprawiony plik musi przejść PEŁNE dekodowanie klatek"
        );
    }

    /// Prawdziwa wartość silnika Zero-Donor: zamiana wyciętego strumienia
    /// elementarnego w grywalny kontener. Tej zdolności projekt nie miał wcale.
    #[test]
    #[ignore = "Wymaga ffmpeg do wygenerowania materiału. Uruchom z --ignored."]
    fn test_e2e_native_odbudowuje_kontener_z_surowego_annexb() {
        if !ffmpeg_dostepny() { panic!("brak ffmpeg"); }
        let dir = tempfile::tempdir().unwrap();
        let wynik = katalog_wynikow(dir.path());

        let mp4 = wygeneruj_mp4(dir.path(), "zrodlo.mp4");
        let surowy = dir.path().join("wyciety.h264");
        let ok = std::process::Command::new("ffmpeg")
            .args(["-nostdin", "-loglevel", "quiet", "-y", "-i"])
            .arg(&mp4)
            .args(["-c", "copy", "-bsf:v", "h264_mp4toannexb", "-f", "h264"])
            .arg(&surowy).status().map(|s| s.success()).unwrap_or(false);
        assert!(ok, "nie udało się wyciąć surowego strumienia Annex B");

        let kontekst = ctx("h264", None, None, None);
        assert!(
            Mp4NativeModule.applies_to(&kontekst),
            "Surowy strumień MUSI kwalifikować się bez żadnej przesłanki uszkodzenia"
        );

        let (plik, _) = Mp4NativeModule
            .repair(&surowy, &kontekst, None, &wynik)
            .expect("Zero-Donor musi odbudować kontener z surowego Annex B");

        assert_eq!(
            plik.extension().and_then(|e| e.to_str()), Some("mp4"),
            "Produktem jest KONTENER, więc rozszerzenie musi być .mp4, nie .h264"
        );
        assert!(
            Mp4NativeModule.verify(&plik, &kontekst).is_ok(),
            "odbudowany kontener musi przejść pełne dekodowanie klatek"
        );
    }

    #[test]
    #[ignore = "Wymaga ffmpeg do wygenerowania materiału. Uruchom z --ignored."]
    fn test_e2e_recontainer_naprawia_zepsute_dane_klatek() {
        if !ffmpeg_dostepny() { panic!("brak ffmpeg"); }
        let dir = tempfile::tempdir().unwrap();
        let wynik = katalog_wynikow(dir.path());

        let zdrowy = wygeneruj_mp4(dir.path(), "zdrowy.mp4");
        let bajty = std::fs::read(&zdrowy).unwrap();
        let boxy = crate::mp4_repair::boxes::parse_top_level_boxes(&bajty);
        let mdat = crate::mp4_repair::boxes::find_box(&boxy, b"mdat").unwrap();

        // Psujemy WYŁĄCZNIE wnętrze mdat — kontener i moov zostają nietknięte.
        // Przy szerszym zasięgu zniszczylibyśmy też moov i test mierzyłby coś
        // innego, niż zakłada (sprawdzone: ffmpeg zgłasza wtedy „moov atom not
        // found" i przepakowanie jest niemożliwe).
        let mut zepsute = bajty.clone();
        let od = mdat.offset + 1000;
        let do_ = (mdat.offset + mdat.size).min(od + 500);
        zepsute[od..do_].fill(0xFF);

        let plik = dir.path().join("zepsuty_strumien.mp4");
        std::fs::write(&plik, &zepsute).unwrap();

        let kontekst = ctx("mp4", Some(false), None, None);
        let (naprawiony, _) = Mp4RecontainerModule
            .repair(&plik, &kontekst, None, &wynik)
            .expect("przepakowanie musi się udać, gdy kontener jest czytelny");

        assert!(
            Mp4RecontainerModule.verify(&naprawiony, &kontekst).is_ok(),
            "przepakowany plik musi przejść pełne dekodowanie klatek"
        );
    }

    /// Granica NEGATYWNA, równie ważna jak pozytywna: Zero-Donor NIE radzi
    /// sobie z danymi z kontenera MP4 (tam NAL-e są w formacie AVCC). Test
    /// pilnuje, żeby nikt nie „poprawił" dokumentacji na optymistyczną.
    #[test]
    #[ignore = "Wymaga ffmpeg do wygenerowania materiału. Uruchom z --ignored."]
    fn test_e2e_native_nie_radzi_z_mp4_bez_moov() {
        if !ffmpeg_dostepny() { panic!("brak ffmpeg"); }
        let dir = tempfile::tempdir().unwrap();
        let wynik = katalog_wynikow(dir.path());

        let zdrowy = wygeneruj_mp4(dir.path(), "zdrowy.mp4");
        let zepsuty = dir.path().join("bez_moov.mp4");
        usun_moov(&zdrowy, &zepsuty);

        let kontekst = ctx("mp4", Some(false), None, None);
        let r = Mp4NativeModule.repair(&zepsuty, &kontekst, None, &wynik);

        // Dopuszczamy oba zachowania: porażkę silnika albo wynik odrzucony
        // przez weryfikację. NIE dopuszczamy wyniku PRZYJĘTEGO — to znaczyłoby,
        // że tabela zdolności w nagłówku modułu jest nieprawdziwa.
        if let Some((plik, _)) = r {
            assert!(
                Mp4NativeModule.verify(&plik, &kontekst).is_err(),
                "Gdyby Zero-Donor naprawdę odbudował MP4 z AVCC, tabela w nagłówku modułu wymaga aktualizacji"
            );
        }
    }

    #[test]
    fn test_surowy_strumien_kwalifikuje_sie_bez_przeslanki_uszkodzenia() {
        for ext in ["h264", "264", "avc"] {
            assert!(
                Mp4NativeModule.applies_to(&ctx(ext, None, None, None)),
                "surowy strumień .{} musi się kwalifikować", ext
            );
            // Pozostałe silniki operują na kontenerach — surowy strumień ich
            // nie dotyczy.
            assert!(!Mp4CloneModule.applies_to(&ctx(ext, None, None, None)), "clone/.{}", ext);
            assert!(!Mp4RecontainerModule.applies_to(&ctx(ext, None, None, None)), "recontainer/.{}", ext);
        }
    }

    #[test]
    fn test_zero_donor_zawsze_produkuje_mp4() {
        let p = sciezka_wyniku_z_rozszerzeniem(
            Path::new("/korpus/wyciety.h264"), Path::new("/w"), "native", "mp4").unwrap();
        assert_eq!(p, Path::new("/w/wyciety_repaired_native.mp4"));
    }

    // ------------------------------------------------------------------
    // Zależność od ffmpeg
    // ------------------------------------------------------------------

    /// `mp4_recontainer` to opakowanie na `ffmpeg` — bez tej binarki nie ma
    /// sensu nawet próbować, więc odpada już na `applies_to`.
    #[test]
    fn test_recontainer_jest_bramkowany_dostepnoscia_ffmpeg() {
        let uszkodzony = ctx("mp4", Some(false), None, None);
        let dostepny = crate::mp4_repair::validator::ffmpeg_dostepny();

        assert_eq!(
            Mp4RecontainerModule.applies_to(&uszkodzony), dostepny,
            "applies_to recontainera musi śledzić dostępność ffmpeg (tu: {})", dostepny
        );

        // Pozostałe dwa silniki NIE zależą od ffmpeg przy produkcji wyniku —
        // działają w czystym Rust i muszą się kwalifikować niezależnie.
        assert!(Mp4CloneModule.applies_to(&uszkodzony), "clone nie zależy od ffmpeg");
        assert!(Mp4NativeModule.applies_to(&uszkodzony), "native nie zależy od ffmpeg");
    }

    /// Weryfikacja musi ZAWSZE jawnie nazwać siłę gwarancji — mocną przy
    /// dekodowaniu ffmpegiem, słabą przy kontroli strukturalnej. Bez tego log
    /// operacyjny wprowadzałby w błąd co do jakości dowodu.
    #[test]
    fn test_weryfikacja_nazywa_sile_gwarancji() {
        let dir = tempfile::tempdir().unwrap();

        // Spójny strukturalnie kontener, ale bez realnej treści wideo.
        let plik = dir.path().join("struktura.mp4");
        std::fs::write(&plik, budowa_spojnego_mp4()).unwrap();

        match weryfikuj_wideo(&plik) {
            Ok(dowod) => assert!(
                dowod.contains("MOCNA") || dowod.contains("SŁABA"),
                "dowód musi nazwać siłę gwarancji, dostałem: {}", dowod
            ),
            Err(powod) => assert!(!powod.is_empty(), "odrzucenie musi mieć powód"),
        }
    }

    /// Minimalny, strukturalnie spójny kontener: ftyp + mdat + moov ze
    /// stco wskazującym wewnątrz pliku.
    fn budowa_spojnego_mp4() -> Vec<u8> {
        fn box_(typ: &[u8; 4], tresc: &[u8]) -> Vec<u8> {
            crate::test_fixtures::box_isobmff(typ, tresc)
        }

        let mut stco = vec![0u8; 4];
        stco.extend_from_slice(&1u32.to_be_bytes());
        stco.extend_from_slice(&48u32.to_be_bytes());

        let moov = box_(b"moov", &box_(b"trak", &box_(b"stbl", &box_(b"stco", &stco))));

        let mut plik = box_(b"ftyp", b"isom\x00\x00\x02\x00");
        plik.extend(box_(b"mdat", &vec![0xAAu8; 2048]));
        plik.extend(moov);
        plik
    }

    #[test]
    #[ignore = "Wymaga ffmpeg. Uruchom z --ignored."]
    fn test_e2e_weryfikacja_daje_mocna_gwarancje_z_ffmpeg() {
        if !ffmpeg_dostepny() { panic!("brak ffmpeg"); }
        let dir = tempfile::tempdir().unwrap();
        let plik = wygeneruj_mp4(dir.path(), "prawdziwe.mp4");

        let dowod = weryfikuj_wideo(&plik).expect("prawdziwe wideo musi przejść");
        assert!(dowod.contains("MOCNA"), "z ffmpeg gwarancja musi być mocna: {}", dowod);
        assert!(dowod.contains("dekodowanie"), "dowód musi nazwać metodę: {}", dowod);
    }

    /// Dowód, że rozszerzenie listy nie jest samą deklaracją: prawdziwy plik
    /// `.3gp` z ffmpeg, pozbawiony atomu `moov`, zostaje odzyskany przez
    /// przeszczep z bliźniaczej kopii i przechodzi PEŁNE dekodowanie klatek.
    ///
    /// Przed rozszerzeniem `ROZSZERZENIA_MP4` moduł w ogóle nie zgłaszał się do
    /// tego pliku, mimo że weryfikacja już go obejmowała.
    ///
    /// REGRESJA NA WADĘ SILNIKA. Ten fixture ma DWIE ścieżki (H.263 + AAC) i
    /// właśnie on obnażył błąd w `engine_clone`: delta przesunięcia tablic
    /// `stco` była liczona z pierwszego wpisu pierwszej tablicy, przy założeniu
    /// że ten kawałek leży na początku danych `mdat`. Tu leży na offsecie 615,
    /// a dane zaczynają się na 44 — silnik mylił się o 571 bajtów na OBU
    /// ścieżkach. Materiał jednościeżkowy tej wady nie pokazywał, więc
    /// dotychczasowe testy jej nie widziały, mimo że dotyczyła praktycznie
    /// każdego nagrania z kamery (obraz + dźwięk).
    #[test]
    #[ignore = "Wymaga image/test_fixture.3gp oraz ffmpeg/ffprobe. Uruchom z --ignored."]
    fn test_e2e_clone_odzyskuje_prawdziwy_3gp() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = katalog_wynikow(dir.path());

        let dawca = dir.path().join("dawca.3gp");
        std::fs::copy("image/test_fixture.3gp", &dawca).expect("fixture musi istnieć");

        let zepsuty = dir.path().join("zepsuty.3gp");
        usun_moov(&dawca, &zepsuty);

        let kontekst = ctx("3gp", Some(false), None, None);

        // Kontrola sensu testu: bez `moov` plik NIE MOŻE przechodzić weryfikacji.
        assert!(
            Mp4CloneModule.verify(&zepsuty, &kontekst).is_err(),
            "Test bez sensu: plik pozbawiony moov musi być odrzucany"
        );

        let (plik, log) = Mp4CloneModule
            .repair(&zepsuty, &kontekst, Some(&dawca), &wynik)
            .expect("przeszczep moov musi się udać dla identycznego materiału .3gp");

        assert!(log.contains("moov"), "log powinien nazwać wykonaną operację: {}", log);
        assert_eq!(
            plik.extension().and_then(|e| e.to_str()), Some("3gp"),
            "Wynik musi zachować rozszerzenie wejścia, inaczej weryfikacja dobierze złą metodę"
        );
        assert!(
            Mp4CloneModule.verify(&plik, &kontekst).is_ok(),
            "Naprawiony .3gp musi przejść pełne dekodowanie klatek"
        );
    }

    /// To samo dla `.f4v` — trzeci z dołożonych formatów.
    #[test]
    #[ignore = "Wymaga image/test_fixture.f4v oraz ffmpeg/ffprobe. Uruchom z --ignored."]
    fn test_e2e_clone_odzyskuje_prawdziwy_f4v() {
        let dir = tempfile::tempdir().unwrap();
        let wynik = katalog_wynikow(dir.path());

        let dawca = dir.path().join("dawca.f4v");
        std::fs::copy("image/test_fixture.f4v", &dawca).expect("fixture musi istnieć");
        let zepsuty = dir.path().join("zepsuty.f4v");
        usun_moov(&dawca, &zepsuty);

        let kontekst = ctx("f4v", Some(false), None, None);
        let (plik, _log) = Mp4CloneModule
            .repair(&zepsuty, &kontekst, Some(&dawca), &wynik)
            .expect("przeszczep moov musi się udać dla .f4v");

        assert!(Mp4CloneModule.verify(&plik, &kontekst).is_ok());
    }
}
