// src/phases/repair_modules/mod.rs

//! # Rejestr Modułów Naprawczych (Faza 17)
//!
//! Każda metoda naprawcza (wstrzykiwanie nagłówka, sanityzacja tekstu, itd.)
//! jest osobnym plikiem implementującym [`RepairModule`]. Orkiestrator
//! (`phase17_repair::run`) nie zna szczegółów żadnej konkretnej naprawy —
//! zna tylko ten trait, buduje [`RepairContext`] per plik z diagnostyki
//! zebranej w poprzednich fazach, i próbuje kolejne moduły z [`all_modules`]
//! W KOLEJNOŚCI PRIORYTETU (kolejność w tym Vec = kolejność prób), aż jeden
//! zwróci sukces.
//!
//! DODANIE NOWEGO MODUŁU: (1) nowy plik w tym katalogu implementujący
//! [`RepairModule`], (2) jedna linia w [`all_modules`]. Zero zmian w
//! orkiestratorze — to jest cały sens tej architektury.
//!
//! KAŻDY wynik naprawy przechodzi OBOWIĄZKOWĄ weryfikację — patrz
//! [`RepairModule::verify`] i [`weryfikuj_naprawiony_plik`]. Nowy moduł
//! dostaje ją domyślnie, bez żadnego dodatkowego kodu; nadpisuje tę metodę
//! tylko wtedy, gdy potrafi udowodnić coś, czego nie widać po formacie pliku.
//!
//! Moduły NIE zarządzają liczeniem statystyk live samodzielnie — orkiestrator
//! generycznie zlicza sukcesy per `id()` modułu do wspólnej mapy, więc nowy
//! moduł automatycznie dostaje własny licznik w panelu bocznym bez żadnego
//! dodatkowego kodu w samym module.

mod extension;
mod header_jpg;
mod header_png;
mod header_raster;
mod archive;
mod dng;
mod heic;
mod jpeg;
mod mkv;
mod mp4;
mod png;
mod splice;
mod stream;
mod sqlite;
mod text;
mod trailer_trim;

use std::path::{Path, PathBuf};

// ============================================================================
// OBOWIĄZKOWA WERYFIKACJA WYNIKU NAPRAWY
// ============================================================================

/// Górny limit rozmiaru pliku poddawanego weryfikacji wymagającej wczytania
/// całości do RAM (dekodowanie obrazu, odczyt archiwum). Powyżej tego progu
/// weryfikacja zwraca wynik SŁABY, zamiast ryzykować OOM — Faza 17 przetwarza
/// pliki równolegle na puli Rayon, więc szczyt zużycia to wielokrotność tej
/// wartości.
const LIMIT_WERYFIKACJI_W_RAM: u64 = 512 * 1024 * 1024; // 512 MB

/// Wynik obowiązkowej weryfikacji naprawionego pliku.
///
/// `Ok(dowod)` — wynik PRZYJĘTY, a `dowod` mówi, czym dokładnie został
/// potwierdzony. Tekst trafia do logu operacyjnego, żeby dało się odróżnić
/// gwarancję MOCNĄ (realne dekodowanie pikseli, suma kontrolna CRC32,
/// `quick_check` bazy) od SŁABEJ (sama struktura nagłówków albo brak metody
/// weryfikacji dla danego formatu). Ta różnica jest w tym projekcie istotna i
/// konsekwentnie odnotowywana — patrz dokumentacja `tar_archive` i `dng_splice`.
///
/// `Err(powod)` — wynik ODRZUCONY. Orkiestrator usuwa wtedy plik i próbuje
/// kolejnego pasującego modułu.
pub type WynikWeryfikacji = std::result::Result<&'static str, String>;

/// Wczytuje plik do weryfikacji, pilnując limitu pamięci.
fn wczytaj_do_weryfikacji(sciezka: &Path, rozmiar: u64) -> std::result::Result<Vec<u8>, WynikWeryfikacji> {
    if rozmiar > LIMIT_WERYFIKACJI_W_RAM {
        return Err(Ok("plik przekracza limit weryfikacji w RAM - sprawdzono tylko, że jest niepusty (gwarancja SŁABA)"));
    }
    match std::fs::read(sciezka) {
        Ok(bajty) => Ok(bajty),
        Err(e) => Err(Err(format!("nie udało się odczytać naprawionego pliku: {}", e))),
    }
}

/// Weryfikuje naprawiony plik metodą właściwą dla JEGO rozszerzenia.
///
/// ## Dlaczego to istnieje
///
/// Faza 18 od początku miała obowiązkową weryfikację kandydata przed zapisem
/// (realne dekodowanie / CRC32) i właśnie dlatego wolno jej było działać
/// automatycznie. Faza 17 nie miała ŻADNEJ — moduł zwracał `Some`, plik
/// wędrował do bazy jako „naprawiony", a Faza 9 kopiowała go do Złotej Kopii,
/// JAWNIE pomijając przy tym kontrolę rozmiaru dla plików naprawionych (patrz
/// `phase9::copy_file_and_meta`). Nic w całym łańcuchu nie sprawdzało, czy
/// naprawa cokolwiek naprawiła.
///
/// Weryfikacja opiera się WYŁĄCZNIE na modułach już przetestowanych
/// empirycznie (`zip_splice`, `tar_archive`, `raw_image`, `heic_image`, crate
/// `image`, `rusqlite`) — tu nie powstaje żadna nowa logika parsowania.
pub fn weryfikuj_naprawiony_plik(sciezka: &Path) -> WynikWeryfikacji {
    let rozmiar = match std::fs::metadata(sciezka) {
        Ok(m) => m.len(),
        Err(e) => return Err(format!("naprawiony plik nie istnieje lub jest nieczytelny: {}", e)),
    };

    if rozmiar == 0 {
        return Err("naprawiony plik jest PUSTY (0 bajtów)".to_string());
    }

    let ext = sciezka.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let nazwa = sciezka.to_string_lossy();

    // --- Bazy SQLite: pełna kontrola integralności stron ---
    if matches!(ext.as_str(), "db" | "sqlite" | "sqlite3") {
        return weryfikuj_sqlite(sciezka);
    }

    // --- Archiwa ZIP-podobne: odczyt KAŻDEGO wpisu z kontrolą CRC32 ---
    if crate::zip_splice::is_zip_based_extension(&format!(".{}", ext)) {
        let bajty = match wczytaj_do_weryfikacji(sciezka, rozmiar) { Ok(b) => b, Err(w) => return w };
        return if crate::zip_splice::verify_zip_bytes(&bajty) {
            Ok("odczyt każdego wpisu archiwum z kontrolą CRC32 (gwarancja MOCNA)")
        } else {
            Err("archiwum nie przechodzi odczytu wpisów / kontroli CRC32".to_string())
        };
    }

    // --- HEIC/HEIF/AVIF: REALNE DEKODOWANIE PIKSELI ---
    //
    // Wcześniej stało tu samo `decode_heic_bytes`, opisane jako „odczyt
    // struktury kontenera HEIF (gwarancja MOCNA)". To zdanie przeczyło samo
    // sobie: `heic_image::extract_info` czyta wyłącznie UCHWYT obrazu
    // (wymiary, alfa, bity na piksel) i nie dekoduje ani jednego piksela.
    // Odbudowany przez `heic_native` kafel mógł więc otworzyć kontener,
    // podać sensowne wymiary z rozsypanym strumieniem HEVC i dostać stempel
    // gwarancji MOCNEJ — czyli dowodu treści tam, gdzie był tylko dowód
    // struktury. W narzędziu dowodowym etykieta gwarancji jest całą stawką.
    if crate::heic_image::is_heic_extension(&nazwa) {
        use crate::heic_image::WeryfikacjaHeic;
        let bajty = match wczytaj_do_weryfikacji(sciezka, rozmiar) { Ok(b) => b, Err(w) => return w };
        return match crate::heic_image::verify_heic_pixels(&bajty) {
            WeryfikacjaHeic::PikseleZdekodowane => {
                Ok("pełne dekodowanie pikseli przez libheif (gwarancja MOCNA)")
            }
            // Brak pluginu kodeka w systemie to wada ŚRODOWISKA, nie pliku.
            // Odrzucenie skasowałoby poprawnie naprawione zdjęcie przez
            // `sprzataj`, więc schodzimy do dowodu strukturalnego i mówimy
            // o tym wprost.
            WeryfikacjaHeic::TylkoStruktura => {
                Ok("brak pluginu kodeka - sprawdzono tylko strukturę kontenera HEIF (gwarancja SŁABA)")
            }
            WeryfikacjaHeic::Odrzucony => {
                Err("plik nie daje się zdekodować jako HEIC/HEIF/AVIF".to_string())
            }
        };
    }

    // --- Strumienie TS i FLV: kontrola RAMOWANIA ---
    //
    // Bez tych gałęzi pliki `.ts`/`.m2ts`/`.mts`/`.flv` wpadały do wariantu
    // domyślnego („brak metody weryfikacji"), więc bajtowe zszycie przez
    // `splice` przechodziło bez oporu. Oba formaty mają czym się bronić, ale
    // wyłącznie na poziomie ramowania - patrz `repair_modules::stream`.
    if crate::ts_stream::is_ts_extension(&nazwa) {
        let bajty = match wczytaj_do_weryfikacji(sciezka, rozmiar) { Ok(b) => b, Err(w) => return w };
        return match crate::ts_stream::analyze_ts(&bajty) {
            Some(a) if a.is_healthy() => Ok("ciągłość pakietów TS bez luk i bez flag błędu transportu (gwarancja SŁABA - dowód ramowania, nie treści)"),
            Some(a) => Err(format!("strumień TS nadal uszkodzony: {}", a.describe())),
            None => Err("plik nie jest rozpoznawalnym strumieniem transportowym".to_string()),
        };
    }

    if crate::flv_stream::is_flv_extension(&nazwa) {
        let bajty = match wczytaj_do_weryfikacji(sciezka, rozmiar) { Ok(b) => b, Err(w) => return w };
        return match crate::flv_stream::analyze_flv(&bajty) {
            Some(a) if a.is_healthy() => Ok("domknięty łańcuch tagów FLV (gwarancja SŁABA - dowód ramowania, nie treści)"),
            Some(a) => Err(format!("kontener FLV nadal uszkodzony: {}", a.describe())),
            None => Err("plik nie jest rozpoznawalnym kontenerem FLV".to_string()),
        };
    }

    // --- Matroska: struktura kontenera + sumy CRC-32 elementów ---
    //
    // Bez tej gałęzi pliki `.mkv`/`.webm`/`.mka` wpadały do gałęzi domyślnej
    // („brak metody weryfikacji"), czyli wystarczyło, że wynik jest niepusty —
    // a więc bajtowe zszycie przez `splice` przechodziło. Matroska ma czym się
    // bronić: strukturę czyta `mkv_container`, a elementy nadrzędne niosą
    // opcjonalne sumy `CRC-32`.
    if crate::mkv_container::is_mkv_extension(&nazwa) {
        let bajty = match wczytaj_do_weryfikacji(sciezka, rozmiar) { Ok(b) => b, Err(w) => return w };

        if crate::mkv_container::read_mkv_bytes(&bajty).is_err() {
            return Err("plik nie daje się odczytać jako Matroska (uszkodzona struktura lub ucięcie)".to_string());
        }

        return match crate::mkv_container::wszystkie_crc_zgodne(&bajty) {
            Some(true) => Ok("odczyt struktury Matroski z kontrolą CRC-32 elementów nadrzędnych (gwarancja MOCNA)"),
            Some(false) => Err("struktura Matroski czytelna, ale suma CRC-32 któregoś elementu się nie zgadza".to_string()),
            // Muxer nie zapisał sum - zostaje sama struktura, i tak trzeba to
            // powiedzieć wprost zamiast zawyżać gwarancję.
            None => Ok("odczyt struktury Matroski (gwarancja SŁABA - kontener nie zawiera sum CRC-32)"),
        };
    }

    // --- Kontenery ISOBMFF Z OBRAZEM: pełne dekodowanie klatek ---
    //
    // Bez tej gałęzi pliki `.mp4`/`.mov`/`.m4v` wpadały do gałęzi domyślnej
    // („brak metody weryfikacji"), czyli wystarczyło, że wynik jest niepusty i
    // nie składa się z samych zer. Bajtowe zszycie dwóch kontenerów przez
    // `splice` spełnia te warunki, nie będąc poprawnym wideo — i przechodziło.
    //
    // `.3gp`, `.3g2` i `.f4v` to ten sam kontener ISOBMFF i też noszą ścieżkę
    // obrazu, więc obejmuje je ten sam, najmocniejszy dowód. Sprawdzone
    // empirycznie na plikach z ffmpeg: dla obu zapytanie o strumień `v:0`
    // zwraca wymiary, więc ffmpeg-owy sędzia ich nie odrzuci.
    //
    // `.mj2` (Motion JPEG 2000) NIE jest tu wpisany świadomie: ffmpeg 7.1 nie
    // ma muxera `mj2`, więc nie dało się zbudować materiału dowodowego, a
    // fałszywe odrzucenie kosztuje usunięcie naprawionego pliku (`sprzataj`).
    // Zostaje w gałęzi domyślnej ze SŁABĄ gwarancją, aż będzie czym to
    // potwierdzić.
    if matches!(ext.as_str(), "mp4" | "mov" | "m4v" | "3gp" | "3g2" | "f4v") {
        // Ta sama weryfikacja, jakiej używają moduły MP4 — z automatycznym
        // zejściem do kontroli strukturalnej, gdy w systemie nie ma `ffmpeg`.
        return mp4::weryfikuj_wideo(sciezka);
    }

    // --- Kontenery ISOBMFF BEZ OBRAZU (audio): kontrola strukturalna ---
    //
    // `.m4a`/`.m4b` to ten sam kontener co MP4, tylko bez ścieżki obrazu.
    // NIE WOLNO ich puszczać przez `weryfikuj_wideo`: jego TEST 2
    // (`validator::is_healthy_video`) wymaga od ffprobe strumienia `v:0` z
    // szerokością i wysokością. Sprawdzone empirycznie na pliku z ffmpeg: dla
    // `.m4a` to zapytanie zwraca pusty wynik, więc POPRAWNIE naprawiony plik
    // audio zostałby uznany za zepsuty i USUNIĘTY przez `sprzataj`.
    //
    // Zostaje więc dowód strukturalny: kontener daje się sparsować i ma co
    // najmniej jedną ścieżkę. Słabszy niż dekodowanie klatek, ale uczciwie
    // zameldowany — i mocniejszy niż gałąź domyślna, która przepuszczała
    // ślepe zszycie.
    if matches!(ext.as_str(), "m4a" | "m4b") {
        let bajty = match wczytaj_do_weryfikacji(sciezka, rozmiar) { Ok(b) => b, Err(w) => return w };
        return if crate::video_image::verify_video_bytes(&bajty) {
            Ok("odczyt struktury ISOBMFF z co najmniej jedną ścieżką (gwarancja SŁABA - dowód struktury kontenera, nie treści próbek)")
        } else {
            Err("plik nie daje się odczytać jako kontener ISOBMFF albo nie ma ani jednej ścieżki".to_string())
        };
    }

    match ext.as_str() {
        // Obrazy rastrowe: realne dekodowanie pikseli - najmocniejszy dostępny
        // dowód, ten sam co `verify_image_bytes` w Fazie 18.
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tif" | "tiff" | "webp" => {
            let bajty = match wczytaj_do_weryfikacji(sciezka, rozmiar) { Ok(b) => b, Err(w) => return w };
            match image::load_from_memory(&bajty) {
                Ok(img) if img.width() > 0 && img.height() > 0 => Ok("realne dekodowanie pikseli (gwarancja MOCNA)"),
                Ok(_) => Err("obraz zdekodowany, ale ma zerowe wymiary".to_string()),
                Err(e) => Err(format!("obraz nie daje się zdekodować: {}", e)),
            }
        }

        // Formaty RAW - dekodowanie przez rawloader (panic-safe).
        "dng" | "nef" | "cr2" | "cr3" | "arw" | "orf" | "rw2" | "raf" | "srw" | "pef" => {
            let bajty = match wczytaj_do_weryfikacji(sciezka, rozmiar) { Ok(b) => b, Err(w) => return w };
            if crate::raw_image::verify_raw_bytes(&bajty) {
                Ok("dekodowanie RAW przez rawloader (gwarancja MOCNA)")
            } else {
                Err("plik nie daje się zdekodować jako RAW".to_string())
            }
        }

        // Tar: suma kontrolna chroni TYLKO nagłówki, nie dane wpisów.
        "tar" => {
            let bajty = match wczytaj_do_weryfikacji(sciezka, rozmiar) { Ok(b) => b, Err(w) => return w };
            if crate::tar_archive::verify_tar_bytes(&bajty) {
                Ok("sumy kontrolne nagłówków wpisów tar (gwarancja SŁABA - tar nie chroni danych)")
            } else {
                Err("archiwum tar ma uszkodzone nagłówki lub ucięte wpisy".to_string())
            }
        }

        // Tekst: dokładnie to, co moduł `text` obiecuje naprawić.
        "txt" | "py" | "csv" | "json" | "xml" | "md" | "log" => {
            let bajty = match wczytaj_do_weryfikacji(sciezka, rozmiar) { Ok(b) => b, Err(w) => return w };
            if bajty.contains(&0x00) {
                return Err("plik tekstowy nadal zawiera bajty NULL".to_string());
            }
            match std::str::from_utf8(&bajty) {
                Ok(_) => Ok("poprawny UTF-8 bez bajtów NULL (gwarancja MOCNA dla tekstu)"),
                Err(e) => Err(format!("plik tekstowy nie jest poprawnym UTF-8: {}", e)),
            }
        }

        // PDF: bez pełnego parsera weryfikujemy tylko obramowanie pliku.
        "pdf" => {
            let bajty = match wczytaj_do_weryfikacji(sciezka, rozmiar) { Ok(b) => b, Err(w) => return w };
            if !bajty.starts_with(b"%PDF-") {
                return Err("brak nagłówka %PDF- na początku pliku".to_string());
            }
            // Znacznik końca szukany w ogonie - w poprawnym PDF jest blisko końca.
            let ogon_od = bajty.len().saturating_sub(2048);
            if !bajty[ogon_od..].windows(5).any(|w| w == b"%%EOF") {
                return Err("brak znacznika %%EOF w końcówce pliku".to_string());
            }
            Ok("nagłówek %PDF- i znacznik %%EOF na miejscu (gwarancja SŁABA - bez parsowania obiektów)")
        }

        // Brak metody dla formatu: NIE udajemy dowodu. Sprawdzamy tylko, że
        // wynik nie jest oczywistym śmieciem, i jawnie meldujemy słabość
        // gwarancji, żeby log operacyjny nie wprowadzał w błąd.
        _ => {
            let bajty = match wczytaj_do_weryfikacji(sciezka, rozmiar) { Ok(b) => b, Err(w) => return w };
            if bajty.iter().all(|&b| b == 0) {
                return Err("naprawiony plik zawiera wyłącznie bajty zerowe".to_string());
            }
            Ok("brak metody weryfikacji dla tego formatu - sprawdzono niepustość i brak samych zer (gwarancja SŁABA)")
        }
    }
}

/// Buduje nazwę pliku towarzyszącego bazie (`-wal`, `-shm`). SQLite DOKLEJA
/// sufiks do pełnej nazwy (`baza.db-wal`), więc nie wolno tu użyć
/// `with_extension`, które podmieniłoby rozszerzenie na `db-wal`.
fn plik_towarzyszacy(sciezka: &Path, sufiks: &str) -> PathBuf {
    let mut nazwa = sciezka.as_os_str().to_os_string();
    nazwa.push(sufiks);
    PathBuf::from(nazwa)
}

/// Weryfikuje bazę SQLite przez `PRAGMA quick_check` — realna kontrola
/// integralności stron i indeksów, nie samo otwarcie pliku.
///
/// ## Weryfikacja nie może zostawiać śladów w materiale dowodowym
///
/// Bazę otwieramy TYLKO DO ODCZYTU, żeby nie zmodyfikować samego pliku. To
/// jednak nie wystarcza: dla bazy w trybie WAL SQLite potrzebuje pamięci
/// współdzielonej i tworzy obok pliki `-wal` oraz `-shm` — sprawdzone
/// empirycznie, tryb read-only tego NIE blokuje. Dlatego zapamiętujemy, które
/// pliki towarzyszące istniały przed weryfikacją, i usuwamy WYŁĄCZNIE te,
/// które powstały przez nas. Plików, które były tam wcześniej, nie ruszamy.
fn weryfikuj_sqlite(sciezka: &Path) -> WynikWeryfikacji {
    use rusqlite::OpenFlags;

    let wal = plik_towarzyszacy(sciezka, "-wal");
    let shm = plik_towarzyszacy(sciezka, "-shm");
    let wal_istnial = wal.exists();
    let shm_istnial = shm.exists();

    // Połączenie w osobnym zakresie — musi zostać zamknięte PRZED sprzątaniem.
    let wynik = {
        let conn = match rusqlite::Connection::open_with_flags(sciezka, OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(c) => c,
            // Fallback na zwykłe otwarcie: lepiej zweryfikować sprawną bazę,
            // niż odrzucić ją z powodu trybu otwarcia.
            Err(_) => match rusqlite::Connection::open(sciezka) {
                Ok(c) => c,
                Err(e) => return Err(format!("nie udało się otworzyć bazy: {}", e)),
            },
        };

        let odpowiedz: std::result::Result<String, _> =
            conn.query_row("PRAGMA quick_check", [], |row| row.get(0));

        match odpowiedz {
            Ok(s) if s == "ok" => Ok("PRAGMA quick_check bazy SQLite (gwarancja MOCNA)"),
            Ok(s) => Err(format!("quick_check bazy zgłosił problem: {}", s)),
            Err(e) => Err(format!("nie udało się wykonać quick_check: {}", e)),
        }
    };

    if !wal_istnial { let _ = std::fs::remove_file(&wal); }
    if !shm_istnial { let _ = std::fs::remove_file(&shm); }

    wynik
}

/// Migawka diagnostyki jednego pliku (po JEDNEJ stronie — UFS albo Skrypt),
/// zebranej z wcześniejszych faz, wystarczająca do podjęcia decyzji przez
/// [`RepairModule::applies_to`]. Budowana raz per zadanie w orkiestratorze —
/// żaden moduł nie dotyka bazy danych bezpośrednio.
pub struct RepairContext<'a> {
    /// Rozszerzenie pliku, już znormalizowane do małych liter, bez kropki.
    pub ext: &'a str,
    /// Powód anomalii z Fazy 12 (`media_reason_ufs`/`_script`), np. zawiera
    /// `"Fałszywe"` lub `"Nagłówek"`.
    pub media_reason: Option<&'a str>,
    /// Wynik walidacji UTF-8 z Fazy 10 (`utf8_ok_ufs`/`_script`).
    pub utf8_ok: Option<bool>,
    /// Flaga one-linera z Fazy 10 (`is_oneliner_ufs`/`_script`).
    pub is_oneliner: Option<bool>,
    /// Wynik walidacji EOF z Fazy 6 (`eof_ok_ufs`/`_script`) — `Some(false)`
    /// oznacza brakujący/uszkodzony znacznik końca pliku LUB doklejone
    /// śmieci binarne po nim.
    pub eof_ok: Option<bool>,
    /// Typ dopasowania z korelacji Fazy 14 (`phase14_analysis.match_type`),
    /// np. `"PARTIAL"` — używane przez moduł zszywania.
    pub match_type: Option<&'a str>,
    /// Wynik diagnostyki kontenera wideo z Fazy 19 (`video_ok_ufs`/`_script`).
    ///
    /// `Some(false)` = kontener uszkodzony (ucięty `moov`, zła struktura) —
    /// to GŁÓWNY sygnał dla modułów naprawy MP4. Bez tego pola musiałyby
    /// opierać się na samym rozszerzeniu i albo próbowałyby naprawiać zdrowe
    /// pliki, albo — przy zbyt ostrym warunku — nie uruchamiałyby się nigdy
    /// (dokładnie ta pułapka, w którą wpadła naprawa rozszerzeń).
    pub video_ok: Option<bool>,
    /// Wynik walidacji struktury archiwum z Fazy 11 (`structure_ok_ufs`/`_script`).
    ///
    /// `Some(false)` = archiwum nie daje się otworzyć albo ma uszkodzone wpisy.
    /// To GŁÓWNY sygnał dla modułów naprawy ZIP i TAR — dokładnie ta sama rola,
    /// jaką `video_ok` pełni dla MP4. Bez niego moduły archiwów musiałyby
    /// kwalifikować po samym rozszerzeniu i albo ruszałyby zdrowe pliki, albo
    /// nie uruchamiały się nigdy.
    pub structure_ok: Option<bool>,
}

/// Wspólny interfejs dla wszystkich modułów naprawczych. Implementacje
/// znajdują się w osobnych plikach tego katalogu.
pub trait RepairModule: Send + Sync {
    /// Stabilny identyfikator używany jako klucz liczników live, w logu
    /// operacyjnym i w menu wyboru modułów. Nie zmieniać wstecznie.
    fn id(&self) -> &'static str;

    /// Nazwa czytelna dla człowieka — pokazywana w menu wyboru (`MultiSelect`)
    /// i w Dzienniku Końcowym.
    fn display_name(&self) -> &'static str;

    /// Rozstrzyga, czy TEN moduł powinien w ogóle próbować naprawić plik
    /// o podanej diagnostyce. Czysta decyzja — brak dostępu do dysku.
    fn applies_to(&self, ctx: &RepairContext) -> bool;

    /// Wykonuje fizyczną naprawę: tworzy NOWY plik (z sufiksem
    /// `_repaired`/`_spliced`) W KATALOGU `katalog_wyjsciowy`, zwraca jego
    /// ścieżkę i opis operacji do logu.
    ///
    /// ## `katalog_wyjsciowy` — dlaczego to parametr
    ///
    /// Moduły wyliczały wcześniej miejsce zapisu jako `source.parent()`, czyli
    /// pisały OBOK oryginału — w środku analizowanego korpusu, który w tym
    /// projekcie jest materiałem dowodowym tylko do odczytu (patrz zasady
    /// katalogów: zapisywać wolno wyłącznie w `/praca/`). Dodatkowo pliki
    /// `*_repaired.*` leżące w korpusie były przy kolejnym mapowaniu struktury
    /// zliczane jako samodzielne pliki korpusu, bo nigdzie nie ma filtra na te
    /// sufiksy. Teraz miejsce zapisu wskazuje orkiestrator, a katalog jest już
    /// utworzony w momencie wywołania — moduł ma go tylko użyć.
    ///
    /// `ctx` to ta sama diagnostyka co w `applies_to` — moduły, którym nie
    /// wystarczy sama ścieżka pliku (np. korekta rozszerzenia potrzebuje
    /// prawdziwego MIME zaszytego w `media_reason`), czerpią z niej dalsze
    /// dane, zamiast nadużywać `twin` do niezwiązanego celu. `twin` jest
    /// obecne tylko gdy orkiestrator znalazł ścieżkę bliźniaczą (dziś:
    /// tylko moduł zszywania z niego korzysta). `None` oznacza porażkę
    /// fizyczną — orkiestrator przechodzi wtedy do KOLEJNEGO pasującego
    /// modułu, nie zatrzymuje się.
    fn repair(
        &self,
        source: &Path,
        ctx: &RepairContext,
        twin: Option<&Path>,
        katalog_wyjsciowy: &Path,
    ) -> Option<(PathBuf, String)>;

    /// OBOWIĄZKOWA weryfikacja wyniku, wołana przez orkiestrator ZAWSZE po
    /// udanym [`RepairModule::repair`] i ZAWSZE przed zapisaniem czegokolwiek
    /// do bazy danych.
    ///
    /// Implementacja domyślna weryfikuje plik metodą właściwą dla jego
    /// rozszerzenia ([`weryfikuj_naprawiony_plik`]) i dla wszystkich obecnych
    /// modułów jest wystarczająca — każdy z nich produkuje plik, którego
    /// format wynika z rozszerzenia, także moduł korekty rozszerzenia (tam
    /// sprawdzenie formatu JEST dowodem, że korekta była trafna).
    ///
    /// Moduł nadpisuje tę metodę tylko wtedy, gdy potrafi udowodnić coś, czego
    /// nie widać po samym formacie pliku. Orkiestrator nie zna i nie musi znać
    /// żadnego formatu — tak jak przy `applies_to`/`repair`.
    ///
    /// Zwrócenie `Err` oznacza, że naprawa jest NIEUDANA: orkiestrator usuwa
    /// wytworzony plik i przechodzi do kolejnego pasującego modułu.
    fn verify(&self, repaired: &Path, _ctx: &RepairContext) -> WynikWeryfikacji {
        weryfikuj_naprawiony_plik(repaired)
    }
}

/// Rejestr wszystkich dostępnych modułów naprawczych, W KOLEJNOŚCI
/// PRIORYTETU prób (pierwszy pasujący i skuteczny wygrywa). Kolejność
/// zachowuje dotychczasowe zachowanie sprzed modularyzacji (Zszywanie →
/// SQLite → Tekst → Nagłówki → Rozszerzenie), z dwoma nowymi modułami
/// (Przycinanie Śmieci, Nagłówek PNG) wstawionymi w miejscach, gdzie ich
/// zastosowanie jest najmniej inwazyjne względem sąsiadów.
pub fn all_modules() -> Vec<Box<dyn RepairModule>> {
    vec![
        // Silniki MP4 stoją PRZED zszywaniem świadomie. `splice` stosuje się do
        // DOWOLNEGO rozszerzenia, gdy Faza 14 dała `match_type = PARTIAL`, więc
        // dla uszkodzonego MP4 trafiłby pierwszy i wyprodukował bajtowe
        // złożenie dwóch kontenerów — coś, co nie jest poprawnym MP4, ale bywa
        // niepuste. Właściwa naprawa kontenera ma pierwszeństwo.
        // HEIC/HEIF/AVIF — przeszczep indeksu `meta`. Stoi obok silników MP4,
        // bo to ten sam kontener ISOBMFF i ta sama strategia; przed `splice`,
        // żeby bajtowe zszycie nie wyprzedziło naprawy świadomej struktury.
        Box::new(heic::HeicCloneModule),
        // Zero-Donor dla HEIC: ostatnia szansa, gdy bliźniaka nie ma.
        Box::new(heic::HeicNativeModule),
        // JPEG — przeszczep prawdziwych tablic DQT/DHT/SOF od bliźniaka.
        // Przed `splice` (bajtowe zszycie nie zna struktury) i przed
        // `header_jpg` (który potrafi tylko wstrzyknąć sztuczny nagłówek).
        Box::new(jpeg::JpegCloneModule),
        // PNG — naprawa po fragmentach, od najpełniejszej do najsłabszej.
        // Oba przed `splice` i przed `header_png`; uzasadnienie kolejności w
        // dokumentacji `repair_modules::png`.
        Box::new(png::PngCloneModule),
        Box::new(png::PngSanitizeModule),
        // DNG — składanie strukturalne (gwarancja SŁABA, patrz dokumentacja
        // modułu). Przed `splice`, bo bajtowe zszycie nie zna TIFF/IFD.
        Box::new(dng::DngStructuralModule),
        // Archiwa — składanie per wpis z dwóch kopii. Przed `splice`, bo
        // bajtowe zszycie nie zna struktury wpisów; uzasadnienie i różnica
        // siły gwarancji ZIP vs TAR w dokumentacji `repair_modules::archive`.
        Box::new(archive::ZipSpliceModule),
        Box::new(archive::TarSpliceModule),
        // Matroska — składanie po elementach `Segment` wg CRC-32, odpowiednik
        // `png_clone`. Przed `splice`, bo bajtowe zszycie nie zna EBML.
        Box::new(mkv::MkvCloneModule),
        // Strumienie TS i FLV — składanie po pakietach/tagach. Gwarancja SŁABA
        // (dowód ramowania, nie treści); szczegóły w `repair_modules::stream`.
        Box::new(stream::TsSpliceModule),
        Box::new(stream::FlvSpliceModule),
        Box::new(mp4::Mp4CloneModule),
        Box::new(mp4::Mp4NativeModule),
        Box::new(mp4::Mp4RecontainerModule),
        Box::new(splice::SpliceModule),
        Box::new(sqlite::SqliteModule),
        Box::new(trailer_trim::TrailerTrimModule),
        Box::new(text::TextModule),
        Box::new(header_jpg::HeaderJpgModule),
        Box::new(header_png::HeaderPngModule),
        // Pozostałe formaty rastrowe — GIF, BMP, TIFF, WEBP. Stoi po JPG i PNG,
        // bo tamte dwa mają węższe, lepiej dopasowane moduły dla swoich formatów.
        Box::new(header_raster::HeaderRasterModule),
        Box::new(extension::ExtensionModule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_modules_nonempty() {
        assert!(!all_modules().is_empty());
    }

    #[test]
    fn test_all_modules_have_unique_ids() {
        let modules = all_modules();
        let mut ids: Vec<&str> = modules.iter().map(|m| m.id()).collect();
        let original_len = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "Znaleziono zduplikowane id() modułów naprawczych");
    }

    #[test]
    fn test_all_modules_have_nonempty_display_names() {
        for module in all_modules() {
            assert!(!module.display_name().is_empty(), "Moduł {} ma pusty display_name", module.id());
        }
    }

    // ------------------------------------------------------------------
    // OBOWIĄZKOWA WERYFIKACJA WYNIKU (weryfikuj_naprawiony_plik)
    //
    // Sedno poprawki: Faza 17 nie miała ŻADNEJ weryfikacji, więc niesprawny
    // "naprawiony" plik trafiał do bazy i do Złotej Kopii. Testy niżej
    // sprawdzają, że każdy obsługiwany format ma realny dowód sprawności, a
    // wynik uszkodzony jest ODRZUCANY.
    // ------------------------------------------------------------------

    use tempfile::tempdir;

    fn zapisz(dir: &Path, nazwa: &str, dane: &[u8]) -> PathBuf {
        let p = dir.join(nazwa);
        std::fs::write(&p, dane).unwrap();
        p
    }

    /// Buduje prawdziwy, dekodowalny PNG.
    fn prawdziwy_png() -> Vec<u8> {
        let obraz = image::RgbImage::new(4, 4);
        let mut bajty = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(obraz)
            .write_to(&mut bajty, image::ImageFormat::Png)
            .unwrap();
        bajty.into_inner()
    }

    #[test]
    fn test_weryfikacja_odrzuca_plik_pusty() {
        let dir = tempdir().unwrap();
        let p = zapisz(dir.path(), "pusty.png", b"");
        let wynik = weryfikuj_naprawiony_plik(&p);
        assert!(wynik.is_err(), "Pusty plik nie może przejść weryfikacji");
        assert!(wynik.unwrap_err().contains("PUSTY"));
    }

    #[test]
    fn test_weryfikacja_odrzuca_plik_nieistniejacy() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("nie_ma_mnie.png");
        assert!(weryfikuj_naprawiony_plik(&p).is_err());
    }

    #[test]
    fn test_weryfikacja_przyjmuje_prawdziwy_png() {
        let dir = tempdir().unwrap();
        let p = zapisz(dir.path(), "ok.png", &prawdziwy_png());
        let wynik = weryfikuj_naprawiony_plik(&p);
        assert!(wynik.is_ok(), "Poprawny PNG musi przejść: {:?}", wynik);
        assert!(wynik.unwrap().contains("MOCNA"), "Dekodowanie pikseli to gwarancja mocna");
    }

    #[test]
    fn test_weryfikacja_odrzuca_uciety_png() {
        // Najważniejszy przypadek: nagłówek jest poprawny, więc sprawdzenie
        // magic bytes by to PRZEPUŚCIŁO. Dopiero realne dekodowanie wykrywa.
        let dir = tempdir().unwrap();
        let pelny = prawdziwy_png();
        let uciety = &pelny[..pelny.len() / 2];
        let p = zapisz(dir.path(), "uciety.png", uciety);

        assert_eq!(&uciety[1..4], b"PNG", "Test bez sensu: sygnatura musi zostać nietknięta");
        assert!(weryfikuj_naprawiony_plik(&p).is_err(), "Ucięty PNG musi zostać odrzucony");
    }

    #[test]
    fn test_weryfikacja_odrzuca_smieci_z_rozszerzeniem_obrazu() {
        let dir = tempdir().unwrap();
        let p = zapisz(dir.path(), "smieci.jpg", b"to zupelnie nie jest obraz jpeg");
        assert!(weryfikuj_naprawiony_plik(&p).is_err());
    }

    #[test]
    fn test_weryfikacja_tekstu_przyjmuje_czysty_utf8() {
        let dir = tempdir().unwrap();
        let p = zapisz(dir.path(), "ok.txt", "zażółć gęślą jaźń\nlinia druga\n".as_bytes());
        assert!(weryfikuj_naprawiony_plik(&p).is_ok());
    }

    #[test]
    fn test_weryfikacja_tekstu_odrzuca_pozostawione_null() {
        // Dokładnie to, co moduł `text` obiecuje usunąć - weryfikacja musi
        // wychwycić, gdyby tego nie zrobił.
        let dir = tempdir().unwrap();
        let p = zapisz(dir.path(), "zle.txt", b"tekst\x00z zerem");
        let wynik = weryfikuj_naprawiony_plik(&p);
        assert!(wynik.is_err());
        assert!(wynik.unwrap_err().contains("NULL"));
    }

    #[test]
    fn test_weryfikacja_tekstu_odrzuca_zly_utf8() {
        let dir = tempdir().unwrap();
        let p = zapisz(dir.path(), "zle.csv", &[0xFF, 0xFE, 0x41, 0x42]);
        assert!(weryfikuj_naprawiony_plik(&p).is_err());
    }

    #[test]
    fn test_weryfikacja_pdf_wymaga_naglowka_i_znacznika_konca() {
        let dir = tempdir().unwrap();

        let dobry = zapisz(dir.path(), "ok.pdf", b"%PDF-1.7\njakas tresc\n%%EOF\n");
        assert!(weryfikuj_naprawiony_plik(&dobry).is_ok());

        let bez_naglowka = zapisz(dir.path(), "bez_nag.pdf", b"tresc\n%%EOF\n");
        assert!(weryfikuj_naprawiony_plik(&bez_naglowka).is_err());

        let bez_konca = zapisz(dir.path(), "bez_konca.pdf", b"%PDF-1.7\njakas tresc\n");
        assert!(weryfikuj_naprawiony_plik(&bez_konca).is_err());
    }

    #[test]
    fn test_weryfikacja_sqlite_przyjmuje_zdrowa_baze() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("zdrowa.db");
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            conn.execute("CREATE TABLE t (a INTEGER)", []).unwrap();
            conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
        }
        let wynik = weryfikuj_naprawiony_plik(&p);
        assert!(wynik.is_ok(), "Zdrowa baza musi przejść quick_check: {:?}", wynik);
    }

    #[test]
    fn test_weryfikacja_sqlite_nie_zostawia_sladow_obok_bazy() {
        // Weryfikacja materiału dowodowego nie może tworzyć plików obok niego.
        // Baza w trybie WAL po checkpointie - dokładnie to, co produkuje moduł
        // naprawczy `sqlite`.
        let dir = tempdir().unwrap();
        let p = dir.path().join("wal.db");
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            conn.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
            conn.execute("CREATE TABLE t (a INTEGER)", []).unwrap();
            conn.execute("INSERT INTO t VALUES (42)", []).unwrap();
            // `execute_batch`, NIE `execute` - ten pragma zwraca wiersz, więc
            // `execute` kończy się `ExecuteReturnedResults`. Patrz naprawiony
            // bug w module `sqlite`.
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        }
        // Sprzątamy ślady po SETUPIE, żeby test mierzył tylko weryfikację.
        let _ = std::fs::remove_file(dir.path().join("wal.db-wal"));
        let _ = std::fs::remove_file(dir.path().join("wal.db-shm"));

        let wynik = weryfikuj_naprawiony_plik(&p);
        assert!(wynik.is_ok(), "Sprawna baza WAL musi przejść: {:?}", wynik);

        let pliki: Vec<String> = std::fs::read_dir(dir.path()).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(pliki, vec!["wal.db".to_string()], "Weryfikacja nie może zostawić plików towarzyszących, znalazłem: {:?}", pliki);
    }

    #[test]
    fn test_weryfikacja_zip_przyjmuje_zdrowe_i_odrzuca_uszkodzone() {
        use std::io::Write as _;
        let dir = tempdir().unwrap();

        // Zdrowe archiwum zbudowane w locie.
        let mut bufor = std::io::Cursor::new(Vec::new());
        {
            let mut zapis = zip::ZipWriter::new(&mut bufor);
            zapis.start_file::<_, ()>("plik.txt", zip::write::SimpleFileOptions::default()).unwrap();
            zapis.write_all(b"zawartosc wpisu").unwrap();
            zapis.finish().unwrap();
        }
        let zdrowe = bufor.into_inner();

        let p_ok = zapisz(dir.path(), "ok.zip", &zdrowe);
        let wynik = weryfikuj_naprawiony_plik(&p_ok);
        assert!(wynik.is_ok(), "Zdrowy ZIP musi przejść: {:?}", wynik);
        assert!(wynik.unwrap().contains("CRC32"));

        // Ucięte archiwum - brak EOCD.
        let p_zle = zapisz(dir.path(), "zle.zip", &zdrowe[..zdrowe.len() / 2]);
        assert!(weryfikuj_naprawiony_plik(&p_zle).is_err(), "Ucięty ZIP musi zostać odrzucony");
    }

    #[test]
    fn test_weryfikacja_sqlite_odrzuca_smieci() {
        let dir = tempdir().unwrap();
        // Poprawny nagłówek SQLite, ale dalej śmieci - samo otwarcie pliku
        // by to przepuściło, quick_check nie.
        let mut dane = b"SQLite format 3\x00".to_vec();
        dane.extend_from_slice(&[0xAB; 4096]);
        let p = zapisz(dir.path(), "zepsuta.db", &dane);

        assert!(weryfikuj_naprawiony_plik(&p).is_err(), "Uszkodzona baza musi zostać odrzucona");
    }

    #[test]
    fn test_weryfikacja_nieznanego_formatu_jest_jawnie_slaba() {
        let dir = tempdir().unwrap();
        let p = zapisz(dir.path(), "cos.xyz", b"dowolna niepusta tresc");
        let wynik = weryfikuj_naprawiony_plik(&p);
        assert!(wynik.is_ok(), "Nieznany format nie jest sam w sobie błędem");
        let dowod = wynik.unwrap();
        assert!(dowod.contains("SŁABA"), "Musi JAWNIE meldować słabą gwarancję, nie udawać dowodu: {}", dowod);
    }

    #[test]
    fn test_weryfikacja_odrzuca_plik_z_samych_zer() {
        let dir = tempdir().unwrap();
        let p = zapisz(dir.path(), "zera.xyz", &[0u8; 4096]);
        assert!(weryfikuj_naprawiony_plik(&p).is_err(), "Same zera to nie jest naprawiony plik");
    }

    #[test]
    fn test_domyslna_implementacja_verify_jest_wpieta_w_kazdy_modul() {
        // Każdy moduł z rejestru musi odrzucić oczywiście niesprawny wynik
        // przez domyślną implementację `verify` - dowód, że nowy moduł
        // dostaje weryfikację bez żadnego dodatkowego kodu.
        let dir = tempdir().unwrap();
        let p = zapisz(dir.path(), "smieci.png", b"to nie png");
        let ctx = RepairContext {
            ext: "png", media_reason: None, utf8_ok: None,
            is_oneliner: None, eof_ok: None, match_type: None, video_ok: None, structure_ok: None
        };

        for modul in all_modules() {
            assert!(
                modul.verify(&p, &ctx).is_err(),
                "Moduł {} przepuścił niesprawny wynik", modul.id()
            );
        }
    }

    // ------------------------------------------------------------------
    // RODZINA ISOBMFF POZA `mp4`/`mov`/`m4v`
    //
    // Wcześniej `.3gp`, `.3g2`, `.f4v`, `.m4a` i `.m4b` wpadały do gałęzi
    // domyślnej („brak metody weryfikacji"), czyli wystarczyło, że wynik jest
    // niepusty i nie jest samymi zerami — a więc ślepe zszycie przez `splice`
    // przechodziło. Testy niżej pracują na materiale z prawdziwego kodera
    // (ffmpeg), nie na ręcznie sklejanych bajtach.
    // ------------------------------------------------------------------

    #[test]
    #[ignore = "Wymaga image/test_fixture.3gp oraz ffmpeg/ffprobe w systemie. Uruchom z --ignored."]
    fn test_weryfikacja_przyjmuje_prawdziwy_3gp() {
        let wynik = weryfikuj_naprawiony_plik(Path::new("image/test_fixture.3gp"));
        assert!(wynik.is_ok(), "Zdrowy .3gp z ffmpeg musi przejść weryfikację: {:?}", wynik);
    }

    #[test]
    #[ignore = "Wymaga image/test_fixture.f4v oraz ffmpeg/ffprobe w systemie. Uruchom z --ignored."]
    fn test_weryfikacja_przyjmuje_prawdziwy_f4v() {
        let wynik = weryfikuj_naprawiony_plik(Path::new("image/test_fixture.f4v"));
        assert!(wynik.is_ok(), "Zdrowy .f4v z ffmpeg musi przejść weryfikację: {:?}", wynik);
    }

    /// NAJWAŻNIEJSZY TEST TEJ GRUPY — regresja na pułapkę audio-only.
    ///
    /// Gdyby `.m4a` trafił do gałęzi ffmpeg-owej (`weryfikuj_wideo`), TEST 2
    /// sędziego zażądałby strumienia `v:0` z wymiarami, dostałby pusty wynik i
    /// uznał ZDROWY plik za zepsuty — a Faza 17 usunęłaby go przez `sprzataj`.
    /// Ten test przechodzi TYLKO wtedy, gdy plik audio idzie gałęzią
    /// strukturalną.
    #[test]
    #[ignore = "Wymaga image/test_fixture.m4a. Uruchom z --ignored."]
    fn test_weryfikacja_przyjmuje_prawdziwy_m4a_bez_sciezki_obrazu() {
        let sciezka = Path::new("image/test_fixture.m4a");

        // Założenie testu: fixture NIE MA ścieżki obrazu. Gdyby ktoś podmienił
        // plik na taki z wideo, test przestałby sprawdzać to, co ma sprawdzać.
        let bajty = std::fs::read(sciezka).expect("fixture musi istnieć");
        assert!(
            crate::video_image::verify_video_bytes(&bajty),
            "Fixture musi być czytelnym kontenerem ISOBMFF"
        );

        let wynik = weryfikuj_naprawiony_plik(sciezka);
        assert!(
            wynik.is_ok(),
            "Zdrowy plik audio-only NIE MOŻE zostać odrzucony - to by go skasowało: {:?}",
            wynik
        );
        let dowod = wynik.unwrap();
        assert!(
            dowod.contains("ISOBMFF"),
            "Plik audio musi iść gałęzią strukturalną, nie ffmpeg-ową: {}",
            dowod
        );
        assert!(
            dowod.contains("SŁABA"),
            "Dowód strukturalny to gwarancja słaba i musi to jawnie meldować: {}",
            dowod
        );
    }

    #[test]
    #[ignore = "Wymaga image/test_fixture.m4a. Uruchom z --ignored."]
    fn test_weryfikacja_odrzuca_uszkodzony_m4a() {
        // Sygnatura `ftyp` zostaje nietknięta, więc sprawdzenie magic bytes by
        // to przepuściło. Niszczymy KOŃCÓWKĘ, w której MP4 z ffmpeg trzyma
        // `moov` - bez niego nie ma ani jednej czytelnej ścieżki.
        let dir = tempdir().unwrap();
        let pelny = std::fs::read("image/test_fixture.m4a").expect("fixture musi istnieć");
        let uciety = &pelny[..pelny.len() / 2];
        let p = zapisz(dir.path(), "zepsuty.m4a", uciety);

        assert_eq!(&uciety[4..8], b"ftyp", "Test bez sensu: sygnatura musi zostać nietknięta");
        assert!(
            weryfikuj_naprawiony_plik(&p).is_err(),
            "Ucięty .m4a musi zostać odrzucony - inaczej gałąź audio jest bezzębna"
        );
    }

    #[test]
    fn test_weryfikacja_odrzuca_smieci_z_rozszerzeniem_m4a() {
        let dir = tempdir().unwrap();
        let p = zapisz(dir.path(), "smieci.m4a", b"to zupelnie nie jest kontener isobmff");
        assert!(weryfikuj_naprawiony_plik(&p).is_err());
    }

    /// Straż nad zasięgiem gałęzi: wszystkie rozszerzenia rodziny ISOBMFF,
    /// które obsługujemy, muszą trafiać do gałęzi FORMATOWEJ, a nie do
    /// domyślnej. Dowodem jest to, że śmieci z takim rozszerzeniem są
    /// ODRZUCANE — gałąź domyślna by je przyjęła (niepuste, nie same zera).
    #[test]
    fn test_rodzina_isobmff_nie_wpada_do_galezi_domyslnej() {
        let dir = tempdir().unwrap();
        for ext in ["mp4", "mov", "m4v", "3gp", "3g2", "f4v", "m4a", "m4b"] {
            let p = zapisz(dir.path(), &format!("smieci.{}", ext), b"dowolna niepusta tresc, nie isobmff");
            assert!(
                weryfikuj_naprawiony_plik(&p).is_err(),
                ".{} wpadło do gałęzi domyślnej - ślepe zszycie by przeszło", ext
            );
        }
    }

    // ------------------------------------------------------------------
    // HEIC: DOWÓD TREŚCI, NIE STRUKTURY
    // ------------------------------------------------------------------

    #[test]
    #[ignore = "Wymaga image/test_fixture.heic oraz pluginu libde265. Uruchom z --ignored."]
    fn test_weryfikacja_heic_daje_mocna_gwarancje_po_zdekodowaniu_pikseli() {
        let wynik = weryfikuj_naprawiony_plik(Path::new("image/test_fixture.heic"));
        let dowod = wynik.expect("zdrowy HEIC musi przejść");
        assert!(dowod.contains("dekodowanie pikseli"), "Dowód musi mówić o pikselach: {}", dowod);
        assert!(dowod.contains("MOCNA"), "Pełne dekodowanie to gwarancja mocna: {}", dowod);
    }

    /// Regresja na wadę, którą ta zmiana usuwa: plik z czytelną strukturą i
    /// rozsypanym strumieniem obrazu dostawał wcześniej stempel „gwarancja
    /// MOCNA", bo weryfikacja czytała tylko uchwyt obrazu.
    #[test]
    #[ignore = "Wymaga image/test_fixture.heic oraz pluginu libde265. Uruchom z --ignored."]
    fn test_weryfikacja_heic_odrzuca_rozsypana_tresc_przy_zdrowej_strukturze() {
        let dir = tempdir().unwrap();
        let mut bajty = std::fs::read("image/test_fixture.heic").expect("fixture musi istnieć");

        let pozycja = (0..bajty.len().saturating_sub(4))
            .find(|&i| &bajty[i..i + 4] == b"mdat")
            .expect("fixture musi mieć pudełko mdat");
        for b in bajty[pozycja + 4..].iter_mut() {
            *b = 0x5A;
        }

        // Założenie testu: metadane nietknięte, kontener nadal się otwiera.
        assert!(
            crate::heic_image::decode_heic_bytes(&bajty).is_some(),
            "Test bez sensu: kontener musi pozostać czytelny"
        );

        let p = zapisz(dir.path(), "rozsypany.heic", &bajty);
        assert!(
            weryfikuj_naprawiony_plik(&p).is_err(),
            "HEIC z rozsypanym strumieniem obrazu MUSI zostać odrzucony"
        );
    }
}
