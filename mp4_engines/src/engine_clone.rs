// src/mp4/engine_clone.rs
//
// PORT z projektu `mp4_doctor` (crate `mp4_doctor`, moduł `engine_clone`).
// Zmiany wobec oryginału: `tracing::debug!` -> `tracing`, brak innych modyfikacji logiki.

//! Moduł `engine_clone` realizuje strategię przeszczepu kontenera.
//!
//! Kopiuje w pełni sprawny atom `moov` z pliku dawcy i łączy go z surowymi 
//! danymi wideo (`mdat`) z pliku uszkodzonego.
//!
//! Zaktualizowano: Pełne wyciszenie logów (użycie `tracing::debug!`) do współpracy z MPSC.

use std::fs::File;
use std::io::{self, Read, Write, Seek, SeekFrom};
use byteorder::{BigEndian, ReadBytesExt};

// `crate::boxes` bez `use ... BoxInfo`, celowo: ten moduł ma WŁASNY,
// starszy `BoxInfo` (offsety w PLIKU, u64) obok `boxes::BoxInfo` (offsety w
// BUFORZE moov_data, usize) - różne jednostki dla różnych celów. Import
// pełną ścieżką (`boxes::BoxInfo`, `boxes::collect_nested`) unika kolizji
// nazw i czyni różnicę widoczną w miejscu użycia.
use crate::boxes;

struct BoxInfo {
    offset: u64,
    size: u64,
}

fn find_box(file: &mut File, target_box: &[u8; 4]) -> io::Result<Option<BoxInfo>> {
    let file_size = file.metadata()?.len();
    let mut position = 0;
    file.seek(SeekFrom::Start(0))?;

    while position < file_size {
        let size_32 = match file.read_u32::<BigEndian>() {
            Ok(s) => s,
            Err(_) => break,
        };

        let mut box_type = [0u8; 4];
        if file.read_exact(&mut box_type).is_err() { break; }

        // (rozmiar, rozmiar_naglowka) - ten sam wzorzec co w
        // `boxes::parse_top_level_boxes`, z którym ten hand-rolled parser
        // dawno się rozjechał (patrz obie poprawki niżej).
        let (actual_size, header_size): (u64, u64) = if size_32 == 1 {
            let big = match file.read_u64::<BigEndian>() {
                Ok(s) => s,
                Err(_) => break,
            };
            (big, 16)
        } else if size_32 == 0 {
            // Rozmiar 0 = box ciągnie się do końca pliku - poprawna konwencja
            // ISOBMFF, obsługiwana w `boxes::parse_top_level_boxes`, ale
            // WCZEŚNIEJ tutaj trafiała w gałąź `size_32 < 8` i przerywała
            // parsowanie. Box na końcu pliku używający tej konwencji -
            // typowo właśnie `mdat`, dokładnie to, czego szuka ta funkcja -
            // był przez to NIEWIDOCZNY: `find_box` zwracał `None`, a `repair`
            // kończył się błędem "Brak danych mdat", mimo że dane fizycznie
            // tam były.
            (file_size - position, 8)
        } else if size_32 < 8 {
            break;
        } else {
            (size_32 as u64, 8)
        };

        // Box deklarujący rozmiar mniejszy niż własny nagłówek albo
        // wychodzący poza koniec pliku to uszkodzony/spreparowany nagłówek -
        // odrzucamy go tu, PRZED zwróceniem wywołującemu.
        //
        // Bez tej kontroli `moov_info.size` z pliku DAWCY (który w tym
        // narzędziu z definicji bywa niezaufany/uszkodzony) trafiało bez
        // żadnej walidacji do `vec![0u8; moov_info.size as usize]` w
        // `repair()` niżej: `largesize` bliskie u64::MAX dawało próbę
        // alokacji, którą alokator ubija (`abort`, nie da się złapać), a
        // `largesize` mniejsze niż 8 dawało `moov_data` krótszy niż 8 bajtów,
        // co przy dalszym (usuniętym niżej) `moov_data.len() - 8` przepełniało
        // `usize`. `checked_add` chroni samo porównanie przed przepełnieniem
        // przy `position` bliskim końca zakresu `u64`.
        let Some(koniec) = position.checked_add(actual_size) else { break };
        if actual_size < header_size || koniec > file_size { break; }

        if &box_type == target_box {
            return Ok(Some(BoxInfo { offset: position, size: actual_size }));
        }

        position = koniec;
        if file.seek(SeekFrom::Start(position)).is_err() { break; }
    }
    Ok(None)
}

/// Główny egzekutor metody Clone.
pub fn repair(broken_file: &str, donor_file: &str, output_file: &str) -> io::Result<()> {
    tracing::debug!("🔗 [CLONE] Rozpoczynam klonowanie atomu 'moov' z dawcy...");

    let mut ref_file = File::open(donor_file)?;
    let mut bro_file = File::open(broken_file)?;

    let moov_info = find_box(&mut ref_file, b"moov")?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Brak 'moov' u dawcy!"))?;

    let mdat_info = find_box(&mut bro_file, b"mdat")?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Brak danych 'mdat' w zepsutym pliku!"))?;

    tracing::debug!("📥 [CLONE] Wyizolowano nagłówek dawcy: {} bajtów.", moov_info.size);
    let mut moov_data = vec![0u8; moov_info.size as usize];
    ref_file.seek(SeekFrom::Start(moov_info.offset))?;
    ref_file.read_exact(&mut moov_data)?;

    // =========================================================================
    // INŻYNIERIA ODWROTNA AVCC: DYNAMICZNY SHIFT TABEL stco / co64
    // =========================================================================
    tracing::debug!("🧠 [CLONE-STCO] Rozpoczynam mapowanie tablic adresów (stco/co64)...");
    
    // Obliczamy rozmiar nagłówka mdat pacjenta
    bro_file.seek(SeekFrom::Start(mdat_info.offset))?;
    let mut mdat_hdr = [0u8; 8];
    bro_file.read_exact(&mut mdat_hdr)?;
    let mut mdat_header_size = 8;
    let size_32 = u32::from_be_bytes(mdat_hdr[0..4].try_into().unwrap());
    if size_32 == 1 { mdat_header_size = 16; }

    // Gdzie znajdzie się payload mdat w naszym nowym pliku?
    let new_mdat_payload_offset = moov_data.len() as i64 + mdat_header_size as i64;

    // =========================================================================
    // WYZNACZENIE DELTY — NA PODSTAWIE UKŁADU DAWCY, NIE PIERWSZEGO WPISU
    //
    // NAPRAWIONY BŁĄD (znaleziony na prawdziwym pliku .3gp z dwiema ścieżkami):
    // wcześniej delta była liczona JEDNORAZOWO z pierwszego wpisu PIERWSZEJ
    // napotkanej tablicy `stco`, przy milczącym założeniu, że pierwszy kawałek
    // tej ścieżki leży dokładnie na początku danych `mdat`. Dla pliku
    // jednościeżkowego to prawda — i dlatego wada nie wychodziła w testach,
    // które używały materiału bez dźwięku.
    //
    // Przy dwóch ścieżkach założenie pada. Zmierzone na `image/test_fixture.3gp`
    // (H.263 + AAC): dane `mdat` zaczynają się na offsecie 44, ale pierwsza
    // tablica `stco` (wideo) ma pierwszy offset 615, a dopiero druga (audio)
    // ma 44. Silnik liczył więc deltę mniejszą o 571 bajtów i przesuwał o tyle
    // OBIE ścieżki — wynik otwierał się w ffprobe (nagłówki były spójne), ale
    // dekodowanie sypało się na obu strumieniach. Praktycznie każde nagranie z
    // kamery ma obraz i dźwięk, więc wada dotyczyła większości realnego
    // materiału.
    //
    // Poprawna delta jest znana WPROST: cały blok `mdat` przenosi się w całości,
    // więc wystarczy różnica położenia jego danych. Offsety w tablicach pochodzą
    // z moov DAWCY, więc punktem odniesienia jest układ dawcy, nie pacjenta.
    let donor_mdat = find_box(&mut ref_file, b"mdat")?;
    let shift_delta: Option<i64> = match donor_mdat {
        Some(info) => {
            ref_file.seek(SeekFrom::Start(info.offset))?;
            let mut hdr = [0u8; 8];
            ref_file.read_exact(&mut hdr)?;
            let donor_header_size: u64 =
                if u32::from_be_bytes(hdr[0..4].try_into().unwrap()) == 1 { 16 } else { 8 };
            let donor_payload = (info.offset + donor_header_size) as i64;
            let delta = new_mdat_payload_offset - donor_payload;
            tracing::debug!(
                "🎯 [CLONE-STCO] Delta z układu dawcy: dane mdat {} -> {} (przesunięcie {} bajtów).",
                donor_payload, new_mdat_payload_offset, delta
            );
            Some(delta)
        }
        None => {
            // Dawca bez `mdat` to materiał, którego nie powinno tu być, ale
            // przerwanie naprawy byłoby regresją wobec dotychczasowego
            // zachowania. Zostaje stara heurystyka kotwicy z pierwszego wpisu.
            tracing::warn!("⚠️ [CLONE-STCO] Dawca nie ma atomu mdat - wracam do heurystyki kotwicy.");
            None
        }
    };
    let mut shift_delta = shift_delta;

    // SZUKANIE STRUKTURALNE, NIE BAJTOWE.
    //
    // Wcześniej ta pętla skanowała KAŻDĄ pozycję bufora szukając dosłownych
    // bajtów `"stco"`/`"co64"`, bez sprawdzenia, czy to w ogóle nagłówek
    // boxu na prawidłowej granicy - dwa realne problemy:
    //
    // 1. BEZPIECZEŃSTWO: `moov_data[i+8..i+12]` (odczyt `entry_count`) był
    //    czytany BEZWARUNKOWO, zanim pętla niżej w ogóle sprawdzała, czy te
    //    bajty mieszczą się w buforze - dopasowanie "stco"/"co64" blisko
    //    końca `moov_data` panikowało (indeksowanie poza zakres).
    // 2. POPRAWNOŚĆ: bajty `"stco"`/`"co64"` mogły przypadkiem wystąpić
    //    wewnątrz NIEZWIĄZANEGO ładunku (np. pole `duration` albo dowolne
    //    metadane) - taki fałszywy trop kotwiczył deltę przesunięcia na
    //    śmieciach albo nadpisywał losowe bajty payloadu, jakby to były
    //    wpisy tablicy offsetów. Ciche uszkodzenie danych, bez żadnego błędu.
    //
    // `boxes::collect_nested` (współdzielony, przetestowany prymityw z
    // `boxes.rs`, używany też przez `validate_moov_offsets`) parsuje
    // strukturę PRAWDZIWEGO drzewa boxów (`moov` → `trak` → `mdia` → `minf`
    // → `stbl`), więc "stco"/"co64" znalezione tą drogą to zawsze nagłówek
    // boxu na prawidłowej granicy, nigdy przypadkowy bajt payloadu.
    let mut stco_boxes = Vec::new();
    boxes::collect_nested(&moov_data, 0, moov_data.len(), b"stco", &mut stco_boxes);
    let mut co64_boxes = Vec::new();
    boxes::collect_nested(&moov_data, 0, moov_data.len(), b"co64", &mut co64_boxes);

    for info in &stco_boxes {
        let (body_start, body_end) = info.body_range();
        // 4 bajty wersji/flag + 4 bajty licznika wpisów.
        if body_start + 8 > body_end { continue; }
        let entry_count = u32::from_be_bytes(moov_data[body_start+4..body_start+8].try_into().unwrap());
        if entry_count == 0 || body_start + 8 + 4 > body_end { continue; }

        let first_offset = u32::from_be_bytes(moov_data[body_start+8..body_start+12].try_into().unwrap()) as i64;
        if shift_delta.is_none() {
            shift_delta = Some(new_mdat_payload_offset - first_offset);
            tracing::debug!("🎯 [CLONE-STCO] Złapano Anchor (stco)! Delta przesunięcia klatek: {} bajtów.", shift_delta.unwrap());
        }

        let delta = shift_delta.unwrap();
        for j in 0..entry_count as usize {
            let off_idx = body_start + 8 + (j * 4);
            if off_idx + 4 <= body_end {
                let old_val = u32::from_be_bytes(moov_data[off_idx..off_idx+4].try_into().unwrap()) as i64;
                let new_val = (old_val + delta) as u32;
                moov_data[off_idx..off_idx+4].copy_from_slice(&new_val.to_be_bytes());
            }
        }
    }
    for info in &co64_boxes {
        let (body_start, body_end) = info.body_range();
        if body_start + 8 > body_end { continue; }
        let entry_count = u32::from_be_bytes(moov_data[body_start+4..body_start+8].try_into().unwrap());
        if entry_count == 0 || body_start + 8 + 8 > body_end { continue; }

        let first_offset = u64::from_be_bytes(moov_data[body_start+8..body_start+16].try_into().unwrap()) as i64;
        if shift_delta.is_none() {
            shift_delta = Some(new_mdat_payload_offset - first_offset);
            tracing::debug!("🎯 [CLONE-STCO] Złapano Anchor (co64)! Delta przesunięcia klatek: {} bajtów.", shift_delta.unwrap());
        }

        let delta = shift_delta.unwrap();
        for j in 0..entry_count as usize {
            let off_idx = body_start + 8 + (j * 8);
            if off_idx + 8 <= body_end {
                let old_val = u64::from_be_bytes(moov_data[off_idx..off_idx+8].try_into().unwrap()) as i64;
                let new_val = (old_val + delta) as u64;
                moov_data[off_idx..off_idx+8].copy_from_slice(&new_val.to_be_bytes());
            }
        }
    }
    // =========================================================================

    let mut out_file = File::create(output_file)?;
    out_file.write_all(&moov_data)?;

    tracing::debug!("🔄 [CLONE] Przepisuję uszkodzone bloki mdat (Rozmiar: {} bajtów)...", mdat_info.size);
    bro_file.seek(SeekFrom::Start(mdat_info.offset))?;
    
    let mut buffer = vec![0u8; 8192 * 1024]; 
    let mut bytes_left = mdat_info.size;
    
    while bytes_left > 0 {
        let to_read = std::cmp::min(bytes_left, buffer.len() as u64) as usize;
        let bytes_read = bro_file.read(&mut buffer[..to_read])?;
        if bytes_read == 0 { break; }
        out_file.write_all(&buffer[..bytes_read])?;
        bytes_left -= bytes_read as u64;
    }

    tracing::debug!("✅ [CLONE] Operacja łączenia bloków zakończona.");
    Ok(())
}

// ============================================================================
// TESTY JEDNOSTKOWE
//
// Ten plik nie miał ŻADNEGO testu, mimo że to najbardziej ryzykowna funkcja
// w projekcie: jedyna, która FIZYCZNIE PRZEPISUJE tablice offsetów w
// nagłówku wynikowego pliku na podstawie danych z pliku DAWCY - a dawca, tak
// samo jak plik zepsuty, jest w tym narzędziu z definicji niezaufany/może
// być uszkodzony. Testy niżej to regresje na 4 błędy znalezione w
// niezależnej recenzji (Gemini) i potwierdzone ręcznie na tym pliku.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Buduje pojedynczy box ISOBMFF (rozmiar 32-bitowy + typ + zawartość).
    fn box_32(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let size = (8 + payload.len()) as u32;
        let mut out = size.to_be_bytes().to_vec();
        out.extend_from_slice(box_type);
        out.extend_from_slice(payload);
        out
    }

    // ------------------------------------------------------------------
    // find_box — konwencja "rozmiar 0 = do końca pliku"
    // ------------------------------------------------------------------

    /// REGRESJA: `size_32 == 0` (legalna konwencja ISOBMFF "box sięga do
    /// końca pliku", obsługiwana od dawna w `boxes::parse_top_level_boxes")
    /// wcześniej trafiała tutaj w gałąź `size_32 < 8` i przerywała
    /// parsowanie - `mdat` zapisany tą konwencją (typowe dla ostatniego boxu
    /// pliku) był przez to NIEWIDOCZNY dla `find_box`.
    #[test]
    fn test_find_box_rozmiar_zero_siega_do_konca_pliku() {
        let dir = tempdir().unwrap();
        let plik = dir.path().join("a.mp4");

        let mut dane = box_32(b"ftyp", b"isomiso2avc1mp41");
        let mdat_pozycja = dane.len() as u64;
        dane.extend_from_slice(&0u32.to_be_bytes()); // size=0
        dane.extend_from_slice(b"mdat");
        dane.extend_from_slice(&[0xAAu8; 100]); // payload

        let oczekiwany_rozmiar = dane.len() as u64 - mdat_pozycja;
        std::fs::write(&plik, &dane).unwrap();

        let mut f = File::open(&plik).unwrap();
        let info = find_box(&mut f, b"mdat").unwrap()
            .expect("mdat z rozmiarem 0 (\"do końca pliku\") musi zostać znaleziony");
        assert_eq!(info.offset, mdat_pozycja);
        assert_eq!(info.size, oczekiwany_rozmiar);
    }

    // ------------------------------------------------------------------
    // find_box — odporność na spreparowany/uszkodzony nagłówek DAWCY
    // ------------------------------------------------------------------

    /// REGRESJA: `largesize` (rozszerzony rozmiar 64-bitowy) mniejszy niż
    /// własny nagłówek boxu (16 bajtów) był wcześniej przyjmowany BEZ
    /// WALIDACJI. `moov_info.size` trafiał później wprost do
    /// `vec![0u8; moov_info.size as usize]` w `repair()`, a stamtąd do
    /// nieużywanego już `moov_data.len() - 8` — przy rozmiarze < 8
    /// przepełniało to `usize` (panika w debug, w release zawijało się do
    /// wartości bliskiej `usize::MAX`).
    #[test]
    fn test_find_box_odrzuca_largesize_mniejszy_niz_wlasny_naglowek() {
        let dir = tempdir().unwrap();
        let plik = dir.path().join("zly.mp4");

        let mut dane = Vec::new();
        dane.extend_from_slice(&1u32.to_be_bytes()); // size32 == 1 -> largesize
        dane.extend_from_slice(b"moov");
        dane.extend_from_slice(&4u64.to_be_bytes()); // largesize=4, mniej niż 16
        dane.extend_from_slice(&[0u8; 20]);
        std::fs::write(&plik, &dane).unwrap();

        let mut f = File::open(&plik).unwrap();
        assert!(
            find_box(&mut f, b"moov").unwrap().is_none(),
            "box mniejszy niż własny nagłówek musi zostać odrzucony, nie zaakceptowany"
        );
    }

    /// REGRESJA: `largesize` deklarujący rozmiar WIĘKSZY niż cały plik był
    /// wcześniej przyjmowany bez walidacji. `repair()` alokowałby wtedy
    /// `vec![0u8; rozmiar]` na podstawie liczby pochodzącej wprost z pliku
    /// DAWCY - dla rozmiaru bliskiego u64::MAX to próba alokacji, którą
    /// alokator ubija (`abort` procesu, nie do złapania przez Rust).
    #[test]
    fn test_find_box_odrzuca_rozmiar_wiekszy_niz_caly_plik() {
        let dir = tempdir().unwrap();
        let plik = dir.path().join("zly2.mp4");

        let mut dane = Vec::new();
        dane.extend_from_slice(&1u32.to_be_bytes());
        dane.extend_from_slice(b"moov");
        dane.extend_from_slice(&(u64::MAX - 100).to_be_bytes()); // absurdalny rozmiar
        dane.extend_from_slice(&[0u8; 20]);
        std::fs::write(&plik, &dane).unwrap();

        let mut f = File::open(&plik).unwrap();
        assert!(
            find_box(&mut f, b"moov").unwrap().is_none(),
            "box deklarujący rozmiar większy niż cały plik musi zostać odrzucony"
        );
    }

    /// Test integracyjny na `repair()` (nie tylko `find_box`): dawca ze
    /// spreparowanym absurdalnym rozmiarem `moov` nie może ani spanikować,
    /// ani zawiesić się w próbie gigantycznej alokacji - `repair()` musi
    /// zwrócić czysty błąd i nie zostawić pliku wyjściowego.
    #[test]
    fn test_repair_odmawia_bez_panikowania_gdy_dawca_ma_absurdalny_rozmiar_moov() {
        let dir = tempdir().unwrap();

        let mut dane_dawcy = Vec::new();
        dane_dawcy.extend_from_slice(&1u32.to_be_bytes());
        dane_dawcy.extend_from_slice(b"moov");
        dane_dawcy.extend_from_slice(&(u64::MAX - 100).to_be_bytes());
        let dawca = dir.path().join("dawca.mp4");
        std::fs::write(&dawca, &dane_dawcy).unwrap();

        let zepsuty = dir.path().join("zepsuty.mp4");
        std::fs::write(&zepsuty, box_32(b"mdat", &[0xBBu8; 16])).unwrap();

        let wynik = dir.path().join("wynik.mp4");
        let rezultat = repair(zepsuty.to_str().unwrap(), dawca.to_str().unwrap(), wynik.to_str().unwrap());

        assert!(rezultat.is_err(), "dawca ze spreparowanym rozmiarem moov nie może dać sukcesu");
        assert!(!wynik.exists(), "nieudana naprawa nie może zostawić pliku wyjściowego");
    }

    // ------------------------------------------------------------------
    // Przesuwanie stco/co64 — SZUKANIE STRUKTURALNE, nie bajtowe
    // ------------------------------------------------------------------

    /// Owija `stco` w pełną hierarchię moov/trak/mdia/minf/stbl wymaganą
    /// przez `boxes::collect_nested`, z opcjonalnym boxem-śmieciem PRZED
    /// prawdziwą ścieżką (do testowania odporności na fałszywe dopasowania).
    fn zbuduj_moov(dodatkowy_box_przed: Option<Vec<u8>>, stco_offset: u32) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(&[0u8; 4]); // wersja + flagi
        entry.extend_from_slice(&1u32.to_be_bytes()); // entry_count = 1
        entry.extend_from_slice(&stco_offset.to_be_bytes());
        let stco = box_32(b"stco", &entry);
        let stbl = box_32(b"stbl", &stco);
        let minf = box_32(b"minf", &stbl);
        let mdia = box_32(b"mdia", &minf);
        let trak = box_32(b"trak", &mdia);

        let mut moov_body = Vec::new();
        if let Some(smiec) = dodatkowy_box_przed {
            moov_body.extend_from_slice(&smiec);
        }
        moov_body.extend_from_slice(&trak);
        box_32(b"moov", &moov_body)
    }

    /// REGRESJA — SEDNO poprawki: box `free` PRZED prawdziwą ścieżką niesie w
    /// swoim payloadzie dosłowne bajty `b"stco"`, zaraz po nich 4 bajty, które
    /// pod STARYM (bajtowym) skanowaniem wyglądałyby jak `entry_count = 1`, a
    /// kolejne 4 - jak wpis tablicy offsetów do PRZEPISANIA. To dokładnie
    /// mechanizm cichego uszkodzenia danych, jaki opisuje recenzja: fałszywe
    /// dopasowanie wewnątrz niezwiązanego payloadu.
    ///
    /// Pod starym kodem te "śmieciowe" 4 bajty zostałyby PRZEPISANE (uznane
    /// za offset do przesunięcia). Pod nowym - `boxes::collect_nested` widzi
    /// tylko PRAWDZIWĄ strukturę boxów, więc payload `free` zostaje
    /// nietknięty co do bajtu, a przesunięciu podlega WYŁĄCZNIE prawdziwy
    /// wpis w prawdziwym `stco` zagnieżdżonym w moov/trak/mdia/minf/stbl.
    #[test]
    fn test_repair_nie_daje_sie_oszukac_falszywym_bajtom_stco_w_payloadzie() {
        let dir = tempdir().unwrap();

        // Payload boxu `free`: literalne "stco" + śmieciowy entry_count=1 +
        // śmieciowy "offset" - identyczny kształt bajtowy co prawdziwy stco,
        // ale to NIE JEST box (nie ma własnego poprawnego nagłówka rozmiaru
        // przed sobą - jest to treść WEWNĄTRZ boxu `free`).
        let mut smieciowy_payload = b"stco".to_vec();
        smieciowy_payload.extend_from_slice(&1u32.to_be_bytes()); // wygląda jak entry_count=1
        smieciowy_payload.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // wygląda jak offset
        let free_box = box_32(b"free", &smieciowy_payload);
        let znacznik_smiecia = smieciowy_payload.clone();

        // Dawca: `ftyp` (wypełnienie PRAWDZIWYM boxem, nie surowymi zerami -
        // surowe zera na starcie pliku same wyglądałyby jak box o rozmiarze
        // 0, czyli "sięga do końca pliku", i połknęłyby całą resztę), potem
        // `mdat`, potem `moov`. Offset danych `mdat` liczony programowo, nie
        // na sztywno, żeby test nie zależał od przypadkowo trafionej stałej.
        let ftyp = box_32(b"ftyp", b"isomiso2avc1mp41");
        let mdat_dawcy = box_32(b"mdat", &[0u8; 8]);
        // Offset DANYCH mdat (za jego 8-bajtowym nagłówkiem size+typ) - stco
        // wskazuje na dane próbek wewnątrz mdat, nie na sam box.
        let prawdziwy_offset_u_dawcy = ftyp.len() as u32 + 8;

        let moov = zbuduj_moov(Some(free_box), prawdziwy_offset_u_dawcy);

        let mut dawca_dane = Vec::new();
        dawca_dane.extend_from_slice(&ftyp);
        dawca_dane.extend_from_slice(&mdat_dawcy);
        dawca_dane.extend_from_slice(&moov);
        let dawca = dir.path().join("dawca.mp4");
        std::fs::write(&dawca, &dawca_dane).unwrap();

        let zepsuty = dir.path().join("zepsuty.mp4");
        let mdat_payload = [0x11u8; 32];
        std::fs::write(&zepsuty, box_32(b"mdat", &mdat_payload)).unwrap();

        let wynik = dir.path().join("wynik.mp4");
        repair(zepsuty.to_str().unwrap(), dawca.to_str().unwrap(), wynik.to_str().unwrap())
            .expect("naprawa na poprawnie zbudowanym materiale testowym musi się udać");

        let wynik_bajty = std::fs::read(&wynik).unwrap();

        // 1. Śmieciowy payload `free` MUSI pozostać BAJT W BAJT nietknięty -
        //    dowód, że fałszywe "stco" nie zostało potraktowane jak tablica
        //    offsetów do przepisania.
        let pozycja_smiecia = wynik_bajty.windows(znacznik_smiecia.len())
            .position(|w| w == znacznik_smiecia.as_slice())
            .expect("śmieciowy payload musi nadal istnieć w wyniku");
        assert_eq!(
            &wynik_bajty[pozycja_smiecia..pozycja_smiecia + znacznik_smiecia.len()],
            znacznik_smiecia.as_slice(),
            "fałszywe bajty \"stco\" w payloadzie boxu free zostały BŁĘDNIE przepisane"
        );

        // 2. Prawdziwy wpis stco MUSI zostać przesunięty o poprawną deltę:
        //    w wyniku dane mdat zaczynają się zaraz po moov (+8 bajtów na
        //    nagłówek mdat pacjenta - standardowy, 32-bitowy rozmiar).
        let mut f = File::open(&wynik).unwrap();
        let moov_info = find_box(&mut f, b"moov").unwrap().expect("wynik musi mieć moov");
        find_box(&mut f, b"mdat").unwrap().expect("wynik musi mieć mdat");
        let oczekiwany_nowy_offset = (moov_info.offset + moov_info.size + 8) as u32; // +8 = nagłówek mdat pacjenta

        // Odczytujemy przesunięty wpis stco wprost z bufora wyjściowego -
        // ten sam układ co w `zbuduj_moov` (jedyny wpis, offset+8+8).
        let mut f2 = File::open(&wynik).unwrap();
        let moov_info2 = find_box(&mut f2, b"moov").unwrap().unwrap();
        f2.seek(SeekFrom::Start(moov_info2.offset)).unwrap();
        let mut moov_bajty = vec![0u8; moov_info2.size as usize];
        f2.read_exact(&mut moov_bajty).unwrap();

        let mut stco_lista = Vec::new();
        boxes::collect_nested(&moov_bajty, 0, moov_bajty.len(), b"stco", &mut stco_lista);
        assert_eq!(stco_lista.len(), 1, "musi istnieć dokładnie jeden PRAWDZIWY box stco");
        let (bs, _) = stco_lista[0].body_range();
        let przesuniety_offset = u32::from_be_bytes(moov_bajty[bs+8..bs+12].try_into().unwrap());
        assert_eq!(
            przesuniety_offset, oczekiwany_nowy_offset,
            "prawdziwy wpis stco musi zostać przesunięty o poprawną deltę"
        );
    }
}
