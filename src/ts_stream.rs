// src/ts_stream.rs

//! # Diagnostyka Strumieni MPEG Transport Stream (.ts, .m2ts, .mts)
//!
//! **ZERO ZALEŻNOŚCI ZEWNĘTRZNYCH** — w odróżnieniu od `video_image` (crate
//! `mp4`) czy `heic_image` (systemowa `libheif`), format TS jest na tyle
//! prosty strukturalnie, że pełna analiza mieści się w czystym `std`.
//!
//! ## Dlaczego TS daje LEPSZĄ diagnostykę niż MP4
//!
//! MP4/MOV to kontener z tablicami indeksowymi — albo się otworzy, albo nie.
//! TS to **ciągły strumień pakietów o STAŁEJ długości 188 bajtów**, gdzie
//! każdy pakiet ma:
//! - bajt synchronizacji `0x47` na pozycji 0,
//! - identyfikator strumienia (PID) w bitach 12-0 bajtów 1-2,
//! - **4-bitowy licznik ciągłości (CC)** w dolnych bitach bajtu 3, inkrementowany
//!   modulo 16 osobno dla KAŻDEGO PID-u.
//!
//! Dzięki temu potrafimy powiedzieć nie tylko "uszkodzony", ale **ILE
//! pakietów zginęło i w którym strumieniu** — licznik ciągłości ujawnia
//! dziury nawet wtedy, gdy plik nadal wygląda na spójny.
//!
//! ## Ograniczenie (uczciwie)
//! To analiza WARSTWY TRANSPORTOWEJ, nie treści wideo. Strumień może mieć
//! idealną ciągłość pakietów i nadal zawierać uszkodzone dane H.264 w
//! środku — do tego trzeba by dekodera (ffmpeg), świadomie pominiętego,
//! tak samo jak przy `video_image`.

/// Standardowy rozmiar pakietu TS (ISO/IEC 13818-1).
pub const TS_PACKET_SIZE: usize = 188;
/// Wariant M2TS/BDAV (Blu-ray): 188 bajtów + 4-bajtowy znacznik czasu z przodu.
pub const M2TS_PACKET_SIZE: usize = 192;
/// Bajt synchronizacji rozpoczynający każdy pakiet.
pub const TS_SYNC_BYTE: u8 = 0x47;

/// Wynik analizy strumienia.
#[derive(Debug, Clone, PartialEq)]
pub struct TsAnalysis {
    /// Wykryty rozmiar pakietu (188 dla .ts, 192 dla .m2ts/.mts).
    pub packet_size: usize,
    /// Liczba poprawnie zsynchronizowanych pakietów.
    pub total_packets: usize,
    /// Pakiety, w których zabrakło bajtu synchronizacji — twarde uszkodzenie
    /// struktury strumienia.
    pub sync_losses: usize,
    /// Liczba WYKRYTYCH LUK w licznikach ciągłości — każda oznacza pakiety,
    /// które fizycznie zginęły (nie dotarły / nie zostały odzyskane).
    pub continuity_errors: usize,
    /// Szacowana liczba ZGUBIONYCH pakietów (suma rozmiarów wszystkich luk).
    pub estimated_lost_packets: usize,
    /// Liczba różnych strumieni (PID) w pliku.
    pub distinct_pids: usize,
    /// Bajty na końcu, które nie tworzą pełnego pakietu — objaw ucięcia pliku.
    pub trailing_garbage_bytes: usize,
    /// Pakiety z ustawioną flagą `transport_error_indicator`.
    ///
    /// To JAWNA flaga formatu, ustawiana przez sprzęt na pakiecie odebranym z
    /// nieusuwalnym błędem — pakiet jest kompletny i stoi na swoim miejscu w
    /// siatce, więc ani kontrola synchronizacji, ani licznik ciągłości go nie
    /// wychwycą. Bez osobnego licznika strumień z takimi pakietami uchodził za
    /// „spójny": zmierzone na materiale z ffmpeg, pięć oflagowanych pakietów
    /// dawało opis „Strumień spójny". W praktyce znaczyło to, że Faza 19
    /// zapisywała `video_ok = true` i moduł naprawczy `ts_splice` NIGDY się dla
    /// takiego pliku nie kwalifikował — choć jego silnik potrafi ten pakiet
    /// zastąpić wersją z drugiej kopii.
    pub transport_errors: usize,
}

impl TsAnalysis {
    /// Czy strumień jest w pełni zdrowy — brak utraty synchronizacji, brak
    /// luk w ciągłości, brak niepełnego pakietu na końcu.
    pub fn is_healthy(&self) -> bool {
        self.total_packets > 0
            && self.sync_losses == 0
            && self.continuity_errors == 0
            && self.trailing_garbage_bytes == 0
            && self.transport_errors == 0
    }

    /// Procent pakietów, które zginęły względem oczekiwanej całości.
    /// Przydatne do oceny, czy plik nadaje się do odtworzenia mimo ubytków.
    pub fn loss_percentage(&self) -> f64 {
        let expected = self.total_packets + self.estimated_lost_packets;
        if expected == 0 { return 0.0; }
        (self.estimated_lost_packets as f64 / expected as f64) * 100.0
    }

    /// Zwięzły opis stanu do zapisania w bazie i pokazania użytkownikowi.
    pub fn describe(&self) -> String {
        if self.total_packets == 0 {
            return "Nie znaleziono żadnych pakietów TS (nie jest to strumień transportowy)".to_string();
        }
        if self.is_healthy() {
            return format!("Strumień spójny: {} pakietów, {} strumieni PID", self.total_packets, self.distinct_pids);
        }
        let mut parts = Vec::new();
        if self.sync_losses > 0 { parts.push(format!("{} utrat synchronizacji", self.sync_losses)); }
        if self.continuity_errors > 0 {
            parts.push(format!("{} luk w ciągłości (~{} zgubionych pakietów, {:.2}%)",
                self.continuity_errors, self.estimated_lost_packets, self.loss_percentage()));
        }
        if self.transport_errors > 0 { parts.push(format!("{} pakietów z flagą błędu transportu", self.transport_errors)); }
        if self.trailing_garbage_bytes > 0 { parts.push(format!("{} bajtów niepełnego pakietu na końcu (ucięty plik)", self.trailing_garbage_bytes)); }
        parts.join("; ")
    }
}

/// Wykrywa rozmiar pakietu, sprawdzając, czy bajty synchronizacji układają
/// się regularnie co 188 (zwykły TS) czy co 192 (M2TS z Blu-ray, gdzie
/// każdy pakiet poprzedza 4-bajtowy znacznik czasu).
///
/// Zwraca `(rozmiar_pakietu, offset_pierwszego_pakietu)` albo `None`, gdy
/// żaden wariant nie daje regularnego wzorca — czyli to nie jest strumień TS.
///
/// ## Próg wykrywania jest ADAPTACYJNY i ODPORNY NA DZIURY (naprawione błędy)
///
/// Dwa realne błędy wykryte przez testy na uszkodzonych strumieniach:
///
/// 1. Sztywne wymaganie 5 trafień odrzucało krótkie pliki jako "nie-TS".
/// 2. Wymaganie trafień **pod rząd** odrzucało strumienie z uszkodzonym
///    bajtem synchronizacji na początku — czyli dokładnie te, które
///    najbardziej potrzebują diagnozy. Dla narzędzia do odzysku danych to
///    najgorszy możliwy wynik: plik zepsuty = brak jakiejkolwiek analizy.
///
/// Teraz liczymy **ILE trafień** wypada w oknie próbek (nie czy wszystkie
/// pod rząd) i wymagamy większości — dzięki temu pojedyncze uszkodzone
/// pakiety nie blokują rozpoznania całego strumienia.
pub fn detect_packet_layout(bytes: &[u8]) -> Option<(usize, usize)> {
    let search_limit = bytes.len().min(M2TS_PACKET_SIZE * 4);
    let mut best: Option<(usize, usize, usize)> = None; // (trafienia, rozmiar, start)

    for start in 0..=search_limit {
        for &size in &[TS_PACKET_SIZE, M2TS_PACKET_SIZE] {
            let sync_offset = if size == M2TS_PACKET_SIZE { 4 } else { 0 };
            // Pierwszy pakiet MUSI mieć sync - inaczej to nie jest początek strumienia.
            if bytes.get(start + sync_offset) != Some(&TS_SYNC_BYTE) { continue; }

            let available = bytes.len().saturating_sub(start) / size;
            if available < 2 { continue; }
            let window = available.min(8);
            let hits = (0..window)
                .filter(|i| bytes.get(start + i * size + sync_offset) == Some(&TS_SYNC_BYTE))
                .count();

            // Większość próbek musi trafić - odporne na pojedyncze uszkodzenia,
            // ale wciąż odrzuca przypadkowe bajty 0x47 w danych nie-TS.
            if hits * 2 > window && best.is_none_or(|(h, _, _)| hits > h) {
                best = Some((hits, size, start));
            }
        }
        // Znaleziony start z kompletem trafień - nie ma sensu szukać dalej.
        if let Some((h, _, _)) = best && h >= 5 { break; }
    }
    best.map(|(_, size, start)| (size, start))
}

/// Analizuje strumień TS: liczy pakiety, wykrywa utraty synchronizacji i
/// **luki w licznikach ciągłości per PID** (kluczowa przewaga tego formatu).
///
/// Zwraca `None`, gdy plik w ogóle nie jest strumieniem transportowym.
pub fn analyze_ts(bytes: &[u8]) -> Option<TsAnalysis> {
    let (packet_size, start) = detect_packet_layout(bytes)?;
    let sync_offset = if packet_size == M2TS_PACKET_SIZE { 4 } else { 0 };

    let mut total_packets = 0usize;
    let mut sync_losses = 0usize;
    let mut transport_errors = 0usize;
    let mut continuity_errors = 0usize;
    let mut estimated_lost_packets = 0usize;
    // Ostatni widziany licznik ciągłości dla każdego PID-u.
    let mut last_cc: std::collections::HashMap<u16, u8> = std::collections::HashMap::new();

    let mut offset = start;
    while offset + packet_size <= bytes.len() {
        let pkt = &bytes[offset..offset + packet_size];
        let header = &pkt[sync_offset..];

        if header[0] != TS_SYNC_BYTE {
            sync_losses += 1;
            offset += packet_size;
            continue;
        }
        total_packets += 1;
        if (header[1] & MASKA_BLEDU_TRANSPORTU) != 0 {
            transport_errors += 1;
        }

        let pid = (((header[1] & 0x1F) as u16) << 8) | header[2] as u16;
        let cc = header[3] & 0x0F;
        // Bity 5-4 bajtu 3 mówią, czy pakiet w ogóle NIESIE payload. Pakiety
        // bez payloadu NIE inkrementują licznika ciągłości - pominięcie tego
        // dałoby fałszywe alarmy o lukach.
        let has_payload = (header[3] & 0x10) != 0;

        if has_payload {
            if let Some(&prev) = last_cc.get(&pid) {
                let expected = (prev + 1) & 0x0F;
                if cc != expected {
                    continuity_errors += 1;
                    // Odległość modulo 16 = ile pakietów przepadło w tej luce.
                    // `gap` jest zawsze >= 1, bo trafiamy tu tylko gdy cc != expected.
                    // UWAGA na fundamentalne ograniczenie 4-bitowego licznika:
                    // utrata DOKŁADNIE 16 (lub wielokrotności) pakietów jest
                    // nieodróżnialna od zera strat - takiej luki nie wykryjemy.
                    let gap = ((cc as i16 - expected as i16) & 0x0F) as usize;
                    estimated_lost_packets += gap;
                }
            }
            last_cc.insert(pid, cc);
        }

        offset += packet_size;
    }

    Some(TsAnalysis {
        packet_size,
        total_packets,
        sync_losses,
        continuity_errors,
        estimated_lost_packets,
        distinct_pids: last_cc.len(),
        trailing_garbage_bytes: bytes.len().saturating_sub(offset),
        transport_errors,
    })
}

// ============================================================================
// SKŁADANIE Z DWÓCH KOPII (FLAGA BŁĘDU I LICZNIK CIĄGŁOŚCI JAKO SĘDZIA)
// ============================================================================

/// Maska bitu `transport_error_indicator` w drugim bajcie nagłówka pakietu.
///
/// To **wbudowana w format flaga uszkodzenia**: demodulator lub demux ustawia
/// ją, gdy pakiet dotarł z nieusuwalnym błędem. Dla składania z dwóch kopii
/// jest obiektywnym sędzią, a nie heurystyką.
pub const MASKA_BLEDU_TRANSPORTU: u8 = 0x80;

/// Jeden pakiet strumienia zlokalizowany w buforze.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PakietTs {
    pub offset: usize,
    pub pid: u16,
    /// Licznik ciągłości (4 bity).
    pub cc: u8,
    /// Czy pakiet niesie payload — tylko takie inkrementują licznik.
    pub ma_payload: bool,
    /// Sync na miejscu i brak flagi błędu transportu.
    pub sprawny: bool,
}

/// Odczytuje pakiet stojący pod podanym offsetem.
fn pakiet_pod(bytes: &[u8], offset: usize, packet_size: usize, sync_offset: usize) -> Option<PakietTs> {
    let pkt = bytes.get(offset..offset + packet_size)?;
    let header = pkt.get(sync_offset..sync_offset + 4)?;

    let sprawny = header[0] == TS_SYNC_BYTE && (header[1] & MASKA_BLEDU_TRANSPORTU) == 0;

    Some(PakietTs {
        offset,
        pid: (((header[1] & 0x1F) as u16) << 8) | header[2] as u16,
        cc: header[3] & 0x0F,
        ma_payload: (header[3] & 0x10) != 0,
        sprawny,
    })
}

/// Składa jeden strumień z dwóch uszkodzonych kopii, wybierając NA POZIOMIE
/// KAŻDEGO PAKIETU tę stronę, której pakiet jest sprawny i zachowuje ciągłość.
///
/// ## Czym tu sędziujemy, skoro TS nie ma sum kontrolnych treści
///
/// Strumień transportowy nie chroni payloadu sumą kontrolną, ale daje **dwa
/// obiektywne sygnały ramowania**:
///
/// * `transport_error_indicator` — bit ustawiany przez sprzęt na pakiecie,
///   który dotarł uszkodzony. To jawna flaga formatu, nie domysł.
/// * **licznik ciągłości** per PID — inkrementowany o 1 modulo 16 na każdym
///   pakiecie z payloadem. Luka dowodzi utraty pakietów co do sztuki.
///
/// Dlatego gwarancja wyniku jest **SŁABA**: dowodzimy poprawności RAMOWANIA
/// (żaden pakiet nie zginął, żaden nie jest oznaczony jako błędny), nigdy
/// poprawności samych bajtów obrazu. To ta sama klasa gwarancji co w tar,
/// gdzie suma chroni wyłącznie nagłówki wpisów.
///
/// ## Dlaczego offsety zostają poprawne
///
/// Siatka pakietów jest sztywna (188 albo 192 bajty), a obie kopie pochodzą z
/// tego samego pliku, więc pakiet o danym numerze leży w obu pod tym samym
/// offsetem. Wynik zachowuje siatkę co do bajtu.
///
/// ## Kiedy odmawia
///
/// - któraś strona nie jest rozpoznawalnym strumieniem TS,
/// - kopie mają różny układ siatki (inny rozmiar pakietu lub inny offset
///   początku) — to nie są dwa odzyski tego samego pliku,
/// - TEN SAM pakiet jest niesprawny po OBU stronach.
pub fn splice_ts(bytes_a: &[u8], bytes_b: &[u8]) -> Option<Vec<u8>> {
    let (rozmiar_a, start_a) = detect_packet_layout(bytes_a)?;
    let (rozmiar_b, start_b) = detect_packet_layout(bytes_b)?;

    if rozmiar_a != rozmiar_b || start_a != start_b {
        return None;
    }

    let packet_size = rozmiar_a;
    let start = start_a;
    let sync_offset = if packet_size == M2TS_PACKET_SIZE { 4 } else { 0 };

    // Bajty przed pierwszym pakietem (offset startu) przepisujemy ze strony A —
    // obie kopie mają go identyczny, co właśnie sprawdziliśmy.
    let mut wynik = bytes_a.get(..start)?.to_vec();

    let ile = |b: &[u8]| b.len().saturating_sub(start) / packet_size;
    let liczba = ile(bytes_a).max(ile(bytes_b));
    if liczba == 0 {
        return None;
    }

    let mut oczekiwany_cc: std::collections::HashMap<u16, u8> = std::collections::HashMap::new();
    let mut wybrano_z_dawcy = 0usize;

    for i in 0..liczba {
        let offset = start + i * packet_size;

        let kandydaci = [
            (pakiet_pod(bytes_a, offset, packet_size, sync_offset), bytes_a, false),
            (pakiet_pod(bytes_b, offset, packet_size, sync_offset), bytes_b, true),
        ];

        // Najpierw pakiet sprawny ZACHOWUJĄCY ciągłość, potem dowolny sprawny.
        // Bez tego pierwszeństwa kopia z przekłamanym licznikiem wygrywałaby
        // tylko dlatego, że stoi pierwsza.
        let wybrany = kandydaci
            .iter()
            .find(|(p, _, _)| p.is_some_and(|p| p.sprawny && zachowuje_ciaglosc(&p, &oczekiwany_cc)))
            .or_else(|| kandydaci.iter().find(|(p, _, _)| p.is_some_and(|p| p.sprawny)))?;

        let (Some(pakiet), zrodlo, z_dawcy) = wybrany else { return None };
        if *z_dawcy {
            wybrano_z_dawcy += 1;
        }

        if pakiet.ma_payload {
            oczekiwany_cc.insert(pakiet.pid, pakiet.cc);
        }

        wynik.extend_from_slice(zrodlo.get(offset..offset + packet_size)?);
    }

    tracing::debug!(pakietow = liczba, z_dawcy = wybrano_z_dawcy, "splice_ts: złożono strumień");
    Some(wynik)
}

/// Czy pakiet kontynuuje licznik ciągłości swojego PID-u.
///
/// Pakiet bez payloadu nie inkrementuje licznika, więc zawsze zachowuje
/// ciągłość. PID widziany pierwszy raz też — nie ma z czym porównać.
fn zachowuje_ciaglosc(p: &PakietTs, oczekiwany: &std::collections::HashMap<u16, u8>) -> bool {
    if !p.ma_payload {
        return true;
    }
    match oczekiwany.get(&p.pid) {
        Some(&poprzedni) => p.cc == ((poprzedni + 1) & 0x0F),
        None => true,
    }
}

/// Rozpoznaje rozszerzenia strumieni transportowych.
pub fn is_ts_extension(path_str: &str) -> bool {
    let lower = path_str.to_lowercase();
    lower.ends_with(".ts") || lower.ends_with(".m2ts") || lower.ends_with(".mts")
}

/// Górny limit rozmiaru pliku wczytywanego w całości do pamięci przed
/// analizą. Ten sam próg i uzasadnienie co
/// `mp4_engines::boxes::LIMIT_DIAGNOZY_W_RAM`/`video_image::LIMIT_DIAGNOZY_W_RAM`:
/// Faza 19 przetwarza pliki równolegle (Rayon), więc szczyt zużycia RAM to
/// wielokrotność tej wartości.
const LIMIT_DIAGNOZY_W_RAM: u64 = 256 * 1024 * 1024; // 256 MB

/// Wariant [`analyze_ts`] operujący na pliku na dysku. Odmawia wczytania
/// plików większych niż [`LIMIT_DIAGNOZY_W_RAM`] (`None`, tak samo jak przy
/// każdej innej porażce odczytu — patrz dokumentacja modułu).
pub fn analyze_ts_file(path: &std::path::Path) -> Option<TsAnalysis> {
    let rozmiar = std::fs::metadata(path).ok()?.len();
    if rozmiar > LIMIT_DIAGNOZY_W_RAM {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    analyze_ts(&bytes)
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// REGRESJA: plik większy niż `LIMIT_DIAGNOZY_W_RAM` musi zostać
    /// odrzucony przed wczytaniem w całości do pamięci. Plik rzadki
    /// (sparse) - tani i szybki.
    #[test]
    fn test_analyze_ts_file_odrzuca_plik_wiekszy_niz_limit() {
        let dir = tempfile::tempdir().unwrap();
        let sciezka = dir.path().join("ogromny.ts");
        let plik = std::fs::File::create(&sciezka).unwrap();
        plik.set_len(LIMIT_DIAGNOZY_W_RAM + 1).unwrap();
        drop(plik);

        assert_eq!(analyze_ts_file(&sciezka), None);
    }

    /// Buduje poprawny pakiet TS o zadanym PID i liczniku ciągłości.
    fn make_packet(pid: u16, cc: u8, with_payload: bool) -> Vec<u8> {
        let mut pkt = vec![0xAAu8; TS_PACKET_SIZE];
        pkt[0] = TS_SYNC_BYTE;
        pkt[1] = ((pid >> 8) & 0x1F) as u8;
        pkt[2] = (pid & 0xFF) as u8;
        pkt[3] = if with_payload { 0x10 } else { 0x00 } | (cc & 0x0F);
        pkt
    }

    fn build_stream(count: usize, pid: u16) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..count {
            out.extend(make_packet(pid, (i % 16) as u8, true));
        }
        out
    }

    // ------------------------------------------------------------------
    // detect_packet_layout
    // ------------------------------------------------------------------

    #[test]
    fn test_detect_standard_ts_layout() {
        let stream = build_stream(10, 256);
        assert_eq!(detect_packet_layout(&stream), Some((TS_PACKET_SIZE, 0)));
    }

    #[test]
    fn test_detect_m2ts_layout_with_timestamp_prefix() {
        // M2TS: 4 bajty znacznika czasu + 188 bajtów pakietu
        let mut stream = Vec::new();
        for i in 0..10 {
            stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            stream.extend(make_packet(256, (i % 16) as u8, true));
        }
        assert_eq!(detect_packet_layout(&stream), Some((M2TS_PACKET_SIZE, 0)));
    }

    #[test]
    fn test_detect_skips_leading_garbage() {
        // Śmieci na początku (typowe po odzysku), potem prawdziwy strumień
        let mut stream = vec![0xFFu8; 37];
        stream.extend(build_stream(10, 256));
        let (size, start) = detect_packet_layout(&stream).expect("powinien znaleźć strumień mimo śmieci");
        assert_eq!(size, TS_PACKET_SIZE);
        assert_eq!(start, 37);
    }

    #[test]
    fn test_detect_rejects_non_ts_data() {
        assert!(detect_packet_layout(b"to na pewno nie jest strumien transportowy MPEG").is_none());
        assert!(detect_packet_layout(&vec![0x00u8; 5000]).is_none());
    }

    #[test]
    fn test_detect_rejects_single_lucky_sync_byte() {
        // Pojedynczy bajt 0x47 w losowych danych NIE może zostać uznany za
        // strumień - wymagamy 5 kolejnych trafień co 188 bajtów.
        let mut data = vec![0x00u8; 5000];
        data[0] = TS_SYNC_BYTE;
        assert!(detect_packet_layout(&data).is_none());
    }

    // ------------------------------------------------------------------
    // analyze_ts - strumień zdrowy
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_healthy_stream() {
        let stream = build_stream(32, 256);
        let a = analyze_ts(&stream).unwrap();
        assert_eq!(a.total_packets, 32);
        assert_eq!(a.sync_losses, 0);
        assert_eq!(a.continuity_errors, 0);
        assert_eq!(a.trailing_garbage_bytes, 0);
        assert_eq!(a.distinct_pids, 1);
        assert!(a.is_healthy());
        assert_eq!(a.loss_percentage(), 0.0);
    }

    #[test]
    fn test_analyze_multiple_pids_counted_separately() {
        // Dwa przeplatane strumienie (np. wideo + audio) - każdy ma WŁASNY
        // licznik ciągłości, więc przeplot NIE może dawać fałszywych luk.
        let mut stream = Vec::new();
        for i in 0..16 {
            stream.extend(make_packet(256, (i % 16) as u8, true));
            stream.extend(make_packet(257, (i % 16) as u8, true));
        }
        let a = analyze_ts(&stream).unwrap();
        assert_eq!(a.distinct_pids, 2);
        assert_eq!(a.continuity_errors, 0, "Przeplot dwóch PID-ów nie jest luką w ciągłości");
        assert!(a.is_healthy());
    }

    // ------------------------------------------------------------------
    // analyze_ts - wykrywanie uszkodzeń
    // ------------------------------------------------------------------

    #[test]
    fn test_analyze_detects_continuity_gap() {
        // Budujemy strumień z DZIURĄ: liczniki 0,1,2, potem skok na 7
        // (pakiety 3,4,5,6 zginęły = 4 zgubione).
        let mut stream = Vec::new();
        for cc in [0u8, 1, 2, 7, 8, 9] {
            stream.extend(make_packet(256, cc, true));
        }
        let a = analyze_ts(&stream).unwrap();
        assert_eq!(a.total_packets, 6);
        assert_eq!(a.continuity_errors, 1, "Jedna luka");
        assert_eq!(a.estimated_lost_packets, 4, "Skok z 2 na 7 = 4 zgubione pakiety");
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_detects_multiple_gaps() {
        let mut stream = Vec::new();
        for cc in [0u8, 1, 5, 6, 12] {
            stream.extend(make_packet(256, cc, true));
        }
        let a = analyze_ts(&stream).unwrap();
        assert_eq!(a.continuity_errors, 2);
        assert_eq!(a.estimated_lost_packets, 3 + 5, "Skoki 1->5 (3 zgubione) i 6->12 (5 zgubionych)");
    }

    #[test]
    fn test_analyze_counts_repeated_cc_as_fifteen_lost() {
        // Powtórzony ten sam licznik (3, potem znowu 3) oznacza skok o 15,
        // NIE o 16: oczekiwano 4, przyszło 3, więc (3-4) mod 16 = 15.
        // Pełne 16 jest nieodróżnialne od zera zgubionych pakietów - to
        // fundamentalne ograniczenie 4-bitowego licznika, nie błąd analizy.
        let mut stream = Vec::new();
        for cc in [3u8, 3] {
            stream.extend(make_packet(256, cc, true));
        }
        let a = analyze_ts(&stream).unwrap();
        assert_eq!(a.continuity_errors, 1);
        assert_eq!(a.estimated_lost_packets, 15);
    }

    #[test]
    fn test_analyze_detects_sync_loss() {
        let mut stream = build_stream(10, 256);
        // Psujemy bajt synchronizacji piątego pakietu
        stream[4 * TS_PACKET_SIZE] = 0x00;
        let a = analyze_ts(&stream).unwrap();
        assert_eq!(a.sync_losses, 1);
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_detects_truncated_file() {
        let mut stream = build_stream(10, 256);
        stream.truncate(stream.len() - 50); // ostatni pakiet niepełny
        let a = analyze_ts(&stream).unwrap();
        assert_eq!(a.total_packets, 9);
        assert_eq!(a.trailing_garbage_bytes, 138, "188 - 50 = 138 bajtów niepełnego pakietu");
        assert!(!a.is_healthy());
    }

    #[test]
    fn test_analyze_ignores_cc_on_packets_without_payload() {
        // Pakiety BEZ payloadu nie inkrementują licznika - gdyby analiza tego
        // nie uwzględniała, dawałaby fałszywe alarmy przy każdym takim pakiecie.
        let mut stream = Vec::new();
        stream.extend(make_packet(256, 0, true));
        stream.extend(make_packet(256, 0, false)); // bez payloadu, ten sam CC
        stream.extend(make_packet(256, 0, false));
        stream.extend(make_packet(256, 1, true));  // kontynuacja
        let a = analyze_ts(&stream).unwrap();
        assert_eq!(a.continuity_errors, 0, "Pakiety bez payloadu nie mogą generować fałszywych luk");
        assert!(a.is_healthy());
    }

    #[test]
    fn test_analyze_rejects_non_ts_file() {
        assert!(analyze_ts(b"zwykly tekst, nie strumien").is_none());
    }

    // ------------------------------------------------------------------
    // loss_percentage / describe
    // ------------------------------------------------------------------

    #[test]
    fn test_loss_percentage_calculation() {
        let mut stream = Vec::new();
        for cc in [0u8, 5] { stream.extend(make_packet(256, cc, true)); }
        let a = analyze_ts(&stream).unwrap();
        // 2 odebrane + 4 zgubione = 6 oczekiwanych; 4/6 = 66.67%
        assert!((a.loss_percentage() - 66.666).abs() < 0.01);
    }

    #[test]
    fn test_describe_healthy_mentions_packet_count() {
        let a = analyze_ts(&build_stream(16, 256)).unwrap();
        let d = a.describe();
        assert!(d.contains("spójny"));
        assert!(d.contains("16 pakietów"));
    }

    #[test]
    fn test_describe_damaged_lists_all_problems() {
        // Strumień z luką w ciągłości ORAZ uciętym ostatnim pakietem -
        // opis musi wymienić OBA problemy, nie tylko pierwszy napotkany.
        let mut stream = Vec::new();
        for cc in [0u8, 1, 2, 7, 8, 9] { stream.extend(make_packet(256, cc, true)); }
        stream.truncate(stream.len() - 20);
        let a = analyze_ts(&stream).unwrap();
        let d = a.describe();
        assert!(d.contains("luk"), "Opis powinien wymienić luki w ciągłości: {}", d);
        assert!(d.contains("ucięty"), "Opis powinien wymienić ucięcie pliku: {}", d);
    }

    // ------------------------------------------------------------------
    // is_ts_extension
    // ------------------------------------------------------------------

    #[test]
    fn test_is_ts_extension() {
        assert!(is_ts_extension("nagranie.ts"));
        assert!(is_ts_extension("NAGRANIE.TS"));
        assert!(is_ts_extension("bluray.m2ts"));
        assert!(is_ts_extension("kamera.mts"));
        assert!(!is_ts_extension("film.mp4"));
        assert!(!is_ts_extension("skrypt.typescript"));
    }

    // ------------------------------------------------------------------
    // Składanie z dwóch kopii — materiał budowany bajt po bajcie
    // ------------------------------------------------------------------

    /// Buduje pakiet 188 B o zadanym PID, liczniku ciągłości i fladze błędu.
    /// `wypelniacz` pozwala rozróżnić, z której kopii pochodzi wynik.
    fn pakiet(pid: u16, cc: u8, blad_transportu: bool, wypelniacz: u8) -> Vec<u8> {
        let mut p = Vec::with_capacity(TS_PACKET_SIZE);
        p.push(TS_SYNC_BYTE);
        let mut b1 = ((pid >> 8) as u8) & 0x1F;
        if blad_transportu {
            b1 |= MASKA_BLEDU_TRANSPORTU;
        }
        p.push(b1);
        p.push((pid & 0xFF) as u8);
        p.push(0x10 | (cc & 0x0F)); // bit 0x10 = pakiet niesie payload
        p.resize(TS_PACKET_SIZE, wypelniacz);
        p
    }

    /// Buduje pakiet w układzie M2TS: 4-bajtowy prefiks czasu, potem 188 B.
    fn pakiet_m2ts(pid: u16, cc: u8, wypelniacz: u8) -> Vec<u8> {
        let mut p = vec![0u8; 4];
        p.extend(pakiet(pid, cc, false, wypelniacz));
        p
    }

    fn strumien(pakiety: &[Vec<u8>]) -> Vec<u8> {
        pakiety.iter().flatten().copied().collect()
    }

    /// Zdrowy strumień: jeden PID, licznik rosnący od zera.
    fn zdrowy(ile: usize, wypelniacz: u8) -> Vec<u8> {
        strumien(&(0..ile).map(|i| pakiet(0x100, (i % 16) as u8, false, wypelniacz)).collect::<Vec<_>>())
    }

    #[test]
    fn test_zdrowy_strumien_zlozony_sam_ze_soba_nic_nie_zmienia() {
        let a = zdrowy(6, 0xAA);
        assert_eq!(splice_ts(&a, &a).as_deref(), Some(a.as_slice()));
    }

    /// Sedno mechanizmu TS: pakiet z ustawioną flagą błędu transportu musi
    /// zostać zastąpiony wersją z drugiej kopii.
    #[test]
    fn test_pakiet_z_flaga_bledu_jest_zastepowany() {
        let mut a_pakiety: Vec<Vec<u8>> = (0..4).map(|i| pakiet(0x100, i as u8, false, 0xAA)).collect();
        // Trzeci pakiet kopii A dotarł uszkodzony - sprzęt oznaczył to flagą.
        a_pakiety[2] = pakiet(0x100, 2, true, 0xAA);

        let a = strumien(&a_pakiety);
        let b = zdrowy(4, 0xBB);

        let wynik = splice_ts(&a, &b).expect("kopia B ma zdrowy pakiet - składanie musi się udać");

        let trzeci = &wynik[2 * TS_PACKET_SIZE..3 * TS_PACKET_SIZE];
        assert_eq!(trzeci[4], 0xBB, "pakiet z flagą błędu musi zostać wzięty z kopii B");
        assert_eq!(trzeci[1] & MASKA_BLEDU_TRANSPORTU, 0, "wynik nie może nieść flagi błędu");

        // Pozostałe pakiety zostają z kopii A - naprawa jest minimalna.
        assert_eq!(wynik[4], 0xAA, "pierwszy pakiet pochodzi z kopii A");
    }

    #[test]
    fn test_pakiet_zepsuty_po_obu_stronach_blokuje_skladanie() {
        let a = strumien(&[pakiet(0x100, 0, false, 0xAA), pakiet(0x100, 1, true, 0xAA)]);
        let b = strumien(&[pakiet(0x100, 0, false, 0xBB), pakiet(0x100, 1, true, 0xBB)]);

        assert!(
            splice_ts(&a, &b).is_none(),
            "nie ma z czego wybrać - składanie musi odmówić, a nie zapisać pakiet oznaczony jako błędny"
        );
    }

    /// Gdy OBA pakiety są formalnie sprawne, decyduje licznik ciągłości.
    ///
    /// Bez tego pierwszeństwa wygrywałaby kopia A tylko dlatego, że jest
    /// pierwsza — i wynik niósłby lukę w liczniku, czyli dowód utraty pakietu
    /// tam, gdzie pakiet był dostępny po drugiej stronie.
    #[test]
    fn test_o_wyborze_decyduje_ciaglosc_gdy_oba_pakiety_sa_sprawne() {
        let a = strumien(&[
            pakiet(0x100, 0, false, 0xAA),
            pakiet(0x100, 9, false, 0xAA), // licznik przekłamany: powinno być 1
        ]);
        let b = strumien(&[
            pakiet(0x100, 0, false, 0xBB),
            pakiet(0x100, 1, false, 0xBB), // ciągłość zachowana
        ]);

        let wynik = splice_ts(&a, &b).expect("składanie musi się udać");

        let drugi = &wynik[TS_PACKET_SIZE..2 * TS_PACKET_SIZE];
        assert_eq!(drugi[3] & 0x0F, 1, "wybrany pakiet musi kontynuować licznik");
        assert_eq!(drugi[4], 0xBB, "czyli pochodzić z kopii B");
    }

    /// Różny układ siatki znaczy, że to nie są dwa odzyski tego samego pliku.
    #[test]
    fn test_rozny_uklad_siatki_blokuje_skladanie() {
        let a = zdrowy(4, 0xAA);
        let b = strumien(&(0..4).map(|i| pakiet_m2ts(0x100, i as u8, 0xBB)).collect::<Vec<_>>());

        assert_eq!(detect_packet_layout(&a).map(|(r, _)| r), Some(TS_PACKET_SIZE));
        assert_eq!(detect_packet_layout(&b).map(|(r, _)| r), Some(M2TS_PACKET_SIZE));

        assert!(splice_ts(&a, &b).is_none(), "188 B kontra 192 B - składanie musi odmówić");
    }

    #[test]
    fn test_material_niebedacy_strumieniem_nie_da_sie_zlozyc() {
        let a = zdrowy(4, 0xAA);
        assert!(splice_ts(b"to nie jest strumien", b"to tez nie").is_none());
        assert!(splice_ts(&a, b"smieci").is_none(), "jedna strona nieczytelna");
    }

    /// Kopia dłuższa uzupełnia pakiety, których w krótszej nie ma — to
    /// najczęstszy przypadek przy odzysku: plik ucięty w ogonie.
    #[test]
    fn test_dluzsza_kopia_uzupelnia_brakujace_pakiety() {
        let uciety = zdrowy(3, 0xAA);
        let pelny = zdrowy(6, 0xBB);

        let wynik = splice_ts(&uciety, &pelny).expect("składanie musi się udać");

        assert_eq!(wynik.len(), 6 * TS_PACKET_SIZE, "wynik musi mieć komplet pakietów");
        assert_eq!(wynik[4], 0xAA, "pakiety obecne w obu kopiach zostają z A");
        assert_eq!(wynik[4 * TS_PACKET_SIZE + 4], 0xBB, "brakujące pakiety pochodzą z B");
    }

    /// Prawdziwy strumień z ffmpeg — siatka 188 bajtów.
    #[test]
    #[ignore = "Wymaga image/test_fixture.ts. Uruchom z --ignored."]
    fn test_prawdziwy_ts_jest_spojny() {
        let bajty = std::fs::read("image/test_fixture.ts").expect("fixture musi istnieć");
        let a = analyze_ts(&bajty).expect("plik musi zostać rozpoznany jako TS");

        assert_eq!(a.packet_size, TS_PACKET_SIZE, "Zwykły .ts to siatka 188 bajtów");
        assert!(a.is_healthy(), "Świeżo zmuxowany strumień musi być spójny: {}", a.describe());
    }

    /// Wariant Blu-ray: 4-bajtowy znacznik czasu przed każdym pakietem.
    /// Ścieżka 192-bajtowa nie miała dotąd ŻADNEGO testu na prawdziwym pliku —
    /// tylko na pakietach budowanych w kodzie testu.
    #[test]
    #[ignore = "Wymaga image/test_fixture.m2ts. Uruchom z --ignored."]
    fn test_prawdziwy_m2ts_jest_rozpoznany_jako_siatka_192() {
        let bajty = std::fs::read("image/test_fixture.m2ts").expect("fixture musi istnieć");
        let a = analyze_ts(&bajty).expect("plik musi zostać rozpoznany jako M2TS");

        assert_eq!(a.packet_size, M2TS_PACKET_SIZE, "M2TS to siatka 192 bajtów");
        assert!(a.is_healthy(), "Strumień musi być spójny: {}", a.describe());
    }

    /// Oba warianty niosą TEN SAM materiał, więc muszą dać tę samą liczbę
    /// pakietów i strumieni — dowód, że prefiks czasowy jest poprawnie
    /// pomijany, a nie liczony jako dane.
    #[test]
    #[ignore = "Wymaga image/test_fixture.ts i image/test_fixture.m2ts. Uruchom z --ignored."]
    fn test_oba_warianty_daja_ten_sam_obraz_strumienia() {
        let ts = analyze_ts(&std::fs::read("image/test_fixture.ts").unwrap()).unwrap();
        let m2ts = analyze_ts(&std::fs::read("image/test_fixture.m2ts").unwrap()).unwrap();

        assert_eq!(ts.total_packets, m2ts.total_packets, "Ta sama liczba pakietów");
        assert_eq!(ts.describe(), m2ts.describe(), "Ten sam opis strumienia");
    }
}
