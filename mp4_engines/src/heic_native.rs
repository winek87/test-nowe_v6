// src/mp4_repair/heic_native.rs

//! # Zero-Donor dla HEIC — odbudowa indeksu `meta` bez drugiej kopii
//!
//! Odpowiednik [`super::engine_native`] dla obrazów: próba złożenia sprawnego
//! pliku wyłącznie z tego, co zostało w `mdat`, bez bliźniaka.
//!
//! ## Najpierw ograniczenie, bo ono kształtuje cały moduł
//!
//! W HEIC zakodowane obrazy leżą w `mdat`, ale **zestawy parametrów HEVC
//! (VPS/SPS/PPS) leżą w `hvcC`, czyli wewnątrz `iprp` → `meta`**. Bez nich
//! żaden dekoder nie ruszy ani jednego kafla: slice'y są zależne od SPS już na
//! poziomie parsowania nagłówka, nie tylko dekodowania pikseli.
//!
//! Pomiar na `image/test_fixture.heic` (aparat Samsung, 7 678 004 B):
//!
//! ```text
//! payloady 31 itemów `hvc1` w mdat:  31 × slice IDR (typ 20), 1 × PPS
//!                                    VPS: 0     SPS: 0
//! hvcC w iprp:                       VPS 24 B, SPS 36 B, PPS 9 B
//! item główny (pitm):                `grid` 5 × 6 kafli, wyjście 2944×2208
//! dane geometrii siatki:             w `idat` — a `idat` też jest WEWNĄTRZ meta
//! ```
//!
//! Zniszczenie `meta` zabiera więc naraz: zestawy parametrów, geometrię siatki
//! i indeks itemów. Dla TEGO materiału Zero-Donor jest **niemożliwy z zasady**,
//! nie „trudny" — brakujących bajtów nie ma nigdzie w pliku. Modułu, który
//! udawałby tu naprawę, nie da się napisać uczciwie: SPS-a nie można odgadnąć,
//! bo wybór CTB, głębi bitowej czy formatu chromy nie daje obrazu gorszego, a
//! obraz **inny** albo błąd dekodera.
//!
//! ## Co więc ten moduł robi
//!
//! Odbudowuje HEIC wtedy i tylko wtedy, gdy da się to **udowodnić** materiałem:
//!
//! 1. `mdat` musi być spójnym łańcuchem NAL-i z prefiksem długości (hipoteza
//!    walidowana przejściem do samego końca, patrz [`przejdz_lancuch_nal`]),
//! 2. w łańcuchu muszą być **wszystkie trzy** zestawy parametrów — część
//!    koderów zapisuje je również „w pasmie", obok `hvcC`, i tylko taki
//!    materiał nadaje się do odbudowy,
//! 3. liczba zakodowanych obrazów nie może wskazywać na siatkę kafli
//!    (patrz [`MAKS_OBRAZOW`]) — inaczej wynikiem byłby jeden kafel podany
//!    jako całe zdjęcie.
//!
//! Gdy którykolwiek warunek nie jest spełniony, moduł **odmawia z konkretną
//! diagnozą**. Na dostępnym fixture'cie odmawia z powodu 2 — i to jest wynik
//! poprawny, nie porażka.
//!
//! Przy spełnionych warunkach powstaje jednoitemowy HEIC: `ftyp` + `meta`
//! (`hdlr`, `pitm`, `iinf`/`infe`, `iprp`/`ipco`[`hvcC`, `ispe`]/`ipma`,
//! `iloc`) + `mdat` ze slice'ami wybranego obrazu. Wymiary do `ispe` pochodzą
//! z **parsowania SPS**, a nie z założenia.

use super::boxes::{find_box, parse_top_level_boxes};
use std::io;
use std::path::Path;

/// Górny limit rozmiaru pliku wczytywanego do odbudowy.
pub const LIMIT_W_RAM: u64 = 256 * 1024 * 1024; // 256 MB

/// Największa liczba zakodowanych obrazów, przy której odbudowa jest jeszcze
/// jednoznaczna.
///
/// Zwykły HEIC ma jeden obraz, często z miniaturą — stąd 2. Więcej obrazów
/// praktycznie zawsze znaczy **siatkę kafli**, a jej geometria (liczba wierszy
/// i kolumn oraz wymiary wyjściowe) mieszka w itemie `grid`, którego dane leżą
/// w `idat` **wewnątrz `meta`**. Przy zniszczonym `meta` nie ma z czego jej
/// odtworzyć: 30 kafli 512×512 daje się ułożyć w 5×6 i w 6×5, a to dwa różne,
/// równie „poprawne" obrazy. Zbudowanie pliku z jednego kafla i nazwanie tego
/// naprawą byłoby wprowadzaniem w błąd, dlatego moduł odmawia.
pub const MAKS_OBRAZOW: usize = 2;

/// Rozmiary prefiksu długości NAL-a próbowane po kolei.
///
/// `lengthSizeMinusOne` z `hvcC` jest nieznane (to `hvcC` właśnie zginęło),
/// więc hipotezę trzeba postawić i **zwalidować**: poprawny rozmiar to ten,
/// przy którym łańcuch długości trafia dokładnie w koniec danych. 4 jest
/// pierwsze, bo to wartość używana w praktyce przez wszystkie znane kodery.
const ROZMIARY_PREFIKSU: [usize; 3] = [4, 2, 1];

// Typy NAL-i HEVC istotne dla odbudowy.
const NAL_VPS: u8 = 32;
const NAL_SPS: u8 = 33;
const NAL_PPS: u8 = 34;

/// Czy typ NAL-a jest zakodowanym wycinkiem obrazu (VCL).
fn jest_slice(typ: u8) -> bool {
    typ <= 31
}

fn blad(rodzaj: io::ErrorKind, opis: String) -> io::Error {
    io::Error::new(rodzaj, opis)
}

/// Jednostka NAL zlokalizowana w buforze.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nal {
    pub typ: u8,
    /// Offset pierwszego bajtu treści NAL-a (za prefiksem długości).
    pub od: usize,
    /// Offset za ostatnim bajtem treści.
    pub do_: usize,
}

impl Nal {
    pub fn dlugosc(&self) -> usize {
        self.do_.saturating_sub(self.od)
    }
}

/// Przechodzi bufor jako łańcuch NAL-i z prefiksem długości i zwraca listę
/// tylko wtedy, gdy łańcuch **domyka się dokładnie** na końcu bufora.
///
/// Domknięcie jest tu jedynym dostępnym dowodem, że zgadliśmy rozmiar
/// prefiksu: przy błędnym założeniu pierwsza długość wyprowadza poza sensowny
/// zakres albo łańcuch kończy się w środku bufora. Ta sama technika, którą
/// `jpeg_splice` stosuje do walidacji łańcucha segmentów.
pub fn przejdz_lancuch_nal(dane: &[u8], rozmiar_prefiksu: usize) -> Option<Vec<Nal>> {
    if dane.is_empty() || rozmiar_prefiksu == 0 || rozmiar_prefiksu > 4 {
        return None;
    }

    let mut nale = Vec::new();
    let mut p = 0usize;

    while p < dane.len() {
        if p + rozmiar_prefiksu + 2 > dane.len() {
            return None;
        }

        let mut dlugosc = 0usize;
        for i in 0..rozmiar_prefiksu {
            dlugosc = (dlugosc << 8) | dane[p + i] as usize;
        }

        if dlugosc < 2 {
            return None;
        }

        let od = p + rozmiar_prefiksu;
        let do_ = od.checked_add(dlugosc)?;
        if do_ > dane.len() {
            return None;
        }

        // Bit zerowy nagłówka NAL-a HEVC jest zarezerwowany i zawsze 0 -
        // tani, ale skuteczny filtr błędnych hipotez.
        if dane[od] & 0x80 != 0 {
            return None;
        }

        nale.push(Nal { typ: (dane[od] >> 1) & 0x3F, od, do_ });
        p = do_;
    }

    if nale.is_empty() { None } else { Some(nale) }
}

/// Rozpoznaje rozmiar prefiksu długości i zwraca listę NAL-i.
pub fn rozpoznaj_lancuch(dane: &[u8]) -> Option<(usize, Vec<Nal>)> {
    ROZMIARY_PREFIKSU
        .iter()
        .find_map(|&r| przejdz_lancuch_nal(dane, r).map(|n| (r, n)))
}

/// Zestawy parametrów znalezione „w pasmie", w `mdat`.
#[derive(Debug, Clone)]
pub struct ZestawyParametrow {
    pub vps: Vec<u8>,
    pub sps: Vec<u8>,
    pub pps: Vec<u8>,
}

/// Wyszukuje VPS, SPS i PPS wśród NAL-i. Bierze pierwsze wystąpienie każdego.
pub fn zestawy_parametrow(dane: &[u8], nale: &[Nal]) -> Option<ZestawyParametrow> {
    let wez = |typ: u8| {
        nale.iter()
            .find(|n| n.typ == typ)
            .map(|n| dane[n.od..n.do_].to_vec())
    };

    Some(ZestawyParametrow {
        vps: wez(NAL_VPS)?,
        sps: wez(NAL_SPS)?,
        pps: wez(NAL_PPS)?,
    })
}

// ============================================================================
// Parsowanie SPS
// ============================================================================

/// Usuwa bajty zapobiegania emulacji (`00 00 03` → `00 00`).
///
/// Bez tego kroku każde parsowanie pól SPS-a rozjedzie się na pierwszym takim
/// trójbajcie — a w rzeczywistym SPS-ie występują one regularnie, bo flagi
/// zgodności profilu to długie ciągi zer.
pub fn usun_zapobieganie_emulacji(dane: &[u8]) -> Vec<u8> {
    let mut wynik = Vec::with_capacity(dane.len());
    let mut zera = 0usize;

    for &b in dane {
        if zera >= 2 && b == 0x03 {
            zera = 0;
            continue;
        }
        if b == 0x00 { zera += 1; } else { zera = 0; }
        wynik.push(b);
    }

    wynik
}

/// Czytnik bitów dla pól o zmiennej długości (u(n) i ue(v)).
struct CzytnikBitow<'a> {
    dane: &'a [u8],
    bit: usize,
}

impl<'a> CzytnikBitow<'a> {
    fn nowy(dane: &'a [u8]) -> Self {
        Self { dane, bit: 0 }
    }

    fn bit(&mut self) -> Option<u32> {
        let bajt = self.bit / 8;
        if bajt >= self.dane.len() {
            return None;
        }
        let przesuniecie = 7 - (self.bit % 8);
        self.bit += 1;
        Some(((self.dane[bajt] >> przesuniecie) & 1) as u32)
    }

    fn u(&mut self, ile: usize) -> Option<u32> {
        if ile > 32 {
            return None;
        }
        let mut wartosc = 0u32;
        for _ in 0..ile {
            wartosc = (wartosc << 1) | self.bit()?;
        }
        Some(wartosc)
    }

    fn pomin(&mut self, ile: usize) -> Option<()> {
        for _ in 0..ile {
            self.bit()?;
        }
        Some(())
    }

    /// Wykładniczy kod Golomba bez znaku.
    fn ue(&mut self) -> Option<u32> {
        let mut zer = 0usize;
        while self.bit()? == 0 {
            zer += 1;
            // Kod dłuższy niż 32 bity zer to na pewno nie poprawny SPS, a
            // rozjechane parsowanie - lepiej zawieść niż pętlić. Próg to
            // `>= 32`, NIE `> 32`: `zer == 32` przepuszczony dalej dawał
            // `1u32 << 32` niżej - przesunięcie o pełną szerokość typu, co
            // panikuje w kompilacji debug (`cargo test`) i daje błędną
            // wartość w release. 32-bitowy akumulator `u32` i tak nie mieści
            // wartości wymagającej 32 wiodących zer.
            if zer >= 32 {
                return None;
            }
        }
        if zer == 0 {
            return Some(0);
        }
        let reszta = self.u(zer)?;
        Some((1u32 << zer) - 1 + reszta)
    }
}

/// Pomija strukturę `profile_tier_level`, zgodnie z H.265 §7.3.3.
fn pomin_profile_tier_level(r: &mut CzytnikBitow, maks_podwarstw_minus1: u32) -> Option<()> {
    // general_profile_space(2) + general_tier_flag(1) + general_profile_idc(5)
    r.pomin(8)?;
    // general_profile_compatibility_flag[32]
    r.pomin(32)?;
    // progressive/interlaced/non_packed/frame_only + 43 bity zarezerwowane + inbld
    r.pomin(48)?;
    // general_level_idc(8)
    r.pomin(8)?;

    let mut profil = Vec::new();
    let mut poziom = Vec::new();
    for _ in 0..maks_podwarstw_minus1 {
        profil.push(r.u(1)?);
        poziom.push(r.u(1)?);
    }

    if maks_podwarstw_minus1 > 0 {
        for _ in maks_podwarstw_minus1..8 {
            r.pomin(2)?;
        }
    }

    for i in 0..maks_podwarstw_minus1 as usize {
        if profil[i] == 1 {
            r.pomin(88)?;
        }
        if poziom[i] == 1 {
            r.pomin(8)?;
        }
    }

    Some(())
}

/// Pola SPS-a potrzebne do odbudowy `hvcC` i `ispe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpisSps {
    pub szerokosc: u32,
    pub wysokosc: u32,
    pub format_chromy: u32,
    pub glebia_luma_minus8: u32,
    pub glebia_chroma_minus8: u32,
    pub liczba_podwarstw: u32,
    pub zagniezdzenie_temporalne: u32,
}

/// Parsuje SPS w postaci pełnego NAL-a (z 2-bajtowym nagłówkiem).
///
/// Wymiary są zwracane **po przycięciu okna zgodności** (`conformance
/// window`), bo to one są prawdziwymi wymiarami obrazu — `pic_width_in_luma_samples`
/// bywa zaokrąglone w górę do wielokrotności rozmiaru CTB.
pub fn parsuj_sps(nal_sps: &[u8]) -> Option<OpisSps> {
    if nal_sps.len() < 3 {
        return None;
    }

    let rbsp = usun_zapobieganie_emulacji(&nal_sps[2..]);
    let mut r = CzytnikBitow::nowy(&rbsp);

    r.pomin(4)?; // sps_video_parameter_set_id
    let maks_podwarstw_minus1 = r.u(3)?;
    let zagniezdzenie = r.u(1)?;

    pomin_profile_tier_level(&mut r, maks_podwarstw_minus1)?;

    r.ue()?; // sps_seq_parameter_set_id
    let format_chromy = r.ue()?;
    if format_chromy == 3 {
        r.pomin(1)?; // separate_colour_plane_flag
    }

    let szerokosc_luma = r.ue()?;
    let wysokosc_luma = r.ue()?;

    let (mut szerokosc, mut wysokosc) = (szerokosc_luma, wysokosc_luma);

    if r.u(1)? == 1 {
        let lewy = r.ue()?;
        let prawy = r.ue()?;
        let gorny = r.ue()?;
        let dolny = r.ue()?;

        // Offsety okna zgodności liczone są w jednostkach chromy.
        let (pod_szer, pod_wys) = match format_chromy {
            1 => (2, 2), // 4:2:0
            2 => (2, 1), // 4:2:2
            _ => (1, 1), // 4:4:4 i monochrom
        };

        // Liczone w u64: `lewy`/`prawy`/`gorny`/`dolny` pochodzą z `ue()` na
        // NIEZAUFANYCH bajtach SPS i mogą być bliskie u32::MAX. Poprzednie
        // `pod_szer * (lewy + prawy)` liczyło w u32 - dodawanie i mnożenie
        // mogły przepełnić TYP ZANIM `saturating_sub` dostał szansę cokolwiek
        // ochronić (panika w debug, cicho złe wymiary w release). W u64 ani
        // dodawanie, ani mnożenie dwóch wartości u32 nie przepełnia.
        let ciecie_szer = (pod_szer as u64) * (lewy as u64 + prawy as u64);
        let ciecie_wys = (pod_wys as u64) * (gorny as u64 + dolny as u64);
        szerokosc = (szerokosc as u64).saturating_sub(ciecie_szer) as u32;
        wysokosc = (wysokosc as u64).saturating_sub(ciecie_wys) as u32;
    }

    let glebia_luma_minus8 = r.ue()?;
    let glebia_chroma_minus8 = r.ue()?;

    if szerokosc == 0 || wysokosc == 0 {
        return None;
    }

    Some(OpisSps {
        szerokosc,
        wysokosc,
        format_chromy,
        glebia_luma_minus8,
        glebia_chroma_minus8,
        liczba_podwarstw: maks_podwarstw_minus1 + 1,
        zagniezdzenie_temporalne: zagniezdzenie,
    })
}

// ============================================================================
// Budowanie pudełek
// ============================================================================

fn pudelko(typ: &[u8; 4], tresc: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + tresc.len());
    out.extend_from_slice(&((8 + tresc.len()) as u32).to_be_bytes());
    out.extend_from_slice(typ);
    out.extend_from_slice(tresc);
    out
}

fn pelne_pudelko(typ: &[u8; 4], wersja: u8, flagi: u32, tresc: &[u8]) -> Vec<u8> {
    let mut ciało = Vec::with_capacity(4 + tresc.len());
    ciało.push(wersja);
    ciało.extend_from_slice(&flagi.to_be_bytes()[1..]);
    ciało.extend_from_slice(tresc);
    pudelko(typ, &ciało)
}

/// Składa `hvcC` z zestawów parametrów i opisu SPS-a.
///
/// Bajty `profile_tier_level` są **kopiowane wprost z SPS-a**, a nie
/// odtwarzane z pól: w SPS-ie ta struktura zaczyna się na granicy bajtu (po
/// dokładnie 8 bitach: `vps_id`(4) + `max_sub_layers_minus1`(3) +
/// `temporal_id_nesting_flag`(1)) i zajmuje równe 12 bajtów, a w `hvcC` stoi w
/// tym samym układzie. Przepisywanie ich pole po polu byłoby okazją do
/// pomyłki bez żadnego zysku — sprawdzone na prawdziwym `hvcC`, gdzie oba
/// fragmenty są identyczne bajt w bajt.
pub fn zbuduj_hvcc(zestawy: &ZestawyParametrow, sps: &OpisSps) -> Option<Vec<u8>> {
    let rbsp_sps = usun_zapobieganie_emulacji(&zestawy.sps[2..]);
    if rbsp_sps.len() < 13 {
        return None;
    }

    let mut c = Vec::with_capacity(32 + zestawy.vps.len() + zestawy.sps.len() + zestawy.pps.len());

    c.push(1); // configurationVersion
    c.extend_from_slice(&rbsp_sps[1..13]); // profile_tier_level (12 B)

    c.extend_from_slice(&[0xF0, 0x00]); // min_spatial_segmentation_idc = 0
    c.push(0xFC); // parallelismType = 0
    c.push(0xFC | (sps.format_chromy as u8 & 0x03));
    c.push(0xF8 | (sps.glebia_luma_minus8 as u8 & 0x07));
    c.push(0xF8 | (sps.glebia_chroma_minus8 as u8 & 0x07));
    c.extend_from_slice(&[0x00, 0x00]); // avgFrameRate = 0 (nieznane)

    // constantFrameRate(2)=0 | numTemporalLayers(3) | temporalIdNested(1) |
    // lengthSizeMinusOne(2)=3
    let temporalne = ((sps.liczba_podwarstw as u8 & 0x07) << 3)
        | ((sps.zagniezdzenie_temporalne as u8 & 0x01) << 2)
        | 0x03;
    c.push(temporalne);

    c.push(3); // numOfArrays: VPS, SPS, PPS

    for (typ, dane) in [
        (NAL_VPS, &zestawy.vps),
        (NAL_SPS, &zestawy.sps),
        (NAL_PPS, &zestawy.pps),
    ] {
        // array_completeness(1)=1 | reserved(1)=0 | NAL_unit_type(6)
        c.push(0x80 | typ);
        c.extend_from_slice(&1u16.to_be_bytes());
        c.extend_from_slice(&(dane.len() as u16).to_be_bytes());
        c.extend_from_slice(dane);
    }

    Some(pudelko(b"hvcC", &c))
}

/// Wynik odbudowy: gotowe bajty i opis tego, na czym oparto decyzje.
#[derive(Debug, Clone)]
pub struct Odbudowa {
    pub bajty: Vec<u8>,
    pub szerokosc: u32,
    pub wysokosc: u32,
    pub liczba_obrazow: usize,
    pub rozmiar_prefiksu: usize,
}

impl Odbudowa {
    pub fn opis(&self) -> String {
        format!(
            "odbudowano indeks `meta` bez dawcy: {}×{} z parsowania SPS, \
             zestawy parametrów znalezione w pasmie w mdat, prefiks długości NAL {} B, \
             zakodowanych obrazów w materiale: {}",
            self.szerokosc, self.wysokosc, self.rozmiar_prefiksu, self.liczba_obrazow
        )
    }
}

/// Grupuje NAL-e w zakodowane obrazy.
///
/// Nowy obraz zaczyna się na NAL-u VCL, którego pierwszy bit nagłówka slice'a
/// (`first_slice_segment_in_pic_flag`) jest ustawiony. Ten bit stoi zaraz za
/// 2-bajtowym nagłówkiem NAL-a, więc jest czytelny bez SPS-a — jedno z
/// niewielu pól, o których da się cokolwiek powiedzieć przy zniszczonym
/// indeksie.
fn pogrupuj_obrazy(dane: &[u8], nale: &[Nal]) -> Vec<Vec<Nal>> {
    let mut obrazy: Vec<Vec<Nal>> = Vec::new();

    for &n in nale {
        if !jest_slice(n.typ) {
            continue;
        }

        let pierwszy_w_obrazie = dane
            .get(n.od + 2)
            .map(|b| b & 0x80 != 0)
            .unwrap_or(false);

        if pierwszy_w_obrazie || obrazy.is_empty() {
            obrazy.push(vec![n]);
        } else if let Some(ostatni) = obrazy.last_mut() {
            ostatni.push(n);
        }
    }

    obrazy
}

/// Odbudowuje jednoitemowy HEIC z zawartości `mdat` uszkodzonego pliku.
///
/// Warunki i uzasadnienie odmów są w dokumentacji modułu.
pub fn odbuduj_bajty(uszkodzony: &[u8]) -> io::Result<Odbudowa> {
    let atomy = parse_top_level_boxes(uszkodzony);
    let mdat = find_box(&atomy, b"mdat").ok_or_else(|| {
        blad(io::ErrorKind::NotFound, "plik nie ma czytelnego atomu `mdat` - nie ma z czego odbudowywać".to_string())
    })?;

    let (od, do_) = mdat.body_range();
    if do_ > uszkodzony.len() || od >= do_ {
        return Err(blad(io::ErrorKind::InvalidData, "atom `mdat` wykracza poza koniec pliku".to_string()));
    }
    let dane = &uszkodzony[od..do_];

    let (rozmiar_prefiksu, nale) = rozpoznaj_lancuch(dane).ok_or_else(|| {
        blad(
            io::ErrorKind::InvalidData,
            "zawartość `mdat` nie układa się w spójny łańcuch NAL-i z prefiksem długości \
             (sprawdzono prefiksy 4, 2 i 1 B) - w HEIC-u z itemami innymi niż obrazy \
             (Exif, XMP) łańcuch nie domyka się na całym mdat".to_string(),
        )
    })?;

    let zestawy = zestawy_parametrow(dane, &nale).ok_or_else(|| {
        blad(
            io::ErrorKind::NotFound,
            "w `mdat` nie ma wszystkich zestawów parametrów HEVC (VPS+SPS+PPS). \
             Zestawy parametrów HEIC trzyma w `hvcC`, czyli WEWNĄTRZ zniszczonego `meta`, \
             a bez SPS-a slice'y są nieodczytywalne dla każdego dekodera - odbudowa bez \
             dawcy nie jest tu możliwa (użyj wariantu z bliźniaczą kopią)".to_string(),
        )
    })?;

    let opis_sps = parsuj_sps(&zestawy.sps).ok_or_else(|| {
        blad(io::ErrorKind::InvalidData, "nie udało się sparsować SPS-a - bez wymiarów nie da się złożyć `ispe`".to_string())
    })?;

    let obrazy = pogrupuj_obrazy(dane, &nale);
    if obrazy.is_empty() {
        return Err(blad(io::ErrorKind::NotFound, "w `mdat` nie ma ani jednego zakodowanego obrazu".to_string()));
    }

    if obrazy.len() > MAKS_OBRAZOW {
        return Err(blad(
            io::ErrorKind::InvalidData,
            format!(
                "materiał zawiera {} zakodowanych obrazów, co wskazuje na siatkę kafli. \
                 Geometria siatki (liczba wierszy i kolumn) leży w itemie `grid`, którego dane \
                 są w `idat` WEWNĄTRZ zniszczonego `meta` - bez niej {} kafli da się ułożyć na \
                 wiele równie poprawnych sposobów, a wynikiem byłby jeden kafel podany jako całe \
                 zdjęcie. Odmawiam zamiast wprowadzać w błąd",
                obrazy.len(), obrazy.len()
            ),
        ));
    }

    // Największy obraz to obraz główny; mniejszy (jeśli jest) to miniatura.
    let glowny = obrazy
        .iter()
        .max_by_key(|o| o.iter().map(|n| n.dlugosc()).sum::<usize>())
        .expect("lista obrazów nie jest pusta");

    // --- mdat wyniku: slice'y obrazu głównego, prefiks znormalizowany do 4 B ---
    let mut ladunek = Vec::new();
    for n in glowny {
        ladunek.extend_from_slice(&(n.dlugosc() as u32).to_be_bytes());
        ladunek.extend_from_slice(&dane[n.od..n.do_]);
    }

    // --- meta ---
    let hvcc = zbuduj_hvcc(&zestawy, &opis_sps).ok_or_else(|| {
        blad(io::ErrorKind::InvalidData, "nie udało się złożyć `hvcC`".to_string())
    })?;

    let mut ispe_tresc = Vec::new();
    ispe_tresc.extend_from_slice(&opis_sps.szerokosc.to_be_bytes());
    ispe_tresc.extend_from_slice(&opis_sps.wysokosc.to_be_bytes());
    let ispe = pelne_pudelko(b"ispe", 0, 0, &ispe_tresc);

    let mut ipco_tresc = Vec::new();
    ipco_tresc.extend_from_slice(&hvcc);
    ipco_tresc.extend_from_slice(&ispe);
    let ipco = pudelko(b"ipco", &ipco_tresc);

    // ipma: item 1 -> właściwość 1 (hvcC, niezbędna) i 2 (ispe, opisowa)
    let mut ipma_tresc = Vec::new();
    ipma_tresc.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    ipma_tresc.extend_from_slice(&1u16.to_be_bytes()); // item_ID
    ipma_tresc.push(2); // association_count
    ipma_tresc.push(0x80 | 1); // essential = 1, property_index = 1 (hvcC)
    ipma_tresc.push(2); // essential = 0, property_index = 2 (ispe)
    let ipma = pelne_pudelko(b"ipma", 0, 0, &ipma_tresc);

    let mut iprp_tresc = Vec::new();
    iprp_tresc.extend_from_slice(&ipco);
    iprp_tresc.extend_from_slice(&ipma);
    let iprp = pudelko(b"iprp", &iprp_tresc);

    let mut hdlr_tresc = Vec::new();
    hdlr_tresc.extend_from_slice(&0u32.to_be_bytes()); // pre_defined
    hdlr_tresc.extend_from_slice(b"pict");
    hdlr_tresc.extend_from_slice(&[0u8; 12]); // reserved
    hdlr_tresc.push(0); // name (pusta, zakończona zerem)
    let hdlr = pelne_pudelko(b"hdlr", 0, 0, &hdlr_tresc);

    let pitm = pelne_pudelko(b"pitm", 0, 0, &1u16.to_be_bytes());

    let mut infe_tresc = Vec::new();
    infe_tresc.extend_from_slice(&1u16.to_be_bytes()); // item_ID
    infe_tresc.extend_from_slice(&0u16.to_be_bytes()); // item_protection_index
    infe_tresc.extend_from_slice(b"hvc1");
    infe_tresc.push(0); // item_name
    let infe = pelne_pudelko(b"infe", 2, 0, &infe_tresc);

    let mut iinf_tresc = Vec::new();
    iinf_tresc.extend_from_slice(&1u16.to_be_bytes()); // entry_count
    iinf_tresc.extend_from_slice(&infe);
    let iinf = pelne_pudelko(b"iinf", 0, 0, &iinf_tresc);

    // iloc z offsetem wstawionym tymczasowo - prawdziwy zna się dopiero po
    // policzeniu rozmiaru `meta`, ale pole ma stałą szerokość (4 B), więc
    // rozmiar się nie zmieni i wystarczy je potem nadpisać.
    let mut iloc_tresc = Vec::new();
    iloc_tresc.push(0x44); // offset_size = 4, length_size = 4
    iloc_tresc.push(0x00); // base_offset_size = 0, index_size = 0
    iloc_tresc.extend_from_slice(&1u16.to_be_bytes()); // item_count
    iloc_tresc.extend_from_slice(&1u16.to_be_bytes()); // item_ID
    iloc_tresc.extend_from_slice(&0u16.to_be_bytes()); // construction_method = 0
    iloc_tresc.extend_from_slice(&0u16.to_be_bytes()); // data_reference_index
    iloc_tresc.extend_from_slice(&1u16.to_be_bytes()); // extent_count
    let pozycja_offsetu_w_tresci = iloc_tresc.len();
    iloc_tresc.extend_from_slice(&0u32.to_be_bytes()); // extent_offset (do nadpisania)
    iloc_tresc.extend_from_slice(&(ladunek.len() as u32).to_be_bytes()); // extent_length
    let iloc = pelne_pudelko(b"iloc", 1, 0, &iloc_tresc);

    // Offset pola extent_offset względem początku pudełka `iloc`:
    // 8 (nagłówek) + 4 (wersja/flagi) + pozycja w treści.
    let offset_w_iloc = 8 + 4 + pozycja_offsetu_w_tresci;

    let mut meta_tresc = Vec::new();
    meta_tresc.extend_from_slice(&hdlr);
    meta_tresc.extend_from_slice(&pitm);
    meta_tresc.extend_from_slice(&iinf);
    meta_tresc.extend_from_slice(&iprp);
    let offset_iloc_w_meta = meta_tresc.len();
    meta_tresc.extend_from_slice(&iloc);
    let meta = pelne_pudelko(b"meta", 0, 0, &meta_tresc);

    let mut ftyp_tresc = Vec::new();
    ftyp_tresc.extend_from_slice(b"heic");
    ftyp_tresc.extend_from_slice(&0u32.to_be_bytes());
    ftyp_tresc.extend_from_slice(b"mif1");
    ftyp_tresc.extend_from_slice(b"heic");
    let ftyp = pudelko(b"ftyp", &ftyp_tresc);

    // Offset danych w gotowym pliku: ftyp + meta + nagłówek mdat.
    let offset_danych = ftyp.len() + meta.len() + 8;

    let mut wynik = Vec::with_capacity(offset_danych + ladunek.len());
    wynik.extend_from_slice(&ftyp);
    wynik.extend_from_slice(&meta);

    // Nadpisanie extent_offset: ftyp + nagłówek meta (8) + wersja/flagi (4)
    // + pozycja iloc w treści meta + offset pola w iloc.
    let bezwzgledny = ftyp.len() + 8 + 4 + offset_iloc_w_meta + offset_w_iloc;
    wynik[bezwzgledny..bezwzgledny + 4].copy_from_slice(&(offset_danych as u32).to_be_bytes());

    wynik.extend_from_slice(&pudelko(b"mdat", &ladunek));

    Ok(Odbudowa {
        bajty: wynik,
        szerokosc: opis_sps.szerokosc,
        wysokosc: opis_sps.wysokosc,
        liczba_obrazow: obrazy.len(),
        rozmiar_prefiksu,
    })
}

/// Wczytuje plik, pilnując limitu pamięci.
fn wczytaj(sciezka: &Path) -> io::Result<Vec<u8>> {
    let rozmiar = std::fs::metadata(sciezka)?.len();
    if rozmiar > LIMIT_W_RAM {
        return Err(blad(
            io::ErrorKind::InvalidInput,
            format!("plik {} ma {} B i przekracza limit odbudowy w RAM ({} B)", sciezka.display(), rozmiar, LIMIT_W_RAM),
        ));
    }
    std::fs::read(sciezka)
}

/// Odbudowuje HEIC bez dawcy, operując na plikach.
///
/// Wynik zapisywany jest dopiero po udanej odbudowie w pamięci, więc nieudana
/// próba nie zostawia pliku-widma.
pub fn repair(broken_file: &str, output_file: &str) -> io::Result<Odbudowa> {
    let uszkodzony = wczytaj(Path::new(broken_file))?;
    let odbudowa = odbuduj_bajty(&uszkodzony)?;

    if let Some(katalog) = Path::new(output_file).parent()
        && !katalog.as_os_str().is_empty() {
            std::fs::create_dir_all(katalog)?;
        }
    std::fs::write(output_file, &odbudowa.bajty)?;

    Ok(odbudowa)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Prawdziwe zestawy parametrów HEVC, wyjęte z `hvcC` fixture'a
    // `image/test_fixture.heic`. Wklejone jako stałe, żeby testy parsowania i
    // budowania `hvcC` działały bez pliku na dysku - to materiał realny, nie
    // wymyślony.
    const VPS: [u8; 24] = [
        0x40, 0x01, 0x0c, 0x01, 0xff, 0xff, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00,
        0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x78, 0x3c, 0x09,
    ];
    const SPS: [u8; 36] = [
        0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00,
        0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x78, 0xa0, 0x04, 0x02, 0x00, 0x80,
        0x5a, 0x3d, 0x2b, 0xb2, 0x5b, 0xc0, 0x1b, 0x82, 0x83, 0x03, 0x00, 0x40,
    ];
    const PPS: [u8; 9] = [0x44, 0x01, 0xc0, 0x24, 0x11, 0x58, 0x19, 0x8c, 0x80];

    /// Prawdziwe `hvcC` z fixture'a — wzorzec do porównania.
    const HVCC_WZORCOWY: [u8; 107] = [
        0x01, 0x01, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x78, 0xf0, 0x00, 0xfc, 0xfd, 0xf8, 0xf8, 0x00, 0x00, 0x03, 0x03, 0x20,
        0x00, 0x01, 0x00, 0x18, 0x40, 0x01, 0x0c, 0x01, 0xff, 0xff, 0x01, 0x60,
        0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03,
        0x00, 0x78, 0x3c, 0x09, 0x21, 0x00, 0x01, 0x00, 0x24, 0x42, 0x01, 0x01,
        0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00,
        0x00, 0x03, 0x00, 0x78, 0xa0, 0x04, 0x02, 0x00, 0x80, 0x5a, 0x3d, 0x2b,
        0xb2, 0x5b, 0xc0, 0x1b, 0x82, 0x83, 0x03, 0x00, 0x40, 0x22, 0x00, 0x01,
        0x00, 0x09, 0x44, 0x01, 0xc0, 0x24, 0x11, 0x58, 0x19, 0x8c, 0x80,
    ];

    fn zestawy() -> ZestawyParametrow {
        ZestawyParametrow { vps: VPS.to_vec(), sps: SPS.to_vec(), pps: PPS.to_vec() }
    }

    /// Dokleja 4-bajtowy prefiks długości.
    fn z_prefiksem(nal: &[u8]) -> Vec<u8> {
        let mut v = (nal.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(nal);
        v
    }

    /// Buduje minimalny plik HEIC-podobny: `ftyp` + `mdat` o podanej treści.
    /// `meta` celowo NIE MA — to jest dokładnie plik do odbudowy.
    fn plik_bez_meta(ladunek: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&pudelko(b"ftyp", b"heic\x00\x00\x00\x00mif1heic"));
        v.extend_from_slice(&pudelko(b"mdat", ladunek));
        v
    }

    /// Syntetyczny slice VCL z ustawionym `first_slice_segment_in_pic_flag`.
    fn slice_syntetyczny(dlugosc: usize) -> Vec<u8> {
        // Nagłówek NAL: typ 20 (IDR_W_RADL) -> bajt0 = 20<<1 = 0x28.
        let mut v = vec![0x28, 0x01, 0x80];
        v.resize(dlugosc.max(3), 0x5A);
        v
    }

    // ------------------------------------------------------------------
    // Czytnik bitów i kod Golomba
    // ------------------------------------------------------------------

    #[test]
    fn test_czytnik_bitow_czyta_pola_o_dowolnej_szerokosci() {
        let dane = [0b1011_0010, 0b0100_0001];
        let mut r = CzytnikBitow::nowy(&dane);

        assert_eq!(r.u(1), Some(1));
        assert_eq!(r.u(3), Some(0b011));
        assert_eq!(r.u(4), Some(0b0010));
        assert_eq!(r.u(8), Some(0b0100_0001));
        assert_eq!(r.u(1), None, "za końcem danych musi zwrócić None, nie zera");
    }

    #[test]
    fn test_kod_golomba_na_znanych_wektorach() {
        // ue(v): '1'->0, '010'->1, '011'->2, '00100'->3, '00111'->6
        let przypadki: [(&[u8], u32); 4] = [
            (&[0b1000_0000], 0),
            (&[0b0100_0000], 1),
            (&[0b0110_0000], 2),
            (&[0b0010_0000], 3),
        ];
        for (dane, oczekiwane) in przypadki {
            assert_eq!(CzytnikBitow::nowy(dane).ue(), Some(oczekiwane), "dane {:08b}", dane[0]);
        }
    }

    #[test]
    fn test_kod_golomba_nie_petli_na_smieciach() {
        // Same zera to kod bez końca - musi zawieść, a nie kręcić się w pętli.
        let zera = [0u8; 16];
        assert_eq!(CzytnikBitow::nowy(&zera).ue(), None);
    }

    /// REGRESJA na off-by-one w progu `zer >= 32` (wcześniej `zer > 32`).
    ///
    /// DOKŁADNIE 32 wiodące bity zerowe, potem terminator '1' i tyle danych,
    /// żeby `u(32)` miało co czytać. Pod starym progiem (`zer > 32`) `zer==32`
    /// PRZECHODZIŁO dalej i trafiało na `1u32 << 32` - przesunięcie o pełną
    /// szerokość typu, panikujące w kompilacji debug (czyli w `cargo test`).
    /// Test `..._nie_petli_na_smieciach` powyżej tego NIE łapał: same zera
    /// zwracają `None` już w PĘTLI liczącej zera, zanim kod doszedłby do
    /// przesunięcia.
    #[test]
    fn test_kod_golomba_odrzuca_dokladnie_32_bity_zerowe_zamiast_panikowac() {
        let mut dane = vec![0u8; 4]; // 32 bity zerowe
        dane.push(0xFF); // terminator '1' + wypełnienie
        dane.extend_from_slice(&[0xFF; 8]); // dane pod ewentualne u(32)

        assert_eq!(
            CzytnikBitow::nowy(&dane).ue(), None,
            "32 wiodące zera to kod na granicy pojemności u32 - musi zostać odrzucony, nie spanikować"
        );
    }

    #[test]
    fn test_usuwanie_bajtow_zapobiegania_emulacji() {
        assert_eq!(usun_zapobieganie_emulacji(&[0x00, 0x00, 0x03, 0x01]), vec![0x00, 0x00, 0x01]);
        assert_eq!(usun_zapobieganie_emulacji(&[0x00, 0x00, 0x03]), vec![0x00, 0x00]);
        // 0x03 bez dwóch poprzedzających zer NIE jest bajtem zapobiegania.
        assert_eq!(usun_zapobieganie_emulacji(&[0x00, 0x03, 0x01]), vec![0x00, 0x03, 0x01]);
        assert_eq!(usun_zapobieganie_emulacji(&[0xAA, 0xBB]), vec![0xAA, 0xBB]);
    }

    // ------------------------------------------------------------------
    // Parsowanie SPS - na PRAWDZIWYM SPS-ie
    // ------------------------------------------------------------------

    #[test]
    fn test_parsowanie_prawdziwego_sps_daje_wymiary_kafla() {
        let opis = parsuj_sps(&SPS).expect("prawdziwy SPS musi się sparsować");

        // Wartości niezależnie potwierdzone: `ispe` kafla w fixture'cie mówi
        // 512×512, a `hvcC` deklaruje chromę 4:2:0 i 8 bitów.
        assert_eq!((opis.szerokosc, opis.wysokosc), (512, 512), "wymiary muszą zgadzać się z `ispe` kafla");
        assert_eq!(opis.format_chromy, 1, "4:2:0");
        assert_eq!(opis.glebia_luma_minus8, 0, "8 bitów na próbkę");
        assert_eq!(opis.glebia_chroma_minus8, 0);
        assert_eq!(opis.liczba_podwarstw, 1);
    }

    #[test]
    fn test_parsowanie_sps_odrzuca_smieci() {
        assert!(parsuj_sps(&[0x42, 0x01]).is_none(), "za krótki NAL");
        assert!(parsuj_sps(&[0x42, 0x01, 0x00, 0x00, 0x00, 0x00]).is_none(), "same zera nie są SPS-em");
    }

    /// Zapisywacz bitów odwrotny do [`CzytnikBitow`] — WYŁĄCZNIE do budowy
    /// syntetycznych SPS-ów w testach. Pozwala zakodować dowolną wartość
    /// polem Exp-Golomb (`ue`), zamiast ręcznie liczyć bity dla każdego testu
    /// z osobna.
    struct ZapisBitow { bity: Vec<bool> }
    impl ZapisBitow {
        fn nowy() -> Self { Self { bity: Vec::new() } }
        fn bit(&mut self, b: bool) { self.bity.push(b); }
        fn u(&mut self, wartosc: u32, ile: u32) {
            // `ile` bywa większe niż 32 (wypełnienie pól bez znaczenia, np.
            // 96-bitowe `profile_tier_level`) - bity powyżej szerokości `u32`
            // są zawsze zerowe, więc samo przesunięcie musi być pominięte,
            // inaczej `wartosc >> i` dla `i >= 32` panikuje tak samo, jak
            // produkcyjny kod, który ten plik testuje.
            for i in (0..ile).rev() {
                let bit = if i < 32 { ((wartosc >> i) & 1) == 1 } else { false };
                self.bit(bit);
            }
        }
        /// Koduje `wartosc` jako Exp-Golomb bez znaku (`ue(v)`), odwrotność
        /// [`CzytnikBitow::ue`].
        fn ue(&mut self, wartosc: u32) {
            let temp = wartosc as u64 + 1;
            let bity_temp = 64 - temp.leading_zeros();
            for _ in 0..bity_temp - 1 { self.bit(false); }
            for i in (0..bity_temp).rev() { self.bit(((temp >> i) & 1) == 1); }
        }
        fn bajty(&self) -> Vec<u8> {
            let mut out = vec![0u8; self.bity.len().div_ceil(8)];
            for (i, &b) in self.bity.iter().enumerate() {
                if b { out[i / 8] |= 1 << (7 - (i % 8)); }
            }
            out
        }
    }

    /// REGRESJA na przepełnienie arytmetyki okna zgodności
    /// (`ciecie_szer`/`ciecie_wys` w `parsuj_sps`).
    ///
    /// Buduje SYNTETYCZNY, ale bitowo POPRAWNY SPS z absurdalnie dużymi
    /// offsetami okna zgodności (bliskimi granicy, jaką w ogóle da się
    /// zakodować przez `ue()` po naprawie progu `zer >= 32` - patrz
    /// `test_kod_golomba_odrzuca_dokladnie_32_bity_zerowe...`). Pod starym
    /// kodem `pod_szer * (lewy + prawy)` liczonym w `u32` to przepełniało TYP
    /// zanim `saturating_sub` dostał szansę cokolwiek ochronić - panika w
    /// kompilacji debug, cicho złe wymiary w release. Test dowodzi, że
    /// funkcja dziś ani nie panikuje, ani nie zwraca wymiarów WIĘKSZYCH niż
    /// oryginalne (obcinanie może tylko zmniejszać, nigdy zwiększać).
    #[test]
    fn test_parsowanie_sps_nie_przepelnia_sie_na_absurdalnym_oknie_zgodnosci() {
        let mut w = ZapisBitow::nowy();
        w.u(0, 4); // sps_video_parameter_set_id
        w.u(0, 3); // sps_max_sub_layers_minus1 = 0 (upraszcza profile_tier_level)
        w.u(0, 1); // sps_temporal_id_nesting_flag
        w.u(0, 96); // profile_tier_level (96 bitów przy max_sub_layers_minus1 == 0) - treść bez znaczenia, jest pomijana
        w.ue(0); // sps_seq_parameter_set_id
        w.ue(1); // chroma_format_idc = 1 (4:2:0) -> pod_szer = pod_wys = 2, maksymalizuje ryzyko przepełnienia
        w.ue(100); // pic_width_in_luma_samples
        w.ue(100); // pic_height_in_luma_samples
        w.bit(true); // conformance_window_flag = 1
        w.ue(0x7FFF_FFFF); // conf_win_left_offset - blisko granicy kodowalnej przez ue()
        w.ue(0x7FFF_FFFF); // conf_win_right_offset
        w.ue(0); // conf_win_top_offset
        w.ue(0); // conf_win_bottom_offset

        let mut nal_sps = vec![0x42, 0x01]; // 2-bajtowy nagłówek NAL, pomijany przez parsuj_sps
        nal_sps.extend(w.bajty());
        nal_sps.extend_from_slice(&[0xFF; 32]); // zapas na dalsze pola, które funkcja mogłaby jeszcze przeczytać

        // Sedno testu: wywołanie nie może spanikować. Jeśli parsowanie mimo
        // to dojdzie do końca, obcięte wymiary nie mogą przekroczyć
        // oryginalnych - inaczej przepełnienie ucieklo z powrotem do wyniku.
        if let Some(opis) = parsuj_sps(&nal_sps) {
            assert!(opis.szerokosc <= 100, "obcinanie nie może ZWIĘKSZYĆ szerokości: {}", opis.szerokosc);
            assert!(opis.wysokosc <= 100, "obcinanie nie może ZWIĘKSZYĆ wysokości: {}", opis.wysokosc);
        }
    }

    // ------------------------------------------------------------------
    // Budowanie hvcC - porównanie z PRAWDZIWYM hvcC
    // ------------------------------------------------------------------

    /// Złożone `hvcC` musi być zgodne z prawdziwym, poza jednym bajtem.
    ///
    /// Bajt 21 niesie `numTemporalLayers` i `temporalIdNested`. Kodera Samsunga
    /// zapisał tam zera, choć SPS deklaruje jedną podwarstwę i włączone
    /// zagnieżdżenie — my przepisujemy to, co mówi SPS, bo to on jest źródłem
    /// prawdy. Różnica jest więc świadoma i dotyczy pola informacyjnego, nie
    /// mającego wpływu na dekodowanie.
    #[test]
    fn test_zbudowane_hvcc_zgadza_sie_z_prawdziwym() {
        let opis = parsuj_sps(&SPS).unwrap();
        let hvcc = zbuduj_hvcc(&zestawy(), &opis).expect("hvcC musi się złożyć");

        // Pomijamy 8-bajtowy nagłówek pudełka.
        let tresc = &hvcc[8..];
        assert_eq!(tresc.len(), HVCC_WZORCOWY.len(), "rozmiar hvcC musi się zgadzać");

        assert_eq!(
            &tresc[..21], &HVCC_WZORCOWY[..21],
            "profile_tier_level, chroma i głębia bitowa muszą być identyczne z prawdziwym hvcC"
        );
        assert_eq!(tresc[22], HVCC_WZORCOWY[22], "liczba tablic zestawów parametrów");

        // Tablice porównujemy po ZAWARTOŚCI, a nie bajt w bajt, bo jeden bit
        // różni się świadomie: `array_completeness`. Samsung zapisał 0 („zestawy
        // parametrów mogą występować też w strumieniu") i dla jego pliku jest to
        // prawda - znaleźliśmy w jego `mdat` zabłąkany PPS. My zapisujemy 1,
        // bo do NASZEGO `mdat` trafiają wyłącznie slice'y, więc tablice w
        // `hvcC` są kompletne. Jedna i druga wartość opisuje własny plik
        // poprawnie.
        let tablice = |dane: &[u8]| -> Vec<(u8, bool, Vec<u8>)> {
            let mut out = Vec::new();
            let mut q = 23usize;
            for _ in 0..dane[22] {
                let naglowek = dane[q];
                q += 1;
                let ile = u16::from_be_bytes([dane[q], dane[q + 1]]) as usize;
                q += 2;
                for _ in 0..ile {
                    let dl = u16::from_be_bytes([dane[q], dane[q + 1]]) as usize;
                    q += 2;
                    out.push((naglowek & 0x3F, naglowek & 0x80 != 0, dane[q..q + dl].to_vec()));
                    q += dl;
                }
            }
            out
        };

        let nasze = tablice(tresc);
        let wzorcowe = tablice(&HVCC_WZORCOWY);

        assert_eq!(nasze.len(), 3, "trzy zestawy parametrów");
        for (n, w) in nasze.iter().zip(wzorcowe.iter()) {
            assert_eq!(n.0, w.0, "typ NAL-a w tablicy musi się zgadzać");
            assert_eq!(n.2, w.2, "bajty zestawu parametrów typu {} muszą być identyczne", n.0);
        }

        assert!(nasze.iter().all(|t| t.1), "nasze tablice deklarują komplet zestawów parametrów");
        assert!(wzorcowe.iter().all(|t| !t.1), "wzorcowe deklarują niekomplet - stąd jedyna różnica bajtowa");
    }

    #[test]
    fn test_profile_tier_level_kopiowane_z_sps_bajt_w_bajt() {
        // Dowód założenia z dokumentacji `zbuduj_hvcc`: PTL w SPS-ie zaczyna
        // się na granicy bajtu i jest identyczny z PTL w hvcC.
        let rbsp = usun_zapobieganie_emulacji(&SPS[2..]);
        assert_eq!(&rbsp[1..13], &HVCC_WZORCOWY[1..13]);
    }

    // ------------------------------------------------------------------
    // Łańcuch NAL-i
    // ------------------------------------------------------------------

    #[test]
    fn test_lancuch_domyka_sie_tylko_przy_wlasciwym_prefiksie() {
        let mut dane = z_prefiksem(&VPS);
        dane.extend(z_prefiksem(&SPS));

        let nale = przejdz_lancuch_nal(&dane, 4).expect("prefiks 4 B musi zadziałać");
        assert_eq!(nale.len(), 2);
        assert_eq!(nale[0].typ, NAL_VPS);
        assert_eq!(nale[1].typ, NAL_SPS);

        assert!(przejdz_lancuch_nal(&dane, 2).is_none(), "błędny rozmiar prefiksu nie może dać domkniętego łańcucha");
    }

    #[test]
    fn test_rozpoznanie_prefiksu_wybiera_wlasciwy() {
        let mut dane = z_prefiksem(&VPS);
        dane.extend(z_prefiksem(&SPS));
        dane.extend(z_prefiksem(&PPS));

        let (rozmiar, nale) = rozpoznaj_lancuch(&dane).expect("łańcuch musi zostać rozpoznany");
        assert_eq!(rozmiar, 4);
        assert_eq!(nale.len(), 3);
    }

    #[test]
    fn test_lancuch_odrzuca_niedomkniety_material() {
        let mut dane = z_prefiksem(&SPS);
        dane.extend_from_slice(b"ogon, ktory nie jest NAL-em");
        assert!(rozpoznaj_lancuch(&dane).is_none(), "niedomknięty łańcuch nie jest dowodem hipotezy");
    }

    // ------------------------------------------------------------------
    // Odmowy - każda chroni przed pozorną naprawą
    // ------------------------------------------------------------------

    #[test]
    fn test_odmawia_bez_zestawow_parametrow() {
        // Same slice'y, bez VPS/SPS/PPS - dokładnie sytuacja z prawdziwego
        // HEIC-a, gdzie zestawy parametrów są tylko w zniszczonym `meta`.
        let plik = plik_bez_meta(&z_prefiksem(&slice_syntetyczny(400)));

        let blad = odbuduj_bajty(&plik).unwrap_err();
        let tekst = blad.to_string();
        assert!(tekst.contains("VPS+SPS+PPS"), "komunikat musi nazwać brak: {}", tekst);
        assert!(tekst.contains("WEWNĄTRZ zniszczonego `meta`"), "komunikat musi wyjaśnić, dlaczego to nienaprawialne: {}", tekst);
    }

    /// Brakuje SAMEGO PPS-a — odbudowa musi odmówić.
    ///
    /// Wymagane są wszystkie trzy zestawy parametrów. Test celuje w pojedynczy
    /// brak, bo przy braku całej trójki odmowę wywołałby już pierwszy warunek
    /// i wymóg kompletu nie byłby sprawdzony.
    #[test]
    fn test_odmawia_gdy_brakuje_samego_pps() {
        let mut ladunek = z_prefiksem(&VPS);
        ladunek.extend(z_prefiksem(&SPS));
        // PPS celowo pominięty.
        ladunek.extend(z_prefiksem(&slice_syntetyczny(300)));

        let blad = odbuduj_bajty(&plik_bez_meta(&ladunek)).unwrap_err();
        assert!(
            blad.to_string().contains("VPS+SPS+PPS"),
            "brak choćby jednego zestawu parametrów musi zatrzymać odbudowę: {}", blad
        );
    }

    /// Zarezerwowany bit nagłówka NAL-a odsiewa błędną hipotezę prefiksu.
    ///
    /// Przypadek jest podstępny: długości układają się w łańcuch domykający
    /// się co do bajtu, więc samo domknięcie NIE wystarcza za dowód. Dopiero
    /// `forbidden_zero_bit` (najstarszy bit pierwszego bajtu NAL-a, zawsze 0 w
    /// H.265) pokazuje, że to nie są jednostki NAL.
    #[test]
    fn test_zarezerwowany_bit_odsiewa_bledna_hipoteze() {
        // Prefiks 4 B + treść, której pierwszy bajt ma ustawiony bit 7.
        let tresc = [0x80u8, 0x01, 0x02, 0x03];
        let mut dane = (tresc.len() as u32).to_be_bytes().to_vec();
        dane.extend_from_slice(&tresc);

        // Kontrola: łańcuch domyka się dokładnie na końcu bufora.
        assert_eq!(dane.len(), 4 + tresc.len());

        assert!(
            przejdz_lancuch_nal(&dane, 4).is_none(),
            "domknięty łańcuch z niepoprawnym nagłówkiem NAL-a nie może być uznany za materiał HEVC"
        );
    }

    #[test]
    fn test_odmawia_przy_siatce_kafli() {
        let mut ladunek = z_prefiksem(&VPS);
        ladunek.extend(z_prefiksem(&SPS));
        ladunek.extend(z_prefiksem(&PPS));
        // Trzy obrazy, każdy z ustawionym first_slice_segment_in_pic_flag.
        for _ in 0..3 {
            ladunek.extend(z_prefiksem(&slice_syntetyczny(300)));
        }

        let blad = odbuduj_bajty(&plik_bez_meta(&ladunek)).unwrap_err();
        let tekst = blad.to_string();
        assert!(tekst.contains("siatkę kafli"), "komunikat musi nazwać przyczynę: {}", tekst);
        assert!(tekst.contains("idat"), "komunikat musi wskazać, gdzie leży brakująca geometria: {}", tekst);
        assert!(tekst.contains("3 zakodowanych obrazów"), "komunikat musi podać liczbę: {}", tekst);
    }

    #[test]
    fn test_odmawia_bez_mdat() {
        let plik = pudelko(b"ftyp", b"heic\x00\x00\x00\x00mif1heic");
        let blad = odbuduj_bajty(&plik).unwrap_err();
        assert!(blad.to_string().contains("mdat"), "komunikat: {}", blad);
    }

    #[test]
    fn test_odmawia_gdy_mdat_nie_jest_lancuchem_nal() {
        let plik = plik_bez_meta(b"to nie sa jednostki NAL, tylko zwykly tekst");
        let blad = odbuduj_bajty(&plik).unwrap_err();
        assert!(blad.to_string().contains("łańcuch NAL-i"), "komunikat: {}", blad);
    }

    // ------------------------------------------------------------------
    // Odbudowa - struktura wyniku
    // ------------------------------------------------------------------

    /// Odbudowa z materiału z zestawami parametrów w pasmie: sprawdzamy
    /// STRUKTURĘ wyniku (dekodowalność wymaga prawdziwego slice'a, o tym niżej).
    #[test]
    fn test_odbudowa_sklada_poprawna_strukture() {
        let mut ladunek = z_prefiksem(&VPS);
        ladunek.extend(z_prefiksem(&SPS));
        ladunek.extend(z_prefiksem(&PPS));
        ladunek.extend(z_prefiksem(&slice_syntetyczny(500)));

        let odbudowa = odbuduj_bajty(&plik_bez_meta(&ladunek)).expect("materiał z zestawami parametrów musi się odbudować");

        assert_eq!((odbudowa.szerokosc, odbudowa.wysokosc), (512, 512), "wymiary z parsowania SPS");
        assert_eq!(odbudowa.liczba_obrazow, 1);
        assert_eq!(odbudowa.rozmiar_prefiksu, 4);

        // Układ pudełek najwyższego poziomu.
        let atomy = parse_top_level_boxes(&odbudowa.bajty);
        let typy: Vec<String> = atomy.iter().map(|a| String::from_utf8_lossy(&a.box_type).to_string()).collect();
        assert_eq!(typy, vec!["ftyp", "meta", "mdat"], "układ pudełek: {:?}", typy);

        // `iloc` musi wskazywać dokładnie na dane w `mdat`.
        let mdat = find_box(&atomy, b"mdat").expect("wynik musi mieć mdat");
        let (od_mdat, do_mdat) = mdat.body_range();

        let pozycja_offsetu = odbudowa.bajty
            .windows(4)
            .position(|w| w == (od_mdat as u32).to_be_bytes())
            .expect("w pliku musi znaleźć się offset wskazujący na dane mdat");
        assert!(pozycja_offsetu < od_mdat, "offset musi być zapisany w `meta`, przed danymi");
        assert_eq!(do_mdat - od_mdat, 4 + 500, "mdat musi zawierać slice z prefiksem długości");
    }

    #[test]
    fn test_opis_ujawnia_podstawy_decyzji() {
        let mut ladunek = z_prefiksem(&VPS);
        ladunek.extend(z_prefiksem(&SPS));
        ladunek.extend(z_prefiksem(&PPS));
        ladunek.extend(z_prefiksem(&slice_syntetyczny(300)));

        let opis = odbuduj_bajty(&plik_bez_meta(&ladunek)).unwrap().opis();
        assert!(opis.contains("512×512"), "opis musi podać wymiary: {}", opis);
        assert!(opis.contains("bez dawcy"), "opis: {}", opis);
        assert!(opis.contains("w pasmie"), "opis musi ujawnić, skąd wzięto zestawy parametrów: {}", opis);
    }

    #[test]
    fn test_repair_nie_zapisuje_pliku_przy_odmowie() {
        let dir = tempfile::tempdir().unwrap();
        let wejscie = dir.path().join("uszkodzony.heic");
        let wyjscie = dir.path().join("nie_powinien_istniec.heic");
        std::fs::write(&wejscie, plik_bez_meta(&z_prefiksem(&slice_syntetyczny(200)))).unwrap();

        assert!(repair(wejscie.to_str().unwrap(), wyjscie.to_str().unwrap()).is_err());
        assert!(!wyjscie.exists(), "odmowa nie może tworzyć pliku");
    }

    // ------------------------------------------------------------------
    // Prawdziwy materiał
    // ------------------------------------------------------------------

    /// Na prawdziwym HEIC-u moduł MUSI odmówić — i to jest wynik poprawny.
    ///
    /// Fixture jest obrazem kafelkowanym z zestawami parametrów wyłącznie w
    /// `hvcC`. Gdyby ten test kiedyś zaczął zwracać sukces, znaczyłoby to, że
    /// moduł zaczął zgadywać zamiast dowodzić.
    #[test]
    #[ignore = "Wymaga image/test_fixture.heic. Uruchom z --ignored."]
    fn test_prawdziwy_heic_jest_nienaprawialny_bez_dawcy() {
        let bajty = std::fs::read(crate::sciezka_fixture("test_fixture.heic")).expect("fixture musi istnieć");

        let blad = odbuduj_bajty(&bajty)
            .expect_err("prawdziwy HEIC bez zestawów parametrów w pasmie NIE MOŻE dać się odbudować bez dawcy");

        let tekst = blad.to_string();
        // mdat fixture'a zawiera też itemy Exif i XMP, więc łańcuch NAL-i nie
        // domyka się na całości - odmowa pada już na tym etapie.
        assert!(
            tekst.contains("łańcuch NAL-i") || tekst.contains("VPS+SPS+PPS"),
            "odmowa musi wynikać z braku dowodu, nie z przypadkowego błędu: {}", tekst
        );
    }
    // UWAGA: test, który dowodził dekodowalności odbudowanego kafla przez
    // `libheif`, mieszka teraz w `phases::repair_modules::heic` Weryfikatora.
    // Przeniesiony świadomie: ten crate nie zależy od `libheif-rs`, a
    // wciąganie go tylko dla jednego testu obciążyłoby build obu projektów
    // kompilacją natywnej biblioteki C.
}
