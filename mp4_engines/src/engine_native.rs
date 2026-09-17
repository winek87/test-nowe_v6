// src/mp4/engine_native.rs
//
// PORT z projektu `mp4_doctor` (moduł `engine_native`).
// Zmiany wobec oryginału: `tracing::debug!` -> `tracing`, a sprzężenie z ich potokiem
// MPSC (`Option<&Sender<PipelineMsg>>`) zastąpione neutralnym callbackiem
// postępu `Option<&dyn Fn(String)>` — dzięki temu silnik nie zna ani
// `PipelineMsg`, ani `PhaseEvent` i da się go wołać z dowolnego kontekstu.

//! Moduł `engine_native` - Natywny Silnik Zero-Donor (Pure-Rust).
//! 
//! # FINAŁ: Kompletne Drzewo MP4 (Wideo + Audio)
//! Silnik w 100% niezależny. Samodzielnie konwertuje format H.264 (Annex B -> AVCC)
//! oraz Audio AAC (ADTS -> RAW), po czym buduje pełne, zagnieżdżone drzewo atomów 
//! `moov` ze ścieżkami `vide` i `soun`.

use std::fs::{self, File};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::process::Command;
use byteorder::{BigEndian, WriteBytesExt};


const MATRIX: [u32; 9] = [0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000];
const AAC_SAMPLE_RATES: [u32; 13] = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350];

// --- STRUKTURY DANYCH ---

#[derive(Debug, Clone)]
struct NalInfo {
    offset: u64,
    size: u32,
    start_len: u32,
}

#[derive(Debug, Clone)]
struct FrameInfo {
    offset: u64,
    size: u32,
    is_keyframe: bool,
    nals: Vec<NalInfo>,
}

struct DecoderConfig {
    sps: Vec<u8>,
    pps: Vec<u8>,
    width: u32,
    height: u32,
    audio_config: Vec<u8>,  // Atom ESDS (AudioSpecificConfig)
    sample_rate: u32,       // Np. 48000 Hz
    channels: u16,          // Np. 2 (Stereo)
}

// =====================================================================
// LOW-LEVEL BIT PARSER DLA H.264 SPS
// =====================================================================

struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn read_bit(&mut self) -> Option<u8> {
        let byte_pos = self.bit_pos / 8;
        if byte_pos >= self.data.len() { return None; }
        let bit_shift = 7 - (self.bit_pos % 8);
        self.bit_pos += 1;
        Some((self.data[byte_pos] >> bit_shift) & 1)
    }

    fn read_ue(&mut self) -> Option<u32> {
        let mut leading_zero_bits = 0;
        while self.read_bit()? == 0 { 
            leading_zero_bits += 1; 
            if leading_zero_bits >= 31 { return None; } // Ochrona przed przepełnieniem w uszkodzonym strumieniu
        }
        let mut value = 0;
        for _ in 0..leading_zero_bits { value = (value << 1) | self.read_bit()? as u32; }
        Some((1u32 << leading_zero_bits) - 1 + value)
    }

    fn read_se(&mut self) -> Option<i32> {
        let ue = self.read_ue()? as i32;
        let sign = if ue % 2 == 1 { 1 } else { -1 };
        Some(((ue + 1) / 2) * sign)
    }
}

fn remove_emulation_prevention(data: &[u8]) -> Vec<u8> {
    let mut res = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if i + 2 < data.len() && data[i] == 0 && data[i+1] == 0 && data[i+2] == 3 {
            res.push(0); res.push(0); i += 3;
        } else {
            res.push(data[i]); i += 1;
        }
    }
    res
}

/// Pomija struktury `scaling_list` w SPS, zgodnie z H.264 §7.3.2.1.1.1.
///
/// # Dlaczego to musi tu być
///
/// Wcześniej stała w tym miejscu pusta instrukcja `if scaling_matrix_present == 1 {}`.
/// Flaga była odczytywana, ale listy NIE były pomijane — a to znaczy, że dla
/// każdego strumienia niosącego własną macierz kwantyzacji (dozwolone w
/// profilach High) czytnik bitów zostawał przesunięty o długość tych list i
/// wszystkie kolejne pola SPS-a czytał z błędnych pozycji. Skutek: **błędna
/// rozdzielczość** wpisana potem w atomy `tkhd` i `stsd` odbudowanego pliku.
///
/// Materiał z fixture'a ma tę flagę zerową, więc wada nie ujawniała się na
/// dostępnych plikach — tym łatwiej było ją przeoczyć.
fn skip_scaling_lists(br: &mut BitReader, chroma_format_idc: u32) -> Option<()> {
    // Dla chromy 4:4:4 list jest 12, dla pozostałych 8.
    let ile_list = if chroma_format_idc != 3 { 8 } else { 12 };

    for i in 0..ile_list {
        if br.read_bit()? != 1 {
            continue;
        }

        // Pierwsze sześć list opisuje bloki 4x4, kolejne 8x8.
        let rozmiar = if i < 6 { 16 } else { 64 };
        let mut last_scale: i32 = 8;
        let mut next_scale: i32 = 8;

        for _ in 0..rozmiar {
            if next_scale != 0 {
                let delta = br.read_se()?;
                next_scale = (last_scale + delta + 256).rem_euclid(256);
            }
            if next_scale != 0 {
                last_scale = next_scale;
            }
        }
    }

    Some(())
}

fn parse_sps_resolution(sps: &[u8]) -> Option<(u32, u32)> {
    let clean = remove_emulation_prevention(sps);
    if clean.len() < 4 { return None; }
    
    let profile_idc = clean[1];
    let mut br = BitReader { data: &clean, bit_pos: 8 * 4 }; 
    
    let _sps_id = br.read_ue()?;

    if profile_idc == 100 || profile_idc == 110 || profile_idc == 122 || profile_idc == 244 
       || profile_idc == 44 || profile_idc == 83 || profile_idc == 86 || profile_idc == 118 || profile_idc == 128 {
        let chroma = br.read_ue()?;
        if chroma == 3 { br.read_bit()?; }
        br.read_ue()?; br.read_ue()?; br.read_bit()?; 
        let scaling_matrix_present = br.read_bit()?;
        if scaling_matrix_present == 1 {
            skip_scaling_lists(&mut br, chroma)?;
        }
    }
    
    br.read_ue()?; 
    let poc_type = br.read_ue()?;
    if poc_type == 0 { br.read_ue()?; } 
    else if poc_type == 1 {
        br.read_bit()?; br.read_se()?; br.read_se()?; 
        let num_ref_frames = br.read_ue()?;
        for _ in 0..num_ref_frames { br.read_se()?; }
    }
    
    br.read_ue()?; br.read_bit()?; 
    
    let pic_width_in_mbs_minus1 = br.read_ue()?;
    let pic_height_in_map_units_minus1 = br.read_ue()?;
    let frame_mbs_only_flag = br.read_bit()?;
    
    let width = (pic_width_in_mbs_minus1 + 1) * 16;
    let mut height = (pic_height_in_map_units_minus1 + 1) * 16;
    if frame_mbs_only_flag == 0 { height *= 2; }
    
    Some((width, height))
}

// =====================================================================
// NARZĘDZIA DO BUDOWY DRZEWA MP4 (Kreatory Atomów)
// =====================================================================

fn write_box_header(out: &mut File, size: u32, box_type: &[u8; 4]) -> io::Result<()> {
    out.write_u32::<BigEndian>(size)?;
    out.write_all(box_type)?;
    Ok(())
}

struct BoxWriter<'a> {
    file: &'a mut File,
    start_pos: u64,
}

impl<'a> BoxWriter<'a> {
    fn new(file: &'a mut File, box_type: &[u8; 4]) -> io::Result<Self> {
        let start_pos = file.stream_position()?;
        file.write_u32::<BigEndian>(0)?; 
        file.write_all(box_type)?;       
        Ok(Self { file, start_pos })
    }

    fn close(self) -> io::Result<()> {
        let end_pos = self.file.stream_position()?;
        let size = end_pos - self.start_pos;
        self.file.seek(SeekFrom::Start(self.start_pos))?;
        self.file.write_u32::<BigEndian>(size as u32)?;
        self.file.seek(SeekFrom::Start(end_pos))?;
        Ok(())
    }
}

struct MdatWriter<'a> {
    file: &'a mut File,
    start_pos: u64,
}

impl<'a> MdatWriter<'a> {
    fn new(file: &'a mut File) -> io::Result<Self> {
        let start_pos = file.stream_position()?;
        file.write_u32::<BigEndian>(1)?; 
        file.write_all(b"mdat")?;
        file.write_u64::<BigEndian>(0)?; 
        Ok(Self { file, start_pos })
    }

    fn close(self) -> io::Result<()> {
        let end_pos = self.file.stream_position()?;
        let size = end_pos - self.start_pos;
        self.file.seek(SeekFrom::Start(self.start_pos + 8))?;
        self.file.write_u64::<BigEndian>(size)?;
        self.file.seek(SeekFrom::Start(end_pos))?;
        Ok(())
    }
}

fn build_stsz_box(out: &mut File, frames: &[FrameInfo]) -> io::Result<()> {
    let box_size = 20 + (frames.len() as u32 * 4);
    write_box_header(out, box_size, b"stsz")?;
    out.write_u32::<BigEndian>(0)?; 
    out.write_u32::<BigEndian>(0)?; 
    out.write_u32::<BigEndian>(frames.len() as u32)?; 
    for frame in frames { out.write_u32::<BigEndian>(frame.size)?; }
    Ok(())
}

fn build_stco_box(out: &mut File, frames: &[FrameInfo]) -> io::Result<()> {
    let box_size = 16 + (frames.len() as u32 * 4);
    write_box_header(out, box_size, b"stco")?;
    out.write_u32::<BigEndian>(0)?; 
    out.write_u32::<BigEndian>(frames.len() as u32)?; 
    for frame in frames { out.write_u32::<BigEndian>(frame.offset as u32)?; }
    Ok(())
}

fn build_stss_box(out: &mut File, frames: &[FrameInfo]) -> io::Result<()> {
    let mut sync_samples = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        if frame.is_keyframe { sync_samples.push((i + 1) as u32); }
    }
    if !sync_samples.is_empty() {
        let box_size = 16 + (sync_samples.len() as u32 * 4);
        write_box_header(out, box_size, b"stss")?;
        out.write_u32::<BigEndian>(0)?; 
        out.write_u32::<BigEndian>(sync_samples.len() as u32)?; 
        for index in sync_samples { out.write_u32::<BigEndian>(index)?; }
    }
    Ok(())
}

// =====================================================================
// NATYWNY MUXER DRZEWA MP4 (WIDEO + AUDIO)
// =====================================================================

fn build_native_tree(
    in_file: &mut File,
    out_file: &mut File, 
    video_frames: &mut [FrameInfo], 
    audio_frames: &mut [FrameInfo],
    config: &DecoderConfig,
    fps: u32
) -> io::Result<()> {
    if config.width == 0 || config.height == 0 || config.sps.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Brak parametrów obrazu do budowy drzewa"));
    }

    // 1. FTYP
    out_file.write_u32::<BigEndian>(32)?;
    out_file.write_all(b"ftyp")?;
    out_file.write_all(b"isom")?;
    out_file.write_u32::<BigEndian>(0x200)?;
    out_file.write_all(b"isomiso2avc1mp41")?;

    // 2. MDAT (Kopiowanie z konwersją dla Wideo i czyszczeniem nagłówków dla Audio)
    let mdat = MdatWriter::new(out_file)?;
    
    // Wideo
    for frame in video_frames.iter_mut() {
        let current_pos = mdat.file.stream_position()?;
        frame.offset = current_pos; 
        let mut total_avcc_size = 0;
        
        for nal in &frame.nals {
            in_file.seek(SeekFrom::Start(nal.offset + nal.start_len as u64))?;
            let payload_size = nal.size.saturating_sub(nal.start_len);
            
            mdat.file.write_u32::<BigEndian>(payload_size)?;
            let mut taker = io::Read::by_ref(&mut *in_file).take(payload_size as u64);
            io::copy(&mut taker, mdat.file)?;
            total_avcc_size += 4 + payload_size;
        }
        frame.size = total_avcc_size;
    }

    // Audio AAC (MP4 wymaga czystych danych bez nagłówków ADTS)
    for frame in audio_frames.iter_mut() {
        let original_offset = frame.offset;
        let current_pos = mdat.file.stream_position()?;
        
        // ADTS header ma zwykle 7 bajtów
        let adts_header_len = 7;
        let raw_size = frame.size.saturating_sub(adts_header_len);
        
        frame.offset = current_pos;
        frame.size = raw_size; // Aktualizujemy rozmiar dla tabeli stsz
        
        in_file.seek(SeekFrom::Start(original_offset + adts_header_len as u64))?;
        let mut taker = io::Read::by_ref(&mut *in_file).take(raw_size as u64);
        io::copy(&mut taker, mdat.file)?;
    }

    mdat.close()?;

    // 3. BUDOWA DRZEWA MOOV
    let timescale: u32 = 90000;
    let sample_duration: u32 = timescale / fps;
    let total_duration: u32 = video_frames.len() as u32 * sample_duration;

    let moov = BoxWriter::new(out_file, b"moov")?;
    
    // -- mvhd --
    let mvhd = BoxWriter::new(moov.file, b"mvhd")?;
    mvhd.file.write_u32::<BigEndian>(0)?; 
    mvhd.file.write_u32::<BigEndian>(0)?; 
    mvhd.file.write_u32::<BigEndian>(0)?; 
    mvhd.file.write_u32::<BigEndian>(timescale)?;
    mvhd.file.write_u32::<BigEndian>(total_duration)?;
    mvhd.file.write_u32::<BigEndian>(0x00010000)?; 
    mvhd.file.write_u16::<BigEndian>(0x0100)?; 
    mvhd.file.write_all(&[0u8; 10])?; 
    for &m in &MATRIX { mvhd.file.write_u32::<BigEndian>(m)?; }
    mvhd.file.write_all(&[0u8; 24])?; 
    let next_track_id = if audio_frames.is_empty() { 2 } else { 3 };
    mvhd.file.write_u32::<BigEndian>(next_track_id)?; 
    mvhd.close()?;

    // ==========================================
    // TRACK 1: WIDEO (H.264)
    // ==========================================
    let trak = BoxWriter::new(moov.file, b"trak")?;
    
    let tkhd = BoxWriter::new(trak.file, b"tkhd")?;
    tkhd.file.write_u32::<BigEndian>(0x0000000F)?; 
    tkhd.file.write_u32::<BigEndian>(0)?; 
    tkhd.file.write_u32::<BigEndian>(0)?; 
    tkhd.file.write_u32::<BigEndian>(1)?; // Track ID 1
    tkhd.file.write_u32::<BigEndian>(0)?; 
    tkhd.file.write_u32::<BigEndian>(total_duration)?;
    tkhd.file.write_all(&[0u8; 8])?; 
    tkhd.file.write_u16::<BigEndian>(0)?; 
    tkhd.file.write_u16::<BigEndian>(0)?; 
    tkhd.file.write_u16::<BigEndian>(0)?; 
    tkhd.file.write_u16::<BigEndian>(0)?; 
    for &m in &MATRIX { tkhd.file.write_u32::<BigEndian>(m)?; }
    tkhd.file.write_u32::<BigEndian>(config.width << 16)?;
    tkhd.file.write_u32::<BigEndian>(config.height << 16)?;
    tkhd.close()?;

    let mdia = BoxWriter::new(trak.file, b"mdia")?;
    let mdhd = BoxWriter::new(mdia.file, b"mdhd")?;
    mdhd.file.write_u32::<BigEndian>(0)?; 
    mdhd.file.write_u32::<BigEndian>(0)?; 
    mdhd.file.write_u32::<BigEndian>(0)?; 
    mdhd.file.write_u32::<BigEndian>(timescale)?;
    mdhd.file.write_u32::<BigEndian>(total_duration)?;
    mdhd.file.write_u16::<BigEndian>(0x55C4)?; 
    mdhd.file.write_u16::<BigEndian>(0)?; 
    mdhd.close()?;

    let hdlr = BoxWriter::new(mdia.file, b"hdlr")?;
    hdlr.file.write_u32::<BigEndian>(0)?; 
    hdlr.file.write_u32::<BigEndian>(0)?; 
    hdlr.file.write_all(b"vide")?;
    hdlr.file.write_all(&[0u8; 12])?;
    hdlr.file.write_all(b"VideoHandler\0")?;
    hdlr.close()?;

    let minf = BoxWriter::new(mdia.file, b"minf")?;
    let vmhd = BoxWriter::new(minf.file, b"vmhd")?;
    vmhd.file.write_u32::<BigEndian>(1)?; 
    vmhd.file.write_u16::<BigEndian>(0)?; 
    vmhd.file.write_all(&[0u8; 6])?; 
    vmhd.close()?;

    let dinf = BoxWriter::new(minf.file, b"dinf")?;
    let dref = BoxWriter::new(dinf.file, b"dref")?;
    dref.file.write_u32::<BigEndian>(0)?; 
    dref.file.write_u32::<BigEndian>(1)?; 
    let url = BoxWriter::new(dref.file, b"url ")?;
    url.file.write_u32::<BigEndian>(1)?; 
    url.close()?;
    dref.close()?;
    dinf.close()?;

    let stbl = BoxWriter::new(minf.file, b"stbl")?;
    let stsd = BoxWriter::new(stbl.file, b"stsd")?;
    stsd.file.write_u32::<BigEndian>(0)?;
    stsd.file.write_u32::<BigEndian>(1)?;
    let avc1 = BoxWriter::new(stsd.file, b"avc1")?;
    avc1.file.write_all(&[0u8; 6])?; 
    avc1.file.write_u16::<BigEndian>(1)?; 
    avc1.file.write_u16::<BigEndian>(0)?; 
    avc1.file.write_u16::<BigEndian>(0)?; 
    avc1.file.write_all(&[0u8; 12])?; 
    avc1.file.write_u16::<BigEndian>(config.width as u16)?;
    avc1.file.write_u16::<BigEndian>(config.height as u16)?;
    avc1.file.write_u32::<BigEndian>(0x00480000)?; 
    avc1.file.write_u32::<BigEndian>(0x00480000)?; 
    avc1.file.write_u32::<BigEndian>(0)?; 
    avc1.file.write_u16::<BigEndian>(1)?; 
    avc1.file.write_all(&[0u8; 32])?; 
    avc1.file.write_u16::<BigEndian>(0x0018)?; 
    avc1.file.write_i16::<BigEndian>(-1)?; 
    
    let avcc = BoxWriter::new(avc1.file, b"avcC")?;
    avcc.file.write_u8(1)?; 
    avcc.file.write_u8(config.sps[1])?; 
    avcc.file.write_u8(config.sps[2])?; 
    avcc.file.write_u8(config.sps[3])?; 
    avcc.file.write_u8(0xFF)?; 
    avcc.file.write_u8(0xE1)?; 
    avcc.file.write_u16::<BigEndian>(config.sps.len() as u16)?;
    avcc.file.write_all(&config.sps)?;
    avcc.file.write_u8(1)?; 
    avcc.file.write_u16::<BigEndian>(config.pps.len() as u16)?;
    avcc.file.write_all(&config.pps)?;
    avcc.close()?;
    avc1.close()?;
    stsd.close()?;

    // =====================================================================
    // ENTERPRISE AI: DETEKCJA WZORCÓW PRZEPLOTU I AUTOKOREKTA SYNC (A/V)
    // =====================================================================
    let mut use_dynamic_sync = false;
    let mut dynamic_video_durations = Vec::new();
    let default_video_duration = (timescale as f64 / fps as f64).round() as u32;

    if !audio_frames.is_empty() && !video_frames.is_empty() {
        // Sprawdzamy czy plik jest przeplatany (interleaved)
        let first_v = video_frames.first().map(|f| f.offset).unwrap_or(0);
        let last_v = video_frames.last().map(|f| f.offset).unwrap_or(0);
        let first_a = audio_frames.first().map(|f| f.offset).unwrap_or(0);
        let last_a = audio_frames.last().map(|f| f.offset).unwrap_or(0);

        // Jeśli zakresy się nakładają w znacznym stopniu, to mamy przeplot!
        if first_a < last_v && first_v < last_a {
            tracing::debug!("🧠 [AI SYNC] Wykryto fizyczny przeplot A/V na dysku! Uruchamiam autokorektę klatkażu...");
            
            
            // Tworzymy oś czasu: (offset, is_video, index_w_swojej_tablicy)
            let mut timeline = Vec::new();
            for (i, v) in video_frames.iter().enumerate() {
                timeline.push((v.offset, true, i));
            }
            for (i, a) in audio_frames.iter().enumerate() {
                timeline.push((a.offset, false, i));
            }
            timeline.sort_by_key(|k| k.0);

            // Audio Clock: każda klatka AAC to 1024 sample (1024 / sample_rate sekund)
            // Będziemy przypisywać czas PTS dla wideo na podstawie tego zegara.
            let audio_tick_duration = (1024.0 / config.sample_rate as f64) * timescale as f64;
            let mut current_audio_time = 0.0;
            let mut video_pts = vec![0.0; video_frames.len()];
            
            let mut last_video_idx = None;

            for &(_, is_video, idx) in &timeline {
                if is_video {
                    video_pts[idx] = current_audio_time;
                    last_video_idx = Some(idx);
                } else {
                    current_audio_time += audio_tick_duration;
                    // Jeśli mamy wideo, to przesuwamy mu lekko czas by zrekompensować bufor
                    if let Some(v_idx) = last_video_idx {
                        video_pts[v_idx] = current_audio_time;
                    }
                }
            }

            // Obliczamy różnice między PTS aby uzyskać sample_duration dla stts
            for i in 0..video_frames.len() {
                let duration = if i + 1 < video_frames.len() {
                    let diff = video_pts[i+1] - video_pts[i];
                    if diff > 0.0 && diff < (timescale as f64) { // Zabezpieczenie przed anomaliami
                        diff as u32
                    } else {
                        default_video_duration
                    }
                } else {
                    default_video_duration
                };
                dynamic_video_durations.push(duration);
            }
            use_dynamic_sync = true;
            tracing::debug!("✅ [AI SYNC] Wygenerowano dynamiczny klatkaż VFR na bazie zegara audio!");
        } else {
            tracing::debug!("⚠️ [AI SYNC] Plik nie jest przeplatany (sklejka). Używam domyślnego CFR: {} FPS", fps);
        }
    }

    let stts = BoxWriter::new(stbl.file, b"stts")?;
    stts.file.write_u32::<BigEndian>(0)?; 
    
    if use_dynamic_sync {
        // Kompresujemy dynamiczne czasy do tabeli (RLE - Run Length Encoding)
        let mut entries: Vec<(u32, u32)> = Vec::new();
        for &dur in &dynamic_video_durations {
            if let Some(last) = entries.last_mut()
                && last.1 == dur {
                    last.0 += 1;
                    continue;
                }
            entries.push((1, dur));
        }
        
        stts.file.write_u32::<BigEndian>(entries.len() as u32)?;
        for (count, dur) in entries {
            stts.file.write_u32::<BigEndian>(count)?;
            stts.file.write_u32::<BigEndian>(dur)?;
        }
    } else {
        stts.file.write_u32::<BigEndian>(1)?; 
        stts.file.write_u32::<BigEndian>(video_frames.len() as u32)?; 
        stts.file.write_u32::<BigEndian>(sample_duration)?; 
    }
    stts.close()?;

    let stsc = BoxWriter::new(stbl.file, b"stsc")?;
    stsc.file.write_u32::<BigEndian>(0)?; 
    stsc.file.write_u32::<BigEndian>(1)?; 
    stsc.file.write_u32::<BigEndian>(1)?; 
    stsc.file.write_u32::<BigEndian>(1)?; 
    stsc.file.write_u32::<BigEndian>(1)?; 
    stsc.close()?;

    build_stsz_box(stbl.file, video_frames)?;
    build_stco_box(stbl.file, video_frames)?;
    build_stss_box(stbl.file, video_frames)?;
    stbl.close()?;
    minf.close()?;
    mdia.close()?;
    trak.close()?;

    // ==========================================
    // TRACK 2: AUDIO (AAC)
    // ==========================================
    if !audio_frames.is_empty() && config.sample_rate > 0 && !config.audio_config.is_empty() {
        let trak_a = BoxWriter::new(moov.file, b"trak")?;
        
        // Czas trwania audio: (ilość_klatek * 1024) w skali sample_rate
        let audio_duration = ((audio_frames.len() as f64 * 1024.0) / config.sample_rate as f64 * timescale as f64) as u32;

        let tkhd_a = BoxWriter::new(trak_a.file, b"tkhd")?;
        tkhd_a.file.write_u32::<BigEndian>(0x0000000F)?; 
        tkhd_a.file.write_u32::<BigEndian>(0)?; 
        tkhd_a.file.write_u32::<BigEndian>(0)?; 
        tkhd_a.file.write_u32::<BigEndian>(2)?; // Track ID 2
        tkhd_a.file.write_u32::<BigEndian>(0)?; 
        tkhd_a.file.write_u32::<BigEndian>(audio_duration)?;
        tkhd_a.file.write_all(&[0u8; 8])?; 
        tkhd_a.file.write_u16::<BigEndian>(0)?; 
        tkhd_a.file.write_u16::<BigEndian>(0)?; 
        tkhd_a.file.write_u16::<BigEndian>(0x0100)?; // Audio volume
        tkhd_a.file.write_u16::<BigEndian>(0)?; 
        for &m in &MATRIX { tkhd_a.file.write_u32::<BigEndian>(m)?; }
        tkhd_a.file.write_u32::<BigEndian>(0)?;
        tkhd_a.file.write_u32::<BigEndian>(0)?;
        tkhd_a.close()?;

        let mdia_a = BoxWriter::new(trak_a.file, b"mdia")?;
        let mdhd_a = BoxWriter::new(mdia_a.file, b"mdhd")?;
        mdhd_a.file.write_u32::<BigEndian>(0)?; 
        mdhd_a.file.write_u32::<BigEndian>(0)?; 
        mdhd_a.file.write_u32::<BigEndian>(0)?; 
        mdhd_a.file.write_u32::<BigEndian>(config.sample_rate)?; // Timescale = sample rate!
        mdhd_a.file.write_u32::<BigEndian>(audio_frames.len() as u32 * 1024)?; // Exact samples
        mdhd_a.file.write_u16::<BigEndian>(0x55C4)?; 
        mdhd_a.file.write_u16::<BigEndian>(0)?; 
        mdhd_a.close()?;

        let hdlr_a = BoxWriter::new(mdia_a.file, b"hdlr")?;
        hdlr_a.file.write_u32::<BigEndian>(0)?; 
        hdlr_a.file.write_u32::<BigEndian>(0)?; 
        hdlr_a.file.write_all(b"soun")?;
        hdlr_a.file.write_all(&[0u8; 12])?;
        hdlr_a.file.write_all(b"SoundHandler\0")?;
        hdlr_a.close()?;

        let minf_a = BoxWriter::new(mdia_a.file, b"minf")?;
        let smhd = BoxWriter::new(minf_a.file, b"smhd")?;
        smhd.file.write_u32::<BigEndian>(0)?; 
        smhd.file.write_u16::<BigEndian>(0)?; 
        smhd.file.write_u16::<BigEndian>(0)?; 
        smhd.close()?;

        let dinf_a = BoxWriter::new(minf_a.file, b"dinf")?;
        let dref_a = BoxWriter::new(dinf_a.file, b"dref")?;
        dref_a.file.write_u32::<BigEndian>(0)?; 
        dref_a.file.write_u32::<BigEndian>(1)?; 
        let url_a = BoxWriter::new(dref_a.file, b"url ")?;
        url_a.file.write_u32::<BigEndian>(1)?; 
        url_a.close()?;
        dref_a.close()?;
        dinf_a.close()?;

        let stbl_a = BoxWriter::new(minf_a.file, b"stbl")?;
        
        let stsd_a = BoxWriter::new(stbl_a.file, b"stsd")?;
        stsd_a.file.write_u32::<BigEndian>(0)?;
        stsd_a.file.write_u32::<BigEndian>(1)?;
        
        let mp4a = BoxWriter::new(stsd_a.file, b"mp4a")?;
        mp4a.file.write_all(&[0u8; 6])?; 
        mp4a.file.write_u16::<BigEndian>(1)?; 
        mp4a.file.write_all(&[0u8; 8])?; // Wersja + reserved
        mp4a.file.write_u16::<BigEndian>(config.channels)?; 
        mp4a.file.write_u16::<BigEndian>(16)?; // Bit depth
        mp4a.file.write_u32::<BigEndian>(0)?; // compression id
        mp4a.file.write_u16::<BigEndian>(config.sample_rate as u16)?;
        mp4a.file.write_u16::<BigEndian>(0)?; 
        
        let esds = BoxWriter::new(mp4a.file, b"esds")?;
        esds.file.write_u32::<BigEndian>(0)?;
        
        // ESDS Descriptor (Skomplikowana architektura bitowa MPEG-4)
        esds.file.write_u8(0x03)?; // ES_DescrTag
        esds.file.write_u8((13 + config.audio_config.len()) as u8)?; 
        esds.file.write_u16::<BigEndian>(0x0000)?; // ES_ID
        esds.file.write_u8(0x00)?; 
        
        esds.file.write_u8(0x04)?; // DecoderConfigDescrTag
        esds.file.write_u8((5 + config.audio_config.len()) as u8)?;
        esds.file.write_u8(0x40)?; // ObjectType: Audio ISO/IEC 14496-3
        esds.file.write_u8(0x15)?; // StreamType: Audio Stream
        esds.file.write_u16::<BigEndian>(8192)?; // Buffer size
        esds.file.write_u8(0)?;
        esds.file.write_u32::<BigEndian>(128000)?; // Max bitrate
        esds.file.write_u32::<BigEndian>(128000)?; // Avg bitrate
        
        esds.file.write_u8(0x05)?; // DecSpecificInfoTag
        esds.file.write_u8(config.audio_config.len() as u8)?;
        esds.file.write_all(&config.audio_config)?;
        
        esds.file.write_u8(0x06)?; // SLConfigDescrTag
        esds.file.write_u8(0x01)?;
        esds.file.write_u8(0x02)?;
        
        esds.close()?;
        mp4a.close()?;
        stsd_a.close()?;

        let stts_a = BoxWriter::new(stbl_a.file, b"stts")?;
        stts_a.file.write_u32::<BigEndian>(0)?; 
        stts_a.file.write_u32::<BigEndian>(1)?; 
        stts_a.file.write_u32::<BigEndian>(audio_frames.len() as u32)?; 
        stts_a.file.write_u32::<BigEndian>(1024)?; // AAC ma zawsze 1024 sample na klatkę!
        stts_a.close()?;

        let stsc_a = BoxWriter::new(stbl_a.file, b"stsc")?;
        stsc_a.file.write_u32::<BigEndian>(0)?; 
        stsc_a.file.write_u32::<BigEndian>(1)?; 
        stsc_a.file.write_u32::<BigEndian>(1)?; 
        stsc_a.file.write_u32::<BigEndian>(1)?; 
        stsc_a.file.write_u32::<BigEndian>(1)?; 
        stsc_a.close()?;

        build_stsz_box(stbl_a.file, audio_frames)?;
        build_stco_box(stbl_a.file, audio_frames)?;

        stbl_a.close()?;
        minf_a.close()?;
        mdia_a.close()?;
        trak_a.close()?;
    }

    moov.close()?;
    Ok(())
}

// --- FALLBACK FFmpeg ---

fn fallback_ffmpeg_mux(
    broken_file: &str, 
    output_file: &str, 
    video_frames: &[FrameInfo], 
    audio_frames: &[FrameInfo]
) -> io::Result<()> {
    let mut in_file = File::open(broken_file)?;
    let video_temp = format!("{}.temp.h264", output_file);
    let mut v_out = File::create(&video_temp)?;
    for f in video_frames {
        in_file.seek(SeekFrom::Start(f.offset))?;
        let mut taker = io::Read::by_ref(&mut in_file).take(f.size as u64);
        io::copy(&mut taker, &mut v_out)?;
    }

    let audio_temp = format!("{}.temp.aac", output_file);
    let mut has_audio = false;
    if !audio_frames.is_empty() {
        let mut a_out = File::create(&audio_temp)?;
        for f in audio_frames {
            in_file.seek(SeekFrom::Start(f.offset))?;
            let mut taker = io::Read::by_ref(&mut in_file).take(f.size as u64);
            io::copy(&mut taker, &mut a_out)?;
        }
        has_audio = true;
    }

    let mut cmd = Command::new("ffmpeg");
    cmd.arg("-y").arg("-v").arg("error").arg("-fflags").arg("+genpts").arg("-i").arg(&video_temp);
    if has_audio { cmd.arg("-i").arg(&audio_temp); }
    cmd.arg("-c").arg("copy").arg(output_file);
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());

    let status = cmd.status()?;
    let _ = fs::remove_file(&video_temp);
    if has_audio { let _ = fs::remove_file(&audio_temp); }
    if status.success() { Ok(()) } else { Err(io::Error::other("FFmpeg fallback zawiódł.")) }
}

// =====================================================================
// GŁÓWNY SILNIK HEURYSTYCZNY
// =====================================================================

pub fn repair(
    broken_file: &str, 
    output_file: &str,
    postep: Option<&dyn Fn(String)>,
) -> io::Result<()> {
    
    let update_ui = |msg: String| {
        if let Some(cb) = postep { cb(msg); }
    };

    tracing::debug!("🧬 [NATIVE] Uruchamiam zaawansowaną analizę wideo (H.264) i audio (AAC)...");
    update_ui("🧬 Native: Rozpoczynam głęboką analizę bitową...".to_string());

    let mut in_file = File::open(broken_file)?;
    // ENTERPRISE AI: ZERO-COPY MEMORY MAPPING
    // Plik jest mapowany bezpośrednio w pamięć RAM (wirtualną), omijając kopiowanie przez Kernel!
    let mmap = unsafe { memmap2::MmapOptions::new().map(&in_file)? };
    let buffer = &mmap[..];
    let valid_data_size = buffer.len();

    let mut video_frames = Vec::new();
    let mut audio_frames = Vec::new();
    let mut config = DecoderConfig { sps: Vec::new(), pps: Vec::new(), width: 0, height: 0, audio_config: Vec::new(), sample_rate: 0, channels: 0 };

    let mut current_gop_size = 0;
    let mut gop_sizes = Vec::new();
    
    let mut current_frame_nals = Vec::new();
    let mut last_nal_start: Option<(u64, u32, u8)> = None;
    let mut frame_is_keyframe = false;

    update_ui("🧮 Native: Skanowanie Memory-Mapped (Mmap) algorytmem Zero-Donor...".to_string());

    let mut i = 0;
    while i < valid_data_size.saturating_sub(8) {
            let mut start_len = 0;
            if buffer[i] == 0 && buffer[i+1] == 0 && buffer[i+2] == 0 && buffer[i+3] == 1 {
                start_len = 4;
            } else if buffer[i] == 0 && buffer[i+1] == 0 && buffer[i+2] == 1 {
                start_len = 3;
            }

            if start_len > 0 {
                let current_nal_absolute = i as u64;
                let nal_type = buffer[i+start_len] & 0x1F;

                if let Some((start, s_len, last_type)) = last_nal_start {
                    let size = current_nal_absolute - start;
                    if size > 0 {
                        current_frame_nals.push(NalInfo { offset: start, size: size as u32, start_len: s_len });
                        if last_type == 5 { frame_is_keyframe = true; }

                        if last_type == 1 || last_type == 5 {
                            video_frames.push(FrameInfo { 
                                nals: current_frame_nals.clone(), 
                                is_keyframe: frame_is_keyframe, 
                                offset: 0, 
                                size: 0 
                            });
                            current_frame_nals.clear();
                            frame_is_keyframe = false;
                            
                            current_gop_size += 1;
                            if last_type == 5 {
                                gop_sizes.push(current_gop_size);
                                current_gop_size = 0;
                            }
                        }
                    }
                }

                // Okna o stałej długości (36/20/8) sondują SPS/PPS zanim
                // znana jest jego prawdziwa granica (kolejny start code).
                // Blisko końca bufora tych bajtów może po prostu ZABRAKNĄĆ -
                // strumień uszkodzony/ucięty tuż po nagłówku SPS/PPS to
                // dokładnie ten przypadek, który ten silnik ma przeżyć, a nie
                // spanikować na nim. `buffer.get(..)` zamiast indeksowania
                // zwraca `None` zamiast panikować, gdy okno wychodzi poza
                // bufor.
                if config.sps.is_empty() && nal_type == 7 {
                    if let Some(sps_data) = buffer.get(i+start_len..i+start_len+36)
                        && let Some((w, h)) = parse_sps_resolution(sps_data) {
                            let msg = format!("🎯 Native: Zdekodowano matrycę: {}x{}", w, h);
                            tracing::debug!("{}", msg); update_ui(msg);
                            config.width = w; config.height = h;
                        }
                    if let Some(sps) = buffer.get(i+start_len..i+start_len+20) {
                        config.sps = sps.to_vec();
                    }
                }
                if config.pps.is_empty() && nal_type == 8
                    && let Some(pps) = buffer.get(i+start_len..i+start_len+8) {
                        config.pps = pps.to_vec();
                    }

                last_nal_start = Some((current_nal_absolute, start_len as u32, nal_type));
                
                i += start_len;
            } 
            else if buffer[i] == 0xFF && (buffer[i+1] & 0xF0) == 0xF0 {
                let frame_size = (((buffer[i+3] & 3) as u32) << 11) | ((buffer[i+4] as u32) << 3) | (((buffer[i+5] & 0xE0) as u32) >> 5);
                let freq_idx = (buffer[i+2] & 0x3C) >> 2;
                let channels = ((buffer[i+2] & 0x01) << 2) | ((buffer[i+3] & 0xC0) >> 6);
                
                let mut is_valid_adts = false;
                if frame_size > 6 && freq_idx < 13 && channels > 0 {
                    let next_i = i + frame_size as usize;
                    // `+ 1` bo sprawdzenie niżej czyta DWA bajty (`next_i` i
                    // `next_i+1`) - `next_i < valid_data_size` gwarantowało
                    // tylko pierwszy z nich. Ucięty strumień, którego kolejny
                    // domniemany nagłówek ADTS ląduje dokładnie na
                    // przedostatnim bajcie bufora, indeksował poza zakres.
                    if next_i + 1 < valid_data_size {
                        if buffer[next_i] == 0xFF && (buffer[next_i+1] & 0xF0) == 0xF0 {
                            is_valid_adts = true;
                        }
                    } else if next_i < valid_data_size {
                        is_valid_adts = true; // Ostatni bajt bufora - nie da się sprawdzić dalej.
                    } else {
                        is_valid_adts = true; // Koniec bufora
                    }
                }
                
                if is_valid_adts {
                    if config.audio_config.is_empty() {
                        let profile = (buffer[i+2] & 0xC0) >> 6;
                        let aac_profile = profile + 1; 
                        let asc: u16 = ((aac_profile as u16) << 11) | ((freq_idx as u16) << 7) | ((channels as u16) << 3);
                        
                        config.audio_config = vec![(asc >> 8) as u8, (asc & 0xFF) as u8];
                        config.channels = channels as u16;
                        config.sample_rate = *AAC_SAMPLE_RATES.get(freq_idx as usize).unwrap_or(&48000);
                        
                        let msg = format!("🎵 Native: Zdekodowano parametry Audio: AAC, {}Hz, kanały: {}", config.sample_rate, config.channels);
                        tracing::debug!("{}", msg); update_ui(msg);
                    }

                    let audio_absolute = i as u64;
                    audio_frames.push(FrameInfo { offset: audio_absolute, size: frame_size, is_keyframe: true, nals: Vec::new() });
                    
                    i += frame_size as usize;
                } else {
                    i += 1;
                }
            } else { i += 1; }
    }

    if let Some((start, s_len, last_type)) = last_nal_start {
        let size = (valid_data_size as u64) - start;
        if size > 0 {
            current_frame_nals.push(NalInfo { offset: start, size: size as u32, start_len: s_len });
            if last_type == 5 { frame_is_keyframe = true; }
            if !current_frame_nals.is_empty() {
                video_frames.push(FrameInfo { nals: current_frame_nals, is_keyframe: frame_is_keyframe, offset: 0, size: 0 });
            }
        }
    }

    if video_frames.is_empty() { return Err(io::Error::new(io::ErrorKind::InvalidData, "Brak NAL H.264")); }

    // =====================================================================
    // ENTERPRISE AI: CHIRURGICZNE CIĘCIE I KWARANTANNA GOP
    // =====================================================================
    update_ui("🛡️ Native: Aktywacja Tarczy Anty-Artefaktowej (GOP Quarantine)...".to_string());
    
    let mut healthy_video_frames = Vec::new();
    let mut is_quarantined = false;
    let mut dropped_count = 0;
    
    for i in 0..video_frames.len() {
        let frame = &video_frames[i];
        let mut total_payload = 0;
        for nal in &frame.nals {
            total_payload += nal.size.saturating_sub(nal.start_len);
        }
        
        let mut corrupted = false;
        
        // 1. Detekcja uciętej klatki (zbyt mały rozmiar jak na sensowny VCL NAL)
        if total_payload < 100 {
            corrupted = true;
        }
        
        // 2. Detekcja gigantycznej dziury w pliku (Bad Sectors)
        if i > 0 {
            let prev_frame = &video_frames[i-1];
            let prev_end = prev_frame.nals.last().map(|n| n.offset + n.size as u64).unwrap_or(0);
            let current_start = frame.nals.first().map(|n| n.offset).unwrap_or(0);
            
            // Jeśli między końcem poprzedniej a startem obecnej klatki brakuje > 256KB
            if current_start.saturating_sub(prev_end) > 256 * 1024 {
                corrupted = true;
            }
        }
        
        if frame.is_keyframe {
            // I-Frame resetuje kwarantannę!
            if corrupted {
                is_quarantined = true; // Sam I-Frame zepsuty? Kwarantanna całego GOP!
                dropped_count += 1;
            } else {
                is_quarantined = false; // Zdrowy I-Frame! Koniec kwarantanny.
                healthy_video_frames.push(frame.clone());
            }
        } else {
            // P-Frame
            if corrupted || is_quarantined {
                is_quarantined = true; // Rozpoczynamy lub kontynuujemy kwarantannę
                dropped_count += 1;
            } else {
                healthy_video_frames.push(frame.clone());
            }
        }
    }
    
    if dropped_count > 0 {
        let msg = format!("✂️ Native: Chirurgicznie usunięto {} zainfekowanych klatek (GOP Quarantine).", dropped_count);
        tracing::debug!("{}", msg);
        update_ui(msg);
    }
    
    video_frames = healthy_video_frames;
    if video_frames.is_empty() { return Err(io::Error::new(io::ErrorKind::InvalidData, "Wszystkie klatki zablokowane przez kwarantannę.")); }
    
    let avg_gop = if !gop_sizes.is_empty() { gop_sizes.iter().sum::<u32>() / (gop_sizes.len() as u32) } else { 30 }; 
    
    let fps = if (23..=24).contains(&avg_gop) { 24 }
    else if (25..=29).contains(&avg_gop) { 25 }
    else if (30..=49).contains(&avg_gop) { 30 }
    else if (50..=60).contains(&avg_gop) { 60 }
    else { 24 };

    update_ui(format!("⏱️ Native: Oszacowano klatkaż: {} FPS", fps)); 
    update_ui("🏗️ Native: Budowa w 100% natywnego drzewa MP4 (Moov Tree)...".to_string());
        
    let mut out_file = File::create(output_file)?;
    
    match build_native_tree(&mut in_file, &mut out_file, &mut video_frames, &mut audio_frames, &config, fps) {
        Ok(_) => { 
            update_ui("🏆 Native: Zbudowano idealne drzewo MP4 w Ruście!".to_string());
            Ok(()) 
        },
        Err(e) => {
            tracing::debug!("🚨 Native: Błąd budowy drzewa: {}. Odpalam Fallback.", e);
            drop(out_file);
            fallback_ffmpeg_mux(broken_file, output_file, &video_frames, &audio_frames)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// PRAWDZIWY SPS H.264 wyjęty z atomu `avcC` pliku `image/test_fixture.mp4`.
    ///
    /// Profil 100 (High), więc parser wchodzi w gałąź z formatem chromy i
    /// głębią bitową — czyli w tę samą, w której siedzi obsługa macierzy
    /// skalowania. Rozdzielczość potwierdzona niezależnie: `ffprobe` na tym
    /// pliku raportuje 640×368.
    const SPS_RZECZYWISTY: [u8; 15] = [
        0x27, 0x64, 0x00, 0x1e, 0xac, 0x56, 0xc0, 0xa0,
        0x2f, 0xa6, 0xa0, 0x20, 0x20, 0x20, 0x40,
    ];

    fn czytnik(dane: &[u8]) -> BitReader<'_> {
        BitReader { data: dane, bit_pos: 0 }
    }

    // ------------------------------------------------------------------
    // Czytnik bitów i kody wykładnicze Golomba
    // ------------------------------------------------------------------

    #[test]
    fn test_czytnik_bitow_idzie_bit_po_bicie() {
        let dane = [0b1011_0010u8, 0b0100_0001];
        let mut br = czytnik(&dane);

        let odczyt: Vec<u8> = (0..16).map(|_| br.read_bit().unwrap()).collect();
        assert_eq!(odczyt, vec![1,0,1,1,0,0,1,0, 0,1,0,0,0,0,0,1]);
        assert_eq!(br.read_bit(), None, "za końcem danych musi zwrócić None, nie zera");
    }

    #[test]
    fn test_kod_golomba_bez_znaku_na_znanych_wektorach() {
        // ue(v): '1'->0, '010'->1, '011'->2, '00100'->3, '00111'->6
        let przypadki: [(&[u8], u32); 5] = [
            (&[0b1000_0000], 0),
            (&[0b0100_0000], 1),
            (&[0b0110_0000], 2),
            (&[0b0010_0000], 3),
            (&[0b0011_1000], 6),
        ];
        for (dane, oczekiwane) in przypadki {
            assert_eq!(czytnik(dane).read_ue(), Some(oczekiwane), "dane {:08b}", dane[0]);
        }
    }

    #[test]
    fn test_kod_golomba_ze_znakiem_na_znanych_wektorach() {
        // se(v) wywodzi się z ue(v): 0->0, 1->1, 2->-1, 3->2, 4->-2
        let przypadki: [(&[u8], i32); 5] = [
            (&[0b1000_0000], 0),
            (&[0b0100_0000], 1),
            (&[0b0110_0000], -1),
            (&[0b0010_0000], 2),
            (&[0b0010_1000], -2),
        ];
        for (dane, oczekiwane) in przypadki {
            assert_eq!(czytnik(dane).read_se(), Some(oczekiwane), "dane {:08b}", dane[0]);
        }
    }

    /// Uszkodzony strumień to długi ciąg zer. Bez bezpiecznika czytnik
    /// kręciłby się w pętli albo przepełnił przesunięcie — stąd twardy limit.
    #[test]
    fn test_kod_golomba_nie_petli_na_dlugim_ciagu_zer() {
        let zera = [0u8; 32];
        assert_eq!(czytnik(&zera).read_ue(), None);
        assert_eq!(czytnik(&zera).read_se(), None);
    }

    /// Limit 31 zer chroni przed PRZEPEŁNIENIEM PRZESUNIĘCIA, nie tylko przed
    /// pętlą.
    ///
    /// Przy 32 i więcej zerach zakończonych jedynką wyrażenie
    /// `1u32 << leading_zero_bits` wychodzi poza szerokość typu. Test podaje
    /// 40 zer i jedynkę — materiał krótszy (same zera) kończy się wcześniej na
    /// braku danych i wady by nie ujawnił.
    #[test]
    fn test_kod_golomba_znosi_ponad_31_zer_bez_przepelnienia() {
        let mut dane = vec![0u8; 5]; // 40 zerowych bitów
        dane.push(0x80);             // ...zakończonych jedynką
        dane.extend_from_slice(&[0xFF; 8]);

        assert_eq!(czytnik(&dane).read_ue(), None, "zbyt długi kod musi zostać odrzucony, a nie przepełnić przesunięcie");
    }

    // ------------------------------------------------------------------
    // Listy skalowania w SPS
    // ------------------------------------------------------------------

    /// Wszystkie flagi wyzerowane: pomijamy dokładnie 8 bitów i ani jednego
    /// więcej.
    #[test]
    fn test_pomijanie_list_skalowania_zuzywa_same_flagi() {
        let dane = [0u8; 4];
        let mut br = czytnik(&dane);

        assert_eq!(skip_scaling_lists(&mut br, 1), Some(()));
        assert_eq!(br.bit_pos, 8, "osiem wyzerowanych flag to osiem bitów");
    }

    #[test]
    fn test_pomijanie_list_skalowania_dla_chromy_444() {
        let dane = [0u8; 4];
        let mut br = czytnik(&dane);

        assert_eq!(skip_scaling_lists(&mut br, 3), Some(()));
        assert_eq!(br.bit_pos, 12, "przy 4:4:4 list jest dwanaście, nie osiem");
    }

    /// Ustawiona flaga oznacza listę do przejścia — czytnik musi zużyć
    /// ZNACZNIE więcej niż same flagi.
    #[test]
    fn test_ustawiona_flaga_powoduje_przejscie_listy() {
        // Same jedynki: każda z ośmiu flag jest ustawiona, a każde `se(v)`
        // zapisane pojedynczym bitem `1` daje deltę 0. Jedna lista 4x4 to więc
        // 16 bitów, a komplet ośmiu list z flagami — 8 * (1 + 16) = 136 bitów.
        let dane = [0xFFu8; 32];

        let mut br = czytnik(&dane);
        assert_eq!(skip_scaling_lists(&mut br, 1), Some(()));
        // Listy o indeksach 0-5 opisują bloki 4x4 (16 wpisów), a 6-7 bloki
        // 8x8 (64 wpisy): 6*16 + 2*64 = 224 wpisy, plus 8 bitów flag.
        assert_eq!(
            br.bit_pos, 232,
            "sześć list po 16 wpisów, dwie po 64, plus osiem flag - zużyto {} bitów", br.bit_pos
        );
    }

    #[test]
    fn test_pomijanie_list_skalowania_znosi_urwane_dane() {
        let dane = [0b1000_0000u8]; // flaga ustawiona, ale danych listy brak
        assert_eq!(skip_scaling_lists(&mut czytnik(&dane), 1), None, "urwany strumień nie może panikować");
    }

    // ------------------------------------------------------------------
    // Bajty zapobiegania emulacji
    // ------------------------------------------------------------------

    #[test]
    fn test_usuwanie_bajtow_zapobiegania_emulacji() {
        assert_eq!(remove_emulation_prevention(&[0x00, 0x00, 0x03, 0x01]), vec![0x00, 0x00, 0x01]);
        assert_eq!(remove_emulation_prevention(&[0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x02]),
                   vec![0x00, 0x00, 0x00, 0x00, 0x02]);

        // 0x03 bez dwóch poprzedzających zer to zwykły bajt danych.
        assert_eq!(remove_emulation_prevention(&[0x00, 0x03, 0x01]), vec![0x00, 0x03, 0x01]);
        assert_eq!(remove_emulation_prevention(&[0xAA, 0xBB, 0xCC]), vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(remove_emulation_prevention(&[]), Vec::<u8>::new());
    }

    // ------------------------------------------------------------------
    // Parsowanie SPS — na PRAWDZIWYM strumieniu
    // ------------------------------------------------------------------

    /// Rozdzielczość z SPS musi zgadzać się z tym, co niezależnie raportuje
    /// `ffprobe`. Pomyłka tutaj trafia wprost do atomów `tkhd` i `stsd`
    /// odbudowanego pliku, czyli wideo deklarowałoby złe wymiary.
    #[test]
    fn test_rozdzielczosc_z_prawdziwego_sps() {
        assert_eq!(
            parse_sps_resolution(&SPS_RZECZYWISTY), Some((640, 368)),
            "wartości potwierdzone ffprobe na image/test_fixture.mp4"
        );
    }

    /// SPS z USTAWIONĄ flagą macierzy skalowania musi dać te same wymiary.
    ///
    /// # Dlaczego akurat ten SPS jest składany ręcznie
    ///
    /// Reszta testów w tym module stoi na materiale z prawdziwego kodera i tak
    /// być powinno. Tutaj się nie da: sprawdzone empirycznie, że **x264
    /// zapisuje macierze kwantyzacji w PPS, nie w SPS** — przy
    /// `-x264-params cqm=jvt` plik wychodzi z `pic_scaling_matrix_present_flag = 1`
    /// w PPS i `seq_scaling_matrix_present_flag = 0` w SPS, niezależnie od
    /// presetu. Żaden dostępny koder nie wyprodukuje więc materiału ćwiczącego
    /// tę gałąź, a jest ona zgodna ze specyfikacją i używana przez inne
    /// implementacje (m.in. kodery sprzętowe).
    ///
    /// Materiał zbudowany polem po polu: profil 100, chroma 4:2:0,
    /// `seq_scaling_matrix_present_flag = 1` i osiem wyzerowanych flag list,
    /// dalej pola dające 40x23 makrobloków, czyli 640x368.
    ///
    /// To jest test na konkretną wadę: dopóki w tym miejscu stała pusta
    /// instrukcja `if scaling_matrix_present == 1 {}`, czytnik nie pomijał
    /// ośmiu bitów flag i wychodził poza dane — funkcja zwracała `None`,
    /// a w realnym strumieniu z niezerowymi listami dałaby po prostu BŁĘDNĄ
    /// rozdzielczość, wpisywaną potem w `tkhd` i `stsd`.
    const SPS_Z_MACIERZA_SKALOWANIA: [u8; 10] = [
        0x27, 0x64, 0x00, 0x1e, 0xad, 0x00, 0xb4, 0x05, 0x01, 0x7c,
    ];

    #[test]
    fn test_rozdzielczosc_ze_sps_niosacego_macierz_skalowania() {
        assert_eq!(
            parse_sps_resolution(&SPS_Z_MACIERZA_SKALOWANIA), Some((640, 368)),
            "listy skalowania muszą zostać pominięte, inaczej wszystkie kolejne pola czytane są z błędnych pozycji"
        );
    }

    #[test]
    fn test_parsowanie_sps_odrzuca_smieci() {
        assert!(parse_sps_resolution(&[]).is_none(), "puste wejście");
        assert!(parse_sps_resolution(&[0x27, 0x64]).is_none(), "za krótki NAL");
        assert!(parse_sps_resolution(&[0u8; 32]).is_none(), "same zera nie są SPS-em");
    }

    /// Parser nie może panikować na dowolnym wejściu — Faza 17 karmi go
    /// materiałem z uszkodzonych plików.
    #[test]
    fn test_parsowanie_sps_nigdy_nie_panikuje() {
        for dlugosc in 0..40usize {
            for wzor in [0x00u8, 0xFF, 0xAA, 0x64] {
                let _ = parse_sps_resolution(&vec![wzor; dlugosc]);
            }
        }
        // Prawdziwy SPS obcinany na każdej długości - typowy plik ucięty.
        for i in 0..SPS_RZECZYWISTY.len() {
            let _ = parse_sps_resolution(&SPS_RZECZYWISTY[..i]);
        }
    }

    // ------------------------------------------------------------------
    // Budowa tablic indeksowych — porównanie BAJTOWE
    // ------------------------------------------------------------------

    fn klatka(offset: u64, size: u32, kluczowa: bool) -> FrameInfo {
        FrameInfo { offset, size, is_keyframe: kluczowa, nals: Vec::new() }
    }

    /// Uruchamia budowniczego atomu na pliku tymczasowym i zwraca zapisane bajty.
    fn zbuduj(f: impl FnOnce(&mut File) -> io::Result<()>) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let sciezka = dir.path().join("atom.bin");
        {
            let mut plik = File::create(&sciezka).unwrap();
            f(&mut plik).unwrap();
        }
        let mut bajty = Vec::new();
        std::io::Read::read_to_end(&mut File::open(&sciezka).unwrap(), &mut bajty).unwrap();
        bajty
    }

    fn u32_z(bajty: &[u8], od: usize) -> u32 {
        u32::from_be_bytes([bajty[od], bajty[od + 1], bajty[od + 2], bajty[od + 3]])
    }

    /// `stsz` niesie rozmiar KAŻDEJ próbki. Rozjazd między deklarowanym
    /// rozmiarem atomu a liczbą wpisów rozjeżdża cały dalszy odczyt `stbl`.
    #[test]
    fn test_stsz_ma_poprawny_rozmiar_i_wszystkie_wpisy() {
        let klatki = [klatka(100, 1111, true), klatka(1211, 2222, false), klatka(3433, 3333, false)];
        let bajty = zbuduj(|f| build_stsz_box(f, &klatki));

        assert_eq!(u32_z(&bajty, 0) as usize, bajty.len(), "zadeklarowany rozmiar musi równać się faktycznemu");
        assert_eq!(&bajty[4..8], b"stsz");
        assert_eq!(u32_z(&bajty, 12), 0, "sample_size = 0 znaczy „rozmiary podane per próbka”");
        assert_eq!(u32_z(&bajty, 16), 3, "liczba wpisów");

        let rozmiary: Vec<u32> = (0..3).map(|i| u32_z(&bajty, 20 + i * 4)).collect();
        assert_eq!(rozmiary, vec![1111, 2222, 3333]);
    }

    /// `stco` niesie OFFSETY próbek. To najwrażliwsza tablica w całym
    /// kontenerze — przekłamany offset daje plik, który się otwiera i pokazuje
    /// śmieci zamiast obrazu.
    #[test]
    fn test_stco_ma_poprawny_rozmiar_i_offsety_w_kolejnosci() {
        let klatki = [klatka(48, 10, true), klatka(58, 20, false), klatka(78, 30, false)];
        let bajty = zbuduj(|f| build_stco_box(f, &klatki));

        assert_eq!(u32_z(&bajty, 0) as usize, bajty.len());
        assert_eq!(&bajty[4..8], b"stco");
        assert_eq!(u32_z(&bajty, 12), 3);

        let offsety: Vec<u32> = (0..3).map(|i| u32_z(&bajty, 16 + i * 4)).collect();
        assert_eq!(offsety, vec![48, 58, 78], "offsety muszą trafić w tablicę w kolejności klatek");
    }

    /// `stss` wskazuje klatki kluczowe i indeksuje je od JEDNEGO, nie od zera.
    /// Przesunięcie o jeden sprawia, że odtwarzacz przewija w złe miejsce.
    #[test]
    fn test_stss_indeksuje_klatki_kluczowe_od_jedynki() {
        let klatki = [
            klatka(0, 10, true),    // indeks 1
            klatka(10, 10, false),
            klatka(20, 10, false),
            klatka(30, 10, true),   // indeks 4
        ];
        let bajty = zbuduj(|f| build_stss_box(f, &klatki));

        assert_eq!(u32_z(&bajty, 0) as usize, bajty.len());
        assert_eq!(&bajty[4..8], b"stss");
        assert_eq!(u32_z(&bajty, 12), 2, "dwie klatki kluczowe");
        assert_eq!(u32_z(&bajty, 16), 1, "pierwsza klatka ma indeks 1, nie 0");
        assert_eq!(u32_z(&bajty, 20), 4, "czwarta klatka ma indeks 4");
    }

    /// Materiał bez klatek kluczowych nie dostaje atomu `stss` w ogóle — pusta
    /// tablica byłaby niezgodna ze specyfikacją.
    #[test]
    fn test_stss_nie_powstaje_bez_klatek_kluczowych() {
        let klatki = [klatka(0, 10, false), klatka(10, 10, false)];
        assert!(zbuduj(|f| build_stss_box(f, &klatki)).is_empty());
    }

    #[test]
    fn test_tablice_znosza_pusta_liste_klatek() {
        let puste: [FrameInfo; 0] = [];

        let stsz = zbuduj(|f| build_stsz_box(f, &puste));
        assert_eq!(u32_z(&stsz, 0) as usize, stsz.len());
        assert_eq!(u32_z(&stsz, 16), 0);

        let stco = zbuduj(|f| build_stco_box(f, &puste));
        assert_eq!(u32_z(&stco, 0) as usize, stco.len());
        assert_eq!(u32_z(&stco, 12), 0);
    }

    // ------------------------------------------------------------------
    // Domykanie rozmiarów atomów (zapis wsteczny)
    // ------------------------------------------------------------------

    /// `BoxWriter` zapisuje rozmiar jako zero, a wpisuje właściwy dopiero przy
    /// zamknięciu. Błąd w tym mechanizmie daje atom o zerowym rozmiarze, czyli
    /// parser czytający do końca pliku.
    #[test]
    fn test_box_writer_domyka_rozmiar_po_zapisie_tresci() {
        let bajty = zbuduj(|f| {
            let bw = BoxWriter::new(f, b"test")?;
            bw.file.write_all(&[0xAB; 16])?;
            bw.close()
        });

        assert_eq!(bajty.len(), 24, "8 bajtów nagłówka + 16 bajtów treści");
        assert_eq!(u32_z(&bajty, 0), 24, "rozmiar musi zostać nadpisany faktyczną wartością");
        assert_eq!(&bajty[4..8], b"test");
        assert_eq!(&bajty[8..], &[0xAB; 16]);
    }

    #[test]
    fn test_box_writer_domyka_rozmiar_pustego_atomu() {
        let bajty = zbuduj(|f| BoxWriter::new(f, b"free")?.close());
        assert_eq!(u32_z(&bajty, 0), 8, "sam nagłówek to 8 bajtów");
    }

    /// `mdat` używa formatu 64-bitowego, bo dane wideo przekraczają 4 GB.
    /// Rozmiar stoi wtedy w osobnym polu za typem, a pole 32-bitowe niesie 1.
    #[test]
    fn test_mdat_writer_zapisuje_rozmiar_64_bitowy() {
        let bajty = zbuduj(|f| {
            let mw = MdatWriter::new(f)?;
            mw.file.write_all(&[0xCD; 100])?;
            mw.close()
        });

        assert_eq!(bajty.len(), 116, "16 bajtów nagłówka + 100 bajtów danych");
        assert_eq!(u32_z(&bajty, 0), 1, "jedynka zapowiada rozmiar 64-bitowy");
        assert_eq!(&bajty[4..8], b"mdat");

        let rozmiar = u64::from_be_bytes(bajty[8..16].try_into().unwrap());
        assert_eq!(rozmiar, 116, "rozmiar 64-bitowy musi objąć cały atom");
    }

    // ------------------------------------------------------------------
    // Materiał z PRAWDZIWEGO kodera
    // ------------------------------------------------------------------

    fn ffmpeg_jest() -> bool {
        std::process::Command::new("ffmpeg").arg("-version")
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
            .status().map(|s| s.success()).unwrap_or(false)
    }

    /// Koduje testowy materiał o zadanych wymiarach do MP4.
    fn zakoduj_mp4(katalog: &Path, szer: u32, wys: u32) -> PathBuf {
        let cel = katalog.join("zrodlo.mp4");
        let status = std::process::Command::new("ffmpeg")
            .args(["-nostdin", "-loglevel", "quiet", "-y", "-f", "lavfi", "-i"])
            .arg(format!("testsrc=size={}x{}:rate=25:duration=2", szer, wys))
            .args(["-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p"])
            .arg(&cel).status().expect("uruchomienie ffmpeg");
        assert!(status.success(), "kodowanie materiału testowego musi się udać");
        cel
    }

    /// Wyjmuje pierwszy SPS z atomu `avcC` pliku MP4.
    fn sps_z_avcc(plik: &Path) -> Vec<u8> {
        let dane = fs::read(plik).expect("odczyt pliku");
        let poz = dane.windows(4).position(|w| w == b"avcC").expect("plik musi mieć atom avcC");
        let cfg = &dane[poz + 4..];

        let liczba_sps = (cfg[5] & 0x1F) as usize;
        assert!(liczba_sps > 0, "avcC musi zawierać co najmniej jeden SPS");

        let dlugosc = u16::from_be_bytes([cfg[6], cfg[7]]) as usize;
        cfg[8..8 + dlugosc].to_vec()
    }

    /// Odczytuje wymiary strumienia wideo narzędziem niezależnym od naszego kodu.
    fn wymiary_wg_ffprobe(plik: &Path) -> (u32, u32) {
        let out = std::process::Command::new("ffprobe")
            .args(["-v", "error", "-select_streams", "v", "-show_entries", "stream=width,height",
                   "-of", "csv=p=0:s=x"])
            .arg(plik).output().expect("uruchomienie ffprobe");
        let tekst = String::from_utf8_lossy(&out.stdout);
        let (w, h) = tekst.trim().split_once('x').unwrap_or_else(|| panic!("ffprobe zwrócił: {:?}", tekst));
        (w.trim().parse().unwrap(), h.trim().parse().unwrap())
    }

    /// Rozdzielczość odczytana z SPS-a PRAWDZIWEGO kodera musi zgadzać się z
    /// tym, co niezależnie raportuje `ffprobe`.
    ///
    /// Wartości nie są tu zapisane na sztywno — pochodzą z dwóch niezależnych
    /// źródeł, a test sprawdza ich zgodność. Dzięki temu nie zestarzeje się
    /// przy zmianie wersji kodera.
    #[test]
    #[ignore = "Wymaga ffmpeg i ffprobe. Uruchom z --ignored."]
    fn test_e2e_rozdzielczosc_ze_sps_prawdziwego_kodera() {
        if !ffmpeg_jest() { panic!("brak ffmpeg - test wymaga prawdziwego kodera"); }

        let dir = tempfile::tempdir().unwrap();
        for (szer, wys) in [(640u32, 368u32), (320, 240), (176, 144)] {
            let mp4 = zakoduj_mp4(dir.path(), szer, wys);
            let sps = sps_z_avcc(&mp4);

            assert_eq!(
                parse_sps_resolution(&sps), Some(wymiary_wg_ffprobe(&mp4)),
                "rozdzielczość z SPS musi zgadzać się z ffprobe dla {}x{} (SPS: {:02x?})",
                szer, wys, sps
            );
        }
    }

    /// Pełna pętla silnika na materiale z prawdziwego kodera: surowy strumień
    /// Annex B wchodzi, kontener MP4 wychodzi — i ma WŁAŚCIWĄ rozdzielczość.
    ///
    /// To jedyny test, który domyka łańcuch od parsowania SPS-a aż po atomy
    /// `tkhd`/`stsd` gotowego pliku. Błąd w szerokości albo wysokości nie
    /// wywraca niczego po drodze; ujawnia się dopiero tutaj.
    #[test]
    #[ignore = "Wymaga ffmpeg i ffprobe. Uruchom z --ignored."]
    fn test_e2e_odbudowa_zachowuje_rozdzielczosc() {
        if !ffmpeg_jest() { panic!("brak ffmpeg - test wymaga prawdziwego kodera"); }

        let dir = tempfile::tempdir().unwrap();
        let mp4 = zakoduj_mp4(dir.path(), 640, 368);
        let oczekiwane = wymiary_wg_ffprobe(&mp4);

        // Wycinamy surowy strumień Annex B - dokładnie to, z czym silnik
        // Zero-Donor pracuje na materiale po carvingu.
        let surowy = dir.path().join("surowy.h264");
        let ok = std::process::Command::new("ffmpeg")
            .args(["-nostdin", "-loglevel", "quiet", "-y", "-i"]).arg(&mp4)
            .args(["-c", "copy", "-bsf:v", "h264_mp4toannexb", "-f", "h264"])
            .arg(&surowy).status().map(|s| s.success()).unwrap_or(false);
        assert!(ok, "wycięcie strumienia Annex B musi się udać");

        let wynik = dir.path().join("odbudowany.mp4");
        repair(surowy.to_str().unwrap(), wynik.to_str().unwrap(), None)
            .expect("odbudowa z surowego Annex B musi się udać");

        assert_eq!(
            wymiary_wg_ffprobe(&wynik), oczekiwane,
            "odbudowany kontener musi deklarować tę samą rozdzielczość co materiał źródłowy"
        );
    }

    // ------------------------------------------------------------------
    // Wejście publiczne
    // ------------------------------------------------------------------

    #[test]
    fn test_repair_odmawia_gdy_brak_pliku_wejsciowego() {
        let dir = tempfile::tempdir().unwrap();
        let wyjscie = dir.path().join("wynik.mp4");

        assert!(repair("/nie/ma/takiego/pliku", wyjscie.to_str().unwrap(), None).is_err());
        assert!(!wyjscie.exists(), "nieudana naprawa nie może zostawić pliku");
    }

    #[test]
    fn test_repair_odmawia_na_materiale_bez_strumienia_h264() {
        let dir = tempfile::tempdir().unwrap();
        let wejscie = dir.path().join("smieci.bin");
        let wyjscie = dir.path().join("wynik.mp4");
        std::fs::write(&wejscie, vec![0xAAu8; 4096]).unwrap();

        let wynik = repair(wejscie.to_str().unwrap(), wyjscie.to_str().unwrap(), None);
        assert!(wynik.is_err(), "bez jednostek NAL nie ma czego odbudowywać");
    }

    /// REGRESJA: sonda SPS (`buffer[i+start_len..i+start_len+36]`) czytana
    /// bezwarunkowym indeksowaniem, gdy start code + bajt typu 7 (SPS)
    /// pojawia się BLISKO KOŃCA pliku. Strażnik pętli głównej
    /// (`i < valid_data_size.saturating_sub(8)`) NIE chroni przed tym - trzyma
    /// tylko 8-bajtowy margines, a sonda sięga 36 bajtów naprzód. Dokładnie
    /// taki plik - ucięty tuż po nagłówku SPS - jest codziennym materiałem
    /// tego narzędzia z definicji.
    ///
    /// Pod starym, bezwarunkowym indeksowaniem to panikowało (`slice index
    /// out of range`). Dziś `buffer.get(..)` ma zwrócić `None` i pozwolić
    /// funkcji zakończyć się normalnie (błędem, nie paniką) - stąd
    /// `catch_unwind`: sedno testu to BRAK PANIKI, niezależnie od tego, czy
    /// ostateczny wynik to `Ok` czy `Err` (może zależeć od obecności ffmpeg
    /// jako mechanizmu awaryjnego).
    #[test]
    fn test_repair_nie_panikuje_na_sps_ucietym_blisko_konca_bufora() {
        let dir = tempfile::tempdir().unwrap();
        let zepsuty = dir.path().join("zepsuty.h264");
        let wynik_path = dir.path().join("wynik.mp4");

        // Start code (4B) + bajt NAL typu 7 (0x67 = dolne 5 bitów = 0b00111 = 7),
        // po którym zostaje ledwie 10 bajtów - dalekie od potrzebnych 36.
        let mut dane = vec![0x00, 0x00, 0x00, 0x01, 0x67];
        dane.extend_from_slice(&[0xAA; 10]);
        std::fs::write(&zepsuty, &dane).unwrap();

        let wynik_panic = std::panic::catch_unwind(|| {
            repair(zepsuty.to_str().unwrap(), wynik_path.to_str().unwrap(), None)
        });
        assert!(
            wynik_panic.is_ok(),
            "silnik Native spanikował na ucietym nagłówku SPS blisko końca bufora zamiast zwrócić błąd"
        );
    }

    /// REGRESJA: off-by-one przy sprawdzaniu KOLEJNEGO nagłówka ADTS.
    ///
    /// Skrojony tak, żeby domniemany "kolejny nagłówek" (`next_i = i +
    /// frame_size`) wypadał DOKŁADNIE na ostatnim bajcie bufora
    /// (`valid_data_size - 1`). Stary warunek `next_i < valid_data_size`
    /// przepuszczał to dalej i czytał `buffer[next_i+1]` - jeden bajt POZA
    /// buforem. Ucięty strumień audio, którego ostatnia ramka ADTS kończy się
    /// dosłownie na granicy pliku, jest dokładnie tym scenariuszem.
    #[test]
    fn test_repair_nie_panikuje_gdy_kolejny_naglowek_adts_wypada_na_ostatnim_bajcie() {
        let dir = tempfile::tempdir().unwrap();
        let zepsuty = dir.path().join("zepsuty.aac");
        let wynik_path = dir.path().join("wynik.mp4");

        // Nagłówek ADTS na i=0, tak dobrany, żeby frame_size == 19: skoro
        // bufor ma DOKŁADNIE 20 bajtów, `next_i = 0 + 19 = 19` to ostatni
        // ważny indeks - `buffer[next_i+1]` (bajt 20.) leży już poza buforem.
        let mut dane = vec![
            0xFFu8, // sync 1
            0xF1,   // sync 2 (górny nibl = 0xF)
            0x0D,   // freq_idx=3, bit0 kanałów=1
            0x40,   // wysokie bity frame_size=0, bit1 kanałów=1 (channels=5)
            0x02,   // środkowe bity frame_size
            0x60,   // niskie bity frame_size -> razem frame_size = 19
        ];
        dane.extend_from_slice(&[0u8; 14]); // dopełnienie do 20 bajtów razem
        assert_eq!(dane.len(), 20, "test zależy od DOKŁADNEJ długości bufora");
        std::fs::write(&zepsuty, &dane).unwrap();

        let wynik_panic = std::panic::catch_unwind(|| {
            repair(zepsuty.to_str().unwrap(), wynik_path.to_str().unwrap(), None)
        });
        assert!(
            wynik_panic.is_ok(),
            "silnik Native spanikował na nagłówku ADTS wypadającym na ostatnim bajcie bufora"
        );
    }

    /// Wywołanie zwrotne postępu jest opcjonalne — silnik musi działać tak
    /// samo, gdy go nie ma, i nie może panikować, gdy jest.
    #[test]
    fn test_wywolanie_zwrotne_postepu_jest_opcjonalne() {
        let dir = tempfile::tempdir().unwrap();
        let wejscie = dir.path().join("smieci.bin");
        std::fs::write(&wejscie, vec![0u8; 128]).unwrap();

        let zebrane = std::cell::RefCell::new(Vec::new());
        let _ = repair(
            wejscie.to_str().unwrap(),
            dir.path().join("a.mp4").to_str().unwrap(),
            Some(&|m: String| zebrane.borrow_mut().push(m)),
        );

        assert!(!zebrane.borrow().is_empty(), "silnik musi raportować postęp, gdy dostanie kanał");
    }
}
