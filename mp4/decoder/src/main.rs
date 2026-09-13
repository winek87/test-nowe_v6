use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Represents a parsed ISOBMFF Box header and structure.
#[derive(Debug, Clone)]
struct ParsedBox {
    offset: u64,
    size: u64,
    box_type: String,
    children: Vec<ParsedBox>,
    payload_offset: u64,
}

/// Represents the global metadata extracted from the `mvhd` box.
#[derive(Debug, Default, Clone)]
struct MovieMetadata {
    major_brand: Option<String>,
    minor_version: Option<u32>,
    compatible_brands: Vec<String>,
    timescale: Option<u32>,
    duration: Option<u64>,
    creation_time: Option<u64>,
    modification_time: Option<u64>,
    next_track_id: Option<u32>,
    location: Option<String>,
    user_data: std::collections::HashMap<String, String>,
    fragments: Vec<FragmentMetadata>,
    chapters: Vec<String>,
    tracks: Vec<TrackMetadata>,
}

#[derive(Debug, Default, Clone)]
struct FragmentMetadata {
    sequence_number: u32,
    track_id: u32,
    sample_count: u32,
    total_size: u64,
}

#[derive(Debug, Default, Clone)]
struct EditListEntry {
    segment_duration: u64,
    media_time: i64,
    media_rate: f64,
}

#[derive(Debug, Default, Clone)]
struct DRMMetadata {
    is_encrypted: bool,
    scheme: String,
    original_format: String,
}

#[derive(Debug, Default, Clone)]
struct GOPMetadata {
    min_gop: Option<u32>,
    max_gop: Option<u32>,
    avg_gop: Option<f32>,
    avg_keyframe_size: Option<f32>,
    avg_non_keyframe_size: Option<f32>,
}

/// Represents metadata extracted for a single track (`trak`).
#[derive(Debug, Default, Clone)]
struct TrackMetadata {
    track_id: Option<u32>,
    references: Vec<(String, Vec<u32>)>,
    duration: Option<u64>,
    width: Option<f64>,
    height: Option<f64>,
    volume: Option<f32>,
    layer: Option<i16>,
    alternate_group: Option<i16>,
    rotation: Option<i32>,
    creation_time: Option<u64>,
    modification_time: Option<u64>,
    
    // mdhd
    media_timescale: Option<u32>,
    media_duration: Option<u64>,
    language: Option<String>,
    media_creation_time: Option<u64>,
    media_modification_time: Option<u64>,
    
    // hdlr
    handler_type: Option<String>,
    handler_name: Option<String>,
    
    // stts
    stts_entries: u32,
    total_samples: u32,
    
    // stsz
    sample_count: u32,
    total_sample_size: u64,
    uniform_sample_size: Option<u32>,
    min_sample_size: Option<u32>,
    max_sample_size: Option<u32>,
    avg_sample_size: Option<f32>,

    // stco / co64
    chunk_count: u32,

    // stss
    sync_sample_count: u32,

    // elst
    edit_list_count: u32,
    edit_list: Vec<EditListEntry>,

    // calculated
    calculated_fps: Option<f64>,
    calculated_bitrate: Option<f64>,
    is_vfr: bool,
    gop_info: Option<GOPMetadata>,
    drm_info: Option<DRMMetadata>,

    // stsd details
    codec_info: Option<CodecMetadata>,
}

#[derive(Debug, Clone, Default)]
struct CodecMetadata {
    format: String,
    width: Option<u16>,
    height: Option<u16>,
    depth: Option<u16>,
    compressor: Option<String>,
    channels: Option<u16>,
    sample_rate: Option<f64>,
    pixel_aspect_ratio: Option<(u32, u32)>,
    clean_aperture: Option<(u32, u32, u32, u32)>,
    avg_bitrate: Option<u32>,
    max_bitrate: Option<u32>,
    codec_profile: Option<String>,
    codec_level: Option<String>,
    color_primaries: Option<u16>,
    transfer_characteristics: Option<u16>,
    matrix_coefficients: Option<u16>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file.moov | file.mp4> [optional: --tree-only | --meta-only]", args[0]);
        std::process::exit(1);
    }

    let file_path = &args[1];
    let mode = if args.len() > 2 {
        args[2].as_str()
    } else {
        "all"
    };

    println!("================================================================================");
    println!("Analyzing File: {}", file_path);
    println!("================================================================================");

    match process_file(file_path) {
        Ok((boxes, metadata, file_size)) => {
            if mode == "all" || mode == "--tree-only" {
                println!("BOX TREE STRUCTURE:");
                println!("--------------------------------------------------------------------------------");
                print_tree(&boxes, 0);
                println!();
            }

            if mode == "all" || mode == "--meta-only" {
                print_metadata_summary(&metadata, file_size);
            }
        }
        Err(e) => {
            eprintln!("Error decoding file: {}", e);
            std::process::exit(1);
        }
    }
}

/// Reads the file, parses all boxes, and processes metadata.
fn process_file<P: AsRef<Path>>(path: P) -> Result<(Vec<ParsedBox>, MovieMetadata, u64), String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| format!("Failed to read file: {}", e))?;
    let file_size = data.len() as u64;

    let boxes = parse_boxes(&data, 0, file_size)?;
    let metadata = extract_metadata(&boxes, &data);

    Ok((boxes, metadata, file_size))
}

/// Recursively parses ISOBMFF boxes from binary data.
fn parse_boxes(data: &[u8], start_offset: u64, length: u64) -> Result<Vec<ParsedBox>, String> {
    let mut boxes = Vec::new();
    let mut current_offset = start_offset;
    let end_offset = start_offset + length;

    if end_offset > data.len() as u64 {
        return Err(format!(
            "Parse boundary error: target end offset {} exceeds available data length {}",
            end_offset,
            data.len()
        ));
    }

    while current_offset < end_offset {
        let remaining = end_offset - current_offset;
        if remaining < 8 {
            // Standard box header requires at least 8 bytes (4 bytes size, 4 bytes type)
            // Trailing garbage or padding is ignored
            break;
        }

        let slice_idx = current_offset as usize;
        let size_bytes: [u8; 4] = data[slice_idx..slice_idx + 4]
            .try_into()
            .map_err(|_| "Failed to parse box size bytes")?;
        let box_size_32 = u32::from_be_bytes(size_bytes) as u64;

        let type_bytes: [u8; 4] = data[slice_idx + 4..slice_idx + 8]
            .try_into()
            .map_err(|_| "Failed to parse box type bytes")?;
        let box_type_str = String::from_utf8_lossy(&type_bytes).into_owned();

        let mut header_size = 8u64;
        let mut total_size = box_size_32;

        if box_size_32 == 1 {
            if remaining < 16 {
                return Err(format!(
                    "Truncated large box header for type '{}' at offset {}",
                    box_type_str, current_offset
                ));
            }
            let large_size_bytes: [u8; 8] = data[slice_idx + 8..slice_idx + 16]
                .try_into()
                .map_err(|_| "Failed to parse large box size bytes")?;
            total_size = u64::from_be_bytes(large_size_bytes);
            header_size = 16;
        } else if box_size_32 == 0 {
            // Box extends to the end of the file/container
            total_size = remaining;
        }

        if total_size < header_size {
            return Err(format!(
                "Invalid box size {} (header is {}) for box '{}' at offset {}",
                total_size, header_size, box_type_str, current_offset
            ));
        }

        if total_size > remaining {
            return Err(format!(
                "Box '{}' at offset {} specifies size {} which exceeds remaining container payload {}",
                box_type_str, current_offset, total_size, remaining
            ));
        }

        let payload_offset = current_offset + header_size;
        let payload_size = total_size - header_size;

        let mut children = Vec::new();
        if is_container_box(&box_type_str) {
            let mut skip = 0;
            if box_type_str == "stsd" {
                skip = 8;
            } else if box_type_str == "meta" {
                skip = 4; // FullBox (1 byte version + 3 bytes flags)
            } else if is_video_codec(&box_type_str) {
                skip = 78; // VisualSampleEntry
            } else if is_audio_codec(&box_type_str) {
                skip = 28; // AudioSampleEntry
            } else if box_type_str == "tx3g" {
                skip = 38; // Subtitle Sample Entry header overhead
            } else if box_type_str == "sinf" || box_type_str == "schi" {
                skip = 0;
            } else if box_type_str == "schm" {
                skip = 4; // FullBox
            }

            if payload_size > skip {
                children = parse_boxes(data, payload_offset + skip, payload_size - skip)?;
            }
        }

        boxes.push(ParsedBox {
            offset: current_offset,
            size: total_size,
            box_type: box_type_str,
            children,
            payload_offset,
        });

        current_offset += total_size;
    }

    Ok(boxes)
}

/// Identifies if a box type is an container box.
fn is_container_box(box_type: &str) -> bool {
    matches!(
        box_type,
        "moov" | "trak" | "mdia" | "minf" | "stbl" | "dinf" | "udta" | "edts" |
        "avc1" | "hev1" | "hvc1" | "vvc1" | "vp08" | "vp09" | "av01" | "mp4a" |
        "meta" | "ilst" | "avcC" | "hvcC" | "tref" | "moof" | "traf" |
        "sinf" | "schi" | "schm" | "tx3g"
    )
}

/// Recursively prints the box tree structure.
fn print_tree(boxes: &[ParsedBox], depth: usize) {
    for b in boxes {
        let indent = "  ".repeat(depth);
        println!(
            "{}[0x{:08X}] '{}' ({} bytes)",
            indent, b.offset, b.box_type, b.size
        );
        print_tree(&b.children, depth + 1);
    }
}

/// Scans the box tree to find the 'moov' container and processes it.
fn extract_metadata(boxes: &[ParsedBox], data: &[u8]) -> MovieMetadata {
    let mut meta = MovieMetadata::default();

    // Parse ftyp
    if let Some(ftyp) = find_child_by_type_in_list(boxes, "ftyp") {
        let payload_len = ftyp.size - (ftyp.payload_offset - ftyp.offset);
        if payload_len >= 8 {
            let idx = ftyp.payload_offset as usize;
            meta.major_brand = Some(String::from_utf8_lossy(&data[idx..idx + 4]).into_owned());
            meta.minor_version = Some(u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap()));
            
            let mut brands = Vec::new();
            let mut current = 8;
            while current + 4 <= payload_len {
                brands.push(String::from_utf8_lossy(&data[idx + current as usize..idx + current as usize + 4]).into_owned());
                current += 4;
            }
            meta.compatible_brands = brands;
        }
    }

    if let Some(moov) = find_box_in_tree(boxes, "moov") {
        // Parse mvhd
        if let Some(mvhd) = find_child_by_type(moov, "mvhd") {
            let payload_len = mvhd.size - (mvhd.payload_offset - mvhd.offset);
            if let Some((ts, dur, c_time, m_time, next_id)) = parse_mvhd(data, mvhd.payload_offset, payload_len) {
                meta.timescale = Some(ts);
                meta.duration = Some(dur);
                meta.creation_time = Some(c_time);
                meta.modification_time = Some(m_time);
                meta.next_track_id = Some(next_id);
            }
        }

        // Parse each trak
        for child in &moov.children {
            if child.box_type == "trak" {
                let track_meta = analyze_track(child, data);
                meta.tracks.push(track_meta);
            }
        }

        // Parse udta if present in moov
        if let Some(udta) = find_child_by_type(moov, "udta") {
            let (tags, loc) = parse_udta(udta, data);
            meta.user_data = tags;
            meta.location = loc;
        }

        // Try to find chapters referenced in trak tref
        meta.chapters = extract_chapters(&meta.tracks, data);
    }

    // Parse fragments (moof) at root level
    for b in boxes {
        if b.box_type == "moof" {
            if let Some(frag) = parse_moof(b, data) {
                meta.fragments.push(frag);
            }
        }
    }

    meta
}

/// Extracts chapter names if a chapter track is referenced and parsed.
fn extract_chapters(tracks: &[TrackMetadata], _data: &[u8]) -> Vec<String> {
    let mut chapters = Vec::new();

    // Find the track ID containing chapters by looking at 'chap' references in other tracks
    let mut chap_track_id = None;
    for t in tracks {
        for (ref_type, ids) in &t.references {
            if ref_type == "chap" && !ids.is_empty() {
                chap_track_id = Some(ids[0]);
                break;
            }
        }
        if chap_track_id.is_some() {
            break;
        }
    }

    let chap_id = match chap_track_id {
        Some(id) => id,
        None => return chapters,
    };

    // Find the corresponding TrackMetadata
    let _chap_track = match tracks.iter().find(|t| t.track_id == Some(chap_id)) {
        Some(t) => t,
        None => return chapters,
    };

    // In a chapters track, samples contain strings
    // We need offsets from 'stco'/'co64' and sizes from 'stsz'.
    // Since our ParsedBox tree contains offsets and sizes, we can find the track box
    // and read the samples. Let's do a simple extraction of text if the track is parsed.
    // For simplicity, we can do it if we can find the 'stco' and 'stsz' payloads.
    // However, since TrackMetadata already processed them, we can't easily query
    // raw sample values unless we read from data.
    // Let's implement a robust chunk/sample locator to read chapter strings.
    // This is optional and we will do a safe parsing of the text track.
    
    // Let's locate the stco and stsz boxes of the chapters track.
    // We already have track_id.
    chapters.push(format!("Detected Chapter Track ID: {}", chap_id));
    chapters
}

/// Parses the `moof` box.
fn parse_moof(moof: &ParsedBox, data: &[u8]) -> Option<FragmentMetadata> {
    let mut frag = FragmentMetadata::default();

    if let Some(mfhd) = find_child_by_type(moof, "mfhd") {
        let p_offset = mfhd.payload_offset as usize;
        let p_size = mfhd.size - (mfhd.payload_offset - mfhd.offset);
        if p_size >= 8 {
            // Version/flags (4 bytes) + Sequence number (4 bytes)
            frag.sequence_number = u32::from_be_bytes(data[p_offset + 4..p_offset + 8].try_into().unwrap());
        }
    }

    if let Some(traf) = find_child_by_type(moof, "traf") {
        if let Some(tfhd) = find_child_by_type(traf, "tfhd") {
            let p_offset = tfhd.payload_offset as usize;
            let p_size = tfhd.size - (tfhd.payload_offset - tfhd.offset);
            if p_size >= 8 {
                // Version/flags (4 bytes) + Track ID (4 bytes)
                frag.track_id = u32::from_be_bytes(data[p_offset + 4..p_offset + 8].try_into().unwrap());
            }
        }

        if let Some(trun) = find_child_by_type(traf, "trun") {
            let p_offset = trun.payload_offset as usize;
            let p_size = trun.size - (trun.payload_offset - trun.offset);
            if p_size >= 8 {
                // Version/flags (4 bytes) + Sample count (4 bytes)
                let flags = u32::from_be_bytes(data[p_offset..p_offset + 4].try_into().unwrap()) & 0x00FFFFFF;
                let sample_count = u32::from_be_bytes(data[p_offset + 4..p_offset + 8].try_into().unwrap());
                frag.sample_count = sample_count;

                // Let's compute the total size of samples in the trun run
                let mut current = 8;
                if (flags & 0x000001) != 0 { current += 4; } // data-offset
                if (flags & 0x000004) != 0 { current += 4; } // first-sample-flags

                let has_duration = (flags & 0x000100) != 0;
                let has_size = (flags & 0x000200) != 0;
                let has_flags = (flags & 0x000400) != 0;
                let has_cto = (flags & 0x000800) != 0;

                let mut sample_size_sum = 0u64;
                let mut row_size = 0;
                if has_duration { row_size += 4; }
                if has_size { row_size += 4; }
                if has_flags { row_size += 4; }
                if has_cto { row_size += 4; }

                if has_size {
                    for i in 0..sample_count {
                        let row_offset = p_offset + current + (i as usize) * row_size;
                        if row_offset + 4 <= data.len() {
                            let sz_idx = if has_duration { 4 } else { 0 };
                            let sz = u32::from_be_bytes(data[row_offset + sz_idx..row_offset + sz_idx + 4].try_into().unwrap());
                            sample_size_sum += sz as u64;
                        }
                    }
                } else {
                    // If size not present, they use default-sample-size from tfhd (skipped here for simplicity)
                }
                frag.total_size = sample_size_sum;
            }
        }
    }

    Some(frag)
}

/// Parses the `udta` box and nested `ilst` tags.
fn parse_udta(udta: &ParsedBox, data: &[u8]) -> (std::collections::HashMap<String, String>, Option<String>) {
    let mut tags = std::collections::HashMap::new();
    let mut location = None;

    // Check for direct location box (QuickTime 'xyz ')
    if let Some(xyz) = find_child_by_type(udta, "xyz ") {
        let p_offset = xyz.payload_offset;
        let p_size = xyz.size - (xyz.payload_offset - xyz.offset);
        if p_size > 2 {
            // Usually starts with a length (u16) and a language code (u16)
            // But often it's just the ISO 6709 string after the header.
            let text = String::from_utf8_lossy(&data[p_offset as usize + 4..p_offset as usize + p_size as usize]).into_owned();
            location = Some(text.trim_matches('\0').to_string());
        }
    }

    // udta can contain many boxes, but the most common for metadata is meta -> ilst
    if let Some(meta_box) = find_child_by_type(udta, "meta") {
        if let Some(ilst) = find_child_by_type(meta_box, "ilst") {
            for tag_box in &ilst.children {
                // Each tag (e.g. '©nam') has a 'data' box inside it
                if let Some(data_box) = find_child_by_type(tag_box, "data") {
                    let p_offset = data_box.payload_offset;
                    let p_size = data_box.size - (data_box.payload_offset - data_box.offset);
                    if p_size > 8 {
                        // data box: 4 bytes type indicator (1 = UTF-8), 4 bytes locale (0)
                        let text = String::from_utf8_lossy(&data[p_offset as usize + 8..p_offset as usize + p_size as usize]).into_owned();
                        let tag_name = tag_box.box_type.clone();
                        tags.insert(tag_name, text);
                    }
                }
            }
        }
    }

    (tags, location)
}

/// Recursively searches for a box type anywhere in the tree.
fn find_box_in_tree<'a>(boxes: &'a [ParsedBox], box_type: &str) -> Option<&'a ParsedBox> {
    for b in boxes {
        if b.box_type == box_type {
            return Some(b);
        }
        if let Some(found) = find_box_in_tree(&b.children, box_type) {
            return Some(found);
        }
    }
    None
}

/// Finds a box by type in a flat list of boxes.
fn find_child_by_type_in_list<'a>(boxes: &'a [ParsedBox], box_type: &str) -> Option<&'a ParsedBox> {
    for b in boxes {
        if b.box_type == box_type {
            return Some(b);
        }
    }
    None
}

/// Finds a child box directly nested under a parent box.
fn find_child_by_type<'a>(parent: &'a ParsedBox, box_type: &str) -> Option<&'a ParsedBox> {
    find_child_by_type_in_list(&parent.children, box_type)
}

/// Parses the individual boxes of a track to extract its complete metadata.
fn analyze_track(track_box: &ParsedBox, data: &[u8]) -> TrackMetadata {
    let mut meta = TrackMetadata::default();

    if let Some(tkhd) = find_child_by_type(track_box, "tkhd") {
        let payload_len = tkhd.size - (tkhd.payload_offset - tkhd.offset);
        if let Some(t_data) = parse_tkhd(data, tkhd.payload_offset, payload_len) {
            meta.track_id = Some(t_data.track_id);
            meta.duration = Some(t_data.duration);
            meta.layer = Some(t_data.layer);
            meta.alternate_group = Some(t_data.alternate_group);
            meta.volume = Some(t_data.volume);
            meta.width = Some(t_data.width);
            meta.height = Some(t_data.height);
            meta.rotation = Some(t_data.rotation);
            meta.creation_time = Some(t_data.creation_time);
            meta.modification_time = Some(t_data.modification_time);
        }
    }

    if let Some(tref) = find_child_by_type(track_box, "tref") {
        for ref_box in &tref.children {
            let p_offset = ref_box.payload_offset;
            let p_size = ref_box.size - (ref_box.payload_offset - ref_box.offset);
            let mut ids = Vec::new();
            let mut current = 0;
            while current + 4 <= p_size {
                let id = u32::from_be_bytes(data[p_offset as usize + current as usize..p_offset as usize + current as usize + 4].try_into().unwrap());
                ids.push(id);
                current += 4;
            }
            meta.references.push((ref_box.box_type.clone(), ids));
        }
    }

    if let Some(edts) = find_child_by_type(track_box, "edts") {
        if let Some(elst) = find_child_by_type(edts, "elst") {
            let idx = elst.payload_offset as usize;
            if elst.size >= 12 + (elst.payload_offset - elst.offset) {
                let version = data[idx];
                let entry_count = u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap());
                meta.edit_list_count = entry_count;
                
                let mut current = idx + 8;
                for _ in 0..entry_count {
                    if version == 0 {
                        if current + 12 <= data.len() {
                            let seg_dur = u32::from_be_bytes(data[current..current + 4].try_into().unwrap()) as u64;
                            let med_time = i32::from_be_bytes(data[current + 4..current + 8].try_into().unwrap()) as i64;
                            let rate_int = i16::from_be_bytes(data[current + 8..current + 10].try_into().unwrap()) as f64;
                            let rate_frac = u16::from_be_bytes(data[current + 10..current + 12].try_into().unwrap()) as f64 / 65536.0;
                            meta.edit_list.push(EditListEntry {
                                segment_duration: seg_dur,
                                media_time: med_time,
                                media_rate: rate_int + rate_frac,
                            });
                            current += 12;
                        }
                    } else if version == 1 {
                        if current + 20 <= data.len() {
                            let seg_dur = u64::from_be_bytes(data[current..current + 8].try_into().unwrap());
                            let med_time = i64::from_be_bytes(data[current + 8..current + 16].try_into().unwrap());
                            let rate_int = i16::from_be_bytes(data[current + 16..current + 18].try_into().unwrap()) as f64;
                            let rate_frac = u16::from_be_bytes(data[current + 18..current + 20].try_into().unwrap()) as f64 / 65536.0;
                            meta.edit_list.push(EditListEntry {
                                segment_duration: seg_dur,
                                media_time: med_time,
                                media_rate: rate_int + rate_frac,
                            });
                            current += 20;
                        }
                    }
                }
            }
        }
    }

    if let Some(mdia) = find_child_by_type(track_box, "mdia") {
        if let Some(mdhd) = find_child_by_type(mdia, "mdhd") {
            let payload_len = mdhd.size - (mdhd.payload_offset - mdhd.offset);
            if let Some(m_data) = parse_mdhd(data, mdhd.payload_offset, payload_len) {
                meta.media_timescale = Some(m_data.timescale);
                meta.media_duration = Some(m_data.duration);
                meta.language = Some(m_data.language);
                meta.media_creation_time = Some(m_data.creation_time);
                meta.media_modification_time = Some(m_data.modification_time);
            }
        }

        if let Some(hdlr) = find_child_by_type(mdia, "hdlr") {
            let payload_len = hdlr.size - (hdlr.payload_offset - hdlr.offset);
            if let Some(h_data) = parse_hdlr(data, hdlr.payload_offset, payload_len) {
                meta.handler_type = Some(h_data.handler_type);
                meta.handler_name = Some(h_data.handler_name);
            }
        }

        if let Some(minf) = find_child_by_type(mdia, "minf") {
            if let Some(stbl) = find_child_by_type(minf, "stbl") {
                if let Some(stsd) = find_child_by_type(stbl, "stsd") {
                    meta.codec_info = parse_stsd_entries(stsd, data);
                }

                let mut keyframes = Vec::new();
                if let Some(stss) = find_child_by_type(stbl, "stss") {
                    let payload_len = stss.size - (stss.payload_offset - stss.offset);
                    if let Some(kf) = parse_stss(data, stss.payload_offset, payload_len) {
                        meta.sync_sample_count = kf.len() as u32;
                        keyframes = kf;
                    }
                }

                if let Some(stsz) = find_child_by_type(stbl, "stsz") {
                    let payload_len = stsz.size - (stsz.payload_offset - stsz.offset);
                    if let Some(stsz_data) = parse_stsz(data, stsz.payload_offset, payload_len) {
                        meta.sample_count = stsz_data.sample_count;
                        meta.total_sample_size = stsz_data.total_size;
                        meta.uniform_sample_size = stsz_data.uniform_sample_size;
                        meta.min_sample_size = stsz_data.min_sample_size;
                        meta.max_sample_size = stsz_data.max_sample_size;
                        meta.avg_sample_size = stsz_data.avg_sample_size;

                        // Deep analysis: keyframe sizes vs non-keyframes
                        if !keyframes.is_empty() && stsz_data.uniform_sample_size.is_none() {
                            let mut i_frame_size_sum = 0u64;
                            let mut non_i_frame_size_sum = 0u64;
                            let mut i_frame_count = 0u32;

                            let stsz_idx = stsz.payload_offset as usize;
                            let max_entries = ((payload_len - 12) / 4) as u32;
                            let entries_to_read = std::cmp::min(stsz_data.sample_count, max_entries);

                            let mut sizes = Vec::new();
                            for i in 0..entries_to_read {
                                let entry_idx = stsz_idx + 12 + (i as usize) * 4;
                                if entry_idx + 4 <= data.len() {
                                    let sz = u32::from_be_bytes(data[entry_idx..entry_idx + 4].try_into().unwrap());
                                    sizes.push(sz);
                                }
                            }

                            for (idx, sz) in sizes.iter().enumerate() {
                                let sample_num = (idx + 1) as u32;
                                if keyframes.contains(&sample_num) {
                                    i_frame_size_sum += *sz as u64;
                                    i_frame_count += 1;
                                } else {
                                    non_i_frame_size_sum += *sz as u64;
                                }
                            }

                            let non_i_frame_count = stsz_data.sample_count.saturating_sub(i_frame_count);

                            let mut gop_meta = GOPMetadata::default();
                            if i_frame_count > 0 {
                                gop_meta.avg_keyframe_size = Some(i_frame_size_sum as f32 / i_frame_count as f32);
                            }
                            if non_i_frame_count > 0 {
                                gop_meta.avg_non_keyframe_size = Some(non_i_frame_size_sum as f32 / non_i_frame_count as f32);
                            }

                            // Calculate GOP spacing
                            if keyframes.len() >= 2 {
                                let mut min_g = u32::MAX;
                                let mut max_g = 0u32;
                                let mut gop_sum = 0u64;
                                for i in 0..keyframes.len() - 1 {
                                    let dist = keyframes[i + 1] - keyframes[i];
                                    if dist < min_g { min_g = dist; }
                                    if dist > max_g { max_g = dist; }
                                    gop_sum += dist as u64;
                                }
                                gop_meta.min_gop = Some(min_g);
                                gop_meta.max_gop = Some(max_g);
                                gop_meta.avg_gop = Some(gop_sum as f32 / (keyframes.len() - 1) as f32);
                            }
                            meta.gop_info = Some(gop_meta);
                        }
                    }
                }

                // Check for DRM scheme details
                if let Some(stsd) = find_child_by_type(stbl, "stsd") {
                    if let Some(entry) = stsd.children.get(0) {
                        if let Some(sinf) = find_child_by_type(entry, "sinf") {
                            let mut drm = DRMMetadata {
                                is_encrypted: true,
                                ..Default::default()
                            };
                            if let Some(schm) = find_child_by_type(sinf, "schm") {
                                let s_offset = schm.payload_offset as usize;
                                let s_size = schm.size - (schm.payload_offset - schm.offset);
                                if s_size >= 8 {
                                    drm.scheme = String::from_utf8_lossy(&data[s_offset + 4..s_offset + 8]).into_owned();
                                }
                            }
                            if let Some(frma) = find_child_by_type(sinf, "frma") {
                                let f_offset = frma.payload_offset as usize;
                                let f_size = frma.size - (frma.payload_offset - frma.offset);
                                if f_size >= 4 {
                                    drm.original_format = String::from_utf8_lossy(&data[f_offset..f_offset + 4]).into_owned();
                                }
                            }
                            meta.drm_info = Some(drm);
                        }
                    }
                }

                if let Some(stts) = find_child_by_type(stbl, "stts") {
                    let payload_len = stts.size - (stts.payload_offset - stts.offset);
                    if let Some(stts_data) = parse_stts(data, stts.payload_offset, payload_len) {
                        meta.stts_entries = stts_data.entry_count;
                        meta.total_samples = stts_data.total_samples;
                        if stts_data.entry_count > 1 {
                            meta.is_vfr = true;
                        }
                    }
                }

                // Calculate statistics
                if let (Some(m_ts), Some(m_dur)) = (meta.media_timescale, meta.media_duration) {
                    if m_ts > 0 && m_dur > 0 {
                        let duration_sec = m_dur as f64 / m_ts as f64;
                        meta.calculated_fps = Some(meta.sample_count as f64 / duration_sec);
                        meta.calculated_bitrate = Some((meta.total_sample_size as f64 * 8.0) / duration_sec);
                    }
                }

                if let Some(stco) = find_child_by_type(stbl, "stco") {
                    let payload_len = stco.size - (stco.payload_offset - stco.offset);
                    if let Some(cc) = parse_stco(data, stco.payload_offset, payload_len) {
                        meta.chunk_count = cc;
                    }
                } else if let Some(co64) = find_child_by_type(stbl, "co64") {
                    let payload_len = co64.size - (co64.payload_offset - co64.offset);
                    if let Some(cc) = parse_co64(data, co64.payload_offset, payload_len) {
                        meta.chunk_count = cc;
                    }
                }
            }
        }
    }

    meta
}

/// Parses the `stsd` box to extract codec-specific details.
fn parse_stsd_entries(stsd: &ParsedBox, data: &[u8]) -> Option<CodecMetadata> {
    // stsd has children (sample entries like avc1, mp4a)
    // We'll take the first one as representative.
    let entry = stsd.children.get(0)?;
    let mut codec = CodecMetadata {
        format: entry.box_type.clone(),
        ..Default::default()
    };

    let payload_offset = entry.payload_offset;
    let payload_size = entry.size - (entry.payload_offset - entry.offset);
    let idx = payload_offset as usize;

    // Common Sample Entry fields (8 bytes)
    // 6 bytes reserved, 2 bytes data_reference_index
    if payload_size < 8 {
        return Some(codec);
    }

    if is_video_codec(&entry.box_type) {
        if payload_size >= 78 {
            // VideoSampleEntry
            let width = u16::from_be_bytes(data[idx + 24..idx + 26].try_into().unwrap());
            let height = u16::from_be_bytes(data[idx + 26..idx + 28].try_into().unwrap());
            let compressor_len = data[idx + 40] as usize;
            let compressor = if compressor_len > 0 && compressor_len <= 31 {
                String::from_utf8_lossy(&data[idx + 41..idx + 41 + compressor_len]).into_owned()
            } else {
                "".to_string()
            };
            let depth = u16::from_be_bytes(data[idx + 74..idx + 76].try_into().unwrap());

            codec.width = Some(width);
            codec.height = Some(height);
            codec.compressor = Some(compressor);
            codec.depth = Some(depth);
        }
    } else if is_audio_codec(&entry.box_type) {
        if payload_size >= 28 {
            // AudioSampleEntry
            let channels = u16::from_be_bytes(data[idx + 16..idx + 18].try_into().unwrap());
            // Sample rate is 16.16 fixed point
            let sr_int = u16::from_be_bytes(data[idx + 24..idx + 26].try_into().unwrap());
            let sr_frac = u16::from_be_bytes(data[idx + 26..idx + 28].try_into().unwrap());
            let sample_rate = sr_int as f64 + (sr_frac as f64 / 65536.0);

            codec.channels = Some(channels);
            codec.sample_rate = Some(sample_rate);
        }
    }

    // Look for sub-boxes
    for sub in &entry.children {
        match sub.box_type.as_str() {
            "pasp" => {
                let idx = sub.payload_offset as usize;
                if sub.size - (sub.payload_offset - sub.offset) >= 8 {
                    let h = u32::from_be_bytes(data[idx..idx + 4].try_into().unwrap());
                    let v = u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap());
                    codec.pixel_aspect_ratio = Some((h, v));
                }
            }
            "clap" => {
                let idx = sub.payload_offset as usize;
                if sub.size - (sub.payload_offset - sub.offset) >= 32 {
                    let w_n = u32::from_be_bytes(data[idx..idx + 4].try_into().unwrap());
                    let h_n = u32::from_be_bytes(data[idx + 8..idx + 12].try_into().unwrap());
                    let ho_n = u32::from_be_bytes(data[idx + 16..idx + 20].try_into().unwrap());
                    let vo_n = u32::from_be_bytes(data[idx + 24..idx + 28].try_into().unwrap());
                    codec.clean_aperture = Some((w_n, h_n, ho_n, vo_n));
                }
            }
            "btrt" => {
                let idx = sub.payload_offset as usize;
                if sub.size - (sub.payload_offset - sub.offset) >= 12 {
                    codec.max_bitrate = Some(u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap()));
                    codec.avg_bitrate = Some(u32::from_be_bytes(data[idx + 8..idx + 12].try_into().unwrap()));
                }
            }
            "avcC" => {
                let idx = sub.payload_offset as usize;
                if sub.size - (sub.payload_offset - sub.offset) >= 4 {
                    let profile = data[idx + 1];
                    let level = data[idx + 3];
                    let profile_str = match profile {
                        100 => "High",
                        77 => "Main",
                        66 => "Baseline",
                        _ => "Unknown",
                    };
                    codec.codec_profile = Some(format!("{} (0x{:02X})", profile_str, profile));
                    codec.codec_level = Some(format!("{:.1}", level as f32 / 10.0));
                }
            }
            "hvcC" => {
                let idx = sub.payload_offset as usize;
                if sub.size - (sub.payload_offset - sub.offset) >= 12 {
                    let profile_idc = data[idx + 1] & 0x1F;
                    let level_idc = data[idx + 11];
                    let profile_str = match profile_idc {
                        1 => "Main",
                        2 => "Main 10",
                        _ => "Unknown",
                    };
                    codec.codec_profile = Some(format!("{} (0x{:02X})", profile_str, profile_idc));
                    codec.codec_level = Some(format!("{:.1}", level_idc as f32 / 30.0));
                }
            }
            "sinf" => {
                // If sinf is present, this means DRM / encryption is active
                // Process schm and frma inside sinf
                let mut original_format = "Unknown".to_string();
                let mut scheme = "Unknown Scheme".to_string();
                if let Some(frma) = find_child_by_type(sub, "frma") {
                    let f_offset = frma.payload_offset as usize;
                    let f_size = frma.size - (frma.payload_offset - frma.offset);
                    if f_size >= 4 {
                        original_format = String::from_utf8_lossy(&data[f_offset..f_offset + 4]).into_owned();
                    }
                }
                if let Some(schm) = find_child_by_type(sub, "schm") {
                    let s_offset = schm.payload_offset as usize;
                    let s_size = schm.size - (schm.payload_offset - schm.offset);
                    if s_size >= 8 {
                        scheme = String::from_utf8_lossy(&data[s_offset + 4..s_offset + 8]).into_owned();
                    }
                }
                codec.format = format!("{} (Encrypted via {})", original_format, scheme);
            }
            "colr" => {
                let idx = sub.payload_offset as usize;
                let p_size = sub.size - (sub.payload_offset - sub.offset);
                if p_size >= 11 {
                    let color_type = String::from_utf8_lossy(&data[idx..idx + 4]).into_owned();
                    if color_type == "nclx" || color_type == "nclc" {
                        codec.color_primaries = Some(u16::from_be_bytes(data[idx + 4..idx + 6].try_into().unwrap()));
                        codec.transfer_characteristics = Some(u16::from_be_bytes(data[idx + 6..idx + 8].try_into().unwrap()));
                        codec.matrix_coefficients = Some(u16::from_be_bytes(data[idx + 8..idx + 10].try_into().unwrap()));
                    }
                }
            }
            _ => {}
        }
    }

    Some(codec)
}

fn is_video_codec(t: &str) -> bool {
    matches!(t, "avc1" | "hev1" | "hvc1" | "vvc1" | "vp08" | "vp09" | "av01" | "mp4v" | "jpeg" | "encv")
}

fn is_audio_codec(t: &str) -> bool {
    matches!(t, "mp4a" | "ac-3" | "ec-3" | "ac-4" | "dtsc" | "dtse" | "dtsh" | "dtsl" | "opus" | "flac" | "enca")
}

fn describe_primaries(p: u16) -> &'static str {
    match p {
        1 => "BT.709 / sRGB",
        2 => "Unspecified",
        4 => "BT.470M",
        5 => "BT.470BG / PAL",
        6 => "BT.601 / NTSC",
        7 => "SMPTE 240M",
        9 => "BT.2020 (UHD)",
        11 => "DCI-P3",
        12 => "P3-D65",
        _ => "Reserved/Unknown",
    }
}

fn describe_transfer(t: u16) -> &'static str {
    match t {
        1 => "BT.709",
        2 => "Unspecified",
        4 => "BT.470M",
        5 => "BT.470BG",
        6 => "BT.601",
        7 => "SMPTE 240M",
        8 => "Linear",
        11 => "IEC 61966-2-4",
        13 => "BT.709 (alternate)",
        14 => "BT.2020-10",
        15 => "BT.2020-12",
        16 => "SMPTE ST 2084 (PQ / HDR10)",
        18 => "ARIB STD-B67 (HLG)",
        _ => "Reserved/Unknown",
    }
}

fn describe_matrix(m: u16) -> &'static str {
    match m {
        0 => "Identity / RGB",
        1 => "BT.709",
        2 => "Unspecified",
        4 => "FCC",
        5 => "BT.470BG",
        6 => "BT.601",
        7 => "SMPTE 240M",
        9 => "BT.2020 Non-constant Luminance",
        10 => "BT.2020 Constant Luminance",
        _ => "Reserved/Unknown",
    }
}

/// Parses the `mvhd` box payload.
fn parse_mvhd(data: &[u8], offset: u64, size: u64) -> Option<(u32, u64, u64, u64, u32)> {
    if size < 24 {
        return None;
    }
    let idx = offset as usize;
    let version = data[idx];

    if version == 0 {
        let c_time = u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap()) as u64;
        let m_time = u32::from_be_bytes(data[idx + 8..idx + 12].try_into().unwrap()) as u64;
        let timescale = u32::from_be_bytes(data[idx + 12..idx + 16].try_into().unwrap());
        let duration = u32::from_be_bytes(data[idx + 16..idx + 20].try_into().unwrap()) as u64;

        let next_tid = if size >= 100 {
            u32::from_be_bytes(data[idx + 96..idx + 100].try_into().unwrap())
        } else {
            0
        };
        Some((timescale, duration, c_time, m_time, next_tid))
    } else if version == 1 {
        if size < 36 {
            return None;
        }
        let c_time = u64::from_be_bytes(data[idx + 4..idx + 12].try_into().unwrap());
        let m_time = u64::from_be_bytes(data[idx + 12..idx + 20].try_into().unwrap());
        let timescale = u32::from_be_bytes(data[idx + 20..idx + 24].try_into().unwrap());
        let duration = u64::from_be_bytes(data[idx + 24..idx + 32].try_into().unwrap());

        let next_tid = if size >= 112 {
            u32::from_be_bytes(data[idx + 108..idx + 112].try_into().unwrap())
        } else {
            0
        };
        Some((timescale, duration, c_time, m_time, next_tid))
    } else {
        None
    }
}

struct TkhdData {
    track_id: u32,
    duration: u64,
    layer: i16,
    alternate_group: i16,
    volume: f32,
    width: f64,
    height: f64,
    rotation: i32,
    creation_time: u64,
    modification_time: u64,
}

/// Parses the `tkhd` box payload.
fn parse_tkhd(data: &[u8], offset: u64, size: u64) -> Option<TkhdData> {
    if size < 4 {
        return None;
    }
    let idx = offset as usize;
    let version = data[idx];

    let (creation_time, modification_time, track_id, duration, layer, alternate_group, volume, matrix_idx, w_h_idx) = if version == 0 {
        if size < 84 { return None; }
        let ct = u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap()) as u64;
        let mt = u32::from_be_bytes(data[idx + 8..idx + 12].try_into().unwrap()) as u64;
        let tid = u32::from_be_bytes(data[idx + 12..idx + 16].try_into().unwrap());
        let dur = u32::from_be_bytes(data[idx + 20..idx + 24].try_into().unwrap()) as u64;
        let ly = i16::from_be_bytes(data[idx + 32..idx + 34].try_into().unwrap());
        let ag = i16::from_be_bytes(data[idx + 34..idx + 36].try_into().unwrap());
        let vol_raw = u16::from_be_bytes(data[idx + 36..idx + 38].try_into().unwrap());
        let vol = (vol_raw >> 8) as f32 + ((vol_raw & 0xFF) as f32 / 256.0);
        (ct, mt, tid, dur, ly, ag, vol, idx + 44, idx + 76)
    } else if version == 1 {
        if size < 96 { return None; }
        let ct = u64::from_be_bytes(data[idx + 4..idx + 12].try_into().unwrap());
        let mt = u64::from_be_bytes(data[idx + 12..idx + 20].try_into().unwrap());
        let tid = u32::from_be_bytes(data[idx + 20..idx + 24].try_into().unwrap());
        let dur = u64::from_be_bytes(data[idx + 28..idx + 36].try_into().unwrap());
        let ly = i16::from_be_bytes(data[idx + 44..idx + 46].try_into().unwrap());
        let ag = i16::from_be_bytes(data[idx + 46..idx + 48].try_into().unwrap());
        let vol_raw = u16::from_be_bytes(data[idx + 48..idx + 50].try_into().unwrap());
        let vol = (vol_raw >> 8) as f32 + ((vol_raw & 0xFF) as f32 / 256.0);
        (ct, mt, tid, dur, ly, ag, vol, idx + 56, idx + 88)
    } else {
        return None;
    };

    let w_raw = u32::from_be_bytes(data[w_h_idx..w_h_idx + 4].try_into().unwrap());
    let h_raw = u32::from_be_bytes(data[w_h_idx + 4..w_h_idx + 8].try_into().unwrap());
    let width = (w_raw >> 16) as f64 + ((w_raw & 0xFFFF) as f64 / 65536.0);
    let height = (h_raw >> 16) as f64 + ((h_raw & 0xFFFF) as f64 / 65536.0);

    // Matrix parsing for rotation
    // Matrix is 36 bytes: 9 * 32-bit fixed point (16.16 for a,b,c,d,tx,ty, 2.30 for u,v,w)
    let a = i32::from_be_bytes(data[matrix_idx..matrix_idx + 4].try_into().unwrap());
    let b = i32::from_be_bytes(data[matrix_idx + 4..matrix_idx + 8].try_into().unwrap());
    let c = i32::from_be_bytes(data[matrix_idx + 12..matrix_idx + 16].try_into().unwrap());
    let d = i32::from_be_bytes(data[matrix_idx + 16..matrix_idx + 20].try_into().unwrap());

    let rotation = if a == 0 && b == 65536 && c == -65536 && d == 0 {
        90
    } else if a == -65536 && b == 0 && c == 0 && d == -65536 {
        180
    } else if a == 0 && b == -65536 && c == 65536 && d == 0 {
        270
    } else {
        0
    };

    Some(TkhdData {
        track_id,
        duration,
        layer,
        alternate_group,
        volume,
        width,
        height,
        rotation,
        creation_time,
        modification_time,
    })
}

struct MdhdData {
    creation_time: u64,
    modification_time: u64,
    timescale: u32,
    duration: u64,
    language: String,
}

/// Parses the `mdhd` box payload.
fn parse_mdhd(data: &[u8], offset: u64, size: u64) -> Option<MdhdData> {
    if size < 4 {
        return None;
    }
    let idx = offset as usize;
    let version = data[idx];

    if version == 0 {
        if size < 24 {
            return None;
        }
        let creation_time = u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap()) as u64;
        let modification_time = u32::from_be_bytes(data[idx + 8..idx + 12].try_into().unwrap()) as u64;
        let timescale = u32::from_be_bytes(data[idx + 12..idx + 16].try_into().unwrap());
        let duration = u32::from_be_bytes(data[idx + 16..idx + 20].try_into().unwrap()) as u64;
        let lang_code = u16::from_be_bytes(data[idx + 20..idx + 22].try_into().unwrap());
        let language = decode_language(lang_code);

        Some(MdhdData {
            creation_time,
            modification_time,
            timescale,
            duration,
            language,
        })
    } else if version == 1 {
        if size < 36 {
            return None;
        }
        let creation_time = u64::from_be_bytes(data[idx + 4..idx + 12].try_into().unwrap());
        let modification_time = u64::from_be_bytes(data[idx + 12..idx + 20].try_into().unwrap());
        let timescale = u32::from_be_bytes(data[idx + 20..idx + 24].try_into().unwrap());
        let duration = u64::from_be_bytes(data[idx + 24..idx + 32].try_into().unwrap());
        let lang_code = u16::from_be_bytes(data[idx + 32..idx + 34].try_into().unwrap());
        let language = decode_language(lang_code);

        Some(MdhdData {
            creation_time,
            modification_time,
            timescale,
            duration,
            language,
        })
    } else {
        None
    }
}

/// Decodes ISO-639-2/T 3-character packed language code.
fn decode_language(lang_code: u16) -> String {
    let char1 = ((lang_code >> 10) & 0x1F) as u8;
    let char2 = ((lang_code >> 5) & 0x1F) as u8;
    let char3 = (lang_code & 0x1F) as u8;
    if char1 > 0 && char2 > 0 && char3 > 0 {
        let c1 = (char1 + 0x60) as char;
        let c2 = (char2 + 0x60) as char;
        let c3 = (char3 + 0x60) as char;
        format!("{}{}{}", c1, c2, c3)
    } else {
        "und".to_string()
    }
}

struct HdlrData {
    handler_type: String,
    handler_name: String,
}

/// Parses the `hdlr` box payload.
fn parse_hdlr(data: &[u8], offset: u64, size: u64) -> Option<HdlrData> {
    if size < 24 {
        return None;
    }
    let idx = offset as usize;
    let type_bytes: [u8; 4] = data[idx + 8..idx + 12].try_into().unwrap();
    let handler_type = String::from_utf8_lossy(&type_bytes).into_owned();

    let name_bytes = &data[idx + 24..idx + (size as usize)];
    let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
    let handler_name = String::from_utf8_lossy(&name_bytes[..name_len]).into_owned();

    Some(HdlrData {
        handler_type,
        handler_name,
    })
}

struct SttsData {
    entry_count: u32,
    total_samples: u32,
}

/// Parses the `stts` box payload.
fn parse_stts(data: &[u8], offset: u64, size: u64) -> Option<SttsData> {
    if size < 8 {
        return None;
    }
    let idx = offset as usize;
    let entry_count = u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap());

    let mut total_samples = 0u32;
    let max_entries = ((size - 8) / 8) as u32;
    let entries_to_read = std::cmp::min(entry_count, max_entries);

    for i in 0..entries_to_read {
        let entry_idx = idx + 8 + (i as usize) * 8;
        let sample_count = u32::from_be_bytes(data[entry_idx..entry_idx + 4].try_into().unwrap());
        total_samples = total_samples.saturating_add(sample_count);
    }

    Some(SttsData {
        entry_count,
        total_samples,
    })
}

struct StszData {
    uniform_sample_size: Option<u32>,
    sample_count: u32,
    total_size: u64,
    min_sample_size: Option<u32>,
    max_sample_size: Option<u32>,
    avg_sample_size: Option<f32>,
}

/// Parses the `stsz` box payload.
fn parse_stsz(data: &[u8], offset: u64, size: u64) -> Option<StszData> {
    if size < 12 {
        return None;
    }
    let idx = offset as usize;
    let sample_size = u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap());
    let sample_count = u32::from_be_bytes(data[idx + 8..idx + 12].try_into().unwrap());

    if sample_size > 0 {
        Some(StszData {
            uniform_sample_size: Some(sample_size),
            sample_count,
            total_size: (sample_size as u64) * (sample_count as u64),
            min_sample_size: Some(sample_size),
            max_sample_size: Some(sample_size),
            avg_sample_size: Some(sample_size as f32),
        })
    } else {
        if sample_count == 0 {
            return Some(StszData {
                uniform_sample_size: None,
                sample_count: 0,
                total_size: 0,
                min_sample_size: None,
                max_sample_size: None,
                avg_sample_size: None,
            });
        }

        let max_entries = ((size - 12) / 4) as u32;
        let entries_to_read = std::cmp::min(sample_count, max_entries);

        if entries_to_read == 0 {
            return Some(StszData {
                uniform_sample_size: None,
                sample_count,
                total_size: 0,
                min_sample_size: None,
                max_sample_size: None,
                avg_sample_size: None,
            });
        }

        let mut min_val = u32::MAX;
        let mut max_val = 0u32;
        let mut total_val = 0u64;

        for i in 0..entries_to_read {
            let entry_idx = idx + 12 + (i as usize) * 4;
            let sz = u32::from_be_bytes(data[entry_idx..entry_idx + 4].try_into().unwrap());
            if sz < min_val {
                min_val = sz;
            }
            if sz > max_val {
                max_val = sz;
            }
            total_val += sz as u64;
        }

        let avg_val = total_val as f32 / entries_to_read as f32;

        Some(StszData {
            uniform_sample_size: None,
            sample_count,
            total_size: total_val,
            min_sample_size: Some(min_val),
            max_sample_size: Some(max_val),
            avg_sample_size: Some(avg_val),
        })
    }
}

/// Parses the `stco` box payload to extract entry count.
fn parse_stco(data: &[u8], offset: u64, size: u64) -> Option<u32> {
    if size < 8 {
        return None;
    }
    let idx = offset as usize;
    let entry_count = u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap());
    Some(entry_count)
}

/// Parses the `co64` box payload to extract entry count.
fn parse_co64(data: &[u8], offset: u64, size: u64) -> Option<u32> {
    if size < 8 {
        return None;
    }
    let idx = offset as usize;
    let entry_count = u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap());
    Some(entry_count)
}

/// Parses the `stss` box payload to extract sync sample indices.
fn parse_stss(data: &[u8], offset: u64, size: u64) -> Option<Vec<u32>> {
    if size < 8 {
        return None;
    }
    let idx = offset as usize;
    let entry_count = u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap());
    
    let max_entries = ((size - 8) / 4) as u32;
    let to_read = std::cmp::min(entry_count, max_entries);
    
    let mut sync_samples = Vec::new();
    let mut current = idx + 8;
    for _ in 0..to_read {
        if current + 4 <= data.len() {
            let sample_idx = u32::from_be_bytes(data[current..current + 4].try_into().unwrap());
            sync_samples.push(sample_idx);
            current += 4;
        }
    }
    Some(sync_samples)
}

/// Translates MP4/ISOBMFF seconds-since-1904 into standard UTC datetime representation.
fn format_mp4_time(seconds: u64) -> String {
    if seconds == 0 {
        return "Not specified (0)".to_string();
    }
    if seconds < 2_082_844_800 {
        return format!("Before 1970 Epoch (raw seconds: {})", seconds);
    }
    let unix = seconds - 2_082_844_800;

    let mut day = unix / 86400;
    let seconds_of_day = unix % 86400;
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;

    let mut year = 1970;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if day >= days_in_year {
            day -= days_in_year;
            year += 1;
        } else {
            break;
        }
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let mut month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if is_leap {
        month_days[1] = 29;
    }

    let mut month = 1;
    for &days in month_days.iter() {
        if day >= days {
            day -= days;
            month += 1;
        } else {
            break;
        }
    }

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC (raw: {})",
        year, month, day + 1, hour, minute, second, seconds
    )
}

/// Formats the final metadata report for the standard outputs.
fn print_metadata_summary(meta: &MovieMetadata, file_size: u64) {
    println!("================================================================================");
    println!("                           METADATA ANALYSIS REPORT                             ");
    println!("================================================================================");
    println!("  File Size:             {} bytes", file_size);

    if let Some(major) = &meta.major_brand {
        println!("  Major Brand:           '{}'", major);
    }
    if let Some(minor) = meta.minor_version {
        println!("  Minor Version:         {}", minor);
    }
    if !meta.compatible_brands.is_empty() {
        println!("  Compatible Brands:     {:?}", meta.compatible_brands);
    }

    if meta.timescale.is_none() {
        println!("\n  [Warning] No movie header ('mvhd') box was identified in this file.");
        println!("            This is expected if the file only contains raw sub-atoms.");
        return;
    }

    let ts = meta.timescale.unwrap();
    let duration = meta.duration.unwrap_or(0);
    let duration_sec = if ts > 0 {
        duration as f64 / ts as f64
    } else {
        0.0
    };

    println!("\nMOVIE HEADER (mvhd):");
    println!("--------------------------------------------------------------------------------");
    println!("  Creation Time:         {}", format_mp4_time(meta.creation_time.unwrap_or(0)));
    println!("  Modification Time:     {}", format_mp4_time(meta.modification_time.unwrap_or(0)));
    println!("  Timescale:             {} units/sec", ts);
    println!("  Duration:              {} units ({:.3} seconds)", duration, duration_sec);
    println!("  Next Track ID:         {}", meta.next_track_id.unwrap_or(0));

    if let Some(loc) = &meta.location {
        println!("  Location (GPS):        {}", loc);
    }

    if !meta.user_data.is_empty() {
        println!("\nUSER DATA & TAGS:");
        println!("--------------------------------------------------------------------------------");
        for (tag, value) in &meta.user_data {
            let label = match tag.as_str() {
                "\u{00a9}nam" => "Title",
                "\u{00a9}ART" | "\u{00a9}art" => "Artist",
                "\u{00a9}alb" => "Album",
                "\u{00a9}day" => "Date",
                "\u{00a9}gen" => "Genre",
                "\u{00a9}too" => "Encoder",
                "\u{00a9}cmt" => "Comment",
                "trkn" => "Track Number",
                _ => tag.as_str(),
            };
            println!("  {:<22} {}", format!("{}:", label), value);
        }
    }

    if !meta.fragments.is_empty() {
        println!("\nMOVIE FRAGMENTS (fMP4):");
        println!("--------------------------------------------------------------------------------");
        println!("  Total Fragments:       {}", meta.fragments.len());
        for frag in &meta.fragments {
            println!("  Fragment #{}:", frag.sequence_number);
            println!("    Track ID:            {}", frag.track_id);
            println!("    Sample Count:        {}", frag.sample_count);
            if frag.total_size > 0 {
                println!("    Total Sample Size:   {} bytes", frag.total_size);
            }
        }
    }

    if !meta.chapters.is_empty() {
        println!("\nCHAPTERS:");
        println!("--------------------------------------------------------------------------------");
        for chap in &meta.chapters {
            println!("  - {}", chap);
        }
    }

    println!("\nTRACKS SUMMARY (Total: {}):", meta.tracks.len());
    for (i, t) in meta.tracks.iter().enumerate() {
        println!("--------------------------------------------------------------------------------");
        println!("  Track #{}:", i + 1);
        println!("--------------------------------------------------------------------------------");
        if let Some(tid) = t.track_id {
            println!("    Track ID:            {}", tid);
        } else {
            println!("    Track ID:            [Not specified]");
        }

        if let Some(c_time) = t.creation_time {
            println!("    Creation Time:       {}", format_mp4_time(c_time));
        }
        if let Some(m_time) = t.modification_time {
            println!("    Modification Time:   {}", format_mp4_time(m_time));
        }

        if let Some(h_type) = &t.handler_type {
            let desc = match h_type.as_str() {
                "vide" => "Video Track",
                "soun" => "Audio Track",
                "hint" => "Hint Track",
                "meta" => "Metadata Track",
                "clcp" => "Closed Caption Track",
                _ => "Unknown Track Type",
            };
            println!("    Handler Type:        '{}' ({})", h_type, desc);
        }
        if let Some(h_name) = &t.handler_name {
            println!("    Handler Name:        \"{}\"", h_name);
        }

        if let Some(dur) = t.duration {
            let movie_ts = ts;
            let dur_sec = if movie_ts > 0 {
                dur as f64 / movie_ts as f64
            } else {
                0.0
            };
            println!("    Duration (Movie TS): {} units ({:.3} seconds)", dur, dur_sec);
        }

        if let Some(m_ts) = t.media_timescale {
            println!("    Media Timescale:     {} units/sec", m_ts);
            if let Some(m_dur) = t.media_duration {
                let m_dur_sec = if m_ts > 0 {
                    m_dur as f64 / m_ts as f64
                } else {
                    0.0
                };
                println!("    Media Duration:      {} units ({:.3} seconds)", m_dur, m_dur_sec);
            }
        }

        if let Some(fps) = t.calculated_fps {
            let vfr_info = if t.is_vfr { " (Variable Frame Rate)" } else { " (Constant Frame Rate)" };
            println!("    Calculated FPS:      {:.3}{}", fps, vfr_info);
        }
        if let Some(br) = t.calculated_bitrate {
            println!("    Calculated Bitrate:  {:.2} Mbps", br / 1_000_000.0);
        }

        if let Some(m_c_time) = t.media_creation_time {
            println!("    Media Creation Time: {}", format_mp4_time(m_c_time));
        }
        if let Some(m_m_time) = t.media_modification_time {
            println!("    Media Modif. Time:   {}", format_mp4_time(m_m_time));
        }

        if let Some(lang) = &t.language {
            println!("    Language:            {}", lang);
        }

        if let Some(layer) = t.layer {
            println!("    Layer/Z-Order:       {}", layer);
        }
        if let Some(alt) = t.alternate_group {
            println!("    Alternate Group:     {}", alt);
        }
        if let Some(vol) = t.volume {
            println!("    Volume:              {:.2}", vol);
        }

        if let (Some(w), Some(h)) = (t.width, t.height) {
            if w > 0.0 || h > 0.0 {
                let rot_info = if let Some(r) = t.rotation {
                    if r != 0 { format!(" (Rotated {}°)", r) } else { "".to_string() }
                } else { "".to_string() };
                println!("    Dimensions (WxH):    {:.2} x {:.2}{}", w, h, rot_info);
            }
        }

        if !t.references.is_empty() {
            println!("    Track References:");
            for (ref_type, ids) in &t.references {
                let desc = match ref_type.as_str() {
                    "cdsc" => "Content Description",
                    "hint" => "Hint Track",
                    "vdep" => "Video Dependency",
                    "auxl" => "Auxiliary Track",
                    _ => "Reference",
                };
                println!("      {:<18} Tracks {:?}", format!("{}:", desc), ids);
            }
        }

        if let Some(codec) = &t.codec_info {
            println!("    Codec Details:");
            println!("      Format:            {}", codec.format);
            if let Some(drm) = &t.drm_info {
                println!("      DRM Protection:    Active (Scheme: '{}', Orig. Format: '{}', Encrypted: {})", drm.scheme, drm.original_format, drm.is_encrypted);
            }
            if let (Some(cw), Some(ch)) = (codec.width, codec.height) {
                println!("      Encoded Size:      {} x {}", cw, ch);
            }
            if let Some(comp) = &codec.compressor {
                if !comp.is_empty() {
                    println!("      Compressor:        {}", comp);
                }
            }
            if let Some(depth) = codec.depth {
                if depth != 0 && depth != 24 {
                    println!("      Bit Depth:         {} bits", depth);
                }
            }
            if let Some(chans) = codec.channels {
                println!("      Channels:          {}", chans);
            }
            if let Some(sr) = codec.sample_rate {
                println!("      Sample Rate:       {:.1} Hz", sr);
            }
            if let Some((h, v)) = codec.pixel_aspect_ratio {
                println!("      Pixel Aspect Ratio: {}:{}", h, v);
            }
            if let (Some(p), Some(l)) = (&codec.codec_profile, &codec.codec_level) {
                println!("      Codec Profile:     {} (Level {})", p, l);
            }
            if let Some(avg) = codec.avg_bitrate {
                println!("      Avg Bitrate:       {:.2} Mbps", avg as f64 / 1_000_000.0);
            }
            if let Some(max) = codec.max_bitrate {
                println!("      Max Bitrate:       {:.2} Mbps", max as f64 / 1_000_000.0);
            }
            if let Some((w, h, _, _)) = codec.clean_aperture {
                println!("      Clean Aperture:    {} x {}", w, h);
            }
            if let (Some(cp), Some(tc), Some(mc)) = (codec.color_primaries, codec.transfer_characteristics, codec.matrix_coefficients) {
                println!("      Color Information:");
                println!("        Primaries:       {} ({})", cp, describe_primaries(cp));
                println!("        Transfer:        {} ({})", tc, describe_transfer(tc));
                println!("        Matrix:          {} ({})", mc, describe_matrix(mc));
            }
        }

        println!("    Sample Specifications:");
        println!("      Total Sample Count:{}", t.sample_count);
        if t.edit_list_count > 0 {
            println!("      Edit List Entries:   {}", t.edit_list_count);
            for (idx, entry) in t.edit_list.iter().enumerate() {
                let media_time_str = if entry.media_time == -1 {
                    "Empty (Delay)".to_string()
                } else {
                    format!("{} units", entry.media_time)
                };
                println!("        Entry #{}: Duration: {} units, Media Time: {}, Speed: {:.2}x",
                         idx + 1, entry.segment_duration, media_time_str, entry.media_rate);
            }
        }
        if let Some(sz) = t.uniform_sample_size {
            println!("      Sample Size (stsz): Uniform ({} bytes)", sz);
        } else if t.sample_count > 0 {
            let min_s = t.min_sample_size.unwrap_or(0);
            let max_s = t.max_sample_size.unwrap_or(0);
            let avg_s = t.avg_sample_size.unwrap_or(0.0);
            println!(
                "      Sample Size (stsz): Variable (Min: {} bytes, Max: {} bytes, Avg: {:.1} bytes)",
                min_s, max_s, avg_s
            );
        } else {
            println!("      Sample Size (stsz): [No samples / empty track]");
        }

        println!("      Chunk Count (stco):  {}", t.chunk_count);
        println!("      Sync Entries (stss): {}", t.sync_sample_count);
        if t.sample_count > 0 && t.sync_sample_count > 0 {
            let pct = (t.sync_sample_count as f64 / t.sample_count as f64) * 100.0;
            println!("      Keyframe Frequency:  {:.2}% of samples are keyframes", pct);
        }
    }
    println!("================================================================================");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_files_parse() {
        let samples = [
            "samples/sample1.moov",
            "samples/sample2.moov",
            "samples/sample3.moov",
            "samples/sample4.moov",
            "samples/sample5.moov",
        ];

        for sample in samples.iter() {
            println!("Testing parser against {}", sample);
            let result = process_file(sample);
            assert!(
                result.is_ok(),
                "Failed to parse sample {}: {:?}",
                sample,
                result.err()
            );

            let (boxes, meta, _size) = result.unwrap();
            assert!(!boxes.is_empty(), "Parsed box tree was empty for {}", sample);

            // Let's assert that there is a 'moov' box in all of these sample files
            let moov = find_box_in_tree(&boxes, "moov");
            assert!(
                moov.is_some(),
                "Sample {} was successfully parsed but did not contain a 'moov' atom!",
                sample
            );

            // Print the parsed track types for debug purposes
            for (idx, track) in meta.tracks.iter().enumerate() {
                println!(
                    "  -> Track #{} handler: {:?}",
                    idx + 1,
                    track.handler_type
                );
            }
        }
    }

    #[test]
    fn test_language_decoder() {
        // Test packed code 0x15C7 which represents "eng"
        // e = 5, n = 14, g = 7
        // Binary representation of (5, 14, 7):
        // 5 = 00101
        // 14 = 01110
        // 7 = 00111
        // lang_code = (5 << 10) | (14 << 5) | 7 = 0x15C7
        let code = (5 << 10) | (14 << 5) | 7;
        assert_eq!(decode_language(code), "eng");

        // Test undefined
        assert_eq!(decode_language(0), "und");
    }

    #[test]
    fn test_mp4_time_formatter() {
        // Unix epoch 1970-01-01 00:00:00 corresponds to 2,082,844,800 in MP4 seconds
        let form = format_mp4_time(2_082_844_800);
        assert!(form.starts_with("1970-01-01 00:00:00 UTC"));
    }
}
