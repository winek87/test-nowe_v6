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
        
        let mut actual_size = size_32 as u64;
        if size_32 == 1 {
            actual_size = match file.read_u64::<BigEndian>() {
                Ok(s) => s,
                Err(_) => break,
            };
        } else if size_32 < 8 {
            break;
        }

        if &box_type == target_box {
            return Ok(Some(BoxInfo { offset: position, size: actual_size }));
        }

        position += actual_size;
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
    
    // Zmienna na wyliczoną deltę
    let mut shift_delta: Option<i64> = None;

    // Funkcja pomocnicza: znajdowanie pierwszego adresu i wyliczanie delty
    let mut i = 0;
    while i < moov_data.len() - 8 {
        if &moov_data[i..i+4] == b"stco" {
            let entry_count = u32::from_be_bytes(moov_data[i+8..i+12].try_into().unwrap());
            if entry_count > 0 && i + 12 + 4 <= moov_data.len() {
                let first_offset = u32::from_be_bytes(moov_data[i+12..i+16].try_into().unwrap()) as i64;
                if shift_delta.is_none() {
                    shift_delta = Some(new_mdat_payload_offset - first_offset);
                    tracing::debug!("🎯 [CLONE-STCO] Złapano Anchor (stco)! Delta przesunięcia klatek: {} bajtów.", shift_delta.unwrap());
                }
                
                let delta = shift_delta.unwrap();
                for j in 0..entry_count as usize {
                    let off_idx = i + 12 + (j * 4);
                    if off_idx + 4 <= moov_data.len() {
                        let old_val = u32::from_be_bytes(moov_data[off_idx..off_idx+4].try_into().unwrap()) as i64;
                        let new_val = (old_val + delta) as u32;
                        moov_data[off_idx..off_idx+4].copy_from_slice(&new_val.to_be_bytes());
                    }
                }
            }
        } else if &moov_data[i..i+4] == b"co64" {
            let entry_count = u32::from_be_bytes(moov_data[i+8..i+12].try_into().unwrap());
            if entry_count > 0 && i + 12 + 8 <= moov_data.len() {
                let first_offset = u64::from_be_bytes(moov_data[i+12..i+20].try_into().unwrap()) as i64;
                if shift_delta.is_none() {
                    shift_delta = Some(new_mdat_payload_offset - first_offset);
                    tracing::debug!("🎯 [CLONE-STCO] Złapano Anchor (co64)! Delta przesunięcia klatek: {} bajtów.", shift_delta.unwrap());
                }
                
                let delta = shift_delta.unwrap();
                for j in 0..entry_count as usize {
                    let off_idx = i + 12 + (j * 8);
                    if off_idx + 8 <= moov_data.len() {
                        let old_val = u64::from_be_bytes(moov_data[off_idx..off_idx+8].try_into().unwrap()) as i64;
                        let new_val = (old_val + delta) as u64;
                        moov_data[off_idx..off_idx+8].copy_from_slice(&new_val.to_be_bytes());
                    }
                }
            }
        }
        i += 1;
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
