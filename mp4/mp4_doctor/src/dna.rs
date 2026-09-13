// src/dna.rs

//! Moduł `dna` służy do niskopoziomowego skanowania plików wideo na poziomie binarnym.
//! 
//! Wersja "Enterprise" - zoptymalizowana pod kątem maszynowego, masowego 
//! skanowania z obsługą potokową. Moduł jest całkowicie "cichy" (nie używa funkcji 
//! logujących na ekran), dzięki czemu nie zakłóca interfejsu (HUD) użytkownika.
//!
//! # Cyfrowe DNA
//! Cyfrowe DNA to unikalna sygnatura sprzętowa nagrania. W najnowszej wersji
//! moduł skanuje plik w poszukiwaniu dwóch kluczowych parametrów:
//! 1. **Wideo (H.264 / AVC):** Szuka ramek SPS (Sequence Parameter Set), aby 
//!    wyciągnąć profil matrycy kamery (Profile, Compatibility, Level).
//! 2. **Audio (AAC):** Szuka nagłówków ADTS, aby wyciągnąć informacje o 
//!    częstotliwości próbkowania i profilu dźwiękowym.
//!
//! Wynikiem jest precyzyjna sygnatura, np.: `DNA_H264_640028_AAC_0103`.

use std::fs::File;
use std::io::Read;
use memchr::memmem;
use crate::ai::FeatureVector;

/// Analizuje surowe bajty pliku wideo w poszukiwaniu konfiguracji sprzętowej (DNA).
///
/// Funkcja ze względów wydajnościowych nie wczytuje całego pliku do pamięci.
/// Odczytuje maksymalnie pierwsze 5 MB (zazwyczaj konfiguracja wideo i audio 
/// znajduje się na samym początku nagrania).
/// 
/// # Zwraca
/// * `Some(String)` - Formatowana sygnatura DNA (np. `DNA_H264_42E01E_AAC_0104`).
/// * `None` - Jeśli plik nie istnieje lub jest całkowicie pusty.
pub fn extract_dna(file_path: &str) -> Option<(String, FeatureVector)> {
    // Próba otwarcia pliku. Używamy wariantu cichego, by w razie błędu 
    // zignorować plik i nie psuć działania pętli wielowątkowej.
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    // Alokujemy bufor wielkości 5 MB. 
    // Jest to optymalny rozmiar, aby znaleźć parametry strumienia, 
    // nie zapychając przy tym pamięci RAM przy np. 100 wątkach skanujących.
    let mut buffer = vec![0u8; 5 * 1024 * 1024];
    let bytes_read = file.read(&mut buffer).unwrap_or(0);
    
    // Obcinamy bufor do faktycznie wczytanego rozmiaru 
    // (w przypadku plików mniejszych niż 5 MB).
    buffer.truncate(bytes_read);

    if bytes_read == 0 {
        return None;
    }

    let mut h264_sig = String::new();
    let mut aac_sig = String::new();

    // =========================================================
    // KROK 1: EKSTRAKCJA DNA WIDEO (H.264 SPS)
    // =========================================================
    // Szukamy znacznika startowego (Start Code Prefix) używanego w NAL units: 0x00000001
    let nal_start_code = b"\x00\x00\x00\x01";
    let finder = memmem::Finder::new(nal_start_code);

    // Iterujemy po wszystkich wystąpieniach prefiksu NAL
    for position in finder.find_iter(&buffer) {
        // Zabezpieczenie przed wyjściem poza bufor (potrzebujemy 4 bajtów prefiksu + 4 bajty danych)
        if position + 7 < buffer.len() {
            // Pierwszy bajt po prefiksie zawiera typ ramki NAL.
            // Maska 0x1F odrzuca bit zabroniony (forbidden_zero_bit) i bity referencyjne, 
            // zostawiając czysty typ jednostki NAL.
            let nal_type = buffer[position + 4] & 0x1F;

            // NAL typ 7 to SPS (Sequence Parameter Set).
            // To tutaj kamera zapisuje informacje o rozdzielczości, FPS i profilu.
            if nal_type == 7 && h264_sig.is_empty() {
                let profile_idc = buffer[position + 5];
                let profile_compat = buffer[position + 6];
                let level_idc = buffer[position + 7];

                // Generujemy i przypisujemy pierwszą część DNA.
                // Używamy zapisu heksadecymalnego (np. 64 00 28 -> High Profile, Level 4.0).
                h264_sig = format!("H264_{:02X}{:02X}{:02X}", profile_idc, profile_compat, level_idc);
            }
        }
        
        // Optymalizacja: Jeśli mamy już H.264 DNA, możemy przerwać to szukanie.
        // Będziemy jednak iterować dalej do szukania AAC (zwykle znajdują się tuż obok siebie).
        if !h264_sig.is_empty() {
            break;
        }
    }

    // =========================================================
    // KROK 2: EKSTRAKCJA DNA AUDIO (AAC ADTS)
    // =========================================================
    // Szukamy nagłówków ADTS. Znacznik synchronizacji to 12 jedynek pod rząd.
    // Oznacza to bajt 0xFF (11111111) oraz pierwszą połowę drugiego bajtu jako 0xF0 (1111xxxx).
    for i in 0..(buffer.len().saturating_sub(2)) {
        if buffer[i] == 0xFF && (buffer[i+1] & 0xF0) == 0xF0 {
            // Znaleźliśmy nagłówek ADTS. Parametry sprzętowe znajdują się w trzecim bajcie.
            
            // Profil dźwiękowy jest na dwóch pierwszych bitach trzeciego bajtu (maska 0xC0).
            // Przesuwamy w prawo o 6, żeby otrzymać czystą wartość.
            let audio_profile = (buffer[i+2] & 0xC0) >> 6;
            
            // Indeks częstotliwości próbkowania zajmuje 4 kolejne bity (maska 0x3C).
            // Przesuwamy w prawo o 2.
            let freq_index = (buffer[i+2] & 0x3C) >> 2;
            
            // Zapisujemy sygnaturę dźwięku, np. AAC_0103
            aac_sig = format!("AAC_{:02X}{:02X}", audio_profile, freq_index);
            break;
        }
    }

    // --- ML: OBLICZANIE CECH (FEATURES) ---
    let file_size_mb = bytes_read as f64 / (1024.0 * 1024.0);
    
    // Obliczanie Entropii Shannona z pierwszych 100KB (lub mniej) do szybkiej analizy
    let sample_size = std::cmp::min(buffer.len(), 100 * 1024);
    let mut counts = [0usize; 256];
    for &b in &buffer[..sample_size] {
        counts[b as usize] += 1;
    }
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / sample_size as f64;
            entropy -= p * p.log2();
        }
    }
    
    // Normalizacja profilu (0-255 -> 0.0-1.0)
    let mut h264_profile_feat = 0.0;
    if !h264_sig.is_empty() {
        // H264_640028 -> 64 to 100 dziesiętnie
        let hex_profile = &h264_sig[5..7];
        if let Ok(p) = u8::from_str_radix(hex_profile, 16) {
            h264_profile_feat = p as f64 / 255.0;
        }
    }

    let mut aac_freq_feat = 0.0;
    if !aac_sig.is_empty() {
        let hex_freq = &aac_sig[6..8];
        if let Ok(f) = u8::from_str_radix(hex_freq, 16) {
            aac_freq_feat = f as f64 / 12.0; // max indeks to ok 12
        }
    }

    // Heurystyka ilości wideo vs audio w buforze
    let video_count = memmem::find_iter(&buffer, b"\x00\x00\x00\x01").count() as f64;
    let audio_count = buffer.windows(2).filter(|w| w[0] == 0xFF && (w[1] & 0xF0) == 0xF0).count() as f64;
    let video_audio_ratio = if audio_count > 0.0 { video_count / audio_count } else { video_count };

    let features = FeatureVector {
        file_size_mb,
        entropy,
        h264_profile: h264_profile_feat,
        aac_freq: aac_freq_feat,
        video_audio_ratio: video_audio_ratio.min(100.0) / 100.0, // Znormalizowane do 0.0 - 1.0
    };

    // =========================================================
    // KROK 3: BUDOWA OSTATECZNEGO CYFROWEGO DNA
    // =========================================================
    
    let sig = if h264_sig.is_empty() {
        format!("DNA_RAW_SIZE_{}", bytes_read)
    } else if !aac_sig.is_empty() {
        format!("DNA_{}_{}", h264_sig, aac_sig)
    } else {
        format!("DNA_{}_NOAUDIO", h264_sig)
    };

    Some((sig, features))
}

/// Tłumaczy maszynowe DNA sprzętowe na czytelny dla człowieka raport.
pub fn get_human_readable_diagnosis(sig: &str, features: &FeatureVector) -> String {
    let mut parts = Vec::new();
    
    if sig.contains("H264_") {
        if let Some(start) = sig.find("H264_") {
            let hex_str = &sig[start+5..start+11];
            if hex_str.len() == 6 {
                let profile = &hex_str[0..2];
                let level_hex = &hex_str[4..6];
                
                let prof_name = match profile {
                    "42" => "Baseline Profile",
                    "4D" => "Main Profile",
                    "64" => "High Profile",
                    "F4" => "High 10 Profile",
                    _ => "Nieznany Profil",
                };
                
                let level = u8::from_str_radix(level_hex, 16).unwrap_or(0);
                let level_str = format!("{}.{}", level / 10, level % 10);
                
                parts.push(format!("Wideo: {} @ Level {}", prof_name, level_str));
            }
        }
    }
    
    if sig.contains("AAC_") {
        if let Some(start) = sig.find("AAC_") {
            let hex_str = &sig[start+4..start+8];
            if hex_str.len() == 4 {
                let freq_idx = u8::from_str_radix(&hex_str[2..4], 16).unwrap_or(255);
                let freq = match freq_idx {
                    3 => "48 kHz",
                    4 => "44.1 kHz",
                    5 => "32 kHz",
                    6 => "24 kHz",
                    8 => "16 kHz",
                    11 => "8 kHz",
                    _ => "Niestandardowe",
                };
                parts.push(format!("Audio: AAC ({})", freq));
            }
        }
    } else {
        parts.push("Audio: Brak (Mute)".to_string());
    }

    let entropy_percent = (features.entropy / 8.0) * 100.0; // max entropy per byte is 8.0
    parts.push(format!("Gęstość (Kompresja): {:.1}%", entropy_percent));

    parts.join(" | ")
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use super::*;

    #[test]
    fn test_extract_dna_valid_video() {
        // Nasz wygenerowany film testowy (h264, aac)
        let path = "tests/assets/test_video_with_dna.mp4";
        // Kopiujemy dummy wideo
        let _ = std::fs::copy("tests/assets/test_video.mp4", path);
        // Doklejamy na siłę sygnatury H264 SPS i AAC ADTS żeby zasymulować "dziki" plik z kamery
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        // NAL SPS: 00 00 00 01 67 42 E0 1E
        // AAC ADTS: FF F1 4C 80
        file.write_all(b"\x00\x00\x00\x01\x67\x42\xE0\x1E").unwrap();
        file.write_all(b"\xFF\xF1\x4C\x80").unwrap();
        
        let result = extract_dna(path);
        let _ = std::fs::remove_file(path);
        assert!(result.is_some(), "System powinien znaleźć DNA w wygenerowanym pliku MP4!");
        
        let (dna, feat) = result.unwrap();
        println!("WYKRYTE DNA: {}", dna);
        // Sprawdzamy czy poprawnie znalazł sygnatury kodeków H264 i AAC
        assert!(dna.contains("DNA_H264_"), "DNA powinno zaczynać się od identyfikatora H.264");
        assert!(dna.contains("_AAC_"), "DNA powinno zawierać profil AAC");
        
        // Funkcje ekstrakcji cech powinny zdekodować poprawne właściwości
        assert!(feat.h264_profile > 0.0);
        assert!(feat.aac_freq > 0.0);
    }
    
    #[test]
    fn test_extract_dna_invalid_file() {
        let path = "non_existent_file.mp4";
        let result = extract_dna(path);
        assert!(result.is_none());
    }
}
