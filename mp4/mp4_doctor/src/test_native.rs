// src/test_native.rs

//! Skrypt diagnostyczny do izolowanego testowania silnika Native.
//! 
//! Wyciąga atom `moov` ze zdrowego pliku, po czym wzywa silnik Native 
//! do zbudowania go od zera, aby zweryfikować poprawność logiki drzewa MP4.

use std::fs::{self, File};
use std::io::{self, Write, Seek, SeekFrom};
use byteorder::{BigEndian, WriteBytesExt};

use crate::engine_native;
use crate::validator;

/// Zmienia plik na strumień Annex B (wideo) i ADTS (audio), symulując zrzut z uszkodzonej kamery.
fn extract_and_destroy_moov(input: &str, output: &str) -> io::Result<()> {
    use std::process::Command;
    
    // Wideo -> Annex B
    let _ = Command::new("ffmpeg")
        .arg("-y").arg("-v").arg("error")
        .arg("-i").arg(input)
        .arg("-c:v").arg("copy").arg("-bsf:v").arg("h264_mp4toannexb")
        .arg("-an").arg("temp_vid.h264")
        .output()?;
        
    // Audio -> ADTS AAC
    let _ = Command::new("ffmpeg")
        .arg("-y").arg("-v").arg("error")
        .arg("-i").arg(input)
        .arg("-c:a").arg("copy")
        .arg("-vn").arg("temp_aud.aac")
        .output()?;
        
    let mut out_file = File::create(output)?;
    if let Ok(mut vid) = File::open("temp_vid.h264") {
        io::copy(&mut vid, &mut out_file)?;
    }
    if let Ok(mut aud) = File::open("temp_aud.aac") {
        io::copy(&mut aud, &mut out_file)?;
    }
    
    let _ = fs::remove_file("temp_vid.h264");
    let _ = fs::remove_file("temp_aud.aac");
    
    Ok(())
}

/// Główna funkcja testowa
pub fn run_diagnostic(healthy_file: &str) {
    println!("\n==================================================");
    println!("🧪 [DEBUG] IZOLOWANY TEST SILNIKA NATIVE");
    println!("==================================================");
    
    let broken_file = "debug_broken.mp4";
    let fixed_file = "debug_fixed.mp4";

    // Czyszczenie pozostałości po poprzednich testach
    let _ = fs::remove_file(broken_file);
    let _ = fs::remove_file(fixed_file);

    println!("1️⃣  Preparowanie pliku testowego...");
    if let Err(e) = extract_and_destroy_moov(healthy_file, broken_file) {
        println!("❌ Błąd preparowania pliku: {}", e);
        return;
    }
    println!("✅ Utworzono uszkodzony plik: {}\n", broken_file);

    println!("2️⃣  Uruchamianie silnika Native...");
    // Wywołujemy silnik Native bez kanału UI (przekazujemy None)
    let repair_result = engine_native::repair(broken_file, fixed_file, None);

    match repair_result {
        Ok(_) => {
            println!("✅ Silnik Native zakończył pracę bez wywołania błędów (Crashy).\n");
            
            println!("3️⃣  Weryfikacja wygenerowanego drzewa przez Sędziego...");
            let is_healthy = validator::is_healthy_video(fixed_file);
            
            if is_healthy {
                println!("\n🏆 [WYNIK]: SUKCES! Natywne drzewo MP4 zadziałało!");
                println!("Możesz obejrzeć plik wpisując w terminalu:");
                println!("ffplay {}", fixed_file);
            } else {
                println!("\n❌ [WYNIK]: PORAŻKA! Sędzia odrzucił plik.");
                println!("Logika budowy drzewa moov ma wady. Sprawdź logi wyżej.");
            }
        },
        Err(e) => {
            println!("\n❌ [WYNIK]: BŁĄD KRYTYCZNY. Silnik Native rzucił błędem: {}", e);
        }
    }
    println!("==================================================\n");
}
