// src/mp4/engine_recontainer.rs
//
// PORT z projektu `mp4_doctor` (moduł `engine_recontainer`).
// Zmiany wobec oryginału: `tracing::debug!` -> `tracing`.

//! Moduł `engine_recontainer` realizuje strategię bezpiecznego przepakowywania.
//!
//! Zmusza silnik FFmpeg do przetworzenia wideo z aktywnymi flagami korygującymi.
//! Wersja Enterprise: zintegrowano zaawansowaną korektę synchronizacji A/V (Audio Drift).

use std::io;
use std::process::{Command, Stdio};

/// Główny egzekutor metody Recontainer z obsługą asynchronizacji Audio-Video.
pub fn repair(broken_file: &str, output_file: &str) -> io::Result<()> {
    tracing::debug!("🔄 [RECONTAINER] Uruchamiam zaawansowaną rekonstrukcję (Korekta A/V)...");

    // -nostdin             : Blokuje FFmpeg przed czekaniem na wpisy z klawiatury (zapobiega zawieszeniom)
    // -err_detect ignore_err : ignoruje uszkodzone fragmenty NAL
    // -fflags +genpts+ignidx : generuje nowe, prawidłowe znaczniki czasu
    // -c:v copy              : wideo przerzucane bezstratnie
    // -c:a aac               : dźwięk jest przetwarzany
    // -af aresample=async=1  : filtr naciągający dźwięk
    let status = Command::new("ffmpeg")
        .arg("-nostdin")
        .arg("-y")
        .arg("-err_detect").arg("ignore_err")
        .arg("-fflags").arg("+genpts+ignidx")
        .arg("-i").arg(broken_file)
        .arg("-c:v").arg("copy")
        .arg("-c:a").arg("aac")
        .arg("-af").arg("aresample=async=1")
        .arg("-movflags").arg("+faststart")
        .arg(output_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    if status.success() {
        tracing::debug!("✅ [RECONTAINER] Kontener zrekonstruowany i zsynchronizowany pomyślnie.");
        Ok(())
    } else {
        tracing::debug!("❌ [RECONTAINER] FFmpeg zgłosił błąd krytyczny podczas przepakowywania.");
        Err(io::Error::other(
            "FFmpeg zgłosił błąd krytyczny podczas przepakowywania.",
        ))
    }
}
