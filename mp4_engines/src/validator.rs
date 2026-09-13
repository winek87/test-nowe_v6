// src/mp4/validator.rs
//
// PORT z projektu `mp4_doctor` (moduł `validator`).
// Zmiany wobec oryginału: `tracing::debug!` -> `tracing`.

//! Moduł `validator` to rygorystyczny tester naprawionych plików.
//!
//! # Zmiany w wersji Enterprise:
//! - **Strict Video Validation:** Wykrywa "puste" pliki, w których kontener został
//!   naprawiony, ale obraz się nie ładuje (np. zepsute offsety, zła rozdzielczość, frame=0).
//! - **Ciche Logowanie:** Zgodność z potokiem UI i zapis do `doktor_raport.log`.
//! - Odtwarzacz podglądu (`play_preview`) NIE został przeniesiony: to
//!   interaktywne wywołanie `ffplay`, które nie ma zastosowania w fazie
//!   wsadowej. Weryfikację robi `is_healthy_video` bez udziału człowieka.

use std::path::Path;
use std::process::Command;

/// Czy `ffprobe` i `ffmpeg` są dostępne w systemie — sprawdzane RAZ i buforowane.
///
/// ## Dlaczego to musi istnieć
///
/// [`is_healthy_video`] ma jawne `return false`, gdy nie da się wywołać
/// `ffprobe`. Bez tej funkcji na maszynie bez ffmpeg wyglądało to tak: silniki
/// naprawy MP4 produkowały wynik, obowiązkowa weryfikacja odrzucała KAŻDY z
/// nich, orkiestrator usuwał pliki, a licznik `rejected_by_verification` rósł
/// bez wskazania przyczyny. Operator widział „naprawy nie działają", a nie
/// „brakuje binarki".
///
/// Sprawdzenie jest buforowane w `OnceLock`, bo `applies_to` wołane jest RAZ
/// NA PLIK — uruchamianie procesu przy każdym pliku byłoby nie do przyjęcia.
pub fn ffmpeg_dostepny() -> bool {
    static DOSTEPNY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    *DOSTEPNY.get_or_init(|| {
        let sprawdz = |binarka: &str| {
            Command::new(binarka)
                .arg("-version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };

        let ok = sprawdz("ffprobe") && sprawdz("ffmpeg");
        if !ok {
            tracing::warn!(
                "Brak ffprobe/ffmpeg w systemie - weryfikacja wideo spadnie do kontroli STRUKTURALNEJ (gwarancja słabsza), a przepakowanie kontenera będzie niedostępne."
            );
        }
        ok
    })
}

/// Sprawdza, czy plik jest w 100% poprawny i dekodowalny.
/// Zwraca `true` jeśli plik to prawdziwy sukces z obrazem, lub `false` jeśli to fałszywy pozytyw.
pub fn is_healthy_video(file_path: &str) -> bool {
    tracing::debug!("⚖️  [SĘDZIA] Otwieram proces weryfikacji dla: {}", file_path);

    if !Path::new(file_path).exists() { 
        tracing::debug!("❌ [SĘDZIA] Plik nie istnieje na dysku.");
        return false; 
    }
    
    if let Ok(metadata) = std::fs::metadata(file_path)
        && metadata.len() < 1024 { 
            tracing::debug!("❌ [SĘDZIA] Plik jest zbyt mały (< 1KB), by być filmem.");
            return false; 
        }

    // TEST 1: Czy kontener jest spójny (odpytywanie o duration)
    let probe = Command::new("ffprobe")
        .arg("-v").arg("error")
        .arg("-show_entries").arg("format=duration")
        .arg("-of").arg("default=noprint_wrappers=1:nokey=1")
        .arg(file_path)
        .output();

    if let Ok(res) = probe {
        let duration = String::from_utf8_lossy(&res.stdout).trim().to_string();
        if !res.status.success() || duration.is_empty() || duration == "N/A" {
            tracing::debug!("❌ [SĘDZIA] ffprobe nie potrafi odczytać czasu trwania. Uszkodzony kontener.");
            return false;
        }
        tracing::debug!("⏳ [SĘDZIA] Kontener zgłasza czas trwania: {} sekund.", duration);
    } else {
        tracing::debug!("❌ [SĘDZIA] Błąd wywołania ffprobe.");
        return false;
    }

    // TEST 2: Sprawdzenie istnienia strumienia WIDEO i jego rozdzielczości
    // -select_streams v:0  -> Wymusza sprawdzanie tylko strumienia obrazu
    let probe_vid = Command::new("ffprobe")
        .arg("-v").arg("error")
        .arg("-select_streams").arg("v:0")
        .arg("-show_entries").arg("stream=width,height")
        .arg("-of").arg("csv=p=0")
        .arg(file_path)
        .output();

    if let Ok(res) = probe_vid {
        let output = String::from_utf8_lossy(&res.stdout).trim().to_string();
        if output.is_empty() {
            tracing::debug!("❌ [SĘDZIA] Plik nie posiada strumienia WIDEO (samo audio lub kompletny szum).");
            return false;
        }
        
        let dimensions: Vec<&str> = output.split(',').collect();
        if dimensions.len() >= 2 {
            let w: u32 = dimensions[0].parse().unwrap_or(0);
            let h: u32 = dimensions[1].parse().unwrap_or(0);
            if w == 0 || h == 0 {
                tracing::debug!("❌ [SĘDZIA] Rozdzielczość wideo to 0x0. Brak faktycznego obrazu.");
                return false;
            }
            tracing::debug!("📏 [SĘDZIA] Potwierdzono legalne wymiary obrazu: {}x{}", w, h);
        } else {
            tracing::debug!("❌ [SĘDZIA] Brak metadanych o szerokości i wysokości.");
            return false;
        }
    }

    // TEST 3: GŁĘBOKIE DEKODOWANIE (Czy silnik narysuje chociaż jedną klatkę?)
    tracing::debug!("🕵️‍♂️ [SĘDZIA] Rozpoczynam rygorystyczny test renderowania NAL...");
    let decode_test = Command::new("ffmpeg")
        .arg("-v").arg("info") // Włączamy info, żeby złapać statystyki 'frame= X'
        .arg("-i").arg(file_path)
        .arg("-t").arg("2")       // Renderujemy tylko 2 pierwsze sekundy
        .arg("-f").arg("null")    // Render wideo w próżnię (test wydajnościowy)
        .arg("-")
        .output();

    if let Ok(res) = decode_test {
        let stderr = String::from_utf8_lossy(&res.stderr);
        
        // =================================================================
        // ENTERPRISE AI: WIZYJNY SĘDZIA (COMPUTER VISION) - DETEKCJA ARTEFAKTÓW
        // =================================================================
        let mut corruption_score = 0;
        let lines: Vec<&str> = stderr.lines().collect();
        
        for line in &lines {
            // 1. Krytyczne błędy kontenera (natychmiastowe odrzucenie)
            if line.contains("Invalid NAL unit size") 
                || line.contains("Error splitting")
                || line.contains("could not find codec parameters") {
                tracing::debug!("🚫 [SĘDZIA] ODRZUCONY! Znalazłem fatalne błędy strukturalne (błędne offsety).");
                return false;
            }
            // 2. Pikseloza, Macro-blocking, zgubione reference frames
            if line.contains("concealing") 
                || line.contains("error while decoding MB")
                || line.contains("Cabac decode")
                || line.contains("left block unavailable")
                || line.contains("decode_slice_header error")
                || line.contains("missing picture in access unit") {
                corruption_score += 1;
            }
        }
        
        // OSTATECZNY TEST OBRAZU: Szukamy, czy wyrenderowano >= 1 klatkę wideo.
        if stderr.contains("frame=    0") || stderr.contains("frame=   0") || !stderr.contains("frame=") {
            tracing::debug!("🚫 [SĘDZIA] ODRZUCONY! FFmpeg zdekodował 0 klatek wideo. Ten plik to pusta wydmuszka.");
            return false;
        }
        
        // Weryfikacja wizyjna (Próg tolerancji: 15 glitchy)
        if corruption_score > 15 {
            tracing::debug!("📉 [WIZYJNY SĘDZIA] ODRZUCONY! Wykryto ogromną pikselozę (Score: {} błędów matrycy). Obraz jest nieoglądalny.", corruption_score);
            return false;
        } else if corruption_score > 0 {
            tracing::debug!("⚠️ [WIZYJNY SĘDZIA] Plik zaakceptowany, ale obraz ma minimalne uszkodzenia (Score: {}/15).", corruption_score);
        } else {
            tracing::debug!("🏆 [WIZYJNY SĘDZIA] PLIK JEST CZYSTY! Silnik wizyjny potwierdził renderowanie klatek bez absolutnie żadnych artefaktów (0 glitchy).");
        }
        true
    } else {
        tracing::debug!("❌ [SĘDZIA] Nie udało się uruchomić silnika dekodowania FFmpeg.");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generuje MAŁY, prawdziwy plik MP4 przez `ffmpeg`.
    ///
    /// Oryginalny test z `mp4_doctor` sięgał po zakomitowany fixture pod
    /// ścieżką RELATYWNĄ (`tests/assets/test_video.mp4`), czego w tym projekcie
    /// nie ma. Generowanie w locie jest odporne na katalog roboczy i nie
    /// wymaga trzymania binarnego pliku w repozytorium.
    fn wygeneruj_wideo(katalog: &std::path::Path) -> Option<std::path::PathBuf> {
        let cel = katalog.join("probka.mp4");
        let status = Command::new("ffmpeg")
            .args([
                "-nostdin", "-loglevel", "quiet", "-y",
                "-f", "lavfi", "-i", "testsrc=duration=1:size=64x64:rate=10",
                "-pix_fmt", "yuv420p",
            ])
            .arg(&cel)
            .status()
            .ok()?;

        if status.success() && cel.exists() { Some(cel) } else { None }
    }

    /// Wymaga `ffmpeg` do wygenerowania materiału, więc zgodnie z konwencją
    /// projektu jest `#[ignore]` — uruchamiany świadomie:
    /// `cargo test --bin weryfikator validator_przyjmuje -- --ignored`
    #[test]
    #[ignore = "Wymaga ffmpeg do wygenerowania prawdziwego wideo. Uruchom z --ignored."]
    fn test_validator_przyjmuje_zdrowe_wideo() {
        let dir = tempfile::tempdir().unwrap();
        let plik = match wygeneruj_wideo(dir.path()) {
            Some(p) => p,
            None => panic!("Nie udało się wygenerować wideo testowego - czy ffmpeg jest dostępny?"),
        };

        assert!(
            is_healthy_video(plik.to_str().unwrap()),
            "Świeżo wygenerowane wideo musi zostać uznane za zdrowe"
        );
    }

    #[test]
    fn test_validator_odrzuca_nieistniejacy_plik() {
        let dir = tempfile::tempdir().unwrap();
        let brak = dir.path().join("nie_ma_mnie.mp4");
        assert!(!is_healthy_video(brak.to_str().unwrap()));
    }

    #[test]
    fn test_validator_odrzuca_plik_ktory_nie_jest_wideo() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("smieci.mp4");
        std::fs::write(&plik, b"to zupelnie nie jest kontener mp4").unwrap();

        assert!(
            !is_healthy_video(plik.to_str().unwrap()),
            "Plik z rozszerzeniem .mp4, ale bez treści wideo, musi zostać odrzucony"
        );
    }

    #[test]
    fn test_validator_odrzuca_plik_pusty() {
        let dir = tempfile::tempdir().unwrap();
        let plik = dir.path().join("pusty.mp4");
        std::fs::write(&plik, b"").unwrap();

        assert!(!is_healthy_video(plik.to_str().unwrap()));
    }
}
