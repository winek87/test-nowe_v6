use std::process::{Command, Stdio};
use std::path::Path;
use crate::workspace::Workspace;
use crate::event::{EventSender, SanitizerMetrics};
use std::fs;
use std::io::{BufRead, BufReader};
use crate::SHUTDOWN_FLAG;
use std::sync::atomic::Ordering;

pub fn run_deep_sanitization(
    ws: &Workspace, 
    recovered_file: &str, 
    tx: &EventSender,
    use_2pass: bool
) -> Result<String, String> {
    let path = Path::new(recovered_file);

    // Nazwa pliku MUSI dać się wyłuskać. `unwrap()` stał tu wcześniej i
    // panikował na pustej ścieżce — przypadek osiągalny wprost z wiersza
    // poleceń (`--sanitize ""`), potwierdzony empirycznie. Panika w bibliotece
    // wywraca też interfejs TUI, który ją woła.
    let file_name = match path.file_name() {
        Some(n) => n.to_string_lossy(),
        None => {
            let powod = format!("Ścieżka '{}' nie wskazuje pliku", recovered_file);
            tx.operation_failed("Sanitizer", &powod);
            return Err(powod);
        }
    };
    
    let sanitized_dir = ws.root_dir.join("4_sanitized_output");
    if !sanitized_dir.exists() {
        let _ = fs::create_dir_all(&sanitized_dir);
    }
    
    let sanitized_path = sanitized_dir.join(format!("PRISTINE_{}", file_name));
    let sanitized_str = sanitized_path.to_str().unwrap();
    
    let log_path = ws.root_dir.join(format!("x264_passlog_{}", file_name));
    let log_str = log_path.to_str().unwrap();

    if !use_2pass {
        tx.operation_started("Sanitizer: 1-Pass CRF");
        tx.info("SANITIZER", "Uruchamianie 1-Pass CRF (Wysoka jakość CRF 18)");
        tx.thread_status(0, "Sanityzator: 1-Pass CRF");
        run_ffmpeg(tx, vec![
            "-y", "-err_detect", "ignore_err", "-i", recovered_file,
            "-c:v", "libx264", "-preset", "fast", "-crf", "18", 
            "-passlogfile", log_str,
            "-c:a", "aac", "-b:a", "192k", "-async", "1",
            sanitized_str
        ], 1)?;
    } else {
        tx.operation_started("Sanitizer: 2-Pass VBR");
        tx.info("SANITIZER", "2-Pass VBR: Uruchamiam Przebieg 1 (Analiza)...");
        tx.thread_status(0, "Sanityzator: Pass 1 (Analiza)");
        
        // Pass 1
        let pass1_res = run_ffmpeg(tx, vec![
            "-y", "-err_detect", "ignore_err", "-i", recovered_file,
            "-c:v", "libx264", "-preset", "fast", "-b:v", "15M",
            "-pass", "1", "-passlogfile", log_str,
            "-an", "-f", "mp4", "/dev/null"
        ], 1);
        
        if pass1_res.is_err() {
            tx.error("SANITIZER", "Błąd podczas analizy (Pass 1)");
            tx.operation_failed("Sanitizer", "Pass 1 Failed");
            return Err("Pass 1 Failed".to_string());
        }

        tx.info("SANITIZER", "2-Pass VBR: Uruchamiam Przebieg 2 (Rendering Główny)...");
        tx.thread_status(0, "Sanityzator: Pass 2 (Rendering Główny)");
        
        // Pass 2
        run_ffmpeg(tx, vec![
            "-y", "-err_detect", "ignore_err", "-i", recovered_file,
            "-c:v", "libx264", "-preset", "fast", "-b:v", "15M",
            "-pass", "2", "-passlogfile", log_str,
            "-c:a", "aac", "-b:a", "192k", "-async", "1",
            sanitized_str
        ], 2)?;
    }

    tx.success("SANITIZER", format!("Sanityzacja zakończona sukcesem: PRISTINE_{}", file_name));
    tx.operation_finished(format!("Zakończono sanityzację: PRISTINE_{}", file_name));
    tx.thread_status(0, "Zakończono sanityzację");
    Ok(sanitized_str.to_string())
}

fn run_ffmpeg(tx: &EventSender, args: Vec<&str>, pass: u8) -> Result<(), String> {
    let mut cmd = Command::new("ffmpeg")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;

    let stderr = cmd.stderr.take().unwrap();
    let reader = BufReader::new(stderr);

    let mut last_logged_frame: u64 = 0;

    for line in reader.split(b'\r') {
        if SHUTDOWN_FLAG.load(Ordering::Relaxed) {
            let _ = cmd.kill();
            tx.warn("SANITIZER", "Przerwano sanityzację przez użytkownika (Ctrl+C)");
            return Err("Przerwano przez użytkownika (Ctrl+C)".to_string());
        }
        if let Ok(line_vec) = line {
            let text = String::from_utf8_lossy(&line_vec).to_string();
            let text_clean = text.replace('\n', " ");
            if text_clean.contains("frame=") {
                let mut frame: u64 = 0;
                let mut fps: f32 = 0.0;
                let mut speed = String::from("0x");

                // Ekstrakcja liczby klatek: "frame=  123"
                if let Some(frame_idx) = text_clean.find("frame=") {
                    let after = &text_clean[frame_idx + 6..];
                    if let Some(tok) = after.split_whitespace().next() {
                        frame = tok.parse::<u64>().unwrap_or(0);
                    }
                }

                // Ekstrakcja klatek na sekundę: "fps= 45.2"
                if let Some(fps_idx) = text_clean.find("fps=") {
                    let after = &text_clean[fps_idx + 4..];
                    if let Some(tok) = after.split_whitespace().next() {
                        fps = tok.parse::<f32>().unwrap_or(0.0);
                    }
                }

                // Ekstrakcja prędkości: "speed= 1.45x"
                if let Some(speed_idx) = text_clean.find("speed=") {
                    let after = &text_clean[speed_idx + 6..];
                    if let Some(tok) = after.split_whitespace().next() {
                        speed = tok.to_string();
                    }
                }

                // Emisja ustrukturyzowanej telemetrii do szyny TUI
                tx.sanitizer_progress(SanitizerMetrics {
                    frame,
                    fps,
                    speed: speed.clone(),
                    pass,
                });

                // Aktualizacja statusu aktywnego wątku
                tx.thread_status(0, format!("Sanityzator [Pass {}]: klatka {} | fps {:.1} | {}", pass, frame, fps, speed));

                // Ograniczone logi operacyjne (co 500 klatek)
                if frame >= last_logged_frame + 500 {
                    last_logged_frame = frame;
                    tx.debug("SANITIZER", format!("Pass {}: przetworzono {} klatek (fps: {:.1}, speed: {})", pass, frame, fps, speed));
                }
            }
        }
    }

    let status = cmd.wait().map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        tx.error("SANITIZER", format!("FFmpeg zakończył działanie z kodem błędu: {:?}", status.code()));
        Err("Błąd FFmpeg".to_string())
    }
}

/// Pomocniczy punkt wejścia w trybie headless
pub fn run_deep_sanitization_headless(
    ws: &Workspace,
    recovered_file: &str,
    use_2pass: bool,
) -> Result<String, String> {
    crate::bezglowe::z_odbiorem(ws, |tx| run_deep_sanitization(ws, recovered_file, tx, use_2pass))
}

// ============================================================================
// TESTY JEDNOSTKOWE
//
// Pełny przebieg sanityzacji uruchamia ffmpeg na materiale wideo i trwa
// minuty — tu sprawdzamy WARUNKI BRZEGOWE wejścia, czyli to, co da się
// sprawdzić szybko i co realnie wywracało program.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::Workspace;

    fn przestrzen(nazwa: &str) -> Workspace {
        let ws = Workspace::init_testowy(nazwa).expect("przestrzeń testowa musi powstać");
        crate::db::init_db(&ws).expect("baza musi się utworzyć");
        ws
    }

    /// REGRESJA: `path.file_name().unwrap()` panikował na pustej ścieżce.
    /// Przypadek osiągalny wprost z wiersza poleceń (`--sanitize ""`),
    /// potwierdzony na zbudowanej binarce. Panika w bibliotece wywraca też
    /// interfejs TUI, który tę funkcję woła.
    #[test]
    fn test_pusta_sciezka_daje_blad_zamiast_paniki() {
        let ws = przestrzen("sanitizer_pusta_sciezka");
        let (tx, _rx) = crate::event::channel();

        let wynik = run_deep_sanitization(&ws, "", &tx, false);

        assert!(wynik.is_err(), "Pusta ścieżka musi dać błąd");
        assert!(
            wynik.unwrap_err().contains("nie wskazuje pliku"),
            "Komunikat musi mówić, co jest nie tak"
        );
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    /// Ścieżka kończąca się `..` też nie ma nazwy pliku — ten sam warunek,
    /// inne wejście.
    #[test]
    fn test_sciezka_bez_nazwy_pliku_daje_blad() {
        let ws = przestrzen("sanitizer_bez_nazwy");
        let (tx, _rx) = crate::event::channel();

        assert!(run_deep_sanitization(&ws, "/tmp/..", &tx, false).is_err());
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }

    #[test]
    fn test_nieistniejacy_plik_daje_blad_a_nie_panike() {
        let ws = przestrzen("sanitizer_brak_pliku");
        let (tx, _rx) = crate::event::channel();

        assert!(run_deep_sanitization(&ws, "/nie/ma/takiego/pliku.mp4", &tx, false).is_err());
        let _ = std::fs::remove_dir_all(&ws.root_dir);
    }
}
