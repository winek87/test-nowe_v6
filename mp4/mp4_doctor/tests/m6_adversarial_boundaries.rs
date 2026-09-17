//! Milestone 6 Adversarial Boundary and Domain Stress Verification Suite
//!
//! Principal Boundary & File Integrity Stress Testing (Tier 5):
//! 1. Domain File & Payload Stress:
//!    - Corrupted MP4 payloads: truncated atoms, zero-byte headers, oversized atom lengths, random noise.
//!    - Scanner and DNA extraction graceful handling via EventSender without panicking or leaking stdout.
//! 2. Extreme Terminal Geometry Stress:
//!    - Resizing churn across extreme aspect ratios (500x10, 10x500, 60x15, 59x14) while operations stream telemetry.
//! 3. Headless Mode & Subprocess Integrity:
//!    - Verification of --help, --version, --auto-test, and --scan flags and terminal cleanliness.
//!    - Diagnostic audit of subprocess stderr/stdout isolation.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use ratatui::{backend::TestBackend, Terminal};

use mp4_doctor::event::{channel, AppEvent, SanitizerMetrics, StatUpdate};
use mp4_doctor::tui::app::{App, ConfirmActionTarget, Modal, PathInputTarget, View};
use mp4_doctor::tui::ui;
use mp4_doctor::workspace::Workspace;
use mp4_doctor::{db, dna, engine_native, scanner};

static TEST_MUTEX: Mutex<()> = Mutex::new(());

/// Zajmuje `TEST_MUTEX` ODPORNIE NA ZATRUCIE.
///
/// Testy w tym pliku serializują się jednym muteksem, bo współdzielą terminal
/// i katalog roboczy. Przy `lock().unwrap()` panika JEDNEGO testu zatruwała
/// muteks i każdy kolejny padał na `PoisonError` — jedna realna porażka dawała
/// dziewięć czerwonych wyników i chowała informację o tym, co się naprawdę
/// zepsuło.
///
/// Zatrucie znaczy tylko tyle, że ktoś spanikował trzymając blokadę. Muteks
/// strzeże tu KOLEJNOŚCI, nie żadnego stanu, który mógłby przez to stracić
/// spójność — więc `into_inner()` jest właściwym zachowaniem.
fn zajmij_muteks() -> std::sync::MutexGuard<'static, ()> {
    TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}
static SUITE_COUNTER: AtomicUsize = AtomicUsize::new(1);

unsafe extern "C" {
    fn dup(fd: i32) -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn pipe(fds: *mut i32) -> i32;
}

/// RAII Guard that redirects stdout (fd 1) and stderr (fd 2) to pipes
/// and restores them on drop, capturing any leaked bytes.
struct StdCapture {
    saved_stdout: i32,
    saved_stderr: i32,
    out_pipe: [i32; 2],
    err_pipe: [i32; 2],
}

impl StdCapture {
    fn start() -> Self {
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();

        unsafe {
            let saved_stdout = dup(1);
            let saved_stderr = dup(2);

            let mut out_pipe = [0i32; 2];
            let mut err_pipe = [0i32; 2];

            assert_eq!(pipe(&mut out_pipe[0] as *mut i32), 0, "Failed to create stdout pipe");
            assert_eq!(pipe(&mut err_pipe[0] as *mut i32), 0, "Failed to create stderr pipe");

            assert_eq!(dup2(out_pipe[1], 1), 1, "Failed to redirect stdout");
            assert_eq!(dup2(err_pipe[1], 2), 2, "Failed to redirect stderr");

            StdCapture {
                saved_stdout,
                saved_stderr,
                out_pipe,
                err_pipe,
            }
        }
    }

    fn finish(self) -> (Vec<u8>, Vec<u8>) {
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();

        unsafe {
            dup2(self.saved_stdout, 1);
            dup2(self.saved_stderr, 2);
            close(self.saved_stdout);
            close(self.saved_stderr);

            close(self.out_pipe[1]);
            close(self.err_pipe[1]);

            let mut out_bytes = Vec::new();
            let mut out_file = File::from_raw_fd(self.out_pipe[0]);
            let _ = out_file.read_to_end(&mut out_bytes);

            let mut err_bytes = Vec::new();
            let mut err_file = File::from_raw_fd(self.err_pipe[0]);
            let _ = err_file.read_to_end(&mut err_bytes);

            (out_bytes, err_bytes)
        }
    }
}

struct TestWorkspaceGuard {
    pub ws: Workspace,
}

impl TestWorkspaceGuard {
    fn new(prefix: &str) -> Self {
        let id = SUITE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("m6_{}_{}_{}", prefix, std::process::id(), id);
        let ws = Workspace::init_testowy(&name).expect("Failed to initialize test workspace");
        db::init_db(&ws).expect("Failed to initialize test db");
        Self { ws }
    }
}

impl Drop for TestWorkspaceGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.ws.root_dir);
    }
}

fn buffer_to_strings(terminal: &Terminal<TestBackend>, width: u16, height: u16) -> Vec<String> {
    let buffer = terminal.backend().buffer();
    let mut lines = Vec::new();
    for y in 0..height {
        let line: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
        lines.push(line);
    }
    lines
}

fn buffer_contains(terminal: &Terminal<TestBackend>, width: u16, height: u16, target: &str) -> bool {
    let lines = buffer_to_strings(terminal, width, height);
    lines.iter().any(|line| line.contains(target))
}

// =========================================================================
// SECTION 1: DOMAIN FILE & PAYLOAD STRESS TESTS
// =========================================================================

#[test]
fn test_payload_truncated_atoms() {
    let _lock = zajmij_muteks();
    let ws_guard = TestWorkspaceGuard::new("truncated");
    let test_dir = ws_guard.ws.broken_dir.clone();

    // 1. Zero-byte file
    let zero_file = test_dir.join("zero_byte.mp4");
    File::create(&zero_file).unwrap();

    // 2. 1-byte file
    let byte1_file = test_dir.join("one_byte.mp4");
    fs::write(&byte1_file, [0x00]).unwrap();

    // 3. 4-byte file (declares size 8 but lacks 4-byte atom type)
    let byte4_file = test_dir.join("four_byte.mp4");
    fs::write(&byte4_file, [0x00, 0x00, 0x00, 0x08]).unwrap();

    // 4. 7-byte file (3 bytes of type: 'moo')
    let byte7_file = test_dir.join("seven_byte.mp4");
    fs::write(&byte7_file, [0x00, 0x00, 0x00, 0x08, b'm', b'o', b'o']).unwrap();

    // 5. 12-byte file: size 16, type 'moov', but truncated before actual content
    let trunc_moov = test_dir.join("trunc_moov.mp4");
    fs::write(
        &trunc_moov,
        [0x00, 0x00, 0x00, 0x10, b'm', b'o', b'o', b'v', 0x01, 0x02, 0x03, 0x04],
    )
    .unwrap();

    // 6. Truncated 64-bit extended size (size=1, type='free', but only 10 bytes total)
    let trunc_ext = test_dir.join("trunc_ext.mp4");
    fs::write(
        &trunc_ext,
        [0x00, 0x00, 0x00, 0x01, b'f', b'r', b'e', b'e', 0x00, 0x01],
    )
    .unwrap();

    let files = [
        &zero_file,
        &byte1_file,
        &byte4_file,
        &byte7_file,
        &trunc_moov,
        &trunc_ext,
    ];

    for f in &files {
        let f_str = f.to_str().unwrap();

        // extract_dna must NOT panic and return valid signature or None
        let dna_res = dna::extract_dna(f_str);
        if f == &&zero_file {
            assert!(dna_res.is_none(), "Zero-byte file should yield None DNA");
        } else {
            assert!(dna_res.is_some(), "Truncated file should yield fallback DNA");
            let (sig, feat) = dna_res.unwrap();
            assert!(!sig.is_empty());
            assert!(feat.entropy >= 0.0 && feat.entropy <= 8.0);
        }

        // extract_and_save_moov must return Err, NEVER panic
        let out_moov = ws_guard.ws.donors_dir.join("out.moov");
        let moov_res = scanner::extract_and_save_moov(f_str, out_moov.to_str().unwrap());
        assert!(moov_res.is_err(), "Truncated atom should not extract valid moov");
    }
}

#[test]
fn test_payload_zero_byte_headers() {
    let _lock = zajmij_muteks();
    let ws_guard = TestWorkspaceGuard::new("zero_headers");
    let test_dir = ws_guard.ws.broken_dir.clone();

    // 8-byte zero header: size 0, type 0000
    let zero8 = test_dir.join("zero8.mp4");
    fs::write(&zero8, [0u8; 8]).unwrap();

    // 16-byte zero header
    let zero16 = test_dir.join("zero16.mp4");
    fs::write(&zero16, [0u8; 16]).unwrap();

    // 1024-byte zero block
    let zero1024 = test_dir.join("zero1024.mp4");
    fs::write(&zero1024, [0u8; 1024]).unwrap();

    for f in [&zero8, &zero16, &zero1024] {
        let f_str = f.to_str().unwrap();

        let dna_res = dna::extract_dna(f_str);
        assert!(dna_res.is_some());
        let (sig, feat) = dna_res.unwrap();
        assert!(sig.starts_with("DNA_RAW_SIZE_"));
        assert_eq!(feat.entropy, 0.0, "All-zero buffer must have 0.0 entropy");

        let out_moov = ws_guard.ws.donors_dir.join("out_zero.moov");
        let moov_res = scanner::extract_and_save_moov(f_str, out_moov.to_str().unwrap());
        assert!(moov_res.is_err());
    }
}

#[test]
fn test_payload_oversized_atom_lengths() {
    let _lock = zajmij_muteks();
    let ws_guard = TestWorkspaceGuard::new("oversized");
    let test_dir = ws_guard.ws.broken_dir.clone();

    // 1. 32-bit oversized: size = u32::MAX (0xFFFFFFFF = 4294967295)
    let over32 = test_dir.join("oversized32.mp4");
    let mut payload = vec![0xFF, 0xFF, 0xFF, 0xFF, b'f', b'r', b'e', b'e'];
    payload.extend_from_slice(&[0x42; 64]);
    fs::write(&over32, &payload).unwrap();

    // 2. 64-bit oversized: size_32 = 1, type = 'free', extended length = u64::MAX
    let over64_max = test_dir.join("oversized64_max.mp4");
    let mut payload64 = vec![0x00, 0x00, 0x00, 0x01, b'f', b'r', b'e', b'e'];
    payload64.extend_from_slice(&[0xFF; 8]); // u64::MAX
    payload64.extend_from_slice(&[0xAB; 64]);
    fs::write(&over64_max, &payload64).unwrap();

    // 3. Multi-atom sequence: atom 1 is valid ftyp (16 bytes), atom 2 has size_32=1, length = u64::MAX - 10
    // Tests potential integer addition overflow: position += actual_size (16 + (u64::MAX - 10))
    let over_chain = test_dir.join("oversized_chain.mp4");
    let mut chain = vec![
        0x00, 0x00, 0x00, 0x10, b'f', b't', b'y', b'p', b'i', b's', b'o', b'm', 0x00, 0x00, 0x02, 0x00,
    ];
    chain.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, b'f', b'r', b'e', b'e']);
    chain.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0]); // u64::MAX - 15
    chain.extend_from_slice(&[0xCC; 32]);
    fs::write(&over_chain, &chain).unwrap();

    for f in [&over32, &over64_max, &over_chain] {
        let f_str = f.to_str().unwrap();

        // DNA extraction should succeed without panic
        let dna_res = dna::extract_dna(f_str);
        assert!(dna_res.is_some());

        // extract_and_save_moov should safely return Err or break without panicking
        let out_moov = ws_guard.ws.donors_dir.join("out_over.moov");
        let moov_res = scanner::extract_and_save_moov(f_str, out_moov.to_str().unwrap());
        assert!(moov_res.is_err());
    }
}

#[test]
fn test_payload_random_noise_and_fuzz() {
    let _lock = zajmij_muteks();
    let ws_guard = TestWorkspaceGuard::new("random_noise");
    let test_dir = ws_guard.ws.broken_dir.clone();

    // Linear Congruential Generator for deterministic pseudo-random fuzz payloads
    let mut state: u64 = 0xDEADBEEFCAFEBABE;
    let mut lcg_rand = || -> u8 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 56) as u8
    };

    // 1. 64 KB of purely random noise
    let noise64 = test_dir.join("noise64k.mp4");
    let noise_data: Vec<u8> = (0..64 * 1024).map(|_| lcg_rand()).collect();
    fs::write(&noise64, &noise_data).unwrap();

    // 2. Bogus NAL unit start codes followed by corrupted SPS bytes
    let bogus_nal = test_dir.join("bogus_nal.mp4");
    let mut nal_data = Vec::new();
    for _ in 0..10 {
        nal_data.extend_from_slice(b"\x00\x00\x00\x01");
        nal_data.push(0x27); // NAL type 7 (SPS) with forbidden bit set (0x20)
        nal_data.extend_from_slice(&[lcg_rand(), lcg_rand(), lcg_rand()]);
        nal_data.extend_from_slice(&(0..50).map(|_| lcg_rand()).collect::<Vec<_>>());
    }
    fs::write(&bogus_nal, &nal_data).unwrap();

    // 3. Bogus ADTS sync words followed by random parameters
    let bogus_adts = test_dir.join("bogus_adts.mp4");
    let mut adts_data = Vec::new();
    for _ in 0..10 {
        adts_data.extend_from_slice(&[0xFF, 0xF1]); // 12-bit syncword
        adts_data.extend_from_slice(&[lcg_rand(), lcg_rand(), lcg_rand()]);
        adts_data.extend_from_slice(&(0..100).map(|_| lcg_rand()).collect::<Vec<_>>());
    }
    fs::write(&bogus_adts, &adts_data).unwrap();

    for f in [&noise64, &bogus_nal, &bogus_adts] {
        let f_str = f.to_str().unwrap();

        let dna_res = dna::extract_dna(f_str);
        assert!(dna_res.is_some(), "Fuzz payload must yield DNA without panic");
        let (sig, feat) = dna_res.unwrap();
        assert!(!sig.is_empty());
        assert!(!feat.entropy.is_nan(), "Entropy must not be NaN");
        assert!(feat.entropy > 0.0);

        // Verify human diagnosis generation survives weird DNA strings
        let report = dna::get_human_readable_diagnosis(&sig, &feat);
        assert!(!report.is_empty());

        let out_moov = ws_guard.ws.donors_dir.join("out_fuzz.moov");
        let _ = scanner::extract_and_save_moov(f_str, out_moov.to_str().unwrap());
    }
}

#[test]
fn test_scanner_pipeline_with_adversarial_payloads_zero_stdout() {
    let _lock = zajmij_muteks();
    let ws_guard = TestWorkspaceGuard::new("scanner_stress");

    // Populate broken directory with diverse adversarial inputs
    let test_dir = ws_guard.ws.root_dir.join("adversarial_input_dir");
    fs::create_dir_all(&test_dir).unwrap();

    fs::write(test_dir.join("trunc1.mp4"), [0x00, 0x00, 0x00, 0x04]).unwrap();
    fs::write(test_dir.join("zero.mp4"), [0u8; 128]).unwrap();
    fs::write(test_dir.join("oversize.mp4"), [0xFF, 0xFF, 0xFF, 0xFF, b'f', b'r', b'e', b'e']).unwrap();
    fs::write(test_dir.join("noise.mp4"), [0x55; 2048]).unwrap();

    let (tx, rx) = channel();

    // Start stdout and stderr capture
    let capture = StdCapture::start();

    // Run scanner in ExtractOnly mode so it doesn't trigger external ffmpeg subprocesses
    scanner::run_scanner(&ws_guard.ws, test_dir.to_str().unwrap(), scanner::ScanMode::ExtractOnly, &tx);

    let (stdout_bytes, _stderr_bytes) = capture.finish();

    // Standard output must be 100% clean (zero bytes leaked)
    assert!(
        stdout_bytes.is_empty(),
        "Scanner leaked {} bytes to stdout! Verbatim: {:?}",
        stdout_bytes.len(),
        String::from_utf8_lossy(&stdout_bytes)
    );

    // Event bus must have captured all events
    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }

    assert!(!events.is_empty(), "Scanner emitted 0 events");
    assert!(
        events.iter().any(|e| matches!(e, AppEvent::OperationStarted(_))),
        "OperationStarted missing"
    );
    assert!(
        events.iter().any(|e| matches!(e, AppEvent::OperationFinished(_))),
        "OperationFinished missing"
    );
    assert!(
        events.iter().any(|e| matches!(e, AppEvent::Stats(_))),
        "Stats update missing"
    );
}

// =========================================================================
// SECTION 2: EXTREME TERMINAL GEOMETRY STRESS TESTS
// =========================================================================

#[test]
fn test_extreme_aspect_ratios_fallback_and_boundary_churn() {
    let _lock = zajmij_muteks();

    // Exact dimensions specified in mission: 500x10, 10x500, 60x15, 59x14
    let test_cases = [
        (500, 10, true, "500x10"),   // Ultra-wide, height sub-threshold (<15)
        (10, 500, true, "10x500"),   // Ultra-tall, width sub-threshold (<60)
        (59, 14, true, "59x14"),     // Both axes sub-threshold
        (60, 15, false, "60x15"),    // Exact threshold boundary (passes!)
    ];

    for (w, h, should_fallback, dim_str) in test_cases {
        let (tx, rx) = channel();
        let mut app = App::with_channel(tx, rx);
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        if should_fallback {
            // Baner awaryjny MUSI się pojawić niezależnie od szerokości.
            // Nagłówek „╔ OSTRZEŻENIE ═…╗" jest przycinany do szerokości
            // terminala, ale jego początek zostaje nawet przy 10 kolumnach
            // („╔ OSTRZEŻ╗") — to więc jedyny marker weryfikowalny zawsze.
            assert!(
                buffer_contains(&terminal, w, h, "OSTRZEŻ"),
                "Fallback banner expected at {}",
                dim_str
            );

            // Menu główne nie może się renderować pod banerem.
            assert!(
                !buffer_contains(&terminal, w, h, "MENU GŁÓWNE"),
                "Main menu must NOT render when fallback is active at {}",
                dim_str
            );

            // NAPRAWIONE ASERCJE: pełne komunikaty są weryfikowalne TYLKO
            // wtedy, gdy fizycznie mieszczą się w szerokości terminala.
            //
            // Poprzednia wersja sprawdzała je bezwarunkowo, więc przy 10
            // kolumnach żądała znalezienia 19-znakowego „Terminal zbyt mały!"
            // i 23-znakowego „Wymagane minimum: 60x15" w linii długiej na 10
            // znaków. `buffer_contains` szuka w obrębie JEDNEJ linii, więc te
            // asercje nie mogły przejść — i nie chodziło o błąd UI: kod
            // poprawnie wchodzi w tryb awaryjny (`width < 60 || height < 15`),
            // tylko rysuje przycięty baner („║Terminal║", „║Wymagane║").
            //
            // Ta jedna niemożliwa asercja zatruwała `TEST_MUTEX` i przewracała
            // osiem kolejnych testów — patrz `zajmij_muteks`.
            let mieszcza_sie = |tekst: &str| (w as usize) >= tekst.chars().count() + 2;

            for tekst in ["Terminal zbyt mały!", "Wymagane minimum: 60x15"] {
                if mieszcza_sie(tekst) {
                    assert!(
                        buffer_contains(&terminal, w, h, tekst),
                        "Message '{}' missing at {} (szerokość {} je pomieści)",
                        tekst, dim_str, w
                    );
                }
            }

            // Baner podaje aktualny rozmiar — też tylko gdy się zmieści.
            let opis_rozmiaru = format!("Aktualny rozmiar: {}", dim_str);
            if mieszcza_sie(&opis_rozmiaru) {
                assert!(
                    buffer_contains(&terminal, w, h, dim_str),
                    "Dimension string '{}' missing in fallback banner at {}",
                    dim_str, dim_str
                );
            }
        } else {
            // At exact 60x15 threshold
            assert!(
                !buffer_contains(&terminal, w, h, "Terminal zbyt mały!"),
                "Fallback must NOT trigger at exact threshold 60x15"
            );
            assert!(
                buffer_contains(&terminal, w, h, "MP4 DOC"),
                "Compact header expected at 60x15"
            );
            assert!(
                buffer_contains(&terminal, w, h, "MENU GŁÓWNE"),
                "Main menu must render at 60x15"
            );
        }
    }
}

#[test]
fn test_resizing_churn_during_live_telemetry_stream() {
    let _lock = zajmij_muteks();

    let (tx, rx) = channel();
    let mut app = App::with_channel(tx.clone(), rx);
    app.current_view = View::OperationRunning;
    app.is_running = true;
    app.current_operation = Some("Adversarial Resizing Stress".to_string());

    // Extreme viewport sequences to churn through
    let dimensions = [
        (500, 10), // Ultra-wide fallback
        (80, 24),  // Standard terminal
        (10, 500), // Ultra-tall fallback
        (120, 40), // Standard wide
        (59, 14),  // Dual sub-threshold
        (60, 15),  // Exact threshold boundary
        (300, 100),// Extreme large
        (60, 15),  // Back to exact threshold
        (500, 10), // Back to ultra-wide
        (100, 30), // Mid-size
    ];

    // Simulate high-volume telemetry stream
    for (i, &(w, h)) in dimensions.iter().cycle().take(40).enumerate() {
        // 1. Send telemetry updates
        tx.info("STRESS", format!("Iteracja {}: Przetwarzanie strumienia...", i));
        if i % 2 == 0 {
            tx.warn("STRESS", format!("Ostrzeżenie: Spadek FPS do {} na klatce {}", 24 + i, i * 100));
        }
        if i % 5 == 0 {
            tx.error("STRESS", format!("Wykryto uszkodzony atom NAL w bloku {}", i));
        }
        if i % 7 == 0 {
            tx.success("STRESS", format!("Uratowano atom moov z powodzeniem! Wątek #{}", i % 4));
        }

        tx.update_stats(StatUpdate::new(
            i * 10,
            i * 8,
            i * 2,
            i,
            (i as u64) * 1024 * 1024,
            4,
        ));
        tx.update_thread(i % 4, format!("Wątek {}: Aktywny przy {}x{}", i % 4, w, h));
        tx.sanitizer_progress(SanitizerMetrics {
            frame: (i as u64) * 30,
            fps: 29.97,
            speed: format!("{:.1}x", 1.5 + (i as f32) * 0.1),
            pass: 1,
        });

        // 2. Drain events into App
        app.process_events();

        // 3. Render frame at chosen dimensions
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| ui::draw(f, &mut app)).unwrap();

        // Verify fallback or normal rendering integrity
        if w < 60 || h < 15 {
            // Ta sama pułapka co w `test_extreme_aspect_ratios_...`: pełny,
            // 19-znakowy komunikat nie zmieści się w terminalu węższym niż 21
            // kolumn (19 znaków treści + dwie krawędzie ramki), a
            // `buffer_contains` szuka w obrębie JEDNEJ linii. Marker „OSTRZEŻ"
            // z nagłówka ramki zostaje widoczny przy każdej szerokości.
            let komunikat = "Terminal zbyt mały!";
            let szukane = if (w as usize) >= komunikat.chars().count() + 2 {
                komunikat
            } else {
                "OSTRZEŻ"
            };

            assert!(
                buffer_contains(&terminal, w, h, szukane),
                "Fallback missing at {}x{} (szukano {:?})", w, h, szukane
            );
        } else {
            assert!(
                buffer_contains(&terminal, w, h, "LIVE TELEMETRIA"),
                "Operation telemetry HUD missing at {}x{}", w, h
            );
        }
    }
}

#[test]
fn test_extreme_geometry_all_views_and_modals() {
    let _lock = zajmij_muteks();

    let (tx, rx) = channel();
    let mut app = App::with_channel(tx, rx);

    let extreme_resolutions = [
        (500, 10),
        (10, 500),
        (60, 15),
        (59, 14),
    ];

    let views = [
        View::MainMenu,
        View::WorkspaceSelect,
        View::WorkspaceDashboard,
        View::ScannerSubMenu,
        View::SettingsMenu,
        View::PreviewFileSelect,
        View::OperationRunning,
    ];

    let modals: Vec<Modal> = vec![
        Modal::None,
        Modal::NewWorkspace {
            input: "TestWorkspace".to_string(),
            cursor: 13,
            error_msg: None,
        },
        Modal::PathInput {
            title: "Ścieżka do skanowania".to_string(),
            prompt: "Podaj ścieżkę:".to_string(),
            input: "/tmp/test".to_string(),
            cursor: 9,
            conf_file: "scan.conf".to_string(),
            target: PathInputTarget::ScannerFull,
            error_msg: None,
        },
        Modal::ConfirmAction {
            title: "Potwierdzenie".to_string(),
            message: "Czy na pewno wyjść?".to_string(),
            action: ConfirmActionTarget::QuitApplication,
            selected_yes: true,
        },
        Modal::SettingsThreadLimit {
            input: "8".to_string(),
            cursor: 1,
            error_msg: None,
        },
        Modal::NotificationDialog {
            title: "Krytyczny Raport".to_string(),
            message: "Krytyczny test modalny w ekstremalnej geometrii".to_string(),
            is_error: true,
        },
    ];

    for &(w, h) in &extreme_resolutions {
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();

        for view in &views {
            app.current_view = *view;

            for modal in &modals {
                app.active_modal = modal.clone();

                // Draw must NEVER panic regardless of view/modal combo at any resolution
                terminal.draw(|f| ui::draw(f, &mut app)).unwrap();
            }
        }
    }
}

// =========================================================================
// SECTION 3: HEADLESS MODE & SUBPROCESS INTEGRITY TESTS
// =========================================================================

#[test]
fn test_headless_help_flag_clean_exit() {
    let bin = env!("CARGO_BIN_EXE_mp4_doctor");
    let output = Command::new(bin).arg("--help").output().unwrap();

    assert!(output.status.success(), "--help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stdout.contains("MP4 Doctor"), "Stdout missing application name");
    assert!(stdout.contains("Usage:"), "Stdout missing usage string");
    assert!(stderr.is_empty(), "Stderr should be empty on --help, found: {}", stderr);
}

#[test]
fn test_headless_version_flag_clean_exit() {
    let bin = env!("CARGO_BIN_EXE_mp4_doctor");
    let output = Command::new(bin).arg("--version").output().unwrap();

    assert!(output.status.success(), "--version failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stdout.contains("mp4_doctor 2.0.0"), "Stdout missing expected version string");
    assert!(stderr.is_empty(), "Stderr should be empty on --version, found: {}", stderr);
}

#[test]
fn test_headless_workspace_and_scan_clean_exit() {
    let _lock = zajmij_muteks();
    let ws_guard = TestWorkspaceGuard::new("cli_scan");
    let target_dir = ws_guard.ws.root_dir.join("scan_target");
    fs::create_dir_all(&target_dir).unwrap();

    let bin = env!("CARGO_BIN_EXE_mp4_doctor");
    let output = Command::new(bin)
        .args([
            "--workspace",
            &ws_guard.ws.name,
            "--scan",
            target_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "Headless scan execution failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[HEADLESS] Uruchamianie Skanera Potokowego"),
        "Expected headless banner not found in stdout"
    );
}

#[test]
fn test_headless_scan_without_workspace_behavior_investigation() {
    // Empirical test of CLI behavior when --scan is specified without --workspace
    let bin = env!("CARGO_BIN_EXE_mp4_doctor");
    let empty_dir = "target/m6_empty_scan_dir";
    let _ = fs::create_dir_all(empty_dir);

    // Run with redirected stdin (/dev/null) so it cannot block interactively
    let output = Command::new(bin)
        .arg("--scan")
        .arg(empty_dir)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();

    // Document whether it exited with non-zero (or fell back to TUI failure)
    let stderr = String::from_utf8_lossy(&output.stderr);
    let _stdout = String::from_utf8_lossy(&output.stdout);

    // If stdin is null and --workspace is omitted, main() attempts run_tui()
    // which fails on non-tty stdin. This documents the observed empirical behavior.
    if !output.status.success() {
        assert!(
            stderr.contains("Błąd interfejsu TUI") || stderr.contains("Inappropriate ioctl") || stderr.contains("Operation not supported") || stderr.contains("bad file descriptor"),
            "Expected TUI initialization failure when running --scan without --workspace on non-tty: {}",
            stderr
        );
    }
}

#[test]
fn test_engine_native_stderr_isolation_diagnostic() {
    let _lock = zajmij_muteks();
    let ws_guard = TestWorkspaceGuard::new("native_audit");

    // Create a corrupted file
    let broken_file = ws_guard.ws.broken_dir.join("corrupted_sample.mp4");
    fs::write(&broken_file, [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33]).unwrap();

    let out_file = ws_guard.ws.output_dir.join("native_out.mp4");

    // Capture standard error during engine_native::repair
    let capture = StdCapture::start();
    let _ = engine_native::repair(broken_file.to_str().unwrap(), out_file.to_str().unwrap(), None);
    let (_stdout_bytes, stderr_bytes) = capture.finish();

    // Empirically check whether ffmpeg leaked anything to stderr
    if !stderr_bytes.is_empty() {
        let leaked = String::from_utf8_lossy(&stderr_bytes);
        println!("Empirically observed stderr output from ffmpeg fallback: {}", leaked);
    }
}

// =========================================================================
// DYSPOZYTOR OPERACJI WSADOWYCH
//
// Biblioteka miała komplet wejść bezgłowych, ale nic ich nie wywoływało.
// Testy niżej sprawdzają sam dyspozytor — przez PODPROCES, bo tylko tak widać
// to, co zobaczy operator: komunikat i kod wyjścia.
// =========================================================================

#[test]
fn test_dyspozytor_wymienia_wszystkie_operacje_wsadowe() {
    let bin = env!("CARGO_BIN_EXE_mp4_doctor");
    let output = Command::new(bin).arg("--help").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    for flaga in ["--scan", "--train", "--sniper", "--sanitize", "--mutate", "--autopilot"] {
        assert!(
            stdout.contains(flaga),
            "Operacja {} musi być widoczna w pomocy - inaczej nikt jej nie znajdzie", flaga
        );
    }
}

#[test]
fn test_dyspozytor_bez_operacji_konczy_sie_czysto_i_podpowiada() {
    let _lock = zajmij_muteks();
    let ws_guard = TestWorkspaceGuard::new("dysp_pusty");

    let bin = env!("CARGO_BIN_EXE_mp4_doctor");
    let output = Command::new(bin)
        .args(["--workspace", &ws_guard.ws.name])
        .output()
        .unwrap();

    assert!(output.status.success(), "Brak operacji to nie jest błąd");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--train") && stdout.contains("--autopilot"),
        "Komunikat musi wymienić dostępne operacje: {}", stdout
    );
}

/// Kod wyjścia to JEDYNY sygnał dla skryptu wsadowego — nikt nie ogląda
/// operacji bezgłowej na żywo.
#[test]
fn test_dyspozytor_zglasza_porazke_kodem_wyjscia() {
    let _lock = zajmij_muteks();
    let ws_guard = TestWorkspaceGuard::new("dysp_porazka");

    let bin = env!("CARGO_BIN_EXE_mp4_doctor");
    let output = Command::new(bin)
        .args(["--workspace", &ws_guard.ws.name, "--sanitize", "/nie/ma/takiego/pliku.mp4"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "Nieudana sanityzacja musi dać niezerowy kod wyjścia");
}

/// Operacja wsadowa nie może być ślepa: `sanitizer` raportuje wyłącznie przez
/// szynę zdarzeń, więc bez odbiornika operator nie zobaczyłby ANI JEDNEJ
/// linii. To właśnie naprawia `bezglowe::z_odbiorem`.
#[test]
fn test_dyspozytor_wypisuje_postep_operacji() {
    let _lock = zajmij_muteks();
    let ws_guard = TestWorkspaceGuard::new("dysp_postep");

    let bin = env!("CARGO_BIN_EXE_mp4_doctor");
    let output = Command::new(bin)
        .args(["--workspace", &ws_guard.ws.name, "--sanitize", "/nie/ma/takiego/pliku.mp4"])
        .output()
        .unwrap();

    let wszystko = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        wszystko.contains("SANITIZER"),
        "Zdarzenia z modułu muszą trafić na wyjście, a nie zginąć w nieodbieranym kanale: {}",
        wszystko
    );
}

#[test]
fn test_dyspozytor_ostrzega_przy_kilku_operacjach_naraz() {
    let _lock = zajmij_muteks();
    let ws_guard = TestWorkspaceGuard::new("dysp_konflikt");

    let bin = env!("CARGO_BIN_EXE_mp4_doctor");
    let output = Command::new(bin)
        .args([
            "--workspace", &ws_guard.ws.name,
            "--sanitize", "/nie/ma/a.mp4",
            "--mutate", "/nie/ma/b.mp4",
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("2 operacje"),
        "Konflikt flag musi być zgłoszony, i to poprawną polszczyzną: {}", stderr
    );
}
