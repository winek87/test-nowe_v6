//! Adversarial and Stress Tests for Milestone 1 Centralized Event Bus (`src/event.rs`)
//!
//! Empirical validation of:
//! 1. Receiver drop resilience & graceful degradation across single and multi-threaded callers.
//! 2. Strict FIFO preservation (single thread, synchronized multi-thread, and per-producer monotonicity).
//! 3. High-volume throughput and burst draining (100,000 events under concurrent contention).
//! 4. Edge-case payload serialization, large payloads, unicode/escape sequences, and numeric boundary values.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use mp4_doctor::event::{
    channel, AppEvent, LogLevel, LogMessage, SanitizerMetrics, StatUpdate,
};

// =========================================================================
// 1. RECEIVER DROP RESILIENCE TESTS
// =========================================================================

#[test]
fn test_receiver_drop_raw_send_returns_err() {
    let (tx, rx) = channel();
    drop(rx);

    let event = AppEvent::OperationStarted("test_after_drop".into());
    let result = tx.send(event.clone());
    assert!(result.is_err(), "Raw send must return Err when receiver dropped");
    if let Err(std::sync::mpsc::SendError(returned_event)) = result {
        assert_eq!(returned_event, event, "SendError must return original event intact");
    }
}

#[test]
fn test_receiver_drop_all_helper_methods_never_panic() {
    let (tx, rx) = channel();
    drop(rx);

    // Every convenience helper must be safe against a disconnected channel
    tx.log(LogLevel::Info, "MOD", "msg");
    tx.info("MOD", "info message");
    tx.warn("MOD", "warn message");
    tx.error("MOD", "error message");
    tx.success("MOD", "success message");
    tx.debug("MOD", "debug message");

    tx.update_stats(StatUpdate::default());
    tx.update_thread(1, "Working");
    tx.thread_status(2, "Idle");
    tx.progress(10, 100, Some("Progressing".into()));
    tx.sanitizer_progress(SanitizerMetrics::default());
    tx.sanitizer_metrics(100, 29.97, "2.0x", 1);

    tx.operation_started("Op");
    tx.operation_finished("Done");
    tx.operation_failed("Op", "Failed");

    tx.donor_found("dna", "/path");
    tx.repair_success("file", "dna", "algo");
    tx.repair_failure("file", "dna", "algo");
}

#[test]
fn test_multithreaded_receiver_drop_concurrent_spam() {
    let (tx, rx) = channel();
    let thread_count = 10;
    let barrier = Arc::new(Barrier::new(thread_count + 1));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    for t_id in 0..thread_count {
        let tx_clone = tx.clone();
        let barrier_clone = barrier.clone();
        let stop_clone = stop_signal.clone();

        handles.push(thread::spawn(move || {
            barrier_clone.wait();
            let mut count = 0;
            while !stop_clone.load(Ordering::Relaxed) && count < 10_000 {
                tx_clone.info(format!("THREAD_{}", t_id), format!("Count {}", count));
                tx_clone.update_thread(t_id, format!("Step {}", count));
                count += 1;
            }
            count
        }));
    }

    // Wait for all worker threads to reach barrier
    barrier.wait();

    // Let threads send some messages, then abruptly drop the receiver
    thread::sleep(std::time::Duration::from_millis(10));
    drop(rx);

    // Allow workers to continue hammering the dropped channel
    thread::sleep(std::time::Duration::from_millis(20));
    stop_signal.store(true, Ordering::Relaxed);

    // All threads must join cleanly without panicking
    for (i, h) in handles.into_iter().enumerate() {
        let sent = h.join().expect("Worker thread panicked on dropped receiver!");
        assert!(sent > 0, "Thread {} should have sent at least 1 message", i);
    }
}

#[test]
fn test_receiver_detects_disconnect_when_all_senders_dropped() {
    let (tx, rx) = channel();
    tx.info("M", "first");
    tx.info("M", "second");
    drop(tx);

    assert!(rx.try_recv().is_ok());
    assert!(rx.try_recv().is_ok());
    assert_eq!(rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Disconnected));
}

// =========================================================================
// 2. FIFO PRESERVATION TESTS
// =========================================================================

#[test]
fn test_single_thread_strict_fifo_ordering() {
    let (tx, rx) = channel();
    let total = 20_000;

    for i in 0..total {
        tx.info("SEQ", i.to_string());
    }

    for expected_seq in 0..total {
        match rx.try_recv() {
            Ok(AppEvent::Log(msg)) => {
                let actual_seq: usize = msg.message.parse().expect("Valid integer");
                assert_eq!(actual_seq, expected_seq, "FIFO order violated at index {}", expected_seq);
            }
            other => panic!("Unexpected event {:?} at index {}", other, expected_seq),
        }
    }

    assert!(rx.try_recv().is_err(), "Channel should be completely drained");
}

#[test]
fn test_cross_thread_per_producer_fifo_monotonicity() {
    let (tx, rx) = channel();
    let num_threads = 8;
    let messages_per_thread = 2_500;
    let total_expected = num_threads * messages_per_thread;

    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::new();

    for t_id in 0..num_threads {
        let tx_clone = tx.clone();
        let b = barrier.clone();

        handles.push(thread::spawn(move || {
            b.wait();
            for seq in 0..messages_per_thread {
                tx_clone.info(format!("T{}", t_id), seq.to_string());
            }
        }));
    }

    drop(tx); // Drop root sender so receiver closes after all workers finish

    for h in handles {
        h.join().expect("Worker thread joined successfully");
    }

    // Map each thread to its last observed sequence number
    let mut last_seen: HashMap<String, usize> = HashMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut total_received = 0;

    while let Ok(event) = rx.try_recv() {
        total_received += 1;
        if let AppEvent::Log(msg) = event {
            let seq: usize = msg.message.parse().expect("Seq must be usize");
            let thread_key = msg.module;

            if let Some(&prev_seq) = last_seen.get(&thread_key) {
                assert_eq!(
                    seq,
                    prev_seq + 1,
                    "Monotonicity violation for thread {}: expected {}, got {}",
                    thread_key,
                    prev_seq + 1,
                    seq
                );
            } else {
                assert_eq!(seq, 0, "First message from thread {} must be seq 0", thread_key);
            }
            last_seen.insert(thread_key.clone(), seq);
            *counts.entry(thread_key).or_insert(0) += 1;
        } else {
            panic!("Expected AppEvent::Log");
        }
    }

    assert_eq!(total_received, total_expected);
    for t_id in 0..num_threads {
        let key = format!("T{}", t_id);
        assert_eq!(counts.get(&key), Some(&messages_per_thread));
        assert_eq!(last_seen.get(&key), Some(&(messages_per_thread - 1)));
    }
}

// =========================================================================
// 3. HIGH-VOLUME THROUGHPUT & BURST STRESS TESTS
// =========================================================================

#[test]
fn test_high_volume_concurrent_burst_throughput() {
    let (tx, rx) = channel();
    let num_threads = 10;
    let msgs_per_thread = 10_000;
    let total_msgs = num_threads * msgs_per_thread;

    let barrier = Arc::new(Barrier::new(num_threads + 1));
    let mut handles = Vec::new();

    for t_id in 0..num_threads {
        let tx_c = tx.clone();
        let b_c = barrier.clone();

        handles.push(thread::spawn(move || {
            b_c.wait();
            for i in 0..msgs_per_thread {
                tx_c.update_stats(StatUpdate::new(i, i, 0, 0, (i as u64) * 1024, t_id));
            }
        }));
    }

    let start = Instant::now();
    barrier.wait();

    for h in handles {
        h.join().unwrap();
    }
    let send_elapsed = start.elapsed();

    // Drain receiver
    let drain_start = Instant::now();
    let mut count = 0;
    while let Ok(AppEvent::Stats(_)) = rx.try_recv() {
        count += 1;
    }
    let drain_elapsed = drain_start.elapsed();

    assert_eq!(count, total_msgs, "All 100,000 burst events must be received intact");

    println!(
        "[STRESS BENCH] Sent {} events in {:?} ({:.2} ev/s). Drained in {:?} ({:.2} ev/s).",
        total_msgs,
        send_elapsed,
        (total_msgs as f64) / send_elapsed.as_secs_f64(),
        drain_elapsed,
        (total_msgs as f64) / drain_elapsed.as_secs_f64()
    );
}

// =========================================================================
// 4. PAYLOAD SERIALIZATION & BOUNDARY TESTING
// =========================================================================

#[test]
fn test_adversarial_payload_serialization_round_trip() {
    // 1. Empty strings
    let empty_log = AppEvent::Log(LogMessage::info("", ""));
    let json_empty = serde_json::to_string(&empty_log).expect("Serialize empty strings");
    let de_empty: AppEvent = serde_json::from_str(&json_empty).expect("Deserialize empty strings");
    assert_eq!(empty_log, de_empty);

    // 2. Huge string payload (1 MB)
    let huge_payload = "X".repeat(1024 * 1024);
    let huge_log = AppEvent::Log(LogMessage::error("HUGE", huge_payload.clone()));
    let json_huge = serde_json::to_string(&huge_log).expect("Serialize 1MB payload");
    let de_huge: AppEvent = serde_json::from_str(&json_huge).expect("Deserialize 1MB payload");
    assert_eq!(huge_log, de_huge);

    // 3. Unicode, multi-byte UTF-8, emojis, RTL, control chars, ANSI escape sequences
    let complex_text = "Za\u{017c}\u{00f3}\u{0142}\u{0107} g\u{0119}\u{015b}l\u{0105} ja\u{017a}\u{0144} \
                        🎬💥🚀🔥 👨‍👩‍👧‍👦 \
                        \u{202E}RTL_OVERRIDE\u{202C} \
                        \x1b[31;1mRedBold\x1b[0m \t\r\n \0null-byte\0";
    let unicode_event = AppEvent::Log(LogMessage::warn("UTF8_MODULE", complex_text));
    let json_unicode = serde_json::to_string(&unicode_event).expect("Serialize complex UTF8");
    let de_unicode: AppEvent = serde_json::from_str(&json_unicode).expect("Deserialize complex UTF8");
    assert_eq!(unicode_event, de_unicode);

    // 4. Boundary integers (usize::MAX, u64::MAX, 0)
    let max_stats = AppEvent::Stats(StatUpdate {
        files_scanned: usize::MAX,
        files_healthy: usize::MAX,
        files_broken: 0,
        files_repaired: usize::MAX,
        bytes_processed: u64::MAX,
        active_threads: usize::MAX,
    });
    let json_max = serde_json::to_string(&max_stats).expect("Serialize max integers");
    let de_max: AppEvent = serde_json::from_str(&json_max).expect("Deserialize max integers");
    assert_eq!(max_stats, de_max);

    // 5. SanitizerMetrics boundary floats and speeds
    let metrics = AppEvent::SanitizerProgress(SanitizerMetrics::new(
        u64::MAX,
        29.97,
        "99.99x",
        u8::MAX,
    ));
    let json_metrics = serde_json::to_string(&metrics).expect("Serialize metrics");
    let de_metrics: AppEvent = serde_json::from_str(&json_metrics).expect("Deserialize metrics");
    assert_eq!(metrics, de_metrics);
}

#[test]
fn test_repair_rate_boundary_math() {
    // 0 broken -> 100.0%
    let s0 = StatUpdate::new(0, 0, 0, 0, 0, 0);
    assert_eq!(s0.repair_rate(), 100.0);

    // 100 broken, 0 repaired -> 0.0%
    let s1 = StatUpdate::new(100, 0, 100, 0, 0, 0);
    assert_eq!(s1.repair_rate(), 0.0);

    // 100 broken, 75 repaired -> 75.0%
    let s2 = StatUpdate::new(100, 0, 100, 75, 0, 0);
    assert_eq!(s2.repair_rate(), 75.0);

    // 100 broken, 100 repaired -> 100.0%
    let s3 = StatUpdate::new(100, 0, 100, 100, 0, 0);
    assert_eq!(s3.repair_rate(), 100.0);

    // Broken = usize::MAX, repaired = usize::MAX / 2
    let s_huge = StatUpdate::new(
        usize::MAX,
        0,
        1_000_000,
        500_000,
        u64::MAX,
        16,
    );
    assert!((s_huge.repair_rate() - 50.0).abs() < 0.001);
}

#[test]
fn test_non_finite_float_serialization_behavior() {
    // Standard JSON does not support IEEE 754 NaN or Infinity.
    // serde_json encodes NaN and Infinity as `null` by default.
    let nan_event = AppEvent::SanitizerProgress(SanitizerMetrics::new(1, f32::NAN, "1x", 1));
    let json_nan = serde_json::to_string(&nan_event).expect("Serialize NaN produces JSON with null");
    assert!(json_nan.contains(r#""fps":null"#), "NaN must be serialized as null");

    // Deserializing null into a non-Option f32 should return a serde error gracefully without panicking
    let de_nan_res: Result<AppEvent, _> = serde_json::from_str(&json_nan);
    assert!(de_nan_res.is_err(), "Deserializing null into f32 must fail gracefully");

    // Finite floats must round-trip cleanly
    let finite_event = AppEvent::SanitizerProgress(SanitizerMetrics::new(1, 59.94, "2.5x", 2));
    let json_finite = serde_json::to_string(&finite_event).expect("Serialize finite float");
    let de_finite: AppEvent = serde_json::from_str(&json_finite).expect("Deserialize finite float");
    assert_eq!(finite_event, de_finite);
}
