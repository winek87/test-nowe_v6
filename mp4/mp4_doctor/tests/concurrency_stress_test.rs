//! Concurrency, Multi-Producer Safety and Stress Test Suite
//!
//! Validates:
//! 1. Multi-producer safety: `EventSender` cloned and used across many threads simultaneously.
//! 2. Race conditions and memory corruption checks under high contention.
//! 3. FIFO event ordering per producer thread.
//! 4. Rayon thread pool parallel iteration emission.
//! 5. Receiver drop resilience under concurrent multi-producer load.
//! 6. Crate root exports: `SHUTDOWN_FLAG`, `get_thread_count`, `set_thread_count`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use rayon::prelude::*;

use mp4_doctor::event::{channel, AppEvent, StatUpdate};
use mp4_doctor::{get_thread_count, set_thread_count, SHUTDOWN_FLAG};

// Serializes tests that write to the hardcoded `workspaces/threads.conf` on disk
static THREAD_CONF_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_multi_producer_concurrent_emission() {
    const NUM_PRODUCERS: usize = 20;
    const EVENTS_PER_PRODUCER: usize = 1000;
    const TOTAL_EVENTS: usize = NUM_PRODUCERS * EVENTS_PER_PRODUCER;

    let (tx, rx) = channel();
    let barrier = Arc::new(Barrier::new(NUM_PRODUCERS + 1));
    let mut handles = Vec::new();

    for thread_id in 0..NUM_PRODUCERS {
        let sender = tx.clone();
        let b = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            b.wait();

            for i in 0..EVENTS_PER_PRODUCER {
                match i % 6 {
                    0 => sender.info(format!("THREAD_{}", thread_id), format!("Event {}", i)),
                    1 => sender.warn(format!("THREAD_{}", thread_id), format!("Warning {}", i)),
                    2 => sender.update_thread(thread_id, format!("Working {}", i)),
                    3 => sender.update_stats(StatUpdate::new(i, i, 0, 0, (i * 100) as u64, thread_id)),
                    4 => sender.sanitizer_metrics(i as u64, 60.0, "1.5x", 1),
                    5 => sender.progress(i, EVENTS_PER_PRODUCER, Some(format!("Progress {}", i))),
                    _ => unreachable!(),
                }
            }
        }));
    }

    drop(tx);
    barrier.wait();

    let mut received_count = 0;
    let mut thread_event_counts = vec![0usize; NUM_PRODUCERS];

    while let Ok(event) = rx.recv() {
        received_count += 1;
        match event {
            AppEvent::Log(log) => {
                if let Some(t_str) = log.module.strip_prefix("THREAD_") {
                    let tid: usize = t_str.parse().unwrap();
                    thread_event_counts[tid] += 1;
                }
            }
            AppEvent::ThreadStatus(ws) => {
                thread_event_counts[ws.thread_id] += 1;
            }
            AppEvent::Stats(st) => {
                thread_event_counts[st.active_threads] += 1;
            }
            AppEvent::SanitizerProgress(_) => {}
            AppEvent::Progress { .. } => {}
            _ => {}
        }
    }

    for handle in handles {
        handle.join().expect("Producer thread panicked!");
    }

    assert_eq!(
        received_count, TOTAL_EVENTS,
        "Mismatch in received events: expected {}, got {}",
        TOTAL_EVENTS, received_count
    );
}

#[test]
fn test_multi_producer_fifo_ordering_per_thread() {
    const NUM_THREADS: usize = 32;
    const EVENTS_PER_THREAD: usize = 500;

    let (tx, rx) = channel();
    let barrier = Arc::new(Barrier::new(NUM_THREADS + 1));
    let mut handles = Vec::new();

    for t_id in 0..NUM_THREADS {
        let sender = tx.clone();
        let b = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            b.wait();
            for seq in 0..EVENTS_PER_THREAD {
                sender.info(format!("T{}", t_id), format!("{}", seq));
            }
        }));
    }

    drop(tx);
    barrier.wait();

    let mut per_thread_sequences: Vec<Vec<usize>> = vec![Vec::with_capacity(EVENTS_PER_THREAD); NUM_THREADS];

    while let Ok(event) = rx.recv() {
        if let AppEvent::Log(log) = event {
            if let Some(t_id_str) = log.module.strip_prefix('T') {
                let tid: usize = t_id_str.parse().unwrap();
                let seq: usize = log.message.parse().unwrap();
                per_thread_sequences[tid].push(seq);
            }
        }
    }

    for handle in handles {
        handle.join().expect("Thread panicked!");
    }

    for (tid, seqs) in per_thread_sequences.into_iter().enumerate() {
        assert_eq!(
            seqs.len(),
            EVENTS_PER_THREAD,
            "Thread {} lost messages: got {}, expected {}",
            tid,
            seqs.len(),
            EVENTS_PER_THREAD
        );
        for (expected, &actual) in seqs.iter().enumerate() {
            assert_eq!(
                expected, actual,
                "FIFO order violation on thread {}: expected seq {}, got {}",
                tid, expected, actual
            );
        }
    }
}

#[test]
fn test_rayon_parallel_iterator_emission() {
    const TOTAL_ITEMS: usize = 2000;
    let (tx, rx) = channel();

    let start = Instant::now();

    (0..TOTAL_ITEMS).into_par_iter().for_each_with(tx.clone(), |s, i| {
        s.info("RAYON", format!("Item {}", i));
    });

    drop(tx);

    let mut count = 0;
    while let Ok(event) = rx.recv() {
        if let AppEvent::Log(log) = event {
            assert_eq!(log.module, "RAYON");
            count += 1;
        }
    }

    let elapsed = start.elapsed();
    assert_eq!(count, TOTAL_ITEMS);
    println!("Rayon parallel dispatch of {} items took {:?}", TOTAL_ITEMS, elapsed);
}

#[test]
fn test_high_volume_stress_100k_events() {
    const NUM_THREADS: usize = 50;
    const EVENTS_PER_THREAD: usize = 2000;
    const TOTAL_EVENTS: usize = NUM_THREADS * EVENTS_PER_THREAD;

    let (tx, rx) = channel();
    let barrier = Arc::new(Barrier::new(NUM_THREADS + 1));
    let mut handles = Vec::new();

    let start = Instant::now();

    for t_id in 0..NUM_THREADS {
        let sender = tx.clone();
        let b = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            b.wait();
            for i in 0..EVENTS_PER_THREAD {
                sender.debug(format!("T{}", t_id), format!("Val {}", i));
            }
        }));
    }

    drop(tx);
    barrier.wait();

    let mut received = 0;
    while let Ok(_) = rx.recv() {
        received += 1;
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let duration = start.elapsed();
    assert_eq!(received, TOTAL_EVENTS);
    println!("Stress test: 100,000 events across 50 threads processed in {:?}", duration);
    assert!(duration < Duration::from_secs(5), "100k events took too long: {:?}", duration);
}

#[test]
fn test_concurrent_cloning_and_sending_hammer() {
    const NUM_CLONERS: usize = 16;
    const CLONES_PER_THREAD: usize = 500;

    let (tx, rx) = channel();
    let barrier = Arc::new(Barrier::new(NUM_CLONERS + 1));
    let mut handles = Vec::new();

    for t_id in 0..NUM_CLONERS {
        let sender = tx.clone();
        let b = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            b.wait();
            for c in 0..CLONES_PER_THREAD {
                let cloned = sender.clone();
                cloned.debug("CLONE_TEST", format!("Thread {} clone {}", t_id, c));
            }
        }));
    }

    drop(tx);
    barrier.wait();

    let mut count = 0;
    while let Ok(_event) = rx.recv() {
        count += 1;
    }

    for handle in handles {
        handle.join().expect("Cloning thread panicked!");
    }

    assert_eq!(count, NUM_CLONERS * CLONES_PER_THREAD);
}

#[test]
fn test_simultaneous_clone_send_drop_chaos() {
    const WORKER_THREADS: usize = 8;
    const CLONE_DROP_THREADS: usize = 8;
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    for w in 0..WORKER_THREADS {
        let sender = tx.clone();
        let s = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let mut i = 0;
            while !s.load(Ordering::Relaxed) {
                sender.info(format!("WORKER_{}", w), format!("Count {}", i));
                i += 1;
            }
        }));
    }

    for c in 0..CLONE_DROP_THREADS {
        let sender = tx.clone();
        let s = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let mut i = 0;
            while !s.load(Ordering::Relaxed) {
                let cl = sender.clone();
                cl.warn(format!("CLONER_{}", c), format!("Iter {}", i));
                drop(cl);
                i += 1;
            }
        }));
    }

    let reader_stop = Arc::clone(&stop);
    let reader = thread::spawn(move || {
        let mut total_drained = 0;
        while !reader_stop.load(Ordering::Relaxed) {
            while let Ok(_) = rx.try_recv() {
                total_drained += 1;
            }
            thread::yield_now();
        }
        while let Ok(_) = rx.try_recv() {
            total_drained += 1;
        }
        total_drained
    });

    thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);

    for h in handles {
        h.join().expect("Chaos worker panicked!");
    }
    drop(tx);

    let drained = reader.join().expect("Reader panicked!");
    assert!(drained > 0, "Expected non-zero drained events in chaos test");
}

#[test]
fn test_receiver_dropped_under_concurrent_load() {
    const NUM_WORKERS: usize = 10;
    let (tx, rx) = channel();
    let barrier = Arc::new(Barrier::new(NUM_WORKERS + 1));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let sent_after_drop_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();

    for _ in 0..NUM_WORKERS {
        let sender = tx.clone();
        let b = Arc::clone(&barrier);
        let stop = Arc::clone(&stop_signal);
        let sent_after = Arc::clone(&sent_after_drop_count);

        handles.push(thread::spawn(move || {
            b.wait();
            while !stop.load(Ordering::Relaxed) {
                sender.info("BURST", "Burst message while channel might be closed");
                sender.update_stats(StatUpdate::default());
                sender.operation_started("dummy_op");

                if let Err(_) = sender.send(AppEvent::OperationFinished("dummy".into())) {
                    sent_after.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    barrier.wait();
    thread::sleep(Duration::from_millis(50));

    drop(rx);
    drop(tx);

    thread::sleep(Duration::from_millis(50));
    stop_signal.store(true, Ordering::Relaxed);

    for handle in handles {
        handle.join().expect("Worker thread panicked when receiver dropped!");
    }

    assert!(sent_after_drop_count.load(Ordering::Relaxed) > 0);
}

#[test]
fn test_crate_root_shutdown_flag() {
    SHUTDOWN_FLAG.store(false, Ordering::SeqCst);
    assert_eq!(SHUTDOWN_FLAG.load(Ordering::SeqCst), false);

    const NUM_THREADS: usize = 10;
    let barrier = Arc::new(Barrier::new(NUM_THREADS + 1));
    let mut handles = Vec::new();

    for i in 0..NUM_THREADS {
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            if i == 5 {
                SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
            }
        }));
    }

    barrier.wait();
    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(SHUTDOWN_FLAG.load(Ordering::SeqCst), true);
    SHUTDOWN_FLAG.store(false, Ordering::SeqCst);
}

/// Liczba rdzeni widziana przez `get_thread_count` — jedyne wiarygodne
/// odniesienie dla oczekiwań w tych testach.
///
/// `get_thread_count` używa dokładnie tego wywołania, więc test i implementacja
/// patrzą na tę samą liczbę, niezależnie od maszyny.
fn sprzetowe_max() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// NAPRAWIONY TEST: poprzednia wersja asertowała `get_thread_count() == 0` po
/// `set_thread_count(0)` oraz `== 64` po `set_thread_count(64)`.
///
/// Pierwsza asercja była NIEMOŻLIWA na jakimkolwiek sprzęcie: implementacja
/// traktuje 0 jako „Auto" i rozwiązuje je na realną liczbę rdzeni
/// (`if configured == 0 { configured = hardware_max }`), a `hardware_max` nigdy
/// nie jest zerem. Druga przechodziła tylko na maszynach z co najmniej
/// 32 rdzeniami, bo limit akceptacji to `2 * hardware_max`.
///
/// Oczekiwania są teraz wyliczane ze sprzętu, więc test sprawdza KONTRAKT
/// funkcji, a nie przypadkowe parametry maszyny, na której powstał.
#[test]
fn test_crate_root_thread_count_exports() {
    let _guard = THREAD_CONF_LOCK.lock().unwrap();
    let original = get_thread_count();
    let rdzenie = sprzetowe_max();

    // Wartość mieszcząca się w limicie jest zachowywana bez zmian.
    set_thread_count(rdzenie);
    assert_eq!(get_thread_count(), rdzenie, "wartość w limicie musi zostać zachowana");

    // GRANICA: dokładnie `2 * rdzenie` jest jeszcze akceptowane.
    set_thread_count(rdzenie * 2);
    assert_eq!(get_thread_count(), rdzenie * 2, "dwukrotność rdzeni to górna granica akceptacji");

    // Powyżej granicy następuje fallback na realny sprzęt.
    set_thread_count(rdzenie * 2 + 1);
    assert_eq!(get_thread_count(), rdzenie, "wartość ponad limit musi spaść do liczby rdzeni");

    // 0 znaczy „Auto" — rozwiązywane na liczbę rdzeni, NIE zwracane jako 0.
    set_thread_count(0);
    assert_eq!(get_thread_count(), rdzenie, "0 to tryb Auto, nie dosłowne zero wątków");

    set_thread_count(original);
}

/// NAPRAWIONY TEST: poprzednia wersja asertowała `== 16` dla wpisu „  16  "
/// (co przechodziło tylko od 8 rdzeni w górę) oraz `== 0` dla wejść
/// nieparsowalnych — a 0 nie może zostać zwrócone nigdy, bo implementacja
/// traktuje je jako „Auto" i podmienia na liczbę rdzeni.
///
/// Test sprawdza teraz dwie rzeczy, obie niezależne od maszyny: że białe znaki
/// wokół liczby są tolerowane (`trim`) i że KAŻDE wejście nieparsowalne kończy
/// się fallbackiem na realny sprzęt.
#[test]
fn test_thread_count_malformed_and_edge_cases() {
    let _guard = THREAD_CONF_LOCK.lock().unwrap();
    // Kieruje `threads.conf` do katalogu tymczasowego — inaczej ten test
    // odtwarzałby `workspaces/` w drzewie projektu.
    let _ = mp4_doctor::workspace::katalog_przestrzeni_dla_testow();
    let conf_path = mp4_doctor::sciezka_konfiguracji_watkow();
    let _ = std::fs::create_dir_all(conf_path.parent().unwrap());
    let rdzenie = sprzetowe_max();

    // Białe znaki wokół liczby muszą być obcięte. Używamy wartości mieszczącej
    // się w limicie, żeby test mierzył `trim`, a nie regułę fallbacku.
    let _ = std::fs::write(&conf_path, format!("  {}  \n", rdzenie));
    assert_eq!(get_thread_count(), rdzenie, "białe znaki wokół liczby muszą być tolerowane");

    // Wejścia NIEPARSOWALNE dają 0 przy parsowaniu, a 0 znaczy „Auto".
    for zle_wejscie in ["", "   ", "invalid_number", "-5", "3.5", "0x10", "99999999999999999999"] {
        let _ = std::fs::write(&conf_path, zle_wejscie);
        assert_eq!(
            get_thread_count(), rdzenie,
            "nieparsowalne wejście {:?} musi dać fallback na liczbę rdzeni", zle_wejscie
        );
    }

    // Brak pliku w ogóle to też tryb Auto.
    let _ = std::fs::remove_file(&conf_path);
    assert_eq!(get_thread_count(), rdzenie, "brak pliku konfiguracji to tryb Auto");

    set_thread_count(0);
}

#[test]
fn test_concurrent_thread_count_reads_and_writes() {
    let _guard = THREAD_CONF_LOCK.lock().unwrap();
    const NUM_READERS: usize = 8;
    const NUM_WRITERS: usize = 4;
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    for w in 0..NUM_WRITERS {
        let s = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let mut val = w;
            while !s.load(Ordering::Relaxed) {
                set_thread_count(val);
                val = (val + 1) % 32;
            }
        }));
    }

    for _ in 0..NUM_READERS {
        let s = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let _ = get_thread_count();
            }
        }));
    }

    thread::sleep(Duration::from_millis(100));
    stop.store(true, Ordering::Relaxed);

    for h in handles {
        h.join().expect("Thread count concurrent test panicked!");
    }

    set_thread_count(0);
}
