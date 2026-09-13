//! Centralized Event Bus for MP4 Doctor
//!
//! Provides a thread-safe, decoupled communication pipeline between operational
//! background workers (Scanner, Autopilot, Sanitizer, Training Ground) and the
//! Terminal User Interface (TUI) rendering loop.

use std::sync::mpsc::{self, Receiver, SendError, Sender};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

/// Log severity levels for operational log messages and TUI color-coding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Success,
    Warn,
    Error,
}

impl LogLevel {
    /// Returns the uppercase string representation of the log level.
    pub const fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Success => "SUCCESS",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }

    /// Returns a fixed-width bracketed badge suitable for console or TUI rendering.
    pub const fn badge(&self) -> &'static str {
        match self {
            LogLevel::Debug => "[DEBUG]  ",
            LogLevel::Info => "[INFO]   ",
            LogLevel::Success => "[SUCCESS]",
            LogLevel::Warn => "[WARN]   ",
            LogLevel::Error => "[ERROR]  ",
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A structured log entry destined for the scrollable, word-wrapped log panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogMessage {
    pub level: LogLevel,
    pub module: String,
    pub message: String,
    pub timestamp: DateTime<Local>,
}

impl LogMessage {
    /// Creates a new log message with the current local timestamp.
    pub fn new(level: LogLevel, module: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            level,
            module: module.into(),
            message: message.into(),
            timestamp: Local::now(),
        }
    }

    /// Creates a log message with an explicit timestamp.
    pub fn with_timestamp(
        level: LogLevel,
        module: impl Into<String>,
        message: impl Into<String>,
        timestamp: DateTime<Local>,
    ) -> Self {
        Self {
            level,
            module: module.into(),
            message: message.into(),
            timestamp,
        }
    }

    /// Convenience constructor for an Info-level message.
    pub fn info(module: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::new(LogLevel::Info, module, msg)
    }

    /// Convenience constructor for a Warn-level message.
    pub fn warn(module: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::new(LogLevel::Warn, module, msg)
    }

    /// Convenience constructor for an Error-level message.
    pub fn error(module: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::new(LogLevel::Error, module, msg)
    }

    /// Convenience constructor for a Success-level message.
    pub fn success(module: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::new(LogLevel::Success, module, msg)
    }

    /// Convenience constructor for a Debug-level message.
    pub fn debug(module: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::new(LogLevel::Debug, module, msg)
    }

    /// Formats the message timestamp as HH:MM:SS.
    pub fn formatted_time(&self) -> String {
        self.timestamp.format("%H:%M:%S").to_string()
    }
}

/// Cumulative operational statistics snapshot for the TUI live statistics panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StatUpdate {
    pub files_scanned: usize,
    pub files_healthy: usize,
    pub files_broken: usize,
    pub files_repaired: usize,
    pub bytes_processed: u64,
    pub active_threads: usize,
}

impl StatUpdate {
    /// Creates a new statistics snapshot.
    pub fn new(
        files_scanned: usize,
        files_healthy: usize,
        files_broken: usize,
        files_repaired: usize,
        bytes_processed: u64,
        active_threads: usize,
    ) -> Self {
        Self {
            files_scanned,
            files_healthy,
            files_broken,
            files_repaired,
            bytes_processed,
            active_threads,
        }
    }

    /// Calculates the repair success rate as a percentage (0.0 to 100.0).
    pub fn repair_rate(&self) -> f32 {
        if self.files_broken == 0 {
            100.0
        } else {
            (self.files_repaired as f32 / self.files_broken as f32) * 100.0
        }
    }
}

/// Status report of a specific worker thread for the multi-threaded HUD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub thread_id: usize,
    pub status: String,
}

impl WorkerStatus {
    /// Creates a new worker thread status report.
    pub fn new(thread_id: usize, status: impl Into<String>) -> Self {
        Self {
            thread_id,
            status: status.into(),
        }
    }
}

impl From<(usize, String)> for WorkerStatus {
    fn from((thread_id, status): (usize, String)) -> Self {
        Self { thread_id, status }
    }
}

impl From<(usize, &str)> for WorkerStatus {
    fn from((thread_id, status): (usize, &str)) -> Self {
        Self {
            thread_id,
            status: status.to_string(),
        }
    }
}

/// Real-time metrics emitted during FFmpeg video sanitization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SanitizerMetrics {
    pub frame: u64,
    pub fps: f32,
    pub speed: String,
    pub pass: u8,
}

impl SanitizerMetrics {
    /// Creates a new sanitization metrics snapshot.
    pub fn new(frame: u64, fps: f32, speed: impl Into<String>, pass: u8) -> Self {
        Self {
            frame,
            fps,
            speed: speed.into(),
            pass,
        }
    }
}

impl Default for SanitizerMetrics {
    fn default() -> Self {
        Self {
            frame: 0,
            fps: 0.0,
            speed: "0x".to_string(),
            pass: 1,
        }
    }
}

/// Unified event enum transmitted across the centralized event bus.
///
/// Decouples operational modules from the TUI rendering thread.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AppEvent {
    /// Append a structured log message to the scrolling operational log panel.
    Log(LogMessage),

    /// Update cumulative metrics in the live statistics panel.
    Stats(StatUpdate),

    /// Update current status message of a worker thread in the thread HUD.
    ThreadStatus(WorkerStatus),

    /// Real-time progress telemetry from the FFmpeg sanitization subprocess.
    SanitizerProgress(SanitizerMetrics),

    /// Overall progress counter (current, total) for bounded operations.
    Progress {
        current: usize,
        total: usize,
        message: Option<String>,
    },

    /// Notifies that a long-running batch or pipeline operation has commenced.
    OperationStarted(String),

    /// Notifies that an operation has finished successfully with a summary.
    OperationFinished(String),

    /// Notifies that an operation failed (operation_name, error_description).
    OperationFailed(String, String),

    /// Donor file analyzed and recorded (persists to SQLite database).
    DonorFound {
        dna: String,
        moov_path: String,
    },

    /// Repair succeeded with a specific heuristic algorithm (rewards algorithm in SQLite).
    RepairSuccess {
        file_name: String,
        dna: String,
        algorithm: String,
    },

    /// Repair failed with a specific heuristic algorithm (penalizes algorithm in SQLite).
    RepairFailure {
        file_name: String,
        dna: String,
        algorithm: String,
    },
}

impl From<LogMessage> for AppEvent {
    fn from(msg: LogMessage) -> Self {
        AppEvent::Log(msg)
    }
}

impl From<StatUpdate> for AppEvent {
    fn from(stats: StatUpdate) -> Self {
        AppEvent::Stats(stats)
    }
}

impl From<WorkerStatus> for AppEvent {
    fn from(status: WorkerStatus) -> Self {
        AppEvent::ThreadStatus(status)
    }
}

impl From<SanitizerMetrics> for AppEvent {
    fn from(metrics: SanitizerMetrics) -> Self {
        AppEvent::SanitizerProgress(metrics)
    }
}

/// Lightweight, thread-safe, clonable handle for sending events to the TUI event loop.
///
/// Wraps `std::sync::mpsc::Sender<AppEvent>`. Implements `Send + Sync + Clone`.
#[derive(Clone, Debug)]
pub struct EventSender {
    sender: Sender<AppEvent>,
}

impl EventSender {
    /// Creates a new `EventSender` wrapping the given MPSC sender.
    pub fn new(sender: Sender<AppEvent>) -> Self {
        Self { sender }
    }

    /// Sends an `AppEvent` directly across the channel.
    ///
    /// Returns `Err(SendError(event))` if the receiving half has hung up.
    pub fn send(&self, event: AppEvent) -> Result<(), SendError<AppEvent>> {
        self.sender.send(event)
    }

    /// Returns a reference to the underlying `mpsc::Sender`.
    pub fn inner(&self) -> &Sender<AppEvent> {
        &self.sender
    }

    // --- LOGGING METHODS ---

    /// Sends a structured log message at the specified log level.
    pub fn log(&self, level: LogLevel, module: impl Into<String>, message: impl Into<String>) {
        let _ = self.send(AppEvent::Log(LogMessage::new(level, module, message)));
    }

    /// Sends an Informational log message.
    pub fn info(&self, module: impl Into<String>, message: impl Into<String>) {
        self.log(LogLevel::Info, module, message);
    }

    /// Sends a Warning log message.
    pub fn warn(&self, module: impl Into<String>, message: impl Into<String>) {
        self.log(LogLevel::Warn, module, message);
    }

    /// Sends an Error log message.
    pub fn error(&self, module: impl Into<String>, message: impl Into<String>) {
        self.log(LogLevel::Error, module, message);
    }

    /// Sends a Success log message.
    pub fn success(&self, module: impl Into<String>, message: impl Into<String>) {
        self.log(LogLevel::Success, module, message);
    }

    /// Sends a Debug log message.
    pub fn debug(&self, module: impl Into<String>, message: impl Into<String>) {
        self.log(LogLevel::Debug, module, message);
    }

    // --- TELEMETRY & STATUS METHODS ---

    /// Updates the cumulative statistics snapshot in the TUI HUD.
    pub fn update_stats(&self, stats: StatUpdate) {
        let _ = self.send(AppEvent::Stats(stats));
    }

    /// Updates the status message of a specific worker thread.
    pub fn update_thread(&self, thread_id: usize, status: impl Into<String>) {
        let _ = self.send(AppEvent::ThreadStatus(WorkerStatus::new(thread_id, status)));
    }

    /// Convenience alias for `update_thread`.
    pub fn thread_status(&self, thread_id: usize, status: impl Into<String>) {
        self.update_thread(thread_id, status);
    }

    /// Emits overall progress counter for a long-running operation.
    pub fn progress(&self, current: usize, total: usize, message: Option<String>) {
        let _ = self.send(AppEvent::Progress {
            current,
            total,
            message,
        });
    }

    /// Emits real-time sanitization telemetry from a `SanitizerMetrics` struct.
    pub fn sanitizer_progress(&self, metrics: SanitizerMetrics) {
        let _ = self.send(AppEvent::SanitizerProgress(metrics));
    }

    /// Emits real-time sanitization telemetry from primitive values.
    pub fn sanitizer_metrics(&self, frame: u64, fps: f32, speed: impl Into<String>, pass: u8) {
        let _ = self.send(AppEvent::SanitizerProgress(SanitizerMetrics::new(
            frame, fps, speed, pass,
        )));
    }

    // --- LIFECYCLE METHODS ---

    /// Notifies that an operation has started.
    pub fn operation_started(&self, title: impl Into<String>) {
        let _ = self.send(AppEvent::OperationStarted(title.into()));
    }

    /// Notifies that an operation has completed.
    pub fn operation_finished(&self, summary: impl Into<String>) {
        let _ = self.send(AppEvent::OperationFinished(summary.into()));
    }

    /// Notifies that an operation has failed with an error.
    pub fn operation_failed(&self, operation: impl Into<String>, error: impl Into<String>) {
        let _ = self.send(AppEvent::OperationFailed(operation.into(), error.into()));
    }

    // --- DOMAIN & DATABASE PERSISTENCE METHODS ---

    /// Notifies that a healthy donor was found (triggers SQLite DB persistence).
    pub fn donor_found(&self, dna: impl Into<String>, moov_path: impl Into<String>) {
        let _ = self.send(AppEvent::DonorFound {
            dna: dna.into(),
            moov_path: moov_path.into(),
        });
    }

    /// Notifies that a repair succeeded with an algorithm (triggers SQLite DB reward).
    pub fn repair_success(
        &self,
        file_name: impl Into<String>,
        dna: impl Into<String>,
        algorithm: impl Into<String>,
    ) {
        let _ = self.send(AppEvent::RepairSuccess {
            file_name: file_name.into(),
            dna: dna.into(),
            algorithm: algorithm.into(),
        });
    }

    /// Notifies that a repair failed with an algorithm (triggers SQLite DB penalty).
    pub fn repair_failure(
        &self,
        file_name: impl Into<String>,
        dna: impl Into<String>,
        algorithm: impl Into<String>,
    ) {
        let _ = self.send(AppEvent::RepairFailure {
            file_name: file_name.into(),
            dna: dna.into(),
            algorithm: algorithm.into(),
        });
    }
}

impl From<Sender<AppEvent>> for EventSender {
    fn from(sender: Sender<AppEvent>) -> Self {
        Self::new(sender)
    }
}

/// Constructs a centralized event bus returning an `EventSender` and an `mpsc::Receiver<AppEvent>`.
///
/// Uses standard unbounded `mpsc::channel()` to guarantee non-blocking transmission
/// from multi-threaded Rayon workers while the TUI event loop drains events non-blockingly
/// via `rx.try_recv()`.
pub fn channel() -> (EventSender, Receiver<AppEvent>) {
    let (tx, rx) = mpsc::channel();
    (EventSender::new(tx), rx)
}

/// Convenience alias for `channel()`.
pub fn event_channel() -> (EventSender, Receiver<AppEvent>) {
    channel()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_sender_thread_safety() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        fn assert_clone<T: Clone>() {}

        assert_send::<EventSender>();
        assert_sync::<EventSender>();
        assert_clone::<EventSender>();
        assert_send::<AppEvent>();
    }

    #[test]
    fn test_logging_convenience_methods() {
        let (tx, rx) = channel();

        tx.info("SCANNER", "Scanning file.mp4");
        tx.warn("AUTOPILOT", "Heuristic low confidence");
        tx.error("SANITIZER", "FFmpeg exited with 1");
        tx.debug("ENGINE", "NAL unit 0x07 found");
        tx.success("POLIGON", "Mutation neutralised");

        let events: Vec<AppEvent> = rx.try_iter().collect();
        assert_eq!(events.len(), 5);

        if let AppEvent::Log(ref msg) = events[0] {
            assert_eq!(msg.level, LogLevel::Info);
            assert_eq!(msg.module, "SCANNER");
            assert_eq!(msg.message, "Scanning file.mp4");
        } else {
            panic!("Expected Log variant");
        }

        if let AppEvent::Log(ref msg) = events[1] {
            assert_eq!(msg.level, LogLevel::Warn);
            assert_eq!(msg.module, "AUTOPILOT");
        } else {
            panic!("Expected Log variant");
        }

        if let AppEvent::Log(ref msg) = events[2] {
            assert_eq!(msg.level, LogLevel::Error);
            assert_eq!(msg.module, "SANITIZER");
        } else {
            panic!("Expected Log variant");
        }

        if let AppEvent::Log(ref msg) = events[3] {
            assert_eq!(msg.level, LogLevel::Debug);
            assert_eq!(msg.module, "ENGINE");
        } else {
            panic!("Expected Log variant");
        }

        if let AppEvent::Log(ref msg) = events[4] {
            assert_eq!(msg.level, LogLevel::Success);
            assert_eq!(msg.module, "POLIGON");
        } else {
            panic!("Expected Log variant");
        }
    }

    #[test]
    fn test_telemetry_methods() {
        let (tx, rx) = channel();

        tx.update_thread(2, "Repairing frame");
        tx.update_stats(StatUpdate {
            files_scanned: 10,
            files_healthy: 8,
            files_broken: 2,
            files_repaired: 1,
            bytes_processed: 1048576,
            active_threads: 4,
        });
        tx.sanitizer_metrics(120, 30.5, "1.2x", 1);
        tx.progress(5, 10, Some("Halfway done".to_string()));

        let events: Vec<AppEvent> = rx.try_iter().collect();
        assert_eq!(events.len(), 4);

        assert_eq!(
            events[0],
            AppEvent::ThreadStatus(WorkerStatus::new(2, "Repairing frame"))
        );
        assert_eq!(
            events[1],
            AppEvent::Stats(StatUpdate {
                files_scanned: 10,
                files_healthy: 8,
                files_broken: 2,
                files_repaired: 1,
                bytes_processed: 1048576,
                active_threads: 4,
            })
        );
        assert_eq!(
            events[2],
            AppEvent::SanitizerProgress(SanitizerMetrics::new(120, 30.5, "1.2x", 1))
        );
        assert_eq!(
            events[3],
            AppEvent::Progress {
                current: 5,
                total: 10,
                message: Some("Halfway done".to_string()),
            }
        );
    }

    #[test]
    fn test_event_sender_silently_drops_when_receiver_closed() {
        let (tx, rx) = channel();
        drop(rx);
        // Must not panic even if receiver is dropped:
        tx.warn("TEST", "Receiver is gone");
        tx.update_stats(StatUpdate::default());
        tx.operation_started("test_op");
    }

    #[test]
    fn test_serialization_round_trip() {
        let stat = StatUpdate {
            files_scanned: 50,
            files_healthy: 40,
            files_broken: 10,
            files_repaired: 8,
            bytes_processed: 5000000,
            active_threads: 2,
        };
        let event = AppEvent::Stats(stat);
        let json = serde_json::to_string(&event).expect("Serialize to JSON failed");
        let deserialized: AppEvent = serde_json::from_str(&json).expect("Deserialize from JSON failed");
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_log_level_formatting_and_badge() {
        assert_eq!(LogLevel::Debug.as_str(), "DEBUG");
        assert_eq!(LogLevel::Info.as_str(), "INFO");
        assert_eq!(LogLevel::Success.as_str(), "SUCCESS");
        assert_eq!(LogLevel::Warn.as_str(), "WARN");
        assert_eq!(LogLevel::Error.as_str(), "ERROR");

        assert_eq!(LogLevel::Debug.badge(), "[DEBUG]  ");
        assert_eq!(LogLevel::Info.badge(), "[INFO]   ");
        assert_eq!(LogLevel::Success.badge(), "[SUCCESS]");
        assert_eq!(LogLevel::Warn.badge(), "[WARN]   ");
        assert_eq!(LogLevel::Error.badge(), "[ERROR]  ");

        assert_eq!(format!("{}", LogLevel::Info), "INFO");
    }

    #[test]
    fn test_stat_update_repair_rate() {
        let stats_zero_broken = StatUpdate::new(10, 10, 0, 0, 1024, 1);
        assert_eq!(stats_zero_broken.repair_rate(), 100.0);

        let stats_half_repaired = StatUpdate::new(10, 6, 4, 2, 1024, 1);
        assert_eq!(stats_half_repaired.repair_rate(), 50.0);
    }

    #[test]
    fn test_worker_status_from_conversions() {
        let ws1: WorkerStatus = (1usize, "Scanning").into();
        assert_eq!(ws1.thread_id, 1);
        assert_eq!(ws1.status, "Scanning");

        let ws2: WorkerStatus = (2usize, String::from("Repairing")).into();
        assert_eq!(ws2.thread_id, 2);
        assert_eq!(ws2.status, "Repairing");
    }

    #[test]
    fn test_lifecycle_and_domain_helpers() {
        let (tx, rx) = event_channel();

        tx.operation_started("Full Scan");
        tx.operation_finished("Scan completed successfully");
        tx.operation_failed("Sanitize", "File not found");
        tx.donor_found("dna123", "/path/to/moov");
        tx.repair_success("corrupt.mp4", "dna123", "recontainer");
        tx.repair_failure("broken.mp4", "dna456", "native");

        let events: Vec<AppEvent> = rx.try_iter().collect();
        assert_eq!(events.len(), 6);

        assert_eq!(events[0], AppEvent::OperationStarted("Full Scan".into()));
        assert_eq!(events[1], AppEvent::OperationFinished("Scan completed successfully".into()));
        assert_eq!(events[2], AppEvent::OperationFailed("Sanitize".into(), "File not found".into()));
        assert_eq!(events[3], AppEvent::DonorFound { dna: "dna123".into(), moov_path: "/path/to/moov".into() });
        assert_eq!(events[4], AppEvent::RepairSuccess { file_name: "corrupt.mp4".into(), dna: "dna123".into(), algorithm: "recontainer".into() });
        assert_eq!(events[5], AppEvent::RepairFailure { file_name: "broken.mp4".into(), dna: "dna456".into(), algorithm: "native".into() });
    }

    #[test]
    fn test_log_message_constructors() {
        let msg = LogMessage::info("MOD", "text");
        assert_eq!(msg.level, LogLevel::Info);
        assert_eq!(msg.module, "MOD");
        assert_eq!(msg.message, "text");
        assert_eq!(msg.formatted_time().len(), 8); // "HH:MM:SS"

        let msg_warn = LogMessage::warn("MOD", "w");
        assert_eq!(msg_warn.level, LogLevel::Warn);

        let msg_err = LogMessage::error("MOD", "e");
        assert_eq!(msg_err.level, LogLevel::Error);

        let msg_succ = LogMessage::success("MOD", "s");
        assert_eq!(msg_succ.level, LogLevel::Success);

        let msg_dbg = LogMessage::debug("MOD", "d");
        assert_eq!(msg_dbg.level, LogLevel::Debug);
    }
}
