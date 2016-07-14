//! Logging and error handling module for nt_mapper_rust
//!
//! Provides structured logging with multiple output targets,
//! configurable log levels, and integration with the error handling system.

use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{MapperError, NtStatus};

/// Log severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Fatal = 5,
    Off = 6,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Fatal => "FATAL",
            LogLevel::Off => "OFF",
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => LogLevel::Trace,
            1 => LogLevel::Debug,
            2 => LogLevel::Info,
            3 => LogLevel::Warn,
            4 => LogLevel::Error,
            5 => LogLevel::Fatal,
            _ => LogLevel::Off,
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single log record containing message and metadata
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub level: LogLevel,
    pub message: String,
    pub timestamp: u64,
    pub module_path: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

impl LogRecord {
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            level,
            message: message.into(),
            timestamp,
            module_path: None,
            file: None,
            line: None,
        }
    }

    pub fn with_location(mut self, module: &str, file: &str, line: u32) -> Self {
        self.module_path = Some(module.to_string());
        self.file = Some(file.to_string());
        self.line = Some(line);
        self
    }
}

/// Trait for log output targets (Strategy pattern)
pub trait LogTarget: Send + Sync {
    fn write(&self, record: &LogRecord) -> Result<(), LogError>;
    fn flush(&self) -> Result<(), LogError>;
    fn name(&self) -> &str;
}

/// Console output target
pub struct ConsoleTarget {
    use_stderr_for_errors: bool,
    colored: bool,
}

impl ConsoleTarget {
    pub fn new() -> Self {
        Self {
            use_stderr_for_errors: true,
            colored: true,
        }
    }

    pub fn with_options(use_stderr_for_errors: bool, colored: bool) -> Self {
        Self {
            use_stderr_for_errors,
            colored,
        }
    }

    fn format_record(&self, record: &LogRecord) -> String {
        let level_str = if self.colored {
            match record.level {
                LogLevel::Trace => "\x1b[90mTRACE\x1b[0m",
                LogLevel::Debug => "\x1b[36mDEBUG\x1b[0m",
                LogLevel::Info => "\x1b[32mINFO\x1b[0m",
                LogLevel::Warn => "\x1b[33mWARN\x1b[0m",
                LogLevel::Error => "\x1b[31mERROR\x1b[0m",
                LogLevel::Fatal => "\x1b[35mFATAL\x1b[0m",
                LogLevel::Off => "OFF",
            }
        } else {
            record.level.as_str()
        };

        let location = match (&record.file, record.line) {
            (Some(file), Some(line)) => format!(" [{}:{}]", file, line),
            _ => String::new(),
        };

        format!(
            "[{:013}] {:5}{} {}",
            record.timestamp, level_str, location, record.message
        )
    }
}

impl Default for ConsoleTarget {
    fn default() -> Self {
        Self::new()
    }
}

impl LogTarget for ConsoleTarget {
    fn write(&self, record: &LogRecord) -> Result<(), LogError> {
        let formatted = self.format_record(record);

        if self.use_stderr_for_errors && record.level >= LogLevel::Error {
            writeln!(io::stderr(), "{}", formatted).map_err(|e| LogError::IoError(e.to_string()))?;
        } else {
            writeln!(io::stdout(), "{}", formatted).map_err(|e| LogError::IoError(e.to_string()))?;
        }

        Ok(())
    }

    fn flush(&self) -> Result<(), LogError> {
        io::stdout()
            .flush()
            .map_err(|e| LogError::IoError(e.to_string()))?;
        io::stderr()
            .flush()
            .map_err(|e| LogError::IoError(e.to_string()))?;
        Ok(())
    }

    fn name(&self) -> &str {
        "console"
    }
}

/// Memory buffer target for testing or deferred output
pub struct MemoryTarget {
    buffer: Mutex<Vec<LogRecord>>,
    capacity: usize,
}

impl MemoryTarget {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Mutex::new(Vec::with_capacity(capacity)),
            capacity,
        }
    }

    pub fn drain(&self) -> Vec<LogRecord> {
        let mut buffer = self.buffer.lock().unwrap();
        std::mem::take(&mut *buffer)
    }

    pub fn records(&self) -> Vec<LogRecord> {
        self.buffer.lock().unwrap().clone()
    }
}

impl LogTarget for MemoryTarget {
    fn write(&self, record: &LogRecord) -> Result<(), LogError> {
        let mut buffer = self.buffer.lock().unwrap();

        if buffer.len() >= self.capacity {
            buffer.remove(0);
        }

        buffer.push(record.clone());
        Ok(())
    }

    fn flush(&self) -> Result<(), LogError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "memory"
    }
}

/// Observer trait for log events
pub trait LogObserver: Send + Sync {
    fn on_log(&self, record: &LogRecord);
    fn on_error(&self, error: &LogError);
}

/// Logging errors
#[derive(Debug, Clone)]
pub enum LogError {
    IoError(String),
    NotInitialized,
    TargetNotFound(String),
    LockPoisoned,
    InvalidConfiguration(String),
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogError::IoError(msg) => write!(f, "I/O error: {}", msg),
            LogError::NotInitialized => write!(f, "Logger not initialized"),
            LogError::TargetNotFound(name) => write!(f, "Log target not found: {}", name),
            LogError::LockPoisoned => write!(f, "Lock poisoned"),
            LogError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
        }
    }
}

impl std::error::Error for LogError {}

impl From<LogError> for MapperError {
    fn from(err: LogError) -> Self {
        MapperError::new(NtStatus::from_raw(0xC0000001), err.to_string())
    }
}

/// Logger configuration
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    pub min_level: LogLevel,
    pub include_location: bool,
    pub async_logging: bool,
    pub buffer_size: usize,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            min_level: LogLevel::Info,
            include_location: true,
            async_logging: false,
            buffer_size: 1024,
        }
    }
}

/// Global logger state
static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static LOGGER_LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Info as u8);

/// Thread-safe logger instance (Factory pattern for targets)
pub struct Logger {
    targets: RwLock<Vec<Arc<dyn LogTarget>>>,
    observers: RwLock<Vec<Arc<dyn LogObserver>>>,
    config: RwLock<LoggerConfig>,
}

impl Logger {
    /// Create a new logger instance
    pub fn new(config: LoggerConfig) -> Self {
        LOGGER_LEVEL.store(config.min_level as u8, Ordering::SeqCst);

        Self {
            targets: RwLock::new(Vec::new()),
            observers: RwLock::new(Vec::new()),
            config: RwLock::new(config),
        }
    }

    /// Initialize with default console target
    pub fn with_console() -> Self {
        let logger = Self::new(LoggerConfig::default());
        logger.add_target(Arc::new(ConsoleTarget::new()));
        logger
    }

    /// Add a log target
    pub fn add_target(&self, target: Arc<dyn LogTarget>) {
        let mut targets = self.targets.write().unwrap();
        targets.push(target);
    }

    /// Remove a target by name
    pub fn remove_target(&self, name: &str) -> bool {
        let mut targets = self.targets.write().unwrap();
        let initial_len = targets.len();
        targets.retain(|t| t.name() != name);
        targets.len() < initial_len
    }

    /// Add an observer
    pub fn add_observer(&self, observer: Arc<dyn LogObserver>) {
        let mut observers = self.observers.write().unwrap();
        observers.push(observer);
    }

    /// Log a record
    pub fn log(&self, record: LogRecord) {
        let config = self.config.read().unwrap();

        if record.level < config.min_level {
            return;
        }

        drop(config);

        // Notify observers
        {
            let observers = self.observers.read().unwrap();
            for observer in observers.iter() {
                observer.on_log(&record);
            }
        }

        // Write to targets
        let targets = self.targets.read().unwrap();
        for target in targets.iter() {
            if let Err(e) = target.write(&record) {
                let observers = self.observers.read().unwrap();
                for observer in observers.iter() {
                    observer.on_error(&e);
                }
            }
        }
    }

    /// Log with level
    pub fn log_message(&self, level: LogLevel, message: impl Into<String>) {
        self.log(LogRecord::new(level, message));
    }

    /// Convenience methods
    pub fn trace(&self, message: impl Into<String>) {
        self.log_message(LogLevel::Trace, message);
    }

    pub fn debug(&self, message: impl Into<String>) {
        self.log_message(LogLevel::Debug, message);
    }

    pub fn info(&self, message: impl Into<String>) {
        self.log_message(LogLevel::Info, message);
    }

    pub fn warn(&self, message: impl Into<String>) {
        self.log_message(LogLevel::Warn, message);
    }

    pub fn error(&self, message: impl Into<String>) {
        self.log_message(LogLevel::Error, message);
    }

    pub fn fatal(&self, message: impl Into<String>) {
        self.log_message(LogLevel::Fatal, message);
    }

    /// Set minimum log level
    pub fn set_level(&self, level: LogLevel) {
        let mut config = self.config.write().unwrap();
        config.min_level = level;
        LOGGER_LEVEL.store(level as u8, Ordering::SeqCst);
    }

    /// Get current log level
    pub fn level(&self) -> LogLevel {
        LogLevel::from_u8(LOGGER_LEVEL.load(Ordering::SeqCst))
    }

    /// Flush all targets
    pub fn flush(&self) -> Result<(), LogError> {
        let targets = self.targets.read().unwrap();
        for target in targets.iter() {
            target.flush()?;
        }
        Ok(())
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::with_console()
    }
}

// Global logger instance
lazy_static::lazy_static! {
    static ref GLOBAL_LOGGER: RwLock<Option<Arc<Logger>>> = RwLock::new(None);
}

/// Initialize the global logger
pub fn init(logger: Logger) -> Result<(), LogError> {
    let mut global = GLOBAL_LOGGER.write().map_err(|_| LogError::LockPoisoned)?;

    if global.is_some() {
        return Err(LogError::InvalidConfiguration(
            "Logger already initialized".to_string(),
        ));
    }

    *global = Some(Arc::new(logger));
    LOGGER_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

/// Initialize with default settings
pub fn init_default() -> Result<(), LogError> {
    init(Logger::with_console())
}

/// Get the global logger
pub fn logger() -> Result<Arc<Logger>, LogError> {
    let global = GLOBAL_LOGGER.read().map_err(|_| LogError::LockPoisoned)?;

    global.clone().ok_or(LogError::NotInitialized)
}

/// Check if logger is initialized
pub fn is_initialized() -> bool {
    LOGGER_INITIALIZED.load(Ordering::SeqCst)
}

/// Shutdown the logger
pub fn shutdown() -> Result<(), LogError> {
    let mut global = GLOBAL_LOGGER.write().map_err(|_| LogError::LockPoisoned)?;

    if let Some(logger) = global.take() {
        logger.flush()?;
    }

    LOGGER_INITIALIZED.store(false, Ordering::SeqCst);
    Ok(())
}

// Logging macros
#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => {
        if let Ok(logger) = $crate::logger::logger() {
            let record = $crate::logger::LogRecord::new(
                $crate::logger::LogLevel::Trace,
                format!($($arg)*)
            ).with_location(module_path!(), file!(), line!());
            logger.log(record);
        }
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if let Ok(logger) = $crate::logger::logger() {
            let record = $crate::logger::LogRecord::new(
                $crate::logger::LogLevel::Debug,
                format!($($arg)*)
            ).with_location(module_path!(), file!(), line!());
            logger.log(record);
        }
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if let Ok(logger) = $crate::logger::logger() {
            let record = $crate::logger::LogRecord::new(
                $crate::logger::LogLevel::Info,
                format!($($arg)*)
            ).with_location(module_path!(), file!(), line!());
            logger.log(record);
        }
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        if let Ok(logger) = $crate::logger::logger() {
            let record = $crate::logger::LogRecord::new(
                $crate::logger::LogLevel::Warn,
                format!($($arg)*)
            ).with_location(module_path!(), file!(), line!());
            logger.log(record);
        }
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if let Ok(logger) = $crate::logger::logger() {
            let record = $crate::logger::LogRecord::new(
                $crate::logger::LogLevel::Error,
                format!($($arg)*)
            ).with_location(module_path!(), file!(), line!());
            logger.log(record);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Fatal);
    }

    #[test]
    fn test_memory_target() {
        let target = MemoryTarget::new(10);
        let record = LogRecord::new(LogLevel::Info, "test message");

        target.write(&record).unwrap();

        let records = target.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, "test message");
    }

    #[test]
    fn test_memory_target_capacity() {
        let target = MemoryTarget::new(2);

        for i in 0..5 {
            let record = LogRecord::new(LogLevel::Info, format!("message {}", i));
            target.write(&record).unwrap();
        }

        let records = target.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].message, "message 3");
        assert_eq!(records[1].message, "message 4");
    }

    #[test]
    fn test_logger_filtering() {
        let mut config = LoggerConfig::default();
        config.min_level = LogLevel::Warn;

        let logger = Logger::new(config);
        let memory_target = Arc::new(MemoryTarget::new(100));
        logger.add_target(memory_target.clone());

        logger.debug("should be filtered");
        logger.info("should be filtered");
        logger.warn("should appear");
        logger.error("should appear");

        let records = memory_target.records();
        assert_eq!(records.len(), 2);
    }
}