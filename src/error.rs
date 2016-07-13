//! Custom error types for nt_mapper_rust
//!
//! This module provides a comprehensive error handling system built around
//! Windows NT status codes with ergonomic Rust integration.

use std::error::Error;
use std::fmt;

/// Windows NT Status code representation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct NtStatus(pub i32);

impl NtStatus {
    // Success codes
    pub const SUCCESS: NtStatus = NtStatus(0x00000000);
    pub const PENDING: NtStatus = NtStatus(0x00000103);

    // Information codes
    pub const INFO_LENGTH_MISMATCH: NtStatus = NtStatus(0xC0000004_u32 as i32);

    // Warning codes
    pub const BUFFER_OVERFLOW: NtStatus = NtStatus(0x80000005_u32 as i32);

    // Error codes
    pub const UNSUCCESSFUL: NtStatus = NtStatus(0xC0000001_u32 as i32);
    pub const NOT_IMPLEMENTED: NtStatus = NtStatus(0xC0000002_u32 as i32);
    pub const INVALID_HANDLE: NtStatus = NtStatus(0xC0000008_u32 as i32);
    pub const INVALID_PARAMETER: NtStatus = NtStatus(0xC000000D_u32 as i32);
    pub const NO_SUCH_FILE: NtStatus = NtStatus(0xC000000F_u32 as i32);
    pub const ACCESS_DENIED: NtStatus = NtStatus(0xC0000022_u32 as i32);
    pub const BUFFER_TOO_SMALL: NtStatus = NtStatus(0xC0000023_u32 as i32);
    pub const OBJECT_NAME_NOT_FOUND: NtStatus = NtStatus(0xC0000034_u32 as i32);
    pub const OBJECT_PATH_NOT_FOUND: NtStatus = NtStatus(0xC000003A_u32 as i32);
    pub const SHARING_VIOLATION: NtStatus = NtStatus(0xC0000043_u32 as i32);
    pub const INSUFFICIENT_RESOURCES: NtStatus = NtStatus(0xC000009A_u32 as i32);
    pub const NOT_SUPPORTED: NtStatus = NtStatus(0xC00000BB_u32 as i32);
    pub const PROCESS_NOT_IN_JOB: NtStatus = NtStatus(0xC0000188_u32 as i32);

    /// Creates a new NtStatus from a raw value
    #[inline]
    pub const fn from_raw(value: i32) -> Self {
        NtStatus(value)
    }

    /// Returns the raw status code value
    #[inline]
    pub const fn raw(&self) -> i32 {
        self.0
    }

    /// Checks if the status indicates success (severity = 0)
    #[inline]
    pub const fn is_success(&self) -> bool {
        self.0 >= 0
    }

    /// Checks if the status indicates an informational message (severity = 1)
    #[inline]
    pub const fn is_information(&self) -> bool {
        (self.0 as u32) >> 30 == 1
    }

    /// Checks if the status indicates a warning (severity = 2)
    #[inline]
    pub const fn is_warning(&self) -> bool {
        (self.0 as u32) >> 30 == 2
    }

    /// Checks if the status indicates an error (severity = 3)
    #[inline]
    pub const fn is_error(&self) -> bool {
        (self.0 as u32) >> 30 == 3
    }

    /// Extracts the facility code from the status
    #[inline]
    pub const fn facility(&self) -> u16 {
        ((self.0 as u32) >> 16 & 0x0FFF) as u16
    }

    /// Extracts the status code portion
    #[inline]
    pub const fn code(&self) -> u16 {
        (self.0 as u32 & 0xFFFF) as u16
    }

    /// Returns a human-readable description of the status
    pub fn description(&self) -> &'static str {
        match *self {
            Self::SUCCESS => "The operation completed successfully",
            Self::PENDING => "The operation is pending",
            Self::INFO_LENGTH_MISMATCH => "The specified information length does not match",
            Self::BUFFER_OVERFLOW => "Buffer overflow occurred",
            Self::UNSUCCESSFUL => "The operation was unsuccessful",
            Self::NOT_IMPLEMENTED => "The requested operation is not implemented",
            Self::INVALID_HANDLE => "The handle is invalid",
            Self::INVALID_PARAMETER => "An invalid parameter was passed",
            Self::NO_SUCH_FILE => "The file does not exist",
            Self::ACCESS_DENIED => "Access is denied",
            Self::BUFFER_TOO_SMALL => "The buffer is too small",
            Self::OBJECT_NAME_NOT_FOUND => "The object name was not found",
            Self::OBJECT_PATH_NOT_FOUND => "The object path was not found",
            Self::SHARING_VIOLATION => "A sharing violation occurred",
            Self::INSUFFICIENT_RESOURCES => "Insufficient system resources",
            Self::NOT_SUPPORTED => "The request is not supported",
            Self::PROCESS_NOT_IN_JOB => "The process is not in a job",
            _ => "Unknown status code",
        }
    }
}

impl fmt::Display for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NTSTATUS 0x{:08X}: {}", self.0 as u32, self.description())
    }
}

impl From<i32> for NtStatus {
    fn from(value: i32) -> Self {
        NtStatus(value)
    }
}

impl From<NtStatus> for i32 {
    fn from(status: NtStatus) -> Self {
        status.0
    }
}

/// Error category for classification and handling strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// System-level errors from NT APIs
    System,
    /// Memory allocation or mapping failures
    Memory,
    /// Process-related errors
    Process,
    /// Module or library loading errors
    Module,
    /// Permission or access control errors
    Permission,
    /// Invalid input or state errors
    Validation,
    /// I/O operation failures
    Io,
    /// Internal logic errors
    Internal,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => write!(f, "System"),
            Self::Memory => write!(f, "Memory"),
            Self::Process => write!(f, "Process"),
            Self::Module => write!(f, "Module"),
            Self::Permission => write!(f, "Permission"),
            Self::Validation => write!(f, "Validation"),
            Self::Io => write!(f, "I/O"),
            Self::Internal => write!(f, "Internal"),
        }
    }
}

/// Primary error type for the nt_mapper library
#[derive(Debug)]
pub struct MapperError {
    category: ErrorCategory,
    message: String,
    status: Option<NtStatus>,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl MapperError {
    /// Creates a new error with the specified category and message
    pub fn new<S: Into<String>>(category: ErrorCategory, message: S) -> Self {
        Self {
            category,
            message: message.into(),
            status: None,
            source: None,
        }
    }

    /// Creates an error from an NT status code
    pub fn from_status(status: NtStatus) -> Self {
        let category = match status {
            NtStatus::ACCESS_DENIED => ErrorCategory::Permission,
            NtStatus::INVALID_HANDLE | NtStatus::INVALID_PARAMETER => ErrorCategory::Validation,
            NtStatus::INSUFFICIENT_RESOURCES | NtStatus::BUFFER_TOO_SMALL => ErrorCategory::Memory,
            NtStatus::NO_SUCH_FILE | NtStatus::OBJECT_NAME_NOT_FOUND => ErrorCategory::Io,
            _ if status.is_error() => ErrorCategory::System,
            _ => ErrorCategory::Internal,
        };

        Self {
            category,
            message: status.description().to_string(),
            status: Some(status),
            source: None,
        }
    }

    /// Attaches an NT status code to this error
    pub fn with_status(mut self, status: NtStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Attaches a source error for chaining
    pub fn with_source<E>(mut self, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }

    /// Returns the error category
    #[inline]
    pub fn category(&self) -> ErrorCategory {
        self.category
    }

    /// Returns the associated NT status if present
    #[inline]
    pub fn status(&self) -> Option<NtStatus> {
        self.status
    }

    /// Checks if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self.category,
            ErrorCategory::Io | ErrorCategory::Memory | ErrorCategory::Process
        )
    }

    // Convenience constructors for common error types

    /// Creates a validation error
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::new(ErrorCategory::Validation, message)
    }

    /// Creates a permission error
    pub fn permission<S: Into<String>>(message: S) -> Self {
        Self::new(ErrorCategory::Permission, message)
    }

    /// Creates a process error
    pub fn process<S: Into<String>>(message: S) -> Self {
        Self::new(ErrorCategory::Process, message)
    }

    /// Creates a memory error
    pub fn memory<S: Into<String>>(message: S) -> Self {
        Self::new(ErrorCategory::Memory, message)
    }

    /// Creates a module error
    pub fn module<S: Into<String>>(message: S) -> Self {
        Self::new(ErrorCategory::Module, message)
    }

    /// Creates an internal error
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::new(ErrorCategory::Internal, message)
    }

    /// Creates an uninitialized library error
    pub fn not_initialized() -> Self {
        Self::new(
            ErrorCategory::Internal,
            "Library has not been initialized. Call initialize() first.",
        )
    }
}

impl fmt::Display for MapperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.category, self.message)?;
        if let Some(status) = self.status {
            write!(f, " ({})", status)?;
        }
        Ok(())
    }
}

impl Error for MapperError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn Error + 'static))
    }
}

impl From<NtStatus> for MapperError {
    fn from(status: NtStatus) -> Self {
        Self::from_status(status)
    }
}

impl From<std::io::Error> for MapperError {
    fn from(err: std::io::Error) -> Self {
        Self::new(ErrorCategory::Io, err.to_string()).with_source(err)
    }
}

impl From<std::ffi::NulError> for MapperError {
    fn from(err: std::ffi::NulError) -> Self {
        Self::new(ErrorCategory::Validation, "String contains null byte").with_source(err)
    }
}

/// Type alias for Results using MapperError
pub type Result<T> = std::result::Result<T, MapperError>;

/// Extension trait for converting NtStatus to Result
pub trait NtStatusExt {
    /// Converts to Result, returning Ok(()) for success codes
    fn to_result(self) -> Result<()>;

    /// Converts to Result with a custom success value
    fn to_result_with<T, F: FnOnce() -> T>(self, f: F) -> Result<T>;
}

impl NtStatusExt for NtStatus {
    fn to_result(self) -> Result<()> {
        if self.is_success() {
            Ok(())
        } else {
            Err(MapperError::from_status(self))
        }
    }

    fn to_result_with<T, F: FnOnce() -> T>(self, f: F) -> Result<T> {
        if self.is_success() {
            Ok(f())
        } else {
            Err(MapperError::from_status(self))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntstatus_severity() {
        assert!(NtStatus::SUCCESS.is_success());
        assert!(NtStatus::ACCESS_DENIED.is_error());
        assert!(NtStatus::BUFFER_OVERFLOW.is_warning());
    }

    #[test]
    fn test_error_creation() {
        let err = MapperError::validation("Invalid process ID");
        assert_eq!(err.category(), ErrorCategory::Validation);
        assert!(err.status().is_none());
    }

    #[test]
    fn test_status_to_result() {
        assert!(NtStatus::SUCCESS.to_result().is_ok());
        assert!(NtStatus::ACCESS_DENIED.to_result().is_err());
    }

    #[test]
    fn test_error_display() {
        let err = MapperError::from_status(NtStatus::ACCESS_DENIED);
        let display = format!("{}", err);
        assert!(display.contains("Permission"));
        assert!(display.contains("denied"));
    }
}