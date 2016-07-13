//! nt_mapper_rust - System utilities and process management library
//!
//! This library provides cross-platform utilities for process management,
//! system information gathering, and resource monitoring.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod memory;
pub mod observer;
pub mod process;
pub mod strategy;
pub mod system;

use std::sync::atomic::{AtomicBool, Ordering};

/// Global initialization state
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Result type alias for library operations
pub type Result<T> = std::result::Result<T, error::MapperError>;

/// Initialize the library subsystems
///
/// # Errors
///
/// Returns an error if initialization fails or if already initialized
pub fn initialize() -> Result<()> {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(error::MapperError::AlreadyInitialized);
    }

    // Platform-specific initialization
    #[cfg(target_os = "windows")]
    {
        system::windows::init_subsystem()?;
    }

    #[cfg(target_os = "linux")]
    {
        system::linux::init_subsystem()?;
    }

    Ok(())
}

/// Check if the library has been initialized
#[must_use]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

/// Shutdown and cleanup library resources
pub fn shutdown() {
    if INITIALIZED
        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        #[cfg(target_os = "windows")]
        {
            system::windows::cleanup_subsystem();
        }

        #[cfg(target_os = "linux")]
        {
            system::linux::cleanup_subsystem();
        }
    }
}

/// Error types for the library
pub mod error {
    use std::fmt;
    use std::io;

    /// NT Status code representation for Windows API compatibility
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct NtStatus(i32);

    impl NtStatus {
        /// Success status
        pub const SUCCESS: Self = Self(0);
        /// Access denied status
        pub const ACCESS_DENIED: Self = Self(-1_073_741_790); // 0xC0000022
        /// Invalid handle status
        pub const INVALID_HANDLE: Self = Self(-1_073_741_816); // 0xC0000008
        /// Invalid parameter status
        pub const INVALID_PARAMETER: Self = Self(-1_073_741_811); // 0xC000000D
        /// Not found status
        pub const NOT_FOUND: Self = Self(-1_073_741_772); // 0xC0000034
        /// Buffer too small status
        pub const BUFFER_TOO_SMALL: Self = Self(-1_073_741_789); // 0xC0000023
        /// Insufficient resources status
        pub const INSUFFICIENT_RESOURCES: Self = Self(-1_073_741_670); // 0xC000009A

        /// Create a new `NtStatus` from a raw value
        #[must_use]
        pub const fn from_raw(value: i32) -> Self {
            Self(value)
        }

        /// Get the raw status value
        #[must_use]
        pub const fn raw(self) -> i32 {
            self.0
        }

        /// Check if the status indicates success
        #[must_use]
        pub const fn is_success(self) -> bool {
            self.0 >= 0
        }

        /// Check if the status indicates an error
        #[must_use]
        pub const fn is_error(self) -> bool {
            self.0 < 0
        }

        /// Convert to a human-readable description
        #[must_use]
        pub fn description(self) -> &'static str {
            match self {
                Self::SUCCESS => "Operation completed successfully",
                Self::ACCESS_DENIED => "Access denied",
                Self::INVALID_HANDLE => "Invalid handle",
                Self::INVALID_PARAMETER => "Invalid parameter",
                Self::NOT_FOUND => "Object not found",
                Self::BUFFER_TOO_SMALL => "Buffer too small",
                Self::INSUFFICIENT_RESOURCES => "Insufficient resources",
                _ => "Unknown status code",
            }
        }
    }

    impl fmt::Display for NtStatus {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "0x{:08X}: {}", self.0 as u32, self.description())
        }
    }

    impl From<i32> for NtStatus {
        fn from(value: i32) -> Self {
            Self::from_raw(value)
        }
    }

    impl From<NtStatus> for i32 {
        fn from(status: NtStatus) -> Self {
            status.raw()
        }
    }

    /// Primary error type for all library operations
    #[derive(Debug)]
    pub enum MapperError {
        /// Library has already been initialized
        AlreadyInitialized,
        /// Library has not been initialized
        NotInitialized,
        /// NT status code error from system calls
        NtStatusError(NtStatus),
        /// Standard I/O error
        IoError(io::Error),
        /// Process not found by ID or name
        ProcessNotFound {
            /// Identifier used in the search
            identifier: String,
        },
        /// Invalid process handle
        InvalidHandle,
        /// Permission denied for the requested operation
        PermissionDenied {
            /// Description of the denied operation
            operation: String,
        },
        /// Memory operation failed
        MemoryError {
            /// Address where the error occurred
            address: usize,
            /// Description of the memory operation
            operation: String,
        },
        /// Resource allocation failure
        ResourceExhausted {
            /// Type of resource that was exhausted
            resource: String,
        },
        /// Invalid argument provided
        InvalidArgument {
            /// Name of the invalid argument
            name: String,
            /// Reason why it's invalid
            reason: String,
        },
        /// Operation timed out
        Timeout {
            /// Duration in milliseconds
            duration_ms: u64,
        },
        /// Platform-specific error
        PlatformError {
            /// Platform identifier
            platform: String,
            /// Error code
            code: i32,
            /// Error message
            message: String,
        },
        /// Generic internal error
        Internal(String),
    }

    impl MapperError {
        /// Create a new NT status error
        #[must_use]
        pub const fn from_nt_status(status: NtStatus) -> Self {
            Self::NtStatusError(status)
        }

        /// Create a process not found error
        #[must_use]
        pub fn process_not_found(identifier: impl Into<String>) -> Self {
            Self::ProcessNotFound {
                identifier: identifier.into(),
            }
        }

        /// Create a permission denied error
        #[must_use]
        pub fn permission_denied(operation: impl Into<String>) -> Self {
            Self::PermissionDenied {
                operation: operation.into(),
            }
        }

        /// Create a memory error
        #[must_use]
        pub fn memory_error(address: usize, operation: impl Into<String>) -> Self {
            Self::MemoryError {
                address,
                operation: operation.into(),
            }
        }

        /// Create an invalid argument error
        #[must_use]
        pub fn invalid_argument(name: impl Into<String>, reason: impl Into<String>) -> Self {
            Self::InvalidArgument {
                name: name.into(),
                reason: reason.into(),
            }
        }

        /// Check if this error is recoverable
        #[must_use]
        pub const fn is_recoverable(&self) -> bool {
            matches!(
                self,
                Self::Timeout { .. } | Self::ResourceExhausted { .. }
            )
        }
    }

    impl fmt::Display for MapperError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::AlreadyInitialized => write!(f, "Library already initialized"),
                Self::NotInitialized => write!(f, "Library not initialized"),
                Self::NtStatusError(status) => write!(f, "NT status error: {status}"),
                Self::IoError(err) => write!(f, "I/O error: {err}"),
                Self::ProcessNotFound { identifier } => {
                    write!(f, "Process not found: {identifier}")
                }
                Self::InvalidHandle => write!(f, "Invalid handle"),
                Self::PermissionDenied { operation } => {
                    write!(f, "Permission denied for operation: {operation}")
                }
                Self::MemoryError { address, operation } => {
                    write!(f, "Memory error at 0x{address:X} during {operation}")
                }
                Self::ResourceExhausted { resource } => {
                    write!(f, "Resource exhausted: {resource}")
                }
                Self::InvalidArgument { name, reason } => {
                    write!(f, "Invalid argument '{name}': {reason}")
                }
                Self::Timeout { duration_ms } => {
                    write!(f, "Operation timed out after {duration_ms}ms")
                }
                Self::PlatformError {
                    platform,
                    code,
                    message,
                } => {
                    write!(f, "Platform error [{platform}] (code {code}): {message}")
                }
                Self::Internal(msg) => write!(f, "Internal error: {msg}"),
            }
        }
    }

    impl std::error::Error for MapperError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::IoError(err) => Some(err),
                _ => None,
            }
        }
    }

    impl From<io::Error> for MapperError {
        fn from(err: io::Error) -> Self {
            Self::IoError(err)
        }
    }

    impl From<NtStatus> for MapperError {
        fn from(status: NtStatus) -> Self {
            Self::NtStatusError(status)
        }
    }

    /// Extension trait for converting `Result<T, MapperError>` to NT status
    pub trait ResultExt<T> {
        /// Convert to NT status, returning `NtStatus::SUCCESS` on `Ok`
        fn to_nt_status(&self) -> NtStatus;
    }

    impl<T> ResultExt<T> for std::result::Result<T, MapperError> {
        fn to_nt_status(&self) -> NtStatus {
            match self {
                Ok(_) => NtStatus::SUCCESS,
                Err(MapperError::NtStatusError(status)) => *status,
                Err(MapperError::PermissionDenied { .. }) => NtStatus::ACCESS_DENIED,
                Err(MapperError::InvalidHandle) => NtStatus::INVALID_HANDLE,
                Err(MapperError::InvalidArgument { .. }) => NtStatus::INVALID_PARAMETER,
                Err(MapperError::ProcessNotFound { .. }) => NtStatus::NOT_FOUND,
                Err(MapperError::ResourceExhausted { .. }) => NtStatus::INSUFFICIENT_RESOURCES,
                Err(_) => NtStatus::from_raw(-1),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nt_status_success() {
        let status = error::NtStatus::SUCCESS;
        assert!(status.is_success());
        assert!(!status.is_error());
        assert_eq!(status.raw(), 0);
    }

    #[test]
    fn test_nt_status_error() {
        let status = error::NtStatus::ACCESS_DENIED;
        assert!(!status.is_success());
        assert!(status.is_error());
    }

    #[test]
    fn test_mapper_error_display() {
        let err = error::MapperError::process_not_found("test_process");
        assert!(err.to_string().contains("test_process"));
    }

    #[test]
    fn test_error_conversion() {
        let status = error::NtStatus::INVALID_HANDLE;
        let err: error::MapperError = status.into();
        assert!(matches!(err, error::MapperError::NtStatusError(_)));
    }

    #[test]
    fn test_result_ext() {
        use error::ResultExt;

        let ok_result: Result<i32> = Ok(42);
        assert_eq!(ok_result.to_nt_status(), error::NtStatus::SUCCESS);

        let err_result: Result<i32> = Err(error::MapperError::InvalidHandle);
        assert_eq!(err_result.to_nt_status(), error::NtStatus::INVALID_HANDLE);
    }
}