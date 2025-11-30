//! Platform-specific errors

use thiserror::Error;

/// Platform-specific errors
#[derive(Error, Debug)]
pub enum PlatformError {
    /// Driver not found or not installed
    #[error("Driver not found: {0}")]
    DriverNotFound(String),

    /// Driver initialization failed
    #[error("Driver initialization failed: {0}")]
    DriverInitFailed(String),

    /// Filter syntax error
    #[error("Invalid filter syntax: {0}")]
    InvalidFilter(String),

    /// Packet capture error
    #[error("Capture error: {0}")]
    CaptureError(String),

    /// Packet injection error
    #[error("Injection error: {0}")]
    InjectionError(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Handle error
    #[error("Handle error: {0}")]
    HandleError(String),

    /// System error with code
    #[error("System error {code}: {message}")]
    SystemError {
        /// Error code
        code: u32,
        /// Error message
        message: String,
    },

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Platform result type
pub type Result<T> = std::result::Result<T, PlatformError>;
