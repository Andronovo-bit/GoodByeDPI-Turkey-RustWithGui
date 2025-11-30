//! Error types for gdpi-core
//!
//! Centralized error handling using `thiserror` for ergonomic error definitions.

use std::net::IpAddr;
use thiserror::Error;

/// Main error type for gdpi-core operations
#[derive(Error, Debug)]
pub enum Error {
    /// Packet parsing failed
    #[error("Packet parsing error: {message}")]
    PacketParse {
        /// Detailed error message
        message: String,
        /// Offset in packet where error occurred
        offset: Option<usize>,
    },

    /// Packet is too small to process
    #[error("Packet too small: expected at least {expected} bytes, got {actual}")]
    PacketTooSmall {
        /// Minimum expected size
        expected: usize,
        /// Actual packet size
        actual: usize,
    },

    /// Strategy execution failed
    #[error("Strategy '{strategy}' failed: {message}")]
    Strategy {
        /// Name of the strategy that failed
        strategy: &'static str,
        /// Error message
        message: String,
    },

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Configuration file not found
    #[error("Configuration file not found: {path}")]
    ConfigNotFound {
        /// Path to the missing config file
        path: String,
    },

    /// Invalid configuration value
    #[error("Invalid configuration value for '{key}': {message}")]
    ConfigValue {
        /// Configuration key
        key: String,
        /// Error message
        message: String,
    },

    /// DNS resolution failed
    #[error("DNS resolution failed for '{domain}': {reason}")]
    DnsResolution {
        /// Domain that failed to resolve
        domain: String,
        /// Failure reason
        reason: String,
    },

    /// Connection tracking error
    #[error("Connection tracking error: {0}")]
    ConnTrack(String),

    /// Connection tracking table is full
    #[error("Connection tracking table overflow: max {max_entries} entries")]
    ConnTrackOverflow {
        /// Maximum allowed entries
        max_entries: usize,
    },

    /// Invalid IP address
    #[error("Invalid IP address: {addr}")]
    InvalidIpAddr {
        /// The invalid address
        addr: String,
    },

    /// Invalid port number
    #[error("Invalid port number: {port} (must be 1-65535)")]
    InvalidPort {
        /// The invalid port
        port: u32,
    },

    /// Invalid TTL value
    #[error("Invalid TTL value: {ttl} (must be 1-255)")]
    InvalidTtl {
        /// The invalid TTL
        ttl: u16,
    },

    /// Checksum calculation failed
    #[error("Checksum calculation failed: {0}")]
    Checksum(String),

    /// TLS SNI extraction failed
    #[error("Failed to extract SNI from TLS ClientHello")]
    SniExtraction,

    /// HTTP header parsing failed
    #[error("HTTP header parsing failed: {0}")]
    HttpParse(String),

    /// Blacklist file error
    #[error("Blacklist file error for '{path}': {message}")]
    Blacklist {
        /// Path to the blacklist file
        path: String,
        /// Error message
        message: String,
    },

    /// I/O error wrapper
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// UTF-8 conversion error
    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    /// TOML parsing error
    #[error("TOML parsing error: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// Hex decoding error
    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

/// Result type alias using our Error type
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Create a packet parse error
    pub fn packet_parse(message: impl Into<String>) -> Self {
        Self::PacketParse {
            message: message.into(),
            offset: None,
        }
    }

    /// Create a packet parse error with offset
    pub fn packet_parse_at(message: impl Into<String>, offset: usize) -> Self {
        Self::PacketParse {
            message: message.into(),
            offset: Some(offset),
        }
    }

    /// Create a strategy error
    pub fn strategy(strategy: &'static str, message: impl Into<String>) -> Self {
        Self::Strategy {
            strategy,
            message: message.into(),
        }
    }

    /// Create a config value error
    pub fn config_value(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ConfigValue {
            key: key.into(),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::packet_parse("Invalid header");
        assert!(err.to_string().contains("Invalid header"));

        let err = Error::strategy("fragmentation", "Buffer too small");
        assert!(err.to_string().contains("fragmentation"));
        assert!(err.to_string().contains("Buffer too small"));
    }

    #[test]
    fn test_error_with_offset() {
        let err = Error::packet_parse_at("Invalid byte", 42);
        match err {
            Error::PacketParse { offset, .. } => assert_eq!(offset, Some(42)),
            _ => panic!("Wrong error type"),
        }
    }
}
