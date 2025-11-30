//! Configuration management for GoodbyeDPI
//!
//! Provides a strongly-typed configuration system with TOML support
//! and profile-based presets for different regions/ISPs.

mod profile;

pub use profile::Profile;

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Active profile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,

    /// General application settings
    pub general: GeneralConfig,

    /// DNS redirection settings
    pub dns: DnsConfig,

    /// Strategy configurations
    pub strategies: StrategiesConfig,

    /// Blacklist/whitelist settings
    pub blacklist: BlacklistConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Performance tuning
    pub performance: PerformanceConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: None,
            general: GeneralConfig::default(),
            dns: DnsConfig::default(),
            strategies: StrategiesConfig::default(),
            blacklist: BlacklistConfig::default(),
            logging: LoggingConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|_| Error::ConfigNotFound {
            path: path.display().to_string(),
        })?;
        Self::from_toml(&content)
    }

    /// Parse configuration from TOML string
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content).map_err(Error::from)
    }

    /// Create configuration from a preset profile
    pub fn from_profile(profile: Profile) -> Self {
        profile.into_config()
    }

    /// Create configuration from legacy CLI mode (-1 through -9)
    pub fn from_legacy_mode(mode: u8) -> Result<Self> {
        match mode {
            1 => Ok(Self::from_profile(Profile::Mode1)),
            2 => Ok(Self::from_profile(Profile::Mode2)),
            3 => Ok(Self::from_profile(Profile::Mode3)),
            4 => Ok(Self::from_profile(Profile::Mode4)),
            5 => Ok(Self::from_profile(Profile::Mode5)),
            6 => Ok(Self::from_profile(Profile::Mode6)),
            7 => Ok(Self::from_profile(Profile::Mode7)),
            8 => Ok(Self::from_profile(Profile::Mode8)),
            9 => Ok(Self::from_profile(Profile::Mode9)),
            _ => Err(Error::config_value("mode", format!("Invalid mode: {mode}. Must be 1-9"))),
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate DNS settings
        if self.dns.enabled {
            if let Some(port) = self.dns.ipv4_port {
                if port == 0 {
                    return Err(Error::InvalidPort { port: port as u32 });
                }
            }
        }

        // Validate fragmentation sizes
        if self.strategies.fragmentation.enabled {
            let http_size = self.strategies.fragmentation.http_size;
            let https_size = self.strategies.fragmentation.https_size;
            
            if http_size == 0 || http_size > 65535 {
                return Err(Error::config_value(
                    "strategies.fragmentation.http_size",
                    "Must be between 1 and 65535",
                ));
            }
            if https_size == 0 || https_size > 65535 {
                return Err(Error::config_value(
                    "strategies.fragmentation.https_size",
                    "Must be between 1 and 65535",
                ));
            }
        }

        // Validate TTL settings
        if let Some(ttl) = self.strategies.fake_packet.ttl {
            if ttl == 0 {
                return Err(Error::InvalidTtl { ttl: ttl as u16 });
            }
        }

        Ok(())
    }

    /// Serialize to TOML string
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))
    }
}

/// General application settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Profile name
    pub name: String,
    /// Configuration version
    pub version: String,
    /// Auto-start with system
    pub auto_start: bool,
    /// Run as Windows service
    pub run_as_service: bool,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            version: "2.0".to_string(),
            auto_start: false,
            run_as_service: false,
        }
    }
}

/// DNS redirection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Enable DNS redirection
    pub enabled: bool,
    /// Primary DNS server (shortcut)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<std::net::IpAddr>,
    /// IPv4 upstream DNS server
    pub ipv4_upstream: Option<Ipv4Addr>,
    /// IPv4 DNS port
    pub ipv4_port: Option<u16>,
    /// IPv6 upstream DNS server
    pub ipv6_upstream: Option<Ipv6Addr>,
    /// IPv6 DNS port
    pub ipv6_port: Option<u16>,
    /// Flush DNS cache on start
    pub flush_cache_on_start: bool,
    /// Verbose DNS logging
    pub verbose: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: None,
            ipv4_upstream: None,
            ipv4_port: Some(53),
            ipv6_upstream: None,
            ipv6_port: Some(53),
            flush_cache_on_start: true,
            verbose: false,
        }
    }
}

/// All strategy configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StrategiesConfig {
    /// Fragmentation strategy
    pub fragmentation: FragmentationConfig,
    /// Fake packet strategy
    pub fake_packet: FakePacketConfig,
    /// Header manipulation strategy
    pub header_mangle: HeaderMangleConfig,
    /// QUIC blocking strategy
    pub quic_block: QuicBlockConfig,
    /// Passive DPI blocking
    pub passive_dpi: PassiveDpiConfig,

    // Convenience shortcuts (CLI compatibility)
    /// Block QUIC (shortcut)
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub block_quic: bool,
    /// Auto TTL (shortcut)
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub auto_ttl: bool,
    /// Fake TTL value (shortcut)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_ttl: Option<u8>,
    /// HTTP fragment position (shortcut)
    #[serde(default = "default_http_frag")]
    pub http_fragment_position: u32,
    /// HTTPS fragment position (shortcut)
    #[serde(default = "default_https_frag")]
    pub https_fragment_position: u32,
    /// Wrong checksum for fake (shortcut)
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fake_with_wrong_checksum: bool,
    /// Wrong seq for fake (shortcut)
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fake_with_wrong_seq: bool,
}

fn default_http_frag() -> u32 { 2 }
fn default_https_frag() -> u32 { 2 }

impl Default for StrategiesConfig {
    fn default() -> Self {
        Self {
            fragmentation: FragmentationConfig::default(),
            fake_packet: FakePacketConfig::default(),
            header_mangle: HeaderMangleConfig::default(),
            quic_block: QuicBlockConfig::default(),
            passive_dpi: PassiveDpiConfig::default(),
            block_quic: true,
            auto_ttl: false,
            fake_ttl: None,
            http_fragment_position: 2,
            https_fragment_position: 2,
            fake_with_wrong_checksum: true,
            fake_with_wrong_seq: true,
        }
    }
}

/// Fragmentation strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FragmentationConfig {
    /// Enable fragmentation
    pub enabled: bool,
    /// HTTP fragment size
    pub http_size: u16,
    /// HTTPS fragment size  
    pub https_size: u16,
    /// Use native TCP segmentation
    pub native_split: bool,
    /// Send fragments in reverse order
    pub reverse_order: bool,
    /// Fragment by SNI position
    pub by_sni: bool,
    /// HTTP persistent connection fragmentation
    pub http_persistent: bool,
    /// Don't wait for ACK in persistent mode
    pub persistent_nowait: bool,
}

impl Default for FragmentationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            http_size: 2,
            https_size: 2,
            native_split: true,
            reverse_order: true,
            by_sni: false,
            http_persistent: true,
            persistent_nowait: true,
        }
    }
}

/// Fake packet strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FakePacketConfig {
    /// Enable fake packets
    pub enabled: bool,
    /// Use wrong TCP checksum
    pub wrong_checksum: bool,
    /// Use wrong SEQ/ACK numbers
    pub wrong_seq: bool,
    /// Fixed TTL value (None = auto)
    pub ttl: Option<u8>,
    /// Auto TTL configuration
    pub auto_ttl: Option<AutoTtlConfig>,
    /// Minimum TTL hops
    pub min_ttl_hops: Option<u8>,
    /// Number of times to resend fake packets
    pub resend_count: u8,
    /// Custom fake payloads (hex encoded)
    pub custom_payloads: Vec<String>,
    /// SNI domains for fake TLS ClientHello
    pub fake_sni_domains: Vec<String>,
    /// Number of random fake packets to generate
    pub random_count: Option<u8>,
}

impl Default for FakePacketConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            wrong_checksum: true,
            wrong_seq: true,
            ttl: None,
            auto_ttl: None,
            min_ttl_hops: None,
            resend_count: 1,
            custom_payloads: Vec::new(),
            fake_sni_domains: Vec::new(),
            random_count: None,
        }
    }
}

/// Auto TTL configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoTtlConfig {
    /// First auto TTL parameter
    pub a1: u8,
    /// Second auto TTL parameter
    pub a2: u8,
    /// Maximum TTL
    pub max: u8,
}

impl Default for AutoTtlConfig {
    fn default() -> Self {
        Self {
            a1: 1,
            a2: 4,
            max: 10,
        }
    }
}

/// Header manipulation strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HeaderMangleConfig {
    /// Enable header manipulation
    pub enabled: bool,
    /// Replace "Host:" with "hoSt:"
    pub host_replace: bool,
    /// Remove space after Host:
    pub host_remove_space: bool,
    /// Mix case in Host header value
    pub host_mix_case: bool,
    /// Add space between method and URI
    pub additional_space: bool,
}

impl Default for HeaderMangleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host_replace: false,
            host_remove_space: false,
            host_mix_case: false,
            additional_space: false,
        }
    }
}

/// QUIC blocking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QuicBlockConfig {
    /// Enable QUIC/HTTP3 blocking
    pub enabled: bool,
}

impl Default for QuicBlockConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Passive DPI blocking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PassiveDpiConfig {
    /// Enable passive DPI blocking
    pub enabled: bool,
    /// IP ID values to filter
    pub ip_ids: Vec<u16>,
}

impl Default for PassiveDpiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ip_ids: Vec::new(),
        }
    }
}

/// Blacklist/whitelist configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BlacklistConfig {
    /// Enable blacklist filtering
    pub enabled: bool,
    /// Blacklist file paths
    pub files: Vec<String>,
    /// Allow connections without SNI when blacklist is enabled
    pub allow_no_sni: bool,
}

impl Default for BlacklistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            files: Vec::new(),
            allow_no_sni: false,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    /// Log file path (None = stdout only)
    pub file: Option<String>,
    /// Maximum log file size in MB
    pub max_size_mb: u32,
    /// Number of rotated files to keep
    pub rotate_count: u32,
    /// Enable JSON format logging
    pub json_format: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: None,
            max_size_mb: 10,
            rotate_count: 5,
            json_format: false,
        }
    }
}

/// Performance tuning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PerformanceConfig {
    /// Maximum payload size to process
    pub max_payload_size: u16,
    /// Number of worker threads (0 = auto)
    pub worker_threads: u8,
    /// Connection tracking table max entries
    pub conntrack_max_entries: usize,
    /// Connection tracking cleanup interval (seconds)
    pub conntrack_cleanup_interval: u32,
    /// Process HTTP on all ports (not just 80)
    pub http_all_ports: bool,
    /// Additional ports to process
    pub additional_ports: Vec<u16>,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_payload_size: 1200,
            worker_threads: 0,
            conntrack_max_entries: 10000,
            conntrack_cleanup_interval: 30,
            http_all_ports: false,
            additional_ports: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(!config.dns.enabled);
        assert!(config.strategies.fragmentation.enabled);
        assert_eq!(config.strategies.fragmentation.http_size, 2);
    }

    #[test]
    fn test_config_validation() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_toml_roundtrip() {
        let config = Config::default();
        let toml = config.to_toml().unwrap();
        let parsed = Config::from_toml(&toml).unwrap();
        assert_eq!(config.strategies.fragmentation.http_size, 
                   parsed.strategies.fragmentation.http_size);
    }

    #[test]
    fn test_legacy_mode() {
        let config = Config::from_legacy_mode(9).unwrap();
        assert!(config.strategies.fragmentation.enabled);
        assert!(config.strategies.quic_block.enabled);
    }
}
