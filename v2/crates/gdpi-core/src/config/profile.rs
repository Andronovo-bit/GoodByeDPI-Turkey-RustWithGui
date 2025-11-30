//! Configuration profiles for different modes and regions
//!
//! Maps legacy CLI modes (-1 to -9) to modern configuration.

use super::*;
use serde::{Deserialize, Serialize};

/// Predefined configuration profiles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Mode 1: Most compatible (-p -r -s -f 2 -k 2 -n -e 2)
    Mode1,
    /// Mode 2: Better HTTPS speed (-p -r -s -f 2 -k 2 -n -e 40)
    Mode2,
    /// Mode 3: Better HTTP/HTTPS speed (-p -r -s -e 40)
    Mode3,
    /// Mode 4: Best speed (-p -r -s)
    Mode4,
    /// Mode 5: Auto TTL + reverse frag
    Mode5,
    /// Mode 6: Wrong SEQ + reverse frag
    Mode6,
    /// Mode 7: Wrong checksum + reverse frag
    Mode7,
    /// Mode 8: Wrong SEQ + wrong checksum
    Mode8,
    /// Mode 9: Full mode with QUIC block (default)
    Mode9,
    /// Turkey-optimized profile
    Turkey,
    /// Custom profile
    Custom,
}

impl Profile {
    /// Convert profile to full configuration
    pub fn into_config(self) -> Config {
        let mut config = Config::default();

        match self {
            Profile::Mode1 => {
                // -p -r -s -f 2 -k 2 -n -e 2 (most compatible mode)
                config.strategies.passive_dpi.enabled = true;
                config.strategies.header_mangle.enabled = true;
                config.strategies.header_mangle.host_replace = true;
                config.strategies.header_mangle.host_remove_space = true;
                config.strategies.fragmentation.enabled = true;
                config.strategies.fragmentation.http_size = 2;
                config.strategies.fragmentation.https_size = 2;
                config.strategies.fragmentation.http_persistent = true;
                config.strategies.fragmentation.persistent_nowait = true;
                config.strategies.fragmentation.native_split = false;
                config.strategies.fake_packet.enabled = false;
                config.strategies.quic_block.enabled = false;
            }
            Profile::Mode2 => {
                // -p -r -s -f 2 -k 2 -n -e 40 (better HTTPS speed)
                config.strategies.passive_dpi.enabled = true;
                config.strategies.header_mangle.enabled = true;
                config.strategies.header_mangle.host_replace = true;
                config.strategies.header_mangle.host_remove_space = true;
                config.strategies.fragmentation.enabled = true;
                config.strategies.fragmentation.http_size = 2;
                config.strategies.fragmentation.https_size = 40;
                config.strategies.fragmentation.http_persistent = true;
                config.strategies.fragmentation.persistent_nowait = true;
                config.strategies.fragmentation.native_split = false;
                config.strategies.fake_packet.enabled = false;
                config.strategies.quic_block.enabled = false;
            }
            Profile::Mode3 => {
                // -p -r -s -e 40 (better HTTP/HTTPS speed)
                config.strategies.passive_dpi.enabled = true;
                config.strategies.header_mangle.enabled = true;
                config.strategies.header_mangle.host_replace = true;
                config.strategies.header_mangle.host_remove_space = true;
                config.strategies.fragmentation.enabled = true;
                config.strategies.fragmentation.http_size = 0; // disabled for HTTP
                config.strategies.fragmentation.https_size = 40;
                config.strategies.fragmentation.native_split = false;
                config.strategies.fake_packet.enabled = false;
                config.strategies.quic_block.enabled = false;
            }
            Profile::Mode4 => {
                // -p -r -s (best speed, minimal processing)
                config.strategies.passive_dpi.enabled = true;
                config.strategies.header_mangle.enabled = true;
                config.strategies.header_mangle.host_replace = true;
                config.strategies.header_mangle.host_remove_space = true;
                config.strategies.fragmentation.enabled = false;
                config.strategies.fake_packet.enabled = false;
                config.strategies.quic_block.enabled = false;
            }
            Profile::Mode5 => {
                // -f 2 -e 2 --auto-ttl --reverse-frag --max-payload
                config.strategies.fragmentation.enabled = true;
                config.strategies.fragmentation.http_size = 2;
                config.strategies.fragmentation.https_size = 2;
                config.strategies.fragmentation.native_split = true;
                config.strategies.fragmentation.reverse_order = true;
                config.strategies.fragmentation.http_persistent = true;
                config.strategies.fragmentation.persistent_nowait = true;
                config.strategies.fake_packet.enabled = true;
                config.strategies.fake_packet.auto_ttl = Some(AutoTtlConfig::default());
                config.strategies.fake_packet.wrong_checksum = false;
                config.strategies.fake_packet.wrong_seq = false;
                config.performance.max_payload_size = 1200;
                config.strategies.quic_block.enabled = false;
            }
            Profile::Mode6 => {
                // -f 2 -e 2 --wrong-seq --reverse-frag --max-payload
                config.strategies.fragmentation.enabled = true;
                config.strategies.fragmentation.http_size = 2;
                config.strategies.fragmentation.https_size = 2;
                config.strategies.fragmentation.native_split = true;
                config.strategies.fragmentation.reverse_order = true;
                config.strategies.fragmentation.http_persistent = true;
                config.strategies.fragmentation.persistent_nowait = true;
                config.strategies.fake_packet.enabled = true;
                config.strategies.fake_packet.wrong_seq = true;
                config.strategies.fake_packet.wrong_checksum = false;
                config.performance.max_payload_size = 1200;
                config.strategies.quic_block.enabled = false;
            }
            Profile::Mode7 => {
                // -f 2 -e 2 --wrong-chksum --reverse-frag --max-payload
                config.strategies.fragmentation.enabled = true;
                config.strategies.fragmentation.http_size = 2;
                config.strategies.fragmentation.https_size = 2;
                config.strategies.fragmentation.native_split = true;
                config.strategies.fragmentation.reverse_order = true;
                config.strategies.fragmentation.http_persistent = true;
                config.strategies.fragmentation.persistent_nowait = true;
                config.strategies.fake_packet.enabled = true;
                config.strategies.fake_packet.wrong_checksum = true;
                config.strategies.fake_packet.wrong_seq = false;
                config.performance.max_payload_size = 1200;
                config.strategies.quic_block.enabled = false;
            }
            Profile::Mode8 => {
                // -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload
                config.strategies.fragmentation.enabled = true;
                config.strategies.fragmentation.http_size = 2;
                config.strategies.fragmentation.https_size = 2;
                config.strategies.fragmentation.native_split = true;
                config.strategies.fragmentation.reverse_order = true;
                config.strategies.fragmentation.http_persistent = true;
                config.strategies.fragmentation.persistent_nowait = true;
                config.strategies.fake_packet.enabled = true;
                config.strategies.fake_packet.wrong_checksum = true;
                config.strategies.fake_packet.wrong_seq = true;
                config.performance.max_payload_size = 1200;
                config.strategies.quic_block.enabled = false;
            }
            Profile::Mode9 => {
                // -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q (default)
                config.strategies.fragmentation.enabled = true;
                config.strategies.fragmentation.http_size = 2;
                config.strategies.fragmentation.https_size = 2;
                config.strategies.fragmentation.native_split = true;
                config.strategies.fragmentation.reverse_order = true;
                config.strategies.fragmentation.http_persistent = true;
                config.strategies.fragmentation.persistent_nowait = true;
                config.strategies.fake_packet.enabled = true;
                config.strategies.fake_packet.wrong_checksum = true;
                config.strategies.fake_packet.wrong_seq = true;
                config.performance.max_payload_size = 1200;
                config.strategies.quic_block.enabled = true;
            }
            Profile::Turkey => {
                // Turkey-optimized (Mode 9 + DNS redirect)
                config = Profile::Mode9.into_config();
                config.general.name = "Turkey".to_string();
                config.dns.enabled = true;
                config.dns.ipv4_upstream = Some(Ipv4Addr::new(77, 88, 8, 8)); // Yandex
                config.dns.ipv4_port = Some(53);
                config.dns.flush_cache_on_start = true;
            }
            Profile::Custom => {
                // Keep defaults, user will customize
            }
        }

        config
    }

    /// Get profile name
    pub fn name(&self) -> &'static str {
        match self {
            Profile::Mode1 => "mode1",
            Profile::Mode2 => "mode2",
            Profile::Mode3 => "mode3",
            Profile::Mode4 => "mode4",
            Profile::Mode5 => "mode5",
            Profile::Mode6 => "mode6",
            Profile::Mode7 => "mode7",
            Profile::Mode8 => "mode8",
            Profile::Mode9 => "mode9",
            Profile::Turkey => "turkey",
            Profile::Custom => "custom",
        }
    }

    /// Get profile description
    pub fn description(&self) -> &'static str {
        match self {
            Profile::Mode1 => "Most compatible mode (legacy)",
            Profile::Mode2 => "Better HTTPS speed (legacy)",
            Profile::Mode3 => "Better HTTP/HTTPS speed (legacy)",
            Profile::Mode4 => "Best speed, minimal processing (legacy)",
            Profile::Mode5 => "Modern: Auto-TTL + reverse fragmentation",
            Profile::Mode6 => "Modern: Wrong SEQ + reverse fragmentation",
            Profile::Mode7 => "Modern: Wrong checksum + reverse fragmentation",
            Profile::Mode8 => "Modern: Wrong SEQ + wrong checksum",
            Profile::Mode9 => "Modern: Full mode with QUIC blocking (default)",
            Profile::Turkey => "Turkey optimized with DNS redirection",
            Profile::Custom => "Custom configuration",
        }
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for Profile {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "1" | "mode1" => Ok(Profile::Mode1),
            "2" | "mode2" => Ok(Profile::Mode2),
            "3" | "mode3" => Ok(Profile::Mode3),
            "4" | "mode4" => Ok(Profile::Mode4),
            "5" | "mode5" => Ok(Profile::Mode5),
            "6" | "mode6" => Ok(Profile::Mode6),
            "7" | "mode7" => Ok(Profile::Mode7),
            "8" | "mode8" => Ok(Profile::Mode8),
            "9" | "mode9" | "default" => Ok(Profile::Mode9),
            "turkey" | "tr" => Ok(Profile::Turkey),
            "custom" => Ok(Profile::Custom),
            _ => Err(Error::config_value("profile", format!("Unknown profile: {s}"))),
        }
    }
}

impl Profile {
    /// Parse profile from name string
    pub fn from_name(name: &str) -> Result<Self> {
        name.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode9_config() {
        let config = Profile::Mode9.into_config();
        assert!(config.strategies.fragmentation.enabled);
        assert!(config.strategies.fake_packet.enabled);
        assert!(config.strategies.quic_block.enabled);
        assert!(config.strategies.fake_packet.wrong_checksum);
        assert!(config.strategies.fake_packet.wrong_seq);
    }

    #[test]
    fn test_turkey_profile() {
        let config = Profile::Turkey.into_config();
        assert!(config.dns.enabled);
        assert_eq!(config.dns.ipv4_upstream, Some(Ipv4Addr::new(77, 88, 8, 8)));
    }

    #[test]
    fn test_profile_parse() {
        assert_eq!("9".parse::<Profile>().unwrap(), Profile::Mode9);
        assert_eq!("turkey".parse::<Profile>().unwrap(), Profile::Turkey);
        assert!("invalid".parse::<Profile>().is_err());
    }
}
