//! Packet fragmentation strategy
//!
//! Splits TCP packets into smaller fragments to evade DPI inspection.

use super::{Strategy, StrategyAction};
use crate::config::FragmentationConfig;
use crate::error::Result;
use crate::packet::{Packet, Direction};
use crate::pipeline::Context;
use tracing::instrument;

/// Fragmentation strategy for splitting packets
pub struct FragmentationStrategy {
    /// HTTP fragment size
    http_size: u16,
    /// HTTPS fragment size
    https_size: u16,
    /// Use native TCP segmentation
    native_split: bool,
    /// Send fragments in reverse order
    reverse_order: bool,
    /// Fragment by SNI position
    by_sni: bool,
    /// Enable for persistent HTTP connections
    http_persistent: bool,
}

impl FragmentationStrategy {
    /// Create a new fragmentation strategy with default settings
    pub fn new() -> Self {
        Self {
            http_size: 2,
            https_size: 2,
            native_split: true,
            reverse_order: true,
            by_sni: false,
            http_persistent: true,
        }
    }

    /// Create from configuration
    pub fn from_config(config: &FragmentationConfig) -> Self {
        Self {
            http_size: config.http_size,
            https_size: config.https_size,
            native_split: config.native_split,
            reverse_order: config.reverse_order,
            by_sni: config.by_sni,
            http_persistent: config.http_persistent,
        }
    }

    /// Get fragment size for this packet
    fn get_fragment_size(&self, packet: &Packet) -> u16 {
        if packet.dst_port == 80 || packet.src_port == 80 {
            self.http_size
        } else {
            self.https_size
        }
    }

    /// Find optimal fragment position for TLS (before SNI)
    fn find_sni_fragment_position(&self, packet: &Packet) -> Option<usize> {
        if !self.by_sni {
            return None;
        }

        let payload = packet.payload();
        if payload.len() < 44 {
            return None;
        }

        // Look for SNI extension in TLS ClientHello
        // SNI extension starts with 00 00 (extension type)
        for i in 0..payload.len().saturating_sub(10) {
            // SNI extension pattern check
            if payload[i] == 0x00 
                && payload[i + 1] == 0x00 
                && payload[i + 2] == 0x00 
            {
                // Found potential SNI, fragment just before it
                return Some(i);
            }
        }

        None
    }
}

impl Default for FragmentationStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for FragmentationStrategy {
    fn name(&self) -> &'static str {
        "fragmentation"
    }

    fn priority(&self) -> u8 {
        // Run after fake packets but before sending
        80
    }

    fn should_apply(&self, packet: &Packet, ctx: &Context) -> bool {
        // Don't fragment fake/decoy packets
        if packet.is_fake {
            tracing::trace!("Fragment: skipping fake packet");
            return false;
        }
        
        // Only apply to outbound TCP packets with data
        if !packet.is_outbound() {
            tracing::trace!("Fragment: not outbound");
            return false;
        }
        if !packet.is_tcp() {
            tracing::trace!("Fragment: not TCP");
            return false;
        }

        // Must have payload to fragment
        if packet.payload_len() == 0 {
            tracing::trace!("Fragment: no payload");
            return false;
        }

        // Check if it's HTTP or HTTPS traffic
        let is_http = packet.dst_port == 80;
        let is_https = packet.dst_port == 443;

        if !is_http && !is_https {
            tracing::trace!(dst_port = packet.dst_port, "Fragment: not HTTP/HTTPS port");
            return false;
        }

        // For HTTP, check if it looks like an HTTP request
        if is_http && !packet.is_http_request() {
            tracing::trace!("Fragment: port 80 but not HTTP request");
            return false;
        }

        // For HTTPS, check if it looks like TLS ClientHello
        if is_https && !packet.is_tls_client_hello() {
            return false;
        }

        // Check blacklist if enabled
        if ctx.blacklist_enabled {
            if let Some(hostname) = self.extract_hostname(packet) {
                if !ctx.is_blacklisted(&hostname) {
                    return false;
                }
            }
        }

        true
    }

    #[instrument(skip(self, ctx), fields(strategy = self.name()))]
    fn apply(&self, packet: Packet, ctx: &mut Context) -> Result<StrategyAction> {
        let fragment_size = if self.by_sni {
            self.find_sni_fragment_position(&packet)
                .map(|pos| pos as u16)
                .unwrap_or_else(|| self.get_fragment_size(&packet))
        } else {
            self.get_fragment_size(&packet)
        };

        // Don't fragment if fragment size is larger than payload
        if fragment_size as usize >= packet.payload_len() {
            return Ok(StrategyAction::Pass(packet));
        }

        // Split the packet
        let (first, second) = packet.split_at_payload(fragment_size as usize)?;

        ctx.stats.packets_fragmented += 1;

        // Return fragments in order (or reversed)
        let fragments = if self.reverse_order {
            vec![second, first]
        } else {
            vec![first, second]
        };

        Ok(StrategyAction::Replace(fragments))
    }
}

impl FragmentationStrategy {
    /// Extract hostname from packet (HTTP Host header or TLS SNI)
    fn extract_hostname(&self, packet: &Packet) -> Option<String> {
        if packet.is_http_request() {
            packet.extract_http_host()
        } else if packet.is_tls_client_hello() {
            packet.extract_sni()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Direction;

    #[test]
    fn test_fragmentation_config() {
        let config = FragmentationConfig {
            enabled: true,
            http_size: 4,
            https_size: 8,
            native_split: true,
            reverse_order: false,
            by_sni: false,
            http_persistent: true,
            persistent_nowait: true,
        };

        let strategy = FragmentationStrategy::from_config(&config);
        assert_eq!(strategy.http_size, 4);
        assert_eq!(strategy.https_size, 8);
        assert!(!strategy.reverse_order);
    }

    #[test]
    fn test_fragment_size_selection() {
        let strategy = FragmentationStrategy::new();

        // Create mock packets
        // HTTP packet (port 80)
        let mut http_packet = create_mock_packet(80);
        assert_eq!(strategy.get_fragment_size(&http_packet), 2);

        // HTTPS packet (port 443)
        let https_packet = create_mock_packet(443);
        assert_eq!(strategy.get_fragment_size(&https_packet), 2);
    }

    fn create_mock_packet(dst_port: u16) -> Packet {
        // Minimal TCP packet for testing
        let mut data = vec![
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x50, 
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0xC0, 0xA8, 0x01, 0x01,
            0xC0, 0xA8, 0x01, 0x02,
            // TCP header (20 bytes)
            0x00, 0x50, // src port
            (dst_port >> 8) as u8, (dst_port & 0xFF) as u8, // dst port
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01,
            0x50, 0x18, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            // Payload
            b'G', b'E', b'T', b' ', b'/', b' ', b'H', b'T', b'T', b'P',
        ];

        Packet::from_bytes(&data, Direction::Outbound).unwrap()
    }
}
