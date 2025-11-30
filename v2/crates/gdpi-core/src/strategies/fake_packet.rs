//! Fake packet injection strategy
//!
//! Sends fake/malformed packets before real requests to confuse DPI systems.

use super::{Strategy, StrategyAction};
use crate::config::{AutoTtlConfig, FakePacketConfig};
use crate::error::Result;
use crate::packet::{Packet, PacketBuilder, TcpFlags, Direction};
use crate::pipeline::Context;
use tracing::{debug, instrument};

/// Fake packet injection strategy
pub struct FakePacketStrategy {
    /// Use wrong TCP checksum
    wrong_checksum: bool,
    /// Use wrong SEQ/ACK numbers
    wrong_seq: bool,
    /// Fixed TTL value (None = use auto)
    ttl: Option<u8>,
    /// Auto TTL configuration
    auto_ttl: Option<AutoTtlConfig>,
    /// Minimum TTL hops
    min_ttl_hops: Option<u8>,
    /// Number of times to resend
    resend_count: u8,
}

impl FakePacketStrategy {
    /// Create a new fake packet strategy
    pub fn new() -> Self {
        Self {
            wrong_checksum: true,
            wrong_seq: true,
            ttl: None,
            auto_ttl: None,
            min_ttl_hops: Some(3),
            resend_count: 1,
        }
    }

    /// Create from configuration
    pub fn from_config(config: &FakePacketConfig) -> Self {
        Self {
            wrong_checksum: config.wrong_checksum,
            wrong_seq: config.wrong_seq,
            ttl: config.ttl,
            auto_ttl: config.auto_ttl.clone(),
            min_ttl_hops: config.min_ttl_hops,
            resend_count: config.resend_count,
        }
    }

    /// Calculate TTL for fake packet
    fn calculate_ttl(&self, ctx: &Context, packet: &Packet) -> Option<u8> {
        // If fixed TTL is set, use it
        if let Some(ttl) = self.ttl {
            return Some(ttl);
        }

        // If auto TTL is enabled, calculate based on connection TTL
        if let Some(auto_config) = &self.auto_ttl {
            // Look up the connection's measured TTL
            if let Some(conn_ttl) = ctx.get_connection_ttl(packet) {
                return self.auto_ttl_calculate(conn_ttl, auto_config);
            }
        }

        // Default: use a low TTL that won't reach the server
        Some(8)
    }

    /// Calculate auto TTL based on measured connection TTL
    fn auto_ttl_calculate(&self, conn_ttl: u8, config: &AutoTtlConfig) -> Option<u8> {
        // Calculate number of hops to destination
        let nhops = if conn_ttl > 98 && conn_ttl < 128 {
            128 - conn_ttl
        } else if conn_ttl > 34 && conn_ttl < 64 {
            64 - conn_ttl
        } else {
            return None;
        };

        // Check minimum hops requirement
        if let Some(min_hops) = self.min_ttl_hops {
            if nhops < min_hops {
                return None;
            }
        }

        // Calculate fake packet TTL
        let mut fake_ttl = nhops.saturating_sub(config.a2);

        // Adjust for short distances
        if fake_ttl < config.a2 && nhops <= 9 {
            let scale = (config.a2 - config.a1) as f32 * (nhops as f32 / 10.0);
            fake_ttl = nhops.saturating_sub(config.a1).saturating_sub(scale as u8);
        }

        // Apply maximum limit
        if fake_ttl > config.max {
            fake_ttl = config.max;
        }

        if fake_ttl > 0 {
            Some(fake_ttl)
        } else {
            None
        }
    }

    /// Create fake HTTP request packet
    fn create_fake_http(&self, original: &Packet, ttl: u8, wrong_seq: bool) -> Packet {
        let fake_payload = b"GET / HTTP/1.1\r\nHost: www.w3.org\r\nUser-Agent: curl/7.65.3\r\n\r\n";
        self.create_fake_packet(original, fake_payload, ttl, wrong_seq)
    }

    /// Create fake TLS ClientHello packet
    fn create_fake_https(&self, original: &Packet, ttl: u8, wrong_seq: bool) -> Packet {
        // Minimal fake TLS ClientHello
        let fake_payload: &[u8] = &[
            0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
            // Random bytes
            0x9a, 0x8f, 0xa7, 0x6a, 0x5d, 0x57, 0xf3, 0x62, 0x19, 0xbe, 0x46, 
            0x82, 0x45, 0xe2, 0x59, 0x5c, 0xb4, 0x48, 0x31, 0x12, 0x15, 0x14, 
            0x79, 0x2c, 0xaa, 0xcd, 0xea, 0xda, 0xf0, 0xe1, 0xfd, 0xbb, 0x20,
            // Session ID
            0xf4, 0x83, 0x2a, 0x94, 0xf1, 0x48, 0x3b, 0x9d, 0xb6, 0x74, 0xba,
            // ... (truncated for brevity)
        ];
        self.create_fake_packet(original, fake_payload, ttl, wrong_seq)
    }

    /// Create a fake packet based on the original
    fn create_fake_packet(&self, original: &Packet, payload: &[u8], ttl: u8, wrong_seq: bool) -> Packet {
        let mut data = original.as_bytes().to_vec();
        
        // Create a copy of the packet
        let mut fake = Packet::from_bytes(&data, original.direction).unwrap();

        // Set TTL
        fake.set_ttl(ttl);

        // If wrong_seq, modify SEQ/ACK to be in the past
        if wrong_seq {
            if let Some(seq) = fake.tcp_seq() {
                fake.set_tcp_seq(seq.wrapping_sub(10000));
            }
            if let Some(ack) = fake.tcp_ack_num() {
                fake.set_tcp_ack(ack.wrapping_sub(66000));
            }
        }

        fake
    }

    /// Damage checksum to make packet invalid
    fn damage_checksum(&self, packet: &mut Packet) {
        // TCP checksum is at offset IP_header_len + 16
        // Just flip a bit to make it invalid
        let data = packet.as_bytes_mut();
        if data.len() > 36 {
            data[36] ^= 0x01;
        }
    }
}

impl Default for FakePacketStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for FakePacketStrategy {
    fn name(&self) -> &'static str {
        "fake_packet"
    }

    fn priority(&self) -> u8 {
        // Run first so fake packets are injected before real packet
        10
    }

    fn should_apply(&self, packet: &Packet, ctx: &Context) -> bool {
        // Only apply to outbound TCP packets with data
        if !packet.is_outbound() || !packet.is_tcp() {
            return false;
        }

        // Must have payload
        if packet.payload_len() == 0 {
            return false;
        }

        // Only for HTTP/HTTPS initial requests
        let is_http = packet.dst_port == 80 && packet.is_http_request();
        let is_https = packet.dst_port == 443 && packet.is_tls_client_hello();

        if !is_http && !is_https {
            return false;
        }

        // Check blacklist if enabled
        if ctx.blacklist_enabled {
            let hostname = if is_http {
                packet.extract_http_host()
            } else {
                packet.extract_sni()
            };

            if let Some(host) = hostname {
                if !ctx.is_blacklisted(&host) {
                    return false;
                }
            }
        }

        true
    }

    #[instrument(skip(self, ctx), fields(strategy = self.name()))]
    fn apply(&self, packet: Packet, ctx: &mut Context) -> Result<StrategyAction> {
        let ttl = match self.calculate_ttl(ctx, &packet) {
            Some(t) => t,
            None => {
                debug!("TTL calculation returned None, skipping fake packet");
                return Ok(StrategyAction::Pass(packet));
            }
        };

        let is_https = packet.dst_port == 443;
        let mut fake_packets = Vec::new();

        for _ in 0..self.resend_count {
            // Create fake with wrong TTL
            if self.ttl.is_some() || self.auto_ttl.is_some() {
                let fake = if is_https {
                    self.create_fake_https(&packet, ttl, false)
                } else {
                    self.create_fake_http(&packet, ttl, false)
                };
                fake_packets.push(fake);
            }

            // Create fake with wrong checksum
            if self.wrong_checksum {
                let mut fake = if is_https {
                    self.create_fake_https(&packet, 64, false)
                } else {
                    self.create_fake_http(&packet, 64, false)
                };
                self.damage_checksum(&mut fake);
                fake_packets.push(fake);
            }

            // Create fake with wrong SEQ/ACK
            if self.wrong_seq {
                let fake = if is_https {
                    self.create_fake_https(&packet, 64, true)
                } else {
                    self.create_fake_http(&packet, 64, true)
                };
                fake_packets.push(fake);
            }
        }

        ctx.stats.fake_packets_sent += fake_packets.len() as u64;
        debug!(
            fake_count = fake_packets.len(),
            ttl,
            wrong_checksum = self.wrong_checksum,
            wrong_seq = self.wrong_seq,
            "Injecting fake packets"
        );

        Ok(StrategyAction::InjectBefore(fake_packets, packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_ttl_calculation() {
        let strategy = FakePacketStrategy {
            wrong_checksum: false,
            wrong_seq: false,
            ttl: None,
            auto_ttl: Some(AutoTtlConfig {
                a1: 1,
                a2: 4,
                max: 10,
            }),
            min_ttl_hops: Some(3),
            resend_count: 1,
        };

        // Test with TTL indicating ~10 hops (128 - 118 = 10)
        let config = strategy.auto_ttl.as_ref().unwrap();
        let result = strategy.auto_ttl_calculate(118, config);
        assert!(result.is_some());
        let ttl = result.unwrap();
        assert!(ttl > 0 && ttl <= 10);
    }

    #[test]
    fn test_min_hops_filter() {
        let strategy = FakePacketStrategy {
            wrong_checksum: false,
            wrong_seq: false,
            ttl: None,
            auto_ttl: Some(AutoTtlConfig::default()),
            min_ttl_hops: Some(5),
            resend_count: 1,
        };

        // TTL 126 means only 2 hops, should return None (below min_hops)
        let config = strategy.auto_ttl.as_ref().unwrap();
        let result = strategy.auto_ttl_calculate(126, config);
        assert!(result.is_none());
    }
}
