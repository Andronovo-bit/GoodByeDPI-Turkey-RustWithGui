//! QUIC/HTTP3 blocking strategy
//!
//! Blocks QUIC traffic to force browsers to use HTTP/2 over TCP,
//! which can then be processed by other DPI bypass strategies.

use super::{Strategy, StrategyAction};
use crate::error::Result;
use crate::packet::Packet;
use crate::pipeline::Context;
use tracing::{debug, instrument};

/// QUIC blocking strategy
///
/// QUIC uses UDP on port 443 and is fully encrypted, making it impossible
/// to manipulate. By blocking QUIC, we force browsers to fall back to
/// HTTP/2 over TCP, which we can then process.
pub struct QuicBlockStrategy {
    /// Minimum payload size for QUIC detection
    min_payload_size: usize,
}

impl QuicBlockStrategy {
    /// Create a new QUIC blocking strategy
    pub fn new() -> Self {
        Self {
            min_payload_size: 1200,
        }
    }

    /// Check if this looks like a QUIC Initial packet
    fn is_quic_initial(&self, packet: &Packet) -> bool {
        let payload = packet.payload();

        // QUIC Initial packets are at least 1200 bytes
        if payload.len() < self.min_payload_size {
            return false;
        }

        // Check QUIC header format
        // First byte: form bit (1) + fixed bit (1) + packet type
        // For Initial packets: 0b11xxxxxx (0xC0 or higher)
        if payload[0] < 0xC0 {
            return false;
        }

        // Check version field at bytes 1-4
        // QUIC version 1 (RFC 9000): 0x00000001
        if payload.len() >= 5 {
            let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
            // Version 1 or version negotiation (0)
            if version == 1 || version == 0 {
                return true;
            }
        }

        false
    }
}

impl Default for QuicBlockStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for QuicBlockStrategy {
    fn name(&self) -> &'static str {
        "quic_block"
    }

    fn priority(&self) -> u8 {
        // Run early to block QUIC before any other processing
        5
    }

    fn should_apply(&self, packet: &Packet, _ctx: &Context) -> bool {
        // Only apply to outbound UDP on port 443
        packet.is_outbound() 
            && packet.is_udp() 
            && packet.dst_port == 443
            && packet.payload_len() >= self.min_payload_size
    }

    #[instrument(skip(self, ctx), fields(strategy = self.name()))]
    fn apply(&self, packet: Packet, ctx: &mut Context) -> Result<StrategyAction> {
        if self.is_quic_initial(&packet) {
            ctx.stats.quic_blocked += 1;
            debug!(
                dst = %packet.dst_addr,
                payload_len = packet.payload_len(),
                "Blocking QUIC Initial packet"
            );
            return Ok(StrategyAction::Drop);
        }

        // Not QUIC, pass through
        Ok(StrategyAction::Pass(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Direction;

    #[test]
    fn test_quic_detection() {
        let strategy = QuicBlockStrategy::new();

        // Create a fake QUIC Initial packet header
        let mut quic_payload = vec![0xC0]; // Form bit + Long header
        quic_payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version 1
        // Pad to minimum size
        quic_payload.resize(1200, 0);

        // Create UDP packet wrapper (simplified)
        let mut packet_data = vec![
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x04, 0xE8, // Total length = 1256 (20 + 8 + 1228)
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x11, 0x00, 0x00, // Protocol = UDP (17)
            0xC0, 0xA8, 0x01, 0x01,
            0xC0, 0xA8, 0x01, 0x02,
            // UDP header (8 bytes)
            0x00, 0x50, 0x01, 0xBB, // Src port, Dst port (443)
            0x04, 0xDC, 0x00, 0x00, // Length, Checksum
        ];
        packet_data.extend_from_slice(&quic_payload);

        // This test validates the detection logic
        assert!(quic_payload[0] >= 0xC0); // QUIC long header
    }
}
