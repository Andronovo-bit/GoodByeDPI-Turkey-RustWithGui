//! Platform-agnostic traits for packet capture
//!
//! These traits define the interface that platform-specific implementations must follow.

use gdpi_core::packet::{Direction, Packet};
use crate::Result;

/// Packet capture and injection interface
///
/// Implemented by platform-specific drivers (WinDivert, NFQUEUE, etc.)
pub trait PacketCapture: Send {
    /// Receive a packet from the network stack
    ///
    /// This blocks until a packet is available or timeout occurs.
    fn recv(&mut self) -> Result<CapturedPacket>;

    /// Receive a batch of packets
    ///
    /// More efficient for high-throughput scenarios.
    fn recv_batch(&mut self, max_count: usize) -> Result<Vec<CapturedPacket>>;

    /// Send/inject a packet
    fn send(&mut self, packet: &[u8], addr: &PacketAddress) -> Result<()>;

    /// Send multiple packets
    fn send_batch(&mut self, packets: &[(Vec<u8>, PacketAddress)]) -> Result<()>;

    /// Close the capture handle
    fn close(&mut self) -> Result<()>;
}

/// Packet filter interface
///
/// Allows setting up filters for which packets to capture.
pub trait PacketFilter {
    /// Set the filter string
    ///
    /// The format is driver-specific (e.g., WinDivert filter syntax).
    fn set_filter(&mut self, filter: &str) -> Result<()>;

    /// Get the current filter
    fn get_filter(&self) -> &str;

    /// Validate a filter string without applying it
    fn validate_filter(filter: &str) -> Result<()>;
}

/// A captured packet with metadata
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    /// Raw packet data
    pub data: Vec<u8>,
    /// Packet direction
    pub direction: Direction,
    /// Interface index (if available)
    pub interface_index: u32,
    /// Subinterface index (if available)
    pub subinterface_index: u32,
    /// Platform-specific address data for reinection
    pub address: PacketAddress,
}

impl CapturedPacket {
    /// Parse the captured packet into a structured Packet
    pub fn parse(&self) -> gdpi_core::Result<Packet> {
        Packet::from_bytes(&self.data, self.direction)
    }
}

/// Platform-specific packet address for reinjection
///
/// This contains the metadata needed to reinject a packet at the correct point.
#[derive(Debug, Clone, Default)]
pub struct PacketAddress {
    /// Interface index
    pub interface_index: u32,
    /// Subinterface index
    pub subinterface_index: u32,
    /// Direction (outbound = true, inbound = false)
    pub outbound: bool,
    /// Whether packet is loopback
    pub loopback: bool,
    /// Whether packet is an impostor (injected)
    pub impostor: bool,
    /// IPv6 flag
    pub ipv6: bool,
    /// IP checksum valid
    pub ip_checksum: bool,
    /// TCP checksum valid
    pub tcp_checksum: bool,
    /// UDP checksum valid
    pub udp_checksum: bool,
}

impl PacketAddress {
    /// Create for outbound packet
    pub fn outbound() -> Self {
        Self {
            outbound: true,
            ..Default::default()
        }
    }

    /// Create for inbound packet
    pub fn inbound() -> Self {
        Self {
            outbound: false,
            ..Default::default()
        }
    }

    /// Mark as impostor (injected)
    pub fn as_impostor(mut self) -> Self {
        self.impostor = true;
        self
    }

    /// Mark checksums as needing recalculation
    pub fn recalculate_checksums(mut self) -> Self {
        self.ip_checksum = false;
        self.tcp_checksum = false;
        self.udp_checksum = false;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_address_outbound() {
        let addr = PacketAddress::outbound();
        assert!(addr.outbound);
        assert!(!addr.loopback);
    }

    #[test]
    fn test_packet_address_impostor() {
        let addr = PacketAddress::outbound().as_impostor();
        assert!(addr.outbound);
        assert!(addr.impostor);
    }

    #[test]
    fn test_packet_address_recalc() {
        let addr = PacketAddress::outbound().recalculate_checksums();
        assert!(!addr.ip_checksum);
        assert!(!addr.tcp_checksum);
        assert!(!addr.udp_checksum);
    }
}
