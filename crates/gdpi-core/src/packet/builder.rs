//! Packet builder utilities

use super::{Direction, IpVersion, Protocol, TcpFlags};
use bytes::BytesMut;

/// Builder for constructing packets
pub struct PacketBuilder {
    ip_version: IpVersion,
    protocol: Protocol,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    tcp_flags: TcpFlags,
    seq: u32,
    ack: u32,
    payload: Vec<u8>,
}

impl PacketBuilder {
    /// Create new IPv4 TCP packet builder
    pub fn tcp_v4() -> Self {
        Self {
            ip_version: IpVersion::V4,
            protocol: Protocol::Tcp,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 0,
            dst_port: 0,
            ttl: 64,
            tcp_flags: TcpFlags::default(),
            seq: 0,
            ack: 0,
            payload: Vec::new(),
        }
    }

    /// Set source IP (IPv4)
    pub fn src_ip_v4(mut self, ip: [u8; 4]) -> Self {
        self.src_ip[..4].copy_from_slice(&ip);
        self
    }

    /// Set destination IP (IPv4)
    pub fn dst_ip_v4(mut self, ip: [u8; 4]) -> Self {
        self.dst_ip[..4].copy_from_slice(&ip);
        self
    }

    /// Set source port
    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = port;
        self
    }

    /// Set destination port
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = port;
        self
    }

    /// Set TTL
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Set TCP flags
    pub fn flags(mut self, flags: TcpFlags) -> Self {
        self.tcp_flags = flags;
        self
    }

    /// Set sequence number
    pub fn seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }

    /// Set acknowledgment number
    pub fn ack(mut self, ack: u32) -> Self {
        self.ack = ack;
        self
    }

    /// Set payload
    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = data.to_vec();
        self
    }

    /// Build the packet
    pub fn build(self) -> Vec<u8> {
        let ip_header_len = 20;
        let tcp_header_len = 20;
        let total_len = ip_header_len + tcp_header_len + self.payload.len();

        let mut packet = BytesMut::with_capacity(total_len);

        // IPv4 header
        packet.extend_from_slice(&[
            0x45,                                // Version (4) + IHL (5)
            0x00,                                // DSCP + ECN
            ((total_len >> 8) & 0xFF) as u8,     // Total Length (high)
            (total_len & 0xFF) as u8,            // Total Length (low)
            0x00, 0x00,                          // Identification
            0x40, 0x00,                          // Flags (DF) + Fragment Offset
            self.ttl,                            // TTL
            0x06,                                // Protocol (TCP)
            0x00, 0x00,                          // Header Checksum (placeholder)
        ]);
        packet.extend_from_slice(&self.src_ip[..4]); // Source IP
        packet.extend_from_slice(&self.dst_ip[..4]); // Dest IP

        // TCP header
        packet.extend_from_slice(&self.src_port.to_be_bytes());
        packet.extend_from_slice(&self.dst_port.to_be_bytes());
        packet.extend_from_slice(&self.seq.to_be_bytes());
        packet.extend_from_slice(&self.ack.to_be_bytes());
        packet.extend_from_slice(&[
            0x50,                           // Data Offset (5 * 4 = 20 bytes)
            self.tcp_flags.to_byte(),       // Flags
            0xFF, 0xFF,                     // Window Size
            0x00, 0x00,                     // Checksum (placeholder)
            0x00, 0x00,                     // Urgent Pointer
        ]);

        // Payload
        packet.extend_from_slice(&self.payload);

        packet.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tcp_packet() {
        let packet = PacketBuilder::tcp_v4()
            .src_ip_v4([192, 168, 1, 1])
            .dst_ip_v4([192, 168, 1, 2])
            .src_port(12345)
            .dst_port(80)
            .ttl(64)
            .flags(TcpFlags { ack: true, psh: true, ..Default::default() })
            .payload(b"GET / HTTP/1.1\r\n")
            .build();

        assert_eq!(packet[0] >> 4, 4); // IPv4
        assert_eq!(packet[9], 6); // TCP
        assert_eq!(packet.len(), 20 + 20 + 16); // IP + TCP + payload
    }
}
