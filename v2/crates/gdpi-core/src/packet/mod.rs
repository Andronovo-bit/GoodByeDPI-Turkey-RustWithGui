//! Packet parsing and manipulation
//!
//! Low-level packet handling for TCP/IP traffic.

mod builder;
mod parser;
mod types;

pub use builder::PacketBuilder;
pub use parser::PacketParser;
pub use types::*;

use crate::error::{Error, Result};
use bytes::{Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Maximum packet size we handle
pub const MAX_PACKET_SIZE: usize = 9016;

/// Maximum hostname length (DNS standard)
pub const MAX_HOSTNAME_LEN: usize = 253;

/// Represents a network packet with parsed headers
#[derive(Debug, Clone)]
pub struct Packet {
    /// Raw packet data
    data: BytesMut,
    /// Packet direction
    pub direction: Direction,
    /// IP version
    pub ip_version: IpVersion,
    /// Transport protocol
    pub protocol: Protocol,
    /// Source IP address
    pub src_addr: IpAddr,
    /// Destination IP address
    pub dst_addr: IpAddr,
    /// Source port (TCP/UDP)
    pub src_port: u16,
    /// Destination port (TCP/UDP)
    pub dst_port: u16,
    /// IP header length
    ip_header_len: usize,
    /// Transport header length
    transport_header_len: usize,
    /// TCP flags (if TCP)
    pub tcp_flags: Option<TcpFlags>,
    /// TTL/Hop Limit
    pub ttl: u8,
    /// IP ID (IPv4 only)
    pub ip_id: Option<u16>,
}

impl Packet {
    /// Create a new packet from raw bytes
    pub fn from_bytes(data: &[u8], direction: Direction) -> Result<Self> {
        if data.len() < 20 {
            return Err(Error::PacketTooSmall {
                expected: 20,
                actual: data.len(),
            });
        }

        let mut packet = Self {
            data: BytesMut::from(data),
            direction,
            ip_version: IpVersion::V4,
            protocol: Protocol::Unknown,
            src_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            ip_header_len: 0,
            transport_header_len: 0,
            tcp_flags: None,
            ttl: 0,
            ip_id: None,
        };

        packet.parse()?;
        Ok(packet)
    }

    /// Parse the packet headers
    fn parse(&mut self) -> Result<()> {
        let version = (self.data[0] >> 4) & 0x0F;

        match version {
            4 => self.parse_ipv4()?,
            6 => self.parse_ipv6()?,
            _ => return Err(Error::packet_parse(format!("Unknown IP version: {version}"))),
        }

        Ok(())
    }

    /// Parse IPv4 header
    fn parse_ipv4(&mut self) -> Result<()> {
        if self.data.len() < 20 {
            return Err(Error::PacketTooSmall {
                expected: 20,
                actual: self.data.len(),
            });
        }

        self.ip_version = IpVersion::V4;
        self.ip_header_len = ((self.data[0] & 0x0F) * 4) as usize;

        if self.data.len() < self.ip_header_len {
            return Err(Error::PacketTooSmall {
                expected: self.ip_header_len,
                actual: self.data.len(),
            });
        }

        // Parse IP ID
        self.ip_id = Some(u16::from_be_bytes([self.data[4], self.data[5]]));

        // Parse TTL
        self.ttl = self.data[8];

        // Parse protocol
        let proto = self.data[9];
        self.protocol = Protocol::from_u8(proto);

        // Parse addresses
        self.src_addr = IpAddr::V4(Ipv4Addr::new(
            self.data[12],
            self.data[13],
            self.data[14],
            self.data[15],
        ));
        self.dst_addr = IpAddr::V4(Ipv4Addr::new(
            self.data[16],
            self.data[17],
            self.data[18],
            self.data[19],
        ));

        // Parse transport layer
        self.parse_transport()?;

        Ok(())
    }

    /// Parse IPv6 header
    fn parse_ipv6(&mut self) -> Result<()> {
        if self.data.len() < 40 {
            return Err(Error::PacketTooSmall {
                expected: 40,
                actual: self.data.len(),
            });
        }

        self.ip_version = IpVersion::V6;
        self.ip_header_len = 40; // Fixed for IPv6

        // Parse Hop Limit (TTL equivalent)
        self.ttl = self.data[7];

        // Parse Next Header (protocol)
        let proto = self.data[6];
        self.protocol = Protocol::from_u8(proto);

        // Parse addresses
        let mut src_bytes = [0u8; 16];
        let mut dst_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&self.data[8..24]);
        dst_bytes.copy_from_slice(&self.data[24..40]);

        self.src_addr = IpAddr::V6(Ipv6Addr::from(src_bytes));
        self.dst_addr = IpAddr::V6(Ipv6Addr::from(dst_bytes));

        // Parse transport layer
        self.parse_transport()?;

        Ok(())
    }

    /// Parse transport layer (TCP/UDP)
    fn parse_transport(&mut self) -> Result<()> {
        let offset = self.ip_header_len;

        match self.protocol {
            Protocol::Tcp => {
                if self.data.len() < offset + 20 {
                    return Err(Error::PacketTooSmall {
                        expected: offset + 20,
                        actual: self.data.len(),
                    });
                }

                self.src_port =
                    u16::from_be_bytes([self.data[offset], self.data[offset + 1]]);
                self.dst_port =
                    u16::from_be_bytes([self.data[offset + 2], self.data[offset + 3]]);

                // Data offset (header length)
                self.transport_header_len = ((self.data[offset + 12] >> 4) * 4) as usize;

                // TCP flags
                let flags_byte = self.data[offset + 13];
                self.tcp_flags = Some(TcpFlags::from_byte(flags_byte));
            }
            Protocol::Udp => {
                if self.data.len() < offset + 8 {
                    return Err(Error::PacketTooSmall {
                        expected: offset + 8,
                        actual: self.data.len(),
                    });
                }

                self.src_port =
                    u16::from_be_bytes([self.data[offset], self.data[offset + 1]]);
                self.dst_port =
                    u16::from_be_bytes([self.data[offset + 2], self.data[offset + 3]]);
                self.transport_header_len = 8;
            }
            _ => {}
        }

        Ok(())
    }

    /// Get the payload (data after headers)
    pub fn payload(&self) -> &[u8] {
        let offset = self.ip_header_len + self.transport_header_len;
        if offset < self.data.len() {
            &self.data[offset..]
        } else {
            &[]
        }
    }

    /// Get payload length
    pub fn payload_len(&self) -> usize {
        self.payload().len()
    }

    /// Check if packet is outbound
    pub fn is_outbound(&self) -> bool {
        matches!(self.direction, Direction::Outbound)
    }

    /// Check if packet is inbound
    pub fn is_inbound(&self) -> bool {
        matches!(self.direction, Direction::Inbound)
    }

    /// Check if this is a TCP packet
    pub fn is_tcp(&self) -> bool {
        matches!(self.protocol, Protocol::Tcp)
    }

    /// Check if this is a UDP packet
    pub fn is_udp(&self) -> bool {
        matches!(self.protocol, Protocol::Udp)
    }

    /// Check if this is IPv4
    pub fn is_ipv4(&self) -> bool {
        matches!(self.ip_version, IpVersion::V4)
    }

    /// Check if this is IPv6
    pub fn is_ipv6(&self) -> bool {
        matches!(self.ip_version, IpVersion::V6)
    }

    /// Check if TCP SYN flag is set
    pub fn is_syn(&self) -> bool {
        self.tcp_flags.map(|f| f.syn).unwrap_or(false)
    }

    /// Check if TCP ACK flag is set
    pub fn is_ack(&self) -> bool {
        self.tcp_flags.map(|f| f.ack).unwrap_or(false)
    }

    /// Check if TCP RST flag is set
    pub fn is_rst(&self) -> bool {
        self.tcp_flags.map(|f| f.rst).unwrap_or(false)
    }

    /// Check if this is a SYN-ACK packet
    pub fn is_syn_ack(&self) -> bool {
        self.tcp_flags.map(|f| f.syn && f.ack).unwrap_or(false)
    }

    /// Check if this looks like HTTP traffic
    pub fn is_http(&self) -> bool {
        self.is_tcp() && (self.dst_port == 80 || self.src_port == 80)
    }

    /// Check if this looks like HTTPS traffic
    pub fn is_https(&self) -> bool {
        self.is_tcp() && (self.dst_port == 443 || self.src_port == 443)
    }

    /// Check if payload looks like HTTP request
    pub fn is_http_request(&self) -> bool {
        let payload = self.payload();
        if payload.len() < 4 {
            return false;
        }

        matches!(
            &payload[..4],
            b"GET " | b"POST" | b"HEAD" | b"PUT " | b"DELE" | b"CONN" | b"OPTI"
        )
    }

    /// Check if payload looks like TLS ClientHello
    pub fn is_tls_client_hello(&self) -> bool {
        let payload = self.payload();
        if payload.len() < 3 {
            return false;
        }

        // TLS record: 0x16 (handshake), 0x03 0x01 or 0x03 0x03 (TLS version)
        payload[0] == 0x16 && payload[1] == 0x03 && (payload[2] == 0x01 || payload[2] == 0x03)
    }

    /// Extract SNI from TLS ClientHello
    pub fn extract_sni(&self) -> Option<String> {
        let payload = self.payload();
        if payload.len() < 44 {
            return None;
        }

        // Look for SNI extension (type 0x00 0x00)
        let mut ptr = 0;
        while ptr + 10 < payload.len() {
            // Look for SNI extension pattern:
            // [0x00, 0x00] = extension type (SNI)
            // [ext_len_hi, ext_len_lo] = extension length
            // [list_len_hi, list_len_lo] = server name list length
            // [0x00] = name type (hostname)
            // [name_len_hi, name_len_lo] = name length
            if payload[ptr] == 0x00 && payload[ptr + 1] == 0x00 {
                // This might be the SNI extension
                if ptr + 9 >= payload.len() {
                    ptr += 1;
                    continue;
                }
                
                let ext_len = ((payload[ptr + 2] as usize) << 8) | (payload[ptr + 3] as usize);
                let list_len = ((payload[ptr + 4] as usize) << 8) | (payload[ptr + 5] as usize);
                let name_type = payload[ptr + 6];
                let name_len = ((payload[ptr + 7] as usize) << 8) | (payload[ptr + 8] as usize);
                
                // Validate lengths: ext_len = list_len + 2, list_len = name_len + 3, name_type = 0
                if ext_len == list_len + 2 && list_len == name_len + 3 && name_type == 0x00 {
                    let sni_start = ptr + 9;
                    let sni_end = sni_start + name_len;

                    if sni_end <= payload.len() && name_len >= 3 && name_len <= MAX_HOSTNAME_LEN {
                        let sni_bytes = &payload[sni_start..sni_end];
                        
                        // Validate hostname characters (allow lowercase, digits, dot, hyphen)
                        if sni_bytes.iter().all(|&b| {
                            (b >= b'0' && b <= b'9')
                                || (b >= b'a' && b <= b'z')
                                || b == b'.'
                                || b == b'-'
                        }) {
                            return String::from_utf8(sni_bytes.to_vec()).ok();
                        }
                    }
                }
            }
            ptr += 1;
        }

        None
    }

    /// Extract Host header from HTTP request
    pub fn extract_http_host(&self) -> Option<String> {
        let payload = self.payload();
        let payload_str = std::str::from_utf8(payload).ok()?;

        // Find "Host: " header
        let host_marker = "\r\nHost: ";
        let host_start = payload_str.find(host_marker)? + host_marker.len();
        let host_end = payload_str[host_start..].find("\r\n")? + host_start;

        let host = &payload_str[host_start..host_end];
        if host.len() >= 3 && host.len() <= MAX_HOSTNAME_LEN {
            Some(host.to_string())
        } else {
            None
        }
    }

    /// Get the raw packet data
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable raw packet data
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get total packet length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if packet is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Clone packet data into a new Bytes
    pub fn to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(&self.data)
    }

    /// Get TCP sequence number
    pub fn tcp_seq(&self) -> Option<u32> {
        if !self.is_tcp() {
            return None;
        }
        let offset = self.ip_header_len + 4;
        if self.data.len() >= offset + 4 {
            Some(u32::from_be_bytes([
                self.data[offset],
                self.data[offset + 1],
                self.data[offset + 2],
                self.data[offset + 3],
            ]))
        } else {
            None
        }
    }

    /// Get TCP acknowledgment number
    pub fn tcp_ack_num(&self) -> Option<u32> {
        if !self.is_tcp() {
            return None;
        }
        let offset = self.ip_header_len + 8;
        if self.data.len() >= offset + 4 {
            Some(u32::from_be_bytes([
                self.data[offset],
                self.data[offset + 1],
                self.data[offset + 2],
                self.data[offset + 3],
            ]))
        } else {
            None
        }
    }

    /// Set TTL/Hop Limit
    pub fn set_ttl(&mut self, ttl: u8) {
        match self.ip_version {
            IpVersion::V4 => self.data[8] = ttl,
            IpVersion::V6 => self.data[7] = ttl,
        }
        self.ttl = ttl;
    }

    /// Set TCP sequence number
    pub fn set_tcp_seq(&mut self, seq: u32) {
        if self.is_tcp() {
            let offset = self.ip_header_len + 4;
            let bytes = seq.to_be_bytes();
            self.data[offset..offset + 4].copy_from_slice(&bytes);
        }
    }

    /// Set TCP acknowledgment number
    pub fn set_tcp_ack(&mut self, ack: u32) {
        if self.is_tcp() {
            let offset = self.ip_header_len + 8;
            let bytes = ack.to_be_bytes();
            self.data[offset..offset + 4].copy_from_slice(&bytes);
        }
    }

    /// Split packet at payload offset, returns (first, second) fragments
    pub fn split_at_payload(&self, offset: usize) -> Result<(Self, Self)> {
        let header_len = self.ip_header_len + self.transport_header_len;
        let payload = self.payload();

        if offset >= payload.len() {
            return Err(Error::strategy("split", "Split offset exceeds payload length"));
        }

        // First fragment: headers + payload[..offset]
        let mut first_data = BytesMut::with_capacity(header_len + offset);
        first_data.extend_from_slice(&self.data[..header_len]);
        first_data.extend_from_slice(&payload[..offset]);

        // Second fragment: headers + payload[offset..]
        let mut second_data = BytesMut::with_capacity(header_len + payload.len() - offset);
        second_data.extend_from_slice(&self.data[..header_len]);
        second_data.extend_from_slice(&payload[offset..]);

        let mut first = self.clone();
        first.data = first_data;
        first.update_lengths()?;

        let mut second = self.clone();
        second.data = second_data;
        // Update SEQ for second fragment
        if let Some(seq) = second.tcp_seq() {
            second.set_tcp_seq(seq.wrapping_add(offset as u32));
        }
        second.update_lengths()?;

        Ok((first, second))
    }

    /// Update IP and TCP length fields after modification
    fn update_lengths(&mut self) -> Result<()> {
        let total_len = self.data.len();

        match self.ip_version {
            IpVersion::V4 => {
                let len_bytes = (total_len as u16).to_be_bytes();
                self.data[2] = len_bytes[0];
                self.data[3] = len_bytes[1];
            }
            IpVersion::V6 => {
                let payload_len = (total_len - 40) as u16;
                let len_bytes = payload_len.to_be_bytes();
                self.data[4] = len_bytes[0];
                self.data[5] = len_bytes[1];
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tcp_packet() -> Vec<u8> {
        // Minimal IPv4 TCP packet
        vec![
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x28, // Version, IHL, TOS, Total Length
            0x00, 0x01, 0x00, 0x00, // ID, Flags, Fragment
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol (TCP), Checksum
            0xC0, 0xA8, 0x01, 0x01, // Source IP (192.168.1.1)
            0xC0, 0xA8, 0x01, 0x02, // Dest IP (192.168.1.2)
            // TCP header (20 bytes)
            0x00, 0x50, 0x01, 0xBB, // Src Port (80), Dst Port (443)
            0x00, 0x00, 0x00, 0x01, // Sequence Number
            0x00, 0x00, 0x00, 0x01, // Ack Number
            0x50, 0x18, 0x00, 0x00, // Data Offset, Flags (ACK+PSH), Window
            0x00, 0x00, 0x00, 0x00, // Checksum, Urgent Pointer
        ]
    }

    #[test]
    fn test_packet_parse() {
        let data = create_test_tcp_packet();
        let packet = Packet::from_bytes(&data, Direction::Outbound).unwrap();

        assert!(packet.is_tcp());
        assert!(packet.is_ipv4());
        assert_eq!(packet.src_port, 80);
        assert_eq!(packet.dst_port, 443);
        assert_eq!(packet.ttl, 64);
    }

    #[test]
    fn test_tcp_flags() {
        let data = create_test_tcp_packet();
        let packet = Packet::from_bytes(&data, Direction::Outbound).unwrap();

        let flags = packet.tcp_flags.unwrap();
        assert!(flags.ack);
        assert!(flags.psh);
        assert!(!flags.syn);
    }

    #[test]
    fn test_packet_too_small() {
        let data = vec![0x45, 0x00];
        let result = Packet::from_bytes(&data, Direction::Outbound);
        assert!(matches!(result, Err(Error::PacketTooSmall { .. })));
    }
}
