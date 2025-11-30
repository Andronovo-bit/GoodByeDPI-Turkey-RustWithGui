//! Packet type definitions

use bitflags::bitflags;

/// Packet direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Packet is outbound (leaving the host)
    Outbound,
    /// Packet is inbound (arriving at the host)
    Inbound,
}

/// IP version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    /// IPv4
    V4,
    /// IPv6
    V6,
}

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP (protocol number 6)
    Tcp,
    /// UDP (protocol number 17)
    Udp,
    /// ICMP (protocol number 1)
    Icmp,
    /// ICMPv6 (protocol number 58)
    Icmpv6,
    /// Unknown protocol
    Unknown,
}

impl Protocol {
    /// Create from protocol number
    pub fn from_u8(proto: u8) -> Self {
        match proto {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            58 => Protocol::Icmpv6,
            _ => Protocol::Unknown,
        }
    }

    /// Get protocol number
    pub fn to_u8(self) -> u8 {
        match self {
            Protocol::Icmp => 1,
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmpv6 => 58,
            Protocol::Unknown => 0,
        }
    }
}

/// TCP flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags {
    /// FIN flag
    pub fin: bool,
    /// SYN flag
    pub syn: bool,
    /// RST flag
    pub rst: bool,
    /// PSH flag
    pub psh: bool,
    /// ACK flag
    pub ack: bool,
    /// URG flag
    pub urg: bool,
    /// ECE flag
    pub ece: bool,
    /// CWR flag
    pub cwr: bool,
}

impl TcpFlags {
    /// Create from TCP flags byte
    pub fn from_byte(byte: u8) -> Self {
        Self {
            fin: byte & 0x01 != 0,
            syn: byte & 0x02 != 0,
            rst: byte & 0x04 != 0,
            psh: byte & 0x08 != 0,
            ack: byte & 0x10 != 0,
            urg: byte & 0x20 != 0,
            ece: byte & 0x40 != 0,
            cwr: byte & 0x80 != 0,
        }
    }

    /// Convert to byte
    pub fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.fin { byte |= 0x01; }
        if self.syn { byte |= 0x02; }
        if self.rst { byte |= 0x04; }
        if self.psh { byte |= 0x08; }
        if self.ack { byte |= 0x10; }
        if self.urg { byte |= 0x20; }
        if self.ece { byte |= 0x40; }
        if self.cwr { byte |= 0x80; }
        byte
    }
}

/// Common well-known ports
pub mod ports {
    /// HTTP port
    pub const HTTP: u16 = 80;
    /// HTTPS port
    pub const HTTPS: u16 = 443;
    /// DNS port
    pub const DNS: u16 = 53;
    /// QUIC port (same as HTTPS)
    pub const QUIC: u16 = 443;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags_roundtrip() {
        let flags = TcpFlags {
            syn: true,
            ack: true,
            ..Default::default()
        };
        
        let byte = flags.to_byte();
        let parsed = TcpFlags::from_byte(byte);
        
        assert_eq!(flags, parsed);
    }

    #[test]
    fn test_protocol_from_u8() {
        assert_eq!(Protocol::from_u8(6), Protocol::Tcp);
        assert_eq!(Protocol::from_u8(17), Protocol::Udp);
        assert_eq!(Protocol::from_u8(99), Protocol::Unknown);
    }
}
