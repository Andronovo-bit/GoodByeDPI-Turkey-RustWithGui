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

    // =========== TcpFlags Tests ===========
    
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
    fn test_tcp_flags_all_set() {
        let flags = TcpFlags {
            fin: true,
            syn: true,
            rst: true,
            psh: true,
            ack: true,
            urg: true,
            ece: true,
            cwr: true,
        };
        
        assert_eq!(flags.to_byte(), 0xFF);
        assert_eq!(TcpFlags::from_byte(0xFF), flags);
    }

    #[test]
    fn test_tcp_flags_none_set() {
        let flags = TcpFlags::default();
        assert_eq!(flags.to_byte(), 0x00);
    }

    #[test]
    fn test_tcp_flags_individual() {
        // Test each flag individually
        assert_eq!(TcpFlags::from_byte(0x01).fin, true);
        assert_eq!(TcpFlags::from_byte(0x02).syn, true);
        assert_eq!(TcpFlags::from_byte(0x04).rst, true);
        assert_eq!(TcpFlags::from_byte(0x08).psh, true);
        assert_eq!(TcpFlags::from_byte(0x10).ack, true);
        assert_eq!(TcpFlags::from_byte(0x20).urg, true);
        assert_eq!(TcpFlags::from_byte(0x40).ece, true);
        assert_eq!(TcpFlags::from_byte(0x80).cwr, true);
    }

    #[test]
    fn test_tcp_flags_syn_ack() {
        // Common SYN-ACK combination
        let flags = TcpFlags::from_byte(0x12); // SYN + ACK
        assert!(flags.syn);
        assert!(flags.ack);
        assert!(!flags.fin);
        assert!(!flags.rst);
    }

    // =========== Protocol Tests ===========
    
    #[test]
    fn test_protocol_from_u8() {
        assert_eq!(Protocol::from_u8(6), Protocol::Tcp);
        assert_eq!(Protocol::from_u8(17), Protocol::Udp);
        assert_eq!(Protocol::from_u8(1), Protocol::Icmp);
        assert_eq!(Protocol::from_u8(58), Protocol::Icmpv6);
        assert_eq!(Protocol::from_u8(99), Protocol::Unknown);
        assert_eq!(Protocol::from_u8(0), Protocol::Unknown);
        assert_eq!(Protocol::from_u8(255), Protocol::Unknown);
    }

    #[test]
    fn test_protocol_to_u8() {
        assert_eq!(Protocol::Tcp.to_u8(), 6);
        assert_eq!(Protocol::Udp.to_u8(), 17);
        assert_eq!(Protocol::Icmp.to_u8(), 1);
        assert_eq!(Protocol::Icmpv6.to_u8(), 58);
        assert_eq!(Protocol::Unknown.to_u8(), 0);
    }

    #[test]
    fn test_protocol_roundtrip() {
        for proto in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp, Protocol::Icmpv6] {
            let num = proto.to_u8();
            assert_eq!(Protocol::from_u8(num), proto);
        }
    }

    // =========== Direction Tests ===========
    
    #[test]
    fn test_direction_equality() {
        assert_eq!(Direction::Outbound, Direction::Outbound);
        assert_eq!(Direction::Inbound, Direction::Inbound);
        assert_ne!(Direction::Outbound, Direction::Inbound);
    }

    // =========== IpVersion Tests ===========
    
    #[test]
    fn test_ip_version_equality() {
        assert_eq!(IpVersion::V4, IpVersion::V4);
        assert_eq!(IpVersion::V6, IpVersion::V6);
        assert_ne!(IpVersion::V4, IpVersion::V6);
    }

    // =========== Ports Tests ===========
    
    #[test]
    fn test_well_known_ports() {
        assert_eq!(ports::HTTP, 80);
        assert_eq!(ports::HTTPS, 443);
        assert_eq!(ports::DNS, 53);
        assert_eq!(ports::QUIC, 443);
    }
}
