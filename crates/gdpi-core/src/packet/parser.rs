//! Packet parser utilities

use crate::error::Result;

/// Packet parser for detailed protocol analysis
pub struct PacketParser;

impl PacketParser {
    /// Calculate Internet Checksum (RFC 1071)
    pub fn internet_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }

        // Handle odd byte
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }

        // Fold 32-bit sum to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }

    /// Calculate TCP checksum with pseudo-header
    pub fn tcp_checksum_ipv4(
        src_ip: &[u8; 4],
        dst_ip: &[u8; 4],
        tcp_segment: &[u8],
    ) -> u16 {
        let tcp_len = tcp_segment.len() as u16;

        // Build pseudo-header
        let mut pseudo = Vec::with_capacity(12 + tcp_segment.len());
        pseudo.extend_from_slice(src_ip);
        pseudo.extend_from_slice(dst_ip);
        pseudo.push(0); // Reserved
        pseudo.push(6); // Protocol (TCP)
        pseudo.extend_from_slice(&tcp_len.to_be_bytes());
        pseudo.extend_from_slice(tcp_segment);

        // Pad if odd length
        if pseudo.len() % 2 != 0 {
            pseudo.push(0);
        }

        Self::internet_checksum(&pseudo)
    }

    /// Calculate UDP checksum with pseudo-header
    pub fn udp_checksum_ipv4(
        src_ip: &[u8; 4],
        dst_ip: &[u8; 4],
        udp_segment: &[u8],
    ) -> u16 {
        let udp_len = udp_segment.len() as u16;

        // Build pseudo-header
        let mut pseudo = Vec::with_capacity(12 + udp_segment.len());
        pseudo.extend_from_slice(src_ip);
        pseudo.extend_from_slice(dst_ip);
        pseudo.push(0); // Reserved
        pseudo.push(17); // Protocol (UDP)
        pseudo.extend_from_slice(&udp_len.to_be_bytes());
        pseudo.extend_from_slice(udp_segment);

        // Pad if odd length
        if pseudo.len() % 2 != 0 {
            pseudo.push(0);
        }

        Self::internet_checksum(&pseudo)
    }

    /// Calculate IPv4 header checksum
    pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
        // Zero out existing checksum field for calculation
        let mut header_copy = header.to_vec();
        if header_copy.len() >= 12 {
            header_copy[10] = 0;
            header_copy[11] = 0;
        }
        Self::internet_checksum(&header_copy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internet_checksum_rfc1071() {
        // Example from RFC 1071
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let checksum = PacketParser::internet_checksum(&data);
        assert_eq!(checksum, 0x220d);
    }

    #[test]
    fn test_internet_checksum_empty() {
        let data: [u8; 0] = [];
        let checksum = PacketParser::internet_checksum(&data);
        assert_eq!(checksum, 0xFFFF); // !0 for empty data
    }

    #[test]
    fn test_internet_checksum_odd_length() {
        // Odd-length data should be padded
        let data = [0x00, 0x01, 0x02];
        let checksum = PacketParser::internet_checksum(&data);
        // Should handle odd byte correctly
        assert!(checksum != 0);
    }

    #[test]
    fn test_internet_checksum_all_zeros() {
        let data = [0x00, 0x00, 0x00, 0x00];
        let checksum = PacketParser::internet_checksum(&data);
        assert_eq!(checksum, 0xFFFF);
    }

    #[test]
    fn test_internet_checksum_all_ones() {
        let data = [0xFF, 0xFF, 0xFF, 0xFF];
        let checksum = PacketParser::internet_checksum(&data);
        assert_eq!(checksum, 0x0000);
    }

    #[test]
    fn test_tcp_checksum_ipv4() {
        // Create a minimal TCP segment
        let src_ip = [192, 168, 1, 1];
        let dst_ip = [192, 168, 1, 2];
        
        // TCP header with SYN flag
        let tcp_segment = [
            0x30, 0x39, // Source port: 12345
            0x00, 0x50, // Dest port: 80
            0x00, 0x00, 0x00, 0x01, // Seq num
            0x00, 0x00, 0x00, 0x00, // Ack num
            0x50, 0x02, // Data offset + SYN flag
            0x72, 0x10, // Window size
            0x00, 0x00, // Checksum (zero for calculation)
            0x00, 0x00, // Urgent pointer
        ];
        
        let checksum = PacketParser::tcp_checksum_ipv4(&src_ip, &dst_ip, &tcp_segment);
        // Checksum should be non-zero for valid data
        assert!(checksum != 0);
    }

    #[test]
    fn test_udp_checksum_ipv4() {
        let src_ip = [10, 0, 0, 1];
        let dst_ip = [10, 0, 0, 2];
        
        // Minimal UDP segment (8 byte header)
        let udp_segment = [
            0x00, 0x35, // Source port: 53 (DNS)
            0x00, 0x35, // Dest port: 53
            0x00, 0x08, // Length: 8 bytes
            0x00, 0x00, // Checksum (zero for calculation)
        ];
        
        let checksum = PacketParser::udp_checksum_ipv4(&src_ip, &dst_ip, &udp_segment);
        assert!(checksum != 0);
    }

    #[test]
    fn test_ipv4_header_checksum() {
        // Standard IPv4 header (20 bytes)
        let header = [
            0x45, 0x00, // Version, IHL, DSCP, ECN
            0x00, 0x3c, // Total length: 60
            0x1c, 0x46, // Identification
            0x40, 0x00, // Flags, Fragment offset
            0x40, 0x06, // TTL: 64, Protocol: TCP
            0x00, 0x00, // Checksum (will be calculated)
            0xac, 0x10, 0x0a, 0x63, // Source IP: 172.16.10.99
            0xac, 0x10, 0x0a, 0x0c, // Dest IP: 172.16.10.12
        ];
        
        let checksum = PacketParser::ipv4_header_checksum(&header);
        // Known checksum for this header is 0xb1e6
        assert_eq!(checksum, 0xb1e6);
    }

    #[test]
    fn test_checksum_verification() {
        // When a correct checksum is included, recalculating should give 0
        let header_with_checksum = [
            0x45, 0x00,
            0x00, 0x3c,
            0x1c, 0x46,
            0x40, 0x00,
            0x40, 0x06,
            0xb1, 0xe6, // Correct checksum
            0xac, 0x10, 0x0a, 0x63,
            0xac, 0x10, 0x0a, 0x0c,
        ];
        
        let verification = PacketParser::internet_checksum(&header_with_checksum);
        assert_eq!(verification, 0x0000); // Valid checksum
    }
}
