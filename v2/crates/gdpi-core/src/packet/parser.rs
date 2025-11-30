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
    fn test_internet_checksum() {
        // Example from RFC 1071
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let checksum = PacketParser::internet_checksum(&data);
        assert_eq!(checksum, 0x220d);
    }
}
