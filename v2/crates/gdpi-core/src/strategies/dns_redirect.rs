//! DNS redirection strategy
//!
//! Redirects DNS queries to alternative DNS servers to bypass DNS-based blocking.

use super::{Strategy, StrategyAction};
use crate::error::Result;
use crate::packet::Packet;
use crate::pipeline::Context;
use std::net::Ipv4Addr;
use tracing::{debug, instrument};

/// DNS redirection strategy
pub struct DnsRedirectStrategy {
    /// Upstream DNS server IPv4 address
    upstream_addr: Ipv4Addr,
    /// Upstream DNS port
    upstream_port: u16,
}

impl DnsRedirectStrategy {
    /// Create a new DNS redirection strategy
    pub fn new(upstream_addr: Ipv4Addr, upstream_port: u16) -> Self {
        Self {
            upstream_addr,
            upstream_port,
        }
    }

    /// Create with Yandex DNS (default for Turkey)
    pub fn yandex() -> Self {
        Self::new(Ipv4Addr::new(77, 88, 8, 8), 53)
    }

    /// Create with Cloudflare DNS
    pub fn cloudflare() -> Self {
        Self::new(Ipv4Addr::new(1, 1, 1, 1), 53)
    }

    /// Create with Google DNS
    pub fn google() -> Self {
        Self::new(Ipv4Addr::new(8, 8, 8, 8), 53)
    }

    /// Check if payload looks like a DNS query
    fn is_dns_query(&self, payload: &[u8]) -> bool {
        if payload.len() < 12 {
            return false;
        }

        // Check DNS header flags
        // Bits: QR(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4)
        // For query: QR=0, typically flags are 0x0100 (RD set)
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        
        // QR bit should be 0 (query, not response)
        if flags & 0x8000 != 0 {
            return false;
        }

        // Check question count is at least 1
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if qdcount == 0 {
            return false;
        }

        // Answer count should be 0 for queries
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);
        if ancount != 0 {
            return false;
        }

        true
    }

    /// Modify packet to redirect to upstream DNS
    fn redirect_packet(&self, packet: &mut Packet) {
        let data = packet.as_bytes_mut();

        // Modify destination IP address (IPv4 at offset 16-19)
        let octets = self.upstream_addr.octets();
        data[16] = octets[0];
        data[17] = octets[1];
        data[18] = octets[2];
        data[19] = octets[3];

        // Modify destination port in UDP header
        // UDP header starts after IP header (typically at offset 20)
        let ip_header_len = ((data[0] & 0x0F) * 4) as usize;
        let port_bytes = self.upstream_port.to_be_bytes();
        data[ip_header_len + 2] = port_bytes[0];
        data[ip_header_len + 3] = port_bytes[1];
    }
}

impl Strategy for DnsRedirectStrategy {
    fn name(&self) -> &'static str {
        "dns_redirect"
    }

    fn priority(&self) -> u8 {
        // DNS redirection runs early
        20
    }

    fn should_apply(&self, packet: &Packet, _ctx: &Context) -> bool {
        // Apply to outbound UDP port 53 (DNS)
        packet.is_outbound() 
            && packet.is_udp() 
            && packet.dst_port == 53
            && packet.is_ipv4()
    }

    #[instrument(skip(self, ctx), fields(strategy = self.name()))]
    fn apply(&self, mut packet: Packet, ctx: &mut Context) -> Result<StrategyAction> {
        if !self.is_dns_query(packet.payload()) {
            return Ok(StrategyAction::Pass(packet));
        }

        // Store original destination for response mapping
        ctx.dns_track_query(
            packet.src_port,
            packet.dst_addr,
            packet.dst_port,
        );

        // Redirect to upstream DNS
        self.redirect_packet(&mut packet);

        ctx.stats.dns_redirected += 1;
        debug!(
            upstream = %self.upstream_addr,
            port = self.upstream_port,
            "Redirecting DNS query"
        );

        Ok(StrategyAction::Pass(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_query_detection() {
        let strategy = DnsRedirectStrategy::yandex();

        // Valid DNS query header
        let query = [
            0x12, 0x34,             // Transaction ID
            0x01, 0x00,             // Flags: standard query, recursion desired
            0x00, 0x01,             // Questions: 1
            0x00, 0x00,             // Answer RRs: 0
            0x00, 0x00,             // Authority RRs: 0
            0x00, 0x00,             // Additional RRs: 0
        ];

        assert!(strategy.is_dns_query(&query));
    }

    #[test]
    fn test_dns_response_not_query() {
        let strategy = DnsRedirectStrategy::yandex();

        // DNS response header (QR bit set)
        let response = [
            0x12, 0x34,             // Transaction ID
            0x81, 0x80,             // Flags: response
            0x00, 0x01,             // Questions: 1
            0x00, 0x01,             // Answer RRs: 1
            0x00, 0x00,             // Authority RRs: 0
            0x00, 0x00,             // Additional RRs: 0
        ];

        assert!(!strategy.is_dns_query(&response));
    }

    #[test]
    fn test_predefined_servers() {
        let yandex = DnsRedirectStrategy::yandex();
        assert_eq!(yandex.upstream_addr, Ipv4Addr::new(77, 88, 8, 8));

        let cloudflare = DnsRedirectStrategy::cloudflare();
        assert_eq!(cloudflare.upstream_addr, Ipv4Addr::new(1, 1, 1, 1));

        let google = DnsRedirectStrategy::google();
        assert_eq!(google.upstream_addr, Ipv4Addr::new(8, 8, 8, 8));
    }
}
