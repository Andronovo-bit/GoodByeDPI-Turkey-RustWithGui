//! WinDivert filter builder
//!
//! Type-safe builder for WinDivert filter expressions.

use std::fmt;

/// Filter builder for WinDivert
///
/// Provides a type-safe way to construct WinDivert filter expressions.
///
/// # Example
///
/// ```rust
/// use gdpi_platform::windows::FilterBuilder;
///
/// let filter = FilterBuilder::new()
///     .outbound()
///     .tcp()
///     .dst_port(443)
///     .or()
///     .dst_port(80)
///     .build();
///
/// assert_eq!(filter, "outbound and tcp and (tcp.DstPort == 443 or tcp.DstPort == 80)");
/// ```
#[derive(Debug, Clone)]
pub struct FilterBuilder {
    parts: Vec<FilterPart>,
}

#[derive(Debug, Clone)]
enum FilterPart {
    Keyword(String),
    Condition(String),
    And,
    Or,
    Not,
    GroupStart,
    GroupEnd,
}

impl FilterBuilder {
    /// Create a new filter builder
    pub fn new() -> Self {
        Self { parts: Vec::new() }
    }

    /// Add "outbound" condition
    pub fn outbound(mut self) -> Self {
        self.parts.push(FilterPart::Keyword("outbound".into()));
        self
    }

    /// Add "inbound" condition
    pub fn inbound(mut self) -> Self {
        self.parts.push(FilterPart::Keyword("inbound".into()));
        self
    }

    /// Add "tcp" protocol filter
    pub fn tcp(mut self) -> Self {
        self.parts.push(FilterPart::Keyword("tcp".into()));
        self
    }

    /// Add "udp" protocol filter
    pub fn udp(mut self) -> Self {
        self.parts.push(FilterPart::Keyword("udp".into()));
        self
    }

    /// Add "ip" protocol filter (IPv4)
    pub fn ip(mut self) -> Self {
        self.parts.push(FilterPart::Keyword("ip".into()));
        self
    }

    /// Add "ipv6" protocol filter
    pub fn ipv6(mut self) -> Self {
        self.parts.push(FilterPart::Keyword("ipv6".into()));
        self
    }

    /// Add "icmp" protocol filter
    pub fn icmp(mut self) -> Self {
        self.parts.push(FilterPart::Keyword("icmp".into()));
        self
    }

    /// Add "loopback" condition
    pub fn loopback(mut self) -> Self {
        self.parts.push(FilterPart::Keyword("loopback".into()));
        self
    }

    /// Add destination port condition
    pub fn dst_port(mut self, port: u16) -> Self {
        self.parts.push(FilterPart::Condition(format!("tcp.DstPort == {}", port)));
        self
    }

    /// Add destination port range
    pub fn dst_port_range(mut self, min: u16, max: u16) -> Self {
        self.parts.push(FilterPart::Condition(
            format!("(tcp.DstPort >= {} and tcp.DstPort <= {})", min, max)
        ));
        self
    }

    /// Add UDP destination port condition
    pub fn udp_dst_port(mut self, port: u16) -> Self {
        self.parts.push(FilterPart::Condition(format!("udp.DstPort == {}", port)));
        self
    }

    /// Add source port condition
    pub fn src_port(mut self, port: u16) -> Self {
        self.parts.push(FilterPart::Condition(format!("tcp.SrcPort == {}", port)));
        self
    }

    /// Add destination IP condition (IPv4)
    pub fn dst_addr(mut self, ip: &str) -> Self {
        self.parts.push(FilterPart::Condition(format!("ip.DstAddr == {}", ip)));
        self
    }

    /// Add source IP condition (IPv4)
    pub fn src_addr(mut self, ip: &str) -> Self {
        self.parts.push(FilterPart::Condition(format!("ip.SrcAddr == {}", ip)));
        self
    }

    /// Add TCP flags condition (SYN)
    pub fn tcp_syn(mut self) -> Self {
        self.parts.push(FilterPart::Condition("tcp.Syn".into()));
        self
    }

    /// Add TCP flags condition (ACK)
    pub fn tcp_ack(mut self) -> Self {
        self.parts.push(FilterPart::Condition("tcp.Ack".into()));
        self
    }

    /// Add TCP flags condition (PSH)
    pub fn tcp_psh(mut self) -> Self {
        self.parts.push(FilterPart::Condition("tcp.Psh".into()));
        self
    }

    /// Add TCP flags condition (RST)
    pub fn tcp_rst(mut self) -> Self {
        self.parts.push(FilterPart::Condition("tcp.Rst".into()));
        self
    }

    /// Add TCP flags condition (FIN)
    pub fn tcp_fin(mut self) -> Self {
        self.parts.push(FilterPart::Condition("tcp.Fin".into()));
        self
    }

    /// Add TCP payload size condition
    pub fn tcp_payload_size(mut self, op: &str, size: u32) -> Self {
        self.parts.push(FilterPart::Condition(
            format!("tcp.PayloadLength {} {}", op, size)
        ));
        self
    }

    /// Add "and" operator
    pub fn and(mut self) -> Self {
        self.parts.push(FilterPart::And);
        self
    }

    /// Add "or" operator
    pub fn or(mut self) -> Self {
        self.parts.push(FilterPart::Or);
        self
    }

    /// Add "not" operator
    pub fn not(mut self) -> Self {
        self.parts.push(FilterPart::Not);
        self
    }

    /// Start a group (open parenthesis)
    pub fn group_start(mut self) -> Self {
        self.parts.push(FilterPart::GroupStart);
        self
    }

    /// End a group (close parenthesis)
    pub fn group_end(mut self) -> Self {
        self.parts.push(FilterPart::GroupEnd);
        self
    }

    /// Add a raw condition
    pub fn raw(mut self, condition: &str) -> Self {
        self.parts.push(FilterPart::Condition(condition.into()));
        self
    }

    /// Build the filter string
    pub fn build(self) -> String {
        let mut result = String::new();
        let mut prev_was_keyword_or_condition = false;

        for part in self.parts {
            match part {
                FilterPart::Keyword(k) => {
                    if prev_was_keyword_or_condition {
                        result.push_str(" and ");
                    }
                    result.push_str(&k);
                    prev_was_keyword_or_condition = true;
                }
                FilterPart::Condition(c) => {
                    if prev_was_keyword_or_condition {
                        result.push_str(" and ");
                    }
                    result.push_str(&c);
                    prev_was_keyword_or_condition = true;
                }
                FilterPart::And => {
                    result.push_str(" and ");
                    prev_was_keyword_or_condition = false;
                }
                FilterPart::Or => {
                    result.push_str(" or ");
                    prev_was_keyword_or_condition = false;
                }
                FilterPart::Not => {
                    if prev_was_keyword_or_condition {
                        result.push_str(" and ");
                    }
                    result.push_str("not ");
                    prev_was_keyword_or_condition = false;
                }
                FilterPart::GroupStart => {
                    if prev_was_keyword_or_condition {
                        result.push_str(" and ");
                    }
                    result.push('(');
                    prev_was_keyword_or_condition = false;
                }
                FilterPart::GroupEnd => {
                    result.push(')');
                    prev_was_keyword_or_condition = true;
                }
            }
        }

        result
    }
}

impl Default for FilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Common filter presets for GoodbyeDPI
pub struct FilterPresets;

impl FilterPresets {
    /// Filter for HTTP (port 80) packets
    pub fn http_outbound() -> String {
        FilterBuilder::new()
            .outbound()
            .tcp()
            .dst_port(80)
            .tcp_psh()
            .tcp_ack()
            .build()
    }

    /// Filter for HTTPS (port 443) packets
    pub fn https_outbound() -> String {
        FilterBuilder::new()
            .outbound()
            .tcp()
            .dst_port(443)
            .build()
    }

    /// Filter for HTTPS Client Hello (first data packet)
    pub fn https_client_hello() -> String {
        FilterBuilder::new()
            .outbound()
            .tcp()
            .dst_port(443)
            .tcp_psh()
            .tcp_ack()
            .tcp_payload_size(">", 0)
            .build()
    }

    /// Filter for DNS (port 53) UDP packets
    pub fn dns_outbound() -> String {
        FilterBuilder::new()
            .outbound()
            .udp()
            .udp_dst_port(53)
            .build()
    }

    /// Filter for QUIC (UDP 443) packets
    pub fn quic_outbound() -> String {
        FilterBuilder::new()
            .outbound()
            .udp()
            .udp_dst_port(443)
            .build()
    }

    /// Filter for incoming SYN-ACK packets
    pub fn syn_ack_inbound() -> String {
        FilterBuilder::new()
            .inbound()
            .tcp()
            .tcp_syn()
            .tcp_ack()
            .build()
    }

    /// Combined filter for GoodbyeDPI (HTTP + HTTPS)
    pub fn goodbyedpi_basic() -> String {
        "outbound and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443)".into()
    }

    /// Full filter for GoodbyeDPI (HTTP + HTTPS + DNS + SYN-ACK)
    pub fn goodbyedpi_full() -> String {
        "(outbound and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443)) or \
         (outbound and udp and udp.DstPort == 53) or \
         (inbound and tcp and tcp.Syn and tcp.Ack)".into()
    }

    /// Turkey-optimized filter (includes QUIC blocking)
    pub fn turkey_optimized() -> String {
        "(outbound and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443)) or \
         (outbound and udp and (udp.DstPort == 53 or udp.DstPort == 443)) or \
         (inbound and tcp and tcp.Syn and tcp.Ack)".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_filter() {
        let filter = FilterBuilder::new()
            .outbound()
            .tcp()
            .build();
        
        assert_eq!(filter, "outbound and tcp");
    }

    #[test]
    fn test_port_filter() {
        let filter = FilterBuilder::new()
            .outbound()
            .tcp()
            .dst_port(443)
            .build();
        
        assert_eq!(filter, "outbound and tcp and tcp.DstPort == 443");
    }

    #[test]
    fn test_or_filter() {
        let filter = FilterBuilder::new()
            .outbound()
            .tcp()
            .group_start()
            .dst_port(80)
            .or()
            .dst_port(443)
            .group_end()
            .build();
        
        assert_eq!(filter, "outbound and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443)");
    }

    #[test]
    fn test_presets() {
        let http = FilterPresets::http_outbound();
        assert!(http.contains("tcp.DstPort == 80"));

        let https = FilterPresets::https_outbound();
        assert!(https.contains("tcp.DstPort == 443"));

        let dns = FilterPresets::dns_outbound();
        assert!(dns.contains("udp.DstPort == 53"));
    }
}
