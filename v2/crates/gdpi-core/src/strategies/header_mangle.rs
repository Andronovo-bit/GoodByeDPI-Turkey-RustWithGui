//! HTTP header manipulation strategy
//!
//! Modifies HTTP headers to evade DPI inspection.

use super::{Strategy, StrategyAction};
use crate::config::HeaderMangleConfig;
use crate::error::Result;
use crate::packet::Packet;
use crate::pipeline::Context;
use tracing::{debug, instrument};

/// Header manipulation strategy
pub struct HeaderMangleStrategy {
    /// Replace "Host:" with "hoSt:"
    host_replace: bool,
    /// Remove space after Host:
    host_remove_space: bool,
    /// Mix case in Host header value
    host_mix_case: bool,
    /// Add space between method and URI
    additional_space: bool,
}

impl HeaderMangleStrategy {
    /// Create a new header mangle strategy
    pub fn new() -> Self {
        Self {
            host_replace: true,
            host_remove_space: true,
            host_mix_case: false,
            additional_space: false,
        }
    }

    /// Create from configuration
    pub fn from_config(config: &HeaderMangleConfig) -> Self {
        Self {
            host_replace: config.host_replace,
            host_remove_space: config.host_remove_space,
            host_mix_case: config.host_mix_case,
            additional_space: config.additional_space,
        }
    }

    /// Find "Host: " header in payload and return its position
    fn find_host_header(&self, payload: &[u8]) -> Option<(usize, usize)> {
        let marker = b"\r\nHost: ";
        for i in 0..payload.len().saturating_sub(marker.len()) {
            if &payload[i..i + marker.len()] == marker {
                // Find end of header value (next \r\n)
                let value_start = i + marker.len();
                for j in value_start..payload.len().saturating_sub(1) {
                    if &payload[j..j + 2] == b"\r\n" {
                        return Some((i, j));
                    }
                }
            }
        }
        None
    }

    /// Replace "Host:" with "hoSt:" in payload
    fn replace_host_header(&self, payload: &mut [u8]) -> bool {
        let marker = b"\r\nHost:";
        let replacement = b"\r\nhoSt:";

        for i in 0..payload.len().saturating_sub(marker.len()) {
            if &payload[i..i + marker.len()] == marker {
                payload[i..i + replacement.len()].copy_from_slice(replacement);
                return true;
            }
        }
        false
    }

    /// Mix case of hostname: "example.com" -> "eXaMpLe.CoM"
    fn mix_case_hostname(&self, hostname: &mut [u8]) {
        for (i, byte) in hostname.iter_mut().enumerate() {
            if i % 2 == 1 && byte.is_ascii_lowercase() {
                *byte = byte.to_ascii_uppercase();
            }
        }
    }

    /// Find HTTP method end position (e.g., "GET " -> position after "GET")
    fn find_method_end(&self, payload: &[u8]) -> Option<usize> {
        // HTTP methods we recognize
        let methods: &[&[u8]] = &[b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"CONNECT ", b"OPTIONS "];
        
        for method in methods {
            if payload.len() >= method.len() && &payload[..method.len()] == *method {
                return Some(method.len() - 1); // Position of the space
            }
        }
        None
    }
}

impl Default for HeaderMangleStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for HeaderMangleStrategy {
    fn name(&self) -> &'static str {
        "header_mangle"
    }

    fn priority(&self) -> u8 {
        // Run after fake packets but before fragmentation
        50
    }

    fn should_apply(&self, packet: &Packet, _ctx: &Context) -> bool {
        // Only apply to outbound HTTP requests
        packet.is_outbound() 
            && packet.is_tcp() 
            && packet.dst_port == 80
            && packet.is_http_request()
    }

    #[instrument(skip(self, ctx), fields(strategy = self.name()))]
    fn apply(&self, mut packet: Packet, ctx: &mut Context) -> Result<StrategyAction> {
        let mut modified = false;

        // Get mutable access to packet payload
        // Note: In real implementation, we need proper packet reconstruction
        let data = packet.as_bytes_mut();
        
        // Calculate payload offset
        let ip_header_len = ((data[0] & 0x0F) * 4) as usize;
        let tcp_header_len = ((data[ip_header_len + 12] >> 4) * 4) as usize;
        let payload_start = ip_header_len + tcp_header_len;

        if payload_start >= data.len() {
            return Ok(StrategyAction::Pass(packet));
        }

        let payload = &mut data[payload_start..];

        // Replace "Host:" with "hoSt:"
        if self.host_replace {
            if self.replace_host_header(payload) {
                modified = true;
                debug!("Replaced 'Host:' with 'hoSt:'");
            }
        }

        // Mix case in hostname
        if self.host_mix_case {
            if let Some((header_start, header_end)) = self.find_host_header(payload) {
                let value_start = header_start + 8; // "\r\nHost: ".len()
                if value_start < header_end {
                    self.mix_case_hostname(&mut payload[value_start..header_end]);
                    modified = true;
                    debug!("Mixed case in Host header value");
                }
            }
        }

        // Add additional space after method
        if self.additional_space {
            if let Some(method_end) = self.find_method_end(payload) {
                // This would require expanding the payload, which is complex
                // For now, we just note this is a TODO
                debug!("Additional space injection not yet implemented");
            }
        }

        if modified {
            ctx.stats.headers_modified += 1;
        }

        Ok(StrategyAction::Pass(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_header_replacement() {
        let mut payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let strategy = HeaderMangleStrategy::new();
        
        let result = strategy.replace_host_header(&mut payload);
        assert!(result);
        assert!(payload.windows(6).any(|w| w == b"\r\nhoSt"));
    }

    #[test]
    fn test_mix_case_hostname() {
        let mut hostname = b"example.com".to_vec();
        let strategy = HeaderMangleStrategy::new();
        
        strategy.mix_case_hostname(&mut hostname);
        
        // Check that odd-indexed lowercase letters are uppercased
        assert_eq!(&hostname, b"eXaMpLe.CoM");
    }

    #[test]
    fn test_find_method_end() {
        let strategy = HeaderMangleStrategy::new();
        
        assert_eq!(strategy.find_method_end(b"GET /path HTTP/1.1"), Some(3));
        assert_eq!(strategy.find_method_end(b"POST /path HTTP/1.1"), Some(4));
        assert_eq!(strategy.find_method_end(b"INVALID"), None);
    }
}
