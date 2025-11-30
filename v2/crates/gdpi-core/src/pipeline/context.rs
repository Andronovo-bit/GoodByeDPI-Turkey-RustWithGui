//! Pipeline execution context
//!
//! Shared state and utilities for strategy execution.

use crate::conntrack::{DnsConnTracker, TcpConnTracker};
use crate::packet::Packet;
use dashmap::DashSet;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

/// Statistics for pipeline execution
#[derive(Debug, Default, Clone)]
pub struct Stats {
    /// Total packets processed
    pub packets_processed: u64,
    /// Packets fragmented
    pub packets_fragmented: u64,
    /// Fake packets sent
    pub fake_packets_sent: u64,
    /// Headers modified
    pub headers_modified: u64,
    /// QUIC packets blocked
    pub quic_blocked: u64,
    /// DNS queries redirected
    pub dns_redirected: u64,
    /// Packets dropped
    pub packets_dropped: u64,
}

/// Execution context for the pipeline
///
/// Provides shared state between strategies including connection tracking,
/// blacklist checking, and statistics.
pub struct Context {
    /// Processing statistics
    pub stats: Stats,
    /// Whether blacklist filtering is enabled
    pub blacklist_enabled: bool,
    /// Blacklisted domains
    blacklist: Arc<DashSet<String>>,
    /// TCP connection tracker (for TTL)
    tcp_tracker: Arc<TcpConnTracker>,
    /// DNS connection tracker
    dns_tracker: Arc<DnsConnTracker>,
}

impl Context {
    /// Create a new context
    pub fn new() -> Self {
        Self {
            stats: Stats::default(),
            blacklist_enabled: false,
            blacklist: Arc::new(DashSet::new()),
            tcp_tracker: Arc::new(TcpConnTracker::new()),
            dns_tracker: Arc::new(DnsConnTracker::new()),
        }
    }

    /// Create context with blacklist
    pub fn with_blacklist(domains: Vec<String>) -> Self {
        let blacklist = Arc::new(DashSet::new());
        for domain in domains {
            blacklist.insert(domain.to_lowercase());
        }
        
        Self {
            stats: Stats::default(),
            blacklist_enabled: true,
            blacklist,
            tcp_tracker: Arc::new(TcpConnTracker::new()),
            dns_tracker: Arc::new(DnsConnTracker::new()),
        }
    }

    /// Check if a hostname is blacklisted
    ///
    /// Also checks parent domains (e.g., "sub.example.com" matches "example.com")
    pub fn is_blacklisted(&self, hostname: &str) -> bool {
        if !self.blacklist_enabled {
            return true; // If blacklist disabled, process all
        }

        let hostname = hostname.to_lowercase();

        // Check exact match
        if self.blacklist.contains(&hostname) {
            return true;
        }

        // Check parent domains
        let mut current = hostname.as_str();
        while let Some(pos) = current.find('.') {
            current = &current[pos + 1..];
            if self.blacklist.contains(current) {
                return true;
            }
        }

        false
    }

    /// Add a domain to the blacklist
    pub fn add_to_blacklist(&self, domain: &str) {
        self.blacklist.insert(domain.to_lowercase());
    }

    /// Load blacklist from a file
    pub fn load_blacklist_file(&self, path: &str) -> std::io::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let mut count = 0;

        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                self.blacklist.insert(line.to_lowercase());
                count += 1;
            }
        }

        Ok(count)
    }

    /// Get the TTL for a connection (from SYN-ACK tracking)
    pub fn get_connection_ttl(&self, packet: &Packet) -> Option<u8> {
        self.tcp_tracker.get_ttl(
            packet.dst_addr,
            packet.dst_port,
            packet.src_addr,
            packet.src_port,
        )
    }

    /// Record a TCP connection's TTL (called on SYN-ACK)
    pub fn record_connection_ttl(&self, packet: &Packet) {
        if packet.is_syn_ack() {
            self.tcp_tracker.record(
                packet.src_addr,
                packet.src_port,
                packet.dst_addr,
                packet.dst_port,
                packet.ttl,
            );
        }
    }

    /// Track a DNS query for response mapping
    pub fn dns_track_query(&self, src_port: u16, original_dst: IpAddr, original_port: u16) {
        self.dns_tracker.track_query(src_port, original_dst, original_port);
    }

    /// Look up original DNS destination for a response
    pub fn dns_get_original(&self, src_port: u16) -> Option<(IpAddr, u16)> {
        self.dns_tracker.get_original(src_port)
    }

    /// Get current statistics
    pub fn get_stats(&self) -> Stats {
        self.stats.clone()
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = Stats::default();
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blacklist_exact_match() {
        let ctx = Context::with_blacklist(vec!["example.com".to_string()]);
        
        assert!(ctx.is_blacklisted("example.com"));
        assert!(ctx.is_blacklisted("EXAMPLE.COM")); // Case insensitive
        assert!(!ctx.is_blacklisted("other.com"));
    }

    #[test]
    fn test_blacklist_subdomain_match() {
        let ctx = Context::with_blacklist(vec!["example.com".to_string()]);
        
        assert!(ctx.is_blacklisted("sub.example.com"));
        assert!(ctx.is_blacklisted("deep.sub.example.com"));
        assert!(!ctx.is_blacklisted("notexample.com"));
    }

    #[test]
    fn test_blacklist_disabled() {
        let ctx = Context::new();
        
        // When blacklist is disabled, everything should match
        assert!(ctx.is_blacklisted("anything.com"));
    }

    #[test]
    fn test_stats() {
        let mut ctx = Context::new();
        
        ctx.stats.packets_processed = 100;
        ctx.stats.packets_fragmented = 50;
        
        let stats = ctx.get_stats();
        assert_eq!(stats.packets_processed, 100);
        assert_eq!(stats.packets_fragmented, 50);

        ctx.reset_stats();
        assert_eq!(ctx.stats.packets_processed, 0);
    }
}
