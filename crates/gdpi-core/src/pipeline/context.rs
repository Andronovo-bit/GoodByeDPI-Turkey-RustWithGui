//! Pipeline execution context
//!
//! Shared state and utilities for strategy execution.

use crate::conntrack::{DnsConnTracker, TcpConnTracker};
use crate::filter::{DomainFilter, FilterMode, FilterResult};
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
    /// Domains filtered (skipped)
    pub domains_filtered: u64,
}

/// Execution context for the pipeline
///
/// Provides shared state between strategies including connection tracking,
/// domain filtering, and statistics.
pub struct Context {
    /// Processing statistics
    pub stats: Stats,
    /// Domain filter (whitelist/blacklist)
    domain_filter: Arc<DomainFilter>,
    /// TCP connection tracker (for TTL)
    tcp_tracker: Arc<TcpConnTracker>,
    /// DNS connection tracker
    dns_tracker: Arc<DnsConnTracker>,
    /// Allow connections without SNI
    pub allow_no_sni: bool,
    
    // Legacy compatibility
    /// Whether blacklist filtering is enabled (legacy)
    pub blacklist_enabled: bool,
    /// Blacklisted domains (legacy)
    blacklist: Arc<DashSet<String>>,
}

impl Context {
    /// Create a new context
    pub fn new() -> Self {
        Self {
            stats: Stats::default(),
            domain_filter: Arc::new(DomainFilter::new()),
            tcp_tracker: Arc::new(TcpConnTracker::new()),
            dns_tracker: Arc::new(DnsConnTracker::new()),
            allow_no_sni: false,
            blacklist_enabled: false,
            blacklist: Arc::new(DashSet::new()),
        }
    }

    /// Create context with domain filter
    pub fn with_filter(filter: DomainFilter) -> Self {
        let filter_enabled = filter.mode() != FilterMode::Disabled;
        Self {
            stats: Stats::default(),
            domain_filter: Arc::new(filter),
            tcp_tracker: Arc::new(TcpConnTracker::new()),
            dns_tracker: Arc::new(DnsConnTracker::new()),
            allow_no_sni: false,
            blacklist_enabled: filter_enabled,
            blacklist: Arc::new(DashSet::new()),
        }
    }

    /// Create context with blacklist (legacy)
    pub fn with_blacklist(domains: Vec<String>) -> Self {
        let blacklist = Arc::new(DashSet::new());
        for domain in &domains {
            blacklist.insert(domain.to_lowercase());
        }
        
        // Also create new filter
        let filter = DomainFilter::with_domains(FilterMode::Blacklist, domains);
        
        Self {
            stats: Stats::default(),
            domain_filter: Arc::new(filter),
            blacklist_enabled: true,
            blacklist,
            tcp_tracker: Arc::new(TcpConnTracker::new()),
            dns_tracker: Arc::new(DnsConnTracker::new()),
            allow_no_sni: false,
        }
    }

    /// Get domain filter reference
    pub fn filter(&self) -> &DomainFilter {
        &self.domain_filter
    }

    /// Check if bypass should be applied to a hostname
    pub fn should_apply_bypass(&self, hostname: &str) -> bool {
        match self.domain_filter.check(hostname) {
            FilterResult::ApplyBypass => true,
            FilterResult::SkipBypass => false,
        }
    }

    /// Check if a hostname is blacklisted (legacy - use should_apply_bypass instead)
    ///
    /// Also checks parent domains (e.g., "sub.example.com" matches "example.com")
    pub fn is_blacklisted(&self, hostname: &str) -> bool {
        // Use new filter system
        self.should_apply_bypass(hostname)
    }

    /// Add a domain to the blacklist
    pub fn add_to_blacklist(&self, domain: &str) {
        self.blacklist.insert(domain.to_lowercase());
        self.domain_filter.add_domain(domain);
    }

    /// Load blacklist from a file
    pub fn load_blacklist_file(&self, path: &str) -> std::io::Result<usize> {
        self.domain_filter.load_file(path)
    }

    /// Check and reload filter file if changed
    pub fn check_filter_reload(&self) -> std::io::Result<bool> {
        self.domain_filter.check_reload()
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
        let ctx = Context::with_blacklist(vec!["*.example.com".to_string()]);
        
        assert!(ctx.is_blacklisted("sub.example.com"));
        assert!(ctx.is_blacklisted("deep.sub.example.com"));
    }

    #[test]
    fn test_filter_disabled() {
        let ctx = Context::new();
        
        // When filter is disabled, everything should get bypass
        assert!(ctx.should_apply_bypass("anything.com"));
    }

    #[test]
    fn test_whitelist_mode() {
        let filter = DomainFilter::with_domains(
            FilterMode::Whitelist,
            vec!["bank.com".to_string()],
        );
        let ctx = Context::with_filter(filter);
        
        // Whitelisted domains should NOT get bypass
        assert!(!ctx.should_apply_bypass("bank.com"));
        // Others should get bypass
        assert!(ctx.should_apply_bypass("youtube.com"));
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

