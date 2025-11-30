//! DNS Connection Tracking
//!
//! Tracks DNS queries for response remapping.
//! When we redirect a DNS query to an alternative DNS server,
//! we need to remember where to send the response back.

use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// DNS query information
#[derive(Debug, Clone)]
struct QueryInfo {
    /// Original destination IP
    original_dst_ip: IpAddr,
    /// Original destination port
    original_dst_port: u16,
    /// When the query was made
    created: Instant,
}

/// DNS connection tracker
///
/// Thread-safe tracker that maps DNS queries to their original destinations.
/// This is needed because we redirect DNS queries to alternative servers,
/// but the response needs to appear as if it came from the original DNS server.
pub struct DnsConnTracker {
    /// Query map: source_port -> original destination
    queries: DashMap<u16, QueryInfo>,
    /// Query timeout (default 5 seconds for DNS)
    timeout: Duration,
}

impl DnsConnTracker {
    /// Create a new DNS connection tracker
    pub fn new() -> Self {
        Self {
            queries: DashMap::new(),
            timeout: Duration::from_secs(5),
        }
    }

    /// Create with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            queries: DashMap::new(),
            timeout,
        }
    }

    /// Track a DNS query
    ///
    /// # Arguments
    /// * `src_port` - Source port of the DNS query (used as key)
    /// * `original_dst_ip` - Original DNS server IP
    /// * `original_dst_port` - Original DNS server port
    pub fn track_query(&self, src_port: u16, original_dst_ip: IpAddr, original_dst_port: u16) {
        let info = QueryInfo {
            original_dst_ip,
            original_dst_port,
            created: Instant::now(),
        };
        self.queries.insert(src_port, info);
    }

    /// Get the original destination for a DNS response
    ///
    /// # Arguments
    /// * `src_port` - Source port from the redirected query
    ///
    /// # Returns
    /// * `Some((ip, port))` - The original destination if found and not expired
    /// * `None` - If no record exists or it has expired
    pub fn get_original(&self, src_port: u16) -> Option<(IpAddr, u16)> {
        if let Some(info) = self.queries.get(&src_port) {
            if info.created.elapsed() < self.timeout {
                return Some((info.original_dst_ip, info.original_dst_port));
            } else {
                // Expired, remove entry
                drop(info);
                self.queries.remove(&src_port);
            }
        }
        None
    }

    /// Remove a query entry (called after response is received)
    pub fn remove(&self, src_port: u16) {
        self.queries.remove(&src_port);
    }

    /// Clean up expired entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.queries.retain(|_, info| {
            now.duration_since(info.created) < self.timeout
        });
    }

    /// Get the number of tracked queries
    pub fn len(&self) -> usize {
        self.queries.len()
    }

    /// Check if tracker is empty
    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.queries.clear();
    }
}

impl Default for DnsConnTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_track_and_get() {
        let tracker = DnsConnTracker::new();
        let original_dns = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // Track a query
        tracker.track_query(12345, original_dns, 53);

        // Get original destination
        let result = tracker.get_original(12345);
        assert_eq!(result, Some((original_dns, 53)));
    }

    #[test]
    fn test_missing_entry() {
        let tracker = DnsConnTracker::new();

        let result = tracker.get_original(59999);
        assert_eq!(result, None);
    }

    #[test]
    fn test_expired_entry() {
        let tracker = DnsConnTracker::with_timeout(Duration::from_millis(10));
        let original_dns = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        tracker.track_query(12345, original_dns, 53);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        let result = tracker.get_original(12345);
        assert_eq!(result, None);
    }

    #[test]
    fn test_remove() {
        let tracker = DnsConnTracker::new();
        let original_dns = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        tracker.track_query(12345, original_dns, 53);
        assert_eq!(tracker.len(), 1);

        tracker.remove(12345);
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn test_multiple_queries() {
        let tracker = DnsConnTracker::new();
        let dns1 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let dns2 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        tracker.track_query(11111, dns1, 53);
        tracker.track_query(22222, dns2, 53);

        assert_eq!(tracker.get_original(11111), Some((dns1, 53)));
        assert_eq!(tracker.get_original(22222), Some((dns2, 53)));
    }

    #[test]
    fn test_cleanup() {
        let tracker = DnsConnTracker::with_timeout(Duration::from_millis(10));
        let dns = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        tracker.track_query(11111, dns, 53);
        tracker.track_query(22222, dns, 53);
        
        assert_eq!(tracker.len(), 2);

        std::thread::sleep(Duration::from_millis(20));
        tracker.cleanup();

        assert_eq!(tracker.len(), 0);
    }
}
