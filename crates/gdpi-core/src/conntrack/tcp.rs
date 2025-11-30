//! TCP Connection Tracking
//!
//! Tracks TCP connections for Auto-TTL feature.
//! When a SYN-ACK is received, we record the TTL value.
//! This TTL is then used for fake packets to ensure they
//! reach the DPI but not the actual server.

use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Connection key for tracking
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ConnKey {
    /// Server IP (remote)
    server_ip: IpAddr,
    /// Server port (remote)
    server_port: u16,
    /// Client IP (local)
    client_ip: IpAddr,
    /// Client port (local)
    client_port: u16,
}

/// Connection information
#[derive(Debug, Clone)]
struct ConnInfo {
    /// TTL value from SYN-ACK
    ttl: u8,
    /// When this entry was created
    created: Instant,
}

/// TCP connection tracker for Auto-TTL
///
/// Thread-safe tracker that stores TTL values from SYN-ACK packets.
pub struct TcpConnTracker {
    /// Connection map
    connections: DashMap<ConnKey, ConnInfo>,
    /// Entry timeout (default 60 seconds)
    timeout: Duration,
}

impl TcpConnTracker {
    /// Create a new TCP connection tracker
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            timeout: Duration::from_secs(60),
        }
    }

    /// Create with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            connections: DashMap::new(),
            timeout,
        }
    }

    /// Record a connection's TTL (from SYN-ACK)
    ///
    /// # Arguments
    /// * `server_ip` - Server IP address (source of SYN-ACK)
    /// * `server_port` - Server port (source port of SYN-ACK)
    /// * `client_ip` - Client IP address (destination of SYN-ACK)
    /// * `client_port` - Client port (destination port of SYN-ACK)
    /// * `ttl` - TTL value from the packet
    pub fn record(
        &self,
        server_ip: IpAddr,
        server_port: u16,
        client_ip: IpAddr,
        client_port: u16,
        ttl: u8,
    ) {
        let key = ConnKey {
            server_ip,
            server_port,
            client_ip,
            client_port,
        };

        let info = ConnInfo {
            ttl,
            created: Instant::now(),
        };

        self.connections.insert(key, info);
    }

    /// Get the TTL for a connection
    ///
    /// # Arguments
    /// * `dst_ip` - Destination IP (server we're sending to)
    /// * `dst_port` - Destination port
    /// * `src_ip` - Source IP (our local IP)
    /// * `src_port` - Source port (our local port)
    ///
    /// # Returns
    /// * `Some(ttl)` - The recorded TTL if found and not expired
    /// * `None` - If no record exists or it has expired
    pub fn get_ttl(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        src_ip: IpAddr,
        src_port: u16,
    ) -> Option<u8> {
        let key = ConnKey {
            server_ip: dst_ip,
            server_port: dst_port,
            client_ip: src_ip,
            client_port: src_port,
        };

        if let Some(info) = self.connections.get(&key) {
            if info.created.elapsed() < self.timeout {
                return Some(info.ttl);
            } else {
                // Entry expired, remove it
                drop(info);
                self.connections.remove(&key);
            }
        }

        None
    }

    /// Clean up expired entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.connections.retain(|_, info| {
            now.duration_since(info.created) < self.timeout
        });
    }

    /// Get the number of tracked connections
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Check if tracker is empty
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.connections.clear();
    }
}

impl Default for TcpConnTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_record_and_get() {
        let tracker = TcpConnTracker::new();
        let server_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        // Record TTL from SYN-ACK
        tracker.record(server_ip, 443, client_ip, 12345, 52);

        // Get TTL when sending packet
        let ttl = tracker.get_ttl(server_ip, 443, client_ip, 12345);
        assert_eq!(ttl, Some(52));
    }

    #[test]
    fn test_missing_entry() {
        let tracker = TcpConnTracker::new();
        let server_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        let ttl = tracker.get_ttl(server_ip, 443, client_ip, 12345);
        assert_eq!(ttl, None);
    }

    #[test]
    fn test_expired_entry() {
        let tracker = TcpConnTracker::with_timeout(Duration::from_millis(10));
        let server_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        tracker.record(server_ip, 443, client_ip, 12345, 52);
        
        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        let ttl = tracker.get_ttl(server_ip, 443, client_ip, 12345);
        assert_eq!(ttl, None);
    }

    #[test]
    fn test_ipv6() {
        let tracker = TcpConnTracker::new();
        let server_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let client_ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));

        tracker.record(server_ip, 443, client_ip, 54321, 64);

        let ttl = tracker.get_ttl(server_ip, 443, client_ip, 54321);
        assert_eq!(ttl, Some(64));
    }

    #[test]
    fn test_cleanup() {
        let tracker = TcpConnTracker::with_timeout(Duration::from_millis(10));
        let server_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        tracker.record(server_ip, 80, client_ip, 11111, 64);
        tracker.record(server_ip, 443, client_ip, 22222, 64);
        
        assert_eq!(tracker.len(), 2);

        std::thread::sleep(Duration::from_millis(20));
        tracker.cleanup();

        assert_eq!(tracker.len(), 0);
    }
}
