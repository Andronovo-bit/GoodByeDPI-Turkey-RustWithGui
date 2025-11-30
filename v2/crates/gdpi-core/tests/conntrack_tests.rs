//! Integration tests for connection tracking

use gdpi_core::conntrack::{DnsConnTracker, TcpConnTracker};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

// ============ TCP Connection Tracker Tests ============

#[test]
fn test_tcp_tracker_basic() {
    let tracker = TcpConnTracker::new();
    
    let server = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)); // example.com
    let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    
    // Record TTL from SYN-ACK
    tracker.record(server, 443, client, 54321, 52);
    
    // Retrieve TTL
    let ttl = tracker.get_ttl(server, 443, client, 54321);
    assert_eq!(ttl, Some(52));
}

#[test]
fn test_tcp_tracker_multiple_connections() {
    let tracker = TcpConnTracker::new();
    
    let google = IpAddr::V4(Ipv4Addr::new(142, 250, 74, 46));
    let cloudflare = IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229));
    let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    
    // Record multiple connections
    tracker.record(google, 443, client, 50000, 55);
    tracker.record(cloudflare, 443, client, 50001, 48);
    tracker.record(google, 80, client, 50002, 55);
    
    // Verify each connection has correct TTL
    assert_eq!(tracker.get_ttl(google, 443, client, 50000), Some(55));
    assert_eq!(tracker.get_ttl(cloudflare, 443, client, 50001), Some(48));
    assert_eq!(tracker.get_ttl(google, 80, client, 50002), Some(55));
    
    // Non-existent connection
    assert_eq!(tracker.get_ttl(google, 443, client, 59999), None);
}

#[test]
fn test_tcp_tracker_ipv6() {
    let tracker = TcpConnTracker::new();
    
    let server = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x6811));
    let client = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    
    tracker.record(server, 443, client, 12345, 64);
    
    assert_eq!(tracker.get_ttl(server, 443, client, 12345), Some(64));
}

#[test]
fn test_tcp_tracker_expiration() {
    let tracker = TcpConnTracker::with_timeout(Duration::from_millis(50));
    
    let server = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    
    tracker.record(server, 443, client, 11111, 50);
    assert_eq!(tracker.get_ttl(server, 443, client, 11111), Some(50));
    
    // Wait for expiration
    std::thread::sleep(Duration::from_millis(60));
    
    // Should be expired
    assert_eq!(tracker.get_ttl(server, 443, client, 11111), None);
}

#[test]
fn test_tcp_tracker_cleanup() {
    let tracker = TcpConnTracker::with_timeout(Duration::from_millis(20));
    
    let server = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    
    // Add multiple entries
    for port in 10000..10100 {
        tracker.record(server, 443, client, port, 64);
    }
    
    assert_eq!(tracker.len(), 100);
    
    // Wait and cleanup
    std::thread::sleep(Duration::from_millis(30));
    tracker.cleanup();
    
    assert_eq!(tracker.len(), 0);
}

// ============ DNS Connection Tracker Tests ============

#[test]
fn test_dns_tracker_basic() {
    let tracker = DnsConnTracker::new();
    
    let original_dns = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    
    // Track a DNS query
    tracker.track_query(12345, original_dns, 53);
    
    // Get original destination
    let result = tracker.get_original(12345);
    assert_eq!(result, Some((original_dns, 53)));
}

#[test]
fn test_dns_tracker_multiple_queries() {
    let tracker = DnsConnTracker::new();
    
    let google_dns = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let cloudflare_dns = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    
    tracker.track_query(10001, google_dns, 53);
    tracker.track_query(10002, cloudflare_dns, 53);
    
    assert_eq!(tracker.get_original(10001), Some((google_dns, 53)));
    assert_eq!(tracker.get_original(10002), Some((cloudflare_dns, 53)));
}

#[test]
fn test_dns_tracker_remove() {
    let tracker = DnsConnTracker::new();
    let dns = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    
    tracker.track_query(12345, dns, 53);
    assert_eq!(tracker.len(), 1);
    
    // Remove after response
    tracker.remove(12345);
    
    assert_eq!(tracker.len(), 0);
    assert_eq!(tracker.get_original(12345), None);
}

#[test]
fn test_dns_tracker_expiration() {
    let tracker = DnsConnTracker::with_timeout(Duration::from_millis(50));
    let dns = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    
    tracker.track_query(55555, dns, 53);
    
    std::thread::sleep(Duration::from_millis(60));
    
    // Should be expired
    assert_eq!(tracker.get_original(55555), None);
}

#[test]
fn test_dns_tracker_high_volume() {
    let tracker = DnsConnTracker::new();
    let dns = IpAddr::V4(Ipv4Addr::new(77, 88, 8, 8)); // Yandex
    
    // Simulate high DNS query volume
    for port in 40000..41000 {
        tracker.track_query(port, dns, 53);
    }
    
    assert_eq!(tracker.len(), 1000);
    
    // Verify random lookups
    assert_eq!(tracker.get_original(40500), Some((dns, 53)));
    assert_eq!(tracker.get_original(40999), Some((dns, 53)));
    
    // Clear
    tracker.clear();
    assert!(tracker.is_empty());
}
