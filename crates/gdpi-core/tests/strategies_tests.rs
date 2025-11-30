//! Integration tests for strategies
//!
//! Tests for packet manipulation strategies.

use gdpi_core::config::*;
use gdpi_core::strategies::*;

mod test_helpers {
    use gdpi_core::packet::{Direction, Packet};

    /// Create a mock HTTP GET request packet
    pub fn create_http_get(host: &str) -> Vec<u8> {
        let payload = format!("GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: test\r\n\r\n", host);
        let ip_header_len = 20;
        let tcp_header_len = 20;
        let total_len = (ip_header_len + tcp_header_len + payload.len()) as u16;

        let mut packet = vec![
            // IPv4 header
            0x45, 0x00,
            (total_len >> 8) as u8, (total_len & 0xFF) as u8,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0xC0, 0xA8, 0x01, 0x01,
            0xC0, 0xA8, 0x01, 0x02,
            // TCP header
            0x04, 0xD2, 0x00, 0x50, // Src: 1234, Dst: 80
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x18, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(payload.as_bytes());
        packet
    }

    /// Create TLS ClientHello with given SNI
    pub fn create_tls_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let sni_len = sni_bytes.len();
        
        // Simplified TLS structure
        let mut tls_payload = vec![
            0x16, 0x03, 0x01, // TLS record: Handshake
            0x00, 0x00,       // Length placeholder
            0x01,             // ClientHello
            0x00, 0x00, 0x00, // Length placeholder
            0x03, 0x03,       // TLS 1.2
        ];
        
        // Random (32 bytes)
        tls_payload.extend_from_slice(&[0u8; 32]);
        
        // Session ID (empty)
        tls_payload.push(0);
        
        // Cipher suites
        tls_payload.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]);
        
        // Compression
        tls_payload.extend_from_slice(&[0x01, 0x00]);
        
        // Extensions length placeholder
        let ext_start = tls_payload.len();
        tls_payload.extend_from_slice(&[0x00, 0x00]);
        
        // SNI extension
        tls_payload.extend_from_slice(&[0x00, 0x00]); // Extension type
        let sni_ext_len = (sni_len + 5) as u16;
        tls_payload.extend_from_slice(&sni_ext_len.to_be_bytes());
        let sni_list_len = (sni_len + 3) as u16;
        tls_payload.extend_from_slice(&sni_list_len.to_be_bytes());
        tls_payload.push(0x00); // Host name type
        tls_payload.extend_from_slice(&(sni_len as u16).to_be_bytes());
        tls_payload.extend_from_slice(sni_bytes);
        
        // Fix extension length
        let ext_len = (tls_payload.len() - ext_start - 2) as u16;
        tls_payload[ext_start] = (ext_len >> 8) as u8;
        tls_payload[ext_start + 1] = (ext_len & 0xFF) as u8;
        
        // Fix TLS lengths
        let tls_len = (tls_payload.len() - 5) as u16;
        tls_payload[3] = (tls_len >> 8) as u8;
        tls_payload[4] = (tls_len & 0xFF) as u8;
        
        let handshake_len = tls_len - 4;
        tls_payload[6] = 0;
        tls_payload[7] = (handshake_len >> 8) as u8;
        tls_payload[8] = (handshake_len & 0xFF) as u8;
        
        // Create full packet
        let ip_header_len = 20;
        let tcp_header_len = 20;
        let total_len = (ip_header_len + tcp_header_len + tls_payload.len()) as u16;
        
        let mut packet = vec![
            0x45, 0x00,
            (total_len >> 8) as u8, (total_len & 0xFF) as u8,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0xC0, 0xA8, 0x01, 0x01,
            0xC0, 0xA8, 0x01, 0x02,
            // TCP header
            0x04, 0xD2, 0x01, 0xBB, // Src: 1234, Dst: 443
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x18, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(&tls_payload);
        packet
    }
}

#[test]
fn test_fragmentation_config() {
    let config = FragmentationConfig {
        enabled: true,
        http_size: 4,
        https_size: 8,
        native_split: true,
        reverse_order: true,
        by_sni: false,
        http_persistent: true,
        persistent_nowait: true,
    };

    assert!(config.enabled);
    assert_eq!(config.http_size, 4);
    assert_eq!(config.https_size, 8);
    assert!(config.reverse_order);
}

#[test]
fn test_fake_packet_config() {
    let config = FakePacketConfig {
        enabled: true,
        wrong_checksum: true,
        wrong_seq: true,
        ttl: Some(8),
        auto_ttl: None,
        min_ttl_hops: Some(3),
        custom_payloads: Vec::new(),
        fake_sni_domains: Vec::new(),
        random_count: None,
        resend_count: 2,
    };

    assert!(config.enabled);
    assert!(config.wrong_checksum);
    assert!(config.wrong_seq);
    assert_eq!(config.ttl, Some(8));
    assert_eq!(config.resend_count, 2);
}

#[test]
fn test_auto_ttl_config() {
    let config = AutoTtlConfig {
        a1: 1,
        a2: 4,
        max: 10,
    };

    assert_eq!(config.a1, 1);
    assert_eq!(config.a2, 4);
    assert_eq!(config.max, 10);
}

#[test]
fn test_header_mangle_config() {
    let config = HeaderMangleConfig {
        enabled: true,
        host_replace: true,
        host_remove_space: true,
        host_mix_case: false,
        additional_space: false,
    };

    assert!(config.enabled);
    assert!(config.host_replace);
    assert!(config.host_remove_space);
    assert!(!config.host_mix_case);
}

#[test]
fn test_quic_block_config() {
    let config = QuicBlockConfig {
        enabled: true,
    };

    assert!(config.enabled);
}

#[test]
fn test_passive_dpi_config() {
    let config = PassiveDpiConfig {
        enabled: true,
        ip_ids: vec![0x0100, 0x0200],
    };

    assert!(config.enabled);
    assert_eq!(config.ip_ids.len(), 2);
}

#[test]
fn test_strategies_config_default() {
    let config = StrategiesConfig::default();
    
    // By default, fragmentation and passive DPI should be enabled
    assert!(config.fragmentation.enabled);
    // Fake packet might be disabled by default
    // QUIC block depends on default profile
}

#[test]
fn test_mode_specific_strategies() {
    // Mode 4: Minimal processing
    let mode4 = Config::from_legacy_mode(4).unwrap();
    assert!(!mode4.strategies.fragmentation.enabled);
    assert!(!mode4.strategies.fake_packet.enabled);
    
    // Mode 9: Full mode
    let mode9 = Config::from_legacy_mode(9).unwrap();
    assert!(mode9.strategies.fragmentation.enabled);
    assert!(mode9.strategies.fake_packet.enabled);
    assert!(mode9.strategies.quic_block.enabled);
}
