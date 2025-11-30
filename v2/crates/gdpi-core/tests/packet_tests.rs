//! Integration tests for packet module
//!
//! These tests verify end-to-end packet parsing, building, and manipulation.

use gdpi_core::packet::*;

/// Test data: minimal valid IPv4 TCP SYN packet
fn create_tcp_syn_packet() -> Vec<u8> {
    vec![
        // IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x28, // Version, IHL, DSCP, ECN, Total Length (40)
        0x00, 0x01, 0x00, 0x00, // Identification, Flags, Fragment Offset
        0x40, 0x06, 0x00, 0x00, // TTL (64), Protocol (TCP), Checksum
        0xC0, 0xA8, 0x01, 0x01, // Source IP: 192.168.1.1
        0xC0, 0xA8, 0x01, 0x02, // Dest IP: 192.168.1.2
        // TCP header (20 bytes)
        0x04, 0xD2, 0x00, 0x50, // Src Port (1234), Dst Port (80)
        0x00, 0x00, 0x00, 0x01, // Sequence Number
        0x00, 0x00, 0x00, 0x00, // Acknowledgment Number
        0x50, 0x02, 0xFF, 0xFF, // Data Offset, SYN flag, Window Size
        0x00, 0x00, 0x00, 0x00, // Checksum, Urgent Pointer
    ]
}

/// Test data: HTTP GET request packet
fn create_http_get_packet() -> Vec<u8> {
    let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    let ip_header_len = 20;
    let tcp_header_len = 20;
    let total_len = (ip_header_len + tcp_header_len + payload.len()) as u16;

    let mut packet = vec![
        // IPv4 header (20 bytes)
        0x45, 0x00,
        (total_len >> 8) as u8, (total_len & 0xFF) as u8,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x01, // Source IP: 192.168.1.1
        0xC0, 0xA8, 0x01, 0x02, // Dest IP: 192.168.1.2
        // TCP header (20 bytes)
        0x04, 0xD2, 0x00, 0x50, // Src Port (1234), Dst Port (80)
        0x00, 0x00, 0x00, 0x01, // Sequence Number
        0x00, 0x00, 0x00, 0x00, // Acknowledgment Number
        0x50, 0x18, 0xFF, 0xFF, // Data Offset, PSH+ACK flags, Window Size
        0x00, 0x00, 0x00, 0x00, // Checksum, Urgent Pointer
    ];
    packet.extend_from_slice(payload);
    packet
}

/// Test data: TLS ClientHello packet (simplified)
fn create_tls_client_hello_packet() -> Vec<u8> {
    // Minimal TLS ClientHello with SNI for "example.com"
    // SNI extension structure:
    // - Extension Type: 0x00 0x00 (SNI)
    // - Extension Length: 0x00 0x10 (16 = list_len + 2)
    // - Server Name List Length: 0x00 0x0E (14 = name_type(1) + name_len(2) + name(11))
    // - Name Type: 0x00 (hostname)
    // - Name Length: 0x00 0x0B (11)
    // - Name: "example.com"
    let tls_payload = vec![
        0x16, 0x03, 0x01, 0x00, 0x43, // TLS record: Handshake, version 3.1, length 67
        0x01,                         // Handshake type: ClientHello
        0x00, 0x00, 0x3F,             // Length (63)
        0x03, 0x03,                   // Client Version: TLS 1.2
        // Random (32 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,                         // Session ID Length: 0
        0x00, 0x02,                   // Cipher Suites Length
        0x00, 0xFF,                   // Cipher Suite
        0x01, 0x00,                   // Compression Methods
        0x00, 0x14,                   // Extensions Length (20)
        // SNI Extension
        0x00, 0x00,                   // Extension Type: SNI
        0x00, 0x10,                   // Extension Length: 16
        0x00, 0x0E,                   // Server Name List Length: 14 (= name_len + 3)
        0x00,                         // Server Name Type: hostname
        0x00, 0x0B,                   // Server Name Length: 11
        b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', // "example.com"
    ];

    let ip_header_len = 20;
    let tcp_header_len = 20;
    let total_len = (ip_header_len + tcp_header_len + tls_payload.len()) as u16;

    let mut packet = vec![
        // IPv4 header
        0x45, 0x00,
        (total_len >> 8) as u8, (total_len & 0xFF) as u8,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x01,
        0xC0, 0xA8, 0x01, 0x02,
        // TCP header
        0x04, 0xD2, 0x01, 0xBB, // Src Port (1234), Dst Port (443)
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x18, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00,
    ];
    packet.extend_from_slice(&tls_payload);
    packet
}

#[test]
fn test_parse_tcp_syn() {
    let data = create_tcp_syn_packet();
    let packet = Packet::from_bytes(&data, Direction::Outbound).unwrap();

    assert!(packet.is_tcp());
    assert!(packet.is_outbound());
    assert_eq!(packet.src_port, 1234);
    assert_eq!(packet.dst_port, 80);
}

#[test]
fn test_parse_http_request() {
    let data = create_http_get_packet();
    let packet = Packet::from_bytes(&data, Direction::Outbound).unwrap();

    assert!(packet.is_tcp());
    assert!(packet.is_http_request());
    assert_eq!(packet.dst_port, 80);
    assert!(packet.payload_len() > 0);
}

#[test]
fn test_parse_tls_client_hello() {
    let data = create_tls_client_hello_packet();
    let packet = Packet::from_bytes(&data, Direction::Outbound).unwrap();

    assert!(packet.is_tcp());
    assert!(packet.is_tls_client_hello());
    assert_eq!(packet.dst_port, 443);
}

#[test]
fn test_extract_http_host() {
    let data = create_http_get_packet();
    let packet = Packet::from_bytes(&data, Direction::Outbound).unwrap();

    let host = packet.extract_http_host();
    assert!(host.is_some());
    assert_eq!(host.unwrap(), "example.com");
}

#[test]
fn test_extract_sni() {
    let data = create_tls_client_hello_packet();
    let packet = Packet::from_bytes(&data, Direction::Outbound).unwrap();

    let sni = packet.extract_sni();
    assert!(sni.is_some());
    assert_eq!(sni.unwrap(), "example.com");
}

#[test]
fn test_packet_builder() {
    let packet = PacketBuilder::tcp_v4()
        .src_ip_v4([10, 0, 0, 1])
        .dst_ip_v4([10, 0, 0, 2])
        .src_port(54321)
        .dst_port(443)
        .ttl(128)
        .flags(TcpFlags { syn: true, ..Default::default() })
        .build();

    // Verify IPv4
    assert_eq!(packet[0] >> 4, 4);
    // Verify protocol (TCP = 6)
    assert_eq!(packet[9], 6);
    // Verify TTL
    assert_eq!(packet[8], 128);
}

#[test]
fn test_tcp_flags() {
    // SYN only
    let syn = TcpFlags::from_byte(0x02);
    assert!(syn.syn);
    assert!(!syn.ack);

    // SYN-ACK
    let syn_ack = TcpFlags::from_byte(0x12);
    assert!(syn_ack.syn);
    assert!(syn_ack.ack);

    // FIN-ACK
    let fin_ack = TcpFlags::from_byte(0x11);
    assert!(fin_ack.fin);
    assert!(fin_ack.ack);

    // RST
    let rst = TcpFlags::from_byte(0x04);
    assert!(rst.rst);
}

#[test]
fn test_protocol_detection() {
    assert_eq!(Protocol::from_u8(6), Protocol::Tcp);
    assert_eq!(Protocol::from_u8(17), Protocol::Udp);
    assert_eq!(Protocol::from_u8(1), Protocol::Icmp);
    assert_eq!(Protocol::from_u8(58), Protocol::Icmpv6);
    assert_eq!(Protocol::from_u8(0), Protocol::Unknown);
}
