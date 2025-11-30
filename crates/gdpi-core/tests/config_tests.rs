//! Integration tests for configuration module

use gdpi_core::config::{Config, Profile};
use std::net::Ipv4Addr;

#[test]
fn test_config_from_profile_mode1() {
    let config = Config::from_profile(Profile::Mode1);
    
    // Mode 1: Most compatible (-p -r -s -f 2 -k 2 -n -e 2)
    assert!(config.strategies.passive_dpi.enabled);
    assert!(config.strategies.header_mangle.enabled);
    assert!(config.strategies.fragmentation.enabled);
    assert_eq!(config.strategies.fragmentation.http_size, 2);
    assert_eq!(config.strategies.fragmentation.https_size, 2);
    assert!(!config.strategies.fake_packet.enabled);
    assert!(!config.strategies.quic_block.enabled);
}

#[test]
fn test_config_from_profile_mode9() {
    let config = Config::from_profile(Profile::Mode9);
    
    // Mode 9: Full mode with QUIC blocking (default)
    assert!(config.strategies.fragmentation.enabled);
    assert!(config.strategies.fake_packet.enabled);
    assert!(config.strategies.fake_packet.wrong_checksum);
    assert!(config.strategies.fake_packet.wrong_seq);
    assert!(config.strategies.quic_block.enabled);
}

#[test]
fn test_config_from_profile_turkey() {
    let config = Config::from_profile(Profile::Turkey);
    
    // Turkey profile: Mode 9 + DNS redirect to Yandex
    assert!(config.dns.enabled);
    assert_eq!(config.dns.ipv4_upstream, Some(Ipv4Addr::new(77, 88, 8, 8)));
    assert_eq!(config.dns.ipv4_port, Some(53));
    assert!(config.strategies.quic_block.enabled);
}

#[test]
fn test_all_profiles_valid() {
    let profiles = [
        Profile::Mode1,
        Profile::Mode2,
        Profile::Mode3,
        Profile::Mode4,
        Profile::Mode5,
        Profile::Mode6,
        Profile::Mode7,
        Profile::Mode8,
        Profile::Mode9,
        Profile::Turkey,
        Profile::Custom,
    ];

    for profile in profiles {
        let config = Config::from_profile(profile);
        // All configs should validate
        assert!(config.validate().is_ok(), "Profile {:?} failed validation", profile);
    }
}

#[test]
fn test_toml_serialization_roundtrip() {
    let original = Config::from_profile(Profile::Turkey);
    
    let toml_str = original.to_toml().expect("Failed to serialize");
    let parsed = Config::from_toml(&toml_str).expect("Failed to parse");
    
    // Verify key settings survived roundtrip
    assert_eq!(original.dns.enabled, parsed.dns.enabled);
    assert_eq!(original.dns.ipv4_upstream, parsed.dns.ipv4_upstream);
    assert_eq!(
        original.strategies.fragmentation.http_size,
        parsed.strategies.fragmentation.http_size
    );
}

#[test]
fn test_toml_custom_config() {
    let toml_content = r#"
[general]
name = "custom_test"
version = "2.0"

[dns]
enabled = true
ipv4_upstream = "8.8.8.8"
ipv4_port = 53

[strategies.fragmentation]
enabled = true
http_size = 4
https_size = 8

[strategies.fake_packet]
enabled = true
wrong_checksum = true
wrong_seq = false

[strategies.quic_block]
enabled = false
"#;

    let config = Config::from_toml(toml_content).expect("Failed to parse");
    
    assert_eq!(config.general.name, "custom_test");
    assert!(config.dns.enabled);
    assert_eq!(config.dns.ipv4_upstream, Some(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(config.strategies.fragmentation.http_size, 4);
    assert!(config.strategies.fake_packet.wrong_checksum);
    assert!(!config.strategies.fake_packet.wrong_seq);
    assert!(!config.strategies.quic_block.enabled);
}

#[test]
fn test_profile_parsing() {
    // Numeric modes
    assert_eq!("1".parse::<Profile>().unwrap(), Profile::Mode1);
    assert_eq!("9".parse::<Profile>().unwrap(), Profile::Mode9);
    
    // Named modes
    assert_eq!("mode1".parse::<Profile>().unwrap(), Profile::Mode1);
    assert_eq!("mode9".parse::<Profile>().unwrap(), Profile::Mode9);
    assert_eq!("default".parse::<Profile>().unwrap(), Profile::Mode9);
    
    // Regional profiles
    assert_eq!("turkey".parse::<Profile>().unwrap(), Profile::Turkey);
    assert_eq!("tr".parse::<Profile>().unwrap(), Profile::Turkey);
    
    // Invalid
    assert!("invalid".parse::<Profile>().is_err());
    assert!("10".parse::<Profile>().is_err());
}

#[test]
fn test_legacy_mode_conversion() {
    for mode in 1..=9 {
        let config = Config::from_legacy_mode(mode).expect("Valid mode should work");
        assert!(config.validate().is_ok());
    }
    
    // Invalid modes
    assert!(Config::from_legacy_mode(0).is_err());
    assert!(Config::from_legacy_mode(10).is_err());
}

#[test]
fn test_config_validation_errors() {
    // Invalid DNS port
    let mut config = Config::default();
    config.dns.enabled = true;
    config.dns.ipv4_port = Some(0);
    assert!(config.validate().is_err());

    // Invalid fragmentation size (both http and https are 0)
    let mut config = Config::default();
    config.strategies.fragmentation.enabled = true;
    config.strategies.fragmentation.http_size = 0;
    config.strategies.fragmentation.https_size = 0;
    assert!(config.validate().is_err());

    // Invalid TTL
    let mut config = Config::default();
    config.strategies.fake_packet.ttl = Some(0);
    assert!(config.validate().is_err());
}