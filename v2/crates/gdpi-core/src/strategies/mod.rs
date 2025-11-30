//! DPI bypass strategies
//!
//! Pluggable strategies for circumventing Deep Packet Inspection.
//! Each strategy implements the [`Strategy`] trait and can be composed
//! into a processing pipeline.

mod fake_packet;
mod fragment;
mod header_mangle;
mod quic_block;
mod dns_redirect;

pub use fake_packet::FakePacketStrategy;
pub use fragment::FragmentationStrategy;
pub use header_mangle::HeaderMangleStrategy;
pub use quic_block::QuicBlockStrategy;
pub use dns_redirect::DnsRedirectStrategy;

use crate::config::Config;
use crate::error::Result;
use crate::packet::Packet;
use crate::pipeline::Context;
use std::sync::Arc;

/// Action to take after strategy processing
#[derive(Debug, Clone)]
pub enum StrategyAction {
    /// Pass the packet through unchanged
    Pass(Packet),
    /// Replace with modified packet(s)
    Replace(Vec<Packet>),
    /// Drop the packet (don't reinject)
    Drop,
    /// Inject additional packets before the original
    InjectBefore(Vec<Packet>, Packet),
    /// Inject additional packets after the original
    InjectAfter(Packet, Vec<Packet>),
}

/// Trait for DPI bypass strategies
///
/// Each strategy examines packets and decides whether to apply
/// transformations to bypass DPI systems.
pub trait Strategy: Send + Sync {
    /// Get the strategy name for logging/debugging
    fn name(&self) -> &'static str;

    /// Get strategy priority (lower = runs first)
    /// Default is 100. Use lower values for strategies that should
    /// run before others (e.g., fake packets before fragmentation).
    fn priority(&self) -> u8 {
        100
    }

    /// Check if this strategy should be applied to the given packet
    fn should_apply(&self, packet: &Packet, ctx: &Context) -> bool;

    /// Apply the strategy to transform the packet
    ///
    /// Returns a `StrategyAction` indicating what to do with the packet.
    fn apply(&self, packet: Packet, ctx: &mut Context) -> Result<StrategyAction>;

    /// Check if strategy is enabled
    fn is_enabled(&self) -> bool {
        true
    }
}

/// Builder for creating strategies from configuration
pub struct StrategyBuilder;

impl StrategyBuilder {
    /// Create all enabled strategies from configuration
    pub fn from_config(config: &Config) -> Vec<Box<dyn Strategy>> {
        let mut strategies: Vec<Box<dyn Strategy>> = Vec::new();

        // Add strategies in priority order
        
        // Fake packet strategy (runs first to inject before real packet)
        if config.strategies.fake_packet.enabled {
            strategies.push(Box::new(
                FakePacketStrategy::from_config(&config.strategies.fake_packet)
            ));
        }

        // Header manipulation
        if config.strategies.header_mangle.enabled {
            strategies.push(Box::new(
                HeaderMangleStrategy::from_config(&config.strategies.header_mangle)
            ));
        }

        // Fragmentation (runs after header modification)
        if config.strategies.fragmentation.enabled {
            strategies.push(Box::new(
                FragmentationStrategy::from_config(&config.strategies.fragmentation)
            ));
        }

        // QUIC blocking
        if config.strategies.quic_block.enabled {
            strategies.push(Box::new(QuicBlockStrategy::new()));
        }

        // DNS redirection
        if config.dns.enabled {
            if let Some(upstream) = config.dns.ipv4_upstream {
                strategies.push(Box::new(
                    DnsRedirectStrategy::new(
                        upstream,
                        config.dns.ipv4_port.unwrap_or(53),
                    )
                ));
            }
        }

        // Sort by priority
        strategies.sort_by_key(|s| s.priority());

        strategies
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;

    #[test]
    fn test_strategy_builder() {
        let config = Profile::Mode9.into_config();
        let strategies = StrategyBuilder::from_config(&config);

        // Mode 9 should have fragmentation, fake_packet, and quic_block
        assert!(!strategies.is_empty());
        
        let names: Vec<_> = strategies.iter().map(|s| s.name()).collect();
        assert!(names.contains(&"fragmentation"));
        assert!(names.contains(&"fake_packet"));
        assert!(names.contains(&"quic_block"));
    }
}
