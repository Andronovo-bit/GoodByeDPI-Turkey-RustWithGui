//! Packet processing pipeline
//!
//! Chain of responsibility pattern for processing packets through strategies.

mod context;

pub use context::{Context, Stats};

use crate::error::Result;
use crate::packet::Packet;
use crate::strategies::{Strategy, StrategyAction};
use tracing::instrument;

/// Packet processing pipeline
///
/// Processes packets through a chain of strategies, collecting and
/// applying transformations.
pub struct Pipeline {
    strategies: Vec<Box<dyn Strategy>>,
}

impl Pipeline {
    /// Create a new empty pipeline
    pub fn new() -> Self {
        Self {
            strategies: Vec::new(),
        }
    }

    /// Add a strategy to the pipeline
    pub fn add_strategy<S: Strategy + 'static>(&mut self, strategy: S) {
        self.strategies.push(Box::new(strategy));
        // Re-sort by priority
        self.strategies.sort_by_key(|s| s.priority());
    }

    /// Add multiple strategies from a vector
    pub fn add_strategies(&mut self, strategies: Vec<Box<dyn Strategy>>) {
        self.strategies.extend(strategies);
        self.strategies.sort_by_key(|s| s.priority());
    }

    /// Get number of strategies in pipeline
    pub fn len(&self) -> usize {
        self.strategies.len()
    }

    /// Check if pipeline is empty
    pub fn is_empty(&self) -> bool {
        self.strategies.is_empty()
    }

    /// Get strategy names for logging
    pub fn strategy_names(&self) -> Vec<&'static str> {
        self.strategies.iter().map(|s| s.name()).collect()
    }

    /// Process a packet through the pipeline
    ///
    /// Returns a vector of packets to be sent (may be empty if dropped,
    /// one packet if unchanged, or multiple if fragmented).
    #[instrument(skip(self, ctx), fields(
        direction = ?packet.direction,
        protocol = ?packet.protocol,
        dst_port = packet.dst_port
    ))]
    pub fn process(&self, packet: Packet, ctx: &mut Context) -> Result<Vec<Packet>> {
        let mut packets = vec![packet];
        
        for strategy in &self.strategies {
            if !strategy.is_enabled() {
                continue;
            }

            let mut new_packets = Vec::new();

            for pkt in packets {
                if strategy.should_apply(&pkt, ctx) {
                    match strategy.apply(pkt, ctx)? {
                        StrategyAction::Pass(p) => {
                            new_packets.push(p);
                        }
                        StrategyAction::Replace(ps) => {
                            new_packets.extend(ps);
                        }
                        StrategyAction::Drop => {
                            // Don't add to new_packets, effectively dropping
                        }
                        StrategyAction::InjectBefore(inject, original) => {
                            new_packets.extend(inject);
                            new_packets.push(original);
                        }
                        StrategyAction::InjectAfter(original, inject) => {
                            new_packets.push(original);
                            new_packets.extend(inject);
                        }
                    }
                } else {
                    new_packets.push(pkt);
                }
            }

            packets = new_packets;

            // If all packets were dropped, exit early
            if packets.is_empty() {
                break;
            }
        }

        ctx.stats.packets_processed += 1;

        Ok(packets)
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Direction;

    // Mock strategy for testing
    struct MockDropStrategy;

    impl Strategy for MockDropStrategy {
        fn name(&self) -> &'static str {
            "mock_drop"
        }

        fn should_apply(&self, packet: &Packet, _ctx: &Context) -> bool {
            packet.dst_port == 12345
        }

        fn apply(&self, _packet: Packet, _ctx: &mut Context) -> Result<StrategyAction> {
            Ok(StrategyAction::Drop)
        }
    }

    struct MockPassStrategy;

    impl Strategy for MockPassStrategy {
        fn name(&self) -> &'static str {
            "mock_pass"
        }

        fn should_apply(&self, _packet: &Packet, _ctx: &Context) -> bool {
            true
        }

        fn apply(&self, packet: Packet, _ctx: &mut Context) -> Result<StrategyAction> {
            Ok(StrategyAction::Pass(packet))
        }
    }

    fn create_test_packet(dst_port: u16) -> Packet {
        let data = vec![
            // IPv4 header
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0xC0, 0xA8, 0x01, 0x01,
            0xC0, 0xA8, 0x01, 0x02,
            // TCP header
            0x00, 0x50,
            (dst_port >> 8) as u8, (dst_port & 0xFF) as u8,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01,
            0x50, 0x18, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        Packet::from_bytes(&data, Direction::Outbound).unwrap()
    }

    #[test]
    fn test_empty_pipeline() {
        let pipeline = Pipeline::new();
        let mut ctx = Context::new();
        let packet = create_test_packet(80);

        let result = pipeline.process(packet, &mut ctx).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_drop_strategy() {
        let mut pipeline = Pipeline::new();
        pipeline.add_strategy(MockDropStrategy);
        
        let mut ctx = Context::new();
        let packet = create_test_packet(12345);

        let result = pipeline.process(packet, &mut ctx).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_pass_strategy() {
        let mut pipeline = Pipeline::new();
        pipeline.add_strategy(MockPassStrategy);
        
        let mut ctx = Context::new();
        let packet = create_test_packet(80);

        let result = pipeline.process(packet, &mut ctx).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_strategy_ordering() {
        let mut pipeline = Pipeline::new();
        pipeline.add_strategy(MockPassStrategy);
        pipeline.add_strategy(MockDropStrategy);

        // MockDropStrategy has default priority 100
        // MockPassStrategy has default priority 100
        // Order should be preserved for same priority
        assert_eq!(pipeline.len(), 2);
    }
}
