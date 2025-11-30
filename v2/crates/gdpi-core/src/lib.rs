//! # GoodbyeDPI Core
//!
//! Platform-independent core library for DPI bypass strategies.
//!
//! ## Architecture
//!
//! This crate provides:
//! - **Packet parsing and manipulation** - Low-level packet handling
//! - **DPI bypass strategies** - Pluggable strategies for circumvention
//! - **Connection tracking** - TCP/UDP state management
//! - **Configuration** - Profile-based configuration system
//!
//! ## Example
//!
//! ```rust,ignore
//! use gdpi_core::{Pipeline, Config, Context};
//! use gdpi_core::strategies::{FragmentationStrategy, FakePacketStrategy};
//!
//! let config = Config::load("config.toml").expect("Failed to load config");
//! let mut pipeline = Pipeline::new();
//!
//! // Add strategies based on configuration
//! pipeline.add_strategy(FragmentationStrategy::from_config(&config.strategies.fragmentation));
//! pipeline.add_strategy(FakePacketStrategy::from_config(&config.strategies.fake_packet));
//!
//! // Process packets through the pipeline
//! let mut context = Context::new(&config);
//! let output_packets = pipeline.process(packet, &mut context).expect("Processing failed");
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod conntrack;
pub mod error;
pub mod packet;
pub mod pipeline;
pub mod strategies;

// Re-exports for convenience
pub use config::Config;
pub use conntrack::{DnsConnTracker, TcpConnTracker};
pub use error::{Error, Result};
pub use packet::Packet;
pub use pipeline::{Context, Pipeline, Stats};
