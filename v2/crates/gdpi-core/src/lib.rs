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
//! ```rust,no_run
//! use gdpi_core::{Pipeline, Config};
//! use gdpi_core::strategies::{FragmentationStrategy, FakePacketStrategy};
//!
//! let config = Config::load("config.toml")?;
//! let mut pipeline = Pipeline::new();
//!
//! pipeline.add_strategy(FragmentationStrategy::from_config(&config));
//! pipeline.add_strategy(FakePacketStrategy::from_config(&config));
//!
//! // Process packets through the pipeline
//! let output_packets = pipeline.process(packet, &mut context)?;
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
