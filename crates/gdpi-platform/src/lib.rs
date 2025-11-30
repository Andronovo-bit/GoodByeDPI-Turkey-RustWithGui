//! GoodbyeDPI Platform Abstraction Layer
//!
//! This crate provides platform-specific packet capture and injection.
//!
//! ## Supported Platforms
//!
//! - **Windows**: WinDivert driver
//! - **Linux**: (Future) NFQUEUE
//! - **macOS**: (Future) Network Extension API

#![warn(missing_docs)]
#![warn(clippy::all)]

mod error;
pub use error::{PlatformError, Result};

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use windows::WinDivertDriver;

// Platform-agnostic traits
mod traits;
pub use traits::{PacketCapture, PacketFilter};

// Driver installer
#[cfg(windows)]
pub mod installer;
