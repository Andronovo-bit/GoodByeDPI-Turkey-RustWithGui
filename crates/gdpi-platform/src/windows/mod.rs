//! Windows platform implementation using WinDivert
//!
//! WinDivert is a kernel driver that allows capturing and modifying
//! network packets on Windows.

mod driver;
mod filter;

pub use driver::{WinDivertDriver, Flags, Layer};
pub use filter::{FilterBuilder, FilterPresets};
