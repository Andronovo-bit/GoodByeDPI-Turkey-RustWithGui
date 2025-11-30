//! Connection tracking module
//!
//! Provides TCP and DNS connection tracking for:
//! - Auto-TTL detection (tracking SYN-ACK TTL values)
//! - DNS query/response mapping

mod tcp;
mod dns;

pub use tcp::TcpConnTracker;
pub use dns::DnsConnTracker;
