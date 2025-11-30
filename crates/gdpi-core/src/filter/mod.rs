//! Domain filtering system for whitelist/blacklist management
//!
//! This module provides a flexible filtering system that allows users to:
//! - Whitelist domains (bypass DPI bypass - let traffic pass normally)
//! - Blacklist domains (only these domains get DPI bypass applied)
//!
//! The filter supports:
//! - Exact domain matching
//! - Wildcard matching (*.example.com)
//! - Suffix matching (example.com matches sub.example.com)
//! - Local file-based configuration with hot-reload

mod domain_filter;

pub use domain_filter::{DomainFilter, FilterMode, FilterResult};
