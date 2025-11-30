//! GoodbyeDPI Windows Service
//!
//! Wrapper for running GoodbyeDPI as a Windows service.

#![cfg(windows)]

pub mod service;

pub use service::run_service;
