//! GoodbyeDPI Turkey - System Tray GUI
//!
//! A lightweight system tray application for controlling the DPI bypass.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod tray;
mod service;
mod config;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

fn main() -> Result<()> {
    // Initialize logging
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("gdpi_gui=info".parse()?))
        .init();

    info!("Starting GoodbyeDPI Turkey GUI");

    // Run the application
    app::run()
}
