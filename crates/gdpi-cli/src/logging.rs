//! Logging initialization

use anyhow::{Context, Result};
use tracing::Level;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::args::{Args, LogFormat};

/// Initialize logging based on CLI arguments
pub fn init(args: &Args) -> Result<()> {
    // Determine log level
    let level = if args.quiet {
        Level::ERROR
    } else {
        match args.verbose {
            0 => Level::INFO,
            1 => Level::DEBUG,
            _ => Level::TRACE,
        }
    };

    // Build env filter
    let env_filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .from_env_lossy();

    // Set up subscriber based on format
    match args.log_format {
        LogFormat::Text => {
            let subscriber = tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .with_target(args.verbose >= 2)
                        .with_thread_ids(args.verbose >= 3)
                        .with_file(args.verbose >= 3)
                        .with_line_number(args.verbose >= 3)
                );

            if let Some(ref log_file) = args.log_file {
                let file = std::fs::File::create(log_file)
                    .with_context(|| format!("Failed to create log file: {}", log_file))?;
                let file_layer = fmt::layer()
                    .with_ansi(false)
                    .with_writer(file);
                subscriber.with(file_layer).init();
            } else {
                subscriber.init();
            }
        }
        LogFormat::Json => {
            let subscriber = tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json());

            if let Some(ref log_file) = args.log_file {
                let file = std::fs::File::create(log_file)
                    .with_context(|| format!("Failed to create log file: {}", log_file))?;
                let file_layer = fmt::layer()
                    .json()
                    .with_writer(file);
                subscriber.with(file_layer).init();
            } else {
                subscriber.init();
            }
        }
        LogFormat::Compact => {
            let subscriber = tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().compact());
            subscriber.init();
        }
    }

    Ok(())
}
