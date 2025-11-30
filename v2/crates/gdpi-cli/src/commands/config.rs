//! Config command - configuration management

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use gdpi_core::config::{Config, Profile};
use std::path::PathBuf;
use tracing::info;

/// Config command arguments
#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

/// Config subcommands
#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Show current configuration
    Show {
        /// Config file to show (default: detect)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Profile to show
        #[arg(short, long)]
        profile: Option<String>,
    },

    /// Generate a configuration file
    Generate {
        /// Output file path
        #[arg(short, long, default_value = "config.toml")]
        output: PathBuf,

        /// Profile to use as base
        #[arg(short, long, default_value = "turkey")]
        profile: String,
    },

    /// Validate a configuration file
    Validate {
        /// Config file to validate
        file: PathBuf,
    },

    /// Show config file locations
    Paths,
}

/// Execute config command
pub fn execute(args: ConfigArgs) -> Result<()> {
    match args.action {
        ConfigAction::Show { file, profile } => show_config(file, profile),
        ConfigAction::Generate { output, profile } => generate_config(output, profile),
        ConfigAction::Validate { file } => validate_config(file),
        ConfigAction::Paths => show_paths(),
    }
}

fn show_config(file: Option<PathBuf>, profile: Option<String>) -> Result<()> {
    let config = if let Some(path) = file {
        Config::load(&path)
            .with_context(|| format!("Failed to load config from {:?}", path))?
    } else if let Some(profile_name) = profile {
        let profile = Profile::from_name(&profile_name)
            .with_context(|| format!("Unknown profile: {}", profile_name))?;
        Config::from_profile(profile)
    } else {
        // Try to find config file
        if let Some(path) = find_config_file() {
            Config::load(&path)
                .with_context(|| format!("Failed to load config from {:?}", path))?
        } else {
            Config::from_profile(Profile::Turkey)
        }
    };

    // Serialize and print
    let toml_str = toml::to_string_pretty(&config)
        .context("Failed to serialize config")?;

    println!("{}", toml_str);
    Ok(())
}

fn generate_config(output: PathBuf, profile_name: String) -> Result<()> {
    let profile = Profile::from_name(&profile_name)
        .with_context(|| format!("Unknown profile: {}", profile_name))?;
    
    let config = Config::from_profile(profile);

    let toml_str = toml::to_string_pretty(&config)
        .context("Failed to serialize config")?;

    // Add header comment
    let content = format!(
        "# GoodbyeDPI-Turkey Configuration\n\
         # Generated from profile: {}\n\
         # See documentation for all available options\n\n\
         {}",
        profile_name, toml_str
    );

    std::fs::write(&output, content)
        .with_context(|| format!("Failed to write config to {:?}", output))?;

    info!("Generated config file: {:?}", output);
    println!("Configuration file generated: {}", output.display());
    
    Ok(())
}

fn validate_config(file: PathBuf) -> Result<()> {
    let config = Config::load(&file)
        .with_context(|| format!("Failed to load config from {:?}", file))?;

    // Validate
    config.validate()
        .context("Configuration validation failed")?;

    println!("✓ Configuration is valid");
    println!("  Profile: {:?}", config.profile);
    println!("  DNS enabled: {}", config.dns.enabled);
    println!("  Block QUIC: {}", config.strategies.block_quic);
    println!("  Auto-TTL: {}", config.strategies.auto_ttl);

    Ok(())
}

fn show_paths() -> Result<()> {
    println!("Configuration file search paths:");
    println!();

    // Current directory
    println!("  1. ./config.toml");
    println!("  2. ./goodbyedpi.toml");

    // User config directory
    if let Some(config_dir) = directories::ProjectDirs::from("", "", "goodbyedpi") {
        println!("  3. {}/config.toml", config_dir.config_dir().display());
    }

    // System-wide (Windows)
    #[cfg(windows)]
    {
        println!("  4. C:\\Program Files\\GoodbyeDPI\\config.toml");
    }

    println!();
    println!("Blacklist file search paths:");
    println!();
    println!("  1. ./blacklist.txt");
    println!("  2. ./turkey-blacklist.txt");

    if let Some(config_dir) = directories::ProjectDirs::from("", "", "goodbyedpi") {
        println!("  3. {}/blacklist.txt", config_dir.config_dir().display());
    }

    Ok(())
}

fn find_config_file() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("config.toml"),
        PathBuf::from("goodbyedpi.toml"),
    ];

    for path in candidates {
        if path.exists() {
            return Some(path);
        }
    }

    // Check user config directory
    if let Some(config_dir) = directories::ProjectDirs::from("", "", "goodbyedpi") {
        let path = config_dir.config_dir().join("config.toml");
        if path.exists() {
            return Some(path);
        }
    }

    None
}
