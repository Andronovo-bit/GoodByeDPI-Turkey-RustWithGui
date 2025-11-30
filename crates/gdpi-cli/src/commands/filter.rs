//! Domain filter management commands
//!
//! Commands for managing whitelist/blacklist domain filters.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use gdpi_core::filter::{DomainFilter, FilterMode};
use std::path::PathBuf;

/// Default filter file location
fn default_filter_path() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    
    exe_dir.join("domains.txt")
}

/// Filter management arguments
#[derive(Args, Debug)]
pub struct FilterArgs {
    #[command(subcommand)]
    pub command: FilterCommands,
}

/// Filter subcommands
#[derive(Subcommand, Debug)]
pub enum FilterCommands {
    /// List all domains in the filter
    List {
        /// Filter file path
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    
    /// Add a domain to the filter
    Add {
        /// Domain to add (use *.example.com for wildcard)
        domain: String,
        
        /// Filter file path
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    
    /// Remove a domain from the filter
    Remove {
        /// Domain to remove
        domain: String,
        
        /// Filter file path
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    
    /// Set filter mode
    Mode {
        /// Mode: whitelist, blacklist, or disabled
        mode: String,
        
        /// Filter file path
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    
    /// Create a new filter file with example entries
    Init {
        /// Filter file path
        #[arg(short, long)]
        file: Option<PathBuf>,
        
        /// Filter mode: whitelist or blacklist
        #[arg(short, long, default_value = "whitelist")]
        mode: String,
    },
    
    /// Check if a domain matches the filter
    Check {
        /// Domain to check
        domain: String,
        
        /// Filter file path
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
}

/// Execute filter command
pub fn execute(args: FilterArgs) -> Result<()> {
    match args.command {
        FilterCommands::List { file } => list_domains(file),
        FilterCommands::Add { domain, file } => add_domain(domain, file),
        FilterCommands::Remove { domain, file } => remove_domain(domain, file),
        FilterCommands::Mode { mode, file } => set_mode(mode, file),
        FilterCommands::Init { file, mode } => init_filter(file, mode),
        FilterCommands::Check { domain, file } => check_domain(domain, file),
    }
}

fn list_domains(file: Option<PathBuf>) -> Result<()> {
    let path = file.unwrap_or_else(default_filter_path);
    
    if !path.exists() {
        println!("{}", "Filter file not found. Create one with 'filter init'".yellow());
        println!("Expected path: {}", path.display());
        return Ok(());
    }
    
    let filter = DomainFilter::from_file(&path, FilterMode::Disabled)
        .context("Failed to load filter file")?;
    
    let domains = filter.domains();
    
    println!("{}", "═".repeat(50).bright_blue());
    println!("{}", " Domain Filter".bright_white().bold());
    println!("{}", "═".repeat(50).bright_blue());
    println!("File: {}", path.display().to_string().cyan());
    println!("Total domains: {}", domains.len().to_string().green());
    println!("{}", "─".repeat(50).bright_black());
    
    if domains.is_empty() {
        println!("{}", "  (empty)".dimmed());
    } else {
        for domain in &domains {
            if domain.starts_with("*.") {
                println!("  {} {}", "◉".yellow(), domain);
            } else {
                println!("  {} {}", "●".green(), domain);
            }
        }
    }
    
    println!("{}", "═".repeat(50).bright_blue());
    
    Ok(())
}

fn add_domain(domain: String, file: Option<PathBuf>) -> Result<()> {
    let path = file.unwrap_or_else(default_filter_path);
    
    // Load existing or create new
    let filter = if path.exists() {
        DomainFilter::from_file(&path, FilterMode::Disabled)?
    } else {
        DomainFilter::new()
    };
    
    filter.add_domain(&domain);
    filter.save_file(&path)?;
    
    println!("{} Added {} to filter", "✓".green(), domain.cyan());
    println!("  File: {}", path.display());
    
    Ok(())
}

fn remove_domain(domain: String, file: Option<PathBuf>) -> Result<()> {
    let path = file.unwrap_or_else(default_filter_path);
    
    if !path.exists() {
        println!("{} Filter file not found: {}", "✗".red(), path.display());
        return Ok(());
    }
    
    let filter = DomainFilter::from_file(&path, FilterMode::Disabled)?;
    filter.remove_domain(&domain);
    filter.save_file(&path)?;
    
    println!("{} Removed {} from filter", "✓".green(), domain.cyan());
    
    Ok(())
}

fn set_mode(mode: String, file: Option<PathBuf>) -> Result<()> {
    let path = file.unwrap_or_else(default_filter_path);
    
    let filter_mode = match mode.to_lowercase().as_str() {
        "whitelist" | "white" => FilterMode::Whitelist,
        "blacklist" | "black" => FilterMode::Blacklist,
        "disabled" | "off" => FilterMode::Disabled,
        _ => {
            println!("{} Invalid mode: {}", "✗".red(), mode);
            println!("Valid modes: whitelist, blacklist, disabled");
            return Ok(());
        }
    };
    
    let filter = if path.exists() {
        DomainFilter::from_file(&path, filter_mode)?
    } else {
        let f = DomainFilter::new();
        f.set_mode(filter_mode);
        f
    };
    
    filter.set_mode(filter_mode);
    filter.save_file(&path)?;
    
    let mode_str = match filter_mode {
        FilterMode::Whitelist => "whitelist".green(),
        FilterMode::Blacklist => "blacklist".yellow(),
        FilterMode::Disabled => "disabled".dimmed(),
    };
    
    println!("{} Filter mode set to {}", "✓".green(), mode_str);
    
    Ok(())
}

fn init_filter(file: Option<PathBuf>, mode: String) -> Result<()> {
    let path = file.unwrap_or_else(default_filter_path);
    
    if path.exists() {
        println!("{} Filter file already exists: {}", "!".yellow(), path.display());
        println!("Use 'filter add' to add domains or delete the file first.");
        return Ok(());
    }
    
    let filter_mode = match mode.to_lowercase().as_str() {
        "whitelist" | "white" => FilterMode::Whitelist,
        "blacklist" | "black" => FilterMode::Blacklist,
        _ => FilterMode::Whitelist,
    };
    
    let filter = DomainFilter::new();
    filter.set_mode(filter_mode);
    
    // Add example entries based on mode
    if filter_mode == FilterMode::Whitelist {
        // Whitelist: sites that should NOT be bypassed
        filter.add_domain("# Banking sites");
        filter.add_domain("*.garanti.com.tr");
        filter.add_domain("*.isbank.com.tr");
        filter.add_domain("*.yapikredi.com.tr");
        filter.add_domain("*.akbank.com");
        filter.add_domain("*.ziraatbank.com.tr");
        filter.add_domain("*.halkbank.com.tr");
        filter.add_domain("*.vakifbank.com.tr");
        filter.add_domain("*.qnb.com.tr");
        filter.add_domain("*.enpara.com");
        filter.add_domain("# Government sites");
        filter.add_domain("*.gov.tr");
        filter.add_domain("e-devlet.gov.tr");
        filter.add_domain("turkiye.gov.tr");
        filter.add_domain("# Payment systems");
        filter.add_domain("*.iyzico.com");
        filter.add_domain("*.paytr.com");
    } else {
        // Blacklist: only these sites get bypass
        filter.add_domain("# Social media");
        filter.add_domain("*.twitter.com");
        filter.add_domain("*.x.com");
        filter.add_domain("# Streaming");
        filter.add_domain("*.youtube.com");
        filter.add_domain("*.googlevideo.com");
        filter.add_domain("# Communication");
        filter.add_domain("*.discord.com");
        filter.add_domain("*.discord.gg");
        filter.add_domain("*.discordapp.com");
    }
    
    filter.save_file(&path)?;
    
    let mode_str = match filter_mode {
        FilterMode::Whitelist => "whitelist".green(),
        FilterMode::Blacklist => "blacklist".yellow(),
        FilterMode::Disabled => "disabled".dimmed(),
    };
    
    println!("{} Created filter file in {} mode", "✓".green(), mode_str);
    println!("  File: {}", path.display().to_string().cyan());
    println!();
    println!("Edit the file to customize your domain list.");
    println!("Use 'goodbyedpi filter list' to view domains.");
    
    Ok(())
}

fn check_domain(domain: String, file: Option<PathBuf>) -> Result<()> {
    let path = file.unwrap_or_else(default_filter_path);
    
    if !path.exists() {
        println!("{} Filter file not found: {}", "✗".red(), path.display());
        println!("Without a filter, all domains get bypass applied.");
        return Ok(());
    }
    
    // We need to know the mode from config, default to whitelist for check
    let filter = DomainFilter::from_file(&path, FilterMode::Whitelist)?;
    
    let matches = filter.matches(&domain);
    let result = filter.check(&domain);
    
    println!("{}", "─".repeat(50).bright_black());
    println!("Domain: {}", domain.cyan());
    println!("Mode: {:?}", filter.mode());
    println!("Matches filter: {}", if matches { "Yes".green() } else { "No".yellow() });
    println!("Result: {}", match result {
        gdpi_core::filter::FilterResult::ApplyBypass => "Apply DPI bypass".green(),
        gdpi_core::filter::FilterResult::SkipBypass => "Skip bypass (normal traffic)".yellow(),
    });
    println!("{}", "─".repeat(50).bright_black());
    
    Ok(())
}
