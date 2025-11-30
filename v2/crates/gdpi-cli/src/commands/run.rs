//! Run command - main DPI bypass execution

use anyhow::{Context, Result};
use clap::Args;
use gdpi_core::config::{Config, Profile};
use gdpi_core::pipeline::{Context as PipelineContext, Pipeline};
use gdpi_core::strategies::StrategyBuilder;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::args::Args as GlobalArgs;

/// Packet processing statistics
#[derive(Default)]
struct PacketStats {
    total: u64,
    modified: u64,
    errors: u64,
}

/// Known blocked domains that we want to highlight in logs
const BLOCKED_DOMAINS: &[&str] = &[
    "discord.com",
    "discordapp.com", 
    "discord.gg",
    "discord.media",
    "discordcdn.com",
    "gateway.discord.gg",
    "media.discordapp.net",
];

/// Check if domain is in our known blocked list
fn is_blocked_domain(host: &str) -> bool {
    let host_lower = host.to_lowercase();
    BLOCKED_DOMAINS.iter().any(|d| host_lower.contains(d))
}

/// Run command arguments
#[derive(Args, Debug)]
pub struct RunArgs {
    /// Profile to use (1-9, turkey)
    #[arg(short = 'p', long)]
    pub profile: Option<String>,

    /// Configuration file
    #[arg(short = 'c', long)]
    pub config: Option<String>,

    /// Blacklist file
    #[arg(short = 'b', long)]
    pub blacklist: Option<String>,

    /// Alternative DNS server
    #[arg(long)]
    pub dns_addr: Option<String>,

    /// Block QUIC (UDP 443)
    #[arg(long)]
    pub block_quic: bool,

    /// Use auto-TTL detection
    #[arg(long)]
    pub auto_ttl: bool,

    /// Manual TTL value
    #[arg(long)]
    pub ttl: Option<u8>,

    /// HTTP fragmentation position
    #[arg(long)]
    pub http_frag: Option<u32>,

    /// HTTPS fragmentation position
    #[arg(long)]
    pub https_frag: Option<u32>,

    /// Use wrong checksum for fake packets
    #[arg(long)]
    pub wrong_chksum: bool,

    /// Use wrong sequence number for fake packets
    #[arg(long)]
    pub wrong_seq: bool,

    /// Dry run (don't actually modify packets)
    #[arg(long)]
    pub dry_run: bool,
}

impl RunArgs {
    /// Create RunArgs from legacy global args
    pub fn from_legacy(args: &GlobalArgs) -> Self {
        let profile = args.legacy_mode().map(|m| {
            if m == 10 { "turkey".to_string() }
            else { m.to_string() }
        });

        Self {
            profile,
            config: args.config.clone(),
            blacklist: args.blacklist.clone(),
            dns_addr: args.dns_addr.clone(),
            block_quic: args.block_quic,
            auto_ttl: args.auto_ttl,
            ttl: args.set_ttl,
            http_frag: args.http_frag,
            https_frag: args.https_frag,
            wrong_chksum: args.wrong_chksum,
            wrong_seq: args.wrong_seq,
            dry_run: false,
        }
    }
}

/// Execute the run command
pub fn execute(args: RunArgs) -> Result<()> {
    info!("Starting GoodbyeDPI...");

    // Load configuration
    let config = load_config(&args)?;
    info!(profile = ?config.profile, "Loaded configuration");

    // Create pipeline
    let mut pipeline = Pipeline::new();
    let strategies = StrategyBuilder::from_config(&config);
    pipeline.add_strategies(strategies);
    
    info!(
        strategy_count = pipeline.len(),
        strategies = ?pipeline.strategy_names(),
        "Initialized pipeline"
    );

    // Create context
    let ctx = if let Some(ref blacklist_path) = args.blacklist {
        let domains = load_blacklist(blacklist_path)?;
        info!(count = domains.len(), "Loaded blacklist");
        PipelineContext::with_blacklist(domains)
    } else {
        PipelineContext::new()
    };

    // Set up signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        info!("Received interrupt signal, shutting down...");
        r.store(false, Ordering::SeqCst);
    }).context("Failed to set signal handler")?;

    // Dry run check
    if args.dry_run {
        warn!("Dry run mode - no packets will be modified");
        info!("Configuration validated successfully");
        return Ok(());
    }

    // Main packet processing loop
    run_packet_loop(config, pipeline, ctx, running)?;

    // Print final stats
    info!("GoodbyeDPI stopped");

    Ok(())
}

fn load_config(args: &RunArgs) -> Result<Config> {
    // Priority: config file > profile > defaults
    if let Some(ref config_path) = args.config {
        return Config::load(config_path)
            .with_context(|| format!("Failed to load config from {}", config_path));
    }

    // Create config from profile or defaults
    let mut config = if let Some(ref profile_name) = args.profile {
        let profile = Profile::from_name(profile_name)
            .with_context(|| format!("Unknown profile: {}", profile_name))?;
        Config::from_profile(profile)
    } else {
        // Default: Turkey profile
        Config::from_profile(Profile::Turkey)
    };

    // Apply command-line overrides
    if let Some(ref dns) = args.dns_addr {
        config.dns.enabled = true;
        let ip: std::net::IpAddr = dns.parse()
            .with_context(|| format!("Invalid DNS address: {}", dns))?;
        config.dns.server = Some(ip);
    }

    if args.block_quic {
        config.strategies.block_quic = true;
    }

    if args.auto_ttl {
        config.strategies.auto_ttl = true;
    }

    if let Some(ttl) = args.ttl {
        config.strategies.fake_ttl = Some(ttl);
    }

    if let Some(pos) = args.http_frag {
        config.strategies.http_fragment_position = pos;
    }

    if let Some(pos) = args.https_frag {
        config.strategies.https_fragment_position = pos;
    }

    if args.wrong_chksum {
        config.strategies.fake_with_wrong_checksum = true;
    }

    if args.wrong_seq {
        config.strategies.fake_with_wrong_seq = true;
    }

    Ok(config)
}

fn load_blacklist(path: &str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read blacklist file: {}", path))?;

    let domains: Vec<String> = content
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        })
        .map(|s| s.trim().to_lowercase())
        .collect();

    Ok(domains)
}

fn run_packet_loop(
    config: Config,
    pipeline: Pipeline,
    mut ctx: PipelineContext,
    running: Arc<AtomicBool>,
) -> Result<()> {
    #[cfg(windows)]
    {
        use gdpi_platform::windows::{FilterPresets, WinDivertDriver, Flags};
        use gdpi_platform::PacketCapture;
        use gdpi_platform::installer::{WinDivertInstaller, interactive_install};

        let installer = WinDivertInstaller::new();
        
        // Check if WinDivert is installed
        if !installer.is_installed() {
            warn!("WinDivert driver not found");
            
            println!("\n╔════════════════════════════════════════════════════════════╗");
            println!("║           WinDivert Driver Installation Required           ║");
            println!("╚════════════════════════════════════════════════════════════╝\n");
            
            println!("WinDivert is required for packet capture and modification.");
            println!("It will be installed to: {:?}\n", installer.install_dir());
            
            // Check if we have admin privileges
            if !WinDivertInstaller::is_admin() {
                println!("🔐 Administrator privileges are required to install the driver.");
                
                if atty::is(atty::Stream::Stdin) {
                    use std::io::{stdin, stdout, Write};
                    
                    print!("\nWould you like to install the driver now? [Y/n]: ");
                    stdout().flush()?;
                    
                    let mut input = String::new();
                    stdin().read_line(&mut input)?;
                    
                    let input = input.trim().to_lowercase();
                    if input.is_empty() || input == "y" || input == "yes" {
                        println!("\n📦 Requesting administrator privileges...");
                        println!("   A UAC prompt will appear shortly.\n");
                        
                        // Request elevation to install driver
                        match WinDivertInstaller::request_admin_and_run(&["driver", "install", "--yes"]) {
                            Ok(false) => {
                                // Check if installation succeeded
                                if installer.is_installed() {
                                    println!("✓ Driver installed successfully!\n");
                                    println!("Restarting DPI bypass...\n");
                                } else {
                                    anyhow::bail!("Driver installation failed or was cancelled");
                                }
                            }
                            Ok(true) => {
                                // Already admin - shouldn't happen
                            }
                            Err(e) => {
                                anyhow::bail!("Failed to install driver: {}", e);
                            }
                        }
                    } else {
                        println!("\nYou can install the driver later with:");
                        println!("  goodbyedpi.exe driver install\n");
                        anyhow::bail!("WinDivert driver is required to run");
                    }
                } else {
                    anyhow::bail!(
                        "WinDivert driver not found. Please run:\n  \
                         goodbyedpi.exe driver install"
                    );
                }
            } else {
                // We have admin, install directly
                if atty::is(atty::Stream::Stdin) {
                    if !interactive_install()? {
                        anyhow::bail!("WinDivert driver installation cancelled");
                    }
                } else {
                    installer.install()?;
                    info!("WinDivert driver installed");
                }
            }
        }
        
        // Check admin for WinDivert operation
        if !WinDivertInstaller::is_admin() {
            println!("\n🔐 Administrator privileges are required to capture packets.");
            
            if atty::is(atty::Stream::Stdin) {
                use std::io::{stdin, stdout, Write};
                
                print!("Would you like to restart with admin privileges? [Y/n]: ");
                stdout().flush()?;
                
                let mut input = String::new();
                stdin().read_line(&mut input)?;
                
                let input = input.trim().to_lowercase();
                if input.is_empty() || input == "y" || input == "yes" {
                    println!("\n📦 Requesting administrator privileges...\n");
                    
                    // Re-run with same arguments
                    let args: Vec<String> = std::env::args().skip(1).collect();
                    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                    
                    match WinDivertInstaller::request_admin_and_run(&args_refs) {
                        Ok(false) => {
                            // Elevated process ran
                            std::process::exit(0);
                        }
                        Ok(true) => {}
                        Err(e) => {
                            anyhow::bail!("Failed to get admin privileges: {}", e);
                        }
                    }
                } else {
                    anyhow::bail!("Administrator privileges are required to run");
                }
            } else {
                anyhow::bail!("Administrator privileges required. Please run as Administrator.");
            }
        }

        // Build filter
        let filter = if config.strategies.block_quic {
            FilterPresets::turkey_optimized()
        } else {
            FilterPresets::goodbyedpi_full()
        };

        info!(filter = filter, "Opening WinDivert handle");

        let mut driver = WinDivertDriver::open(&filter, Flags::default())
            .context("Failed to open WinDivert - is the driver installed?")?;

        info!("Packet capture started - waiting for traffic...");

        // Statistics counters
        let mut stats = PacketStats::default();
        let start_time = std::time::Instant::now();
        
        while running.load(Ordering::SeqCst) {
            match driver.recv() {
                Ok(captured) => {
                    stats.total += 1;
                    
                    match captured.parse() {
                        Ok(packet) => {
                            // Extract SNI for logging blocked domains
                            let sni = if packet.dst_port == 443 && packet.is_tls_client_hello() {
                                packet.extract_sni()
                            } else {
                                None
                            };
                            
                            // Process through pipeline
                            match pipeline.process(packet, &mut ctx) {
                                Ok(output_packets) => {
                                    let was_modified = output_packets.len() > 1;
                                    
                                    if was_modified {
                                        stats.modified += 1;
                                        
                                        // Log only for known blocked domains
                                        if let Some(ref host) = sni {
                                            if is_blocked_domain(host) {
                                                info!("🔓 Bypass: {} → {} packets", host, output_packets.len());
                                            }
                                        }
                                    }
                                    
                                    // Send packets
                                    for pkt in output_packets {
                                        if let Err(e) = driver.send(pkt.as_bytes(), &captured.address) {
                                            error!("Send failed: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    stats.errors += 1;
                                    debug!("Pipeline error: {}", e);
                                    let _ = driver.send(&captured.data, &captured.address);
                                }
                            }
                        }
                        Err(_e) => {
                            // Re-inject as-is
                            if let Err(e) = driver.send(&captured.data, &captured.address) {
                                error!("Failed to re-inject raw packet: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Receive error: {}", e);
                }
            }
        }

        // Final stats
        let elapsed = start_time.elapsed();
        info!(
            "Session ended: {} packets processed, {} modified, {} errors in {:.1}s",
            stats.total,
            stats.modified, 
            stats.errors,
            elapsed.as_secs_f64()
        );

        driver.close()?;
    }

    #[cfg(not(windows))]
    {
        warn!("Packet capture is only supported on Windows");
        warn!("This build can be used for testing configuration only");
        
        // Just wait for interrupt
        while running.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_blacklist() {
        let content = "# Comment\nexample.com\n  test.org  \n\nfoo.bar\n";
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("blacklist.txt");
        std::fs::write(&path, content).unwrap();

        let domains = load_blacklist(path.to_str().unwrap()).unwrap();
        assert_eq!(domains.len(), 3);
        assert!(domains.contains(&"example.com".to_string()));
        assert!(domains.contains(&"test.org".to_string()));
        assert!(domains.contains(&"foo.bar".to_string()));
    }
}
