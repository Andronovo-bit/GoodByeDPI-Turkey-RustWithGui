//! Test command - connectivity testing

use anyhow::Result;
use clap::{Args, Subcommand};
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};

/// Test command arguments
#[derive(Args, Debug)]
pub struct TestArgs {
    #[command(subcommand)]
    pub action: TestAction,
}

/// Test subcommands
#[derive(Subcommand, Debug)]
pub enum TestAction {
    /// Test connection to a URL
    Url {
        /// URL to test
        url: String,

        /// Timeout in seconds
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },

    /// Test DNS resolution
    Dns {
        /// Domain to resolve
        domain: String,

        /// DNS server to use (default: system)
        #[arg(short, long)]
        server: Option<String>,
    },

    /// Test all blocked sites
    All {
        /// Timeout per site in seconds
        #[arg(short, long, default_value = "5")]
        timeout: u64,
    },

    /// Check WinDivert driver status
    Driver,
}

/// Execute test command
pub fn execute(args: TestArgs) -> Result<()> {
    match args.action {
        TestAction::Url { url, timeout } => test_url(&url, timeout),
        TestAction::Dns { domain, server } => test_dns(&domain, server),
        TestAction::All { timeout } => test_all(timeout),
        TestAction::Driver => test_driver(),
    }
}

fn test_url(url: &str, timeout_secs: u64) -> Result<()> {
    use colored::Colorize;

    println!("Testing connection to: {}", url.cyan());
    
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    // Parse URL
    let parsed_url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };

    // Simple TCP connection test
    let host_port = extract_host_port(&parsed_url)?;
    
    println!("  Resolving {}...", host_port);
    
    match host_port.to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            println!("  {} Resolved to {} address(es)", "✓".green(), addrs.len());
            
            for addr in &addrs {
                println!("    {}", addr);
            }

            // Try to connect
            println!("  Attempting TCP connection...");
            
            match std::net::TcpStream::connect_timeout(&addrs[0], timeout) {
                Ok(_) => {
                    let elapsed = start.elapsed();
                    println!("  {} Connected in {:?}", "✓".green(), elapsed);
                    println!();
                    println!("{}", "Connection successful!".green().bold());
                }
                Err(e) => {
                    println!("  {} Connection failed: {}", "✗".red(), e);
                    println!();
                    println!("{}", "Connection failed - site may be blocked".red().bold());
                }
            }
        }
        Err(e) => {
            println!("  {} DNS resolution failed: {}", "✗".red(), e);
            println!();
            println!("{}", "DNS resolution failed - check DNS settings".red().bold());
        }
    }

    Ok(())
}

fn test_dns(domain: &str, _server: Option<String>) -> Result<()> {
    use colored::Colorize;

    println!("Testing DNS resolution for: {}", domain.cyan());
    
    let start = Instant::now();
    let lookup = format!("{}:80", domain);

    match lookup.to_socket_addrs() {
        Ok(addrs) => {
            let elapsed = start.elapsed();
            let addrs: Vec<_> = addrs.collect();
            
            println!();
            println!("{} Resolved in {:?}", "✓".green(), elapsed);
            println!();
            println!("Addresses:");
            for addr in &addrs {
                println!("  {}", addr.ip());
            }
        }
        Err(e) => {
            println!();
            println!("{} Resolution failed: {}", "✗".red(), e);
        }
    }

    Ok(())
}

fn test_all(timeout_secs: u64) -> Result<()> {
    use colored::Colorize;

    let test_sites = [
        ("Twitter/X", "twitter.com"),
        ("YouTube", "youtube.com"),
        ("Wikipedia", "wikipedia.org"),
        ("Discord", "discord.com"),
        ("Spotify", "spotify.com"),
        ("Reddit", "reddit.com"),
        ("Medium", "medium.com"),
    ];

    println!("{}", "Testing commonly blocked sites...".cyan().bold());
    println!();

    let mut success_count = 0;
    let mut fail_count = 0;

    for (name, domain) in test_sites {
        print!("  {} ({})... ", name, domain);

        let host_port = format!("{}:443", domain);
        let start = Instant::now();
        
        match host_port.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    let timeout = Duration::from_secs(timeout_secs);
                    match std::net::TcpStream::connect_timeout(&addr, timeout) {
                        Ok(_) => {
                            let elapsed = start.elapsed();
                            println!("{} ({:?})", "OK".green(), elapsed);
                            success_count += 1;
                        }
                        Err(_) => {
                            println!("{}", "BLOCKED".red());
                            fail_count += 1;
                        }
                    }
                } else {
                    println!("{}", "NO ADDR".yellow());
                    fail_count += 1;
                }
            }
            Err(_) => {
                println!("{}", "DNS FAIL".red());
                fail_count += 1;
            }
        }
    }

    println!();
    println!("Results: {} passed, {} failed", 
        success_count.to_string().green(),
        fail_count.to_string().red()
    );

    if fail_count > 0 {
        println!();
        println!("{}", "Some sites appear to be blocked.".yellow());
        println!("Run GoodbyeDPI with: goodbyedpi run --turkey");
    }

    Ok(())
}

fn test_driver() -> Result<()> {
    use colored::Colorize;

    println!("{}", "Checking WinDivert driver status...".cyan().bold());
    println!();

    #[cfg(windows)]
    {
        // Check if driver is installed
        let driver_path = std::path::Path::new("C:\\Windows\\System32\\drivers\\WinDivert64.sys");
        
        if driver_path.exists() {
            println!("  {} WinDivert64.sys found", "✓".green());
        } else {
            let driver_path_32 = std::path::Path::new("C:\\Windows\\System32\\drivers\\WinDivert.sys");
            if driver_path_32.exists() {
                println!("  {} WinDivert.sys found (32-bit)", "✓".green());
            } else {
                println!("  {} WinDivert driver not found", "✗".red());
                println!();
                println!("Please install WinDivert from:");
                println!("  https://reqrypt.org/windivert.html");
                return Ok(());
            }
        }

        // Try to open handle
        println!();
        println!("Testing driver handle...");
        
        use gdpi_platform::windows::{WinDivertDriver, Flags};
        
        match WinDivertDriver::open("true", Flags::default()) {
            Ok(mut driver) => {
                println!("  {} Driver opened successfully", "✓".green());
                let _ = driver.close();
                println!();
                println!("{}", "WinDivert is working correctly!".green().bold());
            }
            Err(e) => {
                println!("  {} Failed to open driver: {}", "✗".red(), e);
                println!();
                println!("{}", "Driver test failed.".red().bold());
                println!("Make sure to run as Administrator.");
            }
        }
    }

    #[cfg(not(windows))]
    {
        println!("  {} WinDivert is only available on Windows", "!".yellow());
        println!();
        println!("This platform is not supported for packet capture.");
    }

    Ok(())
}

fn extract_host_port(url: &str) -> Result<String> {
    let url = url.trim_start_matches("https://").trim_start_matches("http://");
    let url = url.split('/').next().unwrap_or(url);
    
    if url.contains(':') {
        Ok(url.to_string())
    } else if url.starts_with("https") {
        Ok(format!("{}:443", url))
    } else {
        Ok(format!("{}:443", url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_port() {
        assert_eq!(
            extract_host_port("https://example.com").unwrap(),
            "example.com:443"
        );
        assert_eq!(
            extract_host_port("http://example.com:8080").unwrap(),
            "example.com:8080"
        );
        assert_eq!(
            extract_host_port("example.com/path").unwrap(),
            "example.com:443"
        );
    }
}
