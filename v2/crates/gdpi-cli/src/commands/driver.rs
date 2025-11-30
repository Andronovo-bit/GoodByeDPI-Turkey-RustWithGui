//! Driver management commands

use anyhow::Result;
use clap::Subcommand;
use gdpi_platform::installer::{interactive_install, WinDivertInstaller};

#[derive(Subcommand, Debug)]
pub enum DriverCommands {
    /// Install WinDivert driver
    Install {
        /// Force reinstall even if already installed
        #[arg(short, long)]
        force: bool,
        
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
    
    /// Uninstall WinDivert driver
    Uninstall {
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
    
    /// Check driver status
    Status,
}

pub fn run(cmd: DriverCommands) -> Result<()> {
    match cmd {
        DriverCommands::Install { force, yes } => install_driver(force, yes),
        DriverCommands::Uninstall { yes } => uninstall_driver(yes),
        DriverCommands::Status => show_status(),
    }
}

fn install_driver(force: bool, yes: bool) -> Result<()> {
    let installer = WinDivertInstaller::new();

    if installer.is_installed() && !force {
        println!("✓ WinDivert is already installed at:");
        println!("  {:?}", installer.install_dir());
        println!("\nUse --force to reinstall.");
        return Ok(());
    }

    if !WinDivertInstaller::is_admin() {
        println!("⚠  Administrator privileges required!");
        println!("   Please run this command as Administrator.");
        return Ok(());
    }

    if yes {
        // Non-interactive install
        if force && installer.is_installed() {
            installer.uninstall()?;
        }
        installer.install()?;
        println!("✓ WinDivert installed successfully!");
    } else {
        // Interactive install
        interactive_install()?;
    }

    Ok(())
}

fn uninstall_driver(yes: bool) -> Result<()> {
    let installer = WinDivertInstaller::new();

    if !installer.is_installed() {
        println!("WinDivert is not installed.");
        return Ok(());
    }

    if !WinDivertInstaller::is_admin() {
        println!("⚠  Administrator privileges required!");
        println!("   Please run this command as Administrator.");
        return Ok(());
    }

    if !yes {
        use std::io::{stdin, stdout, Write};
        
        print!("Are you sure you want to uninstall WinDivert? [y/N]: ");
        stdout().flush()?;

        let mut input = String::new();
        stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() != "y" {
            println!("Cancelled.");
            return Ok(());
        }
    }

    installer.uninstall()?;
    println!("✓ WinDivert uninstalled successfully!");

    Ok(())
}

fn show_status() -> Result<()> {
    let installer = WinDivertInstaller::new();

    println!("\n╔═══════════════════════════════════════════════════════╗");
    println!("║              WinDivert Driver Status                  ║");
    println!("╚═══════════════════════════════════════════════════════╝\n");

    println!("Installation Directory: {:?}\n", installer.install_dir());

    // Check files
    let dll_installed = installer.install_dir().join("WinDivert.dll").exists();
    let sys_installed = installer.install_dir().join(if cfg!(target_arch = "x86_64") {
        "WinDivert64.sys"
    } else {
        "WinDivert32.sys"
    }).exists();

    println!("Files:");
    if dll_installed {
        println!("  ✓ WinDivert.dll");
    } else {
        println!("  ✗ WinDivert.dll (not found)");
    }

    if sys_installed {
        println!("  ✓ WinDivert{}.sys", if cfg!(target_arch = "x86_64") { "64" } else { "32" });
    } else {
        println!("  ✗ WinDivert{}.sys (not found)", if cfg!(target_arch = "x86_64") { "64" } else { "32" });
    }

    // Check driver status
    println!("\nDriver Service:");
    if installer.is_driver_loaded() {
        println!("  ✓ Running");
    } else {
        println!("  ○ Not running (will start when needed)");
    }

    // Check admin privileges
    println!("\nPrivileges:");
    if WinDivertInstaller::is_admin() {
        println!("  ✓ Running as Administrator");
    } else {
        println!("  ⚠ Not running as Administrator");
    }

    // Overall status
    println!();
    if installer.is_installed() {
        println!("Status: ✓ Ready");
    } else {
        println!("Status: ✗ Not installed");
        println!("\nTo install, run: goodbyedpi.exe driver install");
    }

    println!();
    Ok(())
}
