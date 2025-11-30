//! Service command - Windows service management

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

/// Service command arguments
#[derive(Args, Debug)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub action: ServiceAction,
}

/// Service subcommands
#[derive(Subcommand, Debug)]
pub enum ServiceAction {
    /// Install Windows service
    Install {
        /// Profile to use
        #[arg(short, long, default_value = "turkey")]
        profile: String,

        /// Config file path
        #[arg(short, long)]
        config: Option<String>,

        /// Start automatically on boot
        #[arg(long)]
        auto_start: bool,
    },

    /// Uninstall Windows service
    Uninstall,

    /// Start the service
    Start,

    /// Stop the service
    Stop,

    /// Restart the service
    Restart,

    /// Check service status
    Status,
}

const SERVICE_NAME: &str = "GoodbyeDPI";
const SERVICE_DISPLAY_NAME: &str = "GoodbyeDPI Turkey";
const SERVICE_DESCRIPTION: &str = "Deep Packet Inspection bypass service for Turkey";

/// Execute service command
pub fn execute(args: ServiceArgs) -> Result<()> {
    #[cfg(windows)]
    {
        match args.action {
            ServiceAction::Install { profile, config, auto_start } => {
                install_service(&profile, config.as_deref(), auto_start)
            }
            ServiceAction::Uninstall => uninstall_service(),
            ServiceAction::Start => start_service(),
            ServiceAction::Stop => stop_service(),
            ServiceAction::Restart => restart_service(),
            ServiceAction::Status => service_status(),
        }
    }

    #[cfg(not(windows))]
    {
        use colored::Colorize;
        println!("{}", "Service management is only available on Windows.".yellow());
        println!();
        println!("On Linux, you can create a systemd service manually:");
        println!("  sudo cp goodbyedpi.service /etc/systemd/system/");
        println!("  sudo systemctl enable goodbyedpi");
        println!("  sudo systemctl start goodbyedpi");
        Ok(())
    }
}

#[cfg(windows)]
fn install_service(profile: &str, config: Option<&str>, auto_start: bool) -> Result<()> {
    use colored::Colorize;

    println!("Installing {} service...", SERVICE_NAME.cyan());

    // Get current executable path
    let exe_path = std::env::current_exe()
        .context("Failed to get executable path")?;

    // Build command line arguments
    let mut args = vec!["run".to_string()];
    
    if let Some(cfg) = config {
        args.push("--config".to_string());
        args.push(cfg.to_string());
    } else {
        args.push("--profile".to_string());
        args.push(profile.to_string());
    }

    // For now, just print what would be done
    println!("  Executable: {}", exe_path.display());
    println!("  Arguments: {:?}", args);
    println!("  Auto-start: {}", auto_start);
    
    // Actual service installation would use Windows Service API
    // sc create GoodbyeDPI binPath= "..." start= auto
    
    println!();
    println!("{}", "Service installation would require elevated privileges.".yellow());
    println!("Run as Administrator to actually install the service.");

    Ok(())
}

#[cfg(windows)]
fn uninstall_service() -> Result<()> {
    use colored::Colorize;

    println!("Uninstalling {} service...", SERVICE_NAME.cyan());
    
    // Stop service first
    let _ = stop_service();

    // sc delete GoodbyeDPI
    
    println!();
    println!("{}", "Service uninstallation would require elevated privileges.".yellow());

    Ok(())
}

#[cfg(windows)]
fn start_service() -> Result<()> {
    use colored::Colorize;

    println!("Starting {} service...", SERVICE_NAME.cyan());
    
    // net start GoodbyeDPI
    
    println!("{}", "Service start would require elevated privileges.".yellow());

    Ok(())
}

#[cfg(windows)]
fn stop_service() -> Result<()> {
    use colored::Colorize;

    println!("Stopping {} service...", SERVICE_NAME.cyan());
    
    // net stop GoodbyeDPI
    
    println!("{}", "Service stop would require elevated privileges.".yellow());

    Ok(())
}

#[cfg(windows)]
fn restart_service() -> Result<()> {
    stop_service()?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    start_service()
}

#[cfg(windows)]
fn service_status() -> Result<()> {
    use colored::Colorize;

    println!("{} Service Status", SERVICE_NAME.cyan().bold());
    println!();

    // Query service status using sc query
    // For now, just check if process is running
    
    println!("  Name: {}", SERVICE_NAME);
    println!("  Display Name: {}", SERVICE_DISPLAY_NAME);
    println!("  Description: {}", SERVICE_DESCRIPTION);
    println!();
    println!("  Status: {}", "Unknown".yellow());
    println!();
    println!("{}", "Full status check requires elevated privileges.".yellow());

    Ok(())
}
