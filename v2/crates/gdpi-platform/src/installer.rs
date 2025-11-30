//! WinDivert driver installer
//!
//! Embeds WinDivert files and provides automatic installation.

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::{debug, error, info, warn};

/// Embedded WinDivert files for x64
#[cfg(target_arch = "x86_64")]
mod embedded {
    pub const WINDIVERT_DLL: &[u8] = include_bytes!("../../../resources/windivert/x64/WinDivert.dll");
    pub const WINDIVERT_SYS: &[u8] = include_bytes!("../../../resources/windivert/x64/WinDivert64.sys");
    pub const SYS_NAME: &str = "WinDivert64.sys";
}

/// Embedded WinDivert files for x86
#[cfg(target_arch = "x86")]
mod embedded {
    pub const WINDIVERT_DLL: &[u8] = include_bytes!("../../../resources/windivert/x86/WinDivert.dll");
    pub const WINDIVERT_SYS: &[u8] = include_bytes!("../../../resources/windivert/x86/WinDivert32.sys");
    pub const SYS_NAME: &str = "WinDivert32.sys";
}

/// WinDivert installer
pub struct WinDivertInstaller {
    /// Installation directory
    install_dir: PathBuf,
}

impl WinDivertInstaller {
    /// Create new installer with default directory
    pub fn new() -> Self {
        let install_dir = Self::default_install_dir();
        Self { install_dir }
    }

    /// Create installer with custom directory
    pub fn with_dir(install_dir: PathBuf) -> Self {
        Self { install_dir }
    }

    /// Get default installation directory
    fn default_install_dir() -> PathBuf {
        // Use the directory where the executable is located
        env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// Check if WinDivert is installed
    pub fn is_installed(&self) -> bool {
        let dll_path = self.install_dir.join("WinDivert.dll");
        let sys_path = self.install_dir.join(embedded::SYS_NAME);
        
        dll_path.exists() && sys_path.exists()
    }

    /// Check if WinDivert driver is loaded in kernel
    pub fn is_driver_loaded(&self) -> bool {
        // Try to query the service status
        let output = Command::new("sc")
            .args(["query", "WinDivert"])
            .output();

        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("RUNNING")
            }
            Err(_) => false,
        }
    }

    /// Install WinDivert files
    pub fn install(&self) -> Result<()> {
        info!("Installing WinDivert to {:?}", self.install_dir);

        // Create directory if needed
        fs::create_dir_all(&self.install_dir)
            .context("Failed to create installation directory")?;

        // Write DLL
        let dll_path = self.install_dir.join("WinDivert.dll");
        Self::write_file(&dll_path, embedded::WINDIVERT_DLL)?;
        info!("Installed WinDivert.dll");

        // Write SYS
        let sys_path = self.install_dir.join(embedded::SYS_NAME);
        Self::write_file(&sys_path, embedded::WINDIVERT_SYS)?;
        info!("Installed {}", embedded::SYS_NAME);

        Ok(())
    }

    /// Uninstall WinDivert files
    pub fn uninstall(&self) -> Result<()> {
        info!("Uninstalling WinDivert from {:?}", self.install_dir);

        // Stop the driver first
        let _ = self.stop_driver();

        // Remove files
        let dll_path = self.install_dir.join("WinDivert.dll");
        let sys_path = self.install_dir.join(embedded::SYS_NAME);

        if dll_path.exists() {
            fs::remove_file(&dll_path).context("Failed to remove WinDivert.dll")?;
            info!("Removed WinDivert.dll");
        }

        if sys_path.exists() {
            fs::remove_file(&sys_path).context("Failed to remove driver")?;
            info!("Removed {}", embedded::SYS_NAME);
        }

        Ok(())
    }

    /// Start the WinDivert driver service
    pub fn start_driver(&self) -> Result<()> {
        debug!("Starting WinDivert driver");

        let output = Command::new("sc")
            .args(["start", "WinDivert"])
            .output()
            .context("Failed to execute sc command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Service might already be running
            if !stderr.contains("already been started") {
                warn!("sc start returned: {}", stderr);
            }
        }

        Ok(())
    }

    /// Stop the WinDivert driver service
    pub fn stop_driver(&self) -> Result<()> {
        debug!("Stopping WinDivert driver");

        let output = Command::new("sc")
            .args(["stop", "WinDivert"])
            .output()
            .context("Failed to execute sc command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Service might not be running
            if !stderr.contains("not been started") {
                debug!("sc stop returned: {}", stderr);
            }
        }

        Ok(())
    }

    /// Write file with proper error handling
    fn write_file(path: &PathBuf, data: &[u8]) -> Result<()> {
        let mut file = fs::File::create(path)
            .with_context(|| format!("Failed to create file: {:?}", path))?;
        
        file.write_all(data)
            .with_context(|| format!("Failed to write file: {:?}", path))?;
        
        Ok(())
    }

    /// Get the installation directory
    pub fn install_dir(&self) -> &PathBuf {
        &self.install_dir
    }

    /// Check if running with admin privileges
    pub fn is_admin() -> bool {
        #[cfg(windows)]
        {
            // Simple check: try to write to a protected location
            let program_files = std::env::var("ProgramFiles")
                .unwrap_or_else(|_| "C:\\Program Files".to_string());
            let test_path = format!("{}\\__gdpi_admin_test__.tmp", program_files);
            
            if std::fs::write(&test_path, "test").is_ok() {
                let _ = std::fs::remove_file(&test_path);
                true
            } else {
                false
            }
        }
        
        #[cfg(not(windows))]
        {
            // On non-Windows, check if running as root
            unsafe { libc::geteuid() == 0 }
        }
    }

    /// Verify installation by trying to load the driver
    pub fn verify_installation(&self) -> Result<()> {
        if !self.is_installed() {
            bail!("WinDivert files not found");
        }

        // The actual verification happens when we try to open a handle
        // For now, just check files exist
        info!("WinDivert files verified");
        Ok(())
    }
}

impl Default for WinDivertInstaller {
    fn default() -> Self {
        Self::new()
    }
}

/// Interactive installation with user prompts
pub fn interactive_install() -> Result<bool> {
    use std::io::{stdin, stdout};

    let installer = WinDivertInstaller::new();

    if installer.is_installed() {
        println!("✓ WinDivert is already installed");
        return Ok(true);
    }

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║           WinDivert Driver Installation Required           ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    println!("WinDivert is a kernel driver required for packet capture and");
    println!("modification. It will be installed to:\n");
    println!("  {:?}\n", installer.install_dir());

    println!("The following files will be created:");
    println!("  • WinDivert.dll  (User-mode library)");
    println!("  • {}  (Kernel driver)\n", embedded::SYS_NAME);

    if !WinDivertInstaller::is_admin() {
        println!("⚠  Administrator privileges are required!");
        println!("   Please run this program as Administrator.\n");
        return Ok(false);
    }

    print!("Do you want to install WinDivert? [Y/n]: ");
    stdout().flush()?;

    let mut input = String::new();
    stdin().read_line(&mut input)?;

    let input = input.trim().to_lowercase();
    if input.is_empty() || input == "y" || input == "yes" {
        installer.install()?;
        println!("\n✓ WinDivert installed successfully!");
        println!("  The driver will be loaded automatically when needed.\n");
        Ok(true)
    } else {
        println!("\nInstallation cancelled.");
        println!("You can install later with: goodbyedpi.exe driver install\n");
        Ok(false)
    }
}

/// Check and install driver if needed (non-interactive)
pub fn ensure_driver_available() -> Result<()> {
    let installer = WinDivertInstaller::new();

    if installer.is_installed() {
        debug!("WinDivert is installed");
        return Ok(());
    }

    if !WinDivertInstaller::is_admin() {
        error!("WinDivert is not installed and administrator privileges are required to install it");
        bail!(
            "WinDivert driver not found. Please run as Administrator or use:\n\
             goodbyedpi.exe driver install"
        );
    }

    // Auto-install in non-interactive mode
    info!("WinDivert not found, installing...");
    installer.install()?;
    info!("WinDivert installed successfully");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_files_exist() {
        assert!(!embedded::WINDIVERT_DLL.is_empty());
        assert!(!embedded::WINDIVERT_SYS.is_empty());
    }

    #[test]
    fn test_default_install_dir() {
        let installer = WinDivertInstaller::new();
        assert!(!installer.install_dir().as_os_str().is_empty());
    }
}
