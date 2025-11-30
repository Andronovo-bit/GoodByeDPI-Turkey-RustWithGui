//! Service management - controls the DPI bypass process

use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::path::PathBuf;
use tokio::sync::watch;
use tracing::{info, error, warn};

/// Service status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

impl ServiceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceStatus::Stopped => "Stopped",
            ServiceStatus::Starting => "Starting...",
            ServiceStatus::Running => "Running",
            ServiceStatus::Stopping => "Stopping...",
            ServiceStatus::Error => "Error",
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, ServiceStatus::Running | ServiceStatus::Starting)
    }
}

/// Service controller
pub struct ServiceController {
    process: Option<Child>,
    status_tx: watch::Sender<ServiceStatus>,
    status_rx: watch::Receiver<ServiceStatus>,
    exe_path: PathBuf,
}

impl ServiceController {
    /// Create a new service controller
    pub fn new() -> Self {
        let (status_tx, status_rx) = watch::channel(ServiceStatus::Stopped);
        
        // Find the CLI executable
        let exe_path = Self::find_exe();
        
        Self {
            process: None,
            status_tx,
            status_rx,
            exe_path,
        }
    }

    /// Find the CLI executable path
    fn find_exe() -> PathBuf {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        
        // Try different possible locations
        let candidates = [
            exe_dir.join("goodbyedpi.exe"),
            exe_dir.join("goodbyedpi-cli.exe"),
            exe_dir.parent().unwrap_or(&exe_dir).join("goodbyedpi.exe"),
        ];

        for candidate in &candidates {
            if candidate.exists() {
                return candidate.clone();
            }
        }

        // Default fallback
        exe_dir.join("goodbyedpi.exe")
    }

    /// Get status receiver for UI updates
    pub fn status_receiver(&self) -> watch::Receiver<ServiceStatus> {
        self.status_rx.clone()
    }

    /// Get current status
    pub fn status(&self) -> ServiceStatus {
        *self.status_rx.borrow()
    }

    /// Start the DPI bypass service
    pub fn start(&mut self, profile: &str) -> anyhow::Result<()> {
        if self.process.is_some() {
            warn!("Service already running");
            return Ok(());
        }

        info!("Starting DPI bypass with profile: {}", profile);
        let _ = self.status_tx.send(ServiceStatus::Starting);

        // Build command
        let mut cmd = Command::new(&self.exe_path);
        cmd.arg("run")
            .arg("--profile")
            .arg(profile)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        // On Windows, create no window
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        match cmd.spawn() {
            Ok(child) => {
                self.process = Some(child);
                let _ = self.status_tx.send(ServiceStatus::Running);
                info!("DPI bypass started successfully");
                Ok(())
            }
            Err(e) => {
                error!("Failed to start DPI bypass: {}", e);
                let _ = self.status_tx.send(ServiceStatus::Error);
                Err(e.into())
            }
        }
    }

    /// Stop the DPI bypass service
    pub fn stop(&mut self) -> anyhow::Result<()> {
        if self.process.is_none() {
            return Ok(());
        }

        info!("Stopping DPI bypass");
        let _ = self.status_tx.send(ServiceStatus::Stopping);

        // Try graceful shutdown first
        if let Some(mut child) = self.process.take() {
            // On Windows, we need to kill the process tree
            #[cfg(windows)]
            {
                let pid = child.id();
                let _ = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/T", "/F"])
                    .output();
            }

            // Wait for process to exit
            match child.kill() {
                Ok(_) => {
                    let _ = child.wait();
                    info!("DPI bypass stopped");
                }
                Err(e) => {
                    warn!("Failed to kill process: {}", e);
                }
            }
        }

        let _ = self.status_tx.send(ServiceStatus::Stopped);
        Ok(())
    }

    /// Toggle service state
    pub fn toggle(&mut self, profile: &str) -> anyhow::Result<()> {
        if self.status().is_running() {
            self.stop()
        } else {
            self.start(profile)
        }
    }

    /// Check if process is still running
    pub fn check_status(&mut self) {
        if let Some(ref mut child) = self.process {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process exited
                    if status.success() {
                        info!("DPI bypass process exited normally");
                    } else {
                        warn!("DPI bypass process exited with error: {:?}", status);
                    }
                    self.process = None;
                    let _ = self.status_tx.send(ServiceStatus::Stopped);
                }
                Ok(None) => {
                    // Still running
                }
                Err(e) => {
                    error!("Failed to check process status: {}", e);
                }
            }
        }
    }
}

impl Default for ServiceController {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ServiceController {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
