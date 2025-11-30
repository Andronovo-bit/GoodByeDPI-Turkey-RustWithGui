//! Service management - controls the DPI bypass process

use std::process::{Child, Command, Stdio};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tracing::{info, error, warn};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::iter::once;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

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
    process_id: Option<u32>,
    status: ServiceStatus,
    exe_path: PathBuf,
    /// Channel for async operation results
    result_rx: Option<mpsc::Receiver<ServiceResult>>,
}

/// Result from async operations
enum ServiceResult {
    Started(Option<u32>),  // Optional PID
    StartFailed(String),
    Stopped,
    StopFailed(String),
}

/// Check if current process is running as administrator
#[cfg(windows)]
fn is_elevated() -> bool {
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::winnt::{TokenElevation, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY};
    
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        
        let result = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        );
        
        winapi::um::handleapi::CloseHandle(token);
        
        result != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
fn is_elevated() -> bool {
    // On non-Windows, check if running as root
    unsafe { libc::geteuid() == 0 }
}

impl ServiceController {
    /// Create a new service controller
    pub fn new() -> Self {
        // Find the CLI executable
        let exe_path = Self::find_exe();
        
        Self {
            process: None,
            process_id: None,
            status: ServiceStatus::Stopped,
            exe_path,
            result_rx: None,
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

    /// Get current status
    pub fn status(&self) -> ServiceStatus {
        self.status
    }

    /// Start the DPI bypass service with administrator privileges (non-blocking)
    pub fn start(&mut self, profile: &str) -> anyhow::Result<()> {
        if self.process.is_some() || self.process_id.is_some() {
            warn!("Service already running");
            return Ok(());
        }

        info!("Starting DPI bypass with profile: {}", profile);
        self.status = ServiceStatus::Starting;

        // Start async operation
        let exe_path = self.exe_path.clone();
        let profile = profile.to_string();
        let (tx, rx) = mpsc::channel();
        self.result_rx = Some(rx);

        thread::spawn(move || {
            let result = Self::start_elevated_async(&exe_path, &profile);
            let _ = tx.send(result);
        });

        Ok(())
    }

    /// Async start with elevation
    #[cfg(windows)]
    fn start_elevated_async(exe_path: &PathBuf, profile: &str) -> ServiceResult {
        use winapi::um::shellapi::ShellExecuteW;
        use winapi::um::winuser::SW_HIDE;
        
        let exe_path_str = exe_path.to_string_lossy().to_string();
        let args = format!("run --profile {}", profile);
        
        // Convert strings to wide strings for Windows API
        let operation: Vec<u16> = OsStr::new("runas").encode_wide().chain(once(0)).collect();
        let file: Vec<u16> = OsStr::new(&exe_path_str).encode_wide().chain(once(0)).collect();
        let parameters: Vec<u16> = OsStr::new(&args).encode_wide().chain(once(0)).collect();
        
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                operation.as_ptr(),
                file.as_ptr(),
                parameters.as_ptr(),
                std::ptr::null(),
                SW_HIDE,
            )
        };

        if (result as isize) > 32 {
            info!("DPI bypass started with elevation");
            
            // Wait a bit and find the process
            thread::sleep(Duration::from_millis(500));
            
            if let Some(pid) = Self::find_process_pid() {
                ServiceResult::Started(Some(pid))
            } else {
                thread::sleep(Duration::from_millis(1000));
                if let Some(pid) = Self::find_process_pid() {
                    ServiceResult::Started(Some(pid))
                } else {
                    ServiceResult::Started(None)
                }
            }
        } else {
            let error_code = result as isize;
            let error_msg = match error_code {
                0 => "Out of memory",
                2 => "File not found",
                3 => "Path not found", 
                5 => "Access denied (UAC cancelled?)",
                _ => "Unknown error",
            };
            error!("Failed to start with elevation: {} (code: {})", error_msg, error_code);
            ServiceResult::StartFailed(format!("{} (code: {})", error_msg, error_code))
        }
    }

    #[cfg(not(windows))]
    fn start_elevated_async(exe_path: &PathBuf, profile: &str) -> ServiceResult {
        let mut cmd = Command::new(exe_path);
        cmd.arg("run")
            .arg("--profile")
            .arg(profile)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        match cmd.spawn() {
            Ok(child) => {
                ServiceResult::Started(Some(child.id()))
            }
            Err(e) => {
                ServiceResult::StartFailed(e.to_string())
            }
        }
    }

    /// Find running goodbyedpi process PID (without creating console window)
    #[cfg(windows)]
    fn find_process_pid() -> Option<u32> {
        let mut cmd = Command::new("tasklist");
        cmd.args(["/FI", "IMAGENAME eq goodbyedpi.exe", "/FO", "CSV", "/NH"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        
        if let Ok(output) = cmd.output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("goodbyedpi.exe") {
                if let Some(pid_str) = stdout.split(',').nth(1) {
                    let pid_str = pid_str.trim().trim_matches('"');
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        info!("Found running process with PID: {}", pid);
                        return Some(pid);
                    }
                }
            }
        }
        None
    }

    #[cfg(not(windows))]
    fn find_process_pid() -> Option<u32> {
        None
    }

    /// Stop the DPI bypass service (non-blocking)
    pub fn stop(&mut self) -> anyhow::Result<()> {
        if self.process.is_none() && self.process_id.is_none() {
            return Ok(());
        }

        info!("Stopping DPI bypass");
        self.status = ServiceStatus::Stopping;

        let pid = self.process_id.take();
        let process = self.process.take();
        
        let (tx, rx) = mpsc::channel();
        self.result_rx = Some(rx);

        thread::spawn(move || {
            let result = Self::stop_async(pid, process);
            let _ = tx.send(result);
        });

        Ok(())
    }

    /// Async stop process
    #[cfg(windows)]
    fn stop_async(pid: Option<u32>, mut process: Option<Child>) -> ServiceResult {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::iter::once;
        use winapi::um::shellapi::ShellExecuteW;
        use winapi::um::winuser::SW_HIDE;
        
        // Kill by PID if we have it
        if let Some(pid) = pid {
            info!("Killing process with PID: {}", pid);
            let mut cmd = Command::new("taskkill");
            cmd.args(["/PID", &pid.to_string(), "/T", "/F"])
                .creation_flags(CREATE_NO_WINDOW)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let _ = cmd.output();
        }

        // Kill child process if we have it
        if let Some(ref mut child) = process {
            let pid = child.id();
            let mut cmd = Command::new("taskkill");
            cmd.args(["/PID", &pid.to_string(), "/T", "/F"])
                .creation_flags(CREATE_NO_WINDOW)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let _ = cmd.output();
            let _ = child.kill();
            let _ = child.wait();
        }

        // Try to kill by name as fallback (non-elevated first)
        let mut cmd = Command::new("taskkill");
        cmd.args(["/IM", "goodbyedpi.exe", "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _ = cmd.output();
        
        // Wait a bit and check if still running
        std::thread::sleep(std::time::Duration::from_millis(300));
        
        // If still running, use elevated taskkill
        if Self::find_process_pid().is_some() {
            info!("Process still running, trying elevated taskkill");
            let operation: Vec<u16> = OsStr::new("runas").encode_wide().chain(once(0)).collect();
            let file: Vec<u16> = OsStr::new("taskkill").encode_wide().chain(once(0)).collect();
            let parameters: Vec<u16> = OsStr::new("/IM goodbyedpi.exe /F").encode_wide().chain(once(0)).collect();
            
            unsafe {
                ShellExecuteW(
                    std::ptr::null_mut(),
                    operation.as_ptr(),
                    file.as_ptr(),
                    parameters.as_ptr(),
                    std::ptr::null(),
                    SW_HIDE,
                );
            }
            
            // Wait for process to be killed
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        info!("DPI bypass stopped");
        ServiceResult::Stopped
    }

    #[cfg(not(windows))]
    fn stop_async(pid: Option<u32>, mut process: Option<Child>) -> ServiceResult {
        if let Some(ref mut child) = process {
            let _ = child.kill();
            let _ = child.wait();
        }
        ServiceResult::Stopped
    }

    /// Toggle service state
    pub fn toggle(&mut self, profile: &str) -> anyhow::Result<()> {
        if self.status().is_running() {
            self.stop()
        } else {
            self.start(profile)
        }
    }

    /// Check if process is still running and poll async results
    pub fn check_status(&mut self) {
        // Check for async operation results (non-blocking)
        if let Some(ref rx) = self.result_rx {
            if let Ok(result) = rx.try_recv() {
                match result {
                    ServiceResult::Started(pid) => {
                        self.process_id = pid;
                        self.status = ServiceStatus::Running;
                        info!("Service started, PID: {:?}", pid);
                    }
                    ServiceResult::StartFailed(msg) => {
                        self.status = ServiceStatus::Error;
                        error!("Service start failed: {}", msg);
                    }
                    ServiceResult::Stopped => {
                        self.status = ServiceStatus::Stopped;
                        info!("Service stopped");
                    }
                    ServiceResult::StopFailed(msg) => {
                        self.status = ServiceStatus::Error;
                        error!("Service stop failed: {}", msg);
                    }
                }
                self.result_rx = None;
            }
        }

        // Check if running process is still alive
        if self.status == ServiceStatus::Running {
            if let Some(ref mut child) = self.process {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        self.process = None;
                        self.process_id = None;
                        self.status = ServiceStatus::Stopped;
                        info!("Process exited");
                    }
                    Ok(None) => {} // Still running
                    Err(e) => {
                        error!("Failed to check process: {}", e);
                    }
                }
            } else if self.process_id.is_some() {
                // Periodically check if elevated process is still running
                #[cfg(windows)]
                {
                    if Self::find_process_pid().is_none() {
                        self.process_id = None;
                        self.status = ServiceStatus::Stopped;
                        info!("Elevated process exited");
                    }
                }
            }
        }
    }

    /// Force kill any running process (for cleanup on exit)
    pub fn force_stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
        }
        
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            use std::iter::once;
            use winapi::um::shellapi::ShellExecuteW;
            use winapi::um::winuser::SW_HIDE;
            
            // First try normal taskkill
            let mut cmd = Command::new("taskkill");
            cmd.args(["/IM", "goodbyedpi.exe", "/F"])
                .creation_flags(CREATE_NO_WINDOW)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let _ = cmd.output();
            
            // If process still running, try with elevation
            if Self::find_process_pid().is_some() {
                // Use elevated taskkill via cmd /c
                let operation: Vec<u16> = OsStr::new("runas").encode_wide().chain(once(0)).collect();
                let file: Vec<u16> = OsStr::new("taskkill").encode_wide().chain(once(0)).collect();
                let parameters: Vec<u16> = OsStr::new("/IM goodbyedpi.exe /F").encode_wide().chain(once(0)).collect();
                
                unsafe {
                    ShellExecuteW(
                        std::ptr::null_mut(),
                        operation.as_ptr(),
                        file.as_ptr(),
                        parameters.as_ptr(),
                        std::ptr::null(),
                        SW_HIDE,
                    );
                }
                
                // Wait a bit for the process to be killed
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
        
        self.process_id = None;
        self.status = ServiceStatus::Stopped;
    }
}

impl Default for ServiceController {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ServiceController {
    fn drop(&mut self) {
        // Force stop on drop - don't use async stop here
        self.force_stop();
    }
}
