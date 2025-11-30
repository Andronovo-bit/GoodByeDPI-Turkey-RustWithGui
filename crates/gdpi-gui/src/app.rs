//! Main application and GUI window

use crate::config::GuiConfig;
use crate::service::{ServiceController, ServiceStatus};
use crate::tray::{TrayEvent, TrayManager};
use eframe::egui;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use tracing::{info, error};

#[cfg(windows)]
use winapi::um::winuser::{SetWindowPos, ShowWindow, SetForegroundWindow, GetWindowRect, 
    HWND_TOP, SWP_SHOWWINDOW, SWP_NOSIZE, SWP_NOZORDER, SWP_NOACTIVATE, SW_HIDE, SW_SHOW};

/// Flag to request window show from another thread
static SHOW_WINDOW_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Saved window position for restore
static mut SAVED_WINDOW_POS: Option<(i32, i32)> = None;

/// Application state
pub struct GoodbyeDpiApp {
    /// Configuration
    config: GuiConfig,
    /// Service controller
    service: Arc<Mutex<ServiceController>>,
    /// Available profiles
    profiles: Vec<String>,
    /// Show settings panel
    show_settings: bool,
    /// Status message
    status_message: Option<(String, Instant)>,
    /// Tray manager (optional - created after window)
    tray: Option<TrayManager>,
    /// Pending show from tray request
    pending_show: bool,
    /// Should quit
    should_quit: bool,
    /// Window visible
    window_visible: bool,
    /// Animation start time for loading spinner
    animation_start: Instant,
}

impl GoodbyeDpiApp {
    /// Create new application
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let config = GuiConfig::load();
        let profiles = GuiConfig::available_profiles();
        
        Self {
            config,
            service: Arc::new(Mutex::new(ServiceController::new())),
            profiles,
            show_settings: false,
            status_message: None,
            tray: None,
            pending_show: false,
            should_quit: false,
            window_visible: true,
            animation_start: Instant::now(),
        }
    }

    /// Initialize tray icon (must be called from main thread after window creation)
    fn init_tray(&mut self) {
        if self.tray.is_some() {
            return;
        }

        let is_running = self.service.lock().unwrap().status().is_running();
        
        match TrayManager::new(&self.profiles, &self.config.profile, is_running) {
            Ok(tray) => {
                self.tray = Some(tray);
                info!("System tray initialized");
            }
            Err(e) => {
                error!("Failed to create tray icon: {}", e);
            }
        }
    }

    /// Hide window to tray using Windows API
    fn hide_to_tray(&mut self, ctx: &egui::Context) {
        self.window_visible = false;
        self.pending_show = false;
        SHOW_WINDOW_REQUESTED.store(false, Ordering::SeqCst);
        
        #[cfg(windows)]
        {
            if let Some(hwnd) = self.get_window_handle(ctx) {
                unsafe {
                    // Save current position before hiding
                    let mut rect: winapi::shared::windef::RECT = std::mem::zeroed();
                    if GetWindowRect(hwnd, &mut rect) != 0 {
                        SAVED_WINDOW_POS = Some((rect.left, rect.top));
                    }
                    
                    // Hide the window completely
                    ShowWindow(hwnd, SW_HIDE);
                }
            }
        }
        
        #[cfg(not(windows))]
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(-10000.0, -10000.0)));
        }
    }

    /// Show window from tray (sets atomic flag - window shows itself via timer)
    fn show_from_tray(&mut self, _ctx: &egui::Context) {
        SHOW_WINDOW_REQUESTED.store(true, Ordering::SeqCst);
        self.pending_show = true;
    }
    
    /// Process pending show request (must be called from update)
    fn process_pending_show(&mut self, ctx: &egui::Context) {
        // Check both the atomic flag (set from tray thread) and pending_show
        if self.pending_show || SHOW_WINDOW_REQUESTED.load(Ordering::SeqCst) {
            self.pending_show = false;
            SHOW_WINDOW_REQUESTED.store(false, Ordering::SeqCst);
            self.window_visible = true;
            
            #[cfg(windows)]
            {
                if let Some(hwnd) = self.get_window_handle(ctx) {
                    unsafe {
                        // Show window
                        ShowWindow(hwnd, SW_SHOW);
                        
                        // Restore saved position or use default
                        let (x, y) = SAVED_WINDOW_POS.unwrap_or((100, 100));
                        SetWindowPos(hwnd, HWND_TOP, x, y, 0, 0, SWP_SHOWWINDOW | SWP_NOSIZE);
                        
                        // Bring to foreground
                        SetForegroundWindow(hwnd);
                    }
                } else {
                    ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(100.0, 100.0)));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
            }
            
            #[cfg(not(windows))]
            {
                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(100.0, 100.0)));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            }
            
            ctx.request_repaint();
        }
    }
    
    /// Get the native window handle
    #[cfg(windows)]
    fn get_window_handle(&self, _ctx: &egui::Context) -> Option<winapi::shared::windef::HWND> {
        // Find window by title
        unsafe {
            let title = "GoodbyeDPI Turkey\0";
            let hwnd = winapi::um::winuser::FindWindowA(
                std::ptr::null(),
                title.as_ptr() as *const i8
            );
            if !hwnd.is_null() {
                Some(hwnd)
            } else {
                None
            }
        }
    }

    /// Handle tray events
    fn handle_tray_events(&mut self, ctx: &egui::Context) {
        // Collect events first to avoid borrow issues
        let events: Vec<TrayEvent> = if let Some(ref tray) = self.tray {
            let mut events = Vec::new();
            while let Some(event) = tray.try_recv() {
                events.push(event);
            }
            events
        } else {
            Vec::new()
        };

        // Process events
        for event in events {
            match event {
                TrayEvent::Toggle => {
                    self.toggle_service();
                }
                TrayEvent::Show | TrayEvent::LeftClick => {
                    self.show_from_tray(ctx);
                }
                TrayEvent::SelectProfile(profile) => {
                    self.config.profile = profile;
                    let _ = self.config.save();
                }
                TrayEvent::OpenSettings => {
                    self.show_settings = true;
                    self.show_from_tray(ctx);
                }
                TrayEvent::Quit => {
                    // Stop service before quitting
                    {
                        let mut service = self.service.lock().unwrap();
                        service.force_stop();
                    }
                    self.should_quit = true;
                }
            }
        }
    }

    /// Toggle service on/off
    fn toggle_service(&mut self) {
        let result = {
            let mut service = self.service.lock().unwrap();
            let res = service.toggle(&self.config.profile);
            let is_running = service.status().is_running();
            (res, is_running)
        };
        
        match result {
            (Ok(_), is_running) => {
                let msg = if is_running {
                    "DPI bypass started"
                } else {
                    "DPI bypass stopped"
                };
                self.set_status(msg);
            }
            (Err(e), _) => {
                self.set_status(&format!("Error: {}", e));
            }
        }
    }

    /// Start the service
    fn start_service(&mut self) {
        let result = {
            let mut service = self.service.lock().unwrap();
            if !service.status().is_running() {
                Some(service.start(&self.config.profile))
            } else {
                None
            }
        };
        
        if let Some(res) = result {
            match res {
                Ok(_) => self.set_status("DPI bypass started"),
                Err(e) => self.set_status(&format!("Failed to start: {}", e)),
            }
        }
    }

    /// Stop the service
    fn stop_service(&mut self) {
        let result = {
            let mut service = self.service.lock().unwrap();
            let status = service.status();
            if status == ServiceStatus::Running || status == ServiceStatus::Starting {
                Some(service.stop())
            } else {
                None
            }
        };
        
        if let Some(res) = result {
            match res {
                Ok(_) => self.set_status("Stopping DPI bypass..."),
                Err(e) => self.set_status(&format!("Failed to stop: {}", e)),
            }
        }
    }

    /// Set status message
    fn set_status(&mut self, msg: &str) {
        self.status_message = Some((msg.to_string(), Instant::now()));
    }

    /// Get current status
    fn get_status(&self) -> ServiceStatus {
        self.service.lock().unwrap().status()
    }

    /// Update service status and sync tray
    fn check_service(&mut self) {
        let status = {
            let mut service = self.service.lock().unwrap();
            service.check_status();
            service.status()
        };
        
        // Update tray icon/menu based on service status
        if let Some(ref mut tray) = self.tray {
            let is_running = status == ServiceStatus::Running;
            tray.update_status(is_running);
        }
    }

    /// Render the main UI
    fn render_main_ui(&mut self, ctx: &egui::Context) {
        // Top bar with window controls
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("GoodbyeDPI Turkey").size(16.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Close button (quit)
                    if ui.button("✕").on_hover_text("Quit").clicked() {
                        self.should_quit = true;
                    }
                    // Minimize to tray button
                    if ui.button("—").on_hover_text("Minimize to tray").clicked() {
                        self.hide_to_tray(ctx);
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                
                // Subtitle
                ui.label("DPI Bypass Tool");
                
                ui.add_space(30.0);

                // Status indicator
                let status = self.get_status();
                let is_loading = matches!(status, ServiceStatus::Starting | ServiceStatus::Stopping);
                
                // Animated spinner for loading states
                let elapsed = self.animation_start.elapsed().as_secs_f32();
                let spin_char = if is_loading {
                    let chars = ["◐", "◓", "◑", "◒"];
                    let idx = ((elapsed * 4.0) as usize) % chars.len();
                    chars[idx]
                } else {
                    match status {
                        ServiceStatus::Running => "●",
                        ServiceStatus::Error => "●",
                        ServiceStatus::Stopped => "○",
                        _ => "◐",
                    }
                };
                
                let status_color = match status {
                    ServiceStatus::Running => egui::Color32::from_rgb(76, 175, 80),
                    ServiceStatus::Starting => egui::Color32::from_rgb(255, 193, 7),
                    ServiceStatus::Stopping => egui::Color32::from_rgb(255, 152, 0),
                    ServiceStatus::Error => egui::Color32::from_rgb(244, 67, 54),
                    ServiceStatus::Stopped => egui::Color32::from_rgb(158, 158, 158),
                };

                ui.horizontal(|ui| {
                    ui.add_space(ui.available_width() / 2.0 - 80.0);
                    ui.label(egui::RichText::new(spin_char).size(48.0).color(status_color));
                    ui.vertical(|ui| {
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new(status.as_str()).size(20.0).color(status_color));
                    });
                });

                ui.add_space(30.0);

                // Start/Stop button with loading state
                let (button_text, button_color, button_enabled) = match status {
                    ServiceStatus::Starting => (
                        "⏳  Starting...",
                        egui::Color32::from_rgb(255, 193, 7),
                        false
                    ),
                    ServiceStatus::Stopping => (
                        "⏳  Stopping...",
                        egui::Color32::from_rgb(255, 152, 0),
                        false
                    ),
                    ServiceStatus::Running => (
                        "⏹  Stop",
                        egui::Color32::from_rgb(244, 67, 54),
                        true
                    ),
                    _ => (
                        "▶  Start",
                        egui::Color32::from_rgb(76, 175, 80),
                        true
                    ),
                };

                let button = egui::Button::new(
                    egui::RichText::new(button_text).size(18.0).color(egui::Color32::WHITE)
                )
                .fill(if button_enabled { button_color } else { button_color.gamma_multiply(0.7) })
                .min_size(egui::vec2(160.0, 45.0));

                let response = ui.add_enabled(button_enabled, button);
                if response.clicked() {
                    self.toggle_service();
                }
                
                // Show tooltip on disabled button
                if !button_enabled {
                    response.on_hover_text("Please wait...");
                }

                // Progress bar during loading
                if is_loading {
                    ui.add_space(10.0);
                    let progress = (elapsed * 0.5).sin() * 0.5 + 0.5; // Pulsing effect
                    let progress_bar = egui::ProgressBar::new(progress)
                        .animate(true);
                    ui.add_sized([200.0, 8.0], progress_bar);
                }

                ui.add_space(20.0);

                // Profile selector (disabled during loading)
                ui.add_enabled_ui(!is_loading, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Profile:");
                        egui::ComboBox::from_id_salt("profile_selector")
                            .selected_text(&self.config.profile)
                            .show_ui(ui, |ui| {
                                for profile in &self.profiles {
                                    if ui.selectable_value(&mut self.config.profile, profile.clone(), profile).changed() {
                                        let _ = self.config.save();
                                    }
                                }
                            });
                    });
                });

                ui.add_space(20.0);

                // Status message
                if let Some((ref msg, time)) = self.status_message {
                    if time.elapsed() < Duration::from_secs(5) {
                        ui.label(egui::RichText::new(msg).italics().color(egui::Color32::GRAY));
                    }
                }

                // Settings button at bottom
                ui.add_space(20.0);
                if ui.button("⚙  Settings").clicked() {
                    self.show_settings = true;
                }
            });
        });
    }

    /// Render settings panel
    fn render_settings(&mut self, ctx: &egui::Context) {
        egui::Window::new("Settings")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.checkbox(&mut self.config.start_minimized, "Start minimized to tray");
                ui.checkbox(&mut self.config.auto_start, "Start with Windows");
                ui.checkbox(&mut self.config.auto_connect, "Auto-connect on startup");
                ui.checkbox(&mut self.config.show_notifications, "Show notifications");

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        if let Err(e) = self.config.save() {
                            self.set_status(&format!("Failed to save: {}", e));
                        } else {
                            self.set_status("Settings saved");
                            self.show_settings = false;
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.show_settings = false;
                    }
                });
            });
    }
}

impl eframe::App for GoodbyeDpiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Initialize tray on first frame
        self.init_tray();

        // Handle tray events
        self.handle_tray_events(ctx);
        
        // Process any pending show request from tray
        self.process_pending_show(ctx);

        // Check service status periodically (non-blocking)
        self.check_service();

        // Handle native window close (X button) - minimize to tray instead
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if close_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.hide_to_tray(ctx);
        }

        // Handle quit - stop service first
        if self.should_quit {
            // Force stop service before closing
            if let Ok(mut service) = self.service.try_lock() {
                service.force_stop();
            }
            // Exit the process completely
            std::process::exit(0);
        }

        // Always render UI (even when "hidden" - egui needs to process events)
        self.render_main_ui(ctx);

        // Settings window
        if self.show_settings {
            self.render_settings(ctx);
        }

        // Request repaint - faster during loading states
        let status = self.get_status();
        let is_loading = matches!(status, ServiceStatus::Starting | ServiceStatus::Stopping);
        let repaint_delay = if is_loading {
            Duration::from_millis(50)  // Fast animation during loading
        } else {
            Duration::from_millis(100) // Keep responsive for tray events
        };
        ctx.request_repaint_after(repaint_delay);
    }
}

/// Run the application
pub fn run() -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([350.0, 400.0])
            .with_min_inner_size([300.0, 350.0])
            .with_icon(load_app_icon())
            .with_title("GoodbyeDPI Turkey"),
        ..Default::default()
    };

    eframe::run_native(
        "GoodbyeDPI Turkey",
        options,
        Box::new(|cc| Ok(Box::new(GoodbyeDpiApp::new(cc)))),
    ).map_err(|e| anyhow::anyhow!("Failed to run GUI: {}", e))
}

/// Load application icon
fn load_app_icon() -> egui::IconData {
    // Create a simple green icon
    let size = 32u32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    
    for y in 0..size {
        for x in 0..size {
            let cx = size as f32 / 2.0;
            let cy = size as f32 / 2.0;
            let dist = ((x as f32 - cx).powi(2) + (y as f32 - cy).powi(2)).sqrt();
            
            if dist < (size as f32 / 2.0) - 2.0 {
                rgba.push(0x4C); // R
                rgba.push(0xAF); // G
                rgba.push(0x50); // B
                rgba.push(255);  // A
            } else {
                rgba.push(0);
                rgba.push(0);
                rgba.push(0);
                rgba.push(0);
            }
        }
    }

    egui::IconData {
        rgba,
        width: size,
        height: size,
    }
}
