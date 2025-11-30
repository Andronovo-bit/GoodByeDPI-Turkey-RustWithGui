//! Main application and GUI window

use crate::config::GuiConfig;
use crate::service::{ServiceController, ServiceStatus};
use crate::tray::{TrayEvent, TrayManager};
use eframe::egui;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, error};

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
    /// Should quit
    should_quit: bool,
    /// Window visible
    window_visible: bool,
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
            should_quit: false,
            window_visible: true,
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
                    self.window_visible = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayEvent::SelectProfile(profile) => {
                    self.config.profile = profile;
                    let _ = self.config.save();
                }
                TrayEvent::OpenSettings => {
                    self.show_settings = true;
                    self.window_visible = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                }
                TrayEvent::Quit => {
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
            if service.status().is_running() {
                Some(service.stop())
            } else {
                None
            }
        };
        
        if let Some(res) = result {
            match res {
                Ok(_) => self.set_status("DPI bypass stopped"),
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

    /// Update service status
    fn check_service(&mut self) {
        self.service.lock().unwrap().check_status();
    }

    /// Render the main UI
    fn render_main_ui(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                
                // Title
                ui.heading(egui::RichText::new("GoodbyeDPI Turkey").size(24.0).strong());
                ui.label("DPI Bypass Tool");
                
                ui.add_space(30.0);

                // Status indicator
                let status = self.get_status();
                let (status_color, status_icon) = match status {
                    ServiceStatus::Running => (egui::Color32::from_rgb(76, 175, 80), "●"),
                    ServiceStatus::Starting => (egui::Color32::from_rgb(255, 193, 7), "◐"),
                    ServiceStatus::Stopping => (egui::Color32::from_rgb(255, 152, 0), "◐"),
                    ServiceStatus::Error => (egui::Color32::from_rgb(244, 67, 54), "●"),
                    ServiceStatus::Stopped => (egui::Color32::from_rgb(158, 158, 158), "○"),
                };

                ui.horizontal(|ui| {
                    ui.add_space(ui.available_width() / 2.0 - 80.0);
                    ui.label(egui::RichText::new(status_icon).size(48.0).color(status_color));
                    ui.vertical(|ui| {
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new(status.as_str()).size(20.0).color(status_color));
                    });
                });

                ui.add_space(30.0);

                // Start/Stop button
                let button_text = if status.is_running() { "⏹  Stop" } else { "▶  Start" };
                let button_color = if status.is_running() {
                    egui::Color32::from_rgb(244, 67, 54)
                } else {
                    egui::Color32::from_rgb(76, 175, 80)
                };

                let button = egui::Button::new(
                    egui::RichText::new(button_text).size(18.0).color(egui::Color32::WHITE)
                )
                .fill(button_color)
                .min_size(egui::vec2(150.0, 45.0));

                if ui.add(button).clicked() {
                    self.toggle_service();
                }

                ui.add_space(20.0);

                // Profile selector
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

        // Check service status periodically
        self.check_service();

        // Handle quit
        if self.should_quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        // Handle window close - minimize to tray instead
        ctx.input(|i| {
            if i.viewport().close_requested() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                self.window_visible = false;
            }
        });

        // Render UI
        self.render_main_ui(ctx);

        // Settings window
        if self.show_settings {
            self.render_settings(ctx);
        }

        // Request repaint for status updates
        ctx.request_repaint_after(Duration::from_millis(100));
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
