//! System tray icon management

use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, CheckMenuItem},
    TrayIcon, TrayIconBuilder, Icon,
};
use std::sync::mpsc;
use tracing::{info, error};

/// Tray menu item IDs
pub mod menu_ids {
    pub const TOGGLE: &str = "toggle";
    pub const SHOW: &str = "show";
    pub const PROFILES: &str = "profiles";
    pub const SETTINGS: &str = "settings";
    pub const QUIT: &str = "quit";
}

/// Tray events sent to the main application
#[derive(Debug, Clone)]
pub enum TrayEvent {
    Toggle,
    Show,
    SelectProfile(String),
    OpenSettings,
    Quit,
    LeftClick,
}

/// System tray manager
pub struct TrayManager {
    _tray: TrayIcon,
    event_rx: mpsc::Receiver<TrayEvent>,
}

impl TrayManager {
    /// Create a new tray manager
    pub fn new(profiles: &[String], current_profile: &str, is_running: bool) -> anyhow::Result<Self> {
        let (event_tx, event_rx) = mpsc::channel();

        // Create menu
        let menu = Self::create_menu(profiles, current_profile, is_running)?;

        // Create icon
        let icon = Self::create_icon(is_running)?;

        // Build tray icon
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(Self::tooltip_text(is_running))
            .with_icon(icon)
            .build()?;

        // Handle menu events
        let tx = event_tx.clone();
        std::thread::spawn(move || {
            loop {
                if let Ok(event) = MenuEvent::receiver().recv() {
                    let tray_event = match event.id.0.as_str() {
                        menu_ids::TOGGLE => TrayEvent::Toggle,
                        menu_ids::SHOW => TrayEvent::Show,
                        menu_ids::SETTINGS => TrayEvent::OpenSettings,
                        menu_ids::QUIT => TrayEvent::Quit,
                        id if id.starts_with("profile_") => {
                            let profile = id.strip_prefix("profile_").unwrap_or("turkey");
                            TrayEvent::SelectProfile(profile.to_string())
                        }
                        _ => continue,
                    };
                    let _ = tx.send(tray_event);
                }
            }
        });

        Ok(Self {
            _tray: tray,
            event_rx,
        })
    }

    /// Create the tray menu
    fn create_menu(profiles: &[String], current_profile: &str, is_running: bool) -> anyhow::Result<Menu> {
        let menu = Menu::new();

        // Toggle button
        let toggle_text = if is_running { "⏹ Stop" } else { "▶ Start" };
        let toggle = MenuItem::with_id(menu_ids::TOGGLE, toggle_text, true, None);
        menu.append(&toggle)?;

        menu.append(&PredefinedMenuItem::separator())?;

        // Profiles submenu
        let profiles_submenu = tray_icon::menu::Submenu::new("Profile", true);
        for profile in profiles {
            let is_current = profile == current_profile;
            let item = CheckMenuItem::with_id(
                format!("profile_{}", profile),
                profile,
                true,
                is_current,
                None,
            );
            profiles_submenu.append(&item)?;
        }
        menu.append(&profiles_submenu)?;

        menu.append(&PredefinedMenuItem::separator())?;

        // Show window
        let show = MenuItem::with_id(menu_ids::SHOW, "Show Window", true, None);
        menu.append(&show)?;

        // Settings
        let settings = MenuItem::with_id(menu_ids::SETTINGS, "Settings", true, None);
        menu.append(&settings)?;

        menu.append(&PredefinedMenuItem::separator())?;

        // Quit
        let quit = MenuItem::with_id(menu_ids::QUIT, "Quit", true, None);
        menu.append(&quit)?;

        Ok(menu)
    }

    /// Create tray icon based on status
    fn create_icon(is_running: bool) -> anyhow::Result<Icon> {
        // Create a simple colored icon (16x16)
        let size = 16u32;
        let mut rgba = Vec::with_capacity((size * size * 4) as usize);
        
        let (r, g, b) = if is_running {
            (0x4C, 0xAF, 0x50) // Green when running
        } else {
            (0x9E, 0x9E, 0x9E) // Gray when stopped
        };

        for y in 0..size {
            for x in 0..size {
                // Create a circular icon
                let cx = size as f32 / 2.0;
                let cy = size as f32 / 2.0;
                let dist = ((x as f32 - cx).powi(2) + (y as f32 - cy).powi(2)).sqrt();
                
                if dist < (size as f32 / 2.0) - 1.0 {
                    rgba.push(r);
                    rgba.push(g);
                    rgba.push(b);
                    rgba.push(255); // Alpha
                } else {
                    rgba.push(0);
                    rgba.push(0);
                    rgba.push(0);
                    rgba.push(0); // Transparent
                }
            }
        }

        Icon::from_rgba(rgba, size, size).map_err(|e| anyhow::anyhow!("Failed to create icon: {}", e))
    }

    /// Get tooltip text
    fn tooltip_text(is_running: bool) -> &'static str {
        if is_running {
            "GoodbyeDPI Turkey - Running"
        } else {
            "GoodbyeDPI Turkey - Stopped"
        }
    }

    /// Try to receive a tray event (non-blocking)
    pub fn try_recv(&self) -> Option<TrayEvent> {
        self.event_rx.try_recv().ok()
    }
}
