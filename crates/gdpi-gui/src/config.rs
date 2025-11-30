//! Application configuration and state persistence

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiConfig {
    /// Currently selected profile
    pub profile: String,
    /// Start minimized to tray
    pub start_minimized: bool,
    /// Start with Windows
    pub auto_start: bool,
    /// Auto-connect on startup
    pub auto_connect: bool,
    /// Show notifications
    pub show_notifications: bool,
    /// Last window position
    pub window_pos: Option<(f32, f32)>,
    /// Last window size
    pub window_size: Option<(f32, f32)>,
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            profile: "turkey".to_string(),
            start_minimized: false,
            auto_start: false,
            auto_connect: false,
            show_notifications: true,
            window_pos: None,
            window_size: None,
        }
    }
}

impl GuiConfig {
    /// Get config file path
    pub fn config_path() -> PathBuf {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        
        exe_dir.join("gui_config.json")
    }

    /// Load configuration from file
    pub fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Self::default()
        }
    }

    /// Save configuration to file
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::config_path();
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Get available profiles
    pub fn available_profiles() -> Vec<String> {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        
        let configs_dir = exe_dir.join("configs");
        
        if !configs_dir.exists() {
            return vec!["turkey".to_string()];
        }

        std::fs::read_dir(configs_dir)
            .ok()
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().map_or(false, |ext| ext == "toml"))
                    .filter_map(|e| {
                        e.path()
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_else(|| vec!["turkey".to_string()])
    }
}
