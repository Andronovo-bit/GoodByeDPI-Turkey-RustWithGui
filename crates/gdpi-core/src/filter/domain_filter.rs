//! Domain filtering implementation
//!
//! Provides whitelist and blacklist functionality for domain-based filtering.

use dashmap::DashSet;
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Filter mode determines how domains are filtered
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterMode {
    /// No filtering - all domains are processed
    #[default]
    Disabled,
    /// Whitelist mode - listed domains SKIP bypass (normal traffic)
    /// Use for: banks, government sites, sensitive sites
    Whitelist,
    /// Blacklist mode - ONLY listed domains get bypass applied
    /// Use for: specific blocked sites only
    Blacklist,
}

/// Result of domain filter check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterResult {
    /// Apply DPI bypass to this domain
    ApplyBypass,
    /// Skip bypass, let traffic pass normally
    SkipBypass,
}

/// Domain filter for whitelist/blacklist management
///
/// Thread-safe and supports hot-reload from file.
#[derive(Debug)]
pub struct DomainFilter {
    /// Current filter mode
    mode: RwLock<FilterMode>,
    /// Exact domain matches
    exact_domains: DashSet<String>,
    /// Wildcard patterns (stored without *. prefix)
    wildcard_domains: DashSet<String>,
    /// Source file path for hot-reload
    file_path: RwLock<Option<PathBuf>>,
    /// Last modification time of the file
    last_modified: RwLock<Option<SystemTime>>,
}

impl Default for DomainFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self {
            mode: RwLock::new(FilterMode::Disabled),
            exact_domains: DashSet::new(),
            wildcard_domains: DashSet::new(),
            file_path: RwLock::new(None),
            last_modified: RwLock::new(None),
        }
    }

    /// Create filter with initial domains
    pub fn with_domains(mode: FilterMode, domains: Vec<String>) -> Self {
        let filter = Self::new();
        *filter.mode.write() = mode;
        
        for domain in domains {
            filter.add_domain(&domain);
        }
        
        filter
    }

    /// Create filter from a file
    pub fn from_file<P: AsRef<Path>>(path: P, mode: FilterMode) -> std::io::Result<Self> {
        let filter = Self::new();
        *filter.mode.write() = mode;
        filter.load_file(path)?;
        Ok(filter)
    }

    /// Get current filter mode
    pub fn mode(&self) -> FilterMode {
        *self.mode.read()
    }

    /// Set filter mode
    pub fn set_mode(&self, mode: FilterMode) {
        *self.mode.write() = mode;
    }

    /// Add a domain to the filter
    ///
    /// Supports:
    /// - Exact domains: "example.com"
    /// - Wildcard: "*.example.com" (matches any subdomain)
    pub fn add_domain(&self, domain: &str) {
        let domain = domain.trim().to_lowercase();
        
        if domain.is_empty() || domain.starts_with('#') {
            return;
        }

        if let Some(stripped) = domain.strip_prefix("*.") {
            self.wildcard_domains.insert(stripped.to_string());
        } else {
            self.exact_domains.insert(domain);
        }
    }

    /// Remove a domain from the filter
    pub fn remove_domain(&self, domain: &str) {
        let domain = domain.trim().to_lowercase();
        
        if let Some(stripped) = domain.strip_prefix("*.") {
            self.wildcard_domains.remove(stripped);
        } else {
            self.exact_domains.remove(&domain);
        }
    }

    /// Clear all domains
    pub fn clear(&self) {
        self.exact_domains.clear();
        self.wildcard_domains.clear();
    }

    /// Load domains from a file
    ///
    /// File format:
    /// - One domain per line
    /// - Lines starting with # are comments
    /// - Empty lines are ignored
    /// - Wildcard: *.example.com
    pub fn load_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<usize> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        
        // Store file path for hot-reload
        *self.file_path.write() = Some(path.to_path_buf());
        
        // Store modification time
        if let Ok(metadata) = std::fs::metadata(path) {
            if let Ok(modified) = metadata.modified() {
                *self.last_modified.write() = Some(modified);
            }
        }

        self.clear();
        
        let mut count = 0;
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                self.add_domain(line);
                count += 1;
            }
        }

        info!("Loaded {} domains from {}", count, path.display());
        Ok(count)
    }

    /// Check if file has been modified and reload if necessary
    pub fn check_reload(&self) -> std::io::Result<bool> {
        let file_path = self.file_path.read().clone();
        let Some(path) = file_path else {
            return Ok(false);
        };

        let metadata = std::fs::metadata(&path)?;
        let modified = metadata.modified()?;

        let last_modified = *self.last_modified.read();
        if last_modified.map_or(true, |last| modified > last) {
            info!("Filter file changed, reloading: {}", path.display());
            self.load_file(&path)?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Save current domains to file
    pub fn save_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let path = path.as_ref();
        let mut content = String::new();

        content.push_str("# GoodbyeDPI Turkey - Domain Filter\n");
        content.push_str("# \n");
        content.push_str("# One domain per line\n");
        content.push_str("# Use *.example.com for wildcard matching\n");
        content.push_str("# Lines starting with # are comments\n");
        content.push_str("#\n");
        content.push_str(&format!("# Mode: {:?}\n", self.mode()));
        content.push_str("#\n\n");

        // Write exact domains
        for domain in self.exact_domains.iter() {
            content.push_str(&domain);
            content.push('\n');
        }

        // Write wildcard domains
        for domain in self.wildcard_domains.iter() {
            content.push_str("*.");
            content.push_str(&domain);
            content.push('\n');
        }

        std::fs::write(path, content)?;
        
        // Update file path and modification time
        *self.file_path.write() = Some(path.to_path_buf());
        if let Ok(metadata) = std::fs::metadata(path) {
            if let Ok(modified) = metadata.modified() {
                *self.last_modified.write() = Some(modified);
            }
        }

        info!("Saved {} domains to {}", self.len(), path.display());
        Ok(())
    }

    /// Check if a domain should have bypass applied
    pub fn check(&self, hostname: &str) -> FilterResult {
        let mode = *self.mode.read();
        
        match mode {
            FilterMode::Disabled => FilterResult::ApplyBypass,
            FilterMode::Whitelist => {
                // Whitelist: if in list, SKIP bypass
                if self.matches(hostname) {
                    debug!("Domain {} is whitelisted, skipping bypass", hostname);
                    FilterResult::SkipBypass
                } else {
                    FilterResult::ApplyBypass
                }
            }
            FilterMode::Blacklist => {
                // Blacklist: ONLY listed domains get bypass
                if self.matches(hostname) {
                    FilterResult::ApplyBypass
                } else {
                    debug!("Domain {} not in blacklist, skipping bypass", hostname);
                    FilterResult::SkipBypass
                }
            }
        }
    }

    /// Check if a hostname matches any filter entry
    pub fn matches(&self, hostname: &str) -> bool {
        let hostname = hostname.to_lowercase();

        // Check exact match
        if self.exact_domains.contains(&hostname) {
            return true;
        }

        // Check wildcard matches (suffix matching)
        // For example, if "example.com" is in wildcards,
        // it matches "sub.example.com", "deep.sub.example.com"
        let mut current = hostname.as_str();
        loop {
            if self.wildcard_domains.contains(current) {
                return true;
            }
            
            // Move to parent domain
            match current.find('.') {
                Some(pos) => current = &current[pos + 1..],
                None => break,
            }
        }

        // Also check if the hostname itself is a wildcard target
        // (e.g., hostname "example.com" matches wildcard "example.com")
        if self.wildcard_domains.contains(&hostname) {
            return true;
        }

        false
    }

    /// Get total number of domains in filter
    pub fn len(&self) -> usize {
        self.exact_domains.len() + self.wildcard_domains.len()
    }

    /// Check if filter is empty
    pub fn is_empty(&self) -> bool {
        self.exact_domains.is_empty() && self.wildcard_domains.is_empty()
    }

    /// Get all domains as a vector
    pub fn domains(&self) -> Vec<String> {
        let mut result: Vec<String> = self.exact_domains
            .iter()
            .map(|d| d.clone())
            .collect();
        
        for d in self.wildcard_domains.iter() {
            result.push(format!("*.{}", d.as_str()));
        }
        
        result.sort();
        result
    }
}

/// Create filter from configuration
impl DomainFilter {
    /// Create from config with local file support
    pub fn from_config(
        enabled: bool,
        mode_str: &str,
        file_path: Option<&str>,
        inline_domains: &[String],
    ) -> std::io::Result<Self> {
        if !enabled {
            return Ok(Self::new());
        }

        let mode = match mode_str.to_lowercase().as_str() {
            "whitelist" | "white" => FilterMode::Whitelist,
            "blacklist" | "black" => FilterMode::Blacklist,
            _ => FilterMode::Disabled,
        };

        let filter = Self::new();
        *filter.mode.write() = mode;

        // Load from file if specified
        if let Some(path) = file_path {
            if Path::new(path).exists() {
                filter.load_file(path)?;
            } else {
                warn!("Filter file not found: {}", path);
            }
        }

        // Add inline domains
        for domain in inline_domains {
            filter.add_domain(domain);
        }

        Ok(filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let filter = DomainFilter::with_domains(
            FilterMode::Blacklist,
            vec!["example.com".to_string()],
        );

        assert!(filter.matches("example.com"));
        assert!(!filter.matches("other.com"));
    }

    #[test]
    fn test_wildcard_match() {
        let filter = DomainFilter::with_domains(
            FilterMode::Blacklist,
            vec!["*.example.com".to_string()],
        );

        assert!(filter.matches("sub.example.com"));
        assert!(filter.matches("deep.sub.example.com"));
        assert!(filter.matches("example.com")); // wildcard also matches base
        assert!(!filter.matches("other.com"));
    }

    #[test]
    fn test_whitelist_mode() {
        let filter = DomainFilter::with_domains(
            FilterMode::Whitelist,
            vec!["bank.com".to_string()],
        );

        // Whitelisted = skip bypass
        assert_eq!(filter.check("bank.com"), FilterResult::SkipBypass);
        // Not in whitelist = apply bypass
        assert_eq!(filter.check("youtube.com"), FilterResult::ApplyBypass);
    }

    #[test]
    fn test_blacklist_mode() {
        let filter = DomainFilter::with_domains(
            FilterMode::Blacklist,
            vec!["blocked.com".to_string()],
        );

        // In blacklist = apply bypass
        assert_eq!(filter.check("blocked.com"), FilterResult::ApplyBypass);
        // Not in blacklist = skip bypass
        assert_eq!(filter.check("other.com"), FilterResult::SkipBypass);
    }

    #[test]
    fn test_disabled_mode() {
        let filter = DomainFilter::new();
        
        // Disabled = always apply bypass
        assert_eq!(filter.check("any.com"), FilterResult::ApplyBypass);
    }
}
