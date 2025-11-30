//! WinDivert driver wrapper
//!
//! Safe Rust wrapper around WinDivert FFI.

use crate::error::{PlatformError, Result};
use crate::traits::{CapturedPacket, PacketAddress, PacketCapture, PacketFilter};
use std::ptr;
use tracing::{debug, info, warn};

/// WinDivert layer enum
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Network layer (IP packets)
    Network = 0,
    /// Network layer forwarding
    NetworkForward = 1,
    /// Flow layer (connection tracking)
    Flow = 2,
    /// Socket layer
    Socket = 3,
    /// Reflect layer (for driver itself)
    Reflect = 4,
}

/// WinDivert flags
#[derive(Debug, Clone, Copy, Default)]
pub struct Flags {
    /// Sniff mode (don't drop original)
    pub sniff: bool,
    /// Drop mode (don't receive packets)
    pub drop: bool,
    /// Receive only (no send)
    pub recv_only: bool,
    /// Send only (no receive)
    pub send_only: bool,
    /// No install (don't install driver)
    pub no_install: bool,
    /// Fragments enabled
    pub fragments: bool,
}

impl Flags {
    /// Convert to WinDivert flags value
    pub fn to_value(&self) -> u64 {
        let mut flags = 0u64;
        if self.sniff { flags |= 0x0001; }
        if self.drop { flags |= 0x0002; }
        if self.recv_only { flags |= 0x0004; }
        if self.send_only { flags |= 0x0008; }
        if self.no_install { flags |= 0x0010; }
        if self.fragments { flags |= 0x0020; }
        flags
    }
}

/// WinDivert driver wrapper
///
/// Provides safe access to WinDivert packet capture and injection.
///
/// # Example
///
/// ```rust,ignore
/// use gdpi_platform::windows::WinDivertDriver;
/// use gdpi_platform::PacketCapture;
///
/// let mut driver = WinDivertDriver::open(
///     "outbound and tcp.DstPort == 443",
///     Default::default(),
/// ).expect("Failed to open driver");
///
/// loop {
///     let captured = driver.recv().expect("Failed to receive");
///     // Process packet...
///     driver.send(&captured.data, &captured.address).expect("Failed to send");
/// }
/// ```
pub struct WinDivertDriver {
    /// WinDivert handle (platform-specific)
    #[cfg(windows)]
    handle: *mut std::ffi::c_void,
    #[cfg(not(windows))]
    handle: usize,
    /// Current filter
    filter: String,
    /// Layer
    layer: Layer,
    /// Buffer for receiving packets
    recv_buffer: Vec<u8>,
    /// Is handle valid
    is_open: bool,
}

// Safety: WinDivert handle can be sent between threads
unsafe impl Send for WinDivertDriver {}

impl WinDivertDriver {
    /// Maximum packet size
    pub const MAX_PACKET_SIZE: usize = 65535;

    /// Default queue length
    pub const DEFAULT_QUEUE_LEN: u32 = 8192;

    /// Default queue time (ms)
    pub const DEFAULT_QUEUE_TIME: u32 = 1000;

    /// Open WinDivert with a filter
    ///
    /// # Arguments
    /// * `filter` - WinDivert filter string
    /// * `flags` - Optional flags
    ///
    /// # Errors
    /// Returns error if driver is not installed or filter is invalid.
    #[cfg(windows)]
    pub fn open(filter: &str, flags: Flags) -> Result<Self> {
        Self::open_ex(filter, Layer::Network, 0, flags)
    }

    /// Open WinDivert with full options
    #[cfg(windows)]
    pub fn open_ex(filter: &str, layer: Layer, priority: i16, flags: Flags) -> Result<Self> {
        use std::ffi::CString;

        info!(filter = filter, layer = ?layer, "Opening WinDivert handle");

        // Validate filter first
        Self::validate_filter_internal(filter)?;

        let c_filter = CString::new(filter)
            .map_err(|_| PlatformError::InvalidFilter("Invalid characters in filter".into()))?;

        // WinDivert FFI call would go here
        // For now, we use a placeholder
        let handle: *mut std::ffi::c_void = unsafe {
            // windivert_sys::WinDivertOpen(
            //     c_filter.as_ptr(),
            //     layer as i32,
            //     priority,
            //     flags.to_value(),
            // )
            ptr::null_mut() // Placeholder
        };

        if handle.is_null() {
            let error = unsafe { 
                // winapi::um::errhandlingapi::GetLastError()
                0u32 // Placeholder
            };
            return Err(PlatformError::DriverInitFailed(
                format!("WinDivertOpen failed with error {}", error)
            ));
        }

        Ok(Self {
            handle,
            filter: filter.to_string(),
            layer,
            recv_buffer: vec![0u8; Self::MAX_PACKET_SIZE],
            is_open: true,
        })
    }

    /// Stub implementation for non-Windows
    #[cfg(not(windows))]
    pub fn open(filter: &str, _flags: Flags) -> Result<Self> {
        warn!("WinDivert is only available on Windows");
        Ok(Self {
            handle: 0,
            filter: filter.to_string(),
            layer: Layer::Network,
            recv_buffer: vec![0u8; Self::MAX_PACKET_SIZE],
            is_open: false,
        })
    }

    /// Stub implementation for non-Windows
    #[cfg(not(windows))]
    pub fn open_ex(filter: &str, layer: Layer, _priority: i16, _flags: Flags) -> Result<Self> {
        warn!("WinDivert is only available on Windows");
        Ok(Self {
            handle: 0,
            filter: filter.to_string(),
            layer,
            recv_buffer: vec![0u8; Self::MAX_PACKET_SIZE],
            is_open: false,
        })
    }

    /// Set queue length
    pub fn set_queue_len(&mut self, queue_len: u32) -> Result<()> {
        #[cfg(windows)]
        {
            // WinDivertSetParam call would go here
            debug!(queue_len, "Set queue length");
        }
        Ok(())
    }

    /// Set queue time
    pub fn set_queue_time(&mut self, queue_time: u32) -> Result<()> {
        #[cfg(windows)]
        {
            // WinDivertSetParam call would go here
            debug!(queue_time, "Set queue time");
        }
        Ok(())
    }

    /// Internal filter validation
    fn validate_filter_internal(filter: &str) -> Result<()> {
        // Basic validation - real implementation would use WinDivertHelperCompileFilter
        if filter.is_empty() {
            return Err(PlatformError::InvalidFilter("Empty filter".into()));
        }

        // Check for basic syntax
        let keywords = [
            "inbound", "outbound", "ip", "ipv6", "icmp", "icmpv6",
            "tcp", "udp", "loopback", "impostor", "fragment",
            "true", "false", "and", "or", "not",
        ];

        // This is a simplified check - real validation is done by WinDivert
        let lower = filter.to_lowercase();
        let has_valid_keyword = keywords.iter().any(|k| lower.contains(k)) 
            || lower.contains("==") 
            || lower.contains("!=")
            || lower == "true";

        if !has_valid_keyword {
            warn!(filter, "Filter may be invalid");
        }

        Ok(())
    }
}

impl PacketCapture for WinDivertDriver {
    fn recv(&mut self) -> Result<CapturedPacket> {
        if !self.is_open {
            return Err(PlatformError::HandleError("Handle not open".into()));
        }

        #[cfg(windows)]
        {
            // Real WinDivert receive would go here
            // let mut addr = std::mem::zeroed();
            // let mut recv_len = 0u32;
            // let result = WinDivertRecv(self.handle, ...);
        }

        // Placeholder for non-Windows/testing
        Err(PlatformError::CaptureError("Not implemented".into()))
    }

    fn recv_batch(&mut self, max_count: usize) -> Result<Vec<CapturedPacket>> {
        // For now, just call recv multiple times
        // Real implementation would use WinDivertRecvEx
        let mut packets = Vec::with_capacity(max_count);
        
        for _ in 0..max_count {
            match self.recv() {
                Ok(pkt) => packets.push(pkt),
                Err(PlatformError::CaptureError(_)) => break,
                Err(e) => return Err(e),
            }
        }

        Ok(packets)
    }

    fn send(&mut self, packet: &[u8], addr: &PacketAddress) -> Result<()> {
        if !self.is_open {
            return Err(PlatformError::HandleError("Handle not open".into()));
        }

        #[cfg(windows)]
        {
            // Real WinDivert send would go here
            // WinDivertSend(self.handle, packet.as_ptr(), packet.len(), ...);
        }

        // Placeholder
        debug!(len = packet.len(), "Would send packet");
        Ok(())
    }

    fn send_batch(&mut self, packets: &[(Vec<u8>, PacketAddress)]) -> Result<()> {
        // Real implementation would use WinDivertSendEx
        for (data, addr) in packets {
            self.send(data, addr)?;
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if self.is_open {
            #[cfg(windows)]
            {
                // WinDivertClose(self.handle);
            }
            self.is_open = false;
            info!("Closed WinDivert handle");
        }
        Ok(())
    }
}

impl PacketFilter for WinDivertDriver {
    fn set_filter(&mut self, filter: &str) -> Result<()> {
        // WinDivert doesn't support changing filter after open
        // Would need to close and reopen
        Err(PlatformError::InvalidFilter(
            "Cannot change filter after open - close and reopen".into()
        ))
    }

    fn get_filter(&self) -> &str {
        &self.filter
    }

    fn validate_filter(filter: &str) -> Result<()> {
        Self::validate_filter_internal(filter)
    }
}

impl Drop for WinDivertDriver {
    fn drop(&mut self) {
        if self.is_open {
            let _ = self.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags() {
        let flags = Flags {
            sniff: true,
            drop: false,
            recv_only: false,
            send_only: false,
            no_install: false,
            fragments: true,
        };
        
        let value = flags.to_value();
        assert_eq!(value, 0x0001 | 0x0020);
    }

    #[test]
    fn test_validate_filter() {
        // Valid filters
        assert!(WinDivertDriver::validate_filter("true").is_ok());
        assert!(WinDivertDriver::validate_filter("outbound").is_ok());
        assert!(WinDivertDriver::validate_filter("tcp.DstPort == 443").is_ok());
        assert!(WinDivertDriver::validate_filter("outbound and tcp").is_ok());

        // Invalid filters
        assert!(WinDivertDriver::validate_filter("").is_err());
    }
}
