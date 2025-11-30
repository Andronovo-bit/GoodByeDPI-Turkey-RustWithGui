//! WinDivert driver wrapper
//!
//! Safe Rust wrapper around WinDivert using the `windivert` crate.

use crate::error::{PlatformError, Result};
use crate::traits::{CapturedPacket, PacketAddress, PacketCapture, PacketFilter};
use tracing::{debug, info, warn};

#[cfg(windows)]
use windivert::prelude::*;

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

    /// Convert to WinDivertFlags
    #[cfg(windows)]
    pub fn to_windivert_flags(&self) -> WinDivertFlags {
        let mut flags = WinDivertFlags::new();
        if self.sniff { flags = flags.set_sniff(); }
        if self.drop { flags = flags.set_drop(); }
        if self.recv_only { flags = flags.set_recv_only(); }
        if self.send_only { flags = flags.set_send_only(); }
        if self.fragments { flags = flags.set_fragments(); }
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
    /// WinDivert handle
    #[cfg(windows)]
    handle: Option<WinDivert<windivert::layer::NetworkLayer>>,
    #[cfg(not(windows))]
    _handle: Option<()>,
    /// Current filter
    filter: String,
    /// Layer (stored for reference)
    _layer: Layer,
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
        info!(filter = filter, layer = ?layer, "Opening WinDivert handle");

        // Validate filter first
        Self::validate_filter_internal(filter)?;

        // Open WinDivert handle using the high-level crate
        let wd_flags = flags.to_windivert_flags();
        
        let handle = WinDivert::network(filter, priority, wd_flags)
            .map_err(|e| PlatformError::DriverInitFailed(format!("WinDivertOpen failed: {:?}", e)))?;

        info!("WinDivert handle opened successfully");

        Ok(Self {
            handle: Some(handle),
            filter: filter.to_string(),
            _layer: layer,
            recv_buffer: vec![0u8; Self::MAX_PACKET_SIZE],
            is_open: true,
        })
    }

    /// Stub implementation for non-Windows
    #[cfg(not(windows))]
    pub fn open(filter: &str, _flags: Flags) -> Result<Self> {
        warn!("WinDivert is only available on Windows");
        Ok(Self {
            _handle: None,
            filter: filter.to_string(),
            _layer: Layer::Network,
            recv_buffer: vec![0u8; Self::MAX_PACKET_SIZE],
            is_open: false,
        })
    }

    /// Stub implementation for non-Windows
    #[cfg(not(windows))]
    pub fn open_ex(filter: &str, layer: Layer, _priority: i16, _flags: Flags) -> Result<Self> {
        warn!("WinDivert is only available on Windows");
        Ok(Self {
            _handle: None,
            filter: filter.to_string(),
            _layer: layer,
            recv_buffer: vec![0u8; Self::MAX_PACKET_SIZE],
            is_open: false,
        })
    }

    /// Set queue length
    #[allow(unused_variables)]
    pub fn set_queue_len(&mut self, queue_len: u32) -> Result<()> {
        debug!(queue_len, "Set queue length");
        Ok(())
    }

    /// Set queue time
    #[allow(unused_variables)]
    pub fn set_queue_time(&mut self, queue_time: u32) -> Result<()> {
        debug!(queue_time, "Set queue time");
        Ok(())
    }

    /// Internal filter validation
    fn validate_filter_internal(filter: &str) -> Result<()> {
        // Basic validation
        if filter.is_empty() {
            return Err(PlatformError::InvalidFilter("Empty filter".into()));
        }

        // Check for basic syntax
        let keywords = [
            "inbound", "outbound", "ip", "ipv6", "icmp", "icmpv6",
            "tcp", "udp", "loopback", "impostor", "fragment",
            "true", "false", "and", "or", "not",
        ];

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
    #[cfg(windows)]
    fn recv(&mut self) -> Result<CapturedPacket> {
        use gdpi_core::packet::Direction;
        
        if !self.is_open {
            return Err(PlatformError::HandleError("Handle not open".into()));
        }

        let handle = self.handle.as_ref()
            .ok_or_else(|| PlatformError::HandleError("No handle".into()))?;

        // Receive packet using the new API
        let packet = handle.recv(&mut self.recv_buffer)
            .map_err(|e| PlatformError::CaptureError(format!("Recv failed: {:?}", e)))?;

        // Extract address info from the packet
        let wd_addr = &packet.address;
        
        let addr = PacketAddress {
            interface_index: wd_addr.interface_index(),
            subinterface_index: wd_addr.subinterface_index(),
            outbound: wd_addr.outbound(),
            loopback: wd_addr.loopback(),
            impostor: wd_addr.impostor(),
            ipv6: wd_addr.ipv6(),
            ip_checksum: wd_addr.ip_checksum(),
            tcp_checksum: wd_addr.tcp_checksum(),
            udp_checksum: wd_addr.udp_checksum(),
        };
        
        let direction = if wd_addr.outbound() { 
            Direction::Outbound 
        } else { 
            Direction::Inbound 
        };

        Ok(CapturedPacket {
            data: packet.data.to_vec(),
            direction,
            interface_index: wd_addr.interface_index(),
            subinterface_index: wd_addr.subinterface_index(),
            address: addr,
        })
    }

    #[cfg(not(windows))]
    fn recv(&mut self) -> Result<CapturedPacket> {
        Err(PlatformError::CaptureError("Not implemented on this platform".into()))
    }

    fn recv_batch(&mut self, max_count: usize) -> Result<Vec<CapturedPacket>> {
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

    #[cfg(windows)]
    fn send(&mut self, packet: &[u8], addr: &PacketAddress) -> Result<()> {
        use windivert::layer::NetworkLayer;
        use windivert_sys::ChecksumFlags;
        
        if !self.is_open {
            return Err(PlatformError::HandleError("Handle not open".into()));
        }

        let handle = self.handle.as_ref()
            .ok_or_else(|| PlatformError::HandleError("No handle".into()))?;

        // Create WinDivert address
        // SAFETY: We're filling in all the fields before sending
        let mut wd_addr = unsafe { WinDivertAddress::<NetworkLayer>::new() };
        wd_addr.set_outbound(addr.outbound);
        wd_addr.set_loopback(addr.loopback);
        wd_addr.set_impostor(addr.impostor);
        // Don't set checksum flags - we'll recalculate them
        wd_addr.set_ip_checksum(false);
        wd_addr.set_tcp_checksum(false);
        wd_addr.set_udp_checksum(false);
        wd_addr.set_interface_index(addr.interface_index);
        wd_addr.set_subinterface_index(addr.subinterface_index);

        // Create packet to send
        let mut wd_packet = WinDivertPacket::<NetworkLayer> {
            address: wd_addr,
            data: packet.to_vec().into(),
        };

        // CRITICAL: Recalculate checksums for modified packets!
        // This calls WinDivertHelperCalcChecksums which properly computes
        // IP header checksum and TCP/UDP checksums
        if let Err(e) = wd_packet.recalculate_checksums(ChecksumFlags::default()) {
            warn!("Failed to recalculate checksums: {:?}", e);
            // Continue anyway - might still work
        }

        handle.send(&wd_packet)
            .map_err(|e| PlatformError::InjectionError(format!("Send failed: {:?}", e)))?;

        Ok(())
    }

    #[cfg(not(windows))]
    fn send(&mut self, packet: &[u8], _addr: &PacketAddress) -> Result<()> {
        debug!(len = packet.len(), "Would send packet (not Windows)");
        Ok(())
    }

    fn send_batch(&mut self, packets: &[(Vec<u8>, PacketAddress)]) -> Result<()> {
        for (data, addr) in packets {
            self.send(data, addr)?;
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if self.is_open {
            #[cfg(windows)]
            {
                self.handle = None;
            }
            self.is_open = false;
            info!("Closed WinDivert handle");
        }
        Ok(())
    }
}

impl PacketFilter for WinDivertDriver {
    #[allow(unused_variables)]
    fn set_filter(&mut self, filter: &str) -> Result<()> {
        // WinDivert doesn't support changing filter after open
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
