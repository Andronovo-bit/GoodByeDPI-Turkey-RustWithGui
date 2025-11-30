//! Command-line argument parsing

use clap::{Parser, ValueEnum};
use crate::commands::Command;

/// GoodbyeDPI-Turkey - DPI bypass tool
///
/// Passive DPI blocking utility for bypassing internet censorship in Turkey.
/// Uses various techniques to modify network packets and circumvent DPI systems.
#[derive(Parser, Debug)]
#[command(name = "goodbyedpi")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Args {
    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Option<Command>,

    // Legacy mode arguments (for backwards compatibility with v1)

    /// Use legacy mode 1 (fragmentation, out-of-order)
    #[arg(short = '1', long, conflicts_with_all = &["mode_2", "mode_3", "mode_4", "mode_5", "mode_6", "mode_7", "mode_8", "mode_9"])]
    pub mode_1: bool,

    /// Use legacy mode 2 (fragmentation + fake)
    #[arg(short = '2', long, conflicts_with_all = &["mode_1", "mode_3", "mode_4", "mode_5", "mode_6", "mode_7", "mode_8", "mode_9"])]
    pub mode_2: bool,

    /// Use legacy mode 3 (fragmentation + fake + wrong checksum)
    #[arg(short = '3', long, conflicts_with_all = &["mode_1", "mode_2", "mode_4", "mode_5", "mode_6", "mode_7", "mode_8", "mode_9"])]
    pub mode_3: bool,

    /// Use legacy mode 4 (fragmentation + fake + wrong seq)
    #[arg(short = '4', long, conflicts_with_all = &["mode_1", "mode_2", "mode_3", "mode_5", "mode_6", "mode_7", "mode_8", "mode_9"])]
    pub mode_4: bool,

    /// Use legacy mode 5 (fake + auto TTL)
    #[arg(short = '5', long, conflicts_with_all = &["mode_1", "mode_2", "mode_3", "mode_4", "mode_6", "mode_7", "mode_8", "mode_9"])]
    pub mode_5: bool,

    /// Use legacy mode 6 (mode 5 + wrong checksum)
    #[arg(short = '6', long, conflicts_with_all = &["mode_1", "mode_2", "mode_3", "mode_4", "mode_5", "mode_7", "mode_8", "mode_9"])]
    pub mode_6: bool,

    /// Use legacy mode 7 (mode 5 + wrong seq)
    #[arg(short = '7', long, conflicts_with_all = &["mode_1", "mode_2", "mode_3", "mode_4", "mode_5", "mode_6", "mode_8", "mode_9"])]
    pub mode_7: bool,

    /// Use legacy mode 8 (mode 5 + set ACK)
    #[arg(short = '8', long, conflicts_with_all = &["mode_1", "mode_2", "mode_3", "mode_4", "mode_5", "mode_6", "mode_7", "mode_9"])]
    pub mode_8: bool,

    /// Use legacy mode 9 (mode 5 + data overlap)
    #[arg(short = '9', long, conflicts_with_all = &["mode_1", "mode_2", "mode_3", "mode_4", "mode_5", "mode_6", "mode_7", "mode_8"])]
    pub mode_9: bool,

    /// Use Turkey-optimized preset
    #[arg(long, short = 't')]
    pub turkey: bool,

    /// Configuration file path
    #[arg(short = 'c', long, value_name = "FILE")]
    pub config: Option<String>,

    /// Blacklist file path
    #[arg(short = 'b', long, value_name = "FILE")]
    pub blacklist: Option<String>,

    /// Alternative DNS server IP
    #[arg(long, value_name = "IP")]
    pub dns_addr: Option<String>,

    /// Alternative DNS server port (default: 53)
    #[arg(long, value_name = "PORT", default_value = "53")]
    pub dns_port: u16,

    /// Set TTL for fake packets
    #[arg(long, value_name = "TTL")]
    pub set_ttl: Option<u8>,

    /// Auto-detect TTL
    #[arg(long)]
    pub auto_ttl: bool,

    /// Fragment HTTP packet at given position
    #[arg(short = 'f', long, value_name = "POS")]
    pub http_frag: Option<u32>,

    /// Fragment HTTPS packet at given position
    #[arg(short = 'e', long, value_name = "POS")]
    pub https_frag: Option<u32>,

    /// Fragment by SNI keyword
    #[arg(long)]
    pub frag_by_sni: bool,

    /// Send fake packets with wrong checksum
    #[arg(long)]
    pub wrong_chksum: bool,

    /// Send fake packets with wrong sequence number
    #[arg(long)]
    pub wrong_seq: bool,

    /// Block QUIC (UDP 443)
    #[arg(long)]
    pub block_quic: bool,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Output format for logs
    #[arg(long, value_enum, default_value = "text")]
    pub log_format: LogFormat,

    /// Log file path
    #[arg(long, value_name = "FILE")]
    pub log_file: Option<String>,

    /// Run in quiet mode (minimal output)
    #[arg(short, long)]
    pub quiet: bool,
}

/// Log output format
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogFormat {
    /// Human-readable text
    Text,
    /// JSON format
    Json,
    /// Compact format
    Compact,
}

impl Args {
    /// Get the selected legacy mode (if any)
    pub fn legacy_mode(&self) -> Option<u8> {
        if self.mode_1 { Some(1) }
        else if self.mode_2 { Some(2) }
        else if self.mode_3 { Some(3) }
        else if self.mode_4 { Some(4) }
        else if self.mode_5 { Some(5) }
        else if self.mode_6 { Some(6) }
        else if self.mode_7 { Some(7) }
        else if self.mode_8 { Some(8) }
        else if self.mode_9 { Some(9) }
        else if self.turkey { Some(10) }
        else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_mode() {
        let args = Args::parse_from(["goodbyedpi", "-1"]);
        assert_eq!(args.legacy_mode(), Some(1));

        let args = Args::parse_from(["goodbyedpi", "-5"]);
        assert_eq!(args.legacy_mode(), Some(5));

        let args = Args::parse_from(["goodbyedpi", "--turkey"]);
        assert_eq!(args.legacy_mode(), Some(10));

        let args = Args::parse_from(["goodbyedpi"]);
        assert_eq!(args.legacy_mode(), None);
    }

    #[test]
    fn test_verbose() {
        let args = Args::parse_from(["goodbyedpi", "-v"]);
        assert_eq!(args.verbose, 1);

        let args = Args::parse_from(["goodbyedpi", "-vvv"]);
        assert_eq!(args.verbose, 3);
    }
}
