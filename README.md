# GoodbyeDPI Turkey v2 🇹🇷

[![CI](https://github.com/Andronovo-bit/GoodbyeDPI-Turkey/actions/workflows/ci.yml/badge.svg)](https://github.com/Andronovo-bit/GoodbyeDPI-Turkey/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/Andronovo-bit/GoodbyeDPI-Turkey)](LICENSE)

Modern Rust implementation of GoodbyeDPI, specifically optimized for bypassing DPI (Deep Packet Inspection) restrictions in Turkey.

## 🚀 Features

- **High Performance**: Written in Rust for maximum speed and memory safety
- **Multi-Strategy Support**: 
  - TCP fragmentation (HTTP/HTTPS)
  - Fake packet injection (TTL-based)
  - SNI manipulation
  - Header mangling
  - DNS redirection
  - QUIC blocking
- **Profile-Based Configuration**: Pre-configured modes for Turkish ISPs
- **Windows Service Support**: Run as a background service
- **Connection Tracking**: Smart TCP/DNS state management
- **Blacklist Support**: Block specific domains

## 📦 Installation

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/Andronovo-bit/GoodbyeDPI-Turkey/releases).

### Build from Source

```bash
# Clone the repository
git clone https://github.com/Andronovo-bit/GoodbyeDPI-Turkey.git
cd GoodbyeDPI-Turkey/v2

# Build release
cargo build --release

# The binary will be at target/release/goodbyedpi.exe
```

### Requirements

- Windows 10/11 (64-bit recommended)
- Administrator privileges
- [WinDivert](https://www.reqrypt.org/windivert.html) driver (included in releases)

## 🎮 Usage

### Quick Start

```powershell
# Run with Turkey-optimized profile (recommended)
.\goodbyedpi.exe run --profile turkey

# Run with specific mode
.\goodbyedpi.exe run --mode 9

# Run with custom config file
.\goodbyedpi.exe run --config my-config.toml
```

### Available Profiles

| Profile | Description | Best For |
|---------|-------------|----------|
| `turkey` | Turkey-optimized settings | Most Turkish ISPs |
| `mode1` | Most compatible | Older systems |
| `mode3` | Better HTTP/HTTPS speed | Performance |
| `mode4` | Minimal modifications | Light DPI |
| `mode9` | Maximum compatibility | Heavy DPI |

### Command-Line Options

```
USAGE:
    goodbyedpi.exe <COMMAND>

COMMANDS:
    run           Run DPI bypass
    service       Windows service management
    config        Configuration management
    test          Test connectivity
    completions   Generate shell completions

OPTIONS:
    -v, --verbose    Increase verbosity (use multiple times for more detail)
    -h, --help       Print help
    -V, --version    Print version
```

### Run Options

```
goodbyedpi.exe run [OPTIONS]

OPTIONS:
    -p, --profile <PROFILE>    Use predefined profile [turkey, mode1-9]
    -m, --mode <MODE>          Legacy mode number (1-9)
    -c, --config <FILE>        Path to config file
    -b, --blacklist <FILE>     Path to blacklist file
    -d, --dns <IP:PORT>        Custom DNS server
        --no-dns               Disable DNS redirection
    -v, --verbose              Verbose output
```

### Windows Service

```powershell
# Install as Windows service
.\goodbyedpi.exe service install

# Start service
.\goodbyedpi.exe service start

# Stop service
.\goodbyedpi.exe service stop

# Uninstall service
.\goodbyedpi.exe service uninstall
```

## ⚙️ Configuration

Configuration is done via TOML files. Example:

```toml
[general]
name = "my-config"
version = "2.0.0"
auto_start = false

[dns]
enabled = true
ipv4_server = "77.88.8.8"  # Yandex DNS
ipv4_port = 1253

[strategies.fragmentation]
enabled = true
http_size = 2
https_size = 40
http_persistent = true
native_split = false

[strategies.fake_packet]
enabled = true
ttl = 3
wrong_checksum = true
wrong_seq = true

[strategies.header_mangle]
enabled = true
host_replace = true
host_mix_case = true

[strategies.quic_block]
enabled = true
```

## 🏗️ Architecture

```
v2/
├── crates/
│   ├── gdpi-core/       # Platform-independent core
│   │   ├── config/      # Configuration management
│   │   ├── conntrack/   # Connection tracking (TCP/DNS)
│   │   ├── packet/      # Packet parsing & building
│   │   ├── pipeline/    # Processing pipeline
│   │   └── strategies/  # DPI bypass strategies
│   ├── gdpi-platform/   # Platform-specific code (WinDivert)
│   ├── gdpi-cli/        # Command-line interface
│   └── gdpi-service/    # Windows service support
```

### Core Strategies

| Strategy | Description |
|----------|-------------|
| `FragmentationStrategy` | Split HTTP/HTTPS packets into smaller fragments |
| `FakePacketStrategy` | Inject fake packets with wrong checksums/TTL |
| `HeaderMangleStrategy` | Modify HTTP headers (Host mixing, spacing) |
| `DnsRedirectStrategy` | Redirect DNS queries to alternative servers |
| `QuicBlockStrategy` | Block QUIC protocol (forces HTTPS fallback) |

## 🧪 Testing

```bash
# Run all tests
cargo test --all

# Run specific test suite
cargo test --package gdpi-core -- config

# Run with coverage
cargo tarpaulin --all

# Run benchmarks
cargo bench
```

### Test Structure

- Unit tests: Located in each module's `tests` submodule
- Integration tests: `crates/gdpi-core/tests/`
- Doc tests: Embedded in documentation comments

## 📊 Performance

The v2 rewrite focuses on performance optimizations:

- **Zero-copy packet parsing**: Minimal memory allocations
- **Lock-free connection tracking**: Using DashMap for concurrent access
- **Batch processing**: Process multiple packets per syscall
- **Compile-time optimizations**: Heavy use of const generics and inlining

## 🤝 Contributing

Contributions are welcome! Please read our Contributing Guide first.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/Andronovo-bit/GoodbyeDPI-Turkey.git
cd GoodbyeDPI-Turkey/v2
cargo build

# Run tests
cargo test --all

# Run clippy
cargo clippy --all
```

## 📝 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](../LICENSE) file for details.

## 🙏 Credits

- Original [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) by ValdikSS
- [WinDivert](https://www.reqrypt.org/windivert.html) by basil00
- Turkish ISP testing and research community

## ⚠️ Disclaimer

This tool is provided for educational and research purposes only. Users are responsible for ensuring their use complies with applicable laws and regulations in their jurisdiction.

---

Made with ❤️ for internet freedom
