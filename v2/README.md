# GoodbyeDPI-Turkey v2

🚀 **Türkiye için DPI Bypass Aracının Rust ile Yeniden Yazılmış Versiyonu**

## Özellikler

- **Rust** ile yazıldı - Bellek güvenliği ve yüksek performans
- **Modüler Mimari** - Hexagonal (Ports & Adapters) pattern
- **Pluggable Stratejiler** - Kolayca yeni DPI bypass teknikleri eklenebilir
- **TOML Yapılandırma** - Modern ve okunabilir config dosyaları
- **Profile Desteği** - Legacy modlar (-1 ile -9) ve Turkey profili
- **Cross-platform** - Windows-first, gelecekte Linux desteği

## Proje Yapısı

```
v2/
├── Cargo.toml              # Workspace tanımı
├── README.md               # Bu dosya
└── crates/
    ├── gdpi-core/          # Platform-bağımsız core mantık
    │   └── src/
    │       ├── config/     # TOML yapılandırma sistemi
    │       ├── conntrack/  # TCP/DNS bağlantı takibi
    │       ├── error.rs    # Hata tipleri
    │       ├── packet/     # Paket parsing ve building
    │       ├── pipeline/   # İşlem hattı (Chain of Responsibility)
    │       └── strategies/ # DPI bypass stratejileri
    │
    ├── gdpi-platform/      # Platform-spesifik driver'lar
    │   └── src/
    │       ├── windows/    # WinDivert entegrasyonu
    │       └── traits.rs   # Platform-agnostik trait'ler
    │
    ├── gdpi-cli/           # Komut satırı arayüzü
    │   └── src/
    │       ├── args.rs     # CLI argümanları
    │       ├── commands/   # Alt komutlar
    │       └── logging.rs  # Log yapılandırması
    │
    └── gdpi-service/       # Windows servisi
```

## Stratejiler

| Strateji | Açıklama |
|----------|----------|
| `FragmentationStrategy` | HTTP/HTTPS paketlerini parçalara ayırır |
| `FakePacketStrategy` | Sahte paketler enjekte eder (yanlış checksum/seq) |
| `HeaderMangleStrategy` | HTTP header'larını modifiye eder |
| `QuicBlockStrategy` | QUIC/HTTP3 (UDP 443) bloklar |
| `DnsRedirectStrategy` | DNS sorgularını alternatif sunuculara yönlendirir |

## Kullanım

### Temel Kullanım (Turkey Profili)

```bash
goodbyedpi --turkey
# veya
goodbyedpi -t
```

### Legacy Modlar

```bash
goodbyedpi -1  # Mode 1: En uyumlu
goodbyedpi -5  # Mode 5: Auto-TTL
goodbyedpi -9  # Mode 9: Tam mod + QUIC engelleme
```

### Yapılandırma Dosyası ile

```bash
goodbyedpi run --config config.toml
```

### Yapılandırma Oluşturma

```bash
goodbyedpi config generate --profile turkey --output my-config.toml
```

### Bağlantı Testi

```bash
goodbyedpi test all
goodbyedpi test url twitter.com
goodbyedpi test driver
```

## Yapılandırma Örneği

```toml
# config.toml

[general]
name = "Turkey"
version = "2.0"

[dns]
enabled = true
ipv4_upstream = "77.88.8.8"  # Yandex DNS

[strategies.fragmentation]
enabled = true
http_size = 2
https_size = 2
reverse_order = true
native_split = true

[strategies.fake_packet]
enabled = true
wrong_checksum = true
wrong_seq = true

[strategies.quic_block]
enabled = true
```

## Derleme

### Gereksinimler

- Rust 1.75+
- Windows 10/11 (packet capture için)
- WinDivert driver

### Derleme Adımları

```bash
# Clone
git clone https://github.com/Andronovo-bit/GoodbyeDPI-Turkey.git
cd GoodbyeDPI-Turkey

# v2 branch'ine geç
git checkout v2-rust-rewrite

# Derle
cd v2
cargo build --release

# Binary: target/release/goodbyedpi.exe
```

## Mimari

### Hexagonal Architecture

```
                    ┌─────────────────────────────────────┐
                    │           CLI / Service             │
                    └─────────────────────────────────────┘
                                      │
                    ┌─────────────────────────────────────┐
                    │         Application Layer           │
                    │    (Pipeline, Context, Config)      │
                    └─────────────────────────────────────┘
                                      │
        ┌─────────────────────────────────────────────────────┐
        │                    Domain Layer                      │
        │  ┌────────────┐ ┌────────────┐ ┌────────────────┐  │
        │  │ Strategies │ │  Packet    │ │  ConnTrack     │  │
        │  └────────────┘ └────────────┘ └────────────────┘  │
        └─────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────────────────────────┐
                    │        Platform Adapters            │
                    │   (WinDivert, NFQUEUE, etc.)        │
                    └─────────────────────────────────────┘
```

### Strategy Pattern

Her DPI bypass tekniği ayrı bir `Strategy` trait implementasyonudur:

```rust
pub trait Strategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn should_apply(&self, packet: &Packet, ctx: &Context) -> bool;
    fn apply(&self, packet: Packet, ctx: &mut Context) -> Result<StrategyAction>;
}
```

## Lisans

Apache License 2.0

## Katkıda Bulunma

Pull request'ler memnuniyetle karşılanır. Büyük değişiklikler için önce bir issue açınız.
