# GoodbyeDPI Turkey v2(RUST) 🇹🇷

[![CI](https://github.com/Andronovo-bit/GoodbyeDPI-Turkey/actions/workflows/ci.yml/badge.svg)](https://github.com/Andronovo-bit/GoodbyeDPI-Turkey/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/Andronovo-bit/GoodbyeDPI-Turkey)](LICENSE)

[🇬🇧 English](README_EN.md)

Türkiye'deki DPI (Derin Paket İncelemesi) kısıtlamalarını aşmak için özel olarak optimize edilmiş, modern Rust implementasyonu.

## 🚀 Özellikler

- **Yüksek Performans**: Maksimum hız ve bellek güvenliği için Rust ile yazılmıştır
- **Çoklu Strateji Desteği**: 
  - TCP fragmentasyonu (HTTP/HTTPS)
  - Sahte paket enjeksiyonu (TTL tabanlı)
  - SNI manipülasyonu
  - Header değiştirme
  - DNS yönlendirme
  - QUIC engelleme
- **Profil Tabanlı Yapılandırma**: Türk ISP'leri için önceden yapılandırılmış modlar
- **Windows Servis Desteği**: Arka plan servisi olarak çalıştırma
- **Bağlantı Takibi**: Akıllı TCP/DNS durum yönetimi
- **Kara Liste Desteği**: Belirli domainleri engelleme
- **Sistem Tepsisi GUI**: Kullanıcı dostu grafik arayüz

## 📦 Kurulum

### Hazır Binary

En son sürümü [GitHub Releases](https://github.com/Andronovo-bit/GoodbyeDPI-Turkey/releases) sayfasından indirin.

### Kaynaktan Derleme

```bash
# Repoyu klonlayın
git clone https://github.com/Andronovo-bit/GoodbyeDPI-Turkey.git
cd GoodbyeDPI-Turkey

# CLI derlemesi
cargo build --release -p gdpi-cli

# GUI derlemesi
cargo build --release -p gdpi-gui

# Binary'ler target/release/ dizininde olacak
```

### Gereksinimler

- Windows 10/11 (64-bit önerilir)
- Yönetici yetkileri
- [WinDivert](https://www.reqrypt.org/windivert.html) sürücüsü (sürümlerde dahildir)

## 🎮 Kullanım

### Hızlı Başlangıç (GUI)

```powershell
# GUI uygulamasını başlatın
.\goodbyedpi-gui.exe
```

GUI özellikleri:
- Sistem tepsisine minimize
- Tek tıkla başlat/durdur
- Profil seçimi
- Servis durumu göstergesi

### Komut Satırı (CLI)

```powershell
# Türkiye için optimize edilmiş profil ile çalıştır (önerilen)
.\goodbyedpi.exe run --profile turkey

# Belirli mod ile çalıştır
.\goodbyedpi.exe run --mode 9

# Özel config dosyası ile çalıştır
.\goodbyedpi.exe run --config my-config.toml
```

### Kullanılabilir Profiller

| Profil | Açıklama | En İyi Kullanım |
|--------|----------|-----------------|
| `turkey` | Türkiye için optimize ayarlar | Çoğu Türk ISP'si |
| `mode1` | En uyumlu | Eski sistemler |
| `mode3` | Daha iyi HTTP/HTTPS hızı | Performans |
| `mode4` | Minimum değişiklik | Hafif DPI |
| `mode9` | Maksimum uyumluluk | Ağır DPI |

### Komut Satırı Seçenekleri

```
KULLANIM:
    goodbyedpi.exe <KOMUT>

KOMUTLAR:
    run           DPI bypass çalıştır
    service       Windows servis yönetimi
    config        Yapılandırma yönetimi
    test          Bağlantı testi
    completions   Shell tamamlama dosyaları oluştur

SEÇENEKLER:
    -v, --verbose    Ayrıntı seviyesini artır
    -h, --help       Yardım göster
    -V, --version    Versiyon göster
```

### Çalıştırma Seçenekleri

```
goodbyedpi.exe run [SEÇENEKLER]

SEÇENEKLER:
    -p, --profile <PROFİL>     Önceden tanımlı profil kullan [turkey, mode1-9]
    -m, --mode <MOD>           Eski mod numarası (1-9)
    -c, --config <DOSYA>       Config dosyası yolu
    -b, --blacklist <DOSYA>    Kara liste dosyası yolu
    -d, --dns <IP:PORT>        Özel DNS sunucusu
        --no-dns               DNS yönlendirmeyi devre dışı bırak
    -v, --verbose              Ayrıntılı çıktı
```

### Windows Servisi

```powershell
# Windows servisi olarak kur
.\goodbyedpi.exe service install

# Servisi başlat
.\goodbyedpi.exe service start

# Servisi durdur
.\goodbyedpi.exe service stop

# Servisi kaldır
.\goodbyedpi.exe service uninstall
```

## ⚙️ Yapılandırma

Yapılandırma TOML dosyaları ile yapılır. Örnek:

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

## 🏗️ Mimari

```
crates/
├── gdpi-core/       # Platform bağımsız çekirdek
│   ├── config/      # Yapılandırma yönetimi
│   ├── conntrack/   # Bağlantı takibi (TCP/DNS)
│   ├── filter/      # Domain filtreleme (whitelist/blacklist)
│   ├── packet/      # Paket ayrıştırma ve oluşturma
│   ├── pipeline/    # İşleme hattı
│   └── strategies/  # DPI bypass stratejileri
├── gdpi-platform/   # Platform özel kod (WinDivert)
├── gdpi-cli/        # Komut satırı arayüzü
├── gdpi-gui/        # Sistem tepsisi GUI
└── gdpi-service/    # Windows servis desteği
```

### Temel Stratejiler

| Strateji | Açıklama |
|----------|----------|
| `FragmentationStrategy` | HTTP/HTTPS paketlerini daha küçük parçalara böl |
| `FakePacketStrategy` | Yanlış checksum/TTL ile sahte paket enjekte et |
| `HeaderMangleStrategy` | HTTP header'larını değiştir (Host karıştırma, boşluk) |
| `DnsRedirectStrategy` | DNS sorgularını alternatif sunuculara yönlendir |
| `QuicBlockStrategy` | QUIC protokolünü engelle (HTTPS fallback'e zorla) |

## 🧪 Test

```bash
# Tüm testleri çalıştır
cargo test --all

# Belirli test paketini çalıştır
cargo test --package gdpi-core -- config

# Coverage ile çalıştır
cargo tarpaulin --all

# Benchmark çalıştır
cargo bench
```

### Test Yapısı

- Birim testler: Her modülün `tests` alt modülünde
- Entegrasyon testleri: `crates/gdpi-core/tests/`
- Dokümantasyon testleri: Dokümantasyon yorumlarına gömülü

## 📊 Performans

v2 yeniden yazımı performans optimizasyonlarına odaklanır:

- **Zero-copy paket ayrıştırma**: Minimum bellek tahsisi
- **Lock-free bağlantı takibi**: Eşzamanlı erişim için DashMap kullanımı
- **Toplu işleme**: Syscall başına birden fazla paket işleme
- **Derleme zamanı optimizasyonları**: const generics ve inlining'in yoğun kullanımı

## 🤝 Katkıda Bulunma

Katkılar memnuniyetle karşılanır!

1. Repoyu fork edin
2. Feature branch oluşturun (`git checkout -b feature/harika-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'Harika özellik ekle'`)
4. Branch'e push edin (`git push origin feature/harika-ozellik`)
5. Pull Request açın

### Geliştirme Ortamı

```bash
# Rust'ı kurun
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Klonlayın ve derleyin
git clone https://github.com/Andronovo-bit/GoodbyeDPI-Turkey.git
cd GoodbyeDPI-Turkey
cargo build

# Testleri çalıştırın
cargo test --all

# Clippy çalıştırın
cargo clippy --all
```

## 📝 Lisans

Bu proje Apache 2.0 Lisansı altında lisanslanmıştır - detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 🙏 Teşekkürler

- Orijinal [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) - ValdikSS
- [WinDivert](https://www.reqrypt.org/windivert.html) - basil00
- Türk ISP test ve araştırma topluluğu

## ⚠️ Sorumluluk Reddi

Bu araç yalnızca eğitim ve araştırma amaçlıdır. Kullanıcılar, kullanımlarının kendi yargı alanlarındaki geçerli yasa ve düzenlemelere uygunluğunu sağlamaktan sorumludur.

---

❤️ ile internet özgürlüğü için yapıldı
