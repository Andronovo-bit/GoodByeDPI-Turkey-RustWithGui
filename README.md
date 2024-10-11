# GoodbyeDPI — Derin Paket İnceleme (DPI) atlatma aracı (Türkiye fork'u)

Bu uygulama Türkiye'de bazı internet servis sağlayıcılarının DNS değişikliğine izin vermemesi sebebiyle asıl proje olan [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) projesi kullanılarak bu durumu bertaraf etmek için forklanmış bir varyasyondur.
Bu yazılım, birçok İnternet Servis Sağlayıcısında bulunan ve belirli web sitelerine erişimi engelleyen Derin Paket İnceleme (DPI) sistemlerini atlatmak için tasarlanmıştır.
Optik ayırıcı veya port yansıtma (Pasif DPI) kullanarak bağlanan ve herhangi bir veriyi engellemeyen, ancak istenen hedeften daha hızlı yanıt veren DPI'yi ve sıralı olarak bağlanan Aktif DPI'yi işler.
Bu uygulama kesinlikle VPN değildir ve oyunlarda/genel internet kullanımında bir hız değişikliğine sebep olmayacaktır.

> [!NOTE]
> Windows 7, 8, 8.1, 10 veya 11 işletim sistemlerinde **yönetici olarak çalıştırmanız** mecburidir.

# GoodbyeDPI'ı Kullanmak
GoodbyeDPI'ın Türkiye fork'unu kullanmak için iki yöntem bulunmaktadır. Hizmet kurarak kullanma ve batch dosyasını çalıştırarak kullanma. Hizmet kurarak kullanmada yalnızca bir kez hizmeti kurup ardından elle herhangi bir şey çalıştırmaya gerek kalmaksızın bilgisayarınız her yeniden başlatıldığında otomatik olarak çalışırken, batch dosyası ile kullanmada her defasında elle batch dosyasını başlatarak kullanmanız gerekir (Batch penceresi kapatıldığında GoodbyeDPI kullanımına son verilir).


## Hizmet Kurarak Kullanma (Windows başlatılırken otomatik olarak çalıştırılır)
GoodbyeDPI Türkiye fork'unu hizmet kurarak kullanmak için:
- [goodbyedpi-0.2.3rc3-turkey.zip](https://github.com/cagritaskn/GoodbyeDPI-Turkey/releases/download/release-0.2.3rc3-turkey/goodbyedpi-0.2.3rc3-turkey.zip) dosyasını bilgisayarınıza indirin. 
- ZIP dosyasını herhangi bir dizine çıkarın.
- Çıkartılan dosyalardan **service_install_dnsredir_turkey.cmd** dosyasına sağ tıklayarak **Yönetici Olarak Çalıştır** seçeneğini seçin.
- Açılan konsol penceresinde herhangi bir tuşa basın.
- Pencere, hizmet kurulduğunda otomatik olarak kapanacaktır. Pencere kapandıktan sonra bilgisayarınızı yeniden başlatın.
> [!NOTE]
> Bu işlem bilgisayarınıza GoodbyeDPI hizmetini kuracaktır. GoodbyeDPI hizmetini bilgisayarınızdan kaldırmak için çıkarttığınız dosyalar içerisindeki **service_remove.cmd** dosyasını yönetici olarak çalıştırmanız gerekmektedir.


## Batch Dosyası İle Kullanma (Tek seferlik, pencere kapatıldığında sona erecek şekilde)
GoodbyeDPI Türkiye fork'unu batch dosyasını çalıştırarak kullanmak için **(Bir komut penceresi açılır ve uygulama çalışmaya başlar, bu pencere kapatıldığında çalışmaya son verilir)** :
- [goodbyedpi-0.2.3rc3-turkey.zip](https://github.com/cagritaskn/GoodbyeDPI-Turkey/releases/download/release-0.2.3rc3-turkey/goodbyedpi-0.2.3rc3-turkey.zip) dosyasını bilgisayarınıza indirin. 
- ZIP dosyasını herhangi bir dizine çıkarın.
- Çıkartılan dosyalardan **turkey_dnsredir.cmd** dosyasına sağ tıklayarak **Yönetici Olarak Çalıştır** seçeneğini seçin.
> [!NOTE]
> **turkey_dnsredir.cmd** dosyasını yönetici olarak çalıştırdığınızda GoodbyeDPI aktif olacaktır. Ancak bu yöntemle çalıştırıldığında hem bilgisayarınız yeniden başlatıldığında GoodbyeDPI'ı elle açmanız gerekecek, hem de **turkey_dnsredir.cmd** ile açılan pencere kapatıldığında GoodbyeDPI deaktive olacaktır.

## DNS ve Port'u Düzenleme
 **turkey_dnsredir.cmd** ve **service_install_dnsredir_turkey.cmd** dosyalarını herhangi bir metin düzenleyici ile düzenleyerek DNS ve port bilgilerini değiştirebilirsiniz.

# Yasal Uyarı
> [!IMPORTANT]
> Bu uygulamanın kullanımından doğan her türlü yasal sorumluluk kullanan kişiye aittir. Uygulama yalnızca eğitim ve araştırma amaçları ile yazılmış ve düzenlenmiş olup; bu uygulamayı bu şartlar altında kullanmak ya da kullanmamak kullanıcının kendi inisiyatifindedir. Açık kaynak kodlarının paylaşıldığı bu platformdaki düzenlenmiş bu proje, bilgi paylaşımı ve kodlama eğitimi amaçları ile yazılmış ve düzenlenmiştir.
