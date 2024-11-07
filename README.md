# Özet​
Bu proje Discord ve diğer engelli site ve uygulamalara VPN'siz ve internet hızında yavaşlama olmadan girmek için GoodbyeDPI'ın düzenlenmiş bir versiyonudur.

# GoodbyeDPI — Derin Paket İnceleme (DPI) atlatma aracı (Türkiye fork'u)
Bu uygulama Türkiye'de bazı internet servis sağlayıcılarının DNS değişikliğine izin vermemesi sebebiyle asıl proje olan [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) projesi kullanılarak bu durumu bertaraf etmek için forklanmış bir varyasyondur.
Bu yazılım, birçok İnternet Servis Sağlayıcısında bulunan ve belirli web sitelerine erişimi engelleyen Derin Paket İnceleme (DPI) sistemlerini atlatmak için tasarlanmıştır.
Optik ayırıcı veya port yansıtma (Pasif DPI) kullanarak bağlanan ve herhangi bir veriyi engellemeyen, ancak istenen hedeften daha hızlı yanıt veren DPI'yi ve sıralı olarak bağlanan Aktif DPI'yi işler.
Bu uygulama kesinlikle VPN değildir ve oyunlarda/genel internet kullanımında bir hız değişikliğine sebep olmayacaktır.

> [!NOTE]
> Windows 7, 8, 8.1, 10 veya 11 işletim sistemlerinde **yönetici olarak çalıştırmanız** mecburidir.

# Virüs & Veri Sızıntısı
Program açık kaynak kodlu olduğundan tüm kodu görüp inceleyebilirsiniz. Bazı kullanıcılar VirusTotal'de false positive bildirimi yapsa da bu WinDivert.dll ve WinDiver64.sys dosyaları fonksiyonlarından dolayı bu şekilde yanlış bir sonuç verebiliyor. Bu DLL ve SYS dosyaları da açık kaynak kodludur ve incelenebilir. Tamamen temizdir. İstemeyen ve güvenmeyen de kullanmaz kimse kimseyi zorlamıyor, programı kullanmak kullanıcının inisiyatifindedir.

# GoodbyeDPI'ı Kullanmak
GoodbyeDPI'ın Türkiye fork'unu kullanmak için iki yöntem bulunmaktadır. Hizmet kurarak kullanma ve batch dosyasını çalıştırarak kullanma. Hizmet kurarak kullanmada yalnızca bir kez hizmeti kurup ardından elle herhangi bir şey çalıştırmaya gerek kalmaksızın bilgisayarınız her yeniden başlatıldığında otomatik olarak çalışırken, batch dosyası ile kullanmada her defasında elle batch dosyasını başlatarak kullanmanız gerekir (Batch penceresi kapatıldığında GoodbyeDPI kullanımına son verilir).
> [!NOTE]
> İndirdiğiniz ZIP dosyasını çıkarttığınız konumdan taşımayın. Kurulacak hizmet cmd dosyasını çalıştırdığınız dosya yolunu kullanacağından eğer dosyaları taşırsanız hizmet çalışmayacaktır. (Tavsiyem sizi rahatsız etmeyecek bir konuma ZIP dosyasını çıkarmanız ve dosyaları orada saklamanız örn. "C:\GoodbyeDPI\")


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

# WinDivert.dll ve WinDivert64.sys Dosyalarını Silmek​
Eğer bu dosyaları silmeye çalıştığınızda dosya kullanımda hatası alırsanız, indirdiğiniz dosyalardaki service_remove.cmd dosyasını yönetici olarak çalıştırdıktan sonra silebilirsiniz.

# Superonline Alternatif Yöntemler
Eğer SuperOnline Fiber kullanıyorsanız ve "Discord update failed - retrying in ** seconds" hatası alıyorsanız:
**1- Alternatif CMD Dosyaları**
> [!NOTE]
> Daha önceden diğer bir servisi kurduysanız service_remove.cmd dosyası ile kurulmuş olan servisi kaldırıp ardından alternatif aşağıdaki işlemleri yapın.
- Yukarıda anlatılan işlemleri **turkey_dnsredir_alternative_superonline.cmd/service_install_dnsredir_turkey_alternative_superonline.cmd**
komut dosyaları ile veya
**turkey_dnsredir_alternative2_superonline.cmd/service_install_dnsredir_turkey_alternative2_superonline.cmd**
komut dosyaları ile yapmayı deneyin. (Sağ Tık > Yönetici Olarak Çalıştır)
- Bu işlemleri tamamladıktan sonra **Windows 10 için [buradan](https://www.ipsorgu.com/windows_10_dns_degistirme.php)**, **Windows 11 için [buradan](https://www.ipsorgu.com/windows_11_dns_degistirme.php)** bakarak Windows ayarlarında DNS'inizi tercih ettiğiniz bir DNS adresine çevirin. (Tavsiye edilen: Yandex DNS, Cloudflare DNS)
- Ardından bilgisayarınızı yeniden başlatın.

Bu şekilde de Discord update failed - retrying in ** seconds hatası alıyorsanız:
**2- VPN ile Kaba Kuvvet**
Yukarıda anlatılan işlemleri yaptıktan (Hizmeti kurduktan veya cmd dosyasını çalışır hale getirdikten) sonra, herhangi bir Windows VPN'i açıp discordu başlatın ve discordun açılmasını bekleyin. Discord açıldıktan sonra VPN'i kapatın ve Discordu kullanmaya devam edin.

Bunlara rağmen Superonline ile Discorda giriş yapamıyorsanız
**3- Secure DNS Client**
SecureDNSClient isimli projeyi de deneyebilirsiniz. (Ben denemedim ve rehberini de bulamadım biraz araştırma ile bulabilirsiniz.)

# Sık Karşılaşılan Sorunlar

- Konsol penceresinin açılıp doğrudan kapanması (Bir tuşa basma veya herhangi bir yazıyı okuma şansı vermeden):
Nadir görülen durumlarda Türkçe karakterler uygulamanın doğru çalışmasına engel olabiliyor. Çalıştırmayı denediğiniz .cmd dosyasını (Örneğin service_remove.cmd dosyası) herhangi bir metin düzenleyici ile (Not Defteri uygulaması gibi) düzenleyip dosyanın içerisindeki tüm Türkçe karakterleri İngilizce karşılıkları ile değiştirerek (Örneğin Ğ harfini G ile değiştirerek) veya silerek bu sorunu çözebilirsiniz.

- Hizmetin başlatmaya çalışıldığında "Dosya yolu bulunamadı" hatası:
Bu hata indirdiğiniz .zip klasörünü çıkardığınız konumdan farklı bir konuma taşımanız halinde ya da bazı dosyaları silmeniz halinde ortaya çıkar. Bu durumda [goodbyedpi-0.2.3rc3-turkey.zip](https://github.com/cagritaskn/GoodbyeDPI-Turkey/releases/download/release-0.2.3rc3-turkey/goodbyedpi-0.2.3rc3-turkey.zip) dosyasını tekrar bilgisayarınızda bir konuma çıkararak öncelikle service_remove.cmd dosyasını yönetici olarak çalıştırdıktan sonra seçeceğiniz diğer .cmd dosyasını tekrar çalıştırarak bu sorunu çözebilirsiniz.

# Yasal Uyarı
> [!IMPORTANT]
> Bu uygulamanın kullanımından doğan her türlü yasal sorumluluk kullanan kişiye aittir. Uygulama yalnızca eğitim ve araştırma amaçları ile yazılmış ve düzenlenmiş olup; bu uygulamayı bu şartlar altında kullanmak ya da kullanmamak kullanıcının kendi inisiyatifindedir. Açık kaynak kodlarının paylaşıldığı bu platformdaki düzenlenmiş bu proje, bilgi paylaşımı ve kodlama eğitimi amaçları ile yazılmış ve düzenlenmiştir.
