# Gözcü — Windows ağ ve sistem izleme paneli

> Eski adı SysDash. Dosya adları (`sysdash.py`) ve güvenlik duvarındaki kural grubu/adları (`SysDash Engel - …`) mevcut kurallar bozulmasın diye aynı bırakıldı.

![Gözcü](gozcu.svg)

Bilgisayarda o an ne olup bittiğini (işlemler, ağ trafiği, DNS, güvenlik duvarı) tek ekranda gösteren yerel bir Windows paneli.
Sunucu yalnızca `127.0.0.1` üzerinde çalışır ve varsayılan olarak hiçbir veri dışarı gönderilmez. Tek istisna, sizin açtığınız
**Telegram bildirimleri**dir (yalnızca kendi botunuza gider). Çevrimdışı IP veritabanı kullanır; sorgular internete çıkmaz.

> **Uyarı:** Panel güvenlik duvarı kuralları ekler/siler, interneti kesebilir ve işlem sonlandırabilir. Yalnızca kendi bilgisayarınızda,
> ne yaptığınızı bilerek kullanın. Riskli işlemlerden önce otomatik güvenlik duvarı yedeği alınır. Yazılım garantisiz sunulur (MIT).

## Çalıştırma

- `start.bat` → normal kullanıcı olarak başlatır, tarayıcıda `http://127.0.0.1:8799` açılır.
- `start-admin.bat` → yönetici olarak başlatır (önerilir).
- Ya da: `python sysdash.py`

Gereksinim: Windows 10/11, 64-bit Python 3.10+ ve `psutil` (`start.bat` eksikse kendisi kurar). Ağ izleme, güvenlik duvarı ve açılışta başlatma yönetici ister.
Port 8799 doluysa sıradaki boş port kullanılır; `SYSDASH_PORT` ortam değişkeniyle değiştirilebilir.

## Sekmeler

| Sekme | İçerik |
|---|---|
| Genel Bakış | CPU / bellek / ağ / disk grafikleri, en çok kaynak kullananlar, çekirdekler, diskler, son uyarılar |
| İşlemler | Tüm işlemler; CPU, bellek, disk G/Ç, bağlantı sayısı, dinlediği portlar, dijital imza durumu. Tıklayınca: komut satırı, üst işlem zinciri, SHA-256, açık dosyalar, sonlandırma, internetini engelleme |
| Ağ Bağlantıları | Tüm TCP/UDP bağlantıları: yön (gelen/giden/dinleyen), uzak IP + ters DNS adı, adres türü (internet/yerel ağ), işaretler, tek tıkla IP engelleme |
| Açık Portlar | Dinleyen portlar; riskli port veritabanı (SMB, RDP, RPC, NetBIOS, Telnet, VNC, WinRM, arka kapı portları…), dış ağa açık mı, güvenlik duvarı izin veriyor mu → risk seviyesi |
| Canlı Akış | Panel açıkken: başlayan/biten işlemler, yeni gelen/giden bağlantılar, açılan/kapanan portlar, uyarılar. Güvenlik duvarı logu (izin verilen/engellenen paketler) |
| Güvenlik Duvarı | Profil durumları, aktif ağ, loglamayı aç/kapat, tüm kurallar (filtreli), hızlı engelleme (IP / program / port), SysDash kurallarını silme |
| Ağ | Ağ arayüzleri ve trafikleri, en çok bağlanılan internet adresleri, yerel ağdaki cihazlar (ARP), DNS sunucuları |
| Başlangıç & Servisler | Registry Run anahtarları, başlangıç klasörleri, Winlogon değişiklikleri, Microsoft dışı zamanlanmış görevler, servisler |
| Disk & Büyük Dosyalar | Disk doluluğu; seçilen klasörde en büyük dosyalar, klasör ve dosya türü bazında boyut dağılımı |
| Güvenlik Kontrolü | Antivirüs, güvenlik duvarı, RDP, UAC, SMBv1, proxy, hosts dosyası, paylaşımlar, kullanıcı hesapları, riskli portlar → puan |

## Ek özellikler

- **Komut paleti (`Ctrl+K`)**: sayfalara git, işlem ara (ad / PID / yol) ve aç, IP yazıp engelle, hızlı eylemler çalıştır. `/` sayfadaki arama kutusuna odaklanır, `Alt+1…0` sayfalar arasında geçer.
- **Açık / koyu tema** (üst çubuktaki ☀/☾) ve **masaüstü + sesli bildirim** (yeni uyarılarda; yüksek öncelikte ses çalar).
- **İşlem ağacı**: İşlemler sekmesinde “Ağaç görünümü”. İşlem ayrıntısında **askıya al / devam ettir** ve **öncelik değiştirme**; kritik sistem işlemleri (csrss, lsass…) sonlandırmaya/askıya almaya karşı korunur.
- **Bağlantı haritası** (Ağ sekmesi): hangi program hangi internet adresine bağlı, üzerine gelince ilişkiler vurgulanır.
- **Disk haritası** (treemap): tarama sonucunu alan olarak gösterir; kareye tıklayıp alt klasöre inebilir, “↑ Üst klasör” ile geri çıkabilirsiniz.
- **Değişiklik tespiti** (Güvenlik Kontrolü): “Şimdiki durumu referans al” → sonradan eklenen/silinen/değişen başlangıç öğeleri, görevler, servisler, dinleyen portlar, ağ cihazları ve gelen izin kuralları listelenir (`baseline.json` olarak yerelde saklanır).
- **CSV dışa aktarma**: tablo araç çubuklarındaki “⬇ CSV” (filtrelenmiş kayıtlar, Excel uyumlu).

## Akıllı analiz

- **Risk skoru (0-100)** her işlem için: taklit/şüpheli klasör, imza durumu, şüpheli porta bağlantı, dışa açık port, şüpheli komut satırı gibi işaretlerin ağırlıklı toplamı. İşlemler sekmesinde “Risk” sütunu; sütunun üzerine gelince gerekçeler görünür. İşlem ayrıntısında gerekçeler ve **“Bu ne?”** açıklaması (≈80 tanınan işlem için Türkçe açıklama) yer alır.
- **Komut satırı analizi**: kodlanmış PowerShell, indir-ve-çalıştır, certutil/mshta/regsvr32 kötüye kullanımı, yedek/olay günlüğü silme, Office → cmd/PowerShell zinciri gibi kalıplar uyarı üretir.
- **Beacon tespiti**: bir program aynı internet adresine düzenli aralıklarla (≥8 kez, ±%15) yeniden bağlanıyorsa uyarı verilir (komuta-kontrol davranışına benzer; senkronizasyon da olabilir).
- **Akıllı içgörüler + uygulama grupları** (Genel Bakış): sorunları düz Türkçe cümlelerle özetler; aynı programın tüm işlemlerini (ör. Chrome × 11) toplayıp gösterir.
- **Temizlik önerileri** (Disk sekmesi): geçici dosyalar, tarayıcı/npm/pip önbellekleri, çökme dökümleri, Windows Update indirmeleri. Yalnızca sabit, bilinen klasörler; “Temizle” 1 günden eski dosyaları siler.

## Otomatik uyarılar

- CPU 30 sn boyunca %90 üzerinde / bellek %92 üzerinde (en çok kullanan işlemle birlikte)
- Olası bellek sızıntısı (bir işlemin belleği ~6 dk içinde sürekli ve belirgin büyüyor)
- Disk %95 üzerinde dolu
- Yerel ağda yeni cihaz göründü (rastgele MAC kullanıyorsa belirtilir; ilk 3 dk referans toplanır)

- Dış ağa açık yeni bir portun dinlenmeye başlaması
- Bilinen şüpheli uzak portlara bağlantı (4444 Metasploit, 6667 IRC, Tor, 31337…)
- İnternetten gelen bağlantılar
- Temp / Downloads / Public gibi klasörlerden çalışıp internete bağlanan programlar
- İmzasız veya imzası bozuk programların internete bağlanması
- Sistem işlemi taklidi (ör. `C:\Windows\System32` dışında çalışan `svchost.exe`)

## Yönetici gerektirenler

Güvenlik duvarı logunu okumak, loglamayı açmak, kural eklemek/silmek ve bazı sistem işlemlerinin yolunu görmek.
Panel normal kullanıcıyla da çalışır; sol alttaki **“Yönetici olarak yeniden başlat”** düğmesiyle yükseltilebilir.

## Bilinen sınırlar

- Paket içeriği (payload) görülmez; ağ trafiği Windows ETW'den üst veri olarak okunur (yönetici gerekir). TLS SNI ve ham paket yakalama için Npcap gerekir, şu an yoktur.
- Canlı Akış yalnızca panel açıkken olan olayları görür; geçmişe dönük kayıt için güvenlik duvarı loglamasını açın.

## Ağ özellikleri (yönetici gerekir)

- **Canlı Akış → Ağ trafiği:** işlem ve bağlantı başına gelen/giden bayt, son aktarımlar, tek tıkla işlem/IP engelleme.
- **Trafik geçmişi:** günlük/işlem bazlı toplamlar `nettraffic.json` içinde 60 gün tutulur.
- **DNS sorguları:** hangi işlem hangi alan adını çözdü; DGA / tünelleme / çok sayıda başarısız sorgu uyarıları.
- **İnterneti kes:** üst çubuktaki düğme tüm internet erişimini güvenlik duvarı kuralıyla keser (yerel ağ etkilenmez), isteğe bağlı otomatik geri açma süresiyle.
- **Ülke / kuruluş (ASN):** `geodata/` klasöründeki çevrimdışı veritabanından. Veri: [IP Geolocation by DB-IP](https://db-ip.com), CC BY 4.0
  (`dbip-country-lite-*.csv.gz`, `dbip-asn-lite-*.csv.gz`; yeni ay dosyalarını aynı klasöre koyunca en yenisi kullanılır).

## Güvenlik duvarı araçları ve bildirimler (yönetici gerekir)

- **Kural sağlığı:** geniş izinler, şüpheli klasördeki programlara izin, dinleyen riskli portlar, ölü/yinelenen/çakışan kurallar; kural başına *Devre dışı bırak* ve *Adresi sınırla* (ör. RDP'yi yalnızca Tailscale aralığına).
- **Yedekle / geri yükle:** `netsh advfirewall export/import` ile tüm ilke `backups/` klasörüne alınır; riskli işlemlerden önce otomatik yedek.
- **Değişiklik izleme:** profil kapatılması, varsayılan gelen eylemin değişmesi, yeni gelen izin kuralı, silinen engeller (panel kapalıyken olanlar dahil) uyarı üretir.
- **İnterneti kes / ülke engelle / program engelle:** tek tıkla ve geri alınabilir.
- **Telegram bildirimleri:** üst çubuktaki *✈ Telegram*; bot token'ı Windows DPAPI ile şifreli saklanır, hız sınırı vardır.
- **Açılışta başlat:** sol alttaki düğme, oturum açılınca arka planda yönetici yetkisiyle başlatan bir zamanlanmış görev (`Gozcu`) oluşturur.

## Yerel veri dosyaları (depoya girmez)

`telegram.json`, `nettraffic.json`, `baseline.json`, `fw_snapshot.json` ve `backups/` kişisel veri içerir; `.gitignore` ile dışarıda tutulur.
Hepsi yalnızca bu bilgisayarda durur. İndirdiğiniz IP veritabanları için `geodata/README.md`'ye bakın.

## Lisans

MIT. IP verisi: DB-IP (CC BY 4.0).
