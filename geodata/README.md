# IP veritabanları (ülke / kuruluş)

Gözcü, ülke ve kuruluş (ASN) bilgisini bu klasördeki çevrimdışı dosyalardan okur. Dosyalar depoya dahil değildir;
isterseniz [DB-IP](https://db-ip.com/db/lite.php) sitesinden ücretsiz indirip bu klasöre koyun:

- `dbip-country-lite-YYYY-MM.csv.gz` — IP to Country Lite
- `dbip-asn-lite-YYYY-MM.csv.gz` — IP to ASN Lite

Örnek (PowerShell, ay adını güncelleyin):

```powershell
Invoke-WebRequest https://download.db-ip.com/free/dbip-country-lite-2026-11.csv.gz -OutFile dbip-country-lite-2026-11.csv.gz
Invoke-WebRequest https://download.db-ip.com/free/dbip-asn-lite-2026-11.csv.gz -OutFile dbip-asn-lite-2026-11.csv.gz
```

Birden fazla ay varsa en yenisi kullanılır. Dosyalar yoksa panel çalışır, yalnızca ülke/kuruluş sütunları boş kalır.
Veri: [IP Geolocation by DB-IP](https://db-ip.com), lisans CC BY 4.0.
