# Update 11 February 2026 17:10 
# DNS MARS - ISP SCALE EDITION (V2.0)
**High Performance Hybrid DNS (Dnsmasq + Unbound) with Advanced Threat Protection**

Sistem DNS yang dioptimalkan untuk ISP dengan topologi NAT skala besar, mampu menangani ribuan user dengan stabilitas tinggi dan fitur keamanan canggih.

## 🚀 Fitur Utama

### 1. Hybrid DNS Engine (ISP Tuned)
- **Dnsmasq:** Caching layer depan yang sangat cepat.
- **Unbound:** Recursive resolver yang aman dengan validasi DNSSEC.
- **Performance:** Menangani 100k+ QPS dengan latency rendah.

### 2. System Threat Analysis (BARU)
- **Botnet & Malware Blocking:** Mendeteksi dan memblokir trafik ACS/TR-069, Crypto Miners, dan C2 Servers.
- **Keyword Blocking (BARU):** Blokir otomatis domain yang mengandung kata kunci tertentu (misal: judi/porn).
- **Bulk Management:** Fitur Search & Select All untuk memblokir/menghapus ratusan domain sekaligus.
- **Auto-Block System:** Otomatisasi pemblokiran ancaman setiap 10 menit dengan dukungan Keyword Blocking.
- **Safe Blocking:** Memutus jalur komunikasi malware tanpa memutus internet user.
- **Dashboard:** Monitoring real-time dengan "One-Click Block".

### 3. Internet Positif & Trust
- **Compliance:** Pemblokiran konten negatif sesuai regulasi.
- **Smart Redirect:** Intersepsi HTTPS yang mulus ke halaman blokir.
- **False Positive Fix:** Whitelist otomatis untuk `connectivitycheck` Android/iOS (Anti-Captive Portal issue).
- **App Optimization:** Whitelist khusus untuk Roblox, WhatsApp, YouTube, Shopee, TikTok, SnackVideo, dan Akamai agar berjalan lancar tanpa terblokir filter ads/malware.

### 4. Keamanan & Stabilitas
- **Log Safety:** Rotasi log otomatis (Max 50MB) mencegah disk penuh.
- **CPU Saver:** Null Route untuk tracker berat (hemat CPU 50%).
- **Emergency Protection:** Guardian menghapus log jika disk > 90%.
- **Anti-DDoS:** Iptables hashlimit untuk mitigasi serangan flood.
- **Auto-Healing:** Service restart otomatis jika macet/crash.
- **Secondary Sync:** Sinkronisasi konfigurasi ke server secondary untuk High Availability.

## 🛠️ Instalasi & Update
Jalankan script auto-installer:
```bash
sudo ./install.sh
```

## 📊 Web Management GUI
Akses dashboard monitoring melalui browser:
- **URL:** `https://IP_SERVER:5000`
- **Default User:** `admin` (Password di-set saat login pertama)

## 📚 Dokumentasi Lengkap
Lihat file `PANDUAN_SISTEM.md` atau akses menu **MANUAL** di Web GUI untuk panduan operasional detail.

---
© 2026 PT MARS DATA TELEKOMUNIKASI
