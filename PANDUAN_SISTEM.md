# BUKU PANDUAN SISTEM - PT MARS DATA TELEKOMUNIKASI
## DUAL STACK DNS ENGINE (ISP SCALE EDITION)

Dokumentasi ini berisi panduan operasional dan teknis untuk sistem DNS Mars Data yang telah dioptimalkan untuk skala ISP dengan topologi NAT.

---

### 1. RINGKASAN SISTEM
Sistem ini menggunakan arsitektur **Hybrid DNS High Performance** yang menggabungkan kecepatan **dnsmasq** dengan keamanan serta rekursi tingkat tinggi dari **Unbound**.

- **DNS Engine:** Hybrid (dnsmasq + Unbound) - Tuned for High Concurrency.
- **Security:** Anti-DDoS (iptables Hashlimit), Malware Shield (100k+ domains), Intelligent Self-Healing Guardian.
- **Web GUI:** Management Dashboard berbasis Flask dengan antarmuka modern dan responsif.
- **Topologi:** Mendukung **NAT Topology** (Ribuan user dibalik satu IP Public) dengan manajemen koneksi yang efisien.
- **High Availability:** Mendukung sinkronisasi konfigurasi ke Secondary DNS secara otomatis.

---

### 2. DNS TRUST & INTERNET POSITIF
Fitur ini dirancang untuk mematuhi regulasi pemblokiran konten negatif (Internet Positif) dengan pengalaman pengguna yang mulus.

- **HTTPS Redirect:** Sistem kini mendukung redirect otomatis dari akses HTTPS ke domain terblokir menuju halaman blokir HTTP (via 302 Redirect) setelah user melewati peringatan SSL.
- **Cara Kerja:** Sistem secara otomatis mencegat trafik DNS dan HTTP/HTTPS melalui firewall (NAT) untuk mengarahkan domain terblokir ke halaman peringatan internal.
- **Konfigurasi Utama:** `/etc/dnsmasq.d/smartdns.conf` (Single Source of Truth).
- **Status:** Jika DNS Trust "Enabled", pemblokiran aktif. Jika "Disabled", sistem tetap melakukan intersepsi namun dengan aturan yang lebih longgar.
- **Guardian:** Layanan `guardian.py` memastikan aturan firewall tetap aktif meskipun sistem direstart.

#### DNS Trust Schedule (BARU)
Fitur penjadwalan otomatis untuk mengaktifkan/menonaktifkan DNS Trust pada jam tertentu.
- **Fungsi:** Berguna untuk kebijakan pemblokiran berbasis waktu (misal: blokir aktif hanya di jam kerja).
- **Akses:** Menu "Internet Positif" -> tombol "SET SCHEDULE".

#### Captive Portal Bypass (False Positive Fix)
Untuk mencegah perangkat (Android/iOS) mendeteksi jaringan sebagai "Captive Portal" palsu yang menyebabkan popup "Sign in to network" muncul terus-menerus:

- **Mechanism:** Whitelisting domain connectivity check (misal: `connectivitycheck.gstatic.com`, `android.clients.google.com`) agar resolve ke IP asli via Unbound, bukan ke IP Block Page.
- **Config:** `/etc/dnsmasq.d/captive_portal.conf`
- **Domains Covered:** Android (Google), iOS (Apple), Windows, Firefox.
- **Benefit:** User tidak akan melihat halaman blokir Internet Positif saat baru terkoneksi ke WiFi, kecuali mereka benar-benar mengakses konten terlarang.

---

### 3. PROTEKSI DISK DARURAT (NEW)
Guardian System kini dilengkapi dengan **Emergency Disk Protection** untuk mencegah kegagalan sistem akibat log yang membanjir:

- **Monitoring Real-time:** Guardian memantau penggunaan disk root (`/`) setiap 10 detik.
- **Critical Threshold:** Jika penggunaan disk mencapai **90%**, sistem akan masuk mode darurat.
- **Auto-Cleanup:**
    - Log aktif (`dnsmasq.log`, `access.log`) akan langsung di-truncate (dikosongkan) menjadi 0 byte.
    - File log arsip (`.gz`, `.1`) akan dihapus paksa.
    - Mencegah server crash atau Unbound gagal start karena kehabisan ruang disk.

---

### 4. MITIGASI SERANGAN INTERNAL & STABILITAS
Sistem kini dilengkapi dengan kernel tuning dan monitoring aktif untuk menangani ancaman kestabilan:

- **Anti-Looping:** Dnsmasq dan Unbound dikonfigurasi untuk mendeteksi DNS forwarding loops.
- **Memory Leak & Swap Thrashing:** 
    - Guardian memantau penggunaan RAM dan Swap.
    - Jika RAM > 90% dan Swap penuh (Thrashing), layanan DNS akan direstart otomatis untuk membebaskan memori sebelum sistem hang (OOM).
- **UDP Drop Prevention:** 
    - Kernel buffer (`rmem_default`, `rmem_max`) ditingkatkan hingga 16MB untuk mencegah paket loss saat traffic tinggi.
- **IRQ Overload:** Menggunakan `irqbalance` untuk mendistribusikan beban interupsi jaringan ke semua core CPU.
- **Botnet Mitigation:** Rate limit per-IP (20.000 QPS) mencegah satu botnet yang terinfeksi melumpuhkan seluruh server.
- **Video Streaming Optimization (Serve-Expired):**
    - Mengaktifkan fitur *serve-expired* pada Unbound (Timeout: 1000ms).
    - DNS akan menyajikan cache kadaluarsa (expired) sejenak kepada client untuk respon instan, sambil melakukan update cache di background.
    - Menghilangkan buffering/loading awal pada aplikasi video (YouTube, TikTok, dll).
- **Application Whitelist Optimization (False Positive Fixes):**
    - **Roblox:** Whitelist domain telemetri, ads, & services (`ads.roblox.com`, `client-telemetry.roblox.com`, `rbxservices.com`, `robloxlabs.com`) yang diperlukan untuk login/gameplay.
    - **WhatsApp:** Whitelist Facebook CDN (`fbcdn.net`, `fbsbx.com`) untuk kelancaran kirim/terima media (Gambar/Video).
    - **YouTube:** Whitelist Google Global Cache (`ggc.cmvideo.cn`, `ytimgg.com`) untuk streaming tanpa buffer.
    - **Shopee:** Whitelist domain Live Streaming & Log Collector (`livetech`, `log-collector`) untuk mempercepat load awal aplikasi.
    - **TikTok:** Whitelist domain core, API, dan CDN (`tiktokv`, `tiktokw`, `byteoversea`) untuk memastikan aplikasi dan streaming berjalan lancar.
    - **SnackVideo:** Whitelist domain API dan Open Platform (`kwaizt.com`) untuk stabilitas aplikasi.
    - **Akamai:** Whitelist domain Analytics (`akamai.tt.omtrdc.net`) untuk mencegah gangguan pada layanan pihak ketiga yang menggunakan Akamai.
    - **Google Play Services:** Whitelist domain Metrics, Telemetry, & Crashlytics (`clientmetrics`, `telemetry`, `firebasecrashlytics`, `admob`) untuk mengatasi masalah loading lambat pada Play Store dan aplikasi Android.
    - **Global Analytics & Error Tracking:** Whitelist `app-measurement.com` (Google) dan `sentry.io` yang sering menyebabkan aplikasi (termasuk Roblox) menjadi lambat atau gagal memuat fitur chat jika diblokir.
    - **Apple Services:** Whitelist domain infrastruktur DNS Apple (`apple-dns.net`, `apple-dns.cn`) untuk kelancaran iCloud dan iTunes.
    - **Xiaomi/MiCloud:** Whitelist domain API, IoT, dan Game Center (`api.jr.mi.com`, `idm.iot.mi.com`, `migc.g.mi.com`) untuk sinkronisasi MiCloud dan layanan Xiaomi.
- **High Load Tracker Optimization (Null Route):**
        - Domain tracker yang menghasilkan beban CPU tinggi (misal: `pangle.io`, `kwai-pro.com`) kini di-route ke `0.0.0.0` (Null Route).
        - Mencegah server Nginx terbebani oleh ribuan request HTTPS background dari aplikasi mobile.
        - Menghemat penggunaan CPU hingga 50% pada beban trafik tinggi.
    - **High Performance Logging (RAM):**
        - Log dnsmasq kini dipindahkan ke `/run/dnsmasq.log` (RAM Disk) untuk menghilangkan bottleneck I/O disk.
        - Memungkinkan pencatatan statistik (QPS) tetap aktif tanpa memperlambat browsing, bahkan saat trafik analitik tinggi.

---

### 5. SYSTEM THREAT ANALYSIS (BARU)
Fitur intelijen keamanan baru untuk mendeteksi dan memblokir ancaman jaringan tingkat lanjut:

- **ACS / TR-069 Botnet Detection:** Mendeteksi pola komunikasi dari perangkat yang terinfeksi botnet (Mirai, Mozi) atau protokol manajemen ISP yang tidak diinginkan (ACS).
- **Crypto Miner Blocking:** Mengidentifikasi dan memblokir trafik ke mining pool cryptocurrency yang memakan resource CPU/Bandwidth pelanggan.
- **C2 Server Blocking:** Memutus komunikasi antara perangkat terinfeksi dengan Command & Control server peretas.
- **Keyword Blocking (BARU):** Memblokir domain berdasarkan kata kunci tertentu (misal: "toto", "slot", "porn"). Domain yang cocok dengan keyword akan otomatis diblokir oleh Auto-Block System.
- **Actionable Intelligence:** 
    - **One-Click Block:** Operator dapat langsung memblokir domain berbahaya dari dashboard.
    - **Bulk Action (BARU):** Fitur seleksi massal, pencarian (Search), dan penghapusan massal (Bulk Delete) pada daftar Blacklist/Whitelist.
    - **Auto-Block System (BARU):** Sistem dapat dikonfigurasi untuk secara otomatis memblokir domain berdasarkan kategori ancaman (ACS, Miner, C2) dan Keyword setiap 10 menit tanpa intervensi manual.
    - **Safe Blocking:** Pemblokiran ancaman ini **TIDAK** akan memutus koneksi internet pelanggan, hanya memutus jalur komunikasi malware tersebut.
    - **Recovery:** Domain yang tidak sengaja diblokir dapat dikembalikan (Unblock) melalui menu **Blacklist**.

---

### 6. ANALISIS TRAFIK & MONITORING
Dashboard Web GUI menyediakan pemantauan real-time yang telah ditingkatkan:

- **Traffic Analysis (Live QPS):**
    - **Garis Magenta (Pink):** Menampilkan **QPS (Queries Per Second)** murni per detik.
    - **Area Biru (Cyan):** Menampilkan **Snapshot Queries** (kepadatan query terbaru).
    - **High Load Warning:** Indikator peringatan akan muncul jika QPS melebihi **90.000 QPS**.
    - **Sampling Engine:** Menggunakan *Deep Log Sampling* (200k baris) untuk akurasi tinggi pada trafik padat.

- **Combined Analysis (Baru):**
    - **SERVFAIL & Blocklist:** Grafik batang gabungan yang menampilkan domain dengan error SERVFAIL terbanyak dan domain yang paling sering diblokir dalam satu tampilan ringkas.
    - **Advanced Table View:** Klik tombol "VIEW THREAT CANDIDATES" untuk melihat tabel detail ancaman dalam popup terpisah dengan fitur pencarian dan filtering.

- **Hardware Monitoring:**
    - **CPU & RAM:** Beban pemrosesan real-time.
    - **HDD Usage:** Pemantauan sisa ruang penyimpanan disk.

---

### 7. FITUR BARU: RESPONSIVE FULLSCREEN MONITORING
Sistem kini dilengkapi dengan mode pemantauan layar penuh yang adaptif:
- **Auto-Scale:** Grafik akan menyesuaikan ukurannya secara otomatis mengikuti orientasi dan ukuran layar perangkat.
- **Mobile Friendly:** Dioptimalkan untuk iPhone dan Android dengan navigasi "Exit Fullscreen" yang mudah.
- **High Performance:** Mode fullscreen menggunakan akselerasi GPU browser untuk memastikan render grafik tetap lancar tanpa membebani CPU server.

---

### 8. BATASAN PERFORMA (ISP SCALE LIMITS)
Sistem telah dikonfigurasi ulang untuk menangani topologi NAT dimana satu IP Public mewakili ribuan user:

- **Global Rate Limit:** **100.000 QPS** (Perlindungan level server).
- **Per-IP Rate Limit:** **20.000 QPS** (Ditingkatkan dari 1.000 QPS untuk mengakomodasi NAT).
- **Unbound Rate Limit:** **20.000 QPS** per IP untuk rekursi.
- **DNS Flood Protection:** Menggunakan modul `hashlimit` iptables yang efisien untuk memitigasi serangan tanpa memblokir trafik legit dari NAT yang padat.

---

### 9. MANAJEMEN WHITELIST & MALWARE
- **Global Whitelist:** IP/Subnet yang ditambahkan ke Whitelist akan melewati (bypass) semua aturan pemblokiran, rate limiting, dan intersepsi.
- **Malware Shield:** Menggunakan database `/etc/dnsmasq.d/malware.conf` yang diperbarui secara berkala untuk memblokir situs berbahaya.

---

### 10. SECONDARY DNS SYNC (HIGH AVAILABILITY)
Fitur sinkronisasi otomatis untuk konfigurasi Cluster DNS (Primary-Secondary).
- **Mekanisme:** VM Secondary secara otomatis menyalin database konfigurasi, blacklist, dan whitelist dari VM Primary setiap 5 menit.
- **Setup:** Panduan instalasi VM Secondary tersedia di menu dashboard "Secondary DNS Sync".
- **Manfaat:** Memastikan konsistensi kebijakan blokir di seluruh node DNS.

---

### 11. PEMELIHARAAN & KEAMANAN LOG (LOG SAFETY)
Sistem telah diamankan dari risiko "Disk Full" akibat banjir log (Log Flooding):

- **Auto Log Rotation:** Log sistem (`dnsmasq.log`, `guardian.log`, `nginx`) dikonfigurasi dengan **Logrotate** yang ketat:
    - **Max Size:** 50MB per file (Aggressive Rotation).
    - **Rotasi:** Maksimal 3 file backup.
    - **Kompresi:** Log lama otomatis dikompres (.gz) untuk menghemat ruang.
- **Proteksi Disk Darurat:** Jika disk tetap penuh hingga 90% (misal karena serangan masif), Guardian akan otomatis **menghapus paksa** log lama agar layanan DNS tetap hidup.
- **Intelligent Self-Healing:** 
    - `guardian.py` secara aktif memonitor port DNS (53/UDP) dan Web GUI (5000/TCP).
    - Jika layanan macet atau mati, Guardian akan mencoba melakukan restart otomatis dan memperbaiki konfigurasi yang korup.
    - Mendeteksi perubahan IP Network dan secara otomatis memperbarui aturan Firewall tanpa downtime.

---

### 12. TROUBLESHOOTING DARURAT
Jika sistem melambat atau DNS sering putus:

1. **Cek Penggunaan Disk:**
   - Command: `df -h`
   - Jika disk penuh (>90%) karena log, jalankan perintah darurat:
     ```bash
     sudo bash -c 'echo > /var/log/nginx/access.log && echo > /var/log/dnsmasq.log'
     sudo systemctl restart nginx dnsmasq
     ```

2. **Web GUI tidak dapat diakses:**
   - Pastikan menggunakan HTTPS (bukan HTTP): `https://IP_SERVER:5000`
   - Sertifikat Self-Signed: Browser akan menampilkan peringatan keamanan - klik "Advanced" → "Proceed" untuk melanjutkan.
   - Cek status layanan: `sudo systemctl status dnsmars-gui`
   - Restart Web GUI: `sudo systemctl restart dnsmars-gui`
   - Health Check: Akses `https://IP_SERVER:5000/health` untuk memastikan layanan aktif.
   - Password default: `admin` (segera ganti setelah login pertama)

---
### 13. TROUBLESHOOTING SECONDARY DNS
Panduan khusus untuk mengatasi masalah pada Node Secondary:

#### A. Secondary DNS Menampilkan Google Resolver (Bukan Self)
Jika hasil tes DNS Leak (misal: dnscheck.tools) di sisi client menampilkan "Google" sebagai resolver saat terkoneksi ke Secondary DNS, ini berarti dnsmasq mem-forward query ke upstream Google (8.8.8.8) karena tidak memiliki resolver lokal.

**Solusi (Aktifkan Recursive Mode):**
Ubah Secondary menjadi Independent Resolver dengan menginstal Unbound.
1. **Install Unbound:**
   ```bash
   sudo apt install -y unbound
   ```
2. **Konfigurasi Unbound (Port 5335):**
   Buat file `/etc/unbound/unbound.conf.d/pi-hole.conf` dengan isi:
   ```text
   server:
       interface: 127.0.0.1
       port: 5335
       do-ip4: yes
       do-udp: yes
       do-tcp: yes
       access-control: 127.0.0.0/8 allow
   ```
3. **Arahkan Dnsmasq ke Local Unbound:**
   ```bash
   # Hapus forwarder google
   sudo sed -i '/server=8.8.8.8/d' /etc/dnsmasq.conf
   # Tambahkan local unbound
   echo "server=127.0.0.1#5335" | sudo tee -a /etc/dnsmasq.conf
   ```
4. **Restart Service:**
   ```bash
   sudo systemctl restart unbound dnsmasq
   ```

#### B. Koneksi Lambat/RTO pada LXC Container (Proxmox)
Jika Secondary DNS berjalan di container LXC dan mengalami koneksi lambat atau packet loss (RTO) saat sinkronisasi atau resolusi DNS.

**Penyebab:**
Nilai MTU (Maximum Transmission Unit) default interface LXC (1500) seringkali tidak cocok dengan interface fisik host atau tunnel VPN, menyebabkan fragmentasi paket.

**Solusi (Turunkan MTU):**
Ubah MTU interface network menjadi 1440 atau 1300.
1. Edit file konfigurasi network (misal: Netplan atau `/etc/network/interfaces`).
2. Atau set sementara via command line:
   ```bash
   sudo ip link set dev eth0 mtu 1440
   ```
3. Pastikan setting permanen diterapkan agar bertahan setelah reboot.

---

*Dokumen ini diperbarui secara otomatis oleh System Assistant.*
*© 2026 PT MARS DATA TELEKOMUNIKASI*
