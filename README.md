Update 13 March 2026 00:15 #FINAL-OPTIMIZED-SPLIT

# BUKU PANDUAN SISTEM - PT MARS DATA TELEKOMUNIKASI
## DNS ENGINE CYBER SECURITY (ISP SCALE EDITION)

Dokumentasi ini berisi panduan operasional dan teknis untuk sistem DNS Mars Data yang telah dioptimalkan untuk skala ISP dengan topologi NAT.

---

### 🚀 OPSI INSTALASI TERPISAH (V2.1)
Kini Anda dapat menginstal **Mesin DNS** dan **Web Management GUI** pada VM yang berbeda untuk skalabilitas yang lebih baik.

#### OPSI A: Instalasi MESIN DNS SAJA (Untuk Node DNS Primary/Secondary)
Gunakan opsi ini jika Anda hanya ingin menginstal mesin DNS yang sudah di-tuning performanya.
```bash
git clone https://github.com/solinos-utab/dnsMars
cd dnsMars
chmod +x install_dns.sh
./install_dns.sh
```

#### OPSI B: Instalasi WEB MANAGEMENT GUI SAJA (Untuk Monitoring Center)
Gunakan opsi ini jika Anda ingin menginstal dashboard monitoring, sistem alarm, dan pengumpul data di VM terpisah.
```bash
git clone https://github.com/solinos-utab/dnsMars
cd dnsMars
chmod +x install_gui.sh
./install_gui.sh
```

#### OPSI C: Instalasi FULL (Mesin DNS + Web GUI)
Jika Anda ingin menginstal semua komponen dalam satu VM yang sama.
```bash
git clone https://github.com/solinos-utab/dnsMars
cd dnsMars
chmod +x install.sh
./install.sh
```

---

### 📋 SPESIFIKASI SISTEM (MINIMUM REQUIREMENTS)
Untuk performa optimal skala ISP, disarankan menggunakan spesifikasi berikut:

- **Operating System:** Ubuntu 22.04 LTS (Jammy Jellyfish) - *Recommended*
- **CPU:** Minimum 4 Core (High Frequency) / 16 Core untuk skala 100k+ user.
- **RAM:** Minimum 4GB (DDR4/DDR5) / 16GB+ untuk caching masif.
- **Disk:** 40GB SSD/NVMe (untuk logging & caching).
- **Network:** 1Gbps / 10Gbps NIC dengan dukungan Multi-queue.
- **Virtualization:** Support Proxmox (LXC/VM), KVM, atau Bare Metal.

---

### 1. RINGKASAN SISTEM
Sistem ini menggunakan arsitektur **Hybrid DNS High Performance** yang menggabungkan kecepatan **dnsmasq** dengan keamanan serta rekursi tingkat tinggi dari **Unbound**.

- **DNS Engine:** Hybrid (dnsmasq + Unbound) - Tuned for High Concurrency.
- **Security:** Anti-DDoS (iptables Hashlimit), Malware Shield (100k+ domains), Intelligent Self-Healing Guardian.
- **Web GUI:** Management Dashboard berbasis Flask dengan antarmuka modern dan responsif.
- **Topologi:** Mendukung **NAT Topology** (Ribuan user dibalik satu IP Public) dengan manajemen koneksi yang efisien.

---

### 2. FITUR UNGGULAN TERBARU (UPDATE 2026)
#### 🛡️ DNS Security & Anti-Flood
- **ANY Query Block:** Menolak query tipe `ANY` secara otomatis untuk mencegah *DNS Amplification Attack*.
- **Rate Limiting:** Perlindungan hingga **90.000 QPS** dengan deteksi flood otomatis (Threshold: 5000 QPS).
- **Loop Prevention:** Deteksi dan pemutusan otomatis rantai *DNS Looping* internal.

#### ⚡ Performance Optimization
- **Multithreading Unbound:** Optimalisasi penggunaan semua core CPU (Up to 16 threads).
- **Smart Caching:** Fitur *Prefetch* dan *Serve-Expired* untuk jawaban DNS instan tanpa menunggu internet.
- **UDP Buffer Tuning:** Kernel buffer ditingkatkan hingga 16MB untuk mencegah *packet drop* pada trafik tinggi.

#### 📊 Advanced Monitoring
- **QPS Smoothing:** Grafik trafik yang lebih halus dan akurat, tahan terhadap *log rotation spikes*.
- **Hardware Health:** Monitoring real-time CPU, RAM, Load Average, dan HDD.
- **Telegram Alarm:** Notifikasi otomatis ke Telegram jika terjadi anomali trafik atau kegagalan sistem.

---

### 3. DNS TRUST & INTERNET POSITIF
Fitur ini dirancang untuk mematuhi regulasi pemblokiran konten negatif (Internet Positif) dengan pengalaman pengguna yang mulus.

- **HTTPS Redirect:** Mendukung redirect otomatis dari akses HTTPS ke domain terblokir (via 302 Redirect).
- **Captive Portal Bypass:** Whitelisting otomatis untuk domain *connectivity check* (Google, Apple, Windows) agar perangkat tidak mendeteksi jaringan sebagai "Captive Portal" palsu.

---

### 4. PROTEKSI DISK & SELF-HEALING
- **Emergency Disk Protection:** Pembersihan log otomatis jika penggunaan disk mencapai **90%**.
- **Guardian System:** Memantau port DNS (53) dan GUI (5000) secara aktif. Jika layanan mati, Guardian akan melakukan restart otomatis.
- **Log Rotation:** Menggunakan metode `copytruncate` yang aman untuk pengumpulan data statistik tanpa memutus aliran log.

---

### 5. LICENSE & PLAN MANAGEMENT
Sistem kini dilengkapi dengan **License Generator Center**:
- **BASIC:** Core Filtering & Caching.
- **PRO:** Advanced Threat Detection & Full Analytics.
- **ENTERPRISE:** High Availability Clustering (Primary-Secondary Sync) & ISP Scale RPS.

---

### 6. TROUBLESHOOTING & MAINTENANCE
- **Web GUI:** Akses via `https://IP_SERVER:5000` (Gunakan HTTPS).
- **Restart All Services:** `sudo systemctl restart dnsmasq unbound dnsmars-alarm dnsmars-traffic dnsmars-gui`
- **Check Logs:** `tail -f /var/log/dnsmasq.log` atau via Dashboard.

---

*Terakhir Diperbarui: 13 Maret 2026 00:15*
*Oleh: DNS Mars System Assistant*
*© 2026 PT MARS DATA TELEKOMUNIKASI*
