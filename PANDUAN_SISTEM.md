# 📘 BUKU PANDUAN SISTEM - PT MARS DATA TELEKOMUNIKASI
## DUAL STACK DNS ENGINE

Dokumentasi ini berisi panduan operasional dan teknis untuk sistem DNS Mars Data.

---

### 1. RINGKASAN SISTEM
Sistem ini menggunakan arsitektur **Hybrid DNS** yang menggabungkan kecepatan **dnsmasq** dengan keamanan serta rekursi tingkat tinggi dari **Unbound**.

- **DNS Engine:** Hybrid (dnsmasq + Unbound)
- **Security:** Anti-DDoS (iptables), Malware Shield (100k+ domains), Self-Healing Guardian.
- **Web GUI:** Management Dashboard berbasis Flask dengan antarmuka modern.

---

### 2. DNS TRUST & INTERNET POSITIF
Fitur ini dirancang untuk mematuhi regulasi pemblokiran konten negatif (Internet Positif).

- **Cara Kerja:** Sistem secara otomatis mencegat trafik DNS dan HTTP/HTTPS melalui firewall (NAT) untuk mengarahkan domain terblokir ke halaman peringatan internal.
- **Konfigurasi Utama:** `/etc/dnsmasq.d/smartdns.conf` (Single Source of Truth).
- **Status:** Jika DNS Trust "Enabled", pemblokiran aktif. Jika "Disabled", sistem tetap melakukan intersepsi namun dengan aturan yang lebih longgar (tergantung kebutuhan).
- **Guardian:** Layanan `guardian.py` memastikan aturan firewall tetap aktif meskipun sistem direstart.

---

### 3. ANALISIS TRAFIK & MONITORING
Dashboard Web GUI menyediakan pemantauan real-time:

- **Traffic Analysis (Grafik):**
    - **Garis Magenta (Pink):** Menampilkan **QPS (Queries Per Second)** murni per detik.
    - **Area Biru (Cyan):** Menampilkan **Snapshot Queries** (kepadatan query terbaru).
- **Hardware Monitoring:**
    - **CPU & RAM:** Beban pemrosesan real-time.
    - **HDD Usage:** Pemantauan sisa ruang penyimpanan disk.

---

### 4. BATASAN PERFORMA (QPS LIMIT)
Sistem dikonfigurasi untuk keamanan maksimal terhadap serangan DDoS:

- **Maksimal Forwarding (dnsmasq):** 1.500 query simultan.
- **Global Rate Limit (Unbound):** 1.000 QPS.
- **Client Rate Limit:** 100 QPS per alamat IP client.
- **Estimasi Kapasitas Hardware:** Sanggup menangani hingga 100.000 QPS (saat ini dibatasi software untuk keamanan).

---

### 5. MANAJEMEN WHITELIST & MALWARE
- **Whitelist:** Domain yang ditambahkan ke Whitelist akan melewati (bypass) semua aturan pemblokiran dan intersepsi.
- **Malware Shield:** Menggunakan database `/etc/dnsmasq.d/malware.conf` yang diperbarui secara berkala untuk memblokir situs berbahaya.

---

### 6. PEMELIHARAAN (MAINTENANCE)
- **Log System:** Sistem secara otomatis melakukan rotasi log untuk mencegah kepenuhan disk.
- **Self-Healing:** Jika layanan `dnsmasq` atau `unbound` mati, `guardian.py` akan mendeteksi dan menghidupkannya kembali dalam hitungan detik.

---
*Dokumen ini diperbarui secara otomatis oleh System Assistant.*
*© 2026 PT MARS DATA TELEKOMUNIKASI*
