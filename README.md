Update 13 March 2026 00:20 #FINAL-OPTIMIZED-SPLIT-READY

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

### 📄 KONTEN AUTO-INSTALLER SCRIPTS

#### 1. install_dns.sh (DNS Engine Only)
```bash
#!/bin/bash
# Target: DNS Node (Primary/Secondary)
set -e
INSTALL_DIR="/home/dns"
echo "🚀 Installing DNS Mars Engine..."
sudo apt-get update
sudo apt-get install -y dnsmasq unbound python3 python3-psutil iptables-persistent curl git re2c
sudo mkdir -p $INSTALL_DIR/system_config_backup
sudo chown -R $USER:$USER $INSTALL_DIR
echo "⚙️ Applying Optimized DNS Configs..."
sudo cp system_config_backup/dnsmasq/*.conf /etc/dnsmasq.d/
sudo cp system_config_backup/unbound/*.conf /etc/unbound/unbound.conf.d/
echo "⚡ Applying Kernel Optimizations..."
sudo chmod +x optimize_dns_100gbps.sh
sudo ./optimize_dns_100gbps.sh
echo "🛡️ Setting up Guardian Service..."
sudo tee /etc/systemd/system/guardian.service <<EOF
[Unit]
Description=Intelligent DNS Guardian
After=network.target dnsmasq.service unbound.service
[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/guardian.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable dnsmasq unbound guardian
sudo systemctl restart dnsmasq unbound guardian
echo "✅ DNS Engine Installation Complete!"
```

#### 2. install_gui.sh (Web Management Only)
```bash
#!/bin/bash
# Target: Management Node
set -e
INSTALL_DIR="/home/dns"
echo "🚀 Installing DNS Mars Management Web GUI..."
sudo apt-get update
sudo apt-get install -y python3 python3-pip sqlite3 curl openssl git rsync sshpass
pip3 install flask requests psutil
sudo mkdir -p $INSTALL_DIR/web_gui
sudo chown -R $USER:$USER $INSTALL_DIR
echo "📂 Setting up Web GUI and Monitoring scripts..."
if [ ! -f "$INSTALL_DIR/web_gui/cert.pem" ]; then
    openssl req -x509 -newkey rsa:4096 -keyout $INSTALL_DIR/web_gui/key.pem -out $INSTALL_DIR/web_gui/cert.pem \
            -days 365 -nodes -subj "/C=ID/ST=Jakarta/L=Jakarta/O=MarsData/CN=dns.mdnet.co.id"
fi
echo "🔄 Setting up Systemd services..."
create_service() {
    local name=$1
    local description=$2
    local exec=$3
    sudo tee /etc/systemd/system/$name.service <<EOF
[Unit]
Description=$description
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$exec
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
}
create_service "dnsmars-alarm" "DNS Mars Alarm System" "/usr/bin/python3 $INSTALL_DIR/alarm_system.py"
create_service "dnsmars-traffic" "DNS Mars Traffic Collector" "/usr/bin/python3 $INSTALL_DIR/traffic_collector.py"
create_service "dnsmars-gui" "DNS Mars Management Web GUI" "/usr/bin/python3 $INSTALL_DIR/web_gui/app.py"
sudo systemctl daemon-reload
sudo systemctl enable dnsmars-alarm dnsmars-traffic dnsmars-gui
sudo systemctl restart dnsmars-alarm dnsmars-traffic dnsmars-gui
echo "-------------------------------------------------------"
echo "🎉 Management GUI Installation Complete!"
echo "🌐 Web GUI: https://\$(curl -s ifconfig.me):5000"
echo "-------------------------------------------------------"
```

---

### 📋 SPESIFIKASI SISTEM (MINIMUM REQUIREMENTS)
- **Operating System:** Ubuntu 22.04 LTS (Jammy Jellyfish)
- **CPU:** Minimum 4 Core / 16 Core untuk 100k+ user.
- **RAM:** Minimum 4GB / 16GB+ untuk caching masif.
- **Disk:** 40GB SSD/NVMe.
- **Network:** 1Gbps / 10Gbps NIC.

---

### 1. RINGKASAN SISTEM
Sistem Hybrid DNS (dnsmasq + Unbound) yang di-tuning untuk ISP Scale dengan fitur Anti-DDoS, Malware Shield, dan Web Management Dashboard.

---

### 2. FITUR UNGGULAN TERBARU (UPDATE 2026)
- **🛡️ Security:** ANY Query Block, Rate Limiting (90k QPS), Loop Prevention.
- **⚡ Performance:** Multithreading Unbound, Smart Caching, UDP Buffer Tuning.
- **📊 Monitoring:** QPS Smoothing, Hardware Health, Telegram Alarm.

---

*Terakhir Diperbarui: 13 Maret 2026 00:20*
*Oleh: DNS Mars System Assistant*
*© 2026 PT MARS DATA TELEKOMUNIKASI*
