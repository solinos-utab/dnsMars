#!/bin/bash

# --- DNS Mars Data Telekomunikasi - Auto Installer (v2.0) ---
# Description: Automated setup for DNS Hybrid (dnsmasq + Unbound), 
#              Traffic Monitoring, Alarm System, and Web GUI.

set -e # Exit on error

# Configuration
INSTALL_DIR="/home/dns"
GIT_REPO="https://github.com/solinos-utab/dnsMars"

echo "🚀 Starting DNS Mars Auto-Installation on Ubuntu 22.04..."

# 1. Update & Install Dependencies
echo "📦 Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y dnsmasq unbound python3 python3-pip python3-psutil \
                        iptables-persistent curl git re2c sshpass sqlite3

# Install Python requirements
pip3 install flask requests psutil

# 2. Setup Directory Structure
echo "📂 Setting up directories..."
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:$USER $INSTALL_DIR
cd $INSTALL_DIR

# 3. Download Source (If not already present)
if [ ! -d "$INSTALL_DIR/.git" ]; then
    echo "📥 Cloning repository..."
    git clone $GIT_REPO .
fi

# 4. Configure DNS Services
echo "⚙️ Configuring DNS (dnsmasq + Unbound)..."

# Copy dnsmasq configs
sudo cp system_config_backup/dnsmasq/*.conf /etc/dnsmasq.d/
# Copy unbound configs
sudo cp system_config_backup/unbound/*.conf /etc/unbound/unbound.conf.d/

# Enable IPv4 forwarding for NAT topology
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 5. Initialize Database (Dummy/Empty)
echo "🗄️ Initializing system databases..."
if [ ! -f "brand_settings.db" ]; then
    sqlite3 brand_settings.db "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);"
    # User will need to fill this via WebGUI or manually
fi

# 6. Setup SSL Certificates
echo "🔐 Generating SSL certificates for Web GUI..."
mkdir -p web_gui
if [ ! -f "web_gui/cert.pem" ]; then
    openssl req -x509 -newkey rsa:4096 -keyout web_gui/key.pem -out web_gui/cert.pem \
            -days 365 -nodes -subj "/C=ID/ST=Jakarta/L=Jakarta/O=MarsData/CN=dns.mdnet.co.id"
fi

# 7. Install Systemd Services
echo "🔄 Installing Systemd services..."

# Service Template Helper
create_service() {
    local name=$1
    local description=$2
    local exec=$3
    sudo tee /etc/systemd/system/$name.service <<EOF
[Unit]
Description=$description
After=network.target dnsmasq.service unbound.service

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

# DNS Alarm System
create_service "dnsmars-alarm" "DNS Mars Alarm System" "/usr/bin/python3 $INSTALL_DIR/alarm_system.py"
# Traffic Collector (Primary)
create_service "dnsmars-traffic" "DNS Mars Traffic Collector" "/usr/bin/python3 $INSTALL_DIR/traffic_collector.py"
# Web GUI
create_service "dnsmars-gui" "DNS Mars Management Web GUI" "/usr/bin/python3 $INSTALL_DIR/web_gui/app.py"

# 8. Enable & Start Services
echo "✅ Finalizing installation..."
sudo systemctl daemon-reload
sudo systemctl enable dnsmasq unbound dnsmars-alarm dnsmars-traffic dnsmars-gui
sudo systemctl restart dnsmasq unbound dnsmars-alarm dnsmars-traffic dnsmars-gui

echo "-------------------------------------------------------"
echo "🎉 Installation Complete!"
echo "🌐 Web GUI: https://$(curl -s ifconfig.me):5000"
echo "⚠️  Important: Update SSH credentials in brand_settings.db via WebGUI."
echo "-------------------------------------------------------"
