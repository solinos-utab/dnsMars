#!/bin/bash

# --- DNS Mars - WEB GUI & MONITORING ONLY INSTALLER ---
# Target: Management Node
# Description: Installs Web GUI, Traffic Collector, and Alarm System.

set -e

INSTALL_DIR="/home/dns"
echo "🚀 Installing DNS Mars Management Web GUI..."

# 1. Dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip sqlite3 curl openssl git rsync sshpass

# Python requirements
pip3 install flask requests psutil

# 2. Setup Directories
sudo mkdir -p $INSTALL_DIR/web_gui
sudo chown -R $USER:$USER $INSTALL_DIR

# 3. Web GUI Setup
echo "📂 Setting up Web GUI and Monitoring scripts..."
# SSL Certificate Generation
if [ ! -f "$INSTALL_DIR/web_gui/cert.pem" ]; then
    openssl req -x509 -newkey rsa:4096 -keyout $INSTALL_DIR/web_gui/key.pem -out $INSTALL_DIR/web_gui/cert.pem \
            -days 365 -nodes -subj "/C=ID/ST=Jakarta/L=Jakarta/O=MarsData/CN=dns.mdnet.co.id"
fi

# 4. Systemd Services
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

# DNS Alarm System
create_service "dnsmars-alarm" "DNS Mars Alarm System" "/usr/bin/python3 $INSTALL_DIR/alarm_system.py"
# Traffic Collector
create_service "dnsmars-traffic" "DNS Mars Traffic Collector" "/usr/bin/python3 $INSTALL_DIR/traffic_collector.py"
# Web GUI
create_service "dnsmars-gui" "DNS Mars Management Web GUI" "/usr/bin/python3 $INSTALL_DIR/web_gui/app.py"

# 5. Enable & Start
sudo systemctl daemon-reload
sudo systemctl enable dnsmars-alarm dnsmars-traffic dnsmars-gui
sudo systemctl restart dnsmars-alarm dnsmars-traffic dnsmars-gui

echo "-------------------------------------------------------"
echo "🎉 Management GUI Installation Complete!"
echo "🌐 Web GUI: https://$(curl -s ifconfig.me):5000"
echo "⚠️  Note: Remember to configure your Node IPs in the Settings menu."
echo "-------------------------------------------------------"
