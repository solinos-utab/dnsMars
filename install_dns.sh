#!/bin/bash

# --- DNS Mars - DNS ENGINE ONLY INSTALLER ---
# Target: DNS Node (Primary/Secondary)
# Description: Installs dnsmasq, Unbound, Guardian, and Performance Tuning.

set -e

INSTALL_DIR="/home/dns"
echo "🚀 Installing DNS Mars Engine..."

# 1. Dependencies
sudo apt-get update
sudo apt-get install -y dnsmasq unbound python3 python3-psutil iptables-persistent curl git re2c

# 2. Setup Directories
sudo mkdir -p $INSTALL_DIR/system_config_backup
sudo chown -R $USER:$USER $INSTALL_DIR

# 3. DNS Configuration
echo "⚙️ Applying Optimized DNS Configs..."
sudo cp system_config_backup/dnsmasq/*.conf /etc/dnsmasq.d/
sudo cp system_config_backup/unbound/*.conf /etc/unbound/unbound.conf.d/

# 4. Kernel & Network Tuning
echo "⚡ Applying Kernel Optimizations..."
sudo chmod +x optimize_dns_100gbps.sh
sudo ./optimize_dns_100gbps.sh

# 5. Guardian Service (Self-Healing)
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

# 6. Enable & Start
sudo systemctl daemon-reload
sudo systemctl enable dnsmasq unbound guardian
sudo systemctl restart dnsmasq unbound guardian

echo "✅ DNS Engine Installation Complete!"
