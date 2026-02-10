#!/bin/bash

# dnsMars Auto Installer
# Installs dependencies, configures services, and starts the system.
# Run this script as root: sudo ./install.sh

set -e

if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root (sudo ./install.sh)"
  exit 1
fi

INSTALL_DIR=$(pwd)
echo "=== Installing dnsMars from $INSTALL_DIR ==="

# 1. Update System & Install Dependencies
echo ">>> [1/7] Updating system and installing dependencies..."
apt-get update -qq
apt-get install -y dnsmasq unbound nginx python3 python3-pip git curl net-tools

# 2. Python Dependencies
echo ">>> [2/7] Installing Python requirements..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
else
    echo "Warning: requirements.txt not found. Installing default libs..."
    pip3 install flask psutil requests
fi

# 3. Configure Dnsmasq
echo ">>> [3/7] Configuring Dnsmasq..."
# Backup original if not exists
if [ ! -f /etc/dnsmasq.conf.bak ]; then
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
fi

# Clean existing custom configs to avoid conflicts
rm -rf /etc/dnsmasq.d/*

# Copy new configs
if [ -d "config/dnsmasq" ]; then
    cp -r config/dnsmasq/* /etc/dnsmasq.d/
    echo "Copied dnsmasq configs."
else
    echo "Error: config/dnsmasq directory not found!"
    exit 1
fi

# Ensure main config includes /etc/dnsmasq.d/*.conf
if ! grep -q "conf-dir=/etc/dnsmasq.d" /etc/dnsmasq.conf; then
    echo "conf-dir=/etc/dnsmasq.d/,*.conf" >> /etc/dnsmasq.conf
fi

# Disable log-queries by default to save disk space
if [ -f /etc/dnsmasq.d/logging.conf ]; then
    sed -i 's/^log-queries/#log-queries/' /etc/dnsmasq.d/logging.conf
fi

# 4. Configure Unbound
echo ">>> [4/7] Configuring Unbound..."
if [ -f "config/unbound/unbound.conf" ]; then
    cp config/unbound/unbound.conf /etc/unbound/unbound.conf
fi
# Initialize anchor
echo "Initializing Unbound trust anchor..."
/usr/lib/unbound/package-helper root_trust_anchor_update || true
chown unbound:unbound /var/lib/unbound/root.key || true

# 5. Configure Nginx (Web GUI)
echo ">>> [5/7] Configuring Nginx..."
if [ -f "config/nginx/sites-available/default" ]; then
    cp config/nginx/sites-available/default /etc/nginx/sites-available/default
    # Ensure symlink
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
    nginx -t || echo "Warning: Nginx config check failed."
fi

# 6. Install Guardian Service
echo ">>> [6/7] Installing Guardian Service..."
SERVICE_FILE="/etc/systemd/system/guardian.service"

if [ -f "config/systemd/guardian.service" ]; then
    cp config/systemd/guardian.service $SERVICE_FILE
    
    # Update paths in service file to match current install directory
    echo "Updating paths in service file..."
    sed -i "s|WorkingDirectory=.*|WorkingDirectory=$INSTALL_DIR|g" $SERVICE_FILE
    sed -i "s|ExecStartPre=.*|ExecStartPre=/bin/bash $INSTALL_DIR/scripts/setup_firewall.sh|g" $SERVICE_FILE
    sed -i "s|ExecStart=.*|ExecStart=/usr/bin/python3 $INSTALL_DIR/src/guardian.py|g" $SERVICE_FILE
    
    # Make setup script executable
    chmod +x "$INSTALL_DIR/scripts/setup_firewall.sh"
else
    echo "Error: config/systemd/guardian.service not found!"
fi

systemctl daemon-reload
systemctl enable dnsmasq unbound guardian nginx

# 7. Start Services
echo ">>> [7/7] Starting Services..."
systemctl restart dnsmasq unbound guardian nginx

echo "=== Installation Complete! ==="
echo "DNS Server is running."
echo "Web GUI should be accessible at: http://$(hostname -I | awk '{print $1}'):5000"
