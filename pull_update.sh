#!/bin/bash
# Script Update Sisi Client (Secondary)
# Jalankan script ini di terminal server Secondary (103.68.213.213)
# Usage: ./pull_update.sh <IP_PRIMARY> <USER_PRIMARY>
# Contoh: ./pull_update.sh 103.68.213.74 dns

PRIMARY_IP=$1
PRIMARY_USER=${2:-dns}

if [ -z "$PRIMARY_IP" ]; then
    echo "Usage: ./pull_update.sh <IP_PRIMARY> [USER_PRIMARY]"
    echo "Example: ./pull_update.sh 103.68.213.74 dns"
    exit 1
fi

echo "--- Pulling Updates from Primary ($PRIMARY_IP) ---"

# 1. Prepare Directories
echo "[1/5] Preparing Directories..."
mkdir -p /home/dns/web_gui/templates
mkdir -p /home/dns/dnsMars/scripts
chown -R $USER:$USER /home/dns 2>/dev/null || true

# 2. Pull Web GUI Files
echo "[2/5] Downloading Web GUI..."
scp $PRIMARY_USER@$PRIMARY_IP:/home/dns/web_gui/app.py /home/dns/web_gui/
scp $PRIMARY_USER@$PRIMARY_IP:/home/dns/web_gui/templates/index.html /home/dns/web_gui/templates/

# 3. Pull Configs & Scripts
echo "[3/5] Downloading Configs & Scripts..."
scp $PRIMARY_USER@$PRIMARY_IP:/home/dns/dnsMars/scripts/setup_firewall.sh /home/dns/setup_firewall.sh
scp $PRIMARY_USER@$PRIMARY_IP:/home/dns/dnsMars/whitelist_domains.txt /home/dns/dnsMars/whitelist_domains.txt
scp $PRIMARY_USER@$PRIMARY_IP:/home/dns/blocked_final.html /home/dns/blocked_final.html

# 4. Apply Block Page
echo "[4/5] Applying Block Page..."
cp /home/dns/blocked_final.html /var/www/html/index.html
systemctl restart nginx

# 5. Apply System Changes
echo "[5/5] Applying System Changes..."

# Apply Firewall (Fix Captive Portal)
if [ -f /home/dns/setup_firewall.sh ]; then
    bash /home/dns/setup_firewall.sh
fi

# Restart Services
if systemctl list-units --full -all | grep -q 'dnsmars-gui.service'; then
    systemctl restart dnsmars-gui
    echo "Web GUI Restarted."
fi

systemctl restart dnsmasq
echo "DNS Service Restarted."

echo "--- Update Complete! ---"
echo "Sekarang Server Secondary sudah identik dengan Primary."
