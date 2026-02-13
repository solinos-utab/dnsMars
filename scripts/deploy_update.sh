#!/bin/bash
# Script untuk menyalin update terbaru ke Secondary DNS
# Usage: ./deploy_update.sh <SECONDARY_IP> <SSH_USER>

SECONDARY_IP=$1
SSH_USER=${2:-root}

if [ -z "$SECONDARY_IP" ]; then
    echo "Usage: ./deploy_update.sh <SECONDARY_IP> [SSH_USER]"
    echo "Example: ./deploy_update.sh 192.168.1.2 dns"
    exit 1
fi

echo "--- Deploying Updates to Secondary ($SECONDARY_IP) ---"

# 0. Prepare Directories (Fix for minimal install)
echo "[0/4] Preparing Directories..."
ssh $SSH_USER@$SECONDARY_IP "
    sudo mkdir -p /home/dns/web_gui/templates
    sudo mkdir -p /home/dns/dnsMars/scripts
    sudo chown -R $SSH_USER:$SSH_USER /home/dns
"

# 1. Copy Web GUI (App & Templates)
echo "[1/4] Updating Web GUI..."
scp /home/dns/web_gui/app.py $SSH_USER@$SECONDARY_IP:/home/dns/web_gui/
scp /home/dns/web_gui/templates/index.html $SSH_USER@$SECONDARY_IP:/home/dns/web_gui/templates/

# 2. Copy Firewall Script
echo "[2/4] Updating Firewall Script..."
scp /home/dns/dnsMars/scripts/setup_firewall.sh $SSH_USER@$SECONDARY_IP:/home/dns/setup_firewall.sh

# 3. Copy Whitelist Domains
echo "[3/4] Updating Whitelist Domains..."
scp /home/dns/dnsMars/whitelist_domains.txt $SSH_USER@$SECONDARY_IP:/home/dns/dnsMars/whitelist_domains.txt

# 3.5 Copy Block Page
echo "[3.5/4] Updating Block Page..."
scp /home/dns/blocked_final.html $SSH_USER@$SECONDARY_IP:/home/dns/blocked_final.html

# 4. Apply Changes via SSH
echo "[4/4] Applying Changes..."
ssh $SSH_USER@$SECONDARY_IP "
    # Update Nginx Block Page
    sudo cp /home/dns/blocked_final.html /var/www/html/index.html
    sudo systemctl restart nginx
    echo 'Block Page updated.'

    # Restart Web GUI (Check if service exists first)
    if systemctl list-units --full -all | grep -q 'dnsmars-gui.service'; then
        sudo systemctl restart dnsmars-gui
        echo 'Web GUI restarted.'
    else
        echo 'Web GUI service not found. Skipping restart.'
    fi
    
    # Apply Firewall Fix (Remove Captive Portal trigger)
    if [ -f /home/dns/setup_firewall.sh ]; then
        sudo bash /home/dns/setup_firewall.sh
        echo 'Firewall rules updated.'
    fi
    
    # Update Blocklist with new Whitelist (if script exists)
    if [ -f /home/dns/dnsMars/scripts/update_blocklist.sh ]; then
        sudo bash /home/dns/dnsMars/scripts/update_blocklist.sh
        echo 'Blocklist updated.'
    else
        # Fallback: Explicit restart if script not present
        sudo systemctl restart dnsmasq
        echo 'Dnsmasq restarted.'
    fi
"

echo "--- Deployment Complete! ---"
