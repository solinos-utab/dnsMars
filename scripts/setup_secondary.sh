#!/bin/bash
# DNS MarsData Secondary Setup Script
# Run this on your SECONDARY VM

PRIMARY_IP=$1
SYNC_TOKEN=$2

if [ -z "$PRIMARY_IP" ] || [ -z "$SYNC_TOKEN" ]; then
    echo "Usage: sudo bash setup_secondary.sh <PRIMARY_IP> <SYNC_TOKEN>"
    exit 1
fi

echo "--- STARTING SECONDARY DNS SETUP ---"

# 1. Install Dependencies
apt-get update
apt-get install -y dnsmasq unbound curl jq

# 2. Stop services to configure
systemctl stop dnsmasq unbound

# 3. Basic Config Sync (Initial)
echo "Fetching initial configuration from Primary ($PRIMARY_IP)..."
SYNC_URL="https://$PRIMARY_IP:5000/api/sync/config?token=$SYNC_TOKEN"
RESPONSE=$(curl -sk "$SYNC_URL")

if [[ $RESPONSE != *"success"* ]]; then
    echo "ERROR: Failed to connect to Primary or Invalid Token."
    echo "Response: $RESPONSE"
    exit 1
fi

# 4. Create Sync Script
cat <<EOF > /home/dns_sync.sh
#!/bin/bash
PRIMARY_IP="$PRIMARY_IP"
SYNC_TOKEN="$SYNC_TOKEN"
SYNC_URL="https://\$PRIMARY_IP:5000/api/sync/config?token=\$SYNC_TOKEN"

RESPONSE=\$(curl -sk "\$SYNC_URL")
if [[ \$RESPONSE == *"success"* ]]; then
    # Extract and save configs
    echo "\$RESPONSE" | jq -r '.configs.blacklist' > /etc/dnsmasq.d/blacklist.conf
    echo "\$RESPONSE" | jq -r '.configs.whitelist_dnsmasq' > /etc/dnsmasq.d/whitelist.conf
    echo "\$RESPONSE" | jq -r '.configs.upstream' > /etc/dnsmasq.d/upstream.conf
    echo "\$RESPONSE" | jq -r '.configs.alias' > /etc/dnsmasq.d/alias.conf
    echo "\$RESPONSE" | jq -r '.configs.whitelist_firewall' > /home/whitelist.conf
    
    # Handle Trust (Internet Positif) Sync
    TRUST_ENABLED=\$(echo "\$RESPONSE" | jq -r '.trust_config.enabled')
    BLOCKLIST_FILE="/etc/dnsmasq.d/internet_positif.conf"
    BLOCKLIST_DISABLED="/home/dns/blocklists/disabled/internet_positif.conf"
    
    # Ensure disabled dir exists
    mkdir -p /home/dns/blocklists/disabled
    
    if [[ "\$TRUST_ENABLED" == "true" ]]; then
        if [ -f "\$BLOCKLIST_DISABLED" ]; then
            mv "\$BLOCKLIST_DISABLED" "\$BLOCKLIST_FILE"
        fi
        # If file missing entirely, we might need to download it (optional future improvement)
        # For now, we assume Secondary was installed with install.sh which provides the file
    else
        if [ -f "\$BLOCKLIST_FILE" ]; then
            mv "\$BLOCKLIST_FILE" "\$BLOCKLIST_DISABLED"
        fi
    fi

    # Test and Restart
    dnsmasq --test && systemctl restart dnsmasq
    echo "Sync Successful: \$(date)"
else
    echo "Sync Failed: \$(date)"
fi
EOF

chmod +x /home/dns_sync.sh

# 5. Run initial sync
bash /home/dns_sync.sh

# 6. Set up Cron (every 5 minutes)
(crontab -l 2>/dev/null; echo "*/5 * * * * /home/dns_sync.sh >> /var/log/dns_sync.log 2>&1") | crontab -

echo "--- SECONDARY DNS SETUP COMPLETE ---"
echo "Secondary will now sync from Primary every 5 minutes."
echo "Logs available at /var/log/dns_sync.log"
