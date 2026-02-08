#!/bin/bash
# Script to update hardcoded IPs in configuration files

# Detect current (soon to be old) IP from config before updating
OLD_IP=$(grep -oP 'address=/dns.mdnet.co.id/\K\S+' /home/dns/dnsmasq_smartdns.conf)

# Retry IP detection for up to 15 seconds (after netplan apply)
for i in {1..15}; do
    NEW_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || ip -4 addr show | grep inet | grep -v '127.0.0.1' | head -n1 | awk '{print $2}' | cut -d/ -f1)
    if [ ! -z "$NEW_IP" ] && [ "$NEW_IP" != "$OLD_IP" ]; then
        # Check if the NEW_IP is actually assigned to an interface
        if ip addr show | grep -q "$NEW_IP"; then
            break
        fi
    fi
    echo "Waiting for NEW IP detection (different from $OLD_IP)... ($i/15)"
    sleep 1
done

# If we couldn't detect a NEW IP, use the current one (maybe it didn't change or we are reverting)
if [ -z "$NEW_IP" ]; then
    NEW_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || ip -4 addr show | grep inet | grep -v '127.0.0.1' | head -n1 | awk '{print $2}' | cut -d/ -f1)
fi

if [ -z "$NEW_IP" ]; then
    echo "Error: Could not detect new IP address."
    exit 1
fi

echo "Detected New IP: $NEW_IP"
echo "Updating configuration files..."

# 1. Update dnsmasq_smartdns.conf
sudo sed -i "s|address=/dns.mdnet.co.id/.*|address=/dns.mdnet.co.id/$NEW_IP|" /home/dns/dnsmasq_smartdns.conf
# Update PTR record (reversed IP)
REVERSED_IP=$(echo $NEW_IP | awk -F. '{print $4"."$3"."$2"."$1}')
sudo sed -i "s|ptr-record=.*.in-addr.arpa,dns.mdnet.co.id|ptr-record=$REVERSED_IP.in-addr.arpa,dns.mdnet.co.id|" /home/dns/dnsmasq_smartdns.conf

# 2. Update unbound_smartdns.conf
sudo sed -i "s|local-data: \"dns.mdnet.co.id. IN A .*\"|local-data: \"dns.mdnet.co.id. IN A $NEW_IP\"|" /home/dns/unbound_smartdns.conf
sudo sed -i "s|local-data-ptr: \".* dns.mdnet.co.id\"|local-data-ptr: \"$NEW_IP dns.mdnet.co.id\"|" /home/dns/unbound_smartdns.conf

# 3. Update all dnsmasq configs that use redirects to server IP
for conf in /etc/dnsmasq.d/blacklist.conf /etc/dnsmasq.d/malware.conf; do
    if [ -f "$conf" ]; then
        echo "Updating redirects in $conf..."
        sudo sed -i "s|/[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$|/$NEW_IP|" "$conf"
    fi
done

# 4. Update whitelist.conf (remove old IP and add new IP)
if [ ! -z "$OLD_IP" ] && [ "$OLD_IP" != "$NEW_IP" ]; then
    echo "Updating whitelist: removing $OLD_IP and adding $NEW_IP"
    sudo sed -i "/$OLD_IP/d" /home/dns/whitelist.conf
fi
if ! grep -q "$NEW_IP" /home/dns/whitelist.conf; then
    echo "$NEW_IP" | sudo tee -a /home/dns/whitelist.conf
fi

# 5. Restart and Apply Firewall Rules
echo "Applying Firewall Rules with IP: $NEW_IP"
sudo bash /home/dns/setup_firewall.sh "$NEW_IP"

# 6. Restart services
echo "Restarting DNS services..."
sudo systemctl restart unbound
sudo systemctl restart dnsmasq
sudo systemctl restart dnsmars-gui
sudo systemctl restart nginx
sudo systemctl restart guardian

echo "System IP update completed. Current IP: $NEW_IP"
