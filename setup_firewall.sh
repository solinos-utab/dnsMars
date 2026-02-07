#!/bin/bash

# Reset rules (Hati-hati: Pastikan port SSH 22 tetap terbuka)
# Kita tidak akan flush semua jika ingin aman, tapi kita tambahkan rule di atas.

echo "Setting up Anti-DDoS and DNS Flood Protection..."

# 1. Port yang diizinkan dengan ACL (SSH)
ALLOWED_IPS=("103.68.213.6" "103.68.213.7")

# Flush existing INPUT rules to apply ACL cleanly
iptables -F INPUT

# Allow SSH and Web GUI (Port 5000) only for trusted IPs
for ip in "${ALLOWED_IPS[@]}"; do
    iptables -A INPUT -s "$ip" -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -s "$ip" -p tcp --dport 5000 -j ACCEPT
done

# Drop all other SSH and Web GUI attempts
iptables -A INPUT -p tcp --dport 22 -j DROP
iptables -A INPUT -p tcp --dport 5000 -j DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 2. Proteksi DNS UDP Flood (Rate Limit: 30 qps per source IP)
iptables -A INPUT -p udp --dport 53 -m hashlimit --hashlimit-name dns_flood --hashlimit-upto 30/sec --hashlimit-burst 50 --hashlimit-mode srcip --hashlimit-htable-expire 30000 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j DROP

# 3. Proteksi DNS TCP Flood (Conn Limit: 10 connections per source IP)
iptables -A INPUT -p tcp --dport 53 -m connlimit --connlimit-above 10 -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# 4. Proteksi ICMP Flood (Ping Flood)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# 5. Drop Invalid Packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# 6. Proteksi SYN Flood (Kernel Level & iptables)
iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# 7. Sysctl Optimizations (Anti-DDoS)
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_synack_retries=2
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1

echo "Firewall rules applied successfully."
