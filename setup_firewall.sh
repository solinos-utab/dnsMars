#!/bin/bash

# Reset rules (Hati-hati: Pastikan port SSH 22 tetap terbuka)
# Kita tidak akan flush semua jika ingin aman, tapi kita tambahkan rule di atas.

echo "Setting up Anti-DDoS and DNS Flood Protection..."

# 1. Port yang diizinkan dengan ACL (SSH & Web GUI)
  # Ambil IP server secara otomatis
  SERVER_IP=$(ip -4 addr show ens18 | grep inet | awk '{print $2}' | cut -d/ -f1)
  
  # Load Whitelist from file
  WHITELIST_FILE="/home/dns/whitelist.conf"
  ALLOWED_IPS=("$SERVER_IP")
  ALLOWED_SUBNETS=()
  
  if [ -f "$WHITELIST_FILE" ]; then
      while IFS= read -r line || [ -n "$line" ]; do
          # Skip comments and empty lines
          [[ "$line" =~ ^#.*$ ]] && continue
          [[ -z "$line" ]] && continue
          
          if [[ "$line" == */* ]]; then
              ALLOWED_SUBNETS+=("$line")
          else
              ALLOWED_IPS+=("$line")
          fi
      done < "$WHITELIST_FILE"
  fi

  # Flush existing INPUT rules to apply ACL cleanly
 iptables -F INPUT

 # Allow loopback
 iptables -A INPUT -i lo -j ACCEPT
 iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH and Web GUI (Port 5000) for trusted IPs
for ip in "${ALLOWED_IPS[@]}"; do
    if [ ! -z "$ip" ]; then
        iptables -A INPUT -s "$ip" -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -s "$ip" -p tcp --dport 5000 -j ACCEPT
    fi
done

# Allow SSH and Web GUI for trusted Subnets
for subnet in "${ALLOWED_SUBNETS[@]}"; do
    iptables -A INPUT -s "$subnet" -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -s "$subnet" -p tcp --dport 5000 -j ACCEPT
done

# Allow Web GUI (Port 5000) for everyone with Rate Limiting (Proteksi Brute Force)
# Ini memungkinkan user mengakses dari mana saja selama tidak melakukan spamming
iptables -A INPUT -p tcp --dport 5000 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 5000 -m state --state NEW -m recent --update --seconds 60 --hitcount 15 -j DROP
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT

# Drop all other SSH attempts (Port 5000 sudah di-allow di atas)
iptables -A INPUT -p tcp --dport 22 -j DROP

# Allow HTTP and HTTPS for Block Page (Accessible to all)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# 2. Proteksi DNS UDP Flood (High Performance: 1.000.000 QPS Global, 1.500 QPS per IP)
  # Whitelist subnet dari rate limit
  for subnet in "${ALLOWED_SUBNETS[@]}"; do
      iptables -A INPUT -s "$subnet" -p udp --dport 53 -j ACCEPT
  done

  # Per-IP Limit: 1.500 QPS (Burst 2.000)
   # Per-IP Limit: 1.500 QPS (Burst 2.000)
    iptables -A INPUT -p udp --dport 53 -m hashlimit --hashlimit-name dns_per_ip --hashlimit-upto 1500/sec --hashlimit-burst 2000 --hashlimit-mode srcip --hashlimit-htable-expire 30000 -j ACCEPT
    
    # Global Limit: Sangat Tinggi (100.000 QPS total sebagai pengaman hardware)
    iptables -A INPUT -p udp --dport 53 -m hashlimit --hashlimit-name dns_global --hashlimit-upto 100000/sec --hashlimit-burst 120000 --hashlimit-htable-expire 30000 -j ACCEPT

   # Drop sisanya
   iptables -A INPUT -p udp --dport 53 -j DROP

# 3. Proteksi DNS TCP Flood (Conn Limit: 10 connections per source IP)
iptables -A INPUT -p tcp --dport 53 -m connlimit --connlimit-above 10 -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# 4. Proteksi ICMP Flood (Ping Flood)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# 5. NAT Interception (Menangkap paksa trafik DNS luar ke server lokal)
iptables -t nat -F PREROUTING
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 53

# 6. Drop Invalid Packets
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
