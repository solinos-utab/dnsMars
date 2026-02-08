ping 8.8.8.8
ip a
systemctl status ssh
sudo ufw status
sudo ufw allow ssh
sudo ufw reload
sudo ufw status
sudo ufw allow 22/tcp
ip a
ls /etc/netplan/
sudo nano /etc/netplan/00-installer-config.yaml
sudo netplan apply
sudo reboot
ping 8.8.8.8
ip a
cat /etc/unbound/unbound.conf.d/forward.conf
dig @127.0.0.1 pornhub.com +short
dig @127.0.0.1#5353 pornhub.com +short
dig @127.0.0.1 google.com +short
dig @127.0.0.1#5353 google.com +short
dig @127.0.0.1 -p 5353 pornhub.com +short
TRUST_IP="1.1.1.3"
echo "server=$TRUST_IP" | sudo tee /etc/dnsmasq.d/trust.conf
echo "forward-zone:
    name: \".\"
    forward-addr: $TRUST_IP
" | sudo tee /etc/unbound/unbound.conf.d/forward.conf
sudo systemctl restart dnsmasq && sudo systemctl restart unbound
# Test
dig @127.0.0.1 pornhub.com +short
dig @127.0.0.1 google.com +short
cat /etc/dnsmasq.d/blacklist.conf
dig @180.131.144.144 reddit.com +short
dig @180.131.144.144 pornhub.com +short
cat /etc/nginx/sites-enabled/*
ls /etc/unbound/unbound.conf.d/
nc -z -v -u 180.131.144.144 53
dig @180.131.145.145 google.com +short
curl -s http://localhost | head -n 10
sudo sed -i 's/^server=127.0.0.1#5353/#server=127.0.0.1#5353/' /etc/dnsmasq.d/smartdns.conf
TRUST_IP="1.1.1.3"
echo "server=$TRUST_IP" | sudo tee /etc/dnsmasq.d/trust.conf
# Also update Unbound
echo "forward-zone:
    name: \".\"
    forward-addr: $TRUST_IP
" | sudo tee /etc/unbound/unbound.conf.d/forward.conf
sudo systemctl restart dnsmasq && sudo systemctl restart unbound
# Test
dig @127.0.0.1 pornhub.com
sudo tail -n 50 /var/log/dnsmasq.log
sudo dnsmasq --test
sudo netstat -tulpn | grep nginx
cat /home/dns/setup_firewall.sh
sudo systemctl restart dnsmasq && sudo unbound-control flush_zone .
echo "Flush DNS: OK"
# Test Update SSH (just update list)
sudo apt-get update > /dev/null && echo "Update SSH (apt update): OK"
# Test Firewall Script (dry run or check syntax)
sudo bash -n /home/dns/setup_firewall.sh && echo "Firewall Script Syntax: OK"
# Test Status Metrics
python3 -c "import psutil; print(f'CPU: {psutil.cpu_percent()}%, RAM: {psutil.virtual_memory().percent}%')"
sudo sed -i '/testnx.com/d' /etc/dnsmasq.d/blacklist.conf
sudo sed -i '/both.com/d' /etc/dnsmasq.d/blacklist.conf
sudo sed -i '/both.com/d' /etc/dnsmasq.d/whitelist.conf
sudo sed -i '/google.com/d' /etc/dnsmasq.d/blacklist.conf
sudo systemctl restart dnsmasq
sudo systemctl restart nginx
sudo systemctl restart nginx
dig @103.68.213.213 porn.com +short
dig @103.68.213.213 188bet.com +short
sudo systemctl restart dnsmasq
dig @103.68.213.213 xvideos.com +short
cat /etc/dnsmasq.d/smartdns.conf
dig @127.0.0.1 reddit.com
dig @127.0.0.1 reddit.com AAAA
dig @103.68.213.213 reddit.com
dig @103.68.213.213 reddit.com +short
dig @103.68.213.213 porn.com
ls /etc/unbound/unbound.conf.d/
cat /etc/unbound/unbound.conf.d/*.conf
cat /etc/unbound/unbound.conf.d/forward.conf
sudo systemctl restart unbound
dig @127.0.0.1 porn.com
dig @103.68.213.213 porn.com
grep -r "server=" /etc/dnsmasq.conf
sudo systemctl stop dnsmasq unbound
dig @127.0.0.1 porn.com
grep -r "server=" /etc/dnsmasq.d/
grep -r "::" /etc/dnsmasq.d/
grep "::" /etc/unbound/unbound.conf.d/smartdns.conf
sudo systemctl restart unbound
cat << 'EOF' | sudo tee /etc/unbound/unbound.conf.d/forward.conf
forward-zone:
    name: "."
    forward-addr: 103.68.213.213
EOF

sudo systemctl restart dnsmasq unbound
dig @103.68.213.213 reddit.com +short
dig @127.0.0.1 porn.com +short
cat /etc/resolv.conf
cat /etc/dnsmasq.d/smartdns.conf
head -n 20 /etc/dnsmasq.d/malware.conf
head -n 20 /etc/dnsmasq.d/blacklist.conf
cat /etc/unbound/unbound.conf.d/forward.conf
cat /etc/unbound/unbound.conf.d/smartdns.conf
sudo rm -f /etc/dnsmasq.d/trust.conf
echo 'forward-zone:
    name: "."
    forward-addr: 8.8.8.8
    forward-addr: 1.1.1.1
' | sudo tee /etc/unbound/unbound.conf.d/forward.conf
sudo truncate -s 0 /etc/dnsmasq.d/malware.conf
sudo truncate -s 0 /etc/dnsmasq.d/malware_test.conf
sudo sed -i 's/^alias=/#alias=/' /etc/dnsmasq.d/smartdns.conf
sudo systemctl restart dnsmasq && sudo systemctl restart unbound
# Verify
ls -l /etc/dnsmasq.d/trust.conf
cat /etc/unbound/unbound.conf.d/forward.conf
grep "alias=" /etc/dnsmasq.d/smartdns.conf
TRUST_IP="103.68.213.213"
echo "server=$TRUST_IP" | sudo tee /etc/dnsmasq.d/trust.conf
echo "forward-zone:
    name: \".\"
    forward-addr: $TRUST_IP
" | sudo tee /etc/unbound/unbound.conf.d/forward.conf
sudo sed -i 's/^#alias=/alias=/' /etc/dnsmasq.d/smartdns.conf
sudo systemctl restart dnsmasq && sudo systemctl restart unbound
# Verify
ls -l /etc/dnsmasq.d/trust.conf
cat /etc/dnsmasq.d/trust.conf
cat /etc/unbound/unbound.conf.d/forward.conf
grep "alias=" /etc/dnsmasq.d/smartdns.conf
sudo systemctl stop dnsmasq
curl -k -X POST https://127.0.0.1:5000/api/login -H "Content-Type: application/json" -d '{"password":"admin"}' -c /tmp/cookie.txt
curl -k -X POST https://127.0.0.1:5000/api/action -H "Content-Type: application/json" -b /tmp/cookie.txt -d '{"type":"restart_dnsmasq"}'
systemctl is-active dnsmasq
# Test Restart Unbound
sudo systemctl stop unbound
curl -k -X POST https://127.0.0.1:5000/api/action -H "Content-Type: application/json" -b /tmp/cookie.txt -d '{"type":"restart_unbound"}'
systemctl is-active unbound
grep -A 5 "cmd_type == 'malware_shield'" /home/dns/web_gui/app.py
# Verifikasi keberadaan script firewall
ls -l /home/dns/setup_firewall.sh
ip a 
ls /etc/netplan
sudo nano /etc/netplan/00-installer-config.yaml
sudo netplan apply
sudo nano /etc/netplan/00-installer-config.yaml
clear
ip a
sudo nano /etc/netplan/00-installer-config.yaml
clear
sudo netplan apply
ip a
sudo nano /etc/netplan/00-installer-config.yaml
clear
sudo netplan apply
reboot
sleep 5
sudo ss -tulpn | grep :5001
sudo iptables -L -n -v | grep 5001
sleep 2
sudo ss -tulpn | grep :5000
dig @180.131.144.144 reddit.com +short
echo "server=1.1.1.3" | sudo tee /etc/dnsmasq.d/trust.conf
echo -e "forward-zone:\n    name: \".\"\n    forward-addr: 1.1.1.3" | sudo tee /etc/unbound/unbound.conf.d/forward.conf
sudo systemctl restart dnsmasq unbound
sleep 2
dig @127.0.0.1 -p 53 pornhub.com +short
grep "103.68.213.74" /etc/unbound/unbound.conf.d/smartdns.conf
ls -l /etc/dnsmasq.d/
sudo tail -n 100 /var/log/syslog | grep -i "5000"
sudo ss -tnp | grep :5000
sudo iptables -L INPUT -n -v --line-numbers
sudo ss -tnp | grep :22
cat /etc/netplan/00-installer-config.yaml
dig @127.0.0.1 -p 53 google.com
dig @180.131.145.145 google.com +short
ping 8.8.8.8
cleart
clear
ip a
ping 8.8.8.8
ip a
ping 8.8.8.8
clear
ls /etc/netplan
sudo nano /etc/netplan/00-installer-config.yaml
clear
sudo netplan apply
reboot
sudo systemctl daemon-reload
sudo systemctl enable dnsmars-gui
sudo systemctl start dnsmars-gui
sudo systemctl status dnsmars-gui --no-pager
clear
ip ad
sudo nano /etc/netplan/00-installer-config.yaml
clear
sudo netplan apply
reboot
clear
ping 8.8.8.8
ip a
ping 8.8.8.8
reboot
sudo rm /etc/unbound/unbound.conf.d/smartdns.conf
sudo mv /home/dns/unbound_smartdns.conf /etc/unbound/unbound.conf.d/smartdns.conf
sudo ln -s /etc/unbound/unbound.conf.d/smartdns.conf /home/dns/unbound_smartdns.conf
sudo chown root:root /etc/unbound/unbound.conf.d/smartdns.conf
sudo chmod 644 /etc/unbound/unbound.conf.d/smartdns.conf
# Do the same for dnsmasq if it's missing or misconfigured
sudo rm -f /etc/dnsmasq.d/dnsmasq_smartdns.conf
sudo mv /home/dns/dnsmasq_smartdns.conf /etc/dnsmasq.d/dnsmasq_smartdns.conf
sudo ln -s /etc/dnsmasq.d/dnsmasq_smartdns.conf /home/dns/dnsmasq_smartdns.conf
sudo chown root:root /etc/dnsmasq.d/dnsmasq_smartdns.conf
sudo chmod 644 /etc/dnsmasq.d/dnsmasq_smartdns.conf
# Restart services
sudo systemctl restart unbound
sudo systemctl restart dnsmasq
systemctl status unbound dnsmasq
sudo cp /home/dns/nginx_default.conf /etc/nginx/sites-available/default
sudo systemctl restart nginx
rm /home/dns/nginx_default.conf
#!/bin/bash
# Reset rules (Hati-hati: Pastikan port SSH 22 tetap terbuka)
# Kita tidak akan flush semua jika ingin aman, tapi kita tambahkan rule di atas.
echo "Setting up Anti-DDoS and DNS Flood Protection..."
# 1. Port yang diizinkan dengan ACL (SSH & Web GUI)
# Ambil IP server secara otomatis atau dari argumen
if [ ! -z "$1" ]; then     SERVER_IP=$1; else
    SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || ip -4 addr show | grep inet | grep -v '127.0.0.1' | head -n1 | awk '{print $2}' | cut -d/ -f1); fi
echo "Using Server IP: $SERVER_IP"
# Load Whitelist from file
WHITELIST_FILE="/home/dns/whitelist.conf"
ALLOWED_IPS=("$SERVER_IP" "127.0.0.1")
# Allow SSH and Web GUI (Port 5000) for trusted IPs
for ip in "${ALLOWED_IPS[@]}"; do     if [ ! -z "$ip" ]; then         iptables -A INPUT -s "$ip" -p tcp --dport 22 -j ACCEPT;         iptables -A INPUT -s "$ip" -p tcp --dport 5000 -j ACCEPT;     fi; done
# Allow SSH and Web GUI for trusted Subnets
for subnet in "${ALLOWED_SUBNETS[@]}"; do     iptables -A INPUT -s "$subnet" -p tcp --dport 22 -j ACCEPT;     iptables -A INPUT -s "$subnet" -p tcp --dport 5000 -j ACCEPT; done
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
# 3. Proteksi DNS TCP Flood (Conn Limit: 10 connections per source IP)
iptables -A INPUT -p tcp --dport 53 -m connlimit --connlimit-above 10 -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
# 4. Proteksi ICMP Flood (Ping Flood)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp -j DROP
# --- DNS TRUST CHECK ---
TRUST_CONF="/etc/dnsmasq.d/trust.conf"
if [ -f "$TRUST_CONF" ] && grep -q "^server=" "$TRUST_CONF"; then     DNS_TRUST_ENABLED=true;     echo "DNS Trust is ENABLED. Applying block rules."; else     DNS_TRUST_ENABLED=false;     echo "DNS Trust is DISABLED. Skipping block rules."; fi
# 5. NAT Interception (Agresif: Menangkap semua trafik DNS dan HTTP luar ke server lokal)
iptables -t nat -F PREROUTING
if [ "$DNS_TRUST_ENABLED" = true ]; then
    iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A PREROUTING -p tcp --dport 80 ! -d $SERVER_IP -j REDIRECT --to-ports 80;     iptables -t nat -A PREROUTING -p tcp --dport 443 ! -d $SERVER_IP -j REDIRECT --to-ports 443; fi
# 6. Restore Persistent Blocks from Guardian
if [ "$DNS_TRUST_ENABLED" = true ]; then     BANNED_IPS_FILE="/home/dns/banned_ips.txt";     if [ -f "$BANNED_IPS_FILE" ]; then         echo "Restoring persistent blocks from $BANNED_IPS_FILE...";         while IFS= read -r ip || [ -n "$ip" ]; do             if [ ! -z "$ip" ]; then                 iptables -I INPUT -s "$ip" -j DROP;             fi;         done < "$BANNED_IPS_FILE";     fi; fi
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
wget -O /home/dns/assets/int_pos.png "https://upload.wikimedia.org/wikipedia/id/thumb/1/12/Internet_Positif.png/300px-Internet_Positif.png" || curl -o /home/dns/assets/int_pos.png "https://upload.wikimedia.org/wikipedia/id/thumb/1/12/Internet_Positif.png/300px-Internet_Positif.png"
curl -4 -L -o /home/dns/assets/komdigi.png "https://www.biznetnetworks.com/static/assets/img/logo-kominfo.png" || true
curl -4 -L -o /home/dns/assets/int_pos.png "https://www.biznetnetworks.com/static/assets/img/internet-positif.png" || true
ls -l /home/dns/assets/
curl -4 -L -H "User-Agent: Mozilla/5.0" -o /home/dns/assets/int_pos.png "https://upload.wikimedia.org/wikipedia/id/1/12/Internet_Positif.png"
file /home/dns/assets/*.png
curl -4 -L -H "User-Agent: Mozilla/5.0" -o /home/dns/assets/int_pos.png "https://upload.wikimedia.org/wikipedia/id/thumb/1/12/Internet_Positif.png/300px-Internet_Positif.png"
file /home/dns/assets/*.jpg /home/dns/assets/*.png
file /home/dns/assets/komdigi.png
file /home/dns/assets/komdigi.png
file /home/dns/assets/komdigi.png
python3 /home/dns/update_logos.py
curl -L -o int_pos.png "https://upload.wikimedia.org/wikipedia/commons/thumb/2/25/Internet_Positif.png/320px-Internet_Positif.png"
ls -lh komdigi.png int_pos.png
curl -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" -o komdigi.png "https://seeklogo.com/images/K/komdigi-logo-0D7A9E5B6E-seeklogo.com.png"
curl -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" -o int_pos.png "https://trustpositive.kominfo.go.id/img/logo.png"
ls -lh komdigi.png int_pos.png
ls -lh int_pos.png
python3 -c "import base64; print('INT_POS_B64=' + base64.b64encode(open('int_pos.png', 'rb').read()).decode('utf-8'))" >> logos_b64.txt
head -c 100 logos_b64.txt
cat logos_b64.txt | grep INT_POS_B64 | cut -d'=' -f2 > int_pos_only.txt
curl -L -A "Mozilla/5.0" -o int_pos.png "https://png.pngitem.com/pimgs/s/525-5250462_internet-positif-logo-hd-png-download.png"
python3 -c "import base64; print(base64.b64encode(open('komdigi.png', 'rb').read()).decode('utf-8'))" > komdigi_only.txt
python3 -c "import base64; print(base64.b64encode(open('int_pos.png', 'rb').read()).decode('utf-8'))" > int_pos_only.txt
ls -lh komdigi.png int_pos.png
cp "/home/dns/.trae-server/bin/stable-91f22ddb51011710299a69e1fd5594a71b47fabf-debian10/c:\Users\solik\AppData\Roaming\Trae\User\workspaceStorage\5cc6d43dba705ec8a6447db0f2b1dbef\images/tos-alisg-i-84wi3idyod-sg%2Fi18n%2F7598448573274178567%2Fimage%2F1770492977368_i0d5bw9rv20_png_457x170.png" /home/dns/new_logos/int_pos_user.png
ls -lh /home/dns/new_logos/int_pos_user.png
cp "/home/dns/.trae-server/bin/stable-91f22ddb51011710299a69e1fd5594a71b47fabf-debian10/c:\Users\solik\AppData\Roaming\Trae\User\workspaceStorage/5cc6d43dba705ec8a6447db0f2b1dbef/images/tos-alisg-i-84wi3idyod-sg%2Fi18n%2F7598448573274178567%2Fimage%2F1770492320067_yj3gqnm5lja0_png_332x281.png" /home/dns/assets/new/img1.png
cp "/home/dns/.trae-server/bin/stable-91f22ddb51011710299a69e1fd5594a71b47fabf-debian10/c:\Users\solik\AppData\Roaming\Trae\User\workspaceStorage/5cc6d43dba705ec8a6447db0f2b1dbef/images/tos-alisg-i-84wi3idyod-sg%2Fi18n%2F7598448573274178567%2Fimage%2F1770492977368_i0d5bw9rv20_png_457x170.png" /home/dns/assets/new/img2.png
cp "/home/dns/.trae-server/bin/stable-91f22ddb51011710299a69e1fd5594a71b47fabf-debian10/c:\Users\solik\AppData\Roaming\Trae\User\workspaceStorage/5cc6d43dba705ec8a6447db0f2b1dbef/images/tos-alisg-i-84wi3idyod-sg%2Fi18n%2F7598448573274178567%2Fimage%2F1770492344769_w23l1mmkdm0_png_325x119.png" /home/dns/assets/new/img3.png
base64 -w 0 /home/dns/assets/new/img2.png > int_pos_only.txt
sudo cp /home/dns/blocked_final.html /var/www/html/blocked.html
strings /home/dns/assets/new/img2.png | head -n 20
strings /home/dns/assets/new/img3.png | head -n 20
base64 -w 0 /home/dns/assets/komdigi_new_user.png > komdigi_only.txt
sudo cp /home/dns/blocked_final.html /var/www/html/blocked.html
base64 -w 0 /home/dns/assets/company_logo.jpeg > company_logo_b64.txt
sudo cp /home/dns/blocked_final.html /var/www/html/blocked.html
sudo cp /home/dns/blocked_final.html /var/www/html/blocked.html
sudo cp /home/dns/blocked_final.html /var/www/html/blocked.html
cp /home/dns/*.py /home/dns/*.sh /home/dns/*.conf /home/dns/backup_github/ 2>/dev/null || true
cp /home/dns/banned_ips.txt /home/dns/backup_github/ 2>/dev/null || true
# Sync scripts dir
cp /home/dns/*.py /home/dns/*.sh /home/dns/backup_github/scripts/ 2>/dev/null || true
# Sync web_gui (excluding logs and pycache)
rsync -av --exclude='*.log' --exclude='__pycache__' /home/dns/web_gui/ /home/dns/backup_github/web_gui/
# Sync configs from /etc
cp /etc/dnsmasq.d/*.conf /home/dns/backup_github/configs/ 2>/dev/null || true
cp /etc/unbound/unbound.conf /home/dns/backup_github/configs/unbound.conf 2>/dev/null || true
cp /etc/unbound/unbound.conf.d/*.conf /home/dns/backup_github/configs/ 2>/dev/null || true
# Sync systemd files
cp /etc/systemd/system/guardian.service /home/dns/backup_github/systemd/ 2>/dev/null || true
cp /etc/systemd/system/dnsmars-gui.service /home/dns/backup_github/systemd/ 2>/dev/null || true
dig @127.0.0.1 poker.com AAAA +short
ls -l /home/dns/blocked_final.html
curl -I -k https://127.0.0.1/
