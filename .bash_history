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
