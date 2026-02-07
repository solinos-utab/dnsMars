# 🚀 DNS Mars Data Telekomunikasi

Intelligent DNS Management System with Anti-DDoS, Malware Protection, and Self-Healing capabilities.

## 🛠️ Quick Installation (One-Liner)

If you have a fresh VM (Ubuntu/Debian) and want to restore or install the entire system, simply run:

```bash
git clone https://github.com/solinos-utab/dnsMars.git /home/dns && cd /home/dns && chmod +x install.sh && sudo ./install.sh
```

## ✨ Features

- **Smart DNS**: Hybrid `dnsmasq` and `unbound` for maximum speed and security.
- **WAF & Security**: Built-in Web Application Firewall and IP Whitelisting (ACL).
- **Anti-DDoS**: Advanced `iptables` rules for flood protection.
- **Malware Shield**: Automatic blocking of 100k+ malicious domains.
- **Intelligent Guardian**: Self-healing service that monitors and repairs DNS services automatically.
- **Modern Dashboard**: Glassmorphism UI for real-time traffic analysis and management.

## 🔒 Security Notice

- Access to **SSH (Port 22)** and **Web GUI (Port 5000)** is strictly limited to whitelisted IPs.
- You can modify allowed IPs in `setup_firewall.sh` and `web_gui/app.py`.

## 📂 Project Structure

- `install.sh`: The master auto-installer script.
- `guardian.py`: The self-healing and attack detection engine.
- `web_gui/`: Flask-based management dashboard.
- `setup_firewall.sh`: Security and anti-DDoS configuration.
- `*.conf`: Optimized DNS configurations.

---
© 2026 PT MARS DATA TELEKOMUNIKASI
