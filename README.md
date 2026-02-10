# dnsMars - Intelligent DNS Guardian & Management System

**dnsMars** is an enterprise-grade, high-performance, and secure DNS infrastructure designed for ISP and large-scale network environments. It combines the speed of **Dnsmasq** (frontend) with the security and reliability of **Unbound** (recursive backend), managed by a self-healing **Guardian** system.

---

## 🚀 Key Features

### 1. **Recursive & Independent Resolution**
- **No Upstream Dependencies**: Uses Unbound to resolve queries directly from Root Servers.
- **Privacy First**: No data leaked to Google (8.8.8.8) or Cloudflare.
- **QNAME Minimisation**: Enhanced privacy by minimizing data sent to authoritative servers.
- **DNSSEC Validated**: Ensures authenticity of DNS responses.

### 2. **Intelligent Guardian (Self-Healing)**
- **Auto-Repair**: Automatically detects and restarts services (Unbound/Dnsmasq) if they hang or crash.
- **Zero-Downtime Updates**: Manages configuration updates without disrupting service.
- **Dynamic IP Handling**: Automatically updates configs when server IP changes.

### 3. **Security & Compliance**
- **Internet Positif (Trust)**: Toggleable filtering for regulatory compliance (managed via Web GUI).
- **Malware & Ad Blocking**: Local sinkholing of malicious domains (0ms latency blocking).
- **DDoS Protection**: Integrated `iptables` rate-limiting and Unbound internal rate-limits (50k qps).
- **Anti-Leak**: Hardened configuration to prevent DNS leaks.

### 4. **High Performance**
- **Multi-Layer Caching**: Dnsmasq (Hot Cache) + Unbound (Deep Cache).
- **Serve-Expired**: Delivers expired cache immediately while refreshing in background (Instant Loading).
- **Prefetching**: Proactively refreshes popular domains before they expire.
- **Optimized Kernel**: Tuned `so-rcvbuf` and `so-sndbuf` for 10Gbps+ throughput.

### 5. **Web Management GUI**
- **Real-time Monitoring**: Visual dashboard for CPU, RAM, and DNS Latency.
- **One-Click Control**: Toggle Trust (Internet Positif), Restart Services, and Flush Cache.
- **Traffic Analysis**: View top blocked domains and query statistics.

---

## 📂 Directory Structure

```
dnsMars/
├── config/             # Production Configuration Files
│   ├── dnsmasq/        # Frontend Caching & Filtering Rules
│   ├── unbound/        # Recursive Backend Settings
│   ├── netplan/        # Network Interface Configs
│   └── systemd/        # Service Definitions (guardian.service)
├── src/                # Source Code
│   ├── guardian.py     # Main Self-Healing Logic
│   └── web_gui/        # Flask-based Web Interface
├── scripts/            # Automation Scripts
│   ├── backup_to_github.sh  # Auto-backup script
│   ├── setup_firewall.sh    # IPTables rules
│   └── update_blocklist.sh  # Blocklist updater
└── docs/               # Documentation & Manuals
```

## 🛠️ Installation & Setup

1.  **Clone Repository**:
    ```bash
    git clone https://github.com/solinos-utab/dnsMars.git /home/dns/dnsMars
    ```

2.  **Run Installer (Optional)**:
    ```bash
    cd dnsMars/scripts
    sudo ./install.sh
    ```

3.  **Manual Setup**:
    - Copy configs from `config/` to `/etc/`.
    - Enable services: `systemctl enable --now dnsmasq unbound guardian`.

## ⚙️ Usage

- **Web GUI**: Access via `https://<SERVER_IP>:5000/`
- **Manual Backup**: Run `scripts/backup_to_github.sh`

## 🔒 Security Notes
- **Firewall**: Port 53 (UDP/TCP) is rate-limited to prevent abuse.
- **Web GUI**: Protected via Login (Session-based).
- **Git**: Token stored securely in `~/.git-credentials`.

---
*Proprietary Software - For Internal Use Only*
