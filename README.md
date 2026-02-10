# 🚀 PT MARS DATA TELEKOMUNIKASI - DUAL STACK DNS ENGINE

Intelligent DNS Management System with Anti-DDoS, Malware Protection, and Self-Healing capabilities.

---

### 📖 Dokumentasi Lengkap
Silakan baca [PANDUAN_SISTEM.md](file:///home/dns/PANDUAN_SISTEM.md) untuk instruksi operasional detail.

---

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

## ⚡ Performance Specifications (Optimized)

### Unbound (Recursive DNS Resolver)
| Parameter | Value | Purpose |
|-----------|-------|---------|
| `num-threads` | **8** | Multi-threaded query processing |
| `ratelimit` | **50000 qps** | Global rate limit (anti-DDoS) |
| `ip-ratelimit` | **2000 qps** | Per-source IP limit (prevents localhost throttling) |
| `msg-cache-size` | **100MB** | DNS response message cache |
| `rrset-cache-size` | **100MB** | DNSSEC RRset cache |
| `cache-min-ttl` | **3600s** | Minimum cache retention |
| `cache-max-ttl` | **86400s** | Maximum cache retention |

### Dnsmasq (Local DNS Cache)
| Parameter | Value | Purpose |
|-----------|-------|---------|
| `cache-size` | **100000** | DNS cache entries (2x optimized) |
| `dns-forward-max` | **10000** | Maximum concurrent forwarded queries |
| `port` | **53** | Standard DNS port |
| `neg-ttl` | **60s** | Negative response caching |
| `proxy-dnssec` | **enabled** | DNSSEC validation passthrough |

### Estimated Capacity
- **Maximum QPS**: 2000+ queries per second
- **Cache Hit Rate**: ~70% for typical workloads (100k entries)
- **Concurrent Connections**: 10000+ simultaneous queries
- **Response Time**: <100ms average (cached), <500ms (recursive)

## 🔒 Security Notice

- Access to **SSH (Port 22)** and **Web GUI (Port 5000)** is strictly limited to whitelisted IPs.
- You can modify allowed IPs in `setup_firewall.sh` and `web_gui/app.py`.

## 📂 Project Structure

- `install.sh`: The master auto-installer script.
- `guardian.py`: The self-healing and attack detection engine.
- `web_gui/`: Flask-based management dashboard.
- `setup_firewall.sh`: Security and anti-DDoS configuration.
- `*.conf`: Optimized DNS configurations.

## 📚 References & Documentation

### Online Guides
- **Unbound DNS Documentation**: https://unbound.docs.nlnetlabs.nl/
  - [Performance Tuning Guide](https://unbound.docs.nlnetlabs.nl/en/latest/topics/core/performance.html)
  - [Configuration Reference](https://unbound.docs.nlnetlabs.nl/en/latest/getting-started/configuration.html)
  - [unbound.conf Manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- **Dnsmasq Manual**: http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html

### Local Documentation
- `PANDUAN_SISTEM.md` - Complete system administration guide (Indonesian)
- `PERFORMANCE_OPTIMIZATION_REPORT.md` - Detailed performance analysis

---
© 2026 PT MARS DATA TELEKOMUNIKASI
