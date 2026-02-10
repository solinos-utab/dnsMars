# dnsMars - Intelligent DNS Guardian & Management System

This repository contains the source code for **dnsMars**, a high-performance, secure, and self-healing DNS system designed for ISP-scale environments.

## Features
- **Intelligent Guardian**: Self-healing service that monitors and repairs DNS services automatically.
- **Recursive Resolver**: Full recursive resolution using Unbound (no upstream dependencies like Google).
- **Ad & Malware Blocking**: High-performance blocking using Dnsmasq.
- **Internet Positif Compliance**: Toggleable filtering for local compliance.
- **Web Management GUI**: Easy-to-use web interface for monitoring and configuration.
- **DDoS Protection**: Integrated firewall and rate-limiting rules.

## Directory Structure
- `src/`: Source code for Guardian and Web GUI.
- `scripts/`: Shell scripts for installation, updates, and optimization.
- `config/`: Configuration files for Dnsmasq, Unbound, Netplan, and Systemd.
- `docs/`: Documentation and manuals.

## Quick Start
1.  Clone this repository.
2.  Run `scripts/install.sh` (if available) or setup manually using provided configs.
3.  Start the Guardian service: `systemctl start guardian`.

## Requirements
- Python 3
- Flask
- psutil
- Dnsmasq
- Unbound

## License
Private / Proprietary
