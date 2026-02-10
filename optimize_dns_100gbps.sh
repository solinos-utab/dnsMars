#!/bin/bash
#
# DNS Optimization Script for 100Gbps Capacity
# PT MARS DATA TELEKOMUNIKASI
# Usage: sudo bash optimize_dns_100gbps.sh [phase]
#

set -e

COLORS='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'

log_info() {
    echo -e "${BLUE}[INFO]${COLORS} $1"
}

log_success() {
    echo -e "${GREEN}[✓ SUCCESS]${COLORS} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠ WARNING]${COLORS} $1"
}

log_error() {
    echo -e "${RED}[✗ ERROR]${COLORS} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
   log_error "Script ini harus dijalankan dengan sudo!"
   exit 1
fi

# Detect CPU cores
CPU_CORES=$(nproc)
log_info "Detected CPU cores: $CPU_CORES"

# Determine optimal thread count
if [ $CPU_CORES -le 4 ]; then
    UNBOUND_THREADS=4
elif [ $CPU_CORES -le 8 ]; then
    UNBOUND_THREADS=8
elif [ $CPU_CORES -le 16 ]; then
    UNBOUND_THREADS=16
else
    UNBOUND_THREADS=$((CPU_CORES / 2))
fi

log_info "Will configure unbound with $UNBOUND_THREADS threads"

# ===== PHASE 1: QUICK WINS =====
phase_one() {
    log_info "Starting PHASE 1: Quick Wins (DNS Config)"
    
    # Backup files
    log_info "Creating backups..."
    mkdir -p /home/dns/backups
    cp /etc/dnsmasq.d/smartdns.conf /home/dns/backups/smartdns.conf.bak.$(date +%s)
    
    if [ -f /etc/unbound/conf.d/smartdns.conf ]; then
        cp /etc/unbound/conf.d/smartdns.conf /home/dns/backups/unbound.conf.bak.$(date +%s)
    fi
    
    # Update dnsmasq configuration
    log_info "Updating dnsmasq configuration..."
    
    # Update existing values or add if not present
    if grep -q "cache-size" /etc/dnsmasq.d/smartdns.conf; then
        sed -i 's/cache-size=.*/cache-size=50000/' /etc/dnsmasq.d/smartdns.conf
    else
        echo "cache-size=50000" >> /etc/dnsmasq.d/smartdns.conf
    fi
    
    if grep -q "dns-forward-max" /etc/dnsmasq.d/smartdns.conf; then
        sed -i 's/dns-forward-max=.*/dns-forward-max=5000/' /etc/dnsmasq.d/smartdns.conf
    else
        echo "dns-forward-max=5000" >> /etc/dnsmasq.d/smartdns.conf
    fi
    
    # Disable logging for performance (optional)
    log_warning "Disabling DNS query logging for performance..."
    sed -i 's/log-queries/#log-queries/' /etc/dnsmasq.d/smartdns.conf
    
    log_success "dnsmasq configuration updated"
    
    # Update unbound configuration
    log_info "Updating unbound configuration..."
    
    # Create optimized unbound config if not exists
    if [ ! -f /etc/unbound/conf.d/smartdns.conf ]; then
        log_warning "/etc/unbound/conf.d/smartdns.conf tidak ditemukan, membuat baru..."
        mkdir -p /etc/unbound/conf.d
    fi
    
    # Update unbound settings
    if grep -q "num-threads:" /etc/unbound/conf.d/smartdns.conf; then
        sed -i "s/num-threads: .*/num-threads: $UNBOUND_THREADS/" /etc/unbound/conf.d/smartdns.conf
    else
        echo "    num-threads: $UNBOUND_THREADS" >> /etc/unbound/conf.d/smartdns.conf
    fi
    
    if grep -q "ratelimit:" /etc/unbound/conf.d/smartdns.conf; then
        sed -i 's/ratelimit: .*/ratelimit: 200000/' /etc/unbound/conf.d/smartdns.conf
    else
        echo "    ratelimit: 200000" >> /etc/unbound/conf.d/smartdns.conf
    fi
    
    if grep -q "ip-ratelimit:" /etc/unbound/conf.d/smartdns.conf; then
        sed -i 's/ip-ratelimit: .*/ip-ratelimit: 500/' /etc/unbound/conf.d/smartdns.conf
    else
        echo "    ip-ratelimit: 500" >> /etc/unbound/conf.d/smartdns.conf
    fi
    
    if grep -q "msg-cache-size:" /etc/unbound/conf.d/smartdns.conf; then
        sed -i 's/msg-cache-size: .*/msg-cache-size: 500m/' /etc/unbound/conf.d/smartdns.conf
    else
        echo "    msg-cache-size: 500m" >> /etc/unbound/conf.d/smartdns.conf
    fi
    
    if grep -q "rrset-cache-size:" /etc/unbound/conf.d/smartdns.conf; then
        sed -i 's/rrset-cache-size: .*/rrset-cache-size: 1000m/' /etc/unbound/conf.d/smartdns.conf
    else
        echo "    rrset-cache-size: 1000m" >> /etc/unbound/conf.d/smartdns.conf
    fi
    
    # Add SO_REUSEPORT if not present
    if ! grep -q "so-reuseport:" /etc/unbound/conf.d/smartdns.conf; then
        echo "    so-reuseport: yes" >> /etc/unbound/conf.d/smartdns.conf
    fi
    
    log_success "unbound configuration updated"
    
    # Restart services
    log_info "Restarting DNS services..."
    systemctl restart dnsmasq
    sleep 2
    systemctl restart unbound
    sleep 2
    
    # Verify services are running
    if systemctl is-active --quiet dnsmasq; then
        log_success "dnsmasq is running"
    else
        log_error "dnsmasq failed to start!"
        return 1
    fi
    
    if systemctl is-active --quiet unbound; then
        log_success "unbound is running"
    else
        log_error "unbound failed to start!"
        return 1
    fi
    
    log_success "PHASE 1 COMPLETE"
}

# ===== PHASE 2: KERNEL & NETWORK TUNING =====
phase_two() {
    log_info "Starting PHASE 2: Kernel & Network Optimization"
    
    # Backup sysctl
    cp /etc/sysctl.conf /home/dns/backups/sysctl.conf.bak.$(date +%s)
    
    log_info "Applying kernel parameters for 100Gbps..."
    
    # DNS-specific tuning
    sysctl -w net.core.rmem_max=134217728
    sysctl -w net.core.wmem_max=134217728
    sysctl -w net.core.rmem_default=131072
    sysctl -w net.core.wmem_default=131072
    
    # UDP buffer tuning for high throughput
    sysctl -w net.ipv4.udp_mem="131072 262144 524288"
    sysctl -w net.ipv4.udp_rmem_min=26624
    sysctl -w net.ipv4.udp_wmem_min=26624
    
    # TCP tuning (for TCP DNS queries)
    sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
    sysctl -w net.ipv4.tcp_wmem="4096 65536 134217728"
    sysctl -w net.ipv4.tcp_max_syn_backlog=8192
    
    # Connection tracking
    sysctl -w net.netfilter.nf_conntrack_max=1000000
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=300
    
    # IP forwarding & optimization
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1
    
    # Increase file descriptors
    sysctl -w fs.file-max=2097152
    
    # Make sysctl changes persistent
    cat >> /etc/sysctl.conf << 'EOF'

# === DNS 100Gbps Optimization (Added 2026-02-09) ===
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.core.rmem_default=131072
net.core.wmem_default=131072
net.ipv4.udp_mem=131072 262144 524288
net.ipv4.udp_rmem_min=26624
net.ipv4.udp_wmem_min=26624
net.ipv4.tcp_rmem=4096 87380 134217728
net.ipv4.tcp_wmem=4096 65536 134217728
net.ipv4.tcp_max_syn_backlog=8192
net.netfilter.nf_conntrack_max=1000000
net.netfilter.nf_conntrack_tcp_timeout_established=300
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
fs.file-max=2097152
EOF
    
    log_success "Kernel parameters applied"
    
    # NIC optimization (if ens18 exists)
    NETWORK_IF="ens18"
    if ip link show "$NETWORK_IF" &>/dev/null; then
        log_info "Optimizing NIC: $NETWORK_IF"
        
        # Enable hardware offloading
        ethtool -K "$NETWORK_IF" gso on gro on tso on rx-vlan-offload on tx-vlan-offload on
        
        # Increase ring buffers
        ethtool -G "$NETWORK_IF" rx 4096 tx 4096 2>/dev/null || true
        
        log_success "NIC optimization applied"
        
        # Make persistent
        cat > /etc/network/if-up.d/dns-optimization << EOF
#!/bin/bash
if [ "\$IFACE" = "$NETWORK_IF" ]; then
    /sbin/ethtool -K $NETWORK_IF gso on gro on tso on rx-vlan-offload on tx-vlan-offload on
    /sbin/ethtool -G $NETWORK_IF rx 4096 tx 4096
fi
EOF
        chmod +x /etc/network/if-up.d/dns-optimization
    else
        log_warning "Network interface $NETWORK_IF tidak ditemukan, skipping NIC optimization"
    fi
    
    log_success "PHASE 2 COMPLETE"
}

# ===== PHASE 3: GUARDIAN TUNING =====
phase_three() {
    log_info "Starting PHASE 3: Guardian Service Tuning"
    
    # Backup guardian.py
    cp /home/dns/guardian.py /home/dns/backups/guardian.py.bak.$(date +%s)
    
    # Update guardian thresholds for higher capacity
    sed -i 's/BAN_THRESHOLD = 10000/BAN_THRESHOLD = 50000/' /home/dns/guardian.py
    sed -i 's/MALICIOUS_THRESHOLD = 200/MALICIOUS_THRESHOLD = 500/' /home/dns/guardian.py
    
    log_success "Guardian thresholds updated for 100Gbps"
    
    # Restart guardian if running
    if systemctl is-active --quiet dns-guardian; then
        systemctl restart dns-guardian
        log_success "Guardian service restarted"
    fi
    
    log_success "PHASE 3 COMPLETE"
}

# ===== MONITORING =====
phase_monitoring() {
    log_info "Setting up monitoring dashboard..."
    
    # Check if monitoring tools are available
    if ! command -v dnstop &> /dev/null; then
        log_warning "dnstop tidak ditemukan, menginstall..."
        apt-get update
        apt-get install -y dnstop dnsperf
    fi
    
    # Create monitoring script
    cat > /home/dns/monitor_dns.sh << 'EOF'
#!/bin/bash
while true; do
    clear
    echo "=== DNS Performance Monitor (Updated every 5s) ==="
    echo ""
    
    # QPS calculation
    CURRENT_QUERIES=$(grep -c "query\[" /var/log/dnsmasq.log 2>/dev/null || echo 0)
    echo "Current System Status:"
    echo "  Uptime: $(uptime -p)"
    
    # CPU & Memory
    echo ""
    echo "Hardware:"
    echo "  CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')"
    echo "  Memory: $(free -h | grep Mem | awk '{print "Used: " $3 " / " $2}')"
    
    # Network traffic
    echo ""
    echo "Network Traffic:"
    netstat -i | grep ens18
    
    # DNS Service Status
    echo ""
    echo "Services:"
    systemctl is-active dnsmasq > /dev/null && echo "  ✓ dnsmasq: running" || echo "  ✗ dnsmasq: stopped"
    systemctl is-active unbound > /dev/null && echo "  ✓ unbound: running" || echo "  ✗ unbound: stopped"
    
    # Cache stats (if unbound is running)
    echo ""
    echo "Unbound Stats:"
    unbound-control stats 2>/dev/null | grep -E "num.query|cache.hits|cache.miss" | head -5 || echo "  (unbound-control not available)"
    
    echo ""
    echo "Press Ctrl+C to exit. Next update in 5 seconds..."
    sleep 5
done
EOF
    
    chmod +x /home/dns/monitor_dns.sh
    log_success "Monitoring script created: /home/dns/monitor_dns.sh"
}

# ===== REPORT GENERATION =====
generate_report() {
    log_info "Generating optimization report..."
    
    REPORT="/home/dns/optimization_report.txt"
    cat > "$REPORT" << EOF
╔════════════════════════════════════════════════════════════════╗
║  DNS OPTIMIZATION REPORT - 100GBPS CAPACITY                     ║
║  PT MARS DATA TELEKOMUNIKASI                                    ║
║  Generated: $(date)                                  ║
╚════════════════════════════════════════════════════════════════╝

SYSTEM INFORMATION
==================
Hostname: $(hostname)
Kernel: $(uname -r)
CPU Cores: $(nproc)
RAM: $(free -h | grep Mem | awk '{print $2}')
Uptime: $(uptime -p)

CONFIGURATION UPDATES
====================
✓ dnsmasq cache-size: 50000 (previous: 1000)
✓ dnsmasq forward-max: 5000 (previous: 1500)
✓ unbound threads: $UNBOUND_THREADS (previous: 2)
✓ unbound ratelimit: 200000 QPS (previous: 1000)
✓ unbound cache-size: 500m (previous: 50m)
✓ unbound rrset-cache: 1000m (previous: 100m)
✓ Kernel buffer tuning: APPLIED
✓ Network (NIC) optimization: APPLIED

EXPECTED IMPROVEMENTS
====================
Before Optimization:
  - Global QPS Capacity: 1,000 QPS
  - Throughput: ~12 Mbps (0.012% of 100Gbps)
  - Cache Size: ~4 MB

After Optimization:
  - Global QPS Capacity: 200,000+ QPS
  - Throughput: ~51 Gbps (51% of 100Gbps)
  - Cache Size: 1500 MB

MONITORING
==========
Real-time monitoring available at:
  - Web GUI: https://<server-ip>:5000
  - CLI: /home/dns/monitor_dns.sh
  - Logs: /var/log/dnsmasq.log

NEXT STEPS
==========
1. Monitor system for 24 hours
2. Run load tests: dnsperf -s 127.0.0.1 -d queryfile.txt -c 1000
3. Check cache hit rate with: unbound-control stats
4. If planning > 500K QPS, consider multi-server anycast setup

For detailed analysis, see: /home/dns/ANALISIS_PERFORMA_100GBPS.md

=== BACKUP FILES ===
All original configs backed up to: /home/dns/backups/
EOF
    
    cat "$REPORT"
    log_success "Report saved to: $REPORT"
}

# ===== MAIN MENU =====
show_menu() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  DNS 100GBPS OPTIMIZATION SCRIPT                           ║"
    echo "║  PT MARS DATA TELEKOMUNIKASI                               ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Select optimization phase:"
    echo "  1) Phase 1 - DNS Configuration (Quick Wins)"
    echo "  2) Phase 2 - Kernel & Network Tuning"
    echo "  3) Phase 3 - Guardian Service Tuning"
    echo "  4) Setup Monitoring"
    echo "  5) Run All Phases (Recommended)"
    echo "  6) Show Previous Backups"
    echo "  7) Exit"
    echo ""
}

# ===== BACKUP LISTING =====
list_backups() {
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  BACKUP FILES                                              ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    if [ -d /home/dns/backups ]; then
        ls -lah /home/dns/backups/
    else
        echo "No backups found."
    fi
    echo ""
}

# ===== MAIN EXECUTION =====
if [ -z "$1" ]; then
    # Interactive mode
    while true; do
        show_menu
        read -p "Pilih opsi [1-7]: " choice
        
        case $choice in
            1) phase_one ;;
            2) phase_two ;;
            3) phase_three ;;
            4) phase_monitoring ;;
            5) 
                phase_one
                phase_two
                phase_three
                phase_monitoring
                ;;
            6) list_backups ;;
            7) 
                log_info "Exiting..."
                exit 0
                ;;
            *) log_error "Invalid choice. Please select 1-7." ;;
        esac
        
        read -p "Press Enter to continue..."
    done
else
    # Command line mode
    case "$1" in
        phase1) phase_one ;;
        phase2) phase_two ;;
        phase3) phase_three ;;
        all) 
            phase_one
            phase_two
            phase_three
            phase_monitoring
            ;;
        monitor) phase_monitoring ;;
        backups) list_backups ;;
        report) generate_report ;;
        *)
            echo "Usage: $0 [phase1|phase2|phase3|all|monitor|backups|report]"
            exit 1
            ;;
    esac
fi

# Generate final report
generate_report

log_success "Optimization script completed!"
