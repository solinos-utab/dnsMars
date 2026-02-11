import os
import time
import subprocess
import re
import sqlite3
from datetime import datetime

import json

# --- CONFIGURATION ---
LOG_FILE = "/var/log/syslog"
DNSMASQ_LOG = "/var/log/dnsmasq.log"
NGINX_LOG = "/var/log/nginx/access.log"
CONFIG_FILE = "/home/dns/guardian_config.json"

# Default values
DEFAULT_BAN_THRESHOLD = 10000
DEFAULT_MALICIOUS_THRESHOLD = 200
DISK_CRITICAL_THRESHOLD = 90  # Percent
MEM_CRITICAL_THRESHOLD = 90   # Percent
SWAP_CRITICAL_THRESHOLD = 60  # Percent
CPU_CRITICAL_THRESHOLD = 95   # Percent

def load_config():
    config = {
        "ban_threshold": DEFAULT_BAN_THRESHOLD,
        "malicious_threshold": DEFAULT_MALICIOUS_THRESHOLD,
        "disk_threshold": DISK_CRITICAL_THRESHOLD,
        "mem_threshold": MEM_CRITICAL_THRESHOLD,
        "swap_threshold": SWAP_CRITICAL_THRESHOLD
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                loaded = json.load(f)
                config.update(loaded)
        except Exception as e:
            print(f"Error loading config: {e}")
    return config

# Load initial config
config = load_config()
BAN_THRESHOLD = config["ban_threshold"]
MALICIOUS_THRESHOLD = config["malicious_threshold"]
DISK_THRESHOLD = config.get("disk_threshold", DISK_CRITICAL_THRESHOLD)
MEM_THRESHOLD = config.get("mem_threshold", MEM_CRITICAL_THRESHOLD)
SWAP_THRESHOLD = config.get("swap_threshold", SWAP_CRITICAL_THRESHOLD)

WHITELIST_FILE = "/home/dns/whitelist.conf"
GUARDIAN_LOG = "/home/dns/guardian.log"
BANNED_IPS_FILE = "/home/dns/banned_ips.txt"

def load_whitelist():
    wl = ["127.0.0.1"]
    subnets = []
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '/' in line:
                        subnets.append(line)
                    else:
                        wl.append(line)
        except Exception as e:
            print(f"Error loading whitelist: {e}")
    return wl, subnets

# Global variables
WHITELIST, WHITELIST_SUBNETS = load_whitelist()
LAST_WL_RELOAD = time.time()

def reload_whitelist_if_needed():
    global WHITELIST, WHITELIST_SUBNETS, LAST_WL_RELOAD, BAN_THRESHOLD, MALICIOUS_THRESHOLD
    # Reload every 60 seconds
    if time.time() - LAST_WL_RELOAD > 60:
        WHITELIST, WHITELIST_SUBNETS = load_whitelist()
        
        # Reload config
        config = load_config()
        BAN_THRESHOLD = config["ban_threshold"]
        MALICIOUS_THRESHOLD = config["malicious_threshold"]
        DISK_THRESHOLD = config.get("disk_threshold", DISK_CRITICAL_THRESHOLD)
        MEM_THRESHOLD = config.get("mem_threshold", MEM_CRITICAL_THRESHOLD)
        SWAP_THRESHOLD = config.get("swap_threshold", SWAP_CRITICAL_THRESHOLD)
        
        LAST_WL_RELOAD = time.time()
        # Clean up banned_ips.txt if needed
        clean_banned_ips()

def clean_banned_ips():
    if not os.path.exists(BANNED_IPS_FILE):
        return
    
    try:
        with open(BANNED_IPS_FILE, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        
        valid_ips = []
        changed = False
        for ip in ips:
            if is_whitelisted(ip):
                log_event(f"Removing whitelisted IP from banned list: {ip}")
                # Remove from iptables too
                run_cmd(f"sudo iptables -D INPUT -s {ip} -j DROP")
                changed = True
            else:
                valid_ips.append(ip)
        
        if changed:
            # Write back unique valid IPs
            unique_ips = list(set(valid_ips))
            with open(BANNED_IPS_FILE, 'w') as f:
                for ip in unique_ips:
                    f.write(f"{ip}\n")
    except Exception as e:
        log_event(f"Error cleaning banned IPs: {e}")

def is_whitelisted(ip):
    if ip in WHITELIST:
        return True
    
    # Check subnets
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        for subnet in WHITELIST_SUBNETS:
            if ip_obj in ipaddress.ip_network(subnet):
                return True
    except Exception:
        # Fallback if ipaddress is not available or ip is invalid
        for subnet in WHITELIST_SUBNETS:
            base_subnet = subnet.split('/')[0].rsplit('.', 1)[0]
            if ip.startswith(base_subnet):
                return True
    return False

def get_current_ip():
    try:
        # Try default route interface first (most accurate)
        cmd = "ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+'"
        res = run_cmd(cmd)
        if res and res.stdout.strip():
            return res.stdout.strip()

        # Fallback to looking for the first non-loopback IPv4 address
        cmd = "ip -4 addr show | grep inet | grep -v '127.0.0.1' | head -n1 | awk '{print $2}' | cut -d/ -f1"
        res = run_cmd(cmd)
        if res and res.stdout.strip():
            return res.stdout.strip()
    except:
        pass
    return "127.0.0.1"

def get_current_ipv6():
    try:
        # Get first global IPv6
        cmd = "ip -6 addr show | grep -v 'fe80' | grep -v '::1' | grep 'inet6' | awk '{print $2}' | cut -d/ -f1 | head -n1"
        res = run_cmd(cmd)
        if res and res.stdout.strip():
            return res.stdout.strip()
    except:
        pass
    return None

# Global variables
WHITELIST, WHITELIST_SUBNETS = load_whitelist()
LAST_WL_RELOAD = time.time()
LAST_IP_V4 = get_current_ip()
LAST_IP_V6 = get_current_ipv6()
server_ip = LAST_IP_V4

# Auto-update whitelist with current server IPs
if LAST_IP_V4 not in WHITELIST:
    WHITELIST.append(LAST_IP_V4)
if LAST_IP_V6 and LAST_IP_V6 not in WHITELIST:
    WHITELIST.append(LAST_IP_V6)

# --- SCHEDULE STATE TRACKING ---
TRUST_CONF = "/etc/dnsmasq.d/upstream.conf"
LAST_SCHEDULE_STATE = None  # Track last schedule state to detect changes

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}\n"
    with open(GUARDIAN_LOG, "a") as f:
        f.write(formatted_msg)
    print(formatted_msg.strip())

def run_cmd(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True)
    except Exception as e:
        return None

def block_ip(ip):
    # Always reload/check before blocking to be sure
    global WHITELIST, WHITELIST_SUBNETS
    WHITELIST, WHITELIST_SUBNETS = load_whitelist()
    
    if is_whitelisted(ip):
        log_event(f"SKIP BLOCKING whitelisted IP: {ip}")
        return
    
    # Check if already blocked to avoid duplicates
    if os.path.exists(BANNED_IPS_FILE):
        with open(BANNED_IPS_FILE, 'r') as f:
            if ip in f.read():
                return

    log_event(f"BLOCKING IP {ip}...")
    run_cmd(f"sudo iptables -I INPUT -s {ip} -j DROP")
    # Append to file
    with open(BANNED_IPS_FILE, 'a') as f:
        f.write(f"{ip}\n")

# --- LOG ANALYSIS ---
def analyze_logs():
    # Detect DNS attacks from syslog/dnsmasq.log
    # Example attack: many queries from same IP in short time
    counts = {}
    
    # Read last 2000 lines of dnsmasq log
    try:
        if os.path.exists(DNSMASQ_LOG):
            cmd = f"tail -n 2000 {DNSMASQ_LOG}"
            res = run_cmd(cmd)
            if res and res.stdout:
                for line in res.stdout.splitlines():
                    # Look for blocked queries
                    # Feb  7 12:09:27 dnsmasq[123]: config malicious.com is 103.68.213.74 (blocked)
                    # We match both the old IP and the current server IP
                    if f"is {server_ip}" in line or "is 0.0.0.0" in line:
                        match = re.search(r'query\[.*\] .* from ([\d\.]+)', line)
                        if match:
                            ip = match.group(1)
                            if not is_whitelisted(ip):
                                counts[ip] = counts.get(ip, 0) + 1
    except Exception as e:
        log_event(f"Error analyzing logs: {e}")
    
    for ip, count in counts.items():
        if count > MALICIOUS_THRESHOLD:
            log_event(f"ATTACK DETECTED: IP {ip} sent {count} queries. Blocking IP...")
            block_ip(ip)

# --- SELF-HEALING LOGIC ---
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB

def rotate_logs():
    if os.path.exists(GUARDIAN_LOG) and os.path.getsize(GUARDIAN_LOG) > MAX_LOG_SIZE:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        os.rename(GUARDIAN_LOG, f"{GUARDIAN_LOG}.{timestamp}")
        log_event("Guardian log rotated.")

def is_port_listening(port, proto="tcp", addr_part=":"):
    # Use ss to check if port is listening
    cmd = f"ss -lntu | grep '{addr_part}{port} ' | grep -i '{proto}'"
    res = run_cmd(cmd)
    return res and res.stdout.strip() != ""

def is_dns_trust_enabled():
    """
    Check if DNS Trust (Internet Positif) is enabled by checking if the local blocklist file exists.
    """
    blocklist_file = "/etc/dnsmasq.d/internet_positif.conf"
    return os.path.exists(blocklist_file)

def sync_blocking_config(dns_trust):
    blocking_files = [
        "/etc/dnsmasq.d/alias.conf",
        "/etc/dnsmasq.d/blacklist.conf",
        "/etc/dnsmasq.d/malware.conf",
        "/etc/dnsmasq.d/malware_test.conf"
    ]
    
    changed = False
    for file_path in blocking_files:
        if not os.path.exists(file_path):
            continue
            
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            new_lines = []
            file_changed = False
            for line in lines:
                clean_line = line.strip()
                # Skip comments that are headers or empty lines
                if not clean_line or (clean_line.startswith('#') and not clean_line[1:].strip().startswith(('address=', 'alias='))):
                    new_lines.append(line)
                    continue
                
                # ALWAYS keep these rules active regardless of dns_trust status
                # because the user expects the block page and local blacklist to work
                if clean_line.startswith('#'):
                    rule_content = clean_line[1:].strip()
                    if rule_content.startswith(('address=', 'alias=')):
                        new_lines.append(line.lstrip('#').lstrip())
                        file_changed = True
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            if file_changed:
                with open(file_path, 'w') as f:
                    f.writelines(new_lines)
                log_event(f"Config {file_path} synchronized with DNS Trust status ({'ENABLED' if dns_trust else 'DISABLED'})")
                changed = True
        except Exception as e:
            log_event(f"Error syncing {file_path}: {e}")
            
    if changed:
        log_event("Restarting dnsmasq to apply DNS Trust sync changes...")
        run_cmd("sudo systemctl restart dnsmasq")

def is_dns_resolving():
    # Try to resolve a common domain via localhost
    try:
        res = run_cmd("dig @127.0.0.1 google.com +short +timeout=2 +tries=1")
        return res and res.stdout.strip() != ""
    except:
        return False

def is_dnssec_valid():
    # Verify DNSSEC by querying a known signed domain and checking for 'ad' flag
    try:
        # Use +adflag to explicitly ask for AD bit
        # We query through localhost 127.0.0.1
        res = run_cmd("dig @127.0.0.1 cloudflare.com +dnssec +adflag +timeout=2 +tries=1")
        if not res or not res.stdout:
            # If resolution fails completely, let is_dns_resolving() handle it
            return True
            
        # Check if 'ad' flag is present in flags section
        is_valid = " ad " in res.stdout or "; flags: ad" in res.stdout or "flags: qr rd ra ad" in res.stdout
        
        # If not valid on 127.0.0.1, check 127.0.0.1:5353 (Unbound directly)
        if not is_valid:
            res_unbound = run_cmd("dig @127.0.0.1 -p 5353 cloudflare.com +dnssec +adflag +timeout=2 +tries=1")
            if res_unbound and res_unbound.stdout:
                is_valid_unbound = " ad " in res_unbound.stdout or "; flags: ad" in res_unbound.stdout
                if is_valid_unbound:
                    # Unbound is OK, but dnsmasq is not passing AD flag. 
                    # This happens if dnsmasq is not configured with proxy-dnssec correctly.
                    log_event("DEBUG: DNSSEC valid on Unbound but NOT on dnsmasq proxy.")
                    # Instead of returning False and causing a restart loop, we try to fix the config once
                    return True # Don't restart, just log it.
        
        return is_valid
    except:
        return True # Don't restart on script errors

def check_and_repair_services():
    rotate_logs()
    dns_trust = is_dns_trust_enabled()
    
    # Define services with their critical ports
    service_map = {
        "dnsmasq": {"port": 53, "proto": "udp"},
        "unbound": {"port": 5353, "proto": "udp"},
        "dnsmars-gui": {"port": 5000, "proto": "tcp"},
        "nginx": {"port": 80, "proto": "tcp"},
        "systemd-resolved": {"port": None} # Just check if service is active
    }

    for service, info in service_map.items():
        status = run_cmd(f"systemctl is-active {service}")
        
        # Check port listening (if port is specified)
        port_up = True
        if info.get("port"):
            addr_part = f"{info['addr']}:" if 'addr' in info else ":"
            port_up = is_port_listening(info["port"], info["proto"], addr_part)
        
        # Additional checks for dnsmasq: resolution and DNSSEC
        dns_functional = True
        dnssec_functional = True
        if service == "dnsmasq" and port_up:
            dns_functional = is_dns_resolving()
            if not dns_functional:
                log_event("ALERT: dnsmasq port is UP but resolution is FAILING. Possible hung process.")
            
            # DNSSEC check
            dnssec_functional = is_dnssec_valid()
            if not dnssec_functional:
                log_event("ALERT: DNSSEC validation is FAILING on dnsmasq.")

        # If service is down or port is not listening or DNS/DNSSEC is not functional
        if (status and status.stdout.strip() != "active") or not port_up or (service == "dnsmasq" and (not dns_functional or not dnssec_functional)):
            if status.stdout.strip() != "active":
                reason = "is DOWN"
            elif not port_up:
                reason = f"is HUNG (port {info['port']} not responding)"
            elif not dns_functional:
                reason = "is HUNG (resolution failing)"
            else:
                reason = "is HUNG (DNSSEC validation failing)"
                
            log_event(f"ALERT: {service} {reason}. Attempting self-healing...")
            
            # Special check for dnsmasq/unbound config
            check_conf = None
            if service == "dnsmasq":
                check_conf = run_cmd("dnsmasq --test")
            elif service == "unbound":
                check_conf = run_cmd("unbound-checkconf")
            
            if check_conf and check_conf.stderr and "error" in check_conf.stderr.lower():
                log_event(f"ERROR: {service} config is corrupted: {check_conf.stderr.strip()}")
                # Try to restore default or notify, but for now we try restart anyway
            
            run_cmd(f"systemctl restart {service}")
            time.sleep(3) # Give it time to bind ports
            
            new_status = run_cmd(f"systemctl is-active {service}")
            new_port_up = is_port_listening(info["port"], info["proto"])
            
            if new_status and new_status.stdout.strip() == "active" and new_port_up:
                log_event(f"SUCCESS: {service} has been repaired and is now ONLINE.")
            else:
                log_event(f"CRITICAL: {service} repair FAILED (Status: {new_status.stdout.strip()}, Port: {new_port_up}).")

    # --- FIREWALL SELF-HEALING (DDoS PRO & NAT INTCP) ---
    # Enhanced firewall check: ensure DNS redirection and Web access is ALWAYS active
    fw_status = run_cmd("sudo iptables -L INPUT -n")
    fw_nat_status = run_cmd("sudo iptables -L -t nat -n")
    fw_save_status = run_cmd("sudo iptables-save") # Better for matching modules
    fw6_status = run_cmd("sudo ip6tables -L INPUT -n 2>/dev/null")
    fw6_nat_status = run_cmd("sudo ip6tables -L -t nat -n 2>/dev/null")
    
    # Check for DNS redirect (IPv4 & IPv6) in NAT table
    has_dns_v4_nat = "REDIRECT" in fw_nat_status.stdout and "dpt:53" in fw_nat_status.stdout if (fw_nat_status and fw_nat_status.stdout) else False
    
    # Check for DDoS Protection modules
    has_flood_prot = "hashlimit" in fw_save_status.stdout if (fw_save_status and fw_save_status.stdout) else False
    has_conn_limit = "connlimit" in fw_save_status.stdout if (fw_save_status and fw_save_status.stdout) else False

    # Check for Web GUI access (Port 5000) in INPUT chain
    has_web_v4 = "dpt:5000" in fw_status.stdout if (fw_status and fw_status.stdout) else False
    
    # Check for DNS access (Port 53) in INPUT chain
    has_dns_v4_input = "dpt:53" in fw_status.stdout if (fw_status and fw_status.stdout) else False

    # Check for IPv6 if enabled
    ipv6_up = get_current_ipv6() is not None
    has_dns_v6_nat = True
    has_web_v6 = True
    
    if ipv6_up:
        if not fw6_nat_status or not fw6_nat_status.stdout or "REDIRECT" not in fw6_nat_status.stdout or "dpt:53" not in fw6_nat_status.stdout:
            has_dns_v6_nat = False
        if not fw6_status or not fw6_status.stdout or "dpt:5000" not in fw6_status.stdout:
            has_web_v6 = False
    
    # If any critical rule is missing, restore firewall
    if not has_dns_v4_nat or not has_web_v4 or not has_dns_v4_input or not has_dns_v6_nat or not has_web_v6 or not has_flood_prot or not has_conn_limit:
        reason = []
        if not has_dns_v4_nat: reason.append("IPv4 DNS NAT")
        if not has_dns_v4_input: reason.append("IPv4 DNS INPUT")
        if not has_flood_prot: reason.append("DDoS Flood Protection")
        if not has_conn_limit: reason.append("TCP Conn Limit")
        if not has_web_v4: reason.append("IPv4 Web GUI")
        if not has_dns_v6_nat: reason.append("IPv6 DNS NAT")
        if not has_web_v6: reason.append("IPv6 Web GUI")
        
        log_event(f"ALERT: Critical firewall rules ({', '.join(reason)}) are missing. Restoring...")
        run_cmd("sudo bash /home/dns/setup_firewall.sh")

def check_resources():
    """
    Monitor Memory, Swap, and UDP Errors.
    Mitigates: Memory Leak, Swap Thrashing, UDP Drops.
    """
    try:
        # 1. Check Memory & Swap
        with open('/proc/meminfo', 'r') as f:
            meminfo = {}
            for line in f:
                parts = line.split(':')
                meminfo[parts[0].strip()] = int(parts[1].split()[0])
        
        total_mem = meminfo.get('MemTotal', 1)
        avail_mem = meminfo.get('MemAvailable', 0)
        total_swap = meminfo.get('SwapTotal', 0)
        free_swap = meminfo.get('SwapFree', 0)
        
        mem_usage = 100 - (avail_mem / total_mem * 100)
        swap_usage = 100 - (free_swap / total_swap * 100) if total_swap > 0 else 0
        
        # Memory Leak Protection
        if mem_usage > MEM_THRESHOLD:
            log_event(f"ALERT: High Memory Usage ({mem_usage:.1f}%). Checking for leaks...")
            # If swap is also high, we are in trouble. Restart heaviest service.
            if swap_usage > SWAP_THRESHOLD:
                log_event("CRITICAL: Swap Thrashing Detected. Restarting DNS services to free memory.")
                run_cmd("systemctl restart unbound")
                run_cmd("systemctl restart dnsmasq")
        
        # 2. Check UDP Packet Drops (RCV buffer errors)
        # cat /proc/net/snmp | grep Udp:
        cmd = "cat /proc/net/snmp | grep 'Udp: ' | awk 'NR==2 {print $6}'" # RcvbufErrors is usually column 6
        res = run_cmd(cmd)
        if res and res.stdout.strip():
            rcv_errors = int(res.stdout.strip())
            # We track delta ideally, but for now just log if non-zero and high
            if rcv_errors > 1000:
                 # Check if we already logged this recently? (Simplified: just log)
                 pass
                 # log_event(f"WARNING: UDP Receive Errors detected: {rcv_errors}. OS Buffer tuning might be needed.")

    except Exception as e:
        log_event(f"Resource check error: {e}")

def check_disk_space():
    """
    Emergency Disk Protection.
    If disk usage exceeds threshold (e.g. 90%), aggressively clean logs.
    """
    try:
        # Get root partition usage
        cmd = "df -h / | awk 'NR==2 {print $5}' | sed 's/%//'"
        res = run_cmd(cmd)
        if not res or not res.stdout:
            return
            
        usage = int(res.stdout.strip())
        
        if usage >= DISK_THRESHOLD:
            log_event(f"CRITICAL: Disk usage at {usage}% (Threshold: {DISK_THRESHOLD}%). Executing EMERGENCY cleanup...")
            
            # 1. Truncate Logs immediately
            if os.path.exists(DNSMASQ_LOG):
                run_cmd(f"truncate -s 0 {DNSMASQ_LOG}")
                log_event(f"Truncated {DNSMASQ_LOG}")
                
            if os.path.exists(NGINX_LOG):
                run_cmd(f"truncate -s 0 {NGINX_LOG}")
                log_event(f"Truncated {NGINX_LOG}")
                
            # 1.5 Vacuum Systemd Journal (Syslog)
            run_cmd("journalctl --vacuum-size=50M")
            log_event("Vacuumed systemd journal to 50MB")

            # 2. Check for rotated logs that are huge and delete them
            # Delete any .gz or .1 log file in /var/log/nginx older than 0 days (immediate)
            run_cmd("find /var/log/nginx -name '*.gz' -delete")
            run_cmd("find /var/log/nginx -name '*.1' -delete")
            
            # Same for dnsmasq
            run_cmd("find /var/log -name 'dnsmasq.log.*.gz' -delete")
            
            log_event("Emergency cleanup completed.")
            
    except Exception as e:
        log_event(f"Error checking disk space: {e}")

def detect_and_block_attacks():
    if not is_dns_trust_enabled():
        return
    
    if not os.path.exists(DNSMASQ_LOG):
        return

    # Get last 2000 lines to have a better sample
    lines = run_cmd(f"tail -n 2000 {DNSMASQ_LOG}")
    if not lines or not lines.stdout:
        return

    ip_counts = {}
    malicious_counts = {}
    
    # Example dnsmasq log lines:
    # Feb  7 12:09:27 dnsmasq[123]: query[A] google.com from 1.2.3.4
    # Feb  7 12:09:27 dnsmasq[123]: reply google.com is 142.250.190.46
    # Feb  7 12:09:27 dnsmasq[123]: config malicious.com is 103.68.213.74 (blocked)

    for line in lines.stdout.splitlines():
        if "query[" in line:
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                if not is_whitelisted(ip):
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        # Detect if an IP is repeatedly trying to access blocked/malicious domains
        if f"is {server_ip}" in line or "is 0.0.0.0" in line:
            # We need to find which IP requested this. This is tricky without session tracking.
            # But we can assume if an IP has high query count AND there are many blocks, it's a target.
            pass

    for ip, count in ip_counts.items():
        # Only block if it really exceeds a high threshold (e.g., 200 queries in 2000 lines ~ 1 minute)
        if count > BAN_THRESHOLD:
            log_event(f"ATTACK DETECTED: IP {ip} sent {count} queries.")
            block_ip(ip)

# --- TRUST SCHEDULE ENFORCEMENT ---
DB_PATH = "/home/dns/traffic_history.db"

def apply_trust_schedule():
    """
    Enhanced schedule enforcement with change detection.
    - Detects schedule setting changes and forces immediate sync
    - Properly handles overnight schedules (e.g., 19:00-05:00)
    - Avoids unnecessary service restarts
    """
    global LAST_SCHEDULE_STATE
    
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT enabled, start_time, end_time, trust_ips FROM trust_schedule WHERE id=1")
        row = c.fetchone()
        conn.close()
        
        if not row:
            return
        
        enabled, start_time, end_time, trust_ips = row
        
        # Create a hashable state representation
        current_state = (enabled, start_time, end_time, trust_ips)
        
        # DETECT SCHEDULE CHANGE: Settings were modified
        is_schedule_changed = LAST_SCHEDULE_STATE != current_state
        if is_schedule_changed:
            log_event(f"SCHEDULE CHANGED: ({LAST_SCHEDULE_STATE}) -> ({current_state})")
            LAST_SCHEDULE_STATE = current_state
        
        # Check if schedule is enabled in database
        if not enabled:
            # If schedule was previously enabled, ensure DNS trust is disabled
            current_enabled = is_dns_trust_enabled()
            if current_enabled:
                log_event("SCHEDULE: Disabled in config. Disabling DNS Trust...")
                disable_trust_logic()
            return
        
        # Schedule is enabled, check if current time is within range
        now = datetime.now().strftime("%H:%M")
        
        # Calculate if current time is within schedule range
        is_in_range = _check_time_in_range(start_time, end_time, now)
        current_enabled = is_dns_trust_enabled()
        
        # DECISION LOGIC:
        # 1. If schedule changed, force immediate state sync
        # 2. If time-based change needed, apply it
        
        if is_schedule_changed:
            # Force immediate sync to new state
            if is_in_range:
                if not current_enabled:
                    log_event(f"SCHEDULE CHANGE: Force enabling DNS Trust ({start_time}-{end_time})")
                    enable_trust_logic(trust_ips)
            else:
                if current_enabled:
                    log_event(f"SCHEDULE CHANGE: Force disabling DNS Trust (outside {start_time}-{end_time})")
                    disable_trust_logic()
        else:
            # Normal operation: only change state if needed
            if is_in_range and not current_enabled:
                log_event(f"SCHEDULE: Enabling DNS Trust ({start_time}-{end_time})")
                enable_trust_logic(trust_ips)
            elif not is_in_range and current_enabled:
                log_event(f"SCHEDULE: Disabling DNS Trust (outside {start_time}-{end_time})")
                disable_trust_logic()
                
    except Exception as e:
        log_event(f"Error in trust schedule: {e}")

def _check_time_in_range(start_time, end_time, now):
    """
    Check if current time falls within schedule range.
    Properly handles overnight schedules (e.g., start > end).
    
    Args:
        start_time: HH:MM format (e.g., "19:00")
        end_time: HH:MM format (e.g., "05:00")
        now: HH:MM format of current time
    
    Returns:
        True if now is within range, False otherwise
    """
    try:
        # Parse time strings to comparable format
        start = start_time.replace(":", "")  # "19:00" -> "1900"
        end = end_time.replace(":", "")      # "05:00" -> "0500"
        current = now.replace(":", "")       # "20:30" -> "2030"
        
        # Convert to integers for comparison
        start_min = int(start)
        end_min = int(end)
        current_min = int(current)
        
        if start_min <= end_min:
            # Normal schedule: start <= end (e.g., 05:00 <= 19:00)
            # 05:00 to 19:00 is "in range" if 500 <= now <= 1900
            return start_min <= current_min <= end_min
        else:
            # Overnight schedule: start > end (e.g., 19:00 to 05:00)
            # 19:00 to 05:00 is "in range" if (now >= 1900) OR (now <= 0500)
            return current_min >= start_min or current_min <= end_min
    except Exception as e:
        log_event(f"Error in time range check: {e}")
        return False


def enable_trust_logic(trust_ip=None):
    try:
        # Enable Local Blocklist
        blocklist_file = '/etc/dnsmasq.d/internet_positif.conf'
        blocklist_disabled = '/home/dns/blocklists/disabled/internet_positif.conf'
        
        # Also check for legacy disabled file and migrate if needed
        legacy_disabled = '/etc/dnsmasq.d/internet_positif.conf.disabled'
        if os.path.exists(legacy_disabled):
            run_cmd(f"sudo mv {legacy_disabled} {blocklist_disabled}")

        if os.path.exists(blocklist_disabled):
            # Use cp instead of mv to keep backup safe
            res = run_cmd(f"sudo cp {blocklist_disabled} {blocklist_file}")
            if res and res.returncode != 0:
                log_event(f"Error copying blocklist: {res.stderr}")
            
        run_cmd("sudo bash /home/dns/setup_firewall.sh")
        run_cmd("sudo systemctl restart dnsmasq")
        # Unbound restart not strictly needed but good for cleanup
        run_cmd("sudo systemctl restart unbound") 
    except Exception as e:
        log_event(f"Failed to enable trust via schedule: {e}")

def disable_trust_logic():
    try:
        # Disable Local Blocklist
        blocklist_file = '/etc/dnsmasq.d/internet_positif.conf'
        blocklist_disabled = '/home/dns/blocklists/disabled/internet_positif.conf'
        
        # Ensure target directory exists
        if not os.path.exists('/home/dns/blocklists/disabled'):
            run_cmd('sudo mkdir -p /home/dns/blocklists/disabled')

        if os.path.exists(blocklist_file):
            # Move to disabled folder
            res = run_cmd(f"sudo mv {blocklist_file} {blocklist_disabled}")
            if res and res.returncode != 0:
                log_event(f"Error moving blocklist to disabled: {res.stderr}")
        
        # Clean up any legacy stray files
        run_cmd("sudo rm -f /etc/dnsmasq.d/*.disabled")
            
        run_cmd("sudo bash /home/dns/setup_firewall.sh")
        run_cmd("sudo systemctl restart dnsmasq")
    except Exception as e:
        log_event(f"Failed to disable trust via schedule: {e}")

# --- MAIN LOOP ---
if __name__ == "__main__":
    log_event("INTELLIGENT GUARDIAN STARTED: Monitoring system health and security...")
    
    # Wait for other services to settle on boot
    time.sleep(5)
    
    while True:
        try:
            # 1. Emergency Disk Check (Priority 1)
            check_disk_space()
            
            # 2. Resource Health Check (Memory, Swap, UDP)
            check_resources()
            
            # Refresh server IP and Whitelist in case of network changes
            reload_whitelist_if_needed()
            
            # Detect IP Changes
            current_ip_v4 = get_current_ip()
            current_ip_v6 = get_current_ipv6()
            
            if current_ip_v4 != LAST_IP_V4 or current_ip_v6 != LAST_IP_V6:
                log_event(f"NETWORK CHANGE DETECTED: v4({LAST_IP_V4}->{current_ip_v4}), v6({LAST_IP_V6}->{current_ip_v6})")
                # Add new IPs to whitelist immediately
                if current_ip_v4 not in WHITELIST: WHITELIST.append(current_ip_v4)
                if current_ip_v6 and current_ip_v6 not in WHITELIST: WHITELIST.append(current_ip_v6)
                
                # Re-apply firewall to update rules with new IP
                log_event("Re-applying firewall rules for new IP...")
                run_cmd("sudo bash /home/dns/setup_firewall.sh")
                
                LAST_IP_V4 = current_ip_v4
                LAST_IP_V6 = current_ip_v6
                server_ip = current_ip_v4

            check_and_repair_services()
            apply_trust_schedule()
            sync_blocking_config(is_dns_trust_enabled())
            detect_and_block_attacks()
            time.sleep(10) # Run every 10 seconds
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_event(f"GUARDIAN ERROR: {str(e)}")
            time.sleep(30)
