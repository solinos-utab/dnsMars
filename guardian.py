import os
import time
import subprocess
import re
from datetime import datetime

# --- CONFIGURATION ---
LOG_FILE = "/var/log/syslog"
DNSMASQ_LOG = "/var/log/dnsmasq.log"
BAN_THRESHOLD = 10000  # Set very high for ISP environment (Mikrotik support)
MALICIOUS_THRESHOLD = 200 # Increased to avoid false positives
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
    global WHITELIST, WHITELIST_SUBNETS, LAST_WL_RELOAD
    # Reload every 60 seconds
    if time.time() - LAST_WL_RELOAD > 60:
        WHITELIST, WHITELIST_SUBNETS = load_whitelist()
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
TRUST_CONF = "/etc/dnsmasq.d/smartdns.conf"
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB

def rotate_logs():
    if os.path.exists(GUARDIAN_LOG) and os.path.getsize(GUARDIAN_LOG) > MAX_LOG_SIZE:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        os.rename(GUARDIAN_LOG, f"{GUARDIAN_LOG}.{timestamp}")
        log_event("Guardian log rotated.")

def is_port_listening(port, proto="tcp"):
    # Use ss to check if port is listening
    cmd = f"ss -lntu | grep ':{port} ' | grep -i '{proto}'"
    res = run_cmd(cmd)
    return res and res.stdout.strip() != ""

def is_dns_trust_enabled():
    if not os.path.exists(TRUST_CONF):
        return False
    try:
        with open(TRUST_CONF, 'r') as f:
            for line in f:
                if line.strip().startswith('server='):
                    return True
    except:
        pass
    return False

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
                if not clean_line or (clean_line.startswith('#') and not clean_line[1:].strip().startswith(('address=', 'alias=', 'filter-AAAA'))):
                    new_lines.append(line)
                    continue
                
                # ALWAYS keep these rules active regardless of dns_trust status
                # because the user expects the block page and local blacklist to work
                if clean_line.startswith('#'):
                    rule_content = clean_line[1:].strip()
                    if rule_content.startswith(('address=', 'alias=', 'filter-AAAA')):
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

def check_and_repair_services():
    rotate_logs()
    dns_trust = is_dns_trust_enabled()
    
    # Define services with their critical ports
    service_map = {
        "dnsmasq": {"port": 53, "proto": "udp"},
        "unbound": {"port": 5353, "proto": "udp"},
        "dnsmars-gui": {"port": 5000, "proto": "tcp"},
        "nginx": {"port": 80, "proto": "tcp"}
    }

    for service, info in service_map.items():
        status = run_cmd(f"systemctl is-active {service}")
        port_up = is_port_listening(info["port"], info["proto"])
        
        # If service is down or port is not listening (hung)
        if (status and status.stdout.strip() != "active") or not port_up:
            reason = "is DOWN" if status.stdout.strip() != "active" else f"is HUNG (port {info['port']} not responding)"
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
    # Enhanced firewall check: ensure DNS redirection is ALWAYS active
    fw_status = run_cmd("sudo iptables -L -n -t nat | grep REDIRECT")
    fw6_status = run_cmd("sudo ip6tables -L -n -t nat | grep REDIRECT 2>/dev/null")
    
    # Check for DNS redirect (IPv4 & IPv6)
    has_dns_v4 = "dpt:53" in fw_status.stdout if fw_status else False
    
    # Check for IPv6 if enabled
    ipv6_up = get_current_ipv6() is not None
    has_dns_v6 = "dpt:53" in fw6_status.stdout if (fw6_status and ipv6_up) else not ipv6_up
    
    if not has_dns_v4 or not has_dns_v6:
        reason = []
        if not has_dns_v4: reason.append("IPv4 DNS")
        if not has_dns_v6: reason.append("IPv6 DNS")
        
        log_event(f"ALERT: Critical DNS firewall rules ({', '.join(reason)}) are missing. Restoring...")
        run_cmd("sudo bash /home/dns/setup_firewall.sh")

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

# --- MAIN LOOP ---
if __name__ == "__main__":
    log_event("INTELLIGENT GUARDIAN STARTED: Monitoring system health and security...")
    
    # Wait for other services to settle on boot
    time.sleep(5)
    
    while True:
        try:
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
            sync_blocking_config(is_dns_trust_enabled())
            detect_and_block_attacks()
            time.sleep(10) # Run every 10 seconds
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_event(f"GUARDIAN ERROR: {str(e)}")
            time.sleep(30)
