import os
import time
import subprocess
import re
from datetime import datetime

# --- CONFIGURATION ---
LOG_FILE = "/var/log/syslog"
DNSMASQ_LOG = "/var/log/dnsmasq.log"
BAN_THRESHOLD = 1800  # Increased to match 1500 QPS (Checking 2000 log lines)
MALICIOUS_THRESHOLD = 50 # Increased slightly
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

WHITELIST, WHITELIST_SUBNETS = load_whitelist()

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
            
        # Specific check for ens18 as a last resort
        cmd = "ip -4 addr show ens18 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1"
        res = run_cmd(cmd)
        if res and res.stdout.strip():
            return res.stdout.strip()
    except:
        pass
    return "127.0.0.1"

# Auto-update whitelist with current server IP
server_ip = get_current_ip()
if server_ip not in WHITELIST:
    WHITELIST.append(server_ip)

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
    if is_whitelisted(ip):
        return
    log_event(f"BLOCKING IP {ip}...")
    run_cmd(f"sudo iptables -I INPUT -s {ip} -j DROP")
    run_cmd(f"echo '{ip}' >> {BANNED_IPS_FILE}")

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
def check_and_repair_services():
    services = ["dnsmasq", "unbound"]
    for service in services:
        status = run_cmd(f"systemctl is-active {service}")
        if status and status.stdout.strip() != "active":
            log_event(f"ALERT: {service} is DOWN. Attempting self-healing...")
            
            # Check for config errors before restarting
            check_conf = ""
            if service == "dnsmasq":
                check_conf = run_cmd("dnsmasq --test")
            elif service == "unbound":
                check_conf = run_cmd("unbound-checkconf")
            
            if check_conf and "error" in check_conf.stderr.lower():
                log_event(f"ERROR: {service} config is corrupted: {check_conf.stderr.strip()}")
                # Optional: Restore from backup if we had one
            
            run_cmd(f"systemctl restart {service}")
            time.sleep(2)
            
            new_status = run_cmd(f"systemctl is-active {service}")
            if new_status and new_status.stdout.strip() == "active":
                log_event(f"SUCCESS: {service} has been repaired and is now ONLINE.")
            else:
                log_event(f"CRITICAL: {service} repair FAILED. Manual intervention required.")

# --- ATTACK DETECTION LOGIC ---
def detect_and_block_attacks():
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
            log_event(f"ATTACK DETECTED: IP {ip} sent {count} queries. Checking if it should be blocked...")
            
            # Additional check: If it's whitelisted, don't block
            if is_whitelisted(ip):
                log_event(f"SKIP BLOCK: IP {ip} is whitelisted.")
                continue

            log_event(f"BLOCKING IP {ip}...")
            run_cmd(f"sudo iptables -I INPUT -s {ip} -j DROP")
            run_cmd(f"echo '{ip}' >> {BANNED_IPS_FILE}")

# --- MAIN LOOP ---
if __name__ == "__main__":
    log_event("INTELLIGENT GUARDIAN STARTED: Monitoring system health and security...")
    while True:
        try:
            # Refresh server IP and Whitelist in case of network changes
            current_ip = get_current_ip()
            if current_ip and current_ip not in WHITELIST:
                WHITELIST.append(current_ip)
                log_event(f"WHITELIST UPDATED: Added new server IP {current_ip}")

            check_and_repair_services()
            detect_and_block_attacks()
            time.sleep(10) # Run every 10 seconds
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_event(f"GUARDIAN ERROR: {str(e)}")
            time.sleep(30)
