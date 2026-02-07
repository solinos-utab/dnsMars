import os
import time
import subprocess
import re
from datetime import datetime

# --- CONFIGURATION ---
LOG_FILE = "/var/log/syslog"
DNSMASQ_LOG = "/var/log/dnsmasq.log"
BAN_THRESHOLD = 50  # Requests per minute from a single IP
WHITELIST = ["127.0.0.1", "103.68.213.6", "103.68.213.7"]
GUARDIAN_LOG = "/home/dns/guardian.log"

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
    # Detect DNS Flood Attacks from dnsmasq log
    if not os.path.exists(DNSMASQ_LOG):
        return

    # Get last 1000 lines
    lines = run_cmd(f"tail -n 1000 {DNSMASQ_LOG}")
    if not lines or not lines.stdout:
        return

    ip_counts = {}
    for line in lines.stdout.splitlines():
        if "query[" in line:
            # Extract IP address
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                if ip not in WHITELIST:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1

    for ip, count in ip_counts.items():
        if count > BAN_THRESHOLD:
            log_event(f"ATTACK DETECTED: IP {ip} sent {count} queries. Blocking IP...")
            run_cmd(f"sudo iptables -I INPUT -s {ip} -j DROP")
            # Log to a permanent ban list
            run_cmd(f"echo '{ip}' >> /home/dns/banned_ips.txt")

# --- MAIN LOOP ---
if __name__ == "__main__":
    log_event("INTELLIGENT GUARDIAN STARTED: Monitoring system health and security...")
    while True:
        try:
            check_and_repair_services()
            detect_and_block_attacks()
            time.sleep(10) # Run every 10 seconds
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_event(f"GUARDIAN ERROR: {str(e)}")
            time.sleep(30)
