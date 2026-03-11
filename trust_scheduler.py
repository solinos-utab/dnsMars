import sqlite3
import time
import subprocess
import os

# Paths
BRAND_DB_PATH = "/home/dns/brand_settings.db"
TRAFFIC_DB_PRIMARY = "/home/dns/traffic_history.db"
TRAFFIC_DB_SECONDARY = "/home/dns/traffic_history_secondary.db"

def get_setting(key):
    try:
        conn = sqlite3.connect(BRAND_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row else None
    except: return None

def ssh_node(node, cmd):
    prefix = "ssh_p_" if node == "primary" else "ssh_s_"
    ip = get_setting(f"{prefix}ip")
    port = get_setting(f"{prefix}port") or "22"
    user = get_setting(f"{prefix}user") or "root"
    ssh_cmd = ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no", "-p", port, f"{user}@{ip}", cmd]
    try:
        p = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
        return p.stdout.strip(), p.stderr.strip(), p.returncode
    except:
        return "", "SSH Timeout", 1

def check_and_apply(node, db_path):
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT enabled, start_time, end_time FROM trust_schedule LIMIT 1")
        row = cur.fetchone()
        conn.close()
        
        if not row or not row[0]: # Not enabled
            return

        enabled, start_t, end_t = row
        now_t = time.strftime("%H:%M")
        
        # Check if current time is within schedule
        is_active = False
        if start_t < end_t:
            is_active = start_t <= now_t <= end_t
        else: # Over midnight
            is_active = now_t >= start_t or now_t <= end_t
            
        if is_active:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {node.upper()}: Schedule ACTIVE. Applying Trust Redirect...")
            # Redirect port 80 to 5001 (Main GUI) for block page / positive internet redirect
            # Based on nginx config, we want to ensure port 80 traffic goes to block_page or stays active
            # This is a simplified logic to ensure the "Trust" state
            cmd = "iptables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 5001 2>/dev/null || iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 5001"
            ssh_node(node, cmd)
        else:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {node.upper()}: Schedule INACTIVE. Removing Trust Redirect...")
            cmd = "iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 5001 2>/dev/null || true"
            ssh_node(node, cmd)
            
    except Exception as e:
        print(f"Error in {node} trust checker: {e}")

def main():
    print("Starting DNS Trust Internet Positif Scheduler (60s cycle)...")
    while True:
        check_and_apply("primary", TRAFFIC_DB_PRIMARY)
        check_and_apply("secondary", TRAFFIC_DB_SECONDARY)
        time.sleep(60)

if __name__ == "__main__":
    main()
