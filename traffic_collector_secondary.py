import subprocess, sqlite3, time, os

DB_PATH = "/home/dns/traffic_history_secondary.db"
BRAND_DB_PATH = "/home/dns/brand_settings.db"

def get_ssh_config():
    try:
        conn = sqlite3.connect(BRAND_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM settings WHERE key IN ('ssh_s_ip', 'ssh_s_port', 'ssh_s_user', 'ssh_s_pass')")
        rows = cur.fetchall()
        conn.close()
        return {r[0]: r[1] for r in rows}
    except:
        return {}

def run_ssh(cmd):
    cfg = get_ssh_config()
    ip = cfg.get("ssh_s_ip")
    port = cfg.get("ssh_s_port") or "22"
    user = cfg.get("ssh_s_user") or "root"
    pw = cfg.get("ssh_s_pass")
    
    if not ip: return ""
    
    ssh_cmd = ["ssh", "-o", "ConnectTimeout=3", "-o", "StrictHostKeyChecking=no", "-p", port, f"{user}@{ip}", cmd]
    try:
        if pw:
            p = subprocess.run(["sshpass", "-p", pw] + ssh_cmd, capture_output=True, text=True, timeout=10)
        else:
            p = subprocess.run(["ssh", "-o", "BatchMode=yes"] + ssh_cmd[1:], capture_output=True, text=True, timeout=10)
        return p.stdout.strip()
    except:
        return ""

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS traffic (timestamp TEXT PRIMARY KEY, qps REAL, queries REAL, load_avg REAL, cpu REAL, ram REAL, hdd REAL, blacklist INTEGER, guardian_error TEXT)")
    # Add columns if they don't exist
    cols = ["load_avg REAL", "cpu REAL", "ram REAL", "hdd REAL", "blacklist INTEGER", "guardian_error TEXT"]
    for col in cols:
        try:
            cur.execute(f"ALTER TABLE traffic ADD COLUMN {col}")
        except:
            pass
    conn.commit()
    conn.close()

def collect():
    init_db()
    print("Starting REAL-TIME system & traffic collector (5s) for Secondary...")
    
    last_total = 0
    last_time = time.time()
    
    while True:
        try:
            now = time.time()
            # Collect Metrics using a clear separator to avoid indexing errors
            # Using 2-sample top to get accurate CPU usage (avoiding startup/average skew)
            cmd = (
                "cat /proc/loadavg | awk '{print $1}'; "
                "top -bn2 -d 0.2 | grep 'Cpu(s)' | tail -1 | awk -F'id,' '{print $1}' | awk '{print 100 - $NF}'; "
                "free | grep Mem | awk '{print $3/$2 * 100.0}'; "
                "df / | tail -1 | awk '{print $5}' | sed 's/%//'; "
                "grep -c 'address=/' /etc/dnsmasq.d/blacklist.conf || echo 0; "
                "tail -n 5 /home/dns/guardian.log | grep -Ei 'ERROR|FAILED|CRITICAL' | tail -n 1 || echo ''; "
                "grep -c 'query' /var/log/dnsmasq.log || echo 0"
            )
            res = run_ssh(cmd)
            lines = [l.strip() for l in res.splitlines()]
            
            if len(lines) >= 7:
                try:
                    current_load = float(lines[0])
                    current_cpu = float(lines[1])
                    current_ram = float(lines[2])
                    current_hdd = float(lines[3])
                    current_blacklist = int(lines[4])
                    current_guardian_err = lines[5]
                    current_total = float(lines[6])
                except:
                    # Skip iteration on parsing failure to avoid data corruption
                    time.sleep(5)
                    continue
            else:
                # If command output is malformed, skip this cycle
                print(f"Malformed output from Secondary (lines={len(lines)})")
                time.sleep(5)
                continue
            
            dt = now - last_time
            
            if last_total > 0 and dt > 0:
                if current_total >= last_total:
                    qps = (current_total - last_total) / dt
                else:
                    # Log rotation detected
                    qps = current_total / dt
            else:
                qps = 0.0
            
            last_total = current_total
            last_time = now
            
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))
            cur.execute("INSERT OR REPLACE INTO traffic (timestamp, qps, queries, load_avg, cpu, ram, hdd, blacklist, guardian_error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (ts, qps, current_total, current_load, current_cpu, current_ram, current_hdd, current_blacklist, current_guardian_err))
            cur.execute("DELETE FROM traffic WHERE timestamp NOT IN (SELECT timestamp FROM traffic ORDER BY timestamp DESC LIMIT 1000)")
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error: {e}")
            
        time.sleep(5) # 5s cycle for full metrics

if __name__ == "__main__":
    collect()
