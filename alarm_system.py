import subprocess, sqlite3, time, os, requests

# Konfigurasi
BRAND_DB_PATH = "/home/dns/brand_settings.db"
PRIMARY_TRAFFIC_DB = "/home/dns/traffic_history.db"
SECONDARY_TRAFFIC_DB = "/home/dns/traffic_history_secondary.db"

# Thresholds
CPU_THRESHOLD = 90.0
RAM_THRESHOLD = 90.0
HDD_THRESHOLD = 90.0
LOAD_THRESHOLD = 12.0
QPS_THRESHOLD = 5000.0
BLACKLIST_THRESHOLD = 100

def get_settings():
    try:
        conn = sqlite3.connect(BRAND_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM settings")
        rows = cur.fetchall()
        conn.close()
        return {r[0]: r[1] for r in rows}
    except:
        return {}

def send_telegram(msg):
    settings = get_settings()
    token = settings.get('tg_bot_token')
    chat_id = settings.get('tg_chat_id')
    if not token or not chat_id: return
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        resp = requests.post(url, json={"chat_id": chat_id, "text": msg, "parse_mode": "Markdown"}, timeout=10)
        if not resp.ok:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Telegram API Error: {resp.text}")
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Telegram Connection Error: {str(e)}")

def run_local(cmd):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return p.stdout.strip()
    except:
        return ""

def check_local():
    # Check Metrics for WebGUI VM (This VM)
    # Using more robust CPU calculation (2-sample top to avoid startup skew)
    res = run_local("top -bn2 -d 0.2 | grep 'Cpu(s)' | tail -1 | awk -F'id,' '{print $1}' | awk '{print 100 - $NF}' && free | grep Mem | awk '{print $3/$2 * 100.0}' && df / | tail -1 | awk '{print $5}' | sed 's/%//' && cat /proc/loadavg | awk '{print $1}'")
    lines = res.splitlines()
    if len(lines) >= 4:
        try:
            cpu = float(lines[0])
            ram = float(lines[1])
            hdd = float(lines[2])
            load = float(lines[3])
            
            alerts = []
            if cpu > CPU_THRESHOLD: alerts.append(f"⚠️ *High CPU Usage*: {cpu}%")
            if ram > RAM_THRESHOLD: alerts.append(f"⚠️ *High RAM Usage*: {ram}%")
            if hdd > HDD_THRESHOLD: alerts.append(f"⚠️ *High HDD Usage*: {hdd}%")
            if load > LOAD_THRESHOLD: alerts.append(f"🔥 *High Load Average*: {load}")
            
            if alerts:
                msg = f"🖥️ *WEBGUI VM ALARM*\n" + "\n".join(alerts) + f"\n🕒 Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                send_telegram(msg)
        except: pass

def check_node_from_db(db_path, label):
    if not os.path.exists(db_path): return
    
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT load_avg, cpu, ram, hdd, blacklist, guardian_error, qps FROM traffic ORDER BY timestamp DESC LIMIT 1")
        row = cur.fetchone()
        conn.close()
        
        if row:
            load, cpu, ram, hdd, blacklist, guardian_err, qps = row
            alerts = []
            
            if cpu > CPU_THRESHOLD: alerts.append(f"⚠️ *High CPU Usage*: {cpu}%")
            if ram > RAM_THRESHOLD: alerts.append(f"⚠️ *High RAM Usage*: {ram}%")
            if hdd > HDD_THRESHOLD: alerts.append(f"⚠️ *High HDD Usage*: {hdd}%")
            if load > LOAD_THRESHOLD: alerts.append(f"🔥 *High Load Average*: {load}")
            if qps > QPS_THRESHOLD: alerts.append(f"🌩️ *DNS FLOOD DETECTED*: {qps:.2f} QPS")
            
            # Check Guardian Issues
            # Filter out "0", empty strings, or just whitespace
            if guardian_err and str(guardian_err).strip() not in ["", "0", "0.0"]:
                resolution = "Automatic configuration restore and service restart."
                if "syntax" in str(guardian_err).lower(): 
                    resolution = "Config syntax check and rollback initiated."
                alerts.append(f"🛡️ *LOG GUARDIAN ISSUE*: `{guardian_err}`\n✅ *Resolution*: {resolution}")
            
            if blacklist > BLACKLIST_THRESHOLD:
                alerts.append(f"🚫 *BLACKLIST ALERT*: *{blacklist} domains* in manual blocklist.")
            
            if alerts:
                msg = f"🚨 *DNS NODE ALARM - {label}*\n" + "\n".join(alerts) + f"\n🕒 Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                send_telegram(msg)
    except Exception as e:
        print(f"DB Error ({label}): {e}")

def main():
    print("Starting WEBGUI-BASED ALARM SYSTEM (60s cycle)...")
    while True:
        try:
            check_local() # Check WebGUI VM locally
            check_node_from_db(PRIMARY_TRAFFIC_DB, "PRIMARY NODE")
            check_node_from_db(SECONDARY_TRAFFIC_DB, "SECONDARY NODE")
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(60)

if __name__ == "__main__":
    main()
