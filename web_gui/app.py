from flask import Flask, render_template, request, jsonify, abort, session, send_file
import subprocess
import psutil
import socket
import re
import os
import time
import hashlib
import sqlite3
import threading
import json
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24) # Random secret key for session

# --- AUTHENTICATION ---
PASSWORD_FILE = '/home/dns/web_gui/.password.hash'
DEFAULT_PASSWORD = 'admin' # Default password if not set

def get_stored_password():
    if os.path.exists(PASSWORD_FILE):
        try:
            with open(PASSWORD_FILE, 'r') as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception as e:
            print(f"Error reading password file: {e}")
            
    # Default password: admin
    hashed = hashlib.sha256(DEFAULT_PASSWORD.encode()).hexdigest()
    try:
        with open(PASSWORD_FILE, 'w') as f:
            f.write(hashed)
        # Ensure correct ownership
        subprocess.run(['sudo', 'chown', 'dns:dns', PASSWORD_FILE])
    except Exception as e:
        print(f"Error writing default password: {e}")
    return hashed

def verify_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return hashed == get_stored_password()

def get_sync_token():
    # Use the first 16 chars of the hashed password as a sync token
    return get_stored_password()[:16]

@app.route('/api/sync/config')
def sync_config():
    token = request.args.get('token')
    if not token or token != get_sync_token():
        return jsonify({'status': 'error', 'message': 'Invalid sync token'}), 401
    
    # Track sync activity
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        remote_ip = request.remote_addr
        c.execute("UPDATE cluster_status SET value = ? WHERE key = 'last_sync_received'", (now,))
        c.execute("UPDATE cluster_status SET value = ? WHERE key = 'secondary_ip'", (remote_ip,))
        conn.commit()
        conn.close()
    except:
        pass

    # Collect essential config files for secondary sync
    configs = {}
    files_to_sync = {
        'blacklist': '/etc/dnsmasq.d/blacklist.conf',
        'whitelist_dnsmasq': '/etc/dnsmasq.d/whitelist.conf',
        'upstream': '/etc/dnsmasq.d/upstream.conf',
        'alias': '/etc/dnsmasq.d/alias.conf',
        'whitelist_firewall': '/home/dns/whitelist.conf'
    }
    
    for key, path in files_to_sync.items():
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    configs[key] = f.read()
            except:
                configs[key] = ""
        else:
            configs[key] = ""
            
    return jsonify({
        'status': 'success',
        'timestamp': datetime.now().isoformat(),
        'configs': configs
    })

def is_authenticated():
    return session.get('authenticated', False)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    password = data.get('password')
    stored_hash = get_stored_password()
    input_hash = hashlib.sha256(password.encode()).hexdigest()
    
    print(f"DEBUG LOGIN: Input='{password}', InputHash='{input_hash}', StoredHash='{stored_hash}'")
    
    if input_hash == stored_hash:
        session['authenticated'] = True
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Invalid password'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('authenticated', None)
    return jsonify({'status': 'success'})

@app.route('/api/check_auth')
def check_auth():
    return jsonify({'authenticated': is_authenticated()})

@app.route('/api/change_password', methods=['POST'])
def change_password():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    data = request.json
    new_password = data.get('new_password')
    if not new_password or len(new_password) < 4:
        return jsonify({'status': 'error', 'message': 'Password too short'}), 400
    
    hashed = hashlib.sha256(new_password.encode()).hexdigest()
    with open(PASSWORD_FILE, 'w') as f:
        f.write(hashed)
    return jsonify({'status': 'success'})

def get_server_ip():
    try:
        # Try ens18 or default route
        cmd = "ip route get 1.1.1.1 | grep -oP 'src \K\S+'"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.stdout.strip():
            return res.stdout.strip()
    except:
        pass
    return "127.0.0.1"

# --- WAF & SECURITY LAYER ---
def get_allowed_ips():
    allowed = ['127.0.0.1', get_server_ip()]
    whitelist_path = '/home/dns/whitelist.conf'
    if os.path.exists(whitelist_path):
        try:
            with open(whitelist_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        allowed.append(line)
        except:
            pass
    return list(set(allowed))

def check_ip():
    client_ip = request.remote_addr
    # Also check X-Forwarded-For if behind a proxy
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0]
    
    allowed_ips = get_allowed_ips()
    
    # Check direct IP match
    if client_ip in allowed_ips:
        return True
        
    # Check subnet match
    try:
        import ipaddress
        client_obj = ipaddress.ip_address(client_ip)
        for entry in allowed_ips:
            if '/' in entry:
                if client_obj in ipaddress.ip_network(entry):
                    return True
    except:
        pass
        
    print(f"DEBUG: Connection attempt from {client_ip} REJECTED")
    return False

def waf_check():
    # Basic protection against common attacks
    path = request.path
    
    # Patterns for SQLi, XSS, Path Traversal
    patterns = [
        r"(['\"%27])", # Single/Double quotes or encoded
        r"(--|%23|#)", # SQL comments
        r"(<script|script>|alert\()", # XSS
        r"(\.\.\/|\.\.\\)", # Path Traversal
        r"(UNION\s+SELECT|SELECT.*FROM|INSERT\s+INTO|DELETE\s+FROM|DROP\s+TABLE)", # SQLi keywords
        r"(eval\(|exec\(|system\()", # RCE
    ]

    # 1. Check Path (only for traversal)
    if re.search(r"(\.\.\/|\.\.\\)", path):
        return True

    # 2. Check Query Parameters (Values only)
    for key, value in request.args.items():
        for pattern in patterns:
            if re.search(pattern, str(value), re.IGNORECASE) or re.search(pattern, str(key), re.IGNORECASE):
                return True

    # 3. Check Request Body
    try:
        data = request.get_data().decode('utf-8', errors='ignore')
        if data:
            for pattern in patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    return True
    except:
        pass

    return False

@app.before_request
def before_request():
    # if not check_ip():
    #     return jsonify({'status': 'error', 'message': 'Access Denied: Your IP is not whitelisted'}), 403
    pass
    
    # Exclude API endpoints from WAF check (prevent false positives blocking Web GUI)
    if request.path.startswith('/api/'):
        # Allow all API paths - WAF patterns can block valid JSON/query params
        return
    if request.path.startswith('/static/') or request.path == '/favicon.ico' or request.path == '/health':
        return

    if waf_check():
        print(f"WAF BLOCK: Path={request.path}, Body={request.get_data().decode('utf-8', errors='ignore')}")
        return jsonify({'status': 'error', 'message': 'Security Block: Malicious activity detected'}), 403

# --- END WAF ---

# Simple in-memory storage for traffic stats
traffic_data = []

def get_traffic_stats():
    try:
        # ISP Scale QPS: Use a 5-second sliding window
        now = datetime.now()
        total_queries = 0
        window_size = 5
        
        # Increase tail for ISP scale (200k lines handles up to 40k QPS over 5s)
        # Assuming avg 20k QPS * 5s = 100k lines. Using 200k for safety margin.
        cmd = "sudo tail -n 200000 /var/log/dnsmasq.log | grep 'query\\['"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        
        if not result:
            return 0, 0
            
        lines = result.split('\n')
        
        # Count queries within the window
        for line in reversed(lines): # Start from newest for speed
            try:
                parts = line.split()
                if len(parts) < 3: continue
                time_str = parts[2]
                
                log_time = datetime.strptime(time_str, '%H:%M:%S').replace(year=now.year, month=now.month, day=now.day)
                diff = (now - log_time).total_seconds()
                
                if diff <= window_size:
                    total_queries += 1
                elif diff > window_size + 2: # Buffer for slight time drift
                    break # Optimization: stop if we are way past the window
            except:
                continue
                
        qps = round(total_queries / window_size, 1)
        snapshot = len(lines)
        
        return qps, snapshot
    except Exception as e:
        print(f"Error in get_traffic_stats: {e}")
        return 0, 0

def get_per_ip_traffic_stats(limit=20):
    """
    Get top IPs by query count in last 5 minutes
    Returns: {ip: queries, rate_limit_status}
    """
    try:
        cmd = f"sudo tail -n 50000 /var/log/dnsmasq.log | grep 'query\\[' | awk '{{print $6}}' | cut -d'#' -f1 | sort | uniq -c | sort -rn | head -n {limit}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        
        if not result:
            return []
        
        per_ip_data = []
        for line in result.split('\n'):
            try:
                parts = line.strip().split()
                if len(parts) >= 2:
                    count = int(parts[0])
                    ip = parts[1]
                    
                    # Check if IP is rate-limited (very high query spike)
                    rate_limit_status = "normal"
                    if count > 10000:  # More than 10000 queries in 5 min window = ~2000 QPS
                        rate_limit_status = "high"
                    elif count > 5000:  # More than 5000 = ~1000 QPS
                        rate_limit_status = "elevated"
                    
                    per_ip_data.append({
                        'ip': ip,
                        'queries': count,
                        'qps': round(count / 5, 1),  # Rough QPS estimate
                        'status': rate_limit_status
                    })
            except:
                continue
        
        return per_ip_data
    except Exception as e:
        print(f"Error in get_per_ip_traffic_stats: {e}")
        return []

def get_servfail_stats(limit=5):
    """
    Get SERVFAIL error statistics from dnsmasq logs
    Returns: [{'domain': domain, 'errors': count, 'percentage': pct}, ...]
    """
    try:
        # Get total queries in recent logs
        cmd_total = "sudo tail -n 100000 /var/log/dnsmasq.log | grep 'query\\[' | wc -l"
        total_result = subprocess.run(cmd_total, shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        total_queries = int(total_result) if total_result else 1
        
        # Get SERVFAIL errors by domain
        cmd = f"sudo tail -n 100000 /var/log/dnsmasq.log | grep 'reply is SERVFAIL' | awk '{{print $8}}' | cut -d'#' -f1 | sort | uniq -c | sort -rn | head -n {limit}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        
        if not result:
            return []
        
        servfail_data = []
        for line in result.split('\n'):
            try:
                parts = line.strip().split()
                if len(parts) >= 2:
                    count = int(parts[0])
                    domain = parts[1]
                    percentage = round((count / total_queries) * 100, 2) if total_queries > 0 else 0
                    
                    servfail_data.append({
                        'domain': domain,
                        'errors': count,
                        'percentage': percentage
                    })
            except:
                continue
        
        return servfail_data
    except Exception as e:
        print(f"Error in get_servfail_stats: {e}")
        return []

def get_blocklist_stats(limit=10):
    """
    Get blocklist hits from dnsmasq logs
    Tracks domains blocked by blacklist configuration
    Returns: [{'domain': domain, 'blocked': count, 'percentage': pct}, ...]
    """
    try:
        # Get total queries
        cmd_total = "sudo tail -n 100000 /var/log/dnsmasq.log | grep 'query\\[' | wc -l"
        total_result = subprocess.run(cmd_total, shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        total_queries = int(total_result) if total_result else 1
        
        # Find blocked domains (queries that were denied/replied with NXDOMAIN or 0.0.0.0)
        # dnsmasq marks blocked queries with specific patterns in logs
        cmd = f"sudo tail -n 100000 /var/log/dnsmasq.log | grep -E 'query\\[' | awk '{{print $6}}' | cut -d'#' -f1 | sort | uniq -c | sort -rn | head -n {limit}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        
        if not result:
            return []
        
        # Additional check for blocked entries (0.0.0.0 or 127.0.0.1 responses)
        cmd_blocked = f"sudo tail -n 100000 /var/log/dnsmasq.log | grep -E 'reply from |addresses' | grep -E '0\\.0\\.0\\.0|127\\.0\\.0\\.1' | awk '{{print $8}}' | cut -d'#' -f1 | sort | uniq -c | sort -rn | head -n {limit}"
        blocked_result = subprocess.run(cmd_blocked, shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        
        blocklist_data = []
        
        if blocked_result:
            for line in blocked_result.split('\n'):
                try:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        count = int(parts[0])
                        domain = parts[1]
                        percentage = round((count / total_queries) * 100, 2) if total_queries > 0 else 0
                        
                        blocklist_data.append({
                            'domain': domain,
                            'blocked': count,
                            'percentage': percentage
                        })
                except:
                    continue
        
        return blocklist_data[:limit]
    except Exception as e:
        print(f"Error in get_blocklist_stats: {e}")
        return []

# --- DNS SETTINGS MANAGEMENT ---

def read_dnsmasq_setting(key):
    """Read a setting from dnsmasq config files"""
    try:
        for config_file in ['/etc/dnsmasq.d/00-base.conf', '/etc/dnsmasq.conf']:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    for line in f:
                        if line.strip().startswith(key + '='):
                            value = line.split('=', 1)[1].strip()
                            return value
    except:
        pass
    return None

def read_unbound_setting(key):
    """Read a setting from unbound config files"""
    try:
        for config_file in ['/etc/unbound/unbound.conf.d/smartdns.conf']:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    for line in f:
                        if key + ':' in line and not line.strip().startswith('#'):
                            parts = line.split(':', 1)
                            if len(parts) > 1:
                                value = parts[1].strip()
                                return value
    except:
        pass
    return None

def get_dns_settings():
    """Get current DNS performance settings"""
    return {
        'dnsmasq': {
            'cache_size': read_dnsmasq_setting('cache-size') or '100000',
            'dns_forward_max': read_dnsmasq_setting('dns-forward-max') or '10000',
            'min_cache_ttl': read_dnsmasq_setting('min-cache-ttl') or '300',
            'max_cache_ttl': read_dnsmasq_setting('max-cache-ttl') or '86400',
        },
        'unbound': {
            'num_threads': read_unbound_setting('num-threads') or '8',
            'ratelimit': read_unbound_setting('ratelimit') or '50000',
            'ip_ratelimit': read_unbound_setting('ip-ratelimit') or '2000',
            'msg_cache_size': read_unbound_setting('msg-cache-size') or '100m',
            'rrset_cache_size': read_unbound_setting('rrset-cache-size') or '100m',
        },
        'limits': {
            'qps_alert_threshold': '200',  # Alert when > 200 QPS
            'max_allowed_qps': '2000',
            'cache_hit_target': '70',  # Target 70% cache hit rate
        }
    }

def update_dnsmasq_setting(key, value):
    """Update dnsmasq setting in config file"""
    try:
        config_file = '/etc/dnsmasq.d/00-base.conf'
        if not os.path.exists(config_file):
            return False
        
        with open(config_file, 'r') as f:
            lines = f.readlines()
        
        updated = False
        for i, line in enumerate(lines):
            if line.strip().startswith(key + '='):
                lines[i] = f"{key}={value}\n"
                updated = True
                break
        
        if not updated:
            lines.append(f"{key}={value}\n")
        
        with open(config_file, 'w') as f:
            f.writelines(lines)
        
        return True
    except Exception as e:
        print(f"Error updating dnsmasq setting: {e}")
        return False

def update_unbound_setting(key, value):
    """Update unbound setting in config file"""
    try:
        config_file = '/etc/unbound/unbound.conf.d/smartdns.conf'
        if not os.path.exists(config_file):
            return False
        
        with open(config_file, 'r') as f:
            lines = f.readlines()
        
        updated = False
        for i, line in enumerate(lines):
            if key + ':' in line and not line.strip().startswith('#'):
                indent = len(line) - len(line.lstrip())
                lines[i] = f"{' ' * indent}{key}: {value}\n"
                updated = True
                break
        
        if not updated:
            lines.append(f"    {key}: {value}\n")
        
        with open(config_file, 'w') as f:
            f.writelines(lines)
        
        return True
    except Exception as e:
        print(f"Error updating unbound setting: {e}")
        return False

def restart_dns_services():
    """Restart dnsmasq and unbound services"""
    try:
        # Test configs first
        test_dnsmasq = subprocess.run(['sudo', 'dnsmasq', '--test'], capture_output=True, text=True)
        if test_dnsmasq.returncode != 0:
            return {'status': 'error', 'message': 'Invalid dnsmasq config', 'detail': test_dnsmasq.stderr}
        
        test_unbound = subprocess.run(['unbound-checkconf'], capture_output=True, text=True)
        if test_unbound.returncode != 0:
            return {'status': 'error', 'message': 'Invalid unbound config', 'detail': test_unbound.stderr}
        
        # Restart services
        subprocess.run(['sudo', 'systemctl', 'restart', 'dnsmasq'], timeout=10)
        subprocess.run(['sudo', 'systemctl', 'restart', 'unbound'], timeout=10)
        
        time.sleep(2)
        return {'status': 'success', 'message': 'Services restarted successfully'}
    except Exception as e:
        return {'status': 'error', 'message': f'Error restarting services: {e}'}

# --- TRAFFIC HISTORY DB ---
DB_PATH = '/home/dns/traffic_history.db'

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS traffic 
                     (timestamp DATETIME PRIMARY KEY, qps REAL, queries INTEGER)''')
        c.execute('''CREATE TABLE IF NOT EXISTS cluster_status
                     (key TEXT PRIMARY KEY, value TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS trust_schedule
                     (id INTEGER PRIMARY KEY, enabled INTEGER, start_time TEXT, end_time TEXT, trust_ips TEXT)''')
        
        # Default schedule (disabled, 00:00 to 00:00, default IPs)
        c.execute("INSERT OR IGNORE INTO trust_schedule (id, enabled, start_time, end_time, trust_ips) VALUES (1, 0, '00:00', '00:00', '8.8.8.8, 1.1.1.1')")
        
        # Default role is PRIMARY
        c.execute("INSERT OR IGNORE INTO cluster_status (key, value) VALUES ('role', 'PRIMARY')")
        c.execute("INSERT OR IGNORE INTO cluster_status (key, value) VALUES ('last_sync_received', 'Never')")
        c.execute("INSERT OR IGNORE INTO cluster_status (key, value) VALUES ('secondary_ip', 'None')")
        
        conn.commit()
        conn.close()
        # Set permissions
        subprocess.run(['sudo', 'chown', 'dns:dns', DB_PATH])
    except Exception as e:
        print(f"DB Init Error: {e}")

init_db()

def background_collector():
    # Delay start to let system stabilize
    time.sleep(10)
    while True:
        try:
            qps, snapshot = get_traffic_stats()
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            # Store data with minute-level precision (every 5 mins)
            timestamp = datetime.now().replace(second=0, microsecond=0).strftime('%Y-%m-%d %H:%M:%S')
            c.execute("INSERT OR REPLACE INTO traffic (timestamp, qps, queries) VALUES (?, ?, ?)", 
                      (timestamp, qps, snapshot))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Background collector error: {e}")
        time.sleep(300) # Record every 5 minutes

# Start background thread
collector_thread = threading.Thread(target=background_collector, daemon=True)
collector_thread.start()

@app.route('/api/traffic/history')
def traffic_history():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    range_type = request.args.get('range', 'daily') # daily, monthly, yearly
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    if range_type == 'monthly':
        # Daily averages for last 30 days
        c.execute('''SELECT strftime('%m-%d', timestamp) as day, AVG(qps), MAX(queries)
                     FROM traffic 
                     WHERE timestamp >= date('now', '-30 days')
                     GROUP BY day ORDER BY timestamp ASC''')
    elif range_type == 'yearly':
        # Monthly averages for last 12 months
        c.execute('''SELECT strftime('%Y-%m', timestamp) as month, AVG(qps), MAX(queries)
                     FROM traffic 
                     WHERE timestamp >= date('now', '-1 year')
                     GROUP BY month ORDER BY timestamp ASC''')
    else:
        # Last 24 hours (hourly averages)
        c.execute('''SELECT strftime('%H:00', timestamp) as hour, AVG(qps), MAX(queries)
                     FROM traffic 
                     WHERE timestamp >= datetime('now', '-24 hours')
                     GROUP BY hour ORDER BY timestamp ASC''')
    
    rows = c.fetchall()
    conn.close()
    
    result = []
    for r in rows:
        result.append({
            'time': r[0],
            'qps': round(r[1], 1),
            'queries': int(r[2])
        })
    return jsonify(result)

@app.route('/api/traffic')
def traffic():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    global traffic_data
    current_time = datetime.now().strftime('%H:%M:%S')
    qps, snapshot = get_traffic_stats()
    
    traffic_data.append({
        'time': current_time, 
        'qps': qps,
        'queries': snapshot
    })
    
    if len(traffic_data) > 20:
        traffic_data.pop(0)
        
    return jsonify(traffic_data)

@app.route('/api/traffic/per-ip')
def traffic_per_ip():
    """Get per-IP traffic analysis for high-performance monitoring"""
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    limit = request.args.get('limit', 20, type=int)
    per_ip_data = get_per_ip_traffic_stats(limit=limit)
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'overall': {
            'qps': get_traffic_stats()[0],
            'total_ips': len(per_ip_data)
        },
        'top_ips': per_ip_data,
        'rate_limits': {
            'global': '100000 QPS',
            'per_ip': '20000 QPS',
            'com_domain': '5000 QPS'
        }
    })

@app.route('/api/traffic/servfail')
def traffic_servfail():
    """Get SERVFAIL error statistics"""
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    limit = request.args.get('limit', 5, type=int)
    servfail_data = get_servfail_stats(limit=limit)
    
    # Calculate total SERVFAIL count
    total_servfail = sum(item['errors'] for item in servfail_data)
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_servfail_errors': total_servfail,
            'affected_domains': len(servfail_data),
            'error_rate': f"{sum(item['percentage'] for item in servfail_data):.2f}%"
        },
        'top_domains': servfail_data
    })

@app.route('/api/traffic/blocklist')
def traffic_blocklist():
    """Get blocklist hits and blocked domains"""
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    limit = request.args.get('limit', 10, type=int)
    blocklist_data = get_blocklist_stats(limit=limit)
    
    # Calculate total blocked count
    total_blocked = sum(item['blocked'] for item in blocklist_data)
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_blocked': total_blocked,
            'blocked_domains': len(blocklist_data),
            'block_rate': f"{sum(item['percentage'] for item in blocklist_data):.2f}%"
        },
        'top_domains': blocklist_data
    })

def get_service_status(service_name):
    try:
        result = subprocess.run(['systemctl', 'is-active', service_name], capture_output=True, text=True)
        return result.stdout.strip() == 'active'
    except:
        return False

def run_command(command, timeout=30):
    return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)

def safe_service_restart():
    """
    ISP-Scale Safety: Test configurations before restarting services.
    If a config is invalid, do NOT restart and return the error.
    """
    # 1. Test Dnsmasq
    test_dnsmasq = run_command("sudo dnsmasq --test")
    if test_dnsmasq.returncode != 0:
        return False, f"Dnsmasq config error: {test_dnsmasq.stderr.strip()}"
    
    # 2. Test Unbound
    test_unbound = run_command("sudo unbound-checkconf")
    if test_unbound.returncode != 0:
        return False, f"Unbound config error: {test_unbound.stderr.strip()}"
    
    # 3. Restart if all good
    run_command("sudo systemctl restart dnsmasq")
    run_command("sudo systemctl restart unbound")
    return True, "Services restarted successfully"

@app.route('/health')
def health():
    """Simple health check for monitoring (no auth required)"""
    return jsonify({'status': 'ok', 'service': 'dnsmars-gui'}), 200

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/manual/pdf')
def download_manual_pdf():
    # Public access for manual
    path = "/home/dns/web_gui/static/manual.pdf"
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name="Buku_Panduan_DNS_MarsData.pdf")
    return jsonify({'status': 'error', 'message': 'File not found'}), 404

@app.route('/api/manual/html')
def view_manual_html():
    # Public access for manual
    # Generate HTML from Markdown on the fly for latest content
    try:
        import markdown
        with open("/home/dns/PANDUAN_SISTEM.md", "r") as f:
            content = f.read()
        html_content = markdown.markdown(content, extensions=['extra', 'codehilite'])
        
        # Add basic styling to make it look good
        styled_html = f"""
        <html>
        <head>
            <title>Manual - PT MARS DATA TELEKOMUNIKASI</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
            <style>
                body {{ font-family: 'Inter', sans-serif; line-height: 1.6; max-width: 800px; margin: 40px auto; padding: 0 20px; color: #333; }}
                h1, h2 {{ color: #003399; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
                h3 {{ color: #0044cc; margin-top: 30px; }}
                code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; font-family: monospace; }}
                pre {{ background: #f4f4f4; padding: 15px; border-radius: 8px; overflow-x: auto; border: 1px solid #ddd; }}
                hr {{ border: 0; border-top: 1px solid #eee; margin: 40px 0; }}
                .footer {{ margin-top: 50px; font-size: 0.8em; color: #777; text-align: center; border-top: 1px solid #eee; padding-top: 20px; }}
            </style>
        </head>
        <body>
            {html_content}
            <div class="footer">
                &copy; 2026 PT MARS DATA TELEKOMUNIKASI
            </div>
        </body>
        </html>
        """
        return styled_html
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error generating HTML: {e}'}), 500

def get_iptables_status():
    try:
        # Check for NAT redirection in both IPv4 and IPv6
        nat_v4 = subprocess.run(['sudo', 'iptables', '-t', 'nat', '-L', 'PREROUTING', '-n'], capture_output=True, text=True)
        nat_v6 = subprocess.run(['sudo', 'ip6tables', '-t', 'nat', '-L', 'PREROUTING', '-n'], capture_output=True, text=True)
        
        # Use iptables-save for more reliable module detection (hashlimit, connlimit)
        save_res = subprocess.run(['sudo', 'iptables-save'], capture_output=True, text=True)
        
        # NAT is considered active if REDIRECT exists in either IPv4 or IPv6
        is_nat_active = 'REDIRECT' in nat_v4.stdout or 'REDIRECT' in nat_v6.stdout
        
        return {
            'nat': is_nat_active,
            'flood_prot': 'hashlimit' in save_res.stdout,
            'conn_limit': 'connlimit' in save_res.stdout
        }
    except:
        return {'nat': False, 'flood_prot': False, 'conn_limit': False}

def get_dns_performance():
    try:
        # Measure response time for local query
        start = time.time()
        subprocess.run(['dig', '@127.0.0.1', 'google.com', '+short'], capture_output=True, timeout=2)
        end = time.time()
        latency = (end - start) * 1000
        # Performance percentage: 100% if < 10ms, drops as latency increases
        perf = max(0, min(100, 100 - (latency - 10) / 2)) if latency > 10 else 100
        return round(perf, 1)
    except:
        return 0

def get_network_info():
    try:
        import yaml
        with open('/etc/netplan/00-installer-config.yaml', 'r') as f:
            config = yaml.safe_load(f)
            
        ip4 = ""
        ip4_gw = ""
        ip6 = ""
        ip6_gw = ""
        
        if 'network' in config and 'ethernets' in config['network']:
            ifname = list(config['network']['ethernets'].keys())[0]
            iface = config['network']['ethernets'][ifname]
            
            # Extract addresses
            for addr in iface.get('addresses', []):
                if ':' in addr:
                    ip6 = addr
                else:
                    ip4 = addr
            
            # Extract gateways (from routes)
            for route in iface.get('routes', []):
                if route.get('to') == 'default':
                    via = route.get('via', '')
                    if ':' in via:
                        ip6_gw = via
                    else:
                        ip4_gw = via
        
        return {
            'ip4': ip4,
            'ip4_gw': ip4_gw,
            'ip6': ip6,
            'ip6_gw': ip6_gw,
            'ipv6_enabled': bool(ip6)
        }
    except Exception as e:
        print(f"Error reading netplan: {e}")
        # Try reading via sudo cat if direct read fails
        try:
            res = subprocess.run(['sudo', 'cat', '/etc/netplan/00-installer-config.yaml'], capture_output=True, text=True)
            if res.returncode == 0:
                config = yaml.safe_load(res.stdout)
                ip4 = ""
                ip4_gw = ""
                ip6 = ""
                ip6_gw = ""
                
                if 'network' in config and 'ethernets' in config['network']:
                    ifname = list(config['network']['ethernets'].keys())[0]
                    iface = config['network']['ethernets'][ifname]
                    for addr in iface.get('addresses', []):
                        if ':' in addr: ip6 = addr
                        else: ip4 = addr
                    for route in iface.get('routes', []):
                        if route.get('to') == 'default':
                            via = route.get('via', '')
                            if ':' in via: ip6_gw = via
                            else: ip4_gw = via
                return {'ip4': ip4, 'ip4_gw': ip4_gw, 'ip6': ip6, 'ip6_gw': ip6_gw, 'ipv6_enabled': bool(ip6)}
        except: pass
        return {'ip4': '', 'ip4_gw': '', 'ip6': '', 'ip6_gw': '', 'ipv6_enabled': False}

def get_trust_info():
    try:
        # ISP Scale: Read from /etc/dnsmasq.d/upstream.conf
        path = '/etc/dnsmasq.d/upstream.conf'
        if os.path.exists(path):
            with open(path, 'r') as f:
                content = f.read()
                # Extract all server= lines
                ips = re.findall(r'^server=([\d.]+)', content, re.MULTILINE)
                
                # Filter out default upstreams to determine if "Trust" (custom DNS) is actually active
                defaults = ['8.8.8.8', '1.1.1.1']
                trust_ips = [ip for ip in ips if ip not in defaults]
                
                if trust_ips:
                    return {'enabled': True, 'ip': ', '.join(trust_ips)}
        return {'enabled': False, 'ip': ''}
    except:
        return {'enabled': False, 'ip': ''}

@app.route('/api/status')
def status():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    fw_status = get_iptables_status()
    cpu_usage = psutil.cpu_percent()
    ram_usage = psutil.virtual_memory().percent
    dns_perf = get_dns_performance()
    net_info = get_network_info()
    trust_info = get_trust_info()
    
    # Check DNSSEC status
    dnssec_active = False
    try:
        # Check if proxy-dnssec is in any dnsmasq config
        # ISP Scale: check 00-base.conf
        base_conf = "/etc/dnsmasq.d/00-base.conf"
        if os.path.exists(base_conf):
            with open(base_conf, 'r') as f:
                if 'proxy-dnssec' in f.read():
                    dnssec_active = True
    except:
        pass

    # Guardian Logs
    guardian_logs = []
    if os.path.exists('/home/dns/guardian.log'):
        try:
            with open('/home/dns/guardian.log', 'r') as f:
                guardian_logs = f.readlines()[-5:] # Last 5 events
        except:
            pass
            
    # Whitelist info
    whitelist = []
    if os.path.exists('/home/dns/whitelist.conf'):
        try:
            with open('/home/dns/whitelist.conf', 'r') as f:
                whitelist = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
        except:
            pass

    # HDD Usage
    hdd_usage = 0
    try:
        hdd = psutil.disk_usage('/')
        hdd_usage = hdd.percent
    except:
        pass

    return jsonify({
        'dnsmasq': get_service_status('dnsmasq'),
        'unbound': get_service_status('unbound'),
        'dnssec': dnssec_active,
        'resolved': get_service_status('systemd-resolved'),
        'guardian': get_service_status('guardian'),
        'iptables': fw_status['nat'],
        'security': {
            'flood_protection': fw_status['flood_prot'],
            'connection_limit': fw_status['conn_limit'],
            'guardian_logs': guardian_logs,
            'whitelist': whitelist
        },
        'metrics': {
            'cpu': cpu_usage,
            'ram': ram_usage,
            'hdd': hdd_usage,
            'dns_perf': dns_perf
        },
        'network': net_info,
        'trust': trust_info
    })

def get_system_ips():
    ips = {'ipv4': [], 'ipv6': []}
    try:
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            if iface == 'lo': continue
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ips['ipv4'].append(addr.address)
                elif addr.family == socket.AF_INET6:
                    # Ignore link-local addresses
                    if not addr.address.startswith('fe80'):
                        ips['ipv6'].append(addr.address)
    except Exception as e:
        print(f"Error getting system IPs: {e}")
    return ips

@app.route('/api/dig', methods=['POST'])
def dig():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    data = request.json
    domain = data.get('domain', 'google.com')
    qtype = data.get('qtype', 'A')
    
    domain = re.sub(r'[^a-zA-Z0-9.-]', '', domain)
    if qtype not in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
        qtype = 'A'
        
    system_ips = get_system_ips()
    # Unique targets starting with loopbacks
    targets = []
    for t in ['127.0.0.1', '::1']:
        if t not in targets: targets.append(t)
    for t in system_ips['ipv4'] + system_ips['ipv6']:
        if t not in targets: targets.append(t)
    
    results = []
    for target in targets:
        dig_target = f"@{target}"
        cmd = f"dig {dig_target} {domain} {qtype} +short +time=1 +tries=1"
        try:
            proc = run_command(cmd)
            output = (proc.stdout or '').strip()
            full_output = (proc.stderr or '') + (proc.stdout or '')
        except subprocess.TimeoutExpired:
            output = "TIMEOUT"
            full_output = "timeout"
        except Exception as e:
            output = ""
            full_output = str(e)
        
        # If +short is empty, try without +short to see if there's an error
        if not output:
            full_cmd = f"dig {dig_target} {domain} {qtype} +time=1 +tries=1"
            try:
                proc2 = run_command(full_cmd)
                full_output = (proc2.stdout or '') + (proc2.stderr or '')
            except Exception:
                full_output = ""
            if "connection timed out" in full_output.lower():
                output = "TIMEOUT"
            elif "communications error" in full_output.lower() or "connection refused" in full_output.lower():
                output = "CONNECTION REFUSED"
            elif "network is unreachable" in full_output.lower():
                output = "NETWORK UNREACHABLE"
            else:
                output = "NO RECORD" if not output else output
                
        results.append(f"[{target}] -> {output}")
        
    return jsonify({'result': "\n".join(results)})

@app.route('/api/list/<list_type>', methods=['GET'])
def list_domains(list_type):
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    file_path = ""
    if list_type == 'blacklist':
        file_path = "/etc/dnsmasq.d/blacklist.conf"
    elif list_type == 'whitelist':
        file_path = "/etc/dnsmasq.d/whitelist.conf"
    else:
        return jsonify({'status': 'error', 'message': 'Invalid list type'}), 400
        
    domains = []
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    # Format for blacklist: address=/domain/0.0.0.0
                    # Format for whitelist: server=/domain/8.8.8.8
                    match = re.search(r'/(.*?)/', line)
                    if match:
                        domains.append(match.group(1))
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
            
    return jsonify({'status': 'success', 'domains': domains})

@app.route('/api/action', methods=['POST'])
def action():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    data = request.json
    cmd_type = data.get('type')
    domain = data.get('domain', '').strip()
    dns_ip = data.get('dns_ip', '').strip()
    ipv6_ip = data.get('ipv6_ip', '').strip()
    
    # Network fields
    ip4_addr = data.get('ip4_addr', '').strip()
    ip4_gw = data.get('ip4_gw', '').strip()
    ip6_addr = data.get('ip6_addr', '').strip()
    ip6_gw = data.get('ip6_gw', '').strip()
    ipv6_enabled = data.get('ipv6_enabled', False)
    
    # Trust fields
    trust_ip = data.get('trust_ip', '').strip()
    trust_enabled = data.get('trust_enabled', False)
    
    # Whitelist fields
    whitelist_data = data.get('whitelist', '').strip()
    
    # Sanitize domain
    if domain:
        domain = re.sub(r'[^a-zA-Z0-9.-]', '', domain)
    
    # Sanitize IPs
    if dns_ip:
        # Allow dots, numbers, spaces and commas for multiple IPs
        dns_ip = re.sub(r'[^0-9., ]', '', dns_ip)
    if ipv6_ip:
        ipv6_ip = re.sub(r'[^a-fA-F0-9:/, ]', '', ipv6_ip)
    if ip4_addr:
        ip4_addr = re.sub(r'[^0-9./]', '', ip4_addr)
    if ip4_gw:
        ip4_gw = re.sub(r'[^0-9.]', '', ip4_gw)
    if ip6_addr:
        ip6_addr = re.sub(r'[^a-fA-F0-9:/]', '', ip6_addr)
    if ip6_gw:
        ip6_gw = re.sub(r'[^a-fA-F0-9:]', '', ip6_gw)
    if trust_ip:
        trust_ip = re.sub(r'[^0-9.]', '', trust_ip)
        
    if cmd_type == 'update_whitelist':
        try:
            # Lines can be IPs or Subnets
            lines = [l.strip() for l in whitelist_data.split('\n') if l.strip()]
            content = "# Dynamic Whitelist Configuration\n# Format: IP or Subnet (one per line)\n"
            content += "\n".join(lines)
            
            with open('/home/dns/whitelist.conf', 'w') as f:
                f.write(content)
            
            # Apply to firewall and restart guardian
            run_command("sudo /home/dns/setup_firewall.sh")
            run_command("sudo systemctl restart guardian")
            return jsonify({'status': 'success', 'message': 'Whitelist updated successfully'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})

    elif cmd_type == 'restart_dnsmasq':
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
    elif cmd_type == 'restart_unbound':
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
    elif cmd_type == 'clear_cache':
        run_command("sudo unbound-control flush_zone .")
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
    elif cmd_type == 'blacklist' and domain:
        # Redirect to 0.0.0.0 or Server IP
        action_val = data.get('action', 'add')
        if action_val == 'add':
            server_ip = get_server_ip()
            run_command(f"echo 'address=/{domain}/{server_ip}' | sudo tee -a /etc/dnsmasq.d/blacklist.conf")
        elif action_val == 'remove':
            # Use a more flexible regex to remove the domain regardless of the IP it points to
            run_command(f"sudo sed -i '/address=\/{domain}\//d' /etc/dnsmasq.d/blacklist.conf")
        
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
        return jsonify({'status': 'success', 'message': f'Domain {domain} {"blacklisted" if action_val=="add" else "removed from blacklist"}'})

    elif cmd_type == 'whitelist' and domain:
        action_val = data.get('action', 'add')
        if action_val == 'add':
            # 1. Remove from blacklist if exists
            blacklist_path = "/etc/dnsmasq.d/blacklist.conf"
            if os.path.exists(blacklist_path):
                run_command(f"sudo sed -i '/address=\/{domain}\//d' {blacklist_path}")
            
            # 2. Add to whitelist.conf with a stable public DNS (8.8.8.8)
            run_command(f"echo 'server=/{domain}/8.8.8.8' | sudo tee -a /etc/dnsmasq.d/whitelist.conf")
        elif action_val == 'remove':
            run_command(f"sudo sed -i '/server=\/{domain}\//d' /etc/dnsmasq.d/whitelist.conf")
            
        # 3. Restart services safely
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
        return jsonify({'status': 'success', 'message': f'Domain {domain} {"whitelisted" if action_val=="add" else "removed from whitelist"}'})
    elif cmd_type == 'update_ssh':
        run_command("sudo apt-get update && sudo apt-get install --only-upgrade openssh-server -y")
    elif cmd_type == 'update_firewall':
        run_command("sudo chmod +x /home/dns/setup_firewall.sh && sudo /home/dns/setup_firewall.sh")
    elif cmd_type == 'malware_shield':
        # Redirect malware domains to 0.0.0.0
        cmd = f"curl -s https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | grep '^0.0.0.0' | awk '{{print \"address=/\"$2\"/0.0.0.0\"}}' | sudo tee /etc/dnsmasq.d/malware.conf > /dev/null"
        run_command(cmd)
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
    elif cmd_type == 'change_dns' and dns_ip:
        # Support multiple IPs separated by comma or space
        ips = re.split(r'[,\s]+', dns_ip)
        forward_lines = "\n".join([f"    forward-addr: {ip.strip()}" for ip in ips if ip.strip()])
        forward_conf = f"forward-zone:\n    name: \".\"\n{forward_lines}\n"
        run_command(f"echo '{forward_conf}' | sudo tee /etc/unbound/unbound.conf.d/forward.conf")
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
    elif cmd_type == 'update_network':
        try:
            import yaml
            # Load existing config
            config = None
            try:
                with open('/etc/netplan/00-installer-config.yaml', 'r') as f:
                    config = yaml.safe_load(f)
            except:
                res = subprocess.run(['sudo', 'cat', '/etc/netplan/00-installer-config.yaml'], capture_output=True, text=True)
                if res.returncode == 0:
                    config = yaml.safe_load(res.stdout)
            
            if not config:
                return jsonify({'status': 'error', 'message': 'Could not read netplan config'})
            
            # Find the first ethernet interface
            if 'network' in config and 'ethernets' in config['network']:
                ifname = list(config['network']['ethernets'].keys())[0]
                iface = config['network']['ethernets'][ifname]
                
                # Update addresses with validation
                def validate_cidr(addr, max_prefix):
                    if '/' in addr:
                        parts = addr.split('/')
                        if len(parts) == 2:
                            try:
                                prefix = int(parts[1])
                                if 0 <= prefix <= max_prefix:
                                    return addr
                            except ValueError:
                                pass
                    return None

                ip4_with_cidr = validate_cidr(ip4_addr, 32) or (f"{ip4_addr}/24" if '/' not in ip4_addr else None)
                if not ip4_with_cidr:
                    return jsonify({'status': 'error', 'message': f'Invalid IPv4 prefix length in {ip4_addr}'})
                
                new_addrs = [ip4_with_cidr]
                
                if ipv6_enabled and ip6_addr:
                    ip6_with_cidr = validate_cidr(ip6_addr, 128) or (f"{ip6_addr}/64" if '/' not in ip6_addr else None)
                    if not ip6_with_cidr:
                        return jsonify({'status': 'error', 'message': f'Invalid IPv6 prefix length in {ip6_addr}'})
                    new_addrs.append(ip6_with_cidr)
                
                iface['addresses'] = new_addrs
                
                # Update routes
                new_routes = [{'to': 'default', 'via': ip4_gw}]
                if ipv6_enabled and ip6_gw:
                    new_routes.append({'to': 'default', 'via': ip6_gw})
                iface['routes'] = new_routes
                
                # Write to temp file
                temp_yaml = '/home/dns/new_netplan.yaml'
                with open(temp_yaml, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False)
                
                # Apply changes
                # Netplan apply can be slow and might disconnect, so we use a longer timeout or no timeout
                cmd = f"sudo mv {temp_yaml} /etc/netplan/00-installer-config.yaml && sudo chmod 600 /etc/netplan/00-installer-config.yaml && sudo netplan apply"
                apply_res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if apply_res.returncode != 0:
                    return jsonify({'status': 'error', 'message': f'Netplan apply failed: {apply_res.stderr}'})
                
                # Update system via central script
                run_command(f"sudo bash /home/dns/update_system_ip.sh")
                
                return jsonify({'status': 'success', 'message': 'Network settings updated. System is restarting with new IP.'})
            else:
                return jsonify({'status': 'error', 'message': 'Invalid netplan structure'})
                
        except Exception as e:
            print(f"Network update error: {e}")
            return jsonify({'status': 'error', 'message': str(e)})
        
    elif cmd_type == 'toggle_ipv6':
        enabled = data.get('enabled', False)
        if enabled:
            run_command("sudo sed -i '/listen-address=127.0.0.1/s/$/,::1/' /home/dns/dnsmasq_smartdns.conf")
            run_command("sudo sed -i 's/do-ip6: no/do-ip6: yes/' /home/dns/unbound_smartdns.conf")
            run_command("sudo sed -i '/interface: 127.0.0.1/a \    interface: ::1' /home/dns/unbound_smartdns.conf")
        else:
            run_command("sudo sed -i 's/,::1//' /home/dns/dnsmasq_smartdns.conf")
            run_command("sudo sed -i 's/do-ip6: yes/do-ip6: no/' /home/dns/unbound_smartdns.conf")
            run_command("sudo sed -i '/interface: ::1/d' /home/dns/unbound_smartdns.conf")
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
        return jsonify({'status': 'success', 'message': 'IPv6 settings updated'})
    elif cmd_type == 'toggle_trust':
        # ISP Scale: Only manage upstreams in a separate file
        upstream_path = '/etc/dnsmasq.d/upstream.conf'
        if trust_enabled and trust_ip:
            # Support multiple IPs separated by comma or space
            ips = re.split(r'[,\s]+', trust_ip)
            # Add trust servers to dnsmasq upstream.conf
            dnsmasq_servers = "\n".join([f"server={ip.strip()}" for ip in ips if ip.strip()])
            
            # Use a temp file for dnsmasq upstream.conf
            with open('/home/dns/temp_upstream.conf', 'w') as f:
                f.write(dnsmasq_servers + "\n")
            run_command(f"sudo mv /home/dns/temp_upstream.conf {upstream_path}")
            
            # Also update Unbound to use trust servers
            forward_lines = "\n".join([f"    forward-addr: {ip.strip()}" for ip in ips if ip.strip()])
            forward_conf = f'forward-zone:\n    name: "."\n{forward_lines}\n'
            
            # Use a temp file to avoid echo escaping issues
            with open('/home/dns/temp_forward.conf', 'w') as f:
                f.write(forward_conf)
            run_command("sudo mv /home/dns/temp_forward.conf /etc/unbound/unbound.conf.d/forward.conf")
            
            # Re-enable aliases if they were disabled
            run_command("sudo sed -i 's/^#alias=/alias=/' /etc/dnsmasq.d/alias.conf")
            # KEEP filter-AAAA commented to support IPv6
            # run_command("sudo sed -i 's/^#filter-AAAA/filter-AAAA/' /etc/dnsmasq.d/alias.conf")
            
            # Apply firewall rules immediately
            run_command("sudo bash /home/dns/setup_firewall.sh")
            success, msg = safe_service_restart()
            if not success:
                return jsonify({'status': 'error', 'message': msg})
            return jsonify({'status': 'success', 'message': 'DNS Trust enabled and services restarted safely'})
        else:
            # Revert to default upstreams (Google/Cloudflare) in upstream.conf
            default_servers = "server=8.8.8.8\nserver=1.1.1.1\n"
            with open('/home/dns/temp_upstream.conf', 'w') as f:
                f.write(default_servers)
            run_command(f"sudo mv /home/dns/temp_upstream.conf {upstream_path}")
            
            # Revert Unbound to default
            forward_conf = 'forward-zone:\n    name: "."\n    forward-addr: 8.8.8.8\n    forward-addr: 1.1.1.1\n'
            with open('/home/dns/temp_forward.conf', 'w') as f:
                f.write(forward_conf)
            run_command("sudo mv /home/dns/temp_forward.conf /etc/unbound/unbound.conf.d/forward.conf")
            
            # Disable aliases to ensure no redirection to block pages (Internet Positif inactive)
            run_command("sudo sed -i 's/^alias=/#alias=/' /etc/dnsmasq.d/alias.conf")
            run_command("sudo sed -i 's/^filter-AAAA/#filter-AAAA/' /etc/dnsmasq.d/alias.conf")
            
            # Apply firewall rules immediately
            run_command("sudo bash /home/dns/setup_firewall.sh")
            success, msg = safe_service_restart()
            if not success:
                return jsonify({'status': 'error', 'message': msg})
            return jsonify({'status': 'success', 'message': 'DNS Trust disabled and services reverted safely'})
        
    return jsonify({'status': 'success'})

@app.route('/api/logs')
def logs():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    # Get last 20 lines of dnsmasq logs
    proc = run_command("sudo tail -n 20 /var/log/dnsmasq.log")
    logs = (proc.stdout or '').strip() if proc else ''
    return jsonify({'logs': logs})

@app.route('/api/banned_ips', methods=['GET'])
def get_banned_ips():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    banned_ips = []
    if os.path.exists('/home/dns/banned_ips.txt'):
        try:
            with open('/home/dns/banned_ips.txt', 'r') as f:
                banned_ips = list(set([line.strip() for line in f if line.strip()]))
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})
    
    return jsonify({'status': 'success', 'ips': banned_ips})

@app.route('/api/trust/schedule', methods=['GET', 'POST'])
def trust_schedule():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    if request.method == 'POST':
        data = request.json
        enabled = 1 if data.get('enabled') else 0
        start_time = data.get('start_time', '00:00')
        end_time = data.get('end_time', '00:00')
        trust_ips = data.get('trust_ips', '')
        
        c.execute("UPDATE trust_schedule SET enabled=?, start_time=?, end_time=?, trust_ips=? WHERE id=1",
                  (enabled, start_time, end_time, trust_ips))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Schedule updated'})
    
    c.execute("SELECT enabled, start_time, end_time, trust_ips FROM trust_schedule WHERE id=1")
    row = c.fetchone()
    conn.close()
    
    if row:
        return jsonify({
            'enabled': bool(row[0]),
            'start_time': row[1],
            'end_time': row[2],
            'trust_ips': row[3]
        })
    return jsonify({'status': 'error', 'message': 'No schedule found'}), 404

@app.route('/api/sync/info')
def sync_info():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT key, value FROM cluster_status")
    status = dict(c.fetchall())
    conn.close()
    
    return jsonify({
        'status': 'success',
        'sync_token': get_sync_token(),
        'primary_ip': get_server_ip(),
        'role': status.get('role', 'PRIMARY'),
        'last_sync': status.get('last_sync_received', 'Never'),
        'secondary_ip': status.get('secondary_ip', 'None')
    })

@app.route('/api/system/role', methods=['POST'])
def set_system_role():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    data = request.json
    role = data.get('role')
    if role not in ['PRIMARY', 'SECONDARY']:
        return jsonify({'status': 'error', 'message': 'Invalid role'}), 400
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE cluster_status SET value = ? WHERE key = 'role'", (role,))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success', 'role': role})

@app.route('/api/unblock_ip', methods=['POST'])
def unblock_ip():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    data = request.json
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'status': 'error', 'message': 'IP address is required'}), 400
    
    # Sanitize IP
    ip = re.sub(r'[^0-9.]', '', ip)
    
    try:
        # Remove from iptables
        run_command(f"sudo iptables -D INPUT -s {ip} -j DROP")
        
        # Remove from banned_ips.txt
        if os.path.exists('/home/dns/banned_ips.txt'):
            run_command(f"sudo sed -i '/^{ip}$/d' /home/dns/banned_ips.txt")
            
        return jsonify({'status': 'success', 'message': f'IP {ip} has been unblocked'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# --- GUARDIAN CONFIGURATION ---
GUARDIAN_CONFIG_FILE = "/home/dns/guardian_config.json"
DNSMASQ_CONFIG_FILE = "/home/dns/dnsmasq_smartdns.conf"

def read_dnsmasq_config():
    config = {}
    if os.path.exists(DNSMASQ_CONFIG_FILE):
        with open(DNSMASQ_CONFIG_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    parts = line.split('=', 1)
                    config[parts[0].strip()] = parts[1].strip()
    return config

def update_dnsmasq_config(new_settings):
    if not os.path.exists(DNSMASQ_CONFIG_FILE):
        return
    
    lines = []
    with open(DNSMASQ_CONFIG_FILE, 'r') as f:
        lines = f.readlines()
    
    with open(DNSMASQ_CONFIG_FILE, 'w') as f:
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('#') and '=' in stripped:
                key = stripped.split('=', 1)[0].strip()
                if key in new_settings:
                    f.write(f"{key}={new_settings[key]}\n")
                else:
                    f.write(line)
            else:
                f.write(line)
    
    # Reload dnsmasq
    subprocess.run("sudo systemctl restart dnsmasq", shell=True)

@app.route('/api/guardian/config', methods=['GET'])
def get_guardian_config():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    # Read Guardian Config
    guardian_config = {
        "ban_threshold": 10000,
        "malicious_threshold": 200
    }
    if os.path.exists(GUARDIAN_CONFIG_FILE):
        try:
            with open(GUARDIAN_CONFIG_FILE, 'r') as f:
                guardian_config.update(json.load(f))
        except:
            pass
            
    # Read DNSMasq Config
    dnsmasq_config = read_dnsmasq_config()
    
    return jsonify({
        'status': 'success',
        'guardian': guardian_config,
        'dnsmasq': {
            'dns_forward_max': dnsmasq_config.get('dns-forward-max', '1500'),
            'cache_size': dnsmasq_config.get('cache-size', '1000')
        }
    })

@app.route('/api/guardian/config', methods=['POST'])
def save_guardian_config():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    data = request.json
    
    # Save Guardian Config
    guardian_settings = {
        "ban_threshold": int(data.get('ban_threshold', 10000)),
        "malicious_threshold": int(data.get('malicious_threshold', 200))
    }
    
    try:
        with open(GUARDIAN_CONFIG_FILE, 'w') as f:
            json.dump(guardian_settings, f, indent=4)
        # Ensure correct ownership
        subprocess.run(['sudo', 'chown', 'dns:dns', GUARDIAN_CONFIG_FILE])
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error saving guardian config: {e}'}), 500
        
    # Save DNSMasq Config
    dnsmasq_settings = {}
    if 'dns_forward_max' in data:
        dnsmasq_settings['dns-forward-max'] = str(data['dns_forward_max'])
    if 'cache_size' in data:
        dnsmasq_settings['cache-size'] = str(data['cache_size'])
        
    if dnsmasq_settings:
        try:
            update_dnsmasq_config(dnsmasq_settings)
        except Exception as e:
             return jsonify({'status': 'error', 'message': f'Error saving dnsmasq config: {e}'}), 500
            
    return jsonify({'status': 'success', 'message': 'Configuration saved and applied'})

if __name__ == '__main__':
    # Use SSL context for HTTPS
    app.run(host='0.0.0.0', port=5000, ssl_context=('/home/dns/web_gui/cert.pem', '/home/dns/web_gui/key.pem'))
