from flask import Flask, render_template, request, jsonify, abort, session, send_file
import subprocess
import psutil
import socket
import re
import os
import time
import hashlib
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
    
    # Exclude auth, action, and dig endpoints from WAF
    if request.path in ['/api/login', '/api/change_password', '/api/action', '/api/dig']:
        return

    if waf_check():
        print(f"WAF BLOCK: Path={request.path}, Body={request.get_data().decode('utf-8', errors='ignore')}")
        return jsonify({'status': 'error', 'message': 'Security Block: Malicious activity detected'}), 403

# --- END WAF ---

# Simple in-memory storage for traffic stats
traffic_data = []

def get_traffic_stats():
    try:
        # Count queries in the last 60 seconds from dnsmasq log
        # This is a simplified version; in production, use a more efficient log parser or dnsmasq stats
        cmd = "sudo tail -n 500 /var/log/dnsmasq.log | grep 'query' | wc -l"
        count = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
        return int(count) if count else 0
    except:
        return 0

@app.route('/api/traffic')
def traffic():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    # Return last 20 data points
    global traffic_data
    current_time = datetime.now().strftime('%H:%M:%S')
    count = get_traffic_stats()
    
    traffic_data.append({'time': current_time, 'queries': count})
    if len(traffic_data) > 20:
        traffic_data.pop(0)
        
    return jsonify(traffic_data)

def get_service_status(service_name):
    try:
        result = subprocess.run(['systemctl', 'is-active', service_name], capture_output=True, text=True)
        return result.stdout.strip() == 'active'
    except:
        return False

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
        return result.stdout if result.stdout else result.stderr
    except Exception as e:
        return str(e)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/manual/pdf')
def download_manual_pdf():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    path = "/home/dns/Buku_Panduan_DNS_MarsData.pdf"
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return jsonify({'status': 'error', 'message': 'File not found'}), 404

@app.route('/api/manual/html')
def view_manual_html():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    path = "/home/dns/sistem_dns_marsdata.html"
    if os.path.exists(path):
        return send_file(path)
    return jsonify({'status': 'error', 'message': 'File not found'}), 404

def get_iptables_status():
    try:
        # Check for NAT redirection
        nat_res = subprocess.run(['sudo', 'iptables', '-t', 'nat', '-L', 'PREROUTING', '-n'], capture_output=True, text=True)
        # Use iptables-save for more reliable module detection (hashlimit, connlimit)
        save_res = subprocess.run(['sudo', 'iptables-save'], capture_output=True, text=True)
        
        return {
            'nat': 'REDIRECT' in nat_res.stdout,
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
        # Try direct read first
        path = '/etc/dnsmasq.d/trust.conf'
        if os.path.exists(path):
            with open(path, 'r') as f:
                lines = f.readlines()
                ips = [line.strip().replace('server=', '') for line in lines if line.strip().startswith('server=')]
                if ips:
                    return {'enabled': True, 'ip': ', '.join(ips)}
        
        # Try sudo cat if direct read fails or file not found by os.path
        res = subprocess.run(['sudo', 'cat', path], capture_output=True, text=True)
        if res.returncode == 0:
            lines = res.stdout.strip().split('\n')
            ips = [line.strip().replace('server=', '') for line in lines if line.strip().startswith('server=')]
            if ips:
                return {'enabled': True, 'ip': ', '.join(ips)}
                
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

    return jsonify({
        'dnsmasq': get_service_status('dnsmasq'),
        'unbound': get_service_status('unbound'),
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
        output = run_command(cmd).strip()
        
        # If +short is empty, try without +short to see if there's an error
        if not output:
            full_cmd = f"dig {dig_target} {domain} {qtype} +time=1 +tries=1"
            full_output = run_command(full_cmd).strip()
            if "connection timed out" in full_output.lower():
                output = "TIMEOUT"
            elif "communications error" in full_output.lower():
                output = "COMM ERROR"
            else:
                output = "NO RECORD"
                
        results.append(f"[{target}] -> {output}")
        
    return jsonify({'result': "\n".join(results)})

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
        run_command("sudo systemctl restart dnsmasq")
    elif cmd_type == 'restart_unbound':
        run_command("sudo systemctl restart unbound")
    elif cmd_type == 'clear_cache':
        run_command("sudo systemctl restart dnsmasq && sudo unbound-control flush_zone .")
    elif cmd_type == 'blacklist' and domain:
        # Redirect to local landing page (Internet Positif) using server IP
        server_ip = get_server_ip()
        action_val = data.get('action', 'add')
        if action_val == 'add':
            run_command(f"echo 'address=/{domain}/{server_ip}' | sudo tee -a /etc/dnsmasq.d/blacklist.conf && sudo systemctl restart dnsmasq")
        elif action_val == 'remove':
            run_command(f"sudo sed -i '/address=\/{domain}\/{server_ip}/d' /etc/dnsmasq.d/blacklist.conf && sudo systemctl restart dnsmasq")
    elif cmd_type == 'whitelist' and domain:
        # Use server=/domain/ to whitelist and forward to a public DNS
        run_command(f"echo 'server=/{domain}/1.1.1.1' | sudo tee -a /etc/dnsmasq.d/whitelist.conf && sudo systemctl restart dnsmasq")
    elif cmd_type == 'update_ssh':
        run_command("sudo apt-get update && sudo apt-get install --only-upgrade openssh-server -y")
    elif cmd_type == 'update_firewall':
        run_command("sudo chmod +x /home/dns/setup_firewall.sh && sudo /home/dns/setup_firewall.sh")
    elif cmd_type == 'malware_shield':
        # Redirect malware domains to landing page
        server_ip = get_server_ip()
        cmd = f"curl -s https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | grep '^0.0.0.0' | awk '{{print \"address=/\"$2\"/{server_ip}\"}}' | sudo tee /etc/dnsmasq.d/malware.conf > /dev/null && sudo systemctl restart dnsmasq"
        run_command(cmd)
    elif cmd_type == 'change_dns' and dns_ip:
        # Support multiple IPs separated by comma or space
        ips = re.split(r'[,\s]+', dns_ip)
        forward_lines = "\n".join([f"    forward-addr: {ip.strip()}" for ip in ips if ip.strip()])
        forward_conf = f"forward-zone:\n    name: \".\"\n{forward_lines}\n"
        run_command(f"echo '{forward_conf}' | sudo tee /etc/unbound/unbound.conf.d/forward.conf && sudo systemctl restart unbound")
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
        run_command("sudo systemctl restart dnsmasq && sudo systemctl restart unbound")
    elif cmd_type == 'toggle_trust':
        if trust_enabled and trust_ip:
            # Support multiple IPs separated by comma or space
            ips = re.split(r'[,\s]+', trust_ip)
            # Add trust servers to dnsmasq
            dnsmasq_servers = "\n".join([f"server={ip.strip()}" for ip in ips if ip.strip()])
            run_command(f"echo '{dnsmasq_servers}' | sudo tee /etc/dnsmasq.d/trust.conf")
            
            # Also update Unbound to use trust servers
            forward_lines = "\n".join([f"    forward-addr: {ip.strip()}" for ip in ips if ip.strip()])
            forward_conf = f'forward-zone:\n    name: "."\n{forward_lines}\n'
            
            # Use a temp file to avoid echo escaping issues
            with open('/home/dns/temp_forward.conf', 'w') as f:
                f.write(forward_conf)
            run_command("sudo mv /home/dns/temp_forward.conf /etc/unbound/unbound.conf.d/forward.conf")
            # Re-enable aliases if they were disabled
            run_command("sudo sed -i 's/^#*alias=/alias=/' /home/dns/dnsmasq_smartdns.conf")
            run_command("sudo systemctl restart dnsmasq && sudo systemctl restart unbound")
        else:
            # Remove trust server from dnsmasq
            run_command("sudo rm -f /etc/dnsmasq.d/trust.conf")
            # Revert Unbound to default (8.8.8.8) when trust is disabled
            forward_conf = 'forward-zone:\n    name: "."\n    forward-addr: 8.8.8.8\n    forward-addr: 1.1.1.1\n'
            with open('/home/dns/temp_forward.conf', 'w') as f:
                f.write(forward_conf)
            run_command("sudo mv /home/dns/temp_forward.conf /etc/unbound/unbound.conf.d/forward.conf")
            # Clear automatic malware lists as requested: "tidak ada blokir an kecuali manual"
            run_command("sudo truncate -s 0 /etc/dnsmasq.d/malware.conf")
            run_command("sudo truncate -s 0 /etc/dnsmasq.d/malware_test.conf")
            # Also disable aliases to ensure no redirection to block pages
            run_command("sudo sed -i 's/^#*alias=/#alias=/' /home/dns/dnsmasq_smartdns.conf")
            run_command("sudo systemctl restart dnsmasq && sudo systemctl restart unbound")
        
    return jsonify({'status': 'success'})

@app.route('/api/logs')
def logs():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    # Get last 20 lines of dnsmasq logs
    result = run_command("sudo tail -n 20 /var/log/syslog | grep -E 'dnsmasq|unbound'")
    return jsonify({'logs': result})

if __name__ == '__main__':
    # Use SSL context for HTTPS
    app.run(host='0.0.0.0', port=5000, ssl_context=('/home/dns/web_gui/cert.pem', '/home/dns/web_gui/key.pem'))
