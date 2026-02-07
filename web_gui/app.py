from flask import Flask, render_template, request, jsonify, abort
import subprocess
import psutil
import socket
import re

import time
from datetime import datetime, timedelta

app = Flask(__name__)

# --- WAF & SECURITY LAYER ---
ALLOWED_IPS = ['103.68.213.6', '103.68.213.7', '127.0.0.1']

def check_ip():
    client_ip = request.remote_addr
    # Also check X-Forwarded-For if behind a proxy
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0]
    
    if client_ip not in ALLOWED_IPS:
        return False
    return True

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
    if not check_ip():
        return jsonify({'status': 'error', 'message': 'Access Denied: Your IP is not whitelisted'}), 403
    if waf_check():
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
        with open('/etc/netplan/00-installer-config.yaml', 'r') as f:
            content = f.read()
            # Simple extraction for demo purposes
            ip4 = ""
            ip4_gw = ""
            ip6 = ""
            ip6_gw = ""
            
            import re
            # Find addresses
            addrs = re.findall(r'- (\d+\.\d+\.\d+\.\d+/\d+)', content)
            if addrs: ip4 = addrs[0]
            
            # Find IPv6 addresses (simplified regex)
            addrs6 = re.findall(r'- ([a-fA-F0-9:]+/\d+)', content)
            if addrs6: ip6 = addrs6[0]
            
            # Find gateways
            gws = re.findall(r'via: (\d+\.\d+\.\d+\.\d+)', content)
            if gws: ip4_gw = gws[0]
            
            gws6 = re.findall(r'via: ([a-fA-F0-9:]+)', content)
            if gws6: ip6_gw = gws6[0]
            
            return {
                'ip4': ip4,
                'ip4_gw': ip4_gw,
                'ip6': ip6,
                'ip6_gw': ip6_gw,
                'ipv6_enabled': bool(ip6)
            }
    except:
        return {'ip4': '', 'ip4_gw': '', 'ip6': '', 'ip6_gw': '', 'ipv6_enabled': False}

def get_trust_info():
    try:
        if subprocess.run(['test', '-f', '/etc/dnsmasq.d/trust.conf']).returncode == 0:
            with open('/etc/dnsmasq.d/trust.conf', 'r') as f:
                content = f.read().strip()
                if content.startswith('server='):
                    return {'enabled': True, 'ip': content.replace('server=', '')}
        return {'enabled': False, 'ip': ''}
    except:
        return {'enabled': False, 'ip': ''}

@app.route('/api/status')
def status():
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
            
    return jsonify({
        'dnsmasq': get_service_status('dnsmasq'),
        'unbound': get_service_status('unbound'),
        'resolved': get_service_status('systemd-resolved'),
        'guardian': get_service_status('guardian'),
        'iptables': fw_status['nat'],
        'security': {
            'flood_protection': fw_status['flood_prot'],
            'connection_limit': fw_status['conn_limit'],
            'guardian_logs': guardian_logs
        },
        'metrics': {
            'cpu': cpu_usage,
            'ram': ram_usage,
            'dns_perf': dns_perf
        },
        'network': net_info,
        'trust': trust_info
    })

@app.route('/api/dig', methods=['POST'])
def dig():
    data = request.json
    domain = data.get('domain', 'google.com')
    qtype = data.get('qtype', 'A') # Default to A record
    
    # Sanitize domain input - STRONGER SANITIZATION
    domain = re.sub(r'[^a-zA-Z0-9.-]', '', domain)
    # Sanitize qtype
    if qtype not in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
        qtype = 'A'
        
    # Use list for subprocess to avoid shell=True if possible, 
    # but run_command uses shell=True. Let's ensure domain is super clean.
    result = run_command(f"dig @127.0.0.1 {domain} {qtype}")
    return jsonify({'result': result})

@app.route('/api/action', methods=['POST'])
def action():
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
    
    # Sanitize domain
    if domain:
        domain = re.sub(r'[^a-zA-Z0-9.-]', '', domain)
    
    # Sanitize IPs
    if dns_ip:
        dns_ip = re.sub(r'[^0-9.]', '', dns_ip)
    if ipv6_ip:
        ipv6_ip = re.sub(r'[^a-fA-F0-9:/]', '', ipv6_ip)
    if trust_ip:
        trust_ip = re.sub(r'[^0-9.]', '', trust_ip)

    if cmd_type == 'restart_dnsmasq':
        run_command("sudo systemctl restart dnsmasq")
    elif cmd_type == 'restart_unbound':
        run_command("sudo systemctl restart unbound")
    elif cmd_type == 'clear_cache':
        run_command("sudo systemctl restart dnsmasq && sudo unbound-control flush_zone .")
    elif cmd_type == 'blacklist' and domain:
        run_command(f"echo 'address=/{domain}/0.0.0.0' | sudo tee -a /etc/dnsmasq.d/blacklist.conf && sudo systemctl restart dnsmasq")
    elif cmd_type == 'whitelist' and domain:
        run_command(f"echo 'server=/{domain}/1.1.1.1' | sudo tee -a /etc/dnsmasq.d/whitelist.conf && sudo systemctl restart dnsmasq")
    elif cmd_type == 'update_ssh':
        run_command("sudo apt-get update && sudo apt-get install --only-upgrade openssh-server -y")
    elif cmd_type == 'update_firewall':
        run_command("sudo chmod +x /home/dns/setup_firewall.sh && sudo /home/dns/setup_firewall.sh")
    elif cmd_type == 'malware_shield':
        # Use a more reliable way to format for dnsmasq
        cmd = "curl -s https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | grep '^0.0.0.0' | awk '{print \"address=/\"$2\"/0.0.0.0\"}' | sudo tee /etc/dnsmasq.d/malware.conf > /dev/null && sudo systemctl restart dnsmasq"
        run_command(cmd)
    elif cmd_type == 'change_dns' and dns_ip:
        forward_conf = f"forward-zone:\n    name: \".\"\n    forward-addr: {dns_ip}\n"
        run_command(f"echo '{forward_conf}' | sudo tee /etc/unbound/unbound.conf.d/forward.conf && sudo systemctl restart unbound")
    elif cmd_type == 'update_network':
        try:
            import yaml
            # Load existing config to preserve other settings if any
            with open('/etc/netplan/00-installer-config.yaml', 'r') as f:
                config = yaml.safe_load(f)
            
            # Update IPv4
            if 'ethernets' in config['network'] and 'ens18' in config['network']['ethernets']:
                iface = config['network']['ethernets']['ens18']
                
                # Update addresses
                new_addrs = [ip4_addr]
                if ipv6_enabled and ip6_addr:
                    new_addrs.append(ip6_addr)
                iface['addresses'] = new_addrs
                
                # Update routes
                new_routes = [{'to': 'default', 'via': ip4_gw}]
                if ipv6_enabled and ip6_gw:
                    new_routes.append({'to': 'default', 'via': ip6_gw})
                iface['routes'] = new_routes
                
                # Write back
                with open('/home/dns/new_netplan.yaml', 'w') as f:
                    yaml.dump(config, f, default_flow_style=False)
                
                run_command("sudo mv /home/dns/new_netplan.yaml /etc/netplan/00-installer-config.yaml && sudo netplan apply")
        except Exception as e:
            print(f"Network update error: {e}")
            return jsonify({'status': 'error', 'message': str(e)})
        
    elif cmd_type == 'toggle_ipv6':
        enabled = data.get('enabled', False)
        if enabled:
            run_command("sudo sed -i '/listen-address=127.0.0.1/s/$/,::1/' /etc/dnsmasq.d/smartdns.conf")
            run_command("sudo sed -i 's/do-ip6: no/do-ip6: yes/' /etc/unbound/unbound.conf.d/smartdns.conf")
            run_command("sudo sed -i '/interface: 127.0.0.1/a \    interface: ::1' /etc/unbound/unbound.conf.d/smartdns.conf")
        else:
            run_command("sudo sed -i 's/,::1//' /etc/dnsmasq.d/smartdns.conf")
            run_command("sudo sed -i 's/do-ip6: yes/do-ip6: no/' /etc/unbound/unbound.conf.d/smartdns.conf")
            run_command("sudo sed -i '/interface: ::1/d' /etc/unbound/unbound.conf.d/smartdns.conf")
        run_command("sudo systemctl restart dnsmasq && sudo systemctl restart unbound")
    elif cmd_type == 'toggle_trust':
        if trust_enabled and trust_ip:
            # Add trust server to dnsmasq
            run_command(f"echo 'server={trust_ip}' | sudo tee /etc/dnsmasq.d/trust.conf && sudo systemctl restart dnsmasq")
        else:
            # Remove trust server
            run_command("sudo rm -f /etc/dnsmasq.d/trust.conf && sudo systemctl restart dnsmasq")
        
    return jsonify({'status': 'success'})

@app.route('/api/logs')
def logs():
    # Get last 20 lines of dnsmasq logs
    result = run_command("sudo tail -n 20 /var/log/syslog | grep -E 'dnsmasq|unbound'")
    return jsonify({'logs': result})

if __name__ == '__main__':
    # Use SSL context for HTTPS
    app.run(host='0.0.0.0', port=5000, ssl_context=('/home/dns/web_gui/cert.pem', '/home/dns/web_gui/key.pem'))
