import re

domain = "xggd&f|x&gzo.itotolink.net"
keywords = ["toto", "acs", "totolink"]

# 1. Test Grep Pattern Construction
base_patterns = [
    "acs", "tr069", "cwmp", "soap", "mirai", "mozi", "botnet", 
    "cnc\.", "loader", "miner", "pool\.", "crypto", "wallet", 
    "tor\.", "onion\.", "trojan", "ransom", "payload", "gate\.", "panel\."
]
escaped_keywords = [re.escape(k) for k in keywords]
all_patterns = base_patterns + escaped_keywords
regex_pattern = "(" + "|".join(all_patterns) + ")"

print(f"Regex Pattern: {regex_pattern}")

# 2. Test Python Matching Logic
domain_lower = domain.lower()
match_found = False
for kw in keywords:
    if kw.lower() in domain_lower:
        print(f"MATCH: Keyword '{kw}' found in '{domain}'")
        match_found = True
        break

if not match_found:
    print(f"NO MATCH: No keywords found in '{domain}'")

# 3. Simulate Grep Command
import subprocess
test_log = "Feb 11 15:30:00 dnsmasq[123]: query[A] xggd&f|x&gzo.itotolink.net from 192.168.1.100"
cmd = f"echo '{test_log}' | grep -Ei 'query\[A\] .*{regex_pattern}'"
try:
    output = subprocess.check_output(cmd, shell=True).decode('utf-8')
    print(f"GREP MATCH: {output.strip()}")
except subprocess.CalledProcessError:
    print("GREP NO MATCH")
