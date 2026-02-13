import os
import json
import uuid
import datetime
import hashlib

LICENSE_DB_FILE = "/home/dns/web_gui/licenses_db.json"

PLAN_FEATURES = {
    "BASIC": [
        "Core DNS Filtering (Ads & Malware)",
        "Standard DNS Caching",
        "Basic Web GUI Access",
        "Local Logs Only"
    ],
    "PRO": [
        "All BASIC Features",
        "Advanced Threat Detection (Botnets, Crypto, C2)",
        "Full Traffic Analysis & Charts",
        "API Access",
        "Priority Support",
        "Unlimited Custom Whitelists"
    ],
    "ENTERPRISE": [
        "All PRO Features",
        "High Availability Clustering (Primary/Secondary Sync)",
        "Unlimited RPS Optimization (ISP Scale)",
        "Custom Branding / White-label",
        "Dedicated Support Channel",
        "Multi-Node Central Management"
    ]
}

def get_plan_features(plan):
    return PLAN_FEATURES.get(plan, [])

def load_db():
    if os.path.exists(LICENSE_DB_FILE):
        try:
            with open(LICENSE_DB_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}

def save_db(db):
    try:
        with open(LICENSE_DB_FILE, 'w') as f:
            json.dump(db, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving license DB: {e}")
        return False

def generate_license(client_name, plan="PRO", duration_days=365):
    # Generate a unique key
    # Format: MARS-{RANDOM_HEX}-{RANDOM_HEX}-{RANDOM_HEX}
    random_part = uuid.uuid4().hex.upper()
    key = f"MARS-{random_part[:4]}-{random_part[4:8]}-{random_part[8:12]}-{random_part[12:16]}"
    
    expiry_str = "LIFETIME"
    if str(duration_days) != "9999":
        expiry_str = (datetime.datetime.now() + datetime.timedelta(days=int(duration_days))).strftime("%Y-%m-%d")
    
    license_data = {
        "client_name": client_name,
        "plan": plan,
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "expiry_date": expiry_str,
        "status": "ACTIVE",
        "key": key
    }
    
    db = load_db()
    db[key] = license_data
    save_db(db)
    
    return license_data

def list_licenses():
    db = load_db()
    # Convert dict to list, sorted by creation date (newest first)
    licenses = [{"key": k, **v} for k, v in db.items()]
    try:
        licenses.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    except:
        pass
    return licenses

def revoke_license(key):
    db = load_db()
    if key in db:
        del db[key]
        save_db(db)
        return True
    return False

def get_license(key):
    db = load_db()
    return db.get(key)
