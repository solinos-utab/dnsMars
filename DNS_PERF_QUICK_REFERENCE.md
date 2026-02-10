# DNS Performance Optimization - Quick Reference
**Date Applied**: Feb 10, 2026 | **System**: PT MARS DATA DNS Engine

---

## 📊 Specifications at a Glance

### What Changed?
```
Unbound Rate Limiting:
  ip-ratelimit: 100 qps  →  2000 qps  (✅ 20x improvement)

Unbound Threading:
  num-threads: 2  →  8  (✅ 4x improvement)

Dnsmasq Cache:
  cache-size: 50000  →  100000  (✅ 2x improvement)
```

### Why?
- Previous: Localhost (dnsmasq) throttled at 100 qps → SERVFAIL errors
- Now: Localhost allowed 2000 qps → No more bottlenecks

---

## ⚙️ Current Configuration

### Unbound (`/etc/unbound/unbound.conf.d/smartdns.conf`)
```
num-threads: 8
ratelimit: 50000
ip-ratelimit: 2000
msg-cache-size: 100m
rrset-cache-size: 100m
cache-min-ttl: 3600
cache-max-ttl: 86400
```

### Dnsmasq (`/etc/dnsmasq.d/00-base.conf`)
```
cache-size=100000
dns-forward-max=10000
```

---

## ✅ Quick Health Check

### Check if optimizations are active:
```bash
# Show unbound config
unbound-checkconf /etc/unbound/unbound.conf.d/smartdns.conf

# Verify services running
systemctl status unbound dnsmasq

# Check for errors
tail -20 /var/log/syslog | grep -i ratelimit
tail -20 /var/log/dnsmasq.log | grep -i servfail
```

### Expected results:
```
✅ unbound: active (running)
✅ dnsmasq: active (running)
✅ No ratelimit errors in logs
✅ No SERVFAIL errors
```

---

## 📈 Performance Monitoring

### Real-time QPS monitoring:
```bash
# Watch query rate (last 1000 entries)
watch -n 1 'tail -1000 /var/log/dnsmasq.log | grep query | wc -l'

# More detailed (per second average)
tail -f /var/log/dnsmasq.log | grep query
```

### Cache performance:
```bash
# Query unbound stats (if monitoring enabled)
unbound-control stats

# Alternative: watch dnsmasq cache
watch -n 2 'systemctl status dnsmasq | grep -i cache'
```

### Response time check:
```bash
# Test DNS response time
time dig @127.0.0.1 -p 5353 google.com  # Unbound
time dig @127.0.0.1 google.com           # Dnsmasq

# Batch test
for i in {1..10}; do time dig google.com; done
```

---

## 🔍 Troubleshooting

### If still experiencing slowness:

**Check 1: Are limits being hit?**
```bash
tail -100 /var/log/syslog | grep -i ratelimit
```
- If you see `ip_ratelimit exceeded 127.0.0.1` → limits need more increase
- If no errors → slowness is elsewhere

**Check 2: Cache hit rate?**
```bash
# Check query types (should see mix of A, AAAA, MX)
tail -1000 /var/log/dnsmasq.log | awk '{print $7}' | sort | uniq -c

# High repeats = good cache rate
```

**Check 3: Upstream latency?**
```bash
# Test upstream DNS speed
dig @8.8.8.8 google.com
dig @1.1.1.1 google.com
dig @103.68.213.213 google.com  # DNS Trust IP

# Compare response times
```

**Check 4: System resources?**
```bash
# CPU
top -bn1 | grep -E 'unbound|dnsmasq'

# Memory
free -h | grep -E 'Mem|Swap'

# Load
uptime
```

---

## 🛠️ Adjustment Guide

### Increase rate limits further:
If you need even higher capacity:

**Edit `/etc/unbound/unbound.conf.d/smartdns.conf`:**
```bash
sudo nano /etc/unbound/unbound.conf.d/smartdns.conf

# Update these lines:
ratelimit: 100000           # Can be 50000-100000
ip-ratelimit: 5000          # Can be 2000-5000 per IP

# Save and restart
sudo systemctl restart unbound
```

### Increase cache:
```bash
# Edit dnsmasq config
sudo nano /etc/dnsmasq.d/00-base.conf

# Update:
cache-size=200000           # Can go higher if memory available

# Restart
sudo systemctl restart dnsmasq
```

### Check available resources before increasing:
```bash
free -h      # Memory available?
nproc        # CPU cores available?
iostat -x    # Disk I/O?
```

---

## 📚 Documentation Links

### Official Unbound Documentation
- **Rate Limiting Guide**: https://unbound.docs.nlnetlabs.nl/en/latest/topics/core/performance.html
- **Configuration Reference**: https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html

### Related Files in This System
- `README.md` - Main documentation with performance specs
- `PERFORMANCE_OPTIMIZATION_APPLIED.md` - Detailed analysis
- `PANDUAN_SISTEM.md` - System administration guide (Indonesian)
- `SCHEDULE_FIX_VERIFICATION.md` - DNS Trust scheduling


---

## 📞 Support References

### Key Metrics to Track
- **Current QPS**: ~25-250 (depends on usage)
- **Max Capacity**: 2000 qps sustained
- **Cache entries**: 100,000
- **Typical response**: <100ms (cached), <500ms (recursive)

### When to Contact Support
- Sustained errors in syslog despite optimization
- Response times >1 second consistently
- Memory usage approaching 50%
- New SERVFAIL pattern emerging

---

**Last Updated**: Feb 10, 2026 13:59 WIB  
**Status**: Active and Optimized ✅
