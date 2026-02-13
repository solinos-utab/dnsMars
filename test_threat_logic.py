
import sys
import os
sys.path.append('/home/dns/web_gui')
from app import analyze_threat_candidates, get_threat_keywords

print("Testing get_threat_keywords...")
keywords = get_threat_keywords()
print(f"Keywords: {keywords}")

print("\nTesting analyze_threat_candidates...")
try:
    results = analyze_threat_candidates()
    print(f"Results count: {len(results)}")
    if results:
        print(f"First result: {results[0]}")
except Exception as e:
    print(f"Error: {e}")
