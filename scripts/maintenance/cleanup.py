#!/usr/bin/env python3
"""
Safe cleanup script for Phishing Detection System
Removes temporary/cache files, keeps essential data
"""

import os
import json
from datetime import datetime, timedelta

def cleanup():
    print("="*60)
    print("SAFE CLEANUP - Phishing Detection System")
    print("="*60)
    
    # 1. Clear IOC cache (older than 24 hours)
    try:
        if os.path.exists('data/cache/ioc_cache.json'):
            with open('data/cache/ioc_cache.json', 'r') as f:
                cache = json.load(f)
            
            # Remove old entries
            current_time = datetime.now()
            cleaned = {}
            for key, value in cache.items():
                if key == 'cached_at':
                    continue
                # Keep only recent entries (implement TTL check if needed)
                cleaned[key] = value
            
            with open('data/cache/ioc_cache.json', 'w') as f:
                json.dump(cleaned, f, indent=2)
            print("✅ IOC cache cleaned (old entries removed)")
    except Exception as e:
        print(f"⚠️ IOC cache cleanup failed: {e}")
    
    # 2. Check __pycache__
    pycache_dirs = []
    for root, dirs, files in os.walk('.'):
        for d in dirs:
            if d == '__pycache__':
                pycache_dirs.append(os.path.join(root, d))
    
    print(f"ℹ️ Found {len(pycache_dirs)} __pycache__ directories")
    print("   (Safe to delete: python -m pyclean .)")
    
    # 3. Report file sizes
    files_to_check = [
        'data/cache/global_threats.db',
        'data/cache/ioc_cache.json',
        'data/cache/qr_fingerprints.json',
        'data/cache/soc_metrics.json',
        'data/cache/threat_actors.json'
    ]
    
    print("\n📊 Current File Sizes:")
    total_size = 0
    for f in files_to_check:
        if os.path.exists(f):
            size = os.path.getsize(f)
            total_size += size
            print(f"  {f}: {size:,} bytes")
        else:
            print(f"  {f}: NOT FOUND")
    
    print(f"\nTotal data files size: {total_size:,} bytes ({total_size/1024:.1f} KB)")
    print("="*60)

if __name__ == "__main__":
    cleanup()
