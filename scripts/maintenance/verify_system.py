#!/usr/bin/env python3
"""System verification script for comprehensive testing"""

import os
import sys
from io import StringIO
from dotenv import load_dotenv

# Capture all output
output = StringIO()
old_stdout = sys.stdout
sys.stdout = output

load_dotenv()

print("=" * 70)
print("COMPREHENSIVE SYSTEM VERIFICATION")
print("=" * 70)

issues = []
success = []

# 1. API Keys
print("\n1. API KEYS")
keys = ['GEMINI_API_KEY_1', 'GEMINI_API_KEY_2', 'VT_API_KEY_1', 'VT_API_KEY_2']
for k in keys:
    v = os.getenv(k)
    if v and len(v) > 20:
        print(f"OK {k}: SET ({len(v)} chars)")
        success.append(k)
    else:
        print(f"FAIL {k}: NOT SET")
        issues.append(f"Missing {k}")

# 2. Core Imports
print("\n2. CORE MODULES")
modules = [
    ('main', 'Flask App'),
    ('app.core.url_engine', 'URLEngine'),
    ('app.core.eml_engine', 'EMLEngine'),
    ('app.integrations.ai_handler', 'AIHandler'),
    ('app.services.accuracy_engine', 'AccuracyEngine'),
]

for mod, name in modules:
    try:
        __import__(mod)
        print(f"OK {name}")
        success.append(name)
    except Exception as e:
        print(f"FAIL {name}: {str(e)[:40]}")
        issues.append(f"{name}: {e}")

# 3. Engine Initialization
print("\n3. ENGINE INITIALIZATION")
try:
    from app.core.url_engine import URLEngine
    ue = URLEngine()
    print(f"OK URLEngine: vt_api={'yes' if ue.vt_api_key else 'no'}")
    success.append("URLEngine init")
except Exception as e:
    print(f"FAIL URLEngine: {e}")
    issues.append(f"URLEngine init: {e}")

try:
    from app.integrations.ai_handler import AIHandler
    ah = AIHandler()
    print(f"OK AIHandler: active={ah.is_active}, keys={len(ah.api_keys)}")
    success.append("AIHandler init")
except Exception as e:
    print(f"FAIL AIHandler: {e}")
    issues.append(f"AIHandler init: {e}")

# 4. Flask Routes
print("\n4. FLASK ROUTES")
try:
    from main import app
    routes = [r.rule for r in app.url_map.iter_rules()]
    required = ['/analyze', '/accuracy', '/api/metrics', '/api/threats']
    for r in required:
        if any(r in route for route in routes):
            print(f"OK Route {r}")
            success.append(f"Route {r}")
        else:
            print(f"FAIL Route {r} missing")
            issues.append(f"Missing route {r}")
except Exception as e:
    print(f"FAIL Flask routes: {e}")
    issues.append(f"Flask: {e}")

# Summary
print("\n" + "=" * 70)
print(f"Success: {len(success)}")
print(f"Issues: {len(issues)}")

if issues:
    print("\nISSUES FOUND:")
    for i, issue in enumerate(issues[:10], 1):
        print(f"  {i}. {issue}")

print("=" * 70)

# Restore stdout and print captured output
sys.stdout = old_stdout
result = output.getvalue()
print(result)

# Also save to file
with open('verification_results.txt', 'w') as f:
    f.write(result)

# Return exit code
sys.exit(0 if not issues else 1)
