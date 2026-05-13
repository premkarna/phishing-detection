#!/usr/bin/env python3
"""Comprehensive system diagnostic report"""

import os
import sys
import traceback
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

print("🔍 PHISHING DETECTION TOOL - COMPREHENSIVE DIAGNOSTIC")
print("=" * 70)

issues = []
warnings = []
success = []

# 1. Environment Variables Check
print("\n1️⃣  API KEYS STATUS")
print("-" * 50)

keys_to_check = [
    'GEMINI_API_KEY_1',
    'GEMINI_API_KEY_2', 
    'VT_API_KEY_1',
    'VT_API_KEY_2'
]

for key in keys_to_check:
    value = os.getenv(key)
    if value and len(value) > 20:
        masked = value[:8] + "..." + value[-4:]
        success.append(f"✅ {key}: {masked}")
        print(f"✅ {key}: {masked}")
    else:
        issues.append(f"❌ {key}: Missing or invalid")
        print(f"❌ {key}: MISSING OR INVALID")

# 2. Module Import Tests
print("\n2️⃣  MODULE IMPORT TESTS")
print("-" * 50)

modules = {
    'Core Engines': [
        'core.url_engine',
        'core.eml_engine',
        'core.quishing_engine',
        'core.sms_engine',
        'core.vishing_engine',
        'core.clone_engine',
        'core.social_engine',
    ],
    'Utilities': [
        'utils.ai_handler',
        'utils.accuracy_engine',
        'utils.sandbox_engine',
        'utils.osint_engine',
        'utils.soar_engine',
        'utils.dom_scanner',
        'utils.visual_analyzer',
        'utils.offensive_defense',
        'utils.predictive_intel',
        'utils.cache_manager',
    ]
}

for category, mod_list in modules.items():
    print(f"\n{category}:")
    for mod in mod_list:
        try:
            module = __import__(mod, fromlist=[''])
            print(f"  ✅ {mod}")
            success.append(f"Import OK: {mod}")
        except Exception as e:
            print(f"  ❌ {mod}: {str(e)[:40]}")
            issues.append(f"Import Failed: {mod} - {str(e)[:40]}")

# 3. Engine Initialization Tests
print("\n3️⃣  ENGINE INITIALIZATION TESTS")
print("-" * 50)

engines_to_test = [
    ('core.url_engine', 'URLEngine'),
    ('core.eml_engine', 'EMLEngine'),
    ('core.quishing_engine', 'QREngine'),
    ('core.sms_engine', 'SMSEngine'),
    ('core.vishing_engine', 'VishingEngine'),
    ('core.clone_engine', 'CloneEngine'),
    ('core.social_engine', 'SocialEngine'),
]

for module_name, class_name in engines_to_test:
    try:
        module = __import__(module_name, fromlist=[class_name])
        engine_class = getattr(module, class_name)
        engine = engine_class()
        print(f"✅ {class_name}: Initialized")
        success.append(f"Engine OK: {class_name}")
    except Exception as e:
        print(f"❌ {class_name}: {str(e)[:40]}")
        issues.append(f"Engine Failed: {class_name} - {str(e)[:40]}")

# 4. File Structure Check
print("\n4️⃣  FILE STRUCTURE CHECK")
print("-" * 50)

required_paths = [
    'main.py',
    'requirements.txt',
    '.env',
    'templates/index.html',
    'templates/accuracy.html',
    'static/style.css',
    'static/script.js',
    'utils/ai_handler.py',
    'utils/accuracy_engine.py',
    'core/url_engine.py',
]

for path in required_paths:
    if Path(path).exists():
        size = Path(path).stat().st_size
        print(f"✅ {path} ({size} bytes)")
        success.append(f"File OK: {path}")
    else:
        print(f"❌ {path}: MISSING")
        issues.append(f"Missing File: {path}")

# 5. AI Handler Specific Check
print("\n5️⃣  AI HANDLER VERIFICATION")
print("-" * 50)

try:
    from app.integrations.ai_handler import AIHandler
    handler = AIHandler()
    print(f"✅ AIHandler initialized")
    print(f"   - Model: {handler.model_name}")
    print(f"   - API Keys loaded: {len(handler.api_keys) > 0}")
    success.append("AIHandler: OK")
except Exception as e:
    print(f"❌ AIHandler failed: {str(e)[:50]}")
    issues.append(f"AIHandler Error: {str(e)[:50]}")

# 6. VirusTotal Integration Check
print("\n6️⃣  VIRUSTOTAL INTEGRATION")
print("-" * 50)

try:
    from app.core.url_engine import URLEngine
    engine = URLEngine()
    vt_key = os.getenv('VT_API_KEY_1')
    if vt_key:
        print(f"✅ VirusTotal API key configured")
        success.append("VirusTotal: Configured")
    else:
        print(f"⚠️  VirusTotal API key missing")
        warnings.append("VirusTotal: No API key")
except Exception as e:
    print(f"❌ VirusTotal check failed: {str(e)[:50]}")
    issues.append(f"VirusTotal Error: {str(e)[:50]}")

# Summary Report
print("\n" + "=" * 70)
print("📊 DIAGNOSTIC SUMMARY")
print("=" * 70)

print(f"\n✅ Success: {len(success)} checks passed")
print(f"⚠️  Warnings: {len(warnings)} items need attention")
print(f"❌ Issues: {len(issues)} critical problems found")

if issues:
    print("\n❌ CRITICAL ISSUES:")
    for issue in issues[:10]:
        print(f"   {issue}")
    if len(issues) > 10:
        print(f"   ... and {len(issues) - 10} more issues")

if warnings:
    print("\n⚠️  WARNINGS:")
    for warning in warnings[:5]:
        print(f"   {warning}")

print("\n" + "=" * 70)

# Save report
with open('diagnostic_report.txt', 'w') as f:
    f.write("PHISHING DETECTION TOOL - DIAGNOSTIC REPORT\n")
    f.write("=" * 70 + "\n\n")
    f.write(f"Success: {len(success)}\n")
    f.write(f"Warnings: {len(warnings)}\n")
    f.write(f"Issues: {len(issues)}\n\n")
    f.write("ISSUES:\n")
    for issue in issues:
        f.write(f"  {issue}\n")
    f.write("\nWARNINGS:\n")
    for warning in warnings:
        f.write(f"  {warning}\n")

print("📄 Report saved to: diagnostic_report.txt")
