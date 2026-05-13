import os
import sys
import json
from unittest.mock import patch, MagicMock

# Add root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.integrations.osint_scanner import DarkWebOSINT

def test_dark_web_osint():
    print("Starting Dark Web OSINT Forensic Test Suite...")
    osint = DarkWebOSINT()
    
    test_cases = [
        {
            "name": "Compromised Admin Identity",
            "payload": "Sender: admin@pwned-company.com",
            "expected_status": "COMPROMISED",
            "expected_marker": "HIGH-VALUE TARGET PATTERN"
        },
        {
            "name": "Malicious Infrastructure Domain",
            "payload": "From: security-update@leak.net",
            "expected_status": "COMPROMISED",
            "expected_marker": "MALICIOUS INFRASTRUCTURE DOMAIN"
        },
        {
            "name": "Highly Exposed Identity (Pwned)",
            "payload": "Contact: pwned-user@gmail.com",
            "expected_status": "COMPROMISED",
            "expected_leak": "Collection #1-5 (Dark Web)"
        },
        {
            "name": "Suspicious Corporate Prefix",
            "payload": "Reply-To: ceo@startup.io",
            "expected_status": "SUSPICIOUS (EXPOSED)",
            "expected_marker": "HIGH-VALUE TARGET PATTERN"
        },
        {
            "name": "Clean Personal Identity",
            "payload": "To: regular.user@gmail.com",
            "expected_status": "SECURE",
            "expected_marker": None
        }
    ]
    
    passed = 0
    print("\n" + "="*80)
    print(f"{'SCENARIO':<30} | {'STATUS':<20} | {'LEAKS FOUND'}")
    print("-" * 80)
    
    for tc in test_cases:
        res = osint.scan_payload(tc['payload'])
        
        if res is None:
            status = "NO IDENTITY"
            leaks = "N/A"
        else:
            status = res['status']
            leaks = ", ".join(res['leaks']) if res['leaks'] else "None"
        
        print(f"{tc['name']:<30} | {status:<20} | {leaks[:25]}...")
        
        # Verifications
        if res:
            if res['status'] == tc['expected_status']:
                if tc.get('expected_marker'):
                    if tc['expected_marker'] in res['forensic_markers']:
                        passed += 1
                    else:
                        print(f"FAIL: Marker '{tc['expected_marker']}' not found in {res['forensic_markers']}")
                else:
                    passed += 1
            else:
                print(f"FAIL: Expected status {tc['expected_status']} but got {res['status']}")
        elif tc['expected_status'] == "NO IDENTITY":
            passed += 1
            
    print("="*80)
    print(f"OSINT TEST SUMMARY: {passed}/{len(test_cases)} Passed")
    print("="*80)
    
    if passed == len(test_cases):
        print("\nAll Dark Web OSINT forensic cases passed successfully!")
    else:
        sys.exit(1)

if __name__ == "__main__":
    test_dark_web_osint()
