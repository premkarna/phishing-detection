import os
import sys
import json

# Add root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.report_generator import generate_pdf_report

def test_pdf_generation():
    print("Starting Automated SOC PDF Report Test Suite...")
    
    # Mock Scan Data for various scenarios
    test_cases = [
        {
            "name": "Critical URL Threat",
            "data": {
                "calculated_risk": 95,
                "payload": "http://secure-login-bank.xyz/verify",
                "server_ip_loc": "185.23.10.4 (Russia)",
                "domain_age": "2 days",
                "ssl_certificate": "Expired / Self-Signed",
                "virustotal": "14/94 Flags",
                "brand_check": "TYPOSQUATTING (Detected)",
                "ai_report": {
                    "verdict": "CRITICAL MALICIOUS",
                    "reason": "The domain uses typosquatting and has a high risk score. Infrastructure linked to known phishing campaigns.",
                    "advice": "DO NOT CLICK. Block domain at firewall level."
                },
                "soar_playbook": [
                    "Isolate host from network",
                    "Invalidate active sessions",
                    "Trigger password reset for user"
                ]
            }
        },
        {
            "name": "Suspicious QR Code",
            "data": {
                "calculated_risk": 45,
                "payload": "https://bit.ly/3xYz123",
                "server_ip_loc": "104.21.45.1 (Cloudflare)",
                "domain_age": "Legacy Asset",
                "ssl_certificate": "Valid",
                "virustotal": "1/94 Flags",
                "brand_check": "Legitimate (bit.ly)",
                "ai_report": {
                    "verdict": "SUSPICIOUS (SHORTENER)",
                    "reason": "QR code contains a shortened link which obfuscates the final destination.",
                    "advice": "Inspect the unmasked URL before proceeding."
                },
                "soar_playbook": [
                    "Unmask shortened link",
                    "Scan destination DOM"
                ]
            }
        },
        {
            "name": "Benign Legitimate Scan",
            "data": {
                "calculated_risk": 5,
                "payload": "https://www.google.com",
                "server_ip_loc": "142.250.190.4 (USA)",
                "domain_age": "26 years",
                "ssl_certificate": "Valid (Google Trust Services)",
                "virustotal": "0/94 Flags",
                "brand_check": "Legitimate",
                "ai_report": {
                    "verdict": "SAFE",
                    "reason": "Highly reputable domain with long history and valid security headers.",
                    "advice": "Safe to proceed."
                }
            }
        }
    ]
    
    generated_files = []
    
    for case in test_cases:
        print(f"\n[TEST] Generating report for: {case['name']}...")
        try:
            filename = generate_pdf_report(case['data'])
            if os.path.exists(filename):
                print(f"PASS: {filename}")
                generated_files.append(filename)
            else:
                print(f"FAIL: File not created for {case['name']}")
        except Exception as e:
            print(f"FAIL: Error during generation for {case['name']}: {str(e)}")
            
    print("\n" + "="*50)
    print(f"PDF TEST SUMMARY: {len(generated_files)}/{len(test_cases)} Passed")
    print("="*50)
    
    if len(generated_files) == len(test_cases):
        print("\nAll SOC PDF reports generated successfully with full forensic metadata!")
    else:
        sys.exit(1)

if __name__ == "__main__":
    test_pdf_generation()
