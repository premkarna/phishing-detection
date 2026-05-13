import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import logging
from app.integrations.secure_requests import secure_get

class DOMScanner:
    def __init__(self):
        # The Chrome Mask for Stealth Scanning
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        
        # Advanced Malicious JS & Obfuscation Patterns
        self.malicious_js_patterns = [
            r"eval\(", r"unescape\(", r"document\.write\(", r"atob\(", r"btoa\(",
            r"String\.fromCharCode", r"location\.replace\(", r"setInterval\(",
            r"window\.atob", r"setTimeout\(", r"execCommand", r"Function\("
        ]
        
        # Data Exfiltration Patterns
        self.exfil_patterns = [
            r"fetch\(", r"XMLHttpRequest", r"navigator\.sendBeacon", r"$.ajax", r"$.post"
        ]

    def scan(self, target_url):
        logging.info(f"[*] DOM SCANNER: Executing Headless Forensic Scan on {target_url}...")
        
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
            
        parsed_url = urlparse(target_url)
        base_domain = parsed_url.netloc.replace("www.", "")
        
        results = {
            "risk_score": 0,
            "threats_found": [],
            "metadata": {
                "forms_found": 0,
                "scripts_found": 0,
                "hidden_elements": 0,
                "external_resources": 0
            }
        }

        try:
            # Secure request with SSL fallback for forensic scanning of potentially self-signed phishing sites
            res = secure_get(target_url, headers=self.headers, timeout=10, enable_ssl_fallback=True)
            soup = BeautifulSoup(res.text, 'lxml') 
            
            # --- 1. THE HIDDEN FORM & HIJACKING TRAP ---
            forms = soup.find_all('form')
            results["metadata"]["forms_found"] = len(forms)
            for form in forms:
                action = form.get('action', '').lower()
                method = form.get('method', 'get').lower()
                
                # External Action (Form Hijacking)
                if action.startswith("http") and base_domain not in action:
                    results["threats_found"].append(f"FORM HIJACKING: Data submits to external domain ({action})")
                    results["risk_score"] += 40
                
                # Hidden Inputs Analysis
                inputs = form.find_all('input')
                for inp in inputs:
                    is_hidden = inp.get('type') == 'hidden' or 'display:none' in str(inp.get('style', '')).replace(" ", "").lower()
                    if is_hidden:
                        results["metadata"]["hidden_elements"] += 1
                        name = str(inp.get('name', '')).lower()
                        id_attr = str(inp.get('id', '')).lower()
                        if any(k in name or k in id_attr for k in ['pass', 'secret', 'token', 'key', 'auth']):
                            results["threats_found"].append(f"SNEAKY ELEMENT: Hidden sensitive field detected ({name or id_attr})")
                            results["risk_score"] += 25

            # --- 2. THE JAVASCRIPT PAYLOAD & OBFUSCATION TRAP ---
            scripts = soup.find_all('script')
            results["metadata"]["scripts_found"] = len(scripts)
            for script in scripts:
                # 2a. External Script Check
                src = script.get('src', '')
                if src:
                    if src.startswith("http") and base_domain not in src:
                        results["metadata"]["external_resources"] += 1
                        # High-risk script sources
                        if any(domain in src for domain in ["bit.ly", "cutt.ly", "tinyurl", "firebase", "ngrok"]):
                            results["threats_found"].append(f"SUSPICIOUS RESOURCE: External script from high-risk domain ({src})")
                            results["risk_score"] += 30

                # 2b. Inline Script Analysis (Obfuscation)
                if script.string:
                    script_content = script.string
                    # Check for execution patterns
                    for pattern in self.malicious_js_patterns:
                        if re.search(pattern, script_content, re.IGNORECASE):
                            pattern_clean = pattern.replace('\\', '')
                            results["threats_found"].append(f"JS OBFUSCATION: Found dynamic execution pattern ({pattern_clean})")
                            results["risk_score"] += 15
                    
                    # Check for data exfiltration patterns
                    if results["risk_score"] > 30: # Only deep scan JS if already suspicious
                        for pattern in self.exfil_patterns:
                            if re.search(pattern, script_content, re.IGNORECASE):
                                pattern_clean = pattern.replace('\\', '')
                                results["threats_found"].append(f"DATA EXFIL PATTERN: JS attempting external data transfer ({pattern_clean})")
                                results["risk_score"] += 20

            # --- 3. IFRAME & REDIRECT TRAPS ---
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                src = iframe.get('src', '')
                if src and base_domain not in src:
                    results["threats_found"].append(f"STEALTH IFRAME: Hidden frame loading external content ({src})")
                    results["risk_score"] += 15

            # --- 4. FINAL VERDICT ---
            if not results["threats_found"]:
                results["threats_found"].append("Clean: Standard DOM Structure")
            
            results["risk_score"] = min(results["risk_score"], 100)
            return results

        except Exception as e:
            return {
                "risk_score": 0, 
                "threats_found": [f"DOM Scan Failed: {str(e)}"],
                "metadata": {"error": True}
            }

if __name__ == "__main__":
    # Quick manual test
    scanner = DOMScanner()
    # Mock test (real sites might block simple requests)
    test_url = "https://google.com"
    print(f"Testing DOM Scanner on {test_url}...")
    res = scanner.scan(test_url)
    print(f"Risk Score: {res['risk_score']}")
    print(f"Threats: {res['threats_found']}")
