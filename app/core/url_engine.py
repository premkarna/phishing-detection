import os
import math
import re
import base64
import socket
import logging
import requests
import difflib
from urllib.parse import urlparse
from datetime import datetime
from dotenv import load_dotenv
from app.core.dom_scanner import DOMScanner
from app.services.threat_sync import ThreatIntelDB
from app.core.visual_analyzer import VisualAnalyzer

class URLEngine:
    def __init__(self):
        load_dotenv()
        # VirusTotal API Keys - dynamically loads VT_API_KEY_1, _2, _3, ...
        vt_keys, _i = [], 1
        while True:
            _k = os.getenv(f"VT_API_KEY_{_i}")
            if not _k:
                break
            vt_keys.append(_k)
            _i += 1
        vt_keys = [k for k in vt_keys if k and len(k) > 10]
        if vt_keys:
            from app.integrations.api_rotator import APIRotator
            self.vt_api_rotator = APIRotator(vt_keys, "VirusTotal")
            self.vt_api_key = self.vt_api_rotator.get_key()
        else:
            self.vt_api_rotator = None
            self.vt_api_key = None
            
        self.dom_scanner = DOMScanner()
        self.visual_analyzer = VisualAnalyzer()
        self.threat_db = ThreatIntelDB()
        self.popular_brands = ["google", "facebook", "amazon", "apple", "microsoft", "netflix", "paypal", "instagram"]
        
        # 2. THE CHROME MASK (Bypasses Bot Protections)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
        }

    def _calculate_entropy(self, text):
        if not text: return 0
        entropy = 0
        for x in set(text):
            p_x = float(text.count(x)) / len(text)
            entropy += - p_x * math.log2(p_x)
        return entropy

    def _parse_age_from_date(self, creation_date):
        age_days = (datetime.now() - creation_date).days
        years = age_days // 365
        months = (age_days % 365) // 30
        reg_str = creation_date.strftime('%d %b %Y')
        age_str = f"{years}y {months}m" if years >= 1 else f"{months} months"
        return f"Registered: {reg_str} ({age_str} old)"

    def get_domain_age(self, domain):
        # Method 1: RDAP (Registration Data Access Protocol) — JSON API, no bot protection
        try:
            rdap_res = requests.get(
                f"https://rdap.org/domain/{domain}",
                headers=self.headers,
                timeout=8
            )
            if rdap_res.status_code == 200:
                rdap_data = rdap_res.json()
                for event in rdap_data.get("events", []):
                    if event.get("eventAction") == "registration":
                        date_str = event.get("eventDate", "")
                        # RDAP returns ISO 8601 e.g. 1997-09-15T04:00:00Z
                        creation_date = datetime.strptime(date_str[:10], '%Y-%m-%d')
                        return self._parse_age_from_date(creation_date)
        except Exception: pass

        # Method 2: HackerTarget WHOIS API — parse actual date from response text
        try:
            res = requests.get(
                f"https://api.hackertarget.com/whois/?q={domain}",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10
            )
            if res.status_code == 200:
                text = res.text
                patterns = [
                    r'[Cc]reation[\s_-]*[Dd]ate[:\s]+([\d]{4}-[\d]{2}-[\d]{2})',
                    r'[Cc]reated[:\s]+([\d]{4}-[\d]{2}-[\d]{2})',
                    r'[Rr]egistered[\s_-]*[Oo]n[:\s]+([\d]{2}-[A-Za-z]+-[\d]{4})',
                    r'[Rr]egistered[:\s]+([\d]{4}-[\d]{2}-[\d]{2})',
                ]
                for pat in patterns:
                    m = re.search(pat, text)
                    if m:
                        date_str = m.group(1)
                        for fmt in ('%Y-%m-%d', '%d-%b-%Y', '%d-%B-%Y'):
                            try:
                                creation_date = datetime.strptime(date_str, fmt)
                                return self._parse_age_from_date(creation_date)
                            except ValueError:
                                continue
        except Exception: pass

        # Method 3: Resolve IP as last resort
        try:
            ip = socket.gethostbyname(domain)
            return f"Age Unknown (Resolved: {ip})"
        except: pass

        return "New Domain / Just Registered (HIGH RISK)"

    def check_virustotal(self, url):
        if not self.vt_api_key or len(self.vt_api_key) < 10: 
            return "API Key Not Set"
        
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            vt_headers = {"x-apikey": self.vt_api_key}
            
            res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=vt_headers, timeout=8)
            if res.status_code == 200:
                stats = res.json()['data']['attributes']['last_analysis_stats']
                total = stats['malicious'] + stats['harmless'] + stats['suspicious'] + stats['undetected']
                return f"{stats['malicious']}/{total} Flags"
            elif res.status_code == 404:
                # URL not in VT database — submit it for scanning
                try:
                    submit_res = requests.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers=vt_headers,
                        data={"url": url},
                        timeout=8
                    )
                    if submit_res.status_code == 200:
                        return "Submitted for Scan"
                except Exception:
                    pass
                return "Not in VT Database"
            elif res.status_code == 429:
                return "Quota Exceeded"
            else:
                logging.warning(f"[VT] Unexpected status {res.status_code} for {url}")
                return f"VT Error ({res.status_code})"
        except Exception as e:
            logging.warning(f"[VT] Request failed: {e}")
            return "VT Error / Timeout"

    def check_urlhaus(self, url):
        """Check URL against URLHaus malware URL database"""
        try:
            api_url = "https://urlhaus-api.abuse.ch/v1/url/"
            response = requests.post(
                api_url,
                data={"url": url},  # URLHaus requires form-encoded POST, not JSON
                timeout=8
            )
            if response.status_code == 200:
                result = response.json()
                status = result.get("query_status", "")
                if status == "is_host":
                    threat = result.get("urls", [{}])[0].get("threat", "malware") if result.get("urls") else "malware"
                    return f"Malicious ({threat})"
                elif status == "no_results":
                    return "Clean (Not in DB)"
                elif status == "is_url":
                    threat = result.get("threat", "")
                    url_status = result.get("url_status", "")
                    if threat:
                        return f"Malicious ({threat}) — {url_status}"
                    return f"Known URL ({url_status})"
            return "Clean (Not in DB)"
        except Exception as e:
            logging.warning(f"[URLHAUS] Check failed: {e}")
            return "Clean (Timeout)"
        
    def analyze(self, target_url: str) -> dict:
        if not target_url.startswith(("http://", "https://")): target_url = "https://" + target_url
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc.replace("www.", "")
        
        results = {
            "target_url": target_url, "domain": domain, "site_status": "Active",
            "server_ip_loc": "Checking...", "domain_age": "Unknown",
            "ssl_certificate": "None", "brand_check": "Clean",
            "virustotal": "Checking...", "urlhaus": "Clean",
            "html_scan": "Standard Structure", "calculated_risk": 0
        }

        # --- 1. THE BRAIN: BRAND SPOOFING CHECK ---
        max_similarity = 0
        target_brand = ""
        # Expanded brand list for better detection
        brands = self.popular_brands + ["instagram", "facebook", "twitter", "linkedin", "whatsapp"]
        
        domain_part = domain.split('.')[0]
        for brand in brands:
            sim = difflib.SequenceMatcher(None, domain_part, brand).ratio()
            if sim > max_similarity:
                max_similarity = sim
                target_brand = brand

        # Similarity threshold: instagrarn.com (0.85+), amozan.com (0.65+)
        if 0.65 <= max_similarity < 1.0:
            results["brand_check"] = f"TYPOSQUATTING: Mimicking {target_brand.upper()}"
            results["calculated_risk"] += 80 # HIGH RISK for typosquatting
        elif max_similarity == 1.0 and domain != f"{target_brand}.com" and domain != f"{target_brand}.net" and domain != f"{target_brand}.in":
             results["brand_check"] = f"SUBDOMAIN/TLD SPOOF: Fake {target_brand.upper()} link"
             results["calculated_risk"] += 70

        # --- 1.1 KEYWORD-BASED PHISHING CHECK (New Layer) ---
        phish_keywords = ["login", "verify", "account", "update", "secure", "support", "gift-card", "verification"]
        for kw in phish_keywords:
            if kw in domain:
                results["brand_check"] = f"SUSPICIOUS: Using security keyword '{kw}'"
                results["calculated_risk"] += 40
                break

        # --- 2. TECHNICAL INDICATORS ---
        try:
            results["server_ip_loc"] = socket.gethostbyname(domain)
        except:
            results["site_status"] = "Offline"
            results["calculated_risk"] += 30

        results["domain_age"] = self.get_domain_age(domain)
        if "Protected" in results["domain_age"]: results["calculated_risk"] += 20

        if not target_url.startswith("https"):
            results["ssl_certificate"] = "Insecure HTTP"
            results["calculated_risk"] += 20
        else:
            results["ssl_certificate"] = "Valid HTTPS"

        # --- 3. VIRUSTOTAL INTEL ---
        results["virustotal"] = self.check_virustotal(target_url)
        if "/" in results["virustotal"]:
            malicious_flags = int(results["virustotal"].split('/')[0])
            if malicious_flags > 0:
                results["calculated_risk"] += (malicious_flags * 10)

        # --- 3.5 URLHAUS INTEL (Malware URL Database) ---
        results["urlhaus"] = self.check_urlhaus(target_url)
        if "Malicious" in results["urlhaus"]:
            results["calculated_risk"] += 40

        # --- 4. DEEP DOM SCAN (Live Page Analysis) ---
        try:
            dom_results = self.dom_scanner.scan(target_url)
            if dom_results["risk_score"] > 0:
                results["html_scan"] = f"THREATS FOUND: {', '.join(dom_results['threats_found'])}"
                results["calculated_risk"] += dom_results["risk_score"]
            else:
                results["html_scan"] = "Clean (Verified via DOM Scan)"
        except Exception as e:
            results["html_scan"] = f"DOM Scan Error: {str(e)}"

        # --- 5. VISUAL ANALYSIS (Brand Spoofing Detection) ---
        try:
            visual_results = self.visual_analyzer.analyze(target_url)
            results["visual_scan"] = {
                "page_fetched": visual_results["page_fetched"],
                "page_title": visual_results["page_title"],
                "detected_brand": visual_results["detected_brand"],
                "brand_confidence": visual_results["brand_confidence"],
                "login_form_detected": visual_results["login_form_detected"],
                "visual_spoofing_indicators": visual_results["visual_spoofing_indicators"],
                "suspicious_elements": visual_results["suspicious_elements"]
            }
            # Add visual risk to total
            if visual_results["risk_score"] > 0:
                results["calculated_risk"] += visual_results["risk_score"]
                # If visual spoofing confirmed, update brand check
                if visual_results["detected_brand"] and visual_results["brand_confidence"] > 50:
                    results["brand_check"] = f"VISUAL SPOOFING: Mimicking {visual_results['detected_brand']}"
        except Exception as e:
            results["visual_scan"] = {"error": str(e), "page_fetched": False}

        # --- 6. SYNC SCORE TO FINAL VERDICT ---
        results["calculated_risk"] = min(results["calculated_risk"], 100)
        return results