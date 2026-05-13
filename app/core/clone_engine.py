import logging
import sys
import os
import ssl
import socket
import hashlib
import re
import json
import difflib
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from app.integrations.secure_requests import secure_get
from app.core.visual_analyzer import VisualAnalyzer
from app.intelligence.sandbox import sandbox_detonator
from app.intelligence.attribution import attribution_engine
from app.intelligence.browser_fingerprinting import fingerprinting_detector
from app.ml.ml_detector import ml_detector
from app.intelligence.fingerprinting import qr_fingerprint_engine

class CloneEngine:
    def __init__(self):
        # List of legitimate targets we protect against clones
        self.trusted_vault = {
            # Big Tech
            "google.com": "https://accounts.google.com",
            "microsoft.com": "https://login.microsoftonline.com",
            "apple.com": "https://appleid.apple.com",
            "amazon.com": "https://www.amazon.com/ap/signin",
            # Social Media
            "facebook.com": "https://www.facebook.com",
            "instagram.com": "https://www.instagram.com/accounts/login",
            "linkedin.com": "https://www.linkedin.com/login",
            "twitter.com": "https://twitter.com/i/flow/login",
            "snapchat.com": "https://accounts.snapchat.com",
            "tiktok.com": "https://www.tiktok.com/login",
            "whatsapp.com": "https://web.whatsapp.com",
            # Finance & Banking
            "paypal.com": "https://www.paypal.com/signin",
            "chase.com": "https://secure.chase.com/web/auth/",
            "bankofamerica.com": "https://www.bankofamerica.com/signin",
            "wellsfargo.com": "https://connect.secure.wellsfargo.com",
            "citibank.com": "https://online.citi.com",
            "sbi.co.in": "https://www.onlinesbi.sbi",
            "hdfcbank.com": "https://netbanking.hdfcbank.com",
            "icicibank.com": "https://www.icicibank.com/Personal-Banking/intranet-login",
            # Services
            "netflix.com": "https://www.netflix.com/login",
            "dropbox.com": "https://www.dropbox.com/login",
            "adobe.com": "https://auth.services.adobe.com",
            "github.com": "https://github.com/login",
            "steam.com": "https://store.steampowered.com/login",
            "epicgames.com": "https://www.epicgames.com/id/login",
            "office365.com": "https://login.microsoftonline.com",
        }

        # CSS class signatures of real brands — clones copy these exactly
        self.brand_css_signatures = {
            "google": ["gb_", "goog-", "RNNXgb", "SFbqRc", "lnXdpd"],
            "microsoft": ["ms-", "mectrl", "mews-", "office-", "c-uhff"],
            "facebook": ["_9ay", "_2t-", "x1", "xjyslct", "x78zum5"],
            "instagram": ["_acan", "_acao", "_acap", "_acas"],
            "linkedin": ["artdeco-", "ember-", "jobs-search", "nav__"],
            "paypal": ["paypal-", "ppvx-", "vx-"],
            "apple": ["apple-pay", "as-", "si-", "idms-"],
            "amazon": ["a-", "nav-", "ap_", "auth-"],
        }
        
        # Advanced utilities
        self.visual_analyzer = VisualAnalyzer()

        logging.info("[CLONE ENGINE] Initialized with MAX detection — 25 brands, 12 detection layers")

    def fetch_structure(self, url: str) -> dict:
        """Extracts deep structural features of a webpage for forensic comparison."""
        try:
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            
            # The Chrome Mask to bypass basic anti-bot
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
            res = secure_get(url, timeout=8, headers=headers, enable_ssl_fallback=True)
            soup = BeautifulSoup(res.text, 'html.parser')
            
            # 1. Functional Analysis (Forms & Scripts)
            forms = [f.get('action', '').lower() for f in soup.find_all('form')]
            scripts = [s.get('src', '').lower() for s in soup.find_all('script') if s.get('src')]
            
            # 2. Structural DNA (Tag Counts)
            # Clones usually maintain the same UI structure
            tag_counts = {
                "div": len(soup.find_all('div')),
                "input": len(soup.find_all('input')),
                "button": len(soup.find_all('button')),
                "a": len(soup.find_all('a')),
                "img": len(soup.find_all('img'))
            }
            
            # 3. CSS Class Extraction for fingerprinting
            all_classes = []
            for tag in soup.find_all(True):
                all_classes.extend(tag.get('class', []))

            # 4. Image src list for perceptual comparison
            images = [img.get('src', '') for img in soup.find_all('img') if img.get('src')]

            # 5. Full text body for brand keyword scanning
            body_text = soup.get_text(separator=' ', strip=True).lower()[:3000]

            return {
                "forms": forms,
                "scripts": scripts,
                "title": soup.title.string.strip() if soup.title and soup.title.string else "",
                "tag_counts": tag_counts,
                "raw_html": res.text[:5000],
                "css_classes": list(set(all_classes)),
                "images": images,
                "body_text": body_text
            }
        except Exception as e:
            logging.error(f"[-] Clone Engine could not fetch {url}: {e}")
            return None

    def detect_brand_from_body(self, susp_data: dict) -> str:
        """Layer 0: Scan body text + title for brand mentions — catches clones that title-only checks miss."""
        body = susp_data.get('body_text', '') + ' ' + susp_data.get('title', '').lower()
        for brand in self.trusted_vault.keys():
            brand_name = brand.split('.')[0]
            if brand_name in body:
                return brand
        return None

    def check_css_fingerprint(self, susp_data: dict, brand: str) -> dict:
        """Layer 8: CSS class fingerprinting — clones copy exact CSS class names from real sites."""
        result = {"css_clone_detected": False, "css_risk": 0, "css_details": [], "matched_classes": []}
        brand_name = brand.split('.')[0].lower()
        signatures = self.brand_css_signatures.get(brand_name, [])
        if not signatures:
            return result
        susp_classes = ' '.join(susp_data.get('css_classes', []))
        matched = [sig for sig in signatures if sig in susp_classes]
        if matched:
            result["css_clone_detected"] = True
            result["matched_classes"] = matched
            result["css_risk"] = min(len(matched) * 20, 60)
            result["css_details"].append(f"CSS CLONE SIGNATURE: {len(matched)} exact class patterns from {brand} found ({matched[:3]})")
        return result

    def check_whois_age(self, url: str) -> dict:
        """Layer 9: WHOIS domain age — phishing domains are almost always < 30 days old."""
        result = {"domain_age_days": None, "age_risk": 0, "age_details": []}
        try:
            parsed = urlparse(url if url.startswith("http") else "https://" + url)
            domain = parsed.netloc.replace("www.", "")
            # Use RDAP (modern WHOIS replacement) — no external lib needed
            rdap_url = f"https://rdap.org/domain/{domain}"
            r = requests.get(rdap_url, timeout=8)
            if r.status_code == 200:
                data = r.json()
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        reg_date_str = event.get("eventDate", "")
                        reg_date = datetime.fromisoformat(reg_date_str.replace("Z", "+00:00"))
                        age_days = (datetime.now(timezone.utc) - reg_date).days
                        result["domain_age_days"] = age_days
                        if age_days < 7:
                            result["age_risk"] = 70
                            result["age_details"].append(f"BRAND NEW DOMAIN: Only {age_days} days old — extremely suspicious")
                        elif age_days < 30:
                            result["age_risk"] = 45
                            result["age_details"].append(f"VERY NEW DOMAIN: {age_days} days old — high phishing probability")
                        elif age_days < 90:
                            result["age_risk"] = 20
                            result["age_details"].append(f"NEW DOMAIN: {age_days} days old — moderately suspicious")
                        break
        except Exception as e:
            result["age_details"].append(f"WHOIS check skipped: {str(e)}")
        return result

    def check_password_harvesting(self, susp_data: dict, real_domain: str) -> dict:
        """Layer 10: Password harvesting detection — credential stealing form patterns."""
        result = {"harvesting_detected": False, "harvest_risk": 0, "harvest_details": []}
        try:
            soup = BeautifulSoup(susp_data.get('raw_html', ''), 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '').lower()
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                has_password = any(i.get('type', '').lower() == 'password' for i in inputs)
                has_external_action = action.startswith('http') and real_domain not in action
                autocomplete_off = form.get('autocomplete', '').lower() == 'off'
                if has_password and has_external_action:
                    result["harvesting_detected"] = True
                    result["harvest_risk"] += 80
                    result["harvest_details"].append(f"CREDENTIAL HARVESTER: Password form submits to external domain ({action})")
                elif has_password and method == 'get':
                    result["harvesting_detected"] = True
                    result["harvest_risk"] += 50
                    result["harvest_details"].append("INSECURE CREDENTIAL FORM: Password sent via GET request (exposes in URL)")
                if has_password and autocomplete_off:
                    result["harvest_risk"] += 15
                    result["harvest_details"].append("ANTI-AUTOFILL: autocomplete=off on password form (hides from password managers)")
        except Exception as e:
            result["harvest_details"].append(f"Harvest check skipped: {str(e)}")
        result["harvest_risk"] = min(result["harvest_risk"], 100)
        return result

    def check_inline_keylogger(self, susp_data: dict) -> dict:
        """Layer 11: Inline keylogger detection — JS event listeners on input fields that exfiltrate keystrokes."""
        result = {"keylogger_detected": False, "keylogger_risk": 0, "keylogger_details": []}
        try:
            html = susp_data.get('raw_html', '')
            keylogger_patterns = [
                (r'addEventListener\([\'"]keyup[\'"]', "keyup listener on input"),
                (r'addEventListener\([\'"]keypress[\'"]', "keypress listener"),
                (r'addEventListener\([\'"]input[\'"]', "input event exfil"),
                (r'onkeyup\s*=', "inline onkeyup handler"),
                (r'onkeypress\s*=', "inline onkeypress handler"),
                (r'navigator\.sendBeacon', "sendBeacon data exfiltration"),
                (r'fetch\([\'"]http(?!s://(?:' + '|'.join([v.split('/')[2] for v in self.trusted_vault.values()]) + r'))', "fetch to external domain"),
                (r'XMLHttpRequest.*open.*POST', "XHR POST to external"),
            ]
            for pattern, description in keylogger_patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    result["keylogger_detected"] = True
                    result["keylogger_risk"] += 25
                    result["keylogger_details"].append(f"KEYLOGGER PATTERN: {description}")
        except Exception as e:
            result["keylogger_details"].append(f"Keylogger check skipped: {str(e)}")
        result["keylogger_risk"] = min(result["keylogger_risk"], 100)
        return result

    def check_image_similarity(self, susp_data: dict, brand: str) -> dict:
        """Layer 12: Image URL pattern similarity — clones reference same CDN paths or copy filenames."""
        result = {"image_clone_detected": False, "image_risk": 0, "image_details": []}
        try:
            brand_name = brand.split('.')[0].lower()
            real_url = self.trusted_vault.get(brand, "")
            real_domain = urlparse(real_url).netloc if real_url else ""
            susp_images = susp_data.get('images', [])
            # Check if suspicious site hotlinks images directly from real brand CDN
            hotlinked = [img for img in susp_images if real_domain and real_domain in img]
            if hotlinked:
                result["image_clone_detected"] = True
                result["image_risk"] += 40
                result["image_details"].append(f"IMAGE HOTLINKING: {len(hotlinked)} images loaded from {real_domain}")
            # Check for brand logo filenames in image paths
            logo_patterns = [brand_name, f"{brand_name}-logo", f"{brand_name}_logo", "logo"]
            logo_matches = [img for img in susp_images if any(pat in img.lower() for pat in logo_patterns)]
            if logo_matches and not hotlinked:
                result["image_risk"] += 20
                result["image_details"].append(f"BRAND LOGO COPY: {len(logo_matches)} images with brand logo filename patterns")
        except Exception as e:
            result["image_details"].append(f"Image check skipped: {str(e)}")
        return result

    def check_ssl_certificate(self, url: str, expected_brand: str) -> dict:
        """Layer 4: SSL Certificate forensics — org name mismatch, self-signed, expired certs."""
        result = {"ssl_valid": False, "ssl_org": None, "ssl_mismatch": False, "ssl_risk": 0, "ssl_details": []}
        try:
            parsed = urlparse(url if url.startswith("http") else "https://" + url)
            hostname = parsed.netloc.split(":")[0]
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname) as s:
                cert = s.getpeercert()
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            org = subject.get('organizationName', '').lower()
            cn = subject.get('commonName', '').lower()
            result["ssl_valid"] = True
            result["ssl_org"] = org
            result["ssl_cn"] = cn
            brand_lower = expected_brand.split('.')[0].lower()
            if org and brand_lower not in org:
                result["ssl_mismatch"] = True
                result["ssl_risk"] += 40
                result["ssl_details"].append(f"SSL Org '{org}' doesn't match brand '{expected_brand}'")
            free_issuers = ['let\'s encrypt', 'zerossl', 'buypass']
            issuer_org = issuer.get('organizationName', '').lower()
            if any(fi in issuer_org for fi in free_issuers):
                result["ssl_risk"] += 15
                result["ssl_details"].append(f"Free CA detected: {issuer_org} (common in phishing sites)")
        except ssl.SSLCertVerificationError:
            result["ssl_risk"] += 60
            result["ssl_details"].append("SSL Certificate Verification FAILED (self-signed or invalid)")
        except Exception as e:
            result["ssl_details"].append(f"SSL check skipped: {str(e)}")
        return result

    def check_favicon_theft(self, suspicious_url: str, real_url: str) -> dict:
        """Layer 5: Favicon hash comparison — attackers often hotlink or copy brand favicons."""
        result = {"favicon_stolen": False, "favicon_risk": 0, "favicon_details": []}
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            def get_favicon_hash(base_url):
                parsed = urlparse(base_url)
                favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
                r = secure_get(favicon_url, timeout=5, headers=headers, enable_ssl_fallback=True)
                if r.status_code == 200 and len(r.content) > 0:
                    return hashlib.md5(r.content).hexdigest(), favicon_url
                soup = BeautifulSoup(secure_get(base_url, timeout=5, headers=headers, enable_ssl_fallback=True).text, 'html.parser')
                icon_tag = soup.find('link', rel=lambda x: x and 'icon' in ' '.join(x).lower())
                if icon_tag and icon_tag.get('href'):
                    fav_url = urljoin(base_url, icon_tag['href'])
                    r2 = secure_get(fav_url, timeout=5, headers=headers, enable_ssl_fallback=True)
                    if r2.status_code == 200:
                        return hashlib.md5(r2.content).hexdigest(), fav_url
                return None, None
            susp_hash, susp_fav_url = get_favicon_hash(suspicious_url)
            real_hash, _ = get_favicon_hash(real_url)
            if susp_hash and real_hash:
                if susp_hash == real_hash:
                    result["favicon_stolen"] = True
                    result["favicon_risk"] += 50
                    result["favicon_details"].append(f"FAVICON THEFT: Identical favicon hash ({susp_hash[:12]}...) as real brand")
                else:
                    result["favicon_details"].append("Favicon differs from real brand (could be original design)")
            if susp_fav_url:
                real_domain = urlparse(real_url).netloc
                if real_domain in susp_fav_url:
                    result["favicon_stolen"] = True
                    result["favicon_risk"] += 40
                    result["favicon_details"].append(f"HOTLINKED FAVICON: Loading icon directly from {real_domain}")
        except Exception as e:
            result["favicon_details"].append(f"Favicon check skipped: {str(e)}")
        return result

    def check_redirect_chain(self, url: str) -> dict:
        """Layer 6: Redirect chain analysis — legitimate sites don't bounce through 3+ redirects."""
        result = {"redirect_count": 0, "suspicious_redirects": [], "redirect_risk": 0, "redirect_details": []}
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = secure_get(url if url.startswith("http") else "https://" + url,
                                timeout=10, headers=headers, allow_redirects=True, enable_ssl_fallback=True)
            history = resp.history
            result["redirect_count"] = len(history)
            result["final_url"] = resp.url
            suspicious_redirect_domains = ['bit.ly', 'tinyurl', 't.co', 'cutt.ly', 'goo.gl', 'ow.ly', 'rb.gy']
            for r in history:
                location = r.headers.get('Location', '')
                if any(sd in location for sd in suspicious_redirect_domains):
                    result["suspicious_redirects"].append(location)
                    result["redirect_risk"] += 20
                    result["redirect_details"].append(f"URL shortener in redirect chain: {location}")
            if len(history) >= 3:
                result["redirect_risk"] += 25
                result["redirect_details"].append(f"Excessive redirects: {len(history)} hops (phishing sites often chain redirects)")
            original_domain = urlparse(url).netloc
            final_domain = urlparse(resp.url).netloc
            if original_domain and final_domain and original_domain != final_domain:
                result["redirect_risk"] += 30
                result["redirect_details"].append(f"Domain switch in redirect: {original_domain} → {final_domain}")
        except Exception as e:
            result["redirect_details"].append(f"Redirect check skipped: {str(e)}")
        return result

    def check_meta_tag_spoofing(self, url: str, expected_brand: str) -> dict:
        """Layer 7: Meta tag & OG tag spoofing — fake sites set brand names in meta to appear legitimate."""
        result = {"meta_spoofing_detected": False, "meta_risk": 0, "meta_details": []}
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            r = secure_get(url if url.startswith("http") else "https://" + url,
                             timeout=8, headers=headers, enable_ssl_fallback=True)
            soup = BeautifulSoup(r.text, 'html.parser')
            brand_lower = expected_brand.split('.')[0].lower()
            domain = urlparse(r.url).netloc.lower()
            meta_checks = {
                'og:site_name': soup.find('meta', property='og:site_name'),
                'og:title': soup.find('meta', property='og:title'),
                'application-name': soup.find('meta', attrs={'name': 'application-name'}),
                'author': soup.find('meta', attrs={'name': 'author'}),
            }
            for tag_name, tag in meta_checks.items():
                if tag:
                    content = tag.get('content', '').lower()
                    if brand_lower in content and brand_lower not in domain:
                        result["meta_spoofing_detected"] = True
                        result["meta_risk"] += 35
                        result["meta_details"].append(f"META SPOOFING [{tag_name}]: Claims to be '{expected_brand}' but domain is '{domain}'")
            canonical = soup.find('link', rel='canonical')
            if canonical:
                canonical_href = canonical.get('href', '').lower()
                if brand_lower in canonical_href and brand_lower not in domain:
                    result["meta_spoofing_detected"] = True
                    result["meta_risk"] += 25
                    result["meta_details"].append(f"CANONICAL SPOOFING: Points to '{canonical_href}' to fake legitimacy")
        except Exception as e:
            result["meta_details"].append(f"Meta tag check skipped: {str(e)}")
        return result

    def analyze(self, suspicious_url: str) -> dict:
        """Compares suspicious site structure against the trusted vault using DOM DNA."""
        logging.info(f"[CLONE ENGINE] Initiating DOM Forensics on: {suspicious_url}")
        
        results = {
            "target_url": suspicious_url,
            "clone_detected": False,
            "mimicked_brand": "None",
            "mismatch_reason": [],
            "structural_similarity": 0.0,
            "calculated_risk": 0
        }

        # 1. Fetch suspicious site structure
        susp_data = self.fetch_structure(suspicious_url)
        if not susp_data:
            results["status"] = "Fetch Failed"
            return results

        # 2. Brand Detection — title + body text (catches clones that hide brand in body only)
        susp_title = susp_data['title'].lower()
        body_detected_brand = self.detect_brand_from_body(susp_data)

        for brand, real_url in self.trusted_vault.items():
            brand_name = brand.split('.')[0]
            # Match from title OR body text
            if brand_name in susp_title or brand == body_detected_brand:
                results["mimicked_brand"] = brand
                logging.info(f"[!] Site claims to be {brand}. Comparing DOM DNA...")
                
                real_data = self.fetch_structure(real_url)
                if not real_data: continue

                # --- LAYER 1: FORM HIJACKING CHECK ---
                susp_forms = susp_data['forms']
                real_domain = urlparse(real_url).netloc
                
                for action in susp_forms:
                    # If form action is external and doesn't belong to the real brand
                    if action.startswith('http') and real_domain not in action:
                        results["clone_detected"] = True
                        results["mismatch_reason"].append(f"Form Hijacking: Data sent to {action}")
                        results["calculated_risk"] += 60

                # --- LAYER 2: STRUCTURAL SIMILARITY (DNA MATCH) ---
                # We compare the ratio of tags. Clones usually have nearly identical counts.
                matches = 0
                total_tags = len(real_data['tag_counts'])
                for tag, count in real_data['tag_counts'].items():
                    susp_count = susp_data['tag_counts'].get(tag, 0)
                    # If counts are within 10% margin, it's a structural match
                    if count > 0 and abs(count - susp_count) / count <= 0.15:
                        matches += 1
                
                results["structural_similarity"] = (matches / total_tags) * 100
                
                if results["structural_similarity"] >= 80:
                    results["clone_detected"] = True
                    results["mismatch_reason"].append(f"DOM DNA Match: {results['structural_similarity']:.1f}% structural similarity")
                    results["calculated_risk"] += 40

                # --- LAYER 3: CONTENT HOTLINKING ---
                hotlink_count = sum(1 for s in susp_data['scripts'] if real_domain in s)
                if hotlink_count >= 2:
                    results["clone_detected"] = True
                    results["mismatch_reason"].append(f"Hotlinking: {hotlink_count} scripts loaded from {real_domain}")
                    results["calculated_risk"] += 30

                # --- LAYER 8: CSS FINGERPRINTING ---
                css_result = self.check_css_fingerprint(susp_data, brand)
                results["css_analysis"] = css_result
                if css_result["css_clone_detected"]:
                    results["clone_detected"] = True
                    results["calculated_risk"] += css_result["css_risk"]
                    results["mismatch_reason"].extend(css_result["css_details"])

                # --- LAYER 10: PASSWORD HARVESTING ---
                harvest_result = self.check_password_harvesting(susp_data, real_domain)
                results["password_harvesting"] = harvest_result
                if harvest_result["harvesting_detected"]:
                    results["clone_detected"] = True
                    results["calculated_risk"] += harvest_result["harvest_risk"]
                    results["mismatch_reason"].extend(harvest_result["harvest_details"])

                # --- LAYER 12: IMAGE SIMILARITY ---
                image_result = self.check_image_similarity(susp_data, brand)
                results["image_analysis"] = image_result
                if image_result["image_clone_detected"]:
                    results["clone_detected"] = True
                    results["calculated_risk"] += image_result["image_risk"]
                    results["mismatch_reason"].extend(image_result["image_details"])

        # --- LAYER 4: SSL CERTIFICATE FORENSICS ---
        if results.get("mimicked_brand") and results["mimicked_brand"] != "None":
            ssl_result = self.check_ssl_certificate(suspicious_url, results["mimicked_brand"])
            results["ssl_analysis"] = ssl_result
            if ssl_result["ssl_risk"] > 0:
                results["calculated_risk"] += ssl_result["ssl_risk"]
                results["mismatch_reason"].extend(ssl_result["ssl_details"])
                if ssl_result.get("ssl_mismatch"):
                    results["clone_detected"] = True

            # --- LAYER 5: FAVICON THEFT DETECTION ---
            real_url_for_brand = self.trusted_vault.get(results["mimicked_brand"], "")
            if real_url_for_brand:
                favicon_result = self.check_favicon_theft(suspicious_url, real_url_for_brand)
                results["favicon_analysis"] = favicon_result
                if favicon_result["favicon_stolen"]:
                    results["clone_detected"] = True
                    results["calculated_risk"] += favicon_result["favicon_risk"]
                    results["mismatch_reason"].extend(favicon_result["favicon_details"])

            # --- LAYER 6: REDIRECT CHAIN ANALYSIS ---
            redirect_result = self.check_redirect_chain(suspicious_url)
            results["redirect_analysis"] = redirect_result
            if redirect_result["redirect_risk"] > 0:
                results["calculated_risk"] += redirect_result["redirect_risk"]
                results["mismatch_reason"].extend(redirect_result["redirect_details"])

            # --- LAYER 7: META TAG SPOOFING ---
            meta_result = self.check_meta_tag_spoofing(suspicious_url, results["mimicked_brand"])
            results["meta_analysis"] = meta_result
            if meta_result["meta_spoofing_detected"]:
                results["clone_detected"] = True
                results["calculated_risk"] += meta_result["meta_risk"]
                results["mismatch_reason"].extend(meta_result["meta_details"])

            # --- LAYER 9: WHOIS DOMAIN AGE ---
            age_result = self.check_whois_age(suspicious_url)
            results["whois_analysis"] = age_result
            if age_result["age_risk"] > 0:
                results["calculated_risk"] += age_result["age_risk"]
                results["mismatch_reason"].extend(age_result["age_details"])

            # --- LAYER 11: INLINE KEYLOGGER DETECTION ---
            keylogger_result = self.check_inline_keylogger(susp_data)
            results["keylogger_analysis"] = keylogger_result
            if keylogger_result["keylogger_detected"]:
                results["clone_detected"] = True
                results["calculated_risk"] += keylogger_result["keylogger_risk"]
                results["mismatch_reason"].extend(keylogger_result["keylogger_details"])

        # 3. ADVANCED: Visual Comparison using AI
        if results.get("mimicked_brand"):
            logging.info(f"[CLONE] Performing visual analysis on: {suspicious_url}")
            
            # Visual analysis of suspicious site
            visual_results = self.visual_analyzer.analyze(suspicious_url)
            results["visual_analysis"] = visual_results
            
            # Check for brand mismatch in visual analysis
            if visual_results.get("detected_brand") and visual_results.get("brand_domain_match", {}).get("is_suspicious_mismatch"):
                results["clone_detected"] = True
                results["mismatch_reason"].append(
                    f"AI Visual Mismatch: Page visually mimics {visual_results['detected_brand']} but domain doesn't match"
                )
                results["calculated_risk"] += 50
                logging.critical(f"🚨 AI CONFIRMED CLONE: {visual_results['detected_brand']} visual spoof!")
            
            # Add visual spoofing indicators
            if visual_results.get("visual_spoofing_indicators"):
                results["visual_indicators"] = visual_results["visual_spoofing_indicators"]
                results["calculated_risk"] += len(visual_results["visual_spoofing_indicators"]) * 10
            
            # 4. SANDBOX DETONATION for Deep Analysis
            logging.info(f"[CLONE] Running sandbox detonation on: {suspicious_url}")
            detonation_results = sandbox_detonator.detonate(suspicious_url, case_id="CLONE_DETECT")
            results["sandbox_analysis"] = detonation_results
            
            # Check for malicious behavior in sandbox
            if detonation_results.get("malicious_indicators"):
                results["calculated_risk"] += 30
                for indicator in detonation_results["malicious_indicators"]:
                    if "exfiltration" in indicator.lower():
                        results["mismatch_reason"].append(f"Data Exfiltration: {indicator}")
                        results["calculated_risk"] += 20
            
            # Check for API analysis
            if detonation_results.get("api_analysis", {}).get("exfiltration_attempts_count", 0) > 0:
                results["clone_detected"] = True
                results["mismatch_reason"].append(
                    f"CREDENTIAL THEFT: {detonation_results['api_analysis']['exfiltration_attempts_count']} exfiltration attempts"
                )
                results["calculated_risk"] = 100  # MAX RISK
            
            # 5. BROWSER FINGERPRINTING DETECTION
            if detonation_results.get("final_page_info", {}).get("console_logs"):
                fp_analysis = fingerprinting_detector.detect_from_console_logs(
                    detonation_results["final_page_info"]["console_logs"],
                    suspicious_url
                )
                results["fingerprinting_analysis"] = fp_analysis
                
                if fp_analysis.get("fingerprinting_detected"):
                    results["calculated_risk"] += 20
                    results["mismatch_reason"].append(
                        f"Browser Fingerprinting: {len(fp_analysis.get('techniques', []))} tracking techniques detected"
                    )
            
            # 6. CAMPAIGN ATTRIBUTION
            clone_indicators = {
                "url_pattern": suspicious_url,
                "domain": urlparse(suspicious_url).netloc,
                "detected_brand": results.get("mimicked_brand"),
                "structural_similarity": results.get("structural_similarity"),
                "risk_level": "CRITICAL" if results["calculated_risk"] > 80 else "HIGH" if results["calculated_risk"] > 50 else "MEDIUM"
            }
            attribution = attribution_engine.attribute_attack(clone_indicators)
            results["attribution"] = attribution
            
            # 7. QR FINGERPRINT (for tracking this clone)
            fingerprint = qr_fingerprint_engine.create_fingerprint(
                suspicious_url,
                campaign_id=attribution.get("primary_attribution", {}).get("actor_id")
            )
            results["fingerprint_id"] = fingerprint.fingerprint_id
        
        # 8. ML-BASED DOMAIN ANALYSIS
        ml_result = ml_detector.predict(suspicious_url)
        results["ml_analysis"] = ml_result
        
        if ml_result.get("classification") == "PHISHING":
            results["calculated_risk"] += 25
            if not results.get("clone_detected"):
                results["mismatch_reason"].append(f"ML Detection: {ml_result.get('phishing_probability', 0):.0f}% phishing probability")
        
        # Final Risk Calculation
        results["calculated_risk"] = min(results["calculated_risk"], 100)

        # Verdict summary
        if results["clone_detected"]:
            results["verdict"] = f"CLONE DETECTED — {results['mimicked_brand']} spoofed | Risk: {results['calculated_risk']}%"
            logging.warning(f"[!] CLONE DETECTED: {results['mimicked_brand']} spoofed with {results['calculated_risk']}% confidence.")
        elif results["calculated_risk"] >= 40:
            results["verdict"] = f"SUSPICIOUS — Possible clone attempt | Risk: {results['calculated_risk']}%"
        else:
            results["verdict"] = f"CLEAN — No clone indicators found | Risk: {results['calculated_risk']}%"

        return results