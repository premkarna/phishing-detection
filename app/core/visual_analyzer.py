"""
AI-Driven Visual Brand Analyzer - Detects visual spoofing using AI Vision APIs
Combines HTML analysis with AI-powered screenshot analysis for comprehensive detection
"""

import re
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import logging
import os
import base64
import io
from typing import Dict, Optional, List

# Secure HTTP requests
from app.integrations.secure_requests import secure_get

# AI Integration
try:
    from app.integrations.ai_handler import AIHandler
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    logging.warning("[VISUAL ANALYZER] AI Handler not available - AI analysis disabled")

class VisualAnalyzer:
    """
    AI-Driven Website Visual Analyzer
    - Fetches actual page content
    - Captures screenshots for AI vision analysis
    - Detects brand logos and visual elements using AI
    - Identifies visual spoofing attempts
    """
    
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        
        # Initialize AI handler if available
        self.ai_handler = AIHandler() if AI_AVAILABLE else None
        
        # Screenshot settings
        self.screenshot_timeout = 30
        self.screenshot_width = 1920
        self.screenshot_height = 1080
        
        # Trusted brands for comparison
        self.trusted_brands = {
            "google": ["google.com", "accounts.google.com", "mail.google.com", "drive.google.com"],
            "facebook": ["facebook.com", "fb.com", "instagram.com", "whatsapp.com"],
            "microsoft": ["microsoft.com", "login.microsoftonline.com", "outlook.com", "office.com"],
            "apple": ["apple.com", "icloud.com", "id.apple.com"],
            "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"],
            "paypal": ["paypal.com", "paypal.me"],
            "netflix": ["netflix.com"],
            "instagram": ["instagram.com"],
            "twitter": ["twitter.com", "x.com"],
            "linkedin": ["linkedin.com"],
            "bankofamerica": ["bankofamerica.com"],
            "chase": ["chase.com"],
            "wellsfargo": ["wellsfargo.com"],
            "citibank": ["citibank.com"]
        }
        
        # Brand visual signatures
        self.brand_signatures = {
            "google": {
                "logos": ["googlelogo", "google-logo", "g-logo", "google.svg"],
                "colors": ["#4285F4", "#34A853", "#FBBC05", "#EA4335"],
                "keywords": ["sign in", "google account", "gmail", "search"]
            },
            "facebook": {
                "logos": ["facebook", "fb-logo", "f_logo", "meta"],
                "colors": ["#1877F2", "#4267B2", "#FFFFFF"],
                "keywords": ["log in", "facebook", "connect with friends"]
            },
            "microsoft": {
                "logos": ["microsoft", "ms-logo", "windows-logo"],
                "colors": ["#00A4EF", "#F25022", "#7FBA00", "#FFB900"],
                "keywords": ["sign in", "microsoft account", "office 365", "onedrive"]
            },
            "apple": {
                "logos": ["apple", "apple-logo", ""],
                "colors": ["#555555", "#000000", "#FFFFFF"],
                "keywords": ["sign in", "apple id", "icloud", "app store"]
            },
            "amazon": {
                "logos": ["amazon", "a-logo", "amazon-logo"],
                "colors": ["#FF9900", "#232F3E"],
                "keywords": ["sign in", "amazon account", "prime", "cart"]
            },
            "paypal": {
                "logos": ["paypal", "pp-logo", "paypal-logo"],
                "colors": ["#003087", "#009CDE", "#FFFFFF"],
                "keywords": ["log in", "paypal account", "wallet", "send money"]
            },
            "netflix": {
                "logos": ["netflix", "n-logo", "netflix-logo"],
                "colors": ["#E50914", "#221F1F", "#FFFFFF"],
                "keywords": ["sign in", "netflix account", "watch", "stream"]
            },
            "instagram": {
                "logos": ["instagram", "ig-logo", "insta"],
                "colors": ["#E4405F", "#833AB4", "#C13584"],
                "keywords": ["log in", "instagram", "share photos", "followers"]
            }
        }
    
    def _capture_screenshot(self, url: str) -> Optional[bytes]:
        """
        Capture screenshot of the webpage using Playwright.
        
        Returns:
            Screenshot as PNG bytes, or None if failed
        """
        try:
            # Try to import Playwright
            from playwright.sync_api import sync_playwright
            
            logging.info(f"[VISUAL ANALYZER] Capturing screenshot of: {url}")
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(viewport={
                    'width': self.screenshot_width,
                    'height': self.screenshot_height
                })
                
                # Set timeout and navigate
                page.set_default_timeout(self.screenshot_timeout * 1000)
                
                try:
                    page.goto(url, wait_until='networkidle', timeout=30000)
                    # Wait a bit for any lazy-loaded content
                    page.wait_for_timeout(2000)
                    
                    # Capture screenshot
                    screenshot = page.screenshot(full_page=False, type='png')
                    
                    browser.close()
                    
                    logging.info("[VISUAL ANALYZER] Screenshot captured successfully")
                    return screenshot
                    
                except Exception as e:
                    browser.close()
                    logging.warning(f"[VISUAL ANALYZER] Screenshot capture failed: {e}")
                    return None
                    
        except ImportError:
            logging.warning("[VISUAL ANALYZER] Playwright not installed - screenshot capture disabled")
            return None
        except Exception as e:
            logging.error(f"[VISUAL ANALYZER] Screenshot error: {e}")
            return None
    
    def _analyze_screenshot_with_ai(self, screenshot_bytes: bytes, url: str) -> Dict:
        """
        Analyze screenshot using AI Vision API.
        
        Args:
            screenshot_bytes: PNG screenshot data
            url: The URL being analyzed
            
        Returns:
            AI analysis results including brand detection and spoofing assessment
        """
        results = {
            "ai_analysis_available": False,
            "ai_detected_brand": None,
            "ai_spoofing_assessment": None,
            "ai_confidence": 0,
            "ai_risk_score": 0,
            "ai_reasoning": None,
            "error": None
        }
        
        if not self.ai_handler or not AI_AVAILABLE:
            results["error"] = "AI handler not available"
            return results
        
        try:
            # Convert screenshot to base64
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            
            # Prepare AI prompt for visual analysis - AGGRESSIVE SPOOFING DETECTION
            prompt = f"""CRITICAL SECURITY ANALYSIS REQUIRED

You are analyzing a screenshot of a webpage at URL: {url}

🎯 PRIMARY OBJECTIVE: Detect visual brand spoofing/phishing attempts

ANALYZE CAREFULLY:
1. **Brand Identification**: What major brand does this page visually impersonate?
   - Look for: Google, Microsoft, Apple, Amazon, Facebook, PayPal, Netflix, banks (Chase, BofA, Wells Fargo), etc.
   
2. **Login Page Detection**: Is this a login/authentication page?
   - Check for: username fields, password fields, "Sign In", "Login", "Authenticate" buttons
   
3. **SPOOFING ANALYSIS** (CRITICAL):
   - ⚠️ Logo quality: Official logo OR fake/misspelled version? (e.g., "G00gle", "Micros0ft")
   - ⚠️ Colors: Brand-accurate colors OR slightly off?
   - ⚠️ Fonts: Professional fonts OR amateur/low-quality?
   - ⚠️ Layout: Clean professional layout OR broken/misaligned?
   - ⚠️ URL Mismatch: Page looks like [Brand] but URL is NOT official?
   
4. **RED FLAGS**:
   - Misspelled brand names in logos or text
   - Low-resolution/pixelated logos
   - Mismatched brand colors
   - Amateur design quality
   - Suspicious URL (e.g., google-login.tk instead of google.com)

RESPOND IN THIS EXACT JSON FORMAT:
{{
    "detected_brand": "exact brand name or null",
    "is_login_page": true/false,
    "is_credential_page": true/false,
    "appears_spoofed": true/false,
    "spoofing_confidence": 0-100,
    "visual_quality": "professional/amateur/broken",
    "logo_authentic": true/false,
    "color_accuracy": "accurate/slightly_off/completely_wrong",
    "indicators": [
        "specific indicator 1",
        "specific indicator 2"
    ],
    "url_appears_fake": true/false,
    "risk_assessment": "SAFE/SUSPICIOUS/MALICIOUS",
    "reasoning": "detailed explanation of visual analysis"
}}

⚠️ SECURITY PRIORITY: If the page mimics a major brand (Google, Microsoft, etc.) but has ANY visual inconsistencies, set "appears_spoofed": true and "risk_assessment": "MALICIOUS".

Be EXTREMELY critical of visual quality - phishing sites often have:
- Wrong colors (Google's #4285F4 vs slightly different blue)
- Blurry logos
- Wrong fonts
- Misaligned elements
- Misspelled text"""

            # Send to AI with image
            ai_response = self.ai_handler.analyze_image(
                prompt=prompt,
                image_data=screenshot_b64,
                mime_type="image/png"
            )
            
            # Parse AI response
            if ai_response:
                results["ai_analysis_available"] = True
                
                # Extract JSON from response
                try:
                    # Find JSON in the response
                    json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
                    if json_match:
                        ai_data = json.loads(json_match.group())
                        
                        # Enhanced fields from new prompt
                        results["ai_detected_brand"] = ai_data.get("detected_brand")
                        results["ai_confidence"] = ai_data.get("spoofing_confidence", 0)
                        results["ai_reasoning"] = ai_data.get("reasoning")
                        results["ai_indicators"] = ai_data.get("indicators", [])
                        results["ai_visual_quality"] = ai_data.get("visual_quality")
                        results["ai_logo_authentic"] = ai_data.get("logo_authentic")
                        results["ai_color_accuracy"] = ai_data.get("color_accuracy")
                        results["ai_url_appears_fake"] = ai_data.get("url_appears_fake", False)
                        results["ai_risk_assessment"] = ai_data.get("risk_assessment", "UNKNOWN")
                        
                        # INSTANT RED FLAG LOGIC
                        is_credential_page = ai_data.get("is_credential_page", False) or ai_data.get("is_login_page", False)
                        appears_spoofed = ai_data.get("appears_spoofed", False)
                        risk_assessment = ai_data.get("risk_assessment", "SAFE")
                        spoofing_confidence = ai_data.get("spoofing_confidence", 0)
                        
                        # 🚨 INSTANT RED FLAG CONDITIONS
                        if appears_spoofed and is_credential_page and spoofing_confidence > 70:
                            results["ai_spoofing_assessment"] = "CONFIRMED_PHISHING"
                            results["ai_risk_score"] = 60  # HIGH RISK
                            logging.critical(f"🚨🚨🚨 [VISUAL ANALYZER] CONFIRMED PHISHING: {results['ai_detected_brand']} login page spoof with {spoofing_confidence}% confidence!")
                        
                        elif appears_spoofed or risk_assessment == "MALICIOUS":
                            results["ai_spoofing_assessment"] = "spoofed"
                            results["ai_risk_score"] = 45
                            logging.critical(f"🚨 [VISUAL ANALYZER] BRAND SPOOFING DETECTED: {results['ai_detected_brand']} visual spoof!")
                        
                        elif is_credential_page and results["ai_detected_brand"]:
                            results["ai_spoofing_assessment"] = "potential_spoofing"
                            results["ai_risk_score"] = 25
                            logging.warning(f"[VISUAL ANALYZER] Potential spoofing: {results['ai_detected_brand']} page detected")
                        
                        else:
                            results["ai_spoofing_assessment"] = "likely_legitimate"
                            results["ai_risk_score"] = 0
                        
                        # Log all detected indicators
                        if results["ai_indicators"]:
                            for indicator in results["ai_indicators"]:
                                logging.warning(f"[VISUAL ANALYZER] Indicator: {indicator}")
                        
                        logging.info(f"[VISUAL ANALYZER] AI: {results['ai_detected_brand']} | Spoofed: {appears_spoofed} | Risk: {risk_assessment}")
                        
                except json.JSONDecodeError:
                    results["error"] = "Could not parse AI response as JSON"
                    logging.error("[VISUAL ANALYZER] Failed to parse AI response")
            else:
                results["error"] = "AI returned no response"
                
        except Exception as e:
            results["error"] = f"AI analysis failed: {str(e)}"
            logging.error(f"[VISUAL ANALYZER] AI analysis error: {e}")
        
        return results
    
    def _check_brand_domain_match(self, detected_brand: str, domain: str) -> Dict:
        """
        Check if detected brand matches the actual domain.
        
        Returns:
            Domain matching analysis results
        """
        results = {
            "brand_detected": detected_brand,
            "domain": domain,
            "is_official_domain": False,
            "is_suspicious_mismatch": False,
            "risk_score": 0,
            "reasoning": None
        }
        
        if not detected_brand:
            return results
        
        detected_brand = detected_brand.lower().strip()
        domain_lower = domain.lower()
        
        # Check against trusted domains
        for brand, trusted_domains in self.trusted_brands.items():
            if brand in detected_brand or detected_brand in brand:
                # Check if current domain is in trusted list
                if any(td in domain_lower for td in trusted_domains):
                    results["is_official_domain"] = True
                    results["reasoning"] = f"Domain matches official {brand} domains"
                    return results
                else:
                    # Brand detected but not on official domain
                    results["is_suspicious_mismatch"] = True
                    results["risk_score"] = 50
                    results["reasoning"] = f"CRITICAL: Page mimics {brand.upper()} but domain {domain} is NOT an official {brand} domain"
                    logging.critical(f"[VISUAL ANALYZER] 🚨 BRAND MISMATCH: {brand} page on {domain}")
                    return results
        
        # Check for common spoofing patterns
        if detected_brand in ["google", "facebook", "microsoft", "apple", "amazon", "paypal", "netflix"]:
            # Brand detected but no match found = spoofing attempt
            results["is_suspicious_mismatch"] = True
            results["risk_score"] = 45
            results["reasoning"] = f"Page appears to be {detected_brand} but domain doesn't match known official domains"
            logging.critical(f"[VISUAL ANALYZER] 🚨 POSSIBLE SPOOFING: {detected_brand} visual elements on {domain}")
        
        return results
    
    def analyze(self, target_url):
        """
        Perform live visual analysis of the target URL
        Returns visual spoofing indicators and brand mimicry score
        """
        logging.info(f"[*] VISUAL ANALYZER: Live scanning {target_url}...")
        
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
            
        parsed = urlparse(target_url)
        domain = parsed.netloc.replace("www.", "").lower()
        
        results = {
            "page_fetched": False,
            "page_title": None,
            "detected_brand": None,
            "brand_confidence": 0,
            "visual_spoofing_indicators": [],
            "login_form_detected": False,
            "credential_fields": 0,
            "suspicious_elements": [],
            "risk_score": 0,
            # AI-driven analysis results
            "ai_analysis": None,
            "screenshot_captured": False,
            "brand_domain_match": None
        }
        
        try:
            # LIVE PAGE FETCH - This is what differentiates us from ChatGPT!
            res = secure_get(target_url, headers=self.headers, timeout=15, allow_redirects=True, enable_ssl_fallback=True)
            results["page_fetched"] = True
            
            soup = BeautifulSoup(res.text, 'html.parser')
            
            # Get page title
            title_tag = soup.find('title')
            if title_tag:
                results["page_title"] = title_tag.get_text(strip=True)
            
            # Detect login forms
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                password_field = any(inp.get('type') == 'password' for inp in inputs)
                email_field = any(inp.get('type') == 'email' or 'email' in str(inp.get('name', '')).lower() for inp in inputs)
                
                if password_field:
                    results["login_form_detected"] = True
                    results["credential_fields"] += 1
                    
                    # Check if form action is external
                    action = form.get('action', '').lower()
                    if action and not any(d in action for d in [domain, '/login', '/signin', 'javascript:']):
                        results["suspicious_elements"].append(f"Form submits to external: {action}")
                        results["risk_score"] += 30
            
            # Check for brand signatures in page content
            page_text = soup.get_text().lower()
            html_str = str(soup).lower()
            
            for brand, signatures in self.brand_signatures.items():
                brand_score = 0
                matches = []
                
                # Check for brand logos/images
                for logo in signatures["logos"]:
                    if logo in html_str:
                        brand_score += 25
                        matches.append(f"Logo: {logo}")
                
                # Check for brand keywords
                for keyword in signatures["keywords"]:
                    if keyword in page_text:
                        brand_score += 15
                        matches.append(f"Keyword: {keyword}")
                
                # If brand score is high but domain doesn't match = SPOOFING!
                if brand_score >= 40:
                    if brand not in domain:
                        results["detected_brand"] = brand.upper()
                        results["brand_confidence"] = min(brand_score, 100)
                        results["visual_spoofing_indicators"].append(
                            f"VISUAL SPOOFING: Page mimics {brand.upper()} but domain is {domain}"
                        )
                        results["risk_score"] += 45
                        break
                    else:
                        results["detected_brand"] = brand.upper()
                        results["brand_confidence"] = min(brand_score, 100)
            
            # Check for suspicious visual patterns
            # Hidden elements
            hidden_inputs = len(soup.find_all('input', {'type': 'hidden'}))
            if hidden_inputs > 5:
                results["suspicious_elements"].append(f"Excessive hidden fields: {hidden_inputs}")
                results["risk_score"] += 10
            
            # Password fields outside forms
            standalone_password = soup.find_all('input', {'type': 'password'})
            if len(standalone_password) > results["credential_fields"]:
                results["suspicious_elements"].append("Password fields outside forms detected")
                results["risk_score"] += 25
            
            # Final scoring
            if results["login_form_detected"] and results["detected_brand"] and results["brand_confidence"] > 50:
                if results["detected_brand"].lower() not in domain:
                    results["visual_spoofing_indicators"].insert(0, 
                        f"🚨 CONFIRMED PHISHING: {results['detected_brand']} login page on non-official domain"
                    )
                    results["risk_score"] = min(100, results["risk_score"] + 50)
            
            results["risk_score"] = min(results["risk_score"], 100)
            
            # === AI-DRIVEN VISUAL ANALYSIS ===
            # Capture screenshot and analyze with AI for advanced spoofing detection
            logging.info("[VISUAL ANALYZER] Initiating AI-driven screenshot analysis...")
            
            screenshot = self._capture_screenshot(target_url)
            if screenshot:
                results["screenshot_captured"] = True
                
                # Analyze screenshot with AI
                ai_results = self._analyze_screenshot_with_ai(screenshot, target_url)
                results["ai_analysis"] = ai_results
                
                # Combine AI detection with HTML detection
                if ai_results["ai_detected_brand"]:
                    # Check if AI detected a different brand than HTML analysis
                    if not results["detected_brand"]:
                        results["detected_brand"] = ai_results["ai_detected_brand"].upper()
                        results["brand_confidence"] = ai_results["ai_confidence"]
                    
                    # Check brand-domain mismatch using AI detection
                    brand_match = self._check_brand_domain_match(
                        ai_results["ai_detected_brand"], 
                        domain
                    )
                    results["brand_domain_match"] = brand_match
                    
                    # Add AI risk score
                    results["risk_score"] += ai_results.get("ai_risk_score", 0)
                    
                    # Add AI-specific spoofing indicators
                    
                    # 🚨 INSTANT RED FLAG: CONFIRMED PHISHING
                    if ai_results["ai_spoofing_assessment"] == "CONFIRMED_PHISHING":
                        results["visual_spoofing_indicators"].insert(0,
                            f"🚨🚨🚨 INSTANT RED FLAG - CONFIRMED PHISHING: "
                            f"AI detected {ai_results['ai_detected_brand']} login page spoof with "
                            f"{ai_results['ai_confidence']}% confidence. "
                            f"Visual quality: {ai_results.get('ai_visual_quality', 'unknown')}. "
                            f"Indicators: {', '.join(ai_results.get('ai_indicators', []))}"
                        )
                        results["risk_score"] = min(100, results["risk_score"] + 60)  # MAX RISK
                    
                    elif brand_match.get("is_suspicious_mismatch"):
                        results["visual_spoofing_indicators"].append(
                            f"🤖 AI DETECTED SPOOFING: {brand_match['reasoning']}"
                        )
                        results["risk_score"] += brand_match.get("risk_score", 0)
                    
                    # Add AI confidence-based indicator
                    if ai_results["ai_confidence"] > 80 and ai_results["ai_spoofing_assessment"] == "spoofed":
                        results["visual_spoofing_indicators"].append(
                            f"🤖 AI HIGH CONFIDENCE: Page visually mimics {ai_results['ai_detected_brand']} with {ai_results['ai_confidence']}% confidence"
                        )
                    
                    # Add visual quality issues
                    if ai_results.get("ai_visual_quality") == "amateur" or ai_results.get("ai_visual_quality") == "broken":
                        results["visual_spoofing_indicators"].append(
                            f"⚠️ LOW VISUAL QUALITY: {ai_results['ai_visual_quality']} design detected"
                        )
                    
                    # Add logo/color issues
                    if ai_results.get("ai_logo_authentic") is False:
                        results["visual_spoofing_indicators"].append(
                            f"⚠️ FAKE LOGO DETECTED: Logo appears inauthentic or misspelled"
                        )
                    
                    if ai_results.get("ai_color_accuracy") in ["slightly_off", "completely_wrong"]:
                        results["visual_spoofing_indicators"].append(
                            f"⚠️ COLOR MISMATCH: Brand colors are {ai_results['ai_color_accuracy']}"
                        )
                
                logging.info(f"[+] AI Analysis Complete: Brand={ai_results['ai_detected_brand']}, Spoofing={ai_results['ai_spoofing_assessment']}")
            else:
                logging.warning("[VISUAL ANALYZER] Screenshot capture failed - AI analysis skipped")
                results["ai_analysis"] = {"error": "Screenshot capture failed"}
            
            # Final risk score cap
            results["risk_score"] = min(results["risk_score"], 100)
            
            logging.info(f"[+] Visual Analysis Complete: {len(results['visual_spoofing_indicators'])} indicators found, Risk Score: {results['risk_score']}")
            return results
            
        except requests.exceptions.Timeout:
            results["suspicious_elements"].append("Page timeout - potential dead link or blocking")
            return results
        except Exception as e:
            logging.error(f"[-] Visual Analysis Failed: {e}")
            results["suspicious_elements"].append(f"Scan failed: {str(e)}")
            return results

# Test
if __name__ == "__main__":
    analyzer = VisualAnalyzer()
    result = analyzer.analyze("https://google.com")
    print(f"\nLive Visual Analysis Results:")
    print(f"Page Fetched: {result['page_fetched']}")
    print(f"Title: {result['page_title']}")
    print(f"Brand: {result['detected_brand']} (confidence: {result['brand_confidence']})")
    print(f"Login Form: {result['login_form_detected']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Indicators: {result['visual_spoofing_indicators']}")
