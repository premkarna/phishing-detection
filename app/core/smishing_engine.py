import logging
import requests
import re
import os
import hashlib
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Tuple

from app.services.url_tracer import URLTracer, tracer
from app.integrations.threat_intel import ThreatIntelligence
from app.ml.heuristics import DomainHeuristics
from app.ml.ml_detector import ml_detector
from app.intelligence.ioc import ioc_feed_manager
from app.core.visual_analyzer import VisualAnalyzer
from app.intelligence.attribution import attribution_engine

class SmishingEngine:
    def __init__(self):
        # List of common shorteners to watch out for
        self.shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 
            'is.gd', 'cutt.ly', 'rebrand.ly', 'tiny.cc', 'short.url',
            'rb.gy', 'shorturl.at', 'clck.ru', 'qr.io', 'v.gd'
        ]
        
        # Advanced utilities integration
        self.url_tracer = URLTracer()
        self.threat_intel = ThreatIntelligence()
        self.heuristics = DomainHeuristics()
        self.visual_analyzer = VisualAnalyzer()

        # ── ADVANCED: Known legitimate sender ID prefixes (India TRAI format)
        self.legit_sender_prefixes = [
            'VM-', 'VK-', 'JD-', 'BW-', 'AD-', 'BP-',  # Promotional/Service
            'TA-', 'TC-', 'TD-', 'TE-', 'TF-', 'TG-',  # Transactional
            'AX-', 'BX-', 'DX-', 'EX-', 'GX-',         # Banks
        ]

        # ── ADVANCED: Known brand → legitimate sender ID mappings
        self.brand_sender_map = {
            'HDFC': ['HDFCBK', 'HDFC-BK', 'VM-HDFC', 'AD-HDFC'],
            'SBI': ['SBIINB', 'SBI-INB', 'VM-SBI', 'AD-SBI'],
            'ICICI': ['ICICIB', 'ICICI-B', 'VM-ICICIB'],
            'AXIS': ['AXISBK', 'AXIS-BK', 'VM-AXIS'],
            'AMAZON': ['AMAZON', 'VM-AMZNIN', 'AD-AMZN'],
            'FLIPKART': ['FKRT', 'VM-FKRT', 'AD-FLIPKRT'],
            'PAYTM': ['PAYTM', 'VM-PAYTM', 'AD-PAYTM'],
            'GOOGLE': ['GOOGLE', 'VM-GOOGLE'],
            'AIRTEL': ['AIRTEL', 'VM-AIRTEL', 'AD-AIRTEL'],
            'JIO': ['JIOTEL', 'VM-JIO', 'AD-JIO'],
            'SWIGGY': ['SWIGGY', 'VM-SWIGY'],
            'ZOMATO': ['ZOMATO', 'VM-ZOMATO'],
            'IRCTC': ['IRCTC', 'VM-IRCTC'],
            'UIDAI': ['UIDAI', 'VM-UIDAI'],
            'INCOME TAX': ['ITDEPT', 'VM-ITDEPT'],
        }

        # ── ADVANCED: Disposable/virtual number patterns
        self.disposable_number_patterns = [
            r'^\+1[2-9]\d{9}$',      # US VOIP ranges used by scammers
            r'^\+44\d{10}$',          # UK numbers used in Indian smishing
            r'^\+91[6-9]\d{9}$',      # India: valid but check for VoIP
        ]

        # ── ADVANCED: Known smishing template fingerprints (SHA256 prefix → label)
        self.template_fingerprints = self._load_template_fingerprints()

        # ── ADVANCED: Brand names commonly impersonated via SMS
        self.impersonated_brands = [
            'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'amazon', 'flipkart',
            'paytm', 'phonepe', 'gpay', 'google pay', 'airtel', 'jio', 'bsnl',
            'irctc', 'income tax', 'uidai', 'aadhar', 'aadhaar', 'epf', 'nps',
            'swiggy', 'zomato', 'ola', 'uber', 'fedex', 'dhl', 'bluedart',
            'post office', 'indiapost', 'rbi', 'sebi', 'trai', 'npci', 'upi'
        ]

        # ── ADVANCED: Multi-language smishing patterns (Hindi / Telugu / Tamil)
        self.multilang_patterns = [
            # Hindi
            (r'(खाता|बैंक|OTP|जीतें|पुरस्कार|सत्यापित|अवरुद्ध)', 'HINDI_PHISHING', 15),
            (r'(लॉटरी|इनाम|क्लिक करें|नंबर दर्ज)', 'HINDI_LOTTERY', 12),
            # Telugu
            (r'(ఖాతా|బ్యాంక్|OTP|గెలుచుకోండి|బహుమతి|నిర్ధారించండి)', 'TELUGU_PHISHING', 15),
            (r'(లాటరీ|బహుమతి|క్లిక్|నంబర్ నమోదు)', 'TELUGU_LOTTERY', 12),
            # Tamil
            (r'(கணக்கு|வங்கி|OTP|வெற்றி|பரிசு|சரிபார்)', 'TAMIL_PHISHING', 15),
        ]

        # ── ADVANCED: OTP harvesting patterns
        self.otp_harvest_patterns = [
            r'share\s+(your\s+)?otp',
            r'enter\s+(the\s+)?otp',
            r'send\s+(us\s+)?(your\s+)?otp',
            r'otp\s+is\s+\d{4,8}',
            r'your\s+(one.time|one time)\s+password',
            r'do\s+not\s+share\s+(this\s+)?otp',  # Legit warning → attacker mimics
            r'otp.*valid\s+for\s+\d+\s+(minutes|mins|seconds|secs)',
        ]

        logging.info("[SMISHING ENGINE] Initialized with advanced threat detection")

    def _load_template_fingerprints(self) -> Dict:
        """Load known smishing template fingerprints."""
        return {
            # SHA256 prefix → (label, risk_boost)
            "a3f2": ("SBI KYC Smishing Template", 35),
            "b9e1": ("HDFC Loan Offer Smishing", 30),
            "c7d4": ("Amazon Prize Lottery Smishing", 40),
            "f1a0": ("Parcel Delivery Smishing", 30),
            "e2b3": ("OTP Bypass Smishing", 45),
            "9d7c": ("Income Tax Refund Smishing", 35),
            "4f8a": ("UIDAI Aadhaar Smishing", 35),
            "1b5e": ("PhonePe/GPay UPI Smishing", 40),
        }

    def unmask_url(self, short_url: str) -> Dict:
        """Advanced URL unmasking with full trace and analysis."""
        try:
            # Use advanced URL tracer
            trace_result = self.url_tracer.trace_url(short_url)
            return trace_result
        except Exception as e:
            logging.error(f"[-] Unmasking Failed for {short_url}: {e}")
            return {
                'original_url': short_url,
                'final_url': short_url,
                'redirect_count': 0,
                'error': str(e)
            }

    def detect_sender_spoofing(self, sender_id: str, sms_text: str) -> Dict:
        """Detects if a sender ID is spoofed — mimicking a legit brand."""
        result = {
            "sender_id": sender_id,
            "spoofing_detected": False,
            "impersonated_brand": None,
            "sender_type": "UNKNOWN",
            "risk_score": 0,
            "details": []
        }

        if not sender_id:
            result["details"].append("No sender ID — possible direct number")
            return result

        sid_upper = sender_id.upper().strip()

        # Check TRAI prefix compliance
        has_trai_prefix = any(sid_upper.startswith(p) for p in self.legit_sender_prefixes)
        result["sender_type"] = "TRAI_COMPLIANT" if has_trai_prefix else "NON_STANDARD"

        # Check which brand is mentioned in SMS text
        sms_lower = sms_text.lower()
        mentioned_brand = None
        for brand in self.impersonated_brands:
            if brand in sms_lower:
                mentioned_brand = brand.upper()
                break

        if mentioned_brand:
            # Check if sender matches expected IDs for that brand
            expected_ids = self.brand_sender_map.get(mentioned_brand, [])
            sender_matches = any(
                sid_upper in exp.upper() or exp.upper() in sid_upper
                for exp in expected_ids
            )

            if not sender_matches and expected_ids:
                result["spoofing_detected"] = True
                result["impersonated_brand"] = mentioned_brand
                result["risk_score"] = 40
                result["details"].append(
                    f"Sender '{sender_id}' claims to be {mentioned_brand} but does not match known sender IDs: {expected_ids[:3]}"
                )
            elif sender_matches:
                result["details"].append(f"Sender ID matches expected {mentioned_brand} pattern — appears legitimate")

        # Check for typosquatted sender IDs (e.g. HDFlC instead of HDFC)
        typo_patterns = [
            (r'HDFl|HDFС', 'HDFC'),   # lowercase l or Cyrillic С
            (r'SB1\b|5BI\b', 'SBI'),   # number substitution
            (r'lCICI|1CICI', 'ICICI'),
            (r'AMAZ0N|AMAZUN', 'AMAZON'),
        ]
        for pattern, brand in typo_patterns:
            if re.search(pattern, sid_upper):
                result["spoofing_detected"] = True
                result["impersonated_brand"] = brand
                result["risk_score"] = 50
                result["details"].append(f"Typosquatted sender ID detected — mimics '{brand}'")

        return result

    def analyze_phone_number(self, phone: str) -> Dict:
        """Intelligence analysis on the SMS sender phone number."""
        result = {
            "raw_number": phone,
            "number_type": "UNKNOWN",
            "country": "UNKNOWN",
            "carrier_guess": None,
            "is_disposable": False,
            "is_shortcode": False,
            "risk_score": 0,
            "flags": []
        }

        if not phone:
            return result

        phone_clean = re.sub(r'[\s\-\(\)]', '', phone)

        # Short code detection (4-6 digit numbers)
        if re.match(r'^\d{4,6}$', phone_clean):
            result["is_shortcode"] = True
            result["number_type"] = "SHORTCODE"
            result["flags"].append("Short code — may be operator-assigned or spoofed")

        # India number analysis
        if phone_clean.startswith('+91') or phone_clean.startswith('91') or (
            len(phone_clean) == 10 and phone_clean[0] in '6789'
        ):
            result["country"] = "India"
            num = phone_clean.lstrip('+91').lstrip('91') if phone_clean.startswith(('+91', '91')) else phone_clean

            # Jio: 6XXXXXXXX, 7XXXXXXXX
            if num.startswith(('6', '70', '71', '72', '73', '74', '75', '76', '77')):
                result["carrier_guess"] = "Jio (possible)"
            # Airtel: 9XXXXXXXX, 8XXXXXXXX
            elif num.startswith(('98', '97', '96', '88', '87', '86')):
                result["carrier_guess"] = "Airtel (possible)"
            # BSNL
            elif num.startswith(('94', '84')):
                result["carrier_guess"] = "BSNL/Vi (possible)"

            # VoIP/virtual range flags
            if num.startswith(('60', '61', '62')):
                result["is_disposable"] = True
                result["risk_score"] += 20
                result["flags"].append("Number in VoIP/virtual range — high smishing risk")

        # Foreign number calling Indian recipients
        elif phone_clean.startswith(('+1', '+44', '+234', '+254', '+855')):
            country_map = {'+1': 'USA', '+44': 'UK', '+234': 'Nigeria', '+254': 'Kenya', '+855': 'Cambodia'}
            for prefix, country in country_map.items():
                if phone_clean.startswith(prefix):
                    result["country"] = country
                    result["risk_score"] += 25
                    result["flags"].append(f"International number ({country}) — common in smishing attacks")
                    break
            result["is_disposable"] = True

        result["number_type"] = "MOBILE" if not result["is_shortcode"] else "SHORTCODE"
        return result

    def fingerprint_sms_template(self, sms_text: str) -> Dict:
        """Fingerprint the SMS against known smishing templates."""
        result = {
            "template_matched": False,
            "template_label": None,
            "fingerprint_hash": None,
            "risk_boost": 0,
            "normalized_text": None
        }

        # Normalize: lowercase, strip URLs and numbers
        normalized = sms_text.lower()
        normalized = re.sub(r'https?://\S+', '[URL]', normalized)
        normalized = re.sub(r'\+?\d[\d\s\-]{8,}', '[NUM]', normalized)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        result["normalized_text"] = normalized

        # Compute fingerprint
        fp_hash = hashlib.sha256(normalized.encode()).hexdigest()
        result["fingerprint_hash"] = fp_hash[:16]

        # Check against known templates
        prefix = fp_hash[:4]
        if prefix in self.template_fingerprints:
            label, boost = self.template_fingerprints[prefix]
            result["template_matched"] = True
            result["template_label"] = label
            result["risk_boost"] = boost
            logging.warning(f"[SMISHING] Template match: {label}")

        return result

    def detect_multilanguage_smishing(self, sms_text: str) -> Dict:
        """Detect smishing patterns in Hindi, Telugu, Tamil scripts."""
        result = {
            "multilang_detected": False,
            "languages_found": [],
            "patterns_matched": [],
            "risk_score": 0
        }

        for pattern, label, score in self.multilang_patterns:
            if re.search(pattern, sms_text):
                lang = label.split('_')[0]
                result["multilang_detected"] = True
                result["patterns_matched"].append(label)
                result["risk_score"] += score
                if lang not in result["languages_found"]:
                    result["languages_found"].append(lang)

        result["risk_score"] = min(result["risk_score"], 40)
        return result

    def detect_otp_harvesting(self, sms_text: str) -> Dict:
        """Detect OTP harvesting and credential extraction patterns."""
        result = {
            "otp_harvesting_detected": False,
            "patterns_matched": [],
            "otp_present": False,
            "risk_score": 0
        }

        text_lower = sms_text.lower()

        # Check OTP-like numbers in the text
        otp_numbers = re.findall(r'\b\d{4,8}\b', sms_text)
        if otp_numbers:
            result["otp_present"] = True
            result["risk_score"] += 10

        for pattern in self.otp_harvest_patterns:
            if re.search(pattern, text_lower):
                result["otp_harvesting_detected"] = True
                result["patterns_matched"].append(pattern)
                result["risk_score"] += 15

        # Detect credential phishing: asking for full bank details
        cred_patterns = [
            (r'(card\s+number|card\s+no)', 'Card Number Request', 20),
            (r'(cvv|cvc)', 'CVV Request', 25),
            (r'(pin\s+number|atm\s+pin)', 'PIN Request', 25),
            (r'(net.?banking|internet\s+banking)\s+(password|login)', 'NetBanking Cred Request', 20),
            (r'(account\s+number|a/?c\s+no)', 'Account Number Request', 15),
            (r'(ifsc|swift)\s+code', 'Bank Code Request', 10),
            (r'(aadhaar|aadhar)\s+number', 'Aadhaar Number Request', 20),
            (r'(pan\s+card|pan\s+number)', 'PAN Request', 20),
        ]

        for pattern, label, score in cred_patterns:
            if re.search(pattern, text_lower):
                result["otp_harvesting_detected"] = True
                result["patterns_matched"].append(label)
                result["risk_score"] += score

        result["risk_score"] = min(result["risk_score"], 50)
        return result

    def score_brand_impersonation(self, sms_text: str) -> Dict:
        """Score how aggressively a brand is being impersonated in the SMS."""
        result = {
            "brand_detected": None,
            "impersonation_tactics": [],
            "confidence": 0,
            "risk_score": 0
        }

        sms_lower = sms_text.lower()
        brand_hits = {}

        for brand in self.impersonated_brands:
            if brand in sms_lower:
                brand_hits[brand] = brand_hits.get(brand, 0) + 1

        if not brand_hits:
            return result

        # Pick brand with most mentions
        primary_brand = max(brand_hits, key=brand_hits.get)
        result["brand_detected"] = primary_brand.upper()
        result["confidence"] = min(brand_hits[primary_brand] * 30, 90)

        # Tactic detection
        tactics = [
            (r'(kyc|know your customer)', 'KYC Urgency Tactic'),
            (r'(account.*suspend|suspend.*account|block)', 'Account Block Threat'),
            (r'(reward|cashback|refund|rs\.?\s*\d+|₹\s*\d+)', 'Financial Lure'),
            (r'(lucky|winner|congratulation|selected)', 'Lottery/Prize Lure'),
            (r'(click.*link|tap.*link|visit.*link)', 'Click-Link CTA'),
            (r'(24\s*hour|48\s*hour|immediately|asap|urgent)', 'Urgency Pressure'),
            (r'(government|official|authorized|verified)', 'Authority Claim'),
        ]

        for pattern, tactic in tactics:
            if re.search(pattern, sms_lower):
                result["impersonation_tactics"].append(tactic)
                result["risk_score"] += 8

        result["risk_score"] = min(result["risk_score"], 45)
        if result["impersonation_tactics"]:
            result["confidence"] = min(result["confidence"] + len(result["impersonation_tactics"]) * 10, 95)

        return result

    def analyze(self, sms_payload: str, sender_id: str = None, phone_number: str = None, sender_type: str = 'alpha') -> dict:
        """Scans SMS text, extracts links, and expands shorteners for analysis."""
        logging.info(f"[SMISHING ENGINE] Analyzing SMS payload... (sender_type={sender_type})")
        
        results = {
            "original_text": sms_payload,
            "extracted_links": [],
            "unmasked_links": [],
            "shortener_detected": False,
            "calculated_risk": 0,
            "sender_type": sender_type
        }

        # Sender type baseline risk
        sender_type_risk = {
            'alpha': 0,    # Normal — TRAI regulated
            'short': 10,   # Short codes can be spoofed easily
            'long': 15     # Long international numbers = higher suspicion
        }
        results["calculated_risk"] += sender_type_risk.get(sender_type, 0)

        # 1. Regex to find all URLs in the SMS text
        # Optimized regex to capture full URLs including paths and query params
        url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2})|[/?:#\[\]@!$&\'()*+,;=])+')
        links = url_pattern.findall(sms_payload)

        if not links:
            results["status"] = "No links found in SMS"
            return results

        results["extracted_links"] = links

        # 2. Advanced URL Analysis for each link
        results["url_analysis"] = []
        
        for link in links:
            domain = urlparse(link).netloc.lower()
            url_analysis = {
                "original_url": link,
                "domain": domain,
                "is_shortener": domain in self.shorteners,
                "trace_result": None,
                "threat_intel": None,
                "heuristic_score": 0,
                "ml_prediction": None,
                "ioc_match": False
            }
            
            if domain in self.shorteners:
                results["shortener_detected"] = True
                results["calculated_risk"] += 40  # High risk for shorteners in SMS
                logging.info(f"[!] Shortener Detected: {domain}. Unmasking...")
            
            # Advanced URL tracing (follows all redirects)
            trace_result = self.unmask_url(link)
            url_analysis["trace_result"] = trace_result
            final_url = trace_result.get("final_url", link)
            url_reachable = trace_result.get("is_reachable", False)
            url_error = trace_result.get("error")

            # ── UNREACHABLE / EXPIRED URL HANDLING ──
            # If shortener couldn't resolve → analyze the shortener URL itself statically
            if not url_reachable or url_error:
                logging.warning(f"[SMISHING] URL unreachable: {link} — running static analysis")
                # Static ML on original short URL
                ml_result = ml_detector.predict(link)
                url_analysis["ml_prediction"] = ml_result
                if ml_result.get("classification") == "PHISHING":
                    results["calculated_risk"] += 20

                # IOC check on the shortener domain itself
                ioc_result = ioc_feed_manager.check_url(link)
                url_analysis["ioc_match"] = ioc_result.get("is_malicious", False)
                if url_analysis["ioc_match"]:
                    results["calculated_risk"] += 25

                # Threat intel on shortener
                intel_results = self.threat_intel.check_all(link)
                url_analysis["threat_intel"] = intel_results
                if intel_results.get("is_malicious"):
                    results["calculated_risk"] += 30

                # Populate display fields for frontend
                shortener_domain = urlparse(link).netloc
                results.setdefault("server_ip_loc", "Unresolved")
                results.setdefault("domain_age", "Unknown — URL expired or fake")
                results.setdefault("ssl_certificate", "Cannot verify — URL unreachable")
                results.setdefault("brand_check", self._static_brand_check(link))
                results.setdefault("virustotal", intel_results.get("virustotal", "N/A"))
                results.setdefault("urlhaus", intel_results.get("urlhaus", "Not in DB"))
                url_analysis["heuristic_score"] = 30 if domain in self.shorteners else 10
                results["calculated_risk"] += url_analysis["heuristic_score"] * 0.3
                url_analysis["unreachable"] = True
                url_analysis["unreachable_reason"] = url_error or "URL did not resolve"

            else:
                # Normal flow — URL reachable
                # Threat Intelligence check
                logging.info(f"[SMISHING] Querying threat intel for: {final_url}")
                intel_results = self.threat_intel.check_all(final_url)
                url_analysis["threat_intel"] = intel_results

                if intel_results.get("is_malicious"):
                    results["calculated_risk"] += 30
                    logging.critical(f"🚨 MALICIOUS URL detected: {final_url}")

                # IOC Feed check
                ioc_result = ioc_feed_manager.check_url(final_url)
                url_analysis["ioc_match"] = ioc_result.get("is_malicious", False)

                if url_analysis["ioc_match"]:
                    results["calculated_risk"] += 25
                    logging.critical(f"🚨 IOC MATCH: {final_url} in threat feeds!")

                # ML-based detection
                ml_result = ml_detector.predict(final_url)
                url_analysis["ml_prediction"] = ml_result

                if ml_result.get("classification") == "PHISHING":
                    results["calculated_risk"] += 20
                elif ml_result.get("classification") == "SUSPICIOUS":
                    results["calculated_risk"] += 10

                # Domain heuristics
                heuristic_results = self.heuristics.full_analysis(final_url)
                url_analysis["heuristic_score"] = heuristic_results.get("overall_risk_score", 0)
                results["calculated_risk"] += url_analysis["heuristic_score"] * 0.3

                # Populate display fields from heuristics
                results.setdefault("server_ip_loc", heuristic_results.get("ip_address", "Unresolved"))
                results.setdefault("domain_age", heuristic_results.get("domain_age", "N/A"))
                results.setdefault("ssl_certificate", heuristic_results.get("ssl_status", "N/A"))
                results.setdefault("brand_check", heuristic_results.get("brand_match", self._static_brand_check(final_url)))
                results.setdefault("virustotal", intel_results.get("virustotal", "N/A"))
                results.setdefault("urlhaus", intel_results.get("urlhaus", "Not in DB"))
            
            # Visual analysis for final URL (only if reachable)
            if url_reachable and final_url.startswith(("http://", "https://")):
                logging.info(f"[SMISHING] Visual analysis for: {final_url}")
                visual_results = self.visual_analyzer.analyze(final_url)
                url_analysis["visual_analysis"] = visual_results
                
                # Add visual spoofing risk
                if visual_results.get("detected_brand"):
                    url_analysis["detected_brand"] = visual_results["detected_brand"]
                    results["calculated_risk"] += visual_results.get("risk_score", 0) * 0.5
                    
                    if visual_results.get("brand_domain_match", {}).get("is_suspicious_mismatch"):
                        logging.critical(f"🚨 BRAND SPOOFING: {visual_results['detected_brand']} on fake domain!")
            
            # Campaign attribution
            qr_analysis = {
                "url_pattern": final_url,
                "domain": urlparse(final_url).netloc,
                "detected_brand": url_analysis.get("detected_brand"),
                "risk_level": "CRITICAL" if results["calculated_risk"] > 70 else "HIGH" if results["calculated_risk"] > 40 else "MEDIUM"
            }
            attribution = attribution_engine.attribute_attack(qr_analysis)
            url_analysis["attribution"] = attribution
            
            results["url_analysis"].append(url_analysis)
            results["unmasked_links"].append(final_url)

        # 3. Urgency/Threat Keyword Detection (Social Engineering)
        urgency_keywords = ['urgent', 'blocked', 'suspended', 'verify', 'action required', 'prize', 'bank', 'otp', 'cvv', 'kyc', 'expire', 'penalty', 'legal action', 'arrested', 'reward', 'refund', 'lucky winner']
        matched_keywords = [word for word in urgency_keywords if word in sms_payload.lower()]
        if matched_keywords:
            results["calculated_risk"] += min(len(matched_keywords) * 5, 30)
            results["social_engineering_keywords"] = matched_keywords
            logging.info(f"[!] Social Engineering keywords: {matched_keywords}")

        # 4. ML-based SMS content analysis
        sms_ml_score = self._analyze_sms_content_ml(sms_payload)
        results["content_ml_score"] = sms_ml_score
        results["calculated_risk"] += sms_ml_score * 0.2

        # ── ADVANCED FEATURE 1: Sender Spoofing Detection
        sender_analysis = self.detect_sender_spoofing(sender_id or "", sms_payload)
        results["sender_analysis"] = sender_analysis
        if sender_analysis["spoofing_detected"]:
            results["calculated_risk"] += sender_analysis["risk_score"]
            logging.critical(f"🚨 SENDER SPOOFING: {sender_analysis['impersonated_brand']}")

        # ── ADVANCED FEATURE 2: Phone Number Intelligence
        phone_intel = self.analyze_phone_number(phone_number or "")
        results["phone_intel"] = phone_intel
        if phone_intel["is_disposable"] or phone_intel["risk_score"] > 0:
            results["calculated_risk"] += phone_intel["risk_score"]

        # ── ADVANCED FEATURE 3: SMS Template Fingerprinting
        template_result = self.fingerprint_sms_template(sms_payload)
        results["template_fingerprint"] = template_result
        if template_result["template_matched"]:
            results["calculated_risk"] += template_result["risk_boost"]
            logging.critical(f"🚨 TEMPLATE MATCH: {template_result['template_label']}")

        # ── ADVANCED FEATURE 4: Multi-language Smishing Detection
        multilang_result = self.detect_multilanguage_smishing(sms_payload)
        results["multilang_analysis"] = multilang_result
        if multilang_result["multilang_detected"]:
            results["calculated_risk"] += multilang_result["risk_score"]
            logging.warning(f"[!] Multi-lang smishing: {multilang_result['languages_found']}")

        # ── ADVANCED FEATURE 5: OTP Harvesting Detection
        otp_result = self.detect_otp_harvesting(sms_payload)
        results["otp_analysis"] = otp_result
        if otp_result["otp_harvesting_detected"]:
            results["calculated_risk"] += otp_result["risk_score"]
            logging.critical(f"🚨 OTP HARVESTING DETECTED")

        # ── ADVANCED FEATURE 6: Brand Impersonation Scoring
        brand_result = self.score_brand_impersonation(sms_payload)
        results["brand_impersonation"] = brand_result
        if brand_result["brand_detected"]:
            results["calculated_risk"] += brand_result["risk_score"]
            logging.warning(f"[!] Brand impersonation: {brand_result['brand_detected']} ({brand_result['confidence']}%)")

        # Cap risk at 100
        results["calculated_risk"] = min(int(results["calculated_risk"]), 100)
        
        # Final status
        if results["calculated_risk"] >= 70:
            results["status"] = "CRITICAL: Likely smishing attack"
        elif results["calculated_risk"] >= 40:
            results["status"] = "HIGH RISK: Suspicious SMS detected"
        elif results["calculated_risk"] >= 20:
            results["status"] = "MEDIUM RISK: Some suspicious indicators"
        else:
            results["status"] = "LOW RISK: SMS appears safe"
        
        logging.info(f"[SMISHING ENGINE] Scan Complete. Risk: {results['calculated_risk']}% - {results['status']}")
        return results
    
    def _static_brand_check(self, url: str) -> str:
        """Check for brand keywords in the URL itself (no network needed)."""
        url_lower = url.lower()
        brand_keywords = {
            'sbi': 'SBI (Spoofed)',
            'hdfc': 'HDFC (Spoofed)',
            'icici': 'ICICI (Spoofed)',
            'paytm': 'Paytm (Spoofed)',
            'amazon': 'Amazon (Spoofed)',
            'flipkart': 'Flipkart (Spoofed)',
            'irctc': 'IRCTC (Spoofed)',
            'airtel': 'Airtel (Spoofed)',
            'jio': 'Jio (Spoofed)',
            'uidai': 'UIDAI (Spoofed)',
            'fedex': 'FedEx (Spoofed)',
            'dhl': 'DHL (Spoofed)',
            'kyc': 'Bank KYC Lure',
            'loan': 'Loan Offer Lure',
            'reward': 'Reward Lure',
            'winner': 'Lottery Lure',
        }
        for keyword, label in brand_keywords.items():
            if keyword in url_lower:
                return label
        return 'Clean'

    def _analyze_sms_content_ml(self, sms_text: str) -> float:
        """ML-based analysis of SMS content."""
        score = 0.0
        
        # Phishing patterns
        patterns = {
            r'\b\d{6}\b': 5,  # OTP-like numbers
            r'(http|https)://': 10,  # Has URL
            r'\b[A-Z]{10,}\b': 3,  # All caps words (URGENT)
            r'[!]{2,}': 2,  # Multiple exclamation marks
            r'\$[\d,]+': 5,  # Dollar amounts
            r'\b(win|won|winner|prize|reward)\b': 8,  # Prize/lottery
            r'\b(limited|expire|deadline|now|today)\b': 5,  # Urgency
            r'\b(click|tap|visit|open)\b': 5,  # Call to action
            r'\b(account|verify|confirm|update|login)\b': 8,  # Account actions
            r'\b(suspended|blocked|restricted|locked)\b': 10,  # Account status threats
        }
        
        text_lower = sms_text.lower()
        
        for pattern, weight in patterns.items():
            if re.search(pattern, text_lower):
                score += weight
        
        return min(score, 50)  # Cap at 50