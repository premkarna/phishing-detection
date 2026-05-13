import logging
import re
from urllib.parse import urlparse
from difflib import SequenceMatcher

class SocialEngine:
    def __init__(self):
        # High-target social brands
        self.social_brands = ["instagram", "linkedin", "twitter", "facebook", "snapchat", "whatsapp", "tiktok", "telegram"]
        # Social media related phishing keywords
        self.social_keywords = [
            "login", "verify", "security", "update", "support", "help",
            "center", "account", "business", "secure", "confirmation",
            "password", "reset", "unusual-activity", "copyright"
        ]

        # --- PSYCHOLOGICAL MANIPULATION TRIGGERS ---
        # Urgency: Creates time pressure to prevent rational thinking
        self.urgency_triggers = [
            "urgent", "immediately", "act now", "expires today", "24 hours",
            "last chance", "final notice", "limited time", "don't wait",
            "deadline", "time sensitive", "respond now", "asap", "right now",
            "within hours", "today only", "expiring soon"
        ]

        # Fear: Threats to trigger panic response
        self.fear_triggers = [
            "suspended", "blocked", "banned", "terminated", "deleted",
            "unauthorized access", "hacked", "compromised", "breached",
            "legal action", "lawsuit", "arrested", "fined", "penalty",
            "account closed", "security breach", "suspicious activity",
            "your device is infected", "virus detected", "criminal charges"
        ]

        # Greed/Reward: Exploit desire for gain
        self.greed_triggers = [
            "you won", "winner", "prize", "reward", "gift card", "cash prize",
            "lottery", "jackpot", "free", "bonus", "congratulations",
            "selected", "chosen", "exclusive offer", "limited offer",
            "claim now", "get paid", "earn money", "investment opportunity",
            "100% profit", "guaranteed return", "double your money"
        ]

        # Authority: Impersonating trusted figures/organizations
        self.authority_triggers = [
            "ceo", "director", "manager", "hr department", "it department",
            "government", "irs", "income tax", "police", "fbi", "interpol",
            "microsoft support", "apple support", "google", "amazon",
            "bank of india", "sbi", "rbi", "trai", "ministry", "official notice",
            "court order", "legal department", "compliance team"
        ]

        # Pretexting: Fake scenarios to establish false context
        self.pretexting_patterns = {
            "job_scam": [
                "work from home", "earn per day", "part time job", "data entry",
                "no experience required", "hiring urgently", "salary advance",
                "registration fee", "training fee", "join our team"
            ],
            "romance_scam": [
                "i love you", "soulmate", "meet in person", "send money",
                "stranded abroad", "medical emergency", "visa fee", "flight ticket",
                "i need help", "loan me", "western union", "gift card payment"
            ],
            "ceo_fraud": [
                "confidential wire transfer", "do not discuss", "keep this secret",
                "transfer immediately", "urgent payment", "invoice approval",
                "bypassing normal process", "personal favour", "act before board meeting"
            ],
            "tech_support_scam": [
                "your computer is infected", "call us now", "toll free",
                "remote access", "install this software", "teamviewer",
                "anydesk", "we detected a virus", "microsoft certified",
                "your license expired", "renew subscription"
            ],
            "kyc_scam": [
                "kyc update", "aadhar link", "pan card update", "verify your account",
                "bank kyc", "otp verification", "share otp", "enter otp",
                "sim card blocked", "mobile number expiry"
            ]
        }

        # Scarcity: Exploit FOMO — limited availability creates panic buying/action
        self.scarcity_triggers = [
            "only 1 left", "limited slots", "seats filling fast", "almost sold out",
            "only today", "offer ends at midnight", "last 5 spots", "closing soon",
            "first come first served", "while stocks last", "reserve your spot now",
            "don't miss out", "running out of time", "spots are limited"
        ]

        # Reciprocity: Build false trust before asking for something
        self.reciprocity_triggers = [
            "i've already sent you", "as promised", "your free gift is ready",
            "i did this for you", "here is what i prepared", "you were selected",
            "we've already processed", "your bonus has been credited",
            "your account has been upgraded", "we've given you access"
        ]

        # Contact/Info harvesting: Extracting PII directly
        self.contact_harvest_patterns = [
            "send your otp", "share your otp", "enter your otp", "reply with otp",
            "send your aadhar", "send your pan", "share your bank details",
            "send your card number", "cvv", "expiry date", "mother's maiden name",
            "date of birth", "send your address", "verify your mobile",
            "reply with your password", "share your pin", "atm pin"
        ]

        # Obfuscation character substitutions used to bypass keyword filters
        self.obfuscation_map = {
            '@': 'a', '0': 'o', '1': 'l', '3': 'e', '5': 's',
            '4': 'a', '7': 't', '$': 's', '|': 'i', '!': 'i'
        }

        # Aggression/Threat severity markers
        self.aggression_patterns = [
            (r'\byou\s+will\s+be\s+arrested\b', 80),
            (r'\bcriminal\s+charges\b', 75),
            (r'\bpolice\s+will\s+come\b', 75),
            (r'\byour\s+account\s+will\s+be\s+permanently\s+deleted\b', 60),
            (r'\blast\s+warning\b', 55),
            (r'\bfinal\s+notice\b', 50),
            (r'\blegal\s+action\b', 50),
            (r'\bwarrant\b', 70),
            (r'\bblacklisted\b', 45),
            (r'\bpenalty\s+of\b', 45),
        ]

        # Platform-specific attack patterns
        self.platform_patterns = {
            "linkedin": [
                "job opportunity", "recruiter", "hiring", "salary", "apply now",
                "connect with me", "job offer", "work visa", "relocation package"
            ],
            "instagram": [
                "follow back", "dm for collab", "brand deal", "sponsored",
                "account verification", "blue tick", "copyright strike",
                "your account will be deleted", "influencer program"
            ],
            "whatsapp": [
                "forward this message", "won a prize", "share with 10 friends",
                "click the link", "your whatsapp will expire", "free whatsapp gold",
                "otp from whatsapp", "video call scam", "sextortion"
            ],
            "facebook": [
                "marketplace scam", "friend in need", "send money",
                "account cloning", "fake fundraiser", "gift card giveaway",
                "share to win", "click for prize", "fb lottery"
            ]
        }

    def detect_punycode(self, domain: str) -> bool:
        """Detects if the domain contains non-ASCII characters or Punycode prefix."""
        if domain.startswith("xn--"):
            return True
        parts = domain.split('.')
        for part in parts:
            if part.startswith("xn--"):
                return True
        try:
            domain.encode('ascii')
        except UnicodeEncodeError:
            return True
        return False

    def analyze_psychological_manipulation(self, text: str) -> dict:
        """Detects psychological manipulation triggers in free text (DM, post, email body, SMS)."""
        text_lower = text.lower()
        result = {
            "manipulation_detected": False,
            "triggered_tactics": [],
            "manipulation_score": 0,
            "tactic_breakdown": {}
        }

        # Check each trigger category
        found_urgency = [t for t in self.urgency_triggers if t in text_lower]
        found_fear = [t for t in self.fear_triggers if t in text_lower]
        found_greed = [t for t in self.greed_triggers if t in text_lower]
        found_authority = [t for t in self.authority_triggers if t in text_lower]

        if found_urgency:
            result["triggered_tactics"].append("URGENCY")
            result["tactic_breakdown"]["urgency"] = found_urgency
            result["manipulation_score"] += len(found_urgency) * 10

        if found_fear:
            result["triggered_tactics"].append("FEAR")
            result["tactic_breakdown"]["fear"] = found_fear
            result["manipulation_score"] += len(found_fear) * 15

        if found_greed:
            result["triggered_tactics"].append("GREED/REWARD")
            result["tactic_breakdown"]["greed"] = found_greed
            result["manipulation_score"] += len(found_greed) * 10

        if found_authority:
            result["triggered_tactics"].append("AUTHORITY IMPERSONATION")
            result["tactic_breakdown"]["authority"] = found_authority
            result["manipulation_score"] += len(found_authority) * 12

        # Combo attack bonus: Multiple triggers = coordinated social engineering
        if len(result["triggered_tactics"]) >= 2:
            result["manipulation_score"] += 20
            result["triggered_tactics"].append("MULTI-VECTOR MANIPULATION")

        result["manipulation_detected"] = result["manipulation_score"] > 0
        result["manipulation_score"] = min(result["manipulation_score"], 100)
        return result

    def detect_pretexting(self, text: str) -> dict:
        """Detects specific pretexting scenarios (fake job, romance scam, CEO fraud, etc.)."""
        text_lower = text.lower()
        result = {
            "pretexting_detected": False,
            "scenario_type": "None",
            "matched_phrases": [],
            "pretext_risk": 0
        }

        for scenario, phrases in self.pretexting_patterns.items():
            matched = [p for p in phrases if p in text_lower]
            if matched:
                result["pretexting_detected"] = True
                result["scenario_type"] = scenario.upper().replace("_", " ")
                result["matched_phrases"].extend(matched)
                result["pretext_risk"] += len(matched) * 15

        result["pretext_risk"] = min(result["pretext_risk"], 100)
        return result

    def deobfuscate_text(self, text: str) -> str:
        """Normalizes leet-speak obfuscation so filters can catch disguised keywords."""
        result = text.lower()
        for char, replacement in self.obfuscation_map.items():
            result = result.replace(char, replacement)
        return result

    def check_obfuscation(self, text: str) -> dict:
        """Detects leet-speak / character substitution used to bypass keyword filters."""
        result = {"obfuscation_detected": False, "obfuscation_risk": 0, "obfuscation_details": []}
        original_lower = text.lower()
        deobfuscated = self.deobfuscate_text(text)
        # Check if deobfuscation reveals new threat keywords
        all_triggers = self.urgency_triggers + self.fear_triggers + self.greed_triggers
        hidden_in_original = [t for t in all_triggers if t not in original_lower and t in deobfuscated]
        if hidden_in_original:
            result["obfuscation_detected"] = True
            result["obfuscation_risk"] += len(hidden_in_original) * 20
            result["obfuscation_details"].append(f"OBFUSCATED KEYWORDS: Hidden triggers revealed after deobfuscation — {hidden_in_original[:3]}")
        # Check ratio of non-alpha chars (high ratio = obfuscation)
        non_alpha = sum(1 for c in text if not c.isalpha() and not c.isspace())
        ratio = non_alpha / max(len(text), 1)
        if ratio > 0.25:
            result["obfuscation_risk"] += 25
            result["obfuscation_details"].append(f"HIGH SYMBOL RATIO: {ratio:.0%} non-alpha chars (likely obfuscated text)")
        result["obfuscation_risk"] = min(result["obfuscation_risk"], 100)
        return result

    def check_aggression_level(self, text: str) -> dict:
        """Scores the severity of threatening language in the text."""
        text_lower = text.lower()
        result = {"aggression_score": 0, "threat_level": "NONE", "threatening_phrases": []}
        for pattern, score in self.aggression_patterns:
            if re.search(pattern, text_lower):
                result["aggression_score"] += score
                matched = re.search(pattern, text_lower).group()
                result["threatening_phrases"].append(matched)
        result["aggression_score"] = min(result["aggression_score"], 100)
        if result["aggression_score"] >= 70:
            result["threat_level"] = "SEVERE"
        elif result["aggression_score"] >= 45:
            result["threat_level"] = "HIGH"
        elif result["aggression_score"] >= 20:
            result["threat_level"] = "MODERATE"
        return result

    def check_contact_harvesting(self, text: str) -> dict:
        """Detects attempts to extract PII, OTP, banking details from victim."""
        text_lower = text.lower()
        result = {"harvesting_detected": False, "harvest_risk": 0, "harvested_targets": []}
        matched = [p for p in self.contact_harvest_patterns if p in text_lower]
        if matched:
            result["harvesting_detected"] = True
            result["harvested_targets"] = matched
            result["harvest_risk"] = min(len(matched) * 25, 100)
        # Also check for PII regex patterns
        pii_patterns = [
            (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', "Credit/Debit card number pattern"),
            (r'\b\d{3}\b', "CVV pattern"),
            (r'\b\d{12}\b', "Aadhar number pattern"),
            (r'\b[A-Z]{5}\d{4}[A-Z]\b', "PAN card pattern"),
        ]
        for pattern, label in pii_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                result["harvesting_detected"] = True
                result["harvest_risk"] += 30
                result["harvested_targets"].append(f"PII PATTERN: {label} found in message")
        result["harvest_risk"] = min(result["harvest_risk"], 100)
        return result

    def check_link_deception(self, text: str) -> dict:
        """Detects cloaked links where display text differs from actual URL."""
        result = {"deception_detected": False, "deception_risk": 0, "deception_details": []}
        # HTML anchor mismatch
        anchor_pattern = re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', text, re.IGNORECASE)
        for href, display in anchor_pattern:
            href_domain = re.search(r'https?://([^/]+)', href)
            if href_domain and href_domain.group(1).lower() not in display.lower():
                similarity = SequenceMatcher(None, href_domain.group(1).lower(), display.lower()).ratio()
                if similarity < 0.5:
                    result["deception_detected"] = True
                    result["deception_risk"] += 50
                    result["deception_details"].append(f"CLOAKED LINK: '{display}' hides '{href}'")
        # Markdown link mismatch
        md_links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', text)
        for display, url in md_links:
            url_domain = re.search(r'https?://([^/]+)', url)
            if url_domain and url_domain.group(1).lower() not in display.lower():
                result["deception_detected"] = True
                result["deception_risk"] += 40
                result["deception_details"].append(f"MARKDOWN CLOAKED LINK: [{display}]({url})")
        # URL shorteners in plain text
        shorteners = ['bit.ly', 'tinyurl', 't.co', 'cutt.ly', 'ow.ly', 'rb.gy', 'goo.gl']
        for s in shorteners:
            if s in text.lower():
                result["deception_risk"] += 20
                result["deception_details"].append(f"URL SHORTENER DETECTED: {s} (masks true destination)")
        result["deception_risk"] = min(result["deception_risk"], 100)
        return result

    def check_scarcity_reciprocity(self, text: str) -> dict:
        """Detects scarcity (FOMO) and reciprocity (false trust) manipulation."""
        text_lower = text.lower()
        result = {"scarcity_detected": False, "reciprocity_detected": False, "sr_risk": 0, "sr_details": []}
        found_scarcity = [t for t in self.scarcity_triggers if t in text_lower]
        if found_scarcity:
            result["scarcity_detected"] = True
            result["sr_risk"] += len(found_scarcity) * 12
            result["sr_details"].append(f"SCARCITY (FOMO): {found_scarcity[:3]}")
        found_reciprocity = [t for t in self.reciprocity_triggers if t in text_lower]
        if found_reciprocity:
            result["reciprocity_detected"] = True
            result["sr_risk"] += len(found_reciprocity) * 15
            result["sr_details"].append(f"RECIPROCITY TRICK: {found_reciprocity[:3]}")
        result["sr_risk"] = min(result["sr_risk"], 100)
        return result

    def detect_platform_attack(self, text: str, platform: str = None) -> dict:
        """Detects platform-specific social engineering patterns."""
        text_lower = text.lower()
        result = {
            "platform_attack_detected": False,
            "targeted_platform": "Unknown",
            "matched_patterns": [],
            "platform_risk": 0
        }

        platforms_to_check = [platform.lower()] if platform else self.platform_patterns.keys()
        for plat in platforms_to_check:
            if plat in self.platform_patterns:
                matched = [p for p in self.platform_patterns[plat] if p in text_lower]
                if matched:
                    result["platform_attack_detected"] = True
                    result["targeted_platform"] = plat.capitalize()
                    result["matched_patterns"].extend(matched)
                    result["platform_risk"] += len(matched) * 12

        result["platform_risk"] = min(result["platform_risk"], 100)
        return result

    def analyze_text(self, text: str, platform: str = None) -> dict:
        """Full MAX social engineering analysis on free text (DM / post / email / SMS body)."""
        logging.info(f"[SOCIAL ENGINE] MAX analysis on text payload...")

        results = {
            "input_type": "text",
            "calculated_risk": 0,
            "social_engineering_detected": False,
            "attack_summary": [],
            "verdict": ""
        }

        # 1. Psychological manipulation (Urgency / Fear / Greed / Authority)
        psych = self.analyze_psychological_manipulation(text)
        results["psychological_analysis"] = psych
        if psych["manipulation_detected"]:
            results["social_engineering_detected"] = True
            results["calculated_risk"] += psych["manipulation_score"]
            tactics = ", ".join(psych["triggered_tactics"])
            results["attack_summary"].append(f"MANIPULATION TACTICS: {tactics}")
            logging.warning(f"[!] Social Engineering: {tactics}")

        # 2. Pretexting scenario detection
        pretext = self.detect_pretexting(text)
        results["pretexting_analysis"] = pretext
        if pretext["pretexting_detected"]:
            results["social_engineering_detected"] = True
            results["calculated_risk"] += pretext["pretext_risk"]
            results["attack_summary"].append(f"PRETEXT SCENARIO: {pretext['scenario_type']} — {pretext['matched_phrases'][:3]}")

        # 3. Platform-specific attack patterns
        platform_result = self.detect_platform_attack(text, platform)
        results["platform_analysis"] = platform_result
        if platform_result["platform_attack_detected"]:
            results["social_engineering_detected"] = True
            results["calculated_risk"] += platform_result["platform_risk"]
            results["attack_summary"].append(f"PLATFORM ATTACK [{platform_result['targeted_platform']}]: {platform_result['matched_patterns'][:3]}")

        # 4. Scarcity + Reciprocity (FOMO / False Trust)
        sr_result = self.check_scarcity_reciprocity(text)
        results["scarcity_reciprocity"] = sr_result
        if sr_result["sr_risk"] > 0:
            results["social_engineering_detected"] = True
            results["calculated_risk"] += sr_result["sr_risk"]
            results["attack_summary"].extend(sr_result["sr_details"])

        # 5. Obfuscation / Leet-speak detection
        obfusc_result = self.check_obfuscation(text)
        results["obfuscation_analysis"] = obfusc_result
        if obfusc_result["obfuscation_detected"]:
            results["social_engineering_detected"] = True
            results["calculated_risk"] += obfusc_result["obfuscation_risk"]
            results["attack_summary"].extend(obfusc_result["obfuscation_details"])

        # 6. Aggression / Threat severity
        aggression = self.check_aggression_level(text)
        results["aggression_analysis"] = aggression
        if aggression["aggression_score"] > 0:
            results["social_engineering_detected"] = True
            results["calculated_risk"] += aggression["aggression_score"]
            results["attack_summary"].append(f"THREAT LEVEL {aggression['threat_level']}: {aggression['threatening_phrases'][:2]}")

        # 7. Contact / PII harvesting
        harvest = self.check_contact_harvesting(text)
        results["contact_harvesting"] = harvest
        if harvest["harvesting_detected"]:
            results["social_engineering_detected"] = True
            results["calculated_risk"] += harvest["harvest_risk"]
            results["attack_summary"].append(f"PII HARVESTING: Requesting {harvest['harvested_targets'][:3]}")

        # 8. Link deception / cloaking
        link_result = self.check_link_deception(text)
        results["link_deception"] = link_result
        if link_result["deception_detected"]:
            results["social_engineering_detected"] = True
            results["calculated_risk"] += link_result["deception_risk"]
            results["attack_summary"].extend(link_result["deception_details"])

        results["calculated_risk"] = min(results["calculated_risk"], 100)

        # Final verdict
        risk = results["calculated_risk"]
        if risk >= 75:
            results["verdict"] = f"CRITICAL SOCIAL ENGINEERING — {len(results['attack_summary'])} attack vectors | Risk: {risk}%"
        elif risk >= 45:
            results["verdict"] = f"HIGH RISK MANIPULATION — Suspicious patterns detected | Risk: {risk}%"
        elif risk >= 20:
            results["verdict"] = f"MODERATE RISK — Some manipulation indicators | Risk: {risk}%"
        else:
            results["verdict"] = f"LOW RISK — No significant social engineering detected | Risk: {risk}%"

        logging.info(f"[SOCIAL ENGINE] Verdict: {results['verdict']}")
        return results

    def analyze(self, target_url: str) -> dict:
        """Analyzes URL for Punycode tricks and Social Media brand impersonation."""
        logging.info(f"[SOCIAL ENGINE] Scanning for Homograph and Social Phishing: {target_url}")

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc.lower().replace("www.", "")

        results = {
            "target_domain": domain,
            "punycode_detected": False,
            "brand_impersonation": "None",
            "keyword_risk": False,
            "calculated_risk": 0
        }

        # 1. Punycode / Homograph Detection (The Silent Killer)
        if self.detect_punycode(domain):
            results["punycode_detected"] = True
            results["calculated_risk"] += 80
            logging.warning(f"[!] HOMOGRAPH ALERT: Punycode/Non-ASCII detected: {domain}")

        # 2. Social Media Brand Impersonation & Keyword Combo
        for brand in self.social_brands:
            if brand in domain:
                is_legit = False
                if domain == f"{brand}.com" or domain.endswith(f".{brand}.com"):
                    is_legit = True

                if not is_legit:
                    results["brand_impersonation"] = f"SUSPICIOUS: Using '{brand}' name in non-official domain"
                    results["calculated_risk"] += 40

                    found_keywords = [kw for kw in self.social_keywords if kw in domain]
                    if found_keywords:
                        results["keyword_risk"] = True
                        results["calculated_risk"] += 30
                        logging.warning(f"[!] COMBO ATTACK: Brand mimicry + keywords {found_keywords}")

                    # Platform-specific URL pattern check
                    platform_url_result = self.detect_platform_attack(domain, brand)
                    if platform_url_result["platform_attack_detected"]:
                        results["calculated_risk"] += platform_url_result["platform_risk"]
                        results["platform_url_patterns"] = platform_url_result["matched_patterns"]

        # 4. TLD Heuristic (Social brands rarely use .xyz, .top, .online for core services)
        suspicious_tlds = ['.xyz', '.top', '.online', '.site', '.click', '.zip', '.mov']
        if any(domain.endswith(tld) for tld in suspicious_tlds) and results["calculated_risk"] > 0:
            results["calculated_risk"] += 20
            logging.info(f"[!] SUSPICIOUS TLD: {domain} uses a high-risk TLD.")

        results["calculated_risk"] = min(results["calculated_risk"], 100)

        # Verdict
        risk = results["calculated_risk"]
        if risk >= 75:
            results["verdict"] = f"CRITICAL — Social media impersonation attack | Risk: {risk}%"
        elif risk >= 40:
            results["verdict"] = f"HIGH RISK — Brand impersonation detected | Risk: {risk}%"
        else:
            results["verdict"] = f"LOW RISK — Domain appears safe | Risk: {risk}%"

        return results