from google import genai
from google.genai import types
import time
import logging
import json
import os
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import OrderedDict
from app.integrations.api_rotator import APIRotator

class AIHandler:
    """
    AI Router - L3 SOC Analyst using Gemini 2.0 Flash (gemini-2.0-flash).
    Aggregates data from all 7 detection engines and provides final verdicts with playbooks.
    """
    
    # L3 SOC Analyst Persona
    L3_SOC_PERSONA = """You are a Level 3 SOC (Security Operations Center) Analyst with 10+ years of experience.
Your role is to:
1. Analyze multi-vector threat data from automated security engines
2. Correlate indicators across different attack vectors
3. Identify Advanced Persistent Threats (APTs) and zero-day patterns
4. Provide actionable intelligence for incident response
5. Generate step-by-step playbooks for containment and remediation

Your analysis must be thorough, professional, and prioritized by business impact.
Always consider: Employee safety first, then data protection, then business continuity."""

    # Attack vector descriptions
    VECTOR_DESCRIPTIONS = {
        "url": "URL/Typosquatting Analysis - Detects domain spoofing and phishing websites",
        "qr": "Quishing (QR Code) Analysis - Extracts and analyzes QR-encoded malicious URLs",
        "eml": "Spear-Phishing (EML) Analysis - Email forensics, headers, and attachment analysis",
        "smishing": "Smishing (SMS) Analysis - Mobile text-based social engineering detection",
        "vishing": "Vishing (Voice) Analysis - Audio-based social engineering and fraud detection",
        "clone": "Clone Site Detection - Identifies visual spoofing of legitimate portals",
        "social": "Social Engineering Analysis - Homograph attacks and cognitive bias detection"
    }

    def __init__(self, api_keys=None, model_name='gemini-2.0-flash'):
        logging.info("[+] SYSTEM: Initializing AI Multi-Model Router (L3 SOC Analyst)...")
        
        # API Keys list (Rotation support)
        # First try passed keys, then read from environment
        if api_keys:
            self.api_keys = [k for k in api_keys if k and len(k) > 10]
        else:
            # Read from environment variables (support multiple keys)
            env_keys = []
            for i in range(1, 6):  # Check GEMINI_API_KEY_1 through _5
                key = os.getenv(f'GEMINI_API_KEY_{i}')
                if key and len(key) > 10:
                    env_keys.append(key)
            # Also check single key
            single_key = os.getenv('GEMINI_API_KEY')
            if single_key and len(single_key) > 10 and single_key not in env_keys:
                env_keys.append(single_key)
            self.api_keys = env_keys
        
        self.rotator = APIRotator(self.api_keys, service_name="Gemini")
        self.current_key_index = 0
        self.is_active = False
        # Use current stable model - gemini-2.0-flash (gemini-1.5-flash is deprecated on v1beta)
        self.model_name = model_name if model_name else 'gemini-2.0-flash'
        
        # Conversation context for multi-turn analysis
        self.conversation_history = []
        self.analysis_cache = OrderedDict()
        self._cache_max_size = 500
        
        # Statistics tracking
        self.stats = {
            "total_requests": 0,
            "successful_analyses": 0,
            "key_rotations": 0,
            "fallbacks": 0
        }
        
        self._init_with_best_key()

    def _init_with_best_key(self):
        """On startup, configure first key. Rotation happens on actual API failures."""
        if not self.api_keys:
            logging.error("[-] AI ROUTER: No API keys provided.")
            return
        self.current_key_index = 0
        self._configure_next_key()
        logging.info(f"[+] AI ROUTER: Startup — {len(self.api_keys)} keys loaded, starting with Key #1")

    def _configure_next_key(self):
        """Rotates to the next API key if the current one fails."""
        if not self.api_keys:
            logging.error("[-] AI ROUTER: No API keys provided.")
            return False

        # Try preferred model first, fall back to alternatives if not available
        model_candidates = [self.model_name, 'gemini-2.0-flash', 'gemini-2.0-flash-lite', 'gemini-1.5-flash']
        seen = set()
        model_candidates = [m for m in model_candidates if not (m in seen or seen.add(m))]

        try:
            key = self.api_keys[self.current_key_index]
            self.client = genai.Client(api_key=key)
            self.model_name = model_candidates[0]
            self.is_active = True
            logging.info(f"[+] AI ROUTER: Configured Key #{self.current_key_index + 1} with model {self.model_name}")
            return True
        except Exception as e:
            logging.error(f"[-] AI ROUTER: Key #{self.current_key_index + 1} failed to configure: {e}")
            return False

    def rotate_key(self):
        """Moves to the next key using round-robin rotator."""
        if len(self.api_keys) > 1:
            # Advance rotator and sync index
            next_key = self.rotator.get_key()
            try:
                self.current_key_index = self.api_keys.index(next_key)
            except ValueError:
                self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
            self.stats["key_rotations"] += 1
            return self._configure_next_key()
        return False

    def get_consensus(self, engine_result: Dict, vector_type: str, 
                      all_engines_data: Optional[Dict] = None) -> Dict:
        """
        Routes threat data to Gemini AI as L3 SOC Analyst.
        
        Args:
            engine_result: Primary engine analysis result
            vector_type: Type of attack vector (url, qr, eml, etc.)
            all_engines_data: Optional - data from all 7 engines for correlation
        
        Returns:
            Dict with verdict, reason, advice, and playbook
        """
        self.stats["total_requests"] += 1

        # Check cache first before API call
        cache_key = self._generate_cache_key(engine_result, vector_type)
        if cache_key in self.analysis_cache:
            logging.info(f"[⚡] AI CACHE HIT: Returning cached analysis for {vector_type}")
            return self.analysis_cache[cache_key]["result"]

        if not self.is_active:
            self.stats["fallbacks"] += 1
            return self._get_fallback_verdict("AI Router Offline", all_engines_data)

        logging.info(f"[*] AI ROUTER: L3 SOC Analyst analyzing {vector_type} vector...")
        if all_engines_data:
            logging.info(f"[*] AI ROUTER: Correlating data from {len(all_engines_data)} engines")

        # Build comprehensive prompt
        prompt = self._build_l3_soc_prompt(engine_result, vector_type, all_engines_data)
        
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    top_p=0.8,
                    top_k=40,
                    max_output_tokens=2048
                )
            )
            
            result = self._parse_ai_response(response.text)
            self.stats["successful_analyses"] += 1
            
            # Cache the analysis (LRU eviction)
            self.analysis_cache[cache_key] = {
                "timestamp": datetime.now().isoformat(),
                "result": result
            }
            self.analysis_cache.move_to_end(cache_key)
            if len(self.analysis_cache) > self._cache_max_size:
                self.analysis_cache.popitem(last=False)
            
            return result
            
        except Exception as e:
            logging.warning(f"[!] AI ERROR on key #{self.current_key_index + 1}: {e}. Trying all remaining keys...")

            failed_index = self.current_key_index
            model_fallbacks = ['gemini-2.0-flash', 'gemini-2.0-flash-lite', 'gemini-1.5-flash']
            for i in range(len(self.api_keys)):
                if i == failed_index:
                    continue
                self.current_key_index = i
                self._configure_next_key()
                self.stats["key_rotations"] += 1
                time.sleep(2)
                for model in model_fallbacks:
                    try:
                        logging.info(f"[*] AI ROUTER: Retrying key #{i+1} with model {model}...")
                        response = self.client.models.generate_content(
                            model=model,
                            contents=prompt,
                            config=types.GenerateContentConfig(
                                temperature=0.2,
                                top_p=0.8,
                                top_k=40,
                                max_output_tokens=2048
                            )
                        )
                        self.model_name = model
                        result = self._parse_ai_response(response.text)
                        self.stats["successful_analyses"] += 1
                        logging.info(f"[+] AI ROUTER: Key #{i+1} + model {model} succeeded.")
                        return result
                    except Exception as e_retry:
                        logging.warning(f"[!] Key #{i+1} model {model} failed: {e_retry}")
                        continue

            # All keys exhausted — fallback
            logging.error(f"[-] AI ROUTER: All {len(self.api_keys)} keys exhausted. Switching to fallback mode.")
            self.stats["fallbacks"] += 1
            return self._get_fallback_verdict(str(e), all_engines_data)

    def analyze_all_engines(self, engines_data: Dict[str, Dict]) -> Dict:
        """
        Perform multi-engine correlation analysis.
        Acts as L3 SOC Analyst reviewing all 7 detection vectors.
        
        Args:
            engines_data: Dict with keys for each engine (url, qr, eml, smishing, vishing, clone, social)
        
        Returns:
            Comprehensive threat assessment with correlated indicators
        """
        logging.info("[*] AI ROUTER: L3 SOC Multi-Engine Correlation Analysis")
        
        # Aggregate risk scores
        risk_scores = {}
        high_risk_engines = []
        
        for engine_name, data in engines_data.items():
            if isinstance(data, dict):
                risk = data.get('calculated_risk', 0)
                risk_scores[engine_name] = risk
                if risk >= 70:
                    high_risk_engines.append(engine_name)

        # Build comprehensive analysis prompt
        prompt = f"""{self.L3_SOC_PERSONA}

MULTI-ENGINE CORRELATION ANALYSIS
================================
Total Engines Analyzed: {len(engines_data)}
High Risk Engines (Risk >= 70): {len(high_risk_engines)}
Risk Score Distribution: {json.dumps(risk_scores, indent=2)}

Detailed Engine Results:
{json.dumps(engines_data, indent=2, default=str)}

CORRELATION TASKS:
1. Identify cross-vector attack patterns (e.g., QR code leading to phishing URL)
2. Detect APT-style multi-stage campaigns
3. Assess if this is a targeted attack (spear-phishing) or mass campaign
4. Determine threat actor sophistication level
5. Generate unified incident response playbook

You MUST return ONLY a valid JSON object:
{{
    "correlation_findings": "Description of cross-engine patterns found",
    "threat_actor_assessment": "APT/Mass/Script Kiddie/Unknown",
    "campaign_type": "Targeted/Broad/Opportunistic",
    "overall_risk": "CRITICAL/HIGH/MEDIUM/LOW",
    "primary_vector": "Main attack vector (url/qr/eml/etc)",
    "secondary_vectors": ["Supporting attack vectors"],
    "recommended_priority": "P1/P2/P3/P4",
    "unified_playbook": {{
        "immediate_actions": ["List of immediate containment steps"],
        "investigation_steps": ["Forensic investigation procedures"],
        "remediation": ["System cleanup and hardening"],
        "user_protection": ["Employee safety measures"],
        "monitoring": ["Ongoing threat hunting activities"]
    }},
    "ioc_summary": {{
        "domains": ["Extracted malicious domains"],
        "ips": ["Extracted suspicious IPs"],
        "hashes": ["File hashes if available"],
        "patterns": ["Behavioral patterns detected"]
    }},
    "verdict": "MALICIOUS/SUSPICIOUS/SAFE",
    "executive_summary": "One paragraph for management briefing",
    "technical_details": "Detailed technical analysis"
}}"""

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,
                    top_p=0.9,
                    max_output_tokens=4096
                )
            )
            
            return self._parse_ai_response(response.text, is_correlation=True)
            
        except Exception as e:
            logging.error(f"[-] Multi-engine analysis failed: {e}")
            return self._get_correlation_fallback(engines_data, risk_scores, high_risk_engines)

    def _build_l3_soc_prompt(self, engine_result: Dict, vector_type: str, 
                             all_engines_data: Optional[Dict]) -> str:
        """Build L3 SOC Analyst prompt with context."""
        
        vector_desc = self.VECTOR_DESCRIPTIONS.get(vector_type, "Unknown Vector")
        
        prompt_parts = [
            self.L3_SOC_PERSONA,
            "\n=== THREAT ANALYSIS REQUEST ===",
            f"Attack Vector: {vector_type.upper()} - {vector_desc}",
            f"Analysis Timestamp: {datetime.now().isoformat()}",
            "\n=== PRIMARY ENGINE DATA ===",
            json.dumps(engine_result, indent=2, default=str)
        ]
        
        if all_engines_data:
            prompt_parts.extend([
                "\n=== CORRELATED ENGINE DATA ===",
                "Data from all detection engines for cross-reference:",
                json.dumps(all_engines_data, indent=2, default=str),
                "\n=== CORRELATION INSTRUCTIONS ===",
                "1. Check if indicators from other engines match this threat",
                "2. Identify if this is part of a multi-vector campaign",
                "3. Assess sophistication level based on cross-engine patterns"
            ])
        
        prompt_parts.extend([
            "\n=== ANALYSIS REQUIREMENTS ===",
            "1. FORENSIC ANALYSIS: Technical details of the threat mechanism",
            "2. SOCIAL ENGINEERING: Cognitive biases and psychological triggers",
            "3. IMPACT ASSESSMENT: Business and employee safety implications",
            "4. CONFIDENCE LEVEL: How certain is this assessment?",
            "5. CONTENT-AWARE VERDICT: A domain may look like typosquatting but serve a completely",
            "   different legitimate purpose (e.g. parody site, unrelated business, redirects to real brand).",
            "   You MUST read the actual page_title, html_scan, and visual_scan data in the engine results.",
            "   If the page content does NOT attempt to impersonate/steal credentials from the mimicked brand,",
            "   downgrade the verdict to SUSPICIOUS or SAFE and clearly explain why it is a false positive.",
            "   Only give MALICIOUS if the site actively tries to deceive users (fake login form, credential harvest, malware).",
            "\nYou MUST return ONLY a valid JSON object:",
            json.dumps({
                "verdict": "MALICIOUS/SUSPICIOUS/SAFE",
                "confidence": "0-100 percentage",
                "threat_level": "CRITICAL/HIGH/MEDIUM/LOW",
                "category": "Malware/Phishing/Social Engineering/Data Theft/etc",
                "reason": "Detailed technical explanation including cognitive analysis",
                "key_indicators": ["List of primary detection indicators"],
                "employee_impact": "How this affects employee safety/career",
                "business_impact": "Business continuity implications",
                "advice": "Immediate tactical recommendations",
                "long_term_recommendations": "Strategic security improvements",
                "playbook": [
                    "Step 1: Immediate containment actions",
                    "Step 2: Investigation and evidence preservation",
                    "Step 3: Remediation and cleanup",
                    "Step 4: User protection and awareness",
                    "Step 5: Recovery and monitoring"
                ],
                "iocs": {
                    "domains": [],
                    "ips": [],
                    "urls": [],
                    "file_hashes": [],
                    "patterns": []
                },
                "false_positive": "true/false — Is this likely a false positive? Explain if the domain pattern looks suspicious but the actual page content is harmless/unrelated",
                "telugish_comment": "Include one Telugish phrase (Telugu-English mix) as requested by Boss"
            }, indent=2)
        ])
        
        return "\n".join(prompt_parts)

    def _parse_ai_response(self, text: str, is_correlation: bool = False) -> Dict:
        """Parse and validate AI response."""
        try:
            # Clean up response
            cleaned = text.replace("```json", "").replace("```", "").strip()
            result = json.loads(cleaned)
            
            # Ensure required fields exist
            if is_correlation:
                required = ["verdict", "overall_risk", "unified_playbook"]
            else:
                required = ["verdict", "reason", "playbook", "advice"]
            
            for field in required:
                if field not in result:
                    result[field] = "N/A" if field != "playbook" else []
            
            return result
            
        except json.JSONDecodeError as e:
            logging.error(f"[-] Failed to parse AI response: {e}")
            logging.debug(f"Raw response: {text[:500]}...")
            return self._get_fallback_verdict("JSON parse error")

    def _get_fallback_verdict(self, error_reason: str, 
                              engines_data: Optional[Dict] = None) -> Dict:
        """Generate fallback verdict when AI is unavailable."""
        
        # Extract all available scan data
        risk = 0
        brand = ''
        vt = ''
        urlhaus = ''
        ssl = ''
        domain_age = ''
        server_ip = ''
        
        if engines_data and isinstance(engines_data, dict):
            risk = engines_data.get('calculated_risk', 0)
            brand = str(engines_data.get('brand_check', ''))
            vt = str(engines_data.get('virustotal', ''))
            urlhaus = str(engines_data.get('urlhaus', ''))
            ssl = str(engines_data.get('ssl_certificate', ''))
            domain_age = str(engines_data.get('domain_age', ''))
            server_ip = str(engines_data.get('server_ip_loc', ''))
        
        if risk >= 70:
            verdict = "SUSPICIOUS"
            threat_level = "HIGH"
        elif risk >= 40:
            verdict = "SUSPICIOUS"
            threat_level = "MEDIUM"
        else:
            verdict = "SAFE"
            threat_level = "LOW"
        
        # Build dynamic analysis from actual scan indicators
        findings = [f"Engine Risk Score: {risk}/100."]
        action_items = []
        
        if brand and 'TYPOSQUATTING' in brand.upper():
            findings.append(f"TYPOSQUATTING detected — domain impersonates a known brand ({brand}).")
            action_items.append("Block domain immediately and report to the spoofed brand's abuse team.")
        elif brand and brand.lower() not in ('', 'clean', 'n/a', 'none'):
            findings.append(f"Brand check result: {brand}.")

        if vt and '/' in vt:
            flags = int(vt.split('/')[0]) if vt.split('/')[0].isdigit() else 0
            total = vt.split('/')[1].split()[0] if len(vt.split('/')) > 1 else '?'
            if flags >= 3:
                findings.append(f"VirusTotal: {flags}/{total} security engines flagged this as malicious.")
                action_items.append(f"Isolate affected systems — {flags} AV engines confirmed threat.")
            elif flags > 0:
                findings.append(f"VirusTotal: {flags}/{total} flag(s) — likely a false positive. Major AV vendors show clean.")
            else:
                findings.append(f"VirusTotal: {vt} — no engines flagged.")
        elif vt and vt not in ('N/A', '', 'Checking...'):
            findings.append(f"VirusTotal: {vt}.")

        if urlhaus and 'malicious' in urlhaus.lower():
            findings.append(f"URLHaus threat intelligence: {urlhaus} — known malicious URL database match.")
            action_items.append("URL is in active threat feeds. Do not access.")
        elif urlhaus and urlhaus not in ('N/A', '', 'Checking...'):
            findings.append(f"URLHaus: {urlhaus}.")

        if ssl and ('invalid' in ssl.lower() or 'missing' in ssl.lower() or 'insecure' in ssl.lower()):
            findings.append(f"SSL Certificate issue detected: {ssl}. Legitimate sites use valid HTTPS.")
            action_items.append("Do not submit credentials — SSL is invalid or missing.")
        elif ssl and ssl not in ('N/A', '', 'Checking...'):
            findings.append(f"SSL Status: {ssl}.")

        if domain_age and domain_age not in ('N/A', '', 'Checking...'):
            findings.append(f"Domain Age: {domain_age}.")
            if 'new' in domain_age.lower() or 'day' in domain_age.lower() or 'week' in domain_age.lower():
                action_items.append("Newly registered domain — high indicator of phishing infrastructure.")

        if server_ip and server_ip not in ('N/A', '', 'Unresolved', 'Checking...'):
            findings.append(f"Resolved to server IP: {server_ip}.")

        reason = ' '.join(findings)

        # Build dynamic recommendation
        if risk >= 70 or 'TYPOSQUATTING' in brand.upper():
            if not action_items:
                action_items = ["Block access immediately.", "Conduct manual forensic review by L3 SOC analyst.", "Alert affected users and reset credentials if accessed."]
            advice = ' '.join(action_items)
        elif risk >= 40:
            if not action_items:
                action_items = ["Exercise caution. Verify domain legitimacy through official channels.", "Do not enter credentials until confirmed safe."]
            advice = ' '.join(action_items)
        else:
            if not action_items:
                advice = "No immediate action required. Continue standard security monitoring."
            else:
                advice = ' '.join(action_items) + " Otherwise, standard security posture applies."
        
        return {
            "verdict": f"{verdict} (FALLBACK MODE)",
            "confidence": "60",
            "threat_level": threat_level,
            "category": "Engine Analysis" if risk > 0 else "Clean",
            "reason": reason,
            "key_indicators": [b for b in [brand, vt, urlhaus] if b and b not in ('N/A', '', 'Clean', 'Checking...')] or ["Risk-based heuristic analysis"],
            "employee_impact": "Standard protocols apply. No immediate action required." if risk < 40 else "Review recommended per security policy.",
            "business_impact": "Normal operations." if risk < 40 else "Potential disruption - verify before action.",
            "advice": advice,
            "long_term_recommendations": "Regular security awareness training.",
            "playbook": [
                "Step 1: Verify detection with secondary engine",
                "Step 2: Document findings in incident log",
                "Step 3: Apply recommended actions",
                "Step 4: Monitor for additional indicators"
            ],
            "iocs": {"domains": [], "ips": [], "urls": [], "file_hashes": [], "patterns": []}
        }

    def _get_correlation_fallback(self, engines_data: Dict, risk_scores: Dict,
                                   high_risk_engines: List) -> Dict:
        """Generate fallback for multi-engine correlation."""
        
        max_risk = max(risk_scores.values()) if risk_scores else 0
        
        if max_risk >= 80:
            overall_risk = "CRITICAL"
        elif max_risk >= 60:
            overall_risk = "HIGH"
        elif max_risk >= 40:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        return {
            "correlation_findings": f"AI offline. Basic correlation: {len(high_risk_engines)} engines report high risk.",
            "threat_actor_assessment": "Unknown (AI Offline)",
            "campaign_type": "Unknown",
            "overall_risk": overall_risk,
            "primary_vector": high_risk_engines[0] if high_risk_engines else "Unknown",
            "secondary_vectors": high_risk_engines[1:] if len(high_risk_engines) > 1 else [],
            "recommended_priority": "P1" if overall_risk in ["CRITICAL", "HIGH"] else "P2",
            "unified_playbook": {
                "immediate_actions": ["Enable AI Router connectivity", "Engage human L3 analyst"],
                "investigation_steps": ["Manual correlation of engine data"],
                "remediation": ["Address highest risk vector first"],
                "user_protection": ["Alert users of potential multi-vector attack"],
                "monitoring": ["Watch for related indicators across all vectors"]
            },
            "ioc_summary": {"domains": [], "ips": [], "hashes": [], "patterns": []},
            "verdict": "SUSPICIOUS" if overall_risk in ["CRITICAL", "HIGH"] else "SAFE",
            "executive_summary": f"Multi-vector attack detected with {overall_risk} risk. AI analysis offline - manual review required.",
            "technical_details": f"Risk scores by engine: {json.dumps(risk_scores)}"
        }

    def _generate_cache_key(self, engine_result: Dict, vector_type: str) -> str:
        """Generate cache key for analysis results."""
        key_data = json.dumps(engine_result, sort_keys=True)
        return f"{vector_type}_{hashlib.md5(key_data.encode()).hexdigest()[:16]}"

    def analyze_image(self, prompt: str, image_data: str, mime_type: str = "image/png") -> str:
        """
        Analyze an image using Gemini's vision capabilities.
        
        Args:
            prompt: The analysis prompt/instructions
            image_data: Base64 encoded image data
            mime_type: MIME type of the image (default: image/png)
            
        Returns:
            AI response text
        """
        if not self.is_active or not self.client:
            logging.error("[-] AI ROUTER: Cannot analyze image - AI not active")
            return None
        
        try:
            logging.info(f"[+] AI ROUTER: Analyzing image with vision model...")
            
            # Create image part
            from google.genai import types
            
            # Build content with image
            image_part = types.Part(
                inline_data=types.Blob(
                    mime_type=mime_type,
                    data=image_data
                )
            )
            
            text_part = types.Part(text=prompt)
            
            # Generate content
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=[text_part, image_part],
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    top_p=0.9,
                    max_output_tokens=2048
                )
            )
            
            self.stats["successful_analyses"] += 1
            logging.info(f"[+] AI ROUTER: Image analysis complete")
            
            return response.text
            
        except Exception as e:
            logging.error(f"[-] AI ROUTER: Image analysis failed: {e}")
            # Try rotating key if it's an API error
            if "429" in str(e) or "quota" in str(e).lower():
                self.rotate_key()
                # Retry once
                try:
                    return self.analyze_image(prompt, image_data, mime_type)
                except Exception as retry_error:
                    logging.error(f"[-] AI ROUTER: Retry failed: {retry_error}")
            return None

    def get_stats(self) -> Dict:
        """Return AI Router statistics."""
        return {
            **self.stats,
            "success_rate": (self.stats["successful_analyses"] / max(1, self.stats["total_requests"])) * 100,
            "active_key": self.current_key_index + 1 if self.is_active else None,
            "total_keys": len(self.api_keys),
            "cache_size": len(self.analysis_cache)
        }

    def clear_cache(self):
        """Clear analysis cache."""
        self.analysis_cache.clear()
        logging.info("[+] AI ROUTER: Analysis cache cleared")