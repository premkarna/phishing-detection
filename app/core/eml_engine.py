import logging
import email
import re
import os
import hashlib
import tempfile
import base64
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime

from app.core.pdf_analyzer import pdf_analyzer
from app.services.url_tracer import URLTracer
from app.integrations.threat_intel import ThreatIntelligence
from app.ml.ml_detector import ml_detector
from app.intelligence.ioc import ioc_feed_manager
from app.intelligence.attribution import attribution_engine
from app.core.visual_analyzer import VisualAnalyzer
from app.intelligence.sandbox import SandboxDetonator
from app.intelligence.temporal import temporal_engine

class EMLEngine:
    def __init__(self):
        # REGEX: Matches 1x1 invisible tracking pixels in emails
        self.tracker_pattern = re.compile(r'width=["\']?1["\']?\s+height=["\']?1["\']?', re.IGNORECASE)
        # SENSITIVE KEYWORDS: Words used in Spear Phishing to create pressure
        self.pressure_keywords = ["urgent", "action required", "unauthorized", "suspended", "security breach", "invoice", "payroll", "legal action"]
        
        # Advanced utilities integration
        self.url_tracer = URLTracer()
        self.threat_intel = ThreatIntelligence()
        self.visual_analyzer = VisualAnalyzer()
        self.sandbox = SandboxDetonator()
        
        # Obfuscation patterns in HTML email bodies
        self.obfuscation_patterns = [
            re.compile(r'eval\s*\(', re.IGNORECASE),
            re.compile(r'unescape\s*\(', re.IGNORECASE),
            re.compile(r'fromcharcode', re.IGNORECASE),
            re.compile(r'&#x[0-9a-f]{2,4};', re.IGNORECASE),
            re.compile(r'%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}', re.IGNORECASE),
        ]
        
        # Dangerous attachment extensions
        self.dangerous_extensions = [
            '.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.jar', '.scr', '.hta', '.pif', '.com', '.reg',
            '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm',
            '.zip', '.rar', '.7z', '.iso', '.img'
        ]
        
        logging.info("[EML ENGINE] Initialized with advanced threat detection")

    def analyze(self, input_data: str, case_id: str = None) -> dict:
        """Parses a raw .eml file or raw email text and conducts forensic analysis."""
        logging.info(f"[EML ENGINE] Initiating Spear Phishing Scan...")
        
        results = {
            "target_id": "Email_Payload",
            "sender_forgery": "Not Checked",
            "spf_record": "Missing/None",
            "dkim_signature": "Missing/None",
            "dmarc_policy": "Missing/None",
            "hidden_trackers": "Clean",
            "suspicious_links": "Clean",
            "pressure_tactics": "None Detected",
            "calculated_risk": 0
        }

        try:
            # Handle both File Path and Raw Text
            msg = None
            if os.path.exists(input_data):
                with open(input_data, 'rb') as fp:
                    msg = BytesParser(policy=policy.default).parse(fp)
                results["target_id"] = os.path.basename(input_data)
            else:
                # If it's raw text, try parsing it as an email string
                msg = email.message_from_string(input_data, policy=policy.default)
                results["target_id"] = "Raw_Email_String"

            if not msg:
                return {"calculated_risk": 0, "status": "Invalid Email Data"}

            # 2. Extract Authentication Headers (The DNA Test)
            auth_results = str(msg.get('Authentication-Results', '')).lower()
            received_spf = str(msg.get('Received-SPF', '')).lower()
            
            # --- SPF Check ---
            if 'pass' in received_spf or 'spf=pass' in auth_results:
                results["spf_record"] = "PASS (Verified Origin)"
            elif 'fail' in received_spf or 'softfail' in received_spf:
                results["spf_record"] = "FAIL / SOFTFAIL"
                results["calculated_risk"] += 40
            
            # --- DKIM Check ---
            if 'dkim=pass' in auth_results:
                results["dkim_signature"] = "PASS (Valid Signature)"
            else:
                results["dkim_signature"] = "FAIL / MISSING"
                results["calculated_risk"] += 20

            # --- DMARC Deep Parse ---
            dmarc_policy = "Missing/None"
            if 'dmarc=pass' in auth_results:
                dmarc_policy = "PASS"
            elif 'dmarc=fail' in auth_results:
                dmarc_policy = "FAIL"
                results["calculated_risk"] += 30
                # Extract policy action (reject/quarantine/none)
                dmarc_action_match = re.search(r'dmarc=\w+\s+action=(\w+)', auth_results)
                if dmarc_action_match:
                    action = dmarc_action_match.group(1)
                    dmarc_policy = f"FAIL (policy={action})"
                    if action == "none":
                        results["calculated_risk"] += 10
            elif 'dmarc=bestguesspass' in auth_results:
                dmarc_policy = "BEST_GUESS_PASS (Weak)"
                results["calculated_risk"] += 10
            results["dmarc_policy"] = dmarc_policy

            # 3. Sender Forgery Check (Deep Forensic Analysis)
            from_header = str(msg.get('From', '')).lower()
            return_path = str(msg.get('Return-Path', '')).lower()
            reply_to = str(msg.get('Reply-To', '')).lower()
            
            clean_rp = return_path.strip('<>')
            clean_rt = reply_to.strip('<>')

            # Detection Logic: Return-Path mismatch is a classic Phishing sign
            if clean_rp and clean_rp not in from_header:
                results["sender_forgery"] = "CRITICAL: Return-Path Mismatch (Spoofing Detected)"
                results["calculated_risk"] += 50
            elif clean_rt and clean_rt not in from_header:
                results["sender_forgery"] = "WARNING: Reply-To differs from Sender"
                results["calculated_risk"] += 30
            else:
                results["sender_forgery"] = "Verified Origin"

            # 4. Body Extraction & HTML Forensics
            body_text = ""
            body_html = ""
            if msg.is_multipart():
                for part in msg.walk():
                    try:
                        ctype = part.get_content_type()
                        # Fix for potential encoding issues in email body
                        content = part.get_content()
                        if isinstance(content, bytes):
                            content = content.decode('utf-8', errors='replace')
                        
                        if ctype == "text/plain": body_text += str(content)
                        if ctype == "text/html": body_html += str(content)
                    except Exception as e:
                        logging.warning(f"[EML ENGINE] Part skip error: {e}")
            else:
                try:
                    content = msg.get_content()
                    if isinstance(content, bytes):
                        content = content.decode('utf-8', errors='replace')
                    body_text = str(content)
                    if msg.get_content_type() == "text/html": body_html = body_text
                except Exception as e:
                    logging.warning(f"[EML ENGINE] Single part read error: {e}")

            # Weapon 1: Pressure Keyword Analysis
            subject = str(msg.get('Subject', ''))
            content_to_check = (subject + " " + body_text + body_html).lower()
            found_tactics = [kw for kw in self.pressure_keywords if kw in content_to_check]
            if found_tactics:
                results["pressure_tactics"] = f"DETECTED: {', '.join(found_tactics)}"
                results["calculated_risk"] += (len(found_tactics) * 10)

            # Initialize all_links before body_html block to avoid NameError in attribution
            all_links = []

            # Weapon 2b: Obfuscated HTML / Base64 Body Detection
            obfuscation_hits = []
            combined_body = body_text + body_html
            for pattern in self.obfuscation_patterns:
                if pattern.search(combined_body):
                    obfuscation_hits.append(pattern.pattern)
            # Detect suspicious base64 blobs embedded in body (not standard MIME)
            b64_blobs = re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', combined_body)
            if b64_blobs:
                for blob in b64_blobs[:3]:
                    try:
                        decoded = base64.b64decode(blob).decode('utf-8', errors='ignore')
                        if any(kw in decoded.lower() for kw in ['http', 'script', 'eval', 'password']):
                            obfuscation_hits.append("base64_encoded_suspicious_payload")
                            break
                    except Exception:
                        pass
            if obfuscation_hits:
                results["obfuscation_detected"] = f"DETECTED: {', '.join(set(obfuscation_hits))}"
                results["calculated_risk"] += 35
                logging.warning(f"[EML ENGINE] Obfuscation detected: {obfuscation_hits}")
            else:
                results["obfuscation_detected"] = "Clean"

            if body_html:
                soup = BeautifulSoup(body_html, 'html.parser')
                # Weapon 2: Detect 1x1 Tracking Pixels
                trackers = soup.find_all('img', width=re.compile(r'^1$'), height=re.compile(r'^1$'))
                if trackers:
                    results["hidden_trackers"] = f"DETECTED: {len(trackers)} tracking pixel(s)"
                    results["calculated_risk"] += 20

                # Weapon 3: Detect Cloaked Links
                suspicious_links = []
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href'].lower()
                    text = a_tag.get_text().strip().lower()
                    all_links.append(href)
                    if text.startswith(("http", "www")) and text != href:
                        suspicious_links.append(f"{text} -> {href}")
                
                if suspicious_links:
                    results["suspicious_links"] = f"CLOAKED: {len(suspicious_links)} links found"
                    results["calculated_risk"] += 40
                
                # === ADVANCED URL ANALYSIS ===
                if all_links:
                    results["url_analysis"] = []
                    for link in set(all_links):
                        if not link.startswith(("http://", "https://")):
                            continue
                        
                        url_analysis = {
                            "url": link,
                            "trace": None,
                            "threat_intel": None,
                            "ml_prediction": None,
                            "visual_analysis": None
                        }
                        
                        # URL Tracing
                        try:
                            trace = self.url_tracer.trace_url(link)
                            url_analysis["trace"] = trace
                            if trace.get("is_shortened"):
                                results["calculated_risk"] += 10
                        except Exception as e:
                            logging.warning(f"[EML] URL trace error: {e}")
                        
                        # Threat Intel
                        try:
                            intel = self.threat_intel.check_all(link)
                            url_analysis["threat_intel"] = intel
                            if intel.get("is_malicious"):
                                results["calculated_risk"] += 30
                                logging.critical(f"🚨 MALICIOUS LINK in email: {link}")
                        except Exception as e:
                            logging.warning(f"[EML] Threat intel error: {e}")
                        
                        # ML Detection
                        try:
                            ml_result = ml_detector.predict(link)
                            url_analysis["ml_prediction"] = ml_result
                            if ml_result.get("classification") == "PHISHING":
                                results["calculated_risk"] += 20
                        except Exception as e:
                            logging.warning(f"[EML] ML error: {e}")
                        
                        # Visual Analysis
                        try:
                            visual = self.visual_analyzer.analyze(link)
                            url_analysis["visual_analysis"] = visual
                            if visual.get("detected_brand") and visual.get("brand_domain_match", {}).get("is_suspicious_mismatch"):
                                results["calculated_risk"] += 25
                                logging.critical(f"🚨 BRAND SPOOFING in email: {visual['detected_brand']}")
                        except Exception as e:
                            logging.warning(f"[EML] Visual analysis error: {e}")
                        
                        results["url_analysis"].append(url_analysis)
                
                # === ATTACHMENT ANALYSIS ===
                attachments_analysis = self._analyze_attachments(msg, case_id)
                if attachments_analysis:
                    results["attachments"] = attachments_analysis
                    for att in attachments_analysis:
                        if att.get("is_malicious", False):
                            results["calculated_risk"] += 35
                            logging.critical(f"🚨 MALICIOUS ATTACHMENT: {att.get('filename', 'Unknown')}")
                        if att.get("is_dangerous_type", False):
                            results["calculated_risk"] += 20
                            logging.warning(f"[EML ENGINE] Dangerous attachment type: {att.get('filename', 'Unknown')}")

                # === SANDBOX DETONATION for suspicious links ===
                if all_links and results["calculated_risk"] >= 40:
                    results["sandbox_detonation"] = []
                    detonation_targets = [l for l in set(all_links) if l.startswith(("http://", "https://"))][:3]
                    for link in detonation_targets:
                        try:
                            logging.info(f"[EML ENGINE] Detonating suspicious link: {link}")
                            det_result = self.sandbox.detonate(link, case_id=case_id, capture_hops=True)
                            results["sandbox_detonation"].append({
                                "url": link,
                                "final_destination": det_result.get("final_destination"),
                                "hops": det_result.get("detonation_stats", {}).get("total_hops", 0),
                                "risk_level": det_result.get("risk_level", "UNKNOWN"),
                                "malicious_indicators": det_result.get("malicious_indicators", []),
                                "exfiltration_attempts": det_result.get("api_analysis", {}).get("exfiltration_attempts_count", 0)
                            })
                            if det_result.get("risk_level") in ["CRITICAL", "HIGH"]:
                                results["calculated_risk"] += 30
                                logging.critical(f"🚨 SANDBOX: {det_result.get('risk_level')} risk link detonated: {link}")
                        except Exception as e:
                            logging.warning(f"[EML] Sandbox detonation error: {e}")
            
            # === CAMPAIGN ATTRIBUTION ===
            email_indicators = {
                "urls": all_links if body_html else [],
                "subject": subject,
                "sender": msg.get('From', 'Unknown'),
                "risk_level": "CRITICAL" if results["calculated_risk"] > 70 else "HIGH" if results["calculated_risk"] > 40 else "MEDIUM"
            }
            attribution = attribution_engine.attribute_attack(email_indicators)
            results["attribution"] = attribution

            # === TEMPORAL ANALYSIS ===
            date_header = msg.get('Date', '')
            if date_header:
                try:
                    from email.utils import parsedate_to_datetime
                    email_dt = parsedate_to_datetime(date_header)
                    attack_record = {
                        "timestamp": email_dt.isoformat(),
                        "subject": subject,
                        "sender": msg.get('From', 'Unknown'),
                        "risk": results["calculated_risk"]
                    }
                    temporal_result = temporal_engine.analyze_attack_timeline([attack_record])
                    results["temporal_analysis"] = temporal_result
                except Exception as e:
                    logging.warning(f"[EML] Temporal analysis error: {e}")

            results["calculated_risk"] = min(100, results["calculated_risk"])
            logging.info(f"[EML ENGINE] Scan Complete. Risk: {results['calculated_risk']}%")
            return results

        except Exception as e:
            logging.error(f"[-] EML Engine Error: {e}")
            return {"calculated_risk": 50, "status": f"Forensic Error: {str(e)}"}
    
    def _analyze_attachments(self, msg, case_id: str = None) -> list:
        """Analyze email attachments for threats."""
        attachments = []
        
        try:
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get('Content-Disposition') is None:
                    continue
                
                filename = part.get_filename()
                if not filename:
                    continue
                
                att_info = {
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "size": 0,
                    "is_malicious": False,
                    "analysis": None
                }
                
                # Get attachment data
                payload = part.get_payload(decode=True)
                if payload:
                    att_info["size"] = len(payload)
                    
                    # Dangerous extension check
                    ext = os.path.splitext(filename.lower())[1]
                    if ext in self.dangerous_extensions:
                        att_info["is_dangerous_type"] = True
                        att_info["danger_reason"] = f"High-risk file type: {ext}"
                        logging.warning(f"[EML] Dangerous attachment extension: {ext} in {filename}")
                    else:
                        att_info["is_dangerous_type"] = False

                    # PDF Analysis
                    if filename.lower().endswith('.pdf'):
                        # Save temporarily for analysis
                        temp_path = os.path.join(tempfile.gettempdir(), f"eml_pdf_{hashlib.md5(filename.encode()).hexdigest()[:8]}.pdf")
                        with open(temp_path, 'wb') as f:
                            f.write(payload)
                        
                        try:
                            pdf_analysis = pdf_analyzer.analyze(temp_path, case_id)
                            att_info["analysis"] = pdf_analysis
                            att_info["is_malicious"] = pdf_analysis.get("risk_level") in ["HIGH", "CRITICAL"]
                            
                            # Cleanup
                            os.remove(temp_path)
                        except Exception as e:
                            logging.warning(f"[EML] PDF analysis error: {e}")
                    
                    # Check file hash against IOCs
                    file_hash = hashlib.sha256(payload).hexdigest()
                    ioc_result = ioc_feed_manager.check_hash(file_hash)
                    if ioc_result.get("is_malicious"):
                        att_info["is_malicious"] = True
                        att_info["threat_intel_match"] = True
                
                attachments.append(att_info)
        
        except Exception as e:
            logging.error(f"[EML] Attachment analysis error: {e}")
        
        return attachments
