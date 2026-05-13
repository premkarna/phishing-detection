import logging
import os
import cv2
import numpy as np
from pyzbar.pyzbar import decode
import re

# Optional: PyMuPDF for PDF QR handling
try:
    import pymupdf as fitz  # PyMuPDF v1.23+ (uses pymupdf import)
    HAS_FITZ = True
except ImportError:
    try:
        import fitz  # Fallback for older versions
        HAS_FITZ = True
    except ImportError:
        HAS_FITZ = False
        logging.warning("[QR ENGINE] PyMuPDF not installed. PDF QR extraction will be limited.")

from app.services.url_tracer import URLTracer, tracer
from app.integrations.threat_intel import ThreatIntelligence
from app.ml.heuristics import DomainHeuristics
from app.core.visual_analyzer import VisualAnalyzer
from app.core.zero_click_extractor import ZeroClickExtractor
from app.intelligence.sandbox import SandboxDetonator

class QREngine:
    def __init__(self):
        # REGEX to verify if the extracted text is actually a URL
        self.url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
        # Known URL shorteners used by hackers to hide the real destination
        self.shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly']
        # URL Tracer for following redirects and unshortening URLs
        self.url_tracer = URLTracer()
        # Threat Intelligence for checking domain reputation
        self.threat_intel = ThreatIntelligence()
        # Domain Heuristics for age, SSL, and structure analysis
        self.heuristics = DomainHeuristics()
        # Visual Analyzer for AI-driven screenshot analysis
        self.visual_analyzer = VisualAnalyzer()
        # Zero-Click Extractor for forensic-safe QR extraction
        self.zero_click_extractor = ZeroClickExtractor()
        # Sandbox Detonator for isolated payload execution
        self.sandbox_detonator = SandboxDetonator()

    def _extract_from_pdf(self, pdf_path: str) -> list:
        """Convert PDF pages to images and decode QR codes from each page."""
        logging.info(f"[QR ENGINE] Processing PDF file: {pdf_path}")
        decoded_payloads = []
        
        # Check if PyMuPDF is available
        if not HAS_FITZ:
            logging.warning("[QR ENGINE] PyMuPDF not installed. Cannot extract from PDF.")
            return decoded_payloads
        
        try:
            pdf_document = fitz.open(pdf_path)
            
            for page_num in range(len(pdf_document)):
                page = pdf_document[page_num]
                # Render page to image at 150 DPI for good QR readability
                mat = fitz.Matrix(150/72, 150/72)  # 150 DPI
                pix = page.get_pixmap(matrix=mat)
                
                # Convert to numpy array for OpenCV
                img_data = np.frombuffer(pix.samples, dtype=np.uint8)
                img = img_data.reshape(pix.height, pix.width, pix.n)
                
                # Convert RGB to BGR for OpenCV
                if pix.n == 3:
                    img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)
                elif pix.n == 4:
                    img = cv2.cvtColor(img, cv2.COLOR_RGBA2BGR)
                
                # Try to decode QR from this page
                decoded_objects = decode(img)
                
                # If standard fails, try forensic enhancement
                if not decoded_objects:
                    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                    _, thresh = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
                    decoded_objects = decode(thresh)
                
                for obj in decoded_objects:
                    payload = obj.data.decode('utf-8')
                    decoded_payloads.append({
                        "page": page_num + 1,
                        "payload": payload,
                        "type": obj.type
                    })
                    logging.info(f"[+] QR Found on Page {page_num + 1}: {payload}")
            
            pdf_document.close()
            
        except Exception as e:
            logging.error(f"[-] PDF Processing Error: {e}")
            raise
        
        return decoded_payloads

    def analyze(self, file_path: str, case_id: str = None) -> dict:
        """
        Acts as the 'Eyes' of the SOC. Reads image/PDF and extracts hidden payloads.
        Uses Zero-Click extraction for forensic-safe QR detection.
        """
        logging.info(f"[QR ENGINE] Initiating scan on: {file_path}")
        
        results = {
            "target_file": file_path,
            "status": "Scanning",
            "extracted_payload": "None",
            "payload_type": "Unknown",
            "obfuscation_detected": False,
            "calculated_risk": 0,
            "pages_scanned": 1,
            "forensic_hash": None
        }

        try:
            # === ZERO-CLICK EXTRACTION (Forensic-Safe) ===
            # Automatically extracts QR without triggering trackers
            logging.info("[QR ENGINE] Using Zero-Click extraction (forensic-safe mode)")
            
            extraction_result = self.zero_click_extractor.extract(file_path, case_id)
            
            if not extraction_result["success"]:
                results["status"] = f"Extraction failed: {extraction_result.get('error', 'Unknown error')}"
                return results
            
            # Store forensic hash
            results["forensic_hash"] = extraction_result.get("file_hash_sha256")
            
            # Check if any payloads found
            payloads = extraction_result.get("payloads", [])
            results["pages_scanned"] = extraction_result.get("payloads_found", 0)
            
            if not payloads:
                results["status"] = "No QR Code Found"
                return results
            
            # Use first payload for main analysis
            first_payload = payloads[0]
            payload = first_payload["payload"]
            results["extracted_payload"] = payload
            results["all_payloads"] = payloads
            results["status"] = f"QR Payload Extracted from {first_payload.get('source', 'unknown')}"
            logging.info(f"[+] Hidden Payload Found: {payload}")
            
            # Add forensic metadata
            results["forensic_extraction"] = {
                "method": extraction_result["forensic_notes"]["method"],
                "tracker_safe": extraction_result["forensic_notes"]["tracker_safe"],
                "extraction_time": extraction_result["extraction_time"],
                "file_hash": extraction_result["file_hash_sha256"]
            }
            
            # Note: Zero-Click extractor already applied forensic enhancement techniques
            # (grayscale, adaptive thresholding, OTSU, scaling) internally

            # 5. Risk Calculation Heuristics
            if self.url_pattern.search(payload):
                results["payload_type"] = "URL Link"
                results["calculated_risk"] += 20  # Base risk for URLs in QR
                
                # Trace URL to find final destination (Unshortening & Redirection Analysis)
                logging.info(f"[QR ENGINE] Initiating URL trace for: {payload}")
                trace_results = self.url_tracer.trace_url(payload)
                results["url_trace"] = trace_results
                results["final_url"] = trace_results["final_url"]
                results["redirect_count"] = trace_results["redirect_count"]
                
                # Add trace-based risk score
                trace_risk = self.url_tracer.get_risk_score(trace_results)
                results["calculated_risk"] += trace_risk // 2  # Add half of trace risk
                
                # Log trace results
                if trace_results["redirect_count"] > 0:
                    logging.info(f"[+] URL Traced: {trace_results['redirect_count']} redirects found")
                    logging.info(f"[+] Final Destination: {trace_results['final_url']}")
                
                if trace_results["is_shortened"]:
                    results["obfuscation_detected"] = True
                    logging.warning("[!] ALERT: Shortened URL detected - Unshortened!")
                    
                if trace_results["redirect_count"] > 3:
                    logging.warning(f"[!] ALERT: Excessive redirects ({trace_results['redirect_count']}) - possible evasion!")
                    
                if trace_results["domain_changes"] > 1:
                    logging.warning(f"[!] ALERT: Domain changed {trace_results['domain_changes']} times during redirect chain!")
                
                # 6. Threat Intelligence Check (Query VirusTotal, URLScan, AbuseIPDB)
                final_url = trace_results.get("final_url", payload)
                logging.info(f"[QR ENGINE] Querying Threat Intelligence for: {final_url}")
                
                intel_results = self.threat_intel.check_all(final_url)
                results["threat_intel"] = intel_results
                results["is_threat_intel_flagged"] = intel_results.get("is_malicious", False)
                
                # Add threat intel score to overall risk
                intel_score = intel_results.get("combined_score", 0)
                results["calculated_risk"] += intel_score
                
                # Log threat intel findings
                if intel_results["is_malicious"]:
                    flagged_services = ", ".join(intel_results["services_detected"])
                    logging.critical(f"[!] CRITICAL: URL flagged as MALICIOUS by {flagged_services}!")
                elif intel_results["services_queried"]:
                    logging.info(f"[+] Threat Intel: {len(intel_results['services_queried'])} services queried, {len(intel_results['services_detected'])} flagged")
                else:
                    logging.warning("[!] Threat Intel: No API keys configured - skipped threat intelligence check")
                
                # 7. Domain Heuristics Analysis (Age, SSL, Structure)
                logging.info(f"[QR ENGINE] Running domain heuristics on: {final_url}")
                
                heuristic_results = self.heuristics.full_analysis(final_url)
                results["heuristics"] = heuristic_results
                results["heuristic_risk_score"] = heuristic_results.get("overall_risk_score", 0)
                
                # Add heuristic score to overall risk
                results["calculated_risk"] += heuristic_results["overall_risk_score"]
                
                # Log critical heuristic findings
                domain_age_info = heuristic_results["details"].get("domain_age", {})
                if domain_age_info.get("is_recent"):
                    age_days = domain_age_info.get("age_days", 0)
                    logging.critical(f"[!] CRITICAL: Domain is only {age_days} days old - very suspicious!")
                elif domain_age_info.get("error") and "not found" in str(domain_age_info.get("error", "")).lower():
                    logging.critical(f"[!] CRITICAL: Domain not found in WHOIS - extremely suspicious!")
                
                # Check SSL issues
                ssl_info = heuristic_results["details"].get("ssl_certificate", {})
                if not ssl_info.get("has_ssl"):
                    logging.warning(f"[!] WARNING: No SSL certificate - HTTP only site")
                if ssl_info.get("is_self_signed"):
                    logging.warning(f"[!] WARNING: Self-signed SSL certificate detected")
                
                # Check structure issues
                structure_info = heuristic_results["details"].get("domain_structure", {})
                if structure_info.get("has_suspicious_tld"):
                    logging.warning(f"[!] WARNING: Suspicious TLD detected")
                if structure_info.get("is_ip_address"):
                    logging.critical(f"[!] CRITICAL: Direct IP address URL detected")
                    
                logging.info(f"[+] Heuristics: Risk level '{heuristic_results['risk_level']}' with score {heuristic_results['overall_risk_score']}/100")
                
                # 8. AI-Driven Visual Analysis (Screenshot & AI Vision Analysis)
                logging.info(f"[QR ENGINE] Initiating AI visual analysis for: {final_url}")
                
                visual_results = self.visual_analyzer.analyze(final_url)
                results["visual_analysis"] = visual_results
                results["visual_risk_score"] = visual_results.get("risk_score", 0)
                
                # Add visual analysis risk score
                results["calculated_risk"] += visual_results["risk_score"]
                
                # Log visual analysis findings
                if visual_results.get("ai_analysis", {}).get("ai_detected_brand"):
                    ai_brand = visual_results["ai_analysis"]["ai_detected_brand"]
                    ai_conf = visual_results["ai_analysis"]["ai_confidence"]
                    logging.info(f"[+] AI detected brand: {ai_brand} (confidence: {ai_conf}%)")
                
                if visual_results.get("brand_domain_match", {}).get("is_suspicious_mismatch"):
                    logging.critical(f"[!] CRITICAL: AI detected brand-domain mismatch - likely phishing!")
                
                if visual_results.get("visual_spoofing_indicators"):
                    for indicator in visual_results["visual_spoofing_indicators"]:
                        logging.warning(f"[!] {indicator}")
                
                if visual_results.get("screenshot_captured"):
                    logging.info(f"[+] Screenshot captured and analyzed by AI")
                else:
                    logging.warning(f"[!] Screenshot capture failed - AI visual analysis limited")
                
                # 9. AUTONOMOUS PAYLOAD DETONATION (Isolated Sandbox)
                # Only detonate if URL is not in threat intel (to save resources) or if high risk
                should_detonate = (
                    intel_results.get("is_malicious") or 
                    heuristic_results["overall_risk_score"] > 30 or
                    visual_results.get("risk_score", 0) > 20
                )
                
                if should_detonate and final_url.startswith(('http://', 'https://')):
                    logging.info(f"[QR ENGINE] Initiating AUTONOMOUS PAYLOAD DETONATION in sandbox")
                    logging.info(f"[QR ENGINE] Target: {final_url}")
                    
                    detonation_result = self.sandbox_detonator.detonate(
                        final_url, 
                        case_id=case_id,
                        capture_hops=True
                    )
                    
                    results["sandbox_detonation"] = detonation_result
                    results["detonation_performed"] = detonation_result.get("detonated", False)
                    
                    # Add detonation risk score
                    if detonation_result.get("success"):
                        hop_risk = min(detonation_result["detonation_stats"]["total_hops"] * 3, 15)
                        results["calculated_risk"] += hop_risk
                        
                        # Log detonation findings
                        if detonation_result["detonation_stats"]["total_hops"] > 0:
                            logging.info(f"[+] Sandbox: {detonation_result['detonation_stats']['total_hops']} redirect hops captured")
                        
                        if detonation_result["detonation_stats"]["downloads_triggered"] > 0:
                            logging.critical(f"[!] CRITICAL: Sandbox detected {detonation_result['detonation_stats']['downloads_triggered']} download attempts!")
                            results["calculated_risk"] += 25
                        
                        if detonation_result.get("malicious_indicators"):
                            for indicator in detonation_result["malicious_indicators"]:
                                logging.warning(f"[!] Sandbox Indicator: {indicator}")
                        
                        # Final destination from sandbox (more accurate than URL trace)
                        if detonation_result.get("final_destination"):
                            sandbox_final = detonation_result["final_destination"]
                            if sandbox_final != final_url:
                                logging.info(f"[+] Sandbox found deeper redirect: {sandbox_final}")
                                results["final_url"] = sandbox_final
                    else:
                        logging.warning(f"[!] Sandbox detonation failed: {detonation_result.get('error', 'Unknown error')}")
                else:
                    logging.info(f"[QR ENGINE] Skipping sandbox detonation (low risk or non-HTTP URL)")
                    results["sandbox_detonation"] = None
                    results["detonation_performed"] = False
                    
            else:
                results["payload_type"] = "Plain Text / Config Data"
                results["url_trace"] = None
                results["threat_intel"] = None
                results["heuristics"] = None
                results["heuristic_risk_score"] = 0
                results["visual_analysis"] = None
                results["visual_risk_score"] = 0
                results["sandbox_detonation"] = None
                results["detonation_performed"] = False
                
            # Cap risk at 100
            results["calculated_risk"] = min(results["calculated_risk"], 100)

        except Exception as e:
            logging.error(f"[-] QR Engine Error: {e}")
            results["status"] = f"Error processing image: {str(e)}"
            results["calculated_risk"] = 0

        logging.info(f"[QR ENGINE] Scan Complete. Base Risk: {results['calculated_risk']}%")
        return results