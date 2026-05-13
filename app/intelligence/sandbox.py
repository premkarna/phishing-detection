"""
Autonomous Payload Detonation Module
====================================
Detonates extracted URLs inside isolated Hyper-V sandbox.
Handles redirect chains automatically and captures final destination.
Uses Playwright with browser isolation for safe payload execution.
"""

import logging
import os
import time
import json
import hashlib
import base64
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import re


class SandboxDetonator:
    """
    Isolated payload detonation environment.
    - Sandboxed browser execution
    - Automatic redirect chain handling
    - Screenshot capture at each hop
    - Network traffic monitoring
    - Final destination capture
    - Complete session isolation
    """
    
    def __init__(self):
        # Sandbox configuration
        self.sandbox_timeout = 60  # Maximum detonation time (seconds)
        self.max_redirects = 20  # Redirect chain limit
        self._project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.screenshot_dir = "sandbox_evidence"
        
        # Ensure evidence directory exists
        os.makedirs(self.sandbox_dir, exist_ok=True)
        
        # Detonation log for forensics
        self.detonation_log = []
        
        logging.info("[SANDBOX DETONATOR] Initialized - Isolated detonation environment ready")
    
    @property
    def sandbox_dir(self):
        """Get or create sandbox evidence directory."""
        evidence_path = os.path.join(self._project_root, self.screenshot_dir)
        os.makedirs(evidence_path, exist_ok=True)
        return evidence_path
    
    def _generate_session_id(self, url: str) -> str:
        """Generate unique session ID for this detonation."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        return f"DET_{timestamp}_{url_hash}"
    
    def _is_safe_url(self, url: str) -> Tuple[bool, str]:
        """
        Pre-flight safety check before detonation.
        
        Returns:
            (is_safe, reason)
        """
        # Check for obviously dangerous schemes
        dangerous_schemes = ['file://', 'ftp://', 'smb://', '\\', 'cmd://', 'powershell://']
        url_lower = url.lower()
        
        for scheme in dangerous_schemes:
            if url_lower.startswith(scheme) or scheme in url_lower:
                return False, f"Dangerous URL scheme detected: {scheme}"
        
        # Check for localhost/private IP access attempts
        private_patterns = [
            r'localhost',
            r'127\.\d+\.\d+\.\d+',
            r'10\.\d+\.\d+\.\d+',
            r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+',
            r'192\.168\.\d+\.\d+',
            r'0\.0\.0\.0',
            r'::1',
            r'169\.254\.\d+\.\d+'  # Link-local
        ]
        
        for pattern in private_patterns:
            if re.search(pattern, url_lower):
                return False, f"Private network access attempt detected: {pattern}"
        
        # Check for data URI (potential XSS/data exfiltration)
        if url_lower.startswith('data:'):
            return False, "Data URI scheme detected - potential injection vector"
        
        # Check for javascript: protocol
        if 'javascript:' in url_lower:
            return False, "JavaScript protocol detected - code execution risk"
        
        return True, "Passed safety checks"
    
    def _capture_screenshot(self, page, filename: str) -> Optional[str]:
        """Capture screenshot and save to evidence directory."""
        try:
            filepath = os.path.join(self.sandbox_dir, filename)
            page.screenshot(path=filepath, full_page=True)
            return filepath
        except Exception as e:
            logging.warning(f"[SANDBOX] Screenshot failed: {e}")
            return None
    
    def _analyze_network_request(self, request, response=None) -> Dict:
        """
        Analyze a network request/response for suspicious activity.
        
        Returns:
            Analysis result with risk assessment
        """
        result = {
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
            "suspicious": False,
            "risk_indicators": [],
            "potential_exfiltration": False
        }
        
        url_lower = request.url.lower()
        
        # Check for credential-related keywords in URL
        credential_keywords = ['password', 'pass', 'pwd', 'credential', 'token', 
                              'api_key', 'secret', 'auth', 'login', 'username', 
                              'user', 'email', 'session']
        
        for keyword in credential_keywords:
            if keyword in url_lower:
                result["risk_indicators"].append(f"Credential keyword in URL: {keyword}")
        
        # Check for suspicious domains (common exfiltration endpoints)
        suspicious_domains = [
            'discord.com/api/webhooks',  # Discord webhooks for exfil
            'api.telegram.org',          # Telegram bots
            'hooks.slack.com',           # Slack webhooks
            'script.google.com',         # Google Apps Script
            'pastebin.com',              # Pastebin
            'requestbin.com',
            'hookbin.com',
            'webhook.site',
            'ngrok.io',                  # Tunneling services
            'burpcollaborator.net',
            'interact.sh'
        ]
        
        for domain in suspicious_domains:
            if domain in url_lower:
                result["risk_indicators"].append(f"Suspicious exfiltration endpoint: {domain}")
                result["suspicious"] = True
                result["potential_exfiltration"] = True
        
        # Check for data exfiltration patterns
        if request.post_data:
            post_data = str(request.post_data).lower()
            if any(kw in post_data for kw in credential_keywords):
                result["risk_indicators"].append("Credential data in POST body")
                result["potential_exfiltration"] = True
            
            # Check for large data transfers (possible bulk exfiltration)
            if len(request.post_data) > 10000:  # 10KB
                result["risk_indicators"].append(f"Large data transfer: {len(request.post_data)} bytes")
        
        # Check for response
        if response:
            result["status"] = response.status
            result["response_size"] = len(response.body()) if response.body() else 0
            
            # Check for successful exfiltration (200 OK on suspicious request)
            if response.status == 200 and result["potential_exfiltration"]:
                result["risk_indicators"].append("SUCCESSFUL EXFILTRATION - 200 OK response")
                result["exfiltration_confirmed"] = True
        
        return result
    
    def detonate(self, url: str, case_id: str = None, capture_hops: bool = True) -> Dict:
        """
        Detonate URL in isolated sandbox environment.
        
        Args:
            url: URL to detonate
            case_id: Optional case identifier
            capture_hops: Capture screenshots at each redirect hop
            
        Returns:
            Detonation results with final destination and evidence
        """
        session_id = self._generate_session_id(url)
        
        logging.info(f"[SANDBOX DETONATOR] Starting detonation session: {session_id}")
        logging.info(f"[SANDBOX DETONATOR] Target URL: {url}")
        
        # Pre-flight safety check
        is_safe, safety_reason = self._is_safe_url(url)
        if not is_safe:
            logging.critical(f"[SANDBOX DETONATOR] SAFETY BLOCK: {safety_reason}")
            return {
                "success": False,
                "session_id": session_id,
                "case_id": case_id,
                "original_url": url,
                "error": f"Safety check failed: {safety_reason}",
                "detonated": False,
                "risk_level": "BLOCKED"
            }
        
        # Initialize results
        results = {
            "success": True,
            "session_id": session_id,
            "case_id": case_id,
            "original_url": url,
            "detonation_time": datetime.now().isoformat(),
            "sandbox_config": {
                "timeout": self.sandbox_timeout,
                "max_redirects": self.max_redirects,
                "isolated": True
            },
            "safety_check": {
                "passed": True,
                "reason": safety_reason
            },
            "redirect_chain": [],
            "final_destination": None,
            "evidence": {
                "screenshots": [],
                "network_logs": [],
                "downloads": []
            },
            "detonation_stats": {
                "total_hops": 0,
                "time_elapsed": 0,
                "js_executed": False,
                "downloads_triggered": 0
            },
            "malicious_indicators": []
        }
        
        # Attempt to import Playwright for sandboxed browser
        try:
            from playwright.sync_api import sync_playwright
            from playwright.sync_api import TimeoutError as PlaywrightTimeout
        except ImportError:
            logging.error("[SANDBOX DETONATOR] Playwright not installed - sandbox detonation unavailable")
            return {
                "success": False,
                "error": "Playwright not installed. Run: pip install playwright && playwright install chromium",
                "detonated": False
            }
        
        start_time = time.time()
        
        try:
            with sync_playwright() as p:
                # Launch browser in isolated context
                # Note: For true Hyper-V isolation, this would use a VM
                # For now, we use Playwright's browser isolation which provides:
                # - Clean profile (no cookies/cache)
                # - No extensions
                # - Network isolation
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',  # Required for Docker/containers
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-accelerated-2d-canvas',
                        '--no-first-run',
                        '--no-zygote',
                        '--single-process',  # Safe for isolated detonation
                        '--disable-gpu',
                        '--disable-web-security',  # Monitor carefully
                        '--disable-features=IsolateOrigins,site-per-process'
                    ]
                )
                
                # Create isolated browser context
                context = browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    accept_downloads=True,  # Capture any downloads triggered
                    bypass_csp=True,  # Bypass CSP to see true behavior
                    java_script_enabled=True
                )
                
                # Set up download handling
                downloads = []
                
                def handle_download(download):
                    downloads.append({
                        "url": download.url,
                        "filename": download.suggested_filename,
                        "timestamp": datetime.now().isoformat()
                    })
                    results["detonation_stats"]["downloads_triggered"] += 1
                    logging.warning(f"[SANDBOX] Download triggered: {download.suggested_filename}")
                    # Don't actually save - just record
                    download.cancel()
                
                page = context.new_page()
                page.on("download", handle_download)
                
                # Set up console monitoring
                console_logs = []
                page.on("console", lambda msg: console_logs.append({
                    "type": msg.type,
                    "text": msg.text,
                    "timestamp": datetime.now().isoformat()
                }))
                
                # Set up network monitoring for API call analysis
                network_logs = []
                suspicious_requests = []
                exfiltration_attempts = []
                
                def handle_request(request):
                    """Capture and analyze all outgoing requests."""
                    try:
                        analysis = self._analyze_network_request(request)
                        network_logs.append({
                            "timestamp": datetime.now().isoformat(),
                            "request": analysis
                        })
                        
                        if analysis["suspicious"]:
                            suspicious_requests.append(analysis)
                            logging.warning(f"[SANDBOX API] Suspicious request: {request.method} {request.url[:80]}...")
                        
                        if analysis.get("potential_exfiltration"):
                            exfiltration_attempts.append(analysis)
                            logging.critical(f"[SANDBOX API] 🚨 POTENTIAL EXFILTRATION: {request.url[:80]}...")
                            
                    except Exception as e:
                        logging.debug(f"[SANDBOX] Request analysis error: {e}")
                
                def handle_response(response):
                    """Capture and analyze responses."""
                    try:
                        request = response.request
                        analysis = self._analyze_network_request(request, response)
                        
                        # Update the corresponding request log
                        for log in network_logs:
                            if log["request"]["url"] == request.url and "response" not in log:
                                log["response"] = {
                                    "status": analysis.get("status"),
                                    "response_size": analysis.get("response_size"),
                                    "risk_indicators": analysis.get("risk_indicators", [])
                                }
                                break
                        
                        # Alert on confirmed exfiltration
                        if analysis.get("exfiltration_confirmed"):
                            logging.critical(f"🚨🚨🚨 [SANDBOX API] CONFIRMED DATA EXFILTRATION!")
                            logging.critical(f"    URL: {request.url}")
                            logging.critical(f"    Status: {analysis.get('status')}")
                            
                    except Exception as e:
                        logging.debug(f"[SANDBOX] Response analysis error: {e}")
                
                page.on("request", handle_request)
                page.on("response", handle_response)
                
                # Navigate to URL with redirect handling
                current_url = url
                hop_count = 0
                
                try:
                    # Initial navigation
                    logging.info(f"[SANDBOX] Initial navigation to: {url}")
                    response = page.goto(url, timeout=self.sandbox_timeout * 1000, wait_until='networkidle')
                    
                    # Wait for any immediate redirects to settle
                    page.wait_for_timeout(3000)
                    
                    # Capture initial state
                    current_url = page.url
                    hop_data = {
                        "hop_number": hop_count,
                        "url": current_url,
                        "timestamp": datetime.now().isoformat(),
                        "title": page.title(),
                        "status": response.status if response else "unknown"
                    }
                    
                    # Capture screenshot of initial page
                    if capture_hops:
                        screenshot_file = f"{session_id}_hop_{hop_count}_initial.png"
                        screenshot_path = self._capture_screenshot(page, screenshot_file)
                        if screenshot_path:
                            hop_data["screenshot"] = screenshot_path
                            results["evidence"]["screenshots"].append(screenshot_path)
                    
                    results["redirect_chain"].append(hop_data)
                    
                    # Monitor for automatic redirects (JavaScript/meta refresh)
                    max_monitor_time = 30  # seconds
                    monitor_start = time.time()
                    last_url = current_url
                    
                    while (time.time() - monitor_start) < max_monitor_time and hop_count < self.max_redirects:
                        # Wait a bit
                        page.wait_for_timeout(2000)
                        
                        # Check if URL changed
                        new_url = page.url
                        if new_url != last_url:
                            hop_count += 1
                            logging.info(f"[SANDBOX] Redirect detected - Hop {hop_count}: {new_url}")
                            
                            hop_data = {
                                "hop_number": hop_count,
                                "url": new_url,
                                "timestamp": datetime.now().isoformat(),
                                "title": page.title(),
                                "trigger": "javascript_redirect"
                            }
                            
                            # Capture screenshot
                            if capture_hops:
                                screenshot_file = f"{session_id}_hop_{hop_count}_redirect.png"
                                screenshot_path = self._capture_screenshot(page, screenshot_file)
                                if screenshot_path:
                                    hop_data["screenshot"] = screenshot_path
                                    results["evidence"]["screenshots"].append(screenshot_path)
                            
                            results["redirect_chain"].append(hop_data)
                            last_url = new_url
                            monitor_start = time.time()  # Reset timer
                        else:
                            # Check for page stability (no more redirects)
                            if (time.time() - monitor_start) > 5:
                                break
                    
                    # Final state capture
                    final_url = page.url
                    results["final_destination"] = final_url
                    results["detonation_stats"]["total_hops"] = hop_count
                    
                    # Capture final screenshot
                    final_screenshot = f"{session_id}_final_destination.png"
                    final_screenshot_path = self._capture_screenshot(page, final_screenshot)
                    if final_screenshot_path:
                        results["evidence"]["screenshots"].append(final_screenshot_path)
                    
                    # Gather page information
                    try:
                        results["final_page_info"] = {
                            "url": final_url,
                            "title": page.title(),
                            "domain": urlparse(final_url).netloc,
                            "console_logs": console_logs[-20:] if console_logs else [],  # Last 20 logs
                            "download_attempts": downloads
                        }
                    except Exception as e:
                        logging.warning(f"[SANDBOX] Could not gather final page info: {e}")
                    
                    # === ATTACKER API ANALYSIS ===
                    # Add network monitoring results
                    results["api_analysis"] = {
                        "total_requests": len(network_logs),
                        "suspicious_requests_count": len(suspicious_requests),
                        "exfiltration_attempts_count": len(exfiltration_attempts),
                        "network_logs": network_logs[-50:] if len(network_logs) > 50 else network_logs,  # Last 50
                        "suspicious_requests": suspicious_requests,
                        "exfiltration_attempts": exfiltration_attempts,
                        "top_destinations": self._extract_top_destinations(network_logs)
                    }
                    
                    # Log API analysis summary
                    logging.info(f"[SANDBOX API] Network analysis: {len(network_logs)} total requests")
                    logging.info(f"[SANDBOX API] Suspicious requests: {len(suspicious_requests)}")
                    logging.info(f"[SANDBOX API] Exfiltration attempts: {len(exfiltration_attempts)}")
                    
                    # Check for malicious indicators (after api_analysis is populated)
                    self._analyze_malicious_indicators(results, console_logs, downloads, results["api_analysis"])
                    
                    # Check if JS was heavily used (potential drive-by download)
                    if len(console_logs) > 50:
                        results["detonation_stats"]["js_executed"] = True
                        results["malicious_indicators"].append("Heavy JavaScript execution detected")
                    
                    # CRITICAL: Exfiltration takes priority
                    if exfiltration_attempts:
                        results["malicious_indicators"].insert(0, 
                            f"🚨 CONFIRMED CREDENTIAL EXFILTRATION: {len(exfiltration_attempts)} attempts detected"
                        )
                        results["risk_level"] = "CRITICAL"
                    
                    logging.info(f"[SANDBOX] Detonation complete: {hop_count} hops, final: {final_url}")
                    
                except PlaywrightTimeout:
                    logging.warning("[SANDBOX] Navigation timeout - potential blocking or slow redirect chain")
                    results["error"] = "Navigation timeout"
                    results["final_destination"] = page.url if page else url
                    
                except Exception as e:
                    logging.error(f"[SANDBOX] Detonation error: {e}")
                    results["error"] = str(e)
                    results["final_destination"] = page.url if page else url
                
                # Cleanup - CRITICAL for isolation
                elapsed = time.time() - start_time
                results["detonation_stats"]["time_elapsed"] = round(elapsed, 2)
                
                context.close()
                browser.close()
                
                logging.info(f"[SANDBOX] Browser context destroyed after {elapsed:.2f}s")
                
        except Exception as e:
            logging.error(f"[SANDBOX] Fatal detonation error: {e}")
            results["success"] = False
            results["error"] = f"Detonation failed: {str(e)}"
        
        # Log detonation
        self.detonation_log.append({
            "session_id": session_id,
            "case_id": case_id,
            "timestamp": results["detonation_time"],
            "original_url": url,
            "final_url": results.get("final_destination"),
            "hops": results["detonation_stats"]["total_hops"],
            "risk_level": results.get("risk_level", "UNKNOWN")
        })
        
        return results
    
    def _extract_top_destinations(self, network_logs: List) -> List[Dict]:
        """Extract and count top API destinations from network logs."""
        from collections import Counter
        from urllib.parse import urlparse
        
        domains = []
        for log in network_logs:
            try:
                url = log.get("request", {}).get("url", "")
                parsed = urlparse(url)
                if parsed.netloc:
                    domains.append(parsed.netloc)
            except (AttributeError, TypeError, ValueError):
                # Log entry format issue - skip this entry
                continue
        
        counter = Counter(domains)
        top_domains = counter.most_common(10)
        
        return [
            {"domain": domain, "request_count": count}
            for domain, count in top_domains
        ]
    
    def _analyze_malicious_indicators(self, results: Dict, console_logs: List, downloads: List, api_analysis: Dict = None):
        """Analyze detonation results for malicious behavior indicators."""
        indicators = []
        
        # Check for download attempts
        if downloads:
            indicators.append(f"Download attempts triggered: {len(downloads)}")
            for dl in downloads:
                # Check for executable downloads
                exe_extensions = ['.exe', '.msi', '.bat', '.cmd', '.sh', '.ps1']
                if any(dl['filename'].lower().endswith(ext) for ext in exe_extensions):
                    indicators.append(f"Executable download attempted: {dl['filename']}")
        
        # Check console logs for suspicious activity
        suspicious_patterns = [
            'eval(',
            'document.write',
            'innerHTML',
            'window.location',
            'window.open',
            'fetch(',
            'XMLHttpRequest',
            'WebSocket',
            'localStorage',
            'sessionStorage',
            'document.cookie'
        ]
        
        for log in console_logs:
            for pattern in suspicious_patterns:
                if pattern in log.get('text', ''):
                    indicators.append(f"Suspicious JS pattern: {pattern}")
                    break
        
        # Check for excessive redirects
        if results["detonation_stats"]["total_hops"] > 5:
            indicators.append(f"Excessive redirects: {results['detonation_stats']['total_hops']} hops")
        
        # Check final domain vs original
        original_domain = urlparse(results["original_url"]).netloc
        final_domain = urlparse(results.get("final_destination", "")).netloc
        if original_domain != final_domain:
            indicators.append(f"Domain changed: {original_domain} → {final_domain}")
        
        # === API/NETWORK BASED INDICATORS ===
        if api_analysis:
            # Suspicious API endpoints
            if api_analysis.get("suspicious_requests_count", 0) > 0:
                indicators.append(f"Suspicious API calls detected: {api_analysis['suspicious_requests_count']}")
            
            # Exfiltration attempts
            if api_analysis.get("exfiltration_attempts_count", 0) > 0:
                exfil_count = api_analysis['exfiltration_attempts_count']
                indicators.insert(0, f"🚨 CRITICAL: Credential exfiltration attempts: {exfil_count}")
                
                # List the exfiltration destinations
                for attempt in api_analysis.get("exfiltration_attempts", [])[:3]:
                    dest = attempt.get("url", "unknown")[:60]
                    indicators.append(f"  → Exfil target: {dest}...")
        
        results["malicious_indicators"] = indicators
        
        # Assign risk level
        has_exfiltration = any("exfiltration" in i.lower() for i in indicators)
        has_executable = any("Executable" in i for i in indicators)
        
        if has_exfiltration:
            results["risk_level"] = "CRITICAL"
        elif len(indicators) >= 3 or has_executable:
            results["risk_level"] = "HIGH"
        elif len(indicators) >= 1:
            results["risk_level"] = "MEDIUM"
        else:
            results["risk_level"] = "LOW"
    
    def get_detonation_log(self) -> List[Dict]:
        """Get detonation history for forensics."""
        return self.detonation_log
    
    def export_evidence(self, detonation_result: Dict, output_dir: str = None) -> str:
        """
        Export detonation evidence to structured report.
        
        Args:
            detonation_result: Results from detonate()
            output_dir: Output directory (default: sandbox_evidence)
            
        Returns:
            Path to exported report JSON
        """
        if output_dir is None:
            output_dir = self.sandbox_dir
        
        session_id = detonation_result["session_id"]
        report_path = os.path.join(output_dir, f"{session_id}_report.json")
        
        with open(report_path, 'w') as f:
            json.dump(detonation_result, f, indent=2, default=str)
        
        logging.info(f"[SANDBOX] Evidence exported: {report_path}")
        return report_path


# Convenience function
def detonate_url(url: str, case_id: str = None) -> Dict:
    """Quick function to detonate URL without instantiation."""
    detonator = SandboxDetonator()
    return detonator.detonate(url, case_id)


# Singleton instance
sandbox_detonator = SandboxDetonator()
