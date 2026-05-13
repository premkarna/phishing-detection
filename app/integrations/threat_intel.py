import logging
import requests
import os
import json
from typing import Dict, Optional, List
from urllib.parse import urlparse
import hashlib
import time


class ThreatIntelligence:
    """
    Queries threat intelligence APIs to check if domains/URLs are flagged as malicious.
    Supports VirusTotal, URLScan.io, and AbuseIPDB.
    """
    
    def __init__(self):
        # Load API keys from environment (support multiple naming conventions)
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY') or os.getenv('VT_API_KEY_1') or os.getenv('VT_API_KEY', '')
        self.urlscan_api_key = os.getenv('URLSCAN_API_KEY') or os.getenv('URLSCAN_API_KEY', '')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY') or os.getenv('ABUSEIPDB_API_KEY', '')
        
        # API endpoints
        self.virustotal_url = "https://www.virustotal.com/vtapi/v2/url/report"
        self.virustotal_domain = "https://www.virustotal.com/vtapi/v2/domain/report"
        self.urlscan_submit = "https://urlscan.io/api/v1/scan/"
        self.urlscan_result = "https://urlscan.io/api/v1/result/"
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
        
        # Rate limiting trackers
        self.vt_last_call = 0
        self.vt_rate_limit = 4  # 4 requests per minute for free tier
        
        # Cache for results
        self._cache = {}
        self._cache_ttl = 3600  # 1 hour cache
    
    def _get_cache_key(self, url: str, service: str) -> str:
        """Generate cache key for URL+service combination."""
        return hashlib.md5(f"{url}:{service}".encode()).hexdigest()
    
    def _get_cached(self, url: str, service: str) -> Optional[Dict]:
        """Get cached result if valid."""
        key = self._get_cache_key(url, service)
        if key in self._cache:
            result, timestamp = self._cache[key]
            if time.time() - timestamp < self._cache_ttl:
                logging.info(f"[THREAT INTEL] Cache hit for {service}: {url}")
                return result
        return None
    
    def _set_cached(self, url: str, service: str, result: Dict):
        """Cache result with timestamp."""
        key = self._get_cache_key(url, service)
        self._cache[key] = (result, time.time())
    
    def _rate_limit_wait(self, last_call: float, min_interval: float) -> float:
        """Wait if needed to respect rate limits."""
        elapsed = time.time() - last_call
        if elapsed < min_interval:
            sleep_time = min_interval - elapsed
            logging.info(f"[THREAT INTEL] Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        return time.time()
    
    def check_virustotal(self, url: str) -> Dict:
        """
        Query VirusTotal API for URL reputation.
        
        Returns:
            Dict with detection stats and permalink
        """
        if not self.virustotal_api_key:
            return {"error": "VirusTotal API key not configured"}
        
        # Check cache
        cached = self._get_cached(url, "virustotal")
        if cached:
            return cached
        
        # Rate limiting (4 requests per minute for free tier)
        self.vt_last_call = self._rate_limit_wait(self.vt_last_call, 15)
        
        try:
            params = {
                'apikey': self.virustotal_api_key,
                'resource': url,
                'allinfo': 'false'
            }
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            }
            
            response = requests.get(
                self.virustotal_url,
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                result = {
                    "service": "VirusTotal",
                    "url": url,
                    "positives": data.get('positives', 0),
                    "total": data.get('total', 0),
                    "scan_date": data.get('scan_date'),
                    "permalink": data.get('permalink'),
                    "detected": data.get('positives', 0) > 0,
                    "threat_level": self._vt_threat_level(data.get('positives', 0), data.get('total', 1)),
                    "scans": {}
                }
                
                # Extract detections from scans
                scans = data.get('scans', {})
                for engine, scan_data in scans.items():
                    if scan_data.get('detected'):
                        result["scans"][engine] = scan_data.get('result', 'Detected')
                
                self._set_cached(url, "virustotal", result)
                logging.info(f"[VirusTotal] {url} - {result['positives']}/{result['total']} detections")
                return result
                
            elif response.status_code == 204:
                return {"error": "VirusTotal API rate limit exceeded"}
            else:
                return {"error": f"VirusTotal API error: {response.status_code}"}
                
        except requests.exceptions.RequestException as e:
            logging.error(f"[VirusTotal] Request error: {e}")
            return {"error": f"Request failed: {str(e)}"}
        except Exception as e:
            logging.error(f"[VirusTotal] Unexpected error: {e}")
            return {"error": str(e)}
    
    def _vt_threat_level(self, positives: int, total: int) -> str:
        """Determine threat level based on VirusTotal positives."""
        if positives == 0:
            return "clean"
        elif positives <= 2:
            return "suspicious"
        elif positives <= 5:
            return "malicious"
        else:
            return "highly_malicious"
    
    def check_urlscan(self, url: str, submit: bool = False) -> Dict:
        """
        Query URLScan.io for URL analysis.
        
        Args:
            url: URL to check
            submit: If True, submit new scan if not found
            
        Returns:
            Dict with URLScan results
        """
        if not self.urlscan_api_key:
            return {"error": "URLScan API key not configured"}
        
        # Check cache
        cached = self._get_cached(url, "urlscan")
        if cached:
            return cached
        
        try:
            # First try to search existing results
            search_url = f"https://urlscan.io/api/v1/search/?q=page.url:{url}"
            headers = {
                'API-Key': self.urlscan_api_key,
                'User-Agent': 'Mozilla/5.0'
            }
            
            response = requests.get(search_url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
                
                if results:
                    # Use most recent result
                    scan = results[0]
                    result = {
                        "service": "URLScan.io",
                        "url": url,
                        "scan_id": scan.get('_id'),
                        "scan_time": scan.get('task', {}).get('time'),
                        "malicious": scan.get('verdicts', {}).get('overall', {}).get('malicious', False),
                        "suspicious": scan.get('verdicts', {}).get('overall', {}).get('suspicious', False),
                        "score": scan.get('verdicts', {}).get('overall', {}).get('score', 0),
                        "categories": scan.get('verdicts', {}).get('overall', {}).get('categories', []),
                        "country": scan.get('page', {}).get('country'),
                        "server": scan.get('page', {}).get('server'),
                        "report_url": f"https://urlscan.io/result/{scan.get('_id')}/",
                        "screenshot": scan.get('task', {}).get('screenshotURL'),
                        "detected": scan.get('verdicts', {}).get('overall', {}).get('malicious', False)
                    }
                    
                    self._set_cached(url, "urlscan", result)
                    logging.info(f"[URLScan] {url} - Malicious: {result['malicious']}")
                    return result
                
                # No existing scan found
                if submit:
                    return self._submit_urlscan(url)
                else:
                    return {"error": "No existing scan found", "service": "URLScan.io"}
                    
            return {"error": f"URLScan search error: {response.status_code}"}
            
        except requests.exceptions.RequestException as e:
            logging.error(f"[URLScan] Request error: {e}")
            return {"error": f"Request failed: {str(e)}"}
        except Exception as e:
            logging.error(f"[URLScan] Unexpected error: {e}")
            return {"error": str(e)}
    
    def _submit_urlscan(self, url: str) -> Dict:
        """Submit new URL to URLScan for analysis."""
        try:
            headers = {
                'API-Key': self.urlscan_api_key,
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0'
            }
            
            data = {
                'url': url,
                'visibility': 'public',
                'tags': ['phishing-detection']
            }
            
            response = requests.post(
                self.urlscan_submit,
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result_data = response.json()
                return {
                    "service": "URLScan.io",
                    "url": url,
                    "status": "submitted",
                    "scan_id": result_data.get('uuid'),
                    "api_endpoint": result_data.get('api'),
                    "result_url": result_data.get('result'),
                    "message": "Scan submitted, check result URL in ~30 seconds"
                }
            else:
                return {"error": f"URLScan submission failed: {response.status_code}"}
                
        except Exception as e:
            return {"error": f"Submission failed: {str(e)}"}
    
    def check_abuseipdb(self, ip_or_domain: str) -> Dict:
        """
        Query AbuseIPDB for IP/domain reputation.
        
        Returns:
            Dict with abuse confidence score and reports
        """
        if not self.abuseipdb_api_key:
            return {"error": "AbuseIPDB API key not configured"}
        
        # Extract IP/domain from URL if needed
        if '://' in ip_or_domain:
            parsed = urlparse(ip_or_domain)
            ip_or_domain = parsed.netloc or parsed.path
        
        # Check cache
        cached = self._get_cached(ip_or_domain, "abuseipdb")
        if cached:
            return cached
        
        try:
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_or_domain,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            
            response = requests.get(
                self.abuseipdb_url,
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                data = data.get('data', {})
                
                result = {
                    "service": "AbuseIPDB",
                    "ip_address": data.get('ipAddress'),
                    "abuse_confidence": data.get('abuseConfidencePercentage', 0),
                    "country": data.get('countryCode'),
                    "usage_type": data.get('usageType'),
                    "isp": data.get('isp'),
                    "total_reports": data.get('totalReports', 0),
                    "last_reported": data.get('lastReportedAt'),
                    "detected": data.get('abuseConfidencePercentage', 0) > 25,
                    "threat_level": self._abuseipdb_threat_level(data.get('abuseConfidencePercentage', 0))
                }
                
                self._set_cached(ip_or_domain, "abuseipdb", result)
                logging.info(f"[AbuseIPDB] {ip_or_domain} - Confidence: {result['abuse_confidence']}%")
                return result
                
            elif response.status_code == 401:
                return {"error": "AbuseIPDB API key invalid"}
            else:
                return {"error": f"AbuseIPDB API error: {response.status_code}"}
                
        except requests.exceptions.RequestException as e:
            logging.error(f"[AbuseIPDB] Request error: {e}")
            return {"error": f"Request failed: {str(e)}"}
        except Exception as e:
            logging.error(f"[AbuseIPDB] Unexpected error: {e}")
            return {"error": str(e)}
    
    def _abuseipdb_threat_level(self, confidence: int) -> str:
        """Determine threat level based on AbuseIPDB confidence."""
        if confidence == 0:
            return "clean"
        elif confidence <= 25:
            return "suspicious"
        elif confidence <= 50:
            return "malicious"
        else:
            return "highly_malicious"
    
    def check_all(self, url: str) -> Dict:
        """
        Query all available threat intelligence services.
        
        Returns:
            Combined results from all services
        """
        logging.info(f"[THREAT INTEL] Checking all services for: {url}")
        
        results = {
            "url": url,
            "domain": urlparse(url).netloc,
            "services_queried": [],
            "services_detected": [],
            "overall_threat_level": "unknown",
            "combined_score": 0,
            "details": {}
        }
        
        # Check VirusTotal
        vt_result = self.check_virustotal(url)
        results["details"]["virustotal"] = vt_result
        if "error" not in vt_result:
            results["services_queried"].append("virustotal")
            if vt_result.get("detected"):
                results["services_detected"].append("virustotal")
        
        # Check URLScan (existing results only, don't submit new)
        us_result = self.check_urlscan(url, submit=False)
        results["details"]["urlscan"] = us_result
        if "error" not in us_result or "No existing scan" not in str(us_result.get("error", "")):
            results["services_queried"].append("urlscan")
            if us_result.get("detected"):
                results["services_detected"].append("urlscan")
        
        # Check AbuseIPDB (extract domain/IP)
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        if domain:
            ab_result = self.check_abuseipdb(domain)
            results["details"]["abuseipdb"] = ab_result
            if "error" not in ab_result:
                results["services_queried"].append("abuseipdb")
                if ab_result.get("detected"):
                    results["services_detected"].append("abuseipdb")
        
        # Calculate overall threat level
        results["overall_threat_level"] = self._calculate_overall_threat(results["details"])
        results["combined_score"] = self._calculate_combined_score(results["details"])
        results["is_malicious"] = len(results["services_detected"]) > 0
        
        logging.info(f"[THREAT INTEL] Results: {len(results['services_detected'])}/{len(results['services_queried'])} services flagged")
        
        return results
    
    def _calculate_overall_threat(self, details: Dict) -> str:
        """Calculate overall threat level from all services."""
        threat_levels = []
        
        for service, result in details.items():
            if "error" in result:
                continue
            if "threat_level" in result:
                threat_levels.append(result["threat_level"])
            elif result.get("detected"):
                threat_levels.append("malicious")
        
        if not threat_levels:
            return "unknown"
        
        # Priority order
        if "highly_malicious" in threat_levels:
            return "highly_malicious"
        elif "malicious" in threat_levels:
            return "malicious"
        elif "suspicious" in threat_levels:
            return "suspicious"
        else:
            return "clean"
    
    def _calculate_combined_score(self, details: Dict) -> int:
        """Calculate combined risk score (0-100) from all services."""
        score = 0
        
        # VirusTotal contribution (0-40 points)
        vt = details.get("virustotal", {})
        if "error" not in vt:
            positives = vt.get("positives", 0)
            total = max(vt.get("total", 1), 1)
            score += (positives / total) * 40
        
        # URLScan contribution (0-30 points)
        us = details.get("urlscan", {})
        if "error" not in us:
            if us.get("malicious"):
                score += 30
            elif us.get("suspicious"):
                score += 15
            else:
                score += us.get("score", 0) * 3  # Max 30
        
        # AbuseIPDB contribution (0-30 points)
        ab = details.get("abuseipdb", {})
        if "error" not in ab:
            confidence = ab.get("abuse_confidence", 0)
            score += (confidence / 100) * 30
        
        return min(int(score), 100)


# Singleton instance
threat_intel = ThreatIntelligence()


def check_url(url: str) -> Dict:
    """Convenience function to check a URL against all threat intel services."""
    return threat_intel.check_all(url)
