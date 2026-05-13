import logging
import whois
import ssl
import socket
import requests
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse
import re


class DomainHeuristics:
    """
    Performs heuristic analysis on domains to detect phishing indicators.
    Checks domain age, SSL certificate, suspicious patterns, and more.
    """
    
    def __init__(self):
        # Suspicious TLDs commonly used for phishing
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains
            '.xyz', '.top', '.club', '.online', '.site',  # Cheap/new TLDs
            '.work', '.click', '.link', '.download', '.racing',
            '.country', '.stream', '.gdn', '.men', '.loan'
        ]
        
        # Suspicious keywords in domain names
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'update',
            'confirm', 'validate', 'authenticate', 'security', 'banking',
            'password', 'credential', 'wallet', 'payment', 'billing',
            'recovery', 'unlock', 'restore', 'suspend', 'limited',
            'alert', 'warning', 'urgent', 'important', 'immediate'
        ]
        
        # Trusted/benign TLDs
        self.trusted_tlds = [
            '.gov', '.edu', '.mil',  # Government/Education/Military
        ]
        
        # Risk thresholds for domain age (in days)
        self.age_thresholds = {
            "critical": 3,      # 0-3 days: Very high risk
            "high": 7,        # 4-7 days: High risk
            "suspicious": 30, # 8-30 days: Suspicious
            "moderate": 90,   # 31-90 days: Moderate risk
            "low": 180        # 91-180 days: Low risk
        }
    
    def _extract_domain(self, url: str) -> str:
        """Extract clean domain from URL."""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
            
        return domain.lower()
    
    def check_domain_age(self, url: str) -> Dict:
        """
        Check domain registration date and calculate age.
        
        Returns:
            Dict with creation_date, age_days, and risk assessment
        """
        domain = self._extract_domain(url)
        
        result = {
            "domain": domain,
            "creation_date": None,
            "age_days": None,
            "age_readable": None,
            "registrar": None,
            "expiration_date": None,
            "is_recent": False,
            "risk_level": "unknown",
            "risk_score": 0,
            "error": None
        }
        
        try:
            # Query WHOIS information
            domain_info = whois.whois(domain)
            
            # Extract creation date (handle different formats)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            expiration_date = domain_info.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            if creation_date:
                # Ensure datetime object
                if isinstance(creation_date, str):
                    try:
                        creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                    except ValueError:
                        creation_date = datetime.strptime(creation_date.split(' ')[0], '%Y-%m-%d')
                
                # Calculate age
                now = datetime.now()
                age_days = (now - creation_date).days
                
                result["creation_date"] = creation_date.strftime('%Y-%m-%d')
                result["age_days"] = age_days
                result["age_readable"] = self._format_age(age_days)
                result["registrar"] = domain_info.registrar
                
                if expiration_date:
                    if isinstance(expiration_date, str):
                        try:
                            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
                        except ValueError:
                            expiration_date = None
                    if expiration_date:
                        result["expiration_date"] = expiration_date.strftime('%Y-%m-%d')
                
                # Determine risk based on age
                if age_days <= self.age_thresholds["critical"]:
                    result["is_recent"] = True
                    result["risk_level"] = "critical"
                    result["risk_score"] = 50
                    logging.critical(f"[!] CRITICAL: Domain '{domain}' is only {age_days} days old!")
                elif age_days <= self.age_thresholds["high"]:
                    result["is_recent"] = True
                    result["risk_level"] = "high"
                    result["risk_score"] = 40
                    logging.warning(f"[!] WARNING: Domain '{domain}' is only {age_days} days old!")
                elif age_days <= self.age_thresholds["suspicious"]:
                    result["is_recent"] = True
                    result["risk_level"] = "suspicious"
                    result["risk_score"] = 25
                    logging.warning(f"[!] Domain '{domain}' is {age_days} days old - relatively new")
                elif age_days <= self.age_thresholds["moderate"]:
                    result["risk_level"] = "moderate"
                    result["risk_score"] = 10
                elif age_days <= self.age_thresholds["low"]:
                    result["risk_level"] = "low"
                    result["risk_score"] = 5
                else:
                    result["risk_level"] = "established"
                    result["risk_score"] = 0
                    
                logging.info(f"[HEURISTICS] Domain '{domain}' age: {result['age_readable']} ({age_days} days)")
            else:
                result["error"] = "Could not determine creation date"
                logging.warning(f"[HEURISTICS] Could not get creation date for: {domain}")
                
        except Exception as e:
            # Handle WHOIS lookup failures (domain not found, connection issues, etc.)
            error_str = str(e).lower()
            if "not found" in error_str or "no match" in error_str or "domain" in error_str:
                result["error"] = "Domain not found in WHOIS - possibly very recent registration"
                result["risk_level"] = "critical"
                result["risk_score"] = 60  # Higher risk if not in WHOIS
                logging.critical(f"[!] CRITICAL: Domain '{domain}' not found in WHOIS - extremely suspicious!")
            else:
                result["error"] = f"WHOIS lookup failed: {str(e)}"
                logging.error(f"[HEURISTICS] WHOIS error for {domain}: {e}")
        
        return result
    
    def _format_age(self, days: int) -> str:
        """Convert days to human readable format."""
        if days < 1:
            return "less than 1 day"
        elif days == 1:
            return "1 day"
        elif days < 30:
            return f"{days} days"
        elif days < 365:
            months = days // 30
            return f"{months} month{'s' if months > 1 else ''}"
        else:
            years = days // 365
            remaining_days = days % 365
            months = remaining_days // 30
            if months > 0:
                return f"{years} year{'s' if years > 1 else ''}, {months} month{'s' if months > 1 else ''}"
            return f"{years} year{'s' if years > 1 else ''}"
    
    def check_ssl_certificate(self, url: str) -> Dict:
        """
        Check SSL certificate information for the domain.
        
        Returns:
            Dict with SSL certificate details and risk assessment
        """
        domain = self._extract_domain(url)
        
        result = {
            "domain": domain,
            "has_ssl": False,
            "issuer": None,
            "issued_date": None,
            "expiry_date": None,
            "days_until_expiry": None,
            "is_self_signed": False,
            "is_valid": False,
            "risk_score": 0,
            "error": None
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Connect and get certificate
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    result["has_ssl"] = True
                    result["is_valid"] = True
                    result["ssl_version"] = version
                    result["cipher"] = cipher[0] if cipher else None
                    
                    # Extract certificate info
                    issuer = cert.get('issuer')
                    if issuer:
                        # Parse issuer tuple
                        for part in issuer:
                            for key, value in part:
                                if key == 'organizationName':
                                    result["issuer"] = value
                                    break
                    
                    # Get dates
                    not_before = cert.get('notBefore')
                    not_after = cert.get('notAfter')
                    
                    if not_before and not_after:
                        # Parse dates
                        issued_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        
                        result["issued_date"] = issued_date.strftime('%Y-%m-%d')
                        result["expiry_date"] = expiry_date.strftime('%Y-%m-%d')
                        
                        # Calculate days until expiry
                        now = datetime.now()
                        days_until = (expiry_date - now).days
                        result["days_until_expiry"] = days_until
                        
                        # Check if certificate is recent (possible sign of phishing)
                        cert_age_days = (now - issued_date).days
                        if cert_age_days <= 7:
                            logging.warning(f"[!] SSL certificate for '{domain}' is only {cert_age_days} days old")
                            result["risk_score"] += 10
                        
                        # Check if about to expire
                        if days_until < 7:
                            result["risk_score"] += 5
                            logging.warning(f"[!] SSL certificate for '{domain}' expires in {days_until} days")
                        
                        # Check for suspicious issuers (self-signed)
                        if result["issuer"] and "self" in result["issuer"].lower():
                            result["is_self_signed"] = True
                            result["risk_score"] += 20
                            logging.warning(f"[!] Self-signed certificate detected for: {domain}")
                    
                    logging.info(f"[HEURISTICS] SSL OK for '{domain}' - Issuer: {result['issuer']}")
                    
        except ssl.SSLError as e:
            result["error"] = f"SSL Error: {str(e)}"
            result["risk_score"] = 15
            logging.warning(f"[!] SSL error for '{domain}': {e}")
            
        except socket.timeout:
            result["error"] = "Connection timeout"
            result["risk_score"] = 10
            logging.warning(f"[!] SSL check timeout for: {domain}")
            
        except socket.error as e:
            # No SSL support or connection refused
            result["error"] = f"No SSL/TLS support: {str(e)}"
            result["risk_score"] = 25  # Higher risk for no SSL
            logging.warning(f"[!] No SSL support on '{domain}' - HTTP only (high risk)")
            
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
            logging.error(f"[HEURISTICS] SSL check error: {e}")
        
        return result
    
    def analyze_domain_structure(self, url: str) -> Dict:
        """
        Analyze domain structure for phishing indicators.
        
        Returns:
            Dict with structural analysis and risk indicators
        """
        domain = self._extract_domain(url)
        parsed = urlparse(url)
        
        result = {
            "domain": domain,
            "tld": None,
            "subdomain_count": 0,
            "has_suspicious_tld": False,
            "has_trusted_tld": False,
            "has_suspicious_keywords": False,
            "suspicious_patterns": [],
            "is_ip_address": False,
            "risk_score": 0
        }
        
        try:
            # Check if it's an IP address
            ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
            if ip_pattern.match(domain):
                result["is_ip_address"] = True
                result["risk_score"] += 30
                result["suspicious_patterns"].append("ip_address_direct")
                logging.warning(f"[!] Direct IP address detected: {domain}")
                return result
            
            # Extract TLD
            parts = domain.split('.')
            if len(parts) >= 2:
                tld = '.' + parts[-1]
                result["tld"] = tld
                
                # Check suspicious TLD
                if any(domain.endswith(stld) for stld in self.suspicious_tlds):
                    result["has_suspicious_tld"] = True
                    result["risk_score"] += 15
                    result["suspicious_patterns"].append("suspicious_tld")
                    logging.warning(f"[!] Suspicious TLD detected: {tld}")
                
                # Check trusted TLD
                if any(domain.endswith(ttld) for ttld in self.trusted_tlds):
                    result["has_trusted_tld"] = True
                    result["risk_score"] -= 10  # Reduce risk for trusted TLDs
                    
                # Count subdomains
                subdomain_count = len(parts) - 2  # Subtract domain and TLD
                result["subdomain_count"] = max(0, subdomain_count)
                
                if subdomain_count > 3:
                    result["risk_score"] += 10
                    result["suspicious_patterns"].append("excessive_subdomains")
                    logging.warning(f"[!] Excessive subdomains ({subdomain_count}): {domain}")
            
            # Check for suspicious keywords
            domain_lower = domain.lower()
            found_keywords = []
            for keyword in self.suspicious_keywords:
                if keyword in domain_lower:
                    found_keywords.append(keyword)
                    result["risk_score"] += 5
            
            if found_keywords:
                result["has_suspicious_keywords"] = True
                result["suspicious_patterns"].append("suspicious_keywords")
                logging.warning(f"[!] Suspicious keywords in domain: {', '.join(found_keywords)}")
            
            # Check for brand impersonation patterns
            brand_patterns = [
                (r'.*-google-.*', 'google'),
                (r'.*-facebook-.*', 'facebook'),
                (r'.*-apple-.*', 'apple'),
                (r'.*-microsoft-.*', 'microsoft'),
                (r'.*-amazon-.*', 'amazon'),
                (r'.*-paypal-.*', 'paypal'),
                (r'.*-netflix-.*', 'netflix'),
            ]
            
            for pattern, brand in brand_patterns:
                if re.match(pattern, domain_lower):
                    result["risk_score"] += 25
                    result["suspicious_patterns"].append(f"possible_{brand}_impersonation")
                    logging.critical(f"[!] CRITICAL: Possible {brand} impersonation: {domain}")
                    break
            
            # Check for character substitution (homograph attacks)
            if '0' in domain_lower.replace('google', '') or '1' in domain_lower:
                if any(brand in domain_lower for brand in ['google', 'facebook', 'amazon', 'apple', 'paypal']):
                    result["risk_score"] += 30
                    result["suspicious_patterns"].append("character_substitution")
                    logging.critical(f"[!] CRITICAL: Character substitution attack detected: {domain}")
            
            logging.info(f"[HEURISTICS] Domain structure analysis complete for: {domain}")
            
        except Exception as e:
            logging.error(f"[HEURISTICS] Domain structure analysis error: {e}")
        
        return result
    
    def full_analysis(self, url: str) -> Dict:
        """
        Perform complete heuristic analysis on a URL.
        
        Returns:
            Combined results from all heuristic checks
        """
        logging.info(f"[HEURISTICS] Starting full analysis for: {url}")
        
        results = {
            "url": url,
            "domain": self._extract_domain(url),
            "overall_risk_score": 0,
            "risk_level": "unknown",
            "checks_performed": [],
            "red_flags": [],
            "details": {}
        }
        
        # Domain age check
        age_check = self.check_domain_age(url)
        results["details"]["domain_age"] = age_check
        results["checks_performed"].append("domain_age")
        results["overall_risk_score"] += age_check.get("risk_score", 0)
        
        if age_check.get("is_recent"):
            results["red_flags"].append(f"domain_only_{age_check['age_days']}_days_old")
        
        if age_check.get("error") and "not found" in str(age_check.get("error", "")).lower():
            results["red_flags"].append("domain_not_in_whois")
        
        # SSL certificate check
        ssl_check = self.check_ssl_certificate(url)
        results["details"]["ssl_certificate"] = ssl_check
        results["checks_performed"].append("ssl_certificate")
        results["overall_risk_score"] += ssl_check.get("risk_score", 0)
        
        if not ssl_check.get("has_ssl"):
            results["red_flags"].append("no_ssl_certificate")
        if ssl_check.get("is_self_signed"):
            results["red_flags"].append("self_signed_certificate")
        
        # Domain structure analysis
        structure_check = self.analyze_domain_structure(url)
        results["details"]["domain_structure"] = structure_check
        results["checks_performed"].append("domain_structure")
        results["overall_risk_score"] += structure_check.get("risk_score", 0)
        
        if structure_check.get("has_suspicious_tld"):
            results["red_flags"].append("suspicious_tld")
        if structure_check.get("has_suspicious_keywords"):
            results["red_flags"].append("suspicious_keywords_in_domain")
        if structure_check.get("is_ip_address"):
            results["red_flags"].append("ip_address_url")
        
        # Cap score at 100
        results["overall_risk_score"] = min(results["overall_risk_score"], 100)
        
        # Determine overall risk level
        score = results["overall_risk_score"]
        if score >= 70:
            results["risk_level"] = "critical"
        elif score >= 50:
            results["risk_level"] = "high"
        elif score >= 30:
            results["risk_level"] = "suspicious"
        elif score >= 15:
            results["risk_level"] = "moderate"
        else:
            results["risk_level"] = "low"
        
        logging.info(f"[HEURISTICS] Analysis complete. Risk: {results['risk_level']} ({score}/100)")
        
        return results


# Singleton instance
heuristics = DomainHeuristics()


def analyze(url: str) -> Dict:
    """Convenience function for full heuristic analysis."""
    return heuristics.full_analysis(url)
