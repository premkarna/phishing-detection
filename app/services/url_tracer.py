import logging
import requests
from urllib.parse import urlparse
from typing import Dict, List, Optional


class URLTracer:
    """
    Traces URL redirections to find final destination.
    Follows HTTP redirects safely without executing malicious content.
    """
    
    def __init__(self, timeout: int = 30, max_redirects: int = 10):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.session = requests.Session()
        # Common browser headers to avoid being blocked
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Known URL shortener domains
        self.shortener_domains = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 
            'is.gd', 'cutt.ly', 'short.link', 'rb.gy', 'shorturl.at',
            'x.co', 'tr.im', 'cli.gs', 'yfrog.com', 'migre.me',
            'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr',
            'twurl.nl', 'snipurl.com', 'short.to', 'budurl.com',
            'ping.fm', 'post.ly', 'just.as', 'bkite.com', 'snipr.com',
            'dlvr.it', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly',
            'ity.im', 'q.gs', 'bc.vc', 'soo.gd', 's2r.co',
            'ouo.io', 'shorte.st', 'sh.st', 'p.pw', 'adfoc.us',
            'linkshrink.net', 'pop.adf.ly', 'v.gd', 'trib.al',
            'rebrand.ly', 'bl.ink', 'smarturl.it', 'rotf.lol'
        ]
        
        # Suspicious patterns in URLs
        self.suspicious_patterns = [
            'redirect', 'redir', 'goto', 'out', 'away', 'jump',
            'click', 'track', 'affiliate', 'clk', 'dest'
        ]
    
    def is_shortened_url(self, url: str) -> bool:
        """Check if URL uses a known shortener service."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        return any(short in domain for short in self.shortener_domains)
    
    def has_open_redirect(self, url: str) -> bool:
        """Check if URL has potential open redirect parameters."""
        parsed = urlparse(url)
        url_lower = url.lower()
        
        # Check for suspicious patterns in URL
        return any(pattern in url_lower for pattern in self.suspicious_patterns)
    
    def trace_url(self, url: str, method: str = 'HEAD') -> Dict:
        """
        Trace a URL through all redirects to find final destination.
        
        Args:
            url: The URL to trace
            method: 'HEAD' (faster, safer) or 'GET' (more reliable)
            
        Returns:
            Dictionary with trace results
        """
        logging.info(f"[URL TRACER] Starting trace for: {url}")
        
        results = {
            "original_url": url,
            "final_url": url,
            "redirect_count": 0,
            "redirect_chain": [],
            "is_shortened": self.is_shortened_url(url),
            "has_open_redirect": self.has_open_redirect(url),
            "status_code": None,
            "is_reachable": False,
            "domain_changes": 0,
            "suspicious_hops": 0,
            "error": None
        }
        
        try:
            # Use HEAD request first (lighter, doesn't download body)
            if method == 'HEAD':
                try:
                    response = self.session.head(
                        url, 
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                except requests.exceptions.RequestException:
                    # Fallback to GET if HEAD fails
                    logging.info("[URL TRACER] HEAD failed, falling back to GET")
                    response = self.session.get(
                        url,
                        timeout=self.timeout,
                        allow_redirects=True,
                        stream=True  # Don't download full content
                    )
            else:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    stream=True
                )
            
            # Build redirect chain
            previous_url = url
            previous_domain = urlparse(url).netloc.lower()
            
            for redirect in response.history:
                redirect_url = redirect.url
                redirect_domain = urlparse(redirect_url).netloc.lower()
                
                hop_info = {
                    "url": redirect_url,
                    "status_code": redirect.status_code,
                    "domain": redirect_domain,
                    "domain_changed": redirect_domain != previous_domain,
                    "is_shortener": self.is_shortened_url(redirect_url),
                    "is_suspicious": self.has_open_redirect(redirect_url)
                }
                
                results["redirect_chain"].append(hop_info)
                
                if hop_info["domain_changed"]:
                    results["domain_changes"] += 1
                    previous_domain = redirect_domain
                
                if hop_info["is_suspicious"]:
                    results["suspicious_hops"] += 1
                
                previous_url = redirect_url
            
            # Final destination
            final_url = response.url
            results["final_url"] = final_url
            results["status_code"] = response.status_code
            results["is_reachable"] = 200 <= response.status_code < 400
            results["redirect_count"] = len(results["redirect_chain"])
            
            # Check if final destination is different from original
            final_domain = urlparse(final_url).netloc.lower()
            original_domain = urlparse(url).netloc.lower()
            
            results["domain_changed"] = final_domain != original_domain
            results["final_domain"] = final_domain
            
            logging.info(f"[URL TRACER] Trace complete. Redirects: {results['redirect_count']}, Final: {final_url}")
            
            # Close response if it was a GET with stream=True
            if hasattr(response, 'close'):
                response.close()
                
        except requests.exceptions.Timeout:
            results["error"] = "Request timed out"
            logging.warning(f"[URL TRACER] Timeout tracing: {url}")
            
        except requests.exceptions.TooManyRedirects:
            results["error"] = f"Too many redirects (max: {self.max_redirects})"
            logging.warning(f"[URL TRACER] Redirect loop detected: {url}")
            
        except requests.exceptions.RequestException as e:
            results["error"] = f"Request failed: {str(e)}"
            logging.error(f"[URL TRACER] Request error: {e}")
            
        except Exception as e:
            results["error"] = f"Unexpected error: {str(e)}"
            logging.error(f"[URL TRACER] Unexpected error: {e}")
        
        return results
    
    def get_risk_score(self, trace_results: Dict) -> int:
        """
        Calculate risk score based on trace results.
        
        Returns:
            Risk score (0-100)
        """
        score = 0
        
        # Shortened URL is inherently suspicious
        if trace_results["is_shortened"]:
            score += 20
        
        # Open redirect parameters
        if trace_results["has_open_redirect"]:
            score += 15
        
        # Multiple redirects
        redirect_count = trace_results["redirect_count"]
        if redirect_count > 5:
            score += 30
        elif redirect_count > 2:
            score += 15
        elif redirect_count > 0:
            score += 5
        
        # Domain changes during redirect
        domain_changes = trace_results.get("domain_changes", 0)
        if domain_changes > 2:
            score += 25
        elif domain_changes > 0:
            score += 10
        
        # Suspicious redirect hops
        suspicious_hops = trace_results.get("suspicious_hops", 0)
        score += suspicious_hops * 10
        
        # Unreachable final destination
        if not trace_results["is_reachable"] and trace_results["error"]:
            score += 10
        
        # Check final URL for suspicious patterns
        final_url = trace_results["final_url"].lower()
        suspicious_final = ['phishing', 'malware', 'virus', 'hack', 'steal']
        if any(word in final_url for word in suspicious_final):
            score += 20
        
        return min(score, 100)
    
    def quick_check(self, url: str) -> str:
        """Quick one-liner to get final destination URL."""
        result = self.trace_url(url, method='HEAD')
        return result["final_url"] if not result["error"] else url


# Singleton instance for easy import
tracer = URLTracer()


def trace_url(url: str) -> Dict:
    """Convenience function to trace a URL."""
    return tracer.trace_url(url)


def unshorten_url(url: str) -> str:
    """Convenience function to get final destination."""
    return tracer.quick_check(url)
