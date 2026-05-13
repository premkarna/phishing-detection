"""
Real-time IOC Feed Integration Module
====================================
Integrates with multiple threat intelligence feeds for live IOC checking.
Supports MISP, AlienVault OTX, Abuse.ch, and custom IOC lists.
Auto-updates and caches threat data.
"""

import logging
import requests
import json
import hashlib
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import threading
import time


class IOCFeedManager:
    """
    Manages threat intelligence feeds for real-time IOC checking.
    
    Supported feeds:
    - MISP (Malware Information Sharing Platform)
    - AlienVault Open Threat Exchange (OTX)
    - URLhaus (Abuse.ch)
    - MalwareBazaar (Abuse.ch)
    - ThreatFox (Abuse.ch)
    - Custom IOC lists
    """
    
    def __init__(self, cache_duration: int = 3600):  # 1 hour default cache
        self.cache_duration = cache_duration
        self.cache_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "cache", "ioc_cache.json")
        self.last_update = None
        
        # API Keys
        self.misp_url = os.getenv('MISP_URL', '')
        self.misp_key = os.getenv('MISP_API_KEY', '')
        self.otx_key = os.getenv('OTX_API_KEY', '')
        
        # IOC Storage
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.malicious_urls: Set[str] = set()
        self.malicious_hashes: Set[str] = set()
        
        # Cache
        self.ioc_cache: Dict[str, Dict] = {}
        self.check_cache: Dict[str, tuple] = {}  # (result, timestamp)
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Load cached data
        self._load_cache()
        
        # Auto-update in background
        self._start_auto_update()
        
        logging.info("[IOC FEEDS] Manager initialized")
    
    def _start_auto_update(self):
        """Start background thread for periodic updates."""
        def update_loop():
            fail_count = 0
            while True:
                try:
                    self.update_feeds()
                    fail_count = 0
                    time.sleep(self.cache_duration)
                except Exception as e:
                    fail_count += 1
                    wait = min(300 * (2 ** (fail_count - 1)), 3600)  # Exponential backoff, max 1hr
                    logging.debug(f"[IOC FEEDS] Auto-update error (attempt {fail_count}): {e}")
                    time.sleep(wait)
        
        thread = threading.Thread(target=update_loop, daemon=True)
        thread.start()
        logging.info("[IOC FEEDS] Auto-update thread started")
    
    def update_feeds(self) -> bool:
        """
        Update all IOC feeds.
        
        Returns:
            True if successful, False otherwise
        """
        logging.info("[IOC FEEDS] Updating threat intelligence feeds...")
        
        success = False
        
        try:
            # Update URLhaus (no API key needed)
            if self._update_urlhaus():
                success = True
            
            # Update ThreatFox (no API key needed)
            if self._update_threatfox():
                success = True
            
            # Update MalwareBazaar (no API key needed)
            if self._update_malwarebazaar():
                success = True
            
            # Update OTX (if key available)
            if self.otx_key:
                if self._update_otx():
                    success = True
            
            # Update MISP (if configured)
            if self.misp_url and self.misp_key:
                if self._update_misp():
                    success = True
            
            self.last_update = datetime.now()
            self._save_cache()
            
            with self.lock:
                logging.info(f"[IOC FEEDS] Updated: {len(self.malicious_domains)} domains, "
                           f"{len(self.malicious_ips)} IPs, "
                           f"{len(self.malicious_urls)} URLs, "
                           f"{len(self.malicious_hashes)} hashes")
            
            return success
            
        except Exception as e:
            logging.error(f"[IOC FEEDS] Update failed: {e}")
            return False
    
    def _update_urlhaus(self) -> bool:
        """Update from URLhaus (Abuse.ch)."""
        try:
            url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                new_urls = 0
                
                for entry in data.get('urls', []):
                    malicious_url = entry.get('url', '').lower()
                    if malicious_url:
                        with self.lock:
                            self.malicious_urls.add(malicious_url)
                            # Also extract domain
                            domain = self._extract_domain(malicious_url)
                            if domain:
                                self.malicious_domains.add(domain)
                        new_urls += 1
                
                logging.info(f"[IOC FEEDS] URLhaus: Added {new_urls} URLs")
                return True
                
        except Exception as e:
            logging.debug(f"[IOC FEEDS] URLhaus update failed: {e}")
        
        return False
    
    def _update_threatfox(self) -> bool:
        """Update from ThreatFox (Abuse.ch)."""
        try:
            url = "https://threatfox-api.abuse.ch/api/v1/"
            payload = {
                "query": "get_iocs",
                "days": 7  # Last 7 days
            }
            
            response = requests.post(url, json=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('query_status') == 'ok':
                    new_iocs = 0
                    
                    for ioc in data.get('data', []):
                        ioc_type = ioc.get('ioc_type', '')
                        ioc_value = ioc.get('ioc', '').lower()
                        
                        with self.lock:
                            if ioc_type == 'domain':
                                self.malicious_domains.add(ioc_value)
                            elif ioc_type == 'ip:port' or ioc_type == 'ip':
                                # Extract IP without port
                                ip = ioc_value.split(':')[0]
                                self.malicious_ips.add(ip)
                            elif ioc_type == 'url':
                                self.malicious_urls.add(ioc_value)
                            elif ioc_type == 'md5_hash':
                                self.malicious_hashes.add(ioc_value)
                        
                        new_iocs += 1
                    
                    logging.info(f"[IOC FEEDS] ThreatFox: Added {new_iocs} IOCs")
                    return True
                    
        except Exception as e:
            logging.debug(f"[IOC FEEDS] ThreatFox update failed: {e}")
        
        return False
    
    def _update_malwarebazaar(self) -> bool:
        """Update from MalwareBazaar (Abuse.ch)."""
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            payload = {
                "query": "get_recent",
                "selector": "time"
            }
            
            response = requests.post(url, data=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                new_hashes = 0
                
                for sample in data.get('data', []):
                    sha256_hash = sample.get('sha256_hash', '').lower()
                    if sha256_hash:
                        with self.lock:
                            self.malicious_hashes.add(sha256_hash)
                        new_hashes += 1
                
                logging.info(f"[IOC FEEDS] MalwareBazaar: Added {new_hashes} hashes")
                return True
                
        except Exception as e:
            logging.debug(f"[IOC FEEDS] MalwareBazaar update failed: {e}")
        
        return False
    
    def _update_otx(self) -> bool:
        """Update from AlienVault OTX."""
        try:
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
            headers = {
                'X-OTX-API-KEY': self.otx_key
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                new_iocs = 0
                
                for pulse in data.get('results', []):
                    for indicator in pulse.get('indicators', []):
                        ioc_type = indicator.get('type', '')
                        ioc_value = indicator.get('indicator', '').lower()
                        
                        with self.lock:
                            if ioc_type == 'domain':
                                self.malicious_domains.add(ioc_value)
                            elif ioc_type == 'IPv4':
                                self.malicious_ips.add(ioc_value)
                            elif ioc_type == 'URL':
                                self.malicious_urls.add(ioc_value)
                            elif ioc_type == 'FileHash-SHA256':
                                self.malicious_hashes.add(ioc_value)
                        
                        new_iocs += 1
                
                logging.info(f"[IOC FEEDS] OTX: Added {new_iocs} IOCs")
                return True
                
        except Exception as e:
            logging.debug(f"[IOC FEEDS] OTX update failed: {e}")
        
        return False
    
    def _update_misp(self) -> bool:
        """Update from MISP instance."""
        try:
            url = f"{self.misp_url}/events/restSearch"
            headers = {
                'Authorization': self.misp_key,
                'Accept': 'application/json'
            }
            
            # Get events from last 7 days
            payload = {
                "returnFormat": "json",
                "timestamp": int((datetime.now() - timedelta(days=7)).timestamp()),
                "enforceWarninglist": True
            }
            
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                new_iocs = 0
                
                for event in data.get('response', []):
                    for attribute in event.get('Event', {}).get('Attribute', []):
                        attr_type = attribute.get('type', '')
                        attr_value = attribute.get('value', '').lower()
                        
                        with self.lock:
                            if attr_type in ['domain', 'hostname']:
                                self.malicious_domains.add(attr_value)
                            elif attr_type == 'ip-dst':
                                self.malicious_ips.add(attr_value)
                            elif attr_type == 'url':
                                self.malicious_urls.add(attr_value)
                            elif attr_type == 'sha256':
                                self.malicious_hashes.add(attr_value)
                        
                        new_iocs += 1
                
                logging.info(f"[IOC FEEDS] MISP: Added {new_iocs} IOCs")
                return True
                
        except Exception as e:
            logging.debug(f"[IOC FEEDS] MISP update failed: {e}")
        
        return False
    
    def check_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        """
        Check if an IOC is in threat intelligence feeds.
        
        Args:
            ioc_type: 'domain', 'ip', 'url', 'hash'
            ioc_value: The value to check
            
        Returns:
            Check result with threat intelligence data
        """
        ioc_value = ioc_value.lower().strip()
        cache_key = f"{ioc_type}:{ioc_value}"
        
        # Check cache first
        if cache_key in self.check_cache:
            result, timestamp = self.check_cache[cache_key]
            if datetime.now().timestamp() - timestamp < 300:  # 5 min cache
                return result
        
        result = {
            'ioc_type': ioc_type,
            'ioc_value': ioc_value,
            'is_malicious': False,
            'sources': [],
            'confidence': 'low',
            'last_seen': None
        }
        
        with self.lock:
            if ioc_type == 'domain':
                # Check exact match and subdomains
                if ioc_value in self.malicious_domains:
                    result['is_malicious'] = True
                    result['sources'].append('threat_feeds')
                else:
                    # Check parent domain
                    parts = ioc_value.split('.')
                    if len(parts) > 2:
                        parent = '.'.join(parts[-2:])
                        if parent in self.malicious_domains:
                            result['is_malicious'] = True
                            result['sources'].append('threat_feeds (parent domain)')
            
            elif ioc_type == 'ip':
                if ioc_value in self.malicious_ips:
                    result['is_malicious'] = True
                    result['sources'].append('threat_feeds')
            
            elif ioc_type == 'url':
                if ioc_value in self.malicious_urls:
                    result['is_malicious'] = True
                    result['sources'].append('threat_feeds')
                else:
                    # Check if domain is malicious
                    domain = self._extract_domain(ioc_value)
                    if domain and domain in self.malicious_domains:
                        result['is_malicious'] = True
                        result['sources'].append('threat_feeds (domain match)')
            
            elif ioc_type == 'hash':
                if ioc_value in self.malicious_hashes:
                    result['is_malicious'] = True
                    result['sources'].append('threat_feeds')
        
        # Set confidence
        if result['is_malicious']:
            result['confidence'] = 'high'
            logging.warning(f"[IOC FEEDS] 🚨 MATCH: {ioc_type}={ioc_value} is MALICIOUS!")
        
        # Cache result
        self.check_cache[cache_key] = (result, datetime.now().timestamp())
        
        return result
    
    def check_url(self, url: str) -> Dict:
        """Convenience method to check a URL."""
        return self.check_ioc('url', url)
    
    def check_domain(self, domain: str) -> Dict:
        """Convenience method to check a domain."""
        return self.check_ioc('domain', domain)
    
    def check_ip(self, ip: str) -> Dict:
        """Convenience method to check an IP."""
        return self.check_ioc('ip', ip)
    
    def check_hash(self, hash_value: str) -> Dict:
        """Convenience method to check a hash."""
        return self.check_ioc('hash', hash_value)
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.lower() if parsed.netloc else None
        except (ValueError, AttributeError):
            # Invalid URL format or missing attributes
            return None
    
    def get_stats(self) -> Dict:
        """Get IOC database statistics."""
        with self.lock:
            return {
                'malicious_domains': len(self.malicious_domains),
                'malicious_ips': len(self.malicious_ips),
                'malicious_urls': len(self.malicious_urls),
                'malicious_hashes': len(self.malicious_hashes),
                'last_update': self.last_update.isoformat() if self.last_update else None,
                'cache_size': len(self.check_cache)
            }
    
    def _save_cache(self):
        """Save IOC database to cache file."""
        try:
            data = {
                'domains': list(self.malicious_domains),
                'ips': list(self.malicious_ips),
                'urls': list(self.malicious_urls),
                'hashes': list(self.malicious_hashes),
                'last_update': self.last_update.isoformat() if self.last_update else None
            }
            with open(self.cache_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logging.error(f"[IOC FEEDS] Cache save failed: {e}")
    
    def _load_cache(self):
        """Load IOC database from cache file."""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                
                self.malicious_domains = set(data.get('domains', []))
                self.malicious_ips = set(data.get('ips', []))
                self.malicious_urls = set(data.get('urls', []))
                self.malicious_hashes = set(data.get('hashes', []))
                
                last_update_str = data.get('last_update')
                if last_update_str:
                    self.last_update = datetime.fromisoformat(last_update_str)
                
                logging.info(f"[IOC FEEDS] Loaded cache: {len(self.malicious_domains)} domains, "
                           f"{len(self.malicious_ips)} IPs")
        except Exception as e:
            logging.error(f"[IOC FEEDS] Cache load failed: {e}")


# Singleton
ioc_feed_manager = IOCFeedManager()


# Convenience functions
def check_malicious_domain(domain: str) -> bool:
    """Quick check if domain is malicious."""
    return ioc_feed_manager.check_domain(domain).get('is_malicious', False)

def check_malicious_url(url: str) -> bool:
    """Quick check if URL is malicious."""
    return ioc_feed_manager.check_url(url).get('is_malicious', False)

def check_malicious_ip(ip: str) -> bool:
    """Quick check if IP is malicious."""
    return ioc_feed_manager.check_ip(ip).get('is_malicious', False)
