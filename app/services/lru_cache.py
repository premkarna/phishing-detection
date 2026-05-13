import logging
import hashlib
from collections import OrderedDict

class ThreatCache:
    def __init__(self, max_size: int = 5000): # Increased size for 1000+ users
        self.cache = OrderedDict()
        self.max_size = max_size
        logging.info(f"[+] HIGH-AVAILABILITY CACHE: Memory allocated for {self.max_size} sessions")

    @staticmethod
    def generate_hash(payload: str) -> str:
        """Converts the payload into a secure SHA-256 hash string."""
        # We lowercase it to avoid redundant scans for Google.com vs google.com
        return hashlib.sha256(str(payload).lower().strip().encode('utf-8')).hexdigest()

    def get(self, payload_hash: str):
        """Fetches from cache. Moves the fetched item to the end (Most Recently Used)."""
        if payload_hash in self.cache:
            self.cache.move_to_end(payload_hash)
            # Add a 'cached': True flag so UI knows it was fast
            result = self.cache[payload_hash].copy()
            result['is_cached'] = True
            logging.info("[⚡] HIGH-SPEED CACHE HIT: Returning in 0.005s.")
            return result
        return None

    def set(self, payload_hash: str, result: dict):
        """Saves to cache. If size exceeds max_size, pops the oldest (FIFO)."""
        self.cache[payload_hash] = result
        self.cache.move_to_end(payload_hash)
        
        # Memory cleanup: Delete the oldest item if limit reached
        if len(self.cache) > self.max_size:
            self.cache.popitem(last=False)

    def clear(self):
        """Purges all sessions from the cache."""
        self.cache.clear()
        logging.info("[+] SOC SYSTEM: Cache successfully purged.")

# Global instance for main.py to use
global_cache = ThreatCache()

def fetch_from_cache(payload_hash: str):
    return global_cache.get(payload_hash)