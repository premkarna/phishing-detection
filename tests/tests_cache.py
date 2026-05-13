import unittest
import time
import json
from app.services.lru_cache import ThreatCache

class TestLRUCache(unittest.TestCase):

    def setUp(self):
        # Test kosam small size cache create chesthunnam
        self.cache_size = 3
        self.cache = ThreatCache(max_size=self.cache_size)

    def test_cache_set_get(self):
        """Verify basic set and get functionality."""
        payload = "google.com"
        result = {"verdict": "SAFE", "risk": 0}
        p_hash = self.cache.generate_hash(payload)
        
        self.cache.set(p_hash, result)
        cached_res = self.cache.get(p_hash)
        
        self.assertIsNotNone(cached_res)
        self.assertEqual(cached_res['verdict'], "SAFE")
        self.assertTrue(cached_res['is_cached'])

    def test_cache_miss(self):
        """Verify behavior on cache miss."""
        p_hash = self.cache.generate_hash("unknown.com")
        self.assertIsNone(self.cache.get(p_hash))

    def test_lru_eviction(self):
        """Verify Least Recently Used (LRU) eviction logic."""
        # 3 items add chesthunnam (Limit: 3)
        items = ["site1.com", "site2.com", "site3.com"]
        for item in items:
            h = self.cache.generate_hash(item)
            self.cache.set(h, {"site": item})
        
        # Ippudu cache full (site1, site2, site3)
        # 4th item add chesthe, oldest (site1) evict avvali
        h4 = self.cache.generate_hash("site4.com")
        self.cache.set(h4, {"site": "site4.com"})
        
        # Site1 should be gone
        h1 = self.cache.generate_hash("site1.com")
        self.assertIsNone(self.cache.get(h1))
        
        # Site2, Site3, Site4 should still be there
        self.assertIsNotNone(self.cache.get(self.cache.generate_hash("site2.com")))
        self.assertIsNotNone(self.cache.get(self.cache.generate_hash("site3.com")))
        self.assertIsNotNone(self.cache.get(h4))

    def test_mru_update(self):
        """Verify that 'get' updates the item to Most Recently Used (MRU)."""
        items = ["site1.com", "site2.com", "site3.com"]
        for item in items:
            h = self.cache.generate_hash(item)
            self.cache.set(h, {"site": item})
            
        # Access site1 to make it MRU
        h1 = self.cache.generate_hash("site1.com")
        self.cache.get(h1)
        
        # Ippudu site2 oldest avvali. New item add chesthe site2 evict avvali.
        h4 = self.cache.generate_hash("site4.com")
        self.cache.set(h4, {"site": "site4.com"})
        
        # Site2 should be gone, Site1 should remain
        self.assertIsNone(self.cache.get(self.cache.generate_hash("site2.com")))
        self.assertIsNotNone(self.cache.get(h1))

    def test_performance_speed(self):
        """Verify the 0.1s performance target (actual target is < 0.01s)."""
        payload = "speed-test.com"
        result = {"data": "fast"}
        p_hash = self.cache.generate_hash(payload)
        self.cache.set(p_hash, result)
        
        start_time = time.perf_counter()
        self.cache.get(p_hash)
        end_time = time.perf_counter()
        
        latency = end_time - start_time
        print(f"\n[DEBUG] Cache Latency: {latency:.6f}s")
        self.assertLess(latency, 0.1, "Cache latency exceeds 0.1s target!")

    def test_case_insensitivity(self):
        """Verify that GOOGLE.com and google.com share the same hash."""
        h1 = self.cache.generate_hash("GOOGLE.com")
        h2 = self.cache.generate_hash("google.com ")
        self.assertEqual(h1, h2)

if __name__ == '__main__':
    unittest.main(verbosity=2)
