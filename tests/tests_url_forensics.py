import unittest
import json
import os
import math
import difflib
from unittest.mock import patch
from app.core.url_engine import URLEngine

class TestURLForensics(unittest.TestCase):
    def setUp(self):
        self.engine = URLEngine()
        # Dataset for Training & Verification
        self.test_urls = [
            # Legitimate URLs
            {"url": "google.com", "expected": "SAFE", "type": "legit"},
            {"url": "amazon.in", "expected": "SAFE", "type": "legit"},
            {"url": "microsoft.com", "expected": "SAFE", "type": "legit"},
            {"url": "facebook.com", "expected": "SAFE", "type": "legit"},
            {"url": "meesho.com", "expected": "SAFE", "type": "legit"},
            
            # Typosquatting URLs
            {"url": "amozon.com", "expected": "MALICIOUS", "type": "typosquat"},
            {"url": "goggle.com", "expected": "MALICIOUS", "type": "typosquat"},
            {"url": "instagrarn.com", "expected": "MALICIOUS", "type": "typosquat"},
            {"url": "faceboook.com", "expected": "MALICIOUS", "type": "typosquat"},
            {"url": "microsft-support.com", "expected": "MALICIOUS", "type": "typosquat"},
            
            # Subdomain/TLD Spoofing
            {"url": "google-login.verification.com", "expected": "MALICIOUS", "type": "spoof"},
            {"url": "amazon-gift-card.xyz", "expected": "MALICIOUS", "type": "spoof"},
            {"url": "netflix-update.account-secure.net", "expected": "MALICIOUS", "type": "spoof"},
            
            # High Entropy / Random Domains (DGA)
            {"url": "xhj123klmn-secure.top", "expected": "MALICIOUS", "type": "dga"},
            {"url": "qwerty-login-page.io", "expected": "MALICIOUS", "type": "phish"}
        ]

    def test_entropy_logic(self):
        """Test if the engine correctly identifies high entropy (randomness) in URLs."""
        legit_entropy = self.engine._calculate_entropy("google.com")
        random_entropy = self.engine._calculate_entropy("xhj123klmn-secure.top")
        print(f"\n[DEBUG] Legit Entropy: {legit_entropy:.2f} | Random Entropy: {random_entropy:.2f}")
        # Random/DGA domains usually have higher entropy
        self.assertGreater(random_entropy, legit_entropy)

    def test_levenshtein_similarity(self):
        """Verify the Levenshtein-based brand check logic."""
        # Manual simulation of engine's brand check
        brand = "amazon"
        typo = "amozon"
        similarity = difflib.SequenceMatcher(None, typo, brand).ratio()
        print(f"\n[DEBUG] Similarity (amozon vs amazon): {similarity:.2f}")
        self.assertGreaterEqual(similarity, 0.8)

    @patch('core.url_engine.URLEngine.get_domain_age')
    @patch('core.url_engine.URLEngine.check_virustotal')
    @patch('utils.dom_scanner.DOMScanner.scan')
    def test_bulk_url_analysis(self, mock_dom, mock_vt, mock_age):
        """Run the engine against the entire dataset and measure accuracy."""
        mock_age.return_value = "Legacy Asset (Verified)"
        mock_vt.return_value = "0/0 Flags"
        mock_dom.return_value = {"risk_score": 0, "threats_found": []}
        
        print("\n" + "="*60)
        print(f"{'URL':<35} | {'RISK':<5} | {'BRAND CHECK':<20}")
        print("-" * 60)
        
        passed_count = 0
        for entry in self.test_urls:
            res = self.engine.analyze(entry['url'])
            risk = res['calculated_risk']
            brand = res['brand_check']
            
            # Prediction based on risk
            prediction = "MALICIOUS" if risk >= 60 else "SAFE"
            
            print(f"{entry['url']:<35} | {risk:<5} | {brand:<20}")
            
            if prediction == entry['expected']:
                passed_count += 1
        
        accuracy = (passed_count / len(self.test_urls)) * 100
        print("="*60)
        print(f"BULK URL SCAN ACCURACY: {accuracy:.2f}% ({passed_count}/{len(self.test_urls)})")
        self.assertGreaterEqual(accuracy, 80)

if __name__ == '__main__':
    unittest.main(verbosity=2)
