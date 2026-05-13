import unittest
import os
import sys

# Add root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.socialengineering_engine import SocialEngine

class TestSocialForensics(unittest.TestCase):
    def setUp(self):
        self.engine = SocialEngine()
        self.test_scenarios = [
            {
                "desc": "Punycode (Homograph) Attack",
                "url": "https://xn--googl-pma.com", # Looks like google.com with Cyrillic 'e'
                "expected_puny": True,
                "expected_brand": "None", # Brand match logic uses literal string
                "min_risk": 80
            },
            {
                "desc": "Social Media Mimicry (Subdomain)",
                "url": "https://instagram.security-update.io",
                "expected_puny": False,
                "expected_brand": "instagram",
                "min_risk": 40
            },
            {
                "desc": "Combo Attack (Brand + Keyword)",
                "url": "http://facebook-login-verify.xyz",
                "expected_puny": False,
                "expected_brand": "facebook",
                "min_risk": 90 # 40 (Brand) + 30 (Keywords) + 20 (TLD)
            },
            {
                "desc": "LinkedIn Phish with .zip TLD",
                "url": "https://linkedin-jobs.zip",
                "expected_puny": False,
                "expected_brand": "linkedin",
                "min_risk": 60 # 40 (Brand) + 20 (TLD)
            },
            {
                "desc": "Legitimate Social Link",
                "url": "https://www.instagram.com/p/abc123",
                "expected_puny": False,
                "expected_brand": "None", # engine marks as legit
                "min_risk": 0
            },
            {
                "desc": "Cyrillic Homograph (Raw Unicode)",
                "url": "https://аррӏе.com", # apple.com with Cyrillic characters
                "expected_puny": True,
                "expected_brand": "None",
                "min_risk": 80
            }
        ]

    def test_social_bulk_forensics(self):
        """Test various social media phishing scenarios."""
        print("\n" + "="*100)
        print(f"{'SCENARIO':<30} | {'RISK':<5} | {'PUNY':<5} | {'BRAND':<12} | {'URL'}")
        print("-" * 100)

        passed_count = 0
        for scenario in self.test_scenarios:
            res = self.engine.analyze(scenario['url'])
            
            risk = res['calculated_risk']
            puny = res['punycode_detected']
            brand = res['brand_impersonation']
            
            # Extract brand name for display
            brand_display = "None"
            if "Using '" in brand:
                brand_display = brand.split("'")[1]
            
            # Use ASCII-safe URL for printing to avoid Windows terminal encoding issues
            safe_url = scenario['url'].encode('ascii', 'replace').decode()
            
            print(f"{scenario['desc']:<30} | {risk:<5} | {str(puny):<5} | {brand_display:<12} | {safe_url}")
            
            # Verifications
            self.assertEqual(puny, scenario['expected_puny'], f"Punycode mismatch for {scenario['desc']}")
            if scenario['expected_brand'] != "None":
                self.assertIn(scenario['expected_brand'], brand, f"Brand mismatch for {scenario['desc']}")
            
            self.assertGreaterEqual(risk, scenario['min_risk'], f"Risk too low for {scenario['desc']}")
            passed_count += 1

        accuracy = (passed_count / len(self.test_scenarios)) * 100
        print("="*100)
        print(f"SOCIAL FORENSIC ACCURACY: {accuracy:.2f}% ({passed_count}/{len(self.test_scenarios)})")

if __name__ == '__main__':
    unittest.main(verbosity=2)
