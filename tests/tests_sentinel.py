import unittest
import json
import os
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import app, engines

class SentinelGuardianTests(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    # --- 1. CORE API TESTS ---
    def test_home_page(self):
        """Test if the SOC Dashboard loads correctly."""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Sentinel Guardian', response.data)

    def test_analyze_url_legit(self):
        """Test scanning a legitimate URL (meesho.com)."""
        payload = {"payload": "meesho.com", "vector": "url"}
        response = self.app.post('/analyze', 
                                data=json.dumps(payload),
                                content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('ai_report', data)
        # For a legit domain, risk should be low
        self.assertLess(data.get('calculated_risk', 100), 70)

    def test_analyze_url_phish(self):
        """Test scanning a typosquatting URL (amozon.com)."""
        payload = {"payload": "amozon.com", "vector": "url"}
        response = self.app.post('/analyze', 
                                data=json.dumps(payload),
                                content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('ai_report', data)
        # Should be flagged as MALICIOUS due to typosquatting override
        self.assertEqual(data['ai_report']['verdict'], "MALICIOUS (PHISHING)")

    # --- 2. ENGINE LOGIC TESTS ---
    def test_url_engine_typosquatting(self):
        """Directly test the URL engine's brand check logic."""
        engine = engines['url']
        result = engine.analyze("instagrarn.com")
        self.assertIn("TYPOSQUATTING", result['brand_check'])
        self.assertGreaterEqual(result['calculated_risk'], 70)

    def test_eml_engine_parsing(self):
        """Test EML engine with raw string input."""
        engine = engines['eml']
        raw_email = "From: sender@malicious.com\nTo: user@company.com\nSubject: Urgent Action Required\n\nClick here: http://fake-login.com"
        result = engine.analyze(raw_email)
        self.assertIn("DETECTED", result['pressure_tactics'])
        self.assertGreater(result['calculated_risk'], 0)

    def test_smishing_engine_logic(self):
        """Test Smishing engine with a malicious SMS text."""
        engine = engines['smishing']
        sms_text = "Your bank account is blocked. Verify now: http://bit.ly/fake-bank"
        result = engine.analyze(sms_text)
        self.assertTrue(result['shortener_detected'])
        self.assertIn("bit.ly", str(result['extracted_links']))
        self.assertGreaterEqual(result['calculated_risk'], 60)

    @patch('cv2.imread')
    @patch('core.quishing_engine.decode')
    def test_quishing_engine_mocked(self, mock_decode, mock_imread):
        """Test QR engine logic using mocks."""
        mock_imread.return_value = MagicMock()
        mock_obj = MagicMock()
        mock_obj.data.decode.return_value = "http://bit.ly/hidden-phish"
        mock_decode.return_value = [mock_obj]
        
        engine = engines['qr']
        result = engine.analyze("dummy_path.png")
        self.assertEqual(result['extracted_payload'], "http://bit.ly/hidden-phish")
        self.assertTrue(result['obfuscation_detected'])
        self.assertGreaterEqual(result['calculated_risk'], 70)

    @patch('speech_recognition.AudioFile')
    @patch('speech_recognition.Recognizer.record')
    @patch('speech_recognition.Recognizer.recognize_google')
    @patch('core.vishing_engine.VishingEngine.convert_to_wav')
    def test_vishing_engine_mocked(self, mock_convert, mock_recognize, mock_record, mock_audiofile):
        """Test Vishing engine logic using mocks."""
        mock_convert.return_value = "dummy.wav"
        mock_recognize.return_value = "this is your bank calling please provide your otp immediately"
        
        engine = engines['vishing']
        result = engine.analyze("dummy_audio.mp3")
        self.assertIn("otp", result['detected_keywords'])
        self.assertEqual(result['urgency_level'], "High (Social Engineering Pattern)")
        self.assertGreaterEqual(result['calculated_risk'], 40)

    @patch('requests.get')
    def test_clone_engine_mocked(self, mock_get):
        """Test Clone engine logic using mocks."""
        # Mocking legitimate site structure
        mock_response = MagicMock()
        mock_response.text = "<html><title>Google Login</title><form action='http://hacker.com/steal'></form></html>"
        mock_get.return_value = mock_response
        
        engine = engines['clone']
        # We need to mock both the suspicious site and the real site fetch
        # But for simplicity, we'll test if it detects the brand in title
        result = engine.analyze("http://fake-google.com")
        self.assertEqual(result['mimicked_brand'], "google.com")
        # Since we mocked the structure to have a mismatched form
        self.assertTrue(result['clone_detected'])
        self.assertGreaterEqual(result['calculated_risk'], 60)

    def test_social_engine_logic(self):
        """Test Social Engineering engine (Homograph/Punycode)."""
        engine = engines['social']
        # Punycode for 'xn--googl-pma.com'
        result = engine.analyze("xn--googl-pma.com")
        self.assertTrue(result['punycode_detected'])
        self.assertGreaterEqual(result['calculated_risk'], 70)
        
        # Brand mimicry
        result2 = engine.analyze("instagram-security-update.net")
        self.assertIn("SUSPICIOUS", result2['brand_impersonation'])
        self.assertGreaterEqual(result2['calculated_risk'], 40)

    # --- 3. ADVANCED MODULE TESTS ---
    def test_offensive_attack(self):
        """Test the offensive counter-attack endpoint."""
        payload = {"target_url": "http://phish-site.com/login"}
        response = self.app.post('/api/offensive_attack', 
                                data=json.dumps(payload),
                                content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], "Attack Successful")
        self.assertGreater(data['injected_records'], 0)

    def test_cache_speed(self):
        """Test if second scan is faster (from cache)."""
        payload = {"payload": "google.com", "vector": "url"}
        # First scan
        self.app.post('/analyze', data=json.dumps(payload), content_type='application/json')
        # Second scan
        import time
        start = time.time()
        response = self.app.post('/analyze', data=json.dumps(payload), content_type='application/json')
        end = time.time()
        data = json.loads(response.data)
        self.assertTrue(data.get('is_cached', False))
        self.assertLess(end - start, 0.1)

    def test_metrics_update(self):
        """Test if soc_metrics.json is updated."""
        with open('soc_metrics.json', 'r') as f:
            old_metrics = json.load(f)
            
        payload = {"payload": "legit-site.com", "vector": "url"}
        self.app.post('/analyze', data=json.dumps(payload), content_type='application/json')
        
        with open('soc_metrics.json', 'r') as f:
            new_metrics = json.load(f)
            
        # Total sum of metrics should increase
        self.assertGreater(sum(new_metrics.values()), sum(old_metrics.values()))

if __name__ == '__main__':
    unittest.main(verbosity=2)
