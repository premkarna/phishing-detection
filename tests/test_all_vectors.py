#!/usr/bin/env python3
"""
COMPREHENSIVE VECTOR TESTS - All 7 Engines
Tests URL, QR, EML, SMS, Voice, Clone, and Social Engineering vectors
"""

import sys
import os
import unittest
import json
import time

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, engines

class TestAllVectors(unittest.TestCase):
    """Test all 7 threat vectors comprehensively"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test client"""
        cls.client = app.test_client()
        cls.client.testing = True
        print("\n" + "="*70)
        print("🧪 COMPREHENSIVE VECTOR TESTING - ALL 7 ENGINES")
        print("="*70)
    
    def _scan_payload(self, payload, vector_type, description=""):
        """Helper to scan a payload and return results"""
        print(f"\n  Testing: {description}")
        print(f"  Payload: {payload[:50]}...")
        
        response = self.client.post('/analyze',
            data=json.dumps({'payload': payload, 'vector': vector_type}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200, f"Failed to scan {vector_type}")
        data = response.get_json()
        
        # Verify response structure
        self.assertIn('ai_report', data, "Missing ai_report in response")
        self.assertIn('calculated_risk', data, "Missing risk score")
        
        verdict = data['ai_report'].get('verdict', 'UNKNOWN')
        risk = data.get('calculated_risk', 0)
        
        print(f"  ✅ Result: {verdict} (Risk: {risk}/100)")
        
        return data

    # =========================================================================
    # 1. URL/PHISHING TESTS
    # =========================================================================
    def test_url_01_typosquatting_amazon(self):
        """URL: Typosquatting - amaz0n.com"""
        result = self._scan_payload("amaz0n.com/login", "url", 
            "Typosquatting: amaz0n.com")
        self.assertGreaterEqual(result['calculated_risk'], 60,
            "Typosquatting should have high risk")
    
    def test_url_02_typosquatting_paypal(self):
        """URL: Typosquatting - paypa1.com"""
        result = self._scan_payload("paypa1.com/verify", "url",
            "Typosquatting: paypa1.com")
        self.assertGreaterEqual(result['calculated_risk'], 60,
            "PayPal typosquat should be high risk")
    
    def test_url_03_legitimate_google(self):
        """URL: Legitimate - google.com"""
        result = self._scan_payload("https://www.google.com", "url",
            "Legitimate: google.com")
        self.assertLessEqual(result['calculated_risk'], 40,
            "Google should be low risk")
    
    def test_url_04_legitimate_amazon(self):
        """URL: Legitimate - amazon.com"""
        result = self._scan_payload("https://www.amazon.com", "url",
            "Legitimate: amazon.com")
        self.assertLessEqual(result['calculated_risk'], 40,
            "Amazon should be low risk")
    
    def test_url_05_phishing_url(self):
        """URL: Obvious phishing"""
        result = self._scan_payload(
            "http://login-secure-verify-account-update.tk/paypal", "url",
            "Phishing: suspicious TLD and structure")
        self.assertGreaterEqual(result['calculated_risk'], 70,
            "Phishing URL should have very high risk")
    
    def test_url_06_subdomain_spoof(self):
        """URL: Subdomain spoofing"""
        result = self._scan_payload(
            "http://login.microsoft.verify-account.secure-update.ru", "url",
            "Subdomain spoofing")
        self.assertGreaterEqual(result['calculated_risk'], 50,
            "Subdomain spoofing should be detected")

    # =========================================================================
    # 2. QR/QUISHING TESTS
    # =========================================================================
    def test_qr_01_malicious_bitly(self):
        """QR: Malicious bit.ly link"""
        result = self._scan_payload("bit.ly/3xMalicious", "qr",
            "QR: Malicious bit.ly link")
        self.assertGreaterEqual(result['calculated_risk'], 50,
            "Malicious QR should be detected")
    
    def test_qr_02_phishing_url(self):
        """QR: Phishing URL encoded"""
        result = self._scan_payload(
            "http://phishing-site.com/login?token=steal", "qr",
            "QR: Phishing URL")
        self.assertGreaterEqual(result['calculated_risk'], 60,
            "Phishing QR should be high risk")
    
    def test_qr_03_legitimate_wifi(self):
        """QR: Legitimate WiFi QR"""
        result = self._scan_payload("WIFI:T:WPA;S:MyHome;P:password;;", "qr",
            "QR: Legitimate WiFi")
        self.assertLessEqual(result['calculated_risk'], 40,
            "WiFi QR should be safe")
    
    def test_qr_04_legitimate_menu(self):
        """QR: Restaurant menu QR"""
        result = self._scan_payload("https://restaurant-menu.com/table/5", "qr",
            "QR: Restaurant menu")
        self.assertLessEqual(result['calculated_risk'], 30,
            "Menu QR should be low risk")

    # =========================================================================
    # 3. EML/EMAIL TESTS
    # =========================================================================
    def test_eml_01_spear_phishing(self):
        """EML: Spear phishing with attachment"""
        email_content = """
        From: ceo@company-secure.com
        To: victim@company.com
        Subject: URGENT: Wire Transfer Needed
        
        Please review the attached invoice and process payment immediately.
        
        Attachment: invoice.exe
        """
        result = self._scan_payload(email_content, "eml",
            "EML: Spear phishing with .exe attachment")
        self.assertGreaterEqual(result['calculated_risk'], 70,
            "Spear phishing with exe should be high risk")
    
    def test_eml_02_spoofed_bank(self):
        """EML: Spoofed bank email"""
        email_content = """
        From: security@bankofamerica-secure.com
        To: user@gmail.com
        Subject: Account Verification Required
        
        Click here to verify: http://verify-bank.tk/login
        """
        result = self._scan_payload(email_content, "eml",
            "EML: Spoofed bank email")
        self.assertGreaterEqual(result['calculated_risk'], 60,
            "Spoofed bank email should be detected")
    
    def test_eml_03_legitimate_newsletter(self):
        """EML: Legitimate newsletter"""
        email_content = """
        From: newsletter@github.com
        To: user@company.com
        Subject: Your weekly GitHub digest
        
        Here are your updates from repositories you follow.
        """
        result = self._scan_payload(email_content, "eml",
            "EML: Legitimate newsletter")
        self.assertLessEqual(result['calculated_risk'], 30,
            "Legitimate newsletter should be safe")
    
    def test_eml_04_business_correspondence(self):
        """EML: Normal business email"""
        email_content = """
        From: john.smith@company.com
        To: team@company.com
        Subject: Meeting notes from today
        
        Attached are the meeting notes and action items.
        """
        result = self._scan_payload(email_content, "eml",
            "EML: Normal business email")
        self.assertLessEqual(result['calculated_risk'], 25,
            "Business email should be low risk")

    # =========================================================================
    # 4. SMS/SMISHING TESTS
    # =========================================================================
    def test_sms_01_prize_scam(self):
        """SMS: Prize/lottery scam"""
        result = self._scan_payload(
            "Congratulations! You've won $1000. Click here to claim: bit.ly/win123", "sms",
            "SMS: Prize scam")
        self.assertGreaterEqual(result['calculated_risk'], 70,
            "Prize scam should be high risk")
    
    def test_sms_02_bank_alert(self):
        """SMS: Fake bank alert"""
        result = self._scan_payload(
            "ALERT: Your account has been suspended. Verify now: http://bank-verify.tk", "sms",
            "SMS: Fake bank alert")
        self.assertGreaterEqual(result['calculated_risk'], 65,
            "Bank smishing should be detected")
    
    def test_sms_03_package_delivery(self):
        """SMS: Fake package delivery"""
        result = self._scan_payload(
            "Your package is held. Pay $2.99 shipping: http://delivery-scam.com/pay", "sms",
            "SMS: Fake delivery")
        self.assertGreaterEqual(result['calculated_risk'], 60,
            "Delivery scam should be detected")
    
    def test_sms_04_legitimate_appointment(self):
        """SMS: Legitimate appointment reminder"""
        result = self._scan_payload(
            "Reminder: Doctor appointment tomorrow at 2PM at City Hospital.", "sms",
            "SMS: Legitimate appointment")
        self.assertLessEqual(result['calculated_risk'], 25,
            "Appointment reminder should be safe")

    # =========================================================================
    # 5. VOICE/VISHING TESTS
    # =========================================================================
    def test_voice_01_irs_scam(self):
        """Voice: IRS tax scam"""
        result = self._scan_payload(
            "This is the IRS. You owe $5000 in back taxes. Pay immediately or face arrest. "
            "Call 555-1234 or provide credit card now.", "voice",
            "Voice: IRS scam")
        self.assertGreaterEqual(result['calculated_risk'], 75,
            "IRS vishing should be very high risk")
    
    def test_voice_02_tech_support(self):
        """Voice: Fake tech support"""
        result = self._scan_payload(
            "This is Microsoft Support. We've detected a virus on your computer. "
            "Please provide remote access to fix it.", "voice",
            "Voice: Tech support scam")
        self.assertGreaterEqual(result['calculated_risk'], 70,
            "Tech support vishing should be high risk")
    
    def test_voice_03_bank_fraud(self):
        """Voice: Bank fraud call"""
        result = self._scan_payload(
            "This is your bank's fraud department. We need to verify your account. "
            "Please provide your OTP and PIN.", "voice",
            "Voice: Bank fraud call")
        self.assertGreaterEqual(result['calculated_risk'], 80,
            "Bank vishing asking for OTP should be critical")
    
    def test_voice_04_legitimate_call(self):
        """Voice: Normal conversation"""
        result = self._scan_payload(
            "Hi, this is John from sales. Just calling to follow up on our meeting yesterday. "
            "Let me know when you're free to discuss the proposal.", "voice",
            "Voice: Normal business call")
        self.assertLessEqual(result['calculated_risk'], 20,
            "Normal call should be low risk")

    # =========================================================================
    # 6. CLONE SITE TESTS
    # =========================================================================
    def test_clone_01_facebook_clone(self):
        """Clone: Facebook login page clone"""
        result = self._scan_payload(
            "https://faceb00k-login.com/signin", "clone",
            "Clone: Fake Facebook login")
        self.assertGreaterEqual(result['calculated_risk'], 70,
            "Facebook clone should be high risk")
    
    def test_clone_02_bank_clone(self):
        """Clone: Bank website clone"""
        result = self._scan_payload(
            "https://chase-bank-secure.xyz/login", "clone",
            "Clone: Fake bank site")
        self.assertGreaterEqual(result['calculated_risk'], 70,
            "Bank clone should be high risk")
    
    def test_clone_03_ecommerce_clone(self):
        """Clone: Fake e-commerce site"""
        result = self._scan_payload(
            "https://amaz0n-deals.tk/products", "clone",
            "Clone: Fake Amazon deals")
        self.assertGreaterEqual(result['calculated_risk'], 65,
            "E-commerce clone should be detected")
    
    def test_clone_04_legitimate_site(self):
        """Clone: Legitimate website"""
        result = self._scan_payload(
            "https://www.wikipedia.org", "clone",
            "Clone: Legitimate Wikipedia")
        self.assertLessEqual(result['calculated_risk'], 20,
            "Wikipedia should be safe")

    # =========================================================================
    # 7. SOCIAL ENGINEERING TESTS
    # =========================================================================
    def test_social_01_pretext_scam(self):
        """Social: Pretexting scam"""
        result = self._scan_payload(
            "I'm from IT support. Your manager asked me to fix your account urgently. "
            "I need your password to resolve this issue immediately.", "social",
            "Social: IT pretexting")
        self.assertGreaterEqual(result['calculated_risk'], 70,
            "Pretexting should be high risk")
    
    def test_social_02_urgent_action(self):
        """Social: Urgent action required"""
        result = self._scan_payload(
            "URGENT: Your account will be deleted in 1 hour! "
            "Click immediately to verify: http://urgent-verify.tk", "social",
            "Social: Urgent action scam")
        self.assertGreaterEqual(result['calculated_risk'], 65,
            "Urgent action should be detected")
    
    def test_social_03_authority_abuse(self):
        """Social: Authority abuse"""
        result = self._scan_payload(
            "This is the CEO. I'm in a meeting and need you to wire $50,000 immediately "
            "to this account for a confidential acquisition. Don't tell anyone.", "social",
            "Social: CEO fraud (BEC)")
        self.assertGreaterEqual(result['calculated_risk'], 75,
            "CEO fraud should be critical risk")
    
    def test_social_04_legitimate_request(self):
        """Social: Normal request"""
        result = self._scan_payload(
            "Hi team, please review the quarterly report when you get a chance. "
            "No rush, just need feedback by end of week. Thanks!", "social",
            "Social: Normal request")
        self.assertLessEqual(result['calculated_risk'], 20,
            "Normal request should be safe")

    # =========================================================================
    # BULK TESTS - Multiple Samples
    # =========================================================================
    def test_bulk_url_scanning(self):
        """Test: Bulk URL scanning performance"""
        print("\n📊 BULK URL TEST: 5 samples")
        urls = [
            ("google.com", "safe"),
            ("amaz0n.com", "malicious"),
            ("paypa1.com", "malicious"),
            ("github.com", "safe"),
            ("login-verify.tk", "malicious")
        ]
        
        results = []
        for url, expected in urls:
            data = self._scan_payload(url, "url", f"Bulk: {url}")
            risk = data['calculated_risk']
            verdict = data['ai_report'].get('verdict', '')
            
            if expected == "malicious":
                self.assertGreaterEqual(risk, 50, f"{url} should be flagged as malicious")
            else:
                self.assertLessEqual(risk, 50, f"{url} should be flagged as safe")
            
            results.append((url, risk, verdict))
        
        print("\n  Bulk Results Summary:")
        for url, risk, verdict in results:
            print(f"    {url[:25]:25} | Risk: {risk:3}/100 | {verdict[:20]}")
        
        print("  ✅ All bulk scans completed successfully")

class TestAPIEndpoints(unittest.TestCase):
    """Test Flask API endpoints"""
    
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        cls.client.testing = True
        print("\n" + "="*70)
        print("🌐 API ENDPOINT TESTS")
        print("="*70)
    
    def test_01_index_page(self):
        """Test: Home page loads"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        print("  ✅ GET / - Home page loads")
    
    def test_02_accuracy_page(self):
        """Test: Accuracy dashboard loads"""
        response = self.client.get('/accuracy')
        self.assertEqual(response.status_code, 200)
        print("  ✅ GET /accuracy - Accuracy page loads")
    
    def test_03_api_metrics(self):
        """Test: Metrics API returns data"""
        response = self.client.get('/api/metrics')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsNotNone(data)
        print("  ✅ GET /api/metrics - Metrics API working")
    
    def test_04_api_threats(self):
        """Test: Threats API returns data"""
        response = self.client.get('/api/threats')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('nodes', data)
        self.assertIn('links', data)
        print("  ✅ GET /api/threats - Threats API working")
    
    def test_05_intel_page(self):
        """Test: Threat intel page loads"""
        response = self.client.get('/intel')
        self.assertEqual(response.status_code, 200)
        print("  ✅ GET /intel - Intel page loads")

class TestResponseStructure(unittest.TestCase):
    """Test response data structure"""
    
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        cls.client.testing = True
        print("\n" + "="*70)
        print("📋 RESPONSE STRUCTURE TESTS")
        print("="*70)
    
    def test_01_response_has_required_fields(self):
        """Test: All required fields present in response"""
        response = self.client.post('/analyze',
            data=json.dumps({'payload': 'test.com', 'vector': 'url'}),
            content_type='application/json'
        )
        
        data = response.get_json()
        required_fields = [
            'ai_report', 'calculated_risk', 'payload', 'vector',
            'virustotal', 'ssl_certificate', 'brand_check'
        ]
        
        for field in required_fields:
            self.assertIn(field, data, f"Missing required field: {field}")
        
        # Check ai_report structure
        ai_fields = ['verdict', 'reason', 'advice']
        for field in ai_fields:
            self.assertIn(field, data['ai_report'], f"Missing ai_report field: {field}")
        
        print("  ✅ Response has all required fields")
    
    def test_02_risk_score_range(self):
        """Test: Risk score is valid (0-100)"""
        test_cases = [
            ("google.com", "url"),
            ("malicious-site.tk", "url"),
            ("test", "sms"),
        ]
        
        for payload, vector in test_cases:
            response = self.client.post('/analyze',
                data=json.dumps({'payload': payload, 'vector': vector}),
                content_type='application/json'
            )
            data = response.get_json()
            risk = data.get('calculated_risk', -1)
            
            self.assertGreaterEqual(risk, 0, "Risk should be >= 0")
            self.assertLessEqual(risk, 100, "Risk should be <= 100")
        
        print("  ✅ Risk scores in valid range (0-100)")
    
    def test_03_verdict_consistency(self):
        """Test: Verdict matches risk score"""
        response = self.client.post('/analyze',
            data=json.dumps({'payload': 'amaz0n.com', 'vector': 'url'}),
            content_type='application/json'
        )
        
        data = response.get_json()
        risk = data['calculated_risk']
        verdict = data['ai_report']['verdict']
        
        # High risk should indicate malicious
        if risk >= 70:
            self.assertIn(verdict.upper(), ['MALICIOUS', 'CRITICAL', 'PHISHING'],
                "High risk should have malicious verdict")
        
        print("  ✅ Verdict consistency maintained")

def run_tests():
    """Run all tests with detailed output"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestAllVectors))
    suite.addTests(loader.loadTestsFromTestCase(TestAPIEndpoints))
    suite.addTests(loader.loadTestsFromTestCase(TestResponseStructure))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("📊 TEST SUMMARY")
    print("="*70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.testsRun - len(result.failures) - len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ ALL TESTS PASSED!")
    else:
        print("\n❌ SOME TESTS FAILED")
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
