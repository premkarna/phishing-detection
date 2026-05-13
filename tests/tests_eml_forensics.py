import unittest
import os
from app.core.eml_engine import EMLEngine

class TestEMLForensics(unittest.TestCase):
    def setUp(self):
        self.engine = EMLEngine()
        
    def test_legit_email_headers(self):
        """Test a legitimate email with passing SPF and DKIM."""
        raw_eml = (
            "From: support@google.com\n"
            "To: user@example.com\n"
            "Subject: Security Update\n"
            "Authentication-Results: mx.google.com; spf=pass; dkim=pass\n"
            "Received-SPF: pass\n\n"
            "This is a legitimate security update."
        )
        res = self.engine.analyze(raw_eml)
        self.assertEqual(res['spf_record'], "PASS (Verified Origin)")
        self.assertEqual(res['dkim_signature'], "PASS (Valid Signature)")
        self.assertEqual(res['sender_forgery'], "Verified Origin")
        self.assertEqual(res['calculated_risk'], 0)

    def test_spf_dkim_fail(self):
        """Test an email where SPF and DKIM both fail."""
        raw_eml = (
            "From: billing@paypal.com\n"
            "To: user@example.com\n"
            "Subject: Action Required\n"
            "Authentication-Results: mx.google.com; spf=fail; dkim=fail\n"
            "Received-SPF: fail\n\n"
            "Your account is suspended."
        )
        res = self.engine.analyze(raw_eml)
        self.assertEqual(res['spf_record'], "FAIL / SOFTFAIL")
        self.assertEqual(res['dkim_signature'], "FAIL / MISSING")
        # Risk: 40 (SPF) + 20 (DKIM) + 10 (Pressure Keyword 'suspended') = 70
        self.assertGreaterEqual(res['calculated_risk'], 60)

    def test_sender_spoofing(self):
        """Test classic sender forgery where Return-Path doesn't match From."""
        raw_eml = (
            "From: ceo@yourcompany.com\n"
            "Return-Path: <attacker@evil-hacker.com>\n"
            "Subject: Urgent Wire Transfer\n\n"
            "Please process this payment immediately."
        )
        res = self.engine.analyze(raw_eml)
        self.assertIn("CRITICAL: Return-Path Mismatch", res['sender_forgery'])
        self.assertGreaterEqual(res['calculated_risk'], 50)

    def test_hidden_tracker_detection(self):
        """Test detection of 1x1 tracking pixels in HTML body."""
        raw_eml = (
            "From: newsletter@site.com\n"
            "Content-Type: text/html\n\n"
            "<html><body>"
            "<h1>Hello</h1>"
            "<img src='http://track.com/pixel.png' width='1' height='1'>"
            "</body></html>"
        )
        res = self.engine.analyze(raw_eml)
        self.assertIn("DETECTED: 1 tracking pixel(s)", res['hidden_trackers'])
        self.assertGreaterEqual(res['calculated_risk'], 20)

    def test_cloaked_links(self):
        """Test detection of cloaked links (Text != Href)."""
        raw_eml = (
            "From: bank@trusted.com\n"
            "Content-Type: text/html\n\n"
            "<html><body>"
            "<a href='http://malicious-site.com/login'>www.trusted-bank.com/login</a>"
            "</body></html>"
        )
        res = self.engine.analyze(raw_eml)
        self.assertIn("CLOAKED", res['suspicious_links'])
        self.assertGreaterEqual(res['calculated_risk'], 40)

    def test_pressure_tactics(self):
        """Test detection of social engineering pressure keywords."""
        raw_eml = (
            "From: hr@company.com\n\n"
            "Urgent: Your payroll has an invoice error. Legal action required."
        )
        res = self.engine.analyze(raw_eml)
        tactics = res['pressure_tactics'].lower()
        self.assertIn("urgent", tactics)
        self.assertIn("invoice", tactics)
        self.assertIn("legal action", tactics)
        # Risk: Keywords detected (7 keywords in list match parts of text)
        self.assertGreaterEqual(res['calculated_risk'], 50)

if __name__ == '__main__':
    unittest.main(verbosity=2)
