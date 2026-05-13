import unittest
import os
import cv2
import numpy as np
from unittest.mock import patch, MagicMock
from app.core.quishing_engine import QREngine

class TestQuishingForensics(unittest.TestCase):
    def setUp(self):
        self.engine = QREngine()
        # Dataset of QR Payloads for testing
        self.test_scenarios = [
            # Legitimate Payloads
            {"payload": "https://google.com", "expected_risk": 20, "obfuscation": False, "desc": "Legit URL"},
            {"payload": "WIFI:S:MyNetwork;T:WPA;P:password123;;", "expected_risk": 0, "obfuscation": False, "desc": "Legit WiFi Config"},
            {"payload": "Just some plain text data", "expected_risk": 0, "obfuscation": False, "desc": "Plain Text"},
            
            # Malicious / Obfuscated Payloads (Non-Legitimate)
            {"payload": "https://bit.ly/secure-login-302", "expected_risk": 70, "obfuscation": True, "desc": "Phishing via bit.ly"},
            {"payload": "http://tinyurl.com/update-account-now", "expected_risk": 70, "obfuscation": True, "desc": "Phishing via tinyurl"},
            {"payload": "https://cutt.ly/bank-verification", "expected_risk": 70, "obfuscation": True, "desc": "Phishing via cutt.ly"},
            {"payload": "https://malicious-site.com/payload.exe", "expected_risk": 20, "obfuscation": False, "desc": "Direct Malicious Link"}
        ]

    @patch('cv2.imread')
    @patch('core.quishing_engine.decode')
    def test_qr_bulk_analysis(self, mock_decode, mock_imread):
        """Run the engine against all QR scenarios using mocked image data."""
        print("\n" + "="*70)
        print(f"{'QR PAYLOAD':<40} | {'RISK':<5} | {'OBFUSCATION':<12}")
        print("-" * 70)
        
        passed_count = 0
        mock_imread.return_value = np.zeros((100, 100, 3), dtype=np.uint8) # Dummy image
        
        for scenario in self.test_scenarios:
            # Setup mock for this specific payload
            mock_obj = MagicMock()
            mock_obj.data.decode.return_value = scenario['payload']
            mock_decode.return_value = [mock_obj]
            
            # Execute analysis
            res = self.engine.analyze("dummy_qr.png")
            
            risk = res['calculated_risk']
            obf = res['obfuscation_detected']
            
            print(f"{scenario['payload'][:40]:<40} | {risk:<5} | {str(obf):<12}")
            
            # Verify results
            self.assertEqual(risk, scenario['expected_risk'], f"Risk mismatch for {scenario['desc']}")
            self.assertEqual(obf, scenario['obfuscation'], f"Obfuscation mismatch for {scenario['desc']}")
            passed_count += 1

        accuracy = (passed_count / len(self.test_scenarios)) * 100
        print("="*70)
        print(f"QR FORENSIC SCAN ACCURACY: {accuracy:.2f}% ({passed_count}/{len(self.test_scenarios)})")

    @patch('cv2.imread')
    @patch('core.quishing_engine.decode')
    def test_forensic_enhancement_trigger(self, mock_decode, mock_imread):
        """Verify that Level 2 Forensic Enhancement triggers when standard scan fails."""
        mock_imread.return_value = np.zeros((100, 100, 3), dtype=np.uint8)
        
        # Level 1 (Standard) returns nothing, Level 2 (Enhanced) returns a payload
        mock_obj = MagicMock()
        mock_obj.data.decode.return_value = "https://legit-site.com"
        
        # Side effect: First call (Standard) empty, Second call (Enhanced) success
        mock_decode.side_effect = [[], [mock_obj]]
        
        with self.assertLogs(level='INFO') as cm:
            res = self.engine.analyze("blurry_qr.png")
            
            self.assertEqual(res['extracted_payload'], "https://legit-site.com")
            # Check if enhancement log message exists
            self.assertTrue(any("Standard scan failed. Applying forensic filters" in r.getMessage() for r in cm.records))

if __name__ == '__main__':
    unittest.main(verbosity=2)
