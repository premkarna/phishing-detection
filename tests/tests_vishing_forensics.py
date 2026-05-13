import unittest
from unittest.mock import MagicMock, patch
import os
import sys

# Add root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.vishing_engine import VishingEngine

class TestVishingForensics(unittest.TestCase):
    def setUp(self):
        self.engine = VishingEngine()
        self.test_scenarios = [
            {
                "desc": "Standard Bank Phish",
                "transcript": "Hello this is your bank. Your account is blocked. Please provide your otp and password immediately.",
                "expected_keywords": ['bank', 'otp', 'password'],
                "expected_urgency": "High (Social Engineering Pattern)",
                "min_risk": 60
            },
            {
                "desc": "KYC Scam",
                "transcript": "Customer care calling for your kyc update. Give your aadhar and pan card details now or account will be suspended.",
                "expected_keywords": ['customer care', 'kyc', 'aadhar', 'pan card'],
                "expected_urgency": "High (Social Engineering Pattern)",
                "min_risk": 70
            },
            {
                "desc": "Lottery Scam",
                "transcript": "Congratulations you won a lottery. To claim your prize buy a gift card and send the code.",
                "expected_keywords": ['lottery'],
                "expected_urgency": "Low",
                "min_risk": 15
            },
            {
                "desc": "Legitimate Call",
                "transcript": "Hi mom I will be home for dinner at 8pm. Don't forget the pizza.",
                "expected_keywords": [],
                "expected_urgency": "Low",
                "min_risk": 0
            },
            {
                "desc": "Urgent Security Alert",
                "transcript": "Security alert. Suspicious activity detected. Verify your identity immediately.",
                "expected_keywords": [],
                "expected_urgency": "High (Social Engineering Pattern)",
                "min_risk": 25
            }
        ]

    @patch('speech_recognition.AudioFile')
    @patch('speech_recognition.Recognizer.record')
    @patch('speech_recognition.Recognizer.recognize_google')
    @patch('core.vishing_engine.VishingEngine.convert_to_wav')
    def test_vishing_bulk_forensics(self, mock_convert, mock_recognize, mock_record, mock_audiofile):
        """Test various vishing scenarios to verify forensic accuracy."""
        print("\n" + "="*80)
        print(f"{'SCENARIO':<25} | {'RISK':<5} | {'URGENCY':<15} | {'KEYWORDS'}")
        print("-" * 80)

        passed_count = 0
        mock_convert.return_value = "dummy.wav"
        
        # Mock AudioFile context manager
        mock_audio_context = MagicMock()
        mock_audiofile.return_value.__enter__.return_value = mock_audio_context

        for scenario in self.test_scenarios:
            # Mock the transcription for this scenario
            mock_recognize.return_value = scenario['transcript']
            
            # Execute analysis
            # We mock os.remove to prevent errors with dummy.wav
            with patch('os.remove'):
                res = self.engine.analyze("test_audio.mp3")
            
            risk = res['calculated_risk']
            urgency = res['urgency_level']
            keywords = ", ".join(res['detected_keywords'])
            
            print(f"{scenario['desc']:<25} | {risk:<5} | {urgency:<15} | {keywords}")
            
            # Verifications
            self.assertGreaterEqual(risk, scenario['min_risk'], f"Risk too low for {scenario['desc']}")
            self.assertEqual(urgency, scenario['expected_urgency'], f"Urgency mismatch for {scenario['desc']}")
            for kw in scenario['expected_keywords']:
                self.assertIn(kw, res['detected_keywords'], f"Missing keyword {kw} in {scenario['desc']}")
            
            passed_count += 1

        accuracy = (passed_count / len(self.test_scenarios)) * 100
        print("="*80)
        print(f"VISHING FORENSIC ACCURACY: {accuracy:.2f}% ({passed_count}/{len(self.test_scenarios)})")

    @patch('core.vishing_engine.AudioSegment.from_file')
    def test_audio_conversion_logic(self, mock_audio_from_file):
        """Verify that the engine correctly attempts audio conversion."""
        mock_audio = MagicMock()
        mock_audio_from_file.return_value = mock_audio
        
        # Test .mp3 to .wav conversion
        result = self.engine.convert_to_wav("suspicious.mp3")
        self.assertTrue(result.endswith("_converted.wav"))
        mock_audio.export.assert_called_once()

    def test_error_handling_invalid_file(self):
        """Ensure the engine handles transcription failures gracefully."""
        # Using a non-existent file which should trigger an exception in transcribe logic
        res = self.engine.analyze("non_existent_file.wav")
        self.assertEqual(res['transcript'], "Transcription Failed")
        self.assertEqual(res['calculated_risk'], 0)

if __name__ == '__main__':
    unittest.main(verbosity=2)
