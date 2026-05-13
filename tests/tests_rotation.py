import unittest
from unittest.mock import MagicMock, patch
import json
from app.integrations.api_rotator import APIRotator
from app.integrations.ai_handler import AIHandler

class TestAPIRotation(unittest.TestCase):

    # --- 1. APIRotator Tests ---
    def test_api_rotator_initialization(self):
        """Verify APIRotator filters empty keys and initializes cycle."""
        keys = ["KEY1", "", "  ", "KEY2"]
        rotator = APIRotator(keys, "TestService")
        self.assertEqual(rotator.api_keys, ["KEY1", "KEY2"])

    def test_api_rotator_round_robin(self):
        """Verify APIRotator cycles through keys in Round-Robin fashion."""
        keys = ["KEY1", "KEY2"]
        rotator = APIRotator(keys)
        # First cycle
        self.assertEqual(rotator.get_key(), "KEY1")
        self.assertEqual(rotator.get_key(), "KEY2")
        # Second cycle (loops back)
        self.assertEqual(rotator.get_key(), "KEY1")
        self.assertEqual(rotator.get_key(), "KEY2")

    def test_api_rotator_empty_keys(self):
        """Verify behavior when no valid keys are provided."""
        rotator = APIRotator([])
        self.assertEqual(rotator.get_key(), "")

    # --- 2. AIHandler Rotation Tests ---
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_ai_handler_rotation_logic(self, mock_model, mock_configure):
        """Verify AIHandler rotates index and reconfigures."""
        keys = ["KEY1", "KEY2", "KEY3"]
        handler = AIHandler(keys)
        
        self.assertEqual(handler.current_key_index, 0)
        
        # Rotate to 2nd key
        handler.rotate_key()
        self.assertEqual(handler.current_key_index, 1)
        
        # Rotate to 3rd key
        handler.rotate_key()
        self.assertEqual(handler.current_key_index, 2)
        
        # Rotate back to 1st key (Round-Robin)
        handler.rotate_key()
        self.assertEqual(handler.current_key_index, 0)

    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_ai_handler_retry_on_failure(self, mock_model_class, mock_configure):
        """Verify AIHandler retries with next key if first key fails."""
        mock_model_instance = MagicMock()
        mock_model_class.return_value = mock_model_instance
        
        # Mocking generate_content to fail once, then succeed
        success_response = MagicMock()
        success_response.text = '{"verdict": "SAFE", "reason": "Test", "advice": "None", "playbook": []}'
        
        mock_model_instance.generate_content.side_effect = [
            Exception("Quota Exceeded"), # 1st call fails
            success_response            # 2nd call (after rotation) succeeds
        ]
        
        keys = ["KEY1", "KEY2"]
        handler = AIHandler(keys)
        
        # Trigger consensus
        result = handler.get_consensus({"test": "data"}, "url")
        
        # Assertions
        self.assertEqual(result['verdict'], "SAFE")
        self.assertEqual(handler.current_key_index, 1) # Should have rotated to 2nd key
        self.assertEqual(mock_model_instance.generate_content.call_count, 2)

    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_ai_handler_all_keys_failure(self, mock_model_class, mock_configure):
        """Verify AIHandler returns fallback when all keys fail."""
        mock_model_instance = MagicMock()
        mock_model_class.return_value = mock_model_instance
        
        # All attempts fail
        mock_model_instance.generate_content.side_effect = Exception("All Keys Blocked")
        
        keys = ["KEY1", "KEY2"]
        handler = AIHandler(keys)
        
        # Trigger consensus
        result = handler.get_consensus({"test": "data"}, "url")
        
        # Assertions - new format uses "FALLBACK MODE"
        self.assertIn("FALLBACK MODE", result['verdict'])
        self.assertEqual(mock_model_instance.generate_content.call_count, 2) # Tried both keys

if __name__ == '__main__':
    unittest.main(verbosity=2)
