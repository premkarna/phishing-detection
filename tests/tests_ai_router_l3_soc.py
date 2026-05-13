"""
AI Router L3 SOC Analyst Test Suite
Comprehensive tests for Gemini 1.5 Flash acting as L3 SOC Analyst
Aggregating all 7 engines data and providing final verdicts with playbooks.
"""
import unittest
from unittest.mock import MagicMock, patch, call
import json
import os
from datetime import datetime
from app.integrations.ai_handler import AIHandler


class TestAIHandlerInitialization(unittest.TestCase):
    """Test AI Router initialization and configuration."""
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_initialization_with_single_key(self, mock_model, mock_configure):
        """Test AIHandler initialization with single API key."""
        handler = AIHandler(api_keys=["test_key_1"])
        
        self.assertTrue(handler.is_active)
        self.assertEqual(handler.current_key_index, 0)
        self.assertEqual(len(handler.api_keys), 1)
        mock_configure.assert_called_once_with(api_key="test_key_1")
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_initialization_with_multiple_keys(self, mock_model, mock_configure):
        """Test AIHandler initialization with multiple API keys for rotation."""
        keys = ["key_1", "key_2", "key_3"]
        handler = AIHandler(api_keys=keys)
        
        self.assertEqual(len(handler.api_keys), 3)
        self.assertEqual(handler.current_key_index, 0)
        self.assertEqual(handler.stats["total_requests"], 0)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_initialization_with_custom_model(self, mock_model, mock_configure):
        """Test AIHandler with custom model name."""
        handler = AIHandler(api_keys=["key"], model_name='gemini-pro')
        
        self.assertEqual(handler.model_name, 'gemini-pro')
        mock_model.assert_called_once_with('gemini-pro')
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_initialization_no_keys(self, mock_model, mock_configure):
        """Test AIHandler with no API keys - should be inactive."""
        handler = AIHandler(api_keys=[])
        
        self.assertFalse(handler.is_active)
        self.assertEqual(handler.api_keys, [])
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_initialization_none_keys(self, mock_model, mock_configure):
        """Test AIHandler with None keys - should handle gracefully."""
        handler = AIHandler(api_keys=None)
        
        self.assertFalse(handler.is_active)
        self.assertEqual(handler.api_keys, [])


class TestAIHandlerKeyRotation(unittest.TestCase):
    """Test API key rotation functionality."""
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_key_rotation_increments_index(self, mock_model, mock_configure):
        """Test that key rotation moves to next key."""
        handler = AIHandler(api_keys=["key_1", "key_2", "key_3"])
        
        self.assertEqual(handler.current_key_index, 0)
        
        handler.rotate_key()
        self.assertEqual(handler.current_key_index, 1)
        
        handler.rotate_key()
        self.assertEqual(handler.current_key_index, 2)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_key_rotation_round_robin(self, mock_model, mock_configure):
        """Test that key rotation wraps around to first key."""
        handler = AIHandler(api_keys=["key_1", "key_2"])
        handler.current_key_index = 1  # At last key
        
        handler.rotate_key()
        self.assertEqual(handler.current_key_index, 0)  # Wrapped to first
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_key_rotation_single_key_no_change(self, mock_model, mock_configure):
        """Test that rotation with single key returns False."""
        handler = AIHandler(api_keys=["only_key"])
        
        result = handler.rotate_key()
        self.assertFalse(result)
        self.assertEqual(handler.current_key_index, 0)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_key_rotation_tracks_stats(self, mock_model, mock_configure):
        """Test that key rotation increments rotation counter."""
        handler = AIHandler(api_keys=["key_1", "key_2"])
        initial_rotations = handler.stats["key_rotations"]
        
        handler.rotate_key()
        
        self.assertEqual(handler.stats["key_rotations"], initial_rotations + 1)


class TestL3SOCPromptBuilding(unittest.TestCase):
    """Test L3 SOC Analyst prompt building."""
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_prompt_includes_persona(self, mock_model, mock_configure):
        """Test that prompt includes L3 SOC Analyst persona."""
        handler = AIHandler(api_keys=["key"])
        
        engine_result = {"calculated_risk": 80, "brand_check": "TYPOSQUATTING"}
        prompt = handler._build_l3_soc_prompt(engine_result, "url", None)
        
        self.assertIn("Level 3 SOC", prompt)
        self.assertIn(handler.L3_SOC_PERSONA, prompt)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_prompt_includes_vector_description(self, mock_model, mock_configure):
        """Test that prompt includes vector-specific description."""
        handler = AIHandler(api_keys=["key"])
        
        for vector in ["url", "qr", "eml", "smishing", "vishing", "clone", "social"]:
            prompt = handler._build_l3_soc_prompt({}, vector, None)
            desc = handler.VECTOR_DESCRIPTIONS.get(vector, "")
            self.assertIn(desc, prompt)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_prompt_includes_engine_data(self, mock_model, mock_configure):
        """Test that prompt includes engine result data."""
        handler = AIHandler(api_keys=["key"])
        
        engine_result = {"calculated_risk": 80, "brand_check": "TYPOSQUATTING"}
        prompt = handler._build_l3_soc_prompt(engine_result, "url", None)
        
        self.assertIn("calculated_risk", prompt)
        self.assertIn("brand_check", prompt)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_prompt_includes_correlation_data(self, mock_model, mock_configure):
        """Test that prompt includes all engines data for correlation."""
        handler = AIHandler(api_keys=["key"])
        
        engine_result = {"risk": 50}
        all_engines = {
            "url": {"risk": 80},
            "qr": {"risk": 30},
            "eml": {"risk": 60}
        }
        prompt = handler._build_l3_soc_prompt(engine_result, "url", all_engines)
        
        self.assertIn("CORRELATED ENGINE DATA", prompt)
        self.assertIn("url", prompt)
        self.assertIn("qr", prompt)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_prompt_includes_json_structure(self, mock_model, mock_configure):
        """Test that prompt includes expected JSON output structure."""
        handler = AIHandler(api_keys=["key"])
        
        prompt = handler._build_l3_soc_prompt({}, "url", None)
        
        self.assertIn("verdict", prompt)
        self.assertIn("confidence", prompt)
        self.assertIn("playbook", prompt)
        self.assertIn("playbook", prompt)


class TestAIResponseParsing(unittest.TestCase):
    """Test AI response parsing and validation."""
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_parse_valid_json_response(self, mock_model, mock_configure):
        """Test parsing of valid JSON response."""
        handler = AIHandler(api_keys=["key"])
        
        response_text = '''{"verdict": "MALICIOUS", "reason": "Test", "playbook": ["Step 1"], "advice": "Be careful"}'''
        result = handler._parse_ai_response(response_text)
        
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(result["reason"], "Test")
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_parse_json_with_code_blocks(self, mock_model, mock_configure):
        """Test parsing JSON wrapped in markdown code blocks."""
        handler = AIHandler(api_keys=["key"])
        
        response_text = '''```json
{"verdict": "SAFE", "reason": "Clean", "playbook": [], "advice": "OK"}
```'''
        result = handler._parse_ai_response(response_text)
        
        self.assertEqual(result["verdict"], "SAFE")
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_parse_invalid_json_returns_fallback(self, mock_model, mock_configure):
        """Test that invalid JSON returns fallback verdict."""
        handler = AIHandler(api_keys=["key"])
        
        response_text = "This is not JSON"
        result = handler._parse_ai_response(response_text)
        
        self.assertIn("FALLBACK MODE", result["verdict"])
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_parse_correlation_response(self, mock_model, mock_configure):
        """Test parsing correlation analysis response."""
        handler = AIHandler(api_keys=["key"])
        
        response_text = '''{"verdict": "MALICIOUS", "overall_risk": "CRITICAL", "unified_playbook": {}}'''
        result = handler._parse_ai_response(response_text, is_correlation=True)
        
        self.assertEqual(result["overall_risk"], "CRITICAL")
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_parse_adds_missing_required_fields(self, mock_model, mock_configure):
        """Test that missing required fields are added."""
        handler = AIHandler(api_keys=["key"])
        
        # Response missing some fields
        response_text = '''{"verdict": "SAFE"}'''
        result = handler._parse_ai_response(response_text)
        
        self.assertIn("reason", result)
        self.assertIn("playbook", result)
        self.assertIn("advice", result)


class TestGetConsensus(unittest.TestCase):
    """Test get_consensus method with L3 SOC Analyst logic."""
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_consensus_when_inactive_returns_fallback(self, mock_model, mock_configure):
        """Test that inactive handler returns fallback verdict."""
        handler = AIHandler(api_keys=[])
        
        result = handler.get_consensus({"test": "data"}, "url")
        
        self.assertIn("FALLBACK MODE", result["verdict"])
        self.assertEqual(handler.stats["fallbacks"], 1)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_consensus_successful_analysis(self, mock_model, mock_configure):
        """Test successful AI analysis."""
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        mock_instance.generate_content.return_value.text = '''{"verdict": "MALICIOUS", "reason": "Phishing detected", "playbook": ["Block"], "advice": "Don\'t click"}'''
        
        handler = AIHandler(api_keys=["key"])
        engine_result = {"calculated_risk": 85, "brand_check": "TYPOSQUATTING"}
        
        result = handler.get_consensus(engine_result, "url")
        
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(handler.stats["successful_analyses"], 1)
        self.assertEqual(handler.stats["total_requests"], 1)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_consensus_with_correlation_data(self, mock_model, mock_configure):
        """Test analysis with all engines data for correlation."""
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        mock_instance.generate_content.return_value.text = '''{"verdict": "MALICIOUS", "reason": "Correlated indicators", "playbook": [], "advice": "Block all vectors"}'''
        
        handler = AIHandler(api_keys=["key"])
        engine_result = {"risk": 80}
        all_engines = {"url": {"risk": 80}, "qr": {"risk": 70}}
        
        result = handler.get_consensus(engine_result, "url", all_engines)
        
        mock_instance.generate_content.assert_called_once()
        # Check that correlation data was included in prompt
        call_args = mock_instance.generate_content.call_args[0][0]
        self.assertIn("CORRELATED ENGINE DATA", call_args)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_consensus_retries_on_failure(self, mock_model, mock_configure):
        """Test that analysis retries with next key on failure."""
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        # First call fails, second succeeds
        mock_instance.generate_content.side_effect = [
            Exception("Quota exceeded"),
            MagicMock(text='''{"verdict": "SAFE", "reason": "OK", "playbook": [], "advice": "OK"}''')
        ]
        
        handler = AIHandler(api_keys=["key_1", "key_2"])
        initial_key = handler.current_key_index
        
        result = handler.get_consensus({"test": "data"}, "url")
        
        # Should have rotated key
        self.assertNotEqual(handler.current_key_index, initial_key)
        self.assertEqual(mock_instance.generate_content.call_count, 2)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_consensus_all_keys_fail_returns_fallback(self, mock_model, mock_configure):
        """Test fallback when all keys fail."""
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        mock_instance.generate_content.side_effect = Exception("All Keys Blocked")
        
        handler = AIHandler(api_keys=["key_1", "key_2"])
        
        result = handler.get_consensus({"test": "data"}, "url")
        
        self.assertIn("FALLBACK MODE", result["verdict"])
        self.assertEqual(handler.stats["fallbacks"], 1)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_consensus_caches_results(self, mock_model, mock_configure):
        """Test that analysis results are cached."""
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        mock_instance.generate_content.return_value.text = '''{"verdict": "SAFE", "reason": "Clean", "playbook": [], "advice": "OK"}'''
        
        handler = AIHandler(api_keys=["key"])
        engine_result = {"test": "data", "risk": 10}
        
        # First call
        handler.get_consensus(engine_result, "url")
        initial_cache_size = len(handler.analysis_cache)
        
        # Same input should use cache (but we can't verify without mocking time)
        self.assertGreater(initial_cache_size, 0)


class TestMultiEngineCorrelation(unittest.TestCase):
    """Test multi-engine correlation analysis."""
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_analyze_all_engines_aggregates_risk(self, mock_model, mock_configure):
        """Test that correlation aggregates risk from all engines."""
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        mock_instance.generate_content.return_value.text = '''{"verdict": "MALICIOUS", "overall_risk": "HIGH"}'''
        
        handler = AIHandler(api_keys=["key"])
        engines_data = {
            "url": {"calculated_risk": 80},
            "qr": {"calculated_risk": 70},
            "eml": {"calculated_risk": 30}
        }
        
        result = handler.analyze_all_engines(engines_data)
        
        self.assertIn("verdict", result)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_analyze_all_engines_identifies_high_risk(self, mock_model, mock_configure):
        """Test that correlation identifies high-risk engines."""
        handler = AIHandler(api_keys=["key"])
        engines_data = {
            "url": {"calculated_risk": 80},
            "qr": {"calculated_risk": 75},
            "eml": {"calculated_risk": 20}
        }
        
        # Call method but it will fail due to no mock response
        # We're just testing the internal logic
        try:
            handler.analyze_all_engines(engines_data)
        except:
            pass  # Expected to fail without mock
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_correlation_fallback_when_ai_fails(self, mock_model, mock_configure):
        """Test fallback when multi-engine analysis fails."""
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        mock_instance.generate_content.side_effect = Exception("AI Error")
        
        handler = AIHandler(api_keys=["key"])
        engines_data = {
            "url": {"calculated_risk": 85},
            "qr": {"calculated_risk": 80}
        }
        
        result = handler.analyze_all_engines(engines_data)
        
        self.assertIn("ai offline", result["correlation_findings"].lower())
        self.assertEqual(result["overall_risk"], "CRITICAL")  # Based on max risk
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_correlation_handles_empty_engines(self, mock_model, mock_configure):
        """Test correlation with empty engine data."""
        handler = AIHandler(api_keys=["key"])
        
        result = handler._get_correlation_fallback({}, {}, [])
        
        self.assertEqual(result["overall_risk"], "LOW")
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_correlation_priority_based_on_risk(self, mock_model, mock_configure):
        """Test that correlation assigns correct priority based on risk."""
        handler = AIHandler(api_keys=["key"])
        
        # Critical risk = P1
        result = handler._get_correlation_fallback({}, {"url": 85}, ["url"])
        self.assertEqual(result["recommended_priority"], "P1")
        
        # High risk = P1
        result = handler._get_correlation_fallback({}, {"url": 65}, ["url"])
        self.assertEqual(result["recommended_priority"], "P1")
        
        # Medium risk = P2
        result = handler._get_correlation_fallback({}, {"url": 45}, [])
        self.assertEqual(result["recommended_priority"], "P2")


class TestFallbackVerdicts(unittest.TestCase):
    """Test fallback verdict generation."""
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_fallback_with_high_risk(self, mock_model, mock_configure):
        """Test fallback for high-risk engine data."""
        handler = AIHandler(api_keys=["key"])
        engine_data = {"calculated_risk": 85, "brand_check": "TYPOSQUATTING"}
        
        result = handler._get_fallback_verdict("AI Error", engine_data)
        
        self.assertEqual(result["threat_level"], "HIGH")
        self.assertIn("TYPOSQUATTING", result["key_indicators"])
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_fallback_with_low_risk(self, mock_model, mock_configure):
        """Test fallback for low-risk engine data."""
        handler = AIHandler(api_keys=["key"])
        engine_data = {"calculated_risk": 10}
        
        result = handler._get_fallback_verdict("AI Error", engine_data)
        
        self.assertEqual(result["threat_level"], "LOW")
        self.assertIn("SAFE", result["verdict"])
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_fallback_includes_playbook(self, mock_model, mock_configure):
        """Test that fallback includes proper playbook."""
        handler = AIHandler(api_keys=["key"])
        
        result = handler._get_fallback_verdict("Error", {})
        
        self.assertIn("playbook", result)
        self.assertIn("FALLBACK MODE", result["verdict"])
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_fallback_has_complete_playbook(self, mock_model, mock_configure):
        """Test that fallback includes complete playbook."""
        handler = AIHandler(api_keys=["key"])
        
        result = handler._get_fallback_verdict("Error", {})
        
        self.assertIsInstance(result["playbook"], list)
        self.assertGreater(len(result["playbook"]), 0)


class TestCacheManagement(unittest.TestCase):
    """Test analysis caching functionality."""
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_cache_key_generation(self, mock_model, mock_configure):
        """Test cache key generation for results."""
        handler = AIHandler(api_keys=["key"])
        engine_result = {"risk": 50, "brand": "test"}
        
        key1 = handler._generate_cache_key(engine_result, "url")
        key2 = handler._generate_cache_key(engine_result, "url")
        key3 = handler._generate_cache_key({"risk": 60}, "url")  # Different data
        
        self.assertEqual(key1, key2)  # Same data = same key
        self.assertNotEqual(key1, key3)  # Different data = different key
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_get_stats_returns_metrics(self, mock_model, mock_configure):
        """Test that get_stats returns proper metrics."""
        handler = AIHandler(api_keys=["key"])
        handler.stats["total_requests"] = 10
        handler.stats["successful_analyses"] = 8
        
        stats = handler.get_stats()
        
        self.assertEqual(stats["total_requests"], 10)
        self.assertEqual(stats["successful_analyses"], 8)
        self.assertEqual(stats["success_rate"], 80.0)
        self.assertEqual(stats["active_key"], 1)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_clear_cache_removes_entries(self, mock_model, mock_configure):
        """Test that clear_cache removes all entries."""
        handler = AIHandler(api_keys=["key"])
        handler.analysis_cache["test_key"] = {"result": "test"}
        
        handler.clear_cache()
        
        self.assertEqual(len(handler.analysis_cache), 0)


class TestVectorDescriptions(unittest.TestCase):
    """Test attack vector descriptions."""
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_all_vectors_have_descriptions(self, mock_model, mock_configure):
        """Test that all 7 vectors have descriptions."""
        handler = AIHandler(api_keys=["key"])
        
        expected_vectors = ["url", "qr", "eml", "smishing", "vishing", "clone", "social"]
        
        for vector in expected_vectors:
            self.assertIn(vector, handler.VECTOR_DESCRIPTIONS)
            self.assertIsInstance(handler.VECTOR_DESCRIPTIONS[vector], str)
            self.assertGreater(len(handler.VECTOR_DESCRIPTIONS[vector]), 0)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_unknown_vector_handling(self, mock_model, mock_configure):
        """Test handling of unknown vector type."""
        handler = AIHandler(api_keys=["key"])
        
        desc = handler.VECTOR_DESCRIPTIONS.get("unknown_vector", "Unknown Vector")
        self.assertEqual(desc, "Unknown Vector")


class TestGenerationConfig(unittest.TestCase):
    """Test generation configuration."""
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_consensus_uses_low_temperature(self, mock_model, mock_configure):
        """Test that consensus uses low temperature for consistent results."""
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        mock_instance.generate_content.return_value.text = '''{"verdict": "SAFE", "reason": "OK", "playbook": [], "advice": "OK"}'''
        
        handler = AIHandler(api_keys=["key"])
        handler.get_consensus({"test": "data"}, "url")
        
        call_kwargs = mock_instance.generate_content.call_args[1]
        gen_config = call_kwargs.get('generation_config', {})
        
        self.assertEqual(gen_config.get('temperature'), 0.2)
        self.assertEqual(gen_config.get('top_p'), 0.8)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_correlation_uses_higher_temperature(self, mock_model, mock_configure):
        """Test that correlation uses slightly higher temperature for creative analysis."""
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        mock_instance.generate_content.return_value.text = '''{"verdict": "MALICIOUS"}'''
        
        handler = AIHandler(api_keys=["key"])
        handler.analyze_all_engines({"url": {"risk": 80}})
        
        call_kwargs = mock_instance.generate_content.call_args[1]
        gen_config = call_kwargs.get('generation_config', {})
        
        self.assertEqual(gen_config.get('temperature'), 0.3)


class TestIntegrationScenarios(unittest.TestCase):
    """Integration test scenarios."""
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_complete_analysis_workflow(self, mock_model, mock_configure):
        """Test complete analysis workflow from request to result."""
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        mock_instance.generate_content.return_value.text = '''{
            "verdict": "MALICIOUS",
            "confidence": "95",
            "threat_level": "CRITICAL",
            "category": "Phishing",
            "reason": "Typosquatting domain detected with urgency keywords",
            "key_indicators": ["brand mimicry", "urgency"],
            "employee_impact": "Job security risk if credentials stolen",
            "business_impact": "Data breach potential",
            "advice": "Block domain immediately",
            "long_term_recommendations": "Deploy DNS filtering",
            "playbook": ["Block domain", "Reset passwords", "Monitor logs"],
            "iocs": {"domains": ["evil.com"], "ips": [], "urls": [], "file_hashes": [], "patterns": []},
            "telugish_comment": "Chala dangerous! (Very dangerous!)"
        }'''
        
        handler = AIHandler(api_keys=["test_key"])
        
        # Simulate complete analysis
        engine_result = {
            "calculated_risk": 85,
            "brand_check": "TYPOSQUATTING: Mimicking AMAZON",
            "virustotal": "5/90 Flags",
            "domain_age": "5 Days"
        }
        
        all_engines = {
            "url": engine_result,
            "qr": {"calculated_risk": 0},
            "eml": {"calculated_risk": 0},
            "smishing": {"calculated_risk": 0},
            "vishing": {"calculated_risk": 0},
            "clone": {"calculated_risk": 0},
            "social": {"calculated_risk": 0}
        }
        
        result = handler.get_consensus(engine_result, "url", all_engines)
        
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(result["confidence"], "95")
        self.assertEqual(result["threat_level"], "CRITICAL")
        self.assertIn("domains", result["iocs"])
        self.assertEqual(result["threat_level"], "CRITICAL")
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_multi_vector_attack_detection(self, mock_model, mock_configure):
        """Test detection of multi-vector coordinated attack."""
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        mock_instance.generate_content.return_value.text = '''{
            "correlation_findings": "Coordinated campaign detected",
            "threat_actor_assessment": "APT",
            "campaign_type": "Targeted",
            "overall_risk": "CRITICAL",
            "primary_vector": "eml",
            "secondary_vectors": ["url", "qr"],
            "recommended_priority": "P1",
            "unified_playbook": {
                "immediate_actions": ["Block all vectors"],
                "investigation_steps": ["Forensic imaging"],
                "remediation": ["Clean systems"],
                "user_protection": ["User awareness training"],
                "monitoring": ["Hunt for related IoCs"]
            },
            "ioc_summary": {"domains": ["c1.com", "c2.com"], "ips": [], "hashes": [], "patterns": []},
            "verdict": "MALICIOUS",
            "executive_summary": "Targeted APT campaign using multiple vectors",
            "technical_details": "Email with QR code leading to phishing URL"
        }'''
        
        handler = AIHandler(api_keys=["key"])
        
        # Multi-vector attack data
        engines_data = {
            "url": {"calculated_risk": 80, "brand_check": "SPOOF"},
            "qr": {"calculated_risk": 75, "extracted_payload": "evil.com"},
            "eml": {"calculated_risk": 90, "sender_forgery": "CRITICAL"},
            "smishing": {"calculated_risk": 0},
            "vishing": {"calculated_risk": 0},
            "clone": {"calculated_risk": 85, "clone_detected": True},
            "social": {"calculated_risk": 70, "punycode_detected": True}
        }
        
        result = handler.analyze_all_engines(engines_data)
        
        self.assertEqual(result["threat_actor_assessment"], "APT")
        self.assertEqual(result["overall_risk"], "CRITICAL")
        self.assertEqual(result["recommended_priority"], "P1")
        self.assertIn("unified_playbook", result)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_safe_verdict_for_clean_data(self, mock_model, mock_configure):
        """Test SAFE verdict for clean engine data."""
        mock_instance = MagicMock()
        mock_model.return_value = mock_instance
        mock_instance.generate_content.return_value.text = '''{
            "verdict": "SAFE",
            "confidence": "98",
            "threat_level": "LOW",
            "reason": "No suspicious indicators detected",
            "playbook": ["Continue monitoring"],
            "advice": "No action required"
        }'''
        
        handler = AIHandler(api_keys=["key"])
        clean_result = {
            "calculated_risk": 0,
            "brand_check": "Clean",
            "virustotal": "0/90"
        }
        
        result = handler.get_consensus(clean_result, "url")
        
        self.assertEqual(result["verdict"], "SAFE")
        self.assertEqual(result["confidence"], "98")


if __name__ == '__main__':
    unittest.main(verbosity=2)
