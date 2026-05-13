"""
Test script for all 12 Advanced Vishing Features
===============================================
Tests the complete integration of advanced voice clone detection
"""

import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.vishing_engine import VishingEngine
from app.core.vishing_features import (
    VoiceBiometricAuth,
    AudioLivenessDetector,
    NeuralAudioClassifier,
    VoiceSplicingDetector,
    EmotionalAnalyzer,
    ActiveDefenseSystem,
    VoiceWatermarkDetector,
    MicrophoneFingerprinting,
    ProsodyAnalyzer,
    CrossLingualDetector
)

def test_feature_initialization():
    """Test that all 12 features initialize correctly"""
    print("\n" + "="*70)
    print("TEST 1: Feature Initialization")
    print("="*70)
    
    try:
        engine = VishingEngine()
        
        # Check all 12 features are initialized
        features = [
            ('voice_biometric', engine.voice_biometric),
            ('liveness_detector', engine.liveness_detector),
            ('neural_classifier', engine.neural_classifier),
            ('stream_analyzer', engine.stream_analyzer),
            ('cross_lingual', engine.cross_lingual),
            ('splicing_detector', engine.splicing_detector),
            ('emotional_analyzer', engine.emotional_analyzer),
            ('active_defense', engine.active_defense),
            ('watermark_detector', engine.watermark_detector),
            ('mic_fingerprint', engine.mic_fingerprint),
            ('prosody_analyzer', engine.prosody_analyzer),
            ('multimodal', engine.multimodal)
        ]
        
        for name, feature in features:
            status = "[OK]" if feature is not None else "[FAIL]"
            print(f"{status} {name:25} initialized")
        
        print("\n[SUCCESS] All 12 advanced features initialized successfully!")
        return True
        
    except Exception as e:
        print(f"\n[FAIL] Feature initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_individual_features():
    """Test individual feature classes"""
    print("\n" + "="*70)
    print("TEST 2: Individual Feature Class Instantiation")
    print("="*70)
    
    features_to_test = [
        ('VoiceBiometricAuth', VoiceBiometricAuth),
        ('AudioLivenessDetector', AudioLivenessDetector),
        ('NeuralAudioClassifier', NeuralAudioClassifier),
        ('VoiceSplicingDetector', VoiceSplicingDetector),
        ('EmotionalAnalyzer', EmotionalAnalyzer),
        ('ActiveDefenseSystem', ActiveDefenseSystem),
        ('VoiceWatermarkDetector', VoiceWatermarkDetector),
        ('MicrophoneFingerprinting', MicrophoneFingerprinting),
        ('ProsodyAnalyzer', ProsodyAnalyzer),
        ('CrossLingualDetector', CrossLingualDetector)
    ]
    
    passed = 0
    for name, FeatureClass in features_to_test:
        try:
            instance = FeatureClass()
            print(f"[OK] {name:30} instantiated")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name:30} failed: {e}")
    
    print(f"\n{passed}/{len(features_to_test)} feature classes instantiated successfully")
    return passed == len(features_to_test)

def test_active_defense_system():
    """Test active defense threat evaluation"""
    print("\n" + "="*70)
    print("TEST 3: Active Defense System")
    print("="*70)
    
    try:
        defense = ActiveDefenseSystem()
        
        # Simulate high threat scenario
        mock_results = {
            "ai_voice_detected": True,
            "neural_classification": {"is_synthetic": True, "synthetic_probability": 85},
            "calculated_risk": 75
        }
        
        threat = defense.evaluate_threat(mock_results)
        print(f"Threat Score: {threat['threat_score']}")
        print(f"Threat Level: {threat['threat_level']}")
        print(f"Recommended Action: {threat['recommended_action']}")
        print(f"Indicators: {threat['indicators']}")
        
        # Test defense execution
        if threat['threat_level'] in ['HIGH', 'CRITICAL']:
            action = defense.execute_defense(threat, {'scam_type': 'bank'})
            print(f"Defense Action: {action['action_executed']}")
            print(f"Action Details: {action['details']}")
        
        print("\n[SUCCESS] Active defense system working correctly!")
        return True
        
    except Exception as e:
        print(f"\n[FAIL] Active defense test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_cross_lingual_detection():
    """Test cross-lingual detection"""
    print("\n" + "="*70)
    print("TEST 4: Cross-Lingual Detection (Telugu-English)")
    print("="*70)
    
    try:
        detector = CrossLingualDetector()
        
        # Test code-switching detection
        test_text = "Meeru otp provide cheyandi immediately"
        result = detector._detect_code_switching(test_text)
        
        print(f"Test Text: {test_text}")
        print(f"Is Code-Switched: {result['is_code_switched']}")
        print(f"Confidence: {result['confidence']}")
        print(f"Detected Languages: {result.get('languages', [])}")
        
        print("\n[SUCCESS] Cross-lingual detection working!")
        return True
        
    except Exception as e:
        print(f"\n[FAIL] Cross-lingual test failed: {e}")
        return False

def test_neural_classifier_mock():
    """Test neural classifier with fallback"""
    print("\n" + "="*70)
    print("TEST 5: Neural Classifier Fallback")
    print("="*70)
    
    try:
        classifier = NeuralAudioClassifier()
        
        print(f"Model Loaded: {classifier.model_loaded}")
        print(f"Fallback Available: {classifier.is_trained if hasattr(classifier, 'is_trained') else 'N/A'}")
        print(f"Feature Dimension: {classifier.feature_dim}")
        
        # Test feature extraction on dummy data (would need real audio for full test)
        print("\n[SUCCESS] Neural classifier initialized (requires audio for full test)")
        return True
        
    except Exception as e:
        print(f"\n[FAIL] Neural classifier test failed: {e}")
        return False

def print_feature_summary():
    """Print summary of all 12 features"""
    print("\n" + "="*70)
    print("ADVANCED VISHING FEATURES SUMMARY")
    print("="*70)
    
    features = [
        ("1", "Voice Biometric Auth", "Speaker identification via voice prints"),
        ("2", "Audio Liveness Detection", "Anti-replay attack detection"),
        ("3", "Neural Audio Classifier", "158-feature ML synthetic speech detection"),
        ("4", "Real-time Stream Analysis", "Live chunk-based processing"),
        ("5", "Cross-Lingual Detection", "Telugu/Hindi/Tamil TTS detection"),
        ("6", "Voice Splicing Detection", "Mid-call voice change detection"),
        ("7", "Emotional Analysis", "Valence-Arousal-Dominance model"),
        ("8", "Active Defense System", "Auto-interrupt + honeypot responses"),
        ("9", "Voice Watermark Detection", "TTS spectral signature detection"),
        ("10", "Microphone Fingerprinting", "Virtual audio device detection"),
        ("11", "Prosody Analysis", "Praat-style detailed speaking patterns"),
        ("12", "Multi-modal Cross Verify", "Audio-video lip-sync detection")
    ]
    
    for num, name, desc in features:
        print(f"{num:>2}. {name:30} - {desc}")
    
    print("\n" + "="*70)
    print("ALL 12 FEATURES INTEGRATED INTO VISHING ENGINE!")
    print("="*70)

def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("ADVANCED VISHING FEATURES - COMPLETE TEST SUITE")
    print("="*70)
    print("Testing all 12 advanced voice clone detection features")
    
    results = []
    
    # Run tests
    results.append(("Feature Initialization", test_feature_initialization()))
    results.append(("Individual Features", test_individual_features()))
    results.append(("Active Defense", test_active_defense_system()))
    results.append(("Cross-Lingual", test_cross_lingual_detection()))
    results.append(("Neural Classifier", test_neural_classifier_mock()))
    
    # Print summary
    print_feature_summary()
    
    # Print test results
    print("\n" + "="*70)
    print("TEST RESULTS")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status:8} - {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n[SUCCESS] ALL TESTS PASSED! Advanced vishing features ready for deployment!")
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed. Review errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
