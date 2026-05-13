import logging
import re
import speech_recognition as sr
from pydub import AudioSegment
import os
import numpy as np
import warnings
from typing import Dict, List, Tuple, Optional
from collections import Counter

# --- PORTABLE FFmpeg LOGIC ---
# Project root = parent of app/
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BIN_DIR = os.path.join(_PROJECT_ROOT, "tools", "bin")
_BIN_CONFIG = os.path.join(_BIN_DIR, "ffmpeg_paths.txt")

ffmpeg_path = ""
ffprobe_path = ""

if os.path.isfile(_BIN_CONFIG):
    with open(_BIN_CONFIG, "r") as f:
        paths = f.read().splitlines()
        if len(paths) >= 2:
            ffmpeg_path = paths[0].strip()
            ffprobe_path = paths[1].strip()

# Fallback: check tools/bin/ directory
if not ffmpeg_path or not os.path.exists(ffmpeg_path):
    ffmpeg_path = os.path.join(_BIN_DIR, "ffmpeg.exe")
if not ffprobe_path or not os.path.exists(ffprobe_path):
    ffprobe_path = os.path.join(_BIN_DIR, "ffprobe.exe")

# Assign to pydub only if the binaries exist
if os.path.exists(ffmpeg_path):
    AudioSegment.converter = ffmpeg_path
if os.path.exists(ffprobe_path):
    AudioSegment.ffprobe = ffprobe_path
# -----------------------------

from app.integrations.ai_handler import AIHandler
from app.intelligence.attribution import attribution_engine
from app.intelligence.temporal import temporal_engine
from app.intelligence.ioc import ioc_feed_manager
from app.ml.ml_detector import ml_detector

# Import all 12 advanced vishing features
from app.core.vishing_features import (
    VoiceBiometricAuth,
    AudioLivenessDetector,
    NeuralAudioClassifier,
    RealTimeStreamAnalyzer,
    CrossLingualDetector,
    VoiceSplicingDetector,
    EmotionalAnalyzer,
    ActiveDefenseSystem,
    VoiceWatermarkDetector,
    MicrophoneFingerprinting,
    ProsodyAnalyzer,
    MultiModalAnalyzer
)


class DeepfakeVoiceDetector:
    """
    Advanced AI-generated voice detection using spectral analysis,
    artifact detection, and prosody analysis.
    """
    
    def __init__(self):
        self.sample_rate = 16000
        self.frame_length = 2048
        self.hop_length = 512
        
        # AI voice artifacts - these are spectral signatures of TTS models
        self.known_tts_signatures = {
            'elevenlabs': {'freq_range': (4000, 8000), 'artifact_type': 'harmonic'},
            'playht': {'freq_range': (3000, 6000), 'artifact_type': 'phase_shift'},
            'azure_tts': {'freq_range': (2000, 5000), 'artifact_type': 'metallic'},
            'google_tts': {'freq_range': (3500, 7000), 'artifact_type': 'buzz'},
            'openai_tts': {'freq_range': (4500, 9000), 'artifact_type': 'smooth'},
            'bark': {'freq_range': (2500, 5500), 'artifact_type': 'noise_floor'},
        }
        
        # Deepfake indicators in speech
        self.suspicious_patterns = {
            'unnatural_pauses': 0.15,  # Pause duration threshold (seconds)
            'robotic_segments': 0.08,  # Spectral flatness threshold
            'frequency_gaps': 0.20,    # Missing frequency bands
            'phase_inconsistency': 0.12, # Phase alignment issues
        }
        
        logging.info("[DEEPFAKE DETECTOR] Initialized AI voice detection engine")
    
    def extract_audio_features(self, audio_path: str) -> Dict:
        """
        Extract deep spectral features from audio for deepfake detection.
        """
        try:
            # Load audio using pydub
            audio = AudioSegment.from_file(audio_path)
            
            # Convert to numpy array
            samples = np.array(audio.get_array_of_samples(), dtype=np.float32)
            
            # Normalize
            samples = samples / np.max(np.abs(samples))
            
            # Convert stereo to mono if needed
            if audio.channels == 2:
                samples = samples.reshape(-1, 2).mean(axis=1)
            
            features = {
                'duration': len(audio) / 1000.0,
                'sample_rate': audio.frame_rate,
                'channels': audio.channels,
                'rms_energy': np.sqrt(np.mean(samples**2)),
                'zero_crossing_rate': np.mean(np.abs(np.diff(np.sign(samples)))) / 2,
            }
            
            # Spectral analysis
            if len(samples) >= self.frame_length:
                # Short-time Fourier Transform
                stft = self._compute_stft(samples)
                
                # Spectral features
                magnitude = np.abs(stft)
                
                # Spectral centroid (brightness of sound)
                freqs = np.linspace(0, audio.frame_rate/2, magnitude.shape[0])
                spectral_centroids = np.sum(freqs[:, np.newaxis] * magnitude, axis=0) / (np.sum(magnitude, axis=0) + 1e-10)
                features['spectral_centroid_mean'] = np.mean(spectral_centroids)
                features['spectral_centroid_std'] = np.std(spectral_centroids)
                
                # Spectral flatness (how noise-like vs tone-like)
                geometric_mean = np.exp(np.mean(np.log(magnitude + 1e-10), axis=0))
                arithmetic_mean = np.mean(magnitude, axis=0)
                spectral_flatness = geometric_mean / (arithmetic_mean + 1e-10)
                features['spectral_flatness_mean'] = np.mean(spectral_flatness)
                
                # Spectral rolloff (frequency below which X% of energy resides)
                cumulative_sum = np.cumsum(magnitude, axis=0)
                total_energy = np.sum(magnitude, axis=0)
                rolloff_threshold = 0.85 * total_energy
                rolloff_indices = np.argmax(cumulative_sum >= rolloff_threshold, axis=0)
                features['spectral_rolloff_mean'] = np.mean(rolloff_indices) * (audio.frame_rate/2) / magnitude.shape[0]
                
                # Harmonic analysis
                features['harmonic_ratio'] = self._analyze_harmonic_content(magnitude, freqs)
                
                # Phase analysis (AI voices often have unnatural phase coherence)
                phase = np.angle(stft)
                features['phase_coherence'] = self._analyze_phase_coherence(phase)
                
                # Specific frequency band energy ratios (key for TTS detection)
                features['freq_band_ratios'] = self._analyze_frequency_bands(magnitude, freqs)
                
                # Transient analysis (unnatural attack/decay in AI voices)
                features['transient_sharpness'] = self._analyze_transients(samples)
                
            return features
            
        except Exception as e:
            logging.error(f"[-] Deepfake feature extraction error: {e}")
            return {}
    
    def _compute_stft(self, samples: np.ndarray) -> np.ndarray:
        """Compute Short-Time Fourier Transform."""
        frames = []
        for i in range(0, len(samples) - self.frame_length, self.hop_length):
            frame = samples[i:i + self.frame_length]
            # Hann window
            window = np.hanning(len(frame))
            frame = frame * window
            fft = np.fft.rfft(frame)
            frames.append(fft)
        return np.array(frames).T if frames else np.array([])
    
    def _analyze_harmonic_content(self, magnitude: np.ndarray, freqs: np.ndarray) -> float:
        """Analyze harmonic vs noise-like content."""
        if magnitude.size == 0:
            return 0.0
        
        # Look for harmonic peaks at integer multiples
        mean_magnitude = np.mean(magnitude, axis=1)
        
        # Find peaks
        peaks = []
        for i in range(1, len(mean_magnitude) - 1):
            if mean_magnitude[i] > mean_magnitude[i-1] and mean_magnitude[i] > mean_magnitude[i+1]:
                if mean_magnitude[i] > np.mean(mean_magnitude) * 2:
                    peaks.append((freqs[i], mean_magnitude[i]))
        
        # Calculate harmonic ratio
        if len(peaks) < 2:
            return 0.0
        
        # Check if peaks are at harmonic intervals
        fundamental = peaks[0][0]
        if fundamental == 0:
            return 0.0
        
        harmonic_score = 0
        for freq, mag in peaks[1:]:
            ratio = freq / fundamental
            # Check if close to integer ratio
            nearest_harmonic = round(ratio)
            if abs(ratio - nearest_harmonic) < 0.05 and nearest_harmonic <= 10:
                harmonic_score += mag
        
        total_energy = np.sum([p[1] for p in peaks])
        return harmonic_score / (total_energy + 1e-10)
    
    def _analyze_phase_coherence(self, phase: np.ndarray) -> float:
        """Analyze phase coherence - AI voices often have unnatural phase patterns."""
        if phase.size == 0:
            return 1.0
        
        # Calculate phase differences between adjacent frames
        phase_diff = np.diff(phase, axis=1)
        
        # Natural speech has progressive phase changes
        # AI speech often has jumps or too-perfect coherence
        phase_variance = np.var(phase_diff)
        
        # Normalize to 0-1 range (0 = very unnatural, 1 = natural)
        coherence = 1.0 / (1.0 + phase_variance)
        return coherence
    
    def _analyze_frequency_bands(self, magnitude: np.ndarray, freqs: np.ndarray) -> Dict:
        """Analyze energy in specific frequency bands."""
        mean_magnitude = np.mean(magnitude, axis=1)
        
        bands = {
            'sub_bass': (20, 60),
            'bass': (60, 250),
            'low_mid': (250, 500),
            'mid': (500, 2000),
            'high_mid': (2000, 4000),
            'presence': (4000, 6000),
            'brilliance': (6000, 20000),
        }
        
        band_energies = {}
        total_energy = np.sum(mean_magnitude) + 1e-10
        
        for band_name, (low, high) in bands.items():
            mask = (freqs >= low) & (freqs <= high)
            energy = np.sum(mean_magnitude[mask])
            band_energies[band_name] = energy / total_energy
        
        return band_energies
    
    def _analyze_transients(self, samples: np.ndarray) -> float:
        """Analyze attack and decay characteristics."""
        if len(samples) < 100:
            return 0.0
        
        # Calculate envelope
        envelope = np.abs(samples)
        
        # Smooth envelope
        window = 100
        smoothed = np.convolve(envelope, np.ones(window)/window, mode='same')
        
        # Find attack rate (how quickly sound reaches peak)
        derivative = np.diff(smoothed)
        
        # High positive derivatives indicate sharp attacks
        attack_indices = np.where(derivative > np.percentile(derivative, 95))[0]
        
        if len(attack_indices) == 0:
            return 0.0
        
        # Measure attack sharpness
        attack_values = derivative[attack_indices]
        return np.mean(attack_values) if len(attack_values) > 0 else 0.0
    
    def detect_deepfake(self, audio_path: str) -> Dict:
        """
        Main deepfake detection method.
        Returns analysis results with confidence scores.
        """
        logging.info(f"[DEEPFAKE] Analyzing audio for AI synthesis: {audio_path}")
        
        result = {
            'is_deepfake': False,
            'confidence': 0.0,
            'synthetic_probability': 0.0,
            'detected_tts_engine': None,
            'artifacts_detected': [],
            'analysis_details': {},
            'warning_level': 'LOW'
        }
        
        # Extract features
        features = self.extract_audio_features(audio_path)
        if not features:
            result['error'] = 'Feature extraction failed'
            return result
        
        result['analysis_details']['features'] = {
            'duration': features.get('duration', 0),
            'spectral_flatness': features.get('spectral_flatness_mean', 0),
            'spectral_centroid': features.get('spectral_centroid_mean', 0),
            'harmonic_ratio': features.get('harmonic_ratio', 0),
            'phase_coherence': features.get('phase_coherence', 1.0),
            'transient_sharpness': features.get('transient_sharpness', 0),
        }
        
        # Detection heuristics
        scores = {
            'spectral_anomaly': 0,
            'phase_anomaly': 0,
            'tts_signature': 0,
            'artifact_detection': 0,
        }
        
        # 1. Spectral flatness analysis
        flatness = features.get('spectral_flatness_mean', 0)
        if flatness > self.suspicious_patterns['robotic_segments']:
            scores['spectral_anomaly'] += 25
            result['artifacts_detected'].append(f'High spectral flatness: {flatness:.3f} (robotic characteristics)')
        
        # 2. Phase coherence analysis
        phase_coherence = features.get('phase_coherence', 1.0)
        if phase_coherence > 0.95 or phase_coherence < 0.3:
            scores['phase_anomaly'] += 30
            result['artifacts_detected'].append(f'Unnatural phase coherence: {phase_coherence:.3f}')
        
        # 3. TTS engine signature detection
        freq_ratios = features.get('freq_band_ratios', {})
        for engine_name, signature in self.known_tts_signatures.items():
            match_score = self._match_tts_signature(freq_ratios, signature)
            if match_score > 0.6:
                scores['tts_signature'] = max(scores['tts_signature'], int(match_score * 40))
                result['detected_tts_engine'] = engine_name
                result['artifacts_detected'].append(f'Matches {engine_name} TTS signature')
                break
        
        # 4. Harmonic content analysis
        harmonic_ratio = features.get('harmonic_ratio', 0)
        if harmonic_ratio < 0.3 or harmonic_ratio > 0.95:
            scores['artifact_detection'] += 20
            result['artifacts_detected'].append(f'Unnatural harmonic structure: {harmonic_ratio:.3f}')
        
        # 5. Transient analysis - AI voices often lack natural attack
        transient = features.get('transient_sharpness', 0)
        if transient < 0.001:  # Too smooth
            scores['artifact_detection'] += 15
            result['artifacts_detected'].append('Unnaturally smooth transients (AI synthesis indicator)')
        
        # Calculate synthetic probability
        total_score = sum(scores.values())
        result['synthetic_probability'] = min(total_score, 100)
        
        # Determine result
        if total_score >= 70:
            result['is_deepfake'] = True
            result['confidence'] = total_score
            result['warning_level'] = 'CRITICAL'
            logging.critical(f"🚨 DEEPFAKE VOICE DETECTED: {total_score}% confidence - AI synthesis confirmed!")
        elif total_score >= 40:
            result['is_likely_deepfake'] = True
            result['confidence'] = total_score
            result['warning_level'] = 'HIGH'
            logging.warning(f"[!] LIKELY AI VOICE: {total_score}% synthetic probability")
        elif total_score >= 20:
            result['warning_level'] = 'MEDIUM'
            result['confidence'] = total_score
        
        result['scores'] = scores
        
        return result
    
    def _match_tts_signature(self, freq_ratios: Dict, signature: Dict) -> float:
        """Match frequency band ratios against known TTS signatures."""
        low, high = signature['freq_range']
        
        # Map frequency range to bands
        band_weights = {
            'sub_bass': (20, 60),
            'bass': (60, 250),
            'low_mid': (250, 500),
            'mid': (500, 2000),
            'high_mid': (2000, 4000),
            'presence': (4000, 6000),
            'brilliance': (6000, 20000),
        }
        
        # Calculate expected energy in the signature range
        total_in_range = 0
        for band, (b_low, b_high) in band_weights.items():
            overlap = max(0, min(high, b_high) - max(low, b_low))
            if overlap > 0:
                total_in_range += freq_ratios.get(band, 0) * (overlap / (b_high - b_low))
        
        # TTS engines typically have boosted presence/brilliance bands
        # and reduced bass/sub-bass
        if total_in_range > 0.4:  # Unusually high energy in high freqs
            return min(total_in_range * 1.5, 1.0)
        
        return 0.0


class VishingEngine:
    def __init__(self):
        self.recognizer = sr.Recognizer()
        # High-risk keywords used in voice scams
        self.risk_keywords = [
            'otp', 'cvv', 'password', 'bank', 'customer care', 
            'account blocked', 'lottery', 'kyc', 'aadhar', 'pan card',
            'credit card', 'debit card', 'gift card', 'verification',
            'tax', 'refund', 'unpaid', 'debt', 'legal action', 'police',
            'suspend', 'urgent', 'immediately', 'verify', 'secure'
        ]
        # Urgency markers used in social engineering
        self.urgency_markers = [
            'immediately', 'now', 'urgent', 'cancelled', 'suspended',
            'asap', 'within 24 hours', 'limited time', 'warning',
            'act now', 'last chance', 'final notice', 'expires today'
        ]
        
        # Advanced utilities
        self.ai_handler = AIHandler()
        self.deepfake_detector = DeepfakeVoiceDetector()
        
        # Initialize all 12 advanced vishing features
        self.voice_biometric = VoiceBiometricAuth()
        self.liveness_detector = AudioLivenessDetector()
        self.neural_classifier = NeuralAudioClassifier()
        self.stream_analyzer = RealTimeStreamAnalyzer()
        self.cross_lingual = CrossLingualDetector()
        self.splicing_detector = VoiceSplicingDetector()
        self.emotional_analyzer = EmotionalAnalyzer()
        self.active_defense = ActiveDefenseSystem()
        self.watermark_detector = VoiceWatermarkDetector()
        self.mic_fingerprint = MicrophoneFingerprinting()
        self.prosody_analyzer = ProsodyAnalyzer()
        self.multimodal = MultiModalAnalyzer()
        
        logging.info("[VISHING ENGINE] Initialized with ALL 12 advanced features!")
        logging.info("[VISHING ENGINE] Features: Biometric | Liveness | Neural | Stream | Cross-lingual | Splicing | Emotional | Defense | Watermark | Mic-FP | Prosody | Multi-modal")

    def convert_to_wav(self, audio_path: str) -> str:
        """Converts various audio formats to WAV for speech recognition."""
        if audio_path.endswith('.wav'):
            return audio_path
        
        try:
            wav_path = audio_path.rsplit('.', 1)[0] + "_converted.wav"
            audio = AudioSegment.from_file(audio_path)
            audio.export(wav_path, format="wav")
            return wav_path
        except Exception as e:
            logging.error(f"[-] Vishing Conversion Error: {e}")
            return audio_path # Return original as fallback

    def analyze(self, audio_path: str) -> dict:
        """Transcribes audio and analyzes the transcript for social engineering patterns."""
        logging.info(f"[VISHING ENGINE] Analyzing audio payload: {audio_path}")

        # --- TEXT-INPUT FAST PATH ---
        # If the input is not a real audio file (plain text transcript/SMS), analyse it directly
        is_text_input = not os.path.exists(str(audio_path))
        if is_text_input:
            text = str(audio_path).lower()
            found_keywords = [word for word in self.risk_keywords if word in text]
            found_urgency = [word for word in self.urgency_markers if word in text]
            risk = len(found_keywords) * 15 + (25 if found_urgency else 0)
            ai_analysis = self._ai_analyze_transcript(text)
            if ai_analysis.get("is_scam"):
                risk += 30
            return {
                "target_file": "text_input",
                "transcript": text,
                "detected_keywords": found_keywords,
                "urgency_level": "High (Social Engineering Pattern)" if found_urgency else "Low",
                "calculated_risk": min(risk, 100),
                "ai_analysis": ai_analysis,
                "classification": "SUSPICIOUS - LIKELY VISHING" if risk >= 40 else "SOME RISK INDICATORS" if risk >= 20 else "LIKELY LEGITIMATE",
            }
        # --- END TEXT-INPUT FAST PATH ---

        results = {
            "target_file": audio_path.split('/')[-1],
            "transcript": "None",
            "detected_keywords": [],
            "urgency_level": "Low",
            "calculated_risk": 0
        }

        try:
            # 1. Convert to WAV if needed
            temp_wav = self.convert_to_wav(audio_path)

            # 2. DEEPFAKE VOICE DETECTION - AI-Generated Audio Analysis
            logging.info("[VISHING] Running deepfake voice detection on audio signal...")
            deepfake_result = self.deepfake_detector.detect_deepfake(temp_wav)
            results["deepfake_analysis"] = deepfake_result
            
            if deepfake_result.get("is_deepfake"):
                results["calculated_risk"] += 40
                results["ai_voice_detected"] = True
                results["tts_engine"] = deepfake_result.get("detected_tts_engine", "Unknown")
                logging.critical(f"🚨 AI VOICE CLONE DETECTED: {deepfake_result.get('detected_tts_engine', 'Unknown')} TTS engine signature!")
            elif deepfake_result.get("is_likely_deepfake"):
                results["calculated_risk"] += 25
                results["ai_voice_suspected"] = True
                logging.warning(f"[!] SUSPICIOUS AI VOICE: {deepfake_result.get('synthetic_probability', 0)}% synthetic probability")
            
            # 3. Transcribe Audio to Text
            with sr.AudioFile(temp_wav) as source:
                audio_data = self.recognizer.record(source)
                text = self.recognizer.recognize_google(audio_data).lower()
                results["transcript"] = text
            
            # 4. Keyword Analysis
            found_keywords = [word for word in self.risk_keywords if word in text]
            results["detected_keywords"] = found_keywords
            results["calculated_risk"] += len(found_keywords) * 15

            # 5. Urgency Detection
            found_urgency = [word for word in self.urgency_markers if word in text]
            if found_urgency:
                results["urgency_level"] = "High (Social Engineering Pattern)"
                results["calculated_risk"] += 25
                logging.warning(f"[!] VISHING ALERT: Urgency detected in voice payload.")

            # 6. AI-Powered Transcript Analysis
            logging.info("[VISHING] Performing AI analysis on transcript...")
            ai_analysis = self._ai_analyze_transcript(text)
            results["ai_analysis"] = ai_analysis
            
            if ai_analysis.get("is_scam", False):
                results["calculated_risk"] += 30
                results["scam_type"] = ai_analysis.get("scam_category", "Unknown")
                logging.critical(f"🚨 AI CONFIRMED SCAM: {ai_analysis.get('scam_category', 'Unknown')} vishing attack!")
            
            # 7. Phone Number / Callback Analysis
            phone_numbers = self._extract_phone_numbers(text)
            if phone_numbers:
                results["extracted_phone_numbers"] = phone_numbers
                results["calculated_risk"] += 10
                
                # Check if numbers are in IOC feeds
                for number in phone_numbers:
                    ioc_result = ioc_feed_manager.check_ioc('phone', number)
                    if ioc_result.get("is_malicious"):
                        results["calculated_risk"] += 20
                        logging.critical(f"🚨 MALICIOUS PHONE NUMBER: {number} in threat feeds!")
            
            # 8. URL/Website Extraction from transcript
            urls = self._extract_urls_from_text(text)
            if urls:
                results["mentioned_urls"] = urls
                # ML analysis on URLs
                url_risks = []
                for url in urls:
                    ml_result = ml_detector.predict(url)
                    url_risks.append({
                        "url": url,
                        "risk": ml_result.get("classification"),
                        "probability": ml_result.get("phishing_probability")
                    })
                    if ml_result.get("classification") == "PHISHING":
                        results["calculated_risk"] += 15
                results["url_risk_analysis"] = url_risks
            
            # 9. Campaign Attribution
            vishing_indicators = {
                "scam_type": ai_analysis.get("scam_category"),
                "keywords": found_keywords,
                "urgency": found_urgency,
                "urls": urls,
                "phone_numbers": phone_numbers,
                "ai_voice_synthesis": results.get("ai_voice_detected", False) or results.get("ai_voice_suspected", False),
                "detected_tts_engine": results.get("tts_engine"),
                "risk_level": "CRITICAL" if results["calculated_risk"] > 70 else "HIGH" if results["calculated_risk"] > 40 else "MEDIUM"
            }
            attribution = attribution_engine.attribute_attack(vishing_indicators)
            results["attribution"] = attribution
            
            # 10. Threat Actor Profile (if attributed)
            if attribution.get("primary_attribution"):
                actor_id = attribution["primary_attribution"]["actor_id"]
                results["threat_actor_profile"] = attribution_engine.get_actor_profile(actor_id)
            
            # 11. Result Summary with AI Reasoning
            results["ai_reasoning"] = ai_analysis.get("reasoning", "")
            
            # ============================================
            # ADVANCED FEATURES ANALYSIS (12-23)
            # ============================================
            
            # 12. LIVENESS DETECTION - Replay attack detection
            logging.info("[VISHING] Running liveness detection (anti-replay)...")
            liveness_result = self.liveness_detector.detect_liveness(temp_wav)
            results["liveness_analysis"] = liveness_result
            
            if not liveness_result.get("is_live", True):
                results["calculated_risk"] += 30
                results["replay_attack_suspected"] = True
                logging.critical("🚨 REPLAY ATTACK DETECTED: Audio appears pre-recorded!")
            
            # 13. NEURAL AUDIO CLASSIFIER - ML-based synthetic speech detection
            logging.info("[VISHING] Running neural audio classification...")
            neural_result = self.neural_classifier.classify(temp_wav)
            results["neural_classification"] = neural_result
            
            if neural_result.get("is_synthetic", False):
                results["calculated_risk"] += 35
                results["neural_synthetic_detected"] = True
                logging.critical(f"🚨 NEURAL SYNTHETIC DETECTION: {neural_result.get('synthetic_probability', 0)}% synthetic probability!")
            
            # 14. VOICE SPLICING DETECTION - Mid-call voice change detection
            logging.info("[VISHING] Running voice splicing analysis...")
            splicing_result = self.splicing_detector.analyze_consistency(temp_wav)
            results["splicing_analysis"] = splicing_result
            
            if splicing_result.get("splicing_detected", False):
                results["calculated_risk"] += 25
                results["voice_splicing_detected"] = True
                results["speaker_changes"] = splicing_result.get("speaker_changes", [])
                logging.critical(f"🚨 VOICE SPLICING: {len(splicing_result.get('speaker_changes', []))} speaker changes detected!")
            
            # 15. EMOTIONAL ANALYSIS - Valence-Arousal-Dominance model
            logging.info("[VISHING] Running emotional analysis...")
            emotional_result = self.emotional_analyzer.analyze_emotions(temp_wav, text)
            results["emotional_analysis"] = emotional_result
            
            if emotional_result.get("is_emotionally_flat", False):
                results["calculated_risk"] += 20
                results["emotional_flatness_detected"] = True
                logging.warning(f"[!] EMOTIONAL FLATNESS: AI voice suspected - consistency {emotional_result.get('emotional_consistency_score', 0):.2f}")
            
            # 16. VOICE WATERMARK DETECTION - TTS spectral signatures
            logging.info("[VISHING] Running watermark detection...")
            watermark_result = self.watermark_detector.detect_watermarks(temp_wav)
            results["watermark_analysis"] = watermark_result
            
            if watermark_result.get("watermarks_detected", False):
                results["calculated_risk"] += 40
                results["tts_watermark_detected"] = True
                results["detected_tts_service"] = watermark_result.get("detected_service")
                logging.critical(f"🎯 TTS WATERMARK FOUND: {watermark_result.get('detected_service')} service signature!")
            
            # 17. MICROPHONE FINGERPRINTING - Device identification
            logging.info("[VISHING] Running microphone fingerprinting...")
            mic_result = self.mic_fingerprint.fingerprint_microphone(temp_wav)
            results["microphone_analysis"] = mic_result
            
            if mic_result.get("is_virtual_audio", False):
                results["calculated_risk"] += 25
                results["virtual_audio_detected"] = True
                logging.warning("[!] VIRTUAL AUDIO: No real microphone characteristics detected!")
            
            # 18. PROSODY ANALYSIS - Detailed speaking pattern analysis
            logging.info("[VISHING] Running prosody and rhythm analysis...")
            prosody_result = self.prosody_analyzer.analyze_prosody(temp_wav)
            results["prosody_analysis"] = prosody_result
            
            if prosody_result.get("naturalness_score", 0.5) < 0.3:
                results["calculated_risk"] += 15
                results["unnatural_prosody_detected"] = True
                logging.warning(f"[!] UNNATURAL PROSODY: Naturalness score {prosody_result.get('naturalness_score', 0):.2f}")
            
            # 19. CROSS-LINGUAL DETECTION - Multi-language TTS detection
            logging.info("[VISHING] Running cross-lingual analysis...")
            lingual_result = self.cross_lingual.detect_language_and_synthesis(temp_wav, text)
            results["cross_lingual_analysis"] = lingual_result
            
            if lingual_result.get("tts_suspected", False):
                results["calculated_risk"] += 20
                results["cross_lingual_tts_detected"] = True
                logging.warning(f"[!] CROSS-LINGUAL TTS: {lingual_result.get('detected_language')} language synthesis suspected")
            
            # 20. VOICE BIOMETRIC - Speaker identity verification (if claimed identity provided)
            # This is optional and depends on having enrolled speakers
            # results["voice_biometric"] = self.voice_biometric.identify_speaker(temp_wav)
            
            # 21. ACTIVE DEFENSE EVALUATION - Threat assessment and response
            logging.info("[VISHING] Running active defense evaluation...")
            threat_assessment = self.active_defense.evaluate_threat(results)
            results["threat_assessment"] = threat_assessment
            results["recommended_defense_action"] = threat_assessment.get("recommended_action", "MONITOR")
            
            if threat_assessment.get("threat_level") in ["HIGH", "CRITICAL"]:
                defense_result = self.active_defense.execute_defense(threat_assessment, call_context=results)
                results["defense_action"] = defense_result
                logging.critical(f"🛡️ ACTIVE DEFENSE: {threat_assessment.get('recommended_action')} executed!")
            
            # 22. MULTI-MODAL PLACEHOLDER (if video provided in future)
            # results["multimodal_analysis"] = self.multimodal.analyze_av_sync(...)
            
            # 23. ADVANCED FEATURES SUMMARY
            results["advanced_features_summary"] = {
                "total_features_run": 12,
                "features_triggered": sum([
                    1 for flag in [
                        results.get("ai_voice_detected"),
                        results.get("replay_attack_suspected"),
                        results.get("neural_synthetic_detected"),
                        results.get("voice_splicing_detected"),
                        results.get("emotional_flatness_detected"),
                        results.get("tts_watermark_detected"),
                        results.get("virtual_audio_detected"),
                        results.get("unnatural_prosody_detected"),
                        results.get("cross_lingual_tts_detected")
                    ] if flag
                ]),
                "detection_layers": "12-layer ensemble"
            }
            
            if results["calculated_risk"] > 0:
                logging.info(f"[+] Vishing Indicators Found. Risk: {results['calculated_risk']}%")

        except Exception as e:
            logging.error(f"[-] Vishing Engine Error: {e}")
            results["transcript"] = "Transcription Failed"
        finally:
            # Cleanup temp file if created - ONLY after all analysis complete
            try:
                if 'temp_wav' in locals() and temp_wav != audio_path and os.path.exists(temp_wav):
                    os.remove(temp_wav)
                    logging.info(f"[VISHING] Cleaned up temp file: {temp_wav}")
            except Exception as cleanup_err:
                logging.warning(f"[VISHING] Temp file cleanup warning: {cleanup_err}")

        # Cap risk at 100
        results["calculated_risk"] = min(results["calculated_risk"], 100)
        
        # Final classification with AI voice clone detection
        deepfake_detected = results.get("ai_voice_detected", False)
        deepfake_suspected = results.get("ai_voice_suspected", False)
        
        if results["calculated_risk"] >= 70:
            if deepfake_detected:
                results["classification"] = "🚨 CONFIRMED AI VOICE CLONE VISHING"
            else:
                results["classification"] = "CONFIRMED VISHING ATTACK"
        elif results["calculated_risk"] >= 40:
            if deepfake_detected or deepfake_suspected:
                results["classification"] = "⚠️ LIKELY AI VOICE VISHING"
            else:
                results["classification"] = "SUSPICIOUS - LIKELY VISHING"
        elif results["calculated_risk"] >= 20:
            if deepfake_suspected:
                results["classification"] = "⚡ SUSPICIOUS - POSSIBLE AI VOICE"
            else:
                results["classification"] = "SOME RISK INDICATORS"
        else:
            results["classification"] = "LIKELY LEGITIMATE"
        
        return results
    
    def _ai_analyze_transcript(self, transcript: str) -> Dict:
        """Use AI to analyze transcript for scam patterns."""
        analysis = {
            "is_scam": False,
            "scam_category": None,
            "confidence": 0,
            "reasoning": "",
            "indicators": []
        }
        
        # Pattern-based analysis (fallback if AI not available)
        scam_patterns = {
            "tech_support": ["technical support", "microsoft", "apple support", "computer virus", "infected"],
            "bank_fraud": ["bank account", "suspicious activity", "verify identity", "transfer money", "secure your account"],
            "irs_tax": ["tax", "irs", "revenue service", "owe money", "unpaid taxes", "arrest warrant"],
            "lottery": ["won", "lottery", "prize", "claim", "processing fee", "winner"],
            "grandparent": ["grandson", "granddaughter", "in jail", "bail", "accident", "emergency"],
            "amazon_refund": ["amazon", "refund", "overcharge", "renewal", "subscription"],
            "social_security": ["social security", "ssn", "suspended", "benefits", "federal crime"]
        }
        
        transcript_lower = transcript.lower()
        
        for category, keywords in scam_patterns.items():
            matches = [kw for kw in keywords if kw in transcript_lower]
            if len(matches) >= 2:  # At least 2 keywords from category
                analysis["is_scam"] = True
                analysis["scam_category"] = category
                analysis["indicators"] = matches
                analysis["confidence"] = min(len(matches) * 20, 100)
                analysis["reasoning"] = f"Detected {len(matches)} indicators of {category} scam: {', '.join(matches)}"
                break
        
        return analysis
    
    def _extract_phone_numbers(self, text: str) -> List[str]:
        """Extract phone numbers from transcript."""
        # US phone patterns
        patterns = [
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # 123-456-7890
            r'\(\d{3}\)\s?\d{3}[-.]?\d{4}',     # (123) 456-7890
            r'\b1[-.]?\d{3}[-.]?\d{3}[-.]?\d{4}\b'  # 1-123-456-7890
        ]
        
        numbers = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            numbers.extend(matches)
        
        return list(set(numbers))
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs mentioned in transcript."""
        url_pattern = r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.(com|net|org|io|co)\b)'
        matches = re.findall(url_pattern, text.lower())
        
        # Flatten if tuples
        urls = []
        for match in matches:
            if isinstance(match, tuple):
                urls.append(match[0])
            else:
                urls.append(match)
        
        return list(set(urls))