"""
Browser Fingerprinting Detector
============================
Detects and analyzes browser fingerprinting techniques used by malicious sites.
Identifies what data sites collect for tracking and device identification.
"""

import logging
import json
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class FingerprintingTechnique:
    """Represents a fingerprinting technique detected."""
    technique: str
    category: str
    data_collected: List[str]
    risk_level: str
    evidence: str


class BrowserFingerprintingDetector:
    """
    Detects browser fingerprinting attempts by malicious websites.
    
    Monitors:
    - Canvas/WebGL fingerprinting
    - Font enumeration
    - Screen/Timezone/Navigator properties
    - AudioContext fingerprinting
    - WebRTC leaks
    - Device sensors
    - Battery API
    """
    
    def __init__(self):
        # Known fingerprinting techniques
        self.fingerprinting_signatures = {
            'canvas': {
                'patterns': [
                    'canvas.getContext',
                    'toDataURL',
                    'fillText',
                    'measureText',
                    'getImageData'
                ],
                'data_collected': ['rendering differences', 'font metrics', 'GPU info'],
                'risk': 'high'
            },
            'webgl': {
                'patterns': [
                    'getContext("webgl"',
                    'getShaderPrecisionFormat',
                    'getParameter',
                    'VENDOR',
                    'RENDERER',
                    'UNMASKED'
                ],
                'data_collected': ['GPU vendor', 'GPU renderer', 'graphics capabilities', 'driver info'],
                'risk': 'high'
            },
            'fonts': {
                'patterns': [
                    'document.fonts',
                    'check',
                    'load',
                    'FontFace',
                    'offsetWidth',
                    'scrollWidth'
                ],
                'data_collected': ['installed fonts list', 'font metrics', 'font rendering'],
                'risk': 'medium'
            },
            'screen': {
                'patterns': [
                    'screen.width',
                    'screen.height',
                    'screen.colorDepth',
                    'screen.pixelDepth',
                    'availWidth',
                    'availHeight'
                ],
                'data_collected': ['screen resolution', 'color depth', 'available space'],
                'risk': 'low'
            },
            'timezone': {
                'patterns': [
                    'Intl.DateTimeFormat',
                    'timeZone',
                    'getTimezoneOffset',
                    'Date().getTimezoneOffset'
                ],
                'data_collected': ['timezone', 'locale', 'geolocation hint'],
                'risk': 'low'
            },
            'navigator': {
                'patterns': [
                    'navigator.userAgent',
                    'navigator.platform',
                    'navigator.language',
                    'navigator.languages',
                    'navigator.hardwareConcurrency',
                    'navigator.deviceMemory',
                    'navigator.maxTouchPoints'
                ],
                'data_collected': ['browser info', 'OS', 'hardware specs', 'touch support'],
                'risk': 'medium'
            },
            'webaudio': {
                'patterns': [
                    'AudioContext',
                    'OfflineAudioContext',
                    'createOscillator',
                    'createDynamicsCompressor',
                    'destination',
                    'startRendering'
                ],
                'data_collected': ['audio processing differences', 'device sound card'],
                'risk': 'high'
            },
            'webrtc': {
                'patterns': [
                    'RTCPeerConnection',
                    'createDataChannel',
                    'createOffer',
                    'onicecandidate',
                    'localDescription'
                ],
                'data_collected': ['internal IP addresses', 'network topology'],
                'risk': 'critical'
            },
            'battery': {
                'patterns': [
                    'navigator.getBattery',
                    'charging',
                    'chargingTime',
                    'dischargingTime',
                    'level'
                ],
                'data_collected': ['battery level', 'charging status', 'device tracking'],
                'risk': 'medium'
            },
            'sensors': {
                'patterns': [
                    'Accelerometer',
                    'Gyroscope',
                    'Magnetometer',
                    'DeviceOrientationEvent',
                    'DeviceMotionEvent',
                    'addEventListener("devicemotion"'
                ],
                'data_collected': ['device orientation', 'movement patterns', 'sensor data'],
                'risk': 'high'
            }
        }
        
        logging.info("[FINGERPRINTING] Browser fingerprinting detector initialized")
    
    def analyze(self, js_code: str, page_url: str = None) -> Dict:
        """
        Analyze JavaScript code for fingerprinting techniques.
        
        Args:
            js_code: JavaScript code to analyze
            page_url: Optional page URL for context
            
        Returns:
            Fingerprinting analysis report
        """
        js_lower = js_code.lower()
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'page_url': page_url,
            'fingerprinting_detected': False,
            'techniques': [],
            'overall_risk': 'low',
            'entropy_score': 0,  # How unique the fingerprint would be
            'privacy_impact': 'minimal',
            'recommendations': []
        }
        
        detected_techniques = []
        total_risk_score = 0
        
        # Check each fingerprinting category
        for category, signature in self.fingerprinting_signatures.items():
            detected = False
            evidence = []
            
            for pattern in signature['patterns']:
                if pattern.lower() in js_lower:
                    detected = True
                    evidence.append(pattern)
            
            if detected:
                technique = FingerprintingTechnique(
                    technique=category,
                    category='browser_fingerprinting',
                    data_collected=signature['data_collected'],
                    risk_level=signature['risk'],
                    evidence=f"Found {len(evidence)} patterns: {', '.join(evidence[:3])}"
                )
                
                detected_techniques.append(technique)
                
                # Calculate risk score
                risk_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 5}
                total_risk_score += risk_scores.get(signature['risk'], 1)
        
        # Check for fingerprinting combinations (more dangerous)
        if detected_techniques:
            results['fingerprinting_detected'] = True
            results['techniques'] = [asdict(t) for t in detected_techniques]
            
            # Calculate entropy score (0-100)
            # More techniques = higher entropy = more unique fingerprint
            technique_count = len(detected_techniques)
            high_risk_count = sum(1 for t in detected_techniques if t.risk_level in ['high', 'critical'])
            
            results['entropy_score'] = min(100, technique_count * 10 + high_risk_count * 15)
            
            # Determine overall risk
            if total_risk_score >= 10:
                results['overall_risk'] = 'critical'
                results['privacy_impact'] = 'severe'
            elif total_risk_score >= 6:
                results['overall_risk'] = 'high'
                results['privacy_impact'] = 'significant'
            elif total_risk_score >= 3:
                results['overall_risk'] = 'medium'
                results['privacy_impact'] = 'moderate'
            else:
                results['overall_risk'] = 'low'
                results['privacy_impact'] = 'minimal'
            
            # Generate recommendations
            results['recommendations'] = self._generate_recommendations(detected_techniques)
            
            # Log detection
            logging.warning(f"[FINGERPRINTING] Detected {technique_count} fingerprinting techniques! "
                          f"Risk: {results['overall_risk']}, Entropy: {results['entropy_score']}")
        
        return results
    
    def _generate_recommendations(self, techniques: List[FingerprintingTechnique]) -> List[str]:
        """Generate privacy recommendations based on detected techniques."""
        recommendations = []
        
        categories = [t.technique for t in techniques]
        
        if 'webrtc' in categories:
            recommendations.append("🚨 CRITICAL: WebRTC leak detected - internal IP addresses exposed. Disable WebRTC in browser.")
        
        if 'canvas' in categories or 'webgl' in categories:
            recommendations.append("⚠️ Canvas/WebGL fingerprinting detected. Use canvas blocker extension or Firefox's resistFingerprinting.")
        
        if 'fonts' in categories:
            recommendations.append("⚠️ Font enumeration detected. Consider using standard font sets only.")
        
        if 'navigator' in categories:
            recommendations.append("⚠️ Browser/ hardware info being collected. Use user agent spoofing.")
        
        if 'webaudio' in categories:
            recommendations.append("⚠️ Audio fingerprinting detected. Disable AudioContext or use privacy extensions.")
        
        if 'sensors' in categories:
            recommendations.append("⚠️ Device sensors accessed. Revoke sensor permissions in browser settings.")
        
        if 'battery' in categories:
            recommendations.append("⚠️ Battery API accessed for tracking. Disable battery API access.")
        
        if len(techniques) >= 3:
            recommendations.append("🚨 Multiple fingerprinting vectors detected - this site is aggressively tracking visitors!")
        
        recommendations.append("💡 General: Use Firefox with privacy.resistFingerprinting enabled, or Brave browser with fingerprinting protection.")
        
        return recommendations
    
    def detect_from_console_logs(self, console_logs: List[Dict], page_url: str = None) -> Dict:
        """
        Analyze browser console logs for fingerprinting attempts.
        
        Args:
            console_logs: List of console log entries
            page_url: Page URL
            
        Returns:
            Fingerprinting analysis
        """
        # Combine all console log text
        combined_js = ' '.join([log.get('text', '') for log in console_logs])
        
        return self.analyze(combined_js, page_url)
    
    def get_privacy_score(self, fingerprinting_report: Dict) -> int:
        """
        Calculate a privacy score (0-100) based on fingerprinting report.
        
        Returns:
            Privacy score (higher = more private)
        """
        if not fingerprinting_report['fingerprinting_detected']:
            return 100  # Perfect privacy
        
        # Start with 100 and subtract based on detected techniques
        score = 100
        
        for technique in fingerprinting_report['techniques']:
            risk = technique.get('risk_level', 'low')
            penalties = {'low': 5, 'medium': 10, 'high': 20, 'critical': 30}
            score -= penalties.get(risk, 5)
        
        # Penalty for high entropy (very unique fingerprint)
        entropy = fingerprinting_report.get('entropy_score', 0)
        score -= entropy // 2
        
        return max(0, score)
    
    def compare_fingerprints(self, report1: Dict, report2: Dict) -> Dict:
        """
        Compare two fingerprinting reports to check if same tracking technique.
        
        Returns:
            Comparison results
        """
        techniques1 = set(t['technique'] for t in report1.get('techniques', []))
        techniques2 = set(t['technique'] for t in report2.get('techniques', []))
        
        common = techniques1 & techniques2
        unique1 = techniques1 - techniques2
        unique2 = techniques2 - techniques1
        
        similarity = len(common) / max(len(techniques1), len(techniques2), 1) * 100
        
        return {
            'similarity_percentage': round(similarity, 2),
            'common_techniques': list(common),
            'likely_same_actor': similarity >= 70,
            'analysis': f"{similarity:.1f}% technique overlap detected"
        }


# Singleton
fingerprinting_detector = BrowserFingerprintingDetector()


# Convenience functions
def check_fingerprinting(js_code: str, page_url: str = None) -> Dict:
    """Quick fingerprinting check."""
    return fingerprinting_detector.analyze(js_code, page_url)

def check_console_logs(console_logs: List[Dict], page_url: str = None) -> Dict:
    """Check console logs for fingerprinting."""
    return fingerprinting_detector.detect_from_console_logs(console_logs, page_url)
