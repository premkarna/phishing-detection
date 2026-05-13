"""
Machine Learning Based QR Phishing Detection
===========================================
Uses trained models to detect suspicious QR codes and URLs.
Features: URL pattern analysis, domain reputation, content analysis.
"""

import logging
import re
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import os


@dataclass
class URLFeatures:
    """Features extracted from URL for ML detection."""
    url_length: int
    domain_length: int
    path_length: int
    has_ip_address: bool
    has_at_symbol: bool
    has_double_slash: bool
    has_dash: int
    has_dot: int
    has_https: bool
    domain_token_count: int
    path_token_count: int
    suspicious_tld: bool
    brand_in_domain: bool
    keyword_matches: int


class MLDetector:
    """
    Machine learning-based QR phishing detector.
    
    Uses:
    - Feature extraction from URLs
    - Heuristic scoring
    - Pattern matching
    - Simple rule-based ML (can be extended to real ML models)
    """
    
    def __init__(self, model_path: str = None):
        _default = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "data", "models", "ml_model.json"
        )
        self.model_path = model_path or _default
        
        # Suspicious keywords in URLs
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'update',
            'confirm', 'validate', 'authenticate', 'security', 'banking',
            'password', 'credential', 'wallet', 'payment', 'billing',
            'recovery', 'unlock', 'restore', 'suspend', 'limited',
            'alert', 'warning', 'urgent', 'immediate', 'action-required'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains
            '.xyz', '.top', '.club', '.online', '.site',
            '.work', '.click', '.link', '.download', '.racing'
        ]
        
        # Known brands often impersonated
        self.known_brands = [
            'google', 'microsoft', 'apple', 'amazon', 'facebook',
            'paypal', 'netflix', 'chase', 'wellsfargo', 'bankofamerica',
            'citibank', 'amex', 'visa', 'mastercard', 'linkedin'
        ]
        
        # Feature weights for scoring
        self.weights = {
            'url_length': 0.1,
            'has_ip': 3.0,
            'has_at': 2.0,
            'has_double_slash': 2.0,
            'dash_count': 0.3,
            'no_https': 2.0,
            'suspicious_tld': 2.5,
            'brand_in_domain': 3.0,
            'keyword_matches': 1.5
        }
        
        # Load or initialize model
        self._load_model()
        
        logging.info("[ML DETECTOR] ML-based detector initialized")
    
    def _load_model(self):
        """Load ML model or initialize with default weights."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'r') as f:
                    data = json.load(f)
                    self.weights = data.get('weights', self.weights)
                logging.info("[ML DETECTOR] Loaded ML model from file")
            except (json.JSONDecodeError, IOError, KeyError) as e:
                logging.warning(f"[ML DETECTOR] Failed to load model ({type(e).__name__}), using defaults")
    
    def extract_features(self, url: str) -> URLFeatures:
        """
        Extract ML features from URL.
        
        Args:
            url: URL to analyze
            
        Returns:
            URLFeatures object
        """
        url_lower = url.lower()
        
        # Length features
        url_length = len(url)
        
        # Parse URL components
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
        except (ValueError, AttributeError):
            # URL parsing failed - fallback to string splitting
            domain = url.split('/')[0] if '/' in url else url
            path = '/'.join(url.split('/')[1:]) if '/' in url else ''
        
        domain_length = len(domain)
        path_length = len(path)
        
        # Count features
        has_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain.split(':')[0]))
        has_at = '@' in url
        has_double_slash = url.count('//') > 1
        dash_count = url.count('-')
        dot_count = url.count('.')
        has_https = url.startswith('https://')
        
        # Token counts
        domain_tokens = len(domain.split('.'))
        path_tokens = len([t for t in path.split('/') if t])
        
        # TLD check
        suspicious_tld = any(url_lower.endswith(tld) for tld in self.suspicious_tlds)
        
        # Brand check (typosquatting)
        brand_in_domain = False
        for brand in self.known_brands:
            if brand in domain and not self._is_official_domain(domain, brand):
                brand_in_domain = True
                break
        
        # Keyword matches
        keyword_matches = sum(1 for kw in self.suspicious_keywords if kw in url_lower)
        
        return URLFeatures(
            url_length=url_length,
            domain_length=domain_length,
            path_length=path_length,
            has_ip_address=has_ip,
            has_at_symbol=has_at,
            has_double_slash=has_double_slash,
            has_dash=dash_count,
            has_dot=dot_count,
            has_https=has_https,
            domain_token_count=domain_tokens,
            path_token_count=path_tokens,
            suspicious_tld=suspicious_tld,
            brand_in_domain=brand_in_domain,
            keyword_matches=keyword_matches
        )
    
    def _is_official_domain(self, domain: str, brand: str) -> bool:
        """Check if domain is official for a brand."""
        official_domains = {
            'google': ['google.com', 'google.co', 'googleapis.com', 'googleusercontent.com'],
            'microsoft': ['microsoft.com', 'office.com', 'outlook.com', 'live.com'],
            'apple': ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
            'amazon': ['amazon.com', 'amazon.co', 'aws.amazon.com'],
            'facebook': ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com'],
            'paypal': ['paypal.com', 'paypal.me'],
            'netflix': ['netflix.com'],
            'chase': ['chase.com'],
            'wellsfargo': ['wellsfargo.com'],
            'bankofamerica': ['bankofamerica.com']
        }
        
        official = official_domains.get(brand, [])
        return any(domain.endswith(d) for d in official)
    
    def calculate_phishing_probability(self, features: URLFeatures) -> Tuple[float, Dict]:
        """
        Calculate phishing probability using feature weights.
        
        Returns:
            (probability_score 0-100, feature_breakdown)
        """
        score = 0.0
        breakdown = {}
        
        # URL length (longer URLs more suspicious)
        if features.url_length > 75:
            score += self.weights['url_length'] * 2
            breakdown['url_length'] = 'Very long URL (+{})'.format(self.weights['url_length'] * 2)
        elif features.url_length > 50:
            score += self.weights['url_length']
            breakdown['url_length'] = 'Long URL (+{})'.format(self.weights['url_length'])
        
        # IP address in domain
        if features.has_ip_address:
            score += self.weights['has_ip']
            breakdown['ip_address'] = 'IP address in domain (+{})'.format(self.weights['has_ip'])
        
        # @ symbol (phishing trick)
        if features.has_at_symbol:
            score += self.weights['has_at']
            breakdown['at_symbol'] = '@ symbol detected (+{})'.format(self.weights['has_at'])
        
        # Double slash (obfuscation)
        if features.has_double_slash:
            score += self.weights['has_double_slash']
            breakdown['double_slash'] = 'Double slash obfuscation (+{})'.format(self.weights['has_double_slash'])
        
        # Excessive dashes
        if features.has_dash > 3:
            score += self.weights['dash_count'] * (features.has_dash - 3)
            breakdown['dash_count'] = 'Many dashes: {} (+{})'.format(
                features.has_dash, 
                self.weights['dash_count'] * (features.has_dash - 3)
            )
        
        # No HTTPS
        if not features.has_https:
            score += self.weights['no_https']
            breakdown['no_https'] = 'No HTTPS encryption (+{})'.format(self.weights['no_https'])
        
        # Suspicious TLD
        if features.suspicious_tld:
            score += self.weights['suspicious_tld']
            breakdown['suspicious_tld'] = 'Suspicious/free TLD (+{})'.format(self.weights['suspicious_tld'])
        
        # Brand impersonation
        if features.brand_in_domain:
            score += self.weights['brand_in_domain']
            breakdown['brand_impersonation'] = 'Brand impersonation (+{})'.format(self.weights['brand_in_domain'])
        
        # Suspicious keywords
        if features.keyword_matches > 0:
            keyword_score = self.weights['keyword_matches'] * min(features.keyword_matches, 5)
            score += keyword_score
            breakdown['keywords'] = '{} suspicious keywords (+{})'.format(
                features.keyword_matches, keyword_score
            )
        
        # Domain token count (subdomain abuse)
        if features.domain_token_count > 4:
            score += 1.0
            breakdown['subdomain_abuse'] = 'Many subdomains (possible obfuscation) (+1.0)'
        
        # Cap score at 100
        probability = min(score, 100.0)
        
        return probability, breakdown
    
    def predict(self, url: str) -> Dict:
        """
        Main prediction function for URL phishing detection.
        
        Args:
            url: URL to analyze
            
        Returns:
            Complete prediction results
        """
        # Extract features
        features = self.extract_features(url)
        
        # Calculate probability
        probability, breakdown = self.calculate_phishing_probability(features)
        
        # Determine classification
        if probability >= 80:
            classification = 'PHISHING'
            confidence = 'high'
        elif probability >= 50:
            classification = 'SUSPICIOUS'
            confidence = 'medium'
        elif probability >= 20:
            classification = 'POTENTIALLY_SUSPICIOUS'
            confidence = 'low'
        else:
            classification = 'LIKELY_SAFE'
            confidence = 'high'
        
        return {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'classification': classification,
            'phishing_probability': round(probability, 2),
            'confidence': confidence,
            'features': {
                'url_length': features.url_length,
                'has_ip_address': features.has_ip_address,
                'has_at_symbol': features.has_at_symbol,
                'has_https': features.has_https,
                'suspicious_tld': features.suspicious_tld,
                'brand_in_domain': features.brand_in_domain,
                'suspicious_keywords': features.keyword_matches,
                'dash_count': features.has_dash,
                'domain_tokens': features.domain_token_count
            },
            'score_breakdown': breakdown,
            'model_version': '1.0-rule-based',
            'recommendation': self._generate_recommendation(classification, probability)
        }
    
    def _generate_recommendation(self, classification: str, probability: float) -> str:
        """Generate recommendation based on classification."""
        if classification == 'PHISHING':
            return "🚨 HIGH RISK: Block immediately. Strong indicators of phishing."
        elif classification == 'SUSPICIOUS':
            return "⚠️ MEDIUM RISK: Exercise caution. Multiple suspicious features detected."
        elif classification == 'POTENTIALLY_SUSPICIOUS':
            return "⚡ LOW RISK: Some suspicious features present. Verify before proceeding."
        else:
            return "✓ APPEARS SAFE: Low risk indicators. Normal browsing precautions apply."
    
    def batch_predict(self, urls: List[str]) -> List[Dict]:
        """Predict for multiple URLs."""
        return [self.predict(url) for url in urls]
    
    def train_from_feedback(self, url: str, actual_label: str, features: URLFeatures = None):
        """
        Update model weights based on feedback.
        
        Args:
            url: URL that was analyzed
            actual_label: 'phishing' or 'safe'
            features: Optional pre-extracted features
        """
        if features is None:
            features = self.extract_features(url)
        
        # Simple weight adjustment based on feedback
        prediction = self.predict(url)
        predicted_prob = prediction['phishing_probability']
        
        if actual_label == 'phishing' and predicted_prob < 50:
            # False negative - increase weights for detected features
            if features.has_ip_address:
                self.weights['has_ip'] += 0.1
            if features.brand_in_domain:
                self.weights['brand_in_domain'] += 0.1
            logging.info("[ML DETECTOR] Updated weights from false negative feedback")
            
        elif actual_label == 'safe' and predicted_prob > 80:
            # False positive - decrease weights
            self.weights['has_ip'] = max(1.0, self.weights['has_ip'] - 0.1)
            self.weights['brand_in_domain'] = max(1.0, self.weights['brand_in_domain'] - 0.1)
            logging.info("[ML DETECTOR] Updated weights from false positive feedback")
        
        # Save updated model
        self._save_model()
    
    def _save_model(self):
        """Save model weights to file."""
        try:
            data = {
                'weights': self.weights,
                'last_updated': datetime.now().isoformat(),
                'version': '1.0'
            }
            with open(self.model_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"[ML DETECTOR] Failed to save model: {e}")
    
    def get_model_stats(self) -> Dict:
        """Get model statistics."""
        return {
            'version': '1.0-rule-based',
            'features_used': 10,
            'weights': self.weights,
            'model_path': self.model_path,
            'suspicious_keywords_count': len(self.suspicious_keywords),
            'known_brands_count': len(self.known_brands)
        }


# Singleton
ml_detector = MLDetector()


# Convenience functions
def check_url(url: str) -> Dict:
    """Quick ML-based URL check."""
    return ml_detector.predict(url)

def check_urls(urls: List[str]) -> List[Dict]:
    """Batch URL check."""
    return ml_detector.batch_predict(urls)

def get_ml_confidence(url: str) -> float:
    """Get phishing probability only."""
    result = ml_detector.predict(url)
    return result['phishing_probability']
