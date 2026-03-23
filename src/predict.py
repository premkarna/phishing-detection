# src/predict.py
import joblib
import os
from src.feature_extraction import extract_features

def predict_url(url):
    model_path = os.path.join(os.path.dirname(__file__), '..', 'model', 'phishing_model.pkl')
    
    if not os.path.exists(model_path):
        return "Error: Model not found. Train it first!", []

    model = joblib.load(model_path)
    
    # Extract the 10 features
    features = extract_features(url)
    
    # Predict using the AI model
    prediction = model.predict([features])[0]
    
    # Mapping our 10 features to Human-Readable Reasons!
    # Feature array: [length, @, dots, dash, punycode, ip, shortener, typosquatting, bad_tld, https]
    reasons = []
    
    if features[1] == 1: reasons.append("Contains '@' symbol (often used to hide real domain)")
    if features[3] == 1: reasons.append("Contains '-' in domain (hackers use this to spoof names)")
    if features[4] == 1: reasons.append("Punycode ('xn--') detected (Homograph attack)")
    if features[5] == 1: reasons.append("IP Address used instead of a proper domain name")
    if features[6] == 1: reasons.append("URL Shortener detected (Hides the true destination)")
    if features[7] == 1: reasons.append("Typosquatting / Brand Spoofing detected (e.g., glthub vs github)")
    if features[8] == 1: reasons.append("Suspicious Top-Level Domain (.xyz, .tk, etc.)")
    if features[9] == 0: reasons.append("Missing HTTPS (Connection is not encrypted)")

    if prediction == 1:
        return "⚠️ PHISHING DETECTED", reasons
    else:
        return "✅ SAFE URL", reasons