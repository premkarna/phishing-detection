# src/feature_extraction.py
import urllib.parse
import re
import difflib

def extract_features(url):
    """
    Extracts 10 advanced cybersecurity features from a URL.
    Includes Crash-Protection for dirty data.
    """
    url = str(url).lower().strip()
    
    # --- 1. PROTOCOL CHECK (Answering your doubt) ---
    has_https = 1 if url.startswith('https://') else 0
    
    # Safely format URL for parsing
    if not url.startswith(('http://', 'https://')):
        url_to_parse = 'http://' + url
    else:
        url_to_parse = url
        
    # --- 2. CRASH PROTECTION (Error Handling) ---
    try:
        parsed_url = urllib.parse.urlparse(url_to_parse)
        domain = parsed_url.netloc
        # Remove port numbers if any (e.g., domain.com:8080)
        domain = domain.split(':')[0] 
    except ValueError:
        # If the Kaggle dataset has garbage data that crashes urllib, 
        # we return default "suspicious" numbers instead of crashing the whole program.
        return [len(url), 1, 0, 1, 0, 1, 0, 0, 1, has_https]

    # --- 3. BASIC FEATURES ---
    url_length = len(url)
    has_at_symbol = 1 if '@' in url else 0
    dot_count = domain.count('.')
    has_dash_in_domain = 1 if '-' in domain else 0
    
    # --- 4. ADVANCED CYBERSECURITY CHECKS ---
    is_punycode = 1 if 'xn--' in domain else 0
    has_ip = 1 if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', domain) else 0
    
    shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs', 'cutt.ly']
    is_shortened = 1 if any(short in domain for short in shorteners) else 0

    # --- 5. SUSPICIOUS TLD CHECK (Answering your doubt) ---
    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.site', '.club', '.online', '.buzz']
    has_suspicious_tld = 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0

    # --- 6. TYPOSQUATTING (Brand Spoofing Check) ---
    # Added your examples here!
    top_brands = [
        'google', 'github', 'victoriassecret', 'instagram', 'facebook', 
        'amazon', 'netflix', 'paypal', 'apple', 'microsoft', 'linkedin', 'whatsapp'
    ]
    is_typosquatting = 0
    
    raw_name = domain.replace('www.', '').split('.')[0]
    
    for brand in top_brands:
        if brand != raw_name:
            # difflib naturally handles missing 's' or 'i' replaced with 'l'
            similarity = difflib.SequenceMatcher(None, raw_name, brand).ratio()
            if similarity > 0.75:  # 75% or more similar (Catch more variations)
                is_typosquatting = 1
                break
                
    # Return 10 Powerful Features
    return [
        url_length, 
        has_at_symbol, 
        dot_count, 
        has_dash_in_domain, 
        is_punycode, 
        has_ip, 
        is_shortened, 
        is_typosquatting,
        has_suspicious_tld,
        has_https
    ]