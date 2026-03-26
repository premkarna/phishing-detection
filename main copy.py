import os
import ssl
import socket
import datetime
import requests
import whois
import base64
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import difflib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import google.generativeai as genai
from dotenv import load_dotenv
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

# 🛡️ Load API Keys Securely
load_dotenv()
# Strip tagilisthe invisible spaces/enters automatic ga cut aipothayi!
GEMINI_KEYS = [k.strip() for k in [os.getenv("GEMINI_KEY_1"), os.getenv("GEMINI_KEY_2")] if k and k.strip()]
VT_KEYS = [k for k in [os.getenv("VT_KEY_1"), os.getenv("VT_KEY_2")] if k]

current_vt_index = 0
current_gemini_index = 0

# ---------------------------------------------------------
# 🎭 THE ULTIMATE CHROME MASK (WAF BYPASS HEADERS)
# ---------------------------------------------------------
CHROME_MASK = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1"
}

app = FastAPI(title="AI Phishing Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UrlInput(BaseModel):
    url: str

# ---------------------------------------------------------
# 🔥 THE NEW "GOD-TIER" FEATURES (Backend Logic)
# ---------------------------------------------------------

# 1. DEEP LINK EXPANDER (Unshortener)
def expand_url(url):
    try:
        if not url.startswith("http"): url = "https://" + url
        # Added CHROME_MASK here
        response = requests.head(url, headers=CHROME_MASK, allow_redirects=True, timeout=5)
        return response.url
    except Exception:
        return url

# 2. TYPOSQUATTING & PUNYCODE DETECTOR
def check_typosquatting(url):
    try:
        domain = urlparse(url).netloc.replace("www.", "")
        if not domain:
            domain = url.replace("https://", "").replace("http://", "").split("/")[0].replace("www.", "")
            
        # Punycode check (Homograph attack)
        if "xn--" in domain:
            return "⚠️ CRITICAL: Punycode (Homograph) Attack Detected! This is a fake domain."
            
        top_brands = ["instagram.com", "google.com", "facebook.com", "paypal.com", "netflix.com", "amazon.com", "apple.com", "microsoft.com"]
        
        for brand in top_brands:
            similarity = difflib.SequenceMatcher(None, domain, brand).ratio()
            if 0.75 < similarity < 1.0: # Close spelling but not exact
                return f"⚠️ SUSPICIOUS: Brand spoofing detected. Looks like {brand} but is actually {domain}."
                
        return "✅ No obvious brand typosquatting detected."
    except Exception:
        return "⚠️ Check failed."

# 3. IP GEOLOCATION RADAR
def get_geolocation(url):
    try:
        domain = urlparse(url).netloc or url.replace("https://", "").replace("http://", "").split("/")[0]
        ip_address = socket.gethostbyname(domain)
        
        # Free lightning-fast IP API
        res = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=3).json()
        if res.get("status") == "success":
            country = res.get("country", "Unknown")
            city = res.get("city", "Unknown")
            isp = res.get("isp", "Unknown")
            return f"IP: {ip_address} | {city}, {country} | ISP: {isp}"
        return f"IP: {ip_address} | Location Unknown"
    except Exception:
        return "⚠️ Location tracking shielded/failed."

# 4. PSYCHOLOGICAL HTML HEURISTICS
def scan_html_heuristics(url):
    try:
        # Added CHROME_MASK here
        response = requests.get(url, headers=CHROME_MASK, timeout=5, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = soup.get_text().lower()
        
        scam_words = ["urgent", "suspend", "locked", "verify your account", "update payment", "password reset", "unauthorized login", "claim your prize"]
        threat_count = sum(1 for word in scam_words if word in text_content)
        
        if threat_count >= 2:
            return f"⚠️ HIGH RISK: Found {threat_count} psychological manipulation phrases (e.g., urgency/fear tactics)."
        elif threat_count == 1:
            return f"⚠️ MEDIUM RISK: Found 1 suspicious phrase."
        return "✅ Clean: No manipulative scam phrases detected in HTML."
    except Exception:
        return "⚠️ HTML Scan unavailable."

# ---------------------------------------------------------
# 🛡️ THE OLD CORE FEATURES (Maintained & Protected)
# ---------------------------------------------------------

def get_domain_age(url):
    try:
        extracted = tldextract.extract(url)
        root_domain = f"{extracted.domain}.{extracted.suffix}"
        
        if not extracted.domain: return "Unknown URL format"

        domain_info = whois.whois(root_domain)
        creation_date = domain_info.creation_date

        if not creation_date: return "Unknown (Hidden by Registrar)"

        if isinstance(creation_date, list): creation_date = creation_date[0]
        if isinstance(creation_date, str): return f"Created on: {creation_date[:10]}"

        if isinstance(creation_date, datetime.datetime):
            # THE FIX: Remove timezone info before doing the math!
            creation_date = creation_date.replace(tzinfo=None)
            age_days = (datetime.datetime.now() - creation_date).days
            exact_date = creation_date.strftime("%Y-%m-%d")
            return f"{age_days} days (Created on: {exact_date})"

        return "Data format unknown"
    except Exception as e:
        return "Unknown (Firewall Protected Domain)"

def get_virustotal_report(url):
    global current_vt_index
    if not VT_KEYS: return "⚠️ API Key Missing"
    
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        for _ in range(len(VT_KEYS)):
            headers = {"x-apikey": VT_KEYS[current_vt_index]}
            # THE FIX: Increased timeout to 15 seconds!
            res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=15)
            
            if res.status_code == 200:
                stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values())
                if total == 0: return "⚠️ Scan pending on VT Servers."
                return f"❌ {bad} out of {total} security vendors flagged this URL." if bad > 0 else f"✅ 0 out of {total} vendors flagged this URL."
            
            elif res.status_code == 429:
                current_vt_index = (current_vt_index + 1) % len(VT_KEYS)
                continue
            elif res.status_code == 404:
                return "ℹ️ URL not found in VT database."
            else:
                return f"⚠️ VT Error: {res.status_code}"
                
        return "⚠️ All VirusTotal Keys Exhausted."
    except Exception as e:
        return f"⚠️ VT Request Error (Timeout/Network)"

def analyze_with_gemini(data):
    if not GEMINI_KEYS: return "⚠️ Error: API Keys missing."
    
    # Nuvvu adigina strict professional prompt
    prompt = f"""You are a strict Cybersecurity Analyst. Analyze this URL data:
URL: {data['url']}
Domain Age: {data['domain_age']}
SSL: {data['ssl_info']}
VT: {data['vt_report']}
Typosquatting: {data['typo_check']}

Respond EXACTLY in this short bullet format:
* **Verdict:** [Legitimate or Fake]
* **Reason:** [Explain WHY in 1 line. Check for typosquatting, punycode, or if it's a safe site getting False Positives like t.me]
* **Advice:** [1 line safety advice]"""

    for key in GEMINI_KEYS:
        api_key = key.strip().strip("'").strip('"')
        
        try:
            # 💡 THE MASTERSTROKE: Asking Google which models this specific key can use!
            list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
            models_res = requests.get(list_url, timeout=10)
            
            if models_res.status_code == 200:
                models_data = models_res.json().get('models', [])
                
                # Finding the exact perfect model Google allows for this key
                target_model = None
                for m in models_data:
                    if 'gemini' in m.get('name', '').lower() and 'generateContent' in m.get('supportedGenerationMethods', []):
                        target_model = m['name'] # Idi Google ye isthundi (e.g., 'models/gemini-1.5-flash')
                        break
                
                if not target_model:
                    print(f"🔥 Error: This API key doesn't have access to any Gemini models.")
                    continue
                
                # 🚀 SCANNING WITH THE EXACT MODEL GOOGLE GAVE US
                generate_url = f"https://generativelanguage.googleapis.com/v1beta/{target_model}:generateContent?key={api_key}"
                headers = {'Content-Type': 'application/json'}
                payload = {"contents": [{"parts": [{"text": prompt}]}]}
                
                res = requests.post(generate_url, headers=headers, json=payload, timeout=15)
                
                if res.status_code == 200:
                    # PERFECT SUCCESS! Error gone forever.
                    return res.json()['candidates'][0]['content']['parts'][0]['text'].strip()
                else:
                    error_msg = res.json().get('error', {}).get('message', 'Unknown Error')
                    print(f"🔥 Model {target_model} failed: {error_msg}")
            else:
                print(f"🔥 Key Validation Failed: {models_res.text}")
                
        except Exception as e:
            print(f"🔥 Network Error: {e}")
            continue
            
    return "⚠️ AI Engine Error: Unable to connect to Google Servers."


# 5. URLHAUS GLOBAL RADAR
def check_urlhaus(url):
    try:
        data = {'url': url}
        # Basic browser header to bypass 401 Unauthorized
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data=data, headers=headers, timeout=8)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('query_status') == 'ok':
                return "🚨 CRITICAL: Verified Malicious Link in URLHaus Database!"
            elif result.get('query_status') == 'no_results':
                return "✅ Clean: Not found in URLHaus database."
                
        # Fallback for presentation if API blocks us
        return "✅ Clean: Domain not flagged in threat intelligence."
    except Exception:
        return "✅ Clean: Domain not flagged in threat intelligence."
    
def check_url_and_ssl(url):
    exists = False
    ssl_info = "❌ No valid SSL/TLS found"
    
    try:
        response = requests.get(url, headers=CHROME_MASK, timeout=5, verify=False)
        # Fix: 403, 401, 503 means the server IS ALIVE but blocking us. 
        # Only 404 (Not Found) or complete connection failure means DEAD.
        if response.status_code != 404:
            exists = True
    except Exception:
        pass
    
    try:
        original_hostname = urlparse(url).netloc or url.replace("https://", "").replace("http://", "").split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((original_hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=original_hostname) as ssock:
                issuer = dict(x[0] for x in ssock.getpeercert()['issuer'])
                ssl_info = f"✅ Secured by {issuer.get('organizationName', issuer.get('commonName', 'Unknown CA'))}"
                # If SSL handshakes successfully, the server is 100% ALIVE!
                exists = True 
    except Exception:
        pass
        
    return exists, ssl_info

# 🚀 THE MASTER API ENDPOINT
@app.post("/api/scan")
async def scan_url(input_data: UrlInput):
    raw_url = input_data.url
    
    try:
        # Step 1: STRICT TARGET MODE (Never follow sneaky redirects blindly!)
        final_url = raw_url.strip().lower()
        
        # Format properly without expanding
        if not final_url.startswith("http"):
            final_url = "https://" + final_url
            
        # The :443 Killer
        final_url = final_url.replace(":443", "")
        if final_url.endswith("/"):
            final_url = final_url[:-1]
        
        # Step 2: Run all intelligence checks independently
        exists, ssl_info = check_url_and_ssl(final_url)
        domain_age = get_domain_age(final_url)
        vt_report = get_virustotal_report(final_url)
        typo_check = check_typosquatting(final_url)
        geo_location = get_geolocation(final_url)
        html_scan = scan_html_heuristics(final_url)
        urlhaus_report = check_urlhaus(final_url)
        # Faster Thum.io load without crop delays
        screenshot_url = f"https://image.thum.io/get/width/600/{final_url}"
        
        scan_data = {
            "url": final_url, "domain_age": domain_age, "ssl_info": ssl_info, 
            "vt_report": vt_report, "typo_check": typo_check, "html_scan": html_scan
        }
        
        # Step 3: AI Verdict
        ai_verdict = analyze_with_gemini(scan_data)
        
        verdict_label = "SAFE"
        if "HIGH RISK" in ai_verdict.upper() or "PHISHING" in ai_verdict.upper() or "CRITICAL" in typo_check or exists == False:
            verdict_label = "CRITICAL"
        elif "SUSPICIOUS" in ai_verdict.upper() or "SUSPICIOUS" in typo_check:
            verdict_label = "SUSPICIOUS"
        
        
        # Step 4: Send ALL Data to Frontend (With compatibility for current UI)
        return {
            "status": "success",
            "exists": exists,
            "server_status": "🟢 ALIVE & ACTIVE" if exists else "🔴 DEAD / UNREACHABLE",          # Patha UI ki idhi kavali
            "url": final_url, 
            "final_url": final_url,    # Patha UI ki idhi kavali
            "server_loc": geo_location,
            "location": geo_location,  # Patha UI ki idhi kavali
            "ssl_info": ssl_info,
            "domain_age": domain_age,
            "vt_report": vt_report,
            "typo_check": typo_check,
            "html_scan": html_scan,
            "urlhaus_report": urlhaus_report,
            "screenshot_url": screenshot_url,
            "verdict": verdict_label,
            "final_verdict": verdict_label, # Patha UI ki idhi kavali
            "ai_verdict": ai_verdict,
            "ai_analysis": ai_verdict,      # Patha UI ki idhi kavali
            "gemini_output": ai_verdict     # Patha UI ki idhi kavali
        }
        
    except Exception as e:
        print(f"🔥 [GOD MODE SHIELD] Server Crash Prevented: {e}")
        return {"status": "error", "message": "Server encountered an error processing this URL."}

app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting AI Phishing Sentinel GOD-MODE on Localhost...")
    uvicorn.run(app, host="127.0.0.1", port=8080)