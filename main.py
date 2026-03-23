# main.py

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from google import genai
import requests
import whois
import datetime
import uvicorn
import ssl
import socket
from urllib.parse import urlparse
import base64
import time

app = FastAPI(title="AI Phishing Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

import os

# Render nundi keys theeskuni List laaga marchadam
GEMINI_KEYS = os.getenv("GEMINI_KEYS", "").split(",")
VT_KEYS = os.getenv("VT_KEYS", "").split(",")

# Okavela Render lo keys pettakapothe, local keys vadela backup (Optional)
if not GEMINI_KEYS[0]:
    GEMINI_KEYS = ["YOUR_LOCAL_KEY_1", "YOUR_LOCAL_KEY_2"]
if not VT_KEYS[0]:
    VT_KEYS = ["YOUR_LOCAL_VT_KEY_1", "YOUR_LOCAL_VT_KEY_2"]

# ======= 💡 CACHE SYSTEM =======
scan_cache = {}
CACHE_EXPIRY_SECONDS = 86400 

class UrlInput(BaseModel):
    url: str

# ==========================================
# 🛠️ HELPER FUNCTIONS (UPGRADED FOR TYPOSQUATTING)
# ==========================================

def check_url_and_ssl(url):
    from urllib.parse import urlparse
    import socket
    import ssl
    import requests
    import datetime

    # 💡 CHANGED: Default to https:// for modern sites
    if not url.startswith("http"):
        url = "https://" + url
    
    parsed_url = urlparse(url)
    original_hostname = parsed_url.hostname
    if not original_hostname:
        original_hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

    exists = False
    final_url = url
    
    # 💡 THE FIX: Acting like a real Chrome Browser to bypass Bot-Protection
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        exists = response.status_code < 400
        final_url = response.url 
    except Exception as e:
        print(f"⚠️ [ANTI-BOT BLOCKED] {url} - {e}")
        exists = False

    ssl_info = "❌ No valid SSL/TLS found"
    try:
        context = ssl.create_default_context()
        with socket.create_connection((original_hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=original_hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                issuer_name = issuer.get('organizationName', issuer.get('commonName', 'Unknown CA'))
                
                if 'notAfter' in cert:
                    try:
                        expiry_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")
                        ssl_info = f"✅ Issued by {issuer_name} (Expires: {expiry_date})"
                    except:
                        ssl_info = f"✅ Issued by {issuer_name}"
                else:
                    ssl_info = f"✅ Issued by {issuer_name}"
    except Exception:
        pass

    return exists, final_url, ssl_info, original_hostname

def get_location(hostname):
    try:
        # 💡 FIX: Get IP of ORIGINAL HOSTNAME
        ip = socket.gethostbyname(hostname)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if response.get("status") == "success":
            return f"{response.get('city', 'Unknown')}, {response.get('country', 'Unknown')} (IP: {ip})"
    except Exception:
        pass
    return "Location Unknown or Offline"

def get_domain_age(url_or_hostname):
    import requests
    import datetime
    from urllib.parse import urlparse
    import whois

    try:
        if not url_or_hostname.startswith('http'):
            url_or_hostname = 'https://' + url_or_hostname
        parsed = urlparse(url_or_hostname)
        domain = parsed.hostname or parsed.path
        if domain.startswith("www."):
            domain = domain[4:]

        print(f"🌍 [DEBUG] Fetching Date for: {domain}")

        # 💡 THE FIX: Adding Chrome Mask to RDAP API so they don't block us!
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

        # METHOD 1: RDAP API (With Mask)
        try:
            rdap_url = f"https://rdap.org/domain/{domain}"
            response = requests.get(rdap_url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        reg_date_str = event.get("eventDate") 
                        reg_date = datetime.datetime.strptime(reg_date_str[:10], "%Y-%m-%d")
                        age = (datetime.datetime.now() - reg_date).days
                        return f"{reg_date_str[:10]} ({age} days old)"
        except Exception as e:
            print(f"⚠️ RDAP blocked/failed: {e}")
            pass

        # METHOD 2: WHOIS Fallback
        w = whois.whois(domain)
        date = w.creation_date
        
        if date:
            if isinstance(date, list):
                date = date[0]
            if isinstance(date, datetime.datetime):
                date = date.replace(tzinfo=None) # Timezone Fix
                age = (datetime.datetime.now() - date).days
                return f"{date.strftime('%Y-%m-%d')} ({age} days old)"
            return str(date)

    except Exception as e:
        print(f"❌ [DOMAIN AGE ERROR] {e}")
        pass
        
    return "Unknown or Hidden by WHOIS Protection"

def get_virustotal_report(url):
    global current_vt_index
    api_key = VT_KEYS[current_vt_index]
    
    if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return "VirusTotal API Key missing"
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"accept": "application/json", "x-apikey": api_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        
        if response.status_code == 429 and len(VT_KEYS) > 1:
            current_vt_index = (current_vt_index + 1) % len(VT_KEYS)
            return get_virustotal_report(url) 
            
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            if malicious > 0 or suspicious > 0:
                return f"⚠️ {malicious} Malicious, {suspicious} Suspicious (out of {total} engines)"
            else:
                return f"✅ 0 out of {total} security vendors flagged this"
        return "No prior scans found in VirusTotal database"
    except Exception:
        return "Error connecting to VirusTotal"

def scan_with_ai(raw_url, final_url, domain_age, ssl_info, vt_report, server_location, exists):
    global current_gemini_index
    api_key = GEMINI_KEYS[current_gemini_index]
    
    if api_key == "YOUR_GEMINI_API_KEY_HERE" or not api_key:
        raise Exception("Google API Key missing!")
        
    try:
        client = genai.Client(api_key=api_key)
        status_text = "LIVE (Active)" if exists else "OFFLINE or BLOCKED BY ANTI-BOT"
            
        prompt = f"""
        You are an elite Cybersecurity AI. Perform a strict threat analysis.
        
        [TELEMETRY DATA]
        1. Original User Input URL: {raw_url}
        2. Final Redirected URL: {final_url}
        3. Server Status: {status_text}
        4. Server Location: {server_location}
        5. Domain Age: {domain_age}
        6. SSL/TLS Status: {ssl_info}
        7. VirusTotal Score: {vt_report}

        [CRITICAL DETECTION RULES - YOU MUST FOLLOW]
        1. **BOT-BLOCKING (FALSE POSITIVE PREVENTION)**: If the Original URL perfectly matches a famous, legitimate brand (like "paypal.com", "google.com", "microsoft.com") with NO typos, IT IS SAFE. Do NOT flag it as phishing even if the status is offline/blocked. Big websites block automated python requests.
        2. **TYPOSQUATTING CHECK**: Visually inspect the Original URL. Is it trying to imitate a brand? (e.g., 'paypa1.com', 'instagrarn.com'). If YES -> VERDICT MUST BE PHISHING.
        3. **PUNYCODE CHECK**: Does the Original URL contain "xn--"? If YES -> VERDICT MUST BE PHISHING.
        4. **VT CHECK**: If VirusTotal has >0 malicious, VERDICT MUST BE PHISHING.

        OUTPUT EXACTLY IN THIS FORMAT:
        VERDICT: SAFE (or PHISHING)
        - [Reason 1]
        - [Reason 2]
        """
        response = client.models.generate_content(model='gemini-2.5-flash', contents=prompt)
        return response.text
    except Exception as e:
        if "429" in str(e) and len(GEMINI_KEYS) > 1:
            current_gemini_index = (current_gemini_index + 1) % len(GEMINI_KEYS)
            return scan_with_ai(raw_url, final_url, domain_age, ssl_info, vt_report, server_location, exists)
        raise e


# ==========================================
# 🚀 MAIN API ENDPOINT
# ==========================================

@app.post("/api/scan")
async def scan_url(input_data: UrlInput):
    raw_url = input_data.url.strip().lower()
    
    if raw_url in scan_cache:
        cached_data = scan_cache[raw_url]
        if time.time() - cached_data['timestamp'] < CACHE_EXPIRY_SECONDS:
            return cached_data['result']

    # 💡 WE PASS THE ORIGINAL URL TO GET ACCURATE INFO
    exists, final_url, ssl_info, original_hostname = check_url_and_ssl(raw_url)
    domain_age = get_domain_age(original_hostname)
    vt_report = get_virustotal_report(raw_url)
    server_location = get_location(original_hostname) if exists else "Unknown (Site Offline)"
    
    try:
        # Pass both raw_url and final_url to AI
        ai_report = scan_with_ai(raw_url, final_url, domain_age, ssl_info, vt_report, server_location, exists)
        
        first_line = ai_report.strip().split('\n')[0].upper()
        verdict = "PHISHING" if "PHISHING" in first_line else "SAFE"
        cleaned_report = ai_report.replace(first_line, "").strip()

        final_result = {
            "status": "success",
            "exists": exists,
            "url": raw_url, # Show the user what they typed
            "location": server_location,
            "domain_age": domain_age,
            "ssl_info": ssl_info,
            "vt_report": vt_report,
            "verdict": verdict,
            "ai_report": cleaned_report
        }
        
        scan_cache[raw_url] = {"result": final_result, "timestamp": time.time()}
        return final_result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Serving static files
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)