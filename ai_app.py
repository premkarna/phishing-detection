# ai_app.py
from google import genai
import requests  # <-- NEW: Website exist avthundo ledo check cheyadaniki
import sys

# ======= NEE API KEY IKKADA PETTU =======
API_KEY = "AIzaSyCder4JxE0mPydnIMnfuZXfjIsdRiKZrXw" 
# ========================================

if API_KEY.startswith("AIzaSy") == False:
    print("❌ Error: API key correct ga pettaledu. Check line 7!")
    sys.exit(1)

try:
    client = genai.Client(api_key=API_KEY)
except Exception as e:
    print(f"❌ Failed to initialize AI Client: {e}")
    sys.exit(1)

# --- KOTHA FUNCTION ---
def check_website_exists(url):
    print(f"\n[🔍 Pinging website to see if it exists...]")
    try:
        # Browser laaga act cheyadaniki headers vaduthunnam
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        # 5 seconds lo website open avvakapothe timeout aipothundi
        response = requests.get(url, headers=headers, timeout=5)
        return True # Website undi!
    except requests.exceptions.RequestException:
        return False # Website ledu or server down
# ----------------------

def scan_with_ai(url):
    print("[🤖 Website exists! AI is analyzing the URL. Please wait...]")
    prompt = f"Analyze this URL for phishing: {url}. Give a direct verdict (SAFE or PHISHING) and list 3 concise technical reasons."
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        return response.text
    except Exception as e:
        return f"Error connecting to AI: {e}"

def main():
    print("==================================================")
    print("🤖  AI PHISHING DETECTOR (WITH LIVE PING)  🤖")
    print("==================================================")
    
    while True:
        user_input = input("\nEnter a URL to scan (or 'exit' to quit): ").strip()
        
        if user_input.lower() == 'exit':
            print("Shutting down... Stay safe!")
            break
            
        if user_input == "":
            continue
            
        scan_url = 'http://' + user_input if not user_input.startswith(('http://', 'https://')) else user_input
            
        # 💡 THE NEW LOGIC: Check if it exists FIRST
        if check_website_exists(scan_url):
            # Website undi kabatti, AI ki isthunnam
            analysis = scan_with_ai(scan_url)
            print("\n" + "="*50)
            print(analysis)
            print("="*50)
        else:
            # Website lekapothe, AI daaka vellakunda ikkade aapesthunnam
            print("\n" + "="*50)
            print(f"❌ RESULT: THE WEBSITE DOESN'T EXIST (Or is currently down).")
            print("="*50)

if __name__ == "__main__":
    main()