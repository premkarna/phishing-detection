# app_dashboard.py
import streamlit as st
from google import genai
import requests

# --- 1. PAGE SETUP (Look & Feel) ---
st.set_page_config(page_title="AI Phishing Scanner", page_icon="🛡️", layout="centered")

st.title("🛡️ Advanced AI Phishing Detector")
st.markdown("Welcome, Security Analyst. Enter a URL below to scan it for typosquatting, homograph attacks, and phishing patterns using Gemini AI.")

# --- 2. SIDEBAR (For Security Key) ---
st.sidebar.header("⚙️ Configuration")
api_key = st.sidebar.text_input("Enter Gemini API Key", type="password", help="Your key is secure and will not be saved.")
st.sidebar.markdown("[Get your free API key here](https://aistudio.google.com/)")
st.sidebar.divider()
st.sidebar.caption("v3.0 - AI Threat Intelligence")

# --- 3. HELPER FUNCTIONS ---
def check_website_exists(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=5)
        return True
    except requests.exceptions.RequestException:
        return False

def scan_with_ai(url, key):
    client = genai.Client(api_key=key)
    prompt = f"Analyze this URL for phishing: {url}. Give a direct verdict (SAFE or PHISHING) and list 3 concise technical reasons."
    response = client.models.generate_content(model='gemini-2.5-flash', contents=prompt)
    return response.text

# --- 4. MAIN USER INTERFACE ---
url_input = st.text_input("🔗 Enter Website URL to Scan:", placeholder="e.g., github.com or victoriasecret.xyz")

# The Scan Button
if st.button("🚀 Analyze URL", use_container_width=True):
    
    # Validations
    if not api_key:
        st.warning("⚠️ Please enter your Gemini API Key in the sidebar first!")
    elif not url_input:
        st.warning("⚠️ Please enter a URL to scan!")
    else:
        # Format URL
        scan_url = 'http://' + url_input if not url_input.startswith(('http://', 'https://')) else url_input
        
        # Loading Animation
        with st.spinner("🔍 Pinging website and running AI Threat Analysis..."):
            
            if check_website_exists(scan_url):
                try:
                    # Call AI
                    result = scan_with_ai(scan_url, api_key)
                    
                    # Display Results Beautifully
                    st.subheader("📊 AI Threat Analysis Report")
                    
                    if "PHISHING" in result.upper():
                        st.error(result) # Shows red box
                    else:
                        st.success(result) # Shows green box
                        
                except Exception as e:
                    st.error(f"❌ Error communicating with AI: {e}")
            else:
                st.error("❌ THE WEBSITE DOESN'T EXIST (Or is currently down / blocked).")