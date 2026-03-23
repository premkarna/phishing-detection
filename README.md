# 🛡️ AI Phishing Sentinel V4.0 Enterprise

![Status](https://img.shields.io/badge/Status-Active-success)
![Version](https://img.shields.io/badge/Version-4.0_Enterprise-blue)
![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![AI](https://img.shields.io/badge/AI_Engine-Gemini_Pro-orange)

An advanced, real-time threat intelligence platform designed to detect zero-day phishing attacks, typosquatting, and homograph vulnerabilities using multi-vector analysis and Neural-Net heuristics.

## 🚀 Key Features

* **🧠 AI-Powered Threat Heuristics:** Utilizes Google Gemini AI to analyze URL structures and detect sophisticated Typosquatting (e.g., `instagrarn` vs `instagram`) and Punycode attacks.
* **🕵️ Stealth Mode (Anti-Bot Bypass):** Implements User-Agent spoofing to bypass anti-bot mechanisms on major platforms (like PayPal, Netflix) to accurately retrieve SSL and server statuses.
* **🌐 Deep-Web Telemetry:** Cross-references URLs with the VirusTotal API database for global threat consensus.
* **🔍 Advanced Domain Intel:** Uses modern RDAP APIs with a classic WHOIS fallback (with strict timezone handling) to determine exact domain age and registration anomalies.
* **🔒 SSL/TLS Validation:** Performs real-time socket connections to verify SSL certificate issuers and expiry dates.
* **⚡ In-Memory Caching:** Built-in 24-hour result caching system to optimize API limits and provide lightning-fast (<0.1s) responses for repeated targets.
* **📊 Executive Reporting:** Generates downloadable, print-ready HTML Threat Intelligence Reports suitable for SOC (Security Operations Center) analysts.

## 💻 System Architecture & Tech Stack

* **Backend Engine:** Python, FastAPI, Uvicorn
* **Threat Intel APIs:** Google Gemini API, VirusTotal v3 API, IP-API, RDAP Protocol
* **Frontend UI:** HTML5, CSS3 (Advanced Glassmorphism & HUD Design), Vanilla JavaScript
* **Security Libraries:** `ssl`, `socket`, `python-whois`, `urllib`

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/premkarna/AI-Phishing-Sentinel.git](https://github.com/premkarna/AI-Phishing-Sentinel.git)
   cd AI-Phishing-Sentinel