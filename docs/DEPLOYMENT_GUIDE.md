# Phishing Sentinel - Deployment Guide
## Production Deployment Instructions

### System Requirements
- **OS**: Windows 10/11, Linux (Ubuntu 20.04+), macOS 12+
- **Python**: 3.10 or higher
- **RAM**: 4GB minimum (8GB recommended)
- **Storage**: 2GB free space
- **Network**: Internet connection for API calls

---

## Quick Start (5 Minutes)

### 1. Clone/Setup Project
```bash
cd c:\Users\premv\Phishing-detection
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

**Core Dependencies:**
- flask, requests, python-dotenv
- beautifulsoup4, pillow, qrcode, pyzbar
- playwright (for sandbox detonation)
- google-generativeai (for AI analysis)
- python-whois, pyOpenSSL
- reportlab (for PDF reports)

**Optional (Enhanced Features):**
```bash
# For PDF QR extraction
pip install PyMuPDF

# For audio vishing analysis
pip install SpeechRecognition pydub
```

### 3. Configure Environment Variables
Create `.env` file in project root:

```env
# === GEMINI AI API KEYS (Required) ===
GEMINI_API_KEY_1=your_gemini_api_key_here
GEMINI_API_KEY_2=your_backup_key_optional
GEMINI_API_KEY_3=another_backup_optional

# === VIRUSTOTAL API KEYS (Recommended) ===
VT_API_KEY_1=your_virustotal_key_here
VT_API_KEY_2=backup_key_optional

# === OPTIONAL: Other Threat Intel ===
URLSCAN_API_KEY=your_urlscan_key
ABUSEIPDB_API_KEY=your_abuseipdb_key

# === OPTIONAL: SIEM Integration ===
SPLUNK_HEC_URL=https://your-splunk:8088
SPLUNK_HEC_TOKEN=your_token
SLACK_WEBHOOK_URL=https://hooks.slack.com/...

# === System Settings ===
FLASK_ENV=production
FLASK_DEBUG=0
CACHE_DURATION=3600
```

**Get API Keys:**
- **Gemini AI**: https://makersuite.google.com/app/apikey
- **VirusTotal**: https://www.virustotal.com/gui/user-id/apikey
- **URLScan**: https://urlscan.io/user/profile/

### 4. Initialize System
```bash
# Test all modules
python test_all_modules.py

# Expected: 20+ tests passing
```

### 5. Start Production Server
```bash
python main.py
```

Server starts at: **http://localhost:5000**

---

## Verification Steps

### Test 1: Engine Status
Open browser: `http://localhost:5000/api/engine-status`

Should show:
```json
{
  "total_modules": 26,
  "system_version": "2.0",
  "status": "fully_operational"
}
```

### Test 2: Advanced Modules
Visit: `http://localhost:5000/api/advanced-modules`

Should list all 10 advanced modules as "active"

### Test 3: URL Scan
```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"payload": "https://google.com", "vector": "url"}'
```

Should return JSON with risk score and AI verdict.

---

## Production Configuration

### 1. Use Production WSGI Server
Replace `python main.py` with:

```bash
# Install gunicorn (Linux/Mac)
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 main:app

# Windows: Use waitress
pip install waitress
waitress-serve --port=5000 main:app
```

### 2. Enable Auto-Sync
System automatically syncs threat feeds every hour. Verify:
```bash
curl http://localhost:5000/api/sync-status
```

### 3. Set Up Reverse Proxy (Nginx)
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 4. SSL Certificate (Let's Encrypt)
```bash
certbot --nginx -d your-domain.com
```

---

## Troubleshooting

### Issue: "Module not found"
```bash
# Reinstall all dependencies
pip install -r requirements.txt --force-reinstall
```

### Issue: "API Key errors"
- Check `.env` file exists in project root
- Verify API keys are valid (not expired)
- Check key has correct permissions

### Issue: "Port 5000 already in use"
```bash
# Kill existing process
lsof -ti:5000 | xargs kill -9
# Or use different port
python main.py --port 5001
```

### Issue: "Playwright not working"
```bash
# Reinstall playwright browsers
playwright install chromium
```

### Issue: "Whois lookup fails"
- Check internet connection
- Some domains block WHOIS queries (normal behavior)
- System handles this gracefully

---

## System Architecture Overview

```
┌─────────────────────────────────────────────┐
│          USER INTERFACE (Browser)           │
│  ├─ 8 Detection Engine Cards                │
│  ├─ 10 Advanced Module Status              │
│  ├─ Risk Gauge & AI Verdict                 │
│  └─ Visual Analysis Results                 │
└─────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────┐
│         FLASK BACKEND (main.py)             │
│  ├─ /analyze (main scan endpoint)          │
│  ├─ /api/upload/* (file uploads)           │
│  ├─ /api/engine-status (health check)       │
│  └─ 15+ API endpoints                      │
└─────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────┐
│         26 MODULES INTEGRATED               │
│  ├─ 7 Detection Engines                     │
│  ├─ 8 Core Utilities                        │
│  ├─ 10 Advanced Intelligence Modules        │
│  └─ AI Router (Gemini L3 SOC Analyst)      │
└─────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────┐
│      EXTERNAL APIs (Configured in .env)     │
│  ├─ VirusTotal (threat intel)               │
│  ├─ Gemini AI (analysis & verdict)          │
│  ├─ URLScan (web scanning)                  │
│  └─ Optional: Splunk, Slack, etc.           │
└─────────────────────────────────────────────┘
```

---

## Performance Optimization

### Cache Configuration
- Default cache duration: 1 hour
- Adjust in `.env`: `CACHE_DURATION=3600`
- Clear cache: System auto-clears on restart

### API Key Rotation
- System automatically rotates Gemini/VT keys
- Add multiple keys for high-availability

### Database
- Uses JSON file storage (no SQL setup needed)
- Data stored in `data/` directory
- Automatic persistence

---

## Security Hardening

### 1. Environment Variables
- Never commit `.env` to git
- Use strong API keys
- Rotate keys monthly

### 2. Network Security
- Run behind firewall
- Use reverse proxy (nginx)
- Enable SSL/TLS

### 3. Input Validation
- All inputs sanitized automatically
- File uploads validated
- URL checks prevent SSRF

---

## Monitoring & Maintenance

### Daily Checks
```bash
# Test system health
curl http://localhost:5000/api/engine-status

# Check logs
tail -f logs/phishing_sentinel.log
```

### Weekly Tasks
- Review detection accuracy metrics
- Update threat intelligence feeds
- Check API key quotas

### Monthly Tasks
- Rotate API keys
- Review and update threat actor profiles
- Backup fingerprint database

---

## Support & Documentation

### API Documentation
- All endpoints self-documented
- Check `/api/engine-status` for module details
- Logs provide detailed operation info

### Logs Location
```
logs/
├── phishing_sentinel.log    # Main system log
├── detections.log           # Detection events
└── errors.log              # Error reports
```

### Getting Help
1. Check logs for error messages
2. Verify `.env` configuration
3. Run `python test_all_modules.py`
4. Review this deployment guide

---

## Quick Reference Commands

```bash
# Start system
python main.py

# Run tests
python test_all_modules.py

# Check status
curl http://localhost:5000/api/engine-status

# Test URL scan
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"payload": "URL_HERE", "vector": "url"}'

# Generate report
curl -X POST http://localhost:5000/api/executive/report \
  -H "Content-Type: application/json" \
  -d '{"scan_data": {...}}'
```

---

**System Version**: 2.0  
**Last Updated**: May 2026  
**Status**: Production Ready ✅

For questions or issues, check the logs and verify your `.env` configuration.
