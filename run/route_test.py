"""Live HTTP route tests against running Flask server."""
import urllib.request, urllib.error, json, sys, time

BASE = "http://127.0.0.1:5000"
PASS, FAIL = "  OK  ", " FAIL "
results = []

def get(path, expect=200):
    try:
        r = urllib.request.urlopen(BASE + path, timeout=15)
        code = r.status
        body = r.read()
        ok = (code == expect)
        tag = PASS if ok else FAIL
        results.append((tag, f"GET {path}", f"HTTP {code}"))
        return code, body
    except urllib.error.HTTPError as e:
        ok = (e.code == expect)
        tag = PASS if ok else FAIL
        results.append((tag, f"GET {path}", f"HTTP {e.code}"))
        return e.code, b""
    except Exception as e:
        results.append((FAIL, f"GET {path}", str(e)[:80]))
        return 0, b""

def post(path, body, expect=200, check_keys=None):
    try:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            BASE + path, data=data,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        r = urllib.request.urlopen(req, timeout=30)
        code = r.status
        resp = json.loads(r.read().decode())
        missing = [k for k in (check_keys or []) if k not in resp]
        ok = code == expect and not missing
        tag = PASS if ok else FAIL
        detail = f"HTTP {code}" + (f" missing={missing}" if missing else "")
        results.append((tag, f"POST {path}", detail))
        return code, resp
    except urllib.error.HTTPError as e:
        ok = (e.code == expect)
        tag = PASS if ok else FAIL
        body_text = e.read().decode(errors="replace")[:80]
        results.append((tag, f"POST {path}", f"HTTP {e.code} {body_text}"))
        return e.code, {}
    except Exception as e:
        results.append((FAIL, f"POST {path}", str(e)[:80]))
        return 0, {}

# ── Page routes ──────────────────────────────────────────────────────────
get("/")
get("/accuracy")
get("/api/metrics")
get("/api/threats")
get("/api/sync-status")
get("/api/engine-status")
get("/api/advanced-modules")
get("/favicon.ico", expect=204)

# ── Analyze endpoint ─────────────────────────────────────────────────────
# Legit domains must not be high risk
code, resp = post("/analyze",
    {"payload": "https://google.com", "vector": "url"},
    check_keys=["ai_report", "calculated_risk"])
if resp.get("calculated_risk", 999) > 50:
    results[-1] = (FAIL, "POST /analyze google.com risk<=50",
                   f"risk={resp.get('calculated_risk')}")

code, resp = post("/analyze",
    {"payload": "https://instagram.com", "vector": "url"},
    check_keys=["ai_report"])
if resp.get("calculated_risk", 999) > 50:
    results[-1] = (FAIL, "POST /analyze instagram.com risk<=50",
                   f"risk={resp.get('calculated_risk')}")

# Phishing URL should have ai_report
post("/analyze",
    {"payload": "http://paypa1-secure.xyz/login", "vector": "url"},
    check_keys=["ai_report", "calculated_risk"])

# Other vectors
post("/analyze",
    {"payload": "Urgent: click http://fake-bank.xyz to verify", "vector": "eml"},
    check_keys=["ai_report"])

post("/analyze",
    {"payload": "Your OTP expires: http://sms-phish.tk", "vector": "smishing"},
    check_keys=["ai_report"])

post("/analyze",
    {"payload": "This is your bank. Press 1 for account verification.", "vector": "vishing"},
    check_keys=["ai_report"])

# Empty payload should not crash
code, resp = post("/analyze", {"payload": "", "vector": "url"})
if code == 500:
    results[-1] = (FAIL, "POST /analyze empty payload safe", f"HTTP 500 crash")

# ── Advanced endpoints ────────────────────────────────────────────────────
post("/api/honeytoken/generate",
    {"campaign_id": "test"},
    check_keys=["status", "credentials"])

post("/api/offensive_attack",
    {"target_url": "http://phish-test.xyz"},
    check_keys=["status", "injected_records"])

# ── Print results ─────────────────────────────────────────────────────────
print()
print("=" * 62)
print("  LIVE ROUTE TEST RESULTS")
print("=" * 62)
passed = failed = 0
for tag, label, detail in results:
    line = f"[{tag}] {label}"
    if tag != PASS:
        line += f"\n          {detail}"
        failed += 1
    else:
        passed += 1
    print(line)

print()
print("=" * 62)
print(f"  PASSED: {passed}   FAILED: {failed}   TOTAL: {len(results)}")
print("=" * 62)
sys.exit(1 if failed else 0)
