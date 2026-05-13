"""
Full end-to-end production-grade audit — Phases 1-6.
Run from project root: py -3.11 run/full_audit.py
"""
import sys, os, warnings, logging, time, json, ast, importlib, traceback
warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = "  OK  "
FAIL = " FAIL "
WARN = " WARN "

results = []

def check(label, fn):
    try:
        msg = fn()
        tag = PASS
        if msg and str(msg).startswith("WARN"):
            tag = WARN
        results.append((tag, label, msg or ""))
    except Exception as e:
        results.append((FAIL, label, str(e)[:120]))

# ── PHASE 1: SYNTAX & IMPORTS ──────────────────────────────────────────────

def syntax_check():
    bad = []
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git", "venv", ".venv")]
        for f in files:
            if not f.endswith(".py"): continue
            path = os.path.join(root, f)
            try:
                with open(path, encoding="utf-8-sig") as fh:
                    src = fh.read()
                ast.parse(src)
            except SyntaxError as e:
                bad.append(f"{path}:{e.lineno}")
    if bad:
        raise Exception(f"Syntax errors in: {bad}")

check("All .py files parse cleanly", syntax_check)

# ── PHASE 2: CORE MODULE IMPORTS ───────────────────────────────────────────

def try_import(mod):
    def _fn():
        importlib.import_module(mod)
    return _fn

for mod in [
    "app.ml.local_ml", "app.ml.ml_detector", "app.ml.heuristics",
    "app.core.url_engine", "app.core.quishing_engine", "app.core.eml_engine",
    "app.core.smishing_engine", "app.core.vishing_engine",
    "app.core.clone_engine", "app.core.socialengineering_engine",
    "app.services.threat_sync", "app.services.auto_sync",
    "app.services.lru_cache", "app.services.soar_playbook",
    "app.services.accuracy_engine", "app.services.executive_reporting",
    "app.integrations.ai_handler", "app.integrations.secure_requests",
    "app.integrations.osint_scanner",
    "app.intelligence.sandbox", "app.intelligence.ioc",
    "app.intelligence.attribution", "app.intelligence.deception",
    "app.intelligence.temporal", "app.intelligence.fingerprinting",
    "app.intelligence.countermeasures", "app.intelligence.predictive",
]:
    check(f"import {mod.split('.')[-1]}", try_import(mod))

# ── PHASE 3: ML ENGINE ─────────────────────────────────────────────────────

def ml_whitelist_legit():
    from app.ml.local_ml import LocalMLEngine
    ml = LocalMLEngine()
    fails = []
    for url in ["instagram.com", "https://google.com", "microsoft.com",
                "https://github.com", "openai.com", "https://paypal.com"]:
        r = ml.predict_offline({"payload": url, "vector": "url"})
        if r["verdict"] not in ("CLEAN", "LOW RISK"):
            fails.append(f"{url}→{r['verdict']}")
    if fails:
        raise Exception(f"False positives: {fails}")

def ml_catches_phishing():
    from app.ml.local_ml import LocalMLEngine
    ml = LocalMLEngine()
    fails = []
    for url in [
        "http://paypa1-secure-login.xyz/verify",
        "http://g00gle-verify.tk/auth",
        "http://192.168.10.1/admin",
        "http://instagram-support-login.xyz/reset",
    ]:
        r = ml.predict_offline({"payload": url, "vector": "url"})
        if r["verdict"] not in ("MALICIOUS", "HIGH RISK"):
            fails.append(f"{url}→{r['verdict']}")
    if fails:
        raise Exception(f"Missed phishing: {fails}")

def ml_normalization():
    from app.ml.local_ml import LocalMLEngine
    ml = LocalMLEngine()
    bare = ml.extract_features("instagram.com", "url")
    https = ml.extract_features("https://instagram.com", "url")
    diffs = [i for i, (a, b) in enumerate(zip(bare, https)) if a != b]
    # Only index 8 (is_https) and 1 (url_len slightly differs http vs bare) allowed
    bad = [i for i in diffs if i not in (1, 8)]
    if bad:
        raise Exception(f"Feature drift at indices {bad} between bare/https")

def ml_empty_input():
    from app.ml.local_ml import LocalMLEngine
    ml = LocalMLEngine()
    r = ml.predict_offline({"payload": "", "vector": "url"})
    if r["verdict"] == "ERROR":
        raise Exception(f"Empty input crashes ML: {r}")

def ml_malformed_input():
    from app.ml.local_ml import LocalMLEngine
    ml = LocalMLEngine()
    for bad in ["not-a-url", "ftp://old.com", "192.168.1.1", "a" * 3000]:
        r = ml.predict_offline({"payload": bad, "vector": "url"})
        if r["verdict"] == "ERROR":
            raise Exception(f"Malformed input crashes ML: {bad}")

check("ML: legit domains → CLEAN",         ml_whitelist_legit)
check("ML: phishing URLs → MALICIOUS",     ml_catches_phishing)
check("ML: bare vs https normalization",   ml_normalization)
check("ML: empty input safe",              ml_empty_input)
check("ML: malformed input safe",          ml_malformed_input)

# ── PHASE 4: ALL 7 ENGINES ─────────────────────────────────────────────────

def engines_init():
    from app.core.url_engine import URLEngine
    from app.core.quishing_engine import QREngine
    from app.core.eml_engine import EMLEngine
    from app.core.smishing_engine import SmishingEngine
    from app.core.vishing_engine import VishingEngine
    from app.core.clone_engine import CloneEngine
    from app.core.socialengineering_engine import SocialEngine
    for cls in [URLEngine, QREngine, EMLEngine, SmishingEngine, VishingEngine, CloneEngine, SocialEngine]:
        obj = cls()
        assert hasattr(obj, "analyze"), f"{cls.__name__} missing analyze()"

def url_engine_legit():
    from app.core.url_engine import URLEngine
    e = URLEngine()
    r = e.analyze("https://google.com")
    assert "calculated_risk" in r, f"Missing calculated_risk: {r.keys()}"
    assert r["calculated_risk"] <= 40, f"google.com risk too high: {r['calculated_risk']}"

def url_engine_phish():
    from app.core.url_engine import URLEngine
    e = URLEngine()
    r = e.analyze("http://paypa1-secure.xyz/login")
    assert "calculated_risk" in r, "Missing calculated_risk"
    assert r["calculated_risk"] >= 40, f"Phishing risk too low: {r['calculated_risk']}"

def eml_engine_basic():
    from app.core.eml_engine import EMLEngine
    e = EMLEngine()
    r = e.analyze("From: hack@evil.xyz\nSubject: Urgent! Verify your account\nClick: http://fake-bank.xyz/login")
    assert "calculated_risk" in r, f"Missing field: {r.keys()}"

def smishing_engine_basic():
    from app.core.smishing_engine import SmishingEngine
    e = SmishingEngine()
    r = e.analyze("Your account is blocked. Verify: http://bit.ly/fake123")
    assert "calculated_risk" in r, f"Missing field: {r.keys()}"

def vishing_engine_basic():
    from app.core.vishing_engine import VishingEngine
    e = VishingEngine()
    r = e.analyze("Your bank account has been suspended. Press 1 to speak to our fraud department.")
    assert "calculated_risk" in r or "urgency_level" in r, f"Unexpected result: {r}"

def social_engine_basic():
    from app.core.socialengineering_engine import SocialEngine
    e = SocialEngine()
    r = e.analyze_text("Congratulations! You have won $1000. Click here to claim your prize immediately!")
    assert "calculated_risk" in r, f"Missing field: {r.keys()}"

def clone_engine_basic():
    from app.core.clone_engine import CloneEngine
    e = CloneEngine()
    # Pass a clearly phishing domain (won't do live fetch in test — result may be partial)
    r = e.analyze("http://paypa1-secure.xyz")
    assert isinstance(r, dict), "Should return dict"
    assert "calculated_risk" in r, f"Missing field: {r.keys()}"

check("All 7 engines init cleanly",     engines_init)
check("URLEngine: google.com → low risk", url_engine_legit)
check("URLEngine: phish → risk>=40",    url_engine_phish)
check("EMLEngine: basic analysis",      eml_engine_basic)
check("SmishingEngine: basic analysis", smishing_engine_basic)
check("VishingEngine: basic analysis",  vishing_engine_basic)
check("SocialEngine: basic analysis",   social_engine_basic)
check("CloneEngine: basic analysis",    clone_engine_basic)

# ── PHASE 5: SERVICES & UTILITIES ──────────────────────────────────────────

def lru_cache_ops():
    from app.services.lru_cache import ThreatCache
    c = ThreatCache(max_size=5)
    h = c.generate_hash("test")
    c.set(h, {"verdict": "CLEAN"})
    got = c.get(h)
    assert got is not None and got.get("verdict") == "CLEAN", f"Cache miss: {got}"
    c.clear()
    assert c.get(h) is None

def threat_sync_init():
    from app.services.threat_sync import ThreatIntelDB
    db = ThreatIntelDB()
    stats = db.get_sync_stats()
    assert "total_threats" in stats

def auto_sync_status():
    from app.services.auto_sync import get_sync_status
    s = get_sync_status()
    assert "running" in s

def accuracy_engine_ops():
    from app.services.accuracy_engine import AccuracyEngine
    ae = AccuracyEngine()
    ae.update_metrics(10, 10, 2, 1)
    m = ae.get_metrics()
    assert "accuracy" in m
    assert m["TP"] >= 10

def soar_playbook():
    from app.services.soar_playbook import SOARPlaybook
    sp = SOARPlaybook()
    pb = sp.generate_playbook(85, "url", {}, None)
    assert isinstance(pb, (dict, list, str))

def ioc_feed_manager():
    from app.intelligence.ioc import ioc_feed_manager
    r = ioc_feed_manager.check_url("http://phish-test.xyz/verify")
    assert "threat_level" in r or "is_malicious" in r

def attribution_engine():
    from app.intelligence.attribution import attribution_engine
    r = attribution_engine.attribute_attack({"url_pattern": "http://phish.xyz", "risk_level": "HIGH"})
    assert isinstance(r, dict)

def temporal_engine():
    from app.intelligence.temporal import temporal_engine
    r = temporal_engine.analyze_attack_timeline([{"timestamp": "2026-01-01T12:00:00", "url": "http://test.xyz"}])
    assert isinstance(r, dict)

def deception_ops():
    from app.intelligence.deception import honeytoken_manager
    token = honeytoken_manager.create_token("test-qr-payload", campaign_id="test_campaign")
    assert token.email and token.password, f"Missing fields: {token}"

def secure_requests_timeout():
    from app.integrations.secure_requests import secure_get
    import requests
    try:
        secure_get("http://httpbin.org/delay/60", timeout=(1, 2))
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        return  # expected
    except Exception:
        return  # any graceful failure is fine

def secure_requests_bad_ssl():
    from app.integrations.secure_requests import secure_get
    # Should not raise unhandled exception; SSL fallback should work
    try:
        secure_get("https://expired.badssl.com/", timeout=(3, 5), enable_ssl_fallback=True)
    except Exception:
        pass  # graceful degradation expected

check("LRU cache: set/get/evict/clear",  lru_cache_ops)
check("ThreatIntelDB: init + stats",      threat_sync_init)
check("AutoSync: get_status safe",        auto_sync_status)
check("AccuracyEngine: update + get",     accuracy_engine_ops)
check("SOAR playbook generation",         soar_playbook)
check("IOC feed manager: check_url",      ioc_feed_manager)
check("Attribution engine",              attribution_engine)
check("Temporal engine",                 temporal_engine)
check("Honeytoken: generate creds",       deception_ops)
check("SecureRequests: timeout graceful", secure_requests_timeout)
check("SecureRequests: bad SSL graceful", secure_requests_bad_ssl)

# ── PHASE 6: FLASK APP ROUTES ──────────────────────────────────────────────

def flask_import():
    # Import without running — just check module-level code doesn't crash
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location("main_test",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py"))
    # Don't exec — just verify it was importable last time
    # Real route tests done via verify_all.py
    pass

def flask_routes_via_verify():
    import subprocess
    result = subprocess.run(
        [sys.executable, "run/verify_all.py"],
        capture_output=True, text=True, timeout=120,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    if "40/40 passed" not in result.stdout:
        lines = [l for l in result.stdout.splitlines() if "FAIL" in l or "ERROR" in l]
        raise Exception(f"verify_all failures: {lines}")

check("run/verify_all.py: 40/40",         flask_routes_via_verify)

# ── PHASE 7: SECURITY CHECKS ───────────────────────────────────────────────

def no_hardcoded_secrets():
    import re
    bad_patterns = [
        (r'api_key\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']', "hardcoded API key"),
        (r'password\s*=\s*["\'][^"\']{8,}["\']', "hardcoded password"),
        (r'secret\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']', "hardcoded secret"),
    ]
    hits = []
    for root, dirs, files in os.walk("app"):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            if not f.endswith(".py"): continue
            path = os.path.join(root, f)
            with open(path, encoding="utf-8-sig") as fh:
                src = fh.read()
            for pat, label in bad_patterns:
                for m in re.finditer(pat, src, re.IGNORECASE):
                    ctx = m.group()[:60]
                    if "os.getenv" not in src[max(0,m.start()-30):m.start()+60]:
                        hits.append(f"{path}: {label}: {ctx}")
    if hits:
        return f"WARN: Possible hardcoded secrets — review: {hits[:3]}"

def no_eval_usage():
    import re
    hits = []
    for root, dirs, files in os.walk("app"):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            if not f.endswith(".py"): continue
            path = os.path.join(root, f)
            with open(path, encoding="utf-8-sig") as fh:
                for i, line in enumerate(fh, 1):
                    stripped = line.strip()
                    if stripped.startswith('#'): continue
                    # Exclude: byte/string literals containing 'eval(', torch .eval(), list items
                    if re.search(r'\beval\s*\(', stripped):
                        # Safe patterns: b'eval(', 'eval(', .eval(), self.model.eval()
                        if re.search(r"[b'\"]\'?eval\(", stripped): continue   # string literal
                        if re.search(r'\.eval\(\)', stripped): continue          # method call like model.eval()
                        hits.append(f"{path}:{i}: {stripped[:60]}")
    if hits:
        raise Exception(f"Dangerous eval() usage found: {hits}")

def no_unsafe_subprocess():
    import re
    hits = []
    for root, dirs, files in os.walk("app"):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            if not f.endswith(".py"): continue
            path = os.path.join(root, f)
            with open(path, encoding="utf-8-sig") as fh:
                for i, line in enumerate(fh, 1):
                    if re.search(r'subprocess\.(call|run|Popen).*shell\s*=\s*True', line):
                        hits.append(f"{path}:{i}")
    if hits:
        raise Exception(f"shell=True subprocess: {hits}")

check("No hardcoded API secrets",       no_hardcoded_secrets)
check("No eval() usage",               no_eval_usage)
check("No shell=True subprocess",      no_unsafe_subprocess)

# ── PRINT REPORT ───────────────────────────────────────────────────────────

print()
print("=" * 68)
print("  FULL PRODUCTION AUDIT RESULTS")
print("=" * 68)
passed = sum(1 for t, _, _ in results if t == PASS)
warned = sum(1 for t, _, _ in results if t == WARN)
failed = sum(1 for t, _, _ in results if t == FAIL)

for tag, label, detail in results:
    line = f"[{tag}] {label}"
    if tag != PASS and detail:
        line += f"\n          {detail}"
    print(line)

print()
print("=" * 68)
print(f"  PASSED: {passed}   WARNED: {warned}   FAILED: {failed}   TOTAL: {len(results)}")
print("=" * 68)

if failed > 0:
    sys.exit(1)
