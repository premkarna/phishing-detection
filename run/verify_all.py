"""Full system verification — runs all module/engine/ML/cache tests."""
import sys
import os
import warnings
import logging
import tempfile
import traceback

warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

results_ok = []
results_fail = []

def test(label, fn):
    try:
        fn()
        results_ok.append(label)
        print(f"  OK   {label}")
    except Exception as e:
        results_fail.append((label, str(e)))
        print(f"  FAIL {label}: {e}")
        traceback.print_exc()

# ── Flask ──────────────────────────────────────────────────────────────
def t_routes():
    import main
    rules = [r.rule for r in main.app.url_map.iter_rules()]
    required = ["/analyze", "/accuracy", "/api/metrics", "/api/threats",
                "/api/sync-status", "/download_report", "/run_tests",
                "/api/advanced-modules"]
    missing = [r for r in required if r not in rules]
    assert not missing, f"Missing routes: {missing}"

# ── Engines ────────────────────────────────────────────────────────────
def t_engines_init():
    from app.core.url_engine import URLEngine
    from app.core.quishing_engine import QREngine
    from app.core.eml_engine import EMLEngine
    from app.core.smishing_engine import SmishingEngine
    from app.core.vishing_engine import VishingEngine
    from app.core.clone_engine import CloneEngine
    from app.core.socialengineering_engine import SocialEngine
    for cls in [URLEngine, QREngine, EMLEngine, SmishingEngine,
                VishingEngine, CloneEngine, SocialEngine]:
        assert cls() is not None

def t_url_engine():
    from app.core.url_engine import URLEngine
    e = URLEngine()
    r = e.analyze("http://paypa1-secure.xyz/login")
    assert "calculated_risk" in r, f"Missing calculated_risk: {r}"

def t_qr_engine():
    from app.core.quishing_engine import QREngine
    e = QREngine()
    r = e.analyze("http://g00gle-verify.tk/auth")
    assert "calculated_risk" in r

def t_eml_engine():
    from app.core.eml_engine import EMLEngine
    e = EMLEngine()
    sample = "From: phish@evil.xyz\nSubject: Urgent\n\nClick here: http://evil.xyz/login"
    r = e.analyze(sample)
    assert "calculated_risk" in r

def t_smishing_engine():
    from app.core.smishing_engine import SmishingEngine
    e = SmishingEngine()
    r = e.analyze("URGENT: Your account is locked. Verify at http://bank-alert.xyz")
    assert "calculated_risk" in r

def t_clone_engine():
    from app.core.clone_engine import CloneEngine
    e = CloneEngine()
    r = e.analyze("https://google.com")
    assert "calculated_risk" in r

def t_social_engine():
    from app.core.socialengineering_engine import SocialEngine
    e = SocialEngine()
    r = e.analyze_text("You have won a prize! Click here to claim.")
    assert "calculated_risk" in r

# ── ML ─────────────────────────────────────────────────────────────────
def t_ml_predict():
    from app.ml.local_ml import LocalMLEngine
    e = LocalMLEngine()
    r = e.predict_offline({"payload": "http://paypa1-secure.xyz/login", "vector": "url"})
    assert "verdict" in r
    assert r["verdict"] in ("MALICIOUS", "CLEAN", "ERROR")

def t_ml_clean_predict():
    from app.ml.local_ml import LocalMLEngine
    e = LocalMLEngine()
    r = e.predict_offline({"payload": "https://google.com", "vector": "url"})
    assert "verdict" in r

def t_ml_features():
    from app.ml.local_ml import LocalMLEngine
    e = LocalMLEngine()
    f = e.extract_features("http://paypa1-secure.xyz/login", "url")
    assert len(f) == 27, f"Expected 27 features, got {len(f)}"

def t_ml_detector():
    from app.ml.ml_detector import ml_detector
    r = ml_detector.predict("http://evil-phish.xyz/login")
    assert "classification" in r

def t_heuristics():
    from app.ml.heuristics import DomainHeuristics
    h = DomainHeuristics()
    r = h.full_analysis("http://paypa1-secure.xyz/login")
    assert isinstance(r, dict)

# ── Cache ──────────────────────────────────────────────────────────────
def t_lru_cache():
    from app.services.lru_cache import ThreatCache
    c = ThreatCache(max_size=5)
    h = c.generate_hash("test-payload")
    c.set(h, {"verdict": "SAFE"})
    result = c.get(h)
    assert result is not None
    assert result["verdict"] == "SAFE"

def t_lru_eviction():
    from app.services.lru_cache import ThreatCache
    c = ThreatCache(max_size=3)
    for i in range(4):
        h = c.generate_hash(f"site{i}.com")
        c.set(h, {"site": i})
    h0 = c.generate_hash("site0.com")
    assert c.get(h0) is None  # oldest evicted

# ── Intelligence ───────────────────────────────────────────────────────
def t_ioc():
    from app.intelligence.ioc import ioc_feed_manager
    r = ioc_feed_manager.check_url("http://google.com")
    assert "is_malicious" in r

def t_attribution():
    from app.intelligence.attribution import attribution_engine
    r = attribution_engine.attribute_attack({
        "url_pattern": "http://test.xyz", "domain": "test.xyz",
        "detected_brand": "", "risk_level": "LOW"
    })
    assert isinstance(r, dict)

def t_temporal():
    from app.intelligence.temporal import temporal_engine
    import datetime
    records = [{"timestamp": datetime.datetime.now().isoformat(), "url": "http://test.xyz"}]
    r = temporal_engine.analyze_attack_timeline(records)
    assert isinstance(r, dict)

def t_fingerprinting():
    from app.intelligence.fingerprinting import qr_fingerprint_engine
    fp = qr_fingerprint_engine.create_fingerprint("http://evil.xyz/qr")
    assert fp is not None

def t_deception():
    from app.intelligence.deception import honeytoken_manager
    t = honeytoken_manager.create_token("http://evil.xyz/qr")
    assert t is not None

def t_sandbox_engine():
    from app.intelligence.sandbox_engine import SandboxSimulator
    s = SandboxSimulator()
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
        f.write("test content\nimport os\nos.system('whoami')")
        p = f.name
    try:
        r = s.analyze_file(p)
        assert isinstance(r, dict)
    finally:
        os.unlink(p)

def t_sandbox_detonator():
    from app.intelligence.sandbox import SandboxDetonator
    s = SandboxDetonator()
    assert os.path.isdir(s.sandbox_dir)

def t_predictive():
    from app.intelligence.predictive import PredictiveIntel
    p = PredictiveIntel()
    r = p.predict_next_target({"brand_check": "PAYPAL"})
    assert isinstance(r, dict)

def t_countermeasures():
    from app.intelligence.countermeasures import OffensiveDefense
    o = OffensiveDefense()
    assert o is not None

# ── Services ───────────────────────────────────────────────────────────
def t_soar():
    from app.services.soar_playbook import SOARPlaybook
    s = SOARPlaybook()
    r = s.generate_playbook(85, "url", {}, None)
    assert isinstance(r, dict)

def t_osint():
    from app.integrations.osint_scanner import DarkWebOSINT
    o = DarkWebOSINT()
    r = o.scan_payload("test@example.com")
    assert isinstance(r, dict)

def t_accuracy():
    from app.services.accuracy_engine import AccuracyEngine
    a = AccuracyEngine()
    m0 = a.get_metrics()
    a.update_metrics(m0['TP']+1, m0['TN'], m0['FP'], m0['FN'])
    m = a.get_metrics()
    assert "accuracy" in m

def t_threat_sync():
    from app.services.threat_sync import ThreatIntelDB
    db = ThreatIntelDB()
    s = db.get_sync_stats()
    assert "total_threats" in s

def t_report_generator():
    from app.services.report_generator import generate_pdf_report
    sample = {
        "calculated_risk": 90, "vector": "url",
        "ai_report": {"verdict": "MALICIOUS", "reason": "Test", "advice": "Block"},
        "soar_playbook": {"phases": []}, "payload": "http://evil.xyz"
    }
    path = generate_pdf_report(sample)
    assert path and os.path.exists(path)
    os.unlink(path)

def t_ai_handler_nokeys():
    from app.integrations.ai_handler import AIHandler
    a = AIHandler(["short"])  # key too short (<10 chars) -> filtered -> no active keys
    assert not a.is_active

def t_api_rotator():
    from app.integrations.api_rotator import APIRotator
    r = APIRotator(["KEY1", "KEY2", "KEY3"], "TestSvc")
    assert r.get_key() == "KEY1"
    assert r.get_key() == "KEY2"
    assert r.get_key() == "KEY3"
    assert r.get_key() == "KEY1"  # wraps

def t_secure_requests():
    from app.integrations.secure_requests import secure_get
    assert callable(secure_get)

def t_integration_hub():
    from app.services.integration_hub import integration_hub
    assert integration_hub is not None

def t_executive_reporting():
    from app.services.executive_reporting import executive_reporting
    r = executive_reporting.generate_executive_summary([], period_days=7)
    assert isinstance(r, dict)

def t_url_tracer():
    from app.services.url_tracer import URLTracer
    t = URLTracer()
    assert t is not None

def t_auto_sync():
    from app.services.auto_sync import get_sync_status
    s = get_sync_status()
    assert isinstance(s, dict)

# ── DOM / Visual / PDF ─────────────────────────────────────────────────
def t_dom_scanner():
    from app.core.dom_scanner import DOMScanner
    d = DOMScanner()
    assert d is not None

def t_visual_analyzer():
    from app.core.visual_analyzer import VisualAnalyzer
    v = VisualAnalyzer()
    assert v is not None

def t_pdf_analyzer():
    from app.core.pdf_analyzer import pdf_analyzer
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False, mode="wb") as f:
        f.write(b"%PDF-1.4 test")
        p = f.name
    try:
        r = pdf_analyzer.analyze(p)
        assert isinstance(r, dict)
    finally:
        os.unlink(p)

def t_zero_click():
    from app.core.zero_click_extractor import ZeroClickExtractor
    z = ZeroClickExtractor()
    assert z is not None

# ── Run all tests ──────────────────────────────────────────────────────
TESTS = [
    ("Flask routes",             t_routes),
    ("All 7 engines init",       t_engines_init),
    ("URLEngine analyze",        t_url_engine),
    ("QREngine analyze",         t_qr_engine),
    ("EMLEngine analyze",        t_eml_engine),
    ("SmishingEngine analyze",   t_smishing_engine),
    ("CloneEngine analyze",      t_clone_engine),
    ("SocialEngine analyze",     t_social_engine),
    ("ML predict malicious",     t_ml_predict),
    ("ML predict clean",         t_ml_clean_predict),
    ("ML feature extraction",    t_ml_features),
    ("ML detector",              t_ml_detector),
    ("Domain heuristics",        t_heuristics),
    ("LRU cache set/get",        t_lru_cache),
    ("LRU eviction",             t_lru_eviction),
    ("IOC feed manager",         t_ioc),
    ("Attribution engine",       t_attribution),
    ("Temporal analysis",        t_temporal),
    ("QR fingerprinting",        t_fingerprinting),
    ("Deception/honeytoken",     t_deception),
    ("Sandbox file analysis",    t_sandbox_engine),
    ("Sandbox detonator",        t_sandbox_detonator),
    ("Predictive intel",         t_predictive),
    ("Countermeasures/OffDef",   t_countermeasures),
    ("SOAR playbook",            t_soar),
    ("OSINT scanner",            t_osint),
    ("Accuracy engine",          t_accuracy),
    ("Threat sync DB",           t_threat_sync),
    ("PDF report gen",           t_report_generator),
    ("AI handler (no keys)",     t_ai_handler_nokeys),
    ("API key rotator",          t_api_rotator),
    ("Secure requests",          t_secure_requests),
    ("Integration hub",          t_integration_hub),
    ("Executive reporting",      t_executive_reporting),
    ("URL tracer",               t_url_tracer),
    ("Auto sync status",         t_auto_sync),
    ("DOM scanner",              t_dom_scanner),
    ("Visual analyzer",          t_visual_analyzer),
    ("PDF analyzer",             t_pdf_analyzer),
    ("Zero-click extractor",     t_zero_click),
]

print(f"\n{'='*60}")
print("  PHISHING SENTINEL — FULL SYSTEM VERIFICATION")
print(f"{'='*60}\n")

for label, fn in TESTS:
    test(label, fn)

total = len(results_ok) + len(results_fail)
print(f"\n{'='*60}")
print(f"  RESULT: {len(results_ok)}/{total} passed")
print(f"{'='*60}")

if results_fail:
    print("\nFAILURES:")
    for label, err in results_fail:
        print(f"  [{label}]")
        print(f"    {err}")

sys.exit(0 if not results_fail else 1)
