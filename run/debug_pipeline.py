"""Deep runtime debug of the full detection pipeline."""
import sys, warnings, logging, json
warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)
sys.path.insert(0, ".")

from app.ml.local_ml import LocalMLEngine

ml = LocalMLEngine()

LEGIT = [
    "instagram.com",
    "https://instagram.com",
    "http://instagram.com",
    "google.com",
    "https://google.com",
    "microsoft.com",
    "https://microsoft.com",
    "github.com",
    "https://github.com",
    "openai.com",
    "https://openai.com",
]

PHISH = [
    "http://paypa1-secure-login.xyz/verify",
    "http://g00gle-verify.tk/auth",
    "http://instagram-support-login.xyz/reset",
    "http://rn1crosoft-update.ml/win11",
    "http://secure-paypa1.gq/login?user=victim",
]

MALFORMED = [
    "",
    "not-a-url",
    "ftp://old-proto.com",
    "instagram",
    "192.168.1.1",
]

print("=" * 70)
print("  FEATURE EXTRACTION DEEP ANALYSIS")
print("=" * 70)

FEAT_NAMES = [
    "url_length", "dot_count", "hyphen_count", "digit_count", "slash_count",
    "at_count", "question_count", "equals_count", "has_https", "has_ip",
    "subdomain_count", "domain_length", "path_length", "entropy",
    "has_suspicious_words", "tld_risk", "brand_in_subdomain", "brand_similarity",
    "domain_age_score", "ssl_score", "redirect_count", "vt_malicious_ratio",
    "has_port", "param_count", "path_depth", "double_slash", "hex_chars",
]

def analyze(url, label):
    feats = ml.extract_features(url, "url")
    pred = ml.predict_offline({"payload": url, "vector": "url"})
    
    named = {}
    for i, name in enumerate(FEAT_NAMES):
        if i < len(feats):
            named[name] = feats[i]
    
    risk_feats = {k: v for k, v in named.items() if v not in (0, 0.0)}
    
    print(f"\n[{label}] {url or '(empty)'}")
    print(f"  Verdict : {pred['verdict']}")
    print(f"  Reason  : {pred['reason']}")
    print(f"  Features ({len(feats)} total, non-zero): {risk_feats}")
    return pred["verdict"], feats

print("\n--- LEGITIMATE DOMAINS ---")
legit_fails = []
for url in LEGIT:
    verdict, feats = analyze(url, "LEGIT")
    if verdict not in ("CLEAN", "LOW RISK"):
        legit_fails.append((url, verdict))

print("\n\n--- PHISHING URLS ---")
phish_fails = []
for url in PHISH:
    verdict, feats = analyze(url, "PHISH")
    if verdict not in ("MALICIOUS", "HIGH RISK", "SUSPICIOUS"):
        phish_fails.append((url, verdict))

print("\n\n--- MALFORMED INPUTS ---")
for url in MALFORMED:
    analyze(url, "MALFORM")

print("\n\n" + "=" * 70)
print("  PROTOCOL NORMALIZATION CHECK")
print("=" * 70)
bare = ml.extract_features("instagram.com", "url")
with_https = ml.extract_features("https://instagram.com", "url")
with_http = ml.extract_features("http://instagram.com", "url")
print(f"\ninstagram.com       features: {bare}")
print(f"https://instagram.com features: {with_https}")
print(f"http://instagram.com  features: {with_http}")
print(f"\nDiff bare vs https: {[i for i,(a,b) in enumerate(zip(bare, with_https)) if a != b]}")
print(f"Diff bare vs http : {[i for i,(a,b) in enumerate(zip(bare, with_http)) if a != b]}")

print("\n\n" + "=" * 70)
print("  SUMMARY")
print("=" * 70)
print(f"\nLegit domains misclassified ({len(legit_fails)}):")
for url, v in legit_fails:
    print(f"  FAIL: {url} -> {v}")

print(f"\nPhishing URLs missed ({len(phish_fails)}):")
for url, v in phish_fails:
    print(f"  MISS: {url} -> {v}")

if not legit_fails and not phish_fails:
    print("\n  ALL CORRECT")
else:
    sys.exit(1)
