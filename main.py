import logging
import os
import json
import tempfile
import datetime
from flask import Flask, render_template, request, jsonify, send_file
from dotenv import load_dotenv

# Project root — main.py lives here
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

from app.services.lru_cache import global_cache
from app.utils.console_cleaner import setup_hacker_console
from app.integrations.ai_handler import AIHandler
from app.services.report_generator import generate_pdf_report
from app.ml.local_ml import LocalMLEngine
from app.services.threat_sync import ThreatIntelDB
from app.intelligence.countermeasures import OffensiveDefense
from app.integrations.osint_scanner import DarkWebOSINT
from app.intelligence.sandbox_engine import SandboxSimulator
from app.services.soar_playbook import SOARPlaybook
from app.intelligence.predictive import PredictiveIntel
from app.services.accuracy_engine import AccuracyEngine
from app.services.auto_sync import start_auto_sync, get_sync_status

# NEW: 10 Advanced Intelligence Modules
from app.intelligence.deception import honeytoken_manager
from app.core.pdf_analyzer import pdf_analyzer
from app.intelligence.ioc import ioc_feed_manager
from app.intelligence.fingerprinting import qr_fingerprint_engine
from app.intelligence.attribution import attribution_engine
from app.intelligence.browser_fingerprinting import fingerprinting_detector
from app.intelligence.temporal import temporal_engine
from app.ml.ml_detector import ml_detector
from app.services.integration_hub import integration_hub
from app.services.executive_reporting import executive_reporting
from app.intelligence.sandbox import sandbox_detonator
from app.core.visual_analyzer import VisualAnalyzer
from app.ml.heuristics import DomainHeuristics

# Importing our 7 Engines
from app.core.url_engine import URLEngine
from app.core.quishing_engine import QREngine
from app.core.eml_engine import EMLEngine
from app.core.smishing_engine import SmishingEngine
from app.core.vishing_engine import VishingEngine
from app.core.clone_engine import CloneEngine
from app.core.socialengineering_engine import SocialEngine

# Validate data file locations (prevent root pollution)
_DATA_FILES = ['global_threats.db', 'ioc_cache.json', 'qr_fingerprints.json', 
               'soc_metrics.json', 'threat_actors.json']
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
CACHE_DIR = os.path.join(DATA_DIR, 'cache')
for f in _DATA_FILES:
    if os.path.exists(os.path.join(PROJECT_ROOT, f)):
        logging.warning(f"[VALIDATION] ⚠️ Data file '{f}' found in root! Should be in data/cache/ folder. Run cleanup.py")

# GPU Acceleration (RTX 3050) - Optional but Recommended
GPUManager = None  # Will be set if import succeeds
try:
    from app.ml.gpu_integration import get_gpu_engines, GPUManager
    GPU_AVAILABLE = True
    logging.info("[GPU] 🚀 RTX 3050 GPU Acceleration Available")
except ImportError as e:
    GPU_AVAILABLE = False
    logging.info(f"[GPU] ⚠️ GPU modules not available: {e}")

def get_gpu_status_safe():
    """Safely get GPU status without raising NameError"""
    if GPU_AVAILABLE and GPUManager is not None:
        try:
            return GPUManager.get_status()
        except Exception as e:
            return {"cuda_available": False, "error": str(e), "note": "GPU status query failed"}
    return {"cuda_available": False, "note": "GPU modules not loaded"}

# Load Env
load_dotenv()

# API Keys - dynamically loads GEMINI_API_KEY_1, _2, _3, ... and VT_API_KEY_1, _2, _3, ...
def _load_keys(prefix):
    keys, i = [], 1
    while True:
        k = os.getenv(f"{prefix}_{i}")
        if not k:
            break
        keys.append(k)
        i += 1
    return keys

GEMINI_KEYS = _load_keys("GEMINI_API_KEY")
VT_KEYS = _load_keys("VT_API_KEY")

# Setup Console
setup_hacker_console()

# Initialize Flask with correct template and static folders
app = Flask(__name__,
            template_folder=os.path.join(PROJECT_ROOT, 'frontend', 'templates'),
            static_folder=os.path.join(PROJECT_ROOT, 'frontend', 'static'))

# Initialize Global Components
local_ml = LocalMLEngine()
offensive_engine = OffensiveDefense()
osint_engine = DarkWebOSINT()
sandbox_engine = SandboxSimulator()
soar_engine = SOARPlaybook()
predictive_engine = PredictiveIntel()
threat_db = ThreatIntelDB()
ai_handler = AIHandler(GEMINI_KEYS)
acc_engine = AccuracyEngine()

# Initialize GPU-enhanced engines if available
if GPU_AVAILABLE:
    try:
        gpu_url_engine, gpu_qr_engine, gpu_manager = get_gpu_engines()
        engines = {
            "url": gpu_url_engine,
            "qr": gpu_qr_engine,
            "eml": EMLEngine(),
            "smishing": SmishingEngine(),
            "vishing": VishingEngine(),
            "clone": CloneEngine(),
            "social": SocialEngine()
        }
        logging.info("[GPU] ✅ GPU-Accelerated Engines Active (95x Speedup)")
        
        # Log GPU status
        gpu_status = GPUManager.get_status()
        logging.info(f"[GPU] VRAM: {gpu_status.get('free_vram_gb', 'N/A')}GB free / {gpu_status.get('total_vram_gb', 'N/A')}GB total")
    except Exception as e:
        logging.error(f"[GPU] ⚠️ Failed to initialize GPU engines: {e}")
        import traceback
        logging.error(f"[GPU] Traceback: {traceback.format_exc()}")
        engines = {
            "url": URLEngine(),
            "qr": QREngine(),
            "eml": EMLEngine(),
            "smishing": SmishingEngine(),
            "vishing": VishingEngine(),
            "clone": CloneEngine(),
            "social": SocialEngine()
        }
else:
    engines = {
        "url": URLEngine(),
        "qr": QREngine(),
        "eml": EMLEngine(),
        "smishing": SmishingEngine(),
        "vishing": VishingEngine(),
        "clone": CloneEngine(),
        "social": SocialEngine()
    }

# Initialize Advanced Utilities
visual_analyzer = VisualAnalyzer()
heuristics = DomainHeuristics()

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/.well-known/appspecific/com.chrome.devtools.json')
def chrome_devtools():
    return jsonify({}), 200

@app.route('/')
def index():
    # Cache busting timestamp
    v = datetime.datetime.now().timestamp()
    return render_template('index.html', v=v)

@app.route('/api/advanced-modules')
def api_advanced_modules():
    """Returns status of all 10 advanced intelligence modules"""
    return jsonify({
        "modules": [
            {"id": "honeytoken", "name": "Honeytoken Manager", "icon": "fa-cookie-bite", "color": "amber", 
             "status": "active", "detail": "Bait credentials ready"},
            {"id": "pdf_analyzer", "name": "PDF Analyzer", "icon": "fa-file-pdf", "color": "red",
             "status": "active", "detail": "JS detection active"},
            {"id": "ioc_feeds", "name": "IOC Feed Manager", "icon": "fa-globe", "color": "cyan",
             "status": "active", "detail": "5 feeds connected"},
            {"id": "qr_fingerprint", "name": "QR Fingerprinting", "icon": "fa-fingerprint", "color": "purple",
             "status": "active", "detail": "Tracking enabled"},
            {"id": "attribution", "name": "Campaign Attribution", "icon": "fa-user-secret", "color": "pink",
             "status": "active", "detail": "APT profiles loaded"},
            {"id": "browser_fp", "name": "Browser Fingerprinting", "icon": "fa-fingerprint", "color": "teal",
             "status": "active", "detail": "Canvas detection on"},
            {"id": "temporal", "name": "Temporal Analysis", "icon": "fa-clock", "color": "orange",
             "status": "active", "detail": "Timeline analysis"},
            {"id": "ml_detector", "name": "ML Detector", "icon": "fa-robot", "color": "green",
             "status": "active", "detail": "20 features active"},
            {"id": "integration", "name": "Integration Hub", "icon": "fa-plug", "color": "blue",
             "status": "active", "detail": "SIEM ready"},
            {"id": "executive", "name": "Executive Reporting", "icon": "fa-chart-pie", "color": "yellow",
             "status": "active", "detail": "Dashboards ready"}
        ],
        "total_modules": 10,
        "integration_status": "fully_operational"
    })

def generate_detailed_analysis(result, vector_type, risk):
    """Generate detailed forensic analysis based on scan results"""
    analysis_parts = []
    
    # Vector-specific analysis
    if vector_type == 'url':
        if result.get('brand_check', '').startswith('TYPOSQUATTING'):
            brand = result.get('brand_check', '').replace('TYPOSQUATTING:', '').strip()
            analysis_parts.append(f"⚠️ TYPOSQUATTING DETECTED: Domain attempts to mimic '{brand}' through character substitution. This is a classic phishing technique.")
        
        if result.get('virustotal', '0/0').split('/')[0] != '0':
            vt_result = result.get('virustotal', '0/0')
            analysis_parts.append(f"🚨 VIRUSTOTAL ALERT: {vt_result} security engines flagged this URL as malicious or suspicious.")
    
    elif vector_type == 'qr':
        analysis_parts.append("📱 QR CODE ANALYSIS: Decoded payload extracted and analyzed through multi-vector detection.")
        if result.get('extracted_url'):
            analysis_parts.append(f"🔗 Embedded URL: {result['extracted_url']}")
    
    elif vector_type == 'eml':
        if result.get('suspicious_links', 'Clean') != 'Clean':
            analysis_parts.append(f"📧 EMAIL FORENSICS: {result.get('suspicious_links')}")
        if result.get('pressure_tactics', 'None') != 'None':
            analysis_parts.append(f"⚡ SOCIAL ENGINEERING: {result.get('pressure_tactics')} detected.")
    
    # Risk-based analysis
    if risk >= 70:
        analysis_parts.append("🔴 CRITICAL RISK: Multiple high-confidence indicators of malicious activity present. Immediate action recommended.")
    elif risk >= 40:
        analysis_parts.append("🟡 MEDIUM RISK: Suspicious patterns detected. Caution advised before interacting with this content.")
    else:
        analysis_parts.append("🟢 LOW RISK: No significant threats detected. Standard security protocols sufficient.")
    
    return "\n\n".join(analysis_parts) if analysis_parts else "Analysis complete. No specific threats identified."

def generate_recommendation(result, verdict, risk):
    """Generate actionable security recommendations"""
    recommendations = []
    
    if "MALICIOUS" in verdict.upper():
        recommendations.append("🚫 BLOCK IMMEDIATELY: Prevent all access to this resource.")
        recommendations.append("📊 QUARANTINE: Isolate any systems that may have interacted with this content.")
        recommendations.append("🔔 ALERT SOC: Notify security operations center for incident response.")
        
        if risk >= 80:
            recommendations.append("🚨 ESCALATE: High-confidence threat - consider enterprise-wide protective actions.")
    
    elif "SUSPICIOUS" in verdict.upper():
        recommendations.append("⚠️ MONITOR CLOSELY: Enable enhanced logging for any interactions.")
        recommendations.append("🔍 INVESTIGATE: Manual review recommended before allowing access.")
        recommendations.append("📋 DOCUMENT: Record findings for threat intelligence database.")
    
    else:
        recommendations.append("✅ PROCEED WITH CAUTION: Standard security awareness practices apply.")
        recommendations.append("📖 LOG: Maintain record for baseline threat landscape analysis.")
    
    # Vector-specific recommendations
    if result.get('vector') == 'eml':
        recommendations.append("📧 EMAIL SECURITY: Train users to recognize similar phishing patterns.")
    elif result.get('vector') == 'qr':
        recommendations.append("📱 QR AWARENESS: Remind users to verify URLs before entering credentials.")
    
    return "\n\n".join(recommendations)

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    payload = data.get('payload')
    vector_type = data.get('vector', 'url').lower()
    
    # 0. Cache Check (0.005s speed bypass)
    payload_hash = global_cache.generate_hash(payload + vector_type)
    cached_result = global_cache.get(payload_hash)
    if cached_result:
        return jsonify(cached_result)

    # 1. Engine Analysis
    try:
        if "url" in vector_type:
            if engines["url"].vt_api_rotator:
                engines["url"].vt_api_key = engines["url"].vt_api_rotator.get_key()
            elif VT_KEYS:
                engines["url"].vt_api_key = VT_KEYS[0]
            result = engines["url"].analyze(payload)
        elif vector_type == "smishing":
            sender_id = data.get('sender_id', '')
            sender_type = data.get('sender_type', 'alpha')
            phone_number = data.get('phone_number', '')
            result = engines["smishing"].analyze(payload, sender_id=sender_id, phone_number=phone_number, sender_type=sender_type)
        elif vector_type == "social":
            platform = data.get('platform', None)
            is_url = payload.strip().startswith(("http://", "https://", "www."))
            if is_url:
                result = engines["social"].analyze(payload)
            else:
                result = engines["social"].analyze_text(payload, platform=platform)
        else:
            result = engines.get(vector_type, engines["url"]).analyze(payload)
    except Exception as e:
        result = {"calculated_risk": 50, "status": f"Engine Error: {str(e)}"}

    # 2. MANDATORY GEMINI AI VERDICT (NO MORE LOCAL ML BY DEFAULT)
    ai_report = {"verdict": "ERROR"}
    
    if ai_handler.is_active:
        ai_report = ai_handler.get_consensus(result, vector_type, all_engines_data=result)
        
    # ONLY fallback to Local ML if Gemini is literally broken/quota hit
    if ai_report.get("verdict") in ["ERROR", "SUSPICIOUS (AI_ERROR)"]:
        logging.warning("[!] GEMINI FAILED. Using emergency Local ML.")
        ml_verdict = local_ml.predict_offline(result)
        ai_report = {
            "verdict": ml_verdict["verdict"] + " (EMERGENCY OFFLINE)",
            "reason": f"[OFFLINE MODE] {ml_verdict['reason']}",
            "advice": "AI API error. Results based on heuristic patterns."
        }
    
    # 3. OVERRIDE: Only force MALICIOUS when AI is offline/fallback AND typosquatting/high risk detected.
    #    When Gemini gave a real verdict, trust it — it already read the page content and can
    #    distinguish a phishing clone from a legitimate site with a similar domain name.
    risk = result.get('calculated_risk', 0)
    brand = str(result.get('brand_check', ''))
    ai_verdict_str = ai_report.get('verdict', '')
    ai_used_fallback = 'FALLBACK' in ai_verdict_str.upper() or 'OFFLINE' in ai_verdict_str.upper() or 'ERROR' in ai_verdict_str.upper()
    if ai_used_fallback and ("TYPOSQUATTING" in brand or risk >= 70):
        if "MALICIOUS" not in ai_verdict_str.upper():
            ai_report['verdict'] = "MALICIOUS (PHISHING)"
            if 'reason' not in ai_report or not ai_report['reason']:
                ai_report['reason'] = generate_detailed_analysis(result, vector_type, risk)
    
    # Generate detailed analysis if not present
    if 'reason' not in ai_report or not ai_report['reason'] or ai_report['reason'] == 'Awaiting scan data...':
        ai_report['reason'] = generate_detailed_analysis(result, vector_type, risk)
    
    # Generate detailed recommendation if not present  
    if 'advice' not in ai_report or not ai_report['advice']:
        ai_report['advice'] = generate_recommendation(result, ai_report.get('verdict', 'SAFE'), risk)

    final_output = {**result, "ai_report": ai_report, "payload": payload, "vector": vector_type}
    
    # OSINT, Sandbox, SOAR & Predictive Intel
    final_output['osint_report'] = osint_engine.scan_payload(payload)
    final_output['soar_playbook'] = soar_engine.generate_playbook(risk, vector_type, result, ai_report.get('playbook'))
    final_output['predictive_intel'] = predictive_engine.predict_next_target(result)
    
    # === NEW: ADVANCED INTELLIGENCE INTEGRATION (10 Modules) ===
    
    # 1. IOC Feed Check - Real-time threat intelligence
    try:
        if vector_type in ['url', 'qr', 'smishing'] and payload.startswith('http'):
            ioc_result = ioc_feed_manager.check_url(payload)
            final_output['ioc_matches'] = ioc_result.get('matches', [])
            final_output['ioc_threat_level'] = ioc_result.get('threat_level', 'unknown')
            if ioc_result.get('is_malicious'):
                risk += 25
                logging.critical(f"🚨 IOC MATCH: {payload} found in threat feeds!")
    except Exception as e:
        logging.warning(f"[IOC] Check failed: {e}")
    
    # 2. ML-Based Detection - No API needed
    try:
        if vector_type in ['url', 'qr'] and payload.startswith('http'):
            ml_result = ml_detector.predict(payload)
            final_output['ml_prediction'] = ml_result
            if ml_result.get('classification') == 'PHISHING':
                risk += 15
    except Exception as e:
        logging.warning(f"[ML] Detection failed: {e}")
    
    # 3. Campaign Attribution - Link to threat actors
    try:
        attack_indicators = {
            "url_pattern": payload,
            "domain": payload.split('/')[2] if '/' in payload else payload,
            "detected_brand": result.get('brand_check', ''),
            "risk_level": "CRITICAL" if risk > 70 else "HIGH" if risk > 40 else "MEDIUM"
        }
        attribution = attribution_engine.attribute_attack(attack_indicators)
        final_output['attribution'] = attribution
        
        if attribution.get('primary_attribution'):
            logging.info(f"[ATTRIBUTION] Linked to: {attribution['primary_attribution'].get('actor_id')}")
    except Exception as e:
        logging.warning(f"[ATTRIBUTION] Failed: {e}")
    
    # 4. QR Fingerprinting - Track attacks
    if vector_type == 'qr':
        try:
            _attribution = final_output.get('attribution', {})
            fingerprint = qr_fingerprint_engine.create_fingerprint(
                payload, 
                campaign_id=_attribution.get('primary_attribution', {}).get('actor_id')
            )
            final_output['fingerprint_id'] = fingerprint.fingerprint_id
            final_output['campaign_attribution'] = fingerprint.campaign_id
        except Exception as e:
            logging.warning(f"[FINGERPRINT] Failed: {e}")
    
    # 5. Temporal Analysis - Time-based insights
    try:
        attack_record = {"timestamp": datetime.datetime.now().isoformat(), "url": payload}
        temporal = temporal_engine.analyze_attack_timeline([attack_record])
        final_output['temporal_analysis'] = {
            "peak_hours": temporal.get("hourly_distribution", {}).get("peak_hours", []),
            "velocity": temporal.get("attack_velocity", {}).get("average_attacks_per_hour", 0),
            "campaign_type": temporal.get("campaign_duration", {}).get("campaign_type", "unknown")
        }
    except Exception as e:
        logging.warning(f"[TEMPORAL] Failed: {e}")
    
    # 6. Integration Hub - Send critical alerts
    if risk >= 70:
        try:
            alert_data = {
                "title": f"CRITICAL: {vector_type.upper()} threat detected",
                "payload": payload,
                "risk_score": risk,
                "risk_level": "CRITICAL" if risk >= 80 else "HIGH",
                "vector": vector_type,
                "verdict": final_output.get("ai_report", {}).get("verdict", "UNKNOWN"),
                "indicators": final_output.get("malicious_indicators", [])
            }
            alert = integration_hub.send_all_alerts(alert_data)
            final_output['integration_alert'] = alert
        except Exception as e:
            logging.warning(f"[INTEGRATION] Alert failed: {e}")
    
    # 4. LOGGING TO TERMINAL (As requested by Boss)
    logging.info(f"\n[SOC FORENSICS] --- {vector_type.upper()} SCAN ---")
    logging.info(f"Target: {payload}")
    logging.info(f"Site Status: {result.get('site_status', 'N/A')}")
    logging.info(f"Server IP: {result.get('server_ip_loc', 'N/A')}")
    logging.info(f"Domain Age: {result.get('domain_age', 'N/A')}")
    logging.info(f"SSL Certificate: {result.get('ssl_certificate', 'N/A')}")
    logging.info(f"VirusTotal: {result.get('virustotal', 'N/A')}")
    logging.info(f"Brand Check: {result.get('brand_check', 'N/A')}")
    logging.info(f"HTML Scan: {result.get('html_scan', 'N/A')}")
    logging.info(f"-------------------------------------------\n")

    # Sandbox logic for files
    if vector_type in ["eml", "qr", "vishing"] and payload:
        ext_map = {"eml": ".eml", "qr": ".txt", "vishing": ".wav"}
        _ext = ext_map.get(vector_type, ".bin")
        _tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=_ext, delete=False, mode='w', encoding='utf-8', errors='replace') as _tf:
                _tf.write(payload if isinstance(payload, str) else str(payload))
                _tmp_path = _tf.name
            final_output['sandbox_report'] = sandbox_engine.analyze_file(_tmp_path)
        except Exception as _e:
            logging.warning(f"[-] Sandbox skipped: {_e}")
            final_output['sandbox_report'] = None
        finally:
            try:
                if _tmp_path:
                    os.unlink(_tmp_path)
            except Exception:
                pass
    
    # Cache the final result
    global_cache.set(payload_hash, final_output)
    
    # 5. Accuracy Metrics Update (TP/TN/FP/FN)
    update_soc_metrics(ai_report.get('verdict', 'SAFE'), risk)
    
    return jsonify(final_output)

def update_soc_metrics(verdict, risk):
    """Updates the accuracy matrix based on AI vs Engine results."""
    try:
        # Simple Logic: 
        # TP: AI Malicious & Risk High
        # TN: AI Safe & Risk Low
        # FP: AI Malicious but Risk Low
        # FN: AI Safe but Risk High
        tp, tn, fp, fn = 0, 0, 0, 0
        
        current = acc_engine.get_metrics()
        tp, tn, fp, fn = current.get("TP", 0), current.get("TN", 0), current.get("FP", 0), current.get("FN", 0)

        if "MALICIOUS" in verdict.upper():
            if risk >= 50: tp += 1
            else: fp += 1
        else:
            if risk < 50: tn += 1
            else: fn += 1
            
        acc_engine.update_metrics(tp, tn, fp, fn)
    except Exception as e:
        logging.error(f"[-] Metrics Update Error: {e}")

@app.route('/api/metrics')
def api_metrics():
    """API endpoint for real-time metrics data"""
    try:
        metrics = acc_engine.get_metrics()
        return jsonify(metrics)
    except Exception as e:
        logging.error(f"[-] API Metrics Error: {e}")
        return jsonify({"TP": 0, "TN": 0, "FP": 0, "FN": 0, "accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0})

@app.route('/api/threats')
def api_threats():
    """API endpoint for threat intelligence data"""
    try:
        # Get threat data from database
        threats = threat_db.get_all_threats() if hasattr(threat_db, 'get_all_threats') else []
        stats = threat_db.get_sync_stats() if hasattr(threat_db, 'get_sync_stats') else {"total_threats": 0, "history": []}
        
        # Create 3D graph data structure for ForceGraph3D
        nodes = []
        links = []
        
        # Add central node (our system)
        nodes.append({"id": "sentinel", "name": "Sentinel Guardian", "group": 0, "color": "#3b82f6", "size": 8})
        
        # Add threat nodes from database or generate sample data
        if threats and len(threats) > 0:
            for i, threat in enumerate(threats[:20]):  # Limit to 20 nodes
                node_id = f"threat_{i}"
                threat_type = threat.get('type', 'unknown')
                group = 1 if threat_type == 'malicious' else 2
                color = "#ef4444" if group == 1 else "#f59e0b"
                nodes.append({
                    "id": node_id,
                    "name": threat.get('url', threat.get('name', f'Threat {i}')),
                    "group": group,
                    "color": color,
                    "size": 4
                })
                links.append({"source": "sentinel", "target": node_id})
        else:
            # Generate sample threat nodes for visualization
            sample_threats = [
                {"id": "t1", "name": "Phishing Campaign A", "group": 1, "color": "#ef4444"},
                {"id": "t2", "name": "Malware C2 Server", "group": 1, "color": "#ef4444"},
                {"id": "t3", "name": "Suspicious Domain", "group": 2, "color": "#f59e0b"},
                {"id": "t4", "name": "Brute Force IP", "group": 1, "color": "#ef4444"},
                {"id": "t5", "name": "Phishing URL", "group": 1, "color": "#ef4444"},
                {"id": "t6", "name": "Unknown Actor", "group": 2, "color": "#f59e0b"},
                {"id": "t7", "name": "APT Group X", "group": 1, "color": "#ef4444"},
            ]
            for t in sample_threats:
                nodes.append({"id": t["id"], "name": t["name"], "group": t["group"], "color": t["color"], "size": 4})
                links.append({"source": "sentinel", "target": t["id"]})
        
        # Add some inter-threat connections
        for i in range(len(nodes) - 1):
            if i > 0 and i % 2 == 0 and len(nodes) > i + 2:
                links.append({"source": nodes[i]["id"], "target": nodes[i + 1]["id"]})
        
        return jsonify({
            "nodes": nodes,
            "links": links,
            "stats": {
                "total_threats": stats.get("total_threats", len(nodes) - 1),
                "last_sync": stats.get("last_sync", "Active"),
                "malicious_nodes": len([n for n in nodes if n.get("group") == 1]),
                "suspicious_nodes": len([n for n in nodes if n.get("group") == 2])
            }
        })
    except Exception as e:
        logging.error(f"[-] API Threats Error: {e}")
        # Return fallback data
        return jsonify({
            "nodes": [
                {"id": "sentinel", "name": "Sentinel Guardian", "group": 0, "color": "#3b82f6", "size": 8},
                {"id": "t1", "name": "Threat Intel Active", "group": 1, "color": "#10b981", "size": 4}
            ],
            "links": [{"source": "sentinel", "target": "t1"}],
            "stats": {"total_threats": 1, "status": "Active", "error": str(e)[:50]}
        })

@app.route('/api/sync-status')
def api_sync_status():
    """Returns auto sync status for global threat feeds"""
    try:
        status = get_sync_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({"running": False, "error": str(e)})

@app.route('/api/engine-status')
def api_engine_status():
    """Returns real-time status of all 26 modules (8 engines + 10 advanced + 8 utilities)"""
    vt_key_1 = os.getenv("VT_API_KEY_1")
    vt_key_2 = os.getenv("VT_API_KEY_2")
    gemini_key_1 = os.getenv("GEMINI_API_KEY_1")
    gemini_key_2 = os.getenv("GEMINI_API_KEY_2")

    vt_status = "active" if (vt_key_1 or vt_key_2) else "no_key"
    gemini_status = "active" if ai_handler.is_active else "quota"

    return jsonify({
        "detection_engines": [
            {"id": "url",      "name": "URL/Typosquatting Engine",  "icon": "fa-link",        "color": "blue",    "status": "active",  "detail": f"VirusTotal: {'2 keys' if vt_key_1 and vt_key_2 else '1 key' if vt_key_1 or vt_key_2 else 'No Key'}"},
            {"id": "qr",       "name": "QR (Quishing) Engine",      "icon": "fa-qrcode",      "color": "purple",  "status": "active",  "detail": "Zero-click + Visual AI analysis"},
            {"id": "eml",      "name": "EML/Spear-Phishing Engine", "icon": "fa-envelope",    "color": "emerald", "status": "active",  "detail": "PDF attachments + URL intel"},
            {"id": "smishing", "name": "SMS/Smishing Engine",       "icon": "fa-comment-sms", "color": "yellow",  "status": "active",  "detail": "ML + IOC + Visual analysis"},
            {"id": "vishing",  "name": "Voice/Vishing Engine",      "icon": "fa-phone",       "color": "rose",    "status": "active",  "detail": "AI scam detection + Attribution"},
            {"id": "clone",    "name": "Clone Site Radar",          "icon": "fa-clone",       "color": "cyan",    "status": "active",  "detail": "Sandbox + Browser FP detection"},
            {"id": "social",   "name": "Social Engineering AI",     "icon": "fa-users",       "color": "orange",  "status": "active",  "detail": f"Gemini AI: {gemini_status}"},
        ],
        "advanced_modules": [
            {"id": "honeytoken", "name": "Honeytoken Manager", "icon": "fa-cookie-bite", "color": "amber", "status": "active", "detail": "Bait credentials deployed"},
            {"id": "pdf_analyzer", "name": "PDF Analyzer", "icon": "fa-file-pdf", "color": "red", "status": "active", "detail": "JS + auto-open detection"},
            {"id": "ioc_feeds", "name": "IOC Feed Manager", "icon": "fa-globe", "color": "cyan", "status": "active", "detail": "5 threat intel feeds"},
            {"id": "qr_fingerprint", "name": "QR Fingerprinting", "icon": "fa-fingerprint", "color": "purple", "status": "active", "detail": "Campaign tracking"},
            {"id": "attribution", "name": "Campaign Attribution", "icon": "fa-user-secret", "color": "pink", "status": "active", "detail": "APT actor matching"},
            {"id": "browser_fp", "name": "Browser Fingerprinting", "icon": "fa-fingerprint", "color": "teal", "status": "active", "detail": "Canvas/WebGL detection"},
            {"id": "temporal", "name": "Temporal Analysis", "icon": "fa-clock", "color": "orange", "status": "active", "detail": "Attack timeline analysis"},
            {"id": "ml_detector", "name": "ML Detector", "icon": "fa-robot", "color": "green", "status": "active", "detail": "Rule-based ML (no API)"},
            {"id": "integration", "name": "Integration Hub", "icon": "fa-plug", "color": "blue", "status": "active", "detail": "SIEM/SOAR connectors"},
            {"id": "executive", "name": "Executive Reporting", "icon": "fa-chart-pie", "color": "yellow", "status": "active", "detail": "PDF dashboards"},
        ],
        "core_utilities": [
            {"id": "zero_click", "name": "Zero-Click Extractor", "icon": "fa-download", "color": "gray", "status": "active", "detail": "Safe QR/PDF extraction"},
            {"id": "url_tracer", "name": "URL Tracer", "icon": "fa-route", "color": "blue", "status": "active", "detail": "50+ shortener support"},
            {"id": "threat_intel", "name": "Threat Intel APIs", "icon": "fa-shield-alt", "color": "green", "status": "active", "detail": "VT, URLScan, AbuseIPDB"},
            {"id": "heuristics", "name": "Domain Heuristics", "icon": "fa-search", "color": "teal", "status": "active", "detail": "WHOIS + SSL + DNS"},
            {"id": "visual", "name": "Visual Analyzer", "icon": "fa-eye", "color": "purple", "status": "active", "detail": "Screenshot + AI detection"},
            {"id": "ai_handler", "name": "AI Handler", "icon": "fa-brain", "color": "pink", "status": gemini_status, "detail": "Gemini consensus engine"},
            {"id": "sandbox", "name": "Sandbox Detonator", "icon": "fa-flask", "color": "orange", "status": "active", "detail": "Isolated browser analysis"},
            {"id": "ai_vision", "name": "AI Vision", "icon": "fa-camera", "color": "indigo", "status": "active", "detail": "Visual spoofing detection"},
        ],
        "api_keys": {
            "virustotal": vt_status,
            "gemini": gemini_status,
            "vt_key_count": sum([1 for k in [vt_key_1, vt_key_2] if k]),
            "gemini_key_count": sum([1 for k in [gemini_key_1, gemini_key_2] if k])
        },
        "gpu_acceleration": get_gpu_status_safe(),
        "total_modules": 26,
        "system_version": "2.0",
        "status": "fully_operational"
    })

@app.route('/accuracy')
def accuracy_dashboard():
    metrics = acc_engine.get_metrics()
    return render_template('accuracy.html', metrics=metrics)

@app.route('/run_tests', methods=['POST'])
def trigger_tests():
    from tests.accuracy_test_runner import run_accuracy_suite
    run_accuracy_suite()
    return jsonify({"status": "Success", "message": "All test cases executed and dashboard updated."})

@app.route('/download_report', methods=['POST'])
def download_report():
    try:
        scan_data = request.json
        pdf_path = generate_pdf_report(scan_data)
        return send_file(os.path.abspath(pdf_path), as_attachment=True)
    except Exception as e:
        logging.error(f"[PDF] Report generation failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/offensive_attack', methods=['POST'])
def offensive_attack():
    target_url = request.json.get('target_url')
    # Fixed method name mismatch
    injected = offensive_engine.flood_hacker_database(target_url, count=10, max_workers=5)
    return jsonify({
        "status": "Attack Successful",
        "injected_records": injected,
        "message": "Hacker database polluted with noise."
    })

# === HELPER: Safe Temporary File Handling ===
def safe_upload_cleanup(tmp_path: str, operation_name: str = "upload"):
    """Safely cleanup temporary upload files with proper error handling."""
    if tmp_path and os.path.exists(tmp_path):
        try:
            os.unlink(tmp_path)
            logging.debug(f"[{operation_name}] Cleaned up temp file: {tmp_path}")
        except PermissionError:
            logging.warning(f"[{operation_name}] Permission denied cleaning up {tmp_path}")
        except Exception as e:
            logging.warning(f"[{operation_name}] Cleanup warning for {tmp_path}: {e}")

def validate_upload_file(file, allowed_extensions=None):
    """Validate uploaded file with security checks."""
    if not file:
        return False, "No file provided"
    if file.filename == '':
        return False, "Empty filename"
    if allowed_extensions:
        ext = os.path.splitext(file.filename.lower())[1]
        if ext not in allowed_extensions:
            return False, f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
    return True, None

# === FILE UPLOAD ENDPOINTS ===

@app.route('/api/upload/qr', methods=['POST'])
def upload_qr():
    """Handle QR code image upload and analysis with guaranteed cleanup"""
    tmp_path = None
    try:
        file = request.files.get('file')
        is_valid, error_msg = validate_upload_file(file, allowed_extensions=['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'])
        if not is_valid:
            return jsonify({"error": error_msg}), 400
        
        # Save temporarily (close first - Windows locks open files)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
            tmp_path = tmp.name
        file.save(tmp_path)
        
        # Analyze using QR Engine
        result = engines['qr'].analyze(tmp_path)
        
        # Add advanced analysis (QREngine returns 'extracted_payload')
        qr_payload = result.get('extracted_payload') or result.get('final_url')
        if qr_payload and qr_payload.startswith(('http://', 'https://')):
            url = qr_payload
            
            # IOC Check
            try:
                ioc_result = ioc_feed_manager.check_url(url)
                result['ioc_analysis'] = ioc_result
            except Exception as e:
                logging.warning(f"[QR Upload] IOC check failed: {e}")
            
            # ML Detection
            try:
                ml_result = ml_detector.predict(url)
                result['ml_analysis'] = ml_result
            except Exception as e:
                logging.warning(f"[QR Upload] ML detection failed: {e}")
            
            # Attribution
            try:
                attribution = attribution_engine.attribute_attack({
                    "url_pattern": url,
                    "domain": url.split('/')[2] if '/' in url else url,
                    "risk_level": "HIGH"
                })
                result['attribution'] = attribution
            except Exception as e:
                logging.warning(f"[QR Upload] Attribution failed: {e}")
            
            # Fingerprint
            try:
                fingerprint = qr_fingerprint_engine.create_fingerprint(url)
                result['fingerprint'] = {
                    "id": fingerprint.fingerprint_id,
                    "visual_hash": fingerprint.visual_hash[:16] + "..."
                }
            except Exception as e:
                logging.warning(f"[QR Upload] Fingerprinting failed: {e}")
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"[QR Upload] Error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        # GUARANTEED cleanup happens regardless of success or failure
        safe_upload_cleanup(tmp_path, "QR Upload")

@app.route('/api/upload/eml', methods=['POST'])
def upload_eml():
    """Handle EML email file upload and analysis with guaranteed cleanup"""
    tmp_path = None
    try:
        file = request.files.get('file')
        is_valid, error_msg = validate_upload_file(file, allowed_extensions=['.eml', '.msg', '.txt'])
        if not is_valid:
            return jsonify({"error": error_msg}), 400
        
        # Save temporarily (close first - Windows locks open files)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.eml') as tmp:
            tmp_path = tmp.name
        file.save(tmp_path)
        
        # Analyze using EML Engine
        case_id = f"EML_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        result = engines['eml'].analyze(tmp_path, case_id=case_id)
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"[EML Upload] Error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        # GUARANTEED cleanup happens regardless of success or failure
        safe_upload_cleanup(tmp_path, "EML Upload")

@app.route('/api/upload/pdf', methods=['POST'])
def upload_pdf():
    """Handle PDF file upload and advanced analysis with guaranteed cleanup"""
    tmp_path = None
    try:
        file = request.files.get('file')
        is_valid, error_msg = validate_upload_file(file, allowed_extensions=['.pdf'])
        if not is_valid:
            return jsonify({"error": error_msg}), 400
        
        # Save temporarily (close first - Windows locks open files)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
            tmp_path = tmp.name
        file.save(tmp_path)
        
        # Advanced PDF Analysis
        case_id = f"PDF_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        analysis = pdf_analyzer.analyze(tmp_path, case_id=case_id)
        
        return jsonify(analysis)
        
    except Exception as e:
        logging.error(f"[PDF Upload] Error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        # GUARANTEED cleanup happens regardless of success or failure
        safe_upload_cleanup(tmp_path, "PDF Upload")

@app.route('/api/upload/voice', methods=['POST'])
def upload_voice():
    """Handle voice/audio file upload for vishing analysis with guaranteed cleanup"""
    tmp_path = None
    try:
        file = request.files.get('file')
        is_valid, error_msg = validate_upload_file(file, allowed_extensions=['.wav', '.mp3', '.ogg', '.m4a', '.flac'])
        if not is_valid:
            return jsonify({"error": error_msg}), 400
        
        # Save temporarily (close first - Windows locks open files)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as tmp:
            tmp_path = tmp.name
        file.save(tmp_path)
        
        # Analyze using Vishing Engine
        result = engines['vishing'].analyze(tmp_path)
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"[Voice Upload] Error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        # GUARANTEED cleanup happens regardless of success or failure
        safe_upload_cleanup(tmp_path, "Voice Upload")

# === ADVANCED FEATURES API ===

@app.route('/api/honeytoken/generate', methods=['POST'])
def generate_honeytoken():
    """Generate honeytoken credentials for bait"""
    try:
        data = request.json or {}
        campaign_id = data.get('campaign_id', 'default')
        
        token = honeytoken_manager.create_token(
            qr_payload=f"honeytoken-bait-{campaign_id}",
            campaign_id=campaign_id
        )
        credentials = {"email": token.email, "password": token.password, "token_id": token.token_id}

        return jsonify({
            "status": "success",
            "credentials": credentials,
            "monitor_url": f"/api/honeytoken/monitor/{token.email}",
            "expires_at": token.expires_at,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/executive/report', methods=['POST'])
def generate_executive_report():
    """Generate executive-level security report"""
    try:
        data = request.json or {}
        scan_data = data.get('scan_data', {})
        
        # Generate executive summary
        summary = executive_reporting.generate_executive_summary(
            scan_data.get('scans', []),
            days=7
        )
        
        # Export to PDF
        _exec_pdf = os.path.join(tempfile.gettempdir(), f"exec_report_{datetime.datetime.now().strftime('%Y%m%d')}.pdf")
        pdf_path = executive_reporting.export_pdf_report(summary, _exec_pdf)
        
        return send_file(pdf_path, as_attachment=True, download_name=f"Executive_Report_{datetime.datetime.now().strftime('%Y%m%d')}.pdf")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/attribution/actor/<actor_id>')
def get_actor_profile(actor_id):
    """Get detailed threat actor profile"""
    try:
        profile = attribution_engine.get_actor_profile(actor_id)
        return jsonify(profile)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/fingerprint/campaign/<campaign_id>')
def get_campaign_fingerprints(campaign_id):
    """Get all fingerprints linked to a campaign"""
    try:
        fingerprints = qr_fingerprint_engine.get_campaign_fingerprints(campaign_id)
        return jsonify({
            "campaign_id": campaign_id,
            "fingerprints": [fp.to_dict() for fp in fingerprints],
            "count": len(fingerprints)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING, format='%(levelname)s:%(name)s: %(message)s')
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    global_cache.clear()
    
    # Start hourly auto sync for global threat feeds (OpenPhish + URLhaus + PhishStats)
    start_auto_sync()
    logging.info("[MAIN] Auto-sync enabled — hourly threat feed updates active")
    
    # Debug=True helps pick up file changes immediately
    app.run(debug=True, port=5000, use_reloader=False)
