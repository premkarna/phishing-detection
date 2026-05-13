"""Detection API Routes"""
from flask import Blueprint, request, jsonify
import logging

bp = Blueprint('detection', __name__)
logger = logging.getLogger(__name__)


@bp.route('/detect/url', methods=['POST'])
def detect_url():
    """Detect phishing in URL"""
    data = request.get_json() or {}
    url = data.get('url') or data.get('payload')
    
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    try:
        from app.core.url_engine import URLEngine
        engine = URLEngine()
        result = engine.analyze(url)
        return jsonify({
            "verdict": result.get('verdict', 'UNKNOWN'),
            "risk_score": result.get('calculated_risk', 0),
            "details": result
        })
    except Exception as e:
        logger.error(f"URL detection error: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route('/detect/qr', methods=['POST'])
def detect_qr():
    """Detect phishing in QR code"""
    data = request.get_json() or {}
    qr_data = data.get('qr') or data.get('payload')
    
    if not qr_data:
        return jsonify({"error": "QR data required"}), 400
    
    try:
        from app.core.quishing_engine import QREngine
        engine = QREngine()
        result = engine.analyze(qr_data)
        return jsonify({
            "verdict": result.get('verdict', 'UNKNOWN'),
            "risk_score": result.get('calculated_risk', 0),
            "details": result
        })
    except Exception as e:
        logger.error(f"QR detection error: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route('/detect/email', methods=['POST'])
def detect_email():
    """Detect phishing in email"""
    data = request.get_json() or {}
    email_content = data.get('email') or data.get('payload')
    
    if not email_content:
        return jsonify({"error": "Email content required"}), 400
    
    try:
        from app.core.eml_engine import EMLEngine
        engine = EMLEngine()
        result = engine.analyze(email_content)
        return jsonify({
            "verdict": result.get('verdict', 'UNKNOWN'),
            "risk_score": result.get('calculated_risk', 0),
            "details": result
        })
    except Exception as e:
        logger.error(f"Email detection error: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route('/analyze', methods=['POST'])
def analyze():
    """Generic analysis endpoint"""
    data = request.get_json() or {}
    payload = data.get('payload')
    vector_type = data.get('vector', 'url').lower()
    
    if not payload:
        return jsonify({"error": "Payload required"}), 400
    
    try:
        if vector_type in ['url']:
            from app.core.url_engine import URLEngine as Engine
        elif vector_type in ['qr']:
            from app.core.quishing_engine import QREngine as Engine
        elif vector_type in ['email', 'eml']:
            from app.core.eml_engine import EMLEngine as Engine
        elif vector_type in ['sms', 'smishing']:
            from app.core.smishing_engine import SmishingEngine as Engine
        elif vector_type in ['voice', 'vishing']:
            from app.core.vishing_engine import VishingEngine as Engine
        elif vector_type == 'clone':
            from app.core.clone_engine import CloneEngine as Engine
        elif vector_type == 'social':
            from app.core.socialengineering_engine import SocialEngine as Engine
        else:
            from app.core.url_engine import URLEngine as Engine
        
        engine = Engine()
        result = engine.analyze(payload)
        
        return jsonify({
            "verdict": result.get('verdict', 'UNKNOWN'),
            "risk_score": result.get('calculated_risk', 0),
            "vector": vector_type,
            "details": result
        })
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({"error": str(e)}), 500
