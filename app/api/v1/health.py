"""Health Check API"""
from flask import Blueprint, jsonify
import datetime

bp = Blueprint('health', __name__)


@bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.datetime.now().isoformat(),
        "version": "1.0.0"
    })


@bp.route('/status', methods=['GET'])
def system_status():
    """Detailed system status"""
    return jsonify({
        "status": "operational",
        "engines": ["url", "qr", "email", "sms", "voice", "clone", "social"],
        "timestamp": datetime.datetime.now().isoformat()
    })
