"""Phishing Detection Platform - Application Factory"""
import os
import logging
from pathlib import Path
from flask import Flask
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get project root
PROJECT_ROOT = Path(__file__).parent.parent


def create_app(config_name=None):
    """Application factory pattern"""
    app = Flask(__name__,
                template_folder=str(PROJECT_ROOT / 'frontend' / 'templates'),
                static_folder=str(PROJECT_ROOT / 'frontend' / 'static'))
    
    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['DEBUG'] = os.getenv('DEBUG', 'False').lower() == 'true'
    app.config['PROJECT_ROOT'] = PROJECT_ROOT
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize extensions storage
    app.extensions = {}
    
    # Register blueprints
    from app.api.v1 import detection, analysis, health
    app.register_blueprint(detection.bp, url_prefix='/api/v1')
    app.register_blueprint(analysis.bp, url_prefix='/api/v1')
    app.register_blueprint(health.bp, url_prefix='/api/v1')
    
    from app.web import dashboard
    app.register_blueprint(dashboard.bp)
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return {"error": "Not found"}, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return {"error": "Internal server error"}, 500
    
    return app
