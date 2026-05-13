"""Dashboard Web Routes"""
from flask import Blueprint, render_template, jsonify
import datetime

bp = Blueprint('dashboard', __name__)


@bp.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html', v=datetime.datetime.now().timestamp())


@bp.route('/accuracy')
def accuracy():
    """Accuracy metrics page"""
    return render_template('accuracy.html')


@bp.route('/favicon.ico')
def favicon():
    return '', 204


@bp.route('/.well-known/appspecific/com.chrome.devtools.json')
def chrome_devtools():
    return jsonify({}), 200
