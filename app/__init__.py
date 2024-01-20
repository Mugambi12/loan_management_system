# Import necessary modules and classes

# app/__init__.py
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_apscheduler import APScheduler
import os

# Initialize Flask app and extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'login'
csrf = CSRFProtect()
schedule = APScheduler()

def create_app():
    app = Flask(__name__)

    # App configuration settings
    app.config['SECRET_KEY'] = 'qwertyurioupiuodsfghfdjgkjhd2345678jgfnxdz'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///loanmanagement.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    app.config['BCRYPT_LOG_ROUNDS'] = 12  # Number of hashing rounds
    app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
    app.config['ALLOWED_DOCS_EXTENSIONS'] = {'pdf', 'docx', 'csv', 'txt', 'xls', 'xlsx'}
    app.config['DOCS_FOLDER'] = 'app/static/uploads/docs'
    app.config['UPLOAD_FOLDER'] = 'app/static/uploads/profiles'
    app.config['TEMP_FOLDER'] = 'app/static/uploads/temp'
    os.makedirs(app.config['DOCS_FOLDER'], exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['TEMP_FOLDER'], exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Register blueprints and start scheduler
    from app.routes import routes
    app.register_blueprint(routes)

    schedule.init_app(app)
    schedule.start()

    # Create database tables and perform initial setup
    with app.app_context():
        from app.setup import add_admin_role, add_admin_user, verify_admin_user, add_loan_types, add_loan_durations
        db.create_all()
        add_admin_role()
        add_admin_user()
        verify_admin_user()
        add_loan_types()
        add_loan_durations()

    return app
