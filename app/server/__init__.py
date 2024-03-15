# Import necessary modules and classes

# app/__init__.py
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_apscheduler import APScheduler
from app.server.config import Config

# Initialize Flask app and extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'routes.login'
csrf = CSRFProtect()
schedule = APScheduler()

def create_app():
    app = Flask(__name__, template_folder='../client/templates', static_folder='../client/static')
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Register blueprints and start scheduler
    from app.server.routes import routes
    app.register_blueprint(routes)

    schedule.init_app(app)
    schedule.start()

    # Create database tables and perform initial setup
    with app.app_context():
        from app.server.system_setup.setup import add_admin_role, add_admin_user, verify_admin_user, add_loan_types, add_loan_durations
        db.create_all()
        add_admin_role()
        add_admin_user()
        verify_admin_user()
        add_loan_types()
        add_loan_durations()

    return app
