# Import necessary modules and classes

# app/config.py
import os
from secrets import token_hex

class Config:
    # MySQL Database settings
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://foo:foo123@localhost/loanmanagement'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # SQLAlchemy Database settings
    #SQLALCHEMY_DATABASE_URI = 'sqlite:///loanmanagement.db'
    #SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session settings
    SECRET_KEY = token_hex(16)

    # Security settings
    SESSION_COOKIE_SECURE = True
    BCRYPT_LOG_ROUNDS = 12


    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    ALLOWED_DOCS_EXTENSIONS = {'pdf', 'docx', 'csv', 'txt', 'xls', 'xlsx'}
    DOCS_FOLDER = 'app/client/static/uploads/docs'
    UPLOAD_FOLDER = 'app/client/static/uploads/profiles'
    TEMP_FOLDER = 'app/client/static/uploads/temp'

    # Server settings
    DEBUG = True
    PORT = 7070
    HOST = '0.0.0.0'

    @staticmethod
    def init_app(app):
        os.makedirs(Config.DOCS_FOLDER, exist_ok=True)
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(Config.TEMP_FOLDER, exist_ok=True)
