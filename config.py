import os
from dotenv import load_dotenv
# Determine the environment
env = os.getenv('FLASK_ENV', 'development')

# Load the appropriate .env file
if env == 'production':
    load_dotenv('.env.production')
else:
    load_dotenv('.env.development')
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'xsqdaesq<wcfa'
    # ----------------------------- Data base config ----------------------------- #
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # ------------------------------ Mailing server ------------------------------ #
    # MAIL_SERVER = 'smtp.example.com'
    # MAIL_PORT = 587
    # MAIL_USE_TLS = True
    # MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    # MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    # MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
