import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'xsqdaesq<wcfa'
    # ----------------------------- Data base config ----------------------------- #
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'mysql+pymysql://root:madjid123@localhost/VTBDD'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # ------------------------------ Mailing server ------------------------------ #
    MAIL_SERVER = 'smtp.example.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
