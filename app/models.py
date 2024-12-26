from . import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(64), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(128), unique=True, nullable=False)
    titre = db.Column(db.String(256), nullable=True)
    description = db.Column(db.Text, nullable=False)
    date_published = db.Column(db.DateTime, nullable=True)
    last_modified = db.Column(db.DateTime, nullable=True)
    type = db.Column(db.String(128), nullable=True)
    platform = db.Column(db.String(128), nullable=True)
    author = db.Column(db.String(128), nullable=True)
    severity = db.Column(db.String(64), nullable=True)
    references = db.Column(db.Text, nullable=True)
    cvss = db.Column(db.String(64), nullable=True)
    created = db.Column(db.DateTime, nullable=True)
    added = db.Column(db.DateTime, nullable=True)
    solutions = db.Column(db.Text, nullable=True)
    verified = db.Column(db.Boolean, default=False)
    application_path = db.Column(db.String(256), nullable=True)
    application_md5 = db.Column(db.String(256), nullable=True)
    base_score = db.Column(db.Float, nullable=True)
    attack_vector = db.Column(db.String(64), nullable=True)
    attack_complexity = db.Column(db.String(64), nullable=True)
    privileges_required = db.Column(db.String(64), nullable=True)
    user_interaction = db.Column(db.String(64), nullable=True)
    scope = db.Column(db.String(64), nullable=True)
    exploitability_score = db.Column(db.Float, nullable=True)
    impact_score = db.Column(db.Float, nullable=True)
    confidentiality_impact = db.Column(db.String(64), nullable=True)
    integrity_impact = db.Column(db.String(64), nullable=True)
    availability_impact = db.Column(db.String(64), nullable=True)
    affected_software = db.Column(db.Text, nullable=True)
    tags = db.Column(db.String(256), nullable=True)
    screenshot_path = db.Column(db.String(256), nullable=True)
    screenshot_thumb_path = db.Column(db.String(256), nullable=True)
    status = db.Column(db.String(64), default='brut')

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    cve_types = db.Column(db.String(256), nullable=False)
