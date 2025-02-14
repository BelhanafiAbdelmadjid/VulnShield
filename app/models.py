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
    tags = db.Column(db.String(1024), nullable=True)
    # screenshot_path = db.Column(db.String(256), nullable=True)
    # screenshot_thumb_path = db.Column(db.String(256), nullable=True)
    status = db.Column(db.String(64), default='brut')

    def to_dict(self):
        return {
            "id" : self.id,
            "CVE_ID": self.cve_id,
            "Titre": self.titre,
            "Description": self.description,
            "Date_Published": self.date_published.isoformat() if self.date_published else None,
            "Last_Modified": self.last_modified.isoformat() if self.last_modified else None,
            "Type": self.type,
            "Platform": self.platform,
            "Author": self.author,
            "Severity": self.severity,
            "References": self.references,
            "CVSS": self.cvss,
            "Created": self.created.isoformat() if self.created else None,
            "Added": self.added.isoformat() if self.added else None,
            "Solutions": self.solutions,
            "verified": self.verified,
            "application_path": self.application_path,
            "application_md5": self.application_md5,
            "Base_Score": self.base_score,
            "Attack_Vector": self.attack_vector,
            "Attack_Complexity": self.attack_complexity,
            "Privileges_Required": self.privileges_required,
            "User_Interaction": self.user_interaction,
            "Scope": self.scope,
            "Exploitability_Score": self.exploitability_score,
            "Impact_Score": self.impact_score,
            "Confidentiality_Impact": self.confidentiality_impact,
            "Integrity_Impact": self.integrity_impact,
            "Availability_Impact": self.availability_impact,
            "Affected_Software": self.affected_software,
            "tags": self.tags,
            "status": self.status
        }


class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    cve_types = db.Column(db.String(256), nullable=False)
    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "cve_types": self.cve_types,
        }