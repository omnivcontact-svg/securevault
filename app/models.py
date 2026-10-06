from datetime import datetime
from . import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    email = db.Column(db.String(320), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=True)
    master_password_hash = db.Column(db.String(255), nullable=True)

    security_q1 = db.Column(db.String(255), nullable=True)
    security_q2 = db.Column(db.String(255), nullable=True)
    security_q3 = db.Column(db.String(255), nullable=True)
    security_a1_hash = db.Column(db.String(255), nullable=True)
    security_a2_hash = db.Column(db.String(255), nullable=True)
    security_a3_hash = db.Column(db.String(255), nullable=True)

    profile_image = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_suspended = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    vault_items = db.relationship("VaultItem", backref="owner", lazy=True, cascade="all, delete-orphan")
    webauthn_credentials = db.relationship("WebAuthnCredential", backref="owner", lazy=True, cascade="all, delete-orphan")

class VaultItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(180), nullable=False)
    encrypted_username = db.Column(db.LargeBinary, nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
    encrypted_notes = db.Column(db.LargeBinary, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class WebAuthnCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    credential_id = db.Column(db.LargeBinary, unique=True, nullable=False)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class OtpToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    code_hash = db.Column(db.String(255), nullable=False)
    purpose = db.Column(db.String(40), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)
    used = db.Column(db.Boolean, default=False)
