import base64
import json
import secrets
from datetime import datetime, timedelta
from functools import wraps

from cryptography.fernet import Fernet
from flask import current_app, session, redirect, url_for, flash
from werkzeug.security import check_password_hash, generate_password_hash

def vault_fernet():
    key = current_app.config["VAULT_ENCRYPTION_KEY"]
    if not key:
        raise RuntimeError("VAULT_ENCRYPTION_KEY is not configured.")
    return Fernet(key.encode() if isinstance(key, str) else key)

def encrypt_text(value: str) -> bytes:
    return vault_fernet().encrypt(value.encode("utf-8"))

def decrypt_text(value: bytes) -> str:
    return vault_fernet().decrypt(value).decode("utf-8")

def make_otp():
    return f"{secrets.randbelow(1_000_000):06d}"

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("main.login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id") or not session.get("is_admin"):
            flash("Administrator access required.", "error")
            return redirect(url_for("main.login"))
        return view(*args, **kwargs)
    return wrapped

def fresh_master_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("master_verified_until", 0) < datetime.utcnow().timestamp():
            flash("Enter your vault master password first.", "error")
            return redirect(url_for("main.unlock"))
        return view(*args, **kwargs)
    return wrapped

def fresh_biometric_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("biometric_verified_until", 0) < datetime.utcnow().timestamp():
            flash("Complete the biometric/passkey verification first.", "error")
            return redirect(url_for("main.biometric"))
        return view(*args, **kwargs)
    return wrapped

def strong_hash(value):
    return generate_password_hash(value)

def verify_hash(stored, value):
    return bool(stored) and check_password_hash(stored, value)

def mark_master_verified():
    session["master_verified_until"] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()

def mark_biometric_verified():
    session["biometric_verified_until"] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()

def clear_security_state():
    session.pop("master_verified_until", None)
    session.pop("biometric_verified_until", None)
