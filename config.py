import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///vault.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    VAULT_ENCRYPTION_KEY = os.getenv("VAULT_ENCRYPTION_KEY", "")

    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "")

    WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "SecureVault")
    WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
    WEBAUTHN_ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:5000")
