from pathlib import Path

from flask import Flask, flash
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from config import Config

db = SQLAlchemy()
mail = Mail()

def _ensure_vault_key(app):
    """Ensure a valid Fernet key exists for local development.

    If the .env value is missing or malformed and there are no encrypted vault
    records yet, generate a fresh key and persist it to .env automatically.
    If encrypted records already exist, never replace the key because that would
    make those records undecryptable.
    """
    key = (app.config.get("VAULT_ENCRYPTION_KEY") or "").strip().strip("\"").strip("'")
    try:
        if key:
            Fernet(key.encode("utf-8"))
            app.config["VAULT_ENCRYPTION_KEY"] = key
            return
    except Exception:
        pass

    from .models import VaultItem
    if VaultItem.query.count() > 0:
        raise RuntimeError(
            "VAULT_ENCRYPTION_KEY is invalid, but the database already contains encrypted vault records. "
            "Restore the original Fernet key in .env; do not generate a new one."
        )

    new_key = Fernet.generate_key().decode("ascii")
    app.config["VAULT_ENCRYPTION_KEY"] = new_key
    env_path = Path(app.root_path).parent / ".env"
    lines = []
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()
    found = False
    output = []
    for line in lines:
        if line.strip().startswith("VAULT_ENCRYPTION_KEY="):
            output.append(f"VAULT_ENCRYPTION_KEY={new_key}")
            found = True
        else:
            output.append(line)
    if not found:
        if output and output[-1].strip():
            output.append("")
        output.append(f"VAULT_ENCRYPTION_KEY={new_key}")
    env_path.write_text("\n".join(output) + "\n", encoding="utf-8")
    app.logger.warning("A valid vault encryption key was generated and saved to .env.")

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    mail.init_app(app)

    from .routes import bp
    app.register_blueprint(bp)

    with app.app_context():
        db.create_all()
        _ensure_vault_key(app)

    return app
