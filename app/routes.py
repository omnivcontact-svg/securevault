import base64
import secrets
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import or_
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_mail import Message
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from email_validator import validate_email, EmailNotValidError

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)

from . import db, mail
from .models import User, VaultItem, OtpToken, WebAuthnCredential
from .security import (
    encrypt_text, decrypt_text, make_otp, login_required, admin_required,
    fresh_master_required, fresh_biometric_required, mark_master_verified,
    mark_biometric_verified, verify_hash, clear_security_state,
)

bp = Blueprint("main", __name__)


def current_user():
    uid = session.get("user_id")
    return User.query.get(uid) if uid else None


def webauthn_settings():
    """Return the configured local WebAuthn RP settings.

    SecureVault deliberately uses one canonical local origin during development:
    http://localhost:5000. Mixing localhost and 127.0.0.1 can invalidate passkeys.
    """
    return (
        current_app.config["WEBAUTHN_RP_ID"],
        current_app.config["WEBAUTHN_ORIGIN"],
    )


def send_otp(user, purpose):
    code = make_otp()
    token = OtpToken(
        user_id=user.id,
        code_hash=generate_password_hash(code),
        purpose=purpose,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db.session.add(token)
    db.session.commit()

    username = current_app.config["MAIL_USERNAME"]
    password = current_app.config["MAIL_PASSWORD"]
    sender = current_app.config["MAIL_DEFAULT_SENDER"] or username

    if not username or not password or not sender:
        current_app.logger.warning("SMTP not configured. Development OTP for %s: %s", user.email, code)
        return code

    try:
        msg = Message(
            subject="SecureVault verification code",
            recipients=[user.email],
            sender=sender,
            body=f"Your SecureVault verification code is {code}. It expires in 10 minutes.",
        )
        mail.send(msg)
        return None
    except Exception:
        current_app.logger.exception("Unable to send OTP email")
        return code


@bp.context_processor
def inject_user():
    return {"current_user": current_user()}


@bp.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("main.dashboard"))
    return render_template("index.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        master = request.form.get("master_password", "")
        q1, q2, q3 = [request.form.get(k, "").strip() for k in ("q1", "q2", "q3")]
        a1, a2, a3 = [request.form.get(k, "") for k in ("a1", "a2", "a3")]

        if not name:
            flash("Enter your name.", "error")
            return render_template("register.html")
        try:
            validate_email(email)
        except EmailNotValidError as e:
            flash(str(e), "error")
            return render_template("register.html")

        if len(password) < 12 or len(master) < 12:
            flash("Login and vault master passwords must each be at least 12 characters.", "error")
            return render_template("register.html")
        if password == master:
            flash("Use a different vault master password from the login password.", "error")
            return render_template("register.html")
        if len({q1.lower(), q2.lower(), q3.lower()}) < 3 or not all([q1, q2, q3]):
            flash("Choose three different security questions.", "error")
            return render_template("register.html")
        if not all([a1.strip(), a2.strip(), a3.strip()]):
            flash("Answer all three security questions.", "error")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
            return render_template("register.html")

        user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            master_password_hash=generate_password_hash(master),
            security_q1=q1, security_q2=q2, security_q3=q3,
            security_a1_hash=generate_password_hash(a1.strip().lower()),
            security_a2_hash=generate_password_hash(a2.strip().lower()),
            security_a3_hash=generate_password_hash(a3.strip().lower()),
            is_verified=True,
        )
        db.session.add(user)
        db.session.commit()
        flash("Account created. Sign in, then register your device passkey from Profile.", "success")
        return redirect(url_for("main.login"))

    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
            flash("Invalid email or password.", "error")
            return render_template("login.html")
        if user.is_suspended:
            flash("This account is suspended. Contact support.", "error")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user.id
        session["is_admin"] = bool(user.is_admin)
        return redirect(url_for("main.dashboard"))

    return render_template("login.html")


@bp.route("/logout")
def logout():
    clear_security_state()
    session.clear()
    return redirect(url_for("main.index"))


@bp.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    items = VaultItem.query.filter_by(user_id=user.id).order_by(VaultItem.updated_at.desc()).all()
    has_passkey = bool(user.webauthn_credentials)
    return render_template("dashboard.html", items=items, has_passkey=has_passkey)


@bp.route("/unlock", methods=["GET", "POST"])
@login_required
def unlock():
    user = current_user()
    if request.method == "POST":
        master = request.form.get("master_password", "")
        if verify_hash(user.master_password_hash, master):
            mark_master_verified()
            return redirect(url_for("main.biometric"))
        flash("Incorrect vault master password.", "error")
    return render_template("unlock.html")


@bp.route("/biometric")
@login_required
def biometric():
    user = current_user()
    registered = bool(user.webauthn_credentials)
    return render_template("biometric.html", registered=registered)


@bp.route("/vault")
@login_required
@fresh_master_required
@fresh_biometric_required
def vault():
    user = current_user()
    items = VaultItem.query.filter_by(user_id=user.id).order_by(VaultItem.updated_at.desc()).all()
    return render_template("vault.html", items=items, decrypt_text=decrypt_text)


@bp.route("/vault/add", methods=["POST"])
@login_required
@fresh_master_required
@fresh_biometric_required
def vault_add():
    user = current_user()
    title = request.form.get("title", "").strip()
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    notes = request.form.get("notes", "")

    if not title or not password:
        flash("Title and password are required.", "error")
        return redirect(url_for("main.vault"))

    item = VaultItem(
        owner=user,
        title=title,
        encrypted_username=encrypt_text(username),
        encrypted_password=encrypt_text(password),
        encrypted_notes=encrypt_text(notes) if notes else None,
    )
    db.session.add(item)
    db.session.commit()
    flash("Vault entry saved.", "success")
    return redirect(url_for("main.vault"))


@bp.route("/vault/edit/<int:item_id>", methods=["POST"])
@login_required
@fresh_master_required
@fresh_biometric_required
def vault_edit(item_id):
    item = VaultItem.query.filter_by(id=item_id, user_id=session["user_id"]).first_or_404()
    title = request.form.get("title", "").strip()
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    notes = request.form.get("notes", "")
    if not title or not password:
        flash("Title and password are required.", "error")
        return redirect(url_for("main.vault"))
    item.title = title
    item.encrypted_username = encrypt_text(username)
    item.encrypted_password = encrypt_text(password)
    item.encrypted_notes = encrypt_text(notes) if notes else None
    db.session.commit()
    flash("Vault entry updated.", "success")
    return redirect(url_for("main.vault"))


@bp.route("/vault/delete/<int:item_id>", methods=["POST"])
@login_required
@fresh_master_required
@fresh_biometric_required
def vault_delete(item_id):
    item = VaultItem.query.filter_by(id=item_id, user_id=session["user_id"]).first_or_404()
    db.session.delete(item)
    db.session.commit()
    flash("Vault entry permanently deleted.", "success")
    return redirect(url_for("main.vault"))


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        user.name = request.form.get("name", user.name).strip()
        upload = request.files.get("profile_image")
        if upload and upload.filename:
            ext = Path(secure_filename(upload.filename)).suffix.lower()
            if ext not in {".png", ".jpg", ".jpeg", ".webp"}:
                flash("Use PNG, JPG, JPEG, or WebP.", "error")
                return redirect(url_for("main.profile"))
            upload_dir = Path(current_app.root_path) / "static" / "uploads"
            upload_dir.mkdir(parents=True, exist_ok=True)
            filename = f"user_{user.id}_{secrets.token_hex(8)}{ext}"
            upload.save(upload_dir / filename)
            user.profile_image = filename
        db.session.commit()
        flash("Profile updated.", "success")
    return render_template("profile.html", user=user)


@bp.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            dev_code = send_otp(user, "password_reset")
            session["reset_user_id"] = user.id
            if dev_code:
                flash(f"Development OTP: {dev_code}", "success")
            else:
                flash("If the account exists, a verification code has been sent.", "success")
            return redirect(url_for("main.verify_otp"))
        flash("If the account exists, a verification code has been sent.", "success")
    return render_template("forgot.html")


@bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if not session.get("reset_user_id"):
        return redirect(url_for("main.forgot"))
    if request.method == "POST":
        code = request.form.get("code", "")
        token = OtpToken.query.filter_by(
            user_id=session["reset_user_id"], purpose="password_reset", used=False
        ).order_by(OtpToken.id.desc()).first()
        if not token or token.expires_at < datetime.utcnow() or token.attempts >= 5:
            flash("Invalid or expired code.", "error")
            return render_template("verify_otp.html")
        token.attempts += 1
        if check_password_hash(token.code_hash, code):
            token.used = True
            db.session.commit()
            session["otp_verified"] = True
            return redirect(url_for("main.reset_password"))
        db.session.commit()
        flash("Invalid code.", "error")
    return render_template("verify_otp.html")


@bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if not session.get("otp_verified"):
        return redirect(url_for("main.forgot"))
    if request.method == "POST":
        new_password = request.form.get("password", "")
        if len(new_password) < 12:
            flash("Password must be at least 12 characters.", "error")
            return render_template("reset_password.html")
        user = User.query.get(session["reset_user_id"])
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        session.pop("reset_user_id", None)
        session.pop("otp_verified", None)
        flash("Password reset successfully.", "success")
        return redirect(url_for("main.login"))
    return render_template("reset_password.html")


@bp.route("/forgot/questions", methods=["GET", "POST"])
def security_questions():
    if request.method == "GET":
        email = request.args.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if not user or not user.security_q1:
            flash("Enter a valid account email first.", "error")
            return redirect(url_for("main.forgot"))
        return render_template("security_questions.html", user=user)

    email = request.form.get("email", "").strip().lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Unable to verify the supplied information.", "error")
        return redirect(url_for("main.forgot"))
    answers = [request.form.get(f"a{i}", "").strip().lower() for i in (1, 2, 3)]
    hashes = [user.security_a1_hash, user.security_a2_hash, user.security_a3_hash]
    if all(verify_hash(h, a) for h, a in zip(hashes, answers)):
        session["question_reset_user_id"] = user.id
        return redirect(url_for("main.reset_from_questions"))
    flash("The security answers did not match.", "error")
    return render_template("security_questions.html", user=user)


@bp.route("/reset-from-questions", methods=["GET", "POST"])
def reset_from_questions():
    if not session.get("question_reset_user_id"):
        return redirect(url_for("main.forgot"))
    if request.method == "POST":
        password = request.form.get("password", "")
        if len(password) < 12:
            flash("Password must be at least 12 characters.", "error")
            return render_template("reset_password.html")
        user = User.query.get(session["question_reset_user_id"])
        user.password_hash = generate_password_hash(password)
        db.session.commit()
        session.pop("question_reset_user_id", None)
        flash("Password reset successfully.", "success")
        return redirect(url_for("main.login"))
    return render_template("reset_password.html")


# ---------------- WebAuthn / passkeys ----------------

@bp.route("/webauthn/register/options")
@login_required
def webauthn_register_options():
    user = current_user()
    rp_id, _ = webauthn_settings()
    exclude = [PublicKeyCredentialDescriptor(id=c.credential_id) for c in user.webauthn_credentials]
    try:
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name=current_app.config["WEBAUTHN_RP_NAME"],
            user_id=int(user.id).to_bytes(8, "big"),
            user_name=user.email,
            user_display_name=user.name,
            timeout=60000,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=exclude,
        )
        session["webauthn_register_challenge"] = base64.urlsafe_b64encode(options.challenge).decode().rstrip("=")
        return options_to_json(options), 200, {"Content-Type": "application/json"}
    except Exception as exc:
        current_app.logger.exception("WebAuthn registration options failed")
        return jsonify({"error": f"Could not start device registration: {exc}"}), 500


@bp.route("/webauthn/register/verify", methods=["POST"])
@login_required
def webauthn_register_verify():
    user = current_user()
    credential = request.get_json(silent=True)
    challenge_text = session.pop("webauthn_register_challenge", None)
    if not credential or not challenge_text:
        return jsonify({"error": "Registration session expired. Click Register device passkey again."}), 400
    try:
        challenge = base64.urlsafe_b64decode(challenge_text + "===")
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=current_app.config["WEBAUTHN_ORIGIN"],
            expected_rp_id=current_app.config["WEBAUTHN_RP_ID"],
            require_user_verification=True,
        )
        existing = WebAuthnCredential.query.filter_by(
            credential_id=verification.credential_id
        ).first()
        if existing:
            return jsonify({"ok": True, "message": "This device passkey is already registered."})

        cred = WebAuthnCredential(
            user_id=user.id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
        )
        db.session.add(cred)
        db.session.commit()
        return jsonify({"ok": True, "message": "Device passkey registered successfully. You can now unlock the vault."})
    except Exception as exc:
        current_app.logger.exception("WebAuthn registration verification failed")
        db.session.rollback()
        return jsonify({"error": f"Device registration failed: {exc}"}), 400


@bp.route("/webauthn/auth/options")
@login_required
def webauthn_auth_options():
    user = current_user()
    rp_id, _ = webauthn_settings()
    allow = [PublicKeyCredentialDescriptor(id=c.credential_id) for c in user.webauthn_credentials]
    if not allow:
        return jsonify({"error": "No device passkey is registered. Open Profile and register this device first."}), 400
    try:
        options = generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=allow,
            timeout=60000,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        session["webauthn_auth_challenge"] = base64.urlsafe_b64encode(options.challenge).decode().rstrip("=")
        return options_to_json(options), 200, {"Content-Type": "application/json"}
    except Exception as exc:
        current_app.logger.exception("WebAuthn authentication options failed")
        return jsonify({"error": f"Could not start device verification: {exc}"}), 500


@bp.route("/webauthn/auth/verify", methods=["POST"])
@login_required
def webauthn_auth_verify():
    credential = request.get_json(silent=True)
    user = current_user()
    challenge_text = session.pop("webauthn_auth_challenge", None)
    if not credential or not challenge_text:
        return jsonify({"error": "Verification session expired. Click Verify with device again."}), 400

    try:
        cred_id = base64url_to_bytes(credential["rawId"])
        stored = WebAuthnCredential.query.filter_by(user_id=user.id, credential_id=cred_id).first()
        if not stored:
            return jsonify({"error": "This device is not registered to this SecureVault account."}), 400

        challenge = base64.urlsafe_b64decode(challenge_text + "===")
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=current_app.config["WEBAUTHN_ORIGIN"],
            expected_rp_id=current_app.config["WEBAUTHN_RP_ID"],
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
            require_user_verification=True,
        )
        stored.sign_count = verification.new_sign_count
        db.session.commit()
        mark_biometric_verified()
        return jsonify({"ok": True, "redirect": url_for("main.vault")})
    except Exception as exc:
        current_app.logger.exception("WebAuthn authentication verification failed")
        db.session.rollback()
        return jsonify({"error": f"Device verification failed: {exc}"}), 400


# ---------------- Admin ----------------

@bp.route("/admin")
@admin_required
def admin_dashboard():
    q = request.args.get("q", "").strip()
    query = User.query
    if q:
        query = query.filter(or_(User.name.ilike(f"%{q}%"), User.email.ilike(f"%{q}%")))
    users = query.order_by(User.created_at.desc()).all()
    total = User.query.count()
    suspended = User.query.filter_by(is_suspended=True).count()
    return render_template("admin.html", users=users, total=total, suspended=suspended, q=q)


@bp.route("/admin/user/<int:user_id>/suspend", methods=["POST"])
@admin_required
def admin_suspend(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == session["user_id"]:
        flash("You cannot suspend your own admin account.", "error")
        return redirect(url_for("main.admin_dashboard"))
    user.is_suspended = not user.is_suspended
    db.session.commit()
    flash("User status updated.", "success")
    return redirect(url_for("main.admin_dashboard"))


@bp.route("/admin/user/<int:user_id>/force-reset", methods=["POST"])
@admin_required
def admin_force_reset(user_id):
    user = User.query.get_or_404(user_id)
    user.password_hash = None
    db.session.commit()
    flash("Login password cleared. The customer must complete account recovery to set a new password.", "success")
    return redirect(url_for("main.admin_dashboard"))


@bp.route("/admin/user/<int:user_id>/details")
@admin_required
def admin_details(user_id):
    user = User.query.get_or_404(user_id)
    return render_template("admin_user.html", user=user)
