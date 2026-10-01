from getpass import getpass
from app import create_app
from app.models import db, User
from werkzeug.security import generate_password_hash

app = create_app()

with app.app_context():
    db.create_all()
    email = input("Admin email: ").strip().lower()
    name = input("Admin name: ").strip()
    password = getpass("Admin login password: ")
    if len(password) < 12:
        raise SystemExit("Use an admin password of at least 12 characters.")

    existing = User.query.filter_by(email=email).first()
    if existing:
        existing.is_admin = True
        existing.password_hash = generate_password_hash(password)
        existing.is_suspended = False
        db.session.commit()
        print("Existing user promoted to admin.")
    else:
        user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=True,
            is_verified=True,
        )
        db.session.add(user)
        db.session.commit()
        print("Admin created.")
