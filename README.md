# SecureVault

A local Flask password-vault project focused on a reliable two-layer vault unlock flow.

## Included

- Email/password account login
- Persistent SQLite database
- Password reset by email OTP
- Password reset by three security questions
- Separate vault master password
- Encrypted vault usernames, passwords and notes using Fernet
- WebAuthn/passkey second layer: Windows Hello, fingerprint, Face ID, Android passkeys, or security keys supported by the browser/device
- Profile picture and account details
- Add, view, edit and permanently delete vault entries
- Admin customer search, suspension and force-password-reset
- No Google Sign-In or Google Cloud dependency

## Important local WebAuthn rule

For local development, always open:

`http://localhost:5000`

Do not switch between `localhost` and `127.0.0.1` after registering a passkey. WebAuthn credentials are tied to the relying-party origin.

## Setup in VS Code

1. Open the `SecureVault` folder in VS Code.
2. Open Terminal.
3. Create a virtual environment:
   `python -m venv .venv`
4. Activate it on Windows PowerShell:
   `.venv\\Scripts\\Activate.ps1`
5. Install packages:
   `pip install -r requirements.txt`
6. Copy `.env.example` to `.env`.
7. Generate a Fernet key:
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
8. Put that value into `VAULT_ENCRYPTION_KEY` in `.env`.
9. Generate a secret key:
   `python -c "import secrets; print(secrets.token_urlsafe(48))"`
10. Put that value into `SECRET_KEY` in `.env`.
11. For real email OTP, configure SMTP. For local testing you can leave SMTP blank; the development OTP is shown as a flash message and logged in the terminal.
12. Create an admin:
   `python create_admin.py`
13. Start the app:
   `python run.py`
14. Open exactly:
   `http://localhost:5000`

## First vault setup

1. Create an account.
2. Sign in with email/password.
3. Open **Profile**.
4. Click **Register device passkey** and complete Windows Hello/fingerprint/Face ID/passkey verification.
5. Return to Dashboard.
6. Click **Unlock vault**.
7. Enter the separate vault master password.
8. Complete the device verification.
9. The encrypted vault opens.

If the browser reports that a passkey already exists, use the same browser/device account or remove the old local test credential and register again.

## Security model

Login and master passwords are one-way hashed. Vault secrets are encrypted at rest. The biometric layer is WebAuthn: SecureVault receives a cryptographic assertion, not a fingerprint or face image.

Admins cannot see plaintext user passwords or decrypted vault contents.

### Automatic vault-key setup
The app now validates `VAULT_ENCRYPTION_KEY` at startup. If the key is missing or malformed and the database has no vault entries yet, SecureVault automatically generates a new valid Fernet key and saves it into `.env`. If the database already contains encrypted vault entries, the app will not replace the key, because doing so would make those entries impossible to decrypt.

For local development, always open the site at `http://localhost:5000`.
