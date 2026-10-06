from app import create_app

app = create_app()

if __name__ == "__main__":
    # Use localhost consistently because WebAuthn binds credentials to the RP/origin.
    app.run(debug=True, host="localhost", port=5000)
