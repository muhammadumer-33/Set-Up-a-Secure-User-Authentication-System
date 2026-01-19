
from flask import Flask, request, send_file, session, render_template
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, io, os
import pyotp, qrcode
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "super-secret-session-key"

login_manager = LoginManager()
login_manager.init_app(app)

def get_db():
    return sqlite3.connect("users.db", check_same_thread=False)

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            twofa_secret BLOB
        )
    """)
    db.commit()

init_db()

KEY_FILE = "secret.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())
cipher = Fernet(open(KEY_FILE, "rb").read())

class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute("SELECT id,email FROM users WHERE id=?", (user_id,)).fetchone()
    return User(*row) if row else None

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        db = get_db()
        if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
            return "Email already registered"
        secret = pyotp.random_base32()
        enc = cipher.encrypt(secret.encode())
        db.execute("INSERT INTO users(email,password,twofa_secret) VALUES(?,?,?)",
                   (email, generate_password_hash(password), enc))
        db.commit()
        return f"<h3>Scan QR</h3><img src='/qrcode/{email}'><br><a href='/login'>Login</a>"
    return render_template("register.html")

@app.route("/qrcode/<email>")
def qr(email):
    db = get_db()
    row = db.execute("SELECT twofa_secret FROM users WHERE email=?", (email,)).fetchone()
    secret = cipher.decrypt(row[0]).decode()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(email, issuer_name="UmerSecure")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        db = get_db()
        row = db.execute("SELECT id,password FROM users WHERE email=?", (email,)).fetchone()
        if not row or not check_password_hash(row[1], password):
            return "Invalid credentials"
        session["2fa"] = row[0]
        return render_template("otp.html")
    return render_template("login.html")

@app.route("/verify-2fa", methods=["POST"])
def verify():
    otp = request.form["otp"]
    uid = session.get("2fa")
    db = get_db()
    row = db.execute("SELECT id,email,twofa_secret FROM users WHERE id=?", (uid,)).fetchone()
    secret = cipher.decrypt(row[2]).decode()
    if not pyotp.TOTP(secret).verify(otp):
        return "Invalid OTP"
    login_user(User(row[0], row[1]))
    return render_template("dashboard.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return "Logged out"

if __name__ == "__main__":
    app.run(debug=True)
