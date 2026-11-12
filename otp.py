import os
import threading
import secrets
import smtplib
import time
from email.message import EmailMessage
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS


load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "otp.env"))

EMAIL = os.getenv("BOOKBUY_EMAIL")
APP_PASSWORD = os.getenv("BOOKBUY_APP_PASSWORD")

app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv("SECRET_KEY")

OTP_VALID_SECONDS = 300  # 5 minutes
MAX_ATTEMPTS = 5

# email -> {"otp": str, "expires": float, "attempts": int}
otp_store = {}
verified_emails ={}
def get_db():
    return sqlite3.connect("users.db")


with get_db() as db:
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        university TEXT,
        college TEXT
    )""")


def send_email(to_email, otp):
    msg = EmailMessage()
    msg["Subject"] = "Your BookBuy OTP"
    msg["From"] = EMAIL
    msg["To"] = to_email
    msg.set_content(
        f"Your BookBuy OTP is {otp}. It is valid for 5 minutes. "
        "Do not share it with anyone."
    )
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL, APP_PASSWORD)
        server.send_message(msg)


@app.route("/")
def home():
    return "BookBuy OTP server is running."


@app.route("/send-otp", methods=["POST"])
def send_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"success": False, "message": "Valid email required"}), 400

    otp = f"{secrets.randbelow(1000000):06d}"
    otp_store[email] = {
        "otp": otp,
        "expires": time.time() + OTP_VALID_SECONDS,
        "attempts": 0,
    }

    try:
        send_email(email, otp)
    except Exception as e:
        print("Email Error:",repr(e))
        return jsonify({"success": False, "message":"could not sent email"}), 500

    return jsonify({"success": True, "message": "OTP sent"})


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()

    record = otp_store.get(email)
    if not record:
        return jsonify({"success": False, "message": "No OTP requested"}), 400

    if time.time() > record["expires"]:
        del otp_store[email]
        return jsonify({"success": False, "message": "OTP expired"}), 400

    record["attempts"] += 1
    if record["attempts"] > MAX_ATTEMPTS:
        del otp_store[email]
        return jsonify({"success": False, "message": "Too many attempts"}), 429

    if secrets.compare_digest(record["otp"], otp):
        del otp_store[email]
        verified_emails[email] = time.time() + 600
        return jsonify({"success": True, "message": "OTP verified"})

    return jsonify({"success": False, "message": "Wrong OTP"}), 400


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    university = (data.get("university") or "").strip()
    college = (data.get("college") or "").strip()

    if not email or "@" not in email or len(password) < 8:
        return jsonify({"success": False, "message": "Valid email aur 8+ character password chahiye"}), 400

    expiry = verified_emails.get(email)
    if not expiry or time.time() > expiry:
        return jsonify({"success": False, "message": "Pehle email OTP se verify karo"}), 403

    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users (email, password_hash, university, college) VALUES (?, ?, ?, ?)",
                (email, generate_password_hash(password), university, college),
            )
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Email already registered"}), 409

    verified_emails.pop(email, None)
    return jsonify({"success": True, "message": "Account created"})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    with get_db() as db:
        row = db.execute(
            "SELECT password_hash, university FROM users WHERE email = ?", (email,)
        ).fetchone()

    if not row or not check_password_hash(row[0], password):
        return jsonify({"success": False, "message": "Email ya password galat hai"}), 401

    return jsonify({"success": True, "message": "Login successful", "university": row[1]})
@app.route("/forgot-send-otp", methods=["POST"])
def forgot_send_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    with get_db() as db:
        user = db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
    if not user:
        return jsonify({"success": False, "message": "Is email se account nahi mila"}), 404

    otp = f"{secrets.randbelow(1000000):06d}"
    otp_store[email] = {
        "otp": otp,
        "expires": time.time() + OTP_VALID_SECONDS,
        "attempts": 0,
    }

    def _send():
        try:
            send_email(email, otp)
        except Exception as e:
            print("Email Error:", repr(e))

    threading.Thread(target=_send).start()

    return jsonify({"success": True, "message": "OTP sent"})


@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if len(password) < 8:
        return jsonify({"success": False, "message": "Password kam se kam 8 character ka ho"}), 400

    expiry = verified_emails.get(email)
    if not expiry or time.time() > expiry:
        return jsonify({"success": False, "message": "Pehle OTP verify karo"}), 403

    with get_db() as db:
        cur = db.execute(
            "UPDATE users SET password_hash = ? WHERE email = ?",
            (generate_password_hash(password), email),
        )
    if cur.rowcount == 0:
        return jsonify({"success": False, "message": "Account nahi mila"}), 404

    verified_emails.pop(email, None)
    return jsonify({"success": True, "message": "Password updated"})

if __name__ == "__main__":
    app.run(debug=True)