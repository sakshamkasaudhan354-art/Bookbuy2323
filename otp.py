import os
import requests
import secrets
import time
import sqlite3

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash


# Load environment variables
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, "otp.env"))

APPS_SCRIPT_URL = os.getenv("APPS_SCRIPT_URL")
MAIL_SECRET = os.getenv("MAIL_SECRET")
SECRET_KEY = os.getenv("SECRET_KEY")

app = Flask(__name__)
app.secret_key = SECRET_KEY
CORS(app)

OTP_VALID_SECONDS = 300
MAX_ATTEMPTS = 5

otp_store = {}
verified_emails = {}


def get_db():
    return sqlite3.connect(os.path.join(BASE_DIR, "users.db"))


# Create database
with get_db() as db:
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            university TEXT,
            college TEXT
        )
    """)


# Send email using Google Apps Script (free, works on Render free plan)
def send_email(to_email, otp):

    if not APPS_SCRIPT_URL or not MAIL_SECRET:
        raise ValueError("Mail configuration missing")

    response = requests.post(
        APPS_SCRIPT_URL,
        json={
            "secret": MAIL_SECRET,
            "to": to_email,
            "subject": "Your BookBuy OTP",
            "text": (
                f"Your BookBuy OTP is {otp}. "
                "It is valid for 5 minutes. "
                "Do not share it with anyone."
            )
        },
        timeout=20
    )

    response.raise_for_status()

    if response.text.strip() != "ok":
        raise RuntimeError(f"Mail failed: {response.text[:200]}")


@app.route("/")
def home():
    return "BookBuy OTP server is running."


# Generate OTP
@app.route("/send-otp", methods=["POST"])
def send_otp():

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email or "@" not in email:
        return jsonify({
            "success": False,
            "message": "Valid email required"
        }), 400

    otp = f"{secrets.randbelow(1000000):06d}"

    otp_store[email] = {
        "otp": otp,
        "expires": time.time() + OTP_VALID_SECONDS,
        "attempts": 0
    }

    try:
        send_email(email, otp)

    except Exception as e:
        print("Email Error:", repr(e))
        otp_store.pop(email, None)

        return jsonify({
            "success": False,
            "message": "Could not send email"
        }), 500

    return jsonify({
        "success": True,
        "message": "OTP sent"
    })


# Verify OTP
@app.route("/verify-otp", methods=["POST"])
def verify_otp():

    data = request.get_json(silent=True) or {}

    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()

    record = otp_store.get(email)

    if not record:
        return jsonify({
            "success": False,
            "message": "No OTP requested"
        }), 400

    if time.time() > record["expires"]:
        otp_store.pop(email, None)

        return jsonify({
            "success": False,
            "message": "OTP expired"
        }), 400

    record["attempts"] += 1

    if record["attempts"] > MAX_ATTEMPTS:
        otp_store.pop(email, None)

        return jsonify({
            "success": False,
            "message": "Too many attempts"
        }), 429

    if secrets.compare_digest(record["otp"], otp):

        otp_store.pop(email, None)
        verified_emails[email] = time.time() + 600

        return jsonify({
            "success": True,
            "message": "OTP verified"
        })

    return jsonify({
        "success": False,
        "message": "Wrong OTP"
    }), 400


# Register
@app.route("/register", methods=["POST"])
def register():

    data = request.get_json(silent=True) or {}

    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    university = (data.get("university") or "").strip()
    college = (data.get("college") or "").strip()

    if not email or "@" not in email or len(password) < 8:
        return jsonify({
            "success": False,
            "message": "Valid email aur 8+ character password chahiye"
        }), 400

    expiry = verified_emails.get(email)

    if not expiry or time.time() > expiry:
        return jsonify({
            "success": False,
            "message": "Pehle email OTP se verify karo"
        }), 403

    try:
        with get_db() as db:
            db.execute(
                """
                INSERT INTO users
                (email, password_hash, university, college)
                VALUES (?, ?, ?, ?)
                """,
                (
                    email,
                    generate_password_hash(password),
                    university,
                    college
                )
            )

    except sqlite3.IntegrityError:
        return jsonify({
            "success": False,
            "message": "Email already registered"
        }), 409

    verified_emails.pop(email, None)

    return jsonify({
        "success": True,
        "message": "Account created"
    })


# Login
@app.route("/login", methods=["POST"])
def login():

    data = request.get_json(silent=True) or {}

    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    with get_db() as db:
        row = db.execute(
            "SELECT password_hash, university FROM users WHERE email = ?",
            (email,)
        ).fetchone()

    if not row or not check_password_hash(row[0], password):
        return jsonify({
            "success": False,
            "message": "Email ya password galat hai"
        }), 401

    return jsonify({
        "success": True,
        "message": "Login successful",
        "university": row[1]
    })


# Forgot password - Send OTP
@app.route("/forgot-send-otp", methods=["POST"])
def forgot_send_otp():

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    with get_db() as db:
        user = db.execute(
            "SELECT 1 FROM users WHERE email = ?",
            (email,)
        ).fetchone()

    if not user:
        return jsonify({
            "success": False,
            "message": "Is email se account nahi mila"
        }), 404

    otp = f"{secrets.randbelow(1000000):06d}"

    otp_store[email] = {
        "otp": otp,
        "expires": time.time() + OTP_VALID_SECONDS,
        "attempts": 0
    }

    try:
        send_email(email, otp)

    except Exception as e:
        print("Email Error:", repr(e))
        otp_store.pop(email, None)

        return jsonify({
            "success": False,
            "message": "Could not send email"
        }), 500

    return jsonify({
        "success": True,
        "message": "OTP sent"
    })


# Reset password
@app.route("/reset-password", methods=["POST"])
def reset_password():

    data = request.get_json(silent=True) or {}

    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if len(password) < 8:
        return jsonify({
            "success": False,
            "message": "Password kam se kam 8 character ka ho"
        }), 400

    expiry = verified_emails.get(email)

    if not expiry or time.time() > expiry:
        return jsonify({
            "success": False,
            "message": "Pehle OTP verify karo"
        }), 403

    with get_db() as db:
        cur = db.execute(
            "UPDATE users SET password_hash = ? WHERE email = ?",
            (generate_password_hash(password), email)
        )

    if cur.rowcount == 0:
        return jsonify({
            "success": False,
            "message": "Account nahi mila"
        }), 404

    verified_emails.pop(email, None)

    return jsonify({
        "success": True,
        "message": "Password updated"
    })


if __name__ == "__main__":
    app.run(debug=False)