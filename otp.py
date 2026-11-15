import os
import re
import requests
import secrets
import time
import psycopg2

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from itsdangerous import URLSafeTimedSerializer, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash


# Load environment variables
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, "otp.env"))

APPS_SCRIPT_URL = (os.getenv("APPS_SCRIPT_URL") or "").strip()
MAIL_SECRET = (os.getenv("MAIL_SECRET") or "").strip().strip(chr(34)).strip(chr(39))
SECRET_KEY = os.getenv("SECRET_KEY")
DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip()

# ---- PREMIUM SETTINGS ----
# Admin wahi hai jo is email se login kare (Render > Environment mein ADMIN_EMAIL se badal sakte ho)
ADMIN_EMAIL = (os.getenv("ADMIN_EMAIL") or "bookbuy2323@gmail.com").strip().lower()
PREMIUM_PRICE = 50
TOKEN_MAX_AGE = 60 * 60 * 24 * 30   # login token 30 din chalega

app = Flask(__name__)
app.secret_key = SECRET_KEY
CORS(app)

if not SECRET_KEY:
    print("WARNING: SECRET_KEY missing. Premium login token band rahega.")

serializer = URLSafeTimedSerializer(SECRET_KEY, salt="bookbuy-auth") if SECRET_KEY else None

OTP_VALID_SECONDS = 300
MAX_ATTEMPTS = 5

otp_store = {}
verified_emails = {}


def db_run(query, params=(), fetch=False):
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                if fetch == "all":
                    return cur.fetchall()
                if fetch:
                    return cur.fetchone()
                return cur.rowcount
    finally:
        conn.close()


# Create table (permanent database, data nahi udega)
db_run("""
    CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        university TEXT,
        college TEXT
    )
""")

# Premium: users table mein naya column (pehle se hai to kuch nahi hoga)
db_run("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_premium BOOLEAN NOT NULL DEFAULT FALSE")

# Premium: payment requests
db_run("""
    CREATE TABLE IF NOT EXISTS payment_requests (
        email TEXT PRIMARY KEY,
        utr TEXT UNIQUE NOT NULL,
        amount INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
""")


# ---------- LOGIN TOKEN HELPERS ----------
def current_email():
    """Request ke Authorization header se logged-in email nikalta hai."""
    if not serializer:
        return None
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    try:
        data = serializer.loads(header[7:], max_age=TOKEN_MAX_AGE)
    except BadSignature:
        return None
    return data.get("email")


def auth_error():
    return jsonify({
        "success": False,
        "message": "Pehle login karo"
    }), 401


def require_admin():
    email = current_email()
    if not email:
        return None, auth_error()
    if email != ADMIN_EMAIL:
        return None, (jsonify({
            "success": False,
            "message": "Ye sirf admin ke liye hai"
        }), 403)
    return email, None


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
        raise RuntimeError(f"Mail failed: {response.text[:200]} (my secret length: {len(MAIL_SECRET)})")


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
        db_run(
            "INSERT INTO users (email, password_hash, university, college) "
            "VALUES (%s, %s, %s, %s)",
            (email, generate_password_hash(password), university, college)
        )

    except psycopg2.IntegrityError:
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

    row = db_run(
        "SELECT password_hash, university FROM users WHERE email = %s",
        (email,),
        fetch=True
    )

    if not row or not check_password_hash(row[0], password):
        return jsonify({
            "success": False,
            "message": "Email ya password galat hai"
        }), 401

    token = serializer.dumps({"email": email}) if serializer else None

    return jsonify({
        "success": True,
        "message": "Login successful",
        "university": row[1],
        "email": email,
        "token": token
    })


# Forgot password - Send OTP
@app.route("/forgot-send-otp", methods=["POST"])
def forgot_send_otp():

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    user = db_run(
        "SELECT 1 FROM users WHERE email = %s",
        (email,),
        fetch=True
    )

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

    updated = db_run(
        "UPDATE users SET password_hash = %s WHERE email = %s",
        (generate_password_hash(password), email)
    )

    if updated == 0:
        return jsonify({
            "success": False,
            "message": "Account nahi mila"
        }), 404

    verified_emails.pop(email, None)

    return jsonify({
        "success": True,
        "message": "Password updated"
    })


# =====================================================
#                    PREMIUM ROUTES
# =====================================================

# User: premium hai ya nahi + payment request ka status
@app.route("/premium-status", methods=["GET"])
def premium_status():

    email = current_email()
    if not email:
        return auth_error()

    row = db_run(
        "SELECT is_premium FROM users WHERE email = %s",
        (email,),
        fetch=True
    )
    if not row:
        return auth_error()

    req = db_run(
        "SELECT status, utr FROM payment_requests WHERE email = %s",
        (email,),
        fetch=True
    )

    return jsonify({
        "success": True,
        "email": email,
        "premium": bool(row[0]),
        "request_status": req[0] if req else None,
        "utr": req[1] if req else None,
        "is_admin": email == ADMIN_EMAIL
    })


# User: UTR bhejna (payment karne ke baad)
@app.route("/payment-request", methods=["POST"])
def payment_request():

    email = current_email()
    if not email:
        return auth_error()

    data = request.get_json(silent=True) or {}
    utr = (data.get("utr") or "").strip()

    if not re.fullmatch(r"\d{12}", utr):
        return jsonify({
            "success": False,
            "message": "UTR 12 digit ka number hona chahiye"
        }), 400

    row = db_run(
        "SELECT is_premium FROM users WHERE email = %s",
        (email,),
        fetch=True
    )
    if not row:
        return auth_error()

    if row[0]:
        return jsonify({
            "success": False,
            "message": "Premium pehle se active hai"
        }), 400

    try:
        db_run(
            "INSERT INTO payment_requests (email, utr, amount, status) "
            "VALUES (%s, %s, %s, 'pending') "
            "ON CONFLICT (email) DO UPDATE SET "
            "utr = EXCLUDED.utr, amount = EXCLUDED.amount, "
            "status = 'pending', created_at = NOW()",
            (email, utr, PREMIUM_PRICE)
        )

    except psycopg2.IntegrityError:
        return jsonify({
            "success": False,
            "message": "Ye UTR pehle use ho chuka hai"
        }), 409

    return jsonify({
        "success": True,
        "message": "Payment request mil gayi"
    })


# Admin: pending requests ki list
@app.route("/admin/payment-requests", methods=["GET"])
def admin_payment_requests():

    admin, err = require_admin()
    if err:
        return err

    rows = db_run(
        "SELECT email, utr, amount FROM payment_requests "
        "WHERE status = 'pending' ORDER BY created_at",
        fetch="all"
    )

    return jsonify({
        "success": True,
        "requests": [
            {"email": r[0], "utr": r[1], "amount": r[2]} for r in rows
        ]
    })


# Admin: approve ya reject
@app.route("/admin/decide", methods=["POST"])
def admin_decide():

    admin, err = require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    approve = bool(data.get("approve"))

    pending = db_run(
        "SELECT 1 FROM payment_requests WHERE email = %s AND status = 'pending'",
        (email,),
        fetch=True
    )
    if not pending:
        return jsonify({
            "success": False,
            "message": "Pending request nahi mili"
        }), 404

    if approve:
        db_run("UPDATE users SET is_premium = TRUE WHERE email = %s", (email,))

    db_run(
        "UPDATE payment_requests SET status = %s WHERE email = %s",
        ("approved" if approve else "rejected", email)
    )

    return jsonify({
        "success": True,
        "message": "Approved" if approve else "Rejected"
    })


if __name__ == "__main__":
    app.run(debug=False)