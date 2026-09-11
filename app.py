"""SecureVote Flask application.

College demonstration project using email OTP authentication, encrypted
ballots, and a local tamper-evident hash chain.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import threading
import time
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formataddr
from functools import wraps
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from blockchain import Blockchain


BASE_DIR = Path(__file__).resolve().parent
IS_RAILWAY = bool(
    os.environ.get("RAILWAY_PROJECT_ID")
    or os.environ.get("RAILWAY_ENVIRONMENT_NAME")
    or os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")
)
DATA_DIR = Path(
    os.environ.get("DATA_DIR")
    or os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")
    or BASE_DIR
).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("DATABASE_PATH", DATA_DIR / "voting.db"))
CHAIN_PATH = Path(os.environ.get("CHAIN_PATH", DATA_DIR / "chain_data.json"))
KEY_PATH = Path(os.environ.get("KEY_PATH", DATA_DIR / "secret.key"))

OTP_VALIDITY_SECONDS = int(os.environ.get("OTP_VALIDITY_SECONDS", "300"))
OTP_RESEND_COOLDOWN_SECONDS = int(os.environ.get("OTP_RESEND_COOLDOWN_SECONDS", "60"))
OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
VOTE_LOCK = threading.RLock()

CANDIDATES = [
    {"id": "C1", "name": "Aarav Sharma", "party": "Party Alpha"},
    {"id": "C2", "name": "Priya Nair", "party": "Party Beta"},
    {"id": "C3", "name": "Rohan Iyer", "party": "Party Gamma"},
    {"id": "NOTA", "name": "None of the Above", "party": "-"},
]


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


IS_PRODUCTION = (
    os.environ.get("APP_ENV", "development").lower() == "production"
    or _env_bool("RENDER")
    or IS_RAILWAY
)
ALLOW_DEV_OTP = _env_bool("ALLOW_DEV_OTP", default=not IS_PRODUCTION)
SHOW_LIVE_RESULTS = _env_bool("SHOW_LIVE_RESULTS", default=False)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "local-dev-secret-change-me"),
    MAX_CONTENT_LENGTH=64 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    WTF_CSRF_TIME_LIMIT=3600,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
csrf = CSRFProtect(app)
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("securevote")


def _validate_production_config() -> None:
    if not IS_PRODUCTION:
        return
    required = [
        "FLASK_SECRET_KEY", "BALLOT_SECRET", "ADMIN_USERNAME",
        "ADMIN_PASSWORD", "SMTP_USER", "SMTP_PASS",
    ]
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError("Missing required production environment variables: " + ", ".join(missing))
    if len(os.environ["ADMIN_PASSWORD"]) < 12:
        raise RuntimeError("ADMIN_PASSWORD must contain at least 12 characters in production.")
    if (
        IS_RAILWAY
        and not os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")
        and not _env_bool("ALLOW_EPHEMERAL_DATA")
    ):
        raise RuntimeError(
            "Railway persistent storage is not attached. Add a Railway volume or "
            "set ALLOW_EPHEMERAL_DATA=true only for a disposable test deployment."
        )


def _load_ballot_key() -> bytes:
    secret = os.environ.get("BALLOT_SECRET")
    if secret:
        return base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEY_PATH.write_bytes(key)
    return key


_validate_production_config()
fernet = Fernet(_load_ballot_key())
blockchain = Blockchain(chain_file=str(CHAIN_PATH))


def _connect_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = _connect_db()
    return g.db


@app.teardown_appcontext
def close_db(exception=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _add_missing_columns(conn: sqlite3.Connection) -> None:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(voters)")}
    migrations = {
        "otp_hash": "TEXT",
        "otp_attempts": "INTEGER NOT NULL DEFAULT 0",
        "otp_last_sent": "REAL",
    }
    for column, definition in migrations.items():
        if column not in columns:
            conn.execute(f"ALTER TABLE voters ADD COLUMN {column} {definition}")


def init_db() -> None:
    conn = _connect_db()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS voters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                voter_id TEXT UNIQUE,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                is_verified INTEGER NOT NULL DEFAULT 0,
                has_voted INTEGER NOT NULL DEFAULT 0,
                otp_code TEXT,
                otp_hash TEXT,
                otp_expiry REAL,
                otp_purpose TEXT,
                otp_attempts INTEGER NOT NULL DEFAULT 0,
                otp_last_sent REAL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_voters_email ON voters(email);
            CREATE INDEX IF NOT EXISTS idx_voters_voter_id ON voters(voter_id);
            """
        )
        _add_missing_columns(conn)
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('voting_open', '1')")
        conn.commit()
    finally:
        conn.close()


def get_setting(key: str, default: str | None = None) -> str | None:
    row = get_db().execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    db.commit()


def generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _otp_digest(otp: str, purpose: str) -> str:
    payload = f"{purpose}:{otp}".encode("utf-8")
    key = app.config["SECRET_KEY"].encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}{'*' * max(2, len(local) - len(visible))}@{domain}"


def send_otp_email(to_email: str, otp: str, purpose: str) -> tuple[bool, str | None]:
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASS", "").replace(" ", "")
    from_name = os.environ.get("SMTP_FROM_NAME", "SecureVote")
    port = int(os.environ.get("SMTP_PORT", "587"))
    purpose_name = "registration" if purpose == "register" else "login"

    if not user or not password:
        if ALLOW_DEV_OTP:
            logger.warning("Development OTP for %s: %s", to_email, otp)
            return True, otp
        return False, None

    message = EmailMessage()
    message["Subject"] = f"SecureVote {purpose_name} code"
    message["From"] = formataddr((from_name, user))
    message["To"] = to_email
    message.set_content(
        f"Your SecureVote {purpose_name} code is {otp}.\n\n"
        f"It expires in {OTP_VALIDITY_SECONDS // 60} minutes. "
        "Do not share it. If you did not request it, ignore this email."
    )
    try:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(user, password)
            server.send_message(message)
        return True, None
    except (OSError, smtplib.SMTPException) as exc:
        logger.error("OTP email delivery failed: %s", exc.__class__.__name__)
        return False, None


def issue_otp(voter_row_id: int, email: str, purpose: str) -> tuple[bool, str]:
    db = get_db()
    voter = db.execute("SELECT otp_last_sent FROM voters WHERE id = ?", (voter_row_id,)).fetchone()
    now = time.time()
    if voter and voter["otp_last_sent"]:
        wait = OTP_RESEND_COOLDOWN_SECONDS - int(now - voter["otp_last_sent"])
        if wait > 0:
            return False, f"Please wait {wait} seconds before requesting another OTP."

    otp = generate_otp()
    delivered, dev_otp = send_otp_email(email, otp, purpose)
    if not delivered:
        return False, "We could not send the OTP. Please try again shortly."
    db.execute(
        """
        UPDATE voters
        SET otp_code = NULL, otp_hash = ?, otp_expiry = ?, otp_purpose = ?,
            otp_attempts = 0, otp_last_sent = ?
        WHERE id = ?
        """,
        (_otp_digest(otp, purpose), now + OTP_VALIDITY_SECONDS, purpose, now, voter_row_id),
    )
    db.commit()
    if dev_otp:
        flash(f"LOCAL DEVELOPMENT OTP: {dev_otp}", "otp-dev")
    return True, "OTP sent successfully."


def verify_otp(voter: sqlite3.Row, submitted_otp: str, purpose: str) -> tuple[bool, str | None]:
    db = get_db()
    if not voter or not voter["otp_hash"] or voter["otp_purpose"] != purpose:
        return False, "No valid OTP was requested for this step."
    if time.time() > (voter["otp_expiry"] or 0):
        return False, "OTP has expired. Request a new one."
    if voter["otp_attempts"] >= OTP_MAX_ATTEMPTS:
        return False, "Too many incorrect attempts. Request a new OTP."
    submitted_digest = _otp_digest(submitted_otp, purpose)
    if not hmac.compare_digest(submitted_digest, voter["otp_hash"]):
        db.execute("UPDATE voters SET otp_attempts = otp_attempts + 1 WHERE id = ?", (voter["id"],))
        db.commit()
        remaining = max(0, OTP_MAX_ATTEMPTS - voter["otp_attempts"] - 1)
        return False, f"Incorrect OTP. {remaining} attempt(s) remaining."
    return True, None


def clear_otp(voter_row_id: int) -> None:
    get_db().execute(
        """
        UPDATE voters SET otp_code = NULL, otp_hash = NULL, otp_expiry = NULL,
            otp_purpose = NULL, otp_attempts = 0, otp_last_sent = NULL WHERE id = ?
        """,
        (voter_row_id,),
    )


def hash_voter_id(voter_id: str) -> str:
    return hashlib.sha256(voter_id.encode("utf-8")).hexdigest()


def generate_voter_id() -> str:
    return "VOT" + secrets.token_hex(5).upper()


def voter_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("voter_row_id"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin login required.", "error")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_helpers():
    return {"mask_email": mask_email}


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; img-src 'self' data:; "
        "script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    if request.endpoint not in {"static", "index", "result", "health"}:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    try:
        get_db().execute("SELECT 1").fetchone()
        chain_valid, _ = blockchain.is_valid()
        status = 200 if chain_valid else 503
        return jsonify(
            {
                "status": "ok" if chain_valid else "degraded",
                "platform": "railway" if IS_RAILWAY else "standard",
                "persistent_storage": bool(os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")),
            }
        ), status
    except Exception:
        logger.exception("Health check failed")
        return jsonify({"status": "unavailable"}), 503


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = " ".join(request.form.get("full_name", "").split())
        email = request.form.get("email", "").strip().lower()
        if not 2 <= len(full_name) <= 80:
            flash("Enter a valid full name between 2 and 80 characters.", "error")
            return render_template("register.html")
        if len(email) > 254 or not EMAIL_RE.fullmatch(email):
            flash("Enter a valid email address.", "error")
            return render_template("register.html")

        db = get_db()
        existing = db.execute("SELECT * FROM voters WHERE email = ?", (email,)).fetchone()
        if existing and existing["is_verified"]:
            flash("This email is already registered. Log in instead.", "error")
            return redirect(url_for("login"))
        if existing:
            voter_row_id = existing["id"]
            db.execute("UPDATE voters SET full_name = ? WHERE id = ?", (full_name, voter_row_id))
        else:
            cursor = db.execute(
                "INSERT INTO voters (full_name, email, created_at) VALUES (?, ?, ?)",
                (full_name, email, time.time()),
            )
            voter_row_id = cursor.lastrowid
        db.commit()

        session.clear()
        sent, message = issue_otp(voter_row_id, email, purpose="register")
        if not sent:
            flash(message, "error")
            return render_template("register.html")
        session["pending_voter_row_id"] = voter_row_id
        session.permanent = True
        flash("OTP sent. Check your email to complete registration.", "info")
        return redirect(url_for("verify_registration_otp"))
    return render_template("register.html")


@app.route("/verify-registration-otp", methods=["GET", "POST"])
def verify_registration_otp():
    voter_row_id = session.get("pending_voter_row_id")
    if not voter_row_id:
        return redirect(url_for("register"))
    db = get_db()
    voter = db.execute("SELECT * FROM voters WHERE id = ?", (voter_row_id,)).fetchone()
    if not voter:
        session.pop("pending_voter_row_id", None)
        return redirect(url_for("register"))

    if request.method == "POST":
        if "resend" in request.form:
            sent, message = issue_otp(voter_row_id, voter["email"], purpose="register")
            flash(message, "info" if sent else "error")
            return redirect(url_for("verify_registration_otp"))
        submitted = request.form.get("otp", "").strip()
        if not re.fullmatch(r"\d{6}", submitted):
            flash("Enter the complete 6-digit OTP.", "error")
            return render_template("verify_otp.html", voter=voter)
        ok, error = verify_otp(voter, submitted, purpose="register")
        if not ok:
            flash(error, "error")
            return render_template("verify_otp.html", voter=voter)

        for _ in range(5):
            voter_id = generate_voter_id()
            try:
                db.execute("UPDATE voters SET is_verified = 1, voter_id = ? WHERE id = ?", (voter_id, voter_row_id))
                clear_otp(voter_row_id)
                db.commit()
                break
            except sqlite3.IntegrityError:
                db.rollback()
        else:
            logger.error("Unable to generate a unique voter ID")
            flash("Registration could not be completed. Please try again.", "error")
            return render_template("verify_otp.html", voter=voter)
        session.pop("pending_voter_row_id", None)
        session["new_voter_id"] = voter_id
        return redirect(url_for("registration_complete"))
    return render_template("verify_otp.html", voter=voter)


@app.route("/registration-complete")
def registration_complete():
    voter_id = session.pop("new_voter_id", None)
    if not voter_id:
        return redirect(url_for("login"))
    return render_template("registration_complete.html", voter_id=voter_id)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        voter_id = request.form.get("voter_id", "").strip().upper()
        email = request.form.get("email", "").strip().lower()
        voter = get_db().execute(
            "SELECT * FROM voters WHERE voter_id = ? AND email = ? AND is_verified = 1",
            (voter_id, email),
        ).fetchone()
        if not voter:
            flash("The Voter ID and email do not match a verified voter.", "error")
            return render_template("login.html")
        session.clear()
        sent, message = issue_otp(voter["id"], voter["email"], purpose="login")
        if not sent:
            flash(message, "error")
            return render_template("login.html")
        session["pending_login_row_id"] = voter["id"]
        session.permanent = True
        flash("Login OTP sent. Check your email.", "info")
        return redirect(url_for("login_otp"))
    return render_template("login.html")


@app.route("/login-otp", methods=["GET", "POST"])
def login_otp():
    voter_row_id = session.get("pending_login_row_id")
    if not voter_row_id:
        return redirect(url_for("login"))
    db = get_db()
    voter = db.execute("SELECT * FROM voters WHERE id = ?", (voter_row_id,)).fetchone()
    if not voter:
        session.pop("pending_login_row_id", None)
        return redirect(url_for("login"))
    if request.method == "POST":
        if "resend" in request.form:
            sent, message = issue_otp(voter_row_id, voter["email"], purpose="login")
            flash(message, "info" if sent else "error")
            return redirect(url_for("login_otp"))
        submitted = request.form.get("otp", "").strip()
        if not re.fullmatch(r"\d{6}", submitted):
            flash("Enter the complete 6-digit OTP.", "error")
            return render_template("login_otp.html", voter=voter)
        ok, error = verify_otp(voter, submitted, purpose="login")
        if not ok:
            flash(error, "error")
            return render_template("login_otp.html", voter=voter)
        clear_otp(voter_row_id)
        db.commit()
        session.clear()
        session["voter_row_id"] = voter_row_id
        session.permanent = True
        flash(f"Welcome, {voter['full_name']}.", "success")
        return redirect(url_for("vote"))
    return render_template("login_otp.html", voter=voter)


@app.route("/vote", methods=["GET", "POST"])
@voter_login_required
def vote():
    db = get_db()
    voter = db.execute("SELECT * FROM voters WHERE id = ?", (session["voter_row_id"],)).fetchone()
    if not voter:
        session.clear()
        return redirect(url_for("login"))
    voting_open = get_setting("voting_open", "1") == "1"
    if voter["has_voted"]:
        return render_template("voted.html", voter=voter)
    if not voting_open:
        flash("Voting is paused by the administrator.", "error")
        return render_template("vote.html", voter=voter, candidates=CANDIDATES, voting_open=False)

    if request.method == "POST":
        candidate_id = request.form.get("candidate_id", "")
        if not any(candidate["id"] == candidate_id for candidate in CANDIDATES):
            flash("Select a valid candidate.", "error")
            return render_template("vote.html", voter=voter, candidates=CANDIDATES, voting_open=True)
        new_block = None
        with VOTE_LOCK:
            try:
                db.execute("BEGIN IMMEDIATE")
                fresh_voter = db.execute("SELECT * FROM voters WHERE id = ?", (voter["id"],)).fetchone()
                current_open = db.execute("SELECT value FROM settings WHERE key = 'voting_open'").fetchone()
                if fresh_voter["has_voted"]:
                    db.rollback()
                    return render_template("voted.html", voter=fresh_voter)
                if not current_open or current_open["value"] != "1":
                    db.rollback()
                    flash("Voting was just paused. Your vote was not submitted.", "error")
                    return redirect(url_for("vote"))

                encrypted_choice = fernet.encrypt(candidate_id.encode("utf-8")).decode("utf-8")
                block_data = {
                    "voter_hash": hash_voter_id(fresh_voter["voter_id"]),
                    "encrypted_vote": encrypted_choice,
                }
                updated = db.execute(
                    "UPDATE voters SET has_voted = 1 WHERE id = ? AND has_voted = 0",
                    (fresh_voter["id"],),
                ).rowcount
                if updated != 1:
                    db.rollback()
                    return render_template("voted.html", voter=fresh_voter)
                new_block = blockchain.add_block(block_data)
                db.commit()
            except Exception:
                db.rollback()
                if new_block is not None:
                    blockchain.rollback_last(new_block.hash)
                logger.exception("Vote submission failed")
                flash("Your vote was not recorded. Please try again.", "error")
                return redirect(url_for("vote"))
        return render_template("voted.html", voter=voter, block=new_block.to_dict())
    return render_template("vote.html", voter=voter, candidates=CANDIDATES, voting_open=True)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


def tally_votes() -> dict[str, int]:
    counts = {candidate["id"]: 0 for candidate in CANDIDATES}
    for block in blockchain.all_vote_blocks():
        token = block.data.get("encrypted_vote")
        if not token:
            continue
        try:
            candidate_id = fernet.decrypt(token.encode("utf-8")).decode("utf-8")
            if candidate_id in counts:
                counts[candidate_id] += 1
        except (InvalidToken, ValueError):
            logger.warning("Skipped an unreadable ballot in block %s", block.index)
    return counts


@app.route("/result")
def result():
    voting_open = get_setting("voting_open", "1") == "1"
    chain_valid, _ = blockchain.is_valid()
    results_visible = chain_valid and (not voting_open or SHOW_LIVE_RESULTS)
    return render_template(
        "result.html",
        tally=tally_votes() if results_visible else {},
        candidates=CANDIDATES,
        voting_open=voting_open,
        chain_valid=chain_valid,
        results_visible=results_visible,
    )


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        valid_user = hmac.compare_digest(username, os.environ.get("ADMIN_USERNAME", "admin"))
        valid_password = hmac.compare_digest(password, os.environ.get("ADMIN_PASSWORD", "admin@123"))
        if valid_user and valid_password:
            session.clear()
            session["is_admin"] = True
            session.permanent = True
            flash("Welcome, administrator.", "success")
            return redirect(url_for("admin_dashboard"))
        time.sleep(0.4)
        flash("Invalid admin credentials.", "error")
    return render_template("admin_login.html", production=IS_PRODUCTION)


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/admin/dashboard")
@admin_login_required
def admin_dashboard():
    voters = get_db().execute(
        "SELECT voter_id, full_name, email, is_verified, has_voted FROM voters ORDER BY created_at DESC"
    ).fetchall()
    chain_valid, chain_message = blockchain.is_valid()
    return render_template(
        "admin_dashboard.html",
        voters=voters,
        total_registered=sum(1 for voter in voters if voter["is_verified"]),
        total_voted=sum(1 for voter in voters if voter["has_voted"]),
        tally=tally_votes(), candidates=CANDIDATES,
        voting_open=get_setting("voting_open", "1") == "1",
        chain_valid=chain_valid, chain_message=chain_message,
    )


@app.route("/admin/toggle-voting", methods=["POST"])
@admin_login_required
def toggle_voting():
    with VOTE_LOCK:
        current = get_setting("voting_open", "1")
        set_setting("voting_open", "0" if current == "1" else "1")
    flash("Voting status updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/chain")
@admin_login_required
def admin_chain():
    chain_valid, chain_message = blockchain.is_valid()
    return render_template(
        "admin_chain.html", blocks=[block.to_dict() for block in blockchain.chain],
        chain_valid=chain_valid, chain_message=chain_message,
    )


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(CSRFError)
def csrf_error(error):
    return render_template(
        "error.html", code=400, message="This form expired. Go back, refresh the page, and try again."
    ), 400


@app.errorhandler(500)
def server_error(error):
    logger.error("Unhandled server error: %s", error)
    return render_template("error.html", code=500, message="Something went wrong. Please try again."), 500


# Gunicorn imports this module, so database setup must run at import time.
init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=not IS_PRODUCTION)
