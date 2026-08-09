```python
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

import sqlite3
import random
import hashlib
import hmac
import os
import secrets
from functools import wraps
from datetime import datetime, timedelta


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

app = Flask(__name__)

# ---------------------------------------------------------
# IMPORTANT:
# In a real deployment, use an environment variable:
#
# set SECRET_KEY=your-long-random-secret
#
# The fallback value is only for local development.
# ---------------------------------------------------------

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "SecureGraphical-Development-Key-Change-In-Production"
)

DATABASE = "securegraphical.db"

# Session security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Set to True when deployed through HTTPS.
app.config["SESSION_COOKIE_SECURE"] = False

# Authentication security
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

# CAPTCHA security
CAPTCHA_LENGTH = 5

# Graphical password
GRAPHICAL_PASSWORD_LENGTH = 3

# Supported graphical password alphabet
GRAPHICAL_ALPHABET = list(
    "abcdefgh12345678"
)

# Eight colour sectors
COLOUR_SECTORS = [
    "red",
    "orange",
    "yellow",
    "green",
    "blue",
    "indigo",
    "purple",
    "pink"
]


# =========================================================
# DATABASE
# =========================================================

def get_db():

    db = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    db.row_factory = sqlite3.Row

    return db


def init_database():

    db = get_db()

    # -----------------------------------------------------
    # USERS TABLE
    # -----------------------------------------------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            name TEXT NOT NULL,

            email TEXT NOT NULL UNIQUE,

            password_hash TEXT NOT NULL,

            graphical_password_hash TEXT NOT NULL,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            failed_attempts INTEGER
                DEFAULT 0,

            locked_until TIMESTAMP,

            last_login TIMESTAMP

        )
    """)

    # -----------------------------------------------------
    # SECURITY AUDIT LOG
    # -----------------------------------------------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            email TEXT,

            event TEXT NOT NULL,

            ip_address TEXT,

            user_agent TEXT,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP

        )
    """)

    db.commit()

    db.close()


# =========================================================
# SECURITY AUDIT LOGGING
# =========================================================

def get_client_ip():

    # Basic deployment-friendly IP detection.
    # If your application is behind a trusted proxy,
    # configure the proxy correctly before trusting headers.

    return request.remote_addr or "unknown"


def log_security_event(
    event,
    user_id=None,
    email=None
):

    try:

        db = get_db()

        db.execute(
            """
            INSERT INTO security_logs
            (
                user_id,
                email,
                event,
                ip_address,
                user_agent
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                email,
                event,
                get_client_ip(),
                request.headers.get(
                    "User-Agent",
                    "unknown"
                )
            )
        )

        db.commit()

        db.close()

    except Exception:

        # Logging should never crash authentication.
        pass


# =========================================================
# CAPTCHA
# =========================================================

def create_captcha():

    number1 = random.randint(1, 9)

    number2 = random.randint(1, 9)

    # Add a random operation so the CAPTCHA
    # is less predictable than a fixed format.

    operation = random.choice([
        "+",
        "-"
    ])

    if operation == "+":

        answer = number1 + number2

    else:

        # Avoid negative answers for usability.
        if number2 > number1:
            number1, number2 = number2, number1

        answer = number1 - number2

    question = (
        f"{number1} {operation} {number2} = ?"
    )

    # Store only the answer required for the current
    # session. It is never stored in the database.

    session["captcha_question"] = question

    session["captcha_answer"] = str(answer)

    # Give CAPTCHA a short lifetime.

    session["captcha_created"] = datetime.utcnow().isoformat()


def captcha_is_valid(user_answer):

    stored_answer = session.get(
        "captcha_answer"
    )

    created = session.get(
        "captcha_created"
    )

    if not stored_answer or not created:

        return False

    try:

        created_time = datetime.fromisoformat(
            created
        )

        if datetime.utcnow() - created_time > timedelta(
            minutes=5
        ):

            return False

    except Exception:

        return False

    return hmac.compare_digest(
        str(user_answer).strip(),
        str(stored_answer)
    )


def consume_captcha():

    session.pop(
        "captcha_answer",
        None
    )

    session.pop(
        "captcha_question",
        None
    )

    session.pop(
        "captcha_created",
        None
    )


# =========================================================
# GRAPHICAL PASSWORD HASHING
# =========================================================

def hash_graphical_password(
    sequence,
    rotation_offset=0
):

    """
    Creates a deterministic authentication hash.

    The graphical password consists of:
        - selected characters
        - dynamic rotation state

    Example:

        a-7-b
        rotation = 2

    becomes:

        a-7-b|rotation:2
    """

    sequence_text = "-".join(
        sequence
    )

    authentication_material = (
        f"{sequence_text}|rotation:{rotation_offset}"
    )

    return hashlib.sha256(
        authentication_material.encode(
            "utf-8"
        )
    ).hexdigest()


# =========================================================
# GRAPHICAL PASSWORD VALIDATION
# =========================================================

def validate_graphical_sequence(
    sequence
):

    if not sequence:

        return False

    if len(sequence) != GRAPHICAL_PASSWORD_LENGTH:

        return False

    for character in sequence:

        if character not in GRAPHICAL_ALPHABET:

            return False

    # Prevent duplicate character selections.
    #
    # This makes the graphical password a sequence
    # of three distinct symbols.

    if len(set(sequence)) != len(sequence):

        return False

    return True


# =========================================================
# LOGIN LOCKOUT
# =========================================================

def is_account_locked(user):

    locked_until = user["locked_until"]

    if not locked_until:

        return False

    try:

        lock_time = datetime.fromisoformat(
            locked_until
        )

        if datetime.utcnow() < lock_time:

            return True

    except Exception:

        return False

    return False


def reset_login_attempts(
    user_id
):

    db = get_db()

    db.execute(
        """
        UPDATE users

        SET failed_attempts = 0,
            locked_until = NULL

        WHERE id = ?
        """,
        (user_id,)
    )

    db.commit()

    db.close()


def register_failed_attempt(
    user_id
):

    db = get_db()

    user = db.execute(
        """
        SELECT failed_attempts
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    if user is None:

        db.close()

        return

    attempts = (
        user["failed_attempts"] or 0
    ) + 1

    locked_until = None

    if attempts >= MAX_LOGIN_ATTEMPTS:

        locked_until = (
            datetime.utcnow()
            + timedelta(
                minutes=LOCKOUT_MINUTES
            )
        ).isoformat()

    db.execute(
        """
        UPDATE users

        SET failed_attempts = ?,
            locked_until = ?

        WHERE id = ?
        """,
        (
            attempts,
            locked_until,
            user_id
        )
    )

    db.commit()

    db.close()


# =========================================================
# LOGIN PROTECTION
# =========================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please login first.",
                "error"
            )

            return redirect(
                url_for("home")
            )

        return function(
            *args,
            **kwargs
        )

    return wrapper


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if (
        "captcha_question"
        not in session
    ):

        create_captcha()

    return render_template(
        "index.html"
    )


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["POST"]
)
def register():

    name = request.form.get(
        "name",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    password = request.form.get(
        "password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    captcha = request.form.get(
        "captcha",
        ""
    ).strip()

    # -----------------------------------------------------
    # CAPTCHA
    # -----------------------------------------------------

    if not captcha_is_valid(
        captcha
    ):

        flash(
            "Incorrect or expired security verification.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#register"
        )

    consume_captcha()

    # -----------------------------------------------------
    # REQUIRED FIELDS
    # -----------------------------------------------------

    if not name or not email or not password:

        flash(
            "Please complete all required fields.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#register"
        )

    # -----------------------------------------------------
    # PASSWORD CONFIRMATION
    # -----------------------------------------------------

    if password != confirm_password:

        flash(
            "Passwords do not match.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#register"
        )

    # -----------------------------------------------------
    # PASSWORD LENGTH
    # -----------------------------------------------------

    if len(password) < 8:

        flash(
            "Password must contain at least 8 characters.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#register"
        )

    # -----------------------------------------------------
    # PASSWORD COMPLEXITY
    # -----------------------------------------------------

    has_letter = any(
        char.isalpha()
        for char in password
    )

    has_number = any(
        char.isdigit()
        for char in password
    )

    if not has_letter or not has_number:

        flash(
            "Password must contain both letters and numbers.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#register"
        )

    # -----------------------------------------------------
    # CHECK EXISTING EMAIL
    # -----------------------------------------------------

    db = get_db()

    existing_user = db.execute(
        """
        SELECT id
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    db.close()

    if existing_user:

        flash(
            "This email is already registered.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#register"
        )

    # -----------------------------------------------------
    # HASH TEXT PASSWORD
    # -----------------------------------------------------

    password_hash = (
        generate_password_hash(
            password
        )
    )

    # -----------------------------------------------------
    # TEMPORARY REGISTRATION SESSION
    # -----------------------------------------------------

    session["registration_name"] = name

    session["registration_email"] = email

    session["registration_password_hash"] = (
        password_hash
    )

    log_security_event(
        "REGISTRATION_STARTED",
        email=email
    )

    # -----------------------------------------------------
    # GRAPHICAL PASSWORD SETUP
    # -----------------------------------------------------

    return redirect(
        url_for(
            "create_graphical_password"
        )
    )


# =========================================================
# CREATE GRAPHICAL PASSWORD
# =========================================================

@app.route(
    "/create-graphical-password",
    methods=["GET", "POST"]
)
def create_graphical_password():

    if (
        "registration_email"
        not in session
    ):

        return redirect(
            url_for("home")
        )

    if request.method == "POST":

        selected = request.form.getlist(
            "selected_images"
        )

        # -------------------------------------------------
        # ROTATION STATE
        # -------------------------------------------------

        rotation_raw = request.form.get(
            "rotation_offset",
            "0"
        )

        try:

            rotation_offset = int(
                rotation_raw
            )

        except ValueError:

            rotation_offset = 0

        # Keep rotation within 0-7 sectors.

        rotation_offset %= 8

        # -------------------------------------------------
        # VALIDATE SELECTION
        # -------------------------------------------------

        if not validate_graphical_sequence(
            selected
        ):

            flash(
                "Please select exactly 3 different valid characters.",
                "error"
            )

            return render_template(
                "graphical_password.html",
                mode="register"
            )

        # -------------------------------------------------
        # HASH GRAPHICAL PASSWORD
        # -------------------------------------------------

        graphical_hash = (
            hash_graphical_password(
                selected,
                rotation_offset
            )
        )

        name = session[
            "registration_name"
        ]

        email = session[
            "registration_email"
        ]

        password_hash = session[
            "registration_password_hash"
        ]

        db = get_db()

        try:

            db.execute(
                """
                INSERT INTO users
                (
                    name,
                    email,
                    password_hash,
                    graphical_password_hash
                )

                VALUES (?, ?, ?, ?)
                """,
                (
                    name,
                    email,
                    password_hash,
                    graphical_hash
                )
            )

            db.commit()

        except sqlite3.IntegrityError:

            db.close()

            session.clear()

            create_captcha()

            flash(
                "This email is already registered.",
                "error"
            )

            return redirect(
                url_for("home")
                + "#register"
            )

        except Exception:

            db.close()

            flash(
                "Registration could not be completed. Please try again.",
                "error"
            )

            return redirect(
                url_for("home")
                + "#register"
            )

        db.close()

        log_security_event(
            "REGISTRATION_COMPLETED",
            email=email
        )

        # -------------------------------------------------
        # CLEAR TEMPORARY DATA
        # -------------------------------------------------

        session.pop(
            "registration_name",
            None
        )

        session.pop(
            "registration_email",
            None
        )

        session.pop(
            "registration_password_hash",
            None
        )

        create_captcha()

        flash(
            "Registration successful! Please login.",
            "success"
        )

        return redirect(
            url_for("home")
            + "#login"
        )

    return render_template(
        "graphical_password.html",
        mode="register"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["POST"]
)
def login():

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    password = request.form.get(
        "password",
        ""
    )

    captcha = request.form.get(
        "captcha",
        ""
    ).strip()

    # -----------------------------------------------------
    # CAPTCHA
    # -----------------------------------------------------

    if not captcha_is_valid(
        captcha
    ):

        log_security_event(
            "LOGIN_FAILED_CAPTCHA",
            email=email
        )

        flash(
            "Incorrect or expired security verification.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#login"
        )

    consume_captcha()

    # -----------------------------------------------------
    # FIND USER
    # -----------------------------------------------------

    db = get_db()

    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    db.close()

    # -----------------------------------------------------
    # USER NOT FOUND
    # -----------------------------------------------------

    if user is None:

        log_security_event(
            "LOGIN_FAILED_UNKNOWN_ACCOUNT",
            email=email
        )

        flash(
            "Invalid email or password.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#login"
        )

    # -----------------------------------------------------
    # ACCOUNT LOCK CHECK
    # -----------------------------------------------------

    if is_account_locked(user):

        log_security_event(
            "LOGIN_BLOCKED_ACCOUNT_LOCKED",
            user_id=user["id"],
            email=email
        )

        flash(
            "Too many failed attempts. Please try again later.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#login"
        )

    # -----------------------------------------------------
    # TEXT PASSWORD
    # -----------------------------------------------------

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        register_failed_attempt(
            user["id"]
        )

        log_security_event(
            "LOGIN_FAILED_PASSWORD",
            user_id=user["id"],
            email=email
        )

        flash(
            "Invalid email or password.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#login"
        )

    # -----------------------------------------------------
    # TEXT PASSWORD SUCCESS
    # -----------------------------------------------------

    session["login_user_id"] = (
        user["id"]
    )

    session["login_user_name"] = (
        user["name"]
    )

    session["login_user_email"] = (
        user["email"]
    )

    log_security_event(
        "TEXT_PASSWORD_VERIFIED",
        user_id=user["id"],
        email=email
    )

    # -----------------------------------------------------
    # GRAPHICAL PASSWORD
    # -----------------------------------------------------

    return redirect(
        url_for(
            "verify_graphical_password"
        )
    )


# =========================================================
# VERIFY GRAPHICAL PASSWORD
# =========================================================

@app.route(
    "/verify-graphical-password",
    methods=["GET", "POST"]
)
def verify_graphical_password():

    if (
        "login_user_id"
        not in session
    ):

        return redirect(
            url_for("home")
        )

    if request.method == "POST":

        selected = request.form.getlist(
            "selected_images"
        )

        rotation_raw = request.form.get(
            "rotation_offset",
            "0"
        )

        try:

            rotation_offset = int(
                rotation_raw
            )

        except ValueError:

            rotation_offset = 0

        rotation_offset %= 8

        # -------------------------------------------------
        # VALIDATE GRAPHICAL INPUT
        # -------------------------------------------------

        if not validate_graphical_sequence(
            selected
        ):

            flash(
                "Please select exactly 3 different valid characters.",
                "error"
            )

            return render_template(
                "graphical_password.html",
                mode="login"
            )

        # -------------------------------------------------
        # GET USER
        # -------------------------------------------------

        db = get_db()

        user = db.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            """,
            (
                session[
                    "login_user_id"
                ],
            )
        ).fetchone()

        db.close()

        if user is None:

            session.clear()

            create_captcha()

            flash(
                "Authentication session expired.",
                "error"
            )

            return redirect(
                url_for("home")
            )

        # -------------------------------------------------
        # CALCULATE SUBMITTED HASH
        # -------------------------------------------------

        submitted_hash = (
            hash_graphical_password(
                selected,
                rotation_offset
            )
        )

        # -------------------------------------------------
        # CONSTANT-TIME COMPARISON
        # -------------------------------------------------

        authentication_success = hmac.compare_digest(
            submitted_hash,
            user[
                "graphical_password_hash"
            ]
        )

        if authentication_success:

            # ---------------------------------------------
            # SUCCESS
            # ---------------------------------------------

            reset_login_attempts(
                user["id"]
            )

            db = get_db()

            db.execute(
                """
                UPDATE users

                SET last_login = ?

                WHERE id = ?
                """,
                (
                    datetime.utcnow().isoformat(),
                    user["id"]
                )
            )

            db.commit()

            db.close()

            log_security_event(
                "GRAPHICAL_PASSWORD_VERIFIED",
                user_id=user["id"],
                email=user["email"]
            )

            # ---------------------------------------------
            # CREATE FINAL AUTHENTICATED SESSION
            # ---------------------------------------------

            session.clear()

            session["user_id"] = (
                user["id"]
            )

            session["user_name"] = (
                user["name"]
            )

            session["user_email"] = (
                user["email"]
            )

            session["authenticated_at"] = (
                datetime.utcnow().isoformat()
            )

            return redirect(
                url_for("dashboard")
            )

        # -------------------------------------------------
        # GRAPHICAL PASSWORD FAILURE
        # -------------------------------------------------

        register_failed_attempt(
            user["id"]
        )

        log_security_event(
            "LOGIN_FAILED_GRAPHICAL_PASSWORD",
            user_id=user["id"],
            email=user["email"]
        )

        # Clear temporary authentication state.

        session.pop(
            "login_user_id",
            None
        )

        session.pop(
            "login_user_name",
            None
        )

        session.pop(
            "login_user_email",
            None
        )

        create_captcha()

        flash(
            "Incorrect graphical password.",
            "error"
        )

        return redirect(
            url_for("home")
            + "#login"
        )

    return render_template(
        "graphical_password.html",
        mode="login"
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "dashboard.html",
        name=session["user_name"],
        email=session["user_email"]
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    user_id = session.get(
        "user_id"
    )

    email = session.get(
        "user_email"
    )

    if user_id:

        log_security_event(
            "LOGOUT",
            user_id=user_id,
            email=email
        )

    session.clear()

    create_captcha()

    flash(
        "You have been securely logged out.",
        "success"
    )

    return redirect(
        url_for("home")
    )


# =========================================================
# SECURITY HEADERS
# =========================================================

@app.after_request
def add_security_headers(response):

    response.headers["X-Content-Type-Options"] = (
        "nosniff"
    )

    response.headers["X-Frame-Options"] = (
        "SAMEORIGIN"
    )

    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    response.headers["Cache-Control"] = (
        "no-store"
    )

    return response


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "index.html"
    ), 404


@app.errorhandler(500)
def internal_server_error(error):

    return render_template(
        "index.html"
    ), 500


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    init_database()

    print("=" * 60)

    print(
        "SecureGraphical Authentication System"
    )

    print(
        "Multi-Layer Graphical Password Security"
    )

    print("=" * 60)

    print(
        "Server running on:"
    )

    print(
        "http://127.0.0.1:5000"
    )

    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )
```
