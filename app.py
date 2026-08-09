from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import random
import hashlib
import os
from functools import wraps
from datetime import datetime, timedelta


app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "SecureGraphical-Development-Key-2026"
)

DATABASE = os.path.join(
    app.root_path,
    "securegraphical.db"
)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 10


# =========================================================
# DATABASE
# =========================================================

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_database():

    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            graphical_password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS login_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Safe migration for older databases
    columns = [
        row["name"]
        for row in db.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "failed_attempts" not in columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0"
        )

    if "locked_until" not in columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN locked_until TEXT"
        )

    if "last_login" not in columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN last_login TEXT"
        )

    db.commit()
    db.close()


# =========================================================
# ACTIVITY LOG
# =========================================================

def log_activity(
    action,
    status,
    user_id=None,
    email=None
):

    db = get_db()

    ip_address = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr
    )

    if ip_address and "," in ip_address:
        ip_address = ip_address.split(",")[0].strip()

    db.execute(
        """
        INSERT INTO login_activity
        (
            user_id,
            email,
            action,
            status,
            ip_address
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            user_id,
            email,
            action,
            status,
            ip_address
        )
    )

    db.commit()
    db.close()


# =========================================================
# CAPTCHA
# =========================================================

def create_captcha():

    number1 = random.randint(1, 9)
    number2 = random.randint(1, 9)

    session["captcha_question"] = (
        f"{number1} + {number2} = ?"
    )

    session["captcha_answer"] = str(
        number1 + number2
    )


# =========================================================
# GRAPHICAL PASSWORD
# =========================================================

def hash_graphical_password(sequence):

    sequence_text = "-".join(sequence)

    return hashlib.sha256(
        sequence_text.encode("utf-8")
    ).hexdigest()


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

        return function(*args, **kwargs)

    return wrapper


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if "captcha_question" not in session:
        create_captcha()

    return render_template(
        "index.html",
        captcha_question=session["captcha_question"]
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

    # CAPTCHA
    if captcha != session.get("captcha_answer"):

        flash(
            "Incorrect security verification.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#register"
        )

    # Required fields
    if not name or not email or not password:

        flash(
            "Please complete all required fields.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#register"
        )

    # Password match
    if password != confirm_password:

        flash(
            "Passwords do not match.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#register"
        )

    # Password length
    if len(password) < 6:

        flash(
            "Password must contain at least 6 characters.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#register"
        )

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
            url_for("home") + "#register"
        )

    session["registration_name"] = name
    session["registration_email"] = email

    session["registration_password_hash"] = (
        generate_password_hash(password)
    )

    return redirect(
        url_for("create_graphical_password")
    )


# =========================================================
# CREATE GRAPHICAL PASSWORD
# =========================================================

@app.route(
    "/create-graphical-password",
    methods=["GET", "POST"]
)
def create_graphical_password():

    if "registration_email" not in session:

        return redirect(
            url_for("home")
        )

    if request.method == "POST":

        selected = request.form.getlist(
            "selected_images"
        )

        if len(selected) != 3:

            flash(
                "Please select exactly 3 characters.",
                "error"
            )

            return render_template(
                "graphical_password.html",
                mode="register"
            )

        graphical_hash = hash_graphical_password(
            selected
        )

        name = session["registration_name"]
        email = session["registration_email"]
        password_hash = session["registration_password_hash"]

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
                url_for("home") + "#register"
            )

        finally:

            try:
                db.close()
            except Exception:
                pass

        session.pop("registration_name", None)
        session.pop("registration_email", None)
        session.pop("registration_password_hash", None)

        create_captcha()

        flash(
            "Registration successful. Please login.",
            "success"
        )

        return redirect(
            url_for("home") + "#login"
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

    # CAPTCHA
    if captcha != session.get("captcha_answer"):

        log_activity(
            "CAPTCHA verification",
            "Failed",
            email=email
        )

        flash(
            "Incorrect security verification.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#login"
        )

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

    if user is None:

        log_activity(
            "Password authentication",
            "Failed",
            email=email
        )

        flash(
            "Invalid email or password.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#login"
        )

    # Account lock
    if user["locked_until"]:

        try:

            locked_until = datetime.fromisoformat(
                user["locked_until"]
            )

            if datetime.now() < locked_until:

                flash(
                    "Account temporarily locked due to multiple failed attempts.",
                    "error"
                )

                return redirect(
                    url_for("home") + "#login"
                )

        except ValueError:
            pass

    # Password check
    if not check_password_hash(
        user["password_hash"],
        password
    ):

        db = get_db()

        attempts = (user["failed_attempts"] or 0) + 1

        if attempts >= MAX_FAILED_ATTEMPTS:

            locked_until = (
                datetime.now()
                + timedelta(minutes=LOCKOUT_MINUTES)
            )

            db.execute(
                """
                UPDATE users
                SET failed_attempts = 0,
                    locked_until = ?
                WHERE id = ?
                """,
                (
                    locked_until.isoformat(),
                    user["id"]
                )
            )

            db.commit()
            db.close()

            log_activity(
                "Password authentication",
                "Account locked",
                user_id=user["id"],
                email=email
            )

            flash(
                "Too many failed attempts. Account locked for 10 minutes.",
                "error"
            )

        else:

            db.execute(
                """
                UPDATE users
                SET failed_attempts = ?
                WHERE id = ?
                """,
                (
                    attempts,
                    user["id"]
                )
            )

            db.commit()
            db.close()

            log_activity(
                "Password authentication",
                "Failed",
                user_id=user["id"],
                email=email
            )

            flash(
                "Invalid email or password.",
                "error"
            )

        create_captcha()

        return redirect(
            url_for("home") + "#login"
        )

    session["login_user_id"] = user["id"]
    session["login_user_name"] = user["name"]
    session["login_user_email"] = user["email"]

    log_activity(
        "Password authentication",
        "Successful",
        user_id=user["id"],
        email=email
    )

    return redirect(
        url_for("verify_graphical_password")
    )


# =========================================================
# VERIFY GRAPHICAL PASSWORD
# =========================================================

@app.route(
    "/verify-graphical-password",
    methods=["GET", "POST"]
)
def verify_graphical_password():

    if "login_user_id" not in session:

        return redirect(
            url_for("home")
        )

    if request.method == "POST":

        selected = request.form.getlist(
            "selected_images"
        )

        if len(selected) != 3:

            flash(
                "Please select exactly 3 characters.",
                "error"
            )

            return render_template(
                "graphical_password.html",
                mode="login"
            )

        submitted_hash = hash_graphical_password(
            selected
        )

        db = get_db()

        user = db.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            """,
            (
                session["login_user_id"],
            )
        ).fetchone()

        db.close()

        if (
            user is not None
            and submitted_hash
            == user["graphical_password_hash"]
        ):

            db = get_db()

            db.execute(
                """
                UPDATE users
                SET failed_attempts = 0,
                    locked_until = NULL,
                    last_login = ?
                WHERE id = ?
                """,
                (
                    datetime.now().isoformat(),
                    user["id"]
                )
            )

            db.commit()
            db.close()

            log_activity(
                "Graphical password",
                "Successful",
                user_id=user["id"],
                email=user["email"]
            )

            session.clear()

            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]

            return redirect(
                url_for("dashboard")
            )

        log_activity(
            "Graphical password",
            "Failed",
            user_id=user["id"] if user else None,
            email=user["email"] if user else None
        )

        session.pop("login_user_id", None)
        session.pop("login_user_name", None)
        session.pop("login_user_email", None)

        create_captcha()

        flash(
            "Incorrect graphical password.",
            "error"
        )

        return redirect(
            url_for("home") + "#login"
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

    db = get_db()

    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    activity = db.execute(
        """
        SELECT *
        FROM login_activity
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
        """,
        (session["user_id"],)
    ).fetchall()

    db.close()

    return render_template(
        "dashboard.html",
        user=user,
        activity=activity
    )


# =========================================================
# SECURITY CENTER
# =========================================================

@app.route("/security")
@login_required
def security():

    db = get_db()

    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    db.close()

    return render_template(
        "security.html",
        user=user
    )


# =========================================================
# ACTIVITY
# =========================================================

@app.route("/activity")
@login_required
def activity():

    db = get_db()

    records = db.execute(
        """
        SELECT *
        FROM login_activity
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 50
        """,
        (session["user_id"],)
    ).fetchall()

    db.close()

    return render_template(
        "activity.html",
        records=records
    )


# =========================================================
# ACCOUNT
# =========================================================

@app.route("/account")
@login_required
def account():

    db = get_db()

    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    db.close()

    return render_template(
        "account.html",
        user=user
    )


# =========================================================
# SETTINGS
# =========================================================

@app.route("/settings")
@login_required
def settings():

    db = get_db()

    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    db.close()

    return render_template(
        "settings.html",
        user=user
    )


# =========================================================
# CHANGE PASSWORD
# =========================================================

@app.route(
    "/change-password",
    methods=["POST"]
)
@login_required
def change_password():

    current_password = request.form.get(
        "current_password",
        ""
    )

    new_password = request.form.get(
        "new_password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    db = get_db()

    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    if not check_password_hash(
        user["password_hash"],
        current_password
    ):

        db.close()

        flash(
            "Current password is incorrect.",
            "error"
        )

        return redirect(
            url_for("settings")
        )

    if len(new_password) < 6:

        db.close()

        flash(
            "New password must contain at least 6 characters.",
            "error"
        )

        return redirect(
            url_for("settings")
        )

    if new_password != confirm_password:

        db.close()

        flash(
            "New passwords do not match.",
            "error"
        )

        return redirect(
            url_for("settings")
        )

    db.execute(
        """
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
        """,
        (
            generate_password_hash(new_password),
            user["id"]
        )
    )

    db.commit()
    db.close()

    log_activity(
        "Password changed",
        "Successful",
        user_id=user["id"],
        email=user["email"]
    )

    flash(
        "Password updated successfully.",
        "success"
    )

    return redirect(
        url_for("settings")
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    user_id = session.get("user_id")
    email = session.get("user_email")

    if user_id:

        log_activity(
            "Logout",
            "Successful",
            user_id=user_id,
            email=email
        )

    session.clear()

    create_captcha()

    return redirect(
        url_for("home")
    )


# =========================================================
# START APPLICATION
# =========================================================

init_database()


if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
