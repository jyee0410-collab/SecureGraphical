from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import random
import hashlib
import os
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)

# =========================================================
# CONFIGURATION
# =========================================================

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "SecureGraphical-Development-Key-2026"
)

DATABASE = os.environ.get(
    "DATABASE_PATH",
    "securegraphical.db"
)

# 16 characters required by the proposed scheme
CHARACTERS = list(
    "abcdefgh12345678"
)

# 8 authentication colours
COLORS = [
    {
        "name": "Red",
        "hex": "#ef4444"
    },
    {
        "name": "Orange",
        "hex": "#f97316"
    },
    {
        "name": "Yellow",
        "hex": "#eab308"
    },
    {
        "name": "Green",
        "hex": "#22c55e"
    },
    {
        "name": "Blue",
        "hex": "#3b82f6"
    },
    {
        "name": "Indigo",
        "hex": "#6366f1"
    },
    {
        "name": "Purple",
        "hex": "#a855f7"
    },
    {
        "name": "Pink",
        "hex": "#ec4899"
    }
]

MAX_LOGIN_ATTEMPTS = 5


# =========================================================
# DATABASE
# =========================================================

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_database():

    db = get_db()

    # -----------------------------------------------------
    # USERS
    # -----------------------------------------------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            name TEXT NOT NULL,

            email TEXT NOT NULL UNIQUE,

            password_hash TEXT NOT NULL,

            graphical_password_hash TEXT NOT NULL,

            pass_color TEXT NOT NULL,

            failed_attempts INTEGER DEFAULT 0,

            account_locked INTEGER DEFAULT 0,

            last_login TIMESTAMP,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)

    # -----------------------------------------------------
    # LOGIN ACTIVITY
    # -----------------------------------------------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            success INTEGER NOT NULL,

            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(user_id)
            REFERENCES users(id)

        )
    """)

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
# GRAPHICAL PASSWORD HASH
# =========================================================

def hash_graphical_password(sequence):

    sequence_text = "-".join(sequence)

    return hashlib.sha256(
        sequence_text.encode("utf-8")
    ).hexdigest()


# =========================================================
# PASSWORD STRENGTH
# =========================================================

def password_strength(password):

    score = 0

    if len(password) >= 4:
        score += 1

    if len(password) >= 6:
        score += 1

    if any(c.isalpha() for c in password):
        score += 1

    if any(c.isdigit() for c in password):
        score += 1

    if any(c.isupper() for c in password):
        score += 1

    if any(not c.isalnum() for c in password):
        score += 1

    if score <= 2:
        return "Weak"

    if score <= 4:
        return "Medium"

    return "Strong"


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
# LOG LOGIN ATTEMPT
# =========================================================

def log_login_attempt(
    user_id,
    success
):

    db = get_db()

    db.execute(
        """
        INSERT INTO login_attempts
        (
            user_id,
            success
        )
        VALUES (?, ?)
        """,
        (
            user_id,
            1 if success else 0
        )
    )

    db.commit()

    db.close()


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if "captcha_question" not in session:
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

    pass_color = request.form.get(
        "pass_color",
        ""
    ).strip()


    # -----------------------------------------------------
    # CAPTCHA
    # -----------------------------------------------------

    if captcha != session.get(
        "captcha_answer"
    ):

        flash(
            "Incorrect security verification.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#register"
        )


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
            url_for("home") + "#register"
        )


    # -----------------------------------------------------
    # PASSWORD LENGTH
    # -----------------------------------------------------

    if len(password) < 4 or len(password) > 8:

        flash(
            "Password must contain 4 to 8 characters.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#register"
        )


    # -----------------------------------------------------
    # PASSWORD MATCH
    # -----------------------------------------------------

    if password != confirm_password:

        flash(
            "Passwords do not match.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#register"
        )


    # -----------------------------------------------------
    # PASS COLOR
    # -----------------------------------------------------

    valid_colors = [
        color["name"]
        for color in COLORS
    ]

    if pass_color not in valid_colors:

        flash(
            "Please select a valid pass-color.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#register"
        )


    # -----------------------------------------------------
    # CHECK EMAIL
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
            url_for("home") + "#register"
        )


    # -----------------------------------------------------
    # STORE TEMPORARY REGISTRATION DATA
    # -----------------------------------------------------

    session["registration_name"] = name

    session["registration_email"] = email

    session["registration_password_hash"] = (
        generate_password_hash(password)
    )

    session["registration_pass_color"] = pass_color


    # -----------------------------------------------------
    # GRAPHICAL PASSWORD
    # -----------------------------------------------------

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


        # Exactly 3 characters for graphical sequence
        if len(selected) != 3:

            flash(
                "Please select exactly 3 characters.",
                "error"
            )

            return render_template(
                "graphical_password.html",
                mode="register",
                characters=CHARACTERS,
                colors=COLORS
            )


        # Prevent duplicate characters
        if len(set(selected)) != len(selected):

            flash(
                "Each graphical character must be different.",
                "error"
            )

            return render_template(
                "graphical_password.html",
                mode="register",
                characters=CHARACTERS,
                colors=COLORS
            )


        graphical_hash = hash_graphical_password(
            selected
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

        pass_color = session[
            "registration_pass_color"
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
                    graphical_password_hash,
                    pass_color
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    name,
                    email,
                    password_hash,
                    graphical_hash,
                    pass_color
                )
            )

            db.commit()


        except sqlite3.IntegrityError:

            db.rollback()

            flash(
                "This email is already registered.",
                "error"
            )

            db.close()

            session.clear()

            create_captcha()

            return redirect(
                url_for("home") + "#register"
            )


        finally:

            db.close()


        # -------------------------------------------------
        # CLEAR TEMP DATA
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

        session.pop(
            "registration_pass_color",
            None
        )


        create_captcha()


        flash(
            "Registration successful! Please login.",
            "success"
        )


        return redirect(
            url_for("home") + "#login"
        )


    return render_template(
        "graphical_password.html",
        mode="register",
        characters=CHARACTERS,
        colors=COLORS
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

    if captcha != session.get(
        "captcha_answer"
    ):

        flash(
            "Incorrect security verification.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#login"
        )


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


    if user is None:

        flash(
            "Invalid email or password.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#login"
        )


    # -----------------------------------------------------
    # ACCOUNT LOCK
    # -----------------------------------------------------

    if user["account_locked"]:

        flash(
            "This account is temporarily locked. Please use account recovery.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#login"
        )


    # -----------------------------------------------------
    # CHECK PASSWORD
    # -----------------------------------------------------

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        db = get_db()

        new_attempts = (
            user["failed_attempts"] + 1
        )

        locked = (
            1
            if new_attempts >= MAX_LOGIN_ATTEMPTS
            else 0
        )

        db.execute(
            """
            UPDATE users
            SET
                failed_attempts = ?,
                account_locked = ?
            WHERE id = ?
            """,
            (
                new_attempts,
                locked,
                user["id"]
            )
        )

        db.commit()

        db.close()


        log_login_attempt(
            user["id"],
            False
        )


        if locked:

            flash(
                "Too many failed attempts. Your account has been locked.",
                "error"
            )

        else:

            remaining = (
                MAX_LOGIN_ATTEMPTS
                - new_attempts
            )

            flash(
                f"Invalid email or password. {remaining} attempts remaining.",
                "error"
            )


        create_captcha()

        return redirect(
            url_for("home") + "#login"
        )


    # -----------------------------------------------------
    # SUCCESSFUL TEXT PASSWORD
    # -----------------------------------------------------

    session["login_user_id"] = user["id"]

    session["login_user_name"] = user["name"]

    session["login_user_email"] = user["email"]


    # -----------------------------------------------------
    # GO TO GRAPHICAL AUTHENTICATION
    # -----------------------------------------------------

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


        # Exactly 3
        if len(selected) != 3:

            flash(
                "Please select exactly 3 characters.",
                "error"
            )

            return render_template(
                "graphical_password.html",
                mode="login",
                characters=CHARACTERS,
                colors=COLORS
            )


        # No duplicates
        if len(set(selected)) != len(selected):

            flash(
                "Duplicate characters are not allowed.",
                "error"
            )

            return render_template(
                "graphical_password.html",
                mode="login",
                characters=CHARACTERS,
                colors=COLORS
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


        if user is None:

            db.close()

            session.clear()

            return redirect(
                url_for("home")
            )


        # -------------------------------------------------
        # VERIFY GRAPHICAL PASSWORD
        # -------------------------------------------------

        correct = (
            submitted_hash
            ==
            user["graphical_password_hash"]
        )


        if correct:

            # Reset failed attempts
            db.execute(
                """
                UPDATE users
                SET
                    failed_attempts = 0,
                    account_locked = 0,
                    last_login = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    user["id"],
                )
            )

            db.commit()

            db.close()


            log_login_attempt(
                user["id"],
                True
            )


            # -------------------------------------------------
            # FINAL AUTHENTICATION SESSION
            # -------------------------------------------------

            session.clear()

            session["user_id"] = user["id"]

            session["user_name"] = user["name"]

            session["user_email"] = user["email"]

            session["authenticated"] = True


            return redirect(
                url_for("dashboard")
            )


        # -------------------------------------------------
        # WRONG GRAPHICAL PASSWORD
        # -------------------------------------------------

        db.execute(
            """
            UPDATE users
            SET failed_attempts = failed_attempts + 1
            WHERE id = ?
            """,
            (
                user["id"],
            )
        )

        db.commit()

        db.close()


        log_login_attempt(
            user["id"],
            False
        )


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
            url_for("home") + "#login"
        )


    # -----------------------------------------------------
    # DISPLAY GRAPHICAL AUTHENTICATION
    # -----------------------------------------------------

    return render_template(
        "graphical_password.html",
        mode="login",
        characters=CHARACTERS,
        colors=COLORS
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
        (
            session["user_id"],
        )
    ).fetchone()


    successful_logins = db.execute(
        """
        SELECT COUNT(*)
        FROM login_attempts
        WHERE user_id = ?
        AND success = 1
        """,
        (
            session["user_id"],
        )
    ).fetchone()[0]


    failed_logins = db.execute(
        """
        SELECT COUNT(*)
        FROM login_attempts
        WHERE user_id = ?
        AND success = 0
        """,
        (
            session["user_id"],
        )
    ).fetchone()[0]


    db.close()


    return render_template(
        "dashboard.html",
        name=user["name"],
        email=user["email"],
        pass_color=user["pass_color"],
        last_login=user["last_login"],
        successful_logins=successful_logins,
        failed_logins=failed_logins
    )


# =========================================================
# ACCOUNT RECOVERY
# =========================================================

@app.route(
    "/recovery",
    methods=["GET", "POST"]
)
def recovery():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()


        db = get_db()

        user = db.execute(
            """
            SELECT id, email
            FROM users
            WHERE email = ?
            """,
            (
                email,
            )
        ).fetchone()

        db.close()


        if user is None:

            flash(
                "If the email exists, recovery instructions will be provided.",
                "success"
            )

            return redirect(
                url_for("recovery")
            )


        # Demo recovery flow
        session["recovery_user_id"] = user["id"]

        return redirect(
            url_for("reset_password")
        )


    return render_template(
        "recovery.html"
    )


# =========================================================
# RESET PASSWORD
# =========================================================

@app.route(
    "/reset-password",
    methods=["GET", "POST"]
)
def reset_password():

    if "recovery_user_id" not in session:

        return redirect(
            url_for("recovery")
        )


    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        if len(password) < 4 or len(password) > 8:

            flash(
                "Password must contain 4 to 8 characters.",
                "error"
            )

            return redirect(
                url_for("reset_password")
            )


        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(
                url_for("reset_password")
            )


        db = get_db()

        db.execute(
            """
            UPDATE users
            SET
                password_hash = ?,
                failed_attempts = 0,
                account_locked = 0
            WHERE id = ?
            """,
            (
                generate_password_hash(password),
                session["recovery_user_id"]
            )
        )

        db.commit()

        db.close()


        session.pop(
            "recovery_user_id",
            None
        )


        create_captcha()


        flash(
            "Password reset successful. Please login again.",
            "success"
        )


        return redirect(
            url_for("home") + "#login"
        )


    return render_template(
        "reset_password.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    create_captcha()

    return redirect(
        url_for("home")
    )


# =========================================================
# APPLICATION START
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
