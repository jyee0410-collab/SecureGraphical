from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import random
import hashlib
import os
from functools import wraps


app = Flask(__name__)

# Secret key
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "SecureGraphical-Development-Key-2026"
)

DATABASE = "securegraphical.db"


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


    # CAPTCHA

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


    # EMPTY FIELDS

    if not name or not email or not password:

        flash(
            "Please complete all required fields.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#register"
        )


    # PASSWORD MATCH

    if password != confirm_password:

        flash(
            "Passwords do not match.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#register"
        )


    # PASSWORD LENGTH

    if len(password) < 6:

        flash(
            "Password must contain at least 6 characters.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#register"
        )


    # CHECK EXISTING EMAIL

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


    # TEMPORARY REGISTRATION DATA

    session["registration_name"] = name

    session["registration_email"] = email

    session["registration_password_hash"] = (
        generate_password_hash(password)
    )


    # GO TO GRAPHICAL PASSWORD

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


        # Must select exactly 3

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

            flash(
                "This email is already registered.",
                "error"
            )

            return redirect(
                url_for("home") + "#register"
            )

        finally:

            db.close()


        # Clear registration information

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


    # FIND USER

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


    # CHECK PASSWORD

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        flash(
            "Invalid email or password.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#login"
        )


    # TEMPORARY LOGIN SESSION

    session["login_user_id"] = user["id"]

    session["login_user_name"] = user["name"]

    session["login_user_email"] = user["email"]


    # GO TO GRAPHICAL PASSWORD

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

            # Authentication successful

            session.clear()

            session["user_id"] = user["id"]

            session["user_name"] = user["name"]

            session["user_email"] = user["email"]


            return redirect(
                url_for("dashboard")
            )


        # Wrong graphical password

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
