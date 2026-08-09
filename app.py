```python
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import random
import hashlib
import os
import time
from functools import wraps

app = Flask(__name__)

# =========================================================
# CONFIGURATION
# =========================================================

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "development-only-secret-key"
)

DATABASE = "securegraphical.db"

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

# Original project alphabet:
# 8 lowercase letters + 8 numbers
CHARACTERS = list("abcdefgh12345678")

COLOURS = [
    "red",
    "orange",
    "yellow",
    "green",
    "blue",
    "purple",
    "pink",
    "brown"
]


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

    # -----------------------------------------------------
    # Upgrade existing database
    # -----------------------------------------------------

    columns = [
        row["name"]
        for row in db.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "pass_colour_hash" not in columns:

        db.execute("""
            ALTER TABLE users
            ADD COLUMN pass_colour_hash TEXT
        """)

    if "failed_attempts" not in columns:

        db.execute("""
            ALTER TABLE users
            ADD COLUMN failed_attempts INTEGER DEFAULT 0
        """)

    if "locked_until" not in columns:

        db.execute("""
            ALTER TABLE users
            ADD COLUMN locked_until REAL DEFAULT 0
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
# HASHING
# =========================================================

def hash_graphical_password(sequence):

    sequence_text = "-".join(sequence)

    return hashlib.sha256(
        sequence_text.encode("utf-8")
    ).hexdigest()


def hash_pass_colour(colour):

    return hashlib.sha256(
        colour.encode("utf-8")
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
# ACCOUNT LOCKOUT
# =========================================================

def is_account_locked(user):

    locked_until = user["locked_until"] or 0

    if locked_until <= 0:
        return False

    if time.time() >= locked_until:
        return False

    return True


def get_remaining_lockout(user):

    locked_until = user["locked_until"] or 0

    remaining = int(
        max(
            0,
            locked_until - time.time()
        )
    )

    return remaining


def reset_login_attempts(user_id):

    db = get_db()

    db.execute("""
        UPDATE users
        SET failed_attempts = 0,
            locked_until = 0
        WHERE id = ?
    """, (user_id,))

    db.commit()
    db.close()


def register_failed_attempt(user_id):

    db = get_db()

    user = db.execute("""
        SELECT failed_attempts
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    attempts = (
        user["failed_attempts"] or 0
    ) + 1

    if attempts >= MAX_LOGIN_ATTEMPTS:

        locked_until = (
            time.time()
            + LOCKOUT_SECONDS
        )

        db.execute("""
            UPDATE users
            SET failed_attempts = ?,
                locked_until = ?
            WHERE id = ?
        """, (
            attempts,
            locked_until,
            user_id
        ))

    else:

        db.execute("""
            UPDATE users
            SET failed_attempts = ?
            WHERE id = ?
        """, (
            attempts,
            user_id
        ))

    db.commit()
    db.close()

    return attempts


# =========================================================
# GRAPHICAL CHALLENGE
# =========================================================

def create_graphical_challenge():

    characters = CHARACTERS.copy()

    random.shuffle(characters)

    # Random initial rotation.
    initial_rotation = random.randint(
        0,
        7
    )

    session["graphical_characters"] = characters

    session["initial_rotation"] = (
        initial_rotation
    )

    session["rotation"] = (
        initial_rotation
    )

    # Each authentication receives a unique challenge ID.
    session["challenge_id"] = (
        hashlib.sha256(
            os.urandom(32)
        ).hexdigest()
    )


def rotate_characters(direction):

    characters = session.get(
        "graphical_characters"
    )

    if not characters:
        return

    rotation = session.get(
        "rotation",
        0
    )

    if direction == "clockwise":

        rotation = (
            rotation + 1
        ) % 8

    elif direction == "counterclockwise":

        rotation = (
            rotation - 1
        ) % 8

    session["rotation"] = rotation


def get_current_characters():

    characters = session.get(
        "graphical_characters",
        []
    )

    rotation = session.get(
        "rotation",
        0
    )

    if not characters:
        return []

    rotation = rotation % len(
        characters
    )

    return (
        characters[rotation:]
        + characters[:rotation]
    )


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

    pass_colour = request.form.get(
        "pass_colour",
        ""
    ).strip().lower()

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
            url_for("home")
            + "#register"
        )

    # -----------------------------------------------------
    # Required fields
    # -----------------------------------------------------

    if (
        not name
        or not email
        or not password
        or not pass_colour
    ):

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
    # Password length
    #
    # Original specification:
    # 4 <= L <= 8
    # -----------------------------------------------------

    if len(password) < 4 or len(password) > 8:

        flash(
            "Password must contain 4 to 8 characters.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#register"
        )

    # -----------------------------------------------------
    # Password confirmation
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
    # Pass-colour validation
    # -----------------------------------------------------

    if pass_colour not in COLOURS:

        flash(
            "Please select a valid pass-colour.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#register"
        )

    # -----------------------------------------------------
    # Store registration temporarily
    # -----------------------------------------------------

    session["registration_name"] = name

    session["registration_email"] = email

    session["registration_password_hash"] = (
        generate_password_hash(
            password
        )
    )

    session["registration_pass_colour_hash"] = (
        hash_pass_colour(
            pass_colour
        )
    )

    # -----------------------------------------------------
    # Create graphical challenge
    # -----------------------------------------------------

    create_graphical_challenge()

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

    if "registration_email" not in session:

        return redirect(
            url_for("home")
        )

    if request.method == "POST":

        selected = request.form.getlist(
            "selected_images"
        )

        # -------------------------------------------------
        # Compatibility with new character system
        # -------------------------------------------------

        if not selected:

            selected = request.form.getlist(
                "selected_characters"
            )

        # User must select between 4 and 8
        # characters according to password length.

        if len(selected) < 4 or len(selected) > 8:

            flash(
                "Please select between 4 and 8 characters.",
                "error"
            )

            return render_template(
                "graphical_password.html",
                mode="register",
                characters=get_current_characters()
            )

        graphical_hash = (
            hash_graphical_password(
                selected
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

        pass_colour_hash = session[
            "registration_pass_colour_hash"
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
                    pass_colour_hash,
                    failed_attempts,
                    locked_until
                )
                VALUES (?, ?, ?, ?, ?, 0, 0)
                """,
                (
                    name,
                    email,
                    password_hash,
                    graphical_hash,
                    pass_colour_hash
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

        db.close()

        # -------------------------------------------------
        # Clear registration data
        # -------------------------------------------------

        for key in [
            "registration_name",
            "registration_email",
            "registration_password_hash",
            "registration_pass_colour_hash",
            "graphical_characters",
            "initial_rotation",
            "rotation",
            "challenge_id"
        ]:

            session.pop(
                key,
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
        mode="register",
        characters=get_current_characters()
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
            url_for("home")
            + "#login"
        )

    # -----------------------------------------------------
    # Find user
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
            url_for("home")
            + "#login"
        )

    # -----------------------------------------------------
    # Account lockout
    # -----------------------------------------------------

    if is_account_locked(user):

        remaining = get_remaining_lockout(
            user
        )

        minutes = remaining // 60
        seconds = remaining % 60

        flash(
            f"Account temporarily locked. "
            f"Try again in {minutes:02d}:{seconds:02d}.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#login"
        )

    # -----------------------------------------------------
    # Password verification
    # -----------------------------------------------------

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        attempts = register_failed_attempt(
            user["id"]
        )

        if attempts >= MAX_LOGIN_ATTEMPTS:

            flash(
                "Too many failed attempts. "
                "Your account has been temporarily locked.",
                "error"
            )

        else:

            remaining_attempts = (
                MAX_LOGIN_ATTEMPTS
                - attempts
            )

            flash(
                f"Invalid email or password. "
                f"{remaining_attempts} attempt(s) remaining.",
                "error"
            )

        create_captcha()

        return redirect(
            url_for("home")
            + "#login"
        )

    # -----------------------------------------------------
    # Temporary login session
    # -----------------------------------------------------

    session["login_user_id"] = user["id"]

    session["login_user_name"] = user["name"]

    session["login_user_email"] = user["email"]

    session["login_user_pass_colour_hash"] = (
        user["pass_colour_hash"]
    )

    # -----------------------------------------------------
    # New graphical challenge
    # -----------------------------------------------------

    create_graphical_challenge()

    return redirect(
        url_for(
            "verify_graphical_password"
        )
    )


# =========================================================
# GRAPHICAL PASSWORD ROTATION
# =========================================================

@app.route(
    "/rotate-graphical-password",
    methods=["POST"]
)
def rotate_graphical_password():

    if "login_user_id" not in session:

        return redirect(
            url_for("home")
        )

    direction = request.form.get(
        "direction"
    )

    if direction not in [
        "clockwise",
        "counterclockwise"
    ]:

        flash(
            "Invalid rotation request.",
            "error"
        )

        return redirect(
            url_for(
                "verify_graphical_password"
            )
        )

    rotate_characters(
        direction
    )

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

    if "login_user_id" not in session:

        return redirect(
            url_for("home")
        )

    # -----------------------------------------------------
    # POST verification
    # -----------------------------------------------------

    if request.method == "POST":

        selected = request.form.getlist(
            "selected_characters"
        )

        if len(selected) < 4 or len(selected) > 8:

            flash(
                "Please select between 4 and 8 characters.",
                "error"
            )

            return render_template(
                "graphical_password.html",
                mode="login",
                characters=get_current_characters()
            )

        submitted_hash = (
            hash_graphical_password(
                selected
            )
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

        # -------------------------------------------------
        # Graphical authentication
        # -------------------------------------------------

        if (
            user is not None
            and submitted_hash
            == user["graphical_password_hash"]
        ):

            reset_login_attempts(
                user["id"]
            )

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
                int(time.time())
            )

            return redirect(
                url_for("dashboard")
            )

        # -------------------------------------------------
        # Wrong graphical password
        # -------------------------------------------------

        attempts = register_failed_attempt(
            user["id"]
        )

        # Remove temporary login session.

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

        session.pop(
            "login_user_pass_colour_hash",
            None
        )

        session.pop(
            "graphical_characters",
            None
        )

        session.pop(
            "rotation",
            None
        )

        session.pop(
            "initial_rotation",
            None
        )

        session.pop(
            "challenge_id",
            None
        )

        create_captcha()

        if attempts >= MAX_LOGIN_ATTEMPTS:

            flash(
                "Too many failed authentication attempts. "
                "Your account has been temporarily locked.",
                "error"
            )

        else:

            flash(
                "Incorrect graphical password.",
                "error"
            )

        return redirect(
            url_for("home")
            + "#login"
        )

    # -----------------------------------------------------
    # GET
    # -----------------------------------------------------

    return render_template(
        "graphical_password.html",
        mode="login",
        characters=get_current_characters(),
        rotation=session.get(
            "rotation",
            0
        ),
        challenge_id=session.get(
            "challenge_id"
        )
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route(
    "/dashboard"
)
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

@app.route(
    "/logout"
)
def logout():

    session.clear()

    create_captcha()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("home")
    )


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

    return """
    <h1>SecureGraphical Server Error</h1>
    <p>Please try again later.</p>
    """, 500


# =========================================================
# START APPLICATION
# =========================================================

init_database()


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=False,
        use_reloader=False
    )
```
