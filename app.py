```python
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import random
import hashlib
import os
from functools import wraps

app = Flask(__name__)

# =========================================================
# SECURITY CONFIGURATION
# =========================================================

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "development-secret-key-change-this"
)

DATABASE = "securegraphical.db"

# 8 colours used by the graphical password system
COLORS = [
    "red",
    "blue",
    "green",
    "yellow",
    "purple",
    "orange",
    "pink",
    "cyan"
]

# 16-character alphabet
CHARACTERS = list(
    "abcdefgh12345678"
)


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
            pass_color TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Upgrade an older database automatically
    columns = [
        row["name"]
        for row in db.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "pass_color" not in columns:

        db.execute("""
            ALTER TABLE users
            ADD COLUMN pass_color TEXT
        """)

        # Existing accounts receive a default colour
        db.execute("""
            UPDATE users
            SET pass_color = 'red'
            WHERE pass_color IS NULL
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
# RANDOM GRAPHICAL PASSWORD BOARD
# =========================================================

def create_graphical_board():

    # Randomise the 16 characters
    shuffled_characters = CHARACTERS.copy()
    random.shuffle(shuffled_characters)

    # Randomise the colour positions
    shuffled_colors = COLORS.copy()
    random.shuffle(shuffled_colors)

    # Divide 16 characters into 8 sectors
    sectors = []

    for i in range(8):

        sectors.append({
            "color": shuffled_colors[i],
            "characters": [
                shuffled_characters[i * 2],
                shuffled_characters[i * 2 + 1]
            ]
        })

    return sectors


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
        captcha=session.get("captcha_question")
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
    # PASSWORD CONFIRMATION
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
    # PASSWORD CHARACTER CHECK
    # -----------------------------------------------------

    password_lower = password.lower()

    for character in password_lower:

        if character not in CHARACTERS:

            flash(
                "Password may only contain a-h and 1-8.",
                "error"
            )

            create_captcha()

            return redirect(
                url_for("home") + "#register"
            )

    # -----------------------------------------------------
    # PASS-COLOR
    # -----------------------------------------------------

    if pass_color not in COLORS:

        flash(
            "Please select a valid pass-color.",
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
        generate_password_hash(password_lower)
    )

    session["registration_pass_color"] = pass_color

    session["registration_graphical_password"] = (
        password_lower
    )

    # -----------------------------------------------------
    # GRAPHICAL PASSWORD SETUP
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

        graphical_sequence = request.form.get(
            "graphical_sequence",
            ""
        ).strip().lower()

        expected_password = session.get(
            "registration_graphical_password"
        )

        if graphical_sequence != expected_password:

            flash(
                "Please complete the graphical password correctly.",
                "error"
            )

            return render_template(
                "graphical_password.html",
                mode="register",
                sectors=create_graphical_board(),
                pass_color=session.get(
                    "registration_pass_color"
                ),
                password_length=len(
                    expected_password
                )
            )

        graphical_hash = hash_graphical_password(
            list(graphical_sequence)
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

        db.close()

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

        session.pop(
            "registration_graphical_password",
            None
        )

        create_captcha()

        flash(
            "Registration successful! You can now login.",
            "success"
        )

        return redirect(
            url_for("home") + "#login"
        )

    password = session.get(
        "registration_graphical_password",
        ""
    )

    return render_template(
        "graphical_password.html",
        mode="register",
        sectors=create_graphical_board(),
        pass_color=session.get(
            "registration_pass_color"
        ),
        password_length=len(password)
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
    # CHECK TEXT PASSWORD
    # -----------------------------------------------------

    if not check_password_hash(
        user["password_hash"],
        password.lower()
    ):

        flash(
            "Invalid email or password.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home") + "#login"
        )

    # -----------------------------------------------------
    # TEMPORARY LOGIN SESSION
    # -----------------------------------------------------

    session["login_user_id"] = user["id"]

    session["login_user_name"] = user["name"]

    session["login_user_email"] = user["email"]

    session["login_pass_color"] = user["pass_color"]

    # -----------------------------------------------------
    # GRAPHICAL PASSWORD
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

        graphical_sequence = request.form.get(
            "graphical_sequence",
            ""
        ).strip().lower()

        # -------------------------------------------------
        # CHARACTER VALIDATION
        # -------------------------------------------------

        if not graphical_sequence:

            flash(
                "Please enter your graphical password.",
                "error"
            )

            return render_template(
                "graphical_password.html",
                mode="login",
                sectors=create_graphical_board(),
                pass_color=session.get(
                    "login_pass_color"
                )
            )

        for character in graphical_sequence:

            if character not in CHARACTERS:

                flash(
                    "Invalid character detected.",
                    "error"
                )

                return render_template(
                    "graphical_password.html",
                    mode="login",
                    sectors=create_graphical_board(),
                    pass_color=session.get(
                        "login_pass_color"
                    )
                )

        # -------------------------------------------------
        # HASH SUBMITTED GRAPHICAL PASSWORD
        # -------------------------------------------------

        submitted_hash = hash_graphical_password(
            list(graphical_sequence)
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
        # VERIFY GRAPHICAL PASSWORD
        # -------------------------------------------------

        if (
            user is not None
            and submitted_hash
            == user["graphical_password_hash"]
        ):

            user_id = user["id"]

            user_name = user["name"]

            user_email = user["email"]

            user_color = user["pass_color"]

            session.clear()

            session["user_id"] = user_id

            session["user_name"] = user_name

            session["user_email"] = user_email

            session["user_color"] = user_color

            return redirect(
                url_for("dashboard")
            )

        # -------------------------------------------------
        # FAILED GRAPHICAL PASSWORD
        # -------------------------------------------------

        session.clear()

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
        mode="login",
        sectors=create_graphical_board(),
        pass_color=session.get(
            "login_pass_color"
        )
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
        email=session["user_email"],
        pass_color=session.get(
            "user_color",
            "red"
        )
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
# RUN
# =========================================================

if __name__ == "__main__":

    init_database()

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=False
    )
```
