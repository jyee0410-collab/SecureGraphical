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
import secrets
from functools import wraps
from datetime import timedelta


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

# Secret key used to sign Flask sessions.
# For a real deployment, store this in an environment variable.
app.secret_key = "SecureGraphical-My-Secret-Key-2026"

DATABASE = "securegraphical.db"

# Session security configuration
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Use True when the application is deployed behind HTTPS.
app.config["SESSION_COOKIE_SECURE"] = False

# Session lifetime
app.permanent_session_lifetime = timedelta(minutes=30)


# ============================================================
# SECURITY CONFIGURATION
# ============================================================

MAX_LOGIN_ATTEMPTS = 5

GRAPHICAL_PASSWORD_LENGTH = 3

CHARACTERS = list(
    "abcdefgh12345678"
)

COLOURS = [
    "red",
    "orange",
    "yellow",
    "green",
    "blue",
    "indigo",
    "purple",
    "pink"
]


# ============================================================
# DATABASE
# ============================================================

def get_db():
    """
    Open SQLite database connection.
    """

    db = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    db.row_factory = sqlite3.Row

    return db


def init_database():
    """
    Create required database tables if they do not exist.
    """

    db = get_db()

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            name TEXT NOT NULL,

            email TEXT NOT NULL UNIQUE,

            password_hash TEXT NOT NULL,

            graphical_password_hash TEXT NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    db.commit()

    db.close()


# ============================================================
# CAPTCHA
# ============================================================

def create_captcha():
    """
    Generate a new arithmetic CAPTCHA.
    """

    number1 = secrets.randbelow(9) + 1
    number2 = secrets.randbelow(9) + 1

    session["captcha_question"] = (
        f"{number1} + {number2} = ?"
    )

    session["captcha_answer"] = str(
        number1 + number2
    )


def verify_captcha(user_answer):
    """
    Verify CAPTCHA answer.
    """

    expected = session.get(
        "captcha_answer"
    )

    if expected is None:
        return False

    return secrets.compare_digest(
        str(user_answer).strip(),
        str(expected)
    )


# ============================================================
# GRAPHICAL PASSWORD HASHING
# ============================================================

def hash_graphical_password(sequence):
    """
    Convert graphical password sequence into
    a SHA-256 hash.

    Example:

        ["a", "4", "h"]

    becomes:

        a-4-h
    """

    sequence_text = "-".join(
        sequence
    )

    return hashlib.sha256(
        sequence_text.encode("utf-8")
    ).hexdigest()


# ============================================================
# GRAPHICAL PASSWORD VALIDATION
# ============================================================

def validate_graphical_selection(sequence):
    """
    Validate graphical password selection.

    Requirements:
    - exactly 3 characters
    - characters must belong to approved alphabet
    - no duplicate characters
    """

    if len(sequence) != GRAPHICAL_PASSWORD_LENGTH:
        return False

    if any(
        character not in CHARACTERS
        for character in sequence
    ):
        return False

    if len(set(sequence)) != len(sequence):
        return False

    return True


# ============================================================
# RANDOM GRAPHICAL AUTHENTICATION STATE
# ============================================================

def create_graphical_state():
    """
    Create a new random graphical authentication state.

    The 16 characters are shuffled every time the graphical
    authentication page is opened.

    Eight colour sectors are also randomly rotated.
    """

    characters = CHARACTERS.copy()

    random.SystemRandom().shuffle(
        characters
    )

    colour_rotation = (
        secrets.randbelow(8)
    )

    session["graphical_characters"] = characters

    session["graphical_rotation"] = (
        colour_rotation
    )

    # Generate a random authentication nonce.
    session["graphical_nonce"] = (
        secrets.token_hex(16)
    )


# ============================================================
# LOGIN ATTEMPT PROTECTION
# ============================================================

def reset_login_attempts():
    """
    Reset failed login attempts.
    """

    session["login_attempts"] = 0


def increase_login_attempts():
    """
    Increase failed login attempts.
    """

    attempts = session.get(
        "login_attempts",
        0
    )

    attempts += 1

    session["login_attempts"] = attempts

    return attempts


def login_blocked():
    """
    Determine whether the current session has
    exceeded the maximum number of login attempts.
    """

    attempts = session.get(
        "login_attempts",
        0
    )

    return attempts >= MAX_LOGIN_ATTEMPTS


# ============================================================
# LOGIN REQUIRED DECORATOR
# ============================================================

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


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    # Create CAPTCHA when a new session starts.
    if (
        "captcha_question"
        not in session
    ):

        create_captcha()

    return render_template(
        "index.html"
    )


# ============================================================
# REGISTER
# ============================================================

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


    # --------------------------------------------------------
    # CAPTCHA
    # --------------------------------------------------------

    if not verify_captcha(
        captcha
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


    # --------------------------------------------------------
    # REQUIRED FIELDS
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # EMAIL VALIDATION
    # --------------------------------------------------------

    if (
        "@" not in email
        or "." not in email.split("@")[-1]
    ):

        flash(
            "Please enter a valid email address.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#register"
        )


    # --------------------------------------------------------
    # PASSWORD MATCH
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # PASSWORD SECURITY
    # --------------------------------------------------------

    if len(password) < 6:

        flash(
            "Password must contain at least 6 characters.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#register"
        )


    # --------------------------------------------------------
    # CHECK PASSWORD COMPLEXITY
    # --------------------------------------------------------

    if (
        password.isalpha()
        or password.isdigit()
    ):

        flash(
            "For stronger security, use a combination of letters and numbers.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#register"
        )


    # --------------------------------------------------------
    # CHECK EMAIL
    # --------------------------------------------------------

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


    if existing_user is not None:

        flash(
            "This email is already registered.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#register"
        )


    # --------------------------------------------------------
    # TEMPORARY REGISTRATION DATA
    # --------------------------------------------------------

    session["registration_name"] = name

    session["registration_email"] = email

    session["registration_password_hash"] = (
        generate_password_hash(
            password
        )
    )


    # --------------------------------------------------------
    # CREATE GRAPHICAL AUTHENTICATION STATE
    # --------------------------------------------------------

    create_graphical_state()


    # --------------------------------------------------------
    # GO TO GRAPHICAL PASSWORD REGISTRATION
    # --------------------------------------------------------

    return redirect(
        url_for(
            "create_graphical_password"
        )
    )


# ============================================================
# CREATE GRAPHICAL PASSWORD
# ============================================================

@app.route(
    "/create-graphical-password",
    methods=["GET", "POST"]
)
def create_graphical_password():

    # User must complete normal registration first.
    if (
        "registration_email"
        not in session
    ):

        flash(
            "Please start registration first.",
            "error"
        )

        return redirect(
            url_for("home")
        )


    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == "POST":

        selected = request.form.getlist(
            "selected_images"
        )


        # ----------------------------------------------------
        # VALIDATE SELECTION
        # ----------------------------------------------------

        if not validate_graphical_selection(
            selected
        ):

            flash(
                "Please select exactly 3 different characters.",
                "error"
            )

            create_graphical_state()

            return render_template(
                "graphical_password.html",
                mode="register"
            )


        # ----------------------------------------------------
        # HASH GRAPHICAL PASSWORD
        # ----------------------------------------------------

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


        finally:

            try:
                db.close()
            except Exception:
                pass


        # ----------------------------------------------------
        # CLEAR REGISTRATION DATA
        # ----------------------------------------------------

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
            "graphical_characters",
            None
        )

        session.pop(
            "graphical_rotation",
            None
        )

        session.pop(
            "graphical_nonce",
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


    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    if (
        "graphical_characters"
        not in session
    ):

        create_graphical_state()


    return render_template(
        "graphical_password.html",
        mode="register"
    )


# ============================================================
# LOGIN - TEXT PASSWORD
# ============================================================

@app.route(
    "/login",
    methods=["POST"]
)
def login():

    # --------------------------------------------------------
    # CHECK LOGIN LOCK
    # --------------------------------------------------------

    if login_blocked():

        flash(
            "Too many unsuccessful login attempts. Please try again later.",
            "error"
        )

        create_captcha()

        reset_login_attempts()

        return redirect(
            url_for("home")
            + "#login"
        )


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


    # --------------------------------------------------------
    # CAPTCHA
    # --------------------------------------------------------

    if not verify_captcha(
        captcha
    ):

        increase_login_attempts()

        flash(
            "Incorrect security verification.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#login"
        )


    # --------------------------------------------------------
    # FIND USER
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # INVALID ACCOUNT
    # --------------------------------------------------------

    if user is None:

        increase_login_attempts()

        flash(
            "Invalid email or password.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#login"
        )


    # --------------------------------------------------------
    # CHECK TEXT PASSWORD
    # --------------------------------------------------------

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        increase_login_attempts()

        flash(
            "Invalid email or password.",
            "error"
        )

        create_captcha()

        return redirect(
            url_for("home")
            + "#login"
        )


    # --------------------------------------------------------
    # TEXT PASSWORD SUCCESS
    # --------------------------------------------------------

    reset_login_attempts()


    # Temporary session.
    # User is NOT fully authenticated yet.
    session["login_user_id"] = (
        user["id"]
    )

    session["login_user_name"] = (
        user["name"]
    )

    session["login_user_email"] = (
        user["email"]
    )


    # --------------------------------------------------------
    # CREATE NEW GRAPHICAL STATE
    # --------------------------------------------------------

    create_graphical_state()


    # --------------------------------------------------------
    # GRAPHICAL PASSWORD
    # --------------------------------------------------------

    return redirect(
        url_for(
            "verify_graphical_password"
        )
    )


# ============================================================
# VERIFY GRAPHICAL PASSWORD
# ============================================================

@app.route(
    "/verify-graphical-password",
    methods=["GET", "POST"]
)
def verify_graphical_password():

    # --------------------------------------------------------
    # TEXT PASSWORD MUST BE COMPLETED FIRST
    # --------------------------------------------------------

    if (
        "login_user_id"
        not in session
    ):

        flash(
            "Please complete the first authentication step.",
            "error"
        )

        return redirect(
            url_for("home")
        )


    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == "POST":

        selected = request.form.getlist(
            "selected_images"
        )


        # ----------------------------------------------------
        # VALIDATE SELECTION
        # ----------------------------------------------------

        if not validate_graphical_selection(
            selected
        ):

            flash(
                "Please select exactly 3 different characters.",
                "error"
            )

            create_graphical_state()

            return render_template(
                "graphical_password.html",
                mode="login"
            )


        # ----------------------------------------------------
        # CREATE SUBMITTED HASH
        # ----------------------------------------------------

        submitted_hash = (
            hash_graphical_password(
                selected
            )
        )


        # ----------------------------------------------------
        # FIND USER
        # ----------------------------------------------------

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


        # ----------------------------------------------------
        # VERIFY GRAPHICAL PASSWORD
        # ----------------------------------------------------

        graphical_valid = False


        if user is not None:

            graphical_valid = secrets.compare_digest(
                submitted_hash,
                user["graphical_password_hash"]
            )


        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        if graphical_valid:

            user_id = user["id"]
            user_name = user["name"]
            user_email = user["email"]


            # Completely clear temporary authentication data.
            session.clear()


            # Create authenticated session.
            session.permanent = True

            session["user_id"] = user_id

            session["user_name"] = user_name

            session["user_email"] = user_email

            session["authenticated"] = True


            # Generate fresh CAPTCHA for future use.
            create_captcha()


            return redirect(
                url_for("dashboard")
            )


        # ----------------------------------------------------
        # GRAPHICAL PASSWORD FAILED
        # ----------------------------------------------------

        increase_login_attempts()


        # Remove temporary login information.
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
            "graphical_characters",
            None
        )

        session.pop(
            "graphical_rotation",
            None
        )

        session.pop(
            "graphical_nonce",
            None
        )


        create_captcha()


        flash(
            "Incorrect graphical password. Authentication was cancelled.",
            "error"
        )


        return redirect(
            url_for("home")
            + "#login"
        )


    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    if (
        "graphical_characters"
        not in session
    ):

        create_graphical_state()


    return render_template(
        "graphical_password.html",
        mode="login"
    )


# ============================================================
# DASHBOARD
# ============================================================

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


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/logout"
)
def logout():

    session.clear()

    create_captcha()

    flash(
        "You have been securely logged out.",
        "success"
    )

    return redirect(
        url_for("home")
    )


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.after_request
def add_security_headers(response):

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "SAMEORIGIN"

    response.headers[
        "Referrer-Policy"
    ] = "strict-origin-when-cross-origin"

    response.headers[
        "Permissions-Policy"
    ] = (
        "camera=(), "
        "microphone=(), "
        "geolocation=()"
    )

    return response


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    init_database()

    # Create first CAPTCHA for the initial session.
    # If the user already has a session, Flask will retain it.
    if "captcha_question" not in session:
        create_captcha()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )
```
