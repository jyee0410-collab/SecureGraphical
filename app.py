、from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

import sqlite3
import random
import time
import os
import secrets

from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# FLASK CONFIGURATION
# ============================================================

app = Flask(__name__)

# Change this to a long random value for your own project
app.secret_key = "SecureGraphicalProject_2026_ChangeThisKey"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "securegraphical.db")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# ============================================================
# GRAPHICAL PASSWORD SYMBOLS
# ============================================================

GRAPHICAL_SYMBOLS = [
    {"id": "sun", "emoji": "☀️", "name": "Sun"},
    {"id": "moon", "emoji": "🌙", "name": "Moon"},
    {"id": "star", "emoji": "⭐", "name": "Star"},
    {"id": "heart", "emoji": "❤️", "name": "Heart"},
    {"id": "fire", "emoji": "🔥", "name": "Fire"},
    {"id": "flower", "emoji": "🌸", "name": "Flower"},
    {"id": "tree", "emoji": "🌳", "name": "Tree"},
    {"id": "cloud", "emoji": "☁️", "name": "Cloud"},
    {"id": "rainbow", "emoji": "🌈", "name": "Rainbow"},
    {"id": "apple", "emoji": "🍎", "name": "Apple"},
    {"id": "coffee", "emoji": "☕", "name": "Coffee"},
    {"id": "rocket", "emoji": "🚀", "name": "Rocket"},
    {"id": "lock", "emoji": "🔐", "name": "Lock"},
    {"id": "key", "emoji": "🔑", "name": "Key"},
    {"id": "diamond", "emoji": "💎", "name": "Diamond"},
    {"id": "crown", "emoji": "👑", "name": "Crown"},
    {"id": "camera", "emoji": "📷", "name": "Camera"},
    {"id": "music", "emoji": "🎵", "name": "Music"},
    {"id": "plane", "emoji": "✈️", "name": "Plane"},
    {"id": "car", "emoji": "🚗", "name": "Car"},
    {"id": "book", "emoji": "📚", "name": "Book"},
    {"id": "gift", "emoji": "🎁", "name": "Gift"},
    {"id": "bell", "emoji": "🔔", "name": "Bell"},
    {"id": "shield", "emoji": "🛡️", "name": "Shield"},
]


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            graphical_password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# CAPTCHA
# ============================================================

def generate_captcha():
    number1 = random.randint(1, 20)
    number2 = random.randint(1, 20)

    operations = [
        ("+", number1 + number2),
        ("-", number1 - number2),
        ("×", number1 * number2)
    ]

    operation, answer = random.choice(operations)

    session["captcha_answer"] = str(answer)

    return f"{number1} {operation} {number2} = ?"


def verify_captcha(user_answer):
    correct_answer = session.get("captcha_answer")

    if not correct_answer:
        return False

    return str(user_answer).strip() == str(correct_answer).strip()


# ============================================================
# GRAPHICAL PASSWORD
# ============================================================

def create_graphical_grid():
    """
    Create a random graphical password grid.

    The order is randomized every time to make
    shoulder surfing and fixed-position observation
    more difficult.
    """

    grid = GRAPHICAL_SYMBOLS.copy()
    random.shuffle(grid)

    return grid


def graphical_password_to_string(selection):
    """
    Convert selected graphical symbols into a consistent
    string representation.

    Example:
    sun|moon|star|heart
    """

    return "|".join(selection)


# ============================================================
# SECURITY / LOGIN ATTEMPT CONTROL
# ============================================================

LOGIN_MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def check_login_lock():
    locked_until = session.get("locked_until")

    if not locked_until:
        return False

    if time.time() < locked_until:
        return True

    session.pop("locked_until", None)
    session.pop("login_attempts", None)

    return False


def register_failed_login():

    attempts = session.get("login_attempts", 0)

    attempts += 1

    session["login_attempts"] = attempts

    if attempts >= LOGIN_MAX_ATTEMPTS:

        session["locked_until"] = time.time() + LOCKOUT_SECONDS

        return True

    return False


def clear_login_attempts():
    session.pop("login_attempts", None)
    session.pop("locked_until", None)


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():

    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    return render_template("index.html")


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":

        grid = create_graphical_grid()

        session["register_grid"] = [
            item["id"] for item in grid
        ]

        captcha_question = generate_captcha()

        return render_template(
            "graphical_password.html",
            mode="register",
            grid=grid,
            captcha_question=captcha_question
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    selected_symbols = request.form.get("graphical_password", "").strip()

    captcha_answer = request.form.get("captcha", "").strip()

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if not username:
        flash("Please enter a username.", "error")
        return redirect(url_for("register"))

    if len(username) < 3:
        flash("Username must contain at least 3 characters.", "error")
        return redirect(url_for("register"))

    if not password:
        flash("Please enter a password.", "error")
        return redirect(url_for("register"))

    if len(password) < 8:
        flash("Password must contain at least 8 characters.", "error")
        return redirect(url_for("register"))

    if not selected_symbols:
        flash("Please select your graphical password.", "error")
        return redirect(url_for("register"))

    selected_list = selected_symbols.split("|")

    if len(selected_list) < 3:
        flash(
            "Please select at least 3 graphical symbols.",
            "error"
        )
        return redirect(url_for("register"))

    if len(selected_list) > 6:
        flash(
            "You can select a maximum of 6 graphical symbols.",
            "error"
        )
        return redirect(url_for("register"))

    if not verify_captcha(captcha_answer):
        flash(
            "Security verification failed. Please try again.",
            "error"
        )
        return redirect(url_for("register"))

    # --------------------------------------------------------
    # Check username
    # --------------------------------------------------------

    conn = get_db()

    existing_user = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if existing_user:

        conn.close()

        flash(
            "Username already exists. Please choose another one.",
            "error"
        )

        return redirect(url_for("register"))

    # --------------------------------------------------------
    # Hash credentials
    # --------------------------------------------------------

    password_hash = generate_password_hash(password)

    graphical_string = graphical_password_to_string(
        selected_list
    )

    graphical_password_hash = generate_password_hash(
        graphical_string
    )

    # --------------------------------------------------------
    # Create user
    # --------------------------------------------------------

    conn.execute("""
        INSERT INTO users
        (
            username,
            password_hash,
            graphical_password_hash
        )
        VALUES (?, ?, ?)
    """, (
        username,
        password_hash,
        graphical_password_hash
    ))

    conn.commit()
    conn.close()

    session.pop("captcha_answer", None)

    flash(
        "Registration successful. Please login.",
        "success"
    )

    return redirect(url_for("index"))


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["POST"])
def login():

    if check_login_lock():

        remaining = int(
            session["locked_until"] - time.time()
        )

        flash(
            f"Too many failed attempts. "
            f"Please wait {max(remaining, 1)} seconds.",
            "error"
        )

        return redirect(url_for("index"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:

        flash(
            "Please enter your username and password.",
            "error"
        )

        return redirect(url_for("index"))

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

    if not user:

        locked = register_failed_login()

        if locked:
            flash(
                "Too many failed attempts. "
                "Account access is temporarily locked.",
                "error"
            )
        else:
            flash(
                "Invalid username or password.",
                "error"
            )

        return redirect(url_for("index"))

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        locked = register_failed_login()

        if locked:
            flash(
                "Too many failed attempts. "
                "Please wait before trying again.",
                "error"
            )
        else:
            flash(
                "Invalid username or password.",
                "error"
            )

        return redirect(url_for("index"))

    # --------------------------------------------------------
    # Normal password passed
    # --------------------------------------------------------

    session["pending_user_id"] = user["id"]
    session["pending_username"] = user["username"]

    # Generate a fresh graphical grid
    grid = create_graphical_grid()

    session["login_grid"] = [
        item["id"] for item in grid
    ]

    captcha_question = generate_captcha()

    return render_template(
        "graphical_password.html",
        mode="login",
        grid=grid,
        captcha_question=captcha_question,
        username=user["username"]
    )


# ============================================================
# GRAPHICAL PASSWORD VERIFICATION
# ============================================================

@app.route("/verify-graphical", methods=["POST"])
def verify_graphical():

    user_id = session.get("pending_user_id")

    if not user_id:

        flash(
            "Your login session has expired. Please login again.",
            "error"
        )

        return redirect(url_for("index"))

    selected_symbols = request.form.get(
        "graphical_password",
        ""
    ).strip()

    captcha_answer = request.form.get(
        "captcha",
        ""
    ).strip()

    # --------------------------------------------------------
    # CAPTCHA verification
    # --------------------------------------------------------

    if not verify_captcha(captcha_answer):

        session.pop("pending_user_id", None)
        session.pop("pending_username", None)

        locked = register_failed_login()

        if locked:
            flash(
                "Too many failed attempts. Please wait.",
                "error"
            )
        else:
            flash(
                "Security verification failed.",
                "error"
            )

        return redirect(url_for("index"))

    # --------------------------------------------------------
    # Graphical password validation
    # --------------------------------------------------------

    if not selected_symbols:

        flash(
            "Please select your graphical password.",
            "error"
        )

        return redirect(url_for("index"))

    selected_list = selected_symbols.split("|")

    if len(selected_list) < 3:

        flash(
            "Please select at least 3 symbols.",
            "error"
        )

        return redirect(url_for("index"))

    if len(selected_list) > 6:

        flash(
            "Please select no more than 6 symbols.",
            "error"
        )

        return redirect(url_for("index"))

    # --------------------------------------------------------
    # Retrieve user
    # --------------------------------------------------------

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:

        conn.close()

        session.clear()

        flash(
            "User account could not be found.",
            "error"
        )

        return redirect(url_for("index"))

    graphical_string = graphical_password_to_string(
        selected_list
    )

    graphical_valid = check_password_hash(
        user["graphical_password_hash"],
        graphical_string
    )

    if not graphical_valid:

        conn.close()

        session.pop("pending_user_id", None)
        session.pop("pending_username", None)

        locked = register_failed_login()

        if locked:
            flash(
                "Too many failed attempts. Please wait.",
                "error"
            )
        else:
            flash(
                "Incorrect graphical password.",
                "error"
            )

        return redirect(url_for("index"))

    # --------------------------------------------------------
    # Login successful
    # --------------------------------------------------------

    conn.execute("""
        UPDATE users
        SET last_login = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (user_id,))

    conn.commit()
    conn.close()

    username = user["username"]

    # Clear temporary authentication data
    session.pop("pending_user_id", None)
    session.pop("pending_username", None)
    session.pop("captcha_answer", None)

    clear_login_attempts()

    # Create authenticated session
    session["user_id"] = user_id
    session["username"] = username
    session["authenticated"] = True

    flash(
        "Authentication successful.",
        "success"
    )

    return redirect(url_for("dashboard"))


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if not session.get("authenticated"):
        flash(
            "Please login first.",
            "error"
        )

        return redirect(url_for("index"))

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    conn.close()

    if not user:

        session.clear()

        flash(
            "Your account could not be found.",
            "error"
        )

        return redirect(url_for("index"))

    return render_template(
        "dashboard.html",
        user=user
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out successfully.",
        "success"
    )

    return redirect(url_for("index"))


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return {
        "status": "online",
        "application": "SecureGraphical",
        "version": "2.0"
    }


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "index.html"
    ), 404


@app.errorhandler(500)
def internal_server_error(error):

    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Server Error</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f5f7fb;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                margin: 0;
            }

            .box {
                background: white;
                padding: 40px;
                border-radius: 20px;
                text-align: center;
                box-shadow: 0 10px 40px rgba(0,0,0,.08);
            }

            h1 {
                color: #172033;
            }

            p {
                color: #667085;
            }
        </style>
    </head>

    <body>

        <div class="box">

            <h1>Internal Server Error</h1>

            <p>
                Something went wrong on the server.
            </p>

            <p>
                Please check the Flask terminal for the error.
            </p>

        </div>

    </body>
    </html>
    """, 500


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    init_db()

    print("=" * 60)
    print(" SecureGraphical Security System")
    print("=" * 60)
    print()
    print(" Local access:")
    print(" http://127.0.0.1:5000")
    print()
    print(" Network access:")
    print(" http://YOUR-COMPUTER-IP:5000")
    print()
    print(" Application is running...")
    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
