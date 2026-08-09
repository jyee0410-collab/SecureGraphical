import os
import sqlite3
import random
import string
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "secure-graphical-password-development-key-change-this"
)

# Render / production port
PORT = int(os.environ.get("PORT", 5000))

# SQLite database
DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "users.db"
)

# Security settings
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

# 8 colours
COLORS = [
    {
        "name": "Red",
        "hex": "#ef4444"
    },
    {
        "name": "Blue",
        "hex": "#3b82f6"
    },
    {
        "name": "Green",
        "hex": "#22c55e"
    },
    {
        "name": "Yellow",
        "hex": "#eab308"
    },
    {
        "name": "Purple",
        "hex": "#a855f7"
    },
    {
        "name": "Orange",
        "hex": "#f97316"
    },
    {
        "name": "Pink",
        "hex": "#ec4899"
    },
    {
        "name": "Cyan",
        "hex": "#06b6d4"
    }
]

# 16 graphical characters
GRAPHICAL_CHARS = list("abcdefgh12345678")


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            graphical_password_hash TEXT NOT NULL,
            pass_color TEXT NOT NULL,
            created_at TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            success INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            ip_address TEXT
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# CAPTCHA
# ============================================================

def generate_captcha():
    """
    Generate a simple mathematical CAPTCHA.
    Example:
        7 + 3 = ?
    """

    number1 = random.randint(1, 9)
    number2 = random.randint(1, 9)

    operators = ["+", "-", "*"]
    operator = random.choice(operators)

    if operator == "+":
        answer = number1 + number2

    elif operator == "-":
        # Avoid negative answers
        if number2 > number1:
            number1, number2 = number2, number1

        answer = number1 - number2

    else:
        answer = number1 * number2

    question = f"{number1} {operator} {number2}"

    session["captcha_answer"] = str(answer)

    return question


def verify_captcha(user_answer):
    correct_answer = session.get("captcha_answer")

    if not correct_answer:
        return False

    return str(user_answer).strip() == str(correct_answer).strip()


# ============================================================
# GRAPHICAL PASSWORD
# ============================================================

def create_graphical_grid():

    characters = GRAPHICAL_CHARS.copy()
    random.shuffle(characters)

    # Random rotation
    rotation = random.choice([0, 90, 180, 270])

    # Random sector
    sector = random.randint(1, 4)

    # Random colour mapping
    color_list = COLORS.copy()
    random.shuffle(color_list)

    grid = []

    for index, char in enumerate(characters):

        color = color_list[index % len(color_list)]

        grid.append({
            "char": char,
            "color": color["name"],
            "hex": color["hex"],
            "position": index + 1
        })

    return {
        "grid": grid,
        "rotation": rotation,
        "sector": sector
    }


def hash_graphical_password(sequence, pass_color):

    raw_value = (
        sequence +
        "|" +
        pass_color +
        "|" +
        app.secret_key
    )

    return hashlib.sha256(
        raw_value.encode("utf-8")
    ).hexdigest()


# ============================================================
# LOGIN LOCKOUT
# ============================================================

def is_account_locked(user):

    locked_until = user["locked_until"]

    if not locked_until:
        return False

    try:
        locked_time = datetime.fromisoformat(locked_until)
    except Exception:
        return False

    if datetime.utcnow() < locked_time:
        return True

    # Lockout expired
    conn = get_db()

    conn.execute("""
        UPDATE users
        SET failed_attempts = 0,
            locked_until = NULL
        WHERE username = ?
    """, (user["username"],))

    conn.commit()
    conn.close()

    return False


def register_failed_attempt(username):

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not user:
        conn.close()
        return

    failed_attempts = user["failed_attempts"] + 1

    locked_until = None

    if failed_attempts >= MAX_LOGIN_ATTEMPTS:

        locked_until = (
            datetime.utcnow() +
            timedelta(minutes=LOCKOUT_MINUTES)
        ).isoformat()

        failed_attempts = 0

    conn.execute("""
        UPDATE users
        SET failed_attempts = ?,
            locked_until = ?
        WHERE username = ?
    """, (
        failed_attempts,
        locked_until,
        username
    ))

    conn.commit()
    conn.close()


def reset_failed_attempts(username):

    conn = get_db()

    conn.execute("""
        UPDATE users
        SET failed_attempts = 0,
            locked_until = NULL
        WHERE username = ?
    """, (username,))

    conn.commit()
    conn.close()


# ============================================================
# LOGIN HISTORY
# ============================================================

def save_login_history(username, success):

    ip_address = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr
    )

    if ip_address and "," in ip_address:
        ip_address = ip_address.split(",")[0].strip()

    conn = get_db()

    conn.execute("""
        INSERT INTO login_history
        (
            username,
            success,
            timestamp,
            ip_address
        )
        VALUES (?, ?, ?, ?)
    """, (
        username,
        1 if success else 0,
        datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        ip_address
    ))

    conn.commit()
    conn.close()


# ============================================================
# AUTH DECORATOR
# ============================================================

def login_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            flash(
                "Please login first.",
                "warning"
            )

            return redirect(
                url_for("index")
            )

        return function(*args, **kwargs)

    return decorated_function


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():

    captcha_question = generate_captcha()

    return render_template(
        "index.html",
        captcha_question=captcha_question
    )


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    captcha_question = generate_captcha()

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        ).strip()

        captcha = request.form.get(
            "captcha",
            ""
        ).strip()

        sequence = request.form.get(
            "graphical_sequence",
            ""
        ).strip()

        pass_color = request.form.get(
            "pass_color",
            ""
        ).strip()

        # --------------------------------
        # Basic validation
        # --------------------------------

        if not username or not password:

            flash(
                "Username and password are required.",
                "danger"
            )

            return render_template(
                "index.html",
                captcha_question=captcha_question
            )

        # --------------------------------
        # CAPTCHA
        # --------------------------------

        if not verify_captcha(captcha):

            flash(
                "Security verification failed. Please solve the CAPTCHA again.",
                "danger"
            )

            captcha_question = generate_captcha()

            return render_template(
                "index.html",
                captcha_question=captcha_question
            )

        # --------------------------------
        # Graphical password validation
        # --------------------------------

        if not sequence:

            flash(
                "Please create your graphical password.",
                "danger"
            )

            captcha_question = generate_captcha()

            return render_template(
                "index.html",
                captcha_question=captcha_question
            )

        selected_chars = sequence.split(",")

        if len(selected_chars) != 3:

            flash(
                "Please select exactly 3 graphical characters.",
                "danger"
            )

            captcha_question = generate_captcha()

            return render_template(
                "index.html",
                captcha_question=captcha_question
            )

        if not pass_color:

            flash(
                "Please select a pass colour.",
                "danger"
            )

            captcha_question = generate_captcha()

            return render_template(
                "index.html",
                captcha_question=captcha_question
            )

        # --------------------------------
        # Check duplicate username
        # --------------------------------

        conn = get_db()

        existing_user = conn.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if existing_user:

            conn.close()

            flash(
                "Username already exists.",
                "danger"
            )

            captcha_question = generate_captcha()

            return render_template(
                "index.html",
                captcha_question=captcha_question
            )

        # --------------------------------
        # Hash passwords
        # --------------------------------

        normal_password_hash = generate_password_hash(
            password
        )

        graphical_hash = hash_graphical_password(
            sequence,
            pass_color
        )

        # --------------------------------
        # Create account
        # --------------------------------

        conn.execute("""
            INSERT INTO users
            (
                username,
                password_hash,
                graphical_password_hash,
                pass_color,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            username,
            normal_password_hash,
            graphical_hash,
            pass_color,
            datetime.utcnow().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        ))

        conn.commit()
        conn.close()

        flash(
            "Registration successful. You can now login.",
            "success"
        )

        return redirect(
            url_for("index")
        )

    return render_template(
        "index.html",
        captcha_question=captcha_question
    )


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["POST"])
def login():

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    ).strip()

    captcha = request.form.get(
        "captcha",
        ""
    ).strip()

    sequence = request.form.get(
        "graphical_sequence",
        ""
    ).strip()

    pass_color = request.form.get(
        "pass_color",
        ""
    ).strip()

    # --------------------------------
    # CAPTCHA
    # --------------------------------

    if not verify_captcha(captcha):

        save_login_history(
            username,
            False
        )

        flash(
            "Security verification failed.",
            "danger"
        )

        return redirect(
            url_for("index")
        )

    # --------------------------------
    # Find user
    # --------------------------------

    conn = get_db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    conn.close()

    if not user:

        save_login_history(
            username,
            False
        )

        flash(
            "Invalid username or password.",
            "danger"
        )

        return redirect(
            url_for("index")
        )

    # --------------------------------
    # Check lockout
    # --------------------------------

    if is_account_locked(user):

        save_login_history(
            username,
            False
        )

        flash(
            f"Account temporarily locked. Please try again in {LOCKOUT_MINUTES} minutes.",
            "danger"
        )

        return redirect(
            url_for("index")
        )

    # --------------------------------
    # Normal password
    # --------------------------------

    normal_password_valid = check_password_hash(
        user["password_hash"],
        password
    )

    # --------------------------------
    # Graphical password
    # --------------------------------

    graphical_password_valid = False

    if sequence and pass_color:

        submitted_graphical_hash = hash_graphical_password(
            sequence,
            pass_color
        )

        graphical_password_valid = (
            submitted_graphical_hash ==
            user["graphical_password_hash"]
        )

    # --------------------------------
    # Final authentication
    # --------------------------------

    if (
        normal_password_valid and
        graphical_password_valid
    ):

        reset_failed_attempts(
            username
        )

        save_login_history(
            username,
            True
        )

        session.clear()

        session["user_id"] = user["id"]
        session["username"] = user["username"]

        return redirect(
            url_for("dashboard")
        )

    # --------------------------------
    # Failed login
    # --------------------------------

    register_failed_attempt(
        username
    )

    save_login_history(
        username,
        False
    )

    flash(
        "Invalid login credentials or graphical password.",
        "danger"
    )

    return redirect(
        url_for("index")
    )


# ============================================================
# GRAPHICAL PASSWORD API
# ============================================================

@app.route("/generate-grid")
def generate_grid():

    grid_data = create_graphical_grid()

    return jsonify(
        grid_data
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    username = session.get(
        "username"
    )

    conn = get_db()

    user = conn.execute(
        """
        SELECT
            username,
            created_at
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    history = conn.execute(
        """
        SELECT
            success,
            timestamp,
            ip_address
        FROM login_history
        WHERE username = ?
        ORDER BY id DESC
        LIMIT 10
        """,
        (username,)
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        user=user,
        history=history
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("index")
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "application": "SecureGraphical"
    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    return """
    <h1>404 - Page Not Found</h1>
    <p>The requested page does not exist.</p>
    """, 404


@app.errorhandler(500)
def internal_server_error(error):

    return """
    <h1>500 - Internal Server Error</h1>
    <p>Please check the application logs.</p>
    """, 500


# ============================================================
# START APPLICATION
# ============================================================

init_db()


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False
    )
