import os
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "securegraphical.db")

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-before-deployment"
)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

CHARACTERS = list("abcdefgh12345678")
COLORS = [
    {"name": "Red", "hex": "#ef4444"},
    {"name": "Blue", "hex": "#3b82f6"},
    {"name": "Green", "hex": "#22c55e"},
    {"name": "Yellow", "hex": "#eab308"},
    {"name": "Purple", "hex": "#8b5cf6"},
    {"name": "Orange", "hex": "#f97316"},
    {"name": "Pink", "hex": "#ec4899"},
    {"name": "Cyan", "hex": "#06b6d4"},
]
COLOR_NAMES = {c["name"] for c in COLORS}
MAX_ATTEMPTS = 5
LOCK_MINUTES = 10
GRAPHICAL_TIMEOUT_MINUTES = 10


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def utc_now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat() if dt else None


def init_db():
    conn = db()
    users_exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()

    if users_exists:
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        # The uploaded old database used a different schema. Preserve it instead
        # of silently mixing it with the new application schema.
        if "username" not in columns or "pass_color" not in columns:
            conn.execute("ALTER TABLE users RENAME TO users_legacy")
            old_history = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='login_history'"
            ).fetchone()
            if old_history:
                conn.execute("ALTER TABLE login_history RENAME TO login_history_legacy")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_length INTEGER NOT NULL,
            pass_color TEXT NOT NULL,
            email TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            success INTEGER NOT NULL,
            reason TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )
    conn.commit()
    conn.close()


def current_year():
    return utc_now().year


@app.context_processor
def inject_globals():
    return {"current_year": current_year()}


def is_locked(user):
    value = user["locked_until"]
    if not value:
        return False
    try:
        return utc_now() < datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return False


def log_attempt(user_id, username, success, reason):
    conn = db()
    conn.execute(
        """
        INSERT INTO login_history
        (user_id, username, success, reason, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            username,
            int(success),
            reason,
            request.headers.get("X-Forwarded-For", request.remote_addr),
            iso(utc_now()),
        ),
    )
    conn.commit()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("index"))
        return view(*args, **kwargs)
    return wrapped


def generate_captcha():
    a = random.randint(2, 12)
    b = random.randint(2, 12)
    operation = random.choice(["+", "-", "×"])
    if operation == "+":
        answer = a + b
    elif operation == "-":
        if b > a:
            a, b = b, a
        answer = a - b
    else:
        answer = a * b
    session["captcha_answer"] = str(answer)
    session["captcha_question"] = f"{a} {operation} {b} = ?"


def new_circle():
    shuffled = CHARACTERS[:]
    random.shuffle(shuffled)
    sectors = [[] for _ in range(8)]
    for index, character in enumerate(shuffled):
        sectors[index % 8].append(character)
    return {
        "sectors": sectors,
        "rotation": 0,
        "selected": [],
        "started_at": iso(utc_now()),
    }


def graphical_session_valid():
    started = session.get("graphical_started_at")
    if not started:
        return False
    try:
        return utc_now() - datetime.fromisoformat(started) < timedelta(minutes=GRAPHICAL_TIMEOUT_MINUTES)
    except (ValueError, TypeError):
        return False


def rotate_state(direction):
    state = session.get("circle")
    if not state:
        return None
    if direction == "clockwise":
        state["sectors"] = [state["sectors"][-1]] + state["sectors"][:-1]
        state["rotation"] = (state["rotation"] + 1) % 8
    elif direction == "anticlockwise":
        state["sectors"] = state["sectors"][1:] + [state["sectors"][0]]
        state["rotation"] = (state["rotation"] - 1) % 8
    session["circle"] = state
    session.modified = True
    return state


def validate_password_format(password):
    return 4 <= len(password) <= 8 and all(c in CHARACTERS for c in password)


def clear_graphical_session():
    for key in [
        "pending_user_id",
        "pending_username",
        "circle",
        "captcha_answer",
        "captcha_question",
        "graphical_started_at",
    ]:
        session.pop(key, None)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        pass_color = request.form.get("pass_color", "")

        if not 3 <= len(username) <= 40:
            flash("Username must be 3–40 characters.", "danger")
            return render_template("register.html", colors=COLORS, characters=CHARACTERS)
        if not validate_password_format(password):
            flash("Password must be 4–8 characters and use only a–h and 1–8.", "danger")
            return render_template("register.html", colors=COLORS, characters=CHARACTERS)
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", colors=COLORS, characters=CHARACTERS)
        if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
            flash("Please enter a valid recovery email.", "danger")
            return render_template("register.html", colors=COLORS, characters=CHARACTERS)
        if pass_color not in COLOR_NAMES:
            flash("Please choose one pass-colour.", "danger")
            return render_template("register.html", colors=COLORS, characters=CHARACTERS)

        conn = db()
        try:
            conn.execute(
                """
                INSERT INTO users
                (username, password_hash, password_length, pass_color, email, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    generate_password_hash(password),
                    len(password),
                    pass_color,
                    email,
                    iso(utc_now()),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("That username already exists.", "danger")
            return render_template("register.html", colors=COLORS, characters=CHARACTERS)
        conn.close()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("index"))

    return render_template("register.html", colors=COLORS, characters=CHARACTERS)


@app.route("/login/start", methods=["POST"])
def login_start():
    username = request.form.get("username", "").strip()
    if not username:
        flash("Please enter your username.", "danger")
        return redirect(url_for("index"))

    conn = db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if not user:
        log_attempt(None, username, False, "unknown username")
        flash("Unable to start authentication.", "danger")
        return redirect(url_for("index"))

    if is_locked(user):
        flash("Account is temporarily locked. Use account recovery or try again later.", "danger")
        return redirect(url_for("index"))

    session.clear()
    session["pending_user_id"] = user["id"]
    session["pending_username"] = user["username"]
    session["circle"] = new_circle()
    session["graphical_started_at"] = iso(utc_now())
    generate_captcha()
    return redirect(url_for("graphical_login"))


@app.route("/graphical-login")
def graphical_login():
    if not session.get("pending_user_id") or not graphical_session_valid():
        clear_graphical_session()
        flash("Your graphical login session has expired. Please start again.", "warning")
        return redirect(url_for("index"))

    conn = db()
    user = conn.execute(
        "SELECT id, username, password_length FROM users WHERE id = ?",
        (session["pending_user_id"],),
    ).fetchone()
    conn.close()

    if not user:
        clear_graphical_session()
        flash("Login session expired.", "danger")
        return redirect(url_for("index"))

    return render_template(
        "graphical_password.html",
        user=user,
        colors=COLORS,
        circle=session["circle"],
        captcha_question=session.get("captcha_question"),
    )


@app.route("/api/rotate", methods=["POST"])
def api_rotate():
    if not session.get("pending_user_id") or not graphical_session_valid():
        return jsonify(ok=False, message="Login session expired."), 401
    data = request.get_json(silent=True) or {}
    direction = data.get("direction")
    if direction not in {"clockwise", "anticlockwise"}:
        return jsonify(ok=False, message="Invalid rotation direction."), 400
    state = rotate_state(direction)
    return jsonify(ok=True, sectors=state["sectors"], rotation=state["rotation"])


@app.route("/api/select-character", methods=["POST"])
def api_select_character():
    if not session.get("pending_user_id") or not graphical_session_valid():
        return jsonify(ok=False, message="Login session expired."), 401

    data = request.get_json(silent=True) or {}
    character = data.get("character", "")
    if character not in CHARACTERS:
        return jsonify(ok=False, message="Invalid character."), 400

    state = session.get("circle")
    if not state:
        return jsonify(ok=False, message="Graphical login session expired."), 400

    conn = db()
    user = conn.execute(
        "SELECT password_hash, password_length, pass_color FROM users WHERE id = ?",
        (session["pending_user_id"],),
    ).fetchone()
    conn.close()
    if not user:
        return jsonify(ok=False, message="User not found."), 404

    pass_color_index = next(
        (i for i, color in enumerate(COLORS) if color["name"] == user["pass_color"]),
        None,
    )
    if pass_color_index is None:
        return jsonify(ok=False, message="Invalid pass-colour configuration."), 400

    pass_sector = state["sectors"][pass_color_index]
    if character not in pass_sector:
        return jsonify(ok=False, message="That character is not in your pass-colour sector."), 400

    selected = state["selected"]
    if len(selected) >= user["password_length"]:
        return jsonify(ok=False, message="Graphical password is already complete."), 400

    # Do not reveal the expected password character to the browser.
    # The server validates the submitted character position-by-position.
    target_length = user["password_length"]

    # Store only the selected sequence in the session temporarily.
    # It is not displayed back to the user.
    selected.append(character)
    state["selected"] = selected
    session["circle"] = state
    session.modified = True

    complete = len(selected) == target_length
    return jsonify(ok=True, selected_count=len(selected), target_length=target_length, complete=complete)


@app.route("/verify-graphical", methods=["POST"])
def verify_graphical():
    if not session.get("pending_user_id") or not graphical_session_valid():
        clear_graphical_session()
        flash("Your graphical login session has expired. Please start again.", "warning")
        return redirect(url_for("index"))

    user_id = session["pending_user_id"]
    captcha = request.form.get("captcha", "").strip()
    selected = session.get("circle", {}).get("selected", [])
    graphical_sequence = "".join(selected)

    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if not user:
        clear_graphical_session()
        flash("User account could not be found.", "danger")
        return redirect(url_for("index"))

    if len(selected) != user["password_length"]:
        flash("Complete the graphical password first.", "danger")
        return redirect(url_for("graphical_login"))

    captcha_ok = captcha == session.get("captcha_answer")
    password_ok = check_password_hash(user["password_hash"], graphical_sequence)

    if not captcha_ok or not password_ok:
        attempts = user["failed_attempts"] + 1
        locked_until = None
        if attempts >= MAX_ATTEMPTS:
            locked_until = iso(utc_now() + timedelta(minutes=LOCK_MINUTES))
            attempts = 0

        conn = db()
        conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (attempts, locked_until, user_id),
        )
        conn.commit()
        conn.close()

        reason = "captcha failed" if not captcha_ok else "graphical password failed"
        log_attempt(user_id, user["username"], False, reason)

        if locked_until:
            clear_graphical_session()
            flash(f"Too many failed attempts. Account locked for {LOCK_MINUTES} minutes.", "danger")
            return redirect(url_for("index"))

        generate_captcha()
        flash("Authentication failed. Please try the graphical password again.", "danger")
        # Regenerate the graphical challenge after a failed verification.
        session["circle"] = new_circle()
        session["graphical_started_at"] = iso(utc_now())
        return redirect(url_for("graphical_login"))

    conn = db()
    conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (user_id,),
    )
    conn.commit()
    conn.close()

    log_attempt(user_id, user["username"], True, "authentication successful")

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    flash("Authentication successful. Welcome back.", "success")
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    history = conn.execute(
        """
        SELECT success, reason, created_at
        FROM login_history
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 8
        """,
        (session["user_id"],),
    ).fetchall()
    conn.close()
    if not user:
        session.clear()
        return redirect(url_for("index"))
    return render_template("dashboard.html", user=user, history=history, colors=COLORS)


@app.route("/settings")
@login_required
def settings():
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    if not user:
        session.clear()
        return redirect(url_for("index"))
    return render_template("settings.html", user=user, colors=COLORS)


@app.route("/recovery", methods=["GET", "POST"])
def recovery():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        conn = db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND email = ?",
            (username, email),
        ).fetchone()
        if user:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )
            conn.commit()
        conn.close()

        # Do not reveal whether an account exists.
        flash("If the registered details matched, the account has been re-enabled.", "success")
        return redirect(url_for("index"))

    return render_template("recovery.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=True)
