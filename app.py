import os
import random
import secrets
import sqlite3
import string
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, flash, jsonify, redirect, render_template,
    request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "securegraphical.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-in-production")

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
MAX_ATTEMPTS = 5
LOCK_MINUTES = 10


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
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
    """)
    conn.commit()
    conn.close()


def utc_now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat() if dt else None


def is_locked(user):
    if not user["locked_until"]:
        return False
    try:
        return utc_now() < datetime.fromisoformat(user["locked_until"])
    except ValueError:
        return False


def log_attempt(user_id, username, success, reason):
    conn = db()
    conn.execute(
        """INSERT INTO login_history
           (user_id, username, success, reason, ip_address, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
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
    op = random.choice(["+", "-", "×"])
    if op == "+":
        answer = a + b
    elif op == "-":
        if b > a:
            a, b = b, a
        answer = a - b
    else:
        answer = a * b
    session["captcha_answer"] = str(answer)
    session["captcha_question"] = f"{a} {op} {b} = ?"


def new_circle():
    shuffled = CHARACTERS[:]
    random.shuffle(shuffled)
    sectors = [[] for _ in range(8)]
    for i, ch in enumerate(shuffled):
        sectors[i % 8].append(ch)

    return {
        "sectors": sectors,
        "rotation": 0,
        "selected": [],
        "round": 0,
        "started_at": iso(utc_now()),
    }


def rotate_state(direction):
    state = session.get("circle")
    if not state:
        return

    if direction == "clockwise":
        # Every character moves to the next sector.
        state["sectors"] = [state["sectors"][-1]] + state["sectors"][:-1]
        state["rotation"] = (state["rotation"] + 1) % 8
    else:
        # Every character moves to the previous sector.
        state["sectors"] = state["sectors"][1:] + [state["sectors"][0]]
        state["rotation"] = (state["rotation"] - 1) % 8

    session["circle"] = state
    session.modified = True


def validate_password_format(password):
    return (
        4 <= len(password) <= 8
        and all(ch in CHARACTERS for ch in password)
    )


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        email = request.form.get("email", "").strip()
        pass_color = request.form.get("pass_color", "")

        if not username or len(username) < 3:
            flash("Username must contain at least 3 characters.", "danger")
            return render_template("register.html", colors=COLORS)

        if not validate_password_format(password):
            flash(
                "Password must be 4–8 characters and use only a–h and 1–8.",
                "danger",
            )
            return render_template("register.html", colors=COLORS)

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", colors=COLORS)

        if "@" not in email or "." not in email.split("@")[-1]:
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html", colors=COLORS)

        if pass_color not in [c["name"] for c in COLORS]:
            flash("Please choose one pass-colour.", "danger")
            return render_template("register.html", colors=COLORS)

        conn = db()
        try:
            conn.execute(
                """INSERT INTO users
                   (username, password_hash, pass_color, email, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    username,
                    generate_password_hash(password),
                    pass_color,
                    email,
                    iso(utc_now()),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("That username already exists.", "danger")
            return render_template("register.html", colors=COLORS)
        conn.close()

        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("index"))

    return render_template("register.html", colors=COLORS)


@app.route("/login/start", methods=["POST"])
def login_start():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if not user:
        log_attempt(None, username, False, "unknown username")
        flash("Invalid username or password.", "danger")
        return redirect(url_for("index"))

    if is_locked(user):
        until = datetime.fromisoformat(user["locked_until"]).astimezone()
        flash(
            f"Account is temporarily locked until {until.strftime('%H:%M:%S')}.",
            "danger",
        )
        return redirect(url_for("index"))

    if not check_password_hash(user["password_hash"], password):
        attempts = user["failed_attempts"] + 1
        locked_until = None
        if attempts >= MAX_ATTEMPTS:
            locked_until = iso(utc_now() + timedelta(minutes=LOCK_MINUTES))
            attempts = 0

        conn = db()
        conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (attempts, locked_until, user["id"]),
        )
        conn.commit()
        conn.close()

        log_attempt(user["id"], username, False, "text password failed")

        if locked_until:
            flash(
                f"Too many failed attempts. Account locked for {LOCK_MINUTES} minutes.",
                "danger",
            )
        else:
            remaining = MAX_ATTEMPTS - attempts
            flash(
                f"Invalid username or password. {remaining} attempt(s) remaining.",
                "danger",
            )
        return redirect(url_for("index"))

    session.clear()
    session["pending_user_id"] = user["id"]
    session["pending_username"] = user["username"]
    session["pending_password"] = password
    session["circle"] = new_circle()
    generate_captcha()
    return redirect(url_for("graphical_login"))


@app.route("/graphical-login")
def graphical_login():
    if not session.get("pending_user_id"):
        flash("Start the login process first.", "warning")
        return redirect(url_for("index"))

    conn = db()
    user = conn.execute(
        "SELECT id, username, pass_color FROM users WHERE id = ?",
        (session["pending_user_id"],),
    ).fetchone()
    conn.close()

    if not user:
        session.clear()
        flash("Login session expired.", "danger")
        return redirect(url_for("index"))

    circle = session.get("circle")
    return render_template(
        "graphical_password.html",
        user=user,
        colors=COLORS,
        circle=circle,
        captcha_question=session.get("captcha_question"),
        selected="".join(circle.get("selected", [])),
    )


@app.route("/api/rotate", methods=["POST"])
def api_rotate():
    if not session.get("pending_user_id"):
        return jsonify({"ok": False, "message": "Login session expired."}), 401

    direction = request.json.get("direction")
    if direction not in ("clockwise", "anticlockwise"):
        return jsonify({"ok": False, "message": "Invalid direction."}), 400

    rotate_state(direction)
    state = session["circle"]
    return jsonify({"ok": True, "sectors": state["sectors"], "rotation": state["rotation"]})


@app.route("/api/select-character", methods=["POST"])
def api_select_character():
    if not session.get("pending_user_id"):
        return jsonify({"ok": False, "message": "Login session expired."}), 401

    char = request.json.get("character", "")
    state = session.get("circle")

    if not state or char not in CHARACTERS:
        return jsonify({"ok": False, "message": "Invalid character."}), 400

    # Pass-colour is the sector at index 0.
    selected_sector = state["sectors"][0]
    if char not in selected_sector:
        return jsonify({
            "ok": False,
            "message": "Select a character currently inside your pass-colour sector."
        }), 400

    state["selected"].append(char)
    session["circle"] = state
    session.modified = True

    target = session.get("pending_password", "")
    complete = len(state["selected"]) == len(target)

    return jsonify({
        "ok": True,
        "selected": state["selected"],
        "complete": complete,
        "message": "Character accepted." if not complete else "Graphical password completed."
    })


@app.route("/verify-graphical", methods=["POST"])
def verify_graphical():
    if not session.get("pending_user_id"):
        flash("Login session expired.", "warning")
        return redirect(url_for("index"))

    captcha = request.form.get("captcha", "").strip()
    user_id = session["pending_user_id"]
    username = session["pending_username"]
    target = session.get("pending_password", "")
    state = session.get("circle", {})
    selected = "".join(state.get("selected", []))

    if captcha != session.get("captcha_answer"):
        log_attempt(user_id, username, False, "CAPTCHA failed")
        generate_captcha()
        flash("Security verification failed.", "danger")
        return redirect(url_for("graphical_login"))

    if selected != target:
        log_attempt(user_id, username, False, "graphical password failed")
        generate_captcha()
        flash("Graphical password sequence is incorrect.", "danger")
        return redirect(url_for("graphical_login"))

    conn = db()
    conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (user_id,),
    )
    conn.commit()
    conn.close()

    log_attempt(user_id, username, True, "successful authentication")

    session.clear()
    session["user_id"] = user_id
    session["username"] = username
    flash("Authentication successful. Welcome back!", "success")
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    history = conn.execute(
        """SELECT success, reason, created_at
           FROM login_history
           WHERE user_id = ?
           ORDER BY id DESC LIMIT 10""",
        (session["user_id"],),
    ).fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        user=user,
        history=history,
        max_attempts=MAX_ATTEMPTS,
    )


@app.route("/recovery", methods=["GET", "POST"])
def recovery():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()

        conn = db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND email = ?",
            (username, email),
        ).fetchone()

        if user:
            # Demo-friendly recovery: clear lock and failed-attempt counter.
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )
            conn.commit()
            conn.close()
            flash(
                "Identity verified. Your account has been re-enabled. "
                "For a production deployment, connect this step to a real email OTP.",
                "success",
            )
        else:
            conn.close()
            flash("Username and recovery email do not match.", "danger")

        return redirect(url_for("index"))

    return render_template("recovery.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.context_processor
def inject_helpers():
    return {
        "current_year": datetime.now().year,
        "colors": COLORS,
    }


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
