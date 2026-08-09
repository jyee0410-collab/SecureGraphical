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
import os

from functools import wraps
from datetime import datetime, timedelta

# =========================================================

# APPLICATION

# =========================================================

app = Flask(**name**)

# =========================================================

# SECRET KEY

# =========================================================

app.secret_key = os.environ.get(
"SECRET_KEY",
"SecureGraphical-Development-Key-2026"
)

# =========================================================

# DATABASE

# =========================================================

DATABASE = "securegraphical.db"

def get_db():

```
db = sqlite3.connect(DATABASE)

db.row_factory = sqlite3.Row

return db
```

def init_database():

```
db = get_db()

# -----------------------------------------------------
# USERS TABLE
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

        locked_until TEXT,

        created_at TIMESTAMP
            DEFAULT CURRENT_TIMESTAMP
    )
""")

# -----------------------------------------------------
# AUTHENTICATION HISTORY TABLE
# -----------------------------------------------------

db.execute("""
    CREATE TABLE IF NOT EXISTS auth_history (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER,

        email TEXT,

        event_type TEXT NOT NULL,

        status TEXT NOT NULL,

        created_at TIMESTAMP
            DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY(user_id)
            REFERENCES users(id)
    )
""")

db.commit()

db.close()
```

# =========================================================

# CONSTANTS

# =========================================================

GRAPHICAL_CHARACTERS = list(
"abcdefgh12345678"
)

PASS_COLORS = [
"red",
"orange",
"yellow",
"green",
"blue",
"indigo",
"purple",
"pink"
]

MAX_FAILED_ATTEMPTS = 5

LOCKOUT_MINUTES = 5

# =========================================================

# CAPTCHA

# =========================================================

def create_login_captcha():

```
number1 = random.randint(1, 9)

number2 = random.randint(1, 9)

session["login_captcha_question"] = (
    f"{number1} + {number2} = ?"
)

session["login_captcha_answer"] = str(
    number1 + number2
)
```

def create_register_captcha():

```
number1 = random.randint(1, 9)

number2 = random.randint(1, 9)

session["register_captcha_question"] = (
    f"{number1} + {number2} = ?"
)

session["register_captcha_answer"] = str(
    number1 + number2
)
```

def validate_login_captcha(answer):

```
correct_answer = session.get(
    "login_captcha_answer"
)

if correct_answer is None:

    return False

return (
    answer.strip()
    == str(correct_answer)
)
```

def validate_register_captcha(answer):

```
correct_answer = session.get(
    "register_captcha_answer"
)

if correct_answer is None:

    return False

return (
    answer.strip()
    == str(correct_answer)
)
```

# =========================================================

# PASSWORD STRENGTH

# =========================================================

def password_strength(password):

```
score = 0

if len(password) >= 4:
    score += 1

if len(password) >= 6:
    score += 1

if any(
    char.islower()
    for char in password
):
    score += 1

if any(
    char.isdigit()
    for char in password
):
    score += 1

if score <= 1:

    return "Weak"

elif score == 2:

    return "Medium"

elif score == 3:

    return "Strong"

return "Very Strong"
```

# =========================================================

# PASSWORD VALIDATION

# =========================================================

def validate_password(password):

```
errors = []

if len(password) < 4:

    errors.append(
        "Password must contain at least 4 characters."
    )

if len(password) > 8:

    errors.append(
        "Password cannot exceed 8 characters."
    )

if not any(
    char.islower()
    for char in password
):

    errors.append(
        "Password must contain at least one lowercase letter."
    )

if not any(
    char.isdigit()
    for char in password
):

    errors.append(
        "Password must contain at least one number."
    )

return errors
```

# =========================================================

# GRAPHICAL PASSWORD HASH

# =========================================================

def hash_graphical_password(
sequence,
pass_color
):

```
sequence_text = "-".join(
    sequence
)

combined = (
    pass_color
    + "|"
    + sequence_text
)

return hashlib.sha256(
    combined.encode("utf-8")
).hexdigest()
```

# =========================================================

# AUTHENTICATION HISTORY

# =========================================================

def record_auth_event(
user_id,
email,
event_type,
status
):

```
db = get_db()

db.execute(
    """
    INSERT INTO auth_history
    (
        user_id,
        email,
        event_type,
        status
    )
    VALUES (?, ?, ?, ?)
    """,
    (
        user_id,
        email,
        event_type,
        status
    )
)

db.commit()

db.close()
```

# =========================================================

# LOGIN REQUIRED DECORATOR

# =========================================================

def login_required(function):

```
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
```

# =========================================================

# HOME

# =========================================================

@app.route("/")
def home():

```
# Create Login CAPTCHA if missing

if (
    "login_captcha_question"
    not in session
):

    create_login_captcha()


# Create Register CAPTCHA if missing

if (
    "register_captcha_question"
    not in session
):

    create_register_captcha()


return render_template(
    "index.html",

    login_captcha_question=session.get(
        "login_captcha_question"
    ),

    register_captcha_question=session.get(
        "register_captcha_question"
    )
)
```

# =========================================================

# REGISTER

# =========================================================

@app.route(
"/register",
methods=["POST"]
)
def register():

```
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


# -----------------------------------------------------
# REGISTER CAPTCHA
# -----------------------------------------------------

if not validate_register_captcha(
    captcha
):

    flash(
        "Incorrect security verification.",
        "error"
    )

    create_register_captcha()

    return redirect(
        url_for("home")
        + "#register"
    )


# CAPTCHA is single-use

session.pop(
    "register_captcha_answer",
    None
)


# -----------------------------------------------------
# BASIC VALIDATION
# -----------------------------------------------------

if not name:

    flash(
        "Please enter your full name.",
        "error"
    )

    create_register_captcha()

    return redirect(
        url_for("home")
        + "#register"
    )


if not email:

    flash(
        "Please enter your email address.",
        "error"
    )

    create_register_captcha()

    return redirect(
        url_for("home")
        + "#register"
    )


if not password:

    flash(
        "Please enter a password.",
        "error"
    )

    create_register_captcha()

    return redirect(
        url_for("home")
        + "#register"
    )


# -----------------------------------------------------
# PASSWORD VALIDATION
# -----------------------------------------------------

password_errors = validate_password(
    password
)


if password_errors:

    flash(
        password_errors[0],
        "error"
    )

    create_register_captcha()

    return redirect(
        url_for("home")
        + "#register"
    )


# -----------------------------------------------------
# CONFIRM PASSWORD
# -----------------------------------------------------

if password != confirm_password:

    flash(
        "Passwords do not match.",
        "error"
    )

    create_register_captcha()

    return redirect(
        url_for("home")
        + "#register"
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

    create_register_captcha()

    return redirect(
        url_for("home")
        + "#register"
    )


# -----------------------------------------------------
# STORE TEMPORARY REGISTRATION DATA
# -----------------------------------------------------

session["registration_name"] = name

session["registration_email"] = email

session["registration_password_hash"] = (
    generate_password_hash(password)
)


# -----------------------------------------------------
# GO TO GRAPHICAL PASSWORD SETUP
# -----------------------------------------------------

return redirect(
    url_for(
        "create_graphical_password"
    )
)
```

# =========================================================

# CREATE GRAPHICAL PASSWORD

# =========================================================

@app.route(
"/create-graphical-password",
methods=["GET", "POST"]
)
def create_graphical_password():

```
if (
    "registration_email"
    not in session
):

    return redirect(
        url_for("home")
    )


if request.method == "POST":

    selected = request.form.getlist(
        "selected_characters"
    )


    pass_color = request.form.get(
        "pass_color",
        ""
    ).strip().lower()


    # -------------------------------------------------
    # GRAPHICAL PASSWORD LENGTH
    # -------------------------------------------------

    if not (
        4 <= len(selected) <= 8
    ):

        flash(
            "Graphical password must contain 4 to 8 characters.",
            "error"
        )

        return render_template(
            "graphical_password.html",
            mode="register",
            pass_colors=PASS_COLORS,
            characters=GRAPHICAL_CHARACTERS
        )


    # -------------------------------------------------
    # CHECK DUPLICATES
    # -------------------------------------------------

    if len(selected) != len(
        set(selected)
    ):

        flash(
            "The same character cannot be selected twice.",
            "error"
        )

        return render_template(
            "graphical_password.html",
            mode="register",
            pass_colors=PASS_COLORS,
            characters=GRAPHICAL_CHARACTERS
        )


    # -------------------------------------------------
    # CHECK CHARACTERS
    # -------------------------------------------------

    if not all(
        character in GRAPHICAL_CHARACTERS
        for character in selected
    ):

        flash(
            "Invalid graphical password character.",
            "error"
        )

        return render_template(
            "graphical_password.html",
            mode="register",
            pass_colors=PASS_COLORS,
            characters=GRAPHICAL_CHARACTERS
        )


    # -------------------------------------------------
    # CHECK PASS COLOR
    # -------------------------------------------------

    if pass_color not in PASS_COLORS:

        flash(
            "Please select a valid pass-color.",
            "error"
        )

        return render_template(
            "graphical_password.html",
            mode="register",
            pass_colors=PASS_COLORS,
            characters=GRAPHICAL_CHARACTERS
        )


    # -------------------------------------------------
    # HASH GRAPHICAL PASSWORD
    # -------------------------------------------------

    graphical_hash = (
        hash_graphical_password(
            selected,
            pass_color
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

        db.close()


        flash(
            "This email is already registered.",
            "error"
        )


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


        create_register_captcha()


        return redirect(
            url_for("home")
            + "#register"
        )


    finally:

        try:
            db.close()
        except Exception:
            pass


    # -------------------------------------------------
    # RECORD REGISTRATION
    # -------------------------------------------------

    db = get_db()


    user = db.execute(
        """
        SELECT id
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()


    db.close()


    if user:

        record_auth_event(
            user["id"],
            email,
            "Account Registration",
            "SUCCESS"
        )


    # -------------------------------------------------
    # CLEAR TEMPORARY DATA
    # -----------------------------------------------------

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


    # Create fresh CAPTCHAs

    create_login_captcha()

    create_register_captcha()


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
    pass_colors=PASS_COLORS,
    characters=GRAPHICAL_CHARACTERS
)
```

# =========================================================

# LOGIN

# =========================================================

@app.route(
"/login",
methods=["POST"]
)
def login():

```
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
# LOGIN CAPTCHA
# -----------------------------------------------------

if not validate_login_captcha(
    captcha
):

    flash(
        "Incorrect security verification.",
        "error"
    )

    create_login_captcha()

    return redirect(
        url_for("home")
        + "#login"
    )


# CAPTCHA is single-use

session.pop(
    "login_captcha_answer",
    None
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

    create_login_captcha()

    return redirect(
        url_for("home")
        + "#login"
    )


# -----------------------------------------------------
# CHECK ACCOUNT LOCK
# -----------------------------------------------------

if user["locked_until"]:

    try:

        locked_until = datetime.fromisoformat(
            user["locked_until"]
        )


        if datetime.now() < locked_until:

            remaining_seconds = (
                locked_until
                - datetime.now()
            ).total_seconds()


            remaining = max(
                1,
                int(
                    remaining_seconds / 60
                ) + 1
            )


            flash(
                f"Account temporarily locked. Try again in {remaining} minute(s).",
                "error"
            )


            return redirect(
                url_for("home")
                + "#login"
            )


    except ValueError:

        pass


# -----------------------------------------------------
# CHECK PASSWORD
# -----------------------------------------------------

if not check_password_hash(
    user["password_hash"],
    password
):

    failed_attempts = (
        user["failed_attempts"] + 1
    )


    db = get_db()


    if (
        failed_attempts
        >= MAX_FAILED_ATTEMPTS
    ):

        locked_until = (
            datetime.now()
            + timedelta(
                minutes=LOCKOUT_MINUTES
            )
        )


        db.execute(
            """
            UPDATE users

            SET
                failed_attempts = ?,
                locked_until = ?

            WHERE id = ?
            """,
            (
                failed_attempts,
                locked_until.isoformat(),
                user["id"]
            )
        )


        db.commit()

        db.close()


        record_auth_event(
            user["id"],
            email,
            "Password Login",
            "LOCKED"
        )


        flash(
            "Too many failed attempts. Your account has been temporarily locked.",
            "error"
        )


    else:

        db.execute(
            """
            UPDATE users

            SET
                failed_attempts = ?

            WHERE id = ?
            """,
            (
                failed_attempts,
                user["id"]
            )
        )


        db.commit()

        db.close()


        record_auth_event(
            user["id"],
            email,
            "Password Login",
            "FAILED"
        )


        flash(
            f"Invalid email or password. Attempt {failed_attempts}/{MAX_FAILED_ATTEMPTS}.",
            "error"
        )


    create_login_captcha()


    return redirect(
        url_for("home")
        + "#login"
    )


# -----------------------------------------------------
# PASSWORD CORRECT
# -----------------------------------------------------

session["login_user_id"] = user["id"]

session["login_user_name"] = user["name"]

session["login_user_email"] = user["email"]


# -----------------------------------------------------
# RESET FAILED ATTEMPTS
# -----------------------------------------------------

db = get_db()


db.execute(
    """
    UPDATE users

    SET
        failed_attempts = 0,
        locked_until = NULL

    WHERE id = ?
    """,
    (user["id"],)
)


db.commit()

db.close()


record_auth_event(
    user["id"],
    email,
    "Password Login",
    "SUCCESS"
)


# -----------------------------------------------------
# GO TO GRAPHICAL PASSWORD
# -----------------------------------------------------

return redirect(
    url_for(
        "verify_graphical_password"
    )
)
```

# =========================================================

# VERIFY GRAPHICAL PASSWORD

# =========================================================

@app.route(
"/verify-graphical-password",
methods=["GET", "POST"]
)
def verify_graphical_password():

```
if (
    "login_user_id"
    not in session
):

    return redirect(
        url_for("home")
    )


if request.method == "POST":

    selected = request.form.getlist(
        "selected_characters"
    )


    pass_color = request.form.get(
        "pass_color",
        ""
    ).strip().lower()


    # -------------------------------------------------
    # VALIDATE LENGTH
    # -------------------------------------------------

    if not (
        4 <= len(selected) <= 8
    ):

        flash(
            "Please select between 4 and 8 characters.",
            "error"
        )

        return render_template(
            "graphical_password.html",
            mode="login",
            pass_colors=PASS_COLORS,
            characters=GRAPHICAL_CHARACTERS
        )


    # -------------------------------------------------
    # VALIDATE CHARACTERS
    # -------------------------------------------------

    if not all(
        character in GRAPHICAL_CHARACTERS
        for character in selected
    ):

        flash(
            "Invalid graphical password character.",
            "error"
        )

        return render_template(
            "graphical_password.html",
            mode="login",
            pass_colors=PASS_COLORS,
            characters=GRAPHICAL_CHARACTERS
        )


    # -------------------------------------------------
    # VALIDATE PASS COLOR
    # -------------------------------------------------

    if pass_color not in PASS_COLORS:

        flash(
            "Please select your pass-color.",
            "error"
        )

        return render_template(
            "graphical_password.html",
            mode="login",
            pass_colors=PASS_COLORS,
            characters=GRAPHICAL_CHARACTERS
        )


    # -------------------------------------------------
    # GET USER
    # -------------------------------------------------

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


    if user is None:

        session.clear()

        create_login_captcha()

        create_register_captcha()


        flash(
            "Authentication session expired.",
            "error"
        )


        return redirect(
            url_for("home")
        )


    # -------------------------------------------------
    # CREATE SUBMITTED HASH
    # -------------------------------------------------

    submitted_hash = (
        hash_graphical_password(
            selected,
            pass_color
        )
    )


    # -------------------------------------------------
    # VERIFY GRAPHICAL PASSWORD
    # -------------------------------------------------

    password_correct = (
        submitted_hash
        == user[
            "graphical_password_hash"
        ]
    )


    color_correct = (
        pass_color
        == user["pass_color"]
    )


    # -------------------------------------------------
    # SUCCESS
    # -------------------------------------------------

    if (
        password_correct
        and color_correct
    ):

        session.clear()


        session["user_id"] = user["id"]

        session["user_name"] = user["name"]

        session["user_email"] = user["email"]

        session["authenticated"] = True


        record_auth_event(
            user["id"],
            user["email"],
            "Graphical Authentication",
            "SUCCESS"
        )


        return redirect(
            url_for("dashboard")
        )


    # -------------------------------------------------
    # FAILED GRAPHICAL AUTHENTICATION
    # -----------------------------------------------------

    record_auth_event(
        user["id"],
        user["email"],
        "Graphical Authentication",
        "FAILED"
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


    create_login_captcha()


    flash(
        "Incorrect graphical password or pass-color.",
        "error"
    )


    return redirect(
        url_for("home")
        + "#login"
    )


return render_template(
    "graphical_password.html",
    mode="login",
    pass_colors=PASS_COLORS,
    characters=GRAPHICAL_CHARACTERS
)
```

# =========================================================

# DASHBOARD

# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

```
db = get_db()


# -----------------------------------------------------
# GET USER
# -----------------------------------------------------

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


# -----------------------------------------------------
# AUTHENTICATION HISTORY
# -----------------------------------------------------

history = db.execute(
    """
    SELECT
        event_type,
        status,
        created_at

    FROM auth_history

    WHERE user_id = ?

    ORDER BY id DESC

    LIMIT 10
    """,
    (
        session["user_id"],
    )
).fetchall()


db.close()


if user is None:

    session.clear()

    create_login_captcha()

    create_register_captcha()


    return redirect(
        url_for("home")
    )


# -----------------------------------------------------
# SECURITY SCORE
# -----------------------------------------------------

security_score = 100


return render_template(
    "dashboard.html",

    name=user["name"],

    email=user["email"],

    pass_color=user["pass_color"],

    security_score=security_score,

    history=history
)
```

# =========================================================

# LOGOUT

# =========================================================

@app.route("/logout")
def logout():

```
session.clear()


create_login_captcha()

create_register_captcha()


flash(
    "You have been securely logged out.",
    "success"
)


return redirect(
    url_for("home")
)
```

# =========================================================

# INITIALIZE DATABASE

# =========================================================

init_database()

# =========================================================

# START APPLICATION

# =========================================================

if **name** == "**main**":

```
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
```
