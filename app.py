import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import date
from functools import wraps

# pyright: reportMissingImports=false
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "birthdays.db")

app = Flask(__name__)
# Set SECRET_KEY to a long random value in your hosting provider.
# The fallback is convenient for local development only.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "").lower() == "true"


@contextmanager
def connect_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    """Create accounts and migrate older birthday databases without deleting rows."""
    with connect_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS birthdays (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                month INTEGER NOT NULL,
                day INTEGER NOT NULL,
                user_id INTEGER,
                reminder_days INTEGER NOT NULL DEFAULT 7
            )
            """
        )
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(birthdays)")
        }
        if "user_id" not in columns:
            connection.execute("ALTER TABLE birthdays ADD COLUMN user_id INTEGER")
        if "reminder_days" not in columns:
            connection.execute(
                "ALTER TABLE birthdays ADD COLUMN reminder_days INTEGER NOT NULL DEFAULT 7"
            )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_birthdays_user_id ON birthdays(user_id)"
        )


init_db()


@app.after_request
def after_request(response):
    # Avoid showing stale birthday lists after logout or changes.
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = "0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.before_request
def protect_post_requests():
    # Lightweight CSRF protection for form submissions.
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not expected or not secrets.compare_digest(submitted, expected):
            abort(400, description="The form expired. Refresh the page and try again.")


@app.context_processor
def inject_template_helpers():
    return {"csrf_token": session.get("_csrf_token", "")}


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("index"))
        return view(*args, **kwargs)
    return wrapped_view


def next_birthday(month, day, today=None):
    """Return the next occurrence of a birthday, including today."""
    today = today or date.today()
    for year in (today.year, today.year + 1):
        try:
            candidate = date(year, month, day)
        except ValueError:
            # A February 29 birthday is observed on February 28 in non-leap years.
            candidate = date(year, 2, 28)
        if candidate >= today:
            return candidate
    raise ValueError("Could not calculate next birthday")


@app.route("/", methods=["GET", "POST"])
def index():
    if "user_id" not in session:
        return render_template("index.html", birthdays=[], reminders=[])

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        try:
            month = int(request.form.get("month", ""))
            day = int(request.form.get("day", ""))
            reminder_days = int(request.form.get("reminder_days", "7"))
            date(2000, month, day)  # Validates month/day and permits February 29.
        except (TypeError, ValueError):
            flash("Please enter a valid birthday.")
            return redirect(url_for("index"))

        if not name or len(name) > 100:
            flash("Please enter a name (up to 100 characters).")
            return redirect(url_for("index"))
        if reminder_days not in (0, 1, 3, 7, 14, 30):
            flash("Please choose a valid reminder setting.")
            return redirect(url_for("index"))

        with connect_db() as connection:
            connection.execute(
                """
                INSERT INTO birthdays (name, month, day, user_id, reminder_days)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, month, day, session["user_id"], reminder_days),
            )
        flash("Birthday added!")
        return redirect(url_for("index"))

    today = date.today()
    with connect_db() as connection:
        rows = connection.execute(
            """
            SELECT id, name, month, day, reminder_days
            FROM birthdays
            WHERE user_id = ?
            """,
            (session["user_id"],),
        ).fetchall()

    birthdays = []
    reminders = []
    for row in rows:
        birthday = dict(row)
        upcoming = next_birthday(birthday["month"], birthday["day"], today)
        birthday["next_date"] = upcoming
        birthday["days_until"] = (upcoming - today).days
        birthdays.append(birthday)
        if birthday["days_until"] <= birthday["reminder_days"]:
            reminders.append(birthday)

    birthdays.sort(key=lambda item: (item["days_until"], item["name"].casefold()))
    reminders.sort(key=lambda item: (item["days_until"], item["name"].casefold()))
    return render_template("index.html", birthdays=birthdays, reminders=reminders)


@app.route("/register", methods=["POST"])
def register():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if len(username) < 3 or len(username) > 30:
        flash("Username must be between 3 and 30 characters.")
        return redirect(url_for("index"))
    if not username.replace("_", "").isalnum():
        flash("Use only letters, numbers, and underscores in your username.")
        return redirect(url_for("index"))
    if len(password) < 8:
        flash("Password must be at least 8 characters.")
        return redirect(url_for("index"))

    try:
        with connect_db() as connection:
            cursor = connection.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        flash("That username is already taken. Choose another.")
        return redirect(url_for("index"))

    session.clear()
    session["user_id"] = user_id
    session["username"] = username
    flash("Account created! Welcome to Birthdays.")
    return redirect(url_for("index"))


@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    with connect_db() as connection:
        user = connection.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        flash("Incorrect username or password.")
        return redirect(url_for("index"))

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    flash("Welcome back!")
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("index"))


@app.route("/deregister", methods=["POST"])
@login_required
def delete():
    birthday_id = request.form.get("id")
    if birthday_id and birthday_id.isdigit():
        with connect_db() as connection:
            # Ownership check prevents deleting another user's record by guessing its ID.
            connection.execute(
                "DELETE FROM birthdays WHERE id = ? AND user_id = ?",
                (int(birthday_id), session["user_id"]),
            )
        flash("Birthday deleted.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "").lower() == "true")
