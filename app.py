import os
import sqlite3  # Native Python library (bypasses Windows DLL blocks)
from flask import Flask, flash, jsonify, redirect, render_template, request, session  # type: ignore[reportMissingImports]

# ==============================================================================
# CS50 DATABASE FALLBACK (Fixes: "應用程式控制原則已封鎖此檔案")
# This mimics the cs50 SQL object natively so your existing code doesn't break.
# ==============================================================================
class CS50_SQL_Fallback:
    def execute(self, query, *args):
        with sqlite3.connect("birthdays.db") as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, args)
            if query.strip().upper().startswith("SELECT"):
                return [dict(row) for row in cursor.fetchall()]
            conn.commit()
            return cursor.lastrowid

db = CS50_SQL_Fallback()
# ==============================================================================

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":

        # TODO: Add the user's entry into the database
        name = request.form.get("name")
        if not name:
            return redirect("/")

        month = request.form.get("month")
        if not month:
            return redirect("/")
        try:
            month = int(month)
        except ValueError:
            return redirect("/")
        if month < 1 or month > 12:
            return redirect("/")

        day = request.form.get("day")
        if not day:
            return redirect("/")
        try:
            day = int(day)
        except ValueError:
            return redirect("/")
        if day < 1 or day > 31:
            return redirect("/")

        db.execute("INSERT INTO birthdays (name, month, day) VALUES(?, ?, ?)", name, month, day)

        return redirect("/")

    else:

        # TODO: Display the entries in the database on index.html
        birthdays = db.execute("SELECT * FROM birthdays")
        return render_template("index.html", birthdays=birthdays)


@app.route("/deregister", methods=["POST"])  # Or @app.route("/delete", methods=["POST"])
def delete():
    # Retrieve the id from the form submission
    id = request.form.get("id")
    if id:
        db.execute("DELETE FROM birthdays WHERE id = ?", id)
    return redirect("/")
