import hashlib
import os
import secrets
import smtplib
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime
from email.message import EmailMessage
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for  # type: ignore
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer  # type: ignore[reportMissingImports]
from werkzeug.security import check_password_hash, generate_password_hash  # type: ignore[reportMissingImports]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, 'birthdays.db'))
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '').lower() == 'true')
REMINDER_OPTIONS = (0, 1, 3, 7, 14, 30)

@contextmanager
def connect_db():
    connection = sqlite3.connect(DATABASE, timeout=20)
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
    with connect_db() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT COLLATE NOCASE UNIQUE)''')
        c.execute('''CREATE TABLE IF NOT EXISTS birthdays (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            month INTEGER NOT NULL, day INTEGER NOT NULL,
            user_id INTEGER, reminder_days INTEGER NOT NULL DEFAULT 7,
            email_reminder INTEGER NOT NULL DEFAULT 1, email_sent_for TEXT)''')
        uc = {r['name'] for r in c.execute('PRAGMA table_info(users)')}
        bc = {r['name'] for r in c.execute('PRAGMA table_info(birthdays)')}
        if 'email' not in uc:
            c.execute('ALTER TABLE users ADD COLUMN email TEXT')
        for col, ddl in (
            ('user_id', 'INTEGER'),
            ('reminder_days', 'INTEGER NOT NULL DEFAULT 7'),
            ('email_reminder', 'INTEGER NOT NULL DEFAULT 1'),
            ('email_sent_for', 'TEXT'),
        ):
            if col not in bc:
                c.execute(f'ALTER TABLE birthdays ADD COLUMN {col} {ddl}')
        c.execute('CREATE INDEX IF NOT EXISTS idx_birthdays_user_id ON birthdays(user_id)')

init_db()

@app.after_request
def no_cache(response):
    response.headers['Cache-Control'] = 'no-store'
    return response

@app.before_request
def csrf_protection():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    if request.method == 'POST':
        if not secrets.compare_digest(request.form.get('csrf_token', ''), session['_csrf_token']):
            abort(400, description='Form expired. Refresh the page and try again.')

@app.context_processor
def template_context():
    return {'csrf_token': session.get('_csrf_token', '')}

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.')
            return redirect(url_for('index'))
        return fn(*args, **kwargs)
    return wrapped

def valid_email(email):
    if not email or len(email) > 254 or email.count('@') != 1 or any(c.isspace() for c in email):
        return False
    local, domain = email.rsplit('@', 1)
    return bool(local and '.' in domain and not domain.startswith('.') and not domain.endswith('.'))

def smtp_ready():
    return all(os.environ.get(k) for k in ('SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD', 'MAIL_FROM'))

def send_email(recipient, subject, content):
    if not smtp_ready():
        app.logger.warning('Email not configured: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, MAIL_FROM required')
        return False
    msg = EmailMessage()
    msg['From'] = os.environ['MAIL_FROM']
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.set_content(content)
    try:
        port = int(os.environ['SMTP_PORT'])
        if os.environ.get('SMTP_SSL', '').lower() == 'true':
            smtp = smtplib.SMTP_SSL(os.environ['SMTP_HOST'], port, timeout=20)
        else:
            smtp = smtplib.SMTP(os.environ['SMTP_HOST'], port, timeout=20)
        with smtp:
            if os.environ.get('SMTP_SSL', '').lower() != 'true':
                smtp.starttls()
            smtp.login(os.environ['SMTP_USER'], os.environ['SMTP_PASSWORD'])
            smtp.send_message(msg)
        return True
    except (OSError, ValueError, smtplib.SMTPException):
        app.logger.exception('Email delivery failed')
        return False

def next_birthday(month, day, today=None):
    today = today or date.today()
    for year in (today.year, today.year + 1):
        try:
            candidate = date(year, month, day)
        except ValueError:
            candidate = date(year, 2, 28)  # Observe Feb 29 on Feb 28 in non-leap years
        if candidate >= today:
            return candidate
    raise ValueError('Could not calculate next birthday')

def send_due_reminders(today=None):
    """Call from a daily scheduler: python app.py send-reminders."""
    today = today or date.today()
    with connect_db() as c:
        rows = c.execute('''SELECT b.id, b.user_id, b.name, b.month, b.day,
            b.reminder_days, b.email_sent_for, u.email
            FROM birthdays b JOIN users u ON u.id = b.user_id
            WHERE b.email_reminder = 1 AND u.email IS NOT NULL''').fetchall()
    sent = 0
    for b in rows:
        occurrence = next_birthday(b['month'], b['day'], today)
        days = (occurrence - today).days
        if days > b['reminder_days'] or b['email_sent_for'] == occurrence.isoformat():
            continue
        when = 'today' if days == 0 else 'tomorrow' if days == 1 else f'in {days} days'
        if send_email(b['email'], f"Birthday reminder: {b['name']}",
                      f"Don't forget! {b['name']}'s birthday is {when} ({b['month']:02d}/{b['day']:02d})."):
            with connect_db() as c:
                c.execute('''UPDATE birthdays SET email_sent_for=? WHERE id=? AND user_id=?
                    AND (email_sent_for IS NULL OR email_sent_for != ?)''',
                    (occurrence.isoformat(), b['id'], b['user_id'], occurrence.isoformat()))
            sent += 1
    return sent

def reset_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt='birthday-password-reset-v1')

def password_fingerprint(password_hash):
    return hashlib.sha256(password_hash.encode()).hexdigest()[:24]

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return render_template('index.html', birthdays=[], reminders=[])
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        try:
            month, day = int(request.form.get('month', '')), int(request.form.get('day', ''))
            reminder_days = int(request.form.get('reminder_days', '7'))
            date(2000, month, day)
        except (ValueError, TypeError):
            flash('Please enter a valid birthday.')
            return redirect(url_for('index'))
        if not name or len(name) > 100 or reminder_days not in REMINDER_OPTIONS:
            flash('Please enter a name (up to 100 characters) and a valid reminder setting.')
            return redirect(url_for('index'))
        email_reminder = int(request.form.get('email_reminder') == 'on')
        with connect_db() as c:
            c.execute('''INSERT INTO birthdays (name, month, day, user_id, reminder_days, email_reminder)
                VALUES (?, ?, ?, ?, ?, ?)''',
                (name, month, day, session['user_id'], reminder_days, email_reminder))
        flash('Birthday added!')
        return redirect(url_for('index'))
    today = date.today()
    with connect_db() as c:
        rows = c.execute('''SELECT id, name, month, day, reminder_days, email_reminder
            FROM birthdays WHERE user_id=?''', (session['user_id'],)).fetchall()
        account = c.execute('SELECT email FROM users WHERE id=?', (session['user_id'],)).fetchone()
    birthdays = []
    for row in rows:
        b = dict(row)
        b['days_until'] = (next_birthday(b['month'], b['day'], today) - today).days
        birthdays.append(b)
    birthdays.sort(key=lambda b: (b['days_until'], b['name'].casefold()))
    reminders = [b for b in birthdays if b['days_until'] <= b['reminder_days']]
    return render_template('index.html', birthdays=birthdays, reminders=reminders,
                           needs_email=bool(account and not account['email']))

@app.route('/register', methods=['POST'])
def register():
    username = (request.form.get('username') or '').strip()
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    if not 3 <= len(username) <= 30 or not username.replace('_', '').isalnum():
        flash('Username must be 3–30 letters, numbers, or underscores.')
    elif not valid_email(email):
        flash('Please enter a valid email address.')
    elif len(password) < 8:
        flash('Password must be at least 8 characters.')
    else:
        try:
            with connect_db() as c:
                cur = c.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                                (username, email, generate_password_hash(password)))
                user_id = cur.lastrowid
        except sqlite3.IntegrityError:
            flash('That username or email is already registered.')
        else:
            session.clear()
            session['user_id'] = user_id
            session['username'] = username
            flash('Account created! Welcome to Birthdays.')
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    username = (request.form.get('username') or '').strip()
    with connect_db() as c:
        user = c.execute('SELECT id, username, password_hash FROM users WHERE username=?',
                         (username,)).fetchone()
    if user is None or not check_password_hash(user['password_hash'], request.form.get('password') or ''):
        flash('Incorrect username or password.')
    else:
        session.clear()
        session['user_id'], session['username'] = user['id'], user['username']
        flash('Welcome back!')
    return redirect(url_for('index'))

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current = request.form.get('current_password') or ''
    new = request.form.get('new_password') or ''
    confirmation = request.form.get('confirm_password') or ''
    with connect_db() as c:
        user = c.execute('SELECT password_hash FROM users WHERE id=?', (session['user_id'],)).fetchone()
        if not user or not check_password_hash(user['password_hash'], current):
            flash('Current password is incorrect.')
        elif len(new) < 8 or new != confirmation:
            flash('New password must be at least 8 characters and match confirmation.')
        else:
            c.execute('UPDATE users SET password_hash=? WHERE id=?',
                      (generate_password_hash(new), session['user_id']))
            flash('Password changed successfully.')
    return redirect(url_for('index'))

@app.route('/set-email', methods=['POST'])
@login_required
def set_email():
    """Allow existing users who registered before emails were collected to add one."""
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    with connect_db() as c:
        user = c.execute('SELECT password_hash, email FROM users WHERE id=?', (session['user_id'],)).fetchone()
        if not user or user['email']:
            flash('Email is already set for this account.')
        elif not check_password_hash(user['password_hash'], password):
            flash('Incorrect password.')
        elif not valid_email(email):
            flash('Enter a valid email address.')
        else:
            try:
                c.execute('UPDATE users SET email=? WHERE id=?', (email, session['user_id']))
                flash('Email address saved.')
            except sqlite3.IntegrityError:
                flash('That email is already registered.')
    return redirect(url_for('index'))

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    username = (request.form.get('username') or '').strip()
    email = (request.form.get('email') or '').strip().lower()
    with connect_db() as c:
        user = c.execute('SELECT id, username, email, password_hash FROM users WHERE username=? AND email=?',
                         (username, email)).fetchone()
    if user and smtp_ready():
        token = reset_serializer().dumps({'id': user['id'], 'fingerprint': password_fingerprint(user['password_hash'])})
        link = url_for('reset_password', token=token, _external=True)
        send_email(user['email'], 'Reset your Birthdays password',
                   f"Hello {user['username']},\n\nUse this link within 30 minutes to reset your password:\n{link}\n\nIf you did not request this, ignore this email.")
    flash('If those details match an account, a reset link will be emailed if email delivery is configured.')
    return redirect(url_for('index'))

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        data = reset_serializer().loads(token, max_age=1800)
        user_id = int(data['id'])
        fingerprint = data['fingerprint']
    except (BadSignature, SignatureExpired, KeyError, TypeError, ValueError):
        flash('Reset link is invalid or expired.')
        return redirect(url_for('index'))
    with connect_db() as c:
        user = c.execute('SELECT password_hash FROM users WHERE id=?', (user_id,)).fetchone()
    if not user or password_fingerprint(user['password_hash']) != fingerprint:
        flash('Reset link is no longer valid.')
        return redirect(url_for('index'))
    if request.method == 'POST':
        new = request.form.get('new_password') or ''
        confirm = request.form.get('confirm_password') or ''
        if len(new) < 8 or new != confirm:
            flash('Password must be at least 8 characters and match confirmation.')
        else:
            with connect_db() as c:
                c.execute('UPDATE users SET password_hash=? WHERE id=? AND password_hash=?',
                          (generate_password_hash(new), user_id, user['password_hash']))
            flash('Password reset. You can now log in.')
            return redirect(url_for('index'))
    return render_template('reset_password.html', token=token)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/deregister', methods=['POST'])
@login_required
def delete():
    birthday_id = request.form.get('id', '')
    if birthday_id.isdigit():
        with connect_db() as c:
            c.execute('DELETE FROM birthdays WHERE id=? AND user_id=?',
                      (int(birthday_id), session['user_id']))
        flash('Birthday deleted.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'send-reminders':
        print(f'Sent {send_due_reminders()} birthday reminder email(s).')
    else:
        app.run(debug=os.environ.get('FLASK_DEBUG', '').lower() == 'true')
