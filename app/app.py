from flask import Flask, render_template, redirect, url_for, session, request
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired
from ldap3 import Server, Connection, ALL, SUBTREE, Tls
from functools import wraps
from dataclasses import dataclass, field
import time
import os
import json
import ssl

app = Flask(__name__)

if os.environ['FLASK_ENV'] == 'development':
    app.secret_key = 'REPLACE_WITH_SECURE_SECRET'
else:
    app.secret_key = os.urandom(24).hex()


csrf = CSRFProtect(app)

# Load Config from env
LDAP_HOST = f"ldaps://{os.environ.get("LDAP_HOST")}"
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN")
LDAP_USERNAME = os.environ.get("LDAP_USERNAME")
LDAP_PASSWORD = os.environ.get("LDAP_PASSWORD")
ROLES = json.loads(os.environ.get("LDAP_ROLES"))
SESSION_TIMEOUT_SECONDS = 3600

# User class
@dataclass
class User:
    username: str
    dn: str = None
    fullname: str = None
    email: str = None
    authenticated: bool = False
    roles: list = field(default_factory = list)

# Flask-WTF login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Refresh session timeout at every request
# or redirect to login form
@app.before_request
def refresh_session():
    if os.environ['FLASK_ENV'] == 'development':
        print(f"refresh_session(): session={session}")
    if 'username' in session:
        now = int(time.time())
        if session.get('expires_at', 0) < now:
            session.clear()  # Session expired
        else:
            session['expires_at'] = now + SESSION_TIMEOUT_SECONDS  # Refresh timeout

# Login required decorator
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# LDAP login function
def ldap_login(username: str, password: str) -> User:
    tls_config = Tls(validate=ssl.CERT_NONE)
    server = Server(
        LDAP_HOST,
        get_info = ALL,
        port = 636,
        use_ssl = True,
        tls = tls_config
    )

    # Use service account to search for user's DN
    try:
        conn = Connection(
            server,
            user = LDAP_USERNAME,
            password = LDAP_PASSWORD,
            auto_bind = True
        )
    except Exception as e:
        print(f"[ERROR] Failed to bind with service account: {e}")
        return User(username=username)

    # Search for the user's DN using sAMAccountName
    search_filter = f"(sAMAccountName={username})"
    conn.search(
        search_base = LDAP_BASE_DN,
        search_filter = search_filter,
        search_scope = SUBTREE,
        attributes = ["distinguishedName", "memberOf", "displayName", "mail"]
    )

    if not conn.entries:
        return User(username=username)

    user_dn = conn.entries[0].entry_dn
    member_of = conn.entries[0].memberOf.values if 'memberOf' in conn.entries[0] else []
    fullname = conn.entries[0].displayName.value
    email = conn.entries[0].mail.value

    # Now try binding with the user's actual credentials
    try:
        Connection(server, user=user_dn, password=password, auto_bind=True)
    except Exception:
        return User(username=username)

    # Now verify group membership
    user_roles = set()
    for role_name,role_groups in ROLES.items():
        for role_group in role_groups:
            for group in member_of:
                if group.startswith(role_group):
                    user_roles.add(role_name)


    return User(
        username = username,
        dn = user_dn,
        roles = list(user_roles),
        fullname = fullname,
        email = email,
        authenticated = True
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    # Avoid LDAP bind if already authenticated
    if "username" in session:
        return redirect(url_for('home'))
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Authenticate
        user = ldap_login(username, password)
        if user.authenticated:
            print(f"User {user.username} authenticated with roles: {user.roles}")
            session["username"] = user.username
            session["roles"] = user.roles
            session["fullname"] = user.fullname
            session["email"] = user.email
            session['expires_at'] = int(time.time()) + SESSION_TIMEOUT_SECONDS
            return redirect(url_for('home'))
        else:
            error = "Access denied."
    
    return render_template("login.html", form=form, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    return f"Hello, {session['fullname']}! You're authenticated as {session['roles']}."

if __name__ == '__main__':
    app.run(debug=True)
