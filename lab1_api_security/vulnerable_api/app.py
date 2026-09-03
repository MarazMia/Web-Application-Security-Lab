import os
import time
import sqlite3
import secrets
import jwt
from functools import wraps

from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================== APPLICATION
app = Flask(__name__)
DB = "vulnmart.db"


# =============================================================== TODO (1)
# Vulnerable default: hardcoded, weak JWT secret.
# STUDENT TASK:
#   Replace this with a secret loaded from an environment variable or other
#   secure configuration. Do not break local execution when the variable is
#   missing; choose an appropriate secure fallback for this teaching app.
#
# Example concepts to consider: os.environ, secrets.
JWT_SECRET = "supersecret123"
JWT_ALGO = "HS256"


# =============================================================== TODO (3)
# Vulnerable default: tokens never expire.
# STUDENT TASK:
#   Define an appropriate token lifetime and add the required JWT claims in
#   make_token(). Ensure expired tokens are rejected by get_current_user().
#
# Example:
# JWT_EXPIRATION_SECONDS = ...


# =============================================================== TODO (2)
# Vulnerable default: any origin is allowed.
# STUDENT TASK:
#   Restrict API CORS to the known frontend origin(s). Think carefully about
#   whether credentials are needed.
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)


# =============================================================== TODO (4)
# Simple in-memory rate-limit scaffolding.
# STUDENT TASK:
#   Complete rate limiting for login. 
#   The application must still run before this TODO is completed.
#
# Production systems should use a shared/distributed limiter rather than this
# process-local dictionary.
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_ATTEMPTS = 5
rate_limit_attempts = {}


def rate_limit_exceeded(bucket, ip):
    """
    TODO (4): Replace the vulnerable/default behavior with a real check.
    Suggested design: keep only timestamps inside the active time window and
    return True when the maximum allowed attempts has already been reached.

    Current default intentionally disables the protection.
    """
    return False


def record_rate_limited_attempt(bucket, ip):
    """
    TODO (4): Record one attempt for the supplied bucket/IP.

    Current default intentionally does nothing, so the app remains vulnerable
    until students implement the policy.
    """
    pass


# ================================================================= FRONTEND
@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/profile.html")
def profile_page():
    return send_from_directory(".", "profile.html")


@app.route("/orders.html")
def orders_page():
    return send_from_directory(".", "orders.html")


@app.route("/products.html")
def products_page():
    return send_from_directory(".", "products.html")


# ================================================================== DATABASE
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.executescript("""
        DROP TABLE IF EXISTS orders;
        DROP TABLE IF EXISTS users;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            ssn TEXT,
            balance REAL DEFAULT 0,
            is_admin INTEGER DEFAULT 0
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'placed',
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)

    users = [
        ("alice", "alicepw", "alice@example.com", "111-22-3333", 250.00, 0),
        ("bob",   "bobpw",   "bob@example.com",   "222-33-4444", 40.00,  0),
        ("admin", "adminpw", "admin@vulnmart.local", "000-00-0000", 0.00, 1),
    ]

    for username, password, email, ssn, balance, is_admin in users:
        c.execute(
            "INSERT INTO users "
            "(username,password_hash,email,ssn,balance,is_admin) "
            "VALUES (?,?,?,?,?,?)",
            (
                username,
                generate_password_hash(password),
                email,
                ssn,
                balance,
                is_admin,
            ),
        )

    orders = [
        (1, "Wireless Mouse", 19.99),
        (1, "Mechanical Keyboard", 89.00),
        (2, "USB-C Cable", 9.50),
        (3, "Server Rack (internal)", 1200.00),
    ]

    for user_id, item, amount in orders:
        c.execute(
            "INSERT INTO orders (user_id,item,amount) VALUES (?,?,?)",
            (user_id, item, amount),
        )

    conn.commit()
    conn.close()


# ======================================================================= JWT
def make_token(user_row):
    """
    TODO (3):
    Add issued-at/expiration information to this payload and configure an
    appropriate lifetime.

    Vulnerable default intentionally contains no expiration.
    """
    payload = {
        "user_id": user_row["id"],
        "username": user_row["username"],
        "is_admin": bool(user_row["is_admin"]),
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


# ============================================================ AUTHENTICATION
def get_current_user():
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header[len("Bearer "):]

    try:
        # TODO (3):
        # Ensure your completed implementation correctly rejects expired tokens.
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.InvalidTokenError:
        return None


# =============================================================== TODO (6/8/9)
# Optional authorization helper scaffolding.
# STUDENT TASK:
#   You may implement reusable decorators/helpers here for authentication,
#   object-level authorization, and administrator checks.
#
# IMPORTANT: The default app intentionally does not enforce these controls.
#
# def require_auth(function):
#     ...
#
# def require_admin(function):
#     ...
#
# def require_same_user(user_id):
#     ...


# ===================================================================== LOGIN
@app.route("/api/login", methods=["POST"])
def login():
    # TODO (4): Apply rate limiting before authentication.
    # Vulnerable default: no throttling or lockout is enforced.

    data = request.get_json(force=True) or {}
    username = data.get("username")
    password = data.get("password")

    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if row and check_password_hash(row["password_hash"], password or ""):
        return jsonify({"token": make_token(row)})

    return jsonify({"error": "invalid credentials"}), 401


# ================================================================= REGISTER
@app.route("/api/register", methods=["POST"])
def register():
    # TODO (4): Optionally apply rate limiting here if required by the policy.

    # TODO (5): Input validation.
    # The secure reference implementation validates the request body and
    # required fields before writing to the database.
    #
    # TODO (5): Mass assignment protection.
    # Vulnerable default below accepts client-controlled sensitive fields.
    # Students should whitelist the fields a registrant is allowed to provide
    # and set protected properties server-side.

    data = request.get_json(force=True) or {}
    db = get_db()

    try:
        # VULNERABLE DEFAULT:
        # balance and is_admin are client-controlled.
        db.execute(
            """INSERT INTO users
               (username,password_hash,email,ssn,balance,is_admin)
               VALUES (?,?,?,?,?,?)""",
            (
                data.get("username"),
                generate_password_hash(data.get("password", "")),
                data.get("email", ""),
                data.get("ssn", ""),
                data.get("balance", 0),
                int(bool(data.get("is_admin", 0))),
            ),
        )
        db.commit()

    except sqlite3.IntegrityError:
        return jsonify({"error": "username taken"}), 409

    return jsonify({"message": "registered"}), 201


# ============================================================= GET USER
@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = get_current_user()

    if not user:
        return jsonify({"error": "unauthorized"}), 401

    # TODO (6): Object-level authorization / BOLA-IDOR protection.
    # Vulnerable default: any authenticated user can request any user_id.
    # Add an ownership (or appropriate administrator) authorization check.

    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if not row:
        return jsonify({"error": "not found"}), 404

    # TODO (6): Excessive data exposure.
    # Vulnerable default returns the entire database row, including sensitive
    # properties. Return only the fields required by the client.
    return jsonify(dict(row))


# =============================================================== UPDATE USER
@app.route("/api/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    user = get_current_user()

    if not user:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True) or {}

    # TODO (7): Ownership authorization.
    # Vulnerable default allows an authenticated user to edit another user.

    # TODO (7): Property-level authorization / mass assignment.
    # Vulnerable default lets the client modify sensitive fields.
    fields = []
    values = []

    for key in ("email", "ssn", "balance", "is_admin"):
        if key in data:
            fields.append(f"{key} = ?")
            values.append(data[key])

    if not fields:
        return jsonify({"error": "no fields to update"}), 400

    values.append(user_id)

    db = get_db()

    db.execute(
        f"UPDATE users SET {', '.join(fields)} WHERE id = ?",
        values,
    )
    db.commit()

    return jsonify({"message": "updated"})


# ============================================================== USER ORDERS
@app.route("/api/users/<int:user_id>/orders", methods=["GET"])
def user_orders(user_id):
    user = get_current_user()

    if not user:
        return jsonify({"error": "unauthorized"}), 401

    # TODO (8): Object-level authorization / BOLA protection.
    # Vulnerable default: an authenticated user can request another user's
    # orders by changing user_id.

    db = get_db()
    rows = db.execute(
        "SELECT * FROM orders WHERE user_id = ?",
        (user_id,),
    ).fetchall()

    return jsonify([dict(row) for row in rows])


# =============================================================== SINGLE ORDER
@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    user = get_current_user()

    if not user:
        return jsonify({"error": "unauthorized"}), 401

    # TODO (9): Object-level authorization.
    # Vulnerable default checks only that the caller is authenticated, not that
    # the requested order belongs to that caller.

    db = get_db()
    row = db.execute(
        "SELECT * FROM orders WHERE id = ?",
        (order_id,),
    ).fetchone()

    if not row:
        return jsonify({"error": "not found"}), 404

    return jsonify(dict(row))


# =================================================================== ADMIN
@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    user = get_current_user()

    if not user:
        return jsonify({"error": "unauthorized"}), 401

    # TODO (10): Function-level authorization.
    # Vulnerable default: any authenticated user can call this admin endpoint.
    # Require an appropriate administrator authorization check.

    db = get_db()
    rows = db.execute("SELECT * FROM users").fetchall()

    # TODO (10): Consider data minimization here too.
    return jsonify([dict(row) for row in rows])


# ====================================================================== SEARCH
@app.route("/api/products", methods=["GET"])
def search_products():
    search = request.args.get("search", "")

    db = get_db()

    # TODO (11): SQL injection prevention.
    # Vulnerable default intentionally concatenates untrusted input into SQL.
    # Replace this with a parameterized query. Consider input validation as well.
    query = (
        "SELECT id, username, email "
        f"FROM users WHERE username LIKE '%{search}%'"
    )

    try:
        rows = db.execute(query).fetchall()
    except sqlite3.OperationalError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify([dict(row) for row in rows])


# ====================================================================== HEALTH
@app.route("/api/health", methods=["GET"])
def health():
    # TODO (12): API versioning / inventory.
    # The vulnerable API has no versioning. Implement the versioning approach
    # required by the lab instructions and update the endpoint inventory/
    # documentation accordingly.
    return jsonify({
        "status": "ok",
        "note": "no versioning on this API - see debrief",
    })


# ================================================================= START APP
if __name__ == "__main__":
    init_db()

    print(
        "\n" + "=" * 60
        + "\nVULNMART - API SECURITY LAB (STUDENT TODO VERSION)\n"
        + "=" * 60
    )

    print("\nOpen:\n  http://127.0.0.1:5000/\n")

    print(
        "Demo accounts:\n"
        "  alice / alicepw\n"
        "  bob   / bobpw\n"
        "  admin / adminpw\n"
    )

    print(
        "API:\n"
        "  /api/login\n"
        "  /api/register\n"
        "  /api/users/<id>\n"
        "  /api/users/<id>/orders\n"
        "  /api/orders/<id>\n"
        "  /api/admin/users\n"
        "  /api/products\n"
        "  /api/health\n"
    )

    print("Student tasks:")
    print("  TODO (1)  Secure JWT secret")
    print("  TODO (2)  Restrictive CORS")
    print("  TODO (3)  JWT expiration")
    print("  TODO (4)  Rate limiting")
    print("  TODO (5)  Registration validation / mass assignment")
    print("  TODO (6)  Profile BOLA / data exposure")
    print("  TODO (7)  Update authorization / property controls")
    print("  TODO (8)  Orders BOLA")
    print("  TODO (9)  Single-order authorization")
    print("  TODO (10) Admin function authorization")
    print("  TODO (11) SQL injection prevention")
    print("  TODO (12) API versioning / inventory")
    print("=" * 60)

    app.run(host="127.0.0.1", port=5000, debug=False)