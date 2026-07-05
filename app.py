# app.py

import sqlite3, uuid, time, re, os, json
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory
import bcrypt, jwt, pyotp

DB = os.environ.get("DEMO_DB", "demo_payments.db")

JWT_SECRET = os.environ.get(
    "JWT_SECRET",
    "CHANGE_THIS_RANDOM_SECRET"
)

JWT_ALGO = "HS256"

HIGH_VALUE_THRESHOLD = float(
    os.environ.get("HIGH_VALUE_THRESHOLD", "1000.0")
)

SIMPLE_WAF_PATTERNS = [
    r"DROP\s+TABLE",
    r"(--\s*$)",
    r"or\s+1=1",
    r"UNION\s+SELECT",
    r"SELECT\s+\*\s+FROM"
]

app = Flask(__name__, static_folder=".", static_url_path="/")


# ---------------- DATABASE ----------------

def get_db():
    db = getattr(g, "_db", None)

    if not db:
        db = g._db = sqlite3.connect(
            DB,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        db.row_factory = sqlite3.Row

    return db


def init_db():
    db = get_db()

    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        mfa_seed TEXT
    );

    CREATE TABLE IF NOT EXISTS payments (
        id TEXT PRIMARY KEY,
        payer TEXT,
        payee TEXT,
        amount REAL,
        currency TEXT,
        description TEXT,
        status TEXT,
        created_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        event_type TEXT,
        detail TEXT,
        actor TEXT,
        ts INTEGER
    );

    CREATE TABLE IF NOT EXISTS pending_approvals (
        id TEXT PRIMARY KEY,
        payment_id TEXT,
        otp TEXT,
        expires_at INTEGER
    );
    """)

    db.commit()


@app.before_first_request
def startup():
    init_db()


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)

    if db:
        db.close()


# ---------------- AUDIT ----------------

def audit(event_type, detail, actor="system"):
    db = get_db()

    db.execute(
        """
        INSERT INTO audit_logs
        (id,event_type,detail,actor,ts)
        VALUES (?,?,?,?,?)
        """,
        (
            str(uuid.uuid4()),
            event_type,
            detail,
            actor,
            int(time.time())
        )
    )

    db.commit()


# ---------------- BASIC WAF ----------------

@app.before_request
def basic_waf():

    try:
        body = request.get_data(as_text=True) or ""
    except:
        body = ""

    for p in SIMPLE_WAF_PATTERNS:

        if re.search(p, body, re.IGNORECASE):

            audit(
                "waf.block",
                f"pattern={p} src={request.remote_addr} path={request.path}",
                "system"
            )

            return jsonify({
                "error": "malicious payload blocked"
            }), 403


# ---------------- AUTH ----------------

def token_required(f):

    @wraps(f)
    def wrapper(*args, **kwargs):

        token = request.headers.get(
            "Authorization",
            ""
        ).replace("Bearer ", "")

        if not token:
            return jsonify({"error": "missing token"}), 401

        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGO]
            )

            request.user_id = payload["sub"]

        except Exception as e:
            return jsonify({"error": "invalid token"}), 401

        return f(*args, **kwargs)

    return wrapper


# ---------------- ROUTES ----------------

@app.route("/")
def root_index():
    return send_from_directory(".", "index.html")


@app.route("/api/auth/register", methods=["POST"])
def register():

    data = request.json or {}

    username = data.get("username")
    pw = data.get("password")

    if not username or not pw:
        return jsonify({
            "error": "username & password required"
        }), 400

    ph = bcrypt.hashpw(
        pw.encode(),
        bcrypt.gensalt()
    ).decode()

    uid = str(uuid.uuid4())

    db = get_db()

    try:
        db.execute(
            """
            INSERT INTO users
            (id,username,password_hash)
            VALUES (?,?,?)
            """,
            (uid, username, ph)
        )

        db.commit()

    except Exception as e:
        return jsonify({
            "error": "user exists or db error"
        }), 400

    audit(
        "user.register",
        f"user={username}",
        username
    )

    return jsonify({
        "id": uid,
        "username": username
    })


@app.route("/api/auth/login", methods=["POST"])
def login():

    data = request.json or {}

    username = data.get("username")
    pw = data.get("password")

    db = get_db()

    r = db.execute(
        """
        SELECT id,password_hash,mfa_seed
        FROM users
        WHERE username=?
        """,
        (username,)
    ).fetchone()

    if not r or not bcrypt.checkpw(
        pw.encode(),
        r["password_hash"].encode()
    ):

        audit(
            "user.login_fail",
            f"user={username} ip={request.remote_addr}",
            username
        )

        return jsonify({
            "error": "invalid credentials"
        }), 401

    if r["mfa_seed"]:

        otp = data.get("otp")

        if not otp:
            return jsonify({
                "mfa_required": True,
                "message": "MFA token required"
            }), 200

        totp = pyotp.TOTP(r["mfa_seed"])

        if not totp.verify(otp):

            audit(
                "user.mfa_fail",
                f"user={username}",
                username
            )

            return jsonify({
                "error": "invalid mfa token"
            }), 401

    token = jwt.encode(
        {
            "sub": r["id"],
            "iat": int(time.time())
        },
        JWT_SECRET,
        algorithm=JWT_ALGO
    )

    audit(
        "user.login",
        f"user={username} ip={request.remote_addr}",
        username
    )

    return jsonify({
        "token": token
    })


@app.route("/api/auth/mfa/register", methods=["POST"])
@token_required
def mfa_register():

    db = get_db()

    uid = request.user_id

    secret = pyotp.random_base32()

    db.execute(
        "UPDATE users SET mfa_seed=? WHERE id=?",
        (secret, uid)
    )

    db.commit()

    audit(
        "user.mfa_register",
        f"user_id={uid}",
        uid
    )

    return jsonify({
        "mfa_secret": secret,
        "qr_uri": pyotp.totp.TOTP(secret).provisioning_uri(
            name=uid,
            issuer_name="DemoPayment"
        )
    })


# ---------------- PAYMENTS ----------------

@app.route("/api/payments", methods=["POST"])
@token_required
def create_payment():

    data = request.json or {}

    payer = data.get("payer")
    payee = data.get("payee")

    try:
        amount = float(data.get("amount", 0))
    except:
        return jsonify({"error": "invalid amount"}), 400

    currency = data.get("currency", "USD")
    desc = data.get("description", "")

    if amount <= 0:
        return jsonify({"error": "invalid amount"}), 400

    pid = str(uuid.uuid4())

    status = "recorded"

    db = get_db()

    if amount >= HIGH_VALUE_THRESHOLD:

        status = "pending"

        db.execute(
            """
            INSERT INTO payments
            (id,payer,payee,amount,currency,description,status,created_at)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                pid,
                payer,
                payee,
                amount,
                currency,
                desc,
                status,
                int(time.time())
            )
        )

        otp = ("%06d" % (int(time.time()) % 1000000))

        expires = int(time.time()) + 300

        db.execute(
            """
            INSERT INTO pending_approvals
            (id,payment_id,otp,expires_at)
            VALUES (?,?,?,?)
            """,
            (
                str(uuid.uuid4()),
                pid,
                otp,
                expires
            )
        )

        db.commit()

        audit(
            "transaction.pending",
            f"id={pid} payer={payer} amount={amount}",
            request.user_id
        )

        print(
            f"[DEMO OTP] payment_id={pid} otp={otp} (expires in 300s)"
        )

        return jsonify({
            "id": pid,
            "status": status,
            "note": "otp_sent_to_owner_simulated"
        }), 201

    db.execute(
        """
        INSERT INTO payments
        (id,payer,payee,amount,currency,description,status,created_at)
        VALUES (?,?,?,?,?,?,?,?)
        """,
        (
            pid,
            payer,
            payee,
            amount,
            currency,
            desc,
            status,
            int(time.time())
        )
    )

    db.commit()

    audit(
        "payment.create",
        f"id={pid} payer={payer} payee={payee} amount={amount}",
        request.user_id
    )

    return jsonify({
        "id": pid,
        "status": status
    }), 201


@app.route("/api/payments/<pid>/approve", methods=["POST"])
@token_required
def approve_payment(pid):

    data = request.json or {}

    otp = data.get("otp")

    db = get_db()

    row = db.execute(
        """
        SELECT id, payment_id, otp, expires_at
        FROM pending_approvals
        WHERE payment_id=?
        """,
        (pid,)
    ).fetchone()

    if not row:
        return jsonify({
            "error": "no pending approval"
        }), 404

    if int(time.time()) > row["expires_at"]:

        audit(
            "transaction.expired",
            f"payment_id={pid}",
            request.user_id
        )

        return jsonify({
            "error": "otp expired"
        }), 400

    if otp != row["otp"]:

        audit(
            "transaction.approve_fail",
            f"payment_id={pid}",
            request.user_id
        )

        return jsonify({
            "error": "invalid otp"
        }), 401

    db.execute(
        "UPDATE payments SET status='approved' WHERE id=?",
        (pid,)
    )

    db.execute(
        "DELETE FROM pending_approvals WHERE id=?",
        (row["id"],)
    )

    db.commit()

    audit(
        "transaction.approved",
        f"payment_id={pid}",
        request.user_id
    )

    return jsonify({
        "payment_id": pid,
        "status": "approved"
    }), 200


@app.route("/api/payments", methods=["GET"])
@token_required
def list_payments():

    db = get_db()

    rows = db.execute(
        """
        SELECT
        id,payer,payee,amount,currency,
        description,status,created_at
        FROM payments
        ORDER BY created_at DESC
        LIMIT 200
        """
    ).fetchall()

    return jsonify([dict(r) for r in rows])


@app.route("/api/audit", methods=["GET"])
@token_required
def get_audit():

    db = get_db()

    rows = db.execute(
        """
        SELECT
        id,event_type,detail,actor,ts
        FROM audit_logs
        ORDER BY ts DESC
        LIMIT 200
        """
    ).fetchall()

    return jsonify([dict(r) for r in rows])


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok"
    })


# ---------------- RUN ----------------

if __name__ == "__main__":

    use_ssl = os.environ.get("USE_SSL", "0") == "1"

    if use_ssl:

        cert = os.environ.get("SSL_CERT", "cert.pem")
        key = os.environ.get("SSL_KEY", "key.pem")

        app.run(
            host="0.0.0.0",
            port=5001,
            debug=True,
            ssl_context=(cert, key)
        )

    else:

        app.run(
            host="127.0.0.1",
            port=5000,
            debug=True
        )
