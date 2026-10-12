"""
FamPay Payment Verification Gateway  (Flask)

index.html dashboard ka poora backend:
  signup / login, Gmail connect (16-letter App Password), API key, verify.php, qr.php,
  transactions, stats, live test, subscription.
Gmail IMAP wala kaam gmail_payment.py me hai.

Run:  pip install -r requirements.txt  ->  python app.py
"""
import base64
import hashlib
import io
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from html import escape
from urllib.parse import quote, urlencode, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_env(path):
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
                v = v[1:-1]
            elif " #" in v:
                v = v.split(" #", 1)[0].strip()
            os.environ.setdefault(k.strip(), v)


_load_env(os.path.join(BASE_DIR, ".env"))

from cryptography.fernet import Fernet, InvalidToken  # noqa: E402
from flask import Flask, Response, abort, g, jsonify, redirect, request, send_file, session  # noqa: E402
from werkzeug.middleware.proxy_fix import ProxyFix  # noqa: E402
from werkzeug.security import check_password_hash, generate_password_hash  # noqa: E402

import gmail_payment as gp  # noqa: E402


# ============================================================ config
def env(name, default=""):
    return (os.getenv(name) or default).strip()


IST = timezone(timedelta(hours=5, minutes=30))
SUB_AMOUNT = int(env("SUBSCRIPTION_AMOUNT", "99"))
SUB_DAYS = int(env("SUBSCRIPTION_DAYS", "30"))
REQUIRE_SUB = True   # Premium plan khareedna zaroori hai (free use band)
OWNER_EMAILS = {e.strip().lower() for e in env("OWNER_EMAILS").split(",") if e.strip()}
ADMIN_UPI, ADMIN_GMAIL, ADMIN_APP_PW = env("ADMIN_UPI"), env("ADMIN_GMAIL"), env("ADMIN_APP_PASSWORD")
PUBLIC_URL = env("PUBLIC_URL").rstrip("/")
SUPPORT_TG = env("SUPPORT_TELEGRAM").lstrip("@")
DEV_TAG = "@" + SUPPORT_TG if SUPPORT_TG else ""
PAYEE_NAME = env("PAYEE_NAME", "Payment")
DB_PATH = env("DB_PATH", os.path.join(BASE_DIR, "fampay.db"))
SUB_PAY_WINDOW = 2 * 3600          # subscription payment 2 ghante se purana na ho
FAR_FUTURE = 4102444800            # 2100-01-01
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
UPI_RE = re.compile(r"^[A-Za-z0-9.\-_]{2,64}@[A-Za-z][A-Za-z0-9]{1,31}$")
UTR_RE = re.compile(r"\d{12}")


def _secret():
    s = env("SECRET_KEY")
    if s:
        return s
    path = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    s = secrets.token_hex(32)
    try:
        with open(path, "w") as f:
            f.write(s)
        os.chmod(path, 0o600)
    except OSError:
        raise RuntimeError("Folder is not writable - set SECRET_KEY=<long random string> in .env.")
    return s


SECRET = _secret()
FERNET = Fernet(base64.urlsafe_b64encode(hashlib.sha256(("gmail-pw|" + SECRET).encode()).digest()))

app = Flask(__name__)
app.secret_key = SECRET
app.json.sort_keys = False
app.json.ensure_ascii = False
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=PUBLIC_URL.startswith("https"),
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    MAX_CONTENT_LENGTH=64 * 1024,
)
if env("TRUST_PROXY", "1") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


# ============================================================ database
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  pw_hash TEXT NOT NULL, sub_start INTEGER, sub_end INTEGER, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS gateways(
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, mobile TEXT,
  gmail TEXT NOT NULL UNIQUE, app_pw TEXT NOT NULL, api_key TEXT NOT NULL UNIQUE, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS orders(
  order_id TEXT PRIMARY KEY, user_id INTEGER, kind TEXT NOT NULL, upi_id TEXT NOT NULL, amount TEXT NOT NULL,
  created INTEGER NOT NULL, expires INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, utr TEXT NOT NULL, transaction_id TEXT,
  sender_name TEXT, amount REAL NOT NULL, paid INTEGER NOT NULL, created INTEGER NOT NULL,
  UNIQUE(user_id, utr));
CREATE TABLE IF NOT EXISTS sub_payments(
  utr TEXT PRIMARY KEY, user_id INTEGER NOT NULL, order_id TEXT, amount REAL, created INTEGER NOT NULL);
"""


def init_db():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript(SCHEMA)
    c.commit()
    c.close()


init_db()


def db():
    if "db" not in g:
        c = sqlite3.connect(DB_PATH, timeout=15)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        g.db = c
    return g.db


@app.teardown_appcontext
def _close_db(_exc):
    c = g.pop("db", None)
    if c is not None:
        c.close()


# ============================================================ small helpers
def ts_iso(ts):
    return datetime.fromtimestamp(ts, IST).isoformat(timespec="seconds") if ts else None


def ist_str(ts):
    return datetime.fromtimestamp(ts, IST).strftime("%d-%m-%Y %H:%M:%S")


def num(x):
    x = float(x)
    return int(x) if x == int(x) else round(x, 2)


def enc(s):
    return FERNET.encrypt(s.encode()).decode()


def dec(s):
    try:
        return FERNET.decrypt(s.encode()).decode()
    except InvalidToken:
        raise gp.GmailError("Stored Gmail password could not be read. Please reconnect Gmail on the API Key page.")


def body():
    b = request.get_json(silent=True)
    return b if isinstance(b, dict) else {}


def jerr(msg, code=400):
    return jsonify(ok=False, error=msg), code


def base_url():
    return PUBLIC_URL or request.host_url.rstrip("/")


_hits, _hits_lock = defaultdict(deque), threading.Lock()


def blocked(key, limit, window):
    now = time.time()
    with _hits_lock:
        q = _hits[key]
        while q and q[0] <= now - window:
            q.popleft()
        return len(q) >= limit


def record(key):
    with _hits_lock:
        if len(_hits) > 10000:
            for k in [k for k, q in _hits.items() if not q or q[-1] < time.time() - 3600]:
                _hits.pop(k, None)
        _hits[key].append(time.time())


def throttle(key, limit, window):
    """True => limit paar ho gayi."""
    if blocked(key, limit, window):
        return True
    record(key)
    return False


def client_ip():
    return request.remote_addr or "0.0.0.0"


@app.before_request
def _origin_guard():
    if request.method == "POST":
        origin = request.headers.get("Origin")
        if origin:
            allowed = {request.host}
            if PUBLIC_URL:
                allowed.add(urlparse(PUBLIC_URL).netloc)
            if urlparse(origin).netloc not in allowed:
                return jerr("Bad origin.", 403)


@app.after_request
def _headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if request.path in ("/", "/index.php", "/verify.php", "/qr.php", "/verify", "/qr"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def sub_state(u):
    """(active, start_ts, end_ts)"""
    if u["email"] in OWNER_EMAILS:
        return True, u["created"], FAR_FUTURE
    on, until = admin.free_mode()      # admin panel se "sabko free" ON ho to sab active
    if on:
        return True, u["created"], until or FAR_FUTURE
    end = u["sub_end"] or 0
    return end > int(time.time()), u["sub_start"], end


def gateway_of(uid):
    return db().execute("SELECT * FROM gateways WHERE user_id=?", (uid,)).fetchone()


# ============================================================ dashboard page
def render_dashboard(u):
    path = os.path.join(BASE_DIR, "index.html")
    if not os.path.exists(path):
        return Response("index.html not found. Put your dashboard index.html in the same folder as app.py.",
                        500, mimetype="text/plain")
    with open(path, encoding="utf-8") as f:
        html = f.read()
    html = html.replace("https://gateway.anujbots.in", base_url())
    html = html.replace("anujffseller@fam", "yourname@fam")
    html = re.sub(r"const SUBSCRIPTION_AMOUNT = \d+;", "const SUBSCRIPTION_AMOUNT = %d;" % SUB_AMOUNT, html)
    extra_css = ""
    if SUPPORT_TG:
        html = re.sub(r"anujxcoder", SUPPORT_TG, html, flags=re.I)
    else:
        html = re.sub(r',\s*"dev":\s*"@ANUJxCODER"', "", html)
        extra_css += ".tg-fab,.tg-pop{display:none!important}"
    if not REQUIRE_SUB:
        extra_css += '.nav-item[data-view="subscription"],#dashSubBanner{display:none!important}'
    if extra_css:
        html = html.replace("</head>", "<style>%s</style></head>" % extra_css, 1)
    if u:
        html = html.replace("const IS_LOGGED_IN = false;", "const IS_LOGGED_IN = true;", 1)
        html = html.replace('<div class="user-avatar">U</div>',
                            '<div class="user-avatar">%s</div>' % escape((u["name"][:1] or "U").upper()), 1)
        html = html.replace('<div class="name">User</div>', '<div class="name">%s</div>' % escape(u["name"]), 1)
        html = html.replace('<div class="email"></div>', '<div class="email">%s</div>' % escape(u["email"]), 1)
    return Response(html, mimetype="text/html")


def render_landing():
    path = os.path.join(BASE_DIR, "landing.html")
    if not os.path.exists(path):
        return redirect("/app")
    with open(path, encoding="utf-8") as f:
        html = f.read()
    html = html.replace("__SITE_NAME__", escape(PAYEE_NAME if PAYEE_NAME != "Payment" else "Fam Pay"))
    html = html.replace("__SUPPORT_TG__", escape(SUPPORT_TG or "famgateway"))
    return Response(html, mimetype="text/html")


@app.get("/")
def home():
    u = current_user()
    if u:
        return render_dashboard(u)
    return render_landing()


@app.get("/app")
def app_entry():
    return render_dashboard(current_user())


@app.get("/health")
def health():
    return jsonify(ok=True)


# ============================================================ action router  (index.php?action=...)
ACTIONS = {}
# Bina paid plan ke sirf ye (Integrations + API Key) band hain. Baaki sab free chalta hai.
PREMIUM_ACTIONS = {"connect", "regen_key", "delete_key", "live_test", "get_active_qr", "verify_subscription"}


def action(name, methods=("POST",), login=True):
    def deco(fn):
        ACTIONS[name] = (fn, methods, login)
        return fn
    return deco


@app.route("/index.php", methods=["GET", "POST"])
def index_php():
    name = request.args.get("action")
    if not name:
        return render_dashboard(current_user())
    entry = ACTIONS.get(name)
    if not entry:
        return jerr("Unknown action.", 404)
    fn, methods, login = entry
    if request.method not in methods:
        return jerr("Method not allowed.", 405)
    if login:
        u = current_user()
        if not u:
            return jerr("Please sign in again.", 401)
        if name in PREMIUM_ACTIONS and not sub_state(u)[0]:
            return jerr("Premium plan required. Please buy a plan from Plans first.", 403)
        return fn(u)
    return fn()


# ------------------------------------------------------------ auth
@action("signup", login=False)
def a_signup():
    b = body()
    name = str(b.get("name", "")).strip()[:60]
    mail = str(b.get("email", "")).strip().lower()[:120]
    pw = str(b.get("password", ""))
    if not name or not EMAIL_RE.match(mail):
        return jerr("Please enter your name and a valid email.")
    if len(pw) < 6:
        return jerr("Password must be at least 6 characters.")
    if throttle("signup:" + client_ip(), 10, 3600):
        return jerr("Too many attempts. Please try again later.", 429)
    try:
        db().execute("INSERT INTO users(name,email,pw_hash,created) VALUES(?,?,?,?)",
                     (name, mail, generate_password_hash(pw), int(time.time())))
        db().commit()
    except sqlite3.IntegrityError:
        return jerr("This email is already registered.")
    # Pehla user, ya OWNER_EMAILS me listed email -> apne aap admin ban jata hai.
    total_users = db().execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    if mail in OWNER_EMAILS or total_users == 1:
        db().execute("UPDATE users SET is_admin=1 WHERE email=?", (mail,))
        db().commit()
    return jsonify(ok=True, message="Account created! Please sign in.")


@action("login", login=False)
def a_login():
    b = body()
    mail = str(b.get("email", "")).strip().lower()
    pw = str(b.get("password", ""))
    if blocked("login:" + client_ip(), 15, 600) or blocked("loginm:" + mail, 10, 600):
        return jerr("Too many failed attempts. Please wait a few minutes.", 429)
    u = db().execute("SELECT * FROM users WHERE email=?", (mail,)).fetchone()
    if not u or not check_password_hash(u["pw_hash"], pw):
        record("login:" + client_ip())
        record("loginm:" + mail)
        return jerr("Invalid email or password.", 401)
    if u["banned"]:
        return jerr("Your account has been suspended. Please contact support.", 403)
    session.clear()
    session["uid"] = u["id"]
    session.permanent = True
    return jsonify(ok=True)


@action("logout", login=False)
def a_logout():
    session.clear()
    return jsonify(ok=True)


# ------------------------------------------------------------ subscription state / stats / transactions
@action("sub_status")
def a_sub_status(u):
    active, start, end = sub_state(u)
    return jsonify(ok=True, user={
        "name": u["name"], "email": u["email"],
        "subscription_status": "active" if active else "inactive",
        "subscription_start": ts_iso(start), "subscription_end": ts_iso(end)})


def _range_start(f):
    now = datetime.now(IST)
    day0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if f == "today":
        return int(day0.timestamp())
    if f == "week":
        return int((now - timedelta(days=7)).timestamp())
    if f == "month":
        return int(day0.replace(day=1).timestamp())
    return 0


def _sum(uid, since):
    r = db().execute("SELECT COALESCE(SUM(amount),0) t, COUNT(*) c FROM transactions WHERE user_id=? AND paid>=?",
                     (uid, since)).fetchone()
    return {"t": round(r["t"], 2), "c": r["c"]}


@action("stats")
def a_stats(u):
    return jsonify(ok=True, stats={k: _sum(u["id"], _range_start(k)) for k in ("today", "month")}
                   | {"total": _sum(u["id"], 0)})


@action("transactions", methods=("GET", "POST"))
def a_transactions(u):
    since = _range_start(request.args.get("filter", "all"))
    rows = db().execute("SELECT utr,transaction_id,sender_name,amount,paid,created FROM transactions "
                        "WHERE user_id=? AND paid>=? ORDER BY paid DESC LIMIT 500", (u["id"], since)).fetchall()
    return jsonify(ok=True, summary=_sum(u["id"], since), transactions=[{
        "utr": r["utr"], "transaction_id": r["transaction_id"], "sender_name": r["sender_name"],
        "amount": r["amount"], "payment_time_ist": ts_iso(r["paid"]), "created_at": ts_iso(r["created"])}
        for r in rows])


# ------------------------------------------------------------ orders / QR
def upi_uri(upi, amount, note):
    q = urlencode({"pa": upi, "pn": PAYEE_NAME, "am": "%.2f" % float(amount), "cu": "INR", "tn": note},
                  quote_via=quote)
    return "upi://pay?" + q


def make_order(user_id, kind, upi, amount):
    now = int(time.time())
    db().execute("DELETE FROM orders WHERE status!='paid' AND created<?", (now - 86400,))
    oid = "FAMPAY" + datetime.now(IST).strftime("%Y%m%d%H%M%S") + secrets.token_hex(4).upper()
    db().execute("INSERT INTO orders(order_id,user_id,kind,upi_id,amount,created,expires) VALUES(?,?,?,?,?,?,?)",
                 (oid, user_id, kind, upi, str(amount), now, now + 300))
    db().commit()
    return db().execute("SELECT * FROM orders WHERE order_id=?", (oid,)).fetchone()


@app.get("/qr_codes/<order_id>.png")
def qr_png(order_id):
    o = db().execute("SELECT upi_id, amount FROM orders WHERE order_id=?", (order_id,)).fetchone()
    if not o:
        abort(404)
    uri = upi_uri(o["upi_id"], o["amount"], order_id)
    try:
        import qrcode
    except ImportError:  # library na ho to free QR service par redirect
        return redirect("https://api.qrserver.com/v1/create-qr-code/?size=400x400&margin=10&data="
                        + quote(uri, safe=""), 302)
    buf = io.BytesIO()
    qrcode.make(uri, box_size=10, border=2).save(buf)
    buf.seek(0)
    resp = send_file(buf, mimetype="image/png")
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


@action("get_active_qr")
def a_get_active_qr(u):
    renew = bool(body().get("renew"))
    active, _, _ = sub_state(u)
    if active and not renew:
        return jsonify(ok=True, already_active=True)
    if not REQUIRE_SUB or u["email"] in OWNER_EMAILS:
        return jerr("Subscription is not required on this server.")
    if not (ADMIN_UPI and ADMIN_GMAIL and ADMIN_APP_PW):
        return jerr("Payments are not configured yet. Please contact support.", 503)
    o = db().execute("SELECT * FROM orders WHERE user_id=? AND kind='sub' AND status='pending' AND expires>? "
                     "ORDER BY created DESC LIMIT 1", (u["id"], int(time.time()))).fetchone()
    if not o:
        o = make_order(u["id"], "sub", ADMIN_UPI, SUB_AMOUNT)
    return jsonify(ok=True, order={
        "order_id": o["order_id"], "qr_url": "%s/qr_codes/%s.png" % (base_url(), o["order_id"]),
        "upi_id": o["upi_id"], "amount": o["amount"], "expires_at": ts_iso(o["expires"])})


@action("verify_subscription")
def a_verify_subscription(u):
    if not REQUIRE_SUB or u["email"] in OWNER_EMAILS:
        return jerr("Subscription is not required on this server.")
    if not (ADMIN_GMAIL and ADMIN_APP_PW):
        return jerr("Payments are not configured yet. Please contact support.", 503)
    b = body()
    utr, oid = str(b.get("utr", "")).strip(), str(b.get("order_id", "")).strip()
    if not UTR_RE.fullmatch(utr):
        return jerr("Please enter a valid 12-digit UTR.")
    if throttle("subv:%d" % u["id"], 10, 300):
        return jerr("Too many attempts. Please wait a few minutes.", 429)
    order = db().execute("SELECT * FROM orders WHERE order_id=? AND user_id=? AND kind='sub'",
                         (oid, u["id"])).fetchone()
    if not order:
        return jerr("Order not found. Please refresh the QR and try again.")
    if db().execute("SELECT 1 FROM sub_payments WHERE utr=?", (utr,)).fetchone():
        return jerr("This UTR has already been used.")
    try:
        pay = gp.find_payment(ADMIN_GMAIL, ADMIN_APP_PW, utr)
    except gp.PaymentNotFound:
        return jerr("Payment not found yet. If you have paid, wait a minute and try again.")
    except (gp.MailRejected, gp.GmailError) as e:
        app.logger.warning("subscription verify failed: %s", e)  # asli wajah sirf server log me
        return jerr("We could not verify this payment right now. Please contact support with your UTR.")
    if pay["amount"] + 1e-9 < SUB_AMOUNT:
        return jerr("Amount received is Rs %s but Rs %s is required." % (num(pay["amount"]), SUB_AMOUNT))
    now, paid_ts = int(time.time()), int(pay["paid_at"].timestamp())
    if paid_ts < now - SUB_PAY_WINDOW:
        return jerr("This payment is too old to activate a subscription.")
    try:
        db().execute("INSERT INTO sub_payments(utr,user_id,order_id,amount,created) VALUES(?,?,?,?,?)",
                     (utr, u["id"], oid, pay["amount"], now))
    except sqlite3.IntegrityError:
        return jerr("This UTR has already been used.")
    old_end = u["sub_end"] or 0
    was_renewal = old_end > now
    remaining = math.ceil((old_end - now) / 86400) if was_renewal else 0
    new_end = (old_end if was_renewal else now) + SUB_DAYS * 86400
    db().execute("UPDATE users SET sub_start=?, sub_end=? WHERE id=?",
                 (u["sub_start"] if was_renewal and u["sub_start"] else now, new_end, u["id"]))
    db().execute("UPDATE orders SET status='paid' WHERE order_id=?", (oid,))
    db().commit()
    return jsonify(ok=True, message="Payment verified. Your subscription is now active.",
                   valid_until=ts_iso(new_end), was_renewal=was_renewal, remaining_days=remaining,
                   added_days=SUB_DAYS, total_days=remaining + SUB_DAYS)


# ------------------------------------------------------------ Gmail connect / API key
@action("api_info")
def a_api_info(u):
    active, _, _ = sub_state(u)
    if not active:  # Premium nahi -> API key / Gmail details server se hi nahi jaate
        return jsonify(ok=True, data=None, locked=True)
    gw = gateway_of(u["id"])
    if not gw:
        return jsonify(ok=True, data=None, locked=False)
    return jsonify(ok=True, data={"api_key": gw["api_key"], "gmail": gw["gmail"], "mobile": gw["mobile"],
                                  "status": "active"}, locked=False)


@action("connect")
def a_connect(u):
    if not sub_state(u)[0]:
        return jerr("Active subscription required to generate API Key.", 403)
    b = body()
    mobile = re.sub(r"\D", "", str(b.get("mobile", "")))
    gmail = str(b.get("gmail", "")).strip().lower()
    app_pw = gp.clean_app_password(str(b.get("app_password", "")))
    if mobile and not re.fullmatch(r"[6-9]\d{9}", mobile):
        return jerr("Enter a valid 10-digit mobile number.")
    if not EMAIL_RE.match(gmail):
        return jerr("Enter a valid Gmail address.")
    if not gp.valid_app_password(app_pw):
        return jerr("App Password must be 16 letters. Create one at myaccount.google.com/apppasswords.")
    if throttle("connect:%d" % u["id"], 8, 600):
        return jerr("Too many attempts. Please wait a few minutes.", 429)
    if db().execute("SELECT 1 FROM gateways WHERE gmail=? AND user_id!=?", (gmail, u["id"])).fetchone():
        return jerr("This Gmail is already connected to another account.")
    try:
        gp.check_login(gmail, app_pw)
    except gp.GmailError as e:
        return jerr(str(e))
    db().execute("INSERT OR REPLACE INTO gateways(user_id,mobile,gmail,app_pw,api_key,created) VALUES(?,?,?,?,?,?)",
                 (u["id"], mobile, gmail, enc(app_pw), "fam_" + secrets.token_hex(16), int(time.time())))
    db().commit()
    return jsonify(ok=True, message="Gmail connected successfully. Your API key is ready.")


@action("delete_key")
def a_delete_key(u):
    db().execute("DELETE FROM gateways WHERE user_id=?", (u["id"],))
    db().commit()
    return jsonify(ok=True)


# ============================================================ verification core (verify.php + live test)
def _ok_payload(utr, txn, amount, sender, paid_ts, already=False):
    out = {"status": "success", "data": {
        "utr": utr, "transaction_id": txn, "amount": num(amount),
        "sender_name": sender or "Unknown", "payment_time_ist": ist_str(paid_ts)}}
    if already:
        out["already_verified"] = True
    return out


def verify_for_gateway(gw, utr, record_tx=True, min_amount=None):
    """(payload, http_status). Public verify.php wali shape me payload."""
    if record_tx:
        prior = db().execute("SELECT * FROM transactions WHERE user_id=? AND utr=?",
                             (gw["user_id"], utr)).fetchone()
        if prior:  # pehle verify ho chuka: Gmail dobara hit nahi, replay pehchaan ke liye flag
            return _ok_payload(utr, prior["transaction_id"], prior["amount"], prior["sender_name"],
                               prior["paid"], already=True), 200
    try:
        pay = gp.find_payment(gw["gmail"], dec(gw["app_pw"]), utr)
    except (gp.PaymentNotFound, gp.MailRejected) as e:
        return {"status": "error", "message": str(e)}, 200
    except gp.GmailError as e:
        return {"status": "error", "message": str(e)}, 502
    if min_amount is not None and pay["amount"] + 1e-9 < min_amount:
        return {"status": "error", "message": "Amount mismatch: received %s, expected %s."
                                               % (num(pay["amount"]), num(min_amount))}, 200
    paid_ts = int(pay["paid_at"].timestamp())
    if record_tx:
        db().execute("INSERT OR IGNORE INTO transactions(user_id,utr,transaction_id,sender_name,amount,paid,created)"
                     " VALUES(?,?,?,?,?,?,?)", (gw["user_id"], utr, pay["transaction_id"], pay["sender_name"],
                                                pay["amount"], paid_ts, int(time.time())))
        db().commit()
    return _ok_payload(utr, pay["transaction_id"], pay["amount"], pay["sender_name"], paid_ts), 200


def api_reply(payload, code=200):
    if DEV_TAG:
        payload["dev"] = DEV_TAG
    return jsonify(payload), code


@app.get("/verify.php")
@app.get("/verify")
def verify_api():
    ip = client_ip()
    if throttle("verify:" + ip, 60, 60) or blocked("badkey:" + ip, 20, 600):
        return api_reply({"status": "error", "message": "Too many requests. Please slow down."}, 429)
    utr = request.args.get("utr", "").strip()
    key = request.args.get("api_key", "").strip()
    if not utr or not key:
        return api_reply({"status": "error", "message": "Both utr and api_key are required."}, 400)
    if not UTR_RE.fullmatch(utr):
        return api_reply({"status": "error", "message": "Invalid UTR. It must be exactly 12 digits."}, 400)
    min_amount = None
    if request.args.get("amount"):
        try:
            min_amount = float(request.args["amount"])
        except ValueError:
            return api_reply({"status": "error", "message": "Invalid amount."}, 400)
    gw = db().execute("SELECT * FROM gateways WHERE api_key=?", (key,)).fetchone()
    if not gw:
        record("badkey:" + ip)
        return api_reply({"status": "error", "message": "Invalid API key."}, 401)
    owner = db().execute("SELECT * FROM users WHERE id=?", (gw["user_id"],)).fetchone()
    if not owner or not sub_state(owner)[0]:
        return api_reply({"status": "error", "message": "Subscription is not active. Please renew."}, 403)
    already = db().execute("SELECT 1 FROM transactions WHERE user_id=? AND utr=?", (gw["user_id"], utr)).fetchone()
    if not already:
        msg = admin.check_limit(gw["user_id"], "txn", min_amount)
        if msg:
            return api_reply({"status": "error", "message": msg}, 403)
    payload, code = verify_for_gateway(gw, utr, True, min_amount)
    return api_reply(payload, code)


@action("live_test")
def a_live_test(u):
    gw = gateway_of(u["id"])
    if not gw:
        return jerr("Connect your Gmail on the API Key page first.")
    if not sub_state(u)[0]:
        return jerr("Your subscription is not active.", 403)
    utr = str(body().get("utr", "")).strip()
    if not UTR_RE.fullmatch(utr):
        return jerr("Enter a valid 12-digit UTR.")
    if throttle("live:%d" % u["id"], 20, 60):
        return jerr("Too many tests. Please wait a minute.", 429)
    payload, _ = verify_for_gateway(gw, utr, record_tx=False)
    return jsonify(ok=True, result=payload)


# ============================================================ qr.php  (public QR generate API)
@app.get("/qr.php")
@app.get("/qr")
def qr_api():
    if throttle("qr:" + client_ip(), 30, 60):
        return api_reply({"status": "error", "message": "Too many requests. Please slow down."}, 429)
    upi = request.args.get("upi", "").strip()
    try:
        amount = float(request.args.get("amount", ""))
    except ValueError:
        amount = 0
    if not UPI_RE.match(upi):
        return api_reply({"status": "error", "message": "Invalid UPI ID."}, 400)
    if not (0 < amount <= 100000):
        return api_reply({"status": "error", "message": "Amount must be between 1 and 100000."}, 400)
    o = make_order(None, "qr", upi, num(amount))
    return api_reply({"status": "success", "data": {
        "order_id": o["order_id"], "qr_url": "%s/qr_codes/%s.png" % (base_url(), o["order_id"]),
        "upi_id": upi, "amount": str(o["amount"]),
        "created_at_ist": ist_str(o["created"]), "expires_at_ist": ist_str(o["expires"])}})


import sys  # noqa: E402
import autopay  # noqa: E402
import admin  # noqa: E402

autopay.init(app, sys.modules[__name__])  # auto payment: /api.php, /pay/<id>, payment links, profile
admin.init(app, sys.modules[__name__])    # full admin panel + plans system + FamGateway auto-verify


if __name__ == "__main__":
    # Production me:  gunicorn -w 1 --threads 8 -b 0.0.0.0:8000 app:app
    app.run(host="0.0.0.0", port=int(env("PORT", "8000")), debug=False)
