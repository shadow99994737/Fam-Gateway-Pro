"""
admin.py  -  Standalone Admin Panel (admin.html) + Plans system + FamGateway (famgateway.in) auto-verify.

app.py ke end me judta hai (autopay ki tarah):
    import admin
    admin.init(app, sys.modules[__name__])

Kya milta hai:
  - /admin            -> standalone admin.html (apna login screen)
  - /admin.php?action=login|logout|status|stats|users|user_set|user_delete|
                         plans|plan_save|plan_delete|orders|settings_get|settings_save
    Ye sab SIRF fixed admin username/password se gate hote hain (regular user account se
    koi lena dena nahi - koi bhi normal user, chahe uska is_admin flag set ho, is panel
    me login nahi kar sakta. Sirf neeche diye ADMIN_USER / ADMIN_PASS se hi access milta hai).
  - plans table: admin jitne chahe plans bana sakta hai (name, price, duration, features)
  - plan_orders table: FamGateway ke through plan purchase orders track hote hain
  - settings table: FamGateway API key, site name waghera - admin panel se hi edit ho sakte hain
  - /index.php?action=plans_list / plan_checkout / plan_status (normal logged-in app users ke liye)
  - /famgateway/webhook  -> FamGateway se instant payment.success callback (HMAC verified)
"""
import hashlib
import hmac
import json
import os
import sqlite3
import time

from flask import Blueprint, Response, jsonify, request, session

import gateway as fg

M = None  # app.py module
bp = Blueprint("admin_panel", __name__)

# ---- Fixed admin credentials. Sirf ye login kar sakta hai - koi normal user account nahi. ----
ADMIN_USER = os.getenv("ADMIN_USER", "shadow_papa")      # Railway Variables me ADMIN_USER / ADMIN_PASS set karke badlo
ADMIN_PASS = os.getenv("ADMIN_PASS", "shadow93373")
ADMIN_SESS_KEY = "sh_admin_ok"

SCHEMA = """
CREATE TABLE IF NOT EXISTS plans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, price REAL NOT NULL,
  duration_days INTEGER NOT NULL, features TEXT NOT NULL DEFAULT '[]',
  active INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL,
  link_limit INTEGER NOT NULL DEFAULT 0, transaction_limit INTEGER NOT NULL DEFAULT 0,
  api_order_limit INTEGER NOT NULL DEFAULT 0, max_amount REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS plan_orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, plan_id INTEGER NOT NULL,
  fg_order_id TEXT NOT NULL UNIQUE, amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
  checkout_url TEXT, qr_url TEXT, upi_intent TEXT, utr TEXT, created INTEGER NOT NULL, paid_at INTEGER);
CREATE INDEX IF NOT EXISTS ix_po_user ON plan_orders(user_id, status);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""


class AErr(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.msg, self.code = msg, code


def fail(msg, code=400):
    r = jsonify(ok=False, error=msg)
    r.status_code = code
    return r


def ok(**kw):
    kw["ok"] = True
    return jsonify(kw)


# ============================================================ settings helpers
def get_setting(key, default=""):
    r = M.db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r and r["value"] is not None else default


def set_setting(key, value):
    M.db().execute("INSERT INTO settings(key,value) VALUES(?,?) "
                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
    M.db().commit()


def free_mode():
    """(on, until_ts). Admin ne 'sabko free' ON kiya ho (aur time khatam na hua ho) to on=True. until=0 => manual off tak."""
    if get_setting("free_for_all", "0") != "1":
        return False, 0
    try:
        until = int(get_setting("free_until", "0") or 0)
    except ValueError:
        until = 0
    if until and until <= int(time.time()):
        return False, 0
    return True, until


def gateway_key():
    k = get_setting("famgateway_api_key", "")
    return k or M.env("FAMGATEWAY_API_KEY", "")


# ============================================================ fixed-credential admin auth
def admin_logged_in():
    return bool(session.get(ADMIN_SESS_KEY))


def require_admin(fn):
    def wrap(*a, **kw):
        if not admin_logged_in():
            return fail("Admin login required.", 401)
        try:
            return fn(*a, **kw)
        except AErr as e:
            return fail(e.msg, e.code)
    wrap.__name__ = fn.__name__
    return wrap


def a_admin_login():
    b = M.body()
    user = str(b.get("username", "")).strip()
    pw = str(b.get("password", ""))
    ip_key = "adminlogin:" + M.client_ip()
    if M.blocked(ip_key, 8, 600):
        return fail("Too many failed attempts. Please wait a few minutes.", 429)
    good = hmac.compare_digest(user, ADMIN_USER) and hmac.compare_digest(pw, ADMIN_PASS)
    if not good:
        M.record(ip_key)
        return fail("Invalid username or password.", 401)
    session[ADMIN_SESS_KEY] = True
    session.permanent = True
    return ok(message="Logged in.")


def a_admin_logout():
    session.pop(ADMIN_SESS_KEY, None)
    return ok(message="Logged out.")


def a_admin_status():
    return ok(logged_in=admin_logged_in())


def plan_public(p):
    try:
        feats = json.loads(p["features"]) if p["features"] else []
    except ValueError:
        feats = []
    return {"id": p["id"], "name": p["name"], "price": M.num(p["price"]),
            "duration_days": p["duration_days"], "features": feats,
            "active": bool(p["active"]), "sort_order": p["sort_order"],
            "link_limit": p["link_limit"] or 0, "transaction_limit": p["transaction_limit"] or 0,
            "api_order_limit": p["api_order_limit"] or 0, "max_amount": M.num(p["max_amount"] or 0)}


# ============================================================ plan limits  (0 = unlimited)
LIMIT_LABELS = {"link": "payment links", "txn": "transactions", "api": "API orders"}


def _plan_of(uid):
    """(user_row, plan_row) - plan sirf tab jab user ka plan set ho aur subscription chal rahi ho."""
    d = M.db()
    u = d.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u or not u["plan_id"] or u["email"] in M.OWNER_EMAILS:
        return u, None
    if not M.sub_state(u)[0]:
        return u, None
    return u, d.execute("SELECT * FROM plans WHERE id=?", (u["plan_id"],)).fetchone()


def plan_usage(uid):
    """Current plan cycle (plan_start se) ka usage."""
    d = M.db()
    u = d.execute("SELECT plan_start, sub_start FROM users WHERE id=?", (uid,)).fetchone()
    since = (u["plan_start"] or u["sub_start"] or 0) if u else 0
    links = d.execute("SELECT COUNT(*) c FROM pay_orders WHERE user_id=? AND src='link' AND created>=?",
                      (uid, since)).fetchone()["c"]
    api_orders = d.execute("SELECT COUNT(*) c FROM pay_orders WHERE user_id=? AND src='api' AND created>=?",
                           (uid, since)).fetchone()["c"]
    txn = d.execute("SELECT COUNT(*) c FROM transactions WHERE user_id=? AND created>=?", (uid, since)).fetchone()["c"]
    txn += d.execute("SELECT COUNT(*) c FROM pay_orders WHERE user_id=? AND status='success' AND paid_at>=?",
                     (uid, since)).fetchone()["c"]
    return {"links": links, "api_orders": api_orders, "transactions": txn}


def check_limit(uid, kind, amount=None):
    """Limit cross ho gayi to error message (str) return karta hai, warna None.
    kind: 'link' | 'api' | 'txn'.  amount: rupees (max_amount check ke liye)."""
    u, p = _plan_of(uid)
    if not p:
        return None
    use = plan_usage(uid)
    if amount is not None and (p["max_amount"] or 0) > 0 and amount > p["max_amount"] + 1e-9:
        return "This plan allows a maximum of Rs %s per payment. Please upgrade." % M.num(p["max_amount"])
    if kind == "link" and (p["link_limit"] or 0) > 0 and use["links"] >= p["link_limit"]:
        return "Payment link limit reached (%d/%d). Please upgrade/renew your plan." % (use["links"], p["link_limit"])
    if kind == "api" and (p["api_order_limit"] or 0) > 0 and use["api_orders"] >= p["api_order_limit"]:
        return "API order limit reached (%d/%d). Please upgrade/renew your plan." % (use["api_orders"], p["api_order_limit"])
    if kind in ("link", "api", "txn") and (p["transaction_limit"] or 0) > 0 and use["transactions"] >= p["transaction_limit"]:
        return "Transaction limit reached (%d/%d). Please upgrade/renew your plan." % (use["transactions"], p["transaction_limit"])
    return None


# ============================================================ admin: dashboard stats
@require_admin
def a_admin_stats():
    d, now = M.db(), int(time.time())
    day0 = now - (now % 86400)
    users_c = d.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    active_subs = d.execute("SELECT COUNT(*) c FROM users WHERE sub_end>?", (now,)).fetchone()["c"]
    plans_c = d.execute("SELECT COUNT(*) c FROM plans WHERE active=1").fetchone()["c"]
    plan_rev = d.execute("SELECT COALESCE(SUM(amount),0) t, COUNT(*) c FROM plan_orders WHERE status='success'").fetchone()
    today_rev = d.execute("SELECT COALESCE(SUM(amount),0) t, COUNT(*) c FROM plan_orders "
                          "WHERE status='success' AND paid_at>=?", (day0,)).fetchone()
    gw_rev = d.execute("SELECT COALESCE(SUM(amount),0) t FROM transactions").fetchone()["t"]
    pending_orders = d.execute("SELECT COUNT(*) c FROM plan_orders WHERE status='pending' AND created>?",
                               (now - 3600,)).fetchone()["c"]
    today_signups = d.execute("SELECT COUNT(*) c FROM users WHERE created>=?", (day0,)).fetchone()["c"]
    return ok(stats={
        "total_users": users_c, "active_subscriptions": active_subs, "active_plans": plans_c,
        "plan_revenue_total": M.num(plan_rev["t"]), "plan_orders_paid": plan_rev["c"],
        "plan_revenue_today": M.num(today_rev["t"]), "plan_orders_today": today_rev["c"],
        "gateway_revenue_total": M.num(gw_rev), "pending_orders": pending_orders,
        "today_signups": today_signups, "free_for_all": free_mode()[0]})


# ============================================================ admin: users
@require_admin
def a_admin_users():
    q = str(request.args.get("q", "")).strip()
    rows = (M.db().execute(
        "SELECT u.*, p.name AS plan_name FROM users u LEFT JOIN plans p ON p.id=u.plan_id "
        "WHERE u.email LIKE ? OR u.name LIKE ? ORDER BY u.id DESC LIMIT 300",
        ("%%%s%%" % q, "%%%s%%" % q)).fetchall())
    now = int(time.time())
    return ok(users=[{
        "id": r["id"], "name": r["name"], "email": r["email"], "created": M.ts_iso(r["created"]),
        "sub_end": M.ts_iso(r["sub_end"]), "active": bool(r["sub_end"] and r["sub_end"] > now),
        "is_admin": bool(r["is_admin"]), "banned": bool(r["banned"]), "plan_name": r["plan_name"]}
        for r in rows])


@require_admin
def a_admin_user_set():
    b = M.body()
    try:
        uid = int(b.get("user_id"))
    except (TypeError, ValueError):
        raise AErr("user_id required.")
    target = M.db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target:
        raise AErr("User not found.", 404)
    if "is_admin" in b:
        M.db().execute("UPDATE users SET is_admin=? WHERE id=?", (1 if b["is_admin"] else 0, uid))
    if "banned" in b:
        M.db().execute("UPDATE users SET banned=? WHERE id=?", (1 if b["banned"] else 0, uid))
    if b.get("extend_days"):
        try:
            days = int(b["extend_days"])
        except (TypeError, ValueError):
            raise AErr("extend_days is invalid.")
        now = int(time.time())
        base = target["sub_end"] if (target["sub_end"] or 0) > now else now
        new_end = base + days * 86400
        M.db().execute("UPDATE users SET sub_start=COALESCE(sub_start,?), sub_end=? WHERE id=?",
                       (now, new_end, uid))
    if b.get("revoke"):
        M.db().execute("UPDATE users SET sub_end=0, plan_id=NULL WHERE id=?", (uid,))
    if "set_plan_id" in b:
        pid = b["set_plan_id"] or None
        M.db().execute("UPDATE users SET plan_id=?, plan_start=? WHERE id=?", (pid, int(time.time()), uid))
    M.db().commit()
    return ok(message="User updated.")


@require_admin
def a_admin_user_delete():
    b = M.body()
    try:
        uid = int(b.get("user_id"))
    except (TypeError, ValueError):
        raise AErr("user_id required.")
    M.db().execute("DELETE FROM users WHERE id=?", (uid,))
    M.db().commit()
    return ok(message="User deleted.")


# ============================================================ admin: plans CRUD
@require_admin
def a_admin_plans():
    rows = M.db().execute("SELECT * FROM plans ORDER BY sort_order, id").fetchall()
    return ok(plans=[plan_public(p) for p in rows])


@require_admin
def a_admin_plan_save():
    b = M.body()
    name = str(b.get("name", "")).strip()[:80]
    if not name:
        raise AErr("Plan name required.")
    try:
        price = round(float(b.get("price")), 2)
    except (TypeError, ValueError):
        raise AErr("Valid price required.")
    if price <= 0 or price > 1000000:
        raise AErr("Price must be between 0 and 1000000.")
    try:
        days = int(b.get("duration_days"))
    except (TypeError, ValueError):
        raise AErr("Valid duration_days required.")
    if days < 1 or days > 3650:
        raise AErr("duration_days must be between 1 and 3650.")
    feats = b.get("features")
    if isinstance(feats, str):
        feats = [x.strip() for x in feats.split("\n") if x.strip()]
    elif isinstance(feats, list):
        feats = [str(x).strip() for x in feats if str(x).strip()]
    else:
        feats = []
    active = 1 if b.get("active", True) else 0
    try:
        sort_order = int(b.get("sort_order") or 0)
    except (TypeError, ValueError):
        sort_order = 0

    def lim(key, label):
        raw = b.get(key)
        if raw in (None, ""):
            return 0
        try:
            v = int(float(raw))
        except (TypeError, ValueError):
            raise AErr("%s must be a number (0 = unlimited)." % label)
        if v < 0 or v > 100000000:
            raise AErr("%s must be between 0 and 100000000." % label)
        return v
    link_limit = lim("link_limit", "Payment link limit")
    txn_limit = lim("transaction_limit", "Transaction limit")
    api_limit = lim("api_order_limit", "API order limit")
    max_amount = lim("max_amount", "Max amount")
    pid = b.get("id")
    if pid:
        M.db().execute("UPDATE plans SET name=?,price=?,duration_days=?,features=?,active=?,sort_order=?,"
                       "link_limit=?,transaction_limit=?,api_order_limit=?,max_amount=? WHERE id=?",
                       (name, price, days, json.dumps(feats), active, sort_order,
                        link_limit, txn_limit, api_limit, max_amount, int(pid)))
    else:
        M.db().execute("INSERT INTO plans(name,price,duration_days,features,active,sort_order,created,"
                       "link_limit,transaction_limit,api_order_limit,max_amount) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                       (name, price, days, json.dumps(feats), active, sort_order, int(time.time()),
                        link_limit, txn_limit, api_limit, max_amount))
    M.db().commit()
    return ok(message="Plan saved.")


@require_admin
def a_admin_plan_delete():
    b = M.body()
    try:
        pid = int(b.get("id"))
    except (TypeError, ValueError):
        raise AErr("id required.")
    M.db().execute("DELETE FROM plans WHERE id=?", (pid,))
    M.db().execute("UPDATE users SET plan_id=NULL WHERE plan_id=?", (pid,))
    M.db().commit()
    return ok(message="Plan deleted.")


# ============================================================ admin: orders feed
@require_admin
def a_admin_orders():
    rows = M.db().execute(
        "SELECT o.*, pl.name AS plan_name, us.email AS user_email FROM plan_orders o "
        "LEFT JOIN plans pl ON pl.id=o.plan_id LEFT JOIN users us ON us.id=o.user_id "
        "ORDER BY o.id DESC LIMIT 200").fetchall()
    return ok(orders=[{
        "fg_order_id": r["fg_order_id"], "user_email": r["user_email"], "plan_name": r["plan_name"],
        "amount": M.num(r["amount"]), "status": r["status"], "utr": r["utr"],
        "created": M.ts_iso(r["created"]), "paid_at": M.ts_iso(r["paid_at"])} for r in rows])


# ============================================================ admin: settings
@require_admin
def a_admin_settings_get():
    key = gateway_key()
    masked = (key[:10] + "..." + key[-4:]) if len(key) > 16 else key
    return ok(settings={
        "famgateway_api_key_set": bool(key), "famgateway_api_key_masked": masked,
        "site_name": get_setting("site_name", "Fam Pay"),
        "gateway_base_url": fg.BASE_URL,
        "free_for_all": free_mode()[0], "free_until": M.ts_iso(free_mode()[1]) if free_mode()[1] else None,
        "require_subscription": M.REQUIRE_SUB})


@require_admin
def a_admin_settings_save():
    b = M.body()
    if "famgateway_api_key" in b and str(b["famgateway_api_key"]).strip():
        key = str(b["famgateway_api_key"]).strip()
        if not key.startswith("fam_") or len(key) < 10:
            raise AErr("FamGateway API key format looks invalid (it should start with fam_...).")
        set_setting("famgateway_api_key", key)
    if str(b.get("gateway_base_url", "")).strip():
        url = str(b["gateway_base_url"]).strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            raise AErr("Gateway URL must start with http:// or https://.")
        set_setting("gateway_base_url", url)
        fg.BASE_URL = url
    if "site_name" in b:
        set_setting("site_name", str(b["site_name"]).strip()[:60] or "Fam Pay")
    return ok(message="Settings saved.")


@require_admin
def a_admin_free_set():
    """Sabko free access ON/OFF. hours=0 => jab tak khud band na karo."""
    b = M.body()
    if b.get("on"):
        try:
            hours = float(b.get("hours") or 0)
        except (TypeError, ValueError):
            raise AErr("hours must be a number.")
        if hours < 0 or hours > 24 * 365:
            raise AErr("hours must be between 0 and 8760.")
        set_setting("free_for_all", "1")
        set_setting("free_until", int(time.time() + hours * 3600) if hours else 0)
        return ok(message="Free access is ON for everyone." if not hours else "Free trial is ON for everyone for %g hours." % hours)
    set_setting("free_for_all", "0")
    set_setting("free_until", 0)
    return ok(message="Free access is OFF. Only users with a plan now.")


@require_admin
def a_admin_grant_all():
    """Sab (ya sirf inactive) users ko N din ka premium do."""
    b = M.body()
    try:
        days = float(b.get("days"))
    except (TypeError, ValueError):
        raise AErr("days must be a number.")
    if days <= 0 or days > 3650:
        raise AErr("days must be between 0 and 3650.")
    only_inactive = bool(b.get("only_inactive"))
    now, add = int(time.time()), int(days * 86400)
    cond = "AND COALESCE(sub_end,0)<=?" if only_inactive else ""
    cur = M.db().execute(
        "UPDATE users SET sub_start=CASE WHEN COALESCE(sub_end,0)>? THEN COALESCE(sub_start,?) ELSE ? END, "
        "sub_end=(CASE WHEN COALESCE(sub_end,0)>? THEN sub_end ELSE ? END)+? WHERE banned=0 " + cond,
        [now, now, now, now, now, add] + ([now] if only_inactive else []))
    M.db().commit()
    return ok(message="%d users received %g days of premium." % (cur.rowcount, days), count=cur.rowcount)


# ============================================================ user-facing: plans + checkout
def _reconcile_pending(u):
    """Jo order pay ho chuke par modal band hone se activate nahi hue, unhe apne aap activate karo."""
    d = M.db()
    key = gateway_key()
    if not key or M.throttle("planrec:%d" % u["id"], 6, 60):
        return
    rows = d.execute("SELECT * FROM plan_orders WHERE user_id=? AND status='pending' AND created>? "
                     "ORDER BY id DESC LIMIT 3", (u["id"], int(time.time()) - 1800)).fetchall()
    for row in rows:
        try:
            st = fg.verify_order(key, row["fg_order_id"])
        except fg.GatewayError:
            return
        if st.get("paid") and float(st.get("amount") or row["amount"]) + 0.001 >= float(row["amount"]):
            plan = d.execute("SELECT * FROM plans WHERE id=?", (row["plan_id"],)).fetchone()
            if plan:
                _apply_plan_payment(d, u["id"], plan, row["fg_order_id"],
                                    st.get("utr") or row["fg_order_id"], st.get("amount") or row["amount"])


def a_plans_list(u):
    _reconcile_pending(u)
    u = M.db().execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    rows = M.db().execute("SELECT * FROM plans WHERE active=1 ORDER BY sort_order, price").fetchall()
    active, _, end = M.sub_state(u)
    cur_plan = None
    if u["plan_id"]:
        p = M.db().execute("SELECT * FROM plans WHERE id=?", (u["plan_id"],)).fetchone()
        cur_plan = plan_public(p) if p else None
    fm = free_mode()
    return ok(free_trial=fm[0], free_trial_until=M.ts_iso(fm[1]) if fm[1] else None,
              plans=[plan_public(p) for p in rows], current_plan=cur_plan,
              subscription_active=active, subscription_end=M.ts_iso(end) if active else None,
              usage=plan_usage(u["id"]) if cur_plan else None)


def a_plan_checkout(u):
    b = M.body()
    try:
        plan_id = int(b.get("plan_id"))
    except (TypeError, ValueError):
        return fail("plan_id required.")
    plan = M.db().execute("SELECT * FROM plans WHERE id=? AND active=1", (plan_id,)).fetchone()
    if not plan:
        return fail("Plan not found.", 404)
    key = gateway_key()
    if not key:
        return fail("The payment gateway is not configured yet. Please contact the admin.", 503)
    if M.throttle("plancheck:%d" % u["id"], 10, 120):
        return fail("Too many attempts. Please wait a minute.", 429)
    redirect_url = M.base_url() + "/index.php#/plans"
    try:
        order = fg.create_order(key, plan["price"], redirect_url=redirect_url,
                                customer_name=u["name"], customer_email=u["email"])
    except fg.GatewayError as e:
        M.app.logger.warning("famgateway create_order failed: %s", e)
        return fail(str(e), 502)
    oid = order.get("order_id")
    if not oid:
        return fail("The gateway did not return an order id.", 502)
    try:
        got = float(order.get("payable_amount"))
    except (TypeError, ValueError):
        got = None
    if got is not None and abs(got - float(plan["price"])) > 0.001:
        M.app.logger.warning("QR amount mismatch: plan %s, gateway %s", plan["price"], got)
        return fail("QR amount (Rs %s) does not match the plan price (Rs %s). Set AMOUNT_BUMP=0 in the Railway API "
                    "and try again." % (M.num(got), M.num(plan["price"])), 502)
    qr_url = order.get("qr_url") or fg.qr_image_url(oid)
    try:
        M.db().execute("INSERT INTO plan_orders(user_id,plan_id,fg_order_id,amount,status,checkout_url,qr_url,"
                       "upi_intent,created) VALUES(?,?,?,?,?,?,?,?,?)",
                       (u["id"], plan_id, oid, plan["price"], "pending",
                        order.get("checkout_url"), qr_url, order.get("upi_intent"), int(time.time())))
        M.db().commit()
    except sqlite3.IntegrityError:
        pass
    # Sirf QR code dikhana hai (koi checkout link nahi). QR apne server se serve hota hai.
    return ok(order={
        "fg_order_id": oid, "amount": M.num(plan["price"]), "qr_url": "/plan_qr/%s.png" % oid,
        "plan_name": plan["name"], "expires_at_ist": order.get("expires_at_ist")})


def _apply_plan_payment(d, user_id, plan, fg_order_id, utr, amount):
    """Idempotent: subscription extend + sub_payments insert + plan_orders mark success."""
    now = int(time.time())
    if d.execute("SELECT 1 FROM sub_payments WHERE utr=?", (utr,)).fetchone():
        d.execute("UPDATE plan_orders SET status='success', utr=?, paid_at=? "
                  "WHERE fg_order_id=? AND status!='success'", (utr, now, fg_order_id))
        d.commit()
        return
    u = d.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    old_end = u["sub_end"] or 0
    was_renewal = old_end > now
    new_end = (old_end if was_renewal else now) + plan["duration_days"] * 86400
    d.execute("UPDATE users SET sub_start=?, sub_end=?, plan_id=?, plan_start=? WHERE id=?",
             (u["sub_start"] if was_renewal and u["sub_start"] else now, new_end, plan["id"], now, user_id))
    try:
        d.execute("INSERT INTO sub_payments(utr,user_id,order_id,amount,created) VALUES(?,?,?,?,?)",
                 (utr, user_id, fg_order_id, amount, now))
    except sqlite3.IntegrityError:
        pass
    d.execute("UPDATE plan_orders SET status='success', utr=?, paid_at=? WHERE fg_order_id=?",
             (utr, now, fg_order_id))
    d.commit()


def a_plan_status(u):
    b = M.body()
    oid = str(b.get("fg_order_id", "")).strip()
    if not oid:
        return fail("fg_order_id required.")
    row = M.db().execute("SELECT * FROM plan_orders WHERE fg_order_id=? AND user_id=?",
                         (oid, u["id"])).fetchone()
    if not row:
        return fail("Order not found.", 404)
    if row["status"] == "success":
        return ok(status="success", amount=M.num(row["amount"]), utr=row["utr"])
    key = gateway_key()
    if not key:
        return fail("The payment gateway is not configured.", 503)
    if M.throttle("planstat:%d" % u["id"], 40, 60):
        return fail("Too many requests.", 429)
    try:
        st = fg.verify_order(key, oid)
    except fg.GatewayError as e:
        M.app.logger.warning("famgateway verify_order failed: %s", e)
        return ok(status="pending")
    if st.get("status") == "expired" and row["status"] == "pending":
        M.db().execute("UPDATE plan_orders SET status='expired' WHERE fg_order_id=?", (oid,))
        M.db().commit()
        return ok(status="expired")
    if not st.get("paid"):
        return ok(status="pending")
    plan = M.db().execute("SELECT * FROM plans WHERE id=?", (row["plan_id"],)).fetchone()
    if not plan:
        return fail("Plan no longer exists.", 410)
    utr = st.get("utr") or oid
    try:
        paid_amt = float(st.get("amount") or row["amount"])
    except (TypeError, ValueError):
        paid_amt = float(row["amount"])
    if paid_amt + 0.001 < float(row["amount"]):
        return ok(status="pending")   # kam amount se plan activate nahi hoga
    _apply_plan_payment(M.db(), u["id"], plan, oid, utr, paid_amt)
    fresh = M.db().execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    _, _, end = M.sub_state(fresh)
    return ok(status="success", amount=M.num(st.get("amount") or row["amount"]), utr=utr,
              sender_name=st.get("sender_name"), plan_name=plan["name"],
              subscription_end=M.ts_iso(end))


@bp.get("/plan_qr/<oid>.png")
def plan_qr(oid):
    uid = session.get("uid")
    row = uid and M.db().execute("SELECT 1 FROM plan_orders WHERE fg_order_id=? AND user_id=?", (oid, uid)).fetchone()
    if not row:
        return Response("Not found", 404)
    try:
        png = fg.fetch_qr_png(oid)
    except fg.GatewayError as e:
        M.app.logger.warning("plan qr fetch failed: %s", e)
        return Response("QR unavailable", 502)
    return Response(png, mimetype="image/png", headers={"Cache-Control": "private, max-age=120"})


# ============================================================ webhook (instant, optional)
@bp.post("/famgateway/webhook")
def famgateway_webhook():
    raw = request.get_data()
    sig = request.headers.get("X-FamGateway-Signature", "")
    key = gateway_key()
    if not key:
        return jsonify(status="ignored"), 200
    expected = hmac.new(key.encode(), raw, hashlib.sha256).hexdigest()
    if not sig or not hmac.compare_digest(sig, expected):
        return jsonify(status="invalid signature"), 401
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return jsonify(status="bad json"), 400
    if payload.get("status") != "success" and payload.get("event") != "payment.success":
        return jsonify(status="ignored"), 200
    oid = payload.get("order_id")
    row = M.db().execute("SELECT * FROM plan_orders WHERE fg_order_id=?", (oid,)).fetchone()
    if not row or row["status"] == "success":
        return jsonify(status="ok"), 200
    plan = M.db().execute("SELECT * FROM plans WHERE id=?", (row["plan_id"],)).fetchone()
    if plan:
        utr = payload.get("utr") or oid
        _apply_plan_payment(M.db(), row["user_id"], plan, oid, utr, payload.get("amount") or row["amount"])
    return jsonify(status="ok"), 200


# ============================================================ standalone /admin.html panel
ADMIN_ACTIONS = {
    "login": (a_admin_login, "POST", False), "logout": (a_admin_logout, "POST", False),
    "status": (a_admin_status, "GET", False),
    "stats": (a_admin_stats, "GET", True), "users": (a_admin_users, "GET", True),
    "user_set": (a_admin_user_set, "POST", True), "user_delete": (a_admin_user_delete, "POST", True),
    "plans": (a_admin_plans, "GET", True), "plan_save": (a_admin_plan_save, "POST", True),
    "plan_delete": (a_admin_plan_delete, "POST", True), "orders": (a_admin_orders, "GET", True),
    "settings_get": (a_admin_settings_get, "GET", True), "settings_save": (a_admin_settings_save, "POST", True),
    "free_set": (a_admin_free_set, "POST", True), "grant_all": (a_admin_grant_all, "POST", True),
}


@bp.get("/admin")
def admin_page():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin.html")
    if not os.path.exists(path):
        return fail("admin.html not found.", 404)
    with open(path, encoding="utf-8") as f:
        return Response(f.read(), mimetype="text/html")


@bp.route("/admin.php", methods=["GET", "POST"])
def admin_router():
    name = request.args.get("action", "")
    entry = ADMIN_ACTIONS.get(name)
    if not entry:
        return fail("Unknown action.", 404)
    fn, method, _needs_auth = entry
    if request.method != method:
        return fail("Method not allowed.", 405)
    return fn()


# ============================================================ wiring
def init(app, main_module):
    global M
    M = main_module
    c = sqlite3.connect(M.DB_PATH, timeout=15)
    c.executescript(SCHEMA)
    cols = {r[1] for r in c.execute("PRAGMA table_info(users)")}
    for col, ddl in (("is_admin", "INTEGER NOT NULL DEFAULT 0"), ("banned", "INTEGER NOT NULL DEFAULT 0"),
                     ("plan_id", "INTEGER"), ("plan_start", "INTEGER")):
        if col not in cols:
            c.execute("ALTER TABLE users ADD COLUMN %s %s" % (col, ddl))
    pcols = {r[1] for r in c.execute("PRAGMA table_info(plans)")}
    for col in ("link_limit", "transaction_limit", "api_order_limit"):
        if col not in pcols:
            c.execute("ALTER TABLE plans ADD COLUMN %s INTEGER NOT NULL DEFAULT 0" % col)
    if "max_amount" not in pcols:
        c.execute("ALTER TABLE plans ADD COLUMN max_amount REAL NOT NULL DEFAULT 0")
    # Default plans (sirf pehli baar). Admin panel se baad me edit/delete kar sakte ho.
    done = c.execute("SELECT 1 FROM settings WHERE key='default_plans_v1'").fetchone()
    if not done:
        now = int(time.time())
        for name, price, days, order, feats in (
            ("1 Day", 2, 1, 1, ["1 day of Premium", "Integrations + API Key unlocked", "Realtime Auto-Verification"]),
            ("2 Days", 10, 2, 2, ["2 days of Premium", "Integrations + API Key unlocked", "Realtime Auto-Verification"]),
            ("Premium Pro", 99, 30, 3, ["30 days of Premium (Best Value)", "Unlimited Daily Orders",
                                        "Integrations + API Key unlocked", "Realtime Auto-Verification",
                                        "No Order Amount Limit", "24x7 Telegram Support"]),
        ):
            c.execute("INSERT INTO plans(name,price,duration_days,features,active,sort_order,created) "
                      "VALUES(?,?,?,?,1,?,?)", (name, price, days, json.dumps(feats), order, now))
        c.execute("INSERT INTO settings(key,value) VALUES('default_plans_v1','1')")
    c.commit()
    c.close()
    app.register_blueprint(bp)
    with app.app_context():
        saved = get_setting("gateway_base_url", "")
        if saved:
            fg.BASE_URL = saved.rstrip("/")
    M.action("plans_list", methods=("GET",))(a_plans_list)
    M.action("plan_checkout")(a_plan_checkout)
    M.action("plan_status")(a_plan_status)
