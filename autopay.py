"""
autopay.py  -  FamPay auto payment (create_order / verify / checkout page / payment links / profile).

app.py me sirf 2 line judti hain (neeche app.py ke end me):
    import autopay
    autopay.init(app, sys.modules[__name__])

Flow:
  1) merchant /api.php (action=create_order) se order banata hai -> checkout_url milta hai
  2) customer /pay/fg_xxx par QR scan karke pay karta hai
  3) checkout page har 2 sec status poll karta hai; server Gmail me FamPay ka "payment received" mail
     dhoondhta hai (exact amount + order banne ke baad aaya + ek mail sirf ek order ke liye)
  4) mil jaye to order success, customer redirect_url par jata hai
"""
import json
import secrets
import sqlite3
import threading
import time
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from html import escape
from urllib.parse import quote, urlencode, urlparse

from flask import Blueprint, Response, abort, jsonify, redirect, request, send_file
from werkzeug.security import check_password_hash, generate_password_hash

import gmail_payment as gp

M = None  # app.py module (init() me set hota hai)
bp = Blueprint("autopay", __name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS pay_orders(
  gid TEXT PRIMARY KEY, user_id INTEGER NOT NULL, order_id TEXT NOT NULL,
  req_paise INTEGER NOT NULL, paise INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
  redirect_url TEXT, payer TEXT, note TEXT, created INTEGER NOT NULL, expires INTEGER NOT NULL,
  paid_at INTEGER, reference TEXT, seen INTEGER, src TEXT NOT NULL DEFAULT 'api', UNIQUE(user_id, order_id));
CREATE INDEX IF NOT EXISTS ix_po_user ON pay_orders(user_id, status, paise);
CREATE TABLE IF NOT EXISTS merchants(
  user_id INTEGER PRIMARY KEY, upi_id TEXT, merchant_name TEXT);
"""

ORDER_ID_OK = __import__("re").compile(r"^[A-Za-z0-9_-]{1,40}$")
LINK_MINUTES = (5, 10, 15, 30, 60, 1440)
SCAN_GAP = 3          # ek user ke Gmail ko 3 sec me ek hi baar scan
MAIL_SLACK = 120      # mail order banne se itna pehle (clock farak) aayi ho tab bhi chalega (sec)
ACTIVE_SEC = 20       # checkout page itne sec ke andar poll hua ho to order "active" (customer abhi page par hai)
# 1 => same amount ke do pending order me naye ka amount 1-9 paise badhta hai (purana behaviour).
# 0 (default) => amount hamesha exact rehta hai, aur payment sabse recent active order ko milti hai.
AMOUNT_BUMP = __import__("os").getenv("AMOUNT_BUMP", "0").strip() == "1"
_scan_lock, _last_scan = threading.Lock(), {}


class Err(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.msg, self.code = msg, code


# ============================================================ helpers
def J(payload, code=200):
    r = jsonify(payload)
    r.status_code = code
    r.headers["Cache-Control"] = "no-store"
    return r


def fail(msg, code=400):
    return J({"ok": False, "error": msg}, code)


def fmt(ts):
    return datetime.fromtimestamp(ts, M.IST).strftime("%Y-%m-%d %H:%M:%S") if ts else None


def to_paise(v):
    try:
        d = Decimal(str(v).strip())
    except (InvalidOperation, ValueError):
        raise Err("amount is invalid.", 422)
    if not d.is_finite() or d < Decimal("0.01") or d > Decimal("10000000"):
        raise Err("amount must be between 0.01 and 10000000.", 422)
    return int((d.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) * 100).to_integral_value())


def params():
    d = {}
    d.update(request.args.to_dict())
    d.update(request.form.to_dict())
    j = request.get_json(silent=True)
    if isinstance(j, dict):
        d.update({k: v for k, v in j.items() if isinstance(k, str) and v is not None})
    return d


def sget(p, key, maxlen):
    return str(p.get(key, "") or "").strip()[:maxlen]


def valid_url(u):
    x = urlparse(u)
    return x.scheme in ("http", "https") and bool(x.netloc) and len(u) <= 500


def merchant_of(uid):
    return M.db().execute("SELECT * FROM merchants WHERE user_id=?", (uid,)).fetchone()


def order_row(gid):
    return M.db().execute("SELECT * FROM pay_orders WHERE gid=?", (gid,)).fetchone()


def eff_status(o):
    if o["status"] == "pending" and o["expires"] <= int(time.time()):
        return "expired"
    return o["status"]


def checkout_url(gid):
    return "%s/pay/%s" % (M.base_url(), gid)


def order_json(o, existing=None):
    now, st = int(time.time()), eff_status(o)
    d = {"ok": True}
    if existing is not None:
        d["existing"] = existing
    d.update(order_id=o["order_id"], gateway_order_id=o["gid"], amount=M.num(o["paise"] / 100),
             currency="INR", status=st, paid=(st == "success"), checkout_url=checkout_url(o["gid"]),
             created_at=fmt(o["created"]), expires_at=fmt(o["expires"]),
             expires_in=max(0, o["expires"] - now) if st == "pending" else 0)
    if st == "success":
        d["paid_at"] = fmt(o["paid_at"])
        d["reference"] = o["reference"]
    else:
        d["verify_url"] = "%s/api.php?action=verify&order_id=%s" % (M.base_url(), quote(o["order_id"]))
    return d


def redirect_target(o):
    if not o["redirect_url"] or o["status"] != "success":
        return None
    q = urlencode({"status": "success", "order_id": o["order_id"], "gateway_order_id": o["gid"],
                   "amount": M.num(o["paise"] / 100), "reference": o["reference"] or ""})
    return o["redirect_url"] + ("&" if "?" in o["redirect_url"] else "?") + q


# ============================================================ order create
def create_core(uid, rp, oid, redir, payer, note, minutes, src="api"):
    d, now = M.db(), int(time.time())
    d.execute("DELETE FROM pay_orders WHERE status!='success' AND expires<?", (now - 7 * 86400,))
    if oid:
        row = d.execute("SELECT * FROM pay_orders WHERE user_id=? AND order_id=?", (uid, oid)).fetchone()
        if row:
            if row["status"] == "success":
                raise Err("order_id already paid.", 409)
            if row["status"] == "pending" and row["expires"] > now:
                if row["req_paise"] != rp:
                    raise Err("order_id already exists with a different amount.", 409)
                return row, True
            d.execute("DELETE FROM pay_orders WHERE gid=?", (row["gid"],))
    msg = M.admin.check_limit(uid, "link" if src == "link" else "api", rp / 100)
    if msg:
        raise Err(msg, 403)
    # Amount EXACT rehta hai (Rs 1 maango to Rs 1.00). Same amount ke kai pending order ho sakte hain;
    # payment aane par scan_and_match() sabse recent active order chunta hai.
    p = rp
    if AMOUNT_BUMP:  # optional purana tarika (env AMOUNT_BUMP=1)
        for _ in range(10):
            if not d.execute("SELECT 1 FROM pay_orders WHERE user_id=? AND status='pending' AND expires>? AND paise=?",
                             (uid, now, p)).fetchone():
                break
            p += 1
        else:
            raise Err("There are too many pending orders for this amount. Please try again later.", 429)
    gid = "fg_" + secrets.token_hex(5)
    try:
        d.execute("INSERT INTO pay_orders(gid,user_id,order_id,req_paise,paise,redirect_url,payer,note,created,expires,src)"
                  " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  (gid, uid, oid or gid, rp, p, redir or None, payer or None, note or None, now,
                   now + minutes * 60, src))
        d.commit()
    except sqlite3.IntegrityError:
        d.rollback()
        raise Err("order_id already exists.", 409)
    return order_row(gid), False


# ============================================================ payment matching (Gmail)
def scan_and_match(uid):
    now = time.time()
    with _scan_lock:
        if now - _last_scan.get(uid, 0) < SCAN_GAP:
            return
        _last_scan[uid] = now
    d = M.db()
    gw = M.gateway_of(uid)
    owner = d.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not gw or not owner or not M.sub_state(owner)[0]:
        return
    pending = d.execute("SELECT * FROM pay_orders WHERE user_id=? AND status='pending' AND expires>? "
                        "ORDER BY created, rowid", (uid, int(now))).fetchall()
    if not pending:
        return
    pos = {o["gid"]: i for i, o in enumerate(pending)}  # bana-hone ka sahi kram (same second me bane orders ke liye)
    try:
        mails = gp.scan_recent(gw["gmail"], M.dec(gw["app_pw"]))
    except gp.GmailError as e:
        M.app.logger.warning("autopay scan failed: %s", e)
        return
    except Exception:  # koi bhi anjaan error status API ko 500 na bana de
        M.app.logger.exception("autopay scan crashed")
        return
    used = {r[0] for r in d.execute("SELECT reference FROM pay_orders WHERE user_id=? AND reference IS NOT NULL",
                                    (uid,))}
    used |= {r[0] for r in d.execute("SELECT utr FROM transactions WHERE user_id=?", (uid,))}
    claimed = set()
    log = M.app.logger
    log.info("autopay scan: %d pending order(s), %d payment mail(s) in Gmail", len(pending), len(mails))
    for mail in mails:  # purane mail pehle
        utr = mail["utr"]
        if utr in used:
            continue
        ts, p = int(mail["paid_at"].timestamp()), int(round(mail["amount"] * 100))
        # is mail ke liye candidate orders: same amount + time window me + abhi tak claim nahi hue
        cands = [o for o in pending
                 if o["gid"] not in claimed and o["paise"] == p
                 and o["created"] - MAIL_SLACK <= ts <= o["expires"] + 120]
        if not cands:
            log.info("autopay: mail utr=%s amount=%s ko koi pending order match nahi hua "
                     "(amount ya time window alag)", utr, mail["amount"])
            continue
        # sabse pehle wo order jiska checkout page abhi khula hai (poll ho raha hai), uske baad sabse naya.
        # Isse "pehle ka bina-pay kiya hua same-amount order" naye order ki payment nahi kha sakta.
        cands.sort(key=lambda o: ((o["seen"] or 0) >= now - ACTIVE_SEC, o["created"], pos[o["gid"]]), reverse=True)
        o = cands[0]
        cur = d.execute("UPDATE pay_orders SET status='success', paid_at=?, reference=? "
                        "WHERE gid=? AND status='pending'", (ts, utr, o["gid"]))
        if cur.rowcount:
            d.execute("INSERT OR IGNORE INTO transactions(user_id,utr,transaction_id,sender_name,amount,paid,"
                      "created) VALUES(?,?,?,?,?,?,?)",
                      (uid, utr, mail["transaction_id"], mail["sender_name"], mail["amount"], ts,
                       int(time.time())))
            claimed.add(o["gid"])
            used.add(utr)
            log.info("autopay: order %s PAID (utr=%s amount=%s)", o["gid"], utr, mail["amount"])
    d.commit()


def mark_seen(gid):
    """Checkout page abhi khula hai -> order 'active' (same amount ke orders me isko priority milti hai)."""
    M.db().execute("UPDATE pay_orders SET seen=? WHERE gid=? AND status='pending'", (int(time.time()), gid))
    M.db().commit()


def refresh(o):
    if o["status"] != "pending":
        return o
    if o["expires"] <= int(time.time()):
        M.db().execute("UPDATE pay_orders SET status='expired' WHERE gid=? AND status='pending'", (o["gid"],))
        M.db().commit()
        return order_row(o["gid"])
    scan_and_match(o["user_id"])
    return order_row(o["gid"])


# ============================================================ public API  (/api.php, /api, /api/<action>)
@bp.route("/api.php", methods=["GET", "POST"])
@bp.route("/api", methods=["GET", "POST"])
@bp.route("/api/<act>", methods=["GET", "POST"])
def pay_api(act=None):
    ip = M.client_ip()
    if M.throttle("api:" + ip, 120, 60):
        return fail("Too many requests. Please slow down.", 429)
    p = params()
    action = (act or p.get("action") or "").strip()
    key = str(p.get("api_key") or request.headers.get("X-API-Key") or "").strip()
    if not key:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            key = auth[7:].strip()
    if M.blocked("badkey:" + ip, 20, 600):
        return fail("Too many invalid API keys. Please wait a few minutes.", 429)
    if not key:
        return fail("api_key missing.", 401)
    gw = M.db().execute("SELECT * FROM gateways WHERE api_key=?", (key,)).fetchone()
    if not gw:
        M.record("badkey:" + ip)
        return fail("Invalid API key.", 401)
    uid = gw["user_id"]
    owner = M.db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not owner or not M.sub_state(owner)[0]:
        return fail("Subscription is not active. Please renew.", 403)
    mer = merchant_of(uid)
    if not mer or not mer["upi_id"] or not mer["merchant_name"]:
        return fail("Integration is not connected: save your UPI ID and merchant name in Profile.", 403)

    try:
        if action == "create_order":
            if request.method != "POST":
                return fail("Use POST for create_order.", 405)
            rp = to_paise(p.get("amount", ""))
            oid = sget(p, "order_id", 41)
            if oid and (not ORDER_ID_OK.match(oid) or oid.lower().startswith("fg_")):
                raise Err("order_id is invalid (letters, numbers, - and _, max 40; must not start with fg_).", 422)
            redir = sget(p, "redirect_url", 501) or sget(p, "return_url", 501)
            if redir and not valid_url(redir):
                raise Err("redirect_url must be http/https.", 422)
            try:
                minutes = int(p.get("expiry_minutes") or 15)
            except (TypeError, ValueError):
                raise Err("expiry_minutes is invalid.", 422)
            if not 1 <= minutes <= 1440:
                raise Err("expiry_minutes must be between 1 and 1440.", 422)
            o, existing = create_core(uid, rp, oid, redir, sget(p, "payer", 60), sget(p, "note", 120), minutes)
            return J(order_json(o, existing))

        if action == "verify":
            ref = sget(p, "order_id", 41)
            if not ref:
                raise Err("order_id required.", 422)
            o = M.db().execute("SELECT * FROM pay_orders WHERE user_id=? AND (order_id=? OR gid=?)",
                               (uid, ref, ref)).fetchone()
            if not o:
                raise Err("Order not found for this api_key.", 404)
            return J(order_json(refresh(o)))
    except Err as e:
        return fail(e.msg, e.code)
    return fail("Unknown action. Use create_order or verify.", 422)


# ============================================================ checkout page
def upi_link(upi, name, rupees, gid):
    q = urlencode({"pa": upi, "pn": name, "am": "%.2f" % rupees, "cu": "INR", "tn": gid}, quote_via=quote)
    return "upi://pay?" + q


@bp.get("/pay/<gid>/qr.png")
def pay_qr(gid):
    o = order_row(gid)
    mer = merchant_of(o["user_id"]) if o else None
    if not o or not mer:
        abort(404)
    uri = upi_link(mer["upi_id"], mer["merchant_name"], o["paise"] / 100, gid)
    try:
        import qrcode
    except ImportError:
        return redirect("https://api.qrserver.com/v1/create-qr-code/?size=400x400&margin=10&data="
                        + quote(uri, safe=""), 302)
    import io
    buf = io.BytesIO()
    qrcode.make(uri, box_size=10, border=2).save(buf)
    buf.seek(0)
    resp = send_file(buf, mimetype="image/png")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.get("/pay/<gid>/status")
def pay_status(gid):
    if M.throttle("paystat:" + M.client_ip(), 120, 60):
        return fail("Too many requests.", 429)
    o = order_row(gid)
    if not o:
        return fail("Order not found.", 404)
    if o["status"] == "pending":
        mark_seen(gid)
        o = order_row(gid)
    o = refresh(o)
    st = eff_status(o)
    return J({"ok": True, "status": st, "redirect": redirect_target(o),
              "expires_in": max(0, o["expires"] - int(time.time())) if st == "pending" else 0})


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay __NAME__</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
background:radial-gradient(circle at 30% 0%,#1b2550,#0a1225 55%);color:#fff;
display:flex;min-height:100vh;align-items:center;justify-content:center;padding:18px}
.card{background:linear-gradient(165deg,#121a35,#0a1225);border:1px solid rgba(255,255,255,.08);
border-radius:28px;max-width:400px;width:100%;padding:30px 26px;text-align:center;
box-shadow:0 30px 80px rgba(0,0,0,.5);position:relative;overflow:hidden}
.m{font-size:14px;color:#9aa6c9;letter-spacing:.3px}
.amt{font-size:42px;font-weight:900;letter-spacing:-1px;margin:6px 0 18px;
background:linear-gradient(135deg,#a5b4fc,#fff);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.qrw{background:#fff;border-radius:20px;padding:16px;display:inline-flex;position:relative;
box-shadow:0 0 0 6px rgba(99,102,241,.14),0 16px 40px rgba(99,102,241,.25)}
.qrw img{width:220px;height:220px;display:block;border-radius:8px}
.scan{position:absolute;left:16px;right:16px;top:16px;height:3px;
background:linear-gradient(90deg,transparent,#6366f1,transparent);animation:scan 2.1s ease-in-out infinite}
@keyframes scan{0%{top:16px}50%{top:224px}100%{top:16px}}
.wait{display:flex;align-items:center;justify-content:center;gap:9px;color:#aab4d4;font-size:14px;margin:16px 0 2px}
.dot{width:8px;height:8px;border-radius:50%;background:#6366f1;animation:pulse 1.2s ease-in-out infinite}
.dot:nth-child(2){animation-delay:.2s}.dot:nth-child(3){animation-delay:.4s}
@keyframes pulse{0%,80%,100%{opacity:.25;transform:scale(.7)}40%{opacity:1;transform:scale(1)}}
.btn{display:block;margin-top:16px;background:rgba(99,102,241,.18);border:1px solid rgba(99,102,241,.4);
color:#c7d2fe;text-decoration:none;padding:14px;border-radius:16px;font-weight:700}
.t{margin-top:12px;font-size:13px;color:#8ea0c9}
.hide{display:none}
.ok-wrap{padding:6px 0 2px;position:relative}
.ok-ring{width:100px;height:100px;margin:0 auto 18px;border-radius:50%;
background:radial-gradient(circle,rgba(34,197,94,.22),transparent 70%);display:flex;align-items:center;justify-content:center;
animation:ringPop .5s cubic-bezier(.34,1.56,.64,1)}
@keyframes ringPop{0%{transform:scale(.3);opacity:0}100%{transform:scale(1);opacity:1}}
.chk{width:74px;height:74px}
.chk circle{stroke:#22c55e;stroke-width:3;fill:none;stroke-dasharray:220;stroke-dashoffset:220;animation:circDraw .55s ease forwards}
.chk path{stroke:#22c55e;stroke-width:4;fill:none;stroke-linecap:round;stroke-linejoin:round;
stroke-dasharray:40;stroke-dashoffset:40;animation:checkDraw .35s .5s ease forwards}
@keyframes circDraw{to{stroke-dashoffset:0}}@keyframes checkDraw{to{stroke-dashoffset:0}}
h2{margin:4px 0 4px;font-size:24px;letter-spacing:-.3px;animation:fadeUp .4s .7s both}
.ok-amt{font-size:32px;font-weight:900;margin:12px 0 4px;color:#4ade80;animation:fadeUp .4s .85s both}
.ok .t{animation:fadeUp .4s .8s both}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.xring{width:100px;height:100px;margin:0 auto 18px;border-radius:50%;
background:radial-gradient(circle,rgba(220,38,38,.2),transparent 70%);display:flex;align-items:center;justify-content:center;
font-size:46px;color:#f87171;animation:ringPop .5s cubic-bezier(.34,1.56,.64,1)}
.confetti-wrap{position:absolute;inset:-20px -26px auto -26px;height:220px;pointer-events:none;overflow:visible}
.cf{position:absolute;top:-10px;width:8px;height:14px;opacity:0;animation:cfFall 1.6s ease-in forwards}
@keyframes cfFall{0%{opacity:1;transform:translateY(0) rotate(0)}100%{opacity:0;transform:translateY(240px) rotate(540deg)}}
</style></head><body><div class="card">
<div id="pay"><div class="m">Pay to __NAME__</div><div class="amt">&#8377;__AMT__</div>
<div class="qrw"><div class="scan"></div><img src="/pay/__GID__/qr.png" alt="UPI QR"></div>
<div class="wait"><span class="dot"></span><span class="dot"></span><span class="dot"></span>Waiting for payment...</div>
<a class="btn" href="__UPI__">Pay with UPI App</a>
<div class="t">UPI ID: __UPIID__</div><div class="t" id="tm"></div>
<div class="t">This page will update automatically once the payment is received.</div>
</div>
<div id="ok" class="hide ok"><div class="ok-wrap">
<div class="ok-ring"><svg class="chk" viewBox="0 0 52 52"><circle cx="26" cy="26" r="23"/><path d="M15 27l7 7 15-15"/></svg></div>
<h2>Payment Successful</h2><div class="ok-amt">+&#8377;__AMT__</div><div class="t">Redirecting...</div></div></div>
<div id="ex" class="hide"><div class="xring">&#10007;</div><h2>Link Expired</h2>
<div class="t">Please request a new payment link.</div></div>
</div><script>
var C=__CFG__,left=C.expires_in,done=false;
function show(id){["pay","ok","ex"].forEach(function(x){document.getElementById(x).className=(x==id?"":"hide")+(x==="ok"?" ok":"")})}
function confetti(){
var colors=["#6366f1","#8b5cf6","#22c55e","#f59e0b","#ec4899","#38bdf8"];
var wrap=document.createElement("div");wrap.className="confetti-wrap";
for(var i=0;i<28;i++){var p=document.createElement("div");p.className="cf";
p.style.left=(Math.random()*100)+"%";p.style.background=colors[i%colors.length];
p.style.animationDelay=(Math.random()*0.3)+"s";
p.style.transform="rotate("+Math.floor(Math.random()*360)+"deg)";wrap.appendChild(p)}
document.querySelector(".card").appendChild(wrap);setTimeout(function(){wrap.remove()},2300)}
function tick(){if(done)return;var m=Math.floor(left/60),s=left%60;
document.getElementById("tm").textContent="Expires in "+m+":"+(s<10?"0":"")+s;if(left>0)left--}
var pt=null,fly=false;
function poll(){if(fly||done)return;fly=true;fetch("/pay/"+C.gid+"/status",{cache:"no-store"}).then(function(r){return r.json()}).then(function(d){
fly=false;
if(d.status==="success"){done=true;show("ok");confetti();if(d.redirect)setTimeout(function(){location.href=d.redirect},3000);return}
if(d.status==="expired"){done=true;show("ex");return}
if(d.expires_in!=null)left=d.expires_in;pt=setTimeout(poll,2000)}).catch(function(){fly=false;pt=setTimeout(poll,4000)})}
function loop(){clearTimeout(pt);poll()}
document.addEventListener("visibilitychange",function(){if(!document.hidden&&!done)loop()});
window.addEventListener("focus",function(){if(!done)loop()});
tick();setInterval(tick,1000);poll();
</script></body></html>"""


@bp.get("/pay/<gid>")
def pay_page(gid):
    o = order_row(gid)
    mer = merchant_of(o["user_id"]) if o else None
    if not o or not mer:
        abort(404)
    if o["status"] == "pending":
        mark_seen(gid)
        o = order_row(gid)
    o = refresh(o)
    st = eff_status(o)
    rupees = o["paise"] / 100
    cfg = json.dumps({"gid": gid, "status": st,
                      "expires_in": max(0, o["expires"] - int(time.time())) if st == "pending" else 0}
                     ).replace("</", "<\\/")
    html = (PAGE.replace("__CFG__", cfg).replace("__GID__", escape(gid))
            .replace("__NAME__", escape(mer["merchant_name"])).replace("__AMT__", "%.2f" % rupees)
            .replace("__UPIID__", escape(mer["upi_id"]))
            .replace("__UPI__", escape(upi_link(mer["upi_id"], mer["merchant_name"], rupees, gid), quote=True)))
    resp = Response(html, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ============================================================ dashboard actions  (index.php?action=...)
def a_pl_create(u):
    b = M.body()
    try:
        mer = merchant_of(u["id"])
        if not mer or not mer["upi_id"] or not mer["merchant_name"]:
            raise Err("Please save your UPI ID and merchant name in Profile first.", 403)
        if not M.gateway_of(u["id"]):
            raise Err("Please connect Gmail in Integrations first.", 403)
        if not M.sub_state(u)[0]:
            raise Err("Your subscription is not active.", 403)
        rp = to_paise(b.get("amount", ""))
        redir = str(b.get("return_url", "") or "").strip()[:500]
        if redir and not valid_url(redir):
            raise Err("Return URL must be http/https.", 422)
        try:
            minutes = int(b.get("expiry_minutes") or 15)
        except (TypeError, ValueError):
            minutes = 15
        if minutes not in LINK_MINUTES:
            minutes = 15
        if M.throttle("pl:%d" % u["id"], 30, 60):
            raise Err("Too many requests. Please wait a minute.", 429)
        o, _ = create_core(u["id"], rp, None, redir, "", "", minutes, src="link")
    except Err as e:
        return fail(e.msg, e.code)
    return J({"ok": True, "link": order_json(o)})


def a_pl_list(u):
    scan_and_match(u["id"])  # dashboard khula ho to bhi payment apne aap detect ho (Gmail scan 5 sec me 1 baar)
    rows =M.db().execute("SELECT * FROM pay_orders WHERE user_id=? ORDER BY created DESC LIMIT 100",
                          (u["id"],)).fetchall()
    return J({"ok": True, "links": [order_json(o) | {"payer": o["payer"], "note": o["note"]} for o in rows]})


def a_scan_debug(u):
    """Browser me logged-in rehkar kholo:  /index.php?action=scan_debug
    Dikhata hai: pending orders + Gmail ki har recent mail (accept / reject ka karan) + kaun sa order match hoga."""
    gw = M.gateway_of(u["id"])
    if not gw:
        return fail("Please connect Gmail first.")
    now = int(time.time())
    pend = M.db().execute("SELECT * FROM pay_orders WHERE user_id=? AND status='pending' AND expires>? "
                          "ORDER BY created", (u["id"], now)).fetchall()
    try:
        rows = gp.scan_debug(gw["gmail"], M.dec(gw["app_pw"]))
    except Exception as e:
        return fail("Gmail error: %s" % e, 502)
    used = {r[0] for r in M.db().execute("SELECT reference FROM pay_orders WHERE user_id=? AND reference IS NOT NULL",
                                         (u["id"],))}
    used |= {r[0] for r in M.db().execute("SELECT utr FROM transactions WHERE user_id=?", (u["id"],))}
    for r in rows:
        if not r["accepted"]:
            continue
        p, ts = int(round(r["amount"] * 100)), r.pop("paid_ts")
        r["already_used"] = r["utr"] in used
        r["would_match_orders"] = [o["gid"] for o in pend
                                   if o["paise"] == p and o["created"] - MAIL_SLACK <= ts <= o["expires"] + 120]
        if not r["would_match_orders"]:
            r["why_no_match"] = "no pending order has this amount, or the mail time is outside the order time window"
    return J({"ok": True, "server_time": fmt(now),
              "pending_orders": [{"gid": o["gid"], "amount": o["paise"] / 100, "created": fmt(o["created"]),
                                  "expires": fmt(o["expires"])} for o in pend],
              "mails": rows})


def a_profile_info(u):
    mer = merchant_of(u["id"])
    return J({"ok": True, "profile": {"name": u["name"], "email": u["email"],
                                      "upi_id": mer["upi_id"] if mer else "",
                                      "merchant_name": mer["merchant_name"] if mer else ""}})


def a_profile_save(u):
    b = M.body()
    upi = str(b.get("upi_id", "")).strip()
    name = str(b.get("merchant_name", "")).strip()[:60]
    if not M.UPI_RE.match(upi):
        return fail("Enter a valid UPI ID.")
    if not name:  # nahi bheja to purana naam, wo bhi nahi to account ka naam
        mer = merchant_of(u["id"])
        name = (mer["merchant_name"] if mer and mer["merchant_name"] else u["name"])[:60]
    M.db().execute("INSERT INTO merchants(user_id,upi_id,merchant_name) VALUES(?,?,?) "
                   "ON CONFLICT(user_id) DO UPDATE SET upi_id=excluded.upi_id, merchant_name=excluded.merchant_name",
                   (u["id"], upi, name))
    M.db().commit()
    return J({"ok": True, "message": "Saved."})


def a_change_password(u):
    b = M.body()
    cur, new, conf = (str(b.get(k, "")) for k in ("current_password", "new_password", "confirm_password"))
    if M.throttle("chpw:%d" % u["id"], 8, 600):
        return fail("Too many attempts. Please wait a few minutes.", 429)
    if not check_password_hash(u["pw_hash"], cur):
        return fail("Current password is incorrect.", 401)
    if len(new) < 6:
        return fail("Password must be at least 6 characters.")
    if new != conf:
        return fail("Passwords do not match.")
    M.db().execute("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(new), u["id"]))
    M.db().commit()
    return J({"ok": True, "message": "Password updated."})


def a_dash(u):
    """Live dashboard: stats + daily chart (7/15/30 din) + recent transactions."""
    from datetime import datetime, timedelta
    try:
        days = int(request.args.get("days") or M.body().get("days") or 7)
    except (TypeError, ValueError):
        days = 7
    days = days if days in (7, 15, 30) else 7
    now = datetime.now(M.IST)
    day0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
    start = day0 - timedelta(days=days - 1)
    since = int(start.timestamp())
    d, uid = M.db(), u["id"]
    series = {}
    for i in range(days):
        k = (start + timedelta(days=i)).strftime("%Y-%m-%d")
        series[k] = {"date": k, "revenue": 0.0, "requests": 0}
    key = lambda ts: datetime.fromtimestamp(ts, M.IST).strftime("%Y-%m-%d")
    total = ok_n = 0
    revenue = 0.0
    for o in d.execute("SELECT status, paise, created, paid_at FROM pay_orders WHERE user_id=? AND created>=?",
                       (uid, since)):
        total += 1
        series[key(o["created"])]["requests"] += 1
        if o["status"] == "success":
            ok_n += 1
            amt = o["paise"] / 100
            revenue += amt
            k = key(o["paid_at"] or o["created"])
            if k in series:
                series[k]["revenue"] += amt
    for t in d.execute("SELECT amount, paid FROM transactions WHERE user_id=? AND paid>=?", (uid, since)):
        total += 1
        ok_n += 1
        revenue += t["amount"]
        series[key(t["paid"])]["requests"] += 1
        series[key(t["paid"])]["revenue"] += t["amount"]
    recent = [{"name": r["payer"] or "Customer", "amount": M.num(r["paise"] / 100), "ref": r["reference"] or r["order_id"],
               "time": M.ts_iso(r["paid_at"] or r["created"]), "ts": r["paid_at"] or r["created"]}
              for r in d.execute("SELECT payer, paise, reference, order_id, paid_at, created FROM pay_orders "
                                 "WHERE user_id=? AND status='success' ORDER BY COALESCE(paid_at,created) DESC LIMIT 8", (uid,))]
    recent += [{"name": r["sender_name"] or "Unknown", "amount": M.num(r["amount"]), "ref": r["utr"],
                "time": M.ts_iso(r["paid"]), "ts": r["paid"]}
               for r in d.execute("SELECT sender_name, amount, utr, paid FROM transactions WHERE user_id=? "
                                  "ORDER BY paid DESC LIMIT 8", (uid,))]
    recent.sort(key=lambda x: x["ts"], reverse=True)
    for r in recent:
        r.pop("ts")
    return J({"ok": True, "name": u["name"], "days": days,
              "stats": {"requests": total, "successful": ok_n, "failed": total - ok_n, "revenue": round(revenue, 2)},
              "series": [{"date": s["date"], "revenue": round(s["revenue"], 2), "requests": s["requests"]}
                         for s in series.values()],
              "recent": recent[:8]})


def a_regen_key(u):
    if not M.sub_state(u)[0]:
        return fail("A Premium plan is required. Please buy a plan from Plans first.", 403)
    if not M.gateway_of(u["id"]):
        return fail("Please connect Gmail first.")
    key = "fam_" + secrets.token_hex(16)
    M.db().execute("UPDATE gateways SET api_key=? WHERE user_id=?", (key, u["id"]))
    M.db().commit()
    return J({"ok": True, "api_key": key})


# ============================================================ wiring
def init(app, main_module):
    global M
    M = main_module
    M.app = app
    c = sqlite3.connect(M.DB_PATH, timeout=15)
    c.executescript(SCHEMA)
    # purani fampay.db me 'seen' column nahi hota -> add kar do
    po_cols = {r[1] for r in c.execute("PRAGMA table_info(pay_orders)")}
    if "seen" not in po_cols:
        c.execute("ALTER TABLE pay_orders ADD COLUMN seen INTEGER")
    if "src" not in po_cols:
        c.execute("ALTER TABLE pay_orders ADD COLUMN src TEXT NOT NULL DEFAULT 'api'")
    c.commit()
    c.close()
    app.register_blueprint(bp)
    M.action("pl_create")(a_pl_create)
    M.action("pl_list", methods=("GET", "POST"))(a_pl_list)
    M.action("scan_debug", methods=("GET", "POST"))(a_scan_debug)
    M.action("profile_info", methods=("GET", "POST"))(a_profile_info)
    M.action("profile_save")(a_profile_save)
    M.action("change_password")(a_change_password)
    M.action("regen_key")(a_regen_key)
    M.action("dash", methods=("GET", "POST"))(a_dash)
