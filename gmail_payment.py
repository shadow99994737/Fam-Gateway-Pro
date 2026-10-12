"""
gmail_payment.py  -  Gmail (IMAP + 16-letter App Password) se FamPay ka "payment received"
email dhoondhta hai aur UTR / amount / sender / time nikaal kar deta hai.

Apne bot me bhi seedha chalega:

    from gmail_payment import find_payment, PaymentNotFound, MailRejected, GmailError
    try:
        p = find_payment("you@gmail.com", "abcd efgh ijkl mnop", "627413248814")
        print(p["amount"], p["sender_name"], p["paid_at"])
    except PaymentNotFound:
        print("email has not arrived yet, please check again shortly")
    except (MailRejected, GmailError) as e:
        print(e)
"""
import email
import hashlib
import imaplib
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

IST = timezone(timedelta(hours=5, minutes=30))
IMAP_HOST = os.getenv("IMAP_HOST", "imap.gmail.com")
IMAP_TIMEOUT = int(os.getenv("IMAP_TIMEOUT", "25"))
MAX_CANDIDATES = 5
DEFAULT_SENDER_DOMAINS = "famapp.in,fampay.in,famapp.com,fampay.com"
UTR_RE = re.compile(r"\d{12}")

__all__ = ["find_payment", "check_login", "valid_app_password", "clean_app_password",
           "GmailError", "PaymentNotFound", "MailRejected", "scan_recent", "scan_debug"]


class GmailError(Exception):
    """Gmail se connect / login / search me problem."""


class PaymentNotFound(Exception):
    """Is UTR ka email abhi Gmail me nahi mila."""


class MailRejected(Exception):
    """Email mila, par sender / authenticity / format check pass nahi hua."""


# ---------------------------------------------------------------- app password / login
def clean_app_password(pw):
    return re.sub(r"\s+", "", pw or "")


def valid_app_password(pw):
    return bool(re.fullmatch(r"[A-Za-z0-9]{16}", clean_app_password(pw)))


_locks, _locks_guard = {}, threading.Lock()


def _lock_for(key):
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


def _open(gmail, app_password):
    try:
        m = imaplib.IMAP4_SSL(IMAP_HOST, 993, timeout=IMAP_TIMEOUT)
    except Exception as e:
        raise GmailError("Could not reach Gmail. Please try again in a moment.") from e
    try:
        m.login(gmail, clean_app_password(app_password))
    except imaplib.IMAP4.error as e:
        _close(m)
        raise GmailError("Gmail login failed. Check the email and the 16-letter App Password "
                         "(2-Step Verification must be ON for App Passwords).") from e
    except OSError as e:
        _close(m)
        raise GmailError("Could not reach Gmail. Please try again in a moment.") from e
    return m


def _close(m):
    try:
        m.logout()
    except Exception:
        try:
            m.shutdown()
        except Exception:
            pass


def check_login(gmail, app_password):
    """Sirf login test karta hai. Galat ho to GmailError."""
    _close(_open(gmail, app_password))
    return True


# ---------------------------------------------------------------- IMAP helpers
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _imap_date(dt):
    return f"{dt.day:02d}-{_MONTHS[dt.month - 1]}-{dt.year}"


def _select_all_mail(m):
    """'All Mail' folder (naam language ke hisaab se badalta hai) select karta hai, warna INBOX."""
    name = "INBOX"
    try:
        typ, data = m.list()
        if typ == "OK":
            for raw in data or []:
                if not isinstance(raw, (bytes, bytearray)):
                    continue
                line = bytes(raw).decode("utf-8", "ignore")
                mt = re.match(r'^\((?P<flags>[^)]*)\)\s+(?:"[^"]*"|NIL)\s+(?P<name>.+)$', line)
                if mt and re.search(r"\\All\b", mt.group("flags"), re.I):
                    name = mt.group("name").strip().strip('"')
                    break
    except Exception:
        pass
    typ, _ = m.select('"%s"' % name.replace('"', ""), readonly=True)
    if typ != "OK":
        typ, _ = m.select("INBOX", readonly=True)
        if typ != "OK":
            raise GmailError("Could not open the Gmail mailbox.")


def _search(m, utr, days):
    typ, data = m.uid("SEARCH", "X-GM-RAW", '"%s newer_than:%dd"' % (utr, days))
    if typ != "OK":  # Gmail-specific search na chale to standard IMAP search
        since = datetime.now(IST) - timedelta(days=days)
        typ, data = m.uid("SEARCH", None, "SINCE", _imap_date(since), "TEXT", '"%s"' % utr)
    if typ != "OK":
        raise GmailError("Gmail search failed. Please try again.")
    ids = (data[0] or b"").split()
    return ids[-MAX_CANDIDATES:][::-1]  # newest pehle


def _fetch(m, uid):
    typ, data = m.uid("FETCH", uid, "(BODY.PEEK[])")  # PEEK: email 'read' mark nahi hota
    if typ != "OK":
        return None
    for part in data or []:
        if isinstance(part, tuple) and len(part) >= 2 and isinstance(part[1], (bytes, bytearray)):
            return bytes(part[1])
    return None


# ---------------------------------------------------------------- email -> text
class _TextExtractor(HTMLParser):
    BLOCK = {"br", "p", "div", "tr", "td", "th", "li", "table", "h1", "h2", "h3", "h4", "h5", "h6"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self._skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in self.BLOCK:
            self.out.append(" \n ")

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag in self.BLOCK:
            self.out.append(" \n ")

    def handle_data(self, data):
        if not self._skip:
            self.out.append(data)


def html_to_text(src):
    p = _TextExtractor()
    try:
        p.feed(src)
        p.close()
    except Exception:
        pass
    return _tidy("".join(p.out))


def _tidy(s):
    s = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", s).replace("\xa0", " ")
    s = re.sub(r"[ \t\r\f\v]+", " ", s)
    return re.sub(r"\s*\n\s*", "\n", s).strip()


def message_text(msg):
    chunks = []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_type() not in ("text/plain", "text/html"):
            continue
        if part.get_content_disposition() == "attachment":
            continue
        try:
            body = part.get_content()
        except Exception:
            body = (part.get_payload(decode=True) or b"").decode(part.get_content_charset() or "utf-8", "ignore")
        chunks.append(html_to_text(body) if part.get_content_type() == "text/html" else _tidy(body))
    return "\n".join(chunks)


# ---------------------------------------------------------------- field parsers
_AMT_PRE = re.compile(r"(?:₹|\bRs\.?|\bINR)\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)", re.I)
_AMT_POST = re.compile(r"\b([0-9][0-9,]*(?:\.[0-9]{1,2})?)\s*(?:INR\b|Rs\b|₹)", re.I)
_AMT_LABEL = re.compile(r"\bamount\b[^0-9\n]{0,25}([0-9][0-9,]*(?:\.[0-9]{1,2})?)", re.I)
_SKIP_CTX = re.compile(r"(balance|bal|limit|available|fees?|charges?|cashback|rewards?)\W*$", re.I)


def parse_amount(text):
    for rx in (_AMT_PRE, _AMT_POST, _AMT_LABEL):
        for m in rx.finditer(text):
            if _SKIP_CTX.search(text[max(0, m.start() - 25):m.start()]):
                continue
            try:
                v = float(m.group(1).replace(",", ""))
            except ValueError:
                continue
            if v > 0:
                return int(v) if v == int(v) else round(v, 2)
    return None


_NAME_PATTERNS = [
    r"(?:received|credited|got|deposit(?:ed)?)\b[^\n]{0,80}?\bfrom\s+([A-Za-z][A-Za-z .'\-]{1,60})",
    r"([A-Za-z][A-Za-z .'\-]{1,60}?)\s+(?:has\s+)?(?:paid|sent)\s+(?:you|₹|rs\b|inr\b)",
    r"(?:sender(?:\s+name)?|paid\s+by|received\s+from|payer|from|name)\s*[:\-]\s*([A-Za-z][A-Za-z .'\-]{1,60})",
]
_NAME_STOP = re.compile(r"\s+(?:on|via|using|through|with|at|to|has|vide|upi|utr|ref|reference|id|for|is|was|"
                        r"credited|received|rs|inr)\b.*$", re.I | re.S)
_NAME_BAD = re.compile(r"^(you|your account|account|a/c|upi|fampay|famapp|fam)$", re.I)


def parse_sender(text):
    for pat in _NAME_PATTERNS:
        m = re.search(pat, text, re.I)
        if m:
            name = _NAME_STOP.sub("", m.group(1)).strip(" .-'\n")
            if len(name) >= 2 and not _NAME_BAD.match(name):
                return name
    return "Unknown"


def parse_txn_id(text, utr):
    m = re.search(r"\b(FM(?=[A-Z0-9]*\d)[A-Z0-9]{6,30})\b", text)
    if m:
        return m.group(1)
    m = re.search(r"(?:transaction|txn|order)\s*(?:id|no\.?|number|ref(?:erence)?)\s*[:#\-]?\s*([A-Za-z0-9\-]{8,40})",
                  text, re.I)
    if m and m.group(1) != utr:
        return m.group(1)
    return None


# ---------------------------------------------------------------- sender / authenticity check
def _allowed_domains():
    raw = os.getenv("SENDER_DOMAINS") or DEFAULT_SENDER_DOMAINS
    return [d.strip().lower().lstrip("@.") for d in raw.split(",") if d.strip()]


def _domain_ok(domain):
    domain = (domain or "").lower().strip(".")
    return any(d == "*" or domain == d or domain.endswith("." + d) for d in _allowed_domains())


def _auth_pass(ar, ident_ok):
    """Gmail ke Authentication-Results me allowed domain ke liye dmarc/dkim/spf pass dhoondhta hai."""
    m = re.search(r"dmarc=pass[^;]*?header\.from=([\w.\-]+)", ar, re.I)
    if m and ident_ok(m.group(1)):
        return True
    for m in re.finditer(r"dkim=pass[^;]*?header\.(?:d|i)=(?:[^@\s;]*@)?([\w.\-]+)", ar, re.I):
        if ident_ok(m.group(1)):
            return True
    for m in re.finditer(r"spf=pass[^;]*?smtp\.mailfrom=(?:[^@\s;]*@)?([\w.\-]+)", ar, re.I):
        if ident_ok(m.group(1)):
            return True
    return False


def check_sender(msg):
    _, addr = parseaddr(str(msg.get("From", "")))
    addr = addr.lower()
    domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""
    exact = [e.strip().lower() for e in os.getenv("SENDER_EMAILS", "").split(",") if e.strip()]
    if addr and addr in exact:
        def ident_ok(d):
            return d.lower() == domain or _domain_ok(d)
    elif _domain_ok(domain):
        ident_ok = _domain_ok
    else:
        return False, (f"An email with this UTR was found, but its sender ({addr or 'unknown'}) is not allowed. "
                       "Add the sender domain to SENDER_DOMAINS in .env.")
    if os.getenv("STRICT_AUTH", "1") == "0":
        return True, ""
    ars = msg.get_all("Authentication-Results") or []
    top = " ".join(str(ars[0]).split()) if ars else ""  # sirf Gmail ka apna (sabse upar wala) header
    if top.lower().startswith("mx.google.com") and _auth_pass(top, ident_ok):
        return True, ""
    return False, ("The email failed the DKIM/SPF authenticity check, so it was not accepted. "
                   "If it is a genuine FamPay email, set STRICT_AUTH=0 in .env.")


def _mail_date(msg):
    try:
        d = parsedate_to_datetime(str(msg.get("Date")))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(IST)
    except Exception:
        return datetime.now(IST)


def _evaluate(raw, utr):
    msg = email.message_from_bytes(raw, policy=policy.default)
    ok, why = check_sender(msg)
    if not ok:
        return None, why
    subject = str(msg.get("Subject", "") or "")
    text = subject + "\n" + message_text(msg)
    if not re.search(r"(?<!\d)%s(?!\d)" % re.escape(utr), text):
        return None, "The matching email does not contain this UTR."
    amount = parse_amount(text)
    if amount is None:
        return None, "The email was found but the amount could not be read from it."
    return {
        "utr": utr,
        "transaction_id": parse_txn_id(text, utr),
        "amount": amount,
        "sender_name": parse_sender(text),
        "paid_at": _mail_date(msg),
        "mail_from": parseaddr(str(msg.get("From", "")))[1],
        "subject": subject,
    }, ""


# ---------------------------------------------------------------- main entry
def find_payment(gmail, app_password, utr, days=None, max_age_hours=None):
    """UTR ka payment email dhoondho. Dict return karta hai, warna PaymentNotFound / MailRejected / GmailError."""
    utr = str(utr).strip()
    if not UTR_RE.fullmatch(utr):
        raise ValueError("UTR must be exactly 12 digits.")
    days = days or int(os.getenv("LOOKBACK_DAYS", "2"))
    if max_age_hours is None:
        max_age_hours = float(os.getenv("MAX_PAYMENT_AGE_HOURS", "24"))
    with _lock_for(gmail.strip().lower()):
        m = _open(gmail.strip(), app_password)
        try:
            _select_all_mail(m)
            uids = _search(m, utr, days)
            if not uids:
                raise PaymentNotFound("Payment not found yet. The FamPay email may take a minute to arrive "
                                      "- wait a bit and verify again.")
            first_reason = ""
            for uid in uids:
                raw = _fetch(m, uid)
                if not raw:
                    continue
                result, why = _evaluate(raw, utr)
                if result:
                    if max_age_hours and result["paid_at"] < datetime.now(IST) - timedelta(hours=max_age_hours):
                        raise PaymentNotFound(f"This payment is older than {max_age_hours:g} hours.")
                    return result
                first_reason = first_reason or why
            if first_reason:
                raise MailRejected(first_reason)
            raise PaymentNotFound("Payment not found yet.")
        except (imaplib.IMAP4.error, OSError) as e:
            raise GmailError("Gmail connection problem. Please try again.") from e
        finally:
            _close(m)


# ---------------------------------------------------------------- auto payment: UTR ke bina recent mails scan
_CREDIT_RE = re.compile(r"\b(received|receive|credited|credit|paid you|sent you|payment from|money in|"
                        r"added to|deposited|collected|incoming)\b", re.I)
_DEBIT_RE = re.compile(r"\b(debited|debit|you paid|you sent|paid to|sent to|payment to|money out|withdrawn)\b", re.I)
_cache, _cache_lock = {}, threading.Lock()   # (gmail, uid) -> (result, reason, info): har mail sirf ek baar fetch/parse


def _extract_utr(text):
    m = re.search(r"UTR[^0-9]{0,25}(\d{12})(?!\d)", text, re.I) or re.search(r"(?<!\d)(\d{12})(?!\d)", text)
    return m.group(1) if m else None


def _is_credit(subject, text):
    """Paisa AAYA hai (credit) ya gaya hai (debit)? Subject me sirf debit shabd ho to reject."""
    if _DEBIT_RE.search(subject) and not _CREDIT_RE.search(subject):
        return False
    return bool(_CREDIT_RE.search(text))


def _parse_internal(s):
    """IMAP INTERNALDATE ('09-Oct-2026 11:14:03 +0530') -> aware datetime (IST). Ye Gmail ke paas mail aane ka
    asli time hai, sender ke 'Date' header (jo galat timezone me ho sakta hai) par nirbhar nahi."""
    try:
        return datetime.strptime(s.strip(), "%d-%b-%Y %H:%M:%S %z").astimezone(IST)
    except Exception:
        return None


def _sender_allowed(addr):
    addr = (addr or "").lower().strip()
    domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""
    exact = [e.strip().lower() for e in os.getenv("SENDER_EMAILS", "").split(",") if e.strip()]
    return addr in exact or _domain_ok(domain)


def _fetch_meta(m, uid):
    """Sasta fetch: sirf INTERNALDATE + From header. -> (arrived_datetime | None, from_addr)"""
    typ, data = m.uid("FETCH", uid, "(INTERNALDATE BODY.PEEK[HEADER.FIELDS (FROM)])")
    if typ != "OK":
        return None, ""
    arrived, frm = None, ""
    for part in data or []:
        chunks = [part[0], part[1]] if isinstance(part, tuple) else [part]
        for c in chunks:
            if not isinstance(c, (bytes, bytearray)):
                continue
            mt = re.search(rb'INTERNALDATE "([^"]+)"', bytes(c))
            if mt and arrived is None:
                arrived = _parse_internal(mt.group(1).decode("ascii", "ignore"))
        if isinstance(part, tuple) and len(part) >= 2 and isinstance(part[1], (bytes, bytearray)):
            hdr = email.message_from_bytes(bytes(part[1]))
            frm = parseaddr(str(hdr.get("From", "")))[1]
    return arrived, frm


def _judge(raw, arrived=None):
    """Mail ko parakho. -> (result | None, reason, info). Kisi bhi genuine 'payment received' mail se
    UTR/amount/sender/time nikalta hai."""
    msg = email.message_from_bytes(raw, policy=policy.default)
    subject = str(msg.get("Subject", "") or "")
    info = {"from": parseaddr(str(msg.get("From", "")))[1], "subject": subject[:120]}
    ok, why = check_sender(msg)
    if not ok:
        return None, why, info
    text = subject + "\n" + message_text(msg)
    if not _is_credit(subject, text):
        return None, "mail does not look like a 'money received' mail (no received/credited/paid-you wording found, or it is a debit mail)", info
    amount = parse_amount(text)
    if amount is None:
        return None, "could not read the amount from the mail", info
    utr = _extract_utr(text)
    synthetic = False
    if not utr:  # mail me 12-digit UTR na ho to mail ke Message-ID se ek pakka reference bana lo
        mid = str(msg.get("Message-ID") or (subject + str(arrived)))
        utr, synthetic = "M" + hashlib.sha1(mid.encode("utf-8", "ignore")).hexdigest()[:11].upper(), True
    res = {"utr": utr, "transaction_id": parse_txn_id(text, utr), "amount": amount,
           "sender_name": parse_sender(text), "paid_at": arrived or _mail_date(msg),
           "mail_date": _mail_date(msg), "synthetic_utr": synthetic}
    return res, "", info


def _evaluate_any(raw, arrived=None):
    return _judge(raw, arrived)[0]


def _scan(gmail, app_password, days, limit):
    """Pichhle `days` din ki mails -> list of (uid, result|None, reason, info). Purani mails cache se aati hain,
    isliye har scan me sirf NAYI mails fetch hoti hain (fast)."""
    key = gmail.strip().lower()
    with _lock_for(key):
        m = _open(gmail.strip(), app_password)
        try:
            _select_all_mail(m)
            typ, data = m.uid("SEARCH", "X-GM-RAW", '"newer_than:%dd"' % days)
            if typ != "OK":
                since = datetime.now(IST) - timedelta(days=days)
                typ, data = m.uid("SEARCH", None, "SINCE", _imap_date(since))
            if typ != "OK":
                raise GmailError("Gmail search failed. Please try again.")
            uids = (data[0] or b"").split()[-limit:]
            rows = []
            for uid in uids:
                ck = (key, uid)
                with _cache_lock:
                    hit = _cache.get(ck)
                if hit is None:
                    arrived, frm = _fetch_meta(m, uid)
                    if frm and not _sender_allowed(frm):
                        hit = (None, "sender %s is not in the allowed list (SENDER_DOMAINS)" % frm, {"from": frm, "subject": ""})
                    else:
                        raw = _fetch(m, uid)
                        if not raw:
                            continue  # fetch fail: cache mat karo, agli baar dobara try hoga
                        hit = _judge(raw, arrived)
                    with _cache_lock:
                        if len(_cache) > 3000:
                            _cache.clear()
                        _cache[ck] = hit
                rows.append((uid.decode(), *hit))
            return rows
        except (imaplib.IMAP4.error, OSError) as e:
            raise GmailError("Gmail connection problem. Please try again.") from e
        finally:
            _close(m)


def scan_recent(gmail, app_password, days=1, limit=40):
    """Pichhle `days` din ke payment mails (sender/DKIM check ke baad). List of dict, purana pehle."""
    out = [r for _, r, _, _ in _scan(gmail, app_password, days, limit) if r]
    out.sort(key=lambda r: r["paid_at"])
    return out


def scan_debug(gmail, app_password, days=1, limit=40):
    """Har recent mail ka hisaab: accept hui ya kyun reject hui. Debugging ke liye."""
    out = []
    for uid, r, why, info in _scan(gmail, app_password, days, limit):
        row = {"uid": uid, "from": info.get("from"), "subject": info.get("subject"), "accepted": bool(r), "reason": why}
        if r:
            row.update(amount=r["amount"], utr=r["utr"], utr_from_mail=not r["synthetic_utr"],
                       paid_at=r["paid_at"].isoformat(timespec="seconds"),
                       mail_date_header=r["mail_date"].isoformat(timespec="seconds"),
                       paid_ts=int(r["paid_at"].timestamp()))
        out.append(row)
    return out
