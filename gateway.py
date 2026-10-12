"""
gateway.py  -  FamGateway (https://famgateway.in) REST client.

Plans system ke liye subscription payments isi external gateway se verify
hote hain (admin panel me set kiya hua api_key use hota hai -> DB settings
table, .env FAMGATEWAY_API_KEY fallback).

    import gateway as fg
    order = fg.create_order(amount=99, customer_name="Rahul", redirect_url="https://site/x")
    status = fg.verify_order(order["order_id"])
    if status["paid"]: ...
"""
import json
import os
import time
import urllib.error
import urllib.request

BASE_URL = os.getenv("FAMGATEWAY_BASE_URL", "https://famapp-production-daca.up.railway.app").rstrip("/")
TIMEOUT = int(os.getenv("FAMGATEWAY_TIMEOUT", "20"))

__all__ = ["GatewayError", "create_order", "verify_order", "qr_image_url"]


class GatewayError(Exception):
    """FamGateway API call fail hui (network, auth, ya business error)."""

    def __init__(self, message, code=None, status=None):
        super().__init__(message)
        self.message = message
        self.code = code        # HTTP status
        self.status = status    # response "status" field, e.g. "unauthorized"


def _request(method, path, api_key=None, params=None, json_body=None):
    url = BASE_URL + path
    if params:
        from urllib.parse import urlencode
        q = urlencode({k: v for k, v in params.items() if v is not None})
        if q:
            url += ("&" if "?" in url else "?") + q
    headers = {"Accept": "application/json",
               "User-Agent": "Mozilla/5.0 (compatible; FamPayServer/1.0; +https://famgateway.in)"}
    data = None
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(json_body).encode()
    if api_key:
        headers["X-Api-Key"] = api_key
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
            code = resp.getcode()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        code = e.code
    except urllib.error.URLError as e:
        raise GatewayError("Could not reach FamGateway: %s" % e.reason)
    except Exception as e:
        raise GatewayError("FamGateway request fail: %s" % e)
    try:
        payload = json.loads(body) if body else {}
    except ValueError:
        raise GatewayError("Received an invalid response from FamGateway.", code=code)
    return payload, code


def create_order(api_key, amount, order_id=None, redirect_url=None, webhook_url=None,
                  customer_name=None, customer_email=None, customer_phone=None, retries=2):
    """POST /api.php action=create_order -> dict: order_id (gateway id), qr_url, checkout_url, upi_intent."""
    body = {"action": "create_order", "amount": "%.2f" % float(amount), "expiry_minutes": 15}
    if order_id:
        body["order_id"] = order_id
    if redirect_url:
        body["redirect_url"] = redirect_url
    if customer_name:
        body["payer"] = customer_name[:60]
    last_err = None
    for attempt in range(retries + 1):
        try:
            payload, code = _request("POST", "/api.php", api_key=api_key, json_body=body)
        except GatewayError as e:
            last_err = e
            time.sleep(0.6)
            continue
        if payload.get("ok"):
            gid = payload.get("gateway_order_id")
            return {"order_id": gid, "checkout_url": payload.get("checkout_url"),
                    "qr_url": "%s/pay/%s/qr.png" % (BASE_URL, gid), "upi_intent": None,
                    "payable_amount": payload.get("amount"), "expires_at_ist": payload.get("expires_at")}
        msg = payload.get("error") or payload.get("message") or "Could not create the order."
        if code == 401:
            raise GatewayError("Gateway API key is invalid.", code=401, status="unauthorized")
        if code and code >= 500:
            last_err = GatewayError(msg, code=code)
            time.sleep(0.6)
            continue
        raise GatewayError(msg, code=code, status="error")
    raise last_err or GatewayError("Could not create the order.")


def verify_order(api_key, order_id):
    """POST /api.php action=verify -> normalized dict: paid, status, amount, utr."""
    payload, code = _request("POST", "/api.php", api_key=api_key,
                             json_body={"action": "verify", "order_id": order_id})
    if code == 401:
        raise GatewayError("Gateway API key is invalid.", code=401, status="unauthorized")
    if code == 404:
        return {"paid": False, "status": "not_found", "order_id": order_id}
    if not payload.get("ok"):
        return {"paid": False, "status": "pending", "order_id": order_id}
    st = payload.get("status")
    if payload.get("paid") or st == "success":
        return {"paid": True, "status": "success", "order_id": order_id, "amount": payload.get("amount"),
                "utr": payload.get("reference"), "sender_name": None, "transaction_id": payload.get("reference"),
                "payment_time_ist": payload.get("paid_at")}
    if st == "expired":
        return {"paid": False, "status": "expired", "order_id": order_id}
    return {"paid": False, "status": "pending", "order_id": order_id}


def qr_image_url(order_id):
    return "%s/pay/%s/qr.png" % (BASE_URL, order_id)


def fetch_qr_png(order_id):
    """Railway API ke order ka QR PNG bytes (public /pay/<id>/qr.png) - apne server se serve karne ke liye."""
    req = urllib.request.Request(qr_image_url(order_id), headers={"User-Agent": "FamPayServer/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = r.read()
            if r.getcode() != 200 or not data.startswith(b"\x89PNG"):
                raise GatewayError("QR image not found.")
            return data
    except GatewayError:
        raise
    except Exception as e:
        raise GatewayError("QR image not found: %s" % e)
