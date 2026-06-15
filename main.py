from __future__ import annotations
"""
TopstepX Bracket Entry Bot  v4.0.0  (multi-user)

A self-hosted website where each user logs in with an account YOU create,
then connects their own Topstep account to place / auto-fire bracket orders.

Key properties:
  * Multi-tenant: every logged-in user gets an isolated session (own Topstep
    token, own armed scheduler, own log). Users never see each other's data.
  * Admin-created accounts only. The owner (admin) creates users, sets their
    password, and toggles them active/inactive for monthly billing.
  * Topstep credentials are held in session memory ONLY and never written to
    disk. App-account passwords are stored as salted PBKDF2 hashes.
  * Concurrent: served by a threaded HTTP server.
"""
import threading, webbrowser, time, json, os, signal, subprocess, hashlib, hmac, secrets
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
import zoneinfo, requests as req

VERSION   = "5.4.0"
PORT      = 5050
# TopstepX runs on the ProjectX Gateway. One REST base for everything;
# the Demo/Live toggle only affects how we label the connection (TopstepX
# routes eval + funded accounts through the same gateway).
BASE      = "https://api.topstepx.com"
RTC_MKT   = "wss://rtc.topstepx.com/hubs/market"
ET        = zoneinfo.ZoneInfo("America/New_York")
APP_DIR   = os.path.dirname(os.path.abspath(__file__))
USERS_DB  = os.path.join(APP_DIR, "users.json")
LOCK      = threading.RLock()          # guards USERS + SESSIONS
SESSIONS  = {}                         # sid -> session dict
TOKEN_TTL = 45 * 60                    # renew Topstep token if older than this
SESS_IDLE = 24 * 3600                  # drop idle sessions after this many secs

# Central license server: every login is validated here. The owner manages all
# accounts (create / deactivate / expire / delete) from this server's panel, so
# deleting or deactivating a user there instantly locks them out of this app.
LICENSE_SERVER = os.environ.get(
    "GUNNA_LICENSE_SERVER",
    "https://gunnas-strat-production.up.railway.app",
).rstrip("/")
LICENSE_RECHECK = 180   # seconds between mid-session license re-checks

# ─────────────────────────────────────────────────────────────────────────────
#  App-account store (the login to YOUR website)
# ─────────────────────────────────────────────────────────────────────────────
def _hash_pw(pw, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()
    return salt, h

def _verify_pw(pw, salt, h):
    return hmac.compare_digest(_hash_pw(pw, salt)[1], h)

def validate_license(username, password):
    """Validate a login against the central license server.
    Returns (ok: bool, info_or_error). On success info is the server's JSON
    ({"username","is_admin","expires"}). On failure it's a user-facing string."""
    try:
        r = req.post(f"{LICENSE_SERVER}/api/validate",
                     json={"username": username, "password": password},
                     timeout=10)
    except Exception:
        return False, "Can't reach the license server. Check your internet connection and try again."
    try:
        data = r.json()
    except Exception:
        return False, "License server returned an unexpected response. Try again shortly."
    if data.get("ok"):
        return True, data
    reason = data.get("reason")
    if reason == "inactive":
        return False, "Your account has been deactivated. Contact the owner."
    if reason == "expired":
        return False, "Your subscription has expired. Contact the owner to renew."
    return False, data.get("error", "Invalid username or password")

def license_active(username):
    """Passwordless mid-session status check against the central server.
    Returns True if the account is still active. Fails OPEN on any network
    or server error so a brief outage never logs out a legitimate user."""
    try:
        r = req.post(f"{LICENSE_SERVER}/api/status",
                     json={"username": username}, timeout=8)
        data = r.json()
    except Exception:
        return True  # fail open: don't punish users for a flaky connection
    if not data.get("exists"):
        return False
    if not data.get("active"):
        return False
    if data.get("expired"):
        return False
    return True

def load_users():
    with LOCK:
        if not os.path.exists(USERS_DB):
            return {}
        try:
            with open(USERS_DB) as f:
                return json.load(f)
        except Exception:
            return {}

def save_users(users):
    with LOCK:
        tmp = USERS_DB + ".tmp"
        with open(tmp, "w") as f:
            json.dump(users, f, indent=2)
        os.replace(tmp, USERS_DB)

def bootstrap_admin():
    """On first run, create an admin account and print the password once."""
    users = load_users()
    if users:
        return
    pw = secrets.token_urlsafe(9)
    salt, h = _hash_pw(pw)
    users["admin"] = {"salt": salt, "hash": h, "active": True,
                      "is_admin": True, "created": datetime.now().isoformat()}
    save_users(users)
    print("\n" + "=" * 56)
    print("  FIRST-RUN SETUP — an admin account was created for you")
    print("  Username: admin")
    print(f"  Password: {pw}")
    print("  Log in, then create accounts for your users in /admin")
    print("  (You can change this password from the admin panel.)")
    print("=" * 56 + "\n")

# ─────────────────────────────────────────────────────────────────────────────
#  TopstepX (ProjectX Gateway) API — every call takes an explicit bearer token
#  Docs: https://gateway.docs.projectx.com/
# ─────────────────────────────────────────────────────────────────────────────
RECORD_SEP = "\x1e"        # SignalR JSON frame terminator

# OrderType enum: 1 Limit, 2 Market, 4 Stop.  OrderSide enum: 0 Bid(buy), 1 Ask(sell).
SIDE_BUY, SIDE_SELL, TYPE_STOP = 0, 1, 4

def _h(token):
    return {"Authorization": f"Bearer {token}",
            "Content-Type": "application/json", "Accept": "text/plain"}

def ts_auth(username, api_key):
    """Log in with a TopstepX username + API key. Returns (ok, token_or_error)."""
    body = {"userName": username, "apiKey": api_key}
    r = req.post(f"{BASE}/api/Auth/loginKey", json=body, timeout=15)
    try:
        d = r.json()
    except Exception:
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    if d.get("success") and d.get("token"):
        return True, d["token"]
    msg = (d.get("errorMessage")
           or f"Login failed (errorCode {d.get('errorCode')}, HTTP {r.status_code})")
    return False, msg

def ts_renew(token):
    """Re-validate a session token; returns a fresh token or None."""
    try:
        r = req.post(f"{BASE}/api/Auth/validate", headers=_h(token), timeout=15)
        d = r.json()
        if d.get("success"):
            return d.get("newToken") or d.get("token") or token
    except Exception:
        pass
    return None

def ts_accounts(token):
    r = req.post(f"{BASE}/api/Account/search",
                 json={"onlyActiveAccounts": True}, headers=_h(token), timeout=15)
    d = r.json()
    return d.get("accounts", []) if isinstance(d, dict) else []

def ts_find_contract(token, symbol, live=False):
    """Search contracts; return the first active match (a dict) or None."""
    r = req.post(f"{BASE}/api/Contract/search",
                 json={"searchText": symbol, "live": bool(live)},
                 headers=_h(token), timeout=15)
    d = r.json()
    contracts = d.get("contracts", []) if isinstance(d, dict) else []
    if not contracts:
        return None
    for c in contracts:
        if c.get("activeContract"):
            return c
    return contracts[0]

def ts_place_stop(token, account_id, contract_id, side, stop_price, qty):
    """Place a stop entry order. side = SIDE_BUY / SIDE_SELL."""
    payload = {"accountId": int(account_id), "contractId": contract_id,
               "type": TYPE_STOP, "side": int(side), "size": int(qty),
               "stopPrice": float(stop_price)}
    r = req.post(f"{BASE}/api/Order/place", json=payload, headers=_h(token), timeout=15)
    return r.json()

def _order_id(resp):
    """Pull the order id out of a place response (or None on failure)."""
    if not isinstance(resp, dict):
        return None
    return resp.get("orderId") or resp.get("id")

def ts_cancel_order(token, account_id, order_id):
    """Cancel a working order by id."""
    payload = {"accountId": int(account_id), "orderId": int(order_id)}
    r = req.post(f"{BASE}/api/Order/cancel", json=payload, headers=_h(token), timeout=15)
    try:
        return r.json()
    except Exception:
        return {"success": False, "http": r.status_code}

def ts_search_open(token, account_id):
    """Return the list of currently working/open orders for an account."""
    r = req.post(f"{BASE}/api/Order/searchOpen",
                 json={"accountId": int(account_id)}, headers=_h(token), timeout=15)
    d = r.json()
    return d.get("orders", []) if isinstance(d, dict) else []

def ts_order_status(token, account_id, order_id, since_iso):
    """Look up one order's status int via Order/search. None if not found.
    ProjectX OrderStatus: 1 Open/Working, 2 Filled, 3 Cancelled, 4 Expired,
    5 Rejected, 6 Pending."""
    payload = {"accountId": int(account_id), "startTimestamp": since_iso}
    r = req.post(f"{BASE}/api/Order/search", json=payload, headers=_h(token), timeout=15)
    d = r.json()
    orders = d.get("orders", []) if isinstance(d, dict) else []
    for o in orders:
        if o.get("id") == order_id:
            return o.get("status")
    return None

ORDER_FILLED   = 2          # ProjectX OrderStatus == Filled
OCO_WATCH_SECS = 6 * 3600   # give up watching a bracket after 6 hours

def oco_monitor(sess, token, account_id, buy_id, sell_id):
    """One-Cancels-the-Other: watch the two stop orders and, the moment one
    fills, cancel its sibling so a whipsaw can't trigger both sides."""
    if not buy_id or not sell_id:
        if not buy_id and not sell_id:
            return
        # Only one order actually placed — nothing to pair it with.
        return
    since_iso = (datetime.now(ET) - timedelta(minutes=5)).isoformat()
    deadline = time.time() + OCO_WATCH_SECS
    log_s(sess, "🛡 OCO active — first stop to fill cancels the other.")
    while time.time() < deadline:
        time.sleep(1.0)
        # Stop watching if the session was reaped / user logged out.
        try:
            with LOCK:
                alive = any(s is sess for s in SESSIONS.values())
            if not alive:
                return
        except Exception:
            pass
        try:
            open_ids = {o.get("id") for o in ts_search_open(token, account_id)}
        except Exception:
            continue
        buy_open, sell_open = buy_id in open_ids, sell_id in open_ids
        if buy_open and sell_open:
            continue
        # At least one order has left the working list — find out which filled.
        try:
            if not buy_open and sell_open:
                if ts_order_status(token, account_id, buy_id, since_iso) == ORDER_FILLED:
                    ts_cancel_order(token, account_id, sell_id)
                    log_s(sess, "🎯 Stop Buy filled → cancelled the Stop Sell (OCO)")
                return
            if buy_open and not sell_open:
                if ts_order_status(token, account_id, sell_id, since_iso) == ORDER_FILLED:
                    ts_cancel_order(token, account_id, buy_id)
                    log_s(sess, "🎯 Stop Sell filled → cancelled the Stop Buy (OCO)")
                return
            # Neither is working anymore — resolve who filled before stopping.
            sb = ts_order_status(token, account_id, buy_id, since_iso)
            ss = ts_order_status(token, account_id, sell_id, since_iso)
            if sb == ORDER_FILLED and ss != ORDER_FILLED:
                ts_cancel_order(token, account_id, sell_id)
                log_s(sess, "🎯 Stop Buy filled → cancelled the Stop Sell (OCO)")
            elif ss == ORDER_FILLED and sb != ORDER_FILLED:
                ts_cancel_order(token, account_id, buy_id)
                log_s(sess, "🎯 Stop Sell filled → cancelled the Stop Buy (OCO)")
            return
        except Exception as e:
            log_s(sess, f"⚠ OCO watch error: {e}")
            return

def ts_quote_live(token, contract_id, timeout=8.0):
    """Open the SignalR market hub and return the first live lastPrice (float)
    for contract_id, or None if no quote arrives within `timeout` seconds."""
    try:
        import websocket  # websocket-client
    except ImportError:
        raise RuntimeError("websocket-client not installed — run: pip install websocket-client")
    url = f"{RTC_MKT}?access_token={token}"
    ws = websocket.create_connection(url, timeout=timeout)
    try:
        ws.settimeout(timeout)
        ws.send('{"protocol":"json","version":1}' + RECORD_SEP)   # handshake
        ws.recv()                                                  # handshake ack
        ws.send(json.dumps({"arguments": [contract_id],
                            "target": "SubscribeContractQuotes",
                            "type": 1}) + RECORD_SEP)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                raw = ws.recv()
            except Exception:
                break
            if not raw:
                continue
            for part in raw.split(RECORD_SEP):
                part = part.strip()
                if not part:
                    continue
                try:
                    msg = json.loads(part)
                except Exception:
                    continue
                if msg.get("target") == "GatewayQuote":
                    args = msg.get("arguments", [])
                    data = next((a for a in args if isinstance(a, dict)), {})
                    px = data.get("lastPrice")
                    if px is None:
                        b, a = data.get("bestBid"), data.get("bestAsk")
                        if b is not None and a is not None:
                            px = (b + a) / 2
                        else:
                            px = b if b is not None else a
                    if px is not None:
                        return float(px)
        return None
    finally:
        try:
            ws.close()
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
#  Per-session helpers
# ─────────────────────────────────────────────────────────────────────────────
def new_session(username, is_admin):
    return {
        "user": username, "is_admin": is_admin,
        "ts_token": None, "ts_token_time": 0,
        "accounts": [], "contract": None,
        "armed": False, "fired_date": None,
        "buy_pts": 10, "sell_pts": 10, "qty": 1, "selected_account": "", "price": "",
        "log": [], "last_seen": time.time(), "last_check": time.time(),
    }

def log_s(sess, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    sess["log"].append(entry)
    if len(sess["log"]) > 200:
        sess["log"] = sess["log"][-200:]
    print(f"({sess['user']}) {entry}")

def ensure_token(sess):
    """Renew the Topstep token if it's getting stale. Returns True if usable."""
    if not sess["ts_token"]:
        return False
    if time.time() - sess["ts_token_time"] > TOKEN_TTL:
        new = ts_renew(sess["ts_token"])
        if new:
            sess["ts_token"] = new
            sess["ts_token_time"] = time.time()
            log_s(sess, "Session token renewed")
        else:
            log_s(sess, "⚠ Token renewal failed — please reconnect Topstep")
            return False
    return True

def selected_account(sess):
    sel = str(sess.get("selected_account", "")).strip()
    accts = sess["accounts"]
    if not accts:
        return None
    if not sel:
        return accts[0]
    for a in accts:
        if str(a["id"]) == sel:
            return a
    return accts[0]

# ─────────────────────────────────────────────────────────────────────────────
#  Scheduler — fires for every logged-in, armed session at 9:29:57 ET
# ─────────────────────────────────────────────────────────────────────────────
def scheduler_loop():
    while True:
        time.sleep(0.25)
        now = datetime.now(ET)
        target = now.replace(hour=9, minute=29, second=57, microsecond=0)
        today = now.date()
        in_window = now >= target and (target - now).total_seconds() > -5
        with LOCK:
            sess_list = list(SESSIONS.values())
        for sess in sess_list:
            if not sess.get("armed"):
                continue
            if in_window and sess.get("fired_date") != today:
                sess["fired_date"] = today
                sess["fired"] = True
                threading.Thread(target=fire_for, args=(sess,), daemon=True).start()

def fire_for(sess, manual=False):
    if manual:
        log_s(sess, "⚡ Test fire — fetching live price and placing orders…")
    else:
        log_s(sess, "⏰ 9:29:57 — auto-fetching price and placing orders…")
    if not ensure_token(sess) or not sess["contract"]:
        log_s(sess, "❌ Not connected to Topstep or no contract set"); return
    acct = selected_account(sess)
    if not acct:
        log_s(sess, "❌ No account selected"); return
    try:
        buy_pts = float(sess.get("buy_pts", 10)); sell_pts = float(sess.get("sell_pts", 10))
        qty = int(sess.get("qty", 1))
    except Exception:
        log_s(sess, "❌ Invalid points/qty"); return
    token = sess["ts_token"]
    cid = sess["contract"]["id"]
    try:
        price = ts_quote_live(token, cid)
        if price is None:
            log_s(sess, "❌ No live quote received (market closed or no data subscription)"); return
        sess["price"] = str(price)
        log_s(sess, f"⏰ Live price: {price}")
    except Exception as e:
        log_s(sess, f"❌ Price fetch error: {e}"); return
    try:
        buy_px, sell_px = round(price + buy_pts, 4), round(price - sell_pts, 4)
        log_s(sess, f"⏰ Stop Buy @ {buy_px}  +  Stop Sell @ {sell_px}  qty={qty}…")
        r1 = ts_place_stop(token, acct["id"], cid, SIDE_BUY,  buy_px,  qty)
        log_s(sess, f"⏰ Buy  → {r1}")
        r2 = ts_place_stop(token, acct["id"], cid, SIDE_SELL, sell_px, qty)
        log_s(sess, f"⏰ Sell → {r2}")
        buy_id, sell_id = _order_id(r1), _order_id(r2)
        threading.Thread(target=oco_monitor,
                         args=(sess, token, acct["id"], buy_id, sell_id),
                         daemon=True).start()
        if manual:
            log_s(sess, "✅ Test fire complete — orders placed")
        else:
            log_s(sess, "✅ Orders placed — scheduler disarmed")
            sess["armed"] = False
    except Exception as e:
        log_s(sess, f"❌ Order error: {e}")

def reaper_loop():
    """Drop sessions that have been idle too long, to bound memory."""
    while True:
        time.sleep(600)
        cutoff = time.time() - SESS_IDLE
        with LOCK:
            dead = [sid for sid, s in SESSIONS.items() if s["last_seen"] < cutoff]
            for sid in dead:
                SESSIONS.pop(sid, None)

# ─────────────────────────────────────────────────────────────────────────────
#  HTML
# ─────────────────────────────────────────────────────────────────────────────
STYLE = r"""
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root{
  --bg:#0b0e14;--bg-2:#0f131c;--surface:#141925;--surface-2:#1a2030;
  --line:#222a3a;--line-2:#2c3550;--text:#eef2fb;--text-2:#9aa6c0;--muted:#6b7690;
  --primary:#6d8bff;--primary-d:#5a78f0;--primary-soft:rgba(109,139,255,.12);
  --buy:#1fc78a;--buy-bg:rgba(31,199,138,.12);--sell:#ff5d73;--sell-bg:rgba(255,93,115,.12);
  --warn:#f0b352;--warn-bg:rgba(240,179,82,.10);
  --radius:16px;--radius-sm:10px;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 8px 30px rgba(0,0,0,.28);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;background:
  radial-gradient(1200px 600px at 50% -200px,rgba(109,139,255,.10),transparent 60%),var(--bg);
  color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased;letter-spacing:-.1px}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:0 28px;height:66px;
  background:rgba(15,19,28,.72);backdrop-filter:blur(14px);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:100}
.brand{display:flex;align-items:center;gap:12px}
.brand-icon{width:36px;height:36px;background:linear-gradient(140deg,#6d8bff,#9b6dff);border-radius:11px;
  display:flex;align-items:center;justify-content:center;color:#fff;font-size:18px;font-weight:800;
  box-shadow:0 4px 16px rgba(109,139,255,.4)}
.brand-name{font-size:17px;font-weight:800;color:var(--text);letter-spacing:-.4px}
.brand-ver{font-size:11px;color:var(--muted);font-weight:500;margin-left:6px;letter-spacing:0}
.top-right{display:flex;align-items:center;gap:18px}
.who{font-size:13px;color:var(--text-2);font-weight:500}
.toplink{font-size:13px;color:var(--primary);text-decoration:none;font-weight:600}
.toplink:hover{color:#fff}
.env-row{display:flex;gap:6px;align-items:center}
.env-label{font-size:11px;color:var(--muted);font-weight:600;margin-right:4px;text-transform:uppercase;letter-spacing:.5px}
.env-pill{padding:6px 15px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid var(--line-2);background:var(--surface);color:var(--text-2);transition:all .15s;letter-spacing:.3px}
.env-pill:hover{border-color:var(--primary);color:var(--primary)}
.env-pill.demo-on{background:var(--primary);color:#fff;border-color:var(--primary)}
.env-pill.live-on{background:var(--sell);color:#fff;border-color:var(--sell)}
.main{max-width:600px;margin:0 auto;padding:34px 18px 72px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:26px;margin-bottom:18px;box-shadow:var(--shadow)}
.card-head{display:flex;align-items:center;gap:13px;margin-bottom:22px}
.step-num{width:30px;height:30px;flex-shrink:0;border-radius:9px;background:var(--primary-soft);color:var(--primary);font-size:14px;font-weight:700;display:flex;align-items:center;justify-content:center;border:1px solid rgba(109,139,255,.25)}
.card-title{font-size:16px;font-weight:700;color:var(--text);flex:1;letter-spacing:-.3px}
.chip{padding:5px 12px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:.2px}
.chip-off{background:var(--surface-2);color:var(--muted);border:1px solid var(--line-2)}
.chip-on{background:var(--buy-bg);color:var(--buy);border:1px solid rgba(31,199,138,.3)}
.chip-blue{background:var(--primary-soft);color:var(--primary);border:1px solid rgba(109,139,255,.3)}
.card-action{font-size:12px;color:var(--text-2);cursor:pointer;padding:5px 12px;border-radius:7px;background:transparent;border:1px solid var(--line-2);font-family:inherit;font-weight:500;transition:all .15s}
.card-action:hover{color:var(--primary);border-color:var(--primary)}
.field{margin-bottom:17px}.field:last-child{margin-bottom:0}
.lbl{display:block;font-size:12px;font-weight:600;color:var(--text-2);margin-bottom:8px;letter-spacing:0}
input[type=text],input[type=password],input[type=number],select{width:100%;background:var(--bg-2);color:var(--text);border:1px solid var(--line-2);border-radius:var(--radius-sm);padding:12px 14px;font-size:14px;font-family:inherit;outline:none;transition:border .15s,box-shadow .15s;-moz-appearance:textfield;appearance:none}
select{background-image:url("data:image/svg+xml;charset=US-ASCII,%3Csvg width='12' height='8' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%239aa6c0' stroke-width='1.6' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center;padding-right:34px}
input[type=number]::-webkit-inner-spin-button,input[type=number]::-webkit-outer-spin-button{-webkit-appearance:none}
input:focus,select:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-soft);background:var(--bg)}
input::placeholder{color:#586280}
.row2{display:flex;gap:12px}.row2>*{flex:1}
.btn{cursor:pointer;border:none;border-radius:var(--radius-sm);padding:12px 18px;font-size:13px;font-weight:600;font-family:inherit;transition:all .15s;white-space:nowrap}
.btn-primary{width:100%;background:linear-gradient(135deg,var(--primary),#8a6dff);color:#fff;box-shadow:0 4px 16px rgba(109,139,255,.32)}
.btn-primary:hover{filter:brightness(1.08);box-shadow:0 6px 22px rgba(109,139,255,.42)}
.btn-ghost{background:var(--surface-2);color:var(--text-2);border:1px solid var(--line-2)}
.btn-ghost:hover{color:var(--primary);border-color:var(--primary);background:var(--surface)}
.btn-place{width:100%;padding:15px;font-size:15px;font-weight:700;background:linear-gradient(135deg,var(--buy),#16b87d);color:#04140d;border-radius:12px;margin-top:6px;letter-spacing:.1px;box-shadow:0 4px 16px rgba(31,199,138,.28)}
.btn-place:hover{filter:brightness(1.06)}
.btn-danger{background:var(--sell-bg);color:var(--sell);border:1px solid rgba(255,93,115,.35)}
.btn-danger:hover{background:var(--sell);color:#fff}
.st{font-size:12.5px;margin-top:10px;min-height:16px;font-weight:500}
.ok{color:var(--buy)}.err{color:var(--sell)}.wrn{color:var(--warn)}
.preview{display:flex;background:var(--bg-2);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin:18px 0 8px}
.pv-cell{flex:1;padding:15px 8px;text-align:center}
.pv-cell+.pv-cell{border-left:1px solid var(--line)}
.pv-lbl{font-size:10px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--muted);margin-bottom:7px}
.pv-val{font-family:'JetBrains Mono',monospace;font-size:19px;font-weight:600}
.pv-buy{color:var(--buy)}.pv-mid{color:var(--text);font-size:16px}.pv-sell{color:var(--sell)}
.sched-card{background:linear-gradient(180deg,var(--surface),var(--bg-2));border:1px solid var(--line);border-radius:var(--radius);padding:28px 26px;margin-bottom:18px;box-shadow:var(--shadow)}
.clock-area{text-align:center;margin-bottom:22px}
.clock-time{font-family:'JetBrains Mono',monospace;font-size:52px;font-weight:600;letter-spacing:2px;font-variant-numeric:tabular-nums;color:var(--text);line-height:1;margin-bottom:8px;text-shadow:0 2px 20px rgba(109,139,255,.25)}
.clock-sub{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1.6px;font-weight:600}
.countdown-bar{display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:20px;padding:11px;background:var(--bg-2);border:1px solid var(--line);border-radius:10px}
.cd-label{font-size:12px;color:var(--text-2);font-weight:500}
.cd-val{font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:600;color:var(--primary);font-variant-numeric:tabular-nums}
.cd-val.soon{color:var(--warn)}
.arm-btn{width:100%;padding:16px;font-size:15px;font-weight:700;font-family:inherit;letter-spacing:.2px;border:1.5px solid transparent;border-radius:12px;cursor:pointer;transition:all .18s}
.arm-off{background:var(--surface-2);color:var(--sell);border-color:rgba(255,93,115,.45)}
.arm-off:hover{background:var(--sell-bg)}
.arm-on{background:linear-gradient(135deg,var(--buy),#16b87d);color:#04140d;border-color:var(--buy);animation:armPulse 2.4s ease-in-out infinite}
@keyframes armPulse{0%,100%{box-shadow:0 0 0 0 rgba(31,199,138,.40)}50%{box-shadow:0 0 0 7px rgba(31,199,138,0)}}
.arm-desc{margin-top:15px;font-size:12.5px;line-height:1.65;color:var(--text-2);text-align:center}
.arm-desc.active{color:var(--buy);font-weight:500}
.log-box{background:#070a12;border:1px solid var(--line);border-radius:12px;padding:14px 16px;height:210px;overflow-y:auto;font-family:'JetBrains Mono',monospace;font-size:11.5px;color:#aeb9d0}
.log-box::-webkit-scrollbar{width:6px}.log-box::-webkit-scrollbar-thumb{background:#2a3656;border-radius:3px}
.le{padding:2px 0;line-height:1.6}
.le.ok{color:#4ade80}.le.err{color:#f87171}.le.inf{color:#7aa2ff}.le.wrn{color:#fbbf24}.le.dim{color:#5b6783;font-style:italic}
.footer{text-align:center;font-size:12px;color:var(--warn);background:var(--warn-bg);border:1px solid rgba(240,179,82,.22);border-radius:10px;padding:12px;margin-top:4px;font-weight:500;line-height:1.55}
.center-wrap{max-width:400px;margin:11vh auto 0;padding:0 16px}
.logo-big{display:flex;align-items:center;gap:13px;justify-content:center;margin-bottom:26px}
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:9px 10px;border-bottom:1px solid var(--line)}
.tbl td{padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
.badge-on{background:var(--buy-bg);color:var(--buy)}
.badge-off{background:var(--sell-bg);color:var(--sell)}
.mini{padding:6px 11px;font-size:12px;border-radius:7px}
"""

LOGIN_HTML = r"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — Gunna's Strat</title><style>__STYLE__</style></head><body>
<div class="center-wrap">
  <div class="logo-big">
    <div class="brand-icon">G</div>
    <span class="brand-name" style="font-size:20px">Gunna's Strat</span>
  </div>
  <div class="card">
    <div class="card-head"><span class="card-title">Sign in</span></div>
    <div class="field"><label class="lbl">Username</label><input id="u" type="text" autocomplete="username" placeholder="Your username"></div>
    <div class="field"><label class="lbl">Password</label><input id="p" type="password" autocomplete="current-password" placeholder="Your password"></div>
    <button class="btn btn-primary" onclick="signin()">Sign in</button>
    <div id="st" class="st"></div>
  </div>
  <div class="footer">Accounts are created by the site owner. Contact them for access.</div>
</div>
<script>
async function signin(){
  const st=document.getElementById('st');
  st.innerHTML='<span class="wrn">Signing in…</span>';
  const r=await fetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({user:document.getElementById('u').value,pass:document.getElementById('p').value})});
  const d=await r.json();
  if(d.ok){location.href='/';}else{st.innerHTML=`<span class="err">${d.error}</span>`;}
}
document.getElementById('p').addEventListener('keydown',e=>{if(e.key==='Enter')signin();});
</script></body></html>"""

APP_HTML = r"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gunna's Strat</title><style>__STYLE__</style></head><body>
<div class="topbar">
  <div class="brand"><div class="brand-icon">G</div>
    <span class="brand-name">Gunna's Strat<span class="brand-ver">v__VER__</span></span></div>
  <div class="top-right">
    <span class="who">__USERNAME__</span>__ADMIN_LINK__
    <a class="toplink" href="/logout">Log out</a>
  </div>
</div>
<div class="main">
  <div class="card">
    <div class="card-head"><span class="step-num">1</span><span class="card-title">Connect your TopstepX account</span>
      <span class="chip chip-off" id="connChip">Disconnected</span></div>
    <div class="field"><label class="lbl">TopstepX username</label><input id="user" type="text" placeholder="Your TopstepX username" autocomplete="off"></div>
    <div class="field"><label class="lbl">API key</label><input id="pass" type="password" placeholder="API key (TopstepX → Settings → API)"></div>
    <button class="btn btn-primary" onclick="connect()">Connect</button>
    <div id="loginSt" class="st"></div>
  </div>
  <div class="card">
    <div class="card-head"><span class="step-num">2</span><span class="card-title">Account &amp; orders</span>
      <span id="symChip" class="chip chip-blue" style="display:none"></span></div>
    <div class="field"><label class="lbl">Account</label><select id="acctSel"><option>Connect first</option></select></div>
    <div class="field"><label class="lbl">Symbol</label>
      <div class="row2"><input id="sym" type="text" placeholder="e.g. NQ, ENQ, MNQ, MES" value="NQ" style="flex:2">
        <button class="btn btn-ghost" onclick="lookup()">Look up</button></div>
      <div id="symSt" class="st"></div></div>
    <div class="row2">
      <div class="field"><label class="lbl">Buy pts (above)</label><input id="ptsBuy" type="number" value="10" step="0.25" min="0.25" oninput="updatePreview()"></div>
      <div class="field"><label class="lbl">Sell pts (below)</label><input id="ptsSell" type="number" value="10" step="0.25" min="0.25" oninput="updatePreview()"></div>
      <div class="field"><label class="lbl">Contracts</label><input id="qty" type="number" value="1" min="1" step="1"></div></div>
    <div class="preview">
      <div class="pv-cell"><div class="pv-lbl">Stop Buy</div><div class="pv-val pv-buy" id="pvBuy">Live + 10.00</div></div>
      <div class="pv-cell"><div class="pv-lbl">Live Price</div><div class="pv-val pv-mid" id="pvMid">Live</div></div>
      <div class="pv-cell"><div class="pv-lbl">Stop Sell</div><div class="pv-val pv-sell" id="pvSell">Live &minus; 10.00</div></div></div>
    <button class="btn btn-place" onclick="placeNow()">Place Stop Buy + Stop Sell now</button>
  </div>
  <div class="sched-card">
    <div class="card-head"><span class="step-num">3</span><span class="card-title">Auto-fire scheduler</span></div>
    <div class="clock-area"><div class="clock-time" id="clock">--:--:--</div><div class="clock-sub">Eastern Time</div></div>
    <div class="countdown-bar" id="cdBar" style="display:none"><span class="cd-label">Fires in</span><span class="cd-val" id="cdVal">--:--:--</span></div>
    <button class="arm-btn arm-off" id="armBtn" onclick="toggleArm()">Disarmed &mdash; click to arm</button>
    <div class="arm-desc" id="armDesc">Fires at 9:29:57 AM ET at the live price. Keep this page open.</div>
    <button class="btn btn-ghost" onclick="testFire()" style="margin-top:12px;width:100%">Test fire now</button>
    <div class="arm-desc">Runs the 9:29 routine now on the selected account. Test on a practice account first.</div>
  </div>
  <div class="card">
    <div class="card-head"><span class="card-title">Activity log</span><button class="card-action" onclick="clearLog()">Clear</button></div>
    <div class="log-box" id="logBox"><div class="le dim">No activity yet.</div></div>
  </div>
  <div class="footer">Connect a practice account on TopstepX to test safely before trading funded.</div>
</div>
<script>
let armed=false,lastLog=0;
async function api(path,data){try{const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data||{})});if(r.status===401){location.href='/';return{};}return await r.json();}catch(e){return{ok:false,error:'Could not reach the app. Make sure it is still running, then reload this page.'};}}
function onConnected(d){document.getElementById('connChip').className='chip chip-on';document.getElementById('connChip').textContent='Connected';
  document.getElementById('loginSt').innerHTML=`<span class="ok">${d.accounts.length} account(s) loaded</span>`;
  document.getElementById('acctSel').innerHTML=d.accounts.map(a=>`<option value="${a.id}">${a.name} (#${a.id})</option>`).join('');}
async function connect(){const s=document.getElementById('loginSt');s.innerHTML='<span class="wrn">Connecting…</span>';
  const key=document.getElementById('pass').value.trim();
  if(!key){s.innerHTML='<span class="err">Enter your API key.</span>';return;}
  const d=await api('/connect',{user:document.getElementById('user').value,pass:key});
  if(d.ok){onConnected(d);}
  else{s.innerHTML=`<span class="err">${d.error}</span>`;}}
async function lookup(){const s=document.getElementById('symSt');s.innerHTML='<span class="wrn">Looking up…</span>';
  const d=await api('/lookup',{sym:document.getElementById('sym').value});
  if(d.ok){s.innerHTML=`<span class="ok">${d.name} &mdash; ${d.fullName}</span>`;const c=document.getElementById('symChip');c.textContent=d.name;c.style.display='';}
  else{s.innerHTML=`<span class="err">${d.error}</span>`;}}
function updatePreview(){const pb=parseFloat(document.getElementById('ptsBuy').value),ps=parseFloat(document.getElementById('ptsSell').value);
  document.getElementById('pvMid').innerHTML='Live';
  document.getElementById('pvBuy').innerHTML=isNaN(pb)?'&mdash;':('Live + '+pb.toFixed(2));
  document.getElementById('pvSell').innerHTML=isNaN(ps)?'&mdash;':('Live &minus; '+ps.toFixed(2));}
function orderArgs(){return{buy_pts:document.getElementById('ptsBuy').value,sell_pts:document.getElementById('ptsSell').value,qty:document.getElementById('qty').value,acct:document.getElementById('acctSel').value};}
async function placeNow(){if(!confirm('Place a Stop Buy and Stop Sell at the live price now?'))return;const d=await api('/place',orderArgs());if(d&&d.ok===false&&d.error){alert(d.error);}}
async function testFire(){if(!confirm('Run a test fire now? This places real stop orders at the live price on the selected account. Use a practice account.'))return;await api('/test_fire',orderArgs());}
async function toggleArm(){const d=await api('/arm',orderArgs());applyArmUI(d.armed);}
function applyArmUI(on){armed=on;const btn=document.getElementById('armBtn'),desc=document.getElementById('armDesc'),cdBar=document.getElementById('cdBar');
  if(on){btn.textContent='Armed — will fire at 9:29:57 AM ET';btn.className='arm-btn arm-on';
    desc.textContent='Armed — fires at 9:29:57 AM ET. Keep this page open.';desc.className='arm-desc active';cdBar.style.display='flex';}
  else{btn.textContent='Disarmed — click to arm';btn.className='arm-btn arm-off';
    desc.textContent='Fires at 9:29:57 AM ET at the live price. Keep this page open.';desc.className='arm-desc';cdBar.style.display='none';}}
function clearLog(){document.getElementById('logBox').innerHTML='<div class="le dim">Log cleared.</div>';lastLog=0;}
async function poll(){try{const r=await fetch('/status');if(r.status===401){location.href='/';return;}const d=await r.json();
  document.getElementById('clock').textContent=d.et_time;
  if(d.armed&&d.countdown){const v=document.getElementById('cdVal');v.textContent=d.countdown;v.className='cd-val'+(d.soon?' soon':'');}
  if(d.armed!==armed)applyArmUI(d.armed);
  if(d.log.length!==lastLog){lastLog=d.log.length;const box=document.getElementById('logBox');
    box.innerHTML=d.log.slice(-80).reverse().map(l=>{let c='';if(l.includes('✅'))c='ok';else if(l.includes('❌'))c='err';else if(l.includes('⏰')||l.includes('⚡'))c='inf';else if(l.includes('⚠'))c='wrn';
      return`<div class="le ${c}">${l.replace(/[✅❌⏰⚡⚠️]/g,'').trim()}</div>`;}).join('')||'<div class="le dim">No activity yet.</div>';}
  }catch(e){}setTimeout(poll,500);}
poll();
</script></body></html>"""

ADMIN_HTML = r"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — Gunna's Strat</title><style>__STYLE__</style></head><body>
<div class="topbar">
  <div class="brand"><div class="brand-icon">G</div><span class="brand-name">Gunna's Strat<span class="brand-ver">Admin</span></span></div>
  <div class="top-right"><a class="toplink" href="/">&larr; Back to app</a><a class="toplink" href="/logout">Log out</a></div>
</div>
<div class="main" style="max-width:720px">
  <div class="card">
    <div class="card-head"><span class="card-title">Create a user</span></div>
    <div class="row2">
      <div class="field"><label class="lbl">Username</label><input id="nu" type="text" placeholder="new username"></div>
      <div class="field"><label class="lbl">Password</label><input id="np" type="text" placeholder="set a password"></div>
    </div>
    <button class="btn btn-primary" onclick="createUser()">Create user</button>
    <div id="cst" class="st"></div>
  </div>
  <div class="card">
    <div class="card-head"><span class="card-title">Users</span><button class="card-action" onclick="loadUsers()">Refresh</button></div>
    <table class="tbl"><thead><tr><th>User</th><th>Status</th><th>Created</th><th style="text-align:right">Actions</th></tr></thead>
      <tbody id="ubody"></tbody></table>
  </div>
  <div class="footer">Toggle a user inactive to instantly block their access (e.g. when their subscription lapses).</div>
</div>
<script>
async function api(path,data){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data||{})});return r.json();}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
async function loadUsers(){const r=await fetch('/admin/users');if(r.status===403){location.href='/';return;}const d=await r.json();
  document.getElementById('ubody').innerHTML=d.users.map(u=>{
    const created=(u.created||'').slice(0,10);
    const badge=u.active?'<span class="badge badge-on">Active</span>':'<span class="badge badge-off">Inactive</span>';
    const role=u.is_admin?' <span class="chip chip-blue">admin</span>':'';
    const toggle=u.active?`<button class="btn btn-danger mini" onclick="setActive('${esc(u.username)}',false)">Deactivate</button>`
                         :`<button class="btn btn-ghost mini" onclick="setActive('${esc(u.username)}',true)">Activate</button>`;
    const pw=`<button class="btn btn-ghost mini" onclick="resetPw('${esc(u.username)}')">Reset PW</button>`;
    const del=u.is_admin?'':`<button class="btn btn-danger mini" onclick="delUser('${esc(u.username)}')">Delete</button>`;
    return `<tr><td><b>${esc(u.username)}</b>${role}</td><td>${badge}</td><td style="color:var(--muted)">${created}</td>
      <td style="text-align:right;white-space:nowrap">${toggle} ${pw} ${del}</td></tr>`;}).join('');}
async function createUser(){const st=document.getElementById('cst');
  const u=document.getElementById('nu').value.trim(),p=document.getElementById('np').value;
  if(!u||!p){st.innerHTML='<span class="err">Username and password required</span>';return;}
  const d=await api('/admin/create',{username:u,password:p});
  if(d.ok){st.innerHTML='<span class="ok">User created</span>';document.getElementById('nu').value='';document.getElementById('np').value='';loadUsers();}
  else{st.innerHTML=`<span class="err">${d.error}</span>`;}}
async function setActive(u,a){await api('/admin/active',{username:u,active:a});loadUsers();}
async function resetPw(u){const p=prompt('New password for '+u+':');if(!p)return;const d=await api('/admin/password',{username:u,password:p});if(d.ok)alert('Password updated.');else alert(d.error);}
async function delUser(u){if(!confirm('Delete user '+u+'? This cannot be undone.'))return;await api('/admin/delete',{username:u});loadUsers();}
loadUsers();
</script></body></html>"""

def render(html, **kw):
    out = html.replace("__STYLE__", STYLE).replace("__VER__", VERSION)
    for k, v in kw.items():
        out = out.replace(f"__{k}__", v)
    return out

# ─────────────────────────────────────────────────────────────────────────────
#  HTTP handler
# ─────────────────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    # ---- low-level helpers ----
    def _json(self, data, code=200, extra_headers=None):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html, code=200, extra_headers=None):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location, extra_headers=None):
        self.send_response(302)
        self.send_header("Location", location)
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n)) if n else {}

    def _sid(self):
        c = self.headers.get("Cookie")
        if not c:
            return None
        ck = SimpleCookie(c)
        return ck["sid"].value if "sid" in ck else None

    def _session(self):
        sid = self._sid()
        if not sid:
            return None
        with LOCK:
            sess = SESSIONS.get(sid)
        if sess:
            now = time.time()
            sess["last_seen"] = now
            # The owner may deactivate/delete this account on the central
            # server mid-session. Re-check periodically (throttled) so we
            # don't hammer the server on every request. Fails open on a
            # network blip via license_active().
            if now - sess.get("last_check", 0) >= LICENSE_RECHECK:
                sess["last_check"] = now
                if not license_active(sess["user"]):
                    with LOCK:
                        SESSIONS.pop(sid, None)
                    return None
        return sess

    # ---- GET ----
    def do_GET(self):
        path = self.path.split("?")[0]
        sess = self._session()

        if path == "/":
            if sess:
                admin_link = ('<a class="toplink" href="/admin">Admin</a>'
                              if sess["is_admin"] else "")
                self._html(render(APP_HTML, USERNAME=sess["user"], ADMIN_LINK=admin_link))
            else:
                self._html(render(LOGIN_HTML))
            return

        if path == "/logout":
            sid = self._sid()
            if sid:
                with LOCK:
                    SESSIONS.pop(sid, None)
            self._redirect("/", [("Set-Cookie", "sid=; Path=/; Max-Age=0")])
            return

        if path == "/admin":
            if sess and sess["is_admin"]:
                self._html(render(ADMIN_HTML))
            else:
                self._redirect("/")
            return

        if path == "/admin/users":
            if not (sess and sess["is_admin"]):
                self._json({"error": "forbidden"}, 403); return
            users = load_users()
            out = [{"username": k, "active": v.get("active", False),
                    "is_admin": v.get("is_admin", False), "created": v.get("created", "")}
                   for k, v in sorted(users.items())]
            self._json({"users": out}); return

        if path == "/status":
            if not sess:
                self._json({"error": "unauthorized"}, 401); return
            now = datetime.now(ET)
            target = now.replace(hour=9, minute=29, second=57, microsecond=0)
            if now >= target:
                target += timedelta(days=1)
            diff = int((target - now).total_seconds())
            h, r = divmod(diff, 3600); m, s = divmod(r, 60)
            self._json({
                "et_time": now.strftime("%H:%M:%S"),
                "countdown": f"{h:02d}:{m:02d}:{s:02d}",
                "soon": diff <= 10 and sess["armed"],
                "armed": sess["armed"],
                "log": sess["log"],
            }); return

        self._json({"error": "not found"}, 404)

    # ---- POST ----
    def do_POST(self):
        path = self.path.split("?")[0]
        try:
            d = self._body()
        except Exception:
            self._json({"ok": False, "error": "bad request"}, 400); return

        # ---- public: site login (validated against the central license server) ----
        if path == "/auth/login":
            uname = str(d.get("user", "")).strip()
            pw = str(d.get("pass", ""))
            if not uname or not pw:
                self._json({"ok": False, "error": "Username and password required"}); return
            ok, info = validate_license(uname, pw)
            if not ok:
                self._json({"ok": False, "error": info}); return
            sid = secrets.token_urlsafe(32)
            with LOCK:
                # This downloadable app is a pure trading client; all account
                # management happens on the central server, so no local admin.
                SESSIONS[sid] = new_session(uname, False)
            self._json({"ok": True},
                       extra_headers=[("Set-Cookie", f"sid={sid}; HttpOnly; SameSite=Lax; Path=/")])
            return

        # ---- everything below requires a session ----
        sess = self._session()
        if not sess:
            self._json({"ok": False, "error": "unauthorized"}, 401); return

        # ---- admin endpoints ----
        if path.startswith("/admin/"):
            if not sess["is_admin"]:
                self._json({"ok": False, "error": "forbidden"}, 403); return
            return self._admin(path, d)

        # ---- per-user app endpoints ----
        if path == "/connect":
            user = d.get("user", "").strip()
            pw = d.get("pass", "").strip()
            ok, res = ts_auth(user, pw)
            if not ok:
                self._json({"ok": False, "error": res}); return
            sess["ts_token"] = res
            sess["ts_token_time"] = time.time()
            try:
                sess["accounts"] = ts_accounts(res)
            except Exception as e:
                self._json({"ok": False, "error": f"Login OK but account load failed: {e}"}); return
            log_s(sess, f"Connected to TopstepX — {len(sess['accounts'])} account(s)")
            self._json({"ok": True, "accounts": sess["accounts"]}); return

        if path == "/lookup":
            if not ensure_token(sess):
                self._json({"ok": False, "error": "Connect to TopstepX first"}); return
            c = ts_find_contract(sess["ts_token"], str(d.get("sym", "")).strip().upper())
            if isinstance(c, dict) and c.get("id"):
                sess["contract"] = c
                log_s(sess, f"Contract: {c.get('name')} — {c.get('description','')} (id={c['id']})")
                self._json({"ok": True, "name": c.get("name"),
                            "fullName": c.get("description", "")})
            else:
                self._json({"ok": False, "error": "No matching contract found"})
            return

        if path == "/place":
            if not ensure_token(sess):
                log_s(sess, "⚠ Connect to TopstepX first")
                self._json({"ok": False, "error": "Connect to TopstepX first"}); return
            if not sess["contract"]:
                log_s(sess, "⚠ Look up a symbol first")
                self._json({"ok": False, "error": "Look up a symbol first (type a symbol and press Look up)."}); return
            sess["selected_account"] = str(d.get("acct", ""))
            acct = selected_account(sess)
            if not acct:
                log_s(sess, "⚠ No account selected")
                self._json({"ok": False, "error": "No account selected"}); return
            try:
                buy_pts = float(d["buy_pts"]); sell_pts = float(d["sell_pts"]); qty = int(d["qty"])
            except Exception:
                log_s(sess, "⚠ Invalid pts/qty")
                self._json({"ok": False, "error": "Enter valid buy/sell points and quantity"}); return
            cid = sess["contract"]["id"]
            token = sess["ts_token"]
            def do_place():
                try:
                    price = ts_quote_live(token, cid)
                    if price is None:
                        log_s(sess, "❌ No live quote (market closed or no data subscription)"); return
                    sess["price"] = str(price)
                    buy_px, sell_px = round(price+buy_pts, 4), round(price-sell_pts, 4)
                    log_s(sess, f"⚡ Live {price} → Stop Buy @ {buy_px}  +  Stop Sell @ {sell_px}  qty={qty}…")
                    r1 = ts_place_stop(token, acct["id"], cid, SIDE_BUY,  buy_px,  qty)
                    log_s(sess, f"Buy  → {r1}")
                    r2 = ts_place_stop(token, acct["id"], cid, SIDE_SELL, sell_px, qty)
                    log_s(sess, f"Sell → {r2}")
                    log_s(sess, "✅ Both orders submitted")
                    buy_id, sell_id = _order_id(r1), _order_id(r2)
                    threading.Thread(target=oco_monitor,
                                     args=(sess, token, acct["id"], buy_id, sell_id),
                                     daemon=True).start()
                except Exception as e:
                    log_s(sess, f"❌ Order error: {e}")
            threading.Thread(target=do_place, daemon=True).start()
            self._json({"ok": True}); return

        if path == "/test_fire":
            if not ensure_token(sess) or not sess["contract"]:
                log_s(sess, "⚠ Connect and look up a symbol first")
                self._json({"ok": False, "error": "Connect and look up a symbol first"}); return
            sess["selected_account"] = str(d.get("acct", ""))
            try:
                sess["buy_pts"] = float(d.get("buy_pts", 10))
                sess["sell_pts"] = float(d.get("sell_pts", 10))
                sess["qty"] = int(d.get("qty", 1))
            except Exception:
                self._json({"ok": False, "error": "Invalid pts/qty"}); return
            threading.Thread(target=fire_for, args=(sess,),
                             kwargs={"manual": True}, daemon=True).start()
            self._json({"ok": True}); return

        if path == "/arm":
            try:
                sess["buy_pts"] = float(d.get("buy_pts", 10)); sess["sell_pts"] = float(d.get("sell_pts", 10)); sess["qty"] = int(d.get("qty", 1))
            except Exception:
                self._json({"ok": False, "error": "Invalid pts/qty"}); return
            sess["selected_account"] = str(d.get("acct", ""))
            sess["armed"] = not sess["armed"]
            if sess["armed"]:
                sess["fired_date"] = None
                log_s(sess, f"Scheduler ARMED — buy +{sess['buy_pts']} / sell -{sess['sell_pts']} qty={sess['qty']} → fires 9:29:57 AM ET")
            else:
                log_s(sess, "Scheduler disarmed")
            self._json({"armed": sess["armed"]}); return

        self._json({"ok": False, "error": "not found"}, 404)

    # ---- admin actions ----
    def _admin(self, path, d):
        users = load_users()
        if path == "/admin/create":
            uname = str(d.get("username", "")).strip()
            pw = str(d.get("password", ""))
            if not uname or not pw:
                self._json({"ok": False, "error": "Username and password required"}); return
            if uname in users:
                self._json({"ok": False, "error": "That username already exists"}); return
            salt, h = _hash_pw(pw)
            users[uname] = {"salt": salt, "hash": h, "active": True,
                            "is_admin": False, "created": datetime.now().isoformat()}
            save_users(users)
            self._json({"ok": True}); return

        if path == "/admin/active":
            uname = str(d.get("username", "")).strip()
            if uname not in users:
                self._json({"ok": False, "error": "No such user"}); return
            users[uname]["active"] = bool(d.get("active"))
            save_users(users)
            # If deactivated, kill their live sessions immediately.
            if not users[uname]["active"]:
                with LOCK:
                    for sid in [k for k, s in SESSIONS.items() if s["user"] == uname]:
                        SESSIONS.pop(sid, None)
            self._json({"ok": True}); return

        if path == "/admin/password":
            uname = str(d.get("username", "")).strip()
            pw = str(d.get("password", ""))
            if uname not in users or not pw:
                self._json({"ok": False, "error": "Bad request"}); return
            salt, h = _hash_pw(pw)
            users[uname]["salt"] = salt; users[uname]["hash"] = h
            save_users(users)
            self._json({"ok": True}); return

        if path == "/admin/delete":
            uname = str(d.get("username", "")).strip()
            if uname in users and not users[uname].get("is_admin"):
                users.pop(uname)
                save_users(users)
                with LOCK:
                    for sid in [k for k, s in SESSIONS.items() if s["user"] == uname]:
                        SESSIONS.pop(sid, None)
            self._json({"ok": True}); return

        self._json({"ok": False, "error": "not found"}, 404)

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Free the port if a previous run is still holding it.
    try:
        r = subprocess.run(["lsof", "-ti", f":{PORT}"], capture_output=True, text=True)
        for pid in r.stdout.strip().split("\n"):
            pid = pid.strip()
            if pid and pid != str(os.getpid()):
                try: os.kill(int(pid), signal.SIGKILL)
                except Exception: pass
    except Exception:
        pass
    time.sleep(0.3)

    print(f"Login is validated against the license server: {LICENSE_SERVER}")
    threading.Thread(target=scheduler_loop, daemon=True).start()
    threading.Thread(target=reaper_loop, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Gunna's Strat v{VERSION}  →  http://127.0.0.1:{PORT}")
    threading.Timer(1.2, lambda: webbrowser.open(f"http://127.0.0.1:{PORT}")).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
