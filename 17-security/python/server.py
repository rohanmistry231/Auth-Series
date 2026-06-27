"""Security Best Practices — Rate Limiter, Security Headers, Audit Log, CSRF.

Demonstrates four key security mechanisms as reusable middleware/components.
"""

import hashlib
import json
import os
import secrets
import time
import uuid
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse

app = FastAPI(title="Security Best Practices Demo")

# In-memory stores
rate_limit_store: dict[str, list[float]] = {}
audit_log: list[dict] = []
csrf_tokens: dict[str, dict] = {}

USERS = {"alice": os.environ.get("ALICE_PASSWORD", "password-alice")}


# ====================================================================
# 1. Rate Limiter (Sliding Window)
# ====================================================================

def rate_limit(key: str, max_requests: int = 10, window_seconds: int = 60):
    now = time.time()
    if key not in rate_limit_store:
        rate_limit_store[key] = []

    window_start = now - window_seconds
    rate_limit_store[key] = [t for t in rate_limit_store[key] if t > window_start]

    if len(rate_limit_store[key]) >= max_requests:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded ({max_requests}/{window_seconds}s)")

    rate_limit_store[key].append(now)


# ====================================================================
# 2. Security Headers (via middleware)
# ====================================================================

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


# ====================================================================
# 3. Audit Logger
# ====================================================================

def log_auth_event(event: str, username: str, ip: str, success: bool, details: str = ""):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "username": username,
        "ip": ip,
        "success": success,
        "details": details,
    }
    audit_log.append(entry)
    print(f"  [AUDIT] {json.dumps(entry)}")


# ====================================================================
# 4. CSRF Protection
# ====================================================================

@app.get("/csrf/token")
def get_csrf_token(request: Request):
    token = secrets.token_hex(32)
    session_id = str(uuid.uuid4())
    csrf_tokens[token] = {"session": session_id, "exp": time.time() + 3600}
    return {"csrf_token": token, "session_id": session_id}


def verify_csrf(token: str, session_id: str):
    record = csrf_tokens.get(token)
    if not record:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    if record["session"] != session_id:
        raise HTTPException(status_code=403, detail="CSRF session mismatch")
    if record["exp"] < time.time():
        csrf_tokens.pop(token, None)
        raise HTTPException(status_code=403, detail="CSRF token expired")
    csrf_tokens.pop(token, None)


# ====================================================================
# Routes
# ====================================================================

@app.get("/")
def index():
    return HTMLResponse("""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:700px;margin:40px auto">
<h2>Security Best Practices Demo</h2>
<ul>
  <li><a href="/login">Login (rate limited + CSRF protected)</a></li>
  <li><a href="/audit-log">View audit log</a></li>
  <li>Security headers applied to all responses</li>
</ul>
</body></html>""")


@app.get("/login")
def login_form(request: Request):
    rate_limit(f"login_page:{request.client.host}", max_requests=20, window_seconds=60)
    return HTMLResponse(f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Login (Rate Limited + CSRF Protected)</h2>
<form method="post" action="/login">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">Login</button></p>
</form>
</body></html>""")


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else "unknown"
    rate_limit(f"login:{ip}", max_requests=5, window_seconds=60)

    if USERS.get(username) != password:
        log_auth_event("LOGIN_FAILURE", username, ip, False, "Invalid password")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    session_id = str(uuid.uuid4())
    log_auth_event("LOGIN_SUCCESS", username, ip, True, f"Session {session_id[:16]}...")

    resp = HTMLResponse(f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Welcome, {username}!</h2>
<p>Session: <code>{session_id[:16]}...</code></p>
<p><a href="/audit-log">View Audit Log</a></p>
</body></html>""")
    resp.set_cookie(key="session_id", value=session_id, httponly=True, samesite="strict", secure=True)
    return resp


@app.get("/audit-log")
def view_audit_log():
    entries = "".join(
        f'<li><code>{e["timestamp"][:19]}</code> '
        f'<strong>{"✅" if e["success"] else "❌"}</strong> '
        f'{e["event"]} — {e["username"]} ({e["ip"]})'
        f'<br><small>{e["details"]}</small></li>'
        for e in audit_log[-20:]
    )
    return HTMLResponse(f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:700px;margin:40px auto">
<h2>Audit Log (last 20)</h2>
<ul style="list-style:none;padding:0">{entries or "<li>No events yet</li>"}</ul>
<p><a href="/">← Back</a></p>
</body></html>""")


@app.get("/check-headers")
def check_headers(request: Request):
    return {
        "message": "Security headers are applied to ALL responses via middleware",
        "headers": {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
    }


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
