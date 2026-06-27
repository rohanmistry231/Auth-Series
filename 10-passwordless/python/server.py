"""Magic Link Passwordless Auth Server.

Endpoints:
  POST /auth/request   → Generate + log magic link
  GET  /auth/verify    → Consume token, create session
"""

import hashlib
import hmac
import os
import time
import uuid
from datetime import datetime

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Query
from fastapi.responses import HTMLResponse

app = FastAPI(title="Magic Link Server")

SECRET_KEY = os.environ.get("MAGIC_LINK_SECRET", "change-me-in-production")
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", "900"))  # 15 min

# In-memory stores
token_hashes: dict[str, dict] = {}       # hash -> metadata
used_tokens: set[str] = set()            # consumed token hashes
users: dict[str, str] = {                # email -> user_id
    "alice@example.com": str(uuid.uuid4()),
    "bob@example.com": str(uuid.uuid4()),
}


def sign_token(payload: str) -> str:
    """HMAC-SHA256 sign a payload."""
    return hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()


def verify_signature(payload: str, sig: str) -> bool:
    """Constant-time verify HMAC signature."""
    expected = sign_token(payload)
    return hmac.compare_digest(expected, sig)


def hash_token(token: str) -> str:
    """SHA-256 hash the full token for server-side storage."""
    return hashlib.sha256(token.encode()).hexdigest()


@app.get("/")
def index():
    return HTMLResponse("""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>Passwordless (Magic Link) Demo</h2>
<form method="post" action="/auth/request">
<p><label>Email: <input name="email" value="alice@example.com"></label></p>
<p><button type="submit">Send Magic Link</button></p>
</form>
</body></html>""")


@app.post("/auth/request")
def request_magic_link(email: str = Form(...)):
    if email not in users:
        raise HTTPException(status_code=404, detail="Unknown email")

    token_id = str(uuid.uuid4())
    exp = int(time.time()) + TOKEN_TTL
    payload = f"{email}:{token_id}:{exp}"
    sig = sign_token(payload)
    token = f"{payload}.{sig}"

    th = hash_token(token)
    token_hashes[th] = {
        "email": email,
        "exp": exp,
        "used": False,
        "created_at": datetime.utcnow().isoformat(),
    }

    magic_url = f"http://127.0.0.1:8000/auth/verify?token={token}"
    print(f"\n  [LOG] Magic link for {email}:")
    print(f"  [LOG]   {magic_url}\n")

    return {
        "message": f"Magic link sent to {email}",
        "magic_url": magic_url,
        "expires_in": TOKEN_TTL,
    }


@app.get("/auth/verify")
def verify_magic_link(token: str = Query(...)):
    parts = token.rsplit(".", 1)
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail="Invalid token format")

    payload, sig = parts
    if not verify_signature(payload, sig):
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        email, token_id, exp_str = payload.split(":", 2)
        exp = int(exp_str)
    except (ValueError, IndexError):
        raise HTTPException(status_code=400, detail="Malformed payload")

    if time.time() > exp:
        raise HTTPException(status_code=401, detail="Token expired")

    th = hash_token(token)
    if th in used_tokens:
        raise HTTPException(status_code=401, detail="Token already used")

    used_tokens.add(th)

    session_token = str(uuid.uuid4())
    return HTMLResponse(f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>Authenticated ✓</h2>
<p>Welcome, <strong>{email}</strong>!</p>
<p>Session: <code>{session_token[:16]}...</code></p>
</body></html>""")


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
