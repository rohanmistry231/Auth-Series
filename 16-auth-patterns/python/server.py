"""Auth Patterns — BFF, Token Rotation, Gateway Middleware.

Demonstrates three key architectural patterns.
"""

import hashlib
import os
import secrets
import time
import uuid

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="Auth Patterns Demo")

# In-memory stores
users = {"alice": os.environ.get("ALICE_PASSWORD", "password-alice")}
refresh_tokens: dict[str, dict] = {}
bff_sessions: dict[str, dict] = {}
token_families: dict[str, str] = {}  # token_hash -> family_id


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ====================================================================
# Pattern 1: BFF (Backend for Frontend)
# ====================================================================

@app.get("/")
def index():
    return HTMLResponse("""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:700px;margin:40px auto">
<h2>Auth Patterns Demo</h2>
<ul>
  <li><a href="/bff/login">BFF Pattern</a> — login via server-side session</li>
  <li><a href="/token-rotation">Token Rotation</a> — refresh with theft detection</li>
  <li><a href="/gateway">Gateway Auth</a> — centralized token validation</li>
</ul>
</body></html>""")


@app.get("/bff/login")
def bff_login_form():
    return HTMLResponse("""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>BFF Login</h2>
<form method="post" action="/bff/login">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">Login</button></p>
</form>
</body></html>""")


@app.post("/bff/login")
def bff_login(username: str = Form(...), password: str = Form(...)):
    if users.get(username) != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    session_id = str(uuid.uuid4())
    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(48)

    bff_sessions[session_id] = {
        "username": username,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "created_at": time.time(),
    }

    resp = JSONResponse({"message": f"Logged in as {username}", "access_token": access_token})
    resp.set_cookie(key="session_id", value=session_id, httponly=True, samesite="lax")
    return resp


@app.get("/bff/api/data")
def bff_api_data(request: Request):
    session_id = request.cookies.get("session_id")
    session = bff_sessions.get(session_id) if session_id else None
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated (BFF session)")

    return {
        "message": f"Protected data for {session['username']}",
        "data": {"secret": "42", "via": "BFF proxy"},
    }


# ====================================================================
# Pattern 2: Token Rotation
# ====================================================================

@app.post("/token/issue")
def issue_tokens(username: str = Form(...), password: str = Form(...)):
    if users.get(username) != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(48)
    rth = hash_token(refresh_token)
    family_id = str(uuid.uuid4())

    refresh_tokens[rth] = {
        "username": username,
        "family": family_id,
        "exp": time.time() + 604800,
        "revoked": False,
    }
    token_families[rth] = family_id

    return {"access_token": access_token, "refresh_token": refresh_token, "expires_in": 900}


@app.post("/token/refresh")
def refresh_tokens(refresh_token: str = Form(...)):
    rth = hash_token(refresh_token)
    record = refresh_tokens.get(rth)

    if not record:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if record["revoked"]:
        # Token reuse — theft detected. Revoke ALL tokens in this family
        family = record["family"]
        for th, rec in list(refresh_tokens.items()):
            if rec["family"] == family:
                rec["revoked"] = True
        raise HTTPException(status_code=401, detail="Token reuse detected — all tokens revoked")

    if record["exp"] < time.time():
        raise HTTPException(status_code=401, detail="Refresh token expired")

    record["revoked"] = True

    new_access = secrets.token_urlsafe(32)
    new_refresh = secrets.token_urlsafe(48)
    nrth = hash_token(new_refresh)
    refresh_tokens[nrth] = {
        "username": record["username"],
        "family": record["family"],
        "exp": time.time() + 604800,
        "revoked": False,
    }
    token_families[nrth] = record["family"]

    return {"access_token": new_access, "refresh_token": new_refresh, "expires_in": 900}


@app.get("/token-rotation")
def token_rotation_docs():
    return HTMLResponse("""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Token Rotation Demo</h2>
<p>Use the client to test: <code>python client.py</code></p>
<p><code>POST /token/issue</code> — issue tokens</p>
<p><code>POST /token/refresh</code> — rotate + detect theft</p>
</body></html>""")


# ====================================================================
# Pattern 3: API Gateway Auth Middleware
# ====================================================================

gateway_tokens: dict[str, dict] = {}


@app.post("/gateway/token")
def gateway_issue_token(username: str = Form(...), password: str = Form(...)):
    if users.get(username) != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = secrets.token_urlsafe(32)
    gateway_tokens[token] = {"username": username, "scopes": ["read", "write"]}
    return {"access_token": token, "token_type": "Bearer"}


@app.get("/gateway/validate")
def gateway_validate(authorization: str = ""):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    token = authorization[7:]
    record = gateway_tokens.get(token)
    if not record:
        raise HTTPException(status_code=401, detail="Invalid token")

    return {"active": True, "sub": record["username"], "scopes": record["scopes"]}


@app.get("/gateway/api/resource")
def gateway_resource(authorization: str = ""):
    # Simulates API gateway check
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization[7:]
    record = gateway_tokens.get(token)
    if not record:
        raise HTTPException(status_code=401, detail="Invalid token")

    return {"message": f"Resource accessed by {record['username']}", "via": "Gateway"}


@app.get("/gateway")
def gateway_docs():
    return HTMLResponse("""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Gateway Auth Demo</h2>
<p><code>POST /gateway/token</code> — get a gateway token</p>
<p><code>GET /gateway/validate</code> — validate token (gateway check)</p>
<p><code>GET /gateway/api/resource</code> — protected resource</p>
</body></html>""")


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
