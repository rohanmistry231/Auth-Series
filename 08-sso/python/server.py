"""SSO Server — central authentication service.

Endpoints:
  GET  /sso/login            → Login form (redirect with ?redirect=)
  POST /sso/login            → Authenticate, set SSO cookie, redirect with token
  GET  /sso/validate?token=  → Validate SSO token, return user info
  GET  /sso/logout           → Clear SSO cookie
"""

import os
import time
import uuid
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI(title="SSO Server")

SSO_SECRET = os.environ.get("SSO_SECRET", "sso-secret-change-me")
SSO_DOMAIN = "http://localhost:8000"
TOKEN_TTL = 60

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

USERS = {
    "alice": os.environ.get("ALICE_PASSWORD", "password-alice"),
    "bob": os.environ.get("BOB_PASSWORD", "password-bob"),
}

sso_sessions: dict[str, dict] = {}


def make_sso_token(username: str) -> str:
    now = int(time.time())
    payload = {
        "iss": SSO_DOMAIN,
        "sub": username,
        "iat": now,
        "exp": now + TOKEN_TTL,
        "jti": str(uuid.uuid4()),
        "type": "sso",
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


@app.get("/sso/login")
def login_form(redirect: str = Query(...)):
    return HTMLResponse(f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:400px;margin:40px auto">
<h2>SSO Login</h2>
<p>Sign in to access <code>{redirect}</code></p>
<form method="post" action="/sso/login">
<input type="hidden" name="redirect" value="{redirect}">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">Sign In</button></p>
</form></body></html>""")


@app.post("/sso/login")
def login_post(redirect: str = Form(...), username: str = Form(...), password: str = Form(...)):
    expected = USERS.get(username)
    if not expected or expected != password:
        return HTMLResponse("Invalid credentials", status_code=401)

    token = make_sso_token(username)
    sso_sessions[token] = {"username": username, "created": time.time()}

    resp = RedirectResponse(url=f"{redirect}?token={token}")
    resp.set_cookie(key="sso_session", value=token, httponly=True, max_age=86400, path="/")
    return resp


@app.get("/sso/validate")
def validate_token(token: str = Query(...)):
    try:
        payload = jwt.decode(token, public_key, algorithms=["RS256"], issuer=SSO_DOMAIN)
        if payload.get("type") != "sso":
            raise HTTPException(status_code=400, detail="Invalid token type")
        return {"sub": payload["sub"], "valid": True}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@app.get("/sso/check")
def check_sso(request: Request):
    """Check if user already has an SSO session (cookie-based re-auth)."""
    token = request.cookies.get("sso_session")
    if not token:
        raise HTTPException(status_code=401, detail="No SSO session")

    try:
        payload = jwt.decode(token, public_key, algorithms=["RS256"], issuer=SSO_DOMAIN)
        return {"sub": payload["sub"], "valid": True}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid SSO session")


@app.get("/sso/logout")
def logout():
    resp = HTMLResponse("Logged out of SSO")
    resp.set_cookie(key="sso_session", value="", httponly=True, max_age=0, path="/")
    return resp


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
