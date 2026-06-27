"""Bearer Token Auth Server.

Endpoints:
  POST /login        → issue bearer token
  GET  /protected    → validate Bearer auth header
  POST /introspect   → token introspection (RFC 7662)
  POST /revoke       → token revocation (RFC 7009)
"""

import hashlib
import os
import secrets
import time
import uuid

import uvicorn
from fastapi import FastAPI, Form, Header, HTTPException
from fastapi.responses import HTMLResponse

app = FastAPI(title="Bearer Token Server")

TOKEN_TTL = int(os.environ.get("TOKEN_TTL", "3600"))

USERS = {
    "alice": {"password": os.environ.get("ALICE_PASSWORD", "password-alice"), "scopes": ["read", "write"]},
    "bob": {"password": os.environ.get("BOB_PASSWORD", "password-bob"), "scopes": ["read"]},
}

tokens: dict[str, dict] = {}  # hash -> token record


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    return secrets.token_urlsafe(48)


@app.get("/")
def index():
    return HTMLResponse("""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Bearer Token Auth</h2>

<h3>1. Login</h3>
<form method="post" action="/login">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">Get Token</button></p>
</form>

<h3>2. Try Protected Endpoint</h3>
<form method="get" action="/protected">
<p><label>Token: <input name="token" size="50"></label></p>
<p><button type="submit">GET /protected</button></p>
</form>

<h3>3. Introspect</h3>
<form method="post" action="/introspect">
<p><label>Token: <input name="token" size="50"></label></p>
<p><button type="submit">Introspect</button></p>
</form>

<h3>4. Revoke</h3>
<form method="post" action="/revoke">
<p><label>Token: <input name="token" size="50"></label></p>
<p><button type="submit">Revoke</button></p>
</form>
</body></html>""")  # noqa: E501


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = USERS.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = generate_token()
    th = hash_token(token)
    now = int(time.time())
    tokens[th] = {
        "token_hash": th,
        "sub": username,
        "scopes": user["scopes"],
        "iat": now,
        "exp": now + TOKEN_TTL,
        "revoked": False,
    }

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
        "scope": " ".join(user["scopes"]),
    }


def extract_token(authorization: str = Header(None)) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth scheme, must be Bearer")
    return authorization[7:]


def validate_token(token_str: str) -> dict:
    th = hash_token(token_str)
    record = tokens.get(th)
    if not record:
        raise HTTPException(status_code=401, detail="Token not found")
    if record["revoked"]:
        raise HTTPException(status_code=401, detail="Token revoked")
    if int(time.time()) > record["exp"]:
        raise HTTPException(status_code=401, detail="Token expired")
    return record


@app.get("/protected")
def protected(token: str = None):
    if token:
        record = validate_token(token)
    else:
        # Try Authorization header
        authorization = Header(None)
        token_str = extract_token(authorization)
        record = validate_token(token_str)

    return {
        "message": f"Authenticated as {record['sub']}",
        "scopes": record["scopes"],
        "exp": record["exp"],
    }


@app.post("/introspect")
def introspect(token: str = Form(...)):
    th = hash_token(token)
    record = tokens.get(th)
    if not record:
        return {"active": False}
    if record["revoked"] or int(time.time()) > record["exp"]:
        return {"active": False}
    return {
        "active": True,
        "sub": record["sub"],
        "scope": " ".join(record["scopes"]),
        "token_type": "Bearer",
        "exp": record["exp"],
        "iat": record["iat"],
    }


@app.post("/revoke")
def revoke(token: str = Form(...)):
    th = hash_token(token)
    record = tokens.get(th)
    if record:
        record["revoked"] = True
    return {"result": "ok"}


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
