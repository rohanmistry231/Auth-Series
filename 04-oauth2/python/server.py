"""OAuth 2.0 Authorization Server.

Supports:
  - Authorization Code Grant (+ PKCE)
  - Client Credentials Grant
  - Device Code Grant
  - Token refresh
"""

import hashlib
import os
import secrets
import time
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode
from urllib.parse import parse_qs, urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

app = FastAPI(title="OAuth 2.0 Authorization Server Example")

ISSUER = "http://localhost:8000"
ACCESS_TTL = 3600
REFRESH_TTL = 86400 * 7
AUTH_CODE_TTL = 300

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

USERS = {
    "alice": os.environ.get("ALICE_PASSWORD", "password-alice"),
    "bob": os.environ.get("BOB_PASSWORD", "password-bob"),
}

CLIENTS = {
    "webapp": {
        "client_secret": os.environ.get("WEBAPP_SECRET", "webapp-secret"),
        "redirect_uris": ["http://localhost:8001/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
    },
    "spa": {
        "client_secret": None,
        "redirect_uris": ["http://localhost:3000/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
    },
    "service-a": {
        "client_secret": os.environ.get("SERVICE_A_SECRET", "service-a-secret"),
        "redirect_uris": [],
        "grant_types": ["client_credentials"],
    },
}

auth_codes: dict[str, dict] = {}
access_tokens: dict[str, dict] = {}
refresh_tokens: dict[str, dict] = {}
device_codes: dict[str, dict] = {}


def b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def random_token() -> str:
    return secrets.token_urlsafe(48)


def make_access_token(sub: str, scope: str, client_id: str) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": sub,
        "client_id": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + ACCESS_TTL,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


@app.get("/authorize")
def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(""),
    state: str = Query(""),
    code_challenge: str | None = Query(None),
    code_challenge_method: str | None = Query(None),
):
    client = CLIENTS.get(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    if redirect_uri not in client["redirect_uris"]:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    if response_type != "code":
        raise HTTPException(status_code=400, detail="response_type must be 'code'")

    if code_challenge and code_challenge_method not in ("S256", "plain"):
        raise HTTPException(status_code=400, detail="Invalid code_challenge_method")

    html = """<!DOCTYPE html>
<html><head><title>OAuth 2.0 — Authorize</title></head>
<body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>Authorize <code>{client_id}</code></h2>
<p>Scope: <code>{scope}</code></p>
<form method="post" action="/authorize/consent">
<input type="hidden" name="response_type" value="{response_type}">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="code_challenge" value="{code_challenge}">
<input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password" value="password-alice"></label></p>
<p><button type="submit" name="approve" value="yes">Approve</button>
<button type="submit" name="approve" value="no">Deny</button></p>
</form></body></html>""".format(
        client_id=client_id, scope=scope, response_type=response_type,
        redirect_uri=redirect_uri, state=state,
        code_challenge=code_challenge or "",
        code_challenge_method=code_challenge_method or "",
    )
    return HTMLResponse(html)


@app.post("/authorize/consent")
def consent_approve(request: Request):
    import asyncio
    body_bytes = asyncio.run(request.body())
    params = parse_qs(body_bytes.decode())

    def get(k: str) -> str:
        return params.get(k, [b""])[0].decode() if isinstance(params.get(k, [b""])[0], bytes) else params.get(k, [""])[0]

    approve = get("approve")
    if approve != "yes":
        raise HTTPException(status_code=403, detail="Consent denied")

    username = get("username")
    password = get("password")
    client_id = get("client_id")
    redirect_uri = get("redirect_uri")
    scope = get("scope")
    state = get("state")
    code_challenge = get("code_challenge")
    code_challenge_method = get("code_challenge_method")

    expected = USERS.get(username)
    if not expected or expected != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    code = random_token()
    auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "username": username,
        "expires": time.time() + AUTH_CODE_TTL,
        "code_challenge": code_challenge or None,
        "code_challenge_method": code_challenge_method or None,
    }

    params = {"code": code, "state": state}
    if state:
        params["state"] = state

    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}")


@app.post("/token")
def token(request: Request):
    import asyncio
    body_bytes = asyncio.run(request.body())
    params = parse_qs(body_bytes.decode())

    def get(k: str) -> str:
        vals = params.get(k, [b""])
        v = vals[0]
        return v.decode() if isinstance(v, bytes) else v

    grant_type = get("grant_type")

    if grant_type == "authorization_code":
        return handle_auth_code(params, get)
    elif grant_type == "client_credentials":
        return handle_client_creds(request, get)
    elif grant_type == "refresh_token":
        return handle_refresh(params, get)
    elif grant_type == "urn:ietf:params:oauth:grant-type:device_code":
        return handle_device_token(params, get)

    raise HTTPException(status_code=400, detail="Unsupported grant_type")


def handle_auth_code(params, get):
    code = get("code")
    client_id = get("client_id")
    client_secret = get("client_secret") or None
    redirect_uri = get("redirect_uri")
    code_verifier = get("code_verifier") or None

    client = CLIENTS.get(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    if client["client_secret"] and client["client_secret"] != client_secret:
        raise HTTPException(status_code=401, detail="Invalid client_secret")

    stored = auth_codes.pop(code, None)
    if not stored:
        raise HTTPException(status_code=400, detail="Invalid authorization code")
    if time.time() > stored["expires"]:
        raise HTTPException(status_code=400, detail="Authorization code expired")
    if stored["client_id"] != client_id:
        raise HTTPException(status_code=400, detail="Client mismatch")
    if stored["redirect_uri"] != redirect_uri:
        raise HTTPException(status_code=400, detail="Redirect URI mismatch")

    if stored["code_challenge"]:
        if not code_verifier:
            raise HTTPException(status_code=400, detail="PKCE: code_verifier required")
        if stored["code_challenge_method"] == "S256":
            expected = b64url(hashlib.sha256(code_verifier.encode()).digest())
            if expected != stored["code_challenge"]:
                raise HTTPException(status_code=400, detail="PKCE: code_verifier mismatch")
        elif stored["code_challenge_method"] == "plain":
            if code_verifier != stored["code_challenge"]:
                raise HTTPException(status_code=400, detail="PKCE: code_verifier mismatch")

    username = stored["username"]
    scope = stored["scope"]

    access_token = make_access_token(username, scope, client_id)
    refresh_token = random_token()

    refresh_tokens[refresh_token] = {
        "client_id": client_id,
        "username": username,
        "scope": scope,
        "expires": time.time() + REFRESH_TTL,
    }

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "refresh_token": refresh_token,
        "scope": scope,
    }


def handle_client_creds(request, get):
    client_id = get("client_id")
    client_secret = get("client_secret") or None
    scope = get("scope") or ""

    if request.headers.get("Authorization", "").startswith("Basic "):
        b64 = request.headers["Authorization"].removeprefix("Basic ")
        decoded = urlsafe_b64decode(b64 + "==").decode()
        client_id, client_secret = decoded.split(":", 1)

    client = CLIENTS.get(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    if client["client_secret"] and client["client_secret"] != client_secret:
        raise HTTPException(status_code=401, detail="Invalid client_secret")

    access_token = make_access_token(client_id, scope, client_id)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "scope": scope,
    }


def handle_refresh(params, get):
    refresh_token = get("refresh_token")
    client_id = get("client_id")

    stored = refresh_tokens.pop(refresh_token, None)
    if not stored:
        raise HTTPException(status_code=400, detail="Invalid refresh token")
    if time.time() > stored["expires"]:
        raise HTTPException(status_code=400, detail="Refresh token expired")
    if stored["client_id"] != client_id:
        raise HTTPException(status_code=400, detail="Client mismatch")

    username = stored["username"]
    scope = stored["scope"]

    new_access = make_access_token(username, scope, client_id)
    new_refresh = random_token()
    refresh_tokens[new_refresh] = {
        "client_id": client_id,
        "username": username,
        "scope": scope,
        "expires": time.time() + REFRESH_TTL,
    }

    return {
        "access_token": new_access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "refresh_token": new_refresh,
        "scope": scope,
    }


def handle_device_token(params, get):
    device_code = get("device_code")
    stored = device_codes.get(device_code)
    if not stored:
        raise HTTPException(status_code=400, detail="Invalid device_code")

    if stored["status"] == "pending":
        return JSONResponse(
            {"error": "authorization_pending"},
            status_code=400,
        )
    if stored["status"] == "approved":
        device_codes.pop(device_code, None)
        username = stored["username"]
        scope = stored.get("scope", "")
        client_id = stored["client_id"]
        return {
            "access_token": make_access_token(username, scope, client_id),
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL,
            "refresh_token": random_token(),
        }

    raise HTTPException(status_code=400, detail="Device code expired or invalid")


@app.post("/device/code")
def device_code(request: Request):
    import asyncio
    body_bytes = asyncio.run(request.body())
    params = parse_qs(body_bytes.decode())

    def get(k: str) -> str:
        vals = params.get(k, [b""])
        v = vals[0]
        return v.decode() if isinstance(v, bytes) else v

    client_id = get("client_id")
    scope = get("scope") or ""

    if not CLIENTS.get(client_id):
        raise HTTPException(status_code=400, detail="Invalid client_id")

    device_code = random_token()
    user_code = secrets.token_hex(3).upper()[:8]
    verification_uri = f"{ISSUER}/device"
    verification_uri_complete = f"{verification_uri}?user_code={user_code}"
    interval = 5

    device_codes[device_code] = {
        "client_id": client_id,
        "scope": scope,
        "user_code": user_code,
        "status": "pending",
        "username": None,
        "expires": time.time() + 600,
    }

    return {
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete,
        "expires_in": 600,
        "interval": interval,
    }


@app.post("/device/approve")
def device_approve(request: Request):
    import asyncio
    body_bytes = asyncio.run(request.body())
    params = parse_qs(body_bytes.decode())

    def get(k: str) -> str:
        vals = params.get(k, [b""])
        v = vals[0]
        return v.decode() if isinstance(v, bytes) else v

    user_code = get("user_code")
    username = get("username")
    password = get("password")

    expected = USERS.get(username)
    if not expected or expected != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    for dc, data in device_codes.items():
        if data["user_code"] == user_code and data["status"] == "pending":
            data["status"] = "approved"
            data["username"] = username
            return {"message": "Device approved"}

    raise HTTPException(status_code=400, detail="Invalid or expired user_code")


@app.get("/device")
def device_form():
    return HTMLResponse("""<!DOCTYPE html>
<html><head><title>Device Authorization</title></head>
<body style="font-family:sans-serif;max-width:400px;margin:40px auto">
<h2>Device Authorization</h2>
<form method="post" action="/device/approve">
<p><label>User Code: <input name="user_code" size="10" autofocus></label></p>
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password" value="password-alice"></label></p>
<p><button type="submit">Approve</button></p>
</form></body></html>""")


@app.get("/userinfo")
def userinfo(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth.removeprefix("Bearer ")
    try:
        payload = jwt.decode(token, public_key, algorithms=["RS256"], issuer=ISSUER)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    return {"sub": payload["sub"], "scope": payload.get("scope", "")}


@app.get("/.well-known/oauth-authorization-server")
def oidc_discovery():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "device_authorization_endpoint": f"{ISSUER}/device/code",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256", "plain"],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
