"""OpenID Connect Provider extending OAuth 2.0.

Adds over OAuth 2.0:
  - ID Token (JWT with identity claims)
  - nonce parameter support
  - OIDC Discovery document
  - Standardized claims based on scopes
"""

import hashlib
import os
import secrets
import time
import uuid
from base64 import urlsafe_b64encode
from urllib.parse import parse_qs, urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI(title="OpenID Connect Provider Example")

ISSUER = "http://localhost:8000"
ACCESS_TTL = 3600
ID_TOKEN_TTL = 3600
REFRESH_TTL = 86400 * 7
AUTH_CODE_TTL = 300

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

USERS = {
    "alice": {
        "password": os.environ.get("ALICE_PASSWORD", "password-alice"),
        "sub": "user-alice-001",
        "name": "Alice Johnson",
        "given_name": "Alice",
        "family_name": "Johnson",
        "email": "alice@example.com",
        "email_verified": True,
        "picture": "https://example.com/avatars/alice.jpg",
    },
    "bob": {
        "password": os.environ.get("BOB_PASSWORD", "password-bob"),
        "sub": "user-bob-002",
        "name": "Bob Smith",
        "given_name": "Bob",
        "family_name": "Smith",
        "email": "bob@example.com",
        "email_verified": False,
        "picture": "https://example.com/avatars/bob.jpg",
    },
}

CLIENTS = {
    "rp": {
        "client_secret": os.environ.get("RP_SECRET", "rp-secret"),
        "redirect_uris": ["http://localhost:8001/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
    },
    "spa": {
        "client_secret": None,
        "redirect_uris": ["http://localhost:3000/callback"],
        "grant_types": ["authorization_code"],
    },
}

auth_codes: dict[str, dict] = {}
access_tokens: dict[str, dict] = {}
refresh_tokens: dict[str, dict] = {}


def b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def random_token() -> str:
    return secrets.token_urlsafe(48)


def make_id_token(user: dict, client_id: str, nonce: str | None, auth_time: int) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": user["sub"],
        "aud": [client_id],
        "exp": now + ID_TOKEN_TTL,
        "iat": now,
        "auth_time": auth_time,
        "nonce": nonce,
        "azp": client_id,
    }

    # Map scopes to claims
    scope_claims = {
        "profile": ["name", "given_name", "family_name", "picture"],
        "email": ["email", "email_verified"],
    }
    for scope_group, fields in scope_claims.items():
        for f in fields:
            if f in user:
                claims[f] = user[f]

    return jwt.encode(claims, private_key, algorithm="RS256")


def make_access_token(user: dict, scope: str, client_id: str) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": user["sub"],
        "client_id": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + ACCESS_TTL,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


def get_user_profile(username: str):
    return USERS.get(username)


def extract_scope_claims(scope: str, user: dict) -> dict:
    result = {"sub": user["sub"]}
    scopes = scope.split()
    if "profile" in scopes:
        for c in ["name", "given_name", "family_name", "picture"]:
            if c in user:
                result[c] = user[c]
    if "email" in scopes:
        for c in ["email", "email_verified"]:
            if c in user:
                result[c] = user[c]
    return result


@app.get("/authorize")
def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(""),
    state: str = Query(""),
    nonce: str | None = Query(None),
    code_challenge: str | None = Query(None),
    code_challenge_method: str | None = Query(None),
):
    client = CLIENTS.get(client_id)
    if not client or redirect_uri not in client["redirect_uris"]:
        raise HTTPException(status_code=400, detail="Invalid client or redirect_uri")
    if response_type != "code":
        raise HTTPException(status_code=400, detail="response_type must be code")
    if "openid" not in scope.split():
        raise HTTPException(status_code=400, detail="openid scope required")

    html = """<!DOCTYPE html>
<html><head><title>OIDC — Authorize</title></head>
<body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>Sign in</h2>
<p><code>{client_id}</code> wants to access your identity</p>
<form method="post" action="/consent">
<input type="hidden" name="response_type" value="{response_type}">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="nonce" value="{nonce}">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password" value="password-alice"></label></p>
<p><button type="submit" name="approve" value="yes">Sign In</button>
<button type="submit" name="approve" value="no">Cancel</button></p>
</form></body></html>""".format(
        client_id=client_id, scope=scope, response_type=response_type,
        redirect_uri=redirect_uri, state=state, nonce=nonce or "",
    )
    return HTMLResponse(html)


@app.post("/consent")
def consent_post(request: Request):
    import asyncio
    body_bytes = asyncio.run(request.body())
    params = parse_qs(body_bytes.decode())

    def g(k: str) -> str:
        vals = params.get(k, [b""])
        v = vals[0]
        return v.decode() if isinstance(v, bytes) else v

    if g("approve") != "yes":
        raise HTTPException(status_code=403, detail="Consent denied")

    username = g("username")
    password = g("password")

    user = get_user_profile(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    code = random_token()
    auth_time = int(time.time())
    auth_codes[code] = {
        "client_id": g("client_id"),
        "redirect_uri": g("redirect_uri"),
        "scope": g("scope"),
        "nonce": g("nonce") or None,
        "username": username,
        "auth_time": auth_time,
        "expires": time.time() + AUTH_CODE_TTL,
    }

    qs = {"code": code}
    if g("state"):
        qs["state"] = g("state")
    return RedirectResponse(f"{g('redirect_uri')}?{urlencode(qs)}")


@app.post("/token")
def token(request: Request):
    import asyncio
    body_bytes = asyncio.run(request.body())
    params = parse_qs(body_bytes.decode())

    def g(k: str) -> str:
        vals = params.get(k, [b""])
        v = vals[0]
        return v.decode() if isinstance(v, bytes) else v

    grant_type = g("grant_type")
    if grant_type == "authorization_code":
        return handle_auth_code(g)
    elif grant_type == "refresh_token":
        return handle_refresh(g)
    raise HTTPException(status_code=400, detail="Unsupported grant_type")


def handle_auth_code(g):
    code = g("code")
    client_id = g("client_id")
    client_secret = g("client_secret") or None
    redirect_uri = g("redirect_uri")

    client = CLIENTS.get(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client")
    if client["client_secret"] and client["client_secret"] != client_secret:
        raise HTTPException(status_code=400, detail="Invalid client_secret")

    stored = auth_codes.pop(code, None)
    if not stored or time.time() > stored["expires"]:
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    if stored["client_id"] != client_id or stored["redirect_uri"] != redirect_uri:
        raise HTTPException(status_code=400, detail="Client or redirect mismatch")

    user = get_user_profile(stored["username"])
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    scope = stored["scope"]
    access_token = make_access_token(user, scope, client_id)
    refresh_token = random_token()
    id_token = make_id_token(user, client_id, stored["nonce"], stored["auth_time"])

    refresh_tokens[refresh_token] = {
        "client_id": client_id,
        "username": stored["username"],
        "scope": scope,
        "expires": time.time() + REFRESH_TTL,
    }

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "refresh_token": refresh_token,
        "id_token": id_token,
    }


def handle_refresh(g):
    refresh_token = g("refresh_token")
    client_id = g("client_id")

    stored = refresh_tokens.pop(refresh_token, None)
    if not stored or time.time() > stored["expires"] or stored["client_id"] != client_id:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    user = get_user_profile(stored["username"])
    new_access = make_access_token(user, stored["scope"], client_id)
    new_refresh = random_token()
    id_token = make_id_token(user, client_id, None, int(time.time()))

    refresh_tokens[new_refresh] = {
        "client_id": client_id,
        "username": stored["username"],
        "scope": stored["scope"],
        "expires": time.time() + REFRESH_TTL,
    }

    return {
        "access_token": new_access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "refresh_token": new_refresh,
        "id_token": id_token,
    }


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

    sub = payload["sub"]
    scope = payload.get("scope", "")

    for username, user in USERS.items():
        if user["sub"] == sub:
            return extract_scope_claims(scope, user)

    raise HTTPException(status_code=404, detail="User not found")


@app.get("/.well-known/openid-configuration")
def discovery():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    }


@app.get("/.well-known/jwks.json")
def jwks():
    pub_numbers = public_key.public_numbers()
    n = int.to_bytes(pub_numbers.n, 256, "big")
    e = int.to_bytes(pub_numbers.e, 3, "big")

    def b64(data: bytes) -> str:
        return urlsafe_b64encode(data).rstrip(b"=").decode()

    return {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "oidc-rsa-1",
            "n": b64(n),
            "e": b64(e),
        }],
    }


@app.get("/.well-known/oauth-authorization-server")
def oauth_discovery():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
