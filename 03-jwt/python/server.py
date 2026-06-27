"""JWT auth server with HS256 and RS256 signing.

Endpoints:
  POST /login          → { access_token, refresh_token }
  GET  /protected      → protected resource (validates access token)
  POST /refresh        → { access_token, refresh_token }  (rotation)
  GET  /.well-known/jwks.json → public keys for RS256 verification
"""

import os
import time
import uuid
from base64 import urlsafe_b64encode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

app = FastAPI(title="JWT Auth Example")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ACCESS_TTL = 900        # 15 minutes
REFRESH_TTL = 604800    # 7 days
ISSUER = "auth-series"
ALG_SYMMETRIC = "HS256"
ALG_ASYMMETRIC = "RS256"

HS256_SECRET = os.environ.get(
    "JWT_HS256_SECRET",
    "change-me-to-a-256-bit-secret-in-production",
).encode()

private_key_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_rsa = private_key_rsa.public_key()

USERS = {
    "alice": os.environ.get("ALICE_PASSWORD", "password-alice"),
    "bob":   os.environ.get("BOB_PASSWORD", "password-bob"),
}

# ---------------------------------------------------------------------------
# Refresh token store (server-side for revocability)
# ---------------------------------------------------------------------------
refresh_store: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Token generation
# ---------------------------------------------------------------------------

def make_access_token(sub: str, role: str, alg: str = ALG_ASYMMETRIC) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": sub,
        "role": role,
        "iat": now,
        "exp": now + ACCESS_TTL,
        "type": "access",
        "jti": str(uuid.uuid4()),
    }
    if alg == "HS256":
        return jwt.encode(payload, HS256_SECRET, algorithm="HS256")
    return jwt.encode(payload, private_key_rsa, algorithm="RS256")

def make_refresh_token(sub: str) -> str:
    now = int(time.time())
    jti = str(uuid.uuid4())
    payload = {
        "iss": ISSUER,
        "sub": sub,
        "iat": now,
        "exp": now + REFRESH_TTL,
        "type": "refresh",
        "jti": jti,
    }
    token = jwt.encode(payload, HS256_SECRET, algorithm="HS256")
    refresh_store[jti] = {"sub": sub, "exp": payload["exp"]}
    return token

def rotate_refresh(old_jti: str, sub: str) -> str:
    refresh_store.pop(old_jti, None)
    return make_refresh_token(sub)

# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------

def verify_access_token(token: str) -> dict | None:
    errors = []
    for alg, key in [(ALG_SYMMETRIC, HS256_SECRET), (ALG_ASYMMETRIC, public_key_rsa)]:
        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=[alg],
                issuer=ISSUER,
                options={"require": ["exp", "iss", "sub", "type"]},
            )
            if payload.get("type") != "access":
                continue
            return payload
        except jwt.PyJWTError:
            errors.append(alg)
    return None

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_bearer(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    return auth.removeprefix("Bearer ")

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/login")
def login(request: Request):
    data = request.state.json if hasattr(request.state, "json") else {}
    body = request.scope.get("body", b"{}")
    import json
    try:
        data = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    username = data.get("username", "")
    password = data.get("password", "")

    expected = USERS.get(username)
    if not expected or expected != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    role = "admin" if username == "alice" else "user"
    access_token = make_access_token(username, role)
    refresh_token = make_refresh_token(username)

    return {"access_token": access_token, "refresh_token": refresh_token}

@app.get("/protected")
def protected(request: Request):
    token = get_bearer(request)
    payload = verify_access_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")

    return {
        "sub": payload["sub"],
        "role": payload["role"],
        "message": "You have accessed a protected resource via JWT",
    }

@app.post("/refresh")
def refresh(request: Request):
    body = request.scope.get("body", b"{}")
    import json
    try:
        data = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    refresh_token = data.get("refresh_token", "")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Missing refresh_token")

    try:
        payload = jwt.decode(
            refresh_token,
            HS256_SECRET,
            algorithms=["HS256"],
            issuer=ISSUER,
            options={"require": ["exp", "iss", "sub", "jti", "type"]},
        )
        if payload.get("type") != "refresh":
            raise ValueError("wrong type")
    except (jwt.PyJWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    jti = payload["jti"]
    stored = refresh_store.get(jti)
    if not stored:
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")

    sub = payload["sub"]
    role = "admin" if sub == "alice" else "user"

    new_access = make_access_token(sub, role)
    new_refresh = rotate_refresh(jti, sub)

    return {"access_token": new_access, "refresh_token": new_refresh}

@app.get("/.well-known/jwks.json")
def jwks():
    pub_numbers = public_key_rsa.public_numbers()
    n = int.to_bytes(pub_numbers.n, 256, "big")
    e = int.to_bytes(pub_numbers.e, 3, "big")

    def b64url(data: bytes) -> str:
        return urlsafe_b64encode(data).rstrip(b"=").decode()

    return JSONResponse({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "auth-series-rsa-1",
            "n": b64url(n),
            "e": b64url(e),
        }],
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
