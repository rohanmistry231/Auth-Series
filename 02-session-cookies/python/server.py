"""Session & Cookie-based auth server using FastAPI.

Demonstrates:
- In-memory session store
- Signed session ID cookies
- Session regeneration on login (prevents fixation)
- CSRF token generation
- Logout (server-side deletion)
"""

import hmac
import os
import secrets
import time
import uuid

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response, status

app = FastAPI(title="Session Cookie Auth Example")

SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-secret-change-in-production-32chars")
SESSION_TTL = 3600  # 1 hour
IDLE_TTL = 900      # 15 minutes idle timeout

USERS = {
    "alice": os.environ.get("ALICE_PASSWORD", "password-alice"),
    "bob":   os.environ.get("BOB_PASSWORD", "password-bob"),
}

store: dict[str, dict] = {}

def sign(value: str) -> str:
    return hmac.new(SESSION_SECRET.encode(), value.encode(), "sha256").hexdigest()

def create_signed_session_id() -> str:
    session_id = str(uuid.uuid4())
    return f"{session_id}.{sign(session_id)}"

def verify_signed_session_id(signed: str) -> str | None:
    parts = signed.split(".")
    if len(parts) != 2:
        return None
    session_id, signature = parts
    if not hmac.compare_digest(signature, sign(session_id)):
        return None
    return session_id

def get_session(request: Request) -> dict | None:
    raw = request.cookies.get("session_id")
    if not raw:
        return None
    sid = verify_signed_session_id(raw)
    if not sid:
        return None
    session = store.get(sid)
    if not session:
        return None
    now = time.time()
    if now > session["expires_absolute"]:
        del store[sid]
        return None
    if now > session["expires_idle"]:
        del store[sid]
        return None
    session["expires_idle"] = now + IDLE_TTL
    return session

@app.get("/csrf-token")
def csrf_token(request: Request, response: Response):
    session = get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = secrets.token_hex(32)
    session["csrf_token"] = token
    return {"csrf_token": token}

@app.get("/public")
def public_endpoint():
    return {"message": "This is public — no session required"}

@app.post("/login")
def login(request: Request, response: Response):
    body = request.state.json if hasattr(request.state, "json") else {}
    body_data = secrets.token_hex(8)

    import json as _json
    raw = request.scope.get("body", b"{}")
    try:
        data = _json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    username = data.get("username", "")
    password = data.get("password", "")

    expected = USERS.get(username)
    if not expected or not hmac.compare_digest(expected.encode(), password.encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    signed = create_signed_session_id()
    sid = signed.split(".")[0]

    now = time.time()
    store[sid] = {
        "user_id": username,
        "role": "admin" if username == "alice" else "user",
        "expires_absolute": now + SESSION_TTL,
        "expires_idle": now + IDLE_TTL,
        "csrf_token": None,
    }

    response.set_cookie(
        key="session_id",
        value=signed,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=SESSION_TTL,
    )
    return {"message": f"Logged in as {username}"}

@app.get("/me")
def me(request: Request):
    session = get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {
        "user_id": session["user_id"],
        "role": session["role"],
    }

@app.post("/data")
def create_data(request: Request):
    session = get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    import json as _json
    raw = request.scope.get("body", b"{}")
    try:
        data = _json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    token = data.get("csrf_token", "")
    if not session.get("csrf_token") or not hmac.compare_digest(
        session["csrf_token"].encode(), token.encode()
    ):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    session["csrf_token"] = None
    return {"message": "Data created", "data": data.get("payload")}

@app.post("/logout")
def logout(request: Request, response: Response):
    session = get_session(request)
    if session:
        sid = request.cookies.get("session_id", "").split(".")[0]
        store.pop(sid, None)

    response.delete_cookie("session_id", path="/")
    return {"message": "Logged out"}

if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
