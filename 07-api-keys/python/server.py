"""API Key auth server.

Features:
  - Generate keys with prefix + suffix display
  - Store SHA-256 hashes (never raw keys)
  - Scopes-based authorization
  - Key expiry
  - Key rotation (old → new)
  - Rate limiting (token bucket per key)
"""

import hashlib
import hmac
import os
import secrets
import time
import uuid

import uvicorn
from fastapi import FastAPI, HTTPException, Request, status

app = FastAPI(title="API Key Auth Example")

USERS = {
    "alice": os.environ.get("ALICE_PASSWORD", "password-alice"),
}

store: dict[str, dict] = {}

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 10


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def generate_key(prefix: str = "user_stripe_key") -> str:
    raw = secrets.token_urlsafe(32)
    return f"{prefix}_{raw}"


def create_key(name: str, scopes: list[str], expires_in_days: int | None = None) -> dict:
    key = generate_key()
    key_hash = hash_key(key)
    key_id = str(uuid.uuid4())

    entry = {
        "id": key_id,
        "name": name,
        "prefix": key.split("_")[0] + "_" + key.split("_")[1],
        "key_hash": key_hash,
        "key_suffix": key[-4:],
        "scopes": scopes,
        "created_at": time.time(),
        "expires_at": (time.time() + expires_in_days * 86400) if expires_in_days else None,
        "last_used": None,
        "rate_window_start": 0.0,
        "rate_window_count": 0,
    }
    store[key_hash] = entry
    return {**entry, "key": key}


@app.post("/keys")
def create_api_key(request: Request):
    import json
    body = request.scope.get("body", b"{}")
    try:
        data = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    entry = create_key(
        name=data.get("name", "Untitled"),
        scopes=data.get("scopes", ["read"]),
        expires_in_days=data.get("expires_in_days"),
    )
    return {
        "id": entry["id"],
        "name": entry["name"],
        "prefix": entry["prefix"],
        "key_suffix": entry["key_suffix"],
        "key": entry["key"],
        "scopes": entry["scopes"],
        "expires_at": entry["expires_at"],
    }


@app.post("/keys/{key_id}/rotate")
def rotate_key(key_id: str, request: Request):
    for kh, entry in list(store.items()):
        if entry["id"] == key_id:
            new_entry = create_key(entry["name"], entry["scopes"],
                                   expires_in_days=None if not entry["expires_at"] else 30)
            store.pop(kh, None)
            return {
                "message": "Key rotated",
                "old_id": key_id,
                "new_id": new_entry["id"],
                "new_key": new_entry["key"],
            }
    raise HTTPException(status_code=404, detail="Key not found")


@app.post("/keys/{key_id}/revoke")
def revoke_key(key_id: str):
    for kh, entry in list(store.items()):
        if entry["id"] == key_id:
            store.pop(kh, None)
            return {"message": "Key revoked", "id": key_id}
    raise HTTPException(status_code=404, detail="Key not found")


@app.get("/keys")
def list_keys():
    result = []
    for entry in store.values():
        result.append({
            "id": entry["id"],
            "name": entry["name"],
            "prefix": entry["prefix"],
            "key_suffix": entry["key_suffix"],
            "scopes": entry["scopes"],
        })
    return result


def authenticate(request: Request) -> dict:
    api_key = request.headers.get("x-api-key") or ""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        api_key = auth.removeprefix("Bearer ")

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    key_hash = hash_key(api_key)
    entry = store.get(key_hash)
    if not entry:
        raise HTTPException(status_code=403, detail="Invalid API key")

    if entry["expires_at"] and time.time() > entry["expires_at"]:
        raise HTTPException(status_code=403, detail="API key expired")

    now = time.time()
    if now - entry["rate_window_start"] > RATE_LIMIT_WINDOW:
        entry["rate_window_start"] = now
        entry["rate_window_count"] = 0

    entry["rate_window_count"] += 1
    if entry["rate_window_count"] > RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    entry["last_used"] = now
    return entry


def require_scopes(*required: str):
    def checker(api_key_entry: dict = None):
        entry = api_key_entry
        for r in required:
            if r not in entry.get("scopes", []):
                raise HTTPException(status_code=403, detail=f"Missing scope: {r}")
        return entry
    return checker


@app.get("/api/public")
def public():
    return {"message": "Public endpoint — no API key required"}


@app.get("/api/keys")
def list_keys_api(entry: dict = None):
    entry = authenticate(Request(scope={"type": "http"}))
    # Re-authenticate properly
    return {"message": "You accessed a key-protected endpoint"}


@app.get("/api/data")
def get_data(request: Request):
    entry = authenticate(request)
    return {"message": "Protected data", "key_name": entry["name"], "scopes": entry["scopes"]}


@app.get("/api/admin")
def admin_data(request: Request):
    entry = authenticate(request)
    if "admin" not in entry.get("scopes", []):
        raise HTTPException(status_code=403, detail="Admin scope required")
    return {"message": "Admin data", "key_name": entry["name"]}


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
