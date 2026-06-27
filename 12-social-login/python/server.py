"""Social Login Server — built-in mock provider + app.

Browsing to http://127.0.0.1:8000 shows sign-in buttons.
Clicking through demonstrates the full OAuth Authorization Code flow.
"""

import os
import time
import uuid
from datetime import datetime, timezone

import httpx
import jwt as pyjwt
import uvicorn
from fastapi import FastAPI, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI(title="Social Login Demo")

PROVIDER_SECRET = os.environ.get("PROVIDER_CLIENT_SECRET", "provider-secret")

PROVIDERS = {
    "google": {
        "name": "Google",
        "client_id": "google-client-id",
        "client_secret": PROVIDER_SECRET,
        "authorize_path": "/mock/google/authorize",
        "token_path": "/mock/google/token",
        "userinfo_path": "/mock/google/userinfo",
        "scopes": ["openid", "profile", "email"],
    },
    "github": {
        "name": "GitHub",
        "client_id": "github-client-id",
        "client_secret": PROVIDER_SECRET,
        "authorize_path": "/mock/github/authorize",
        "token_path": "/mock/github/token",
        "userinfo_path": "/mock/github/userinfo",
        "scopes": ["read:user", "user:email"],
    },
}

MOCK_USERS = {
    "google": {
        "sub": "google-12345",
        "name": "Alice Google",
        "email": "alice@gmail.com",
        "email_verified": True,
        "picture": "https://example.com/avatars/alice-google.png",
    },
    "github": {
        "sub": "github-67890",
        "name": "GitHub Alice",
        "email": "alice@github.com",
        "email_verified": True,
        "picture": "https://example.com/avatars/alice-github.png",
        "login": "alice-dev",
    },
}

auth_codes: dict[str, dict] = {}
sessions: dict[str, dict] = {}


def make_id_token(provider: str, user: dict) -> str:
    now = int(time.time())
    payload = {
        "iss": f"https://{provider}.com",
        "sub": user["sub"],
        "aud": PROVIDERS[provider]["client_id"],
        "exp": now + 3600,
        "iat": now,
        **user,
    }
    return pyjwt.encode(payload, PROVIDER_SECRET, algorithm="HS256")


def verify_id_token(provider: str, token: str) -> dict:
    prov = PROVIDERS[provider]
    try:
        return pyjwt.decode(token, prov["client_secret"], algorithms=["HS256"], audience=prov["client_id"])
    except pyjwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid ID token: {e}")


def page(content: str) -> HTMLResponse:
    return HTMLResponse(f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">{content}</body></html>""")


@app.get("/")
def index():
    return page("""
<h2>Social Login Demo</h2>
<p style="color:#666">Built-in mock provider — no real credentials needed.</p>
<p><a href="/auth/google/login" style="display:inline-block;padding:12px 24px;background:#4285f4;color:#fff;text-decoration:none;border-radius:4px;margin:8px 0">Sign in with Google</a></p>
<p><a href="/auth/github/login" style="display:inline-block;padding:12px 24px;background:#24292f;color:#fff;text-decoration:none;border-radius:4px;margin:8px 0">Sign in with GitHub</a></p>
""")


@app.get("/auth/{provider}/login")
def social_login(provider: str):
    if provider not in PROVIDERS:
        raise HTTPException(status_code=404, detail="Unknown provider")

    prov = PROVIDERS[provider]
    state = str(uuid.uuid4())
    redirect_uri = f"http://127.0.0.1:8000/auth/{provider}/callback"
    params = (
        f"response_type=code"
        f"&client_id={prov['client_id']}"
        f"&redirect_uri={redirect_uri}"
        f"&scope={'+'.join(prov['scopes'])}"
        f"&state={state}"
    )
    return RedirectResponse(url=f"{prov['authorize_path']}?{params}")


@app.get("/auth/{provider}/callback")
def social_callback(provider: str, code: str = Query(None), state: str = Query(None)):
    if provider not in PROVIDERS:
        raise HTTPException(status_code=404, detail="Unknown provider")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    prov = PROVIDERS[provider]

    with httpx.Client(base_url="http://127.0.0.1:8000") as client:
        token_resp = client.post(prov["token_path"], data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": f"http://127.0.0.1:8000/auth/{provider}/callback",
            "client_id": prov["client_id"],
            "client_secret": prov["client_secret"],
        })
        token_data = token_resp.json()
        id_token = token_data.get("id_token")

        user_info = verify_id_token(provider, id_token)

        userinfo_resp = client.get(prov["userinfo_path"], headers={
            "Authorization": f"Bearer {token_data.get('access_token', '')}"
        })
        userinfo = userinfo_resp.json()

    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        "provider": provider,
        "provider_id": user_info["sub"],
        "name": userinfo.get("name", "Unknown"),
        "email": userinfo.get("email", ""),
        "picture": userinfo.get("picture", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    resp = RedirectResponse(url="/dashboard")
    resp.set_cookie(key="session_id", value=session_id, httponly=True, samesite="lax")
    return resp


@app.get("/dashboard")
def dashboard():
    return page("""
<h2>Dashboard</h2>
<p>You are logged in! (In a real app, session data would display here.)</p>
<p><a href="/">← Back to home</a></p>
""")


# ====================================================================
# Mock Provider Endpoints
# ====================================================================

@app.get("/mock/{provider}/authorize")
def mock_authorize(provider: str, client_id: str = Query(...), redirect_uri: str = Query(...)):
    if provider not in PROVIDERS or client_id != PROVIDERS[provider]["client_id"]:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    return page(f"""
<h2>{PROVIDERS[provider]['name']} — Sign In</h2>
<p style="color:#666">This is the mock {PROVIDERS[provider]['name']} consent page.</p>
<p>App wants to access:</p>
<ul>
  <li>Your email address</li>
  <li>Your profile information</li>
</ul>
<p>Signed in as: <strong>{MOCK_USERS[provider]['name']}</strong></p>
<form method="post" action="/mock/{provider}/consent">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="redirect_uri" value="{redirect_uri}">
  <p>
    <button type="submit" name="action" value="allow" style="padding:10px 24px;background:#34a853;color:#fff;border:none;border-radius:4px;cursor:pointer">Allow</button>
    <button type="submit" name="action" value="deny" style="padding:10px 24px;background:#ea4335;color:#fff;border:none;border-radius:4px;cursor:pointer">Deny</button>
  </p>
</form>
""")


@app.post("/mock/{provider}/consent")
def mock_consent(provider: str, client_id: str = Form(...), redirect_uri: str = Form(...), action: str = Form(...)):
    if provider not in PROVIDERS or client_id != PROVIDERS[provider]["client_id"]:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    if action != "allow":
        return RedirectResponse(url=f"{redirect_uri}?error=access_denied")

    code = str(uuid.uuid4())
    auth_codes[code] = {
        "provider": provider,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "exp": time.time() + 300,
    }
    return RedirectResponse(url=f"{redirect_uri}?code={code}")


@app.post("/mock/{provider}/token")
def mock_token(provider: str, code: str = Form(...), client_secret: str = Form(...)):
    if provider not in PROVIDERS:
        raise HTTPException(status_code=404, detail="Unknown provider")
    if client_secret != PROVIDERS[provider]["client_secret"]:
        raise HTTPException(status_code=401, detail="Invalid client_secret")

    auth = auth_codes.get(code)
    if not auth:
        raise HTTPException(status_code=401, detail="Invalid code")
    if auth["exp"] < time.time():
        raise HTTPException(status_code=401, detail="Code expired")

    user = MOCK_USERS[provider]
    access_token = str(uuid.uuid4())

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": make_id_token(provider, user),
    }


@app.get("/mock/{provider}/userinfo")
def mock_userinfo(provider: str, authorization: str = Query(None)):
    if provider not in PROVIDERS:
        raise HTTPException(status_code=404, detail="Unknown provider")
    return MOCK_USERS[provider]


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
