"""SSO Client App — validates SSO tokens, maintains local session.

Run two instances:
  APP_ID=app1 APP_PORT=8001 APP_NAME="My Dashboard" python app.py
  APP_ID=app2 APP_PORT=8002 APP_NAME="Admin Panel" python app.py
"""

import os
import secrets
import time
import uuid
from urllib.parse import urlencode

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI(title="SSO Client App")

APP_ID = os.environ.get("APP_ID", "app1")
APP_PORT = int(os.environ.get("APP_PORT", "8001"))
APP_NAME = os.environ.get("APP_NAME", "My App")
SSO_SERVER = os.environ.get("SSO_SERVER", "http://localhost:8000")

local_sessions: dict[str, dict] = {}


@app.get("/")
@app.get("/dashboard")
def dashboard(request: Request):
    session_id = request.cookies.get("app_session")
    if not session_id or session_id not in local_sessions:
        redirect_url = f"{SSO_SERVER}/sso/login?{urlencode({'redirect': f'http://localhost:{APP_PORT}/sso/callback'})}"
        return RedirectResponse(url=redirect_url)

    session = local_sessions[session_id]
    return HTMLResponse(f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>{APP_NAME}</h2>
<p>Logged in as: <strong>{session['username']}</strong></p>
<p>App ID: {APP_ID}</p>
<hr>
<p><a href="/profile">Profile</a> | <a href="/logout">Logout</a></p>
</body></html>""")


@app.get("/sso/callback")
def sso_callback(token: str = Query(...)):
    with httpx.Client() as client:
        resp = client.get(f"{SSO_SERVER}/sso/validate", params={"token": token})
        if resp.status_code != 200:
            return HTMLResponse("SSO validation failed", status_code=401)

        data = resp.json()
        username = data["sub"]

        session_id = str(uuid.uuid4())
        local_sessions[session_id] = {
            "username": username,
            "created": time.time(),
            "app_id": APP_ID,
        }

        html_resp = RedirectResponse(url="/dashboard")
        html_resp.set_cookie(key="app_session", value=session_id, httponly=True, max_age=86400)
        return html_resp


@app.get("/profile")
def profile(request: Request):
    session_id = request.cookies.get("app_session")
    if not session_id or session_id not in local_sessions:
        return RedirectResponse(url="/dashboard")

    session = local_sessions[session_id]
    return HTMLResponse(f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Profile</h2>
<table border="1" cellpadding="8" style="border-collapse:collapse">
<tr><td>Username</td><td>{session['username']}</td></tr>
<tr><td>App</td><td>{APP_NAME}</td></tr>
<tr><td>Session ID</td><td>{session_id[:8]}...</td></tr>
</table>
<p><a href="/dashboard">Back to {APP_NAME}</a></p>
</body></html>""")
    return HTMLResponse("Profile")


@app.get("/logout")
def logout(request: Request):
    session_id = request.cookies.get("app_session")
    if session_id in local_sessions:
        del local_sessions[session_id]

    resp = HTMLResponse(f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:400px;margin:40px auto">
<h2>Logged out of {APP_NAME}</h2>
<p>You are still logged into SSO. <a href="{SSO_SERVER}/sso/logout">Logout of all apps</a></p>
<p><a href="/dashboard">Login again</a></p>
</body></html>""")
    resp.set_cookie(key="app_session", value="", httponly=True, max_age=0)
    return resp


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=APP_PORT, reload=False)
