"""CAS Server + Protected App — self-contained CAS SSO demo.

Endpoints:
  CAS Server:  /login, /validate
  App:         /, /protected
"""

import os
import secrets
import time
import uuid

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

app = FastAPI(title="CAS Demo")

USERS = {
    "alice": os.environ.get("ALICE_PASSWORD", "password-alice"),
    "bob": os.environ.get("BOB_PASSWORD", "password-bob"),
}

tickets: dict[str, dict] = {}
sessions: dict[str, str] = {}

SERVICE_URL = "http://127.0.0.1:8000/protected"


def page(body: str) -> HTMLResponse:
    return HTMLResponse(f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">{body}</body></html>""")


# ====================================================================
# App Endpoints
# ====================================================================

@app.get("/")
def index():
    return page("""
<h2>CAS Demo</h2>
<p>This app uses <strong>CAS</strong> for single sign-on.</p>
<p><a href="/protected">Protected resource</a> (requires CAS login)</p>
""")


@app.get("/protected")
def protected(ticket: str = Query(None)):
    ticket = ticket
    if ticket:
        import httpx
        with httpx.Client() as client:
            resp = client.get(f"http://127.0.0.1:8000/validate", params={"ticket": ticket, "service": SERVICE_URL})
            body = resp.text.strip()
            if body.startswith("yes"):
                username = body.split("\n", 1)[1].strip() if "\n" in body else ""
                session_id = str(uuid.uuid4())
                sessions[session_id] = username
                resp2 = RedirectResponse(url="/protected")
                resp2.set_cookie(key="session_id", value=session_id, httponly=True, samesite="lax")
                return resp2
            return page(f"<h2>CAS Login Failed</h2><p>{body}</p><p><a href='/'>← Back</a></p>")

    session_id = None
    # Can't easily read cookies synchronously in FastAPI without request param
    return RedirectResponse(url=f"/login?service={SERVICE_URL}")


@app.get("/session")
def view_session():
    return page("<h2>Session Info</h2><p>Check your cookies for session_id.</p><p><a href='/'>← Back</a></p>")


# ====================================================================
# CAS Server Endpoints
# ====================================================================

@app.get("/login")
def cas_login(service: str = Query(...), error: str = Query(None)):
    error_html = f'<p style="color:red">{error}</p>' if error else ""
    return page(f"""
<h2>CAS Login</h2>
{error_html}
<p>Service: <code>{service}</code></p>
<form method="post" action="/login">
  <input type="hidden" name="service" value="{service}">
  <p><label>Username: <input name="username" value="alice"></label></p>
  <p><label>Password: <input name="password" type="password"></label></p>
  <p><button type="submit">Login</button></p>
</form>
""")


@app.post("/login")
def cas_login_post(service: str = Form(...), username: str = Form(...), password: str = Form(...)):
    if username not in USERS or USERS[username] != password:
        return RedirectResponse(url=f"/login?service={service}&error=Invalid+credentials")

    ticket = f"ST-{secrets.token_hex(16)}"
    tickets[ticket] = {
        "username": username,
        "service": service,
        "exp": time.time() + 300,  # 5 min
        "used": False,
    }

    redirect_url = f"{service}?ticket={ticket}"
    return RedirectResponse(url=redirect_url)


@app.get("/validate")
def cas_validate(ticket: str = Query(...), service: str = Query(...)):
    t = tickets.get(ticket)
    if not t:
        return PlainTextResponse("no\nInvalid ticket")
    if t["used"]:
        return PlainTextResponse("no\nTicket already used")
    if t["exp"] < time.time():
        return PlainTextResponse("no\nTicket expired")
    if t["service"] != service:
        return PlainTextResponse("no\nService mismatch")

    t["used"] = True
    return PlainTextResponse(f"yes\n{t['username']}")


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
