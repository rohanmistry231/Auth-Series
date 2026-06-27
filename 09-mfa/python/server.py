"""MFA Server with TOTP.

Endpoints:
  POST /mfa/setup      → Generate TOTP secret, return QR URI
  POST /mfa/verify     → Verify a TOTP code, activate MFA + return backup codes
  POST /login          → Password + TOTP login
  POST /recovery       → Use backup code to login
"""

import os
import secrets
import time
import uuid

import pyotp
import uvicorn
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse

app = FastAPI(title="MFA Server")

USERS = {
    "alice": {
        "password": os.environ.get("ALICE_PASSWORD", "password-alice"),
        "mfa_secret": None,
        "mfa_enabled": False,
        "backup_codes": [],
    },
}

backup_codes_used: set[str] = set()


@app.get("/")
def index():
    return HTMLResponse("""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>MFA Demo</h2>
<form method="post" action="/setup">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">Setup MFA</button></p>
</form>
<hr>
<form method="post" action="/login">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><label>TOTP Code: <input name="totp"></label></p>
<p><button type="submit">Login with MFA</button></p>
</form>
</body></html>""")


@app.post("/setup")
def setup_mfa(username: str = Form(...), password: str = Form(...)):
    user = USERS.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    secret = pyotp.random_base32()
    user["mfa_secret"] = secret
    user["mfa_enabled"] = False

    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name="AuthSeries MFA")

    return {
        "secret": secret,
        "qr_uri": provisioning_uri,
        "message": "Scan this QR code with Google Authenticator or similar",
    }


@app.post("/mfa/verify")
def verify_mfa(username: str = Form(...), totp: str = Form(...)):
    user = USERS.get(username)
    if not user or not user["mfa_secret"]:
        raise HTTPException(status_code=400, detail="MFA not set up")

    totp_obj = pyotp.TOTP(user["mfa_secret"])
    if not totp_obj.verify(totp):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    user["mfa_enabled"] = True
    codes = [secrets.token_hex(4).upper() for _ in range(5)]
    user["backup_codes"] = codes

    return {
        "message": "MFA enabled successfully",
        "backup_codes": codes,
        "warning": "Save these backup codes somewhere safe. They are shown once.",
    }


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), totp: str = Form(None)):
    user = USERS.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user["mfa_enabled"]:
        if not totp:
            raise HTTPException(status_code=401, detail="TOTP code required")
        totp_obj = pyotp.TOTP(user["mfa_secret"])
        if not totp_obj.verify(totp, valid_window=1):
            raise HTTPException(status_code=401, detail="Invalid TOTP code")

    token = str(uuid.uuid4())
    return {"access_token": token, "message": f"Authenticated as {username}"}


@app.post("/recovery")
def recovery_login(username: str = Form(...), backup_code: str = Form(...)):
    user = USERS.get(username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username")

    if backup_code in backup_codes_used:
        raise HTTPException(status_code=401, detail="Backup code already used")

    if backup_code not in user.get("backup_codes", []):
        raise HTTPException(status_code=401, detail="Invalid backup code")

    backup_codes_used.add(backup_code)

    token = str(uuid.uuid4())
    return {
        "access_token": token,
        "message": f"Recovery login as {username}",
        "codes_remaining": len([c for c in user["backup_codes"] if c not in backup_codes_used]),
    }


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
