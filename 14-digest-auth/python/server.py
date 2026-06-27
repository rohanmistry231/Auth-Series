"""Digest Access Authentication Server.

Demonstrates the challenge-response protocol (RFC 7616).
"""

import hashlib
import os
import secrets
import time
import uuid

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

app = FastAPI(title="Digest Auth Server")

REALM = "Auth Series"
USERS = {
    "alice": os.environ.get("ALICE_PASSWORD", "password-alice"),
    "bob": os.environ.get("BOB_PASSWORD", "password-bob"),
}

nonces: dict[str, float] = {}
used_nonces: set[str] = set()


def generate_nonce() -> str:
    return secrets.token_hex(16)


def compute_ha1(username: str, password: str) -> str:
    return hashlib.md5(f"{username}:{REALM}:{password}".encode()).hexdigest()


def compute_ha2(method: str, uri: str) -> str:
    return hashlib.md5(f"{method}:{uri}".encode()).hexdigest()


def compute_response(ha1: str, nonce: str, nc: str, cnonce: str, qop: str, ha2: str) -> str:
    return hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()


def parse_digest_header(header: str) -> dict:
    if not header.startswith("Digest "):
        return {}
    parts = header[7:]
    params = {}
    for part in parts.split(","):
        k, _, v = part.strip().partition("=")
        params[k] = v.strip('"')
    return params


def authenticate(request: Request) -> str:
    auth_header = request.headers.get("Authorization", "")
    params = parse_digest_header(auth_header)
    if not params:
        raise HTTPException(status_code=401)

    username = params.get("username", "")
    password = USERS.get(username)
    if not password:
        raise HTTPException(status_code=401)

    nonce = params.get("nonce", "")
    if nonce in used_nonces:
        raise HTTPException(status_code=401)

    uri = params.get("uri", "")
    response_client = params.get("response", "")
    qop = params.get("qop", "auth")
    nc = params.get("nc", "00000001")
    cnonce = params.get("cnonce", "")

    ha1 = compute_ha1(username, password)
    ha2 = compute_ha2(request.method, uri)
    expected = compute_response(ha1, nonce, nc, cnonce, qop, ha2)

    if not secrets.compare_digest(expected, response_client):
        raise HTTPException(status_code=401)

    used_nonces.add(nonce)
    return username


def unauthorized_response() -> Response:
    nonce = generate_nonce()
    nonces[nonce] = time.time()
    opaque = secrets.token_hex(16)
    return Response(
        status_code=401,
        headers={
            "WWW-Authenticate": (
                f'Digest realm="{REALM}",'
                f'nonce="{nonce}",'
                f'opaque="{opaque}",'
                f'qop="auth",'
                f'algorithm=MD5'
            ),
            "Content-Type": "text/plain",
        },
        content="Unauthorized — provide Digest credentials",
    )


@app.exception_handler(HTTPException)
def digest_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        return unauthorized_response()
    return PlainTextResponse(str(exc.detail), status_code=exc.status_code)


@app.get("/")
def index():
    return HTMLResponse("""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Digest Auth Demo</h2>
<p>Visit <a href="/protected">/protected</a> — your browser will prompt for credentials.</p>
<p>Or use the Python client: <code>python client.py</code></p>
</body></html>""")


@app.get("/protected")
def protected(request: Request):
    try:
        username = authenticate(request)
        return {"message": f"Authenticated as {username}", "scheme": "Digest", "realm": REALM}
    except HTTPException:
        return unauthorized_response()


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
