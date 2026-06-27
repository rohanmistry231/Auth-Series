"""Digest Auth client — performs the challenge-response dance."""

import hashlib
import os
import re

import httpx

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")
REALM = "Auth Series"


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def parse_authenticate_header(header: str) -> dict:
    params = {}
    for part in header.split(","):
        k, _, v = part.strip().partition("=")
        params[k.strip()] = v.strip('"')
    return params


def compute_response(username: str, password: str, method: str, uri: str, nonce: str, cnonce: str, nc: str, qop: str) -> str:
    ha1 = md5(f"{username}:{REALM}:{password}")
    ha2 = md5(f"{method}:{uri}")
    return md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")


def main():
    client = httpx.Client(base_url=BASE_URL, follow_redirects=False)

    print("=== Step 1: Request protected resource (no auth) ===")
    resp = client.get("/protected")
    print(f"  Status: {resp.status_code}")
    assert resp.status_code == 401

    www_auth = resp.headers.get("www-authenticate", "")
    print(f"  WWW-Authenticate: {www_auth[:60]}...")

    params = parse_authenticate_header(www_auth)
    nonce = params.get("nonce", "")
    opaque = params.get("opaque", "")
    qop = params.get("qop", "auth")
    print(f"  Nonce: {nonce[:16]}...")
    print(f"  Opaque: {opaque[:16]}...")

    username = "alice"
    password = os.environ.get("ALICE_PASSWORD", "password-alice")
    cnonce = hashlib.md5(os.urandom(16)).hexdigest()[:16]
    nc = "00000001"
    uri = "/protected"
    response = compute_response(username, password, "GET", uri, nonce, cnonce, nc, qop)

    print(f"\n=== Step 2: Retry with Digest auth ===")
    digest_header = (
        f'Digest username="{username}",'
        f'realm="{REALM}",'
        f'nonce="{nonce}",'
        f'uri="{uri}",'
        f'qop={qop},'
        f'nc={nc},'
        f'cnonce="{cnonce}",'
        f'response="{response}",'
        f'opaque="{opaque}"'
    )
    resp = client.get("/protected", headers={"Authorization": digest_header})
    print(f"  Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"  ✅ {data['message']}")
    else:
        print(f"  ❌ Failed: {resp.text}")

    print(f"\n=== Step 3: Replay nonce (should fail) ===")
    resp = client.get("/protected", headers={"Authorization": digest_header})
    print(f"  Status: {resp.status_code}")
    if resp.status_code == 401:
        print("  ✅ Replay correctly blocked")
    else:
        print("  ❌ Should have been blocked")

    client.close()


if __name__ == "__main__":
    main()
