"""OpenID Connect Relying Party (RP) client.

Demonstrates:
  - Fetching OIDC discovery document
  - Initiating authorization request with openid scope + nonce
  - Exchanging code for tokens
  - Validating ID Token (signature, iss, aud, exp, nonce)
  - Calling /userinfo endpoint
"""

import os
import secrets
import sys
import time
from base64 import urlsafe_b64decode
from urllib.parse import parse_qs, urlparse

import httpx
import jwt

ISSUER = os.environ.get("OIDC_ISSUER", "http://localhost:8000")
CLIENT_ID = "rp"
CLIENT_SECRET = os.environ.get("RP_SECRET", "rp-secret")
REDIRECT_URI = "http://localhost:8001/callback"


def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return urlsafe_b64decode(s)


def discover():
    with httpx.Client() as c:
        resp = c.get(f"{ISSUER}/.well-known/openid-configuration")
        config = resp.json()
        print("=== Discovery Document ===")
        for k in ["issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"]:
            print(f"  {k}: {config.get(k)}")
        return config


def fetch_jwks():
    with httpx.Client() as c:
        return c.get(f"{ISSUER}/.well-known/jwks.json").json()


def validate_id_token(id_token: str, expected_nonce: str | None, jwks: dict) -> dict:
    """Validate ID Token per OIDC spec."""
    header = jwt.get_unverified_header(id_token)
    payload = jwt.decode(id_token, options={"verify_signature": False})

    # Find the matching key in JWKS
    for jwk_key in jwks.get("keys", []):
        if jwk_key["kid"] == header.get("kid"):
            from cryptography.hazmat.primitives.asymmetric import rsa as rsa_alg
            from cryptography.hazmat.primitives.serialization import load_der_public_key

            n_bytes = b64url_decode(jwk_key["n"])
            e_bytes = b64url_decode(jwk_key["e"])
            e_int = int.from_bytes(e_bytes, "big")
            n_int = int.from_bytes(n_bytes, "big")

            rsa_pub = rsa_alg.RSAPublicNumbers(e_int, n_int).public_key()
            break
    else:
        raise ValueError("No matching JWK key found")

    # Verify signature
    payload = jwt.decode(id_token, rsa_pub, algorithms=["RS256"], issuer=ISSUER)

    now = int(time.time())
    checks = []

    # Verify issuer
    if payload.get("iss") != ISSUER:
        checks.append(f"FAIL: iss={payload.get('iss')} expected={ISSUER}")

    # Verify audience
    aud = payload.get("aud", [])
    if isinstance(aud, str):
        aud = [aud]
    if CLIENT_ID not in aud:
        checks.append(f"FAIL: aud={aud} must contain {CLIENT_ID}")

    # Verify expiry
    if payload.get("exp", 0) < now:
        checks.append(f"FAIL: token expired at {payload.get('exp')}")

    # Verify issued at
    if payload.get("iat", 0) > now + 60:
        checks.append(f"FAIL: iat={payload.get('iat')} is in the future")

    # Verify nonce
    if expected_nonce and payload.get("nonce") != expected_nonce:
        checks.append(f"FAIL: nonce mismatch ({payload.get('nonce')} vs {expected_nonce})")

    # Verify azp if present
    if "azp" in payload and payload["azp"] != CLIENT_ID:
        checks.append(f"FAIL: azp={payload.get('azp')} must be {CLIENT_ID}")

    if checks:
        for c in checks:
            print(f"  {c}")
        raise ValueError("ID Token validation failed")

    print("  ✅ ID Token validated successfully")
    return payload


def run_flow():
    print("=== OpenID Connect Flow ===\n")

    discover()
    nonce = secrets.token_urlsafe(16)
    state = secrets.token_urlsafe(16)

    with httpx.Client() as client:
        authorize_redirect = client.get(
            f"{ISSUER}/authorize",
            params={
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid profile email",
                "state": state,
                "nonce": nonce,
            },
            follow_redirects=False,
        )
        print(f"\n1. Authorize redirect: {authorize_redirect.status_code}")

        consent = client.post(
            f"{ISSUER}/consent",
            data={
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid profile email",
                "state": state,
                "nonce": nonce,
                "username": "alice",
                "password": os.environ.get("ALICE_PASSWORD", "password-alice"),
                "approve": "yes",
            },
            follow_redirects=False,
        )
        print(f"2. Consent: {consent.status_code}")

        location = consent.headers.get("location", "")
        qs = parse_qs(urlparse(location).query)
        code = qs.get("code", [None])[0]
        print(f"3. Auth code: {code[:20]}...")

        token_resp = client.post(
            f"{ISSUER}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uri": REDIRECT_URI,
            },
        )
        tokens = token_resp.json()
        print(f"\n4. Token response: {token_resp.status_code}")
        for k, v in tokens.items():
            display = v[:50] + "..." if isinstance(v, str) and len(v) > 50 else v
            print(f"   {k}: {display}")

        id_token = tokens.get("id_token", "")

        print("\n5. Validating ID Token...")
        jwks = fetch_jwks()
        id_claims = validate_id_token(id_token, nonce, jwks)
        print(f"   sub: {id_claims.get('sub')}")
        print(f"   name: {id_claims.get('name')}")
        print(f"   email: {id_claims.get('email')}")
        print(f"   nonce: {id_claims.get('nonce')}")

        print("\n6. Fetching UserInfo...")
        userinfo = client.get(
            f"{ISSUER}/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        print(f"   {userinfo.status_code}: {userinfo.json()}")


if __name__ == "__main__":
    run_flow()
