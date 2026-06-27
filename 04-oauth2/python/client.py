"""OAuth 2.0 client demonstrating all grant types.

Usage:
  python client.py auth-code       # Authorization Code
  python client.py pkce            # Authorization Code + PKCE
  python client.py client-creds    # Client Credentials
  python client.py device          # Device Code
  python client.py refresh         # Token Refresh
"""

import hashlib
import os
import secrets
import sys
import time
from base64 import urlsafe_b64encode

import httpx

AUTH_SERVER = os.environ.get("AUTH_SERVER", "http://localhost:8000")


def b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def auth_code_flow():
    print("=== Authorization Code Flow ===")
    redirect_uri = "http://localhost:8001/callback"
    state = secrets.token_urlsafe(16)

    with httpx.Client() as client:
        step1 = client.get(f"{AUTH_SERVER}/authorize", params={
            "response_type": "code",
            "client_id": "webapp",
            "redirect_uri": redirect_uri,
            "scope": "openid profile",
            "state": state,
        })
        print(f"1. Authorize URL: {step1.url}")

        step2 = client.post(f"{AUTH_SERVER}/authorize/consent", data={
            "response_type": "code",
            "client_id": "webapp",
            "redirect_uri": redirect_uri,
            "scope": "openid profile",
            "state": state,
            "username": "alice",
            "password": os.environ.get("ALICE_PASSWORD", "password-alice"),
            "approve": "yes",
        }, follow_redirects=False)
        print(f"2. Consent status: {step2.status_code}")
        if step2.status_code == 302:
            location = step2.headers["location"]
            print(f"   Redirect to: {location}")

            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(location).query)
            code = qs.get("code", [None])[0]
            print(f"   Auth code: {code[:20]}...")

            step3 = client.post(f"{AUTH_SERVER}/token", data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": "webapp",
                "client_secret": os.environ.get("WEBAPP_SECRET", "webapp-secret"),
                "redirect_uri": redirect_uri,
            })
            print(f"3. Token response: {step3.status_code}")
            for k, v in step3.json().items():
                display = v[:40] + "..." if isinstance(v, str) and len(v) > 40 else v
                print(f"   {k}: {display}")

            return step3.json()
    return None


def pkce_flow():
    print("\n=== Authorization Code + PKCE Flow ===")
    redirect_uri = "http://localhost:3000/callback"
    state = secrets.token_urlsafe(16)

    code_verifier = b64url(secrets.token_bytes(32))
    code_challenge = b64url(hashlib.sha256(code_verifier.encode()).digest())

    with httpx.Client() as client:
        step1 = client.get(f"{AUTH_SERVER}/authorize", params={
            "response_type": "code",
            "client_id": "spa",
            "redirect_uri": redirect_uri,
            "scope": "openid profile",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        })
        print(f"1. Authorize URL: {step1.url}")

        step2 = client.post(f"{AUTH_SERVER}/authorize/consent", data={
            "response_type": "code",
            "client_id": "spa",
            "redirect_uri": redirect_uri,
            "scope": "openid profile",
            "state": state,
            "username": "alice",
            "password": os.environ.get("ALICE_PASSWORD", "password-alice"),
            "approve": "yes",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }, follow_redirects=False)
        print(f"2. Consent status: {step2.status_code}")

        if step2.status_code == 302:
            from urllib.parse import urlparse, parse_qs
            location = step2.headers["location"]
            qs = parse_qs(urlparse(location).query)
            code = qs.get("code", [None])[0]
            print(f"3. Auth code: {code[:20]}...")

            step3 = client.post(f"{AUTH_SERVER}/token", data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": "spa",
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            })
            print(f"4. Token response: {step3.status_code}")
            for k, v in step3.json().items():
                display = v[:40] + "..." if isinstance(v, str) and len(v) > 40 else v
                print(f"   {k}: {display}")

            return step3.json()
    return None


def client_creds_flow():
    print("\n=== Client Credentials Flow ===")
    with httpx.Client() as client:
        resp = client.post(f"{AUTH_SERVER}/token", data={
            "grant_type": "client_credentials",
            "client_id": "service-a",
            "client_secret": os.environ.get("SERVICE_A_SECRET", "service-a-secret"),
            "scope": "read:data",
        })
        print(f"Token response: {resp.status_code}")
        body = resp.json()
        for k, v in body.items():
            display = v[:40] + "..." if isinstance(v, str) and len(v) > 40 else v
            print(f"   {k}: {display}")

        print("\n   Accessing /userinfo with token:")
        userinfo = client.get(f"{AUTH_SERVER}/userinfo", headers={
            "Authorization": f"Bearer {body['access_token']}",
        })
        print(f"   {userinfo.status_code} {userinfo.json()}")

        return body


def device_flow():
    print("\n=== Device Code Flow ===")
    with httpx.Client() as client:
        step1 = client.post(f"{AUTH_SERVER}/device/code", data={
            "client_id": "webapp",
            "scope": "openid profile",
        })
        print(f"1. Device code response: {step1.json()}")

        body = step1.json()
        user_code = body["user_code"]
        device_code = body["device_code"]
        print(f"   User code: {user_code}")
        print(f"   Go to: {body['verification_uri_complete']}")

        step2 = client.post(f"{AUTH_SERVER}/device/approve", data={
            "user_code": user_code,
            "username": "alice",
            "password": os.environ.get("ALICE_PASSWORD", "password-alice"),
        })
        print(f"\n2. Approval status: {step2.status_code} {step2.json()}")

        step3 = client.post(f"{AUTH_SERVER}/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": "webapp",
        })
        print(f"3. Token response: {step3.status_code}")
        for k, v in step3.json().items():
            display = v[:40] + "..." if isinstance(v, str) and len(v) > 40 else v
            print(f"   {k}: {display}")

        return step3.json()


def refresh_flow(tokens):
    print("\n=== Token Refresh Flow ===")
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        print("No refresh token to test")
        return

    with httpx.Client() as client:
        resp = client.post(f"{AUTH_SERVER}/token", data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "webapp",
            "client_secret": os.environ.get("WEBAPP_SECRET", "webapp-secret"),
        })
        print(f"Refresh response: {resp.status_code}")
        body = resp.json()
        for k, v in body.items():
            display = v[:40] + "..." if isinstance(v, str) and len(v) > 40 else v
            print(f"   {k}: {display}")


if __name__ == "__main__":
    flow = sys.argv[1] if len(sys.argv) > 1 else "all"

    flows = {
        "auth-code": auth_code_flow,
        "pkce": pkce_flow,
        "client-creds": client_creds_flow,
        "device": device_flow,
        "refresh": lambda: None,
    }

    tokens = None
    if flow == "all":
        tokens = auth_code_flow()
        pkce_flow()
        client_creds_flow()
        device_flow()
        if tokens:
            refresh_flow(tokens)
    elif flow in flows:
        result = flows[flow]()
        if flow == "auth-code":
            refresh_flow(result)
    else:
        print(f"Unknown flow: {flow}")
        print("Usage: python client.py [auth-code|pkce|client-creds|device|all]")
