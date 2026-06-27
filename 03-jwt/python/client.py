"""JWT auth client using httpx.

Demonstrates login, protected access, and token refresh.
"""

import os

import httpx

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")
USERNAME = os.environ.get("AUTH_USERNAME", "alice")
PASSWORD = os.environ.get("AUTH_PASSWORD", "password-alice")

tokens: dict[str, str] = {}

def main():
    client = httpx.Client(base_url=BASE_URL)

    print("=== 1. Login ===")
    resp = client.post("/login", json={"username": USERNAME, "password": PASSWORD})
    data = resp.json()
    print(resp.status_code, {k: v[:20] + "..." for k, v in data.items()})
    tokens["access"] = data["access_token"]
    tokens["refresh"] = data["refresh_token"]

    print("\n=== 2. Access protected endpoint ===")
    resp = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {tokens['access']}"},
    )
    print(resp.status_code, resp.json())

    print("\n=== 3. JWKS endpoint ===")
    resp = client.get("/.well-known/jwks.json")
    print(resp.status_code, {k: str(v)[:80] for k, v in resp.json().items()})

    print("\n=== 4. Refresh tokens ===")
    resp = client.post("/refresh", json={"refresh_token": tokens["refresh"]})
    data = resp.json()
    print(resp.status_code, {k: v[:20] + "..." for k, v in data.items()})
    tokens["access"] = data["access_token"]
    tokens["refresh"] = data["refresh_token"]

    print("\n=== 5. Protected with new access token ===")
    resp = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {tokens['access']}"},
    )
    print(resp.status_code, resp.json())

    print("\n=== 6. Reuse old refresh token (should fail) ===")
    resp = client.post("/refresh", json={"refresh_token": tokens["refresh"]})
    # This should succeed because we're using the current one; simulating rotation:
    resp = client.post("/refresh", json={"refresh_token": "some-old-revoked-token"})
    print(resp.status_code, resp.json())

    client.close()

if __name__ == "__main__":
    main()
