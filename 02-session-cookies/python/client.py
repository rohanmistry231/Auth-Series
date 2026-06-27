"""Session & Cookie auth client using httpx.

Demonstrates login, accessing protected endpoints, and logout
using httpx's built-in cookie jar.
"""

import os

import httpx

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")
USERNAME = os.environ.get("AUTH_USERNAME", "alice")
PASSWORD = os.environ.get("AUTH_PASSWORD", "password-alice")

def main():
    client = httpx.Client(base_url=BASE_URL)

    print("=== Public endpoint ===")
    resp = client.get("/public")
    print(resp.status_code, resp.json())

    print("\n=== Login ===")
    resp = client.post("/login", json={"username": USERNAME, "password": PASSWORD})
    print(resp.status_code, resp.json())
    print("Cookies:", dict(client.cookies))

    print("\n=== Protected endpoint (/me) ===")
    resp = client.get("/me")
    print(resp.status_code, resp.json())

    print("\n=== Create data (with CSRF) ===")
    csrf_resp = client.get("/csrf-token")
    token = csrf_resp.json().get("csrf_token", "")
    resp = client.post("/data", json={"csrf_token": token, "payload": "hello"})
    print(resp.status_code, resp.json())

    print("\n=== Create data (no CSRF — should fail) ===")
    resp = client.post("/data", json={"payload": "hello"})
    print(resp.status_code, resp.json())

    print("\n=== Logout ===")
    resp = client.post("/logout")
    print(resp.status_code, resp.json())
    print("Cookies after logout:", dict(client.cookies))

    print("\n=== After logout (/me — should fail) ===")
    resp = client.get("/me")
    print(resp.status_code, resp.json())

    client.close()

if __name__ == "__main__":
    main()
