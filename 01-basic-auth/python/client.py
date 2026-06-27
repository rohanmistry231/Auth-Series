"""HTTP Basic Auth client using httpx."""

import os

import httpx
from httpx import HTTPStatusError

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")
USERNAME = os.environ.get("AUTH_USERNAME", "alice")
PASSWORD = os.environ.get("AUTH_PASSWORD", "password-alice")

def main():
    client = httpx.Client(auth=(USERNAME, PASSWORD))

    print("=== Public endpoint ===")
    resp = client.get(f"{BASE_URL}/public")
    print(resp.status_code, resp.json())

    print("\n=== Protected endpoint (with auth) ===")
    resp = client.get(f"{BASE_URL}/protected")
    print(resp.status_code, resp.json())

    client.close()

    print("\n=== Protected endpoint (wrong password) ===")
    bad_client = httpx.Client(auth=(USERNAME, "wrong-password"))
    try:
        bad_client.get(f"{BASE_URL}/protected")
    except HTTPStatusError as e:
        print(e.response.status_code, e.response.json())
    bad_client.close()

    print("\n=== Protected endpoint (no auth) ===")
    try:
        httpx.get(f"{BASE_URL}/protected")
    except HTTPStatusError as e:
        print(e.response.status_code, e.response.json())

if __name__ == "__main__":
    main()
