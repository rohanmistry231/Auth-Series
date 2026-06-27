"""API Key auth client."""

import os
import httpx

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")

def main():
    client = httpx.Client(base_url=BASE_URL)

    print("=== Create an API key ===")
    resp = client.post("/keys", json={"name": "My App Key", "scopes": ["read", "write"], "expires_in_days": 30})
    key_data = resp.json()
    api_key = key_data["key"]
    print(f"  Created: {key_data['prefix']}...{key_data['key_suffix']}")
    print(f"  Full key: {api_key[:20]}...")

    print("\n=== Public endpoint ===")
    resp = client.get("/api/public")
    print(f"  {resp.status_code}: {resp.json()}")

    print("\n=== Protected endpoint (valid key) ===")
    resp = client.get("/api/data", headers={"X-API-Key": api_key})
    print(f"  {resp.status_code}: {resp.json()}")

    print("\n=== Protected endpoint (invalid key) ===")
    resp = client.get("/api/data", headers={"X-API-Key": "enter_api_key_here"})
    print(f"  {resp.status_code}: {resp.json()}")

    print("\n=== Admin endpoint (no admin scope) ===")
    resp = client.get("/api/admin", headers={"X-API-Key": api_key})
    print(f"  {resp.status_code}: {resp.json()}")

    print("\n=== Create admin key ===")
    resp = client.post("/keys", json={"name": "Admin Key", "scopes": ["read", "write", "admin"]})
    admin_key = resp.json()["key"]

    print("\n=== Admin endpoint (with admin scope) ===")
    resp = client.get("/api/admin", headers={"X-API-Key": admin_key})
    print(f"  {resp.status_code}: {resp.json()}")

    print("\n=== List keys ===")
    resp = client.get("/keys")
    print(f"  {resp.status_code}: {len(resp.json())} keys")

    print("\n=== Rotate key ===")
    key_id = key_data["id"]
    resp = client.post(f"/keys/{key_id}/rotate")
    print(f"  {resp.status_code}: {resp.json()['message']}")

    print("\n=== Old key no longer works ===")
    resp = client.get("/api/data", headers={"X-API-Key": api_key})
    print(f"  {resp.status_code}: {resp.json()}")

    client.close()

if __name__ == "__main__":
    main()
