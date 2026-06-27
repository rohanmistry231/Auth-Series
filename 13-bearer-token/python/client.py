"""Bearer Token client — login, access protected, introspect, revoke."""

import os

import httpx

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")


def main():
    client = httpx.Client(base_url=BASE_URL)

    print("=== Step 1: Login (alice) ===")
    resp = client.post("/login", data={"username": "alice", "password": os.environ.get("ALICE_PASSWORD", "password-alice")})
    data = resp.json()
    token = data["access_token"]
    print(f"  Token: {token[:32]}...")
    print(f"  Scopes: {data['scope']}")
    print(f"  Expires in: {data['expires_in']}s")

    print("\n=== Step 2: Access Protected (query param) ===")
    resp = client.get(f"/protected?token={token}")
    if resp.status_code == 200:
        print(f"  ✅ {resp.json()['message']}")
    else:
        print(f"  ❌ {resp.json()['detail']}")

    print("\n=== Step 3: Access Protected (Authorization header) ===")
    resp = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    if resp.status_code == 200:
        print(f"  ✅ {resp.json()['message']}")
    else:
        print(f"  ❌ {resp.json()['detail']}")

    print("\n=== Step 4: Introspect ===")
    resp = client.post("/introspect", data={"token": token})
    data = resp.json()
    print(f"  Active: {data['active']}")
    print(f"  Sub: {data.get('sub', 'N/A')}")

    print("\n=== Step 5: Revoke ===")
    resp = client.post("/revoke", data={"token": token})
    print(f"  Revoked: {resp.json()['result']}")

    print("\n=== Step 6: Try revoked token ===")
    resp = client.get(f"/protected?token={token}")
    if resp.status_code == 401:
        print(f"  ✅ Correctly blocked: {resp.json()['detail']}")

    print("\n=== Step 7: Missing header ===")
    resp = client.get("/protected")
    if resp.status_code == 401:
        print(f"  ✅ {resp.json()['detail']}")

    client.close()


if __name__ == "__main__":
    main()
