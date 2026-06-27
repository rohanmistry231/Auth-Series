"""Auth Patterns client — demonstrates BFF, token rotation, and gateway."""

import os

import httpx

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")


def demo_bff(client: httpx.Client):
    print("=== BFF Pattern ===")
    resp = client.post("/bff/login", data={"username": "alice", "password": os.environ.get("ALICE_PASSWORD", "password-alice")})
    data = resp.json()
    print(f"  Login: {data['message']}")
    session_id = resp.cookies.get("session_id")

    resp = client.get("/bff/api/data", cookies={"session_id": session_id})
    if resp.status_code == 200:
        print(f"  API: {resp.json()['message']}")
    else:
        print(f"  API failed: {resp.status_code}")


def demo_token_rotation(client: httpx.Client):
    print("\n=== Token Rotation ===")
    resp = client.post("/token/issue", data={"username": "alice", "password": os.environ.get("ALICE_PASSWORD", "password-alice")})
    tokens = resp.json()
    rt = tokens["refresh_token"]
    print(f"  Issued: access={tokens['access_token'][:16]}..., refresh={rt[:16]}...")

    resp = client.post("/token/refresh", data={"refresh_token": rt})
    tokens2 = resp.json()
    rt2 = tokens2["refresh_token"]
    print(f"  Rotated: new access={tokens2['access_token'][:16]}..., new refresh={rt2[:16]}...")

    # Replay old token — should be detected as theft
    resp = client.post("/token/refresh", data={"refresh_token": rt})
    print(f"  Replay old token: {resp.status_code} - {resp.json()['detail']}")

    # New token now also revoked (same family)
    resp = client.post("/token/refresh", data={"refresh_token": rt2})
    print(f"  Try new token after theft: {resp.status_code} - {resp.json()['detail']}")


def demo_gateway(client: httpx.Client):
    print("\n=== Gateway Auth ===")
    resp = client.post("/gateway/token", data={"username": "alice", "password": os.environ.get("ALICE_PASSWORD", "password-alice")})
    token = resp.json()["access_token"]
    print(f"  Gateway token: {token[:16]}...")

    resp = client.get("/gateway/api/resource", headers={"Authorization": f"Bearer {token}"})
    print(f"  Resource: {resp.json()['message']}")

    resp = client.get("/gateway/api/resource", headers={"Authorization": "Bearer invalid"})
    print(f"  Invalid token: {resp.status_code}")


def main():
    client = httpx.Client(base_url=BASE_URL)
    demo_bff(client)
    demo_token_rotation(client)
    demo_gateway(client)
    client.close()


if __name__ == "__main__":
    main()
