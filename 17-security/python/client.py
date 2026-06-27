"""Security client — demonstrates rate limiting, audit logging, CSRF."""

import os

import httpx

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")


def main():
    client = httpx.Client(base_url=BASE_URL)

    print("=== Check Security Headers ===")
    resp = client.get("/")
    for header in ["strict-transport-security", "x-content-type-options", "x-frame-options"]:
        print(f"  {header}: {resp.headers.get(header, '❌ MISSING')}")

    print("\n=== Login (success) ===")
    resp = client.post("/login", data={"username": "alice", "password": os.environ.get("ALICE_PASSWORD", "password-alice")})
    print(f"  Status: {resp.status_code}")
    if resp.status_code == 200:
        print("  ✅ Logged in")
    else:
        print(f"  ❌ {resp.text}")

    print("\n=== Login (wrong password, should be rate limited or fail) ===")
    for i in range(7):
        resp = client.post("/login", data={"username": "alice", "password": "wrong"})
        if resp.status_code == 429:
            print(f"  ✅ Rate limited on attempt {i + 1}")
            break
        elif resp.status_code == 401:
            print(f"  Attempt {i + 1}: 401 (expected)")
        else:
            print(f"  Attempt {i + 1}: {resp.status_code} — {resp.text}")

    print("\n=== View Audit Log ===")
    resp = client.get("/audit-log")
    if "LOGIN" in resp.text:
        print("  ✅ Audit log entries found")
    print(f"  Log page loaded ({len(resp.text)} bytes)")

    client.close()


if __name__ == "__main__":
    main()
