"""CAS client — simulates the browser dance through login + ticket validation."""

import os

import httpx

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")
SERVICE_URL = f"{BASE_URL}/protected"


def main():
    client = httpx.Client(base_url=BASE_URL, follow_redirects=False)

    print("=== Step 1: Visit protected resource ===")
    resp = client.get("/protected")
    print(f"  Status: {resp.status_code}")
    location = resp.headers.get("location", "")
    if location:
        print(f"  Redirected to CAS: {location[:80]}...")
    else:
        print("  Already authenticated?")
        return

    print("\n=== Step 2: Follow redirect to CAS login ===")
    resp = client.get(location)
    print(f"  Status: {resp.status_code}")
    assert resp.status_code == 200
    print("  ✅ CAS login page loaded")

    print("\n=== Step 3: Submit login form ===")
    resp = client.post("/login", data={"service": SERVICE_URL, "username": "alice", "password": "password-alice"}, follow_redirects=False)
    location = resp.headers.get("location", "")
    print(f"  Redirected to: {location[:80]}...")
    assert "ticket=ST-" in location
    ticket = location.split("ticket=")[1]
    print(f"  Ticket: {ticket[:24]}...")

    print("\n=== Step 4: Follow redirect back to app with ticket ===")
    resp = client.get(location, follow_redirects=True)
    print(f"  Status: {resp.status_code}")
    if resp.status_code == 200:
        # Check if there's a Set-Cookie for session
        print("  ✅ Authenticated via CAS!")
    else:
        print(f"  ❌ Failed: {resp.text}")

    print("\n=== Step 5: Replay ticket (should fail) ===")
    resp = client.get(f"/protected?ticket={ticket}")
    resp_text = resp.text
    if "Failed" in resp_text or resp.status_code in (302, 307):
        print("  ✅ Replay correctly blocked")
    else:
        print(f"  Status: {resp.status_code}")

    client.close()


if __name__ == "__main__":
    main()
