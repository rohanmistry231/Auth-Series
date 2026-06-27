"""Social Login client — requests auth, follows redirects, verifies session."""

import os

import httpx

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")


def main():
    client = httpx.Client(base_url=BASE_URL, follow_redirects=False)

    print("=== Step 1: Visit home page ===")
    resp = client.get("/")
    assert resp.status_code == 200
    print("  ✅ Home page loaded")

    print("\n=== Step 2: Click 'Sign in with Google' ===")
    resp = client.get("/auth/google/login", follow_redirects=False)
    print(f"  Redirected to: {resp.headers.get('location', 'N/A')[:80]}...")
    assert resp.status_code in (302, 307)

    print("\n=== Step 3: Follow redirect to mock provider ===")
    resp = client.get(resp.headers["location"])
    print(f"  Status: {resp.status_code}")
    assert resp.status_code == 200
    assert "Google" in resp.text
    print("  ✅ Consent page loaded")

    print("\n=== Step 4: Allow access ===")
    # Find the form action
    import re
    match = re.search(r'action="([^"]+)"', resp.text)
    action = match.group(1) if match else "/mock/google/consent"
    # Extract hidden fields
    client_id_match = re.search(r'name="client_id" value="([^"]+)"', resp.text)
    redirect_match = re.search(r'name="redirect_uri" value="([^"]+)"', resp.text)
    client_id = client_id_match.group(1) if client_id_match else "google-client-id"
    redirect_uri = redirect_match.group(1) if redirect_match else "http://127.0.0.1:8000/auth/google/callback"

    resp = client.post(action, data={
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "action": "allow",
    }, follow_redirects=False)
    print(f"  Redirected to: {resp.headers.get('location', 'N/A')[:80]}...")
    assert resp.status_code in (302, 307)

    print("\n=== Step 5: Follow callback redirect ===")
    resp = client.get(resp.headers["location"], follow_redirects=True)
    print(f"  Final URL: {resp.url}")
    assert resp.status_code == 200
    assert "Dashboard" in resp.text
    print("  ✅ Successfully signed in with Google!")

    client.close()


if __name__ == "__main__":
    main()
