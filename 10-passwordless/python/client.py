"""Magic Link client — requests and verifies a magic link."""

import os

import httpx

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")


def main():
    client = httpx.Client(base_url=BASE_URL)

    email = "alice@example.com"

    print("=== Step 1: Request Magic Link ===")
    resp = client.post("/auth/request", data={"email": email})
    data = resp.json()
    print(f"  {data['message']}")
    print(f"  Expires in: {data['expires_in']}s")
    print(f"  Magic URL (copy-paste in browser):")
    print(f"    {data['magic_url']}")

    print("\n=== Step 2: Verify Magic Link ===")
    magic_url = data["magic_url"]
    resp = client.get(magic_url)
    print(f"  Status: {resp.status_code}")
    if resp.status_code == 200:
        print("  ✅ Successfully authenticated!")
    else:
        print(f"  ❌ Failed: {resp.text}")

    print("\n=== Step 3: Replay token (should fail) ===")
    resp = client.get(magic_url)
    if resp.status_code == 401:
        print("  ✅ Replay correctly blocked")
    else:
        print(f"  Unexpected: {resp.status_code}")

    client.close()


if __name__ == "__main__":
    main()
