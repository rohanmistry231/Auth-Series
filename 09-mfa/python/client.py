"""MFA client — demonstrates setup, verify, login with TOTP."""

import os

import httpx

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")


def main():
    client = httpx.Client(base_url=BASE_URL)
    username = "alice"
    password = os.environ.get("ALICE_PASSWORD", "password-alice")

    print("=== Step 1: Setup MFA ===")
    resp = client.post("/setup", data={"username": username, "password": password})
    data = resp.json()
    print(f"  Secret: {data['secret']}")
    print(f"  QR URI: {data['qr_uri']}")
    print(f"  IMPORTANT: Add this secret to an authenticator app (e.g. Google Authenticator)")

    print("\n=== Step 2: Verify TOTP ===")
    import pyotp
    totp = pyotp.TOTP(data["secret"])
    current_code = totp.now()
    print(f"  Current TOTP code: {current_code}")

    resp = client.post("/mfa/verify", data={"username": username, "totp": current_code})
    data = resp.json()
    print(f"  MFA enabled: {data['message']}")
    print(f"  Backup codes: {data['backup_codes']}")

    print("\n=== Step 3: Login with MFA ===")
    current_code = totp.now()
    resp = client.post("/login", data={"username": username, "password": password, "totp": current_code})
    data = resp.json()
    print(f"  {data['message']}")
    print(f"  Token: {data['access_token'][:20]}...")

    print("\n=== Step 4: Login with wrong TOTP (should fail) ===")
    resp = client.post("/login", data={"username": username, "password": password, "totp": "000000"})
    print(f"  Status: {resp.status_code} - {resp.json()['detail']}")

    print("\n=== Step 5: Recovery login ===")
    backup_code = totp.secret  # just placeholder
    import secrets as _s
    bc = data.get("backup_codes", [None])[0]
    if bc:
        resp = client.post("/recovery", data={"username": username, "backup_code": bc})
        data2 = resp.json()
        print(f"  {data2['message']}")
        print(f"  Codes remaining: {data2['codes_remaining']}")

    client.close()


if __name__ == "__main__":
    main()
