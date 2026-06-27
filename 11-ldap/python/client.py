"""LDAP Auth client — login and search via the server API."""

import os

import httpx

BASE_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8000")


def main():
    client = httpx.Client(base_url=BASE_URL)

    print("=== Login: newton / newton ===")
    resp = client.post("/login", data={"username": "newton", "password": "newton"})
    if resp.status_code == 200:
        data = resp.json()
        print(f"  ✅ Logged in as {data['username']}")
        print(f"  DN: {data['dn']}")
        print(f"  Session: {data['session_id'][:16]}...")
        attrs = data["attributes"]
        print(f"  cn: {attrs.get('cn', 'N/A')}")
        print(f"  mail: {attrs.get('mail', 'N/A')}")
        print(f"  uid: {attrs.get('uid', 'N/A')}")
    else:
        print(f"  ❌ {resp.json()['detail']}")

    print("\n=== Login: wrong password ===")
    resp = client.post("/login", data={"username": "newton", "password": "wrong"})
    print(f"  Status: {resp.status_code} - {resp.json()['detail']}")

    print("\n=== Search: all persons ===")
    resp = client.post("/search", data={"filter": "(objectClass=person)"})
    if resp.status_code == 200:
        data = resp.json()
        print(f"  Found {data['count']} entries:")
        for entry in data["entries"][:5]:
            print(f"    - {entry['dn']}")
        if data["count"] > 5:
            print(f"    ... and {data['count'] - 5} more")
    else:
        print(f"  ❌ {resp.json()['detail']}")

    client.close()


if __name__ == "__main__":
    main()
