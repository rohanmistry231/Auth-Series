"""LDAP Authentication Server.

Authenticates users against an LDAP directory via BIND.
Issues JWT sessions on successful auth.

Uses the public test LDAP server by default:
  Host: ldap.forumsys.com:389
  Bind DN: cn=read-only-admin,dc=example,dc=com / password
  Users: newton|galileo|einstein|... (password = username)
"""

import os
import uuid

import ldap3
import uvicorn
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse

app = FastAPI(title="LDAP Auth Server")

LDAP_HOST = os.environ.get("LDAP_HOST", "ldap.forumsys.com")
LDAP_PORT = int(os.environ.get("LDAP_PORT", "389"))
LDAP_USE_SSL = os.environ.get("LDAP_USE_SSL", "false").lower() == "true"
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=example,dc=com")
LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "cn=read-only-admin,dc=example,dc=com")
LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "password")
LDAP_USER_FILTER = os.environ.get("LDAP_USER_FILTER", "(&(uid={username})(objectClass=person))")

sessions: dict[str, dict] = {}


def get_ldap_connection() -> ldap3.Connection:
    server = ldap3.Server(LDAP_HOST, port=LDAP_PORT, use_ssl=LDAP_USE_SSL, get_info=ldap3.ALL)
    conn = ldap3.Connection(server, auto_bind=True)
    return conn


@app.get("/")
def index():
    return HTMLResponse("""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>LDAP Auth Demo</h2>
<p>Connect: <code>ldap://ldap.forumsys.com:389</code></p>
<p>Test users: <code>newton</code>, <code>galileo</code>, <code>einstein</code> (pwd = username)</p>
<form method="post" action="/login">
<p><label>Username: <input name="username" value="newton"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">LDAP Login</button></p>
</form>
<hr>
<form method="post" action="/search">
<p><label>Search filter: <input name="filter" value="(objectClass=person)"></label></p>
<p><button type="submit">Search LDAP</button></p>
</form>
</body></html>""")


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    conn = get_ldap_connection()
    try:
        conn.bind(LDAP_BIND_DN, LDAP_BIND_PASSWORD)
    except Exception:
        raise HTTPException(status_code=500, detail="LDAP service bind failed")

    search_filter = LDAP_USER_FILTER.replace("{username}", username)
    conn.search(search_base=LDAP_BASE_DN, search_filter=search_filter, attributes=[ldap3.ALL_ATTRIBUTES])

    if len(conn.entries) == 0:
        raise HTTPException(status_code=401, detail="User not found")

    entry = conn.entries[0]
    user_dn = entry.entry_dn

    try:
        user_conn = ldap3.Connection(
            ldap3.Server(LDAP_HOST, port=LDAP_PORT, use_ssl=LDAP_USE_SSL),
            user=user_dn,
            password=password,
            auto_bind=True,
        )
        user_conn.unbind()
    except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
        raise HTTPException(status_code=401, detail="Invalid password")

    session_id = str(uuid.uuid4())
    attrs = {attr: str(entry[attr].value) for attr in entry.entry_attributes}
    sessions[session_id] = {"dn": user_dn, "username": username, "attrs": attrs}

    return {
        "session_id": session_id,
        "dn": user_dn,
        "username": username,
        "attributes": attrs,
    }


@app.post("/search")
def search(filter: str = Form(...)):
    conn = get_ldap_connection()
    try:
        conn.bind(LDAP_BIND_DN, LDAP_BIND_PASSWORD)
    except Exception:
        raise HTTPException(status_code=500, detail="LDAP service bind failed")

    try:
        conn.search(search_base=LDAP_BASE_DN, search_filter=filter, attributes=[ldap3.ALL_ATTRIBUTES])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Search failed: {e}")

    results = []
    for entry in conn.entries:
        attrs = {attr: str(entry[attr].value) for attr in entry.entry_attributes}
        results.append({"dn": entry.entry_dn, "attributes": attrs})

    return {"count": len(results), "entries": results}


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
