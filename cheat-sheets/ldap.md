# LDAP — Cheat Sheet

## Directory Structure

```
dc=example,dc=com
├── cn=admin,dc=example,dc=com   (admin account)
├── ou=users
│   ├── uid=jdoe,ou=users        (user entries)
│   └── uid=jsmith,ou=users
└── ou=groups
    └── cn=admins,ou=groups      (group entries)
```

## Common Filters

| Filter | Finds |
|--------|-------|
| `(uid=jdoe)` | User by username |
| `(&(objectClass=user)(mail=jdoe@co.com))` | User by email |
| `(|(uid=jdoe)(mail=jdoe@co.com))` | User by username OR email |
| `(memberOf=cn=admins,ou=groups,dc=example,dc=com)` | Group members |

## Auth Flow (BIND)

```
1. Connect to LDAP (ldap[s]://host:389/636)
2. BIND with service account (search-only)
3. Search for user: (&(uid=user)(objectClass=person))
4. Get user DN: uid=jdoe,ou=users,dc=example,dc=com
5. BIND with user DN + password
6. Success/failure → UNBIND
```

## Security

| Practice | Why |
|----------|-----|
| Always LDAPS (636) | Credentials in plaintext otherwise |
| Escape filters (use library API) | Prevent LDAP injection |
| Minimal service account scopes | Limit blast radius |
| Connection pooling | LDAP BIND is synchronous |
| Timeout on binds | Prevent hanging connections |
