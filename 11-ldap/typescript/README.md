# TypeScript — LDAP Auth

## Requirements

- Node.js 18+
- `npm install ldapjs`

## Run the Server

```bash
export LDAP_HOST=ldap.forumsys.com
export LDAP_PORT=389
export LDAP_BASE_DN=dc=example,dc=com

npx tsx server.ts
```

## Run the Client

```bash
npx tsx client.ts
```

## Configuration

| Env Var | Default | Purpose |
|---------|---------|---------|
| `LDAP_HOST` | `ldap.forumsys.com` | LDAP server host |
| `LDAP_PORT` | `389` | LDAP port |
| `LDAP_BASE_DN` | `dc=example,dc=com` | Search base |
| `LDAP_BIND_DN` | `cn=read-only-admin,dc=example,dc=com` | Service bind DN |
| `LDAP_BIND_PASSWORD` | `password` | Service bind password |
| `LDAP_USER_FILTER` | `(&(uid={username})(objectClass=person))` | User search filter |

## Files

| File | Purpose |
|------|---------|
| `server.ts` | Node.js LDAP auth server |
| `client.ts` | Demo login + search client |
