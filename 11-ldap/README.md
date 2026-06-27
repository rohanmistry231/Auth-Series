# 11 — LDAP / Active Directory

LDAP (Lightweight Directory Access Protocol, RFC 4511) is a protocol for accessing distributed directory services. Active Directory is Microsoft's implementation, combining LDAP, Kerberos, and DNS.

---

## 1. Directory Information Tree (DIT)

```
dc=example,dc=com                    Root domain
│
├── ou=Users                         Container for user objects
│   ├── cn=John Doe                  User object
│   │   ├── uid=jdoe                 Login name
│   │   ├── mail=jdoe@example.com
│   │   ├── userPassword={SSHA}...   Password hash
│   │   ├── memberOf=cn=Admins,...
│   │   └── objectClass=inetOrgPerson
│   ├── cn=Jane Smith
│   └── cn=Bob Wilson
│
├── ou=Groups                        Container for group objects
│   ├── cn=Admins
│   │   ├── member=cn=John Doe,...
│   │   └── objectClass=groupOfNames
│   ├── cn=Developers
│   └── cn=Viewers
│
├── ou=Devices
│   ├── cn=Server-01
│   └── cn=Printer-Lobby3
│
└── ou=ServiceAccounts
    ├── cn=svc-api
    └── cn=svc-monitoring
```

---

## 2. LDAP Operations (Complete)

| Operation | RFC | Description | When Used |
|-----------|-----|-------------|-----------|
| **Bind** | 4513 §3 | Authenticate to directory | Every interaction |
| **Search** | 4511 §4.5 | Query entries matching filter | Look up user, verify group membership |
| **Compare** | 4511 §4.7 | Check attribute value | "Is user member of group X?" |
| **Add** | 4511 §4.6 | Create new entry | Provisioning new users |
| **Modify** | 4511 §4.6 | Change attribute values | Update email, reset password |
| **ModDN** | 4511 §4.8 | Rename / move entry | Move user between OUs |
| **Delete** | 4511 §4.7 | Remove entry | Deprovisioning |
| **Unbind** | 4511 §4.3 | Close connection | Done |

---

## 3. LDAP Authentication Flow (BIND)

```
Application                     LDAP Server
     │                               │
     │  1. TCP Connect (389/636)     │
     │──────────────────────────────>│
     │                               │
     │  2. START TLS (for 389)       │
     │──────────────────────────────>│
     │                               │
     │  3. BIND (service account)    │
     │  dn: cn=svc-api,ou=Service.. │
     │  password: ****               │
     │──────────────────────────────>│
     │  4. BIND Response: Success    │
     │<──────────────────────────────│
     │                               │
     │  5. SEARCH for user           │
     │  base: ou=Users,dc=example..  │
     │  filter: (&(uid=jdoe)        │
     │          (objectClass=user))  │
     │──────────────────────────────>│
     │  6. Search Result Entry       │
     │  dn: cn=John Doe,ou=Users... │
     │<──────────────────────────────│
     │                               │
     │  7. BIND (user credentials)   │
     │  dn: cn=John Doe,ou=Users... │
     │  password: user_input         │
     │──────────────────────────────>│
     │  8. BIND Response: Success    │
     │<──────────────────────────────│
     │                               │
     │  9. UNBIND                    │
     │──────────────────────────────>│
```

---

## 4. LDAP Filter Grammar

```
Filter        ::= "(" FilterComp ")"
FilterComp    ::= And | Or | Not | Item
And           ::= "&" FilterList
Or            ::= "|" FilterList
Not           ::= "!" Filter
FilterList    ::= Filter+
Item          ::= Simple | Present | Substring | Extensible
Simple        ::= Attribute "=" " " AttributeValue " "
Present       ::= Attribute "=*"
Substring     ::= Attribute "=" [Initial] Any Final
Initial       ::= [""] Value
Any           ::= "*" (Value "*")*
Final         ::= Value ""

Examples:
  (&(objectClass=user)(uid=jdoe))
  (|(uid=jdoe)(mail=jdoe@example.com))
  (&(uid=jdoe)(!(accountStatus=disabled)))
  (cn=John*)
```

---

## 5. Active Directory Specifics

| AD Concept | LDAP Equivalent | Notes |
|------------|----------------|-------|
| **sAMAccountName** | `uid` | Pre-Windows 2000 login (`DOMAIN\user`) |
| **userPrincipalName** | `mail` | `user@domain.com` |
| **distinguishedName** | `dn` | Full path in DIT |
| **memberOf** | `memberOf` | Multi-valued, computed attribute |
| **objectSid** | `uidNumber` | Security Identifier (SID) |
| **Kerberos** | — | Integrated Windows auth |
| **GPO** | — | Applied via LDAP path link |

---

## 6. Code Examples

### Java (Spring LDAP)

```java
// build.gradle: implementation 'org.springframework.ldap:spring-ldap-core'

@Repository
public class LdapUserRepository {

    @Autowired
    private LdapTemplate ldapTemplate;

    public User authenticate(String username, String password) {
        try {
            // Step 1: Search for user
            List<String> dns = ldapTemplate.search(
                query()
                    .base("ou=Users")
                    .filter("(&(uid={0})(objectClass=user))", username)
                    .attributes("dn"),
                (Attributes attrs) -> attrs.get("distinguishedName").toString()
            );

            if (dns.isEmpty()) {
                throw new AuthenticationException("User not found");
            }

            // Step 2: Attempt bind with user credentials
            LdapContextSource ctx = new LdapContextSource();
            ctx.setUrl("ldaps://ldap.example.com:636");
            ctx.setUserDn(dns.get(0));
            ctx.setPassword(password);
            ctx.afterPropertiesSet();

            ctx.getContext("", "");  // throws if invalid

            // Step 3: Fetch user details
            return ldapTemplate.searchForObject(
                query()
                    .base("ou=Users")
                    .filter("(uid={0})", username)
                    .attributes("cn", "mail", "memberOf"),
                (Attributes attrs) -> User.builder()
                    .dn(dns.get(0))
                    .cn((String) attrs.get("cn").get())
                    .mail((String) attrs.get("mail").get())
                    .build()
            );
        } catch (Exception e) {
            throw new AuthenticationException("LDAP authentication failed", e);
        }
    }
}
```

### Python (ldap3)

```python
import ldap3

server = ldap3.Server("ldaps://ldap.example.com:636", use_ssl=True)

def authenticate_user(username: str, password: str) -> dict | None:
    with ldap3.Connection(server, auto_bind=True) as conn:
        # Search for user DN
        conn.search(
            search_base="ou=Users,dc=example,dc=com",
            search_filter=f"(&(uid={username})(objectClass=user))",
            attributes=["dn", "cn", "mail", "memberOf"],
        )

        if len(conn.entries) == 0:
            return None

        user_dn = conn.entries[0].entry_dn

        # Attempt bind with user credentials
        if conn.rebind(user=user_dn, password=password):
            return {
                "dn": user_dn,
                "cn": str(conn.entries[0].cn),
                "mail": str(conn.entries[0].mail),
            }
        return None
```

### TypeScript (ldapjs)

```typescript
import ldap from 'ldapjs';

const client = ldap.createClient({ url: 'ldaps://ldap.example.com:636' });

async function authenticateUser(username: string, password: string) {
  // Bind with service account
  await bindAsync(client, 'cn=svc-api,ou=ServiceAccounts,dc=example,dc=com',
    process.env.LDAP_SERVICE_PASSWORD!);

  // Search for user
  const entries = await searchAsync(client, 'ou=Users,dc=example,dc=com', {
    filter: `(&(uid=${username})(objectClass=user))`,
    scope: 'sub',
    attributes: ['dn', 'cn', 'mail'],
  });

  if (entries.length === 0) throw new Error('User not found');

  // Rebind with user credentials
  try {
    await bindAsync(client, entries[0].dn, password);
    return entries[0];
  } catch {
    throw new Error('Invalid password');
  }
}
```

---

## 7. References

- [RFC 4511 — LDAP: The Protocol](https://datatracker.ietf.org/doc/html/rfc4511)
- [RFC 4513 — LDAP Authentication Methods](https://datatracker.ietf.org/doc/html/rfc4513)
- [Microsoft AD DS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/)
- [OWASP LDAP Injection](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
