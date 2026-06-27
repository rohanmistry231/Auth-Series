const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";
const USERNAME = process.env.AUTH_USERNAME ?? "alice";
const PASSWORD = process.env.AUTH_PASSWORD ?? "password-alice";

const tokens: Record<string, string> = {};

async function request(
  path: string,
  options: { method?: string; body?: Record<string, unknown>; token?: string } = {},
) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (options.token) {
    headers["Authorization"] = `Bearer ${options.token}`;
  }

  const resp = await fetch(`${BASE_URL}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const body = await resp.json();
  return { status: resp.status, body };
}

async function main() {
  console.log("=== 1. Login ===");
  const login = await request("/login", {
    method: "POST",
    body: { username: USERNAME, password: PASSWORD },
  });
  const d = login.body as Record<string, string>;
  tokens.access = d.access_token;
  tokens.refresh = d.refresh_token;
  console.log(login.status, {
    access_token: tokens.access.slice(0, 30) + "...",
    refresh_token: tokens.refresh.slice(0, 30) + "...",
  });

  console.log("\n=== 2. Access protected endpoint ===");
  const prot = await request("/protected", { token: tokens.access });
  console.log(prot.status, prot.body);

  console.log("\n=== 3. JWKS endpoint ===");
  const jwks = await request("/.well-known/jwks.json");
  console.log(jwks.status, jwks.body);

  console.log("\n=== 4. Refresh tokens ===");
  const ref = await request("/refresh", {
    method: "POST",
    body: { refresh_token: tokens.refresh },
  });
  const rd = ref.body as Record<string, string>;
  console.log(ref.status, {
    access_token: rd.access_token?.slice(0, 30) + "...",
    refresh_token: rd.refresh_token?.slice(0, 30) + "...",
  });
  tokens.access = rd.access_token;
  tokens.refresh = rd.refresh_token;

  console.log("\n=== 5. Protected with new access token ===");
  const prot2 = await request("/protected", { token: tokens.access });
  console.log(prot2.status, prot2.body);

  console.log("\n=== 6. Try revoked refresh token ===");
  const badRef = await request("/refresh", {
    method: "POST",
    body: { refresh_token: "some-revoked-token" },
  });
  console.log(badRef.status, badRef.body);
}

main().catch(console.error);
