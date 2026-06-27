const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";

async function postForm(path: string, body: Record<string, string>) {
  const resp = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body),
  });
  return { status: resp.status, body: await resp.json() };
}

async function get(path: string, headers?: Record<string, string>) {
  const resp = await fetch(`${BASE_URL}${path}`, { headers });
  return { status: resp.status, body: await resp.json() };
}

async function main() {
  const password = process.env.ALICE_PASSWORD ?? "password-alice";

  console.log("=== Step 1: Login (alice) ===");
  const login = await postForm("/login", { username: "alice", password });
  const token = login.body.access_token as string;
  console.log(`  Token: ${token.slice(0, 32)}...`);
  console.log(`  Scopes: ${login.body.scope}`);

  console.log("\n=== Step 2: Access Protected (query param) ===");
  const prot = await get(`/protected?token=${token}`);
  console.log(`  Status: ${prot.status} - ${prot.status === 200 ? "✅ " + prot.body.message : "❌"}`);

  console.log("\n=== Step 3: Access Protected (header) ===");
  const prot2 = await get("/protected", { Authorization: `Bearer ${token}` });
  console.log(`  Status: ${prot2.status} - ${prot2.status === 200 ? "✅ " + prot2.body.message : "❌"}`);

  console.log("\n=== Step 4: Introspect ===");
  const intro = await postForm("/introspect", { token });
  console.log(`  Active: ${intro.body.active}  Sub: ${intro.body.sub ?? "N/A"}`);

  console.log("\n=== Step 5: Revoke ===");
  const rev = await postForm("/revoke", { token });
  console.log(`  Result: ${rev.body.result}`);

  console.log("\n=== Step 6: Try revoked token ===");
  const prot3 = await get(`/protected?token=${token}`);
  console.log(`  Status: ${prot3.status} - ${prot3.status === 401 ? "✅ Blocked" : "❌"}`);

  console.log("\n=== Step 7: Missing header ===");
  const prot4 = await get("/protected");
  console.log(`  Status: ${prot4.status} - ${prot4.status === 401 ? "✅ Blocked" : "❌"}`);
}

main().catch(console.error);
