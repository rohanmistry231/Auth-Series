const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";

async function request(method: string, path: string, body?: any, apiKey?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) headers["X-API-Key"] = apiKey;
  const resp = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: resp.status, body: await resp.json() };
}

async function main() {
  console.log("=== Create API key ===");
  const created = await request("POST", "/keys", { name: "My App Key", scopes: ["read", "write"], expires_in_days: 30 });
  const apiKey = created.body.key;
  console.log(`  Created: ${created.body.prefix}...${created.body.key_suffix}`);

  console.log("\n=== Public endpoint ===");
  const pub = await request("GET", "/api/public");
  console.log(`  ${pub.status}:`, pub.body);

  console.log("\n=== Protected (valid key) ===");
  const prot = await request("GET", "/api/data", undefined, apiKey);
  console.log(`  ${prot.status}:`, prot.body);

  console.log("\n=== Protected (invalid key) ===");
  const bad = await request("GET", "/api/data", undefined, "enter_api_key_here");
  console.log(`  ${bad.status}:`, bad.body);

  console.log("\n=== Admin (no admin scope) ===");
  const admin = await request("GET", "/api/admin", undefined, apiKey);
  console.log(`  ${admin.status}:`, admin.body);

  console.log("\n=== Create admin key ===");
  const adminKey = (await request("POST", "/keys", { name: "Admin Key", scopes: ["read", "write", "admin"] })).body.key;

  console.log("\n=== Admin (with admin scope) ===");
  const adminOk = await request("GET", "/api/admin", undefined, adminKey);
  console.log(`  ${adminOk.status}:`, adminOk.body);

  console.log("\n=== Rotate key ===");
  const rot = await request("POST", `/keys/${created.body.id}/rotate`);
  console.log(`  ${rot.status}:`, rot.body.message);

  console.log("\n=== Old key fails ===");
  const old = await request("GET", "/api/data", undefined, apiKey);
  console.log(`  ${old.status}:`, old.body);
}

main().catch(console.error);
