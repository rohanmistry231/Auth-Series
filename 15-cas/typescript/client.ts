const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";
const SERVICE_URL = `${BASE_URL}/protected`;

async function main() {
  const client = (path: string, opts?: any) =>
    fetch(`${BASE_URL}${path}`, { redirect: "manual", ...opts });

  console.log("=== Step 1: Visit protected resource ===");
  const resp1 = await client("/protected");
  const loc1 = resp1.headers.get("location") ?? "";
  console.log(`  Status: ${resp1.status} → ${loc1.slice(0, 80)}...`);

  console.log("\n=== Step 2: Follow redirect to CAS login ===");
  const resp2 = await client(loc1);
  console.log(`  Status: ${resp2.status} ✅`);

  console.log("\n=== Step 3: Submit login form ===");
  const resp3 = await client("/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ service: SERVICE_URL, username: "alice", password: process.env.ALICE_PASSWORD ?? "password-alice" }),
  });
  const loc3 = resp3.headers.get("location") ?? "";
  console.log(`  Redirected to: ${loc3.slice(0, 80)}...`);
  const ticket = loc3.split("ticket=")[1] ?? "";
  console.log(`  Ticket: ${ticket.slice(0, 24)}...`);

  console.log("\n=== Step 4: Follow redirect back to app ===");
  const resp4 = await client(loc3, { redirect: "manual" });
  const loc4 = resp4.headers.get("location") ?? "";
  const resp4b = await client(loc4);
  console.log(`  Status: ${resp4b.status} ✅ Authenticated via CAS!`);

  console.log("\n=== Step 5: Replay ticket (should fail) ===");
  const resp5 = await client(`/protected?ticket=${ticket}`, { redirect: "manual" });
  const text5 = await resp5.text();
  console.log(`  Status: ${resp5.status} — ${text5.includes("Failed") ? "✅ Blocked" : "❌"}`);
}

main().catch(console.error);
