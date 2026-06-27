const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";

async function main() {
  console.log("=== Check Security Headers ===");
  const resp = await fetch(BASE_URL + "/");
  for (const h of ["strict-transport-security", "x-content-type-options", "x-frame-options"]) {
    console.log(`  ${h}: ${resp.headers.get(h) ?? "❌ MISSING"}`);
  }

  console.log("\n=== Login (success) ===");
  const login = await fetch(BASE_URL + "/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username: "alice", password: process.env.ALICE_PASSWORD ?? "password-alice" }),
    redirect: "manual",
  });
  console.log(`  Status: ${login.status} — ${login.status === 200 ? "✅" : "❌"}`);

  console.log("\n=== Rate limit test ===");
  for (let i = 0; i < 7; i++) {
    const r = await fetch(BASE_URL + "/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username: "alice", password: "wrong" }),
    });
    if (r.status === 429) { console.log(`  ✅ Rate limited on attempt ${i + 1}`); break; }
    if (r.status !== 401) console.log(`  Attempt ${i + 1}: ${r.status}`);
  }

  console.log("\n=== Audit Log ===");
  const audit = await fetch(BASE_URL + "/audit-log");
  const text = await audit.text();
  console.log(`  ${text.includes("LOGIN") ? "✅ Entries found" : "No entries"} (${text.length}b)`);
}

main().catch(console.error);
