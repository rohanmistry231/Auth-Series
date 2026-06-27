const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";

async function postJson(path: string, body: Record<string, string>) {
  const resp = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body),
  });
  return { status: resp.status, body: await resp.json() };
}

async function main() {
  console.log("=== Login: newton / newton ===");
  const login = await postJson("/login", { username: "newton", password: "newton" });
  if (login.status === 200) {
    console.log(`  ✅ Logged in as ${login.body.username}`);
    console.log(`  DN: ${login.body.dn}`);
    console.log(`  Session: ${(login.body.session_id as string).slice(0, 16)}...`);
    const attrs = login.body.attributes as Record<string, string>;
    console.log(`  cn: ${attrs["cn"] ?? "N/A"}`);
    console.log(`  mail: ${attrs["mail"] ?? "N/A"}`);
  } else {
    console.log(`  ❌ ${login.body.error}`);
  }

  console.log("\n=== Login: wrong password ===");
  const bad = await postJson("/login", { username: "newton", password: "wrong" });
  console.log(`  ${bad.status} - ${bad.body.error}`);

  console.log("\n=== Search: all persons ===");
  const search = await postJson("/search", { filter: "(objectClass=person)" });
  if (search.status === 200) {
    console.log(`  Found ${search.body.count} entries:`);
    for (const entry of (search.body.entries as any[]).slice(0, 5)) {
      console.log(`    - ${entry.dn}`);
    }
    if (search.body.count > 5) console.log(`    ... and ${search.body.count - 5} more`);
  }
}

main().catch(console.error);
