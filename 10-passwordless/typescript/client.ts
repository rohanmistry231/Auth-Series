const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";

async function postForm(path: string, body: Record<string, string>) {
  const resp = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body),
  });
  return { status: resp.status, body: await resp.json() };
}

async function main() {
  const email = "alice@example.com";

  console.log("=== Step 1: Request Magic Link ===");
  const request = await postForm("/auth/request", { email });
  console.log(`  ${request.body.message}`);
  console.log(`  Expires in: ${request.body.expires_in}s`);
  console.log(`  Magic URL: ${request.body.magic_url}`);

  console.log("\n=== Step 2: Verify Magic Link ===");
  const verify = await fetch(request.body.magic_url as string);
  console.log(`  Status: ${verify.status}`);
  if (verify.status === 200) console.log("  ✅ Successfully authenticated!");
  else console.log(`  ❌ Failed: ${await verify.text()}`);

  console.log("\n=== Step 3: Replay token (should fail) ===");
  const replay = await fetch(request.body.magic_url as string);
  console.log(`  Status: ${replay.status}`);
  if (replay.status === 401) console.log("  ✅ Replay correctly blocked");
}

main().catch(console.error);
