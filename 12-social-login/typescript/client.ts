const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";

async function main() {
  const client = async (path: string, opts?: any) => {
    const resp = await fetch(`${BASE_URL}${path}`, { redirect: "manual", ...opts });
    return { status: resp.status, headers: resp.headers, body: resp.status === 200 ? await resp.text() : null };
  };

  console.log("=== Step 1: Visit home page ===");
  const home = await client("/");
  console.log(`  Status: ${home.status} ✅`);

  console.log("\n=== Step 2: Click 'Sign in with Google' ===");
  const loginRedirect = await client("/auth/google/login");
  const location1 = loginRedirect.headers.get("location") ?? "";
  console.log(`  Redirected to: ${location1.slice(0, 80)}...`);

  console.log("\n=== Step 3: Follow redirect to mock provider ===");
  const consent = await fetch(`${BASE_URL}${location1}`);
  console.log(`  Status: ${consent.status} ✅`);

  console.log("\n=== Step 4: Allow access ===");
  const match = (await consent.text()).match(/action="([^"]+)"/);
  const actionPath = match?.[1] ?? "/mock/google/consent";
  const consentResp = await fetch(`${BASE_URL}${actionPath}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: "google-client-id", redirect_uri: "http://127.0.0.1:8000/auth/google/callback", action: "allow" }),
    redirect: "manual",
  });
  const location2 = consentResp.headers.get("location") ?? "";
  console.log(`  Redirected to: ${location2.slice(0, 80)}...`);

  console.log("\n=== Step 5: Follow callback to app ===");
  const callback = await fetch(`${BASE_URL}${location2}`, { redirect: "manual" });
  const location3 = callback.headers.get("location") ?? "";
  console.log(`  Redirected to: ${location3}`);

  const dashboard = await fetch(`${BASE_URL}${location3}`);
  console.log(`  Status: ${dashboard.status}`);
  if (dashboard.status === 200) console.log("  ✅ Successfully signed in with Google!");
}

main().catch(console.error);
