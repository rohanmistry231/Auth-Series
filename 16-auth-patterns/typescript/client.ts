const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";
const ALICE_PASSWORD = process.env.ALICE_PASSWORD ?? "password-alice";

async function postForm(path: string, data: Record<string, string>) {
  const resp = await fetch(`${BASE_URL}${path}`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(data), redirect: "manual" });
  return { status: resp.status, body: await resp.json(), cookies: resp.headers.get("set-cookie") ?? "" };
}

async function get(path: string, headers?: Record<string, string>) {
  const resp = await fetch(`${BASE_URL}${path}`, { headers });
  return { status: resp.status, body: await resp.json() };
}

async function main() {
  console.log("=== BFF Pattern ===");
  const login = await postForm("/bff/login", { username: "alice", password: ALICE_PASSWORD });
  console.log(`  ${login.body.message}`);
  const sid = login.cookies.split("session_id=")[1]?.split(";")[0] ?? "";
  const api = await get("/bff/api/data", { Cookie: `session_id=${sid}` });
  console.log(`  ${api.status === 200 ? `✅ ${api.body.message}` : "❌"}`);

  console.log("\n=== Token Rotation ===");
  const issue = await postForm("/token/issue", { username: "alice", password: ALICE_PASSWORD });
  const rt = issue.body.refresh_token as string;
  console.log(`  Issued: refresh=${rt.slice(0, 16)}...`);
  const refresh1 = await postForm("/token/refresh", { refresh_token: rt });
  console.log(`  Rotated: ${refresh1.status === 200 ? "✅" : "❌"}`);
  const refresh2 = await postForm("/token/refresh", { refresh_token: rt });
  console.log(`  Replay old: ${refresh2.status === 401 ? "✅ Theft detected" : "❌"}`);

  console.log("\n=== Gateway Auth ===");
  const g_token = await postForm("/gateway/token", { username: "alice", password: ALICE_PASSWORD });
  const tok = g_token.body.access_token as string;
  const g_res = await get("/gateway/api/resource", { Authorization: `Bearer ${tok}` });
  console.log(`  ${g_res.status === 200 ? `✅ ${g_res.body.message}` : "❌"}`);
}

main().catch(console.error);
