const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";
const USERNAME = process.env.AUTH_USERNAME ?? "alice";
const PASSWORD = process.env.AUTH_PASSWORD ?? "password-alice";

const cookieStore = new Map<string, string>();

async function request(
  path: string,
  options: { method?: string; body?: Record<string, unknown> } = {},
): Promise<{ status: number; body: unknown }> {
  const url = `${BASE_URL}${path}`;
  const headers: Record<string, string> = { "Content-Type": "application/json" };

  const cookieParts: string[] = [];
  for (const [key, value] of cookieStore) {
    cookieParts.push(`${key}=${value}`);
  }
  if (cookieParts.length) {
    headers["Cookie"] = cookieParts.join("; ");
  }

  const resp = await fetch(url, {
    method: options.method ?? "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const setCookie = resp.headers.get("set-cookie");
  if (setCookie) {
    const match = setCookie.match(/session_id=([^;]+)/);
    if (match) {
      cookieStore.set("session_id", match[1]);
    } else {
      cookieStore.delete("session_id");
    }
  }

  const body = await resp.json();
  return { status: resp.status, body };
}

async function main() {
  console.log("=== Public endpoint ===");
  const pub = await request("/public");
  console.log(pub.status, pub.body);

  console.log("\n=== Login ===");
  const login = await request("/login", {
    method: "POST",
    body: { username: USERNAME, password: PASSWORD },
  });
  console.log(login.status, login.body);

  console.log("\n=== Protected endpoint (/me) ===");
  const me = await request("/me");
  console.log(me.status, me.body);

  console.log("\n=== Create data (with CSRF) ===");
  const csrfResp = await request("/csrf-token");
  const token = (csrfResp.body as Record<string, string>).csrf_token;
  const data = await request("/data", {
    method: "POST",
    body: { csrf_token: token, payload: "hello" },
  });
  console.log(data.status, data.body);

  console.log("\n=== Create data (no CSRF — should fail) ===");
  const noCsrf = await request("/data", {
    method: "POST",
    body: { payload: "hello" },
  });
  console.log(noCsrf.status, noCsrf.body);

  console.log("\n=== Logout ===");
  const logout = await request("/logout", { method: "POST" });
  console.log(logout.status, logout.body);

  console.log("\n=== After logout (/me — should fail) ===");
  const after = await request("/me");
  console.log(after.status, after.body);
}

main().catch(console.error);
