const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";
const USERNAME = process.env.AUTH_USERNAME ?? "alice";
const PASSWORD = process.env.AUTH_PASSWORD ?? "password-alice";

function basicAuthHeader(username: string, password: string): string {
  const encoded = Buffer.from(`${username}:${password}`).toString("base64");
  return `Basic ${encoded}`;
}

async function get(
  url: string,
  auth?: { username: string; password: string },
): Promise<{ status: number; body: unknown }> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };

  if (auth) {
    headers["Authorization"] = basicAuthHeader(auth.username, auth.password);
  }

  const resp = await fetch(url, { headers });
  const body = await resp.json();
  return { status: resp.status, body };
}

async function main() {
  console.log("=== Public endpoint ===");
  const { status: pubStatus, body: pubBody } = await get(`${BASE_URL}/public`);
  console.log(pubStatus, pubBody);

  console.log("\n=== Protected endpoint (with auth) ===");
  const { status: authStatus, body: authBody } = await get(`${BASE_URL}/protected`, {
    username: USERNAME,
    password: PASSWORD,
  });
  console.log(authStatus, authBody);

  console.log("\n=== Protected endpoint (wrong password) ===");
  const { status: badStatus, body: badBody } = await get(`${BASE_URL}/protected`, {
    username: USERNAME,
    password: "wrong-password",
  });
  console.log(badStatus, badBody);

  console.log("\n=== Protected endpoint (no auth) ===");
  const { status: noStatus, body: noBody } = await get(`${BASE_URL}/protected`);
  console.log(noStatus, noBody);
}

main().catch(console.error);
