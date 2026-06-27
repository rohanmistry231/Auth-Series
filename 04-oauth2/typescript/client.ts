/** OAuth 2.0 client demonstrating all grant types. */

const AUTH_SERVER = process.env.AUTH_SERVER ?? "http://localhost:8000";

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

async function request(path: string, options: { method?: string; body?: string; headers?: Record<string, string> } = {}) {
  const resp = await fetch(`${AUTH_SERVER}${path}`, {
    method: options.method ?? "GET",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...options.headers },
    body: options.body,
    redirect: "manual",
  });
  const text = await resp.text();
  let body: any;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: resp.status, body, headers: resp.headers };
}

async function authCodeFlow() {
  console.log("=== Authorization Code Flow ===");
  const redirectUri = "http://localhost:8001/callback";
  const state = b64url(crypto.randomBytes(16));

  const authResp = await request(`/authorize?response_type=code&client_id=webapp&redirect_uri=${encodeURIComponent(redirectUri)}&scope=openid+profile&state=${state}`);
  console.log("1. Authorize page loaded");

  const consentResp = await request("/consent", {
    method: "POST",
    body: new URLSearchParams({
      response_type: "code", client_id: "webapp", redirect_uri: redirectUri,
      scope: "openid profile", state, username: "alice",
      password: process.env.ALICE_PASSWORD ?? "password-alice", approve: "yes",
    }).toString(),
  });
  console.log(`2. Consent: ${consentResp.status}`);

  const location = consentResp.headers.get("location");
  if (location) {
    const code = new URL(location).searchParams.get("code")!;
    console.log(`   Auth code: ${code.slice(0, 20)}...`);

    const tokenResp = await request("/token", {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "authorization_code", code, client_id: "webapp",
        client_secret: process.env.WEBAPP_SECRET ?? "webapp-secret",
        redirect_uri: redirectUri,
      }).toString(),
    });
    console.log(`3. Token: ${tokenResp.status}`);
    displayTokens(tokenResp.body);
    return tokenResp.body;
  }
}

async function pkceFlow() {
  console.log("\n=== Authorization Code + PKCE Flow ===");
  const redirectUri = "http://localhost:3000/callback";
  const state = b64url(crypto.randomBytes(16));
  const codeVerifier = b64url(crypto.randomBytes(32));
  const codeChallenge = b64url(crypto.createHash("sha256").update(codeVerifier).digest());

  const authResp = await request(`/authorize?response_type=code&client_id=spa&redirect_uri=${encodeURIComponent(redirectUri)}&scope=openid+profile&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`);
  console.log("1. Authorize page loaded");

  const consentResp = await request("/consent", {
    method: "POST",
    body: new URLSearchParams({
      response_type: "code", client_id: "spa", redirect_uri: redirectUri,
      scope: "openid profile", state, username: "alice",
      password: process.env.ALICE_PASSWORD ?? "password-alice", approve: "yes",
      code_challenge: codeChallenge, code_challenge_method: "S256",
    }).toString(),
  });
  console.log(`2. Consent: ${consentResp.status}`);

  const location = consentResp.headers.get("location");
  if (location) {
    const code = new URL(location).searchParams.get("code")!;
    console.log(`   Auth code: ${code.slice(0, 20)}...`);

    const tokenResp = await request("/token", {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "authorization_code", code, client_id: "spa",
        redirect_uri: redirectUri, code_verifier: codeVerifier,
      }).toString(),
    });
    console.log(`3. Token: ${tokenResp.status}`);
    displayTokens(tokenResp.body);
  }
}

async function clientCredsFlow() {
  console.log("\n=== Client Credentials Flow ===");
  const tokenResp = await request("/token", {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "client_credentials", client_id: "service-a",
      client_secret: process.env.SERVICE_A_SECRET ?? "service-a-secret",
      scope: "read:data",
    }).toString(),
  });
  console.log(`Token: ${tokenResp.status}`);
  displayTokens(tokenResp.body);

  const userinfo = await fetch(`${AUTH_SERVER}/userinfo`, {
    headers: { Authorization: `Bearer ${tokenResp.body.access_token}` },
  });
  console.log(`   /userinfo: ${userinfo.status}`, await userinfo.json());
}

async function deviceFlow() {
  console.log("\n=== Device Code Flow ===");
  const deviceResp = await request("/device/code", {
    method: "POST",
    body: new URLSearchParams({ client_id: "webapp", scope: "openid profile" }).toString(),
  });
  console.log("1. Device code response:", deviceResp.body);

  const { user_code, device_code, verification_uri_complete } = deviceResp.body;
  console.log(`   User code: ${user_code}`);
  console.log(`   Go to: ${verification_uri_complete}`);

  const approveResp = await request("/device/approve", {
    method: "POST",
    body: new URLSearchParams({
      user_code, username: "alice",
      password: process.env.ALICE_PASSWORD ?? "password-alice",
    }).toString(),
  });
  console.log(`\n2. Approval: ${approveResp.status}`, approveResp.body);

  const tokenResp = await request("/token", {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code, client_id: "webapp",
    }).toString(),
  });
  console.log(`3. Token: ${tokenResp.status}`);
  displayTokens(tokenResp.body);
}

async function refreshFlow(tokens: any) {
  console.log("\n=== Token Refresh Flow ===");
  if (!tokens?.refresh_token) {
    console.log("No refresh token available");
    return;
  }
  const resp = await request("/token", {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "refresh_token", refresh_token: tokens.refresh_token,
      client_id: "webapp",
      client_secret: process.env.WEBAPP_SECRET ?? "webapp-secret",
    }).toString(),
  });
  console.log(`Refresh: ${resp.status}`);
  displayTokens(resp.body);
}

function displayTokens(body: any) {
  if (!body) return;
  for (const [k, v] of Object.entries(body)) {
    const display = typeof v === "string" && v.length > 40 ? `${(v as string).slice(0, 40)}...` : v;
    console.log(`   ${k}: ${display}`);
  }
}

async function main() {
  const flow = process.argv[2] ?? "all";

  if (flow === "all" || flow === "auth-code") {
    const tokens = await authCodeFlow();
    if (flow === "all" && tokens) await refreshFlow(tokens);
  }
  if (flow === "all" || flow === "pkce") await pkceFlow();
  if (flow === "all" || flow === "client-creds") await clientCredsFlow();
  if (flow === "all" || flow === "device") await deviceFlow();
}

main().catch(console.error);
