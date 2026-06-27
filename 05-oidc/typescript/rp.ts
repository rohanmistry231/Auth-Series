/** OpenID Connect Relying Party (RP) client. */

const ISSUER = process.env.OIDC_ISSUER ?? "http://localhost:8000";
const CLIENT_ID = "rp";
const CLIENT_SECRET = process.env.RP_SECRET ?? "rp-secret";
const REDIRECT_URI = "http://localhost:8001/callback";

async function discover() {
  const resp = await fetch(`${ISSUER}/.well-known/openid-configuration`);
  const config = await resp.json();
  console.log("=== Discovery ===");
  for (const k of ["issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"]) {
    console.log(`  ${k}: ${config[k]}`);
  }
  return config;
}

async function fetchJwks(): Promise<any> {
  const resp = await fetch(`${ISSUER}/.well-known/jwks.json`);
  return resp.json();
}

function base64urlDecode(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

function validateIdToken(idToken: string, expectedNonce: string | null, jwks: any, publicKeyPem: string): any {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");

  const header = JSON.parse(base64urlDecode(parts[0]).toString());
  const payload = JSON.parse(base64urlDecode(parts[1]).toString());
  const now = Math.floor(Date.now() / 1000);

  const errors: string[] = [];

  if (payload.iss !== ISSUER) errors.push(`iss: ${payload.iss} !== ${ISSUER}`);
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(CLIENT_ID)) errors.push(`aud: ${aud} must contain ${CLIENT_ID}`);
  if (payload.exp < now) errors.push("token expired");
  if (payload.iat > now + 60) errors.push("iat in future");
  if (expectedNonce && payload.nonce !== expectedNonce) errors.push("nonce mismatch");
  if (payload.azp && payload.azp !== CLIENT_ID) errors.push(`azp: ${payload.azp} !== ${CLIENT_ID}`);

  if (errors.length) {
    errors.forEach((e) => console.log(`  FAIL: ${e}`));
    throw new Error("ID Token validation failed");
  }

  // Verify signature
  if (publicKeyPem) {
    const valid = crypto.verify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`), publicKeyPem, Buffer.from(parts[2], "base64url"));
    if (!valid) throw new Error("Signature validation failed");
  }

  console.log("  ✅ ID Token validated");
  return payload;
}

import crypto from "node:crypto";

async function runFlow() {
  const config = await discover();
  const nonce = crypto.randomBytes(16).toString("base64url");
  const state = crypto.randomBytes(16).toString("base64url");

  console.log("\n1. Redirect to authorize...");
  await fetch(`${ISSUER}/authorize?${new URLSearchParams({
    response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    scope: "openid profile email", state, nonce,
  })}`);

  console.log("2. Submit consent...");
  const consentResp = await fetch(`${ISSUER}/consent`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
      scope: "openid profile email", state, nonce,
      username: "alice", password: process.env.ALICE_PASSWORD ?? "password-alice", approve: "yes",
    }),
    redirect: "manual",
  });

  const location = consentResp.headers.get("location");
  if (!location) { console.log("  No redirect — consent failed"); return; }

  const code = new URL(location).searchParams.get("code")!;
  console.log(`3. Auth code: ${code.slice(0, 20)}...`);

  console.log("\n4. Exchange code for tokens...");
  const tokenResp = await fetch(`${ISSUER}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code, client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET, redirect_uri: REDIRECT_URI,
    }),
  });
  const tokens = await tokenResp.json();
  for (const [k, v] of Object.entries(tokens)) {
    const display = typeof v === "string" && v.length > 50 ? `${(v as string).slice(0, 50)}...` : v;
    console.log(`  ${k}: ${display}`);
  }

  const idToken = tokens.id_token as string;
  const jwks = await fetchJwks();
  const jwkKey = jwks.keys[0];
  const pubPem = `-----BEGIN PUBLIC KEY-----\n${jwkKey.n}\n-----END PUBLIC KEY-----`;

  console.log("\n5. Validate ID Token...");
  const claims = validateIdToken(idToken, nonce, jwks, pubPem);
  console.log(`  sub: ${claims.sub}\n  name: ${claims.name}\n  email: ${claims.email}`);

  console.log("\n6. Fetch UserInfo...");
  const ui = await fetch(`${ISSUER}/userinfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  console.log(`  ${ui.status}:`, await ui.json());
}

runFlow().catch(console.error);
