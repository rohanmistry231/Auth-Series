import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";

const ISSUER = "http://localhost:8000";
const ACCESS_TTL = 3600;
const ID_TOKEN_TTL = 3600;
const REFRESH_TTL = 86400 * 7;
const AUTH_CODE_TTL = 300;

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const USERS: Record<string, any> = {
  alice: {
    password: process.env.ALICE_PASSWORD ?? "password-alice",
    sub: "user-alice-001",
    name: "Alice Johnson",
    given_name: "Alice",
    family_name: "Johnson",
    email: "alice@example.com",
    email_verified: true,
    picture: "https://example.com/avatars/alice.jpg",
  },
  bob: {
    password: process.env.BOB_PASSWORD ?? "password-bob",
    sub: "user-bob-002",
    name: "Bob Smith",
    given_name: "Bob",
    family_name: "Smith",
    email: "bob@example.com",
    email_verified: false,
    picture: "https://example.com/avatars/bob.jpg",
  },
};

const CLIENTS: Record<string, any> = {
  rp: {
    client_secret: process.env.RP_SECRET ?? "rp-secret",
    redirect_uris: ["http://localhost:8001/callback"],
    grant_types: ["authorization_code", "refresh_token"],
  },
  spa: {
    client_secret: null,
    redirect_uris: ["http://localhost:3000/callback"],
    grant_types: ["authorization_code"],
  },
};

const authCodes = new Map<string, any>();
const refreshTokens = new Map<string, any>();

function base64url(buf: Buffer): string { return buf.toString("base64url"); }
function randomToken(): string { return crypto.randomBytes(48).toString("base64url"); }

function encodeJwt(payload: Record<string, unknown>, key: string): string {
  const header = { alg: "RS256", typ: "JWT", kid: "oidc-rsa-1" };
  const h = base64url(Buffer.from(JSON.stringify(header)));
  const p = base64url(Buffer.from(JSON.stringify(payload)));
  const sig = crypto.sign("sha256", Buffer.from(`${h}.${p}`), key);
  return `${h}.${p}.${base64url(sig)}`;
}

function makeIdToken(user: any, clientId: string, nonce: string | null, authTime: number): string {
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, any> = {
    iss: ISSUER, sub: user.sub, aud: [clientId],
    exp: now + ID_TOKEN_TTL, iat: now, auth_time: authTime,
    nonce, azp: clientId,
  };
  for (const c of ["name", "given_name", "family_name", "email", "email_verified", "picture"]) {
    if (user[c] !== undefined) claims[c] = user[c];
  }
  return encodeJwt(claims, privateKey);
}

function makeAccessToken(user: any, scope: string, clientId: string): string {
  const now = Math.floor(Date.now() / 1000);
  return encodeJwt({ iss: ISSUER, sub: user.sub, client_id: clientId, scope, iat: now, exp: now + ACCESS_TTL, jti: randomUUID() }, privateKey);
}

function extractScopeClaims(scope: string, user: any): Record<string, any> {
  const result: Record<string, any> = { sub: user.sub };
  const scopes = scope.split(" ");
  if (scopes.includes("profile")) {
    for (const c of ["name", "given_name", "family_name", "picture"]) {
      if (user[c] !== undefined) result[c] = user[c];
    }
  }
  if (scopes.includes("email")) {
    for (const c of ["email", "email_verified"]) {
      if (user[c] !== undefined) result[c] = user[c];
    }
  }
  return result;
}

function findUserBySub(sub: string): any {
  for (const u of Object.values(USERS)) if (u.sub === sub) return u;
  return null;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
  });
}

function sendJson(res: ServerResponse, status: number, data: any) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function sendHtml(res: ServerResponse, html: string) {
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(html);
}

function sendRedirect(res: ServerResponse, loc: string) {
  res.writeHead(302, { Location: loc });
  res.end();
}

function parseForm(body: string): Record<string, string> {
  const r: Record<string, string> = {};
  for (const p of body.split("&")) {
    const [k, ...v] = p.split("=");
    r[decodeURIComponent(k)] = decodeURIComponent(v.join("="));
  }
  return r;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;
  const method = req.method ?? "GET";
  const q = Object.fromEntries(url.searchParams);

  try {
    if (path === "/authorize" && method === "GET") {
      const client = CLIENTS[q.client_id];
      if (!client || !client.redirect_uris.includes(q.redirect_uri)) {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      if (q.response_type !== "code") {
        sendJson(res, 400, { error: "unsupported_response_type" });
        return;
      }
      if (!q.scope?.split(" ").includes("openid")) {
        sendJson(res, 400, { error: "openid scope required" });
        return;
      }
      sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>Sign in</h2>
<form method="post" action="/consent">
<input type="hidden" name="response_type" value="${q.response_type}">
<input type="hidden" name="client_id" value="${q.client_id}">
<input type="hidden" name="redirect_uri" value="${q.redirect_uri}">
<input type="hidden" name="scope" value="${q.scope}">
<input type="hidden" name="state" value="${q.state ?? ""}">
<input type="hidden" name="nonce" value="${q.nonce ?? ""}">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit" name="approve" value="yes">Sign In</button>
<button type="submit" name="approve" value="no">Cancel</button></p>
</form></body></html>`);
      return;
    }

    if (path === "/consent" && method === "POST") {
      const body = await readBody(req);
      const f = parseForm(body);
      if (f.approve !== "yes") { sendJson(res, 403, { error: "access_denied" }); return; }

      const user = USERS[f.username];
      if (!user || user.password !== f.password) {
        sendJson(res, 401, { error: "invalid_credentials" });
        return;
      }

      const code = randomToken();
      const authTime = Math.floor(Date.now() / 1000);
      authCodes.set(code, {
        client_id: f.client_id, redirect_uri: f.redirect_uri,
        scope: f.scope, nonce: f.nonce || null,
        username: f.username, auth_time: authTime,
        expires: Date.now() + AUTH_CODE_TTL * 1000,
      });

      const p = new URLSearchParams({ code });
      if (f.state) p.set("state", f.state);
      sendRedirect(res, `${f.redirect_uri}?${p}`);
      return;
    }

    if (path === "/token" && method === "POST") {
      const body = await readBody(req);
      const f = parseForm(body);
      if (f.grant_type === "authorization_code") return handleAuthCode(res, f);
      if (f.grant_type === "refresh_token") return handleRefresh(res, f);
      sendJson(res, 400, { error: "unsupported_grant_type" });
      return;
    }

    if (path === "/userinfo" && method === "GET") {
      const auth = req.headers.authorization ?? "";
      if (!auth.startsWith("Bearer ")) {
        sendJson(res, 401, { error: "missing_token" });
        return;
      }
      const token = auth.slice(7);
      const parts = token.split(".");
      if (parts.length !== 3) { sendJson(res, 401, { error: "invalid_token" }); return; }
      try {
        const valid = crypto.verify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, Buffer.from(parts[2], "base64url"));
        if (!valid) { sendJson(res, 401, { error: "invalid_token" }); return; }
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
        const user = findUserBySub(payload.sub);
        if (!user) { sendJson(res, 404, { error: "user_not_found" }); return; }
        sendJson(res, 200, extractScopeClaims(payload.scope ?? "", user));
      } catch {
        sendJson(res, 401, { error: "invalid_token" });
      }
      return;
    }

    if (path === "/.well-known/openid-configuration") {
      sendJson(res, 200, {
        issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`, userinfo_endpoint: `${ISSUER}/userinfo`,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        scopes_supported: ["openid", "profile", "email"],
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        id_token_signing_alg_values_supported: ["RS256"],
      });
      return;
    }

    if (path === "/.well-known/jwks.json") {
      const pub = crypto.createPublicKey(publicKey);
      const jwk = pub.export({ format: "jwk" });
      sendJson(res, 200, { keys: [{ kty: jwk.kty, use: "sig", alg: "RS256", kid: "oidc-rsa-1", n: jwk.n, e: jwk.e }] });
      return;
    }

    sendJson(res, 404, { error: "not_found" });
  } catch {
    sendJson(res, 500, { error: "server_error" });
  }
});

function handleAuthCode(res: ServerResponse, f: Record<string, string>) {
  const client = CLIENTS[f.client_id];
  if (!client || (client.client_secret && client.client_secret !== f.client_secret)) {
    sendJson(res, 400, { error: "invalid_client" });
    return;
  }
  const stored = authCodes.get(f.code);
  if (!stored || stored.expires < Date.now() || stored.client_id !== f.client_id || stored.redirect_uri !== f.redirect_uri) {
    authCodes.delete(f.code);
    sendJson(res, 400, { error: "invalid_grant" });
    return;
  }
  authCodes.delete(f.code);

  const user = USERS[stored.username];
  const scope = stored.scope;
  const accessToken = makeAccessToken(user, scope, f.client_id);
  const idToken = makeIdToken(user, f.client_id, stored.nonce, stored.auth_time);
  const refreshToken = randomToken();
  refreshTokens.set(refreshToken, { client_id: f.client_id, username: stored.username, scope, expires: Date.now() + REFRESH_TTL * 1000 });

  sendJson(res, 200, { access_token: accessToken, token_type: "Bearer", expires_in: ACCESS_TTL, refresh_token: refreshToken, id_token: idToken, scope });
}

function handleRefresh(res: ServerResponse, f: Record<string, string>) {
  const stored = refreshTokens.get(f.refresh_token);
  if (!stored || stored.expires < Date.now() || stored.client_id !== f.client_id) {
    refreshTokens.delete(f.refresh_token);
    sendJson(res, 400, { error: "invalid_grant" });
    return;
  }
  refreshTokens.delete(f.refresh_token);
  const user = USERS[stored.username];
  const newAccess = makeAccessToken(user, stored.scope, f.client_id);
  const newRefresh = randomToken();
  const idToken = makeIdToken(user, f.client_id, null, Math.floor(Date.now() / 1000));
  refreshTokens.set(newRefresh, { client_id: f.client_id, username: stored.username, scope: stored.scope, expires: Date.now() + REFRESH_TTL * 1000 });
  sendJson(res, 200, { access_token: newAccess, token_type: "Bearer", expires_in: ACCESS_TTL, refresh_token: newRefresh, id_token: idToken, scope: stored.scope });
}

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "0.0.0.0", () => console.log(`OIDC Provider at http://localhost:${PORT}`));
