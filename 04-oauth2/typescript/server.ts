import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";

const ISSUER = "http://localhost:8000";
const ACCESS_TTL = 3600;
const REFRESH_TTL = 86400 * 7;
const AUTH_CODE_TTL = 300;

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const USERS: Record<string, string> = {
  alice: process.env.ALICE_PASSWORD ?? "password-alice",
  bob: process.env.BOB_PASSWORD ?? "password-bob",
};

const CLIENTS: Record<string, { client_secret: string | null; redirect_uris: string[]; grant_types: string[] }> = {
  webapp: {
    client_secret: process.env.WEBAPP_SECRET ?? "webapp-secret",
    redirect_uris: ["http://localhost:8001/callback"],
    grant_types: ["authorization_code", "refresh_token"],
  },
  spa: {
    client_secret: null,
    redirect_uris: ["http://localhost:3000/callback"],
    grant_types: ["authorization_code", "refresh_token"],
  },
  "service-a": {
    client_secret: process.env.SERVICE_A_SECRET ?? "service-a-secret",
    redirect_uris: [],
    grant_types: ["client_credentials"],
  },
};

const authCodes = new Map<string, any>();
const refreshTokens = new Map<string, any>();
const deviceCodes = new Map<string, any>();

function base64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function randomToken(): string {
  return crypto.randomBytes(48).toString("base64url");
}

function makeAccessToken(sub: string, scope: string, clientId: string): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = { iss: ISSUER, sub, client_id: clientId, scope, iat: now, exp: now + ACCESS_TTL, jti: randomUUID() };

  const h = base64url(Buffer.from(JSON.stringify(header)));
  const p = base64url(Buffer.from(JSON.stringify(payload)));
  const sig = crypto.sign("sha256", Buffer.from(`${h}.${p}`), privateKey);

  return `${h}.${p}.${base64url(sig)}`;
}

function parseQuery(url: string): Record<string, string> {
  const idx = url.indexOf("?");
  if (idx === -1) return {};
  const qs: Record<string, string> = {};
  for (const part of url.slice(idx + 1).split("&")) {
    const [k, ...v] = part.split("=");
    qs[decodeURIComponent(k)] = decodeURIComponent(v.join("="));
  }
  return qs;
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

function sendRedirect(res: ServerResponse, location: string) {
  res.writeHead(302, { Location: location });
  res.end();
}

function parseForm(body: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of body.split("&")) {
    const [k, ...v] = part.split("=");
    result[decodeURIComponent(k)] = decodeURIComponent(v.join("="));
  }
  return result;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;
  const method = req.method ?? "GET";
  const query = Object.fromEntries(url.searchParams);

  try {
    // GET /authorize
    if (path === "/authorize" && method === "GET") {
      const { response_type, client_id, redirect_uri, scope = "", state = "", code_challenge, code_challenge_method } = query;

      const client = CLIENTS[client_id];
      if (!client || !client.redirect_uris.includes(redirect_uri)) {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }
      if (response_type !== "code") {
        sendJson(res, 400, { error: "unsupported_response_type" });
        return;
      }
      if (code_challenge && code_challenge_method !== "S256" && code_challenge_method !== "plain") {
        sendJson(res, 400, { error: "invalid_request" });
        return;
      }

      sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>Authorize <code>${client_id}</code></h2>
<form method="post" action="/consent">
<input type="hidden" name="response_type" value="${response_type}">
<input type="hidden" name="client_id" value="${client_id}">
<input type="hidden" name="redirect_uri" value="${redirect_uri}">
<input type="hidden" name="scope" value="${scope}">
<input type="hidden" name="state" value="${state}">
<input type="hidden" name="code_challenge" value="${code_challenge ?? ""}">
<input type="hidden" name="code_challenge_method" value="${code_challenge_method ?? ""}">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password" value="password-alice"></label></p>
<p><button type="submit" name="approve" value="yes">Approve</button>
<button type="submit" name="approve" value="no">Deny</button></p>
</form></body></html>`);
      return;
    }

    // POST /consent
    if (path === "/consent" && method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);

      if (form.approve !== "yes") {
        sendJson(res, 403, { error: "access_denied" });
        return;
      }

      const expected = USERS[form.username];
      if (!expected || expected !== form.password) {
        sendJson(res, 401, { error: "invalid_credentials" });
        return;
      }

      const code = randomToken();
      authCodes.set(code, {
        client_id: form.client_id,
        redirect_uri: form.redirect_uri,
        scope: form.scope,
        username: form.username,
        expires: Date.now() + AUTH_CODE_TTL * 1000,
        code_challenge: form.code_challenge || null,
        code_challenge_method: form.code_challenge_method || null,
      });

      const params = new URLSearchParams({ code });
      if (form.state) params.set("state", form.state);
      sendRedirect(res, `${form.redirect_uri}?${params}`);
      return;
    }

    // POST /token
    if (path === "/token" && method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);

      if (form.grant_type === "authorization_code") return handleAuthCode(res, form);
      if (form.grant_type === "client_credentials") return handleClientCreds(res, req, form);
      if (form.grant_type === "refresh_token") return handleRefresh(res, form);
      if (form.grant_type === "urn:ietf:params:oauth:grant-type:device_code") return handleDeviceToken(res, form);

      sendJson(res, 400, { error: "unsupported_grant_type" });
      return;
    }

    // POST /device/code
    if (path === "/device/code" && method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);

      if (!CLIENTS[form.client_id]) {
        sendJson(res, 400, { error: "invalid_client" });
        return;
      }

      const deviceCode = randomToken();
      const userCode = crypto.randomBytes(3).toString("hex").toUpperCase().slice(0, 8);

      deviceCodes.set(deviceCode, {
        client_id: form.client_id,
        scope: form.scope ?? "",
        user_code: userCode,
        status: "pending",
        username: null,
        expires: Date.now() + 600000,
      });

      sendJson(res, 200, {
        device_code: deviceCode,
        user_code: userCode,
        verification_uri: `${ISSUER}/device`,
        verification_uri_complete: `${ISSUER}/device?user_code=${userCode}`,
        expires_in: 600,
        interval: 5,
      });
      return;
    }

    // POST /device/approve
    if (path === "/device/approve" && method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);

      const expected = USERS[form.username];
      if (!expected || expected !== form.password) {
        sendJson(res, 401, { error: "invalid_credentials" });
        return;
      }

      for (const [dc, data] of deviceCodes) {
        if (data.user_code === form.user_code && data.status === "pending") {
          data.status = "approved";
          data.username = form.username;
          sendJson(res, 200, { message: "Device approved" });
          return;
        }
      }

      sendJson(res, 400, { error: "invalid_user_code" });
      return;
    }

    // GET /device
    if (path === "/device" && method === "GET") {
      sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:400px;margin:40px auto">
<h2>Device Authorization</h2>
<form method="post" action="/device/approve">
<p><label>User Code: <input name="user_code" size="10" autofocus></label></p>
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password" value="password-alice"></label></p>
<p><button type="submit">Approve</button></p>
</form></body></html>`);
      return;
    }

    // GET /userinfo
    if (path === "/userinfo" && method === "GET") {
      const auth = req.headers.authorization ?? "";
      if (!auth.startsWith("Bearer ")) {
        sendJson(res, 401, { error: "missing_token" });
        return;
      }

      const token = auth.slice(7);
      const parts = token.split(".");
      if (parts.length !== 3) {
        sendJson(res, 401, { error: "invalid_token" });
        return;
      }

      try {
        const valid = crypto.verify(
          "sha256",
          Buffer.from(`${parts[0]}.${parts[1]}`),
          publicKey,
          Buffer.from(parts[2], "base64url"),
        );
        if (!valid) {
          sendJson(res, 401, { error: "invalid_token" });
          return;
        }
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
        sendJson(res, 200, { sub: payload.sub, scope: payload.scope ?? "" });
      } catch {
        sendJson(res, 401, { error: "invalid_token" });
      }
      return;
    }

    // GET .well-known/oauth-authorization-server
    if (path === "/.well-known/oauth-authorization-server") {
      sendJson(res, 200, {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        device_authorization_endpoint: `${ISSUER}/device/code`,
        userinfo_endpoint: `${ISSUER}/userinfo`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
        code_challenge_methods_supported: ["S256", "plain"],
      });
      return;
    }

    sendJson(res, 404, { error: "not_found" });
  } catch (err) {
    sendJson(res, 500, { error: "server_error" });
  }
});

function handleAuthCode(res: ServerResponse, form: Record<string, string>) {
  const client = CLIENTS[form.client_id];
  if (!client) {
    sendJson(res, 400, { error: "invalid_client" });
    return;
  }
  if (client.client_secret && client.client_secret !== form.client_secret) {
    sendJson(res, 401, { error: "invalid_client_secret" });
    return;
  }

  const stored = authCodes.get(form.code);
  if (!stored || stored.expires < Date.now() || stored.client_id !== form.client_id || stored.redirect_uri !== form.redirect_uri) {
    authCodes.delete(form.code);
    sendJson(res, 400, { error: "invalid_grant" });
    return;
  }
  authCodes.delete(form.code);

  // PKCE verification
  if (stored.code_challenge) {
    if (!form.code_verifier) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "PKCE: code_verifier required" });
      return;
    }
    if (stored.code_challenge_method === "S256") {
      const expected = base64url(crypto.createHash("sha256").update(form.code_verifier).digest());
      if (expected !== stored.code_challenge) {
        sendJson(res, 400, { error: "invalid_grant", error_description: "PKCE: code_verifier mismatch" });
        return;
      }
    } else if (form.code_verifier !== stored.code_challenge) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "PKCE: code_verifier mismatch" });
      return;
    }
  }

  const accessToken = makeAccessToken(stored.username, stored.scope, form.client_id);
  const refreshToken = randomToken();
  refreshTokens.set(refreshToken, {
    client_id: form.client_id,
    username: stored.username,
    scope: stored.scope,
    expires: Date.now() + REFRESH_TTL * 1000,
  });

  sendJson(res, 200, {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TTL,
    refresh_token: refreshToken,
    scope: stored.scope,
  });
}

function handleClientCreds(res: ServerResponse, req: IncomingMessage, form: Record<string, string>) {
  let clientId = form.client_id;
  let clientSecret = form.client_secret;

  const auth = req.headers.authorization ?? "";
  if (auth.startsWith("Basic ")) {
    const decoded = Buffer.from(auth.slice(6), "base64").toString();
    [clientId, clientSecret] = decoded.split(":", 2);
  }

  const client = CLIENTS[clientId];
  if (!client || (client.client_secret && client.client_secret !== clientSecret)) {
    sendJson(res, 401, { error: "invalid_client" });
    return;
  }

  const accessToken = makeAccessToken(clientId, form.scope ?? "", clientId);
  sendJson(res, 200, {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TTL,
    scope: form.scope ?? "",
  });
}

function handleRefresh(res: ServerResponse, form: Record<string, string>) {
  const stored = refreshTokens.get(form.refresh_token);
  if (!stored || stored.expires < Date.now() || stored.client_id !== form.client_id) {
    refreshTokens.delete(form.refresh_token);
    sendJson(res, 400, { error: "invalid_grant" });
    return;
  }
  refreshTokens.delete(form.refresh_token);

  const newAccess = makeAccessToken(stored.username, stored.scope, form.client_id);
  const newRefresh = randomToken();
  refreshTokens.set(newRefresh, {
    client_id: form.client_id,
    username: stored.username,
    scope: stored.scope,
    expires: Date.now() + REFRESH_TTL * 1000,
  });

  sendJson(res, 200, {
    access_token: newAccess,
    token_type: "Bearer",
    expires_in: ACCESS_TTL,
    refresh_token: newRefresh,
    scope: stored.scope,
  });
}

function handleDeviceToken(res: ServerResponse, form: Record<string, string>) {
  const stored = deviceCodes.get(form.device_code);
  if (!stored) {
    sendJson(res, 400, { error: "invalid_grant" });
    return;
  }

  if (stored.status === "pending") {
    sendJson(res, 400, { error: "authorization_pending" });
    return;
  }

  if (stored.status === "approved") {
    deviceCodes.delete(form.device_code);
    sendJson(res, 200, {
      access_token: makeAccessToken(stored.username, stored.scope, stored.client_id),
      token_type: "Bearer",
      expires_in: ACCESS_TTL,
      refresh_token: randomToken(),
    });
    return;
  }

  sendJson(res, 400, { error: "expired_token" });
}

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "0.0.0.0", () => {
  console.log(`OAuth 2.0 Server running at http://localhost:${PORT}`);
});
