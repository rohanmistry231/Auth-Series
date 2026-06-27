import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";

const PROVIDER_SECRET = process.env.PROVIDER_CLIENT_SECRET ?? "provider-secret";

const PROVIDERS: Record<string, any> = {
  google: {
    name: "Google",
    client_id: "google-client-id",
    client_secret: PROVIDER_SECRET,
    authorize_path: "/mock/google/authorize",
    token_path: "/mock/google/token",
    userinfo_path: "/mock/google/userinfo",
    scopes: ["openid", "profile", "email"],
  },
  github: {
    name: "GitHub",
    client_id: "github-client-id",
    client_secret: PROVIDER_SECRET,
    authorize_path: "/mock/github/authorize",
    token_path: "/mock/github/token",
    userinfo_path: "/mock/github/userinfo",
    scopes: ["read:user", "user:email"],
  },
};

const MOCK_USERS: Record<string, any> = {
  google: {
    sub: "google-12345",
    name: "Alice Google",
    email: "alice@gmail.com",
    email_verified: true,
    picture: "https://example.com/avatars/alice-google.png",
  },
  github: {
    sub: "github-67890",
    name: "GitHub Alice",
    email: "alice@github.com",
    email_verified: true,
    picture: "https://example.com/avatars/alice-github.png",
    login: "alice-dev",
  },
};

const authCodes = new Map<string, any>();
const sessions = new Map<string, any>();

function hmacSign(payload: string): string {
  return crypto.createHmac("sha256", PROVIDER_SECRET).update(payload).digest("hex");
}

function makeIdToken(provider: string, user: any): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    iss: `https://${provider}.com`,
    sub: user.sub,
    aud: PROVIDERS[provider].client_id,
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    ...user,
  })).toString("base64url");
  const sig = hmacSign(`${header}.${payload}`);
  return `${header}.${payload}.${sig}`;
}

function verifyIdToken(provider: string, token: string): any {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid token format");
  const sig = hmacSign(`${parts[0]}.${parts[1]}`);
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(parts[2]))) throw new Error("Invalid signature");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  if (payload.aud !== PROVIDERS[provider].client_id) throw new Error("Invalid audience");
  return payload;
}

function sendHtml(res: ServerResponse, html: string, status = 200) {
  res.writeHead(status, { "Content-Type": "text/html;charset=utf-8" });
  res.end(html);
}

function sendJson(res: ServerResponse, status: number, data: any) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => { const c: Buffer[] = []; req.on("data", (d) => c.push(d)); req.on("end", () => resolve(Buffer.concat(c).toString())); });
}

function parseForm(body: string): Record<string, string> {
  const r: Record<string, string> = {};
  for (const p of body.split("&")) { const [k, ...v] = p.split("="); r[decodeURIComponent(k)] = decodeURIComponent(v.join("=")); }
  return r;
}

function serveStatic(res: ServerResponse, status: number, contentType: string, body: string, extraHeaders: Record<string, string> = {}) {
  res.writeHead(status, { "Content-Type": contentType, ...extraHeaders });
  res.end(body);
}

function redirect(res: ServerResponse, url: string) {
  res.writeHead(302, { Location: url });
  res.end();
}

function pageHtml(title: string, body: string): string {
  return `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
${body}</body></html>`;
}

// In-memory session store for cookie-based sessions
const sessionStore = new Map<string, any>();

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;
  const method = req.method ?? "GET";

  try {
    // === App: Home ===
    if (path === "/" && method === "GET") {
      sendHtml(res, pageHtml("Social Login Demo", `
<h2>Social Login Demo</h2>
<p style="color:#666">Built-in mock provider — no real credentials needed.</p>
<p><a href="/auth/google/login" style="display:inline-block;padding:12px 24px;background:#4285f4;color:#fff;text-decoration:none;border-radius:4px;margin:8px 0">Sign in with Google</a></p>
<p><a href="/auth/github/login" style="display:inline-block;padding:12px 24px;background:#24292f;color:#fff;text-decoration:none;border-radius:4px;margin:8px 0">Sign in with GitHub</a></p>
`));
      return;
    }

    // === App: Initiate login ===
    if (path.startsWith("/auth/") && path.endsWith("/login") && method === "GET") {
      const provider = path.split("/")[2];
      if (!PROVIDERS[provider]) { sendHtml(res, "Unknown provider", 404); return; }
      const prov = PROVIDERS[provider];
      const redirectUri = `http://127.0.0.1:8000/auth/${provider}/callback`;
      const params = `response_type=code&client_id=${prov.client_id}&redirect_uri=${redirectUri}&scope=${prov.scopes.join("+")}&state=${crypto.randomUUID()}`;
      redirect(res, `${prov.authorize_path}?${params}`);
      return;
    }

    // === App: Callback ===
    if (path.startsWith("/auth/") && path.endsWith("/callback") && method === "GET") {
      const provider = path.split("/")[2];
      if (!PROVIDERS[provider]) { sendHtml(res, "Unknown provider", 404); return; }
      const code = url.searchParams.get("code");
      if (!code) { sendHtml(res, "Missing code", 400); return; }

      const prov = PROVIDERS[provider];
      const tokenBody = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: `http://127.0.0.1:8000/auth/${provider}/callback`,
        client_id: prov.client_id,
        client_secret: prov.client_secret,
      });

      const tokenResp = await fetch(`http://127.0.0.1:8000${prov.token_path}`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: tokenBody,
      });
      const tokenData: any = await tokenResp.json();
      const userInfo = verifyIdToken(provider, tokenData.id_token);

      const userinfoResp = await fetch(`http://127.0.0.1:8000${prov.userinfo_path}`, {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      const userinfo: any = await userinfoResp.json();

      const sessionId = crypto.randomUUID();
      sessionStore.set(sessionId, {
        provider,
        provider_id: userInfo.sub,
        name: userinfo.name ?? "Unknown",
        email: userinfo.email ?? "",
        picture: userinfo.picture ?? "",
      });

      res.writeHead(302, {
        Location: "/dashboard",
        "Set-Cookie": `session_id=${sessionId}; HttpOnly; SameSite=Lax; Path=/`,
      });
      res.end();
      return;
    }

    // === App: Dashboard ===
    if (path === "/dashboard" && method === "GET") {
      sendHtml(res, pageHtml("Dashboard", `
<h2>Dashboard</h2>
<p>You are logged in!</p>
<p><a href="/">← Back</a></p>
`));
      return;
    }

    // === Mock Provider: Authorize ===
    if (path.includes("/mock/") && path.endsWith("/authorize") && method === "GET") {
      const provider = path.split("/")[2];
      if (!PROVIDERS[provider]) { sendHtml(res, "Unknown provider", 404); return; }
      const clientId = url.searchParams.get("client_id") ?? "";
      const redirectUri = url.searchParams.get("redirect_uri") ?? "";

      sendHtml(res, pageHtml(`${PROVIDERS[provider].name} Consent`, `
<h2>${PROVIDERS[provider].name} — Sign In</h2>
<p style="color:#666">Mock ${PROVIDERS[provider].name} consent page.</p>
<p>Signed in as: <strong>${MOCK_USERS[provider].name}</strong></p>
<form method="post" action="/mock/${provider}/consent">
  <input type="hidden" name="client_id" value="${clientId}">
  <input type="hidden" name="redirect_uri" value="${redirectUri}">
  <p>
    <button type="submit" name="action" value="allow" style="padding:10px 24px;background:#34a853;color:#fff;border:none;border-radius:4px;cursor:pointer">Allow</button>
    <button type="submit" name="action" value="deny" style="padding:10px 24px;background:#ea4335;color:#fff;border:none;border-radius:4px;cursor:pointer">Deny</button>
  </p>
</form>
`));
      return;
    }

    // === Mock Provider: Consent ===
    if (path.includes("/mock/") && path.endsWith("/consent") && method === "POST") {
      const provider = path.split("/")[2];
      const body = await readBody(req);
      const form = parseForm(body);
      const clientId = form.client_id ?? "";
      const redirectUri = form.redirect_uri ?? "";
      const action = form.action ?? "";

      if (!PROVIDERS[provider] || clientId !== PROVIDERS[provider].client_id) {
        sendHtml(res, "Invalid client", 400);
        return;
      }

      if (action !== "allow") {
        redirect(res, `${redirectUri}?error=access_denied`);
        return;
      }

      const code = crypto.randomUUID();
      authCodes.set(code, { provider, client_id: clientId, exp: Date.now() + 300000 });
      redirect(res, `${redirectUri}?code=${code}`);
      return;
    }

    // === Mock Provider: Token ===
    if (path.includes("/mock/") && path.endsWith("/token") && method === "POST") {
      const provider = path.split("/")[2];
      const body = await readBody(req);
      const form = parseForm(body);
      const code = form.code ?? "";
      const clientSecret = form.client_secret ?? "";

      if (!PROVIDERS[provider]) { sendJson(res, 404, { error: "Unknown provider" }); return; }
      if (clientSecret !== PROVIDERS[provider].client_secret) { sendJson(res, 401, { error: "Invalid secret" }); return; }

      const auth = authCodes.get(code);
      if (!auth) { sendJson(res, 401, { error: "Invalid code" }); return; }
      if (auth.exp < Date.now()) { sendJson(res, 401, { error: "Code expired" }); return; }

      const user = MOCK_USERS[provider];
      sendJson(res, 200, {
        access_token: crypto.randomUUID(),
        token_type: "Bearer",
        expires_in: 3600,
        id_token: makeIdToken(provider, user),
      });
      return;
    }

    // === Mock Provider: UserInfo ===
    if (path.includes("/mock/") && path.endsWith("/userinfo") && method === "GET") {
      const provider = path.split("/")[2];
      if (!PROVIDERS[provider]) { sendJson(res, 404, { error: "Unknown provider" }); return; }
      sendJson(res, 200, MOCK_USERS[provider]);
      return;
    }

    sendHtml(res, "Not found", 404);
  } catch {
    sendJson(res, 500, { error: "Internal error" });
  }
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "127.0.0.1", () => console.log(`Social Login Server at http://127.0.0.1:${PORT}`));
