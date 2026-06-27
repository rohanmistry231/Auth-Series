/** Auth Patterns — BFF, Token Rotation, Gateway Middleware. */

import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";

const USERS: Record<string, string> = {
  alice: process.env.ALICE_PASSWORD ?? "password-alice",
};

function sha256(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function sendHtml(res: ServerResponse, html: string, status = 200) {
  res.writeHead(status, { "Content-Type": "text/html;charset=utf-8" });
  res.end(html);
}

function sendJson(res: ServerResponse, status: number, data: any, extraHeaders?: Record<string, string>) {
  res.writeHead(status, { "Content-Type": "application/json", ...extraHeaders });
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

// Stores
const bffSessions = new Map<string, any>();
const refreshTokens = new Map<string, any>();
const gatewayTokens = new Map<string, any>();

function page(title: string, content: string): string {
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:700px;margin:40px auto">${content}</body></html>`;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;

  try {
    // === Home ===
    if (path === "/") {
      sendHtml(res, page("Auth Patterns", `
<h2>Auth Patterns Demo</h2>
<ul>
  <li><a href="/bff/login">BFF Pattern</a></li>
  <li><a href="/token-rotation">Token Rotation</a></li>
  <li><a href="/gateway">Gateway Auth</a></li>
</ul>`));
      return;
    }

    // === BFF ===
    if (path === "/bff/login" && req.method === "GET") {
      sendHtml(res, page("BFF Login", `
<h2>BFF Login</h2>
<form method="post" action="/bff/login"><p><label>User: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p><p><button type="submit">Login</button></p></form>`));
      return;
    }

    if (path === "/bff/login" && req.method === "POST") {
      const body = await readBody(req); const form = parseForm(body);
      if (USERS[form.username] !== form.password) { sendJson(res, 401, { error: "Invalid" }); return; }
      const sid = crypto.randomUUID();
      bffSessions.set(sid, { username: form.username, access_token: crypto.randomUUID(), created_at: Date.now() });
      sendJson(res, 200, { message: `Logged in as ${form.username}` }, { "Set-Cookie": `session_id=${sid}; HttpOnly; SameSite=Lax; Path=/` });
      return;
    }

    if (path === "/bff/api/data" && req.method === "GET") {
      const sid = req.headers["cookie"]?.split("session_id=")?.[1]?.split(";")?.[0];
      const session = sid ? bffSessions.get(sid) : null;
      if (!session) { sendJson(res, 401, { error: "Not authenticated" }); return; }
      sendJson(res, 200, { message: `Protected data for ${session.username}`, data: "secret-42" });
      return;
    }

    // === Token Rotation ===
    if (path === "/token/issue" && req.method === "POST") {
      const body = await readBody(req); const form = parseForm(body);
      if (USERS[form.username] !== form.password) { sendJson(res, 401, { error: "Invalid" }); return; }
      const rt = crypto.randomBytes(48).toString("base64url");
      const family = crypto.randomUUID();
      refreshTokens.set(sha256(rt), { username: form.username, family, exp: Date.now() + 604800000, revoked: false });
      sendJson(res, 200, { access_token: crypto.randomUUID(), refresh_token: rt, expires_in: 900 });
      return;
    }

    if (path === "/token/refresh" && req.method === "POST") {
      const body = await readBody(req); const form = parseForm(body);
      const rth = sha256(form.refresh_token ?? "");
      const record = refreshTokens.get(rth);
      if (!record) { sendJson(res, 401, { error: "Invalid token" }); return; }
      if (record.revoked) {
        for (const [h, r] of refreshTokens) { if (r.family === record.family) r.revoked = true; }
        sendJson(res, 401, { error: "Token reuse detected — all tokens revoked" }); return;
      }
      if (record.exp < Date.now()) { sendJson(res, 401, { error: "Expired" }); return; }
      record.revoked = true;
      const newRt = crypto.randomBytes(48).toString("base64url");
      refreshTokens.set(sha256(newRt), { username: record.username, family: record.family, exp: Date.now() + 604800000, revoked: false });
      sendJson(res, 200, { access_token: crypto.randomUUID(), refresh_token: newRt, expires_in: 900 });
      return;
    }

    if (path === "/token-rotation") {
      sendHtml(res, page("Token Rotation", "<h2>Token Rotation</h2><p>Use client to test.</p>"));
      return;
    }

    // === Gateway ===
    if (path === "/gateway/token" && req.method === "POST") {
      const body = await readBody(req); const form = parseForm(body);
      if (USERS[form.username] !== form.password) { sendJson(res, 401, { error: "Invalid" }); return; }
      const token = crypto.randomUUID();
      gatewayTokens.set(token, { username: form.username, scopes: ["read", "write"] });
      sendJson(res, 200, { access_token: token });
      return;
    }

    if (path.startsWith("/gateway/")) {
      const auth = req.headers["authorization"] ?? "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
      const record = token ? gatewayTokens.get(token) : null;
      if (!record) { sendJson(res, 401, { error: "Invalid token" }); return; }

      if (path === "/gateway/validate") {
        sendJson(res, 200, { active: true, sub: record.username, scopes: record.scopes });
        return;
      }
      if (path === "/gateway/api/resource") {
        sendJson(res, 200, { message: `Resource accessed by ${record.username}` });
        return;
      }
    }

    sendHtml(res, "Not found", 404);
  } catch {
    sendJson(res, 500, { error: "Internal error" });
  }
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "127.0.0.1", () => console.log(`Auth Patterns Server at http://127.0.0.1:${PORT}`));
