import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";

const TOKEN_TTL = parseInt(process.env.TOKEN_TTL ?? "3600", 10);

const USERS: Record<string, any> = {
  alice: { password: process.env.ALICE_PASSWORD ?? "password-alice", scopes: ["read", "write"] },
  bob: { password: process.env.BOB_PASSWORD ?? "password-bob", scopes: ["read"] },
};

const tokens = new Map<string, any>();

function sha256(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function generateToken(): string {
  return crypto.randomBytes(48).toString("base64url");
}

function sendHtml(res: ServerResponse, html: string, status = 200) {
  res.writeHead(status, { "Content-Type": "text/html;charset=utf-8" });
  res.end(html);
}

function sendJson(res: ServerResponse, status: number, data: any, extraHeaders: Record<string, string> = {}) {
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

function getBearer(req: IncomingMessage): string | null {
  const auth = req.headers["authorization"] ?? "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

function validateToken(tokenStr: string): any {
  const th = sha256(tokenStr);
  const record = tokens.get(th);
  if (!record) return null;
  if (record.revoked) return null;
  if (Math.floor(Date.now() / 1000) > record.exp) return null;
  return record;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;

  try {
    if (path === "/") {
      sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Bearer Token Auth</h2>
<form method="post" action="/login"><p><label>User: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p><p><button type="submit">Get Token</button></p></form>
<form method="get" action="/protected"><p><label>Token: <input name="token" size="50"></label></p>
<p><button type="submit">GET /protected</button></p></form>
<form method="post" action="/introspect"><p><label>Token: <input name="token" size="50"></label></p>
<p><button type="submit">Introspect</button></p></form>
<form method="post" action="/revoke"><p><label>Token: <input name="token" size="50"></label></p>
<p><button type="submit">Revoke</button></p></form>
</body></html>`);
      return;
    }

    if (path === "/login" && req.method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);
      const user = USERS[form.username];
      if (!user || user.password !== form.password) { sendJson(res, 401, { error: "Invalid credentials" }); return; }

      const token = generateToken();
      const th = sha256(token);
      const now = Math.floor(Date.now() / 1000);
      tokens.set(th, { sub: form.username, scopes: user.scopes, iat: now, exp: now + TOKEN_TTL, revoked: false });

      sendJson(res, 200, { access_token: token, token_type: "Bearer", expires_in: TOKEN_TTL, scope: user.scopes.join(" ") });
      return;
    }

    if (path === "/protected" && req.method === "GET") {
      const tokenStr = url.searchParams.get("token") ?? getBearer(req);
      if (!tokenStr) { sendJson(res, 401, { error: "Missing token" }); return; }
      const record = validateToken(tokenStr);
      if (!record) { sendJson(res, 401, { error: "Invalid or expired token" }); return; }
      sendJson(res, 200, { message: `Authenticated as ${record.sub}`, scopes: record.scopes, exp: record.exp });
      return;
    }

    if (path === "/introspect" && req.method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);
      const th = sha256(form.token ?? "");
      const record = tokens.get(th);
      if (!record || record.revoked || Math.floor(Date.now() / 1000) > record.exp) {
        sendJson(res, 200, { active: false }); return;
      }
      sendJson(res, 200, { active: true, sub: record.sub, scope: record.scopes.join(" "), token_type: "Bearer", exp: record.exp, iat: record.iat });
      return;
    }

    if (path === "/revoke" && req.method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);
      const th = sha256(form.token ?? "");
      const record = tokens.get(th);
      if (record) record.revoked = true;
      sendJson(res, 200, { result: "ok" });
      return;
    }

    sendHtml(res, "Not found", 404);
  } catch {
    sendJson(res, 500, { error: "Internal error" });
  }
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "127.0.0.1", () => console.log(`Bearer Token Server at http://127.0.0.1:${PORT}`));
