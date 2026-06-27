import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";

const SSO_SECRET = process.env.SSO_SECRET ?? "sso-secret-change-me";
const SSO_DOMAIN = "http://localhost:8000";
const TOKEN_TTL = 60;

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const USERS: Record<string, string> = {
  alice: process.env.ALICE_PASSWORD ?? "password-alice",
  bob: process.env.BOB_PASSWORD ?? "password-bob",
};

function base64url(buf: Buffer): string { return buf.toString("base64url"); }

function makeSSOToken(username: string): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = { iss: SSO_DOMAIN, sub: username, iat: now, exp: now + TOKEN_TTL, jti: crypto.randomUUID(), type: "sso" };
  const h = base64url(Buffer.from(JSON.stringify(header)));
  const p = base64url(Buffer.from(JSON.stringify(payload)));
  const sig = crypto.sign("sha256", Buffer.from(`${h}.${p}`), privateKey);
  return `${h}.${p}.${base64url(sig)}`;
}

function verifySSOToken(token: string): any | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const valid = crypto.verify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, Buffer.from(parts[2], "base64url"));
    if (!valid) return null;
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    if (payload.iss !== SSO_DOMAIN || payload.type !== "sso" || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

function sendHtml(res: ServerResponse, html: string, status = 200) {
  res.writeHead(status, { "Content-Type": "text/html" });
  res.end(html);
}

function sendRedirect(res: ServerResponse, loc: string) {
  res.writeHead(302, { Location: loc });
  res.end();
}

function setCookie(res: ServerResponse, name: string, value: string, maxAge: number) {
  res.setHeader("Set-Cookie", `${name}=${value}; HttpOnly; SameSite=Lax; Max-Age=${maxAge}; Path=/`);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => { const c: Buffer[] = []; req.on("data", (d) => c.push(d)); req.on("end", () => resolve(Buffer.concat(c).toString())); });
}

function parseForm(body: string): Record<string, string> {
  const r: Record<string, string> = {};
  for (const p of body.split("&")) { const [k, ...v] = p.split("="); r[decodeURIComponent(k)] = decodeURIComponent(v.join("=")); }
  return r;
}

function parseCookie(cookie: string): Record<string, string> {
  const r: Record<string, string> = {};
  for (const p of cookie.split(";")) { const [k, ...v] = p.trim().split("="); r[k] = v.join("="); }
  return r;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;

  try {
    // GET /sso/login
    if (path === "/sso/login" && req.method === "GET") {
      const redirect = url.searchParams.get("redirect") ?? "";
      sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:400px;margin:40px auto">
<h2>SSO Login</h2>
<p>Sign in to access <code>${redirect}</code></p>
<form method="post" action="/sso/login">
<input type="hidden" name="redirect" value="${redirect}">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">Sign In</button></p>
</form></body></html>`);
      return;
    }

    // POST /sso/login
    if (path === "/sso/login" && req.method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);
      const expected = USERS[form.username];
      if (!expected || expected !== form.password) {
        sendHtml(res, "Invalid credentials", 401);
        return;
      }
      const token = makeSSOToken(form.username);
      const redirect = form.redirect;
      setCookie(res, "sso_session", token, 86400);
      sendRedirect(res, `${redirect}?token=${token}`);
      return;
    }

    // GET /sso/validate
    if (path === "/sso/validate") {
      const token = url.searchParams.get("token") ?? "";
      const payload = verifySSOToken(token);
      if (!payload) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid token" }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ sub: payload.sub, valid: true }));
      return;
    }

    // GET /sso/check
    if (path === "/sso/check") {
      const cookies = parseCookie(req.headers.cookie ?? "");
      const payload = verifySSOToken(cookies.sso_session ?? "");
      if (!payload) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "No SSO session" }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ sub: payload.sub, valid: true }));
      return;
    }

    // GET /sso/logout
    if (path === "/sso/logout") {
      res.setHeader("Set-Cookie", "sso_session=; HttpOnly; Max-Age=0; Path=/");
      sendHtml(res, "<h2>Logged out of SSO</h2>");
      return;
    }

    sendHtml(res, "Not found", 404);
  } catch { sendHtml(res, "Error", 500); }
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "0.0.0.0", () => console.log(`SSO Server at http://localhost:${PORT}`));
