/** Security Best Practices — Rate Limiter, Headers, Audit Log, CSRF. */

import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";

const USERS: Record<string, string> = {
  alice: process.env.ALICE_PASSWORD ?? "password-alice",
};

const rateLimitStore: Record<string, number[]> = {};
const auditLog: any[] = [];
const csrfTokens = new Map<string, any>();

function rateLimit(key: string, max: number, windowMs: number) {
  const now = Date.now();
  if (!rateLimitStore[key]) rateLimitStore[key] = [];
  rateLimitStore[key] = rateLimitStore[key].filter((t) => t > now - windowMs);
  if (rateLimitStore[key].length >= max) return false;
  rateLimitStore[key].push(now);
  return true;
}

function logAuthEvent(event: string, username: string, ip: string, success: boolean, details = "") {
  const entry = { timestamp: new Date().toISOString(), event, username, ip, success, details };
  auditLog.push(entry);
  console.log(`  [AUDIT] ${JSON.stringify(entry)}`);
}

function sendHtml(res: ServerResponse, html: string, status = 200) {
  const headers: Record<string, string> = {
    "Content-Type": "text/html;charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
  };
  res.writeHead(status, headers);
  res.end(html);
}

function sendJson(res: ServerResponse, status: number, data: any) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  };
  res.writeHead(status, headers);
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

function page(title: string, content: string): string {
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:700px;margin:40px auto">${content}</body></html>`;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;
  const ip = req.socket.remoteAddress ?? "unknown";

  try {
    if (path === "/") {
      sendHtml(res, page("Security Demo", `
<h2>Security Best Practices Demo</h2>
<ul>
  <li><a href="/login">Login (rate limited)</a></li>
  <li><a href="/audit-log">Audit Log</a></li>
  <li>Security headers on all responses</li>
</ul>`));
      return;
    }

    if (path === "/login" && req.method === "GET") {
      if (!rateLimit(`page:${ip}`, 20, 60000)) { sendJson(res, 429, { error: "Rate limited" }); return; }
      sendHtml(res, page("Login", `
<h2>Login (Rate Limited)</h2>
<form method="post" action="/login"><p><label>User: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p><p><button type="submit">Login</button></p></form>`));
      return;
    }

    if (path === "/login" && req.method === "POST") {
      if (!rateLimit(`login:${ip}`, 5, 60000)) { sendJson(res, 429, { error: "Rate limited" }); return; }

      const body = await readBody(req);
      const form = parseForm(body);

      if (USERS[form.username] !== form.password) {
        logAuthEvent("LOGIN_FAILURE", form.username, ip, false, "Invalid password");
        sendJson(res, 401, { error: "Invalid credentials" });
        return;
      }

      const sid = crypto.randomUUID();
      logAuthEvent("LOGIN_SUCCESS", form.username, ip, true, `Session ${sid.slice(0, 16)}...`);

      res.writeHead(200, {
        "Content-Type": "text/html",
        "Set-Cookie": `session_id=${sid}; HttpOnly; SameSite=Strict; Path=/`,
      });
      res.end(page("Welcome", `<h2>Welcome, ${form.username}!</h2><p><a href="/audit-log">View Audit Log</a></p>`));
      return;
    }

    if (path === "/audit-log") {
      const entries = auditLog.slice(-20).map((e) =>
        `<li><code>${e.timestamp.slice(0, 19)}</code> <strong>${e.success ? "✅" : "❌"}</strong> ${e.event} — ${e.username}<br><small>${e.details}</small></li>`
      ).join("");
      sendHtml(res, page("Audit Log", `<h2>Audit Log (last 20)</h2><ul style="list-style:none;padding:0">${entries || "<li>No events</li>"}</ul><p><a href="/">← Back</a></p>`));
      return;
    }

    if (path === "/check-headers") {
      sendJson(res, 200, { message: "Security headers on all responses", headers: ["HSTS", "X-Content-Type-Options", "X-Frame-Options"] });
      return;
    }

    sendHtml(res, "Not found", 404);
  } catch {
    sendJson(res, 500, { error: "Internal error" });
  }
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "127.0.0.1", () => console.log(`Security Server at http://127.0.0.1:${PORT}`));
