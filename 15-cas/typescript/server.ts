import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";

const USERS: Record<string, string> = {
  alice: process.env.ALICE_PASSWORD ?? "password-alice",
  bob: process.env.BOB_PASSWORD ?? "password-bob",
};

const tickets = new Map<string, any>();
const sessions = new Map<string, string>();

const SERVICE_URL = "http://127.0.0.1:8000/protected";

function sendHtml(res: ServerResponse, html: string, status = 200) {
  res.writeHead(status, { "Content-Type": "text/html;charset=utf-8" });
  res.end(html);
}

function sendText(res: ServerResponse, text: string, status = 200) {
  res.writeHead(status, { "Content-Type": "text/plain" });
  res.end(text);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => { const c: Buffer[] = []; req.on("data", (d) => c.push(d)); req.on("end", () => resolve(Buffer.concat(c).toString())); });
}

function parseForm(body: string): Record<string, string> {
  const r: Record<string, string> = {};
  for (const p of body.split("&")) { const [k, ...v] = p.split("="); r[decodeURIComponent(k)] = decodeURIComponent(v.join("=")); }
  return r;
}

function pageHtml(title: string, body: string): string {
  return `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">${body}</body></html>`;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;

  try {
    // App: Home
    if (path === "/") {
      sendHtml(res, pageHtml("CAS Demo", `
<h2>CAS Demo</h2>
<p>This app uses <strong>CAS</strong> for single sign-on.</p>
<p><a href="/protected">Protected resource</a></p>`));
      return;
    }

    // App: Protected
    if (path === "/protected") {
      const ticket = url.searchParams.get("ticket");

      if (ticket) {
        const validateResp = await fetch(`http://127.0.0.1:8000/validate?ticket=${ticket}&service=${encodeURIComponent(SERVICE_URL)}`);
        const text = await validateResp.text();
        const lines = text.split("\n");
        if (lines[0] === "yes") {
          const username = lines.slice(1).join("\n").trim();
          const sessionId = crypto.randomUUID();
          sessions.set(sessionId, username);
          res.writeHead(302, {
            Location: "/protected",
            "Set-Cookie": `session_id=${sessionId}; HttpOnly; SameSite=Lax; Path=/`,
          });
          res.end();
          return;
        }
        sendHtml(res, pageHtml("CAS Failed", `<h2>CAS Login Failed</h2><p>${text}</p><p><a href="/">← Back</a></p>`));
        return;
      }

      // No ticket — redirect to CAS
      res.writeHead(302, { Location: `/login?service=${encodeURIComponent(SERVICE_URL)}` });
      res.end();
      return;
    }

    // CAS: Login form
    if (path === "/login" && req.method === "GET") {
      const service = url.searchParams.get("service") ?? "";
      const error = url.searchParams.get("error") ?? "";
      const errHtml = error ? `<p style="color:red">${error}</p>` : "";
      sendHtml(res, pageHtml("CAS Login", `
<h2>CAS Login</h2>
${errHtml}
<form method="post" action="/login">
  <input type="hidden" name="service" value="${service}">
  <p><label>Username: <input name="username" value="alice"></label></p>
  <p><label>Password: <input name="password" type="password"></label></p>
  <p><button type="submit">Login</button></p>
</form>`));
      return;
    }

    // CAS: Login submit
    if (path === "/login" && req.method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);
      const service = form.service ?? "";
      const username = form.username ?? "";
      const password = form.password ?? "";

      if (!USERS[username] || USERS[username] !== password) {
        res.writeHead(302, { Location: `/login?service=${encodeURIComponent(service)}&error=Invalid+credentials` });
        res.end();
        return;
      }

      const ticket = `ST-${crypto.randomBytes(16).toString("hex")}`;
      tickets.set(ticket, { username, service, exp: Date.now() + 300000, used: false });

      res.writeHead(302, { Location: `${service}?ticket=${ticket}` });
      res.end();
      return;
    }

    // CAS: Validate
    if (path === "/validate") {
      const ticket = url.searchParams.get("ticket") ?? "";
      const service = url.searchParams.get("service") ?? "";

      const t = tickets.get(ticket);
      if (!t) { sendText(res, "no\nInvalid ticket"); return; }
      if (t.used) { sendText(res, "no\nTicket already used"); return; }
      if (t.exp < Date.now()) { sendText(res, "no\nTicket expired"); return; }
      if (t.service !== service) { sendText(res, "no\nService mismatch"); return; }

      t.used = true;
      sendText(res, `yes\n${t.username}`);
      return;
    }

    sendHtml(res, "Not found", 404);
  } catch {
    sendText(res, "Internal error", 500);
  }
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "127.0.0.1", () => console.log(`CAS Server at http://127.0.0.1:${PORT}`));
