import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";
import { authenticator } from "otplib";

const USERS: Record<string, any> = {
  alice: {
    password: process.env.ALICE_PASSWORD ?? "password-alice",
    mfa_secret: null,
    mfa_enabled: false,
    backup_codes: [],
  },
};

const usedBackupCodes = new Set<string>();

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

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;

  try {
    if (path === "/" && req.method === "GET") {
      sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>MFA Demo</h2>
<form method="post" action="/setup"><p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p><p><button type="submit">Setup MFA</button></p></form>
<hr>
<form method="post" action="/login"><p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><label>TOTP: <input name="totp"></label></p><p><button type="submit">Login</button></p></form></body></html>`);
      return;
    }

    if (path === "/setup" && req.method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);
      const user = USERS[form.username];
      if (!user || user.password !== form.password) { sendJson(res, 401, { error: "Invalid credentials" }); return; }

      const secret = authenticator.generateSecret();
      user.mfa_secret = secret;
      user.mfa_enabled = false;

      const uri = authenticator.keyuri(form.username, "AuthSeries MFA", secret);
      sendJson(res, 200, { secret, qr_uri: uri, message: "Scan QR with authenticator app" });
      return;
    }

    if (path === "/mfa/verify" && req.method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);
      const user = USERS[form.username];
      if (!user || !user.mfa_secret) { sendJson(res, 400, { error: "MFA not setup" }); return; }

      const isValid = authenticator.check(form.totp, user.mfa_secret);
      if (!isValid) { sendJson(res, 401, { error: "Invalid TOTP" }); return; }

      user.mfa_enabled = true;
      const codes = Array.from({ length: 5 }, () => crypto.randomBytes(4).toString("hex").toUpperCase());
      user.backup_codes = codes;

      sendJson(res, 200, { message: "MFA enabled", backup_codes: codes, warning: "Save these codes" });
      return;
    }

    if (path === "/login" && req.method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);
      const user = USERS[form.username];
      if (!user || user.password !== form.password) { sendJson(res, 401, { error: "Invalid credentials" }); return; }

      if (user.mfa_enabled) {
        if (!form.totp) { sendJson(res, 401, { error: "TOTP required" }); return; }
        const isValid = authenticator.check(form.totp, user.mfa_secret);
        if (!isValid) { sendJson(res, 401, { error: "Invalid TOTP" }); return; }
      }

      sendJson(res, 200, { access_token: crypto.randomUUID(), message: `Authenticated as ${form.username}` });
      return;
    }

    if (path === "/recovery" && req.method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);
      const user = USERS[form.username];
      if (!user) { sendJson(res, 401, { error: "Invalid username" }); return; }

      if (usedBackupCodes.has(form.backup_code)) { sendJson(res, 401, { error: "Code already used" }); return; }
      if (!user.backup_codes.includes(form.backup_code)) { sendJson(res, 401, { error: "Invalid backup code" }); return; }

      usedBackupCodes.add(form.backup_code);
      const remaining = user.backup_codes.filter((c: string) => !usedBackupCodes.has(c)).length;
      sendJson(res, 200, { access_token: crypto.randomUUID(), message: `Recovery login as ${form.username}`, codes_remaining: remaining });
      return;
    }

    sendHtml(res, "Not found", 404);
  } catch (err) {
    sendJson(res, 400, { error: "Bad request" });
  }
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "127.0.0.1", () => console.log(`MFA Server at http://127.0.0.1:${PORT}`));
