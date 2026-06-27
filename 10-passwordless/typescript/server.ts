import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";

const SECRET_KEY = process.env.MAGIC_LINK_SECRET ?? "change-me-in-production";
const TOKEN_TTL = parseInt(process.env.TOKEN_TTL_SECONDS ?? "900", 10);

const tokenHashes: Record<string, { email: string; exp: number; created_at: string }> = {};
const usedTokens = new Set<string>();

const users: Record<string, string> = {
  "alice@example.com": crypto.randomUUID(),
  "bob@example.com": crypto.randomUUID(),
};

function hmacSign(payload: string): string {
  return crypto.createHmac("sha256", SECRET_KEY).update(payload).digest("hex");
}

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
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

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;

  try {
    if (path === "/" && req.method === "GET") {
      sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>Passwordless (Magic Link) Demo</h2>
<form method="post" action="/auth/request">
<p><label>Email: <input name="email" value="alice@example.com"></label></p>
<p><button type="submit">Send Magic Link</button></p>
</form></body></html>`);
      return;
    }

    if (path === "/auth/request" && req.method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);
      const email = form.email;

      if (!users[email]) { sendJson(res, 404, { error: "Unknown email" }); return; }

      const tokenId = crypto.randomUUID();
      const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL;
      const payload = `${email}:${tokenId}:${exp}`;
      const sig = hmacSign(payload);
      const token = `${payload}.${sig}`;
      const th = hashToken(token);

      tokenHashes[th] = { email, exp, created_at: new Date().toISOString() };

      const magicUrl = `http://127.0.0.1:8000/auth/verify?token=${encodeURIComponent(token)}`;
      console.log(`\n  [LOG] Magic link for ${email}:`);
      console.log(`  [LOG]   ${magicUrl}\n`);

      sendJson(res, 200, { message: `Magic link sent to ${email}`, magic_url: magicUrl, expires_in: TOKEN_TTL });
      return;
    }

    if (path === "/auth/verify" && req.method === "GET") {
      const rawToken = url.searchParams.get("token") ?? "";
      const parts = rawToken.split(".");
      if (parts.length < 2) { sendHtml(res, "Invalid token format", 400); return; }
      const sig = parts.pop()!;
      const payload = parts.join(".");

      const expectedSig = hmacSign(payload);
      if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) { sendHtml(res, "Invalid signature", 401); return; }

      const [email, tokenId, expStr] = payload.split(":");
      const exp = parseInt(expStr, 10);
      if (Math.floor(Date.now() / 1000) > exp) { sendHtml(res, "Token expired", 401); return; }

      const th = hashToken(rawToken);
      if (usedTokens.has(th)) { sendHtml(res, "Token already used", 401); return; }
      usedTokens.add(th);

      const sessionToken = crypto.randomUUID();
      sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>Authenticated ✓</h2>
<p>Welcome, <strong>${email}</strong>!</p>
<p>Session: <code>${sessionToken.slice(0, 16)}...</code></p>
</body></html>`);
      return;
    }

    sendHtml(res, "Not found", 404);
  } catch {
    sendJson(res, 400, { error: "Bad request" });
  }
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "127.0.0.1", () => console.log(`Magic Link Server at http://127.0.0.1:${PORT}`));
