import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";

const REALM = "Auth Series";

const USERS: Record<string, string> = {
  alice: process.env.ALICE_PASSWORD ?? "password-alice",
  bob: process.env.BOB_PASSWORD ?? "password-bob",
};

const usedNonces = new Set<string>();

function md5(s: string): string {
  return crypto.createHash("md5").update(s).digest("hex");
}

function md5hex(data: string): string {
  return crypto.createHash("md5").update(data).digest("hex");
}

function computeHa1(username: string, password: string): string {
  return md5(`${username}:${REALM}:${password}`);
}

function computeHa2(method: string, uri: string): string {
  return md5(`${method}:${uri}`);
}

function computeResponse(ha1: string, nonce: string, nc: string, cnonce: string, qop: string, ha2: string): string {
  return md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
}

function parseDigestHeader(header: string): Record<string, string> {
  if (!header.startsWith("Digest ")) return {};
  const parts = header.slice(7);
  const params: Record<string, string> = {};
  for (const part of parts.split(",")) {
    const eqIdx = part.indexOf("=");
    if (eqIdx === -1) continue;
    const k = part.slice(0, eqIdx).trim();
    let v = part.slice(eqIdx + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    params[k] = v;
  }
  return params;
}

function sendHtml(res: ServerResponse, html: string, status = 200) {
  res.writeHead(status, { "Content-Type": "text/html;charset=utf-8" });
  res.end(html);
}

function sendJson(res: ServerResponse, status: number, data: any, extraHeaders?: Record<string, string>) {
  res.writeHead(status, { "Content-Type": "application/json", ...extraHeaders });
  res.end(JSON.stringify(data));
}

function unauthorized(res: ServerResponse) {
  const nonce = crypto.randomBytes(16).toString("hex");
  const opaque = crypto.randomBytes(16).toString("hex");
  res.writeHead(401, {
    "WWW-Authenticate": `Digest realm="${REALM}",nonce="${nonce}",opaque="${opaque}",qop="auth",algorithm=MD5`,
    "Content-Type": "text/plain",
  });
  res.end("Unauthorized");
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;

  if (path === "/") {
    sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Digest Auth Demo</h2>
<p><a href="/protected">/protected</a> — browser will prompt for creds.</p></body></html>`);
    return;
  }

  if (path === "/protected") {
    const authHeader = req.headers["authorization"] ?? "";
    const params = parseDigestHeader(authHeader);
    if (!params.username) { unauthorized(res); return; }

    const username = params.username;
    const password = USERS[username];
    if (!password) { unauthorized(res); return; }

    const nonce = params.nonce ?? "";
    if (usedNonces.has(nonce)) { unauthorized(res); return; }

    const uri = params.uri ?? path;
    const responseClient = params.response ?? "";
    const qop = params.qop ?? "auth";
    const nc = params.nc ?? "00000001";
    const cnonce = params.cnonce ?? "";

    const ha1 = computeHa1(username, password);
    const ha2 = computeHa2(req.method ?? "GET", uri);
    const expected = computeResponse(ha1, nonce, nc, cnonce, qop, ha2);

    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(responseClient))) {
      unauthorized(res);
      return;
    }

    usedNonces.add(nonce);
    sendJson(res, 200, { message: `Authenticated as ${username}`, scheme: "Digest", realm: REALM });
    return;
  }

  sendHtml(res, "Not found", 404);
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "127.0.0.1", () => console.log(`Digest Auth Server at http://127.0.0.1:${PORT}`));
