import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";

const RATE_WINDOW = 60000;
const RATE_MAX = 10;

const store = new Map<string, any>();

function hashKey(key: string): string {
  return crypto.createHash("sha256").update(key).digest("hex");
}

function generateKey(prefix = "user_stripe_key"): string {
  const raw = crypto.randomBytes(32).toString("base64url");
  return `${prefix}_${raw}`;
}

function createKey(name: string, scopes: string[], expiresInDays?: number) {
  const key = generateKey();
  const keyHash = hashKey(key);
  const keyId = crypto.randomUUID();
  const now = Date.now();

  const entry: any = {
    id: keyId,
    name,
    prefix: key.split("_").slice(0, 2).join("_"),
    key_hash: keyHash,
    key_suffix: key.slice(-4),
    scopes,
    created_at: now,
    expires_at: expiresInDays ? now + expiresInDays * 86400000 : null,
    last_used: null,
    rate_window_start: 0,
    rate_window_count: 0,
  };
  store.set(keyHash, entry);
  return { ...entry, key };
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

function authenticate(req: IncomingMessage): any {
  let apiKey = req.headers["x-api-key"] as string ?? "";
  const auth = req.headers["authorization"] as string ?? "";
  if (auth.startsWith("Bearer ")) apiKey = auth.slice(7);

  if (!apiKey) {
    sendJson(res, 401, { error: "Missing API key" });
    return null;
  }

  const keyHash = hashKey(apiKey);
  const entry = store.get(keyHash);
  if (!entry) {
    sendJson(res, 403, { error: "Invalid API key" });
    return null;
  }

  if (entry.expires_at && Date.now() > entry.expires_at) {
    sendJson(res, 403, { error: "API key expired" });
    return null;
  }

  if (Date.now() - entry.rate_window_start > RATE_WINDOW) {
    entry.rate_window_start = Date.now();
    entry.rate_window_count = 0;
  }
  entry.rate_window_count++;
  if (entry.rate_window_count > RATE_MAX) {
    sendJson(res, 429, { error: "Rate limit exceeded" });
    return null;
  }

  entry.last_used = Date.now();
  return entry;
}

let res: ServerResponse;

const server = http.createServer(async (req, res2) => {
  res = res2;
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;
  const method = req.method ?? "GET";

  try {
    // POST /keys — Create
    if (path === "/keys" && method === "POST") {
      const body = JSON.parse(await readBody(req));
      const entry = createKey(body.name ?? "Untitled", body.scopes ?? ["read"], body.expires_in_days);
      sendJson(res, 200, {
        id: entry.id, name: entry.name, prefix: entry.prefix,
        key_suffix: entry.key_suffix, key: entry.key, scopes: entry.scopes,
      });
      return;
    }

    // POST /keys/:id/rotate
    const rotateMatch = path.match(/^\/keys\/([^/]+)\/rotate$/);
    if (rotateMatch && method === "POST") {
      const keyId = rotateMatch[1];
      for (const [kh, entry] of store) {
        if (entry.id === keyId) {
          const newEntry = createKey(entry.name, entry.scopes, entry.expires_at ? 30 : undefined);
          store.delete(kh);
          sendJson(res, 200, { message: "Key rotated", old_id: keyId, new_id: newEntry.id, new_key: newEntry.key });
          return;
        }
      }
      sendJson(res, 404, { error: "Key not found" });
      return;
    }

    // POST /keys/:id/revoke
    const revokeMatch = path.match(/^\/keys\/([^/]+)\/revoke$/);
    if (revokeMatch && method === "POST") {
      const keyId = revokeMatch[1];
      for (const [kh, entry] of store) {
        if (entry.id === keyId) { store.delete(kh); sendJson(res, 200, { message: "Key revoked" }); return; }
      }
      sendJson(res, 404, { error: "Key not found" });
      return;
    }

    // GET /keys
    if (path === "/keys" && method === "GET") {
      const result: any[] = [];
      for (const entry of store.values()) {
        result.push({ id: entry.id, name: entry.name, prefix: entry.prefix, key_suffix: entry.key_suffix, scopes: entry.scopes });
      }
      sendJson(res, 200, result);
      return;
    }

    // GET /api/public
    if (path === "/api/public") {
      sendJson(res, 200, { message: "Public endpoint" });
      return;
    }

    // GET /api/data
    if (path === "/api/data") {
      const entry = authenticate(req);
      if (!entry) return;
      sendJson(res, 200, { message: "Protected data", key_name: entry.name, scopes: entry.scopes });
      return;
    }

    // GET /api/admin
    if (path === "/api/admin") {
      const entry = authenticate(req);
      if (!entry) return;
      if (!entry.scopes.includes("admin")) {
        sendJson(res, 403, { error: "Admin scope required" });
        return;
      }
      sendJson(res, 200, { message: "Admin data", key_name: entry.name });
      return;
    }

    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    sendJson(res, 400, { error: "Bad request" });
  }
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "127.0.0.1", () => console.log(`API Key Server at http://127.0.0.1:${PORT}`));
