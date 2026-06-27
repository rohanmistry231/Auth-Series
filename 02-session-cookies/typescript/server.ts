import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";

const SESSION_SECRET = process.env.SESSION_SECRET ?? "dev-secret-change-in-production-32chars";
const SESSION_TTL = 3600_000; // 1 hour in ms
const IDLE_TTL = 900_000; // 15 minutes

const USERS: Record<string, string> = {
  alice: process.env.ALICE_PASSWORD ?? "password-alice",
  bob: process.env.BOB_PASSWORD ?? "password-bob",
};

interface Session {
  user_id: string;
  role: string;
  expires_absolute: number;
  expires_idle: number;
  csrf_token: string | null;
}

const store = new Map<string, Session>();

function sign(value: string): string {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function createSignedSessionId(): string {
  const sessionId = crypto.randomUUID();
  return `${sessionId}.${sign(sessionId)}`;
}

function verifySignedSessionId(signed: string): string | null {
  const parts = signed.split(".");
  if (parts.length !== 2) return null;
  const [sessionId, signature] = parts;
  const expected = sign(sessionId);
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return null;
  }
  return sessionId;
}

function getSession(req: IncomingMessage): Session | null {
  const rawCookie = parseCookie(req.headers.cookie ?? "");
  const raw = rawCookie.session_id;
  if (!raw) return null;

  const sid = verifySignedSessionId(raw);
  if (!sid) return null;

  const session = store.get(sid);
  if (!session) return null;

  const now = Date.now();
  if (now > session.expires_absolute) {
    store.delete(sid);
    return null;
  }
  if (now > session.expires_idle) {
    store.delete(sid);
    return null;
  }

  session.expires_idle = now + IDLE_TTL;
  return session;
}

function parseCookie(cookie: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const pair of cookie.split(";")) {
    const [key, ...rest] = pair.trim().split("=");
    if (key) result[key] = rest.join("=");
  }
  return result;
}

function setSessionCookie(res: ServerResponse, signed: string, maxAge: number) {
  res.setHeader("Set-Cookie", [
    `session_id=${signed}`,
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    `Max-Age=${maxAge}`,
    "Path=/",
  ].join("; "));
}

function deleteSessionCookie(res: ServerResponse) {
  res.setHeader("Set-Cookie", [
    "session_id=;",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Max-Age=0",
    "Path=/",
  ].join("; "));
}

function sendJson(res: ServerResponse, status: number, data: Record<string, unknown>) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString()));
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;
  const method = req.method ?? "GET";

  try {
    if (path === "/public" && method === "GET") {
      sendJson(res, 200, { message: "This is public — no session required" });
      return;
    }

    if (path === "/csrf-token" && method === "GET") {
      const session = getSession(req);
      if (!session) {
        sendJson(res, 401, { error: "Not authenticated" });
        return;
      }
      const token = crypto.randomBytes(32).toString("hex");
      session.csrf_token = token;
      sendJson(res, 200, { csrf_token: token });
      return;
    }

    if (path === "/login" && method === "POST") {
      const data = await readBody(req);
      const username = String(data.username ?? "");
      const password = String(data.password ?? "");

      const expected = USERS[username];
      if (!expected || expected !== password) {
        sendJson(res, 401, { error: "Invalid credentials" });
        return;
      }

      const signed = createSignedSessionId();
      const sid = signed.split(".")[0];
      const now = Date.now();

      store.set(sid, {
        user_id: username,
        role: username === "alice" ? "admin" : "user",
        expires_absolute: now + SESSION_TTL,
        expires_idle: now + IDLE_TTL,
        csrf_token: null,
      });

      setSessionCookie(res, signed, SESSION_TTL / 1000);
      sendJson(res, 200, { message: `Logged in as ${username}` });
      return;
    }

    if (path === "/me" && method === "GET") {
      const session = getSession(req);
      if (!session) {
        sendJson(res, 401, { error: "Not authenticated" });
        return;
      }
      sendJson(res, 200, { user_id: session.user_id, role: session.role });
      return;
    }

    if (path === "/data" && method === "POST") {
      const session = getSession(req);
      if (!session) {
        sendJson(res, 401, { error: "Not authenticated" });
        return;
      }

      const data = await readBody(req);
      const token = String(data.csrf_token ?? "");

      if (!session.csrf_token || session.csrf_token !== token) {
        sendJson(res, 403, { error: "Invalid CSRF token" });
        return;
      }

      session.csrf_token = null;
      sendJson(res, 200, { message: "Data created", data: data.payload });
      return;
    }

    if (path === "/logout" && method === "POST") {
      const rawCookie = parseCookie(req.headers.cookie ?? "");
      const raw = rawCookie.session_id;
      if (raw) {
        const sid = raw.split(".")[0];
        store.delete(sid);
      }
      deleteSessionCookie(res);
      sendJson(res, 200, { message: "Logged out" });
      return;
    }

    sendJson(res, 404, { error: "Not found" });
  } catch (err) {
    sendJson(res, 400, { error: "Bad request" });
  }
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "127.0.0.1", () => {
  console.log(`Server running at http://127.0.0.1:${PORT}`);
});
