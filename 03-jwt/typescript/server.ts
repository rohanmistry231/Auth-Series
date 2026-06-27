import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";

const ACCESS_TTL = 900; // 15 minutes
const REFRESH_TTL = 604800; // 7 days
const ISSUER = "auth-series";

const HS256_SECRET = Buffer.from(
  process.env.JWT_HS256_SECRET ?? "change-me-to-a-256-bit-secret-in-production",
);

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const USERS: Record<string, string> = {
  alice: process.env.ALICE_PASSWORD ?? "password-alice",
  bob: process.env.BOB_PASSWORD ?? "password-bob",
};

// Refresh token store (revocable)
const refreshStore = new Map<string, { sub: string; exp: number }>();

// ---------------------------------------------------------------------------
// JWT helpers (manual, no external deps)
// ---------------------------------------------------------------------------

function base64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function base64urlDecode(str: string): Buffer {
  return Buffer.from(str, "base64url");
}

function signHmac(data: string, secret: Buffer): Buffer {
  return crypto.createHmac("sha256", secret).update(data).digest();
}

function signRsa(data: string, key: string): Buffer {
  return crypto.sign("sha256", Buffer.from(data), key);
}

function verifyRsa(data: string, sig: Buffer, key: string): boolean {
  return crypto.verify("sha256", Buffer.from(data), key, sig);
}

function encodeJwt(
  payload: Record<string, unknown>,
  key: Buffer | string,
  alg: "HS256" | "RS256",
): string {
  const header = { alg, typ: "JWT" };
  const headerB64 = base64url(Buffer.from(JSON.stringify(header)));
  const payloadB64 = base64url(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  let sig: Buffer;
  if (alg === "HS256") {
    sig = signHmac(signingInput, key as Buffer);
  } else {
    sig = signRsa(signingInput, key as string);
  }

  return `${signingInput}.${base64url(sig)}`;
}

function decodeJwt(
  token: string,
  key: Buffer | string,
  alg: "HS256" | "RS256",
): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [headerB64, payloadB64, sigB64] = parts;

  try {
    const header = JSON.parse(base64urlDecode(headerB64).toString());
    if (header.alg !== alg) return null;

    const signingInput = `${headerB64}.${payloadB64}`;
    const sig = base64urlDecode(sigB64);

    let valid = false;
    if (alg === "HS256") {
      const expected = signHmac(signingInput, key as Buffer);
      valid = crypto.timingSafeEqual(sig, expected);
    } else {
      valid = verifyRsa(signingInput, sig, key as string);
    }

    if (!valid) return null;

    const payload = JSON.parse(base64urlDecode(payloadB64).toString());
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp && payload.exp < now) return null;
    if (payload.nbf && payload.nbf > now) return null;
    if (payload.iss && payload.iss !== ISSUER) return null;

    return payload;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

function makeAccessToken(sub: string, role: string): string {
  const now = Math.floor(Date.now() / 1000);
  return encodeJwt(
    {
      iss: ISSUER,
      sub,
      role,
      iat: now,
      exp: now + ACCESS_TTL,
      type: "access",
      jti: crypto.randomUUID(),
    },
    privateKey,
    "RS256",
  );
}

function makeRefreshToken(sub: string): string {
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID();
  const token = encodeJwt(
    {
      iss: ISSUER,
      sub,
      iat: now,
      exp: now + REFRESH_TTL,
      type: "refresh",
      jti,
    },
    HS256_SECRET,
    "HS256",
  );
  refreshStore.set(jti, { sub, exp: now + REFRESH_TTL });
  return token;
}

function rotateRefresh(oldJti: string, sub: string): string {
  refreshStore.delete(oldJti);
  return makeRefreshToken(sub);
}

function verifyAccessToken(token: string): Record<string, unknown> | null {
  const result = decodeJwt(token, publicKey, "RS256");
  if (result && result.type === "access") return result;
  const hsResult = decodeJwt(token, HS256_SECRET, "HS256");
  if (hsResult && hsResult.type === "access") return hsResult;
  return null;
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

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

function sendJson(res: ServerResponse, status: number, data: Record<string, unknown>) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;
  const method = req.method ?? "GET";

  try {
    // POST /login
    if (path === "/login" && method === "POST") {
      const data = await readBody(req);
      const username = String(data.username ?? "");
      const password = String(data.password ?? "");

      const expected = USERS[username];
      if (!expected || expected !== password) {
        sendJson(res, 401, { error: "Invalid credentials" });
        return;
      }

      const role = username === "alice" ? "admin" : "user";
      sendJson(res, 200, {
        access_token: makeAccessToken(username, role),
        refresh_token: makeRefreshToken(username),
      });
      return;
    }

    // GET /protected
    if (path === "/protected" && method === "GET") {
      const auth = req.headers.authorization ?? "";
      if (!auth.startsWith("Bearer ")) {
        sendJson(res, 401, { error: "Missing or malformed Authorization header" });
        return;
      }
      const token = auth.slice(7);
      const payload = verifyAccessToken(token);
      if (!payload) {
        sendJson(res, 401, { error: "Invalid or expired access token" });
        return;
      }
      sendJson(res, 200, {
        sub: payload.sub,
        role: payload.role,
        message: "You have accessed a protected resource via JWT",
      });
      return;
    }

    // POST /refresh
    if (path === "/refresh" && method === "POST") {
      const data = await readBody(req);
      const refreshToken = String(data.refresh_token ?? "");
      if (!refreshToken) {
        sendJson(res, 400, { error: "Missing refresh_token" });
        return;
      }

      const payload = decodeJwt(refreshToken, HS256_SECRET, "HS256");
      if (!payload || payload.type !== "refresh") {
        sendJson(res, 401, { error: "Invalid or expired refresh token" });
        return;
      }

      const jti = String(payload.jti ?? "");
      const stored = refreshStore.get(jti);
      if (!stored) {
        sendJson(res, 401, { error: "Refresh token has been revoked" });
        return;
      }

      const sub = String(payload.sub ?? "");
      const role = sub === "alice" ? "admin" : "user";

      sendJson(res, 200, {
        access_token: makeAccessToken(sub, role),
        refresh_token: rotateRefresh(jti, sub),
      });
      return;
    }

    // GET /.well-known/jwks.json
    if (path === "/.well-known/jwks.json" && method === "GET") {
      const pub = crypto.createPublicKey(publicKey);
      const keyDetails = pub.export({ format: "jwk" });
      sendJson(res, 200, {
        keys: [{
          kty: keyDetails.kty,
          use: "sig",
          alg: "RS256",
          kid: "auth-series-rsa-1",
          n: keyDetails.n,
          e: keyDetails.e,
        }],
      });
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
