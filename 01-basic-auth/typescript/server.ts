import http from "node:http";

const USERS: Record<string, string> = {
  alice: process.env.ALICE_PASSWORD ?? "password-alice",
  bob: process.env.BOB_PASSWORD ?? "password-bob",
};

function decodeBasicAuth(header: string | undefined): { username: string; password: string } | null {
  if (!header || !header.startsWith("Basic ")) return null;

  const base64 = header.slice(6);
  const decoded = Buffer.from(base64, "base64").toString("utf-8");
  const colonIndex = decoded.indexOf(":");

  if (colonIndex === -1) return null;

  return {
    username: decoded.slice(0, colonIndex),
    password: decoded.slice(colonIndex + 1),
  };
}

function authenticate(header: string | undefined): string | null {
  const creds = decodeBasicAuth(header);
  if (!creds) return null;

  const expected = USERS[creds.username];
  if (!expected || expected !== creds.password) return null;

  return creds.username;
}

function sendJson(
  res: http.ServerResponse,
  status: number,
  data: Record<string, unknown>,
) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

const server = http.createServer((req, res) => {
  if (!req.url) {
    sendJson(res, 400, { error: "Bad request" });
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  if (path === "/public") {
    sendJson(res, 200, { message: "This is public — no auth required" });
    return;
  }

  if (path === "/protected") {
    const username = authenticate(req.headers.authorization);

    if (!username) {
      res.writeHead(401, {
        "Content-Type": "application/json",
        "WWW-Authenticate": "Basic",
      });
      res.end(JSON.stringify({ error: "Invalid or missing credentials" }));
      return;
    }

    sendJson(res, 200, { username, message: "Authenticated via Basic Auth" });
    return;
  }

  sendJson(res, 404, { error: "Not found" });
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "127.0.0.1", () => {
  console.log(`Server running at http://127.0.0.1:${PORT}`);
});
