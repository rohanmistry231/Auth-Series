const APP_ID = process.env.APP_ID ?? "app1";
const APP_PORT = parseInt(process.env.APP_PORT ?? "8001", 10);
const APP_NAME = process.env.APP_NAME ?? "My App";
const SSO_SERVER = process.env.SSO_SERVER ?? "http://localhost:8000";

import http, { IncomingMessage, ServerResponse } from "node:http";

const localSessions = new Map<string, any>();

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

function parseCookie(cookie: string): Record<string, string> {
  const r: Record<string, string> = {};
  for (const p of cookie.split(";")) { const [k, ...v] = p.trim().split("="); r[k] = v.join("="); }
  return r;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;

  if (path === "/" || path === "/dashboard") {
    const cookies = parseCookie(req.headers.cookie ?? "");
    const session = localSessions.get(cookies.app_session);
    if (!session) {
      sendRedirect(res, `${SSO_SERVER}/sso/login?redirect=http://localhost:${APP_PORT}/sso/callback`);
      return;
    }
    sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>${APP_NAME}</h2>
<p>Logged in as: <strong>${session.username}</strong></p>
<p>App ID: ${APP_ID}</p>
<hr>
<p><a href="/profile">Profile</a> | <a href="/logout">Logout</a></p>
</body></html>`);
    return;
  }

  if (path === "/sso/callback") {
    const token = url.searchParams.get("token") ?? "";
    const resp = await fetch(`${SSO_SERVER}/sso/validate?token=${token}`);
    if (resp.status !== 200) {
      sendHtml(res, "SSO validation failed", 401);
      return;
    }
    const data = await resp.json() as any;
    const sessionId = crypto.randomUUID();
    localSessions.set(sessionId, { username: data.sub, app_id: APP_ID });
    setCookie(res, "app_session", sessionId, 86400);
    sendRedirect(res, "/dashboard");
    return;
  }

  if (path === "/profile") {
    const cookies = parseCookie(req.headers.cookie ?? "");
    const session = localSessions.get(cookies.app_session);
    if (!session) { sendRedirect(res, "/dashboard"); return; }
    sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Profile</h2>
<table border="1" cellpadding="8" style="border-collapse:collapse">
<tr><td>Username</td><td>${session.username}</td></tr>
<tr><td>App</td><td>${APP_NAME}</td></tr>
<tr><td>Session ID</td><td>${(cookies.app_session ?? "").slice(0, 8)}...</td></tr>
</table>
<p><a href="/dashboard">Back</a></p>`);
    return;
  }

  if (path === "/logout") {
    const cookies = parseCookie(req.headers.cookie ?? "");
    localSessions.delete(cookies.app_session);
    setCookie(res, "app_session", "", 0);
    sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:400px;margin:40px auto">
<h2>Logged out of ${APP_NAME}</h2>
<p><a href="${SSO_SERVER}/sso/logout">Logout of all apps</a></p>
<p><a href="/dashboard">Login again</a></p>
</body></html>`);
    return;
  }

  sendHtml(res, "Not found", 404);
});

const PORT = APP_PORT;
server.listen(PORT, "0.0.0.0", () => console.log(`${APP_NAME} at http://localhost:${PORT}`));
