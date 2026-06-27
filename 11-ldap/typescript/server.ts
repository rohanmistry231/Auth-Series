import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";
import ldap from "ldapjs";

const LDAP_HOST = process.env.LDAP_HOST ?? "ldap.forumsys.com";
const LDAP_PORT = parseInt(process.env.LDAP_PORT ?? "389", 10);
const LDAP_BASE_DN = process.env.LDAP_BASE_DN ?? "dc=example,dc=com";
const LDAP_BIND_DN = process.env.LDAP_BIND_DN ?? "cn=read-only-admin,dc=example,dc=com";
const LDAP_BIND_PASSWORD = process.env.LDAP_BIND_PASSWORD ?? "password";
const LDAP_USER_FILTER = process.env.LDAP_USER_FILTER ?? "(&(uid={username})(objectClass=person))";

const sessions = new Map<string, any>();

function createClient(): ldap.Client {
  return ldap.createClient({ url: `ldap://${LDAP_HOST}:${LDAP_PORT}`, reconnect: false });
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
<h2>LDAP Auth Demo</h2>
<p>Test users: <code>newton</code>, <code>galileo</code>, <code>einstein</code></p>
<form method="post" action="/login"><p><label>User: <input name="username" value="newton"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">Login</button></p></form>
<form method="post" action="/search">
<p><label>Filter: <input name="filter" value="(objectClass=person)"></label></p>
<p><button type="submit">Search</button></p></form></body></html>`);
      return;
    }

    if (path === "/login" && req.method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);
      const username = form.username;
      const password = form.password;

      const client = createClient();
      await new Promise<void>((resolve, reject) => {
        client.bind(LDAP_BIND_DN, LDAP_BIND_PASSWORD, (err) => {
          if (err) reject(new Error("LDAP bind failed")); else resolve();
        });
      });

      const searchFilter = LDAP_USER_FILTER.replace("{username}", username);
      const entries = await new Promise<any[]>((resolve, reject) => {
        client.search(LDAP_BASE_DN, { filter: searchFilter, scope: "sub", attributes: ["*"] }, (err, searchRes) => {
          if (err) { reject(err); return; }
          const results: any[] = [];
          searchRes.on("searchEntry", (entry) => results.push(entry.object));
          searchRes.on("error", reject);
          searchRes.on("end", () => resolve(results));
        });
      });

      if (entries.length === 0) { sendJson(res, 401, { error: "User not found" }); client.unbind(); return; }

      const user = entries[0];
      const userDN = user.dn || user.dn;

      try {
        await new Promise<void>((resolve, reject) => {
          const userClient = ldap.createClient({ url: `ldap://${LDAP_HOST}:${LDAP_PORT}` });
          userClient.bind(userDN, password, (err) => {
            if (err) reject(new Error("Invalid password"));
            else { userClient.unbind(); resolve(); }
          });
        });
      } catch {
        sendJson(res, 401, { error: "Invalid password" }); client.unbind(); return;
      }

      const sessionId = crypto.randomUUID();
      sessions.set(sessionId, { dn: userDN, username });

      sendJson(res, 200, {
        session_id: sessionId,
        dn: userDN,
        username,
        attributes: user,
      });
      client.unbind();
      return;
    }

    if (path === "/search" && req.method === "POST") {
      const body = await readBody(req);
      const form = parseForm(body);
      const filter = form.filter;

      const client = createClient();
      await new Promise<void>((resolve, reject) => {
        client.bind(LDAP_BIND_DN, LDAP_BIND_PASSWORD, (err) => {
          if (err) reject(new Error("LDAP bind failed")); else resolve();
        });
      });

      const entries = await new Promise<any[]>((resolve, reject) => {
        client.search(LDAP_BASE_DN, { filter, scope: "sub", attributes: ["*"] }, (err, searchRes) => {
          if (err) { reject(err); return; }
          const results: any[] = [];
          searchRes.on("searchEntry", (entry) => results.push(entry.object));
          searchRes.on("error", reject);
          searchRes.on("end", () => resolve(results));
        });
      });

      sendJson(res, 200, { count: entries.length, entries });
      client.unbind();
      return;
    }

    sendHtml(res, "Not found", 404);
  } catch (err: any) {
    sendJson(res, 500, { error: err.message });
  }
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "127.0.0.1", () => console.log(`LDAP Auth Server at http://127.0.0.1:${PORT}`));
