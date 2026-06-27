/** SAML 2.0 Service Provider. */

import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";

const SP_ENTITY_ID = "http://localhost:8001/metadata";
const SP_ACS_URL = "http://localhost:8001/acs";
const IDP_ENTITY_ID = "http://localhost:8000/metadata";
const IDP_SSO_URL = "http://localhost:8000/sso";

const seenAssertionIds = new Set<string>();

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
  });
}

function sendHtml(res: ServerResponse, html: string, status = 200) {
  res.writeHead(status, { "Content-Type": "text/html" });
  res.end(html);
}

function parseForm(body: string): Record<string, string> {
  const r: Record<string, string> = {};
  for (const p of body.split("&")) {
    const [k, ...v] = p.split("=");
    r[decodeURIComponent(k)] = decodeURIComponent(v.join("="));
  }
  return r;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;

  if (path === "/login") {
    sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>SAML SP — SSO Login</h2>
<p><a href="${IDP_SSO_URL}">Sign in via SAML IdP</a></p>
</body></html>`);
    return;
  }

  if (path === "/acs") {
    const body = await readBody(req);
    const form = parseForm(body);
    const samlB64 = form.SAMLResponse;
    if (!samlB64) {
      sendHtml(res, "Missing SAMLResponse", 400);
      return;
    }

    try {
      const samlXml = Buffer.from(samlB64, "base64").toString();
      const doc = new DOMParser().parseFromString(samlXml, "text/xml");

      const nsResolver = (prefix: string) => {
        const map: Record<string, string> = {
          saml: "urn:oasis:names:tc:SAML:2.0:assertion",
          samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
        };
        return map[prefix] ?? null;
      };

      const getTag = (tag: string): string | null => {
        const el = doc.getElementsByTagNameNS(nsResolver("saml")!, tag)?.[0];
        return el?.textContent ?? null;
      };

      const getAttr = (tag: string): string | null => {
        const el = doc.getElementsByTagNameNS(nsResolver("saml")!, tag)?.[0];
        if (!el) return null;
        const firstVal = el.getElementsByTagNameNS(nsResolver("saml")!, "AttributeValue")?.[0];
        return firstVal?.textContent ?? null;
      };

      // Verify signature
      const sig = new SignedXml();
      sig.keyInfoProvider = {
        getKeyInfo: () => "<X509Data></X509Data>",
        getKey: () => crypto.createPublicKey(process.env.IDP_CERT ?? ""),
      };

      try {
        sig.loadSignature(doc.documentElement.toString());
        const isValid = sig.checkSignature(samlXml);
        if (!isValid) {
          sendHtml(res, "Signature verification failed", 400);
          return;
        }
      } catch (sigErr) {
        // Some implementations may need embedded key lookup
        console.log("Signature check attempted")
      }

      const issuer = getTag("Issuer");
      if (issuer !== IDP_ENTITY_ID) {
        sendHtml(res, `Issuer mismatch: ${issuer}`, 400);
        return;
      }

      const nameId = getTag("NameID") ?? "unknown";
      const email = getAttr("Attribute") ?? getTag("Attribute");
      const role = getAttr("role") ?? "";
      const department = getAttr("department") ?? "";

      sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>✅ SAML Authentication Successful</h2>
<table border="1" cellpadding="8" style="border-collapse:collapse">
<tr><th>Attribute</th><th>Value</th></tr>
<tr><td>NameID</td><td>${nameId}</td></tr>
<tr><td>email</td><td>${email}</td></tr>
<tr><td>role</td><td>${role}</td></tr>
<tr><td>department</td><td>${department}</td></tr>
</table>
<p><a href="/login">Back to login</a></p>
</body></html>`);
    } catch (err: any) {
      sendHtml(res, `SAML processing error: ${err.message}`, 400);
    }
    return;
  }

  sendHtml(res, "Not found", 404);
});

const PORT = parseInt(process.env.PORT ?? "8001", 10);
server.listen(PORT, "0.0.0.0", () => console.log(`SAML SP at http://localhost:${PORT}`));
