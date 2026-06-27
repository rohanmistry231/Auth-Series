/** SAML 2.0 Identity Provider. */

import crypto from "node:crypto";
import http, { IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";

const IDP_ENTITY_ID = "http://localhost:8000/metadata";
const SP_ACS_URL = "http://localhost:8001/acs";
const SP_ENTITY_ID = "http://localhost:8001/metadata";

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const USERS: Record<string, any> = {
  alice: {
    password: process.env.ALICE_PASSWORD ?? "password-alice",
    email: "alice@example.com",
    role: "admin",
    department: "Engineering",
  },
};

function makeSAMLResponse(username: string): string {
  const user = USERS[username];
  const assertionId = `ASSERTION_${randomUUID().replace(/-/g, "")}`;
  const responseId = `RESPONSE_${randomUUID().replace(/-/g, "")}`;
  const now = new Date().toISOString();
  const notOnOrAfter = new Date(Date.now() + 3600000).toISOString();

  const ns = "urn:oasis:names:tc:SAML:2.0:assertion";
  const nsp = "urn:oasis:names:tc:SAML:2.0:protocol";

  const assertion = `
    <saml:Assertion xmlns:saml="${ns}" xmlns:samlp="${nsp}"
      ID="${assertionId}" IssueInstant="${now}" Version="2.0">
      <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
      <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${user.email}</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
          <saml:SubjectConfirmationData InResponseTo="" NotOnOrAfter="${notOnOrAfter}" Recipient="${SP_ACS_URL}"/>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:Conditions NotBefore="${now}" NotOnOrAfter="${notOnOrAfter}">
        <saml:AudienceRestriction>
          <saml:Audience>${SP_ENTITY_ID}</saml:Audience>
        </saml:AudienceRestriction>
      </saml:Conditions>
      <saml:AuthnStatement AuthnInstant="${now}">
        <saml:AuthnContext>
          <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
        </saml:AuthnContext>
      </saml:AuthnStatement>
      <saml:AttributeStatement>
        <saml:Attribute Name="email"><saml:AttributeValue>${user.email}</saml:AttributeValue></saml:Attribute>
        <saml:Attribute Name="role"><saml:AttributeValue>${user.role}</saml:AttributeValue></saml:Attribute>
        <saml:Attribute Name="department"><saml:AttributeValue>${user.department}</saml:AttributeValue></saml:Attribute>
      </saml:AttributeStatement>
    </saml:Assertion>`;

  // Sign the assertion
  const doc = new DOMParser().parseFromString(assertion, "text/xml");
  const sig = new SignedXml();
  sig.signingKey = privateKey;
  sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  sig.addReference({
    xpath: `//*[local-name(.)='Assertion' and namespace-uri(.)='${ns}']`,
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  sig.computeSignature(doc);
  const signedAssertion = sig.getSignedXml();

  const response = `<?xml version="1.0" encoding="UTF-8"?>
    <samlp:Response xmlns:samlp="${nsp}" xmlns:saml="${ns}"
      ID="${responseId}" Version="2.0" IssueInstant="${now}" Destination="${SP_ACS_URL}">
      <saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </samlp:Status>
      ${signedAssertion}
    </samlp:Response>`;

  return response;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
  });
}

function sendHtml(res: ServerResponse, html: string) {
  res.writeHead(200, { "Content-Type": "text/html" });
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
  const method = req.method ?? "GET";

  if (path === "/sso" && method === "GET") {
    sendHtml(res, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:400px;margin:40px auto">
<h2>SAML IdP — Sign In</h2>
<form method="post" action="/sso">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">Sign In</button></p>
</form></body></html>`);
    return;
  }

  if (path === "/sso" && method === "POST") {
    const body = await readBody(req);
    const form = parseForm(body);

    const user = USERS[form.username];
    if (!user || user.password !== form.password) {
      sendHtml(res, "Invalid credentials");
      return;
    }

    const samlResponse = makeSAMLResponse(form.username);
    const samlB64 = Buffer.from(samlResponse).toString("base64");

    sendHtml(res, `<!DOCTYPE html>
<html><body onload="document.forms[0].submit()">
<form method="post" action="${SP_ACS_URL}">
<input type="hidden" name="SAMLResponse" value="${samlB64}">
<input type="hidden" name="RelayState" value="">
<noscript><button type="submit">Continue</button></noscript>
</form></body></html>`);
    return;
  }

  if (path === "/metadata") {
    const md = `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${IDP_ENTITY_ID}">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8000/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;
    res.writeHead(200, { "Content-Type": "application/xml" });
    res.end(md);
    return;
  }

  sendHtml(res, "Not found");
});

const PORT = parseInt(process.env.PORT ?? "8000", 10);
server.listen(PORT, "0.0.0.0", () => console.log(`SAML IdP at http://localhost:${PORT}`));
