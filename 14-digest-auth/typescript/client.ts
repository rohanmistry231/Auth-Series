import crypto from "node:crypto";

const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";
const REALM = "Auth Series";

function md5(s: string): string {
  return crypto.createHash("md5").update(s).digest("hex");
}

function computeResponse(username: string, password: string, method: string, uri: string, nonce: string, cnonce: string, nc: string, qop: string): string {
  const ha1 = md5(`${username}:${REALM}:${password}`);
  const ha2 = md5(`${method}:${uri}`);
  return md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
}

async function main() {
  console.log("=== Step 1: Request protected resource (no auth) ===");
  const resp1 = await fetch(`${BASE_URL}/protected`, { redirect: "manual" });
  console.log(`  Status: ${resp1.status}`);
  const wwwAuth = resp1.headers.get("www-authenticate") ?? "";
  console.log(`  WWW-Authenticate: ${wwwAuth.slice(0, 60)}...`);

  const parseParams = (h: string) => {
    const params: Record<string, string> = {};
    for (const part of h.slice(7).split(",")) {
      const eqIdx = part.indexOf("=");
      if (eqIdx === -1) continue;
      let v = part.slice(eqIdx + 1).trim();
      if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
      params[part.slice(0, eqIdx).trim()] = v;
    }
    return params;
  };

  const params = parseParams(wwwAuth);
  const nonce = params.nonce ?? "";
  const opaque = params.opaque ?? "";
  const qop = params.qop ?? "auth";
  console.log(`  Nonce: ${nonce.slice(0, 16)}...`);

  const username = "alice";
  const password = process.env.ALICE_PASSWORD ?? "password-alice";
  const cnonce = md5(crypto.randomBytes(16).toString("hex")).slice(0, 16);
  const nc = "00000001";
  const uri = "/protected";
  const response = computeResponse(username, password, "GET", uri, nonce, cnonce, nc, qop);

  console.log("\n=== Step 2: Retry with Digest auth ===");
  const digestHeader = `Digest username="${username}",realm="${REALM}",nonce="${nonce}",uri="${uri}",qop=${qop},nc=${nc},cnonce="${cnonce}",response="${response}",opaque="${opaque}"`;
  const resp2 = await fetch(`${BASE_URL}/protected`, { headers: { Authorization: digestHeader }, redirect: "manual" });
  console.log(`  Status: ${resp2.status}`);
  if (resp2.status === 200) {
    const data: any = await resp2.json();
    console.log(`  ✅ ${data.message}`);
  }

  console.log("\n=== Step 3: Replay nonce (should fail) ===");
  const resp3 = await fetch(`${BASE_URL}/protected`, { headers: { Authorization: digestHeader }, redirect: "manual" });
  console.log(`  Status: ${resp3.status} — ${resp3.status === 401 ? "✅ Blocked" : "❌"}`);
}

main().catch(console.error);
