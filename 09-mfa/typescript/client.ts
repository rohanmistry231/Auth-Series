import { authenticator } from "otplib";

const BASE_URL = process.env.SERVER_URL ?? "http://127.0.0.1:8000";

async function post(path: string, form: Record<string, string>) {
  const resp = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form),
  });
  return { status: resp.status, body: await resp.json() };
}

async function main() {
  const username = "alice";
  const password = process.env.ALICE_PASSWORD ?? "password-alice";

  console.log("=== Step 1: Setup MFA ===");
  const setup = await post("/setup", { username, password });
  console.log(`  Secret: ${setup.body.secret}`);
  console.log(`  QR URI: ${setup.body.qr_uri}`);

  console.log("\n=== Step 2: Verify TOTP ===");
  const currentCode = authenticator.generate(setup.body.secret);
  console.log(`  Current TOTP: ${currentCode}`);
  const verify = await post("/mfa/verify", { username, totp: currentCode });
  console.log(`  ${verify.body.message}`);
  console.log(`  Backup codes: ${verify.body.backup_codes}`);

  console.log("\n=== Step 3: Login with MFA ===");
  const code = authenticator.generate(setup.body.secret);
  const login = await post("/login", { username, password, totp: code });
  console.log(`  ${login.body.message}`);
  console.log(`  Token: ${(login.body.access_token as string).slice(0, 20)}...`);

  console.log("\n=== Step 4: Login with wrong TOTP ===");
  const bad = await post("/login", { username, password, totp: "000000" });
  console.log(`  Status: ${bad.status} - ${bad.body.error}`);

  console.log("\n=== Step 5: Recovery login ===");
  if (verify.body.backup_codes?.[0]) {
    const recovery = await post("/recovery", { username, backup_code: verify.body.backup_codes[0] });
    console.log(`  ${recovery.body.message}`);
    console.log(`  Codes remaining: ${recovery.body.codes_remaining}`);
  }
}

main().catch(console.error);
