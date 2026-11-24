"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const envPath = path.join(root, ".env");
const keysDir = path.join(root, "keys");
const publicPath = path.join(keysDir, "public.pem");

const existing = fs.existsSync(envPath) ? fs.readFileSync(envPath, "utf8") : "";
if (/^PRIVATE_KEY_B64=.+/m.test(existing) && !process.argv.includes("--force")) {
  process.stderr.write(".env already contains PRIVATE_KEY_B64. Rotating the key makes existing notes unreadable. Re-run with --force to replace it.\n");
  process.exit(1);
}

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 3072 });
const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
const publicPem = publicKey.export({ type: "spki", format: "pem" });

fs.mkdirSync(keysDir, { recursive: true, mode: 0o755 });
fs.writeFileSync(publicPath, publicPem, { mode: 0o644 });

const lines = existing.split(/\r?\n/).filter((l) => l && !/^PRIVATE_KEY_B64=/.test(l) && !/^PUBLIC_KEY_PATH=/.test(l));
lines.push(`PRIVATE_KEY_B64=${Buffer.from(privatePem).toString("base64")}`);
lines.push("PUBLIC_KEY_PATH=./keys/public.pem");
if (!lines.some((l) => /^POSTGRES_PASSWORD=/.test(l))) lines.push(`POSTGRES_PASSWORD=${crypto.randomBytes(24).toString("base64url")}`);
fs.writeFileSync(envPath, lines.join("\n") + "\n", { mode: 0o600 });
fs.chmodSync(envPath, 0o600);

const kid = crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex").slice(0, 16);
process.stdout.write(`Generated RSA-3072 key pair (kid ${kid}).\nPublic key: keys/public.pem\nSecrets written to .env (mode 600). Back up PRIVATE_KEY_B64: losing it makes every note unreadable.\n`);
