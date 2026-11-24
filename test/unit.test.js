"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const { createKeyring, CryptoError } = require("../src/crypto");
const { parseWebhook, isSnowflake } = require("../src/webhook");
const { LruCache } = require("../src/cache");
const { createLogger, redact } = require("../src/logger");
const { loadConfig, ConfigError, parseTrustProxy } = require("../src/config");
const { createNoteService, normalizeUsername, normalizeAvatar, sanitizeMessage, mapLimit } = require("../src/service");
const { DiscordError, createDiscordClient } = require("../src/discord");
const { testKeys, randomToken } = require("./helpers");

const keys = testKeys();
const kr = createKeyring(keys.privatePem, keys.publicPem);

test("keyring rejects mismatched or weak keys", () => {
  const other = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" });
  assert.throws(() => createKeyring(keys.privatePem, other), /does not match/);
  const weak = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey.export({ type: "pkcs8", format: "pem" });
  assert.throws(() => createKeyring(weak), /2048/);
  const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "pem" });
  assert.throws(() => createKeyring(ec), /RSA/);
  assert.equal(createKeyring(keys.privatePem).kid, kr.kid);
});

test("v2 note encryption binds ciphertext to the webhook", () => {
  const a = "a".repeat(64);
  const b = "b".repeat(64);
  const p = kr.encryptNote("hello", a);
  assert.equal(kr.decryptNote(p, a, { allowLegacy: false }), "hello");
  assert.throws(() => kr.decryptNote(p, b, { allowLegacy: true }), CryptoError);
  const flipped = Buffer.from(p);
  flipped[flipped.length - 1] ^= 1;
  assert.throws(() => kr.decryptNote(flipped, a, { allowLegacy: false }), CryptoError);
  assert.notDeepEqual(kr.encryptNote("hello", a), p);
});

test("legacy payloads only decrypt when allowed", () => {
  const aes = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", aes, iv);
  const ct = Buffer.concat([c.update("legacy", "utf8"), c.final()]);
  const ek = crypto.publicEncrypt({ key: keys.publicPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, aes);
  const payload = Buffer.from([ek, iv, c.getAuthTag(), ct].map((x) => x.toString("base64")).join("|"));
  assert.equal(kr.decryptNote(payload, "x".repeat(64), { allowLegacy: true }), "legacy");
  assert.throws(() => kr.decryptNote(payload, "x".repeat(64), { allowLegacy: false }), CryptoError);
});

test("transport decrypt accepts only well-formed OAEP blobs", () => {
  const url = "https://discord.com/api/webhooks/123456789012345678/" + randomToken();
  const blob = crypto.publicEncrypt({ key: keys.publicPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from(url)).toString("base64");
  assert.equal(kr.decryptTransport(blob), url);
  assert.equal(kr.decryptTransport(blob.slice(4)), null);
  assert.equal(kr.decryptTransport(123), null);
  assert.equal(kr.decryptTransport("A".repeat(344)), null);
  const pkcs1 = crypto.publicEncrypt({ key: keys.publicPem, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(url)).toString("base64");
  assert.equal(kr.decryptTransport(pkcs1), null);
});

test("webhook parsing canonicalizes host variants and rejects junk", () => {
  const token = randomToken();
  const id = "123456789012345678";
  const variants = [
    `https://discord.com/api/webhooks/${id}/${token}`,
    `https://discordapp.com/api/webhooks/${id}/${token}`,
    `https://canary.discord.com/api/webhooks/${id}/${token}`,
    `https://discord.com/api/v10/webhooks/${id}/${token}`
  ];
  const keysSet = new Set(variants.map((v) => parseWebhook(v).key));
  assert.equal(keysSet.size, 1);
  for (const bad of [
    `http://discord.com/api/webhooks/${id}/${token}`,
    `https://discord.com.evil.com/api/webhooks/${id}/${token}`,
    `https://discord.com/api/webhooks/${id}/${token}/../x`,
    `https://discord.com/api/webhooks/${id}/${token}?x=1`,
    `https://discord.com/api/webhooks/${id}/${token}#a`,
    `https://user@discord.com/api/webhooks/${id}/${token}`,
    `https://discord.com/api/webhooks/99999999999999999999/${token}`,
    ` https://discord.com/api/webhooks/${id}/${token}`
  ]) assert.equal(parseWebhook(bad), null, bad);
  assert.equal(isSnowflake("9223372036854775807"), true);
  assert.equal(isSnowflake("9223372036854775808"), false);
});

test("input normalizers", () => {
  assert.equal(normalizeUsername("  Vault​ "), "Vault");
  assert.equal(normalizeUsername("DISCORD fan"), null);
  assert.equal(normalizeUsername("ｄｉｓｃｏｒｄ"), null);
  assert.equal(normalizeUsername("here"), null);
  assert.equal(normalizeUsername(""), "");
  assert.equal(normalizeUsername(5), null);
  assert.equal(normalizeUsername("x".repeat(81)), null);
  assert.equal(normalizeAvatar("https://a.example/x.png"), "https://a.example/x.png");
  assert.equal(normalizeAvatar("https://u:p@a.example/x.png"), null);
  assert.equal(normalizeAvatar("http://a.example/x.png"), null);
  assert.equal(normalizeAvatar("data:image/png;base64,AAAA"), null);
  assert.equal(sanitizeMessage("a\r\nb"), "a\nb");
  assert.equal(sanitizeMessage("\uD800"), null);
  assert.equal(sanitizeMessage("\u0000\u0000"), null);
});

test("lru cache respects ttl, entry and byte budgets", () => {
  let now = 0;
  const c = new LruCache({ maxEntries: 3, maxBytes: 10, ttlMs: 100, sizeOf: (v) => v.length, now: () => now });
  c.set("a", "aaaa");
  c.set("b", "bbbb");
  c.get("a");
  c.set("c", "cccc");
  assert.equal(c.get("b"), undefined);
  assert.equal(c.get("a"), "aaaa");
  assert.ok(c.bytes <= 10);
  now = 200;
  assert.equal(c.get("a"), undefined);
  c.set("big", "x".repeat(11));
  assert.equal(c.get("big"), undefined);
});

test("logger redacts secrets", () => {
  const lines = [];
  const log = createLogger("debug", (l) => lines.push(l));
  const token = randomToken();
  log.error("fail https://discord.com/api/webhooks/123456789012345678/" + token, { err: new Error("x " + keys.privatePem), url: "postgres://u:pw@h/db", cdn: "https://cdn.discordapp.com/a?ex=1&hm=secret" });
  const out = lines.join("");
  assert.ok(!out.includes(token));
  assert.ok(!out.includes("PRIVATE KEY"));
  assert.ok(!out.includes(":pw@"));
  assert.ok(!out.includes("hm=secret"));
  assert.ok(!out.includes("stack"));
  assert.equal(redact("x".repeat(600)).length < 510, true);
});

test("config validation", () => {
  const b64 = Buffer.from(keys.privatePem).toString("base64");
  const ok = loadConfig({ POSTGRES_URL: "postgres://x", PRIVATE_KEY_B64: b64, PORT: "8080", TRUST_PROXY: "1", ALLOWED_ORIGINS: "https://a.example/,https://b.example" });
  assert.equal(ok.port, 8080);
  assert.equal(ok.trustProxy, 1);
  assert.deepEqual(ok.allowedOrigins, ["https://a.example", "https://b.example"]);
  assert.equal(ok.postgres.ssl.mode, "require");
  assert.throws(() => loadConfig({ POSTGRES_URL: "x", PRIVATE_KEY_B64: b64, PORT: "99999" }), ConfigError);
  assert.throws(() => loadConfig({ POSTGRES_URL: "x", PRIVATE_KEY_B64: b64, PORT: "3000; rm" }), ConfigError);
  assert.throws(() => loadConfig({ POSTGRES_URL: "x" }), ConfigError);
  assert.throws(() => loadConfig({ POSTGRES_URL: "x", PRIVATE_KEY_B64: b64, PUBLIC_KEY_PATH: "../../etc/passwd" }), /escapes/);
  assert.equal(parseTrustProxy(undefined), false);
  assert.deepEqual(parseTrustProxy("loopback, 10.0.0.0/8"), ["loopback", "10.0.0.0/8"]);
});

test("mapLimit bounds concurrency and preserves order", async () => {
  let active = 0;
  let peak = 0;
  const out = await mapLimit([1, 2, 3, 4, 5, 6], 2, async (x) => {
    active++;
    peak = Math.max(peak, active);
    await new Promise((r) => setTimeout(r, 5));
    active--;
    if (x === 3) throw new Error("boom");
    return x * 2;
  });
  assert.equal(peak, 2);
  assert.deepEqual(out.map((r) => (r.ok ? r.value : "err")), [2, 4, "err", 8, 10, 12]);
});

test("service list returns the readable prefix when rate limited mid-page", async () => {
  const webhookKey = "c".repeat(64);
  const rows = ["900000000000000005", "900000000000000004", "900000000000000003", "900000000000000002"].map((id) => ({ id, digest: null }));
  const payloads = new Map(rows.map((r) => [r.id, kr.encryptNote(`n${r.id.slice(-1)}`, webhookKey)]));
  const store = { listNotes: async () => rows, deleteNote: async () => true, adoptLegacy: async () => {} };
  const discord = {
    getMessage: async (wh, id) => {
      if (id === "900000000000000003") throw new DiscordError("rate_limited", { retryAfterMs: 3000 });
      return { id, timestamp: new Date().toISOString(), edited: false, attachment: { url: "u", filename: "payload.bin", size: 10 } };
    },
    downloadAttachment: async (url) => payloads.get(url) || payloads.get([...payloads.keys()].find(Boolean))
  };
  let lastId;
  discord.getMessage = ((orig) => async (wh, id) => { lastId = id; return orig(wh, id); })(discord.getMessage);
  discord.downloadAttachment = async () => payloads.get(lastId);
  const svc = createNoteService({ store, discord, keyring: kr, logger: createLogger("error", () => {}) });
  const out = await svc.list({ key: webhookKey, id: "1" }, { limit: 4 });
  assert.equal(out.partial, true);
  assert.equal(out.next_cursor, "900000000000000004");
  assert.equal(out.consumed, 2);
  assert.equal(out.retry_after, 3);
  assert.ok(out.notes.length <= 2);
});

test("discord client honours rate-limit headers and maps errors", async () => {
  let calls = 0;
  const fetchImpl = async (url) => {
    calls++;
    if (calls === 1) return new Response(JSON.stringify({ retry_after: 0.05 }), { status: 429, headers: { "content-type": "application/json" } });
    if (url.includes("/messages/")) return new Response(JSON.stringify({ code: 10008 }), { status: 404 });
    return new Response(JSON.stringify({ name: "n" }), { status: 200, headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset-after": "0.05" } });
  };
  const d = createDiscordClient({ fetchImpl, apiBase: "https://discord.com/api/v10" });
  const wh = parseWebhook("https://discord.com/api/webhooks/123456789012345678/" + randomToken());
  const t0 = Date.now();
  assert.deepEqual(await d.getWebhook(wh), { name: "n" });
  assert.equal(calls, 2);
  assert.equal(await d.getMessage(wh, "123456789012345679"), null);
  assert.ok(Date.now() - t0 >= 90);
  assert.equal(d.isCdnUrl("https://cdn.discordapp.com/x"), true);
  assert.equal(d.isCdnUrl("https://cdn.discordapp.com.evil.io/x"), false);
  assert.equal(d.isCdnUrl("http://cdn.discordapp.com/x"), false);
  assert.equal(d.isCdnUrl("https://a@cdn.discordapp.com/x"), false);
  const big = createDiscordClient({ fetchImpl: async () => new Response("x".repeat(2000), { status: 200 }) });
  await assert.rejects(big.downloadAttachment("https://cdn.discordapp.com/a", 1000), (e) => e.kind === "too_large");
});
