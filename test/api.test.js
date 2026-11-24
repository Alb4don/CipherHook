"use strict";

const { test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const { startFakeDiscord, buildTestApp } = require("./helpers");

let fake;
let t;

before(async () => {
  fake = await startFakeDiscord();
});

after(async () => {
  await fake.close();
});

beforeEach(async () => {
  if (t) await t.close();
  fake.state.messages.clear();
  fake.state.calls.length = 0;
  fake.state.rateLimitNext = 0;
  fake.state.unknownWebhookOnMessages = false;
  t = await buildTestApp({ fake });
});

after(async () => {
  if (t) await t.close();
});

function legacyV1Payload(message, publicPem) {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  let enc = cipher.update(message, "utf8", "base64");
  enc += cipher.final("base64");
  const tag = cipher.getAuthTag().toString("base64");
  const ek = crypto.publicEncrypt({ key: publicPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, aesKey).toString("base64");
  return Buffer.from(`${ek}|${iv.toString("base64")}|${tag}|${enc}`, "utf8");
}

test("public key endpoints expose matching SPKI and key id", async () => {
  const txt = await fetch(t.base + "/public_key");
  assert.equal(txt.status, 200);
  assert.equal(txt.headers.get("x-key-id"), t.keyring.kid);
  const spki = await txt.text();
  const j = await (await fetch(t.base + "/api/v1/public_key")).json();
  assert.equal(j.spki, spki);
  assert.equal(j.alg, "RSA-OAEP-256");
  const pub = crypto.createPublicKey({ key: Buffer.from(spki, "base64"), format: "der", type: "spki" });
  assert.equal(pub.asymmetricKeyDetails.modulusLength, 2048);
});

test("verify accepts live webhook and negatively caches dead ones", async () => {
  const wh = fake.addWebhook("My Notes");
  const ok = await t.post("/api/v1/verify", { webhook_url: t.encrypt(wh) });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.name, "My Notes");
  const dead = wh.replace(/\/[^/]+$/, "/" + "x".repeat(68));
  const r1 = await t.post("/api/v1/verify", { webhook_url: t.encrypt(dead) });
  assert.equal(r1.status, 400);
  assert.equal(r1.json.code, "invalid_webhook");
  const calls = fake.state.calls.length;
  const r2 = await t.post("/api/v1/send", { webhook_url: t.encrypt(dead), raw_message: "x" });
  assert.equal(r2.status, 400);
  assert.equal(fake.state.calls.length, calls);
});

test("send, cursor pagination, count, legacy index pagination", async () => {
  const wh = fake.addWebhook();
  const enc = t.encrypt(wh);
  const sent = [];
  for (let i = 0; i < 12; i++) {
    const r = await t.post("/send", { webhook_url: enc, raw_message: `note ${i} ✓ 日本語` });
    assert.equal(r.status, 200, r.text);
    sent.push(r.json.note_id);
  }
  const stored = [...fake.state.messages.values()][0].payload;
  assert.equal(stored.subarray(0, 4).toString("latin1"), "CH2\u0000");
  assert.ok(!stored.includes(Buffer.from("note 0")));
  const seen = [];
  let cursor;
  for (let guard = 0; guard < 10; guard++) {
    const r = await t.post("/api/v1/retrieve", { webhook_url: enc, cursor, limit: 5 });
    assert.equal(r.status, 200, r.text);
    seen.push(...r.json.notes.map((n) => n.content));
    for (const n of r.json.notes) assert.ok(!Number.isNaN(Date.parse(n.timestamp)));
    cursor = r.json.next_cursor;
    if (!cursor) break;
  }
  assert.deepEqual(seen, Array.from({ length: 12 }, (_, i) => `note ${11 - i} ✓ 日本語`));
  const c = await t.post("/count", { webhook_url: enc });
  assert.equal(c.json.notes_count, 12);
  const l0 = await t.post("/retrieve", { webhook_url: enc, note_index: 10 });
  assert.equal(l0.json.notes.length, 2);
  const l1 = await t.post("/retrieve", { webhook_url: enc, note_index: 12 });
  assert.equal(l1.status, 404);
  assert.equal(l1.json.error, "note not found");
});

test("utf-8 heavy message at the 5000 char limit is accepted, 5001 rejected", async () => {
  const enc = t.encrypt(fake.addWebhook());
  const ok = await t.post("/send", { webhook_url: enc, raw_message: "語".repeat(5000) });
  assert.equal(ok.status, 200, ok.text);
  const bad = await t.post("/send", { webhook_url: enc, raw_message: "a".repeat(5001) });
  assert.equal(bad.status, 400);
  const blank = await t.post("/send", { webhook_url: enc, raw_message: "   \n " });
  assert.equal(blank.status, 400);
});

test("delete removes from discord and db; unknown id never reaches discord", async () => {
  const enc = t.encrypt(fake.addWebhook());
  const s = await t.post("/send", { webhook_url: enc, raw_message: "bye" });
  const d = await t.post("/delete", { webhook_url: enc, note_id: s.json.note_id });
  assert.equal(d.status, 200);
  assert.equal(d.json.deleted, true);
  assert.equal(fake.state.messages.has(s.json.note_id), false);
  const before = fake.state.calls.length;
  const d2 = await t.post("/delete", { webhook_url: enc, note_id: "123456789012345678" });
  assert.equal(d2.json.deleted, false);
  assert.equal(fake.state.calls.length, before);
  const r = await t.post("/api/v1/retrieve", { webhook_url: enc });
  assert.equal(r.json.notes.length, 0);
});

test("delete keeps the record when discord rate limits", async () => {
  const enc = t.encrypt(fake.addWebhook());
  const s = await t.post("/send", { webhook_url: enc, raw_message: "keep" });
  fake.state.rateLimitNext = 5;
  const d = await t.post("/delete", { webhook_url: enc, note_id: s.json.note_id });
  assert.equal(d.status, 429);
  assert.ok(d.headers.get("retry-after"));
  fake.state.rateLimitNext = 0;
  assert.equal((await t.post("/count", { webhook_url: enc })).json.notes_count, 1);
});

test("settings validation and use in outgoing payload", async () => {
  const enc = t.encrypt(fake.addWebhook());
  assert.equal((await t.post("/update_settings", { webhook_url: enc, username: "My Discord Bot" })).status, 400);
  assert.equal((await t.post("/update_settings", { webhook_url: enc, pfp_link: "http://insecure.example/a.png" })).status, 400);
  assert.equal((await t.post("/update_settings", { webhook_url: enc, pfp_link: "javascript:alert(1)" })).status, 400);
  const ok = await t.post("/update_settings", { webhook_url: enc, username: "  Vault​ ", pfp_link: "https://example.com/a.png" });
  assert.equal(ok.status, 200, ok.text);
  const g = await t.post("/settings", { webhook_url: enc });
  assert.equal(g.json.username, "Vault");
  assert.equal(g.json.pfp_link, "https://example.com/a.png");
  await t.post("/send", { webhook_url: enc, raw_message: "@everyone hi" });
  assert.equal(fake.state.lastPayloadJson.username, "Vault");
  assert.deepEqual(fake.state.lastPayloadJson.allowed_mentions, { parse: [] });
});

test("decryption oracle: foreign ciphertext swapped into another webhook is rejected", async () => {
  const victim = t.encrypt(fake.addWebhook());
  const attacker = t.encrypt(fake.addWebhook());
  const v = await t.post("/send", { webhook_url: victim, raw_message: "victim secret" });
  const a = await t.post("/send", { webhook_url: attacker, raw_message: "attacker" });
  const victimPayload = fake.state.messages.get(v.json.note_id).payload;
  const msg = fake.state.messages.get(a.json.note_id);
  msg.payload = victimPayload;
  const t2 = await buildTestAppKeepDb();
  const swapped = await t2.post("/api/v1/retrieve", { webhook_url: attacker });
  assert.equal(swapped.status, 200);
  assert.equal(swapped.json.notes.length, 0);
  assert.equal(swapped.json.unreadable, 1);
  assert.ok(!swapped.text.includes("victim secret"));
  msg.edited = new Date().toISOString();
  await t2.store.pool.query("UPDATE note_messages SET digest = NULL");
  const t3 = await buildTestAppKeepDb();
  const edited = await t3.post("/api/v1/retrieve", { webhook_url: attacker });
  assert.equal(edited.json.notes.length, 0);
  msg.edited = null;
  const t4 = await buildTestAppKeepDb();
  const noDigest = await t4.post("/api/v1/retrieve", { webhook_url: attacker });
  assert.equal(noDigest.json.notes.length, 0);
  await t2.close();
  await t3.close();
  await t4.close();
});

test("legacy v1 rows and payloads are migrated and readable", async () => {
  const wh = fake.addWebhook();
  const id = wh.split("/")[5];
  const payload = legacyV1Payload("old note", t.keys.publicPem);
  const mid = require("./helpers").snowflake();
  fake.state.messages.set(mid, { id: mid, webhookId: id, payload, filename: "payload.bin", timestamp: new Date().toISOString(), edited: null });
  const legacyHash = crypto.createHash("sha256").update(wh).digest("hex");
  await t.store.pool.query("INSERT INTO notes (webhook_hash, note_ids, pfp_link, username) VALUES ($1, $2, $3, $4)", [legacyHash, JSON.stringify([mid, "bogus", mid]), "https://i.imgur.com/1BxJoqZ.jpeg", "CipherHook"]);
  const t2 = await buildTestAppKeepDb();
  const r = await t2.post("/api/v1/retrieve", { webhook_url: t2.encrypt(wh) });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json.notes.map((n) => n.content), ["old note"]);
  const left = await t2.store.pool.query("SELECT count(*)::int AS n FROM notes");
  assert.equal(left.rows[0].n, 0);
  const alt = wh.replace("https://discord.com", "https://discordapp.com");
  const r2 = await t2.post("/api/v1/count", { webhook_url: t2.encrypt(alt) });
  assert.equal(r2.json.notes_count, 1);
  await t2.close();
});

async function buildTestAppKeepDb() {
  const { createStore } = require("../src/store");
  const { createKeyring } = require("../src/crypto");
  const { createDiscordClient } = require("../src/discord");
  const { createNoteService } = require("../src/service");
  const { createApp } = require("../src/http/app");
  const { createLogger } = require("../src/logger");
  const { TEST_DB, testKeys } = require("./helpers");
  const keys = testKeys();
  const logger = createLogger("error", () => {});
  const keyring = createKeyring(keys.privatePem, keys.publicPem);
  const store = createStore({ url: TEST_DB, ssl: { mode: "off" }, logger });
  await store.migrate();
  const discord = createDiscordClient({ apiBase: `http://127.0.0.1:${fake.port}/api/v10`, cdnHosts: [`127.0.0.1:${fake.port}`], allowInsecureCdn: true });
  const app = createApp({ config: { trustProxy: false, allowedOrigins: [], publicDir: require("path").join(__dirname, "..", "public") }, service: createNoteService({ store, discord, keyring, logger }), store, keyring, logger });
  const server = await new Promise((r) => { const s = app.listen(0, "127.0.0.1", () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    store,
    encrypt: t.encrypt,
    post: async (p, b) => {
      const res = await fetch(base + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b) });
      const text = await res.text();
      return { status: res.status, text, json: JSON.parse(text) };
    },
    close: async () => { server.closeAllConnections?.(); await new Promise((r) => server.close(r)); await store.close(); }
  };
}

test("discord 429 with nothing loaded surfaces retry_after", async () => {
  const enc = t.encrypt(fake.addWebhook());
  await t.post("/send", { webhook_url: enc, raw_message: "a" });
  const t2 = await buildTestAppKeepDb();
  fake.state.rateLimitNext = 10;
  const r = await t2.post("/api/v1/retrieve", { webhook_url: enc });
  assert.equal(r.status, 429);
  assert.equal(r.json.code, "rate_limited");
  assert.ok(r.json.retry_after >= 1);
  fake.state.rateLimitNext = 0;
  await t2.close();
});

test("unknown message is pruned, unknown webhook keeps records", async () => {
  const enc = t.encrypt(fake.addWebhook());
  const a = await t.post("/send", { webhook_url: enc, raw_message: "a" });
  await t.post("/send", { webhook_url: enc, raw_message: "b" });
  fake.state.messages.delete(a.json.note_id);
  const t2 = await buildTestAppKeepDb();
  const r = await t2.post("/api/v1/retrieve", { webhook_url: enc });
  assert.deepEqual(r.json.notes.map((n) => n.content), ["b"]);
  assert.equal(r.json.removed, 1);
  await t2.close();
  const t3 = await buildTestAppKeepDb();
  fake.state.unknownWebhookOnMessages = true;
  const r2 = await t3.post("/api/v1/retrieve", { webhook_url: enc });
  assert.equal(r2.status, 400);
  assert.equal(r2.json.code, "invalid_webhook");
  fake.state.unknownWebhookOnMessages = false;
  const kept = await t3.store.pool.query("SELECT count(*)::int AS n FROM note_messages");
  assert.equal(kept.rows[0].n, 1);
  const cachedDead = await t3.post("/count", { webhook_url: enc });
  assert.equal(cachedDead.json.code, "invalid_webhook");
  await t3.close();
});

test("nonce makes concurrent duplicate sends idempotent", async () => {
  const enc = t.encrypt(fake.addWebhook());
  const nonce = crypto.randomBytes(16).toString("base64url");
  const [a, b] = await Promise.all([
    t.post("/send", { webhook_url: enc, raw_message: "once", nonce }),
    t.post("/send", { webhook_url: enc, raw_message: "once", nonce })
  ]);
  assert.equal(a.json.note_id, b.json.note_id);
  assert.equal(fake.state.messages.size, 1);
});

test("transport hardening: content-type, origin, body errors, 404s, headers", async () => {
  const enc = t.encrypt(fake.addWebhook());
  const form = await fetch(t.base + "/send", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "a=b" });
  assert.equal(form.status, 415);
  const cross = await t.post("/send", { webhook_url: enc, raw_message: "x" }, { origin: "https://evil.example" });
  assert.equal(cross.status, 403);
  const site = await t.post("/send", { webhook_url: enc, raw_message: "x" }, { "sec-fetch-site": "cross-site" });
  assert.equal(site.status, 403);
  const same = await t.post("/count", { webhook_url: enc }, { origin: t.base });
  assert.equal(same.status, 200);
  const behindTls = await t.post("/count", { webhook_url: enc }, { origin: t.base.replace("http://", "https://") });
  assert.equal(behindTls.status, 200);
  const nullOrigin = await t.post("/count", { webhook_url: enc }, { origin: "null" });
  assert.equal(nullOrigin.status, 403);
  const bad = await t.post("/send", "{not json");
  assert.equal(bad.status, 400);
  assert.equal(bad.json.code, "invalid_body");
  const arr = await t.post("/send", "[1,2]");
  assert.equal(arr.status, 400);
  const big = await t.post("/send", { webhook_url: enc, raw_message: "x".repeat(70000) });
  assert.equal(big.status, 413);
  const nf = await t.post("/nope", {});
  assert.equal(nf.status, 404);
  const html = await fetch(t.base + "/nope", { headers: { accept: "text/html" } });
  assert.equal(html.status, 404);
  assert.match(html.headers.get("content-type"), /html/);
  const put = await fetch(t.base + "/send", { method: "PUT" });
  assert.equal(put.status, 405);
  const idx = await fetch(t.base + "/");
  assert.equal(idx.status, 200);
  const csp = idx.headers.get("content-security-policy");
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /require-trusted-types-for 'script'/);
  assert.equal(idx.headers.get("x-frame-options"), "DENY");
  const api = await t.post("/count", { webhook_url: enc });
  assert.equal(api.headers.get("cache-control"), "no-store");
  assert.equal(api.headers.get("x-powered-by"), null);
  const dot = await fetch(t.base + "/.env");
  assert.equal(dot.status, 404);
});

test("logs never contain webhook tokens or plaintext", async () => {
  const wh = fake.addWebhook();
  const enc = t.encrypt(wh);
  await t.post("/send", { webhook_url: enc, raw_message: "TOPSECRET-PLAINTEXT" });
  await t.post("/api/v1/retrieve", { webhook_url: enc });
  await t.post("/send", "{broken");
  const token = wh.split("/").pop();
  const all = t.logLines.join("\n");
  assert.ok(t.logLines.length > 0);
  assert.ok(!all.includes(token));
  assert.ok(!all.includes("TOPSECRET"));
  assert.ok(!all.includes(enc.slice(0, 40)));
});

test("discord unreachable yields 502 without internals", async () => {
  const { createDiscordClient } = require("../src/discord");
  const { createNoteService } = require("../src/service");
  const { createLogger } = require("../src/logger");
  const discord = createDiscordClient({ apiBase: "http://127.0.0.1:1/api/v10", timeoutMs: 1000 });
  const svc = createNoteService({ store: t.store, discord, keyring: t.keyring, logger: createLogger("error", () => {}) });
  const { parseWebhook } = require("../src/webhook");
  const wh = parseWebhook(fake.addWebhook());
  await assert.rejects(svc.send(wh, "x"), (e) => e.status === 502 && e.code === "upstream_error");
});

test("rate limiters engage on verify bursts", async () => {
  const t2 = await buildTestApp({ fake, rateLimits: { verify: 3 } });
  const enc = t2.encrypt(fake.addWebhook());
  const codes = [];
  for (let i = 0; i < 5; i++) codes.push((await t2.post("/verify", { webhook_url: enc })).status);
  assert.deepEqual(codes, [200, 200, 200, 429, 429]);
  await t2.close();
});
