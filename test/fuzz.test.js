"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");
const { createKeyring, CryptoError } = require("../src/crypto");
const { parseWebhook } = require("../src/webhook");
const { sanitizeMessage, normalizeUsername, normalizeAvatar } = require("../src/service");
const { redact } = require("../src/logger");
const { testKeys, startFakeDiscord, buildTestApp } = require("./helpers");

const RUNS = Number(process.env.FUZZ_RUNS || 300);
const keys = testKeys();
const kr = createKeyring(keys.privatePem, keys.publicPem);

test("fuzz: webhook parser never throws and only accepts canonical shapes", () => {
  const tokenArb = fc.stringMatching(/^[A-Za-z0-9_-]{60,100}$/);
  const idArb = fc.stringMatching(/^[1-9]\d{16,17}$/);
  fc.assert(fc.property(idArb, tokenArb, (id, token) => {
    const w = parseWebhook(`https://discord.com/api/webhooks/${id}/${token}`);
    return w && w.id === id && w.token === token && /^[0-9a-f]{64}$/.test(w.key) && w.path === `/webhooks/${id}/${token}`;
  }), { numRuns: RUNS });
  fc.assert(fc.property(fc.oneof(fc.string(), fc.fullUnicodeString(), fc.webUrl(), fc.anything()), (s) => {
    const w = parseWebhook(s);
    return w === null || (typeof s === "string" && !/[\s?#@]/.test(s));
  }), { numRuns: RUNS * 3 });
});

test("fuzz: note codec roundtrips arbitrary unicode", () => {
  fc.assert(fc.property(fc.fullUnicodeString({ minLength: 1, maxLength: 5000 }), fc.hexaString({ minLength: 64, maxLength: 64 }), (msg, key) => {
    return kr.decryptNote(kr.encryptNote(msg, key), key, { allowLegacy: false }) === msg;
  }), { numRuns: RUNS });
});

test("fuzz: decryptNote on hostile bytes only throws CryptoError", () => {
  const valid = kr.encryptNote("seed", "d".repeat(64));
  const mutated = fc.tuple(fc.nat({ max: valid.length - 1 }), fc.integer({ min: 1, max: 255 })).map(([i, x]) => {
    const b = Buffer.from(valid);
    b[i] ^= x;
    return b;
  });
  const arb = fc.oneof(
    fc.uint8Array({ maxLength: 4096 }).map((a) => Buffer.from(a)),
    fc.uint8Array({ maxLength: 512 }).map((a) => Buffer.concat([Buffer.from("CH2\u0000", "latin1"), Buffer.from(a)])),
    fc.array(fc.base64String({ maxLength: 400 }), { minLength: 4, maxLength: 4 }).map((p) => Buffer.from(p.join("|"))),
    mutated
  );
  fc.assert(fc.property(arb, fc.boolean(), (buf, legacy) => {
    try {
      kr.decryptNote(buf, "d".repeat(64), { allowLegacy: legacy });
      return false;
    } catch (e) {
      return e instanceof CryptoError;
    }
  }), { numRuns: RUNS * 3 });
});

test("fuzz: transport decrypt never throws", () => {
  fc.assert(fc.property(fc.oneof(fc.base64String({ minLength: 0, maxLength: 1500 }), fc.string(), fc.anything()), (s) => {
    return kr.decryptTransport(s) === null;
  }), { numRuns: RUNS * 3 });
});

test("fuzz: normalizers are total and preserve invariants", () => {
  fc.assert(fc.property(fc.oneof(fc.fullUnicodeString({ maxLength: 6000 }), fc.anything()), (v) => {
    const m = sanitizeMessage(v);
    if (m !== null && (typeof m !== "string" || m.length > 5000 || m.includes("\u0000") || m.includes("\r") || !m.trim())) return false;
    const u = normalizeUsername(v);
    if (u !== null && (typeof u !== "string" || u.length > 80 || /discord|clyde/i.test(u) || /[\u0000-\u001F]/.test(u))) return false;
    const a = normalizeAvatar(v);
    if (a !== null && a !== "" && (!a.startsWith("https://") || a.length > 512)) return false;
    return true;
  }), { numRuns: RUNS * 3 });
});

test("fuzz: redaction removes any embedded webhook token", () => {
  fc.assert(fc.property(fc.string(), fc.stringMatching(/^[A-Za-z0-9_-]{60,80}$/), fc.string(), (pre, token, post) => {
    return !redact(`${pre}https://discord.com/api/webhooks/123456789012345678/${token}${post}`).includes(token);
  }), { numRuns: RUNS });
});

let fake;
let t;
before(async () => {
  fake = await startFakeDiscord();
  t = await buildTestApp({ fake, rateLimits: { global: 1e6, send: 1e6, verify: 1e6 } });
});
after(async () => {
  await t.close();
  await fake.close();
});

test("fuzz: API never returns 5xx or leaks internals on hostile bodies", async () => {
  const wh = fake.addWebhook();
  const enc = t.encrypt(wh);
  await t.post("/send", { webhook_url: enc, raw_message: "seed" });
  const routes = ["/send", "/retrieve", "/delete", "/count", "/settings", "/update_settings", "/verify", "/api/v1/retrieve", "/api/v1/send"];
  const junk = fc.oneof(fc.string(), fc.integer(), fc.double(), fc.boolean(), fc.constant(null), fc.array(fc.string(), { maxLength: 3 }), fc.object({ maxDepth: 2 }), fc.fullUnicodeString({ maxLength: 300 }), fc.stringMatching(/^\d{17,21}$/));
  const mix = (valid) => fc.oneof({ arbitrary: valid, weight: 4 }, { arbitrary: junk, weight: 1 });
  const body = fc.record({
    webhook_url: mix(fc.constant(enc)),
    raw_message: mix(fc.fullUnicodeString({ minLength: 1, maxLength: 400 })),
    note_id: mix(fc.stringMatching(/^[1-9]\d{17}$/)),
    note_index: mix(fc.nat({ max: 50 })),
    cursor: mix(fc.stringMatching(/^[1-9]\d{17,18}$/)),
    limit: mix(fc.integer({ min: 1, max: 25 })),
    nonce: mix(fc.stringMatching(/^[A-Za-z0-9_-]{16,64}$/)),
    username: mix(fc.string({ maxLength: 90 })),
    pfp_link: mix(fc.webUrl({ validSchemes: ["https"] })),
    __proto__: junk,
    constructor: junk
  }, { requiredKeys: ["webhook_url"] });
  const raw = fc.oneof(body.map((b) => JSON.stringify(b)), fc.string({ maxLength: 200 }), fc.constant("null"), fc.constant("[]"), fc.constant('"x"'), fc.constant("{\"__proto__\":{\"polluted\":1}}"));
  const statuses = new Map();
  await fc.assert(fc.asyncProperty(fc.constantFrom(...routes), raw, async (route, payload) => {
    const r = await t.post(route, payload);
    statuses.set(r.status, (statuses.get(r.status) || 0) + 1);
    assert.ok(r.status < 500, `${route} ${r.status} ${r.text}`);
    assert.notEqual(r.status, 429, "fuzz must exercise handlers, not the limiter");
    assert.ok(!/at \w+ \(|node_modules|\/src\/|stack|SyntaxError|TypeError/.test(r.text), r.text);
    assert.ok(r.json && typeof r.json === "object", r.text);
    assert.equal({}.polluted, undefined);
  }), { numRuns: Number(process.env.FUZZ_HTTP_RUNS || 600) });
  if (process.env.FUZZ_REPORT) console.log("status distribution", JSON.stringify([...statuses].sort()));
  assert.ok((statuses.get(200) || 0) > 50, JSON.stringify([...statuses]));
  assert.ok((statuses.get(400) || 0) > 10, JSON.stringify([...statuses]));
});

test("fuzz: legacy payload with forged key and invalid utf-8 is rejected cleanly", () => {
  const crypto = require("crypto");
  const aes = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", aes, iv);
  const ct = Buffer.concat([c.update(Buffer.from([0xff, 0xfe, 0xc3])), c.final()]);
  const ek = crypto.publicEncrypt({ key: keys.publicPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, aes);
  const p = Buffer.from([ek, iv, c.getAuthTag(), ct].map((x) => x.toString("base64")).join("|"));
  assert.throws(() => kr.decryptNote(p, "e".repeat(64), { allowLegacy: true }), CryptoError);
});
