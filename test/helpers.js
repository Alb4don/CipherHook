"use strict";

const http = require("http");
const crypto = require("crypto");
const { createKeyring } = require("../src/crypto");
const { createStore } = require("../src/store");
const { createDiscordClient } = require("../src/discord");
const { createNoteService } = require("../src/service");
const { createApp } = require("../src/http/app");
const { createLogger } = require("../src/logger");

const TEST_DB = process.env.TEST_POSTGRES_URL || "postgres://cipherhook@127.0.0.1:55432/cipherhook_test";

let cachedKeys;
function testKeys() {
  if (!cachedKeys) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    cachedKeys = {
      privatePem: privateKey.export({ type: "pkcs8", format: "pem" }),
      publicPem: publicKey.export({ type: "spki", format: "pem" })
    };
  }
  return cachedKeys;
}

function randomToken() {
  return crypto.randomBytes(51).toString("base64url").slice(0, 68);
}

let snowCounter = 0n;
function snowflake() {
  snowCounter = (snowCounter + 1n) % 4096n;
  return ((BigInt(Date.now() - 1420070400000) << 22n) | snowCounter).toString();
}

function startFakeDiscord() {
  const state = {
    webhooks: new Map(),
    messages: new Map(),
    calls: [],
    rateLimitNext: 0,
    unknownWebhookOnMessages: false,
    lastPayloadJson: null
  };
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    const url = new URL(req.url, "http://x");
    state.calls.push(`${req.method} ${url.pathname}`);
    const json = (status, obj, headers = {}) => {
      res.writeHead(status, { "content-type": "application/json", ...headers });
      res.end(obj === undefined ? "" : JSON.stringify(obj));
    };
    const cdn = /^\/cdn\/(\d+)\/payload\.bin$/.exec(url.pathname);
    if (cdn) {
      const m = state.messages.get(cdn[1]);
      if (!m) return json(404, { message: "not found" });
      res.writeHead(200, { "content-type": "application/octet-stream" });
      return res.end(m.payload);
    }
    const m = /^\/api\/v10\/webhooks\/(\d+)\/([A-Za-z0-9_-]+)(?:\/messages\/(\d+))?$/.exec(url.pathname);
    if (!m) return json(404, { code: 0 });
    if (state.rateLimitNext > 0) {
      state.rateLimitNext--;
      return json(429, { message: "rate limited", retry_after: 30, global: false }, { "x-ratelimit-remaining": "0", "x-ratelimit-reset-after": "30" });
    }
    const [, id, token, mid] = m;
    const wh = state.webhooks.get(id);
    if (!wh || wh.token !== token) return json(404, { code: 10015, message: "Unknown Webhook" });
    const headers = { "x-ratelimit-remaining": "4", "x-ratelimit-reset-after": "0.2" };
    if (!mid && req.method === "GET") return json(200, { id, name: wh.name, token }, headers);
    if (!mid && req.method === "POST") {
      const form = await new Response(body, { headers: { "content-type": req.headers["content-type"] } }).formData();
      const file = form.get("files[0]");
      state.lastPayloadJson = JSON.parse(form.get("payload_json"));
      const msgId = snowflake();
      const payload = Buffer.from(await file.arrayBuffer());
      const msg = { id: msgId, webhookId: id, payload, filename: file.name, timestamp: new Date().toISOString(), edited: null };
      state.messages.set(msgId, msg);
      return json(200, { id: msgId, timestamp: msg.timestamp, attachments: [] }, headers);
    }
    if (mid) {
      if (state.unknownWebhookOnMessages) return json(404, { code: 10015, message: "Unknown Webhook" });
      const msg = state.messages.get(mid);
      if (!msg || msg.webhookId !== id) return json(404, { code: 10008, message: "Unknown Message" });
      if (req.method === "DELETE") {
        state.messages.delete(mid);
        res.writeHead(204, headers);
        return res.end();
      }
      if (req.method === "GET") {
        const port = server.address().port;
        return json(200, {
          id: mid,
          timestamp: msg.timestamp,
          edited_timestamp: msg.edited,
          attachments: [{ id: "1", filename: msg.filename, size: msg.payload.length, url: `http://127.0.0.1:${port}/cdn/${mid}/payload.bin?ex=abc&hm=def` }]
        }, headers);
      }
    }
    return json(405, { code: 0 });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      resolve({
        state,
        port,
        addWebhook(name = "Notes") {
          const id = snowflake();
          const token = randomToken();
          state.webhooks.set(id, { token, name });
          return `https://discord.com/api/webhooks/${id}/${token}`;
        },
        close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); })
      });
    });
  });
}

async function resetDb(store) {
  await store.pool.query("DROP TABLE IF EXISTS note_messages, webhook_profiles, notes, schema_migrations CASCADE");
}

async function buildTestApp({ fake, logLines = [], rateLimits }) {
  const keys = testKeys();
  const logger = createLogger("debug", (l) => logLines.push(l));
  const keyring = createKeyring(keys.privatePem, keys.publicPem);
  const store = createStore({ url: TEST_DB, ssl: { mode: "off" }, poolMax: 8, logger });
  await resetDb(store);
  await store.migrate();
  const discord = createDiscordClient({
    apiBase: `http://127.0.0.1:${fake.port}/api/v10`,
    cdnHosts: [`127.0.0.1:${fake.port}`],
    allowInsecureCdn: true,
    maxWaitMs: 1000
  });
  const service = createNoteService({ store, discord, keyring, logger });
  const config = { trustProxy: false, allowedOrigins: [], rateLimits, publicDir: require("path").join(__dirname, "..", "public") };
  const app = createApp({ config, service, store, keyring, logger });
  const server = await new Promise((r) => { const s = app.listen(0, "127.0.0.1", () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const encrypt = (url) => crypto.publicEncrypt({ key: keys.publicPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from(url)).toString("base64");
  const post = async (path, body, headers = {}) => {
    const res = await fetch(base + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text, headers: res.headers };
  };
  return {
    keys, keyring, store, service, base, post, encrypt, logLines,
    close: async () => { server.closeAllConnections?.(); await new Promise((r) => server.close(r)); await store.close(); }
  };
}

module.exports = { startFakeDiscord, buildTestApp, testKeys, randomToken, snowflake, TEST_DB };
