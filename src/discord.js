"use strict";

const DEFAULT_API_BASE = "https://discord.com/api/v10";
const DEFAULT_CDN_HOSTS = ["cdn.discordapp.com", "media.discordapp.net", "cdn.discord.com"];
const UNKNOWN_WEBHOOK = 10015;

class DiscordError extends Error {
  constructor(kind, { status, retryAfterMs, code } = {}) {
    super(`discord ${kind}`);
    this.name = "DiscordError";
    this.kind = kind;
    this.status = status;
    this.retryAfterMs = retryAfterMs;
    this.discordCode = code;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class Semaphore {
  constructor(n) {
    this.n = n;
    this.waiters = [];
  }
  async acquire() {
    if (this.n > 0) {
      this.n--;
      return;
    }
    await new Promise((r) => this.waiters.push(r));
  }
  release() {
    const next = this.waiters.shift();
    if (next) next();
    else this.n++;
  }
}

async function readLimited(res, maxBytes) {
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    try { await res.body?.cancel(); } catch {}
    throw new DiscordError("too_large");
  }
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      try { await reader.cancel(); } catch {}
      throw new DiscordError("too_large");
    }
    chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
  }
  return Buffer.concat(chunks, total);
}

async function readJson(res, maxBytes = 256 * 1024) {
  const buf = await readLimited(res, maxBytes);
  if (buf.length === 0) return null;
  try {
    return JSON.parse(buf.toString("utf8"));
  } catch {
    return null;
  }
}

function createDiscordClient({
  apiBase = DEFAULT_API_BASE,
  cdnHosts = DEFAULT_CDN_HOSTS,
  allowInsecureCdn = false,
  fetchImpl = globalThis.fetch,
  timeoutMs = 10000,
  maxWaitMs = 4000,
  perWebhookConcurrency = 2,
  now = Date.now
} = {}) {
  const cdn = new Set(cdnHosts.map((h) => h.toLowerCase()));
  const buckets = new Map();
  let globalResetAt = 0;

  function bucket(id) {
    let b = buckets.get(id);
    if (!b) {
      b = { remaining: Infinity, resetAt: 0, sem: new Semaphore(perWebhookConcurrency), touched: now() };
      buckets.set(id, b);
      if (buckets.size > 10000) {
        const cutoff = now() - 120000;
        for (const [k, v] of buckets) if (v.touched < cutoff) buckets.delete(k);
      }
    }
    b.touched = now();
    return b;
  }

  function updateFromHeaders(b, res) {
    const remaining = Number(res.headers.get("x-ratelimit-remaining"));
    const resetAfter = Number(res.headers.get("x-ratelimit-reset-after"));
    if (Number.isFinite(remaining)) b.remaining = remaining;
    if (Number.isFinite(resetAfter)) b.resetAt = now() + Math.ceil(resetAfter * 1000);
  }

  async function waitFor(b) {
    for (;;) {
      const t = now();
      const waitGlobal = globalResetAt - t;
      const waitBucket = b.remaining <= 0 ? b.resetAt - t : 0;
      const wait = Math.max(waitGlobal, waitBucket);
      if (wait <= 0) {
        if (b.remaining <= 0 && b.resetAt <= t) b.remaining = Infinity;
        return;
      }
      if (wait > maxWaitMs) throw new DiscordError("rate_limited", { retryAfterMs: wait });
      await sleep(wait);
    }
  }

  async function call(webhook, method, subpath, { body, headers, query } = {}) {
    const b = bucket(webhook.id);
    await b.sem.acquire();
    try {
      for (let attempt = 0; attempt < 2; attempt++) {
        await waitFor(b);
        if (b.remaining !== Infinity) b.remaining--;
        const url = `${apiBase}${webhook.path}${subpath}${query ? `?${query}` : ""}`;
        let res;
        try {
          res = await fetchImpl(url, { method, body, headers, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
        } catch (err) {
          throw new DiscordError(err?.name === "TimeoutError" ? "timeout" : "network");
        }
        updateFromHeaders(b, res);
        if (res.status === 429) {
          const data = await readJson(res, 16 * 1024);
          const ra = Number(data?.retry_after ?? res.headers.get("retry-after"));
          const retryAfterMs = Math.max(250, Math.ceil((Number.isFinite(ra) ? ra : 1) * 1000));
          if (data?.global || res.headers.get("x-ratelimit-global")) globalResetAt = now() + retryAfterMs;
          b.remaining = 0;
          b.resetAt = now() + retryAfterMs;
          if (attempt === 0 && retryAfterMs <= maxWaitMs) continue;
          throw new DiscordError("rate_limited", { status: 429, retryAfterMs });
        }
        return res;
      }
      throw new DiscordError("rate_limited", { status: 429, retryAfterMs: 1000 });
    } finally {
      b.sem.release();
    }
  }

  async function failFrom(res, { messageScoped = false } = {}) {
    const data = await readJson(res, 16 * 1024).catch(() => null);
    const code = typeof data?.code === "number" ? data.code : undefined;
    if (res.status === 401 || res.status === 403) return new DiscordError("invalid_webhook", { status: res.status, code });
    if (res.status === 404) {
      if (messageScoped && code !== UNKNOWN_WEBHOOK) return new DiscordError("not_found", { status: 404, code });
      return new DiscordError("invalid_webhook", { status: 404, code });
    }
    if (res.status === 400) return new DiscordError("bad_request", { status: 400, code });
    return new DiscordError("upstream", { status: res.status, code });
  }

  async function getWebhook(webhook) {
    const res = await call(webhook, "GET", "");
    if (res.status !== 200) throw await failFrom(res);
    const data = await readJson(res, 64 * 1024);
    const name = typeof data?.name === "string" ? data.name.slice(0, 80) : "";
    return { name };
  }

  async function executeWebhook(webhook, { payload, filename, username, avatarUrl }) {
    const form = new FormData();
    form.append("payload_json", JSON.stringify({
      username,
      avatar_url: avatarUrl,
      allowed_mentions: { parse: [] },
      attachments: [{ id: 0, filename }]
    }));
    form.append("files[0]", new Blob([payload], { type: "application/octet-stream" }), filename);
    const res = await call(webhook, "POST", "", { body: form, query: "wait=true" });
    if (res.status !== 200) throw await failFrom(res);
    const data = await readJson(res, 128 * 1024);
    const id = typeof data?.id === "string" ? data.id : null;
    if (!id || !/^\d{17,20}$/.test(id)) throw new DiscordError("upstream", { status: res.status });
    return { id, timestamp: typeof data.timestamp === "string" ? data.timestamp : new Date(now()).toISOString() };
  }

  async function getMessage(webhook, messageId) {
    const res = await call(webhook, "GET", `/messages/${messageId}`);
    if (res.status !== 200) {
      const err = await failFrom(res, { messageScoped: true });
      if (err.kind === "not_found") return null;
      throw err;
    }
    const data = await readJson(res, 128 * 1024);
    if (!data || data.id !== messageId) throw new DiscordError("upstream", { status: 200 });
    const att = Array.isArray(data.attachments) && data.attachments.length === 1 ? data.attachments[0] : null;
    return {
      id: data.id,
      timestamp: typeof data.timestamp === "string" ? data.timestamp : null,
      edited: data.edited_timestamp != null,
      attachment: att && typeof att.url === "string"
        ? { url: att.url, filename: String(att.filename || ""), size: Number(att.size) || 0 }
        : null
    };
  }

  async function deleteMessage(webhook, messageId) {
    const res = await call(webhook, "DELETE", `/messages/${messageId}`);
    if (res.status === 204) return true;
    const err = await failFrom(res, { messageScoped: true });
    if (err.kind === "not_found") return true;
    throw err;
  }

  function isCdnUrl(raw) {
    try {
      const u = new URL(raw);
      if (u.username || u.password) return false;
      if (u.protocol !== "https:" && !(allowInsecureCdn && u.protocol === "http:")) return false;
      return cdn.has(u.host.toLowerCase()) || cdn.has(u.hostname.toLowerCase());
    } catch {
      return false;
    }
  }

  async function downloadAttachment(url, maxBytes) {
    if (!isCdnUrl(url)) throw new DiscordError("bad_attachment");
    let res;
    try {
      res = await fetchImpl(url, { redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
    } catch (err) {
      throw new DiscordError(err?.name === "TimeoutError" ? "timeout" : "network");
    }
    if (res.status !== 200) {
      try { await res.body?.cancel(); } catch {}
      throw new DiscordError(res.status === 404 ? "not_found" : "upstream", { status: res.status });
    }
    return readLimited(res, maxBytes);
  }

  return { getWebhook, executeWebhook, getMessage, deleteMessage, downloadAttachment, isCdnUrl };
}

module.exports = { createDiscordClient, DiscordError };
