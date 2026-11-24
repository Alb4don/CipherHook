"use strict";

const { parseWebhook, isSnowflake } = require("./webhook");
const { DiscordError } = require("./discord");
const { CryptoError, MAX_PAYLOAD_BYTES } = require("./crypto");
const { LruCache } = require("./cache");
const { AppError, Errors } = require("./errors");

const LIMITS = Object.freeze({
  messageLength: 5000,
  notesPerWebhook: 5000,
  pageDefault: 10,
  pageMax: 25,
  usernameLength: 80,
  avatarLength: 512
});
const FILENAME = "payload.bin";
const DEFAULT_USERNAME = "CipherHook";
const DEFAULT_AVATAR = "https://i.imgur.com/1BxJoqZ.jpeg";
const NOTE_NONCE = /^[A-Za-z0-9_-]{16,64}$/;

function sanitizeMessage(msg) {
  if (typeof msg !== "string") return null;
  const cleaned = msg.replace(/\u0000/g, "").replace(/\r\n?/g, "\n");
  if (cleaned.trim().length === 0 || cleaned.length > LIMITS.messageLength) return null;
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(cleaned)) return null;
  return cleaned;
}

function normalizeUsername(name) {
  if (name === undefined || name === null) return "";
  if (typeof name !== "string") return null;
  const cleaned = name.normalize("NFKC").replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF]/g, "").trim();
  if (cleaned.length === 0) return "";
  if (cleaned.length > LIMITS.usernameLength) return null;
  if (/discord|clyde/i.test(cleaned) || /^(everyone|here)$/i.test(cleaned)) return null;
  return cleaned;
}

function normalizeAvatar(raw) {
  if (raw === undefined || raw === null) return "";
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  if (s.length === 0) return "";
  if (s.length > LIMITS.avatarLength) return null;
  let u;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || u.username || u.password || !u.hostname.includes(".")) return null;
  return u.href.length > LIMITS.avatarLength ? null : u.href;
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      try {
        out[idx] = { ok: true, value: await fn(items[idx], idx) };
      } catch (error) {
        out[idx] = { ok: false, error };
      }
    }
  });
  await Promise.all(workers);
  return out;
}

function createNoteService({ store, discord, keyring, logger, payloadCacheBytes = 32 * 1024 * 1024 }) {
  const payloadCache = new LruCache({ maxEntries: 8000, maxBytes: payloadCacheBytes, ttlMs: 10 * 60 * 1000, sizeOf: (v) => v.payload.length + 128 });
  const invalidWebhooks = new LruCache({ maxEntries: 20000, ttlMs: 10 * 60 * 1000 });
  const verifiedWebhooks = new LruCache({ maxEntries: 20000, ttlMs: 5 * 60 * 1000 });
  const inflightSends = new LruCache({ maxEntries: 5000, ttlMs: 2 * 60 * 1000 });

  function toAppError(err, webhook) {
    if (err instanceof AppError) return err;
    if (err instanceof DiscordError) {
      if (err.kind === "invalid_webhook") {
        if (webhook) {
          invalidWebhooks.set(webhook.key, true);
          verifiedWebhooks.delete(webhook.key);
        }
        return Errors.invalidWebhook();
      }
      if (err.kind === "rate_limited") return Errors.rateLimited(err.retryAfterMs);
      if (err.kind === "bad_request") return new AppError(422, "rejected", "discord rejected the request");
      return Errors.upstream();
    }
    return err;
  }

  async function resolveWebhook(encrypted) {
    const plain = keyring.decryptTransport(encrypted);
    const webhook = plain ? parseWebhook(plain) : null;
    if (!webhook) throw Errors.invalidWebhook();
    if (invalidWebhooks.get(webhook.key)) throw Errors.invalidWebhook();
    await store.adoptLegacy(webhook);
    return webhook;
  }

  async function verify(webhook) {
    try {
      const info = await discord.getWebhook(webhook);
      verifiedWebhooks.set(webhook.key, info.name);
      return { name: info.name };
    } catch (err) {
      throw toAppError(err, webhook);
    }
  }

  async function profileFor(key) {
    const p = await store.getProfile(key);
    const username = normalizeUsername(p?.username) || DEFAULT_USERNAME;
    const avatarUrl = normalizeAvatar(p?.avatarUrl) || DEFAULT_AVATAR;
    return { username, avatarUrl, custom: Boolean(p && (p.username || p.avatarUrl)) };
  }

  async function doSend(webhook, message) {
    const count = await store.countNotes(webhook.key);
    if (count >= LIMITS.notesPerWebhook) throw Errors.limitReached();
    const profile = await profileFor(webhook.key);
    const payload = keyring.encryptNote(message, webhook.key);
    let sent;
    try {
      sent = await discord.executeWebhook(webhook, { payload, filename: FILENAME, username: profile.username, avatarUrl: profile.avatarUrl });
    } catch (err) {
      throw toAppError(err, webhook);
    }
    try {
      await store.addNote(webhook.key, sent.id, keyring.digest(payload));
    } catch (err) {
      logger.error("note persist failed, compensating", { err });
      discord.deleteMessage(webhook, sent.id).catch(() => logger.warn("compensating delete failed"));
      throw err;
    }
    payloadCache.set(`${webhook.key}:${sent.id}`, { payload, timestamp: sent.timestamp });
    return { note_id: sent.id, timestamp: sent.timestamp, content: message, author: profile.username };
  }

  async function send(webhook, rawMessage, nonce) {
    const message = sanitizeMessage(rawMessage);
    if (!message) throw Errors.invalidMessage();
    if (nonce !== undefined && (typeof nonce !== "string" || !NOTE_NONCE.test(nonce))) throw Errors.invalidBody();
    if (!nonce) return doSend(webhook, message);
    const k = `${webhook.key}:${nonce}`;
    const existing = inflightSends.get(k);
    if (existing) return existing;
    const p = doSend(webhook, message);
    inflightSends.set(k, p);
    p.catch(() => inflightSends.delete(k));
    return p;
  }

  async function loadPayload(webhook, row) {
    const ck = `${webhook.key}:${row.id}`;
    const cached = payloadCache.get(ck);
    if (cached) return cached;
    const m = await discord.getMessage(webhook, row.id);
    if (!m) return null;
    if (m.edited) throw new CryptoError("edited message rejected");
    if (!m.attachment || m.attachment.filename !== FILENAME || m.attachment.size > MAX_PAYLOAD_BYTES) throw new CryptoError("unexpected attachment");
    const payload = await discord.downloadAttachment(m.attachment.url, MAX_PAYLOAD_BYTES);
    const entry = { payload, timestamp: m.timestamp };
    payloadCache.set(ck, entry);
    return entry;
  }

  async function readNote(webhook, row) {
    const entry = await loadPayload(webhook, row);
    if (!entry) {
      await store.deleteNote(webhook.key, row.id);
      return { gone: true };
    }
    if (row.digest && !keyring.digest(entry.payload).equals(row.digest)) throw new CryptoError("digest mismatch");
    const content = keyring.decryptNote(entry.payload, webhook.key, { allowLegacy: !row.digest });
    if (content.length > LIMITS.messageLength * 2) throw new CryptoError("oversized");
    return { note: { note_id: row.id, content, timestamp: entry.timestamp } };
  }

  async function list(webhook, { cursor, index, limit }) {
    const size = limit === undefined ? LIMITS.pageDefault : limit;
    if (!Number.isInteger(size) || size < 1 || size > LIMITS.pageMax) throw Errors.invalidBody();
    if (cursor !== undefined && cursor !== null && !isSnowflake(cursor)) throw Errors.invalidCursor();
    if (index !== undefined && (!Number.isInteger(index) || index < 0 || index > 100000)) throw Errors.invalidIndex();
    const rows = await store.listNotes(webhook.key, { before: cursor || null, offset: cursor ? 0 : index || 0, limit: size });
    if (index !== undefined && !cursor && rows.length === 0) throw Errors.noteNotFound();
    const results = await mapLimit(rows, 4, (row) => readNote(webhook, row));
    let cut = results.length;
    let rateLimit = null;
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.ok || r.error instanceof CryptoError) continue;
      const app = toAppError(r.error, webhook);
      if (app.code === "invalid_webhook") throw app;
      if (app.code === "rate_limited") {
        cut = i;
        rateLimit = app;
        break;
      }
      if (!(r.error instanceof DiscordError)) throw r.error;
    }
    if (rateLimit && cut === 0) throw rateLimit;
    const notes = [];
    let removed = 0;
    let unreadable = 0;
    for (const r of results.slice(0, cut)) {
      if (r.ok) {
        if (r.value.gone) removed++;
        else notes.push(r.value.note);
      } else {
        unreadable++;
        logger.warn("note unreadable", { reason: r.error instanceof CryptoError ? r.error.message : r.error.kind });
      }
    }
    const partial = cut < rows.length;
    const nextCursor = partial ? rows[cut - 1].id : rows.length === size ? rows[rows.length - 1].id : null;
    return {
      notes,
      next_cursor: nextCursor,
      consumed: cut,
      removed,
      unreadable,
      partial,
      retry_after: rateLimit?.extra?.retry_after
    };
  }

  async function remove(webhook, noteId) {
    if (!isSnowflake(noteId)) throw Errors.invalidNoteId();
    const row = await store.getNote(webhook.key, noteId);
    if (!row) return { deleted: false };
    try {
      await discord.deleteMessage(webhook, noteId);
    } catch (err) {
      throw toAppError(err, webhook);
    }
    await store.deleteNote(webhook.key, noteId);
    payloadCache.delete(`${webhook.key}:${noteId}`);
    return { deleted: true };
  }

  async function count(webhook) {
    return store.countNotes(webhook.key);
  }

  async function getSettings(webhook) {
    const p = await store.getProfile(webhook.key);
    return {
      username: normalizeUsername(p?.username) || DEFAULT_USERNAME,
      pfp_link: normalizeAvatar(p?.avatarUrl) || DEFAULT_AVATAR
    };
  }

  async function updateSettings(webhook, { username, pfp_link }) {
    const u = normalizeUsername(username);
    if (u === null) throw Errors.invalidUsername();
    const a = normalizeAvatar(pfp_link);
    if (a === null) throw Errors.invalidAvatar();
    await store.upsertProfile(webhook.key, { username: u, avatarUrl: a });
    return { username: u || DEFAULT_USERNAME, pfp_link: a || DEFAULT_AVATAR };
  }

  return { resolveWebhook, verify, send, list, remove, count, getSettings, updateSettings };
}

module.exports = { createNoteService, sanitizeMessage, normalizeUsername, normalizeAvatar, mapLimit, LIMITS, DEFAULT_USERNAME, DEFAULT_AVATAR };
