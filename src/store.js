"use strict";

const { Pool } = require("pg");
const { LruCache } = require("./cache");

const MIGRATIONS = [
  {
    version: 1,
    sql: `CREATE TABLE IF NOT EXISTS notes (
            webhook_hash TEXT PRIMARY KEY,
            note_ids TEXT NOT NULL DEFAULT '[]',
            pfp_link TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL DEFAULT ''
          )`
  },
  {
    version: 2,
    sql: `CREATE TABLE IF NOT EXISTS webhook_profiles (
            webhook_key TEXT PRIMARY KEY CHECK (webhook_key ~ '^[0-9a-f]{64}$'),
            username TEXT NOT NULL DEFAULT '' CHECK (char_length(username) <= 80),
            avatar_url TEXT NOT NULL DEFAULT '' CHECK (char_length(avatar_url) <= 512),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
          );
          CREATE TABLE IF NOT EXISTS note_messages (
            webhook_key TEXT NOT NULL CHECK (webhook_key ~ '^[0-9a-f]{64}$'),
            message_id BIGINT NOT NULL CHECK (message_id > 0),
            digest BYTEA CHECK (digest IS NULL OR octet_length(digest) = 32),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (webhook_key, message_id)
          )`
  }
];

function createStore({ url, ssl, poolMax = 12, logger, PoolImpl = Pool }) {
  const sslOpt = ssl.mode === "off" ? false : { rejectUnauthorized: ssl.mode === "verify" };
  const pool = new PoolImpl({
    connectionString: url,
    ssl: sslOpt,
    max: poolMax,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    statement_timeout: 5000,
    query_timeout: 6000,
    application_name: "cipherhook"
  });
  pool.on("error", (err) => logger.warn("idle database client error", { err }));

  const adopted = new LruCache({ maxEntries: 20000, ttlMs: 6 * 60 * 60 * 1000 });
  let legacyPresent = true;

  async function tx(fn) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const out = await fn(client);
      await client.query("COMMIT");
      return out;
    } catch (err) {
      try { await client.query("ROLLBACK"); } catch {}
      throw err;
    } finally {
      client.release();
    }
  }

  async function migrate() {
    await tx(async (c) => {
      await c.query("SELECT pg_advisory_xact_lock(727274)");
      await c.query("CREATE TABLE IF NOT EXISTS schema_migrations (version INT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())");
      const { rows } = await c.query("SELECT version FROM schema_migrations");
      const done = new Set(rows.map((r) => r.version));
      for (const m of MIGRATIONS) {
        if (done.has(m.version)) continue;
        await c.query(m.sql);
        await c.query("INSERT INTO schema_migrations (version) VALUES ($1)", [m.version]);
      }
    });
    const { rows } = await pool.query("SELECT EXISTS (SELECT 1 FROM notes) AS present");
    legacyPresent = rows[0].present;
  }

  function parseLegacyIds(raw) {
    try {
      const parsed = JSON.parse(raw || "[]");
      if (!Array.isArray(parsed)) return [];
      return [...new Set(parsed.filter((id) => typeof id === "string" && /^\d{17,19}$/.test(id) && BigInt(id) <= 9223372036854775807n))];
    } catch {
      return [];
    }
  }

  async function adoptLegacy(webhook) {
    if (!legacyPresent || adopted.get(webhook.key)) return;
    await tx(async (c) => {
      const { rows } = await c.query("SELECT note_ids, pfp_link, username FROM notes WHERE webhook_hash = $1 FOR UPDATE", [webhook.legacyKey]);
      if (!rows.length) return;
      const ids = parseLegacyIds(rows[0].note_ids);
      if (ids.length) {
        await c.query(
          "INSERT INTO note_messages (webhook_key, message_id, digest) SELECT $1, unnest($2::bigint[]), NULL ON CONFLICT DO NOTHING",
          [webhook.key, ids]
        );
      }
      await c.query(
        "INSERT INTO webhook_profiles (webhook_key, username, avatar_url) VALUES ($1, $2, $3) ON CONFLICT (webhook_key) DO NOTHING",
        [webhook.key, String(rows[0].username || "").slice(0, 80), String(rows[0].pfp_link || "").slice(0, 512)]
      );
      await c.query("DELETE FROM notes WHERE webhook_hash = $1", [webhook.legacyKey]);
    });
    adopted.set(webhook.key, true);
  }

  async function addNote(key, messageId, digest) {
    await pool.query(
      "INSERT INTO note_messages (webhook_key, message_id, digest) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
      [key, messageId, digest]
    );
  }

  async function listNotes(key, { before, offset, limit }) {
    if (before) {
      const { rows } = await pool.query(
        "SELECT message_id::text AS id, digest FROM note_messages WHERE webhook_key = $1 AND message_id < $2 ORDER BY message_id DESC LIMIT $3",
        [key, before, limit]
      );
      return rows;
    }
    const { rows } = await pool.query(
      "SELECT message_id::text AS id, digest FROM note_messages WHERE webhook_key = $1 ORDER BY message_id DESC OFFSET $2 LIMIT $3",
      [key, offset || 0, limit]
    );
    return rows;
  }

  async function getNote(key, messageId) {
    const { rows } = await pool.query(
      "SELECT message_id::text AS id, digest FROM note_messages WHERE webhook_key = $1 AND message_id = $2",
      [key, messageId]
    );
    return rows[0] || null;
  }

  async function countNotes(key) {
    const { rows } = await pool.query("SELECT count(*)::int AS n FROM note_messages WHERE webhook_key = $1", [key]);
    return rows[0].n;
  }

  async function deleteNote(key, messageId) {
    const { rowCount } = await pool.query("DELETE FROM note_messages WHERE webhook_key = $1 AND message_id = $2", [key, messageId]);
    return rowCount > 0;
  }

  async function getProfile(key) {
    const { rows } = await pool.query("SELECT username, avatar_url FROM webhook_profiles WHERE webhook_key = $1", [key]);
    return rows[0] ? { username: rows[0].username, avatarUrl: rows[0].avatar_url } : null;
  }

  async function upsertProfile(key, { username, avatarUrl }) {
    await pool.query(
      `INSERT INTO webhook_profiles (webhook_key, username, avatar_url) VALUES ($1, $2, $3)
       ON CONFLICT (webhook_key) DO UPDATE SET username = EXCLUDED.username, avatar_url = EXCLUDED.avatar_url, updated_at = now()`,
      [key, username, avatarUrl]
    );
  }

  async function ping() {
    await pool.query("SELECT 1");
  }

  async function close() {
    await pool.end();
  }

  return { migrate, adoptLegacy, addNote, listNotes, getNote, countNotes, deleteNote, getProfile, upsertProfile, ping, close, pool };
}

module.exports = { createStore, MIGRATIONS };
