const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
  ssl: process.env.POSTGRES_SSL === "false" ? false : { rejectUnauthorized: false },
  max: 12,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 8000
});

pool.on("error", () => {
  console.error("database pool error");
  process.exit(1);
});

pool.connect()
  .then(() => console.log("database connected"))
  .catch(() => {
    console.error("database connection failed");
    process.exit(1);
  });

const query = (text, params) => pool.query(text, params);

async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    throw err;
  } finally {
    client.release();
  }
}

async function init_db() {
  try {
    await query(`
      CREATE TABLE IF NOT EXISTS notes (
        webhook_hash TEXT PRIMARY KEY,
        note_ids TEXT NOT NULL DEFAULT '[]',
        pfp_link TEXT NOT NULL DEFAULT '',
        username TEXT NOT NULL DEFAULT ''
      )
    `);
  } catch {
    console.error("schema init failed");
  }
}

init_db();

module.exports = { query, withTransaction };
