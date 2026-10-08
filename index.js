const express = require("express");
const axios = require("axios");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");
const FormData = require("form-data");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const { query, withTransaction } = require("./db");

const app = express();
const PORT = parseInt(process.env.PORT, 10);
const DEFAULT_USERNAME = "CipherHook";
const DEFAULT_PFP = "https://i.imgur.com/1BxJoqZ.jpeg";
const MAX_MESSAGE_LENGTH = 5000;
const MAX_USERNAME_LENGTH = 80;
const MAX_PFP_LENGTH = 512;
const MAX_NOTE_IDS = 5000;

const WEBHOOK_REGEX = /^https:\/\/(?:www\.)?discord(?:app)?\.com\/api\/webhooks\/(\d{17,20})\/([A-Za-z0-9_-]{60,100})$/;
const DISCORD_CDN_HOSTS = new Set([
  "cdn.discordapp.com",
  "media.discordapp.net",
  "cdn.discord.com"
]);

const limiter = rateLimit({
  windowMs: 20 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "rate limited" }
});

const sendLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "send rate limited" }
});

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "12kb" }));
app.use(cors({
  origin: true,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"],
  maxAge: 600
}));
app.use(limiter);
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://api.allorigins.win; script-src 'self'; base-uri 'self'; form-action 'self'"
  );
  next();
});
app.use(express.static(path.join(__dirname, "public"), {
  maxAge: "1h",
  etag: true,
  index: false
}));

let public_key;
let private_key;

function loadKeys() {
  const keyPathEnv = process.env.PUBLIC_KEY_PATH;
  if (!keyPathEnv || !process.env.PRIVATE_KEY_B64) {
    console.error("missing required environment");
    process.exit(1);
  }
  const resolved = path.resolve(__dirname, keyPathEnv);
  if (!resolved.startsWith(path.resolve(__dirname) + path.sep) && resolved !== path.resolve(__dirname)) {
    console.error("PUBLIC_KEY_PATH escapes application root");
    process.exit(1);
  }
  try {
    public_key = fs.readFileSync(resolved, "utf8");
    private_key = Buffer.from(process.env.PRIVATE_KEY_B64, "base64").toString("ascii");
  } catch {
    console.error("key load failed");
    process.exit(1);
  }
  if (!public_key.includes("BEGIN PUBLIC KEY") || !private_key.includes("BEGIN")) {
    console.error("invalid key material");
    process.exit(1);
  }
}

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  console.error("invalid PORT");
  process.exit(1);
}

loadKeys();

function hash_webhook(url) {
  return crypto.createHash("sha256").update(url).digest("hex");
}

function generate_aes_key() {
  return crypto.randomBytes(32);
}

function encrypt_message_aes(message, aes_key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", aes_key, iv);
  let encrypted = cipher.update(message, "utf8", "base64");
  encrypted += cipher.final("base64");
  const tag = cipher.getAuthTag().toString("base64");
  return { encrypted_data: encrypted, iv: iv.toString("base64"), tag };
}

function encrypt_aes_key(aes_key) {
  return crypto.publicEncrypt({
    key: public_key,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256"
  }, aes_key).toString("base64");
}

function decrypt_aes_key(encrypted) {
  return crypto.privateDecrypt({
    key: private_key,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256"
  }, Buffer.from(encrypted, "base64"));
}

function decrypt_message_aes(encrypted, aes_key, iv, tag) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", aes_key, Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  let decrypted = decipher.update(encrypted, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function decrypt_webhook(encrypted) {
  if (typeof encrypted !== "string" || encrypted.length < 64 || encrypted.length > 1200) return null;
  try {
    const plain = crypto.privateDecrypt({
      key: private_key,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    }, Buffer.from(encrypted, "base64")).toString("utf8");
    if (!WEBHOOK_REGEX.test(plain)) return null;
    return plain;
  } catch {
    return null;
  }
}

function is_valid_url(str) {
  if (typeof str !== "string" || str.length === 0 || str.length > MAX_PFP_LENGTH) return false;
  try {
    const u = new URL(str);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

function is_discord_cdn_url(str) {
  if (typeof str !== "string" || !str.startsWith("https://")) return false;
  try {
    const u = new URL(str);
    return DISCORD_CDN_HOSTS.has(u.hostname.toLowerCase());
  } catch {
    return false;
  }
}

function sanitize_username(name) {
  if (typeof name !== "string") return DEFAULT_USERNAME;
  const cleaned = name.replace(/[\u0000-\u001F\u007F]/g, "").trim().slice(0, MAX_USERNAME_LENGTH);
  return cleaned.length > 0 ? cleaned : DEFAULT_USERNAME;
}

function sanitize_message(msg) {
  if (typeof msg !== "string") return null;
  const cleaned = msg.replace(/\u0000/g, "");
  if (cleaned.length === 0 || cleaned.length > MAX_MESSAGE_LENGTH) return null;
  return cleaned;
}

function parse_note_ids(raw) {
  try {
    const parsed = JSON.parse(raw || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((id) => typeof id === "string" && /^\d{17,20}$/.test(id));
  } catch {
    return [];
  }
}

async function store_message_id(webhook_url, message_id) {
  const hashed = hash_webhook(webhook_url);
  const mid = String(message_id);
  if (!/^\d{17,20}$/.test(mid)) return;

  await withTransaction(async (client) => {
    const { rows } = await client.query(
      "SELECT note_ids FROM notes WHERE webhook_hash = $1 FOR UPDATE",
      [hashed]
    );
    let note_ids = rows.length ? parse_note_ids(rows[0].note_ids) : [];
    note_ids.unshift(mid);
    if (note_ids.length > MAX_NOTE_IDS) note_ids = note_ids.slice(0, MAX_NOTE_IDS);
    const serialized = JSON.stringify(note_ids);
    if (rows.length) {
      await client.query("UPDATE notes SET note_ids = $1 WHERE webhook_hash = $2", [serialized, hashed]);
    } else {
      await client.query(
        "INSERT INTO notes (webhook_hash, note_ids, pfp_link, username) VALUES ($1, $2, $3, $4)",
        [hashed, serialized, DEFAULT_PFP, DEFAULT_USERNAME]
      );
    }
  });
}

async function delete_note_record(webhook_url, note_id) {
  const hashed = hash_webhook(webhook_url);
  const mid = String(note_id);

  await withTransaction(async (client) => {
    const { rows } = await client.query(
      "SELECT note_ids FROM notes WHERE webhook_hash = $1 FOR UPDATE",
      [hashed]
    );
    if (!rows.length) return;
    let note_ids = parse_note_ids(rows[0].note_ids);
    note_ids = note_ids.filter((id) => id !== mid);
    if (note_ids.length === 0) {
      await client.query("DELETE FROM notes WHERE webhook_hash = $1", [hashed]);
    } else {
      await client.query("UPDATE notes SET note_ids = $1 WHERE webhook_hash = $2", [
        JSON.stringify(note_ids),
        hashed
      ]);
    }
  });
}

async function get_webhook_pfp(webhook_url) {
  const hashed = hash_webhook(webhook_url);
  const { rows } = await query("SELECT pfp_link FROM notes WHERE webhook_hash = $1", [hashed]);
  if (rows[0]?.pfp_link && is_valid_url(rows[0].pfp_link)) return rows[0].pfp_link;
  return DEFAULT_PFP;
}

async function get_webhook_username(webhook_url) {
  const hashed = hash_webhook(webhook_url);
  const { rows } = await query("SELECT username FROM notes WHERE webhook_hash = $1", [hashed]);
  if (rows[0]?.username) return sanitize_username(rows[0].username);
  return DEFAULT_USERNAME;
}

const axiosDiscord = {
  timeout: 10000,
  maxRedirects: 0,
  maxContentLength: 1024 * 1024,
  maxBodyLength: 1024 * 1024,
  validateStatus: (s) => s >= 200 && s < 300
};

app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/send", sendLimiter, async (req, res) => {
  try {
    const webhook_url = decrypt_webhook(req.body?.webhook_url);
    const raw_message = sanitize_message(req.body?.raw_message);

    if (!webhook_url) return res.status(400).json({ error: "invalid webhook" });
    if (!raw_message) return res.status(400).json({ error: "invalid message" });

    const aes_key = generate_aes_key();
    const { encrypted_data, iv, tag } = encrypt_message_aes(raw_message, aes_key);
    const encrypted_aes_key = encrypt_aes_key(aes_key);
    const payload = Buffer.from(`${encrypted_aes_key}|${iv}|${tag}|${encrypted_data}`, "utf8");

    const pfp_link = await get_webhook_pfp(webhook_url);
    const username = await get_webhook_username(webhook_url);

    const form = new FormData();
    form.append("file", payload, { filename: "payload.bin", contentType: "application/octet-stream" });
    form.append("payload_json", JSON.stringify({ username, avatar_url: pfp_link }));

    const response = await axios.post(webhook_url + "?wait=true", form, {
      ...axiosDiscord,
      headers: form.getHeaders(),
      timeout: 12000
    });

    const message_id = response.data?.id;
    if (!message_id || !/^\d{17,20}$/.test(String(message_id))) {
      return res.status(502).json({ error: "send failed" });
    }

    await store_message_id(webhook_url, message_id);
    res.json({ success: true, note_id: String(message_id) });
  } catch (err) {
    const status = err.response?.status;
    if (status === 429) {
      return res.status(429).json({
        error: "rate limited",
        retry_after: err.response?.data?.retry_after || 5
      });
    }
    if (status === 401 || status === 403 || status === 404) {
      return res.status(400).json({ error: "invalid webhook" });
    }
    console.error("send error");
    res.status(500).json({ error: "send failed" });
  }
});

app.post("/delete", async (req, res) => {
  try {
    const webhook_url = decrypt_webhook(req.body?.webhook_url);
    const note_id = req.body?.note_id;

    if (!webhook_url) return res.status(400).json({ error: "invalid webhook" });
    if (typeof note_id !== "string" || !/^\d{17,20}$/.test(note_id)) {
      return res.status(400).json({ error: "invalid note id" });
    }

    try {
      await axios.delete(`${webhook_url}/messages/${note_id}`, {
        timeout: 8000,
        maxRedirects: 0,
        validateStatus: (s) => s === 204 || s === 404
      });
    } catch {}

    await delete_note_record(webhook_url, note_id);
    res.json({ success: true });
  } catch {
    console.error("delete error");
    res.status(500).json({ error: "delete failed" });
  }
});

app.post("/retrieve", async (req, res) => {
  try {
    const webhook_url = decrypt_webhook(req.body?.webhook_url);
    const start = parseInt(req.body?.note_index, 10);

    if (!webhook_url) return res.status(400).json({ error: "invalid webhook" });
    if (Number.isNaN(start) || start < 0 || start > 100000) {
      return res.status(400).json({ error: "invalid index" });
    }

    const hashed = hash_webhook(webhook_url);
    const { rows } = await query("SELECT note_ids FROM notes WHERE webhook_hash = $1", [hashed]);
    const message_ids = rows.length ? parse_note_ids(rows[0].note_ids) : [];

    if (start >= message_ids.length) {
      return res.status(404).json({ error: "note not found" });
    }

    const end = Math.min(start + 5, message_ids.length);
    const retrieved = [];

    for (let i = start; i < end; i++) {
      const message_id = message_ids[i];
      try {
        const response = await axios.get(`${webhook_url}/messages/${message_id}`, {
          timeout: 8000,
          maxRedirects: 0,
          validateStatus: (s) => s === 200
        });

        if (!response.data?.attachments?.length) continue;
        const file_url = response.data.attachments[0].url;
        if (!is_discord_cdn_url(file_url)) continue;

        const file_res = await axios.get(file_url, {
          responseType: "text",
          timeout: 8000,
          maxRedirects: 0,
          maxContentLength: 256 * 1024
        });

        const parts = String(file_res.data).split("|");
        if (parts.length !== 4) continue;

        const [enc_key, iv, tag, ciphertext] = parts;
        if (!enc_key || !iv || !tag || !ciphertext) continue;
        if (enc_key.length > 1024 || iv.length > 64 || tag.length > 64 || ciphertext.length > 200000) {
          continue;
        }

        let content;
        try {
          const aes_key = decrypt_aes_key(enc_key);
          content = decrypt_message_aes(ciphertext, aes_key, iv, tag);
        } catch {
          continue;
        }

        if (typeof content !== "string" || content.length > MAX_MESSAGE_LENGTH) continue;

        const ts = response.data.timestamp
          ? new Date(response.data.timestamp).toLocaleString("en-US", {
              month: "2-digit",
              day: "2-digit",
              year: "numeric",
              hour: "2-digit",
              minute: "2-digit",
              hour12: true
            })
          : "";

        retrieved.push({
          note_id: String(message_id),
          content,
          timestamp: ts
        });

        await new Promise((r) => setTimeout(r, 120));
      } catch (err) {
        if (err.response?.status === 404) {
          await delete_note_record(webhook_url, message_id);
        }
        if (err.response?.status === 429) {
          return res.status(429).json({
            error: "rate limited",
            retry_after: err.response?.data?.retry_after || 5
          });
        }
      }
    }

    res.json({ success: true, notes: retrieved });
  } catch {
    console.error("retrieve error");
    res.status(500).json({ error: "retrieve failed" });
  }
});

app.post("/count", async (req, res) => {
  try {
    const webhook_url = decrypt_webhook(req.body?.webhook_url);
    if (!webhook_url) return res.status(400).json({ error: "invalid webhook" });
    const hashed = hash_webhook(webhook_url);
    const { rows } = await query("SELECT note_ids FROM notes WHERE webhook_hash = $1", [hashed]);
    const count = rows.length ? parse_note_ids(rows[0].note_ids).length : 0;
    res.json({ success: true, notes_count: count });
  } catch {
    res.status(500).json({ error: "count failed" });
  }
});

app.post("/settings", async (req, res) => {
  try {
    const webhook_url = decrypt_webhook(req.body?.webhook_url);
    if (!webhook_url) return res.status(400).json({ error: "invalid webhook" });
    const pfp_link = await get_webhook_pfp(webhook_url);
    const username = await get_webhook_username(webhook_url);
    res.json({ success: true, pfp_link, username });
  } catch {
    res.status(500).json({ error: "settings failed" });
  }
});

app.post("/update_settings", async (req, res) => {
  try {
    const webhook_url = decrypt_webhook(req.body?.webhook_url);
    if (!webhook_url) return res.status(400).json({ error: "invalid webhook" });

    let pfp_link = req.body?.pfp_link;
    const username = sanitize_username(req.body?.username);

    if (!pfp_link || typeof pfp_link !== "string" || pfp_link.trim() === "") {
      pfp_link = DEFAULT_PFP;
    } else if (!is_valid_url(pfp_link)) {
      return res.status(400).json({ error: "invalid avatar url" });
    } else {
      pfp_link = pfp_link.trim().slice(0, MAX_PFP_LENGTH);
    }

    const hashed = hash_webhook(webhook_url);
    await query(
      `INSERT INTO notes (webhook_hash, note_ids, pfp_link, username)
       VALUES ($1, '[]', $2, $3)
       ON CONFLICT (webhook_hash)
       DO UPDATE SET pfp_link = EXCLUDED.pfp_link, username = EXCLUDED.username`,
      [hashed, pfp_link, username]
    );

    res.json({ success: true });
  } catch {
    console.error("settings update error");
    res.status(500).json({ error: "settings update failed" });
  }
});

app.get("/public_key", (req, res) => {
  const cleaned = public_key
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
  res.setHeader("Content-Type", "text/plain");
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.send(cleaned);
});

app.get("*", (req, res) => {
  res.status(404).sendFile(path.join(__dirname, "public", "404.html"));
});

app.use((req, res) => {
  res.status(404).json({ error: "not found" });
});

app.use((err, req, res, next) => {
  console.error("unhandled error");
  res.status(500).json({ error: "internal error" });
});

app.listen(PORT, () => {
  console.log(`cipherhook listening on ${PORT}`);
});
