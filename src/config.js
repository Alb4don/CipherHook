"use strict";

const path = require("path");
const fs = require("fs");

class ConfigError extends Error {}

function parsePort(value, fallback) {
  const raw = value === undefined || value === "" ? String(fallback) : String(value);
  if (!/^\d{1,5}$/.test(raw)) throw new ConfigError("invalid PORT");
  const port = Number(raw);
  if (port < 1 || port > 65535) throw new ConfigError("invalid PORT");
  return port;
}

function parseTrustProxy(value) {
  if (value === undefined || value === "" || value === "false" || value === "0") return false;
  if (/^\d{1,2}$/.test(value)) return Number(value);
  if (value === "true") return 1;
  if (/^[\w.:/,\s-]+$/.test(value)) return value.split(",").map((s) => s.trim()).filter(Boolean);
  throw new ConfigError("invalid TRUST_PROXY");
}

function parseOrigins(value) {
  if (!value) return [];
  return value.split(",").map((s) => s.trim()).filter(Boolean).map((o) => {
    let u;
    try {
      u = new URL(o);
    } catch {
      throw new ConfigError("invalid ALLOWED_ORIGINS");
    }
    if (u.protocol !== "https:" && u.protocol !== "http:") throw new ConfigError("invalid ALLOWED_ORIGINS");
    return u.origin;
  });
}

function parseSsl(value) {
  const v = (value || "").toLowerCase();
  if (v === "false" || v === "off" || v === "disable") return { mode: "off" };
  if (v === "verify" || v === "verify-full") return { mode: "verify" };
  return { mode: "require" };
}

function readPrivateKey(env, rootDir) {
  if (env.PRIVATE_KEY_B64) {
    const decoded = Buffer.from(env.PRIVATE_KEY_B64.trim(), "base64").toString("utf8");
    if (!decoded.includes("BEGIN")) throw new ConfigError("invalid PRIVATE_KEY_B64");
    return decoded;
  }
  if (env.PRIVATE_KEY_PATH) return fs.readFileSync(resolveInside(rootDir, env.PRIVATE_KEY_PATH, "PRIVATE_KEY_PATH"), "utf8");
  throw new ConfigError("missing PRIVATE_KEY_B64");
}

function resolveInside(rootDir, p, name) {
  const root = path.resolve(rootDir);
  const resolved = path.resolve(root, p);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) throw new ConfigError(`${name} escapes application root`);
  return resolved;
}

function loadConfig(env = process.env, rootDir = path.join(__dirname, "..")) {
  if (!env.POSTGRES_URL) throw new ConfigError("missing POSTGRES_URL");
  const privateKeyPem = readPrivateKey(env, rootDir);
  let publicKeyPem = null;
  if (env.PUBLIC_KEY_PATH) {
    const p = resolveInside(rootDir, env.PUBLIC_KEY_PATH, "PUBLIC_KEY_PATH");
    if (fs.existsSync(p)) publicKeyPem = fs.readFileSync(p, "utf8");
  }
  const logLevel = (env.LOG_LEVEL || "info").toLowerCase();
  if (!["debug", "info", "warn", "error"].includes(logLevel)) throw new ConfigError("invalid LOG_LEVEL");
  return Object.freeze({
    port: parsePort(env.PORT, 3000),
    host: env.HOST || "0.0.0.0",
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
    allowedOrigins: parseOrigins(env.ALLOWED_ORIGINS),
    logLevel,
    postgres: Object.freeze({ url: env.POSTGRES_URL, ssl: parseSsl(env.POSTGRES_SSL), poolMax: 12 }),
    privateKeyPem,
    publicKeyPem,
    publicDir: path.join(rootDir, "public")
  });
}

module.exports = { loadConfig, ConfigError, parseTrustProxy, parsePort };
