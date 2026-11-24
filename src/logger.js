"use strict";

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

const REDACTIONS = [
  [/discord(?:app)?\.com\/api\/(?:v\d+\/)?webhooks\/\d+\/[A-Za-z0-9_-]+/gi, "discord.com/api/webhooks/[redacted]"],
  [/-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g, "[redacted-key]"],
  [/postgres(?:ql)?:\/\/[^\s"']+/gi, "postgres://[redacted]"],
  [/([?&](?:ex|is|hm|token|key|sig)=)[^&\s"']+/gi, "$1[redacted]"]
];

function redact(value) {
  let s = String(value);
  for (const [re, rep] of REDACTIONS) s = s.replace(re, rep);
  return s.length > 500 ? s.slice(0, 500) + "..." : s;
}

function sanitizeFields(fields) {
  const out = {};
  for (const [k, v] of Object.entries(fields || {})) {
    if (v === undefined) continue;
    if (v instanceof Error) {
      out[k] = { name: v.name, code: typeof v.code === "string" ? v.code : undefined, message: redact(v.message) };
    } else if (typeof v === "string") {
      out[k] = redact(v);
    } else if (typeof v === "number" || typeof v === "boolean" || v === null) {
      out[k] = v;
    } else {
      out[k] = redact(JSON.stringify(v));
    }
  }
  return out;
}

function createLogger(level = "info", sink = (line) => process.stdout.write(line + "\n")) {
  const threshold = LEVELS[level] ?? LEVELS.info;
  const emit = (lvl, msg, fields) => {
    if (LEVELS[lvl] < threshold) return;
    try {
      sink(JSON.stringify({ t: new Date().toISOString(), level: lvl, msg: redact(msg), ...sanitizeFields(fields) }));
    } catch {}
  };
  return {
    debug: (m, f) => emit("debug", m, f),
    info: (m, f) => emit("info", m, f),
    warn: (m, f) => emit("warn", m, f),
    error: (m, f) => emit("error", m, f)
  };
}

module.exports = { createLogger, redact };
