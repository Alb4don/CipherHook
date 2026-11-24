"use strict";

const crypto = require("crypto");

const WEBHOOK_REGEX = /^https:\/\/(?:(?:www|canary|ptb)\.)?discord(?:app)?\.com\/api\/(?:v10\/)?webhooks\/(\d{17,20})\/([A-Za-z0-9_-]{60,100})$/;
const SNOWFLAKE_REGEX = /^\d{17,20}$/;
const MAX_SNOWFLAKE = 9223372036854775807n;

function isSnowflake(value) {
  if (typeof value !== "string" || !SNOWFLAKE_REGEX.test(value)) return false;
  return BigInt(value) <= MAX_SNOWFLAKE;
}

function parseWebhook(raw) {
  if (typeof raw !== "string" || raw.length > 256) return null;
  const m = WEBHOOK_REGEX.exec(raw);
  if (!m || !isSnowflake(m[1])) return null;
  const id = m[1];
  const token = m[2];
  const key = crypto.createHash("sha256").update(`cipherhook:webhook:v2:${id}:${token}`).digest("hex");
  const legacyKey = crypto.createHash("sha256").update(raw).digest("hex");
  return Object.freeze({ id, token, key, legacyKey, path: `/webhooks/${id}/${token}` });
}

module.exports = { parseWebhook, isSnowflake, WEBHOOK_REGEX };
