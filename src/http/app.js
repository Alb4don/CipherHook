"use strict";

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const rateLimit = require("express-rate-limit");
const { AppError, Errors } = require("../errors");

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types 'none'"
].join("; ");

const REQUEST_ID = /^[A-Za-z0-9-]{8,64}$/;

function limiter(windowMs, max, code) {
  return rateLimit({
    windowMs,
    limit: max,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    handler: (req, res, next, options) => {
      const retry = Math.ceil(options.windowMs / 1000);
      res.setHeader("Retry-After", String(retry));
      res.status(429).json({ success: false, error: "rate limited", code, retry_after: retry });
    }
  });
}

const DEFAULT_LIMITS = Object.freeze({ global: 180, send: 30, verify: 20 });

function createApp({ config, service, store, keyring, logger }) {
  const limits = { ...DEFAULT_LIMITS, ...(config.rateLimits || {}) };
  const app = express();
  app.disable("x-powered-by");
  app.set("etag", false);
  app.set("trust proxy", config.trustProxy);
  app.set("json escape", true);

  app.use((req, res, next) => {
    const incoming = req.get("x-request-id");
    req.id = incoming && REQUEST_ID.test(incoming) ? incoming : crypto.randomUUID();
    res.setHeader("X-Request-Id", req.id);
    const start = process.hrtime.bigint();
    res.on("finish", () => {
      const ms = Number(process.hrtime.bigint() - start) / 1e6;
      const rp = req.route?.path;
      const route = rp ? (Array.isArray(rp) ? rp.join("|") : String(rp)) : res.statusCode === 404 ? "unmatched" : "static";
      logger[res.statusCode >= 500 ? "warn" : "info"]("request", { rid: req.id, method: req.method, route, status: res.statusCode, ms: Math.round(ms * 10) / 10 });
    });
    next();
  });

  app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", CSP);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("Origin-Agent-Cluster", "?1");
    res.setHeader("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()");
    if (req.secure) res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
    next();
  });

  const allowed = new Set(config.allowedOrigins);
  app.use((req, res, next) => {
    const origin = req.get("origin");
    let originHost = null;
    if (origin && origin !== "null") {
      try {
        originHost = new URL(origin).host;
      } catch {}
    }
    const sameOrigin = Boolean(originHost) && originHost === req.get("host");
    const crossAllowed = Boolean(origin) && !sameOrigin && allowed.has(origin);
    if (crossAllowed) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      if (req.method === "OPTIONS") {
        res.setHeader("Access-Control-Allow-Methods", "GET, POST");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Request-Id");
        res.setHeader("Access-Control-Max-Age", "600");
        return res.status(204).end();
      }
    }
    if (req.method === "POST") {
      const site = req.get("sec-fetch-site");
      const foreign = (origin && !sameOrigin && !crossAllowed) || (!origin && site === "cross-site");
      if (foreign) return res.status(403).json({ success: false, error: "forbidden origin", code: "forbidden_origin" });
      if (!req.is("application/json")) return res.status(415).json({ success: false, error: "unsupported media type", code: "unsupported_media_type" });
    } else if (req.method !== "GET" && req.method !== "HEAD" && req.method !== "OPTIONS") {
      return res.status(405).json({ success: false, error: "method not allowed", code: "method_not_allowed" });
    }
    next();
  });

  app.use(express.json({ limit: "64kb", strict: true, type: "application/json" }));
  app.use(limiter(60 * 1000, limits.global, "rate_limited"));

  const wrap = (fn) => async (req, res, next) => {
    try {
      res.setHeader("Cache-Control", "no-store");
      const body = req.method === "POST" ? req.body : undefined;
      if (req.method === "POST" && (body === null || typeof body !== "object" || Array.isArray(body))) throw Errors.invalidBody();
      const out = await fn(req, body || {});
      res.status(200).json({ success: true, ...out });
    } catch (err) {
      next(err);
    }
  };

  const withWebhook = (fn) => wrap(async (req, body) => fn(await service.resolveWebhook(body.webhook_url), body, req));

  const api = express.Router();
  const sendLimiter = limiter(60 * 1000, limits.send, "send_rate_limited");
  const verifyLimiter = limiter(10 * 60 * 1000, limits.verify, "verify_rate_limited");

  api.get("/health", (req, res) => res.status(200).json({ status: "ok" }));
  api.get("/ready", async (req, res) => {
    try {
      await store.ping();
      res.status(200).json({ status: "ready" });
    } catch {
      res.status(503).json({ status: "unavailable" });
    }
  });

  api.get("/public_key", (req, res) => {
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.setHeader("X-Key-Id", keyring.kid);
    if (req.baseUrl === "/api/v1") return res.json({ kid: keyring.kid, alg: "RSA-OAEP-256", spki: keyring.publicKeySpkiB64 });
    res.type("text/plain").send(keyring.publicKeySpkiB64);
  });

  api.post("/verify", verifyLimiter, withWebhook(async (wh) => {
    const info = await service.verify(wh);
    return { valid: true, name: info.name };
  }));

  api.post("/send", sendLimiter, withWebhook(async (wh, body) => service.send(wh, body.raw_message ?? body.message, body.nonce)));

  api.post("/retrieve", withWebhook(async (wh, body) => {
    const parseInt10 = (v) => (v === undefined || v === null ? undefined : typeof v === "number" ? v : /^\d{1,6}$/.test(String(v)) ? Number(v) : NaN);
    const index = parseInt10(body.note_index);
    const limit = parseInt10(body.limit);
    if (Number.isNaN(index)) throw Errors.invalidIndex();
    if (Number.isNaN(limit)) throw Errors.invalidBody();
    const cursor = body.cursor === undefined || body.cursor === null || body.cursor === "" ? undefined : body.cursor;
    return service.list(wh, { cursor, index: cursor ? undefined : index, limit });
  }));

  api.post("/delete", withWebhook(async (wh, body) => service.remove(wh, body.note_id)));
  api.post("/count", withWebhook(async (wh) => ({ notes_count: await service.count(wh) })));
  api.post("/settings", withWebhook(async (wh) => service.getSettings(wh)));
  api.post("/update_settings", withWebhook(async (wh, body) => service.updateSettings(wh, body)));

  app.use("/api/v1", api);
  app.use("/", api);

  app.use("/api", (req, res) => res.status(404).json({ success: false, error: "not found", code: "not_found" }));

  const publicDir = config.publicDir;
  const sendPage = (res, file, status) => {
    res.status(status).sendFile(path.join(publicDir, file), (err) => {
      if (err && !res.headersSent) res.status(404).json({ success: false, error: "not found", code: "not_found" });
    });
  };
  app.get(["/", "/index.html"], (req, res) => {
    res.setHeader("Cache-Control", "no-cache");
    sendPage(res, "index.html", 200);
  });
  app.use(express.static(publicDir, { index: false, maxAge: "1h", etag: true, dotfiles: "deny", redirect: false }));

  app.use((req, res) => {
    if (req.method === "GET" && req.accepts(["html", "json"]) === "html") {
      return sendPage(res, "404.html", 404);
    }
    res.status(404).json({ success: false, error: "not found", code: "not_found" });
  });

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    res.setHeader("Cache-Control", "no-store");
    if (err instanceof AppError) {
      if (err.extra?.retry_after) res.setHeader("Retry-After", String(err.extra.retry_after));
      return res.status(err.status).json({ success: false, error: err.message, code: err.code, ...(err.extra || {}) });
    }
    if (err?.type === "entity.parse.failed" || err?.type === "encoding.unsupported" || err?.type === "charset.unsupported") {
      return res.status(400).json({ success: false, error: "invalid request body", code: "invalid_body" });
    }
    if (err?.type === "entity.too.large") {
      return res.status(413).json({ success: false, error: "payload too large", code: "payload_too_large" });
    }
    logger.error("unhandled error", { rid: req.id, err });
    res.status(500).json({ success: false, error: "internal error", code: "internal", request_id: req.id });
  });

  return app;
}

module.exports = { createApp, CSP, DEFAULT_LIMITS };
