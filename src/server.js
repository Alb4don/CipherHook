"use strict";

require("dotenv").config({ quiet: true });

const { loadConfig } = require("./config");
const { createLogger } = require("./logger");
const { createKeyring } = require("./crypto");
const { createStore } = require("./store");
const { createDiscordClient } = require("./discord");
const { createNoteService } = require("./service");
const { createApp } = require("./http/app");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function migrateWithRetry(store, logger, attempts = 12) {
  for (let i = 1; ; i++) {
    try {
      await store.migrate();
      return;
    } catch (err) {
      if (i >= attempts) throw err;
      const delay = Math.min(10000, 250 * 2 ** i) + Math.floor(Math.random() * 250);
      logger.warn("database not ready, retrying", { attempt: i, delay_ms: delay, err });
      await sleep(delay);
    }
  }
}

async function start({ env = process.env, discord } = {}) {
  let logger = createLogger("info");
  let config;
  try {
    config = loadConfig(env);
    logger = createLogger(config.logLevel);
  } catch (err) {
    logger.error("configuration error", { reason: err.message });
    process.exit(1);
  }

  let keyring;
  try {
    keyring = createKeyring(config.privateKeyPem, config.publicKeyPem);
  } catch (err) {
    logger.error("key material error", { reason: err.message });
    process.exit(1);
  }
  if (config.postgres.ssl.mode === "require") logger.warn("POSTGRES_SSL without certificate verification; set POSTGRES_SSL=verify or false");
  if (config.trustProxy === false) logger.info("TRUST_PROXY disabled; client IPs taken from socket");

  const store = createStore({ ...config.postgres, logger });
  try {
    await migrateWithRetry(store, logger);
  } catch (err) {
    logger.error("database migration failed", { err });
    process.exit(1);
  }

  const service = createNoteService({ store, discord: discord || createDiscordClient(), keyring, logger });
  const app = createApp({ config, service, store, keyring, logger });

  const server = app.listen(config.port, config.host, () => logger.info("cipherhook listening", { port: config.port, kid: keyring.kid }));
  server.headersTimeout = 15000;
  server.requestTimeout = 30000;
  server.keepAliveTimeout = 65000;
  server.maxHeadersCount = 64;

  let closing = false;
  const shutdown = (signal) => {
    if (closing) return;
    closing = true;
    logger.info("shutting down", { signal });
    const force = setTimeout(() => process.exit(1), 10000);
    force.unref();
    server.close(async () => {
      try { await store.close(); } catch {}
      process.exit(0);
    });
    server.closeIdleConnections?.();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("unhandledRejection", (err) => logger.error("unhandled rejection", { err }));
  process.on("uncaughtException", (err) => {
    logger.error("uncaught exception", { err });
    process.exit(1);
  });

  return { server, app, store };
}

module.exports = { start };
