"use strict";

class AppError extends Error {
  constructor(status, code, message, extra) {
    super(message);
    this.name = "AppError";
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

const Errors = {
  invalidWebhook: () => new AppError(400, "invalid_webhook", "invalid webhook"),
  invalidMessage: () => new AppError(400, "invalid_message", "invalid message"),
  invalidNoteId: () => new AppError(400, "invalid_note_id", "invalid note id"),
  invalidIndex: () => new AppError(400, "invalid_index", "invalid index"),
  invalidCursor: () => new AppError(400, "invalid_cursor", "invalid cursor"),
  invalidAvatar: () => new AppError(400, "invalid_avatar", "invalid avatar url"),
  invalidUsername: () => new AppError(400, "invalid_username", "invalid display name"),
  invalidBody: () => new AppError(400, "invalid_body", "invalid request body"),
  noteNotFound: () => new AppError(404, "note_not_found", "note not found"),
  limitReached: () => new AppError(409, "note_limit", "note limit reached"),
  rateLimited: (retryAfterMs) => new AppError(429, "rate_limited", "rate limited", { retry_after: Math.max(1, Math.ceil((retryAfterMs || 1000) / 1000)) }),
  upstream: () => new AppError(502, "upstream_error", "discord unavailable")
};

module.exports = { AppError, Errors };
