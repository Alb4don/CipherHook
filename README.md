
## Overview

- Browser fetches `/public_key` and imports the SPKI key.
- User pastes a Discord webhook. The client validates the format, optionally probes the endpoint, encrypts the URL with RSA-OAEP, and keeps the plaintext only in localStorage.
- On send the server decrypts the webhook, builds `encKey|iv|tag|ciphertext`, and POSTs it as `payload.bin` to the webhook with `?wait=true`.
- The returned message ID is prepended to the list stored under the webhook hash (transaction + row lock).
- On retrieve the server walks stored IDs five at a time, downloads each attachment from Discord’s CDN only, decrypts, and returns plaintext plus timestamp.
- Delete issues a Discord `DELETE` on the message, then removes the ID from the local list.

- Avatar URL and display name for the webhook bot are optional per webhook settings. Defaults apply when unset.

<img width="938" height="548" alt="frontendhook" src="https://github.com/user-attachments/assets/8bd6e50b-1e8d-4319-a899-f421dad11824" />

# Configuration

| Variable | Default | Notes |
|---|---|---|
| `PRIVATE_KEY_B64` | required | Base64 of an RSA PKCS#8/PKCS#1 PEM, at least 2048 bits. `PRIVATE_KEY_PATH` is an alternative |
| `PUBLIC_KEY_PATH` | optional | If set, must match the private key. The public key is otherwise derived |
| `POSTGRES_URL` | required | |
| `POSTGRES_SSL` | `require` | `false`, `require` (encrypted, unverified, logs a warning), `verify` |
| `PORT` | `3000` | Port inside the container |
| `HOST_PORT` / `BIND_ADDRESS` | `3000` / `127.0.0.1` | Docker Compose port publishing |
| `TRUST_PROXY` | `false` | Hop count (`1`), `true`, or a list of subnets |
| `ALLOWED_ORIGINS` | empty | Comma separated extra origins allowed to call the API cross-origin |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

## Interface

- Paste a webhook matching `https://discord.com/api/webhooks/<>/<token>`. The client checks the format before accepting it.

- Once connected:

- Type a note (max 5000 characters). Enter sends; Shift+Enter inserts a newline.
- Scroll the message list to load older notes.
- Hover a note for Copy / Delete. Delete removes both the Discord message and the local record.
- Settings changes the webhook’s avatar and username.
- The eye control toggles masked vs full webhook display. Disconnect clears localStorage.

## API

- All state-changing routes are `POST` with `Content-Type: application/json`. Each takes `webhook_url`: the webhook URL encrypted with RSA-OAEP-SHA256 under the public key, base64-encoded. Routes are served under `/api/v1` and, for compatibility with 1.x clients, at the root.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/public_key` | | `/api/v1`: `{kid, alg, spki}`; root: base64 SPKI text. Header `X-Key-Id` |
| POST | `/verify` | | `{valid, name}`, the webhook checked live against Discord |
| POST | `/send` | `raw_message`, optional `nonce` (16–64 url-safe chars, makes retries idempotent) | `{note_id, timestamp, content, author}` |
| POST | `/retrieve` | `cursor` (note ID) or legacy `note_index`, optional `limit` (1–25, default 10) | `{notes[], next_cursor, consumed, removed, unreadable, partial, retry_after?}` |
| POST | `/delete` | `note_id` | `{deleted}` |
| POST | `/count` | | `{notes_count}` |
| POST | `/settings` | | `{username, pfp_link}` |
| POST | `/update_settings` | `username`, `pfp_link` (HTTPS) | `{username, pfp_link}` |
| GET | `/health`, `/ready` | | Liveness; readiness checks the database |

- Errors have the shape `{success: false, error, code}`, plus `retry_after` and a `Retry-After` header on 429. Timestamps are ISO 8601, and the browser formats them in the user's timezone.
