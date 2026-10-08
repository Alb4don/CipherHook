
## Overview

- Browser fetches `/public_key` and imports the SPKI key.
- User pastes a Discord webhook. The client validates the format, optionally probes the endpoint, encrypts the URL with RSA-OAEP, and keeps the plaintext only in localStorage.
- On send the server decrypts the webhook, builds `encKey|iv|tag|ciphertext`, and POSTs it as `payload.bin` to the webhook with `?wait=true`.
- The returned message ID is prepended to the list stored under the webhook hash (transaction + row lock).
- On retrieve the server walks stored IDs five at a time, downloads each attachment from Discord’s CDN only, decrypts, and returns plaintext plus timestamp.
- Delete issues a Discord `DELETE` on the message, then removes the ID from the local list.

- Avatar URL and display name for the webhook bot are optional per webhook settings. Defaults apply when unset.

<img width="938" height="548" alt="frontendhook" src="https://github.com/user-attachments/assets/8bd6e50b-1e8d-4319-a899-f421dad11824" />

## Interface

- Paste a webhook matching `https://discord.com/api/webhooks/<>/<token>`. The client checks the format before accepting it.

- Once connected:

- Type a note (max 5000 characters). Enter sends; Shift+Enter inserts a newline.
- Scroll the message list to load older notes.
- Hover a note for Copy / Delete. Delete removes both the Discord message and the local record.
- Settings changes the webhook’s avatar and username.
- The eye control toggles masked vs full webhook display. Disconnect clears localStorage.

## API

- State-changing routes expect a JSON body containing the RSA-encrypted webhook.

          | Method | Path             | Purpose                       |
          |--------|------------------|-------------------------------|
          | POST   | /send            | Encrypt and post a note       |
          | POST   | /retrieve        | Decrypt a page of notes       |
          | POST   | /delete          | Remove note from Discord + DB |
          | POST   | /count           | Return stored ID count        |
          | POST   | /settings        | Read avatar / username        |
          | POST   | /update_settings | Write avatar / username       |
          | GET    | /public_key      | Return RSA public key (SPKI)  |
          | GET    | /health          | `{ "status": "ok" }`          |
