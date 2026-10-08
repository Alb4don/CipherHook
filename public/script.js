const textarea = document.getElementById("input_note");
const send_button = document.getElementById("send_button");
const input_webhook = document.getElementById("input_webhook");
const set_webhook_button = document.getElementById("set_webhook_button");
const char_count = document.getElementById("char_count");
const notes_container = document.getElementById("notes_container");
const logout_button = document.getElementById("logout_button");
const login_text = document.getElementById("login_text");
const show_hide_button = document.getElementById("show_hide_button");
const notes_count = document.getElementById("notes_count");
const settings_button = document.getElementById("settings_button");
const settings = document.getElementById("settings");
const cancel_button = document.getElementById("cancel_button");
const save_button = document.getElementById("save_button");
const input_pfp = document.getElementById("input_pfp");
const input_username = document.getElementById("input_username");
const error_settings_message = document.getElementById("error_settings_message");
const error_webhook_message = document.getElementById("error_webhook_message");
const error_message = document.getElementById("error_message");

let webhook_status = "hidden";
let note_index = 0;
let loading = false;
let login = false;
let all_notes_loaded = false;
let settings_panel = false;
let settings_changed = true;
let last_pfp = "";
let last_username = "";

const WEBHOOK_REGEX = /^https:\/\/(?:www\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,100}$/;

function disable_button(btn) {
  if (!btn) return;
  btn.disabled = true;
}

function enable_button(btn) {
  if (!btn) return;
  btn.disabled = false;
}

function escape_html(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const stored = localStorage.getItem("cipherhook_webhook");
if (stored && WEBHOOK_REGEX.test(stored)) {
  login = true;
}

function show_note(note_id, note_timestamp, raw_content, is_new) {
  if (!/^\d{17,20}$/.test(String(note_id))) return;

  const note = document.createElement("div");
  note.className = "note";
  note.setAttribute("note_id", String(note_id));

  const content = document.createElement("div");
  content.className = "note-content";

  const header = document.createElement("div");
  header.className = "note-header";

  const author = document.createElement("span");
  author.className = "note-author";
  author.textContent = "CipherHook";

  const time = document.createElement("span");
  time.className = "note-time";
  time.textContent = String(note_timestamp || "");

  header.appendChild(author);
  header.appendChild(time);

  const body = document.createElement("div");
  body.className = "note-body";
  const parts = String(raw_content).split(/(https?:\/\/[^\s<>"']+)/g);
  parts.forEach((part) => {
    if (/^https?:\/\/[^\s<>"']+$/.test(part)) {
      try {
        const u = new URL(part);
        if (u.protocol === "http:" || u.protocol === "https:") {
          const a = document.createElement("a");
          a.href = u.href;
          a.textContent = part;
          a.target = "_blank";
          a.rel = "noopener noreferrer nofollow";
          body.appendChild(a);
          return;
        }
      } catch {}
    }
    body.appendChild(document.createTextNode(part));
  });

  content.appendChild(header);
  content.appendChild(body);

  const actions = document.createElement("div");
  actions.className = "note-actions";

  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.setAttribute("data-action", "copy");
  copyBtn.textContent = "Copy";

  const delBtn = document.createElement("button");
  delBtn.type = "button";
  delBtn.className = "danger";
  delBtn.setAttribute("data-action", "delete");
  delBtn.setAttribute("data-note-id", String(note_id));
  delBtn.textContent = "Delete";

  actions.appendChild(copyBtn);
  actions.appendChild(delBtn);

  note.appendChild(content);
  note.appendChild(actions);

  if (is_new) notes_container.prepend(note);
  else notes_container.appendChild(note);
}

function no_note() {
  return document.querySelectorAll("[note_id]").length === 0;
}

async function retrieve_notes() {
  if (loading || all_notes_loaded) return;
  loading = true;

  const loader = document.createElement("div");
  loader.id = "loading_notes";
  loader.className = "loading-state";
  loader.textContent = "Loading notes…";
  notes_container.appendChild(loader);

  try {
    const encrypted_webhook = await encrypt_webhook(localStorage.getItem("cipherhook_webhook"));
    const response = await fetch("/retrieve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ webhook_url: encrypted_webhook, note_index })
    });
    const data = await response.json();

    if (data.success && Array.isArray(data.notes) && data.notes.length > 0) {
      data.notes.forEach((n) => show_note(n.note_id, n.timestamp, n.content, false));
      note_index += data.notes.length;
    } else if (data.error === "note not found") {
      if (no_note()) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.textContent = "No notes yet. Send a message to get started.";
        notes_container.innerHTML = "";
        notes_container.appendChild(empty);
      }
      all_notes_loaded = true;
    }
  } catch {
    const fail = document.createElement("div");
    fail.className = "empty-state";
    fail.textContent = "Failed to load notes.";
    notes_container.appendChild(fail);
  } finally {
    const el = document.getElementById("loading_notes");
    if (el) el.remove();
    loading = false;
  }
}

function webhook_login(hidden) {
  const raw = localStorage.getItem("cipherhook_webhook") || "";
  const clean = raw.replace(/^https:\/\//, "");
  login_text.textContent = "";
  if (hidden) {
    const parts = clean.split("/");
    if (parts.length >= 5) {
      login_text.appendChild(document.createTextNode("Connected to "));
      const strong = document.createElement("strong");
      strong.textContent = `…/${parts[3].slice(0, 5)}***/${parts[4].slice(0, 5)}***`;
      login_text.appendChild(strong);
    } else {
      login_text.textContent = "Connected";
    }
  } else {
    login_text.appendChild(document.createTextNode("Connected to "));
    const strong = document.createElement("strong");
    strong.textContent = clean;
    login_text.appendChild(strong);
  }
}

async function count_notes() {
  try {
    const encrypted_webhook = await encrypt_webhook(localStorage.getItem("cipherhook_webhook"));
    const response = await fetch("/count", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ webhook_url: encrypted_webhook })
    });
    const data = await response.json();
    if (data.success) {
      const n = data.notes_count;
      notes_count.textContent = n === 1 ? "1 note" : `${n} notes`;
    }
  } catch {}
}

function bytes_to_b64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

async function get_public_key() {
  if (!localStorage.getItem("cipherhook_pubkey")) {
    const response = await fetch("/public_key");
    if (!response.ok) throw new Error("pubkey fetch failed");
    const b64 = await response.text();
    if (!b64 || b64.length < 64) throw new Error("invalid pubkey");
    localStorage.setItem("cipherhook_pubkey", b64);
  }
  const b64 = localStorage.getItem("cipherhook_pubkey");
  const binary = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return window.crypto.subtle.importKey(
    "spki",
    binary,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}

async function encrypt_webhook(url) {
  if (typeof url !== "string" || !WEBHOOK_REGEX.test(url)) {
    throw new Error("invalid webhook");
  }
  const key = await get_public_key();
  const encoded = new TextEncoder().encode(url);
  const encrypted = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, encoded);
  return bytes_to_b64(new Uint8Array(encrypted));
}

function auto_resize() {
  if (!textarea) return;
  textarea.style.height = "auto";
  textarea.style.height = Math.min(textarea.scrollHeight, 160) + "px";
}

if (textarea) {
  textarea.addEventListener("input", () => {
    if (textarea.value.trim() === "") disable_button(send_button);
    else enable_button(send_button);
    const len = textarea.value.length;
    char_count.textContent = `${len} / 5000`;
    if (len >= 4900) char_count.classList.add("limit");
    else char_count.classList.remove("limit");
    auto_resize();
  });

  textarea.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (!send_button.disabled) send_button.click();
    }
  });
}

if (input_webhook) {
  input_webhook.addEventListener("input", () => {
    if (WEBHOOK_REGEX.test(input_webhook.value.trim())) enable_button(set_webhook_button);
    else disable_button(set_webhook_button);
  });
}

if (set_webhook_button) {
  set_webhook_button.addEventListener("click", async () => {
    disable_button(set_webhook_button);
    if (error_webhook_message) error_webhook_message.classList.remove("visible");
    const webhook = input_webhook.value.trim();
    if (!WEBHOOK_REGEX.test(webhook)) {
      enable_button(set_webhook_button);
      if (error_webhook_message) error_webhook_message.classList.add("visible");
      return;
    }
    try {
      const response = await fetch(`https://api.allorigins.win/get?url=${encodeURIComponent(webhook)}`);
      const data = await response.json();
      if (data.status?.http_code !== 200) throw new Error("invalid");
      localStorage.setItem("cipherhook_webhook", webhook);
      input_webhook.value = "";
      document.getElementById("webhook_setup").classList.add("hidden");
      document.getElementById("content").classList.remove("hidden");
      location.reload();
    } catch {
      enable_button(set_webhook_button);
      if (error_webhook_message) error_webhook_message.classList.add("visible");
    }
  });
}

if (send_button) {
  send_button.addEventListener("click", async () => {
    disable_button(send_button);
    if (error_message) error_message.classList.remove("visible");
    const raw = textarea.value;
    try {
      const encrypted = await encrypt_webhook(localStorage.getItem("cipherhook_webhook"));
      const response = await fetch("/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ webhook_url: encrypted, raw_message: raw })
      });
      if (!response.ok) throw new Error("fail");
      const data = await response.json();
      textarea.value = "";
      char_count.textContent = "0 / 5000";
      char_count.classList.remove("limit");
      auto_resize();
      if (no_note()) notes_container.innerHTML = "";
      show_note(data.note_id, "Just now", raw, true);
      note_index += 1;
      count_notes();
    } catch {
      enable_button(send_button);
      if (error_message) error_message.classList.add("visible");
    }
  });
}

if (logout_button) {
  logout_button.addEventListener("click", () => {
    localStorage.removeItem("cipherhook_webhook");
    location.reload();
  });
}

if (show_hide_button) {
  show_hide_button.addEventListener("click", () => {
    if (webhook_status === "hidden") {
      webhook_login(false);
      webhook_status = "revealed";
    } else {
      webhook_login(true);
      webhook_status = "hidden";
    }
  });
}

if (notes_container) {
  notes_container.addEventListener("click", async (e) => {
    const del = e.target.closest("[data-action='delete']");
    const copy = e.target.closest("[data-action='copy']");
    if (del) {
      const id = del.getAttribute("data-note-id");
      if (!id || !/^\d{17,20}$/.test(id)) return;
      try {
        const encrypted = await encrypt_webhook(localStorage.getItem("cipherhook_webhook"));
        await fetch("/delete", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ webhook_url: encrypted, note_id: id })
        });
        const card = document.querySelector(`[note_id="${CSS.escape(id)}"]`);
        if (card) card.remove();
        const m = notes_count.textContent.match(/(\d+)/);
        if (m) {
          const n = Math.max(0, parseInt(m[1], 10) - 1);
          notes_count.textContent = n === 1 ? "1 note" : `${n} notes`;
        }
        if (no_note()) {
          const empty = document.createElement("div");
          empty.className = "empty-state";
          empty.textContent = "No notes yet. Send a message to get started.";
          notes_container.innerHTML = "";
          notes_container.appendChild(empty);
        }
      } catch {}
    } else if (copy) {
      const card = copy.closest("[note_id]");
      const text = card?.querySelector(".note-body")?.textContent;
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        copy.textContent = "Copied";
        setTimeout(() => { copy.textContent = "Copy"; }, 800);
      } catch {}
    }
  });
}

if (settings_button) {
  settings_button.addEventListener("click", async () => {
    if (!settings_panel) {
      if (error_settings_message) error_settings_message.classList.remove("visible");
      settings.classList.remove("hidden");
      settings_panel = true;
      if (settings_changed) {
        try {
          const encrypted = await encrypt_webhook(localStorage.getItem("cipherhook_webhook"));
          const response = await fetch("/settings", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ webhook_url: encrypted })
          });
          const data = await response.json();
          if (data.success) {
            input_pfp.value = data.pfp_link || "";
            input_username.value = data.username || "";
            last_pfp = data.pfp_link || "";
            last_username = data.username || "";
            settings_changed = false;
          }
        } catch {}
      } else {
        input_pfp.value = last_pfp;
        input_username.value = last_username;
      }
    } else {
      settings.classList.add("hidden");
      settings_panel = false;
    }
  });
}

if (save_button) {
  save_button.addEventListener("click", async () => {
    if (error_settings_message) error_settings_message.classList.remove("visible");
    try {
      const encrypted = await encrypt_webhook(localStorage.getItem("cipherhook_webhook"));
      const response = await fetch("/update_settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          webhook_url: encrypted,
          pfp_link: input_pfp.value.trim(),
          username: input_username.value.trim()
        })
      });
      if (response.ok) {
        settings_panel = false;
        settings_changed = true;
        settings.classList.add("hidden");
      } else {
        if (error_settings_message) error_settings_message.classList.add("visible");
      }
    } catch {
      if (error_settings_message) error_settings_message.classList.add("visible");
    }
  });
}

if (cancel_button) {
  cancel_button.addEventListener("click", () => {
    settings.classList.add("hidden");
    settings_panel = false;
  });
}

if (login) {
  document.getElementById("webhook_setup").classList.add("hidden");
  document.getElementById("content").classList.remove("hidden");
  if (settings_button) settings_button.classList.remove("hidden");
  if (logout_button) logout_button.classList.remove("hidden");
  webhook_login(true);
  retrieve_notes();
  window.addEventListener("scroll", () => {
    if (window.innerHeight + window.scrollY >= document.body.offsetHeight - 200 && !all_notes_loaded) {
      retrieve_notes();
    }
  }, true);
  const notesArea = document.querySelector(".notes-area");
  if (notesArea) {
    notesArea.addEventListener("scroll", () => {
      if (notesArea.scrollTop + notesArea.clientHeight >= notesArea.scrollHeight - 100 && !all_notes_loaded) {
        retrieve_notes();
      }
    });
  }
  count_notes();
}
