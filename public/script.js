(() => {
  "use strict";

  const WEBHOOK_REGEX = /^https:\/\/(?:(?:www|canary|ptb)\.)?discord(?:app)?\.com\/api\/(?:v10\/)?webhooks\/(\d{17,20})\/([A-Za-z0-9_-]{60,100})$/;
  const STORAGE_KEY = "cipherhook_webhook";
  const NAME_KEY = "cipherhook_name";
  const MAX_LEN = 5000;
  const PAGE_SIZE = 15;
  const REQUEST_TIMEOUT = 25000;

  const $ = (id) => document.getElementById(id);
  const ui = {
    session: $("session"),
    identity: $("identity"),
    identityName: $("identity_name"),
    identityId: $("identity_id"),
    refresh: $("refresh_button"),
    settingsBtn: $("settings_button"),
    logout: $("logout_button"),
    connectView: $("connect_view"),
    connectForm: $("connect_form"),
    webhookInput: $("input_webhook"),
    revealInput: $("reveal_input"),
    connectError: $("connect_error"),
    remember: $("remember"),
    connectBtn: $("connect_button"),
    appView: $("app_view"),
    composer: $("composer"),
    note: $("input_note"),
    charCount: $("char_count"),
    send: $("send_button"),
    search: $("search"),
    count: $("notes_count"),
    feed: $("feed"),
    feedStatus: $("feed_status"),
    sentinel: $("sentinel"),
    settingsDialog: $("settings_dialog"),
    settingsForm: $("settings_form"),
    username: $("input_username"),
    avatar: $("input_pfp"),
    settingsError: $("settings_error"),
    settingsCancel: $("settings_cancel"),
    settingsSave: $("settings_save"),
    confirmDialog: $("confirm_dialog"),
    confirmTitle: $("confirm_title"),
    confirmPreview: $("confirm_preview"),
    confirmOk: $("confirm_ok"),
    toasts: $("toasts")
  };

  const state = {
    webhook: null,
    webhookId: "",
    name: "",
    author: "CipherHook",
    notes: new Map(),
    cursor: null,
    done: false,
    loading: false,
    generation: 0,
    count: 0,
    revealId: false,
    retryTimer: null,
    retryUntil: 0,
    filter: ""
  };

  class ApiError extends Error {
    constructor(status, code, message, retryAfter) {
      super(message);
      this.status = status;
      this.code = code;
      this.retryAfter = retryAfter;
    }
  }

  const MESSAGES = {
    invalid_webhook: "Discord did not accept this webhook. Check that it still exists and the URL is complete.",
    invalid_message: "Notes must contain text and be at most 5000 characters.",
    invalid_avatar: "The avatar must be an HTTPS URL.",
    invalid_username: "Display names can have up to 80 characters and cannot contain “discord” or “clyde”.",
    note_limit: "This vault reached its note limit. Delete old notes to add new ones.",
    rate_limited: "Discord is rate limiting requests. Try again in a moment.",
    send_rate_limited: "You are sending too fast. Wait a minute and try again.",
    verify_rate_limited: "Too many connection attempts. Wait a few minutes.",
    upstream_error: "Discord is not responding right now. Try again shortly.",
    rejected: "Discord rejected the request. Check the webhook appearance settings.",
    payload_too_large: "This note is too large.",
    timeout: "The request timed out. Check your connection.",
    network: "Network error. Check your connection.",
    insecure: "CipherHook needs a secure (HTTPS) connection to encrypt your webhook."
  };

  const messageFor = (code) => MESSAGES[code] || "Something went wrong. Please try again.";

  const storage = {
    load() {
      for (const area of [sessionStorage, localStorage]) {
        try {
          const url = area.getItem(STORAGE_KEY);
          if (url && WEBHOOK_REGEX.test(url)) return { url, name: area.getItem(NAME_KEY) || "" };
        } catch {}
      }
      return null;
    },
    save(url, name, remember) {
      this.clear();
      try {
        const area = remember ? localStorage : sessionStorage;
        area.setItem(STORAGE_KEY, url);
        area.setItem(NAME_KEY, name || "");
      } catch {}
    },
    clear() {
      for (const area of [sessionStorage, localStorage]) {
        try {
          area.removeItem(STORAGE_KEY);
          area.removeItem(NAME_KEY);
          area.removeItem("cipherhook_pubkey");
        } catch {}
      }
    }
  };

  let keyPromise = null;
  let sealCache = { k: "", v: "" };

  function b64FromBuffer(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(bin);
  }

  function loadKey(force) {
    if (keyPromise && !force) return keyPromise;
    keyPromise = (async () => {
      if (!window.isSecureContext || !window.crypto?.subtle) throw new ApiError(0, "insecure", messageFor("insecure"));
      let res;
      try {
        res = await fetch("/api/v1/public_key", { cache: force ? "reload" : "default", credentials: "same-origin" });
      } catch {
        throw new ApiError(0, "network", messageFor("network"));
      }
      if (!res.ok) throw new ApiError(res.status, "upstream_error", messageFor("upstream_error"));
      const data = await res.json();
      if (typeof data?.spki !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(data.spki)) throw new ApiError(0, "key", "Invalid server key.");
      const der = Uint8Array.from(atob(data.spki), (c) => c.charCodeAt(0));
      const key = await crypto.subtle.importKey("spki", der, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
      return { key, kid: String(data.kid || "") };
    })();
    keyPromise.catch(() => { keyPromise = null; });
    return keyPromise;
  }

  async function seal(url, force) {
    const { key, kid } = await loadKey(force);
    const k = `${kid}|${url}`;
    if (!force && sealCache.k === k) return sealCache.v;
    const ct = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, new TextEncoder().encode(url));
    sealCache = { k, v: b64FromBuffer(ct) };
    return sealCache.v;
  }

  async function api(path, payload, { webhook = state.webhook, retried = false } = {}) {
    if (!webhook) throw new ApiError(0, "invalid_webhook", messageFor("invalid_webhook"));
    const body = JSON.stringify({ ...payload, webhook_url: await seal(webhook, retried) });
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT);
    let res;
    try {
      res = await fetch(`/api/v1${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        signal: ctrl.signal,
        credentials: "same-origin",
        cache: "no-store"
      });
    } catch {
      const code = ctrl.signal.aborted ? "timeout" : "network";
      throw new ApiError(0, code, messageFor(code));
    } finally {
      clearTimeout(timer);
    }
    let data = null;
    try {
      data = await res.json();
    } catch {}
    if (res.ok && data && data.success) return data;
    const code = typeof data?.code === "string" ? data.code : `http_${res.status}`;
    if (code === "invalid_webhook" && !retried) return api(path, payload, { webhook, retried: true });
    throw new ApiError(res.status, code, messageFor(code), Number(data?.retry_after) || undefined);
  }

  function svgIcon(name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "ic");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#i-${name}`);
    svg.appendChild(use);
    return svg;
  }

  function h(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else node.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children) if (c !== null && c !== undefined) node.append(c);
    return node;
  }

  function toast(message, kind = "info", ms = 3800) {
    const node = h("div", { class: `toast ${kind}`, text: message });
    ui.toasts.append(node);
    while (ui.toasts.children.length > 3) ui.toasts.firstElementChild.remove();
    setTimeout(() => {
      node.classList.add("leaving");
      setTimeout(() => node.remove(), 220);
    }, ms);
  }

  function setBusy(btn, busy) {
    btn.classList.toggle("loading", busy);
    btn.disabled = busy;
    btn.setAttribute("aria-busy", busy ? "true" : "false");
  }

  const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
  const fullFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "full", timeStyle: "medium" });
  const dayFmt = new Intl.DateTimeFormat(undefined, { weekday: "long", month: "long", day: "numeric", year: "numeric" });

  function parseDate(value) {
    const d = value ? new Date(value) : null;
    return d && !Number.isNaN(d.getTime()) ? d : null;
  }

  function dayKey(d) {
    return d ? `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}` : "unknown";
  }

  function dayLabel(d) {
    if (!d) return "Unknown date";
    const today = new Date();
    const yesterday = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
    if (dayKey(d) === dayKey(today)) return "Today";
    if (dayKey(d) === dayKey(yesterday)) return "Yesterday";
    return dayFmt.format(d);
  }

  function linkify(container, text) {
    const re = /https?:\/\/[^\s<>"'`]+[^\s<>"'`.,;:!?)\]}]/g;
    let last = 0;
    for (const m of text.matchAll(re)) {
      if (m.index > last) container.append(document.createTextNode(text.slice(last, m.index)));
      let url = null;
      try {
        url = new URL(m[0]);
      } catch {}
      if (url && (url.protocol === "https:" || url.protocol === "http:")) {
        container.append(h("a", { href: url.href, target: "_blank", rel: "noopener noreferrer nofollow", text: m[0] }));
      } else {
        container.append(document.createTextNode(m[0]));
      }
      last = m.index + m[0].length;
    }
    if (last < text.length) container.append(document.createTextNode(text.slice(last)));
  }

  function initials(name) {
    const parts = String(name || "C").trim().split(/\s+/).filter(Boolean);
    const s = parts.length > 1 ? parts[0][0] + parts[1][0] : (parts[0] || "C").slice(0, 2);
    return s.toUpperCase();
  }

  function buildNote(n) {
    const time = n.ts ? h("time", { class: "note-time", datetime: n.ts.toISOString(), title: fullFmt.format(n.ts), text: timeFmt.format(n.ts) }) : null;
    const body = h("div", { class: "note-body" });
    linkify(body, n.content);
    const copy = h("button", { type: "button", class: "icon-btn", "data-action": "copy", title: "Copy", "aria-label": "Copy note" }, svgIcon("copy"));
    const del = h("button", { type: "button", class: "icon-btn danger", "data-action": "delete", title: "Delete", "aria-label": "Delete note" }, svgIcon("trash"));
    const node = h("article", { class: "note fresh", "data-id": n.id },
      h("div", { class: "avatar", "aria-hidden": "true", text: initials(state.author) }),
      h("div", { class: "note-main" },
        h("div", { class: "note-head" }, h("span", { class: "note-author", text: state.author }), time),
        body),
      h("div", { class: "note-actions" }, copy, del));
    node.addEventListener("animationend", () => node.classList.remove("fresh"), { once: true });
    n.search = n.content.toLowerCase();
    n.el = node;
    return n;
  }

  function sortedNotes() {
    return [...state.notes.values()].sort((a, b) => (BigInt(b.id) > BigInt(a.id) ? 1 : -1));
  }

  function renderFeed() {
    const frag = document.createDocumentFragment();
    let lastDay = null;
    const list = sortedNotes();
    for (const n of list) {
      const dk = dayKey(n.ts);
      if (dk !== lastDay) {
        frag.append(h("div", { class: "day", role: "separator", text: dayLabel(n.ts) }));
        lastDay = dk;
      }
      frag.append(n.el);
    }
    if (list.length === 0 && state.done) {
      frag.append(h("div", { class: "empty" }, h("strong", { text: "No notes yet" }), "Write your first encrypted note above."));
    }
    ui.feed.replaceChildren(frag);
    applyFilter();
  }

  function applyFilter() {
    const q = state.filter;
    let shown = 0;
    for (const n of state.notes.values()) {
      const match = !q || n.search.includes(q);
      n.el.classList.toggle("hidden-by-filter", !match);
      if (match) shown++;
    }
    for (const sep of ui.feed.querySelectorAll(".day")) {
      let next = sep.nextElementSibling;
      let visible = false;
      while (next && !next.classList.contains("day")) {
        if (next.classList.contains("note") && !next.classList.contains("hidden-by-filter")) visible = true;
        next = next.nextElementSibling;
      }
      sep.classList.toggle("hidden", !visible);
    }
    updateCount(q ? shown : null);
  }

  function updateCount(filtered) {
    const total = `${state.count} ${state.count === 1 ? "note" : "notes"}`;
    ui.count.textContent = filtered === null || filtered === undefined ? total : `${filtered} of ${state.notes.size} loaded`;
  }

  function setStatus(text, action) {
    const children = [];
    if (text) children.push(h("div", { text }));
    if (action) {
      const btn = h("button", { type: "button", class: "btn btn-secondary", text: action.label });
      btn.addEventListener("click", action.run);
      children.push(btn);
    }
    ui.feedStatus.replaceChildren(...children);
  }

  function showSkeleton(on) {
    const existing = ui.feed.querySelectorAll(".skeleton");
    existing.forEach((n) => n.remove());
    ui.feed.setAttribute("aria-busy", on ? "true" : "false");
    if (!on) return;
    for (let i = 0; i < 3; i++) {
      ui.feed.append(h("div", { class: "skeleton", "aria-hidden": "true" },
        h("div", { class: "sk sk-avatar" }),
        h("div", { class: "sk-lines" }, h("div", { class: "sk sk-line short" }), h("div", { class: "sk sk-line long" }))));
    }
  }

  function addNotes(list) {
    for (const raw of list) {
      if (!raw || typeof raw.note_id !== "string" || !/^\d{17,20}$/.test(raw.note_id) || typeof raw.content !== "string") continue;
      if (state.notes.has(raw.note_id)) continue;
      state.notes.set(raw.note_id, buildNote({ id: raw.note_id, content: raw.content, ts: parseDate(raw.timestamp) }));
    }
  }

  function sentinelVisible() {
    const r = ui.sentinel.getBoundingClientRect();
    return r.top < window.innerHeight + 400;
  }

  async function loadMore() {
    if (state.loading || state.done || !state.webhook || Date.now() < state.retryUntil) return;
    const gen = state.generation;
    state.loading = true;
    setStatus("");
    showSkeleton(true);
    try {
      const data = await api("/retrieve", { cursor: state.cursor || undefined, limit: PAGE_SIZE });
      if (gen !== state.generation) return;
      addNotes(data.notes || []);
      state.cursor = data.next_cursor || null;
      state.done = !state.cursor;
      if (data.removed) state.count = Math.max(state.notes.size, state.count - data.removed);
      if (data.unreadable) toast(`${data.unreadable} note${data.unreadable === 1 ? "" : "s"} could not be verified and ${data.unreadable === 1 ? "was" : "were"} hidden.`, "error", 6000);
      showSkeleton(false);
      renderFeed();
      if (data.partial) {
        const wait = Math.max(1, Number(data.retry_after) || 2);
        setStatus(`Discord is rate limiting. Loading more in ${wait}s…`);
        scheduleRetry(wait);
        return;
      }
      setStatus(state.done && state.notes.size > 0 ? "You have reached the first note." : "");
    } catch (err) {
      if (gen !== state.generation) return;
      showSkeleton(false);
      if (err.code === "invalid_webhook") {
        disconnect(messageFor("invalid_webhook"));
        return;
      }
      if (err.code === "rate_limited" && err.retryAfter) {
        setStatus(`Discord is rate limiting. Retrying in ${err.retryAfter}s…`);
        scheduleRetry(err.retryAfter);
        return;
      }
      setStatus(err.message || messageFor(), { label: "Retry", run: () => loadMore() });
    } finally {
      if (gen === state.generation) state.loading = false;
    }
    if (gen === state.generation && !state.done && sentinelVisible()) requestAnimationFrame(() => loadMore());
  }

  function scheduleRetry(seconds) {
    const ms = Math.min(60, Math.max(1, seconds)) * 1000;
    state.retryUntil = Date.now() + ms;
    clearTimeout(state.retryTimer);
    state.retryTimer = setTimeout(() => {
      state.retryUntil = 0;
      loadMore();
    }, ms);
  }

  const observer = "IntersectionObserver" in window
    ? new IntersectionObserver((entries) => { if (entries.some((e) => e.isIntersecting)) loadMore(); }, { rootMargin: "400px 0px" })
    : null;

  async function refreshCount() {
    try {
      const data = await api("/count", {});
      state.count = Number(data.notes_count) || 0;
      applyFilter();
    } catch {}
  }

  async function refreshProfile() {
    try {
      const data = await api("/settings", {});
      if (typeof data.username === "string" && data.username) {
        state.author = data.username;
        return true;
      }
    } catch {}
    return false;
  }

  function maskedId(id) {
    return id.length > 6 ? `…${id.slice(-6)}` : id;
  }

  function renderIdentity() {
    ui.identityName.textContent = state.name || "Webhook";
    ui.identityId.textContent = state.revealId ? state.webhookId : maskedId(state.webhookId);
    ui.identity.title = state.revealId ? "Hide webhook ID" : "Show webhook ID";
  }

  function resetVault() {
    state.generation++;
    clearTimeout(state.retryTimer);
    state.retryTimer = null;
    state.retryUntil = 0;
    state.notes.clear();
    state.cursor = null;
    state.done = false;
    state.loading = false;
    state.count = 0;
    state.filter = "";
    ui.search.value = "";
    ui.feed.replaceChildren();
    setStatus("");
  }

  async function enterApp(url, name) {
    resetVault();
    state.webhook = url;
    state.webhookId = WEBHOOK_REGEX.exec(url)[1];
    state.name = name;
    state.revealId = false;
    renderIdentity();
    ui.connectView.classList.add("hidden");
    ui.appView.classList.remove("hidden");
    ui.session.classList.remove("hidden");
    const gen = state.generation;
    await Promise.all([refreshProfile(), refreshCount()]);
    if (gen !== state.generation) return;
    loadMore();
    if (observer) observer.observe(ui.sentinel);
    ui.note.focus({ preventScroll: true });
  }

  function disconnect(reason) {
    resetVault();
    if (observer) observer.disconnect();
    storage.clear();
    sealCache = { k: "", v: "" };
    state.webhook = null;
    state.webhookId = "";
    state.name = "";
    state.author = "CipherHook";
    ui.session.classList.add("hidden");
    ui.appView.classList.add("hidden");
    ui.connectView.classList.remove("hidden");
    ui.note.value = "";
    updateComposer();
    ui.connectError.textContent = reason || "";
    ui.webhookInput.setAttribute("aria-invalid", reason ? "true" : "false");
    ui.webhookInput.focus();
  }

  function validateWebhookInput() {
    const v = ui.webhookInput.value.trim();
    const ok = WEBHOOK_REGEX.test(v);
    ui.connectBtn.disabled = !ok;
    if (v && !ok) {
      ui.connectError.textContent = "Expected https://discord.com/api/webhooks/<id>/<token>";
      ui.webhookInput.setAttribute("aria-invalid", "true");
    } else {
      ui.connectError.textContent = "";
      ui.webhookInput.setAttribute("aria-invalid", "false");
    }
    return ok;
  }

  ui.webhookInput.addEventListener("input", validateWebhookInput);

  ui.revealInput.addEventListener("click", () => {
    const show = ui.webhookInput.type === "password";
    ui.webhookInput.type = show ? "text" : "password";
    ui.revealInput.setAttribute("aria-pressed", show ? "true" : "false");
    ui.revealInput.setAttribute("aria-label", show ? "Hide webhook URL" : "Show webhook URL");
  });

  ui.connectForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!validateWebhookInput()) return;
    const url = ui.webhookInput.value.trim();
    setBusy(ui.connectBtn, true);
    try {
      const data = await api("/verify", {}, { webhook: url });
      storage.save(url, data.name || "", ui.remember.checked);
      ui.webhookInput.value = "";
      ui.webhookInput.type = "password";
      ui.revealInput.setAttribute("aria-pressed", "false");
      await enterApp(url, data.name || "");
    } catch (err) {
      ui.connectError.textContent = err.message || messageFor();
      ui.webhookInput.setAttribute("aria-invalid", "true");
    } finally {
      setBusy(ui.connectBtn, false);
      ui.connectBtn.disabled = !WEBHOOK_REGEX.test(ui.webhookInput.value.trim());
    }
  });

  function autoResize() {
    ui.note.style.height = "auto";
    ui.note.style.height = `${Math.min(ui.note.scrollHeight, 280)}px`;
  }

  function updateComposer() {
    const len = ui.note.value.length;
    ui.charCount.textContent = `${len} / ${MAX_LEN}`;
    ui.charCount.classList.toggle("warn", len >= MAX_LEN * 0.9 && len < MAX_LEN);
    ui.charCount.classList.toggle("limit", len >= MAX_LEN);
    if (!ui.send.classList.contains("loading")) ui.send.disabled = ui.note.value.trim().length === 0 || len > MAX_LEN;
    autoResize();
  }

  ui.note.addEventListener("input", updateComposer);
  ui.note.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing || e.keyCode === 229) return;
    e.preventDefault();
    if (!ui.send.disabled) ui.composer.requestSubmit();
  });

  function newNonce() {
    const bytes = new Uint8Array(18);
    crypto.getRandomValues(bytes);
    return b64FromBuffer(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  ui.composer.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = ui.note.value;
    if (!text.trim() || text.length > MAX_LEN || ui.send.classList.contains("loading")) return;
    setBusy(ui.send, true);
    const gen = state.generation;
    try {
      const data = await api("/send", { raw_message: text, nonce: newNonce() });
      if (gen !== state.generation) return;
      if (typeof data.author === "string" && data.author) state.author = data.author;
      addNotes([{ note_id: data.note_id, content: typeof data.content === "string" ? data.content : text, timestamp: data.timestamp }]);
      state.count += 1;
      if (ui.note.value === text) ui.note.value = "";
      renderFeed();
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (err) {
      if (err.code === "invalid_webhook") disconnect(err.message);
      else toast(err.retryAfter ? `${err.message} (${err.retryAfter}s)` : err.message, "error");
    } finally {
      setBusy(ui.send, false);
      updateComposer();
    }
  });

  function confirmAction({ title, preview, ok }) {
    return new Promise((resolve) => {
      ui.confirmTitle.textContent = title;
      ui.confirmPreview.textContent = preview || "";
      ui.confirmPreview.classList.toggle("hidden", !preview);
      ui.confirmOk.textContent = ok;
      ui.confirmDialog.returnValue = "";
      ui.confirmDialog.addEventListener("close", () => resolve(ui.confirmDialog.returnValue === "confirm"), { once: true });
      ui.confirmDialog.showModal();
    });
  }

  ui.feed.addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-action]");
    if (!btn) return;
    const card = btn.closest(".note");
    const id = card?.getAttribute("data-id");
    const note = id ? state.notes.get(id) : null;
    if (!note) return;
    if (btn.dataset.action === "copy") {
      try {
        await navigator.clipboard.writeText(note.content);
        toast("Copied to clipboard", "success", 1800);
      } catch {
        toast("Clipboard access was blocked by the browser.", "error");
      }
      return;
    }
    const preview = note.content.length > 240 ? `${note.content.slice(0, 240)}…` : note.content;
    if (!(await confirmAction({ title: "Delete note?", preview, ok: "Delete" }))) return;
    card.classList.add("removing");
    try {
      await api("/delete", { note_id: id });
      state.notes.delete(id);
      state.count = Math.max(0, state.count - 1);
      renderFeed();
      toast("Note deleted", "success", 1800);
    } catch (err) {
      card.classList.remove("removing");
      if (err.code === "invalid_webhook") disconnect(err.message);
      else toast(err.retryAfter ? `${err.message} (${err.retryAfter}s)` : err.message, "error");
    }
  });

  ui.search.addEventListener("input", () => {
    state.filter = ui.search.value.trim().toLowerCase();
    applyFilter();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    if (t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t?.isContentEditable) return;
    if (ui.appView.classList.contains("hidden")) return;
    e.preventDefault();
    ui.search.focus();
  });

  ui.identity.addEventListener("click", () => {
    state.revealId = !state.revealId;
    renderIdentity();
  });

  ui.refresh.addEventListener("click", async () => {
    if (!state.webhook) return;
    const url = state.webhook;
    resetVault();
    state.webhook = url;
    await refreshCount();
    loadMore();
  });

  ui.logout.addEventListener("click", async () => {
    if (await confirmAction({ title: "Disconnect?", preview: "", ok: "Disconnect" })) disconnect("");
  });

  ui.settingsBtn.addEventListener("click", async () => {
    ui.settingsError.textContent = "";
    ui.username.value = "";
    ui.avatar.value = "";
    ui.settingsDialog.showModal();
    try {
      const data = await api("/settings", {});
      ui.username.value = data.username || "";
      ui.avatar.value = data.pfp_link || "";
    } catch (err) {
      ui.settingsError.textContent = err.message;
    }
  });

  ui.settingsCancel.addEventListener("click", () => ui.settingsDialog.close());

  ui.settingsForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    ui.settingsError.textContent = "";
    const username = ui.username.value.trim();
    const avatar = ui.avatar.value.trim();
    if (avatar && !/^https:\/\//i.test(avatar)) {
      ui.settingsError.textContent = messageFor("invalid_avatar");
      return;
    }
    if (/discord|clyde/i.test(username)) {
      ui.settingsError.textContent = messageFor("invalid_username");
      return;
    }
    setBusy(ui.settingsSave, true);
    try {
      const data = await api("/update_settings", { username, pfp_link: avatar });
      state.author = data.username || "CipherHook";
      for (const n of state.notes.values()) buildNote(n);
      renderFeed();
      ui.settingsDialog.close();
      toast("Appearance saved", "success", 1800);
    } catch (err) {
      ui.settingsError.textContent = err.message;
    } finally {
      setBusy(ui.settingsSave, false);
    }
  });

  function setOnline() {
    ui.identity.classList.toggle("offline", !navigator.onLine);
  }
  window.addEventListener("online", setOnline);
  window.addEventListener("offline", setOnline);

  window.addEventListener("storage", (e) => {
    if (e.key === STORAGE_KEY && e.newValue === null && state.webhook) disconnect("");
  });

  try {
    localStorage.removeItem("cipherhook_pubkey");
  } catch {}

  updateComposer();
  setOnline();
  const saved = storage.load();
  if (saved) {
    enterApp(saved.url, saved.name);
  } else {
    ui.connectView.classList.remove("hidden");
    ui.webhookInput.focus();
  }
})();
