"use strict";

class LruCache {
  constructor({ maxEntries = 5000, maxBytes = 32 * 1024 * 1024, ttlMs = 10 * 60 * 1000, sizeOf = () => 1, now = Date.now } = {}) {
    this.maxEntries = maxEntries;
    this.maxBytes = maxBytes;
    this.ttlMs = ttlMs;
    this.sizeOf = sizeOf;
    this.now = now;
    this.map = new Map();
    this.bytes = 0;
  }

  get(key) {
    const e = this.map.get(key);
    if (!e) return undefined;
    if (e.exp <= this.now()) {
      this.delete(key);
      return undefined;
    }
    this.map.delete(key);
    this.map.set(key, e);
    return e.value;
  }

  set(key, value, ttlMs = this.ttlMs) {
    const size = this.sizeOf(value);
    if (size > this.maxBytes) return;
    this.delete(key);
    this.map.set(key, { value, size, exp: this.now() + ttlMs });
    this.bytes += size;
    while (this.map.size > this.maxEntries || this.bytes > this.maxBytes) {
      this.delete(this.map.keys().next().value);
    }
  }

  delete(key) {
    const e = this.map.get(key);
    if (!e) return false;
    this.map.delete(key);
    this.bytes -= e.size;
    return true;
  }

  get size() {
    return this.map.size;
  }
}

module.exports = { LruCache };
