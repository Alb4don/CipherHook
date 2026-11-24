"use strict";

const crypto = require("crypto");

const MAGIC_V2 = Buffer.from("CH2\u0000", "latin1");
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const HEADER_LEN = MAGIC_V2.length + SALT_LEN + IV_LEN + TAG_LEN;
const MAX_PAYLOAD_BYTES = 64 * 1024;

class CryptoError extends Error {}

function createKeyring(privateKeyPem, publicKeyPem) {
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(privateKeyPem);
  } catch {
    throw new CryptoError("invalid private key");
  }
  if (privateKey.asymmetricKeyType !== "rsa") throw new CryptoError("private key must be RSA");
  const bits = privateKey.asymmetricKeyDetails?.modulusLength || 0;
  if (bits < 2048) throw new CryptoError("RSA key must be at least 2048 bits");
  const derivedPublic = crypto.createPublicKey(privateKey);
  const spki = derivedPublic.export({ type: "spki", format: "der" });
  if (publicKeyPem) {
    let given;
    try {
      given = crypto.createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
    } catch {
      throw new CryptoError("invalid public key");
    }
    if (!given.equals(spki)) throw new CryptoError("public key does not match private key");
  }
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
  const master = Buffer.from(crypto.hkdfSync("sha256", pkcs8, Buffer.from("cipherhook/master/v2"), Buffer.from("note-encryption"), 32));
  const maxCiphertext = Math.ceil(bits / 8);
  const kid = crypto.createHash("sha256").update(spki).digest("hex").slice(0, 16);
  const rsaOpts = { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" };

  function rsaDecrypt(b64) {
    if (typeof b64 !== "string" || b64.length < 64 || b64.length > 1400 || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) return null;
    const buf = Buffer.from(b64, "base64");
    if (buf.length !== maxCiphertext) return null;
    try {
      return crypto.privateDecrypt(rsaOpts, buf);
    } catch {
      return null;
    }
  }

  function noteKey(salt, webhookKey) {
    return Buffer.from(crypto.hkdfSync("sha256", master, salt, Buffer.from(`note:v2:${webhookKey}`), 32));
  }

  function aad(webhookKey) {
    return Buffer.from(`cipherhook:v2:${webhookKey}`);
  }

  function encryptNote(plaintext, webhookKey) {
    const salt = crypto.randomBytes(SALT_LEN);
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv("aes-256-gcm", noteKey(salt, webhookKey), iv, { authTagLength: TAG_LEN });
    cipher.setAAD(aad(webhookKey));
    const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return Buffer.concat([MAGIC_V2, salt, iv, cipher.getAuthTag(), ct]);
  }

  function decryptV2(buf, webhookKey) {
    if (buf.length < HEADER_LEN) throw new CryptoError("malformed");
    let o = MAGIC_V2.length;
    const salt = buf.subarray(o, (o += SALT_LEN));
    const iv = buf.subarray(o, (o += IV_LEN));
    const tag = buf.subarray(o, (o += TAG_LEN));
    const ct = buf.subarray(o);
    const decipher = crypto.createDecipheriv("aes-256-gcm", noteKey(salt, webhookKey), iv, { authTagLength: TAG_LEN });
    decipher.setAAD(aad(webhookKey));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  }

  function decryptV1(buf) {
    const text = buf.toString("latin1");
    const parts = text.split("|");
    if (parts.length !== 4) throw new CryptoError("malformed");
    const [encKey, iv, tag, ct] = parts;
    const b64 = /^[A-Za-z0-9+/]+={0,2}$/;
    if (![encKey, iv, tag, ct].every((p) => p && b64.test(p))) throw new CryptoError("malformed");
    const ivBuf = Buffer.from(iv, "base64");
    const tagBuf = Buffer.from(tag, "base64");
    if (ivBuf.length !== IV_LEN || tagBuf.length !== TAG_LEN) throw new CryptoError("malformed");
    const aesKey = rsaDecrypt(encKey);
    if (!aesKey || aesKey.length !== 32) throw new CryptoError("malformed");
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, ivBuf, { authTagLength: TAG_LEN });
    decipher.setAuthTag(tagBuf);
    return Buffer.concat([decipher.update(Buffer.from(ct, "base64")), decipher.final()]);
  }

  function decryptNote(buf, webhookKey, { allowLegacy }) {
    if (!Buffer.isBuffer(buf) || buf.length === 0 || buf.length > MAX_PAYLOAD_BYTES) throw new CryptoError("malformed");
    let plain;
    try {
      if (buf.subarray(0, MAGIC_V2.length).equals(MAGIC_V2)) plain = decryptV2(buf, webhookKey);
      else if (allowLegacy) plain = decryptV1(buf);
      else throw new CryptoError("legacy payload not allowed");
    } catch (err) {
      if (err instanceof CryptoError) throw err;
      throw new CryptoError("authentication failed");
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(plain);
    } catch {
      throw new CryptoError("invalid encoding");
    }
  }

  function decryptTransport(b64) {
    const buf = rsaDecrypt(b64);
    if (!buf) return null;
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(buf);
    } catch {
      return null;
    }
  }

  function digest(buf) {
    return crypto.createHash("sha256").update(buf).digest();
  }

  return Object.freeze({
    kid,
    publicKeySpkiB64: spki.toString("base64"),
    encryptNote,
    decryptNote,
    decryptTransport,
    digest
  });
}

module.exports = { createKeyring, CryptoError, MAX_PAYLOAD_BYTES };
