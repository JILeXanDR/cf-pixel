import CryptoJS from 'crypto-js';

export async function generate(keyInput, payload) {
  const json = JSON.stringify(payload);
  const encrypted = encryptPayloadAES(keyInput, Buffer.from(json));
  return Buffer.from(encrypted).toString('base64');
}

/**
 * Encrypts a payload using AES-CFB mode.
 * @param {string} key - Must be 16, 24, or 32 bytes.
 * @param {Buffer|Uint8Array} payload
 * @returns {Buffer} cipherText (IV + encrypted payload)
 */
function encryptPayloadAES(key, payload) {
  if (![16, 24, 32].includes(key.length)) {
    throw new Error(`Key must be 16, 24, or 32 bytes, got ${key.length} bytes`);
  }
  const iv = CryptoJS.lib.WordArray.random(16);
  const encrypted = CryptoJS.AES.encrypt(CryptoJS.lib.WordArray.create(payload), CryptoJS.enc.Utf8.parse(key), {
    iv,
    mode: CryptoJS.mode.CFB,
    padding: CryptoJS.pad.NoPadding,
  });
  // Concatenate IV and ciphertext
  const ivBytes = Buffer.from(iv.toString(CryptoJS.enc.Hex), 'hex');
  const ctBytes = Buffer.from(encrypted.ciphertext.toString(CryptoJS.enc.Hex), 'hex');
  return Buffer.concat([ivBytes, ctBytes]);
}

export async function decryptCookie(encryptionKey, v) {
  const key = decodeKeyPhase(encryptionKey);
  const {
    iv,
    ct,
  } = decodeBase64Phase(v);
  const pt = decryptPhase(key, iv, ct);
  console.log('pt', pt);
  return decodeJsonPhase(pt);
}

function decodeBase64Phase(v) {
  const data = base64ToU8(v);
  if (data.length < 16) throw new Error('cipher must be greater than 16 bytes, got ' + data.length + ' bytes');
  return {
    iv: data.slice(0, 16),
    ct: data.slice(16),
  };
}

function decodeKeyPhase(keyInput) {
  console.log('decodeKeyPhase keyInput', keyInput);
  const key = parseKeyToBytes(keyInput);
  if ([16, 24, 32].indexOf(key.length) === -1) {
    throw new Error(`AES key must be 16/24/32 bytes after decoding; got ${key.length}`);
  }
  return key;
}

function decryptPhase(key, iv, ct) {
  const ptWA = CryptoJS.AES.decrypt({ ciphertext: u8ToWordArray(ct) }, u8ToWordArray(key), {
    iv: u8ToWordArray(iv),
    mode: CryptoJS.mode.CFB,
    padding: CryptoJS.pad.NoPadding,
  });
  return wordArrayToU8(ptWA);
}

function decodeJsonPhase(pt) {
  const td = new TextDecoder();
  return JSON.parse(td.decode(pt));
}

// --- helpers (inlined) ---
function normalizeB64(b64) {
  let s = (b64 || '').trim().replace(/[\r\n\s]/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (s.length % 4 !== 0) s += '='.repeat(4 - (s.length % 4));
  return s;
}

function base64ToU8(b64maybeUrl) {
  const s = normalizeB64(b64maybeUrl);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
  return out;
}

function hexToU8(hex) {
  const s = (hex || '').trim().toLowerCase();
  if (!/^[0-9a-f]+$/i.test(s) || s.length % 2 !== 0) throw new Error('Invalid hex key');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

function parseKeyToBytes(input) {
  if (!input) throw new Error('Key is empty');
  try {
    const b = base64ToU8(input);
    if (b.length) return b;
  } catch (_) {
  }
  try {
    const b = hexToU8(input);
    if (b.length) return b;
  } catch (_) {
  }
  // fallback: treat as UTF-8 passphrase
  return new TextEncoder().encode(input);
}

function u8ToWordArray(u8) {
  const words = [];
  for (let i = 0; i < u8.length; i++) words[i >>> 2] = (words[i >>> 2] || 0) | (u8[i] << (24 - (i % 4) * 8));
  return CryptoJS.lib.WordArray.create(words, u8.length);
}

function wordArrayToU8(wa) {
  const words = wa.words, sigBytes = wa.sigBytes;
  const out = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i++) out[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  return out;
}
