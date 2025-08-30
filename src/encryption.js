import CryptoJS from 'crypto-js';

/**
 * Encrypts payload using AES-CFB mode.
 * @param {string} key - 16, 24, or 32 bytes (utf8).
 * @param {Buffer<ArrayBuffer>} payload
 * @returns {Buffer} IV + ciphertext
 */
export function encryptPayloadAES(key, payload) {
  if (typeof key !== 'string' || !key.length) throw new Error('key must be a non-empty string');
  if (!Buffer.isBuffer(payload)) throw new Error('payload must be Buffer<ArrayBuffer>');

  const keyBytes = parseKey(key);
  const iv = CryptoJS.lib.WordArray.random(16);
  const encrypted = CryptoJS.AES.encrypt(CryptoJS.lib.WordArray.create(payload), CryptoJS.lib.WordArray.create(keyBytes), {
    iv,
    mode: CryptoJS.mode.CFB,
    padding: CryptoJS.pad.NoPadding,
  });
  // Concatenate IV and ciphertext
  return Buffer.concat([
    Buffer.from(iv.toString(CryptoJS.enc.Hex), 'hex'), Buffer.from(encrypted.ciphertext.toString(CryptoJS.enc.Hex), 'hex')]);
}

/**
 * Decrypts AES-CFB payload.
 * @param {string} key
 * @param {Buffer<ArrayBuffer>} payload - base64 or Buffer
 * @returns {Buffer} plaintext
 */
export function decryptPayloadAES(key, payload) {
  if (typeof key !== 'string' || !key.length) throw new Error('key must be a non-empty string');
  if (!Buffer.isBuffer(payload)) throw new Error('payload must be Buffer<ArrayBuffer>');

  const keyBytes = parseKey(key);
  if (payload.length < 16) throw new Error('cipher must be greater than 16 bytes');
  const iv = payload.subarray(0, 16), ct = payload.subarray(16);
  // CryptoJS expects ciphertext as WordArray
  const ptWA = CryptoJS.AES.decrypt({ ciphertext: CryptoJS.lib.WordArray.create(ct) }, CryptoJS.lib.WordArray.create(keyBytes), {
    iv: CryptoJS.lib.WordArray.create(iv),
    mode: CryptoJS.mode.CFB,
    padding: CryptoJS.pad.NoPadding,
  });
  return Buffer.from(wordArrayToU8(ptWA));
}

/**
 * Parses key as utf8 and checks length.
 * @param {string} input
 * @returns {Buffer}
 */
function parseKey(input) {
  if (typeof input !== 'string' || !input.length) throw new Error('Key is empty');
  const keyBytes = Buffer.from(input, 'utf8');
  if (![16, 24, 32].includes(keyBytes.length)) throw new Error(`Key must be 16, 24, or 32 bytes, got ${keyBytes.length}`);
  return keyBytes;
}

/**
 * Converts CryptoJS WordArray to Uint8Array.
 * @param {CryptoJS.lib.WordArray} wa
 * @returns {Uint8Array}
 */
function wordArrayToU8(wa) {
  // WordArray stores bytes in 32-bit words
  const out = new Uint8Array(wa.sigBytes);
  for (let i = 0; i < wa.sigBytes; i++) out[i] = (wa.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  return out;
}
