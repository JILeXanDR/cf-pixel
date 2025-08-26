import { base64ToBytes, bytesToBase64, stripQuotes } from './utils.js';

// Token v1: encrypted JSON payload (current)
export default class TokenV1 {
  constructor(keyBytes) {
    this.keyBytes = keyBytes;
  }

  async gen(visitorId) {
    const payload = new TextEncoder().encode(JSON.stringify({
      id: visitorId,
      ts: new Date().toISOString(),
    }));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const cipher = await aesCfbEncrypt(this.keyBytes, iv, payload);
    return bytesToBase64(concat(iv, cipher));
  }

  async parse(token) {
    const tok = base64ToBytes(stripQuotes(token));
    if (tok.length >= 16) {
      const iv = tok.slice(0, 16);
      const cipher = tok.slice(16);
      const plain = await aesCfbDecrypt(this.keyBytes, iv, cipher);
      const json = JSON.parse(new TextDecoder().decode(plain));
      if (json && typeof json.id === 'string' && json.id) return json.id;
      return null;
    }
  }
}

async function aesCfbEncrypt(keyBytes, iv, plaintext) {
  const key = await importAesCbcKey(keyBytes);
  const out = new Uint8Array(plaintext.length);
  let ivBlock = new Uint8Array(iv);
  const zero = new Uint8Array(16);
  for (let o = 0; o < plaintext.length;) {
    const ks = new Uint8Array(await crypto.subtle.encrypt({
      name: 'AES-CBC',
      iv: ivBlock,
    }, key, zero));
    const n = Math.min(16, plaintext.length - o);
    for (let i = 0; i < n; i++) out[o + i] = plaintext[o + i] ^ ks[i];
    if (n === 16) ivBlock = out.slice(o, o + 16);
    o += n;
  }
  return out;
}

async function aesCfbDecrypt(keyBytes, iv, ciphertext) {
  const key = await importAesCbcKey(keyBytes);
  const out = new Uint8Array(ciphertext.length);
  let ivBlock = new Uint8Array(iv);
  const zero = new Uint8Array(16);
  for (let o = 0; o < ciphertext.length;) {
    const ks = new Uint8Array(await crypto.subtle.encrypt({
      name: 'AES-CBC',
      iv: ivBlock,
    }, key, zero));
    const n = Math.min(16, ciphertext.length - o);
    for (let i = 0; i < n; i++) out[o + i] = ciphertext[o + i] ^ ks[i];
    if (n === 16) ivBlock = ciphertext.slice(o, o + 16);
    o += n;
  }
  return out;
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// ----- AES-CFB via AES-CBC zero-block trick -----
async function importAesCbcKey(keyBytes) {
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt']);
}

