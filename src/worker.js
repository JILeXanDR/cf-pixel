import { parse as parseCookie, serialize as serializeCookie } from 'cookie';

const PATH = '/p.js';

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      if (url.pathname !== PATH) return new Response('not found', { status: 404 });

      // --- AES key must be 32 bytes (AES-256)
      const keyBytes = new TextEncoder().encode(env?.ENC_KEY);
      if (keyBytes.byteLength !== 32) {
        console.error('ENC_KEY must be exactly 32 bytes, got', keyBytes.byteLength);
        return new Response(null, { status: 500 });
      }

      // Share cookie across apex & subs: e.g. ".example.com"
      const COOKIE_DOMAIN = env?.DOMAIN || '';
      if (COOKIE_DOMAIN.length === 0) {
        console.error('DOMAIN must be set, got', COOKIE_DOMAIN);
        return new Response(null, { status: 500 });
      }

      // Read cookie via library
      const reqCookies = parseCookie(request.headers.get('Cookie') || '');
      let visitorId = null;

      if (reqCookies.token) {
        try {
          visitorId = await parseVisitorId(reqCookies.token);
        } catch (e) {
          console.warn('cookie decrypt failed', e);
        }
      }

      const headers = new Headers({
        'Content-Type': 'text/javascript; charset=utf-8',
        'Cache-Control': 'public, max-age=31536000, immutable',
        'Timing-Allow-Origin': '*',
      });

      if (!visitorId) {
        visitorId = genXid();
        const tokenValue = await genToken(keyBytes, visitorId);

        // use cookie.serialize for correctness
        headers.append('Set-Cookie', serializeCookie('token', tokenValue, {
          path: '/',
          maxAge: 31536000, // 1y
          httpOnly: true,
          secure: true,
          sameSite: 'none',
          domain: COOKIE_DOMAIN,
        }));
      }

      const body = `window._PH_VISITOR_ID='${visitorId}';`;
      return new Response(body, {
        status: 200,
        headers,
      });
    } catch (err) {
      console.error('unhandled error', err);
      return new Response(null, { status: 500 });
    }
  },
};

function stripQuotes(s) {
  return s.replace(/^"|"$/g, '');
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

// ----- Base64 (std) -----
function bytesToBase64(bytes) {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  return btoa(bin);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function genToken(keyBytes, visitorId) {
  const payload = new TextEncoder().encode(JSON.stringify({
    id: visitorId,
    ts: new Date().toISOString(),
  }));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const cipher = await aesCfbEncrypt(keyBytes, iv, payload);
  return bytesToBase64(concat(iv, cipher));
}

async function parseVisitorId(keyBytes, token) {
  const tok = base64ToBytes(stripQuotes(token));
  if (tok.length >= 16) {
    const iv = tok.slice(0, 16);
    const cipher = tok.slice(16);
    const plain = await aesCfbDecrypt(keyBytes, iv, cipher);
    const json = JSON.parse(new TextDecoder().decode(plain));
    if (json && typeof json.id === 'string' && json.id) return json.id;
    return null;
  }
}

// ----- XID-like (20-char base32hex) -----
function genXid() {
  const buf = new Uint8Array(12);
  const nowSec = Math.floor(Date.now() / 1000);
  buf[0] = (nowSec >>> 24) & 0xff;
  buf[1] = (nowSec >>> 16) & 0xff;
  buf[2] = (nowSec >>> 8) & 0xff;
  buf[3] = nowSec & 0xff;
  crypto.getRandomValues(buf.subarray(4));
  return base32HexEncode(buf);
}

function base32HexEncode(bytes) {
  const alphabet = '0123456789abcdefghijklmnopqrstuv';
  let bits = 0, value = 0, out = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
