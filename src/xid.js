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

export default genXid;