// ----- Base64 (std) -----
export function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

export function base64ToBytes(b64) {
  return Uint8Array.from(Buffer.from(b64, 'base64'));
}

export function stripQuotes(s) {
  return s.replace(/^"|"$/g, '');
}
