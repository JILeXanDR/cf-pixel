// Token v2: raw JSON + base64 (not encrypted)
import { base64ToBytes, bytesToBase64, stripQuotes } from './utils.js';

export default class TokenV2 {
  gen(visitorId) {
    const payload = JSON.stringify({
      id: visitorId,
      ts: new Date().toISOString(),
    });
    return bytesToBase64(new TextEncoder().encode(payload));
  }

  parse(token) {
    try {
      const bytes = base64ToBytes(stripQuotes(token));
      const json = JSON.parse(new TextDecoder().decode(bytes));
      if (json && typeof json.id === 'string' && json.id) return json.id;
      return null;
    } catch {
      return null;
    }
  }
}
