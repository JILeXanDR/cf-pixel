// Token v2: raw JSON + base64 (not encrypted)
import { base64ToBytes, bytesToBase64, stripQuotes } from './utils.js';

export default class {
  generate(visitorId) {
    return bytesToBase64(new TextEncoder().encode(JSON.stringify({
      id: visitorId,
      ts: new Date().toISOString(),
    })));
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
