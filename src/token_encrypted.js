// Token v1: encrypted JSON payload (current)
import { decryptCookie, generate } from './encryption.js';

export default class {
  constructor(keyBytes) {
    this.keyBytes = keyBytes;
  }

  /**
   * Generate a new token for the given visitor ID.
   * @param {String} visitorId
   * @return {Promise<string>}
   */
  async generate(visitorId) {
    // json stringify
    // encrypt with AES-CFB
    // base64 encode
    return await generate(this.keyBytes, {
      id: visitorId,
      ts: new Date().toISOString(),
    });
  }

  /**
   * Parse a token and return the visitor ID.
   * @param {String} token
   * @return {Promise<String>}
   */
  async parse(token) {
    // decode base64
    // decrypt with AES-CFB
    // parse JSON
    const decrypted = await decryptCookie(this.keyBytes, token);
    return decrypted.id;
  }

}
