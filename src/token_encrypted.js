import { decryptPayloadAES, encryptPayloadAES } from './encryption.js';

export default class {
  /**
   * Creates an instance of the class with the provided encryption key.
   *
   * @param {string} encryptionKey - The 32-byte encryption key used for encryption and decryption. Must be exactly 32 characters long.
   * @throws {Error} If the encryptionKey is not provided.
   * @throws {Error} If the encryptionKey length is not equal to 32 bytes.
   * @return {Object} A new instance initialized with the specified encryption key.
   */
  constructor(encryptionKey) {
    if (!encryptionKey) throw new Error('encryptionKey is required');
    if (encryptionKey.length !== 32) throw new Error('encryptionKey must be 32 bytes, got ' + encryptionKey.length + ' bytes');
    this.encryptionKey = encryptionKey;
  }

  /**
   * Generate a new token for the given visitor ID.
   * @param {String} visitorId
   * @return {Promise<string>}
   */
  async generate(visitorId) {
    const json = JSON.stringify({
      id: visitorId,
      ts: new Date().toISOString(),
    });
    const encrypted = encryptPayloadAES(this.encryptionKey, Buffer.from(json));
    const encoded = encrypted.toString('base64');

    console.log(`generated token ${encoded} for visitor id ${visitorId} using ${this.encryptionKey} encryption key`);
    // try {
    //   await this.selfTest(token, visitorId);
    // } catch (e) {
    //   console.error('self test failed', e);
    //   throw e;
    // }

    return encoded;
  }

  /**
   * Parse a token and return the visitor ID.
   * @param {String} token
   * @return {Promise<String>}
   */
  async parse(token) {
    const decoded = Buffer.from(token, 'base64');
    const decrypted = decryptPayloadAES(this.encryptionKey, decoded);
    const parsed = JSON.parse((new TextDecoder()).decode(decrypted));
    return parsed.id;
  }

  async selfTest(token, visitorId) {
    const parsedVisitorId = await this.parse(token);
    console.log('parsedVisitorId', parsedVisitorId);
    if (parsedVisitorId !== visitorId) {
      throw new Error('parsedVisitorId !== visitorId');
    } else {
      console.log('self test passed %s === %s', parsedVisitorId, visitorId);
    }
  }
}
