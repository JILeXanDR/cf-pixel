import { expect } from '@jest/globals';
import Token_encrypted from './token_encrypted.js';

describe('token_encrypted', () => {
  test('encryptToken should return a string', async () => {
    const token = new Token_encrypted('N56n9na#Ybs4Tyeg6Lotadi7Rs!fpThD');
    const visitorId = 'd11davpphrtc738ql0jg';
    const encrypted = await token.generate(visitorId);
    expect(typeof encrypted).toBe('string');
    expect(encrypted.length).toBeGreaterThan(visitorId.length);
  });

  test('decryptToken should return the original token', async () => {
    const token = new Token_encrypted('N56n9na#Ybs4Tyeg6Lotadi7Rs!fpThD');
    const visitorId = 'd11davpphrtc738ql0jg';
    const encrypted = await token.generate(visitorId);
    const decrypted = await token.parse(encrypted);
    expect(decrypted).toBe(visitorId);
  });

  test('token encrypted in Go should be decrypted by JS', async () => {
    const token = new Token_encrypted('N56n9na#Ybs4Tyeg6Lotadi7Rs!fpThD');
    const visitorId = 'd11davpphrtc738ql0jg';
    const decrypted = await token.parse(`+3XSf471QOFlkatyPdqek6PYUTAvTGqm/mZQ1nH2NBZKaZPdspqTEWk1r0uf7+Ld4+/KyWlZ5/XFNZlZaxho0Jlcpu+gymckxmUqS3C1sYqAVdU=`);
    expect(decrypted).toBe(visitorId);
  });
});
