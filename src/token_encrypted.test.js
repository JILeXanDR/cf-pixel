import { expect } from '@jest/globals';
import Token_encrypted from './token_encrypted.js';

describe('token_encrypted', () => {
  test('decryptToken should return the original token', async () => {
    const token = new Token_encrypted('N56n9na#Ybs4Tyeg6Lotadi7Rs!fpThD');
    const visitorId = 'd11davpphrtc738ql0jg';
    const encrypted = await token.generate(visitorId);
    console.log('encrypted', encrypted);
    expect(typeof encrypted).toBe('string');
    const decrypted = await token.parse(encrypted);
    expect(decrypted).toBe(visitorId);
  });

  test('', async () => {
    const token = new Token_encrypted('N56n9na#Ybs4Tyeg6Lotadi7Rs!fpThD');
    const visitorId = 'hello world';
    const encrypted = await token.generate(visitorId);
    console.log('encrypted', encrypted);
    expect(typeof encrypted).toBe('string');
    const decrypted = await token.parse(encrypted);
    expect(decrypted).toBe(visitorId);
  });

  test('token 1 encrypted in Go should be decrypted by JS', async () => {
    const token = new Token_encrypted('N56n9na#Ybs4Tyeg6Lotadi7Rs!fpThD');
    const visitorId = 'd11davpphrtc738ql0jg';
    const decrypted = await token.parse(`+3XSf471QOFlkatyPdqek6PYUTAvTGqm/mZQ1nH2NBZKaZPdspqTEWk1r0uf7+Ld4+/KyWlZ5/XFNZlZaxho0Jlcpu+gymckxmUqS3C1sYqAVdU=`);
    expect(decrypted).toBe(visitorId);
  });

  test('token 2 encrypted in Go should be decrypted by JS', async () => {
    const token = new Token_encrypted('N56n9na#Ybs4Tyeg6Lotadi7Rs!fpThD');
    const visitorId = 'd2oq5di3miqc73c5vpr0';
    const decrypted = await token.parse(`yTeyB+dY708wnI3/WcFcCJTupwqVrFhF/OG2ZPOl5MPBQKYiUH81+LT0jgLbbAMXFm6gw7YAyCGfIxKLLIKaVMui+l0JIb5pphNeOj0SErLz9Ik=`);
    expect(decrypted).toBe(visitorId);
  });
});
