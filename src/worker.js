import { parse as parseCookie, serialize as serializeCookie } from 'cookie';
import Token from './token_encrypted.js';
import genXid from './xid.js';

const encryptionKey = process.env['ENC_KEY'] || '';

if (encryptionKey.length !== 32) {
  console.error('ENC_KEY must be 32 bytes, got', encryptionKey.length);
  process.exit(1);
}

console.log('loaded ENC_KEY', encryptionKey);

export default {
  async fetch(request, env, ctx) {
    try {
      // Step 1: Validate request path
      const url = new URL(request.url);
      if (url.pathname !== '/p.js' && url.pathname !== '/p1.js') return new Response('not found', { status: 404 });

      // Step 3: Validate cookie domain
      const COOKIE_DOMAIN = env?.DOMAIN || '';
      if (COOKIE_DOMAIN.length === 0) {
        console.error('DOMAIN must be set, got', COOKIE_DOMAIN);
        return new Response(null, { status: 500 });
      }

      let visitorId = null;

      const token = new Token(encryptionKey);

      const encryptedToken = getEncryptedToken(request.headers.get('Cookie'));

      // Step 5: Try to decrypt visitorId from cookie
      if (encryptedToken) {
        try {
          visitorId = await token.parse(encryptedToken);
        } catch (e) {
          console.error('cookie decrypt failed', e);
          return new Response(null, { status: 500 });
        }
      }

      // Step 6: Generate new visitorId and set cookie if not found
      const headers = new Headers({
        'Content-Type': 'text/javascript; charset=utf-8',
        'Cache-Control': 'public, max-age=31536000, immutable',
        'Timing-Allow-Origin': '*',
      });

      if (!visitorId) {
        visitorId = genXid();
        const tokenValue = await token.generate(visitorId);
        headers.append('Set-Cookie', genCookie(COOKIE_DOMAIN, tokenValue));
      }

      return new Response(`window._PH_VISITOR_ID='${visitorId}';`, {
        status: 200,
        headers,
      });
    } catch (err) {
      console.error('unhandled error', err);
      return new Response(null, { status: 500 });
    }
  },
};

function getEncryptedToken(cookies) {
  const reqCookies = parseCookie(cookies || '', { decode: (v) => v });
  return reqCookies.token;
}

function genCookie(domain, value) {
  return serializeCookie('token', value, {
    path: '/',
    maxAge: 31536000, // 1y
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    domain: domain,
    encode: (v) => v,
  });
}
