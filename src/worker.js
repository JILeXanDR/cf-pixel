import { parse as parseCookie, serialize as serializeCookie } from 'cookie';
import Token from './token_base64.js';
import genXid from './xid.js';

const PATH = '/p1.js';

export default {
  async fetch(request, env, ctx) {
    try {
      // Step 1: Validate request path
      const url = new URL(request.url);
      if (url.pathname !== PATH) return new Response('not found', { status: 404 });

      // Step 2: Validate AES key
      const keyBytes = new TextEncoder().encode(env?.ENC_KEY);
      if (keyBytes.byteLength !== 32) {
        console.error('ENC_KEY must be exactly 32 bytes, got', keyBytes.byteLength);
        return new Response(null, { status: 500 });
      }

      // Step 3: Validate cookie domain
      const COOKIE_DOMAIN = env?.DOMAIN || '';
      if (COOKIE_DOMAIN.length === 0) {
        console.error('DOMAIN must be set, got', COOKIE_DOMAIN);
        return new Response(null, { status: 500 });
      }

      // Step 4: Parse cookies
      const reqCookies = parseCookie(request.headers.get('Cookie') || '');
      let visitorId = null;

      // const tokenV1 = new Token(keyBytes);
      const token = new Token();

      // Step 5: Try to decrypt visitorId from cookie
      if (reqCookies.token) {
        try {
          visitorId = token.parse(reqCookies.token);
        } catch (e) {
          console.warn('cookie decrypt failed', e);
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
        const tokenValue = token.gen(visitorId);
        headers.append('Set-Cookie', genCookie(COOKIE_DOMAIN, tokenValue));
      }

      // Step 7: Respond with visitorId JS
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

function genCookie(domain, value) {
  return serializeCookie('token', value, {
    path: '/',
    maxAge: 31536000, // 1y
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    domain: domain,
  });
}
