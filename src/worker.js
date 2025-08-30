import { parse as parseCookie, serialize as serializeCookie } from 'cookie';
import Token from './token_encrypted.js';
import genXid from './xid.js';

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

      const token = new Token(env?.ENC_KEY);

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

function getEncryptedToken(cookies) {
  const reqCookies = parseCookie(cookies || '');
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
  });
}
