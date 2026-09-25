import type { Env, Settings } from '../core/settings.ts';
import { CAMO_HTML } from '../generated/assets.ts';

/**
 * Camouflage: every path that is not the admin panel, the subscription route
 * or the tunnel behaves like an ordinary website.
 *
 * With `camoUrl` set the request is proxied to that origin (cookies and our
 * own session headers stripped so the site cannot see panel internals);
 * otherwise a local static page is served — cheap, no outbound fetch, nothing
 * to trigger upstream logs.
 */

const STRIP_REQUEST_HEADERS = new Set([
  'cookie',
  'x-session',
  'cf-connecting-ip',
  'cf-ipcountry',
  'cf-ray',
  'cf-visitor',
  'cf-worker',
  'x-forwarded-for',
  'x-forwarded-proto',
]);

const STRIP_RESPONSE_HEADERS = new Set([
  'content-encoding',
  'content-length',
  'set-cookie',
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'server',
]);

export async function handleCamo(request: Request, _env: Env, settings: Settings): Promise<Response> {
  const url = new URL(request.url);

  if (settings.camoUrl) {
    try {
      const origin = new URL(settings.camoUrl);
      const upstream = new URL(url.pathname + url.search, origin.origin);
      const headers = new Headers();
      for (const [k, v] of request.headers) {
        const key = k.toLowerCase();
        if (STRIP_REQUEST_HEADERS.has(key) || key === 'host') continue;
        headers.set(k, v);
      }
      headers.set('accept-encoding', 'identity');
      const res = await fetch(upstream.toString(), {
        method: request.method === 'HEAD' ? 'HEAD' : 'GET',
        headers,
        redirect: 'manual',
      });
      const out = new Response(request.method === 'HEAD' ? null : res.body, {
        status: res.status,
        statusText: res.statusText,
        headers: res.headers,
      });
      for (const h of STRIP_RESPONSE_HEADERS) out.headers.delete(h);
      return out;
    } catch {
      // origin unreachable: fall through to the local page
    }
  }

  const html = CAMO_HTML.replaceAll('__BRAND__', () => settings.brand.replace(/[<>&"]/g, ''));
  const status = url.pathname === '/' ? 200 : 404;
  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'referrer-policy': 'no-referrer',
      'cache-control': 'public, max-age=300',
      'x-robots-tag': 'noindex, nofollow',
      'content-security-policy':
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
    },
  });
}
