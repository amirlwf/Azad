import { settingsFor, type Env } from './core/settings.ts';
import { cspHeader, injectNonce, newNonce } from './http/csp.ts';
import { FONT_B64 } from './generated/assets.ts';
import { handleAdminApi, isAuthed } from './http/admin-api.ts';
import { handleCamo } from './http/camo.ts';
import { handleSubscription } from './http/subscription.ts';
import { PANEL_HTML } from './generated/assets.ts';
import { handleTunnel } from './proxy/ws.ts';

/**
 * Entry point.
 *
 * Routing order matters:
 *   1. websocket upgrade  -> tunnel (path-checked inside)
 *   2. /{adminPath}       -> panel HTML + JSON API
 *   3. /{subPath}/<token> -> subscription / portal
 *   4. everything else    -> camouflage site
 *
 * Unknown paths never reveal which service this worker runs: there is no
 * version endpoint, no robots.txt with hints and no stack trace in errors.
 */

function html(body: string, csp?: string): Response {
  return new Response(body, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'referrer-policy': 'no-referrer',
      'cache-control': 'no-store',
      'x-robots-tag': 'noindex, nofollow',
      ...(csp ? { 'content-security-policy': csp } : {}),
    },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const upgrade = request.headers.get('Upgrade') || request.headers.get('upgrade');
      if (upgrade && upgrade.toLowerCase() === 'websocket') {
        return handleTunnel(request, env);
      }

      const url = new URL(request.url);
      const settings = await settingsFor(env);
      const path = url.pathname;

      if (path === '/favicon.ico') return new Response(null, { status: 204 });

      if (path === '/f.woff2') {
        // Vazirmatn variable font: base64 lives in the bundle, bytes are cached
        if (!FONT_B64) return new Response('not found', { status: 404 });
        const bin = atob(FONT_B64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return new Response(bytes, {
          headers: {
            'content-type': 'font/woff2',
            'cache-control': 'public, max-age=31536000, immutable',
          },
        });
      }

      const adminBase = `/${settings.adminPath}`;
      if (path === adminBase || path.startsWith(`${adminBase}/`)) {
        if (path === `${adminBase}/api` || path.startsWith(`${adminBase}/api/`)) {
          const authed = await isAuthed(env, request);
          const res = await handleAdminApi({ env, request, url, settings, authed });
          res.headers.set('x-content-type-options', 'nosniff');
          return res;
        }
        if (request.method !== 'GET' && request.method !== 'HEAD') {
          return new Response('Method Not Allowed', { status: 405 });
        }
        const nonce = newNonce();
        const page = injectNonce(
          PANEL_HTML.replaceAll('__BRAND__', () => escapeHtml(settings.brand)),
          nonce,
        );
        return html(page, cspHeader(nonce));
      }

      if (path.startsWith(`/${settings.subPath}/`)) {
        return handleSubscription(request, env, settings, url);
      }

      return handleCamo(request, env, settings);
    } catch (err) {
      // never leak internals (a stack trace is a fingerprint by itself)
      return new Response('Service Unavailable', {
        status: 503,
        headers: { 'content-type': 'text/plain; charset=utf-8', 'retry-after': '5' },
      });
    }
  },
};

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : c === '"' ? '&quot;' : '&#39;',
  );
}


