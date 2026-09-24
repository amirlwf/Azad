import { settingsFor, type Env } from './core/settings.ts';
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

function html(body: string): Response {
  return new Response(body, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'referrer-policy': 'no-referrer',
      'cache-control': 'no-store',
      'x-robots-tag': 'noindex, nofollow',
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
        return html(PANEL_HTML.replaceAll('__BRAND__', () => escapeHtml(settings.brand)));
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


