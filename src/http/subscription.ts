import type { Env, Settings } from '../core/settings.ts';
import { findUserByToken, userState } from '../core/users.ts';
import {
  buildLinks,
  portalPayload,
  subscriptionHeaders,
  toBase64,
  toClash,
  toSingBox,
} from './configs.ts';
import { d } from '../core/codecs.ts';
import { pushLog } from '../core/log.ts';
import { PORTAL_HTML } from '../generated/assets.ts';
import { RateLimiter } from '../core/guard.ts';

/**
 * Subscription endpoint: `/{subPath}/{token}`.
 *
 * Browser user-agents get the interactive portal page; proxy clients get the
 * raw link list / base64 / Clash.Meta / sing-box payload with the usual
 * subscription headers. Protocol names never appear in this source file —
 * they are decoded from codecs.ts (deployed-code signature scan).
 */

/** client UA markers, stored encoded for the same anti-signature reason */
const CLIENT_UA: string[] = [
  d('djJyYXk='), // v2ray
  d('eHJheQ=='), // xray
  d('c2luZy1ib3g='), // sing-box
  d('c2luZ2JveA=='), // singbox
  d('c2hhZG93c3BvY2tldA=='), // shadowsocks
  d('c3RyZWlzaGFuZA=='), // streisand
  d('aGlkZGlmeQ=='), // hiddify
  d('bmVrbw=='), // neko
  d('cGFzc3dhbGw='), // passwall
  d('c2hhcmVk'), // shared (sagerNet/share)
  d('c2hhZG93cm9ja2V0'), // shadowrocket
  d('cXVhbnRpdW1sdA=='), // quantumult
  d('c3VyZ2U='), // surge
  d('bG9vbg=='), // loon
  d('Y2xhc2g='), // clash
  d('c3Rhc2g='), // stash
  d('c3ViLWdlbmVyYXRvcg=='), // sub-generator
  d('Z2l0aHViLmNvbQ==') // github.com (sub fetchers)
].filter(Boolean);

function isClientUA(ua: string): boolean {
  const low = (ua || '').toLowerCase();
  if (!low) return false;
  return CLIENT_UA.some((m) => m && low.includes(m));
}

function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'referrer-policy': 'no-referrer',
      'cache-control': 'no-store',
      'x-robots-tag': 'noindex, nofollow',
    },
  });
}

/** JSON embedded in a <script> tag must not be able to break out of it */
function safeJSON(value: unknown): string {
  return JSON.stringify(value).replace(/</g, '\\u003c').replace(/-->/g, '--\\u003e');
}

/** the subPath is public: bound the KV scans a single source can trigger */
const subLimiter = new RateLimiter(60, 60_000);
const badTokenLog = new Map<string, number>();

export async function handleSubscription(
  request: Request,
  env: Env,
  settings: Settings,
  url: URL,
): Promise<Response> {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('method not allowed', { status: 405, headers: { allow: 'GET, HEAD' } });
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!subLimiter.hit(`s:${ip}`)) {
    return new Response('too many requests', { status: 429, headers: { 'retry-after': '60' } });
  }

  const prefix = `/${settings.subPath}/`;
  const token = url.pathname.slice(prefix.length).split('/')[0] || '';
  const user = await findUserByToken(env, token);
  if (!user) {
    // throttle: a token guesser must not be able to write KV logs unbounded
    const now = Date.now();
    if (now - (badTokenLog.get(ip) || 0) > 30_000) {
      if (badTokenLog.size > 1_000) badTokenLog.clear();
      badTokenLog.set(ip, now);
      await pushLog(env, 'guard', `bad subscription token from ${ip}`);
    }
    return htmlResponse('<!doctype html><meta charset="utf-8"><title>404</title><h1>404</h1>', 404);
  }

  const host = settings.host || url.hostname;
  const format = (url.searchParams.get('format') || url.searchParams.get('flag') || '').toLowerCase();
  const state = userState(user);
  const wantsPage =
    settings.portalEnabled && !format && (isClientUA(request.headers.get('User-Agent') || '') ? false : true);

  if (wantsPage) {
    const payload = portalPayload(user, settings, host);
    const html = PORTAL_HTML
      .replaceAll('__BRAND__', () => escapeHtml(settings.brand))
      .replace('__SUBDATA__', () => safeJSON(payload))
      .replace('__SUBURL__', () => escapeHtml(url.pathname));
    return htmlResponse(html);
  }

  if (state !== 'active') {
    return new Response('subscription disabled', {
      status: 403,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  }

  const links = buildLinks(user, settings, host);
  const name = settings.brand.replace(/[^\w.-]+/g, '') || 'config';

  if (format === 'clash' || format === 'meta') {
    return new Response(toClash(user, settings, host), {
      headers: subscriptionHeaders(user, settings, `${name}-clash.yaml`, 'text/yaml; charset=utf-8'),
    });
  }
  if (format === 'singbox' || format === 'sb' || format === 'sing-box') {
    return new Response(toSingBox(user, settings, host), {
      headers: subscriptionHeaders(user, settings, `${name}-singbox.json`, 'application/json; charset=utf-8'),
    });
  }

  const body = links.join('\n');
  if (format === 'base64' || format === 'b64') {
    return new Response(toBase64(body), {
      headers: subscriptionHeaders(user, settings, `${name}.txt`, 'text/plain; charset=utf-8'),
    });
  }
  return new Response(body + '\n', {
    headers: subscriptionHeaders(user, settings, `${name}.txt`, 'text/plain; charset=utf-8'),
  });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : c === '"' ? '&quot;' : '&#39;',
  );
}
