import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

/**
 * End-to-end HTTP suite against a live `wrangler dev` instance:
 *   npx wrangler dev --port 8787 --var LOCAL_TEST:1
 * All tests skip when the server is not reachable so `npm test` stays offline.
 */

const BASE = process.env.E2E_BASE ?? 'http://127.0.0.1:8787';
const ADMIN = '/console-dev';
const SUB = '/get-dev';
const PASS = 'e2e-correct-horse-battery';

let live = false;
let cookie = '';
let token = '';

before(async () => {
  try {
    const r = await fetch(BASE + '/', { signal: AbortSignal.timeout(2000) });
    live = r.status === 200 || r.status === 404;
  } catch {
    live = false;
  }
  if (!live) {
    console.log(`[e2e] ${BASE} not reachable — skipping live suite`);
    return;
  }
  // fresh instance: establish the admin session (setup on first boot)
  const s = await fetch(BASE + ADMIN + '/api/session');
  const sj: any = await s.json();
  const initBody = JSON.stringify({ password: PASS });
  const init = await fetch(BASE + ADMIN + (sj.setupRequired ? '/api/setup' : '/api/login'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: initBody,
  });
  const setCookie = init.headers.get('set-cookie') ?? '';
  cookie = /azad_sid=([^;]+)/.exec(setCookie)?.[1] ? `azad_sid=${/azad_sid=([^;]+)/.exec(setCookie)![1]}` : '';
  if (!cookie) {
    // already initialised in a previous run — log in normally
    const login = await fetch(BASE + ADMIN + '/api/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: PASS }),
    });
    const m = /azad_sid=([^;]+)/.exec(login.headers.get('set-cookie') ?? '');
    cookie = m ? `azad_sid=${m[1]}` : '';
  }
  // ensure a test user exists
  const created = await fetch(BASE + ADMIN + '/api/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ name: 'e2e-user' }),
  });
  if (created.status === 201) {
    const cj: any = await created.json();
    token = cj.user.token;
  } else {
    const list: any = await (await fetch(BASE + ADMIN + '/api/users', { headers: { cookie } })).json();
    token = list.users?.[0]?.token ?? '';
  }
});

const skip = () => !live;

describe('e2e: camouflage', () => {
  it('serves the cover page on /', async () => {
    if (skip()) return;
    const r = await fetch(BASE + '/');
    assert.equal(r.status, 200);
    const body = await r.text();
    assert.match(body, /^<!doctype html>/i);
    assert.ok(!/vless|trojan|subscription/i.test(body), 'cover page must not leak what we run');
    assert.equal(r.headers.get('x-robots-tag'), 'noindex, nofollow');
  });

  it('returns the cover page for unknown deep paths', async () => {
    if (skip()) return;
    const r = await fetch(BASE + '/blog/2026/any-post');
    const body = await r.text();
    assert.equal(r.status, 404, 'unknown content should read as a 404 site');
    assert.match(body, /<!doctype html>/i);
  });

  it('answers 204 to favicon probes', async () => {
    if (skip()) return;
    const r = await fetch(BASE + '/favicon.ico');
    assert.equal(r.status, 204);
  });

  it('does not expose robots.txt or admin hints', async () => {
    if (skip()) return;
    const r = await fetch(BASE + '/robots.txt');
    const body = await r.text();
    assert.ok(!body.includes(ADMIN.slice(1)), 'robots must not reveal the panel path');
  });
});

describe('e2e: admin console', () => {
  it('serves the panel HTML on the random path only', async () => {
    if (skip()) return;
    const ok = await fetch(BASE + ADMIN);
    assert.equal(ok.status, 200);
    const html = await ok.text();
    assert.match(html, /<!doctype html>/i);
    assert.ok(!html.includes('__BRAND__'), 'brand placeholder must be replaced');
    assert.ok(!/<script[^>]+src=/i.test(html), 'panel must be fully self-contained');

    const wrong = await fetch(BASE + '/console-0000');
    assert.equal(wrong.status, 404);
  });

  it('rejects non-GET on the panel shell', async () => {
    if (skip()) return;
    const r = await fetch(BASE + ADMIN, { method: 'POST' });
    assert.equal(r.status, 405);
  });

  it('reports session state without auth', async () => {
    if (skip()) return;
    const r = await fetch(BASE + ADMIN + '/api/session');
    assert.equal(r.status, 200);
    const j: any = await r.json();
    assert.equal(typeof j.setupRequired, 'boolean');
    assert.equal(j.authed, false);
    assert.ok(!JSON.stringify(j).includes('adminPassHash'), 'hash must never be exposed');
  });

  it('requires auth for the user list', async () => {
    if (skip()) return;
    const r = await fetch(BASE + ADMIN + '/api/users');
    assert.equal(r.status, 401);
  });

  it('accepts the session cookie from the bootstrap step', async () => {
    if (skip()) return;
    assert.ok(cookie, 'bootstrap must have produced a session');
    const r = await fetch(BASE + ADMIN + '/api/users', { headers: { cookie } });
    assert.equal(r.status, 200);
    const j: any = await r.json();
    assert.ok(Array.isArray(j.users));
    assert.ok(j.users.length >= 1);
  });

  it('rejects malformed JSON with 400, not a stack trace', async () => {
    if (skip()) return;
    const r = await fetch(BASE + ADMIN + '/api/users', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: '{broken json',
    });
    assert.equal(r.status, 400);
    const body = await r.text();
    assert.ok(!/at .*\.js:\d+/.test(body), 'no stack traces in error bodies');
  });

  it('returns an overview with stats', async () => {
    if (skip()) return;
    const r = await fetch(BASE + ADMIN + '/api/overview', { headers: { cookie } });
    assert.equal(r.status, 200);
    const j: any = await r.json();
    assert.ok(typeof j.stats.total === 'number');
    assert.ok(typeof j.stats.online === 'number');
  });
});

describe('e2e: subscription + portal', () => {
  it('serves the portal page to browsers', async () => {
    if (skip()) return;
    assert.ok(token, 'need a user token');
    const r = await fetch(BASE + SUB + '/' + token, {
      headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0' },
    });
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.match(html, /<!doctype html>/i);
    assert.ok(html.includes('e2e-user'), 'portal must show the user name');
    assert.ok(!html.includes('adminPassHash'));
  });

  it('serves raw links to client user agents', async () => {
    if (skip()) return;
    const r = await fetch(BASE + SUB + '/' + token, {
      headers: { 'user-agent': 'v2rayNG/1.8.30' },
    });
    assert.equal(r.status, 200);
    const body = await r.text();
    assert.match(body, /(vless|trojan):\/\//);
    assert.ok(!body.startsWith('<!doctype'), 'client must get links, not HTML');
  });

  it('serves base64, clash and sing-box formats', async () => {
    if (skip()) return;
    const b64 = await fetch(`${BASE}${SUB}/${token}?format=base64`);
    assert.equal(b64.status, 200);
    const decoded = Buffer.from((await b64.text()).trim(), 'base64').toString('utf8');
    assert.match(decoded, /(vless|trojan):\/\//);

    const clash = await fetch(`${BASE}${SUB}/${token}?format=clash`);
    assert.equal(clash.status, 200);
    assert.match(await clash.text(), /proxies:/);

    const sb = await fetch(`${BASE}${SUB}/${token}?format=singbox`);
    assert.equal(sb.status, 200);
    const json = JSON.parse(await sb.text());
    assert.ok(Array.isArray(json.outbounds));
  });

  it('rejects unknown or malformed tokens', async () => {
    if (skip()) return;
    const bad = await fetch(BASE + SUB + '/' + 'f'.repeat(20), {
      headers: { 'user-agent': 'v2rayNG/1.8.30' },
    });
    assert.equal(bad.status, 404);
    const badShape = await fetch(BASE + SUB + '/' + '../etc/passwd');
    assert.equal(badShape.status, 404);
  });

  it('sets accounting headers on raw subscriptions', async () => {
    if (skip()) return;
    const r = await fetch(`${BASE}${SUB}/${token}?format=raw`, {
      headers: { 'user-agent': 'v2rayNG/1.8.30' },
    });
    assert.equal(r.status, 200);
    const sui = r.headers.get('subscription-userinfo');
    assert.ok(sui && sui.includes('upload='), `missing accounting header: ${sui}`);
    assert.ok(r.headers.get('profile-update-interval'));
  });
});
