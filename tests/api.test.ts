import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { handleAdminApi, isAuthed, resetLoginLimiter } from '../src/http/admin-api.ts';
import { defaultSettings, settingsFor, resetSettingsCache, type Env } from '../src/core/settings.ts';
import { clearCache, type KVLike } from '../src/core/store.ts';

/* ------------------------------------------------------------------ mock KV */
function mockKV(): KVLike {
  const store = new Map<string, string>();
  return {
    async get(key: string) {
      return store.has(key) ? (store.get(key) as string) : null;
    },
    async put(key: string, value: string) {
      store.set(key, value);
    },
    async delete(key: string) {
      store.delete(key);
    },
    async list(opts?: { prefix?: string }) {
      const keys = [...store.keys()].filter((n) => !opts?.prefix || n.startsWith(opts.prefix));
      return { keys: keys.map((name) => ({ name })), list_complete: true };
    },
  };
}

const ORIGIN = 'http://panel.test';

let kv: KVLike;
let env: Env;
let base = '';

async function call(path: string, init: RequestInit & { cookie?: string } = {}) {
  const { cookie, ...rest } = init;
  const urlStr = ORIGIN + (path.startsWith('/') ? path : base + '/' + path);
  const request = new Request(urlStr, {
    ...rest,
    headers: {
      'content-type': 'application/json',
      ...(cookie ? { cookie } : {}),
      ...((rest.headers as Record<string, string>) ?? {}),
    },
  });
  const settings = await settingsFor(env);
  const authed = await isAuthed(env, request);
  const res = await handleAdminApi({ env, request, url: new URL(urlStr), settings, authed });
  const setCookie = res.headers.get('set-cookie') ?? '';
  const token = /azad_sid=([^;]+)/.exec(setCookie)?.[1] ?? '';
  let body: any = null;
  try {
    body = await res.json();
  } catch {
    /* empty body */
  }
  return { status: res.status, body, cookie: token ? `azad_sid=${token}` : '' };
}

beforeEach(async () => {
  kv = mockKV();
  env = { KV: kv };
  clearCache(); // per-isolate kv cache would otherwise leak state between tests
  resetSettingsCache();
  resetLoginLimiter();
  const s = await settingsFor(env); // materialises defaults in kv
  base = `/${s.adminPath}/api`;
});

describe('bootstrap + auth', () => {
  it('requires setup before anything else', async () => {
    const r = await call('/session');
    assert.equal(r.status, 200);
    assert.equal(r.body.setupRequired, true);
    assert.equal(r.body.authed, false);
    const users = await call('/users');
    assert.equal(users.status, 401);
  });

  it('setup rejects weak passwords and is one-shot', async () => {
    const weak = await call('/setup', { method: 'POST', body: JSON.stringify({ password: 'short' }) });
    assert.equal(weak.status, 400);

    const good = await call('/setup', { method: 'POST', body: JSON.stringify({ password: 'correct horse battery' }) });
    assert.equal(good.status, 201);
    assert.ok(good.cookie, 'setup must set the session cookie');

    const again = await call('/setup', { method: 'POST', body: JSON.stringify({ password: 'attacker password' }) });
    assert.equal(again.status, 409);
  });

  it('login accepts the right password and rejects wrong ones', async () => {
    await call('/setup', { method: 'POST', body: JSON.stringify({ password: 'correct horse battery' }) });
    const bad = await call('/login', { method: 'POST', body: JSON.stringify({ password: 'wrong wrong wrong' }) });
    assert.equal(bad.status, 401);
    const ok = await call('/login', { method: 'POST', body: JSON.stringify({ password: 'correct horse battery' }) });
    assert.equal(ok.status, 200);
    assert.ok(ok.cookie);
  });

  it('rate-limits repeated login failures', async () => {
    await call('/setup', { method: 'POST', body: JSON.stringify({ password: 'correct horse battery' }) });
    let limited = false;
    for (let i = 0; i < 14; i++) {
      const r = await call('/login', { method: 'POST', body: JSON.stringify({ password: 'wrong wrong wrong' }) });
      if (r.status === 429) {
        limited = true;
        break;
      }
    }
    assert.equal(limited, true, 'expected a 429 within 14 bad attempts');
  });

  it('logout invalidates the session', async () => {
    const setup = await call('/setup', { method: 'POST', body: JSON.stringify({ password: 'correct horse battery' }) });
    const out = await call('/logout', { method: 'POST', cookie: setup.cookie, body: '{}' });
    assert.equal(out.status, 200);
    const after = await call('/users', { cookie: setup.cookie });
    assert.equal(after.status, 401);
  });

  it('unknown admin path is a plain 404', async () => {
    const setup = await call('/setup', { method: 'POST', body: JSON.stringify({ password: 'correct horse battery' }) });
    const r = await call('/definitely-not-here', { cookie: setup.cookie });
    assert.equal(r.status, 404);
  });
});

describe('users + settings + logs', () => {
  let cookie = '';

  beforeEach(async () => {
    const setup = await call('/setup', { method: 'POST', body: JSON.stringify({ password: 'correct horse battery' }) });
    cookie = setup.cookie;
  });

  it('creates, lists, updates and deletes users', async () => {
    const create = await call('/users', {
      method: 'POST',
      cookie,
      body: JSON.stringify({ name: 'ali', limitBytes: 5 * 1024 ** 3, limitDays: 30 }),
    });
    assert.equal(create.status, 201);
    assert.equal(create.body.user.name, 'ali');
    assert.equal(create.body.user.enabled, true);
    assert.ok(create.body.user.token, 'token is required for subscription links');
    assert.match(create.body.user.uuid, /^[0-9a-f-]{36}$/);

    const list = await call('/users', { cookie });
    assert.equal(list.status, 200);
    assert.equal(list.body.users.length, 1);

    const id = create.body.user.id as string;
    const updated = await call(`/users/${id}`, {
      method: 'PUT',
      cookie,
      body: JSON.stringify({ name: 'renamed', enabled: false }),
    });
    assert.equal(updated.status, 200);
    assert.equal(updated.body.user.name, 'renamed');
    assert.equal(updated.body.user.enabled, false);

    const reset = await call(`/users/${id}/reset`, { method: 'POST', cookie, body: '{}' });
    assert.equal(reset.status, 200);

    const del = await call(`/users/${id}`, { method: 'DELETE', cookie });
    assert.equal(del.status, 200);
    assert.equal((await call('/users', { cookie })).body.users.length, 0);
  });

  it('rejects invalid user payloads', async () => {
    const badUuid = await call('/users', { method: 'POST', cookie, body: JSON.stringify({ uuid: 'nope' }) });
    assert.equal(badUuid.status, 400);
    const badDays = await call('/users', {
      method: 'POST',
      cookie,
      body: JSON.stringify({ name: 'x', limitDays: -3 }),
    });
    assert.equal(badDays.status, 400);
    const missing = await call('/users/00000000', { method: 'DELETE', cookie });
    assert.equal(missing.status, 404);
  });

  it('reports stats in the overview', async () => {
    await call('/users', { method: 'POST', cookie, body: JSON.stringify({ name: 'a' }) });
    const ov = await call('/overview', { cookie });
    assert.equal(ov.status, 200);
    assert.equal(ov.body.stats.total, 1);
    assert.equal(ov.body.stats.active, 1);
    assert.equal(typeof ov.body.stats.online, 'number');
  });

  it('validates settings', async () => {
    const badPath = await call('/settings', { method: 'PUT', cookie, body: JSON.stringify({ wsPath: 'no-slash' }) });
    assert.equal(badPath.status, 400);

    const leak = await call('/settings', {
      method: 'PUT',
      cookie,
      body: JSON.stringify({ allowPrivateDest: true }),
    });
    assert.equal(leak.status, 400);
    assert.match(leak.body.error, /cannot be enabled/);

    const badCamo = await call('/settings', {
      method: 'PUT',
      cookie,
      body: JSON.stringify({ camoUrl: 'http://insecure.example' }),
    });
    assert.equal(badCamo.status, 400);

    const good = await call('/settings', {
      method: 'PUT',
      cookie,
      body: JSON.stringify({ theme: 'light', brand: 'TestBrand' }),
    });
    assert.equal(good.status, 200);
    assert.equal(good.body.settings.theme, 'light');
    assert.equal(good.body.settings.allowPrivateDest, false);
  });

  it('persists settings across requests', async () => {
    await call('/settings', { method: 'PUT', cookie, body: JSON.stringify({ brand: 'Persisted' }) });
    resetSettingsCache();
    const s = await settingsFor(env);
    assert.equal(s.brand, 'Persisted');
  });

  it('rotates the tunnel path', async () => {
    const before = (await call('/settings', { cookie })).body.settings.wsPath;
    const r = await call('/rotate', { method: 'POST', cookie, body: '{}' });
    assert.equal(r.status, 200);
    assert.ok(r.body.settings.wsPath.startsWith('/'));
    assert.notEqual(r.body.settings.wsPath, before);
  });

  it('changes the admin password', async () => {
    const wrong = await call('/password', {
      method: 'PUT',
      cookie,
      body: JSON.stringify({ current: 'not the password', next: 'another password' }),
    });
    assert.equal(wrong.status, 401);
    const ok = await call('/password', {
      method: 'PUT',
      cookie,
      body: JSON.stringify({ current: 'correct horse battery', next: 'a brand new password' }),
    });
    assert.equal(ok.status, 200);
    const relogin = await call('/login', { method: 'POST', body: JSON.stringify({ password: 'a brand new password' }) });
    assert.equal(relogin.status, 200);
  });

  it('returns logs', async () => {
    const r = await call('/logs', { cookie });
    assert.equal(r.status, 200);
    assert.ok(Array.isArray(r.body.logs));
  });
});

describe('default settings', () => {
  it('are leak-free and sane', () => {
    const s = defaultSettings();
    assert.equal(s.allowPrivateDest, false);
    assert.equal(s.portalEnabled, true);
    assert.ok(!s.adminPath.includes('/'));
    assert.ok(s.wsPath.startsWith('/'));
    assert.equal(s.adminPassHash, '');
    assert.ok(s.mode === 'a' || s.mode === 'b' || s.mode === 'both');
  });
});


describe('security regressions (audit)', () => {
  async function setup(): Promise<string> {
    const r = await call('/setup', { method: 'POST', body: JSON.stringify({ password: 'correct horse battery' }) });
    assert.equal(r.status, 201);
    return r.cookie;
  }

  it('GET settings never exposes the password hash', async () => {
    const cookie = await setup();
    const r = await call('/settings', { cookie });
    assert.equal(r.status, 200);
    assert.equal(r.body.settings.adminPassHash, undefined);
  });

  it('PUT settings cannot overwrite the password hash', async () => {
    const cookie = await setup();
    const before = (await call('/settings', { cookie })).body.settings;
    const r = await call('/settings', {
      method: 'PUT',
      cookie,
      body: JSON.stringify({ brand: 'AzadX', adminPassHash: '' }),
    });
    assert.equal(r.status, 200);
    const after = (await call('/settings', { cookie })).body.settings;
    assert.equal(after.brand, 'AzadX');
    assert.equal(after.adminPassHash, undefined);
    // the original password must still authenticate
    const login = await call('/login', { method: 'POST', body: JSON.stringify({ password: 'correct horse battery' }) });
    assert.equal(login.status, 200);
  });

  it('rejects an empty egress port list (would mean ANY port)', async () => {
    const cookie = await setup();
    const r = await call('/settings', { method: 'PUT', cookie, body: JSON.stringify({ egressPorts: [] }) });
    assert.equal(r.status, 400);
  });

  it('rejects a cross-origin state-changing request', async () => {
    const cookie = await setup();
    const r = await call('/settings', {
      method: 'PUT',
      cookie,
      headers: { origin: 'http://evil.test' },
      body: JSON.stringify({ brand: 'Hacked' }),
    });
    assert.equal(r.status, 403);
    const after = await call('/settings', { cookie });
    assert.equal(after.body.settings.brand, 'Azad'); // unchanged
  });

  it('does not disclose the brand before login', async () => {
    const r = await call('/session');
    assert.equal(r.status, 200);
    assert.equal(r.body.brand, undefined);
    assert.equal(r.body.setupRequired, true);
  });

  it('accepts maxConns 0 as "use panel default"', async () => {
    const cookie = await setup();
    const r = await call('/users', {
      method: 'POST',
      cookie,
      body: JSON.stringify({ name: 'defconn', maxConns: 0 }),
    });
    assert.equal(r.status, 201);
    assert.equal(r.body.user.maxConns, null);
  });
});
