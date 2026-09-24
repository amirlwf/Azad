import {
  createSession,
  destroySession,
  hashPassword,
  parseCookie,
  validSession,
  verifyPassword,
} from '../core/auth.ts';
import { isValidUUID, randomHex } from '../core/codecs.ts';
import { pushLog, readLogs } from '../core/log.ts';
import { resetSettingsCache, saveSettings, type Env, type Settings } from '../core/settings.ts';
import {
  createUser,
  deleteUser,
  getUser,
  listUsers,
  putUser,
  userState,
  type User,
} from '../core/users.ts';
import { checkDestination, isIPv4, isPrivateIPv4, isPrivateIPv6, RateLimiter } from '../core/guard.ts';
import { tunnelStats } from '../core/stats.ts';

const SESSION_COOKIE = 'azad_sid';

/** per-IP brute-force shield for the admin login (10 tries / minute) */
const loginLimiter = new RateLimiter(10, 60_000);

/** test hook: clear the in-memory login limiter */
export function resetLoginLimiter(): void {
  (loginLimiter as unknown as { hits: Map<string, unknown> }).hits.clear();
}

const json = (data: unknown, status = 200, extra?: Record<string, string>) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      // bodies include subscription tokens — never cache them
      'cache-control': 'no-store',
      ...extra,
    },
  });

const fail = (msg: string, status = 400) => json({ ok: false, error: msg }, status);

export interface AdminRequest {
  env: Env;
  request: Request;
  url: URL;
  settings: Settings;
  authed: boolean;
}

export async function isAuthed(env: Env, request: Request): Promise<boolean> {
  const token =
    request.headers.get('x-session') || parseCookie(request.headers.get('cookie'), SESSION_COOKIE);
  return validSession(env, token);
}

export function sessionCookie(token: string, secure: boolean): string {
  const attrs = [
    `${SESSION_COOKIE}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${12 * 3600}`,
  ];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}

export function clearCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
}

export async function handleAdminApi(ctx: AdminRequest): Promise<Response> {
  const { env, request, url } = ctx;
  const method = request.method.toUpperCase();
  const path = url.pathname.replace(`${ctx.settings.adminPath}/api`, '').replace(/^\/+/, '');

  // CSRF: browsers attach Origin to cross-site state-changing requests.
  // (non-browser clients send no Origin and are unaffected)
  if (method !== 'GET' && method !== 'HEAD') {
    const origin = request.headers.get('origin');
    if (origin && origin !== url.origin) return fail('cross-origin request rejected', 403);
  }

  // ---- public: login -----------------------------------------------------
  if (path === 'login' && method === 'POST') {
    const ip = request.headers.get('cf-connecting-ip') ?? 'unknown';
    if (!loginLimiter.hit(`login:${ip}`, Date.now())) {
      return fail('too many attempts, try again later', 429);
    }
    let body: { password?: string };
    try {
      body = (await request.json()) as { password?: string };
    } catch {
      return fail('bad request');
    }
    if (!body.password || !(await verifyPassword(body.password, ctx.settings.adminPassHash))) {
      await pushLog(env, 'auth', 'failed admin login');
      return fail('invalid password', 401);
    }
    const token = await createSession(env);
    await pushLog(env, 'auth', 'admin logged in');
    const secure = url.protocol === 'https:';
    return json(
      { ok: true, token },
      200,
      { 'set-cookie': sessionCookie(token, secure) },
    );
  }

  if (path === 'session' && method === 'GET') {
    const body: Record<string, unknown> = {
      ok: true,
      authed: ctx.authed,
      setupRequired: !ctx.settings.adminPassHash,
    };
    if (ctx.authed) body.brand = ctx.settings.brand;
    return json(body);
  }

  // first boot: define the admin password before anything else works
  if (path === 'setup' && method === 'POST') {
    if (ctx.settings.adminPassHash) return fail('already initialized', 409);
    // unauthenticated until this lands: same brute-force shield as /login
    const sip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!loginLimiter.hit(`setup:${sip}`)) return fail('too many attempts', 429);
    let body: { password?: string };
    try {
      body = (await request.json()) as { password?: string };
    } catch {
      return fail('bad request');
    }
    if (!body.password || body.password.length < 8) return fail('password too short (min 8)');
    if (body.password.length > 256) return fail('password too long');
    const hash = await hashPassword(body.password);
    await saveSettings(env, { ...ctx.settings, adminPassHash: hash });
    resetSettingsCache();
    await pushLog(env, 'auth', 'initial admin password set');
    const token = await createSession(env);
    const secure = url.protocol === 'https:';
    return json({ ok: true, token }, 201, { 'set-cookie': sessionCookie(token, secure) });
  }

  if (path === 'logout' && method === 'POST') {
    const token =
      request.headers.get('x-session') || parseCookie(request.headers.get('cookie'), SESSION_COOKIE);
    await destroySession(env, token);
    return json({ ok: true }, 200, { 'set-cookie': clearCookie() });
  }

  if (!ctx.authed) return fail('unauthorized', 401);

  // ---- authenticated -----------------------------------------------------
  if (path === 'overview' && method === 'GET') return adminOverview(env);
  if (path === 'users' && method === 'GET') return json({ ok: true, users: await listUsers(env) });
  if (path === 'logs' && method === 'GET') return json({ ok: true, logs: await readLogs(env) });

  if (path === 'users' && method === 'POST') {
    let body: Record<string, unknown>;
    try {
      body = (await request.json()) as Record<string, unknown>;
    } catch {
      return fail('bad request');
    }
    const uuid = typeof body.uuid === 'string' && body.uuid ? body.uuid : undefined;
    if (uuid && !isValidUUID(uuid)) return fail('invalid uuid');
    const invalid = validateUserPatch(body);
    if (invalid) return fail(invalid);
    if (body.expires === undefined && typeof body.limitDays === 'number') {
      body.expires = Date.now() + Number(body.limitDays) * 86400000;
    }
    const user = await createUser(env, {
      name: typeof body.name === 'string' ? body.name : undefined,
      uuid,
      enabled: body.enabled !== false,
      expires:
        body.expires !== undefined || body.limitDays !== undefined
          ? normalizeExpiry(body.expires)
          : ctx.settings.defaultExpiryDays
            ? Date.now() + ctx.settings.defaultExpiryDays * 86_400_000
            : normalizeExpiry(undefined),
      limitBytes:
        body.limitBytes !== undefined
          ? normalizeLimit(body.limitBytes)
          : ctx.settings.defaultLimitBytes || normalizeLimit(undefined),
      maxConns: normalizeConns(body.maxConns),
      note: typeof body.note === 'string' ? body.note : undefined,
    });
    await putUser(env, user);
    await pushLog(env, 'user', `created ${user.name}`);
    return json({ ok: true, user }, 201);
  }

  const userMatch = path.match(/^users\/([0-9a-f]{8,32})$/);
  if (userMatch) {
    const id = userMatch[1];
    const user = await getUser(env, id);
    if (!user) return fail('not found', 404);

    if (method === 'PUT' || method === 'PATCH') {
      let body: Record<string, unknown>;
      try {
        body = (await request.json()) as Record<string, unknown>;
      } catch {
        return fail('bad request');
      }
      const invalid = validateUserPatch(body);
      if (invalid) return fail(invalid);
      applyUserPatch(user, body);
      await putUser(env, user);
      await pushLog(env, 'user', `updated ${user.name}`);
      return json({ ok: true, user });
    }
    if (method === 'DELETE') {
      await deleteUser(env, id);
      await pushLog(env, 'user', `deleted ${user.name}`);
      return json({ ok: true });
    }
  }

  const resetMatch = path.match(/^users\/([0-9a-f]{8,32})\/reset$/);
  if (resetMatch && method === 'POST') {
    const user = await getUser(env, resetMatch[1]);
    if (!user) return fail('not found', 404);
    user.usedUp = 0;
    user.usedDown = 0;
    await putUser(env, user);
    return json({ ok: true, user });
  }

  if (path === 'settings' && method === 'GET') {
    const { adminPassHash: _omit, ...safe } = ctx.settings;
    void _omit;
    return json({ ok: true, settings: safe });
  }
  if (path === 'settings' && method === 'PUT') {
    let body: Partial<Settings>;
    try {
      body = (await request.json()) as Partial<Settings>;
    } catch {
      return fail('bad request');
    }
    // adminPassHash is not a user-editable field: accepting it would let a
    // session holder reset the password (or fall back to first-run setup)
    delete (body as Record<string, unknown>).adminPassHash;
    const next = validateSettings(ctx.settings, body);
    if ('error' in next) return fail((next as { error: string }).error);
    await saveSettings(env, next as Settings);
    resetSettingsCache();
    await pushLog(env, 'sys', 'settings updated');
    const { adminPassHash: _h, ...safeNext } = next;
    void _h;
    return json({ ok: true, settings: safeNext });
  }

  if (path === 'password' && method === 'PUT') {
    let body: { current?: string; next?: string };
    try {
      body = (await request.json()) as { current?: string; next?: string };
    } catch {
      return fail('bad request');
    }
    if (!body.current || !(await verifyPassword(body.current, ctx.settings.adminPassHash))) {
      return fail('wrong current password', 401);
    }
    if (!body.next || body.next.length < 8) return fail('password too short (min 8)');
    const hash = await hashPassword(body.next);
    const next = { ...ctx.settings, adminPassHash: hash };
    await saveSettings(env, next);
    resetSettingsCache();
    return json({ ok: true });
  }

  if (path === 'rotate' && method === 'POST') {
    // rotate the tunnel path (cheap mitigation when a path leaks)
    const next: Settings = { ...ctx.settings, wsPath: `/${randomHex(12)}` };
    await saveSettings(env, next);
    resetSettingsCache();
    await pushLog(env, 'sys', 'tunnel path rotated');
    const { adminPassHash: _h, ...safeNext } = next;
    void _h;
    return json({ ok: true, settings: safeNext });
  }

  if (path === 'diagnose' && method === 'GET') {
    return json({ ok: true, report: await diagnose(env, ctx.settings) });
  }

  return fail('not found', 404);
}

async function adminOverview(env: Env) {
  const users = await listUsers(env);
  const now = Date.now();
  let active = 0;
  let disabled = 0;
  let expired = 0;
  let overQuota = 0;
  let up = 0;
  let down = 0;
  for (const u of users) {
    up += u.usedUp;
    down += u.usedDown;
    const st = userState(u, now);
    if (st === 'active') active++;
    else if (st === 'disabled') disabled++;
    else if (st === 'expired') expired++;
    else overQuota++;
  }
  return json({
    ok: true,
    stats: {
      total: users.length,
      active,
      disabled,
      expired,
      overQuota,
      usedUp: up,
      usedDown: down,
      online: tunnelStats.total,
    },
  });
}

/** strict validation for user payloads — garbage must be a 400, never silently coerced */
function validateUserPatch(body: Record<string, unknown>): string | null {
  if ('limitBytes' in body && body.limitBytes !== null && body.limitBytes !== undefined) {
    const n = Number(body.limitBytes);
    if (!Number.isFinite(n) || n < 0) return 'limitBytes must be a non-negative number';
  }
  if ('limitDays' in body && body.limitDays !== null && body.limitDays !== undefined && body.limitDays !== '') {
    const d = Number(body.limitDays);
    if (!Number.isInteger(d) || d < 1 || d > 3650) return 'limitDays must be an integer in 1..3650';
  }
  if ('expires' in body && body.expires !== null && body.expires !== undefined && body.expires !== '' && body.expires !== 0) {
    const n = Number(body.expires);
    if (!Number.isFinite(n) || n < 0) return 'expires must be a timestamp or 0';
  }
  if ('enabled' in body && typeof body.enabled !== 'boolean') return 'enabled must be a boolean';
  if ('name' in body && typeof body.name !== 'string') return 'name must be a string';
  if ('maxConns' in body && body.maxConns !== null && body.maxConns !== undefined && body.maxConns !== 0 && body.maxConns !== '') {
    const c = Number(body.maxConns);
    // 0 / null mean "inherit the panel default" (panel modal sends 0)
    if (!Number.isInteger(c) || c < 1 || c > 100) return 'maxConns must be an integer in 1..100';
  }
  return null;
}

function normalizeExpiry(v: unknown): number | null {
  if (v === null || v === undefined || v === '' || v === 0 || v === '0') return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  // accept both seconds and milliseconds
  return n > 1e12 ? n : n * 1000;
}

function normalizeLimit(v: unknown): number {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

function normalizeConns(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.min(100, Math.floor(n));
}

function applyUserPatch(user: User, body: Record<string, unknown>): void {
  if (typeof body.name === 'string' && body.name.trim()) user.name = body.name.trim().slice(0, 64);
  if (typeof body.note === 'string') user.note = body.note.slice(0, 200);
  if (typeof body.enabled === 'boolean') user.enabled = body.enabled;
  if ('expires' in body) user.expires = normalizeExpiry(body.expires);
  if ('limitBytes' in body) user.limitBytes = normalizeLimit(body.limitBytes);
  if ('maxConns' in body) user.maxConns = normalizeConns(body.maxConns);
  if (typeof body.uuid === 'string' && isValidUUID(body.uuid)) user.uuid = body.uuid.toLowerCase();
}

export function validateSettings(base: Settings, patch: Partial<Settings>): Settings | { error: string } {
  const next: Settings = { ...base, ...patch };

  if (typeof next.brand !== 'string' || !next.brand.trim() || next.brand.length > 32) {
    return { error: 'brand must be 1..32 chars' };
  }
  if (!/^\/[0-9a-zA-Z_-]{8,64}$/.test(next.wsPath)) {
    return { error: 'wsPath must be /<8..64 url-safe chars>' };
  }
  if (!/^[0-9a-zA-Z_-]{4,64}$/.test(next.adminPath)) {
    return { error: 'adminPath must be 4..64 url-safe chars' };
  }
  if (!/^[0-9a-zA-Z_-]{4,64}$/.test(next.subPath)) {
    return { error: 'subPath must be 4..64 url-safe chars' };
  }
  if (!['a', 'b', 'both'].includes(next.mode)) return { error: 'invalid mode' };
  if (!['chrome', 'firefox', 'safari', 'edge', 'ios'].includes(next.fingerprint)) {
    return { error: 'invalid fingerprint' };
  }
  if (!Array.isArray(next.tlsPorts) || next.tlsPorts.length === 0) {
    return { error: 'at least one tls port required' };
  }
  if (!Array.isArray(next.httpPorts)) return { error: 'httpPorts must be a list' };
  if (next.host && !/^[a-z0-9.-]+$/i.test(next.host)) return { error: 'invalid host' };
  if (!Number.isInteger(next.earlyData) || next.earlyData < 0 || next.earlyData > 8192) {
    return { error: 'earlyData must be 0..8192' };
  }
  for (const p of [...next.tlsPorts, ...next.httpPorts]) {
    if (!Number.isInteger(p) || p < 1 || p > 65535) return { error: 'invalid port' };
  }
  if (!Array.isArray(next.proxyIPs) || next.proxyIPs.length > 20) return { error: 'too many proxy IPs' };
  for (const entry of next.proxyIPs) {
    // fallback proxies are dialed during retry — they must pass the same
    // destination guard as the original target, not skip it
    const m = /^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/.exec(entry);
    if (!m) return { error: `invalid proxy entry: ${entry}` };
    const host = m[1] || m[2];
    const port = Number(m[3]);
    const g = checkDestination(host, port, { ports: next.egressPorts, allowPrivate: false });
    if (!g.ok) return { error: `proxy entry not allowed (${g.reason}): ${entry}` };
  }
  if (next.egressPorts.length === 0) {
    // guard.ts treats an empty list as "any port" — that is a full open proxy
    return { error: 'egressPorts must not be empty (empty list means ANY port)' };
  }
  for (const p of next.egressPorts) {
    if (!Number.isInteger(p) || p < 1 || p > 65535) return { error: 'invalid egress port' };
  }
  if (!Number.isInteger(next.maxConnsPerUser) || next.maxConnsPerUser < 1 || next.maxConnsPerUser > 100) {
    return { error: 'maxConnsPerUser must be an integer 1..100' };
  }
  if (!Number.isInteger(next.maxUpgradesPerMinute) || next.maxUpgradesPerMinute < 1 || next.maxUpgradesPerMinute > 600) {
    return { error: 'maxUpgradesPerMinute must be an integer 1..600' };
  }
  if (next.allowPrivateDest) {
    // hard block: private egress is the open-proxy pattern that gets accounts banned
    return { error: 'allowPrivateDest cannot be enabled' };
  }
  if (next.camoUrl && !/^https:\/\/[a-z0-9.-]+/i.test(next.camoUrl)) {
    return { error: 'camoUrl must be an https origin' };
  }
  return next;
}

async function diagnose(env: Env, s: Settings) {
  void env;
  const report: Record<string, unknown> = {
    brand: s.brand,
    host: s.host || '(request host)',
    wsPath: s.wsPath,
    mode: s.mode,
    ports: { tls: s.tlsPorts, http: s.httpPorts },
    fingerprint: s.fingerprint,
    earlyData: s.earlyData,
    proxyIPs: s.proxyIPs.length,
    egressPorts: s.egressPorts,
    guards: {
      privateDestinations: s.allowPrivateDest ? 'ALLOWED (danger)' : 'blocked',
      upgradesPerMinute: s.maxUpgradesPerMinute,
      connsPerUser: s.maxConnsPerUser,
    },
  };

  const results: { name: string; url: string; ok: boolean; ms: number; note?: string }[] = [];
  const start = Date.now();
  try {
    const res = await fetch('https://speed.cloudflare.com/__down?bytes=64');
    results.push({
      name: 'egress',
      url: 'https://speed.cloudflare.com/__down?bytes=64',
      ok: res.ok,
      ms: Date.now() - start,
      note: `status ${res.status}`,
    });
  } catch (err) {
    results.push({
      name: 'egress',
      url: 'speed.cloudflare.com',
      ok: false,
      ms: Date.now() - start,
      note: String(err).slice(0, 100),
    });
  }
  report.tests = results;
  return report;
  }

  export { isIPv4, isPrivateIPv4, isPrivateIPv6 };
