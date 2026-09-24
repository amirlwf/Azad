import { randomHex } from './codecs.ts';
import { checkDestination, type GuardResult } from './guard.ts';
import { DEFAULT_EGRESS_PORTS } from './guard.ts';
import { cachedGet, clearCache, getKV, writeJSON, type Env, type KVLike } from './store.ts';
import { hashPassword } from './auth.ts';

export const SETTINGS_KEY = 'settings';

export interface Settings {
  brand: string;
  /** admin panel base path (secret, shown in the panel) */
  adminPath: string;
  /** subscription base path (secret, per-panel) */
  subPath: string;
  /** websocket path of the tunnel */
  wsPath: string;
  /** pbkdf2 hash, format: pbkdf2$<saltHex>$<hashHex>; empty => first-run setup */
  adminPassHash: string;
  /** bumped on password change: orphan every session issued before it */
  sessionEpoch: number;
  /** protocol selection: a = vless-only, b = trojan-only, both = a+b */
  mode: 'a' | 'b' | 'both';
  /** ports advertised in generated client configs */
  tlsPorts: number[];
  httpPorts: number[];
  /** host used inside generated configs; empty = use the request host */
  host: string;
  /** ws early-data (?ed=) advertised to clients */
  earlyData: number;
  /** client TLS fingerprint hint: chrome | firefox | safari | edge | ios */
  fingerprint: string;
  /** fallback proxies used when a direct connect yields no data */
  proxyIPs: string[];
  /** allowed destination ports inside the tunnel (empty = unrestricted) */
  egressPorts: number[];
  /** dev/test only — must stay false in production */
  allowPrivateDest: boolean;
  maxConnsPerUser: number;
  /** new websocket upgrades allowed per minute per client IP */
  maxUpgradesPerMinute: number;
  /** bytes a user may transfer (per user record overrides this) */
  defaultLimitBytes: number;
  /** default account lifetime in days (null = unlimited) */
  defaultExpiryDays: number | null;
  /** camouflage: proxy unknown paths to this origin; empty = local fake page */
  camoUrl: string;
  /** hide subscription from browser UAs (portal page shown instead) */
  portalEnabled: boolean;
}

export function defaultSettings(env: { BRAND?: string; LOCAL_TEST?: string } = {}): Settings {
  // LOCAL_TEST is a wrangler-dev switch only (--var LOCAL_TEST:1): it makes the
  // random paths deterministic so the e2e suite can find the panel and the
  // tunnel. It is never set in production, where paths stay random.
  const dev = env.LOCAL_TEST === '1';
  return {
    brand: env.BRAND || 'Azad',
    adminPath: dev ? 'console-dev' : `console-${randomHex(4)}`,
    subPath: dev ? 'get-dev' : `get-${randomHex(4)}`,
    wsPath: dev ? '/devws1234567890' : `/${randomHex(12)}`,
    adminPassHash: '',
    sessionEpoch: 0,
    mode: 'both',
    tlsPorts: [443],
    httpPorts: [80, 8080, 8880, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096],
    host: '',
    earlyData: 2560,
    fingerprint: 'chrome',
    proxyIPs: [],
    egressPorts: [...DEFAULT_EGRESS_PORTS],
    allowPrivateDest: false,
    // <= ISOLATE_BUDGET (5): Cloudflare caps an invocation at 6 outbound
    // sockets and one is kept free for DoH
    maxConnsPerUser: 5,
    maxUpgradesPerMinute: 30,
    defaultLimitBytes: 0, // 0 = unlimited
    defaultExpiryDays: null,
    camoUrl: '',
    portalEnabled: true,
  };
}

export type { Env, KVLike };

/**
 * The single gate every tunnel destination passes through.
 * `LOCAL_TEST=1` (wrangler dev only) relaxes the loopback rule so the e2e
 * suite can dial a local echo server; cloud metadata stays blocked even then.
 */
export function egressAllowed(
  env: Env,
  s: Settings,
  host: string,
  port: number,
  anyPort = false,
): GuardResult {
  const dev = env.LOCAL_TEST === '1';
  const allowPrivate = s.allowPrivateDest || dev;
  // dev mode also lifts the port allow-list so the e2e echo server can listen on
  // an ephemeral port; blocked *hostnames* (cloud metadata) still apply.
  const ports = dev || anyPort ? [] : s.egressPorts;
  return checkDestination(host, port, { ports, allowPrivate });
}

export async function loadSettings(env: Env): Promise<Settings> {
  const kv = getKV(env);
  const existing = await cachedGet<Settings>(kv, SETTINGS_KEY, 30_000);
  const base = defaultSettings(env);

  if (!existing) {
    const merged = { ...base };
    // bootstrap admin password from the environment on very first boot
    if (env.ADMIN_PASSWORD && !merged.adminPassHash) {
      merged.adminPassHash = await hashPassword(env.ADMIN_PASSWORD);
    }
    await writeJSON(kv, SETTINGS_KEY, merged);
    return merged;
  }

  const merged: Settings = { ...base, ...existing };
  if (env.ADMIN_PASSWORD && !merged.adminPassHash) {
    merged.adminPassHash = await hashPassword(env.ADMIN_PASSWORD);
    await writeJSON(kv, SETTINGS_KEY, merged);
  }
  return merged;
}

/**
 * Deliberately NOT memoised forever: the 30s cachedGet window inside
 * loadSettings is the only cache, so security changes (path rotation, port
 * rules) reach every isolate within ~30s and a transient KV failure cannot
 * poison an isolate with a permanently rejected promise.
 */
export function settingsFor(env: Env): Promise<Settings> {
  return loadSettings(env);
}

export async function saveSettings(env: Env, settings: Settings): Promise<void> {
  await writeJSON(getKV(env), SETTINGS_KEY, settings);
  clearCache();
}

export function resetSettingsCache(): void {
  clearCache();
}
