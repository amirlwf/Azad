/**
 * KV helpers: JSON read/write + a per-isolate TTL cache for the hot-path
 * records (settings, users) so a tunnel handshake never waits on KV.
 */

export interface KVLike {
  get(key: string, type?: 'text' | 'json'): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
  list(opts: { prefix?: string; limit?: number; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string }>;
}

interface CacheEntry {
  value: unknown;
  expires: number;
}

const cache = new Map<string, CacheEntry>();
const DEFAULT_TTL = 15_000;

export function clearCache(): void {
  cache.clear();
}

export type Env = {
  KV?: KVLike;
  BRAND?: string;
  ADMIN_PASSWORD?: string;
  /** wrangler-dev only: relax loopback + deterministic paths (see settings.ts) */
  LOCAL_TEST?: string;
};

let memoryFallback: Record<string, string> | null = null;

/** KV is required; a tiny in-memory shim keeps `wrangler dev` bootable while binding is missing. */
function fallbackKV(): KVLike {
  if (!memoryFallback) memoryFallback = {};
  const store = memoryFallback;
  return {
    async get(key) {
      return store[key] ?? null;
    },
    async put(key, value) {
      store[key] = value;
    },
    async delete(key) {
      delete store[key];
    },
    async list({ prefix = '', cursor }: { prefix?: string; cursor?: string }) {
      const all = Object.keys(store).filter((k) => k.startsWith(prefix)).map((name) => ({ name }));
      const start = cursor ? all.findIndex((k) => k.name >= cursor) : 0;
      const page = start < 0 ? [] : all.slice(start, start + 25);
      const next = start < 0 ? undefined : page[page.length - 1]?.name;
      return { keys: page, list_complete: page.length < 25, cursor: next };
    },
  };
}

export function getKV(env: Env): KVLike {
  return env.KV || fallbackKV();
}


export async function cachedGet<T>(kv: KVLike, key: string, ttlMs = DEFAULT_TTL): Promise<T | null> {
  const now = Date.now();
  const hit = cache.get(key);
  if (hit && hit.expires > now) return hit.value as T;
  const raw = await kv.get(key);
  if (raw === null) {
    cache.set(key, { value: null, expires: now + 2_000 });
    return null;
  }
  let parsed: T | null = null;
  try {
    parsed = JSON.parse(raw) as T;
  } catch {
    return null;
  }
  cache.set(key, { value: parsed, expires: now + ttlMs });
  return parsed;
}

export async function readJSON<T>(kv: KVLike, key: string): Promise<T | null> {
  const raw = await kv.get(key);
  if (raw === null) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export async function writeJSON(
  kv: KVLike,
  key: string,
  value: unknown,
  opts?: { expirationTtl?: number },
): Promise<void> {
  await kv.put(key, JSON.stringify(value), opts);
  cache.delete(key);
}
