import { randomHex } from './codecs.ts';
import { getKV, readJSON, writeJSON, type Env } from './store.ts';
import { settingsFor } from './settings.ts';

/**
 * Admin authentication: PBKDF2-SHA256 password hash (WebCrypto only, no
 * dependency) + opaque session tokens stored in KV with a TTL.
 */

const ITERATIONS = 100_000;
const SESSION_TTL = 12 * 3600; // seconds

function hex(buf: ArrayBufferLike): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

function unhex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as unknown as BufferSource, iterations },
    key,
    256,
  );
  return new Uint8Array(bits);
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derived = await pbkdf2(password, salt, ITERATIONS);
  return `pbkdf2$${hex(salt.buffer)}$${hex(derived.buffer)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 3 || parts[0] !== 'pbkdf2') return false;
  try {
    const salt = unhex(parts[1]);
    const expected = unhex(parts[2]);
    const derived = await pbkdf2(password, salt, ITERATIONS);
    if (derived.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < derived.length; i++) diff |= derived[i] ^ expected[i];
    return diff === 0;
  } catch {
    return false;
  }
}

interface Session {
  exp: number;
}

const sessKey = (t: string, epoch: number) => `s:${epoch}:${t}`;

async function epoch(env: Env): Promise<number> {
  return (await settingsFor(env)).sessionEpoch || 0;
}

export async function createSession(env: Env): Promise<string> {
  const token = randomHex(24);
  const kv = getKV(env);
  await writeJSON(kv, sessKey(token, await epoch(env)), { exp: Date.now() + SESSION_TTL * 1000 } satisfies Session, {
    expirationTtl: SESSION_TTL,
  });
  return token;
}

export async function validSession(env: Env, token: string | null): Promise<boolean> {
  if (!token || !/^[0-9a-f]{48}$/.test(token)) return false;
  // keyed by the current epoch: a password change orphans every old session
  const sess = await readJSON<Session>(getKV(env), sessKey(token, await epoch(env)));
  if (!sess) return false;
  if (sess.exp <= Date.now()) {
    await getKV(env).delete(sessKey(token, await epoch(env)));
    return false;
  }
  return true;
}

export async function destroySession(env: Env, token: string | null): Promise<void> {
  if (token) await getKV(env).delete(sessKey(token, await epoch(env)));
}

export function parseCookie(header: string | null, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) {
      try {
        return decodeURIComponent(v.join('='));
      } catch {
        return null; // %zz garbage must not escape into a 503
      }
    }
  }
  return null;
}

/** bootstraps the admin password from env on an instance that has none */
export async function ensureAdmin(env: Env, storedHash: string): Promise<string> {
  if (storedHash) return storedHash;
  if (env.ADMIN_PASSWORD) return hashPassword(env.ADMIN_PASSWORD);
  return '';
}

export type { KVLike } from './store.ts';
