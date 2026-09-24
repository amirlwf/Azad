import { randomHex } from './codecs.ts';
import { getKV, readJSON, writeJSON, type Env, type KVLike } from './store.ts';

export type LogKind = 'auth' | 'tunnel' | 'guard' | 'user' | 'sys';

export interface LogEntry {
  t: number;
  k: LogKind;
  m: string;
}

const LOG_KEY = 'logs';
const MAX = 200;

/**
 * Ring buffer of the last MAX events in one KV key. Writes are cheap because
 * the hot path (tunnel traffic) never logs per-packet — only handshakes,
 * blocks and admin actions.
 */
export async function pushLog(env: Env, kind: LogKind, message: string): Promise<void> {
  const kv = getKV(env);
  try {
    const current = (await readJSON<LogEntry[]>(kv, LOG_KEY)) || [];
    current.push({ t: Date.now(), k: kind, m: message.slice(0, 300) });
    while (current.length > MAX) current.shift();
    await writeJSON(kv, LOG_KEY, current);
  } catch {
    // logging must never break the request
    void kv;
  }
}

export async function readLogs(env: Env): Promise<LogEntry[]> {
  return (await readJSON<LogEntry[]>(getKV(env), LOG_KEY)) || [];
}

export { randomHex };
export type { KVLike };
