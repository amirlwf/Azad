import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { defaultSettings, settingsFor, resetSettingsCache, egressAllowed, type Env } from '../src/core/settings.ts';
import { clearCache, type KVLike } from '../src/core/store.ts';

function mockKV(): KVLike {
  const store = new Map<string, string>();
  return {
    async get(k: string) { return store.has(k) ? (store.get(k) as string) : null; },
    async put(k: string, v: string) { store.set(k, v); },
    async delete(k: string) { store.delete(k); },
    async list(opts?: { prefix?: string }) {
      const keys = [...store.keys()].filter((n) => !opts?.prefix || n.startsWith(opts.prefix));
      return { keys: keys.map((name) => ({ name })), list_complete: true };
    },
  };
}

beforeEach(() => {
  clearCache();
  resetSettingsCache();
});

describe('LOCAL_TEST dev switch', () => {
  it('seeds deterministic admin/ws/sub paths on first boot', async () => {
    const env = { KV: mockKV(), LOCAL_TEST: '1' } as Env;
    const s = await settingsFor(env);
    assert.equal(s.adminPath, 'console-dev');
    assert.equal(s.wsPath, '/devws1234567890');
    assert.equal(s.subPath, 'get-dev');
  });

  it('keeps random paths when the switch is off (production behaviour)', async () => {
    const s = await settingsFor({ KV: mockKV() } as Env);
    assert.notEqual(s.adminPath, 'console-dev');
    assert.notEqual(s.subPath, 'get-dev');
    assert.match(s.adminPath, /^console-[0-9a-f]{8}$/);
  });

  it('permits loopback egress only when the switch is on', () => {
    const s = defaultSettings();
    const dev = egressAllowed({ LOCAL_TEST: '1' } as Env, s, '127.0.0.1', 9999);
    assert.equal(dev.ok, true, 'dev mode must allow loopback targets for e2e tests');

    const prod = egressAllowed({} as Env, s, '127.0.0.1', 9999);
    assert.equal(prod.ok, false, 'production must never allow loopback');

    // and metadata endpoints stay blocked even in dev
    const meta = egressAllowed({ LOCAL_TEST: '1' } as Env, s, '169.254.169.254', 80);
    assert.equal(meta.ok, false, 'cloud metadata must stay blocked in dev too');
  });
});
