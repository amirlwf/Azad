import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { listUsers } from '../src/core/users.ts';
import { clearCache, type KVLike } from '../src/core/store.ts';
import { resetSettingsCache } from '../src/core/settings.ts';

function mockKV(): KVLike {
  const store = new Map<string, string>();
  return {
    async get(k: string) { return store.has(k) ? (store.get(k) as string) : null; },
    async put(k: string, v: string) { store.set(k, v); },
    async delete(k: string) { store.delete(k); },
    async list(opts?: { prefix?: string }) {
      const keys = [...store.keys()].filter((n) => !opts?.prefix || n.startsWith(opts!.prefix));
      return { keys: keys.map((name) => ({ name })), list_complete: true };
    },
  };
}

let env: any;

beforeEach(() => {
  env = { KV: mockKV() };
  clearCache();
  resetSettingsCache();
});

describe('kv isolation', () => {
  it('first test creates a user', async () => {
    const { putUser, makeUser } = await import('../src/core/users.ts');
    await putUser(env, makeUser({ name: 'a' }, 0));
    assert.equal((await listUsers(env)).length, 1);
  });

  it('second test starts empty', async () => {
    const users = await listUsers(env);
    assert.equal(users.length, 0, `expected fresh kv, got ${users.length}`);
  });

  it('third test starts empty too', async () => {
    const users = await listUsers(env);
    assert.equal(users.length, 0, `expected fresh kv, got ${users.length}`);
  });
});
