import { isValidUUID, randomHex, randomUUID } from './codecs.ts';
import { getKV, readJSON, writeJSON, type Env } from './store.ts';

export interface User {
  id: string;
  name: string;
  uuid: string;
  /** subscription token (path segment) */
  token: string;
  enabled: boolean;
  created: number;
  /** expiry epoch ms, null = never */
  expires: number | null;
  /** traffic quota in bytes, 0 = unlimited */
  limitBytes: number;
  usedUp: number;
  usedDown: number;
  /** per-user connection cap override, null = panel default */
  maxConns: number | null;
  note: string;
}

const USER_PREFIX = 'u:';
const idxKey = (id: string) => `${USER_PREFIX}${id}`;

export interface UserInput {
  name?: string;
  uuid?: string;
  enabled?: boolean;
  expires?: number | null;
  limitBytes?: number;
  maxConns?: number | null;
  note?: string;
}

export function makeUser(input: UserInput, settingsLimit: number): User {
  const uuid = input.uuid && isValidUUID(input.uuid) ? input.uuid.toLowerCase() : randomUUID();
  return {
    id: randomHex(8),
    name: (input.name || '').trim().slice(0, 64) || 'user',
    uuid,
    token: randomHex(10),
    enabled: input.enabled !== false,
    created: Date.now(),
    expires: input.expires ?? null,
    limitBytes: typeof input.limitBytes === 'number' ? input.limitBytes : settingsLimit,
    usedUp: 0,
    usedDown: 0,
    maxConns: input.maxConns ?? null,
    note: (input.note || '').slice(0, 200),
  };
}

export async function listUsers(env: Env): Promise<User[]> {
  const kv = getKV(env);
  // paginate: a single list() caps at 1000 keys and would silently drop users
  const names: { name: string }[] = [];
  let cursor: string | undefined;
  do {
    const page = (await kv.list({ prefix: USER_PREFIX, cursor })) as {
      keys: { name: string }[];
      list_complete: boolean;
      cursor?: string;
    };
    names.push(...page.keys);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  const users: User[] = [];
  for (const k of names) {
    const u = await readJSON<User>(kv, k.name);
    // defensive: only accept records that actually look like users
    if (u && typeof u === 'object' && typeof u.uuid === 'string' && typeof u.token === 'string') users.push(u);
  }
  users.sort((a, b) => a.created - b.created);
  return users;
}

export async function getUser(env: Env, id: string): Promise<User | null> {
  return readJSON<User>(getKV(env), idxKey(id));
}

export async function findUserByUUID(env: Env, uuid: string): Promise<User | null> {
  const users = await listUsers(env);
  return users.find((u) => u.uuid === uuid) || null;
}

export async function findUserByToken(env: Env, token: string): Promise<User | null> {
  if (!/^[0-9a-f]{10,32}$/.test(token)) return null;
  const users = await listUsers(env);
  return users.find((u) => u.token === token) || null;
}

export async function putUser(env: Env, user: User): Promise<void> {
  await writeJSON(getKV(env), idxKey(user.id), user);
}

export async function createUser(env: Env, input: UserInput): Promise<User> {
  const user = makeUser(input, 0);
  await putUser(env, user);
  return user;
}

export async function deleteUser(env: Env, id: string): Promise<void> {
  await getKV(env).delete(idxKey(id));
}

export type UserState = 'active' | 'disabled' | 'expired' | 'over-quota';

export function userState(user: User, now = Date.now()): UserState {
  if (!user.enabled) return 'disabled';
  if (user.expires !== null && user.expires <= now) return 'expired';
  if (user.limitBytes > 0 && user.usedUp + user.usedDown >= user.limitBytes) return 'over-quota';
  return 'active';
}

/**
 * Add transferred bytes to a user record.
 *
 * KV has no atomic increments; the read-modify-write race window matters only
 * when two isolates flush the same user simultaneously — acceptable loss for
 * traffic accounting (and we always keep the *check* conservative by also
 * charging bytes on close, see proxy/ws.ts).
 */
export async function addUsage(env: Env, userId: string, up: number, down: number): Promise<void> {
  if (up <= 0 && down <= 0) return;
  const kv = getKV(env);
  const user = await readJSON<User>(kv, idxKey(userId));
  if (!user) return;
  user.usedUp += up;
  user.usedDown += down;
  await writeJSON(kv, idxKey(userId), user);
}
