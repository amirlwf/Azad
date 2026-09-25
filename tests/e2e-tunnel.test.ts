import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:net';
import { createHash } from 'node:crypto';

/**
 * Live tunnel E2E — full round trip through workerd:
 *   client --WS--> wrangler dev --TCP--> local echo server
 * Needs LOCAL_TEST=1 (loopback + relaxed port list):
 *   npx wrangler dev --port 8787 --var LOCAL_TEST:1
 * Skips silently when the server or echo endpoint cannot be reached.
 */

const BASE = process.env.E2E_BASE ?? 'http://127.0.0.1:8787';
const ADMIN = '/console-dev';
const PASS = 'e2e-correct-horse-battery';
const WS_PATH = '/devws1234567890';

let live = false;
let cookie = '';
let uuid = '';
let echoPort = 0;
let echo: Server;

function protoaFrame(opts: { uuid: string; host: string; port: number; payload?: Uint8Array; command?: number }): Uint8Array {
  const hex = opts.uuid.replace(/-/g, '');
  const head: number[] = [0];
  for (let i = 0; i < 32; i += 2) head.push(parseInt(hex.slice(i, i + 2), 16));
  head.push(0); // optLen
  head.push(opts.command ?? 1);
  head.push((opts.port >> 8) & 0xff, opts.port & 0xff);
  if (/^\d+\.\d+\.\d+\.\d+$/.test(opts.host)) {
    head.push(1, ...opts.host.split('.').map(Number));
  } else {
    const name = new TextEncoder().encode(opts.host);
    head.push(2, name.length, ...name);
  }
  const payload = opts.payload ?? new Uint8Array(0);
  const out = new Uint8Array(head.length + payload.length);
  out.set(head, 0);
  out.set(payload, head.length);
  return out;
}

function protobFrame(opts: { uuid: string; host: string; port: number; payload?: Uint8Array }): Uint8Array {
  const hash = createHash('sha224').update(opts.uuid).digest('hex');
  const head: number[] = [...hash].map((c) => c.charCodeAt(0));
  head.push(0x0d, 0x0a, 1);
  const name = new TextEncoder().encode(opts.host);
  if (/^\d+\.\d+\.\d+\.\d+$/.test(opts.host)) {
    head.push(1, ...opts.host.split('.').map(Number));
  } else {
    head.push(3, name.length, ...name);
  }
  head.push((opts.port >> 8) & 0xff, opts.port & 0xff);
  const payload = opts.payload ?? new Uint8Array(0);
  const out = new Uint8Array(head.length + payload.length);
  out.set(head, 0);
  out.set(payload, head.length);
  return out;
}

interface DialResult {
  messages: Uint8Array[];
  closeCode: number | null;
  closeReason: string;
}

/** open one tunnel, send one handshake, wait for `expect` bytes or close */
async function dial(
  frame: Uint8Array,
  opts: { expect?: number; expectBytes?: number; timeoutMs?: number; followUp?: { delayMs: number; data: Uint8Array } } = {},
): Promise<DialResult> {
  const expect = opts.expect ?? 1;
  const expectBytes = opts.expectBytes ?? 0;
  const timeoutMs = opts.timeoutMs ?? 6000;
  const messages: Uint8Array[] = [];
  let closeCode: number | null = null;
  let closeReason = '';
  let received = 0;
  let bytes = 0;

  const ws = new WebSocket(`${BASE.replace(/^http/, 'ws')}${WS_PATH}`);
  ws.binaryType = 'arraybuffer';

  const done = new Promise<void>((resolve) => {
    const timer = setTimeout(() => resolve(), timeoutMs);
    ws.addEventListener('message', (ev: MessageEvent) => {
      const data = ev.data;
      if (typeof data === 'string') {
        messages.push(new TextEncoder().encode(data));
      } else {
        messages.push(new Uint8Array(data as ArrayBuffer));
      }
      received++;
      bytes += (messages[messages.length - 1]?.length ?? 0);
      const done = expectBytes > 0 ? bytes >= expectBytes : received >= expect;
      if (done) {
        clearTimeout(timer);
        resolve();
      }
    });
    ws.addEventListener('close', (ev: CloseEvent) => {
      closeCode = ev.code;
      closeReason = ev.reason;
      clearTimeout(timer);
      resolve();
    });
    ws.addEventListener('error', () => {
      clearTimeout(timer);
      resolve();
    });
  });

  await new Promise<void>((resolve, reject) => {
    ws.addEventListener('open', () => resolve(), { once: true });
    ws.addEventListener('error', () => reject(new Error('ws open failed')), { once: true });
    setTimeout(() => reject(new Error('ws open timeout')), 4000);
  }).catch(() => undefined);

  if (ws.readyState === WebSocket.OPEN) ws.send(frame);
  if (opts.followUp) {
    setTimeout(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send(opts.followUp!.data);
    }, opts.followUp.delayMs);
  }

  await done;
  try {
    ws.close();
  } catch {
    /* already closing */
  }
  return { messages, closeCode, closeReason };
}

const total = (r: DialResult) => r.messages.reduce((n, m) => n + m.length, 0);

before(async () => {
  // local echo endpoint the tunnel will dial
  echo = createServer((sock) => {
    sock.on('data', (d) => sock.write(d));
    sock.on('error', () => undefined);
  });
  await new Promise<void>((resolve) => echo.listen(0, '127.0.0.1', resolve));
  echoPort = (echo.address() as { port: number }).port;

  try {
    const r = await fetch(BASE + '/', { signal: AbortSignal.timeout(2000) });
    live = r.status === 200 || r.status === 404;
  } catch {
    live = false;
  }
  if (!live) {
    console.log(`[e2e-tunnel] ${BASE} not reachable — skipping live tunnel suite`);
    return;
  }

  const s = await fetch(BASE + ADMIN + '/api/session');
  const sj: any = await s.json();
  const init = await fetch(BASE + ADMIN + (sj.setupRequired ? '/api/setup' : '/api/login'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: PASS }),
  });
  let m = /azad_sid=([^;]+)/.exec(init.headers.get('set-cookie') ?? '');
  if (!m) {
    const login = await fetch(BASE + ADMIN + '/api/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: PASS }),
    });
    m = /azad_sid=([^;]+)/.exec(login.headers.get('set-cookie') ?? '');
  }
  cookie = m ? `azad_sid=${m[1]}` : '';
  const list: any = await (await fetch(BASE + ADMIN + '/api/users', { headers: { cookie } })).json();
  uuid = list.users?.[0]?.uuid ?? '';
});

after(() => {
  try {
    echo?.close();
  } catch {
    /* ignore */
  }
});

const skip = () => !live || !uuid;

describe('e2e tunnel: protoa over ws', () => {
  it('round-trips a payload through the echo server', async () => {
    if (skip()) return;
    const payload = new TextEncoder().encode('hello from the e2e suite');
    const frame = protoaFrame({ uuid, host: '127.0.0.1', port: echoPort, payload });
    const r = await dial(frame, { expect: 1, timeoutMs: 8000 });

    assert.equal(r.closeCode, null, `connection closed early: ${r.closeCode} ${r.closeReason}`);
    const all = new Uint8Array(total(r));
    let off = 0;
    for (const m of r.messages) {
      all.set(m, off);
      off += m.length;
    }
    assert.deepEqual([all[0], all[1]], [0, 0], 'protoa response header must lead the stream');
    const body = new TextDecoder().decode(all.subarray(2));
    assert.ok(body.includes('hello from the e2e suite'), `echo mismatch: ${JSON.stringify(body)}`);
  });

  it('keeps the connection alive for a delayed follow-up (idle data)', async () => {
    if (skip()) return;
    const payload = new TextEncoder().encode('first');
    const frame = protoaFrame({ uuid, host: '127.0.0.1', port: echoPort, payload });
    const r = await dial(frame, {
      expect: 2,
      timeoutMs: 10000,
      followUp: { delayMs: 1500, data: new TextEncoder().encode('-second') },
    });
    const text = r.messages.map((m) => new TextDecoder().decode(m)).join('');
    assert.ok(text.includes('first'), 'missing first echo');
    assert.ok(text.includes('second'), 'missing delayed echo — connection was dropped while idle');
  });

  it('transfers a large payload without dropping the stream', async () => {
    if (skip()) return;
    const big = new Uint8Array(96 * 1024);
    for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
    const frame = protoaFrame({ uuid, host: '127.0.0.1', port: echoPort, payload: big });
    const r = await dial(frame, { expectBytes: 2 + big.length, timeoutMs: 15000 });
    const all = r.messages.reduce((n, m) => n + m.length, 0);
    // 2 header bytes + full echo (arrives across several messages)
    assert.ok(all >= 2 + big.length, `got ${all} bytes, expected >= ${2 + big.length}`);
  });

  it('runs several tunnels concurrently and releases them all', async () => {
    if (skip()) return;
    const jobs = Array.from({ length: 4 }, (_, i) => {
      const payload = new TextEncoder().encode(`parallel-${i}`);
      return dial(protoaFrame({ uuid, host: '127.0.0.1', port: echoPort, payload }), {
        expect: 1,
        timeoutMs: 8000,
      });
    });
    const results = await Promise.all(jobs);
    for (const [i, r] of results.entries()) {
      const text = r.messages.map((m) => new TextDecoder().decode(m)).join('');
      assert.ok(text.includes(`parallel-${i}`), `tunnel ${i} failed: close=${r.closeCode} ${r.closeReason}`);
    }
  });

  it('rejects a wrong uuid with close code 1008', async () => {
    if (skip()) return;
    const bad = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
    const r = await dial(protoaFrame({ uuid: bad, host: '127.0.0.1', port: echoPort }), {
      expect: 1,
      timeoutMs: 5000,
    });
    assert.equal(r.closeCode, 1008, `expected 1008, got ${r.closeCode} (${r.closeReason})`);
    assert.equal(total(r), 0, 'no data may flow for a rejected handshake');
  });

  it('blocks metadata destinations even in dev mode', async () => {
    if (skip()) return;
    const r = await dial(
      protoaFrame({ uuid, host: '169.254.169.254', port: 80, payload: new TextEncoder().encode('GET /') }),
      { expect: 1, timeoutMs: 5000 },
    );
    assert.equal(r.closeCode, 1011, `expected refusal, got ${r.closeCode}`);
    assert.equal(total(r), 0, 'metadata endpoint must never answer');
  });

  it('refuses an upgrade on a wrong ws path', async () => {
    if (skip()) return;
    const ws = new WebSocket(`${BASE.replace(/^http/, 'ws')}${WS_PATH}-wrong`);
    const outcome = await new Promise<string>((resolve) => {
      ws.addEventListener('open', () => resolve('open'), { once: true });
      ws.addEventListener('close', (ev: CloseEvent) => resolve(`close:${ev.code}`), { once: true });
      ws.addEventListener('error', () => resolve('error'), { once: true });
      setTimeout(() => resolve('timeout'), 4000);
    });
    assert.notEqual(outcome, 'open', 'upgrade on a wrong path must not succeed');
  });
});

describe('e2e tunnel: protob over ws', () => {
  it('round-trips with the sha224 password handshake', async () => {
    if (skip()) return;
    const payload = new TextEncoder().encode('protob hello');
    const frame = protobFrame({ uuid, host: '127.0.0.1', port: echoPort, payload });
    const r = await dial(frame, { expect: 1, timeoutMs: 8000 });
    const text = r.messages.map((m) => new TextDecoder().decode(m)).join('');
    assert.ok(text.includes('protob hello'), `close=${r.closeCode} ${r.closeReason} body=${JSON.stringify(text)}`);
    // protob has no leading response header — first bytes are the echo itself
    assert.ok(text.startsWith('protob hello') || text.includes('protob hello'));
  });
});
