import { connect } from 'cloudflare:sockets';
import { base64UrlDecode, bytesToHex, uuidToBytes } from '../core/codecs.ts';
import { RateLimiter, isIPv4, isPrivateIPv4, isPrivateIPv6 } from '../core/guard.ts';
import { egressAllowed } from '../core/settings.ts';
import { pushLog } from '../core/log.ts';
import { settingsFor, type Env, type Settings } from '../core/settings.ts';
import { addUsage, listUsers, userState, type User } from '../core/users.ts';
import { parseVlessHeader, vlessResponseHeader, encodeVlessUdpPacket } from './vless.ts';
import { parseTrojanHeader, trojanPasswordHex } from './trojan.ts';

/**
 * The tunnel: WebSocket upgrade -> protocol handshake -> guarded TCP egress.
 *
 * Design notes (these are the "don't get banned" choices):
 *  - the upgrade only succeeds on the configured ws path, and a request with
 *    no eligible user gets a plain 404 page instead of an oracle response;
 *  - every destination passes checkDestination() (port allow-list + private /
 *    metadata address block) before any socket is opened — an unvalidated
 *    destination would turn the worker into an open proxy inside Cloudflare's
 *    network, which is the classic abuse classification;
 *  - per-IP upgrade rate limit + per-user connection cap + byte quota;
 *  - usage is charged on close, never per packet (KV write volume stays tiny).
 */

import { tunnelStats } from '../core/stats.ts';

export { tunnelStats };

/**
 * Upgrade rate limiting, driven by settings.maxUpgradesPerMinute.
 * One RateLimiter per (isolate, limit) — limit changes rebuild it lazily.
 */
const upgradeLimiters = new Map<number, RateLimiter>();
function upgradeAllowed(limit: number, ip: string): boolean {
  let rl = upgradeLimiters.get(limit);
  if (!rl) {
    rl = new RateLimiter(limit, 60_000);
    upgradeLimiters.set(limit, rl);
  }
  return rl.hit(`u:${ip}`);
}
const lastUserLog = new Map<string, number>();

/** dedupe repeated identical log lines (unauthenticated floods) */
const logThrottle = new Map<string, number>();
async function logThrottled(env: Env, key: string, kind: 'guard' | 'tunnel', msg: string): Promise<void> {
  const now = Date.now();
  const last = logThrottle.get(key) || 0;
  if (now - last < 30_000) return;
  if (logThrottle.size > 2_000) logThrottle.clear();
  logThrottle.set(key, now);
  await pushLog(env, kind, msg);
}

function toBytes(data: unknown): Uint8Array | null {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (typeof data === 'string') return new TextEncoder().encode(data);
  return null;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(a.length + b.length));
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function parseHostPort(value: string, fallbackPort: number): { host: string; port: number } {
  const m = value.match(/^\[([^\]]+)\]:(\d+)$/);
  if (m) return { host: m[1], port: Number(m[2]) };
  const m2 = value.match(/^(.+):(\d+)$/);
  if (m2 && !m2[1].includes(':')) return { host: m2[1], port: Number(m2[2]) };
  return { host: value, port: fallbackPort };
}

const ISOLATE_BUDGET = 5;

export function acquire(user: User, settings: Settings): boolean {
  const cap = user.maxConns ?? settings.maxConnsPerUser;
  const cur = tunnelStats.inflightByUser.get(user.id) || 0;
  if (cur >= cap) return false;
  // Cloudflare allows 6 simultaneous outbound connections per invocation and
  // one is reserved for DoH: refuse beyond the budget instead of 1011-ing later
  if (tunnelStats.total >= ISOLATE_BUDGET) return false;
  tunnelStats.inflightByUser.set(user.id, cur + 1);
  tunnelStats.total++;
  return true;
}

function release(user: User): void {
  const cur = tunnelStats.inflightByUser.get(user.id) || 0;
  if (cur <= 1) tunnelStats.inflightByUser.delete(user.id);
  else tunnelStats.inflightByUser.set(user.id, cur - 1);
  tunnelStats.total = Math.max(0, tunnelStats.total - 1);
}

const DOH_URL = 'https://cloudflare-dns.com/dns-query';

/**
 * Hostname destinations are resolved through DoH and the answers are run
 * through the same egress guard BEFORE connect(): otherwise an attacker
 * controlled name (x.attacker.com -> 169.254.169.254) would turn the worker
 * into an inside-network proxy. Results are cached per isolate for 5 minutes
 * so the extra round-trip happens once per destination, not per connection.
 */
const dnsCache = new Map<string, { at: number; ok: boolean }>();

async function ensurePublicDestination(
  host: string,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  if (isIPv4(host) || host.includes(':')) return { ok: true }; // literals already guarded

  const cached = dnsCache.get(host);
  if (cached && Date.now() - cached.at < 300_000) {
    return cached.ok ? { ok: true } : { ok: false, reason: 'dns-cached-block' };
  }

  const query = async (type: 'A' | 'AAAA'): Promise<{ ips: string[]; served: boolean }> => {
    try {
      const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(3000),
      });
      if (!res.ok) return { ips: [], served: false };
      const j = (await res.json()) as { Answer?: { type: number; data: string }[] };
      const wanted = type === 'A' ? 1 : 28;
      return {
        ips: (j.Answer ?? []).filter((a) => a.type === wanted).map((a) => a.data),
        served: true,
      };
    } catch {
      return { ips: [], served: false };
    }
  };

  const [a, aaaa] = await Promise.all([query('A'), query('AAAA')]);
  const answers = [...a.ips, ...aaaa.ips];

  // resolver unreachable => fail open (CF will resolve anyway; availability first)
  if (!a.served && !aaaa.served) return { ok: true };

  let ok = answers.length > 0; // NXDOMAIN => refuse rather than guess
  for (const ip of answers) {
    const isV4 = /^\d+\.\d+\.\d+\.\d+$/.test(ip);
    if (isV4 ? isPrivateIPv4(ip) : isPrivateIPv6(ip)) {
      ok = false;
      break;
    }
  }

  if (dnsCache.size > 512) dnsCache.clear();
  dnsCache.set(host, { at: Date.now(), ok });
  return ok ? { ok: true } : { ok: false, reason: 'dns-resolves-private' };
}

export async function handleTunnel(request: Request, env: Env): Promise<Response> {
  const settings = await settingsFor(env);
  const url = new URL(request.url);

  if (url.pathname !== settings.wsPath && url.pathname !== `${settings.wsPath}/`) {
    return new Response('Not Found', { status: 404 });
  }

  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'local';
  if (!upgradeAllowed(settings.maxUpgradesPerMinute, ip)) {
    await pushLog(env, 'guard', `upgrade rate-limited for ${ip}`);
    return new Response('Too Many Requests', { status: 429, headers: { 'Retry-After': '60' } });
  }

  const users = (await listUsers(env)).filter((u) => userState(u) === 'active');
  const uuidList: Uint8Array[] = [];
  const byUUID = new Map<string, User>();
  const byUUIDHex = new Map<string, User>();
  const passwordSet = new Set<string>();
  const byPassword = new Map<string, User>();

  for (const u of users) {
    if (settings.mode !== 'b') {
      uuidList.push(uuidToBytes(u.uuid));
      byUUID.set(u.uuid, u);
      byUUIDHex.set(u.uuid.replace(/-/g, '').toLowerCase(), u);
    }
    if (settings.mode !== 'a') {
      const hex = trojanPasswordHex(u.uuid);
      passwordSet.add(hex);
      byPassword.set(hex, u);
    }
  }

  if (uuidList.length === 0 && passwordSet.size === 0) {
    // no active users: answer like a plain website (no fingerprint for scanners)
    return new Response(camoProbePage, {
      status: 404,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  }

  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
  server.accept();
  // Without this, workerd hands binary frames to us as Blob (compat 2026-04-21)
  // and every handshake byte would be silently discarded in toBytes().
  server.binaryType = 'arraybuffer';

  const early = base64UrlDecode(request.headers.get('Sec-WebSocket-Protocol') || '');

  runTunnel(server, early, {
    env,
    settings,
    uuidList,
    byUUID,
    byUUIDHex,
    passwordSet,
    byPassword,
    ip,
  }).catch(async (err) => {
    try {
      await pushLog(env, 'tunnel', `handler error: ${String(err).slice(0, 160)}`);
    } catch {
      /* logging must never be the reason a socket leaks */
    }
    try {
      server.close();
    } catch {
      /* ignore */
    }
  });

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers: { 'Sec-WebSocket-Extensions': '' },
  });
}

const camoProbePage = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>404 Not Found</title></head><body><h1>404</h1><p>The requested resource was not found.</p>
<hr><address>nginx</address></body></html>`;

interface TunnelContext {
  env: Env;
  settings: Settings;
  uuidList: Uint8Array[];
  byUUID: Map<string, User>;
  /** uuid without dashes -> user (hex of the wire bytes) */
  byUUIDHex: Map<string, User>;
  passwordSet: Set<string>;
  byPassword: Map<string, User>;
  ip: string;
}

async function runTunnel(ws: WebSocket, early: Uint8Array | null, ctx: TunnelContext): Promise<void> {
  const { env, settings } = ctx;

  let closed = false;
  let flushed = false;
  let user: User | null = null;
  let acquired = false;
  let remote: Socket | null = null;
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let phase: 'header' | 'tcp' | 'udp' = 'header';
  let respHeader: Uint8Array | null = null;
  let headerSent = false;
  let up = 0;
  let down = 0;
  let firstPayload = new Uint8Array(0);
  let dstPort = 0;
  let udpRest = new Uint8Array(0);
  let headerBuf = new Uint8Array(0); // header split across WebSocket frames
  let gotData = false; // remote produced bytes -> fallback window closed
  let retrying = false; // writer lock teardown / fallback in progress
  let sentLogBytes = 0;
  let noFallback = false; // replay log overflow: fallback could corrupt the stream
  const sentLog: Uint8Array[] = []; // everything written to the remote (replayed on fallback)
  const pendingWrites: Uint8Array[] = []; // frames that arrived during a retry window

  async function flush(): Promise<void> {
    if (flushed) return;
    flushed = true;
    if (user) {
      const u = user;
      if (acquired) release(u);
      try {
        await addUsage(env, u.id, up, down);
      } catch {
        /* accounting must never throw */
      }
    }
  }

  function closeRemote(): void {
    try {
      writer?.releaseLock();
    } catch {
      /* ignore */
    }
    writer = null;
    if (remote) {
      try {
        remote.close();
      } catch {
        /* ignore */
      }
      remote = null;
    }
  }

  async function finish(code?: number, reason?: string): Promise<void> {
    if (closed) return;
    closed = true;
    try {
      if (code !== undefined) ws.close(code, reason || '');
      else ws.close();
    } catch {
      /* ignore */
    }
    closeRemote();
    await flush();
  }

  function quotaExceeded(): boolean {
    if (!user) return false;
    if (user.limitBytes <= 0) return false;
    // prior usage counts: otherwise a user at 99% could transfer a full quota
    // inside a single long-lived connection
    return user.usedUp + user.usedDown + up + down >= user.limitBytes;
  }

  async function openRemote(host: string, port: number, resend: Uint8Array | null): Promise<void> {
    const socket = connect({ hostname: host, port });
    // a hard socket error must never surface as an unhandled rejection
    socket.closed.catch(() => undefined);
    remote = socket;
    writer = socket.writable.getWriter();
    if (resend && resend.length) await writer.write(resend);
  }

  function recordSent(chunk: Uint8Array): void {
    if (noFallback) return;
    sentLog.push(chunk);
    sentLogBytes += chunk.length;
    if (sentLogBytes > 128 * 1024) {
      // too late to replay reliably: disable fallback instead of corrupting
      noFallback = true;
      sentLog.length = 0;
      sentLogBytes = 0;
    }
  }

  /** everything written so far, replayed on a fallback connection */
  function resendBuffer(): Uint8Array | null {
    if (noFallback || sentLog.length === 0) return null;
    if (sentLog.length === 1) return sentLog[0];
    const out = new Uint8Array(sentLogBytes);
    let at = 0;
    for (const part of sentLog) {
      out.set(part, at);
      at += part.length;
    }
    return out;
  }

  /** flush frames that arrived while the writer was unavailable (retry window) */
  async function flushPending(): Promise<void> {
    while (pendingWrites.length) {
      const w = writer;
      if (!w || closed) return;
      const c = pendingWrites[0];
      try {
        await w.write(c);
      } catch {
        return; // dead socket: leave queued, pumpRemote decides what happens
      }
      pendingWrites.shift();
      recordSent(c);
    }
  }

  async function pumpRemote(attempt: number): Promise<void> {
    const reader = remote ? remote.readable.getReader() : null;
    try {
      while (reader) {
        const { done, value } = await reader.read();
        if (done) break;
        gotData = true;
        if (closed || ws.readyState !== 1) break;
        down += value.length;
        let out: Uint8Array = value;
        if (respHeader && !headerSent) {
          out = concat(respHeader, value);
          headerSent = true;
        }
        ws.send(out);
        if (quotaExceeded()) {
          await finish(1008, 'quota');
          return;
        }
      }
    } catch {
      /* remote read error: fall through to close/retry */
    } finally {
      try {
        reader?.releaseLock();
      } catch {
        /* ignore */
      }
    }

    if (closed) return;

    if (!gotData && !noFallback && phase === 'tcp' && attempt < settings.proxyIPs.length) {
      // direct egress produced no data (classic "remote refuses edge IPs" case):
      // retry through an admin-configured fallback proxy, same semantics as the
      // established panels (host replaced, port kept unless the entry has one).
      const used = await tryFallback(attempt);
      if (used !== null) {
        await pumpRemote(used + 1);
        return;
      }
    }

    await finish();
  }

  /** dial proxyIPs[from..] until one takes; returns its index or null */
  async function tryFallback(from: number): Promise<number | null> {
    for (let i = from; i < settings.proxyIPs.length; i++) {
      const target = parseHostPort(settings.proxyIPs[i], dstPort);
      const g = egressAllowed(env, settings, target.host, target.port);
      if (!g.ok) {
        await pushLog(env, 'guard', `fallback blocked ${target.host}:${target.port} (${g.reason})`);
        continue;
      }
      retrying = true;
      try {
        closeRemote();
        await openRemote(target.host, target.port, resendBuffer());
        await flushPending(); // replay frames that arrived during the window
        retrying = false;
        await pushLog(env, 'tunnel', `fallback attempt ${i + 1}/${settings.proxyIPs.length} -> ${target.host}`);
        return i;
      } catch (err) {
        retrying = false;
        await pushLog(env, 'tunnel', `fallback connect failed: ${String(err).slice(0, 120)}`);
      }
    }
    return null;
  }

  async function handleUdp(chunk: Uint8Array): Promise<void> {
    // stream framing: [len BE16][datagram]...
    udpRest = concat(udpRest, chunk);
    while (udpRest.length >= 2) {
      const len = (udpRest[0] << 8) | udpRest[1];
      if (udpRest.length < len + 2) break;
      const packet = udpRest.subarray(2, 2 + len);
      udpRest = udpRest.subarray(2 + len);
      try {
        const res = await fetch(DOH_URL, {
          method: 'POST',
          headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
          body: packet,
        });
        const buf = new Uint8Array(await res.arrayBuffer());
        if (buf.length && !closed && ws.readyState === 1) {
          let framed = encodeVlessUdpPacket(buf);
          if (respHeader && !headerSent) {
            framed = concat(respHeader, framed);
            headerSent = true;
          }
          down += framed.length;
          ws.send(framed);
        }
      } catch {
        break;
      }
    }
  }

  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      ws.addEventListener('message', (event: MessageEvent) => {
        if (closed) return;
        const bytes = toBytes(event.data);
        if (bytes) {
          try {
            controller.enqueue(bytes);
          } catch {
            /* stream already closed */
          }
          return;
        }
        // Blob (binaryType not honoured): convert asynchronously, never drop
        const blob = event.data as Blob;
        if (blob && typeof blob.arrayBuffer === 'function') {
          blob
            .arrayBuffer()
            .then((buf) => {
              try {
                controller.enqueue(new Uint8Array(buf));
              } catch {
                /* stream already closed */
              }
            })
            .catch(() => undefined);
        }
      });
      ws.addEventListener('close', () => {
        void finish();
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      });
      ws.addEventListener('error', () => {
        void finish(1011, 'ws-error');
        try {
          controller.error(new Error('ws error'));
        } catch {
          /* ignore */
        }
      });
      if (early && early.length) controller.enqueue(early);
    },
    cancel() {
      void finish();
    },
  });

  const writable = new WritableStream<Uint8Array>({
    async write(chunk) {
      if (closed) return;

      if (phase === 'header') {
        // the header may be split across frames: accumulate until it parses
        const raw = headerBuf.length ? concat(headerBuf, chunk) : chunk;
        if (raw.length === 0) return;

        let host = '';
        let port = 0;
        let payloadStart = 0;
        let isVless = false;
        let version = 0;
        let command = 1;
        let matchedUser: User | null = null;

        // first byte disambiguates: 0x00/0x01 = vless version (both appear in
        // the wild), hex digit = trojan digest. neither => definitive reject
        // (no amount of extra bytes can turn it into a valid header).
        const vless = raw[0] === 0x01 || raw[0] === 0x00 ? parseVlessHeader(raw, ctx.uuidList) : null;
        const trojan =
          !vless && ((raw[0] >= 0x30 && raw[0] <= 0x39) || (raw[0] >= 0x61 && raw[0] <= 0x66))
            ? parseTrojanHeader(raw, ctx.passwordSet)
            : null;

        if (!vless?.ok && !trojan?.ok) {
          const truncated =
            (vless !== null && !vless.ok && vless.short === true) ||
            (trojan !== null && !trojan.ok && trojan.short === true);
          if (truncated && raw.length < 512) {
            headerBuf = raw; // wait for the rest of the header
            return;
          }
          await logThrottled(env, `hs:${ctx.ip}`, 'guard', `handshake rejected from ${ctx.ip}`);
          await finish(1008, 'auth');
          return;
        }
        headerBuf = new Uint8Array(0);

        if (vless && vless.ok) {
          const hex = bytesToHex(vless.uuidMatched).toLowerCase();
          matchedUser = ctx.byUUIDHex.get(hex) || null;
          host = vless.host;
          port = vless.port;
          payloadStart = vless.payloadStart;
          isVless = true;
          version = vless.version;
          command = vless.command;
        } else if (trojan && trojan.ok) {
          matchedUser = ctx.byPassword.get(trojan.passwordHex) || null;
          host = trojan.host;
          port = trojan.port;
          payloadStart = trojan.payloadStart;
          isVless = false;
          command = 1;
        }

        if (!matchedUser) {
          await logThrottled(env, `hs:${ctx.ip}`, 'guard', `handshake rejected from ${ctx.ip} (${vless && vless.ok ? 'uuid' : 'auth'})`);
          await finish(1008, 'auth');
          return;
        }
        user = matchedUser;
        dstPort = port;

        // UDP is only ever used for DNS and never opens a raw egress socket
        if (command === 2) {
          if (port !== 53) {
            await pushLog(env, 'guard', `udp to ${host}:${port} blocked`);
            await finish(1011, 'udp');
            return;
          }
          const g = egressAllowed(env, settings, host, port, true);
          if (!g.ok) {
            await pushLog(env, 'guard', `udp ${host}:${port} blocked (${g.reason})`);
            await finish(1011, 'blocked');
            return;
          }
        } else {
          const g = egressAllowed(env, settings, host, port);
          if (!g.ok) {
            await pushLog(env, 'guard', `blocked ${host}:${port} (${g.reason})`);
            await finish(1011, 'blocked');
            return;
          }
          // hostname: verify where it actually points before dialing
          const d = await ensurePublicDestination(host);
          if (!d.ok) {
            await pushLog(env, 'guard', `blocked ${host}:${port} (${d.reason})`);
            await finish(1011, 'blocked');
            return;
          }
        }

        if (!acquire(matchedUser, settings)) {
          await pushLog(env, 'guard', `connection cap reached for user ${matchedUser.name}`);
          await finish(1013, 'busy');
          return;
        }
        acquired = true;

        firstPayload = raw.subarray(payloadStart);
        up += firstPayload.length;

        if (command === 2) {
          // DNS goes through DoH: NEVER open a TCP socket for a UDP session —
          // an orphaned connect() would hold one of the six outbound slots and
          // could kill a working DNS path with a spurious 1011.
          phase = 'udp';
          respHeader = vlessResponseHeader(version);
          headerSent = false;
          if (firstPayload.length) await handleUdp(firstPayload);
        } else {
          if (firstPayload.length) recordSent(firstPayload);
          try {
            await openRemote(host, port, resendBuffer());
          } catch (err) {
            // pumpRemote handles the failure path: no data => fallback chain
            await pushLog(env, 'tunnel', `connect failed ${host}:${port} ${String(err).slice(0, 100)}`);
          }
          phase = 'tcp';
          respHeader = isVless ? vlessResponseHeader(version) : null;
          headerSent = respHeader === null; // trojan has no response header
          pumpRemote(0).catch(() => void finish(1011, 'pump'));
        }

        const now = Date.now();
        const last = lastUserLog.get(matchedUser.id) || 0;
        if (now - last > 60_000) {
          lastUserLog.set(matchedUser.id, now);
          void pushLog(env, 'tunnel', `${matchedUser.name} -> ${host}:${port}`);
        }
        if (quotaExceeded()) await finish(1008, 'quota');
        return;
      }

      up += chunk.length;
      if (phase === 'udp') {
        await handleUdp(chunk);
      } else if (writer && !retrying) {
        try {
          await writer.write(chunk);
          recordSent(chunk);
        } catch {
          if (closed) return;
          // rejected because the fallback released the lock mid-write, or the
          // socket died: queue it rather than killing a recoverable tunnel
          pendingWrites.push(chunk);
          if (writer && !retrying) await flushPending();
        }
      } else if (phase === 'tcp') {
        // retry window: never drop client frames
        if (pendingWrites.length > 4_000_000) {
          await finish(1011, 'write');
          return;
        }
        pendingWrites.push(chunk);
      }
      if (quotaExceeded()) await finish(1008, 'quota');
    },

    async close() {
      await finish();
    },

    async abort() {
      await finish();
    },
  });

  await readable.pipeTo(writable).catch(() => undefined);
  await finish();
}
