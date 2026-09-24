/**
 * Egress guard + sliding-window rate limiter.
 *
 * The single biggest abuse signal a tunnel worker can give off is acting as an
 * *open proxy*: any holder of the UUID can then scan Cloudflare's network from
 * the inside (SSH/SMTP/redis ports, RFC1918 ranges, cloud metadata endpoints).
 * That pattern is what turns "terms review" into an account ban. So every
 * outbound connection must pass:
 *   1. a destination-port allow-list (web ports by default), and
 *   2. a private/reserved IP block-list for IP literals + hostname rules.
 */

export interface GuardPolicy {
  /** allowed destination ports; empty array = allow every port */
  ports: number[];
  /** test/dev only: allow loopback/private targets */
  allowPrivate: boolean;
}

export type GuardResult = { ok: true } | { ok: false; reason: string };

export const DEFAULT_EGRESS_PORTS = [
  80, 443, 8080, 8443, 8880, 8886,
  2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096,
];

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data', // aws ec2 metadata alias
]);

const BLOCKED_HOST_SUFFIXES = ['.localhost', '.local', '.internal', '.localdomain', '.home.arpa'];

export function isIPv4(host: string): boolean {
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    if (n > 255 || (p.length > 1 && p[0] === '0')) return false;
  }
  return true;
}

export function isPrivateIPv4(ip: string): boolean {
  if (!isIPv4(ip)) return false;
  const [a, b, c] = ip.split('.').map(Number);
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local + metadata 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24 IETF
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
  if (a >= 224) return true; // multicast + reserved + broadcast
  return false;
}

export function isPrivateIPv6(ip: string): boolean {
  const h = ip.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === '::' || h === '::1') return true;
  if (h.startsWith('::ffff:')) {
    const tail = h.slice(7);
    if (isIPv4(tail)) return isPrivateIPv4(tail);
    // ::ffff:aabb:ccdd
    const m = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (m) {
      const hi = parseInt(m[1], 16);
      const lo = parseInt(m[2], 16);
      return isPrivateIPv4(`${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`);
    }
  }
  const first = parseInt(h.split(':')[0] || '0', 16);
  if (Number.isNaN(first)) return false;
  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link local
  if ((first & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (first === 0x2001 && h.startsWith('2001:db8')) return true; // documentation
  return false;
}

/** 169.254.0.0/16 (incl. 169.254.169.254) and fe80::/10 — blocked unconditionally */
function isMetadataAddress(host: string, v4: boolean): boolean {
  if (v4) {
    const [a, b] = host.split('.').map(Number);
    return a === 169 && b === 254;
  }
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  const first = parseInt(h.split(':')[0] || '0', 16);
  return !Number.isNaN(first) && (first & 0xffc0) === 0xfe80;
}

function normalizeHost(raw: string): string {
  let host = raw.trim().toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  return host;
}

/**
 * Validate a parsed tunnel destination.
 * `policy.allowPrivate` exists for local tests (echo servers on loopback) and
 * must stay false in production.
 */
export function checkDestination(
  rawHost: string,
  port: number,
  policy: GuardPolicy,
): GuardResult {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, reason: 'bad-port' };
  }
  if (policy.ports.length > 0 && !policy.ports.includes(port)) {
    return { ok: false, reason: 'port-not-allowed' };
  }

  const host = normalizeHost(rawHost);
  if (!host) return { ok: false, reason: 'empty-host' };

  if (BLOCKED_HOSTNAMES.has(host)) return { ok: false, reason: 'blocked-hostname' };
  for (const suffix of BLOCKED_HOST_SUFFIXES) {
    if (host.endsWith(suffix)) return { ok: false, reason: 'blocked-hostname' };
  }

  const looksV6 = host.includes(':');
  const looksV4 = isIPv4(host);

  if (looksV4 || looksV6) {
    const priv = looksV4 ? isPrivateIPv4(host) : isPrivateIPv6(host);
    if (!priv) return { ok: true };
    // link-local / cloud metadata are NEVER reachable, not even with allowPrivate:
    // reaching 169.254.169.254 from a tunnel is the single clearest abuse signal.
    if (isMetadataAddress(host, looksV4)) return { ok: false, reason: 'metadata-address' };
    if (policy.allowPrivate) return { ok: true };
    return { ok: false, reason: 'private-address' };
  }

  // hostname: workerd resolves it on connect, so we can only apply name rules.
  if (!/^[a-z0-9._-]+$/.test(host)) return { ok: false, reason: 'bad-hostname' };
  return { ok: true };
}

/** Fixed-window counter (per-isolate). Good enough for abuse throttling. */
export class RateLimiter {
  private hits = new Map<string, { count: number; resetAt: number }>();
  private limit: number;
  private windowMs: number;

  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  /** returns true when the request may proceed */
  hit(key: string, now = Date.now()): boolean {
    let slot = this.hits.get(key);
    if (!slot || slot.resetAt <= now) {
      slot = { count: 0, resetAt: now + this.windowMs };
      this.hits.set(key, slot);
    }
    slot.count++;
    // opportunistic cleanup so the map cannot grow without bound
    if (this.hits.size > 4096) {
      for (const [k, v] of this.hits) if (v.resetAt <= now) this.hits.delete(k);
    }
    return slot.count <= this.limit;
  }

  reset(key?: string): void {
    if (key) this.hits.delete(key);
    else this.hits.clear();
  }
}
