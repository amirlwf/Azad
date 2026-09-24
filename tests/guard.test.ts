import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkDestination,
  isPrivateIPv4,
  isPrivateIPv6,
  RateLimiter,
  DEFAULT_EGRESS_PORTS,
} from '../src/core/guard.ts';

const strict = { ports: [80, 443], allowPrivate: false };
const permissive = { ports: [], allowPrivate: true };

describe('private address detection', () => {
  it('flags IPv4 private/reserved ranges', () => {
    const priv = [
      '10.0.0.1', '10.255.255.255', '127.0.0.1', '172.16.0.1', '172.31.255.255',
      '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '198.18.0.1',
      '224.0.0.1', '255.255.255.255', '192.0.0.1',
    ];
    for (const ip of priv) assert.equal(isPrivateIPv4(ip), true, ip);
  });

  it('allows public IPv4', () => {
    const pub = ['1.1.1.1', '8.8.8.8', '104.16.1.1', '172.15.0.1', '172.32.0.1', '100.63.0.1'];
    for (const ip of pub) assert.equal(isPrivateIPv4(ip), false, ip);
  });

  it('flags IPv6 private ranges incl. v4-mapped', () => {
    const priv = ['::1', '::', 'fd00::1', 'fe80::1', 'ff02::1', '::ffff:10.0.0.1', '::ffff:192.168.0.1', '2001:db8::1'];
    for (const ip of priv) assert.equal(isPrivateIPv6(ip), true, ip);
    assert.equal(isPrivateIPv6('2606:4700:4700::1111'), false);
  });
});

describe('checkDestination', () => {
  it('rejects ports outside the allow-list', () => {
    assert.deepEqual(checkDestination('1.1.1.1', 22, strict), { ok: false, reason: 'port-not-allowed' });
    assert.deepEqual(checkDestination('1.1.1.1', 3306, { ports: DEFAULT_EGRESS_PORTS, allowPrivate: false }), {
      ok: false,
      reason: 'port-not-allowed',
    });
    assert.equal(checkDestination('1.1.1.1', 443, strict).ok, true);
  });

  it('rejects private destinations in strict mode', () => {
    assert.deepEqual(checkDestination('127.0.0.1', 443, strict), { ok: false, reason: 'private-address' });
    assert.deepEqual(checkDestination('169.254.169.254', 80, strict), { ok: false, reason: 'metadata-address' });
    // even the dev escape hatch never reaches metadata
    assert.deepEqual(checkDestination('169.254.169.254', 80, { ports: [], allowPrivate: true }), {
      ok: false,
      reason: 'metadata-address',
    });
    assert.deepEqual(checkDestination('10.1.2.3', 443, strict), { ok: false, reason: 'private-address' });
    assert.deepEqual(checkDestination('[fd00::1]', 443, strict), { ok: false, reason: 'private-address' });
  });

  it('allows loopback only when explicitly permitted (local test mode)', () => {
    assert.equal(checkDestination('127.0.0.1', 45678, permissive).ok, true);
    assert.equal(checkDestination('::1', 9, { ports: [], allowPrivate: true }).ok, true);
  });

  it('blocks local/hostnames used for metadata probing', () => {
    for (const h of ['localhost', 'foo.localhost', 'printer.local', 'db.internal', 'metadata.google.internal']) {
      assert.deepEqual(checkDestination(h, 443, { ports: [], allowPrivate: true }), {
        ok: false,
        reason: 'blocked-hostname',
      });
    }
  });

  it('accepts ordinary public hostnames', () => {
    assert.equal(checkDestination('example.com', 443, strict).ok, true);
    assert.equal(checkDestination('speed.cloudflare.com', 443, strict).ok, true);
  });

  it('rejects malformed hosts and ports', () => {
    assert.equal(checkDestination('', 443, strict).ok, false);
    assert.equal(checkDestination('1.1.1.1', 0, strict).ok, false);
    assert.equal(checkDestination('1.1.1.1', 70000, strict).ok, false);
    assert.equal(checkDestination('exa mple.com', 443, strict).ok, false);
  });
});

describe('RateLimiter', () => {
  it('allows up to the limit inside the window and blocks after', () => {
    const rl = new RateLimiter(3, 1000);
    const now = 10_000;
    assert.equal(rl.hit('ip', now), true);
    assert.equal(rl.hit('ip', now), true);
    assert.equal(rl.hit('ip', now), true);
    assert.equal(rl.hit('ip', now), false);
    // other keys are independent
    assert.equal(rl.hit('other', now), true);
    // after the window resets the key recovers
    assert.equal(rl.hit('ip', now + 1001), true);
  });
});
