import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { looksLikeProtob, parseProtobHeader, protobPasswordHex } from '../src/proxy/protob.ts';

const PASSWORD = '11111111-2222-4333-8444-555555555555';
const HASH = protobPasswordHex(PASSWORD);
const known = new Set([HASH]);

function buildProtob(opts: {
  hash?: string;
  host: string;
  port: number;
  cmd?: number;
  payload?: string;
  atyp?: 1 | 3 | 4;
}): Uint8Array {
  const head: number[] = [];
  for (const ch of opts.hash ?? HASH) head.push(ch.charCodeAt(0));
  head.push(0x0d, 0x0a, opts.cmd ?? 1);
  const atyp = opts.atyp ?? (opts.host.includes(':') ? 4 : /^\d+\.\d+\.\d+\.\d+$/.test(opts.host) ? 1 : 3);
  head.push(atyp);
  if (atyp === 1) {
    for (const p of opts.host.split('.').map(Number)) head.push(p);
  } else if (atyp === 3) {
    const bytes = new TextEncoder().encode(opts.host);
    head.push(bytes.length, ...bytes);
  } else {
    for (const g of opts.host.split(':')) {
      const v = parseInt(g, 16);
      head.push((v >> 8) & 0xff, v & 0xff);
    }
  }
  head.push((opts.port >> 8) & 0xff, opts.port & 0xff);
  const payload = new TextEncoder().encode(opts.payload ?? '');
  const out = new Uint8Array(head.length + payload.length);
  out.set(head, 0);
  out.set(payload, head.length);
  return out;
}

describe('protob header parsing', () => {
  it('sha224 password matches node:crypto via the wire hash', () => {
    assert.match(HASH, /^[0-9a-f]{56}$/);
    assert.equal(HASH, createHash('sha224').update(PASSWORD).digest('hex'));
  });

  it('parses a domain target (atyp 3)', () => {
    const pkt = buildProtob({ host: 'example.com', port: 443, payload: 'hello' });
    assert.equal(looksLikeProtob(pkt), true);
    const r = parseProtobHeader(pkt, known);
    assert.equal(r.ok, true);
    if (!r.ok) return;
    assert.equal(r.host, 'example.com');
    assert.equal(r.port, 443);
    assert.equal(r.passwordHex, HASH);
    assert.equal(new TextDecoder().decode(pkt.subarray(r.payloadStart)), 'hello');
  });

  it('parses IPv4 (atyp 1) and IPv6 (atyp 4)', () => {
    const v4 = parseProtobHeader(buildProtob({ host: '1.2.3.4', port: 80 }), known);
    assert.equal(v4.ok && v4.host, '1.2.3.4');
    assert.equal(v4.ok && v4.port, 80);

    const v6 = parseProtobHeader(buildProtob({ host: '2001:db8:0:0:0:0:0:1', port: 443 }), known);
    assert.equal(v6.ok && v6.host, '2001:db8:0:0:0:0:0:1');
  });

  it('rejects an unknown password hash', () => {
    const pkt = buildProtob({ host: 'example.com', port: 443, hash: 'f'.repeat(56) });
    const r = parseProtobHeader(pkt, known);
    assert.equal(r.ok, false);
    assert.equal(r.ok === false && r.reason, 'password-mismatch');
  });

  it('rejects packets that do not have the 56-hex + CRLF prefix', () => {
    assert.equal(looksLikeProtob(new Uint8Array(100)), false);
    assert.equal(looksLikeProtob(buildProtob({ host: 'x.com', port: 1 }).subarray(0, 40)), false);
    const bad = buildProtob({ host: 'x.com', port: 443 });
    bad[10] = 0x41; // 'A' is not lowercase hex
    assert.equal(looksLikeProtob(bad), false);
  });

  it('rejects unsupported commands', () => {
    const r = parseProtobHeader(buildProtob({ host: 'example.com', port: 443, cmd: 2 }), known);
    assert.equal(r.ok, false);
    assert.equal(r.ok === false && r.reason, 'unsupported-command');
  });
});
