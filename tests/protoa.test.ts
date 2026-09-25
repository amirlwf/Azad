import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseProtoaHeader, encodeProtoaUdpPacket, protoaResponseHeader, readAddressValue } from '../src/proxy/protoa.ts';
import { uuidToBytes, isValidUUID, bytesToHex } from '../src/core/codecs.ts';

const UUID_A = '11111111-2222-4333-8444-555555555555';
const UUID_B = '99999999-8888-4777-8666-555555555555';
const known = [uuidToBytes(UUID_A), uuidToBytes(UUID_B)];

function buildProtoa(opts: {
  uuid: string;
  host: string;
  port: number;
  payload?: string;
  version?: number;
  command?: number;
  optLen?: number;
  atyp?: 1 | 2 | 3;
}): Uint8Array {
  const head: number[] = [opts.version ?? 0];
  const hex = opts.uuid.replace(/-/g, '');
  for (let i = 0; i < 32; i += 2) head.push(parseInt(hex.slice(i, i + 2), 16));
  const optLen = opts.optLen ?? 0;
  head.push(optLen);
  for (let i = 0; i < optLen; i++) head.push(0); // padding options
  head.push(opts.command ?? 1);
  head.push((opts.port >> 8) & 0xff, opts.port & 0xff);

  const atyp = opts.atyp ?? (opts.host.includes(':') ? 3 : /^\d+\.\d+\.\d+\.\d+$/.test(opts.host) ? 1 : 2);
  head.push(atyp);
  if (atyp === 1) {
    for (const p of opts.host.split('.').map(Number)) head.push(p);
  } else if (atyp === 2) {
    const bytes = new TextEncoder().encode(opts.host);
    head.push(bytes.length, ...bytes);
  } else {
    const parts = opts.host.split(':');
    // expand nothing: tests use full 8-group form
    for (const g of parts) {
      const v = parseInt(g, 16);
      head.push((v >> 8) & 0xff, v & 0xff);
    }
  }
  const payload = new TextEncoder().encode(opts.payload ?? '');
  const out = new Uint8Array(head.length + payload.length);
  out.set(head, 0);
  out.set(payload, head.length);
  return out;
}

describe('protoa header parsing', () => {
  it('parses a domain target and returns the payload offset', () => {
    const pkt = buildProtoa({ uuid: UUID_A, host: 'example.com', port: 443, payload: 'GET / HTTP/1.1' });
    const r = parseProtoaHeader(pkt, known);
    assert.equal(r.ok, true);
    if (!r.ok) return;
    assert.equal(r.host, 'example.com');
    assert.equal(r.port, 443);
    assert.equal(r.command, 1);
    assert.equal(r.version, 0);
    assert.equal(bytesToHex(r.uuidMatched), UUID_A.replace(/-/g, ''));
    assert.equal(new TextDecoder().decode(pkt.subarray(r.payloadStart)), 'GET / HTTP/1.1');
  });

  it('parses IPv4 and IPv6 targets', () => {
    const v4 = parseProtoaHeader(buildProtoa({ uuid: UUID_A, host: '93.184.216.34', port: 80 }), known);
    assert.equal(v4.ok && v4.host, '93.184.216.34');
    assert.equal(v4.ok && v4.port, 80);

    const v6 = parseProtoaHeader(
      buildProtoa({ uuid: UUID_B, host: '2606:2800:220:1:248:1893:25c8:1946', port: 443 }),
      known,
    );
    assert.equal(v6.ok && v6.host, '2606:2800:220:1:248:1893:25c8:1946');
  });

  it('honours option padding (optLen) when locating the command', () => {
    const pkt = buildProtoa({ uuid: UUID_A, host: 'a.example.org', port: 8443, optLen: 7, payload: 'xyz' });
    const r = parseProtoaHeader(pkt, known);
    assert.equal(r.ok, true);
    if (!r.ok) return;
    assert.equal(r.host, 'a.example.org');
    assert.equal(r.port, 8443);
    assert.equal(new TextDecoder().decode(pkt.subarray(r.payloadStart)), 'xyz');
  });

  it('rejects an unknown uuid', () => {
    const pkt = buildProtoa({ uuid: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', host: 'example.com', port: 443 });
    const r = parseProtoaHeader(pkt, known);
    assert.deepEqual(r, { ok: false, reason: 'uuid-mismatch' });
  });

  it('rejects truncated headers', () => {
    const pkt = buildProtoa({ uuid: UUID_A, host: 'example.com', port: 443 });
    assert.equal(parseProtoaHeader(pkt.subarray(0, 10), known).ok, false);
    assert.equal(parseProtoaHeader(new Uint8Array(0), known).ok, false);
  });

  it('rejects unsupported commands', () => {
    const pkt = buildProtoa({ uuid: UUID_A, host: 'example.com', port: 443, command: 3 });
    assert.equal(parseProtoaHeader(pkt, known).ok, false);
  });

  it('handles udp command and reports the destination', () => {
    const pkt = buildProtoa({ uuid: UUID_A, host: '8.8.8.8', port: 53, command: 2 });
    const r = parseProtoaHeader(pkt, known);
    assert.equal(r.ok && r.command, 2);
    assert.equal(r.ok && r.port, 53);
  });

  it('builds the expected response header', () => {
    assert.deepEqual([...protoaResponseHeader(0)], [0, 0]);
    assert.deepEqual([...protoaResponseHeader(1)], [1, 0]);
  });

  it('frames UDP packets with a big-endian length prefix', () => {
    const framed = encodeProtoaUdpPacket(new Uint8Array([1, 2, 3]));
    assert.deepEqual([...framed], [0, 3, 1, 2, 3]);
    assert.deepEqual([...encodeProtoaUdpPacket(new Uint8Array(0))], [0, 0]);
  });

  it('readAddressValue bounds-checks', () => {
    assert.equal(readAddressValue(new Uint8Array([2, 5, 97]), 0), null);
    assert.equal(readAddressValue(new Uint8Array([1, 1, 2]), 0), null);
  });
});

describe('uuid helpers', () => {
  it('validates uuids', () => {
    assert.equal(isValidUUID(UUID_A), true);
    assert.equal(isValidUUID('not-a-uuid'), false);
    assert.equal(isValidUUID('11111111222243338444555555555555'), false);
  });

  it('round-trips uuid bytes', () => {
    assert.equal(bytesToHex(uuidToBytes(UUID_A)), UUID_A.replace(/-/g, ''));
  });
});
