import { createHash, randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { sha224Bytes, sha224Hex } from '../src/core/sha224.ts';

const hex = (buf: Uint8Array) => Buffer.from(buf).toString('hex');

describe('sha224', () => {
  it('matches node:crypto for the empty string', () => {
    assert.equal(sha224Hex(''), createHash('sha224').update('').digest('hex'));
  });

  it('matches node:crypto for arbitrary strings', () => {
    const samples = [
      'a',
      'abc',
      '00000000-0000-4000-8000-000000000000',
      'x'.repeat(55), // padding edge: one byte short of the 64-byte block
      'y'.repeat(56), // crosses the block boundary
      'z'.repeat(64),
      'پیام فارسی با طول بلند برای تست',
    ];
    for (const s of samples) {
      assert.equal(sha224Hex(s), createHash('sha224').update(s, 'utf8').digest('hex'), `mismatch for ${s.slice(0, 12)}`);
    }
  });

  it('matches node:crypto for random bytes', () => {
    for (let i = 0; i < 25; i++) {
      const bytes = randomBytes(1 + Math.floor(Math.random() * 300));
      const expected = createHash('sha224').update(bytes).digest('hex');
      assert.equal(hex(sha224Bytes(new Uint8Array(bytes))), expected);
    }
  });

  it('always returns 28 bytes', () => {
    assert.equal(sha224Bytes(new TextEncoder().encode('hello')).length, 28);
  });
});
