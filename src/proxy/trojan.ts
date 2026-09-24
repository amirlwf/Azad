import { bytesToHex } from '../core/codecs.ts';
import { sha224Bytes } from '../core/sha224.ts';

/**
 * Trojan header parsing (client -> worker).
 *
 * Wire layout:
 *   hex(sha224(password))  56 bytes, lowercase hex
 *   CRLF                   0x0d 0x0a
 *   CMD                    0x01 = connect
 *   ATYP                   SOCKS5 style: 1 = IPv4, 3 = domain, 4 = IPv6
 *   ADDR + PORT (BE16)
 *   payload
 *
 * The password embedded in generated links is the user's UUID, so the wire
 * form is sha224(uuid); the server precomputes one hex string per user and
 * compares it against the first 56 bytes.
 */

const decoder = new TextDecoder();

export type TrojanResult =
  | { ok: true; host: string; port: number; payloadStart: number; passwordHex: string }
  /** `short: true` = truncated, caller should wait for more bytes */
  | { ok: false; reason: string; short?: boolean };

/** cheap shape check so we do not hash on clearly non-trojan traffic */
export function looksLikeTrojan(data: Uint8Array): boolean {
  if (data.length < 59) return false;
  if (data[56] !== 0x0d || data[57] !== 0x0a) return false;
  for (let i = 0; i < 56; i++) {
    const c = data[i];
    const isHex = (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66);
    if (!isHex) return false;
  }
  return true;
}

export function trojanPasswordHex(password: string): string {
  return bytesToHex(sha224Bytes(new TextEncoder().encode(password)));
}

export function parseTrojanHeader(data: Uint8Array, knownPasswords: Set<string>): TrojanResult {
  if (data.length < 58) return { ok: false, reason: 'short-header', short: true };

  // hex(sha224) + CRLF — definitive shape check on the first 58 bytes
  if (data[56] !== 0x0d || data[57] !== 0x0a) return { ok: false, reason: 'bad-prefix' };
  for (let i = 0; i < 56; i++) {
    const c = data[i];
    const isHex = (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66);
    if (!isHex) return { ok: false, reason: 'bad-prefix' };
  }

  const got = decoder.decode(data.subarray(0, 56));
  if (!knownPasswords.has(got)) return { ok: false, reason: 'password-mismatch' };

  let p = 58; // skip hex + CRLF
  if (p >= data.length) return { ok: false, reason: 'short-header', short: true };
  if (data[p] !== 0x01) return { ok: false, reason: 'unsupported-command' };
  p += 1;

  const addr = readAddress(data, p);
  if (!addr) {
    // distinguish a truncated address from an unknown ATYP
    const atyp = p < data.length ? data[p] : -1;
    if (atyp !== 0x01 && atyp !== 0x03 && atyp !== 0x04) return { ok: false, reason: 'bad-address' };
    return { ok: false, reason: 'short-header', short: true };
  }
  return { ok: true, host: addr.host, port: addr.port, payloadStart: addr.next, passwordHex: got };
}

function readAddress(
  data: Uint8Array,
  at: number,
): { host: string; port: number; next: number } | null {
  if (at >= data.length) return null;
  const atyp = data[at];
  let p = at + 1;
  let host = '';
  if (atyp === 0x01) {
    if (p + 4 > data.length) return null;
    host = `${data[p]}.${data[p + 1]}.${data[p + 2]}.${data[p + 3]}`;
    p += 4;
  } else if (atyp === 0x03) {
    if (p >= data.length) return null;
    const len = data[p];
    p += 1;
    if (p + len > data.length) return null;
    host = decoder.decode(data.subarray(p, p + len));
    p += len;
  } else if (atyp === 0x04) {
    if (p + 16 > data.length) return null;
    const parts: string[] = [];
    for (let i = 0; i < 8; i++) parts.push(((data[p + i * 2] << 8) | data[p + i * 2 + 1]).toString(16));
    host = parts.join(':');
    p += 16;
  } else {
    return null;
  }
  if (p + 2 > data.length) return null;
  const port = (data[p] << 8) | data[p + 1];
  p += 2;
  return { host, port, next: p };
}
