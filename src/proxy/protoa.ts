import { equalBytes } from '../core/codecs.ts';

/**
 * PROTOA header parsing (client -> worker).
 *
 * Wire layout (matches Xray / BPB / edgetunnel parsers):
 *   [0]      version
 *   [1..17)  16-byte UUID
 *   [17]     option length (1 byte)
 *   [18+n)   cmd        1 = TCP, 2 = UDP
 *   [..]     port       big-endian 16
 *   [..]     atyp       1 = IPv4, 2 = domain(+len), 3 = IPv6
 *   [..]     address value
 *   [...]    payload    (there is NO port after the address)
 */

export interface ParsedAddress {
  host: string;
  port: number;
  /** offset right after the header — the rest is already application data */
  payloadStart: number;
}

export type ProtoaResult =
  | ({ ok: true; version: number; command: number; uuidMatched: Uint8Array } & ParsedAddress)
  /** `short: true` = input was truncated, caller should wait for more bytes */
  | { ok: false; reason: string; short?: boolean };

/** address value only (PROTOA puts the port *before* the address) */
export function readAddressValue(
  data: Uint8Array,
  at: number,
): { host: string; next: number } | null {
  if (at >= data.length) return null;
  const atyp = data[at];
  let p = at + 1;
  let host = '';
  if (atyp === 1) {
    if (p + 4 > data.length) return null;
    host = `${data[p]}.${data[p + 1]}.${data[p + 2]}.${data[p + 3]}`;
    p += 4;
  } else if (atyp === 2) {
    if (p >= data.length) return null;
    const len = data[p];
    p += 1;
    if (p + len > data.length) return null;
    host = new TextDecoder().decode(data.subarray(p, p + len));
    p += len;
  } else if (atyp === 3) {
    if (p + 16 > data.length) return null;
    const parts: string[] = [];
    for (let i = 0; i < 8; i++) {
      parts.push(((data[p + i * 2] << 8) | data[p + i * 2 + 1]).toString(16));
    }
    host = parts.join(':');
    p += 16;
  } else {
    return null;
  }
  return { host, next: p };
}

/**
 * @param knownUUIDs enabled-user UUID byte arrays; the header is accepted only
 *        when the embedded UUID matches one of them.
 */
export function parseProtoaHeader(data: Uint8Array, knownUUIDs: Uint8Array[]): ProtoaResult {
  // ver(1) + uuid(16): uuid cannot be judged before it is complete
  if (data.length < 17) return { ok: false, reason: 'short-header', short: true };

  const version = data[0];
  let matched: Uint8Array | null = null;
  for (const uuid of knownUUIDs) {
    if (equalBytes(data, 1, uuid)) {
      matched = uuid;
      break;
    }
  }
  if (!matched) return { ok: false, reason: 'uuid-mismatch' };

  // ver + uuid + optlen + cmd + port + atyp
  if (data.length < 22) return { ok: false, reason: 'short-header', short: true };

  const optLen = data[17];
  let p = 18 + optLen;
  if (p + 4 > data.length) return { ok: false, reason: 'short-header', short: true };

  const command = data[p];
  p += 1;
  if (command !== 1 && command !== 2) return { ok: false, reason: 'bad-command' };

  const port = (data[p] << 8) | data[p + 1];
  p += 2;

  if (p >= data.length) return { ok: false, reason: 'short-header', short: true };
  const atyp = data[p];
  if (atyp !== 1 && atyp !== 2 && atyp !== 3) return { ok: false, reason: 'bad-address' };
  const addr = readAddressValue(data, p);
  if (!addr || !addr.host) return { ok: false, reason: 'short-header', short: true };

  return {
    ok: true,
    version,
    command,
    uuidMatched: matched,
    host: addr.host,
    port,
    payloadStart: addr.next,
  };
}

/** [version, 0] response header the client expects before the first payload byte */
export function protoaResponseHeader(version: number): Uint8Array {
  return new Uint8Array([version, 0]);
}

/** UDP (cmd 2) payload framing: [len BE16][packet] repeated */
export function encodeProtoaUdpPacket(payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + payload.length);
  out[0] = (payload.length >> 8) & 0xff;
  out[1] = payload.length & 0xff;
  out.set(payload, 2);
  return out;
}
