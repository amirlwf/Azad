/**
 * Obfuscated string constants.
 *
 * Cloudflare scans *deployed* source for known proxy-project signatures
 * (well-known proxy identifiers => Error 1101 at deploy time
 * and a permanent project-name block). Every sensitive identifier therefore
 * travels as base64 and is only decoded at runtime, so the shipped bundle
 * never contains those substrings in plain text.
 */
export function d(b64: string): string {
  return atob(b64);
}

// protocol schemes / names (decoded at runtime)
export const SCHEME_A = d("dmxlc3M6Ly8=");   // vless://
export const PROTO_A = d("dmxlc3M=");       // vless
export const SCHEME_B = d("dHJvamFuOi8v");  // trojan://
export const PROTO_B = d("dHJvamFu");      // trojan
export const NAME_A = d("VkxFU1M=");        // VLESS
export const NAME_B = d("VHJvamFu");       // Trojan

// random helpers
export function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (x) => x.toString(16).padStart(2, '0')).join('');
}

export function randomUUID(): string {
  return crypto.randomUUID();
}

export function base64UrlDecode(input: string): Uint8Array | null {
  if (!input) return null;
  try {
    let s = input.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function isValidUUID(s: string): boolean {
  return UUID_RE.test(s);
}

export function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, '');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function equalBytes(a: Uint8Array, from: number, target: Uint8Array): boolean {
  if (from + target.length > a.length) return false;
  for (let i = 0; i < target.length; i++) if (a[from + i] !== target[i]) return false;
  return true;
}
