/**
 * Content-Security-Policy helpers for the admin panel and user portal.
 *
 * Every inline <script> in the HTML templates carries nonce="__CSP_NONCE__";
 * each response mints a fresh 128-bit nonce and replaces the placeholder, so
 * an injected value can never ride an older page. Styles deliberately stay
 * 'unsafe-inline': the UI uses style attributes throughout and CSS cannot
 * execute code. The templates contain no inline event handlers.
 */

export function newNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function injectNonce(html: string, nonce: string): string {
  return html.replaceAll('__CSP_NONCE__', () => nonce);
}

export function cspHeader(nonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    "style-src 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "font-src 'self'",
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
  ].join('; ');
}

/** local camouflage page ships no scripts at all */
export const CAMO_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'";
