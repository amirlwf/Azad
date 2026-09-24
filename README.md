# Azad Panel

A self-hosted Cloudflare Workers proxy panel: **VLESS + Trojan over WebSocket**, with a
bilingual (fa/en, RTL/LTR) admin panel, user subscription portal, client-config generators
(`vless://`, Clash, sing-box) and a camouflage page — built for **stealth and abuse-resistance**
rather than raw feature count.

> Deployed output (`dist/worker.js`) contains **no recognizable proxy-project signatures** —
> a build-time scanner fails the build if any appear (see `scripts/build.js`).

## Why it exists

Cloudflare Error 1101 bans follow a predictable pattern: recognizable code signatures at
deploy time, banned project/worker names, open-proxy behaviour (no destination validation,
no rate limits) and post-review traffic volume. Research notes: `docs/RESEARCH-ban-rootcause.md`.
Every countermeasure here is architectural:

- obfuscated protocol constants + signature scanner gate (`dist/worker.js` must be clean)
- egress guard: private/metadata IP block (always, even in local dev), port allow-list,
  hostname destinations pre-resolved through DoH and validated before `connect()`
- rate limits: upgrades/min, login attempts, subscription fetches, per-user connection caps,
  Cloudflare's 6-outbound-connection budget respected (`ISOLATE_BUDGET = 5`)
- PBKDF2-hashed admin password (not plaintext KV), 192-bit session tokens, CSRF origin check

## Layout

```
src/core      settings, users, auth (PBKDF2), KV store, egress guard, rate limiters, logs, sha224
src/proxy     vless/trojan header parsers + the WebSocket tunnel (ws.ts)
src/http      admin API, subscription/portal, config builders, camouflage proxy
src/ui        panel.html (admin), portal.html (user), camo.html
src/worker.ts entrypoint / routing
scripts/build.js  inline UI -> bundle -> minify -> signature scan
tests/        92 tests: unit + live E2E (HTTP) + live E2E (WS tunnel round-trips)
docs/         audit findings & fix status, ban root-cause research
```

## Commands

```bash
npm install --include=dev
node scripts/build.js                 # bundle + minify + signature scan (fails on banned tokens)
npx tsc --noEmit                      # typecheck
node --test --experimental-transform-types tests/*.test.ts
# for the E2E suites, first run:
npx wrangler dev --port 8787 --var LOCAL_TEST:1
```

## Deploy

1. `node scripts/build.js`
2. Create a KV namespace, put its id into `wrangler.toml`
3. `npx wrangler deploy`
4. Open the admin path shown in the panel settings (random per instance)

## Test status

92/92 (62 unit + 6 security-regression + 16 live HTTP E2E + 8 live WS tunnel E2E),
`tsc --noEmit` clean, signature scan clean. Audit details: `docs/AUDIT.md`.
