# Audit findings & fix status (2026-09-24)

Two independent audits were run against the implementation (tunnel correctness vs.
reference panels; security of the admin API / anti-abuse design). This file tracks
every finding and what was done about it. Test evidence: 92/92 automated tests
(62 unit + 6 security regressions + 16 live HTTP E2E + 8 live WS tunnel E2E).

## Fixed — tunnel correctness (`src/proxy/ws.ts` unless noted)

| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| T1 | CRITICAL | `binaryType` never set → frames arrive as Blob → `toBytes()` returned null and every client frame was silently dropped (total stall, 101 with zero bytes moved) | `server.binaryType = 'arraybuffer'` right after `accept()` + Blob branch in the readable source (belt & braces) |
| T2 | CRITICAL | UDP/DNS sessions dialed a real TCP socket to the DNS server before the `command===2` branch (orphan socket = one of six CF slots; a refused connect killed the working DoH path) | `openRemote()` only in the TCP branch; UDP goes straight to `phase='udp'` |
| T3 | HIGH | Fallback (`proxyIPs`) dead for Trojan (`headerSent` started true) and never attempted on connect failure | switch driven by `gotData` (bytes actually read); `pumpRemote` handles a null remote and falls into the same retry chain |
| T4 | HIGH | Retry replayed only `firstPayload`; later bytes were lost → corrupted stream after fallback | `sentLog` replays everything written (capped at 128KB → beyond that fallback is disabled instead of corrupting) |
| T5 | HIGH | Client frames dropped while `writer` was null (retry window) | `pendingWrites` queue, flushed after reconnect; 4MB overflow guard |
| T6 | HIGH | `releaseLock()` racing an in-flight `write()` killed a healthy tunnel (1011) | `retrying` flag: writes are queued instead of failing during teardown |
| T7 | HIGH | Per-user default 8 / isolate cap 500 exceeded Cloudflare's 6-simultaneous-outbound limit | `ISOLATE_BUDGET = 5` (one slot reserved for DoH); default `maxConnsPerUser = 5` |
| T8 | HIGH | Hostname destinations never re-checked after DNS resolution (attacker name → `169.254.169.254`) | DoH pre-resolve (`ensurePublicDestination`, A+AAAA, 5-min per-isolate cache) run through the egress guard before `connect()`; resolver outage fails open, NXDOMAIN refuses |
| T9 | MEDIUM | Protocol header had to fit in one WebSocket frame | `headerBuf` accumulates frames until the header parses (cap 512B); parsers now distinguish `short` (wait) from definitive failures |
| T10 | MEDIUM | Unhandled rejections could leave sockets hanging | `.catch` on `pumpRemote`, `socket.closed` observed, `runTunnel` failure closes the WS, `pushLog` never throws |
| T11 | MEDIUM | `maxUpgradesPerMinute` setting ignored (hardcoded 30/min) | `upgradeAllowed(settings.maxUpgradesPerMinute, ip)` — limiter built per limit value |
| T12 | MEDIUM | Quota check ignored previously used bytes | `usedUp + usedDown + up + down >= limitBytes` |
| T13 | MEDIUM | Full user scan from KV on every upgrade / bad-token log thrash | handshake-reject logs throttled per IP (30s window); sub route rate-limited 60/min/IP |
| T14 | LOW | `settingsFor` memoised forever (rejected promise poisoned the isolate) | no promise memo — 30s `cachedGet` TTL only (see S6) |

## Fixed — security (`src/http/admin-api.ts`, `src/core/*`, UI)

| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| S1 | HIGH | DNS-name SSRF bypass of private/metadata block | T8 (shared fix) |
| S2 | HIGH | `proxyIPs` fallback entries skipped the guard entirely | `checkDestination` inside `tryFallback()` **and** in `validateSettings` (host+port format, private IPs rejected) |
| S3 | HIGH | CSRF: no Origin/SameSite-independent check on state changes | non-GET with a mismatched `Origin` → 403 (browser-only path; API clients unaffected) |
| S4 | HIGH | `PUT /settings` could overwrite `adminPassHash` (reset to first-run) | key stripped before merge; hash also stripped from GET/PUT responses |
| S5 | HIGH | `egressPorts: []` = "any port" = open proxy | empty list rejected |
| S6 | MED-HIGH | Settings memoised per isolate forever (path rotation never propagated) | promise memo removed; 30s TTL cache only |
| S7 | MED | Unauthenticated `kv.list` scans unbounded per token guess | 60/min/IP limiter + throttled bad-token logging |
| S8 | MED | `kv.list` unpaginated (1000-key cap silently dropped users) | cursor pagination in `listUsers` (mock paginates too) |
| S9 | MED | `GET /settings` returned PBKDF2 salt+hash to the browser | stripped |
| S10 | MED | `maxConns`/`maxUpgradesPerMinute` accepted non-integers → caps silently off | `Number.isInteger` validation |
| S11 | MED | Panel contract break: `maxConns: 0` ("default") rejected | 0/null → `null` (inherit) |
| S12 | MED | `/setup` unauthenticated and unrate-limited | same `RateLimiter` as login (`setup:<ip>`), password ≤256 before hashing |
| S13 | MED | `defaultLimitBytes` / `defaultExpiryDays` displayed but never applied | applied in `createUser` when the request omits them |
| S14 | LOW | No `cache-control: no-store` on admin JSON (bodies carry sub tokens) | added in `json()` |
| S15 | LOW | `/api/session` disclosed brand pre-auth | brand only when authenticated |
| S16 | LOW | Malformed cookie → `URIError` → 503 | `decodeURIComponent` guarded → 401 |
| S17 | LOW | Subscription accepted POST; camo proxied arbitrary methods | 405 for non-GET/HEAD |
| S18 | LOW | No `Referrer-Policy` (adminPath/subPath leak via Referer) | `no-referrer` on every HTML response |
| S19 | LOW | `subPath` interpolated raw into `innerHTML` (stored XSS if KV hand-edited) | wrapped in `esc()` (`panel.html`) |
| S20 | LOW | Default admin path 32 bits of entropy | `randomHex(12)` (96 bits) |

## Deferred (documented, not yet implemented)

- **Session epoch on password change** (stolen session survives credential rotation, ≤12h). Requires versioning `s:` keys + settings write; planned as `s:<epoch>:<token>`.
- **Content-Security-Policy** on the admin HTML: the panel relies on inline scripts, so a useful CSP needs nonces and a browser QA pass first.
- **Cookie-only API auth** (drop `x-session`/localStorage): panel currently authenticates via header; rework touches the whole UI session flow.
- **Per-isolate limits are soft** by design (login 10/min, upgrades, 60/min sub, guard windows): effective limits multiply with isolate count. Documented; a Durable Object would make them global.
- **Dashboard "online" is per-isolate** — should be labelled/aggregated if accuracy matters.

## Verified clean

No open redirect (no redirects at all), no CORS output, no session fixation,
user-controlled fields escaped at every HTML injection point, `allowPrivateDest`
cannot be enabled via the API (metadata IP always blocked, even in dev), 192-bit
session tokens / 80-bit sub tokens, constant-time password compare, KV key
namespaces cannot collide, shared isolate cache holds only `settings`.
