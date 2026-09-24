# Cloudflare Worker Ban (Error 1101 / Account Suspension) — Root Causes

Source: blog.cmliussss.com/p/CF1101/ (author of cmliu/edgetunnel ecosystem), GitHub issues
cmliu/edgetunnel#950, #1262, #1276, V2EX thread, community reports (2024-2026).

## Two distinct failure modes

### A) Error 1101 (project-level, appears after ~hours-days of use)
Trigger conditions, in order of likelihood:
1. **Code signature detection at deploy time** — CF scans deployed source for known
   fingerprint strings of proxy projects. Threshold of matches -> 1101, and the
   project NAME goes onto a permanent name blacklist.
2. **Request-count review** — around ~110k total requests CF performs a *code review*
   of the project; failing it -> 1101. (Workers projects have a ~100k/day request cap
   that resets daily and does NOT trigger the review; Pages projects do trigger it.)
   Paradox: obfuscation raises the chance of failing the manual/automated review.
3. **Project-name blacklist** — names containing: `edgetunnel`, `edtunnel`, `epeius`,
   `bpb`, `cmliu`, `vless`, `trojan` -> instant 1101.
4. **Domain blacklist** — after repeated 1101s, the account's workers.dev subdomain
   and custom domains get blacklisted (workers.dev -> 1101, custom domain -> 522).

Fix: once 1101, no code edit helps — the project must be deleted and redeployed
under a fresh name; if domain blacklisted, change first subdomain label.

### B) Account suspension (login blocked, "possible ToS violation")
- CF Terms (Nov 2024 update) explicitly prohibit using Workers as a VPN/proxy.
- Automated abuse classification of the Worker source (VLESS/VMess/Trojan proxies).
- Fresh accounts used immediately = high risk ("养号": age the account ~2 weeks first).
- Open-proxy behavior (worker connects to ANY destination requested by the client)
  makes abuse reports / traffic patterns easy to classify.
- Sharing the deployment publicly (GitHub one-click deploy badges, shared links)
  multiplies request volume and abuse signals -> ban.

## Practical mitigation list (what we must implement)
1. Never ship strings: vless/vmess/trojan/edgetunnel/bpb in project name, paths,
   worker variable names, comments. Protocol names only appear in *client-facing*
   generated links (subscription output), never in the worker source as literals —
   build-time encoding (e.g. base64/rot13 of constants, generic function names).
2. Build pipeline: esbuild minify + mangle (terser) as the ONLY deploy artifact;
   source repo stays clean/modular.
3. Deploy as a **Workers** project (not Pages) with a name that is not on the
   blacklist, to stay under the request-review threshold (daily ~100k cap).
4. Restrict destinations: block private/loopback/link-local/metadata IP ranges and
   only allow outbound to configured proxy-IP list or domain destinations -> no
   open proxy (also fixes the classic abuse classification).
5. Rate limiting + per-UUID connection caps in the worker.
6. Prefer custom domain attached to a personal zone over workers.dev; rotate
   subdomain label if 522 appears.
7. Account hygiene: age accounts, don't share links, keep daily requests modest.
8. Human-looking panel (real HTML UI, no protocol keywords in HTML/JS of the UI).
