import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { defaultSettings } from '../src/core/settings.ts';
import { makeUser } from '../src/core/users.ts';
import { endpoints, buildLinks, toBase64, toClash, toSingBox, portalPayload, subscriptionHeaders } from '../src/http/configs.ts';

const s = defaultSettings();
const host = 'example.workers.dev';
const user = makeUser({ name: 'tester' }, 0);

describe('endpoints', () => {
  it('lists cloudflare-supported ports with a tls flag', () => {
    const list = endpoints(s);
    assert.ok(list.length > 0);
    const ports = new Set<number>();
    for (const e of list) {
      assert.ok(Number.isInteger(e.port) && e.port > 0 && e.port <= 65535);
      assert.equal(typeof e.tls, 'boolean');
      ports.add(e.port);
    }
    assert.ok(ports.has(443) && ports.has(80), 'standard ports must be present');
  });
});

describe('buildLinks', () => {
  it('returns one link per endpoint, all parseable', () => {
    const links = buildLinks(user, s, host);
    const perEndpoint = s.mode === 'both' ? 2 : 1;
    assert.equal(links.length, endpoints(s).length * perEndpoint);
    for (const link of links) {
      const scheme = link.slice(0, link.indexOf(':'));
      assert.ok(scheme === 'vless' || scheme === 'trojan', `unexpected scheme: ${scheme}`);
      const url = new URL(link);
      assert.ok(url.username, 'credentials required');
      assert.equal(url.searchParams.get('type'), 'ws');
      const sec = url.searchParams.get('security');
      assert.ok(sec === 'tls' || sec === 'none' || sec === 'reality', `bad security=${sec}`);
      assert.ok(url.searchParams.get('path')?.startsWith('/'));
    }
  });

  it('embeds the uuid/password as username and never leaks internals', () => {
    const links = buildLinks(user, s, host);
    const joined = links.join('\n');
    if (s.mode === 'a' || s.mode === 'both') {
      assert.ok(joined.includes(user.uuid), 'uuid missing from links');
    }
    assert.ok(!joined.includes('adminPassHash'));
    assert.ok(!joined.includes(s.wsPath + '"'));
  });

  it('base64 subscription decodes back to newline separated links', () => {
    const raw = buildLinks(user, s, host).join('\n');
    const b64 = toBase64(raw);
    assert.match(b64, /^[A-Za-z0-9+/=]+$/);
    assert.equal(Buffer.from(b64, 'base64').toString('utf8'), raw);
  });
});

describe('client configs', () => {
  it('clash yaml is structurally valid and references the proxy group', () => {
    const yaml = toClash(user, s, host);
    assert.ok(yaml.includes('proxies:'));
    assert.ok(yaml.includes('proxy-groups:'));
    assert.ok(yaml.includes('rules:'));
    assert.ok(yaml.includes(`name: ${user.name}`) || yaml.includes('name: '));
    // minimal indentation sanity: every list item under proxies uses "- name:"
    assert.ok(/\n\s+-\s+name:/.test(yaml));
  });

  it('sing-box json parses and has selector + outbound entries', () => {
    const json = JSON.parse(toSingBox(user, s, host));
    assert.ok(Array.isArray(json.outbounds));
    const types = json.outbounds.map((o: any) => o.type);
    const selector = json.outbounds.find((o: any) => o.type === 'selector');
    assert.ok(selector, 'selector outbound missing');
    assert.ok(types.some((t: string) => t === 'vless' || t === 'trojan'));
    assert.ok(Array.isArray(selector.outbounds) && selector.outbounds.length > 0, 'selector must list tags');
  });

  it('sing-box outbound uses wire-format host/port without scheme', () => {
    const json = JSON.parse(toSingBox(user, s, host));
    const real = json.outbounds.find((o: any) => o.type === 'vless' || o.type === 'trojan');
    assert.ok(typeof real.server === 'string' && !real.server.includes('://'));
    assert.ok(Number.isInteger(real.server_port));
    assert.equal(real.transport.type, 'ws');
    assert.ok(real.transport.path.startsWith(s.wsPath), `path ${real.transport.path} must start with ${s.wsPath}`);
    assert.ok(real.tls, 'tls block required');
    assert.equal(real.tls.server_name, real.server);
  });
});

describe('portal payload', () => {
  it('contains user identity, links and quota info', () => {
    const p: any = portalPayload(user, s, host);
    assert.equal(p.name, user.name);
    assert.ok(Array.isArray(p.links) && p.links.length > 0);
    assert.equal(typeof p.usedUp, 'number');
    assert.equal(typeof p.usedDown, 'number');
    assert.equal(typeof p.limitBytes, 'number');
    assert.equal(p.state, true);
    assert.equal(p.brand, s.brand);
    assert.ok(p.rawPath && p.base64Path && p.clashPath && p.singboxPath);
    // must never expose admin internals to subscribers
    const json = JSON.stringify(p);
    assert.ok(!json.includes('adminPassHash'));
    assert.ok(!json.includes('adminPath'));
  });
});

describe('subscription headers', () => {
  it('sets content-type and traffic accounting for raw/base64', () => {
    const h = subscriptionHeaders(user, s, 'test.txt', 'text/plain; charset=utf-8');
    assert.equal(h['content-type'], 'text/plain; charset=utf-8');
    assert.ok(h['subscription-userinfo'].includes('upload='));
    assert.ok(h['subscription-userinfo'].includes('expire='));
    assert.equal(h['profile-update-interval'], '6');
  });
});


describe('config parity (edgetunnel/nahan reference quality)', () => {
  const hostRef = 'example.workers.dev';
  const userRef = makeUser({ name: 'parity' }, 0);

  it('vless links carry encryption=none, trojan links never carry it', () => {
    const sV = { ...defaultSettings(), mode: 'a' as const };
    for (const l of buildLinks(userRef, sV, hostRef)) {
      assert.ok(l.startsWith('vless://'), l);
      assert.ok(l.includes('&encryption=none'), `missing encryption attr: ${l}`);
    }
    const sT = { ...defaultSettings(), mode: 'b' as const };
    for (const l of buildLinks(userRef, sT, hostRef)) {
      assert.ok(l.startsWith('trojan://'), l);
      assert.ok(!l.includes('encryption'), `trojan must not carry encryption: ${l}`);
    }
  });

  it('every tls link has sni + fingerprint + alpn and an early-data path', () => {
    const sV = { ...defaultSettings(), mode: 'a' as const };
    for (const l of buildLinks(userRef, sV, hostRef)) {
      const u = new URL(l);
      if (u.searchParams.get('security') !== 'tls') continue;
      assert.ok(u.searchParams.get('sni'), l);
      assert.ok(u.searchParams.get('fp'), l);
      assert.ok(u.searchParams.get('alpn'), l);
      assert.ok(u.searchParams.get('path')?.includes('ed='), `early data missing: ${l}`);
    }
  });

  it('clash output carries servername (vless) / sni (trojan), alpn and fingerprint', () => {
    const yaml = toClash(userRef, defaultSettings(), hostRef);
    if (defaultSettings().mode !== 'b') assert.ok(/\n\s+servername:/.test(yaml), 'vless servername missing');
    if (defaultSettings().mode !== 'a') assert.ok(/\n\s+sni:/.test(yaml), 'trojan sni missing');
    assert.ok(/\n\s+alpn:\n\s+- http\/1\.1/.test(yaml), 'alpn block missing');
    assert.ok(/\n\s+client-fingerprint:/.test(yaml), 'fingerprint missing');
  });

  it('sing-box outbounds pin tls alpn and do not use the obsolete network field', () => {
    const cfg = JSON.parse(toSingBox(userRef, defaultSettings(), hostRef));
    const real = cfg.outbounds.find((o: any) => o.type === 'vless' || o.type === 'trojan');
    assert.ok(real, 'no protocol outbound');
    assert.ok(!('network' in real), 'obsolete top-level network field must be gone');
    assert.ok(real.transport?.type === 'ws');
    assert.deepEqual(real.tls.alpn, ['http/1.1']);
  });
});


describe('clash early-data + udp honesty', () => {
  it('uses max-early-data (not ?ed= in path) and udp: false', () => {
    const yaml = toClash(makeUser({ name: 'ed' }, 0), defaultSettings(), 'example.workers.dev');
    assert.ok(yaml.includes('max-early-data: 2560'), 'max-early-data missing');
    assert.ok(yaml.includes('early-data-header-name: Sec-WebSocket-Protocol'), 'early-data header missing');
    assert.ok(/\n\s+udp: false/.test(yaml), 'udp must be false (our UDP path is DNS-only)');
    const m = /ws-opts:\n\s+path: '([^']+)'/.exec(yaml);
    assert.ok(m, 'ws-opts.path missing');
    assert.ok(!m[1].includes('ed='), `clash path must be query-free: ${m[1]}`);
  });
});


describe('sing-box early-data (BPB style)', () => {
  it('transport has query-free path + max_early_data', () => {
    const cfg = JSON.parse(toSingBox(makeUser({ name: 'sb' }, 0), defaultSettings(), 'example.workers.dev'));
    const ob = cfg.outbounds.find((o: { type?: string }) => o.type === 'vless');
    assert.ok(ob, 'vless outbound missing');
    assert.equal(ob.transport.type, 'ws');
    assert.ok(!ob.transport.path.includes('?'), `path must be query-free: ${ob.transport.path}`);
    assert.equal(ob.transport.max_early_data, 2560);
    assert.equal(ob.transport.early_data_header_name, 'Sec-WebSocket-Protocol');
  });
});
