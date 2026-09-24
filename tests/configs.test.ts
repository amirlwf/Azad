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
