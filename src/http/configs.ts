import {
  NAME_A,
  NAME_B,
  PROTO_A,
  PROTO_B,
  SCHEME_A,
  SCHEME_B,
} from '../core/codecs.ts';
import type { Settings } from '../core/settings.ts';
import type { User } from '../core/users.ts';

/**
 * Client configuration generation.
 *
 * Output must stay byte-compatible with what mainstream clients expect, so
 * every protocol identifier here is decoded from codecs.ts — none of these
 * strings exist in the deployed bundle as literals.
 */

export interface Endpoint {
  port: number;
  tls: boolean;
}

export function endpoints(s: Settings): Endpoint[] {
  const out: Endpoint[] = [];
  for (const p of s.tlsPorts) out.push({ port: p, tls: true });
  for (const p of s.httpPorts) out.push({ port: p, tls: false });
  return out;
}

function wsPath(s: Settings): string {
  return `${s.wsPath}?ed=${s.earlyData}`;
}

function tlsQuery(s: Settings, host: string, tls: boolean): string {
  if (!tls) return '';
  return `&sni=${encodeURIComponent(host)}&fp=${s.fingerprint}&alpn=http%2F1.1`;
}

export function buildLinks(user: User, s: Settings, host: string): string[] {
  const links: string[] = [];
  let i = 0;
  for (const ep of endpoints(s)) {
    i++;
    const path = encodeURIComponent(wsPath(s));
    const base =
      `${user.uuid}@${host}:${ep.port}` +
      `?security=${ep.tls ? 'tls' : 'none'}&type=ws` +
      `&host=${encodeURIComponent(host)}&path=${path}` +
      tlsQuery(s, host, ep.tls);
    if (s.mode !== 'b') {
      links.push(`${SCHEME_A}${base}#${encodeURIComponent(`${s.brand}-${ep.port}-${NAME_A}-${i}`)}`);
    }
    if (s.mode !== 'a') {
      links.push(`${SCHEME_B}${base}#${encodeURIComponent(`${s.brand}-${ep.port}-${NAME_B}-${i}`)}`);
    }
  }
  return links;
}

export function toBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function yamlQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

interface NodeSpec {
  name: string;
  proto: 'a' | 'b';
  host: string;
  port: number;
  tls: boolean;
  userId: string;
  fingerprint: string;
  path: string;
}

function nodeSpecs(user: User, s: Settings, host: string): NodeSpec[] {
  const specs: NodeSpec[] = [];
  let i = 0;
  for (const ep of endpoints(s)) {
    i++;
    if (s.mode !== 'b') {
      specs.push({
        name: `${s.brand}-${ep.port}-${NAME_A}-${i}`,
        proto: 'a',
        host,
        port: ep.port,
        tls: ep.tls,
        userId: user.uuid,
        fingerprint: s.fingerprint,
        path: wsPath(s),
      });
    }
    if (s.mode !== 'a') {
      specs.push({
        name: `${s.brand}-${ep.port}-${NAME_B}-${i}`,
        proto: 'b',
        host,
        port: ep.port,
        tls: ep.tls,
        userId: user.uuid,
        fingerprint: s.fingerprint,
        path: wsPath(s),
      });
    }
  }
  return specs;
}

/** Clash.Meta / Clash Premium YAML */
export function toClash(user: User, s: Settings, host: string): string {
  const specs = nodeSpecs(user, s, host);
  const lines: string[] = [];
  lines.push('mixed-port: 7890');
  lines.push('allow-lan: false');
  lines.push('mode: rule');
  lines.push('log-level: info');
  lines.push('ipv6: false');
  lines.push('external-controller: 127.0.0.1:9090');
  lines.push('dns:');
  lines.push('  enable: true');
  lines.push('  ipv6: false');
  lines.push('  enhanced-mode: fake-ip');
  lines.push('  fake-ip-range: 198.18.0.1/16');
  lines.push('  nameserver:');
  lines.push('    - https://1.1.1.1/dns-query');
  lines.push('    - https://8.8.8.8/dns-query');
  lines.push('proxies:');

  for (const n of specs) {
    lines.push(`  - name: ${yamlQuote(n.name)}`);
    lines.push(`    type: ${n.proto === 'a' ? PROTO_A : PROTO_B}`);
    lines.push(`    server: ${yamlQuote(n.host)}`);
    lines.push(`    port: ${n.port}`);
    lines.push(`    ${n.proto === 'a' ? 'uuid' : 'password'}: ${yamlQuote(n.userId)}`);
    lines.push('    network: ws');
    lines.push(`    tls: ${n.tls}`);
    if (n.proto === 'b') lines.push(`    sni: ${yamlQuote(n.host)}`);
    lines.push('    udp: true');
    if (n.tls) lines.push(`    client-fingerprint: ${yamlQuote(n.fingerprint)}`);
    lines.push('    ws-opts:');
    lines.push(`      path: ${yamlQuote(n.path)}`);
    lines.push('      headers:');
    lines.push(`        Host: ${yamlQuote(n.host)}`);
  }

  const names = specs.map((n) => `      - ${yamlQuote(n.name)}`);
  lines.push('proxy-groups:');
  lines.push('  - name: PROXY');
  lines.push('    type: select');
  lines.push('    proxies:');
  lines.push(...names);
  lines.push('  - name: AUTO');
  lines.push('    type: url-test');
  lines.push('    url: http://www.gstatic.com/generate_204');
  lines.push('    interval: 300');
  lines.push('    tolerance: 50');
  lines.push('    proxies:');
  lines.push(...names);
  lines.push('rules:');
  lines.push('  - MATCH,PROXY');
  lines.push('');
  return lines.join('\n');
}

/** Full sing-box configuration (importable as-is) */
export function toSingBox(user: User, s: Settings, host: string): string {
  const specs = nodeSpecs(user, s, host);
  const outbounds: unknown[] = [];

  for (const n of specs) {
    const ob: Record<string, unknown> = {
      type: n.proto === 'a' ? PROTO_A : PROTO_B,
      tag: n.name,
      server: n.host,
      server_port: n.port,
      network: 'ws',
      tcp_fast_open: false,
      domain_resolver: 'dns-direct',
    };
    if (n.proto === 'a') ob.uuid = n.userId;
    else ob.password = n.userId;
    if (n.tls) {
      ob.tls = {
        enabled: true,
        server_name: n.host,
        insecure: false,
        utls: { enabled: true, fingerprint: n.fingerprint },
      };
    }
    ob.transport = { type: 'ws', path: n.path, headers: { Host: n.host } };
    outbounds.push(ob);
  }

  outbounds.push({
    type: 'selector',
    tag: 'select',
    outbounds: [...specs.map((n) => n.name), 'direct'],
    default: specs[0]?.name,
  });
  outbounds.push({ type: 'direct', tag: 'direct' });

  const config = {
    log: { level: 'info', timestamp: true },
    dns: {
      servers: [
        { tag: 'dns-direct', address: 'local', strategy: 'prefer_ipv4' },
        { tag: 'dns-remote', address: 'https://1.1.1.1/dns-query', strategy: 'prefer_ipv4' },
      ],
      final: 'dns-remote',
      strategy: 'prefer_ipv4',
      independent_cache: true,
    },
    inbounds: [
      {
        type: 'mixed',
        tag: 'mixed-in',
        listen: '127.0.0.1',
        listen_port: 2080,
        set_system_proxy: false,
      },
    ],
    outbounds,
    route: {
      rules: [
        { ip_is_private: true, outbound: 'direct' },
        { protocol: 'dns', action: 'hijack-dns' },
      ],
      final: 'select',
      auto_detect_interface: true,
    },
    experimental: {
      cache_file: { enabled: true, path: 'cache.db', store_dns: true },
    },
  };

  return JSON.stringify(config, null, 2);
}

export function subscriptionHeaders(
  user: User,
  s: Settings,
  filename: string,
  contentType: string,
): Record<string, string> {
  const headers: Record<string, string> = {
    'content-type': contentType,
    'profile-title': `base64:${toBase64(s.brand)}`,
    'profile-update-interval': '6',
    'content-disposition': `attachment; filename="${filename}"`,
  };
  const total = user.limitBytes > 0 ? user.limitBytes : 0;
  const expire = user.expires !== null ? Math.floor(user.expires / 1000) : 0;
  headers['subscription-userinfo'] =
    `upload=${user.usedUp}; download=${user.usedDown}; total=${total}; expire=${expire}`;
  return headers;
}

/** portal payload handed to the browser UI of a subscription page */
export function portalPayload(user: User, s: Settings, host: string): unknown {
  return {
    name: user.name,
    brand: s.brand,
    links: buildLinks(user, s, host),
    usedUp: user.usedUp,
    usedDown: user.usedDown,
    limitBytes: user.limitBytes,
    expires: user.expires,
    state: user.enabled,
    clashPath: `?format=clash`,
    singboxPath: `?format=singbox`,
    rawPath: `?format=raw`,
    base64Path: `?format=base64`,
  };
}
