// Azad installer proxy
//
// The installer page runs in a browser, and the Cloudflare API sends no CORS
// headers — so all API calls are relayed through this tiny worker. Deploy it
// once on your own account (call it whatever you like), then paste its URL
// into the installer. It forwards ONLY the endpoints the installer needs and
// passes your API token straight through without ever storing it, so it can
// not be abused as a general-purpose relay.

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'access-control-allow-headers': 'Content-Type, Authorization, X-Proxy-Target',
  'access-control-max-age': '86400',
};

// Every path the installer is allowed to reach, checked against the
// /client/v4/... path of the target URL.
const ALLOWED = [
  /^\/client\/v4\/user\/tokens\/verify$/,
  /^\/client\/v4\/accounts$/,
  /^\/client\/v4\/accounts\/[^/]+$/,
  /^\/client\/v4\/accounts\/[^/]+\/workers\/scripts\/[^/]+$/,
  /^\/client\/v4\/accounts\/[^/]+\/workers\/scripts\/[^/]+\/settings$/,
  /^\/client\/v4\/accounts\/[^/]+\/workers\/subdomain$/,
  /^\/client\/v4\/accounts\/[^/]+\/workers\/services\/[^/]+\/environments\/production\/subdomain$/,
  /^\/client\/v4\/accounts\/[^/]+\/storage\/kv\/namespaces$/,
  /^\/client\/v4\/accounts\/[^/]+\/storage\/kv\/namespaces\/[^/]+$/,
];

function corsResponse(status) {
  return new Response(null, { status, headers: CORS });
}

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') return corsResponse(204);

    const target = request.headers.get('X-Proxy-Target') || '';
    let path = '';
    try {
      const u = new URL(target);
      if (u.protocol !== 'https:' || u.hostname !== 'api.cloudflare.com') {
        return new Response(JSON.stringify({ errors: [{ message: 'target must be api.cloudflare.com' }] }),
          { status: 400, headers: { 'content-type': 'application/json', ...CORS } });
      }
      path = u.pathname;
    } catch {
      return new Response(JSON.stringify({ errors: [{ message: 'bad X-Proxy-Target' }] }),
        { status: 400, headers: { 'content-type': 'application/json', ...CORS } });
    }

    if (!ALLOWED.some((re) => re.test(path))) {
      return new Response(JSON.stringify({ errors: [{ message: 'path not allowed by installer proxy' }] }),
        { status: 403, headers: { 'content-type': 'application/json', ...CORS } });
    }

    // Forward method, auth, content-type and raw body untouched.
    const headers = new Headers({ ...CORS });
    if (request.headers.get('authorization')) headers.set('authorization', request.headers.get('authorization'));
    if (request.headers.get('content-type')) headers.set('content-type', request.headers.get('content-type'));

    try {
      const upstream = await fetch(target, {
        method: request.method,
        headers,
        body: request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body,
        redirect: 'manual',
      });
      const out = new Response(upstream.body, { status: upstream.status, headers: CORS });
      out.headers.set('content-type', upstream.headers.get('content-type') || 'application/json');
      return out;
    } catch (e) {
      return new Response(JSON.stringify({ errors: [{ message: 'upstream failed: ' + String(e) }] }),
        { status: 502, headers: { 'content-type': 'application/json', ...CORS } });
    }
  },
};
