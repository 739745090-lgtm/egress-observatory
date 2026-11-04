/** Cloudflare Worker ESM. Secrets are supplied only through runtime env bindings. */
const DEFAULT_ORIGIN = 'https://blackslience-reaper.github.io';
const CACHE_SECONDS = 600;
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 10;
const MAX_CALLER_BUCKETS = 10_000;
const callers = new Map();
let lastSweep = 0;
const ROUTES = Object.freeze({ '/v1/proxycheck': 'proxycheck', '/v1/dbip': 'dbip', '/v1/ip2location': 'ip2location' });
const PROVIDER_META = Object.freeze({
  proxycheck: { name: 'Proxycheck', database: 'Proxycheck', weight: 20,
    attribution: 'Selected network classifications supplied by proxycheck.io, normalized for the multi-source assessment.',
    attributionUrl: 'https://proxycheck.io/', sourceUrl: 'https://proxycheck.io/api/' },
  dbip: { name: 'DB-IP', database: 'DB-IP', weight: 20,
    attribution: 'IP Geolocation by DB-IP. Public free server API; 500 daily queries.',
    attributionUrl: 'https://db-ip.com/', sourceUrl: 'https://db-ip.com/api/free' },
  ip2location: { name: 'IP2Location.io', database: 'IP2Location', weight: 25,
    attribution: 'Egress Observatory uses IP2Location.io IP geolocation web service.',
    attributionUrl: 'https://www.ip2location.io', sourceUrl: 'https://www.ip2location.io/ip2location-documentation' },
});

function canonicalIP(value) {
  if (typeof value !== 'string' || value.length > 45 || value !== value.trim()) return null;
  if (/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)) {
    const parts = value.split('.').map(Number);
    return parts.every((part) => part <= 255) ? parts.join('.') : null;
  }
  if (!value.includes(':') || !/^[a-fA-F0-9:.]+$/.test(value)) return null;
  try { return new URL(`http://[${value}]/`).hostname.replace(/^\[|\]$/g, '').toLowerCase(); }
  catch { return null; }
}

function publicIP(value) {
  const ip = canonicalIP(value);
  if (!ip) return null;
  if (!ip.includes(':')) {
    const [a, b, c] = ip.split('.').map(Number);
    const special = a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
      || (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 192 && b === 88 && c === 99)
      || (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100)
      || (a === 203 && b === 0 && c === 113);
    return special ? null : ip;
  }
  const halves = ip.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const words = (halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left).map((word) => Number.parseInt(word, 16));
  if (words.length !== 8 || words.some((word) => !Number.isInteger(word))) return null;
  const special = (words[0] & 0xe000) !== 0x2000
    || (words[0] === 0x2001 && (words[1] < 0x200 || words[1] === 0xdb8))
    || words[0] === 0x2002 || (words[0] === 0x3fff && (words[1] & 0xf000) === 0);
  return special ? null : ip;
}

function allowedOrigin(env) {
  const value = env.ALLOWED_ORIGIN === undefined ? DEFAULT_ORIGIN : String(env.ALLOWED_ORIGIN);
  try {
    const url = new URL(value);
    if (url.origin !== value || url.protocol !== 'https:' || url.username || url.password) return null;
    return value;
  } catch { return null; }
}

function responseHeaders(origin, extra = {}) {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'private, no-store',
    'X-Content-Type-Options': 'nosniff',
    'Vary': 'Origin',
    ...extra,
  });
  if (origin) {
    headers.set('Access-Control-Allow-Origin', origin);
    headers.set('Access-Control-Allow-Credentials', 'true');
    headers.set('Access-Control-Expose-Headers', 'Retry-After, X-Data-Cache');
  }
  return headers;
}

function json(body, status, origin, extra) {
  return new Response(JSON.stringify(body), { status, headers: responseHeaders(origin, extra) });
}

function emptyRecord(ip = null, providerId = 'proxycheck') {
  const provider = PROVIDER_META[providerId];
  return {
    providerId, providerName: provider.name, database: provider.database, kind: 'database', weight: provider.weight,
    ip, observedAt: new Date().toISOString(), duration: 0,
    country: null, city: null, asn: null, org: null, networkType: null,
    flags: { vpn: null, proxy: null, tor: null, relay: null, hosting: null, abuser: null, bogon: null },
    fieldSources: { flags: {} }, targetMatch: null,
    status: 'error', error: null, errorCode: null,
    attribution: provider.attribution, attributionUrl: provider.attributionUrl, sourceUrl: provider.sourceUrl,
  };
}

function failure(status, code, message, origin, ip = null, retryAfter = null, providerId = 'proxycheck') {
  const payload = { ...emptyRecord(ip, providerId), errorCode: code, error: message };
  if (retryAfter !== null) payload.retryAfterSeconds = retryAfter;
  return json(payload, status, origin, retryAfter === null ? {} : { 'Retry-After': String(retryAfter) });
}

function takeRateSlot(request) {
  const now = Date.now();
  if (now - lastSweep >= RATE_WINDOW_MS) {
    for (const [key, bucket] of callers) if (bucket.expires <= now) callers.delete(key);
    lastSweep = now;
  }
  // CF-Connecting-IP is trusted only when the platform supplied request.cf metadata.
  // X-Forwarded-For, X-Real-IP, query parameters, and caller-supplied identifiers are ignored.
  const trustedAddress = request.cf ? canonicalIP(request.headers.get('CF-Connecting-IP')) : null;
  const key = trustedAddress || 'unknown-caller';
  let bucket = callers.get(key);
  if (!bucket || bucket.expires <= now) {
    if (!bucket && callers.size >= MAX_CALLER_BUCKETS) return { allowed: false, retryAfter: 60 };
    bucket = { count: 0, expires: now + RATE_WINDOW_MS };
    callers.set(key, bucket);
  }
  if (bucket.count >= RATE_LIMIT) return { allowed: false, retryAfter: Math.max(1, Math.ceil((bucket.expires - now) / 1000)) };
  bucket.count += 1;
  return { allowed: true };
}

const text = (value) => typeof value === 'string' && value.trim() ? value.trim().slice(0, 200) : null;
const bool = (value) => typeof value === 'boolean' ? value : null;

function selectFields(data, ip, duration) {
  if (!data || typeof data !== 'object' || !['ok', 'warning'].includes(data.status)) return null;
  const entries = Object.entries(data).filter(([key]) => canonicalIP(key) !== null);
  if (entries.length !== 1 || canonicalIP(entries[0][0]) !== ip) return null;
  const item = entries[0][1];
  if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
  const flags = { ...emptyRecord().flags,
    vpn: bool(item.detections?.vpn), proxy: bool(item.detections?.proxy),
    tor: bool(item.detections?.tor), hosting: bool(item.detections?.hosting),
  };
  const rawType = text(item.network?.type)?.toLowerCase();
  const networkTypes = { residential: 'residential', isp: 'isp', 'fixed line isp': 'isp', mobile: 'mobile', 'mobile isp': 'mobile', business: 'business', hosting: 'hosting' };
  const networkType = flags.hosting === true ? 'hosting' : networkTypes[rawType] || null;
  const rawASN = text(item.network?.asn);
  const country = text(item.location?.country_code);
  const selected = {
    ...emptyRecord(ip), status: 'success', duration,
    country: country && /^[a-z]{2}$/i.test(country) ? country.toUpperCase() : null,
    city: text(item.location?.city_name),
    asn: rawASN && /^AS\d+$/i.test(rawASN) ? rawASN.toUpperCase() : null,
    org: text(item.network?.organisation) || text(item.network?.provider), networkType, flags,
    targetMatch: 'exact-ip', upstreamWarning: data.status === 'warning',
  };
  for (const field of ['country', 'city', 'asn', 'org', 'networkType']) if (selected[field] !== null) selected.fieldSources[field] = 'proxycheck';
  for (const [flag, value] of Object.entries(flags)) if (value !== null) selected.fieldSources.flags[flag] = 'proxycheck';
  return selected;
}

function safeRetryAfter(response) {
  const raw = response.headers.get('Retry-After');
  if (raw && /^\d{1,6}$/.test(raw)) return Math.max(1, Math.min(86400, Number(raw)));
  return 60;
}

async function getUpstream(ip, key) {
  const started = performance.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12_000);
  try {
    const upstreamURL = new URL(`https://proxycheck.io/v3/${encodeURIComponent(ip)}`);
    upstreamURL.searchParams.set('key', key);
    upstreamURL.searchParams.set('tag', '0');
    // No user-controlled host, forwarded cookies, Origin, or authorization headers.
    const response = await fetch(upstreamURL, {
      method: 'GET', redirect: 'manual', headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    if(response.status>=300&&response.status<400)return {status:502,code:'upstream-redirect',message:'上游返回重定向，授权请求未被转发。'};
    if (response.status === 429) return { status: 429, code: 'upstream-rate-limit', message: 'Proxycheck 额度或速率受限，请等待重置。', retryAfter: safeRetryAfter(response) };
    if (response.status === 401 || response.status === 403) return { status: 502, code: 'upstream-access-denied', message: 'Proxycheck 拒绝了服务端授权请求。' };
    if (!response.ok) return { status: 502, code: 'upstream-http-error', message: 'Proxycheck 暂时未返回可用数据。' };
    let data;
    try { data = await response.json(); }
    catch {
      return controller.signal.aborted
        ? { status: 504, code: 'upstream-timeout', message: 'Proxycheck 请求超过 12 秒。' }
        : { status: 502, code: 'upstream-invalid-json', message: 'Proxycheck 响应格式异常。' };
    }
    if (data?.status === 'warning' && /disabled|invalid.{0,12}key|revoked/i.test(String(data.message || ''))) {
      return { status: 502, code: 'upstream-key-unavailable', message: 'Proxycheck 的服务端授权当前不可用。' };
    }
    const record = selectFields(data, ip, Math.round(performance.now() - started));
    if (!record) return { status: 502, code: 'upstream-target-or-schema', message: '上游目标或响应格式不匹配，结果已弃用。' };
    return { record };
  } catch (error) {
    return controller.signal.aborted
      ? { status: 504, code: 'upstream-timeout', message: 'Proxycheck 请求超过 12 秒。' }
      : { status: 502, code: /cache/i.test(String(error?.message))?'runtime-cache-option':'upstream-network', message: 'Proxycheck 网络请求未完成。' };
  } finally { clearTimeout(timeout); }
}

function selectPublicFields(providerId, data, ip, duration) {
  if (!data || typeof data !== 'object' || Array.isArray(data) || data.error || data.errorCode) return null;
  const returnedIP = providerId === 'dbip' ? data.ipAddress : data.ip;
  if (canonicalIP(returnedIP) !== ip) return null;
  const selected = { ...emptyRecord(ip, providerId), status: 'success', duration, targetMatch: 'exact-ip' };
  const country = text(providerId === 'dbip' ? data.countryCode : data.country_code);
  selected.country = country && /^[a-z]{2}$/i.test(country) ? country.toUpperCase() : null;
  selected.city = text(providerId === 'dbip' ? data.city : data.city_name);
  if (providerId === 'ip2location') {
    const rawASN = typeof data.asn === 'number' ? String(data.asn) : text(data.asn);
    const match = rawASN?.match(/^(?:AS)?(\d{1,10})$/i);
    selected.asn = match && Number(match[1]) <= 4294967295 ? `AS${match[1]}` : null;
    selected.org = text(data.as);
    // The keyless plan exposes only basic open-proxy classification, not VPN/Tor/hosting.
    selected.flags.proxy = bool(data.is_proxy);
  }
  for (const field of ['country', 'city', 'asn', 'org']) if (selected[field] !== null) selected.fieldSources[field] = providerId;
  for (const [flag, value] of Object.entries(selected.flags)) if (value !== null) selected.fieldSources.flags[flag] = providerId;
  return selected;
}

async function getPublicUpstream(providerId, ip) {
  const name = PROVIDER_META[providerId].name;
  const started = performance.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12_000);
  try {
    // Documented, keyless server-to-server lookup. No browser headers or caller-IP spoofing.
    const upstreamURL = providerId === 'dbip'
      ? new URL(`https://api.db-ip.com/v2/free/${encodeURIComponent(ip)}`)
      : new URL(`https://api.ip2location.io/?ip=${encodeURIComponent(ip)}`);
    const response = await fetch(upstreamURL, {
      method: 'GET', redirect: 'manual', headers: { Accept: 'application/json' }, signal: controller.signal,
    });
    if (response.status >= 300 && response.status < 400) return { status: 502, code: 'upstream-redirect', message: `${name} 返回重定向，请求未继续转发。` };
    if (response.status === 429) return { status: 429, code: 'upstream-rate-limit', message: `${name} 免费额度或速率受限，请等待重置。`, retryAfter: safeRetryAfter(response) };
    if (response.status === 401 || response.status === 403) return { status: 502, code: 'upstream-access-denied', message: `${name} 拒绝了当前免费接口请求。` };
    if (!response.ok) return { status: 502, code: 'upstream-http-error', message: `${name} 暂时未返回可用数据。` };
    let data;
    try { data = await response.json(); }
    catch {
      return controller.signal.aborted
        ? { status: 504, code: 'upstream-timeout', message: `${name} 请求超过 12 秒。` }
        : { status: 502, code: 'upstream-invalid-json', message: `${name} 响应格式异常。` };
    }
    if (providerId === 'dbip' && data?.errorCode === 'OVER_QUERY_LIMIT') {
      return { status: 429, code: 'upstream-daily-quota', message: 'DB-IP 免费日额度已用尽，已停止请求。', retryAfter: 86400 };
    }
    if (providerId === 'ip2location' && Number(data?.error?.error_code) === 10000) {
      const now = Date.now();
      const nextUTC = Math.floor(now / 86400000) * 86400000 + 86400000;
      return { status: 429, code: 'upstream-quota-or-access', message: 'IP2Location.io 匿名额度或访问资格受限，已停止请求。', retryAfter: Math.max(1, Math.ceil((nextUTC - now) / 1000)) };
    }
    if (data?.error || data?.errorCode) return { status: 502, code: 'upstream-service-error', message: `${name} 拒绝了本次查询，结果未纳入评分。` };
    const record = selectPublicFields(providerId, data, ip, Math.round(performance.now() - started));
    if (!record) return { status: 502, code: 'upstream-target-or-schema', message: `${name} 返回目标或格式不匹配，结果已弃用。` };
    return { record };
  } catch {
    return controller.signal.aborted
      ? { status: 504, code: 'upstream-timeout', message: `${name} 请求超过 12 秒。` }
      : { status: 502, code: 'upstream-network', message: `${name} 网络请求未完成。` };
  } finally { clearTimeout(timeout); }
}

async function handle(request, env, ctx) {
  const permitted = allowedOrigin(env);
  if (!permitted) return failure(503, 'origin-configuration', '服务端来源配置无效。', null);
  const sentOrigin = request.headers.get('Origin');
  if (sentOrigin !== null && sentOrigin !== permitted) return failure(403, 'origin-denied', '此来源未获允许。', null);
  const origin = sentOrigin === permitted ? permitted : null;
  const url = new URL(request.url);
  const providerId = ROUTES[url.pathname];
  const knownPath = url.pathname === '/health' || Boolean(providerId);
  if (!knownPath) return failure(404, 'not-found', '接口不存在。', origin);
  if (request.method === 'OPTIONS') {
    if (!origin || request.headers.get('Access-Control-Request-Method') !== 'GET') return failure(403, 'preflight-denied', '预检请求未获允许。', origin);
    const requestedHeaders = (request.headers.get('Access-Control-Request-Headers') || '').split(',').map((header) => header.trim().toLowerCase()).filter(Boolean);
    if (requestedHeaders.some((header) => !['accept', 'content-type'].includes(header))) return failure(403, 'preflight-headers-denied', '预检请求头未获允许。', origin);
    return new Response(null, { status: 204, headers: responseHeaders(origin, {
      'Access-Control-Allow-Methods': 'GET, OPTIONS', 'Access-Control-Allow-Headers': 'Accept, Content-Type', 'Access-Control-Max-Age': '600',
    }) });
  }
  if (request.method !== 'GET') return failure(405, 'method-not-allowed', '仅支持 GET。', origin);
  if (url.pathname === '/health') return json({ status: 'ok', service: 'egress-observatory-api', apiVersion: 2, providers: ['proxycheck', 'dbip', 'ip2location'], cacheTTLSeconds: CACHE_SECONDS, rateLimitPerMinute: RATE_LIMIT, rateLimitScope: 'per-caller-per-isolate-memory-shared-across-routes', configured: typeof env.PROXYCHECK_API_KEY === 'string' && env.PROXYCHECK_API_KEY.trim().length > 0 }, 200, origin);
  const parameterNames = [...url.searchParams.keys()];
  if (parameterNames.length !== 1 || parameterNames[0] !== 'ip') return failure(400, 'invalid-parameters', '只接受一个 ip 参数。', origin, null, null, providerId);
  const ip = publicIP(url.searchParams.get('ip'));
  if (!ip) return failure(400, 'invalid-public-ip', '请输入公网 IPv4 或 IPv6；域名、URL、私网及保留地址不接受。', origin, null, null, providerId);
  const key = providerId === 'proxycheck' && typeof env.PROXYCHECK_API_KEY === 'string' ? env.PROXYCHECK_API_KEY.trim() : '';
  if (providerId === 'proxycheck' && !key) return failure(503, 'provider-not-configured', 'Proxycheck 服务端授权尚未配置。', origin, ip);
  const slot = takeRateSlot(request);
  if (!slot.allowed) return failure(429, 'local-rate-limit', '请求频率超过每分钟 10 次，请稍后重试。', origin, ip, slot.retryAfter, providerId);

  // An origin-independent, versioned, IP-only cache key. No secret or inbound headers.
  const cacheURL = new URL(`/__egress_cache/${providerId}-v1/${encodeURIComponent(ip)}`, url.origin);
  const cacheKey = new Request(cacheURL, { method: 'GET' });
  const edgeCache = typeof caches !== 'undefined' ? caches.default : null;
  if (edgeCache) {
    try {
      const cached = await edgeCache.match(cacheKey);
      if (cached) {
        const record = await cached.json();
        const age = Date.now() - new Date(record.observedAt).getTime();
        if (record.status === 'success' && record.providerId === providerId && canonicalIP(record.ip) === ip && age >= 0 && age < CACHE_SECONDS * 1000) {
          return json({ ...record, cacheHit: true }, 200, origin, { 'X-Data-Cache': 'HIT' });
        }
      }
    } catch { /* Cache availability does not change upstream data semantics. */ }
  }
  const result = providerId === 'proxycheck' ? await getUpstream(ip, key) : await getPublicUpstream(providerId, ip);
  if (!result.record) return failure(result.status, result.code, result.message, origin, ip, result.retryAfter ?? null, providerId);
  if (edgeCache) {
    const response = new Response(JSON.stringify(result.record), { headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': `public, max-age=${CACHE_SECONDS}` } });
    const write = edgeCache.put(cacheKey, response).catch(() => {});
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(write);
    else await write;
  }
  return json({ ...result.record, cacheHit: false }, 200, origin, { 'X-Data-Cache': 'MISS' });
}

export default {
  async fetch(request, env = {}, ctx) {
    try { return await handle(request, env, ctx); }
    catch {
      const permitted = allowedOrigin(env);
      const origin = permitted && request.headers.get('Origin') === permitted ? permitted : null;
      return failure(500, 'internal-error', '接口暂时无法处理请求。', origin);
    }
  },
};
