/**
 * Egress API — Cloudflare Worker ESM (also runs on Sites). Secrets come only from runtime env bindings:
 *   PROXYCHECK_API_KEY, TURNSTILE_SECRET_KEY, RECAPTCHA_SECRET_KEY, ABUSEIPDB_API_KEY (optional), CF_RADAR_TOKEN (optional)
 * Optional ALLOWED_ORIGIN: one exact https origin (default GitHub Pages). Local dev origins on :4187 are always allowed.
 */
const DEFAULT_ORIGIN = 'https://blackslience-reaper.github.io';
const DEV_ORIGINS = new Set(['http://127.0.0.1:4187', 'http://localhost:4187']);
const API_VERSION = 5;
const CACHE_SECONDS = 3600;
// Every success is also kept this long as a fallback for when the upstream refuses (quota, rate limit, outage).
const STALE_SECONDS = 24 * 3600;
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 30;
const UPSTREAM_TIMEOUT = 12_000;
// Small free quotas: keep their answers longer.
const CACHE_FOR = Object.freeze({ ipqs: 12 * 3600, abuseipdb: 12 * 3600, ipregistry: 12 * 3600, ipdata: 12 * 3600, greynoise: 6 * 3600, crowdsec: 6 * 3600, getipintel: 6 * 3600, scamalytics: 6 * 3600, virustotal: 6 * 3600, vpnapi: 12 * 3600, iphub: 6 * 3600, ipapiis: 12 * 3600 });
const PAGE_SERVICE = 'https://egress-observatory-lookup.onrender.com';
const PAGE_PROVIDERS = new Set(['ipinfo', 'ipsuper', 'sources', 'getipintel']);
const PAGE_ADMISSION = '/internal/page-admission';
const PAGE_TICKET_MS = 120_000;
const pageRequests = new Map();
let pageWarmup = null;
let pageWarmUntil = 0;

const LOOKUPS = Object.freeze({
  '/v1/proxycheck': 'proxycheck', '/v1/dbip': 'dbip', '/v1/ip2location': 'ip2location', '/v1/ipapi': 'ipapi', '/v1/abuseipdb': 'abuseipdb', '/v1/ipqs': 'ipqs', '/v1/ipinfo': 'ipinfo', '/v1/ipregistry': 'ipregistry', '/v1/ipdata': 'ipdata',
  '/v1/greynoise': 'greynoise', '/v1/crowdsec': 'crowdsec', '/v1/vpnapi': 'vpnapi', '/v1/iphub': 'iphub', '/v1/getipintel': 'getipintel',
  '/v1/scamalytics': 'scamalytics', '/v1/virustotal': 'virustotal', '/v1/ipapiis': 'ipapiis',
});
const META = Object.freeze({
  proxycheck: { name: 'Proxycheck', attribution: 'Selected classifications by proxycheck.io.' },
  dbip: { name: 'DB-IP', attribution: 'IP Geolocation by DB-IP.' },
  ip2location: { name: 'IP2Location.io', attribution: 'IP geolocation by IP2Location.io.' },
  ipapi: { name: 'ip-api.com', attribution: 'Geolocation by ip-api.com.' },
  abuseipdb: { name: 'AbuseIPDB', attribution: 'Abuse reports by AbuseIPDB.' },
  ipqs: { name: 'IPQualityScore', attribution: 'Fraud scoring by IPQualityScore.' },
  ipinfo: { name: 'IPinfo', attribution: 'IP data by IPinfo.' },
  ipregistry: { name: 'IPRegistry', attribution: 'IP data by Ipregistry.' },
  ipdata: { name: 'IPData', attribution: 'IP data by ipdata.co.' },
  greynoise: { name: 'GreyNoise', attribution: 'Internet noise data by GreyNoise.' },
  crowdsec: { name: 'CrowdSec CTI', attribution: 'Threat intelligence by CrowdSec.' },
  vpnapi: { name: 'vpnapi.io', attribution: 'VPN detection by vpnapi.io.' },
  iphub: { name: 'IPHub', attribution: 'Proxy detection by IPHub.' },
  getipintel: { name: 'GetIPIntel', attribution: 'Proxy probability by GetIPIntel.' },
  scamalytics: { name: 'Scamalytics', attribution: 'Fraud scoring by Scamalytics.' },
  virustotal: { name: 'VirusTotal', attribution: 'Reputation by VirusTotal.' },
  ipapiis: { name: 'ipapi.is', attribution: 'IP data by ipapi.is.' },
});

// ---------- input validation ----------

function canonicalIP(value) {
  if (typeof value !== 'string' || value.length > 45 || value !== value.trim()) return null;
  if (/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)) {
    const parts = value.split('.').map(Number);
    return parts.every(part => part <= 255) ? parts.join('.') : null;
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
  const words = (halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left).map(word => Number.parseInt(word, 16));
  if (words.length !== 8 || words.some(word => !Number.isInteger(word))) return null;
  const special = (words[0] & 0xe000) !== 0x2000
    || (words[0] === 0x2001 && (words[1] < 0x200 || words[1] === 0xdb8))
    || words[0] === 0x2002 || (words[0] === 0x3fff && (words[1] & 0xf000) === 0);
  return special ? null : ip;
}

const text = value => typeof value === 'string' && value.trim() ? value.trim().slice(0, 200) : null;
const bool = value => typeof value === 'boolean' ? value : null;
const num = value => typeof value === 'number' && Number.isFinite(value) ? value : (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value)) ? Number(value) : null);
const secret = value => typeof value === 'string' && value.trim() ? value.trim() : '';

// ---------- origin, CORS, responses ----------

function allowedOrigin(env, requested) {
  if (requested && DEV_ORIGINS.has(requested)) return requested;
  const value = env.ALLOWED_ORIGIN === undefined ? DEFAULT_ORIGIN : String(env.ALLOWED_ORIGIN);
  try {
    const url = new URL(value);
    if (url.origin !== value || url.protocol !== 'https:' || url.username || url.password) return null;
    return value;
  } catch { return null; }
}

function headers(origin, extra = {}) {
  const result = new Headers({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff', Vary: 'Origin', ...extra });
  if (origin) {
    result.set('Access-Control-Allow-Origin', origin);
    result.set('Access-Control-Expose-Headers', 'Retry-After, X-Data-Cache');
  }
  return result;
}

const json = (body, status, origin, extra) => new Response(JSON.stringify(body), { status, headers: headers(origin, extra) });

function failure(status, code, message, origin, extra = {}) {
  return json({ status: 'error', errorCode: code, error: message, ...extra }, status, origin, extra.retryAfterSeconds ? { 'Retry-After': String(extra.retryAfterSeconds) } : {});
}

function enabledRoutes(env) {
  const routes = ['dbip', 'ip2location', 'ipapi', ...[...PAGE_PROVIDERS].map(provider => `page-${provider}`)];
  if (secret(env.PROXYCHECK_API_KEY)) routes.unshift('proxycheck');
  if (secret(env.ABUSEIPDB_API_KEY)) routes.push('abuseipdb');
  if (secret(env.IPQS_API_KEY)) routes.push('ipqs');
  if (secret(env.IPINFO_TOKEN)) routes.push('ipinfo');
  if (secret(env.IPREGISTRY_API_KEY)) routes.push('ipregistry');
  if (secret(env.IPDATA_API_KEY)) routes.push('ipdata');
  if (secret(env.GREYNOISE_API_KEY)) routes.push('greynoise');
  if (secret(env.CROWDSEC_CTI_KEY)) routes.push('crowdsec');
  if (secret(env.VPNAPI_KEY)) routes.push('vpnapi');
  if (secret(env.IPHUB_KEY)) routes.push('iphub');
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(secret(env.GETIPINTEL_CONTACT))) routes.push('getipintel');
  if (secret(env.SCAMALYTICS_USER) && secret(env.SCAMALYTICS_KEY)) routes.push('scamalytics');
  if (secret(env.VT_API_KEY)) routes.push('virustotal');
  if (secret(env.IPAPI_IS_KEY)) routes.push('ipapiis');
  if (secret(env.CF_RADAR_TOKEN)) routes.push('radar');
  if (secret(env.TURNSTILE_SECRET_KEY)) routes.push('turnstile-verify');
  if (secret(env.RECAPTCHA_SECRET_KEY)) routes.push('recaptcha-verify');
  return routes;
}

// ---------- rate limit (atomic D1 counters shared by all isolates) ----------

function trustedCaller(request) {
  // CF-Connecting-IP is set by Cloudflare's edge, which rejects a client-sent copy (error 1000). Sites passes no
  // request.cf, but sets X-Real-IP to the same address and overwrites a client-sent one, so the pair is trusted.
  // X-Forwarded-For is never used: it carries whatever the client sent.
  const address = canonicalIP(request.headers.get('CF-Connecting-IP'));
  return address && (request.cf || canonicalIP(request.headers.get('X-Real-IP')) === address) ? address : null;
}

let securitySchema = null;

function securityReady() {
  securitySchema ??= db.batch([
    db.prepare('CREATE TABLE IF NOT EXISTS egress_security_salt (id INTEGER PRIMARY KEY CHECK (id = 1), salt TEXT NOT NULL)'),
    db.prepare('INSERT OR IGNORE INTO egress_security_salt (id, salt) VALUES (1, ?)').bind(crypto.randomUUID() + crypto.randomUUID()),
    db.prepare('CREATE TABLE IF NOT EXISTS egress_rate_limits (caller TEXT PRIMARY KEY, used INTEGER NOT NULL, expires INTEGER NOT NULL)'),
    db.prepare('CREATE TABLE IF NOT EXISTS egress_page_tickets (ticket TEXT PRIMARY KEY, provider TEXT NOT NULL, ip TEXT NOT NULL, expires INTEGER NOT NULL)'),
  ]).then(() => db.prepare('SELECT salt FROM egress_security_salt WHERE id = 1').first('salt'))
    .catch(error => { securitySchema = null; throw error; });
  return securitySchema;
}

async function takeRateSlot(request, scope = 'query', limit = RATE_LIMIT) {
  const caller = trustedCaller(request);
  if (!caller || !db) return { unavailable: true };
  const now = Date.now();
  try {
    const salt = await securityReady();
    const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${salt}|${scope}|${caller}`));
    const key = [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
    // A single UPSERT increments and returns the counter under D1's write lock.
    // Saturating rejected requests avoids overflow; rejected calls never extend the window.
    const row = await db.prepare(`INSERT INTO egress_rate_limits (caller, used, expires) VALUES (?, 1, ?)
      ON CONFLICT (caller) DO UPDATE SET
        used = CASE WHEN egress_rate_limits.expires <= ? THEN 1 ELSE MIN(egress_rate_limits.used + 1, ?) END,
        expires = CASE WHEN egress_rate_limits.expires <= ? THEN excluded.expires ELSE egress_rate_limits.expires END
      RETURNING used, expires`).bind(key, now + RATE_WINDOW_MS, now, limit + 1, now).first();
    if (!row) return { unavailable: true };
    if (Math.random() < 0.02) await db.batch([
      db.prepare('DELETE FROM egress_rate_limits WHERE expires <= ?').bind(now),
      db.prepare('DELETE FROM egress_page_tickets WHERE expires <= ?').bind(now),
    ]);
    return { allowed: row.used <= limit, retryAfter: Math.max(1, Math.ceil((row.expires - now) / 1000)) };
  } catch {
    // Missing identity or unavailable storage must never disable quota protection.
    return { unavailable: true };
  }
}

async function pageAdmission(request) {
  if (request.method !== 'POST') return failure(405, 'method-not-allowed', '仅支持 POST。', null);
  const slot = await takeRateSlot(request, 'page-admission', 120);
  if (slot.unavailable) return failure(503, 'rate-limit-unavailable', '请求额度校验暂时不可用。', null, { retryAfterSeconds: 5 });
  if (!slot.allowed) return failure(429, 'caller-rate-limit', '请求频率过高。', null, { retryAfterSeconds: slot.retryAfter });
  // A bounded JSON body carries a single-use capability, never a caller-supplied identity.
  const reader = request.body?.getReader();
  if (!reader) return failure(400, 'invalid-ticket', '查询凭据无效。', null);
  let size = 0; let body = '';
  try {
    const decoder = new TextDecoder();
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > 256) { await reader.cancel(); return failure(400, 'invalid-ticket', '查询凭据无效。', null); }
      body += decoder.decode(chunk.value, { stream: true });
    }
    body += decoder.decode();
    const { ticket, provider, ip } = JSON.parse(body);
    if (!/^[a-f0-9]{64}$/.test(ticket) || !PAGE_PROVIDERS.has(provider) || publicIP(ip) !== ip) return failure(403, 'invalid-ticket', '查询凭据无效。', null);
    const admitted = await db.prepare('DELETE FROM egress_page_tickets WHERE ticket = ? AND provider = ? AND ip = ? AND expires > ? RETURNING ticket')
      .bind(ticket, provider, ip, Date.now()).first();
    return admitted ? new Response(null, { status: 204, headers: headers(null) }) : failure(403, 'invalid-ticket', '查询凭据无效或已使用。', null);
  } catch {
    return failure(403, 'invalid-ticket', '查询凭据无效。', null);
  } finally { reader.releaseLock(); }
}

// ---------- upstream fetch ----------

function retryAfter(response) {
  const raw = response.headers.get('Retry-After');
  return raw && /^\d{1,6}$/.test(raw) ? Math.max(1, Math.min(86400, Number(raw))) : 60;
}

async function upstream(url, init, name) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT);
  const started = Date.now();
  try {
    // Fixed upstream hosts only; no visitor cookies, Origin or authorization headers are forwarded.
    const response = await fetch(url, { redirect: 'manual', ...init, signal: controller.signal });
    if (response.status >= 300 && response.status < 400) return { error: { status: 502, code: 'upstream-redirect', message: `${name} 返回重定向，请求未继续。` } };
    if (response.status === 429) return { error: { status: 429, code: 'upstream-rate-limit', message: `${name} 额度或频率受限。`, retryAfter: retryAfter(response) } };
    if (response.status === 401 || response.status === 403) return { error: { status: 502, code: 'upstream-access-denied', message: `${name} 拒绝了服务端授权。` } };
    if (!response.ok) return { error: { status: 502, code: 'upstream-http-error', message: `${name} 暂时不可用。`, httpStatus: response.status } };
    let data;
    try { data = await response.json(); }
    catch { return { error: { status: 502, code: 'upstream-invalid-json', message: `${name} 响应格式异常。` } }; }
    return { data, ms: Date.now() - started };
  } catch {
    return { error: controller.signal.aborted ? { status: 504, code: 'upstream-timeout', message: `${name} 请求超时。` } : { status: 502, code: 'upstream-network', message: `${name} 网络请求未完成。` } };
  } finally { clearTimeout(timer); }
}

/**
 * Usage type (how the IP is used) and company type (who owns it), normalized across providers:
 * residential | mobile | business | hosting | education | government. Unknown stays null.
 */
function usage(value) {
  const raw = String(value ?? '').trim().toLowerCase();
  if (!raw) return null;
  if (/^(isp|fixed line isp|residential|cable\/dsl\/isp|dsl|res)$/.test(raw) || raw === 'isp/mob' || raw.includes('fixed line')) return raw.includes('mob') ? 'mobile' : 'residential';
  if (/(^mob$|mobile|wireless|cellular)/.test(raw)) return 'mobile';
  if (/(^dch$|data ?center|hosting|web hosting|transit|^cdn$|content delivery|^ses$|search engine|cloud)/.test(raw)) return 'hosting';
  if (/(^com$|^org$|business|commercial|corporate|organization|enterprise)/.test(raw)) return 'business';
  if (/(^edu$|^lib$|education|university|college|school|library|^edu)/.test(raw)) return 'education';
  if (/(^gov$|^mil$|government|military)/.test(raw)) return 'government';
  return null;
}

function record(providerId, ip, fields) {
  return {
    providerId, providerName: META[providerId].name, status: 'success', ip, observedAt: new Date().toISOString(),
    country: null, region: null, city: null, lat: null, lon: null, timezone: null, asn: null, org: null, hostname: null,
    networkType: null, usageType: null, companyType: null, risk: null, flags: { vpn: null, proxy: null, tor: null, relay: null, hosting: null, abuser: null, crawler: null, mobile: null, bogon: null },
    attribution: META[providerId].attribution, ...fields,
  };
}

const country = value => { const code = text(value); return code && /^[a-z]{2}$/i.test(code) ? code.toUpperCase() : null; };
const asn = value => { const match = String(value ?? '').match(/^(?:AS)?(\d{1,10})\b/i); return match && Number(match[1]) > 0 ? `AS${match[1]}` : null; };

const PROVIDERS = {
  async proxycheck(ip, env) {
    const url = new URL(`https://proxycheck.io/v3/${encodeURIComponent(ip)}`);
    url.searchParams.set('key', secret(env.PROXYCHECK_API_KEY));
    url.searchParams.set('tag', '0');
    const result = await upstream(url, { headers: { Accept: 'application/json' } }, 'Proxycheck');
    if (result.error) return result;
    const data = result.data;
    if (data?.status === 'warning' && /disabled|invalid.{0,12}key|revoked/i.test(String(data.message || ''))) return { error: { status: 502, code: 'upstream-key-unavailable', message: 'Proxycheck 授权当前不可用。' } };
    if (!data || !['ok', 'warning'].includes(data.status)) return { error: { status: 502, code: 'upstream-service-error', message: 'Proxycheck 拒绝了本次查询。' } };
    const entries = Object.entries(data).filter(([key]) => canonicalIP(key) !== null);
    if (entries.length !== 1 || canonicalIP(entries[0][0]) !== ip) return { error: { status: 502, code: 'upstream-target', message: '上游目标不匹配，结果已弃用。' } };
    const item = entries[0][1] || {};
    const d = item.detections || {};
    const rawType = text(item.network?.type)?.toLowerCase();
    const types = { residential: 'residential', isp: 'isp', 'fixed line isp': 'isp', wireless: 'mobile', mobile: 'mobile', 'mobile isp': 'mobile', business: 'business', hosting: 'hosting', education: 'education' };
    return { record: record('proxycheck', ip, {
      country: country(item.location?.country_code), region: text(item.location?.region_name), city: text(item.location?.city_name),
      lat: num(item.location?.latitude), lon: num(item.location?.longitude), timezone: text(item.location?.timezone),
      asn: asn(item.network?.asn), org: text(item.network?.organisation) || text(item.network?.provider), hostname: text(item.network?.hostname),
      networkType: d.hosting === true ? 'hosting' : types[rawType] || null, usageType: usage(types[rawType] || rawType), risk: num(d.risk),
      flags: { vpn: bool(d.vpn), proxy: bool(d.proxy), tor: bool(d.tor), relay: null, hosting: bool(d.hosting), abuser: d.compromised === true ? true : null, crawler: d.scraper === true ? true : null, mobile: null, bogon: null },
      devices: item.device_estimate ? { address: num(item.device_estimate.address), subnet: num(item.device_estimate.subnet) } : null,
      lastSeen: text(d.last_seen),
    }), ms: result.ms };
  },
  async dbip(ip) {
    const result = await upstream(`https://api.db-ip.com/v2/free/${encodeURIComponent(ip)}`, { headers: { Accept: 'application/json' } }, 'DB-IP');
    if (result.error) return result;
    if (result.data?.errorCode === 'OVER_QUERY_LIMIT') return { error: { status: 429, code: 'upstream-daily-quota', message: 'DB-IP 免费日额度已用尽。', retryAfter: 86400 } };
    if (result.data?.error || result.data?.errorCode || canonicalIP(result.data?.ipAddress) !== ip) return { error: { status: 502, code: 'upstream-target-or-schema', message: 'DB-IP 返回目标或格式不匹配。' } };
    return { record: record('dbip', ip, { country: country(result.data.countryCode), region: text(result.data.stateProv), city: text(result.data.city) }), ms: result.ms };
  },
  async ip2location(ip, env) {
    // Keyless quota is per calling IP and the hosting egress is shared, so a free account key is preferred.
    const url = new URL('https://api.ip2location.io/');
    if (secret(env.IP2LOCATION_API_KEY)) url.searchParams.set('key', secret(env.IP2LOCATION_API_KEY));
    url.searchParams.set('ip', ip);
    const result = await upstream(url, { headers: { Accept: 'application/json' } }, 'IP2Location.io');
    if (result.error) return result;
    const data = result.data;
    if (Number(data?.error?.error_code) === 10000) return { error: { status: 429, code: 'upstream-quota', message: 'IP2Location.io 匿名额度已用尽。', retryAfter: 3600 } };
    if (data?.error || canonicalIP(data?.ip) !== ip) return { error: { status: 502, code: 'upstream-target-or-schema', message: 'IP2Location.io 返回目标或格式不匹配。' } };
    return { record: record('ip2location', ip, {
      country: country(data.country_code), region: text(data.region_name), city: text(data.city_name), lat: num(data.latitude), lon: num(data.longitude),
      asn: asn(data.asn), org: text(data.as), usageType: usage(data.usage_type), companyType: usage(data.as_usage_type),
      networkType: usage(data.usage_type) === 'residential' ? 'isp' : usage(data.usage_type),
      flags: { vpn: null, proxy: bool(data.is_proxy), tor: null, relay: null, hosting: null, abuser: null, crawler: null, mobile: null, bogon: null },
    }), ms: result.ms };
  },
  async ipapi(ip) {
    // ip-api.com's free endpoint is HTTP-only, so browsers on HTTPS pages cannot call it directly.
    const fields = 'status,message,countryCode,regionName,city,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query';
    const result = await upstream(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`, { headers: { Accept: 'application/json' } }, 'ip-api.com');
    if (result.error) return result;
    const data = result.data;
    if (data?.status !== 'success' || canonicalIP(data.query) !== ip) return { error: { status: 502, code: 'upstream-service-error', message: `ip-api.com：${text(data?.message) || '查询失败'}` } };
    return { record: record('ipapi', ip, {
      country: country(data.countryCode), region: text(data.regionName), city: text(data.city), lat: num(data.lat), lon: num(data.lon),
      timezone: text(data.timezone), asn: asn(data.as), org: text(data.org) || text(data.isp),
      networkType: data.hosting === true ? 'hosting' : data.mobile === true ? 'mobile' : null,
      usageType: data.hosting === true ? 'hosting' : data.mobile === true ? 'mobile' : null,
      flags: { vpn: null, proxy: bool(data.proxy), tor: null, relay: null, hosting: bool(data.hosting), abuser: null, crawler: null, mobile: bool(data.mobile), bogon: null },
    }), ms: result.ms };
  },
  async abuseipdb(ip, env) {
    const url = new URL('https://api.abuseipdb.com/api/v2/check');
    url.searchParams.set('ipAddress', ip);
    url.searchParams.set('maxAgeInDays', '90');
    const result = await upstream(url, { headers: { Accept: 'application/json', Key: secret(env.ABUSEIPDB_API_KEY) } }, 'AbuseIPDB');
    if (result.error) return result;
    const data = result.data?.data;
    if (!data || canonicalIP(data.ipAddress) !== ip) return { error: { status: 502, code: 'upstream-target-or-schema', message: 'AbuseIPDB 返回目标或格式不匹配。' } };
    const usage = String(data.usageType || '');
    const networkType = /Data Center|Hosting|Content Delivery/i.test(usage) ? 'hosting' : /Mobile/i.test(usage) ? 'mobile' : /Fixed Line ISP/i.test(usage) ? 'isp'
      : /University|College|School/i.test(usage) ? 'education' : /Commercial|Organization|Government|Military/i.test(usage) ? 'business' : null;
    const score = num(data.abuseConfidenceScore);
    // Neighbours: reports for the rest of the /24 in the last 30 days (free plan allows /24 blocks).
    let block = null;
    if (!ip.includes(':')) {
      const prefix = `${ip.split('.').slice(0, 3).join('.')}.0/24`;
      const blockURL = new URL('https://api.abuseipdb.com/api/v2/check-block');
      blockURL.searchParams.set('network', prefix);
      blockURL.searchParams.set('maxAgeInDays', '30');
      const neighbours = await upstream(blockURL, { headers: { Accept: 'application/json', Key: secret(env.ABUSEIPDB_API_KEY) } }, 'AbuseIPDB');
      const reported = Array.isArray(neighbours.data?.data?.reportedAddress) ? neighbours.data.data.reportedAddress.filter(item => canonicalIP(item?.ipAddress) !== ip) : null;
      if (reported) block = { prefix, reported: reported.length, maxScore: reported.reduce((max, item) => Math.max(max, num(item.abuseConfidenceScore) || 0), 0) };
    }
    return { record: record('abuseipdb', ip, {
      country: country(data.countryCode), org: text(data.isp), hostname: text(data.hostnames?.[0]), networkType, usageType: networkType === 'isp' ? 'residential' : networkType, risk: score,
      flags: { vpn: null, proxy: null, tor: bool(data.isTor), relay: null, hosting: null, abuser: score === null ? null : score >= 25 ? true : data.totalReports === 0 ? false : null, crawler: null, mobile: null, bogon: null },
      reports: num(data.totalReports), lastReported: text(data.lastReportedAt), usageType: text(usage), block,
    }), ms: result.ms };
  },
};

PROVIDERS.ipinfo = async function ipinfo(ip, env) {
  const token = secret(env.IPINFO_TOKEN);
  // Current API (api.ipinfo.io/lookup): geo / as / anonymous / is_* fields, present on plans that include them.
  const lookup = new URL(`https://api.ipinfo.io/lookup/${encodeURIComponent(ip)}`);
  lookup.searchParams.set('token', token);
  const current = await upstream(lookup, { headers: { Accept: 'application/json' } }, 'IPinfo');
  if (!current.error && canonicalIP(current.data?.ip) === ip) return { record: ipinfoCurrent(ip, current.data), ms: current.ms };
  if (current.error && current.error.code !== 'upstream-access-denied' && current.error.code !== 'upstream-http-error') return current;
  // Legacy token endpoint (ipinfo.io/{ip}): privacy / company / asn objects on plans that include them.
  const legacy = new URL(`https://ipinfo.io/${encodeURIComponent(ip)}`);
  legacy.searchParams.set('token', token);
  const result = await upstream(legacy, { headers: { Accept: 'application/json' } }, 'IPinfo');
  if (result.error) return result;
  const data = result.data;
  if (!data || canonicalIP(data.ip) !== ip) return { error: { status: 502, code: 'upstream-target-or-schema', message: 'IPinfo 返回目标或格式不匹配。' } };
  const [lat, lon] = String(data.loc || '').split(',').map(Number);
  const companyType = text(data.company?.type);
  const privacy = data.privacy || {};
  return { record: record('ipinfo', ip, {
    country: country(data.country), region: text(data.region), city: text(data.city), lat: Number.isFinite(lat) ? lat : null, lon: Number.isFinite(lon) ? lon : null,
    timezone: text(data.timezone), asn: asn(data.asn?.asn || data.org), org: text(data.company?.name) || text(data.org)?.replace(/^AS\d+\s+/i, '') || null, hostname: text(data.hostname),
    networkType: { isp: 'isp', hosting: 'hosting', business: 'business', education: 'education' }[companyType] || null,
    usageType: privacy.hosting === true ? 'hosting' : null, companyType: usage(companyType || data.asn?.type),
    flags: { vpn: bool(privacy.vpn), proxy: bool(privacy.proxy), tor: bool(privacy.tor), relay: bool(privacy.relay), hosting: bool(privacy.hosting), abuser: null, crawler: null, mobile: null, bogon: bool(data.bogon) },
    asnType: text(data.asn?.type), privacyService: text(privacy.service), anycast: data.anycast === true,
  }), ms: result.ms };
};

function ipinfoCurrent(ip, data) {
  const geo = data.geo || {}; const as = data.as || {}; const anon = data.anonymous || {};
  const hosting = bool(data.is_hosting); const mobile = bool(data.is_mobile);
  // A residential-proxy hit is still a proxy; keep it separately so the page can name it.
  const resProxy = bool(anon.is_res_proxy);
  return record('ipinfo', ip, {
    country: country(geo.country_code), region: text(geo.region), city: text(geo.city), lat: num(geo.latitude), lon: num(geo.longitude),
    timezone: text(geo.timezone), asn: asn(as.asn), org: text(as.name), hostname: text(data.hostname),
    networkType: hosting === true ? 'hosting' : mobile === true ? 'mobile' : null,
    usageType: hosting === true ? 'hosting' : mobile === true ? 'mobile' : null, companyType: usage(data.company?.type || as.type),
    flags: {
      vpn: bool(anon.is_vpn), proxy: anon.is_proxy === true || resProxy === true ? true : bool(anon.is_proxy), tor: bool(anon.is_tor), relay: bool(anon.is_relay),
      hosting, abuser: null, crawler: null, mobile, bogon: null,
    },
    asnType: text(as.type), resProxy, anycast: data.is_anycast === true, satellite: data.is_satellite === true, geoChanged: text(geo.last_changed),
  });
}

PROVIDERS.ipqs = async function ipqs(ip, env) {
  const url = new URL(`https://ipqualityscore.com/api/json/ip/${encodeURIComponent(secret(env.IPQS_API_KEY))}/${encodeURIComponent(ip)}`);
  url.searchParams.set('strictness', '1');
  url.searchParams.set('allow_public_access_points', 'true');
  url.searchParams.set('fast', 'true');
  const result = await upstream(url, { headers: { Accept: 'application/json' } }, 'IPQualityScore');
  if (result.error) return result;
  const data = result.data;
  if (data?.success !== true) {
    const quota = /quota|credits|exceeded|limit/i.test(String(data?.message || ''));
    return { error: quota ? { status: 429, code: 'upstream-quota', message: 'IPQualityScore 本月额度已用尽。', retryAfter: 86400 } : { status: 502, code: 'upstream-service-error', message: 'IPQualityScore 拒绝了本次查询。' } };
  }
  const connection = String(data.connection_type || '');
  const networkType = /Data Center/i.test(connection) ? 'hosting' : /Mobile/i.test(connection) ? 'mobile' : /Residential/i.test(connection) ? 'residential'
    : /Corporate/i.test(connection) ? 'business' : /Education/i.test(connection) ? 'education' : null;
  return { record: record('ipqs', ip, {
    country: country(data.country_code), region: text(data.region), city: text(data.city), lat: num(data.latitude), lon: num(data.longitude),
    timezone: text(data.timezone), asn: asn(data.ASN), org: text(data.organization) || text(data.ISP), hostname: text(data.host) !== ip ? text(data.host) : null,
    networkType, usageType: networkType === 'isp' ? 'residential' : networkType, risk: num(data.fraud_score),
    flags: {
      vpn: data.vpn === true || data.active_vpn === true ? true : bool(data.vpn), proxy: bool(data.proxy), tor: data.tor === true || data.active_tor === true ? true : bool(data.tor),
      relay: null, hosting: networkType === 'hosting' ? true : null, abuser: bool(data.recent_abuse), crawler: data.is_crawler === true || data.bot_status === true ? true : bool(data.is_crawler), mobile: bool(data.mobile), bogon: null,
    },
    activeVpn: data.active_vpn === true, activeTor: data.active_tor === true, abuseVelocity: text(data.abuse_velocity), connectionType: text(connection),
  }), ms: result.ms };
};

PROVIDERS.ipregistry = async function ipregistry(ip, env) {
  const url = new URL(`https://api.ipregistry.co/${encodeURIComponent(ip)}`);
  url.searchParams.set('key', secret(env.IPREGISTRY_API_KEY));
  url.searchParams.set('fields', 'ip,connection,company,location.country.code,location.region.name,location.city,location.latitude,location.longitude,time_zone.id,security');
  const result = await upstream(url, { headers: { Accept: 'application/json' } }, 'IPRegistry');
  if (result.error) return result;
  const data = result.data;
  if (!data || canonicalIP(data.ip) !== ip) return { error: { status: 502, code: 'upstream-target-or-schema', message: 'IPRegistry 返回目标或格式不匹配。' } };
  const sec = data.security || {};
  const usageType = usage(data.connection?.type);
  return { record: record('ipregistry', ip, {
    country: country(data.location?.country?.code), region: text(data.location?.region?.name), city: text(data.location?.city),
    lat: num(data.location?.latitude), lon: num(data.location?.longitude), timezone: text(data.time_zone?.id),
    asn: asn(data.connection?.asn), org: text(data.connection?.organization) || text(data.company?.name),
    networkType: usageType === 'residential' ? 'isp' : usageType, usageType, companyType: usage(data.company?.type),
    flags: {
      vpn: bool(sec.is_vpn), proxy: bool(sec.is_proxy), tor: sec.is_tor === true || sec.is_tor_exit === true ? true : bool(sec.is_tor), relay: bool(sec.is_relay),
      hosting: sec.is_cloud_provider === true || usageType === 'hosting' ? true : null, abuser: sec.is_abuser === true || sec.is_attacker === true || sec.is_threat === true ? true : bool(sec.is_abuser),
      crawler: null, mobile: usageType === 'mobile' ? true : null, bogon: bool(sec.is_bogon),
    },
  }), ms: result.ms };
};

PROVIDERS.ipdata = async function ipdata(ip, env) {
  const url = new URL(`https://api.ipdata.co/${encodeURIComponent(ip)}`);
  url.searchParams.set('api-key', secret(env.IPDATA_API_KEY));
  const result = await upstream(url, { headers: { Accept: 'application/json' } }, 'IPData');
  if (result.error) return result;
  const data = result.data;
  if (!data || canonicalIP(data.ip) !== ip) return { error: { status: 502, code: 'upstream-target-or-schema', message: 'IPData 返回目标或格式不匹配。' } };
  const threat = data.threat || {};
  const scores = threat.scores || {};
  return { record: record('ipdata', ip, {
    country: country(data.country_code), region: text(data.region), city: text(data.city), lat: num(data.latitude), lon: num(data.longitude),
    timezone: text(data.time_zone?.name), asn: asn(data.asn?.asn), org: text(data.asn?.name) || text(data.company?.name),
    networkType: threat.is_datacenter === true ? 'hosting' : null, usageType: threat.is_datacenter === true ? 'hosting' : null,
    companyType: usage(data.company?.type || data.asn?.type), risk: num(scores.threat_score),
    flags: {
      vpn: typeof scores.vpn_score === 'number' ? scores.vpn_score >= 70 : null, proxy: bool(threat.is_proxy), tor: bool(threat.is_tor), relay: bool(threat.is_icloud_relay),
      hosting: bool(threat.is_datacenter), abuser: threat.is_known_attacker === true || threat.is_known_abuser === true ? true : (threat.is_known_attacker === false && threat.is_known_abuser === false ? false : null),
      crawler: null, mobile: null, bogon: bool(threat.is_bogon),
    },
  }), ms: result.ms };
};

const NO_FLAGS = () => ({ vpn: null, proxy: null, tor: null, relay: null, hosting: null, abuser: null, crawler: null, mobile: null, bogon: null });

PROVIDERS.greynoise = async function greynoise(ip, env) {
  const result = await upstream(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, { headers: { Accept: 'application/json', key: secret(env.GREYNOISE_API_KEY) } }, 'GreyNoise');
  // 404 means "not seen scanning and not a known benign service" — a clean answer, not an error.
  if (result.error?.httpStatus === 404) return { record: record('greynoise', ip, { noise: false, riot: false, classification: 'unseen', flags: { ...NO_FLAGS(), crawler: false } }), ms: 0 };
  if (result.error) return result;
  const data = result.data || {};
  const classification = text(data.classification);
  return { record: record('greynoise', ip, {
    noise: data.noise === true, riot: data.riot === true, classification, name: text(data.name), lastSeen: text(data.last_seen),
    flags: { ...NO_FLAGS(), crawler: data.noise === true ? true : data.noise === false ? false : null, abuser: classification === 'malicious' ? true : classification === 'benign' ? false : null },
  }), ms: result.ms };
};

PROVIDERS.crowdsec = async function crowdsec(ip, env) {
  const result = await upstream(`https://cti.api.crowdsec.net/v2/smoke/${encodeURIComponent(ip)}`, { headers: { Accept: 'application/json', 'x-api-key': secret(env.CROWDSEC_CTI_KEY) } }, 'CrowdSec');
  if (result.error?.httpStatus === 404) return { record: record('crowdsec', ip, { reputation: 'unknown', flags: { ...NO_FLAGS(), abuser: false } }), ms: 0 };
  if (result.error) return result;
  const data = result.data || {};
  const names = [...(data.classifications?.classifications || []), ...(data.classifications?.false_positives || [])].map(item => String(item?.name || ''));
  const reputation = text(data.reputation);
  const total = num(data.scores?.overall?.total);
  return { record: record('crowdsec', ip, {
    country: country(data.location?.country), asn: asn(data.as_num), org: text(data.as_name), reputation,
    behaviors: (data.behaviors || []).map(item => text(item?.label || item?.name)).filter(Boolean).slice(0, 6), risk: total === null ? null : Math.round(total * 20),
    flags: {
      ...NO_FLAGS(), vpn: names.some(name => /vpn/i.test(name)) || null, tor: names.some(name => /tor/i.test(name)) || null,
      proxy: names.some(name => /proxy:(?!vpn|tor)/i.test(name)) || null,
      abuser: reputation === 'malicious' || reputation === 'suspicious' ? true : reputation === 'safe' || reputation === 'known' ? false : null,
    },
  }), ms: result.ms };
};

PROVIDERS.vpnapi = async function vpnapi(ip, env) {
  const result = await upstream(`https://vpnapi.io/api/${encodeURIComponent(ip)}?key=${encodeURIComponent(secret(env.VPNAPI_KEY))}`, { headers: { Accept: 'application/json' } }, 'vpnapi.io');
  if (result.error) return result;
  const data = result.data || {};
  if (canonicalIP(data.ip) !== ip) return { error: { status: 502, code: 'upstream-target-or-schema', message: 'vpnapi.io 返回目标或格式不匹配。' } };
  const sec = data.security || {};
  return { record: record('vpnapi', ip, {
    country: country(data.location?.country_code), city: text(data.location?.city), asn: asn(data.network?.autonomous_system_number), org: text(data.network?.autonomous_system_organization),
    flags: { ...NO_FLAGS(), vpn: bool(sec.vpn), proxy: bool(sec.proxy), tor: bool(sec.tor), relay: bool(sec.relay) },
  }), ms: result.ms };
};

PROVIDERS.iphub = async function iphub(ip, env) {
  const result = await upstream(`https://v2.api.iphub.info/ip/${encodeURIComponent(ip)}`, { headers: { Accept: 'application/json', 'X-Key': secret(env.IPHUB_KEY) } }, 'IPHub');
  if (result.error) return result;
  const data = result.data || {};
  if (canonicalIP(data.ip) !== ip) return { error: { status: 502, code: 'upstream-target-or-schema', message: 'IPHub 返回目标或格式不匹配。' } };
  // block 0 = residential / unclassified, 1 = non-residential (hosting, proxy), 2 = mixed.
  const block = num(data.block);
  return { record: record('iphub', ip, {
    country: country(data.countryCode), asn: asn(data.asn), org: text(data.isp), block,
    usageType: block === 1 ? 'hosting' : null, networkType: block === 1 ? 'hosting' : null,
    flags: { ...NO_FLAGS(), hosting: block === 1 ? true : block === 0 ? false : null },
  }), ms: result.ms };
};

PROVIDERS.getipintel = async function getipintel(ip, env) {
  const url = new URL('https://check.getipintel.net/check.php');
  url.searchParams.set('ip', ip); url.searchParams.set('contact', secret(env.GETIPINTEL_CONTACT)); url.searchParams.set('format', 'json'); url.searchParams.set('flags', 'm');
  const result = await upstream(url, { headers: { Accept: 'application/json' } }, 'GetIPIntel');
  if (result.error) return result;
  const p = num(result.data?.result);
  if (result.data?.status !== 'success' || p === null || p < 0) return { error: { status: 502, code: 'upstream-service-error', message: 'GetIPIntel 未返回概率。' } };
  return { record: record('getipintel', ip, { risk: Math.round(p * 100), probability: p, flags: { ...NO_FLAGS(), proxy: p >= 0.95 ? true : p <= 0.3 ? false : null } }), ms: result.ms };
};

PROVIDERS.scamalytics = async function scamalytics(ip, env) {
  const host = /^api\d*\.scamalytics\.com$/.test(secret(env.SCAMALYTICS_HOST)) ? secret(env.SCAMALYTICS_HOST) : 'api11.scamalytics.com';
  const url = new URL(`https://${host}/v3/${encodeURIComponent(secret(env.SCAMALYTICS_USER))}/`);
  url.searchParams.set('key', secret(env.SCAMALYTICS_KEY)); url.searchParams.set('ip', ip);
  const result = await upstream(url, { headers: { Accept: 'application/json' } }, 'Scamalytics');
  if (result.error) return result;
  const data = result.data?.scamalytics || {};
  if (data.status !== 'ok') return { error: { status: 502, code: 'upstream-service-error', message: 'Scamalytics 拒绝了本次查询。' } };
  const proxy = data.scamalytics_proxy || {};
  return { record: record('scamalytics', ip, {
    risk: num(data.scamalytics_score), riskLabel: text(data.scamalytics_risk), org: text(data.scamalytics_isp),
    flags: { ...NO_FLAGS(), vpn: bool(proxy.is_vpn), hosting: proxy.is_datacenter === true || proxy.is_amazon_aws === true || proxy.is_google === true ? true : bool(proxy.is_datacenter), relay: bool(proxy.is_apple_icloud_private_relay) },
  }), ms: result.ms };
};

PROVIDERS.virustotal = async function virustotal(ip, env) {
  const result = await upstream(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, { headers: { Accept: 'application/json', 'x-apikey': secret(env.VT_API_KEY) } }, 'VirusTotal');
  if (result.error) return result;
  const attributes = result.data?.data?.attributes || {};
  const stats = attributes.last_analysis_stats || {};
  const malicious = num(stats.malicious) || 0; const suspicious = num(stats.suspicious) || 0;
  return { record: record('virustotal', ip, {
    country: country(attributes.country), asn: asn(attributes.asn), org: text(attributes.as_owner),
    vtMalicious: malicious, vtSuspicious: suspicious, vtReputation: num(attributes.reputation),
    risk: Math.min(100, malicious * 12 + suspicious * 4),
    flags: { ...NO_FLAGS(), abuser: malicious >= 3 ? true : malicious === 0 && suspicious === 0 ? false : null },
  }), ms: result.ms };
};

PROVIDERS.ipapiis = async function ipapiis(ip, env) {
  const result = await upstream(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}&key=${encodeURIComponent(secret(env.IPAPI_IS_KEY))}`, { headers: { Accept: 'application/json' } }, 'ipapi.is');
  if (result.error) return result;
  const data = result.data || {};
  if (canonicalIP(data.ip) !== ip) return { error: { status: 502, code: 'upstream-target-or-schema', message: 'ipapi.is 返回目标或格式不匹配。' } };
  const company = data.company || {}; const as = data.asn || {}; const loc = data.location || {};
  const companyType = usage(company.type);
  const scoreOf = value => ({ 'very low': 3, low: 10, elevated: 40, high: 70, 'very high': 90 })[String(/\(([^)]+)\)/.exec(String(value || ''))?.[1] || '').toLowerCase()] ?? null;
  return { record: record('ipapiis', ip, {
    country: country(loc.country_code), region: text(loc.state), city: text(loc.city), lat: num(loc.latitude), lon: num(loc.longitude), timezone: text(loc.timezone),
    asn: asn(as.asn), org: text(company.name) || text(as.org), networkType: companyType === 'residential' ? 'isp' : companyType, companyType,
    usageType: data.is_datacenter === true ? 'hosting' : data.is_mobile === true ? 'mobile' : null, asnType: text(as.type), risk: scoreOf(company.abuser_score),
    flags: { vpn: bool(data.is_vpn), proxy: bool(data.is_proxy), tor: bool(data.is_tor), relay: null, hosting: bool(data.is_datacenter), abuser: bool(data.is_abuser), crawler: bool(data.is_crawler), mobile: bool(data.is_mobile), bogon: bool(data.is_bogon) },
  }), ms: result.ms };
};

// ---------- verification & ASN routes ----------

async function readToken(request, kind) {
  const type = request.headers.get('Content-Type') || '';
  if (!type.includes('application/json')) return null;
  const maxTokenLength = kind === 'recaptcha' ? 8192 : 2048;
  const maxBodyBytes = kind === 'recaptcha' ? 16384 : 4096;
  const reader = request.body?.getReader();
  if (!reader) return null;
  const decoder = new TextDecoder();
  let body = ''; let bytes = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > maxBodyBytes) { await reader.cancel(); return null; }
      body += decoder.decode(chunk.value, { stream: true });
    }
    body += decoder.decode();
  } catch { return null; }
  finally { reader.releaseLock(); }
  try { const token = JSON.parse(body)?.token; return typeof token === 'string' && token.length >= 10 && token.length <= maxTokenLength ? token : null; }
  catch { return null; }
}

async function siteverify(kind, request, env, origin) {
  const token = await readToken(request, kind);
  if (!token) return failure(400, 'invalid-token', '缺少有效的 token。', origin);
  const form = new URLSearchParams({ secret: secret(kind === 'turnstile' ? env.TURNSTILE_SECRET_KEY : env.RECAPTCHA_SECRET_KEY), response: token });
  const caller = trustedCaller(request);
  if (caller) form.set('remoteip', caller);
  const endpoint = kind === 'turnstile' ? 'https://challenges.cloudflare.com/turnstile/v0/siteverify' : 'https://www.google.com/recaptcha/api/siteverify';
  const result = await upstream(endpoint, { method: 'POST', body: form, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }, kind === 'turnstile' ? 'Turnstile' : 'reCAPTCHA');
  if (result.error) return failure(result.error.status, result.error.code, result.error.message, origin);
  const data = result.data || {};
  const body = { success: data.success === true, hostname: text(data.hostname), challengeTs: text(data.challenge_ts), errorCodes: Array.isArray(data['error-codes']) ? data['error-codes'].map(String).slice(0, 5) : [] };
  if (kind === 'recaptcha') { body.score = num(data.score); body.action = text(data.action); }
  return json(body, 200, origin);
}

async function radar(url, env, origin, ctx) {
  const value = url.searchParams.get('asn') || '';
  if (!/^\d{1,10}$/.test(value) || Number(value) <= 0) return failure(400, 'invalid-asn', '需要一个 ASN 数字。', origin);
  const cacheKey = new Request(new URL(`/__egress_cache/radar-v1/${value}`, url.origin));
  const cached = await readCache(cacheKey);
  if (cached) return json({ ...cached, cacheHit: true }, 200, origin);
  const api = `https://api.cloudflare.com/client/v4/radar/http/summary/bot_class?asn=${value}&dateRange=28d&format=json`;
  const result = await upstream(api, { headers: { Authorization: `Bearer ${secret(env.CF_RADAR_TOKEN)}`, Accept: 'application/json' } }, 'Cloudflare Radar');
  if (result.error) return failure(result.error.status, result.error.code, result.error.message, origin);
  const summary = result.data?.result?.summary_0;
  const bot = num(summary?.bot); const human = num(summary?.human);
  if (bot === null || human === null) return failure(404, 'no-data', 'Radar 没有该 ASN 的流量数据。', origin);
  const body = { status: 'success', asn: Number(value), bot: Math.round(bot * 10) / 1000, human: Math.round(human * 10) / 1000, window: '28d', observedAt: new Date().toISOString() };
  await writeCache(cacheKey, body, ctx, 6 * 3600);
  return json({ ...body, cacheHit: false }, 200, origin);
}

// ---------- cache ----------
// A bound D1 database (under any binding name) keeps answers across isolates and regions. Without one the platform
// Cache API is tried, which on some hosts, Sites included, keeps nothing. Only answers this service fetched are stored.

let db = null;
let schema = null;
const cacheName = key => (typeof key === 'string' ? key : new URL(key.url).pathname);

function useDatabase(env) {
  db = Object.values(env || {}).find(value => value && typeof value.prepare === 'function' && typeof value.batch === 'function') || null;
}

function ready() {
  schema ??= db.prepare('CREATE TABLE IF NOT EXISTS egress_cache (k TEXT PRIMARY KEY, v TEXT NOT NULL, expires INTEGER NOT NULL)').run()
    .catch(error => { schema = null; throw error; });
  return schema;
}

async function readCache(key) {
  if (db) {
    try {
      await ready();
      const row = await db.prepare('SELECT v FROM egress_cache WHERE k = ? AND expires > ?').bind(cacheName(key), Date.now()).first();
      return row ? JSON.parse(row.v) : null;
    } catch { return null; }
  }
  const store = typeof caches !== 'undefined' ? caches.default : null;
  if (!store) return null;
  try { const hit = await store.match(key); return hit ? await hit.json() : null; } catch { return null; }
}

async function writeCache(key, body, ctx, seconds = CACHE_SECONDS) {
  let write;
  if (db) {
    write = ready().then(async () => {
      await db.prepare('INSERT OR REPLACE INTO egress_cache (k, v, expires) VALUES (?, ?, ?)').bind(cacheName(key), JSON.stringify(body), Date.now() + seconds * 1000).run();
      // Expired rows are swept now and then rather than on every write.
      if (Math.random() < 0.02) await db.prepare('DELETE FROM egress_cache WHERE expires < ?').bind(Date.now()).run();
    }).catch(() => {});
  } else {
    const store = typeof caches !== 'undefined' ? caches.default : null;
    if (!store) return;
    write = store.put(key, new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json', 'Cache-Control': `public, max-age=${seconds}` } })).catch(() => {});
  }
  if (ctx?.waitUntil) ctx.waitUntil(write); else await write;
}

// ---------- browser report relay ----------

async function warmPageService() {
  if (Date.now() < pageWarmUntil) return;
  if (!pageWarmup) {
    pageWarmup = (async () => {
      const response = await fetch(`${PAGE_SERVICE}/health`, { redirect: 'manual', signal: AbortSignal.timeout(75000) });
      if (!response.ok || (await response.json()).status !== 'ok') throw Error('page-service-unavailable');
      pageWarmUntil = Date.now() + 60000;
    })().finally(() => { pageWarmup = null; });
  }
  await pageWarmup;
}

async function fetchPageReport(provider, ip) {
  try {
    await warmPageService();
    await securityReady();
    const ticket = (crypto.randomUUID() + crypto.randomUUID()).replaceAll('-', '');
    await db.prepare('INSERT INTO egress_page_tickets (ticket, provider, ip, expires) VALUES (?, ?, ?, ?)')
      .bind(ticket, provider, ip, Date.now() + PAGE_TICKET_MS).run();
    const response = await fetch(`${PAGE_SERVICE}/lookup/${provider}`, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/json', Origin: DEFAULT_ORIGIN, 'X-Egress-Ticket': ticket },
      body: JSON.stringify({ ip }), signal: AbortSignal.timeout(110000),
    });
    if (!response.ok) {
      const status = response.status === 429 ? 429 : response.status >= 500 ? 503 : 502;
      return { error: { status, code: 'page-service-unavailable',
        message: status === 429 ? '网页查询服务正在处理其他请求，请稍后重试。' : '网页查询服务暂时不可用，请稍后重试。',
        after: Math.min(15, Math.max(1, Number(response.headers.get('Retry-After')) || 3)) } };
    }
    const report = await response.json();
    if (provider === 'getipintel' && report.time === undefined) report.time = Date.now();
    if (canonicalIP(report.ip) !== ip || !Number.isFinite(report.time) || Math.abs(Date.now() - report.time) > 600000) throw Error('page-target-or-time');
    let body;
    if (provider === 'getipintel') {
      if (!Number.isFinite(report.probability) || report.probability < 0 || report.probability > 1) throw Error('page-schema');
      body = { ip, time: report.time, probability: report.probability, risk: Math.round(report.probability * 100) };
    } else if (provider === 'sources') {
      if (!report.sources || typeof report.sources !== 'object' || Array.isArray(report.sources)) throw Error('page-schema');
      const sources = Object.fromEntries(['iphub', 'ipqs', 'ipdata', 'ipregistry', 'dbip', 'scamalytics', 'ipapiis', 'ipquery', 'blackbox']
        .filter(name => report.sources[name] && ['ok', 'error'].includes(report.sources[name].status)).map(name => [name, report.sources[name]]));
      if (!Object.keys(sources).length) throw Error('page-schema');
      body = { ip, time: report.time, sources };
    } else if (provider === 'ipinfo') {
      if (typeof report.text !== 'string' || report.text.length > 120000 || !report.text.includes('Summary')) throw Error('page-schema');
      body = { ip, time: report.time, text: report.text };
    } else {
      if (!Array.isArray(report.headers) || !report.headers.length || report.headers.length > 20
        || report.headers.some(name => typeof name !== 'string' || name.length > 80)) throw Error('page-schema');
      const rows = {};
      for (const name of ['使用类型', '公司类型']) {
        const row = report.rows?.[name];
        if (!Array.isArray(row) || row.length !== report.headers.length || row.some(value => typeof value !== 'string' || value.length > 80)) throw Error('page-schema');
        rows[name] = row;
      }
      const riskPercent = Object.fromEntries(Object.entries(report.riskPercent || {}).filter(([name, value]) => name.length <= 80 && typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100));
      const riskFlags = {};
      for (const name of ['IPData','IPRegistry','IP2Location','Scamalytics','IP-API','IPQualityScore','IPWhois','DBIP']) {
        const flags = Object.fromEntries(['hosting','abuser','proxy','vpn','tor','crawler'].filter(key => typeof report.riskFlags?.[name]?.[key] === 'boolean').map(key => [key,report.riskFlags[name][key]]));
        if (Object.keys(flags).length) riskFlags[name] = flags;
      }
      body = { ip, time: report.time, headers: report.headers, rows, riskPercent, riskFlags };
    }
    return { body };
  } catch (error) {
    const timeout = error.name === 'TimeoutError';
    return { error: { status: 503, code: timeout ? 'page-timeout' : 'page-service-unavailable',
      message: timeout ? '网页服务启动或查询超时，请稍后重试。' : '网页服务连接或报告读取失败，请稍后重试。', after: 3 } };
  }
}

async function pageLookup(provider, ip, url, origin, ctx) {
  const cacheKey = new Request(new URL(`/__egress_cache/page-${provider}-v3/${encodeURIComponent(ip)}`, url.origin));
  const cached = await readCache(cacheKey);
  const cacheMs = provider === 'sources' && Object.values(cached?.sources || {}).some(row => row.status !== 'ok') ? 60000 : 600000;
  if (cached?.ip === ip && Date.now() - cached.time < cacheMs) return json({ ...cached, cacheHit: true }, 200, origin, { 'X-Data-Cache': 'HIT' });
  const key = `${provider}:${ip}`;
  let pending = pageRequests.get(key);
  if (!pending) {
    if (pageRequests.size >= 32) return failure(503, 'page-service-busy', '网页查询服务繁忙，请稍后重试。', origin, { retryAfterSeconds: 5 });
    pending = (async () => {
      const result = await fetchPageReport(provider, ip);
      const ttl = provider === 'sources' && Object.values(result.body?.sources || {}).some(row => row.status !== 'ok') ? 60000 : 600000;
      if (result.body) await writeCache(cacheKey, result.body, ctx, Math.max(1, Math.floor((result.body.time + ttl - Date.now()) / 1000)));
      return result;
    })().finally(() => { pageRequests.delete(key); });
    pageRequests.set(key, pending);
  }
  const result = await pending;
  if (result.error) return failure(result.error.status, result.error.code, result.error.message, origin, { retryAfterSeconds: result.error.after });
  return json({ ...result.body, cacheHit: false }, 200, origin, { 'X-Data-Cache': 'MISS' });
}

// ---------- who checks each address ----------
// For every checked IP: how many times each querier asked. A querier is a salted hash of the caller's address and an
// anonymous per-browser id, so no address or id is stored as is; the salt is random and lives only in the database.
// A check counts towards the sharer estimate only when the caller's own address is the checked IP, i.e. that person
// is actually going out through it. New sharers per address are throttled so nobody can inflate a count quickly.
const SEEN_WINDOW_MS = 30 * 864e5;
const NEW_SHARERS_PER_HOUR = 5;
let seenSchema = null;

function seenReady() {
  seenSchema ??= db.batch([
    db.prepare('CREATE TABLE IF NOT EXISTS egress_salt (id INTEGER PRIMARY KEY CHECK (id = 1), salt TEXT NOT NULL)'),
    db.prepare('CREATE TABLE IF NOT EXISTS egress_seen (target TEXT NOT NULL, querier TEXT NOT NULL, self INTEGER NOT NULL, count INTEGER NOT NULL, first INTEGER NOT NULL, last INTEGER NOT NULL, PRIMARY KEY (target, querier))'),
    db.prepare('CREATE INDEX IF NOT EXISTS egress_seen_last ON egress_seen (last)'),
    db.prepare('INSERT OR IGNORE INTO egress_salt (id, salt) VALUES (1, ?)').bind(crypto.randomUUID() + crypto.randomUUID()),
  ]).then(() => db.prepare('SELECT salt FROM egress_salt WHERE id = 1').first('salt')).catch(error => { seenSchema = null; throw error; });
  return seenSchema;
}

async function digest(text) {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  return [...bytes.slice(0, 16)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function seen(request, url, origin) {
  if (!db) return failure(503, 'not-configured', '服务端未绑定数据库。', origin);
  const names = [...url.searchParams.keys()].sort().join(',');
  if (names !== 'client,ip') return failure(400, 'invalid-parameters', '只接受 ip 与 client 参数。', origin);
  const ip = publicIP(url.searchParams.get('ip'));
  const client = url.searchParams.get('client') || '';
  if (!ip) return failure(400, 'invalid-public-ip', '请输入公网 IPv4 或 IPv6。', origin);
  if (!/^[a-f0-9-]{32,40}$/.test(client)) return failure(400, 'invalid-client', '浏览器标识无效。', origin);
  const caller = trustedCaller(request);
  const self = caller === ip ? 1 : 0;
  const now = Date.now();
  try {
    const salt = await seenReady();
    const querier = await digest(`${salt}|${caller || 'unknown'}|${client}`);
    const since = now - SEEN_WINDOW_MS;
    // One statement checks the hourly cap and writes, so concurrent requests cannot slip past the cap together.
    // A known querier or a lookup of someone else's address is always recorded; a new sharer only under the cap.
    await db.prepare(`INSERT INTO egress_seen (target, querier, self, count, first, last)
      SELECT ?1, ?2, ?3, 1, ?4, ?4
      WHERE ?3 = 0 OR EXISTS (SELECT 1 FROM egress_seen WHERE target = ?1 AND querier = ?2)
        OR (SELECT COUNT(*) FROM egress_seen WHERE target = ?1 AND self = 1 AND first > ?5) < ?6
      ON CONFLICT (target, querier) DO UPDATE SET count = count + 1, last = excluded.last, self = MAX(self, excluded.self)`)
      .bind(ip, querier, self, now, now - 3600e3, NEW_SHARERS_PER_HOUR).run();
    // Every check also deletes rows older than the window (indexed on last), so retention does not depend on chance.
    await db.prepare('DELETE FROM egress_seen WHERE last < ?').bind(since).run();
    const row = await db.prepare('SELECT SUM(self) AS sharers, COUNT(*) AS lookers, SUM(count) AS lookups FROM egress_seen WHERE target = ? AND last > ?').bind(ip, since).first();
    return json({ status: 'success', ip, self: Boolean(self), callerKnown: Boolean(caller), sharers: row?.sharers || 0, lookers: row?.lookers || 0, lookups: row?.lookups || 0, windowDays: 30, observedAt: new Date(now).toISOString() }, 200, origin);
  } catch {
    return failure(503, 'seen-unavailable', '查询记录暂时不可用。', origin);
  }
}

// ---------- router ----------

async function handle(request, env, ctx) {
  useDatabase(env);
  const url = new URL(request.url);
  if (url.pathname === PAGE_ADMISSION) return pageAdmission(request);
  const sentOrigin = request.headers.get('Origin');
  const permitted = allowedOrigin(env, sentOrigin);
  if (!permitted) return failure(503, 'origin-configuration', '服务端来源配置无效。', null);
  if (sentOrigin !== null && sentOrigin !== permitted) return failure(403, 'origin-denied', '此来源未获允许。', null);
  const origin = sentOrigin === permitted ? permitted : null;
  const routes = enabledRoutes(env);
  const verifyKind = { '/v1/turnstile/verify': 'turnstile', '/v1/recaptcha/verify': 'recaptcha' }[url.pathname];
  const lookup = LOOKUPS[url.pathname];
  const pageName = url.pathname.startsWith('/v1/page/') ? url.pathname.slice('/v1/page/'.length) : '';
  const pageProvider = PAGE_PROVIDERS.has(pageName) ? pageName : null;
  const known = url.pathname === '/health' || url.pathname === '/v1/radar' || url.pathname === '/v1/seen' || Boolean(lookup) || Boolean(verifyKind) || Boolean(pageProvider);
  if (!known) return failure(404, 'not-found', '接口不存在。', origin);
  const method = verifyKind ? 'POST' : 'GET';

  if (request.method === 'OPTIONS') {
    if (!origin || request.headers.get('Access-Control-Request-Method') !== method) return failure(403, 'preflight-denied', '预检请求未获允许。', origin);
    const requested = (request.headers.get('Access-Control-Request-Headers') || '').split(',').map(item => item.trim().toLowerCase()).filter(Boolean);
    if (requested.some(item => !['accept', 'content-type'].includes(item))) return failure(403, 'preflight-headers-denied', '预检请求头未获允许。', origin);
    return new Response(null, { status: 204, headers: headers(origin, { 'Access-Control-Allow-Methods': `${method}, OPTIONS`, 'Access-Control-Allow-Headers': 'Accept, Content-Type', 'Access-Control-Max-Age': '600' }) });
  }
  if (request.method !== method) return failure(405, 'method-not-allowed', `仅支持 ${method}。`, origin);

  if (url.pathname === '/health') {
    return json({ status: 'ok', service: 'egress-observatory-api', apiVersion: API_VERSION, routes, providers: routes.filter(route => LOOKUPS[`/v1/${route}`]), cacheTTLSeconds: CACHE_SECONDS, staleSeconds: STALE_SECONDS, cacheStore: db ? 'd1' : typeof caches !== 'undefined' ? 'cache-api' : 'none', seen: Boolean(db), callerKnown: Boolean(trustedCaller(request)), rateLimitPerMinute: RATE_LIMIT, rateLimitStore: db ? 'd1' : 'unavailable', pageAdmission: 'single-use-ticket' }, 200, origin);
  }

  const slot = await takeRateSlot(request);
  if (slot.unavailable) return failure(503, 'rate-limit-unavailable', '调用者地址或额度校验暂时不可用，请稍后重试。', origin, { retryAfterSeconds: 5 });
  if (!slot.allowed) return failure(429, 'caller-rate-limit', `当前出口 IP 的请求频率超过每分钟 ${RATE_LIMIT} 次。`, origin, { retryAfterSeconds: slot.retryAfter });

  if (verifyKind) {
    if (!routes.includes(`${verifyKind}-verify`)) return failure(503, 'not-configured', '服务端未配置该验证密钥。', origin);
    return siteverify(verifyKind, request, env, origin);
  }
  if (url.pathname === '/v1/seen') return seen(request, url, origin);
  if (url.pathname === '/v1/radar') {
    if (!routes.includes('radar')) return failure(503, 'not-configured', '服务端未配置 Radar token。', origin);
    return radar(url, env, origin, ctx);
  }

  if (!pageProvider && !routes.includes(lookup)) return failure(503, 'provider-not-configured', '该来源未配置服务端密钥。', origin);
  const names = [...url.searchParams.keys()];
  if (names.length !== 1 || names[0] !== 'ip') return failure(400, 'invalid-parameters', '只接受一个 ip 参数。', origin);
  const ip = publicIP(url.searchParams.get('ip'));
  if (!ip) return failure(400, 'invalid-public-ip', '请输入公网 IPv4 或 IPv6；域名、URL、私网及保留地址不接受。', origin);
  if (pageProvider) return pageLookup(pageProvider, ip, url, origin, ctx);

  // Versioned, IP-only cache key: no secrets, no inbound headers.
  const cacheKey = new Request(new URL(`/__egress_cache/${lookup}-v3/${encodeURIComponent(ip)}`, url.origin));
  const cached = await readCache(cacheKey);
  if (cached?.status === 'success' && cached.ip === ip) return json({ ...cached, cacheHit: true }, 200, origin, { 'X-Data-Cache': 'HIT' });
  const result = await PROVIDERS[lookup](ip, env);
  const staleKey = new Request(new URL(`/__egress_cache/${lookup}-stale-v1/${encodeURIComponent(ip)}`, url.origin));
  if (result.error) {
    // Only answers this service fetched itself are kept, so a stale copy cannot be planted by a client.
    const stale = await readCache(staleKey);
    if (stale?.status === 'success' && stale.ip === ip) return json({ ...stale, cacheHit: true, stale: true, staleReason: result.error.message }, 200, origin, { 'X-Data-Cache': 'STALE' });
    const { status, code, message, retryAfter: after } = result.error;
    return failure(status, code, message, origin, after ? { retryAfterSeconds: after } : {});
  }
  await writeCache(cacheKey, result.record, ctx, CACHE_FOR[lookup] || CACHE_SECONDS);
  await writeCache(staleKey, result.record, ctx, STALE_SECONDS);
  return json({ ...result.record, duration: result.ms, cacheHit: false }, 200, origin, { 'X-Data-Cache': 'MISS' });
}

export default {
  async fetch(request, env = {}, ctx) {
    try { return await handle(request, env, ctx); }
    catch {
      const permitted = allowedOrigin(env, request.headers.get('Origin'));
      return failure(500, 'internal-error', '接口暂时无法处理请求。', permitted && request.headers.get('Origin') === permitted ? permitted : null);
    }
  },
};
