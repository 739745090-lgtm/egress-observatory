/**
 * IP intelligence sources. Each adapter queries exactly one target and normalizes to:
 * { country, region, city, lat, lon, asn, org, tz, type, flags:{vpn,proxy,tor,hosting,relay,abuser,crawler,mobile,bogon},
 *   risk (0–100, higher = riskier), regCountry, hostname, ... }
 * Unknown stays null — a missing field is never turned into a negative.
 */
import { getJSON, countryCode, asnNumber, text, bool, num, parseIP, sameIP, reverseName } from './util.js';
import { API_BASE } from '../config.js';

const flags = (values = {}) => ({ vpn: null, proxy: null, tor: null, hosting: null, relay: null, abuser: null, crawler: null, mobile: null, bogon: null, ...values });
const RIPE = 'https://stat.ripe.net/data';
const ripeURL = (call, params) => `${RIPE}/${call}/data.json?${new URLSearchParams({ ...params, sourceapp: 'egress-observatory' })}`;

function fail(message) { const error = new Error(message); error.soft = true; throw error; }
function checkIP(returned, ip) { if (returned && !sameIP(returned, ip)) fail('返回目标与查询 IP 不一致'); }
const label = value => ({ 'very low': 3, low: 10, elevated: 40, high: 70, 'very high': 90 })[String(value || '').toLowerCase()] ?? null;

async function json(url, ctx, options) {
  const result = await getJSON(url, { signal: ctx.signal, timeout: 12000, ...options });
  if (!result.ok) fail(result.error);
  return result;
}

const EXTRA_KEYS = ['noise', 'riot', 'classification', 'name', 'reputation', 'behaviors', 'block', 'probability', 'riskLabel', 'vtMalicious', 'vtSuspicious', 'vtReputation',
  'asnType', 'resProxy', 'satellite', 'anycast', 'privacyService', 'activeVpn', 'activeTor', 'abuseVelocity', 'connectionType', 'reports', 'lastReported'];

function workerRecord(data, ip) {
  if (!data || data.status !== 'success') fail(data?.error || '服务端未返回结果');
  checkIP(data.ip, ip);
  const out = {
    country: countryCode(data.country), city: text(data.city), region: text(data.region), lat: num(data.lat), lon: num(data.lon),
    asn: asnNumber(data.asn), org: text(data.org), tz: text(data.timezone),
    type: ['residential', 'isp', 'mobile', 'business', 'hosting', 'education'].includes(data.usageType || data.networkType) ? (data.usageType || data.networkType) : null,
    // Older backend versions only send networkType; treat it as the usage type (isp = residential).
    usageType: ['residential', 'mobile', 'business', 'hosting', 'education', 'government'].includes(data.usageType) ? data.usageType
      : ({ isp: 'residential', residential: 'residential', mobile: 'mobile', business: 'business', hosting: 'hosting', education: 'education' })[data.networkType] || null,
    companyType: ['residential', 'isp', 'mobile', 'business', 'hosting', 'education', 'government'].includes(data.companyType) ? data.companyType : null,
    flags: flags(Object.fromEntries(Object.entries(data.flags || {}).map(([key, value]) => [key, bool(value)]))),
    risk: num(data.risk), hostname: text(data.hostname), cacheHit: data.cacheHit === true,
  };
  if (data.devices) out.devices = { address: num(data.devices.address), subnet: num(data.devices.subnet) };
  if (data.lastSeen) out.lastSeen = text(data.lastSeen);
  for (const key of EXTRA_KEYS) {
    const value = data[key];
    if (typeof value === 'string') out[key] = text(value);
    else if (typeof value === 'number' && Number.isFinite(value)) out[key] = value;
    else if (typeof value === 'boolean') out[key] = value;
    else if (Array.isArray(value)) out[key] = value.map(item => text(String(item))).filter(Boolean).slice(0, 6);
  }
  return out;
}

/** Worker routes that need the owner's own API key; absent keys show as "未配置" and do not count. */
const optionalWorker = (route, geo = true) => async (ip, ctx) => {
  const health = await ctx.healthReady;
  if (!health?.routes?.includes(route)) { const error = new Error('未配置密钥'); error.skip = true; throw error; }
  const { data, ms } = await json(`${API_BASE}/v1/${route}?ip=${encodeURIComponent(ip)}`, ctx);
  // Threat and fraud services are not geolocation databases; keep them out of the location vote.
  return { ...workerRecord(data, ip), ...(geo ? {} : { geoVote: false }), _ms: ms };
};

const worker = (route) => async (ip, ctx) => {
  const health = await ctx.healthReady;
  if (!health?.routes?.includes(route)) fail(health ? '服务端未启用此来源（需要重新部署）' : '服务端不可用');
  const { data, ms } = await json(`${API_BASE}/v1/${route}?ip=${encodeURIComponent(ip)}`, ctx);
  return { ...workerRecord(data, ip), _ms: ms };
};

export const SOURCES = [
  {
    id: 'netcoffee', name: 'Net.Coffee', group: 'intel', site: ip => `https://ip.net.coffee/ip/${ip}`,
    async run(ip, ctx) {
      const {data} = await json(`https://ip.net.coffee/api/ip/lookup/${encodeURIComponent(ip)}`, ctx);
      if (!data.ip || !sameIP(data.ip, ip)) fail('Net.Coffee 返回目标不匹配');
      const companyType = new Map(Object.entries({hosting:'hosting', isp:'residential', business:'business', education:'education', government:'government', mobile:'mobile'})).get(data.company_type) || null;
      const usageType = data.is_datacenter === true ? 'hosting' : data.is_mobile === true ? 'mobile' : data.isResidential === true ? 'residential' : null;
      return {companyType, usageType, flags:flags(), country:countryCode(data.countryCode), city:text(data.city), geoVote:false,
        sourceNote:'Net.Coffee 查询结果；上游类型库未具名，独立展示。'};
    },
  },
  // ---------- IP intelligence & geolocation ----------
  {
    id: 'proxycheck', name: 'Proxycheck', group: 'intel', site: ip => `https://proxycheck.io/threats/${ip}`,
    run: worker('proxycheck'),
  },
  {
    id: 'ipapi', name: 'ip-api.com', group: 'intel', site: ip => `https://ip-api.com/#${ip}`,
    run: worker('ipapi'),
  },
  {
    id: 'ip2location', name: 'IP2Location', group: 'intel', site: ip => `https://www.ip2location.io/${ip}`,
    run: worker('ip2location'),
  },
  {
    id: 'dbip', name: 'DB-IP', group: 'intel', site: ip => `https://db-ip.com/${ip}`,
    run: worker('dbip'),
  },
  {
    id: 'abuseipdb', name: 'AbuseIPDB', group: 'threat', site: ip => `https://www.abuseipdb.com/check/${ip}`, optional: true,
    async run(ip, ctx) {
      const health = await ctx.healthReady;
      if (!health?.routes?.includes('abuseipdb')) { const error = new Error('未配置密钥'); error.skip = true; throw error; }
      const { data } = await json(`${API_BASE}/v1/abuseipdb?ip=${encodeURIComponent(ip)}`, ctx);
      const record = workerRecord(data, ip);
      record.reports = num(data.reports); record.lastReported = text(data.lastReported);
      record.rawUsageType = text(data.usageType);
      record.type = record.usageType;
      record.sourceNote = '国家、ISP 和使用类型来自 IPinfo；举报记录和滥用置信分来自 AbuseIPDB。';
      if (data.block) record.block = { prefix: text(data.block.prefix), reported: num(data.block.reported) || 0, maxScore: num(data.block.maxScore) };
      return record;
    },
  },
  {
    id: 'ipqs', name: 'IPQualityScore', group: 'intel', site: ip => `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${ip}`, optional: true,
    async run(ip, ctx) {
      const health = await ctx.healthReady;
      if (!health?.routes?.includes('ipqs')) { const error = new Error('未配置密钥'); error.skip = true; throw error; }
      const { data } = await json(`${API_BASE}/v1/ipqs?ip=${encodeURIComponent(ip)}`, ctx);
      const record = workerRecord(data, ip);
      record.activeVpn = data.activeVpn === true; record.activeTor = data.activeTor === true;
      record.abuseVelocity = text(data.abuseVelocity); record.connectionType = text(data.connectionType);
      return record;
    },
  },
  {
    id: 'ipregistry', name: 'IPRegistry', group: 'intel', site: ip => `https://ipregistry.co/${ip}`, optional: true, run: optionalWorker('ipregistry'),
  },
  {
    id: 'ipdata', name: 'IPData', group: 'intel', site: ip => `https://ipdata.co/?ip=${ip}`, optional: true, run: optionalWorker('ipdata'),
  },
  {
    id: 'ipquery', name: 'IPQuery', group: 'intel', site: ip => `https://ipquery.io/?ip=${ip}`,
    async run(ip, ctx) {
      const { data } = await json(`https://api.ipquery.io/${encodeURIComponent(ip)}?format=json`, ctx);
      checkIP(data.ip, ip);
      return {
        country: countryCode(data.location?.country_code), region: text(data.location?.state), city: text(data.location?.city),
        lat: num(data.location?.latitude), lon: num(data.location?.longitude), tz: text(data.location?.timezone),
        asn: asnNumber(data.isp?.asn), org: text(data.isp?.org) || text(data.isp?.isp),
        flags: flags({ vpn: bool(data.risk?.is_vpn), proxy: bool(data.risk?.is_proxy), tor: bool(data.risk?.is_tor), hosting: bool(data.risk?.is_datacenter), mobile: bool(data.risk?.is_mobile) }),
        type: data.risk?.is_mobile === true ? 'mobile' : null,
        usageType: data.risk?.is_datacenter === true ? 'hosting' : data.risk?.is_mobile === true ? 'mobile' : null,
        risk: num(data.risk?.risk_score),
      };
    },
  },
  {
    id: 'ipapiis', name: 'ipapi.is', group: 'intel', site: ip => `https://ipapi.is/?q=${ip}`,
    async run(ip, ctx) {
      const health = await ctx.healthReady;
      if (health?.routes?.includes('ipapiis')) {
        const { data, ms } = await json(`${API_BASE}/v1/ipapiis?ip=${encodeURIComponent(ip)}`, ctx);
        return { ...workerRecord(data, ip), _ms: ms };
      }
      const { data } = await json(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`, ctx);
      if (data.error) fail(text(data.error) || '拒绝查询');
      checkIP(data.ip, ip);
      const company = typeof data.company === 'object' ? data.company : null;
      const asn = typeof data.asn === 'object' ? data.asn : null;
      const type = { isp: 'isp', hosting: 'hosting', business: 'business', education: 'education', government: 'business', banking: 'business' }[company?.type] || null;
      return {
        country: countryCode(data.location?.country_code || data.country), region: text(data.location?.state || data.region),
        city: text(data.location?.city || data.city), lat: num(data.location?.latitude ?? data.lat), lon: num(data.location?.longitude ?? data.lon),
        tz: text(data.location?.timezone || data.timezone), asn: asnNumber(asn?.asn ?? data.asn), org: text(company?.name || data.company),
        flags: flags({
          bogon: bool(data.is_bogon), mobile: bool(data.is_mobile), crawler: bool(data.is_crawler), hosting: bool(data.is_datacenter),
          tor: bool(data.is_tor), proxy: bool(data.is_proxy), vpn: bool(data.is_vpn), abuser: bool(data.is_abuser),
        }),
        type, risk: label(/\(([^)]+)\)/.exec(String(company?.abuser_score || ''))?.[1]),
        usageType: data.is_datacenter === true ? 'hosting' : data.is_mobile === true ? 'mobile' : null,
        companyType: { isp: 'residential', hosting: 'hosting', business: 'business', education: 'education', government: 'government', banking: 'business' }[company?.type] || null,
        asnType: text(asn?.type), companyDomain: text(company?.domain),
      };
    },
  },
  {
    id: 'ipinfo', name: 'IPinfo', group: 'intel', site: ip => `https://ipinfo.io/${ip}`,
    async run(ip, ctx) {
      // Prefer the token-backed backend route (higher quota, privacy fields on paid plans); else the public API.
      const health = await ctx.healthReady;
      if (health?.routes?.includes('ipinfo')) {
        const { data, ms } = await json(`${API_BASE}/v1/ipinfo?ip=${encodeURIComponent(ip)}`, ctx);
        return { ...workerRecord(data, ip), asnType: text(data.asnType), privacyService: text(data.privacyService), anycast: data.anycast === true, resProxy: data.resProxy === true, satellite: data.satellite === true, _ms: ms };
      }
      const { data } = await json(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, ctx);
      checkIP(data.ip, ip);
      const [lat, lon] = String(data.loc || '').split(',').map(Number);
      return {
        country: countryCode(data.country), region: text(data.region), city: text(data.city), lat: Number.isFinite(lat) ? lat : null, lon: Number.isFinite(lon) ? lon : null,
        tz: text(data.timezone), asn: asnNumber(data.org), org: text(data.org)?.replace(/^AS\d+\s+/i, '') || null,
        hostname: text(data.hostname), flags: flags({ bogon: bool(data.bogon) }), anycast: data.anycast === true,
      };
    },
  },
  {
    id: 'ipwhois', name: 'ipwho.is', group: 'intel', site: ip => `https://ipwho.is/${ip}`,
    async run(ip, ctx) {
      const { data } = await json(`https://ipwho.is/${encodeURIComponent(ip)}`, ctx);
      if (data.success === false) fail(text(data.message) || '拒绝查询');
      checkIP(data.ip, ip);
      return {
        country: countryCode(data.country_code), region: text(data.region), city: text(data.city), lat: num(data.latitude), lon: num(data.longitude),
        tz: text(data.timezone?.id), asn: asnNumber(data.connection?.asn), org: text(data.connection?.org) || text(data.connection?.isp),
        isp: text(data.connection?.isp), domain: text(data.connection?.domain), flags: flags(),
      };
    },
  },
  {
    id: 'ipsb', name: 'IP.SB', group: 'intel', site: ip => `https://ip.sb/ip/${ip}`,
    async run(ip, ctx) {
      const { data } = await json(`https://api.ip.sb/geoip/${encodeURIComponent(ip)}`, ctx);
      checkIP(data.ip, ip);
      return {
        country: countryCode(data.country_code), region: text(data.region), city: text(data.city), lat: num(data.latitude), lon: num(data.longitude),
        tz: text(data.timezone), asn: asnNumber(data.asn), org: text(data.isp) || text(data.organization), flags: flags(),
      };
    },
  },
  {
    id: 'ipleak', name: 'ipleak (MaxMind)', group: 'intel', site: ip => `https://ipleak.net/${ip}`,
    async run(ip, ctx) {
      const { data } = await json(`https://ipleak.net/json/${encodeURIComponent(ip)}`, ctx);
      checkIP(data.ip, ip);
      return {
        country: countryCode(data.country_code), region: text(data.region_name), city: text(data.city_name), lat: num(data.latitude), lon: num(data.longitude),
        tz: text(data.time_zone), asn: asnNumber(data.as_number), org: text(data.isp_name), regCountry: countryCode(data.registered_country_code),
        hostname: text(data.reverse), prefix: text(data.as_network), flags: flags(),
      };
    },
  },
  {
    id: 'geojs', name: 'GeoJS', group: 'intel', site: () => 'https://www.geojs.io/',
    async run(ip, ctx) {
      const { data } = await json(`https://get.geojs.io/v1/ip/geo/${encodeURIComponent(ip)}.json`, ctx);
      checkIP(data.ip, ip);
      return {
        country: countryCode(data.country_code), region: text(data.region), city: text(data.city), lat: num(data.latitude), lon: num(data.longitude),
        tz: text(data.timezone), asn: asnNumber(data.asn), org: text(data.organization_name), flags: flags(),
      };
    },
  },
  {
    id: 'ipapico', name: 'ipapi.co', group: 'intel', site: ip => `https://ipapi.co/${ip}/`,
    async run(ip, ctx) {
      const { data } = await json(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, ctx);
      if (data.error) fail(text(data.reason) || '拒绝查询');
      checkIP(data.ip, ip);
      return {
        country: countryCode(data.country_code), region: text(data.region), city: text(data.city), lat: num(data.latitude), lon: num(data.longitude),
        tz: text(data.timezone), asn: asnNumber(data.asn), org: text(data.org), prefix: text(data.network), flags: flags(),
      };
    },
  },
  {
    id: 'iplocation', name: 'iplocation.net', group: 'intel', site: ip => `https://www.iplocation.net/ip-lookup?query=${ip}`,
    async run(ip, ctx) {
      const { data } = await json(`https://api.iplocation.net/?ip=${encodeURIComponent(ip)}`, ctx);
      if (String(data.response_code) !== '200') fail(text(data.response_message) || '拒绝查询');
      checkIP(data.ip, ip);
      return { country: countryCode(data.country_code2), org: text(data.isp), flags: flags() };
    },
  },
  {
    id: 'freeipapi', name: 'FreeIPAPI', group: 'intel', site: () => 'https://freeipapi.com/',
    async run(ip, ctx) {
      const { data } = await json(`https://free.freeipapi.com/api/v1/json/${encodeURIComponent(ip)}`, ctx);
      checkIP(data.ipAddress, ip);
      return {
        country: countryCode(data.countryCode), region: text(data.regionName), city: text(data.cityName), lat: num(data.latitude), lon: num(data.longitude),
        tz: text(data.timeZones?.[0]), asn: asnNumber(data.asn), org: text(data.asnOrganization), flags: flags({ proxy: bool(data.isProxy) }),
      };
    },
  },
  {
    id: 'maxmind', name: 'GeoLite2 (RIPEstat)', group: 'intel', site: ip => `https://stat.ripe.net/app/${ip}`,
    async run(ip, ctx) {
      const { data } = await json(ripeURL('maxmind-geo-lite', { resource: ip }), ctx);
      const location = data.data?.located_resources?.[0]?.locations?.[0];
      if (!location) fail('无定位数据');
      return { country: countryCode(location.country), city: text(location.city), lat: num(location.latitude), lon: num(location.longitude), flags: flags() };
    },
  },
  {
    id: 'iplocate', name: 'IPLocate', group: 'intel', site: ip => `https://www.iplocate.io/lookup/${ip}`,
    async run(ip, ctx) {
      const { data } = await json(`https://www.iplocate.io/api/lookup/${encodeURIComponent(ip)}`, ctx);
      if (data.error) fail(text(data.error) || '拒绝查询');
      checkIP(data.ip, ip);
      const p = data.privacy || {};
      const COMPANY = { isp: 'residential', hosting: 'hosting', business: 'business', education: 'education', government: 'government' };
      return {
        country: countryCode(data.country_code), region: text(data.subdivision), city: text(data.city), lat: num(data.latitude), lon: num(data.longitude), tz: text(data.time_zone),
        asn: asnNumber(data.asn?.asn), org: text(data.company?.name) || text(data.asn?.name),
        flags: flags({ vpn: bool(p.is_vpn), proxy: bool(p.is_proxy), tor: bool(p.is_tor), relay: bool(p.is_icloud_relay), hosting: bool(p.is_hosting), abuser: bool(p.is_abuser), bogon: bool(p.is_bogon) }),
        type: p.is_hosting === true ? 'hosting' : null, usageType: p.is_hosting === true ? 'hosting' : null,
        companyType: COMPANY[data.company?.type] || null, asnType: text(data.asn?.type), anycast: data.is_anycast === true,
      };
    },
  },
  {
    id: 'geoiplookup', name: 'GeoIPLookup', group: 'intel', site: ip => `https://geoiplookup.io/ip/${ip}`,
    async run(ip, ctx) {
      const { data } = await json(`https://json.geoiplookup.io/${encodeURIComponent(ip)}`, ctx);
      if (data.success === false) fail('拒绝查询');
      checkIP(data.ip, ip);
      const connection = String(data.connection_type || '');
      const usageType = /corporate|business/i.test(connection) ? 'business' : /cable|dsl|dialup|residential|fiber/i.test(connection) ? 'residential'
        : /cellular|mobile/i.test(connection) ? 'mobile' : /hosting|data ?cent/i.test(connection) ? 'hosting' : null;
      return {
        country: countryCode(data.country_code), region: text(data.region), city: text(data.city), lat: num(data.latitude), lon: num(data.longitude), tz: text(data.timezone_name),
        asn: asnNumber(data.asn_number), org: text(data.org) || text(data.isp), hostname: text(data.hostname), type: usageType, usageType, flags: flags(),
      };
    },
  },
  {
    // A published supplementary service. Its underlying vendor is not independently asserted.
    // Wait for this target's actual primary result, rather than assuming an enabled route succeeded.
    id: 'ipapimirror', name: 'TechnikNews IPgeo', group: 'intel', site: () => 'https://api.techniknews.net/',
    async run(ip, ctx) {
      const primary = await ctx.sourceReady?.get('ipapi');
      if (primary?.status === 'ok') { const error = new Error('主来源已返回，本轮无需补充'); error.skip = true; throw error; }
      if (ctx.signal?.aborted) fail('本轮查询已取消');
      const { data } = await json(`https://api.techniknews.net/ipgeo/${encodeURIComponent(ip)}`, ctx);
      if (data.status !== 'success') fail('拒绝查询');
      if (!data.ip) fail('补充来源未标明目标 IP');
      checkIP(data.ip, ip);
      const usageType = data.hosting === true ? 'hosting' : data.mobile === true ? 'mobile' : null;
      const cacheSeconds = num(data.cacheTimestamp);
      const sourceUpdatedAt = cacheSeconds > 0 && cacheSeconds <= Date.now() / 1000 + 300 ? new Date(cacheSeconds * 1000).toISOString() : null;
      return {
        country: countryCode(data.countryCode), region: text(data.regionName), city: text(data.city), lat: num(data.lat), lon: num(data.lon), tz: text(data.timezone),
        asn: asnNumber(data.as), org: text(data.org) || text(data.isp), type: usageType, usageType,
        flags: flags({ proxy: bool(data.proxy), hosting: bool(data.hosting), mobile: bool(data.mobile) }),
        hostname: text(data.reverse), cached: bool(data.cached), sourceUpdatedAt,
        via: 'TechnikNews IPgeo', sourceNote: `通过 TechnikNews 公开接口补充；原始数据库归属未独立核实${sourceUpdatedAt ? `；来源缓存时间 ${sourceUpdatedAt}` : ''}`,
        primaryFailure: primary?.error || null,
      };
    },
  },
  {
    id: 'blackbox', name: 'Blackbox v3 beta', group: 'intel', site: () => 'https://blackbox.ipinfo.app/',
    async run(ip, ctx) {
      const { data } = await json(`https://blackbox.ipinfo.app/api/v3beta/${encodeURIComponent(ip)}`, ctx);
      if (data.error || !data.ip || !data.signals || typeof data.signals !== 'object') fail('Beta 接口未返回可识别的目标与分类字段');
      checkIP(data.ip, ip);
      const signals = data.signals;
      const detected = (...values) => values.some(value => value === true) ? true : values.length && values.every(value => value === false) ? false : null;
      const classification = text(data.classification);
      const hasClassification = ['residential', 'mobile', 'business', 'hosting', 'vpn', 'tor', 'privacy_relay', 'bogon'].includes(classification);
      const classifiedFlag = value => value === true ? true : hasClassification ? bool(value) : null;
      const usageType = { residential: 'residential', mobile: 'mobile', business: 'business', hosting: 'hosting' }[classification] || null;
      const hostname = text(data.rdns?.hostname);
      return {
        asn: asnNumber(data.asn?.number), org: text(data.asn?.name), hostname,
        prefix: data.asn?.network && Number.isInteger(data.asn?.cidr) ? `${data.asn.network}/${data.asn.cidr}` : null,
        type: usageType, usageType, geoVote: false,
        flags: flags({
          proxy: classifiedFlag(signals.proxy), tor: classifiedFlag(signals.tor), bogon: classifiedFlag(signals.bogon),
          vpn: classification === 'vpn' ? true : classifiedFlag(signals.vpnasn), relay: classifiedFlag(signals.goodvpn),
          hosting: classifiedFlag(detected(signals.hosting, signals.cloud)), mobile: classification === 'mobile' ? true : classifiedFlag(signals.mobileasn),
        }),
        classification, classificationConfidence: num(data.confidence),
        classificationEvidence: Array.isArray(data.evidence) ? data.evidence.map(text).filter(Boolean).slice(0, 15) : [],
        sourceVersion: text(data.version), spamhausListed: bool(signals.spamhaus),
        sfsListed: bool(signals.sfs_listed), ic3Listed: bool(signals.ic3_listed),
        // Feed-derived reputation remains supplementary; SFS/Tor are already queried separately.
        sourceNote: `ipinfo.app 的公开 Beta 分类服务；分类与具体标记分开使用，未把“机房”视为“代理”${data.version ? `；版本 ${text(data.version)}` : ''}`,
      };
    },
  },
  {
    id: 'netatlas', name: 'Net Atlas', group: 'registry', site: () => 'https://www.ipinfo.app/api/ip2country/',
    async run(ip, ctx) {
      const { data } = await json(`https://atlas.ipinfo.app/api/v2/ip/${encodeURIComponent(ip)}`, ctx);
      if (data.error || !data.ip) fail('Net Atlas 未返回有效目标');
      checkIP(data.ip, ip);
      const location = data.location && typeof data.location === 'object' ? data.location : null;
      const dbipLocation = location?.source === 'baseline';
      return {
        country: countryCode(location?.country_code), region: text(location?.region), city: text(location?.city),
        lat: num(location?.latitude), lon: num(location?.longitude), asn: asnNumber(data.as_number), org: text(data.as_description),
        prefix: text(data.cidr), networkCountry: countryCode(data.country_code), flags: flags(), geoVote: dbipLocation,
        locationSource: text(location?.source), sourceVersion: text(data.version),
        locationDatabase: dbipLocation ? 'DB-IP City Lite' : null,
        locationConfidence: text(location?.confidence), locationAccuracyKm: num(location?.accuracy_km),
        sourceNote: `Net Atlas 经 IPtoASN/BGP 提供网络归属；城市数据：IP Geolocation by DB-IP (CC BY 4.0)。${dbipLocation ? '本次为 DB-IP City Lite 补充，与 DB-IP 同库只计一票。' : `本次定位来源 ${text(location?.source) || '未提供'}，只展示，不增加独立定位票。`}`,
      };
    },
  },
  {
    id: 'cloudflare', name: 'Cloudflare', group: 'intel', selfOnly: true, site: () => 'https://radar.cloudflare.com/ip',
    async run(ip, ctx) {
      const host = parseIP(ip)?.v === 6 ? 'ipv6' : 'ipv4';
      const { data } = await json(`https://${host}-check-perf.radar.cloudflare.com/`, ctx);
      if (!sameIP(data.ip_address, ip)) fail('浏览器当前出口与目标不同');
      return {
        country: countryCode(data.country), region: text(data.region), city: text(data.city), lat: num(data.latitude), lon: num(data.longitude),
        asn: asnNumber(data.asn), colo: text(data.colo), flags: flags(),
      };
    },
  },

  // ---------- registration & routing ----------
  {
    id: 'rdap', name: 'RDAP (RIR)', group: 'registry', site: ip => `https://client.rdap.org/?type=ip&object=${ip}`,
    async run(ip, ctx) {
      const { data } = await json(`https://rdap.org/ip/${encodeURIComponent(ip)}`, ctx, { init: { headers: { Accept: 'application/rdap+json' } } });
      if (data.errorCode) fail(`RDAP ${data.errorCode}`);
      const events = Object.fromEntries((data.events || []).map(event => [event.eventAction, event.eventDate]));
      const vcard = entity => Object.fromEntries((entity?.vcardArray?.[1] || []).map(item => [item[0], item[0] === 'adr' ? item[1]?.label || item[3] : item[3]]));
      const flat = [];
      const walk = list => (list || []).forEach(entity => { flat.push(entity); walk(entity.entities); });
      walk(data.entities);
      const registrant = flat.find(entity => entity.roles?.includes('registrant') && vcard(entity).kind === 'org') || flat.find(entity => entity.roles?.includes('registrant'));
      const abuse = flat.find(entity => entity.roles?.includes('abuse'));
      const org = vcard(registrant);
      const address = typeof org.adr === 'string' ? org.adr.split('\n').map(line => line.trim()).filter(Boolean) : [];
      const cidr = data.cidr0_cidrs?.[0] ? `${data.cidr0_cidrs[0].v4prefix || data.cidr0_cidrs[0].v6prefix}/${data.cidr0_cidrs[0].length}` : null;
      return {
        regCountry: countryCode(data.country), netname: text(data.name), handle: text(data.handle), status: text(data.type) || (data.status || []).join(', '),
        range: data.startAddress && data.endAddress ? `${data.startAddress} – ${data.endAddress}` : null, cidr,
        regDate: text(events.registration), changed: text(events['last changed']),
        orgName: text(org.fn), orgCountry: countryCode(address[address.length - 1]), abuseName: text(vcard(abuse).fn),
        abuseEmail: text(vcard(abuse).email), rir: text(data.port43)?.replace(/^whois\./, '').replace(/\.net$|\.(?:net|org)$/i, '').toUpperCase() || null,
        flags: flags(), geoVote: false,
      };
    },
  },
  {
    id: 'ipguide', name: 'ip.guide', group: 'registry', site: ip => `https://ip.guide/${ip}`,
    async run(ip, ctx) {
      const { data } = await json(`https://ip.guide/${encodeURIComponent(ip)}`, ctx);
      checkIP(data.ip, ip);
      const as = data.network?.autonomous_system || {};
      return {
        asn: asnNumber(as.asn), org: text(as.organization), asName: text(as.name), asCountry: countryCode(as.country), rir: text(as.rir),
        prefix: text(data.network?.cidr), country: countryCode(data.location?.country), city: text(data.location?.city),
        lat: num(data.location?.latitude), lon: num(data.location?.longitude), tz: text(data.location?.timezone), flags: flags(),
      };
    },
  },
  {
    id: 'riperir', name: 'RIR 分配记录', group: 'registry', site: ip => `https://stat.ripe.net/app/${ip}`,
    async run(ip, ctx) {
      const { data } = await json(ripeURL('rir-stats-country', { resource: ip }), ctx);
      const located = data.data?.located_resources?.[0];
      if (!located?.location) fail('无记录');
      return { regCountry: countryCode(located.location), block: text(located.resource), flags: flags(), geoVote: false };
    },
  },
  {
    id: 'ripeprefix', name: 'RIPEstat 路由', group: 'registry', site: ip => `https://bgp.tools/prefix/${ip}`,
    async run(ip, ctx) {
      const { data } = await json(ripeURL('prefix-overview', { resource: ip }), ctx);
      const asns = data.data?.asns || [];
      if (!data.data?.announced) return { announced: false, flags: flags(), geoVote: false };
      return { announced: true, prefix: text(data.data.resource), asn: asnNumber(asns[0]?.asn), asName: text(asns[0]?.holder), origins: asns.length, flags: flags(), geoVote: false };
    },
  },

  // ---------- threat & scan ----------
  {
    id: 'otx', name: 'AlienVault OTX', group: 'threat', site: ip => `https://otx.alienvault.com/indicator/ip/${ip}`,
    async run(ip, ctx) {
      const kind = parseIP(ip).v === 6 ? 'IPv6' : 'IPv4';
      const { data } = await json(`https://otx.alienvault.com/api/v1/indicators/${kind}/${encodeURIComponent(ip)}/general`, ctx);
      const pulses = data.pulse_info?.pulses || [];
      const validation = (data.validation || []).map(item => text(item?.source || item?.name)).filter(Boolean);
      // Whitelisted / false-positive indicators are reported but never counted against the IP.
      const benign = (data.false_positive || []).length > 0 || validation.some(name => /whitelist|alexa|majestic|akamai|false/i.test(name));
      return {
        pulses: num(data.pulse_info?.count) || 0, pulseNames: pulses.map(pulse => text(pulse?.name)).filter(Boolean).slice(0, 4), validation, benign,
        flags: flags({ tor: validation.some(name => /tor/i.test(name)) || null }), geoVote: false,
      };
    },
  },
  { id: 'greynoise', name: 'GreyNoise', group: 'threat', site: ip => `https://viz.greynoise.io/ip/${ip}`, optional: true, run: optionalWorker('greynoise', false) },
  { id: 'crowdsec', name: 'CrowdSec CTI', group: 'threat', site: ip => `https://app.crowdsec.net/cti/${ip}`, optional: true, run: optionalWorker('crowdsec', false) },
  { id: 'virustotal', name: 'VirusTotal', group: 'threat', site: ip => `https://www.virustotal.com/gui/ip-address/${ip}`, optional: true, run: optionalWorker('virustotal', false) },
  { id: 'scamalytics', name: 'Scamalytics', group: 'intel', site: ip => `https://scamalytics.com/ip/${ip}`, optional: true, run: optionalWorker('scamalytics', false) },
  { id: 'vpnapi', name: 'vpnapi.io', group: 'intel', site: ip => `https://vpnapi.io/`, optional: true, run: optionalWorker('vpnapi') },
  { id: 'iphub', name: 'IPHub', group: 'intel', site: () => 'https://iphub.info/', optional: true, run: optionalWorker('iphub', false) },
  { id: 'getipintel', name: 'GetIPIntel', group: 'intel', site: () => 'https://getipintel.net/', optional: true, run: optionalWorker('getipintel', false) },
  {
    id: 'shodan', name: 'Shodan InternetDB', group: 'threat', site: ip => `https://www.shodan.io/host/${ip}`,
    async run(ip, ctx) {
      const result = await getJSON(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { signal: ctx.signal, timeout: 12000 });
      if (result.status === 404) return { ports: [], tags: [], vulns: [], hostnames: [], flags: flags(), geoVote: false, unseen: true };
      if (!result.ok) fail(result.error);
      const data = result.data;
      const tags = Array.isArray(data.tags) ? data.tags.map(String) : [];
      return {
        ports: Array.isArray(data.ports) ? data.ports.filter(Number.isInteger) : [], tags,
        vulns: Array.isArray(data.vulns) ? data.vulns.map(String) : [], hostnames: Array.isArray(data.hostnames) ? data.hostnames.map(String).slice(0, 5) : [],
        flags: flags({
          proxy: tags.includes('proxy') || null, vpn: tags.includes('vpn') || null, tor: tags.includes('tor') || null,
          hosting: tags.includes('cloud') || null, abuser: tags.includes('compromised') || tags.includes('malware') || null,
        }),
        geoVote: false,
      };
    },
  },
  {
    id: 'sfs', name: 'StopForumSpam', group: 'threat', site: ip => `https://www.stopforumspam.com/ipcheck/${ip}`,
    async run(ip, ctx) {
      const { data } = await json(`https://api.stopforumspam.org/api?ip=${encodeURIComponent(ip)}&json`, ctx);
      if (data.success !== 1 || !data.ip) fail('查询失败');
      const record = data.ip;
      return {
        appears: num(record.appears) || 0, frequency: num(record.frequency) || 0, confidence: num(record.confidence), lastseen: text(record.lastseen),
        flags: flags({ tor: record.torexit ? true : null, abuser: num(record.appears) > 0 ? true : null }), geoVote: false,
      };
    },
  },
  {
    id: 'onionoo', name: 'Tor Project', group: 'threat', site: () => 'https://metrics.torproject.org/exonerator.html',
    async run(ip, ctx) {
      // IPv4: search the whole /24 ("a.b.c." prefix) so relays next door count as neighbours.
      const v4 = parseIP(ip).v === 4;
      const query = v4 ? `${ip.split('.').slice(0, 3).join('.')}.` : ip;
      const { data } = await json(`https://onionoo.torproject.org/details?search=${encodeURIComponent(query)}&fields=nickname,or_addresses,exit_addresses,flags,running`, ctx);
      const addresses = relay => [...(relay.or_addresses || []).map(address => address.replace(/^\[|\]?:\d+$/g, '').replace(/\]$/, '')), ...(relay.exit_addresses || [])];
      const relays = (data.relays || []).filter(relay => addresses(relay).some(address => sameIP(address, ip)));
      const neighbours = v4 ? (data.relays || []).filter(relay => !relays.includes(relay) && addresses(relay).some(address => address.startsWith(query))) : [];
      const exit = relays.some(relay => (relay.flags || []).includes('Exit') || (relay.exit_addresses || []).some(address => sameIP(address, ip)));
      return {
        relays: relays.map(relay => relay.nickname).slice(0, 3), torRelay: relays.length > 0, flags: flags({ tor: exit }), hard: { tor: exit }, geoVote: false,
        neighbourRelays: neighbours.length, neighbourExits: neighbours.filter(relay => (relay.flags || []).includes('Exit')).length,
      };
    },
  },
  {
    id: 'ptr', name: '反向解析 PTR', group: 'threat', site: ip => `https://dns.google/query?name=${reverseName(ip)}${parseIP(ip)?.v === 6 ? '.ip6' : '.in-addr'}.arpa&rr_type=PTR`,
    async run(ip, ctx) {
      const zone = parseIP(ip).v === 6 ? 'ip6.arpa' : 'in-addr.arpa';
      const { data } = await json(`https://dns.google/resolve?name=${reverseName(ip)}.${zone}&type=PTR`, ctx);
      const hostname = (data.Answer || []).find(answer => answer.type === 12)?.data?.replace(/\.$/, '') || null;
      return { hostname, ...classifyHostname(hostname), geoVote: false };
    },
  },
];

/** PTR naming conventions are a weak but useful type hint. */
export function classifyHostname(hostname) {
  const name = String(hostname || '').toLowerCase();
  const base = { flags: flags(), type: null };
  if (!name) return base;
  if (/(^|[.-])(vps|server|srv|host|hosting|cloud|dedi(cated)?|colo|static\.\d|compute|ec2|googleusercontent|linode|vultr|contabo|hetzner|ovh|leaseweb|your-server|kimsufi|clients\.your-server|ip-\d+-\d+-\d+\.(eu|net))([.-]|\d|$)/.test(name)) {
    return { flags: flags({ hosting: true }), type: 'hosting' };
  }
  if (/(^|[.-])(dyn|dynamic|dhcp|pool|ppp|pppoe|adsl|dsl|vdsl|cable|cpe|fttx|ftth|fiber|fibre|home|broadband|res|customer|client|user|subscriber|bb|flets|ocn|kddi|softbank|hinet|dynamicip)([.-]|\d|$)/.test(name)) {
    return { flags: flags(), type: 'residential' };
  }
  if (/(^|[.-])(mobile|wireless|lte|4g|5g|gprs|umts|cellular|mob)([.-]|\d|$)/.test(name)) return { flags: flags({ mobile: true }), type: 'mobile' };
  return base;
}

export async function runSource(source, ip, ctx) {
  const started = performance.now();
  try {
    const data = await source.run(ip, ctx);
    const ms = data?._ms ?? Math.round(performance.now() - started);
    if (data) delete data._ms;
    return { status: 'ok', data, ms };
  } catch (error) {
    return { status: error.skip ? 'skip' : 'error', error: error.soft || error.skip ? error.message : '请求失败', ms: Math.round(performance.now() - started) };
  }
}
