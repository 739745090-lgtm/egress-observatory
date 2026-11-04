/** Browser adapters. Private credentials live only in the backend runtime. */
const sourceCooldowns=new Map();
export const PROVIDERS = Object.freeze([
  {
    id:'ip2location',name:'IP2Location',database:'IP2Location',kind:'database',weight:25,
    sourceUrl:'https://www.ip2location.io/ip2location-documentation',fields:['country','city','asn','org','flags.proxy'],qualityFields:['proxy'],
    description:'本站服务端调用官方 Keyless API，取得实际地理、ASN 与 is_proxy 字段。',
    limit:'官方免密钥每天 1,000 次；UTC 日重置，本站缓存 600 秒。',cors:'own backend',upstreams:['IP2Location'],
    attribution:'IP Geolocation by IP2Location.io.',attributionUrl:'https://www.ip2location.io',
  },
  {
    id:'proxycheck',name:'Proxycheck',database:'Proxycheck',kind:'database',weight:20,
    sourceUrl:'https://proxycheck.io/api/',fields:['country','city','asn','org','networkType','flags.vpn','flags.proxy','flags.tor','flags.hosting'],qualityFields:['vpn','proxy','tor','hosting'],
    description:'经本站服务端查询本方授权的分类数据，私钥保存在运行时。请求可命中十分钟缓存。',
    limit:'本方免费套餐每天 1,000 次；服务端每调用者每分钟 10 次内存限速。',cors:'own backend',upstreams:['Proxycheck classification'],
    attribution:'Selected classifications by proxycheck.io, normalized for this combined assessment.',attributionUrl:'https://proxycheck.io/',
  },
  {
    id: 'ipinfo', name: 'IPinfo', database: 'IPinfo', kind: 'database', weight: 30,
    sourceUrl: 'https://support.ipinfo.io/hc/en-us/articles/30792479436562-What-Is-the-Difference-Between-Using-the-Authenticated-Free-Plan-and-the-Public-API-With-No-Account',
    fields: ['country', 'city', 'asn', 'org'], qualityFields: [],
    description: 'IPinfo 官方 legacy 公开接口；国家、城市与 ASN。免费响应未提供的隐私标签保持未知。',
    limit: '免 key；同一请求出口共享 1,000 次/日。', cors: '*', upstreams: ['IPinfo'],
    attribution: 'IPinfo 官方公开数据接口；数据 © IPinfo。', attributionUrl: 'https://ipinfo.io/',
  },
  {
    id: 'ipquery', name: 'IPQuery', database: 'IPQuery', kind: 'composite', weight: 20,
    sourceUrl: 'https://ipquery.io/developers/api',
    fields: ['country', 'city', 'asn', 'org', 'networkType', 'flags.vpn', 'flags.proxy', 'flags.tor', 'flags.hosting'],
    qualityFields: ['vpn', 'proxy', 'tor', 'hosting'],
    description: '公开单 IP 接口，返回 VPN、Proxy、Tor、Hosting 分类。Enterprise MMDB 的厂商品牌未明确，不映射成其他厂商的一票。',
    limit: '免 key、公开浏览器接口；批量查询已关闭；官方文档未承诺固定单 IP 请求额度。', cors: '*',
    upstreams: ['IPQuery Enterprise records', 'IPQuery classification', 'proxio.io', 'Proxmint'],
    attribution: 'IPQuery Enterprise records 与自有分类；代理列表注明 proxio.io、Proxmint，CC BY 4.0。',
    attributionUrl: 'https://ipquery.io/sources',
  },
  {
    id: 'ipapiis', name: 'ipapi.is', database: 'ipapi.is', kind: 'database', weight: 25,
    sourceUrl: 'https://ipapi.is/free-tier.html', fields: ['country', 'city', 'asn', 'org', 'flags.bogon'], qualityFields: ['bogon'],
    description: '匿名接口只提供归属、位置和 Bogon；完整 VPN、代理、滥用分类需要本方 API key。',
    limit: '匿名每出口 IP / IPv6 /64 每 UTC 日 30 次；出现 429 后停止，等待额度重置。', cors: '*',
    upstreams: ['ipapi.is geolocation', 'RIR WHOIS', 'BGP'],
    attribution: 'ipapi.is 自有地理库，结合 RIR WHOIS 与 BGP；匿名返回不含完整安全数据。',
    attributionUrl: 'https://ipapi.is/developers.html',
  },
  {
    id: 'ipwhois', name: 'ipwho.is', database: 'ipwho.is', kind: 'database', weight: 15,
    sourceUrl: 'https://ipwhois.io/documentation', fields: ['country', 'city', 'asn', 'org'], qualityFields: [],
    description: '地理与网络归属数据库；免费套餐不包含 Security Data。',
    limit: '免 key、允许商用；1,000 次/日，CORS 请求由整个来源域名共享额度。', cors: 'documented',
    upstreams: ['ipwhois proprietary database'],
    attribution: 'ipwho.is / ipwhois.io 地理及连接数据。', attributionUrl: 'https://ipwhois.io/documentation',
  },
  {
    id: 'dbip', name: 'DB-IP', database: 'DB-IP', kind: 'database', weight: 20,
    sourceUrl: 'https://db-ip.com/api/free', fields: ['country', 'city'], qualityFields: [],
    description: '本站服务端调用 DB-IP 官方免费地理 API，按实际目标取得国家与城市。',
    limit: '免费 500 次/日；本站缓存 600 秒，额度耗尽时保留缺失。', cors: 'own backend',
    upstreams: ['DB-IP'],
    attribution: 'IP Geolocation by DB-IP。', attributionUrl: 'https://db-ip.com/',
  },
  {
    id: 'freeipapi', name: 'FreeIPAPI', database: 'FreeIPAPI', kind: 'aggregate', weight: 10,
    sourceUrl: 'https://freeipapi.com/docs/api-reference/get-ip-info',
    fields: ['country', 'city', 'asn', 'org', 'flags.proxy'], qualityFields: ['proxy'],
    description: '包含 DB-IP 的聚合来源，只有 isProxy 为明确公开质量字段；作为相关旁证，避免与 DB-IP 重复投票。',
    limit: '免 key、允许商用；每访客 IP 10 次/10 秒、60 次/分钟。', cors: '*',
    upstreams: ['DB-IP', 'other undisclosed sources'],
    attribution: 'FreeIPAPI；公开来源包含 IP Geolocation by DB-IP（CC BY 4.0）。',
    attributionUrl: 'https://freeipapi.com/data-sources',
  },
  {
    id: 'ripe', name: 'RIPEstat', database: 'RIPE RIS', kind: 'routing', weight: 0,
    sourceUrl: 'https://stat.ripe.net/docs/data-api/api-endpoints/network-info',
    fields: ['asn', 'prefix'], qualityFields: [],
    description: 'BGP 宣告前缀与 ASN 路由观测；单独显示，风险评分权重为零。',
    limit: '同一 IP 最多 8 并发；经常超过 1,000 次/日需注册；底层约 8 小时快照。', cors: '*',
    upstreams: ['RIPE RIS'], attribution: 'RIPE NCC RIPEstat / Routing Information Service。',
    attributionUrl: 'https://stat.ripe.net/docs/data-api/ripestat-data-api',
  },
].map((provider) => Object.freeze(provider)));

const REGION_CODES = 'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split(' ');
const REGION_SET = new Set(REGION_CODES);
let countryNames;
const cleanText = (value) => typeof value === 'string' && value.trim() ? value.trim().slice(0, 300) : null;
const bool = (value) => typeof value === 'boolean' ? value : null;
const blankFlags = () => ({ vpn: null, proxy: null, tor: null, relay: null, hosting: null, abuser: null, bogon: null });

function canonicalIP(value) {
  if (typeof value !== 'string') return null;
  const address = value.trim();
  if (/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(address)) {
    const parts = address.split('.').map(Number);
    return parts.every((part) => part <= 255) ? parts.join('.') : null;
  }
  if (!address.includes(':') || !/^[a-fA-F0-9:.]+$/.test(address)) return null;
  try {
    return new URL(`http://[${address}]/`).hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch { return null; }
}

function regionKey(value) {
  return String(value).normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function countryCode(value) {
  const text = cleanText(value);
  if (!text) return null;
  if (REGION_SET.has(text.toUpperCase())) return text.toUpperCase();
  if (!countryNames) {
    countryNames = new Map();
    if (typeof Intl.DisplayNames === 'function') {
      const english = new Intl.DisplayNames(['en'], { type: 'region' });
      for (const code of REGION_CODES) countryNames.set(regionKey(english.of(code)), code);
    }
    for (const [name, code] of Object.entries({
      'United States of America': 'US', 'United States': 'US', 'United Kingdom': 'GB',
      'Russian Federation': 'RU', 'Republic of Korea': 'KR', 'South Korea': 'KR',
      'Democratic Peoples Republic of Korea': 'KP', 'North Korea': 'KP', 'Czech Republic': 'CZ',
      'Viet Nam': 'VN', 'Iran Islamic Republic of': 'IR', 'Taiwan Province of China': 'TW',
      'Hong Kong': 'HK', 'Macao': 'MO', 'Macau': 'MO', 'Palestine': 'PS', 'Turkey': 'TR',
      'Republic of Moldova': 'MD', 'Bolivia Plurinational State of': 'BO',
      'Venezuela Bolivarian Republic of': 'VE', 'United Republic of Tanzania': 'TZ',
      'Japan': 'JP', 'China': 'CN', 'Australia': 'AU', 'France': 'FR', 'Germany': 'DE',
    })) countryNames.set(regionKey(name), code);
  }
  return countryNames.get(regionKey(text)) || null;
}

function asn(value) {
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0) return `AS${value}`;
  if (typeof value !== 'string') return null;
  const match = value.trim().match(/^(?:AS)?(\d+)(?:\s|$)/i);
  return match ? `AS${match[1]}` : null;
}

function ipNumber(ip) {
  if (!ip.includes(':')) return { value: ip.split('.').reduce((value, part) => (value << 8n) + BigInt(part), 0n), bits: 32 };
  const halves = ip.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const words = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  if (words.length !== 8) return null;
  return { value: words.reduce((value, word) => (value << 16n) + BigInt(`0x${word}`), 0n), bits: 128 };
}

function prefixContains(prefix, ip) {
  if (typeof prefix !== 'string') return false;
  const [network, length, extra] = prefix.split('/');
  const normalizedNetwork = canonicalIP(network);
  if (!normalizedNetwork || extra !== undefined || !/^\d+$/.test(length || '')) return false;
  const addressValue = ipNumber(ip);
  const networkValue = ipNumber(normalizedNetwork);
  const size = Number(length);
  if (!addressValue || !networkValue || addressValue.bits !== networkValue.bits || size > addressValue.bits) return false;
  const shift = BigInt(addressValue.bits - size);
  return (addressValue.value >> shift) === (networkValue.value >> shift);
}

function requestURL(id, ip) {
  const target = encodeURIComponent(ip);
  switch (id) {
    case 'proxycheck': return `https://egress-observatory-api.reaper-f.chatgpt.site/v1/proxycheck?ip=${target}`;
    case 'ip2location': return `https://egress-observatory-api.reaper-f.chatgpt.site/v1/ip2location?ip=${target}`;
    case 'ipinfo': return `https://ipinfo.io/${target}/json`;
    case 'ipquery': return `https://api.ipquery.io/${target}?format=json`;
    case 'ipapiis': return `https://api.ipapi.is/?q=${target}`;
    case 'ipwhois': return `https://ipwho.is/${target}`;
    case 'dbip': return `https://egress-observatory-api.reaper-f.chatgpt.site/v1/dbip?ip=${target}`;
    case 'freeipapi': return `https://free.freeipapi.com/api/v1/json/${target}`;
    case 'ripe': return `https://stat.ripe.net/data/network-info/data.json?resource=${target}&sourceapp=egress-observatory`;
    default: return null;
  }
}

class ProviderError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

function assertProviderResponse(id, data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new ProviderError('invalid-response', '接口未返回有效的数据对象。');
  if (id === 'dbip' && data.errorCode === 'RESTRICTED') throw new ProviderError('visitor-only', 'DB-IP 当前浏览器接口仅允许查询请求者 IP；此目标受限。');
  if (data.error || data.errorCode || data.error_code || data.success === false || (id === 'ripe' && data.status !== 'ok')) {
    const code = cleanText(data.errorCode || data.error_code) || 'provider-error';
    throw new ProviderError(code, id === 'ipwhois' && /limit|quota/i.test(String(data.message || '')) ? 'ipwho.is 共享额度已用尽，请等待重置。' : '数据提供方拒绝了本次请求，未将错误结果纳入评分。');
  }
}

function normalize(id, data, targetIP) {
  const record = { country: null, city: null, asn: null, org: null, networkType: null, flags: blankFlags(), fieldSources: { flags: {} }, raw: {} };
  let responseIP;
  if (['proxycheck','dbip','ip2location'].includes(id)) {
    if(data.providerId!==id||data.status!=='success')throw new ProviderError('invalid-response','服务端未返回可用的数据库查询结果。');
    responseIP=data.ip;
    record.country=countryCode(data.country);record.city=cleanText(data.city);record.asn=asn(data.asn);record.org=cleanText(data.org);
    record.networkType=['residential','isp','mobile','business','hosting'].includes(data.networkType)?data.networkType:null;
    for(const key of Object.keys(record.flags))record.flags[key]=bool(data.flags?.[key]);
    record.cacheHit=data.cacheHit===true;
    record.dataObservedAt=cleanText(data.observedAt);
  } else if (id === 'ipinfo') {
    responseIP = data.ip;
    record.country = countryCode(data.country);
    record.city = cleanText(data.city);
    record.asn = asn(data.org);
    record.org = cleanText(data.org)?.replace(/^AS\d+\s+/i, '') || null;
    record.flags.bogon = bool(data.bogon);
    record.raw = { country: cleanText(data.country), city: record.city, org: cleanText(data.org), bogon: bool(data.bogon) };
  } else if (id === 'ipquery') {
    responseIP = data.ip;
    record.country = countryCode(data.location?.country_code);
    record.city = cleanText(data.location?.city);
    record.asn = asn(data.isp?.asn);
    record.org = cleanText(data.isp?.org) || cleanText(data.isp?.isp);
    record.flags.vpn = bool(data.risk?.is_vpn);
    record.flags.proxy = bool(data.risk?.is_proxy);
    record.flags.tor = bool(data.risk?.is_tor);
    record.flags.hosting = bool(data.risk?.is_datacenter);
    record.networkType = record.flags.hosting === true ? 'hosting' : data.risk?.is_mobile === true ? 'mobile' : null;
    record.fieldSources.country = 'ipquery-enterprise';
    record.fieldSources.networkType = 'ipquery-classification';
    record.raw = { country_code: record.country, is_mobile: bool(data.risk?.is_mobile), ...record.flags, risk_score: typeof data.risk?.risk_score === 'number' && Number.isFinite(data.risk.risk_score) ? data.risk.risk_score : null };
  } else if (id === 'ipapiis') {
    responseIP = data.ip;
    record.country = countryCode(data.country);
    record.city = cleanText(data.city);
    record.asn = asn(data.asn);
    record.org = cleanText(data.company);
    record.flags.bogon = bool(data.is_bogon);
    record.raw = { country: cleanText(data.country), company: record.org, asn: cleanText(data.asn), is_bogon: record.flags.bogon };
  } else if (id === 'ipwhois') {
    responseIP = data.ip;
    record.country = countryCode(data.country_code);
    record.city = cleanText(data.city);
    record.asn = asn(data.connection?.asn);
    record.org = cleanText(data.connection?.org) || cleanText(data.connection?.isp);
    record.raw = { country_code: record.country, city: record.city, asn: record.asn, org: record.org };
  } else if (id === 'dbip') {
    responseIP = data.ipAddress;
    record.country = countryCode(data.countryCode);
    record.city = cleanText(data.city);
    record.raw = { countryCode: record.country, city: record.city, stateProv: cleanText(data.stateProv) };
  } else if (id === 'freeipapi') {
    responseIP = data.ipAddress;
    record.country = countryCode(data.countryCode);
    record.city = cleanText(data.cityName);
    record.asn = asn(data.asn);
    record.org = cleanText(data.asnOrganization);
    record.flags.proxy = bool(data.isProxy);
    record.raw = { countryCode: record.country, cityName: record.city, asn: record.asn, asnOrganization: record.org, isProxy: record.flags.proxy };
  } else if (id === 'ripe') {
    if (!prefixContains(data.data?.prefix, targetIP)) throw new ProviderError('target-mismatch', 'RIPE 返回前缀未包含目标 IP，该结果已弃用。');
    responseIP = targetIP;
    record.asns = Array.isArray(data.data?.asns) ? data.data.asns.map(asn).filter(Boolean) : [];
    record.asn = record.asns.length === 1 ? record.asns[0] : null;
    record.prefix = cleanText(data.data?.prefix);
    record.raw = { prefix: record.prefix, asns: record.asns };
    record.targetMatch = 'prefix-containment';
  }
  if (canonicalIP(responseIP) !== targetIP) throw new ProviderError('target-mismatch', '接口返回的目标与本次查询不一致，已弃用这条结果。');
  record.ip = targetIP;
  record.targetMatch ||= 'exact-ip';
  for (const field of ['country', 'city', 'asn', 'org', 'networkType']) {
    if (record[field] !== null) record.fieldSources[field] ||= id === 'ipquery' ? (field === 'networkType' ? 'ipquery-classification' : 'ipquery-enterprise') : id;
  }
  for (const [flag, value] of Object.entries(record.flags)) {
    if (value !== null) record.fieldSources.flags[flag] = id === 'ipquery' ? 'ipquery-classification' : id;
  }
  return record;
}

/** Query exactly one target through a documented public HTTPS endpoint. */
export async function queryProvider(id, ip, { signal } = {}) {
  const provider = PROVIDERS.find((item) => item.id === id);
  const targetIP = canonicalIP(ip);
  const start = performance.now();
  const base = {
    providerId: id, providerName: provider?.name || id, database: provider?.database || null,
    kind: provider?.kind || null, weight: provider?.weight ?? 0, ip: targetIP,
    observedAt: new Date().toISOString(), duration: 0,
    country: null, city: null, asn: null, org: null, networkType: null, flags: blankFlags(),
    status: 'error', error: null, errorCode: null, attribution: provider?.attribution || null,
    attributionUrl: provider?.attributionUrl || null, sourceUrl: provider?.sourceUrl || null,
    upstreams: provider?.upstreams || [], fieldSources: { flags: {} },
  };
  if (!provider || !targetIP) return { ...base, errorCode: !provider ? 'unknown-provider' : 'invalid-ip', error: !provider ? '未知数据提供方。' : '请提供完整 IPv4 或 IPv6 地址。' };
  if((sourceCooldowns.get(id)||0)>Date.now())return {...base,errorCode:'rate-limit-cooldown',error:'来源仍在上次限流的等待期，本轮未重复请求。'};
  if (signal?.aborted) return { ...base, status: 'cancelled', errorCode: 'cancelled', error: '查询已取消。' };
  const controller = new AbortController();
  let timedOut = false;
  const cancel = () => controller.abort();
  signal?.addEventListener('abort', cancel, { once: true });
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, 12000);
  try {
    const response = await fetch(requestURL(id, targetIP), {
      method: 'GET', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal: controller.signal,
    });
    if (!response.ok) {
      const retryAfter = response.headers.get('Retry-After');
      const numericRetry = retryAfter && /^\d+$/.test(retryAfter) ? Number(retryAfter) : null;
      if (response.status === 429) {
        sourceCooldowns.set(id,Date.now()+Math.max(60,numericRetry||60)*1000);
        const failure = new ProviderError('rate-limit', '接口额度或速率受限，已停止本来源请求，请等待提供方重置。');
        failure.retryAfterSeconds = numericRetry;
        throw failure;
      }
      throw new ProviderError(`http-${response.status}`, `接口返回 HTTP ${response.status}，本次数据未取得。`);
    }
    let data;
    try { data = await response.json(); }
    catch (error) {
      if (controller.signal.aborted) throw error;
      throw new ProviderError('invalid-json', '接口响应无法解析为 JSON。');
    }
    if (signal?.aborted) throw new ProviderError('cancelled', '查询已取消。');
    assertProviderResponse(id, data);
    const normalized = normalize(id, data, targetIP);
    return { ...base, ...normalized, status: 'success', observedAt: normalized.dataObservedAt || new Date().toISOString(), fetchedAt:new Date().toISOString(), duration: Math.round(performance.now() - start) };
  } catch (error) {
    const cancelled = signal?.aborted || error.code === 'cancelled';
    return {
      ...base, status: cancelled ? 'cancelled' : 'error', duration: Math.round(performance.now() - start),
      errorCode: cancelled ? 'cancelled' : timedOut ? 'timeout' : error.code || 'network-or-cors',
      error: cancelled ? '查询已取消。' : timedOut ? '接口 12 秒内未完成响应。' : error instanceof ProviderError ? error.message : '网络请求未完成或浏览器跨域读取受限；未取得可评分数据。',
      retryAfterSeconds: typeof error.retryAfterSeconds === 'number' ? error.retryAfterSeconds : null,
    };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', cancel);
  }
}
