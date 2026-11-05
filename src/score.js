/**
 * Egress IP quality score. Pure function: evidence in, explained score out.
 *
 * Score = 100 − Σ min(category cap, Σ item points), Tor exits capped at 25.
 * Safety comes first: anonymity, abuse, and the reputation of the /24 neighbours and the ASN carry most
 * of the weight; network type, ASN-type consistency and native/broadcast are small descriptive hints.
 * Live connection checks apply only when the target is the visitor's own egress.
 * Every deduction carries its evidence so the UI can show exactly why points were taken.
 */

const CATEGORIES = Object.freeze([
  { id: 'anon', label: '匿名化', cap: 45 },
  { id: 'abuse', label: '滥用与黑名单', cap: 40 },
  { id: 'neighbours', label: '邻居与 ASN 信誉', cap: 25 },
  { id: 'network', label: '网络类型与 ASN 画像', cap: 20 },
  { id: 'geo', label: '原生与定位', cap: 8 },
  { id: 'live', label: '连接实测', cap: 50 },
]);

/** Per-source reliability for each kind of signal (0–1). */
export const SOURCE_WEIGHTS = Object.freeze({
  // IPinfo leads: highest weight for location and, when its privacy data is available, flags and type.
  ipinfo: { flags: 1.3, type: 1.3, geo: 1.6 },
  proxycheck: { flags: 1.0, type: 1.0, risk: 1.0 },
  ipapiis: { flags: 0.9, type: 0.9, risk: 0.8 },
  ipapi: { flags: 0.8, type: 0.8 },
  ipquery: { flags: 0.8, risk: 0.5 },
  ip2location: { flags: 0.6 },
  blackbox: { flags: 0.5, type: 0.5 },
  freeipapi: { flags: 0.4 },
  shodan: { flags: 0.5, positiveOnly: true, observed: true },
  sfs: { flags: 0.8, positiveOnly: true, observed: true },
  iplocate: { flags: 0.9, type: 0.8 },
  geoiplookup: { type: 0.7 },
  ipapimirror: { flags: 0.5, type: 0.5, geo: 0.6 },
  netatlas: { geo: 0.6 },
  otx: { flags: 0.6, positiveOnly: true, observed: true },
  greynoise: { flags: 0.8, observed: true },
  crowdsec: { flags: 0.9, risk: 1.0, observed: true },
  vpnapi: { flags: 0.8 },
  iphub: { flags: 0.7, type: 0.7 },
  getipintel: { flags: 0.5, risk: 0.5 },
  scamalytics: { flags: 0.8, risk: 1.1 },
  virustotal: { flags: 0.8, risk: 0.8, observed: true },
  onionoo: { flags: 1.0 },
  abuseipdb: { flags: 1.0, type: 0.9, risk: 1.2 },
  ipqs: { flags: 1.0, type: 0.9, risk: 1.3 },
  ipregistry: { flags: 0.9, type: 0.9 },
  ipdata: { flags: 0.8, type: 0.8, risk: 0.8 },
  ptr: { flags: 0.5, type: 0.5 },
});

/** Geo databases that share an upstream count once in the location vote. */
export const GEO_FAMILY = Object.freeze({
  abuseipdb: 'ipinfo',
  ipsb: 'maxmind', ipleak: 'maxmind', maxmind: 'maxmind', geojs: 'maxmind',
  dbip: 'dbip', freeipapi: 'dbip', netatlas: 'dbip', ipapi: 'ipapi', ipapimirror: 'ipapi',
});

const TYPE_LABEL = { residential: '家宽', mobile: '移动网络', business: '商业宽带', hosting: '机房', education: '教育网' };
export const AI_BLOCKED = new Set(['CN', 'HK', 'MO', 'RU', 'BY', 'IR', 'KP', 'SY', 'CU']);
const NOW = () => Date.now();
/** Score of a clean IP without positive evidence; bonuses (up to BONUS_CAP) lift it towards 100. */
export const BASE = 92;
export const BONUS_CAP = 8;

import { zoneOffset } from './util.js';

/** Main languages per country, used only for the browser-language consistency hint. */
const COUNTRY_LANGS = {
  CN: ['zh'], TW: ['zh'], HK: ['zh', 'en'], MO: ['zh', 'pt'], SG: ['en', 'zh', 'ms', 'ta'], JP: ['ja'], KR: ['ko'],
  US: ['en', 'es'], GB: ['en'], CA: ['en', 'fr'], AU: ['en'], NZ: ['en'], IE: ['en', 'ga'], IN: ['en', 'hi'],
  DE: ['de'], AT: ['de'], CH: ['de', 'fr', 'it'], FR: ['fr'], BE: ['nl', 'fr', 'de'], NL: ['nl'], LU: ['fr', 'de', 'lb'],
  ES: ['es', 'ca'], PT: ['pt'], IT: ['it'], PL: ['pl'], CZ: ['cs'], SE: ['sv'], NO: ['no', 'nb', 'nn'], DK: ['da'], FI: ['fi', 'sv'],
  RU: ['ru'], UA: ['uk', 'ru'], TR: ['tr'], GR: ['el'], RO: ['ro'], HU: ['hu'], BG: ['bg'], IL: ['he'], AE: ['ar', 'en'], SA: ['ar'],
  BR: ['pt'], MX: ['es'], AR: ['es'], CL: ['es'], CO: ['es'], TH: ['th'], VN: ['vi'], ID: ['id'], MY: ['ms', 'en', 'zh'], PH: ['en', 'tl', 'fil'],
};

const r1 = value => Math.round(value * 10) / 10;
const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

// ---------- evidence helpers ----------

/**
 * Two evidence classes.
 * - Classified: a database labels the IP. Weighted vote E_db = P / (P + 0.5 N); a detection counts more than a miss.
 * - Observed: someone saw the behaviour directly (open proxy port, public proxy / Tor list, drone list).
 *   Observations combine as noisy-OR, E_obs = 1 − Π(1 − w), and are not diluted by databases that never classified the IP.
 * E = 1 − (1 − E_obs)(1 − E_db); a hard confirmation (Tor consensus, WARP) is E = 1.
 */
function tally(votes) {
  const known = votes.filter(vote => typeof vote.value === 'boolean');
  const positive = known.filter(vote => vote.value);
  const hard = positive.some(vote => vote.hard);
  const classified = positive.filter(vote => !vote.obs);
  const observed = positive.filter(vote => vote.obs);
  const P = classified.reduce((sum, vote) => sum + vote.w, 0);
  const N = known.filter(vote => !vote.value).reduce((sum, vote) => sum + vote.w, 0);
  const Edb = P === 0 ? 0 : P / (P + 0.5 * N);
  const Eobs = 1 - observed.reduce((acc, vote) => acc * (1 - Math.min(0.95, vote.w)), 1);
  const E = hard ? 1 : 1 - (1 - Eobs) * (1 - Edb);
  return {
    E: r1(E * 100) / 100, Edb: r1(Edb * 100) / 100, Eobs: r1(Eobs * 100) / 100, yes: positive.length, of: known.length, hard,
    by: positive.map(vote => vote.by), observedBy: observed.map(vote => vote.by), clear: known.filter(vote => !vote.value).map(vote => vote.by),
  };
}

function okSources(evidence) {
  return Object.entries(evidence.sources || {})
    .filter(([, source]) => source && source.status === 'ok' && source.data)
    .map(([id, source]) => ({ id, name: source.name || id, ...source.data }));
}

function flagVotes(sources, flag) {
  const votes = [];
  for (const source of sources) {
    const value = source.flags?.[flag];
    if (typeof value !== 'boolean') continue;
    const weights = SOURCE_WEIGHTS[source.id] || { flags: 0.5 };
    if (weights.positiveOnly && value === false) continue;
    // Scanners and community lists report what they saw; their positives are observations.
    votes.push({ by: source.name, value, w: weights.flags ?? 0.5, hard: Boolean(source.hard?.[flag]) && value, obs: Boolean(weights.observed) && value });
  }
  return votes;
}

function weightedRank(entries) {
  const totals = new Map();
  for (const entry of entries) {
    const item = totals.get(entry.value) || { value: entry.value, w: 0, by: [] };
    item.w += entry.w; item.by.push(entry.by); totals.set(entry.value, item);
  }
  const sum = [...totals.values()].reduce((acc, item) => acc + item.w, 0);
  return [...totals.values()].map(item => ({ ...item, share: sum ? item.w / sum : 0 }))
    .sort((a, b) => b.w - a.w || String(a.value).localeCompare(String(b.value)));
}

// ---------- main ----------

export function score(evidence) {
  const sources = okSources(evidence);
  const items = Object.fromEntries(CATEGORIES.map(category => [category.id, []]));
  const notes = [];
  const add = (category, id, label, pts, detail) => {
    if (pts > 0.05) items[category].push({ id, label, pts: r1(pts), detail });
  };
  const note = (level, textValue) => notes.push({ level, text: textValue });

  // ---------- location consensus (families deduplicated) ----------
  const geoWeight = source => (SOURCE_WEIGHTS[source.id] || {}).geo ?? 1;
  const familySeen = new Map();
  for (const source of sources) {
    if (!source.country || source.geoVote === false) continue;
    const family = GEO_FAMILY[source.id] || source.id;
    const entry = { value: source.country, w: geoWeight(source), by: source.name, city: source.city, lat: source.lat, lon: source.lon, tz: source.tz };
    if (!familySeen.has(family) || entry.w > familySeen.get(family).w) familySeen.set(family, entry);
  }
  const countries = weightedRank([...familySeen.values()]);
  const country = countries[0]?.value || null;
  const countrySupport = countries[0]?.share ?? null;
  const geoCount = sources.filter(source => source.country && source.geoVote !== false).length;
  const locationFieldRank = field => {
    const families = new Map();
    for (const source of sources) {
      if (source.geoVote === false || !source[field] || source.country !== country) continue;
      const family = GEO_FAMILY[source.id] || source.id;
      const entry = { value: source[field], w: geoWeight(source), by: source.name };
      if (!families.has(family) || entry.w > families.get(family).w) families.set(family, entry);
    }
    return weightedRank([...families.values()]);
  };
  const cityRank = locationFieldRank('city');
  const city = cityRank[0]?.value || null;
  const tzRank = locationFieldRank('tz');
  const ipTimezone = tzRank[0]?.value || null;
  const asnRank = weightedRank(sources.filter(source => source.asn).map(source => ({ value: source.asn, w: geoWeight(source), by: source.name })));
  const asn = evidence.asn?.asn || asnRank[0]?.value || null;
  const orgRank = weightedRank(sources.filter(source => source.org).map(source => ({ value: source.org, w: geoWeight(source), by: source.name })));
  const hostname = sources.find(source => source.hostname)?.hostname || null;

  if (countries.length > 1 && countrySupport < 0.85) {
    const pts = clamp(6 * (0.85 - countrySupport) / 0.35, 0, 5);
    add('geo', 'geo-split', '定位分歧', pts, `${countries.map(item => `${item.value} ×${item.by.length}`).join(' · ')}`);
  }

  // ---------- registration country (native vs broadcast) ----------
  const regVotes = [];
  for (const source of sources) {
    if (!source.regCountry) continue;
    const w = source.id === 'ipleak' ? 1.0 : source.id === 'riperir' ? 0.8 : source.id === 'rdap' ? 0.6 : 0.5;
    regVotes.push({ value: source.regCountry, w, by: source.name });
  }
  const regRank = weightedRank(regVotes);
  const regCountry = regRank[0]?.value || null;
  let native = null; let nativeShare = null; let nativeCertainty = 0;
  if (regCountry && country) {
    const total = regRank.reduce((sum, item) => sum + item.w, 0);
    nativeShare = r1((regRank.find(item => item.value === country)?.w || 0) / total * 100) / 100;
    nativeCertainty = Math.max(nativeShare, 1 - nativeShare) * Math.min(1, regVotes.length / 2);
  }
  if (regCountry && country) {
    native = regCountry === country;
    if (!native) add('geo', 'broadcast', '广播 IP', 3, `注册地 ${regCountry}，定位 ${country}`);
    if (regRank.length > 1) note('info', `注册信息不一致：${regRank.map(item => `${item.value}（${item.by.join('、')}）`).join(' / ')}`);
  }

  // ---------- anonymity ----------
  const extraVotes = evidence.extraVotes || {};
  const anonFlags = {};
  for (const flag of ['vpn', 'proxy', 'tor', 'relay', 'crawler']) {
    anonFlags[flag] = tally([...flagVotes(sources, flag), ...(extraVotes[flag] || [])]);
  }
  const tor = anonFlags.tor;
  if (tor.E > 0) add('anon', 'tor', 'Tor', 40 * tor.E, `${tor.yes}/${tor.of} 来源命中：${tor.by.join('、')}`);
  if (anonFlags.vpn.E > 0) add('anon', 'vpn', 'VPN', 18 * anonFlags.vpn.E, `${anonFlags.vpn.yes}/${anonFlags.vpn.of}：${anonFlags.vpn.by.join('、')}`);
  const resProxyBy = sources.filter(source => source.resProxy === true).map(source => source.name);
  if (anonFlags.proxy.E > 0) add('anon', 'proxy', resProxyBy.length ? '代理（含住宅代理）' : '代理', 20 * anonFlags.proxy.E, `${anonFlags.proxy.yes}/${anonFlags.proxy.of}：${anonFlags.proxy.by.join('、')}`);
  if (anonFlags.relay.E > 0) add('anon', 'relay', '隐私中继', 5 * anonFlags.relay.E, anonFlags.relay.by.join('、'));
  if (anonFlags.crawler.E > 0) add('anon', 'crawler', '爬虫 / 自动化', 8 * anonFlags.crawler.E, anonFlags.crawler.by.join('、'));
  const devices = sources.find(source => source.id === 'proxycheck')?.devices;
  if (devices?.address >= 10) {
    add('anon', 'shared', '多设备共用出口', devices.address >= 50 ? 5 : 3, `Proxycheck 估计该地址近期约 ${devices.address} 台设备`);
  }

  // ---------- network type ----------
  const hostingVotes = flagVotes(sources, 'hosting').concat(extraVotes.hosting || []);
  const typeVotes = [];
  for (const source of sources) {
    if (!source.type) continue;
    if (source.id === 'abuseipdb' && sources.some(item => item.id === 'ipinfo' && item.type)) continue;
    const w = (SOURCE_WEIGHTS[source.id] || {}).type ?? 0.5;
    typeVotes.push({ value: source.type, w, by: source.name });
    const hasHostingFlag = typeof source.flags?.hosting === 'boolean';
    if (source.type === 'hosting' && !hasHostingFlag) hostingVotes.push({ by: source.name, value: true, w });
    if (source.type !== 'hosting' && !hasHostingFlag) hostingVotes.push({ by: source.name, value: false, w: w * 0.6 });
  }
  const hosting = tally(hostingVotes);
  const nonHostingRank = weightedRank(typeVotes.filter(vote => vote.value !== 'hosting')
    .map(vote => ({ ...vote, value: vote.value === 'isp' ? 'residential' : vote.value === 'government' ? 'business' : vote.value })));
  const asnInfo = evidence.asn || {};
  const asnCls = asnInfo.inferred?.cls || null;
  const asnHosting = asnInfo.inferred?.hosting ?? null;
  let ipType = null; let typeFrom = null;
  if (hosting.E >= 0.5) { ipType = 'hosting'; typeFrom = 'sources'; }
  else if (nonHostingRank.length) { ipType = nonHostingRank[0].value; typeFrom = 'sources'; }
  else if (hosting.of > 0) { ipType = 'residential'; typeFrom = 'exclusion'; }
  else if (asnCls === 'isp') { ipType = 'residential'; typeFrom = 'asn'; }
  else if (asnCls === 'mobile') { ipType = 'mobile'; typeFrom = 'asn'; }
  else if (asnCls === 'hosting' || asnCls === 'cdn') { ipType = 'hosting'; typeFrom = 'asn'; }
  else if (asnCls === 'business' || asnCls === 'education') { ipType = asnCls; typeFrom = 'asn'; }

  // Mixture and certainty behind the type label, for gradient "家宽 / 机房 ?" tags.
  const TYPE_FROM_ASN = { isp: 'residential', mobile: 'mobile', hosting: 'hosting', cdn: 'hosting', transit: 'business', business: 'business', government: 'business', education: 'education' };
  let typeMix = []; let typeCertainty = 0;
  if (typeFrom === 'sources' || typeFrom === 'exclusion') {
    const hostShare = hosting.of ? hosting.E : ipType === 'hosting' ? 1 : 0;
    const others = nonHostingRank.length ? nonHostingRank : [{ value: 'residential', share: 1 }];
    typeMix = [{ value: 'hosting', share: hostShare }, ...others.map(item => ({ value: item.value, share: (1 - hostShare) * item.share }))];
    const evidenceCount = hosting.of + typeVotes.length;
    typeCertainty = typeFrom === 'exclusion' ? 0.35 : Math.max(...typeMix.map(item => item.share)) * Math.min(1, evidenceCount / 4);
  } else if (typeFrom === 'asn') {
    const merged = new Map();
    for (const item of asnInfo.inferred?.mix || []) {
      const value = TYPE_FROM_ASN[item.value];
      if (value) merged.set(value, (merged.get(value) || 0) + item.share);
    }
    typeMix = [...merged].map(([value, share]) => ({ value, share }));
    typeCertainty = (asnInfo.inferred?.confidence ?? 0) * 0.6;
  }
  typeMix = typeMix.filter(item => item.share > 0.005).sort((a, b) => b.share - a.share).map(item => ({ ...item, share: r1(item.share * 100) / 100 }));

  if (hosting.E > 0) add('network', 'hosting', '机房 IP', 15 * hosting.E, `${hosting.yes}/${hosting.of} 来源标记机房：${hosting.by.join('、')}`);
  else if (ipType === 'hosting' && typeFrom === 'asn') add('network', 'hosting-asn', '机房 IP（按 ASN 推断）', 10 * (asnHosting ?? 0.7), asnInfo.inferred?.reasons?.[0] || '');
  if (ipType === 'business' && hosting.E < 0.5) add('network', 'business', '商业 / 企业网络', 2, nonHostingRank[0]?.by.join('、') || 'ASN 推断');

  // The key cross-check: a "residential" label inside a datacenter or transit ASN.
  let asnConsistency = null;
  if (asnCls && ipType) {
    const homeLike = ipType === 'residential' || ipType === 'mobile';
    if (homeLike && (asnCls === 'hosting' || asnCls === 'cdn') && (asnHosting ?? 0) >= 0.5) {
      asnConsistency = { ok: false, text: `标为${TYPE_LABEL[ipType]}，但 ${asnInfo.label || 'ASN'} 以机房为主` };
      add('network', 'asn-conflict', '类型与 ASN 不符', 5 * asnHosting, asnConsistency.text);
    } else if (homeLike && asnCls === 'transit') {
      asnConsistency = { ok: true, warn: true, text: `标为${TYPE_LABEL[ipType]}，宣告方却是骨干 / 传输网：骨干网本身可靠，但家宽很少直接挂在它下面，这个标签存疑` };
      add('network', 'asn-transit', '骨干网下的家宽标签存疑', 2, asnConsistency.text);
    } else if (ipType === 'hosting' && (asnCls === 'isp' || asnCls === 'mobile')) {
      asnConsistency = { ok: true, warn: true, text: '运营商 ASN 中的机房段（IDC / 云业务）' };
    } else if (homeLike && (asnCls === 'isp' || asnCls === 'mobile')) {
      asnConsistency = { ok: true, text: '类型与 ASN 一致：运营商网络' };
    } else if (ipType === 'hosting' && (asnCls === 'hosting' || asnCls === 'cdn')) {
      asnConsistency = { ok: true, text: '类型与 ASN 一致：机房网络' };
    } else if (ipType === 'business' && asnCls === 'transit') {
      asnConsistency = { ok: true, warn: true, text: '骨干网直接宣告的商业段，常见于 IP 租赁与代理' };
    } else {
      asnConsistency = { ok: true, text: `ASN 类型：${asnInfo.inferred?.label || asnCls}` };
    }
  }

  // Leased / sub-allocated address space (IP brokers, recent re-registration).
  const rdap = sources.find(source => source.id === 'rdap');
  const lease = asnInfo.lease || null;
  if (lease?.leased || lease?.possible) {
    add('network', 'leased', lease.leased ? '租赁 / 转售地址段' : '可能是租赁地址段', 3 * clamp(lease.confidence / 0.7, 0, 1), lease.reasons.join('；'));
  }
  if (asnInfo.regDate && NOW() - Date.parse(asnInfo.regDate) < 2 * 365 * 864e5) {
    add('network', 'asn-young', '新注册 ASN', 2, `ASN 注册于 ${asnInfo.regDate.slice(0, 10)}`);
  }

  // ---------- neighbours & ASN reputation: what the surrounding addresses have been doing ----------
  const nb = evidence.neighbours || null;
  if (nb) {
    if (nb.whole.length) add('neighbours', 'block-listed', '整个网段被列入威胁列表', 15, `${nb.prefix} 整段在 ${nb.whole.join('、')}`);
    if (nb.count) {
      const pts = nb.count >= 30 ? 14 : nb.count >= 10 ? 10 : nb.count >= 3 ? 6 : 3;
      add('neighbours', 'neighbours', '同网段邻居上榜', pts, `${nb.prefix} 内另有 ${nb.count} 个地址近期上榜${nb.lists.length ? `（${nb.lists.join('、')}）` : ''}${nb.abuseipdb?.reported ? `；AbuseIPDB 30 天内 ${nb.abuseipdb.reported} 个被举报` : ''}`);
    }
    if (nb.tor) add('neighbours', 'neighbour-tor', '同网段有 Tor 节点', 3, `${nb.prefix} 内有 ${nb.tor} 个 Tor 中继`);
  }
  const rep = evidence.asnRep || null;
  if (rep && rep.ratio >= 2) {
    const pts = rep.ratio >= 50 ? 12 : rep.ratio >= 15 ? 9 : rep.ratio >= 5 ? 6 : 3;
    add('neighbours', 'asn-abuse', 'ASN 滥用密度偏高', pts, `每万个地址 ${rep.per10k} 个近期上榜，约为全网平均的 ${rep.ratio} 倍`);
  }
  if (typeof asnInfo.botShare === 'number' && asnInfo.botShare > 0.5) {
    add('neighbours', 'asn-bots', 'ASN 机器流量偏高', (asnInfo.botShare - 0.5) / 0.5 * 6, `Cloudflare Radar：机器流量 ${Math.round(asnInfo.botShare * 100)}%`);
  }
  if (asnInfo.rpki === 'invalid') add('neighbours', 'rpki', 'RPKI 校验无效', 3, '该前缀的路由宣告与 ROA 不符，可能是配置错误或劫持');

  // ---------- abuse ----------
  const riskEntries = [];
  for (const source of sources) {
    if (typeof source.risk !== 'number') continue;
    riskEntries.push({ by: source.name, v: clamp(source.risk, 0, 100), w: (SOURCE_WEIGHTS[source.id] || {}).risk ?? 0.5 });
  }
  const riskW = riskEntries.reduce((sum, entry) => sum + entry.w, 0);
  // One major vendor's high score matters even if others say 0: blend the weighted mean with the (weight-capped) maximum.
  const riskMean = riskW ? riskEntries.reduce((sum, entry) => sum + entry.v * entry.w, 0) / riskW : null;
  const riskMax = riskEntries.length ? Math.max(...riskEntries.map(entry => entry.v * Math.min(1, entry.w))) : null;
  const risk = riskW ? Math.round(0.6 * riskMean + 0.4 * riskMax) : null;
  if (risk) add('abuse', 'risk', '欺诈 / 风险分', 0.3 * risk, riskEntries.map(entry => `${entry.by} ${entry.v}`).join(' · '));
  const abuser = tally([...flagVotes(sources, 'abuser'), ...(extraVotes.abuser || [])]);
  if (abuser.E > 0) add('abuse', 'abuser', '滥用 / 入侵记录', 10 * abuser.E, abuser.by.join('、'));

  const dnsbl = (evidence.dnsbl || []).filter(item => item.status === 'ok');
  const dnsblListed = dnsbl.filter(item => item.listed && item.kind !== 'tor');
  const dnsblPts = dnsblListed.reduce((sum, item) => sum + (item.kind === 'mail' ? 4 : 6), 0);
  if (dnsblPts) add('abuse', 'dnsbl', '黑名单收录', Math.min(20, dnsblPts), dnsblListed.map(item => item.name).join('、'));

  const lists = (evidence.lists || []).filter(item => item.status === 'ok');
  // Several independent lists agreeing is stronger than one: the worst list counts fully, each further list adds 2.
  const attack = lists.filter(item => (item.kind === 'attack' || item.kind === 'spam') && item.listed && item.pts > 0);
  if (attack.length) {
    const pts = Math.max(...attack.map(item => item.pts)) + 2 * (attack.length - 1);
    add('abuse', 'firehol', '威胁情报列表', pts, attack.map(item => item.name).join('、'));
  }
  const otx = sources.find(source => source.id === 'otx');
  if (otx?.pulses && !otx.benign) {
    add('abuse', 'otx', '威胁情报报告提及', otx.pulses >= 10 ? 10 : otx.pulses >= 3 ? 6 : 3, `AlienVault OTX ${otx.pulses} 份报告${otx.pulseNames?.length ? `：${otx.pulseNames.slice(0, 2).join('；')}` : ''}`);
  }
  const vt = sources.find(source => source.id === 'virustotal');
  if (vt?.vtMalicious) add('abuse', 'vt', '安全厂商标记恶意', vt.vtMalicious >= 5 ? 12 : vt.vtMalicious >= 2 ? 8 : 3, `VirusTotal ${vt.vtMalicious} 家判定恶意${vt.vtSuspicious ? `、${vt.vtSuspicious} 家可疑` : ''}`);
  const crowdsec = sources.find(source => source.id === 'crowdsec');
  if (crowdsec?.behaviors?.length && ['malicious', 'suspicious'].includes(crowdsec.reputation)) note('warn', `CrowdSec 观测到的行为：${crowdsec.behaviors.join('、')}`);
  const sfs = sources.find(source => source.id === 'sfs');
  if (sfs?.appears > 0) {
    const recent = sfs.lastseen && NOW() - Date.parse(sfs.lastseen) < 90 * 864e5;
    add('abuse', 'sfs', '垃圾注册记录', Math.min(12, 3 + 9 * (sfs.confidence || 0) / 100 + (recent ? 2 : 0)), `StopForumSpam 记录 ${sfs.appears} 次${sfs.lastseen ? `，最近 ${sfs.lastseen.slice(0, 10)}` : ''}`);
  }
  const shodan = sources.find(source => source.id === 'shodan');
  if (shodan?.vulns?.length) add('abuse', 'vulns', '存在已知漏洞', 6, `${shodan.vulns.length} 个 CVE，可能被入侵后用作跳板`);

  // ---------- live connection (only when the target is the visitor's own egress) ----------
  const probes = evidence.self ? evidence.probes || {} : {};
  const live = {};
  const webrtc = probes.webrtc;
  if (webrtc?.status === 'ok') {
    if (webrtc.leak) {
      live.webrtc = 'bad';
      add('live', 'webrtc', 'WebRTC 泄漏', webrtc.leakCountryDiffers ? 20 : 15, `UDP 出口 ${webrtc.leakIPs.join('、')} 与网页出口不同`);
    } else live.webrtc = webrtc.srflx?.length ? 'good' : 'info';
    if (webrtc.localExposed) add('live', 'webrtc-local', '内网地址暴露', 2, webrtc.localIPs.join('、'));
  }
  const dns = probes.dns;
  if (dns?.status === 'ok' && dns.verdict) {
    const pts = { own: 0, same: 0, public: 3, leak: 8, 'leak-cn': 12 }[dns.verdict] ?? 0;
    live.dns = pts >= 8 ? 'bad' : pts > 0 ? 'warn' : 'good';
    if (pts) add('live', 'dns', dns.verdict === 'public' ? 'DNS 跨区解析' : 'DNS 泄漏', pts, dns.summary);
    if (dns.ecsLeak) { live.dns = 'bad'; add('live', 'dns-ecs', 'EDNS 子网暴露位置', 10, dns.ecsSummary); }
  }
  const tcp = probes.tcp;
  if (tcp?.status === 'ok') {
    if (tcp.relay) { live.tcp = 'bad'; add('live', 'tcp', 'TCP 指纹像代理转发', 10, tcp.summary); }
    else if (tcp.osMismatch) { live.tcp = 'warn'; add('live', 'tcp', 'TCP 系统指纹不一致', 5, tcp.summary); }
    else live.tcp = 'good';
  }
  const tz = probes.tz;
  const ipOffset = zoneOffset(ipTimezone);
  if (tz && ipTimezone && typeof tz.offset === 'number' && ipOffset !== null) {
    const mismatch = tz.offset !== ipOffset;
    live.tz = mismatch ? 'warn' : 'good';
    if (mismatch) add('live', 'tz', '时区与 IP 不符', 6, `浏览器 ${tz.zone}，IP 所在 ${ipTimezone}`);
  }
  const lang = probes.lang;
  const countryLangs = COUNTRY_LANGS[country] || null;
  if (lang?.languages?.length && countryLangs) {
    const match = lang.languages.some(code => countryLangs.includes(code.split('-')[0].toLowerCase()));
    live.lang = match ? 'good' : 'warn';
    if (!match) add('live', 'lang', '语言与 IP 地区不符', 2, `浏览器 ${lang.languages.slice(0, 3).join(', ')}，${country} 常用 ${countryLangs.join('/')}`);
  }
  const ipv6 = probes.ipv6;
  if (ipv6?.status === 'ok' && ipv6.mismatch) {
    live.ipv6 = 'bad';
    add('live', 'ipv6', 'IPv6 绕过代理', 8, ipv6.summary);
  } else if (ipv6?.status === 'ok') live.ipv6 = ipv6.address ? 'good' : 'info';
  const egress = probes.egress;
  if (egress?.split) { live.egress = 'warn'; add('live', 'egress', '多出口分流', 3, egress.summary); }
  else if (egress) live.egress = egress.domesticDiffers ? 'info' : 'good';
  const turnstile = probes.turnstile;
  if (turnstile?.status === 'ok') {
    const pts = turnstile.outcome === 'silent' ? 0 : turnstile.outcome === 'interactive' ? 8 : 15;
    live.turnstile = pts === 0 ? 'good' : pts < 15 ? 'warn' : 'bad';
    if (pts) add('live', 'turnstile', turnstile.outcome === 'interactive' ? 'Turnstile 需要人工验证' : 'Turnstile 未通过', pts, turnstile.summary);
  }
  const recaptcha = probes.recaptcha;
  if (recaptcha?.status === 'ok' && typeof recaptcha.score === 'number') {
    const pts = 20 * clamp((0.7 - recaptcha.score) / 0.6, 0, 1);
    live.recaptcha = recaptcha.score >= 0.7 ? 'good' : recaptcha.score >= 0.4 ? 'warn' : 'bad';
    if (pts) add('live', 'recaptcha', 'reCAPTCHA 分数偏低', pts, `Google reCAPTCHA v3 = ${recaptcha.score.toFixed(1)}`);
  }

  // ---------- totals ----------
  const categories = CATEGORIES.map(category => {
    const list = items[category.id].sort((a, b) => b.pts - a.pts);
    const raw = list.reduce((sum, item) => sum + item.pts, 0);
    return { ...category, items: list, raw: r1(raw), penalty: r1(Math.min(category.cap, raw)) };
  });
  const penaltyOf = id => categories.find(category => category.id === id).penalty;
  const ipPenalty = penaltyOf('anon') + penaltyOf('abuse') + penaltyOf('neighbours') + penaltyOf('network') + penaltyOf('geo');

  // ---------- bonuses: strong positive evidence lifts a clean IP from the base towards 100 ----------
  const bonusItems = [];
  const plus = (id, label, pts, detail, isLive = false) => bonusItems.push({ id, label, pts, detail, live: isLive });
  const anonCoverage = Math.max(anonFlags.vpn.of, anonFlags.proxy.of);
  if (anonFlags.vpn.E === 0 && anonFlags.proxy.E === 0 && tor.E === 0 && anonCoverage >= 4 && risk !== null && risk <= 10 && riskEntries.length >= 2) {
    plus('multi-clean', '多库一致干净', 2, `${anonCoverage} 个来源都未标记代理 / VPN，${riskEntries.length} 个风险分平均 ${risk}`);
  }
  if (nb && nb.checked >= 4 && !nb.count && !nb.whole.length && !nb.tor) plus('clean-neighbours', '邻居干净', 2, `${nb.prefix} 在 ${nb.checked} 个威胁列表里没有任何邻居上榜`);
  if (rep && rep.ratio < 0.5 && rep.size >= 4096) plus('asn-clean', 'ASN 信誉良好', 2, `滥用密度只有全网平均的 ${rep.ratio} 倍`);
  if ((ipType === 'residential' || ipType === 'mobile') && typeCertainty >= 0.7 && (asnCls === 'isp' || asnCls === 'mobile') && (asnInfo.inferred?.confidence ?? 0) >= 0.6) {
    plus('eyeball', ipType === 'mobile' ? '可信的移动网络' : '可信的运营商家宽', ipType === 'mobile' ? 2 : 1.5, '数据库与 ASN 都指向运营商接入网，网站很少整段封禁这类地址');
  }
  if (native && nativeCertainty >= 0.7) plus('native', '原生 IP', 0.5, '注册地与定位一致');
  if (asnInfo.rpki === 'valid') plus('rpki', 'RPKI 有效', 0.5, '路由宣告有 ROA 背书，不像被劫持的地址');
  const greynoise = sources.find(source => source.id === 'greynoise');
  if (greynoise?.riot) plus('riot', '已知良性服务', 1, `GreyNoise RIOT：${greynoise.name || '常见商业服务'}`);
  if (live.turnstile === 'good') plus('turnstile', 'Turnstile 直接放行', 1, 'Cloudflare 没有弹出任何验证', true);
  if (recaptcha?.status === 'ok' && recaptcha.score >= 0.9) plus('recaptcha', 'reCAPTCHA 高分', 2, `Google 给出 ${recaptcha.score.toFixed(1)}`, true);
  const ipBonus = Math.min(BONUS_CAP, bonusItems.filter(item => !item.live).reduce((sum, item) => sum + item.pts, 0));
  const allBonus = Math.min(BONUS_CAP, bonusItems.reduce((sum, item) => sum + item.pts, 0));
  const liveBonus = evidence.self ? allBonus - ipBonus : 0;

  let ipScore = Math.round(clamp(BASE + ipBonus - ipPenalty, 0, 100));
  let total = Math.round(clamp(BASE + ipBonus + liveBonus - ipPenalty - penaltyOf('live'), 0, 100));
  const torHard = tor.hard || tor.E >= 0.7;
  if (torHard) { ipScore = Math.min(ipScore, 25); total = Math.min(total, 25); }
  const scoredSources = sources.length;
  const pending = Object.values(evidence.sources || {}).filter(source => source?.status === 'pending').length;

  // ---------- tiles ----------
  const anonAny = Math.max(anonFlags.vpn.E, anonFlags.proxy.E);
  const checks = {
    type: { value: ipType, label: ipType ? TYPE_LABEL[ipType] || ipType : null, from: typeFrom, hosting, votes: nonHostingRank, mix: typeMix, certainty: r1(typeCertainty * 100) / 100, level: ipType === 'hosting' ? 'warn' : ipType === 'business' ? 'info' : ipType ? 'good' : 'none' },
    native: { native, regCountry, regVotes: regRank, nativeShare, certainty: r1(nativeCertainty * 100) / 100, level: native === null ? 'none' : native ? 'good' : 'warn' },
    lease,
    geo: { country, city, support: countrySupport, countries, families: familySeen.size, count: geoCount, level: !country ? 'none' : countries.length > 1 ? 'warn' : 'good' },
    anon: { vpn: anonFlags.vpn, proxy: anonFlags.proxy, relay: anonFlags.relay, crawler: anonFlags.crawler, E: anonAny, level: anonFlags.vpn.of + anonFlags.proxy.of === 0 ? 'none' : anonAny >= 0.5 ? 'bad' : anonAny > 0 ? 'warn' : 'good' },
    tor: { ...tor, level: tor.of === 0 ? 'none' : tor.E > 0 ? 'bad' : 'good' },
    risk: { value: risk, entries: riskEntries, level: risk === null ? 'none' : risk >= 70 ? 'bad' : risk >= 35 ? 'warn' : 'good' },
    abuse: { abuser, sfs: sfs ? { appears: sfs.appears || 0, lastseen: sfs.lastseen || null } : null, lists: attack.map(item => item.name), level: (abuser.E > 0 || attack.length || sfs?.appears) ? 'bad' : (abuser.of || sfs || lists.length) ? 'good' : 'none' },
    dnsbl: { listed: dnsblListed.map(item => item.name), checked: dnsbl.filter(item => item.kind !== 'tor').length, level: !dnsbl.length ? 'none' : dnsblListed.length ? 'bad' : 'good' },
    neighbours: { ...(nb || {}), level: !nb ? 'none' : nb.whole.length || nb.count >= 10 ? 'bad' : nb.count || nb.tor ? 'warn' : 'good' },
    asnRep: { ...(rep || {}), level: !rep ? 'none' : rep.ratio >= 15 ? 'bad' : rep.ratio >= 2 ? 'warn' : 'good' },
    asn: { consistency: asnConsistency, level: !asnConsistency ? 'none' : !asnConsistency.ok ? 'bad' : asnConsistency.warn ? 'warn' : 'good' },
    ports: { ports: shodan?.ports || [], tags: shodan?.tags || [], level: !shodan ? 'none' : shodan.tags?.some(tag => ['proxy', 'vpn', 'tor', 'compromised', 'malware'].includes(tag)) ? 'warn' : shodan.ports?.length ? 'info' : 'good' },
  };

  // ---------- scenarios ----------
  const isHosting = ipType === 'hosting';
  const anonSome = anonAny > 0 || torHard;
  const liveFlags = ['webrtc', 'dns', 'tcp', 'tz', 'ipv6'].filter(key => live[key] === 'bad' || live[key] === 'warn');
  const uses = {};
  const use = (id, level, why) => { uses[id] = { level, why }; };
  if (country && AI_BLOCKED.has(country)) use('ai', 'bad', `${country} 不在主流 AI 服务的支持地区`);
  else if (torHard || (risk ?? 0) >= 70) use('ai', 'bad', '风险分过高或 Tor 出口，容易被拒绝或封号');
  else if ((isHosting && (anonSome || (risk ?? 0) >= 35)) || liveFlags.includes('tcp') || liveFlags.includes('webrtc')) use('ai', 'warn', isHosting ? '机房 + 代理标记，可能触发风控' : '连接特征暴露了代理');
  else use('ai', 'good', '地区受支持，风险较低');
  if (torHard || anonAny >= 0.5) use('stream', 'bad', '被识别为 VPN / 代理，流媒体大概率拒绝');
  else if (isHosting || anonSome) use('stream', 'warn', isHosting ? '机房 IP，部分平台只给自制剧或拒绝' : '有来源标记代理');
  else if (native === false || countries.length > 1) use('stream', 'warn', native === false ? '广播 IP，地区可能被判成注册地' : '各库定位不一致');
  else use('stream', 'good', '原生、非机房，解锁概率较高');
  const turnstileBad = live.turnstile === 'bad'; const recaptchaBad = live.recaptcha === 'bad';
  if (torHard || (risk ?? 0) >= 75 || dnsblListed.length >= 2 || turnstileBad || recaptchaBad) use('captcha', 'bad', turnstileBad || recaptchaBad ? '实测人机验证未通过' : '高风险，验证码会频繁出现');
  else if ((risk ?? 0) >= 40 || (isHosting && anonSome) || dnsblListed.length || live.turnstile === 'warn' || live.recaptcha === 'warn' || (nb && (nb.whole.length || nb.count >= 10))) use('captcha', 'warn', nb && (nb.whole.length || nb.count >= 10) ? '同网段邻居名声不好，可能被连带要求验证' : '偶尔会被要求验证');
  else use('captcha', 'good', live.turnstile === 'good' || live.recaptcha === 'good' ? '实测直接通过' : '一般不会弹验证码');
  if (torHard || (risk ?? 0) >= 70 || abuser.yes >= 2) use('account', 'bad', '注册 / 支付风控大概率拦截');
  else if ((risk ?? 0) >= 35 || anonSome || isHosting || abuser.yes || liveFlags.length >= 2) use('account', 'warn', '可能需要额外验证');
  else use('account', 'good', '注册与付款风险较低');
  if (dnsblListed.length) use('mail', 'bad', '在邮件黑名单中，发信会被拒');
  else if (ipType === 'residential' || ipType === 'mobile') use('mail', 'warn', '家宽 / 移动段通常不被允许直接发信');
  else if (!hostname) use('mail', 'warn', '没有反向解析（PTR），发信会被降级');
  else use('mail', 'good', '有 PTR 且未上黑名单');
  if (torHard || isHosting || anonAny >= 0.5) use('social', 'bad', '机房或代理 IP，TikTok / 社媒容易限流');
  else if (native === false || anonSome || liveFlags.length) use('social', 'warn', '非原生或连接特征异常，账号可能被风控');
  else use('social', 'good', '适合社媒运营');

  // ---------- verdict ----------
  const grade = gradeOf(total);
  const liveCategory = categories.find(category => category.id === 'live');
  const ipIssues = categories.filter(category => category.id !== 'live').flatMap(category => category.items).sort((a, b) => b.pts - a.pts);
  let verdict;
  if (torHard) verdict = '这是 Tor 出口节点，几乎所有网站都会把你当高风险流量。';
  else if (ipScore >= 85 && liveCategory.penalty < 8) verdict = `${ipType === 'hosting' ? '机房 IP，但' : ''}没有明显风险标记，网站会把你当普通用户。`;
  else if (ipScore >= 85) verdict = `IP 本身很干净，但连接实测发现 ${liveCategory.items.slice(0, 2).map(item => item.label).join('、')}，网站仍可能识别出代理。`;
  else if (ipScore >= 60) verdict = `整体可用，主要扣分在 ${ipIssues.slice(0, 2).map(item => item.label).join('、')}${liveCategory.items.length ? `；实测另有 ${liveCategory.items[0].label}` : ''}。`;
  else verdict = `风险偏高：${ipIssues.slice(0, 3).map(item => item.label).join('、')}，注册、支付和 AI 服务都可能受限。`;

  const anonOf = Math.max(anonFlags.vpn.of, anonFlags.proxy.of);
  const confidence = scoredSources >= 10 && anonOf >= 3 ? 'high' : scoredSources >= 5 && anonOf >= 2 ? 'medium' : 'low';

  return {
    score: total, ipScore, base: BASE, bonus: { items: bonusItems.sort((a, b) => b.pts - a.pts), total: r1(allBonus), cap: BONUS_CAP },
    liveDelta: evidence.self ? Math.round(liveBonus - penaltyOf('live')) : null, grade, verdict,
    categories, checks, live, uses, notes,
    summary: { country, city, asn, org: orgRank[0]?.value || null, hostname, type: ipType, regCountry, native, ipTimezone, ipOffset, countryLangs, rdapName: rdap?.netname || null },
    confidence: { level: confidence, sources: scoredSources, pending, anonSources: anonOf },
  };
}

export function gradeOf(value) {
  if (value >= 95) return { letter: 'S', label: '极度纯净', tone: 'great' };
  if (value >= 85) return { letter: 'A', label: '纯净', tone: 'good' };
  if (value >= 70) return { letter: 'B', label: '良好', tone: 'ok' };
  if (value >= 55) return { letter: 'C', label: '一般', tone: 'warn' };
  if (value >= 40) return { letter: 'D', label: '可疑', tone: 'bad' };
  return { letter: 'F', label: '高危', tone: 'bad' };
}

export { CATEGORIES, TYPE_LABEL };
