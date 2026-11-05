/**
 * Egress IP quality score. Pure function: evidence in, explained score out.
 *
 * Score = 92 + bonuses (≤ 10) − Σ min(category cap, Σ item points), Tor exits capped at 25.
 * Voted items deduct by the weighted share of sources that flag them, so a lone hit among many misses costs little.
 * Safety comes first: anonymity, abuse, and the reputation of the /24 neighbours and the ASN carry most
 * of the weight; network type, ASN-type consistency and native/broadcast are small descriptive hints.
 * Live connection checks apply only when the target is the visitor's own egress.
 * Every deduction carries its evidence so the UI can show exactly why points were taken.
 */

const CATEGORIES = Object.freeze([
  { id: 'anon', label: '匿名化', cap: 50 },
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
  ipqs: { flags: 1.0, type: 0.9, risk: 0.7 },
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
export const BONUS_CAP = 10;

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
const r3 = value => Math.round(value * 1000) / 1000;
const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

// ---------- evidence helpers ----------

/**
 * Weighted share of the sources that answered: E = H / (H + N), so one hit among seven misses costs about a seventh
 * of the item, one hit against one miss about half.
 * - H, hit strength: a database classification adds its weight w; a direct observation (open proxy port,
 *   public proxy / Tor list, drone list) adds its odds w / (1 − w), so a reliable sighting (0.85 → 5.7) is hard
 *   to outvote while a weak one (Shodan tag 0.5 → 1) counts like a single database.
 * - N, miss strength: Σ w of the sources that explicitly said no. Missing fields never count.
 * A hard confirmation (Tor consensus, WARP) is E = 1.
 */
function tally(votes) {
  const known = votes.filter(vote => typeof vote.value === 'boolean');
  const positive = known.filter(vote => vote.value);
  const hard = positive.some(vote => vote.hard);
  const observed = positive.filter(vote => vote.obs);
  const H = positive.reduce((sum, vote) => {
    const w = Math.min(0.95, vote.w);
    return sum + (vote.obs ? w / (1 - w) : vote.w);
  }, 0);
  const N = known.filter(vote => !vote.value).reduce((sum, vote) => sum + vote.w, 0);
  const E = hard ? 1 : H > 0 ? H / (H + N) : 0;
  return {
    E: r3(E), H: r3(H), N: r3(N), yes: positive.length, of: known.length, hard,
    by: positive.map(vote => vote.by), observedBy: observed.map(vote => vote.by), clear: known.filter(vote => !vote.value).map(vote => vote.by),
  };
}

/** "2/7 来源命中：A、B · 加权占比 31%" — the detail line behind every voted deduction. */
function voteText(t, verb = '来源命中') {
  const share = t.hard ? '直接确认' : `加权占比 ${Math.round(t.E * 100)}%`;
  return `${t.yes}/${t.of} ${verb}${t.by.length ? `：${t.by.join('、')}` : ''} · ${share}`;
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
    // Scaled by how much of the registration evidence disagrees with the location.
    if (!native) add('geo', 'broadcast', '广播 IP', 3 * (1 - nativeShare), `注册地 ${regCountry}，定位 ${country}${nativeShare > 0 ? `；${Math.round(nativeShare * 100)}% 的注册信息与定位一致` : ''}`);
    if (regRank.length > 1) note('info', `注册信息不一致：${regRank.map(item => `${item.value}（${item.by.join('、')}）`).join(' / ')}`);
  }

  // ---------- anonymity ----------
  const extraVotes = evidence.extraVotes || {};
  const anonFlags = {};
  for (const flag of ['vpn', 'proxy', 'tor', 'relay', 'crawler']) {
    anonFlags[flag] = tally([...flagVotes(sources, flag), ...(extraVotes[flag] || [])]);
  }
  const tor = anonFlags.tor;
  const torHard = tor.hard || tor.E >= 0.7;
  if (tor.E > 0) add('anon', 'tor', 'Tor', 40 * tor.E, voteText(tor));
  // VPN and proxy flags usually describe the same anonymised egress, often from the same database:
  // the stronger one counts in full, the other at half.
  const vpnPts = 24 * anonFlags.vpn.E; const proxyPts = 26 * anonFlags.proxy.E;
  const overlap = vpnPts > 0 && proxyPts > 0;
  const halfNote = other => (overlap ? `；与${other}证据重叠，按一半计` : '');
  if (vpnPts) add('anon', 'vpn', 'VPN', overlap && vpnPts < proxyPts ? vpnPts / 2 : vpnPts, voteText(anonFlags.vpn) + (vpnPts < proxyPts ? halfNote('代理') : ''));
  const resProxyBy = sources.filter(source => source.resProxy === true).map(source => source.name);
  if (proxyPts) add('anon', 'proxy', resProxyBy.length ? '代理（含住宅代理）' : '代理', overlap && proxyPts <= vpnPts ? proxyPts / 2 : proxyPts, voteText(anonFlags.proxy) + (proxyPts <= vpnPts ? halfNote(' VPN ') : ''));
  if (anonFlags.relay.E > 0) add('anon', 'relay', '隐私中继', 5 * anonFlags.relay.E, voteText(anonFlags.relay));
  if (anonFlags.crawler.E > 0) add('anon', 'crawler', '爬虫 / 自动化', 8 * anonFlags.crawler.E, voteText(anonFlags.crawler));
  const anonAny = Math.max(anonFlags.vpn.E, anonFlags.proxy.E);
  const devices = sources.find(source => source.id === 'proxycheck')?.devices;
  if (devices?.address >= 10) {
    add('anon', 'shared', '多设备共用出口', devices.address >= 50 ? 5 : 3, `Proxycheck 估计该地址近期约 ${devices.address} 台设备`);
  }
  // 共享人数估计: distinct browsers that checked this IP from this IP itself in the last 30 days (Egress's own log).
  // 1–3 earns a bonus below, 4–10 is normal, from 11 on each extra person costs 0.5, up to 10.
  const seen = evidence.seen?.callerKnown ? evidence.seen : null;
  const sharers = seen?.sharers || 0;
  const sharersText = `近 ${seen?.windowDays || 30} 天约 ${sharers} 个不同浏览器从这个 IP 出口做过检测`;
  if (sharers > 10) add('anon', 'sharers', '共享人数多', Math.min(10, (sharers - 10) * 0.5), sharersText);

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
  // How sure we are that this is an operator access line (home broadband or mobile), for the clean-ISP bonus.
  let homeCertainty = 0;
  if (typeFrom === 'sources' || typeFrom === 'exclusion') {
    const hostShare = hosting.of ? hosting.E : ipType === 'hosting' ? 1 : 0;
    const others = nonHostingRank.length ? nonHostingRank : [{ value: 'residential', share: 1 }];
    typeMix = [{ value: 'hosting', share: hostShare }, ...others.map(item => ({ value: item.value, share: (1 - hostShare) * item.share }))];
    const evidenceCount = hosting.of + typeVotes.length;
    const coverage = Math.min(1, evidenceCount / 4);
    typeCertainty = typeFrom === 'exclusion' ? 0.35 : Math.max(...typeMix.map(item => item.share)) * coverage;
    const homeShare = typeMix.filter(item => item.value === 'residential' || item.value === 'mobile').reduce((sum, item) => sum + item.share, 0);
    homeCertainty = typeFrom === 'exclusion' ? 0.35 : homeShare * coverage;
  } else if (typeFrom === 'asn') {
    const merged = new Map();
    for (const item of asnInfo.inferred?.mix || []) {
      const value = TYPE_FROM_ASN[item.value];
      if (value) merged.set(value, (merged.get(value) || 0) + item.share);
    }
    typeMix = [...merged].map(([value, share]) => ({ value, share }));
    typeCertainty = (asnInfo.inferred?.confidence ?? 0) * 0.6;
    if (ipType === 'residential' || ipType === 'mobile') homeCertainty = typeCertainty;
  }
  typeMix = typeMix.filter(item => item.share > 0.005).sort((a, b) => b.share - a.share).map(item => ({ ...item, share: r1(item.share * 100) / 100 }));

  if (hosting.E > 0) add('network', 'hosting', '机房 IP', 15 * hosting.E, voteText(hosting, '来源标记机房'));
  else if (ipType === 'hosting' && typeFrom === 'asn') add('network', 'hosting-asn', '机房 IP（按 ASN 推断）', 10 * (asnHosting ?? 0.7), asnInfo.inferred?.reasons?.[0] || '');
  // A business line is not a risk in itself: proxies on it are caught by the anonymity, lease and abuse items.

  // The key cross-check: a "residential" label inside a datacenter or transit ASN.
  let asnConsistency = null;
  if (asnCls && ipType) {
    const homeLike = ipType === 'residential' || ipType === 'mobile';
    if (homeLike && (asnCls === 'hosting' || asnCls === 'cdn') && (asnHosting ?? 0) >= 0.5) {
      asnConsistency = { ok: false, text: `标为${TYPE_LABEL[ipType]}，但 ${asnInfo.label || 'ASN'} 以机房为主` };
      add('network', 'asn-conflict', '类型与 ASN 不符', 5 * asnHosting, asnConsistency.text);
    } else if (homeLike && asnCls === 'transit') {
      // A hint only: neither side is a datacenter, and leased space under the backbone is scored by the lease item.
      asnConsistency = { ok: true, warn: true, text: `标为${TYPE_LABEL[ipType]}，宣告方却是骨干 / 传输网：骨干网本身可靠，但家宽很少直接挂在它下面，这个标签存疑` };
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
  // 人机流量: Cloudflare Radar's 28-day human vs bot share of the ASN's HTTP traffic. Eyeball networks sit
  // around 10–30% bots; above 40% the network looks like servers and scrapers, and the deduction grows to 6 at 90%.
  const botShare = typeof asnInfo.botShare === 'number' ? clamp(asnInfo.botShare, 0, 1) : null;
  const humanShare = botShare === null ? null : typeof asnInfo.radar?.human === 'number' ? clamp(asnInfo.radar.human, 0, 1) : 1 - botShare;
  const botE = botShare === null ? 0 : clamp((botShare - 0.4) / 0.5, 0, 1);
  const botText = botShare === null ? '' : `Cloudflare Radar 近 28 天：人类 ${Math.round(humanShare * 100)}%，机器 ${Math.round(botShare * 100)}%`;
  if (botE > 0) add('neighbours', 'asn-bots', 'ASN 机器流量偏高', 6 * botE, botText);
  if (asnInfo.rpki === 'invalid') add('neighbours', 'rpki', 'RPKI 校验无效', 3, '该前缀的路由宣告与 ROA 不符，可能是配置错误或劫持');

  // ---------- abuse ----------
  const riskEntries = [];
  for (const source of sources) {
    if (typeof source.risk !== 'number') continue;
    riskEntries.push({ by: source.name, v: clamp(source.risk, 0, 100), w: (SOURCE_WEIGHTS[source.id] || {}).risk ?? 0.5 });
  }
  const riskW = riskEntries.reduce((sum, entry) => sum + entry.w, 0);
  // One major vendor's high score matters even if others say 0: blend the weighted mean with the (weight-capped) maximum.
  // The more vendors answer, the less a lone outlier counts: the maximum's share is 0.4 up to 3 vendors, 0.4·√(3/n) beyond.
  const riskMean = riskW ? riskEntries.reduce((sum, entry) => sum + entry.v * entry.w, 0) / riskW : null;
  const riskMax = riskEntries.length ? Math.max(...riskEntries.map(entry => entry.v * Math.min(1, entry.w))) : null;
  const maxShare = riskEntries.length ? 0.4 * Math.min(1, Math.sqrt(3 / riskEntries.length)) : 0;
  const risk = riskW ? Math.round((1 - maxShare) * riskMean + maxShare * riskMax) : null;
  if (risk) add('abuse', 'risk', '欺诈 / 风险分', 0.3 * risk, riskEntries.map(entry => `${entry.by} ${entry.v}`).join(' · '));
  const abuser = tally([...flagVotes(sources, 'abuser'), ...(extraVotes.abuser || [])]);
  if (abuser.E > 0) add('abuse', 'abuser', '滥用 / 入侵记录', 10 * abuser.E, voteText(abuser));

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
  if (shodan?.vulns?.length) {
    // Shodan matches the software versions in the banners it saw against CVE data: likely, not verified.
    const cves = [...shodan.vulns].sort((a, b) => b.localeCompare(a, 'en', { numeric: true }));
    add('abuse', 'vulns', '存在已知漏洞', 6, `${cves.length} 个 CVE：${cves.slice(0, 6).join('、')}${cves.length > 6 ? ' 等' : ''}。Shodan 按开放端口上的软件版本推断，未实际验证；主机若被入侵，可能被用作跳板`);
  }

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
    if (mismatch) add('live', 'tz', '时区与 IP 不符', 3, `浏览器 ${tz.zone}，IP 所在 ${ipTimezone}`);
  }
  const lang = probes.lang;
  const countryLangs = COUNTRY_LANGS[country] || null;
  if (lang?.languages?.length && countryLangs) {
    const match = lang.languages.some(code => countryLangs.includes(code.split('-')[0].toLowerCase()));
    live.lang = match ? 'good' : 'warn';
    if (!match) add('live', 'lang', '语言与 IP 地区不符', 1, `浏览器 ${lang.languages.slice(0, 3).join(', ')}，${country} 常用 ${countryLangs.join('/')}`);
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
  // +2 at half the internet-wide abuse density, rising to +4 at a tenth of it or less.
  if (rep && rep.ratio < 0.5 && rep.size >= 4096) {
    plus('asn-clean', rep.ratio <= 0.2 ? 'ASN 信誉优异' : 'ASN 信誉良好', r1(2 + 2 * clamp((0.5 - rep.ratio) / 0.4, 0, 1)), `滥用密度只有全网平均的 ${rep.ratio} 倍`);
  }
  // A clean operator access line (home broadband / mobile) is what websites trust most. Up to +3, scaled by how sure
  // the type is and whether the ASN agrees; any anonymity or abuse evidence forfeits it.
  const safeRecord = !torHard && anonAny < 0.15 && abuser.E < 0.15 && (risk ?? 0) < 25 && !attack.length && !dnsblListed.some(item => item.kind === 'abuse');
  if ((ipType === 'residential' || ipType === 'mobile') && safeRecord) {
    const asnConf = asnInfo.inferred?.confidence ?? 0;
    const asnFactor = (asnCls === 'isp' || asnCls === 'mobile') && asnConf >= 0.6 ? 1
      : asnCls === 'isp' || asnCls === 'mobile' || !asnCls ? 0.5 : asnCls === 'business' || asnCls === 'education' || asnCls === 'government' ? 0.3 : 0;
    const pts = r1(3 * clamp((homeCertainty - 0.5) / 0.4, 0, 1) * asnFactor);
    const asnText = asnFactor === 1 ? 'ASN 也是运营商' : asnFactor === 0.5 ? 'ASN 类型未确认' : 'ASN 不是运营商';
    if (pts >= 0.3) {
      plus('eyeball', ipType === 'mobile' ? '纯净移动网络' : '纯净运营商 IP', pts,
        `类型确定度 ${Math.round(homeCertainty * 100)}%，${asnText}，没有匿名或滥用记录；网站很少整段封禁这类地址`);
    }
  }
  if (native && nativeCertainty >= 0.7) plus('native', '原生 IP', 0.5, '注册地与定位一致');
  if (asnInfo.rpki === 'valid') plus('rpki', 'RPKI 有效', 0.5, '路由宣告有 ROA 背书，不像被劫持的地址');
  const greynoise = sources.find(source => source.id === 'greynoise');
  if (greynoise?.riot) plus('riot', '已知良性服务', 1, `GreyNoise RIOT：${greynoise.name || '常见商业服务'}`);
  if (botShare !== null && botShare <= 0.2) plus('asn-human', '人类流量为主', 1, botText);
  if (sharers >= 1 && sharers <= 3) plus('sharers', sharers === 1 ? '独享 IP' : '共享人数少', 2, sharersText);
  if (live.turnstile === 'good') plus('turnstile', 'Turnstile 直接放行', 1, 'Cloudflare 没有弹出任何验证', true);
  if (recaptcha?.status === 'ok' && recaptcha.score >= 0.9) plus('recaptcha', 'reCAPTCHA 高分', 2, `Google 给出 ${recaptcha.score.toFixed(1)}`, true);
  const ipBonus = Math.min(BONUS_CAP, bonusItems.filter(item => !item.live).reduce((sum, item) => sum + item.pts, 0));
  const allBonus = Math.min(BONUS_CAP, bonusItems.reduce((sum, item) => sum + item.pts, 0));
  const liveBonus = evidence.self ? allBonus - ipBonus : 0;

  let ipScore = Math.round(clamp(BASE + ipBonus - ipPenalty, 0, 100));
  let total = Math.round(clamp(BASE + ipBonus + liveBonus - ipPenalty - penaltyOf('live'), 0, 100));
  if (torHard) { ipScore = Math.min(ipScore, 25); total = Math.min(total, 25); }
  const scoredSources = sources.length;
  const pending = Object.values(evidence.sources || {}).filter(source => source?.status === 'pending').length;

  // ---------- tiles ----------
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
    bots: { bot: botShare === null ? null : r3(botShare), human: humanShare === null ? null : r3(humanShare), window: asnInfo.radar?.window || null, level: botShare === null ? 'none' : botShare >= 0.6 ? 'bad' : botShare >= 0.4 ? 'warn' : 'good' },
    asn: { consistency: asnConsistency, level: !asnConsistency ? 'none' : !asnConsistency.ok ? 'bad' : asnConsistency.warn ? 'warn' : 'good' },
    sharers: { count: seen ? sharers : null, tier: !seen || !sharers ? null : sharers === 1 ? '独享 IP' : sharers <= 3 ? '少量共享' : sharers <= 10 ? '正常' : '多人共享', lookers: seen?.lookers ?? null, lookups: seen?.lookups ?? null, windowDays: seen?.windowDays || 30, level: !seen || !sharers ? 'none' : sharers <= 3 ? 'good' : sharers <= 10 ? 'info' : sharers <= 20 ? 'warn' : 'bad' },
    ports: { ports: shodan?.ports || [], tags: shodan?.tags || [], level: !shodan ? 'none' : shodan.tags?.some(tag => ['proxy', 'vpn', 'tor', 'compromised', 'malware'].includes(tag)) ? 'warn' : shodan.ports?.length ? 'info' : 'good' },
  };

  // ---------- scenarios: every use case gets its own 0–100 meter ----------
  // Each starts at 100 and deducts only what that kind of website checks: ≥ 75 可以, 50–74 看情况, < 50 不建议.
  // Hard gates (unsupported AI region, Tor exit) cap the meter whatever the rest says.
  const typeShare = value => typeMix.filter(item => item.value === value).reduce((sum, item) => sum + item.share, 0);
  const hostE = typeShare('hosting'); const businessE = typeShare('business');
  const homeE = typeShare('residential'); const mobileE = typeShare('mobile');
  const anonTop = anonFlags.vpn.E >= anonFlags.proxy.E ? anonFlags.vpn : anonFlags.proxy;
  const geoSplitE = countries.length > 1 ? clamp((0.85 - countrySupport) / 0.35, 0, 1) : 0;
  const broadcastE = native === false ? 1 - nativeShare : 0;
  const leaseE = lease?.leased || lease?.possible ? clamp(lease.confidence / 0.7, 0, 1) : 0;
  const sharedE = devices?.address >= 50 ? 1 : devices?.address >= 10 ? 0.5 : 0;
  const nbE = !nb ? 0 : nb.whole.length ? 1 : nb.count >= 10 ? 0.7 : nb.count >= 3 ? 0.4 : nb.count ? 0.2 : 0;
  const asnAbuseE = !rep ? 0 : rep.ratio >= 15 ? 1 : rep.ratio >= 5 ? 0.6 : rep.ratio >= 2 ? 0.3 : 0;
  const abuseE = Math.max(abuser.E, attack.length ? 1 : 0);
  const mailListed = dnsblListed.filter(item => item.kind === 'mail');
  const abuseListed = dnsblListed.filter(item => item.kind === 'abuse');
  const riskV = risk ?? 0;
  const blockedGeo = countries.filter(item => AI_BLOCKED.has(item.value));
  const ptrSource = sources.find(source => source.id === 'ptr');
  const sfsRecent = Boolean(sfs?.lastseen && NOW() - Date.parse(sfs.lastseen) < 90 * 864e5);
  const asnYoung = Boolean(asnInfo.regDate && NOW() - Date.parse(asnInfo.regDate) < 2 * 365 * 864e5);
  const dnsVerdict = dns?.status === 'ok' ? dns.verdict : null;
  const tcpVerdict = tcp?.status === 'ok' ? (tcp.relay ? 'relay' : tcp.osMismatch ? 'os' : null) : null;
  const tsOutcome = turnstile?.status === 'ok' ? turnstile.outcome : null;
  const rcScore = recaptcha?.status === 'ok' && typeof recaptcha.score === 'number' ? recaptcha.score : null;
  const leakE = webrtc?.status === 'ok' && webrtc.leak ? (webrtc.leakCountryDiffers ? 1 : 0.75) : 0;
  const captchaPassed = (tsOutcome !== null || rcScore !== null) && (tsOutcome === null || tsOutcome === 'silent') && (rcScore === null || rcScore >= 0.7);

  /** Signals several scenarios share; each scenario passes its own weight. */
  const signals = (hit, gate) => ({
    anon: pts => hit('VPN / 代理标记', pts * anonAny, anonTop.yes ? voteText(anonTop) : ''),
    hosting: pts => hit('机房 IP', pts * hostE, `IP 类型中机房占 ${Math.round(hostE * 100)}%`),
    business: pts => hit('商业线路', pts * businessE, `IP 类型中商业宽带占 ${Math.round(businessE * 100)}%`),
    broadcast: pts => hit('广播 IP', pts * broadcastE, `注册地 ${regCountry}，定位 ${country}`),
    geoSplit: pts => hit('定位不一致', pts * geoSplitE, countries.map(item => `${item.value} ${Math.round(item.share * 100)}%`).join(' · ')),
    lease: pts => hit('租赁地址段', pts * leaseE, lease?.reasons?.[0] || ''),
    shared: pts => hit('多设备共用出口', pts * sharedE, devices ? `Proxycheck 估计近期约 ${devices.address} 台设备` : ''),
    risk: per => hit('欺诈 / 风险分', per * riskV, `综合风险分 ${riskV}`),
    abuse: pts => hit('滥用 / 威胁记录', pts * abuseE, [abuser.yes ? voteText(abuser) : '', attack.map(item => item.name).join('、')].filter(Boolean).join('；')),
    neighbours: pts => hit('同网段邻居上榜', pts * nbE, nb ? (nb.whole.length ? `${nb.prefix} 整段在 ${nb.whole.join('、')}` : `${nb.prefix} 内 ${nb.count} 个地址上榜`) : ''),
    asnAbuse: pts => hit('ASN 滥用密度高', pts * asnAbuseE, rep ? `约为全网平均的 ${rep.ratio} 倍` : ''),
    bots: pts => hit('人机流量：机器占比高', pts * botE, botText),
    webrtc: pts => hit('WebRTC 泄漏', pts * leakE, webrtc?.leakIPs?.join('、') || ''),
    dns: (leak, cn, cross) => {
      if (dnsVerdict === 'leak-cn') hit('DNS 解析来自中国大陆', cn, dns.summary);
      else if (dnsVerdict === 'leak') hit('DNS 泄漏', leak, dns.summary);
      else if (dnsVerdict === 'public') hit('DNS 跨区解析', cross, dns.summary);
    },
    ecs: pts => { if (dns?.status === 'ok' && dns.ecsLeak) hit('EDNS 子网暴露位置', pts, dns.ecsSummary); },
    ipv6: pts => { if (live.ipv6 === 'bad') hit('IPv6 走了别的出口', pts, ipv6.summary); },
    tcp: (relay, os) => {
      if (tcpVerdict === 'relay') hit('TCP 指纹像代理转发', relay, tcp.summary);
      else if (tcpVerdict === 'os') hit('TCP 系统指纹不一致', os, tcp.summary);
    },
    tz: pts => { if (live.tz === 'warn') hit('时区与 IP 不符', pts, `浏览器 ${tz.zone}，IP 所在 ${ipTimezone}`); },
    lang: pts => { if (live.lang === 'warn') hit('语言与 IP 地区不符', pts, `浏览器 ${lang.languages.slice(0, 2).join(', ')}`); },
    turnstile: (interactive, fail) => {
      if (tsOutcome === 'interactive') hit('Turnstile 需要人工验证', interactive, turnstile.summary);
      else if (tsOutcome === 'fail') hit('Turnstile 未通过', fail, turnstile.summary);
    },
    recaptcha: pts => { if (rcScore !== null) hit('reCAPTCHA 分数偏低', pts * clamp((0.7 - rcScore) / 0.6, 0, 1), `Google reCAPTCHA v3 = ${rcScore.toFixed(1)}`); },
    tor: (pts, max, text) => { hit('Tor 出口', pts * tor.E, voteText(tor)); if (torHard) gate(max, text); },
  });
  const meter = (calm, build, note = '') => {
    const items = []; const gates = [];
    const hit = (label, pts, detail = '') => { if (pts >= 0.5) items.push({ label, pts: r1(pts), detail }); };
    const gate = (max, text) => gates.push({ max, text });
    build(hit, gate, signals(hit, gate));
    items.sort((a, b) => b.pts - a.pts);
    const cap = gates.sort((a, b) => a.max - b.max)[0] || null;
    const value = Math.round(Math.min(cap ? cap.max : 100, clamp(100 - items.reduce((sum, item) => sum + item.pts, 0), 0, 100)));
    const level = value >= 75 ? 'good' : value >= 50 ? 'warn' : 'bad';
    const why = cap?.text || (items[0]?.pts >= 5 ? `主要扣分：${items.slice(0, 2).map(item => item.label).join('、')}` : calm);
    return { score: value, level, why, gate: cap?.text || null, note, items };
  };

  const uses = {
    // Netflix-style catalogues: anonymity and datacenter lists first, then which region the IP resolves to.
    stream: meter('原生、非机房，解锁概率较高', (hit, gate, s) => {
      s.anon(91); s.hosting(55); s.business(8); s.broadcast(20); s.geoSplit(25); s.lease(8); s.shared(10);
      hit('隐私中继', 10 * anonFlags.relay.E, voteText(anonFlags.relay));
      s.ipv6(25); s.dns(10, 10, 4); s.ecs(8); s.risk(0.1);
      s.tor(60, 5, 'Tor 出口，流媒体基本都会拒绝');
    }),
    // AI services: supported region is a hard gate; anything that reveals a different real location weighs most.
    ai: meter('地区受支持，风险较低', (hit, gate, s) => {
      if (country && AI_BLOCKED.has(country)) gate(0, `${country} 不在主流 AI 服务的支持地区`);
      else hit('部分数据库定位在不支持地区', 40 * blockedGeo.reduce((sum, item) => sum + item.share, 0), blockedGeo.map(item => `${item.value}：${item.by.join('、')}`).join('；'));
      s.webrtc(35); s.dns(12, 25, 3); s.ecs(20); s.ipv6(15);
      s.anon(33); s.hosting(15); s.risk(0.4); s.abuse(15);
      s.tcp(12, 5); s.tz(4); s.lang(1.5); s.turnstile(10, 25); s.bots(8);
      s.tor(60, 10, 'Tor 出口，AI 服务会拒绝或封号');
    }),
    // CAPTCHA frequency follows IP reputation; a measured pass outweighs the predictions.
    captcha: meter(captchaPassed ? '实测直接通过' : '一般不会弹验证码', (hit, gate, s) => {
      const k = captchaPassed ? 0.4 : 1;
      s.anon(33 * k); s.hosting(20 * k); s.risk(0.35 * k); s.abuse(25 * k);
      hit('黑名单收录', Math.min(20, 10 * abuseListed.length + 3 * mailListed.length) * k, dnsblListed.map(item => item.name).join('、'));
      s.neighbours(20 * k); s.asnAbuse(12 * k); s.shared(10 * k);
      s.bots(10 * k);
      s.turnstile(25, 45); s.recaptcha(50);
      s.tor(60, 10, 'Tor 出口几乎每次都要验证');
    }, captchaPassed ? '实测通过：推测项按 40% 计' : ''),
    // Sign-up and payment risk engines: fraud score, anonymity, spam history and browser / IP consistency.
    account: meter('注册与付款风险较低', (hit, gate, s) => {
      s.risk(0.6); s.anon(39); s.hosting(20); s.abuse(15);
      if (sfs?.appears > 0) hit('垃圾注册记录', 12 + (sfsRecent ? 5 : 0), `StopForumSpam 记录 ${sfs.appears} 次${sfs.lastseen ? `，最近 ${sfs.lastseen.slice(0, 10)}` : ''}`);
      s.broadcast(6); s.geoSplit(10); s.lease(5); s.shared(8); s.bots(8);
      s.tz(6); s.lang(2.5); s.webrtc(20); s.dns(10, 15, 3); s.tcp(10, 5); s.ipv6(10);
      s.tor(70, 5, 'Tor 出口，注册和支付基本都会被拦截');
    }),
    // Direct SMTP: mail blacklists, dynamic (home / mobile) ranges and PTR decide; a server IP is normal here.
    mail: meter('有 PTR 且未上黑名单，适合直接发信', (hit, gate, s) => {
      hit('邮件黑名单', Math.min(60, 25 * mailListed.length), mailListed.map(item => item.name).join('、'));
      hit('滥用类黑名单', Math.min(30, 15 * abuseListed.length), abuseListed.map(item => item.name).join('、'));
      hit(mobileE > homeE ? '移动网络地址段' : '家宽地址段', (55 * homeE + 60 * mobileE) * clamp(0.4 + homeCertainty, 0.6, 1), '收件方通常整段拒收家宽 / 移动段直接发来的邮件');
      if (ptrSource && !hostname) hit('没有反向解析（PTR）', 25, '多数收件方要求发信 IP 有 PTR');
      else if (hostname && (ptrSource?.type === 'residential' || ptrSource?.type === 'mobile')) hit('PTR 像动态地址', 15, hostname);
      s.abuse(15); s.neighbours(15); s.asnAbuse(15); s.anon(20); s.lease(5);
      if (asnYoung) hit('新注册 ASN', 5, `ASN 注册于 ${asnInfo.regDate.slice(0, 10)}`);
      s.tor(60, 10, 'Tor 出口不能用来发信');
    }),
    // TikTok / Instagram: residential, native and a consistent device environment matter most.
    social: meter(homeE + mobileE >= 0.5 ? '原生住宅 / 移动网络，适合社媒运营' : '没有明显风控信号', (hit, gate, s) => {
      s.hosting(55); s.anon(52); s.broadcast(20); s.geoSplit(15); s.business(5); s.lease(8); s.shared(15);
      s.risk(0.25); s.abuse(10); s.bots(8);
      s.tz(8); s.lang(3); s.webrtc(20); s.dns(10, 15, 4); s.ipv6(15); s.tcp(12, 6);
      s.tor(80, 5, 'Tor 出口，社媒账号会被直接限制');
    }),
  };

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
