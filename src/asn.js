/**
 * ASN profile: who announces the prefix, what kind of network it is, and whether the address
 * space looks leased. The inferred class feeds the "residential label vs ASN type" cross-check.
 */
import { getJSON, text, num } from './util.js';
import { API_BASE } from '../config.js';

const LISTS = {
  hosting: [16509, 14618, 8987, 396982, 19527, 8075, 8068, 8069, 12076, 31898, 36351, 45102, 37963, 132203, 45090, 136907, 55990, 135377, 59019,
    14061, 63949, 20473, 16276, 24940, 213230, 51167, 40021, 12876, 60781, 28753, 30633, 59253, 7203, 395954, 9009, 60068, 212238, 40676, 8100,
    36352, 53667, 25820, 906, 199524, 202422, 36007, 63473, 35916, 62240, 21859, 54600, 35908, 46844, 54290, 47583, 8560, 6724, 31034, 202053,
    54825, 3258, 35913, 397423, 62904, 46606, 26496, 32244, 22612, 19318, 32613, 13213, 29802, 33387, 138997, 141995, 55933,
    20278, 397373, 49505, 207990, 44477, 203020, 210644, 50673, 48282, 58061, 211252, 31173, 39351, 9370, 2635, 7506, 38001],
  cdn: [13335, 209242, 20940, 16625, 54113, 22822, 33438, 15169, 32934, 2906, 16550, 60626],
  transit: [174, 3356, 3549, 1299, 2914, 6453, 6762, 3257, 6939, 4637, 3491, 1239, 6461, 5511, 9002, 4826, 58453, 4809, 23764, 10099, 9929,
    12956, 1273, 2828, 10026, 20485, 7473, 5400, 4651, 9304, 37100, 64049],
  mobile: [9605, 21928, 22394, 6167, 20057, 55836, 31133, 16135, 45609, 24445, 56040, 56041, 56042, 56044, 56046, 56047, 56048],
  isp: [4134, 4837, 9808, 4812, 17621, 4808, 17816, 7922, 7018, 701, 209, 20115, 22773, 5650, 11427, 20001, 10796, 11351, 12271, 33363, 6128,
    3209, 5089, 2856, 3215, 12322, 5410, 15557, 3352, 3269, 1136, 2516, 4713, 17676, 2527, 4766, 9318, 3786, 3462, 4780, 9924, 4760, 9269,
    10091, 9506, 45899, 7552, 18403, 17974, 9829, 24560, 1221, 4804, 7545, 812, 577, 6327, 852, 8151, 28573, 12389, 8402, 25513, 9121, 8452,
    6849, 5617, 12741, 2119, 3301, 1759, 5432, 6805, 8881, 3303, 8447, 15502, 2860, 3243, 12430, 6739, 30722, 12874, 4788, 9583, 23969, 4818,
    17552, 131090, 18881, 26599, 27699, 7303, 10318, 22927, 13999, 4230, 6830, 3320, 7713],
};
const KNOWN = new Map(Object.entries(LISTS).flatMap(([cls, asns]) => asns.map(asn => [asn, cls])));
// Transit operators that also run a big hosting business: transit for the backbone check, but hosting-leaning.
const TRANSIT_HOSTING = new Set([6939, 58453, 4809, 23764, 10099, 9929, 3491]);

const KEYWORDS = [
  ['cdn', /\b(cdn|akamai|cloudflare|fastly|edgecast|limelight|stackpath|bunnycdn|bunnyway|content delivery)\b/i, 1.5],
  ['hosting', /(hosting|\bhost\b|server|datacent(er|re)|data cent(er|re)|\bidc\b|cloud|\bvps\b|colo(cation)?|dedicated|compute|virtual|\bovh|hetzner|leaseweb|contabo|digitalocean|linode|vultr|choopa|amazon|\baws\b|azure|alibaba|aliyun|tencent|oracle|softlayer|rackspace|\bm247|datacamp|cdn77|psychz|quadranet|colocrossing|frantech|buyvm|krypt|sharktech|hostwinds|ionos|scaleway|upcloud|kamatera|g-?core|zenlayer|clouvider|dmit|xtom|racknerd|hostinger|\bvpn\b|proxy|\bnetwork solutions\b)/i, 1.4],
  ['transit', /(backbone|transit|\bcarrier\b|cogent|lumen|level ?3|arelion|telia carrier|\bgtt\b|zayo|tata comm|sparkle|pccw global|telstra global|telstra international|hurricane electric|ntt (america|global)|global crossing|\bretn\b)/i, 1.6],
  ['mobile', /(mobile|wireless|cellular|\blte\b|\b5g\b|\bgsm\b|mobil\b|movil|móvil)/i, 1.2],
  ['education', /(universit|college|school|academ|education|research|\bedu\b|cernet|institute|\bnren\b)/i, 1.6],
  ['government', /(government|ministry|\bgov\b|federal|municipal)/i, 1.4],
  ['isp', /(telecom|telekom|telecommunication|broadband|\bcable|communications?|comcast|charter|verizon|at&t|\bisp\b|internet service|\bdsl\b|fib(er|re)|ftth|netcom|unicom|telefonica|vodafone|orange|kddi|\bntt\b|softbank|telstra|optus|rogers|\bbell\b|shaw|telus|hinet|chunghwa|pccw|hkbn|singtel|starhub|telkom|viettel|vnpt|airtel|\bjio\b|rostelecom|beeline|megafon|\bmts\b|turk ?telekom|kt corp|sk broadband|lg ?u\+|chinanet|china telecom|china mobile|cmnet)/i, 1.0],
];

const PDB_TYPES = {
  'Cable/DSL/ISP': ['isp', 2.2], NSP: ['transit', 2.2], Content: ['hosting', 1.8], Enterprise: ['business', 1.6],
  'Educational/Research': ['education', 2.2], 'Non-Profit': ['business', 1.0], Government: ['government', 2.0],
  'Route Server': ['business', 0.6], 'Network Services': ['business', 0.6], 'Route Collector': ['business', 0.6],
};

export const CLASS_LABEL = {
  isp: '运营商宽带', mobile: '移动运营商', hosting: '机房 / 云', cdn: 'CDN / 内容网络', transit: '骨干 / 传输网',
  business: '企业网络', education: '教育科研网', government: '政府网络',
};

/** Infer the network class from everything known about an ASN. Pure; exported for tests. */
export function inferASN({ asn, names = [], pdb = null, v4ips = null, botShare = null, ipapiType = null, ipinfoType = null, companyTypes = [], regDate = null }) {
  const votes = {}; const reasons = [];
  // Self-declared evidence (PeeringDB entry, network name) is what "ISP proxy" sellers dress up,
  // so a verdict without any independent evidence gets a lower confidence.
  let independent = false;
  const vote = (cls, weight, reason, own = false) => { votes[cls] = (votes[cls] || 0) + weight; if (reason) reasons.push(reason); if (!own) independent = true; };
  const known = KNOWN.get(asn);
  if (known) vote(known, 3, `AS${asn} 在已知${CLASS_LABEL[known]}名单中`);
  if (TRANSIT_HOSTING.has(asn)) vote('hosting', 1.2, '该骨干网同时经营大量机房 / 跨境专线业务');
  for (const type of pdb?.types || (pdb?.type ? [pdb.type] : [])) {
    const mapped = PDB_TYPES[type];
    if (mapped) vote(mapped[0], mapped[1], `PeeringDB 自报类型：${type}`, true);
  }
  if (pdb?.ratio === 'Heavy Outbound' || pdb?.ratio === 'Mostly Outbound') vote('hosting', 0.8, `PeeringDB 流量以出向为主（${pdb.ratio}）`, true);
  if (pdb?.ratio === 'Heavy Inbound' || pdb?.ratio === 'Mostly Inbound') vote('isp', 0.8, `PeeringDB 流量以入向为主（${pdb.ratio}），典型的用户接入网`, true);
  const nameText = names.filter(Boolean).join(' | ');
  for (const [cls, pattern, weight] of KEYWORDS) {
    if (pattern.test(nameText)) { vote(cls, weight, `名称含${CLASS_LABEL[cls]}特征：${nameText.match(pattern)[0]}`, true); break; }
  }
  // Company types reported by IP databases (IPinfo, IP2Location, IPRegistry, IPData, ipapi.is): independent votes.
  const COMPANY = { residential: 'isp', mobile: 'mobile', hosting: 'hosting', business: 'business', education: 'education', government: 'government' };
  for (const item of companyTypes) {
    const mapped = COMPANY[item.value];
    if (mapped) vote(mapped, 1.0, `${item.by} 公司类型：${item.value}`);
  }
  if (ipinfoType) {
    const mapped = { isp: 'isp', hosting: 'hosting', business: 'business', edu: 'education', education: 'education' }[ipinfoType];
    if (mapped) vote(mapped, 2.2, `IPinfo ASN 类型：${ipinfoType}`);
  }
  if (ipapiType) {
    const mapped = { isp: 'isp', hosting: 'hosting', business: 'business', education: 'education', government: 'government' }[ipapiType];
    if (mapped) vote(mapped, 1.5, `ipapi.is ASN 类型：${ipapiType}`);
  }
  if (typeof v4ips === 'number' && v4ips > 0) {
    if (v4ips >= 1_000_000) vote('isp', 0.5, `宣告 ${v4ips.toLocaleString()} 个 IPv4，规模属于大型运营商`);
    else if (v4ips <= 4096) { vote('hosting', 0.4); vote('business', 0.4, `仅宣告 ${v4ips.toLocaleString()} 个 IPv4，小型网络`); }
  }
  const ageYears = regDate ? (Date.now() - Date.parse(regDate)) / (365.25 * 864e5) : null;
  if (ageYears !== null && ageYears < 5 && !known) vote('hosting', 0.4, `ASN ${regDate.slice(0, 10)} 才注册，新网络里机房与代理业务更常见`);
  if (typeof botShare === 'number') {
    if (botShare >= 0.6) vote('hosting', 1.5, `Cloudflare Radar：机器流量占 ${Math.round(botShare * 100)}%`);
    else if (botShare <= 0.25) vote('isp', 0.6, `Cloudflare Radar：机器流量仅 ${Math.round(botShare * 100)}%`);
  }
  const ranked = Object.entries(votes).sort((a, b) => b[1] - a[1]);
  if (!ranked.length) return { cls: null, label: '未知', hosting: null, confidence: 0, reasons: ['没有足够的 ASN 信息'], mix: [] };
  const total = ranked.reduce((sum, [, weight]) => sum + weight, 0);
  const [cls, top] = ranked[0];
  const hosting = ((votes.hosting || 0) + (votes.cdn || 0) + 0.3 * (votes.transit || 0)) / total;
  let confidence = Math.min(1, top / 4) * (top / total);
  if (!independent) { confidence *= 0.65; reasons.push('只有 ASN 自报的信息（PeeringDB、名称），没有第三方佐证'); }
  // Share of each class, for the mixed "ISP / 机房" style tags.
  const mix = ranked.map(([value, weight]) => ({ value, share: Math.round(weight / total * 100) / 100 }));
  return { cls, label: CLASS_LABEL[cls], hosting: Math.round(hosting * 100) / 100, confidence: Math.round(confidence * 100) / 100, reasons, votes, mix };
}

const tokens = value => new Set(String(value || '').toLowerCase().replace(/[^a-z0-9 ]/g, ' ').split(/\s+/)
  .filter(word => word.length > 2 && !['inc', 'ltd', 'llc', 'limited', 'the', 'and', 'corp', 'corporation', 'company', 'network', 'networks', 'global', 'international', 'internet', 'services', 'asn'].includes(word)));

const BROKERS = /(ipxo|interlir|heficed|ipbroker|internet utilities|logicweb|ip-?volume|ipv4 ?(mall|market|depot)|abuseradar|cloud innovation|larus|netutils)/i;

/**
 * Leased / sub-allocated space. Each signal adds independent evidence; confidence = 1 − Π(1 − w).
 * Signals: registrant differs from the announcing ASN, recent sub-allocation, IP-broker contacts,
 * and space registered in another RIR / country than the ASN that announces it.
 */
export function detectLease({ rdap, holder, sourcesOrgs = [], asRir = null, asCountry = null, geoCountry = null }) {
  if (!rdap) return null;
  const reasons = []; const weights = [];
  const orgName = rdap.orgName || rdap.netname;
  const holderTokens = tokens(holder);
  const overlap = [...tokens(orgName)].some(word => holderTokens.has(word));
  const subAllocated = /SUB-ALLOCATED|ASSIGNED PA|REASSIGNED|REALLOCATED|ALLOCATED-BY-LIR/i.test(rdap.status || '');
  const ageDays = rdap.regDate ? (Date.now() - Date.parse(rdap.regDate)) / 864e5 : null;
  const recent = ageDays !== null && ageDays < 3 * 365;
  const brokerText = [rdap.abuseName, rdap.abuseEmail, rdap.netname, rdap.orgName, ...sourcesOrgs].filter(Boolean).join(' ');
  const broker = BROKERS.test(brokerText);
  const signal = (weight, reason) => { weights.push(weight); reasons.push(reason); };
  if (orgName && holder && !overlap && subAllocated) signal(0.4, `地址段登记给 ${orgName}，与宣告方 ${holder} 不同`);
  if (recent && subAllocated) signal(0.25, `${rdap.regDate.slice(0, 10)} 才登记的子分配`);
  if (broker) signal(0.6, `管理方为 IP 租赁平台（${brokerText.match(BROKERS)[0]}）`);
  const ipRir = rdap.rir ? rdap.rir.toUpperCase() : null;
  if (ipRir && asRir && ipRir !== asRir.toUpperCase()) signal(0.35, `地址段属于 ${ipRir}，宣告它的 ASN 属于 ${asRir.toUpperCase()}`);
  else if (rdap.regCountry && asCountry && geoCountry && rdap.regCountry !== asCountry && rdap.regCountry !== geoCountry) {
    signal(0.25, `地址段登记在 ${rdap.regCountry}，ASN 在 ${asCountry}，定位在 ${geoCountry}`);
  }
  const confidence = Math.round((1 - weights.reduce((acc, weight) => acc * (1 - weight), 1)) * 100) / 100;
  return { leased: confidence >= 0.5, possible: confidence >= 0.3 && confidence < 0.5, confidence, reasons };
}

/** Count IPv4 addresses covered by a route list, merging nested and overlapping prefixes. */
function uniqueSpace(routes) {
  const ranges = routes.map(cidr => {
    const [address, length] = String(cidr).split('/');
    const start = address.split('.').reduce((acc, part) => acc * 256 + Number(part), 0);
    return [start, start + 2 ** (32 - Number(length ?? 32)) - 1];
  }).filter(([start, end]) => Number.isFinite(start) && Number.isFinite(end)).sort((a, b) => a[0] - b[0]);
  let total = 0; let reach = -1;
  for (const [start, end] of ranges) {
    if (end <= reach) continue;
    total += end - Math.max(start, reach + 1) + 1;
    reach = end;
  }
  return total;
}

/** Fetch everything about one ASN. Returns a profile even when some calls fail. */
export async function fetchASN(asn, { signal, prefix, health } = {}) {
  const ripe = (call, params) => getJSON(`https://stat.ripe.net/data/${call}/data.json?${new URLSearchParams({ ...params, sourceapp: 'egress-observatory' })}`, { signal, timeout: 12000 });
  const tasks = {
    overview: ripe('as-overview', { resource: `AS${asn}` }),
    routing: ripe('routing-status', { resource: `AS${asn}` }),
    pdb: getJSON(`https://www.peeringdb.com/api/net?asn=${asn}`, { signal, timeout: 12000 }),
    rdap: getJSON(`https://rdap.org/autnum/${asn}`, { signal, timeout: 12000, init: { headers: { Accept: 'application/rdap+json' } } }),
    rpki: prefix ? ripe('rpki-validation', { resource: `AS${asn}`, prefix }) : Promise.resolve(null),
    radar: health?.routes?.includes('radar') ? getJSON(`${API_BASE}/v1/radar?asn=${asn}`, { signal, timeout: 12000 }) : Promise.resolve(null),
    // Announced IPv4 routes: the ASN's address space for the abuse-density reputation check.
    guide: getJSON(`https://ip.guide/AS${asn}`, { signal, timeout: 15000 }),
  };
  const entries = await Promise.all(Object.entries(tasks).map(async ([key, task]) => [key, await task]));
  const results = Object.fromEntries(entries);
  const profile = { asn, sources: {} };
  for (const [key, result] of entries) profile.sources[key] = result ? (result.ok ? 'ok' : 'error') : 'skip';

  if (results.overview?.ok) profile.holder = text(results.overview.data?.data?.holder);
  if (results.routing?.ok) {
    const data = results.routing.data?.data || {};
    profile.v4ips = num(data.announced_space?.v4?.ips);
    profile.v4prefixes = num(data.announced_space?.v4?.prefixes);
    profile.v6prefixes = num(data.announced_space?.v6?.prefixes);
    profile.visibility = num(data.visibility?.v4?.ris_peers_seeing);
  }
  let routes = results.guide?.ok && Array.isArray(results.guide.data?.routes?.v4) ? results.guide.data.routes.v4 : null;
  if (!routes) {
    const announced = await ripe('announced-prefixes', { resource: `AS${asn}` });
    if (announced.ok) routes = (announced.data?.data?.prefixes || []).map(item => item.prefix).filter(prefix => typeof prefix === 'string' && !prefix.includes(':'));
  }
  if (routes?.length) {
    profile.routes = routes;
    // RIPEstat routing-status occasionally times out; derive the size from the route list instead.
    if (!profile.v4ips) { profile.v4prefixes = routes.length; profile.v4ips = uniqueSpace(routes); }
  }
  if (results.pdb?.ok) {
    const net = results.pdb.data?.data?.[0];
    if (net) profile.pdb = { name: text(net.name), type: text(net.info_type), types: Array.isArray(net.info_types) ? net.info_types : null, traffic: text(net.info_traffic), ratio: text(net.info_ratio), scope: text(net.info_scope), website: text(net.website), created: text(net.created) };
  }
  if (results.rdap?.ok) {
    const data = results.rdap.data || {};
    profile.regDate = text((data.events || []).find(event => event.eventAction === 'registration')?.eventDate);
    profile.asCountry = text(data.country);
    profile.rdapName = text(data.name);
  }
  if (results.rpki?.ok) profile.rpki = text(results.rpki.data?.data?.status);
  if (results.radar?.ok && typeof results.radar.data?.bot === 'number') {
    profile.botShare = results.radar.data.bot;
    profile.radar = results.radar.data;
  }
  return profile;
}
