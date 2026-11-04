/**
 * DNS blocklists over DNS-over-HTTPS, plus downloadable CIDR threat / datacenter lists used three ways:
 * the IP itself, its /24 neighbours, and the abuse density of its whole ASN.
 * Spamhaus refuses public resolvers, so it is deliberately absent rather than shown as "clean".
 */
import { getJSON, reverseName, parseIP, ipToBigInt } from './util.js';

// kind: mail = spam reputation, abuse = attacks / brute force, proxy = open proxies & drones, tor = Tor exits.
export const DNSBLS = [
  { id: 'spamcop', name: 'SpamCop', zone: 'bl.spamcop.net', kind: 'mail', site: () => 'https://www.spamcop.net/bl.shtml' },
  { id: 'barracuda', name: 'Barracuda', zone: 'b.barracudacentral.org', kind: 'mail', site: () => 'https://www.barracudacentral.org/lookups' },
  { id: 'psbl', name: 'PSBL', zone: 'psbl.surriel.com', kind: 'mail', site: ip => `https://psbl.org/listing?ip=${ip}` },
  { id: 'mailspike', name: 'Mailspike', zone: 'bl.mailspike.net', kind: 'mail', site: () => 'https://mailspike.org/iplookup.html' },
  { id: 'uceprotect', name: 'UCEPROTECT L1', zone: 'dnsbl-1.uceprotect.net', kind: 'mail', site: ip => `https://www.uceprotect.net/en/rblcheck.php?ipr=${ip}` },
  { id: 'gbudb', name: 'GBUdb Truncate', zone: 'truncate.gbudb.net', kind: 'mail', site: () => 'https://www.gbudb.com/truncate/' },
  { id: 'nordspam', name: 'NordSpam', zone: 'bl.nordspam.com', kind: 'mail', site: () => 'https://www.nordspam.com/' },
  { id: 'justspam', name: 'JustSpam', zone: 'dnsbl.justspam.org', kind: 'mail', site: () => 'http://www.justspam.org/' },
  { id: 'sem', name: 'SpamEatingMonkey', zone: 'bl.spameatingmonkey.net', kind: 'mail', site: () => 'https://spameatingmonkey.com/' },
  { id: 'spfbl', name: 'SPFBL', zone: 'dnsbl.spfbl.net', kind: 'mail', ignore: ['127.0.0.4'], site: ip => `https://spfbl.net/en/dnsbl/${ip}` },
  { id: 'zerospam', name: '0spam', zone: 'bl.0spam.org', kind: 'mail', site: () => 'https://0spam.org/' },
  { id: 'interserver', name: 'InterServer', zone: 'rbl.interserver.net', kind: 'abuse', site: ip => `https://rbl.interserver.net/ip-lookup?ip=${ip}` },
  { id: 'blocklistde', name: 'blocklist.de', zone: 'bl.blocklist.de', kind: 'abuse', site: ip => `https://www.blocklist.de/en/search.html?ip=${ip}` },
  { id: 's5h', name: 'S5H', zone: 'all.s5h.net', kind: 'abuse', site: () => 'https://www.usenix.org.uk/content/rbl.html' },
  // DroneBL return codes 8–11, 14, 19 are proxy / VPN classes; others are bots, scanners and compromised hosts.
  { id: 'dronebl', name: 'DroneBL', zone: 'dnsbl.dronebl.org', kind: 'abuse', proxyCodes: [8, 9, 10, 11, 14, 19], site: ip => `https://dronebl.org/lookup?ip=${ip}` },
  { id: 'dantor', name: 'dan.me.uk Tor', zone: 'torexit.dan.me.uk', kind: 'tor', site: () => 'https://www.dan.me.uk/dnsbl' },
];

const RESOLVERS = [
  name => `https://dns.google/resolve?name=${name}&type=A`,
  name => `https://cloudflare-dns.com/dns-query?name=${name}&type=A`,
];

async function resolveA(name, signal) {
  for (const resolver of RESOLVERS) {
    const result = await getJSON(resolver(name), { signal, timeout: 8000, init: { headers: { Accept: 'application/dns-json' } } });
    if (!result.ok || typeof result.data?.Status !== 'number') continue;
    if (result.data.Status === 3) return { ok: true, answers: [] };          // NXDOMAIN: not listed
    if (result.data.Status !== 0) continue;                                  // SERVFAIL / REFUSED: try next resolver
    return { ok: true, answers: (result.data.Answer || []).filter(answer => answer.type === 1).map(answer => answer.data) };
  }
  return { ok: false };
}

export async function checkDNSBL(list, ip, signal) {
  const parsed = parseIP(ip);
  if (parsed.v === 6 && list.zone !== 'torexit.dan.me.uk') return { status: 'skip', error: '仅支持 IPv4' };
  const result = await resolveA(`${reverseName(ip)}.${list.zone}`, signal);
  if (!result.ok) return { status: 'error', error: '解析失败' };
  // 127.255.255.x and 127.0.0.1 are refusal / test markers, not listings.
  const codes = result.answers.filter(address => address.startsWith('127.') && !address.startsWith('127.255.') && address !== '127.0.0.1' && !(list.ignore || []).includes(address));
  const last = codes.map(code => Number(code.split('.')[3]));
  return { status: 'ok', listed: codes.length > 0, codes, proxy: Boolean(list.proxyCodes && last.some(code => list.proxyCodes.includes(code))) };
}

// ---------- CIDR lists (IPv4) ----------
// kind: attack / spam lists count against the IP, its /24 neighbours and its ASN; datacenter / vpn only describe type.
// density: address-level lists, used for the ASN abuse-density comparison.

const FIREHOL = name => `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/${name}`;
const IPLIST = name => `https://iplists.firehol.org/?ipset=${name}`;
export const CIDR_LISTS = [
  { id: 'firehol1', name: 'FireHOL Level 1', kind: 'attack', pts: 15, url: FIREHOL('firehol_level1.netset'), site: () => IPLIST('firehol_level1'), note: '高置信攻击源，含 Spamhaus DROP 劫持 / 犯罪网段' },
  { id: 'firehol2', name: 'FireHOL Level 2', kind: 'attack', pts: 10, url: FIREHOL('firehol_level2.netset'), site: () => IPLIST('firehol_level2'), note: '近 48 小时的攻击与扫描' },
  { id: 'firehol3', name: 'FireHOL Level 3', kind: 'attack', pts: 6, url: FIREHOL('firehol_level3.netset'), site: () => IPLIST('firehol_level3'), note: '近 30 天的攻击、垃圾与恶意软件' },
  { id: 'blocklistde', name: 'blocklist.de', kind: 'attack', pts: 10, density: true, url: FIREHOL('blocklist_de.ipset'), site: () => IPLIST('blocklist_de'), note: '近 48 小时对 SSH、邮件、Web 的暴力破解与攻击' },
  { id: 'greensnow', name: 'GreenSnow', kind: 'attack', pts: 8, density: true, url: FIREHOL('greensnow.ipset'), site: () => IPLIST('greensnow'), note: '扫描与暴力破解' },
  { id: 'cybercrime', name: 'CyberCrime C&C', kind: 'attack', pts: 15, density: true, url: FIREHOL('cybercrime.ipset'), site: () => IPLIST('cybercrime'), note: '恶意软件控制服务器' },
  { id: 'sfs7d', name: 'StopForumSpam 7 天', kind: 'spam', pts: 0, density: true, url: FIREHOL('stopforumspam_7d.ipset'), site: () => IPLIST('stopforumspam_7d'), note: '近 7 天的垃圾注册；本 IP 自身由 StopForumSpam 接口计分' },
  { id: 'dshield', name: 'DShield 攻击网段', kind: 'attack', pts: 0, url: FIREHOL('dshield_7d.netset'), site: () => IPLIST('dshield_7d'), note: '近 7 天攻击最多的 /24 网段' },
  { id: 'ipsum3', name: 'IPsum ≥3 黑名单', kind: 'attack', pts: 8, url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt', site: () => 'https://github.com/stamparm/ipsum', note: '同时出现在至少 3 个公开黑名单（共约 30 个）' },
  { id: 'etcompromised', name: 'ET 已入侵主机', kind: 'attack', pts: 10, density: true, url: FIREHOL('et_compromised.ipset'), site: () => IPLIST('et_compromised'), note: 'Emerging Threats 已知被入侵的主机' },
  { id: 'ciarmy', name: 'CINS Army', kind: 'attack', pts: 8, density: true, url: FIREHOL('ciarmy.ipset'), site: () => IPLIST('ciarmy'), note: 'CINS 哨兵网络观测到的恶意来源' },
  { id: 'botscout', name: 'BotScout 7 天', kind: 'spam', pts: 6, density: true, url: FIREHOL('botscout_7d.ipset'), site: () => IPLIST('botscout_7d'), note: '近 7 天在表单里注册垃圾账号的机器人' },
  { id: 'socksproxy', name: '公开 SOCKS 代理', kind: 'proxy', url: FIREHOL('socks_proxy_7d.ipset'), site: () => IPLIST('socks_proxy_7d'), note: '近 7 天出现在公开 SOCKS 代理列表' },
  { id: 'sslproxy', name: '公开 HTTPS 代理', kind: 'proxy', url: FIREHOL('sslproxies_7d.ipset'), site: () => IPLIST('sslproxies_7d'), note: '近 7 天出现在公开 HTTPS 代理列表' },
  { id: 'torexits', name: 'Tor 出口（FireHOL）', kind: 'tor', url: FIREHOL('tor_exits.ipset'), site: () => IPLIST('tor_exits'), note: 'Tor 出口节点' },
  { id: 'x4bdc', name: 'X4BNet 机房段', kind: 'datacenter', url: 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt', site: () => 'https://github.com/X4BNet/lists_vpn' },
  { id: 'x4bvpn', name: 'X4BNet VPN 段', kind: 'vpn', url: 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt', site: () => 'https://github.com/X4BNet/lists_vpn' },
];

const cache = new Map();
const toIP = number => [24, 16, 8, 0].map(shift => Math.floor(number / 2 ** shift) % 256).join('.');
const ipValue = parts => parts.reduce((acc, part) => acc * 256 + Number(part), 0);

/** Parse a netset into sorted [start, end] uint32 ranges. */
function parseRanges(body) {
  const ranges = [];
  for (const line of body.split('\n')) {
    const entry = line.trim();
    if (!entry || entry.startsWith('#')) continue;
    const [address, lengthText] = entry.split('/');
    const parts = address.split('.');
    if (parts.length !== 4) continue;
    const start = ipValue(parts);
    const length = lengthText === undefined ? 32 : Number(lengthText);
    if (!Number.isFinite(start) || !(length >= 0 && length <= 32)) continue;
    const size = 2 ** (32 - length);
    const base = Math.floor(start / size) * size;
    ranges.push([base, base + size - 1]);
  }
  return ranges.sort((a, b) => a[0] - b[0]);
}

function lastStartAtOrBefore(ranges, value) {
  let low = 0; let high = ranges.length - 1; let index = -1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    if (ranges[mid][0] <= value) { index = mid; low = mid + 1; } else high = mid - 1;
  }
  return index;
}

/** All ranges intersecting [a, b]. Ranges may nest, so look a little further back than the first start < a. */
function intersecting(ranges, a, b) {
  const out = [];
  for (let i = lastStartAtOrBefore(ranges, b), behind = 0; i >= 0 && behind < 64; i -= 1) {
    if (ranges[i][0] < a) behind += 1;
    if (ranges[i][1] >= a) out.push(ranges[i]);
  }
  return out;
}

export function loadList(list, signal) {
  if (!cache.has(list.id)) {
    cache.set(list.id, getJSON(list.url, { signal, timeout: 25000, as: 'text', init: { cache: 'default' } })
      .then(result => { if (!result.ok) { cache.delete(list.id); return null; } return parseRanges(result.data); }));
  }
  return cache.get(list.id);
}

/** The IP itself, plus its /24: other listed addresses, and whether the whole /24 (or a larger block) is listed. */
export async function checkCIDRList(list, ip, signal) {
  const parsed = parseIP(ip);
  if (parsed.v !== 4) return { status: 'skip', error: '仅收录 IPv4' };
  const ranges = await loadList(list, signal);
  if (!ranges) return { status: 'error', error: '列表下载失败' };
  const value = Number(ipToBigInt(parsed).value);
  const hit = intersecting(ranges, value, value)[0] || null;
  const block = Math.floor(value / 256) * 256;
  const neighbours = new Set(); let whole = false;
  for (const [start, end] of intersecting(ranges, block, block + 255)) {
    if (start <= block && end >= block + 255) { whole = true; continue; }
    for (let address = Math.max(start, block); address <= Math.min(end, block + 255); address += 1) if (address !== value) neighbours.add(address);
  }
  return {
    status: 'ok', listed: Boolean(hit), match: hit ? `${toIP(hit[0])} – ${toIP(hit[1])}` : null, size: ranges.length,
    neighbours: { prefix: `${toIP(block)}/24`, ips: [...neighbours].map(toIP), whole },
  };
}

/** Number of addresses of `ranges` inside the merged, sorted `space` (two-pointer walk). */
function overlapCount(ranges, space) {
  let total = 0; let j = 0;
  for (const [start, end] of ranges) {
    while (j < space.length && space[j][1] < start) j += 1;
    for (let k = j; k < space.length && space[k][0] <= end; k += 1) total += Math.min(end, space[k][1]) - Math.max(start, space[k][0]) + 1;
  }
  return total;
}

export function mergeRoutes(routes) {
  const ranges = (routes || []).map(cidr => {
    const [address, length] = String(cidr).split('/');
    const parts = address.split('.');
    if (parts.length !== 4) return null;
    const size = 2 ** (32 - Number(length ?? 32));
    const start = Math.floor(ipValue(parts) / size) * size;
    return Number.isFinite(start) ? [start, start + size - 1] : null;
  }).filter(Boolean).sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const range of ranges) {
    const previous = merged[merged.length - 1];
    if (previous && range[0] <= previous[1] + 1) previous[1] = Math.max(previous[1], range[1]);
    else merged.push([...range]);
  }
  return merged;
}

// Routed IPv4 space, the "whole internet" baseline for listing density.
const ROUTED_IPV4 = 3.0e9;

/**
 * ASN reputation: how many addresses in the ASN's announced IPv4 space sit on the address-level
 * threat lists, compared with the same lists' density across all routed space (ratio 1 = average).
 */
export async function asnAbuseDensity(routes, signal) {
  const space = mergeRoutes(routes);
  const size = space.reduce((sum, [start, end]) => sum + end - start + 1, 0);
  if (!size) return null;
  const lists = CIDR_LISTS.filter(list => list.density);
  const loaded = await Promise.all(lists.map(list => loadList(list, signal)));
  const counts = {}; let listed = 0; let global = 0;
  lists.forEach((list, index) => {
    const ranges = loaded[index];
    if (!ranges) return;
    const count = overlapCount(ranges, space);
    counts[list.name] = count; listed += count;
    global += ranges.reduce((sum, [start, end]) => sum + end - start + 1, 0);
  });
  if (!global) return null;
  const per10k = listed / size * 1e4;
  const baseline = global / ROUTED_IPV4 * 1e4;
  return { size, listed, counts, per10k: Math.round(per10k * 100) / 100, baseline: Math.round(baseline * 1000) / 1000, ratio: Math.round(per10k / baseline * 10) / 10 };
}
