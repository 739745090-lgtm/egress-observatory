/**
 * Live connection probes. They measure the visitor's own browser and network path, so they only
 * apply when the queried IP is the visitor's current egress.
 */
import { getJSON, parseIP, isPublicIP, sameIP, randomId, countryCode, asnNumber, sleep, zoneOffset } from './util.js';

const traceParse = body => Object.fromEntries(String(body || '').split('\n').map(line => line.split('=')).filter(pair => pair.length === 2).map(([key, value]) => [key.trim(), value.trim()]));

// ---------- egress: what different websites see ----------

export const EGRESS_ENDPOINTS = [
  { id: 'ipify4', name: 'ipify · IPv4', url: 'https://api4.ipify.org?format=json', pick: data => data?.ip },
  { id: 'ipify6', name: 'ipify · IPv6', url: 'https://api6.ipify.org?format=json', pick: data => data?.ip, v6: true },
  { id: 'cloudflare', name: 'Cloudflare', url: 'https://www.cloudflare.com/cdn-cgi/trace', as: 'text', pick: body => traceParse(body).ip },
  { id: 'one', name: '1.1.1.1', url: 'https://1.1.1.1/cdn-cgi/trace', as: 'text', pick: body => traceParse(body).ip },
  { id: 'ipsb', name: 'IP.SB', url: 'https://api.ip.sb/ip', as: 'text', pick: body => String(body || '').trim() },
  { id: 'ipinfo', name: 'IPinfo', url: 'https://ipinfo.io/json', pick: data => data?.ip },
  { id: 'ipip', name: 'IPIP.net（国内站点）', url: 'https://myip.ipip.net/json', pick: data => data?.data?.ip, domestic: true },
];

export async function detectEgress(signal, onUpdate) {
  const results = EGRESS_ENDPOINTS.map(endpoint => ({ id: endpoint.id, name: endpoint.name, domestic: Boolean(endpoint.domestic), status: 'pending', ip: null }));
  await Promise.all(EGRESS_ENDPOINTS.map(async (endpoint, index) => {
    const result = await getJSON(endpoint.url, { signal, timeout: 8000, as: endpoint.as || 'json' });
    const parsed = result.ok ? parseIP(endpoint.pick(result.data)) : null;
    results[index] = { ...results[index], status: parsed && isPublicIP(parsed.ip) ? 'ok' : 'error', ip: parsed?.ip || null, v: parsed?.v || null, ms: result.ms, raw: endpoint.as === 'text' && endpoint.id !== 'ipsb' ? traceParse(result.data) : null };
    onUpdate?.(results);
  }));
  return summarizeEgress(results);
}

export function summarizeEgress(results) {
  const ok = results.filter(item => item.status === 'ok');
  const foreign4 = [...new Set(ok.filter(item => !item.domestic && item.v === 4).map(item => item.ip))];
  const v4 = results.find(item => item.id === 'ipify4' && item.ip)?.ip || ok.find(item => item.v === 4 && !item.domestic)?.ip || null;
  const v6 = results.find(item => item.id === 'ipify6' && item.ip)?.ip || ok.find(item => item.v === 6 && !item.domestic)?.ip || null;
  const domestic = ok.find(item => item.domestic)?.ip || null;
  const domesticDiffers = Boolean(domestic && v4 && !sameIP(domestic, v4) && !sameIP(domestic, v6));
  const split = foreign4.length > 1;
  const trace = results.find(item => item.id === 'cloudflare' && item.raw)?.raw || results.find(item => item.id === 'one' && item.raw)?.raw || null;
  const summary = split ? `不同海外网站看到 ${foreign4.length} 个 IPv4：${foreign4.join('、')}`
    : domesticDiffers ? `国内站点看到 ${domestic}，海外站点看到 ${v4}（分流规则生效）` : `${ok.length} 个网站看到同一出口`;
  return { results, v4, v6, domestic, domesticDiffers, split, summary, trace, ips: [...new Set(ok.map(item => item.ip))] };
}

// ---------- WebRTC ----------

export async function probeWebRTC(egressIPs, signal) {
  if (typeof RTCPeerConnection !== 'function') return { status: 'ok', supported: false, srflx: [], leak: false, summary: '浏览器不支持或已禁用 WebRTC' };
  const candidates = [];
  let pc;
  try {
    pc = new RTCPeerConnection({ iceServers: [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }, { urls: 'stun:stun.cloudflare.com:3478' }] });
    pc.createDataChannel('egress');
    const gathered = new Promise(resolve => {
      pc.onicecandidate = event => { if (event.candidate?.candidate) candidates.push(event.candidate.candidate); else resolve(); };
      pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') resolve(); };
    });
    await pc.setLocalDescription(await pc.createOffer());
    await Promise.race([gathered, sleep(6000), new Promise(resolve => signal?.addEventListener('abort', resolve, { once: true }))]);
  } catch {
    return { status: 'ok', supported: false, srflx: [], leak: false, summary: 'WebRTC 被浏览器或扩展拦截' };
  } finally { try { pc?.close(); } catch { /* closed */ } }
  const srflx = new Set(); const local = new Set(); let mdns = false;
  for (const line of candidates) {
    const parts = line.split(' ');
    const address = parts[4]; const type = parts[parts.indexOf('typ') + 1];
    if (!address) continue;
    if (address.endsWith('.local')) { mdns = true; continue; }
    const parsed = parseIP(address);
    if (!parsed) continue;
    if (type === 'srflx' || type === 'prflx' || (type === 'host' && isPublicIP(parsed.ip))) srflx.add(parsed.ip);
    else if (type === 'host') local.add(parsed.ip);
  }
  const srflxList = [...srflx];
  const leakIPs = srflxList.filter(address => !egressIPs.some(egress => sameIP(egress, address)));
  return {
    status: 'ok', supported: true, srflx: srflxList, leakIPs, leak: leakIPs.length > 0, mdns,
    localIPs: [...local], localExposed: local.size > 0,
    summary: leakIPs.length ? `UDP 出口 ${leakIPs.join('、')} 不同于网页出口` : srflxList.length ? `UDP 出口与网页出口一致（${srflxList.length} 个候选）` : '没有获得公网候选：UDP 不通或 WebRTC 走代理且被阻断',
  };
}

// ---------- DNS resolvers ----------

const PUBLIC_RESOLVER_ASNS = new Set([13335, 15169, 19281, 36692, 42, 34939, 212772, 37963, 45090, 21859, 4808, 20473, 16509, 30607, 203380, 209242]);

export async function probeDNS(signal) {
  const id = randomId(16, '0123456789abcdef');
  const fire = n => getJSON(`https://${n}.${id}.bash.ws/`, { signal, timeout: 4000, as: 'text', init: { mode: 'no-cors' } });
  const edns = getJSON(`https://${randomId(32)}.edns.ip-api.com/json`, { signal, timeout: 8000 });
  await Promise.all([1, 2, 3, 4, 5, 6].map(fire));
  await sleep(1200);
  const [bash, ednsResult] = await Promise.all([getJSON(`https://bash.ws/dnsleak/test/${id}?json`, { signal, timeout: 10000 }), edns]);
  const resolvers = [];
  if (bash.ok && Array.isArray(bash.data)) {
    for (const entry of bash.data) {
      if (entry.type !== 'dns' || !parseIP(entry.ip)) continue;
      resolvers.push({ ip: entry.ip, country: countryCode(entry.country), asn: asnNumber(entry.asn), org: entry.org || String(entry.asn || '').replace(/^AS\d+\s*/, '') || null });
    }
  }
  let ecs = null; let ednsResolver = null;
  if (ednsResult.ok && ednsResult.data?.dns) {
    const geo = String(ednsResult.data.dns.geo || '');
    ednsResolver = { ip: ednsResult.data.dns.ip, country: countryCode(geo.split(' - ')[0]), org: geo.split(' - ')[1] || null };
    if (!resolvers.some(item => sameIP(item.ip, ednsResolver.ip))) resolvers.push({ ...ednsResolver, asn: null });
    if (ednsResult.data.edns?.ip) {
      const ecsGeo = String(ednsResult.data.edns.geo || '');
      ecs = { subnet: ednsResult.data.edns.ip, country: countryCode(ecsGeo.split(' - ')[0]), org: ecsGeo.split(' - ')[1] || null };
    }
  }
  if (!resolvers.length) return { status: 'error', error: 'DNS 探测没有回传结果' };
  return { status: 'ok', resolvers, ecs };
}

/** Classify resolvers against the egress location. */
export function classifyDNS(raw, { country, asn }) {
  if (!raw || raw.status !== 'ok') return raw;
  const kinds = raw.resolvers.map(resolver => {
    let kind;
    if (asn && resolver.asn === asn) kind = 'own';
    else if (country && resolver.country === country) kind = 'same';
    else if (PUBLIC_RESOLVER_ASNS.has(resolver.asn) || /cloudflare|google|quad9|opendns|nextdns|adguard/i.test(resolver.org || '')) kind = 'public';
    else if (resolver.country === 'CN' && country !== 'CN') kind = 'leak-cn';
    else kind = 'leak';
    return { ...resolver, kind };
  });
  const order = ['own', 'same', 'public', 'leak', 'leak-cn'];
  const verdict = country ? kinds.reduce((worst, item) => order.indexOf(item.kind) > order.indexOf(worst) ? item.kind : worst, 'own') : null;
  const countries = [...new Set(kinds.map(item => item.country).filter(Boolean))];
  const summary = { own: '解析器属于出口同一网络', same: `解析器与出口同在 ${country}`, public: `公共 DNS 在 ${countries.join('/')} 解析，出口在 ${country}`, leak: `解析器位于 ${countries.join('/')}，与出口 ${country} 不符`, 'leak-cn': '解析请求从中国大陆发出，暴露真实位置' }[verdict] || '';
  const ecsLeak = Boolean(raw.ecs?.country && country && raw.ecs.country !== country);
  return { ...raw, resolvers: kinds, verdict, summary, ecsLeak, ecsSummary: ecsLeak ? `EDNS 客户端子网 ${raw.ecs.subnet} 位于 ${raw.ecs.country}` : null };
}

// ---------- TCP/IP fingerprint ----------

export async function probeTCP(egressIPs, signal) {
  const result = await getJSON('https://tcpip.incolumitas.com/classify?by_ip=1', { signal, timeout: 10000 });
  if (!result.ok || !result.data?.avg_score_os_class) return { status: 'error', error: result.error || '指纹服务无结果' };
  const data = result.data;
  const ranked = Object.entries(data.avg_score_os_class).sort((a, b) => b[1] - a[1]);
  const [tcpOS, best] = ranked[0] || [];
  const uaOS = data.relay?.ua_os || null;
  const onPath = egressIPs.some(ip => sameIP(ip, data.lookup_ip));
  if (!onPath) {
    return { status: 'ok', tcpOS, best, uaOS, relay: false, osMismatch: false, onPath, lookupIP: data.lookup_ip, summary: `指纹服务看到的是 ${data.lookup_ip}，不是本次检测的出口，结果不计分` };
  }
  const relay = Boolean(data.relay?.flagged);
  const osMismatch = data.os_mismatch === true;
  return {
    status: 'ok', tcpOS, best, perfect: data.perfect_score, uaOS, relay, osMismatch, onPath, lookupIP: data.lookup_ip,
    probability: typeof data.relay?.probability === 'number' ? data.relay.probability : null,
    summary: relay ? `SYN 指纹最像 ${tcpOS}，浏览器是 ${uaOS || '其他系统'}：连接由中间服务器重新发起` : osMismatch ? `SYN 指纹 ${tcpOS} 与浏览器 ${uaOS || '系统'} 不一致` : `SYN 指纹 ${tcpOS || '未知'} 与浏览器一致`,
  };
}

// ---------- local environment ----------

export function probeEnvironment() {
  let zone = null;
  try { zone = Intl.DateTimeFormat().resolvedOptions().timeZone || null; } catch { /* unavailable */ }
  const offset = zone ? zoneOffset(zone) : -new Date().getTimezoneOffset();
  const languages = (navigator.languages?.length ? navigator.languages : [navigator.language]).filter(Boolean).slice(0, 5);
  return { tz: { zone, offset }, lang: { languages } };
}

export async function probeIPv6(v6, target, signal) {
  if (!v6) return { status: 'ok', address: null };
  if (sameIP(v6, target)) return { status: 'ok', address: v6, isTarget: true };
  const result = await getJSON(`https://api.ip.sb/geoip/${encodeURIComponent(v6)}`, { signal, timeout: 8000 });
  if (!result.ok) return { status: 'ok', address: v6, country: null, asn: null, org: null };
  return { status: 'ok', address: v6, country: countryCode(result.data?.country_code), asn: asnNumber(result.data?.asn), org: result.data?.isp || result.data?.organization || null };
}

/** Compare the IPv6 egress with the IPv4 location consensus. */
export function classifyIPv6(raw, summary) {
  if (!raw || raw.status !== 'ok') return raw;
  if (!raw.address) return { ...raw, mismatch: false, summary: '没有 IPv6 出口，网站只能看到 IPv4' };
  if (raw.isTarget) return { ...raw, mismatch: false, summary: '正在检测的就是 IPv6 出口' };
  const mismatch = Boolean(raw.country && summary.country && raw.country !== summary.country);
  return {
    ...raw, mismatch,
    summary: mismatch ? `IPv6 出口在 ${raw.country}（${raw.org || `AS${raw.asn}`}），与 IPv4 出口 ${summary.country} 不同；支持 IPv6 的网站会看到它`
      : `IPv6 出口同在 ${raw.country || '—'}${raw.asn && raw.asn === summary.asn ? '，同一 ASN' : ''}`,
  };
}

export function traceProbe(trace) {
  if (!trace) return null;
  return { status: 'ok', warp: trace.warp || 'off', gateway: trace.gateway || 'off', colo: trace.colo || null, loc: trace.loc || null, http: trace.http || null, tls: trace.tls || null };
}
