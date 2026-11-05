import { lookupIPOK, fillSource } from './supplements.js';
import { readIPinfoPage, mergeIPinfoPage } from './ipinfo-page.js?v=3.4';
import { setupImport, supplementTypes, readReport } from './ipsuper.js?v=3.1';
/** Orchestration: detect the egress, fan out every check, rescore as results arrive. */
import { API_BASE, PAGE_LOOKUP_BASE, PAGE_LOOKUP_CLOUD } from '../config.js?v=cloud1';
import { getJSON, parseIP, isPublicIP, sameIP, maskIP } from './util.js';
import { SOURCES, runSource } from './sources.js?v=3.2';
import { DNSBLS, checkDNSBL, CIDR_LISTS, checkCIDRList, asnAbuseDensity } from './blocklists.js';
import { fetchASN, inferASN, detectLease } from './asn.js';
import { detectEgress, summarizeEgress, probeWebRTC, probeDNS, classifyDNS, probeTCP, probeEnvironment, probeIPv6, classifyIPv6, traceProbe } from './probes.js';
import { runTurnstile, runRecaptcha } from './captcha.js';
import { score } from './score.js';
import * as view from './render.js?v=cloud2';

const $ = id => document.getElementById(id);
const app = {
  masked: localStorage.getItem('egress-mask') === '1',
  egress: null, egressPromise: null, health: null, healthPromise: null, run: null, frame: 0,
};

// ---------- backend capabilities ----------

app.healthPromise = Promise.race([
  getJSON(`${API_BASE}/health`, { timeout: 6000 }).then(result => {
    if (!result.ok) return null;
    // Older deployments list `providers`; newer ones list every enabled `routes` entry.
    const routes = result.data.routes || result.data.providers || [];
    return { ...result.data, routes };
  }),
  new Promise(resolve => setTimeout(() => resolve(null), 6500)),
]).then(health => { app.health = health; return health; });

// ---------- evidence & scoring ----------

/** Same-/24 neighbours across the threat lists, Tor relays next door, and AbuseIPDB block reports. */
function neighbourSummary(run) {
  if (run.v !== 4) return null;
  const ips = new Set(); const lists = []; const whole = [];
  let prefix = null; let checked = 0;
  for (const item of run.lists) {
    if (item.status !== 'ok' || !['attack', 'spam', 'proxy'].includes(item.kind) || !item.neighbours) continue;
    checked += 1; prefix = item.neighbours.prefix;
    if (item.neighbours.whole) whole.push(item.name);
    if (item.neighbours.ips.length) { lists.push(`${item.name} ${item.neighbours.ips.length}`); item.neighbours.ips.forEach(ip => ips.add(ip)); }
  }
  const tor = run.sources.onionoo?.status === 'ok' ? run.sources.onionoo.data.neighbourRelays || 0 : 0;
  const block = run.sources.abuseipdb?.status === 'ok' ? run.sources.abuseipdb.data.block : null;
  if (!checked && !block) return null;
  return { prefix: prefix || block?.prefix || null, count: Math.max(ips.size, block?.reported || 0), sample: [...ips].slice(0, 6), lists, whole, tor, abuseipdb: block, checked };
}

function majorityCountry(run) {
  const counts = new Map();
  for (const record of Object.values(run.sources)) {
    const code = record.status === 'ok' && record.data.geoVote !== false ? record.data.country : null;
    if (code) counts.set(code, (counts.get(code) || 0) + 1);
  }
  return [...counts].sort((a, b) => b[1] - a[1])[0]?.[0] || null;
}

function buildEvidence(run) {
  const sources = Object.fromEntries(Object.entries(run.sources).map(([id, record]) => [id, { ...record, name: SOURCES.find(source => source.id === id)?.name || id }]));
  const extraVotes = { vpn: [], proxy: [], tor: [], hosting: [], abuser: [] };
  for (const item of run.dnsbl) {
    if (item.status !== 'ok') continue;
    if (item.id === 'dantor') extraVotes.tor.push({ by: 'dan.me.uk', value: item.listed, w: item.listed ? 0.95 : 0.3, hard: item.listed });
    if (item.proxy) extraVotes.proxy.push({ by: 'DroneBL', value: true, w: 0.9, obs: true });
  }
  for (const item of run.lists) {
    if (item.status !== 'ok') continue;
    if (item.id === 'x4bdc') extraVotes.hosting.push({ by: 'X4BNet 机房段', value: item.listed, w: item.listed ? 0.7 : 0.25 });
    if (item.id === 'x4bvpn') extraVotes.vpn.push({ by: 'X4BNet VPN 段', value: item.listed, w: item.listed ? 0.7 : 0.2 });
    // Public proxy and Tor lists are direct observations of the service running on this address.
    if (item.kind === 'proxy' && item.listed) extraVotes.proxy.push({ by: item.name, value: true, w: 0.85, obs: true });
    if (item.kind === 'tor') extraVotes.tor.push({ by: item.name, value: item.listed, w: item.listed ? 1 : 0.3, hard: item.listed });
  }
  const trace = run.self ? run.probes.trace : null;
  if (trace && trace.warp !== 'off') extraVotes.vpn.push({ by: 'Cloudflare WARP', value: true, w: 1, hard: true });

  if (run.asn) {
    const data = id => run.sources[id]?.status === 'ok' ? run.sources[id].data : null;
    const names = [run.asn.holder, run.asn.pdb?.name, run.asn.rdapName, data('ipguide')?.asName, data('ipguide')?.org, data('ripeprefix')?.asName];
    run.asnProfile = {
      ...run.asn,
      inferred: inferASN({ asn: run.asn.asn, names, pdb: run.asn.pdb, v4ips: run.asn.v4ips, botShare: run.asn.botShare, ipapiType: data('ipapiis')?.asnType, ipinfoType: data('ipinfo')?.asnType, regDate: run.asn.regDate,
        companyTypes: Object.entries(run.sources).filter(([, record]) => record.status === 'ok' && record.data.companyType).map(([id, record]) => ({ by: SOURCES.find(source => source.id === id)?.name || id, value: record.data.companyType })) }),
      lease: detectLease({
        rdap: data('rdap'), holder: run.asn.holder || data('ipguide')?.org, sourcesOrgs: [data('ipwhois')?.domain, data('ipapiis')?.companyDomain],
        asRir: data('ipguide')?.rir, asCountry: run.asn.asCountry || data('ipguide')?.asCountry, geoCountry: majorityCountry(run),
      }),
      label: run.asn.holder ? run.asn.holder.split(' - ').pop() : `AS${run.asn.asn}`,
    };
  }
  return {
    ip: run.ip, v: run.v, self: run.self, sources, dnsbl: run.dnsbl, lists: run.lists, extraVotes,
    asn: run.asnProfile || null, asnRep: run.asnRep || null, neighbours: neighbourSummary(run),
    probes: run.self ? {
      webrtc: run.probes.webrtc, tcp: run.probes.tcp, tz: run.probes.env?.tz, lang: run.probes.env?.lang,
      egress: app.egress, turnstile: run.probes.turnstile, recaptcha: run.probes.recaptcha,
    } : {},
  };
}

function compute(run) {
  const evidence = buildEvidence(run);
  const first = score(evidence);
  if (run.self) {
    // Second pass: DNS and IPv6 are judged against the location consensus from the first pass.
    run.probes.dnsClassified = classifyDNS(run.probes.dns, first.summary);
    run.probes.ipv6Classified = classifyIPv6(run.probes.ipv6, first.summary);
    evidence.probes.dns = run.probes.dnsClassified;
    evidence.probes.ipv6 = run.probes.ipv6Classified;
    return score(evidence);
  }
  return first;
}

function scheduleRender() {
  if (app.frame) return;
  // Hidden or occluded windows stop delivering animation frames (document.hidden can still be false),
  // so race the next frame against a short timer; whichever comes first renders.
  let done = false;
  const defer = callback => {
    const once = () => { if (!done) { done = true; callback(); } };
    requestAnimationFrame(once);
    setTimeout(once, 120);
    return 1;
  };
  app.frame = defer(() => {
    app.frame = 0;
    const run = app.run;
    if (!run) return;
    const result = compute(run);
    run.result = result;
    document.body.classList.add('has-result');
    view.renderHero(run, result, app);
    view.renderChecks(run, result);
    view.renderUses(result);
    view.renderLive(run, result, app.egress, app);
    view.renderASN(run, result);
    view.renderBreakdown(run, result);
    view.renderTypes(run);
    view.renderGeo(run, result);
    view.renderSources(run);
    view.renderProgress(run, result);
    view.renderEgress(app.egress, run, app);
    view.applyMask(app.masked);
    view.refreshTip();
  });
}

// ---------- a single check ----------

async function startRun(input, fetchPages = true) {
  const parsed = parseIP(input);
  if (!parsed || !isPublicIP(parsed.ip)) { $('status').textContent = '请输入有效的公网 IPv4 或 IPv6 地址。'; return; }
  app.run?.controller.abort();
  const controller = new AbortController();
  const signal = controller.signal;
  const egress = app.egress || await Promise.race([app.egressPromise, new Promise(resolve => setTimeout(resolve, 4000))]) || app.egress;
  const self = Boolean(egress?.ips?.some(ip => sameIP(ip, parsed.ip)));
  const run = {
    ip: parsed.ip, v: parsed.v, self, controller, startedAt: Date.now(),
    sources: {}, dnsbl: [], lists: [], asn: null, asnProfile: null, probes: {}, result: null,
  };
  app.run = run;
  $('ip-input').value = parsed.ip;
  const url = new URL(location.href);
  if (self) url.searchParams.delete('ip'); else url.searchParams.set('ip', parsed.ip);
  history.replaceState(null, '', url);
  view.crossLinks(parsed.ip);
  $('ipinfo-page-link').href = 'https://ipinfo.io/' + encodeURIComponent(parsed.ip);
  $('ipinfo-message').textContent = '';
  $('ipsuper-query').href = 'https://ipsuper.com/?ip=' + encodeURIComponent(parsed.ip);

  const ctx = { signal, healthReady: app.healthPromise, sourceReady: new Map() };
  const active = SOURCES.filter(source => !source.selfOnly || self);
  for (const source of active) run.sources[source.id] = { status: 'pending' };
  run.dnsbl = DNSBLS.map(list => ({ id: list.id, name: list.name, kind: list.kind, status: 'pending' }));
  run.lists = CIDR_LISTS.map(list => ({ id: list.id, name: list.name, kind: list.kind, pts: list.pts, status: 'pending' }));
  scheduleRender();

  const alive = () => app.run === run && !signal.aborted;
  let asnStarted = false;
  const maybeASN = () => {
    if (asnStarted) return;
    const order = ['ripeprefix', 'ipguide', 'ipinfo', 'proxycheck', 'ipwhois', 'ipsb', 'ipleak', 'geojs', 'netatlas'];
    const asn = order.map(id => run.sources[id]?.status === 'ok' ? run.sources[id].data.asn : null).find(Boolean);
    if (!asn) return;
    asnStarted = true;
    const prefix = run.sources.ripeprefix?.data?.prefix || run.sources.ipguide?.data?.prefix || run.sources.netatlas?.data?.prefix || null;
    app.healthPromise.then(health => fetchASN(asn, { signal, prefix, health })).then(profile => {
      if (!alive()) return;
      run.asn = profile; scheduleRender();
      if (profile.routes?.length) asnAbuseDensity(profile.routes, signal).then(rep => { if (alive() && rep) { run.asnRep = rep; scheduleRender(); } });
    });
  };

  let webTypes = importedTypes;
  let ipokRows = {};
  let ipsuperRisk = {};
  const records = new Map();
  function refreshTypes() {
    const abuse = records.get('abuseipdb')?.data;
    for (const [id, record] of records) {
      let data = id === 'ipinfo' ? mergeIPinfoPage(record, run.ipinfoPage) : record;
      if (id === 'ipinfo' && !data.data?.usageType && abuse?.usageType) {
        const d = {...data.data, flags:data.data?.flags || {}, usageType:abuse.usageType, type:data.data?.type || abuse.usageType, usageVia:'AbuseIPDB'};
        data = {...data,status:'ok',directStatus:data.status,error:null,data:d};
      }
      const atlas = records.get('netatlas')?.data;
      if (id === 'dbip' && atlas?.locationDatabase === 'DB-IP City Lite') {
        data = fillSource(data, {country:atlas.country,city:atlas.city,region:atlas.region}, 'DB-IP City Lite，经 Net Atlas 转供');
      }
      const namedRisk = ipsuperRisk[{ipqs:'IPQualityScore', scamalytics:'Scamalytics', dbip:'DBIP'}[id]];
      if (Number.isFinite(namedRisk) && namedRisk >= 0 && namedRisk <= 100 && data.data?.risk == null) {
        data = fillSource(data, {webRiskPercent:namedRisk}, 'IPSuper 网页逐库风险百分比，仅展示');
      }
      const row = ipokRows[id];
      if (row && !row.unavailable && record.status !== 'ok') {
        data = fillSource(data, {flags:row.flags, webRiskPercent:row.percent}, 'IPOK 逐库观察'+(row.observedAt ? ' · '+row.observedAt : ''));
      }
      data = supplementTypes(data, webTypes(parsed.ip, id));
      if (row?.unavailable && data.status !== 'ok') data = {...data,error:'网页来源暂缺 · '+row.reason};
      run.sources[id] = data;
    }
  }
  const pageStatus = $('auto-page-status');
  pageStatus.textContent = '';
  if (fetchPages) {
    lookupIPOK(parsed.ip, signal).then(rows => {
      if (!alive()) return;
      ipokRows = rows; refreshTypes(); scheduleRender();
    }).catch(error => {
      if (!alive()) return;
      ipokRows = Object.fromEntries(['iphub','vpnapi','scamalytics','ipqs'].map(id => [id,{unavailable:true,reason:error.message}]));
      refreshTypes(); scheduleRender();
    });
    const statuses = {ipinfo:'IPinfo 查询中', ipsuper:'IPSuper 查询中'};
    pageStatus.textContent = Object.values(statuses).join(' · ');
    for (const provider of Object.keys(statuses)) {
      const name = provider === 'ipinfo' ? 'IPinfo' : 'IPSuper';
      fetch(PAGE_LOOKUP_BASE + '/lookup/' + provider, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:parsed.ip}),signal:AbortSignal.any([signal,AbortSignal.timeout(150000)])})
        .then(async response => {
          const report = await response.json();
          if (!response.ok) throw Error(report.error || '网页查询失败');
          if (!alive()) return;
          if (!sameIP(report.ip, parsed.ip)) throw Error('返回的 IP 不匹配');
          if (provider === 'ipinfo') {
            run.ipinfoPage = readIPinfoPage(report.text, parsed.ip);
            const d = run.ipinfoPage;
            statuses.ipinfo = ['IPinfo 网页已读取', d.companyName, d.asnType && 'ASN 类型 '+d.asnType,
              typeof d.flags.hosting === 'boolean' && (d.flags.hosting ? '机房检出' : '机房未检出')].filter(Boolean).join(' · ');
          } else {
            webTypes = readReport(report, parsed.ip);
            ipsuperRisk = report.riskPercent || {};
            run.ipsuperReturned = SOURCES.filter(source => webTypes(parsed.ip, source.id)).map(source => source.id);
            statuses.ipsuper = 'IPSuper 网页已读取';
          }
          refreshTypes(); scheduleRender();
        }).catch(error => {statuses[provider] = name+'：'+(error instanceof TypeError ? '线上网页查询服务连接失败' : error.message);})
        .finally(() => { if (alive()) pageStatus.textContent = Object.values(statuses).join(' ｜ '); });
    }
  }
  const tasks = [];
  for (const source of active) {
    const sourceTask = runSource(source, parsed.ip, ctx);
    ctx.sourceReady.set(source.id, sourceTask);
    tasks.push(sourceTask.then(async result => {
      if (!alive()) return;
      if (fetchPages && source.id === 'getipintel' && result.status !== 'ok') {
        try {
          const response = await fetch(PAGE_LOOKUP_CLOUD + '/lookup/getipintel', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:parsed.ip}),signal:AbortSignal.any([signal,AbortSignal.timeout(130000)])});
          const answer = await response.json();
          if (response.ok && sameIP(answer.ip,parsed.ip) && Number.isFinite(answer.probability) && answer.probability>=0 && answer.probability<=1) {
            result = fillSource(result,{probability:answer.probability,risk:answer.risk},'GetIPIntel 官方免费接口');
          } else if (answer.error) result = {...result,error:answer.error};
        } catch { /* Retain the first route's concrete failure. */ }
      }
      if (!alive()) return;
      records.set(source.id, result);
      refreshTypes();
      if (['ripeprefix', 'ipguide'].includes(source.id) || run.sources.ripeprefix?.status !== 'pending') maybeASN();
      scheduleRender();
    }));
  }
  // If the routing sources fail, fall back to any ASN once everything has answered.
  Promise.all(tasks).then(() => { if (alive() && !asnStarted) { maybeASN(); scheduleRender(); } });

  run.dnsbl.forEach((item, index) => {
    checkDNSBL(DNSBLS[index], parsed.ip, signal).then(result => { if (alive()) { run.dnsbl[index] = { ...item, ...result }; scheduleRender(); } });
  });
  run.lists.forEach((item, index) => {
    checkCIDRList(CIDR_LISTS[index], parsed.ip, signal).then(result => { if (alive()) { run.lists[index] = { ...item, ...result }; scheduleRender(); } });
  });

  if (self) runProbes(run, signal, alive);
}

async function runProbes(run, signal, alive) {
  const update = (key, value) => { if (alive()) { run.probes[key] = value; scheduleRender(); } };
  update('env', probeEnvironment());
  probeDNS(signal).then(value => update('dns', value));
  runCaptcha(run, 'turnstile', alive);
  runCaptcha(run, 'recaptcha', alive);
  // Probes that compare against "all of your exits" need the complete egress list.
  const egress = await app.egressPromise;
  if (!alive()) return;
  const egressIPs = egress?.ips?.length ? egress.ips : [run.ip];
  update('trace', traceProbe(egress?.trace));
  probeWebRTC(egressIPs, signal).then(value => update('webrtc', value));
  probeTCP(egressIPs, signal).then(value => update('tcp', value));
  probeIPv6(run.v === 4 ? egress?.v6 : egress?.v4, run.ip, signal).then(value => update('ipv6', value));
}

async function runCaptcha(run, kind, alive = () => app.run === run) {
  run.probes[kind] = null; scheduleRender();
  const health = await app.healthPromise;
  const value = kind === 'turnstile' ? await runTurnstile($('turnstile-slot'), health) : await runRecaptcha(health);
  if (alive()) { run.probes[kind] = value; scheduleRender(); }
}

// ---------- page wiring ----------

function exportReport() {
  const run = app.run;
  if (!run?.result) return;
  const hide = value => app.masked && typeof value === 'string' ? value.split(run.ip).join('[hidden]') : value;
  const report = {
    schema: 'egress-report/v3', exportedAt: new Date().toISOString(), ip: app.masked ? maskIP(run.ip) : run.ip, self: run.self,
    score: run.result.score, ipScore: run.result.ipScore, grade: run.result.grade, verdict: run.result.verdict,
    categories: run.result.categories, uses: run.result.uses, summary: run.result.summary,
    sources: Object.fromEntries(Object.entries(run.sources).map(([id, record]) => [id, { status: record.status, error: record.error || null, data: record.data || null }])),
    dnsbl: run.dnsbl, lists: run.lists, asn: run.asnProfile, probes: run.self ? { ...run.probes, dns: undefined, ipv6: undefined } : null,
  };
  const json = JSON.stringify(report, (key, value) => hide(value), 2);
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
  link.download = `egress-report-${Date.now()}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 2000);
}

async function share() {
  const run = app.run;
  if (!run) return;
  const url = new URL(location.href);
  url.search = `?ip=${encodeURIComponent(run.ip)}`;
  const button = $('share');
  try { await navigator.clipboard.writeText(url.href); button.dataset.done = '已复制链接'; }
  catch { button.dataset.done = '复制失败'; }
  setTimeout(() => { delete button.dataset.done; }, 1800);
}

$('query').addEventListener('submit', event => { event.preventDefault(); startRun($('ip-input').value, true); });
$('ip-input').addEventListener('input', () => $('ip-input').classList.remove('is-masked'));
$('mask-toggle').addEventListener('click', () => { app.masked = !app.masked; localStorage.setItem('egress-mask', app.masked ? '1' : '0'); view.applyMask(app.masked); });
$('share').addEventListener('click', share);
$('export').addEventListener('click', exportReport);
$('rerun').addEventListener('click', () => app.run && startRun(app.run.ip));
document.addEventListener('click', event => {
  const check = event.target.closest('[data-check]');
  if (check) { startRun(check.dataset.check); window.scrollTo({ top: 0, behavior: 'smooth' }); }
  if (event.target.closest('[data-self-check]')) $('self-check').click();
  const rerun = event.target.closest('[data-rerun]');
  if (rerun && app.run) runCaptcha(app.run, rerun.dataset.rerun);
});

// ---------- boot ----------

/**
 * Detect what websites see as this machine's egress. With autoStart, check the first IPv4 as soon as
 * it is known (or IPv6 when there is no IPv4). Always fresh: switching proxy nodes shows up here.
 */
function refreshEgress({ autoStart }) {
  let started = false;
  const button = $('self-check');
  button.disabled = true;
  app.egress = null;
  if (autoStart) $('status').textContent = '正在识别本机出口 IP…';
  app.egressPromise = detectEgress(undefined, results => {
    app.egress = { ...summarizeEgress(results), partial: true };
    if (autoStart && !started) {
      const first = app.egress.v4 || null;
      if (first && results.find(item => item.id === 'ipify4')?.status !== 'pending') { started = true; startRun(first); }
    }
    if (app.run) scheduleRender(); else view.renderEgress(app.egress, null, app);
  }).then(summary => {
    app.egress = summary;
    button.disabled = false;
    if (autoStart && !started) {
      started = true;
      if (summary.v4 || summary.v6) startRun(summary.v4 || summary.v6);
      else $('status').textContent = '没能识别本机出口 IP，可以直接输入要检测的地址。';
    }
    if (app.run) {
      // The egress set decides whether live probes apply; upgrade a run that started before it was known.
      const self = summary.ips.some(ip => sameIP(ip, app.run.ip));
      if (self && !app.run.self) startRun(app.run.ip); else scheduleRender();
    }
    return summary;
  });
  return app.egressPromise;
}

$('self-check').addEventListener('click', () => {
  $('ip-input').value = '';
  window.scrollTo({ top: 0, behavior: 'smooth' });
  refreshEgress({ autoStart: true });
});

$('ipinfo-apply').addEventListener('click', () => {
  const run = app.run;
  if (!run) return;
  try {
    const page = readIPinfoPage($('ipinfo-text').value, run.ip);
    run.ipinfoPage = page;
    run.sources.ipinfo = mergeIPinfoPage(run.sources.ipinfo || {}, page);
    $('ipinfo-text').value = '';
    const labels = {vpn:'VPN',proxy:'代理',tor:'Tor',relay:'中继',hosting:'机房'};
    $('ipinfo-message').textContent = [run.ip, page.companyName, page.asnType && 'ASN 类型 '+page.asnType,
      ...Object.entries(page.flags).map(([k,v])=>labels[k]+' '+(v?'检出':'未检出')),
      typeof page.resProxy === 'boolean' && '住宅代理 '+(page.resProxy?'检出':'未检出')].filter(Boolean).join(' · ');
    scheduleRender();
  } catch (error) { $('ipinfo-message').textContent = error.message; }
});
const importedTypes = setupImport();
const requested = new URLSearchParams(location.search).get('ip');
view.initTooltips();
view.applyMask(app.masked);
view.renderEgress(null, null, app);
refreshEgress({ autoStart: !requested });
if (requested) startRun(requested);
