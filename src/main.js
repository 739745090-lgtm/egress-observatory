import { lookupIPOK, lookupDBIPWeb, fillSource } from './supplements.js?v=3';
import { readIPinfoPage, mergeIPinfoPage } from './ipinfo-page.js?v=3.4';
import { setupImport, supplementTypes, readReport, readRiskReport, mergeTypeReports, mergeRiskReports } from './ipsuper.js?v=3.4';
import { setupProviderImport, readProviderReport, mergeProviderPage, lookupChromePages } from './provider-pages.js?v=4.1';
/** Orchestration: detect the egress, fan out every check, rescore as results arrive. */
import { API_BASE } from '../config.js?v=cloud2';
import { lookupPage } from './page-lookups.js?v=6';
import { getJSON, parseIP, isPublicIP, sameIP, maskIP, maskText } from './util.js?v=4.1';
import { SOURCES, runSource } from './sources.js?v=3.3';
import { DNSBLS, checkDNSBL, CIDR_LISTS, checkCIDRList, asnAbuseDensity } from './blocklists.js';
import { fetchASN, inferASN, detectLease } from './asn.js?v=4.3';
import { detectEgress, summarizeEgress, probeWebRTC, probeDNS, classifyDNS, probeTCP, probeEnvironment, probeIPv6, classifyIPv6, traceProbe } from './probes.js';
import { runTurnstile, runRecaptcha } from './captcha.js?v=4.2';
import { score } from './score.js?v=4.8';
import * as view from './render.js?v=4.22';

const $ = id => document.getElementById(id);
$('types').addEventListener('click',event=>{if(event.target.closest('[data-lookup-details]'))$('lookup-details').open=true;});
const app = {
  masked: localStorage.getItem('egress-mask') === '1',
  egress: null, egressPromise: null, health: null, healthPromise: null, healthPending: false, healthAt: 0, run: null, frame: 0,
};

// ---------- backend capabilities ----------

function refreshHealth(force = false) {
  if (app.healthPending) return app.healthPromise;
  if (!force && app.health && Date.now() - app.healthAt < 60000) return Promise.resolve(app.health);
  app.healthPending = true;
  app.healthPromise = (async () => {
    for (const timeout of [6000, 10000]) {
      const result = await getJSON(`${API_BASE}/health`, { timeout });
      if (result.ok && result.data?.service === 'egress-observatory-api') {
        // Only a valid capability response can establish that a route is unconfigured.
        const routes = result.data.routes || result.data.providers;
        if (Array.isArray(routes)) return { ...result.data, routes };
      }
      if (result.status === 429) break;
    }
    return null;
  })().then(health => {
    app.health = health;
    app.healthAt = Date.now();
    return health;
  }).finally(() => { app.healthPending = false; });
  return app.healthPromise;
}
refreshHealth();

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
    asn: run.asnProfile || null, asnRep: run.asnRep || null, neighbours: neighbourSummary(run), seen: run.seen || null,
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

// An anonymous random id for this browser, so several people behind one exit IP count separately.
function clientId() {
  let id = localStorage.getItem('egress-client');
  if (!/^[a-f0-9-]{32,40}$/.test(id || '')) { id = crypto.randomUUID(); try { localStorage.setItem('egress-client', id); } catch { /* Private mode: a fresh id each time. */ } }
  return id;
}

// The last six addresses checked in this browser, newest first. Kept only in localStorage.
const HISTORY = 'egress-history';
function readHistory() {
  try { const list = JSON.parse(localStorage.getItem(HISTORY)); return Array.isArray(list) ? list.map(ip => parseIP(ip)?.ip).filter(ip => ip && isPublicIP(ip)).slice(0, 6) : []; }
  catch { return []; }
}
function rememberIP(ip) {
  const list = [ip, ...readHistory().filter(item => !sameIP(item, ip))].slice(0, 6);
  try { localStorage.setItem(HISTORY, JSON.stringify(list)); } catch { /* Storage disabled: history stays empty. */ }
  view.renderHistory(list);
}

async function startRun(input, fetchPages = true) {
  const parsed = parseIP(input);
  if (!parsed || !isPublicIP(parsed.ip)) { $('status').textContent = '请输入有效的公网 IPv4 或 IPv6 地址。'; return; }
  rememberIP(parsed.ip);
  const healthReady = refreshHealth(true);
  app.run?.controller.abort();
  const controller = new AbortController();
  const signal = controller.signal;
  const egress = app.egress || await Promise.race([app.egressPromise, new Promise(resolve => setTimeout(resolve, 4000))]) || app.egress;
  const self = Boolean(egress?.ips?.some(ip => sameIP(ip, parsed.ip)));
  const run = {
    ip: parsed.ip, v: parsed.v, self, controller, healthReady, startedAt: Date.now(),
    sources: {}, apiSources:{}, pageLookups:{}, chrome:{rows:{},active:false}, providerPages: sameIP(importedProviderIP, parsed.ip) ? {...importedProviderPages} : {}, dnsbl: [], lists: [], asn: null, asnProfile: null, probes: {}, result: null,
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

  const ctx = { signal, healthReady, sourceReady: new Map() };
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
    healthReady.then(health => fetchASN(asn, { signal, prefix, health })).then(profile => {
      if (!alive()) return;
      run.asn = profile; scheduleRender();
      if (profile.routes?.length) asnAbuseDensity(profile.routes, signal).then(rep => { if (alive() && rep) { run.asnRep = rep; scheduleRender(); } });
    });
  };

  let webTypes = importedTypes;
  let ipokRows = {};
  let ipsuperRisk = {};
  let ipsuperPages = {};
  let ipsuperObservedAt = 0;
  const records = new Map();
  function refreshTypes() {
    const abuse = records.get('abuseipdb')?.data;
    for (const [id, record] of records) {
      let data = id === 'ipinfo' ? mergeIPinfoPage(record, run.ipinfoPage) : record;
      data = mergeProviderPage(data, run.providerPages[id], SOURCES.find(source => source.id === id)?.name || id);
      data = mergeProviderPage(data, ipsuperPages[id], SOURCES.find(source => source.id === id)?.name || id);
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
      if (row && !row.unavailable) {
        const scored = Object.keys(row.flags).filter(key=>data.data?.flags?.[key]==null);
        if(row.percent!=null && data.data?.risk==null)scored.push('risk');
        data = fillSource(data, {...row.fields,flags:row.flags, risk:row.percent, webRiskScore:row.percent, webObservedAt:row.observedAt,webScoreFields:[...new Set([...(data.data?.webScoreFields || []),...scored])]}, 'IPOK 逐库风险与匿名标记'+(row.observedAt ? ' · '+row.observedAt : ''));
      }
      data = supplementTypes(data, webTypes(parsed.ip, id));
      if (row?.unavailable && data.status !== 'ok' && !data.webLookup) data = {...data,error:row.reason === 'cached_only' ? '网页暂无该 IP 的缓存记录' : '网页来源暂缺 · '+row.reason};
      run.sources[id] = data;
    }
  }
  const pageStatus = $('auto-page-status');
  pageStatus.textContent = '';
  $('lookup-detail-rows').innerHTML = '';
  const challengeBox = $('chrome-challenges');
  challengeBox.innerHTML = '';
  if (fetchPages) {
    const pageSignal=AbortSignal.any([signal,AbortSignal.timeout(240000)]);
    lookupIPOK(parsed.ip, signal).then(rows => {
      if (!alive()) return;
      ipokRows = rows; refreshTypes(); scheduleRender();
      statuses.ipok={status:'ok',message:'补充 '+Object.values(rows).filter(row=>!row.unavailable).length+' 库'};
      showStatus();
    }).catch(error => {
      if (!alive()) return;
      ipokRows = Object.fromEntries(['iphub','vpnapi','scamalytics','ipqs'].map(id => [id,{unavailable:true,reason:error.message}]));
      refreshTypes(); scheduleRender();
      statuses.ipok={status:'error',message:error.message};
      showStatus();
    });
    const statuses = run.pageLookups = Object.fromEntries(['ipinfo','ipsuper','ipok','sources'].map(id=>[id,{status:'pending',message:'查询中'}]));
    const showStatus = () => view.renderLookupStatus(run);
    const primaryPages = [];
    showStatus();
    // The helper extension reads each source page in this Chrome session and reports them one by one.
    const chromeRows = run.chrome.rows;
    let focusChrome = null;
    let cancelChrome = null;
    const sourceName = id => id === 'ipsuper' ? 'IPSuper' : SOURCES.find(source => source.id === id)?.name || id;
    const showChrome = () => {
      const rows = Object.entries(chromeRows);
      const waiting = rows.filter(([, row]) => row.challenge).map(([id]) => id);
      showStatus();
      challengeBox.innerHTML = waiting.length && focusChrome ? waiting.map(id => `<button type="button" class="small accent" data-provider="${id}">去验证 ${sourceName(id)}</button>`).join(' ') + ' <span class="muted">通过后自动补充</span> <button type="button" class="small" data-stop-waiting>停止等待</button>' : '';
    };
    challengeBox.onclick = event => { const id = event.target.closest('button[data-provider]')?.dataset.provider; if (id && focusChrome) focusChrome(id); if (event.target.closest('[data-stop-waiting]')) cancelChrome?.(); };
    const applyChrome = report => {
      if (!alive() || !report) return;
      const pages = readProviderReport(report, parsed.ip);
      if (Number.isInteger(report.total)) run.chrome.total = report.total;
      if (report.version) run.chrome.version = report.version;
      if (report.thirdParty) chromeRows.ipsuper = {status:report.thirdParty.status,error:String(report.thirdParty.error || '').slice(0,200),challenge:report.thirdParty.status === 'challenge',ms:report.thirdParty.ms};
      for (const [id, page] of Object.entries(pages)) {
        chromeRows[id] = page;
        if (page.status !== 'skip' && (page.status === 'ok' || run.providerPages[id]?.status !== 'ok')) run.providerPages[id] = page;
      }
      if (report.ipsuper && report.ipsuper.time >= ipsuperObservedAt) {
        ipsuperPages=mergeRiskReports(ipsuperPages,readRiskReport(report.ipsuper,parsed.ip));ipsuperRisk={...ipsuperRisk,...report.ipsuper.riskPercent};
        webTypes=mergeTypeReports(webTypes,readReport(report.ipsuper,parsed.ip));ipsuperObservedAt=report.ipsuper.time;
        run.ipsuperReturned=SOURCES.filter(source=>webTypes(parsed.ip,source.id)).map(source=>source.id);
      }
      refreshTypes(); scheduleRender(); showChrome();
    };
    Promise.resolve().then(async()=>{
      const skip=[];
      for(const id of ['ipapiis','iplocate']) {
        const record = await ctx.sourceReady.get(id);
        if (record?.status === 'ok' || /429|额度|限流/.test(record?.error || '')) skip.push(id);
      }
      return lookupChromePages(parsed.ip, signal, {
        skip,
        onStart: (focus,info) => { if (!alive()) return;focusChrome=focus;cancelChrome=info.cancel;run.chrome.active=true;run.chrome.version=info.version;showStatus(); },
        onPartial: applyChrome,
      });
    }).then(report => { if (!alive()) return;if(report)applyChrome(report);focusChrome=null;run.chrome.active=false;showChrome(); })
      .catch(error=>{if(alive()){focusChrome=null;run.chrome.active=false;run.chrome.error=error.message;for(const row of Object.values(chromeRows))if(row.challenge){row.challenge=false;row.status='error';row.error=error.message;}challengeBox.innerHTML='';showStatus();scheduleRender();}});
    for (const provider of ['ipinfo','ipsuper','sources']) {
      const query = () => lookupPage(provider, parsed.ip, pageSignal, message => {
        if (!alive()) return;
        statuses[provider] = {status:'pending',message};
        showStatus();
      });
      const pageTask = (provider === 'sources' ? Promise.allSettled(primaryPages).then(() => { pageSignal.throwIfAborted(); return query(); }) : query())
        .then(report => {
          if (!alive()) return;
          if (!sameIP(report.ip, parsed.ip)) throw Error('返回的 IP 不匹配');
          if (provider === 'sources') {
            const pages = readProviderReport(report,parsed.ip);
            for (const [id,page] of Object.entries(pages)) {
              const previous = run.providerPages[id];
              if (!previous || page.status === 'ok' && (previous.status !== 'ok' || page.time >= previous.time)) run.providerPages[id] = page;
            }
            const ok = Object.values(pages).filter(row => row.status === 'ok').length;
            statuses.sources = {status:'ok',message:`读取 ${ok}/${Object.keys(pages).length}`};
          } else if (provider === 'ipinfo') {
            run.ipinfoPage = readIPinfoPage(report.text, parsed.ip);
            statuses.ipinfo = {status:'ok',message:'已读取'};
          } else {
            if(report.time>=ipsuperObservedAt) {
              webTypes = mergeTypeReports(webTypes,readReport(report, parsed.ip));
              ipsuperRisk = {...ipsuperRisk,...report.riskPercent};
              ipsuperPages = mergeRiskReports(ipsuperPages,readRiskReport(report,parsed.ip));
              ipsuperObservedAt=report.time;
            }
            run.ipsuperReturned = SOURCES.filter(source => webTypes(parsed.ip, source.id)).map(source => source.id);
            const n=Object.keys(ipsuperPages).length;
            const fields=Object.values(ipsuperPages).reduce((sum,row)=>sum+Object.keys(row.data.flags).length+(row.data.risk!=null?1:0),0);
            statuses.ipsuper = {status:'ok',message:`补充 ${n} 库、${fields} 字段`};
          }
          refreshTypes(); scheduleRender();
        }).catch(error => {
          if (!alive()) return;
          statuses[provider] = {status:'error',message:error.message};
          if (provider === 'sources') {
            refreshTypes(); scheduleRender();
          }
        })
        .finally(() => { if (alive()) showStatus(); });
      if (provider !== 'sources') primaryPages.push(pageTask);
    }
  }
  const tasks = [];
  for (const source of active) {
    const sourceTask = runSource(source, parsed.ip, ctx);
    ctx.sourceReady.set(source.id, sourceTask);
    tasks.push(sourceTask.then(async result => {
      if (!alive()) return;
      if (fetchPages && source.id === 'dbip' && result.status !== 'ok') {
        const fields = await lookupDBIPWeb(parsed.ip,signal);
        if (fields) result = fillSource(result,fields,'DB-IP City Lite，经 Net Atlas 的逐来源地理记录补充');
      }
      if (fetchPages && source.id === 'getipintel' && result.status !== 'ok') {
        try {
          const response = await fetch(API_BASE + '/v1/page/getipintel?ip=' + encodeURIComponent(parsed.ip), {signal:AbortSignal.any([signal,AbortSignal.timeout(130000)])});
          const answer = await response.json();
          if (response.ok && sameIP(answer.ip,parsed.ip) && Number.isFinite(answer.probability) && answer.probability>=0 && answer.probability<=1) {
            result = fillSource(result,{probability:answer.probability,risk:answer.risk},'GetIPIntel 官方免费接口');
          } else if (answer.error) result = {...result,error:answer.error};
        } catch { /* Retain the first route's concrete failure. */ }
      }
      if (!alive()) return;
      records.set(source.id, result);
      run.apiSources[source.id] = result;
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

  // Count this check: how many people have gone out through this IP (see /v1/seen in the API worker).
  healthReady.then(health => health?.seen ? getJSON(`${API_BASE}/v1/seen?ip=${encodeURIComponent(parsed.ip)}&client=${clientId()}`, { signal, timeout: 12000 }) : null)
    .then(result => { if (alive() && result?.ok && result.data?.status === 'success' && sameIP(result.data.ip, parsed.ip)) { run.seen = result.data; scheduleRender(); } })
    .catch(() => {});

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

async function runCaptcha(run, kind, alive = () => app.run === run, refreshBackend = false) {
  run.probes[kind] = null; scheduleRender();
  const health = await (refreshBackend ? refreshHealth(true) : run.healthReady);
  if (!alive()) return;
  const value = kind === 'turnstile' ? await runTurnstile($('turnstile-slot'), health) : await runRecaptcha(health);
  if (alive()) { run.probes[kind] = value; scheduleRender(); }
}

// ---------- page wiring ----------

function exportReport() {
  const run = app.run;
  if (!run?.result) return;
  // Hidden mode masks every address in the report (the IP, its /24, neighbours, hostnames), not just the exact IP string.
  const hide = value => (app.masked && typeof value === 'string' ? maskText(value, [run.ip]) : value);
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
  if (event.target.closest('[data-clear-history]')) { localStorage.removeItem(HISTORY); view.renderHistory([]); }
  const rerun = event.target.closest('[data-rerun]');
  if (rerun && app.run) runCaptcha(app.run, rerun.dataset.rerun, undefined, true);
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
const importedProviderIP = new URL(location.href).searchParams.get('ip');
const importedProviderPages = setupProviderImport();
$('provider-apply').addEventListener('click', () => {
  const run = app.run;
  if (!run) return;
  try {
    const pages = readProviderReport(JSON.parse($('provider-text').value),run.ip);
    for (const [id,page] of Object.entries(pages)) {
      run.providerPages[id] = page;
      run.sources[id] = mergeProviderPage(run.sources[id] || {},page,SOURCES.find(source => source.id === id)?.name || id);
    }
    $('provider-text').value = '';
    $('provider-message').textContent = `已导入 ${Object.keys(pages).length} 个来源网页的目标字段`;
    scheduleRender();
  } catch (error) { $('provider-message').textContent = error.message; }
});
const requested = new URLSearchParams(location.search).get('ip');
view.initTooltips();
view.applyMask(app.masked);
view.renderHistory(readHistory());
view.renderEgress(null, null, app);
refreshEgress({ autoStart: !requested });
if (requested) startRun(requested);
