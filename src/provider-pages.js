import { sameIP } from './util.js';
import { fillSource } from './supplements.js?v=3';
import { extractProviderPage } from './page-extract.js?v=4.1';
import { PAGE_PROVIDERS } from './page-providers.js?v=1';

export const PAGE_SOURCES = Object.keys(PAGE_PROVIDERS).filter(id=>id!=='ipsuper');
const fields = new Set(['country','city','region','asn','org','companyName','tz','usageType','companyType','asnType','usageDetail','connectionType','risk','trustScore','riskLabel','block','geoVote','lat','lon','noise','classification','name','lastSeen','proxyProvider']);
const types = new Set(['residential','mobile','business','hosting','education','government']);

export function readProviderReport(report, ip) {
  if (!report || !sameIP(report.ip, ip) || !Number.isFinite(report.time) || Math.abs(Date.now()-report.time)>600000 || !report.sources || Array.isArray(report.sources)) throw Error('网页报告的目标、时间或来源无效');
  const result = {};
  for (const id of PAGE_SOURCES) {
    const row = report.sources[id];
    if (!row) continue;
    const meta = {...(row.via === 'Chrome' ? {via:'Chrome'} : {}),...(Number.isFinite(row.ms) && row.ms >= 0 ? {ms:row.ms} : {}),...(row.cached ? {cached:true} : {})};
    if (row.status !== 'ok') { result[id] = {...meta,status:row.status === 'skip' ? 'skip' : 'error',error:String(row.error || '网页未返回字段').slice(0,200),...(row.status === 'challenge' ? {challenge:true} : {})}; continue; }
    if (!Number.isFinite(row.time) || Math.abs(Date.now()-row.time)>600000) continue;
    const data = {flags:{}};
    for (const [key,value] of Object.entries(row.data || {})) {
      if (!fields.has(key) || value == null) continue;
      if (key === 'usageType' || key === 'companyType') { if (types.has(value)) data[key] = value; }
      else if (key === 'risk' || key === 'trustScore') { if (typeof value === 'number' && value >= 0 && value <= 100) data[key] = value; }
      else if (key === 'asn') { if (Number.isInteger(value) && value > 0 && value <= 4294967295) data[key] = value; }
      else if (key === 'block') { if ([0,1,2].includes(value)) data[key] = value; }
      else if (key === 'geoVote' || key === 'noise') { if (typeof value === 'boolean') data[key] = value; }
      else if (key === 'lat' || key === 'lon') { if (typeof value === 'number' && Math.abs(value) <= (key === 'lat' ? 90 : 180)) data[key] = value; }
      else if (typeof value === 'string' && value.length <= 240) data[key] = value;
    }
    for (const key of ['vpn','proxy','tor','hosting','mobile','abuser','crawler','relay','resProxy','bogon']) if (typeof row.data?.flags?.[key] === 'boolean') data.flags[key] = row.data.flags[key];
    if (!Object.keys(data.flags).length && Object.keys(data).every(key => ['flags','geoVote'].includes(key))) {
      result[id] = {status:'error',error:'网页未提供可读取的目标字段'};
    } else result[id] = {...meta,status:'ok',data,time:row.time};
  }
  return result;
}

export function mergeProviderPage(record, page, name) {
  if (!page) return record;
  if (page.status === 'skip') return record;
  if (page.status !== 'ok') return {...record,webLookup:page,...(record.status === 'ok' ? {} : {error:[record.error, page.error].filter(Boolean).join(' · ')})};
  const data = {...page.data};
  data.flags = {...page.data.flags};
  if (data.flags.resProxy === true) { data.resProxy = true; data.flags.proxy = true; }
  if (data.usageType) data.type = data.usageType;
  data.webObservedAt = new Date(page.time).toISOString();
  let merged = fillSource(record, data, name + (page.via === 'IPSuper' ? '，经 IPSuper 网页逐库字段' : page.via === 'Chrome' ? ' 官方网页，Chrome 自动读取' : ' 官方网页') + ' · ' + data.webObservedAt);
  const scored = ['vpn','proxy','tor','hosting','relay','crawler','abuser'].filter(key => typeof data.flags[key] === 'boolean' && record.data?.flags?.[key] == null);
  if (data.risk != null && record.data?.risk == null) scored.push('risk');
  if (scored.length) merged = {...merged,data:{...merged.data,webScoreFields:[...new Set([...(record.data?.webScoreFields || []),...scored])]}};
  const added = ['usageType','companyType'].filter(key => page.data[key] && !record.data?.[key]);
  if (added.length) merged = {...merged,data:{...merged.data,webTypeFields:added}};
  return {...merged,webLookup:page};
}

/**
 * Ask the installed helper extension to read the source pages in this Chrome session.
 * onStart(focus) fires once it answers; focus(provider) brings a page waiting on a human check to the front.
 * onPartial(report) receives each source as soon as it is read; the promise resolves with the full report.
 */
export function lookupChromePages(ip,signal,{onStart=()=>{},onPartial=()=>{},skip=[]}={}) {
  return new Promise((resolve,reject)=>{
    signal.throwIfAborted();
    const requestId = crypto.randomUUID();
    let started = false;
    let discover,timeout;
    const waiting = new Set();
    const send = (kind,extra={}) => window.postMessage({channel:'egress-browser-client',kind,requestId,ip,skip,...extra},location.origin);
    const resetTimeout = () => {
      clearTimeout(timeout);
      if (!waiting.size) timeout=setTimeout(()=>{send('cancel');finish(null,Error('插件 90 秒未返回进度，已取消剩余查询'));},90000);
    };
    const finish = (value,error) => { clearTimeout(discover);clearTimeout(timeout);window.removeEventListener('message',receive);signal.removeEventListener('abort',abort); error ? reject(error) : resolve(value); };
    const abort = () => { send('cancel'); finish(null,signal.reason); };
    const receive = event => {
      if(event.source!==window || event.origin!==location.origin || event.data?.channel!=='egress-browser-helper') return;
      const message = event.data;
      if(message.kind==='ready' && (!message.requestId || message.requestId===requestId) && !started) {
        started=true;clearTimeout(discover);send('lookup');
        onStart(provider=>send('focus',{provider}),{version:message.version,cancel:()=>send('cancel')});
        resetTimeout();
      }
      if(message.requestId!==requestId) return;
      if(message.kind==='partial') {
        const rows = {...message.report?.sources,...(message.report?.thirdParty ? {ipsuper:message.report.thirdParty} : {})};
        for (const [id,row] of Object.entries(rows)) row.status === 'challenge' ? waiting.add(id) : waiting.delete(id);
        resetTimeout();
        try { onPartial(message.report); } catch { /* The final report repeats each partial row. */ }
      }
      else if(message.kind==='report') finish(message.report,message.report?.error ? Error(message.report.error) : null);
      else if(message.kind==='error') finish(null,Error(message.error));
    };
    window.addEventListener('message',receive);
    signal.addEventListener('abort',abort,{once:true});
    discover=setTimeout(()=>finish(null),1500);
    send('discover');
  });
}

export function setupProviderImport() {
  const destination = location.origin + location.pathname;
  // Runs only when the user clicks their bookmark on an official result page.
  function send(destination, extract) {
    const providers = {'iphub.info':'iphub','www.ipqualityscore.com':'ipqs','ipqualityscore.com':'ipqs','ipdata.co':'ipdata','ipregistry.co':'ipregistry','db-ip.com':'dbip','scamalytics.com':'scamalytics','ipapi.is':'ipapiis','api.ipquery.io':'ipquery','blackbox.ipinfo.app':'blackbox','www.ip2location.io':'ip2location','viz.greynoise.io':'greynoise'};
    const provider = providers[location.hostname];
    if (!provider) return alert('请在支持的来源查询结果页使用此书签。');
    const ip = provider === 'iphub' ? document.querySelector('[data-copy-field=ip]')?.textContent.trim() : provider === 'ipapiis' ? document.querySelector('input[type=search]')?.value.trim() : decodeURIComponent(location.pathname.split('/').filter(Boolean).at(-1) || '');
    try {
      const row = extract(provider,ip);
      const time = Date.now();
      const url = new URL(destination);
      url.searchParams.set('ip',ip);
      url.hash = 'provider-page=' + encodeURIComponent(JSON.stringify({ip,time,sources:{[provider]:{status:'ok',data:row.data,time}}}));
      window.open(url.href,'_blank','noopener');
    } catch (error) { alert(error.message); }
  }
  document.getElementById('provider-bookmark').href = 'javascript:(' + send.toString() + ')(' + JSON.stringify(destination) + ',' + extractProviderPage.toString() + ');void 0';
  let imported = {};
  if (location.hash.startsWith('#provider-page=')) {
    try { if (location.hash.length < 16000) imported = readProviderReport(JSON.parse(decodeURIComponent(location.hash.slice(15))), new URL(location.href).searchParams.get('ip')); }
    catch (error) { document.getElementById('provider-message').textContent = error.message; }
    history.replaceState(null,'',location.pathname + location.search);
  }
  return imported;
}
