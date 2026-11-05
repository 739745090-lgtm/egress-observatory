import { parseIP, isPublicIP } from './util.js';
import { extractProviderPage, extractIPSuperReport } from './page-extract.js';
import { PAGE_PROVIDERS } from './page-providers.js';

const SITES = PAGE_PROVIDERS;
const PARALLEL = 3;
const READ_MS = 45000;
const VERSION = chrome.runtime.getManifest().version;
const jobs = new Map();
const cache = new Map();
const pause = ms => new Promise(resolve=>setTimeout(resolve,ms));

function allowed(sender) {
  if (!sender.tab || !sender.url) return false;
  const url = new URL(sender.url);
  return url.origin === 'https://blackslience-reaper.github.io' && url.pathname.startsWith('/egress-observatory/')
    || ['http://127.0.0.1:4187','http://localhost:4187'].includes(url.origin);
}

/** At most `size` pages load at once; a page waiting on a human check gives its slot back. */
function limiter(size) {
  let active = 0;
  const waiting = [];
  return () => new Promise(resolve => {
    const start = () => {
      active++;
      let released = false;
      resolve(() => { if (released) return; released = true; active--; waiting.shift()?.(); });
    };
    active < size ? start() : waiting.push(start);
  });
}

function notify(job, provider, row) {
  const report = provider === 'ipsuper'
    ? {ip:job.ip,time:Date.now(),sources:{},thirdParty:row,...(row.status === 'ok' ? {ipsuper:row.report} : {thirdPartyError:row.error})}
    : {ip:job.ip,time:Date.now(),sources:{[provider]:row}};
  report.total = Object.keys(SITES).length;
  report.version = VERSION;
  chrome.tabs.sendMessage(job.client, {channel:'egress-browser-partial',requestId:job.requestId,report}).catch(()=>{});
}

async function read(provider, ip, job, release) {
  let tab;
  let owned = false;
  const started = Date.now();
  const site = SITES[provider];
  const target = site.url(encodeURIComponent(ip));
  try {
    if (job.cancelled) throw Error('查询已取消');
    if (site.json) {
      const response = await fetch(target,{credentials:'omit',signal:AbortSignal.any([job.controller.signal,AbortSignal.timeout(20000)])});
      if (!response.ok) throw Error(`HTTP ${response.status}：${response.status === 429 ? '来源查询额度或频率受限' : response.status === 403 ? '来源拒绝访问' : '来源接口请求失败'}`);
      let raw;
      try { raw = await response.json(); } catch { throw Error('HTTP 200：来源返回非 JSON 响应'); }
      const result = extractProviderPage(provider,ip,raw);
      return {status:'ok',data:result.data,time:Date.now(),via:'Chrome',ms:Date.now()-started,mode:'api'};
    }
    // Read a matching result the visitor already opened without navigating or closing it.
    const matches = await chrome.tabs.query({url:target});
    tab = matches.find(candidate=>![...jobs.values()].some(other=>other.tabs.has(candidate.id)));
    if(!tab) {
      tab = await chrome.tabs.create({url:target,active:false,windowId:job.window});
      owned = true;
      job.tabs.add(tab.id);
      if (job.group != null) await chrome.tabs.group({groupId:job.group,tabIds:[tab.id]}).catch(()=>{});
    }
    const deadline = Date.now() + READ_MS;
    let afterCheckDeadline = null;
    let reason = '页面加载超过 45 秒';
    // Await the visitor's manual check until completion, cancellation or tab closure.
    while ((Date.now() < deadline || job.challenges.has(provider)) && !job.cancelled) {
      try {
        const current = await chrome.tabs.get(tab.id);
        // Read rendered results while third-party resources are still loading.
        const currentURL = current.url || current.pendingUrl || target;
        if(currentURL === 'about:blank'){await pause(700);continue;}
        if (new URL(currentURL).origin !== new URL(target).origin) throw Error('网页跳转到其他站点');
        const [result] = await chrome.scripting.executeScript({target:{tabId:tab.id},func:provider === 'ipsuper' ? extractIPSuperReport : extractProviderPage,args:provider === 'ipsuper' ? [ip,true] : [provider,ip,null,true]});
        // Chrome does not reliably reject executeScript when the injected function throws.
        if(result?.result?.status === 'error')throw Error(result.result.error);
        if(!result?.result)throw Error('页面脚本未返回结果，等待页面继续加载');
        if (result.result?.ip === ip) {
          if (job.challenges.has(provider) && job.focused.has(provider)) chrome.tabs.update(job.client,{active:true}).catch(()=>{});
          return {status:'ok',...(provider === 'ipsuper' ? {report:result.result} : {data:result.result.data}),time:Date.now(),via:'Chrome',ms:Date.now()-started,mode:'page'};
        }
      } catch (error) {
        reason = String(error.message || '网页字段暂不可读取').replace(/^Error:\s*/,'').slice(0,180);
        if (/其他站点|closed|No tab|HTTP 4|来源拒绝/.test(reason)) break;
        if (/人机校验/.test(reason) && !job.challenges.has(provider)) {
          // Never click or solve it: keep the tab, tell the Egress page, and let the visitor finish it.
          job.challenges.set(provider, tab.id);
          release();
          notify(job, provider, {status:'challenge',error:'等待手动验证，通过后自动补充',time:Date.now(),ms:Date.now()-started,via:'Chrome'});
        }
        if (job.challenges.has(provider)) {
          if (/人机校验/.test(reason)) afterCheckDeadline = null;
          else {
            afterCheckDeadline ??= Date.now() + READ_MS;
            if (Date.now() >= afterCheckDeadline) { reason = '校验提示已消失，45 秒后仍无法读取结果：' + reason; break; }
          }
        }
      }
      await pause(job.challenges.has(provider) ? 1500 : 700);
    }
    throw Error(job.cancelled ? '已停止等待' : reason);
  } catch (error) {
    let message = error.name === 'TimeoutError' ? '来源接口连接超过 20 秒' : error instanceof TypeError ? '来源连接失败，浏览器未取得响应' : String(error.message || 'Chrome 读取失败');
    if (job.cancelled) message = '已停止等待';
    return {status:'error',error:message.slice(0,180),time:Date.now(),via:'Chrome',ms:Date.now()-started};
  } finally {
    release();
    if (tab && owned) { await chrome.tabs.remove(tab.id).catch(()=>{}); job.tabs.delete(tab.id); }
    job.challenges.delete(provider);
  }
}

async function lookup(ip, job) {
  const sources = {};
  let third = null;
  const slot = limiter(PARALLEL);
  // A blank anchor keeps the tab group alive while result pages open and close around it.
  const anchor = await chrome.tabs.create({url:'about:blank',active:false,windowId:job.window});
  job.tabs.add(anchor.id);
  try {
    job.group = await chrome.tabs.group({tabIds:[anchor.id]});
    await chrome.tabGroups.update(job.group,{title:'Egress 自动查询',color:'blue'});
  } catch { job.group = null; }
  try {
    await Promise.all(Object.keys(SITES).map(async provider => {
      const key = provider + ':' + ip;
      const previous = cache.get(key);
      let row;
      if (job.skip.includes(provider)) row = {status:'skip',error:'接口已返回或已限流，本轮避免重复消耗额度',time:Date.now(),via:'Chrome'};
      else if (previous?.status === 'ok' && Date.now() - previous.time < 600000) row = {...previous,cached:true};
      else {
        const release = await slot();
        if (job.cancelled) { release(); row = {status:'error',error:'查询已取消',time:Date.now()}; }
        else row = await read(provider, ip, job, release);
      }
      if (row.status === 'ok') { if (cache.size >= 128) cache.delete(cache.keys().next().value); cache.set(key,row); }
      if (provider === 'ipsuper') third = row; else sources[provider] = row;
      if (!job.cancelled) notify(job, provider, row);
    }));
  } finally { for (const tab of job.tabs) await chrome.tabs.remove(tab).catch(()=>{}); job.tabs.clear(); }
  return {ip,time:Date.now(),version:VERSION,total:Object.keys(SITES).length,sources,thirdParty:third,...(third?.status === 'ok' ? {ipsuper:third.report} : {thirdPartyError:third?.error})};
}

function cancel(job) {
  job.cancelled = true;
  job.controller.abort();
  for (const tab of job.tabs) chrome.tabs.remove(tab).catch(()=>{});
}

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (!allowed(sender) || typeof message.requestId !== 'string' || message.requestId.length > 80) return;
  const key = sender.tab.id + ':' + message.requestId;
  if (message.kind === 'cancel') {
    const job = jobs.get(key);
    if (job) cancel(job);
    respond({cancelled:true}); return;
  }
  if (message.kind === 'focus') {
    // Bring a page that is waiting on a human check to the front, on the visitor's request.
    const job = jobs.get(key);
    const tabId = job?.challenges.get(message.provider);
    if (tabId == null) { respond({focused:false}); return; }
    job.focused.add(message.provider);
    chrome.tabs.update(tabId,{active:true}).then(tab => chrome.windows.update(tab.windowId,{focused:true})).then(() => respond({focused:true}), () => respond({focused:false}));
    return true;
  }
  const ip = parseIP(message.ip)?.ip;
  if (message.kind !== 'lookup' || !ip || !isPublicIP(ip)) { respond({error:'需要有效的公网 IP'}); return; }
  // A fresh query from this Egress tab cancels only its own previous work.
  for (const [id, job] of jobs) if (id.startsWith(sender.tab.id + ':')) cancel(job);
  const job = {ip,requestId:message.requestId,client:sender.tab.id,window:sender.tab.windowId,tabs:new Set(),group:null,cancelled:false,challenges:new Map(),focused:new Set(),controller:new AbortController(),skip:Array.isArray(message.skip) ? message.skip.filter(id=>['ipapiis','iplocate'].includes(id)) : []};
  jobs.set(key, job);
  // Finish this message immediately. Polling Chrome APIs keeps an active manual wait alive
  // without holding one onMessage event open beyond the service worker event deadline.
  respond({started:true});
  lookup(ip, job).then(report => chrome.tabs.sendMessage(job.client,{channel:'egress-browser-complete',requestId:job.requestId,report}))
    .catch(error=>chrome.tabs.sendMessage(job.client,{channel:'egress-browser-complete',requestId:job.requestId,report:{error:String(error.message || '插件查询中断').slice(0,180)}}).catch(()=>{}))
    .finally(()=>jobs.delete(key));
});

chrome.tabs.onRemoved.addListener(tabId => {
  for (const job of jobs.values()) if (job.client === tabId) cancel(job);
});
