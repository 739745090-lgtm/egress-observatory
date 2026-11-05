import { parseIP, isPublicIP } from './util.js';
import { extractProviderPage, extractIPSuperReport } from './page-extract.js';

// One fixed result page per source. ipapi.is is left out: its page spends the same 30-per-IP daily quota
// that Egress already uses directly, and requests past it get the address blocked for a day. IPData is left out:
// its page shows the full record only after a Turnstile check, in a layout no extractor reads yet.
const SITES = {
  ipsuper: ip => 'https://ipsuper.com/?ip=' + encodeURIComponent(ip),
  iphub: ip => 'https://iphub.info/?ip=' + encodeURIComponent(ip),
  ipqs: ip => 'https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/' + encodeURIComponent(ip),
  scamalytics: ip => 'https://scamalytics.com/ip/' + encodeURIComponent(ip),
  ip2location: ip => 'https://www.ip2location.io/' + encodeURIComponent(ip),
  greynoise: ip => 'https://viz.greynoise.io/ip/' + encodeURIComponent(ip),
  dbip: ip => 'https://db-ip.com/' + encodeURIComponent(ip),
  ipregistry: ip => 'https://ipregistry.co/' + encodeURIComponent(ip),
  blackbox: ip => 'https://blackbox.ipinfo.app/api/v3beta/' + encodeURIComponent(ip),
  ipquery: ip => 'https://api.ipquery.io/' + encodeURIComponent(ip) + '?format=json',
};
const PARALLEL = 3;
const READ_MS = 45000;
// A page behind a human check stays open this long for the visitor to complete it themselves.
const CHALLENGE_MS = 150000;
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
    ? {ip:job.ip,time:Date.now(),sources:{},...(row.status === 'ok' ? {ipsuper:row.report} : {thirdPartyError:row.error})}
    : {ip:job.ip,time:Date.now(),sources:{[provider]:row}};
  chrome.tabs.sendMessage(job.client, {channel:'egress-browser-partial',requestId:job.requestId,report}).catch(()=>{});
}

async function read(provider, ip, job, release) {
  let tab;
  try {
    if (job.cancelled) throw Error('查询已取消');
    const target = SITES[provider](ip);
    tab = await chrome.tabs.create({url:target,active:false,windowId:job.window});
    job.tabs.add(tab.id);
    if (job.group != null) await chrome.tabs.group({groupId:job.group,tabIds:[tab.id]}).catch(()=>{});
    let deadline = Date.now() + READ_MS;
    let reason = '网页未返回目标字段';
    while (Date.now() < deadline && !job.cancelled) {
      try {
        const current = await chrome.tabs.get(tab.id);
        if (current.status !== 'complete') { await pause(700); continue; }
        if (new URL(current.url).origin !== new URL(target).origin) throw Error('网页跳转到其他站点');
        const [result] = await chrome.scripting.executeScript({target:{tabId:tab.id},func:provider === 'ipsuper' ? extractIPSuperReport : extractProviderPage,args:provider === 'ipsuper' ? [ip] : [provider,ip]});
        if (result.result?.ip === ip) {
          if (job.challenges.has(provider) && job.focused.has(provider)) chrome.tabs.update(job.client,{active:true}).catch(()=>{});
          return {status:'ok',...(provider === 'ipsuper' ? {report:result.result} : {data:result.result.data}),time:Date.now(),via:'Chrome'};
        }
      } catch (error) {
        reason = String(error.message || '网页字段暂不可读取').replace(/^Error:\s*/,'').slice(0,100);
        if (/其他站点|closed|No tab/i.test(reason)) break;
        if (/人机校验/.test(reason) && !job.challenges.has(provider)) {
          // Never click or solve it: keep the tab, tell the Egress page, and let the visitor finish it.
          job.challenges.set(provider, tab.id);
          deadline = Date.now() + CHALLENGE_MS;
          release();
          notify(job, provider, {status:'challenge',error:'等待你在 Chrome 中完成人机验证',time:Date.now()});
        }
      }
      await pause(job.challenges.has(provider) ? 1500 : 700);
    }
    throw Error(job.cancelled ? '查询已取消' : job.challenges.has(provider) ? '人机验证未完成，已跳过' : reason);
  } catch (error) {
    return {status:'error',error:String(error.message || 'Chrome 网页读取失败').slice(0,100),time:Date.now()};
  } finally {
    release();
    if (tab) { await chrome.tabs.remove(tab.id).catch(()=>{}); job.tabs.delete(tab.id); }
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
      if (previous?.status === 'ok' && Date.now() - previous.time < 600000) row = previous;
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
  return {ip,time:Date.now(),version:VERSION,sources,...(third?.status === 'ok' ? {ipsuper:third.report} : {thirdPartyError:third?.error})};
}

function cancel(job) {
  job.cancelled = true;
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
  const job = {ip,requestId:message.requestId,client:sender.tab.id,window:sender.tab.windowId,tabs:new Set(),group:null,cancelled:false,challenges:new Map(),focused:new Set()};
  jobs.set(key, job);
  lookup(ip, job).then(respond).catch(() => respond({error:'Chrome 网页读取失败'})).finally(() => jobs.delete(key));
  return true;
});
