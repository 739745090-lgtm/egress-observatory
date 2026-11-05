import { parseIP, isPublicIP } from './util.js';
import { extractProviderPage, extractIPSuperReport } from './page-extract.js';

const SITES = {ipsuper:ip=>'https://ipsuper.com/?ip='+encodeURIComponent(ip),iphub:ip=>'https://iphub.info/?ip='+encodeURIComponent(ip),ipqs:ip=>'https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/'+encodeURIComponent(ip)};
const jobs = new Map();
const cache = new Map();
const pause = ms => new Promise(resolve=>setTimeout(resolve,ms));

function allowed(sender) {
  if (!sender.tab || !sender.url) return false;
  const url = new URL(sender.url);
  return url.origin === 'https://blackslience-reaper.github.io' && url.pathname.startsWith('/egress-observatory/')
    || ['http://127.0.0.1:4187','http://localhost:4187'].includes(url.origin);
}

async function read(provider,ip,job) {
  let tab;
  try {
    if (job.cancelled) throw Error('查询已取消');
    tab = await chrome.tabs.create({url:SITES[provider](ip),active:false});
    job.tabs.add(tab.id);
    if (job.group == null) {
      job.group = await chrome.tabs.group({tabIds:[tab.id]});
      await chrome.tabGroups.update(job.group,{title:'Egress 自动查询',color:'blue'});
    } else await chrome.tabs.group({groupId:job.group,tabIds:[tab.id]});
    const deadline = Date.now()+45000;
    let reason = '网页未返回目标字段';
    while (Date.now() < deadline && !job.cancelled) {
      try {
        const current = await chrome.tabs.get(tab.id);
        if (current.status !== 'complete') { await pause(700); continue; }
        if (new URL(current.url).origin !== new URL(SITES[provider](ip)).origin) throw Error('网页跳转到其他站点');
        const [result] = await chrome.scripting.executeScript({target:{tabId:tab.id},func:provider==='ipsuper'?extractIPSuperReport:extractProviderPage,args:provider==='ipsuper'?[ip]:[provider,ip]});
        if (result.result?.ip === ip) return {status:'ok',...(provider==='ipsuper'?{report:result.result}:{data:result.result.data}),time:Date.now(),via:'Chrome'};
      } catch (error) {
        reason = String(error.message || '网页字段暂不可读取').replace(/^Error:\s*/,'').slice(0,100);
        if (/人机校验|其他站点|closed|No tab/i.test(reason)) break;
      }
      await pause(700);
    }
    throw Error(job.cancelled ? '查询已取消' : reason);
  } catch (error) {
    return {status:'error',error:String(error.message || 'Chrome 网页读取失败').slice(0,100),time:Date.now()};
  } finally {
    if (tab) { await chrome.tabs.remove(tab.id).catch(()=>{}); job.tabs.delete(tab.id); }
  }
}

async function lookup(ip,job) {
  const sources = {};
  const anchor = await chrome.tabs.create({url:'about:blank',active:false});
  job.tabs.add(anchor.id);
  job.group = await chrome.tabs.group({tabIds:[anchor.id]});
  await chrome.tabGroups.update(job.group,{title:'Egress 自动查询',color:'blue'});
  try { for (const provider of Object.keys(SITES)) {
    if (job.cancelled) break;
    const key = provider+':'+ip;
    const previous = cache.get(key);
    const row = previous?.status === 'ok' && Date.now()-previous.time<600000 ? previous : await read(provider,ip,job);
    if (row.status === 'ok') { if(cache.size>=64)cache.delete(cache.keys().next().value); cache.set(key,row); }
    sources[provider] = row;
  } } finally { for(const tab of job.tabs) await chrome.tabs.remove(tab).catch(()=>{}); job.tabs.clear(); }
  const third = sources.ipsuper;
  delete sources.ipsuper;
  return {ip,time:Date.now(),sources,...(third?.status==='ok'?{ipsuper:third.report}:{thirdPartyError:third?.error})};
}

chrome.runtime.onMessage.addListener((message,sender,respond)=>{
  if (!allowed(sender) || typeof message.requestId !== 'string' || message.requestId.length>80) return;
  const key = sender.tab.id+':'+message.requestId;
  if (message.kind === 'cancel') {
    const job = jobs.get(key);
    if(job) { job.cancelled=true; for(const tab of job.tabs) chrome.tabs.remove(tab).catch(()=>{}); }
    respond({cancelled:true}); return;
  }
  const ip = parseIP(message.ip)?.ip;
  if (message.kind !== 'lookup' || !ip || !isPublicIP(ip)) { respond({error:'需要有效的公网 IP'}); return; }
  // A fresh query from this Egress tab cancels only its own previous work.
  for(const [id,job] of jobs) if(id.startsWith(sender.tab.id+':')) { job.cancelled=true; for(const tab of job.tabs) chrome.tabs.remove(tab).catch(()=>{}); }
  const job = {tabs:new Set(),group:null,cancelled:false};
  jobs.set(key,job);
  lookup(ip,job).then(respond).catch(()=>respond({error:'Chrome 网页读取失败'})).finally(()=>jobs.delete(key));
  return true;
});
