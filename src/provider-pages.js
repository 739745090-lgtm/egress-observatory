import { sameIP } from './util.js';
import { fillSource } from './supplements.js?v=2';
import { extractProviderPage } from './page-extract.js?v=1';

export const PAGE_SOURCES = ['iphub','ipqs','ipdata','ipregistry','dbip','scamalytics','ipapiis','ipquery','blackbox'];
const fields = new Set(['country','city','region','asn','org','usageType','companyType','asnType','usageDetail','connectionType','risk','block','geoVote']);
const types = new Set(['residential','mobile','business','hosting','education','government']);

export function readProviderReport(report, ip) {
  if (!report || !sameIP(report.ip, ip) || !Number.isFinite(report.time) || Math.abs(Date.now()-report.time)>600000 || !report.sources || Array.isArray(report.sources)) throw Error('网页报告的目标、时间或来源无效');
  const result = {};
  for (const id of PAGE_SOURCES) {
    const row = report.sources[id];
    if (!row) continue;
    if (row.status !== 'ok') { result[id] = {status:'error',error:String(row.error || '网页未返回字段').slice(0,120)}; continue; }
    if (!Number.isFinite(row.time) || Math.abs(Date.now()-row.time)>600000) continue;
    const data = {flags:{}};
    for (const [key,value] of Object.entries(row.data || {})) {
      if (!fields.has(key) || value == null) continue;
      if (key === 'usageType' || key === 'companyType') { if (types.has(value)) data[key] = value; }
      else if (key === 'risk') { if (typeof value === 'number' && value >= 0 && value <= 100) data[key] = value; }
      else if (key === 'asn') { if (Number.isInteger(value) && value > 0 && value <= 4294967295) data[key] = value; }
      else if (key === 'block') { if ([0,1,2].includes(value)) data[key] = value; }
      else if (key === 'geoVote') { if (typeof value === 'boolean') data[key] = value; }
      else if (typeof value === 'string' && value.length <= 240) data[key] = value;
    }
    for (const key of ['vpn','proxy','tor','hosting','mobile','abuser','crawler','relay','resProxy']) if (typeof row.data?.flags?.[key] === 'boolean') data.flags[key] = row.data.flags[key];
    if (!Object.keys(data.flags).length && Object.keys(data).every(key => ['flags','geoVote'].includes(key))) {
      result[id] = {status:'error',error:'网页未提供可读取的目标字段'};
    } else result[id] = {status:'ok',data,time:row.time};
  }
  return result;
}

export function mergeProviderPage(record, page, name) {
  if (!page) return record;
  if (page.status !== 'ok') return {...record,webLookup:page,...(record.status === 'ok' ? {} : {error:[record.error, page.error].filter(Boolean).join(' · ')})};
  const data = {...page.data};
  if (data.usageType) data.type = data.usageType;
  data.webObservedAt = new Date(page.time).toISOString();
  let merged = fillSource(record, data, name + ' 官方网页 · ' + data.webObservedAt);
  const added = ['usageType','companyType'].filter(key => page.data[key] && !record.data?.[key]);
  if (added.length) merged = {...merged,data:{...merged.data,webTypeFields:added}};
  return {...merged,webLookup:page};
}

export function setupProviderImport() {
  const destination = location.origin + location.pathname;
  // Runs only when the user clicks their bookmark on an official result page.
  function send(destination, extract) {
    const providers = {'iphub.info':'iphub','www.ipqualityscore.com':'ipqs','ipqualityscore.com':'ipqs','ipdata.co':'ipdata','ipregistry.co':'ipregistry','db-ip.com':'dbip','scamalytics.com':'scamalytics','ipapi.is':'ipapiis','api.ipquery.io':'ipquery','blackbox.ipinfo.app':'blackbox'};
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
