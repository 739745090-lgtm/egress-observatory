import {sameIP, getJSON} from './util.js';

const optional = {IPQS:'ipqs', IPQualityScore:'ipqs', Scamalytics:'scamalytics', IPHub:'iphub', 'vpnapi.io':'vpnapi', 'ip-api':'ipapi','ip-api.com':'ipapi','ipapi.is':'ipapiis',proxycheck:'proxycheck',Proxycheck:'proxycheck',AbuseIPDB:'abuseipdb'};
const cachedReports = new Map();

export async function lookupIPOK(ip, signal) {
  const cached = cachedReports.get(ip);
  if (cached?.until > Date.now()) return cached.rows;
  const response = await getJSON('https://ipok.io/api/ip?ip='+encodeURIComponent(ip), {signal, timeout:22000});
  if (!response.ok) throw Error(response.error || 'IPOK 查询失败');
  const report = response.data;
  if (!sameIP(report.geo?.ip || report.geo?.query, ip)) throw Error('IPOK 返回目标不一致');
  const rows = {};
  for (const attempt of report.sourceAttempts || []) {
    const id = optional[attempt.source];
    if (id) rows[id] = {unavailable:true,reason:String(attempt.reason || attempt.status || '')};
  }
  for (const row of report.sources || []) {
    const id = optional[row.source];
    if (!id || row.ok !== true) continue;
    const observed = typeof row.observedAt === 'number' ? row.observedAt : Date.parse(row.observedAt || '');
    if (!Number.isFinite(observed) || observed > Date.now()+60000 || Date.now()-observed>72*3600000) {
      rows[id] = {unavailable:true,reason:'第三方观测时间不明或超过 72 小时'}; continue;
    }
    const flags = {};
    for (const key of ['vpn','proxy','tor','hosting','relay','abuser','crawler','mobile']) {
      if (typeof row.flags?.[key] === 'boolean') flags[key] = row.flags[key];
    }
    const percent = typeof row.risk === 'number' && row.risk >= 0 && row.risk <= 100 ? row.risk : null;
    const type = value => ({isp:'residential',residential:'residential',mobile:'mobile',business:'business',hosting:'hosting',education:'education',government:'government'})[String(value || '').toLowerCase()];
    const fields = {usageType:type(row.usageType || row.networkType),companyType:type(row.companyType)};
    if (flags.hosting === true) fields.usageType ??= 'hosting';
    if (flags.mobile === true) fields.usageType ??= 'mobile';
    if (percent !== null || Object.keys(flags).length || fields.usageType || fields.companyType) rows[id] = {flags,percent,fields,observedAt:new Date(observed).toISOString()};
  }
  if (cachedReports.size >= 32) cachedReports.delete(cachedReports.keys().next().value);
  cachedReports.set(ip,{until:Date.now()+600000,rows});
  return rows;
}

export function fillSource(record, extra, note) {
  const data = {...record.data,flags:{...record.data?.flags}};
  let added = false;
  for (const [key,value] of Object.entries(extra)) {
    if (key === 'flags') {
      for (const [flag,v] of Object.entries(value)) if (data.flags[flag] == null) {data.flags[flag] = v; added = true;}
    } else if (value != null && data[key] == null) {data[key] = value; added = true;}
  }
  if (!added) return record;
  data.sourceNote = [data.sourceNote,note].filter(Boolean).join(' · ');
  return {...record,status:'ok',directStatus:record.directStatus || record.status,directError:record.directError || record.error,error:null,data};
}

export async function lookupDBIPWeb(ip, signal) {
  const response = await getJSON('https://atlas.ipinfo.app/api/v2/geo/'+encodeURIComponent(ip), {signal,timeout:12000});
  if (!response.ok || !sameIP(response.data?.ip,ip)) return null;
  const baseline = response.data.evidence?.find(row => row.source === 'baseline' && row.detail === 'DB-IP City Lite');
  if (!baseline || !/^[A-Z]{2}$/.test(baseline.country_code)) return null;
  return {country:baseline.country_code,region:baseline.region,city:baseline.city,geoVote:true};
}
