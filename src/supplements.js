import {sameIP, getJSON} from './util.js';

const optional = {IPQS:'ipqs', IPQualityScore:'ipqs', Scamalytics:'scamalytics', IPHub:'iphub', 'vpnapi.io':'vpnapi'};
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
    const flags = {};
    for (const key of ['vpn','proxy','tor','hosting','relay','abuser','crawler','mobile']) {
      if (typeof row.flags?.[key] === 'boolean') flags[key] = row.flags[key];
    }
    const percent = typeof row.risk === 'number' && row.risk >= 0 && row.risk <= 100 ? row.risk : null;
    if (percent !== null || Object.keys(flags).length) rows[id] = {flags,percent,observedAt:row.observedAt || null};
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
