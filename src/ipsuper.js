import { sameIP } from './util.js';

const columns = new Map(Object.entries({ IPInfo:'ipinfo', IP2Location:'ip2location', IPRegistry:'ipregistry', 'IP-API':'ipapi', IPData:'ipdata', AbuseIPDB:'abuseipdb', DBIP:'dbip' }));
const types = new Map(Object.entries({ '机房':'hosting', '家宽':'residential', '移动':'mobile', '移动网络':'mobile', '商业':'business', '企业':'business', '教育':'education', '政府':'government' }));

// This bookmark runs on the open report. Read visible cells in column order, including blanks.
function sendReport(destination) {
  if (location.hostname !== 'ipsuper.com') return alert('请在 IPSuper 查询结果页使用此书签。');
  const ip = new URL(location.href).searchParams.get('ip');
  const grid = [...document.querySelectorAll('.attributes-grid')].find(el => el.innerText.includes('公司类型'));
  if (!ip || !grid || document.querySelector('input[placeholder*="IP"]')?.value.trim() !== ip) return alert('请先查询目标 IP，等待多源 IP 类型表显示。');
  const headers = [...grid.querySelectorAll(':scope > .grid-header')].slice(1).map(el => el.innerText.trim());
  const rows = {};
  for (const label of grid.querySelectorAll(':scope > .grid-label')) {
    const cells = [];
    let cell = label.nextElementSibling;
    while (cell?.classList.contains('grid-cell')) {
      cells.push(cell.innerText.trim()); cell = cell.nextElementSibling;
    }
    if (cells.length === headers.length) rows[label.innerText.trim()] = cells;
  }
  if (!rows['使用类型'] || !rows['公司类型']) return alert('表格尚未完整，无法导入。');
  const url = new URL(destination);
  url.searchParams.set('ip', ip);
  url.hash = 'ipsuper=' + encodeURIComponent(JSON.stringify({ip, headers, rows, time:Date.now()}));
  window.open(url.href, '_blank', 'noopener');
}

export function setupImport() {
  const destination = location.origin + location.pathname;
  document.getElementById('ipsuper-bookmark').href = 'javascript:(' + sendReport.toString() + ')(' + JSON.stringify(destination) + ');void 0';
  let report;
  if (location.hash.startsWith('#ipsuper=')) {
    try { if (location.hash.length < 12000) report = JSON.parse(decodeURIComponent(location.hash.slice('#ipsuper='.length))); } catch {}
    history.replaceState(null, '', location.pathname + location.search);
  }
  const result = new Map();
  const ip = new URL(location.href).searchParams.get('ip');
  if (!report || report.ip !== ip || !Array.isArray(report.headers) || report.headers.length > 20 || !Number.isFinite(report.time) || Math.abs(Date.now()-report.time)>900000) return () => null;
  report.headers.forEach((name, i) => {
    const id = columns.get(name);
    if (!id) return;
    const fields = {};
    for (const [field, label] of [['usageType','使用类型'],['companyType','公司类型']]) {
      const row = report.rows?.[label];
      if (!Array.isArray(row) || row.length !== report.headers.length) continue;
      const value = types.get(row[i]);
      if (value) fields[field] = value;
    }
    if (Object.keys(fields).length) result.set(id,fields);
  });
  return (target,id) => sameIP(target,ip) ? result.get(id) : null;
}

export function supplementTypes(record, fields) {
  if (!fields) return record;
  const data = {...record.data};
  const imported = [];
  for (const [field,value] of Object.entries(fields)) {
    if (data[field]) continue;
    data[field] = value;
    imported.push(field);
  }
  if (!imported.length) return record;
  data.type ??= data.usageType;
  data.flags ??= {};
  data.importedFields = imported;
  data.sourceNote = [data.sourceNote,'部分类型经 IPSuper 页面导入'].filter(Boolean).join(' · ');
  return {...record,status:'ok',error:null,directStatus:record.status,directError:record.error,data};
}
