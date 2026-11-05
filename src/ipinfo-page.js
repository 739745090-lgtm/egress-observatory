import { sameIP } from './util.js';

export function readIPinfoPage(raw, target) {
  const normalized = raw.replace(/\r/g, '').replace(/\u00a0/g, ' ');
  const [header, ...sections] = normalized.split(/^Summary\s*$/m);
  if (!sections.length) throw Error('请复制包含目标地址、Summary 和 Anonymization 的 IPinfo 详情页全文。');
  const addresses = header.trim().split(/\s+/).filter(word => /^[.\da-f:]+$/i.test(word) && /[.:]/.test(word));
  if (!sameIP(addresses.at(-1) || '', target)) throw Error('报告地址与当前查询 IP 不一致。');
  const body = sections.join('\n').split('Table of Contents')[0];
  const field = name => body.match(new RegExp('^' + name + '[ \\t]+([^\\n]+)', 'mi'))?.[1].trim();
  const flags = {};
  for (const [label, key] of [['VPN','vpn'], ['Proxy','proxy'], ['Tor','tor'], ['Relay','relay'], ['Hosting','hosting'], ['Residential Proxy','resProxy']]) {
    const value = body.match(new RegExp('^' + label + '\\s+(Not detected|Detected)\\s*$', 'mi'))?.[1];
    if (value) flags[key] = value.toLowerCase() === 'detected';
  }
  const companyName = field('Company');
  const asnType = field('AS Type')?.toLowerCase();
  const data = {flags,companyName,asnType,city:field('City'),tz:field('Timezone')};
  if (flags.resProxy !== undefined) { data.resProxy = flags.resProxy; delete flags.resProxy; }
  if (flags.hosting === true) data.usageType = data.type = 'hosting';
  if (!Object.keys(flags).length && !companyName && !asnType) throw Error('未识别到 IPinfo 摘要字段。');
  return data;
}

export function mergeIPinfoPage(record, imported) {
  if (!imported) return record;
  const data = {...record.data, flags:{...record.data?.flags}};
  for (const [key,value] of Object.entries(imported)) {
    if (key !== 'flags' && value != null) data[key] ??= value;
  }
  for (const [key,value] of Object.entries(imported.flags)) data.flags[key] ??= value;
  data.sourceNote = 'IPinfo 直查及本人导入的 IPinfo 网页，同库合并。';
  return {...record,status:'ok',data,error:null};
}
