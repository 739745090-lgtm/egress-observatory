const DEFAULT_WEIGHTS = Object.freeze({
  ipinfo: 30, dbip: 20, ip2location:25, ipapiis: 25, ipwhois: 15,
  freeipapi: 10, ipquery: 20, proxycheck:20, ripe: 0,
});

const RISK_FIELDS = Object.freeze([
  { id: 'vpn', label: 'VPN', weight: 15, positiveScore: 30 },
  { id: 'proxy', label: '代理', weight: 25, positiveScore: 25 },
  { id: 'tor', label: 'Tor', weight: 20, positiveScore: 0 },
  { id: 'relay', label: '中继', weight: 5, positiveScore: 50 },
  { id: 'abuser', label: '滥用记录', weight: 25, positiveScore: 0 },
  { id: 'bogon', label: '保留 / 未分配地址', weight: 10, positiveScore: 0 },
]);

const NETWORK_SCORES = Object.freeze({ residential: 100, isp: 90, mobile: 85, business: 70, hosting: 35 });
const NETWORK_LABELS = Object.freeze({ residential: '住宅', isp: 'ISP', mobile: '移动网络', business: '商业网络', hosting: '托管 / 数据中心' });
const FLAG_NAMES = ['vpn', 'proxy', 'tor', 'relay', 'hosting', 'abuser', 'bogon'];
const round = value => Math.round(value * 10) / 10;
const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

function sourceId(value) {
  const id = String(value || '').toLowerCase().trim().replace(/[^a-z0-9]/g, '');
  const aliases = {
    ipinfo: 'ipinfo', ipinfoio: 'ipinfo', dbip: 'dbip', dbipcom: 'dbip',
    ipapiis: 'ipapiis', ipwhois: 'ipwhois', freeipapi: 'freeipapi',
    ipquery: 'ipquery', ipqueryio: 'ipquery',
    ripestat: 'ripe', riperis: 'ripe', ripe: 'ripe',
    abuseipdb: 'abuseipdb', ipqualityscore: 'ipqualityscore', ipqs: 'ipqualityscore',
  };
  return aliases[id] || id || 'unattributed';
}

function canonicalIP(value) {
  if (typeof value !== 'string') return null;
  const ip = value.trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    const parts = ip.split('.').map(Number);
    return parts.every(part => part >= 0 && part <= 255) ? parts.join('.') : null;
  }
  if (!ip.includes(':') || !/^[a-f\d:.]+$/i.test(ip)) return null;
  try { return new URL(`https://[${ip}]/`).hostname.slice(1, -1).toLowerCase(); }
  catch { return null; }
}

function countryCode(value) {
  const code = String(value || '').trim().toUpperCase();
  return /^[A-Z]{2}$/.test(code) && !['XX', 'ZZ'].includes(code) ? code : null;
}

function normalizeASN(value) {
  const asn = String(value || '').trim().replace(/^AS/i, '');
  return /^\d+$/.test(asn) && Number(asn) > 0 ? `AS${asn}` : null;
}

function networkType(value) {
  const type = String(value || '').trim().toLowerCase();
  const aliases = { residential: 'residential', isp: 'isp', mobile: 'mobile', business: 'business', hosting: 'hosting', datacenter: 'hosting', 'data center': 'hosting', 'data centre': 'hosting' };
  return aliases[type] || null;
}

function emptyDimensions() {
  return [
    { id: 'network', label: '网络类型', weight: 20, score: null, coverage: 0, contribution: null, observedWeight: 0, sourceCount: 0, fields: [] },
    { id: 'risk', label: '匿名与滥用风险', weight: 70, score: null, coverage: 0, contribution: null, observedWeight: 0, sourceCount: 0, fields: [] },
    { id: 'region', label: '地区一致性', weight: 10, score: null, coverage: 0, contribution: null, observedWeight: 0, sourceCount: 0, fields: [] },
  ];
}

// A field's owner is independent from the website through which it was fetched.
function fieldOwner(provider, field) {
  const original = provider.record;
  const explicit = field.startsWith('flags.')
    ? original.fieldSources?.flags?.[field.slice(6)] ?? original.fieldSources?.[field]
    : original.fieldSources?.[field];
  const explicitName = typeof explicit === 'string' ? explicit : explicit?.database || explicit?.source;
  const pid = provider.providerId;

  if (pid === 'freeipapi' || original.kind === 'aggregate') {
    return { id: `aggregate:${pid}`, weightKey: pid, corroborative: true, reason: '聚合来源的逐字段上游未完整披露，仅保留旁证。' };
  }
  if (pid === 'ripe' || original.kind === 'routing' || sourceId(original.database) === 'ripe') {
    return { id: 'ripe', weightKey: 'ripe', corroborative: true, reason: 'RIPE 路由信息单独展示，不参与质量评分。' };
  }
  if (pid === 'ipquery') {
    if (['country', 'city', 'asn', 'org'].includes(field)) {
      return { id: 'ipquery-enterprise', weightKey: 'ipquery', corroborative: true, reason: 'Enterprise MMDB 未公开厂商，地理数据仅作旁证，不认定为新的独立数据库。' };
    }
    return { id: 'ipquery-classification', weightKey: 'ipquery', corroborative: false, reason: '使用 IPQuery 的分类结果；不将其未命名的地理库冒认为其他数据库。' };
  }
  if (pid === 'abuseipdb' && ['country', 'city', 'asn', 'org', 'networkType'].includes(field)) {
    return { id: 'ipinfo', weightKey: 'ipinfo', corroborative: false, reason: 'AbuseIPDB 官方注明该基础字段来自 IPinfo，按 IPinfo 去重。' };
  }

  const id = sourceId(explicitName || original.database || pid);
  if (/aggregate|unknown|unattributed|enterprise/.test(id)) {
    return { id, weightKey: pid, corroborative: true, reason: '此字段的底层来源未明确，只保留旁证。' };
  }
  return { id, weightKey: id, corroborative: false, reason: '相同底层来源的同一字段只保留一份有效记录。' };
}

/**
 * Fuse only actual, same-IP observations. This is a transparent heuristic,
 * not a probability of access, account safety, or a provider's own score.
 * No DOM, storage, network, or mutation of caller-owned records is used.
 */
export function assess(records, { weights = {}, expectedCountry = '' } = {}) {
  const configured = { ...DEFAULT_WEIGHTS };
  for (const [key, value] of Object.entries(weights && typeof weights === 'object' ? weights : {})) {
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0) configured[sourceId(key)] = Math.min(value, 1000);
  }
  const weightFor = key => configured[sourceId(key)] ?? 10;
  const conflicts = [];
  const explanations = [];
  const input = Array.isArray(records) ? records : [];
  const providers = input.map((record, index) => {
    const safe = record && typeof record === 'object' ? record : {};
    const id = sourceId(safe.providerId || safe.database || `source${index + 1}`);
    const flags = Object.fromEntries(FLAG_NAMES.map(flag => [flag, typeof safe.flags?.[flag] === 'boolean' ? safe.flags[flag] : null]));
    const ip = canonicalIP(safe.ip);
    const status = ['success', 'error', 'cancelled'].includes(safe.status) ? safe.status : 'error';
    const exclusions = [];
    if (status !== 'success') exclusions.push(status === 'cancelled' ? '本轮已取消。' : '本轮未取得有效响应。');
    if (status === 'success' && !ip) exclusions.push('缺少可识别的查询 IP。');
    return {
      providerId: id, providerName: String(safe.providerName || safe.providerId || safe.database || '未命名来源'),
      database: String(safe.database || safe.providerId || '未声明'), ip,
      status, observedAt: safe.observedAt || null, duration: Number.isFinite(safe.duration) ? safe.duration : null,
      error: safe.error ? String(safe.error) : null, attribution: safe.attribution || null,
      country: countryCode(safe.country), city: safe.city || null, asn: normalizeASN(safe.asn), org: safe.org || null,
      networkType: networkType(safe.networkType), flags, weight: weightFor(id),
      included: status === 'success' && Boolean(ip), exclusions, contributions: [], record: safe,
    };
  });
  const expected = countryCode(expectedCountry);
  if (expectedCountry && !expected) explanations.push('期望国家需使用两位国家代码；本次改用来源共识。');
  const usable = providers.filter(provider => provider.included);
  const targets = [...new Set(usable.map(provider => provider.ip))];
  const consensus = {
    ip: targets.length === 1 ? targets[0] : null,
    expectedCountry: expected, country: null, countrySupport: null,
    countries: [], asn: null, asns: [], networkType: null,
    sourceCount: 0, riskSourceCount: 0, corroboratedRiskCoverage: 0,
  };
  const finish = result => ({ ...result, providers: providers.map(({ record, ...provider }) => provider) });

  if (targets.length !== 1) {
    if (targets.length > 1) {
      conflicts.push({ field: 'ip', kind: 'target', values: targets, message: '来源返回了多个查询 IP，无法合成为同一地址的评估。' });
      usable.forEach(provider => { provider.included = false; provider.exclusions.push('目标 IP 冲突，本轮未纳入综合评分。'); });
      explanations.push('不同 IP 的结果保留在来源记录中；综合评分等待所有有效结果指向同一地址。');
    } else explanations.push('尚无带有效 IP 的成功来源记录，不能计算参考分。');
    return finish({ score: null, coverage: 0, provisional: true, dimensions: emptyDimensions(), consensus, conflicts, explanations });
  }

  const seenExclusions = new Set();
  function noteExclusion(provider, reason) {
    if (!provider.exclusions.includes(reason)) provider.exclusions.push(reason);
    seenExclusions.add(reason);
  }

  function votesFor(field, getValue) {
    const groups = new Map();
    for (const provider of usable) {
      const value = getValue(provider);
      if (value === null || value === undefined || value === '') continue;
      const owner = fieldOwner(provider, field);
      const weight = weightFor(owner.weightKey);
      if (owner.corroborative || weight === 0) {
        const reason = owner.corroborative ? owner.reason : '该底层来源权重为 0，结果展示但不参与评分。';
        noteExclusion(provider, reason);
        provider.contributions.push({ field, value, database: owner.id, weight, included: false, reason });
        continue;
      }
      const date = Date.parse(provider.observedAt || '');
      const entry = { provider, value, database: owner.id, weight, time: Number.isFinite(date) ? date : -Infinity, reason: owner.reason };
      if (!groups.has(owner.id)) groups.set(owner.id, []);
      groups.get(owner.id).push(entry);
    }
    const votes = [];
    for (const [database, entries] of groups) {
      entries.sort((left, right) => right.time - left.time);
      const newest = entries.filter(entry => entry.time === entries[0].time);
      const newestValues = [...new Set(newest.map(entry => String(entry.value)))];
      const values = [...new Set(entries.map(entry => String(entry.value)))];
      if (values.length > 1) {
        conflicts.push({ field, kind: 'within-database', database, values, message: newestValues.length > 1 ? '同库同字段的最新记录互相冲突，暂不计入。' : '同库记录发生变化，采用最新观测并保留分歧。' });
      }
      if (newestValues.length > 1) {
        for (const entry of entries) entry.provider.contributions.push({ field, value: entry.value, database, weight: entry.weight, included: false, reason: '同库最新记录冲突，字段保持未知。' });
        continue;
      }
      const selected = entries[0];
      const vote = { value: selected.value, database, weight: selected.weight, providerId: selected.provider.providerId, providerName: selected.provider.providerName, observedAt: selected.provider.observedAt, via: entries.map(entry => entry.provider.providerId) };
      votes.push(vote);
      for (const entry of entries) entry.provider.contributions.push({ field, value: entry.value, database, weight: entry.weight, included: entry === selected, reason: entry === selected ? selected.reason : '相同底层库同字段已去重，使用最新记录。' });
    }
    return votes;
  }

  function fieldResult(id, label, featureWeight, votes, scoreValue) {
    const denominator = votes.reduce((sum, vote) => sum + vote.weight, 0);
    const score = denominator ? votes.reduce((sum, vote) => sum + scoreValue(vote.value) * vote.weight, 0) / denominator : null;
    const values = [...new Set(votes.map(vote => String(vote.value)))];
    if (values.length > 1) conflicts.push({ field: id, kind: 'between-databases', values: votes.map(vote => ({ database: vote.database, value: vote.value })), message: '独立来源对该字段存在分歧，保留各值并按实际来源权重融合。' });
    return { id, label, weight: featureWeight, score: score === null ? null : round(score), coverage: denominator ? 100 : 0, sourceCount: votes.length, sources: votes, positiveScore: null };
  }

  const typeVotes = votesFor('networkType', provider => provider.networkType);
  const hostingVotes = votesFor('flags.hosting', provider => provider.flags.hosting);
  const networkFields = [
    fieldResult('networkType', '网络类型', 70, typeVotes, value => NETWORK_SCORES[value]),
    fieldResult('hosting', '托管 / 数据中心标记', 30, hostingVotes, value => value ? 35 : 100),
  ];
  networkFields[0].scale = Object.entries(NETWORK_SCORES).map(([id, score]) => ({ id, label: NETWORK_LABELS[id], score }));
  networkFields[1].positiveScore = 35;
  const riskFields = RISK_FIELDS.map(rule => ({
    ...fieldResult(rule.id, rule.label, rule.weight, votesFor(`flags.${rule.id}`, provider => provider.flags[rule.id]), value => value ? rule.positiveScore : 100),
    positiveScore: rule.positiveScore,
  }));
  const countryVotes = votesFor('country', provider => provider.country);
  const asnVotes = votesFor('asn', provider => provider.asn);

  function rankedValues(votes) {
    const totals = new Map();
    for (const vote of votes) {
      if (!totals.has(vote.value)) totals.set(vote.value, { value: vote.value, weight: 0, sources: [] });
      const item = totals.get(vote.value); item.weight += vote.weight; item.sources.push(vote.database);
    }
    const denominator = [...totals.values()].reduce((sum, item) => sum + item.weight, 0);
    return [...totals.values()].map(item => ({ ...item, support: denominator ? round(item.weight / denominator * 100) : 0 })).sort((left, right) => right.weight - left.weight || String(left.value).localeCompare(String(right.value)));
  }
  const countries = rankedValues(countryVotes);
  const asns = rankedValues(asnVotes);
  const types = rankedValues(typeVotes);
  const tiedCountry = countries.length > 1 && countries[0].weight === countries[1].weight;
  consensus.country = countries.length && !tiedCountry ? countries[0].value : null;
  consensus.countrySupport = countries[0]?.support ?? null;
  consensus.countries = countries;
  consensus.asn = asns.length && (asns.length === 1 || asns[0].weight > asns[1].weight) ? asns[0].value : null;
  consensus.asns = asns;
  consensus.networkType = types.length && (types.length === 1 || types[0].weight > types[1].weight) ? types[0].value : null;
  const regionTarget = expected || consensus.country;
  const regionField = fieldResult('country', expected ? `与期望地区 ${expected} 一致` : '国家加权共识', 100, countryVotes, value => value === regionTarget ? 100 : 0);
  if (!expected && tiedCountry) {
    // An exact tie has no preferred country; agreement is still measurable.
    regionField.score = countries[0].support;
  }
  if (asns.length > 1) conflicts.push({ field: 'asn', kind: 'between-databases', values: asns, message: 'ASN 归属存在分歧；该项展示为网络证据，不自动换算风险。' });

  function dimension(id, label, weight, fields) {
    const observedFeatureWeight = fields.filter(field => field.score !== null).reduce((sum, field) => sum + field.weight, 0);
    const score = observedFeatureWeight ? fields.reduce((sum, field) => sum + (field.score === null ? 0 : field.score * field.weight), 0) / observedFeatureWeight : null;
    const coverage = observedFeatureWeight;
    const databases = new Set(fields.flatMap(field => field.sources.map(source => source.database)));
    return { id, label, weight, score: score === null ? null : round(score), coverage: round(coverage), observedWeight: round(weight * coverage / 100), contribution: null, sourceCount: databases.size, fields };
  }
  const dimensions = [
    dimension('network', '网络类型适配', 20, networkFields),
    dimension('risk', '匿名与滥用风险', 70, riskFields),
    dimension('region', '地区一致性', 10, [regionField]),
  ];
  // Related anonymity tags describe overlapping phenomena. Use their strongest
  // observed signal once, retaining each raw field and its missingness below.
  const riskGroup=dimensions.find(item=>item.id==='risk');
  const anonymityFields=riskFields.filter(field=>['vpn','proxy','tor','relay'].includes(field.id)&&field.score!==null);
  const otherRiskFields=riskFields.filter(field=>['abuser','bogon'].includes(field.id)&&field.score!==null);
  const anonymityWeight=anonymityFields.reduce((sum,field)=>sum+field.weight,0);
  const anonymityScore=anonymityFields.length?Math.min(...anonymityFields.map(field=>field.score)):null;
  const knownRiskWeight=anonymityWeight+otherRiskFields.reduce((sum,field)=>sum+field.weight,0);
  if(knownRiskWeight)riskGroup.score=round(((anonymityScore??0)*anonymityWeight+otherRiskFields.reduce((sum,field)=>sum+field.score*field.weight,0))/knownRiskWeight);
  riskGroup.grouping={name:'关联匿名标签',fields:['vpn','proxy','tor','relay'],score:anonymityScore,observedWeight:anonymityWeight,rule:'各字段先按数据库融合，再采用已知匿名标签中的最低分，合并同类信号。'};
  const coverage = round(dimensions.reduce((sum, item) => sum + item.observedWeight, 0));
  const riskDimension = dimensions.find(item => item.id === 'risk');
  const allDatabases = new Set(dimensions.flatMap(item => item.fields.flatMap(field => field.sources.map(source => source.database))));
  const riskDatabases = new Set(riskFields.flatMap(field => field.sources.map(source => source.database)));
  consensus.sourceCount = allDatabases.size;
  consensus.riskSourceCount = riskDatabases.size;
  consensus.corroboratedRiskCoverage = riskFields.filter(field => field.sources.length > 1).reduce((sum, field) => sum + field.weight, 0);
  const enoughForScore = coverage >= 20 && riskDimension.score !== null;
  const total = coverage ? dimensions.reduce((sum, item) => sum + (item.score === null ? 0 : item.score * item.observedWeight), 0) / coverage : null;
  const score = enoughForScore ? round(total) : null;
  for (const item of dimensions) item.contribution = score !== null && item.score !== null ? round(item.score * item.observedWeight / coverage) : null;
  const provisional = score === null || coverage < 80 || riskDimension.coverage < 70 || riskDatabases.size < 2 || consensus.corroboratedRiskCoverage === 0 || conflicts.length > 0;

  for (const provider of providers) provider.included = provider.contributions.some(contribution => contribution.included);
  explanations.push('参考分采用网络类型 20%、匿名与滥用风险 70%、地区一致性 10%。各维度只计算实际返回的字段；当前有效部分按已覆盖权重归一化。');
  explanations.push('覆盖率表示上述指标权重中已取得数据的比例，不是厂商数量、准确率或安全概率。未知字段保持缺失，false 才作为明确的阴性证据。');
  explanations.push('数据库权重仅作用于它实际返回的同一字段；相同底层库的同字段先去重，再融合独立来源。IPinfo 的定位或 ASN 不会补成风险分。');
  explanations.push('VPN、Proxy、Tor、Relay 归为相关匿名信号组：先融合每个字段的数据库证据，再采用组内已观测字段的最低分。相关标签合并处理，明确命中不会被其他阴性标签逐项冲淡；原始字段与缺失范围继续显示。');
  explanations.push('正向风险标记采用公开可见的启发式映射；住宅、ISP、移动和机房类型也使用固定参考刻度。分数不预测 Claude 登录、对话或账号处理结果。');
  explanations.push(expected ? `地区维度比较各库结果与期望国家 ${expected}，不将地区匹配视为 IP 纯净。` : '未设置期望国家时，地区维度描述加权共识与分歧；相同国家只说明地理一致性。');
  if (!enoughForScore) explanations.push('有效覆盖率低于 20%，或尚无匿名 / 滥用字段，暂不生成总分；已有地理和网络数据继续展示。');
  else if (provisional) explanations.push(`当前为暂定参考：指标覆盖率 ${coverage}%，风险来源 ${riskDatabases.size} 个；缺失项和分歧需要随分数一起阅读。`);
  if (riskDatabases.size === 1) explanations.push('风险维度目前仅有一个可归属的数据源，尚未形成多库交叉确认。');
  else if (riskDatabases.size > 1 && consensus.corroboratedRiskCoverage === 0) explanations.push('多个来源目前覆盖不同风险字段，同一风险字段尚无多库交叉确认。');
  explanations.push(...seenExclusions);
  return finish({ score, coverage, provisional, dimensions, consensus, conflicts, explanations });
}
