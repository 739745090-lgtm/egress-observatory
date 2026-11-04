const DATABASES = [
  { id: 'ipinfo', name: 'IPinfo', weight: 30 },
  { id: 'maxmind', name: 'MaxMind', weight: 25 },
  { id: 'ip2location', name: 'IP2Location', weight: 25 },
  { id: 'dbip', name: 'DB-IP', weight: 20 },
];
const WEBSITES = [
  { id: 'ping0', name: 'Ping0', direction: '原始风险分，越低越好' },
  { id: 'ippure', name: 'IPPure', direction: '原始风险分，越低越好' },
  { id: 'netcoffee', name: 'Net.Coffee', direction: '原始纯净度，越高越好' },
  { id: 'ipcx', name: 'ip.cx', direction: '原始 IP 评分，越高越好' },
  { id: 'ipsuper', name: 'IPSUPER', direction: '原始站方分数，方向由站方定义' },
];
const PRIVACY = [
  { id: 'vpn', name: 'VPN', penalty: 40 },
  { id: 'proxy', name: 'Proxy', penalty: 45 },
  { id: 'tor', name: 'Tor', penalty: 70 },
  { id: 'relay', name: 'Relay', penalty: 30 },
];
const NETWORK = { residential: 100, isp: 100, mobile: 80, business: 70, hosting: 30 };
const COUNTRIES = new Set('AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split(' '));
let mounted = null;
let latestIPPure = null;
let mountCount = 0;
const latestDatabaseObservations = new Map();

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function localTime(date = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
function publicIP(input) {
  const value = String(input ?? '').trim();
  if (!value) return { error: '请填写目标公网 IPv4 或 IPv6。' };
  if (value.includes(':')) {
    if (!/^[a-fA-F0-9:.]+$/.test(value)) return { error: 'IPv6 地址中不能包含 URL、端口或区域标识。' };
    let ip;
    try { ip = new URL(`http://[${value}]/`).hostname.replace(/^\[|\]$/g, '').toLowerCase(); }
    catch { return { error: 'IPv6 地址格式无效。' }; }
    const halves = ip.split('::');
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    const parts = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
    if (parts.length !== 8 || parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return { error: 'IPv6 地址格式无效。' };
    const words = parts.map((part) => Number.parseInt(part, 16));
    const reserved = (words[0] & 0xe000) !== 0x2000
      || (words[0] === 0x2001 && (words[1] < 0x200 || words[1] === 0xdb8))
      || words[0] === 0x2002 || (words[0] === 0x3fff && (words[1] & 0xf000) === 0);
    return reserved ? { error: '请填写公网 IPv6；本地、文档示例和保留地址不能评分。' } : { value: ip, version: 6 };
  }
  if (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)) return { error: '目标必须是完整 IP，不能填写域名、URL 或端口。' };
  const parts = value.split('.').map(Number);
  if (parts.some((part) => part > 255)) return { error: 'IPv4 每段必须介于 0 和 255。' };
  const [a, b, c] = parts;
  const reserved = a === 0 || a === 10 || a === 127 || a >= 224
    || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
    || (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 192 && b === 88 && c === 99)
    || (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113);
  return reserved ? { error: '请填写公网 IPv4；私网、回环、共享、文档示例和保留地址不能评分。' } : { value: parts.join('.'), version: 4 };
}
function numberValue(input, maximum = Infinity) {
  if (input.validity.badInput) return { error: true };
  if (input.value.trim() === '') return { missing: true };
  const value = Number(input.value);
  return Number.isFinite(value) && value >= 0 && value <= maximum ? { value } : { error: true };
}
function dateValue(input) {
  if (!input.value || !input.validity.valid) return null;
  const date = new Date(input.value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}
function evidenceOrigin(value) {
  if (!value.trim()) return null;
  try {
    const url = new URL(value);
    return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password ? url.origin : null;
  } catch { return null; }
}
function labelControl(text, control, id) {
  const wrapper = el('div', 'score-control');
  const label = el('label', '', text);
  control.id = id;
  label.htmlFor = id;
  wrapper.append(label, control);
  return wrapper;
}
function input(type, value = '') {
  const node = el('input');
  node.type = type;
  node.value = value;
  return node;
}
function select(options) {
  const node = el('select');
  for (const [value, label] of options) {
    const option = el('option', '', label);
    option.value = value;
    node.append(option);
  }
  return node;
}
function calculate() {
  if (!mounted) return null;
  const target = publicIP(mounted.target.value);
  const expectedCountry = mounted.expected.value.trim().toUpperCase();
  const errors = target.error ? [target.error] : [];
  const expectedValid = !expectedCountry || COUNTRIES.has(expectedCountry);
  if (!expectedValid) errors.push('期望国家请填写有效 ISO 两字母代码，例如 JP；留空关闭国家匹配维度。');
  const dimensions = [
    { id: 'country', name: '国家目标匹配', weight: expectedCountry ? 35 : 0 },
    { id: 'network', name: '网络类型偏好', weight: 20 },
    { id: 'privacy', name: '隐私标签偏好', weight: 45 },
  ];
  const databases = DATABASES.map((definition) => {
    const row = mounted.rows[definition.id];
    const parsedWeight = numberValue(row.weight);
    const weightValid = !parsedWeight.error && !parsedWeight.missing;
    const weight = weightValid ? parsedWeight.value : 0;
    if (!weightValid) errors.push(`${definition.name} 权重必须为大于或等于 0 的数字。`);
    const country = row.country.value.trim().toUpperCase();
    const countryValid = !country || COUNTRIES.has(country);
    if (!countryValid) errors.push(`${definition.name} 国家代码无效。`);
    const networkType = row.network.value;
    const privacy = Object.fromEntries(PRIVACY.map((tag) => [tag.id, row.privacy[tag.id].value]));
    const privacyComplete = Object.values(privacy).every((value) => value === 'yes' || value === 'no');
    const hasObservation = Boolean(country) || networkType !== 'unknown' || Object.values(privacy).some((value) => value !== 'unknown');
    const observedAt = hasObservation ? dateValue(row.date) : null;
    if (hasObservation && !observedAt) errors.push(`${definition.name} 抓取时间无效。`);
    const scores = {
      country: country && countryValid && expectedCountry && expectedValid ? (country === expectedCountry ? 100 : 0) : null,
      network: Object.hasOwn(NETWORK, networkType) ? NETWORK[networkType] : null,
      privacy: privacyComplete ? 100 - Math.max(0, ...PRIVACY.filter((tag) => privacy[tag.id] === 'yes').map((tag) => tag.penalty)) : null,
    };
    return {
      id: definition.id, name: definition.name, weight, weightValid, country: country || null, networkType, privacy,
      privacyComplete, observedAt, evidenceOrigin: evidenceOrigin(row.evidence.value), inputMethod: row.inputMethod,
      scores, usable: Boolean(observedAt && weightValid && !target.error && expectedValid),
    };
  });
  const totalDatabaseWeight = databases.reduce((sum, database) => sum + database.weight, 0);
  if (!Number.isFinite(totalDatabaseWeight) || totalDatabaseWeight <= 0) errors.push('数据库权重合计必须大于 0。');
  let weightedScoreSum = 0;
  let availableCellWeight = 0;
  const expectedCellWeight = totalDatabaseWeight * dimensions.reduce((sum, dimension) => sum + dimension.weight, 0);
  for (const dimension of dimensions) {
    let numerator = 0;
    let denominator = 0;
    for (const database of databases) {
      const value = database.scores[dimension.id];
      if (database.usable && database.weight > 0 && dimension.weight > 0 && value !== null) {
        numerator += value * database.weight;
        denominator += database.weight;
        weightedScoreSum += value * database.weight * dimension.weight;
        availableCellWeight += database.weight * dimension.weight;
      }
    }
    dimension.score = denominator > 0 && Number.isFinite(numerator) && Number.isFinite(denominator) ? Math.round(numerator / denominator) : null;
    dimension.availableDatabaseWeight = Number.isFinite(denominator) ? denominator : null;
    dimension.coveragePercent = totalDatabaseWeight > 0 && Number.isFinite(totalDatabaseWeight) && Number.isFinite(denominator) && dimension.weight > 0 ? denominator / totalDatabaseWeight * 100 : null;
  }
  if (!Number.isFinite(weightedScoreSum) || !Number.isFinite(expectedCellWeight)) errors.push('数据库权重过大，请缩小后重算。');
  const coverage = expectedCellWeight > 0 && Number.isFinite(expectedCellWeight) ? availableCellWeight / expectedCellWeight * 100 : 0;
  const score = errors.length === 0 && availableCellWeight > 0 ? Math.round(weightedScoreSum / availableCellWeight) : null;
  const websiteEvidence = WEBSITES.map((definition) => {
    const row = mounted.websites[definition.id];
    const raw = numberValue(row.score, 100);
    return {
      id: definition.id, name: definition.name, direction: definition.direction, rawScore: raw.value ?? null,
      status: raw.error ? 'invalid' : raw.missing ? 'missing' : dateValue(row.date) ? 'recorded' : 'invalid-date',
      observedAt: raw.value === undefined ? null : dateValue(row.date), inputMethod: row.inputMethod,
      databaseProvenance: 'unknown', includedInDatabaseScore: false,
    };
  });
  return { target, expectedCountry, expectedValid, errors, databases, dimensions, websiteEvidence, score, coverage, totalDatabaseWeight, availableCellWeight, expectedCellWeight };
}
function clearObservations() {
  for (const row of Object.values(mounted.rows)) {
    row.country.value = '';
    row.network.value = 'unknown';
    for (const field of Object.values(row.privacy)) field.value = 'unknown';
    row.evidence.value = '';
    row.date.value = localTime();
    row.inputMethod = 'manual';
  }
  for (const row of Object.values(mounted.websites)) {
    row.score.value = '';
    row.date.value = localTime();
    row.inputMethod = 'manual';
  }
}
export function setScoreTarget(value) {
  if (!mounted) return false;
  const parsed = publicIP(value);
  if (parsed.error) return false;
  if (publicIP(mounted.target.value).value !== parsed.value) {
    mounted.target.value = parsed.value;
    clearObservations();
  }
  render();
  return true;
}
function updateObservationButtons() {
  if (!mounted) return;
  const target = publicIP(mounted.target.value);
  const row = mounted.websites.ippure;
  const matched = latestIPPure && !target.error && target.value === latestIPPure.ip;
  row.button.disabled = !matched;
  row.note.textContent = !latestIPPure ? '运行出口检测后，可引用该目标最近的 IPPure 公开 API 旁证。'
    : matched ? `目标匹配 · ${latestIPPure.timeBasis === 'received' ? '接收' : '抓取'}时间 ${new Date(latestIPPure.observedAt).toLocaleString('zh-CN')} · 仅记录旁证。`
      : '已有 IPPure 观测；目标地址完全匹配后才能引用。';
  for (const definition of DATABASES) {
    const databaseRow = mounted.rows[definition.id];
    const observation = latestDatabaseObservations.get(definition.id);
    const matches = observation && !target.error && target.value === observation.ip;
    databaseRow.apiButton.disabled = !matches;
    databaseRow.apiNote.textContent = !observation ? '暂无可引用的原始数据库观测。'
      : matches ? `目标匹配 · 国家 ${observation.country} · ${new Date(observation.observedAt).toLocaleString('zh-CN')}。引用会将其余字段重置为未知。`
        : '已有数据库观测；填写完全匹配的目标地址后可引用。';
  }
}
function render() {
  const result = calculate();
  if (!result) return;
  const summary = mounted.summary;
  mounted.target.setAttribute('aria-invalid', String(Boolean(result.target.error)));
  mounted.expected.setAttribute('aria-invalid', String(!result.expectedValid));
  mounted.targetNote.textContent = result.target.error || '更换目标 IP 或期望国家，会清空旧观测并保留数据库权重。';
  summary.number.textContent = result.score === null ? '—' : String(result.score);
  summary.coverage.textContent = `有效数据覆盖率 ${Number(result.coverage.toFixed(1))}%`;
  summary.meter.value = result.coverage;
  summary.meter.setAttribute('aria-label', summary.coverage.textContent);
  summary.status.textContent = result.errors.length ? '输入待完善' : result.score === null ? '尚无可用观测' : result.coverage < 60 ? '数据不足 · 暂定' : '出口匹配参考分';
  summary.message.textContent = result.errors.length ? result.errors.join(' ')
    : result.score === null ? '录入至少一个正权重数据库的有效维度；缺失数据保持未知。'
      : '分数按有效“维度权重 × 数据库权重”计算，网站旁证独立保存。';
  summary.dimensions.replaceChildren();
  const dimensionWeightTotal = result.dimensions.reduce((sum, dimension) => sum + dimension.weight, 0);
  for (const dimension of result.dimensions) {
    const item = el('div', 'score-breakdown-row');
    const text = dimension.weight === 0 ? '已关闭' : dimension.score === null ? '缺失' : `${dimension.score} / 100 · 覆盖 ${Number(dimension.coveragePercent.toFixed(1))}%`;
    item.append(el('span', '', `${dimension.name} ${Number((dimension.weight / dimensionWeightTotal * 100).toFixed(1))}%`), el('span', 'muted', text));
    summary.dimensions.append(item);
  }
  for (const database of result.databases) {
    const row = mounted.rows[database.id];
    row.weight.setAttribute('aria-invalid', String(!database.weightValid));
    row.mode.textContent = database.inputMethod === 'public-api' ? '底层数据库 · 公开 API 观测' : '底层数据库 · 人工录入';
    const show = (value) => value === null ? '未知' : String(value);
    row.result.textContent = `国家 ${result.expectedCountry ? show(database.scores.country) : '已关闭'} · 网络 ${show(database.scores.network)} · 隐私 ${show(database.scores.privacy)} · 权重 ${database.weightValid ? database.weight : '无效'}`;
  }
  for (const evidence of result.websiteEvidence) {
    const row = mounted.websites[evidence.id];
    row.score.setAttribute('aria-invalid', String(evidence.status === 'invalid'));
    row.result.textContent = `${evidence.inputMethod === 'public-api' ? '公开 API 观测' : '人工录入'} · ${evidence.status === 'invalid' ? '请填写 0–100' : evidence.status === 'invalid-date' ? '请填写有效时间' : evidence.status === 'missing' ? '尚未提供' : '已记录'} · 上游来源未确认 · 不参与总分`;
  }
  updateObservationButtons();
}
export function mountScore(container) {
  if (!container || typeof container.replaceChildren !== 'function') throw new TypeError('mountScore requires a DOM container.');
  const prefix = `db-score-${++mountCount}`;
  const layout = el('div', 'score-layout');
  const inputs = el('div', 'score-inputs');
  const targetCard = el('section', 'card score-target');
  const target = input('text');
  target.placeholder = '公网 IPv4 或 IPv6';
  target.autocomplete = 'off';
  target.spellcheck = false;
  target.required = true;
  const expected = input('text', 'JP');
  expected.maxLength = 2;
  expected.autocomplete = 'off';
  expected.placeholder = 'JP；留空关闭';
  const targetNote = el('p', 'muted');
  targetCard.append(el('h3', '', '绑定评分目标'), labelControl('目标公网 IP', target, `${prefix}-target`), labelControl('期望国家（ISO 两字母代码）', expected, `${prefix}-expected`), targetNote);
  targetCard.append(el('p', 'muted', '对同一个 IP 逐库录入。网站是观测入口，同一个底层数据库只占一行；套餐没有返回的字段保持未知。'));
  inputs.append(targetCard);
  mounted = { target, expected, targetNote, rows: {}, websites: {}, summary: {}, identity: '|JP' };
  for (const definition of DATABASES) {
    const card = el('section', 'card score-row');
    const header = el('div', 'score-row-heading');
    const mode = el('span', 'badge', '底层数据库 · 人工录入');
    header.append(el('h3', '', definition.name), mode);
    const fields = el('div', 'score-row-fields');
    const country = input('text');
    country.maxLength = 2;
    country.placeholder = 'JP；未知留空';
    country.autocomplete = 'off';
    const network = select([['unknown', '未知 / 未提供'], ['residential', 'Residential · 住宅'], ['isp', 'ISP · 固网运营商'], ['mobile', 'Mobile · 移动网络'], ['business', 'Business · 商业网络'], ['hosting', 'Hosting · 数据中心']]);
    const weight = input('number', String(definition.weight));
    weight.min = '0';
    weight.step = 'any';
    const date = input('datetime-local', localTime());
    const evidence = input('url');
    evidence.placeholder = 'https://…（可选）';
    evidence.maxLength = 2048;
    const apiButton = el('button', 'button secondary', `引用最近 ${definition.name} 国家观测`);
    apiButton.type = 'button';
    apiButton.disabled = true;
    const apiNote = el('p', 'muted');
    const row = { country, network, weight, date, evidence, mode, apiButton, apiNote, inputMethod: 'manual', privacy: {}, result: el('p', 'score-row-result') };
    fields.append(labelControl('数据库标注国家', country, `${prefix}-${definition.id}-country`));
    fields.append(labelControl('数据库标注网络类型', network, `${prefix}-${definition.id}-network`));
    const tags = el('div', 'score-ipinfo-tags');
    for (const tag of PRIVACY) {
      const field = select([['unknown', '未知 / 未提供'], ['no', '明确为否'], ['yes', '明确为是']]);
      row.privacy[tag.id] = field;
      field.addEventListener('change', () => { row.inputMethod = 'manual'; render(); });
      tags.append(labelControl(`${tag.name}（命中惩罚 ${tag.penalty}）`, field, `${prefix}-${definition.id}-${tag.id}`));
    }
    fields.append(tags, el('p', 'muted', '隐私维度仅在四项均有明确结果时纳入。普通国家、ASN 查询不提供这些标签，不能据此填“否”。'));
    const metadata = el('div', 'score-weights');
    metadata.append(labelControl('数据库权重（可为 0）', weight, `${prefix}-${definition.id}-weight`), labelControl('来源抓取时间（设备时区）', date, `${prefix}-${definition.id}-date`));
    fields.append(metadata, labelControl('证据网站 URL（可选；不参与权重）', evidence, `${prefix}-${definition.id}-evidence`), apiButton, apiNote);
    card.append(header, fields, row.result);
    mounted.rows[definition.id] = row;
    country.addEventListener('input', () => { country.value = country.value.toUpperCase(); row.inputMethod = 'manual'; render(); });
    weight.addEventListener('input', render);
    for (const field of [network, date, evidence]) field.addEventListener(field.tagName === 'SELECT' ? 'change' : 'input', () => { row.inputMethod = 'manual'; render(); });
    apiButton.addEventListener('click', () => {
      const observation = latestDatabaseObservations.get(definition.id);
      const parsed = publicIP(mounted.target.value);
      if (!observation || parsed.error || observation.ip !== parsed.value) return;
      country.value = observation.country;
      network.value = 'unknown';
      for (const field of Object.values(row.privacy)) field.value = 'unknown';
      date.value = localTime(new Date(observation.observedAt));
      evidence.value = observation.sourceOrigin || '';
      row.inputMethod = 'public-api';
      render();
    });
    inputs.append(card);
  }
  const summaryCard = el('aside', 'card score-summary');
  summaryCard.setAttribute('aria-live', 'polite');
  const number = el('div', 'score-number', '—');
  const status = el('span', 'badge');
  const coverage = el('p');
  const meter = el('progress');
  meter.max = 100;
  meter.value = 0;
  const message = el('p', 'muted');
  const dimensions = el('div', 'score-breakdown');
  summaryCard.append(el('p', 'eyebrow', 'DATABASE EVIDENCE'), el('h3', '', '出口匹配参考分'), number, el('p', 'muted', '/ 100 · 本站自定义偏好'), status, coverage, meter, message, dimensions);
  summaryCard.append(el('p', 'muted', '这份分数衡量出口与所选偏好的匹配程度，不预测 Claude 成功概率或封禁概率。'));
  const clear = el('button', 'button secondary', '清空全部观测');
  clear.type = 'button';
  clear.addEventListener('click', () => { clearObservations(); render(); });
  summaryCard.append(clear);
  mounted.summary = { number, status, coverage, meter, message, dimensions };
  layout.append(inputs, summaryCard);
  const evidenceSection = el('section', 'card score-explanation');
  evidenceSection.append(el('h3', '', '网站评分旁证'), el('p', 'muted', 'Ping0、IPPure、Net.Coffee、ip.cx、IPSUPER 的站方分数保留原始口径。上游数据库尚未确认时标为未知，全部旁证独立于底层库加权分。'));
  const evidenceGrid = el('div', 'score-evidence-grid');
  for (const definition of WEBSITES) {
    const section = el('div', 'score-row');
    const score = input('number');
    score.min = '0';
    score.max = '100';
    score.step = 'any';
    score.placeholder = '0–100；缺失留空';
    const date = input('datetime-local', localTime());
    const row = { score, date, inputMethod: 'manual', result: el('p', 'muted') };
    section.append(el('h4', '', definition.name), el('p', 'muted', definition.direction), labelControl('网站原始分数', score, `${prefix}-${definition.id}-score`), labelControl('抓取时间（设备时区）', date, `${prefix}-${definition.id}-time`));
    for (const field of [score, date]) field.addEventListener('input', () => { row.inputMethod = 'manual'; render(); });
    if (definition.id === 'ippure') {
      row.button = el('button', 'button secondary', '使用最近 IPPure 观测');
      row.button.type = 'button';
      row.button.disabled = true;
      row.note = el('p', 'muted');
      row.button.addEventListener('click', () => {
        const parsed = publicIP(mounted.target.value);
        if (!latestIPPure || parsed.error || parsed.value !== latestIPPure.ip) return;
        score.value = String(latestIPPure.fraudScore);
        date.value = localTime(new Date(latestIPPure.observedAt));
        row.inputMethod = 'public-api';
        render();
      });
      section.append(row.button, row.note);
    }
    section.append(row.result);
    mounted.websites[definition.id] = row;
    evidenceGrid.append(section);
  }
  evidenceSection.append(evidenceGrid);
  const explanation = el('section', 'card score-explanation');
  explanation.append(el('h3', '', '透明计算方法'));
  explanation.append(el('p', '', '默认数据库权重：IPinfo 30、MaxMind 25、IP2Location 25、DB-IP 20。IPinfo 略高，其他库提供交叉对照；权重属于本站经验取值，全部可修改。相同数据库经多个网站展示时只录入一次。'));
  explanation.append(el('p', '', '维度权重：国家匹配 35%、网络类型 20%、隐私标签 45%。国家匹配记 100，不匹配记 0。住宅 / ISP 记 100，移动网络 80，商业网络 70，数据中心 30。隐私分为 100 − 最大命中惩罚：Tor 70、Proxy 45、VPN 40、Relay 30；四项明确为否时为 100。'));
  explanation.append(el('p', '', '各维度先按有效数据库权重加权展示；总分 = round(Σ(单元得分 × 维度权重 × 数据库权重) / Σ(有效单元权重))。覆盖率 = 有效单元权重 / 预期单元权重。缺失字段保持未知，零权重数据库不参与计算。'));
  explanation.append(el('p', '', '期望国家留空时关闭国家匹配维度，剩余网络与隐私维度按 20:45 归一。覆盖率低于 60% 标为“数据不足 · 暂定”。覆盖率表达数据完整度，不代表统计置信度。'));
  explanation.append(el('p', '', '数据库之间也可能共享上游与地理馈送。标签含义随产品与版本而异，住宅、代理或中继等标签不能直接推导账号结局；来源网站、抓取时间和原始字段应一并核对。'));
  explanation.append(el('p', 'muted', '全部录入保留在当前页面内存。导出默认隐藏目标 IP；证据 URL 仅导出网站 origin，排除路径、参数和凭据。更换目标或期望国家清空旧观测，权重保留。'));
  container.replaceChildren(layout, evidenceSection, explanation);
  const changeTarget = () => {
    expected.value = expected.value.toUpperCase();
    const parsed = publicIP(target.value);
    const identity = `${parsed.value || target.value.trim()}|${expected.value.trim()}`;
    if (identity !== mounted.identity) { clearObservations(); mounted.identity = identity; }
    render();
  };
  target.addEventListener('input', changeTarget);
  expected.addEventListener('input', changeTarget);
  render();
}
export function setCurrentIPPure(inputData) {
  const data = inputData?.data && typeof inputData.data === 'object' ? inputData.data : inputData;
  const target = publicIP(data?.ip);
  const raw = data?.fraudScore;
  const value = typeof raw === 'number' || (typeof raw === 'string' && /^\d+(\.\d+)?$/.test(raw)) ? Number(raw) : NaN;
  const observedAt = inputData?.observedAt ?? data?.observedAt;
  const time = observedAt === undefined ? new Date() : new Date(observedAt);
  latestIPPure = target.error || !Number.isFinite(value) || value < 0 || value > 100 || !Number.isFinite(time.getTime()) ? null
    : { ip: target.value, fraudScore: value, observedAt: time.toISOString(), timeBasis: observedAt === undefined ? 'received' : 'observed' };
  updateObservationButtons();
}
export function setDatabaseObservation(observation) {
  if (!observation || !DATABASES.some((database) => database.id === observation.database)) return;
  const target = publicIP(observation.ip);
  const country = String(observation.country ?? '').trim().toUpperCase();
  const time = new Date(observation.observedAt);
  if (target.error || !COUNTRIES.has(country) || observation.observedAt == null || !Number.isFinite(time.getTime())) {
    latestDatabaseObservations.delete(observation.database);
  } else {
    latestDatabaseObservations.set(observation.database, {
      ip: target.value, country, observedAt: time.toISOString(), sourceOrigin: evidenceOrigin(String(observation.sourceUrl ?? '')),
    });
  }
  updateObservationButtons();
}
export function getScoreReport({ mask = true } = {}) {
  const result = calculate();
  if (!result) return { schemaVersion: 2, kind: 'database-weighted-egress-match', status: 'not-mounted', score: null };
  const finite = (value) => Number.isFinite(value) ? value : null;
  const databases = result.databases.map((database) => {
    if (!mask || !database.evidenceOrigin) return database;
    const hostname = new URL(database.evidenceOrigin).hostname;
    const numericHost = hostname.includes(':') || /^\d+(\.\d+){3}$/.test(hostname);
    return numericHost ? { ...database, evidenceOrigin: '[已隐藏 IP 来源]' } : database;
  });
  return {
    schemaVersion: 2, kind: 'database-weighted-egress-match', generatedAt: new Date().toISOString(),
    targetIP: result.target.value ? (mask ? '[已隐藏]' : result.target.value) : null,
    targetIPMasked: Boolean(mask), targetValid: !result.target.error, expectedCountry: result.expectedCountry || null,
    status: result.errors.length ? 'invalid-input' : result.score === null ? 'no-data' : result.coverage < 60 ? 'provisional' : 'reference-only',
    score: result.score, coveragePercent: Number(result.coverage.toFixed(2)), errors: result.errors,
    totalDatabaseWeight: finite(result.totalDatabaseWeight), availableCellWeight: finite(result.availableCellWeight), expectedCellWeight: finite(result.expectedCellWeight),
    dimensions: result.dimensions, databases, websiteEvidence: result.websiteEvidence,
    formula: 'round(sum(cellScore * dimensionWeight * databaseWeight) / sum(available cell weights))',
    boundary: '本站自定义出口偏好；底层库逐库计权，网站评分仅作旁证；不预测 Claude 可用性或封禁概率。',
  };
}
