/** DOM rendering. All external text goes through esc(). */
import { esc, countryName, maskIP, formatOffset, zoneOffset } from './util.js';
import { SOURCES } from './sources.js?v=3.2';
import { DNSBLS, CIDR_LISTS } from './blocklists.js';
import { CATEGORIES, TYPE_LABEL } from './score.js';
import { captchaConfig } from './captcha.js';

const $ = id => document.getElementById(id);

const ICONS = {
  good: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7"/><path d="M4.8 8.2l2.1 2.1 4.3-4.6"/></svg>',
  warn: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7"/><path d="M8 4.5v4.2M8 11.2v.3"/></svg>',
  bad: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7"/><path d="M5.6 5.6l4.8 4.8M10.4 5.6l-4.8 4.8"/></svg>',
  info: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7"/><path d="M8 7.2v4.2M8 4.6v.3"/></svg>',
  none: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7"/><path d="M5.5 8h5"/></svg>',
  pending: '<svg viewBox="0 0 16 16" aria-hidden="true" class="spin"><circle cx="8" cy="8" r="6" stroke-dasharray="26 12"/></svg>',
};
const icon = level => `<span class="ico ico-${level}">${ICONS[level] || ICONS.none}</span>`;
const flag = code => code ? `<img class="flag" src="https://flagcdn.com/w40/${esc(code.toLowerCase())}.png" alt="" width="20" height="15" loading="lazy" referrerpolicy="no-referrer">` : '';
const place = (code, city) => code ? `${flag(code)}<span>${city ? `${esc(city)}，` : ''}${esc(countryName(code))}</span>` : '<span class="muted">—</span>';
const ipSpan = (ip, masked) => `<span class="ipv" data-ip="${esc(ip)}">${esc(masked ? maskIP(ip) : ip)}</span>`;
const pen = pts => pts ? `<span class="pen">−${Math.round(pts)}</span>` : '';
const asnLink = asn => asn ? `<a class="asn" href="https://bgp.tools/as/${asn}" target="_blank" rel="noopener noreferrer">AS${asn}</a>` : '—';
const pct = value => typeof value === 'number' ? `${Math.round(value * 100)}%` : '—';
const fmt = value => (Math.round(value * 10) / 10).toString();

// ---------- tags: gradient for mixed evidence, "?" for low certainty, hover / focus for the why ----------

const TONES = { residential: 'good', isp: 'good', native: 'good', mobile: 'teal', business: 'sky', hosting: 'warn', cdn: 'orange', broadcast: 'warn', leased: 'warn', transit: 'violet', education: 'slate', government: 'slate', bad: 'bad' };
const IP_TYPE_LABEL = { residential: '家宽', mobile: '移动网络', business: '商业宽带', hosting: '机房', education: '教育网' };
const ASN_LABEL = { isp: 'ISP', mobile: '移动运营商', hosting: '机房 / 云', cdn: 'CDN', transit: '骨干网', business: '企业网', education: '教育网', government: '政府网' };
const UNSURE = 0.6;

/** parts: [{ value, share }] sorted desc. Shows up to two parts; the gradient sits at their split. */
function mixTag({ parts, labels, certainty = 1, tip = '', size = '' }) {
  const shown = (parts || []).filter((part, index) => index === 0 || part.share >= 0.2).slice(0, 2);
  if (!shown.length) return '<span class="muted">—</span>';
  const mixed = shown.length === 2;
  const name = value => (typeof labels === 'function' ? labels(value, mixed) : labels[value]) || value;
  const c1 = `var(--t-${TONES[shown[0].value] || 'muted'})`;
  const c2 = mixed ? `var(--t-${TONES[shown[1].value] || 'muted'})` : c1;
  const split = mixed ? Math.round(shown[0].share / (shown[0].share + shown[1].share) * 100) : 100;
  const unsure = certainty < UNSURE;
  return `<span class="tag2 ${size}${mixed ? ' mixed' : ''}${unsure ? ' unsure' : ''}" tabindex="0" data-tip="${esc(tip)}" style="--c1:${c1};--c2:${c2};--split:${split}%">`
    + `<span class="tag2-text">${esc(shown.map(part => name(part.value)).join(' / '))}</span>${unsure ? '<i class="q" aria-label="不确定">?</i>' : ''}</span>`;
}

const certaintyLine = value => `确定度 ${pct(value)}${value < UNSURE ? '：证据不足或互相矛盾，所以标了 ?' : ''}`;

function typeTag(result) {
  const t = result.checks.type;
  if (!t.value) return '<span class="muted">—</span>';
  const lines = ['IP 网络类型（这个地址本身）', t.mix.map(part => `${IP_TYPE_LABEL[part.value] || part.value} ${pct(part.share)}`).join(' · ')];
  if (t.from === 'sources') {
    for (const vote of t.votes) lines.push(`${vote.by.join('、')} 标为${IP_TYPE_LABEL[vote.value] || vote.value}`);
    if (t.hosting.yes) lines.push(`标记机房：${t.hosting.by.join('、')}`);
  }
  if (t.from === 'exclusion') lines.push('没有来源给出明确类型；只是没被标成机房，按排除法记为家宽');
  if (t.from === 'asn') lines.push('没有来源给出这个 IP 的类型，按所属 ASN 的类型推断');
  if (t.hosting.clear.length) lines.push(`未标记机房：${t.hosting.clear.join('、')}`);
  lines.push(certaintyLine(t.certainty));
  return mixTag({ parts: t.mix, labels: IP_TYPE_LABEL, certainty: t.certainty, tip: lines.join('\n') });
}

function asnTag(run, size = '') {
  const inferred = run.asnProfile?.inferred;
  if (!inferred?.cls) return run.asnProfile ? '<span class="muted">未知</span>' : '<span class="muted">—</span>';
  const lines = [`运营商类型（按 AS${run.asnProfile.asn} 推断）`, inferred.mix.slice(0, 4).map(part => `${ASN_LABEL[part.value]} ${pct(part.share)}`).join(' · '),
    `推断置信 ${pct(inferred.confidence)}${inferred.confidence < UNSURE ? '：依据少或互相矛盾，所以标了 ?' : ''}`, '依据：', ...inferred.reasons.map(reason => `· ${reason}`)];
  return mixTag({ parts: inferred.mix, labels: ASN_LABEL, certainty: inferred.confidence, tip: lines.join('\n'), size });
}

function nativeTag(result) {
  const n = result.checks.native;
  if (n.native === null) return '';
  const country = result.summary.country;
  const share = n.nativeShare ?? (n.native ? 1 : 0);
  const parts = [{ value: 'native', share }, { value: 'broadcast', share: 1 - share }].sort((a, b) => b.share - a.share);
  const labels = (value, mixed) => value === 'native' ? (mixed ? '原生' : '原生 IP') : (mixed ? `广播·${n.regCountry === country ? n.regVotes.find(item => item.value !== country)?.value : n.regCountry}` : `广播 IP · 注册地 ${n.regCountry}`);
  const lines = ['IP 原生性：注册国家与定位国家是否一致', `定位国家 ${country}`, ...n.regVotes.map(item => `注册地 ${item.value}：${item.by.join('、')}`), certaintyLine(n.certainty)];
  return mixTag({ parts, labels, certainty: n.certainty, tip: lines.join('\n') });
}

function leaseTag(result) {
  const lease = result.checks.lease;
  if (!lease || !(lease.leased || lease.possible)) return '';
  const certainty = lease.confidence >= 0.7 ? 1 : 0.5;
  return mixTag({ parts: [{ value: 'leased', share: 1 }], labels: { leased: lease.leased ? '租赁地址段' : '可能租赁' }, certainty,
    tip: ['地址段像是租来或转售的（代理商常用）', `把握 ${pct(lease.confidence)}`, ...lease.reasons.map(reason => `· ${reason}`)].join('\n') });
}

function asnRepTag(run, result) {
  const rep = run.asnRep;
  if (!rep) return run.asnProfile?.routes ? '<span class="muted">计算中…</span>' : '<span class="muted">—</span>';
  const tone = rep.ratio >= 15 ? 'bad' : rep.ratio >= 2 ? 'warn' : 'good';
  const label = rep.ratio >= 15 ? '较差' : rep.ratio >= 5 ? '一般偏差' : rep.ratio >= 2 ? '一般' : rep.ratio < 0.5 ? '良好' : '正常';
  const tip = ['ASN 信誉：整个 ASN 的地址里近期有多少在威胁列表上', `宣告 ${rep.size.toLocaleString()} 个 IPv4，近期上榜 ${rep.listed.toLocaleString()} 次`,
    ...Object.entries(rep.counts).filter(([, count]) => count).map(([name, count]) => `· ${name} ${count}`),
    `密度 ${rep.per10k} / 万，全网平均 ${rep.baseline} / 万，约为平均的 ${rep.ratio} 倍`].join('\n');
  return `${mixTag({ parts: [{ value: tone === 'good' ? 'residential' : tone === 'warn' ? 'hosting' : 'bad', share: 1 }], labels: { residential: label, hosting: label, bad: label }, tip })} <span class="muted small">${rep.per10k} / 万 · 平均 ${rep.ratio} 倍</span>`;
}

function listValue(item) {
  if (item.status !== 'ok') return '';
  const n = item.neighbours;
  const neighbours = !n || !['attack', 'spam', 'proxy'].includes(item.kind) ? '' : n.whole ? ' · 整段在列' : n.ips.length ? ` · 邻居 ${n.ips.length}` : '';
  return `${item.listed ? `命中 ${item.match}` : '未命中'}${neighbours}`;
}

let tipNode = null; let tipFor = null;
export function initTooltips() {
  tipNode = document.createElement('div');
  tipNode.id = 'tip'; tipNode.setAttribute('role', 'tooltip');
  document.body.append(tipNode);
  const show = target => {
    tipFor = target;
    tipNode.textContent = target.dataset.tip;
    tipNode.classList.add('on');
    const rect = target.getBoundingClientRect(); const box = tipNode.getBoundingClientRect();
    const above = rect.top - box.height - 8;
    const top = above >= 8 ? above : rect.bottom + 8;
    const left = Math.min(Math.max(8, rect.left + rect.width / 2 - box.width / 2), innerWidth - box.width - 8);
    tipNode.style.transform = `translate(${Math.round(left)}px, ${Math.round(top)}px)`;
  };
  const hide = () => { tipFor = null; tipNode.classList.remove('on'); };
  const pick = event => event.target.closest?.('[data-tip]');
  document.addEventListener('pointerover', event => { const target = pick(event); if (target?.dataset.tip) { if (target !== tipFor) show(target); } else if (tipFor) hide(); });
  document.addEventListener('focusin', event => { const target = pick(event); if (target?.dataset.tip) show(target); });
  document.addEventListener('focusout', hide);
  addEventListener('scroll', hide, { passive: true });
  document.addEventListener('keydown', event => { if (event.key === 'Escape') hide(); });
}
export function refreshTip() { if (tipFor && !tipFor.isConnected) { tipFor = null; tipNode?.classList.remove('on'); } }

function itemPts(result, id) {
  return result.categories.flatMap(category => category.items).filter(item => item.id === id || item.id.startsWith(`${id}-`)).reduce((sum, item) => sum + item.pts, 0);
}

// ---------- hero ----------

export function renderHero(run, result, view) {
  const g = result.grade;
  const pending = result.confidence.pending;
  const circumference = 2 * Math.PI * 52;
  const issues = result.categories.flatMap(category => category.items).sort((a, b) => b.pts - a.pts).slice(0, 5);
  $('score-ring').innerHTML = `
    <svg viewBox="0 0 120 120" class="ring tone-${g.tone}" aria-hidden="true">
      <circle cx="60" cy="60" r="52" class="ring-track"/>
      <circle cx="60" cy="60" r="52" class="ring-value" stroke-dasharray="${circumference}" stroke-dashoffset="${circumference * (1 - result.score / 100)}"/>
    </svg>
    <div class="ring-text"><strong>${result.score}</strong><span class="tone-${g.tone}">${g.letter} 级</span></div>`;
  $('score-ring').setAttribute('aria-label', `综合分 ${result.score}，${g.letter} 级`);
  $('verdict').innerHTML = `
    <div class="verdict-head"><span class="verdict-label tone-${g.tone}">${esc(g.label)}</span>
      <span class="confidence c-${result.confidence.level}" tabindex="0" data-tip="评分可信程度&#10;成功来源 ${result.confidence.sources} 个；匿名类字段 ${result.confidence.anonSources} 个来源">置信度${{ high: '高', medium: '中', low: '低' }[result.confidence.level]}</span>
      ${pending ? `<span class="pending-note">${icon('pending')}还有 ${pending} 个来源在路上</span>` : ''}</div>
    <p class="verdict-text">${esc(result.verdict)}</p>
    ${run.self ? `<p class="score-split"><span>IP 信誉 <b>${result.ipScore}</b></span><span>连接实测 <b class="${result.liveDelta < 0 ? 'neg' : ''}">${result.liveDelta === 0 ? '±0' : result.liveDelta}</b></span><span>综合 <b>${result.score}</b></span></p>`
      : '<p class="score-split muted">查询的不是本机出口，只计算 IP 信誉，连接实测不适用。<button type="button" class="link-btn" data-self-check>改测本机出口 →</button></p>'}
    <ul class="deductions">${issues.map(item => `<li tabindex="0" data-tip="${esc(item.detail || '')}"><span class="dot"></span><b>−${fmt(item.pts)}</b> ${esc(item.label)}</li>`).join('')}${result.bonus.items.slice(0, 3).map(item => `<li class="plus" tabindex="0" data-tip="${esc(item.detail || '')}"><span class="dot"></span><b>+${fmt(item.pts)}</b> ${esc(item.label)}</li>`).join('')}${!issues.length && !result.bonus.items.length ? '<li class="clean"><b>0</b> 没有扣分项</li>' : ''}</ul>`;
  const s = result.summary;
  $('addr').innerHTML = `
    <div class="addr-row"><dt>IP</dt><dd>${ipSpan(run.ip, view.masked)} <span class="tag">IPv${run.v}</span>${run.self ? '<span class="tag tag-self">你的出口</span>' : ''}</dd></div>
    <div class="addr-row"><dt>位置</dt><dd>${place(s.country, s.city)}</dd></div>
    <div class="addr-row"><dt>所属网络</dt><dd>${asnLink(s.asn)} <span class="muted">${esc(s.org || '')}</span></dd></div>
    <div class="addr-row"><dt>类型</dt><dd>${typeTag(result)} ${nativeTag(result)} ${leaseTag(result)}</dd></div>
    <div class="addr-row"><dt>运营商类型</dt><dd>${asnTag(run)}${run.asnProfile?.pdb?.type ? ` <span class="muted small">PeeringDB：${esc(run.asnProfile.pdb.type)}</span>` : ''}</dd></div>
    <div class="addr-row"><dt>主机名</dt><dd class="mono">${esc(s.hostname || '–')}</dd></div>
    <div class="addr-row"><dt>时区</dt><dd>${esc(s.ipTimezone || '—')} <span class="muted">${s.ipOffset === null || s.ipOffset === undefined ? '' : formatOffset(s.ipOffset)}</span></dd></div>`;
}

export function renderEgress(egress, run, view) {
  const box = $('egress');
  if (!egress) { box.innerHTML = '<p class="muted">正在识别你的出口…</p>'; return; }
  const rows = egress.results.map(item => {
    const target = run && item.ip && run.ip === item.ip;
    return `<li class="${target ? 'is-target' : ''}">
      <span class="eg-name">${esc(item.name)}</span>
      ${item.status === 'pending' ? `<span class="muted">${icon('pending')}</span>` : item.ip ? `<button type="button" class="eg-ip" data-check="${esc(item.ip)}" title="检测这个 IP">${ipSpan(item.ip, view.masked)}</button>` : '<span class="muted">无响应</span>'}
    </li>`;
  }).join('');
  const note = egress.split ? `<p class="eg-note warn">${icon('warn')}${esc(egress.summary)}</p>`
    : egress.domesticDiffers ? `<p class="eg-note">${icon('info')}${esc(egress.summary)}</p>` : '';
  box.innerHTML = `<ul class="egress-list">${rows}</ul>${note}
    ${egress.v6 ? '' : '<p class="muted small">没有发现 IPv6 出口。</p>'}`;
}

// ---------- verdict tiles ----------

function tile({ label, level, value, sub, pts, title }) {
  return `<div class="tile lv-${level}${pts >= 1 ? ' has-pen' : ''}" ${title ? `tabindex="0" data-tip="${esc(title)}"` : ''}>
    <div class="tile-head">${icon(level)}<span class="tile-label">${esc(label)}</span>${pen(pts)}</div>
    <div class="tile-value">${value}${sub ? ` <small>${sub}</small>` : ''}</div>
  </div>`;
}

export function renderChecks(run, result) {
  const c = result.checks;
  const loading = level => (level === 'none' && result.confidence.pending ? 'pending' : level);
  const t = c.type;
  const typeSub = t.from === 'asn' ? '按 ASN 推断' : t.from === 'exclusion' ? `未被标记机房 · ${t.hosting.of} 源` : `机房 ${t.hosting.yes}/${t.hosting.of}`;
  const anon = c.anon;
  const anonText = anon.E > 0 ? [anon.proxy.yes ? `代理 ${anon.proxy.yes}/${anon.proxy.of}` : '', anon.vpn.yes ? `VPN ${anon.vpn.yes}/${anon.vpn.of}` : ''].filter(Boolean).join(' · ') : '未检测到';
  const geo = c.geo;
  const geoText = !geo.country ? '—' : geo.countries.length > 1 ? `${geo.countries.map(item => `${esc(item.value)} ×${item.by.length}`).join(' · ')}` : `${flag(geo.country)}${geo.count} 个来源一致`;
  const native = c.native;
  const abuse = c.abuse;
  const abuseText = abuse.level === 'none' ? '没有数据' : abuse.lists.length ? esc(abuse.lists.join('、')) : abuse.sfs?.appears ? `垃圾注册 ${abuse.sfs.appears} 次` : abuse.abuser.yes ? `${abuse.abuser.yes} 个来源标记` : '无记录';
  const tiles = [
    { label: '网络类型', level: loading(t.level), value: t.label ? typeTag(result) : '—', sub: t.label ? typeSub : '', pts: itemPts(result, 'hosting') + itemPts(result, 'business') },
    { label: '原生 IP', level: loading(native.level), value: native.native === null ? '—' : `${flag(native.regCountry)}${nativeTag(result)}`, sub: '', pts: itemPts(result, 'broadcast') },
    { label: '定位一致', level: loading(geo.level), value: geoText, sub: geo.families > 1 ? `${geo.families} 个独立库` : '', pts: itemPts(result, 'geo-split') },
    { label: '代理 / VPN', level: loading(anon.level), value: anonText, sub: anon.E > 0 ? '' : `${Math.max(anon.vpn.of, anon.proxy.of)} 源`, pts: itemPts(result, 'proxy') + itemPts(result, 'vpn') + itemPts(result, 'relay') + itemPts(result, 'crawler') + itemPts(result, 'shared') },
    { label: 'Tor', level: loading(c.tor.level), value: c.tor.E > 0 ? `是 · ${esc(c.tor.by.join('、'))}` : c.tor.of ? '不是' : '—', sub: c.tor.of ? `${c.tor.of} 源` : '', pts: itemPts(result, 'tor') },
    { label: '欺诈分数', level: loading(c.risk.level), value: c.risk.value === null ? '—' : String(c.risk.value), sub: c.risk.entries.length ? `${c.risk.entries.length} 个来源加权` : '', pts: itemPts(result, 'risk') },
    { label: '滥用记录', level: loading(abuse.level), value: abuseText, sub: '', pts: itemPts(result, 'abuser') + itemPts(result, 'firehol') + itemPts(result, 'sfs') + itemPts(result, 'vulns') },
    { label: '黑名单', level: loading(c.dnsbl.level), value: c.dnsbl.listed.length ? `收录 ${c.dnsbl.listed.length}` : c.dnsbl.checked ? '未收录' : '—', sub: c.dnsbl.checked ? `${c.dnsbl.checked} 个` : '', pts: itemPts(result, 'dnsbl'), title: c.dnsbl.listed.join('、') },
    { label: 'ASN 一致性', level: loading(c.asn.level), value: c.asn.consistency ? (c.asn.consistency.ok ? (c.asn.consistency.warn ? '需留意' : '一致') : '冲突') : '—', sub: c.asn.consistency ? asnTag(run) : '', pts: itemPts(result, 'asn-conflict') + itemPts(result, 'asn-transit') + itemPts(result, 'leased'), title: c.asn.consistency?.text },
    neighbourTile(c.neighbours, result, loading),
    { label: 'ASN 信誉', level: c.asnRep.level === 'none' ? (run.asnProfile && !run.asnProfile.routes ? 'none' : 'pending') : c.asnRep.level, value: c.asnRep.ratio === undefined ? '—' : c.asnRep.ratio >= 15 ? '较差' : c.asnRep.ratio >= 2 ? '一般' : c.asnRep.ratio < 0.5 ? '良好' : '正常', sub: c.asnRep.ratio === undefined ? '' : `滥用密度 ${c.asnRep.ratio} 倍均值`, pts: itemPts(result, 'asn-abuse') + itemPts(result, 'asn-bots') + itemPts(result, 'rpki'), title: c.asnRep.ratio === undefined ? '' : `整个 ASN 每万个地址有 ${c.asnRep.per10k} 个近期上榜，全网平均 ${c.asnRep.baseline}` },
    { label: '开放端口', level: loading(c.ports.level), value: c.ports.ports.length ? esc(c.ports.ports.slice(0, 4).join(', ')) + (c.ports.ports.length > 4 ? '…' : '') : c.ports.level === 'none' ? '—' : '未发现', sub: c.ports.tags.length ? esc(c.ports.tags.join(' ')) : '' },
  ];
  $('checks').innerHTML = tiles.map(tile).join('');
}

function neighbourTile(nb, result, loading) {
  if (nb.level === 'none') return { label: '邻居网段', level: loading('none'), value: '—', sub: '' };
  const value = nb.whole?.length ? '整段上榜' : nb.count ? `${nb.count} 个邻居上榜` : nb.tor ? '有 Tor 节点' : '干净';
  const tip = [`同一 /24（${nb.prefix}）里其他地址的表现`, nb.whole?.length ? `整段被列入：${nb.whole.join('、')}` : '', nb.lists?.length ? `上榜：${nb.lists.join('、')}` : '',
    nb.sample?.length ? `例如 ${nb.sample.join('、')}` : '', nb.tor ? `Tor 中继 ${nb.tor} 个` : '', nb.abuseipdb ? `AbuseIPDB 30 天内被举报 ${nb.abuseipdb.reported} 个` : '', `查了 ${nb.checked} 个威胁列表`].filter(Boolean).join('\n');
  return { label: '邻居网段', level: nb.level, value, sub: esc(nb.prefix || ''), pts: itemPts(result, 'block-listed') + itemPts(result, 'neighbours') + itemPts(result, 'neighbour-tor'), title: tip };
}

const USE_LABELS = { stream: '流媒体', ai: 'AI 服务', captcha: '验证码', account: '注册付款', mail: '发邮件', social: '社媒 / TikTok' };
const USE_LEVEL = { good: '可以', warn: '看情况', bad: '不建议' };
export function renderUses(result) {
  $('uses').innerHTML = Object.entries(USE_LABELS).map(([id, name]) => {
    const use = result.uses[id];
    return `<div class="use lv-${use?.level || 'none'}" tabindex="0" data-tip="${esc(use?.why || '')}"><span class="use-name">${esc(name)}</span><span class="use-level">${esc(USE_LEVEL[use?.level] || '—')}</span><span class="use-why">${esc(use?.why || '')}</span></div>`;
  }).join('');
}

// ---------- live probes ----------

export function renderLive(run, result, egress, view) {
  const section = $('live-section');
  section.hidden = !run.self;
  if (!run.self) return;
  const p = run.probes;
  const lv = key => result.live[key] || (p[key]?.status === 'error' ? 'none' : p[key] ? 'info' : 'pending');
  const tiles = [];
  const w = p.webrtc;
  tiles.push({ label: 'WebRTC', level: lv('webrtc'), value: !w ? '检测中' : w.status !== 'ok' ? '失败' : !w.supported ? '已禁用' : w.leak ? `泄漏 ${w.leakIPs.map(ip => ipSpan(ip, view.masked)).join(' ')}` : w.srflx.length ? '无泄漏' : 'UDP 不通', sub: w?.status === 'ok' ? esc(w.leak ? '' : w.srflx.length ? 'UDP 出口一致' : '') : '', pts: itemPts(result, 'webrtc'), title: w?.summary });
  const d = p.dnsClassified;
  const dnsTitle = { own: '同网解析', same: '同一国家', public: '公共 DNS 跨区', leak: 'DNS 泄漏', 'leak-cn': '真实位置泄漏' };
  tiles.push({ label: 'DNS 解析', level: lv('dns'), value: !d ? '检测中' : d.status !== 'ok' ? '失败' : `${esc(dnsTitle[d.verdict] || '—')}`, sub: d?.status === 'ok' ? groupResolvers(d.resolvers).slice(0, 2).map(group => `${flag(group.country)}${esc(group.org || group.ip)}${group.count > 1 ? ` ×${group.count}` : ''}`).join(' ') : esc(d?.error || ''), pts: itemPts(result, 'dns'), title: [d?.summary, d?.ecsSummary].filter(Boolean).join('；') });
  const t = p.tcp;
  tiles.push({ label: 'TCP 连接', level: lv('tcp'), value: !t ? '检测中' : t.status !== 'ok' ? '失败' : t.relay ? '像代理转发' : t.osMismatch ? '系统不一致' : '直连特征', sub: t?.status === 'ok' ? `SYN ≈ ${esc(t.tcpOS)}${t.uaOS ? ` · UA ${esc(t.uaOS)}` : ''}` : esc(t?.error || ''), pts: itemPts(result, 'tcp'), title: t?.summary });
  const env = p.env;
  const tzLevel = result.live.tz || 'none';
  tiles.push({ label: '时区', level: tzLevel, value: tzLevel === 'warn' ? '与 IP 不符' : tzLevel === 'good' ? '一致' : '—', sub: env ? `${esc(env.tz.zone || '')} ${formatOffset(env.tz.offset)}` : '', pts: itemPts(result, 'tz') });
  tiles.push({ label: '语言', level: result.live.lang || 'none', value: result.live.lang === 'warn' ? '与地区不符' : result.live.lang === 'good' ? '匹配' : '—', sub: env ? esc(env.lang.languages.slice(0, 2).join(', ')) : '', pts: itemPts(result, 'lang') });
  const v6 = p.ipv6Classified;
  tiles.push({ label: 'IPv6', level: lv('ipv6'), value: !v6 ? '检测中' : !v6.address ? '无 IPv6' : v6.mismatch ? '绕过代理' : '一致', sub: v6?.address && !v6.isTarget ? `${flag(v6.country)}${esc(v6.org || '')}` : '', pts: itemPts(result, 'ipv6'), title: v6?.summary });
  const tr = p.trace;
  tiles.push({ label: 'Cloudflare', level: tr ? (tr.warp !== 'off' ? 'bad' : 'good') : 'none', value: tr ? (tr.warp !== 'off' ? `WARP ${esc(tr.warp)}` : 'WARP 未开启') : '—', sub: tr ? `节点 ${esc(tr.colo || '—')} · ${esc(tr.http || '')}` : '', title: tr ? `Cloudflare 认为你在 ${tr.loc}；接入节点 ${tr.colo}` : '' });
  tiles.push({ label: '出口一致性', level: result.live.egress || 'none', value: egress ? (egress.split ? '多出口' : egress.domesticDiffers ? '国内外分流' : '单一出口') : '检测中', sub: egress ? `${egress.ips.length} 个地址` : '', pts: itemPts(result, 'egress'), title: egress?.summary });
  $('live').innerHTML = tiles.map(tile).join('');
  renderCaptcha(run, result);
}

function groupResolvers(resolvers) {
  const groups = new Map();
  for (const item of resolvers) {
    const key = `${item.country}|${String(item.org || item.ip).toLowerCase().replace(/[^a-z0-9]/g, '').replace(/inc$/, '')}`;
    const group = groups.get(key) || { ...item, count: 0 };
    group.count += 1; groups.set(key, group);
  }
  return [...groups.values()].sort((a, b) => b.count - a.count);
}

function renderCaptcha(run, result) {
  const ts = run.probes.turnstile; const rc = run.probes.recaptcha;
  const card = (kind, title, data, extra) => {
    // Configuration problems are neutral: they say nothing about this visitor and are never scored.
    const level = !data ? 'pending' : data.status === 'skip' || data.status === 'error' ? 'none' : result.live[kind] || 'info';
    const head = !data ? '正在实测…' : data.status === 'skip' ? (data.pendingSecret ? '待后端密钥' : '未配置') : data.status === 'error' ? '未计分' : kind === 'turnstile'
      ? { silent: '直接通过', interactive: '需要验证', fail: '未通过' }[data.outcome] : `${data.score.toFixed(1)} 分`;
    const body = !data ? '用你现在的网络和浏览器真跑一次。' : data.status === 'skip' ? `${esc(data.reason)}${data.pendingSecret ? '' : '，配置 site key 后自动运行'}；不影响其他评分。` : esc(data.summary || data.error || '');
    return `<div class="cap lv-${level}">
      <div class="cap-head">${icon(level)}<strong>${esc(title)}</strong><span class="cap-result">${esc(head)}</span>${pen(itemPts(result, kind))}</div>
      <p>${body}</p>${extra || ''}
      ${data && data.status !== 'skip' ? `<button type="button" class="ghost small" data-rerun="${kind}">再测一次</button>` : ''}
    </div>`;
  };
  const tsNote = ts?.test ? '<p class="muted small">本地测试密钥：结果恒为通过，仅用于验证流程。</p>' : ts?.server && !ts.server.verified ? `<p class="muted small">${esc(ts.server.reason)}</p>` : '';
  $('captcha').innerHTML = card('turnstile', 'Cloudflare Turnstile', ts, tsNote) + card('recaptcha', 'Google reCAPTCHA v3', rc,
    '<p class="muted small">本站受 reCAPTCHA 保护，适用 Google <a href="https://policies.google.com/privacy" target="_blank" rel="noopener noreferrer">隐私政策</a>和<a href="https://policies.google.com/terms" target="_blank" rel="noopener noreferrer">服务条款</a>。</p>');
}

// ---------- ASN profile ----------

export function renderASN(run, result) {
  const box = $('asn');
  const a = run.asnProfile;
  const s = result.summary;
  const rdap = run.sources.rdap?.data;
  const ipguide = run.sources.ipguide?.data;
  const prefix = run.sources.ripeprefix?.data?.prefix || ipguide?.prefix || rdap?.cidr;
  if (!a) { box.innerHTML = `<p class="muted">${s.asn ? '正在获取 ASN 档案…' : '等待来源返回 ASN…'}</p>`; return; }
  const inferred = a.inferred || {};
  const consistency = result.checks.asn.consistency;
  const row = (label, value) => `<div class="kv"><dt>${esc(label)}</dt><dd>${value}</dd></div>`;
  box.innerHTML = `
    <div class="asn-head">
      <div><div class="asn-number">${asnLink(a.asn)}</div><div class="asn-holder">${esc(a.holder || ipguide?.asName || s.org || '')}</div></div>
      <div class="asn-class">${asnTag(run, 'lg')}<small>推断置信 ${pct(inferred.confidence)}</small></div>
    </div>
    ${consistency ? `<p class="asn-verdict lv-${result.checks.asn.level}">${icon(result.checks.asn.level)}${esc(consistency.text)}</p>` : ''}
    <dl class="kv-list">
      ${row('机房倾向', `<span class="meter"><i style="width:${Math.round((inferred.hosting ?? 0) * 100)}%"></i></span> ${pct(inferred.hosting)}`)}
      ${row('PeeringDB 自报', a.pdb ? `${esc(a.pdb.type || '—')}${a.pdb.traffic ? ` · ${esc(a.pdb.traffic)}` : ''}${a.pdb.scope ? ` · ${esc(a.pdb.scope)}` : ''}` : '<span class="muted">未登记</span>')}
      ${row('宣告规模', a.v4ips ? `${a.v4ips.toLocaleString()} 个 IPv4 · ${a.v4prefixes ?? '—'} 个前缀` : '—')}
      ${row('ASN 注册', a.regDate ? `${esc(a.regDate.slice(0, 10))}${a.asCountry ? ` · ${flag(a.asCountry)}${esc(a.asCountry)}` : ''}` : '—')}
      ${row('RPKI', a.rpki ? `<span class="pill pill-${a.rpki === 'valid' ? 'good' : a.rpki === 'invalid' ? 'bad' : 'muted'}">${esc(a.rpki)}</span>` : '—')}
      ${row('ASN 信誉', asnRepTag(run, result))}
      ${row('机器流量', typeof a.botShare === 'number' ? `${pct(a.botShare)} <span class="muted">Cloudflare Radar</span>` : '<span class="muted">未配置 Radar</span>')}
      ${row('所在网段', prefix ? `<span class="mono">${esc(prefix)}</span>` : '—')}
      ${row('登记信息', rdap ? `${esc(rdap.netname || '')} · ${esc(rdap.orgName || '')}${rdap.regDate ? ` · ${esc(rdap.regDate.slice(0, 10))}` : ''}` : '—')}
      ${row('租赁判断', a.lease ? (leaseTag(result) || '<span class="pill pill-good">未见租赁特征</span>') + (a.lease.reasons.length ? ` <span class="muted small">${esc(a.lease.reasons.join('；'))}</span>` : '') : '—')}
    </dl>
    ${inferred.reasons?.length ? `<details class="reasons"><summary>推断依据（${inferred.reasons.length}）</summary><ul>${inferred.reasons.map(reason => `<li>${esc(reason)}</li>`).join('')}</ul></details>` : ''}`;
}

// ---------- breakdown ----------

export function renderBreakdown(run, result) {
  const b = result.bonus;
  const bonusBlock = `
    <div class="cat cat-bonus">
      <div class="cat-head"><span>安全加分 <small class="muted">基准 ${result.base}</small></span><span class="cat-pts pos">${b.total ? `+${fmt(b.total)}` : '0'} <small>/ 上限 ${b.cap}</small></span></div>
      <div class="bar bar-plus"><i style="width:${Math.min(100, b.total / b.cap * 100)}%"></i></div>
      ${b.items.length ? `<ul>${b.items.filter(item => !item.live || run.self).map(item => `<li><b>+${fmt(item.pts)}</b><span>${esc(item.label)}</span><small>${esc(item.detail || '')}</small></li>`).join('')}</ul>` : '<p class="muted small">没有足够的正面证据：干净但缺少多源佐证的 IP 停在基准分。</p>'}
    </div>`;
  $('breakdown').innerHTML = bonusBlock + result.categories.filter(category => category.id !== 'live' || run.self).map(category => `
    <div class="cat">
      <div class="cat-head"><span>${esc(category.label)}</span><span class="cat-pts ${category.penalty ? 'neg' : ''}">${category.penalty ? `−${Math.round(category.penalty)}` : '0'} <small>/ 上限 ${category.cap}</small></span></div>
      <div class="bar"><i style="width:${Math.min(100, category.penalty / category.cap * 100)}%"></i></div>
      ${category.items.length ? `<ul>${category.items.map(item => `<li><b>−${item.pts}</b><span>${esc(item.label)}</span><small>${esc(item.detail || '')}</small></li>`).join('')}</ul>` : '<p class="muted small">无扣分</p>'}
      ${category.raw > category.cap ? `<p class="muted small">原始扣分 ${category.raw}，按上限封顶。</p>` : ''}
    </div>`).join('') + (result.notes.length ? `<div class="notes">${result.notes.map(item => `<p>${icon(item.level)}${esc(item.text)}</p>`).join('')}</div>` : '');
}

// ---------- multi-source IP type matrix ----------

const TYPE_SOURCES = ['ipinfo', 'ip2location', 'ipregistry', 'ipapi', 'ipapimirror', 'ipdata', 'abuseipdb', 'dbip', 'proxycheck', 'ipqs', 'ipapiis', 'iplocate', 'geoiplookup', 'iphub', 'ipquery', 'blackbox'];
const GIVES_COMPANY = new Set(['ipinfo', 'ip2location', 'ipregistry', 'ipdata', 'ipapiis', 'iplocate', 'netcoffee']);
const UT_LABEL = { residential: '家宽', mobile: '移动', business: '商业', hosting: '机房', education: '教育', government: '政府' };
const UT_TIP = {
  residential: '运营商给家庭 / 个人用户的接入地址', mobile: '移动网络（多为运营商 NAT 共享出口）', business: '企业专线或商业宽带',
  hosting: '数据中心、云服务器、CDN 或传输网', education: '学校与科研网络', government: '政府或军方网络',
};

function typeCell(record, field, id) {
  if (!record || record.status === 'pending') return `<span class="ut ut-pending">${icon('pending')}</span>`;
  if (record.status === 'skip') return '<span class="ut ut-off" tabindex="0" data-tip="需要在后端配置该数据库的 API key">未配置</span>';
  if (record.status !== 'ok') return `<span class="ut ut-off" tabindex="0" data-tip="${esc(record.error || '请求失败')}">失败</span>`;
  if (field === 'companyType' && !GIVES_COMPANY.has(id) && !record.data.companyType) return '<span class="muted">—</span>';
  const value = record.data[field];
  if (!value) return `<span class="ut ut-unknown" tabindex="0" data-tip="${esc(field === 'usageType' ? '这个来源没有给出使用类型（免费接口或套餐不含该字段）' : '这个来源没有给出公司类型')}">未知</span>`;
  const via = record.data.importedFields?.includes(field) ? 'IPSuper' : field === 'usageType' ? record.data.usageVia : null;
  const hint = [SOURCES.find(source => source.id === id)?.name, UT_TIP[value], via && '补充来源：'+via].filter(Boolean).join('\n');
  return `<span class="ut ut-${esc(value)}" tabindex="0" data-tip="${esc(hint)}">${esc(UT_LABEL[value] || value)}</span>`;
}

export function renderTypes(run) {
  // The supplementary IPgeo service runs only after this target's primary lookup failed.
  const ids = TYPE_SOURCES.filter(id => run.sources[id] && !(id === 'ipapimirror' && run.sources[id].status === 'skip'));
  const tally = field => {
    const counts = {};
    for (const id of ids) { const value = run.sources[id]?.status === 'ok' ? run.sources[id].data[field] : null; if (value) counts[value] = (counts[value] || 0) + 1; }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([value, count]) => `${UT_LABEL[value] || value} ${count}`).join(' · ') || '暂无';
  };
  const filled = [];
  for (const id of ids) {
    const data = run.sources[id]?.data;
    for (const field of data?.importedFields || []) {
      const name = SOURCES.find(source => source.id === id)?.name || id;
      filled.push(`${name} ${field === 'usageType' ? '使用类型' : '公司类型'}：${UT_LABEL[data[field]] || data[field]}`);
    }
  }
  const supplement = run.ipsuperReturned ? `<div class="type-summary" aria-label="IPSuper 补全结果"><strong>本轮补全了 ${filled.length} 格</strong><p>${filled.length ? filled.map(esc).join(' · ') : '本轮已返回的类型与现有字段没有可补的空格。'}</p></div>` : '';
  $('types').innerHTML = `${supplement}<table class="type-table"><thead><tr><th></th>${ids.map(id => `<th>${esc(SOURCES.find(source => source.id === id)?.name || id)}</th>`).join('')}</tr></thead>
    <tbody>
      <tr><th scope="row">使用类型</th>${ids.map(id => `<td>${typeCell(run.sources[id], 'usageType', id)}</td>`).join('')}</tr>
      <tr><th scope="row">公司类型</th>${ids.map(id => `<td>${typeCell(run.sources[id], 'companyType', id)}</td>`).join('')}</tr>
    </tbody></table>
    <p class="muted small type-summary">使用类型：${esc(tally('usageType'))}；公司类型：${esc(tally('companyType'))}。使用类型参与“网络类型”投票，公司类型作为第三方证据参与 ASN 类型推断。</p>`;
}

// ---------- geo comparison ----------

export function renderGeo(run, result) {
  const rows = SOURCES.map(source => ({ source, record: run.sources[source.id] }))
    .filter(({ record }) => record?.status === 'ok' && (record.data.country || record.data.asn) && record.data.geoVote !== false);
  const consensus = result.summary.country;
  $('geo').innerHTML = rows.length ? `<table class="geo-table"><thead><tr><th>来源</th><th>国家 / 城市</th><th>ASN</th><th>组织</th><th>标记</th></tr></thead><tbody>
    ${rows.map(({ source, record }) => {
      const d = record.data;
      const tags = Object.entries(d.flags || {}).filter(([, value]) => value === true).map(([key]) => ({ vpn: 'VPN', proxy: '代理', tor: 'Tor', hosting: '机房', relay: '中继', abuser: '滥用', crawler: '爬虫', mobile: '移动', bogon: 'Bogon' })[key]);
      if (d.type && !tags.includes(TYPE_LABEL[d.type])) tags.unshift(TYPE_LABEL[d.type] || d.type);
      return `<tr class="${d.country && consensus && d.country !== consensus ? 'differs' : ''}">
        <td><a href="${esc(source.site(run.ip))}" target="_blank" rel="noopener noreferrer"${d.sourceNote ? ` data-tip="${esc(d.sourceNote)}"` : ''}>${esc(source.name)}</a></td>
        <td>${d.country ? `${flag(d.country)}${esc(d.country)}${d.city ? ` · ${esc(d.city)}` : ''}` : '—'}</td>
        <td>${d.asn ? `AS${d.asn}` : '—'}</td><td class="org">${esc(d.org || '—')}</td>
        <td>${tags.map(tag => `<span class="mini" tabindex="0" data-tip="${esc(`${source.name} 把这个 IP 标为「${tag}」`)}">${esc(tag)}</span>`).join('') || '<span class="muted">—</span>'}</td></tr>`;
    }).join('')}</tbody></table>` : '<p class="muted">等待来源返回…</p>';
}

// ---------- sources ----------

function sourceValue(id, d) {
  if (!d) return '';
  switch (id) {
    case 'rdap': return `注册地 ${d.regCountry || '—'}${d.netname ? ` · ${d.netname}` : ''}`;
    case 'riperir': return `分配地 ${d.regCountry || '—'}`;
    case 'ripeprefix': return d.announced ? `${d.prefix || ''}` : '未宣告';
    case 'ipguide': return `${d.prefix || ''}${d.rir ? ` · ${d.rir}` : ''}`;
    case 'shodan': return d.unseen ? '未被扫描' : d.ports.length ? `${d.tags.join(' ') || '端口'} ${d.ports.slice(0, 3).join(', ')}` : '无开放端口';
    case 'sfs': return d.appears ? `记录 ${d.appears} 次` : '无记录';
    case 'onionoo': return d.flags.tor ? 'Tor 出口' : d.torRelay ? 'Tor 中继（非出口）' : '不在 Tor 列表';
    case 'ptr': return d.hostname || '无 PTR';
    case 'blackbox': {
      const category = ({ hosting: '机房', residential: '家宽', mobile: '移动', business: '商业', vpn: 'VPN', tor: 'Tor', privacy_relay: '隐私中继', bogon: '保留地址', unknown: '类型未知' })[d.classification] || '类型未知';
      return `${category} · Beta${d.spamhausListed === true ? ' · Spamhaus 标记' : ''}`;
    }
    case 'netcoffee': return (d.geoSources || []).map(r => r.id+' '+(r.city || r.country || '未知')).join(' · ') || '聚合查询';
    case 'netatlas': return [d.asn ? `AS${d.asn}` : '', d.prefix, d.city ? `${d.locationDatabase ? 'DB-IP' : '位置'} ${d.city}` : ''].filter(Boolean).join(' · ');
    case 'ipapimirror': return [d.country, d.usageType ? UT_LABEL[d.usageType] : '', '公开接口补充', d.cached ? '来源缓存' : ''].filter(Boolean).join(' · ');
    default: {
      const tags = Object.entries(d.flags || {}).filter(([, value]) => value === true).map(([key]) => key.toUpperCase());
      return [d.country, typeof d.risk === 'number' ? `风险 ${d.risk}` : '', ...tags].filter(Boolean).join(' · ');
    }
  }
}

function chip({ name, site, status, value, ms, error, listed, note }) {
  const level = status === 'pending' ? 'pending' : status === 'skip' ? 'none' : status !== 'ok' ? 'off' : listed ? 'bad' : 'good';
  return `<a class="src src-${level}" href="${esc(site)}" target="_blank" rel="noopener noreferrer" data-tip="${esc([name, error || value || '', note || '', '点击打开该来源的查询页'].filter(Boolean).join('\n'))}">
    <span class="src-name">${level === 'pending' ? icon('pending') : ''}${esc(name)}</span>
    <span class="src-val">${status === 'ok' ? esc(value || '✓') : status === 'pending' ? '查询中' : esc(error || '不可用')}</span>
    ${status === 'ok' && typeof ms === 'number' ? `<span class="src-ms">${ms} ms</span>` : ''}
  </a>`;
}

export function renderSources(run) {
  const groups = [
    { id: 'intel', title: 'IP 情报库' }, { id: 'registry', title: '注册与路由' }, { id: 'threat', title: '威胁与扫描' },
  ];
  const html = groups.map(group => {
    const list = SOURCES.filter(source => source.group === group.id && run.sources[source.id]);
    const ok = list.filter(source => run.sources[source.id].status === 'ok').length;
    return `<div class="src-group"><h3>${esc(group.title)} <small>${ok} / ${list.length}</small></h3><div class="src-grid">
      ${list.map(source => { const record = run.sources[source.id]; return chip({ name: source.name, site: source.site(run.ip), status: record.status, value: sourceValue(source.id, record.data), ms: record.ms, error: record.error, note: record.data?.sourceNote, listed: source.group === 'threat' && ['sfs', 'onionoo'].includes(source.id) && (record.data?.appears || record.data?.flags?.tor) }); }).join('')}
    </div></div>`;
  });
  const bl = run.dnsbl;
  const blOk = bl.filter(item => item.status === 'ok').length;
  html.push(`<div class="src-group"><h3>DNS 黑名单 <small>${blOk} / ${bl.length}</small></h3><div class="src-grid">
    ${bl.map(item => { const def = DNSBLS.find(list => list.id === item.id); return chip({ name: def.name, site: def.site(run.ip), status: item.status, value: item.listed ? `收录 ${item.codes.join(' ')}` : '未收录', error: item.error, listed: item.listed }); }).join('')}
  </div></div>`);
  const lists = run.lists;
  html.push(`<div class="src-group"><h3>威胁 / 机房 IP 列表 <small>${lists.filter(item => item.status === 'ok').length} / ${lists.length}</small></h3><div class="src-grid">
    ${lists.map(item => { const def = CIDR_LISTS.find(list => list.id === item.id); return chip({ name: def.name, site: def.site(), status: item.status, value: listValue(item), error: item.error, listed: item.listed && ['attack', 'spam', 'proxy', 'tor'].includes(def.kind) }); }).join('')}
  </div></div>`);
  $('sources').innerHTML = html.join('');
}

export function renderProgress(run, result) {
  const all = Object.values(run.sources).length + run.dnsbl.length + run.lists.length;
  const done = Object.values(run.sources).filter(item => item.status !== 'pending').length + run.dnsbl.filter(item => item.status !== 'pending').length + run.lists.filter(item => item.status !== 'pending').length;
  $('progress').style.width = `${Math.round(done / all * 100)}%`;
  $('progress').parentElement.classList.toggle('done', done === all);
  $('status').textContent = done === all
    ? `${result.confidence.sources} 个来源返回了结果 · ${new Date(run.startedAt).toLocaleString('zh-CN', { hour12: false })}`
    : `正在检测 · 已完成 ${done} / ${all}`;
}

export function crossLinks(ip) {
  const links = [
    ['Scamalytics', `https://scamalytics.com/ip/${ip}`], ['IPQualityScore', `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${ip}`],
    ['AbuseIPDB', `https://www.abuseipdb.com/check/${ip}`], ['Spur', `https://spur.us/context/${ip}`], ['ping0', `https://ping0.cc/ip/${ip}`],
    ['IPPure', `https://ippure.com/`], ['bgp.tools', `https://bgp.tools/prefix/${ip}`], ['Cisco Talos', `https://talosintelligence.com/reputation_center/lookup?search=${ip}`],
    ['VirusTotal', `https://www.virustotal.com/gui/ip-address/${ip}`], ['Net.Coffee', `https://ip.net.coffee/ip/${ip}`],
  ];
  $('crosslinks').innerHTML = links.map(([name, url]) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(name)} ↗</a>`).join('');
}

export function applyMask(masked) {
  document.querySelectorAll('.ipv').forEach(node => { node.textContent = masked ? maskIP(node.dataset.ip) : node.dataset.ip; });
  const input = $('ip-input');
  input.classList.toggle('is-masked', masked && Boolean(input.value));
  $('mask-toggle').textContent = masked ? '显示 IP' : '隐藏 IP';
  $('mask-toggle').setAttribute('aria-pressed', String(masked));
}

export { zoneOffset };
