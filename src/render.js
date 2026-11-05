/** DOM rendering. All external text goes through esc(). */
import { esc, countryName, maskIP, maskText, formatOffset, zoneOffset } from './util.js?v=4.1';
import { SOURCES } from './sources.js?v=3.3';
import { DNSBLS, CIDR_LISTS } from './blocklists.js';
import { CATEGORIES, TYPE_LABEL } from './score.js?v=4.8';
import { captchaConfig } from './captcha.js';
import { PAGE_PROVIDERS } from './page-providers.js?v=1';

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
/** Shown wherever a value is still on its way from a third-party source, so it never reads as "no data". */
const WAIT = '<span class="wait">等待第三方返回…</span>';
const place = (code, city) => code ? `${flag(code)}<span>${city ? `${esc(city)}，` : ''}${esc(countryName(code))}</span>` : '<span class="muted">—</span>';
const ipSpan = (ip, masked) => `<span class="ipv" data-ip="${esc(ip)}">${esc(masked ? maskIP(ip) : ip)}</span>`;
// "隐藏 IP" state. Free text that carries addresses (prefixes, neighbours, hostnames, details) goes through ipText,
// tooltips are masked when shown, and applyMask re-masks both live.
let masked = false; let knownIPs = [];
const scrub = text => (masked ? maskText(text, knownIPs) : text);
const ipText = value => {
  const raw = String(value ?? '');
  return maskText(raw) === raw ? esc(raw) : `<span class="ipt" data-raw="${esc(raw)}">${esc(scrub(raw))}</span>`;
};
const pen = pts => pts ? `<span class="pen">−${Math.round(pts)}</span>` : '';
const asnLink = asn => asn ? `<a class="asn" href="https://bgp.tools/as/${asn}" target="_blank" rel="noopener noreferrer">AS${asn}</a>` : '—';
const pct = value => typeof value === 'number' ? `${Math.round(value * 100)}%` : '—';
const fmt = value => (Math.round(value * 10) / 10).toString();

// ---------- tags: gradient for mixed evidence, "?" for low certainty, hover / focus for the why ----------

const TONES = { residential: 'good', isp: 'good', native: 'good', mobile: 'teal', business: 'sky', hosting: 'warn', cdn: 'orange', broadcast: 'warn', leased: 'warn', transit: 'violet', education: 'slate', government: 'slate', bad: 'bad' };
const IP_TYPE_LABEL = { residential: '家宽', mobile: '移动网络', business: '商业宽带', hosting: '机房', education: '教育网' };
const ASN_LABEL = { isp: 'ISP', mobile: '移动运营商', hosting: '机房 / 云', cdn: 'CDN', transit: '骨干网', business: '企业网', education: '教育网', government: '政府网' };
const UNSURE = 0.6;

/**
 * parts: [{ value, share }] sorted desc. Shows up to two parts; the gradient sits at their split.
 * tone overrides a value's colour; conflict ('bad' | 'warn') marks a label that the detection contradicts (red + "!").
 */
function mixTag({ parts, labels, certainty = 1, tip = '', size = '', tone = {}, conflict = null }) {
  const shown = (parts || []).filter((part, index) => index === 0 || part.share >= 0.2).slice(0, 2);
  if (!shown.length) return '<span class="muted">—</span>';
  const mixed = shown.length === 2;
  const name = value => (typeof labels === 'function' ? labels(value, mixed) : labels[value]) || value;
  const color = value => `var(--t-${tone[value] || TONES[value] || 'muted'})`;
  const c1 = color(shown[0].value);
  const c2 = mixed ? color(shown[1].value) : c1;
  const split = mixed ? Math.round(shown[0].share / (shown[0].share + shown[1].share) * 100) : 100;
  const unsure = certainty < UNSURE;
  return `<span class="tag2 ${size}${mixed ? ' mixed' : ''}${unsure ? ' unsure' : ''}${conflict ? ` conflict conflict-${conflict}` : ''}" tabindex="0" data-tip="${esc(tip)}" style="--c1:${c1};--c2:${c2};--split:${split}%">`
    + `<span class="tag2-text">${esc(shown.map(part => name(part.value)).join(' / '))}</span>${unsure ? '<i class="q" aria-label="不确定">?</i>' : ''}${conflict ? '<i class="x" aria-label="与检测结果矛盾">!</i>' : ''}</span>`;
}

const certaintyLine = value => `确定度 ${pct(value)}${value < UNSURE ? '：证据不足或互相矛盾，所以标了 ?' : ''}`;
const HOME = new Set(['residential', 'mobile']);
const DATACENTER = new Set(['hosting', 'cdn']);

/** A home / mobile label that the ASN contradicts: red when the ASN is a datacenter, amber when it is a backbone. */
function typeClash(result) {
  const consistency = result.checks.asn.consistency;
  if (!consistency || !HOME.has(result.checks.type.value)) return null;
  return !consistency.ok ? { level: 'bad', text: consistency.text } : consistency.warn ? { level: 'warn', text: consistency.text } : null;
}

function typeTag(result) {
  const t = result.checks.type;
  if (!t.value) return '<span class="muted">—</span>';
  const clash = typeClash(result);
  const lines = ['IP 网络类型（这个地址本身）', t.mix.map(part => `${IP_TYPE_LABEL[part.value] || part.value} ${pct(part.share)}`).join(' · ')];
  if (clash) lines.push(`矛盾：${clash.text}`);
  if (t.from === 'sources') {
    for (const vote of t.votes) lines.push(`${vote.by.join('、')} 标为${IP_TYPE_LABEL[vote.value] || vote.value}`);
    if (t.hosting.yes) lines.push(`标记机房：${t.hosting.by.join('、')}`);
  }
  if (t.from === 'exclusion') lines.push('没有来源给出明确类型；只是没被标成机房，按排除法记为家宽');
  if (t.from === 'asn') lines.push('没有来源给出这个 IP 的类型，按所属 ASN 的类型推断');
  if (t.hosting.clear.length) lines.push(`未标记机房：${t.hosting.clear.join('、')}`);
  lines.push(certaintyLine(t.certainty));
  const tone = clash ? { residential: clash.level, mobile: clash.level } : {};
  return mixTag({ parts: t.mix, labels: IP_TYPE_LABEL, certainty: t.certainty, tip: lines.join('\n'), tone, conflict: clash?.level });
}

/** The ASN's own claim (PeeringDB, its name) that independent evidence contradicts, if any. */
function asnClash(run) {
  const inferred = run.asnProfile?.inferred;
  return inferred?.conflict && inferred.declared ? { cls: inferred.declared.cls, ...inferred.conflict } : null;
}

function asnTag(run, size = '') {
  const inferred = run.asnProfile?.inferred;
  if (!inferred?.cls) return run.asnProfile ? '<span class="muted">未知</span>' : '<span class="muted">—</span>';
  const clash = asnClash(run);
  const declared = inferred.declared;
  const lines = [clash ? `运营商类型：自报${ASN_LABEL[clash.cls]}，与检测矛盾` : `运营商类型（按 AS${run.asnProfile.asn} 推断）`,
    ...(clash ? [clash.text, ...declared.by.map(reason => `· ${reason}`), '检测推断：'] : []),
    inferred.mix.slice(0, 4).map(part => `${ASN_LABEL[part.value]} ${pct(part.share)}`).join(' · '),
    `推断置信 ${pct(inferred.confidence)}${inferred.confidence < UNSURE ? '：依据少或互相矛盾，所以标了 ?' : ''}`, '依据：', ...inferred.reasons.map(reason => `· ${reason}`)];
  // A self-declared type that independent evidence contradicts is shown as the claim itself ("ISP"), in red or yellow.
  if (clash) return mixTag({ parts: [{ value: clash.cls, share: 1 }], labels: ASN_LABEL, tip: lines.join('\n'), size, tone: { [clash.cls]: clash.level }, conflict: clash.level });
  return mixTag({ parts: inferred.mix, labels: ASN_LABEL, certainty: inferred.confidence, tip: lines.join('\n'), size });
}

/** Why a source's 家宽 / 移动 label is contradicted: the IP is judged a datacenter, or its ASN is one by independent evidence. */
function homeClash(run, field) {
  const t = run.result?.checks.type;
  if (field === 'usageType' && t?.value === 'hosting' && t.certainty >= 0.5) return `综合判断为机房（确定度 ${pct(t.certainty)}）`;
  const inferred = run.asnProfile?.inferred;
  const observed = inferred?.observed;
  if (observed && DATACENTER.has(observed.cls) && observed.hosting >= 0.5) return `AS${run.asnProfile.asn} 的独立证据指向${observed.label}`;
  if (field === 'usageType' && run.result?.checks.asn.consistency?.ok === false) return run.result.checks.asn.consistency.text;
  return null;
}

/** Type-matrix cell: a home label that the detection contradicts keeps its text and turns red. */
function markClash(html, record, field, run) {
  const value = record?.status === 'ok' ? record.data[field] : null;
  const reason = value && HOME.has(value) ? homeClash(run, field) : null;
  return reason ? html.replace('class="ut ', 'class="ut ut-conflict ').replace('data-tip="', `data-tip="${esc(`与检测矛盾：${reason}`)}&#10;`) : html;
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
    tipNode.textContent = scrub(target.dataset.tip);
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

function tweenNumber(node, to) {
  const from = Number(node.dataset.v);
  node.dataset.v = to;
  cancelAnimationFrame(node.raf);
  if (!Number.isFinite(from) || from === to || document.hidden || matchMedia('(prefers-reduced-motion: reduce)').matches) { node.textContent = to; return; }
  const start = performance.now();
  const frame = now => {
    const k = Math.min(1, (now - start) / 700);
    node.textContent = Math.round(from + (to - from) * (1 - (1 - k) ** 3));
    if (k < 1) node.raf = requestAnimationFrame(frame);
  };
  node.raf = requestAnimationFrame(frame);
}

// Score ring: a full circle whose value arc is a gradient from a deep to a bright shade of the grade colour.
// The arc, its round caps and the sweep are CSS (conic gradient + ring mask, driven by --p); updates only move --p.
function renderRing(result, g) {
  const box = $('score-ring');
  box.classList.add('has-score');
  box.dataset.tone = g.tone;
  box.style.setProperty('--p', result.score);
  tweenNumber(box.querySelector('.ring-text strong'), result.score);
  const grade = box.querySelector('.ring-text span');
  grade.className = `tone-${g.tone}`;
  grade.textContent = `${g.letter} 级`;
  box.setAttribute('aria-label', `综合分 ${result.score}，${g.letter} 级`);
}

export function renderHero(run, result, view) {
  knownIPs = [run.ip];
  const g = result.grade;
  const pending = result.confidence.pending;
  const issues = result.categories.flatMap(category => category.items).sort((a, b) => b.pts - a.pts).slice(0, 5);
  renderRing(result, g);
  $('verdict').innerHTML = `
    <div class="verdict-head"><span class="verdict-label tone-${g.tone}">${esc(g.label)}</span>
      <span class="confidence c-${result.confidence.level}" tabindex="0" data-tip="评分可信程度&#10;成功来源 ${result.confidence.sources} 个；匿名类字段 ${result.confidence.anonSources} 个来源">置信度${{ high: '高', medium: '中', low: '低' }[result.confidence.level]}</span>
      ${pending ? `<span class="pending-note">${icon('pending')}正在等待 ${pending} 个第三方来源返回，分数可能还会变化</span>` : ''}</div>
    <p class="verdict-text">${esc(result.verdict)}</p>
    ${run.self ? `<p class="score-split"><span>IP 信誉 <b>${result.ipScore}</b></span><span>连接实测 <b class="${result.liveDelta < 0 ? 'neg' : ''}">${result.liveDelta === 0 ? '±0' : result.liveDelta}</b></span><span>综合 <b>${result.score}</b></span></p>`
      : '<p class="score-split muted">查询的不是本机出口，只计算 IP 信誉，连接实测不适用。<button type="button" class="link-btn" data-self-check>改测本机出口 →</button></p>'}
    <ul class="deductions">${issues.map(item => `<li tabindex="0" data-tip="${esc(item.detail || '')}"><span class="dot"></span><b>−${fmt(item.pts)}</b> ${esc(item.label)}</li>`).join('')}${result.bonus.items.slice(0, 3).map(item => `<li class="plus" tabindex="0" data-tip="${esc(item.detail || '')}"><span class="dot"></span><b>+${fmt(item.pts)}</b> ${esc(item.label)}</li>`).join('')}${!issues.length && !result.bonus.items.length ? '<li class="clean"><b>0</b> 没有扣分项</li>' : ''}</ul>`;
  const s = result.summary;
  const orWait = (has, html) => has || !pending ? html : WAIT;
  $('addr').innerHTML = `
    <div class="addr-row"><dt>IP</dt><dd>${ipSpan(run.ip, view.masked)} <span class="tag">IPv${run.v}</span>${run.self ? '<span class="tag tag-self">你的出口</span>' : ''}</dd></div>
    <div class="addr-row"><dt>位置</dt><dd>${orWait(s.country, place(s.country, s.city))}</dd></div>
    <div class="addr-row"><dt>所属网络</dt><dd>${orWait(s.asn, `${asnLink(s.asn)} <span class="muted">${esc(s.org || '')}</span>`)}</dd></div>
    <div class="addr-row"><dt>类型</dt><dd>${orWait(result.checks.type.value, `${typeTag(result)} ${nativeTag(result)} ${leaseTag(result)}`)}</dd></div>
    <div class="addr-row"><dt>运营商类型</dt><dd>${orWait(run.asnProfile, asnTag(run))}${run.asnProfile?.pdb?.type ? ` <span class="muted small">PeeringDB：${esc(run.asnProfile.pdb.type)}</span>` : ''}</dd></div>
    <div class="addr-row"><dt>主机名</dt><dd class="mono">${s.hostname ? ipText(s.hostname) : orWait(false, '–')}</dd></div>
    <div class="addr-row"><dt>时区</dt><dd>${orWait(s.ipTimezone, esc(s.ipTimezone || '—'))} <span class="muted">${s.ipOffset === null || s.ipOffset === undefined ? '' : formatOffset(s.ipOffset)}</span></dd></div>`;
}

export function renderEgress(egress, run, view) {
  const box = $('egress');
  if (!egress) { box.innerHTML = '<p class="muted">正在识别你的出口…</p>'; return; }
  const rows = egress.results.map(item => {
    const target = run && item.ip && run.ip === item.ip;
    return `<li class="${target ? 'is-target' : ''}">
      <span class="eg-name">${esc(item.name)}</span>
      ${item.status === 'pending' ? `<span class="muted">${icon('pending')}等待返回</span>` : item.ip ? `<button type="button" class="eg-ip" data-check="${esc(item.ip)}" title="检测这个 IP">${ipSpan(item.ip, view.masked)}</button>` : '<span class="muted">无响应</span>'}
    </li>`;
  }).join('');
  const note = egress.split ? `<p class="eg-note warn">${icon('warn')}${esc(egress.summary)}</p>`
    : egress.domesticDiffers ? `<p class="eg-note">${icon('info')}${esc(egress.summary)}</p>` : '';
  box.innerHTML = `<ul class="egress-list">${rows}</ul>${note}
    ${egress.v6 ? '' : '<p class="muted small">没有发现 IPv6 出口。</p>'}`;
}

// ---------- verdict tiles ----------

/** Gradient meter, red → yellow → green, with a marker at value (0–100) and a 0 / 25 / 50 / 75 / 100 scale. */
function gauge(value, { low = '高危', high = '可信', label = '' } = {}) {
  const v = Math.max(0, Math.min(100, Math.round(value)));
  return `<span class="gauge" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${v}"${label ? ` aria-label="${esc(label)}"` : ''}>`
    + `<span class="gauge-track"><i class="gauge-mark" style="left:clamp(2px, ${v}%, calc(100% - 2px))"></i></span>`
    + `<span class="gauge-scale" aria-hidden="true"><span>0<em> ${esc(low)}</em></span><span class="g25" style="left:25%">25</span><span style="left:50%">50</span><span style="left:75%">75</span><span>100<em> ${esc(high)}</em></span></span>`
    + '</span>';
}

function tile({ label, level, value, sub, pts, title, wide = false }) {
  return `<div class="tile lv-${level}${pts >= 1 ? ' has-pen' : ''}${wide ? ' tile-wide' : ''}" ${title ? `tabindex="0" data-tip="${esc(title)}"` : ''}>
    <div class="tile-head">${icon(level)}<span class="tile-label">${esc(label)}</span>${pen(pts)}</div>
    <div class="tile-value">${level === 'pending' && value === '—' ? WAIT : value}${sub ? ` <small>${sub}</small>` : ''}</div>
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
    asnTile(run, result, loading),
    neighbourTile(c.neighbours, result, loading),
    { label: 'ASN 信誉', level: c.asnRep.level === 'none' ? (run.asnProfile && !run.asnProfile.routes ? 'none' : 'pending') : c.asnRep.level, value: c.asnRep.ratio === undefined ? '—' : c.asnRep.ratio >= 15 ? '较差' : c.asnRep.ratio >= 2 ? '一般' : c.asnRep.ratio <= 0.2 ? '优异' : c.asnRep.ratio < 0.5 ? '良好' : '正常', sub: c.asnRep.ratio === undefined ? '' : `滥用密度 ${c.asnRep.ratio} 倍均值`, pts: itemPts(result, 'asn-abuse') + itemPts(result, 'rpki'), title: c.asnRep.ratio === undefined ? '' : `整个 ASN 每万个地址有 ${c.asnRep.per10k} 个近期上榜，全网平均 ${c.asnRep.baseline}` },
    { label: '开放端口', level: loading(c.ports.level), value: c.ports.ports.length ? esc(c.ports.ports.slice(0, 4).join(', ')) + (c.ports.ports.length > 4 ? '…' : '') : c.ports.level === 'none' ? '—' : '未发现', sub: c.ports.tags.length ? esc(c.ports.tags.join(' ')) : '' },
    botTile(run, result),
    { label: '共享人数估计', level: loading(c.sharers.level), value: c.sharers.count === null ? '—' : c.sharers.count === 1 ? '独享 IP' : c.sharers.count ? `约 ${c.sharers.count} 人` : '暂无记录',
      sub: c.sharers.count ? `${c.sharers.count === 1 ? '仅见 1 人' : c.sharers.tier} · 近 ${c.sharers.windowDays} 天` : '', pts: itemPts(result, 'sharers'),
      title: c.sharers.count === null ? '估计来源：Egress 自己的检测记录；本次没有取到（记录服务不可用，或服务端拿不到查询者地址）' : `估计来源：Egress 自己的检测记录。近 ${c.sharers.windowDays} 天里，从这个 IP 本身出口做过检测的不同浏览器约 ${c.sharers.count} 个（共 ${c.sharers.lookers} 个查询方、${c.sharers.lookups} 次查询）。` },
  ];
  $('checks').innerHTML = tiles.map(tile).join('');
}

/** ASN 一致性: the IP's type against its ASN, and the ASN's self-declared type against independent evidence. */
function asnTile(run, result, loading) {
  const c = result.checks.asn;
  const clash = asnClash(run);
  const rank = { none: 0, good: 1, warn: 2, bad: 3 };
  const level = clash && rank[clash.level] > rank[c.level] ? clash.level : c.level;
  const value = clash?.level === 'bad' ? '冲突' : c.consistency ? (c.consistency.ok ? (c.consistency.warn || clash ? '需留意' : '一致') : '冲突') : '—';
  return { label: 'ASN 一致性', level: loading(level), value, sub: c.consistency || clash ? asnTag(run) : '',
    pts: itemPts(result, 'asn-conflict') + itemPts(result, 'leased'), title: [c.consistency?.text, clash?.text].filter(Boolean).join('\n') };
}

/** Human share as a green bar from the left, bot share as a pink bar from the right, each share written under its end. */
function splitBar(human, bot, label = '') {
  const total = Math.max(0.001, human + bot);
  const share = value => `${(value * 100).toFixed(1)}%`;
  return `<span class="split" role="img" aria-label="${esc(label || `人类 ${share(human)}，机器 ${share(bot)}`)}">`
    + `<span class="split-track"><i class="split-human" style="flex-grow:${(human / total).toFixed(3)}"></i><i class="split-bot" style="flex-grow:${(bot / total).toFixed(3)}"></i></span>`
    + `<span class="split-ends"><span class="split-end human">人类 ${share(human)}</span><span class="split-end bot">机器 ${share(bot)}</span></span></span>`;
}
const BOT_LEVEL = { good: '人类为主', warn: '人机混合', bad: '机器为主' };
const botBadge = level => `<span class="bot-badge lv-${level}"><svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="5.4" r="2.6"/><path d="M3.2 13.6c.7-2.6 2.5-4 4.8-4s4.1 1.4 4.8 4"/></svg>${BOT_LEVEL[level]}</span>`;

/** 人机流量: Cloudflare Radar's human vs bot share of the ASN's HTTP traffic, human from the left and bots from the right. */
function botTile(run, result) {
  const b = result.checks.bots;
  const radar = run.asnProfile?.sources?.radar;
  const asn = run.asnProfile?.asn ? `AS${run.asnProfile.asn}` : 'ASN';
  if (b.bot === null) {
    const value = !run.asnProfile ? WAIT : radar === 'skip' ? '未配置' : run.asnProfile.radarNoData ? '无数据' : '查询失败';
    const title = radar === 'skip' ? '人机流量需要后端配置 CF_RADAR_TOKEN（Cloudflare Radar 只读 token）后才能查询'
      : radar === 'error' ? run.asnProfile.radarError || `Cloudflare Radar 查询 ${asn} 失败，请重新检测` : '';
    return { label: '人机流量', level: run.asnProfile ? 'none' : 'pending', value, sub: 'Cloudflare Radar', title, wide: true };
  }
  const human = Math.round(b.human * 100);
  const title = [`人机流量：${asn} 近 ${b.window === '28d' ? '28 天' : b.window || '一段时间'}的 HTTP 请求里人类与机器的比例（Cloudflare Radar）`,
    `人类 ${human}% · 机器 ${Math.round(b.bot * 100)}%`, '运营商接入网通常机器占 10–30%；超过 40% 说明这个网络里服务器、爬虫较多，网站更容易弹验证或限流'].join('\n');
  return {
    label: '人机流量', level: b.level, wide: true, title, pts: itemPts(result, 'asn-bots'),
    value: `<span class="tile-gauge">${splitBar(b.human, b.bot, `${asn} 人类流量 ${human}%，机器流量 ${Math.round(b.bot * 100)}%`)}${botBadge(b.level)}</span>`,
    sub: `${esc(asn)} · 运营商接入网通常机器占 10–30%`,
  };
}

function neighbourTile(nb, result, loading) {
  if (nb.level === 'none') return { label: '邻居网段', level: loading('none'), value: '—', sub: '' };
  const value = nb.whole?.length ? '整段上榜' : nb.count ? `${nb.count} 个邻居上榜` : nb.tor ? '有 Tor 节点' : '干净';
  const tip = [`同一 /24（${nb.prefix}）里其他地址的表现`, nb.whole?.length ? `整段被列入：${nb.whole.join('、')}` : '', nb.lists?.length ? `上榜：${nb.lists.join('、')}` : '',
    nb.sample?.length ? `例如 ${nb.sample.join('、')}` : '', nb.tor ? `Tor 中继 ${nb.tor} 个` : '', nb.abuseipdb ? `AbuseIPDB 30 天内被举报 ${nb.abuseipdb.reported} 个` : '', `查了 ${nb.checked} 个威胁列表`].filter(Boolean).join('\n');
  return { label: '邻居网段', level: nb.level, value, sub: ipText(nb.prefix || ''), pts: itemPts(result, 'block-listed') + itemPts(result, 'neighbours') + itemPts(result, 'neighbour-tor'), title: tip };
}

const USE_LABELS = { stream: '流媒体', ai: 'AI 服务', captcha: '验证码', account: '注册付款', mail: '发邮件', social: '社媒 / TikTok' };
const USE_LEVEL = { good: '可以', warn: '看情况', bad: '不建议' };
// Each use case is its own 0–100 meter on the gradient gauge: < 50 不建议, 50–74 看情况, ≥ 75 可以.
export function renderUses(result) {
  $('uses').innerHTML = Object.entries(USE_LABELS).map(([id, name]) => {
    const use = result.uses[id];
    if (!use) return `<div class="use lv-none"><div class="use-head"><span class="use-name">${esc(name)}</span><span class="use-badge"><strong>—</strong></span></div></div>`;
    const tip = [
      `${name} ${use.score} 分 · ${USE_LEVEL[use.level]}`,
      use.gate ? `封顶：${use.gate}` : '',
      ...use.items.map(item => `−${fmt(item.pts)} ${item.label}${item.detail ? `：${item.detail}` : ''}`),
      use.items.length ? '' : use.why,
      use.note,
      '100 起算；≥ 75 可以，50–74 看情况，< 50 不建议',
    ].filter(Boolean).join('\n');
    const top = use.items.slice(0, 2);
    const body = use.gate ? `<span class="use-why">${esc(use.gate)}</span>`
      : top.length ? `<ul class="use-items">${top.map(item => `<li><b>−${fmt(item.pts)}</b><span>${esc(item.label)}</span></li>`).join('')}</ul>`
        : `<span class="use-why">${esc(use.why)}</span>`;
    return `<div class="use lv-${use.level}" tabindex="0" data-tip="${esc(tip)}">
      <div class="use-head"><span class="use-name">${esc(name)}</span><span class="use-badge"><strong>${use.score}</strong>${esc(USE_LEVEL[use.level])}</span></div>
      ${gauge(use.score, { label: `${name} ${use.score} 分` })}
      ${body}
    </div>`;
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
  tiles.push({ label: 'DNS 解析', level: lv('dns'), value: !d ? '检测中' : d.status !== 'ok' ? '失败' : `${esc(dnsTitle[d.verdict] || '—')}`, sub: d?.status === 'ok' ? groupResolvers(d.resolvers).slice(0, 2).map(group => `${flag(group.country)}${ipText(group.org || group.ip)}${group.count > 1 ? ` ×${group.count}` : ''}`).join(' ') : esc(d?.error || ''), pts: itemPts(result, 'dns'), title: [d?.summary, d?.ecsSummary].filter(Boolean).join('；') });
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
      ${data && (data.status !== 'skip' || data.pendingSecret) ? `<button type="button" class="ghost small" data-rerun="${kind}">再测一次</button>` : ''}
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
    ${asnClash(run) ? `<p class="asn-verdict lv-${asnClash(run).level}">${icon(asnClash(run).level)}${esc(asnClash(run).text)}</p>` : ''}
    ${consistency ? `<p class="asn-verdict lv-${result.checks.asn.level}">${icon(result.checks.asn.level)}${esc(consistency.text)}</p>` : ''}
    <dl class="kv-list">
      ${row('机房倾向', `<span class="meter"><i style="width:${Math.round((inferred.hosting ?? 0) * 100)}%"></i></span> ${pct(inferred.hosting)}`)}
      ${row('PeeringDB 自报', a.pdb ? `${esc(a.pdb.type || '—')}${a.pdb.traffic ? ` · ${esc(a.pdb.traffic)}` : ''}${a.pdb.scope ? ` · ${esc(a.pdb.scope)}` : ''}` : '<span class="muted">未登记</span>')}
      ${row('宣告规模', a.v4ips ? `${a.v4ips.toLocaleString()} 个 IPv4 · ${a.v4prefixes ?? '—'} 个前缀` : '—')}
      ${row('ASN 注册', a.regDate ? `${esc(a.regDate.slice(0, 10))}${a.asCountry ? ` · ${flag(a.asCountry)}${esc(a.asCountry)}` : ''}` : '—')}
      ${row('RPKI', a.rpki ? `<span class="pill pill-${a.rpki === 'valid' ? 'good' : a.rpki === 'invalid' ? 'bad' : 'muted'}">${esc(a.rpki)}</span>` : '—')}
      ${row('ASN 信誉', asnRepTag(run, result))}
      ${row('人机流量', result.checks.bots.bot !== null ? `<span class="tile-gauge" tabindex="0" data-tip="人机流量：Cloudflare Radar 统计的 AS${a.asn} HTTP 请求里人类与机器的比例">${splitBar(result.checks.bots.human, result.checks.bots.bot)}${botBadge(result.checks.bots.level)}</span>` : '<span class="muted">未配置 Radar</span>')}
      ${row('所在网段', prefix ? `<span class="mono">${ipText(prefix)}</span>` : '—')}
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
      ${b.items.length ? `<ul>${b.items.filter(item => !item.live || run.self).map(item => `<li><b>+${fmt(item.pts)}</b><span>${esc(item.label)}</span><small>${ipText(item.detail || '')}</small></li>`).join('')}</ul>` : '<p class="muted small">没有足够的正面证据：干净但缺少多源佐证的 IP 停在基准分。</p>'}
    </div>`;
  $('breakdown').innerHTML = bonusBlock + result.categories.filter(category => category.id !== 'live' || run.self).map(category => `
    <div class="cat">
      <div class="cat-head"><span>${esc(category.label)}</span><span class="cat-pts ${category.penalty ? 'neg' : ''}">${category.penalty ? `−${Math.round(category.penalty)}` : '0'} <small>/ 上限 ${category.cap}</small></span></div>
      <div class="bar"><i style="width:${Math.min(100, category.penalty / category.cap * 100)}%"></i></div>
      ${category.items.length ? `<ul>${category.items.map(item => `<li><b>−${item.pts}</b><span>${esc(item.label)}</span><small>${ipText(item.detail || '')}</small></li>`).join('')}</ul>` : '<p class="muted small">无扣分</p>'}
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
  if (!record || record.status === 'pending') return `<span class="ut ut-pending">${icon('pending')}等待返回</span>`;
  if (record.status !== 'ok') {
    const reason = record.webLookup?.error || record.error || '请求失败';
    return `<button type="button" class="ut ut-off lookup-cell" data-lookup-details data-tip="${esc(reason)}">${lookupLabel(record.webLookup || record)}</button>`;
  }
  if (field === 'companyType' && !GIVES_COMPANY.has(id) && !record.data.companyType) return '<span class="muted">—</span>';
  const value = record.data[field];
  if (!value) return `<span class="ut ut-unknown" tabindex="0" data-tip="${esc([field === 'usageType' ? '这个来源没有给出明确的使用类型' : '这个来源没有给出公司类型',record.webLookup?.error || (record.webLookup?.status === 'ok' ? '官方网页已读取' : '')].filter(Boolean).join(' · '))}">${esc(field === 'usageType' && record.data.usageDetail || '未知')}</span>`;
  const via = record.data.importedFields?.includes(field) ? 'IPSuper' : record.data.webTypeFields?.includes(field) ? '官方网页' : field === 'usageType' ? record.data.usageVia : null;
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
  $('types').innerHTML = `<table class="type-table"><thead><tr><th></th>${ids.map(id => `<th><a href="${esc(SOURCES.find(source => source.id === id)?.site(run.ip) || '#')}" target="_blank" rel="noopener noreferrer">${esc(SOURCES.find(source => source.id === id)?.name || id)}</a></th>`).join('')}</tr></thead>
    <tbody>
      <tr><th scope="row">使用类型</th>${ids.map(id => `<td>${markClash(typeCell(run.sources[id], 'usageType', id), run.sources[id], 'usageType', run)}</td>`).join('')}</tr>
      <tr><th scope="row">公司类型</th>${ids.map(id => `<td>${markClash(typeCell(run.sources[id], 'companyType', id), run.sources[id], 'companyType', run)}</td>`).join('')}</tr>
      ${run.chrome?.version ? `<tr class="chrome-type-row"><th scope="row">插件</th>${ids.map(id=>{const row=run.chrome.rows[id];return `<td><button type="button" class="lookup-cell ${row?.status === 'ok' ? 'lookup-ok' : row?.challenge ? 'lookup-wait' : ''}" data-lookup-details data-tip="${esc(row ? lookupDetail(row) : run.chrome.active ? '排队中' : '此版本插件未返回该来源')}" aria-label="${esc((PAGE_PROVIDERS[id]?.name || id)+' 插件查询详情')}">${row ? lookupLabel(row) : run.chrome.active ? '排队' : '未返回'}</button></td>`;}).join('')}</tr>` : ''}
    </tbody></table>
    <p class="muted small type-summary">使用：${esc(tally('usageType'))} · 公司：${esc(tally('companyType'))}${filled.length ? ` · 补充 ${filled.length} 项` : ''}</p>`;
  renderLookupStatus(run);
}

function lookupLabel(row) {
  if (row.challenge || row.status === 'challenge') return '待验证';
  if (row.status === 'pending') return '查询中';
  if (row.status === 'ok') return '已读取';
  const reason = row.error || row.message || '';
  if (/停止|取消/.test(reason)) return '已停止';
  if (/额度|频率|限流|429/.test(reason)) return '限流';
  if (row.status === 'skip') return /未配置/.test(reason) ? '未配置' : '已跳过';
  if (/校验提示已消失/.test(reason)) return '字段缺失';
  if (/人机|校验/.test(reason)) return '待验证';
  if (/401|403|拒绝/.test(reason)) return '拒绝访问';
  if (/超时|超过|秒未返回/.test(reason)) return '超时';
  if (/连接|网络|跨域|Failed to fetch/.test(reason)) return '连接失败';
  if (/字段|版式|JSON|未找到/.test(reason)) return '字段缺失';
  return '失败';
}

function lookupDetail(row) {
  if (row.challenge || row.status === 'challenge') return '等待手动验证，通过后自动补充';
  if (row.status !== 'ok') return row.error || row.message || '查询中';
  if (row.message) return row.message;
  const d = row.data;
  if (!d) return '已读取';
  const parts = ['usageType','companyType'].filter(key=>d[key]).map(key=>(key==='usageType'?'使用：':'公司：')+(UT_LABEL[d[key]] || d[key]));
  if(d.risk != null)parts.push(`风险 ${d.risk}/100`);
  if(d.trustScore != null)parts.push(`信任 ${d.trustScore}/100`);
  const labels={vpn:'VPN',proxy:'代理',tor:'Tor',hosting:'机房',relay:'中继',abuser:'滥用',crawler:'爬虫',mobile:'移动',bogon:'Bogon'};
  for(const [key,value] of Object.entries(d.flags || {}))if(typeof value==='boolean')parts.push(`${labels[key] || key}${value?'检出':'未检出'}`);
  if(d.asnType)parts.push('ASN：'+d.asnType);
  if(!d.usageType && !d.companyType)parts.push('未提供类型');
  if(row.cached)parts.push('10 分钟内缓存');
  return parts.join(' · ');
}

export function renderLookupStatus(run) {
  const chrome = run.chrome || {rows:{}};
  const rows = Object.values(chrome.rows);
  const ok = rows.filter(row=>row.status==='ok').length;
  const waiting = rows.filter(row=>row.challenge || row.status==='challenge').length;
  const failed = rows.filter(row=>row.status==='error' && !row.challenge).length;
  const server = Object.values(run.pageLookups || {});
  const parts = [];
  if(chrome.version)parts.push(`插件 ${ok}/${chrome.total || rows.length || '…'}`+(chrome.active?' 查询中':''));
  else parts.push('未连接插件');
  if(waiting)parts.push(`${waiting} 个待验证`);
  if(failed)parts.push(`${failed} 个失败`);
  if(chrome.error)parts.push(chrome.error);
  if(chrome.version && /^1\.(?:[012]\.|3\.0$)/.test(chrome.version))parts.push('请更新至 v1.3.1');
  if(server.length)parts.push(`服务器补充 ${server.filter(row=>row.status==='ok').length}/${server.length}`);
  $('auto-page-status').textContent=parts.join(' · ');
  const details=[];
  const add=(name,channel,row)=>details.push({name,channel,row});
  for(const [id,row] of Object.entries(chrome.rows))add(PAGE_PROVIDERS[id]?.name || id,'插件',row);
  for(const id of TYPE_SOURCES) {
    const row=run.apiSources?.[id];
    if(row && row.status!=='ok')add(SOURCES.find(s=>s.id===id)?.name || id,'API',row);
    const page=run.providerPages?.[id];
    if(page && page.via!=='Chrome' && page.status!=='ok')add(PAGE_PROVIDERS[id]?.name || id,'服务器网页',page);
  }
  for(const [id,row] of Object.entries(run.pageLookups || {}))add(({ipinfo:'IPinfo',ipsuper:'IPSuper',ipok:'IPOK',sources:'来源网页'})[id] || id,'服务器',row);
  details.sort((a,b)=>(a.row.status==='ok')-(b.row.status==='ok'));
  $('lookup-detail-rows').innerHTML=details.map(({name,channel,row})=>`<tr><th scope="row">${esc(name)}</th><td>${esc(channel)}</td><td class="${row.challenge?'lookup-wait':row.status==='ok'?'lookup-ok':''}">${lookupLabel(row)}</td><td>${esc(lookupDetail(row))}</td><td>${Number.isFinite(row.ms)?(row.ms/1000).toFixed(1)+' s':'—'}</td></tr>`).join('');
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
  if (Number.isFinite(d.trustScore)) return '信任分 '+d.trustScore+'/100';
  if (Number.isFinite(d.webRiskScore)) return '风险值 '+d.webRiskScore+'/100';
  if (Number.isFinite(d.webRiskPercent)) return '网页风险 '+d.webRiskPercent+'%';
  if (d.importedFields?.length && !d.country && d.risk == null) return [UT_LABEL[d.usageType],UT_LABEL[d.companyType]].filter(Boolean).join(' / ');
  switch (id) {
    case 'rdap': return `注册地 ${d.regCountry || '—'}${d.netname ? ` · ${d.netname}` : ''}`;
    case 'riperir': return `分配地 ${d.regCountry || '—'}`;
    case 'ripeprefix': return d.announced ? `${d.prefix || ''}` : '未宣告';
    case 'ipguide': return `${d.prefix || ''}${d.rir ? ` · ${d.rir}` : ''}`;
    case 'shodan': return d.unseen ? '未被扫描' : (d.ports.length ? `${d.tags.join(' ') || '端口'} ${d.ports.slice(0, 3).join(', ')}` : '无开放端口') + (d.vulns?.length ? ` · ${d.vulns.length} 个 CVE` : '');
    case 'sfs': return d.appears ? `记录 ${d.appears} 次` : '无记录';
    case 'otx': return d.benign ? '白名单 / 误报' : d.pulses ? `${d.pulses} 份威胁报告` : '无威胁报告';
    case 'greynoise': return d.classification === 'unseen' || d.noise === false ? '未观测到扫描' : [({ benign: '良性扫描', malicious: '恶意扫描', suspicious: '可疑扫描', unknown: '扫描' })[d.classification] || d.classification, d.name].filter(Boolean).join(' · ') || '—';
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

// ---------- source cards: each one coloured by what that source said about this IP ----------

const GO = '<svg class="go" viewBox="0 0 16 16" aria-hidden="true"><path d="M5.5 10.5l5-5M6.5 5.5h4v4"/></svg>';
const TONE_WORD = { good: '干净', warn: '需留意', bad: '有风险', info: '仅位置 / 注册信息' };
const tone = (level, label = '') => ({ level, label });

/**
 * One source's own verdict, never the overall score: bad (anonymous, abusive, high risk), warn (datacenter, medium risk,
 * scanning), good (clean), info (location or registry only). Risk thresholds follow the score: ≥ 70 bad, ≥ 35 warn.
 */
function sourceTone(id, d, run) {
  const f = d.flags || {};
  const consensus = run.result?.summary?.country;
  switch (id) {
    case 'sfs': return d.appears ? tone('bad', '垃圾注册') : tone('good', '无记录');
    case 'onionoo': return f.tor ? tone('bad', 'Tor 出口') : d.torRelay ? tone('warn', 'Tor 中继') : tone('good', '非 Tor');
    case 'otx': return d.benign ? tone('good', '白名单') : d.pulses >= 3 ? tone('bad', '多份报告') : d.pulses ? tone('warn', '有报告') : tone('good', '无报告');
    case 'greynoise':
      if (d.classification === 'malicious') return tone('bad', '恶意扫描');
      if (d.classification === 'unseen' || d.noise === false) return tone('good', '未观测到');
      return tone('warn', d.classification === 'suspicious' ? '可疑扫描' : '扫描器');
    case 'shodan': {
      // Matches the score's port check: proxy / malware tags are a warning, open ports alone are information.
      const tag = (d.tags || []).find(value => ['proxy', 'vpn', 'tor', 'compromised', 'malware'].includes(value));
      if (d.unseen) return tone('good', '未被扫描');
      if (tag) return tone('warn', { proxy: '代理端口', vpn: 'VPN 端口', tor: 'Tor', compromised: '已入侵', malware: '恶意软件' }[tag]);
      if (d.vulns?.length) return tone('warn', 'CVE');
      return d.ports?.length ? tone('info', '开放端口') : tone('good', '无开放端口');
    }
    case 'ripeprefix': return d.announced ? tone('info') : tone('warn', '未宣告');
    case 'rdap': case 'riperir': case 'ipguide': case 'netatlas': return tone('info');
  }
  const risk = [d.risk, d.webRiskScore, d.webRiskPercent].find(Number.isFinite);
  const use = d.usageType || d.type || d.aggregateUsageType;
  if (f.tor) return tone('bad', 'Tor');
  if (f.proxy) return tone('bad', '代理');
  if (f.vpn) return tone('bad', 'VPN');
  if (f.abuser) return tone('bad', '滥用记录');
  if (d.spamhausListed === true) return tone('bad', 'Spamhaus');
  if (risk >= 70) return tone('bad', '高风险');
  if (risk >= 35) return tone('warn', '中风险');
  if (f.relay) return tone('warn', '隐私中继');
  if (f.crawler) return tone('warn', '爬虫');
  if (f.hosting || use === 'hosting') return tone('warn', '机房');
  if (Number.isFinite(risk)) return tone('good', '低风险');
  // A home label the detection contradicts (same rule as the type matrix) is not a clean answer.
  if ((use === 'residential' || use === 'isp' || use === 'mobile') && homeClash(run, 'usageType')) return tone('warn', use === 'mobile' ? '移动存疑' : '家宽存疑');
  if (use === 'residential' || use === 'isp') return tone('good', '家宽');
  if (use === 'mobile' || f.mobile) return tone('good', '移动网络');
  if (consensus && d.country && d.country !== consensus && d.geoVote !== false) return tone('warn', '位置不同');
  // An explicit "not a proxy / VPN / Tor" is a verdict too; flags left unknown are not.
  if ([f.proxy, f.vpn, f.tor].includes(false)) return tone('good', '无代理标记');
  return tone('info');
}

/** Type lists (datacenter / VPN ranges) only describe the IP; abuse lists count against it, and so do listed neighbours. */
function listTone(item, def) {
  if (item.listed) return tone(['datacenter', 'vpn'].includes(def.kind) ? 'warn' : 'bad');
  const n = item.neighbours;
  return tone(n && ['attack', 'spam', 'proxy'].includes(def.kind) && (n.whole || n.ips?.length) ? 'warn' : 'good');
}

function chip({ name, site, status, value, ms, error, note, tone: verdict }) {
  const level = status === 'pending' ? 'pending' : status === 'skip' ? 'none' : status !== 'ok' ? 'off' : verdict.level;
  const label = status === 'ok' ? verdict.label : '';
  const tip = [name, error || value || '', status === 'ok' ? `结论：${label || TONE_WORD[level]}` : '', note || '', '点击打开该来源的查询页 ↗'];
  const foot = (label ? `<span class="src-tag">${esc(label)}</span>` : '') + (status === 'ok' && typeof ms === 'number' ? `<span class="src-ms">${ms} ms</span>` : '');
  return `<a class="src src-${level}" href="${esc(site)}" target="_blank" rel="noopener noreferrer" data-tip="${esc(tip.filter(Boolean).join('\n'))}">
    <span class="src-head">${icon(level === 'off' ? 'none' : level)}<span class="src-name">${esc(name)}</span>${GO}</span>
    <span class="src-val">${status === 'ok' ? ipText(value || '✓') : status === 'pending' ? '等待返回' : esc(error || '不可用')}</span>
    ${foot ? `<span class="src-foot">${foot}</span>` : ''}
  </a>`;
}

function sourceGroup(title, cards) {
  const answered = cards.filter(card => card.status === 'ok');
  const tally = ['bad', 'warn', 'good'].map(level => [level, answered.filter(card => card.tone.level === level).length]).filter(([, count]) => count);
  return `<div class="src-group"><h3>${esc(title)} <small>${answered.length} / ${cards.length}</small>${tally.map(([level, count]) => `<span class="tally tally-${level}">${count} ${TONE_WORD[level]}</span>`).join('')}</h3>
    <div class="src-grid">${cards.map(chip).join('')}</div></div>`;
}

export function renderSources(run) {
  const verdicts = {};
  const groups = [
    { id: 'intel', title: 'IP 情报库' }, { id: 'registry', title: '注册与路由' }, { id: 'threat', title: '威胁与扫描' },
  ];
  const html = groups.map(group => sourceGroup(group.title, SOURCES.filter(source => source.group === group.id && run.sources[source.id]).map(source => {
    const record = run.sources[source.id];
    const verdict = record.status === 'ok' ? sourceTone(source.id, record.data, run) : tone('none');
    if (record.status === 'ok') verdicts[source.id] = verdict;
    return { name: source.name, site: source.site(run.ip), status: record.status, value: sourceValue(source.id, record.data), ms: record.ms, error: record.error, note: record.data?.sourceNote, tone: verdict };
  })));
  html.push(sourceGroup('DNS 黑名单', run.dnsbl.map(item => {
    const def = DNSBLS.find(list => list.id === item.id);
    return { name: def.name, site: def.site(run.ip), status: item.status, value: item.listed ? `收录 ${item.codes.join(' ')}` : '未收录', error: item.error, tone: tone(item.listed ? 'bad' : 'good') };
  })));
  html.push(sourceGroup('威胁 / 机房 IP 列表', run.lists.map(item => {
    const def = CIDR_LISTS.find(list => list.id === item.id);
    return { name: def.name, site: def.site(), status: item.status, value: listValue(item), error: item.error, tone: listTone(item, def) };
  })));
  $('sources').innerHTML = html.join('');
  // Cross-check links that are also sources carry the same colour.
  document.querySelectorAll('#crosslinks a[data-src]').forEach(link => {
    const verdict = verdicts[link.dataset.src];
    link.dataset.tone = verdict?.level || '';
    if (verdict) link.dataset.tip = `本次结果：${verdict.label || TONE_WORD[verdict.level]}`; else delete link.dataset.tip;
  });
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
    ['Scamalytics', `https://scamalytics.com/ip/${ip}`, 'scamalytics'], ['IPQualityScore', `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${ip}`, 'ipqs'],
    ['AbuseIPDB', `https://www.abuseipdb.com/check/${ip}`, 'abuseipdb'], ['Spur', `https://spur.us/context/${ip}`], ['ping0', `https://ping0.cc/ip/${ip}`],
    ['IPPure', `https://ippure.com/`], ['bgp.tools', `https://bgp.tools/prefix/${ip}`], ['Cisco Talos', `https://talosintelligence.com/reputation_center/lookup?search=${ip}`],
    ['VirusTotal', `https://www.virustotal.com/gui/ip-address/${ip}`, 'virustotal'], ['Net.Coffee', `https://ip.net.coffee/ip/${ip}`, 'netcoffee'],
  ];
  // The dot fills in once the matching source answers (renderSources).
  $('crosslinks').innerHTML = links.map(([name, url, id]) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer"${id ? ` data-src="${id}"` : ''}><i aria-hidden="true"></i>${esc(name)}${GO}</a>`).join('');
}

/** Up to six recently queried addresses, newest first; clicking one checks it again. Masked like every other address. */
export function renderHistory(list) {
  $('ip-history').innerHTML = list.length ? '最近查询 ' + list.map(ip => `<button type="button" class="chip-btn" data-check="${esc(ip)}">${ipSpan(ip, masked)}</button>`).join('') + '<button type="button" class="chip-btn clear" data-clear-history>清除</button>' : '';
}

export function applyMask(on) {
  masked = on;
  document.querySelectorAll('.ipv').forEach(node => { node.textContent = on ? maskIP(node.dataset.ip) : node.dataset.ip; });
  document.querySelectorAll('.ipt').forEach(node => { node.textContent = scrub(node.dataset.raw); });
  if (tipFor) tipNode.textContent = scrub(tipFor.dataset.tip);
  const input = $('ip-input');
  input.classList.toggle('is-masked', masked && Boolean(input.value));
  $('mask-toggle').textContent = masked ? '显示 IP' : '隐藏 IP';
  $('mask-toggle').setAttribute('aria-pressed', String(masked));
}

export { zoneOffset };
