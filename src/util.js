/** Shared helpers: IP parsing, CIDR matching, fetch with timeout, country and timezone formatting. */

export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
export const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
export const round1 = value => Math.round(value * 10) / 10;

// ---------- IP addresses ----------

function ipv6Words(text) {
  if (!/^[0-9a-f:.]+$/i.test(text) || !text.includes(':')) return null;
  let head = text;
  let tail4 = null;
  const dotted = text.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const v4 = parseIPv4(dotted[2]);
    if (!v4) return null;
    head = dotted[1] + '0:0';
    tail4 = v4.split('.').map(Number);
  }
  const halves = head.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const words = [...left, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...right];
  if (words.length !== 8 || words.some(word => !/^[0-9a-f]{1,4}$/i.test(word))) return null;
  const numbers = words.map(word => parseInt(word, 16));
  if (tail4) { numbers[6] = tail4[0] << 8 | tail4[1]; numbers[7] = tail4[2] << 8 | tail4[3]; }
  return numbers;
}

function parseIPv4(text) {
  if (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(text)) return null;
  const parts = text.split('.').map(Number);
  return parts.every(part => part <= 255) ? parts.join('.') : null;
}

function formatIPv6(words) {
  // RFC 5952: compress the longest run (>=2) of zero words, lowercase hex.
  let bestStart = -1; let bestLength = 0;
  for (let i = 0; i < 8;) {
    if (words[i] !== 0) { i += 1; continue; }
    let j = i; while (j < 8 && words[j] === 0) j += 1;
    if (j - i > bestLength && j - i >= 2) { bestStart = i; bestLength = j - i; }
    i = j;
  }
  const hex = words.map(word => word.toString(16));
  if (bestStart < 0) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLength).join(':')}`;
}

/** Returns { ip, v } with a canonical address, or null. */
export function parseIP(input) {
  const text = String(input ?? '').trim().replace(/^\[|\]$/g, '');
  const v4 = parseIPv4(text);
  if (v4) return { ip: v4, v: 4 };
  const words = ipv6Words(text);
  return words ? { ip: formatIPv6(words), v: 6, words } : null;
}

/** Public, globally routable unicast only. */
export function isPublicIP(input) {
  const parsed = parseIP(input);
  if (!parsed) return false;
  if (parsed.v === 4) {
    const [a, b, c] = parsed.ip.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
      || (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 198 && (b === 18 || b === 19))
      || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113));
  }
  const w = parsed.words;
  if ((w[0] & 0xe000) !== 0x2000) return false;
  if (w[0] === 0x2001 && (w[1] < 0x200 || w[1] === 0xdb8)) return false;
  return w[0] !== 0x2002;
}

export function ipToBigInt(input) {
  const parsed = typeof input === 'object' ? input : parseIP(input);
  if (!parsed) return null;
  if (parsed.v === 4) return { value: parsed.ip.split('.').reduce((acc, part) => (acc << 8n) + BigInt(part), 0n), bits: 32 };
  return { value: parsed.words.reduce((acc, word) => (acc << 16n) + BigInt(word), 0n), bits: 128 };
}

export function cidrContains(cidr, ip) {
  const [network, lengthText] = String(cidr).split('/');
  const net = ipToBigInt(network); const address = ipToBigInt(ip);
  if (!net || !address || net.bits !== address.bits) return false;
  const length = lengthText === undefined ? net.bits : Number(lengthText);
  if (!Number.isInteger(length) || length < 0 || length > net.bits) return false;
  const shift = BigInt(net.bits - length);
  return (net.value >> shift) === (address.value >> shift);
}

export function cidrSize(cidr) {
  const [network, lengthText] = String(cidr).split('/');
  const parsed = parseIP(network);
  if (!parsed) return 0;
  const bits = parsed.v === 4 ? 32 : 128;
  const length = Number(lengthText ?? bits);
  return parsed.v === 4 ? 2 ** (bits - length) : 0;
}

/** Name used for DNSBL / PTR queries: reversed octets or nibbles. */
export function reverseName(input) {
  const parsed = parseIP(input);
  if (!parsed) return null;
  if (parsed.v === 4) return parsed.ip.split('.').reverse().join('.');
  return parsed.words.map(word => word.toString(16).padStart(4, '0')).join('').split('').reverse().join('.');
}

export function maskIP(ip) {
  const parsed = parseIP(ip);
  if (!parsed) return ip || '—';
  if (parsed.v === 4) return parsed.ip.replace(/\.\d+\.\d+$/, '.•••.•••');
  return `${parsed.ip.split(':').slice(0, 2).join(':')}:••••:••••`;
}

export function sameIP(a, b) {
  const left = parseIP(a); const right = parseIP(b);
  return Boolean(left && right && left.ip === right.ip);
}

// ---------- ASN / country normalization ----------

export function asnNumber(value) {
  if (typeof value === 'number' && Number.isInteger(value) && value > 0) return value;
  const match = String(value ?? '').trim().match(/^(?:AS)?(\d{1,10})\b/i);
  const number = match ? Number(match[1]) : 0;
  return number > 0 && number <= 4294967295 ? number : null;
}

export const text = (value, max = 200) => typeof value === 'string' && value.trim() ? value.trim().slice(0, max) : null;
export const bool = value => typeof value === 'boolean' ? value : null;
export const num = value => {
  const number = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  return typeof number === 'number' && Number.isFinite(number) ? number : null;
};

const REGIONS = 'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split(' ');
const REGION_SET = new Set(REGIONS);
let nameIndex = null;
const regionKey = value => String(value).normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');

export function countryCode(value) {
  const raw = text(value, 80);
  if (!raw) return null;
  const upper = raw.toUpperCase();
  if (upper === 'UK') return 'GB';
  if (REGION_SET.has(upper)) return upper;
  if (!nameIndex) {
    nameIndex = new Map();
    try {
      const english = new Intl.DisplayNames(['en'], { type: 'region' });
      for (const code of REGIONS) nameIndex.set(regionKey(english.of(code)), code);
    } catch { /* Intl.DisplayNames unavailable */ }
    const extra = {
      'United States of America': 'US', 'United Kingdom': 'GB', 'Great Britain': 'GB', 'Russian Federation': 'RU',
      'Republic of Korea': 'KR', 'Korea, Republic of': 'KR', 'South Korea': 'KR', 'North Korea': 'KP', 'Czech Republic': 'CZ',
      'Viet Nam': 'VN', 'Iran, Islamic Republic of': 'IR', 'Taiwan, Province of China': 'TW', 'Hong Kong SAR': 'HK',
      Macao: 'MO', Macau: 'MO', Turkey: 'TR', Turkiye: 'TR', Holland: 'NL', 'The Netherlands': 'NL', Deutschland: 'DE',
    };
    for (const [name, code] of Object.entries(extra)) nameIndex.set(regionKey(name), code);
  }
  return nameIndex.get(regionKey(raw)) || null;
}

let zhRegions = null;
export function countryName(code) {
  if (!code) return '未知';
  try { zhRegions ||= new Intl.DisplayNames(['zh-CN'], { type: 'region' }); return zhRegions.of(code) || code; }
  catch { return code; }
}

// ---------- time zones ----------

/** Offset in minutes east of UTC for an IANA zone at `date`, or null. */
export function zoneOffset(zone, date = new Date()) {
  if (!zone) return null;
  try {
    const part = new Intl.DateTimeFormat('en-US', { timeZone: zone, timeZoneName: 'longOffset' })
      .formatToParts(date).find(item => item.type === 'timeZoneName')?.value || '';
    if (part === 'GMT') return 0;
    const match = part.match(/GMT([+-])(\d{2}):?(\d{2})?/);
    if (!match) return null;
    return (match[1] === '-' ? -1 : 1) * (Number(match[2]) * 60 + Number(match[3] || 0));
  } catch { return null; }
}

export function formatOffset(minutes) {
  if (minutes === null || minutes === undefined) return '—';
  const sign = minutes < 0 ? '−' : '+';
  const abs = Math.abs(minutes);
  return `UTC${sign}${Math.floor(abs / 60)}${abs % 60 ? `:${String(abs % 60).padStart(2, '0')}` : ''}`;
}

// ---------- geography ----------

export function distanceKm(a, b) {
  if (![a?.lat, a?.lon, b?.lat, b?.lon].every(value => typeof value === 'number')) return null;
  const rad = Math.PI / 180;
  const dLat = (b.lat - a.lat) * rad; const dLon = (b.lon - a.lon) * rad;
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(a.lat * rad) * Math.cos(b.lat * rad) * Math.sin(dLon / 2) ** 2;
  return 2 * 6371 * Math.asin(Math.sqrt(h));
}

// ---------- network ----------

/**
 * GET with timeout and abort. Never sends cookies or referrer.
 * Resolves to { ok, status, data, ms, error } and never throws.
 */
export async function getJSON(url, { timeout = 10000, signal, as = 'json', init = {} } = {}) {
  const started = performance.now();
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(abort, timeout);
  try {
    const response = await fetch(url, { credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', ...init, signal: controller.signal });
    const body = as === 'text' ? await response.text() : await response.json().catch(() => null);
    const ms = Math.round(performance.now() - started);
    if (!response.ok) return { ok: false, status: response.status, data: body, ms, error: response.status === 429 ? '额度或频率受限' : `HTTP ${response.status}` };
    if (as === 'json' && body === null) return { ok: false, status: response.status, data: null, ms, error: '响应不是 JSON' };
    return { ok: true, status: response.status, data: body, ms, error: null };
  } catch {
    const ms = Math.round(performance.now() - started);
    return { ok: false, status: 0, data: null, ms, error: signal?.aborted ? '已取消' : ms >= timeout - 50 ? '超时' : '网络或跨域受限' };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}

export function randomId(length, alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789') {
  return Array.from(crypto.getRandomValues(new Uint8Array(length)), byte => alphabet[byte % alphabet.length]).join('');
}

// ---------- HTML ----------

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ESCAPES[char]);
