import { API_BASE, PAGE_LOOKUP_BASE, PAGE_LOOKUP_CLOUD } from '../config.js?v=cloud2';
import { sameIP } from './util.js';

const reports = new Map();
const transient = new Set([408, 429, 500, 502, 503, 504]);

function pause(ms, signal) {
  return new Promise((resolve, reject) => {
    signal.throwIfAborted();
    const finish = () => { signal.removeEventListener('abort', abort); resolve(); };
    const timer = setTimeout(finish, ms);
    const abort = () => { clearTimeout(timer); reject(signal.reason); };
    signal.addEventListener('abort', abort, { once: true });
  });
}

/** Bound the complete lookup, including retries, to one user-visible deadline. */
export async function lookupPage(provider, ip, signal, progress = () => {}) {
  const key = `${provider}:${ip}`;
  signal.throwIfAborted();
  const cached = reports.get(key);
  const cacheMs = provider === 'sources' && Object.values(cached?.sources || {}).some(row => row.status !== 'ok') ? 60000 : 600000;
  if (cached && Date.now() - cached.time < cacheMs) return cached;
  const relay = { url: `${API_BASE}/v1/page/${provider}?ip=${encodeURIComponent(ip)}`, method: 'GET', timeout: 145000 };
  const local = PAGE_LOOKUP_BASE !== PAGE_LOOKUP_CLOUD;
  const routes = local
    ? [{ url: `${PAGE_LOOKUP_BASE}/lookup/${provider}`, method: 'POST', timeout: 110000 }, { ...relay, timeout: 90000 }, { ...relay, timeout: 25000 }]
    : [relay, { ...relay, timeout: 65000 }, { ...relay, timeout: 25000 }];
  const deadline = AbortSignal.timeout(240000);
  const overall = AbortSignal.any([signal, deadline]);
  let lastError;
  const failures = [];
  for (let attempt = 0; attempt < routes.length; attempt++) {
    overall.throwIfAborted();
    const route = routes[attempt];
    progress(attempt ? '连接恢复中，第 ' + attempt + ' 次重试' : local ? '正在读取网页' : '正在连接网页服务，首次启动可能稍慢');
    const requestSignal = AbortSignal.any([overall, AbortSignal.timeout(route.timeout)]);
    try {
      const response = await fetch(route.url, {
        method: route.method,
        ...(route.method === 'POST' ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) } : {}),
        signal: requestSignal,
      });
      let report;
      try { report = await response.json(); }
      catch {
        overall.throwIfAborted();
        const error = Error(`HTTP ${response.status}：服务返回非 JSON 响应`);
        error.retryable = response.ok || transient.has(response.status) || [403, 404].includes(response.status);
        error.skipRoute = [403, 404].includes(response.status);
        throw error;
      }
      if (!response.ok) {
        const error = Error(`HTTP ${response.status}：${report.error || '网页服务请求失败'}`);
        if (report.errorCode === 'caller-rate-limit') throw error;
        error.retryable = transient.has(response.status) || [403, 404].includes(response.status);
        error.skipRoute = [403, 404].includes(response.status);
        const seconds = Number(response.headers.get('Retry-After') || report.retryAfterSeconds);
        error.delay = Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds * 1000, 15000) : null;
        throw error;
      }
      if (!sameIP(report.ip, ip)) throw Error('返回的 IP 不匹配');
      if (!Number.isFinite(report.time) || Math.abs(Date.now() - report.time) > 600000) throw Error('网页报告时间无效，请重新查询');
      if (provider === 'sources' ? !report.sources || typeof report.sources !== 'object' || Array.isArray(report.sources)
        : provider === 'ipinfo' ? typeof report.text !== 'string' || !report.text.includes('Summary')
        : !Array.isArray(report.headers) || !Array.isArray(report.rows?.['使用类型']) || !Array.isArray(report.rows?.['公司类型'])) {
        throw Error('网页报告字段不完整');
      }
      overall.throwIfAborted();
      if (reports.size >= 64) reports.delete(reports.keys().next().value);
      reports.set(key, report);
      return report;
    } catch (error) {
      if (signal.aborted) throw signal.reason;
      if (deadline.aborted) throw Error('网页查询超时，请重新检测');
      const retryable = error.retryable ?? (error instanceof TypeError || error.name === 'TimeoutError');
      if (!retryable) throw error;
      lastError = error;
      const reason = error.name === 'TimeoutError' ? `连接超过 ${Math.round(route.timeout/1000)} 秒` : error instanceof TypeError ? '浏览器未取得响应（网络或跨域）' : error.message;
      failures.push(new URL(route.url).host + '：' + reason);
      if (error.skipRoute) {
        while (routes[attempt + 1]?.url === route.url) attempt++;
      }
      if (attempt + 1 < routes.length) {
        progress('服务连接暂时中断，正在重试');
        try { await pause(error.delay || 1000 * (attempt + 1), overall); }
        catch (error) { if (signal.aborted) throw signal.reason; throw Error('网页查询超时，请重新检测'); }
      }
    }
  }
  throw Error([...new Set(failures)].join('；') || lastError?.message || '网页查询失败');
}
