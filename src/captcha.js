/**
 * Real human-verification checks: Cloudflare Turnstile (does it pass without interaction?)
 * and Google reCAPTCHA v3 (0.0–1.0 score, read server-side with the secret).
 */
import { API_BASE, TURNSTILE_SITE_KEY, RECAPTCHA_SITE_KEY } from '../config.js';

const TEST_TURNSTILE = '1x00000000000000000000AA';
const isLocal = ['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname);
const testMode = isLocal && new URLSearchParams(location.search).has('captchaTest');

export const captchaConfig = {
  turnstile: testMode ? TEST_TURNSTILE : TURNSTILE_SITE_KEY || '',
  recaptcha: RECAPTCHA_SITE_KEY || '',
  testMode,
};

const scripts = new Map();
function loadScript(src) {
  if (!scripts.has(src)) {
    scripts.set(src, new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = src; script.async = true; script.defer = true; script.referrerPolicy = 'origin';
      const finish = error => {
        clearTimeout(timer);
        script.onload = script.onerror = null;
        if (error) { scripts.delete(src); script.remove(); reject(error); }
        else resolve();
      };
      const timer = setTimeout(() => finish(new Error('脚本加载超时')), 15000);
      script.onload = () => finish();
      script.onerror = () => finish(new Error('脚本加载失败'));
      document.head.append(script);
    }));
  }
  return scripts.get(src);
}

async function withTimeout(task, ms, message) {
  let timer;
  try {
    return await Promise.race([task, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), ms);
    })]);
  } finally { clearTimeout(timer); }
}

async function verify(kind, token, health) {
  if (health && !health.routes?.includes(`${kind}-verify`)) return { verified: false, unconfigured: true, reason: '服务端未配置密钥，只记录浏览器端结果' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(`${API_BASE}/v1/${kind}/verify`, {
      method: 'POST', credentials: 'omit', referrerPolicy: 'no-referrer',
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }),
    });
    const data = await response.json();
    if (response.status === 503 && data.errorCode === 'not-configured') return { verified: false, unconfigured: true, reason: data.error };
    if (!response.ok) return { verified: false, reason: `校验接口 HTTP ${response.status}：${data.error || '请求未被接受'}` };
    return { verified: true, ...data };
  } catch { return { verified: false, reason: controller.signal.aborted ? '服务端校验超时，请重试' : '服务端校验连接失败，请重试' }; }
  finally { clearTimeout(timer); }
}

export async function runTurnstile(container, health) {
  if (!captchaConfig.turnstile) return { status: 'skip', reason: '未配置 Turnstile site key' };
  try { await loadScript('https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'); }
  catch { return { status: 'ok', outcome: 'fail', summary: 'Turnstile 脚本被拦截或无法连接 Cloudflare' }; }
  container.replaceChildren();
  const started = performance.now();
  const client = await new Promise(resolve => {
    let interactive = false;
    const finish = value => { clearTimeout(timer); resolve({ ...value, interactive, ms: Math.round(performance.now() - started) }); };
    const timer = setTimeout(() => finish({ error: 'timeout' }), 60000);
    try {
      window.turnstile.render(container, {
        sitekey: captchaConfig.turnstile, appearance: 'interaction-only', retry: 'never', 'refresh-expired': 'never', theme: 'dark', language: 'zh-cn',
        callback: token => finish({ token }),
        'before-interactive-callback': () => { interactive = true; },
        'error-callback': code => { finish({ error: String(code || 'error') }); return true; },
        'unsupported-callback': () => finish({ error: 'unsupported' }),
        'timeout-callback': () => finish({ error: 'challenge-timeout' }),
      });
    } catch { finish({ error: 'render' }); }
  });
  if (!client.token) {
    // Only challenge failures (600xxx), client execution errors (300xxx) and challenge timeouts say anything about this
    // visitor. Site-key / hostname / parameter problems, unsupported browsers and Cloudflare internal errors do not.
    const code = String(client.error);
    const verdict = /^(6\d{5}|3\d{5}|110600|110620|challenge-timeout|timeout)$/.test(code);
    if (!verdict) {
      const reason = /^1102/.test(code) ? '当前域名未加入 Turnstile 的主机名列表' : /^(1101|400020)/.test(code) ? 'site key 无效' : /^(1105|unsupported)/.test(code) ? '浏览器不受支持' : '配置或 Cloudflare 内部错误';
      return { status: 'error', error: `${reason}（${code}），本项不计分` };
    }
    return { status: 'ok', outcome: 'fail', ms: client.ms, summary: `Cloudflare 没有放行（${code}）` };
  }
  const server = testMode ? { verified: false, reason: '本地测试密钥，结果恒为通过' } : await verify('turnstile', client.token, health);
  if (server.verified && server.success === false) {
    return { status: 'ok', outcome: 'fail', ms: client.ms, server, summary: `服务端校验未通过（${(server.errorCodes || []).join(', ') || '未知原因'}）` };
  }
  const outcome = client.interactive ? 'interactive' : 'silent';
  return {
    status: 'ok', outcome, ms: client.ms, server, test: testMode,
    summary: outcome === 'silent' ? `直接通过，用时 ${(client.ms / 1000).toFixed(1)} 秒，没有弹出验证` : '需要手动点击验证后才放行',
  };
}

export async function runRecaptcha(health) {
  if (!captchaConfig.recaptcha) return { status: 'skip', reason: '未配置 reCAPTCHA site key' };
  const key = encodeURIComponent(captchaConfig.recaptcha);
  try { await loadScript(`https://www.google.com/recaptcha/api.js?render=${key}`); }
  catch {
    try { await loadScript(`https://www.recaptcha.net/recaptcha/api.js?render=${key}`); }
    catch { return { status: 'error', error: '无法加载 reCAPTCHA（Google 不可达）' }; }
  }
  try {
    await withTimeout(new Promise(resolve => window.grecaptcha.ready(resolve)), 20000, 'reCAPTCHA 初始化超时，请重试');
    const token = await withTimeout(window.grecaptcha.execute(captchaConfig.recaptcha, { action: 'ip_check' }), 20000, 'reCAPTCHA 执行超时，请重试');
    const server = await verify('recaptcha', token, health);
    if (!server.verified) return server.unconfigured
      ? { status: 'skip', reason: server.reason, pendingSecret: true }
      : { status: 'error', error: server.reason || '服务端校验请求失败' };
    if (!server.success || typeof server.score !== 'number') return { status: 'error', error: `校验失败（${(server.errorCodes || []).join(', ') || '无分数'}）` };
    return { status: 'ok', score: server.score, action: server.action, summary: `Google 给出 ${server.score.toFixed(1)} 分（1.0 最像真人）` };
  } catch (error) { return { status: 'error', error: error.message?.includes('超时') ? error.message : 'reCAPTCHA 执行失败，请重试' }; }
}
