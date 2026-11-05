// The Chrome helper's background worker, driven through a fake chrome.* API.
import test from 'node:test';
import assert from 'node:assert/strict';

const IP = '8.8.8.8';
const sent = [];
const removed = new Set();
const tabs = new Map();
let listener;
let open = 0;
let peak = 0;
let nextId = 100;
// Per provider: how each executeScript call answers, in order; the last answer repeats.
const script = {
  ipsuper: [{ ip: IP, time: Date.now(), headers: [], rows: {}, riskPercent: {}, riskFlags: {} }],
  ipregistry: ['challenge', 'challenge', { ip: IP, data: { flags: { vpn: false }, country: 'JP' } }],
  dbip: ['offsite'],
};
const calls = {};

globalThis.chrome = {
  runtime: { getManifest: () => ({ version: '9.9.9' }), onMessage: { addListener: fn => { listener = fn; } } },
  tabs: {
    async create({ url }) {
      const id = nextId++;
      const provider = url === 'about:blank' ? null : Object.keys(script).find(key => url.includes(key === 'dbip' ? 'db-ip' : key)) || url;
      tabs.set(id, { id, url, provider, windowId: 1 });
      if (provider) { open++; peak = Math.max(peak, open); }
      return { id, windowId: 1 };
    },
    async get(id) { if (!tabs.has(id)) throw Error('No tab'); return { status: 'complete', url: tabs.get(id).url }; },
    async remove(id) { if (tabs.get(id)?.provider && !removed.has(id)) open--; removed.add(id); },
    async group() { return 7; },
    async update(id) { return { id, windowId: 1 }; },
    async sendMessage(tab, message) { sent.push(message); },
  },
  tabGroups: { async update() {} },
  windows: { async update() {} },
  scripting: {
    async executeScript({ target, args }) {
      const tab = tabs.get(target.tabId);
      const provider = Object.keys(script).find(key => tab.url.includes(key === 'dbip' ? 'db-ip' : key));
      const answers = script[provider] || [{ ip: IP, data: { flags: { proxy: false } } }];
      calls[provider] = (calls[provider] || 0) + 1;
      const answer = answers[Math.min(calls[provider], answers.length) - 1];
      if (answer === 'challenge') throw Error('网页需要浏览器或人机校验');
      if (answer === 'offsite') { tab.url = 'https://elsewhere.example/'; return [{ result: null }]; }
      return [{ result: provider === 'ipsuper' ? answer : { ip: args[1], data: answer.data } }];
    },
  },
};

await import('../browser-helper/background.js');
const sender = { tab: { id: 1, windowId: 1 }, url: 'http://127.0.0.1:4187/' };
const ask = message => new Promise(resolve => { if (listener(message, sender, resolve) !== true) resolve(undefined); });

test('the helper reads every source page, three at a time, and reports each one as it lands', { timeout: 30000 }, async () => {
  const report = ask({ kind: 'lookup', requestId: 'r1', ip: IP });
  // Wait until the challenged page has told the Egress page, then bring it forward on request.
  while (!sent.some(m => m.report.sources.ipregistry?.status === 'challenge')) await new Promise(r => setTimeout(r, 50));
  assert.deepEqual(await ask({ kind: 'focus', requestId: 'r1', provider: 'ipregistry' }), { focused: true });
  const done = await report;

  // Three loading slots; the page waiting on a human check gives its slot back but stays open.
  assert.ok(peak >= 3 && peak <= 4, `3 loading pages, plus at most the challenged one; saw ${peak}`);
  assert.equal(done.ip, IP);
  assert.equal(done.version, '9.9.9');
  assert.deepEqual(Object.keys(done.sources).sort(), ['blackbox', 'dbip', 'greynoise', 'ip2location', 'iphub', 'ipqs', 'ipquery', 'ipregistry', 'scamalytics']);
  assert.ok(!('ipapiis' in done.sources), 'ipapi.is is not opened: its page spends the per-IP daily quota');
  assert.equal(done.sources.ipregistry.status, 'ok', 'a page behind a human check is read once the visitor completes it');
  assert.equal(done.sources.ipregistry.data.country, 'JP');
  assert.equal(done.sources.dbip.status, 'error');
  assert.match(done.sources.dbip.error, /其他站点/);
  assert.ok(done.ipsuper, 'IPSuper report travels separately');
  // Partial messages: one challenge notice, then one per source including IPSuper.
  const partial = sent.filter(m => m.requestId === 'r1');
  assert.equal(partial.filter(m => m.report.sources.ipregistry?.status === 'challenge').length, 1);
  assert.ok(partial.some(m => m.report.ipsuper));
  assert.ok(partial.some(m => m.report.sources.ipregistry?.status === 'ok'));
  assert.equal(open, 0, 'every result page is closed afterwards');
});

test('a second lookup within ten minutes is served from the helper cache', { timeout: 10000 }, async () => {
  const before = { ...calls };
  const done = await ask({ kind: 'lookup', requestId: 'r2', ip: IP });
  assert.equal(done.sources.ipqs.status, 'ok');
  assert.equal(calls.ipqs, before.ipqs, 'cached rows are not read again');
  assert.equal(calls.ipregistry, before.ipregistry);
});

test('lookups for non-public addresses and other origins are refused', async () => {
  assert.deepEqual(await ask({ kind: 'lookup', requestId: 'r3', ip: '10.0.0.1' }), { error: '需要有效的公网 IP' });
  assert.equal(listener({ kind: 'lookup', requestId: 'r4', ip: IP }, { tab: { id: 2 }, url: 'https://evil.example/' }, () => {}), undefined);
});

test('the Egress page accepts the new page fields and marks pages waiting on a human check', async () => {
  const { readProviderReport, PAGE_SOURCES } = await import('../src/provider-pages.js');
  for (const id of ['ip2location', 'greynoise']) assert.ok(PAGE_SOURCES.includes(id));
  const time = Date.now();
  const pages = readProviderReport({ ip: IP, time, sources: {
    ip2location: { status: 'ok', time, data: { usageType: 'residential', usageDetail: '(ISP) Fixed Line ISP', lat: 35.7, lon: 139.7, risk: 0, proxyProvider: 'Tor', flags: { proxy: false, bogon: false } } },
    greynoise: { status: 'ok', time, data: { noise: true, classification: 'benign', name: 'Shodan.io', lastSeen: '2026-11-05', geoVote: false, flags: { crawler: true, abuser: false } } },
    ipregistry: { status: 'challenge', error: '等待你在 Chrome 中完成人机验证', time },
    ipdata: { status: 'ok', time, data: { lat: 500, noise: 'yes', flags: {} } },
  } }, IP);
  assert.deepEqual(pages.ip2location.data, { flags: { proxy: false, bogon: false }, usageType: 'residential', usageDetail: '(ISP) Fixed Line ISP', lat: 35.7, lon: 139.7, risk: 0, proxyProvider: 'Tor' });
  assert.equal(pages.greynoise.data.noise, true);
  assert.equal(pages.greynoise.data.name, 'Shodan.io');
  assert.deepEqual(pages.ipregistry, { status: 'error', error: '等待你在 Chrome 中完成人机验证', challenge: true });
  assert.equal(pages.ipdata.status, 'error', 'out-of-range coordinates and non-boolean flags are dropped');
});
