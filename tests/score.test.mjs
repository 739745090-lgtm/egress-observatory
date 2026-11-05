// Run: npm test
import test from 'node:test';
import assert from 'node:assert/strict';

// Browser modules (config.js) read location.hostname at import time, so stub it before loading them.
globalThis.location ??= { hostname: '' };
const { score, gradeOf } = await import('../src/score.js');
const { inferASN, detectLease } = await import('../src/asn.js');
const { parseIP, isPublicIP, cidrContains, reverseName, maskText } = await import('../src/util.js');
const { classifyDNS } = await import('../src/probes.js');
const { classifyHostname } = await import('../src/sources.js');

const f = (values = {}) => ({ vpn: null, proxy: null, tor: null, hosting: null, relay: null, abuser: null, crawler: null, mobile: null, bogon: null, ...values });
const ok = data => ({ status: 'ok', data: { flags: f(), ...data } });
const geo = (country = 'JP', extra = {}) => ({ country, city: 'Tokyo', tz: 'Asia/Tokyo', asn: 2516, ...extra });

function clean(extra = {}) {
  return {
    ip: '203.0.113.9', v: 4, self: false,
    sources: {
      proxycheck: ok({ ...geo(), type: 'residential', flags: f({ vpn: false, proxy: false, tor: false, hosting: false }), risk: 0 }),
      ipquery: ok({ ...geo(), flags: f({ vpn: false, proxy: false, tor: false, hosting: false }), risk: 0 }),
      ipinfo: ok(geo()), ipwhois: ok(geo()), ipsb: ok(geo()), ipleak: ok({ ...geo(), regCountry: 'JP' }),
      onionoo: ok({ geoVote: false, flags: f({ tor: false }) }),
    },
    dnsbl: [{ id: 'spamcop', name: 'SpamCop', kind: 'mail', status: 'ok', listed: false }],
    lists: [{ id: 'firehol1', name: 'FireHOL Level 1', kind: 'attack', pts: 15, status: 'ok', listed: false }],
    asn: { asn: 2516, inferred: { cls: 'isp', label: '运营商宽带', hosting: 0.05 } },
    ...extra,
  };
}

test('a clean IP has no deductions; thin clean-ISP evidence adds only a small bonus', () => {
  const result = score(clean());
  assert.equal(result.categories.reduce((sum, c) => sum + c.penalty, 0), 0);
  assert.equal(result.summary.type, 'residential');
  assert.equal(result.checks.asn.consistency.ok, true);
  assert.equal(result.liveDelta, null);
  // Three type votes and an ISP ASN of unknown confidence: (0.75 − 0.5) / 0.4 × 3 × 0.5 ≈ 0.9.
  assert.deepEqual(result.bonus.items.map(i => i.id), ['eyeball']);
  assert.equal(result.bonus.total, 0.9);
  assert.equal(result.score, 93);
  assert.equal(result.grade.letter, 'A');
});

test('a safe business line is not deducted and sits at the base score', () => {
  const evidence = clean({ asn: { asn: 64500, inferred: { cls: 'business', label: '企业网络', hosting: 0.1 } } });
  evidence.sources.proxycheck = ok({ ...geo(), type: 'business', flags: f({ vpn: false, proxy: false, tor: false, hosting: false }), risk: 0 });
  const result = score(evidence);
  assert.equal(result.summary.type, 'business');
  assert.equal(result.categories.reduce((sum, c) => sum + c.penalty, 0), 0);
  assert.equal(result.bonus.items.length, 0);
  assert.equal(result.score, 92);
});

test('voted deductions follow the weighted share: 1 of 8 costs far less than 1 of 2', () => {
  const shodan = ok({ geoVote: false, ports: [12323], tags: ['proxy'], flags: f({ proxy: true }) });
  const proxyItem = evidence => score(evidence).categories.find(c => c.id === 'anon').items.find(i => i.id === 'proxy');

  const half = clean();
  half.sources.shodan = shodan;
  half.sources.ipquery = ok({ ...geo(), flags: f({ vpn: false, tor: false, hosting: false }), risk: 0 });
  // H = 0.5 / (1 − 0.5) = 1, N = 1.0 (Proxycheck) → E = 0.5 → 13 of 26
  assert.equal(proxyItem(half).pts, 13);

  const many = clean();
  many.sources.shodan = shodan;
  for (const id of ['ipinfo', 'ipapi', 'ipapiis', 'iplocate', 'ip2location']) many.sources[id] = ok({ ...geo(), flags: f({ vpn: false, proxy: false, hosting: false }) });
  // N = 1.0 + 0.8 + 1.3 + 0.8 + 0.9 + 0.9 + 0.6 = 6.3 → E = 1 / 7.3 ≈ 0.14 → ≈ 3.6 of 26
  const result = score(many);
  assert.equal(result.checks.anon.proxy.yes, 1);
  assert.equal(result.checks.anon.proxy.of, 8);
  assert.equal(proxyItem(many).pts, 3.6);
  assert.match(proxyItem(many).detail, /^1\/8 来源命中：shodan · 加权占比 14%$/);
});

test('a residential label inside a hosting ASN is flagged as a conflict', () => {
  const evidence = clean({ asn: { asn: 20473, label: 'Vultr', inferred: { cls: 'hosting', label: '机房 / 云', hosting: 0.9 } } });
  const result = score(evidence);
  const conflict = result.categories.find(c => c.id === 'network').items.find(i => i.id === 'asn-conflict');
  assert.ok(conflict, 'expected asn-conflict deduction');
  assert.equal(conflict.pts, 4.5);
  assert.equal(result.checks.asn.consistency.ok, false);
});

test('a residential label under a transit / backbone ASN is flagged but not deducted', () => {
  const result = score(clean({ asn: { asn: 4637, inferred: { cls: 'transit', label: '骨干 / 传输网', hosting: 0.28 } } }));
  // Neither side is a datacenter: the ASN tile warns, the score is untouched.
  assert.equal(result.checks.asn.consistency.warn, true);
  assert.equal(result.checks.asn.level, 'warn');
  assert.equal(result.categories.find(c => c.id === 'network').items.length, 0);
});

test('registration country different from location means broadcast IP', () => {
  const evidence = clean();
  evidence.sources.ipleak = ok({ ...geo(), regCountry: 'FR' });
  evidence.sources.riperir = ok({ regCountry: 'FR', geoVote: false });
  const result = score(evidence);
  assert.equal(result.summary.native, false);
  assert.equal(result.summary.regCountry, 'FR');
  assert.equal(result.categories.find(c => c.id === 'geo').items.find(i => i.id === 'broadcast').pts, 3);

  // Registration evidence that is itself split costs less: FR 1.8 vs JP 0.6 → 3 × 0.75.
  evidence.sources.rdap = ok({ regCountry: 'JP', geoVote: false });
  assert.equal(score(evidence).categories.find(c => c.id === 'geo').items.find(i => i.id === 'broadcast').pts, 2.3);
});

test('geo votes from the same upstream family count once', () => {
  const evidence = clean();
  // Three MaxMind-family sources disagree; they must not outvote independent databases.
  for (const id of ['ipsb', 'ipleak', 'geojs']) evidence.sources[id] = ok(geo('HK'));
  const result = score(evidence);
  assert.equal(result.summary.country, 'JP');
});

test('a confirmed Tor exit caps the score at 25', () => {
  const evidence = clean();
  evidence.sources.onionoo = ok({ geoVote: false, flags: f({ tor: true }), hard: { tor: true } });
  const result = score(evidence);
  assert.ok(result.score <= 25);
  assert.equal(result.uses.ai.level, 'bad');
});

test('live probes only count for the visitor\'s own egress', () => {
  const probes = {
    webrtc: { status: 'ok', leak: true, leakIPs: ['198.51.100.7'], srflx: ['198.51.100.7'], leakCountryDiffers: true },
    tcp: { status: 'ok', relay: true, osMismatch: true, summary: 'relay' },
    tz: { zone: 'Asia/Shanghai', offset: 480 },
    lang: { languages: ['zh-CN'] },
    turnstile: { status: 'ok', outcome: 'interactive', summary: '' },
    recaptcha: { status: 'ok', score: 0.3 },
  };
  const other = score(clean({ probes }));
  assert.equal(other.categories.find(c => c.id === 'live').penalty, 0);
  const self = score(clean({ self: true, probes }));
  const live = self.categories.find(c => c.id === 'live');
  const ids = live.items.map(i => i.id);
  for (const id of ['webrtc', 'tcp', 'tz', 'lang', 'turnstile', 'recaptcha']) assert.ok(ids.includes(id), `missing ${id}`);
  assert.equal(live.items.find(i => i.id === 'recaptcha').pts, 13.3);
  assert.equal(self.ipScore, other.ipScore);
  assert.equal(self.score, Math.round(92 + self.bonus.total - live.penalty));
  assert.ok(live.penalty <= live.cap);
});

test('blacklists and threat lists land in the abuse category with caps', () => {
  const evidence = clean();
  evidence.dnsbl = Array.from({ length: 8 }, (_, i) => ({ id: `bl${i}`, name: `BL${i}`, kind: i < 4 ? 'mail' : 'abuse', status: 'ok', listed: true }));
  evidence.lists = [{ id: 'firehol1', name: 'FireHOL Level 1', kind: 'attack', pts: 15, status: 'ok', listed: true }, { id: 'firehol3', name: 'FireHOL Level 3', kind: 'attack', pts: 6, status: 'ok', listed: true }];
  const abuse = score(evidence).categories.find(c => c.id === 'abuse');
  assert.equal(abuse.items.find(i => i.id === 'dnsbl').pts, 20);
  assert.equal(abuse.items.find(i => i.id === 'firehol').pts, 17); // worst list 15 + 2 for the second list
  assert.equal(abuse.raw, 37);
  assert.equal(abuse.penalty, Math.min(abuse.cap, 37));
});

test('a reliable direct observation is hard to outvote, a weak one is not', () => {
  const strong = clean();
  strong.extraVotes = { proxy: [{ by: '公开 SOCKS 代理', value: true, w: 0.85, obs: true }] };
  // Two databases say "not a proxy", but an open proxy list saw one running here: H = 0.85 / 0.15 ≈ 5.7, N = 1.8.
  const result = score(strong);
  assert.ok(result.checks.anon.proxy.E >= 0.75, `E ${result.checks.anon.proxy.E}`);
  assert.ok(result.categories.find(c => c.id === 'anon').items.find(i => i.id === 'proxy').pts >= 15);

  const weak = clean();
  weak.sources.shodan = ok({ geoVote: false, ports: [3128], tags: ['proxy'], flags: f({ proxy: true }) });
  assert.ok(score(weak).checks.anon.proxy.E < 0.4);
});

test('VPN and proxy flags for the same egress are not counted twice', () => {
  const evidence = clean();
  for (const id of ['proxycheck', 'ipquery']) evidence.sources[id].data.flags = f({ vpn: true, proxy: true, tor: false, hosting: false });
  const anon = score(evidence).categories.find(c => c.id === 'anon');
  assert.equal(anon.items.find(i => i.id === 'proxy').pts, 26);
  assert.equal(anon.items.find(i => i.id === 'vpn').pts, 12);
  assert.equal(anon.raw, 38);
});

test('a lone high fraud score weighs less when many vendors disagree', () => {
  const few = clean();
  few.sources.abuseipdb = ok({ ...geo(), flags: f(), risk: 85 });
  const many = clean();
  many.sources.abuseipdb = ok({ ...geo(), flags: f(), risk: 85 });
  for (const id of ['ipapiis', 'ipdata', 'scamalytics']) many.sources[id] = ok({ ...geo(), flags: f(), risk: 0 });
  const riskFew = score(few).checks.risk.value;
  const riskMany = score(many).checks.risk.value;
  assert.ok(riskMany < riskFew - 15, `${riskMany} vs ${riskFew}`);
  assert.ok(riskMany >= 30, `still visible: ${riskMany}`);
});

test('one high fraud score from a major vendor is not averaged away', () => {
  const evidence = clean();
  evidence.sources.abuseipdb = ok({ ...geo(), flags: f(), risk: 85 });
  const risk = score(evidence).checks.risk.value;
  // Mean alone would be ~33; the blend keeps the worst vendor visible.
  assert.ok(risk >= 50, `risk ${risk}`);
});

test('an IPQS fraud score weighs less than the same score from AbuseIPDB', () => {
  const ipqs = clean();
  ipqs.sources.ipqs = ok({ ...geo(), flags: f(), risk: 85 });
  const abuse = clean();
  abuse.sources.abuseipdb = ok({ ...geo(), flags: f(), risk: 85 });
  const riskIpqs = score(ipqs).checks.risk.value;
  const riskAbuse = score(abuse).checks.risk.value;
  assert.ok(riskIpqs < riskAbuse - 5, `${riskIpqs} vs ${riskAbuse}`);
});

test('missing fields never become negatives', () => {
  const result = score({ ip: '203.0.113.9', v: 4, self: false, sources: { ipinfo: ok(geo()) }, dnsbl: [], lists: [] });
  assert.equal(result.checks.anon.level, 'none');
  assert.equal(result.checks.tor.level, 'none');
  assert.equal(result.confidence.level, 'low');
});

test('grades', () => {
  assert.equal(gradeOf(96).letter, 'S');
  assert.equal(gradeOf(85).letter, 'A');
  assert.equal(gradeOf(70).letter, 'B');
  assert.equal(gradeOf(55).letter, 'C');
  assert.equal(gradeOf(40).letter, 'D');
  assert.equal(gradeOf(39).letter, 'F');
});

test('ASN inference: backbone, hosting, ISP', () => {
  assert.equal(inferASN({ asn: 4637, names: ['Telstra Global'], pdb: { types: ['NSP'] } }).cls, 'transit');
  const vultr = inferASN({ asn: 20473, names: ['AS-CHOOPA'], pdb: { types: ['Content'], ratio: 'Heavy Outbound' } });
  assert.equal(vultr.cls, 'hosting');
  assert.ok(vultr.hosting > 0.8);
  assert.equal(inferASN({ asn: 64512, names: ['Example Broadband Cable'], pdb: { types: ['Cable/DSL/ISP'], ratio: 'Heavy Inbound' } }).cls, 'isp');
  assert.equal(inferASN({ asn: 64513, names: ['Tiny Cloud Hosting'], v4ips: 1024 }).cls, 'hosting');
  assert.equal(inferASN({ asn: 64514 }).cls, null);
});

test('lease detection: sub-allocated to a different org via an IP broker', () => {
  const lease = detectLease({
    rdap: { netname: 'BUDGET31', orgName: 'MINT SA', status: 'SUB-ALLOCATED PA', regDate: new Date(Date.now() - 200 * 864e5).toISOString(), abuseName: 'Internet Utilities Abuse Contact', regCountry: 'JP', orgCountry: 'FR' },
    holder: 'ASN-TELSTRA-GLOBAL - Telstra Global',
  });
  assert.equal(lease.leased, true);
  assert.equal(lease.reasons.length, 3);
  assert.equal(detectLease({ rdap: { netname: 'OCN', orgName: 'NTT Communications', status: 'ALLOCATED PA', regDate: '2001-01-01' }, holder: 'OCN NTT Communications Corporation' }).leased, false);
});

test('DNS classification against the egress location', () => {
  const raw = { status: 'ok', resolvers: [{ ip: '162.158.1.1', country: 'HK', asn: 13335, org: 'CloudFlare Inc' }], ecs: { subnet: '1.2.3.0', country: 'CN' } };
  const result = classifyDNS(raw, { country: 'JP', asn: 4637 });
  assert.equal(result.verdict, 'public');
  assert.equal(result.ecsLeak, true);
  const leak = classifyDNS({ status: 'ok', resolvers: [{ ip: '202.96.1.1', country: 'CN', asn: 4134, org: 'Chinanet' }] }, { country: 'US', asn: 7922 });
  assert.equal(leak.verdict, 'leak-cn');
  assert.equal(classifyDNS({ status: 'ok', resolvers: [{ ip: '1.1.1.1', country: 'JP', asn: 2516 }] }, { country: 'JP', asn: 2516 }).verdict, 'own');
});

test('hidden mode masks every address in free text, including the /24 and hostname forms', () => {
  const known = ['203.0.113.9'];
  assert.equal(maskText('203.0.113.0/24 在 14 个威胁列表里没有任何邻居上榜', known), '203.0.•••.•••/24 在 14 个威胁列表里没有任何邻居上榜');
  assert.equal(maskText('例如 203.0.113.7、203.0.113.99', known), '例如 203.0.•••.•••、203.0.•••.•••');
  assert.equal(maskText('9.113.0.203.static.example.net', known), '•••.•••.•••.•••.static.example.net');
  assert.equal(maskText('9-113-0-203.static.isp.jp', known), '•••-•••-•••-•••.static.isp.jp');
  assert.equal(maskText('2001:db8::/32', known), '2001:db8:••••:••••/32');
  // Not addresses: dates, clock times, ratios, ports, ASNs.
  for (const text of ['最近 2025-07-10', 'Asia/Tokyo 10:36:14', '约为全网平均的 0.1 倍', '端口 12323, 44444', 'AS4637 · 机器 51%']) assert.equal(maskText(text, known), text);
});

test('IP helpers', () => {
  assert.deepEqual(parseIP('2001:DB8:0:0:0:0:0:1'), { ip: '2001:db8::1', v: 6, words: [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1] });
  assert.equal(parseIP('256.1.1.1'), null);
  assert.equal(isPublicIP('10.1.2.3'), false);
  assert.equal(isPublicIP('2001:db8::1'), false);
  assert.equal(isPublicIP('8.8.8.8'), true);
  assert.equal(cidrContains('203.0.113.0/24', '203.0.113.9'), true);
  assert.equal(cidrContains('203.0.112.0/24', '203.0.113.9'), false);
  assert.equal(reverseName('203.0.113.9'), '9.113.0.203');
  assert.equal(reverseName('2001:db8::1').slice(0, 7), '1.0.0.0');
});

test('PTR hostname hints', () => {
  assert.equal(classifyHostname('vps-12.example-hosting.net').type, 'hosting');
  assert.equal(classifyHostname('p1234-ipngn.adsl.ocn.ne.jp').type, 'residential');
  assert.equal(classifyHostname(null).type, null);
});

test('neighbours and ASN abuse density land in their own capped category', () => {
  const evidence = clean({
    neighbours: { prefix: '203.0.113.0/24', count: 12, sample: [], lists: ['blocklist.de 12'], whole: ['DShield 攻击网段'], tor: 1, checked: 7 },
    asnRep: { size: 65536, listed: 300, per10k: 45.8, baseline: 0.15, ratio: 305, counts: {} },
  });
  const result = score(evidence);
  const category = result.categories.find(c => c.id === 'neighbours');
  const ids = category.items.map(i => i.id);
  for (const id of ['block-listed', 'neighbours', 'neighbour-tor', 'asn-abuse']) assert.ok(ids.includes(id), `missing ${id}`);
  assert.equal(category.penalty, category.cap);
  assert.equal(result.checks.neighbours.level, 'bad');
  assert.equal(result.checks.asnRep.level, 'bad');
});

test('strong positive evidence earns bonuses up to the cap, and type hints weigh little', () => {
  const evidence = clean({
    neighbours: { prefix: '203.0.113.0/24', count: 0, sample: [], lists: [], whole: [], tor: 0, checked: 7 },
    asnRep: { size: 1 << 20, listed: 2, per10k: 0.02, baseline: 0.15, ratio: 0.1, counts: {} },
    asn: { asn: 2516, rpki: 'valid', inferred: { cls: 'isp', label: '运营商宽带', hosting: 0.05, confidence: 0.9, mix: [{ value: 'isp', share: 1 }] } },
  });
  for (const id of ['ipapi', 'ipapiis']) evidence.sources[id] = ok({ ...geo(), flags: f({ vpn: false, proxy: false, hosting: false }), risk: 0 });
  const result = score(evidence);
  const ids = result.bonus.items.map(i => i.id);
  for (const id of ['multi-clean', 'clean-neighbours', 'asn-clean', 'eyeball', 'rpki']) assert.ok(ids.includes(id), `missing bonus ${id}`);
  assert.equal(result.bonus.total, 10);
  assert.equal(result.score, 100);
  assert.equal(result.grade.letter, 'S');

  assert.equal(result.bonus.items.find(i => i.id === 'eyeball').pts, 3);

  // A business line under a backbone ASN is a hint for the ASN tile, not a deduction.
  const backbone = clean({ asn: { asn: 4637, inferred: { cls: 'transit', label: '骨干 / 传输网', hosting: 0.28 } } });
  backbone.sources.proxycheck = ok({ ...geo(), type: 'business', flags: f({ vpn: false, proxy: false, tor: false, hosting: false }), risk: 0 });
  assert.equal(score(backbone).score, 92);
});

test('the clean-ISP bonus is forfeited by any anonymity evidence', () => {
  const evidence = clean({ asn: { asn: 2516, inferred: { cls: 'isp', label: '运营商宽带', hosting: 0.05, confidence: 0.9, mix: [{ value: 'isp', share: 1 }] } } });
  for (const id of ['ipapi', 'ipapiis']) evidence.sources[id] = ok({ ...geo(), flags: f({ vpn: false, proxy: false, hosting: false }), risk: 0 });
  assert.equal(score(evidence).bonus.items.find(i => i.id === 'eyeball').pts, 3);
  evidence.sources.proxycheck.data.flags.proxy = true; // residential proxy
  assert.equal(score(evidence).bonus.items.find(i => i.id === 'eyeball'), undefined);
});

// ---------- use-case meters ----------

const USE_IDS = ['stream', 'ai', 'captcha', 'account', 'mail', 'social'];
const levelOf = value => (value >= 75 ? 'good' : value >= 50 ? 'warn' : 'bad');

test('every use case is a 0–100 meter whose level follows the 50 / 75 thresholds', () => {
  for (const evidence of [clean(), clean({ self: true, probes: { tcp: { status: 'ok', relay: true, summary: 'relay' } } })]) {
    const { uses } = score(evidence);
    for (const id of USE_IDS) {
      const use = uses[id];
      assert.ok(use.score >= 0 && use.score <= 100, `${id} ${use.score}`);
      assert.equal(use.level, levelOf(use.score), id);
      assert.equal(Math.round(Math.max(0, 100 - use.items.reduce((sum, item) => sum + item.pts, 0))), use.score, `${id} is 100 − Σ items`);
    }
  }
});

test('each use case weighs the same evidence differently', () => {
  // A clean VPS with a PTR: fine for mail, poor for streaming and social media.
  const vps = clean({ asn: { asn: 20473, label: 'Vultr', inferred: { cls: 'hosting', label: '机房 / 云', hosting: 0.9, confidence: 0.9, mix: [{ value: 'hosting', share: 1 }] } } });
  vps.sources.proxycheck = ok({ ...geo(), type: 'hosting', flags: f({ vpn: false, proxy: false, tor: false, hosting: true }), risk: 0 });
  vps.sources.ipquery = ok({ ...geo(), flags: f({ vpn: false, proxy: false, tor: false, hosting: true }), risk: 0 });
  vps.sources.ptr = ok({ geoVote: false, hostname: 'mail.example.net', type: null });
  const server = score(vps).uses;
  assert.equal(server.mail.score, 100);
  assert.equal(server.stream.level, 'bad');
  assert.equal(server.social.level, 'bad');
  assert.equal(server.ai.level, 'good');

  // A clean home line: the reverse.
  const home = score(clean()).uses;
  assert.equal(home.stream.score, 100);
  assert.equal(home.social.score, 100);
  assert.equal(home.mail.level, 'bad');
  assert.ok(home.mail.items.some(item => item.label === '家宽地址段'));
});

test('a missing PTR costs mail points only once the PTR lookup has answered', () => {
  const evidence = clean();
  assert.ok(!score(evidence).uses.mail.items.some(item => item.label.includes('PTR')));
  evidence.sources.ptr = ok({ geoVote: false, hostname: null, type: null });
  assert.equal(score(evidence).uses.mail.items.find(item => item.label === '没有反向解析（PTR）').pts, 25);
});

test('hard gates cap a meter: unsupported AI region and Tor exits', () => {
  const hk = clean();
  for (const id of ['proxycheck', 'ipquery', 'ipinfo', 'ipwhois', 'ipsb', 'ipleak']) hk.sources[id].data.country = 'HK';
  const ai = score(hk).uses.ai;
  assert.equal(ai.score, 0);
  assert.match(ai.gate, /HK/);

  const tor = clean();
  tor.sources.onionoo = ok({ geoVote: false, flags: f({ tor: true }), hard: { tor: true } });
  const uses = score(tor).uses;
  for (const id of USE_IDS) assert.ok(uses[id].score <= 10 && uses[id].gate, `${id} ${uses[id].score}`);
});

test('a measured CAPTCHA pass damps the predicted CAPTCHA deductions', () => {
  const evidence = clean();
  evidence.sources.proxycheck.data.flags.proxy = true;
  const predicted = score(evidence).uses.captcha;
  const measured = score({ ...evidence, self: true, probes: { turnstile: { status: 'ok', outcome: 'silent', summary: '' }, recaptcha: { status: 'ok', score: 0.9 } } }).uses.captcha;
  const proxyPts = use => use.items.find(item => item.label === 'VPN / 代理标记').pts;
  assert.equal(proxyPts(measured), r1(proxyPts(predicted) * 0.4));
  assert.ok(measured.score > predicted.score);
  assert.match(measured.note, /40%/);

  const failed = score({ ...evidence, self: true, probes: { turnstile: { status: 'ok', outcome: 'fail', summary: '' } } }).uses.captcha;
  assert.equal(failed.level, 'bad');
});

test('人机流量: a bot-heavy ASN costs reputation and scenario points, a human one earns a bonus', () => {
  const withBots = bot => clean({ asn: { asn: 2516, botShare: bot, radar: { bot, human: 1 - bot, window: '28d' }, inferred: { cls: 'isp', label: '运营商宽带', hosting: 0.05 } } });

  const heavy = score(withBots(0.85));
  // (0.85 − 0.4) / 0.5 = 0.9 → 6 × 0.9 = 5.4
  assert.equal(heavy.categories.find(c => c.id === 'neighbours').items.find(i => i.id === 'asn-bots').pts, 5.4);
  assert.equal(heavy.checks.bots.level, 'bad');
  assert.equal(heavy.checks.bots.human, 0.15);
  for (const id of ['captcha', 'ai', 'account', 'social']) assert.ok(heavy.uses[id].items.some(item => item.label.startsWith('人机流量')), `${id} misses the bot item`);
  assert.ok(!heavy.uses.mail.items.some(item => item.label.startsWith('人机流量')));

  const human = score(withBots(0.15));
  assert.equal(human.checks.bots.level, 'good');
  assert.ok(human.bonus.items.some(i => i.id === 'asn-human'));
  assert.ok(!human.categories.some(c => c.items.some(i => i.id === 'asn-bots')));

  // No Radar data: nothing counted either way.
  const none = score(clean());
  assert.equal(none.checks.bots.level, 'none');
  assert.equal(none.checks.bots.bot, null);
});

function r1(value) { return Math.round(value * 10) / 10; }
