/** Read target-specific, rendered fields only. Shared by Chromium and the import bookmark. */
export function extractProviderPage(provider, ip, raw = null) {
  const body = document.body.innerText;
  const clean = value => {
    const s = String(value ?? '').trim();
    return !s || /^(?:n\/a|unknown|null|undefined|[-—])$/i.test(s) ? null : s.slice(0, 240);
  };
  const type = value => ({isp:'residential', residential:'residential', business:'business', commercial:'business', hosting:'hosting', datacenter:'hosting', mobile:'mobile', cellular:'mobile', education:'education', government:'government'})[String(value || '').trim().toLowerCase()] || null;
  const yes = value => /^(yes|true)$/i.test(value || '') ? true : /^(no|false)$/i.test(value || '') ? false : null;
  const rows = {};
  for (const table of document.querySelectorAll('table')) {
    const trs = [...table.querySelectorAll('tr')];
    trs.forEach((tr, index) => {
      const cells = [...tr.children];
      if (cells.length === 2 && cells[0].tagName === 'TH' && cells[1].tagName === 'TD') rows[cells[0].innerText.trim()] = cells[1].innerText.trim();
      if (cells.length && cells.every(c => c.tagName === 'TH')) {
        const values = [...(trs[index + 1]?.children || [])];
        if (values.length === cells.length && values.every(c => c.tagName === 'TD')) cells.forEach((cell, i) => { rows[cell.innerText.trim()] = values[i].innerText.trim(); });
      }
    });
  }
  const data = { flags: {} };
  const hasTarget = node => node?.innerText.split(/[^\da-f:.]+/i).some(word => word === ip);
  let returned;
  if (provider === 'iphub') {
    const field = name => raw ? name.split('.').reduce((value, key) => value?.[key], raw) : document.querySelector('[data-copy-field="' + name + '"]')?.textContent.trim();
    returned = field('ip');
    if (returned === ip) {
      data.block = Number(field('block'));
      data.country = clean(field('countryCode'));
      data.asn = Number(field('asn')) || null;
      data.org = clean(field('isp'));
      // block 0 covers both residential and business; it is not a residential vote.
      if (data.block === 0) { data.usageDetail = '家宽或商业'; data.flags.hosting = false; }
      if (data.block === 1) data.usageDetail = '代理 / VPN / 机房';
      if (data.block === 2) data.usageDetail = '混合类型';
      for (const [label,key] of [['proxy','proxy'],['tor','tor'],['hosting','hosting'],['relay','relay'],['residentialProxy','resProxy']]) {
        const value = field('proxyType.' + label);
        const flag = typeof value === 'boolean' ? value : yes(value);
        if (flag !== null) data.flags[key] = flag;
      }
      data.geoVote = false;
    }
  } else if (provider === 'ipqs') {
    returned = hasTarget(document.querySelector('h1')) ? ip : null;
    if (returned) {
      for (const [label, key] of [['VPN','vpn'],['PROXY','proxy'],['TOR','tor']]) { const v = yes(rows[label]); if (v !== null) data.flags[key] = v; }
      for (const [label,key] of [['Recent Abuse','abuser'],['Bot','crawler'],['Datacenter','hosting']]) { const value = yes(rows[label]); if (value !== null) data.flags[key] = value; }
      const score = body.match(/(?:scoring|Fraud Score\s*:?)[\s]*(\d{1,3})(?:\s*out of 100)?/i);
      if (score && Number(score[1]) <= 100) data.risk = Number(score[1]);
      data.city = clean(rows.City); data.region = clean(rows.Region);
      data.connectionType = clean(rows['Connection Type']);
      data.usageType = type(data.connectionType);
      data.geoVote = false;
    }
  } else if (provider === 'scamalytics') {
    returned = hasTarget(document.querySelector('h1')) ? ip : null;
    if (returned) {
      const score = body.match(/Fraud Score:\s*(\d{1,3})/i);
      if (score && Number(score[1]) <= 100) data.risk = Number(score[1]);
      for (const [label, key] of [['Anonymizing VPN','vpn'],['Tor Exit Node','tor'],['Datacenter','hosting'],['Search Engine Robot','crawler'],['Residential Proxy','resProxy']]) { const v = yes(rows[label]); if (v !== null) data.flags[key] = v; }
      const proxy = ['Public Proxy','Web Proxy'].map(key => yes(rows[key]));
      if (proxy.includes(true)) data.flags.proxy = true;
      else if (proxy.every(v => v === false)) data.flags.proxy = false;
      if (data.flags.hosting == null) { const server = yes(rows.Server); if (server !== null) data.flags.hosting = server; }
      // The blacklist rows Scamalytics checks itself (Spamhaus, FireHOL, IPsum, X4Bnet).
      const listed = ['Spamhaus','Firehol','IPsum','X4Bnet Spambot'].map(key => yes(rows[key])).filter(v => v !== null);
      if (listed.includes(true)) data.flags.abuser = true; else if (listed.length) data.flags.abuser = false;
      data.connectionType = clean(rows['Connection type']); data.usageType = type(data.connectionType);
      data.country = clean(rows['Country Code']); if (!/^[A-Z]{2}$/.test(data.country || '')) delete data.country;
      data.city = clean(rows.City); data.region = clean(rows['State / Province']);
      data.asn = Number(rows.ASN) || null; data.org = clean(rows['Organization Name'] || rows['ISP Name']);
      data.geoVote = false;
    }
  } else if (provider === 'ip2location') {
    // Server-rendered "label + p.ip-result" pairs; richer than the keyless API (usage, proxy type, threat, fraud score).
    const f = {};
    for (const label of document.querySelectorAll('label')) {
      const value = label.nextElementSibling;
      if (value?.classList.contains('ip-result')) f[label.innerText.trim()] ??= value.innerText.trim();
    }
    returned = f['IP Address'] === ip ? ip : null;
    if (returned) {
      const code = value => /^\(([A-Z/]+)\)/.exec(value || '')?.[1] || null;
      const usage = code(f['Usage Type']);
      data.usageType = usage ? ({ISP:'residential', 'ISP/MOB':'mobile', MOB:'mobile', DCH:'hosting', CDN:'hosting', SES:'hosting', COM:'business', ORG:'business', EDU:'education', LIB:'education', GOV:'government', MIL:'government'})[usage] || null : null;
      data.usageDetail = clean(f['Usage Type']);
      data.country = /\(([A-Z]{2})\)\s*$/.exec(f.Country || '')?.[1] || null;
      data.region = clean(f.Region); data.city = clean(f.City);
      const [lat, lon] = String(f.Coordinates || '').split(',').map(Number);
      if (Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180) { data.lat = lat; data.lon = lon; }
      data.asn = Number(f.ASN) || null; data.org = clean(f.ISP || f.AS);
      const proxy = yes(String(f.Proxy || '').trim().split(/\s+/).at(-1));
      if (proxy !== null) data.flags.proxy = proxy;
      // "(TOR) Tor Exit Nodes". IP2Proxy types: VPN, TOR, DCH, PUB, WEB, SES, RES, CPN (consumer privacy network), EPN (enterprise).
      const kind = (code(f['Proxy Type']) || clean(f['Proxy Type']) || '').toUpperCase();
      const key = kind && ({VPN:'vpn', EPN:'vpn', TOR:'tor', DCH:'hosting', PUB:'proxy', WEB:'proxy', SES:'crawler', RES:'resProxy', CPN:'relay'})[kind];
      if (key) data.flags[key] = true;
      const threat = clean(f.Threat)?.toUpperCase();
      if (threat && /SPAM|SCANNER|BOTNET/.test(threat)) data.flags.abuser = true;
      if (threat && /BOGON/.test(threat)) data.flags.bogon = true;
      const score = Number(f['Fraud Score']);
      if (f['Fraud Score'] && Number.isInteger(score) && score >= 0 && score <= 100) data.risk = score;
      data.proxyProvider = clean(f.Provider);
    }
  } else if (provider === 'greynoise') {
    // The logged-out Visualizer shows scanner observations; business-service (RIOT) data needs an account.
    returned = document.title.split('|')[0].trim() === ip && /\nScope:/.test(body) ? ip : null;
    const after = label => new RegExp('\\n' + label + '\\n(?:>\\n)?([^\\n]+)').exec(body)?.[1].trim() || null;
    const classification = after('Classification')?.toLowerCase();
    const unseen = /\nNOT OBSERVED\n/.test(body);
    if (returned && !unseen && !classification) returned = null;
    if (returned) {
      data.noise = !unseen;
      data.flags.crawler = !unseen;
      data.classification = unseen ? 'unseen' : classification;
      if (classification === 'malicious') data.flags.abuser = true;
      if (classification === 'benign') data.flags.abuser = false;
      if (!unseen) {
        data.name = clean(after('Actor')); data.lastSeen = clean(after('Last Seen'));
        for (const [label, key] of [['VPN','vpn'],['Tor','tor']]) { const value = yes(after(label)); if (value !== null) data.flags[key] = value; }
      }
      data.asn = Number(String(after('ASN') || '').replace(/^AS/i, '')) || null; data.org = clean(after('Organization') || after('AS Name'));
      data.geoVote = false;
    }
  } else {
    // Several official pages render the full lookup JSON in a code/pre element.
    for (const node of document.querySelectorAll('pre, code')) {
      try {
        const raw = JSON.parse(node.innerText);
        if (raw.ip !== ip) continue;
        returned = raw.ip;
        const location = raw.location || {};
        data.country = clean(raw.country_code || location.country_code || raw.country);
        if (!/^[A-Z]{2}$/.test(data.country || '')) delete data.country;
        data.city = clean(raw.city || location.city); data.region = clean(raw.region || location.state);
        data.asn = Number(String(raw.asn?.asn || raw.asn || raw.isp?.asn || '').replace(/^AS/i,'')) || null;
        data.org = clean(raw.company?.name || raw.asn?.name || raw.org || raw.isp?.org);
        data.companyType = type(raw.company?.type);
        data.asnType = clean(raw.asn?.type);
        data.usageType = type(raw.connection?.type || raw.usage_type);
        for (const [name, key] of [['is_vpn','vpn'],['is_proxy','proxy'],['is_tor','tor'],['is_datacenter','hosting'],['is_mobile','mobile'],['is_abuser','abuser'],['is_crawler','crawler'],['is_icloud_relay','relay']]) {
          const value = raw.threat?.[name] ?? raw.risk?.[name] ?? raw[name];
          if (typeof value === 'boolean') data.flags[key] = value;
        }
        const score = raw.risk?.risk_score ?? raw.threat?.scores?.threat_score;
        if (typeof score === 'number' && score >= 0 && score <= 100) data.risk = score;
        if (data.flags.hosting === true) data.usageType = 'hosting';
        else if (data.flags.mobile === true) data.usageType = 'mobile';
        if (provider === 'blackbox') {
          data.classification = clean(raw.classification);
          data.usageType = type(raw.classification);
          if (!data.usageType) data.usageDetail = '类型未知';
          // Do not turn untriggered signals into negative votes for unknown categories.
          if (raw.classification !== 'unknown') for (const key of ['proxy','tor','hosting']) if (typeof raw.signals?.[key] === 'boolean') data.flags[key] = raw.signals[key];
        }
        break;
      } catch { /* Ignore examples and unfinished JSON. */ }
    }
    if (!returned && provider === 'dbip' && hasTarget(document.querySelector('h1'))) {
      returned = ip;
      data.usageType = type(rows['Usage type'] || rows['Usage Type']);
      data.companyType = type(rows['Company type'] || rows['Company Type']);
      data.org = clean(rows.Organization || rows.ISP);
    }
  }
  if (data.flags.resProxy === true) data.flags.proxy = true;
  if (returned !== ip) {
    if (/checking your browser|checking your connection|security verification|verify you are human|confirm you.re human|just a moment|human verification|正在进行安全验证|确认您是真人|请验证您是真人/i.test(body)) throw Error('网页需要浏览器或人机校验');
    if (/rate limit|too many requests|quota|limit reached/i.test(body)) throw Error('网页查询额度或频率受限');
    throw Error('网页未返回与目标 IP 一致的字段');
  }
  for (const key of Object.keys(data)) if (data[key] == null) delete data[key];
  if (!Object.keys(data.flags).length && Object.keys(data).every(key => ['flags','geoVote'].includes(key))) throw Error('网页已打开，未提供可读取的目标字段');
  return { ip: returned, data };
}

/** Target-checked, named database fields from the IPSuper report and its legend. */
export function extractIPSuperReport(ip) {
  const grid = document.querySelector('.attributes-grid');
  const target = new URL(location.href).searchParams.get('ip');
  const shown = [...document.querySelectorAll('input')].some(n=>n.value.trim()===ip) || [...document.querySelectorAll('a[href]')].some(n=>n.textContent.trim()===ip && new URL(n.href,location.href).searchParams.get('ip')===ip);
  if (target!==ip || !shown || !grid?.innerText.includes('公司类型')) throw Error('第三方网页的目标结果尚未返回');
  const running=document.body.innerText.match(/\d+\s*tasks,?\s*(\d+)\s*running/i);
  if(running && Number(running[1])>0)throw Error('第三方检测尚在进行');
  const headers=[...grid.querySelectorAll(':scope > .grid-header')].slice(1).map(n=>n.innerText.trim());
  const rows={};
  for(const label of grid.querySelectorAll(':scope > .grid-label')) {
    const values=[];let cell=label.nextElementSibling;
    while(cell?.classList.contains('grid-cell')){values.push(cell.innerText.trim());cell=cell.nextElementSibling;}
    if(values.length===headers.length)rows[label.innerText.trim()]=values;
  }
  if(!headers.length || !rows['使用类型'] || !rows['公司类型'])throw Error('第三方类型表尚未完整');
  const riskPercent={};
  for(const row of document.querySelectorAll('.risk-scores .info-row')) {
    const name=row.querySelector('.info-label')?.textContent.trim();
    const match=/^风险\s*\(([0-9.]+)%\)$/.exec(row.querySelector('.right-label')?.title || '');
    if(name && match && Number(match[1])<=100)riskPercent[name]=Number(match[1]);
  }
  const riskFlags={};
  const factors=document.querySelector('.factors-grid');
  const names=[...(factors?.querySelectorAll(':scope > .grid-header') || [])].slice(1).map(n=>n.innerText.trim());
  const keys={Server:'hosting',Abuse:'abuser',Proxy:'proxy',Vpn:'vpn',Tor:'tor',Bot:'crawler'};
  for(const label of factors?.querySelectorAll(':scope > .grid-label') || []) {
    const cells=[];let cell=label.nextElementSibling;
    while(cell?.classList.contains('grid-cell')){cells.push(cell);cell=cell.nextElementSibling;}
    if(cells.length!==names.length)continue;
    const flags={};
    cells.forEach((cell,i)=>{
      const key=keys[names[i]],indicator=cell.querySelector('.factor-indicator');
      if(key && indicator && !indicator.classList.contains('null') && !indicator.classList.contains('failed'))flags[key]=indicator.classList.contains('detected');
    });
    if(Object.keys(flags).length)riskFlags[label.innerText.trim()]=flags;
  }
  return {ip,time:Date.now(),headers,rows,riskPercent,riskFlags};
}
