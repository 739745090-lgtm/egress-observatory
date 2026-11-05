/** Read target-specific, rendered fields only. Shared by Chromium and the import bookmark. */
export function extractProviderPage(provider, ip) {
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
  let returned;
  if (provider === 'iphub') {
    const field = name => document.querySelector('[data-copy-field="' + name + '"]')?.textContent.trim();
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
      data.geoVote = false;
    }
  } else if (provider === 'ipqs') {
    returned = document.querySelector('h1')?.innerText.includes(ip) ? ip : null;
    if (returned) {
      for (const [label, key] of [['VPN','vpn'],['PROXY','proxy'],['TOR','tor']]) { const v = yes(rows[label]); if (v !== null) data.flags[key] = v; }
      const score = body.match(/(?:scoring|Fraud Score\s*:?)[\s]*(\d{1,3})(?:\s*out of 100)?/i);
      if (score && Number(score[1]) <= 100) data.risk = Number(score[1]);
      data.city = clean(rows.City); data.region = clean(rows.Region);
      data.connectionType = clean(rows['Connection Type']);
      data.usageType = type(data.connectionType);
      data.geoVote = false;
    }
  } else if (provider === 'scamalytics') {
    returned = document.querySelector('h1')?.innerText.includes(ip) ? ip : null;
    if (returned) {
      const score = body.match(/Fraud Score:\s*(\d{1,3})/i);
      if (score && Number(score[1]) <= 100) data.risk = Number(score[1]);
      for (const [label, key] of [['Anonymizing VPN','vpn'],['Tor Exit Node','tor'],['Datacenter','hosting'],['Search Engine Robot','crawler'],['Residential Proxy','resProxy']]) { const v = yes(rows[label]); if (v !== null) data.flags[key] = v; }
      const proxy = ['Public Proxy','Web Proxy'].map(key => yes(rows[key]));
      if (proxy.includes(true)) data.flags.proxy = true;
      else if (proxy.every(v => v === false)) data.flags.proxy = false;
      data.connectionType = clean(rows['Connection type']); data.usageType = type(data.connectionType);
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
        for (const [name, key] of [['is_vpn','vpn'],['is_proxy','proxy'],['is_tor','tor'],['is_datacenter','hosting'],['is_mobile','mobile'],['is_abuser','abuser']]) {
          const value = raw.threat?.[name] ?? raw.risk?.[name] ?? raw[name];
          if (typeof value === 'boolean') data.flags[key] = value;
        }
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
    if (!returned && provider === 'dbip' && document.querySelector('h1')?.innerText.includes(ip)) {
      returned = ip;
      data.usageType = type(rows['Usage type'] || rows['Usage Type']);
      data.companyType = type(rows['Company type'] || rows['Company Type']);
      data.org = clean(rows.Organization || rows.ISP);
    }
  }
  if (returned !== ip) {
    if (/checking your browser|checking your connection|security verification|verify you are human|just a moment|human verification/i.test(body)) throw Error('网页需要浏览器或人机校验');
    if (/rate limit|too many requests|quota|limit reached/i.test(body)) throw Error('网页查询额度或频率受限');
    throw Error('网页未返回与目标 IP 一致的字段');
  }
  for (const key of Object.keys(data)) if (data[key] == null) delete data[key];
  if (!Object.keys(data.flags).length && Object.keys(data).every(key => ['flags','geoVote'].includes(key))) throw Error('网页已打开，未提供可读取的目标字段');
  return { ip: returned, data };
}
