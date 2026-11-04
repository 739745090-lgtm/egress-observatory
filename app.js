import { SOURCES, EXPERIENCES } from './data.js';
import { initAssessment, runAssessment, renderAssessment, cancelAssessment, getAssessmentReport } from './dashboard.js';

const $ = (id) => document.getElementById(id);
const state = { endpoints: [], claude: [], lookup: [], lookupTarget: '', rtc: null, busy: false, controllers: new Set(), filter: 'all', observedAt: null };
const pages = {
  overview: ['综合测评', '一次查询，融合多库数据，生成可追溯的质量判断。'],
  lookup: ['IP 数据对照', '保留来源、时间与分歧，让每个结论都有出处。'],
  score: ['评分依据', '从原始字段到来源贡献，解释每一步计算。'],
  claude: ['Claude 观测', '分别观察网络响应、出口信息与官方服务状态。'],
  sources: ['来源目录', '从实际使用经验出发，明确每个数据源的能力。'],
  notes: ['经验与方法', '把配置中遇到的问题，变成可解释的观测方法。'],
};
function el(tag, className, text) { const n = document.createElement(tag); if (className) n.className = className; if (text !== undefined) n.textContent = text; return n; }
function masked(ip) { if (!ip) return '—'; if (!$('mask-ip').checked) return ip; return ip.includes(':') ? `${ip.split(':').slice(0, 2).join(':')}:••••` : `${ip.split('.').slice(0, 2).join('.')}.•••.•••`; }
function normalizeIP(input) {
  const value = input.trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
    const p = value.split('.'); if (p.some(x => Number(x) > 255 || (x.length > 1 && x[0] === '0'))) return null;
    const [a,b] = p.map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) return null;
    return p.map(Number).join('.');
  }
  if (!/^[a-f\d:]+$/i.test(value) || !value.includes(':')) return null;
  try {
    const ip = new URL(`https://[${value}]/`).hostname.slice(1,-1);
    if (ip === '::' || ip === '::1' || /^(fc|fd|fe[89ab]|ff)/i.test(ip) || /^::ffff:/i.test(ip)) return null;
    return ip;
  } catch { return null; }
}
function canonical(ip) { return normalizeIP(String(ip || '')) || String(ip || '').toLowerCase(); }
function timeString(time) { return new Date(time).toLocaleString('zh-CN', { hour12:false }); }
function route() {
  if(location.hash === '#main') return;
  const key = location.hash.slice(1) in pages ? location.hash.slice(1) : 'overview';
  document.querySelectorAll('.view').forEach(n => { n.hidden = n.id !== key; });
  document.querySelectorAll('nav a[href^="#"]').forEach(n => { const active = n.hash === `#${key}`; n.classList.toggle('active', active); if(active) n.setAttribute('aria-current','page'); else n.removeAttribute('aria-current'); });
  $('page-title').textContent = pages[key][0]; $('page-subtitle').textContent = pages[key][1];
  document.title = `${pages[key][0]} · EGRESS 出口观测站`;
  requestAnimationFrame(()=>window.scrollTo({top:0,left:0,behavior:'instant'}));
}
window.addEventListener('hashchange', route);

async function request(url, { format='json', mode='cors', timeout=11000 } = {}) {
  const controller = new AbortController(); state.controllers.add(controller);
  let timedOut = false; const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeout);
  const started = performance.now();
  try {
    const response = await fetch(url, { signal:controller.signal, credentials:'omit', cache:'no-store', referrerPolicy:'no-referrer', mode });
    const duration = Math.round(performance.now() - started);
    if (response.type === 'opaque') return { data:null, duration, opaque:true, observedAt:new Date().toISOString() };
    if (!response.ok) throw new Error(response.status === 429 ? '来源限流或额度耗尽（HTTP 429）' : `来源返回 HTTP ${response.status}`);
    const data = format === 'text' ? await response.text() : await response.json();
    return { data, duration, observedAt:new Date().toISOString() };
  } catch (error) {
    if (controller.signal.aborted) throw new Error(timedOut ? '请求超时，本次未取得结果' : '本次观测已取消');
    if (error instanceof TypeError) throw new Error('浏览器未能读取响应：可能涉及 CORS、网络或扩展拦截');
    throw error;
  } finally { clearTimeout(timer); state.controllers.delete(controller); }
}
function parseTrace(text) { return Object.fromEntries(text.trim().split('\n').filter(x => x.includes('=')).map(x => { const i=x.indexOf('='); return [x.slice(0,i), x.slice(i+1)]; })); }
function busy(value) {
  state.busy=value;
  ['run-all','run-claude','lookup-submit','run-webrtc','start-assessment'].forEach(id => { $(id).disabled=value; });
  $('cancel-run').disabled=!value;
  $('cancel-assessment').disabled=!value;
}
function fieldsCard(result) {
  const card = el('article','result-card card');
  const head = el('div','result-head'); head.append(el('h3','',result.name));
  const status = result.idle ? ['neutral','待观测'] : result.pending ? ['neutral','观测中'] : result.error ? ['warn','未取得结果'] : ['ok',result.opaque ? '响应不可读' : '已取得数据'];
  if (result.opaque) status[0]='warn';
  if (result.unknown) {status[0]='warn';status[1]='未观测到公网候选';}
  head.append(el('span',`badge ${status[0]}`,status[1])); card.append(head);
  if (result.subtitle) card.append(el('p','muted small', result.subtitle));
  if(result.idle) { card.append(el('p','muted','点击开始后记录本次响应。')); return card; }
  if(result.pending) { card.append(el('p','muted','等待浏览器响应…')); return card; }
  if(result.error) { card.append(el('p','small',result.error)); return card; }
  const dl=el('dl','details');
  for (const [key,value,sensitive] of result.fields || []) {
    const row=el('div','detail-row'); row.append(el('dt','',key),el('dd',sensitive ? 'mono' : '',sensitive ? masked(String(value || '')) : String(value ?? '未提供'))); dl.append(row);
  }
  card.append(dl);
  if(result.note) card.append(el('p','muted small',result.note));
  if(result.observedAt) card.append(el('p','source-meta',`${timeString(result.observedAt)} · 请求 ${result.duration} ms`));
  return card;
}
function renderEndpoints() {
  $('endpoint-grid').replaceChildren(...state.endpoints.map(fieldsCard));
  const good=state.endpoints.filter(x=>x.ip && !x.error);
  const main=good.find(x=>x.id==='ipv4') || good.find(x=>!x.ip.includes(':'));
  $('summary-ip').textContent=main ? masked(main.ip) : '等待观测';
  $('summary-sources').textContent=`${good.length} / ${state.endpoints.length || 5}`;
  const ipv4=new Set(good.map(x=>x.ip).filter(x=>!x.includes(':')));
  const ipv6=new Set(good.map(x=>canonical(x.ip)).filter(x=>x.includes(':')));
  $('summary-route').textContent=ipv4.size>1 || ipv6.size>1 ? '存在出口差异' : good.length>=2 ? '样本未见差异' : '样本不足';
  $('route-note').textContent=ipv4.size>1 || ipv6.size>1
    ? '同一地址族出现不同出口，可能存在按域名分流或动态出口。请结合代理客户端的实际连接记录判断。'
    : '分别比较 IPv4 与 IPv6；两种地址族同时出现属于正常双栈现象。样本相同仅描述这些请求，浏览器无法确认整机路由或强制 DIRECT。';
  if(state.observedAt) $('observed-at').textContent=timeString(state.observedAt);
}
const endpointDefs = [
  {id:'ipv4',name:'IPv4 出口',subtitle:'ipify · IPv4 专用',url:'https://api.ipify.org?format=json',kind:'ip'},
  {id:'ipv6',name:'IPv6 出口',subtitle:'ipify · IPv6 专用',url:'https://api6.ipify.org?format=json',kind:'ip'},
  {id:'dual',name:'双栈访问',subtitle:'ipify · 浏览器选择的地址族',url:'https://api64.ipify.org?format=json',kind:'ip'},
  {id:'cloudflare',name:'Cloudflare 路径',subtitle:'Cloudflare · 本次 HTTP 请求',url:'https://www.cloudflare.com/cdn-cgi/trace',kind:'trace'},
  {id:'ippure',name:'IPPure 观测',subtitle:'IPPure · 公开 Beta 接口',url:'https://my.ippure.com/v1/info',kind:'pure'},
];
async function runEndpoints() {
  if(state.busy) return; busy(true); state.observedAt=new Date().toISOString();
  state.endpoints=endpointDefs.map(x=>({...x,pending:true})); renderEndpoints(); $('run-status').textContent='正在从当前浏览器请求 5 个观测端点…';
  try {
    await Promise.all(endpointDefs.map(async(def,index)=>{
      try {
        const response=await request(def.url,{format:def.kind==='trace'?'text':'json'});
        const data=def.kind==='trace'?parseTrace(response.data):response.data;
        const ip=data.ip;
        if(!normalizeIP(String(ip || ''))) throw new Error('来源未返回有效公网 IP');
        const fields=[['所见出口',ip,true]];
        if(def.kind==='trace') fields.push(['地区代码',data.loc],['CDN 接入点',data.colo],['TLS / HTTP',`${data.tls || '—'} / ${data.http || '—'}`]);
        if(def.kind==='pure') {
          fields.push(['国家 / 城市',`${data.countryCode || data.country || '未提供'} / ${data.city || '未提供'}`],['ASN',data.asn ? `AS${String(data.asn).replace(/^AS/,'')}` : '未提供'],['风险系数',typeof data.fraudScore==='number'?`${data.fraudScore} / 100（越低越好）`:'未提供'],['住宅标签',typeof data.isResidential==='boolean'?(data.isResidential?'是':'否'):'未提供']);
        }
        state.endpoints[index]={...def,...response,ip,fields,pending:false,data:undefined,note:def.kind==='trace'?'接入点表示 CDN 处理请求的位置。':def.kind==='pure'?'这是 IPPure 的站方判断，底层来源未公开的字段单独保留。':'耗时包含 DNS、TLS、浏览器和服务器处理时间。'};
      } catch(error) { state.endpoints[index]={...def,error:error.message,pending:false}; }
      renderEndpoints();
    }));
    $('run-status').textContent=`本轮结束，${state.endpoints.filter(x=>!x.error).length} / 5 个端点返回数据。`;
  } finally { busy(false); }
}

function renderLookup() {}
async function lookup(event) {
  event.preventDefault();
  $('assessment-ip').value=$('ip-input').value;
  location.hash='overview';
  await runAssessment();
}
function renderClaude() { $('claude-results').replaceChildren(...state.claude.map(fieldsCard)); }
async function runClaude() {
  if(state.busy)return;busy(true);$('claude-note').textContent='正在观察官方状态、Claude 路径与 API 域名的响应…';
  const defs=[{id:'status',name:'官方服务状态',url:'https://status.claude.com/api/v2/summary.json'},
    {id:'trace',name:'Claude 网页路径',url:'https://claude.ai/cdn-cgi/trace'},
    {id:'api',name:'Anthropic API 域名',url:'https://api.anthropic.com/'}];
  state.claude=defs.map(x=>({...x,pending:true}));renderClaude();
  try {
    await Promise.all(defs.map(async(def,index)=>{
      try {
        const r=await request(def.url,{format:def.id==='trace'?'text':'json',mode:def.id==='api'?'no-cors':'cors'});
        let fields=[],note='';
        if(def.id==='status') {
          if(!r.data?.status)throw new Error('官方状态响应结构不可读');
          fields=[['公告状态',r.data.status.description],['未解决事件',String((r.data.incidents||[]).length)],['公告更新时间',r.data.page?.updated_at ? timeString(r.data.page.updated_at):'未提供']];
          note='这是服务方公告。当前账号能否登录和对话需要在 Claude 中实际确认。';
          $('summary-claude').textContent=r.data.status.indicator==='none'?'官方公告正常':'官方报告事件';
        } else if(def.id==='trace') {
          const d=parseTrace(r.data);if(!normalizeIP(d.ip || ''))throw new Error('目标未返回可识别的 trace；网页可用性尚未确认');
          fields=[['目标所见出口',d.ip,true],['国家 / CDN',`${d.loc || '—'} / ${d.colo || '—'}`],['TLS',d.tls || '未提供']];
          note='仅代表此浏览器访问 Claude trace 的路径；Desktop 和 Code 需要各自观察连接记录。';
        } else {fields=[['响应类型','Opaque（状态码与正文不可读）'],['登录 / 模型调用','未进行']];note='收到不透明响应可能包含错误页或拦截页，无法据此判断 API 授权、地区支持或对话能力。';}
        state.claude[index]={...def,...r,data:undefined,fields,note,pending:false};
      } catch(error) {state.claude[index]={...def,error:error.message,pending:false};if(def.id==='status')$('summary-claude').textContent='状态暂不可读';}
      renderClaude();
    }));
    $('claude-note').textContent='本轮观测结束。网络响应、官方公告、人工验证与账号权限分别判断；本站未提交登录信息或模型请求。';
  } finally {busy(false);}
}

function browserFacts() {
  const tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
  const facts=[['浏览器语言',navigator.languages.join(', ')],['系统时区',tz],['当前时间',new Date().toLocaleString('zh-CN')],['运行方式',window.isSecureContext?'安全上下文 HTTPS / localhost':'非安全上下文']];
  const dl=el('dl','details');for(const [key,value]of facts){const row=el('div','detail-row');row.append(el('dt','',key),el('dd','',value));dl.append(row);} $('browser-facts').replaceChildren(dl);
}
function renderRTC() {
  if(!state.rtc)return;
  const card=fieldsCard({name:'WebRTC / ICE',...state.rtc});$('webrtc-result').replaceChildren(card);
}
async function runRTC() {
  if(state.busy)return;busy(true);$('webrtc-result').textContent='正在收集 ICE 候选；请求将发送至 Google STUN，不访问摄像头或麦克风。';
  const started=performance.now();let pc;let cancelled=false;
  try {
    if(!window.RTCPeerConnection)throw new Error('当前浏览器不支持 RTCPeerConnection');
    pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});pc.createDataChannel('egress');
    const candidates=[];
    await new Promise(async(resolve,reject)=>{
      const timer=setTimeout(resolve,7000);
      state.cancelRTC=()=>{cancelled=true;clearTimeout(timer);pc.close();resolve();};
      pc.onicecandidate=event=>{
        if(!event.candidate){clearTimeout(timer);resolve();return;}
        const c=event.candidate;
        if(c.address)candidates.push({address:c.address,type:c.type || 'unknown',protocol:c.protocol || 'unknown'});
      };
      try {await pc.setLocalDescription(await pc.createOffer());}catch(error){clearTimeout(timer);reject(error);}
    });
    if(cancelled)throw new Error('本次 WebRTC 观测已取消，ICE 连接已关闭');
    const unique=[...new Map(candidates.map(x=>[`${x.address}/${x.type}`,x])).values()];
    const publicOnes=unique.filter(x=>normalizeIP(x.address));
    const httpIPs=new Set(state.endpoints.filter(x=>x.ip).map(x=>canonical(x.ip)));
    const differs=publicOnes.some(x=>{const peers=[...httpIPs].filter(ip=>ip.includes(':')===x.address.includes(':'));return peers.length && !peers.includes(canonical(x.address));});
    state.rtc={observedAt:new Date().toISOString(),duration:Math.round(performance.now()-started),fields:unique.length?unique.map(x=>[`${x.type} / ${x.protocol}`,x.address,true]):[['观测结果','本次未取得 ICE 候选']],note:differs?'公网候选与已观测的同地址族 HTTP 出口不同；需要结合 UDP 路由核实。':publicOnes.length?'已取得公网候选。结果只描述本次 ICE 连接，无法覆盖所有应用。':'本次未观测到公网候选；可能受 mDNS、浏览器策略、防火墙或 UDP 路由影响，不能判定不存在泄漏。'};
    state.rtc.unknown=publicOnes.length===0;
  }catch(error){state.rtc={error:error.message};}finally{state.cancelRTC=null;pc?.close();busy(false);renderRTC();}
}

function renderSources() {
  const search=$('source-search').value.trim().toLowerCase();
  const list=SOURCES.filter(s=>(state.filter==='all'||s.category===state.filter)&&[s.name,s.description,...s.tags,s.evidence].join(' ').toLowerCase().includes(search));
  $('source-count').textContent=`${list.length} 个来源`;
  $('source-grid').replaceChildren(...list.map(s=>{
    const card=el('article','source-card card');const head=el('div','result-head');head.append(el('h3','',s.name),el('span','badge neutral',{history:'历史使用',api:'公开接口',database:'底层数据',diagnostic:'诊断参考'}[s.category]||s.category));
    const tags=el('div','source-tags');s.tags.forEach(t=>tags.append(el('span','tag',t)));
    card.append(head,tags,el('p','',s.description),el('p','source-meta',s.access),el('p','muted small',s.evidence));
    const link=el('a','source-link','访问来源 ↗');link.href=s.url;link.target='_blank';link.rel='noopener noreferrer';card.append(link);return card;
  }));
  if(!list.length)$('source-grid').append(el('p','empty','没有符合条件的来源。'));
}
function renderNotes(){ $('experience-list').replaceChildren(...EXPERIENCES.map((item,index)=>{const card=el('article','note-card card');card.append(el('span','eyebrow',String(index+1).padStart(2,'0')),el('h3','',item.title),el('p','',item.body));if(item.sourceUrl){const a=el('a','source-link','相关来源 ↗');a.href=item.sourceUrl;a.target='_blank';a.rel='noopener noreferrer';card.append(a);}return card;}));}
function exportReport() {
  const redact=(record)=>({...record,url:record.url?.replace(/(resource=|\/ip\/)[^&/]+/g,'$1[redacted]'),ip:record.ip?masked(record.ip):undefined,fields:record.fields?.map(([k,v,s])=>[k,s?masked(String(v||'')):v]),data:undefined});
  const lookupReport=state.lookup.map(record=>({...redact(record),url:undefined}));
  const report={schema:'egress-observatory/v1',exportedAt:new Date().toISOString(),ipMasked:$('mask-ip').checked,scope:'本次浏览器观测；不证明整机路由、账号可用性或安全概率',observedAt:state.observedAt,endpoints:state.endpoints.map(redact),lookupTarget:state.lookupTarget?masked(state.lookupTarget):null,lookup:lookupReport,claude:state.claude.map(redact),webrtc:state.rtc?redact(state.rtc):null,assessment:getAssessmentReport({mask:$('mask-ip').checked})};
  const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`egress-report-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);$('run-status').textContent=$('mask-ip').checked?'已导出隐藏 IP 的报告。':'已导出包含完整 IP 的报告。';
}

$('run-all').addEventListener('click',runEndpoints);
$('cancel-run').addEventListener('click',()=>{state.controllers.forEach(c=>c.abort());state.cancelRTC?.();cancelAssessment();$('run-status').textContent='已取消尚未完成的请求。';});
$('run-claude').addEventListener('click',runClaude);
$('run-webrtc').addEventListener('click',runRTC);
$('lookup-form').addEventListener('submit',lookup);
$('mask-ip').addEventListener('change',()=>{renderEndpoints();renderLookup();renderClaude();renderRTC();renderAssessment();});
$('export-report').addEventListener('click',exportReport);
$('source-search').addEventListener('input',renderSources);
document.querySelectorAll('[data-filter]').forEach(button=>button.addEventListener('click',()=>{state.filter=button.dataset.filter;document.querySelectorAll('[data-filter]').forEach(b=>{b.classList.toggle('active',b===button);b.setAttribute('aria-pressed',String(b===button));});renderSources();}));
initAssessment({request,setBusy:busy,isBusy:()=>state.busy,normalizeIP,masked,cancelRequests:()=>state.controllers.forEach(c=>c.abort())});
state.endpoints=endpointDefs.map(d=>({...d,idle:true}));
renderEndpoints();renderSources();renderNotes();browserFacts();route();

