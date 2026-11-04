import { PROVIDERS, queryProvider } from './providers.js';
import { assess } from './assessment.js';

const $=id=>document.getElementById(id);
const state={records:[],target:null,expected:'',result:null,controller:null,observedAt:null,weights:Object.fromEntries(PROVIDERS.map(p=>[p.id,p.weight]))};
let context;
const typeLabels={residential:'住宅',isp:'ISP',mobile:'移动',business:'企业',hosting:'数据中心'};
function node(tag,css,text){const n=document.createElement(tag);if(css)n.className=css;if(text!==undefined)n.textContent=text;return n;}
function flagCell(value){return node('td',value===true?'flag-yes':value===false?'flag-no':'flag-unknown',value===true?'命中':value===false?'否':'—');}
function formatTime(value){return value?new Date(value).toLocaleString('zh-CN',{hour12:false}):'—';}
function valueText(value){return value===true?'命中':value===false?'否':value===null||value===undefined?'缺失':String(value);}

export function renderAssessment(){
  if(!context || !state.records.length)return;
  state.result=assess(state.records,{weights:state.weights,expectedCountry:state.expected});
  const result=state.result;
  const score=node('article','assessment-score card');
  score.append(node('p','eyebrow','WEIGHTED DATABASE EVIDENCE'),node('h3','','综合参考分 · 含类型适配'),node('div','score-number',result.score===null?'—':String(result.score)));
  score.append(node('span',`badge ${result.provisional?'warn':'ok'}`,result.score===null?'数据不足，暂不评分':result.provisional?'暂定参考 · 保留缺失项':'本轮综合结果'));
  score.append(node('p','',`指标覆盖率 ${result.coverage}%`));
  const meter=node('progress');meter.max=100;meter.value=result.coverage;meter.setAttribute('aria-label',`指标覆盖率 ${result.coverage}%`);score.append(meter);
  score.append(node('p','small muted',`目标 ${context.masked(state.target)} · 已取得 ${state.records.filter(r=>r.status==='success').length} / ${PROVIDERS.length} 个来源`),node('p','small muted','分数由本轮数据库字段自动计算；覆盖率描述已取得的指标，分数不代表 Claude 可用概率。'));
  const findings=node('article','assessment-findings card');findings.append(node('p','eyebrow','THIS OBSERVATION'),node('h3','','主要发现'));
  const rows=[['国家加权共识',result.consensus.country || '暂无共识'],['国家支持权重',result.consensus.countrySupport===null?'—':`${result.consensus.countrySupport}%`],['ASN 共识',result.consensus.asn || '暂无共识'],['网络类型',typeLabels[result.consensus.networkType] || '未提供'],['可归属的风险来源',`${result.consensus.riskSourceCount} 个`],['观测时间',formatTime(state.observedAt)]];
  const dl=node('dl','details');for(const[k,v]of rows){const row=node('div','detail-row');row.append(node('dt','',k),node('dd','',v));dl.append(row);}findings.append(dl);
  const knownFlags=[...new Set(state.records.filter(r=>r.status==='success').flatMap(r=>Object.entries(r.flags || {}).filter(([,v])=>v===true).map(([k])=>k)))];
  if(knownFlags.some(f=>['tor','abuser','bogon'].includes(f))){score.classList.add('risk-alert');score.prepend(node('p','callout warn','存在重要风险标签，综合分不能抵消该项证据。'));}
  const riskFlags=knownFlags.filter(f=>f!=='hosting');
  findings.append(node('p',riskFlags.length?'callout warn':'callout',riskFlags.length?`匿名或滥用相关标签：${riskFlags.join(' / ')}。各库定义可能不同，见下方逐项结果。`:'已取得的匿名或滥用字段未出现阳性标签；未返回的字段仍为未知。'));
  if(knownFlags.includes('hosting'))findings.append(node('p','small muted','数据中心标签计入网络类型适配，与匿名或滥用记录分别展示。'));
  if(result.conflicts.length)findings.append(node('p','callout warn',`存在 ${result.conflicts.length} 项字段分歧：${[...new Set(result.conflicts.map(x=>x.field))].join('、')}。`));
  $('assessment-summary').replaceChildren(score,findings);

  const table=node('table','data-matrix');const thead=node('thead');const heading=node('tr');
  ['数据库 / 接口','状态','国家','城市','ASN','网络类型','VPN','Proxy','Tor','Hosting','Abuse','Bogon','请求耗时'].forEach(x=>heading.append(node('th','',x)));thead.append(heading);table.append(thead);
  const tbody=node('tbody');
  for(const record of state.records){
    const tr=node('tr');const source=node('td');source.append(node('strong','',record.providerName));
    const definition=PROVIDERS.find(p=>p.id===record.providerId);
    source.append(node('small','muted',definition?.kind==='aggregate'?'聚合旁证':definition?.kind==='routing'?'BGP 路由证据':record.providerId==='ipquery'?'分类库；地理上游未命名':'数据库原始接口'));
    tr.append(source);
    const status=node('td');status.append(node('span',`badge ${record.status==='success'?'ok':record.status==='pending'?'neutral':'warn'}`,{success:'已返回',pending:'查询中',cancelled:'已取消',error:'未取得'}[record.status]||'待查询'));
    if(record.error){status.title=record.error;status.append(node('small','muted',record.error));}tr.append(status);
    for(const v of [record.country,record.city,record.asn,typeLabels[record.networkType]])tr.append(node('td','',v || '—'));
    for(const key of ['vpn','proxy','tor','hosting','abuser','bogon']){const cell=flagCell(record.flags?.[key]);if(key==='hosting'&&record.flags?.[key]===true){cell.className='flag-type';cell.textContent='机房';}tr.append(cell);}
    tr.append(node('td','mono',record.status==='pending'?'…':`${record.duration ?? 0} ms${record.cacheHit?' · 缓存':''}`));tbody.append(tr);
  }
  table.append(tbody);$('database-matrix').replaceChildren(table);
  const legend=node('p','matrix-legend','— 表示未提供。阴性“否”来自接口明确的 false；获取失败、聚合旁证和缺失字段分别保留。');$('database-matrix').append(legend);

  const breakdown=node('div','assessment-breakdown');
  const dims=node('div','result-grid');
  for(const dim of result.dimensions){const card=node('article','card');card.append(node('p','eyebrow',`维度权重 ${dim.weight}%`),node('h3','',dim.label),node('div','score-number',dim.score===null?'—':String(dim.score)),node('p','small muted',`维度覆盖率 ${dim.coverage}% · ${dim.sourceCount} 个可归属来源`));
    const detail=node('details');detail.append(node('summary','','字段与来源贡献'));
    for(const field of dim.fields){const row=node('div','contribution-list');row.append(node('strong','',`${field.label}：${field.score===null?'缺失':field.score+' / 100'}`));for(const src of field.sources)row.append(node('p','small muted',`${src.providerName} / ${src.database}：${valueText(src.value)} · 权重 ${src.weight}`));detail.append(row);}card.append(detail);dims.append(card);}
  breakdown.append(dims);
  const methodology=node('article','card score-explanation');methodology.append(node('h3','','融合与去重规则'));result.explanations.forEach(text=>methodology.append(node('p','',text)));breakdown.append(methodology);
  const attribution=node('article','card score-explanation');attribution.append(node('h3','','本轮数据归属与接口边界'));
  for(const provider of PROVIDERS){const p=node('p');const a=node('a','source-link',provider.name);a.href=provider.attributionUrl;a.rel='noopener noreferrer';a.target='_blank';p.append(a,document.createTextNode(` · ${provider.attribution} ${provider.description}`));attribution.append(p);}breakdown.append(attribution);
  $('score-panel').replaceChildren(breakdown);
}

export async function runAssessment(){
  if(context.isBusy())return;
  let target=$('assessment-ip').value.trim();const expected=$('expected-country').value.trim().toUpperCase();
  if(target&&!context.normalizeIP(target)){$('assessment-status').textContent='请输入有效公网 IPv4 或 IPv6 地址。';return;}
  if(expected&&!/^[A-Z]{2}$/.test(expected)){$('assessment-status').textContent='期望国家使用两位代码，如 JP；留空按多库共识评估。';return;}
  context.setBusy(true);state.controller=new AbortController();state.observedAt=new Date().toISOString();state.expected=expected;
  state.records=[];state.result=null;state.target=null;
  $('assessment-summary').replaceChildren(node('p','empty','正在识别测评目标并请求数据库…'));$('database-matrix').replaceChildren();
  $('score-panel').replaceChildren(node('p','empty','本轮查询进行中，等待数据库字段。'));
  $('assessment-status').textContent=target?'正在向数据库发起同一目标的并行查询…':'正在获取当前浏览器出口…';
  try{
    if(!target){const r=await context.request('https://api64.ipify.org?format=json');target=r.data.ip;}
    if(state.controller.signal.aborted)throw new Error('本轮已取消。');
    target=context.normalizeIP(target);if(!target)throw new Error('当前出口未返回有效公网 IP。');state.target=target;
    state.records=PROVIDERS.map(p=>({providerId:p.id,providerName:p.name,database:p.database,status:'pending',ip:target,flags:{},country:null,city:null,asn:null,networkType:null}));renderAssessment();
    await Promise.all(PROVIDERS.map(async(provider,index)=>{
      const record=await queryProvider(provider.id,target,{signal:state.controller.signal});state.records[index]=record;renderAssessment();
      const complete=state.records.filter(r=>r.status!=='pending').length;
      $('assessment-status').textContent=`正在测评 ${context.masked(target)} · 已完成 ${complete} / ${PROVIDERS.length} 个数据源`;
    }));
    $('assessment-status').textContent=`${state.controller.signal.aborted?'本轮已取消':'综合测评完成'} · ${state.records.filter(r=>r.status==='success').length} / ${PROVIDERS.length} 个来源返回数据 · ${formatTime(state.observedAt)}`;
  }catch(error){$('assessment-status').textContent=error.message;}
  finally{context.setBusy(false);state.controller=null;}
}
export function cancelAssessment(){state.controller?.abort();}

export function getAssessmentReport({mask=true}={}){
  if(!state.result)return null;
  const scrub=value=>{
    if(Array.isArray(value))return value.map(scrub);
    if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).filter(([key])=>!['raw','record','prefix','upstreams'].includes(key)).map(([key,v])=>[key,key==='ip'&&v&&mask?'[IP hidden]':scrub(v)]));
    if(typeof value==='string'&&mask&&state.target)return value.split(state.target).join('[IP hidden]');
    return value;
  };
  return scrub({target:mask?'[IP hidden]':state.target,observedAt:state.observedAt,expectedCountry:state.expected,weights:state.weights,records:state.records,result:state.result});
}
function exportAssessment(){
  if(!state.result){$('assessment-status').textContent='请先完成一次综合测评。';return;}
  const report={schema:'egress-assessment/v2',exportedAt:new Date().toISOString(),...getAssessmentReport({mask:$('mask-ip').checked})};
  const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=node('a');a.href=url;a.download=`egress-assessment-${Date.now()}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  $('assessment-status').textContent=$('mask-ip').checked?'综合测评报告已导出，目标 IP 已隐藏。':'综合测评报告已导出，包含完整目标 IP。';
}
export function initAssessment(options){
  context=options;
  $('assessment-form').addEventListener('submit',event=>{event.preventDefault();runAssessment();});
  $('cancel-assessment').addEventListener('click',()=>{cancelAssessment();context.cancelRequests();});
  $('export-assessment').addEventListener('click',exportAssessment);
  const grid=node('div','score-weights');
  for(const provider of PROVIDERS){const label=node('label','weight-control',provider.name);const input=node('input');input.type='number';input.min=0;input.max=100;input.step=1;input.value=provider.weight;input.setAttribute('aria-label',`${provider.name} 数据库权重`);input.disabled=['routing','aggregate'].includes(provider.kind);
    input.addEventListener('input',()=>{if(input.value!==''&&input.validity.valid){state.weights[provider.id]=Number(input.value);renderAssessment();}});label.append(input,node('small','muted',input.disabled?'保留旁证，不计质量分':provider.id==='ipinfo'?'对实际返回字段略增权重':'同字段归属去重后融合'));grid.append(label);}
  $('weight-controls').replaceChildren(grid,node('p','small muted','风险 70%、网络类型 20%、地区一致性 10%。数据库权重只作用于实际返回字段；IPinfo 缺失的风险字段不参与风险得分。'));
}
