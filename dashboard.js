import { PROVIDERS, queryProvider } from './providers.js?v=1.2';
import { assess } from './assessment.js?v=1.2';
import { visualSummary, visualBreakdown } from './visuals.js?v=1.2';

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
  $('assessment-summary').replaceChildren(visualSummary(state.records,result,{target:state.target,masked:context.masked,observedAt:state.observedAt,total:PROVIDERS.length}));
  const table=node('table','data-matrix');const thead=node('thead');const heading=node('tr');
  ['数据库 / 接口','状态','国家','城市','ASN','网络类型','VPN','Proxy','Tor','Hosting','Abuse','Bogon','请求耗时'].forEach(x=>heading.append(node('th','',x)));thead.append(heading);table.append(thead);
  const tbody=node('tbody');
  for(const record of state.records){
    const tr=node('tr');const source=node('td');source.append(node('strong','',record.providerName));
    const definition=PROVIDERS.find(p=>p.id===record.providerId);
    source.append(node('small','muted',definition?.kind==='aggregate'?'聚合旁证':definition?.kind==='routing'?'BGP 路由证据':record.providerId==='ipquery'?'分类库；地理上游未命名':'数据库原始接口'));
    if(['ip2location','dbip'].includes(record.providerId)){const credit=node('a','source-credit',record.providerId==='ip2location'?'IP Geolocation by IP2Location.io':'IP Geolocation by DB-IP');credit.href=definition.attributionUrl;credit.target='_blank';credit.rel='noopener noreferrer';source.append(credit);}
    tr.append(source);
    const status=node('td');status.append(node('span',`badge ${record.status==='success'?'ok':record.status==='pending'?'neutral':'warn'}`,{success:'已返回',pending:'查询中',cancelled:'已取消',error:'未取得'}[record.status]||'待查询'));
    if(record.error){status.title=record.error;status.append(node('small','muted',record.error));}tr.append(status);
    for(const v of [record.country,record.city,record.asn,typeLabels[record.networkType]])tr.append(node('td','',v || '—'));
    for(const key of ['vpn','proxy','tor','hosting','abuser','bogon']){const cell=flagCell(record.flags?.[key]);if(key==='hosting'&&record.flags?.[key]===true){cell.className='flag-type';cell.textContent='机房';}tr.append(cell);}
    tr.append(node('td','mono',record.status==='pending'?'…':`${record.duration ?? 0} ms${record.cacheHit?' · 缓存':''}`));tbody.append(tr);
  }
  table.append(tbody);$('database-matrix').replaceChildren(table);
  const legend=node('p','matrix-legend','— 表示未提供。阴性“否”来自接口明确的 false；获取失败、聚合旁证和缺失字段分别保留。');$('database-matrix').append(legend);

  $('score-panel').replaceChildren(visualBreakdown(result,PROVIDERS));
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
  document.getElementById('report-dialog')?.remove();
  const json=JSON.stringify(report,null,2);const url=URL.createObjectURL(new Blob([json],{type:'application/json'}));
  const dialog=node('dialog','report-dialog');dialog.id='report-dialog';dialog.setAttribute('aria-labelledby','report-title');
  const header=node('div','result-topline');const title=node('h2','','本轮测评报告');title.id='report-title';const close=node('button','secondary','关闭');close.type='button';close.addEventListener('click',()=>dialog.close());header.append(title,close);dialog.append(header);
  dialog.append(node('p','',`已汇总 ${state.records.filter(r=>r.status==='success').length} 个来源 · 综合分 ${state.result.score??'暂无'} · 指标覆盖 ${state.result.coverage}%`),node('p','small muted',$('mask-ip').checked?'目标 IP 已隐藏。报告包含数据来源、观测时间、字段与计算依据。':'报告包含完整目标 IP、数据来源、观测时间、字段与计算依据。'));
  const a=node('a','report-download','下载 JSON 报告 ↓');a.href=url;a.download=`egress-assessment-${Date.now()}.json`;dialog.append(a);
  const detail=node('details');detail.append(node('summary','','查看报告内容'));detail.append(node('pre','',json));dialog.append(detail);
  dialog.addEventListener('close',()=>{setTimeout(()=>URL.revokeObjectURL(url),1000);dialog.remove();},{once:true});
  document.body.append(dialog);dialog.showModal();
  $('assessment-status').textContent=$('mask-ip').checked?'报告已生成，目标 IP 已隐藏。':'报告已生成，包含完整目标 IP。';
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
