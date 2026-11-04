const NS='http://www.w3.org/2000/svg';
function h(tag,css,text){const e=document.createElement(tag);if(css)e.className=css;if(text!==undefined)e.textContent=text;return e;}
function svgNode(tag,attrs={}){const e=document.createElementNS(NS,tag);for(const[k,v]of Object.entries(attrs))e.setAttribute(k,String(v));return e;}
function flagVotes(result,id){return result.dimensions.flatMap(d=>d.fields).find(f=>f.id===id)?.sources || [];}
function countryName(code){if(!code)return '尚未确认';try{return new Intl.DisplayNames(['zh-CN'],{type:'region'}).of(code);}catch{return code;}}
const labels={residential:'住宅网络',isp:'运营商网络',mobile:'移动网络',business:'企业网络',hosting:'数据中心'};

function ring(score){
  const wrap=h('div','score-orbit');const svg=svgNode('svg',{viewBox:'0 0 220 220','aria-hidden':'true'});
  const circumference=2*Math.PI*86;
  svg.append(svgNode('circle',{cx:110,cy:110,r:100,fill:'none',stroke:'currentColor','stroke-opacity':'.05','stroke-width':1}));
  svg.append(svgNode('circle',{cx:110,cy:110,r:86,fill:'none',stroke:'#e8edf5','stroke-width':14}));
  if(score!==null)svg.append(svgNode('circle',{cx:110,cy:110,r:86,fill:'none',stroke:score>=80?'#486bff':score>=50?'#e1a133':'#e15a66','stroke-width':14,'stroke-linecap':'round','stroke-dasharray':`${circumference*score/100} ${circumference}`,transform:'rotate(-90 110 110)'}));
  const center=h('div','score-center');center.append(h('strong','',score===null?'—':String(score)),h('span','','综合参考分'));
  wrap.append(svg,center);return wrap;
}
function globe(code){
  const wrap=h('div','geo-orb');const svg=svgNode('svg',{viewBox:'0 0 160 160','aria-hidden':'true'});
  svg.append(svgNode('circle',{cx:80,cy:80,r:65,fill:'#eff4ff',stroke:'#dce5fc','stroke-width':1.5}));
  svg.append(svgNode('ellipse',{cx:80,cy:80,rx:30,ry:65,fill:'none',stroke:'#c9d8fa','stroke-width':1.2}));
  svg.append(svgNode('ellipse',{cx:80,cy:80,rx:65,ry:24,fill:'none',stroke:'#c9d8fa','stroke-width':1.2}));
  svg.append(svgNode('path',{d:'M15 80h130 M80 15v130',fill:'none',stroke:'#c9d8fa','stroke-width':1.2}));
  wrap.append(svg,h('span','',code || '?'));return wrap;
}

export function visualSummary(records,result,{target,masked,observedAt,total}){
  const layout=h('div','visual-results');
  const overview=h('article','score-orbit-card');
  const header=h('div','result-topline');header.append(h('span','eyebrow','本轮检测'),h('span',`badge ${result.provisional?'warn':'ok'}`,result.score===null?'等待证据':result.provisional?'仍有未覆盖项':'数据已汇总'));overview.append(header,ring(result.score));
  const context=h('div','result-context');context.append(h('p','mono',masked(target)),h('p','',`${countryName(result.consensus.country)} · ${result.consensus.asn || 'ASN 待确认'}`));overview.append(context);
  const progress=h('div','dimension-track');const fill=h('span','dimension-fill');fill.style.width=`${result.coverage}%`;progress.append(fill);
  const coverage=h('div','coverage-label');coverage.append(h('span','','指标覆盖'),h('strong','',`${result.coverage}%`));overview.append(coverage,progress,h('p','small muted','综合分包含类型适配，未覆盖的指标保持未知。'));
  if(records.some(r=>r.status==='success'&&['tor','abuser','bogon'].some(k=>r.flags?.[k]===true)))overview.append(h('p','insight-line warning','发现重要风险标记，请查看对应证据。'));

  const signals=h('article','risk-signals card');const signalHeader=h('div','result-topline');signalHeader.append(h('div','', '风险信号'),h('span','small muted','按真实数据库字段绘制'));signals.append(signalHeader);
  const grid=h('div','signals-grid');
  for(const[id,label,symbol]of [['vpn','VPN','↗'],['proxy','代理','⇄'],['tor','Tor','◎'],['hosting','网络类型','▤'],['abuser','滥用记录','!'],['bogon','地址分配','◇']]){
    const votes=flagVotes(result,id);const yes=votes.filter(v=>v.value===true).length;const known=votes.length;
    const css=!known?'unknown':yes?(id==='hosting'?'type':'hit'):'clear';const tile=h('div',`signal-tile ${css}`);
    tile.append(h('span','signal-icon',!known?'?':yes?symbol:'✓'),h('span','signal-name',label),h('strong','',!known?'未覆盖':yes?(id==='hosting'?'机房标签':'有标记'):(id==='hosting'?'非机房标签':'未标记')),h('small','',!known?'等待相关数据':yes?`${yes} / ${known} 个来源标记`:`${known} 个来源明确为否`));grid.append(tile);
  }
  signals.append(grid,h('p','small muted','“未标记”只对应已返回的字段；机房类型与匿名、滥用行为分别判断。'));

  const geo=h('article','geo-card card');const geoHeader=h('div','result-topline');geoHeader.append(h('span','','地理归属'),h('span','badge neutral',result.consensus.countrySupport===null?'等待数据':`${result.consensus.countrySupport}% 国家支持权重`));geo.append(geoHeader);
  const location=h('div','geo-location');const title=h('div');title.append(h('h3','',countryName(result.consensus.country)),h('p','muted',labels[result.consensus.networkType] || '网络类型暂未形成共识'));location.append(globe(result.consensus.country),title);geo.append(location);
  const cities=new Map();for(const r of records.filter(r=>r.status==='success'&&r.city)){if(!cities.has(r.city))cities.set(r.city,[]);cities.get(r.city).push(r.providerName);}
  const sorted=[...cities].sort((a,b)=>b[1].length-a[1].length);const cityTotal=sorted.reduce((n,[,sources])=>n+sources.length,0);
  for(const[city,sources]of sorted.slice(0,4)){const row=h('div','location-row');const caption=h('div');caption.append(h('span','',city),h('small','',`${sources.length} 个来源`));row.append(caption);const track=h('div','location-track');const bar=h('span','location-fill');bar.style.width=`${sources.length/cityTotal*100}%`;track.append(bar);row.append(track);row.title=sources.join('、');geo.append(row);}
  geo.append(h('p','insight-line',cities.size>1?'城市标签存在分歧，各来源分别保留。':'城市级标签用于对照，不代表物理定位。'));

  const health=h('article','source-health card');const ready=records.filter(r=>r.status==='success').length;const heading=h('div','result-topline');heading.append(h('span','','数据连接'),h('strong','',`${ready} / ${total}`));health.append(heading);
  const dots=h('div','source-dots');for(const record of records){const item=h('div',`source-dot ${record.status==='success'?'ok':record.status==='pending'?'pending':'warn'}`);item.append(h('i'),h('span','',record.providerName));item.title=record.error || (record.cacheHit?'缓存中的有效响应':'本轮数据库响应');dots.append(item);}health.append(dots);
  const failures=records.filter(r=>['error','cancelled'].includes(r.status));health.append(h('p','small muted',failures.length?`${failures.length} 个来源本轮未返回，错误与缺失保留在明细中。`:'每个来源分别保留观测时间和数据归属。'));
  health.append(h('span','observation-time',new Date(observedAt).toLocaleTimeString('zh-CN',{hour12:false})+' · 本轮观测'));
  layout.append(overview,signals,geo,health);return layout;
}

export function visualBreakdown(result,providers){
  const view=h('div','visual-breakdown');const dimensions=h('div','visual-dimensions');
  const icons={network:'▤',risk:'◇',region:'◎'};
  for(const dim of result.dimensions){const card=h('article','card dimension-card');const header=h('div','result-topline');header.append(h('span','',`${icons[dim.id]} ${dim.label}`),h('span','small muted',`占比 ${dim.weight}%`));card.append(header);
    const value=h('div','dimension-value');value.append(h('strong','',dim.score===null?'—':String(dim.score)),h('small','','/ 100'));card.append(value);const track=h('div','dimension-track');const bar=h('span','dimension-fill');bar.style.width=`${dim.score || 0}%`;track.append(bar);card.append(track,h('p','small muted',`指标覆盖 ${dim.coverage}% · ${dim.sourceCount} 个可归属来源`));
    const details=h('details');details.append(h('summary','','查看字段与来源'));
    for(const field of dim.fields){const row=h('div','contribution-list');row.append(h('strong','',`${field.label} · ${field.score===null?'未覆盖':field.score}`));for(const source of field.sources)row.append(h('p','small muted',`${source.providerName}：${source.value===true?'命中':source.value===false?'明确为否':source.value} · 权重 ${source.weight}`));details.append(row);}card.append(details);dimensions.append(card);
  }
  view.append(dimensions);
  const formula=h('article','card');formula.append(h('h3','','每一分如何计算'));result.explanations.forEach(text=>formula.append(h('p','method-line',text)));view.append(formula);
  const credits=h('details','card');credits.append(h('summary','','数据来源与署名'));for(const p of providers){const line=h('p','method-line');const a=h('a','',p.name);a.href=p.attributionUrl;a.target='_blank';a.rel='noopener noreferrer';line.append(a,document.createTextNode(` · ${p.attribution} ${p.description}`));credits.append(line);}view.append(credits);
  return view;
}
