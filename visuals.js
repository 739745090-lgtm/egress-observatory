const NS='http://www.w3.org/2000/svg';
function h(tag,css,text){const e=document.createElement(tag);if(css)e.className=css;if(text!==undefined)e.textContent=text;return e;}
function s(tag,attrs){const e=document.createElementNS(NS,tag);for(const[k,v]of Object.entries(attrs))e.setAttribute(k,String(v));return e;}
function votes(result,id){return result.dimensions.flatMap(d=>d.fields).find(f=>f.id===id)?.sources || [];}
function country(code){if(!code)return '国家待确认';try{return new Intl.DisplayNames(['zh-CN'],{type:'region'}).of(code);}catch{return code;}}
const types={residential:'住宅网络',isp:'运营商网络',mobile:'移动网络',business:'企业网络',hosting:'数据中心'};
const num=value=>value===null?'—':String(value);
function ring(score){const box=h('div','score-orbit');const svg=s('svg',{viewBox:'0 0 160 160','aria-hidden':'true'});const length=2*Math.PI*64;
  svg.append(s('circle',{cx:80,cy:80,r:64,fill:'none',stroke:'#303a45','stroke-width':12}));
  if(score!==null)svg.append(s('circle',{cx:80,cy:80,r:64,fill:'none',stroke:score>=80?'#39cc92':score>=50?'#e5b654':'#ed7279','stroke-width':12,'stroke-linecap':'butt','stroke-dasharray':`${length*score/100} ${length}`,transform:'rotate(-90 80 80)'}));
  const center=h('div','score-center');center.append(h('strong','',num(score)),h('span','','综合参考'));box.append(svg,center);return box;}
function fact(dl,label,value){const row=h('div','detail-row');row.append(h('dt','',label),h('dd','',value || '—'));dl.append(row);}
function conclusion(grid,label,value,detail,status='unknown'){const tile=h('div',`conclusion-item status-${status}`);const caption=h('div','conclusion-label');caption.append(h('i','',status==='clear'?'✓':status==='hit'?'!':status==='type'?'◈':'−'),h('span','',label));tile.append(caption,h('strong','conclusion-value',value),h('small','',detail));grid.append(tile);}

export function visualSummary(records,result,{target,masked,observedAt,total}){
  const layout=h('div','ip-result-layout');const good=records.filter(r=>r.status==='success');
  const cityMap=new Map();for(const r of good.filter(r=>r.city)){if(!cityMap.has(r.city))cityMap.set(r.city,[]);cityMap.get(r.city).push(r.providerName);}
  const cities=[...cityMap].sort((a,b)=>b[1].length-a[1].length);const primaryCity=cities[0]?.[0] || '';
  const org=good.find(r=>r.providerId==='ipinfo'&&r.org)?.org || good.find(r=>r.org)?.org || '未提供';
  const bar=h('section','ip-overview-bar');const identity=h('div','overview-identity');identity.append(h('strong','mono',masked(target)),h('span','country-chip',result.consensus.country || '—'),h('span','',`${country(result.consensus.country)}${primaryCity?' · '+primaryCity:''}`));bar.append(identity);
  const meter=h('div','quality-meter');const meterLine=h('div','quality-meter-line');const pointer=h('i');pointer.style.left=`${result.score??0}%`;if(result.score===null)pointer.hidden=true;meterLine.append(pointer);const scale=h('div','quality-scale');scale.append(h('small','','0 参考低'),h('small','','50'),h('small','','100 参考高'));meter.append(meterLine,scale);bar.append(meter,h('div','score-badge',result.score===null?'待评估':`${result.score} 分`));layout.append(bar);

  const main=h('div','ip-main-grid');const left=h('article','identity-card card');const top=h('div','identity-top');top.append(ring(result.score));const verdict=h('div','verdict-block');
  const positive=result.dimensions.flatMap(d=>d.fields).filter(f=>['vpn','proxy','tor','abuser','bogon'].includes(f.id)).some(f=>f.sources.some(v=>v.value===true));
  verdict.append(h('h2','',result.score===null?'等待有效数据':positive?'发现风险标记':result.score>=80?'已知风险较少':'需要结合明细判断'));
  verdict.append(h('p','',result.score===null?'查询完成后，根据实际返回字段生成结果。':`已取得 ${good.length} / ${total} 个来源，指标覆盖 ${result.coverage}%。`));
  verdict.append(h('span',`badge ${result.provisional?'warn':'ok'}`,result.provisional?'暂定参考 · 有未覆盖项':'本轮数据已汇总'));
  verdict.append(h('p','small muted','分数包含网络类型适配；缺失字段保持未知。'));top.append(verdict);left.append(top);
  left.append(h('h3','section-caption','地址信息'));const facts=h('dl','identity-facts');fact(facts,'IP 地址',masked(target));fact(facts,'国家 / 地区',country(result.consensus.country));fact(facts,'城市标注',primaryCity || '未提供');fact(facts,'网络类型',types[result.consensus.networkType] || '未形成共识');fact(facts,'查询时间',new Date(observedAt).toLocaleTimeString('zh-CN',{hour12:false}));left.append(facts);
  const location=h('section','location-comparison');location.append(h('h3','section-caption','多库城市标注'));const totalCities=cities.reduce((n,[,list])=>n+list.length,0);
  for(const[city,list]of cities.slice(0,4)){const row=h('div','location-row');const caption=h('div');caption.append(h('span','',city),h('small','',`${list.length} 个来源`));row.append(caption);const track=h('div','location-track');const fill=h('span','location-fill');fill.style.width=`${list.length/totalCities*100}%`;track.append(fill);row.append(track);row.title=list.join('、');location.append(row);}
  location.append(h('p','small muted',cities.length>1?'城市标签存在分歧，来源保留在明细中。':'城市标注是数据库判断，不代表物理位置。'));left.append(location);

  const right=h('div','conclusion-column');const conclusions=h('section','conclusion-card card');conclusions.append(h('h3','section-caption','检测结论'));const grid=h('div','conclusion-grid');
  const anon=[...votes(result,'vpn'),...votes(result,'proxy')];const anonProviders=new Set(anon.map(x=>x.database));const anonHit=anon.some(x=>x.value===true);
  conclusion(grid,'代理 / VPN',!anon.length?'未提供数据':anonHit?'有来源标记':'已知项未标记',`${anonProviders.size} 个可归属来源`,!anon.length?'unknown':anonHit?'hit':'clear');
  const tor=votes(result,'tor');conclusion(grid,'Tor 网络',!tor.length?'未提供数据':tor.some(x=>x.value===true)?'有来源标记':'未标记',`${tor.length} 个来源`,!tor.length?'unknown':tor.some(x=>x.value===true)?'hit':'clear');
  const hosting=votes(result,'hosting');conclusion(grid,'网络类型',types[result.consensus.networkType] || '未形成共识',hosting.length?`${hosting.length} 个来源返回机房标记`:'类型字段未提供',result.consensus.networkType==='hosting'?'type':result.consensus.networkType?'clear':'unknown');
  const countries=votes(result,'country');conclusion(grid,'地区一致性',!countries.length?'未提供数据':result.consensus.countrySupport===100?'国家标注一致':'国家存在分歧',`${countries.length} 个可归属来源`,!countries.length?'unknown':result.consensus.countrySupport===100?'clear':'type');
  for(const[id,label]of [['abuser','滥用记录'],['bogon','保留 / 未分配地址']]){const v=votes(result,id);const hit=v.some(x=>x.value===true);conclusion(grid,label,!v.length?'未提供数据':hit?'有来源标记':'未标记',v.length?`${v.length} 个来源`:'未知项不会补成通过',!v.length?'unknown':hit?'hit':'clear');}
  conclusions.append(grid);right.append(conclusions);
  const network=h('section','network-card card');network.append(h('h3','section-caption','ASN / 运营商'));const networkFacts=h('dl','identity-facts');fact(networkFacts,'ASN',result.consensus.asn || '未形成共识');fact(networkFacts,'所属网络',org);fact(networkFacts,'有效来源',`${good.length} / ${total}`);fact(networkFacts,'指标覆盖',`${result.coverage}%`);network.append(networkFacts);
  network.append(h('p','risk-note',positive?'明确命中的风险标签需要单独关注，综合分不能抵消该项证据。':'来源未提供的黑名单、滥用记录等指标，继续显示为未知。'));right.append(network);
  main.append(left,right);layout.append(main);

  const providerStrip=h('section','provider-strip card');const providerHeading=h('div','result-topline');providerHeading.append(h('h3','','数据来源'),h('span','small muted',`${good.length} / ${total} 已返回`));providerStrip.append(providerHeading);const pills=h('div','provider-pills');
  for(const record of records){const pill=h('div',`provider-pill ${record.status==='success'?'ok':record.status==='pending'?'pending':'warn'}`);pill.append(h('i'),h('span','',record.providerName));pill.title=record.error || (record.cacheHit?'来自有效缓存':'本轮返回有效数据');pills.append(pill);}providerStrip.append(pills);
  const attribution=h('p','data-attribution');attribution.append(document.createTextNode('地理数据：'));for(const [label,url]of [['IP2Location.io','https://www.ip2location.io'],['DB-IP','https://db-ip.com/']]){const a=h('a','',label);a.href=url;a.target='_blank';a.rel='noopener noreferrer';attribution.append(a,document.createTextNode('  '));}providerStrip.append(attribution);layout.append(providerStrip);
  return layout;
}

export function visualBreakdown(result,providers){
  const view=h('div','visual-breakdown');const dimensions=h('div','visual-dimensions');
  for(const dim of result.dimensions){const card=h('article','card dimension-card');const header=h('div','result-topline');header.append(h('span','',dim.label),h('span','small muted',`占比 ${dim.weight}%`));card.append(header);const value=h('div','dimension-value');value.append(h('strong','',num(dim.score)),h('small','','/ 100'));card.append(value);const track=h('div','dimension-track');const fill=h('span','dimension-fill');fill.style.width=`${dim.score || 0}%`;track.append(fill);card.append(track,h('p','small muted',`指标覆盖 ${dim.coverage}% · ${dim.sourceCount} 个来源`));
    const details=h('details');details.append(h('summary','','字段与来源'));for(const field of dim.fields){const row=h('div','contribution-list');row.append(h('strong','',`${field.label} · ${num(field.score)}`));for(const source of field.sources)row.append(h('p','small muted',`${source.providerName}：${source.value===true?'命中':source.value===false?'明确为否':source.value} · 权重 ${source.weight}`));details.append(row);}card.append(details);dimensions.append(card);}
  view.append(dimensions);const explanation=h('section','method-copy');result.explanations.forEach(text=>explanation.append(h('p','method-line',text)));view.append(explanation);
  const credits=h('details');credits.append(h('summary','','接口说明与完整署名'));for(const p of providers){const line=h('p','method-line');const a=h('a','',p.name);a.href=p.attributionUrl;a.target='_blank';a.rel='noopener noreferrer';line.append(a,document.createTextNode(` · ${p.attribution} ${p.description}`));credits.append(line);}view.append(credits);return view;
}
