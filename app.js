import { initAssessment, renderAssessment } from './dashboard.js?v=1.3';

const $=id=>document.getElementById(id);
let busy=false;
let edited=false;
const controllers=new Set();
const inFlight=new Map();

function normalizeIP(input){
  const value=String(input || '').trim();
  if(/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)){
    const p=value.split('.').map(Number);if(p.some(x=>x>255))return null;
    const[a,b]=p;if(a===0||a===10||a===127||a>=224||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===100&&b>=64&&b<=127))return null;
    return p.join('.');
  }
  if(!/^[a-f\d:]+$/i.test(value)||!value.includes(':'))return null;
  try{const ip=new URL(`https://[${value}]/`).hostname.slice(1,-1);return ip==='::'||ip==='::1'||/^(fc|fd|fe[89ab]|ff|::ffff:)/i.test(ip)?null:ip;}catch{return null;}
}
function masked(ip){if(!ip)return '—';if(!$('mask-ip').checked)return ip;return ip.includes(':')?`${ip.split(':').slice(0,2).join(':')}:••••`:`${ip.split('.').slice(0,2).join('.')}.•••.•••`;}
function setBusy(value){busy=value;$('start-assessment').disabled=value;$('cancel-assessment').disabled=!value;}
function cancelRequests(){controllers.forEach(controller=>controller.abort());}
function request(url){
  if(inFlight.has(url))return inFlight.get(url);
  const operation=(async()=>{
    const controller=new AbortController();controllers.add(controller);const timer=setTimeout(()=>controller.abort(),10000);
    try{const response=await fetch(url,{credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',signal:controller.signal});if(!response.ok)throw new Error(`出口接口 HTTP ${response.status}`);return {data:await response.json()};}
    finally{clearTimeout(timer);controllers.delete(controller);inFlight.delete(url);}
  })();inFlight.set(url,operation);return operation;
}
function maskInput(){ $('assessment-ip').classList.toggle('is-masked',$('mask-ip').checked&&Boolean($('assessment-ip').value)); }
$('assessment-ip').addEventListener('input',()=>{edited=true;maskInput();});
$('mask-ip').addEventListener('change',()=>{maskInput();renderAssessment();});
initAssessment({request,setBusy,isBusy:()=>busy,normalizeIP,masked,cancelRequests});

// Only this address lookup runs on opening the page. Full assessment is explicit.
$('assessment-status').textContent='正在自动识别当前公网出口…';
request('https://api64.ipify.org?format=json').then(({data})=>{
  const ip=normalizeIP(data.ip);
  if(!ip)throw new Error('出口地址不可识别');
  if(!edited&&!$('assessment-ip').value.trim()){$('assessment-ip').value=ip;maskInput();if(!busy)$('assessment-status').textContent='当前公网 IP 已自动填入。点击查询查看检测结果。';}
  else if(!busy)$('assessment-status').textContent='已保留输入的地址，可直接查询。';
}).catch(()=>{if(!busy)$('assessment-status').textContent=$('assessment-ip').value.trim()?'已保留输入的地址，可直接查询。':'自动识别暂时不可用，可直接输入公网 IP 查询。';});
